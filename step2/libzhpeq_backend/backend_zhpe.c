/*
 * Copyright (C) 2017-2019 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define _GNU_SOURCE
#include <internal.h>

#include <fcntl.h>
#include <numaif.h>
#include <search.h>
#include <unistd.h>

#define NODE_CHUNKS     (128)

static int              dev_fd = -1;
static pthread_mutex_t  dev_mutex = PTHREAD_MUTEX_INITIALIZER;
static void             *dev_uuid_tree;
static void             *dev_mr_tree;
static uint64_t         big_rsp_zaddr;

#define BIG_ZMMU_LEN    (((uint64_t)1) << 47)
#define BIG_ZMMU_REQ_FLAGS \
    (ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE)
#define BIG_ZMMU_RSP_FLAGS \
    (ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE | ZHPE_MR_ZMMU_ONLY)

struct dev_uuid_tree_entry {
    uuid_t              uuid;
    int32_t             use_count;
    bool                fam;
};

struct dev_mr_tree_entry {
    struct zhpeq_key_data qkdata;
    int32_t             use_count;
};

static struct zhpe_global_shared_data *shared_global;
static struct zhpe_local_shared_data *shared_local;

struct zhpe_rq_epoll_irq {
    int                 fd;
    uint16_t            qnum;
    uint16_t            clump;
    uint16_t            count;
};

static pthread_mutex_t  epoll_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct zhpeq_rqi *epoll_rqi[ZHPE_MAX_RDMQS];
static struct zhpe_rq_epoll_irq epoll_irq[ZHPE_MAX_IRQS];
static int              epoll_fd = -1;
static int              epoll_pipe_fds[2] = { -1, -1 };

struct zdom_data {
    pthread_mutex_t     node_mutex;
    int32_t             node_idx;
    struct zdom_node {
        struct dev_uuid_tree_entry *uue;
        uint64_t        big_req_zaddr;
        uint64_t        big_req_cnt;
        uint32_t        sz_queue;
    } *nodes;
};

/* For the moment, we will do all driver I/O synchronously.*/

static int __driver_cmd(union zhpe_op *op, size_t req_len, size_t rsp_len,
                        bool err_print)
{
    int                 ret = 0;
    int                 opcode = op->hdr.opcode;
    ssize_t             res;

    op->hdr.version = ZHPE_OP_VERSION;
    op->hdr.index = 0;

    res = write(dev_fd, op, req_len);
    ret = zhpeu_check_func_io(__func__, __LINE__, "write", DEV_NAME,
                              req_len, res, 0);
    if (ret < 0)
        goto done;

    res = read(dev_fd, op, rsp_len);
    ret = zhpeu_check_func_io(__func__, __LINE__, "read", DEV_NAME,
                              rsp_len, res, 0);
    if (ret < 0)
        goto done;
    ret = -EIO;
    if (res < sizeof(op->hdr)) {
        zhpeu_print_err("%s,%u:Unexpected short read %lu\n",
                        __func__, __LINE__, res);
        goto done;
    }
    ret = -EINVAL;
    if (!zhpeu_expected_saw("version", (uint8_t)ZHPE_OP_VERSION,
                            op->hdr.version))
        goto done;
    if (!zhpeu_expected_saw("opcode", (uint8_t)(opcode | ZHPE_OP_RESPONSE),
                            op->hdr.opcode))
        goto done;
    if (!zhpeu_expected_saw("index", (uint16_t)0, op->hdr.index))
        goto done;
    ret = op->hdr.status;
    if (ret < 0 && err_print)
        zhpeu_print_err("%s,%u:zhpe command 0x%02x returned error %d:%s\n",
                        __func__, __LINE__, op->hdr.opcode, -ret,
                        strerror(-ret));

 done:

    return ret;
}

static int driver_cmd(union zhpe_op *op, size_t req_len, size_t rsp_len,
                      bool err_print)
{
    int                 ret;

    mutex_lock(&dev_mutex);
    ret = __driver_cmd(op, req_len, rsp_len, err_print);
    mutex_unlock(&dev_mutex);

    return ret;
}

static int zhpe_lib_init(struct zhpeq_attr *attr)
{
    int                 ret = -EINVAL;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    if ((dev_fd = open(DEV_NAME, O_RDWR)) == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "open", DEV_NAME, ret);
        goto done;
    }

    req->hdr.opcode = ZHPE_OP_INIT;
    ret = driver_cmd(&op, sizeof(req->init), sizeof(rsp->init), true);
    if (ret < 0)
        goto done;

    if (!zhpeu_expected_saw("rsp->init.magic", ZHPE_MAGIC, rsp->init.magic)) {
        ret = -EINVAL;
        goto done;
    }

    attr->backend = ZHPEQ_BACKEND_ZHPE;
    attr->z = rsp->init.attr;

    shared_global = _zhpeu_mmap(NULL, rsp->init.global_shared_size,
                                PROT_READ, MAP_SHARED, dev_fd,
                                rsp->init.global_shared_offset);
    if (!shared_global) {
        ret = -errno;
        goto done;
    }
    shared_local = _zhpeu_mmap(NULL, rsp->init.local_shared_size,
                               PROT_READ | PROT_WRITE, MAP_SHARED, dev_fd,
                               rsp->init.local_shared_offset);
    if (!shared_local) {
        ret = -errno;
        goto done;
    }

    memcpy(zhpeq_uuid, rsp->init.uuid, sizeof(zhpeq_uuid));

    ret = 0;
 done:

    return ret;
}

static int compare_uuid(const void *key1, const void *key2)
{
    const uuid_t        *u1 = key1;
    const uuid_t        *u2 = key2;

    return uuid_compare(*u1, *u2);
}

static int do_uuid_free(uuid_t uuid)
{
    int                 ret;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    req->hdr.opcode = ZHPE_OP_UUID_FREE;
    memcpy(req->uuid_free.uuid, uuid, sizeof(req->uuid_free.uuid));
    ret =__driver_cmd(&op, sizeof(req->uuid_free), sizeof(rsp->uuid_free),
                      false);
    if (ret < 0) {
        if (ret != -ENOENT)
            zhpeu_print_func_err(__func__, __LINE__, "__driver_cmd", "", ret);
        else
            ret = 0;
    }

    return ret;
}

static int uuid_free(uuid_t *uu)
{
    int                 ret = 0;
    void                **tval;
    struct dev_uuid_tree_entry *uue;

    mutex_lock(&dev_mutex);
    tval = tfind(uu, &dev_uuid_tree, compare_uuid);
    if (tval) {
        uue = *tval;
        if (!--(uue->use_count)) {
            (void)tdelete(uu, &dev_uuid_tree, compare_uuid);
            if (uuid_compare(*uu, zhpeq_uuid))
                ret = do_uuid_free(*uu);
            free(uue);
        }
    } else {
        ret = -ENOENT;
        zhpeu_print_func_err(__func__, __LINE__, "tfind", "", ret);
    }
    mutex_unlock(&dev_mutex);

    return ret;
}

static int zhpe_domain_free(struct zhpeq_domi *zdomi)
{
    int                 ret = 0;
    struct zdom_data    *bdom = zdomi->backend_data;
    struct dev_uuid_tree_entry *uue;
    uint32_t            i;
    int                 rc;

    if (!bdom)
        goto done;

    zdomi->backend_data = NULL;
    mutex_destroy(&bdom->node_mutex);
    for (i = 0; i < bdom->node_idx; i++) {
        uue = bdom->nodes[i].uue;
        if (uue) {
            rc = uuid_free(&uue->uuid);
            ret = (ret >= 0 ? rc : ret);
        }
    }
    free(bdom->nodes);
    free(bdom);

 done:
    return ret;
}

static int zhpe_domain(struct zhpeq_domi *zdomi)
{
    int                 ret = -ENOMEM;
    struct zdom_data    *bdom;

    bdom = zdomi->backend_data = calloc(1, sizeof(*bdom));
    if (!bdom)
        goto done;
    mutex_init(&bdom->node_mutex, NULL);
    ret = 0;
 done:

    return ret;
}

static int zhpe_xq_free_pre(struct zhpeq_xqi *xqi)
{
    return 0;
}

static int zhpe_xq_free(struct zhpeq_xqi *xqi)
{

    int                 ret;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    req->hdr.opcode = ZHPE_OP_XQFREE;
    req->xqfree.info = xqi->zxq.xqinfo;
    ret = driver_cmd(&op, sizeof(req->xqfree), sizeof(rsp->xqfree), true);

    return ret;
}

static int zhpe_xq_alloc(struct zhpeq_xqi *xqi, int wqlen, int cqlen,
                         int traffic_class, int priority, int slice_mask)
{
    int                 ret;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    req->hdr.opcode = ZHPE_OP_XQALLOC;
    req->xqalloc.cmdq_ent = wqlen;
    req->xqalloc.cmplq_ent = wqlen;
    req->xqalloc.traffic_class = traffic_class;
    req->xqalloc.priority = priority;
    req->xqalloc.slice_mask = slice_mask;
    ret = driver_cmd(&op, sizeof(req->xqalloc), sizeof(rsp->xqalloc), true);
    if (ret < 0)
        goto done;
    xqi->dev_fd = dev_fd;
    xqi->zxq.xqinfo = rsp->xqalloc.info;
 done:

    return ret;
}

static int zhpe_xq_alloc_post(struct zhpeq_xqi *xqi)
{
    return 0;
}

static inline struct zdom_data *xqi2bdom(struct zhpeq_xqi *xqi)
{
    struct zhpeq_domi   *zdomi = container_of(xqi->zxq.zdom, struct zhpeq_domi,
                                              zdom);

    return zdomi->backend_data;
}

static int zhpe_xq_open(struct zhpeq_xqi *xqi, void *sa)
{
    int                 ret = 0;
    struct zdom_data    *bdom = xqi2bdom(xqi);
    struct sockaddr_zhpe *sz = sa;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;
    struct zdom_node    *node;
    void                **tval;
    struct dev_uuid_tree_entry *uue;

    if (sz->sz_family != AF_ZHPE)
        return -EINVAL;

    mutex_lock(&dev_mutex);
    tval = tsearch(&sz->sz_uuid, &dev_uuid_tree, compare_uuid);
    if (tval) {
        uue = *tval;
        if (uue != (void *)&sz->sz_uuid)
            uue->use_count++;
        else {
            uue = malloc(sizeof(*uue));
            if (!uue)
                ret = -ENOMEM;
            if (ret >= 0) {
                memcpy(uue->uuid, sz->sz_uuid, sizeof(uue->uuid));
                uue->use_count = 1;
                uue->fam = ((sz->sz_queue & ZHPE_SZQ_FLAGS_MASK) ==
                            ZHPE_SZQ_FLAGS_FAM);

                req->hdr.opcode = ZHPE_OP_UUID_IMPORT;
                memcpy(req->uuid_import.uuid, sz->sz_uuid,
                       sizeof(req->uuid_import.uuid));
                if (uue->fam) {
                    memcpy(req->uuid_import.mgr_uuid, sz[1].sz_uuid,
                           sizeof(req->uuid_import.mgr_uuid));
                    req->uuid_import.uu_flags = UUID_IS_FAM;
                } else {
                    memset(req->uuid_import.mgr_uuid, 0,
                           sizeof(req->uuid_import.mgr_uuid));
                    req->uuid_import.uu_flags = 0;
                }
                ret = __driver_cmd(&op, sizeof(req->uuid_import),
                                   sizeof(rsp->uuid_import), true);
            }
            if (ret < 0) {
                (void)tdelete(&sz->sz_uuid, &dev_uuid_tree, compare_uuid);
                free(uue);
            } else
                *tval = uue;
        }
    } else {
        ret = -ENOMEM;
        zhpeu_print_func_err(__func__, __LINE__, "tsearch", "", ret);
    }
    mutex_unlock(&dev_mutex);
    if (ret < 0)
        goto done;

    mutex_lock(&bdom->node_mutex);
    if ((bdom->node_idx % NODE_CHUNKS) == 0) {
        bdom->nodes = realloc(
            bdom->nodes, (bdom->node_idx + NODE_CHUNKS) * sizeof(*bdom->nodes));
        if (!bdom->nodes)
            ret = -ENOMEM;
    }
    if (ret >= 0) {
        if (bdom->node_idx < INT32_MAX) {
            ret = bdom->node_idx++;
            node = &bdom->nodes[ret];
            node->uue = uue;
            node->big_req_zaddr = 0;
            node->big_req_cnt = 0;
            node->sz_queue = sz->sz_queue;
        } else
            ret = -ENOSPC;
    } else
        (void)uuid_free(&sz->sz_uuid);
    mutex_unlock(&bdom->node_mutex);

 done:
    return ret;
}

static int zhpe_xq_close(struct zhpeq_xqi *xqi, int open_idx)
{
    int                 ret = -EINVAL;
    struct zdom_data    *bdom = xqi2bdom(xqi);
    struct zdom_node    *node;
    struct dev_uuid_tree_entry *uue;

    if (open_idx < 0 || open_idx >= bdom->node_idx)
        goto done;

    mutex_lock(&bdom->node_mutex);
    node = &bdom->nodes[open_idx];
    uue = node->uue;
    node->uue = NULL;
    mutex_unlock(&bdom->node_mutex);
    ret = (uue ? uuid_free(&uue->uuid) : -ENOENT);

 done:
    return ret;
}

static int zhpe_rq_epoll_deinit(void)
{
    int                 ret = 0;

    ret = zhpeu_update_error(ret, FD_CLOSE(epoll_fd));
    ret = zhpeu_update_error(ret, FD_CLOSE(epoll_pipe_fds[0]));
    ret = zhpeu_update_error(ret, FD_CLOSE(epoll_pipe_fds[1]));

    return ret;
}

static int zhpe_rq_epoll_init(void)
{
    int                 ret = -EEXIST;
    struct epoll_event  pipe_event = {
        .events         = EPOLLIN,
        .data.u64       = ZHPE_MAX_IRQS,
    };

    if (epoll_fd != -1)
        goto done;

    if ((ret = epoll_create1(EPOLL_CLOEXEC)) == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "epoll_create1", "", ret);
        goto done;
    }
    epoll_fd = ret;

    if (pipe2(epoll_pipe_fds, O_CLOEXEC | O_NONBLOCK) == -1) {
        ret = -errno;
        epoll_pipe_fds[0] = -1;
        epoll_pipe_fds[1] = -1;
        zhpeu_print_func_err(__func__, __LINE__, "pipe2", "", ret);
        goto done;
    }

    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, epoll_pipe_fds[0], &pipe_event);
    if (ret == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "epoll_ctl", "ADD", ret);
        goto done;
    }
 done:
    if (ret < 0)
        (void)zhpe_rq_epoll_deinit();

    return ret;
}

static inline uint rqi_irq(struct zhpeq_rqi *rqi)
{
    return rqi->zrq.rqinfo.irq_vector;
}

static inline uint rqi_qnum(struct zhpeq_rqi *rqi)
{
    struct zhpe_rqinfo  *rqinfo = &rqi->zrq.rqinfo;

    return ZHPE_MAX_RDMQS_PER_SLICE * rqinfo->slice + rqinfo->queue;
}

static int zhpe_rq_epoll_del(struct zhpeq_rqi *rqi)
{
    int                 ret = 0;
    uint32_t            irq = rqi_irq(rqi);
    uint32_t            qnum = rqi_qnum(rqi);
    struct zhpeq_rqi    *rqi_old;

    mutex_lock(&epoll_mutex);

    for (;;) {
        rqi_old = atm_load_rlx(&epoll_rqi[qnum]);
        if (atm_cmpxchg(&epoll_rqi[qnum], &rqi_old, NULL))
            break;
    }
    if (!rqi_old) {
        /* Should never happen. */
        abort();
    }

    if (--(epoll_irq[irq].count))
        goto done;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, epoll_irq[irq].fd, NULL) == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "epoll_ctl", "DEL", -errno);
    }
 done:

    mutex_unlock(&epoll_mutex);

    return ret;
}

static int zhpe_rq_epoll_add(struct zhpeq_rqi *rqi)
{
    int                 ret = -EEXIST;
    uint32_t            irq = rqi_irq(rqi);
    uint32_t            qnum = rqi_qnum(rqi);
    struct zhpeq_rqi    *rqi_old = NULL;
    char                *fname = NULL;
    struct epoll_event  poll_event = {
        .events         = EPOLLIN,
        .data.u64       = irq,
    };

    mutex_lock(&epoll_mutex);

    if (epoll_fd == -1 && (ret = zhpe_rq_epoll_init()) < 0)
        goto done;

    if (!atm_cmpxchg(&epoll_rqi[qnum], &rqi_old, rqi)) {
        /* Should never happen. */
        abort();
    }

    ret = 0;
    if (epoll_irq[irq].count++)
        goto done;

    epoll_irq[irq].qnum = qnum & ~(rqi->zrq.rqinfo.clump - 1);
    epoll_irq[irq].clump = rqi->zrq.rqinfo.clump;

    fname = _zhpeu_asprintf("%s_poll_%u", DEV_NAME, irq);
    if (!fname) {
        ret = -ENOMEM;
        goto done;
    }
    epoll_irq[irq].fd = open(fname, O_RDONLY);
    if (epoll_irq[irq].fd == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "open", fname, ret);
        goto done;
    }
    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, epoll_irq[irq].fd, &poll_event);
    if (ret == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "epoll_ctl", "ADD", ret);
        goto done;
    }
    ret = 0;
 done:

    if (ret < 0) {
        if (fname) {
            free(fname);
            FD_CLOSE(epoll_irq[irq].fd);
        }
        epoll_irq[irq].count--;
    }
    mutex_unlock(&epoll_mutex);

    return ret;
}

static int zhpe_rq_free(struct zhpeq_rqi *rqi)
{

    int                 ret = 0;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;
    int                 rc;

    ret = zhpeu_update_error(ret, zhpe_rq_epoll_del(rqi));
    req->hdr.opcode = ZHPE_OP_RQFREE;
    req->rqfree.info = rqi->zrq.rqinfo;
    rc = driver_cmd(&op, sizeof(req->rqfree), sizeof(rsp->rqfree), true);
    ret = zhpeu_update_error(ret, rc);

    return ret;
}

static int zhpe_rq_alloc(struct zhpeq_rqi *rqi, int rqlen, int slice_mask)
{
    int                 ret;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    req->hdr.opcode = ZHPE_OP_RQALLOC;
    req->rqalloc.cmplq_ent = rqlen;
    req->rqalloc.slice_mask = slice_mask;
    ret = driver_cmd(&op, sizeof(req->rqalloc), sizeof(rsp->rqalloc), true);
    if (ret < 0)
        goto done;
    rqi->dev_fd = dev_fd;
    rqi->zrq.rqinfo = rsp->rqalloc.info;
    ret = zhpe_rq_epoll_add(rqi);
 done:

    return ret;
}

static int zhpe_rq_epoll(int timeout_ms, const sigset_t *sigmask, bool eintr_ok,
                         int (*zrq_ready)(void *varg, struct zhpeq_rq *zrq),
                         void *varg)
{
    int                 ret;
    uint32_t            irq;
    uint32_t            evts;
    uint32_t            i;
    struct zhpeq_rqi    *rqi;
    struct zhpeq_rqi    *rqi_lock;
    int                 nevents;
    struct epoll_event  events[ZHPE_MAX_IRQS];
    char                pipe_buf[32];

    ret = epoll_pwait(epoll_fd, events, ARRAY_SIZE(events),
                      timeout_ms, sigmask);
    if (ret == -1) {
        ret = -errno;
        if (ret != -EINTR || !eintr_ok)
            zhpeu_print_func_err(__func__, __LINE__, "epoll", "", ret);
        goto done;
    }

    /* Protect against zrqs being deleted. */
    mutex_lock(&epoll_mutex);

    assert(timeout_ms == 0 || ret);
    nevents = ret;
    ret = 0;
    for (i = 0; i < nevents; i++) {
        irq = events[i].data.u64;
        evts = events[i].events;
        if (evts & ~EPOLLIN) {
            zhpeu_print_err("%s,%u:irq_index %u unexpected events 0x%x\n",
                            __func__, __LINE__, irq, evts);
            ret = -EIO;
            goto done_locked;
        }
        if (irq >= ZHPE_MAX_IRQS) {
            /* Pipe: just used to wake us up, empty it. */
            (void)read(epoll_pipe_fds[0], pipe_buf, sizeof(pipe_buf));
            continue;
        }
        atm_store(&shared_local->handled_counter[irq],
                  atm_load(&shared_global->triggered_counter[irq]));

        for (i = epoll_irq[irq].qnum;
             i < epoll_irq[irq].qnum + epoll_irq[irq].clump; i++) {
            rqi = atm_load_rlx(&epoll_rqi[i]);
            if (!rqi)
                continue;
            /* We'll steal bit 0 as a flag; non-zero => skip. (evil) */
            if ((uintptr_t)rqi & 1)
                continue;
            /* Is the current head valid? */
            if (!zhpeq_rq_valid(&rqi->zrq, false))
                continue;
            /*
             * A queue has a valid entry. Use cmpxchg to lock the queue
             * from further polling and handle races.
             */
            rqi_lock = TO_PTR((uintptr_t)rqi | 1);
            if (!atm_cmpxchg(&epoll_rqi[i], &rqi, rqi_lock))
                continue;
            /* Lock succeeded, call zrq_ready(). */
            ret = zrq_ready(varg, &rqi->zrq);
            if (ret < 0)
                goto done_locked;
        }
    }
 done_locked:

    mutex_unlock(&epoll_mutex);
 done:

    return ret;
}

static int zhpe_rq_epoll_enable(struct zhpeq_rqi *rqi)
{
    int                 ret = 0;
    uint32_t            qnum = rqi_qnum(rqi);
    struct zhpeq_rqi    *rqi_old = TO_PTR((uintptr_t)rqi | 1);

    if (atm_cmpxchg(&epoll_rqi[qnum], &rqi_old, rqi))
        goto done;
    assert(rqi_old == rqi);
 done:

    return ret;
}

int zhpe_rq_epoll_signal(void)
{
    int                 ret = 0;
    char                buf[1] = { 0 };

    if (write(epoll_pipe_fds[1], buf, sizeof(buf)) == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            ret = -errno;
            zhpeu_print_func_err(__func__, __LINE__, "write", "", ret);
        }
    }

    return ret;
}

static int compare_qkdata(const void *key1, const void *key2)
{
    int                 ret;
    const struct zhpeq_key_data *qk1 = key1;
    const struct zhpeq_key_data *qk2 = key2;
    uint64_t            s1;
    uint64_t            e1;
    uint32_t            a1;
    uint64_t            s2;
    uint64_t            e2;
    uint32_t            a2;

    /* Expand the search parameters to the nearest page boundary. */
    s1 = page_down(qk1->z.vaddr);
    s2 = page_down(qk2->z.vaddr);
    ret = arithcmp(s1, s2);
    if (ret)
        return ret;
    e1 = page_up(qk1->z.vaddr + qk1->z.len);
    e2 = page_up(qk2->z.vaddr + qk2->z.len);
    ret = arithcmp(e1, e2);
    if (ret)
        return ret;
    /* Mask off user flags in comparison. */
    a1 = qk1->z.access & ZHPE_MR_USER_MASK;
    a2 = qk2->z.access & ZHPE_MR_USER_MASK;
    ret = arithcmp(a1, a2);

    return ret;
}

static int do_mr_reg(uint64_t vaddr, size_t len, uint32_t access,
                     uint64_t *zaddr)
{
    int                 ret;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    req->hdr.opcode = ZHPE_OP_MR_REG;
    req->mr_reg.vaddr = vaddr;
    req->mr_reg.len = len;
    req->mr_reg.access = access;

    ret = __driver_cmd(&op, sizeof(req->mr_reg), sizeof(rsp->mr_reg), true);
    if (ret >= 0)
        *zaddr = rsp->mr_reg.rsp_zaddr;

    return ret;
}

static int do_mr_free(uint64_t vaddr, size_t len, uint32_t access,
                      uint64_t zaddr)
{
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    req->hdr.opcode = ZHPE_OP_MR_FREE;
    req->mr_reg.vaddr = vaddr;
    req->mr_reg.len = len;
    req->mr_reg.access = access;
    req->mr_free.rsp_zaddr = zaddr;

    return __driver_cmd(&op, sizeof(req->mr_free), sizeof(rsp->mr_free), true);
}

static int zhpe_mr_reg(struct zhpeq_domi *zdomi,
                       const void *buf, size_t len,
                       uint32_t access, struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -ENOMEM;
    struct zhpeq_mr_desc_v1 *desc = NULL;
    uint64_t            end = page_up((uintptr_t)buf + len);
    uint64_t            start = page_down((uintptr_t)buf);
    uint64_t            pglen = end - start;
    struct zhpeq_key_data *qkdata = NULL;
    void                **tval;
    struct dev_mr_tree_entry *mre;

    if (!big_rsp_zaddr) {
        ret = do_mr_reg(0, BIG_ZMMU_LEN, BIG_ZMMU_RSP_FLAGS, &big_rsp_zaddr);
        if (ret < 0)
            goto done;
    }

    desc = malloc(sizeof(*desc));
    if (!desc)
        goto done;
    qkdata = &desc->qkdata;

    /* Zero access is expected to work. */
    if (!access)
        access = ZHPEQ_MR_PUT;

    desc->hdr.magic = ZHPE_MAGIC;
    desc->hdr.version = ZHPEQ_MR_V1;
    desc->hdr.zdomi = zdomi;
    qkdata->z.vaddr = (uintptr_t)buf;
    qkdata->laddr = (uintptr_t)buf;
    qkdata->z.len = len;
    qkdata->z.access = access;

    ret = 0;

    mutex_lock(&dev_mutex);
    tval = tsearch(qkdata, &dev_mr_tree, compare_qkdata);
    if (tval) {
        mre = *tval;
        if (mre != (void *)qkdata) {
            qkdata->z.zaddr = mre->qkdata.z.zaddr + page_off(qkdata->z.vaddr);
            mre->use_count++;
        } else {
            mre = malloc(sizeof(*mre));
            if (mre) {
                mre->qkdata.z.vaddr = start;
                mre->qkdata.z.len = pglen;
                mre->qkdata.z.access = access;
                mre->use_count = 1;
            } else
                ret = -ENOMEM;
            /* mbind region to turn off NUMA balancing */
            if (ret >= 0 &&
                mbind(TO_PTR(mre->qkdata.z.vaddr), mre->qkdata.z.len,
                      MPOL_PREFERRED, NULL, 1, 0) == -1) {
                ret = -errno;
                zhpeu_print_func_err(__func__, __LINE__, "mbind", "preferred",
                                     ret);
            }
            if (ret >= 0) {
                ret = do_mr_reg(mre->qkdata.z.vaddr, mre->qkdata.z.len,
                                mre->qkdata.z.access, &mre->qkdata.z.zaddr);
                qkdata->z.zaddr = (mre->qkdata.z.zaddr +
                                   page_off(qkdata->z.vaddr));
                /* Restore to default policy on error. (Imperfect) */
                if (ret < 0 &&
                    mbind(TO_PTR(mre->qkdata.z.vaddr), mre->qkdata.z.len,
                          MPOL_DEFAULT, NULL, 1, 0) == -1)
                    zhpeu_print_func_err(__func__, __LINE__, "mbind", "fixup",
                                         -errno);
            }
            if (ret >= 0)
                *tval = mre;
            else {
                (void)tdelete(qkdata, &dev_mr_tree, compare_qkdata);
                 free(mre);
            }
        }
    } else
        zhpeu_print_func_err(__func__, __LINE__, "tsearch", "", ret);
    mutex_unlock(&dev_mutex);

 done:
    if (ret >= 0)
        *qkdata_out = qkdata;
    else
        free(desc);

    return ret;
}

static int zhpe_mr_free(struct zhpeq_mr_desc_v1 *desc)
{
    int                 ret = 0;
    struct zhpeq_key_data *qkdata = &desc->qkdata;
    void                **tval;
    struct dev_mr_tree_entry *mre;
    int                 rc;

    mutex_lock(&dev_mutex);
    tval = tfind(qkdata, &dev_mr_tree, compare_qkdata);
    if (tval) {
        mre = *tval;
        if (!--(mre->use_count)) {
            (void)tdelete(qkdata, &dev_mr_tree, compare_qkdata);
            ret = do_mr_free(mre->qkdata.z.vaddr, mre->qkdata.z.len,
                             mre->qkdata.z.access, mre->qkdata.z.zaddr);
            if (mbind(TO_PTR(mre->qkdata.z.vaddr), mre->qkdata.z.len,
                      MPOL_DEFAULT, NULL, 0, 0) == -1) {
                rc = -errno;
                /*
                 * For the moment, suppress EFAULT errors as these can
                 * occur correctly when the mr_cache frees a registration
                 * that has been unmapped.
                 */
                if (rc != -EFAULT) {
                    ret = zhpeu_update_error(ret, rc);
                    zhpeu_print_func_err(__func__, __LINE__, "mbind", "default",
                                         rc);
                }
            }
            free(mre);
        }
    } else {
        ret = -ENOENT;
        zhpeu_print_func_err(__func__, __LINE__, "tfind", "", ret);
    }
    if (!dev_mr_tree && big_rsp_zaddr) {
        ret = zhpeu_update_error(
            ret, do_mr_free(0, BIG_ZMMU_LEN, BIG_ZMMU_RSP_FLAGS,
                            big_rsp_zaddr));
        big_rsp_zaddr = 0;
    }
    mutex_unlock(&dev_mutex);

    return ret;
}

static int do_rmr_import(uuid_t uuid, uint64_t rsp_zaddr, size_t len,
                         uint32_t access, uint64_t *req_zaddr,
                         uint64_t *pgoff)
{
    int                 ret;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    req->hdr.opcode = ZHPE_OP_RMR_IMPORT;
    memcpy(req->rmr_import.uuid, uuid, sizeof(req->rmr_import.uuid));
    req->rmr_import.rsp_zaddr = rsp_zaddr;
    req->rmr_import.len = len;
    req->rmr_import.access = access;
    ret = driver_cmd(&op, sizeof(req->rmr_import), sizeof(rsp->rmr_import),
                     true);
    if (ret >= 0) {
        *req_zaddr = rsp->rmr_import.req_addr;
        if (pgoff)
            *pgoff = rsp->rmr_import.offset;
    }

    return ret;
}

static int do_rmr_free(uuid_t uuid, uint64_t rsp_zaddr, size_t len,
                       uint32_t access, uint64_t req_zaddr)
{
    int                 ret;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    req->hdr.opcode = ZHPE_OP_RMR_FREE;
    memcpy(req->rmr_free.uuid, uuid, sizeof(req->rmr_free.uuid));
    req->rmr_free.req_addr = req_zaddr;
    req->rmr_free.len = len;
    req->rmr_free.access = access;
    req->rmr_free.rsp_zaddr = rsp_zaddr;

    ret = driver_cmd(&op, sizeof(req->rmr_free), sizeof(rsp->rmr_free), false);
    if (ret < 0) {
        if (ret != -ENOENT)
            zhpeu_print_func_err(__func__, __LINE__, "__driver_cmd", "", ret);
        else
            ret = 0;
    }

    return ret;
}

static int zhpe_zmmu_reg(struct zhpeq_mr_desc_v1 *desc)
{
    int                 ret = -EINVAL;
    struct zhpeq_key_data *qkdata = &desc->qkdata;
    struct zdom_data    *bdom = desc->hdr.zdomi->backend_data;
    struct zdom_node    *node = &bdom->nodes[desc->open_idx];

    if (!node->uue)
        goto done;
    if (!(qkdata->z.access & ZHPE_MR_INDIVIDUAL)) {
        mutex_lock(&bdom->node_mutex);
        if (!node->big_req_zaddr)
            ret = do_rmr_import(node->uue->uuid,
                                qkdata->rsp_zaddr - qkdata->z.vaddr,
                                BIG_ZMMU_LEN, BIG_ZMMU_REQ_FLAGS,
                                &node->big_req_zaddr, NULL);
        else
            ret = 0;
        if (ret >= 0) {
            node->big_req_cnt++;
            qkdata->z.zaddr = node->big_req_zaddr + qkdata->z.vaddr;
        }
        mutex_unlock(&bdom->node_mutex);
    } else
        ret = do_rmr_import(node->uue->uuid, qkdata->rsp_zaddr, qkdata->z.len,
                            qkdata->z.access, &qkdata->z.zaddr, NULL);

 done:
    return ret;
}

static int zhpe_fam_qkdata(struct zhpeq_domi *zdomi, int open_idx,
                           struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -EINVAL;
    struct zdom_data    *bdom = zdomi->backend_data;
    struct zhpeq_mr_desc_v1 *desc = NULL;
    struct zhpeq_key_data *qkdata;
    struct zdom_node    *node;

    if (open_idx < 0 || open_idx >= bdom->node_idx)
        goto done;
    node = &bdom->nodes[open_idx];
    if (!node->uue || !node->uue->fam)
        goto done;

    ret = -ENOMEM;
    desc = malloc(sizeof(*desc));
    if (!desc)
        goto done;
    qkdata = &desc->qkdata;

    desc->hdr.magic = ZHPE_MAGIC;
    desc->hdr.version = ZHPEQ_MR_V1 | ZHPEQ_MR_REMOTE;
    desc->hdr.zdomi = zdomi;
    desc->open_idx = open_idx;
    qkdata->z.vaddr = 0;
    qkdata->z.zaddr = 0;
    qkdata->rsp_zaddr = 0;
    /* FAM size in GiB in XID portion of sz_queue. */
    qkdata->z.len = node->sz_queue & ZHPE_CTXID_MASK;
    qkdata->z.len *= (1ULL << 30);
    qkdata->z.access = (ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE |
                        ZHPEQ_MR_KEY_ZERO_OFF | ZHPE_MR_INDIVIDUAL);
    *qkdata_out = qkdata;
    ret = 0;

 done:
    return ret;
}

static int zhpe_zmmu_free(struct zhpeq_mr_desc_v1 *desc)
{
    int                 ret = -EINVAL;
    struct zhpeq_key_data *qkdata = &desc->qkdata;
    struct zdom_data    *bdom = desc->hdr.zdomi->backend_data;
    struct zdom_node    *node = &bdom->nodes[desc->open_idx];

    if (!node->uue)
        goto done;
    if (!(qkdata->z.access & ZHPE_MR_INDIVIDUAL)) {
        mutex_lock(&bdom->node_mutex);
        if (node->big_req_cnt) {
            node->big_req_cnt--;
            if (!node->big_req_cnt) {
                ret = do_rmr_free(node->uue->uuid,
                                  qkdata->rsp_zaddr - qkdata->z.vaddr,
                                  BIG_ZMMU_LEN, BIG_ZMMU_REQ_FLAGS,
                                  node->big_req_zaddr);
                if (ret < 0 && ret != -ENOENT)
                    zhpeu_print_func_err(__func__, __LINE__, "__driver_cmd", "",
                                         ret);
                node->big_req_zaddr = 0;
            } else
                ret = 0;
        } else
            ret = -ENOENT;
        mutex_unlock(&bdom->node_mutex);
    } else
        ret = do_rmr_free(node->uue->uuid, qkdata->rsp_zaddr,
                          qkdata->z.len, qkdata->z.access, qkdata->z.zaddr);

 done:
    return ret;
}

static int zhpe_mmap(const struct zhpeq_mr_desc_v1 *desc_orig,
                     uint32_t cache_mode, void *addr, size_t length,
                     int prot, int flags, off_t offset,
                     struct zhpeq_mmap_desc **zmdesc_out)
{
    int                 ret = -ENOMEM;
    struct zdom_data    *bdom = desc_orig->hdr.zdomi->backend_data;
    struct zdom_node    *node = &bdom->nodes[desc_orig->open_idx];
    struct zhpeq_mmap_desc *zmdesc = NULL;
    struct zhpeq_key_data *qkdata = NULL;
    struct zhpeq_mr_desc_v1 *desc;
    uint64_t            pgoff;

    zmdesc = calloc(1, sizeof(*zmdesc));
    if (!zmdesc)
        goto done;
    desc = malloc(sizeof(*desc));
    if (!desc)
        goto done;
    *desc  = *desc_orig;
    qkdata = &desc->qkdata;
    zmdesc->qkdata = qkdata;
    qkdata->z.vaddr += offset;
    qkdata->z.len -= offset;
    qkdata->rsp_zaddr += offset;
    qkdata->z.access |= cache_mode | ZHPEQ_MR_REQ_CPU | ZHPE_MR_INDIVIDUAL;

    ret = do_rmr_import(node->uue->uuid, qkdata->rsp_zaddr, qkdata->z.len,
                        qkdata->z.access, &qkdata->z.zaddr, &pgoff);
    if (ret < 0) {
        qkdata->z.zaddr = 0;
        goto done;
    }

    zmdesc->addr = _zhpeu_mmap(addr, length, prot, flags, dev_fd, pgoff);
    if (!zmdesc->addr) {
        ret = -errno;
        goto done;
    }

 done:
    if (ret >= 0)
        *zmdesc_out = zmdesc;
    else if (zmdesc) {
        if (zmdesc->qkdata)
            zhpeq_qkdata_free(qkdata);
        free(zmdesc);
    }

    return ret;
}

static int zhpe_mmap_unmap(struct zhpeq_mmap_desc *zmdesc)
{
    int                 ret;
    struct zhpeq_mr_desc_v1 *desc =
        container_of(zmdesc->qkdata, struct zhpeq_mr_desc_v1, qkdata);
    struct zhpeq_key_data *qkdata = &desc->qkdata;
    int                 rc;

    ret = munmap(zmdesc->addr, qkdata->z.len);

    rc = zhpe_zmmu_free(desc);
    if (ret >= 0)
        ret = rc;
    free(zmdesc);

    return ret;
}

static int zhpe_mmap_commit(struct zhpeq_mmap_desc *zmdesc,
                            const void *addr, size_t length, bool fence,
                            bool invalidate, bool wait)
{
    if (!addr && !length && zmdesc) {
        addr = zmdesc->addr;
        length = zmdesc->qkdata->z.len;
    }

    if (invalidate)
        clflush_range(addr, length, fence);
    else
        clwb_range(addr, length, fence);
    if (wait)
        zhpeq_mcommit();
    if (invalidate)
        io_mb();

    return 0;
}

static int zhpe_qkdata_export(const struct zhpeq_key_data *qkdata,
                              struct key_data_packed *blob)
{
    pack_kdata(qkdata, blob, qkdata->z.zaddr);

    return 0;
}

static void zhpe_print_xq_info(struct zhpeq_xqi *xqi)
{
    zhpeu_print_info("GenZ ASIC backend\n");
}

static int zhpe_rq_get_addr(struct zhpeq_rqi *rqi, void *sa, size_t *sa_len)
{
    int                 ret = -EOVERFLOW;
    struct sockaddr_zhpe *sz = sa;

    if (*sa_len < sizeof(*sz))
        goto done;

    sz->sz_family = AF_ZHPE;
    memcpy(sz->sz_uuid, &zhpeq_uuid, sizeof(sz->sz_uuid));
    sz->sz_queue = rqi->zrq.rqinfo.rspctxid;
    ret = 0;

 done:
    *sa_len = sizeof(*sz);

    return ret;
}

static char *zhpe_qkdata_id_str(const struct zhpeq_mr_desc_v1 *desc)
{
    char                *ret = NULL;
    struct zdom_data    *bdom = desc->hdr.zdomi->backend_data;
    char                uuid_str[37];

    if (!(desc->hdr.version & ZHPEQ_MR_REMOTE))
        goto done;

    uuid_unparse_upper(bdom->nodes[desc->open_idx].uue->uuid, uuid_str);
    ret = zhpeu_asprintf(ret, "%d %s", desc->open_idx, uuid_str);
 done:

    return ret;
}

#ifndef ZHPEQ_DIRECT

/* Out of date, but keep for now. */
struct backend_ops ops = {
    .lib_init           = zhpe_lib_init,
    .domain             = zhpe_domain,
    .domain_free        = zhpe_domain_free,
    .qalloc             = zhpe_alloc,
    .qfree              = zhpe_free,
    .open               = zhpe_open,
    .close              = zhpe_close,
    .wq_signal          = zhpe_wq_signal,
    .mr_reg             = zhpe_mr_reg,
    .mr_free            = zhpe_mr_free,
    .qkdata_export      = zhpe_qkdata_export,
    .zmmu_reg           = zhpe_zmmu_reg,
    .zmmu_free          = zhpe_zmmu_free,
    .fam_qkdata         = zhpe_fam_qkdata,
    .mmap               = zhpe_mmap,
    .mmap_unmap         = zhpe_mmap_unmap,
    .mmap_commit        = zhpe_mmap_commit,
    .print_xq_info      = zhpe_print_xq_info,
    .xq_get_addr        = zhpe_get_addr,
    .qkdata_id_str      = zhpe_qkdata_id_str,
};

void zhpeq_backend_zhpe_init(int fd)
{
    if (fd == -1)
        return;

    zhpeq_register_backend(ZHPE_BACKEND_ZHPE, &ops);
}

#endif
