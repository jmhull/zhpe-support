/*
 * Copyright (C) 2019 Hewlett Packard Enterprise Development LP.
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

#undef _ZHPEQ_TEST_COMPAT_
#include <zhpeq.h>
#include <zhpeq_util.h>

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif
#define DEFAULT_POLL    (100U)
#define DEFAULT_QLEN    (1023U)
#define DEFAULT_WARMUP  (100U)
#define DEFAULT_EPOLL   (10000U)

static struct zhpeq_attr zhpeq_attr;

#ifdef NDEBUG
#define DO_LOG          (0)
#else
#define DO_LOG          (1)
#endif

#if DO_LOG

struct log {
    int line;
    uint32_t head;
    uint32_t head_commit;
    uint64_t v[3];
};

struct log dbg_log[4096];

uint32_t dbg_log_idx;

void do_log(uint line, struct zhpeq_rq *zrq,
            uint64_t v0, uint64_t v1, uint64_t v2)
{
    uint32_t i = dbg_log_idx++ & (ARRAY_SIZE(dbg_log) - 1);

    dbg_log[i].line = line;
    if (zrq) {
        dbg_log[i].head = zrq->head;
        dbg_log[i].head_commit = zrq->head_commit;
    } else {
        dbg_log[i].head = 0;
        dbg_log[i].head_commit = 0;
    }
    dbg_log[i].v[0] = v0;
    dbg_log[i].v[1] = v1;
    dbg_log[i].v[2] = v2;
}

#else

static inline void do_log(uint line, struct zhpeq_rq *zrq,
                          uint64_t v0, uint64_t v1, uint64_t v2)
{
}

#endif /* DO_LOG */

struct cli_wire_msg {
    uint64_t            poll_usec;
    uint64_t            rqlen;
    uint64_t            tqlen;
    bool                once_mode;
    bool                pp_only;
};

enum {
    TX_NONE = 0,
    TX_WARMUP,
    TX_RUNNING,
    TX_LAST,
};

struct args {
    const char          *node;
    const char          *service;
    uint64_t            ring_ops;
    uint64_t            warmup;
    uint64_t            rqlen;
    uint64_t            tqlen;
    uint64_t            poll_usec;
    bool                once_mode;
    bool                pp_only;
    bool                seconds_mode;
};

struct timing {
    uint64_t            tot;
    uint64_t            min;
    uint64_t            max;
    uint64_t            cnt;
    uint64_t            skw;
};

struct stuff {
    void                (*free)(void *ptr);
    const struct args   *args;
    struct zhpeq_dom    *zdom;
    struct zhpeq_xq     *zxq;
    struct zhpeq_rq     *zrq;
    int                 sock_fd;
    size_t              ring_ops;
    size_t              ring_warmup;
    uint32_t            msg_tx_seq;
    uint32_t            msg_rx_seq;
    uint32_t            tx_seq;
    uint32_t            tx_oos_max;
    uint32_t            rx_oos_max;
    uint32_t            rx_oos_ent_base;
    uint32_t            rx_oos_ent_cnt;
    struct zhpe_rdm_entry rx_oos_ent[64] CACHE_ALIGNED;
    size_t              tx_oos;
    size_t              rx_oos;
    size_t              tx_retry;
    size_t              epoll_cnt;
    uint64_t            poll_cycles;
    uint64_t            retry_cycles;
    struct timing       tx_lat;
    struct timing       tx_cmp;
    struct timing       rx_lat;
    struct timing       pp_lat;
    struct zhpeq_rq_epoll_ring epoll_ring;
    size_t              tx_avail;
    size_t              tx_max;
    size_t              rqlen;
    size_t              tqlen;
    uint32_t            dgcid;
    uint32_t            rspctxid;
    int                 open_idx;
    uint8_t             qd_last;
    bool                epoll;
};

struct enqa_msg {
    uint64_t            tx_start;
    uint64_t            pp_start;
    uint32_t            msg_seq;
    uint32_t            tx_seq;
    uint8_t             flag;
};

static void timing_reset(struct timing *t)
{
    t->tot = 0;
    t->min = ~(uint64_t)0;
    t->max = 0;
    t->cnt = 0;
    t->skw = 0;
}

static void timing_update(struct timing *t, uint64_t cycles)
{
    if ((int64_t)cycles < 0)
        t->skw++;
    t->tot += cycles;
    t->min = min(t->min, cycles);
    t->max = max(t->max, cycles);
    t->cnt++;
}

static void conn_tx_stats_reset(struct stuff *conn)
{
    timing_reset(&conn->tx_lat);
    timing_reset(&conn->tx_cmp);
}

static void conn_rx_stats_reset(struct stuff *conn)
{
    timing_reset(&conn->rx_lat);
    timing_reset(&conn->pp_lat);
}

static void timing_print(struct timing *t, const char *lbl, uint64_t divisor)
{
    if (!t->cnt)
        return;

    zhpeu_print_info("%s:%s:ave/min/max/cnt/skw %.3lf/%.3lf/%.3lf/%" PRIu64
                     "/%" PRIu64 "\n",
                     zhpeu_appname, lbl,
                     cycles_to_usec(t->tot, t->cnt * divisor),
                     cycles_to_usec(t->min, divisor),
                     cycles_to_usec(t->max, divisor),
                     t->cnt, t->skw);
}

static void conn_stats_print(struct stuff *conn)
{
    timing_print(&conn->pp_lat, "pp_lat", 2);
    timing_print(&conn->tx_lat, "tx_lat", 1);
    timing_print(&conn->tx_cmp, "tx_cmp", 1);
    timing_print(&conn->rx_lat, "rx_lat", 1);
    zhpeu_print_info("%s:tx/rx %u/%u, tx_oos/max/retry %lu/%u/%lu"
                     " rx_oos/max %lu/%u epoll %lu\n",
                     zhpeu_appname, conn->zxq->cq_head, conn->zrq->head,
                     conn->tx_oos, conn->tx_oos_max, conn->tx_retry,
                     conn->rx_oos, conn->rx_oos_max, conn->epoll_cnt);
}

static void stuff_free(struct stuff *stuff)
{
    if (!stuff)
        return;

    zhpeq_rq_epoll_ring_deinit(&stuff->epoll_ring);
    if (stuff->open_idx != -1)
        zhpeq_xq_backend_close(stuff->zxq, stuff->open_idx);
    zhpeq_rq_free(stuff->zrq);
    zhpeq_xq_free(stuff->zxq);
    zhpeq_domain_free(stuff->zdom);

    FD_CLOSE(stuff->sock_fd);
}

static int conn_tx_msg(struct stuff *conn, uint64_t pp_start,
                       uint32_t msg_seq, uint8_t flag)
{
    int32_t             ret;
    struct zhpeq_xq     *zxq = conn->zxq;
    uint64_t            start = get_cycles(NULL);
    struct enqa_msg     *msg;

    ret = zhpeq_xq_reserve(zxq);
    if (ret < 0) {
        if (ret != -EAGAIN)
            zhpeu_print_func_err(__func__, __LINE__, "zhpeq_xq_reserve", "",
                                 ret);
        goto done;
    }
    msg = zhpeq_xq_enqa(zxq, ret, 0, conn->dgcid, conn->rspctxid);
    zhpeq_xq_set_context(zxq, ret, msg);
    msg->tx_start = htobe64(start);
    if (!pp_start)
        pp_start = msg->tx_start;
    msg->pp_start = pp_start;
    msg->msg_seq = msg_seq;
    msg->tx_seq = conn->tx_seq++;
    msg->flag = flag;
    zhpeq_xq_insert(zxq, ret, false);
    zhpeq_xq_commit(zxq);
    conn->tx_avail--;
    timing_update(&conn->tx_lat, get_cycles(NULL) - start);
    do_log(__LINE__, NULL, conn->tx_seq - 1, be32toh(msg_seq), 0);
 done:

    return ret;
}

#define _conn_tx_msg(...)                                       \
    zhpeu_call_neg_errorok(zhpeu_err, conn_tx_msg,  int, -EAGAIN, __VA_ARGS__)

static int conn_tx_completions(struct stuff *conn, bool qfull_ok,
                               bool qd_check);

#define _conn_tx_completions(...)                               \
    zhpeu_call_neg(zhpeu_err, conn_tx_completions,  int, __VA_ARGS__)

static int conn_tx_msg_retry(struct stuff *conn, uint64_t pp_start,
                             uint32_t msg_seq, uint8_t flag)
{
    int                 ret;

    for (;;) {
        ret = _conn_tx_msg(conn, pp_start, msg_seq, flag);
        if (ret >= 0 || ret != -EAGAIN)
            break;
        ret = _conn_tx_completions(conn, false, false);
        if (ret < 0)
            break;
    }

    return ret;
}

#define _conn_tx_msg_retry(...)                                 \
    zhpeu_call_neg(zhpeu_err, conn_tx_msg_retry,  int, __VA_ARGS__)

static int conn_tx_completions(struct stuff *conn, bool qfull_ok, bool qd_check)
{
    ssize_t             ret = 0;
    struct zhpeq_xq     *zxq = conn->zxq;
    struct enqa_msg     *msg;
    struct enqa_msg     msg_copy;
    int32_t             oos;
    struct zhpe_cq_entry *cqe;
    struct zhpe_cq_entry cqe_copy;

    while ((cqe = zhpeq_xq_cq_entry(zxq))) {
        conn->tx_avail++;
        msg = zhpeq_xq_cq_context(zxq, cqe);
        do_log(__LINE__, NULL, msg->tx_seq, zxq->cq_head, 0);
        /* unlikely() to optimize the no-error case. */
        if (unlikely(cqe->status != ZHPEQ_XQ_CQ_STATUS_SUCCESS)) {
            cqe_copy = *cqe;
            msg_copy = *msg;
            zhpeq_xq_cq_entry_done(zxq, cqe);
            ret = -EIO;
            if (cqe_copy.status != ZHPE_HW_CQ_STATUS_GENZ_RDM_QUEUE_FULL) {
                zhpeu_print_err("%s,%u:cqe %p ctx %p index 0x%x status 0x%x\n",
                                __func__, __LINE__, cqe, msg,
                                cqe_copy.index, cqe_copy.status);
            } else if (!qfull_ok) {
                /*
                 * Retry: given that we're single threaded and we just
                 * freed a tx slot, EAGAIN should not be possible.
                 */
                do_log(__LINE__, NULL, conn->tx_retry, 0, 0);
                conn->tx_retry++;
                ret = _conn_tx_msg(conn, msg_copy.pp_start, msg_copy.msg_seq,
                                   msg_copy.flag);
            }
            goto done;
        }
        timing_update(&conn->tx_cmp, get_cycles(NULL) - be64toh(msg->tx_start));
        oos = (int32_t)(msg->tx_seq - zxq->cq_head);
        zhpeq_xq_cq_entry_done(zxq, cqe);
        if (unlikely(oos)) {
            conn->tx_oos++;
            conn->tx_oos_max = max(conn->tx_oos_max, (uint32_t)abs(oos));
        }
    }
 done:

    return ret;
}

static ssize_t conn_tx_completions_wait(struct stuff *conn, bool qfull_ok,
                                       bool qd_check)
{
    int                 ret = 0;

    while (conn->tx_avail != conn->tx_max && !ret)
        ret = conn_tx_completions(conn, qfull_ok, qd_check);

    return ret;
}

#define _conn_tx_completions_wait(...)                          \
    zhpeu_call_neg(zhpeu_err, conn_tx_completions_wait, int,  __VA_ARGS__)

static int conn_rx_oos_insert(struct stuff *conn, struct zhpe_rdm_entry *rqe,
                              int32_t oos)
{
    int                 ret = 0;
    uint32_t            off = oos + (conn->msg_rx_seq - conn->rx_oos_ent_base);

    assert(off < ARRAY_SIZE(conn->rx_oos_ent));
    if (off >= ARRAY_SIZE(conn->rx_oos_ent)) {
        ret = -EOVERFLOW;
        goto done;
    }
    conn->rx_oos++;
    conn->rx_oos_max = max(conn->rx_oos_max, (uint32_t)oos);
    conn->rx_oos_ent_cnt++;
    conn->rx_oos_ent[off] = *rqe;
    conn->rx_oos_ent[off].hdr.valid = 1;
    /* Advance the queue head, but not conn->rx_seq. */
    zhpeq_rq_entry_done(conn->zrq, rqe);
    zhpeq_rq_head_update(conn->zrq, false);
 done:
    return ret;
}

static int conn_rx_oos_saved(struct stuff *conn, struct enqa_msg *msg_out)
{
    int                 ret = 0;
    struct enqa_msg     *msg;
    uint32_t            off;

    /*
     * If there is a saved entry for the current conn->msg_rx_seq,
     * we return it and advance conn->msg_rx_seq.
     */
    off = conn->msg_rx_seq - conn->rx_oos_ent_base;
    assert(off < ARRAY_SIZE(conn->rx_oos_ent));
    if (off >= ARRAY_SIZE(conn->rx_oos_ent)) {
        ret = -EOVERFLOW;
        goto done;
    }
    if (conn->rx_oos_ent[off].hdr.valid) {
        conn->rx_oos_ent_cnt--;
        msg = (void *)conn->rx_oos_ent[off].payload;
        *msg_out = *msg;
        conn->rx_oos_ent[off].hdr.valid = 0;
        ret = 1;
        conn->msg_rx_seq++;
    }
 done:

    return ret;
}

static int conn_rx_oos(struct stuff *conn, struct enqa_msg *msg_out,
                       int32_t oos, struct zhpe_rdm_entry *rqe)
{
    int                 ret;
    struct enqa_msg     *msg = (void *)rqe->payload;

    assert(oos > 0);
    do_log(__LINE__, conn->zrq, conn->msg_rx_seq, be32toh(msg->msg_seq), 0);
    /* Example: 0, 3, 2, 1, 4, ...  */
    if (!conn->rx_oos_ent_cnt) {
        conn->rx_oos_ent_base = conn->msg_rx_seq;
        ret = conn_rx_oos_insert(conn, rqe, oos);
        goto done;
    }
    ret = conn_rx_oos_saved(conn, msg_out);
    if (!ret)
        ret = conn_rx_oos_insert(conn, rqe, oos);
 done:

    return ret;
}

static void cycles_delay(uint64_t start_cyc, uint64_t delay_cyc)
{
    while (get_cycles(NULL) - start_cyc < delay_cyc)
        yield();

}

static int conn_rx_msg(struct stuff *conn, struct enqa_msg *msg_out,
                       bool sleep_ok)
{
    int                 ret = 0;
    struct zhpeq_rq     *zrq = conn->zrq;
    struct zhpe_rdm_entry *rqe;
    struct enqa_msg     *msg;
    int32_t             oos;

    for (;;) {
        if (unlikely(conn->epoll)) {
            ret = zhpeq_rq_epoll((sleep_ok ? -1 : 0), NULL, false,
                                 zhpeq_rq_epoll_ring_ready, &conn->epoll_ring);
            if (likely(ret > 0)) {
                assert(ret == 1);
                zrq = zhpeq_rq_epoll_ring_read(&conn->epoll_ring);
                assert(zrq == conn->zrq);
                conn->epoll = false;
            } else if (!ret) {
                assert(!sleep_ok);
                /* Check for an out of sequence final packet. */
                if (conn->rx_oos_ent_cnt)
                    ret = conn_rx_oos_saved(conn, msg_out);
                break;
            } else
                break;
        }
        io_rmb();
        if ((rqe = zhpeq_rq_entry(zrq))) {
            msg = (void *)rqe->payload;
            oos = (int32_t)(be32toh(msg->msg_seq) - conn->msg_rx_seq);
            if (likely(!oos)) {
                *msg_out = *msg;
                zhpeq_rq_entry_done(zrq, rqe);
                zhpeq_rq_head_update(zrq, false);
                conn->msg_rx_seq++;
                ret = 1;
            } else
                ret = conn_rx_oos(conn, msg_out, oos, rqe);
            break;
        }
        if (!conn->epoll) {
            ret = zhpeq_rq_wait_check(conn->zrq, conn->poll_cycles);
            if (unlikely(ret)) {
                if (ret > 0) {
                    conn->epoll = true;
                    conn->epoll_cnt++;
                } else {
                    zhpeu_print_func_err(__func__, __LINE__,
                                         "zhpeq_rq_wait_check", "", ret);
                    break;
                }
            }
        }
        if (!sleep_ok) {
            ret = 0;
            break;
        }
    }
    if (ret > 0)
        do_log(__LINE__, zrq, conn->msg_rx_seq, be32toh(msg_out->msg_seq), 0);

    return ret;
}

#define _conn_rx_msg(...)                                       \
    zhpeu_call_neg(zhpeu_err, conn_rx_msg,  int, __VA_ARGS__)

static int do_server_tests(struct stuff *conn)
{
    int                 ret;
    uint64_t            i;
    struct enqa_msg     msg;

    /*
     * First, the client will send conn->rqlen  + 1 messages to overrun the
     * receive queue. We will not read the receive queue until the server
     * handshakes over the socket.
     */
    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Receive all the pending entries. */
    conn_rx_stats_reset(conn);
    for (i = 0; i < conn->rqlen; i++) {
        ret = _conn_rx_msg(conn, &msg, false);
        if (ret < 0)
            goto done;
        if (!ret)
            continue;
    }

    conn_stats_print(conn);

    /* Second, an epoll test. Server rate limits to force epoll. */
    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Receive all pending entries. */
    conn_rx_stats_reset(conn);
    for (i = 0; i < DEFAULT_EPOLL; i++) {
        ret = _conn_rx_msg(conn, &msg, true);
        if (ret < 0)
            goto done;
        assert(ret == 1);
    }

    conn_stats_print(conn);

    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
 done:

    return ret;
}

static int do_server_pong(struct stuff *conn)
{
    int                 ret = 0;
    const struct args   *args = conn->args;
    uint                tx_flag_in = TX_NONE;
    uint64_t            op_count;
    uint64_t            warmup_count;
    struct enqa_msg     msg;

    zhpeq_print_xq_info(conn->zxq);

    /* Tests for QD, overflow, and epoll. */
    if (!args->pp_only) {
        ret = do_server_tests(conn);
        if (ret < 0)
            goto done;
    }

    /* Ping-pong test. Handshake before beginning. */
    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Server only sends as many times as it receives. */
    conn_tx_stats_reset(conn);
    conn_rx_stats_reset(conn);
    for (op_count = warmup_count = 0; tx_flag_in != TX_LAST; op_count++) {
        /*
         * Receive a packet, send a packet: we are guaranteed the messages are
         * in sequence; we send an immediate reply to so we don't have to
         * buffer the messages to be able to reflect the pp_start and flag
         * to the client.
         */
        for (;;) {
            ret = _conn_rx_msg(conn, &msg, false);
            if (unlikely(ret < 0))
                goto done;
            if (ret > 0)
                break;
        }
        if (msg.flag != tx_flag_in) {
            if (tx_flag_in == TX_WARMUP) {
                warmup_count = op_count;
                conn_tx_stats_reset(conn);
                conn_rx_stats_reset(conn);
            }
            tx_flag_in = msg.flag;
        }
        timing_update(&conn->rx_lat, get_cycles(NULL) - be64toh(msg.tx_start));

        ret = _conn_tx_msg_retry(conn, msg.pp_start,
                                 htobe32(conn->msg_tx_seq++),  msg.flag);
        if (ret < 0)
            goto done;
    }

    /* Wait for all transmits to complete. */
    ret = _conn_tx_completions_wait(conn, false, false);
    if (ret < 0)
        goto done;

    zhpeu_print_info("%s:op_cnt/warmup %lu/%lu\n",
                     zhpeu_appname, op_count - warmup_count, warmup_count);
    conn_stats_print(conn);
 done:

    return ret;
}

static int do_nop(struct stuff *conn)
{
    int                 ret;
    struct zhpeq_xq     *zxq = conn->zxq;
    struct zhpe_cq_entry *cqe;
    uint                i;
    uint64_t            start;

    conn_tx_stats_reset(conn);
    for (i = 0; i < 5; i++) {
        ret = zhpeq_xq_reserve(zxq);
        if (ret < 0) {
            if (ret != -EAGAIN)
                zhpeu_print_func_err(__func__, __LINE__, "zhpeq_xq_reserve", "",
                                     ret);
            goto done;
        }
        zhpeq_xq_nop(zxq, ret, 0);
        start = get_cycles(NULL);
        zhpeq_xq_insert(zxq, ret, false);
        zhpeq_xq_commit(zxq);
        while (!(cqe = zhpeq_xq_cq_entry(zxq)));
        timing_update(&conn->tx_cmp, get_cycles(NULL) - start);
        zhpeq_xq_cq_entry_done(zxq, cqe);
    }
    conn_stats_print(conn);
 done:

    return ret;
}

static int do_client_tests(struct stuff *conn)
{
    int                 ret;
    uint64_t            i;
    uint64_t            start;

    /*
     * First, the client will send conn->rqlen + 1 messages and then
     * handshake across the socket until the server empties the RDM
     * queue.
     *
     * The final message should result in status 0x93 and the queue
     * should not be stopped if the bridge is properly configured.
     *
     * The client will wait for each send, so they should complete
     * on both sides in order. The QD bits should be appearing in the
     * XDM reponses as the RDM queue fills up, but this seems not to be
     * working.
     */
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    conn_tx_stats_reset(conn);
    for (i = 0; i < conn->rqlen; i++) {
        ret = _conn_tx_msg_retry(conn, 0, htobe32(conn->msg_tx_seq++), 0);
        if (ret < 0)
            goto done;
        ret = _conn_tx_completions_wait(conn, false, true);
        if (ret < 0)
            goto done;
    }
    /* No sequence because it is expected to fail. */
    ret = _conn_tx_msg_retry(conn, 0, 0, 0);
    if (ret < 0)
        goto done;
    ret = conn_tx_completions_wait(conn, true, true);
    assert(ret == -EIO);

    conn_stats_print(conn);

    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /*
     * Second, a test of polling behavor: the client will send 10000 messages
     * with a minimum delay of 2 * poll_cycles between them. This should cause
     * the should the server to use epoll for each message.
     */
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    conn_tx_stats_reset(conn);
    for (i = 0; i < DEFAULT_EPOLL; i++) {
        start = get_cycles(NULL);
        ret = _conn_tx_msg_retry(conn, 0, htobe32(conn->msg_tx_seq++), 0);
        if (ret < 0)
            goto done;
        ret = _conn_tx_completions_wait(conn, false, false);
        if (ret < 0)
            goto done;
        cycles_delay(start, conn->poll_cycles * 2);
    }

    conn_stats_print(conn);

    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

 done:

    return ret;
}

static int do_client_pong(struct stuff *conn)
{
    int                 ret = 0;
    const struct args   *args = conn->args;
    uint                tx_flag_in = TX_NONE;
    uint                tx_flag_out = TX_WARMUP;
    uint64_t            rx_avail = min(conn->tx_max, conn->rqlen);
    uint64_t            tx_count;
    uint64_t            rx_count;
    uint64_t            warmup_count;
    struct enqa_msg     msg;
    uint64_t            start;
    uint64_t            now;
    uint64_t            delta;

    zhpeq_print_xq_info(conn->zxq);

    /* Do 5 nop's to measure completion write time. */
    ret = do_nop(conn);
    if (ret < 0)
        goto done;

    /* Tests for QD, overflow, and epoll. */
    if (!args->pp_only) {
        ret = do_client_tests(conn);
        if (ret < 0)
            goto done;
    }

    /* Ping-pong test. Handshake before beginning. */
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /*
     * Client tracks notional numbers of receives available and
     * doesn't overrun the server.
     */
    conn_tx_stats_reset(conn);
    conn_rx_stats_reset(conn);
    start = get_cycles(NULL);
    for (tx_count = rx_count = warmup_count = 0;
         tx_count != rx_count || tx_flag_out != TX_LAST; ) {
        /* Receive packets up to first miss. */
        for (;tx_flag_in != TX_LAST; rx_count++) {
            ret = _conn_rx_msg(conn, &msg, false);
            if (unlikely(ret < 0))
                goto done;
            if (!ret)
                break;
            /* Messages are in sequence. */
            rx_avail++;
            if (msg.flag != tx_flag_in) {
                if (tx_flag_in == TX_WARMUP) {
                    warmup_count = rx_count;
                    conn_rx_stats_reset(conn);
                }
                tx_flag_in = msg.flag;
            }
            now = get_cycles(NULL);
            timing_update(&conn->rx_lat, now - be64toh(msg.tx_start));
            timing_update(&conn->pp_lat, now - be64toh(msg.pp_start));
        }

        ret = _conn_tx_completions(conn, false, false);
        if (ret < 0)
            goto done;

        /* Send all available buffers. */
        for (; rx_avail > 0 && tx_flag_out != TX_LAST; tx_count++, rx_avail--) {

            /* Compute delta based on cycles/ops. */
            if (args->seconds_mode)
                delta = get_cycles(NULL) - start;
            else
                delta = tx_count;

            /* Handle switching between warmup/running/last. */
            switch (tx_flag_out) {

            case TX_WARMUP:
                if (delta < conn->ring_warmup)
                    break;
                tx_flag_out = TX_RUNNING;
                conn_tx_stats_reset(conn);
                /* FALLTHROUGH */

            case TX_RUNNING:
                if  (delta >= conn->ring_ops - 1)
                    tx_flag_out = TX_LAST;
                break;

            default:
                zhpeu_print_err("%s,%u:Unexpected state %d\n",
                                __func__, __LINE__, tx_flag_out);
                ret = -EINVAL;
                goto done;
            }

            ret = _conn_tx_msg(conn, 0, htobe32(conn->msg_tx_seq), tx_flag_out);
            if (ret < 0) {
                if (ret == -EAGAIN) {
                    if (tx_flag_out == TX_LAST)
                        tx_flag_out = TX_RUNNING;
                    break;
                }
                goto done;
            }
            conn->msg_tx_seq++;
        }
    }

    zhpeu_print_info("%s:op_cnt/warmup %lu/%lu\n",
                     zhpeu_appname, tx_count - warmup_count, warmup_count);
    conn_stats_print(conn);
 done:

    return ret;
}

struct q_wire_msg {
    /* Actual queue lengths. */
    uint64_t            rqlen;
    uint64_t            tqlen;
};

int do_q_setup(struct stuff *conn)
{
    int                 ret;
    const struct args   *args = conn->args;
    union sockaddr_in46 sa;
    size_t              sa_len = sizeof(sa);
    struct q_wire_msg   q_msg;

    ret = -EINVAL;
    conn->tqlen = args->tqlen;
    if (conn->tqlen) {
        if (conn->tqlen > zhpeq_attr.z.max_tx_qlen)
            goto done;
    } else
        conn->tqlen = DEFAULT_QLEN;

    conn->rqlen = args->rqlen;
    if (conn->rqlen) {
        if (conn->rqlen > zhpeq_attr.z.max_rx_qlen)
            goto done;
    } else
        conn->rqlen = DEFAULT_QLEN;

    conn->poll_cycles = usec_to_cycles(args->poll_usec ?: DEFAULT_POLL);

    /* Allocate domain. */
    ret = zhpeq_domain_alloc(&conn->zdom);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", ret);
        goto done;
    }
    /* Allocate zqueues. */
    ret = zhpeq_xq_alloc(conn->zdom, conn->tqlen, conn->tqlen,
                         0, 0, 0,  &conn->zxq);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_xq_alloc", "", ret);
        goto done;
    }
    /*
     * conn->tqlen is the actual size of the tx queue; conn->tx_max is the
     * requested size of the tx queue. This will allow the user to
     * specify 16 and user only command buffers.
     */
    conn->tx_max = conn->tx_avail = conn->tqlen;
    conn->tqlen = conn->zxq->xqinfo.cmdq.ent - 1;

    ret = zhpeq_rq_alloc(conn->zdom, conn->rqlen, 0, &conn->zrq);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_rq_alloc", "", ret);
        goto done;
    }
    conn->rqlen = conn->zrq->rqinfo.cmplq.ent - 1;
    if (!zhpeu_expected_saw("qlen1", conn->zxq->xqinfo.cmdq.ent,
                            conn->zxq->xqinfo.cmplq.ent)) {
        ret = -EIO;
        goto done;
    }

    /* Paranoia:exchange and compare queue lengths between client and server. */
    q_msg.rqlen = htobe64(conn->rqlen);
    q_msg.tqlen = htobe64(conn->tqlen);
    ret = _zhpeu_sock_send_blob(conn->sock_fd, &q_msg, sizeof(q_msg));
    if (ret < 0)
        goto done;
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, &q_msg, sizeof(q_msg));
    if (ret < 0)
        goto done;
    q_msg.rqlen = be64toh(q_msg.rqlen);
    q_msg.tqlen = be64toh(q_msg.tqlen);
    if (!zhpeu_expected_saw("qlen2", conn->rqlen, q_msg.rqlen) ||
        !zhpeu_expected_saw("qlen3", conn->rqlen, q_msg.rqlen)) {
        ret = -EIO;
        goto done;
    }

    /* Exchange addresses. */
    ret = zhpeq_rq_xchg_addr(conn->zrq, conn->sock_fd, &sa, &sa_len);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_xq_xchg_addr", "", ret);
        goto done;
    }
    if (!zhpeu_expected_saw("sa_family", zhpeu_sockaddr_family(&sa), AF_ZHPE)) {
        ret = -EIO;
        goto done;
    }
    conn->dgcid = zhpeu_uuid_to_gcid(sa.zhpe.sz_uuid);
    conn->rspctxid = sa.zhpe.sz_queue;

    /* Do setup for remote. */
    ret = zhpeq_xq_backend_open(conn->zxq, &sa);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_xq_backend_open",
                             "", ret);
        goto done;
    }
    conn->open_idx = ret;

    /* Initalize epoll_ring. */
    ret = zhpeq_rq_epoll_ring_init(&conn->epoll_ring, 4);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_rq_epoll_ring",
                             "", ret);
        goto done;
    }
    conn->epoll = true;
 done:

    return ret;
}

static int do_server_one(const struct args *oargs, int conn_fd)
{
    int                 ret;
    struct args         one_args = *oargs;
    struct args         *args = &one_args;
    struct stuff        conn = {
        .args           = args,
        .sock_fd        = conn_fd,
        .open_idx       = -1,
    };
    struct cli_wire_msg cli_msg;

    /* Receive parameters from client. */
    ret = _zhpeu_sock_recv_fixed_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    args->poll_usec = be64toh(cli_msg.poll_usec);
    args->rqlen = be64toh(cli_msg.rqlen);
    args->tqlen = be64toh(cli_msg.tqlen);
    args->once_mode = cli_msg.once_mode;
    args->pp_only = cli_msg.pp_only;

    ret = do_q_setup(&conn);
    if (ret < 0)
        goto done;

    /* Run test. */
    ret = do_server_pong(&conn);
    if (ret < 0)
        goto done;

    /* Completion handshake. */
    ret = _zhpeu_sock_recv_fixed_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
    ret = _zhpeu_sock_send_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

 done:
    stuff_free(&conn);

    if (ret >= 0)
        ret = (cli_msg.once_mode ? 1 : 0);

    return ret;
}

static int do_server(const struct args *args)
{
    int                 ret;
    int                 listener_fd = -1;
    int                 conn_fd = -1;
    struct addrinfo     *resp = NULL;
    int                 oflags = 1;

    ret = _zhpeu_sock_getaddrinfo(NULL, args->service,
                                  AF_INET6, SOCK_STREAM, true, &resp);
    if (ret < 0)
        goto done;
    listener_fd = socket(resp->ai_family, resp->ai_socktype,
                         resp->ai_protocol);
    if (listener_fd == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "socket", "", ret);
        goto done;
    }
    if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR,
                   &oflags, sizeof(oflags)) == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "setsockopt", "", ret);
        goto done;
    }
    /* None of the usual: no polling; no threads; no cloexec; no nonblock. */
    if (bind(listener_fd, resp->ai_addr, resp->ai_addrlen) == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "bind", "", ret);
        goto done;
    }
    if (listen(listener_fd, BACKLOG) == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "listen", "", ret);
        goto done;
    }
    for (ret = 0; !ret;) {
        conn_fd = accept(listener_fd, NULL, NULL);
        if (conn_fd == -1) {
            ret = -errno;
            zhpeu_print_func_err(__func__, __LINE__, "accept", "", ret);
            goto done;
        }
        ret = do_server_one(args, conn_fd);
    }

done:
    if (listener_fd != -1)
        close(listener_fd);
    if (resp)
        freeaddrinfo(resp);

    return ret;
}

static int do_client(const struct args *args)
{
    int                 ret;
    struct stuff        conn = {
        .args           = args,
        .sock_fd        = -1,
        .open_idx       = -1,
        .ring_ops       = args->ring_ops,
    };
    struct cli_wire_msg cli_msg;

    ret = _zhpeu_sock_connect(args->node, args->service);
    if (ret < 0)
        goto done;
    conn.sock_fd = ret;

    /* Send arguments to the server. */
    cli_msg.poll_usec = htobe64(args->poll_usec);
    cli_msg.rqlen = htobe64(args->rqlen);
    cli_msg.tqlen = htobe64(args->tqlen);
    cli_msg.once_mode = args->once_mode;
    cli_msg.pp_only = args->pp_only;

    ret = _zhpeu_sock_send_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    conn.ring_warmup = args->warmup;
    /* Compute warmup operations. */
    if (args->seconds_mode) {
        if (conn.ring_warmup == SIZE_MAX)
            conn.ring_warmup = 1;
        conn.ring_ops += conn.ring_warmup;
        conn.ring_warmup *= get_tsc_freq();
        conn.ring_ops *= get_tsc_freq();
    } else if (conn.ring_warmup == SIZE_MAX) {
        conn.ring_warmup = conn.ring_ops / 10;
        if (conn.ring_warmup < DEFAULT_WARMUP)
            conn.ring_warmup = DEFAULT_WARMUP;
        conn.ring_ops += conn.ring_warmup;
    }

    /* Build the queues before sending parameters to server. */
    ret = do_q_setup(&conn);
    if (ret < 0)
        goto done;

    /* Run test. */
    ret = do_client_pong(&conn);
    if (ret < 0)
        goto done;

    /* Completion handshake. */
    ret = _zhpeu_sock_send_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
    ret = _zhpeu_sock_recv_fixed_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
 done:
    stuff_free(&conn);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    zhpeu_print_usage(
        help,
        "Usage:%s [-os] ] -p <poll_usec> ] [-q <qlen>] [-w <warmup_ops]\n"
        "    <port> [<node> <op_count/seconds>]\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "Server requires just port; client requires all 3 arguments.\n"
        "Client only options:\n"
        " -o : run once and then server will exit\n"
        " -P : ping-pong test only\n"
        " -p <poll_usec> : length of receive polling before sleeping\n"
        " -r <qlen> : rx queue length (default %u)\n"
        " -s : treat the final argument as seconds\n"
        " -t <qlen> : tx queue length (default %u)\n"
        " -w <ops> : number of warmup operations\n",
        zhpeu_appname, DEFAULT_QLEN, DEFAULT_QLEN);

    if (help)
        zhpeq_print_xq_info(NULL);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = {
        .warmup         = SIZE_MAX,
    };
    bool                client_opt = false;
    int                 opt;
    int                 rc;

    zhpeu_util_init(argv[0], LOG_INFO, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION);
    if (rc < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    rc = zhpeq_query_attr(&zhpeq_attr);
    if (rc < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_query_attr", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "oPp:r:st:w:")) != -1) {

        /* All opts are client only, now. */
        client_opt = true;

        switch (opt) {

        case 'o':
            if (args.once_mode)
                usage(false);
            args.once_mode = true;
            break;

        case 'P':
            if (args.pp_only)
                usage(false);
            args.pp_only = true;
            break;

        case 'p':
            if (args.poll_usec)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("poll_usec", optarg, &args.poll_usec,
                                         0, 1, SIZE_MAX,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 'r':
            if (args.rqlen)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("rlen", optarg, &args.rqlen, 0, 1,
                                         zhpeq_attr.z.max_rx_qlen,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 's':
            if (args.seconds_mode)
                usage(false);
            args.seconds_mode = true;
            break;

        case 't':
            if (args.tqlen)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("tqlen", optarg, &args.tqlen, 0, 1,
                                         zhpeq_attr.z.max_tx_qlen,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 'w':
            if (args.warmup != SIZE_MAX)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("warmup", optarg, &args.warmup, 0, 0,
                                         SIZE_MAX - 1,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        default:
            usage(false);

        }
    }

    opt = argc - optind;

    if (opt == 1) {
        args.service = argv[optind++];
        if (client_opt)
            usage(false);
        if (do_server(&args) < 0)
            goto done;
    } else if (opt == 3) {
        args.service = argv[optind++];
        args.node = argv[optind++];
        if (_zhpeu_parse_kb_uint64_t(
                (args.seconds_mode ? "seconds" : "op_counts"),
                argv[optind++], &args.ring_ops, 0, 1,
                (args.seconds_mode ? 1000000 : SIZE_MAX),
                PARSE_KB | PARSE_KIB) < 0)
            usage(false);
        if (do_client(&args) < 0)
            goto done;
    } else
        usage(false);

    ret = 0;
 done:

    return ret;
}
