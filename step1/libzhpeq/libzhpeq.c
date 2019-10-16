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

#include <internal.h>

#include <cpuid.h>
#include <dlfcn.h>
#include <limits.h>

#define LIBNAME         "libzhpeq"

static_assert(sizeof(union zhpe_hw_wq_entry) ==  ZHPE_ENTRY_LEN,
              "zhpe_hw_wq_entry");
static_assert(sizeof(union zhpe_hw_cq_entry) ==  ZHPE_ENTRY_LEN,
              "zhpe_hw_cq_entry");
static_assert(__BYTE_ORDER == __LITTLE_ENDIAN, "Only little endian supported");

/* Set to 1 to dump qkdata when registered/exported/imported/freed. */
#define QKDATA_DUMP     (0)

static pthread_mutex_t  init_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct zhpeq_attr b_attr;

enum ins_idx {
    INS_CMD             = 0,
    INS_MEM,
    INS_LEN,
};

zhpeq_xq_entry_insert_fn zhpeq_insert[INS_LEN];
void                    (*zhpeq_mcommit)(void);
uuid_t                  zhpeq_uuid;

static inline union zhpe_hw_wq_entry *xq_get_wq(struct zhpeq_xq *zxq)
{
    size_t              i = zxq->wq_tail++ & (zxq->xqinfo.cmdq.ent - 1);

    return &zxq->wq[i];
}

static void cmd_insert64(struct zhpeq_xq *zxq, uint16_t reservation16)
{
    union zhpe_hw_wq_entry *src = &zxq->mem[reservation16];
    union zhpe_hw_wq_entry *dst = &zxq->cmd[reservation16];
    size_t              i;

    for (i = 1; i < ARRAY_SIZE(dst->bytes8); i++)
        iowrite64(src->bytes8[i], &dst->bytes8[i]);
    iowrite64(src->bytes8[0], &dst->bytes8[0]);
}

static void mem_insert64(struct zhpeq_xq *zxq, uint16_t reservation16)
{
    union zhpe_hw_wq_entry *src = &zxq->mem[reservation16];
    union zhpe_hw_wq_entry *dst = xq_get_wq(zxq);

    memcpy(dst, src, sizeof(*dst));
}

static void cmd_insert128(struct zhpeq_xq *zxq, uint16_t reservation16)
{
    union zhpe_hw_wq_entry *src = &zxq->mem[reservation16];
    union zhpe_hw_wq_entry *dst = &zxq->cmd[reservation16];

    asm volatile (
        "vmovdqa   (%[s]), %%xmm0\n"
        "vmovdqa 16(%[s]), %%xmm1\n"
        "vmovdqa 32(%[s]), %%xmm2\n"
        "vmovdqa 48(%[s]), %%xmm3\n"
        "vmovdqa   %%xmm1, 16(%[d])\n"
        "vmovdqa   %%xmm2, 32(%[d])\n"
        "vmovdqa   %%xmm3, 48(%[d])\n"
        "vmovdqa   %%xmm0,   (%[d])\n"
        : "=m" (*dst): [s] "r" (src), [d] "r" (dst)
        : "%xmm0", "%xmm1", "%xmm2", "%xmm3");
}

static void cmd_insert256(struct zhpeq_xq *zxq, uint16_t reservation16)
{
    union zhpe_hw_wq_entry *src = &zxq->mem[reservation16];
    union zhpe_hw_wq_entry *dst = &zxq->cmd[reservation16];

    asm volatile (
        "vmovdqa   (%[s]), %%ymm0\n"
        "vmovdqa 32(%[s]), %%ymm1\n"
        "vmovdqa   %%ymm1, 32(%[d])\n"
        "vmovdqa   %%ymm0,   (%[d])\n"
        : "=m" (*dst) : [s] "r" (src), [d] "r" (dst) : "%ymm0", "%ymm1");
}

static void mem_insert256(struct zhpeq_xq *zxq, uint16_t reservation16)
{
    union zhpe_hw_wq_entry *src = &zxq->mem[reservation16];
    union zhpe_hw_wq_entry *dst = xq_get_wq(zxq);

    asm volatile (
        "vmovdqa   (%[s]), %%ymm0\n"
        "vmovdqa 32(%[s]), %%ymm1\n"
        "vmovntdq  %%ymm0,   (%[d])\n"
        "vmovntdq  %%ymm1, 32(%[d])\n"
        : "=m" (*dst) : [s] "r" (src), [d] "r" (dst) : "%ymm0", "%ymm1");
}

static void do_mcommit(void)
{
    mcommit();
}

static void no_mcommit(void)
{
}

#ifdef ZHPEQ_DIRECT

#define CPUID_0000_0007                 (0x00000007)
#define CPUID_0000_0007_SUB_0           (0x0)
#define CPUID_0000_0007_SUB_0_EBX_AVX2  (0x20)

static void __attribute__((constructor)) lib_init(void)
{
    uint                eax;
    uint                ebx;
    uint                ecx;
    uint                edx;

    /* Defaults for Carbon. */
    zhpeq_insert[INS_CMD] = cmd_insert64;
    zhpeq_insert[INS_MEM] = mem_insert64;
    zhpeq_mcommit = no_mcommit;

    /*
     * Both Naples and Rome support AVX2, Carbon does not. Naples
     * supports 16 byte UC writes, Rome supports 32. I will assume
     * MCOMMIT cannot be enabled if AVX2 isn't supported and that
     * MCOMMIT is a good proxy for 32 byte UC writes.
     *
     * The driver won't load on Intel platforms, so I'm not going
     * to bother verifying AMD CPUs, here.
     */
    if (__get_cpuid_count(CPUID_0000_0007, CPUID_0000_0007_SUB_0,
                          &eax, &ebx, &ecx, &edx) &&
        (ebx & CPUID_0000_0007_SUB_0_EBX_AVX2)) {
        zhpeq_insert[INS_MEM] = mem_insert256;
        /*
         * We assume the driver enabled mcommit if it is possible.
         * Since mcommit is supported on Rome and not on Naples, I'll
         * use that as test the PCI 32-byte writes work.
         */
        if (__get_cpuid(CPUID_8000_0008, &eax, &ebx, &ecx, &edx) &&
            (ebx & CPUID_8000_0008_EBX_MCOMMIT)) {
            zhpeq_mcommit = do_mcommit;
            zhpeq_insert[INS_CMD] = cmd_insert256;
        } else
            zhpeq_insert[INS_CMD] = cmd_insert128;
    }
    if (getenv("ZHPEQ_DISABLE_CMD_BUF"))
        zhpeq_insert[INS_CMD] = zhpeq_insert[INS_MEM];
}

#include "../step2/libzhpeq_backend/backend_zhpe.c"

#else

#error optional indirect support unfinished

#define BACKNAME        "libzhpeq_backend.so"

static bool             b_zhpe;
static struct backend_ops *b_ops;

static void __attribute__((constructor)) lib_init(void)
{
    void                *dlhandle = dlopen(BACKNAME, RTLD_NOW);

    if (!dlhandle) {
        zhpeu_print_err("Failed to load %s:%s\n", BACKNAME, dlerror());
        abort();
    }
}

void zhpeq_register_backend(enum zhpe_backend backend, struct backend_ops *ops)
{
    /* For the moment, the zhpe backend will only register if the zhpe device
     * can be opened and the libfabric backend will only register if the zhpe
     * device can't be opened.
     */

    switch (backend) {

    case ZHPEQ_BACKEND_LIBFABRIC:
        b_ops = ops;
        break;

    case ZHPEQ_BACKEND_ZHPE:
        b_zhpe = true;
        b_ops = ops;
        break;

    default:
        zhpeu_print_err("Unexpected backed %d\n", backend);
        break;
    }
}

#endif

int zhpeq_init(int api_version)
{
    int                 ret = -EINVAL;
    static int          init_status = 1;

    if (init_status > 0) {
        if (!zhpeu_expected_saw("api_version", ZHPEQ_API_VERSION, api_version))
            goto done;

        mutex_lock(&init_mutex);
        ret = zhpe_lib_init(&b_attr);
        init_status = (ret <= 0 ? ret : 0);
        mutex_unlock(&init_mutex);
    }
    ret = init_status;
 done:

    return ret;
}

int zhpeq_query_attr(struct zhpeq_attr *attr)
{
    int                 ret = -EINVAL;

    /* Compatibility handling is left for another day. */
    if (!attr)
        goto done;

    *attr = b_attr;
    ret = 0;

 done:

    return ret;
}

int zhpeq_domain_free(struct zhpeq_dom *zdom)
{
    int                 ret = -EINVAL;
    struct zhpeq_domi   *zdomi = container_of(zdom, struct zhpeq_domi, pub);

    if (!zdom)
        goto done;

    ret = zhpe_domain_free(zdomi);
    free(zdom);

 done:
    return ret;
}

int zhpeq_domain_alloc(struct zhpeq_dom **zdom_out)
{
    int                 ret = -EINVAL;
    struct zhpeq_domi   *zdomi = NULL;

    if (!zdom_out)
        goto done;
    *zdom_out = NULL;

    ret = -ENOMEM;
    zdomi = calloc_cachealigned(1, sizeof(*zdomi));
    if (!zdomi)
        goto done;

    ret = zhpe_domain(zdomi);

 done:
    if (ret >= 0)
        *zdom_out = &zdomi->pub;
    else
        (void)zhpeq_domain_free(&zdomi->pub);

    return ret;
}

int zhpeq_xq_free(struct zhpeq_xq *zxq)
{
    int                 ret = -EINVAL;
    struct zhpeq_xqi    *xqi = container_of(zxq, struct zhpeq_xqi, pub);
    int                 rc;
    union xdm_active    active;

    if (!zxq)
        goto done;
    /* Stop the queue. */
    if (xqi->pub.qcm) {
        qcmwrite64(1, xqi->pub.qcm, ZHPE_XDM_QCM_STOP_OFFSET);
        for (;;) {
            active.u64 = qcmread64(xqi->pub.qcm,
                                   ZHPE_XDM_QCM_ACTIVE_STATUS_ERROR_OFFSET);
            if (!active.bits.active)
                break;
            yield();
        }
    }
    rc = zhpe_xqfree_pre(xqi);

    ret = 0;
    /* Unmap qcm, wq, and cq. */
    rc = _zhpeu_munmap((void *)xqi->pub.qcm, xqi->pub.xqinfo.qcm.size);
    if (ret >= 0 && rc < 0)
        ret = rc;
    rc = _zhpeu_munmap(xqi->pub.wq, xqi->pub.xqinfo.cmdq.size);
    if (ret >= 0 && rc < 0)
        ret = rc;
    rc = _zhpeu_munmap(xqi->pub.cq, xqi->pub.xqinfo.cmplq.size);
    if (ret >= 0 && rc < 0)
        ret = rc;

    /* Call the driver to free the queue. */
    if (xqi->pub.xqinfo.qcm.size) {
        rc = zhpe_xqfree(xqi);
        if (ret >= 0 && rc < 0)
            ret = rc;
    }

    /* Free queue memory. */
    free(xqi->pub.ctx);
    free(xqi->pub.mem);
    free(xqi->free_bitmap);
    free(xqi);

 done:
    return ret;
}

int zhpeq_xq_alloc(struct zhpeq_dom *zdom, int cmd_qlen, int cmp_qlen,
                   int traffic_class, int priority, int slice_mask,
                   struct zhpeq_xq **zxq_out)
{
    int                 ret = -EINVAL;
    struct zhpeq_xqi    *xqi = NULL;
    union xdm_cmp_tail  tail = {
        .bits.toggle_valid = 1,
    };
    int                 flags;
    size_t              i;
    size_t              e;

    if (!zxq_out)
        goto done;
    *zxq_out = NULL;
    if (!zdom || cmp_qlen < cmd_qlen ||
        cmd_qlen < 2 || cmd_qlen > b_attr.z.max_tx_qlen ||
        cmp_qlen < 2 || cmp_qlen > b_attr.z.max_tx_qlen ||
        traffic_class < 0 || traffic_class > ZHPEQ_TC_MAX ||
        priority < 0 || priority > ZHPEQ_PRI_MAX ||
        (slice_mask & ~(ALL_SLICES | SLICE_DEMAND)))
        goto done;

    ret = -ENOMEM;
    xqi = calloc_cachealigned(1, sizeof(*xqi));
    if (!xqi)
        goto done;
    xqi->pub.zdom = zdom;

    /*
     * Questions:
     * 1.) Code is much cleaner if I actually allocate to a power of 2,
     * but I could still honor the actual size and I am not.
     * 2.) The requires that we use one less than the queue size. Should I care
     * if the caller specified a power of 2, or should I just assume they
     * understood the limitations.
     * A comment:
     * I really can't allocate less than a page the queue, 64 entries, and my
     * bitmap chunks are 64 bits, so it really seems easiest just to force
     * 64 as the minimum allocation.
     */
    cmd_qlen = max(roundup_pow_of_2(cmd_qlen), (uint64_t)ZHPEQ_BITMAP_BITS);
    cmp_qlen = max(roundup_pow_of_2(cmp_qlen), (uint64_t)ZHPEQ_BITMAP_BITS);

    ret = zhpe_xqalloc(xqi, cmd_qlen, cmp_qlen, traffic_class,
                       priority, slice_mask);
    if (ret < 0)
        goto done;

    ret = -ENOMEM;
    e = xqi->pub.xqinfo.cmdq.ent - 1;
    xqi->pub.ctx = calloc_cachealigned(e, sizeof(*xqi->pub.ctx));
    if (!xqi->pub.ctx)
        goto done;
    xqi->pub.mem = calloc_cachealigned(e, sizeof(*xqi->pub.mem));
    if (!xqi->pub.mem)
        goto done;
    for (i = 0; i < e; i++)
        xqi->pub.mem[i].hdr.cmp_index = i;
    e = (e >> ZHPEQ_BITMAP_SHIFT) + 1;
    xqi->free_bitmap = calloc_cachealigned(e, sizeof(*xqi->free_bitmap));
    if (!xqi->free_bitmap)
        goto done;

    /* Initial free_bitmap. */
    for (i = 0; i < e; i++)
        xqi->free_bitmap[i] = ~(uint64_t)0;
    xqi->free_bitmap[e - 1] &= ~((uint64_t)1 << (ZHPEQ_BITMAP_BITS - 1));

    /* xqi->fd == -1 means we're faking things out. */
    flags = (xqi->fd == -1 ? MAP_ANONYMOUS | MAP_PRIVATE : MAP_SHARED);

    /* Map qcm, wq, and cq. */
    xqi->pub.qcm = _zhpeu_mmap(NULL, xqi->pub.xqinfo.qcm.size,
                               PROT_READ | PROT_WRITE, flags, xqi->fd,
                               xqi->pub.xqinfo.qcm.off);
    if (!xqi->pub.qcm) {
        ret = -errno;
        goto done;
    }
    xqi->pub.cmd = VPTR(xqi->pub.qcm, ZHPE_XDM_QCM_CMD_BUF_OFFSET);

    xqi->pub.wq = _zhpeu_mmap(NULL, xqi->pub.xqinfo.cmdq.size,
                              PROT_READ | PROT_WRITE, flags, xqi->fd,
                              xqi->pub.xqinfo.cmdq.off);
    if (!xqi->pub.qcm) {
        ret = -errno;
        goto done;
    }

    xqi->pub.cq = _zhpeu_mmap(NULL, xqi->pub.xqinfo.cmplq.size,
                              PROT_READ | PROT_WRITE, flags, xqi->fd,
                              xqi->pub.xqinfo.cmplq.off);
    if (!xqi->pub.cq) {
        ret = -errno;
        goto done;
    }

    ret = zhpe_xqalloc_post(xqi);
    if (ret < 0)
        goto done;

    /* Initialize completion tail to zero and set toggle bit. */
    qcmwrite64(tail.u64, xqi->pub.qcm,
               ZHPE_XDM_QCM_CMPL_QUEUE_TAIL_TOGGLE_OFFSET);
    /* Intialize command head and tail to zero. */
    qcmwrite64(0, xqi->pub.qcm, ZHPE_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
    qcmwrite64(0, xqi->pub.qcm, ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
    /* Start the queue. */
    qcmwrite64(0, xqi->pub.qcm, ZHPE_XDM_QCM_STOP_OFFSET);
    ret = 0;

 done:
    if (ret >= 0)
        *zxq_out = &xqi->pub;
    else
        (void)zhpeq_xq_free(&xqi->pub);

    return ret;
}

int zhpeq_xq_xchg_addr(struct zhpeq_xq *zxq, int sock_fd,
                       void *sa, size_t *sa_len)
{
    int                 ret = -EINVAL;

    if (!zxq || sock_fd == -1 || !sa || !sa_len)
        goto done;

    ret = zhpeq_xq_get_addr(zxq, sa, sa_len);
    if (ret < 0)
        goto done;
    ret = zhpeu_sock_send_blob(sock_fd, sa, *sa_len);
    if (ret < 0)
        goto done;
    ret = zhpeu_sock_recv_fixed_blob(sock_fd, sa, *sa_len);
    if (ret < 0)
        goto done;
 done:
    return ret;
}

int zhpeq_xq_backend_open(struct zhpeq_xq *zxq, void *sa)
{
    int                 ret = -EINVAL;
    struct zhpeq_xqi    *xqi = container_of(zxq, struct zhpeq_xqi, pub);

    if (!zxq)
        goto done;

    ret = zhpe_open(xqi, sa);
 done:

    return ret;
}

int zhpeq_xq_backend_close(struct zhpeq_xq *zxq, int open_idx)
{
    int                 ret = -EINVAL;
    struct zhpeq_xqi    *xqi = container_of(zxq, struct zhpeq_xqi, pub);

    if (!zxq)
        goto done;

    ret = zhpe_close(xqi, open_idx);
 done:

    return ret;
}

int32_t zhpeq_xq_reserve(struct zhpeq_xq *zxq, void *context)
{
    int32_t             ret;
    struct zhpeq_xqi    *xqi = container_of(zxq, struct zhpeq_xqi, pub);
    uint                i;

    if (unlikely(!zxq)) {
        ret = -EINVAL;
        goto done;
    }
    ret = ffs64(xqi->free_bitmap[0]);
    if (likely(ret)) {
        ret--;
        xqi->free_bitmap[0] &= ~((uint64_t)1 << ret);
        zxq->ctx[ret] = context;
        /* INS_CMD == 0 */
        if (unlikely(ret >= ZHPE_XDM_QCM_CMD_BUF_COUNT))
            ret |= (INS_MEM << 16);
    } else {
        for (i = 1; i < (xqi->pub.xqinfo.cmdq.ent >> ZHPEQ_BITMAP_SHIFT); i++) {
            ret = ffs64(xqi->free_bitmap[i]);
            if (ret) {
                ret--;
                xqi->free_bitmap[i] &= ~((uint64_t)1 << ret);
                ret += (i << ZHPEQ_BITMAP_SHIFT);
                zxq->ctx[ret] = context;
                ret |= (INS_MEM << 16);
                goto done;
            }
        }
        ret = -EAGAIN;
    }
 done:

    return ret;
}

void zhpeq_xq_commit(struct zhpeq_xq *zxq)
{
    uint32_t            qmask;

    if (unlikely(zxq->wq_tail != zxq->wq_tail_commit)) {
        qmask = zxq->xqinfo.cmdq.ent - 1;
        zxq->wq_tail_commit = zxq->wq_tail;
        qcmwrite64(zxq->wq_tail_commit & qmask,
                   zxq->qcm, ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
    }
}

static void *get_context(struct zhpeq_xqi *xqi, struct zhpe_cq_entry *cqe)
{
    void                *ret = xqi->pub.ctx[cqe->index];

    xqi->free_bitmap[cqe->index >> ZHPEQ_BITMAP_SHIFT] |=
        ((uint64_t)1 << (cqe->index & (ZHPEQ_BITMAP_BITS - 1)));

    return ret;
}

static void set_atomic_operands(union zhpe_hw_wq_entry *wqe,
                                enum zhpeq_atomic_size datasize,
                                uint64_t op1, uint64_t op2)
{
    switch (datasize) {

    case ZHPEQ_ATOMIC_SIZE32:
        wqe->atm.size = ZHPE_HW_ATOMIC_SIZE_32 | ZHPE_HW_ATOMIC_RETURN;
        wqe->atm.operands32[0] = op1;
        wqe->atm.operands32[1] = op2;
        break;

    case ZHPEQ_ATOMIC_SIZE64:
        wqe->atm.size |= ZHPE_HW_ATOMIC_SIZE_64 | ZHPE_HW_ATOMIC_RETURN;
        wqe->atm.operands64[0] = op1;
        wqe->atm.operands64[1] = op2;
        break;

    default:
        abort();
    }
}

void zhpeq_atomic(struct zhpeq_xq *zxq, int32_t reservation, uint16_t fence,
                  enum zhpeq_atomic_size datasize, enum zhpeq_atomic_op op,
                  uint64_t rem_addr, const uint64_t *operands)
{
    union zhpe_hw_wq_entry *wqe = &zxq->mem[(uint16_t)reservation];

    wqe->atm.rem_addr = rem_addr;

    switch (op) {

    case ZHPEQ_ATOMIC_ADD:
        wqe->hdr.opcode = ZHPE_HW_OPCODE_ATM_ADD | fence;
        set_atomic_operands(wqe, datasize, operands[0], 0);
        break;

    case ZHPEQ_ATOMIC_CAS:
        wqe->hdr.opcode = ZHPE_HW_OPCODE_ATM_CAS | fence;
        set_atomic_operands(wqe, datasize, operands[1], operands[0]);
        break;

    case ZHPEQ_ATOMIC_SWAP:
        wqe->hdr.opcode = ZHPE_HW_OPCODE_ATM_SWAP | fence;
        set_atomic_operands(wqe, datasize, operands[0], 0);
        break;

    default:
        abort();
    }
}

int zhpeq_mr_reg(struct zhpeq_dom *zdom, const void *buf, size_t len,
                 uint32_t access, struct zhpeq_key_data **qkdata_out)
{
    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 0));

    int                 ret = -EINVAL;

    if (!qkdata_out)
        goto done;
    *qkdata_out = NULL;
    if (!zdom || !len || page_up((uintptr_t)buf + len)  <= (uintptr_t)buf ||
        (access & ~ZHPEQ_MR_VALID_MASK))
        goto done;

    ret = zhpe_mr_reg(zdom, buf, len, access, qkdata_out);
#if QKDATA_DUMP
    if (ret >= 0)
        zhpeq_print_qkdata(__func__, __LINE__, *qkdata_out);
#endif

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 0));

    return ret;
}

int zhpeq_qkdata_free(struct zhpeq_key_data *qkdata)
{
    int                 ret = 0;
    struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, struct zhpeq_mr_desc_v1, qkdata);

    if (!qkdata)
        goto done;
    ret = -EINVAL;
    if (desc->hdr.magic != ZHPE_MAGIC ||
        (desc->hdr.version & ~ZHPEQ_MR_REMOTE) != ZHPEQ_MR_V1)
        goto done;
#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif
    if (desc->qkdata.z.zaddr) {
        if (desc->hdr.version & ZHPEQ_MR_REMOTE) {
            zhpe_stats_start(zhpe_stats_subid(ZHPQ, 50));
            ret = zhpe_zmmu_free(qkdata);
            zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 50));
        } else {
            zhpe_stats_start(zhpe_stats_subid(ZHPQ, 10));
            ret = zhpe_mr_free(qkdata);
            zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 10));
        }
    }
    free(desc);

 done:

    return ret;
}

int zhpeq_zmmu_reg(struct zhpeq_key_data *qkdata)
{
    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 40));

    int                 ret = -EINVAL;
    struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, struct zhpeq_mr_desc_v1, qkdata);

    if (!qkdata || desc->hdr.magic != ZHPE_MAGIC ||
        desc->hdr.version != (ZHPEQ_MR_V1 | ZHPEQ_MR_REMOTE))
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif
    ret = zhpe_zmmu_reg(qkdata);

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 40));

    return ret;
}

int zhpeq_fam_qkdata(struct zhpeq_dom *zdom, int open_idx,
                     struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -EINVAL;
    struct zhpeq_domi   *zdomi = container_of(zdom, struct zhpeq_domi, pub);

    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 20));

    if (!qkdata_out)
        goto done;
    *qkdata_out = NULL;
    if (!zdom)
        goto done;

    ret = zhpe_fam_qkdata(zdomi, open_idx, qkdata_out);

#if QKDATA_DUMP
    if (ret >= 0)
        zhpeq_print_qkdata(__func__, __LINE__, *qkdata_out);
#endif

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 20));

    return ret;
}

int zhpeq_qkdata_export(const struct zhpeq_key_data *qkdata,
                        void *blob, size_t *blob_len)
{
    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 30));

    int                 ret = -EINVAL;
    const struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, const struct zhpeq_mr_desc_v1, qkdata);

    if (!qkdata || !blob || !blob_len ||
        *blob_len < sizeof(struct key_data_packed) ||
        desc->hdr.magic != ZHPE_MAGIC || desc->hdr.version != ZHPEQ_MR_V1)
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif
    *blob_len = sizeof(struct key_data_packed);
    ret = zhpe_qkdata_export(qkdata, blob);

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 30));

    return ret;
}

int zhpeq_qkdata_import(struct zhpeq_dom *zdom, int open_idx,
                        const void *blob, size_t blob_len,
                        struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -EINVAL;
    struct zhpeq_domi   *zdomi = container_of(zdom, struct zhpeq_domi, pub);
    const struct key_data_packed *pdata = blob;
    struct zhpeq_mr_desc_v1 *desc = NULL;
    struct zhpeq_key_data *qkdata;

    if (!qkdata_out)
        goto done;
    *qkdata_out = NULL;
    if (!blob || blob_len != sizeof(*pdata))
        goto done;

    desc = calloc_cachealigned(1, sizeof(*desc));
    if (!desc) {
        ret = -ENOMEM;
        goto done;
    }
    qkdata = &desc->qkdata;

    desc->hdr.magic = ZHPE_MAGIC;
    desc->hdr.version = ZHPEQ_MR_V1 | ZHPEQ_MR_REMOTE;
    desc->hdr.zdomi = zdomi;
    desc->open_idx = open_idx;
    unpack_kdata(pdata, qkdata);
    qkdata->rsp_zaddr = qkdata->z.zaddr;
    qkdata->z.zaddr = 0;
    *qkdata_out = qkdata;
    ret = 0;

 done:
    return ret;
}

int zhpeq_mmap(const struct zhpeq_key_data *qkdata,
               uint32_t cache_mode, void *addr, size_t length, int prot,
               int flags, off_t offset, struct zhpeq_mmap_desc **zmdesc)
{
    int                 ret = -EINVAL;
    const struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, const struct zhpeq_mr_desc_v1, qkdata);

    if (zmdesc)
        *zmdesc = NULL;
    if (!qkdata || !zmdesc || (cache_mode & ~ZHPEQ_MR_REQ_CPU_CACHE) ||
        desc->hdr.magic != ZHPE_MAGIC ||
        desc->hdr.version != (ZHPEQ_MR_V1 | ZHPEQ_MR_REMOTE) ||
        !length || page_off(offset) ||
        page_off(qkdata->z.vaddr) || page_off(qkdata->z.len) ||
        offset + length > desc->qkdata.z.len || (prot & PROT_EXEC) ||
        ((prot & PROT_READ) && !(qkdata->z.access & ZHPEQ_MR_GET_REMOTE)) ||
        ((prot & PROT_WRITE) && !(qkdata->z.access & ZHPEQ_MR_PUT_REMOTE)))
        goto done;
    cache_mode |= ZHPEQ_MR_REQ_CPU;

    ret = zhpe_mmap(qkdata, cache_mode, addr, length, prot,
                    flags, offset, zmdesc);

#if QKDATA_DUMP
    if (ret >= 0)
        zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif

 done:
    return ret;
}

int zhpeq_mmap_unmap(struct zhpeq_mmap_desc *zmdesc)
{
    int                 ret = -EINVAL;

    if (!zmdesc)
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, zmdesc->qkdata);
#endif
    ret = zhpe_mmap_unmap(zmdesc);

 done:
    return ret;
}

int zhpeq_mmap_commit(struct zhpeq_mmap_desc *zmdesc,
                      const void *addr, size_t length, bool fence,
                      bool invalidate, bool wait)
{
    int                 ret;

    ret = zhpe_mmap_commit(zmdesc, addr, length, fence, invalidate, wait);

    return ret;
}

ssize_t zhpeq_xq_cq_read(struct zhpeq_xq *zxq,
                         struct zhpeq_xq_cq_entry *entries, size_t n_entries)
{
    ssize_t             ret = -EINVAL;
    struct zhpeq_xqi    *xqi = container_of(zxq, struct zhpeq_xqi, pub);
    union zhpe_hw_cq_entry *cqe;
    ssize_t             i;
    uint32_t            qmask;

    if (!zxq || !entries || n_entries > SSIZE_MAX)
        goto done;

    qmask = xqi->pub.xqinfo.cmplq.ent - 1;

    for (i = 0; i < n_entries; i++) {
        cqe = xqi->pub.cq + (xqi->pub.cq_head & qmask);
        if ((atm_load_rlx(&cqe->entry_alt.valid) & ZHPE_HW_CQ_VALID) !=
            cq_valid(xqi->pub.cq_head, qmask))
            break;
        entries[i].z = cqe->entry;
        entries[i].z.context = get_context(xqi, &entries[i].z);
        zhpe_stats_stamp(zhpe_stats_subid(ZHPQ, 80), (uintptr_t)zxq,
                         entries[i].z.index, (uintptr_t)entries[i].z.context);
        xqi->pub.cq_head++;
    }
    ret = i;

 done:
    return ret;
}

void zhpeq_print_xq_info(struct zhpeq_xq *zxq)
{
    const char          *b_str = "unknown";
    struct zhpe_attr    *attr = &b_attr.z;
    struct zhpeq_xqi    *xqi = container_of(zxq, struct zhpeq_xqi, pub);

    switch (b_attr.backend) {

    case ZHPEQ_BACKEND_ZHPE:
        b_str = "zhpe";
        break;

    case ZHPEQ_BACKEND_LIBFABRIC:
        b_str = "libfabric";
        break;

    default:
        break;
    }

    printf("%s:attributes\n", LIBNAME);
    printf("backend       : %s\n", b_str);
    printf("max_tx_queues : %u\n", attr->max_tx_queues);
    printf("max_rx_queues : %u\n", attr->max_rx_queues);
    printf("max_tx_qlen   : %u\n", attr->max_tx_qlen);
    printf("max_rx_qlen   : %u\n", attr->max_rx_qlen);
    printf("max_dma_len   : %Lu\n", (ullong)attr->max_dma_len);

    printf("\n");
    zhpe_print_xq_info(xqi);
}

int zhpeq_xq_get_addr(struct zhpeq_xq *zxq, void *sa, size_t *sa_len)
{
    ssize_t             ret = -EINVAL;
    struct zhpeq_xqi    *xqi = container_of(zxq, struct zhpeq_xqi, pub);

    if (!zxq || !sa || !sa_len)
        goto done;

    ret = zhpe_xq_get_addr(xqi, sa, sa_len);
 done:

    return ret;
}

#if 0
int zhpeq_getzaddr(const char *host, const char *service,
                   struct sockaddr_zhpe *zaddr)
{
	int			ret = -FI_EINVAL;
	FILE			*gcid_file = NULL;
	const char		*gcid_fname;
	uint			gcid;
        ulong                   ctxid;
	char			*name;
	int			n;
        char                    *e;
	char			line[FI_NAME_MAX * 2];

        if (!host || !zaddr)
            goto done;

        ctxid = ZHPE_SZQ_INVAL;
        if (service) {
            errno = 0;
            ctxid = strtoul(service, &e, 0);
            if (errno != 0) {
                ret = -errno;
                goto done;
            }
            if (*e != '\0')
                goto done;
            if (ctxid & ~(ulong)ZHPE_CTXID_MASK)
                goto done;
        }
        zaddr->sz_family = AF_ZHPE;
        uuid_clear(zaddr->sz_uuid);
        zaddr->zq_queue = ctxid;
        if (isdigit(host[0])) {
            errno = 0;
            gcid = strtoul(gcid, &e, 0);
            if (errno != 0) {
                ret = -errno;
                goto done;
            }
            if (*e != '\0')
                goto done;
            if (gcid & ~(ulong)ZHPE_GCID_MASK)
                goto done;
            zhpeu_install_gcid_in_uuid(zaddr->sz_uuid, gcid);
            ret = 0;
            goto done;
        }

	gcid_fname = getenv(ZHPEQ_HOSTS_GCID_ENV);
	if (!gcid_fname)
		gcid_fname = ZHPEQ_HOSTS_GCID_FILE;
	gcid_file = fopen(gcid_file, "r");
	if (!gcid_file) {
		ret = -errno;
		ZHPE_LOG_ERROR("Error %d opening %s:%s\n",
			       ret, gcid_fname, strerror(-ret));
		goto done;
	}
        ret = -FI_ENOENT;
	for (;;) {
		if (!fgets(line, sizeof(line), gcid_file)) {
			if (ferror(gcid_file)) {
				ret = -errno;
				ZHPE_LOG_ERROR("Error %d reading %s:%s\n",
					       ret, gcid_fname, strerror(-ret));
				break;
			}
			if (feof(gcid_file))
				break;
			continue;
		}
		n = sscanf(line, "%ms %x\n", &name, &gcid);
		if (n == 2) {
			if (!strcasecmp(host, name)) {
				free(name);
				if (gcid & ~GCID_MASK) {
					ret = -FI_EINVAL;
                                        goto done;
                                }
                                zhpeu_install_gcid_in_uuid(zaddr->sz_uuid,
                                                           gcid);
                                ret = gcid;
				break;
			}
		}
		if (n >= 1) {
			free(name);
			n = 0;
		}
	}
 done:
	if (gcid_file)
		fclose(gcid_file);

	return ret;
}
#endif

void zhpeq_print_qkdata(const char *func, uint line,
                        const struct zhpeq_key_data *qkdata)
{
    char                *id_str = NULL;

    id_str = zhpe_qkdata_id_str(qkdata);
    fprintf(stderr, "%s,%u:%p %s\n", func, line, qkdata, (id_str ?: ""));
    fprintf(stderr, "%s,%u:v/z/l 0x%Lx 0x%Lx 0x%Lx\n", func, line,
            (ullong)qkdata->z.vaddr, (ullong)qkdata->z.zaddr,
            (ullong)qkdata->z.len);
    fprintf(stderr, "%s,%u:a/l 0x%Lx 0x%Lx\n", func, line,
            (ullong)qkdata->z.access, (ullong)qkdata->laddr);
}

static void print_qcm1(const char *func, uint line, const volatile void *qcm,
                      uint offset)
{
    printf("%s,%u:qcm[0x%03x] = 0x%lx\n",
           func, line, offset, qcmread64(qcm, offset));
}

void zhpeq_print_xq_qcm(const char *func, uint line, const struct zhpeq_xq *zxq)
{
    uint                i;

    printf("%s,%u:%s %p\n", func, line, __func__, zxq->qcm);
    for (i = 0x00; i < 0x30; i += 0x08)
        print_qcm1(func, line, zxq->qcm, i);
    for (i = 0x40; i < 0x108; i += 0x40)
        print_qcm1(func, line, zxq->qcm, i);
}

static uint wq_opcode(union zhpe_hw_wq_entry *wqe)
{
    return (wqe->hdr.opcode & ZHPE_HW_OPCODE_MASK);
}

static uint wq_fence(union zhpe_hw_wq_entry *wqe)
{
    return !!(wqe->hdr.opcode & ZHPE_HW_OPCODE_FENCE);
}

static uint wq_index(union zhpe_hw_wq_entry *wqe)
{
    return wqe->hdr.cmp_index;
}

static void wq_print_imm(union zhpe_hw_wq_entry *wqe, uint i, const char *opstr)
{
    struct zhpe_hw_wq_imm *imm = &wqe->imm;

    fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x len 0x%x rem 0x%lx\n",
            i, opstr, wq_fence(wqe), wq_index(wqe),
            imm->len, imm->rem_addr);
}

static void wq_print_dma(union zhpe_hw_wq_entry *wqe, uint i, const char *opstr)
{
    struct zhpe_hw_wq_dma *dma = &wqe->dma;

    fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x len 0x%x rd 0x%lx wr 0x%lx\n",
            i, opstr, wq_fence(wqe), wq_index(wqe),
            dma->len, dma->rd_addr, dma->wr_addr);
}

static void wq_print_atm(union zhpe_hw_wq_entry *wqe, uint i, const char *opstr)
{
    struct zhpe_hw_wq_atomic *atm = &wqe->atm;
    uint64_t            operands[2];

    if ((atm->size & ZHPE_HW_ATOMIC_SIZE_MASK) == ZHPE_HW_ATOMIC_SIZE_32) {
        operands[0] = atm->operands32[0];
        operands[1] = atm->operands32[1];
    } else {
        operands[0] = atm->operands64[0];
        operands[1] = atm->operands64[1];
    }
    fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x size 0x%x rem 0x%lx"
            " operands 0x%lx 0x%lx\n",
            i, opstr, wq_fence(wqe), wq_index(wqe),
            atm->size, atm->rem_addr, operands[0], operands[1]);
}

static void wq_print(union zhpe_hw_wq_entry *wqe, uint i)
{
    switch (wq_opcode(wqe)) {

    case ZHPE_HW_OPCODE_NOP:
        fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x\n",
                i, "NOP", wq_fence(wqe), wq_index(wqe));
        break;

    case ZHPE_HW_OPCODE_GETIMM:
        wq_print_imm(wqe, i, "GETIMM");
        break;

    case ZHPE_HW_OPCODE_PUTIMM:
        wq_print_imm(wqe, i, "PUTIMM");
        break;

    case ZHPE_HW_OPCODE_GET:
        wq_print_dma(wqe, i, "GET");
        break;

    case ZHPE_HW_OPCODE_PUT:
        wq_print_dma(wqe, i, "PUT");
        break;

    case ZHPE_HW_OPCODE_ATM_ADD:
        wq_print_atm(wqe, i, "ATMADD");
        break;

    case ZHPE_HW_OPCODE_ATM_CAS:
        wq_print_atm(wqe, i, "ATMCAS");
        break;

    case ZHPE_HW_OPCODE_ATM_SWAP:
        wq_print_atm(wqe, i, "ATMSWAP");
        break;

    default:
        fprintf(stderr, "%7d:OP 0x%02x:f %u idx %0x04x\n",
                i, wq_opcode(wqe), wq_fence(wqe), wq_index(wqe));
        break;
    }
}

void zhpeq_print_xq_wq(struct zhpeq_xq *zxq, int cnt)
{
    uint32_t            qmask = zxq->xqinfo.cmdq.ent - 1;
    uint                i;

    if (!cnt || cnt > qmask)
        cnt = qmask;
    if (cnt > zxq->wq_tail)
        cnt = zxq->wq_tail;
    for (i = zxq->wq_tail - cnt ; cnt > 0; i++, cnt--)
        wq_print(&zxq->wq[i & qmask], i);
}

void zhpeq_print_xq_cq(struct zhpeq_xq *zxq, int cnt)
{
    uint32_t            qmask = zxq->xqinfo.cmplq.ent - 1;
    uint                i;
    union zhpe_hw_cq_entry *cqe;
    char                *d;

    if (!cnt || cnt > qmask)
        cnt = qmask;
    if (cnt > zxq->cq_head)
        cnt = zxq->cq_head;
    for (i = zxq->cq_head - cnt ; cnt > 0; i++, cnt--) {
        cqe = &zxq->cq[i & qmask];
        /* Print the first 8 bytes of the result */
        d = cqe->entry.result.data;
        fprintf(stderr, "%7d:v %u idx 0x%04x status 0x%02x"
                " data %02x%02x%x02%02x%02x%02x%02x%02x\n",
                i, cqe->entry.valid, cqe->entry.index, cqe->entry.status,
                d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
    }
}
