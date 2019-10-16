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

#ifndef _ZHPEQ_H_
#define _ZHPEQ_H_

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zhpe_uapi.h>

_EXTERN_C_BEG

#define ZHPEQ_API_VERSION       (1)

#define __IMPORT(_x)            ZHPEQ_##_x = ZHPE_##_x

enum {
    __IMPORT(MR_GET),
    __IMPORT(MR_PUT),
    __IMPORT(MR_GET_REMOTE),
    __IMPORT(MR_PUT_REMOTE),
    __IMPORT(MR_SEND),
    __IMPORT(MR_RECV),
    ZHPEQ_MR_KEY_ZERO_OFF       = ZHPE_MR_FLAG0,
    __IMPORT(MR_FLAG1),
    __IMPORT(MR_FLAG2),
    __IMPORT(MR_REQ_CPU),
    __IMPORT(MR_REQ_CPU_CACHE),
    __IMPORT(MR_REQ_CPU_WB),
    __IMPORT(MR_REQ_CPU_WC),
    __IMPORT(MR_REQ_CPU_WT),
    __IMPORT(MR_REQ_CPU_UC),
};

enum zhpeq_backend {
    __IMPORT(BACKEND_ZHPE),
    __IMPORT(BACKEND_LIBFABRIC),
    __IMPORT(BACKEND_MAX),
};

#undef __IMPORT

enum zhpeq_atomic_size {
    ZHPEQ_ATOMIC_SIZE_NONE      = ZHPE_HW_ATOMIC_RETURN,
    ZHPEQ_ATOMIC_SIZE32         = ZHPE_HW_ATOMIC_SIZE_32,
    ZHPEQ_ATOMIC_SIZE64         = ZHPE_HW_ATOMIC_SIZE_64,
};

#define __IMPORT(_x)            ZHPEQ_ATOMIC_##_x = ZHPE_HW_OPCODE_ATM_##_x

enum zhpeq_atomic_op {
    ZHPEQ_ATOMIC_NONE           = ZHPE_HW_OPCODE_NOP,
    __IMPORT(SWAP),
    __IMPORT(ADD),
    __IMPORT(AND),
    __IMPORT(OR),
    __IMPORT(XOR),
    __IMPORT(SMIN),
    __IMPORT(SMAX),
    __IMPORT(UMIN),
    __IMPORT(UMAX),
    __IMPORT(CAS),
};

#undef __IMPORT

#define	ZHPEQ_HOSTS_FILE	"/etc/hosts.zhpeq"
#define	ZHPEQ_HOSTS_ENV         "ZHPEQ_HOSTS"

#define __IMPORT(_x)                                            \
    ZHPEQ_XQ_CQ_STATUS_##_x = ZHPE_HW_CQ_STATUS_##_x

enum zhpeq_xq_cq_status {
    __IMPORT(SUCCESS),
    __IMPORT(XDM_PUT_READ_ERROR),
    __IMPORT(XDM_BAD_COMMAND),
    __IMPORT(GENZ_UNSUPPORTED_REQ),
    __IMPORT(GENZ_MALFORMED_PKT),
    __IMPORT(GENZ_PKT_EXECUTION_ERROR),
    __IMPORT(GENZ_INVALID_PERMISSION),
    __IMPORT(GENZ_COMP_CONTAINMENT),
    __IMPORT(GENZ_RDM_QUEUE_FULL),
    __IMPORT(GENZ_UNSUPPORTED_SVC),
    __IMPORT(GENZ_RETRIES_EXCEEDED),
};

#undef __IMPORT

enum {
    ZHPEQ_PRI_MAX               = 1,
    ZHPEQ_TC_MAX                = 15,
    ZHPEQ_IMM_MAX               = ZHPE_IMM_MAX,
    ZHPEQ_KEY_BLOB_MAX          = 32,
};

struct zhpeq_attr {
    enum zhpeq_backend  backend;
    struct zhpe_attr    z;
};

struct zhpeq_key_data {
    struct zhpe_key_data z;
    union {
        uint64_t        laddr;
        uint64_t        rsp_zaddr;
    };
};

struct zhpeq_xq_cq_entry {
    struct zhpe_cq_entry z;
};

/* Public portions of structures. */
struct zhpeq_mmap_desc {
    struct zhpeq_key_data *qkdata;
    void                *addr;
};

struct zhpeq_dom {
    void                *dummy;
};


#define ZHPEQ_BITMAP_BITS       (64U)
#define ZHPEQ_BITMAP_SHIFT      (6U)

struct zhpeq_xq {
    struct zhpeq_dom    *zdom;
    struct zhpe_xqinfo  xqinfo;
    volatile void       *qcm;
    union zhpe_hw_wq_entry *cmd;
    union zhpe_hw_wq_entry *wq;
    union zhpe_hw_cq_entry *cq;
    void                **ctx;
    union zhpe_hw_wq_entry *mem;
    uint32_t            wq_tail;
    uint32_t            wq_tail_commit;
    uint32_t            cq_head;
};

struct zhpeq_rq {
    struct zhpeq_dom    *zdom;
    struct zhpe_rqinfo  rqinfo;
    volatile void       *qcm;
    union zhpe_hw_rdm_entry *rq;
};

static inline int zhpeq_rem_key_access(struct zhpeq_key_data *qkdata,
                                       uint64_t start, uint64_t len,
                                       uint32_t qaccess, uint64_t *zaddr)
{
    struct zhpe_key_data *kdata = &qkdata->z;

    if (!qkdata)
        return -EINVAL;
    if (kdata->access & ZHPEQ_MR_KEY_ZERO_OFF)
        start += kdata->vaddr;
    if ((qaccess & kdata->access) != qaccess ||
        start < kdata->vaddr || start + len > kdata->vaddr + kdata->len)
        return -EINVAL;
    *zaddr = (start - kdata->vaddr) + kdata->zaddr;

    return 0;
}

static inline int zhpeq_lcl_key_access(struct zhpeq_key_data *qkdata,
                                       void *buf, uint64_t len,
                                       uint32_t qaccess, uint64_t *zaddr)
{
    uintptr_t           start = (uintptr_t)buf;
    struct zhpe_key_data *kdata = &qkdata->z;

    if (!qkdata)
        return -EINVAL;
    if ((qaccess & kdata->access) != qaccess ||
        start < kdata->vaddr || start + len > kdata->vaddr + kdata->len)
        return -EINVAL;
    *zaddr = (start - kdata->vaddr) + qkdata->laddr;

    return 0;
}

int zhpeq_init(int api_version);

int zhpeq_query_attr(struct zhpeq_attr *attr);

int zhpeq_domain_alloc(struct zhpeq_dom **zdom_out);

int zhpeq_domain_free(struct zhpeq_dom *zdom);

int zhpeq_xq_alloc(struct zhpeq_dom *zdom, int cmd_qlen, int cmp_qlen,
                   int traffic_class, int priority, int slice_mask,
                   struct zhpeq_xq **zxq_out);

int zhpeq_xq_free(struct zhpeq_xq *zxq);

int zhpeq_xq_backend_open(struct zhpeq_xq *zxq, void *sa);

int zhpeq_xq_backend_close(struct zhpeq_xq *zxq, int open_idx);

ssize_t zhpeq_xq_cq_read(struct zhpeq_xq *zxq,
                         struct zhpeq_xq_cq_entry *entries, size_t n_entries);

int zhpeq_mr_reg(struct zhpeq_dom *zdom, const void *buf, size_t len,
                 uint32_t access, struct zhpeq_key_data **qkdata_out);

int zhpeq_qkdata_free(struct zhpeq_key_data *qkdata);

int zhpeq_qkdata_export(const struct zhpeq_key_data *qkdata,
                        void *blob, size_t *blob_len);

int zhpeq_qkdata_import(struct zhpeq_dom *zdom, int open_idx,
                        const void *blob, size_t blob_len,
                        struct zhpeq_key_data **qkdata_out);

int zhpeq_fam_qkdata(struct zhpeq_dom *zdom, int open_idx,
                     struct zhpeq_key_data **qkdata_out);

int zhpeq_zmmu_reg(struct zhpeq_key_data *qkdata);

int zhpeq_mmap(const struct zhpeq_key_data *qkdata,
               uint32_t cache_mode, void *addr, size_t length, int prot,
               int flags, off_t offset, struct zhpeq_mmap_desc **zmdesc);

int zhpeq_mmap_unmap(struct zhpeq_mmap_desc *zmdesc);

int zhpeq_mmap_commit(struct zhpeq_mmap_desc *zmdesc,
                      const void *addr, size_t length, bool fence,
                      bool invalidate, bool wait);

static inline uint64_t ioread64(const volatile void *addr)
{
    return le64toh(*(const volatile uint64_t *)addr);
}

static inline void iowrite64(uint64_t value, volatile void *addr)
{
    *(volatile uint64_t *)addr = htole64(value);
}

static inline uint64_t qcmread64(const volatile void *qcm, size_t off)
{
    return ioread64((char *)qcm + off);
}

static inline void qcmwrite64(uint64_t value, volatile void *qcm, size_t off)
{
    iowrite64(value, (char *)qcm + off);
}

int32_t zhpeq_xq_reserve(struct zhpeq_xq *zxq, void *context);
void zhpeq_xq_commit(struct zhpeq_xq *zxq);

typedef void (*zhpeq_xq_entry_insert_fn)(struct zhpeq_xq *zxq,
                                         uint16_t reservation16);
extern zhpeq_xq_entry_insert_fn zhpeq_insert[];

static inline void zhpeq_xq_insert(struct zhpeq_xq *zxq, int32_t reservation)
{
   zhpeq_insert[reservation >> 16](zxq, reservation);
}

static inline void zhpeq_xq_nop(struct zhpeq_xq *zxq, int32_t reservation,
                                uint16_t fence)
{
    union zhpe_hw_wq_entry *wqe = &zxq->mem[(uint16_t)reservation];

    wqe->hdr.opcode = ZHPE_HW_OPCODE_NOP | fence;
}

static inline void zhpeq_xq_sync(struct zhpeq_xq *zxq, int32_t reservation)
{
    union zhpe_hw_wq_entry *wqe = &zxq->mem[(uint16_t)reservation];

    wqe->hdr.opcode = ZHPE_HW_OPCODE_SYNC | ZHPE_HW_OPCODE_FENCE;
}

static inline void zhpeq_xq_rw(struct zhpeq_xq *zxq, int32_t reservation,
                               uint16_t opcode, uint64_t rd_addr, size_t len,
                               uint64_t wr_addr)
{
    union zhpe_hw_wq_entry *wqe = &zxq->mem[(uint16_t)reservation];

    wqe->hdr.opcode = opcode;
    wqe->dma.len = len;
    wqe->dma.rd_addr = rd_addr;
    wqe->dma.wr_addr = wr_addr;
}

static inline void zhpeq_xq_put(struct zhpeq_xq *zxq, int32_t reservation,
                                uint16_t fence, uint64_t lcl_addr, size_t len,
                                uint64_t rem_addr)
{
    zhpeq_xq_rw(zxq, reservation, (ZHPE_HW_OPCODE_PUT | fence),
                lcl_addr, len, rem_addr);
}

static inline void zhpeq_xq_puti(struct zhpeq_xq *zxq, int32_t reservation,
                                 uint16_t fence, const void *buf, size_t len,
                                 uint64_t rem_addr)
{
    union zhpe_hw_wq_entry *wqe = &zxq->mem[(uint16_t)reservation];

    wqe->hdr.opcode = ZHPE_HW_OPCODE_PUTIMM | fence;
    wqe->imm.len = len;
    wqe->imm.rem_addr = rem_addr;
    memcpy(wqe->imm.data, buf, len);
}

static inline void zhpeq_xq_get(struct zhpeq_xq *zxq, int32_t reservation,
                                uint16_t fence, uint64_t lcl_addr, size_t len,
                                uint64_t rem_addr)
{
    zhpeq_xq_rw(zxq, reservation, (ZHPE_HW_OPCODE_GET | fence),
                rem_addr, len, lcl_addr);
}

static inline void zhpeq_xq_geti(struct zhpeq_xq *zxq, int32_t reservation,
                                 uint16_t fence, size_t len, uint64_t rem_addr)
{
    union zhpe_hw_wq_entry *wqe = &zxq->mem[(uint16_t)reservation];

    wqe->hdr.opcode = ZHPE_HW_OPCODE_GETIMM | fence;
    wqe->imm.len = len;
    wqe->imm.rem_addr = rem_addr;
}

static inline void *zhpeq_xq_enqa(struct zhpeq_xq *zxq, int32_t reservation,
                                  uint16_t fence, uint32_t dgcid,
                                  uint32_t rspctxid)
{
    union zhpe_hw_wq_entry *wqe = &zxq->mem[(uint16_t)reservation];

    wqe->hdr.opcode = ZHPE_HW_OPCODE_ENQA | fence;
    wqe->enqa_alt.dgcid = dgcid << ZHPE_ENQA_GCID_SHIFT;
    wqe->enqa_alt.rspctxid = rspctxid;

    return wqe->enqa_alt.payload;
}

void zhpeq_atomic(struct zhpeq_xq *zxq, int32_t reservation, uint16_t fence,
                  enum zhpeq_atomic_size datasize, enum zhpeq_atomic_op op,
                  uint64_t rem_addr, const uint64_t *operands);

void zhpeq_print_xq_info(struct zhpeq_xq *zxq);

void zhpeq_print_qkdata(const char *func, uint line,
                        const struct zhpeq_key_data *qkdata);

void zhpeq_print_xq_qcm(const char *func, uint line,
                        const struct zhpeq_xq *zxq);

void zhpeq_print_xq_wq(struct zhpeq_xq *zxq, int cnt);

void zhpeq_print_xq_cq(struct zhpeq_xq *zxq, int cnt);

int zhpeq_xq_get_addr(struct zhpeq_xq *zxq, void *sa, size_t *sa_len);

int zhpeq_xq_xchg_addr(struct zhpeq_xq *zxq, int sock_fd,
                       void *sa, size_t *sa_len);

_EXTERN_C_END

#endif /* _ZHPEQ_H_ */
