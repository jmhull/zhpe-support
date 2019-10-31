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
#define DEFAULT_EPOLL   (1023U)
/* ! */
struct cli_wire_msg {
    uint64_t            poll_usec;
    uint64_t            qlen;
    bool                once_mode;
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
    uint64_t            qlen;
    uint64_t            poll_usec;
    bool                once_mode;
    bool                seconds_mode;
};

struct timing {
    uint64_t            tot;
    uint64_t            min;
    uint64_t            max;
    uint64_t            cnt;
};

struct stuff {
    const struct args   *args;
    struct zhpeq_dom    *zdom;
    struct zhpeq_xq     *zxq;
    struct zhpeq_rq     *zrq;
    int                 sock_fd;
    size_t              ring_ops;
    size_t              ring_warmup;
    uint32_t            tx_seq;
    uint32_t            cq_seq;
    uint32_t            rx_seq;
    uint32_t            tx_oos_max;
    uint32_t            rx_oos_max;
    uint32_t            rx_oos_ent_base;
    uint32_t            rx_oos_ent_cnt;
    struct zhpe_rdm_entry rx_oos_ent[64] CACHE_ALIGNED;
    size_t              tx_oos;
    size_t              rx_oos;
    size_t              epoll_cnt;
    uint64_t            poll_cycles;
    struct timing       tx_lat;
    struct timing       tx_cmp;
    uint64_t            rx_last;
    struct timing       rx_lat;
    struct timing       pp_lat;
    struct zhpeq_rq_epoll_ring epoll_ring;
    size_t              tx_avail;
    size_t              tx_max;
    size_t              qlen;
    uint32_t            dgcid;
    uint32_t            rspctxid;
    int                 open_idx;
    uint8_t             qd_last;
    bool                epoll;
    bool                allocated;
};

struct enqa_msg {
    uint64_t            tx_start;
    uint64_t            pp_start;
    uint32_t            seq;
    uint8_t             flag;
};

static void timing_reset(struct timing *t)
{
    t->tot = 0;
    t->min = ~(uint64_t)0;
    t->max = 0;
    t->cnt = 0;
}

static void timing_update(struct timing *t, uint64_t cycles)
{
    t->tot += cycles;
    t->min = min(t->min, cycles);
    t->max = max(t->max, cycles);
    t->cnt++;
}

static void conn_tx_stats_reset(struct stuff *conn)
{
    timing_reset(&conn->tx_lat);
    timing_reset(&conn->tx_cmp);
#if 0
    conn->tx_seq = 0;
    conn->cq_seq = 0;
    conn->tx_oos = 0;
    conn->tx_oos_max = 0;
#endif
}

static void conn_rx_stats_reset(struct stuff *conn, uint64_t rx_last)
{
    timing_reset(&conn->rx_lat);
#if 0
    conn->rx_seq = 0;
    conn->rx_oos = 0;
    conn->rx_oos_max = 0;
#endif
    assert(conn->rx_oos_ent_cnt == 0);
    conn->rx_last = rx_last;
    timing_reset(&conn->pp_lat);
}

static void timing_print(struct timing *t, const char *lbl, uint64_t divisor)
{
    if (!t->cnt)
        return;

    zhpeu_print_info("%s:%s:ave/min/max/cnt %.3lf/%.3lf/%.3lf/%" PRIu64 "\n",
                     zhpeu_appname, lbl,
                     cycles_to_usec(t->tot, t->cnt * divisor),
                     cycles_to_usec(t->min, divisor),
                     cycles_to_usec(t->max, divisor),
                     t->cnt);
}

static void conn_stats_print(struct stuff *conn)
{
    timing_print(&conn->pp_lat, "pp_lat", 2);
    timing_print(&conn->tx_lat, "tx_lat", 1);
    timing_print(&conn->tx_cmp, "tx_cmp", 1);
    timing_print(&conn->rx_lat, "rx_lat", 1);
    zhpeu_print_info("%s:tx/rx %u/%u, tx_oos/max %lu/%d rx_oos/max %lu/%d"
                     " epoll %lu\n",
                     zhpeu_appname, conn->tx_seq, conn->rx_seq,
                     conn->tx_oos, conn->tx_oos_max,
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

    if (stuff->allocated)
        free(stuff);
}

static int conn_tx_msg(struct stuff *conn, uint64_t pp_start, uint8_t flag)
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
    msg->seq = htobe32(conn->tx_seq++);
    msg->flag = flag;
    zhpeq_xq_insert(zxq, ret, false);
    zhpeq_xq_commit(zxq);
    conn->tx_avail--;
    timing_update(&conn->tx_lat, get_cycles(NULL) - start);
 done:

    return ret;
}

static ssize_t conn_tx_completions(struct stuff *conn, bool qfull_ok,
                                   bool qd_check)
{
    ssize_t             ret = 0;
    struct zhpeq_xq     *zxq = conn->zxq;
    uint                i;
    uint                nentries;
    struct enqa_msg     *msg;
    uint32_t            oos;
    struct zhpeq_xq_cq_entry zxq_comp[64];

    ret = zhpeq_xq_cq_read(zxq, zxq_comp, ARRAY_SIZE(zxq_comp));
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_xq_cq_read", "", ret);
        goto done;
    }
    if (!ret)
        goto done;;
    nentries = ret;
    ret = 0;
    for (i = 0; i < nentries; i++) {
        msg = zxq_comp[i].z.context;
        timing_update(&conn->tx_cmp, get_cycles(NULL) - be64toh(msg->tx_start));
        oos = be32toh(msg->seq) - conn->cq_seq;
        if (likely(!oos))
            conn->cq_seq++;
        else {
            conn->tx_oos++;
            conn->tx_oos_max = max(conn->tx_oos_max, oos);
        }
        conn->tx_avail++;
        if (zxq_comp[i].z.status != ZHPEQ_XQ_CQ_STATUS_SUCCESS) {
            if (!qfull_ok ||
                zxq_comp[i].z.status != ZHPE_HW_CQ_STATUS_GENZ_RDM_QUEUE_FULL)
                zhpeu_print_err("%s,%u:cqe %p ctx %p index 0x%x status 0x%x\n",
                                __func__, __LINE__,
                                zxq_comp[i].z.cqe, zxq_comp[i].z.context,
                                zxq_comp[i].z.index, zxq_comp[i].z.status);
            ret = -EIO;
        }
        if (qd_check && zxq_comp[i].z.qd != conn->qd_last) {
            zhpeu_print_info("%s,%u:cqe %p ctx %p index 0x%x qd 0x%x\n",
                             __func__, __LINE__,
                             zxq_comp[i].z.cqe, zxq_comp[i].z.context,
                             zxq_comp[i].z.index, zxq_comp[i].z.qd);
            conn->qd_last = zxq_comp[i].z.qd;
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

static int conn_rx_oos_insert(struct stuff *conn, struct zhpe_rdm_entry *rqe,
                              uint32_t oos)
{
    int                 ret = 0;
    uint32_t            off = oos + (conn->rx_seq - conn->rx_oos_ent_base);

    if (off >= ARRAY_SIZE(conn->rx_oos_ent)) {
        ret = -EOVERFLOW;
        goto done;
    }
    conn->rx_oos++;
    conn->rx_oos_max = max(conn->rx_oos_max, oos);
    conn->rx_oos_ent_cnt++;
    conn->rx_oos_ent[off] = *rqe;
    conn->rx_oos_ent[off].hdr.valid = 1;
    /* Advance the queue head, but not conn->rx_seq. */
    zhpeq_rq_entry_done(conn->zrq, 1, true);
 done:
    return ret;
}

static int conn_rx_oos(struct stuff *conn, struct enqa_msg *msg_out,
                       uint32_t oos, struct zhpe_rdm_entry *rqe)
{
    int                 ret;
    uint32_t            off;

    /* Assume 0, 3, 2, 1, 4, ...  */
    if (!conn->rx_oos_ent_cnt) {
        /*
         * Given the example above: conn->rx_seq == 1 and oos == 2; we know
         * we don't have to save the rqe for tx_seq == 1, so the base for
         * saving things starts at conn->rx_seq + 1 or 2.
         */
        conn->rx_oos_ent_base = conn->rx_seq + 1;
        ret = conn_rx_oos_insert(conn, rqe, oos);
        goto done;
    }
    /*
     * If there is a saved entry for the current conn->rx_seq,
     * we return it and advance conn->rx_seq; we do not advance the queue head.
     *
     * If there is no saved entry, then we save the new entry.
     */
    off = conn->rx_seq - conn->rx_oos_ent_base;
    if (conn->rx_oos_ent[off].hdr.valid) {
        conn->rx_oos_ent_cnt--;
        *msg_out = *(struct enqa_msg *)conn->rx_oos_ent[off].payload;
        conn->rx_oos_ent[off].hdr.valid = 0;
        ret = 1;
        conn->rx_seq++;
    } else
        ret = conn_rx_oos_insert(conn, rqe, oos);
 done:

    return ret;
}

struct rx_log {
    int line;
    uint32_t head;
    uint64_t v[3];
};

struct rx_log rx_log[4096];

uint32_t rx_log_idx;

void do_rx_log(uint line, uint32_t head, uint64_t v0, uint64_t v1, uint64_t v2)
{
    uint32_t i = rx_log_idx++ & (ARRAY_SIZE(rx_log) - 1);

    rx_log[i].line = line;
    rx_log[i].head = head;
    rx_log[i].v[0] = v0;
    rx_log[i].v[1] = v1;
    rx_log[i].v[2] = v2;
}

static int conn_rx_msg(struct stuff *conn, struct enqa_msg *msg_out,
                       bool sleep_ok)
{
    int                 ret = 0;
    struct zhpeq_rq     *zrq = conn->zrq;
    struct zhpe_rdm_entry *rqe = NULL; /* ! */
    struct enqa_msg     *msg;
    uint64_t            now;
    uint32_t            oos;

    do_rx_log(__LINE__, zrq->head, 0, 0, 0);
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
                break;
            } else
                break;
        }
        if (likely(rqe = zhpeq_rq_entry_valid(zrq))) {

            now = get_cycles(NULL);
            if (conn->rx_last)
                timing_update(&conn->rx_lat, now - conn->rx_last);
            conn->rx_last = now;

            msg = (void *)rqe->payload;
            oos = be32toh(msg->seq) - conn->rx_seq;
            if (likely(!oos)) {
                conn->rx_seq++;
                *msg_out = *msg;
                assert(!memcmp(msg_out, msg, sizeof(*msg)));
                zhpeq_rq_entry_done(zrq, 1, true);
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
    do_rx_log(__LINE__, zrq->head, ret, (uintptr_t)rqe, 0);

    return ret;
}

static int do_server_pong(struct stuff *conn)
{
    int                 ret = 0;
    uint                tx_flag_in = TX_NONE;
    uint64_t            op_count;
    uint64_t            warmup_count;
    uint64_t            i;
    struct enqa_msg     msg;
    uint32_t            rx_seq MAYBE_UNUSED;

    zhpeq_print_xq_info(conn->zxq);

    conn_tx_stats_reset(conn);

    /*
     * First, the client will send conn->qlen  + 1 messages to overrun the
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
    conn_rx_stats_reset(conn, 0);
    for (i = 0, rx_seq = conn->rx_seq; i < conn->qlen; i++, rx_seq++) {
        ret = conn_rx_msg(conn, &msg, false);
        if (ret < 0)
            goto done;
        if (!ret)
            continue;
        assert(be32toh(msg.seq) == rx_seq);
        assert(conn->rx_seq == rx_seq + 1);
    }

    conn_stats_print(conn);

    /* Second, an epoll test. Server rate limits to force epoll. */
    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Receive all pending entries. */
    conn_rx_stats_reset(conn, 0);
    for (i = 0, rx_seq = conn->rx_seq; i < DEFAULT_EPOLL; i++, rx_seq++) {
        ret = conn_rx_msg(conn, &msg, true);
        if (ret < 0)
            goto done;
        assert(ret == 1);
        assert(be32toh(msg.seq) == rx_seq);
        assert(conn->rx_seq == rx_seq + 1);
    }

    conn_stats_print(conn);

    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Finally a pingpong test. Handshake before beginning. */
    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Server only sends as many times as it receives. */
    conn_tx_stats_reset(conn);
    conn_rx_stats_reset(conn, 0);
    for (op_count = warmup_count = 0, rx_seq = conn->rx_seq;
         tx_flag_in != TX_LAST; op_count++, rx_seq++) {
        /*
         * Receive a packet, send a packet: we are guaranteed the messages are
         * in sequence; we send an immediate reply to so we don't have to
         * buffer the messages to be able to reflect the pp_start and flag
         * to the client.
         */
        for (;;) {
            ret = conn_rx_msg(conn, &msg, false);
            if (ret > 0)
                break;
            if (unlikely(ret < 0))
                goto done;
        }
        assert(be32toh(msg.seq) == rx_seq);
        assert(conn->rx_seq == rx_seq + 1);
        if (msg.flag != tx_flag_in) {
            if (tx_flag_in == TX_WARMUP) {
                warmup_count = op_count;
                conn_tx_stats_reset(conn);
                conn_rx_stats_reset(conn, conn->rx_last);
            }
            tx_flag_in = msg.flag;
        }
        for (;;) {
            ret = conn_tx_msg(conn, msg.pp_start, msg.flag);
            if (ret >= 0)
                break;
            if (ret != -EAGAIN)
                goto done;
            ret = conn_tx_completions(conn, false, false);
            if (ret < 0)
                goto done;
        }
    }

    /* Wait for all transmits to complete. */
    ret = conn_tx_completions_wait(conn, false, false);
    if (ret < 0)
        goto done;

    zhpeu_print_info("%s:op_cnt/warmup %lu/%lu\n",
                     zhpeu_appname, op_count - warmup_count, warmup_count);
    conn_stats_print(conn);
 done:

    return ret;
}

static int do_client_pong(struct stuff *conn)
{
    int                 ret = 0;
    const struct args   *args = conn->args;
    uint                tx_flag_in = TX_NONE;
    uint                tx_flag_out = TX_WARMUP;
    uint64_t            rx_avail = conn->qlen;
    uint64_t            tx_count;
    uint64_t            rx_count;
    uint64_t            warmup_count;
    uint64_t            i;
    struct enqa_msg     msg;
    uint64_t            start;
    uint64_t            delta;
    uint32_t            rx_seq MAYBE_UNUSED;

    zhpeq_print_xq_info(conn->zxq);

    conn_rx_stats_reset(conn, 0);

    /*
     * First, the client will send conn->qlen + 1 messages and then
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
    for (i = 0; i < conn->qlen; i++) {
        ret = conn_tx_msg(conn, 0, 0);
        if (ret < 0)
            goto done;
        ret = conn_tx_completions_wait(conn, false, true);
        if (ret < 0)
            goto done;
    }
#if 0
    ret = conn_tx_msg(conn, 0, 0);
    if (ret < 0)
        goto done;
    for (;;) {
        ret = conn_tx_completions(conn, true, true);
        if (!ret)
            continue;
        assert(ret == -EIO);

        break;
    }
#endif
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
        ret = conn_tx_msg(conn, 0, 0);
        if (ret < 0)
            goto done;
        ret = conn_tx_completions_wait(conn, false, false);
        if (ret < 0)
            goto done;
        while (get_cycles(NULL) - start < conn->poll_cycles * 2)
            yield();
    }

    conn_stats_print(conn);

    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Finally a pingpong test. Handshake before beginning. */
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /*
     * Client tracks notional numbers of receives available and
     * doesn't overrun the server.
     */
    conn_tx_stats_reset(conn);
    conn_rx_stats_reset(conn, 0);
    rx_seq = conn->rx_seq;
    start = get_cycles(NULL);
    for (tx_count = rx_count = warmup_count = 0;
         tx_count != rx_count || tx_flag_out != TX_LAST; ) {
        /* Receive packets up to first miss. */
        for (rx_seq = conn->rx_seq;tx_flag_in != TX_LAST;
             rx_count++, rx_seq++) {
            ret = conn_rx_msg(conn, &msg, false);
            if (unlikely(ret < 0))
                goto done;
            if (!ret)
                break;
            assert(be32toh(msg.seq) == rx_seq);
            assert(conn->rx_seq == rx_seq + 1);
            /* Messages are in sequence. */
            rx_avail++;
            if (msg.flag != tx_flag_in) {
                if (tx_flag_in == TX_WARMUP) {
                    warmup_count = rx_count;
                    conn_rx_stats_reset(conn, conn->rx_last);
                }
                tx_flag_in = msg.flag;
            }
            timing_update(&conn->pp_lat,
                          get_cycles(NULL) - be64toh(msg.pp_start));
        }

        ret = conn_tx_completions(conn, false, false);
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

            ret = conn_tx_msg(conn, 0, tx_flag_out);
            if (ret < 0) {
                if (ret == -EAGAIN) {
                    if (tx_flag_out == TX_LAST)
                        tx_flag_out = TX_RUNNING;
                    break;
                }
                goto done;
            }
        }
    }

    zhpeu_print_info("%s:op_cnt/warmup %lu/%lu\n",
                     zhpeu_appname, tx_count - warmup_count, warmup_count);
    conn_stats_print(conn);
 done:

    return ret;
}

struct q_wire_msg {
    /* Actual queue length. */
    uint64_t            qlen;
};

int do_q_setup(struct stuff *conn)
{
    int                 ret;
    const struct args   *args = conn->args;
    union sockaddr_in46 sa;
    size_t              sa_len = sizeof(sa);
    struct zhpeq_attr   attr;
    struct q_wire_msg   q_msg;

    ret = zhpeq_query_attr(&attr);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_query_attr", "", ret);
        goto done;
    }

    ret = -EINVAL;
    conn->qlen = args->qlen;
    if (conn->qlen) {
        if (conn->qlen > attr.z.max_tx_qlen)
            goto done;
    } else
        conn->qlen = DEFAULT_QLEN;
    conn->tx_max = conn->tx_avail = conn->qlen;

    conn->poll_cycles = usec_to_cycles(args->poll_usec ?: DEFAULT_POLL);

    /* Allocate domain. */
    ret = zhpeq_domain_alloc(&conn->zdom);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", ret);
        goto done;
    }
    /* Allocate zqueues. */
    ret = zhpeq_xq_alloc(conn->zdom, conn->qlen, conn->qlen,
                         0, 0, 0,  &conn->zxq);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_xq_alloc", "", ret);
        goto done;
    }

    ret = zhpeq_rq_alloc(conn->zdom, conn->qlen * 4, 0, &conn->zrq);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_rq_alloc", "", ret);
        goto done;
    }
    /*
     * conn->qlen is the actual size of the queues; conn->tx_max is the
     * requested size of the queues. This will allow the user to specify
     * 16 and user only command buffers.
     */
    conn->qlen = conn->zxq->xqinfo.cmdq.ent - 1;
#if 0
    if (!zhpeu_expected_saw("qlen1", conn->zxq->xqinfo.cmdq.ent,
                            conn->zxq->xqinfo.cmplq.ent) ||
        !zhpeu_expected_saw("qlen2", conn->zxq->xqinfo.cmdq.ent,
                            conn->zrq->rqinfo.cmplq.ent)) {
        ret = -EIO;
        goto done;
    }
#endif
    /* Exchange resulting queue length between client and server. */
    q_msg.qlen = htobe64(conn->qlen);
    ret = _zhpeu_sock_send_blob(conn->sock_fd, &q_msg, sizeof(q_msg));
    if (ret < 0)
        goto done;
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, &q_msg, sizeof(q_msg));
    if (ret < 0)
        goto done;
    q_msg.qlen = be64toh(q_msg.qlen);
    if (!zhpeu_expected_saw("qlen3", conn->qlen, q_msg.qlen)) {
        ret = -EIO;
        goto done;
    }

    /* Get address index. */
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
    args->qlen = be64toh(cli_msg.qlen);
    args->once_mode = cli_msg.once_mode;

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
    cli_msg.qlen = htobe64(args->qlen);
    cli_msg.once_mode = args->once_mode;

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
        "Server requires just port; client requires all 5 arguments.\n"
        "Client only options:\n"
        " -o : run once and then server will exit\n"
        " -s : treat the final argument as seconds\n"
        " -p <poll_usec> : length of receive polling before sleeping\n"
        " -q <qlen> : tx and rx queue length\n"
        " -w <ops> : number of warmup operations\n",
        zhpeu_appname);

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

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "op:q:sw:")) != -1) {

        /* All opts are client only, now. */
        client_opt = true;

        switch (opt) {

        case 'o':
            if (args.once_mode)
                usage(false);
            args.once_mode = true;
            break;

        case 'p':
            if (args.poll_usec)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("poll_usec", optarg, &args.poll_usec,
                                         0, 1, SIZE_MAX,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 'q':
            if (args.qlen)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("qlen", optarg, &args.qlen, 0, 1,
                                         SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 's':
            if (args.seconds_mode)
                usage(false);
            args.seconds_mode = true;
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
