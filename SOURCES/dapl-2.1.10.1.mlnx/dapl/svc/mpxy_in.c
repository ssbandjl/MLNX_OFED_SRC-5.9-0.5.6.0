/*
 * Copyright (c) 2012-2015 Intel Corporation. All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/*
 * mpxyd service - mpxy_in.c
 *
 * 	Proxy-out resources/services
 *
 */
#include "mpxyd.h"

extern int log_level;
extern int mcm_wc_max;
extern int mcm_rr_signal;
extern int mcm_rr_max;
extern int mcm_wr_max;
extern int mcm_rx_entries;
extern int mcm_ib_signal_rate;
extern uint64_t system_guid;

void m_pi_destroy_wc_q(struct mcm_qp *m_qp)
{
	mlog(2, " Destroying QP %p PI WC_q %p\n", m_qp, m_qp->wrc.wc_addr);
	if (m_qp->wc_rbuf_mr) {
		ibv_dereg_mr(m_qp->wc_rbuf_mr);
		m_qp->wc_rbuf_mr = NULL;
	}
	if (m_qp->wrc.wc_addr) {
		free((void*)m_qp->wrc.wc_addr);
		m_qp->wrc.wc_addr = 0;
	}
}

/* buffer pools for proxy inbound RDMA work request, RX queue, and completion entries, IB registration for RDMA writes */
void m_pi_destroy_bpool(struct mcm_qp *m_qp)
{
	if (m_qp->wr_rbuf_mr) {
		ibv_dereg_mr(m_qp->wr_rbuf_mr);
		m_qp->wr_rbuf_mr = NULL;
	}
	if (m_qp->wrc.wr_addr) {
		free((void*)m_qp->wrc.wr_addr);
		m_qp->wrc.wr_addr = 0;
	}
	m_pi_destroy_wc_q(m_qp);

	if (m_qp->sr_buf) {
		free(m_qp->sr_buf);
		m_qp->sr_buf = 0;
	}
	if (m_qp->wc_buf_rx_mr) {
		ibv_dereg_mr(m_qp->wc_buf_rx_mr);
		m_qp->wc_buf_rx_mr = NULL;
	}
	if (m_qp->wc_buf_rx) {
		free(m_qp->wc_buf_rx);
		m_qp->wc_buf_rx = 0;
	}
}

int m_pi_create_wr_q(struct mcm_qp *m_qp, int entries)
{
	/* RDMA proxy WR pool, register with SCIF and IB, set pool and segm size with parameters */
	m_qp->wrc.wr_sz = ALIGN_64(sizeof(struct mcm_wr_rx));
	m_qp->wrc.wr_len = m_qp->wrc.wr_sz * entries; /* 64 byte aligned for signal_fence */
	m_qp->wrc.wr_end = entries - 1;
	m_qp->wr_hd_r = 0;
	m_qp->wr_tl_r = 0;
	m_qp->wr_tl_r_wt = 1; /* start at tl+1 */

	if (posix_memalign((void **)&m_qp->wrc.wr_addr, 4096, ALIGN_PAGE(m_qp->wrc.wr_len))) {
		mlog(0, "failed to allocate wr_rbuf, m_qp=%p, wr_len=%d, entries=%d\n",
			m_qp, m_qp->wrc.wr_len, entries);
		return -1;
	}
	memset((void*)m_qp->wrc.wr_addr, 0, ALIGN_PAGE(m_qp->wrc.wr_len));

	mlog(4, " WR rbuf pool %p, LEN req=%d, act=%d\n",
		m_qp->wrc.wr_addr, m_qp->wrc.wr_len, ALIGN_PAGE(m_qp->wrc.wr_len) );

	m_qp->wr_rbuf_mr = ibv_reg_mr(m_qp->smd->md->pd, (void*)m_qp->wrc.wr_addr, m_qp->wrc.wr_len,
				       IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

	if (!m_qp->wr_rbuf_mr) {
		mlog(0, " IB_register addr=%p,%d failed %s\n",
		     m_qp->wrc.wr_addr, ALIGN_PAGE(m_qp->wrc.wr_len), strerror(errno));
		return -1;;
	}
	m_qp->wrc.wr_addr = (uint64_t)(uintptr_t)m_qp->wr_rbuf_mr->addr;
	m_qp->wrc.wr_rkey = m_qp->wr_rbuf_mr->rkey;

	mlog(4, " IB_mr for wr_buf addr %p, off 0x%llx, len %d, entries %d, rkey %x lkey %x\n",
		m_qp->wrc.wr_addr, m_qp->wr_rbuf_mr->addr, ALIGN_PAGE(m_qp->wrc.wr_len),
		entries, m_qp->wr_rbuf_mr->rkey, m_qp->wr_rbuf_mr->rkey);

	m_qp->wr_off_r = scif_register(m_qp->smd->scif_tx_ep, (void*)m_qp->wrc.wr_addr, ALIGN_PAGE(m_qp->wrc.wr_len),
				      (off_t)0, SCIF_PROT_READ | SCIF_PROT_WRITE, 0);
	if (m_qp->wr_off_r == (off_t)(-1)) {
		mlog(0, " SCIF_register addr=%p,%d failed %s\n",
		     m_qp->wrc.wr_addr, ALIGN_PAGE(m_qp->wrc.wr_len), strerror(errno));
		return -1;
	}

	mlog(4, " WR rbuf pool %p, LEN req=%d, act=%d\n", m_qp->wr_buf, m_qp->wr_len, ALIGN_PAGE(m_qp->wrc.wr_len));
	mlog(4, " SCIF_mr for wr_rbuf addr %p, off 0x%llx, len %d, entries %d\n",
		m_qp->wrc.wr_addr, m_qp->wr_off_r, ALIGN_PAGE(m_qp->wrc.wr_len), entries);

	if (!m_qp->smd->md->indata) {
		if (posix_memalign((void **)&m_qp->wc_buf_rx, 4096, entries * sizeof(mcm_wc_rx_t))) {
			mlog(0, "failed to allocate wc_buf_rx, m_qp=%p, wr_rx_len=%d, entries=%d\n",
				 m_qp, entries * sizeof(mcm_wc_rx_t), entries);
			goto err;
		}
		memset(m_qp->wc_buf_rx, 0, entries * sizeof(mcm_wc_rx_t));

		m_qp->wc_buf_rx_mr = ibv_reg_mr(m_qp->smd->md->pd, (void*)m_qp->wc_buf_rx,
						entries * sizeof(mcm_wc_rx_t),
					        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
		if (!m_qp->wc_buf_rx_mr) {
			mlog(0, " IB_register addr=%p,%d failed %s\n",
				m_qp->wc_buf_rx_mr->addr,
				entries * sizeof(mcm_wc_rx_t),
				strerror(errno));
			goto err;
		}
		mlog(4, " no inline support: WC_buf_rx pool %p, LEN %d\n",
			m_qp->wc_buf_rx, entries * sizeof(mcm_wc_rx_t) );
		mlog(4, " no inline support: WC_buf_rx_mr = %x\n", m_qp->wc_buf_rx_mr);
	}
	return 0;
err:
	m_pi_destroy_bpool(m_qp);
	return -1;
}

int m_pi_create_wc_q(struct mcm_qp *m_qp, int entries)
{
	/* RDMA proxy WC pool, register with SCIF and IB, set pool and segm size with parameters */
	m_qp->wrc.wc_sz = ALIGN_64(sizeof(struct mcm_wc_rx));
	m_qp->wrc.wc_len = m_qp->wrc.wc_sz * entries; /* 64 byte aligned for signal_fence */
	m_qp->wrc.wc_end = entries - 1;
	m_qp->wc_hd_rem = 0;
	m_qp->wc_tl_rem = 0;

	if (posix_memalign((void **)&m_qp->wrc.wc_addr, 4096, ALIGN_PAGE(m_qp->wrc.wc_len))) {
		mlog(0, "failed to allocate wc_rbuf, m_qp=%p, wc_len=%d, entries=%d\n",
			m_qp, m_qp->wrc.wc_len, entries);
		return -1;
	}
	memset((void*)m_qp->wrc.wc_addr, 0, ALIGN_PAGE(m_qp->wrc.wc_len));

	mlog(4, " WC rbuf pool %p, LEN req=%d, act=%d\n",
		m_qp->wrc.wc_addr, m_qp->wrc.wc_len, ALIGN_PAGE(m_qp->wrc.wc_len));

	m_qp->wc_rbuf_mr = ibv_reg_mr(m_qp->smd->md->pd, (void*)m_qp->wrc.wc_addr, m_qp->wrc.wc_len,
				      IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
	if (!m_qp->wc_rbuf_mr) {
		mlog(0, " IB_register addr=%p,%d failed %s\n",
		        m_qp->wrc.wc_addr, ALIGN_PAGE(m_qp->wrc.wc_len), strerror(errno));
		return -1;
	}
	m_qp->wrc.wc_addr = (uint64_t)(uintptr_t)m_qp->wc_rbuf_mr->addr;
	m_qp->wrc.wc_rkey = m_qp->wc_rbuf_mr->rkey;

	mlog(4, " IB_mr for wc_buf addr %p, mr 0x%llx, len %d, entries %d rkey %x lkey %x\n",
		m_qp->wrc.wc_addr, m_qp->wc_rbuf_mr->addr, ALIGN_PAGE(m_qp->wrc.wc_len),
		entries, m_qp->wc_rbuf_mr->rkey, m_qp->wc_rbuf_mr->lkey);

	return 0;
}

int m_pi_create_sr_q(struct mcm_qp *m_qp, int entries)
{
	/* create SR queue for messages */
	m_qp->sr_sz = sizeof(dat_mix_sr_t);
	m_qp->sr_len = m_qp->sr_sz * entries;
	m_qp->sr_end = entries;
	m_qp->sr_hd = 0;
	m_qp->sr_tl = 0;
	if (posix_memalign((void **)&m_qp->sr_buf, 4096, ALIGN_PAGE(m_qp->sr_len))) {
		mlog(0, "failed to allocate sr_buf, m_qp=%p, sr_len=%d, entries=%d\n",
			m_qp, m_qp->sr_len, entries);
		return -1;
	}
	memset(m_qp->sr_buf, 0, m_qp->sr_len);
	mlog(4, " SR rx queue - %p, qlen %d, entries %d, entry_sz %d\n",
		m_qp->sr_buf, m_qp->sr_len, entries, sizeof(dat_mix_sr_t));

	return 0;
}

/* called with m_qp->rxlock */
static inline void m_pi_free_sr(struct mcm_qp *m_qp, struct mcm_sr *sr)
{
	struct mcm_sr *sr_tail = (struct mcm_sr *)(m_qp->sr_buf + (m_qp->sr_sz * m_qp->sr_tl));

	if (sr_tail != sr) {
		mlog(0, " ERR: SR free - %p [%d]  != tl %p [%d], tl %d hd %d\n",
			sr, sr->s_idx, sr_tail, sr_tail->s_idx, m_qp->sr_tl, m_qp->sr_hd);
	}
	sr->wr_id = 0; sr->w_idx = 0; sr->s_idx = 0;

	if (++m_qp->sr_tl == m_qp->sr_end)
		m_qp->sr_tl = 0;
}

/* called with m_qp->rxlock */
static inline struct mcm_sr *m_pi_get_sr(struct mcm_qp *m_qp, int wr_idx)
{
	int idx = m_qp->sr_tl;
	struct mcm_sr *sr;

	while (idx != m_qp->sr_hd) {
		sr = (struct mcm_sr *)(m_qp->sr_buf + (m_qp->sr_sz * idx));
		if (sr->wr_id && !sr->w_idx) { /* first SR slot not taken with WR_rx */
			sr->w_idx = wr_idx;
			return sr;
		}
		if (++idx == m_qp->sr_end)
			idx = 0;
	}
	return NULL;
}

int m_pi_create_bpool(struct mcm_qp *m_qp, int max_recv_wr)
{
	/* PI work request queue, updated from peer PO service via RW_imm */
	if (m_pi_create_wr_q(m_qp, max_recv_wr))
		goto err;

	/* PO work completion queue, updated from peer PI service via RW_imm */
	if (m_pi_create_wc_q(m_qp, max_recv_wr))
		goto err;

	/* PI SR recv queue, updated via RR's for inbound send operations */
	if (m_pi_create_sr_q(m_qp, max_recv_wr))
		goto err;

	return 0;
err:
	m_pi_destroy_bpool(m_qp);
	return -1;
}

/* called with smd->rblock */
static int m_pi_buf_ordered(mcm_scif_dev_t *smd, int next)
{
	int idx;

	if (smd->m_buf_hd_r == 0)  /* previous m_idx */
		idx = smd->m_buf_end_r;
	else
		idx = smd->m_buf_hd_r - 1;

	mlog(8," smd %p - m_buf_wc_r %p: tl %d hd %d buf_wc_hd[%d].m_idx=0x%x next=0x%x\n",
		smd, smd->m_buf_wc_r, smd->m_buf_tl_r, smd->m_buf_hd_r,
		idx, smd->m_buf_wc_r[idx].m_idx, next);

	if (smd->m_buf_wc_r[idx].done || ALIGN_64(smd->m_buf_wc_r[idx].m_idx + 1) == next)
		return 1;
	else
		return 0;

}

/* called with smd->rblock */
static int m_pi_buf_hd(mcm_scif_dev_t *smd, int m_idx, struct mcm_wr_rx *m_wr_rx)
{
	mlog(4," [%d:%d] m_buf_wc_r %p: tl %d hd %d buf_wc_hd[%d].m_idx=0x%x\n",
		smd->md->mc->scif_id, smd->entry.tid, smd->m_buf_wc_r, smd->m_buf_tl_r,
		(smd->m_buf_hd_r + 1) & smd->m_buf_end_r,
		(smd->m_buf_hd_r + 1) & smd->m_buf_end_r, m_idx);

	if (((smd->m_buf_hd_r + 1) & smd->m_buf_end_r) == smd->m_buf_tl_r) {
		mlog(0," ERR: PI Buf WC full (%d) m_buf_wc_r %p:"
			"tl %d hd %d buf_wc_hd_r[%d].m_idx=0x%x\n",
			smd->m_buf_end_r, smd->m_buf_wc_r, smd->m_buf_tl_r + 1,
			smd->m_buf_hd_r, smd->m_buf_hd_r, m_idx);
		return 1;
	}
	smd->m_buf_hd_r = (smd->m_buf_hd_r + 1) & smd->m_buf_end_r; /* move hd */
	smd->m_buf_wc_r[smd->m_buf_hd_r].m_idx = m_idx;
	smd->m_buf_wc_r[smd->m_buf_hd_r].done = 0;
#ifdef MCM_PROFILE
	smd->m_buf_wc_r[smd->m_buf_hd_r].hd = smd->m_hd_r;
	smd->m_buf_wc_r[smd->m_buf_hd_r].tl = smd->m_tl_r;
	smd->m_buf_wc_r[smd->m_buf_hd_r].ref++;
	smd->m_buf_wc_r[smd->m_buf_hd_r].ts = mcm_ts_us();
	smd->m_buf_wc_r[smd->m_buf_hd_r].wr = (void *) m_wr_rx;
	if ((smd->m_hd_ro_r != smd->m_tl_ro_r) && (smd->m_hd_r >= smd->m_tl_r)) {
		struct mcm_qp *m_qp = (struct mcm_qp*)m_wr_rx->context;
		mlog(0, " ERR: [%d:%d:%d] PI_buf HD(%d) passed TL(%d): w_tl %d w_hd %d:"
			" wc_r[%d].m_idx=%x, m_tl %x m_hd %x\n",
			smd->md->mc->scif_id, smd->entry.tid, m_qp->r_entry.tid,
			smd->m_hd_ro_r, smd->m_tl_ro_r, smd->m_buf_tl_r + 1,
			smd->m_buf_hd_r, smd->m_buf_hd_r, m_idx,
			smd->m_tl_r, smd->m_hd_r);
		mcm_check_io();
	}
#endif
	return 0;
}

/* called with smd->rblock */
static void m_pi_buf_tl(mcm_scif_dev_t *smd, int m_idx, struct mcm_wr_rx *m_wr_rx)
{
	int idx;
	int busy = 0, match = 0;
#ifdef MCM_PROFILE
	off_t tl_sav = smd->m_tl_r;
	uint32_t now = mcm_ts_us();
#endif
	idx = (smd->m_buf_tl_r + 1) & smd->m_buf_end_r; /* tl == hd is empty */

	/* mark m_idx complete, move proxy buffer tail until busy slot */
	while ((!match || !busy) && smd->m_buf_tl_r != smd->m_buf_hd_r) {
		if (smd->m_buf_wc_r[idx].m_idx == m_idx) {
			smd->m_buf_wc_r[idx].done = 1;
			match = 1;
#ifdef MCM_PROFILE
			smd->m_buf_wc_r[idx].ref--;
			smd->m_buf_wc_r[idx].ts = now - smd->m_buf_wc_r[idx].ts;
#endif
		}
		if (smd->m_buf_wc_r[idx].done && !busy) {
			smd->m_tl_r = smd->m_buf_wc_r[idx].m_idx;
			smd->m_buf_wc_r[idx].m_idx = 0;
			smd->m_buf_tl_r = (smd->m_buf_tl_r + 1) & smd->m_buf_end_r;
		}
		if (!smd->m_buf_wc_r[idx].done)
			busy = 1;

		if (idx == smd->m_buf_hd_r)
			break;

		idx = (idx + 1) & smd->m_buf_end_r;
	}

#ifdef MCM_PROFILE
	if (tl_sav > smd->m_tl_r)
		smd->m_tl_ro_r++;

	if (!match) {
		mlog(0, " [%d:%d] ERR: m_tl 0x%x m_hd 0x%x"
		        "- m_wc: tl %d hd %d - m_idx=0x%x NO MATCH\n",
			smd->md->mc->scif_id, smd->entry.tid,
			smd->m_tl_r, smd->m_hd_r, smd->m_buf_tl_r,
			(smd->m_buf_hd_r + 1) & smd->m_buf_end_r, m_idx);
		mcm_check_io();
	}
#endif
}

static off_t m_pi_mr_trans(mcm_scif_dev_t *smd, uint64_t raddr, uint32_t rkey, int len)
{
	struct mcm_mr *m_mr;
	uint64_t mr_start, mr_end, scif_off = 0;
	uint32_t offset;

	mlog(8,"LOCATE: 0x%Lx to 0x%Lx, rkey 0x%x len %d\n", raddr, raddr+len, rkey, len);
	mpxy_lock(&smd->mrlock);
	m_mr = get_head_entry(&smd->mrlist);
	while (m_mr) {
		mlog(8, "mr %p: ib_addr 0x%Lx ib_rkey 0x%x len %d\n",
		        m_mr, m_mr->mre.ib_addr, m_mr->mre.ib_rkey, m_mr->mre.mr_len);
		if (m_mr->mre.ib_rkey == rkey) {
			mr_start = m_mr->mre.ib_addr;
			mr_end = m_mr->mre.ib_addr + m_mr->mre.mr_len;
			mlog(8, "rkey match: start %Lx end %Lx\n", mr_start, mr_end);
			if ((raddr >= mr_start) && ((raddr+len) <= mr_end)) {
				mlog(8, " FOUND: mr %p: ib_addr 0x%Lx ib_rkey 0x%x len %d sci_addr %Lx sci_off %x\n",
					 m_mr, m_mr->mre.ib_addr, m_mr->mre.ib_rkey, m_mr->mre.mr_len,
					 m_mr->mre.sci_addr, m_mr->mre.sci_off);
				offset = raddr - mr_start;
				scif_off = m_mr->mre.sci_addr + m_mr->mre.sci_off + offset;
				goto done;
			}
		}
		m_mr = get_next_entry(&m_mr->entry, &smd->mrlist);
	}
done:
	mpxy_unlock(&smd->mrlock);
	mlog(8,"LOCATE: return scif_off == 0x%Lx \n", scif_off);
	return scif_off;
}

int m_pi_prep_rcv_q(struct mcm_qp *m_qp)
{
	struct ibv_recv_wr recv_wr, *recv_err;
	struct ibv_qp *ib_qp;
	int i;

	/* MXS -> MSS or HST, PI service will be on QP1 */
	if (MXF_EP(&m_qp->smd->md->addr) &&
	   (MSS_EP(&m_qp->cm->msg.daddr1) || HST_EP(&m_qp->cm->msg.daddr1)))
	        ib_qp = m_qp->ib_qp1;
	else
		ib_qp = m_qp->ib_qp2;

	if (!ib_qp) {
		mlog(0, " ERR: m_qp %p ib_qp == 0, QP1 %p QP2 %p\n",
			m_qp, m_qp->ib_qp1, m_qp->ib_qp2);
		return -1;
	}
	mlog(4, " post %d 0-byte messages, m_qp %p qpn %x\n",
		mcm_rx_entries, m_qp, ib_qp->qp_num);

	recv_wr.next = NULL;
	recv_wr.sg_list = NULL;
	recv_wr.num_sge = 0;
	recv_wr.wr_id = (uint64_t)(uintptr_t) m_qp;

	/* pre-post zero byte messages for proxy-in service, inbound rdma_writes with immed data */
	for (i=0; i< mcm_rx_entries; i++) {
		errno = 0;
		if (ibv_post_recv(ib_qp, &recv_wr, &recv_err)) {
			mlog(0, " ERR: qpn %x ibv_post_recv[%d] - %s\n",
				ib_qp->qp_num, i, strerror(errno));
			return 1;
		}
		MCNTR(m_qp->smd->md, MCM_QP_RECV);
	}
	return 0;
}

static int m_pi_send_wc_local(struct mcm_qp *m_qp, struct mcm_wr_rx *wr_r, int wc_idx)
{
	mcm_cm_t *m_cm = m_qp->cm;

	mlog(0, " ERR: Po->Pi same node: not implemented\n");
	mlog(0, " CM %p %s SRC 0x%x %x 0x%x %Lx -> DST 0x%x %x 0x%x %Lx %s\n",
		m_cm, mcm_state_str(m_cm->state),
		htons(m_cm->msg.saddr1.lid), htonl(m_cm->msg.saddr1.qpn),
		htons(m_cm->msg.sport),	system_guid,
		htons(m_cm->msg.daddr1.lid), htonl(m_cm->msg.dqpn),
		htons(m_cm->msg.dport), ntohll(m_cm->msg.sys_guid),
		mcm_map_str(m_cm->msg.daddr1.ep_map));
	return 0;
}

/* called with m_qp->rxlock */
static int m_pi_send_wc(struct mcm_qp *m_qp, struct mcm_wr_rx *wr_rx, int status)
{
	struct ibv_send_wr *bad_wr;
	struct ibv_send_wr wr;
	struct ibv_sge sge;
	struct wrc_idata wrc;
	struct mcm_wc_rx wc_rx;
	struct mcm_wc_rx *wc_rx_ptr;
	struct ibv_qp *ib_qp;
	int wc_idx, ret;

	mlog(0x10,"[%d:%d:%d] WC_rem: wr_rx[%d] %p wc_hd %d flgs %x WR_r tl %d-%d"
		  " wt %d hd %d oid %Lx st %d\n",
		m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
		wr_rx->w_idx, wr_rx, m_qp->wc_hd_rem, wr_rx->flags, m_qp->wr_tl_r,
		wr_rx->w_idx, m_qp->wr_tl_r_wt, m_qp->wr_hd_r, wr_rx->org_id, status);

	/* local WR and remote WR are serialized, should never reach tail of remote WR */
	if (((m_qp->wc_hd_rem + 1) & m_qp->wrc.wc_end) == m_qp->wc_tl_rem) {
		mlog(0, " ERR: m_qp %p stalled, peer proxy-out WC queue full hd %d == tl %d\n",
			m_qp, m_qp->wc_hd_rem, m_qp->wc_tl_rem);
		return -1;
	}
	m_qp->wc_hd_rem = (m_qp->wc_hd_rem + 1) & m_qp->wrc.wc_end; /* move remote wc_hd */
	m_qp->wr_tl_r = wr_rx->w_idx; /* move wr_rx tail */

	wc_idx = m_qp->wc_hd_rem;
	wrc.id = (uint16_t)wc_idx;  /* imm_data for proxy_out rcv engine */
	wrc.type = M_WC_TYPE;
	wrc.flags = 0;

	if (m_qp->smd->md->indata) {
		wc_rx_ptr = &wc_rx;
		sge.lkey = 0; /* inline doesn't need registered */
	} else {
		wc_rx_ptr = (struct mcm_wc_rx *)
			    (m_qp->wc_buf_rx + (sizeof(struct mcm_wc_rx) * wc_idx));
		sge.lkey = m_qp->wc_buf_rx_mr->lkey;
	}
	sge.addr = (uint64_t)(uintptr_t) wc_rx_ptr;
	sge.length = (uint32_t) sizeof(struct mcm_wc_rx);

	mcm_hton_wc_rx(wc_rx_ptr, wr_rx, m_qp->wr_tl_r, status);

	/* P2P on same system, keep it local */
	if (htonll(m_qp->cm->msg.sys_guid) == system_guid)
		return (m_pi_send_wc_local(m_qp, wr_rx, wc_idx));

	/* send back a WC with error */
	memset(&wr, 0, sizeof(struct ibv_send_wr));
	wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
	wr.imm_data = htonl(*(uint32_t *)&wrc);
	wr.num_sge = 1;
	wr.send_flags |= IBV_SEND_SIGNALED;
	wr.wr_id = WRID_SET(wr_rx, WRID_RX_RW_IMM);
	wr.wr.rdma.rkey = m_qp->wrc_rem.wc_rkey;
	wr.wr.rdma.remote_addr = (uint64_t)(uintptr_t)((struct mcm_wc_rx *)
				 (m_qp->wrc_rem.wc_addr + (m_qp->wrc_rem.wc_sz * wc_idx)));
	wr.sg_list = &sge;

	if (m_qp->smd->md->indata)
		wr.send_flags |= IBV_SEND_INLINE;

	mlog(4, " WC: RW_imm post: wr_id[%d] %Lx sglist %p sge %d op %d flgs %x"
		" idata %x WR_rem = raddr %p rkey %x io_ln %d op %x\n",
		wr_rx->w_idx, wr.wr_id, wr.sg_list, wr.num_sge, wr.opcode,
		wr.send_flags, ntohl(wr.imm_data), wr.wr.rdma.remote_addr,
		wr.wr.rdma.rkey, wr_rx->sg[0].length, wr_rx->wr.opcode);

	/* MXS -> MSS or HST, PI service will be on QP1 */
	if (MXF_EP(&m_qp->smd->md->addr) &&
	   (MSS_EP(&m_qp->cm->msg.daddr1) || HST_EP(&m_qp->cm->msg.daddr1)))
	        ib_qp = m_qp->ib_qp1;
	else
		ib_qp = m_qp->ib_qp2;

	errno = 0;
	ret = ibv_post_send(ib_qp, &wr, &bad_wr);
	if (ret) {
		mlog(0, " ERR: wr_rx %p rx_idx %d laddr=%p ln=%d lkey=%x\n",
			wr_rx, wr_rx->w_idx, sge.addr, sge.length, sge.lkey);
		mlog(0, " wr_id %Lx %p sglist %p sge %d op %d flgs %x"
			" idata 0x%x raddr %p rkey %x \n",
			wr_rx->wr.wr_id, wr_rx->sg,
			wr_rx->wr.num_sge, wr_rx->wr.opcode,
			wr_rx->wr.send_flags, wr_rx->wr.imm_data,
			wr_rx->wr.wr.rdma.remote_addr, wr_rx->wr.wr.rdma.rkey);
		return ret;
	}

	mlog(4," WC_rem hd %d tl %d, m_qp %p qpn 0x%x, m_cm %p\n",
		m_qp->wc_hd_rem, m_qp->wc_tl_rem, m_qp, ib_qp->qp_num, m_qp->cm);
	return 0;
}

/* called with rxlock, process all RR's up to signal marker at wr_last */
static void m_pi_post_writeto(struct mcm_qp *m_qp, struct mcm_wr_rx *wr_sig)
{
	mcm_scif_dev_t *smd = m_qp->smd;
	struct mcm_wr_rx *wr_rx;
	struct mcm_sr *m_sr = NULL;
	off_t l_off, l_off_wr, r_off = 0;
	int ret, i, l_start, l_end, l_len, sg_len = 0, w_len, num_sge = 0, wr_idx, wr_cnt = 0;
	int wt_flag;

	wr_idx = m_qp->wr_tl_r_wt; /* from WT tail, process RR's posted until reaching wr_last */

	while (m_qp->pi_rr_cnt) { /* RR's pending */
		wr_rx = (struct mcm_wr_rx *)(m_qp->wrc.wr_addr + (m_qp->wrc.wr_sz * wr_idx));

		/* SCIF sync required on IB RW, multiple SCIF writes are not ordered */
		if (m_qp->post_cnt_wt &&
		    (wr_rx->flags & (M_SEND_FS|M_SEND_LS)) &&
		    (!(wr_rx->flags & (M_READ_WRITE_TO_DONE|M_READ_WRITE_TO)))) {
			break;
		}

		if (!(wr_rx->flags & M_READ_DONE)) {
			/* reached head pointer */
			if (wr_idx == m_qp->wr_hd_r)
				break;

			/* maintain order */
			if (wr_rx->flags & M_READ_POSTED)
				break;

			wr_idx = (wr_idx + 1) & m_qp->wrc.wr_end; /* next WR */
			continue;
		}
		wr_cnt++;
#if MCM_PROFILE
		if (wr_rx == wr_sig)
			mcm_qp_prof_ts(m_qp, MCM_QP_IB_RR, wr_rx->time, wr_rx->qcnt, wr_cnt);
#endif
		mlog(4, " WR_rx[%d-%d] %p m_qp %p wr_rx->wr.op %x\n",
			wr_rx->w_idx, wr_sig->w_idx, wr_rx, m_qp, wr_rx->wr.opcode);

		m_qp->pi_rr_cnt--; /* rdma read complete */
		MCNTR(smd->md, MCM_QP_READ_DONE);

		/* if SR or RW_imm, need a posted receive */
		if ((wr_rx->wr.opcode == IBV_WR_SEND) ||
		    (wr_rx->wr.opcode == IBV_WR_RDMA_WRITE_WITH_IMM)) {
			m_sr = m_pi_get_sr(m_qp, wr_rx->w_idx);
			if (!m_sr) {
				mlog(0, " WARNING: SR stalled, no RCV messages posted"
					" m_qp %p, sr_tl %d sr_hd %d\n",
					m_qp, m_qp->sr_tl, m_qp->sr_hd);
				wr_rx->flags |= M_RECV_PAUSED;
				return;
			}
			wr_rx->s_idx = m_sr->s_idx; /* link WR_RX and SR */
			m_sr->len = 0;
			num_sge = m_sr->num_sge;
			sg_len = m_sr->sg[0].length;
			r_off = m_sr->sg[0].addr; /* post recv buffer address */
			mlog(4, " WR %s: m_sr[%d] %p -> scif r_off %Lx ln %d\n",
				(wr_rx->wr.opcode == IBV_WR_SEND) ? "SR":"RW_IMM",
				m_sr->s_idx, m_sr, r_off, sg_len);
		}
		/* need to translate to rdma write dst */
		if (!(wr_rx->wr.opcode == IBV_WR_SEND)) {
			num_sge = 1;
			sg_len = wr_rx->sg[2].length;
			r_off = m_pi_mr_trans(smd, wr_rx->wr.wr.rdma.remote_addr,
					      wr_rx->wr.wr.rdma.rkey, sg_len);
			if (!r_off && sg_len)
				goto bail;

			if (!sg_len) {  /* 0 byte rdma write, no scif */
				mlog(1, " RDMA_WRITE op: wr_rx[%d] %p,"
					 " raddr %p rkey %x 0 bytes\n",
					 wr_rx->w_idx, wr_rx,
					 wr_rx->wr.wr.rdma.remote_addr,
					 wr_rx->wr.wr.rdma.rkey);

				m_qp->post_cnt_wt++;
				wr_rx->flags &= ~M_READ_DONE;
				wr_rx->flags |= M_READ_WRITE_TO;
				wr_rx->wr.wr_id = wr_rx->org_id; /* mark done */

				if (wr_idx == m_qp->wr_hd_r)
					break;

				wr_idx = (wr_idx + 1) & m_qp->wrc.wr_end; /* next WR */
				continue;
			}
		}

		/* sg[0] entry == proxy-out buffer, src for IB RR */
		/* sg[1] entry == proxy-in buffer, dst for IB RR */
		/* sg[2] entry == proxy-in buffer src for scif_sendto */
		/* wr.rdma.remote_addr, wr.rdma.rkey, dst for scif_sento - TPT to sci_off */
		wr_rx->wr.wr_id = 0;
		l_off_wr = (uint64_t) (m_qp->wr_off_r + (wr_rx->w_idx * m_qp->wrc.wr_sz));
		l_off = wr_rx->sg[2].addr;
		l_len = wr_rx->sg[2].length;
		l_start = l_off - (uint64_t)smd->m_offset_r;
		l_end = l_start + l_len;

		for (i=0; (i<num_sge && l_len); i++) {
			w_len = min(sg_len, l_len);
			wt_flag = 0;
			mlog(4, " WR_rx[%d] %p writeto l_off %Lx r_off %Lx rb_off 0x%x-0x%x ln %d org_id %Lx tl %d hd %d\n",
				wr_rx->w_idx, wr_rx, l_off, r_off, l_start, l_end, w_len, wr_rx->org_id,
				m_qp->wr_tl_r, m_qp->wr_hd_r);
#if MCM_PROFILE
			wr_rx->time = mcm_ts_us();
			wr_rx->qcnt = m_qp->post_cnt_wt;
#endif
			if (wr_rx->flags & M_SEND_LS)
				wt_flag |= SCIF_RMA_ORDERED;

			ret = scif_writeto(smd->scif_tx_ep, l_off, w_len, r_off, wt_flag);

			if (ret) {
				mlog(0," [%d:%d:%d] ERR: scif_sendto, ret %d err: %d %s\n",
					smd->md->mc->scif_id, smd->entry.tid, m_qp->r_entry.tid,
					ret, errno, strerror(errno));
				mlog(0," PI: wc %d rr %d stall %d wt %d\n",
				     m_qp->pi_rw_cnt, m_qp->pi_rr_cnt,
				     m_qp->stall_cnt_rr, m_qp->post_cnt_wt);
				mlog(0," PO: wr %d wr_rem %d pst_sig %d cmp_sig %d\n",
				     m_qp->wr_pp, m_qp->wr_pp_rem,
				     m_qp->post_sig_cnt, m_qp->comp_cnt);
				mlog(0, " WR_rx[%d] %p l_o %Lx r_o %Lx rb 0x%x-0x%x ln %d id %Lx tl %d hd %d\n",
					wr_rx->w_idx, wr_rx, l_off, r_off, l_start, l_end, w_len, wr_rx->org_id,
					m_qp->wr_tl_r, m_qp->wr_hd_r);
				goto bail;
			}
			MCNTR(smd->md, MCM_SCIF_WRITE_TO);

			/* adjust for multiple SG entries on post_recv */
			l_off += w_len;
			l_len = l_len - w_len;
			if (m_sr) {
				m_sr->len += w_len;
				r_off = m_sr->sg[i].addr; /* next SR segment */
				sg_len = m_sr->sg[i].length;
			}
		}
		if (l_len) {
			mlog(0, " ERR: RX overrun: written %d remaining %d sge's %d\n",
				wr_rx->sg[2].length, l_len, num_sge);
			goto bail;
		}

		/* signal last segment */
		mlog(4, " SCIF_fence_signal: l_off_wr %p, wr_rx %p wr_idx %d\n",
			l_off_wr, wr_rx, wr_rx->w_idx);

		ret = scif_fence_signal(smd->scif_tx_ep, l_off_wr, wr_rx->org_id, 0, 0,
					SCIF_FENCE_INIT_SELF | SCIF_SIGNAL_LOCAL);
		if (ret) {
			mlog(0," ERR: scif_fence_signal, ret %d %s\n", ret, strerror(errno));
			goto bail;
		}
		MCNTR(smd->md, MCM_SCIF_SIGNAL);
		wr_rx->flags &= ~M_READ_DONE;
		wr_rx->flags |= M_READ_WRITE_TO;
		m_qp->post_cnt_wt++;

		/* reached head */
		if (wr_idx == m_qp->wr_hd_r)
			break;

		wr_idx = (wr_idx + 1) & m_qp->wrc.wr_end; /* next WR */
	}
	return;
bail:
	/* report error via WC back to proxy-out, all pending WRs */
	wr_idx = m_qp->wr_tl_r_wt;
	do {
		wr_rx = (struct mcm_wr_rx *)(m_qp->wrc.wr_addr + (m_qp->wrc.wr_sz * wr_idx));

		mlog(0, " ERR: wr_rx[%d] %p -> IB raddr %Lx %x"
			" SCIF r_o %Lx, ln %d fl %x wt_pnd %d\n",
			wr_rx->w_idx, wr_rx, wr_rx->wr.wr.rdma.remote_addr,
			wr_rx->wr.wr.rdma.rkey, r_off, sg_len, wr_rx->flags,
			m_qp->post_cnt_wt);

		m_pi_send_wc(m_qp, wr_rx, IBV_WC_REM_ACCESS_ERR);
		wr_idx = (wr_idx + 1) & m_qp->wrc.wr_end; /* next WR */

	} while (wr_idx != m_qp->wr_hd_r);

	return;
}

/* Called from TX request thread */
void m_pi_pending_wc(struct mcm_qp *m_qp, int *events)
{
	mpxy_lock(&m_qp->rxlock);
	*events += (m_qp->pi_rw_cnt + m_qp->pi_rr_cnt);
	mpxy_unlock(&m_qp->rxlock);
}

/* RR has completed, forward segment to final dst address via SCIF_sendto */
void m_pi_req_event(struct mcm_qp *m_qp, struct mcm_wr_rx *wr_rx, struct ibv_wc *wc, int type)
{
	mlog(4, " WR_rx[%d] %p %s complete po-addr=%p ln=%d, key=%x ctx=%Lx\n",
		wr_rx->w_idx, wr_rx,
		type == WRID_RX_RR ? "RR":"RW_IMM WC",
		wr_rx->sg[0].addr, wr_rx->sg[0].length,
		wr_rx->sg[0].lkey, wr_rx->context);

	if (wc->status && (wc->status != IBV_WC_WR_FLUSH_ERR)) {
		mlog(0," WR ERR: %s st %d, vn %x rr %d wt %d WC[%d] %p %x %d\n",
			type == WRID_RX_RR ? "RR":"RW_IMM WC",
			wc->status, wc->vendor_err, m_qp->post_cnt_rr,
			m_qp->post_cnt_wt, m_qp->wc_hd_rem,
			m_qp->wrc_rem.wc_addr, m_qp->wrc_rem.wc_rkey,
			m_qp->wrc_rem.wc_sz);
		mlog(0, " WR ERR: wr_rx[%d] oid %Lx sge %d op %d flgs %d"
			" imm 0x%x SRC %p %x ln %d, DST %p %x ln %d\n",
			wr_rx->w_idx, wr_rx->org_id, wr_rx->wr.num_sge,
		        wr_rx->wr.opcode, wr_rx->wr.send_flags, wr_rx->wr.imm_data,
		        wr_rx->sg[0].addr, wr_rx->sg[0].lkey, wr_rx->sg[0].length,
		        wr_rx->sg[1].addr, wr_rx->sg[1].lkey, wr_rx->sg[1].length);

		/* send WC with ERR to RW initiator, hold rxlock */
		mpxy_lock(&m_qp->rxlock);
		if (m_pi_send_wc(m_qp, wr_rx, wc->status))
			mlog(0, "WR ERR: proxy-in to proxy-out WC send failed\n");
		mpxy_unlock(&m_qp->rxlock);
		return;
	}
	/* RR complete, ready for SCIF_writeto to complete RW or SR */
	if (type == WRID_RX_RR) {
		mpxy_lock(&m_qp->rxlock);
		wr_rx->flags &= ~M_READ_POSTED; /* reset READ_POSTED */
		wr_rx->flags |= M_READ_DONE;
		m_pi_post_writeto(m_qp, wr_rx);
		mpxy_unlock(&m_qp->rxlock);
		write(m_qp->smd->md->mc->rx_pipe[1], "w", sizeof "w"); /* signal rx_thread */
		sched_yield();
	}
}

/* called with m_qp->rxlock */
static void m_pi_post_read(struct mcm_qp *m_qp, struct mcm_wr_rx *wr_rx)
{
	mcm_scif_dev_t *smd = m_qp->smd;
	struct ibv_qp *ib_qp;
	char *rbuf;
	int l_start, l_end, ret = 0;
	int l_len = wr_rx->sg[0].length;
	struct ibv_send_wr ib_wr;
	struct ibv_send_wr *bad_wr;

	mlog(4, " [%d:%d:%d] WR_rx[%d] %p RR init: po-addr=%p ln=%d, key=%x ctx=%Lx\n",
		m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
		wr_rx->w_idx, wr_rx, wr_rx->sg[0].addr, wr_rx->sg[0].length,
		wr_rx->sg[0].lkey, wr_rx->context);

	/* shared proxy-in buffer, device level serialization */
	mpxy_lock(&smd->rblock);

	/* Stall if data request arrives before RTU */
	if (m_qp->cm && m_qp->cm->state != MCM_CONNECTED && !m_qp->post_cnt_rr) {
		mlog(1, " [%d:%d:%d] WARN: WR[%d] %p PAUSED !CONN: po-addr=%p"
			" ln=%d, key=%x ctx=%Lx\n",
			m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid,
			m_qp->r_entry.tid, wr_rx->w_idx, wr_rx,
			wr_rx->sg[0].addr, wr_rx->sg[0].length,
			wr_rx->sg[0].lkey, wr_rx->context);
		wr_rx->flags |= M_READ_PAUSED;
		m_qp->stall_cnt_rr++;
		mpxy_unlock(&smd->rblock);
		return;
	}

	/* slice out proxy buffer for this segment */
	l_start = ALIGN_64(smd->m_hd_r);
	if ((l_start + l_len) > smd->m_len_r)
		l_start = 64;
	l_end = l_start + l_len;

	if (pb_full(l_start, l_end, smd->m_hd_r, smd->m_tl_r, l_len, smd->m_len_r)) {
		if (!(wr_rx->flags & M_READ_PAUSED)) {
			wr_rx->flags |= M_READ_PAUSED;
			m_qp->stall_cnt_rr++;
			MCNTR(smd->md, MCM_MX_RR_STALL);

			mlog(1, " WARN[%d:%d:%d] WR_rx[%d] org_id %Lx RR stall (%d)"
				" low mem (%p-%p) hd 0x%x tl 0x%x ln %x,%d\n",
				smd->md->mc->scif_id, smd->entry.tid,
				m_qp->r_entry.tid, wr_rx->w_idx, wr_rx->org_id,
				m_qp->stall_cnt_rr, smd->m_buf_r, smd->m_buf_r + smd->m_len_r,
				smd->m_hd_r, smd->m_tl_r, l_len, l_len);
			mlog(1, " wr[%d] %p RR(%d,%d,%d): flgs %x tl %d tl_wt %d hd %d\n",
				wr_rx->w_idx, wr_rx, m_qp->post_cnt_rr, m_qp->stall_cnt_rr,
				m_qp->pi_rr_cnt,  wr_rx->flags,	m_qp->wr_tl_r, m_qp->wr_tl_r_wt,
				m_qp->wr_hd_r);
		}
		mpxy_unlock(&smd->rblock);
		return;
	}
	rbuf = (char*)(smd->m_buf_r + l_start);

	if ((m_qp->pi_rr_cnt >= mcm_rr_max) && !(wr_rx->flags & M_READ_PAUSED)) {
		wr_rx->flags |= M_READ_PAUSED;
		m_qp->stall_cnt_rr++;
		mlog(0x1, "WARN[%d:%d:%d] WR_rx[%d] max RR's, stalling (%d)"
			" memory (%p-%p) hd 0x%x tl 0x%x %x,%d\n",
			smd->md->mc->scif_id, smd->entry.tid, m_qp->r_entry.tid,
			wr_rx->w_idx, m_qp->stall_cnt_rr,
			smd->m_buf_r, smd->m_buf_r + smd->m_len_r,
			smd->m_hd_r, smd->m_tl_r, l_len, l_len);
		mlog(0x1, " wr[%d] %p RR(%d,%d,%d): flgs %x tl %d tl_wt %d hd %d\n",
			wr_rx->w_idx, wr_rx, m_qp->post_cnt_rr, m_qp->stall_cnt_rr,
			m_qp->pi_rr_cnt,  wr_rx->flags,	m_qp->wr_tl_r, m_qp->wr_tl_r_wt,
			m_qp->wr_hd_r);
		mpxy_unlock(&smd->rblock);
		return;
	}
	/* rbuf available, progress if paused, no progress if any prior IO waiting */
	if (wr_rx->flags & M_READ_PAUSED) {
		m_qp->stall_cnt_rr--;
		wr_rx->flags &= ~M_READ_PAUSED;
		mlog(0x1, "[%d:%d:%d] WR_rx[%d] RR (%d) got memory (%p-%p)"
			" hd 0x%x tl 0x%x (0x%x-0x%x) ln %x,%d\n",
			smd->md->mc->scif_id, smd->entry.tid, m_qp->r_entry.tid,
			wr_rx->w_idx, m_qp->stall_cnt_rr,
			smd->m_buf_r, smd->m_buf_r + smd->m_len_r,
			smd->m_hd_r, smd->m_tl_r, l_start, l_end, l_len, l_len);
	} else if (m_qp->stall_cnt_rr) {
		wr_rx->flags |= M_READ_PAUSED;
		m_qp->stall_cnt_rr++;
		mlog(0x1, "WARN[%d:%d:%d] WR_rx[%d] previous RR stall (%d)"
			" memory (%p-%p) hd 0x%x tl 0x%x %x,%d\n",
			smd->md->mc->scif_id, smd->entry.tid, m_qp->r_entry.tid,
			wr_rx->w_idx, m_qp->stall_cnt_rr, smd->m_buf_r,
			smd->m_buf_r + smd->m_len_r,
			smd->m_hd_r, smd->m_tl_r, l_len, l_len);
		mlog(0x1, " wr[%d] %p RR(%d,%d,%d): flgs %x tl %d tl_wt %d hd %d\n",
			wr_rx->w_idx, wr_rx, m_qp->post_cnt_rr, m_qp->stall_cnt_rr,
			m_qp->pi_rr_cnt,  wr_rx->flags,	m_qp->wr_tl_r, m_qp->wr_tl_r_wt,
			m_qp->wr_hd_r);
		mpxy_unlock(&smd->rblock);
		return;
	}

	/* sg[0] entry == proxy-out buffer, src for IB RR */
	/* sg[1] entry == proxy-in buffer, dst for IB RR */
	/* sg[2] entry == proxy-in buffer src for scif_sendto */
	/* wr.rdma.remote_addr, wr.rdma.rkey, dst for scif_sento */
	wr_rx->sg[1].addr = (uint64_t)(rbuf);
	wr_rx->sg[1].lkey = smd->m_mr_r->lkey;
	wr_rx->sg[1].length = l_len;
	wr_rx->sg[2].addr = (uint64_t)smd->m_offset_r + l_start;
	wr_rx->sg[2].lkey = 0;
	wr_rx->sg[2].length = l_len;

	/* initiate RR from remote po proxy buf to local pi buffer, signal all */
	wr_rx->wr.wr_id = 0; /*  indication of wr_rx type */
	wr_rx->m_idx = 0;

	/* build an ib_wr from wr_rx */
	const_ib_rr(&ib_wr, &wr_rx->wr, (struct ibv_sge*)wr_rx->sg);
	ib_wr.wr_id = WRID_SET(wr_rx, WRID_RX_RR);

	/* signal and mark rbuf idx, if m_idx out of order must mark and signal */
	if ((wr_rx->flags & M_SEND_LS) ||
	    (!m_pi_buf_ordered(smd, rbuf - smd->m_buf_r)) ||
	    (m_qp->pi_rr_cnt == mcm_rr_max-1) ||
	    (!((m_qp->post_cnt_rr+1) % mcm_rr_signal))) {
		ib_wr.send_flags = IBV_SEND_SIGNALED;
		wr_rx->m_idx = ((rbuf + (l_len - 1)) - smd->m_buf_r);
		if (m_pi_buf_hd(smd, wr_rx->m_idx, wr_rx)) {
			mpxy_unlock(&smd->rblock);
			goto buf_err;
		}
	}
#ifdef MCM_PROFILE
	if (l_end < smd->m_hd_r)
		smd->m_hd_ro_r++;
#endif
	/*
	 * update shared proxy-in buffer hd, save end of buffer idx
	 * and save ref m_idx for out of order completions across QP's
	 */
	smd->m_hd_r = l_end;
	mpxy_unlock(&smd->rblock);

	/* MXS -> MSS or HST, PI service will be on QP1 */
	if (MXF_EP(&m_qp->smd->md->addr) &&
	   (MSS_EP(&m_qp->cm->msg.daddr1) || HST_EP(&m_qp->cm->msg.daddr1)))
	        ib_qp = m_qp->ib_qp1;
	else
		ib_qp = m_qp->ib_qp2;

#if MCM_PROFILE
	wr_rx->time = mcm_ts_us();
	wr_rx->qcnt = m_qp->pi_rr_cnt;
#endif

	if (wr_rx->flags & M_PROXY_INLINE) {
		mlog(0x10, "wr_rx flag PROXY_INLINE is set. data len %d\n", wr_rx->sg[0].length);
		memcpy((void *)rbuf, wr_rx->inline_data, wr_rx->sg[0].length);
		m_qp->pi_rr_cnt++;
		m_qp->post_cnt_rr++;
		wr_rx->flags |= M_READ_DONE;
		m_pi_post_writeto(m_qp, wr_rx);
	}
	else {
		errno = 0;
		wr_rx->flags |= M_READ_POSTED;
		ret = ibv_post_send(ib_qp, &ib_wr, &bad_wr);
		if (ret)
			goto bail;

		m_qp->pi_rr_cnt++;
		m_qp->post_cnt_rr++;
		MCNTR(smd->md, MCM_QP_READ);

		mlog(0x10, "[%d:%d:%d] WR[%d] %p RR(%d,%d,%d): wr_id %Lx qn %x flgs %x,%x ln %d "
			   "r_addr,key %Lx %x to l_addr,key %Lx %x tl %d hd %d, m_idx %x\n",
			smd->md->mc->scif_id, smd->entry.tid, m_qp->r_entry.tid,
			wr_rx->w_idx, wr_rx, m_qp->post_cnt_rr, m_qp->stall_cnt_rr,
			m_qp->pi_rr_cnt, ib_wr.wr_id, ib_qp->qp_num, ib_wr.send_flags,
			wr_rx->flags, l_len, ib_wr.wr.rdma.remote_addr,
			ib_wr.wr.rdma.rkey, ib_wr.sg_list->addr, ib_wr.sg_list->lkey,
			m_qp->wr_tl_r, m_qp->wr_hd_r, wr_rx->m_idx);
	}
	write(smd->md->mc->tx_pipe[1], "w", sizeof "w");
	return;
bail:
	mpxy_lock(&smd->rblock);
	mlog(0x0, "[%d:%d:%d] ERR: WR[%d] %p RR(%d,%d,%d): wr_id %Lx qn %x f=%x,%x ln %d "
		   "RA %Lx %x to LA %Lx %x tl %d hd %d, m=%x\n",
		smd->md->mc->scif_id, smd->entry.tid, m_qp->r_entry.tid,
		wr_rx->w_idx, wr_rx, m_qp->post_cnt_rr, m_qp->stall_cnt_rr,
		m_qp->pi_rr_cnt, ib_wr.wr_id, ib_qp->qp_num, ib_wr.send_flags,
		wr_rx->flags, l_len, ib_wr.wr.rdma.remote_addr,
		ib_wr.wr.rdma.rkey, ib_wr.sg_list->addr, ib_wr.sg_list->lkey,
		m_qp->wr_tl_r, m_qp->wr_hd_r, wr_rx->m_idx);
	m_pi_buf_tl(smd, wr_rx->m_idx, wr_rx); /* return buffer slot */
	mpxy_unlock(&smd->rblock);
buf_err:
	m_qp->stall_cnt_rr++;
	wr_rx->flags |= M_READ_PAUSED;
	wr_rx->flags &= ~M_READ_POSTED;

	mlog(0, " WARN[%d] (%d,%d): wr[%d] %p RR ibv_post/pi_buf ERR stall (%d,%d,%d,%d):"
		" flgs 0x%x ln %d r_addr,key %Lx %x to l_addr,key %Lx %x"
		" tl %d w_tl %d hd %d\n",
		smd->entry.tid, ret, errno, wr_rx->w_idx, wr_rx, m_qp->pi_rr_cnt,
		m_qp->pi_rw_cnt, m_qp->post_sig_cnt, m_qp->stall_cnt_rr,
		ib_wr.send_flags, l_len, ib_wr.wr.rdma.remote_addr,
		ib_wr.wr.rdma.rkey, ib_wr.sg_list->addr, ib_wr.sg_list->lkey,
		m_qp->wr_tl_r, m_qp->wr_tl_r_wt, m_qp->wr_hd_r);

	m_pi_send_wc(m_qp, wr_rx, IBV_WC_REM_ACCESS_ERR); /* report error */
}

void m_pi_rcv_event(struct mcm_qp *m_qp, wrc_idata_t *wrc)
{
	mlog(8," WRC id %d, type %x, flags %x\n", wrc->id, wrc->type, wrc->flags);
	if (wrc->type == M_WR_TYPE) {
		struct mcm_wr_rx *wr_rx;

		if (wrc->id > m_qp->wrc.wr_end) {
			mlog(0," RX imm_data: WR id out of range %x > %x \n",
				wrc->id, m_qp->wrc.wr_end);
			return;
		}
		wr_rx = (struct mcm_wr_rx *)(m_qp->wrc.wr_addr + (m_qp->wrc.wr_sz * wrc->id));
		mcm_ntoh_wr_rx(wr_rx); /* received in network order, convert */
		wr_rx->context = (uint64_t)(uintptr_t)m_qp;  /* local side QP context */

		mlog(8," WR_rx[%d] %p id %Lx wc_tl_rem %d flgs %x wr.wr_id %Lx imm 0x%x raddr %Lx,%x,%d\n",
			wrc->id, wr_rx, wr_rx->org_id, wr_rx->w_idx, wr_rx->flags,
			wr_rx->wr.wr_id, wr_rx->wr.imm_data,
			wr_rx->sg[0].addr, wr_rx->sg[0].lkey, wr_rx->sg[0].length);

		mpxy_lock(&m_qp->rxlock);
		m_qp->wc_tl_rem = wr_rx->w_idx; /* remote WC tail update in WR */
#ifdef MCM_PROFILE
		if (wrc->id == m_qp->wr_hd_r)
			mlog(0," ERR: RX imm_data: WR id %d duplicate!!!\n", wrc->id);
#endif
		m_qp->wr_hd_r = wrc->id; /* new WR took slot, move hd_r */
		wr_rx->w_idx = wrc->id;   /* my idx slot, to move tl */
		m_pi_post_read(m_qp, wr_rx);
		mpxy_unlock(&m_qp->rxlock);
		write(m_qp->smd->md->mc->tx_pipe[1], "w", sizeof "w");

	} else if (wrc->type == M_WC_TYPE) {
		struct mcm_wc_rx *m_wc;

		/* work completion of rdma_write sent to remote proxy-in */
		if (wrc->id > m_qp->wrc.wc_end) {
			mlog(0," RX imm_data: WC id out of range %x > %x \n",
				wrc->id, m_qp->wrc.wc_end);
			return;
		}
		m_wc = (struct mcm_wc_rx *)(m_qp->wrc.wc_addr + (m_qp->wrc.wc_sz * wrc->id));
		mcm_ntoh_wc_rx(m_wc);   /* convert received WC contents */

		/* work completion for proxy_out service */
		m_po_wc_event(m_qp, m_wc, wrc->id);

	} else {
		mlog(0," ERR: RX imm_data: type unknown %x\n", wrc->type);
	}
}


/* Proxy-in service - RX thread
 *
 *  <- Work request in (RW_imm - WR idata), remote initiated RW, local RR
 *  <- Work completion in (RW_imm - WC idata), local initiated RW, remote RR
 */
void m_rcv_event(struct mcm_cq *m_cq, int *events)
{
	struct ibv_wc wc[mcm_wc_max/2];
	struct ibv_cq *ib_cq;
	struct mcm_qp *m_qp;
	void *cq_ctx;
	int i, wc_cnt, ret, err=0, notify=0;

	ret = ibv_get_cq_event(m_cq->ib_ch, &ib_cq, (void *)&cq_ctx);
	if (ret == 0)
		ibv_ack_cq_events(m_cq->ib_cq, 1);

	wc_cnt = 0;
retry:
	if (wc_cnt >= mcm_wc_max) {
		*events += 1;  /* pending */
		return;
	}

	ret = ibv_poll_cq(m_cq->ib_cq, mcm_wc_max/2, wc);
	if (ret <= 0) {
		if (!ret && !notify) {
			ibv_req_notify_cq(m_cq->ib_cq, 0);
			notify = 1;
			goto retry;
		}
		return;
	} else
		notify = 0;

	wc_cnt += ret;

	for (i=0; i<ret; i++) {
		m_qp = (struct mcm_qp *)wc[i].wr_id;

		mlog(0x40," wr_id[%d of %d] m_qp %p\n", i+1, ret, m_qp);
		mlog(0x40," ib_wc: st %d, vn %x idata %x  op %x wr_id %Lx\n",
			wc[i].status, wc[i].vendor_err, ntohl(wc[i].imm_data),
			wc[i].opcode, wc[i].wr_id);

		if (wc[i].status != IBV_WC_SUCCESS) {
			if (wc[i].status != IBV_WC_WR_FLUSH_ERR)
				mlog(0," DTO ERR: st %d, vn %x idata %x qstate 0x%x\n",
					wc[i].status, wc[i].vendor_err,
					ntohl(wc[i].imm_data), m_qp->ib_qp2->state);
			continue;
		}
		if (m_qp->cm && (m_qp->cm->state == MCM_DISCONNECTED)) {
			mlog(1," WARN: RX data on DISC m_qp %p qp1 %p qp2 %p %s\n",
				m_qp, m_qp->ib_qp1, m_qp->ib_qp2,
				mcm_state_str(m_qp->cm->state));
			continue;
		}

		if (wc[i].opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
			struct ibv_recv_wr r_wr, *r_err;
			wrc_idata_t  wrc;
			struct ibv_qp *ib_qp;

			wrc.id = WRC_ID_DATA(ntohl(wc[i].imm_data));
			wrc.type = WRC_TYPE_DATA(ntohl(wc[i].imm_data));
			wrc.flags = WRC_FLAGS_DATA(ntohl(wc[i].imm_data));

			/* process WR or WC */
			m_pi_rcv_event(m_qp, &wrc);

			/* re-post message */
			r_wr.next = NULL;
			r_wr.sg_list = NULL;
			r_wr.num_sge = 0;
			r_wr.wr_id = (uint64_t)(uintptr_t) m_qp;

			/* MXS -> MSS or HST, PI service will be on QP1 */
			if (MXF_EP(&m_qp->smd->md->addr) &&
			   (MSS_EP(&m_qp->cm->msg.daddr1) || HST_EP(&m_qp->cm->msg.daddr1)))
			        ib_qp = m_qp->ib_qp1;
			else
				ib_qp = m_qp->ib_qp2;

			errno = 0;
			if (ib_qp) {
				err = ibv_post_recv(ib_qp, &r_wr, &r_err);
				if (err) {
					mlog(0,"ERR: qp %p (%s) qpn %x ibv_post_recv ret = %d %s\n",
						m_qp, (MXF_EP(&m_qp->smd->md->addr) &&
						MSS_EP(&m_qp->cm->msg.daddr1)) ? "QP1":"QP2",
						m_qp->ib_qp2 ?
						m_qp->ib_qp2->qp_num:m_qp->ib_qp1->qp_num,
						ret, strerror(errno));
				}
			}
			MCNTR(m_qp->smd->md, MCM_QP_RECV);

		} else {
			mlog(0,"ERR: unexpected WC opcode = %d on m_qp %p\n", wc[i].opcode, m_qp);
		}
	}
	goto retry;
}

/* Process scif_writeto DMAs waiting for previous WTs completions, order */
void m_pi_pending_wt(struct mcm_qp *m_qp)
{
	struct mcm_wr_rx *wr_rx;

	mpxy_lock(&m_qp->rxlock);
	wr_rx = (struct mcm_wr_rx *)(m_qp->wrc.wr_addr + (m_qp->wrc.wr_sz * m_qp->wr_hd_r));
	m_pi_post_writeto(m_qp, wr_rx);
	mpxy_unlock(&m_qp->rxlock);
}

/*
 * Pending Proxy-in services for RDMA Writes from remote peer
 *
 *  	RX side WR's waiting for proxy buffer to post RR for data segment
 *  	RX side WR's waiting for scif_sendto to complete
 *
 */
void m_pi_pending_wr(struct mcm_qp *m_qp, int *data)
{
	mcm_scif_dev_t *smd = m_qp->smd;
	struct mcm_wr_rx *wr_rx;
	int wr_idx, wr_max, wr_cnt;

	mpxy_lock(&m_qp->rxlock);
	if (m_qp->cm && m_qp->cm->state != MCM_CONNECTED && !m_qp->post_cnt_rr)
		goto done;

	wr_max = mcm_wr_max;
	wr_idx = m_qp->wr_tl_r_wt; /* last write_to marker */
	wr_cnt = 0;

	while (--wr_max && (m_qp->post_cnt_wt || m_qp->stall_cnt_rr)) {

		wr_rx = (struct mcm_wr_rx *)(m_qp->wrc.wr_addr + (m_qp->wrc.wr_sz * wr_idx));

		if (wr_rx->flags & M_READ_WRITE_TO_DONE) {
			if (wr_idx == m_qp->wr_hd_r)
				goto done;

			wr_idx = (wr_idx + 1) & m_qp->wrc.wr_end; /* next */
			continue;
		}
		wr_cnt++;

		if ((wr_rx->flags & M_READ_WRITE_TO) && (wr_rx->wr.wr_id == wr_rx->org_id)) {
			struct ibv_wc;
#if MCM_PROFILE
			mcm_qp_prof_ts(m_qp, MCM_QP_WT, wr_rx->time, wr_rx->qcnt, 1);
#endif
			wr_rx->flags |= M_READ_WRITE_TO_DONE;
			wr_rx->flags &= ~M_READ_WRITE_TO;
			MCNTR(smd->md, MCM_SCIF_WRITE_TO_DONE);

			mlog(0x10, " [%d,%d,%d] WR_rx[%d] wr %p scif_wt DONE! flgs  0x%x"
				   " tl %d w_tl %d hd %d org_id %Lx m_idx %x\n",
				   smd->md->mc->scif_id, smd->entry.tid, m_qp->r_entry.tid,
				   wr_rx->w_idx, wr_rx, wr_rx->flags,
				   m_qp->wr_tl_r, m_qp->wr_tl_r_wt, m_qp->wr_hd_r,
				   wr_rx->wr.wr_id, wr_rx->m_idx);

			m_qp->post_cnt_wt--;
			if (wr_rx->m_idx) {
				mpxy_lock(&smd->rblock);
				m_pi_buf_tl(smd, wr_rx->m_idx, wr_rx); /* release shared buffer slot */
				mpxy_unlock(&smd->rblock);
			}
			m_qp->wr_tl_r_wt = wr_rx->w_idx;  /* writeto pending tail */

			/* if SR operation, send local RX event */
			if ((wr_rx->wr.opcode == IBV_WR_SEND) ||
			    (wr_rx->wr.opcode == IBV_WR_RDMA_WRITE_WITH_IMM)) {
				struct dat_mix_wc wc;
				struct mcm_sr *m_sr;

				m_sr = (struct mcm_sr *)(m_qp->sr_buf + (m_qp->sr_sz * wr_rx->s_idx));

				wc.wr_id = m_sr->wr_id;
				wc.imm_data = wr_rx->wr.imm_data;
				wc.byte_len = m_sr->len;
				wc.status = IBV_WC_SUCCESS;
				wc.vendor_err = 0;
				wc.wc_flags = 0;
				wc.opcode = (wr_rx->wr.opcode == IBV_WR_SEND) ? IBV_WC_RECV:IBV_WC_RECV_RDMA_WITH_IMM;

				mlog(4, " SR[%d] rx_event: m_sr %p idx %d wr_idx %d"
					" wr_id %Lx imm %x ln %d wr.op %x wc.op %x\n",
					wr_rx->s_idx,m_sr, m_sr->s_idx, m_sr->w_idx,
					m_sr->wr_id, wr_rx->wr.imm_data, m_sr->len,
					wr_rx->wr.opcode, wc.opcode);

				mix_dto_event(m_qp->m_cq_rx, &wc, 1);
				m_pi_free_sr(m_qp, m_sr);

			}
			/* Last Segment and !DIRECT (no segments) or peer PO wants signaled */
			if ((wr_rx->flags & M_SEND_MP_SIG) ||
			    ((wr_rx->flags & M_SEND_LS) && !(wr_rx->flags & M_SEND_DIRECT))) {
				mlog(4, "WR_rx[%d] wr %p LastSeg: send WC! tl %d hd %d\n",
					wr_rx->w_idx, wr_rx, m_qp->wr_tl_r, m_qp->wr_hd_r);

				if (m_pi_send_wc(m_qp, wr_rx, IBV_WC_SUCCESS))
					goto done;
			}

		} else if (wr_rx->flags & M_READ_PAUSED) {

			mlog(0x4, " RR PAUSED: qp %p tl %d hd %d idx %d wr %p wr_id %p,"
				" addr %p sz %d sflg 0x%x mflg 0x%x\n",
				m_qp, m_qp->wr_tl_r, m_qp->wr_hd_r, wr_idx, wr_rx,
				wr_rx->org_id, wr_rx->sg[1].addr, wr_rx->sg[1].length,
				wr_rx->wr.send_flags, wr_rx->flags);
			mlog(0x4, " WR_rx[%d] RR stall (pnd %d stl %d cnt %d max %d)"
				" memory (%p-%p) hd 0x%x tl 0x%x %x\n",
				wr_rx->w_idx, m_qp->pi_rr_cnt, m_qp->stall_cnt_rr, wr_cnt, wr_max,
				smd->m_buf_r, smd->m_buf_r + smd->m_len_r,
				smd->m_hd_r, smd->m_tl_r, wr_rx->sg[0].length);

			/* check for buffer, post RR if available */
			m_pi_post_read(m_qp, wr_rx);

			/* no progress or RR posted needs completion processing */
			if ((wr_rx->flags & M_READ_PAUSED) || (m_qp->pi_rr_cnt >= 10)) {
				mlog(0x4, " PAUSED or pi_rr_cnt %d > 10, exit\n",  m_qp->pi_rr_cnt);
				goto done;
			}
		}

		/* still pending, maintain order */
		if (wr_rx->flags & M_READ_WRITE_TO)
			goto done;

		/* reached pending RR with max pending, don't release any paused RR's */
		if ((wr_rx->flags & M_READ_POSTED) && (m_qp->pi_rr_cnt >= 10))
			goto done;

		if (wr_idx == m_qp->wr_hd_r) /* reached head */
			goto done;

		wr_idx = (wr_idx + 1) & m_qp->wrc.wr_end; /* next */

		if (smd->destroy) {
			mlog(0, " SMD destroy - QP %p hd %d tl %d pst %d,%d cmp %d, pp %d, data %d\n",
				m_qp, m_qp->wr_hd, m_qp->wr_tl,m_qp->post_cnt,
				m_qp->post_sig_cnt, m_qp->comp_cnt, m_qp->wr_pp, data);
			mlog(0, " wr %p wr_id %p org_id %p sglist %p sge %d ln %d op %d flgs"
				" %x idata 0x%x raddr %p rkey %x m_flgs %x\n",
			     wr_rx, wr_rx->wr.wr_id, wr_rx->org_id, wr_rx->sg,
			     wr_rx->wr.num_sge, wr_rx->sg->length, wr_rx->wr.opcode,
			     wr_rx->wr.send_flags, wr_rx->wr.imm_data,
			     wr_rx->wr.wr.rdma.remote_addr, wr_rx->wr.wr.rdma.rkey, wr_rx->flags);
			goto done;
		}
	}
done:
	/* wt pending, stalled RR's, pending RR's, wr queued */
	*data += ((m_qp->post_cnt_wt || m_qp->stall_cnt_rr || m_qp->pi_rr_cnt || m_qp->wr_tl_r != m_qp->wr_hd_r) ? 1:0);
	mpxy_unlock(&m_qp->rxlock);
	if (smd->destroy) {
		mlog(0, "  SMD destroy - QP %p hd %d tl %d, pending data %d\n",
			m_qp, m_qp->wr_hd_r, m_qp->wr_tl_r, data);
	}
}



