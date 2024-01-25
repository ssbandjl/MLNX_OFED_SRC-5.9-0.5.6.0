/*
 * Copyright (c) 2009-2015 Intel Corporation.  All rights reserved.
 *
 * This Software is licensed under one of the following licenses:
 *
 * 1) under the terms of the "Common Public License 1.0" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/cpl.php.
 *
 * 2) under the terms of the "The BSD License" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/bsd-license.php.
 *
 * 3) under the terms of the "GNU General Public License (GPL) Version 2" a
 *    copy of which is available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/gpl-license.php.
 *
 * Licensee has the right to choose one of the above licenses.
 *
 * Redistributions of source code must retain the above copyright
 * notice and one of the license notices.
 *
 * Redistributions in binary form must reproduce both the above copyright
 * notice, one of the license notices in the documentation
 * and/or other materials provided with the distribution.
 */
#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_ib_util.h"
#include "dapl_evd_util.h"
#include "dapl_ep_util.h"
#include "dapl_osd.h"

/*
 * HST -> MXS - proxy-out (PO) to proxy-in (PI)
 *
 * non-MIC host to MIC cross socket EP needs to send WR to remote PI service
 * instead of direct IB send or write. Inbound traffic from remote MXS will still be
 * be direct so there is no need for PI service on this MCM providers host side.
 */
#define MCM_MP_SIG_RATE 5
#define MCM_MP_RETRY 	100000

int mcm_send_pi(struct dcm_ib_qp *m_qp,
		int len,
		struct ibv_send_wr *wr,
		struct ibv_send_wr **bad_wr)
{
	struct ibv_send_wr wr_imm;
	struct ibv_sge sge;
	struct mcm_wr_rx m_wr_rx;
	int i, l_len, seg_len, retry_cnt, ret = 0, wr_idx=0;
	struct wrc_idata wrc;
	uint32_t wr_flags, l_off, r_off = 0;
	uint64_t l_addr;
	struct mcm_wr_rx *wr_rx_ptr;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " mcm_send_pi: ep %p qpn %x ln %d sge %d sg %d"
		     " WR: tl %d hd %d end %d wr_id %Lx\n",
		     m_qp->ep, m_qp->qp2->qp_num, len,  wr->num_sge,
		     m_qp->seg_sz, m_qp->wr_tl, m_qp->wr_hd,
		     m_qp->wrc_rem.wr_end, wr->wr_id);

	if (wr->num_sge > DAT_MIX_SGE_MAX) {
		ret = EINVAL;
		goto bail;
	}

	/* one WR per IB sge, no additional segmentation */
	for (i=0;i<wr->num_sge;i++) {
		l_len = wr->sg_list[i].length;
		l_addr = wr->sg_list[i].addr;
		l_off = 0;

		while (l_len) {
			wr_flags = M_SEND_DIRECT | M_SEND_PI;
			if ((i==0) && (l_len == wr->sg_list[i].length))
				wr_flags |= M_SEND_FS;

			if (wr->opcode == IBV_WR_SEND)
				seg_len = l_len;
			else
				seg_len = (l_len > m_qp->seg_sz) ? m_qp->seg_sz : l_len;

			dapl_os_lock(&m_qp->lock);
			if (((m_qp->wr_hd + 1) & m_qp->wrc_rem.wr_end) == m_qp->wr_tl) { /* full */
				dapl_os_unlock(&m_qp->lock);
				retry_cnt = MCM_MP_RETRY;
retry_wr:
				sched_yield();
				dapl_os_lock(&m_qp->tp->cqlock);
				mcm_dto_event(m_qp->rcv_cq); /* process CQ, free WR slots */
				dapl_os_unlock(&m_qp->tp->cqlock);

				dapl_os_lock(&m_qp->lock); /* retry */
				if (((m_qp->wr_hd + 1) & m_qp->wrc_rem.wr_end) == m_qp->wr_tl) {
					dapl_os_unlock(&m_qp->lock);
					if (--retry_cnt)
						goto retry_wr;
					ret = ENOMEM;
					goto bail;
				}
			}
			m_qp->wr_hd = (m_qp->wr_hd + 1) & m_qp->wrc_rem.wr_end; /* move hd */
			wr_idx = m_qp->wr_hd;
			dapl_os_unlock(&m_qp->lock);

			/* last WR segment and last proxy data segment */
			if ((i==(wr->num_sge-1)) && (seg_len >= l_len)) {
				wr_flags |= M_SEND_LS;
				if (wr->send_flags & IBV_SEND_SIGNALED)
					wr_flags |= M_SEND_CN_SIG;
			}
			if (!(wr_idx % MCM_MP_SIG_RATE) || (wr_flags & M_SEND_CN_SIG))
				wr_flags |= M_SEND_MP_SIG;

			if (!m_qp->wr_buf_rx) {
				wr_rx_ptr = &m_wr_rx;
				sge.lkey = 0; /* inline doesn't need registered */
			} else {
				wr_rx_ptr = (struct mcm_wr_rx *)
					    (m_qp->wr_buf_rx + (sizeof(struct mcm_wr_rx) * wr_idx));
				sge.lkey = m_qp->wr_buf_rx_mr->lkey;
			}
			sge.addr = (uint64_t)(uintptr_t) wr_rx_ptr;
			sge.length = (uint32_t)m_qp->wrc_rem.wr_sz;

			if (m_qp->p2p_data && seg_len < m_qp->p2p_data) {
				dapl_log(DAPL_DBG_TYPE_EP,
					 " Sending p2p data, len %d\n", seg_len);
				wr_flags |= M_PROXY_INLINE;
				memcpy(wr_rx_ptr->inline_data, (void *)(l_addr + l_off), seg_len);
			}

			dapl_dbg_log(DAPL_DBG_TYPE_EP,
				     " mcm_send_pi[%d]: seg_ln %d wr_idx %d, tl %d hd %d\n",
				     i, seg_len, wr_idx, m_qp->wr_tl, m_qp->wr_hd);

			/* build local m_wr_rx for remote PI */
			memset((void*)wr_rx_ptr, 0, MCM_WR_RX_NO_DATA);
			wr_rx_ptr->org_id = (uint64_t) htonll((uint64_t)wr->wr_id);
			wr_rx_ptr->flags = htonl(wr_flags);
			wr_rx_ptr->w_idx = htonl(m_qp->wc_tl); /* snd back wc tail */
			wr_rx_ptr->wr.num_sge = htonl(wr->num_sge);
			wr_rx_ptr->wr.opcode = htonl(wr->opcode);

			/* RW_IMM: reset opcode on all segments except last */
			if (!(wr_flags & M_SEND_LS) &&
			     (wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM))
				wr_rx_ptr->wr.opcode = htonl(IBV_WR_RDMA_WRITE);

			wr_rx_ptr->wr.send_flags = htonl(wr->send_flags);
			wr_rx_ptr->wr.imm_data = htonl(wr->imm_data);
			wr_rx_ptr->sg[0].addr = htonll(l_addr + l_off);
			wr_rx_ptr->sg[0].lkey = htonl(wr->sg_list[i].lkey);
			wr_rx_ptr->sg[0].length = htonl(seg_len);

			if ((wr->opcode == IBV_WR_RDMA_WRITE) ||
			    (wr->opcode == IBV_WR_RDMA_WRITE_WITH_IMM)) {
				wr_rx_ptr->wr.wr.rdma.remote_addr = htonll(wr->wr.rdma.remote_addr + r_off);
				wr_rx_ptr->wr.wr.rdma.rkey = htonl(wr->wr.rdma.rkey);
			}

			/* setup imm_data for PI rcv engine */
			wrc.id = (uint16_t)wr_idx;
			wrc.type = M_WR_TYPE;
			wrc.flags = 0;

			/* setup local WR for wr_rx transfer - RW_imm inline */
			memset(&wr_imm, 0, sizeof(struct ibv_send_wr));
			wr_imm.wr_id = wr->wr_id; /* MUST be original cookie, CQ processing */
			wr_imm.sg_list = &sge;
			wr_imm.num_sge = 1;
			wr_imm.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
			if (wr_flags & M_SEND_MP_SIG)
				wr_imm.send_flags |= IBV_SEND_SIGNALED;
			if (!m_qp->wr_buf_rx)
				wr_imm.send_flags |= IBV_SEND_INLINE;
			wr_imm.imm_data = htonl(*(uint32_t *)&wrc);
			wr_imm.wr.rdma.rkey = m_qp->wrc_rem.wr_rkey;
			wr_imm.wr.rdma.remote_addr =
				(uint64_t)(uintptr_t)
				((struct mcm_wr_rx *) (m_qp->wrc_rem.wr_addr + (m_qp->wrc_rem.wr_sz * wr_idx)));

			dapl_dbg_log(DAPL_DBG_TYPE_EP,
				     " mcm_send_pi[%d]: WR_RX wr_id %Lx qn %x op %d flgs 0x%x"
				     " imm %x laddr %p raddr %p rkey %x wr_ln %d ln %d\n",
				     i, wr_imm.wr_id, m_qp->qp2->qp_num, wr_imm.opcode,
				     wr_flags, ntohl(wr_imm.imm_data),
				     l_addr + l_off, wr_imm.wr.rdma.remote_addr,
				     wr_imm.wr.rdma.rkey, sge.length, l_len);
			dapl_dbg_log(DAPL_DBG_TYPE_EP,
				     " mcm_send_pi[%d]: WR wr_id %Lx qn %x op %d flgs %x"
				     " imm %x raddr %p rkey %x sg_ln %d tl %d me %d hd %d\n",
				     i, wr->wr_id, m_qp->qp2->qp_num, wr->opcode,
				     wr->send_flags, wr->imm_data,
				     wr->wr.rdma.remote_addr + r_off,
				     wr->wr.rdma.rkey, seg_len, m_qp->wr_tl, wr_idx, m_qp->wr_hd);

			ret = ibv_post_send(m_qp->qp2, &wr_imm, bad_wr);  /* QP2: QPtx - QPrx PI */
			if (ret) {
				dapl_log(DAPL_DBG_TYPE_ERR,
					" mcm_send_pi ERR: m_wr %p idx %d laddr=%p ln=%d lkey=%x flgs %x"
					" tl %d hd %d\n",
					wr_rx_ptr, wr_idx, wr->sg_list[0].addr,
					wr->sg_list[0].length, wr->sg_list[0].lkey,
					wr_rx_ptr->flags, m_qp->wr_tl, m_qp->wr_hd);
				dapl_log(DAPL_DBG_TYPE_ERR,
					" mcm_send_pi ERR: wr_id %Lx %p sglist %p sge %d op %d flgs %x"
					" idata 0x%x raddr %p rkey %x \n",
					wr_rx_ptr->wr.wr_id, wr->sg_list,
					wr_rx_ptr->wr.num_sge, wr_rx_ptr->wr.opcode,
					wr_rx_ptr->wr.send_flags, wr_rx_ptr->wr.imm_data,
					wr_rx_ptr->wr.wr.rdma.remote_addr,
					wr_rx_ptr->wr.wr.rdma.rkey);
				goto bail;
			}
			l_len -= seg_len;
			l_off += seg_len;
			r_off += seg_len;

		} /* wire segmentation of each IOV segment */
	}
bail:
	return ret;
}

/* TX - RW_imm work request data to remote PI or consumer TX data direct to peer */
static inline void mcm_dto_req(struct dcm_ib_cq *m_cq, struct ibv_wc *wc)
{
	DAPL_COOKIE *cookie;
	struct dcm_ib_qp *m_qp;

	cookie = (DAPL_COOKIE *)(uintptr_t)wc->wr_id;
	m_qp = cookie->ep->qp_handle;

	if (!m_qp->tp->scif_ep && MXF_EP(m_qp) &&
	    (wc->opcode == (uint32_t)IBV_WR_RDMA_WRITE_WITH_IMM)) {
		dapl_log(DAPL_DBG_TYPE_EP,
			 " mcm_dto_req: RW_imm -> WR, wr_id %Lx\n", wc->wr_id);
		return;  /* post_send -> RW_imm to peer PI */
	}

	dapl_log(DAPL_DBG_TYPE_EP,
		 " mcm_dto_req: SIG evd %p ep %p WR tl %d hd %d WC tl %d wr_id %p\n",
		 m_qp->req_cq ? m_qp->req_cq->evd:0, m_qp->ep, m_qp->wr_tl, m_qp->wr_hd,
		 m_qp->wc_tl, cookie);

	dapl_os_lock(&m_qp->req_cq->evd->header.lock);
	dapls_evd_cqe_to_event(m_qp->req_cq->evd, wc);
	dapl_os_unlock(&m_qp->req_cq->evd->header.lock);
}

/* RX work completion of RW data to remote PI, remote RR completion */
static inline void mcm_dto_rcv(struct dcm_ib_cq *m_cq, struct ibv_wc *wc)
{
	struct mcm_wc_rx *m_wc;
	struct dcm_ib_qp *m_qp = (struct dcm_ib_qp *)wc->wr_id;
	struct wrc_idata wrc;

	wrc.id = WRC_ID_DATA(ntohl(wc->imm_data));
	wrc.type = WRC_TYPE_DATA(ntohl(wc->imm_data));
	wrc.flags = WRC_FLAGS_DATA(ntohl(wc->imm_data));

	if (wrc.type != M_WC_TYPE) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 "mcm_dto_rcv: ERR imm WC type ?= 0x%x\n", wrc.type);
		goto bail;
	}

	if (wrc.id > m_qp->wrc.wc_end) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			" mcm_dto_rcv: ERR WC id out of range %x > %x \n",
			wrc.id, m_qp->wrc.wc_end);
		goto bail;
	}
	m_wc = (struct mcm_wc_rx *)(m_qp->wrc.wc_addr + (m_qp->wrc.wc_sz * wrc.id));
	mcm_ntoh_wc_rx(m_wc);   /* convert WC contents, pushed via wire */

	dapl_log(DAPL_DBG_TYPE_EP,
		 " mcm_dto_rcv WC: ep %p wc_id %d wc %p wr_id %Lx wr_tl %d flgs 0x%x %s\n",
		 m_qp->ep, wrc.id, m_wc, m_wc->wc.wr_id, m_wc->wr_tl,
		 m_wc->flags, m_wc->flags & M_SEND_CN_SIG ? "SIG":"NO_SIG");

	dapl_os_lock(&m_qp->lock);
	m_qp->wr_tl = m_wc->wr_tl;
	m_qp->wc_tl = wrc.id; /* move wc_tl, for wc_tl_rem on peer PI service */
	dapl_os_unlock(&m_qp->lock);
	if (m_wc->flags & M_SEND_CN_SIG) {
		struct ibv_wc ib_wc;
		DAPL_COOKIE *cookie = (DAPL_COOKIE *)(uintptr_t) m_wc->wc.wr_id;

		dapl_log(DAPL_DBG_TYPE_EP,
			 " mcm_dto_rcv: MCM SIG evd %p ep %p WR tl %d hd %d WC tl %d wr_id %p\n",
			 m_qp->req_cq ? m_qp->req_cq->evd:0, m_qp->ep, m_qp->wr_tl, m_qp->wr_hd,
			 m_qp->wc_tl, cookie);

		mcm_const_ib_wc(&ib_wc, &m_wc->wc, 1);
		dapl_os_lock(&m_qp->req_cq->evd->header.lock);
		dapls_evd_cqe_to_event(m_qp->req_cq->evd, &ib_wc);
		dapl_os_unlock(&m_qp->req_cq->evd->header.lock);
	}
bail:
	if (mcm_post_rcv_wc(m_qp, 1))
		dapl_log(DAPL_DBG_TYPE_ERR,"mcm_dto_rcv: recv wc repost failed\n");
}

int mcm_post_rcv_wc(struct dcm_ib_qp *m_qp, int cnt)
{
	struct ibv_recv_wr r_wr, *r_err;
	int err, i;

	r_wr.next = NULL; /* re-post message */
	r_wr.sg_list = NULL;
	r_wr.num_sge = 0;
	r_wr.wr_id = (uint64_t)(uintptr_t) m_qp;
	errno = 0;

	for (i=0;i<cnt;i++) {
		err = ibv_post_recv(m_qp->qp2, &r_wr, &r_err);
		if (err) {
			dapl_log(DAPL_DBG_TYPE_ERR,"ERR: qp %p (QP2) qpn %x "
				 "ibv_post_recv ret = %d %s\n",
				 m_qp, m_qp->qp2 ? m_qp->qp2->qp_num:0,
				 err, strerror(errno));
			return errno;
		}
	}
	dapl_log(DAPL_DBG_TYPE_EP, "mcm_post_rcv_wc: qp %p qpn 0x%x posted %d\n",
		 m_qp, m_qp->qp2->qp_num, cnt);
	return 0;
}

/* Proxy-in service - called from CM-RX thread
 *
 *  This processes both TX and RX events
 *  	rcv_cq is PI only service
 *  	req_cq is PO-PI RW_imm or HST->Direct RW if CQ shared across QP's
 *
 *  <- Work completion in (RW_imm - WC idata), local initiated RW
 *  -> RW_imm work requests out PO-PI
 *  -> RW direct from consumer post HST->Direct (remote is HST or MSS)
 *
 */
void mcm_dto_event(struct dcm_ib_cq *m_cq)
{
	struct ibv_wc wc[5];
	struct ibv_cq *ib_cq;
	void *cq_ctx = NULL;
	int i, wc_cnt, ret, err, notify;

	dapl_log(DAPL_DBG_TYPE_THREAD," PI event: enter\n");

	ret = ibv_get_cq_event(m_cq->cq->channel, &ib_cq, (void *)&cq_ctx);
	if (ret == 0)
		ibv_ack_cq_events(ib_cq, 1);

	wc_cnt = err = notify = 0;
retry:
	ret = ibv_poll_cq(m_cq->cq, 5, wc);
	if (ret <= 0) {
		if (!ret && !notify) {
			ibv_req_notify_cq(m_cq->cq, 0);
			notify = 1;
			goto retry;
		}
		dapl_log(DAPL_DBG_TYPE_THREAD," PI event: empty, return\n");
		return;
	} else
		notify = 0;

	wc_cnt += ret;
	for (i=0; i<ret; i++) {
#if 1
		dapl_log(DAPL_DBG_TYPE_EP,
			 " mcm_dto_event: ib_wc[%d-%d]: st %d, vn %x imm %x op %x wr_id %Lx ctx %p\n",
			 i+1, ret, wc[i].status, wc[i].vendor_err, ntohl(wc[i].imm_data),
			 wc[i].opcode, wc[i].wr_id, cq_ctx);
#endif
		if (wc[i].status != IBV_WC_SUCCESS) {
			if (wc[i].status != IBV_WC_WR_FLUSH_ERR)
				dapl_log(DAPL_DBG_TYPE_ERR,
					 " mcm_dto_event: ERR DTO st %d, vn %x"
					 " imm %x m_cq cq_ctx %p \n",
					 wc[i].status, wc[i].vendor_err,
					 ntohl(wc[i].imm_data), m_cq, cq_ctx);
			continue;
		}

		/* only one expected receive event, otherwise request */
		if (wc->opcode == IBV_WC_RECV_RDMA_WITH_IMM)
			mcm_dto_rcv(m_cq, &wc[i]);
		else
			mcm_dto_req(m_cq, &wc[i]);
	}
	goto retry;
}

void mcm_destroy_wc_q(struct dcm_ib_qp *m_qp)
{
	dapl_log(DAPL_DBG_TYPE_EP,
		 "mcm_destroy_wc_q: QP %p PI WC_q %p\n",
		 m_qp, m_qp->wrc.wc_addr);

	if (m_qp->wc_mr) {
		ibv_dereg_mr(m_qp->wc_mr);
		m_qp->wc_mr = NULL;
	}
	if (m_qp->wrc.wc_addr) {
		free((void*)m_qp->wrc.wc_addr);
		m_qp->wrc.wc_addr = 0;
	}
	if (m_qp->wr_buf_rx_mr) {
		ibv_dereg_mr(m_qp->wr_buf_rx_mr);
		m_qp->wr_buf_rx_mr = NULL;
	}
	if(m_qp->wr_buf_rx) {
		free(m_qp->wr_buf_rx);
		m_qp->wr_buf_rx = NULL;
	}
}

int mcm_create_wc_q(struct dcm_ib_qp *m_qp, int entries)
{
	struct ibv_pd *ib_pd = ((DAPL_PZ *)m_qp->ep->param.pz_handle)->pd_handle;

	dapl_log(DAPL_DBG_TYPE_EP,
		 "mcm_create_wc_q: QP %p entries %d\n", m_qp, entries);

	/* RDMA proxy WC pool, register with SCIF and IB, set pool and segm size with parameters */
	m_qp->wrc.wc_sz = ALIGN_64(sizeof(struct mcm_wc_rx));
	m_qp->wrc.wc_len = m_qp->wrc.wc_sz * entries; /* 64 byte aligned for signal_fence */
	m_qp->wrc.wc_end = entries - 1;

	if (posix_memalign((void **)&m_qp->wrc.wc_addr, 4096, ALIGN_PAGE(m_qp->wrc.wc_len))) {
		dapl_log(DAPL_DBG_TYPE_EP, "failed to allocate wc_rbuf,"
			 " m_qp=%p, wc_len=%d, entries=%d\n",
			 m_qp, m_qp->wrc.wc_len, entries);
		return -1;
	}
	memset((void*)m_qp->wrc.wc_addr, 0, ALIGN_PAGE(m_qp->wrc.wc_len));

	dapl_log(DAPL_DBG_TYPE_EP, " WC rbuf pool %p, LEN req=%d, act=%d\n",
		m_qp->wrc.wc_addr, m_qp->wrc.wc_len, ALIGN_PAGE(m_qp->wrc.wc_len));

	m_qp->wc_mr = ibv_reg_mr(ib_pd, (void*)m_qp->wrc.wc_addr, m_qp->wrc.wc_len,
				 IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
	if (!m_qp->wc_mr) {
		dapl_log(DAPL_DBG_TYPE_ERR, " IB_register addr=%p,%d failed %s\n",
		        m_qp->wrc.wc_addr, ALIGN_PAGE(m_qp->wrc.wc_len), strerror(errno));
		return -1;
	}
	m_qp->wrc.wc_addr = (uint64_t)(uintptr_t)m_qp->wc_mr->addr;
	m_qp->wrc.wc_rkey = m_qp->wc_mr->rkey;

	dapl_log(DAPL_DBG_TYPE_EP, " IB_mr for wc_buf addr %p, mr 0x%llx, len %d, entries %d rkey %x lkey %x\n",
		m_qp->wrc.wc_addr, m_qp->wc_mr->addr, ALIGN_PAGE(m_qp->wrc.wc_len),
		entries, m_qp->wc_mr->rkey, m_qp->wc_mr->lkey);

	if (!m_qp->tp->ib_cm.max_inline) {

		if (posix_memalign((void **)&m_qp->wr_buf_rx,
				   4096, entries * sizeof(mcm_wr_rx_t))) {
			dapl_log(DAPL_DBG_TYPE_ERR,
				 "failed to allocate proxy wr_buf_rx, "
				 "m_qp=%p, wr_rx_len=%d, entries=%d\n",
				 m_qp, entries * sizeof(mcm_wr_rx_t), entries);
			goto err;
		}
		memset(m_qp->wr_buf_rx, 0, entries * sizeof(mcm_wr_rx_t));

		m_qp->wr_buf_rx_mr = ibv_reg_mr(m_qp->qp->pd, (void*)m_qp->wr_buf_rx,
						entries * sizeof(mcm_wr_rx_t),
						IBV_ACCESS_LOCAL_WRITE |
						IBV_ACCESS_REMOTE_WRITE);

		if (!m_qp->wr_buf_rx_mr) {
			dapl_log(DAPL_DBG_TYPE_ERR, " IB_register addr=%p,%d failed %s\n",
					m_qp->wr_buf_rx_mr->addr,
					entries * sizeof(mcm_wr_rx_t),
					strerror(errno));
			goto err;
		}
		dapl_log(DAPL_DBG_TYPE_EP,
			 " no inline support: WR_buf_rx pool %p, LEN %d, mr %x\n",
			 m_qp->wr_buf_rx, entries * sizeof(mcm_wr_rx_t),
			 m_qp->wr_buf_rx_mr);
	}

	/* Put QP's req and rcv CQ on device PI cqlist, mark CQ for indirect signaling */
	dapl_os_lock(&m_qp->tp->cqlock);
	m_qp->req_cq->flags |= DCM_CQ_TX_INDIRECT;
	if (!m_qp->req_cq->entry.list_head)
		dapl_llist_add_tail(&m_qp->tp->cqlist, &m_qp->req_cq->entry, m_qp->req_cq);
	if (!m_qp->rcv_cq->entry.list_head)
		dapl_llist_add_tail(&m_qp->tp->cqlist, &m_qp->rcv_cq->entry, m_qp->rcv_cq);
	dapl_os_unlock(&m_qp->tp->cqlock);
	dapls_thread_signal(&m_qp->tp->signal); /* CM thread will process PI */

	return 0;

err:
        if (m_qp->wr_buf_rx)
                free(m_qp->wr_buf_rx);

        if (m_qp->wc_mr)
                ibv_dereg_mr(m_qp->wc_mr);

        free((void*)m_qp->wrc.wc_addr);

        return -1;
}

void mcm_destroy_pi_cq(struct dcm_ib_qp *m_qp)
{
	if (!m_qp->rcv_cq)
		return;

	dapl_log(DAPL_DBG_TYPE_EP, "mcm_destroy_pi_cq: QP %p CQ %p\n",
		 m_qp, m_qp->rcv_cq);

	/* remove from device PI processing list  */
	dapl_os_lock(&m_qp->tp->cqlock);
	if (m_qp->rcv_cq->entry.list_head)
		dapl_llist_remove_entry(&m_qp->tp->cqlist,
					&m_qp->rcv_cq->entry);
	dapl_os_unlock(&m_qp->tp->cqlock);

	if (m_qp->rcv_cq->cq) {
		struct ibv_comp_channel *channel = m_qp->rcv_cq->cq->channel;

		ibv_destroy_cq(m_qp->rcv_cq->cq);
		m_qp->rcv_cq->cq = NULL;
		if (channel)
			ibv_destroy_comp_channel(channel);
	}
	dapl_os_free(m_qp->rcv_cq, sizeof(struct dcm_ib_cq));
	m_qp->rcv_cq = NULL;
}

int mcm_create_pi_cq(struct dcm_ib_qp *m_qp, int len)
{
	struct ibv_comp_channel *channel = NULL;
	int cqlen = len;
	int opts, ret = ENOMEM;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     "mcm_create_pi_cq: qp = %p cqlen=%d \n", m_qp, cqlen);

	/* create CQ object */
	m_qp->rcv_cq = dapl_os_alloc(sizeof(struct dcm_ib_cq));
	if (!m_qp->rcv_cq)
		goto err;

	dapl_os_memzero(m_qp->rcv_cq, sizeof(struct dcm_ib_cq));
	m_qp->rcv_cq->tp = m_qp->tp;
	dapl_llist_init_entry(&m_qp->rcv_cq->entry);

	errno = 0;
	channel = ibv_create_comp_channel(m_qp->tp->hca->ib_hca_handle);
	if (!channel)
		goto err;

	/* move channel FD to non-blocking */
	opts = fcntl(channel->fd, F_GETFL);
	if (opts < 0 || fcntl(channel->fd, F_SETFL, opts | O_NONBLOCK) < 0) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " dapls_config_fd: fcntl on channel->fd %d ERR %d %s\n",
			 channel->fd, opts, strerror(errno));
		goto err;
	}
	m_qp->rcv_cq->cq = ibv_create_cq(m_qp->tp->hca->ib_hca_handle,
			      	         cqlen, m_qp, channel, 0);
	if (!m_qp->rcv_cq->cq)
		goto err;

	/* arm cq for events */
	ibv_req_notify_cq(m_qp->rcv_cq->cq, 0);

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     "mcm_create_pi_cq: new_cq %p cqlen=%d \n",
		     m_qp->rcv_cq, cqlen);

	dapl_log(DAPL_DBG_TYPE_EVD,
		 "mcm_create_pi_cq (%d): new_cq %p ib_cq %p cqlen %d,%d\n",
		 m_qp->rcv_cq, m_qp->rcv_cq->cq, len, cqlen);

	return 0;

err:
	dapl_log(DAPL_DBG_TYPE_ERR,
		 "mcm_create_pi_cq: ERR new_cq %p cqlen %d,%d ret %s\n",
		 m_qp->rcv_cq, len, cqlen, strerror(errno));

	if (m_qp->rcv_cq) {
		dapl_os_free(m_qp->rcv_cq, sizeof(struct dcm_ib_cq));
		m_qp->rcv_cq = NULL;
	}
	if (channel)
		ibv_destroy_comp_channel(channel);

	return dapl_convert_errno(ret, "create_pi_cq" );
}




