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
 * mpxyd service - mpxy_out.c
 *
 * 	Proxy-out resources/services
 *
 */
#include "mpxyd.h"

extern int log_level;
extern int mcm_wc_max;
extern int mcm_rw_signal;
extern int mcm_wr_max;
extern int mcm_ib_inline;
extern int mix_eager_completion;
extern int mix_inline_threshold;
extern uint64_t system_guid;

#ifdef MCM_PROFILE
extern void mcm_check_io();
#endif

/* buffer pool for proxy outbount RDMA work request entries, SCIF registration, scif_ep */
void m_po_destroy_bpool(struct mcm_qp *m_qp)
{
	if (m_qp->wr_off)
		scif_unregister(m_qp->smd->scif_tx_ep, m_qp->wr_off, ALIGN_PAGE(m_qp->wr_len));

	if (m_qp->wr_buf) {
		free(m_qp->wr_buf);
		m_qp->wr_buf = 0;
	}

	if (m_qp->wr_buf_rx_mr) {
		ibv_dereg_mr(m_qp->wr_buf_rx_mr);
		m_qp->wr_buf_rx_mr = NULL;
	}

	if (m_qp->wr_buf_rx) {
		free(m_qp->wr_buf_rx);
		m_qp->wr_buf_rx = 0;
	}
}

int m_po_create_bpool(struct mcm_qp *m_qp, int entries)
{
	/* RDMA proxy pool, register with SCIF and IB, set pool and segm size with parameters */
	m_qp->wr_end = entries - 1;
	m_qp->wr_sz = ALIGN_64(sizeof(struct mcm_wr));
	m_qp->wr_len = m_qp->wr_sz * entries; /* 64 byte aligned for signal_fence */
	m_qp->wr_tl =  0;
	m_qp->wr_tl_rf = 1; /* start at tl+1 */
	if (posix_memalign((void **)&m_qp->wr_buf, 4096, ALIGN_PAGE(m_qp->wr_len))) {
		mlog(0, "failed to allocate wr_buf, m_qp=%p, wr_len=%d, entries=%d\n",
			 m_qp, m_qp->wr_len, entries);
		goto err;
	}
	memset(m_qp->wr_buf, 0, ALIGN_PAGE(m_qp->wr_len));

	m_qp->wr_off = scif_register(m_qp->smd->scif_tx_ep, m_qp->wr_buf, ALIGN_PAGE(m_qp->wr_len),
				    (off_t)0, SCIF_PROT_READ | SCIF_PROT_WRITE, 0);
	if (m_qp->wr_off == (off_t)(-1)) {
		mlog(0, " SCIF_register addr=%p,%d failed %s\n",
		     m_qp->wr_buf, ALIGN_PAGE(m_qp->wr_len), strerror(errno));
		goto err;
	}

	mlog(4, " WR buf pool %p, LEN req=%d, act=%d\n",
		m_qp->wr_buf, m_qp->wr_len, ALIGN_PAGE(m_qp->wr_len));
	mlog(4, " SCIF_mr for wr_buf addr %p, off 0x%llx, len %d, entries %d\n",
		m_qp->wr_buf, m_qp->wr_off, ALIGN_PAGE(m_qp->wr_len), entries);

	if (!m_qp->smd->md->indata) {
		if (posix_memalign((void **)&m_qp->wr_buf_rx, 4096, entries * sizeof(mcm_wr_rx_t))) {
			mlog(0, "failed to allocate wr_buf_rx, m_qp=%p, wr_rx_len=%d, entries=%d\n",
				 m_qp, entries * sizeof(mcm_wr_rx_t), entries);
			goto err;
		}
		memset(m_qp->wr_buf_rx, 0, entries * sizeof(mcm_wr_rx_t));

		m_qp->wr_buf_rx_mr = ibv_reg_mr(m_qp->smd->md->pd, (void*)m_qp->wr_buf_rx,
						entries * sizeof(mcm_wr_rx_t),
					        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
		if (!m_qp->wr_buf_rx_mr) {
			mlog(0, " IB_register addr=%p,%d failed %s\n",
				m_qp->wr_buf_rx_mr->addr,
				entries * sizeof(mcm_wr_rx_t),
				strerror(errno));
			goto err;
		}
		mlog(4, " no inline support: WR_buf_rx pool %p, LEN %d\n",
			m_qp->wr_buf, entries * sizeof(mcm_wr_rx_t));
		mlog(4, " no inline support: WR_buf_rx_mr = %x\n", m_qp->wr_buf_rx_mr);
	}

	return 0;
err:
	m_po_destroy_bpool(m_qp);
	return -1;
}

/* called with smd->tblock */
int m_po_buf_hd(mcm_scif_dev_t *smd, int m_idx, struct mcm_wr *wr)
{
	mlog(0x10," [%d:%d] m_hd 0x%Lx - m_wc %p: tl %d wc_hd[%d].m_idx=0x%x insert\n",
		smd->md->mc->scif_id, smd->entry.tid,
		smd->m_hd, smd->m_buf_wc, smd->m_buf_tl,
		(smd->m_buf_hd + 1) & smd->m_buf_end, m_idx);

	if (((smd->m_buf_hd + 1) & smd->m_buf_end) == smd->m_buf_tl) {
		mlog(0, " ERR: PO Buf WC full (%d) m_buf_wc %p:"
			"tl %d hd %d buf_wc_hd[%d].m_idx=0x%x\n",
			smd->m_buf_end, smd->m_buf_wc, smd->m_buf_tl,
			smd->m_buf_hd, smd->m_buf_hd, m_idx);
		return 1;
	}
	smd->m_buf_hd = (smd->m_buf_hd + 1) & smd->m_buf_end; /* move hd */
	smd->m_buf_wc[smd->m_buf_hd].m_idx = m_idx;
	smd->m_buf_wc[smd->m_buf_hd].done = 0;
#ifdef MCM_PROFILE
	smd->m_buf_wc[smd->m_buf_hd].hd = smd->m_hd;
	smd->m_buf_wc[smd->m_buf_hd].tl = smd->m_tl;
	smd->m_buf_wc[smd->m_buf_hd].ref++;
	smd->m_buf_wc[smd->m_buf_hd].ts = mcm_ts_us();
	smd->m_buf_wc[smd->m_buf_hd].wr = (void *) wr;
	if ((smd->m_hd_ro != smd->m_tl_ro) && (smd->m_hd >= smd->m_tl)) {
		struct mcm_qp *m_qp = (struct mcm_qp*)wr->context;
		mlog(0, " WARNING: [%d:%d:%d] PO_buf HD(%d) passed TL(%d): w_tl %d w_hd %d:"
			" wc_r[%d].m_idx=%x, m_tl %x m_hd %x\n",
			smd->md->mc->scif_id, smd->entry.tid, m_qp->r_entry.tid,
			smd->m_hd_ro, smd->m_tl_ro, smd->m_buf_tl + 1,
			smd->m_buf_hd, smd->m_buf_hd, m_idx,
			smd->m_tl, smd->m_hd);
		mcm_check_io();
	}
#endif
	return 0;
}

/* called with smd->tblock */
static void m_po_buf_tl(mcm_scif_dev_t *smd, int m_idx)
{
	int idx;
	int busy = 0, match = 0, hits = 0;
#ifdef MCM_PROFILE
	off_t tl_sav = smd->m_tl;
	uint32_t now = mcm_ts_us();
#endif
	idx = (smd->m_buf_tl + 1) & smd->m_buf_end; /* tl == hd is empty */

	mlog(0x10," [%d:%d] m_tl 0x%Lx m_hd 0x%Lx - "
		  "m_wc %p: tl %d hd %d - m_idx=0x%x free\n",
		  smd->md->mc->scif_id, smd->entry.tid,
		  smd->m_tl, smd->m_hd, smd->m_buf_wc, idx,
		  (smd->m_buf_hd + 1) & smd->m_buf_end, m_idx);

	/* mark m_idx complete, move proxy buffer tail until busy slot */
	while ((!match || !busy) && smd->m_buf_tl != smd->m_buf_hd) {
		if (smd->m_buf_wc[idx].m_idx == m_idx) {
			smd->m_buf_wc[idx].done = 1;
			match = 1;
#ifdef MCM_PROFILE
			smd->m_buf_wc[idx].ref--;
			smd->m_buf_wc[idx].ts = now - smd->m_buf_wc[idx].ts;
#endif
		}
		if (smd->m_buf_wc[idx].done && !busy) {
			smd->m_tl = smd->m_buf_wc[idx].m_idx;
			smd->m_buf_wc[idx].m_idx = 0;
			smd->m_buf_tl = (smd->m_buf_tl + 1) & smd->m_buf_end;
			hits++;
		}
		if (!smd->m_buf_wc[idx].done)
			busy = 1;

		if (idx == smd->m_buf_hd)
			break;

		idx = (idx + 1) & smd->m_buf_end;
	}

#ifdef MCM_PROFILE
	if (tl_sav > smd->m_tl)
		smd->m_tl_ro++;

	if (!match) {
		mlog(0, " [%d:%d] ERR: m_tl 0x%x m_hd 0x%x"
			"- m_wc %p: tl %d hd %d - m_idx=0x%x NO MATCH\n",
			smd->md->mc->scif_id, smd->entry.tid,
			smd->m_tl, smd->m_hd, smd->m_buf_wc, smd->m_buf_tl,
			(smd->m_buf_hd + 1) & smd->m_buf_end, m_idx);
		mcm_check_io();
	}
#endif
}

/*
 * Proxy-out to Proxy-in - Endpoints are on same platform
 */
static int m_po_send_wr_local(struct mcm_qp *m_qp, struct mcm_wr *m_wr, int wr_idx)
{
	mcm_cm_t *m_cm = m_qp->cm;

	mlog(0, " ERR: Po->Pi same node: not implemented\n");
	mlog(0, " SRC 0x%x %x 0x%x -> DST 0x%x %x 0x%x guid %Lx %Lx %s\n",
		htons(m_cm->msg.saddr1.lid), htonl(m_cm->msg.saddr1.qpn),
		htons(m_cm->msg.sport),	htons(m_cm->msg.daddr1.lid),
		htonl(m_cm->msg.dqpn), htons(m_cm->msg.dport),
		ntohll(m_cm->msg.sys_guid), ntohll(system_guid),
		mcm_map_str(m_cm->msg.daddr1.ep_map));

	return 0;
}

/*
 * Proxy-out to Proxy-in - Endpoints remote across fabric
 *
 * check data xfer segment complete, forward segment to proxy-in on remote node
 *
 * RDMA Write WR to remote proxy-in service, manage WR hd/tl from this side.
 * With inline large enough we don't have to register local side WR data
 *
 * called with m_qp->txlock held
 *
 */
static int m_po_send_pi(struct mcm_qp *m_qp, struct mcm_wr *m_wr, int wr_idx)
{
	struct ibv_send_wr *bad_wr;
	struct ibv_qp *ib_qp;
	struct ibv_send_wr wr;
	struct ibv_sge sge;
	struct mcm_wr_rx wr_rx;
	struct mcm_wr_rx *wr_rx_ptr;
	int ret;
	struct wrc_idata wrc;

	/* if proxy-out to proxy-in on same system, keep it local */
	if (m_qp->cm->msg.sys_guid == system_guid)
		return (m_po_send_wr_local(m_qp, m_wr, wr_idx));

	if (m_qp->smd->md->indata) {
		wr_rx_ptr = &wr_rx;
		sge.lkey = 0; /* inline doesn't need registered */
	} else {
		wr_rx_ptr = (struct mcm_wr_rx *)
			    (m_qp->wr_buf_rx + (sizeof(struct mcm_wr_rx) * wr_idx));
		sge.lkey = m_qp->wr_buf_rx_mr->lkey;
	}
	sge.addr = (uint64_t)(uintptr_t) wr_rx_ptr;
	sge.length = (uint32_t) m_qp->wrc_rem.wr_sz;

	/* proxy m_wr over to remote m_wr_rem slot, remote will initiate RR and send back WC */
	if (m_qp->p2p_data && m_wr->sg[0].length < m_qp->p2p_data) {
		mlog(0x4, " Sending the proxy data ( len %d ) inside the WR.\n", m_wr->sg[0].length);
		m_wr->flags |= M_PROXY_INLINE;
		memcpy (wr_rx_ptr->inline_data, (void *)m_wr->sg[0].addr, m_wr->sg[0].length);
	}

	m_wr->flags |= M_SEND_PI;
	mcm_hton_wr_rx(wr_rx_ptr, m_wr, m_qp->wc_tl); /* build rx_wr for wire transfer, send it */

	wrc.id = (uint16_t)wr_idx;  /* setup imm_data for proxy_in rcv engine */
	wrc.type = M_WR_TYPE;
	wrc.flags = 0;

	memset(&wr, 0, sizeof(struct ibv_send_wr));
	wr.wr_id = WRID_SET(m_wr, WRID_TX_RW_IMM);
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;

	if (m_qp->smd->md->indata)
		wr.send_flags = IBV_SEND_INLINE;

	if (m_wr->flags & M_SEND_MP_SIG) {
		m_qp->post_sig_cnt++;  /* sig event pending */
#if MCM_PROFILE /* MCM_QP_PO_PI_RW */
		if ((m_wr->flags & M_SEND_FS) && (m_wr->sg[0].length > 1024)) {
			m_wr->wr.wr.atomic.swap = mcm_ts_us();
			m_wr->wr.wr.atomic.rkey = ((m_wr->w_idx - m_qp->last_wr_pst) & m_qp->wr_end); /* queued */
			m_qp->last_wr_pst = m_wr->w_idx;
		}
#endif
	}

	wr.send_flags |= IBV_SEND_SIGNALED;
	wr.imm_data = htonl(*(uint32_t *)&wrc);
	wr.wr.rdma.rkey = m_qp->wrc_rem.wr_rkey;
	wr.wr.rdma.remote_addr =
		(uint64_t)(uintptr_t)
		((struct mcm_wr_rx *) (m_qp->wrc_rem.wr_addr + (m_qp->wrc_rem.wr_sz * wr_idx)));


	/* MXS -> MSS or HST, PI service will be on QP1 */
	if (MXF_EP(&m_qp->smd->md->addr) &&
	   (MSS_EP(&m_qp->cm->msg.daddr1) || HST_EP(&m_qp->cm->msg.daddr1)))
	        ib_qp = m_qp->ib_qp1;
	else
		ib_qp = m_qp->ib_qp2;

	mlog(0x4, " RW_imm: wr_id %Lx qn %x op %d flgs %x"
		" idata %x wr_rx: raddr %p rkey %x ln %d tl %d me %d hd %d\n",
		wr.wr_id, ib_qp->qp_num, wr.opcode, wr.send_flags, ntohl(wr.imm_data),
		wr.wr.rdma.remote_addr, wr.wr.rdma.rkey, m_wr->sg[0].length,
		m_qp->wr_tl, wr_idx, m_qp->wr_hd);

	mlog(0x4, "[%d:%d:%d] RW_wr[%d]: %p org_id %Lx op %d flgs %d imm 0x%x"
		   " raddr %p rkey %x m_idx %x\n",
		   m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
		   wr_idx, m_wr, m_wr->wr.wr_id, m_wr->wr.opcode, m_wr->wr.send_flags,
		   m_wr->wr.imm_data, m_wr->wr.wr.rdma.remote_addr, m_wr->wr.wr.rdma.rkey,
		   m_wr->m_idx);

	errno = 0;
	ret = ibv_post_send(ib_qp, &wr, &bad_wr);
	if (ret) {
		mlog(0, " ERR: m_wr %p idx %d laddr=%p ln=%d lkey=%x flgs %x"
			" tl %d hd %d pp %d sig %d ret %d %s\n",
			m_wr, wr_idx, sge.addr, sge.length, sge.lkey,
			m_wr->flags, m_qp->wr_tl, m_qp->wr_hd,
			m_qp->wr_pp_rem, m_qp->post_sig_cnt,
			ret, strerror(errno));
		mlog(0, " ERR: wr_id %Lx %p sglist %p sge %d op %d flgs %x"
			" idata 0x%x raddr %p rkey %x \n",
			m_wr->wr.wr_id, m_wr->wr.sg_list,
			m_wr->wr.num_sge, m_wr->wr.opcode,
			m_wr->wr.send_flags, m_wr->wr.imm_data,
			m_wr->wr.wr.rdma.remote_addr,
			m_wr->wr.wr.rdma.rkey);
		return ret;
	}
	m_qp->wr_pp_rem++;
	return 0;
}

void m_po_pending_wr(struct mcm_qp *m_qp, int *data)
{
	mcm_scif_dev_t *smd = m_qp->smd;
	struct mcm_wr *m_wr;
	struct ibv_send_wr *bad_wr;
	int ret, wr_idx, wr_max, poll_cnt, cn_signal;

	mpxy_lock(&m_qp->txlock);
	if ((m_qp->wr_tl == m_qp->wr_hd) ||
	    ((m_qp->wr_tl_rf == m_qp->wr_hd) && !m_qp->wr_pp)) { /* empty, no work pending */
		mpxy_unlock(&m_qp->txlock);
		return;
	}
	wr_max = mcm_wr_max;
	wr_idx = m_qp->wr_tl_rf;

	while (wr_max && m_qp->wr_pp) {
		cn_signal = 0; poll_cnt = 50;
		m_wr = (struct mcm_wr *)(m_qp->wr_buf + (m_qp->wr_sz * wr_idx));

		mlog(0x4, " CHECK: qp %p hd %d tl %d idx %d wr %p wr_id %p,"
			" addr %p sz %d sflg 0x%x mflg 0x%x pp %d\n",
			m_qp, m_qp->wr_hd,
			m_qp->wr_tl, wr_idx, m_wr, m_wr->org_id,
			m_wr->wr.sg_list ? m_wr->wr.sg_list->addr:0,
			m_wr->wr.sg_list ? m_wr->sg->length:0,
			m_wr->wr.send_flags, m_wr->flags, m_qp->wr_pp);

		/* inline, OP thread posted */
		if (m_wr->flags & M_SEND_POSTED) {
			mlog(0x20, " POSTED: qp %p hd %d tl %d idx %d wr %p wr_id %p,"
				" addr %p sz %d sflg 0x%x mflg 0x%x\n",
				m_qp, m_qp->wr_hd,
				m_qp->wr_tl, wr_idx, m_wr, m_wr->org_id,
				m_wr->wr.sg_list ? m_wr->wr.sg_list->addr:0,
				m_wr->wr.sg_list ? m_wr->sg->length:0,
				m_wr->wr.send_flags, m_wr->flags);

			if (wr_idx == m_qp->wr_hd)
				goto done;

			wr_idx = (wr_idx + 1) & m_qp->wr_end;
			continue;
		}
		wr_max--;

		while ((m_wr->wr.wr_id != m_wr->org_id) && (--poll_cnt));

		mlog(4, " qp %p hd %d tl %d idx %d wr %p wr_id %Lx = %Lx at %p POLL=%d flgs=%x\n",
			m_qp, m_qp->wr_hd, (m_qp->wr_tl + 1) & m_qp->wr_end,
			wr_idx, m_wr, m_wr->org_id, m_wr->wr.wr_id,
			&m_wr->wr.wr_id, poll_cnt, m_wr->flags);

		if (m_wr->wr.wr_id == m_wr->org_id) {
			char *sbuf = (char*)m_wr->wr.sg_list->addr;

			/* mark RF done, start timer */
			if (!(m_wr->flags & M_READ_FROM_DONE)) {
				m_wr->flags |= M_READ_FROM_DONE;
#if MCM_PROFILE
				if (!(m_wr->flags & M_SEND_INLINE)) {
					mcm_qp_prof_ts(m_qp, MCM_QP_RF,
						       m_wr->wr.wr.atomic.swap,
						       m_wr->wr.wr.atomic.rkey, 1);
				}
#endif
			}

			if (!(m_wr->flags & M_SEND_INLINE))
				MCNTR(smd->md, MCM_SCIF_READ_FROM_DONE);

			mlog(4, " m_wr %p READY for ibv_post addr=%p ln=%d, lkey=%x\n",
				m_wr, sbuf, m_wr->sg->length, m_wr->sg->lkey);
			mlog(4, " wr_id %Lx next %p sglist %p sge %d op %d flgs"
				" %d idata 0x%x raddr %p rkey %x \n",
			     m_wr->wr.wr_id, m_wr->wr.next, m_wr->wr.sg_list,
			     m_wr->wr.num_sge, m_wr->wr.opcode,
			     m_wr->wr.send_flags, m_wr->wr.imm_data,
			     m_wr->wr.wr.rdma.remote_addr, m_wr->wr.wr.rdma.rkey);

			/* signaling and eager completion */
			if (m_wr->flags & M_SEND_CN_SIG)
				cn_signal = 1;

			if (mix_eager_completion) {
				m_wr->flags &= ~M_SEND_CN_SIG;
				if (!(m_wr->flags & M_SEND_MP_SIG))
					m_wr->wr.send_flags &= ~IBV_SEND_SIGNALED;
			}

			if (!(MXF_EP(&m_qp->cm->msg.daddr1)) &&
			     (m_wr->wr.send_flags & IBV_SEND_SIGNALED)) {
				m_qp->post_sig_cnt++;

				mlog(0x10, "[%d:%d:%d] %s_RW_post_sig: WR[%d] qp %p wr_id %p flgs 0x%x,"
					" pcnt %d sg_rate %d hd %d tl %d sz %d m_idx %x\n",
					m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
					(MXF_EP(&m_qp->cm->msg.daddr1)) ? "po_pi":"po_direct",
					m_wr->w_idx, m_qp, m_wr->wr.wr_id, m_wr->wr.send_flags,
					m_qp->post_cnt,	mcm_rw_signal, m_qp->wr_hd, m_qp->wr_tl,
					m_wr->wr.sg_list->length, m_wr->m_idx);
#if MCM_PROFILE
				m_wr->wr.wr.atomic.swap = mcm_ts_us();
				m_wr->wr.wr.atomic.rkey = ((m_wr->w_idx - m_qp->last_wr_pst) & ~m_qp->wr_end); /* queued */
				m_qp->last_wr_pst = m_wr->w_idx;
#endif
			}
			m_wr->wr.wr_id = WRID_SET(m_wr, WRID_TX_RW);

			errno = 0;
			if (MXF_EP(&m_qp->cm->msg.daddr1)) /* remote PI */
				ret = m_po_send_pi(m_qp, m_wr, wr_idx);
			else
				ret = ibv_post_send(m_qp->ib_qp2, &m_wr->wr, &bad_wr);

			if (ret || (cn_signal && mix_eager_completion)) {
				struct dat_mix_wc wc;

				wc.wr_id = m_wr->org_id;
				wc.byte_len = m_wr->sg->length;
				wc.status = ret ? IBV_WC_GENERAL_ERR : IBV_WC_SUCCESS;
				wc.opcode = m_wr->wr.opcode == IBV_WR_SEND ? IBV_WC_SEND:IBV_WC_RDMA_WRITE;
				if (m_wr->wr.opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
					wc.wc_flags = IBV_WC_WITH_IMM;
				else
					wc.wc_flags = 0;
				wc.vendor_err = ret;
				if (ret) {
					mlog(0, "[%d:%d:%d] ERR %s_RW_post: WR[%d] wr_id %p flgs 0x%x,"
						" pcnt %d sg_rate %d hd %d tl %d sz %d m_idx %x\n",
						m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid,
						m_qp->r_entry.tid,
						(MXF_EP(&m_qp->cm->msg.daddr1)) ? "po_pi":"po_direct",
						m_wr->w_idx, m_wr->wr.wr_id, m_wr->wr.send_flags,
						m_qp->post_cnt,	mcm_rw_signal, m_qp->wr_hd, m_qp->wr_tl,
						m_wr->wr.sg_list->length, m_wr->m_idx);
					mlog(0, "[%d:%d:%d] ERR wr_id %Lx next %p sglist %p sge %d op %d flgs"
						" %d idata 0x%x raddr %p rkey %x \n",
						m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid,
						m_qp->r_entry.tid, m_wr->wr.wr_id, m_wr->wr.next,
						m_wr->wr.sg_list, m_wr->wr.num_sge, m_wr->wr.opcode,
						m_wr->wr.send_flags, m_wr->wr.imm_data,
						m_wr->wr.wr.rdma.remote_addr, m_wr->wr.wr.rdma.rkey);
				}
				mix_dto_event(m_qp->ib_qp2->send_cq->cq_context, &wc, 1);
			}

			if (m_wr->w_idx != m_qp->wr_hd) /* set next start */
				m_qp->wr_tl_rf = (m_wr->w_idx + 1) & m_qp->wr_end;
			else
				m_qp->wr_tl_rf = m_qp->wr_hd;

			m_qp->wr_pp--;
			m_qp->post_cnt++;
			m_wr->flags |= M_SEND_POSTED;

			if (m_wr->wr.opcode == IBV_WR_SEND) {
				if (m_wr->sg->length <= mix_inline_threshold)
					MCNTR(smd->md, MCM_QP_SEND_INLINE);
				else
					MCNTR(smd->md, MCM_QP_SEND);
			} else {
				if (m_wr->sg->length <= mix_inline_threshold)
					MCNTR(smd->md, MCM_QP_WRITE_INLINE);
				else
					MCNTR(smd->md, MCM_QP_WRITE);
			}
			mlog(4, " qp %p wr %p wr_id %Lx posted tl=%d tl_rf=%d"
				" hd=%d idx=%d pst=%d,%d cmp %d %s\n",
				m_qp, m_wr, m_wr->org_id, m_qp->wr_tl,
				m_qp->wr_tl_rf, m_qp->wr_hd, wr_idx,
				m_qp->post_cnt, m_qp->post_sig_cnt,
				m_qp->comp_cnt,
				m_wr->flags & M_SEND_FS ? "FS":
				(m_wr->flags & M_SEND_LS) ? "LS":"");
		}

		if (!(m_wr->flags & M_SEND_POSTED)) {
			mlog(4, " qp %p wr %p wr_id %Lx not done\n",
				m_qp, m_wr, m_wr->org_id);
			goto done;
		}
		if (wr_idx == m_qp->wr_hd)
			goto done;

		wr_idx = (wr_idx + 1) & m_qp->wr_end; /* next, hd == done */

		if (smd->destroy) {
			mlog(0, " SMD destroy - QP %p hd %d tl %d pst %d,%d cmp %d, pp %d, data %d\n",
				m_qp, m_qp->wr_hd, m_qp->wr_tl,m_qp->post_cnt,
				m_qp->post_sig_cnt, m_qp->comp_cnt, m_qp->wr_pp, data);
			mlog(0, " wr %p wr_id %p org_id %p sglist %p sge %d ln %d op %d flgs"
				" %x idata 0x%x raddr %p rkey %x m_flgs %x\n",
			     m_wr, m_wr->wr.wr_id, m_wr->org_id, m_wr->wr.sg_list,
			     m_wr->wr.num_sge, m_wr->sg->length, m_wr->wr.opcode,
			     m_wr->wr.send_flags, m_wr->wr.imm_data,
			     m_wr->wr.wr.rdma.remote_addr, m_wr->wr.wr.rdma.rkey, m_wr->flags);
			goto done;
		}
	}
done:
	*data += m_qp->wr_pp;
	*data +=  m_qp->post_sig_cnt - m_qp->comp_cnt;
	mpxy_unlock(&m_qp->txlock);

	if (smd->destroy) {
		mlog(0, " SMD destroy - QP %p hd %d tl %d pst %d,%d cmp %d,"
			" pending data %d, data %d\n",
			m_qp, m_qp->wr_hd, m_qp->wr_tl,m_qp->post_cnt,
			m_qp->post_sig_cnt, m_qp->comp_cnt, data, data);
	}
}

static uint32_t po_ts = 0;

/* initiate proxy data transfer, operation channel */
int m_po_proxy_data(mcm_scif_dev_t *smd, dat_mix_sr_t *pmsg, struct mcm_qp *m_qp)
{
	int len, ret, i, retries, wc_err = IBV_WC_GENERAL_ERR;
	off_t l_off, r_off;
	uint64_t total_offset;
	int  l_start, l_end, l_len, cacheln_off, seg_len;
	struct mcm_wr *m_wr = NULL;
	struct ibv_sge *m_sge;

	mlog(4, " q_id %d, q_ctx %p, len %d, wr_id %p, sge %d, op %x flgs %x wr_idx %d\n",
		pmsg->qp_id, (void*)pmsg->qp_ctx, pmsg->len, pmsg->wr.wr_id,
		pmsg->wr.num_sge, pmsg->wr.opcode, pmsg->wr.send_flags, pmsg->sge[0].lkey);

	total_offset = 0;

#if MCM_PROFILE
	if (!m_qp->last_ps) {
		m_qp->last_ps = mcm_ts_us();
	} else {
		mcm_qp_prof_ts(m_qp, MCM_QP_PO_POST, m_qp->last_ps, 1, 1);
		m_qp->last_ps = mcm_ts_us();
	}
#endif
	if (pmsg->wr.opcode == IBV_WR_SEND)
		MCNTR(smd->md, MCM_MX_SEND);
	else
		MCNTR(smd->md, MCM_MX_WRITE);

	mpxy_lock(&m_qp->txlock);
	retries = 0;
	while (((m_qp->wr_hd + 1) & m_qp->wr_end) == m_qp->wr_tl) {
		if (!retries) {
			MCNTR(smd->md, MCM_MX_WR_STALL);
		}
		if (!(++retries % 100)) {
			mlog(1, " WARN: DTO delay: no PO WRs: sz %d, hd %d tl %d io %d"
				" retried %d pst %d,%d cmp %d wr_pp %d -> %s\n",
				m_qp->wr_end, m_qp->wr_hd, m_qp->wr_tl,
				pmsg->len, retries, m_qp->post_cnt,
				m_qp->post_sig_cnt, m_qp->comp_cnt, m_qp->wr_pp,
				mcm_map_str(m_qp->cm->msg.daddr1.ep_map));
			mcm_pr_addrs(1, &m_qp->cm->msg, m_qp->cm->state, 0);
		}
		if (retries == 1000) {
			ret = ENOMEM;
			wc_err = IBV_WC_RETRY_EXC_ERR;
			goto bail;
		}
		write(smd->md->mc->tx_pipe[1], "w", sizeof("w"));
		mpxy_unlock(&m_qp->txlock);
		sleep_usec(1000);
		mpxy_lock(&m_qp->txlock);
	}
	if (retries) {
		mlog(1, " WR stalled: sz %d, hd %d tl %d io %d"
			" retried %d pst %d,%d cmp %d wr_pp %d\n",
			m_qp->wr_end, m_qp->wr_hd, m_qp->wr_tl,
			pmsg->len, retries, m_qp->post_cnt,
			m_qp->post_sig_cnt, m_qp->comp_cnt, m_qp->wr_pp);
	}

	m_qp->wr_hd = (m_qp->wr_hd + 1) & m_qp->wr_end; /* move hd */
	m_wr = (struct mcm_wr *)(m_qp->wr_buf + (m_qp->wr_sz * m_qp->wr_hd));
	m_sge = m_wr->sg;
	m_wr->org_id = pmsg->wr.wr_id;
	m_wr->m_idx = 0;
	m_wr->w_idx = m_qp->wr_hd;
	m_wr->flags = M_SEND_FS;
	m_wr->context = (uint64_t)m_qp;
	const_ib_rw(&m_wr->wr, &pmsg->wr, m_sge);

	mlog(4, " m_wr %p m_sge %p num_sge %d\n", m_wr, m_sge, pmsg->wr.num_sge);
	mlog(4, " m_wr: raddr %Lx rkey 0x%x, ib_wr: raddr %Lx rkey 0x%x\n",
		pmsg->wr.wr.rdma.remote_addr, pmsg->wr.wr.rdma.rkey,
		m_wr->wr.wr.rdma.remote_addr, m_wr->wr.wr.rdma.rkey);

	for (i=0;i<pmsg->wr.num_sge;i++) {
		len = pmsg->sge[i].length;
		r_off = pmsg->sge[i].addr;
		l_len = ALIGN_64(r_off + len) - ALIGN_DOWN_64(r_off);
		cacheln_off = OFFSET_64(r_off);
		r_off = ALIGN_DOWN_64(r_off);

		mlog(4, " r_off %p = %p, cl_off %d l_len %d len %d\n",
			pmsg->sge[i].addr, r_off, cacheln_off, l_len, len);

		while (l_len) {
			m_wr->wr.num_sge++;

			/* Send or last available WR, send all */
			if (pmsg->wr.opcode == IBV_WR_SEND)
				seg_len = l_len;
			else
				seg_len = (l_len > smd->m_seg) ? smd->m_seg : l_len;

			retries = 0;
			mpxy_lock(&smd->tblock);
retry_mr:
			l_start = ALIGN_64(smd->m_hd);
			if ((l_start + seg_len) > smd->m_len)
				l_start = 64;
			l_end = l_start + seg_len;

			if (pb_full(l_start, l_end, smd->m_hd, smd->m_tl, seg_len, smd->m_len)) {
				if (!retries) {
					po_ts = mcm_ts_us();
					MCNTR(smd->md, MCM_MX_MR_STALL);
					write(smd->md->mc->tx_pipe[1], "w", sizeof("w"));
					write(smd->md->mc->rx_pipe[1], "w", sizeof("w"));
				}
				if (!(++retries % 100)) {
					mlog(1, " [%d:%d:%d] WARN: no PO memory,"
						" 0x%x hd 0x%x tl 0x%x 0x%x 0x%x,"
						" need 0x%x-0x%x ln %d %d<-%d,"
						" retries = %d -> %s\n",
						m_qp->smd->md->mc->scif_id,
						m_qp->smd->entry.tid, m_qp->r_entry.tid,
						smd->m_buf, smd->m_hd, smd->m_tl,
						smd->m_len, smd->m_buf + smd->m_len,
						l_start, l_end, seg_len, l_len,
						pmsg->sge[i].length, retries,
						mcm_map_str(m_qp->cm->msg.daddr1.ep_map));
					mlog(1," [%d:%d:%d] WR tl %d idx %d hd %d QP pst %d,%d cmp %d - %s\n",
						m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
						m_qp->wr_tl, m_wr->w_idx, m_qp->wr_hd,
						m_qp->post_cnt, m_qp->post_sig_cnt, m_qp->comp_cnt,
						mcm_map_str(m_qp->cm->msg.daddr1.ep_map));
					mcm_pr_addrs(1, &m_qp->cm->msg, m_qp->cm->state, 0);
				}
				if (retries == 1000) {
					ret = ENOMEM;
					wc_err = IBV_WC_RETRY_EXC_ERR;
					mpxy_unlock(&smd->tblock);
					goto bail;
				}
				mpxy_unlock(&smd->tblock);
				mpxy_unlock(&m_qp->txlock);
				sleep_usec(1000);
				mpxy_lock(&m_qp->txlock);
				mpxy_lock(&smd->tblock);
				goto retry_mr;
			}
			if (retries) {
				mlog(1, " MEM stalled: %x hd 0x%x tl 0x%x %x"
					" got 0x%x-0x%x ln %d %d<-%d retried %d %dus\n",
					smd->m_buf, smd->m_hd, smd->m_tl,
					smd->m_buf + smd->m_len,
					l_start, l_end, seg_len, l_len,
					pmsg->sge[i].length, retries, mcm_ts_us() - po_ts);
			}
#ifdef MCM_PROFILE
			if (l_end < smd->m_hd)
				smd->m_hd_ro++;
#endif
			l_off = smd->m_offset + l_start;
			smd->m_hd = l_end;

			mlog(4, " SCIF_readfrom[%d] l_off %p, r_off %p,"
				" l_start 0x%x l_end 0x%x seg_len %d,"
				" len %d l_len %d cacheln_off %d %s\n",
				 i, l_off, r_off, l_start, l_end,
				 seg_len, len, l_len, cacheln_off,
				 m_wr->flags & M_SEND_FS ? "FS":
				 (len <= smd->m_seg) ? "LS":"");
#if MCM_PROFILE
			m_wr->wr.wr.atomic.swap = mcm_ts_us();
			m_wr->wr.wr.atomic.rkey = m_qp->wr_pp;
			if (m_qp->last_rf) {
				uint32_t now = mcm_ts_us();
				if ((now - m_qp->last_rf) > 100000) {
					mlog(0x1, " WARN: delayed post (%d us):"
						   " WR[%d] hd %d tl %d io %d"
						   " pst %d,%d cmp %d wr_pp %d\n",
						now - m_qp->last_rf,
						m_wr->w_idx, m_qp->wr_hd,
						m_qp->wr_tl, seg_len,
						m_qp->post_cnt, m_qp->post_sig_cnt,
						m_qp->comp_cnt, m_qp->wr_pp);
				}
			}
			m_qp->last_rf = mcm_ts_us();
#endif
			if (seg_len < 256)
				ret = scif_readfrom(smd->scif_tx_ep, l_off, seg_len, r_off, SCIF_RMA_USECPU);
			else
				ret = scif_readfrom(smd->scif_tx_ep, l_off, seg_len, r_off, 0);

			if (ret) {
				mlog(0, " ERR: scif_readfrom, ret %d\n", ret);
				mpxy_unlock(&smd->tblock);
				goto bail;
			}
			MCNTR(smd->md, MCM_SCIF_READ_FROM);

			m_sge->addr = (uint64_t)(smd->m_buf + l_start + cacheln_off);
			m_sge->lkey = smd->m_mr->lkey;
			m_sge->length = seg_len - cacheln_off;

			if (m_sge->length > len)
				m_sge->length = len;

			mlog(4, " update sge[%d] addr %p len %d lkey 0x%x\n",
			     i, m_sge->addr, m_sge->length, m_sge->lkey);

			l_len -= seg_len;
			r_off += seg_len;
			len -= m_sge->length;
			total_offset += m_sge->length;
			cacheln_off = 0; /* only apply to the first segment of a sge */

			m_sge++;

			/* if enough for this WR, then set up DMA signal, and move to next WR */
			if (seg_len == smd->m_seg || i == (pmsg->wr.num_sge - 1)) {
				l_off = m_qp->wr_off + (m_qp->wr_hd * m_qp->wr_sz);

				/* Remove IMM unless it's the last segment
				 * NON-COMPLIANT: IMM segmented causes receiver
				 * RDMA length will be wrong
				 */
				if (len || i != (pmsg->wr.num_sge - 1)) {
					if (m_wr->wr.opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
						m_wr->wr.opcode = IBV_WR_RDMA_WRITE;
					m_wr->wr.send_flags = 0;
				} else {
					m_wr->flags |= M_SEND_LS;
					if (m_wr->wr.send_flags & IBV_SEND_SIGNALED)
						m_wr->flags |= M_SEND_CN_SIG;
				}

				/* MP service signaling, set PO mbuf tail adjustment */
				if (!((m_wr->w_idx) % mcm_rw_signal) || m_wr->flags & M_SEND_LS) {
					char *sbuf = (char*)m_wr->wr.sg_list->addr;

					m_wr->wr.send_flags |= IBV_SEND_SIGNALED;
					m_wr->flags |= M_SEND_MP_SIG;
					m_wr->m_idx = (sbuf + (m_wr->wr.sg_list->length - 1)) - smd->m_buf;
					if (m_po_buf_hd(smd, m_wr->m_idx, m_wr)) {
						mpxy_unlock(&smd->tblock);
						goto bail;
					}
					mlog(0x10, "[%d:%d:%d] %s_RF_post_sig: WR[%d] qp %p wr_id %p flgs 0x%x,"
						" sg_rate %d hd %d tl %d sz %d m_idx %x\n",
						m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
						(MXF_EP(&m_qp->cm->msg.daddr1)) ? "po_pi":"po_direct",
						m_wr->w_idx, m_qp, pmsg->wr.wr_id, m_wr->wr.send_flags,
						mcm_rw_signal, m_qp->wr_hd, m_qp->wr_tl,
						m_wr->wr.sg_list->length, m_wr->m_idx);
				}

				if ((smd->md->indata) && (pmsg->len <= mcm_ib_inline))
					m_wr->wr.send_flags |= IBV_SEND_INLINE;

				mlog(4, " SCIF_fence[%d] l_off %p, ln %d,%d,%d wr_id %p"
					" wr_idx %d, tl %d hd %d\n",
					 i, l_off, len, l_len, seg_len, pmsg->wr.wr_id,
					 m_wr->w_idx, m_qp->wr_tl, m_qp->wr_hd);

				ret = scif_fence_signal(smd->scif_tx_ep, l_off,
						        pmsg->wr.wr_id, 0, 0,
							SCIF_FENCE_INIT_SELF |
							SCIF_SIGNAL_LOCAL);
				if (ret) {
					mlog(0," ERR: scif_fence_sig, ret %d \n", ret);
					mpxy_unlock(&smd->tblock);
					goto bail;
				}
				m_qp->wr_pp++;
				MCNTR(smd->md, MCM_SCIF_SIGNAL);
				MCNTR(smd->md, MCM_MX_WRITE_SEG);

				if (!len) { /* done */
					mpxy_unlock(&smd->tblock);
					break;
				}

				/* get next WR */
				retries = 0;
				while (((m_qp->wr_hd + 1) & m_qp->wr_end) == m_qp->wr_tl) {
					if (!retries) {
						MCNTR(smd->md, MCM_MX_WR_STALL);
						write(smd->md->mc->tx_pipe[1], "w", sizeof("w"));
						write(smd->md->mc->rx_pipe[1], "w", sizeof("w"));
					}
					if (!(++retries % 100)) {
						mlog(1, " WARN: DTO delay: no PO WR: sz %d, hd %d tl %d io %d"
							" retried %d pst %d,%d cmp %d wr_pp %d -> %s\n",
							m_qp->wr_end, m_qp->wr_hd, m_qp->wr_tl,
							seg_len, retries, m_qp->post_cnt,
							m_qp->post_sig_cnt, m_qp->comp_cnt, m_qp->wr_pp,
							mcm_map_str(m_qp->cm->msg.daddr1.ep_map));
						mcm_pr_addrs(1, &m_qp->cm->msg, m_qp->cm->state, 0);
					}
					if (retries == 1000) {
						ret = ENOMEM;
						wc_err = IBV_WC_RETRY_EXC_ERR;
						mpxy_unlock(&smd->tblock);
						goto bail;
					}
					mpxy_unlock(&smd->tblock);
					mpxy_unlock(&m_qp->txlock);
					sleep_usec(1000);
					mpxy_lock(&m_qp->txlock);
					mpxy_lock(&smd->tblock);
				}
				if (retries) {
					mlog(1, " WR stalled: sz %d, hd %d tl %d io %d"
						" retried %d pst %d,%d cmp %d wr_pp %d\n",
						m_qp->wr_end, m_qp->wr_hd, m_qp->wr_tl,
						seg_len, retries, m_qp->post_cnt,
						m_qp->post_sig_cnt, m_qp->comp_cnt, m_qp->wr_pp);
				}

				if (m_wr->flags & M_SEND_LS) {
					mpxy_unlock(&smd->tblock);
					goto bail;
				}

				/* prepare the next WR */
				m_qp->wr_hd = (m_qp->wr_hd + 1) & m_qp->wr_end; /* move hd */
				m_wr = (struct mcm_wr *)(m_qp->wr_buf + (m_qp->wr_sz * m_qp->wr_hd));
				m_sge = m_wr->sg;
				m_wr->org_id = pmsg->wr.wr_id;
				m_wr->w_idx = m_qp->wr_hd;
				m_wr->m_idx = 0;
				m_wr->flags = 0;
				m_wr->context = (uint64_t)m_qp;
				const_ib_rw(&m_wr->wr, &pmsg->wr, m_sge);
				m_wr->wr.wr.rdma.remote_addr += total_offset;
			}
			mpxy_unlock(&smd->tblock);

			if (!(m_qp->wr_hd % mcm_wr_max)) {
				write(smd->md->mc->tx_pipe[1], "w", sizeof("w"));
				write(smd->md->mc->rx_pipe[1], "w", sizeof("w"));
				mpxy_unlock(&m_qp->txlock);
				sched_yield();
				mpxy_lock(&m_qp->txlock);
			}
		}
	}
	ret = 0;
bail:
	write(smd->md->mc->tx_pipe[1], "w", sizeof("w"));
	write(smd->md->mc->rx_pipe[1], "w", sizeof("w"));
	mpxy_unlock(&m_qp->txlock);
	if (ret) {
		struct dat_mix_wc wc;

		wc.wr_id = pmsg->wr.wr_id;
		wc.byte_len = pmsg->sge[0].length;
		wc.status = wc_err;
		wc.opcode = pmsg->wr.opcode == IBV_WR_SEND ? IBV_WC_SEND:IBV_WC_RDMA_WRITE;
		if (pmsg->wr.opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
			wc.wc_flags = IBV_WC_WITH_IMM;
		else
			wc.wc_flags = 0;
		wc.vendor_err = ret;

		mlog(0, "[%d:%d:%d] ERR %s_RF_post: WR[%d] qp %p wr_id %p, "
			" post %d hd %d tl %d sz %d \n",
			m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
			(MXF_EP(&m_qp->cm->msg.daddr1)) ? "po_pi":"po_direct",
			m_wr ? m_wr->w_idx:0, m_qp, m_wr, pmsg->wr.wr_id,
			m_qp->post_cnt,	m_qp->wr_hd, m_qp->wr_tl, wc.byte_len);
		mlog(0, "[%d:%d:%d] ERR m_wr: raddr %Lx rkey 0x%x, ib_wr: raddr %Lx rkey 0x%x\n",
			m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
			pmsg->wr.wr.rdma.remote_addr, pmsg->wr.wr.rdma.rkey,
			m_wr ? m_wr->wr.wr.rdma.remote_addr:0, m_wr ? m_wr->wr.wr.rdma.rkey:0);

		mix_dto_event(m_qp->ib_qp2->send_cq->cq_context, &wc, 1);
	}

	mlog(4, " exit: q_id %d, q_ctx %p, len %d, wr_hd %d pp %d\n",
		 pmsg->qp_id, (void*)pmsg->qp_ctx, pmsg->len, m_qp->wr_hd, m_qp->wr_pp);

	sched_yield();
	return ret;
}


/* work completion from remote proxy-in service, RX thread */
void m_po_wc_event(struct mcm_qp *m_qp, struct mcm_wc_rx *wc_rx, int wc_idx)
{
	struct mcm_wr *m_wr;
	struct mcm_cq *m_cq;
	struct dat_mix_wc wc_ev;
	int event = 0;

	m_wr = (struct mcm_wr *)(m_qp->wr_buf + (m_qp->wr_sz * wc_rx->wr_idx));

	if (wc_rx->wr_idx > m_qp->wr_end) {
		mlog(0," ERR: WC_rx: WR idx out of range %x > %x \n",
		     wc_rx->wr_idx, m_qp->wr_end);
		return;
	}
	m_cq = m_qp->m_cq_tx;

	if (wc_rx->wc.status == IBV_WC_SUCCESS) {
		mlog(8," WC_RX: SUCCESS m_wr %p idx %d=%d flags 0x%x \n",
			m_wr, m_wr->w_idx, wc_rx->wr_idx, m_wr->flags);
		if (m_wr->flags & M_SEND_CN_SIG) {
			m_wr->flags &= ~M_SEND_CN_SIG;
			wc_ev.wr_id = m_wr->org_id;
			wc_ev.status = IBV_WC_SUCCESS;
			wc_ev.byte_len = wc_rx->wc.byte_len;
			wc_ev.opcode = wc_rx->wc.opcode;
			wc_ev.wc_flags = wc_rx->wc.wc_flags;
			event++;
		}
	}
	else {
		/* segmentation, only report first error */
		if (m_cq->prev_id != m_wr->org_id) {
			char *sbuf = (char*)m_wr->sg->addr;

			mlog(0," DTO ERR: st %d, vn %x pst %d cmp %d qstate 0x%x\n",
				wc_rx->wc.status, wc_rx->wc.vendor_err, m_qp->post_cnt,
				m_qp->comp_cnt, m_qp->ib_qp2->state);
			mlog(0, " DTO ERR: m_wr %p laddr %p=0x%x - %p=0x%x, len=%d, lkey=%x\n",
				m_wr,  sbuf, sbuf[0], &sbuf[m_wr->sg->length],
				sbuf[m_wr->sg->length], m_wr->sg->length, m_wr->sg->lkey);
			mlog(0, " DTO ERR: wr_id %Lx next %p sglist %p sge %d op %d flgs"
				" %d idata 0x%x raddr %p rkey %x \n",
			     m_wr->org_id, m_wr->wr.next, m_wr->sg, m_wr->wr.num_sge,
			     m_wr->wr.opcode, m_wr->wr.send_flags, m_wr->wr.imm_data,
			     m_wr->wr.wr.rdma.remote_addr, m_wr->wr.wr.rdma.rkey);

			m_cq->prev_id = m_wr->org_id;
			wc_ev.wr_id = m_wr->org_id;
			wc_ev.status = wc_rx->wc.status;
			wc_ev.vendor_err = wc_rx->wc.vendor_err;
			event++;
		}
	}
	mlog(0x10," [%d:%d:%d] po_pi_RW DONE!: mb_tl %x->%x, m_hd %x wr_tl %d->%d wr_id %d wr_hd %d"
		  " wc_tl %d->%d - pst %d,%d cmp %d\n",
		m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
		m_qp->smd->m_tl, m_wr->m_idx, m_qp->smd->m_hd, m_qp->wr_tl, wc_rx->wr_tl,
		m_wr->w_idx, m_qp->wr_hd, m_qp->wc_tl, wc_idx,
		m_qp->post_cnt, m_qp->post_sig_cnt, m_qp->comp_cnt);

	/* PI peer has copy of data, free buffer slot if saved on MP signal mark */
	if (m_wr->flags & M_SEND_MP_SIG) {
#if MCM_PROFILE
		if ((m_wr->flags & M_SEND_LS) && (m_wr->sg[0].length > 1024)) {
			mcm_qp_prof_ts( m_qp, MCM_QP_PO_PI_RW,
					m_wr->wr.wr.atomic.swap,
					m_wr->wr.wr.atomic.rkey,
					1);
			m_qp->last_wr_sig = m_wr->w_idx;
		}
#endif
		m_qp->comp_cnt++;
		mpxy_lock(&m_qp->smd->tblock);
		m_po_buf_tl(m_qp->smd, m_wr->m_idx); /* move proxy buffer tail */
		mpxy_unlock(&m_qp->smd->tblock);
	}

	mpxy_lock(&m_qp->txlock);
	if (m_qp->wrc_rem.wr_addr)  /* remote MXS: sync PO WR tail with remote PI WR tail */
		m_qp->wr_tl = wc_rx->wr_tl;

	m_qp->wc_tl = wc_idx; /* move local wc_tl, for wc_tl_rem on peer PI service */
	mpxy_unlock(&m_qp->txlock);

	if (event)
		mix_dto_event(m_cq, &wc_ev, 1);
}

/*
 * Process the following completions from request queue:
 *
 * 	Proxy-out -> Direct-in, ibv_post_send RW of data segment
 * 	Proxy-out -> Proxy-in, ibv_post_send RW_imm of M_WR referencing data segment
 *
 * 	Proxy-in -> Proxy-out, ibv_post_send RR of remote proxy-out data segment
 * 	Proxy-in -> Proxy-out, ibv_post_send RW_imm of a M_WC completion status
 *
 *
 */
void m_req_event(struct mcm_cq *m_cq, int *events)
{
	struct ibv_cq *ib_cq = NULL;
	struct mcm_qp *m_qp;
	struct mcm_wr *m_wr;
	struct mcm_wr_rx *m_wr_rx;
	void *cq_ctx;
	int i, ret, num, wr_type, wc_cnt, notify = 0;
	struct ibv_wc wc[DAT_MIX_WC_MAX];
	struct dat_mix_wc wc_ev[DAT_MIX_WC_MAX];

	ret = ibv_get_cq_event(m_cq->ib_ch, &ib_cq, (void *)&cq_ctx);
	if (ret == 0)
		ibv_ack_cq_events(m_cq->ib_cq, 1);

	wc_cnt = 0;
retry:
	if (wc_cnt >= mcm_wc_max) {
		*events += 1;  /* pending */
		return;
	}

	ret = ibv_poll_cq(m_cq->ib_cq, DAT_MIX_WC_MAX, wc);
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
	num = 0;
	for (i=0; i<ret; i++) {
		wr_type = WRID_TYPE(wc[i].wr_id);

		mlog(4," ib_wc[%d of %d]: wr_id %Lx status %d, op %x vn %x len %d type %d\n",
		       i+1, ret, wc[i].wr_id, wc[i].status, wc[i].opcode,
		       wc[i].vendor_err, wc[i].byte_len, wr_type);

		/* Proxy_in -> */
		if (wr_type == WRID_RX_RW_IMM) {  /* RW_imm WC */
			continue;
		}
		if (wr_type == WRID_RX_RR) {
			m_wr_rx = (struct mcm_wr_rx *)WRID_ADDR(wc[i].wr_id);
			assert(m_wr_rx);
			m_qp = (struct mcm_qp *)m_wr_rx->context;
			assert(m_qp);
			m_pi_req_event(m_qp, m_wr_rx, &wc[i], wr_type);
			continue;

		} else if (wr_type > WRID_RX_RW_IMM) {
			mlog(0," ERR: wr_id corrupt - ib_wc[%d of %d]: wr_id %Lx stat %d"
			       " op %x vn %x len %d type %d\n",
			       i+1, ret, wc[i].wr_id, wc[i].status, wc[i].opcode,
			       wc[i].vendor_err, wc[i].byte_len, wr_type);
			continue;
		}
		/* Proxy_out ->  */
		m_wr = (struct mcm_wr *)WRID_ADDR(wc[i].wr_id);
		m_qp = (struct mcm_qp *)m_wr->context;
		if (m_qp->cm && !MXF_EP(&m_qp->cm->msg.daddr1))
			m_qp->comp_cnt++;
		MCNTR(m_qp->smd->md, MCM_QP_WRITE_DONE);

		mlog(8," wr_id[%d of %d] m_wr %p m_qp %p\n", i+1, ret, m_wr, m_qp);

		if (wc[i].status == IBV_WC_SUCCESS) {
			if (m_wr->flags & M_SEND_CN_SIG) {
				m_wr->flags &= ~M_SEND_CN_SIG;
				wc_ev[num].wr_id = m_wr->org_id;
				wc_ev[num].status = IBV_WC_SUCCESS;
				wc_ev[num].byte_len = wc[i].byte_len;
				wc_ev[num].opcode = m_wr->wr.opcode == IBV_WR_SEND ? IBV_WC_SEND:IBV_WC_RDMA_WRITE;
				if (m_wr->wr.opcode == IBV_WR_RDMA_WRITE_WITH_IMM)
					wc_ev[num].wc_flags = IBV_WC_WITH_IMM;
				else
					wc_ev[num].wc_flags = 0;
				num++;
			}
		}
		else {
			/* segmentation, only report first error */
			if (m_cq->prev_id != m_wr->org_id) {
				char *sbuf = (char*)m_wr->sg->addr;

				mlog(0," DTO ERR: st %d, vn %x pst %d cmp %d qstate 0x%x\n",
					wc[i].status, wc[i].vendor_err, m_qp->post_cnt,
					m_qp->comp_cnt, m_qp->ib_qp2->state);
				mlog(0, " DTO ERR: m_wr %p laddr %p=0x%x - %p=0x%x, len=%d, lkey=%x\n",
					m_wr,  sbuf, sbuf[0], &sbuf[m_wr->sg->length],
					sbuf[m_wr->sg->length], m_wr->sg->length, m_wr->sg->lkey);
				mlog(0, " DTO ERR: wr_id %Lx next %p sglist %p sge %d op %d flgs"
					" %d idata 0x%x raddr %p rkey %x \n",
				     m_wr->org_id, m_wr->wr.next, m_wr->sg, m_wr->wr.num_sge,
				     m_wr->wr.opcode, m_wr->wr.send_flags, m_wr->wr.imm_data,
				     m_wr->wr.wr.rdma.remote_addr, m_wr->wr.wr.rdma.rkey);

				m_cq->prev_id = m_wr->org_id;
				wc_ev[num].wr_id = m_wr->org_id;
				wc_ev[num].status = wc[i].status;
				wc_ev[num].vendor_err = wc[i].vendor_err;
				num++;
			}
		}

		/* Can move PO buffer tail if no peer PI service */
		if (!MXF_EP(&m_qp->cm->msg.daddr1)) {
#if MCM_PROFILE
			mcm_qp_prof_ts( m_qp, MCM_QP_IB_RW,
					m_wr->wr.wr.atomic.swap,
					m_wr->wr.wr.atomic.rkey,
					((m_wr->w_idx - m_qp->last_wr_sig) & m_qp->wr_end));
			m_qp->last_wr_sig = m_wr->w_idx;
#endif
			mlog(0x10," [%d:%d:%d] po_RW DONE!: WR[%d] wr %p MB_tl %Lx hd %Lx m_idx %x - %s\n",
				  m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
				  m_wr->w_idx, m_wr, m_qp->smd->m_tl, m_qp->smd->m_hd, m_wr->m_idx,
				  mcm_map_str(m_qp->cm->msg.daddr1.ep_map));

			mpxy_lock(&m_qp->smd->tblock);
			m_po_buf_tl(m_qp->smd, m_wr->m_idx); /* move proxy buffer tail */
			mpxy_unlock(&m_qp->smd->tblock);

			mpxy_lock(&m_qp->txlock);
			m_qp->wr_tl = m_wr->w_idx; /* move QP wr tail */
			mpxy_unlock(&m_qp->txlock);
		} else
			m_qp->wr_pp_rem--;

		mlog(0x10," [%d:%d:%d] mb_tl %x hd %x: WR tl %d idx %d hd %d: QP pst %d,%d cmp %d - %s\n",
			  m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
			  m_qp->smd->m_tl, m_qp->smd->m_hd, m_qp->wr_tl, m_wr->w_idx, m_qp->wr_hd,
			  m_qp->post_cnt, m_qp->post_sig_cnt, m_qp->comp_cnt,
			  mcm_map_str(m_qp->cm->msg.daddr1.ep_map));
	}
	if (num)
		mix_dto_event(m_cq, wc_ev, num);

	goto retry;
}

