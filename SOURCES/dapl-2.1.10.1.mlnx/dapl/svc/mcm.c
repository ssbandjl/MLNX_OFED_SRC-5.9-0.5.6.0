/*
 * Copyright (c) 2012-2014 Intel Corporation. All rights reserved.
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
 * mpxyd service - cm.c
 *
 * 	Communication Management for mpxyd
 * 		MIC is local endpoint via MIX protocol on Intel SCI
 * 		MIC/HOST is remote endpoint via MCM protocol on InfiniBand
 *
 * CM protocol, CM thread, resource management
 *
 */
#include "mpxyd.h"

/* cm parameters, setup defaults */
int mcm_depth = 500;
int mcm_size = 256;
int mcm_signal = 100;
int mcm_max_rcv = 20;
int mcm_retry = 10;
int mcm_disc_retry = 5;
int mcm_rep_ms = 4000;
int mcm_rtu_ms = 2000;
int mcm_dreq_ms = 1000;
int mcm_proxy_in = 1;
int mcm_mic0_mss = 1;  /* numa_node invalid, default mic0 == MSS */
int mcm_mic1_mss = 0;  /* numa_node invalid, default mic1 == MXS */

extern int mix_buffer_sg_po2;
extern int mcm_rx_entries;
extern uint64_t system_guid;
extern char gid_str[INET6_ADDRSTRLEN];

void mcm_get_attr(dat_mix_prov_attr_t *pr_attr)
{
	pr_attr->cm_retry = mcm_retry;
	pr_attr->cm_disc_retry = mcm_disc_retry;
	pr_attr->cm_rep_time_ms = mcm_rep_ms;
	pr_attr->cm_rtu_time_ms = mcm_rtu_ms;
	pr_attr->cm_drep_time_ms = mcm_dreq_ms;
}


/* Create address handle for remote QP, info in network order */
struct ibv_ah *mcm_create_ah(mcm_ib_dev_t *md,
			     struct ibv_pd *pd,
			     struct ibv_qp *qp,
			     uint16_t lid,
			     union ibv_gid *gid)
{
	struct ibv_qp_attr qp_attr;
	struct ibv_ah *ah;

	memset((void *)&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QP_STATE;
	qp_attr.ah_attr.dlid = lid;
	if (gid != NULL) {
		mlog(8, "create_ah: with GID\n");
		qp_attr.ah_attr.is_global = 1;
		qp_attr.ah_attr.grh.dgid.global.subnet_prefix =
				ntohll(gid->global.subnet_prefix);
		qp_attr.ah_attr.grh.dgid.global.interface_id =
				ntohll(gid->global.interface_id);
		qp_attr.ah_attr.grh.hop_limit =	md->dev_attr.hop_limit;
		qp_attr.ah_attr.grh.traffic_class = md->dev_attr.tclass;
	}
	qp_attr.ah_attr.sl = md->dev_attr.sl;
	qp_attr.ah_attr.src_path_bits = 0;
	qp_attr.ah_attr.port_num = md->port;

	mlog(8, "create_ah: port %x lid %x pd %p ctx %p handle 0x%x\n",
		md->port, qp_attr.ah_attr.dlid, pd, pd->context, pd->handle);

	/* UD: create AH for remote side */
	ah = ibv_create_ah(pd, &qp_attr.ah_attr);
	if (!ah) {
		mlog(0,	" create_ah: ERR %s\n", strerror(errno));
		return NULL;
	}

	mlog(8, "create_ah: AH %p for lid %x\n", ah, qp_attr.ah_attr.dlid);
	return ah;
}

/* Modify UD-QP from init, rtr, rts, info network order */
int modify_ud_qp(mcm_ib_dev_t *md, struct ibv_qp *qp)
{
	struct ibv_qp_attr qp_attr;

	/* modify QP, setup and prepost buffers */
	memset((void *)&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_INIT;
        qp_attr.pkey_index = md->dev_attr.pkey_idx;
        qp_attr.port_num = md->port;
        qp_attr.qkey = DAT_MCM_UD_QKEY;
	if (ibv_modify_qp(qp, &qp_attr,
			  IBV_QP_STATE		|
			  IBV_QP_PKEY_INDEX	|
                          IBV_QP_PORT		|
                          IBV_QP_QKEY)) {
		mlog(0, "INIT: ERR %s\n", strerror(errno));
		return 1;
	}
	memset((void *)&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_RTR;
	if (ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE)) {
		mlog(0, "RTR: ERR %s\n", strerror(errno));
		return 1;
	}
	memset((void *)&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_RTS;
	qp_attr.sq_psn = 1;
	if (ibv_modify_qp(qp, &qp_attr,
			  IBV_QP_STATE | IBV_QP_SQ_PSN)) {
		mlog(0, "RTS: ERR %s\n", strerror(errno));
		return 1;
	}
	return 0;
}

int mcm_init_cm_service(mcm_ib_dev_t *md)
{
        struct ibv_qp_init_attr qp_create;
        struct ibv_port_attr port_attr;
	struct ibv_recv_wr recv_wr, *recv_err;
        struct ibv_sge sge;
	int i, mlen = sizeof(dat_mcm_msg_t);
	char *rbuf;

	mlog(8, " create CM services.. %p, max pkt_sz %d + %d\n",
		md, mlen, sizeof(struct ibv_grh));

	/* setup CM msg attributes and timers */
	md->retries = mcm_retry;
	md->rep_time = mcm_rep_ms;
	md->rtu_time = mcm_rtu_ms;
	md->cm_timer = min(md->rep_time, md->rtu_time);
	md->qpe = mcm_depth;
	md->cqe = mcm_depth;
	md->signal = mcm_signal;

	/* ibscif: MIC and HST different, save MIC addresses */
	if (!strncmp(md->ibdev->name, "scif", 4)) {
		md->m_lid = md->addr.lid;
		memcpy(md->m_gid, md->addr.gid, 16);
	}

	/* Save addr information */
	/* get lid for this hca-port, convert to network order */
	if (ibv_query_port(md->ibctx, md->port, &port_attr)) {
		mlog(0,  "  ERR: get lid for %s, err=%s\n",
		     ibv_get_device_name(md->ibdev),
		     strerror(errno));
		return -1;
	} else
		md->lid = md->addr.lid = htons(port_attr.lid);

	if (md->lid == 0) {
		mlog(0, "  device %s, port %d not active\n",
			ibv_get_device_name(md->ibdev),	md->port);
		return -1;
	}

	/* get gid for this hca-port, in network order */
	if (ibv_query_gid(md->ibctx, md->port, 0, (union ibv_gid *)&md->addr.gid)) {
		mlog(0, " ERR: query GID for %s, err=%s\n",
		     ibv_get_device_name(md->ibdev),
		     strerror(errno));
		return -1;
	}
	/* EP mapping hint for MIC to HCA, set MSS if compat or PI disabled */
	if (md->addr.ep_map != MIC_FULL_DEV) {
		if (((md->numa_node != -1) &&
			 (md->numa_node == md->mc->numa_node)) ||
			  md->mc->ver == MIX_COMP || mcm_proxy_in == 0)
			md->addr.ep_map = MIC_SSOCK_DEV;
		else
			md->addr.ep_map = MIC_XSOCK_DEV;

		/* Invalid numa, check settings MSS for mic0, MXS for mic1 */
		if (md->numa_node == -1 && md->mc->scif_id == 1 && mcm_mic0_mss)
			md->addr.ep_map = MIC_SSOCK_DEV;
		if (md->numa_node == -1 && md->mc->scif_id == 2 && mcm_mic1_mss)
			md->addr.ep_map = MIC_SSOCK_DEV;
	}

	/* setup CM timers and queue sizes */
	md->pd = ibv_alloc_pd(md->ibctx);
        if (!md->pd)
                goto bail;

      	md->rch = ibv_create_comp_channel(md->ibctx);
	if (!md->rch)
		goto bail;
	mcm_config_fd(md->rch->fd);

	md->scq = ibv_create_cq(md->ibctx, md->cqe, md, NULL, 0);
	if (!md->scq)
		goto bail;

	md->rcq = ibv_create_cq(md->ibctx, md->cqe, md, md->rch, 0);
	if (!md->rcq)
		goto bail;

	if(ibv_req_notify_cq(md->rcq, 0))
		goto bail;

	memset((void *)&qp_create, 0, sizeof(qp_create));
	qp_create.qp_type = IBV_QPT_UD;
	qp_create.send_cq = md->scq;
	qp_create.recv_cq = md->rcq;
	qp_create.cap.max_send_wr = qp_create.cap.max_recv_wr = md->qpe;
	qp_create.cap.max_send_sge = qp_create.cap.max_recv_sge = 1;
	if (md->indata)
		qp_create.cap.max_inline_data = mlen + sizeof(struct ibv_grh);
	qp_create.qp_context = (void *)md;

	md->qp = ibv_create_qp(md->pd, &qp_create);
	if (!md->qp)
                goto bail;

	/* local addr info in network order */
	md->addr.port = htons(md->port);
	md->addr.qpn = htonl(md->qp->qp_num);
	md->addr.qp_type = md->qp->qp_type;

	md->ah = (struct ibv_ah **) malloc(sizeof(struct ibv_ah *) * 0xffff);
	md->ports = (uint64_t*) malloc(sizeof(uint64_t) * MCM_PORT_SPACE);
	md->rbuf = malloc((mlen + sizeof(struct ibv_grh)) * md->qpe);
	md->sbuf = malloc(mlen * md->qpe);
	md->s_hd = md->s_tl = 0;

	if (!md->ah || !md->rbuf || !md->sbuf || !md->ports)
		goto bail;

	(void)memset(md->ah, 0, (sizeof(struct ibv_ah *) * 0xffff));
	(void)memset(md->ports, 0, (sizeof(uint64_t) * MCM_PORT_SPACE));
	md->ports[0] = 1; /* resv slot 0, 0 == no ports available */
	(void)memset(md->rbuf, 0, ((mlen + sizeof(struct ibv_grh)) * md->qpe));
	(void)memset(md->sbuf, 0, (mlen * md->qpe));

	md->mr_sbuf = ibv_reg_mr(md->pd, md->sbuf,
				 (mlen * md->qpe),
				 IBV_ACCESS_LOCAL_WRITE);
	if (!md->mr_sbuf)
		goto bail;

	md->mr_rbuf = ibv_reg_mr(md->pd, md->rbuf,
				 (mlen + sizeof(struct ibv_grh)) * md->qpe,
				 IBV_ACCESS_LOCAL_WRITE);
	if (!md->mr_rbuf)
		goto bail;

	/* modify UD QP: init, rtr, rts */
	if ((modify_ud_qp(md, md->qp)) != DAT_SUCCESS)
		goto bail;

	/* post receive buffers, setup head, tail pointers */
	recv_wr.next = NULL;
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;
	sge.length = mlen + sizeof(struct ibv_grh);
	sge.lkey = md->mr_rbuf->lkey;
	rbuf = (char*)md->rbuf;

	for (i = 0; i < md->qpe; i++) {
		recv_wr.wr_id = (uintptr_t) (rbuf + sizeof(struct ibv_grh));
		sge.addr = (uintptr_t) rbuf;
		errno = 0;
		if (ibv_post_recv(md->qp, &recv_wr, &recv_err))
			goto bail;
		rbuf += (mlen + sizeof(struct ibv_grh));
	}

	/* save qp_num as part of ia_address, network order */
	md->addr.qpn = htonl(md->qp->qp_num);

	mlog(0, " IB LID %x (%x) PORT %d GID %s QPN %x: mic%d -> %s - %s, mic_ver %d %s\n",
		ntohs(md->addr.lid), md->m_lid, md->port,
		inet_ntop(AF_INET6, md->addr.gid, gid_str, sizeof(gid_str)),
		md->qp->qp_num, md->mc->scif_id - 1, md->ibdev->name,
		mcm_map_str(md->addr.ep_map), md->mc->ver,
	        md->mc->ver == MIX_COMP ? "WARN: OLD MPSS -> RUN COMP MODE":"");

	return 0;
bail:
	mlog(0, " ERR: MCM UD-CM services: %s\n",strerror(errno));
	return -1;
}

int mcm_modify_qp(struct ibv_qp	*qp_handle,
	      enum ibv_qp_state	qp_state,
	      uint32_t		qpn,
	      uint16_t		lid,
	      union ibv_gid	*gid)
{
	struct ibv_qp_attr qp_attr;
	enum ibv_qp_attr_mask mask = IBV_QP_STATE;
	mcm_qp_t *m_qp;
	int ret;

	if (!qp_handle) {
		mlog(1, "WARNING: qp_handle==NULL\n");
		return EINVAL;
	}

	m_qp = (mcm_qp_t *)qp_handle->qp_context;

	memset((void *)&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = qp_state;

	switch (qp_state) {
	case IBV_QPS_RTR:
		mask |= IBV_QP_AV |
			IBV_QP_PATH_MTU |
			IBV_QP_DEST_QPN |
			IBV_QP_RQ_PSN |
			IBV_QP_MIN_RNR_TIMER |
			IBV_QP_MAX_DEST_RD_ATOMIC;

		qp_attr.dest_qp_num = ntohl(qpn);
		qp_attr.rq_psn = 1;
		qp_attr.path_mtu = m_qp->mtu ?
				   min(m_qp->mtu, m_qp->smd->dev_attr.mtu):
				   m_qp->smd->dev_attr.mtu;
		qp_attr.max_dest_rd_atomic = 16;
		qp_attr.min_rnr_timer = m_qp->smd->dev_attr.rnr_timer;
		qp_attr.ah_attr.dlid = ntohs(lid);
		if (gid && m_qp->smd->dev_attr.global) {
			mlog(1," Global Routing: GID %s \n",
			     inet_ntop(AF_INET6, gid, gid_str, sizeof(gid_str)));
			qp_attr.ah_attr.is_global = 1;
			qp_attr.ah_attr.grh.dgid.global.subnet_prefix =
				gid->global.subnet_prefix;
			qp_attr.ah_attr.grh.dgid.global.interface_id =
				gid->global.interface_id;
			qp_attr.ah_attr.grh.hop_limit =
				m_qp->smd->dev_attr.hop_limit;
			qp_attr.ah_attr.grh.traffic_class =
				m_qp->smd->dev_attr.tclass;
		}
		qp_attr.ah_attr.sl = m_qp->smd->dev_attr.sl;
		qp_attr.ah_attr.src_path_bits = 0;
		qp_attr.ah_attr.port_num = m_qp->smd->md->port;

		mlog(8,	" QPS_RTR: l_qpn %x type %d r_qpn 0x%x gid %p (%d) lid 0x%x"
			" port %d qp %p qp_state %d rd_atomic %d rnr_timer %d\n",
			qp_handle->qp_num, qp_handle->qp_type,
			ntohl(qpn), gid, m_qp->smd->dev_attr.global,
			ntohs(lid), m_qp->smd->md->port, qp_handle,
			qp_handle->state, qp_attr.max_dest_rd_atomic,
			qp_attr.min_rnr_timer);
		break;

	case IBV_QPS_RTS:
		mask |= IBV_QP_SQ_PSN |
			IBV_QP_TIMEOUT |
			IBV_QP_RETRY_CNT |
			IBV_QP_RNR_RETRY |
			IBV_QP_MAX_QP_RD_ATOMIC;
		qp_attr.sq_psn = 1;
		qp_attr.timeout = m_qp->smd->dev_attr.ack_timer;
		qp_attr.retry_cnt = m_qp->smd->dev_attr.ack_retry;
		qp_attr.rnr_retry = m_qp->smd->dev_attr.rnr_retry;
		qp_attr.max_rd_atomic = 16;

		mlog(8,	" QPS_RTS: psn %x rd_atomic %d ack %d "
			" retry %d rnr_retry %d qpn %x qp_state %d\n",
			qp_attr.sq_psn, qp_attr.max_rd_atomic,
			qp_attr.timeout, qp_attr.retry_cnt,
			qp_attr.rnr_retry, qp_handle->qp_num,
			qp_handle->state);
		break;

	case IBV_QPS_INIT:
		mask |= IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
		qp_attr.qp_access_flags =
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_ATOMIC |
				IBV_ACCESS_MW_BIND;
		qp_attr.pkey_index = m_qp->smd->dev_attr.pkey_idx;
		qp_attr.port_num = m_qp->smd->md->port;
		qp_attr.qkey = 0;

		mlog(8,	" QPS_INIT: pi %x port %x acc %x qkey 0x%x\n",
			qp_attr.pkey_index, qp_attr.port_num,
			qp_attr.qp_access_flags, qp_attr.qkey);
		break;

	default:
		break;
	}

	ret = ibv_modify_qp(qp_handle, &qp_attr, mask);
	if (ret == 0) {
		m_qp->qp_attr2.cur_state = m_qp->qp_attr2.state = qp_state;
	} else {
		switch (qp_state) {
			case IBV_QPS_RTR:
				mlog(0,	" QPS_RTR: ERR %s l_qpn %x type %d r_qpn 0x%x gid %p (%d) lid 0x%x"
					" port %d ep %p qp_state %d \n",
					strerror(ret), qp_handle->qp_num, qp_handle->qp_type,
					ntohl(qpn), gid, m_qp->smd->dev_attr.global,
					ntohs(lid), m_qp->smd->md->port, m_qp, m_qp->qp_attr2.cur_state);
				break;
			case IBV_QPS_RTS:
				mlog(0,	" QPS_RTS: ERR %s psn %x rd_atomic %d ack %d "
					" retry %d rnr_retry %d qpn %x qp_state %d\n",
					strerror(ret), qp_attr.sq_psn, qp_attr.max_rd_atomic,
					qp_attr.timeout, qp_attr.retry_cnt,
					qp_attr.rnr_retry, m_qp->ib_qp2->qp_num,
					m_qp->qp_attr2.cur_state);
				break;
			case IBV_QPS_INIT:
				mlog(0,	" QPS_INIT: ERR %s pi %x port %x acc %x qkey 0x%x\n",
					strerror(ret), qp_attr.pkey_index, qp_attr.port_num,
					qp_attr.qp_access_flags, qp_attr.qkey);
				break;

			default:
				mlog(0,	" ERR (%s): l_qpn %x type %d qpn 0x%x lid 0x%x"
					" port %d state %s->%s mtu %d rd %d rnr %d sl %d\n",
					strerror(ret), qp_handle->qp_num, qp_handle->qp_type,
					ntohl(qpn), ntohs(lid), m_qp->smd->md->port,
					mcm_qp_state_str(m_qp->qp_attr2.cur_state),
					mcm_qp_state_str(qp_state), qp_attr.path_mtu,
					qp_attr.max_dest_rd_atomic, qp_attr.min_rnr_timer,
					qp_attr.ah_attr.sl);
				break;
		}
	}
	return ret;
}

/* move QP's to error state. Flush the proxy SR queue is exists */
void mcm_flush_qp(struct mcm_qp *m_qp)
{
	struct mcm_sr *m_sr;
	struct dat_mix_wc wc;

	mlog(2, " QP1 %p QP2 %p\n", m_qp->ib_qp1, m_qp->ib_qp2);

	if (m_qp->ib_qp1)
		mcm_modify_qp(m_qp->ib_qp1, IBV_QPS_ERR, 0, 0, NULL);

	if (m_qp->ib_qp2)
		mcm_modify_qp(m_qp->ib_qp2, IBV_QPS_ERR, 0, 0, NULL);

	mpxy_lock(&m_qp->rxlock);
	while (m_qp->sr_tl != m_qp->sr_hd) {
		m_sr = (struct mcm_sr *)(m_qp->sr_buf + (m_qp->sr_sz * m_qp->sr_tl));
		if (m_sr->wr_id) {
			mlog(2, " QP %p SR[%d] %p wr_id %Lx dto_event -> IBV_WC_FLUSH\n",
				m_qp, m_sr->s_idx, m_sr, m_sr->wr_id);
			wc.wr_id = m_sr->wr_id;
			wc.imm_data = 0;
			wc.byte_len = 0;
			wc.status = IBV_WC_WR_FLUSH_ERR;
			wc.opcode =  IBV_WC_RECV;
			wc.vendor_err = 0;
			mix_dto_event(m_qp->m_cq_rx, &wc, 1);
			m_sr->wr_id = 0; /* free posted SR slot */
		}
		if (++m_qp->sr_tl == m_qp->sr_end) /* move tail */
			m_qp->sr_tl = 0;
	}
	mpxy_unlock(&m_qp->rxlock);
}

/* MCM Endpoint CM objects */
void m_cm_free(mcm_cm_t *cm)
{
	mlog(2, "CM %p free: qp %p ref_cnt %d state %s sid %x\n",
		cm, cm->m_qp, cm->ref_cnt,
		mcm_state_str(cm->state), cm->sid);

	mpxy_lock(&cm->lock);
	if (cm->state != MCM_DESTROY) {
		cm->ref_cnt--; /* alloc ref */
		cm->state = MCM_DESTROY;
	}

	/* client, release local conn id port */
	if (!cm->l_ep && cm->sid) {
		mpxy_lock(&cm->md->plock);
		mcm_free_port(cm->md->ports, cm->sid);
		cm->sid = 0;
		mpxy_unlock(&cm->md->plock);
	}
	/* last reference, destroy */
	if (!cm->ref_cnt) {
		mpxy_unlock(&cm->lock);
		mpxy_lock_destroy(&cm->lock);
		cm->smd->ref_cnt--;
		free(cm);
	} else
		mpxy_unlock(&cm->lock);
}

mcm_cm_t *m_cm_create(mcm_scif_dev_t *smd, mcm_qp_t *m_qp, dat_mcm_addr_t *r_addr)
{
	mcm_cm_t *cm;
	dat_mcm_addr_t *l_addr = &smd->md->addr;

	/* Allocate CM, init lock, and initialize */
	if ((cm = malloc(sizeof(*cm))) == NULL) {
		mlog(0, "failed to allocate cm: %s\n", strerror(errno));
		return NULL;
	}

	memset(cm, 0, sizeof(*cm));

	init_list(&cm->entry);
	if (mpxy_lock_init(&cm->lock, NULL))
		goto bail;

	cm->ref_cnt++; /* alloc ref */
	cm->state = MCM_INIT;
	cm->smd = smd;
	cm->md = smd->md;
	cm->msg.ver = htons(DAT_MCM_VER);
	cm->msg.sqpn = smd->md->addr.qpn; /* ucm, in network order */
	cm->msg.seg_sz = mix_buffer_sg_po2;
#ifdef MPXYD_LOCAL_SUPPORT
	cm->msg.sys_guid = system_guid; /* network order */
#else
	cm->msg.sys_guid = rand(); /* send local guid */
#endif

	/* ACTIVE: init source address QP info from MPXYD and MIC client */
	if (m_qp) {
		mpxy_lock(&smd->md->plock);
		cm->sid = mcm_get_port(smd->md->ports, 0, (uint64_t)cm);
		mpxy_unlock(&smd->md->plock);
		cm->msg.sport = htons(cm->sid);
		if (!cm->msg.sport) {
			mpxy_lock_destroy(&cm->lock);
			goto bail;
		}
		cm->ref_cnt++; /* Active: QP ref */
		cm->m_qp = m_qp;
		m_qp->cm = cm;

		/* MPXYD SRC IB info, QP2t = saddr2 all cases */
		cm->msg.saddr2.qpn = htonl(m_qp->ib_qp2->qp_num);
		cm->msg.saddr2.qp_type = m_qp->qp_attr2.qp_type;
		cm->msg.saddr2.ep_map = smd->md->addr.ep_map;

                /* MPXYD RCV IB info */
                cm->msg.saddr1.ep_map = smd->md->addr.ep_map;

		/* intra-node: QPt addr 2 - ibscif HST lid != MICx lid's */
		if (smd->md->m_lid) {
			cm->msg.saddr1.lid = smd->md->m_lid;
			cm->msg.saddr2.lid = smd->md->addr.lid;
			memcpy(&cm->msg.saddr1.gid[0], &smd->md->m_gid, 16);
			memcpy(&cm->msg.saddr2.gid[0], &smd->md->addr.gid, 16);
		} else {
			cm->msg.saddr1.lid = smd->md->lid;
			cm->msg.saddr2.lid = smd->md->lid;
			memcpy(&cm->msg.saddr1.gid[0], &smd->md->addr.gid, 16);
			memcpy(&cm->msg.saddr2.gid[0], &smd->md->addr.gid, 16);
		}

                /* MSS, QPr is on MIC, QP1r == saddr1 */
	        if (MSS_EP(l_addr)) {
			cm->msg.saddr1.qpn = htonl(cm->m_qp->qp_attr1.qp_num);
			cm->msg.saddr1.qp_type = cm->m_qp->qp_attr1.qp_type;

			/* MSS_EP -> (MXS or unknown) WC queue for MXS peer PI service */
			if (MXF_EP(r_addr) || UND_EP(r_addr)) {
				if (m_pi_create_wc_q(m_qp, mcm_rx_entries))
					goto bail;
			}
	        }

        	/* MXS -> (MSS, HOST, or unknown), need a QPr on mpxyd, QP1r == saddr1 */
                if (MXF_EP(l_addr) && !MXF_EP(r_addr)) {
                	/* note: pi_wr_q and pi_wc_q created via MXS create_qp */
                	if (m_qp_create_pi(smd, m_qp))
                		goto bail;
                	cm->msg.saddr1.qpn = htonl(m_qp->ib_qp1->qp_num);
                	cm->msg.saddr1.qp_type = m_qp->qp_attr1.qp_type;
                }

                /* MXS -> MXS, QPs and QPr is QP2 on mpxyd, saddr 1 == saddr2 */
                if (MXF_EP(l_addr) && MXF_EP(r_addr))
                	memcpy(&cm->msg.saddr1, &cm->msg.saddr2, sizeof(dat_mcm_addr_t));

		mlog(8, " SRC: QPt qpn 0x%x lid 0x%x, QPr qpn 0x%x lid 0x%x"
			" CM: qpn 0x%x port=0x%x %s\n",
			cm->m_qp->qp_attr2.qp_num, ntohs(cm->msg.saddr2.lid),
			cm->msg.saddr1.qpn ?
			cm->m_qp->qp_attr1.qp_num:cm->m_qp->qp_attr2.qp_num,
			cm->msg.saddr1.qpn ?
			ntohs(cm->msg.saddr1.lid):ntohs(cm->msg.saddr2.lid),
			ntohl(cm->msg.sqpn), ntohs(cm->msg.sport),
			mcm_map_str(cm->msg.saddr2.ep_map));
        }
	cm->smd->ref_cnt++;
	return cm;
bail:
	free(cm);
	return NULL;
}

/* queue up connection object on CM list */
void mcm_qconn(mcm_scif_dev_t *smd, mcm_cm_t *cm)
{
	mpxy_lock(&cm->lock);
	cm->ref_cnt++; /* clist ref */
	mpxy_unlock(&cm->lock);

	/* add to CONN work queue, list, for mcm fabric CM */
	mpxy_lock(&smd->clock);
	insert_tail(&cm->entry, &smd->clist, (void *)cm);
	mpxy_unlock(&smd->clock);
}
/* dequeue connection object from CM list */
void mcm_dqconn_free(mcm_scif_dev_t *smd, mcm_cm_t *cm)
{
	/* Remove from work queue, cr thread processing */
	if (cm->entry.tid) {
		mpxy_lock(&smd->clock);
		remove_entry(&cm->entry);
		mpxy_unlock(&smd->clock);

		mpxy_lock(&cm->lock);
		cm->ref_cnt--; /* clist ref */
		mpxy_unlock(&cm->lock);
	}
	m_cm_free(cm);
}

/* queue listen object on listen list */
void mcm_qlisten(mcm_scif_dev_t *smd, mcm_cm_t *cm)
{
	mpxy_lock(&cm->lock);
	cm->ref_cnt++; /* llist ref */
	mpxy_unlock(&cm->lock);

	/* add to LISTEN work queue, list, for mcm fabric CM */
	mpxy_lock(&smd->llock);
	insert_tail(&cm->entry, &smd->llist, (void *)cm);
	mpxy_unlock(&smd->llock);
}
/* dequeue listen object from listen list */
void mcm_dqlisten_free(mcm_scif_dev_t *smd, mcm_cm_t *cm)
{
	if (cm->entry.tid) {
		mpxy_lock(&smd->llock);
		remove_entry(&cm->entry);
		mpxy_unlock(&smd->llock);

		mpxy_lock(&smd->md->plock);
		mcm_free_port(smd->md->ports, cm->sid);
		cm->sid = 0;
		mpxy_unlock(&smd->md->plock);

		mpxy_lock(&cm->lock);
		cm->ref_cnt--; /* llist ref */
		mpxy_unlock(&cm->lock);
	}
	m_cm_free(cm);
}

/*
 *
 * Fabric side MCM messages, IB UD QP
 *
 */

/*  IB async device event */
int mcm_ib_async_event(struct mcm_ib_dev *md)
{
	struct ibv_async_event event;
	int status = 0;

	if (!ibv_get_async_event(md->ibctx, &event)) {
		switch (event.event_type) {
		case IBV_EVENT_CQ_ERR:
			mlog(0, "IBV_EVENT_CQ_ERR: ctx(%p) \n",
			     event.element.cq->cq_context);
			break;
		case IBV_EVENT_COMM_EST:
			mlog(0, "IBV_EVENT_COMM_EST ERR: (QP=%p) rdata beat RTU\n",
				event.element.qp);
			break;
		case IBV_EVENT_QP_FATAL:
		case IBV_EVENT_QP_REQ_ERR:
		case IBV_EVENT_QP_ACCESS_ERR:
		case IBV_EVENT_QP_LAST_WQE_REACHED:
		case IBV_EVENT_SRQ_ERR:
		case IBV_EVENT_SRQ_LIMIT_REACHED:
		case IBV_EVENT_SQ_DRAINED:
			mlog(0, "%s ERR: QP (%p)\n",
				mcm_ib_async_str(event.event_type),
				event.element.qp->qp_context);
			break;
		case IBV_EVENT_PATH_MIG:
		case IBV_EVENT_PATH_MIG_ERR:
		case IBV_EVENT_DEVICE_FATAL:
		case IBV_EVENT_PORT_ERR:
		case IBV_EVENT_LID_CHANGE:
		case IBV_EVENT_PKEY_CHANGE:
		case IBV_EVENT_SM_CHANGE:
			mlog(0, "%s ERR: shutting down device %s, closing all active clients\n",
				mcm_ib_async_str(event.event_type), md->ibdev->name);
			status = -1;
			break;
		case IBV_EVENT_PORT_ACTIVE:
			mlog(0, "%s\n", mcm_ib_async_str(event.event_type));
			break;
		case IBV_EVENT_CLIENT_REREGISTER:
			mlog(0, "%s\n", mcm_ib_async_str(event.event_type));
			break;
		default:
			mlog(0, "ERR: IBV async event %d UNKNOWN\n", event.event_type);
			break;
		}
		ibv_ack_async_event(&event);
	}
	/* no need to send event to MIX client, it has same IB device opened */
	return status;
}

/* Get CM UD message from send queue, called with s_lock held */
static dat_mcm_msg_t *mcm_get_smsg(mcm_ib_dev_t *md)
{
	dat_mcm_msg_t *msg = NULL;
	int ret, polled = 1, hd = md->s_hd;

	hd++;
	if (hd == md->qpe)
		hd = 0;
retry:
	if (hd == md->s_tl) {
		msg = NULL;
		if (polled % 1000000 == 0)
			mlog(1,	 " ucm_get_smsg: FULLq hd %d == tl %d,"
				 " completions stalled, polls=%d\n",
				 hd, md->s_tl, polled);
	}
	else {
		msg = &md->sbuf[hd];
		md->s_hd = hd; /* new hd */
	}

	/* if empty, process some completions */
	if (msg == NULL) {
		struct ibv_wc wc;

		/* process completions, based on UCM_TX_BURST */
		ret = ibv_poll_cq(md->scq, 1, &wc);
		if (ret < 0) {
			mlog(8, " get_smsg: cq %p %s\n", md->scq, strerror(errno));
			return NULL;
		}
		/* free up completed sends, update tail */
		if (ret > 0)
			md->s_tl = (int)wc.wr_id;

		polled++;
		MCNTR(md, MCM_CM_TX_POLL);
		goto retry;
	}
	return msg;
}

/* ACTIVE/PASSIVE: build and send CM message out of CM object */
static int mcm_send(mcm_ib_dev_t *md, dat_mcm_msg_t *msg, DAT_PVOID p_data, DAT_COUNT p_size)
{
	dat_mcm_msg_t *smsg = NULL;
	struct ibv_send_wr wr, *bad_wr;
	struct ibv_sge sge;
	int len, ret = -1;
	uint16_t dlid = ntohs(msg->daddr1.lid);

	/* intra-node, CM on host side, HST lid != MIC lid */
	if (md->m_lid)
		dlid = ntohs(md->addr.lid);

	/* Get message from send queue, copy data, and send */
	mpxy_lock(&md->txlock);
	if ((smsg = mcm_get_smsg(md)) == NULL) {
		mlog(0,	" mcm_send ERR: get_smsg(hd=%d,tl=%d) \n",
			md->s_hd, md->s_tl);
		goto bail;
	}

	len = sizeof(dat_mcm_msg_t);
	memcpy(smsg, msg, len);
	if (p_size) {
		smsg->p_size = ntohs(p_size);
		memcpy(&smsg->p_data, p_data, p_size);
	} else
		smsg->p_size = 0;

	wr.next = NULL;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        wr.opcode = IBV_WR_SEND;
        wr.wr_id = (unsigned long)md->s_hd;
	wr.send_flags = (wr.wr_id % md->signal) ? 0 : IBV_SEND_SIGNALED;
	if (md->indata)
		wr.send_flags |= IBV_SEND_INLINE;

        sge.length = len;
        sge.lkey = md->mr_sbuf->lkey;
        sge.addr = (uintptr_t)smsg;

        if (sge.length > (sizeof(dat_mcm_msg_t) + sizeof(struct ibv_grh))) {
        	mlog(0, " ERR: cm_msg too large - %d bytes\n", sge.length);
        	ret = -1;
           	goto bail;
        }

	mlog(8," cm_send: op %s ln %d lid %x c_qpn %x rport %x, p_size %d\n",
		mcm_op_str(ntohs(smsg->op)), sge.length, dlid,
		ntohl(smsg->dqpn), ntohs(smsg->dport), p_size);

	/* empty slot, then create AH */
	if (!md->ah[dlid]) {
		md->ah[dlid] =	mcm_create_ah(md, md->pd, md->qp, dlid, NULL);
		if (!md->ah[dlid]) {
			mlog(0, " ERR: create_ah %s\n", strerror(errno));
			goto bail;
		}
	}

	wr.wr.ud.ah = md->ah[dlid];
	wr.wr.ud.remote_qpn = ntohl(smsg->dqpn);
	wr.wr.ud.remote_qkey = DAT_MCM_UD_QKEY;
	errno = 0;
	ret = ibv_post_send(md->qp, &wr, &bad_wr);
bail:
	if (ret)
		mlog(0, " ERR: ibv_post_send() %s\n", strerror(errno));

	MCNTR(md, MCM_CM_MSG_OUT);
	mpxy_unlock(&md->txlock);
	return ret;
}

static int mcm_post_rmsg(mcm_ib_dev_t *md, dat_mcm_msg_t *msg)
{
	struct ibv_recv_wr recv_wr, *recv_err;
	struct ibv_sge sge;

	msg->ver = 0;
	recv_wr.next = NULL;
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;
	recv_wr.wr_id = (uint64_t)(uintptr_t) msg;
	sge.length = sizeof(dat_mcm_msg_t) + sizeof(struct ibv_grh);
	sge.lkey = md->mr_rbuf->lkey;
	sge.addr = (uintptr_t)((char *)msg - sizeof(struct ibv_grh));
	MCNTR(md, MCM_CM_MSG_POST);
	errno = 0;
	return (ibv_post_recv(md->qp, &recv_wr, &recv_err));
}

int mcm_cm_rej_out(mcm_ib_dev_t *md, dat_mcm_msg_t *msg, DAT_MCM_OP type, int swap)
{
	dat_mcm_msg_t smsg;

	memset(&smsg, 0, sizeof(smsg));
	smsg.ver = htons(DAT_MCM_VER);
	smsg.op = htons(type);

	if (swap) {
		smsg.dport = msg->sport;
		smsg.dqpn = msg->sqpn;
		smsg.sport = msg->dport;
		smsg.sqpn = msg->dqpn;
		memcpy(&smsg.saddr1, &msg->daddr1, sizeof(dat_mcm_addr_t));
		memcpy(&smsg.daddr1, &msg->saddr1, sizeof(dat_mcm_addr_t));
		memcpy(&smsg.saddr2, &msg->daddr2, sizeof(dat_mcm_addr_t));
		memcpy(&smsg.daddr2, &msg->saddr2, sizeof(dat_mcm_addr_t));
	} else {
		smsg.dport = msg->dport;
		smsg.dqpn = msg->dqpn;
		smsg.sport = msg->sport;
		smsg.sqpn = msg->sqpn;
		memcpy(&smsg.daddr1, &msg->daddr1, sizeof(dat_mcm_addr_t));
		memcpy(&smsg.saddr1, &msg->saddr1, sizeof(dat_mcm_addr_t));
		memcpy(&smsg.daddr2, &msg->daddr2, sizeof(dat_mcm_addr_t));
		memcpy(&smsg.saddr2, &msg->saddr2, sizeof(dat_mcm_addr_t));
	}

	/* intra-node; addr1 == mic lid, addr2 == cm lid */
	if (md->m_lid) {
		smsg.saddr1.lid = md->m_lid;
		memcpy(&smsg.saddr1.gid[0], &md->m_gid, 16);
	}
	smsg.saddr2.lid = md->addr.lid;
	memcpy(&smsg.saddr2.gid[0], &md->addr.gid, 16);

	mlog(2," sLID %x, sQPN %x sPORT %x -> dLID %x, dQPN %x dPORT %x\n",
	     ntohs(smsg.saddr2.lid), ntohl(smsg.sqpn), ntohs(smsg.sport),
	     ntohs(smsg.daddr2.lid), ntohl(smsg.dqpn), ntohs(smsg.dport));

	if (type == MCM_REJ_USER)
		MCNTR(md, MCM_CM_REJ_USER_OUT);
	else
		MCNTR(md, MCM_CM_REJ_OUT);

	return (mcm_send(md, &smsg, NULL, 0));
}

int mcm_qp_busy(struct mcm_qp *m_qp)
{
	int busy = 0;

	mpxy_lock(&m_qp->rxlock);
	busy += (m_qp->pi_rw_cnt + m_qp->pi_rr_cnt);
	busy += (m_qp->stall_cnt_rr + m_qp->post_cnt_wt);
	mpxy_unlock(&m_qp->rxlock);
	mlog(2," PI[%d]: rw_cnt %d rr_cnt %d stall %d post %d\n",
	     busy, m_qp->pi_rw_cnt, m_qp->pi_rr_cnt,
	     m_qp->stall_cnt_rr, m_qp->post_cnt_wt);

	mpxy_lock(&m_qp->txlock);
	busy += (m_qp->wr_pp + m_qp->wr_pp_rem);
	busy += (m_qp->post_sig_cnt - m_qp->comp_cnt);
	mpxy_unlock(&m_qp->txlock);
	mlog(2," PO[%d]: wr_pp %d pp_rem %d pst_sig %d cmp_sig %d\n",
	     busy, m_qp->wr_pp, m_qp->wr_pp_rem,
	     m_qp->post_sig_cnt, m_qp->comp_cnt);

	return busy;
}

void mcm_cm_disc(mcm_cm_t *cm)
{
	int finalize = 1;

	mpxy_lock(&cm->lock);
	mlog(2," enter: state = %s \n",  mcm_state_str(cm->state));
	switch (cm->state) {
	case MCM_CONNECTED:
		/* CONSUMER: move to err state to flush */
		if (cm->m_qp && !mcm_qp_busy(cm->m_qp))
			mcm_flush_qp(cm->m_qp);

		/* send DREQ, event after DREP or DREQ timeout */
		cm->state = MCM_DISC_PENDING;
		cm->msg.op = htons(MCM_DREQ);
		cm->retries = 0;
		finalize = 0; /* wait for DREP */
		mlog(2,	" DREQ_out (%d): cm_id %d %x %x %x -> %x %x %x\n",
			cm->retries+1, cm->entry.tid,
			htons(cm->msg.saddr1.lid),htonl(cm->msg.saddr1.qpn),
			htons(cm->msg.sport),htons(cm->msg.daddr1.lid),
			htonl(cm->msg.dqpn), htons(cm->msg.dport));
		MCNTR(cm->md, MCM_CM_DREQ_OUT);
		break;
	case MCM_DISC_PENDING:
		/* DREQ timeout, retry */
		if (cm->retries > mcm_disc_retry) {
			mlog(0,	" DISC: RETRIES EXHAUSTED:"
				" %x %x %x -> %x %x %x\n",
				htons(cm->msg.saddr1.lid),
				htonl(cm->msg.saddr1.qpn),
				htons(cm->msg.sport),
				htons(cm->msg.daddr1.lid),
				htonl(cm->msg.dqpn),
				htons(cm->msg.dport));
			cm->state = MCM_DISCONNECTED;
			goto final;
		}
		cm->msg.op = htons(MCM_DREQ);
		finalize = 0; /* wait for DREP */
		mlog(2,	" DREQ_out (%d): cm_id %d %x %x %x -> %x %x %x\n",
			cm->retries+1, cm->entry.tid,
			htons(cm->msg.saddr1.lid),htonl(cm->msg.saddr1.qpn),
			htons(cm->msg.sport),htons(cm->msg.daddr1.lid),
			htonl(cm->msg.dqpn), htons(cm->msg.dport));
		MCNTR(cm->md, MCM_CM_DREQ_OUT);
		break;
	case MCM_DISC_RECV:
		MCNTR(cm->md, MCM_CM_DREQ_IN);
		/* CM_THREAD: move to err state to flush */
		if (cm->m_qp && !mcm_qp_busy(cm->m_qp))
			mcm_flush_qp(cm->m_qp);

		/* DREQ received, send DREP and schedule event, finalize */
		cm->msg.op = htons(MCM_DREP);
		cm->state = MCM_DISCONNECTED;
		mlog(2,	" DREQ_in: cm_id %d send DREP %x %x %x -> %x %x %x\n",
			cm->entry.tid, htons(cm->msg.saddr1.lid),htonl(cm->msg.saddr1.qpn),
			htons(cm->msg.sport),htons(cm->msg.daddr1.lid),
			htonl(cm->msg.dqpn), htons(cm->msg.dport));
		MCNTR(cm->md, MCM_CM_DREP_OUT);
		break;
	case MCM_DISCONNECTED:
		mlog(2," state = %s already disconnected\n",  mcm_state_str(cm->state) );
		if (cm->m_qp) /* MIC client disc, force flush */
			mcm_flush_qp(cm->m_qp);
		mpxy_unlock(&cm->lock);
		MCNTR(cm->md, MCM_CM_DREQ_DUP);
		return;
	default:
		MCNTR(cm->md, MCM_CM_ERR_UNEXPECTED_STATE);
		mlog(1, "  disconnect UNKNOWN state: qp %p cm %p %s %s"
			"  %x %x %x %s %x %x %x r_id %x l_id %x\n",
			cm->m_qp, cm, cm->msg.saddr1.qp_type == IBV_QPT_RC ? "RC" : "UD",
			mcm_state_str(cm->state),ntohs(cm->msg.saddr1.lid),
			ntohs(cm->msg.sport), ntohl(cm->msg.saddr1.qpn),
			cm->l_ep ? "<-" : "->", ntohs(cm->msg.daddr1.lid),
			ntohs(cm->msg.dport), ntohl(cm->msg.daddr1.qpn),
			ntohl(cm->msg.d_id), ntohl(cm->msg.s_id));
		mpxy_unlock(&cm->lock);
		return;
	}

	cm->timer = mcm_time_us(); /* DREQ, expect reply */
	mcm_send(cm->md, &cm->msg, NULL, 0);
final:
	mpxy_unlock(&cm->lock);
	if (finalize) {
		MCNTR(cm->md, MCM_CM_DISC_EVENT);
		mix_cm_event(cm, DAT_CONNECTION_EVENT_DISCONNECTED);
	}
}

int mcm_cm_rep_out(mcm_cm_t *cm)
{
	mpxy_lock(&cm->lock);
	if (cm->state != MCM_RTU_PENDING) {
		mlog(1,	 " CM_REPLY: wrong state qp %p cm %p %s refs=%d"
			 " %x %x i_%x -> %x %x i_%x l_pid %x r_pid %x\n",
			 cm->m_qp, cm, mcm_state_str(cm->state),
			 cm->ref_cnt,
			 htons(cm->msg.saddr1.lid),
			 htons(cm->msg.sport),
			 htonl(cm->msg.saddr1.qpn),
			 htons(cm->msg.daddr1.lid),
			 htons(cm->msg.dport),
			 htonl(cm->msg.daddr1.qpn),
			 ntohl(cm->msg.s_id),
			 ntohl(cm->msg.d_id));
		mpxy_unlock(&cm->lock);
		return -1;
	}

	if (cm->retries == cm->md->retries) {
		mlog(0,	" CM_REPLY: RETRIES (%d) EXHAUSTED (lid port qpn)"
			 " %x %x %x -> %x %x %x\n",
			 cm->retries, htons(cm->msg.saddr1.lid),
			 htons(cm->msg.sport),
			 htonl(cm->msg.saddr1.qpn),
			 htons(cm->msg.daddr1.lid),
			 htons(cm->msg.dport),
			 htonl(cm->msg.daddr1.qpn));

		mpxy_unlock(&cm->lock);
		MCNTR(cm->md, MCM_CM_TIMEOUT_EVENT);
		mix_cm_event(cm, DAT_CONNECTION_EVENT_TIMED_OUT);
		return -1;
	}
	MCNTR(cm->md, MCM_CM_REP_OUT);
	cm->timer = mcm_time_us(); /* RTU expected */
	if (mcm_send(cm->md, &cm->msg, cm->p_data, cm->p_size)) {
		mlog(0," accept ERR: mcm reply send()\n");
		mpxy_unlock(&cm->lock);
		return -1;
	}
	mpxy_unlock(&cm->lock);
	return 0;
}

static void mcm_process_recv(mcm_ib_dev_t *md, dat_mcm_msg_t *msg, mcm_cm_t *cm, int len)
{
	mlog(2, " cm %p cm_id %d state %s cm->m_qp %p\n",
		cm, cm->entry.tid, mcm_state_str(cm->state), cm->m_qp);
	mpxy_lock(&cm->lock);
	switch (cm->state) {
	case MCM_LISTEN: /* passive */
		mlog(2, "LISTEN: req_in: dev_id %d l_cm %p, sid %d,0x%x\n",
			 cm->smd->entry.tid, cm, cm->sid, cm->sid);
		mpxy_unlock(&cm->lock);
		MCNTR(md, MCM_CM_REQ_IN);
		mix_cm_req_in(cm, msg, len);
		break;
	case MCM_RTU_PENDING: /* passive */
		mlog(2, "RTU_PENDING: cm %p, my_id %d, cm_id %d\n",
			cm, cm->entry.tid, cm->cm_id);
		mpxy_unlock(&cm->lock);
		MCNTR(md, MCM_CM_RTU_IN);
		mix_cm_rtu_in(cm, msg, len);
		break;
	case MCM_REP_PENDING: /* active */
		mlog(2, "REP_PENDING: cm %p, my_id %d, cm_id %d\n",
			cm, cm->entry.tid, cm->cm_id);
		mpxy_unlock(&cm->lock);
		if (ntohs(msg->op) == MCM_REP)
			mix_cm_rep_in(cm, msg, len);
		else
			mix_cm_rej_in(cm, msg, len);
		break;
	case MCM_REP_RCV: /* active */
		if (ntohs(msg->op) == MCM_REP) {
			mlog(2, "REP_RCV: DUPLICATE cm %p, my_id %d, cm_id %d\n",
				cm, cm->entry.tid, cm->cm_id);
			MCNTR(md, MCM_CM_ERR_REP_DUP);
		}
		mpxy_unlock(&cm->lock);
		break;
	case MCM_CONNECTED: /* active and passive */
		/* DREQ, change state and process */
		if (ntohs(msg->op) == MCM_DREQ) {
			mlog(2, "DREQ_in: cm %p, cm_id %d\n", cm, cm->entry.tid);
			cm->state = MCM_DISC_RECV;
			mpxy_unlock(&cm->lock);
			mcm_cm_disc(cm);
			break;
		}
		/* active: RTU was dropped, resend */
		if (ntohs(msg->op) == MCM_REP) {
			mlog(2,	 " REP_in resend RTU: op %s st %s [lid, port, cqp, iqp]:"
				 " %x %x %x %x -> %x %x %x %x r_pid %x\n",
				  mcm_op_str(ntohs(cm->msg.op)),
				  mcm_state_str(cm->state),
				 ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
				 ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn),
				 ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
				 ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn),
				 ntohl(cm->msg.d_id));
			MCNTR(md, MCM_CM_REP_IN);
			cm->msg.op = htons(MCM_RTU);
			mcm_send(cm->smd->md, &cm->msg, NULL, 0);
		}
		mpxy_unlock(&cm->lock);
		break;
	case MCM_DISC_PENDING: /* active and passive */
		MCNTR(md, MCM_CM_DREP_IN);
		MCNTR(md, MCM_CM_DISC_EVENT);
		cm->state = MCM_DISCONNECTED;
		mpxy_unlock(&cm->lock);
		mix_cm_event(cm, DAT_CONNECTION_EVENT_DISCONNECTED);
		break;
	case MCM_DISCONNECTED:
	case MCM_FREE:
	case MCM_DESTROY:
		/* DREQ dropped, resend */
		if (ntohs(msg->op) == MCM_DREQ) {
			MCNTR(md, MCM_CM_DREQ_DUP);
			mlog(2,	" DREQ_in resend DREP: cm_id %d op %s st %s [lid, port, qpn]:"
				" %x %x %x -> %x %x %x\n",
				cm->entry.tid, mcm_op_str(ntohs(msg->op)),
				mcm_state_str(cm->state),
				ntohs(cm->msg.saddr1.lid),
				ntohs(cm->msg.sport),
				ntohl(cm->msg.saddr1.qpn),
				ntohs(cm->msg.daddr1.lid),
				ntohs(cm->msg.dport),
				ntohl(cm->msg.daddr1.qpn));
			MCNTR(md, MCM_CM_DREP_OUT);
			cm->msg.op = htons(MCM_DREP);
			mcm_send(cm->smd->md, &cm->msg, NULL, 0);

		} else if (ntohs(msg->op) != MCM_DREP){
			/* DREP ok to ignore, any other print warning */
			mlog(2,	" mcm_recv: UNEXPECTED MSG on cm %p"
				" <- op %s, st %s spsp %x sqpn %x\n",
				cm, mcm_op_str(ntohs(msg->op)),
				mcm_state_str(cm->state),
				ntohs(msg->sport), ntohl(msg->sqpn));
			MCNTR(cm->md, MCM_CM_ERR_UNEXPECTED_MSG);
		}
		mpxy_unlock(&cm->lock);
		break;
	case MCM_REJECTED:
		if (ntohs(msg->op) == MCM_REJ_USER) {
			mpxy_unlock(&cm->lock);
			MCNTR(md, MCM_CM_REJ_USER_IN);
			break;
		}
	default:
		mlog(2, " mcm_recv: Warning, UNKNOWN state"
			" <- op %s, %s spsp %x sqpn %x slid %x\n",
			mcm_op_str(ntohs(msg->op)), mcm_state_str(cm->state),
			ntohs(msg->sport), ntohl(msg->sqpn), ntohs(msg->saddr1.lid));
		MCNTR(md, MCM_CM_ERR_UNEXPECTED_STATE);
		mpxy_unlock(&cm->lock);
		break;
	}
}

void mcm_dump_cm_lists(mcm_scif_dev_t *smd)
{
	mcm_cm_t *cm = NULL, *next;
	LLIST_ENTRY *list;
	mpxy_lock_t *lock;

	mlog(0,	" SMD %p : \n");

	/* listen list*/
	list = &smd->llist;
	lock = &smd->llock;
	mpxy_lock(lock);
	next = get_head_entry(list);
	while (next) {
		cm = next;
		next = get_next_entry(&cm->entry, list);

		mlog(0,	 " CM_LIST %s [lid, port, cqp, iqp, pid]: SRC %x %x %x %x %x DST %x %x %x %x %x\n",
			mcm_state_str(cm->state),
			ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
			ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn), ntohl(cm->msg.s_id),
			ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
			ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn), ntohl(cm->msg.d_id));
	}
	mpxy_unlock(lock);

	/* conn list */
	list = &smd->clist;
	lock = &smd->clock;
	mpxy_lock(lock);
	next = get_head_entry(list);
	while (next) {
		cm = next;
		next = get_next_entry(&cm->entry, list);

		mlog(0,	 " CM_CONN %s [lid, port, cqp, iqp, pid]: SRC %x %x %x %x %x DST %x %x %x %x %x\n",
			mcm_state_str(cm->state),
			ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
			ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn), ntohl(cm->msg.s_id),
			ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
			ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn), ntohl(cm->msg.d_id));
	}
	mpxy_unlock(lock);

}

/* Find matching CM object for this receive message, return CM reference, timer */
mcm_cm_t *mcm_get_smd_cm(mcm_scif_dev_t *smd, dat_mcm_msg_t *msg, int *dup)
{
	mcm_cm_t *cm = NULL, *next, *found = NULL;
	LLIST_ENTRY *list;
	mpxy_lock_t *lock;
	int listenq = 0;

	mlog(8,	" <- SMD %p rmsg(%p): op %s [lid, sid, cQP, QPr, QPt, pid]: "
		"%x %x %x %x %x <- %x %x %x %x %x l_pid %x r_pid %x\n",
		 smd, msg, mcm_op_str(ntohs(msg->op)),
		 ntohs(msg->daddr1.lid), ntohs(msg->dport), ntohl(msg->dqpn),
		 ntohl(msg->daddr1.qpn), ntohl(msg->daddr2.qpn), ntohs(msg->saddr1.lid),
		 ntohs(msg->sport), ntohl(msg->sqpn), ntohl(msg->saddr1.qpn),
		 ntohl(msg->saddr2.qpn), ntohl(msg->s_id), ntohl(msg->d_id));

	/* conn list first, duplicate requests for MCM_REQ */
	list = &smd->clist;
	lock = &smd->clock;
	*dup = 0;

retry_listenq:
	mpxy_lock(lock);
	next = get_head_entry(list);

	while (next) {
		cm = next;
		next = get_next_entry(&cm->entry, list);
		if (cm->state == MCM_DESTROY || cm->state == MCM_FREE)
			continue;

		mlog(8,	 " CM %s [lid, port, cqp, iqp, pid]: SRC %x %x %x %x %x DST %x %x %x %x %x\n",
			mcm_state_str(cm->state),
			ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
			ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn), ntohl(cm->msg.s_id),
			ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
			ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn), ntohl(cm->msg.d_id));

		/* CM sPORT + QPN, match is good enough for listenq */
		if (listenq &&
		    cm->msg.sport == msg->dport &&
		    cm->msg.sqpn == msg->dqpn) {
			found = cm;
			break;
		}
		/* connectq, check src and dst plus id's, check duplicate conn_reqs */
		if (!listenq &&
		    cm->msg.sport == msg->dport && cm->msg.sqpn == msg->dqpn &&
		    cm->msg.dport == msg->sport && cm->msg.dqpn == msg->sqpn &&
		    cm->msg.daddr1.lid == msg->saddr1.lid) {
			if (ntohs(msg->op) != MCM_REQ) {
				found = cm;
				break;
			} else {
				/* duplicate; bail and throw away */
				mpxy_unlock(lock);
				mlog(1,	 " DUPLICATE: cm %p op %s (%s) st %s"
					 " [lid, port, cqp, iqp]:"
					 " %x %x %x %x <- (%x %x %x %x :"
					 " %x %x %x %x) -> %x %x %x %x\n",
					 cm, mcm_op_str(ntohs(msg->op)),
					 mcm_op_str(ntohs(cm->msg.op)),
					 mcm_state_str(cm->state),
					 ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
					 ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn),
					 ntohs(msg->saddr1.lid), ntohs(msg->sport),
					 ntohl(msg->sqpn), ntohl(msg->saddr1.qpn),
					 ntohs(msg->daddr1.lid), ntohs(msg->dport),
					 ntohl(msg->dqpn), ntohl(msg->daddr1.qpn),
					 ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
					 ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn));
				*dup = 1;
				MCNTR(cm->md, MCM_CM_ERR_REQ_DUP);
				if (cm->state == MCM_REJECTED) { /* REJ dropped, resend REJ*/
					mlog(1," DUPLICATE: CM_REQ in: REJECT state, resend CM_REJ %d\n",
						ntohs(cm->msg.op));
					mcm_cm_rej_out(cm->md, &cm->msg, ntohs(cm->msg.op), 1);
				}
				return NULL;
			}
		}
	}
	mpxy_unlock(lock);

	/* no duplicate request on connq, check listenq for new request */
	if (ntohs(msg->op) == MCM_REQ && !listenq && !found) {
		listenq = 1;
		list = &smd->llist;
		lock = &smd->llock;
		goto retry_listenq;
	}

	return found;
}

/* locate CM object for msg, walk all SCIF clients for MD */
mcm_cm_t *mcm_get_cm(mcm_ib_dev_t *md, dat_mcm_msg_t *msg)
{
	mcm_cm_t *cm = NULL;
	mcm_scif_dev_t *smd;
	int dup = 0;

	/* Walk scif device client list */
	mpxy_lock(&md->slock);
	smd = get_head_entry(&md->smd_list);
	while (smd && !smd->destroy) {
		cm = mcm_get_smd_cm(smd, msg, &dup);
		if (cm || dup)
			break;
		smd = get_next_entry(&smd->entry, &md->smd_list);
	}
	mpxy_unlock(&md->slock);

	if (!cm && !dup) {
		mlog(2,	 " %s - op %s [lid, port, cqp, iqp]:"
			 " %x %x %x %x <- %x %x %x %x lpid %x rpid %x\n",
			 ntohs(msg->op) == MCM_REQ ? "NO LISTENER":"NO MATCH",
			 mcm_op_str(ntohs(msg->op)),
			 ntohs(msg->daddr1.lid), ntohs(msg->dport),
			 ntohl(msg->dqpn), ntohl(msg->daddr1.qpn),
			 ntohs(msg->saddr1.lid),
			 ntohs(msg->sport), ntohl(msg->sqpn),
			 ntohl(msg->saddr1.qpn), ntohl(msg->s_id),
			 ntohl(msg->d_id));

		if (ntohs(msg->op) == MCM_REQ)
			mcm_cm_rej_out(md, msg, MCM_REJ_CM, 1);

		if (ntohs(msg->op) == MCM_DREP)
			MCNTR(md, MCM_CM_ERR_DREP_DUP);
#ifdef MCM_DEBUG
		mpxy_lock(&md->slock);
		smd = get_head_entry(&md->smd_list);
		while (smd) {
			mcm_dump_cm_lists(smd);
			smd = get_next_entry(&smd->entry, &md->smd_list);
		}
		mpxy_unlock(&md->slock);
#endif
	}
	return cm;
}

/* Get rmsgs from CM completion queue, 10 at a time */
void mcm_ib_recv(mcm_ib_dev_t *md)
{
	struct ibv_wc wc[10];
	dat_mcm_msg_t *msg;
	mcm_cm_t *cm;
	int i, ret, notify = 0;
	struct ibv_cq *ibv_cq = NULL;

	/* POLLIN on channel FD */
	ret = ibv_get_cq_event(md->rch, &ibv_cq, (void *)&md);
	if (ret == 0) {
		ibv_ack_cq_events(ibv_cq, 1);
	}
retry:
	ret = ibv_poll_cq(md->rcq, 10, wc);
	if (ret <= 0) {
		if (!ret && !notify) {
			ibv_req_notify_cq(md->rcq, 0);
			notify = 1;
			goto retry;
		}
		return;
	} else
		notify = 0;

	MCNTR(md, MCM_CM_RX_POLL);
	for (i = 0; i < ret; i++) {
		msg = (dat_mcm_msg_t*) (uintptr_t) wc[i].wr_id;

		mlog(2, " mcm_recv[%d]: stat=%d op=%s ln=%d id=%p sqp=%x\n",
		     i, wc[i].status, mcm_op_str(ntohs(msg->op)),
		     wc[i].byte_len, (void*)wc[i].wr_id, wc[i].src_qp);

		MCNTR(md, MCM_CM_MSG_IN);

		/* validate CM message, version */
		if (ntohs(msg->ver) != DAT_MCM_VER) {
			mlog(1, " UNKNOWN cm_msg %p, op %s ver %d st %x ln %d\n",
				msg, mcm_op_str(ntohs(msg->op)), ntohs(msg->ver),
				wc[i].status, wc[i].byte_len);
			mcm_post_rmsg(md, msg);
			continue;
		}
		if (!(cm = mcm_get_cm(md, msg))) {
			mlog(2, " NO_MATCH or DUP: post_rmsg %p op %s ver %d st %x ln %d\n",
				msg, mcm_op_str(ntohs(msg->op)), ntohs(msg->ver),
				wc[i].status, wc[i].byte_len);
			mcm_post_rmsg(md, msg);
			continue;
		}

		/* match, process it */
		mcm_process_recv(md, msg, cm, wc[i].byte_len - sizeof(struct ibv_grh));
		mcm_post_rmsg(md, msg);
	}

	/* finished this batch of WC's, poll and rearm */
	goto retry;
}

int mcm_cm_req_out(mcm_cm_t *m_cm)
{
	mcm_pr_addrs(2, &m_cm->msg, m_cm->state, 0);

	mpxy_lock(&m_cm->lock);
	if (m_cm->state != MCM_INIT && m_cm->state != MCM_REP_PENDING)
		goto bail;

	if (m_cm->retries == m_cm->md->retries) {
		mlog(0, " CM_REQ: RETRIES EXHAUSTED: 0x%x %x 0x%x -> 0x%x %x 0x%x\n",
		     htons(m_cm->msg.saddr1.lid), htonl(m_cm->msg.saddr1.qpn), htons(m_cm->msg.sport),
		     htons(m_cm->msg.daddr1.lid), htonl(m_cm->msg.dqpn), htons(m_cm->msg.dport));

		m_cm->state = MCM_FREE;
		mpxy_unlock(&m_cm->lock);
		MCNTR(m_cm->md, MCM_CM_TIMEOUT_EVENT);
		mix_cm_event(m_cm, DAT_CONNECTION_EVENT_TIMED_OUT);
		return -1;
	}

	mlog(8, " m_cm %p guid %Lx state %d, retries %d \n",
		m_cm, ntohll(m_cm->msg.sys_guid), m_cm->state,m_cm->md->retries);

	MCNTR(m_cm->md, MCM_CM_REQ_OUT);
	m_cm->state = MCM_REP_PENDING;
	m_cm->msg.op = htons(MCM_REQ);
	m_cm->timer = mcm_time_us(); /* reset reply timer */
	m_cm->msg.mtu = m_cm->smd->dev_attr.mtu; /* local MTU to peer */

	if (mcm_send(m_cm->md, &m_cm->msg, &m_cm->msg.p_data, ntohs(m_cm->msg.p_size)))
		return -1;

	mpxy_unlock(&m_cm->lock);
	return 0;
bail:
	mpxy_unlock(&m_cm->lock);
	return -1;
}

int mcm_cm_rtu_out(mcm_cm_t *m_cm)
{
	uint64_t r_guid = m_cm->msg.sys_guid;

	MCNTR(m_cm->md, MCM_CM_RTU_OUT);

	mlog(1, "[%d:%d] CONN_EST[%d]: %p 0x%x %x 0x%x %Lx %s -> 0x%x %x 0x%x %Lx %s mtu %d\n",
		m_cm->md->mc->scif_id, m_cm->smd->entry.tid,
		m_cm->md->cntrs ? (uint32_t)((uint64_t *)m_cm->md->cntrs)[MCM_CM_RTU_OUT]:0,
		m_cm, htons(m_cm->msg.saddr2.lid), htonl(m_cm->msg.saddr2.qpn),
		htons(m_cm->msg.sport),	system_guid, mcm_map_str(m_cm->msg.saddr2.ep_map),
		htons(m_cm->msg.daddr1.lid),
		MXF_EP(&m_cm->msg.saddr1) && MXF_EP(&m_cm->msg.daddr1) ?
				htonl(m_cm->msg.daddr2.qpn):htonl(m_cm->msg.daddr1.qpn),
		htons(m_cm->msg.dport), ntohll(r_guid), mcm_map_str(m_cm->msg.daddr1.ep_map),
		m_cm->m_qp->mtu);

	mpxy_lock(&m_cm->lock);
	if (m_cm->state != MCM_REP_RCV) {
		mlog(0, " state %s wrong, s/be REP_RCV\n", mcm_state_str(m_cm->state));
		goto bail;
	}

	m_cm->state = MCM_CONNECTED;
	m_cm->msg.op = htons(MCM_RTU);
	m_cm->timer = mcm_time_us(); /* reset reply timer */
#ifdef MPXYD_LOCAL_SUPPORT
	m_cm->msg.sys_guid = system_guid; /* send local guid */
#else
	m_cm->msg.sys_guid = rand(); /* send local guid */
#endif
	if (mcm_send(m_cm->md, &m_cm->msg, NULL, 0)) {
		m_cm->msg.sys_guid = r_guid;
		goto bail;
	}

	m_cm->msg.sys_guid = r_guid; /* reset to remote guid */
	mpxy_unlock(&m_cm->lock);
	return 0;
bail:
	/* send CM event */
	mpxy_unlock(&m_cm->lock);
	return -1;
}


/* SMD device lock held */
void mcm_check_timers(mcm_scif_dev_t *smd, int *timer)
{
	uint64_t time;
	mcm_cm_t *cm;

	mpxy_lock(&smd->clock);
	cm = get_head_entry(&smd->clist);
	while (cm) {
		mpxy_lock(&cm->lock);
		time = mcm_time_us();
		switch (cm->state) {
		case MCM_REP_PENDING:
			*timer = cm->md->cm_timer;
			/* wait longer each retry */
			if ((time - cm->timer)/1000 > (cm->md->rep_time << cm->retries)) {
				mlog(1,	 " CM_REQ retry %p %d [lid, port, cqp, iqp]:"
					 " %x %x %x %x %s -> %s %x %x %x %x Time %d > %d\n",
					 cm, cm->retries+1,
					 ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
					 ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn),
					 mcm_map_str(cm->msg.saddr1.ep_map),
					 mcm_map_str(cm->msg.daddr1.ep_map),
					 ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
					 ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn),
					 (time - cm->timer)/1000,
					 cm->md->rep_time << cm->retries);
				cm->retries++;
				MCNTR(cm->md, MCM_CM_ERR_REQ_RETRY);
				mpxy_unlock(&cm->lock);
				mcm_cm_req_out(cm);
				mpxy_lock(&cm->lock);
				break;
			}
			break;
		case MCM_RTU_PENDING:
			*timer = cm->md->cm_timer;
			if ((time - cm->timer)/1000 > (cm->md->rtu_time << cm->retries)) {
				mlog(1,	 " CM_REPLY retry %d %s [lid, port, cqp, iqp]:"
					 " %x %x %x %x %s -> %s %x %x %x %x r_pid %x Time %d > %d\n",
					 cm->retries+1,
					 mcm_op_str(ntohs(cm->msg.op)),
					 ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
					 ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn),
					 mcm_map_str(cm->msg.saddr1.ep_map),
					 mcm_map_str(cm->msg.daddr1.ep_map),
					 ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
					 ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn),
					 ntohl(cm->msg.d_id),
					 (time - cm->timer)/1000,
					 cm->md->rtu_time << cm->retries);
				cm->retries++;
				MCNTR(cm->md, MCM_CM_ERR_REP_RETRY);
				mpxy_unlock(&cm->lock);
				mcm_cm_rep_out(cm);
				mpxy_lock(&cm->lock);
				break;
			}
			break;
		case MCM_DISC_PENDING:
			*timer = cm->md->cm_timer;
			if ((time - cm->timer)/1000 > (mcm_dreq_ms << cm->retries)) {
				mlog(1,	 " CM_DREQ retry %d [lid, port, cqp, iqp]:"
					 " %x %x %x %x -> %x %x %x %x r_pid %x Time %d > %d\n",
					 cm->retries+1,
					 ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
					 ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn),
					 ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
					 ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn),
					 ntohl(cm->msg.d_id),
					 (time - cm->timer)/1000,
					 cm->md->rtu_time << cm->retries);
				cm->retries++;
				MCNTR(cm->md, MCM_CM_ERR_DREQ_RETRY);
				mpxy_unlock(&cm->lock);
				mcm_cm_disc(cm);
				mpxy_lock(&cm->lock);
	                        break;
			}
			break;
		default:
			break;
		}
		mpxy_unlock(&cm->lock);
		cm = get_next_entry(&cm->entry, &smd->clist);
	}
	mpxy_unlock(&smd->clock);
}






