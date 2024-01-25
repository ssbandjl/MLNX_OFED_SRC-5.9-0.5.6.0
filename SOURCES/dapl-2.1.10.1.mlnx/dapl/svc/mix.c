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
 * mpxyd service - mix.c
 *
 * 	MIC message exchange (MIX) services via Intel SCI
 * 		operations, resource management
 *
 */
#include "mpxyd.h"

/* scif-rdma cmd and data channel parameters */
int mix_align = 64;
int mix_buffer_sg_cnt = 300;
int mix_cmd_depth = 50;
int mix_cmd_size = 256;
int mix_shared_buffer = 1;
int mix_max_msg_mb = 16;
int mix_inline_threshold = 256;
int mix_eager_completion = 1;
int mcm_ib_inline = MCM_IB_INLINE;
int mcm_rw_signal = 1;
int mcm_rr_signal = 1;
int mcm_rr_max = 40;	/* PO rdma read in-process limit */
int mcm_wr_max = 10; 	/* PO WR batch processing limit */
int mcm_wc_max = 10; 	/* PO-PI poll_cq WC processing limit */
int mcm_tx_entries = MCM_WRC_QLEN; /* power of 2, default = 512 */
int mcm_rx_entries = MCM_WRC_QLEN;
int mcm_rx_cq_size = MCM_WRC_QLEN;
int mcm_tx_cq_size = MCM_WRC_QLEN;
int mcm_buf_wc_size = MCM_WRC_QLEN;

extern int mix_buffer_mb;
extern int mix_buffer_sg_po2;
extern uint64_t system_guid;
extern int mcm_profile;
extern int log_level;
extern int mcm_cpu_family;
extern int mcm_cpu_model;

static void mix_get_prov_attr(mcm_scif_dev_t *smd, dat_mix_prov_attr_t *pr_attr)
{
	memset(pr_attr, 0, sizeof(dat_mix_prov_attr_t));
	memcpy(&pr_attr->dev_attr, &smd->dev_attr, sizeof(dat_mix_dev_attr_t));

	mcm_get_attr(pr_attr);  /* CM attributes */
	pr_attr->max_msg_sz = mix_max_msg_mb * 1024 * 1024;
	pr_attr->max_tx_dtos = mcm_tx_entries;
	pr_attr->max_rx_dtos = mcm_rx_entries;
	pr_attr->max_tx_pool = mix_buffer_mb * 1024 * 1024;
	pr_attr->max_rx_pool = mix_buffer_mb * 1024 * 1024;
	pr_attr->tx_segment_sz = (mix_buffer_sg_po2 << 1);
	pr_attr->rx_segment_sz = (mix_buffer_sg_po2 << 1);
	pr_attr->system_guid = system_guid;
	pr_attr->cpu_model = mcm_cpu_model;
	pr_attr->cpu_family = mcm_cpu_family;
	pr_attr->cap |= DAT_MIX_MMAP_CAP;
}

/* close MCM device, MIC client, md->slock held */
void mix_close_device(mcm_ib_dev_t *md, mcm_scif_dev_t *smd)
{
	int op, tx, ev;
	MCNTR(md, MCM_IA_CLOSE);
	mlog(8, " MIC client: close mdev %p smd %p mic%d -> %s port %d - %s socket IO\n",
		md, smd, md->mc->scif_id-1, md->ibdev->name, md->port,
		md->numa_node == md->mc->numa_node ? "local":"cross" );

	smd->destroy = 1;
	op = smd->scif_op_ep;
	tx = smd->scif_tx_ep;
	ev = smd->scif_ev_ep;
	mpxy_unlock(&md->slock);

	write(smd->md->mc->cm_pipe[1], "w", sizeof("w"));
	write(smd->md->mc->op_pipe[1], "w", sizeof("w"));
	write(smd->md->mc->tx_pipe[1], "w", sizeof("w"));
	write(smd->md->mc->rx_pipe[1], "w", sizeof("w"));

	mpxy_lock(&md->slock);
	while (smd->th_ref_cnt) {
		mlog(1, " waiting for SMD %p ref_cnt (%d) = 0\n", smd, smd->th_ref_cnt);
		mpxy_unlock(&md->slock);
		sched_yield();
		mpxy_lock(&md->slock);
	}
	mpxy_destroy_smd(smd);

	/* close and remove scif MIX client, leave parent mcm_ib_dev open */
	if (op)
		scif_close(op);
	if (tx)
		scif_close(tx);
	if (ev)
		scif_close(ev);

	mlog(8, " All SCIF EP's closed for smd %p\n", smd);
	return;
}

/* accept SCIF endpoint connect request */
void mix_scif_accept(scif_epd_t listen_ep)
{
	struct scif_portID peer, peer_cm;
	scif_epd_t tx_ep, ev_ep, op_ep;
	int peer_listen;
	int ret, len;
	dat_mix_open_t msg;
	mcm_scif_dev_t	*smd = NULL;

	/* 2 channels created with clients, OP and TX processing */
	ret = scif_accept(listen_ep, &peer, &op_ep, SCIF_ACCEPT_SYNC);
	if (ret) {
		mlog(0, " ERR: scif_accept on OP ep %d, ret = %s\n", listen_ep, strerror(errno));
		return;
	}
	mlog(8, " SCIF op_ep %d connected to local_listen %d\n", op_ep, listen_ep);

	len = sizeof(peer_listen);
	ret = scif_recv(op_ep, &peer_listen, len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: rcv on new_ep %d, actual %d, expected %d, ret = %s\n", op_ep, ret, len, strerror(errno));
		goto out_close_op_ep;
	}

	peer_cm = peer;
	peer_cm.port = peer_listen; /* TX and EV connections */
	ev_ep = scif_open();
	if (ev_ep < 0) {
		mlog(0, " ERR: scif_open failed for EV ep, ret = %s\n", strerror(errno));
		goto out_close_op_ep;
	}
	ret = scif_connect(ev_ep, &peer_cm);
	if (ret < 0) {
		mlog(0, " ERR: scif_connect EV ep %d port %d on node %d, ret = %s\n",
			ev_ep, peer.node, peer_listen, strerror(errno));
		goto out_close_ev_ep;
	}
	mlog(8, " SCIF ev_ep %d connected to peer_listen %d\n", ev_ep, peer_listen);

	tx_ep = scif_open();
	if (tx_ep < 0) {
		mlog(0, " ERR: scif_open failed for TX ep, ret = %s\n", strerror(errno));
		goto out_close_ev_ep;
	}
	ret = scif_connect(tx_ep, &peer_cm);
	if (ret < 0) {
		mlog(0, " ERR: scif_connect TX ep %d on node %d, ret = %s\n", tx_ep, peer.node, strerror(errno));
		goto out_close_tx_ep;
	}
	mlog(8, " SCIF tx_ep %d connected to peer_listen %d \n", tx_ep, peer_listen);

	/* connect is followed immediately by MIX open command on OP channel */
	len = sizeof(dat_mix_open_t);
	ret = scif_recv(op_ep, &msg, len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: rcv on new_ep %d, actual %d, expected %d, ret = %s\n",
			op_ep, ret, len, strerror(errno));
		goto out_close_tx_ep;
	}
	mlog(8, " SCIF client: device open client_pid 0x%x - mlen %d - ep %d\n",
		ntohl(msg.hdr.req_id), len, op_ep);

	if (msg.hdr.ver < MIX_MIN || msg.hdr.ver > MIX_MAX || msg.hdr.op != MIX_IA_OPEN) {
		mlog(0, " ERR: MIC client incompatible with MPXYD (exp %d,rcvd %d) or OP (exp %d,rcvd %d)\n",
			DAT_MIX_VER, msg.hdr.ver, msg.hdr.op, MIX_IA_OPEN);
		msg.hdr.ver = DAT_MIX_VER;
		msg.hdr.status = MIX_EINVAL;
		goto err;
	}

	if (peer.node > MCM_CLIENT_MAX) {
		mlog(0, " ERR: too many MIC clients (%d)\n", peer.node);
		msg.hdr.status = MIX_EOVERFLOW;
		goto err;
	}

	/* open new device with hca name and port info, send response with addr info */
	smd = mix_open_device(&msg, op_ep, ev_ep, tx_ep, peer.node);
	if (smd)
		return;
err:

out_close_tx_ep:
	scif_close(tx_ep);

out_close_ev_ep:
	scif_close(ev_ep);

out_close_op_ep:
	scif_close(op_ep);
}

static int mix_query_device(mcm_scif_dev_t *smd, dat_mix_device_attr_t *pmsg)
{
	int ret, len;
	dat_mix_device_attr_t msg;
	struct ibv_device_attr dev_attr;

	len = sizeof(dat_mix_device_attr_t);
	msg.hdr.ver = DAT_MIX_VER;
	msg.hdr.op = MIX_QUERY_DEVICE;
	msg.hdr.flags = MIX_OP_RSP;

	ret = ibv_query_device(smd->md->ibctx, &dev_attr);
	if (ret) {
	        msg.hdr.status = MIX_EFAULT;
	        goto done;
	}
	msg.hdr.status = MIX_SUCCESS;

	strncpy(msg.fw_ver, dev_attr.fw_ver, sizeof(msg.fw_ver));
	msg.node_guid = dev_attr.node_guid;
	msg.sys_image_guid = dev_attr.sys_image_guid;
	msg.max_mr_size = dev_attr.max_mr_size;
	msg.page_size_cap = dev_attr.page_size_cap;
	msg.vendor_id = dev_attr.vendor_id;
	msg.vendor_part_id = dev_attr.vendor_part_id;
	msg.hw_ver = dev_attr.hw_ver;
	msg.max_qp = dev_attr.max_qp;
	msg.max_qp_wr = dev_attr.max_qp_wr;
	msg.device_cap_flags = dev_attr.device_cap_flags;
	msg.max_sge = dev_attr.max_sge;
	msg.max_sge_rd = dev_attr.max_sge_rd;
	msg.max_cq = dev_attr.max_cq;
	msg.max_cqe = dev_attr.max_cqe;
	msg.max_mr = dev_attr.max_mr;
	msg.max_pd = dev_attr.max_pd;
	msg.max_qp_rd_atom = dev_attr.max_qp_rd_atom;
	msg.max_ee_rd_atom = dev_attr.max_ee_rd_atom;
	msg.max_ee_rd_atom = dev_attr.max_res_rd_atom;
	msg.max_qp_init_rd_atom = dev_attr.max_qp_init_rd_atom;
	msg.max_ee_init_rd_atom = dev_attr.max_ee_init_rd_atom;
	msg.atomic_cap = dev_attr.atomic_cap;
	msg.max_ee = dev_attr.max_ee;
	msg.max_rdd = dev_attr.max_rdd;
	msg.max_mw = dev_attr.max_mw;
	msg.max_raw_ipv6_qp = dev_attr.max_raw_ipv6_qp;
	msg.max_raw_ethy_qp = dev_attr.max_raw_ethy_qp;
	msg.max_mcast_grp = dev_attr.max_mcast_grp;
	msg.max_mcast_qp_attach = dev_attr.max_mcast_qp_attach;
	msg.max_total_mcast_qp_attach = dev_attr.max_total_mcast_qp_attach;
	msg.max_ah = dev_attr.max_ah;
	msg.max_fmr = dev_attr.max_fmr;
	msg.max_map_per_fmr = dev_attr.max_map_per_fmr;
	msg.max_srq = dev_attr.max_srq;
	msg.max_srq_wr = dev_attr.max_srq_wr;
	msg.max_srq_sge = dev_attr.max_srq_sge;
	msg.max_pkeys = dev_attr.max_pkeys;
	msg.local_ca_ack_delay = dev_attr.local_ca_ack_delay;
	msg.phys_port_cnt = dev_attr.phys_port_cnt;
done:
	return (scif_send_msg(smd->scif_op_ep, &msg, len));
}

static int mix_query_port(mcm_scif_dev_t *smd, dat_mix_port_attr_t *pmsg)
{
	int ret, len;
	dat_mix_port_attr_t msg;
	struct ibv_port_attr port_attr;

	len = sizeof(dat_mix_port_attr_t);
	msg.hdr.ver = DAT_MIX_VER;
	msg.hdr.op = MIX_QUERY_PORT;
	msg.hdr.flags = MIX_OP_RSP;

	ret = ibv_query_port(smd->md->ibctx, pmsg->hdr.req_id, &port_attr);
	if (ret) {
	        msg.hdr.status = MIX_EFAULT;
	        goto done;
	}
	msg.hdr.status = MIX_SUCCESS;

	msg.gid_tbl_len = port_attr.gid_tbl_len;
	msg.port_cap_flags = port_attr.port_cap_flags;
	msg.max_msg_sz = port_attr.max_msg_sz;
	msg.bad_pkey_cntr = port_attr.bad_pkey_cntr;
	msg.qkey_viol_cntr = port_attr.qkey_viol_cntr;
	msg.pkey_tbl_len = port_attr.pkey_tbl_len;
	msg.lid = port_attr.lid;
	msg.sm_lid = port_attr.sm_lid;
	msg.lmc = port_attr.lmc;
	msg.max_vl_num = port_attr.max_vl_num;
	msg.sm_sl = port_attr.sm_sl;
	msg.subnet_timeout = port_attr.subnet_timeout;
	msg.init_type_reply = port_attr.init_type_reply;
	msg.active_width = port_attr.active_width;
	msg.active_speed = port_attr.active_speed;
	msg.phys_state = port_attr.phys_state;
	msg.link_layer = port_attr.link_layer;
	msg.state = port_attr.state;
	msg.max_mtu = port_attr.max_mtu;
	msg.active_mtu = port_attr.active_mtu;
done:
	return (scif_send_msg(smd->scif_op_ep, &msg, len));
}

static int mix_prov_attr(mcm_scif_dev_t *smd, dat_mix_attr_t *pmsg)
{
	int len, ret;

	if (pmsg->hdr.flags & MIX_OP_SET) {
		len = sizeof(dat_mix_attr_t) - sizeof(dat_mix_hdr_t);
		ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
		if (ret != len) {
			mlog(0, " ERR: ret %d, exp %d\n", ret, len);
			return ret;
		}

		/* SET not supported */
		len = sizeof(dat_mix_hdr_t);
		pmsg->hdr.flags = MIX_OP_RSP;
		pmsg->hdr.status = MIX_EINVAL;

		/* send back response */
		return (scif_send_msg(smd->scif_op_ep, pmsg, len));

	} else {
		dat_mix_attr_t msg;

		/* GET attributes and send back response and data */
		mix_get_prov_attr(smd, &msg.attr);

		len = sizeof(dat_mix_attr_t);
		msg.hdr.ver = DAT_MIX_VER;
		msg.hdr.op = MIX_PROV_ATTR;
		msg.hdr.flags = MIX_OP_RSP;
		msg.hdr.status = MIX_SUCCESS;

		return (scif_send_msg(smd->scif_op_ep, &msg, len));
	}
}

static int mix_listen_free(mcm_scif_dev_t *smd, dat_mix_hdr_t *pmsg)
{
	int len;
	mcm_cm_t *cm;

	mlog(8, " MIX_LISTEN_FREE: sid 0x%x \n", pmsg->req_id);

	mpxy_lock(&smd->llock);
	cm = get_head_entry(&smd->llist);
	while (cm) {
		if (cm->sid == (uint16_t)pmsg->req_id)
			break;
		cm = get_next_entry(&cm->entry, &smd->llist);
	}
	mpxy_unlock(&smd->llock);

	if (cm) {
		mcm_dqlisten_free(smd, cm);
		pmsg->status = MIX_SUCCESS;
	} else {
		mlog(0, " MIX_LISTEN_FREE: ERR: sid 0x%x not found\n", pmsg->req_id);
		pmsg->status = MIX_EINVAL;
	}

	/* send back response */
	pmsg->flags = MIX_OP_RSP;
	len = sizeof(dat_mix_hdr_t);
	return (scif_send_msg(smd->scif_op_ep, pmsg, len));
}

static int mix_listen(mcm_scif_dev_t *smd, dat_mix_listen_t *pmsg)
{
	int len, ret;
	uint16_t lport;
	mcm_cm_t *cm;

	/* hdr already read, get operation data */
	len = sizeof(dat_mix_listen_t) - sizeof(dat_mix_hdr_t);
	ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d\n", ret, len);
		return ret;
	}

	/* create listen EP for provided SID */
	mpxy_lock(&smd->md->plock);
	lport = mcm_get_port(smd->md->ports, pmsg->sid, (uint64_t)smd);
	mpxy_unlock(&smd->md->plock);
	if (lport == pmsg->sid) {
		cm = m_cm_create(smd, NULL, NULL);
		if (cm == NULL) {
			pmsg->hdr.status = MIX_ENOMEM;
			mpxy_lock(&smd->md->plock);
			mcm_free_port(smd->md->ports, lport);
			mpxy_unlock(&smd->md->plock);
		} else {
			cm->state = MCM_LISTEN;
			cm->sid = lport;
			cm->sp_ctx = pmsg->sp_ctx;
			cm->msg.sport = htons((uint16_t)lport);
			cm->msg.sqpn = htonl(smd->md->qp->qp_num);
			cm->msg.saddr1.qp_type = IBV_QPT_UD;
			cm->msg.saddr1.lid = smd->md->lid;
			cm->msg.saddr1.port = smd->md->port;
			cm->msg.saddr1.ep_map = smd->md->addr.ep_map;
#ifdef MPXYD_LOCAL_SUPPORT
			cm->msg.sys_guid = system_guid; /* network order */
#else
			cm->msg.sys_guid = rand();
#endif
			memcpy(&cm->msg.saddr1.gid[0], &smd->md->addr.gid, 16);

			mcm_qlisten(smd, cm);
			pmsg->hdr.status = MIX_SUCCESS;
		}
		mlog(2, " [%d:%d] cm %p sPORT 0x%x cm_qp 0x%x %s \n",
			 smd->md->mc->scif_id, smd->entry.tid, cm,
			 ntohs(cm->msg.sport), smd->md->qp->qp_num,
			 mcm_map_str(cm->md->addr.ep_map));
	} else {
		mlog(1, " MIX_LISTEN: WARN smd %p sid 0x%x port->ctx %p, backlog %d, qpn 0x%x lid 0x%x EADDRINUSE\n",
			smd, pmsg->sid, mcm_get_port_ctx(smd->md->ports, pmsg->sid),
			pmsg->backlog, smd->md->qp->qp_num, ntohs(smd->md->lid));
		pmsg->hdr.status = MIX_EADDRINUSE;
	}

	/* send back response */
	pmsg->hdr.flags = MIX_OP_RSP;
	len = sizeof(dat_mix_listen_t);
	return (scif_send_msg(smd->scif_op_ep, (void*)pmsg, len));
}

/* locate MR object */
mcm_mr_t *mix_get_mr(mcm_scif_dev_t *smd, uint32_t tid)
{
	mcm_mr_t *mr = NULL;

	mpxy_lock(&smd->mrlock);
	mr = get_head_entry(&smd->mrlist);
	while (mr) {
		if (mr->entry.tid == tid)
			break;
		mr = get_next_entry(&mr->entry, &smd->mrlist);
	}
	mpxy_unlock(&smd->mrlock);
	return mr;
}

/* locate CQ object */
mcm_cq_t *mix_get_cq(mcm_scif_dev_t *smd, uint32_t tid)
{
	mcm_cq_t *cq = NULL;

	mpxy_lock(&smd->cqlock);
	cq = get_head_entry(&smd->cqlist);
	while (cq) {
		if (cq->entry.tid == tid)
			break;
		cq = get_next_entry(&cq->entry, &smd->cqlist);
	}
	mpxy_unlock(&smd->cqlock);
	return cq;
}

/* locate QP object, qpt list */
mcm_qp_t *mix_get_qp(mcm_scif_dev_t *smd, uint32_t tid)
{
	mcm_qp_t *qp = NULL;

	mpxy_lock(&smd->qptlock);
	qp = get_head_entry(&smd->qptlist);
	while (qp) {
		if (qp->t_entry.tid == tid)
			break;
		qp = get_next_entry(&qp->t_entry, &smd->qptlist);
	}
	mpxy_unlock(&smd->qptlock);
	return qp;
}

/* locate CM object */
mcm_cm_t *mix_get_cm(mcm_scif_dev_t *smd, uint32_t tid)
{
	mcm_cm_t *cm = NULL;

	mpxy_lock(&smd->clock);
	cm = get_head_entry(&smd->clist);
	while (cm) {
		if (cm->entry.tid == tid)
			break;
		cm = get_next_entry(&cm->entry, &smd->clist);
	}
	mpxy_unlock(&smd->clock);
	return cm;
}

/* smd->cqlock held */
void m_cq_free(struct mcm_cq *m_cq)
{
	ibv_destroy_cq(m_cq->ib_cq);
	ibv_destroy_comp_channel(m_cq->ib_ch);
	remove_entry(&m_cq->entry);
	m_cq->entry.tid = 0;
	m_cq->ref_cnt--;
	free(m_cq);
}

/* smd->cqlock/cqrlock held */
void m_cq_flush(struct mcm_cq *m_cq)
{
	struct ibv_cq *ib_cq = NULL;
	void *cq_ctx;
	int ret, cnt=0;
	struct ibv_wc wc;

	mlog(8, " m_cq %p enter:\n", m_cq);
	ret = ibv_get_cq_event(m_cq->ib_ch, &ib_cq, (void *)&cq_ctx);
	if (ret == 0)
		ibv_ack_cq_events(m_cq->ib_cq, 1);

	do {
		ret = ibv_poll_cq(m_cq->ib_cq, 1, &wc);
		cnt += ret;
	}
	while (ret > 0);
	mlog(8, " m_cq %p exit: %d events flushed\n", m_cq, cnt);
}

/* destroy proxy CQ, fits in header */
static int mix_cq_destroy(mcm_scif_dev_t *smd, dat_mix_hdr_t *pmsg)
{
	int len;
	struct mcm_cq *m_cq;

	mlog(8, " MIX_CQ_DESTROY: cq_id 0x%x\n", pmsg->req_id);
	MCNTR(smd->md, MCM_CQ_FREE);

	/* Find the CQ */
	m_cq = mix_get_cq(smd, pmsg->req_id);
	if (!m_cq) {
		mlog(0, " ERR: mix_get_cq, id %d, not found\n", pmsg->req_id);
		goto err;
	}
	mpxy_lock(&smd->cqlock);
	m_cq_free(m_cq);
	mpxy_unlock(&smd->cqlock);

	pmsg->status = MIX_SUCCESS;
	goto resp;
err:
	mlog(0, " ERR: %s\n", strerror(errno));
	if (m_cq)
		free(m_cq);

	pmsg->status = MIX_EINVAL;
resp:
	/* send back response */
	pmsg->flags = MIX_OP_RSP;
	len = sizeof(dat_mix_hdr_t);
	return (scif_send_msg(smd->scif_op_ep, (void*)pmsg, len));
}

#define MCM_CQ_TX 1
#define MCM_CQ_RX 2

/* Create CQ object, IB channel and CQ, insert on list, update object tid */
static int m_cq_create(mcm_scif_dev_t *smd, int cq_len, struct mcm_cq **m_cq_out, int type)
{
	struct mcm_cq *m_cq;
	int ret = 0;

	m_cq = malloc(sizeof(mcm_cq_t));
	if (!m_cq)
		goto err;
	memset(m_cq, 0, sizeof(mcm_cq_t));

	init_list(&m_cq->entry);
	m_cq->smd = smd;

	m_cq->ib_ch = ibv_create_comp_channel(smd->md->ibctx);
	if (!m_cq->ib_ch)
		goto err;

	if (mcm_config_fd(m_cq->ib_ch->fd))
		goto err;

	m_cq->ib_cq = ibv_create_cq(smd->md->ibctx, cq_len, m_cq, m_cq->ib_ch, 0);
	if (!m_cq->ib_cq)
		goto err;

	ret = ibv_req_notify_cq(m_cq->ib_cq, 0);
	if (ret)
		goto err;

	if (type == MCM_CQ_TX) {
		mpxy_lock(&smd->cqlock);
		insert_tail(&m_cq->entry, &smd->cqlist, m_cq);
		m_cq->cq_id = m_cq->entry.tid;
		mpxy_unlock(&smd->cqlock);
		write(smd->md->mc->tx_pipe[1], "w", sizeof("w"));
		mlog(8, " cq %p id %d on TX cqlist\n", m_cq, m_cq->cq_id);
	} else {
		mpxy_lock(&smd->cqrlock);
		insert_tail(&m_cq->entry, &smd->cqrlist, m_cq);
		m_cq->cq_id = m_cq->entry.tid;
		mpxy_unlock(&smd->cqrlock);
		write(smd->md->mc->rx_pipe[1], "w", sizeof("w"));
		mlog(8, " cq %p id %d on RX cqlist\n", m_cq, m_cq->cq_id);
	}
	m_cq->ref_cnt++;
	*m_cq_out = m_cq;
	return 0;
err:
	mlog(0, " ERR: m_cq %p ib_ch %p, ib_cq %p ret %d %s\n",
		m_cq, m_cq ? m_cq->ib_ch:NULL,
		m_cq ? m_cq->ib_cq:NULL, ret, strerror(errno));
	if (m_cq)
		free(m_cq);
	return -1;
}

/* create new proxy-out CQ */
static int mix_cq_create(mcm_scif_dev_t *smd, dat_mix_cq_t *pmsg)
{
	int len, ret, cq_len;
	struct mcm_cq *new_mcq;

	/* hdr already read, get operation data */
	len = sizeof(dat_mix_cq_t) - sizeof(dat_mix_hdr_t);
	ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d\n", ret, len);
		return ret;
	}

	cq_len = max(pmsg->cq_len, mcm_tx_cq_size);
	mlog(8, " MIX_CQ_CREATE: cq_len = %d,%d mic_ctx = %Lx, dev_id %d\n",
		pmsg->cq_len, cq_len, pmsg->cq_ctx, smd->entry.tid);

	if (m_cq_create(smd, cq_len, &new_mcq, MCM_CQ_TX))
		goto err;

	new_mcq->cq_ctx = pmsg->cq_ctx;
	pmsg->cq_len = cq_len;
	pmsg->cq_id = new_mcq->cq_id;
	pmsg->cq_ctx = (uint64_t)new_mcq;
	pmsg->hdr.status = MIX_SUCCESS;
	mlog(8, " new cq_id %d, mpxyd_ctx %p, mcm_ctx %p\n",
		pmsg->cq_id, pmsg->cq_ctx, new_mcq->cq_ctx);
	MCNTR(smd->md, MCM_CQ_CREATE);
	goto resp;
err:
	mlog(0, " ERR: %s\n", strerror(errno));
	pmsg->hdr.status = MIX_EINVAL;
resp:
	/* send back response */
	pmsg->hdr.flags = MIX_OP_RSP;
	len = sizeof(dat_mix_cq_t);
	return (scif_send_msg(smd->scif_op_ep, (void*)pmsg, len));
}


static int mix_mmap_free(mcm_scif_dev_t *smd, dat_mix_mmap_addr_t *pmsg)
{
	int ret, len;

	/* hdr already read, get operation data */
	len = sizeof(dat_mix_mmap_addr_t) - sizeof(dat_mix_hdr_t);
	ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d %s\n", ret, len, strerror(errno));
		return ret;
	}

	if (pmsg->hdr.status != MIX_SUCCESS ) {
		/* MIC could not init after host ACK ADDR_EXG - fall back to scif_send */
		smd->mm_s_peer_addr_off = SCIF_REGISTER_FAILED;
		mlog(0, " WARN: MIC failed to init SEND_OP via mmap memory\n");
	}

	pmsg->hdr.status = MIX_SUCCESS;

	/* MIC side want us not to access it's memory */
	if (smd->mm_s_peer_addr) {
		ret = scif_munmap((void *)smd->mm_s_peer_addr, ALIGN_PAGE(sizeof(int)));
		if (ret < 0) {
			mlog(0, " ERR: scif_munmap %s\n", strerror(errno));
			pmsg->hdr.status = MIX_EINVAL;
		}
	}

	/* Valid s_peer_addr and NULL s_mmap_addr mark that we stopped using mmap memory
	 * we are closing down but that will keep process pending SEND_OP */
	smd->mm_s_peer_addr = NULL;

	if (smd->mm_s_place_holder) {
		free(smd->mm_s_place_holder);
		smd->mm_s_place_holder = NULL;
	}

	pmsg->hdr.flags = MIX_OP_RSP;
	len = sizeof(dat_mix_mmap_addr_t);

	/* send back response */
	if (smd->scif_op_ep) {
		ret = scif_send_msg(smd->scif_op_ep, (void*)pmsg, len);
		if (ret != len) {
			mlog(0, " ERR: ret %d, exp %d %s\n",
				ret, len, strerror(errno));
			return ret;
		}
	}

	return ret;
}


static int mix_mmap_alloc(mcm_scif_dev_t *smd, dat_mix_mmap_addr_t *pmsg)
{
	int ret, len;

	/* hdr already read, get operation data */
	len = sizeof(dat_mix_mmap_addr_t) - sizeof(dat_mix_hdr_t);
	ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d %s\n", ret, len, strerror(errno));
		return ret;
	}

	pmsg->hdr.status = MIX_EINVAL;

	mlog(8, " mm_s_peer_addr_off from MIC 0x%llx\n", pmsg->addr);

	if (pmsg->addr == SCIF_REGISTER_FAILED) {
		mlog(0, " ERR: op send got invalid input 0x%llx\n", pmsg->addr);
		goto resp;
	}

	if(!smd->mm_r_addr) {
		/* init_smd_send_op_mmap failed - fall back to reg OP */
		mlog(8, " init_smd_send_op_mmap failed - send MIC ENOMEM\n");
		pmsg->hdr.status = MIX_ENOMEM;
		goto resp;
	}

	smd->mm_s_peer_addr_off = pmsg->addr;

	ret = posix_memalign((void **)&smd->mm_s_place_holder, 4096, ALIGN_PAGE(sizeof(int)));
	if (ret) {
		mlog(0, " ERR: alloc mm_s_place_holder, ret=%d\n", ret);
		smd->mm_s_peer_addr_off = SCIF_REGISTER_FAILED;
		smd->mm_s_place_holder = NULL;
		goto resp;
	}

	/* mmap peer buffer so we can write into it like a reg memory */
	smd->mm_s_peer_addr = (volatile int *)
		scif_mmap(smd->mm_s_place_holder,
            	   	  ALIGN_PAGE(sizeof(int)),
            	   	  SCIF_PROT_READ | SCIF_PROT_WRITE, 0,
            	   	  smd->scif_op_ep, smd->mm_s_peer_addr_off);

	if (smd->mm_s_peer_addr == SCIF_MMAP_FAILED) {
		smd->mm_s_peer_addr_off = SCIF_REGISTER_FAILED;
		smd->mm_s_peer_addr = NULL;
		free(smd->mm_s_place_holder);
		smd->mm_s_place_holder = NULL;
		mlog(0, " ERR: scif_mmap m_s_peer_addr %s", strerror(errno));
		goto resp;
	}

	/* Send other side our scif base address of the SNED OP ARRAY */
	pmsg->addr = smd->mm_r_addr_off;
	pmsg->hdr.status = MIX_SUCCESS;

	/* Initialize the other side, WR tail */
	*smd->mm_s_peer_addr = 0;

	mlog(8, " mmap done: mm_s_peer_off 0x%llx, mm_r_addr_off 0x%llx\n",
		smd->mm_s_peer_addr_off, smd->mm_r_addr_off);
resp:
	/* send back response */
	pmsg->hdr.flags = MIX_OP_RSP;
	len = sizeof(dat_mix_mmap_addr_t);

	return (scif_send_msg(smd->scif_op_ep, (void*)pmsg, len));
}

/* create new proxy-out PZ */
static int mix_pz_create(mcm_scif_dev_t *smd, dat_mix_pz_t *pmsg)
{
	int len, ret;
	mcm_pz_t *new_pz;

	/* hdr already read, get operation data */
	len = sizeof(dat_mix_pz_t) - sizeof(dat_mix_hdr_t);
	ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d\n", ret, len);
		return ret;
	}

	new_pz = malloc(sizeof(mcm_pz_t));
	if (!new_pz) {
		mlog(0, " ERR: Could not alloc mcm_pz_t\n");
		goto err;
	}

	memset(new_pz, 0, sizeof(mcm_pz_t));

	init_list(&new_pz->entry);
	new_pz->smd = smd;
	new_pz->pd_ctx = pmsg->ctx;

	new_pz->ib_pd = ibv_alloc_pd(smd->md->ibctx);

	if (!new_pz->ib_pd) {
		mlog(0, " ERR: Could not alloc pd\n");
		goto err;
	}

	mpxy_lock(&smd->pzlock);
	insert_tail(&new_pz->entry, &smd->pzlist, new_pz);
	mpxy_unlock(&smd->pzlock);
	mlog(8, " new mcm_pz %p and ib_pd %p created\n", new_pz, new_pz->ib_pd);

	pmsg->ib_pd = (uint64_t)new_pz;
	pmsg->hdr.status = MIX_SUCCESS;
	goto resp;
err:
	if (new_pz)
		free(new_pz);

	mlog(0, " ERR: %s\n", strerror(errno));
	pmsg->hdr.status = MIX_EINVAL;
resp:
	/* send back response */
	pmsg->hdr.flags = MIX_OP_RSP;
	len = sizeof(dat_mix_pz_t);
	return (scif_send_msg(smd->scif_op_ep, (void*)pmsg, len));
}

/* destroy proxy-out PZ */
static int mix_pz_destroy(mcm_scif_dev_t *smd, dat_mix_pz_t *pmsg)
{
	mcm_pz_t *mcm_pz;
	int len, ret;

	/* hdr already read, get operation data */
	len = sizeof(dat_mix_pz_t) - sizeof(dat_mix_hdr_t);
	ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d\n", ret, len);
		return ret;
	}

	mlog(8, " MIX_PZ_DESTROY: msg ctx 0x%lx, msg ib_pd 0x%lx\n", pmsg->ctx, pmsg->ib_pd);

	/* find the PD in list */
	mpxy_lock(&smd->pzlock);
	mcm_pz = get_head_entry(&smd->pzlist);
	while (mcm_pz) {
		if ((uint64_t)mcm_pz == pmsg->ib_pd) {
			mlog(8, " Matched mcm_pz %p (ib_pd %p)\n", mcm_pz, mcm_pz->ib_pd);
			break;
		}
		mcm_pz = get_next_entry(&mcm_pz->entry, &smd->pzlist);
	}
	mpxy_unlock(&smd->pzlock);

	if (!mcm_pz) {
		mlog(0, " ERR: ib_pd 0x%lx was not found\n", pmsg->ib_pd);
		goto err;
	}

	mpxy_lock(&smd->pzlock);
	ret = ibv_dealloc_pd(mcm_pz->ib_pd);
	remove_entry(&mcm_pz->entry);
	free(mcm_pz);
	mpxy_unlock(&smd->pzlock);

	if (ret)
		goto err;

	pmsg->hdr.status = MIX_SUCCESS;
	goto resp;
err:
	mlog(0, " ERR: %s\n", strerror(errno));
	pmsg->hdr.status = MIX_EINVAL;
resp:
	/* send back response */
	pmsg->hdr.flags = MIX_OP_RSP;
	len = sizeof(dat_mix_pz_t);
	return (scif_send_msg(smd->scif_op_ep, (void*)pmsg, len));
}

/* called with smd->qptlist lock held */
void m_qp_free(struct mcm_qp *m_qp)
{
	if (m_qp->t_entry.tid)
		remove_entry(&m_qp->t_entry);

	if (m_qp->r_entry.tid) { /* MXS - MXS, also qprlist */
		mpxy_lock(&m_qp->smd->qprlock);
		remove_entry(&m_qp->r_entry);
		mpxy_unlock(&m_qp->smd->qprlock);
	}

	mlog(8, " m_qp %p m_cm %p cm_id %d cm_state %d\n",
		m_qp, m_qp->cm, m_qp->cm ? m_qp->cm->entry.tid:0,
		m_qp->cm ? m_qp->cm->state:0);

	if (m_qp->cm)
		m_qp->cm->state = MCM_DISCONNECTED;

	mcm_flush_qp(m_qp); /* QP to error, flush consumer messages */

	if (m_qp->m_cq_tx) { /* flush pending PO WRs on cq_tx */
		mpxy_lock(&m_qp->smd->cqlock);
		m_cq_flush(m_qp->m_cq_tx);
		mpxy_unlock(&m_qp->smd->cqlock);
	}

	if (m_qp->m_cq_rx) { /* flush pending PI WRs on cq_rx */
		mpxy_lock(&m_qp->smd->cqrlock);
		m_cq_flush(m_qp->m_cq_rx);
		mpxy_unlock(&m_qp->smd->cqrlock);
	}

	if (m_qp->cm) { /* unlink CM, serialized */
		struct mcm_cm *cm = m_qp->cm;

		mpxy_lock(&cm->lock);
		m_qp->cm->ref_cnt--; /* QP ref */
		m_qp->cm->m_qp = NULL;
		m_qp->cm = NULL;
		mpxy_unlock(&cm->lock);
		mcm_dqconn_free(m_qp->smd, cm);
	}

	if (m_qp->ib_qp1) {
		ibv_destroy_qp(m_qp->ib_qp1);
		m_qp->ib_qp1 = NULL;
	}
	if (m_qp->ib_qp2) {
		ibv_destroy_qp(m_qp->ib_qp2);
		m_qp->ib_qp2 = NULL;
	}

#ifdef MCM_PROFILE
	if (mcm_profile)
		mcm_qp_prof_pr(m_qp, MCM_QP_ALL);
#endif
	/* resource pools, proxy_in CQ, and qp object */
	m_po_destroy_bpool(m_qp);
	m_pi_destroy_bpool(m_qp);
	if (m_qp->m_cq_rx) {
		mpxy_lock(&m_qp->smd->cqrlock);
		m_cq_free(m_qp->m_cq_rx);
		m_qp->m_cq_rx = NULL;
		mpxy_unlock(&m_qp->smd->cqrlock);
	}
	mpxy_lock_destroy(&m_qp->txlock); /* proxy out */
	mpxy_lock_destroy(&m_qp->rxlock); /* proxy in */
	m_qp->smd->ref_cnt--;
	free(m_qp);
}

/* destroy proxy QP, fits in hdr */
static int mix_qp_destroy(mcm_scif_dev_t *smd, dat_mix_hdr_t *pmsg)
{
	int len;
	struct mcm_qp *m_qp;

	MCNTR(smd->md, MCM_QP_FREE);

	/* Find the QP */
	m_qp = mix_get_qp(smd, pmsg->req_id);
	if (!m_qp) {
		mlog(0, " ERR: mix_get_qp, id %d, not found\n", pmsg->req_id);
		goto err;
	}
	mlog(8, " QP_t - id 0x%x m_qp = %p\n", pmsg->req_id, m_qp);

	mpxy_lock(&smd->qptlock);
	m_qp_free(m_qp);
	mpxy_unlock(&smd->qptlock);

	pmsg->status = MIX_SUCCESS;
	goto resp;
err:
	mlog(0, " ERR: %s\n", strerror(errno));
	if (m_qp)
		free(m_qp);

	pmsg->status = MIX_EINVAL;
resp:
	/* send back response */
	pmsg->flags = MIX_OP_RSP;
	len = sizeof(dat_mix_hdr_t);
	if (scif_send_msg(smd->scif_op_ep, (void*)pmsg, len))
		return -1;

	mlog(8, " QP_t %p response sent to MIC client\n", m_qp);
	return 0;
}

static int mix_qp_modify(mcm_scif_dev_t *smd, dat_mix_qp_t *pmsg)
{
	return 0;
}

void m_qp_destroy_pi(struct mcm_qp *m_qp)
{
	mlog(2, " Destroying PI QP1r %p\n", m_qp);
	if (m_qp->ib_qp1) {
		ibv_destroy_qp(m_qp->ib_qp1);
		m_qp->ib_qp1 = NULL;
	}
}

/* create 2nd qp for proxy-in service, remote is not proxy-in so we need 2 QPs */
int m_qp_create_pi(mcm_scif_dev_t *smd, struct mcm_qp *m_qp)
{
	struct ibv_qp_init_attr qp_create;

	/* Setup attributes and create 2nd qp, for proxy_in TX/RX services */
	memset((void *)&qp_create, 0, sizeof(qp_create));

	qp_create.cap.max_recv_wr = mcm_rx_entries; /* proxy_in, inbound 0 byte RW's with immed data, WR's */
	qp_create.cap.max_recv_sge = 1;
	qp_create.cap.max_send_wr = mcm_tx_entries;
	qp_create.cap.max_send_sge = 1;
	if (smd->md->indata)
		qp_create.cap.max_inline_data = mcm_ib_inline;
	qp_create.qp_type = IBV_QPT_RC;
	qp_create.send_cq = m_qp->m_cq_tx->ib_cq; /* signal rate adjusted to avoid CQ overrun */
	qp_create.recv_cq = m_qp->m_cq_rx->ib_cq;
	qp_create.qp_context = (void *)m_qp;

	m_qp->ib_qp1 = ibv_create_qp(smd->md->pd, &qp_create);
	if (!m_qp->ib_qp1) {
		mlog(0, "  ERR: ibv_create_qp, %s\n", strerror(errno));
		return -1;
	}

	/* set to INIT state */
	if (mcm_modify_qp(m_qp->ib_qp1, IBV_QPS_INIT, 0, 0, NULL)) {
		ibv_destroy_qp(m_qp->ib_qp1);
		m_qp->ib_qp1 = NULL;
		return -1;
	}

	/* init proxy-in QP1 attributes, to be exhanged with peer */
	m_qp->qp_attr1.ctx = (uint64_t)m_qp;
	m_qp->qp_attr1.qp_type = IBV_QPT_RC;
	m_qp->qp_attr1.qp_num = m_qp->ib_qp1->qp_num;
	m_qp->qp_attr1.state = m_qp->ib_qp1->state;
	m_qp->qp_attr1.max_recv_wr = mcm_rx_entries;
	m_qp->qp_attr1.max_recv_sge = 1;
	m_qp->qp_attr1.max_send_wr = mcm_tx_entries;
	m_qp->qp_attr1.max_send_sge = 1;
	m_qp->qp_attr1.max_inline_data = mcm_ib_inline;

	return 0;
}

static int m_qp_create(mcm_scif_dev_t *smd,
		       struct ibv_qp_init_attr *attr,
		       uint32_t scq_id,
		       uint32_t	rcq_id,
		       struct mcm_qp **new_mqp)
{
	struct mcm_qp *m_qp;
	struct mcm_cq *m_cq_tx;
	int ret;

	/* Create QP object, save QPr info from MIC client */
	m_qp = malloc(sizeof(mcm_qp_t));
	if (!m_qp)
		goto err;
	memset(m_qp, 0, sizeof(mcm_qp_t));
	init_list(&m_qp->t_entry);
	init_list(&m_qp->r_entry);
	mpxy_lock_init(&m_qp->txlock, NULL);
	mpxy_lock_init(&m_qp->rxlock, NULL);
	m_qp->smd = smd;

	/* proxy-out WR pool */
	if (m_po_create_bpool(m_qp, attr->cap.max_send_wr))
		goto err;

	/* Find the CQ's for this QP for transmitting */
	m_cq_tx = mix_get_cq(smd, scq_id);
	if (!m_cq_tx) {
		mlog(0, " ERR: mix_get_cq_tx, id %d, not found\n", scq_id);
		goto err;
	}
	m_qp->m_cq_tx = m_cq_tx;

	 /* always need rx_cq, WC traffic in from PI service even when no PI local (MSS) */
  	if (m_cq_create(smd, mcm_rx_cq_size, &m_qp->m_cq_rx, MCM_CQ_RX))
		goto err;

	/* plus proxy-in: create WR and WC pools, rx_cq */
	if (MXF_EP(&smd->md->addr)) {
		if (m_pi_create_bpool(m_qp, attr->cap.max_recv_wr))
			goto err;

		/* get client CQ context for proxy-in receive messages if client rcq exists */
		if (scq_id == rcq_id)
			m_qp->m_cq_rx->cq_ctx = m_cq_tx->cq_ctx;
		else if (rcq_id) {
			struct mcm_cq *m_cq_rx;

			m_cq_rx = mix_get_cq(smd, rcq_id);
			if (!m_cq_rx) {
				mlog(0, " ERR: mix_get_cq_rx, rcq_id %d, not found\n", rcq_id);
				goto err;
			}
			m_qp->m_cq_rx->cq_ctx = m_cq_rx->cq_ctx;
		}
		attr->recv_cq = m_qp->m_cq_rx->ib_cq; /* proxy for MIC client */
	} else
	   	attr->recv_cq = m_qp->m_cq_rx->ib_cq;

	/*
	 * NOTE: Proxy-in mode we may need another QP if remote ep_map is not the same.
	 * Default to single QP, assuming both proxy-out and proxy-in services. Create the
	 * other if needed at CM request time when we know remote side mappings differ and
	 * require separate QP's for RX and TX services.
	 *
	 * QP2 is proxy-out TX always.
	 * QP2 is also proxy-in RX if local and remote is MIC_XSOCK_DEV.
	 * QP1 is proxy-in TX and RX if local is MIC_XSOCK_DEV and remote is not.
	 * QP1 is not needed if both sides are not MIC_XSOCK_DEV, QP1 on MIC.
	 */
	attr->send_cq = m_cq_tx->ib_cq;
	attr->qp_context = (void *)m_qp;

	m_qp->ib_qp2 = ibv_create_qp(smd->md->pd, attr);
	if (!m_qp->ib_qp2) {
		mlog(0, "  ERR: ibv_create_qp, %s\n", strerror(errno));
		goto err;
	}

	/* set to INIT state */
	ret = mcm_modify_qp(m_qp->ib_qp2, IBV_QPS_INIT, 0, 0, NULL);
	if (ret) {
		ibv_destroy_qp(m_qp->ib_qp2);
		m_qp->ib_qp2 = NULL;
		goto err;
	}

	/* init QPt with ib qp info, QPr included for proxy-in option */
	m_qp->qp_attr2.ctx = (uint64_t)m_qp;
	m_qp->qp_attr2.qp_type = m_qp->ib_qp2->qp_type;
	m_qp->qp_attr2.qp_num = m_qp->ib_qp2->qp_num;
	m_qp->qp_attr2.state = m_qp->ib_qp2->state;
	m_qp->qp_attr2.max_recv_wr = attr->cap.max_recv_wr;
	m_qp->qp_attr2.max_recv_sge = attr->cap.max_recv_sge;
	m_qp->qp_attr2.max_send_wr = attr->cap.max_send_wr;
	m_qp->qp_attr2.max_send_sge = attr->cap.max_send_sge;
	if (smd->md->indata)
		m_qp->qp_attr2.max_inline_data = attr->cap.max_inline_data;

	/* don't post recv msgs until RTU, if local MXS or local MSS to remote MXS */
	if (MXF_EP(&smd->md->addr))
		memcpy(&m_qp->qp_attr1, &m_qp->qp_attr2, sizeof(dat_mix_qp_attr_t));

	/* TX proxy-out thread queue */
	mpxy_lock(&smd->qptlock);
	insert_tail(&m_qp->t_entry, &smd->qptlist, m_qp);
	mpxy_unlock(&smd->qptlock);

	m_qp->qp_attr2.qp_id = m_qp->t_entry.tid;
	m_qp->smd->ref_cnt++;
	*new_mqp = m_qp;
	return 0;
err:
	ret = errno ? errno:EINVAL;
	m_po_destroy_bpool(m_qp);
	m_pi_destroy_bpool(m_qp);
	if (m_qp->m_cq_rx) {
		mpxy_lock(&smd->cqrlock);
		m_cq_free(m_qp->m_cq_rx);
		mpxy_unlock(&smd->cqrlock);
	}
	if (m_qp)
		free(m_qp);

	return ret;
}

/* create new proxy QP */
static int mix_qp_create(mcm_scif_dev_t *smd, dat_mix_qp_t *pmsg)
{
	int len, ret;
	struct ibv_qp_init_attr qp_create;
	struct mcm_qp *new_mqp = NULL;

	/* hdr already read, get operation data */
	len = sizeof(dat_mix_qp_t) - sizeof(dat_mix_hdr_t);
	ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d\n", ret, len);
		return -1;
	}

	mlog(8, " Client QP_r - dev_id %d qpn 0x%x, ctx %p, rq %d,%d rcq_id %d\n",
		smd->entry.tid, pmsg->qp_r.qp_num, pmsg->qp_r.ctx,
		pmsg->qp_r.max_recv_wr,
		pmsg->qp_r.max_recv_sge, pmsg->qp_r.rcq_id);

	mlog(8, " Client QP_t - wr %d sge %d inline %d sq %d,%d scq_id %d\n",
		pmsg->qp_t.max_send_wr, pmsg->qp_t.max_send_sge,
		pmsg->qp_t.max_inline_data, pmsg->qp_t.max_send_wr,
		pmsg->qp_t.max_send_sge, pmsg->qp_t.scq_id);

	/* Setup attributes and create qp, for TX services */
	memset((void *)&qp_create, 0, sizeof(qp_create));
	qp_create.cap.max_recv_wr = mcm_rx_entries; /* proxy_in, 0 byte RW's with idata */
	qp_create.cap.max_recv_sge = 1;
	qp_create.cap.max_send_wr = mcm_tx_entries; /* proxy-out WR separate from client WR */
	qp_create.cap.max_send_sge = min(pmsg->qp_t.max_send_sge, DAT_MIX_SGE_MAX);
	if (smd->md->indata)
		qp_create.cap.max_inline_data = mcm_ib_inline;
	qp_create.qp_type = IBV_QPT_RC;

	mlog(8, " QP_t - client max_wr %d, proxy_out max_wr %d\n",
	      pmsg->qp_t.max_send_wr, qp_create.cap.max_send_wr);

	pmsg->hdr.status = m_qp_create(smd, &qp_create, pmsg->qp_t.scq_id, pmsg->qp_r.rcq_id, &new_mqp);
	if (pmsg->hdr.status) {
		mlog(0, " ERR: QP_t - wr req %d act %d, sge %d, inline %d, QP's %d\n",
			pmsg->qp_t.max_send_wr, qp_create.cap.max_send_wr,
			pmsg->qp_t.max_send_sge, pmsg->qp_t.max_inline_data,
			((uint64_t *)smd->md->cntrs)[MCM_QP_CREATE] -
			((uint64_t *)smd->md->cntrs)[MCM_QP_FREE]);
		goto resp;
	}

	/* return QPt, QPr info to MIC client, insert on QP list */
	memcpy(&pmsg->qp_t, &new_mqp->qp_attr2, sizeof(dat_mix_qp_attr_t));

	if (MXF_EP(&smd->md->addr))
		memcpy(&pmsg->qp_r, &new_mqp->qp_attr1, sizeof(dat_mix_qp_attr_t));
	else {
		new_mqp->qp_attr1.qp_num = pmsg->qp_r.qp_num; /* QP1 == MIC QPr */
		new_mqp->qp_attr1.qp_type = pmsg->qp_r.qp_type;
	}

	/* return qp_id, proxy buffer, and wr pool info */
	pmsg->hdr.status = MIX_SUCCESS;
	pmsg->wr_off = new_mqp->wr_off;
	pmsg->wr_len = new_mqp->wr_end;
	pmsg->m_inline = mix_inline_threshold;
	MCNTR(smd->md, MCM_QP_CREATE);

	mlog(8, " Proxy QP_t - qpn %x q_id %d ctx %p sq %d,%d rq %d,%d, il %d\n",
		pmsg->qp_t.qp_num, pmsg->qp_t.qp_id, new_mqp,
		qp_create.cap.max_send_wr, qp_create.cap.max_send_sge,
		qp_create.cap.max_recv_wr, qp_create.cap.max_recv_sge,
		qp_create.cap.max_inline_data);
	mlog(8, " Proxy QP_r - qpn %x q_id %d ctx %p sq %d,%d rq %d,%d rcq_id %d\n",
		pmsg->qp_r.qp_num, pmsg->qp_t.qp_id, pmsg->qp_r.ctx,
		pmsg->qp_r.max_send_wr,
		pmsg->qp_r.max_send_sge, pmsg->qp_r.max_recv_wr,
		pmsg->qp_r.max_recv_sge, pmsg->qp_r.rcq_id);
resp:
	/* send back response */
	pmsg->hdr.flags = MIX_OP_RSP;
	len = sizeof(dat_mix_qp_t);
	return (scif_send_msg(smd->scif_op_ep, (void*)pmsg, len));
}

typedef struct dat_mix_mr_v4
{
	dat_mix_hdr_t		hdr;
	uint32_t		mr_id;
	uint32_t		len;
	uint64_t		off;
	uint64_t		ctx;

} dat_mix_mr_v4_t;

/* MIX_MR_CREATE: new proxy mr, insert on mr_list */
static int mix_mr_create(mcm_scif_dev_t *smd, dat_mix_mr_t *pmsg)
{
	int len, ret;
	struct mcm_mr *m_mr = NULL;

	/* hdr already read, get operation data */

	if (smd->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_mr_compat_t) - sizeof(dat_mix_hdr_t);
	else
		len = sizeof(dat_mix_mr_t) - sizeof(dat_mix_hdr_t);

	ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d\n", ret, len);
		return -1;
	}

	/* create MR object, save mr info, add to mrlist, return mr_id */
	m_mr = malloc(sizeof(mcm_mr_t));
	if (!m_mr) {
		pmsg->hdr.status = MIX_ENOMEM;
		goto resp;
	}
	memset(m_mr, 0, sizeof(mcm_mr_t));
	init_list(&m_mr->entry);
	m_mr->smd = smd;
	memcpy(&m_mr->mre, pmsg, sizeof(dat_mix_mr_t));

	mpxy_lock(&smd->mrlock);
	insert_tail(&m_mr->entry, &smd->mrlist, m_mr);
	mpxy_unlock(&smd->mrlock);

	pmsg->mr_id = m_mr->entry.tid;
	smd->ref_cnt++;
	if (MFO_EP(&smd->md->addr)) {
		m_mr->mre.ib_lkey = m_mr->entry.tid;
		m_mr->mre.ib_rkey = m_mr->entry.tid;
	}
	pmsg->hdr.status = MIX_SUCCESS;

	mlog(8, " mr[%d] - len %d lmr_ctx %p, scif_addr %Lx, scif_off 0x%x, ib addr %Lx ib_rkey 0x%x\n",
		pmsg->mr_id, pmsg->mr_len, pmsg->ctx, pmsg->sci_addr,
		pmsg->sci_off, pmsg->ib_addr, pmsg->ib_rkey);
resp:
	/* send back response */
	pmsg->hdr.flags = MIX_OP_RSP;
	if (smd->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_mr_compat_t);
	else
		len = sizeof(dat_mix_mr_t);

	return (scif_send_msg(smd->scif_op_ep, (void*)pmsg, len));
}

/* called with smd->mrlist lock held */
void m_mr_free(struct mcm_mr *m_mr)
{
	remove_entry(&m_mr->entry);
	m_mr->smd->ref_cnt--;
	free(m_mr);
}

/* proxy mr object cleanup */
static int m_mr_destroy(mcm_scif_dev_t *smd, int mr_id)
{
	struct mcm_mr *m_mr = NULL;
	int ret = MIX_EAGAIN;

	/* get entry and remove, if xfer not in progress */
	m_mr = mix_get_mr(smd, mr_id);
	if (m_mr) {
		mpxy_lock(&smd->mrlock);
		if (m_mr->busy)
			goto done;
		m_mr_free(m_mr);
		ret = MIX_SUCCESS;
	} else
		ret = MIX_EINVAL;
done:
	mpxy_unlock(&smd->mrlock);
	return ret;
}

/* MIX_MR_FREE */
static int mix_mr_free(mcm_scif_dev_t *smd, dat_mix_mr_t *pmsg)
{
	int len, ret;

	/* hdr already read, get operation data */
	len = sizeof(dat_mix_mr_t) - sizeof(dat_mix_hdr_t);
	ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d\n", ret, len);
		return -1;
	}
	mlog(8, " mr[%d] - len %d lmr_ctx %p, scif_addr 0x%p, scif_off 0x%x\n",
		pmsg->mr_id, pmsg->mr_len, pmsg->ctx, pmsg->sci_addr, pmsg->sci_addr);

	/* status only, hdr */
	pmsg->hdr.status = m_mr_destroy(smd, pmsg->mr_id);
	pmsg->hdr.flags = MIX_OP_RSP;
	len = sizeof(dat_mix_hdr_t);
	return (scif_send_msg(smd->scif_op_ep, (void*)pmsg, len));
}

void mix_dto_event(struct mcm_cq *m_cq, struct dat_mix_wc *wc, int nc)
{
	dat_mix_dto_comp_t msg;
	int i;

	/* send DTO events to MIC client */
	msg.hdr.ver = m_cq->smd->md->mc->ver;
	msg.hdr.op = MIX_DTO_EVENT;
	msg.hdr.flags = MIX_OP_REQ;
	msg.cq_id = m_cq->cq_id;
	msg.cq_ctx = m_cq->cq_ctx;
	msg.wc_cnt = nc;

	if (!m_cq->smd->scif_op_ep)
		return;

	for (i=0; i < nc; i++) {
		memcpy(&msg.wc[i], &wc[i], sizeof(*wc));

		if (msg.wc[i].status != IBV_WC_SUCCESS) {
			if (msg.wc[i].status  != IBV_WC_WR_FLUSH_ERR) {
				mlog(0, " [%d:%d] ERROR (ep=%d): id %d stat %d"
					" op %x flg %x ln %d wr_id %p wc's %d"
					" verr 0x%x errno=%d,%s\n",
					m_cq->smd->md->mc->scif_id,
					m_cq->smd->entry.tid,
					m_cq->smd->scif_op_ep, msg.cq_id,
					msg.wc[i].status, msg.wc[i].opcode,
					msg.wc[i].wc_flags, msg.wc[i].byte_len,
					msg.wc[i].wr_id, msg.wc_cnt,
					msg.wc[i].vendor_err,
					errno, strerror(errno));
			}
		} else {
			mlog(0x10, " SUCCESS (ep=%d): cq %p id %d ctx %p stat %d"
				" op 0x%x ln %d wr_id %p wc's %d verr 0x%x\n",
				m_cq->smd->scif_op_ep, m_cq, msg.cq_id, msg.cq_ctx,
				msg.wc[i].status, msg.wc[i].opcode, msg.wc[i].byte_len,
				msg.wc[i].wr_id, msg.wc_cnt, msg.wc[i].vendor_err);
		}
	}
	/* multi-thread sync */
	mpxy_lock(&m_cq->smd->evlock);
	scif_send_msg(m_cq->smd->scif_ev_ep, (void*)&msg, sizeof(msg));
	mpxy_unlock(&m_cq->smd->evlock);
}

void mix_cm_event(mcm_cm_t *m_cm, uint32_t event)
{
	dat_mix_cm_event_t msg;
	int len;

	/* send event to MIC client */
	msg.hdr.ver = m_cm->md->mc->ver;
	msg.hdr.op = MIX_CM_EVENT;
	msg.hdr.flags = MIX_OP_REQ;
	msg.cm_id = m_cm->cm_id;
	msg.cm_ctx = m_cm->cm_ctx;
	msg.event = event;

	if (event == DAT_CONNECTION_EVENT_DISCONNECTED) {
		mpxy_lock(&m_cm->lock);
		m_cm->state = MCM_FREE;
		mpxy_unlock(&m_cm->lock);
	}

	mlog(2, " MIX_CM_EVENT: (ep=%d) cm %p id %d ctx %p event 0x%x dev_id %d\n",
		m_cm->smd->scif_ev_ep, m_cm, m_cm->entry.tid,
		msg.cm_ctx, event, m_cm->smd->entry.tid);

	len = sizeof(dat_mix_cm_event_t);
	mpxy_lock(&m_cm->smd->evlock);
	if (scif_send_msg(m_cm->smd->scif_ev_ep, (void*)&msg, len)) {
		mlog(0, " Warning: cm %p cm_id %d, ctx %p, event 0x%x -> no MIC client\n",
			m_cm, m_cm->entry.tid, msg.cm_ctx, event);
	}
	mpxy_unlock(&m_cm->smd->evlock);
}

/* Active: new connection request operation, consumer context, create CM object */
static int mix_cm_req_out(mcm_scif_dev_t *smd, dat_mix_cm_t *pmsg, scif_epd_t scif_ep)
{
	int len, ret;
	struct mcm_qp *m_qp = NULL;
	struct mcm_cm *m_cm = NULL;

	/* hdr already read, get operation data, support compat mode */
	if (smd->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_cm_compat_t) - sizeof(dat_mix_hdr_t);
	else
		len = sizeof(dat_mix_cm_t) - sizeof(dat_mix_hdr_t);

	ret = scif_recv(scif_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d ver %d\n", ret, len, smd->md->mc->ver);
		return ret;
	}

	/* Find the QP for linking */
	m_qp = mix_get_qp(smd, pmsg->qp_id);
	if (!m_qp) {
		mlog(0, " ERR: mix_get_qp, id %d, not found\n", pmsg->qp_id);
		goto err;
	}

	/* Create CM, init saddr1 and saddr2 info for QPt and QPr */
	m_cm = m_cm_create(smd, m_qp, &pmsg->msg.daddr1);
	if (!m_cm)
		goto err;

	/*
	 * MIC client CM id, ctx, daddr1 = remote CM (lid,ep_map)
	 *
	 * MSS Proxy-out -> Host, MSS Direct-in, or MXS Proxy-in via fabric (2 QPs)
	 * saddr1  = IB QPr from MIC, setup with cm_create, QP1->QP2,
	 * saddr2 = IB QPt from MPXYD, setup with cm_create, QP2->QP1
	 *
	 * MXS Proxy-out/in -> MXS Proxy-in/out via fabric (1 QPs)
	 * saddr1 = N/A
	 * saddr2 = IB QPt/QPr from MPXYD, setup with cm_create
	 *
	 * MXS Proxy-out/in -> MXS Proxy-in/out inter-platform (0 QPs)
	 * saddr1 = N/A
	 * saddr2 = N/A
	 *
	 */
	m_cm->cm_id = pmsg->cm_id;
	m_cm->cm_ctx = pmsg->cm_ctx;
	m_cm->msg.dqpn = pmsg->msg.dqpn;
	m_cm->msg.dport = pmsg->msg.dport;
	m_cm->msg.p_size = pmsg->msg.p_size;
	if (m_cm->msg.p_size)
		memcpy(m_cm->msg.p_data, pmsg->msg.p_data, ntohs(m_cm->msg.p_size));

	memcpy(&m_cm->msg.daddr1, &pmsg->msg.daddr1, sizeof(dat_mcm_addr_t));
	memcpy(&m_cm->msg.daddr2, &pmsg->msg.daddr1, sizeof(dat_mcm_addr_t));
	mcm_hton_wrc((mcm_wrc_info_t *)m_cm->msg.p_proxy, &m_qp->wrc); /* PI WR/WC raddr,rkey info */
	m_cm->msg.seg_sz = mix_buffer_sg_po2;

	/* intra-node; set QPt to HST lid */
	if (smd->md->m_lid) {
		m_cm->msg.saddr2.lid = smd->md->addr.lid;
		memcpy(&m_cm->msg.saddr2.gid[0], &smd->md->addr.gid, 16);
	}

	mlog(2," QP2 0x%x QP1 0x%x:"
	       " CM sPORT 0x%x sQPN 0x%x sLID 0x%x - dPORT 0x%x dQPN 0x%x dLID 0x%x, psz %d %s\n",
		m_cm->msg.saddr2.qpn, m_cm->msg.saddr1.qpn,
		ntohs(m_cm->msg.sport), ntohl(m_cm->msg.sqpn), ntohs(m_cm->msg.saddr2.lid),
		ntohs(m_cm->msg.dport), ntohl(m_cm->msg.dqpn), ntohs(m_cm->msg.daddr1.lid),
		ntohs(m_cm->msg.p_size), mcm_map_str(m_cm->msg.daddr1.ep_map));

	/* send request on wire */
	if (mcm_cm_req_out(m_cm))
		goto err;

	/* insert on cm list, update proxy CM object tid */
	mcm_qconn(smd, m_cm);
	pmsg->cm_id = m_cm->entry.tid;
	pmsg->cm_ctx = (uint64_t)m_cm;
	pmsg->hdr.status = MIX_SUCCESS;
	goto resp;
err:
	mlog(0, " ERR: %s\n", strerror(errno));
	if (m_cm)
		free(m_cm);

	pmsg->hdr.status = MIX_EINVAL;
resp:
	mlog(8, " MPXYD id 0x%x, ctx %p - MIC id 0x%x, ctx %p dev_id %d\n",
	     pmsg->cm_id, pmsg->cm_ctx, m_cm->cm_id, m_cm->cm_ctx,
	     smd->entry.tid);

	/* send back response */
	pmsg->hdr.flags = MIX_OP_RSP;

	/* support compat mode */
	if (m_cm->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_cm_compat_t);
	else
		len = sizeof(dat_mix_cm_t);

	return (scif_send_msg(smd->scif_op_ep, (void*)pmsg, len));
}

/* disconnect request out */
static int mix_cm_disc_out(mcm_scif_dev_t *smd, dat_mix_cm_t *pmsg, scif_epd_t scif_ep)
{
	int len, ret;
	struct mcm_cm *m_cm;

	/* hdr already read, get operation data, support compat mode */
	if (smd->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_cm_compat_t) - sizeof(dat_mix_hdr_t);
	else
		len = sizeof(dat_mix_cm_t) - sizeof(dat_mix_hdr_t);

	ret = scif_recv(scif_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d\n", ret, len);
		return ret;
	}
	mlog(8, " cm_id %d, cm_ctx %p, qp_id %d \n",
		pmsg->cm_id, (void*)pmsg->cm_ctx, pmsg->qp_id);

	/* Find the CM for linking */
	m_cm = mix_get_cm(smd, pmsg->cm_id);
	if (!m_cm) {
		mlog(2, " CM_DREQ mix_get_cm, id %d, not found\n", pmsg->cm_id);
		return 0;
	}

	/* process DREQ, flush QP */
	mcm_cm_disc(m_cm);
	if (m_cm->m_qp)
		mcm_flush_qp(m_cm->m_qp); /* move QP to error, flush */
	return 0;
}

/* Active, reply received, send RTU, unsolicited channel */
static int mix_cm_rtu_out(mcm_scif_dev_t *smd, dat_mix_cm_t *pmsg, scif_epd_t scif_ep)
{
	int len, ret;
	struct mcm_cm *m_cm;

	/* hdr already read, get operation data, support compat mode */
	if (smd->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_cm_compat_t) - sizeof(dat_mix_hdr_t);
	else
		len = sizeof(dat_mix_cm_t) - sizeof(dat_mix_hdr_t);

	ret = scif_recv(scif_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d\n", ret, len);
		return ret;
	}
	mlog(8, " cm_id %d, cm_ctx %p, qp_id %d dev_id\n",
		pmsg->cm_id, (void*)pmsg->cm_ctx, pmsg->qp_id, smd->entry.tid);

	/* Find the CM for linking */
	m_cm = mix_get_cm(smd, pmsg->cm_id);
	if (!m_cm) {
		mlog(0, " ERR: mix_get_cm, id %d, not found\n", pmsg->cm_id);
		return -1;
	}

	mlog(2," QPt 0x%x QPr 0x%x -> dport 0x%x, dqpn 0x%x dlid 0x%x %Lx\n",
		 m_cm->m_qp?m_cm->m_qp->qp_attr2.qp_num:0,
		 m_cm->m_qp?m_cm->m_qp->qp_attr1.qp_num:0,
		 ntohs(m_cm->msg.dport), ntohl(m_cm->msg.dqpn),
		 ntohs(m_cm->msg.daddr1.lid), ntohll(m_cm->msg.sys_guid));

	/* send RTU on wire */
	m_cm->msg.mtu = m_cm->m_qp->mtu; /* send negotiated MTU */
	mcm_cm_rtu_out(m_cm);

	return 0;
}

/* ACTIVE: CR reject from server, unsolicited channel */
int mix_cm_rej_in(mcm_cm_t *m_cm, dat_mcm_msg_t *pkt, int pkt_len)
{
	dat_mix_cm_t msg;
	int len;

	mlog(2, " dev_id %d cm_id %d, ctx %p, m_cm %p pkt %p pln %d psz %d r_guid %Lx\n",
	     m_cm->smd->entry.tid, m_cm->cm_id, m_cm->cm_ctx, m_cm, pkt,
	     pkt_len, ntohs(pkt->p_size), ntohll(pkt->sys_guid));

	/* Forward appropriate reject message to MIC client */
	if (ntohs(pkt->op) == MCM_REJ_USER) {
		MCNTR(m_cm->md, MCM_CM_REJ_USER_IN);
		msg.hdr.op = MIX_CM_REJECT_USER;
	} else {
		MCNTR(m_cm->md, MCM_CM_REJ_IN);
		msg.hdr.op = MIX_CM_REJECT;
	}
	msg.hdr.ver = m_cm->md->mc->ver;
	msg.hdr.flags = MIX_OP_REQ;
	msg.cm_id = m_cm->cm_id;
	msg.cm_ctx = m_cm->cm_ctx;
	memcpy(&msg.msg, pkt, pkt_len);

	mcm_pr_addrs(2, pkt, m_cm->state, 1);

	/* save dst id, daddr1 and daddr2 info, remote guid, pdata, proxy data */
	m_cm->msg.d_id = pkt->s_id;
	m_cm->msg.sys_guid = pkt->sys_guid;
	memcpy(m_cm->msg.p_data, &pkt->p_data, ntohs(pkt->p_size));
	memcpy(m_cm->msg.p_proxy, pkt->p_proxy, DAT_MCM_PROXY_DATA);
	memcpy(&m_cm->msg.daddr1, &pkt->saddr1, sizeof(dat_mcm_addr_t));
	memcpy(&m_cm->msg.daddr2, &pkt->saddr2, sizeof(dat_mcm_addr_t));

	mpxy_lock(&m_cm->lock);
	m_cm->state = MCM_REJECTED;
	mpxy_unlock(&m_cm->lock);

	/* clean up proxy QP, CQ resources here ??? */

	/* support compat mode */
	if (m_cm->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_cm_compat_t);
	else
		len = sizeof(dat_mix_cm_t);

	mpxy_lock(&m_cm->smd->evlock);
	if (scif_send_msg(m_cm->smd->scif_ev_ep, (void*)&msg, len)) {
		mpxy_unlock(&m_cm->smd->evlock);
		goto err;
	}
	mpxy_unlock(&m_cm->smd->evlock);
	return 0;
err:
	mlog(0, " ERR %s: my_id %d, mic_id %d, %p\n",
	     strerror(errno), m_cm->entry.tid, m_cm->cm_id, m_cm->cm_ctx);
	return -1;
}

/* ACTIVE: CR reply from server, unsolicited channel */
int mix_cm_rep_in(mcm_cm_t *m_cm, dat_mcm_msg_t *pkt, int pkt_len)
{
	dat_mix_cm_t msg;
	int len;
	struct ibv_qp *qp;
	union ibv_gid *dgid;
	uint32_t dqpn;
	uint16_t dlid;

	MCNTR(m_cm->md, MCM_CM_REP_IN);

	mlog(2, " [%d:%d] %s cm_id %d m_cm %p pkt %p pln %d psz %d Guids l=%Lx r=%Lx\n",
	     m_cm->md->mc->scif_id, m_cm->smd->entry.tid,
	     mcm_map_str(m_cm->md->addr.ep_map), m_cm->cm_id, m_cm, pkt,
	     pkt_len, ntohs(pkt->p_size), ntohll(system_guid), ntohll(pkt->sys_guid));

	/* Forward, as is, conn_reply message to MIC client, with remote QP info */
	msg.hdr.ver = m_cm->md->mc->ver;
	msg.hdr.flags = MIX_OP_REQ;
	msg.hdr.op = MIX_CM_REP;
	msg.cm_id = m_cm->cm_id;
	msg.cm_ctx = m_cm->cm_ctx;
	memcpy(&msg.msg, pkt, pkt_len);

	mcm_pr_addrs(2, pkt, m_cm->state, 1);

	/* save dst id, daddr1 and daddr2 info, remote guid, pdata, proxy data */
	m_cm->msg.d_id = pkt->s_id;
	m_cm->msg.sys_guid = pkt->sys_guid;
	memcpy(m_cm->msg.p_data, &pkt->p_data, ntohs(pkt->p_size));
	memcpy(m_cm->msg.p_proxy, pkt->p_proxy, DAT_MCM_PROXY_DATA);
	memcpy(&m_cm->msg.daddr1, &pkt->saddr1, sizeof(dat_mcm_addr_t));
	memcpy(&m_cm->msg.daddr2, &pkt->saddr2, sizeof(dat_mcm_addr_t));
	mcm_ntoh_wrc(&m_cm->m_qp->wrc_rem, (mcm_wrc_info_t *)m_cm->msg.p_proxy); /* peer RI WRC info */
	if (m_cm->m_qp->wrc_rem.wr_sz > MCM_WR_RX_NO_DATA)
		m_cm->m_qp->p2p_data = DAT_MCM_P2P_INLINE;
	else
		m_cm->m_qp->p2p_data = 0;

	/* Set QP MTU, if negotiated. 2K for compatibility */
	m_cm->m_qp->mtu = pkt->mtu ?
			  min(pkt->mtu, m_cm->smd->dev_attr.mtu):
			  m_cm->smd->mtu_env ? m_cm->smd->mtu_env : IBV_MTU_2048;
	m_cm->msg.mtu = m_cm->m_qp->mtu; /* forward negotiated MTU */

	mlog(2, " WRC: m_qp %p - WR 0x%Lx rkey 0x%x ln %d, sz %d end %d"
		" WC 0x%Lx rkey 0x%x ln %d, sz %d end %d\n",
	     m_cm->m_qp, m_cm->m_qp->wrc.wr_addr, m_cm->m_qp->wrc.wr_rkey,
	     m_cm->m_qp->wrc.wr_len, m_cm->m_qp->wrc.wr_sz,
	     m_cm->m_qp->wrc.wr_end, m_cm->m_qp->wrc.wc_addr,
	     m_cm->m_qp->wrc.wc_rkey, m_cm->m_qp->wrc.wc_len,
	     m_cm->m_qp->wrc.wc_sz, m_cm->m_qp->wrc.wc_end);

	mlog(2, " WRC_rem: WR 0x%Lx rkey 0x%x ln %d, sz %d end %d"
		" WC 0x%Lx rkey 0x%x ln %d, sz %d end %d p2p %d\n",
	     m_cm->m_qp->wrc_rem.wr_addr, m_cm->m_qp->wrc_rem.wr_rkey,
	     m_cm->m_qp->wrc_rem.wr_len, m_cm->m_qp->wrc_rem.wr_sz,
	     m_cm->m_qp->wrc_rem.wr_end, m_cm->m_qp->wrc_rem.wc_addr,
	     m_cm->m_qp->wrc_rem.wc_rkey, m_cm->m_qp->wrc_rem.wc_len,
	     m_cm->m_qp->wrc_rem.wc_sz, m_cm->m_qp->wrc_rem.wc_end,
	     m_cm->m_qp->p2p_data);

	/* MXS <- MSS or HOST, fabric: TX: QP2->QP1 direct, RX: QP1<-QP2 proxy */
	if ((MXF_EP(&m_cm->md->addr) && !MXF_EP(&m_cm->msg.daddr1)) &&
	    system_guid != m_cm->msg.sys_guid) {
		mlog(2, " MXS <- %s remote \n", mcm_map_str(m_cm->msg.daddr1.ep_map));

		if (m_pi_prep_rcv_q(m_cm->m_qp))
			goto err;

		/* RX proxy-in QP */
		qp = m_cm->m_qp->ib_qp1;
		dgid = (union ibv_gid *)m_cm->msg.daddr2.gid;
		dqpn = m_cm->msg.daddr2.qpn;
		dlid = m_cm->msg.daddr2.lid;

		if (mcm_modify_qp(qp, IBV_QPS_RTR, dqpn, dlid, dgid))
			goto err;

		if (mcm_modify_qp(qp, IBV_QPS_RTS, dqpn, dlid, NULL))
			goto err;

		/* TX proxy-out QP  */
		qp = m_cm->m_qp->ib_qp2;
		dgid = (union ibv_gid *)m_cm->msg.daddr1.gid;
		dqpn = m_cm->msg.daddr1.qpn;
		dlid = m_cm->msg.daddr1.lid;

		/* QP1r onto RX PI thread queue */
		mpxy_lock(&m_cm->smd->qprlock);
		insert_tail(&m_cm->m_qp->r_entry, &m_cm->smd->qprlist, m_cm->m_qp);
		mpxy_unlock(&m_cm->smd->qprlock);

	/* MXS <- MXS, proxy-in both sides, fabric, 1 QP only  */
	} else if ((MXF_EP(&m_cm->md->addr) && MXF_EP(&m_cm->msg.daddr1)) &&
		   system_guid != m_cm->msg.sys_guid) {
		mlog(2, " MXS <- MXS remote \n");

		if (m_pi_prep_rcv_q(m_cm->m_qp))
			return -1;

		qp = m_cm->m_qp->ib_qp2;
		dgid = (union ibv_gid *)m_cm->msg.daddr2.gid;
		dqpn = m_cm->msg.daddr2.qpn;
		dlid = m_cm->msg.daddr2.lid;

		/* QP2r onto RX PI thread queue */
		mpxy_lock(&m_cm->smd->qprlock);
		insert_tail(&m_cm->m_qp->r_entry, &m_cm->smd->qprlist, m_cm->m_qp);
		mpxy_unlock(&m_cm->smd->qprlock);

		/* destroy QP1, created if remote ep_map unknown */
		m_qp_destroy_pi(m_cm->m_qp);

	/* MXS <- MXS, proxy-in both sides, inside system, no QP's, SCIF services only */
	} else if ((MXF_EP(&m_cm->md->addr) && MXF_EP(&m_cm->msg.daddr1)) &&
		   system_guid == m_cm->msg.sys_guid) {
		mlog(0, " MXS <- MXS local NOT SUPPORTED \n");
		qp = NULL;

	/* MSS <- MSS,MXS,HOST - fabric, TX: QP2->QP1 on mpxyd and RX: QP1->QP2 on MIC */
	} else {
		mlog(2, " MSS <- %s remote \n", mcm_map_str(m_cm->msg.daddr1.ep_map));

		if (MXF_EP(&m_cm->msg.daddr1) && m_pi_prep_rcv_q(m_cm->m_qp))
				goto err;

		if (!MXF_EP(&m_cm->msg.daddr1))
			m_pi_destroy_wc_q(m_cm->m_qp); /* created if ep_map was unknown */

		qp = m_cm->m_qp->ib_qp2;
		dgid = (union ibv_gid *)m_cm->msg.daddr1.gid;
		dqpn = m_cm->msg.daddr1.qpn;
		dlid = m_cm->msg.daddr1.lid;
	}

	if (qp) {
		if (mcm_modify_qp(qp, IBV_QPS_RTR, dqpn, dlid, dgid))
			goto err;

		if (mcm_modify_qp(qp, IBV_QPS_RTS, dqpn, dlid, NULL))
			goto err;
	}

	/* support compat mode */
	if (m_cm->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_cm_compat_t);
	else
		len = sizeof(dat_mix_cm_t);

	mpxy_lock(&m_cm->smd->evlock);
	if (scif_send_msg(m_cm->smd->scif_ev_ep, (void*)&msg, len)) {
		mpxy_unlock(&m_cm->smd->evlock);
		goto err;
	}
	mpxy_unlock(&m_cm->smd->evlock);

	mpxy_lock(&m_cm->lock);
	m_cm->state = MCM_REP_RCV;
	mpxy_unlock(&m_cm->lock);
	return 0;
err:
	mlog(0, " ERR %s: my_id %d, mic_id %d, %p\n",
	     strerror(errno), m_cm->entry.tid, m_cm->cm_id, m_cm->cm_ctx);

	mcm_pr_addrs(0, pkt, m_cm->state, 1);
	m_cm->state = MCM_REJECTED;
	mcm_cm_rej_out(m_cm->md, &m_cm->msg, MCM_REJ_CM, 0);
	return -1;
}

/* PASSIVE, connect request in on listen_cm object, create new cm */
int mix_cm_req_in(mcm_cm_t *cm, dat_mcm_msg_t *pkt, int pkt_len)
{
	dat_mix_cm_t msg;
	mcm_cm_t *acm;
	int len;

	acm = m_cm_create(cm->smd, NULL, NULL);
	if (!acm)
		return -1;

	mcm_pr_addrs(2, pkt, acm->state, 1);

	msg.hdr.ver = cm->md->mc->ver;
	msg.hdr.flags = MIX_OP_REQ;
	msg.hdr.op = MIX_CM_REQ;
	msg.hdr.status = MIX_SUCCESS;

	/* dest CM info from CR msg, source CM info from listen */
	acm->sid = cm->sid;
	acm->sp_ctx = cm->sp_ctx;
	acm->l_ep = cm->l_ep;
	acm->msg.op = pkt->op;
	acm->msg.dport = pkt->sport;
	acm->msg.dqpn = pkt->sqpn;
	acm->msg.sport = cm->msg.sport;
	acm->msg.sqpn = cm->msg.sqpn;
	acm->msg.p_size = pkt->p_size;
	acm->msg.d_id = pkt->s_id;
	acm->msg.rd_in = pkt->rd_in;
	acm->msg.mtu = pkt->mtu;
#ifdef MPXYD_LOCAL_SUPPORT
	acm->msg.sys_guid = pkt->sys_guid; /* remote system guid */;
#else
	acm->msg.sys_guid = rand();
#endif
	memcpy(acm->msg.p_proxy, pkt->p_proxy, DAT_MCM_PROXY_DATA);

	/* CR saddr1 is CM daddr1 info, need EP for local saddr1, saddr2 for MXS */
	memcpy(&acm->msg.daddr1, &pkt->saddr1, sizeof(dat_mcm_addr_t));
	memcpy(&acm->msg.daddr2, &pkt->saddr2, sizeof(dat_mcm_addr_t));

	mlog(2, " [%d:%d] cm %p ep %d: %x %s <- %x lid=%x psz=%d %s %s %Lx (%p %d) lmtu %d rmtu %d\n",
		 cm->md->mc->scif_id, cm->smd->entry.tid, acm, acm->smd->scif_ev_ep,
		 ntohs(acm->msg.sport), mcm_map_str(acm->md->addr.ep_map),
		 ntohs(acm->msg.dport), ntohs(acm->msg.daddr1.lid), htons(acm->msg.p_size),
		 mcm_map_str(acm->msg.daddr2.ep_map),
		 acm->md->addr.lid == acm->msg.daddr1.lid ? "platform":"fabric",
		 ntohll(acm->msg.sys_guid), &msg, sizeof(dat_mcm_msg_t),
		 cm->smd->dev_attr.mtu, pkt->mtu);

	if (pkt->p_size)
		memcpy(acm->msg.p_data, pkt->p_data, ntohs(pkt->p_size));

	/* forward reformated CM message info to MIX client, support compat mode */
	if (cm->md->mc->ver == MIX_COMP) {
		len = sizeof(dat_mix_cm_compat_t);
		memcpy(&msg.msg, &acm->msg, sizeof(dat_mcm_msg_compat_t));
	} else {
		len = sizeof(dat_mix_cm_t);
		memcpy(&msg.msg, &acm->msg, sizeof(dat_mcm_msg_t));
	}

	acm->state = MCM_ACCEPTING;
	mcm_qconn(acm->smd, acm);
	msg.cm_id = acm->entry.tid;
	msg.cm_ctx = (uint64_t)acm;
	msg.sp_ctx = cm->sp_ctx;

	mpxy_lock(&acm->smd->evlock);
	if (scif_send_msg(acm->smd->scif_ev_ep, (void*)&msg, len)) {
		mpxy_unlock(&acm->smd->evlock);
		return -1;
	}
	mpxy_unlock(&acm->smd->evlock);
	return 0;
}

/* PASSIVE: rtu from client */
int mix_cm_rtu_in(mcm_cm_t *m_cm, dat_mcm_msg_t *pkt, int pkt_len)
{
	dat_mix_cm_t msg;
	int len;

	mlog(1, "[%d:%d] CONN_EST[%d]: %p 0x%x %x 0x%x %Lx %s <- 0x%x %x 0x%x %Lx %s mtu %d\n",
		m_cm->md->mc->scif_id, m_cm->smd->entry.tid,
		m_cm->md->cntrs ? (uint32_t)((uint64_t *)m_cm->md->cntrs)[MCM_CM_RTU_IN]:0,
		m_cm, htons(pkt->daddr1.lid),
		MXF_EP(&m_cm->msg.daddr1) && MXF_EP(&m_cm->msg.saddr1) ?
			htonl(m_cm->msg.daddr2.qpn):htonl(m_cm->msg.daddr1.qpn),
		htons(pkt->dport), system_guid, mcm_map_str(pkt->daddr1.ep_map),
		htons(pkt->saddr2.lid), htonl(pkt->saddr2.qpn),
		htons(pkt->sport), ntohll(pkt->sys_guid), mcm_map_str(pkt->saddr2.ep_map),
		m_cm->m_qp->mtu);

	/* MXF_EP <- HST_EP, host sends WC on RTU, save WRC info */
	if (MXF_EP(&pkt->daddr1) && HST_EP(&pkt->saddr2)) {
		mcm_ntoh_wrc(&m_cm->m_qp->wrc_rem, (mcm_wrc_info_t *)pkt->p_proxy);
		if (m_cm->m_qp->wrc_rem.wr_sz > MCM_WR_RX_NO_DATA)
			m_cm->m_qp->p2p_data = DAT_MCM_P2P_INLINE;
		else
			m_cm->m_qp->p2p_data = 0;

		mlog(2, " WRC_rem: WC addr 0x%Lx rkey 0x%x len %d, sz %d end %d p2p %d\n",
		     m_cm->m_qp, m_cm->m_qp->wrc_rem.wc_addr, m_cm->m_qp->wrc_rem.wc_rkey,
		     m_cm->m_qp->wrc_rem.wc_len, m_cm->m_qp->wrc_rem.wc_sz,
		     m_cm->m_qp->wrc_rem.wc_end, m_cm->m_qp->p2p_data);
	}

	mpxy_lock(&m_cm->lock);
	m_cm->state = MCM_CONNECTED;
	mpxy_unlock(&m_cm->lock);

	/* Forward, as is, conn_reply message to MIC client, with remote QP info */
	msg.hdr.ver = m_cm->md->mc->ver;
	msg.hdr.flags = MIX_OP_REQ;
	msg.hdr.op = MIX_CM_RTU;
	msg.cm_id = m_cm->cm_id;
	msg.cm_ctx = m_cm->cm_ctx;
	m_cm->msg.sys_guid = pkt->sys_guid; /* save remote quid */

	/* support compat mode */
	if (m_cm->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_cm_compat_t);
	else
		len = sizeof(dat_mix_cm_t);

	mpxy_lock(&m_cm->smd->evlock);
	if (scif_send_msg(m_cm->smd->scif_ev_ep, (void*)&msg, len)) {
		mpxy_unlock(&m_cm->smd->evlock);
		mcm_cm_disc(m_cm);
		return -1;
	}
	mpxy_unlock(&m_cm->smd->evlock);
	return 0;
}

/* PASSIVE, accept connect request from client, cr_reply */
static int mix_cm_rep_out(mcm_scif_dev_t *smd, dat_mix_cm_t *pmsg, scif_epd_t scif_ep)
{
	int len, ret;
	struct mcm_cm *m_cm;
	struct ibv_qp *qp, *qp2 = NULL;
	union ibv_gid *dgid = NULL, *dgid2 = NULL;
	uint32_t dqpn = 0, dqpn2 = 0;
	uint16_t dlid = 0, dlid2 = 0;

	/* hdr already read, get operation data, support compat mode */
	if (smd->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_cm_compat_t) - sizeof(dat_mix_hdr_t);
	else
		len = sizeof(dat_mix_cm_t) - sizeof(dat_mix_hdr_t);

	ret = scif_recv(scif_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d\n", ret, len);
		return ret;
	}
	mlog(8, "dev_id %d mic_ctx %p my_id %d, my_ctx %p, qp_id %d, pmsg_sz=%d \n",
		smd->entry.tid,	pmsg->sp_ctx, pmsg->cm_id,
		(void*)pmsg->cm_ctx, pmsg->qp_id, sizeof(dat_mix_cm_t));

	/* Find the CM for this reply */
	m_cm = mix_get_cm(smd, pmsg->cm_id);
	if (!m_cm) {
		mlog(0, " ERR: mix_get_cm, id %d, not found\n", pmsg->cm_id);
		return -1;
	}
	mpxy_lock(&m_cm->lock);
	/* update CM message from MIX client, save clients id,ctx */
	m_cm->cm_id = 0; /* no client id for now, just ctx */
	m_cm->cm_ctx = pmsg->sp_ctx;
	m_cm->p_size = ntohs(pmsg->msg.p_size);
	memcpy(&m_cm->p_data, &pmsg->msg.p_data, m_cm->p_size);

	if (smd->md->mc->ver == MIX_COMP)
		memcpy(&m_cm->msg, &pmsg->msg, sizeof(dat_mcm_msg_compat_t));
	else
		memcpy(&m_cm->msg, &pmsg->msg, sizeof(dat_mcm_msg_t));

	/* Attach the QP for this CR */
	m_cm->m_qp = mix_get_qp(smd, pmsg->qp_id);
	if (!m_cm->m_qp) {
		mlog(0, " ERR: mix_get_qp, id %d, not found\n", pmsg->qp_id);
		mpxy_unlock(&m_cm->lock);
		return -1;
	}
	m_cm->ref_cnt++; /* Passive: QP ref */
	m_cm->m_qp->cm = m_cm;
	mcm_ntoh_wrc(&m_cm->m_qp->wrc_rem, (mcm_wrc_info_t *)m_cm->msg.p_proxy); /* save peer PI WRC info */
	if (m_cm->m_qp->wrc_rem.wr_sz > MCM_WR_RX_NO_DATA)
		m_cm->m_qp->p2p_data = DAT_MCM_P2P_INLINE;
	else
		m_cm->m_qp->p2p_data = 0;

	mlog(2, " WRC: m_qp %p - WR 0x%Lx rkey 0x%x ln %d, sz %d end %d"
		" WC 0x%Lx rkey 0x%x ln %d, sz %d end %d sg_po2 %d\n",
	     m_cm->m_qp, m_cm->m_qp->wrc.wr_addr, m_cm->m_qp->wrc.wr_rkey,
	     m_cm->m_qp->wrc.wr_len, m_cm->m_qp->wrc.wr_sz,
	     m_cm->m_qp->wrc.wr_end, m_cm->m_qp->wrc.wc_addr,
	     m_cm->m_qp->wrc.wc_rkey, m_cm->m_qp->wrc.wc_len,
	     m_cm->m_qp->wrc.wc_sz, m_cm->m_qp->wrc.wc_end,
	     m_cm->msg.seg_sz);

	mlog(2, " WRC_rem: WR 0x%Lx rkey 0x%x ln %d, sz %d end %d"
		" WC 0x%Lx rkey 0x%x ln %d, sz %d end %d p2p %d\n",
	     m_cm->m_qp->wrc_rem.wr_addr, m_cm->m_qp->wrc_rem.wr_rkey,
	     m_cm->m_qp->wrc_rem.wr_len, m_cm->m_qp->wrc_rem.wr_sz,
	     m_cm->m_qp->wrc_rem.wr_end, m_cm->m_qp->wrc_rem.wc_addr,
	     m_cm->m_qp->wrc_rem.wc_rkey, m_cm->m_qp->wrc_rem.wc_len,
	     m_cm->m_qp->wrc_rem.wc_sz, m_cm->m_qp->wrc_rem.wc_end,
	     m_cm->m_qp->p2p_data);

	/* MXS -> MSS or HOST, remote: need QPr1, saddr1 on mpxyd */
	if ((MXF_EP(&m_cm->md->addr) && !MXF_EP(&m_cm->msg.daddr1)) &&
	    (system_guid != m_cm->msg.sys_guid) ) {
		mlog(2, " MXS -> %s remote \n", mcm_map_str(m_cm->msg.daddr1.ep_map));

		if (m_qp_create_pi(smd, m_cm->m_qp))
			goto err;

		if (m_pi_prep_rcv_q(m_cm->m_qp))
			goto err;

		/* KR to KL or XEON, QP1<-QP2 and QP2->QP1 */
		/* update the src information in CM msg */
		m_cm->msg.saddr1.ep_map = smd->md->addr.ep_map;
		m_cm->msg.saddr1.qpn = htonl(m_cm->m_qp->ib_qp1->qp_num);
		m_cm->msg.saddr1.qp_type = m_cm->m_qp->qp_attr1.qp_type;
	        m_cm->msg.saddr1.lid = m_cm->smd->md->addr.lid;
		memcpy(&m_cm->msg.saddr1.gid[0], &m_cm->smd->md->addr.gid, 16);

		m_cm->msg.saddr2.ep_map = smd->md->addr.ep_map;
		m_cm->msg.saddr2.qpn = htonl(m_cm->m_qp->ib_qp2->qp_num);
		m_cm->msg.saddr2.qp_type = m_cm->m_qp->qp_attr2.qp_type;
	        m_cm->msg.saddr2.lid = m_cm->smd->md->addr.lid;
		memcpy(&m_cm->msg.saddr2.gid[0], &m_cm->smd->md->addr.gid, 16);

		/* local QPr to remote QPt */
		qp = m_cm->m_qp->ib_qp1;
		dgid = (union ibv_gid *)m_cm->msg.daddr2.gid;
		dqpn = m_cm->msg.daddr2.qpn;
		dlid = m_cm->msg.daddr2.lid;

		/* local QPt to remote QPr */
		qp2 = m_cm->m_qp->ib_qp2;
		dgid2 = (union ibv_gid *)m_cm->msg.daddr1.gid;
		dqpn2 = m_cm->msg.daddr1.qpn;
		dlid2 = m_cm->msg.daddr1.lid;

		/* QP1r onto RX PI thread queue */
		mpxy_lock(&smd->qprlock);
		insert_tail(&m_cm->m_qp->r_entry, &smd->qprlist, m_cm->m_qp);
		mpxy_unlock(&smd->qprlock);

	/* MXS -> MXS, proxy-in both sides, remote, 1 QP - already setup */
	} else if ((MXF_EP(&m_cm->md->addr) && MXF_EP(&m_cm->msg.daddr1)) &&
		   (system_guid != m_cm->msg.sys_guid)) {
		mlog(2, " MXS -> MXS remote \n");

		if (m_pi_prep_rcv_q(m_cm->m_qp))
			goto err;

		/* update the QPt src information in CM msg */
		m_cm->msg.saddr1.ep_map = smd->md->addr.ep_map;
		m_cm->msg.saddr2.ep_map = smd->md->addr.ep_map;
		m_cm->msg.saddr2.qpn = htonl(m_cm->m_qp->ib_qp2->qp_num);
		m_cm->msg.saddr2.qp_type = m_cm->m_qp->qp_attr2.qp_type;
		m_cm->msg.saddr2.lid = m_cm->smd->md->addr.lid;
		m_cm->msg.saddr1.lid = m_cm->smd->md->addr.lid; /* for cm rcv engine */
		memcpy(&m_cm->msg.saddr2.gid[0], &m_cm->smd->md->addr.gid, 16);

		qp = m_cm->m_qp->ib_qp2;
		dgid = (union ibv_gid *)m_cm->msg.daddr2.gid;
		dqpn = m_cm->msg.daddr2.qpn;
		dlid = m_cm->msg.daddr2.lid;

		/* QP2r onto RX PI thread queue */
		mpxy_lock(&smd->qprlock);
		insert_tail(&m_cm->m_qp->r_entry, &smd->qprlist, m_cm->m_qp);
		mpxy_unlock(&smd->qprlock);

	/* MXS -> MXS, proxy-in both sides, local, no QP's, SCIF services only */
	} else if ((MXF_EP(&m_cm->md->addr) && MXF_EP(&m_cm->msg.daddr1)) &&
		   (system_guid == m_cm->msg.sys_guid)) {
		mlog(2, " MXS -> MXS local - MODE NOT SUPPORTED, running MXS -> MXS remote mode\n");

		qp = m_cm->m_qp->ib_qp2;
		dgid = (union ibv_gid *)m_cm->msg.daddr2.gid;
		dqpn = m_cm->msg.daddr2.qpn;
		dlid = m_cm->msg.daddr2.lid;
		m_cm->msg.saddr1.ep_map = smd->md->addr.ep_map;
		m_cm->msg.saddr2.ep_map = smd->md->addr.ep_map;

	/* MSS -> MSS,MXS,HOST - fabric, TX: QP2->QP1 on mpxyd and RX: QP1->QP2 on MIC */
	} else {
		mlog(2, " MSS -> %s remote \n", mcm_map_str(m_cm->msg.daddr1.ep_map));

		/* KL to KL, QP1->QP2 and QP1<-QP2 */
		/* update the QPt src information in CM msg, QPr updated on MIC */
		m_cm->msg.saddr1.ep_map = smd->md->addr.ep_map;
		if (smd->md->m_lid) {
			m_cm->msg.saddr1.lid = smd->md->m_lid;
			memcpy(&m_cm->msg.saddr1.gid[0], &m_cm->smd->md->m_gid, 16);
		}
		m_cm->msg.saddr2.ep_map = smd->md->addr.ep_map;
		m_cm->msg.saddr2.qpn = htonl(m_cm->m_qp->ib_qp2->qp_num);
		m_cm->msg.saddr2.qp_type = m_cm->m_qp->qp_attr2.qp_type;
		m_cm->msg.saddr2.lid = m_cm->smd->md->addr.lid;
		memcpy(&m_cm->msg.saddr2.gid[0], &m_cm->smd->md->addr.gid, 16);

		qp = m_cm->m_qp->ib_qp2;
		dgid = (union ibv_gid *)m_cm->msg.daddr1.gid;
		dqpn = m_cm->msg.daddr1.qpn;
		dlid = m_cm->msg.daddr1.lid;

		if (MXF_EP(&m_cm->msg.daddr1)) {
			if (m_pi_create_wc_q(m_cm->m_qp, mcm_rx_entries))
				goto err;

			if (m_pi_prep_rcv_q(m_cm->m_qp))
				goto err;
		}
	}
	mcm_hton_wrc((mcm_wrc_info_t *)m_cm->msg.p_proxy, &m_cm->m_qp->wrc); /* send PI WRC info */
	m_cm->msg.seg_sz = mix_buffer_sg_po2;
	mcm_pr_addrs(2, &m_cm->msg, m_cm->state, 0);

	/* return sys_guid */
#ifdef MPXYD_LOCAL_SUPPORT
	m_cm->msg.sys_guid = system_guid;
#else
	m_cm->msg.sys_guid = rand();
#endif

	/* Set QP MTU, if negotiated. 2K for compatibility */
	m_cm->m_qp->mtu = m_cm->msg.mtu ?
			  min(m_cm->msg.mtu, smd->dev_attr.mtu):
			  smd->mtu_env ? smd->mtu_env : IBV_MTU_2048;

	if (qp) {
		if (mcm_modify_qp(qp, IBV_QPS_RTR, dqpn, dlid, dgid))
			goto err;

		if (mcm_modify_qp(qp, IBV_QPS_RTS, dqpn, dlid, NULL))
			goto err;
	}
	if (qp2) {
		if (mcm_modify_qp(qp2, IBV_QPS_RTR, dqpn2, dlid2, dgid2))
			goto err;

		if (mcm_modify_qp(qp2, IBV_QPS_RTS, dqpn2, dlid2, NULL))
			goto err;
	}

	/* send REP on wire, monitor for retries */
	m_cm->state = MCM_RTU_PENDING;
	m_cm->msg.mtu = m_cm->m_qp->mtu; /* send negotiated MTU */
	mpxy_unlock(&m_cm->lock);
	mcm_cm_rep_out(m_cm);
	return 0;
err:
	mlog(0," ERR: QPt 0x%x -> d_port 0x%x, cqpn %x QPr %x lid 0x%x psize %d\n",
	      m_cm->m_qp->qp_attr2.qp_num,
	      ntohs(m_cm->msg.dport), ntohl(m_cm->msg.dqpn),
	      ntohl(dqpn), ntohs(dlid), ntohs(m_cm->msg.p_size));

	mlog(0," ERR: QPr 0x%x -> d_port 0x%x, cqpn %x QPt %x lid 0x%x\n",
	      m_cm->m_qp->qp_attr1.qp_num,
	      ntohs(m_cm->msg.dport), ntohl(m_cm->msg.dqpn),
	      ntohl(dqpn), ntohs(dlid));

	mcm_pr_addrs(0, &m_cm->msg, m_cm->state, 0);
	mpxy_unlock(&m_cm->lock);
	return -1;
}

/* PASSIVE, user reject from MIX client */
static int mix_cm_rej_out(mcm_scif_dev_t *smd, dat_mix_cm_t *pmsg, scif_epd_t scif_ep)
{
	int len, ret;
	struct mcm_cm *m_cm;

	/* hdr already read, get operation data, support compat mode */
	if (smd->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_cm_compat_t) - sizeof(dat_mix_hdr_t);
	else
		len = sizeof(dat_mix_cm_t) - sizeof(dat_mix_hdr_t);

	ret = scif_recv(scif_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: ret %d, exp %d\n", ret, len);
		return ret;
	}

	/* Find the CM for linking */
	m_cm = mix_get_cm(smd, pmsg->cm_id);
	if (!m_cm) {
		mlog(0, " ERR: mix_get_cm, id %d, not found\n", pmsg->cm_id);
		return -1;
	}
	mlog(2, " MIX_CM_REJ_OUT: dev_id %d cm_id %d, cm_ctx %p, qp_id %d m_cm %p\n",
		smd->entry.tid, pmsg->cm_id, (void*)pmsg->cm_ctx, pmsg->qp_id, m_cm);

	/* update CM message from MIX client, send back guid */
	if (smd->md->mc->ver == MIX_COMP)
		memcpy(&m_cm->msg, &pmsg->msg, sizeof(dat_mcm_msg_compat_t));
	else
		memcpy(&m_cm->msg, &pmsg->msg, sizeof(dat_mcm_msg_t));

#ifdef MPXYD_LOCAL_SUPPORT
	m_cm->msg.sys_guid = system_guid;
#else
	m_cm->msg.sys_guid = rand();
#endif
	/* send rej on wire */
	m_cm->state = MCM_REJECTED;
	mcm_cm_rej_out(smd->md, &m_cm->msg, MCM_REJ_USER, 0);
	mcm_dqconn_free(smd, m_cm); /* dequeue and free */
	return 0;
}

/* disconnect request from peer, unsolicited channel */
int mix_cm_disc_in(mcm_cm_t *m_cm)
{
	dat_mix_hdr_t msg;
	int len;

	/* send disconnect to MIC client */
	msg.ver = m_cm->md->mc->ver;
	msg.flags = MIX_OP_REQ;
	msg.op = MIX_CM_DISC;
	msg.req_id = m_cm->cm_id;

	/* support compat mode */
	if (m_cm->md->mc->ver == MIX_COMP)
		len = sizeof(dat_mix_cm_compat_t);
	else
		len = sizeof(dat_mix_cm_t);

	mpxy_lock(&m_cm->smd->evlock);
	if (scif_send_msg(m_cm->smd->scif_ev_ep, (void*)&msg, len)) {
		return -1;
		mpxy_unlock(&m_cm->smd->evlock);
	}
	mpxy_unlock(&m_cm->smd->evlock);
	return 0;
}

/* Post SEND message request, IB send or rdma write, proxy out to remote direct endpoint */
static int mix_proxy_out(mcm_scif_dev_t *smd, dat_mix_sr_t *pmsg, mcm_qp_t *m_qp)
{
	int len, ret = 0, l_start, l_end, retries, wc_err = IBV_WC_GENERAL_ERR;
	struct mcm_wr *m_wr;

	if (!(pmsg->hdr.flags & MIX_OP_INLINE))
		return (m_po_proxy_data(smd, pmsg, m_qp));

	if (pmsg->wr.opcode == IBV_WR_SEND)
		MCNTR(smd->md, MCM_MX_SEND_INLINE);
	else
		MCNTR(smd->md, MCM_MX_WRITE_INLINE);

	len = pmsg->len;

	mpxy_lock(&m_qp->txlock);
	if (((m_qp->wr_hd + 1) & m_qp->wr_end) == m_qp->wr_tl) { /* full */
		ret = ENOMEM;
		mlog(0, " ERR: WR full hd %d tl %d\n", m_qp->wr_hd, m_qp->wr_tl);
		goto bail;
	}
	m_qp->wr_hd = (m_qp->wr_hd + 1) & m_qp->wr_end; /* move hd */
	m_wr = (struct mcm_wr *)(m_qp->wr_buf + (m_qp->wr_sz * m_qp->wr_hd));

	/* IB rdma write WR */
	const_ib_rw(&m_wr->wr, &pmsg->wr, m_wr->sg);
	m_wr->wr.sg_list = m_wr->sg;
	m_wr->wr.num_sge = len ? 1:0;

	/* M_WR */
	m_wr->org_id = pmsg->wr.wr_id;
	m_wr->m_idx = 0;
	m_wr->w_idx = m_qp->wr_hd;
	m_wr->flags = (M_SEND_INLINE | M_SEND_FS | M_SEND_LS);
	m_wr->context = (uint64_t)m_qp;

	mpxy_lock(&smd->tblock);
	retries = 0;

retry_mr:
	l_start = ALIGN_64(smd->m_hd);
	if ((l_start + len) > smd->m_len)
		l_start = 64;
	l_end = l_start + len;

	if (pb_full(l_start, l_end, smd->m_hd, smd->m_tl, len, smd->m_len)) {
		if (!retries) {
			MCNTR(smd->md, MCM_MX_MR_STALL);
			write(smd->md->mc->tx_pipe[1], "w", sizeof("w"));
		}
		if (!(++retries % 100)) {
			mlog(1, " [%d:%d:%d] WARN: inline DTO delay, no memory,"
				" %x hd 0x%x tl 0x%x %x need 0x%x-0x%x ln %d,"
				" retries = %d -> %s\n",
				m_qp->smd->md->mc->scif_id,
				m_qp->smd->entry.tid, m_qp->r_entry.tid,
				smd->m_buf, smd->m_hd, smd->m_tl,
				smd->m_buf + smd->m_len, l_start,
				l_end, len, retries,
				mcm_map_str(m_qp->cm->msg.daddr1.ep_map));
			mlog(1," [%d:%d:%d] WR tl %d idx %d hd %d QP pst %d,%d cmp %d - %s\n",
				m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid, m_qp->r_entry.tid,
				m_qp->wr_tl, m_wr->w_idx, m_qp->wr_hd,
				m_qp->post_cnt, m_qp->post_sig_cnt, m_qp->comp_cnt,
				mcm_map_str(m_qp->cm->msg.daddr1.ep_map));
			mcm_pr_addrs(1, &m_qp->cm->msg, m_qp->cm->state, 0);
		}
		if (retries == 2000) {
			mlog(0, " ERR: send inline stalled, no bufs, hd %d tl %d ln %d\n",
						smd->m_hd, smd->m_tl, len);
			ret = ENOMEM;
			wc_err = IBV_WC_RETRY_EXC_ERR;
			mpxy_unlock(&smd->tblock);
			goto bail;
		}
		mpxy_unlock(&smd->tblock);
		mpxy_unlock(&m_qp->txlock);
		sched_yield();
		mpxy_lock(&m_qp->txlock);
		mpxy_lock(&smd->tblock);
		goto retry_mr;
	}

	if (retries) {
		mlog(1, " MEM stalled: %x hd 0x%x tl 0x%x %x got 0x%x-0x%x"
			" ln %d retried %d\n",
			smd->m_buf, smd->m_hd, smd->m_tl,
			smd->m_buf + smd->m_len, l_start, len, retries);
	}
#ifdef MCM_PROFILE
	if (l_end < smd->m_hd)
		smd->m_hd_ro++;
#endif
	m_wr->sg->addr = (uint64_t)(smd->m_buf + l_start);
	m_wr->sg->lkey = smd->m_mr->lkey;
	m_wr->sg->length = len;
	smd->m_hd = l_end; /* move proxy buffer hd */

	if (m_wr->wr.send_flags & IBV_SEND_SIGNALED)
		m_wr->flags |= M_SEND_CN_SIG;

	/* MP service signaling, set PO mbuf tail adjustment */
	if (!((m_wr->w_idx) % mcm_rw_signal) || m_wr->flags & M_SEND_LS) {
		char *sbuf = (char*)m_wr->wr.sg_list->addr;

		m_wr->flags |= M_SEND_MP_SIG;
		m_wr->wr.send_flags |= IBV_SEND_SIGNALED;
		m_wr->m_idx = (sbuf + (len - 1)) - smd->m_buf;
		if (m_po_buf_hd(smd, m_wr->m_idx, m_wr)) {
			mpxy_unlock(&smd->tblock);
			goto bail;
		}
	}
	mpxy_unlock(&smd->tblock);

	if (len) {
		/* copy data into proxy buffer, signal TX thread via wr_id */
		if (smd->mm_s_peer_addr_off != SCIF_REGISTER_FAILED && pmsg->hdr.op == MIX_SEND) {
			/* inline data is after the msg */
			memcpy((void*)m_wr->sg->addr, pmsg + 1, len);
		} else {
			ret = scif_recv(smd->scif_op_ep, (void*)m_wr->sg->addr, len, SCIF_RECV_BLOCK);
			if (ret != len) {
				mlog(0, " ERR: scif_recv inline DATA, ret %d, exp %d\n", ret, len);
				ret = errno;
				len = 0;
				goto bail;
			}
		}
	}

	if ((smd->md->indata) && (len <= mcm_ib_inline))
		m_wr->wr.send_flags |= IBV_SEND_INLINE;

	/* signal TX, CQ thread, this WR data ready, post pending */
	m_qp->wr_pp++;
	m_wr->wr.wr_id = pmsg->wr.wr_id;
	ret = 0;
bail:
	mpxy_unlock(&m_qp->txlock);
	write(smd->md->mc->tx_pipe[1], "w", sizeof("w")); /* signal tx_thread */
	if (ret) {
		struct dat_mix_wc wc;
		char dbuf[DAT_MIX_INLINE_MAX];

		if (len && !(smd->mm_s_peer_addr_off != SCIF_REGISTER_FAILED && pmsg->hdr.op == MIX_SEND)) {
			 /* drain inline data */
			scif_recv(smd->scif_op_ep, dbuf, len, SCIF_RECV_BLOCK);
		}

		wc.wr_id = pmsg->wr.wr_id;
		wc.byte_len = len;
		wc.status = wc_err;
		wc.opcode = pmsg->wr.opcode == IBV_WR_SEND ? IBV_WC_SEND:IBV_WC_RDMA_WRITE;
		wc.vendor_err = ret;
		mix_dto_event(m_qp->ib_qp2->send_cq->cq_context, &wc, 1);
	}
	sched_yield();
	return ret;
}

/* Post SEND message request, IB send or rdma write, operation channel Via scif send*/
static int mix_post_send(mcm_scif_dev_t *smd, dat_mix_sr_t *pmsg)
{
	int len, ret;
	struct mcm_qp *m_qp;

	/* hdr already read, get operation data */
	len = sizeof(dat_mix_sr_t) - sizeof(dat_mix_hdr_t);
	ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: scif_recv WR, ret %d, exp %d\n", ret, len);
		return POLLERR;
	}

	/* get QP by ID */
	m_qp = mix_get_qp(smd, pmsg->qp_id);
	if (!m_qp || !m_qp->ib_qp2) {
		mlog(0, " ERR: mix_get_qp, id %d, not found\n", pmsg->qp_id);
		if ((pmsg->hdr.flags & MIX_OP_INLINE) && pmsg->len) { /* purge data, send event */
			char dbuf[DAT_MIX_INLINE_MAX];

			ret = scif_recv(smd->scif_op_ep, (void*)dbuf, pmsg->len, SCIF_RECV_BLOCK);
			if (ret != len) {
				mlog(0, " ERR: scif_recv inline DATA, ret %d, exp %d\n", ret, len);
				return -1;
			}
		}
		return POLLERR; /* device async err, cannot report event with no QP */
	}

	mlog(4, " [%d:%d:%d] id %d qpn %x data %d pkt %d wr_id %p, sge %d,"
		" op %x flgs %x pst %d,%d cmp %d, inl %d, %s %s\n",
		m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid,
		m_qp->r_entry.tid,pmsg->qp_id, m_qp->ib_qp2->qp_num, pmsg->len,
		pmsg->hdr.flags & MIX_OP_INLINE ?
		  sizeof(dat_mix_sr_t) + pmsg->len : sizeof(dat_mix_sr_t),
		pmsg->wr.wr_id,
		pmsg->wr.num_sge, pmsg->wr.opcode, pmsg->wr.send_flags,
		m_qp->post_cnt,	m_qp->post_sig_cnt, m_qp->comp_cnt,
		pmsg->hdr.flags & MIX_OP_INLINE ? 1:0,
		pmsg->wr.opcode == IBV_WR_SEND ? "SND":"RW",
		m_qp->wrc_rem.wr_len ? "PROXY_OUT_IN":"PROXY_OUT");

	return (mix_proxy_out(smd, pmsg, m_qp));
}

/* Post SEND message request, IB send or rdma write, operation channel Via scif mmap memory */
int mix_post_send_ext(mcm_scif_dev_t *smd)
{
	int ret, retry, max_io = 32;
	struct mcm_qp *m_qp;
	dat_mix_mmap_wr_t *mm_wr_entry;
	volatile dat_mix_sr_t *pmsg;

	while (max_io--) {
		retry = 100;
		mm_wr_entry = &smd->mm_r_addr[smd->mm_r_head];
		pmsg = &mm_wr_entry->msg;

		/* wait little for SEND OP msg */
		while(retry-- && !mm_wr_entry->flags) {
			if(!retry)
				return 0;
			sched_yield();
		}

		if (pmsg->hdr.op != MIX_SEND) {
			mlog(0, " ERR: no MIX_SEND OP CODE? Got %d, exp %d\n",
				pmsg->hdr.op, MIX_SEND);
			return -1;
		}

		/* get QP by ID */
		m_qp = mix_get_qp(smd, pmsg->qp_id);
		if (!m_qp || !m_qp->ib_qp2) {
			mlog(0, " ERR: mix_get_qp id %d not found\n",
				pmsg->qp_id);
			return POLLERR; /* async err, no QP to report */
		}

		ret = mix_proxy_out(smd, (dat_mix_sr_t *)pmsg, m_qp);

		/* Mark entry empty, update local head and MIC head */
		mm_wr_entry->flags = 0;
		smd->mm_r_head = ((smd->mm_r_head + 1) % smd->mm_r_last);

		if(smd->mm_s_peer_addr)
			*smd->mm_s_peer_addr = smd->mm_r_head;

		if (ret) {
			mlog(0, " ERR: failed mix proxy out. ret %d\n", ret);
			return ret;
		}
	}

	return 0;
}

/* Post RECV message request on Proxy-RX channel */
static int mix_post_recv(mcm_scif_dev_t *smd, dat_mix_sr_t *pmsg)
{
	int i, len, ret;
	struct mcm_qp *m_qp;
	struct mcm_sr *m_sr;
	struct dat_mix_wc wc;

	/* hdr already read, get operation data */
	ret = -1;
	len = sizeof(dat_mix_sr_t) - sizeof(dat_mix_hdr_t);
	ret = scif_recv(smd->scif_op_ep, ((char*)pmsg + sizeof(dat_mix_hdr_t)), len, SCIF_RECV_BLOCK);
	if (ret != len) {
		mlog(0, " ERR: scif_recv WR, ret %d, exp %d\n", ret, len);
		return -1;
	}

	/* get QP by ID */
	m_qp = mix_get_qp(smd, pmsg->qp_id);
	if (!m_qp) {
		mlog(0, " ERR: mix_get_qp, id %d, not found\n", pmsg->qp_id);
		goto err;
	}

	mlog(4, " q_id %d, q_num %x data %d pkt %d wr_id %p, sge %d\n",
		pmsg->qp_id, m_qp->ib_qp2->qp_num, pmsg->len,
		sizeof(dat_mix_sr_t) + pmsg->len, pmsg->wr.wr_id,
		pmsg->wr.num_sge, m_qp->post_sr);

	/* Post WR on Rx Queue and let RX thread process */
	mpxy_lock(&m_qp->rxlock);
	m_sr = (struct mcm_sr *)(m_qp->sr_buf + (m_qp->sr_sz * m_qp->sr_hd));
	m_sr->wr_id = pmsg->wr.wr_id;
	m_sr->s_idx = m_qp->sr_hd;
	m_sr->w_idx = m_sr->m_idx = 0; /* no WR proxy data bindings */
	m_sr->num_sge = pmsg->wr.num_sge;
	memcpy(m_sr->sg, pmsg->sge, sizeof(struct dat_mix_sge) * m_sr->num_sge);

	for (i=0; i< m_sr->num_sge; i++) {
		mlog(4, " m_sr[%d] %p -> sg[%d] scif l_off %Lx len %d lkey %x\n",
			m_qp->sr_hd, m_sr, i, m_sr->sg[i].addr,
			m_sr->sg[i].length, m_sr->sg[i].lkey);
	}
	/* took SR slot */
	if (++m_qp->sr_hd == m_qp->sr_end)
		m_qp->sr_hd = 0;

	mpxy_unlock(&m_qp->rxlock);
	return 0;
err:
	wc.wr_id = pmsg->wr.wr_id;
	wc.byte_len = 0;
	wc.status = IBV_WC_GENERAL_ERR;
	wc.opcode = pmsg->wr.opcode == IBV_WC_RECV;
	wc.vendor_err = EINVAL;
	mix_dto_event(m_qp->ib_qp2->recv_cq->cq_context, &wc, 1);
	return 0;
}

/* receive data on connected SCIF endpoints, operation and unsolicited channels,  */
int mix_scif_recv(mcm_scif_dev_t *smd, scif_epd_t scif_ep)
{
	dat_mix_hdr_t *phdr = (dat_mix_hdr_t *)smd->cmd_buf;
	int ret, len;

	len = sizeof(*phdr);
	phdr->ver = 0; phdr->op = 0;
	ret = scif_recv(scif_ep, phdr, len, SCIF_RECV_BLOCK);
	if ((ret != len) || (phdr->ver < MIX_MIN) || (phdr->ver > MIX_MAX)) {
		mlog(0,
		     " ERR: smd %p ep %d ret %d exp %d ver %d op %s flgs %d\n",
		     smd, scif_ep, ret, len, phdr->ver, mix_op_str(phdr->op),
		     phdr->flags);
		return -1;
	}
	mlog(8, " dev_id %d scif_ep %d, %d bytes: ver %d, op %s, flgs %d id %d\n",
	     smd->entry.tid, scif_ep, len, phdr->ver, mix_op_str(phdr->op),
	     phdr->flags, phdr->req_id);

	switch (phdr->op) {
	case MIX_MR_CREATE:
		ret = mix_mr_create(smd, (dat_mix_mr_t *)phdr);
		break;
	case MIX_MR_FREE:
		ret = mix_mr_free(smd, (dat_mix_mr_t *)phdr);
		break;
	case MIX_QP_CREATE:
		ret = mix_qp_create(smd, (dat_mix_qp_t *)phdr);
		break;
	case MIX_QP_MODIFY:
		ret = mix_qp_modify(smd, (dat_mix_qp_t *)phdr);
		break;
	case MIX_QP_FREE:
		ret = mix_qp_destroy(smd, phdr);
		break;
	case MIX_PZ_CREATE:
		ret = mix_pz_create(smd, (dat_mix_pz_t *)phdr);
		break;
	case MIX_PZ_FREE:
		ret = mix_pz_destroy(smd, (dat_mix_pz_t *)phdr);
		break;
	case MIX_CQ_CREATE:
		ret = mix_cq_create(smd, (dat_mix_cq_t *)phdr);
		break;
	case MIX_CQ_FREE:
		ret = mix_cq_destroy(smd, phdr);
		break;
	case MIX_CQ_POLL:
		ret = 0; /* no-op */
		break;
	case MIX_SEND:
		ret = mix_post_send(smd, (dat_mix_sr_t *)phdr);
		break;
	case MIX_RECV:
		ret = mix_post_recv(smd, (dat_mix_sr_t *)phdr);
		break;
	case MIX_LISTEN:
		ret = mix_listen(smd, (dat_mix_listen_t *)phdr);
		break;
	case MIX_LISTEN_FREE:
		ret = mix_listen_free(smd, phdr);
		break;
	case MIX_PROV_ATTR:
		ret = mix_prov_attr(smd, (dat_mix_attr_t *)phdr);
		break;
	case MIX_QUERY_DEVICE:
		ret = mix_query_device(smd, (dat_mix_device_attr_t *)phdr);
		break;
	case MIX_QUERY_PORT:
		ret = mix_query_port(smd, (dat_mix_port_attr_t *)phdr);
		break;
	case MIX_CM_REQ:
		ret = mix_cm_req_out(smd, (dat_mix_cm_t *)phdr, scif_ep);
		break;
	case MIX_CM_REP:
	case MIX_CM_ACCEPT:
		ret = mix_cm_rep_out(smd, (dat_mix_cm_t *)phdr, scif_ep);
		break;
	case MIX_CM_REJECT:
		ret = mix_cm_rej_out(smd, (dat_mix_cm_t *)phdr, scif_ep);
		break;
	case MIX_CM_RTU:
	case MIX_CM_EST:
		ret = mix_cm_rtu_out(smd, (dat_mix_cm_t *)phdr, scif_ep);
		break;
	case MIX_CM_DISC:
		ret = mix_cm_disc_out(smd, (dat_mix_cm_t *)phdr, scif_ep);
		break;
	case MIX_MMAP_ALLOC:
		ret = mix_mmap_alloc(smd, (dat_mix_mmap_addr_t *)phdr);
		break;
	case MIX_MMAP_FREE:
		ret = mix_mmap_free(smd, (dat_mix_mmap_addr_t *)phdr);
		break;
	case MIX_CM_DREP:
	default:
		mlog(0, " ERR: smd %p unknown msg->op: %d, close dev_id %d\n",
			smd, phdr->op, smd->entry.tid);
		return -1;
	}
	MCNTR(smd->md, MCM_SCIF_RECV);
	return ret;
}





