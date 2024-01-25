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
#include "mpxyd.h"

scif_epd_t scif_listen_ep;
struct scif_portID scif_id;
short scif_sport = SCIF_OFED_PORT_8;
int scif_listen_qlen = 240;
int mix_buffer_mb = 32;
int mix_buffer_sg = 131072;
int mix_buffer_sg_po2 = DAT_MCM_SEG_PO2;   /* 128 KB */
int mcm_set_priority = 0; /* set to SCHED_FIFO */
int mcm_affinity = 1;
int mcm_op_poll = 0;
int mcm_affinity_base_mic = 0;
int mcm_affinity_base_hca = 0;
int mcm_counters = 0;
int mcm_cpu_model = 0;
int mcm_cpu_family = 0;
uint64_t system_guid = 0; /* network order */

extern int mix_max_msg_mb;
extern int mcm_tx_entries;
extern int mcm_rx_entries;
extern int mcm_ib_inline;
extern char *lock_file;
extern char *log_file;
extern char *opts_file;
extern FILE *logfile;
extern mpxy_lock_t flock;
extern char gid_str[INET6_ADDRSTRLEN];

#define MCM_NNODES 8

static mcm_client_t mcm_client_list[MCM_CLIENT_MAX];
static int mcm_cpumask[MCM_NNODES];
static mpxy_lock_t mcm_cplock;

void mcm_check_io();

/*
 * mpxyd service - mpxyd.c
 *
 * 	MIC proxy service for uDAPL rdma write, message send/recv
 *
 * 	init SCI services, listen on well-known port service
 * 	create/manage thread pool for each MIC (op, cm, tx, rx)
 * 	open/manage IB devices per client device open
 */

/* main service entry point for all MIC clients */
static int init_scif()
{
	int i,ii,ret;
	mcm_client_t *mc;
	mcm_ib_dev_t *md;

	mpxy_lock_init(&mcm_cplock, NULL);
	for (i=0;i<MCM_NNODES;i++)
		mcm_cpumask[i] = -1;

	/* initialize client list and associated devices to init state */
	for (i=0; i<MCM_CLIENT_MAX; i++) {
		mc = &mcm_client_list[i];
		mc->scif_id = 0;
		if (pipe(mc->op_pipe) || pipe(mc->tx_pipe) ||
		    pipe(mc->cm_pipe) || pipe(mc->rx_pipe))
			return -1;

		/* non-blocking */
		mcm_config_fd(mc->op_pipe[0]);
		mcm_config_fd(mc->op_pipe[1]);
		mcm_config_fd(mc->tx_pipe[0]);
		mcm_config_fd(mc->tx_pipe[1]);
		mcm_config_fd(mc->cm_pipe[0]);
		mcm_config_fd(mc->cm_pipe[1]);
		mcm_config_fd(mc->rx_pipe[0]);
		mcm_config_fd(mc->rx_pipe[1]);

		mpxy_lock_init(&mc->oplock, NULL);
		mpxy_lock_init(&mc->txlock, NULL);
		mpxy_lock_init(&mc->cmlock, NULL);
		mpxy_lock_init(&mc->rxlock, NULL);
		for (ii=0; ii< MCM_IB_MAX; ii++) {
			md = &mc->mdev[ii];
			memset((void *)md, 0, sizeof(mcm_ib_dev_t));
		}
	}

	ret = scif_get_nodeIDs(NULL, 0, &scif_id.node);
	if (ret < 0) {
		mlog(0, "scif_get_nodeIDs() failed with error %d\n", strerror(errno));
		return -1;
	}
	mlog(8," SCIF node_id: %d, scif node count =%d\n", (uint16_t)scif_id.node, ret);
	if (scif_id.node != 0) {
		mlog(0,"ERROR scif node_id must be 0, get_nodeID = %d\n", (uint16_t)scif_id.node);
		return -1;
	}

	scif_listen_ep = scif_open();
	if (scif_listen_ep < 0) {
		mlog(0, "scif_open() failed with error %s\n", strerror(errno));
		return -1;
	}
	mlog(8,"Opened SCIF endpoint for OPERATIONS listening, ep = %d\n", scif_listen_ep);

	ret = scif_bind(scif_listen_ep, scif_sport);
	if (ret < 0) {
		mlog(0, "scif_bind() to %d failed with error %s\n", scif_sport, strerror(errno));
		scif_close(scif_listen_ep);
		return -1;
	}

	scif_id.port = ret;

	ret = scif_listen(scif_listen_ep, scif_listen_qlen);
	if (ret < 0) {
		mlog(0, "scif_listen() failed with error %s\n", strerror(errno));
		scif_close(scif_listen_ep);
		return -1;
	}
	mlog(1," MPXYD: Listening on reserved SCIF OFED port %d, backlog %d\n",
		(uint16_t)scif_id.port, scif_listen_qlen);

	return 0;
}

static void close_scif()
{
	scif_close(scif_listen_ep);
}

static void close_ib()
{
	int i,ii;
	mcm_client_t *mc;
	mcm_ib_dev_t *md;

	/* clean up device resources */
	for (i=0; i<MCM_CLIENT_MAX; i++) {
		mc = &mcm_client_list[i];
		for (ii=0; ii< MCM_IB_MAX; ii++) {
			md = &mc->mdev[ii];
			if (md->cntrs) {
				free(md->cntrs);
				md->cntrs = NULL;
			}
			if (md->ibctx) {
				ibv_close_device(md->ibctx);
				md->ibctx = NULL;
				md->ibdev = NULL;
			}
		}
	}
	return;
}

/* Open IB device */
static struct ibv_context *open_ib_device(struct mcm_ib_dev *md, char *name, int port)
{
	int i, ibcnt;
	struct ibv_device **iblist;
	struct ibv_context *ibctx = NULL;
	struct ibv_port_attr port_attr;

	/* get list of all IB devices */
	iblist = ibv_get_device_list(&ibcnt);
	if (!iblist) {
		mlog(0,"ERR ibv_get_dev_list, %s\n", strerror(errno));
		return NULL;
	}

	for (i=0; i < ibcnt; ++i) {
		/* system GUID set to first IB device GUID */
		if (!system_guid && iblist[i]->transport_type == IBV_TRANSPORT_IB) {
			system_guid = ibv_get_device_guid(iblist[i]);
			mlog(0, "System GUID == %04x:%04x:%04x:%04x\n",
				(unsigned) (system_guid >> 48) & 0xffff,
				(unsigned) (system_guid >> 32) & 0xffff,
				(unsigned) (system_guid >> 16) & 0xffff,
				(unsigned) (system_guid >>  0) & 0xffff);
		}
		if (!strcmp(iblist[i]->name, name)) {
			ibctx = ibv_open_device(iblist[i]);
			if (!ibctx) {
				mlog(0,"ERR ibv_open, %s\n", strerror(errno));
				goto bail;
			}
			if (ibv_query_port(ibctx, port, &port_attr)) {
				mlog(0,"ERR ibv_query, %s\n", strerror(errno));
				ibv_close_device(ibctx);
				ibctx = NULL;
				goto bail;
			}
			else {
				char val[64];
				struct ibv_device_attr device_attr;

				if (ibv_query_device(ibctx, &device_attr)) {
					mlog(0,"ERR ibv_device, %s\n", strerror(errno));
					ibv_close_device(ibctx);
					ibctx = NULL;
					goto bail;
				}
				md->dev_attr.mtu = port_attr.active_mtu;
				md->dev_attr.rd_atom_in = device_attr.max_qp_rd_atom;
				md->dev_attr.rd_atom_out = device_attr.max_qp_init_rd_atom;
				md->ibdev = iblist[i];
				if (!rd_dev_file(md->ibdev->ibdev_path,
				    "device/numa_node", val, sizeof val))
					md->numa_node = atoi(val);
				else if (!strncmp(name, "scif", 4))
					md->numa_node = md->mc->numa_node; /* intra-node, MSS */
				else
					mlog(0," ERR ibdev %s numa_node at "
					     "%s/device/numa_node unreadable\n",
					      name, md->ibdev->ibdev_path);

				if (mcm_ib_inline_data(ibctx) && mcm_ib_inline)
					md->indata = 1;

				break;
			}
		}
		else {
			continue;
		}
	}
bail:
	ibv_free_device_list(iblist);
	return ibctx;
}

void mcm_destroy_md(struct mcm_ib_dev *md)
{
	if (md->mr_sbuf)
		ibv_dereg_mr(md->mr_sbuf);

	if (md->mr_rbuf)
		ibv_dereg_mr(md->mr_rbuf);

	if (md->qp)
		ibv_destroy_qp(md->qp);

	if (md->scq)
		ibv_destroy_cq(md->scq);

	if (md->rcq)
		ibv_destroy_cq(md->rcq);

	if (md->rch)
		ibv_destroy_comp_channel(md->rch);

 	if (md->ah) {
		int i;

		for (i = 0;i < 0xffff; i++) {
			if (md->ah[i])
				ibv_destroy_ah(md->ah[i]);
		}
		free(md->ah);
	}

	if (md->pd)
		ibv_dealloc_pd(md->pd);

	if (md->ports)
		free(md->ports);

	if (md->rbuf)
		free(md->rbuf);

	if (md->sbuf)
		free(md->sbuf);

	if (md->ibctx)
		ibv_close_device(md->ibctx);

	memset((void *)md, 0, sizeof(mcm_ib_dev_t));
	return;
}

void destroy_smd_send_op_mmap(mcm_scif_dev_t *smd)
{
	if (smd->mm_r_addr_off != SCIF_REGISTER_FAILED && smd->scif_op_ep) {
		scif_unregister(smd->scif_op_ep, smd->mm_r_addr_off, smd->mm_r_len);
		smd->mm_r_addr_off = SCIF_REGISTER_FAILED;
	}

	if (smd->mm_r_addr) {
		free(smd->mm_r_addr);
		smd->mm_r_addr = NULL;
	}

	if (smd->mm_s_peer_addr > (int *)0 && smd->scif_op_ep) {
		scif_munmap((void *)smd->mm_s_peer_addr, ALIGN_PAGE(sizeof(int)));
		smd->mm_s_peer_addr = NULL;
	}

	if (smd->mm_s_place_holder) {
		free(smd->mm_s_place_holder);
		smd->mm_s_place_holder = NULL;
	}
}

void mpxy_destroy_bpool(mcm_scif_dev_t *smd)
{
	if (smd->m_offset && smd->scif_tx_ep)
		scif_unregister(smd->scif_tx_ep, smd->m_offset, smd->m_len);
	if (smd->m_offset_r && smd->scif_tx_ep)
		scif_unregister(smd->scif_tx_ep, smd->m_offset_r, smd->m_len_r);
	if (smd->m_mr)
		ibv_dereg_mr(smd->m_mr);
	if (smd->m_mr_r)
		ibv_dereg_mr(smd->m_mr_r);
	if (smd->m_buf)
		free (smd->m_buf);
	if (smd->m_buf_r)
		free (smd->m_buf_r);
	if (smd->m_buf_wc_r)
		free(smd->m_buf_wc_r);
	if (smd->m_buf_wc)
		free(smd->m_buf_wc);
}

/* destroy SMD, md->slock held */
void mpxy_destroy_smd(mcm_scif_dev_t *smd)
{
	mcm_cm_t *m_cm, *next_cm;
	mcm_qp_t *m_qp, *next_qp;
	mcm_cq_t *m_cq, *next_cq;
	mcm_mr_t *m_mr, *next_mr;

	if (smd->entry.tid)
		remove_entry(&smd->entry); /* remove off md->smd_list */

	/* free cm_id port */
	if (smd->cm_id) {
		mpxy_lock(&smd->md->plock);
		mcm_free_port(smd->md->ports, smd->cm_id);
		mpxy_unlock(&smd->md->plock);
		smd->cm_id = 0;
	}

	/* free all listen objects */
	mpxy_lock(&smd->llock);
	m_cm = get_head_entry(&smd->llist);
	while (m_cm) {
		next_cm = get_next_entry(&m_cm->entry, &smd->llist);
		mpxy_unlock(&smd->llock);
		mcm_dqlisten_free(smd, m_cm); /* dequeue and free */
		mpxy_lock(&smd->llock);
		m_cm = next_cm;
	}
	init_list(&smd->llist);
	mpxy_unlock(&smd->llock);
	mlog(8, " cm listen list destroyed \n");

	/* free all CM, QP, CQ objects and then port space */
	mpxy_lock(&smd->clock);
	m_cm = get_head_entry(&smd->clist);
	while (m_cm) {
		next_cm = get_next_entry(&m_cm->entry, &smd->clist);
		mpxy_unlock(&smd->clock);
		mcm_dqconn_free(smd, m_cm); /* dequeue and free */
		mpxy_lock(&smd->clock);
		m_cm = next_cm;
	}
	init_list(&smd->clist);
	mpxy_unlock(&smd->clock);
	mlog(8, " cm connection list destroyed \n");

	mpxy_lock(&smd->qptlock);
	m_qp = get_head_entry(&smd->qptlist);
	while (m_qp) {
		next_qp = get_next_entry(&m_qp->t_entry, &smd->qptlist);
		m_qp_free(m_qp);
		m_qp = next_qp;
	}
	init_list(&smd->qptlist);
	mpxy_unlock(&smd->qptlock);
	mlog(8, " qpt_list destroyed \n");

	mpxy_lock(&smd->qprlock);
	m_qp = get_head_entry(&smd->qprlist);
	while (m_qp) {
		next_qp = get_next_entry(&m_qp->r_entry, &smd->qprlist);
		m_qp_free(m_qp);
		m_qp = next_qp;
	}
	init_list(&smd->qprlist);
	mpxy_unlock(&smd->qprlock);
	mlog(8, " qpr_list destroyed \n");

	mpxy_lock(&smd->cqlock);
	m_cq = get_head_entry(&smd->cqlist);
	while (m_cq) {
		next_cq = get_next_entry(&m_cq->entry, &smd->cqlist);
		m_cq_free(m_cq);
		m_cq = next_cq;
	}
	init_list(&smd->cqlist);
	mlog(8, " cqt_list destroyed \n");
	mpxy_unlock(&smd->cqlock);

	mpxy_lock(&smd->cqrlock);
	m_cq = get_head_entry(&smd->cqrlist);
	while (m_cq) {
		next_cq = get_next_entry(&m_cq->entry, &smd->cqrlist);
		m_cq_free(m_cq);
		m_cq = next_cq;
	}
	init_list(&smd->cqrlist);
	mpxy_unlock(&smd->cqrlock);
	mlog(8, " cqr_list destroyed \n");

	mpxy_lock(&smd->mrlock);
	m_mr = get_head_entry(&smd->mrlist);
	while (m_mr) {
		next_mr = get_next_entry(&m_mr->entry, &smd->mrlist);
		m_mr_free(m_mr);
		m_mr = next_mr;
	}
	init_list(&smd->mrlist);
	mpxy_unlock(&smd->mrlock);
	mlog(8, " mr_list destroyed \n");

	mpxy_lock(&smd->plock);
	if (smd->ports) {
		free(smd->ports);
		smd->ports = NULL;
	}
	mpxy_unlock(&smd->plock);
	mlog(8, " port space destroyed \n");

	if (smd->cmd_buf)
		free(smd->cmd_buf);
	mlog(8, " cmd_buf freed\n");

	if (smd->ref_cnt)
		mlog(0, " WARNING: ref_cnt not 0, = %d \n", smd->ref_cnt);

	destroy_smd_send_op_mmap(smd);
	mlog(8, " send op via scif wt destroyed\n");

	mpxy_destroy_bpool(smd);
	mlog(8, " proxy buffer pools destroyed \n");

	/* destroy all mutex resources */
	mpxy_lock_destroy(&smd->plock);
	mpxy_lock_destroy(&smd->clock);
	mpxy_lock_destroy(&smd->llock);
	mpxy_lock_destroy(&smd->qptlock);
	mpxy_lock_destroy(&smd->qprlock);
	mpxy_lock_destroy(&smd->cqlock);
	mpxy_lock_destroy(&smd->cqrlock);
	mpxy_lock_destroy(&smd->mrlock);
	mpxy_lock_destroy(&smd->pzlock);
	mpxy_lock_destroy(&smd->evlock);
	mpxy_lock_destroy(&smd->tblock);
	mpxy_lock_destroy(&smd->rblock);

	if (mcm_counters)
		md_cntr_log(smd->md, MCM_ALL_COUNTERS, 1);

	smd->md = NULL;
	free(smd);
}

static int init_smd_send_op_mmap(mcm_scif_dev_t *smd)
{
	int ret, len;

	smd->mm_s_peer_addr_off = SCIF_REGISTER_FAILED;
	smd->mm_r_addr_off = SCIF_REGISTER_FAILED;
	smd->mm_s_peer_addr = NULL;
	smd->mm_s_place_holder = NULL;
	smd->mm_r_head = 0;
	smd->mm_r_last = DAT_MIX_MMAP_WR_MAX;
	smd->mm_r_addr = NULL;

	/* Activate send OP via mmap only when polling mode is set */
	if (!mcm_op_poll)
		return -1;

	len = ALIGN_PAGE(DAT_MIX_MMAP_WR_MAX * (sizeof(dat_mix_mmap_wr_t)));
	smd->mm_r_len = len;
	ret = posix_memalign((void **)&smd->mm_r_addr, 4096, len);
	if (ret) {
		mlog(0, " ERR: alloc r_addr ln=%d, %s\n", len, strerror(errno));
		smd->mm_r_addr = NULL;
		return -1;
	}
	memset(smd->mm_r_addr, 0, len);

	mlog(8, " MMAP send_op: buf %p len %d\n", smd->mm_r_addr, len);

	smd->mm_r_addr_off = scif_register(smd->scif_op_ep, smd->mm_r_addr, len,
				      (off_t)0, SCIF_PROT_READ | SCIF_PROT_WRITE, 0);

	if (smd->mm_r_addr_off == SCIF_REGISTER_FAILED) {
		mlog(0, " ERR: scif_register addr=%p,%d ret=%s\n", smd->mm_r_addr, len, strerror(errno));
		free(smd->mm_r_addr);
		smd->mm_r_addr = NULL;
		return -1;
	}
	mlog(8, " MMAP send_op: addr=%p, off=0x%llx, len %d\n",
		smd->mm_r_addr, smd->mm_r_addr_off, len);

	return 0;
}


static int create_smd_bpool(mcm_scif_dev_t *smd)
{
	int ret;
	int wcq_len, wcq_size, wcq_entries;

	/* SEND proxy buffers */
	smd->m_seg = mix_buffer_sg; /* segment size */
	smd->m_len = ((mix_buffer_mb + 8) * (1024 * 1024));
	ret = posix_memalign((void **)&smd->m_buf, 4096, smd->m_len);
	if (ret) {
		mlog(0, "failed to allocate smd m_buf, m_len=%d, ERR: %d\n", smd->m_len, ret);
		return -1;
	}
	mlog(8, " Allocate/Register RDMA Proxy-out TX buffer %p-%p, ln=%d\n",
		smd->m_buf, (char*)smd->m_buf + smd->m_len, smd->m_len);

	smd->m_offset = scif_register(smd->scif_tx_ep, smd->m_buf, smd->m_len,
				      (off_t)0, SCIF_PROT_READ | SCIF_PROT_WRITE, 0);
	if (smd->m_offset == (off_t)(-1)) {
		mlog(0, " scif_register addr=%p,%d failed %s\n", smd->m_buf, smd->m_len, strerror(errno));
		return -1;
	}
	mlog(8, " SCIF addr=%p, offset=0x%llx, len %d\n", smd->m_buf, smd->m_offset, smd->m_len);

	smd->m_mr = ibv_reg_mr(smd->md->pd, smd->m_buf, smd->m_len,
			       IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
	if (smd->m_mr == NULL) {
		mlog(0, " IB addr=%p,%d failed %s\n", smd->m_buf, smd->m_len, strerror(errno));
		return -1;
	}
	mlog(8, " IB registered addr=%p,%d, mr_addr=%p handle=0x%x, lkey=0x%x rkey=0x%x \n",
	     smd->m_buf, smd->m_len, smd->m_mr->addr, smd->m_mr->handle, smd->m_mr->lkey, smd->m_mr->rkey);

	/* SEND WC queue for buffer management, manage empty slots, power of 2 */
	wcq_size = (((mix_max_msg_mb*1024*1024)/smd->m_seg) * 8);
	wcq_entries = 1;
	while (wcq_entries < wcq_size)
		wcq_entries <<= 1;

	wcq_len = (sizeof(mcm_buf_wc_t) * wcq_entries);
	ret = posix_memalign((void **)&smd->m_buf_wc, 4096, wcq_len);
	if (ret) {
		mlog(0, "failed to allocate smd m_bu_wc, m_len=%d, ERR: %d\n", wcq_len, ret);
		return -1;
	}
	memset(smd->m_buf_wc, 0, wcq_len);
	mlog(0x10, " m_buf_wc %p, len %d, entries %d \n",
		   smd->m_buf_wc, wcq_len, wcq_entries);

	smd->m_buf_hd = 0;
	smd->m_buf_tl = 0;
	smd->m_buf_end = wcq_entries - 1;

	/* RECEIVE proxy buffers */
	smd->m_len_r = ((mix_buffer_mb + 8) * (1024 * 1024));
	ret = posix_memalign((void **)&smd->m_buf_r, 4096, smd->m_len_r);
	if (ret) {
		mlog(0, "failed to allocate smd m_buf_r, m_lrx_en=%d, ERR: %d\n", smd->m_len_r, ret);
		return -1;
	}
	mlog(8, " Allocate/Register RDMA Proxy-in RX buffer %p-%p, ln=%d\n",
		smd->m_buf_r, (char*)smd->m_buf_r + smd->m_len_r, smd->m_len_r);

	smd->m_offset_r = scif_register(smd->scif_tx_ep, smd->m_buf_r, smd->m_len_r,
				      (off_t)0, SCIF_PROT_READ | SCIF_PROT_WRITE, 0);
	if (smd->m_offset_r == (off_t)(-1)) {
		mlog(0, " scif_register rx_addr=%p,%d failed %s\n",
			smd->m_buf_r, smd->m_len_r, strerror(errno));
		return -1;
	}
	mlog(8, " SCIF rx_addr=%p, rx_offset=0x%llx, rx_len %d on smd->ev_ep %d\n",
		smd->m_buf_r, smd->m_offset_r, smd->m_len_r, smd->scif_ev_ep);

	smd->m_mr_r = ibv_reg_mr(smd->md->pd, smd->m_buf_r, smd->m_len_r,
			         IBV_ACCESS_LOCAL_WRITE |
			         IBV_ACCESS_REMOTE_READ |
			         IBV_ACCESS_REMOTE_WRITE);
	if (smd->m_mr_r == NULL) {
		mlog(0, " IB rx_addr=%p,%d failed %s\n", smd->m_buf_r, smd->m_len_r, strerror(errno));
		return -1;
	}
	mlog(8, " IB registered rx_addr=%p,%d, mr_addr=%p rx_handle=0x%x, rx_lkey=0x%x rx_rkey=0x%x \n",
	     smd->m_buf_r, smd->m_len_r, smd->m_mr_r->addr,
	     smd->m_mr_r->handle, smd->m_mr_r->lkey, smd->m_mr_r->rkey);

	/* RECV WC queue for buffer management, manage empty slots, power of 2 */
	wcq_size = (((mix_max_msg_mb*1024*1024)/smd->m_seg) * 8);
	wcq_entries = 1;
	while (wcq_entries < wcq_size)
		wcq_entries <<= 1;

	wcq_len = (sizeof(mcm_buf_wc_t) * wcq_entries);
	ret = posix_memalign((void **)&smd->m_buf_wc_r, 4096, wcq_len);
	if (ret) {
		mlog(0, "failed to allocate smd m_buf_wc_r, m_len=%d, ERR: %d\n", wcq_len);
		return -1;
	}
	memset(smd->m_buf_wc_r, 0, wcq_len);
	mlog(0x10, " m_buf_wc_r %p, len %d, entries %d \n",
		   smd->m_buf_wc_r, wcq_len, wcq_entries);

	smd->m_buf_hd_r = 0;
	smd->m_buf_tl_r = 0;
	smd->m_buf_end_r = wcq_entries - 1;
	return 0;
}

static mcm_scif_dev_t *mcm_create_smd(mcm_ib_dev_t *md, scif_epd_t op_ep, scif_epd_t ev_ep, scif_epd_t tx_ep)
{
	mcm_scif_dev_t	*smd = NULL;
	int ret;

	/* SCIF device object, allocate and init resources, one per MIC client */
	smd = malloc(sizeof(*smd));
	if (!smd) {
		mlog(0, "failed to allocate smd: %s\n", strerror(errno));
		goto err;
	}

	memset(smd, 0, sizeof(*smd));
	smd->md = md;

	ret = posix_memalign((void **)&smd->cmd_buf, 4096, DAT_MIX_MSG_MAX + DAT_MIX_INLINE_MAX);
	if (ret) {
		mlog(0, "failed to allocate smd cmd_buf, m_len=%d, ERR: %d\n",
			ALIGN_64(DAT_MIX_MSG_MAX + DAT_MIX_INLINE_MAX), ret);
		smd->cmd_buf = NULL;
		goto err;
	}
	mlog(8, "Allocated smd cmd_buf = %p len %d\n",
		smd->cmd_buf, DAT_MIX_MSG_MAX + DAT_MIX_INLINE_MAX);

	/* SCIF device client port space */
	smd->ports = (uint64_t*) malloc(sizeof(uint64_t) * 0xffff);
	if (!smd->ports) {
		mlog(0, "failed to allocate smd ports: %s\n", strerror(errno));
		goto err;
	}
	memset(smd->ports, 0, sizeof(uint64_t) * 0xffff);

	mpxy_lock(&md->plock);
	smd->scif_op_ep = op_ep;
	smd->scif_ev_ep = ev_ep;
	smd->scif_tx_ep = tx_ep;
	smd->cm_id = mcm_get_port(md->ports, 0, (uint64_t)smd);
	mpxy_unlock(&md->plock);

	if (!smd->cm_id)
		goto err;

	/* no need to check ret val - in case of failure we fall back to reg OP */
	init_smd_send_op_mmap(smd);

	if (create_smd_bpool(smd))
		goto err;

	mpxy_lock_init(&smd->plock, NULL); 	 /* port space for EP's */
	mpxy_lock_init(&smd->clock, NULL); 	 /* connect list */
	mpxy_lock_init(&smd->llock, NULL); 	 /* listen list */
	mpxy_lock_init(&smd->qptlock, NULL);  /* qp tx list */
	mpxy_lock_init(&smd->qprlock, NULL);  /* qp rx list */
	mpxy_lock_init(&smd->cqlock, NULL);  /* cq list */
	mpxy_lock_init(&smd->cqrlock, NULL);  /* cq rx list */
	mpxy_lock_init(&smd->mrlock, NULL);  /* mr list */
	mpxy_lock_init(&smd->pzlock, NULL);  /* pz list */
	mpxy_lock_init(&smd->evlock, NULL);  /* DTO event, multi-threads */
	mpxy_lock_init(&smd->tblock, NULL);  /* tx proxy buffer, shared across all QP's */
	mpxy_lock_init(&smd->rblock, NULL);  /* rx proxy buffer, shared across all QP's */

	init_list(&smd->entry);
	init_list(&smd->clist);
	init_list(&smd->llist);
	init_list(&smd->qptlist);
	init_list(&smd->qprlist);
	init_list(&smd->cqlist);
	init_list(&smd->cqrlist);
	init_list(&smd->mrlist);
	init_list(&smd->pzlist);

	return smd;
err:
	if (smd) {
		if (smd->mm_r_addr)
			free(smd->mm_r_addr);
		if (smd->cmd_buf)
			free(smd->cmd_buf);
		if (smd->ports)
			free(smd->ports);

		mpxy_destroy_bpool(smd);
		free(smd);
	}
	return NULL;
}

/*
 *
 *   Platform side - MIC Indirect eXchange (MIX) operations, SCIF
 *
 */

/* open MCM device, New MIC client via SCIF listen on well known port, new ep from accept */
mcm_scif_dev_t *mix_open_device(dat_mix_open_t *msg, scif_epd_t op_ep, scif_epd_t ev_ep, scif_epd_t tx_ep, uint16_t node)
{
	mcm_client_t *mc;
	mcm_ib_dev_t *md = NULL, *new_md = NULL;
	mcm_scif_dev_t *smd = NULL;
	int i, ret;

	mlog(8, " IB device - %s, IB port %d, scif_node %d EPs %d %d %d op_msg %p lid %x\n",
		msg->name, msg->port, node, op_ep, tx_ep, ev_ep, msg, ntohs(msg->dev_addr.lid));

	mc = &mcm_client_list[node];

	mpxy_lock(&mc->oplock);
	mpxy_lock(&mc->cmlock);
	mpxy_lock(&mc->txlock);
	mpxy_lock(&mc->rxlock);

	/* New MIC node, start up OP and TX threads per node */
	if (!mc->scif_id) {
		char value[64];
		char path[64];

		mc->ver = msg->hdr.ver;
		mc->scif_id = node;
		mc->numa_node = -1;
		sprintf(path, "/sys/class/mic/mic%d/device", mc->scif_id - 1);

		if (!rd_dev_file(path, "numa_node", value, sizeof value))
			mc->numa_node = atoi(value);

		if (mc->numa_node < 0 || mc->numa_node > MCM_NNODES) {
			mlog(0, " WARN: %s numa_node = %d invalid\n",
				path, mc->numa_node);
			mc->numa_node = 0;
		}
		if (!rd_dev_file(path, "local_cpulist", value, sizeof value)) {
			if (mcm_cpumask[mc->numa_node] < 0)
				mcm_cpumask[mc->numa_node] = atoi(value);
		}

		mlog(0, " New MIC device - %s, numa_node %d, cpu %d - %s\n",
			path, mc->numa_node, mcm_cpumask[mc->numa_node], value);

		if (pthread_create(&mc->op_thread, NULL,
				   (void *(*)(void *))mpxy_op_thread, (void*)mc)) {
			mlog(0, " op pthread_create ERR: %s\n", strerror(errno));
			goto err;
		}
		if (pthread_create(&mc->tx_thread, NULL,
				   (void *(*)(void *))mpxy_tx_thread, (void*)mc)) {
			pthread_cancel(mc->op_thread);
			mlog(0, " tx pthread_create ERR: %s\n", strerror(errno));
			goto err;
		}
		if (pthread_create(&mc->cm_thread, NULL,
				   (void *(*)(void *))mpxy_cm_thread, (void*)mc)) {
			pthread_cancel(mc->op_thread);
			pthread_cancel(mc->tx_thread);
			mlog(0, " cm pthread_create ERR: %s\n", strerror(errno));
			goto err;
		}
		if (pthread_create(&mc->rx_thread, NULL,
				   (void *(*)(void *))mpxy_rx_thread, (void*)mc)) {
			pthread_cancel(mc->cm_thread);
			pthread_cancel(mc->op_thread);
			pthread_cancel(mc->tx_thread);
			mlog(0, " rx pthread_create ERR: %s\n", strerror(errno));
			goto err;
		}
	}
	for (i=0; i<MCM_IB_MAX; i++) {
		md = &mc->mdev[i];
		if (md->ibdev && !strcmp(md->ibdev->name, msg->name) && md->port == msg->port)
			goto found;
		else if (md->ibctx == NULL && new_md == NULL) {
			new_md = md;
			break;
		}
	}
	if (!new_md)
		goto err;

	/* This IB device is not yet open for SCIF node. Allocate and init */
	md = new_md;
	memset(md, 0, sizeof(*md));
	init_list(&md->entry);
	init_list(&md->smd_list);
	mpxy_lock_init(&md->slock, NULL);
	mpxy_lock_init(&md->plock, NULL);
	mpxy_lock_init(&md->txlock, NULL);
	md->cntrs = malloc(sizeof(uint64_t) * MCM_ALL_COUNTERS);
	if (!md->cntrs) {
		free(md);
		goto err;
	}
	memset(md->cntrs, 0, sizeof(uint64_t) * MCM_ALL_COUNTERS);
	md->mc = mc;
	md->port = msg->port;
	memcpy(&md->addr, &msg->dev_addr, sizeof(dat_mcm_addr_t));
	md->ibctx = open_ib_device(md, msg->name, msg->port);
	md->addr.ep_map = msg->dev_addr.ep_map;

	if ((!md->ibctx) || mcm_init_cm_service(md)) {
		mcm_destroy_md(md);
		goto err;
	}
found:
	MCNTR(md, MCM_IA_OPEN);

	/* SCIF client (SMD) bound to IB device, send open_dev response */
	smd = mcm_create_smd(md, op_ep, ev_ep, tx_ep);
	if (!smd)
		goto err;

	/* insert on active MIX device list */
	mpxy_lock(&md->slock);
	insert_tail(&smd->entry, &md->smd_list, (void *)smd);
	mpxy_unlock(&md->slock);

	msg->hdr.req_id = smd->entry.tid;
	msg->hdr.status = MIX_SUCCESS;
	msg->dev_attr.rd_atom_in = md->dev_attr.rd_atom_in;
	msg->dev_attr.rd_atom_out = md->dev_attr.rd_atom_out;

	/* MIC side changed MTU via DAPL_IB_MTU, cover new and old clients */
	if ((msg->hdr.flags & MIX_OP_MTU) ||
	    (msg->dev_attr.mtu != IBV_MTU_2048)) {
		smd->mtu_env = msg->dev_attr.mtu;
		smd->dev_attr.mtu = msg->dev_attr.mtu; /* set new MTU per MIC */
	} else if (msg->hdr.flags & MIX_OP_SET) {
		smd->dev_attr.mtu = md->dev_attr.mtu; /* MIC set to active_MTU */
	} else {
		smd->dev_attr.mtu = IBV_MTU_2048; /* run compat_mode */
	}
	msg->dev_attr.mtu = smd->dev_attr.mtu; /* return MTU settings */

	if (!(mcm_ib_inline_data(md->ibctx))  || !mcm_ib_inline)
		msg->dev_attr.max_inline = 0;

	memcpy(&smd->dev_attr, &msg->dev_attr, sizeof(dat_mix_dev_attr_t)); /* save to smd */
	memcpy(&msg->dev_addr, &md->addr, sizeof(dat_mcm_addr_t)); /* proxy CM lid */

	/* intra-node: restore MIC lid, gid */
	if (md->m_lid) {
		msg->dev_addr.lid = md->m_lid;
		memcpy(msg->dev_addr.gid, md->m_gid, 16);
	}
err:
	if (!smd) {
		mlog(1, " WARN: open failed for %s - %d\n", msg->name, msg->port);
		msg->hdr.status = MIX_ENODEV;
	}

	/* send back response */
	msg->hdr.flags = MIX_OP_RSP;
	ret = scif_send_msg(op_ep, (void*)msg, sizeof(dat_mix_open_t));
	if (ret) {
		mlog(0, " ERR: scif_send dev_id %d op_ep %d, closing device %p\n",
			op_ep, msg->hdr.req_id, smd);
		if (smd) {
			mpxy_destroy_smd(smd);
			smd = NULL;
		}
		goto bail;
	}

	mlog(1, " MIC client: mdev[%d] %p->%p mic%d[%d] -> %s[%d] port %d lid %x %s mtu %d (%d)\n",
		md->smd_list.tid, md, smd, mc->scif_id-1, mc->numa_node, msg->name,
		md->numa_node, msg->port, ntohs(msg->dev_addr.lid), mcm_map_str(md->addr.ep_map),
		smd ? smd->dev_attr.mtu:md->dev_attr.mtu,
		smd ? smd->mtu_env:0);
bail:
	mpxy_unlock(&mc->oplock);
	mpxy_unlock(&mc->cmlock);
	mpxy_unlock(&mc->txlock);
	mpxy_unlock(&mc->rxlock);

	/* new device, FD's to add to poll in threads */
	write(mc->op_pipe[1], "w", sizeof "w"); /* signal op_thread */
	write(mc->cm_pipe[1], "w", sizeof "w"); /* signal cm_thread */

	return smd;
}

static int finished = 0;
void sig_handler( int signum )
{
	mlog(0, "Killed by signal %d.\n", signum);
	finished = 1;
}

static int mpxy_set_thread_attrs(struct mcm_client *mc, cpu_set_t *cpu_mask, int rx)
{
	int policy, cpu = 0;
	struct sched_param params;
	pthread_t self;

	if (cpu_mask && mcm_affinity) {
		mpxy_lock(&mcm_cplock);
		CPU_ZERO(cpu_mask);
		if (mcm_affinity_base_mic) {
			if (mcm_affinity == 2)
				cpu = mcm_affinity_base_mic;
			else
				cpu = mcm_affinity_base_mic++;
		} else {
			if (mcm_affinity == 2)
				cpu = mcm_cpumask[mc->numa_node];
			else
				cpu = mcm_cpumask[mc->numa_node]++;
		}
		CPU_SET(cpu, cpu_mask);
		if(sched_setaffinity( 0, sizeof(*cpu_mask), cpu_mask) == -1)
		      mlog(0, "WARNING: setaffinity (%s) ERR, cpu_id=%d\n",
			      strerror(errno), cpu);
		mpxy_unlock(&mcm_cplock);
	} else {
		cpu = sched_getcpu();
	}

	if (mcm_set_priority) {
		self = pthread_self();
		params.sched_priority = sched_get_priority_max(SCHED_FIFO) - 50;

		if (pthread_setschedparam(self, SCHED_FIFO, &params)) {
			mlog(0, " ERR: setschedparam returned - %s\n",
				strerror(errno));
			goto bail;
		}
		if (pthread_getschedparam(self, &policy, &params)) {
			mlog(0, " ERR: getschedparam returned - %s\n",
				strerror(errno));
			goto bail;
		}
		if (policy != SCHED_FIFO) {
			mlog(0, " ERR: policy != SCHED_FIFO\n");
			goto bail;
		}
		mlog(0, " Thread (%x) policy = SCHED_FIFO, priority = %d\n",
			pthread_self(), params.sched_priority);
	}
bail:
	return cpu;
}

void mpxy_tx_thread(void *mic_client)
{
	mcm_client_t *mc = (mcm_client_t*)mic_client;
	struct mcm_ib_dev *md;
	struct mcm_scif_dev *smd;
	struct mcm_cq *m_cq;
	struct mcm_qp *m_qp;
	struct mcm_fd_set *set;
	int i, time_ms, data, cpu_id;
	char rbuf[2];

	cpu_id = mpxy_set_thread_attrs(mc, &mc->tx_mask, 0);

	mlog(0, "TX thread (%x) MIC node_id %d bound to numa_node %d and cpu_id=%d\n",
 		pthread_self(), mc->scif_id, mc->numa_node, cpu_id);
	set = mcm_alloc_fd_set();
	if (!set)
		return;

	while (!finished) {
		mpxy_lock(&mc->txlock);
		mcm_fd_zero(set);
		mcm_fd_set(mc->tx_pipe[0], set, POLLIN);
		data = 0;
		for (i=0;i<MCM_IB_MAX;i++) {
			md = &mc->mdev[i];
			if (md->ibctx == NULL)
				continue;

			/* all active MCM clients on this IB device */
			mpxy_lock(&md->slock);
			smd = get_head_entry(&md->smd_list);
			while (smd && !smd->destroy) {
				smd->th_ref_cnt++;
				mpxy_unlock(&md->slock);

				mpxy_lock(&smd->cqlock);
				m_cq = get_head_entry(&smd->cqlist);
				while (m_cq) {
					m_req_event(m_cq, &data); /* check completions, PO and PI */
					if (m_cq->ib_ch)
						mcm_fd_set(m_cq->ib_ch->fd, set, POLLIN);
					m_cq = get_next_entry(&m_cq->entry, &smd->cqlist);
				}
				mpxy_unlock(&smd->cqlock);

				mpxy_lock(&smd->qptlock);
				m_qp = get_head_entry(&smd->qptlist);
				while (m_qp) {
					if (m_qp->r_entry.tid)
						m_pi_pending_wc(m_qp, &data);
					m_po_pending_wr(m_qp, &data); /* proxy-out WR's */
					m_qp = get_next_entry(&m_qp->t_entry, &smd->qptlist);
				}
				mpxy_unlock(&smd->qptlock);
				sched_yield();
				mpxy_lock(&md->slock);
				smd->th_ref_cnt--;
				smd = get_next_entry(&smd->entry, &md->smd_list);
			}
			mpxy_unlock(&md->slock);
			sched_yield();
		}
		mc->tx_busy = data;
		time_ms = (data) ? 0:-1;

		mpxy_unlock(&mc->txlock);
		if (time_ms == -1) mlog(0x10," sleep\n");
		mcm_select(set, time_ms);
		if (time_ms == -1) mlog(0x10," wake\n");
		if (mcm_poll(mc->tx_pipe[0], POLLIN) == POLLIN) {
			int cnt = 0;
			while (read(mc->tx_pipe[0], rbuf, 1) > 0)
				cnt++;
		}
	}
	mlog(0, "TX thread exiting, cpu=%d\n");
}

void mpxy_op_thread(void *mic_client)
{
	mcm_client_t *mc = (mcm_client_t*)mic_client;
	struct mcm_fd_set *set;
	struct mcm_ib_dev *md;
	struct mcm_scif_dev *smd, *next;
	char rbuf[2];
	int i, ret, time_ms, cpu_id, smd_cnt;

	cpu_id = mpxy_set_thread_attrs(mc, &mc->op_mask, 0);

	mlog(0, "OP thread (%x) MIC node_id %d bound to numa_node %d and cpu_id=%d\n",
 		pthread_self(), mc->scif_id, mc->numa_node, cpu_id );

	set = mcm_alloc_fd_set();
	if (!set)
		return;

	while (!finished) {
		mpxy_lock(&mc->oplock);
		smd_cnt = 0;
		time_ms = -1;
		mcm_fd_zero(set);
		mcm_fd_set(mc->op_pipe[0], set, POLLIN);

		/* Set up FD set array for all active client sessions */
		for (i=0;i<MCM_IB_MAX;i++) {
			md = &mc->mdev[i];
			if (md->ibctx == NULL)
				continue;

			/* all active SCIF MIC clients, OP channels */
			mpxy_lock(&md->slock);
			smd = get_head_entry(&md->smd_list);
			while (smd && !smd->destroy) {
				smd_cnt++;
				smd->th_ref_cnt++;
				mpxy_unlock(&md->slock);

				ret = 0;
				if (smd->mm_s_peer_addr_off != SCIF_REGISTER_FAILED)
					ret = mix_post_send_ext(smd); /* mmap operation */

				if (ret == POLLERR)
					mix_close_device(md, smd);

				ret = mcm_poll(smd->scif_op_ep, POLLIN); /* operations */
				if (ret == POLLIN)
					ret = mix_scif_recv(smd, smd->scif_op_ep);
				if (ret != POLLERR) {
					ret = mcm_poll(smd->scif_ev_ep, POLLIN); /* client CM msgs */
					if (ret == POLLIN)
						ret = mix_scif_recv(smd, smd->scif_ev_ep);
				}
				mpxy_lock(&md->slock);
				next = get_next_entry(&smd->entry, &md->smd_list);
				smd->th_ref_cnt--;

				if (ret == POLLERR) {
					mix_close_device(md, smd);
				} else {
					mcm_fd_set(smd->scif_op_ep, set, POLLIN);
					mcm_fd_set(smd->scif_ev_ep, set, POLLIN);
				}
				smd = next;
			}
			mpxy_unlock(&md->slock);

			if (smd)
				sched_yield();
		}
		mpxy_unlock(&mc->oplock);
		/* data-path, loop if busy or device open & single core */
		if ((mc->tx_busy || mc->rx_busy) || (smd_cnt && mcm_op_poll))
			time_ms = 0;

		mcm_select(set, time_ms); /* Another sched yield */
		if (time_ms == -1) mlog(0x10," OP wake\n");
		if (mcm_poll(mc->op_pipe[0], POLLIN) == POLLIN)
			read(mc->op_pipe[0], rbuf, 2);
	}
	free(set);
	mlog(0, "OP,CM,Event thread exiting\n");
}

void mpxy_cm_thread(void *mic_client)
{
	mcm_client_t *mc = (mcm_client_t*)mic_client;
	struct mcm_ib_dev *md;
	struct mcm_scif_dev *smd, *next;
	struct pollfd set[MCM_IB_MAX*3];
	int i, fds, cpu_id, ret, cnt, time_ms = -1;
	char rbuf[2];

	cpu_id = mpxy_set_thread_attrs(mc, &mc->cm_mask, 0);

	mlog(0, "CM thread (%x) MIC node_id %d bound to numa_node %d and cpu_id=%d\n",
 		pthread_self(), mc->scif_id, mc->numa_node, cpu_id);

	while (!finished) {
		mpxy_lock(&mc->cmlock);
		set[0].fd = mc->cm_pipe[0];
		set[0].events = POLLIN;
		set[0].revents = 0;
		fds = 1;

		for (i=0;i<MCM_IB_MAX;i++) {
			md = &mc->mdev[i];
			if (md->ibctx == NULL)
				continue;

			set[fds].fd = md->rch->fd;
			set[fds].events = POLLIN;
			set[fds].revents = 0;
			set[fds+1].fd = md->ibctx->async_fd;
			set[fds+1].events = POLLIN;
			set[fds+1].revents = 0;
			fds += 2;
		}
		mpxy_unlock(&mc->cmlock);

		poll(set, fds, time_ms);
		time_ms = -1;

		mpxy_lock(&mc->cmlock);
		for (i=0;i<MCM_IB_MAX;i++) {
			md = &mc->mdev[i];
			if (md->ibctx == NULL)
				continue;

			while (mcm_poll(mc->cm_pipe[0], POLLIN) == POLLIN)
				read(mc->cm_pipe[0], rbuf, 2);

			if (mcm_poll(md->rch->fd, POLLIN) == POLLIN)
				mcm_ib_recv(md);

			if (mcm_poll(md->ibctx->async_fd, POLLIN) == POLLIN) {
				ret = mcm_ib_async_event(md);
				if (ret) {
					mlog(0, " Shutdown all clients on MC %p MD %p \n", mc, md);
					mpxy_lock(&mc->oplock);
					mpxy_lock(&mc->txlock);
					mpxy_lock(&mc->rxlock);
					mpxy_lock(&md->slock);
					cnt = 0;
					smd = get_head_entry(&md->smd_list);
					while (smd && !smd->destroy) {
						cnt++;
						next = get_next_entry(&smd->entry, &md->smd_list);
						mix_close_device(md, smd);
						smd = next;
					}
					mpxy_unlock(&md->slock);

					mcm_destroy_md(md);
					mpxy_unlock(&mc->rxlock);
					mpxy_unlock(&mc->txlock);
					mpxy_unlock(&mc->oplock);
					mlog(0, " Shutdown MC %p MD %p complete (%d clients)\n", mc, md, cnt);
				}
			}
			mpxy_lock(&md->slock);
			smd = get_head_entry(&md->smd_list);
			while (smd && !smd->destroy) {
				mcm_check_timers(smd, &time_ms);
				smd = get_next_entry(&smd->entry, &md->smd_list);
			}
			mpxy_unlock(&md->slock);
			sched_yield();
		}
		mpxy_unlock(&mc->cmlock);
	}
	mlog(0, "CM thread exiting\n");
}

void mpxy_rx_thread(void *mic_client)
{
	mcm_client_t *mc = (mcm_client_t*)mic_client;
	struct mcm_ib_dev *md;
	struct mcm_scif_dev *smd = NULL;
	struct mcm_qp *m_qp;
	struct mcm_cq *m_cq;
	struct mcm_fd_set *set;
	char rbuf[2];
	int i, cpu_id, data, time_ms;

	cpu_id = mpxy_set_thread_attrs(mc, &mc->cm_mask, 1);

	mlog(0, "RX thread (%x) MIC node_id %d bound to numa_node %d and cpu_id=%d\n",
 		pthread_self(), mc->scif_id, mc->numa_node, cpu_id);

	set = mcm_alloc_fd_set();
	if (!set)
		return;

	while (!finished) {
		mpxy_lock(&mc->rxlock);
		mcm_fd_zero(set);
		mcm_fd_set(mc->rx_pipe[0], set, POLLIN);
		data = 0;
		for (i=0;i<MCM_IB_MAX;i++) {
			md = &mc->mdev[i];
			if (md->ibctx == NULL)
				continue;

			mpxy_lock(&md->slock);
			smd = get_head_entry(&md->smd_list);
			while (smd && !smd->destroy) {
				smd->th_ref_cnt++;
				mpxy_unlock(&md->slock);

				mpxy_lock(&smd->cqrlock);
				m_cq = get_head_entry(&smd->cqrlist);
				while (m_cq) {
					m_rcv_event(m_cq, &data); /* chk receive requests, initiate RR's */
					if (m_cq->ib_ch)
						mcm_fd_set(m_cq->ib_ch->fd, set, POLLIN);
					m_cq = get_next_entry(&m_cq->entry, &smd->cqrlist);
				}
				mpxy_unlock(&smd->cqrlock);

				mpxy_lock(&smd->qprlock);
				m_qp = get_head_entry(&smd->qprlist);
				while (m_qp) {
					m_pi_pending_wr(m_qp, &data); /* RR's and scif_sendto */
					m_pi_pending_wt(m_qp); /* WT's pending */
					m_qp = get_next_entry(&m_qp->r_entry, &smd->qprlist);
				}
				mpxy_unlock(&smd->qprlock);
				sched_yield();
				mpxy_lock(&md->slock);
				smd->th_ref_cnt--;
				smd = get_next_entry(&smd->entry, &md->smd_list);
			}
			mpxy_unlock(&md->slock);
			sched_yield();
		}
		mc->rx_busy = data;
		time_ms = data ? 0:-1;

		mpxy_unlock(&mc->rxlock);
		if (time_ms == -1) mlog(0x10," RX sleep\n");
		mcm_select(set, time_ms);
		if (time_ms == -1) mlog(0x10," RX wake\n");
		if (mcm_poll(mc->rx_pipe[0], POLLIN) == POLLIN)
			read(mc->rx_pipe[0], rbuf, 2);
	}
	mlog(0, "RX thread exiting\n");
}

/*
 * MPXY server will listen on both a IB UD QP for fabric CM messages
 * and a SCIF port for inter-bus MCM operation messages to/from MIC MCM clients.
 *
 * MPXY message protocol is very similar to existing DCM but not compatible
 * therefore we are setting version number to 1 for MCM protocol so it will
 * not connect incompatible DAPL endpoints by mistake.
 *
 * 1st draft - one IB UD QP per device, multiplex multiple MIC opens to same device
 * 		one thread for both SCIF and IB traffic, try FD select for now
 * 		and move to polling memory if we can't get pipelining at wire speeds.
 *
 */
static void mpxy_server(void)
{
	struct pollfd set;
	struct sigaction act, oldact;
	int i, cpu_id;

	act.sa_handler = sig_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGINT, &act, &oldact))
		mlog(0, "sigaction: %s\n", strerror(errno));
	if (sigaction(SIGTERM, &act, &oldact))
		mlog(0, "sigaction: %s\n", strerror(errno));

	cpu_id = mpxy_set_thread_attrs(&mcm_client_list[0], NULL, 0);

	mlog(0, "Server started, cpu_id=%d\n", cpu_id);
	while (!finished) {
		set.fd = scif_listen_ep;
		set.events = POLLIN;
		set.revents = 0;
		mlog(0x8, "Server sleep\n");
		poll(&set, 1, -1); /* sleep */
		mlog(0x8, "Server wake, cpu_id=%d\n", cpu_id);
		/* process listens */
		if (mcm_poll(scif_listen_ep, POLLIN) == POLLIN)
			mix_scif_accept(scif_listen_ep);
	}
	mlog(0, "server exiting, canceling all threads...\n");

	/* cancel all MIC node client threads */
	for (i=0;i<MCM_CLIENT_MAX;i++) {
		if (mcm_client_list[i].scif_id) {
			mlog(0, "server canceling threads for MIC node %d\n",
			     mcm_client_list[i].scif_id);
			pthread_cancel(mcm_client_list[i].tx_thread);
			pthread_cancel(mcm_client_list[i].rx_thread);
			pthread_cancel(mcm_client_list[i].op_thread);
			pthread_cancel(mcm_client_list[i].cm_thread);
		}
	}
	mlog(0, "all threads canceled, server down\n");
}

static void kill_daemon(void)
{
	FILE *fp;
	int pid;

	fp = fopen(lock_file, "r");
	if (!fp) {
		perror(lock_file);
		return;
	}

	fscanf(fp, "%d", &pid);
	if (kill(pid, SIGTERM))
		perror("kill");

	fclose(fp);
}

static void show_usage(char *program)
{
        printf("usage: %s\n", program);
        printf("   [-P]             - run as a standard process, (default daemon)\n");
        printf("   [-O option_file] - option configuration file\n");
        printf("                      (default %s\n", MPXYD_CONF);
        printf("   [-k]             - kill the running daemon\n");
        printf("   [-d]             - debug mode (standard process, log to stdout, manage lock file)\n");
}

int main(int argc, char **argv)
{
	int op, mdaemon = 1, kill = 0, debug_mode = 0;
	const char *fam_str = "cpu family";
	const char *mod_str = "model";

	while ((op = getopt(argc, argv, "dkDPO:")) != -1) {
		switch (op) {
		case 'P':
			mdaemon = 0;
			break;
		case 'O':
			opts_file = optarg;
			break;
		case 'k':
			kill = 1;
			break;
		case 'd':
			debug_mode = 1;
			mdaemon = 0;
			break;

		default:
			show_usage(argv[0]);
			exit(1);
		}
	}

	mpxy_set_options( debug_mode );

	if (kill) {
		kill_daemon();
		exit(0);
	}

	if (mdaemon)
		if (daemon(0, 0)) {
			perror("daemon");
			return -1;
		}

	if (mpxy_open_lock_file())
		return -1;

	/* init locks */
	mpxy_lock_init(&flock, NULL);

	logfile = mpxy_open_log();
	mpxy_log_options();

	mlog(0, "CCL Proxy - SCIF/IB DAPL RDMA Proxy Service %s (%u)\n",
		 PACKAGE_VERSION, PACKAGE_DATE);

	if (init_scif()) {
		mlog(0, "ERROR - unable to open/init SCIF device\n");
		return -1;
	}

	mcm_cpu_family = mpxy_cpuinfo_atoi(fam_str);
	mcm_cpu_model  = mpxy_cpuinfo_atoi(mod_str);

	mlog(1, "Host CPU Family = %d\n", mcm_cpu_family);
	mlog(1, "Host CPU Model  = %d\n", mcm_cpu_model);

	mlog(0, "Starting server\n");
	mpxy_server();
	mlog(0, "Shutting down\n");

	close_scif();
	close_ib();

	mlog(0, "Shutdown complete\n");
	fclose(logfile);

	mpxyd_release_lock_file();
	return 0;
}

#ifdef MCM_PROFILE
/* Diagnostic helper functions, log client/device/connection states */
void mcm_qp_log(struct mcm_qp *m_qp, int tx)
{
	int io;

	if (tx) {
		io = m_qp->wr_pp_rem + m_qp->wr_pp +  (m_qp->post_sig_cnt - m_qp->comp_cnt);
		mlog(0, "[%d:%d:%d] PO QPt %p - WR tl %d tl_rf %d hd %d -"
			" RW pst %d sig %d po_cmp %d, wr_rem %d wr %d - IO %d ACT %d\n",
			m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid,
			m_qp->r_entry.tid, m_qp, m_qp->wr_tl, m_qp->wr_tl_rf, m_qp->wr_hd,
			m_qp->post_cnt, m_qp->post_sig_cnt, m_qp->comp_cnt,
			m_qp->wr_pp_rem, m_qp->wr_pp,
			m_qp->post_cnt, io);
		if (m_qp->cm)
			mcm_pr_addrs(0, &m_qp->cm->msg, m_qp->cm->state, 0);
	} else {
		io = m_qp->stall_cnt_rr + m_qp->post_cnt_wt + m_qp->pi_rw_cnt;
		mlog(0,	"[%d:%d:%d] PI QPr %p - WR tl %d tl_wt %d hd %d -"
			" RR pst %d pst_pnd %d stl %d, WT %d, RW_imm %d - IO %d ACT %d\n",
			m_qp->smd->md->mc->scif_id, m_qp->smd->entry.tid,
			m_qp->r_entry.tid, m_qp, m_qp->wr_tl_r, m_qp->wr_tl_r_wt,
			m_qp->wr_hd_r, m_qp->post_cnt_rr, m_qp->pi_rr_cnt,
			m_qp->stall_cnt_rr, m_qp->post_cnt_wt, m_qp->pi_rw_cnt,
			m_qp->post_cnt_rr, io);
		if (m_qp->cm)
			mcm_pr_addrs(0, &m_qp->cm->msg, m_qp->cm->state, 0);
	}
}

void mcm_connect_log(struct mcm_scif_dev *smd)
{
	struct mcm_qp *m_qp_t;
	struct mcm_qp *m_qp_r;

	m_qp_t = get_head_entry(&smd->qptlist);
	m_qp_r = get_head_entry(&smd->qprlist);
	while (m_qp_t || m_qp_r) {
		if (m_qp_t) {
			mcm_qp_log(m_qp_t, 1);
			m_qp_t = get_next_entry(&m_qp_t->t_entry,
						&smd->qptlist);
		}
		if (m_qp_r) {
			mcm_qp_log(m_qp_r, 0);
			m_qp_r = get_next_entry(&m_qp_r->r_entry,
						&smd->qprlist);
		}
	}
}

void mcm_dat_dev_log(struct mcm_scif_dev *smd)
{
	int idx;
	uint32_t now = mcm_ts_us();

	mlog(0, "[%d:%d] PO_BUF %p tl 0x%x hd 0x%x ln %d -"
		" WC %p tl %d hd %d ln %d - SEGs %d ACT %u\n",
		smd->md->mc->scif_id, smd->entry.tid, smd->m_buf,
		smd->m_tl, smd->m_hd, smd->m_len, smd->m_buf_wc,
		smd->m_buf_tl, smd->m_buf_hd, smd->m_buf_end,
		smd->m_buf_hd, smd->m_buf_hd - smd->m_buf_tl);
	mlog(0, "[%d:%d] PI_BUF %p tl 0x%x hd 0x%x ln %d -"
		" WC %p tl %d hd %d ln %d - SEGs %d ACT %u\n",
		smd->md->mc->scif_id, smd->entry.tid, smd->m_buf_r,
		smd->m_tl_r, smd->m_hd_r, smd->m_len_r, smd->m_buf_wc_r,
 		smd->m_buf_tl_r, smd->m_buf_hd_r, smd->m_buf_end_r,
 		smd->m_buf_hd_r, smd->m_buf_hd_r - smd->m_buf_tl_r);

	/* show PO mbuf_wc busy slots */
	idx = smd->m_buf_tl;
	while (idx != smd->m_buf_hd) {
		if ((smd->m_buf_wc[idx].m_idx && !smd->m_buf_wc[idx].done) || 1) {
			struct mcm_wr *m_wr = NULL;
			struct mcm_qp *m_qp = NULL;
			if (smd->m_buf_wc[idx].wr) {
				m_wr = (struct mcm_wr *)smd->m_buf_wc[idx].wr;
				m_qp = (struct mcm_qp *)m_wr->context;
			}
			mlog(0, "[%d:%d:%d] PO: m_wc - tl %d hd %d wc[%d].m_idx=0x%x %s"
				" wr[%d] f=%x,m=%x t=%u ref=%d m_tl %x hd %x\n",
				smd->md->mc->scif_id, smd->entry.tid,
				m_qp ? m_qp->r_entry.tid:0,
				smd->m_buf_tl, smd->m_buf_hd, idx,
				smd->m_buf_wc[idx].m_idx,
				smd->m_buf_wc[idx].done ? "DONE":"BUSY",
				m_wr ? m_wr->w_idx:0, m_wr ? m_wr->flags:0,
				m_wr ? m_wr->m_idx:0, smd->m_buf_wc[idx].done ?
				smd->m_buf_wc[idx].ts : now - smd->m_buf_wc[idx].ts,
				smd->m_buf_wc[idx].ref,
				smd->m_buf_wc[idx].tl, smd->m_buf_wc[idx].hd);
		}
		idx = (idx + 1) & smd->m_buf_end;
	}

	/* show PI mbuf_wc busy slots, start from tail */
	idx = smd->m_buf_tl_r;
	while ((smd->m_buf_tl_r != smd->m_buf_hd_r) &&
	       (smd->m_buf_hd_r - smd->m_buf_tl_r)) {
		if (smd->m_buf_wc_r[idx].m_idx || 1) {
			struct mcm_wr_rx *m_wr = NULL;
			struct mcm_qp *m_qp = NULL;
			if (smd->m_buf_wc_r[idx].wr) {
				m_wr = (struct mcm_wr_rx *)smd->m_buf_wc_r[idx].wr;
				m_qp = (struct mcm_qp *)m_wr->context;
			}
			mlog(0, "[%d:%d:%d] PI: m_wc_r - tl %d hd %d wc[%d].m_idx=0x%x %s "
				"wr[%d] f=%x,m=%x t=%u ref=%d m_tl %x hd %x\n",
				smd->md->mc->scif_id, smd->entry.tid,
				m_qp ? m_qp->r_entry.tid:0,
				smd->m_buf_tl_r, smd->m_buf_hd_r, idx,
				smd->m_buf_wc_r[idx].m_idx,
				smd->m_buf_wc_r[idx].done ? "DONE":"BUSY",
				m_wr ? m_wr->w_idx:0, m_wr ? m_wr->flags:0,
				m_wr ? m_wr->m_idx:0, smd->m_buf_wc_r[idx].done ?
				smd->m_buf_wc_r[idx].ts : now - smd->m_buf_wc_r[idx].ts,
				smd->m_buf_wc_r[idx].ref,
				smd->m_buf_wc_r[idx].tl, smd->m_buf_wc_r[idx].hd);
		}
		idx = (idx + 1) & smd->m_buf_end_r;
		if (idx == (smd->m_buf_hd_r+2))
			break;
	}
}

void mcm_ib_dev_log(struct mcm_ib_dev *md)
{
	mlog(0, "[%d] MD %p - LID 0x%x PORT %d GID %s QPN 0x%x: mic%d ->"
		" %s - %s, mic_ver %d\n",
		md->mc->scif_id, md, ntohs(md->addr.lid), md->port,
		inet_ntop(AF_INET6, md->addr.gid, gid_str, sizeof(gid_str)),
		md->qp->qp_num, md->mc->scif_id - 1, md->ibdev->name,
		mcm_map_str(md->addr.ep_map), md->mc->ver);
}

static int check_io_run;
void mcm_check_io()
{
	mcm_client_t *mc;
	struct mcm_ib_dev *md;
	struct mcm_scif_dev *smd;
	int i, ii;

	if (check_io_run)
		return;
	else
		check_io_run++;

	for (i=0;i<MCM_CLIENT_MAX;i++) {
		if (mcm_client_list[i].scif_id)
			mc = &mcm_client_list[i];
		else
			continue;

		/* MIC adapter */
		mlog(0, "[%d] MC %p scif_id %d\n",
			i, mcm_client_list[i].scif_id, mc);

		for (ii=0;ii<MCM_IB_MAX;ii++) {
			md = &mc->mdev[ii];
			if (md->ibctx == NULL)
				continue;

			mcm_ib_dev_log(md); /* ibv_open_device */
			smd = get_head_entry(&md->smd_list);
			while (smd && !smd->destroy) {
				mlog(0, "[%d:%d] SMD %p \n",
					smd->md->mc->scif_id,
					smd->entry.tid, smd);
				mcm_dat_dev_log(smd); /* dat_ia_open */
				mcm_connect_log(smd); /* dat_connect */
				smd = get_next_entry(&smd->entry,
						     &md->smd_list);
			}
		}
	}
	assert(0);
}
#endif

