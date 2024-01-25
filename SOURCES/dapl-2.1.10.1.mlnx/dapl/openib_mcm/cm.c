/*
 * Copyright (c) 2009-2014 Intel Corporation.  All rights reserved.
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
#include "dapl_evd_util.h"
#include "dapl_cr_util.h"
#include "dapl_name_service.h"
#include "dapl_ib_util.h"
#include "dapl_ep_util.h"
#include "dapl_osd.h"

extern char gid_str[INET6_ADDRSTRLEN];

enum DAPL_FD_EVENTS {
	DAPL_FD_READ = POLLIN,
	DAPL_FD_WRITE = POLLOUT,
	DAPL_FD_ERROR = POLLERR
};

struct dapl_fd_set {
	int index;
	struct pollfd set[DAPL_FD_SETSIZE];
};

static struct dapl_fd_set *dapl_alloc_fd_set(void)
{
	return dapl_os_alloc(sizeof(struct dapl_fd_set));
}

static void dapl_fd_zero(struct dapl_fd_set *set)
{
	set->index = 0;
}

static int dapl_fd_set(DAPL_SOCKET s, struct dapl_fd_set *set,
		       enum DAPL_FD_EVENTS event)
{
	if (!s)
		return 0;

	if (set->index == DAPL_FD_SETSIZE - 1) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " ERR: cm_thread exceeded FD_SETSIZE %d\n",
			 set->index + 1);
		return -1;
	}

	set->set[set->index].fd = s;
	set->set[set->index].revents = 0;
	set->set[set->index++].events = event;
	return 0;
}

static enum DAPL_FD_EVENTS dapl_poll(DAPL_SOCKET s, enum DAPL_FD_EVENTS event)
{
	struct pollfd fds;
	int ret;

	if (!s)
		return 0;

	fds.fd = s;
	fds.events = event;
	fds.revents = 0;
	ret = poll(&fds, 1, 0);
	dapl_log(DAPL_DBG_TYPE_THREAD, " dapl_poll: fd=%d ret=%d, evnts=0x%x\n",
		 s, ret, fds.revents);
	if (ret == 0)
		return 0;
	else if (fds.revents & (POLLERR | POLLHUP | POLLNVAL)) {
		dapl_log(DAPL_DBG_TYPE_CM_WARN,
			 " dapl_poll: ERR: fd=%d ret=%d, revent=0x%x\n",
			 s,ret,fds.revents);
		return DAPL_FD_ERROR;
	} else
		return fds.revents;
}

static int dapl_select(struct dapl_fd_set *set, int time_ms)
{
	int ret;

	dapl_dbg_log(DAPL_DBG_TYPE_THREAD, " dapl_select: sleep, fds=%d\n", set->index);
	ret = poll(set->set, set->index, time_ms);
	dapl_dbg_log(DAPL_DBG_TYPE_THREAD, " dapl_select: wakeup, ret=0x%x\n", ret);
	return ret;
}

/* forward declarations */
static int mcm_reply(dp_ib_cm_handle_t cm);
static void mcm_accept(ib_cm_srvc_handle_t cm, dat_mcm_msg_t *msg);
static void mcm_accept_rtu(dp_ib_cm_handle_t cm, dat_mcm_msg_t *msg);
static int mcm_send(ib_hca_transport_t *tp, dat_mcm_msg_t *msg, DAT_PVOID p_data, DAT_COUNT p_size);
DAT_RETURN dapli_cm_disconnect(dp_ib_cm_handle_t cm);
DAT_RETURN dapli_cm_connect(DAPL_EP *ep, dp_ib_cm_handle_t cm);
static void mcm_log_addrs(int lvl, struct dat_mcm_msg *msg, int state, int in);

/* Service ids - port space */
static uint16_t mcm_get_port(ib_hca_transport_t *tp, uint16_t port)
{
	int i = 0;
	
	dapl_os_lock(&tp->plock);
	/* get specific ID */
	if (port) {
		if (tp->sid[port] == 0) {
			tp->sid[port] = 1;
			i = port;
		}
		goto done;
	} 
	
	/* get any free ID */
	for (i = 0xffff; i > 0; i--) {
		if (tp->sid[i] == 0) {
			tp->sid[i] = 1;
			break;
		}
	}
done:
	dapl_os_unlock(&tp->plock);
	return i;
}

static void mcm_free_port(ib_hca_transport_t *tp, uint16_t port)
{
	dapl_os_lock(&tp->plock);
	tp->sid[port] = 0;
	dapl_os_unlock(&tp->plock);
}

static void mcm_check_timers(dp_ib_cm_handle_t cm, int *timer)
{
	DAPL_OS_TIMEVAL time;

	if (cm->tp->scif_ep) /* CM timers running on MPXYD */
		return;

        dapl_os_lock(&cm->lock);
	dapl_os_get_time(&time); 
	switch (cm->state) {
	case MCM_REP_PENDING:
		*timer = cm->hca->ib_trans.cm_timer; 
		/* wait longer each retry */
		if ((time - cm->timer)/1000 > 
		    (cm->hca->ib_trans.rep_time << cm->retries)) {
			dapl_log(DAPL_DBG_TYPE_CM_WARN,
				 " CM_REQ retry %p %d [lid, port, cqp, iqp]:"
				 " %x %x %x %x -> %x %x %x %x Time(ms) %d > %d\n",
				 cm, cm->retries+1,
				 ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
				 ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn),
				 ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
				 ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn),
				 (time - cm->timer)/1000,
				 cm->hca->ib_trans.rep_time << cm->retries);
			cm->retries++;
			DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ERR_REQ_RETRY);
			dapl_os_unlock(&cm->lock);
			dapli_cm_connect(cm->ep, cm);
			return;
		}
		break;
	case MCM_RTU_PENDING:
		*timer = cm->hca->ib_trans.cm_timer;  
		if ((time - cm->timer)/1000 > 
		    (cm->hca->ib_trans.rtu_time << cm->retries)) {
			dapl_log(DAPL_DBG_TYPE_CM_WARN,
				 " CM_REPLY retry %d %s [lid, port, cqp, iqp]:"
				 " %x %x %x %x -> %x %x %x %x r_pid %x Time(ms) %d > %d\n",
				 cm->retries+1,
				 dapl_cm_op_str(ntohs(cm->msg.op)),
				 ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
				 ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn),
				 ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
				 ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn),
				 ntohl(cm->msg.d_id),
				 (time - cm->timer)/1000, 
				 cm->hca->ib_trans.rtu_time << cm->retries);
			cm->retries++;
			DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ERR_REP_RETRY);
			dapl_os_unlock(&cm->lock);
			mcm_reply(cm);
			return;
		}
		break;
	case MCM_DISC_PENDING:
		*timer = cm->hca->ib_trans.cm_timer; 
		/* wait longer each retry */
		if ((time - cm->timer)/1000 > 
		    (cm->hca->ib_trans.rtu_time << cm->retries)) {
			dapl_log(DAPL_DBG_TYPE_CM_WARN,
				 " CM_DREQ retry %d [lid, port, cqp, iqp]:"
				 " %x %x %x %x -> %x %x %x %x r_pid %x Time(ms) %d > %d\n",
				 cm->retries+1,
				 ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
				 ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn),
				 ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
				 ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn),
				 ntohl(cm->msg.d_id),
				 (time - cm->timer)/1000, 
				 cm->hca->ib_trans.rtu_time << cm->retries);
			cm->retries++;
			DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ERR_DREQ_RETRY);
			dapl_os_unlock(&cm->lock);
			dapli_cm_disconnect(cm);
                        return;
		}
		break;
	default:
		break;
	}
	dapl_os_unlock(&cm->lock);
}

/* SEND CM MESSAGE PROCESSING */

/* Get CM UD message from send queue, called with s_lock held */
static dat_mcm_msg_t *mcm_get_smsg(ib_hca_transport_t *tp)
{
	dat_mcm_msg_t *msg = NULL;
	int ret, polled = 1, hd = tp->s_hd;

	hd++;

	if (hd == tp->qpe)
		hd = 0;
retry:
	if (hd == tp->s_tl) {
		msg = NULL;
		if (polled % 1000000 == 0)
			dapl_log(DAPL_DBG_TYPE_WARN,
				 " mcm_get_smsg: FULLq hd %d == tl %d,"
				 " completions stalled, polls=%d\n",
				 hd, tp->s_tl, polled);
	}
	else {
		msg = &tp->sbuf[hd];
		tp->s_hd = hd; /* new hd */
	}

	/* if empty, process some completions */
	if (msg == NULL) {
		struct ibv_wc wc;

		/* process completions, based on mcm_TX_BURST */
		ret = ibv_poll_cq(tp->scq, 1, &wc);
		if (ret < 0) {
			dapl_log(DAPL_DBG_TYPE_WARN,
				" get_smsg: cq %p %s\n",
				tp->scq, strerror(errno));
			return NULL;
		}
		/* free up completed sends, update tail */
		if (ret > 0)
			tp->s_tl = (int)wc.wr_id;

		polled++;
		goto retry;
	}
	DAPL_CNTR_DATA(((DAPL_IA *)dapl_llist_peek_head(&tp->hca->ia_list_head)), DCNT_IA_CM_ERR_REQ_FULLQ, polled > 1 ? 1:0);
	DAPL_CNTR_DATA(((DAPL_IA *)dapl_llist_peek_head(&tp->hca->ia_list_head)), DCNT_IA_CM_REQ_FULLQ_POLL, polled - 1);
	return msg;
}

/* RECEIVE CM MESSAGE PROCESSING */

static int mcm_post_rmsg(ib_hca_transport_t *tp, dat_mcm_msg_t *msg)
{	
	struct ibv_recv_wr recv_wr, *recv_err;
	struct ibv_sge sge;
        
	recv_wr.next = NULL;
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;
	recv_wr.wr_id = (uint64_t)(uintptr_t) msg;
	sge.length = sizeof(dat_mcm_msg_t) + sizeof(struct ibv_grh);
	sge.lkey = tp->mr_rbuf->lkey;
	sge.addr = (uintptr_t)((char *)msg - sizeof(struct ibv_grh));
	
	return (ibv_post_recv(tp->qp, &recv_wr, &recv_err));
}

static int mcm_reject(ib_hca_transport_t *tp, dat_mcm_msg_t *msg)
{
	dat_mcm_msg_t	smsg;

	/* setup op, rearrange the src, dst cm and addr info */
	(void)dapl_os_memzero(&smsg, sizeof(smsg));
	smsg.ver = htons(DAT_MCM_VER);
	smsg.op = htons(MCM_REJ_CM);
	smsg.dport = msg->sport;
	smsg.dqpn = msg->sqpn;
	smsg.sport = msg->dport; 
	smsg.sqpn = msg->dqpn;

	dapl_os_memcpy(&smsg.daddr1, &msg->saddr1, sizeof(dat_mcm_addr_t));
	
	/* no dst_addr IB info in REQ, init lid, gid, get type from saddr1 */
	smsg.saddr1.lid = tp->addr.lid;
	smsg.saddr1.qp_type = msg->saddr1.qp_type;
	dapl_os_memcpy(&smsg.saddr1.gid[0],
		       &tp->addr.gid, 16);

	dapl_os_memcpy(&smsg.saddr1, &msg->daddr1, sizeof(dat_mcm_addr_t));

	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		     " CM reject -> LID %x, QPN %x PORT %x\n", 
		     ntohs(smsg.daddr1.lid),
		     ntohl(smsg.dqpn), ntohs(smsg.dport));

	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&tp->hca->ia_list_head)), DCNT_IA_CM_ERR_REJ_TX);
	return (mcm_send(tp, &smsg, NULL, 0));
}

void mcm_process_recv(ib_hca_transport_t *tp,
			     dat_mcm_msg_t *msg,
			     dp_ib_cm_handle_t cm)
{
	dapl_os_lock(&cm->lock);
	switch (cm->state) {
	case MCM_LISTEN: /* passive */
		dapl_os_unlock(&cm->lock);
		mcm_accept(cm, msg);
		break;
	case MCM_RTU_PENDING: /* passive */
		dapl_os_unlock(&cm->lock);
		mcm_accept_rtu(cm, msg);
		break;
	case MCM_REP_PENDING: /* active */
		dapl_os_unlock(&cm->lock);
		mcm_connect_rtu(cm, msg);
		break;
	case MCM_CONNECTED: /* active and passive */
		/* DREQ, change state and process */
		cm->retries = 2; 
		if (ntohs(msg->op) == MCM_DREQ) {
			cm->state = MCM_DISC_RECV;
			dapl_os_unlock(&cm->lock);
			dapli_cm_disconnect(cm);
			break;
		} 
		/* active: RTU was dropped, resend */
		if (ntohs(msg->op) == MCM_REP) {
			dapl_log(DAPL_DBG_TYPE_CM_WARN,
				 " RESEND RTU: op %s st %s [lid, port, cqp, iqp]:"
				 " %x %x %x %x -> %x %x %x %x r_pid %x\n",
				  dapl_cm_op_str(ntohs(cm->msg.op)),
				  dapl_cm_state_str(cm->state),
				 ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
				 ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn),
				 ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
				 ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn),
				 ntohl(cm->msg.d_id));

			cm->msg.op = htons(MCM_RTU);
			mcm_send(&cm->hca->ib_trans, &cm->msg, NULL, 0);

			DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ERR_RTU_RETRY);
		}
		dapl_os_unlock(&cm->lock);
		break;
	case MCM_DISC_PENDING: /* active and passive */
		/* DREQ or DREP, finalize */
		dapl_os_unlock(&cm->lock);
		mcm_disconnect_final(cm);
		break;
	case MCM_DISCONNECTED:
	case MCM_FREE:
		/* DREQ dropped, resend */
		if (ntohs(msg->op) == MCM_DREQ) {
			dapl_log(DAPL_DBG_TYPE_CM_WARN,
				" RESEND DREP: op %s st %s [lid, port, qpn]:"
				" %x %x %x -> %x %x %x\n", 
				dapl_cm_op_str(ntohs(msg->op)), 
				dapl_cm_state_str(cm->state),
				ntohs(msg->saddr1.lid),
				ntohs(msg->sport),
				ntohl(msg->saddr1.qpn),
				ntohs(msg->daddr1.lid),
				ntohs(msg->dport),
				ntohl(msg->daddr1.qpn));
			cm->msg.op = htons(MCM_DREP);
			mcm_send(&cm->hca->ib_trans, &cm->msg, NULL, 0);
			
			DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ERR_DREP_RETRY);

		} else if (ntohs(msg->op) != MCM_DREP){
			/* DREP ok to ignore, any other print warning */
			dapl_log(DAPL_DBG_TYPE_WARN,
				" mcm_recv: UNEXPECTED MSG on cm %p"
				" <- op %s, st %s spsp %x sqpn %x\n", 
				cm, dapl_cm_op_str(ntohs(msg->op)),
				dapl_cm_state_str(cm->state),
				ntohs(msg->sport), ntohl(msg->sqpn));
			DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ERR_UNEXPECTED);
		}
		dapl_os_unlock(&cm->lock);
		break;
	case MCM_REJECTED:
		if (ntohs(msg->op) == MCM_REJ_USER) {
			DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_USER_REJ_RX);
			dapl_os_unlock(&cm->lock);
			break;
		}
	default:
		dapl_log(DAPL_DBG_TYPE_WARN,
			" mcm_recv: Warning, UNKNOWN state"
			" <- op %s, %s spsp %x sqpn %x slid %x\n",
			dapl_cm_op_str(ntohs(msg->op)),
			dapl_cm_state_str(cm->state),
			ntohs(msg->sport), ntohl(msg->sqpn),
			ntohs(msg->saddr1.lid));
		dapl_os_unlock(&cm->lock);
		break;
	}
}

/* Find matching CM object for this receive message, return CM reference, timer */
dp_ib_cm_handle_t mcm_cm_find(ib_hca_transport_t *tp, dat_mcm_msg_t *msg)
{
	dp_ib_cm_handle_t cm = NULL, next, found = NULL;
	struct dapl_llist_entry	**list;
	DAPL_OS_LOCK *lock;
	int listenq = 0;

	/* conn list first, duplicate requests for MCM_REQ */
	list = &tp->list;
	lock = &tp->lock;

retry_listenq:
	dapl_os_lock(lock);
        if (!dapl_llist_is_empty(list))
		next = dapl_llist_peek_head(list);
	else
		next = NULL;

	while (next) {
		cm = next;
		next = dapl_llist_next_entry(list,
					     (DAPL_LLIST_ENTRY *)&cm->local_entry);
		if (cm->state == MCM_DESTROY || cm->state == MCM_FREE)
			continue;
		
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
		    cm->msg.daddr2.lid == msg->saddr2.lid) {
			if (ntohs(msg->op) != MCM_REQ) {
				found = cm;
				break; 
			} else {
				/* duplicate; bail and throw away */
				dapl_log(DAPL_DBG_TYPE_CM_WARN,
					 " DUPLICATE: cm %p op %s (%s) st %s"
					 " [lid, port, cqp, iqp]:"
					 " %x %x %x %x <- (%x %x %x %x :"
					 " %x %x %x %x) -> %x %x %x %x\n",
					 cm, dapl_cm_op_str(ntohs(msg->op)),
					 dapl_cm_op_str(ntohs(cm->msg.op)),
					 dapl_cm_state_str(cm->state),
					 ntohs(cm->msg.daddr2.lid), ntohs(cm->msg.dport),
					 ntohl(cm->msg.dqpn), ntohl(cm->msg.daddr1.qpn),
					 ntohs(msg->saddr2.lid), ntohs(msg->sport),
					 ntohl(msg->sqpn), ntohl(msg->saddr1.qpn),
					 ntohs(msg->daddr2.lid), ntohs(msg->dport),
					 ntohl(msg->dqpn), ntohl(msg->daddr1.qpn),
					 ntohs(cm->msg.saddr2.lid), ntohs(cm->msg.sport),
					 ntohl(cm->msg.sqpn), ntohl(cm->msg.saddr1.qpn));

				DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)),
					    DCNT_IA_CM_ERR_REQ_DUP);

				dapl_os_unlock(lock);
				return NULL;
			}
		}
	}
	dapl_os_unlock(lock);
	/* no duplicate request on connq, check listenq for new request */
	if (ntohs(msg->op) == MCM_REQ && !listenq && !found) {
		listenq = 1;
		list = &tp->llist;
		lock = &tp->llock;
		goto retry_listenq;
	}

	/* not match on listenq for valid request, send reject */
	if (ntohs(msg->op) == MCM_REQ && !found) {
		dapl_log(DAPL_DBG_TYPE_WARN,
			" mcm_recv: NO LISTENER for %s %x %x i%x c%x"
			" < %x %x %x, sending reject\n", 
			dapl_cm_op_str(ntohs(msg->op)), 
			ntohs(msg->daddr2.lid), ntohs(msg->dport),
			ntohl(msg->daddr1.qpn), ntohl(msg->sqpn),
			ntohs(msg->saddr2.lid), ntohs(msg->sport),
			ntohl(msg->saddr1.qpn));

		mcm_reject(tp, msg);
	}

	if (!found) {
		dapl_log(DAPL_DBG_TYPE_CM_WARN,
			 " NO MATCH: op %s [lid, port, cqp, iqp, pid]:"
			 " %x %x %x %x %x <- %x %x %x %x l_pid %x r_pid %x\n",
			 dapl_cm_op_str(ntohs(msg->op)),
			 ntohs(msg->daddr2.lid), ntohs(msg->dport),
			 ntohl(msg->dqpn), ntohl(msg->daddr1.qpn),
			 ntohl(msg->d_id), ntohs(msg->saddr2.lid),
			 ntohs(msg->sport), ntohl(msg->sqpn),
			 ntohl(msg->saddr1.qpn), ntohl(msg->s_id),
			 ntohl(msg->d_id));

		if (ntohs(msg->op) == MCM_DREP) {
			DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&tp->hca->ia_list_head)), DCNT_IA_CM_ERR_DREP_DUP);
		}
	}

	return found;
}

/* Get rmsgs from CM completion queue, 10 at a time */
static void mcm_recv(ib_hca_transport_t *tp)
{
	struct ibv_wc wc[10];
	dat_mcm_msg_t *msg;
	dp_ib_cm_handle_t cm;
	int i, ret, notify = 0;
	struct ibv_cq *ibv_cq = NULL;
	DAPL_HCA *hca;

	/* POLLIN on channel FD */
	ret = ibv_get_cq_event(tp->rch, &ibv_cq, (void *)&hca);
	if (ret == 0) {
		ibv_ack_cq_events(ibv_cq, 1);
	}
retry:	
	ret = ibv_poll_cq(tp->rcq, 10, wc);
	if (ret <= 0) {
		if (!ret && !notify) {
			ibv_req_notify_cq(tp->rcq, 0);
			notify = 1;
			goto retry;
		}
		return;
	} else 
		notify = 0;
	
	for (i = 0; i < ret; i++) {
		msg = (dat_mcm_msg_t*) (uintptr_t) wc[i].wr_id;

		dapl_dbg_log(DAPL_DBG_TYPE_CM, 
			     " mcm_recv: stat=%d op=%s ln=%d id=%p qp2=%x\n",
			     wc[i].status, dapl_cm_op_str(ntohs(msg->op)),
			     wc[i].byte_len,
			     (void*)wc[i].wr_id, wc[i].src_qp);

		/* validate CM message, version */
		if (ntohs(msg->ver) != DAT_MCM_VER) {
			dapl_log(DAPL_DBG_TYPE_WARN,
				 " mcm_recv: UNKNOWN msg %p, ver %d\n",
				 msg, msg->ver);
			mcm_post_rmsg(tp, msg);
			continue;
		}
		if (!(cm = mcm_cm_find(tp, msg))) {
			mcm_post_rmsg(tp, msg);
			continue;
		}
		
		/* match, process it */
		mcm_process_recv(tp, msg, cm);
		mcm_post_rmsg(tp, msg);
	}
	
	/* finished this batch of WC's, poll and rearm */
	goto retry;
}

/* ACTIVE/PASSIVE: build and send CM message out of CM object */
static int mcm_send(ib_hca_transport_t *tp, dat_mcm_msg_t *msg, DAT_PVOID p_data, DAT_COUNT p_size)
{
	dat_mcm_msg_t *smsg = NULL;
	struct ibv_send_wr wr, *bad_wr;
	struct ibv_sge sge;
	int len, ret = -1;
	uint16_t dlid = ntohs(msg->daddr2.lid);

	/* Get message from send queue, copy data, and send */
	dapl_os_lock(&tp->slock);
	if ((smsg = mcm_get_smsg(tp)) == NULL) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			" mcm_send ERR: get_smsg(hd=%d,tl=%d) \n",
			tp->s_hd, tp->s_tl);
		goto bail;
	}

	len = sizeof(dat_mcm_msg_t);
	dapl_os_memcpy(smsg, msg, len);
	if (p_size) {
		smsg->p_size = ntohs(p_size);
		dapl_os_memcpy(&smsg->p_data, p_data, p_size);
	} else
		smsg->p_size = 0;

	wr.next = NULL;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        wr.opcode = IBV_WR_SEND;
        wr.wr_id = (unsigned long)tp->s_hd;
	wr.send_flags = (wr.wr_id % tp->burst) ? 0 : IBV_SEND_SIGNALED;
	if (len <= tp->ib_cm.max_inline)
		wr.send_flags |= IBV_SEND_INLINE; 

        sge.length = len;
        sge.lkey = tp->mr_sbuf->lkey;
        sge.addr = (uintptr_t)smsg;

	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		" mcm_send: op %s ln %d lid %x c_qpn %x rport %x\n",
		dapl_cm_op_str(ntohs(smsg->op)), 
		sge.length, htons(smsg->daddr1.lid),
		htonl(smsg->dqpn), htons(smsg->dport));

	/* empty slot, then create AH */
	if (!tp->ah[dlid]) {
		tp->ah[dlid] = 	
			dapls_create_ah(tp->hca, tp->pd, tp->qp, 
					htons(dlid), NULL);
		if (!tp->ah[dlid])
			goto bail;
	}
		
	wr.wr.ud.ah = tp->ah[dlid];
	wr.wr.ud.remote_qpn = ntohl(smsg->dqpn);
	wr.wr.ud.remote_qkey = DAT_MCM_UD_QKEY;

	ret = ibv_post_send(tp->qp, &wr, &bad_wr);
	if (ret) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " mcm_send ERR: post_send() %s\n",
			 strerror(errno) );
	}

bail:
	dapl_os_unlock(&tp->slock);	
	return ret;
}

/* ACTIVE/PASSIVE: CM objects */
static void dapli_cm_dealloc(dp_ib_cm_handle_t cm) {

	dapl_os_assert(!cm->ref_count);
	dapl_os_lock_destroy(&cm->lock);
	dapl_os_wait_object_destroy(&cm->d_event);
	dapl_os_wait_object_destroy(&cm->f_event);
	dapl_os_free(cm, sizeof(*cm));
}

void dapls_cm_acquire(dp_ib_cm_handle_t cm)
{
	dapl_os_lock(&cm->lock);
	cm->ref_count++;
	dapl_os_unlock(&cm->lock);
}

void dapls_cm_release(dp_ib_cm_handle_t cm)
{
	dapl_os_lock(&cm->lock);
	cm->ref_count--;

	if (cm->ref_count) {
		if (cm->ref_count == 1)
			dapl_os_wait_object_wakeup(&cm->f_event);
                dapl_os_unlock(&cm->lock);
		return;
	}

	/* active, release local conn id port, if exists on client */
	if (!cm->sp && cm->msg.sport && cm->tp->sid)
		mcm_free_port(cm->tp, ntohs(cm->msg.sport));

	/* clean up any UD address handles */
	if (cm->ah) {
		ibv_destroy_ah(cm->ah);
		cm->ah = NULL;
	}
	dapl_os_unlock(&cm->lock);
	dapli_cm_dealloc(cm);
}

dp_ib_cm_handle_t dapls_cm_create(DAPL_HCA *hca, DAPL_EP *ep)
{
	dp_ib_cm_handle_t cm;

	/* Allocate CM, init lock, and initialize */
	if ((cm = dapl_os_alloc(sizeof(*cm))) == NULL)
		return NULL;

	(void)dapl_os_memzero(cm, sizeof(*cm));
	if (dapl_os_lock_init(&cm->lock))
		goto bail;
	
	if (dapl_os_wait_object_init(&cm->f_event)) {
		dapl_os_lock_destroy(&cm->lock);
		goto bail;
	}
	if (dapl_os_wait_object_init(&cm->d_event)) {
		dapl_os_lock_destroy(&cm->lock);
		dapl_os_wait_object_destroy(&cm->f_event);
		goto bail;
	}
	dapls_cm_acquire(cm);
	cm->hca = hca;
	cm->tp = &hca->ib_trans;
	cm->msg.ver = htons(DAT_MCM_VER);
	cm->msg.s_id = htonl(dapl_os_getpid()); /* process id for src id */
	cm->msg.sys_guid = hca->ib_trans.sys_guid;
	cm->msg.seg_sz = DAT_MCM_SEG_PO2;
	
	/* ACTIVE: init source address QP info from local EP */
	if (ep) {
		if (!hca->ib_trans.scif_ep) { /* CM service local and not on MPXYD */

			cm->msg.sport = htons(mcm_get_port(&hca->ib_trans, 0));
			if (!cm->msg.sport) {
				dapl_os_wait_object_destroy(&cm->f_event);
				dapl_os_wait_object_destroy(&cm->d_event);
				dapl_os_lock_destroy(&cm->lock);
				goto bail;
			}
			cm->msg.sqpn = htonl(hca->ib_trans.qp->qp_num); /* ucm */
			cm->msg.saddr2.qpn = htonl(ep->qp_handle->qp2->qp_num); /* QPt */
			cm->msg.saddr2.qp_type = ep->qp_handle->qp->qp_type;
			cm->msg.saddr2.lid = hca->ib_trans.addr.lid;
			cm->msg.saddr2.ep_map = hca->ib_trans.addr.ep_map;
			dapl_os_memcpy(&cm->msg.saddr2.gid[0],
				       &hca->ib_trans.addr.gid, 16);

		}
		/* QPr is on proxy when xsocket from device */
		if (!MXF_EP(&hca->ib_trans.addr)) {
			cm->msg.saddr1.qpn = htonl(ep->qp_handle->qp->qp_num); /* QPr local*/
			cm->msg.saddr1.qp_type = ep->qp_handle->qp->qp_type;
			cm->msg.saddr1.lid = hca->ib_trans.addr.lid;
			cm->msg.saddr1.ep_map = hca->ib_trans.addr.ep_map;
			dapl_os_memcpy(&cm->msg.saddr1.gid[0],
				       &hca->ib_trans.addr.gid, 16);
		}

		/* link CM object to EP */
		dapl_ep_link_cm(ep, cm);
		cm->ep = ep;
        }
	return cm;
bail:
	dapl_os_free(cm, sizeof(*cm));
	return NULL;
}

/* schedule destruction of CM object */
void dapli_cm_free(dp_ib_cm_handle_t cm)
{
	dapl_os_lock(&cm->lock);
	cm->state = MCM_FREE;
	dapls_thread_signal(&cm->hca->ib_trans.signal);
	dapl_os_unlock(&cm->lock);
}

/* Blocking, ONLY called from dat_ep_free */
void dapls_cm_free(dp_ib_cm_handle_t cm)
{
	/* free from internal workq, wait until EP is last ref */
	dapl_os_lock(&cm->lock);
	cm->state = MCM_FREE;
	if (cm->ref_count != 1) {
		dapl_os_unlock(&cm->lock);
		dapls_thread_signal(&cm->hca->ib_trans.signal);
		dapl_os_wait_object_wait(&cm->f_event, DAT_TIMEOUT_INFINITE);
		dapl_os_lock(&cm->lock);
	}
	dapl_os_unlock(&cm->lock);

	/* unlink, dequeue from EP. Final ref so release will destroy */
	dapl_ep_unlink_cm(cm->ep, cm);
}

DAT_RETURN dapls_ud_cm_free(DAPL_EP *ep_ptr, dp_ib_cm_handle_t cm_ptr)
{
	return DAT_NOT_IMPLEMENTED;
}

/* ACTIVE/PASSIVE: queue up connection object on CM list */
void dapli_queue_conn(dp_ib_cm_handle_t cm)
{
	/* add to work queue, list, for cm thread processing */
	dapl_llist_init_entry((DAPL_LLIST_ENTRY *)&cm->local_entry);
	dapl_os_lock(&cm->hca->ib_trans.lock);
	dapls_cm_acquire(cm);
	dapl_llist_add_tail(&cm->hca->ib_trans.list,
			    (DAPL_LLIST_ENTRY *)&cm->local_entry, cm);
	dapl_os_unlock(&cm->hca->ib_trans.lock);
	if (!cm->hca->ib_trans.scif_ep)
		dapls_thread_signal(&cm->hca->ib_trans.signal);
}

/* PASSIVE: queue up listen object on listen list */
static void dapli_queue_listen(dp_ib_cm_handle_t cm)
{
	/* add to work queue, llist, for cm thread processing */
	dapl_llist_init_entry((DAPL_LLIST_ENTRY *)&cm->local_entry);
	dapl_os_lock(&cm->hca->ib_trans.llock);
	dapls_cm_acquire(cm);
	dapl_llist_add_tail(&cm->hca->ib_trans.llist,
			    (DAPL_LLIST_ENTRY *)&cm->local_entry, cm);
	dapl_os_unlock(&cm->hca->ib_trans.llock);
}

static void dapli_dequeue_listen(dp_ib_cm_handle_t cm) 
{
	DAPL_HCA *hca = cm->hca;

	dapl_os_lock(&hca->ib_trans.llock);
	dapl_llist_remove_entry(&hca->ib_trans.llist, 
				(DAPL_LLIST_ENTRY *)&cm->local_entry);
	dapls_cm_release(cm);
	dapl_os_unlock(&hca->ib_trans.llock);
}

/* called with local LIST and CM object lock */
void dapli_cm_dequeue(dp_ib_cm_handle_t cm)
{
	/* Remove from work queue, cr thread processing */
	dapl_llist_remove_entry(&cm->hca->ib_trans.list,
				(DAPL_LLIST_ENTRY *)&cm->local_entry);
	dapls_cm_release(cm);
}

void mcm_disconnect_final(dp_ib_cm_handle_t cm)
{
	/* no EP attachment or not RC, nothing to process */
	if (cm->ep == NULL ||
	    cm->ep->param.ep_attr.service_type != DAT_SERVICE_TYPE_RC) 
		return;

	dapl_os_lock(&cm->lock);
	if ((cm->state == MCM_DISCONNECTED) || (cm->state == MCM_FREE)) {
		dapl_os_unlock(&cm->lock);
		return;
	}
		
	cm->state = MCM_DISCONNECTED;
	dapl_os_unlock(&cm->lock);

	if (cm->sp) 
		dapls_cr_callback(cm, IB_CME_DISCONNECTED, NULL, 0, cm->sp);
	else
		dapl_evd_connection_callback(cm, IB_CME_DISCONNECTED, NULL, 0, cm->ep);

	dapl_os_wait_object_wakeup(&cm->d_event);

}

/*
 * called from consumer thread via ep_disconnect/ep_free or 
 * from cm_thread when receiving DREQ
 */
DAT_RETURN dapli_cm_disconnect(dp_ib_cm_handle_t cm)
{
	int finalize = 1;
	int wakeup = 0;

	dapl_os_lock(&cm->lock);
	switch (cm->state) {
	case MCM_CONNECTED:
		/* CONSUMER: move to err state to flush, if not UD */
		if (cm->ep->param.ep_attr.service_type == DAT_SERVICE_TYPE_RC)
			dapls_modify_qp_state(cm->ep->qp_handle->qp, IBV_QPS_ERR,0,0,0);

		/* send DREQ, event after DREP or DREQ timeout */
		cm->state = MCM_DISC_PENDING;
		cm->msg.op = htons(MCM_DREQ);
		finalize = 0; /* wait for DREP, wakeup timer after DREQ sent */
		wakeup = 1;
		DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_DREQ_TX);
		break;
	case MCM_DISC_PENDING:
		/* DREQ timeout, resend until retries exhausted */
		cm->msg.op = htons(MCM_DREQ);
		if (cm->retries >= cm->hca->ib_trans.retries) {
			dapl_log(DAPL_DBG_TYPE_ERR, 
				" CM_DREQ: RETRIES EXHAUSTED:"
				" %x %x %x -> %x %x %x\n",
				htons(cm->msg.saddr1.lid),
				htonl(cm->msg.saddr1.qpn),
				htons(cm->msg.sport), 
				htons(cm->msg.daddr1.lid),
				htonl(cm->msg.dqpn), 
				htons(cm->msg.dport));
			finalize = 1;
		}
		DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ERR_DREQ_RETRY);
		break;
	case MCM_DISC_RECV:
		/* CM_THREAD: move to err state to flush, if not UD */
		if (cm->ep->param.ep_attr.service_type == DAT_SERVICE_TYPE_RC)
			dapls_modify_qp_state(cm->ep->qp_handle->qp, IBV_QPS_ERR,0,0,0);

		/* DREQ received, send DREP and schedule event, finalize */
		cm->msg.op = htons(MCM_DREP);
		DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_DREP_TX);
		break;
	case MCM_DISCONNECTED:
		dapl_os_unlock(&cm->lock);
		return DAT_SUCCESS;
	default:
		dapl_log(DAPL_DBG_TYPE_EP, 
			"  disconnect UNKNOWN state: ep %p cm %p %s %s"
			"  %x %x %x %s %x %x %x r_id %x l_id %x\n",
			cm->ep, cm,
			cm->msg.saddr1.qp_type == IBV_QPT_RC ? "RC" : "UD",
			dapl_cm_state_str(cm->state),
			ntohs(cm->msg.saddr1.lid),
			ntohs(cm->msg.sport),
			ntohl(cm->msg.saddr1.qpn),
			cm->sp ? "<-" : "->",
			ntohs(cm->msg.daddr1.lid),
			ntohs(cm->msg.dport),
			ntohl(cm->msg.daddr1.qpn),
			ntohl(cm->msg.d_id),
			ntohl(cm->msg.s_id));

		dapl_os_unlock(&cm->lock);
		return DAT_SUCCESS;
	}
	
	dapl_os_get_time(&cm->timer); /* reply expected */
	mcm_send(&cm->hca->ib_trans, &cm->msg, NULL, 0);
	dapl_os_unlock(&cm->lock);
	
	if (wakeup)
		dapls_thread_signal(&cm->hca->ib_trans.signal);

	if (finalize) 
		mcm_disconnect_final(cm);
	
	return DAT_SUCCESS;
}

/*
 * ACTIVE: get remote CM SID server info from r_addr. 
 *         send, or resend CM msg via UD CM QP 
 */
DAT_RETURN
dapli_cm_connect(DAPL_EP *ep, dp_ib_cm_handle_t cm)
{
	/* ibscif: intra-node, MIC lid != HST lid,
	 * HST->HST/MIC (CM always HST lid)
	 * 	CM locality via addr2
	 * 	EP locality via addr1
	 */
	if (!strncmp(cm->hca->name, "scif", 4) &&
	    HST_EP(&cm->hca->ib_trans.addr)) {
		cm->msg.daddr2.lid = cm->tp->addr.lid;
		memcpy(cm->msg.daddr2.gid, cm->tp->addr.gid, 16);
	}

	dapl_log(DAPL_DBG_TYPE_CM,
		 " MCM connect: lid %x QPr %x QPt %x lport %x p_sz=%d -> "
		 " lid %x clid %x cqpn %x rport %x, %s -> %s"
		 " retries=%d\n",
		 htons(cm->tp->addr.lid), htonl(cm->msg.saddr1.qpn),
		 htonl(cm->msg.saddr2.qpn),
		 htons(cm->msg.sport), htons(cm->msg.p_size),
		 htons(cm->msg.daddr1.lid), htons(cm->msg.daddr2.lid),
		 htonl(cm->msg.dqpn), htons(cm->msg.dport),
		 mcm_map_str(cm->tp->addr.ep_map),
		 mcm_map_str(cm->msg.daddr1.ep_map),
		 cm->tp->retries);

	dapl_os_lock(&cm->lock);
	if (cm->state != MCM_INIT && cm->state != MCM_REP_PENDING) {
		dapl_os_unlock(&cm->lock);
		return DAT_INVALID_STATE;
	}
	
	if (cm->retries == cm->hca->ib_trans.retries) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			" CM_REQ: RETRIES (%d) EXHAUSTED:"
			 " 0x%x %x 0x%x -> 0x%x %x 0x%x\n",
			 cm->retries, htons(cm->msg.saddr1.lid),
			 htonl(cm->msg.saddr1.qpn),
			 htons(cm->msg.sport), 
			 htons(cm->msg.daddr1.lid),
			 htonl(cm->msg.dqpn), 
			 htons(cm->msg.dport));

		dapl_os_unlock(&cm->lock);

#ifdef DAPL_COUNTERS
		/* called from check_timers in cm_thread, cm lock held */
		if (g_dapl_dbg_type & DAPL_DBG_TYPE_CM_LIST) {
			dapl_os_unlock(&cm->hca->ib_trans.lock);
			dapls_print_cm_list(ep->header.owner_ia);
			dapl_os_lock(&cm->hca->ib_trans.lock);
		}
#endif
		dapl_evd_connection_callback(cm, 
					     IB_CME_DESTINATION_UNREACHABLE,
					     NULL, 0, ep);
		
		return DAT_ERROR(DAT_INVALID_ADDRESS, 
				 DAT_INVALID_ADDRESS_UNREACHABLE);
	}

	cm->state = MCM_REP_PENDING;
	cm->msg.op = htons(MCM_REQ);
	dapl_os_get_time(&cm->timer); /* reset reply timer */

	if (cm->tp->scif_ep) {	/* MIC: proxy CR to MPXYD */
		if (dapli_mix_cm_req_out(cm, ep->qp_handle))
			goto bail;
	} else {
		if (mcm_send(&cm->hca->ib_trans, &cm->msg,
			     &cm->msg.p_data, ntohs(cm->msg.p_size)))
			goto bail;
	}
	dapl_os_unlock(&cm->lock);
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)),
		  ep->param.ep_attr.service_type != DAT_SERVICE_TYPE_RC ?
		  DCNT_IA_CM_AH_REQ_TX : DCNT_IA_CM_REQ_TX);

	return DAT_SUCCESS;

bail:
	dapl_os_unlock(&cm->lock);
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ERR);
	dapl_log(DAPL_DBG_TYPE_WARN, 
		 " connect: snd ERR -> cm_lid %x cm_qpn %x r_psp %x p_sz=%d\n",
		 htons(cm->msg.daddr1.lid),
		 htonl(cm->msg.dqpn), htons(cm->msg.dport), 
		 htons(cm->msg.p_size));

	dapli_cm_free(cm);
	return DAT_INSUFFICIENT_RESOURCES;
}

/*
 * ACTIVE: exchange QP information, called from CR thread
 */
void mcm_connect_rtu(dp_ib_cm_handle_t cm, dat_mcm_msg_t *msg)
{
	DAPL_EP *ep = cm->ep;
	ib_cm_events_t event = IB_CME_CONNECTED;
	DAT_RETURN ret;

	dapl_os_lock(&cm->lock);
	if (cm->state != MCM_REP_PENDING) {
		dapl_log(DAPL_DBG_TYPE_WARN, 
			 " CONN_RTU: UNEXPECTED state:"
			 " op %s, st %s <- lid %x sqpn %x sport %x\n", 
			 dapl_cm_op_str(ntohs(msg->op)), 
			 dapl_cm_state_str(cm->state), 
			 ntohs(msg->saddr1.lid), ntohl(msg->saddr1.qpn),
			 ntohs(msg->sport));
		dapl_os_unlock(&cm->lock);
		return;
	}

	/* CM_REP: save remote address information to EP and CM */
	if (msg->seg_sz) /* set po2 seg_sz, if provided */
		cm->msg.seg_sz = msg->seg_sz;

	/* Set QP MTU, if negotiated. 2K for compatibility */
	ep->qp_handle->mtu = msg->mtu ?
			     DAPL_MIN(msg->mtu, cm->hca->ib_trans.ib_cm.mtu):
			     getenv("DAPL_IB_MTU") ? cm->hca->ib_trans.ib_cm.mtu : IBV_MTU_2048;

	cm->msg.d_id = msg->s_id;
	dapl_os_memcpy(&ep->remote_ia_address, &msg->saddr2, sizeof(dat_mcm_addr_t));
	dapl_os_memcpy(&cm->msg.daddr2, &msg->saddr2, sizeof(dat_mcm_addr_t));
	dapl_os_memcpy(&cm->msg.daddr1, &msg->saddr1, sizeof(dat_mcm_addr_t));
	dapl_os_memcpy(&cm->msg.p_proxy, &msg->p_proxy, DAT_MCM_PROXY_DATA);

	/* validate private data size, and copy if necessary */
	if (msg->p_size) {
		if (ntohs(msg->p_size) > DAT_MCM_PDATA_SIZE) {
			dapl_log(DAPL_DBG_TYPE_WARN, 
				 " CONN_RTU: invalid p_size %d:"
				 " st %s <- lid %x sqpn %x s2qpn %x spsp %x\n",
				 ntohs(msg->p_size), 
				 dapl_cm_state_str(cm->state), 
				 ntohs(msg->saddr1.lid),
				 ntohl(msg->saddr1.qpn),
				 ntohl(msg->saddr2.qpn),
				 ntohs(msg->sport));
			dapl_os_unlock(&cm->lock);
			goto bail;
		}
		dapl_os_memcpy(cm->msg.p_data, msg->p_data, ntohs(msg->p_size));
	}
		
	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		     " CONN_RTU: DST lid=%x, QPr=%x, QPt=%x qp_type=%d,"
		     " port=%x psize=%d mtu=%d,%d\n",
		     ntohs(cm->msg.daddr1.lid), ntohl(cm->msg.daddr1.qpn),
		     ntohl(cm->msg.daddr2.qpn), cm->msg.daddr1.qp_type,
		     ntohs(msg->sport), ntohs(msg->p_size),
		     cm->tp->ib_cm.mtu, cm->msg.mtu);

	if (ntohs(msg->op) == MCM_REP)
		event = IB_CME_CONNECTED;
	else if (ntohs(msg->op) == MCM_REJ_USER)
		event = IB_CME_DESTINATION_REJECT_PRIVATE_DATA;
	else  {
		dapl_log(DAPL_DBG_TYPE_WARN,
			 " Warning, non-user CR REJECT:"
			 " cm %p op %s, st %s dlid %x iqp %x iqp2 %xport %x <-"
			 " slid %x iqp %x port %x\n", cm,
			 dapl_cm_op_str(ntohs(msg->op)), dapl_cm_state_str(cm->state),
			 ntohs(msg->daddr1.lid), ntohl(msg->daddr1.qpn),ntohl(msg->daddr2.qpn),
			 ntohs(msg->dport), ntohs(msg->saddr1.lid), ntohl(msg->saddr1.qpn),
			 ntohs(msg->sport));
		DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ERR_REJ_RX);
		event = IB_CME_DESTINATION_REJECT;
	}
	if (event != IB_CME_CONNECTED) {
		dapl_log(DAPL_DBG_TYPE_CM, 
			 " ACTIVE: CM_REQ REJECTED:"
			 " cm %p op %s, st %s dlid %x iqp %x port %x <-"
			 " slid %x iqp %x port %x\n", cm,
			 dapl_cm_op_str(ntohs(msg->op)), 
			 dapl_cm_state_str(cm->state), 
			 ntohs(msg->daddr1.lid), ntohl(msg->daddr1.qpn),
			 ntohs(msg->dport), ntohs(msg->saddr1.lid),
			 ntohl(msg->saddr1.qpn), ntohs(msg->sport));

		cm->state = MCM_REJECTED;
		dapl_os_unlock(&cm->lock);
		goto bail;
	}
	dapl_os_unlock(&cm->lock);

 	/* QP to RTR-RTS with remote QPt (daddr2) info */
	dapl_os_lock(&cm->ep->header.lock);

	if (!MXF_EP(&cm->hca->ib_trans.addr)) {
		ret = dapls_modify_qp_rtu(cm->ep->qp_handle->qp,
					  cm->msg.daddr2.qpn,
					  cm->msg.daddr2.lid,
					  (ib_gid_handle_t)cm->msg.daddr2.gid);
		if (ret != DAT_SUCCESS) {
			dapl_os_unlock(&cm->ep->header.lock);
			event = IB_CME_LOCAL_FAILURE;
			goto bail;
		}
	}

	/* QP to RTR-RTS with remote QPr (daddr1) info */
	if (!cm->tp->scif_ep) { /* NON-MIC, qp2 is local and not on MPXYD */
		ret = dapls_modify_qp_rtu(
				cm->ep->qp_handle->qp2,
			    	cm->msg.daddr1.qpn,
			    	cm->msg.daddr1.lid,
			    	(ib_gid_handle_t)cm->msg.daddr1.gid);
		if (ret != DAT_SUCCESS) {
			dapl_os_unlock(&cm->ep->header.lock);
			event = IB_CME_LOCAL_FAILURE;
			goto bail;
		}
		/* MXS peer: setup PI WC and save peer WR queue info */
		if (MXF_EP(&cm->msg.daddr1)) {
			/* save PI WR info, create local WC_q, send back WC info */
			mcm_ntoh_wrc(&ep->qp_handle->wrc_rem, (mcm_wrc_info_t*)cm->msg.p_proxy);
			if (ep->qp_handle->wrc_rem.wr_sz > MCM_WR_RX_NO_DATA)
				ep->qp_handle->p2p_data = DAT_MCM_P2P_INLINE;
			else
				ep->qp_handle->p2p_data = 0;

			dapl_log(DAPL_DBG_TYPE_CM, "CONN_RTU: qp %p set proxy max inline to %d\n",
					ep->qp_handle, ep->qp_handle->p2p_data);

			mcm_create_wc_q(ep->qp_handle, ep->qp_handle->wrc_rem.wr_end + 1);
			mcm_hton_wrc((mcm_wrc_info_t*)cm->msg.p_proxy, &ep->qp_handle->wrc);
			ep->qp_handle->ep_map = cm->msg.daddr1.ep_map;
			ep->qp_handle->seg_sz = (1 << cm->msg.seg_sz);

			/* post 0-byte rcv for inbound WC's via RW_imm */
			if (mcm_post_rcv_wc(ep->qp_handle, MCM_WRC_QLEN))
				goto bail;

			dapl_log(DAPL_DBG_TYPE_CM, "CONN_RTU: WR_rem %p sz %d, WC %p sz %d, sg %d\n",
				 ep->qp_handle->wrc_rem.wr_addr,
				 ep->qp_handle->wrc_rem.wr_end+1,
				 ep->qp_handle->wrc.wc_addr,
				 ep->qp_handle->wrc.wc_end+1,
				 ep->qp_handle->seg_sz);
		}
	}
	dapl_os_unlock(&cm->ep->header.lock);
	
	/* Send RTU, no private data */
	cm->msg.op = htons(MCM_RTU);
	cm->msg.mtu = ep->qp_handle->mtu; /* send negotiated MTU */
	
	dapl_os_lock(&cm->lock);
	cm->state = MCM_CONNECTED;
	if (cm->tp->scif_ep) {	/* MPXYD */
		dapli_mix_cm_rtu_out(cm);
	} else {
		if (mcm_send(&cm->hca->ib_trans, &cm->msg, NULL, 0)) {
			dapl_os_unlock(&cm->lock);
			goto bail;
		}
	}
	dapl_os_unlock(&cm->lock);
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_RTU_TX);

	/* init cm_handle and post the event with private data */
	dapl_dbg_log(DAPL_DBG_TYPE_EP, " ACTIVE: connected!\n");
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ACTIVE_EST);
	dapl_evd_connection_callback(cm,
				     IB_CME_CONNECTED,
				     cm->msg.p_data, ntohs(cm->msg.p_size), cm->ep);

	dapl_log(DAPL_DBG_TYPE_CM_EST,
		 " mcm_ACTIVE_CONN %p %d [lid port qpn] %x %x %x -> %x %x %x %s mtu %d\n",
		 cm->hca, cm->retries, ntohs(cm->msg.saddr1.lid),
		 ntohs(cm->msg.sport), ntohl(cm->msg.saddr1.qpn),
		 ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
		 ntohl(cm->msg.dqpn), mcm_map_str(cm->msg.daddr1.ep_map),
		 cm->ep->qp_handle->mtu);

	mcm_log_addrs(DAPL_DBG_TYPE_CM_EST, &cm->msg, cm->state, 0);

	return;
bail:
	dapl_evd_connection_callback(NULL, event, cm->msg.p_data, ntohs(cm->msg.p_size), cm->ep);
	dapli_cm_free(cm);
}

/*
 * PASSIVE: Accept on listen CM PSP.
 *          create new CM object for this CR, 
 *	    receive peer QP information, private data, 
 *	    and post cr_event 
 */
static void mcm_accept(ib_cm_srvc_handle_t cm, dat_mcm_msg_t *msg)
{
	dp_ib_cm_handle_t acm;

	/* Allocate accept CM and setup passive references */
	if ((acm = dapls_cm_create(cm->hca, NULL)) == NULL) {
		dapl_log(DAPL_DBG_TYPE_WARN, " accept: ERR cm_create\n");
		return;
	}

	/* dest CM info from CR msg, source CM info from listen */
	acm->sp = cm->sp;
	acm->hca = cm->hca;
	acm->tp = cm->tp;
	acm->msg.op = msg->op;
	acm->msg.dport = msg->sport;
	acm->msg.dqpn = msg->sqpn;
	acm->msg.sport = cm->msg.sport; 
	acm->msg.sqpn = cm->msg.sqpn;
	acm->msg.p_size = msg->p_size;
	acm->msg.d_id = msg->s_id;
	acm->msg.rd_in = msg->rd_in;
	acm->msg.mtu = msg->mtu; /* save peer MTU */
	if (msg->seg_sz) /* set po2 seg_sz, if provided */
		acm->msg.seg_sz = msg->seg_sz;

	/* CR saddr1 is CM daddr1 info, need EP for local saddr1 */
	dapl_os_memcpy(&acm->msg.daddr1, &msg->saddr1, sizeof(dat_mcm_addr_t));
	dapl_os_memcpy(&acm->msg.daddr2, &msg->saddr2, sizeof(dat_mcm_addr_t));
	dapl_os_memcpy(&acm->msg.p_proxy, &msg->p_proxy, DAT_MCM_PROXY_DATA);
	
	dapl_log(DAPL_DBG_TYPE_CM,
		 " accept: DST port=%x lid=%x, iqp=%x, iqp2=%x, psize=%d\n",
		 ntohs(acm->msg.dport), ntohs(acm->msg.daddr1.lid),
		 htonl(acm->msg.daddr1.qpn),  htonl(acm->msg.daddr2.qpn), htons(acm->msg.p_size));

	/* validate private data size before reading */
	if (ntohs(msg->p_size) > DAT_MCM_PDATA_SIZE) {
		dapl_log(DAPL_DBG_TYPE_WARN, " accept: psize (%d) wrong\n",
			 ntohs(msg->p_size));
		goto bail;
	}

	/* read private data into cm_handle if any present */
	if (msg->p_size) 
		dapl_os_memcpy(acm->msg.p_data, 
			       msg->p_data, ntohs(msg->p_size));
		
	acm->state = MCM_ACCEPTING;
	dapli_queue_conn(acm);

	/* trigger CR event and return SUCCESS */
	dapls_cr_callback(acm,
			  IB_CME_CONNECTION_REQUEST_PENDING,
			  acm->msg.p_data, ntohs(msg->p_size), acm->sp);
	return;
bail:
	/* schedule work thread cleanup */
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ERR);
	dapli_cm_free(acm);
	return;
}

/*
 * PASSIVE: read RTU from active peer, post CONN event
 */
static void mcm_accept_rtu(dp_ib_cm_handle_t cm, dat_mcm_msg_t *msg)
{
	dapl_os_lock(&cm->lock);
	if ((ntohs(msg->op) != MCM_RTU) || (cm->state != MCM_RTU_PENDING)) {
		dapl_log(DAPL_DBG_TYPE_WARN, 
			 " accept_rtu: UNEXPECTED op, state:"
			 " op %s, st %s <- lid %x iqp %x iqp2 %x sport %x\n",
			 dapl_cm_op_str(ntohs(msg->op)), 
			 dapl_cm_state_str(cm->state), 
			 ntohs(msg->saddr1.lid), ntohl(msg->saddr1.qpn),
			 ntohl(msg->saddr1.qpn), ntohs(msg->sport));
		dapl_os_unlock(&cm->lock);
		goto bail;
	}
	cm->state = MCM_CONNECTED;
	dapl_os_unlock(&cm->lock);
	
	/* final data exchange if remote QP state is good to go */
	dapl_dbg_log(DAPL_DBG_TYPE_CM, " PASSIVE: connected!\n");

	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_PASSIVE_EST);

	dapls_cr_callback(cm, IB_CME_CONNECTED, NULL, 0, cm->sp);

	dapl_log(DAPL_DBG_TYPE_CM_EST,
		 " PASSIVE_CONN %p %d [lid port qpn] %x %x %x <- %x %x %x %s mtu %d\n",
		 cm->hca, cm->retries, ntohs(cm->msg.saddr1.lid),
		 ntohs(cm->msg.sport), ntohl(cm->msg.saddr1.qpn),
		 ntohs(cm->msg.daddr1.lid), ntohs(cm->msg.dport),
		 ntohl(cm->msg.dqpn), mcm_map_str(cm->msg.daddr1.ep_map),
		 cm->ep->qp_handle->mtu);

	mcm_log_addrs(DAPL_DBG_TYPE_CM_EST, &cm->msg, cm->state, 1);
	return;
bail:
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)), DCNT_IA_CM_ERR);
	dapls_cr_callback(cm, IB_CME_LOCAL_FAILURE, NULL, 0, cm->sp);
	dapli_cm_free(cm);
}

/*
 * PASSIVE: user accepted, check and re-send reply message, called from cm_thread.
 */
static int mcm_reply(dp_ib_cm_handle_t cm)
{
	dapl_os_lock(&cm->lock);
	if (cm->state != MCM_RTU_PENDING) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " CM_REPLY: wrong state ep %p cm %p %s refs=%d"
			 " %x %x i_%x i2 %x -> %x %x i_%x i_2 %x l_pid %x r_pid %x\n",
			 cm->ep, cm, dapl_cm_state_str(cm->state),
			 cm->ref_count,
			 htons(cm->msg.saddr1.lid), htons(cm->msg.sport),
			 htonl(cm->msg.saddr1.qpn), htonl(cm->msg.saddr2.qpn),
			 htons(cm->msg.daddr1.lid), htons(cm->msg.dport),
			 htonl(cm->msg.daddr1.qpn), htonl(cm->msg.daddr2.qpn),
			 ntohl(cm->msg.s_id), ntohl(cm->msg.d_id));
		dapl_os_unlock(&cm->lock);
		return -1;
	}

	if (cm->retries == cm->hca->ib_trans.retries) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			" CM_REPLY: RETRIES EXHAUSTED (lid port qpn)"
			 " %x %x %x %x -> %x %x %x %x \n",
			 htons(cm->msg.saddr1.lid), htons(cm->msg.sport),
			 htonl(cm->msg.saddr1.qpn), htonl(cm->msg.saddr2.qpn),
			 htons(cm->msg.daddr1.lid), htons(cm->msg.dport),
			 htonl(cm->msg.daddr1.qpn), htonl(cm->msg.daddr2.qpn));
			
		dapl_os_unlock(&cm->lock);

#ifdef DAPL_COUNTERS
		if (g_dapl_dbg_type & DAPL_DBG_TYPE_CM_LIST) {
			dapl_os_unlock(&cm->hca->ib_trans.lock);
			dapls_print_cm_list(dapl_llist_peek_head(&cm->hca->ia_list_head));
			dapl_os_lock(&cm->hca->ib_trans.lock);
		}
#endif

		dapls_cr_callback(cm, IB_CME_LOCAL_FAILURE, NULL, 0, cm->sp);
		return -1;
	}

	dapl_os_get_time(&cm->timer); /* RTU expected */
	if (mcm_send(&cm->hca->ib_trans, &cm->msg, cm->p_data, cm->p_size)) {
		dapl_log(DAPL_DBG_TYPE_ERR," accept ERR: ucm reply send()\n");
		dapl_os_unlock(&cm->lock);
		return -1;
	}
	dapl_os_unlock(&cm->lock);
	return 0;
}


/*
 * PASSIVE: consumer accept, send local QP information, private data, 
 * queue on work thread to receive RTU information to avoid blocking
 * user thread. 
 */
DAT_RETURN
dapli_accept_usr(DAPL_EP *ep, DAPL_CR *cr, DAT_COUNT p_size, DAT_PVOID p_data)
{
	DAPL_IA *ia = ep->header.owner_ia;
	dp_ib_cm_handle_t cm = cr->ib_cm_handle;
	int ret;

	dapl_log(DAPL_DBG_TYPE_CM,
		 " MCM_ACCEPT_USR: ep %p cm %p QPt %p QPr %p p_data %p p_size %d\n",
		 ep, cm, ep->qp_handle->qp2, ep->qp_handle->qp, p_data, p_size);

	dapl_log(DAPL_DBG_TYPE_CM, " MCM_ACCEPT_USR: ep %p cm %p %s refs=%d"
		 " %x %x i_%x i2_%x %s <- %x %x i1_%x i2_%x l_pid %x r_pid %x %s\n",
		 ep, cm, dapl_cm_state_str(cm->state), cm->ref_count,
		 htons(cm->hca->ib_trans.addr.lid), htons(cm->msg.sport),
		 ep->qp_handle->qp ? ep->qp_handle->qp->qp_num:0,
		 ep->qp_handle->qp2 ? ep->qp_handle->qp2->qp_num:0,
		 mcm_map_str(cm->hca->ib_trans.addr.ep_map),
		 htons(cm->msg.daddr1.lid), htons(cm->msg.dport),
		 htonl(cm->msg.daddr1.qpn), htonl(cm->msg.daddr2.qpn),
		 ntohl(cm->msg.s_id), ntohl(cm->msg.d_id),
		 mcm_map_str(cm->msg.daddr1.ep_map));

	if (p_size > DAT_MCM_PDATA_SIZE)
		return DAT_LENGTH_ERROR;

	dapl_os_lock(&cm->lock);
	if (cm->state != MCM_ACCEPTING) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " CM_ACCEPT_USR: wrong state ep %p cm %p %s refs=%d"
			 " %x %x i_%x i2_ %x <- %x %x i_%x i2_%x l_pid %x r_pid %x\n",
			 cm->ep, cm, dapl_cm_state_str(cm->state), cm->ref_count,
			 htons(cm->hca->ib_trans.addr.lid), htons(cm->msg.sport),
			 ep->qp_handle->qp ? ep->qp_handle->qp->qp_num:0,
			 ep->qp_handle->qp2 ? ep->qp_handle->qp2->qp_num:0,
			 htons(cm->msg.daddr1.lid), htons(cm->msg.dport),
			 htonl(cm->msg.daddr1.qpn), htonl(cm->msg.daddr2.qpn),
			 ntohl(cm->msg.s_id), ntohl(cm->msg.d_id));
		dapl_os_unlock(&cm->lock);
		return DAT_INVALID_STATE;
	}
	dapl_os_unlock(&cm->lock);

	dapl_dbg_log(DAPL_DBG_TYPE_CM," ACCEPT_USR: rlid=%x iqp=%x type %d, psize=%d\n",
		     ntohs(cm->msg.daddr1.lid), ntohl(cm->msg.daddr1.qpn),
		     cm->msg.daddr1.qp_type, p_size);

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		     " ACCEPT_USR: remote GID subnet %s\n",
		     inet_ntop(AF_INET6, cm->msg.daddr1.gid,
			       gid_str, sizeof(gid_str)));

	/* rdma_out, initiator, cannot exceed remote rdma_in max */
	ep->param.ep_attr.max_rdma_read_out =
		DAPL_MIN(ep->param.ep_attr.max_rdma_read_out, cm->msg.rd_in);

	/* Set QP MTU, if negotiated. 2K for compatibility */
	ep->qp_handle->mtu = cm->msg.mtu ?
			     DAPL_MIN(cm->msg.mtu, cm->hca->ib_trans.ib_cm.mtu):
			     getenv("DAPL_IB_MTU") ? cm->hca->ib_trans.ib_cm.mtu : IBV_MTU_2048;

	/* modify QPr to RTR and then to RTS, QPr (qp) to remote QPt (daddr2), !xsocket */
	dapl_os_lock(&ep->header.lock);
	if (!MXF_EP(&cm->hca->ib_trans.addr)) {
		ret = dapls_modify_qp_rtu(ep->qp_handle->qp,
					  cm->msg.daddr2.qpn,
					  cm->msg.daddr2.lid,
					  (ib_gid_handle_t)cm->msg.daddr2.gid);
		if (ret) {
			dapl_log(DAPL_DBG_TYPE_ERR,
				 " ACCEPT_USR: QPS_RTR ERR %s -> lid %x qpn %x\n",
				 strerror(errno), ntohs(cm->msg.daddr2.lid),
				 ntohl(cm->msg.daddr2.qpn));
			dapl_os_unlock(&ep->header.lock);
			goto bail;
		}
	}
	/* modify QPt to RTR and then to RTS, QPt (qp2) to remote QPr (daddr1) */
	if (!cm->tp->scif_ep) { /* NON-MIC, qp2 is local and not on MPXYD */
		ret = dapls_modify_qp_rtu(ep->qp_handle->qp2,
					  cm->msg.daddr1.qpn,
					  cm->msg.daddr1.lid,
					  (ib_gid_handle_t)cm->msg.daddr1.gid);
		if (ret) {
			dapl_log(DAPL_DBG_TYPE_ERR,
				 " ACCEPT_USR: QPS_RTS ERR %s -> lid %x qpn %x\n",
				 strerror(errno), ntohs(cm->msg.daddr1.lid),
				 ntohl(cm->msg.daddr1.qpn));
			dapl_os_unlock(&ep->header.lock);
			goto bail;
		}
		cm->msg.saddr2.qpn = htonl(ep->qp_handle->qp2->qp_num);
		cm->msg.saddr2.lid = cm->hca->ib_trans.addr.lid;
		cm->msg.saddr2.qp_type = ep->qp_handle->qp->qp_type;
		cm->msg.saddr2.ep_map = cm->hca->ib_trans.addr.ep_map;
		dapl_os_memcpy(&cm->msg.saddr2.gid[0],
			       &cm->hca->ib_trans.addr.gid, 16);

		/* MXS peer: setup PI WC and save peer WR queue info */
		if (MXF_EP(&cm->msg.daddr1)) {
			/* save PI WR info, create local WC_q, send back WC info */
			mcm_ntoh_wrc(&ep->qp_handle->wrc_rem, (mcm_wrc_info_t*)cm->msg.p_proxy);
			if (ep->qp_handle->wrc_rem.wr_sz > MCM_WR_RX_NO_DATA)
				ep->qp_handle->p2p_data = DAT_MCM_P2P_INLINE;
			else
				ep->qp_handle->p2p_data = 0;

			dapl_log(DAPL_DBG_TYPE_CM, "ACCEPT_USR: qp %p set proxy max inline to %d\n",
					ep->qp_handle, ep->qp_handle->p2p_data);

			mcm_create_wc_q(ep->qp_handle, ep->qp_handle->wrc_rem.wr_end + 1);
			mcm_hton_wrc((mcm_wrc_info_t*)cm->msg.p_proxy, &ep->qp_handle->wrc);
			ep->qp_handle->ep_map = cm->msg.daddr1.ep_map;
			ep->qp_handle->seg_sz = (1 << cm->msg.seg_sz);

			/* post 0-byte rcv for inbound WC's via RW_imm */
			if (mcm_post_rcv_wc(ep->qp_handle, MCM_WRC_QLEN))
					goto bail;

			dapl_log(DAPL_DBG_TYPE_CM,
				 "ACCEPT_USR: WR_rem %p rkey %x sz %d, WC %p rkey %x sz %d sg %d\n",
				 ep->qp_handle->wrc_rem.wr_addr,
				 ep->qp_handle->wrc_rem.wr_rkey,
				 ep->qp_handle->wrc_rem.wr_end+1,
				 ep->qp_handle->wrc.wc_addr,
				 ep->qp_handle->wrc.wc_rkey,
				 ep->qp_handle->wrc.wc_end+1,
				 ep->qp_handle->seg_sz);
		}
	}
	dapl_os_unlock(&ep->header.lock);

	/* save remote address information, QPr */
	dapl_os_memcpy(&ep->remote_ia_address,
		       &cm->msg.daddr1, sizeof(dat_mcm_addr_t));

	/* setup local QPr info (if !KR) and type from EP, copy pdata, for reply */
	cm->msg.op = htons(MCM_REP);
	cm->msg.rd_in = ep->param.ep_attr.max_rdma_read_in;
	cm->msg.mtu = ep->qp_handle->mtu; /* send negotiated MTU */

	if (!MXF_EP(&cm->hca->ib_trans.addr)) {
		cm->msg.saddr1.qpn = htonl(ep->qp_handle->qp->qp_num);
		cm->msg.saddr1.qp_type = ep->qp_handle->qp->qp_type;
		cm->msg.saddr1.lid = cm->hca->ib_trans.addr.lid;
		cm->msg.saddr1.ep_map = cm->hca->ib_trans.addr.ep_map;
		dapl_os_memcpy(&cm->msg.saddr1.gid[0],
			       &cm->hca->ib_trans.addr.gid, 16);
	}

	/*
	 * UD: deliver p_data with REQ and EST event, keep REQ p_data in
	 * cm->msg.p_data and save REPLY accept data in cm->p_data for retries
	 */
	cm->p_size = p_size;
	dapl_os_memcpy(&cm->p_data, p_data, p_size);

	if (cm->tp->scif_ep) {
		dapl_ep_link_cm(ep, cm);
		cm->ep = ep;
		return (dapli_mix_cm_rep_out(cm, p_size, p_data));
	}

	/* save state and setup valid reference to EP, HCA. !PSP !RSP */
	if (!cm->sp->ep_handle && !cm->sp->psp_flags)
		dapl_ep_link_cm(ep, cm);
	cm->ep = ep;
	cm->hca = ia->hca_ptr;

	/* Send RTU and change state under CM lock */
	dapl_os_lock(&cm->lock);
	cm->state = MCM_RTU_PENDING;
	dapl_os_get_time(&cm->timer); /* RTU expected */
	if (mcm_send(&cm->hca->ib_trans, &cm->msg, cm->p_data, cm->p_size)) {
		dapl_log(DAPL_DBG_TYPE_ERR," accept ERR: ucm reply send()\n");
		dapl_os_unlock(&cm->lock);
		dapl_ep_unlink_cm(ep, cm);
		goto bail;
	}
	dapl_os_unlock(&cm->lock);

	DAPL_CNTR(ia, DCNT_IA_CM_REP_TX);
	dapl_dbg_log(DAPL_DBG_TYPE_CM, " PASSIVE: accepted!\n");
	dapls_thread_signal(&cm->hca->ib_trans.signal);
	return DAT_SUCCESS;
bail:
	dapls_ib_reject_connection(cm, ~IB_CM_REJ_REASON_CONSUMER_REJ, 0, 0);
	DAPL_CNTR(ia, DCNT_IA_CM_ERR);
	return DAT_INTERNAL_ERROR;
}


/*
 * dapls_ib_connect
 *
 * Initiate a connection with the passive listener on another node
 *
 * Input:
 *	ep_handle,
 *	remote_ia_address,
 *	remote_conn_qual,
 *	prd_size		size of private data and structure
 *	prd_prt			pointer to private data structure
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_connect(IN DAT_EP_HANDLE ep_handle,
		 IN DAT_IA_ADDRESS_PTR r_addr,
		 IN DAT_CONN_QUAL r_psp,
		 IN DAT_COUNT p_size, IN void *p_data)
{
	DAPL_EP *ep = (DAPL_EP *)ep_handle;
	DAPL_HCA *hca = ep->header.owner_ia->hca_ptr;
	struct dat_mcm_addr *mcm_ia = (struct dat_mcm_addr *)r_addr;
	dp_ib_cm_handle_t cm;
	
	dapl_log(DAPL_DBG_TYPE_CM, " MCM connect -> AF %d LID 0x%x QPN 0x%x GID %s"
		 " port %d ep_map %s sl %d qt %d\n",
		 mcm_ia->family, ntohs(mcm_ia->lid), ntohl(mcm_ia->qpn),
		 inet_ntop(AF_INET6, &mcm_ia->gid, gid_str, sizeof(gid_str)),
		 mcm_ia->port, mcm_map_str(mcm_ia->ep_map),
		 mcm_ia->sl, mcm_ia->qp_type);

	/* create CM object, initialize SRC info from EP */
	cm = dapls_cm_create(hca, ep);
	if (cm == NULL)
		return DAT_INSUFFICIENT_RESOURCES;

	/* remote hca and port: lid, gid, network order */
	dapl_os_memcpy(&cm->msg.daddr1, r_addr, sizeof(struct dat_mcm_addr));
	dapl_os_memcpy(&cm->msg.daddr2, r_addr, sizeof(struct dat_mcm_addr));

	/* HST dev scif0, remote LID is host proxy, not MIC */

	/* validate port and ep_map range */
	if ((mcm_ia->port > 2) || (mcm_ia->ep_map > 4))
		cm->msg.daddr1.ep_map = 0;

	/* remote uCM information, comes from consumer provider r_addr */
	cm->msg.dport = htons((uint16_t)r_psp);
	cm->msg.dqpn = cm->msg.daddr1.qpn;
	cm->msg.daddr1.qpn = 0; /* don't have a remote qpn until reply */
	
        /* set max rdma inbound requests */
        cm->msg.rd_in = ep->param.ep_attr.max_rdma_read_in;
        cm->msg.mtu = cm->tp->ib_cm.mtu; /* local MTU to peer */

	if (p_size) {
		cm->msg.p_size = htons(p_size);
		dapl_os_memcpy(&cm->msg.p_data, p_data, p_size);
	}
	cm->state = MCM_INIT;

	/* link EP and CM, put on work queue */
	dapli_queue_conn(cm);

	/* build connect request, send to remote CM based on r_addr info */
	return (dapli_cm_connect(ep, cm));
}

/*
 * dapls_ib_disconnect
 *
 * Disconnect an EP
 *
 * Input:
 *	ep_handle,
 *	disconnect_flags
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 */
DAT_RETURN
dapls_ib_disconnect(IN DAPL_EP *ep_ptr, IN DAT_CLOSE_FLAGS close_flags)
{
	dp_ib_cm_handle_t cm_ptr = dapl_get_cm_from_ep(ep_ptr);

	if (cm_ptr && cm_ptr->tp->scif_ep) { /* always force proxy flush */
		dapli_mix_cm_dreq_out(cm_ptr);
		if (ep_ptr->qp_handle->qp)
			dapls_modify_qp_state(ep_ptr->qp_handle->qp,
					      IBV_QPS_ERR,0,0,0);
	}

	dapl_os_lock(&ep_ptr->header.lock);
	if (ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED ||
	    ep_ptr->param.ep_attr.service_type != DAT_SERVICE_TYPE_RC ||
	    cm_ptr == NULL) {
		dapl_os_unlock(&ep_ptr->header.lock);
		return DAT_SUCCESS;
	} 
	dapl_os_unlock(&ep_ptr->header.lock);
	
	/* HST: QPt and QPr local */
	if (!cm_ptr->tp->scif_ep) {
		dapli_cm_disconnect(cm_ptr);
		dapls_modify_qp_state(ep_ptr->qp_handle->qp2, IBV_QPS_ERR,0,0,0);
	}

	return DAT_SUCCESS;
}

/*
 * dapls_ib_disconnect_clean
 *
 * Clean up outstanding connection data. This routine is invoked
 * after the final disconnect callback has occurred. Only on the
 * ACTIVE side of a connection. It is also called if dat_ep_connect
 * times out using the consumer supplied timeout value.
 *
 * Input:
 *	ep_ptr		DAPL_EP
 *	active		Indicates active side of connection
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	void
 *
 */
void
dapls_ib_disconnect_clean(IN DAPL_EP *ep,
			  IN DAT_BOOLEAN active,
			  IN const ib_cm_events_t ib_cm_event)
{
	if (ib_cm_event == IB_CME_TIMEOUT) {
		dp_ib_cm_handle_t cm_ptr;

		if ((cm_ptr = dapl_get_cm_from_ep(ep)) == NULL)
			return;

		dapl_log(DAPL_DBG_TYPE_WARN,
			"dapls_ib_disc_clean: CONN_TIMEOUT ep %p cm %p %s\n",
			ep, cm_ptr, dapl_cm_state_str(cm_ptr->state));
		
		/* schedule release of socket and local resources */
		dapli_cm_free(cm_ptr);
	}
}

/*
 * dapl_ib_setup_conn_listener
 *
 * Have the CM set up a connection listener.
 *
 * Input:
 *	ibm_hca_handle		HCA handle
 *	qp_handle			QP handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INTERNAL_ERROR
 *	DAT_CONN_QUAL_UNAVAILBLE
 *	DAT_CONN_QUAL_IN_USE
 *
 */
DAT_RETURN
dapls_ib_setup_conn_listener(IN DAPL_IA *ia, 
			     IN DAT_UINT64 sid, 
			     IN DAPL_SP *sp)
{
	dp_ib_cm_handle_t cm = NULL;
	int ret;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " listen(ia %p ServiceID %x sp %p)\n",
		     ia, sid, sp);

	/* cm_create will setup saddr1 for listen server */
	if ((cm = dapls_cm_create(ia->hca_ptr, NULL)) == NULL)
		return DAT_INSUFFICIENT_RESOURCES;

	/* LISTEN: init DST address and QP info to local CM server info */
	cm->sp = sp;
	cm->hca = ia->hca_ptr;

	/* save cm_handle reference in service point */
	sp->cm_srvc_handle = cm;

	/* proxy CM service: send listen over to MPXYD */
	if (ia->hca_ptr->ib_trans.scif_ep) {
		ret = dapli_mix_listen(cm, sid);
		if (ret) {
			dapl_dbg_log(DAPL_DBG_TYPE_WARN,
				     " listen: MIX_ERROR %d on conn_qual %x\n",
				     ret, sid);
			dapli_cm_free(cm);
			if (ret == MIX_EADDRINUSE)
				return DAT_CONN_QUAL_IN_USE;
			else
				return DAT_INSUFFICIENT_RESOURCES;
		}
	} else {
		/* local CM service, reserve local port and setup addr info */
		if (!mcm_get_port(&ia->hca_ptr->ib_trans, (uint16_t)sid)) {
			dapl_dbg_log(DAPL_DBG_TYPE_WARN,
				     " listen: ERROR %s on conn_qual %x\n",
				     strerror(errno), sid);
			dapli_cm_free(cm);
			return DAT_CONN_QUAL_IN_USE;
		}
		cm->msg.sport = htons((uint16_t)sid);
		cm->msg.sqpn = htonl(ia->hca_ptr->ib_trans.qp->qp_num);
		cm->msg.saddr1.qp_type = IBV_QPT_UD;
		cm->msg.saddr1.lid = ia->hca_ptr->ib_trans.addr.lid;
		dapl_os_memcpy(&cm->msg.saddr1.gid[0],
			       &cm->hca->ib_trans.addr.gid, 16);
	}
	
	/* queue up listen socket to process inbound CR's */
	cm->state = MCM_LISTEN;
	dapli_queue_listen(cm);

	DAPL_CNTR(ia, DCNT_IA_CM_LISTEN);

	return DAT_SUCCESS;
}


/*
 * dapl_ib_remove_conn_listener
 *
 * Have the CM remove a connection listener.
 *
 * Input:
 *	ia_handle		IA handle
 *	ServiceID		IB Channel Service ID
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_STATE
 *
 */
DAT_RETURN
dapls_ib_remove_conn_listener(IN DAPL_IA *ia, IN DAPL_SP *sp)
{
	dp_ib_cm_handle_t cm = sp->cm_srvc_handle;

	/* free cm_srvc_handle and port, and mark CM for cleanup */
	if (cm) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " remove_listener(ia %p sp %p cm %p psp=%x)\n",
		     ia, sp, cm, ntohs(cm->msg.sport));

		sp->cm_srvc_handle = NULL;
		dapli_dequeue_listen(cm);  

		/* clean up proxy listen, otherwise local port space */
		if (cm->hca->ib_trans.scif_ep)
			dapli_mix_listen_free(cm);
		else
			mcm_free_port(&cm->hca->ib_trans, ntohs(cm->msg.sport));

		dapls_cm_release(cm);  /* last ref, dealloc */
	}
	return DAT_SUCCESS;
}

/*
 * dapls_ib_accept_connection
 *
 * Perform necessary steps to accept a connection
 *
 * Input:
 *	cr_handle
 *	ep_handle
 *	private_data_size
 *	private_data
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INTERNAL_ERROR
 *
 */
DAT_RETURN
dapls_ib_accept_connection(IN DAT_CR_HANDLE cr_handle,
			   IN DAT_EP_HANDLE ep_handle,
			   IN DAT_COUNT p_size, 
			   IN const DAT_PVOID p_data)
{
	DAPL_CR *cr = (DAPL_CR *)cr_handle;
	DAPL_EP *ep = (DAPL_EP *)ep_handle;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " accept_connection(cr %p cm %p ep %p prd %p,%d)\n",
		     cr, cr->ib_cm_handle, ep, p_data, p_size);

	/* allocate and attach a QP if necessary */
	if (ep->qp_state == DAPL_QP_STATE_UNATTACHED) {
		DAT_RETURN status;
		status = dapls_ib_qp_alloc(ep->header.owner_ia,
					   ep, ep);
		if (status != DAT_SUCCESS)
			return status;
	}

	return (dapli_accept_usr(ep, cr, p_size, p_data));
}

/*
 * dapls_ib_reject_connection
 *
 * Reject a connection
 *
 * Input:
 *	cr_handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INTERNAL_ERROR
 *
 */
DAT_RETURN
dapls_ib_reject_connection(IN dp_ib_cm_handle_t cm,
			   IN int reason,
			   IN DAT_COUNT p_size, IN const DAT_PVOID p_data)
{
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " reject(cm %p reason %x, p_data %p, p_size %d)\n",
		     cm, reason, p_data, p_size);

        if (p_size > DAT_MCM_PDATA_SIZE)
                return DAT_LENGTH_ERROR;

	if (cm->tp->scif_ep)
		return (dapli_mix_cm_rej_out(cm, p_size, p_data, reason));

	/* cr_thread will destroy CR, update saddr1 lid, gid, qp_type info */
	dapl_os_lock(&cm->lock);
	dapl_log(DAPL_DBG_TYPE_CM, 
		 " PASSIVE: REJECTING CM_REQ:"
		 " cm %p op %s, st %s slid %x iqp %x port %x ->"
		 " dlid %x iqp %x port %x\n", cm,
		 dapl_cm_op_str(ntohs(cm->msg.op)), 
		 dapl_cm_state_str(cm->state), 
		 ntohs(cm->hca->ib_trans.addr.lid),
		 ntohl(cm->msg.saddr1.qpn),
		 ntohs(cm->msg.sport), ntohs(cm->msg.daddr1.lid),
		 ntohl(cm->msg.daddr1.qpn), ntohs(cm->msg.dport));

	cm->state = MCM_REJECTED;
	cm->msg.saddr1.lid = cm->hca->ib_trans.addr.lid;
	cm->msg.saddr1.qp_type = cm->msg.daddr1.qp_type;
	dapl_os_memcpy(&cm->msg.saddr1.gid[0],
		       &cm->hca->ib_trans.addr.gid, 16);
	
	if (reason == IB_CM_REJ_REASON_CONSUMER_REJ)
		cm->msg.op = htons(MCM_REJ_USER);
	else
		cm->msg.op = htons(MCM_REJ_CM);

	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm->hca->ia_list_head)),
		  reason == IB_CM_REJ_REASON_CONSUMER_REJ ?
		  DCNT_IA_CM_USER_REJ_TX : DCNT_IA_CM_ERR_REJ_TX);

	if (mcm_send(&cm->hca->ib_trans, &cm->msg, p_data, p_size)) {
		dapl_log(DAPL_DBG_TYPE_WARN,
			 " cm_reject: send ERR: %s\n", strerror(errno));
		dapl_os_unlock(&cm->lock);
		return DAT_INTERNAL_ERROR;
	}
	dapl_os_unlock(&cm->lock);
	dapli_cm_free(cm);
	return DAT_SUCCESS;
}

/*
 * dapls_ib_cm_remote_addr
 *
 * Obtain the remote IP address given a connection
 *
 * Input:
 *	cr_handle
 *
 * Output:
 *	remote_ia_address: where to place the remote address
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *
 */
DAT_RETURN
dapls_ib_cm_remote_addr(IN DAT_HANDLE dat_handle,
			OUT DAT_SOCK_ADDR6 * remote_ia_address)
{
	DAPL_HEADER *header;
	dp_ib_cm_handle_t cm;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     "dapls_ib_cm_remote_addr(dat_handle %p, ....)\n",
		     dat_handle);

	header = (DAPL_HEADER *) dat_handle;

	if (header->magic == DAPL_MAGIC_EP)
		cm = dapl_get_cm_from_ep((DAPL_EP *) dat_handle);
	else if (header->magic == DAPL_MAGIC_CR)
		cm = ((DAPL_CR *) dat_handle)->ib_cm_handle;
	else
		return DAT_INVALID_HANDLE;

	dapl_os_memcpy(remote_ia_address,
		       &cm->msg.daddr1,
		       sizeof(DAT_SOCK_ADDR6));

	return DAT_SUCCESS;
}

int dapls_ib_private_data_size(
	IN DAPL_HCA *hca_ptr)
{
	return DAT_MCM_PDATA_SIZE;
}

void cm_thread(void *arg)
{
	struct dapl_hca *hca = arg;
	dp_ib_cm_handle_t cm, next;
	ib_cq_handle_t m_cq;
	struct dapl_fd_set *set;
	char rbuf[2];
	int time_ms, ret;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, " cm_thread: ENTER hca %p\n", hca);
	set = dapl_alloc_fd_set();
	if (!set)
		goto out;

	dapl_os_lock(&hca->ib_trans.lock);
	hca->ib_trans.cm_state = IB_THREAD_RUN;

	while (1) {
		time_ms = -1; /* reset to blocking */
		dapl_fd_zero(set);
		dapl_fd_set(hca->ib_trans.signal.scm[0], set, DAPL_FD_READ);	
		dapl_fd_set(hca->ib_trans.scif_ev_ep, set, DAPL_FD_READ);
		if (!MFO_EP(&hca->ib_trans.addr) || !hca->ib_trans.self.node)
		{
			dapl_fd_set(hca->ib_hca_handle->async_fd, set, DAPL_FD_READ);
			dapl_fd_set(hca->ib_trans.rch_fd, set, DAPL_FD_READ);
			dapl_fd_set(hca->ib_trans.ib_cq->fd, set, DAPL_FD_READ);
		}

		dapl_os_lock(&hca->ib_trans.cqlock); /* CQt for HST->MXS */
		if (!dapl_llist_is_empty(&hca->ib_trans.cqlist))
			m_cq = dapl_llist_peek_head(&hca->ib_trans.cqlist);
		else
			m_cq = NULL;

		while (m_cq) {
			dapl_fd_set(m_cq->cq->channel->fd, set, DAPL_FD_READ);
			dapl_log(DAPL_DBG_TYPE_CM, " cm_thread: mcm_pio_event(%p)\n", m_cq);
			mcm_dto_event(m_cq);
			m_cq = dapl_llist_next_entry(
					&hca->ib_trans.cqlist,
					(DAPL_LLIST_ENTRY *)&m_cq->entry);
		}
		dapl_os_unlock(&hca->ib_trans.cqlock);

		if (!dapl_llist_is_empty(&hca->ib_trans.list))
			next = dapl_llist_peek_head(&hca->ib_trans.list);
		else
			next = NULL;

		while (next) {
			cm = next;
			next = dapl_llist_next_entry(
					&hca->ib_trans.list,
					(DAPL_LLIST_ENTRY *)&cm->local_entry);
			dapls_cm_acquire(cm); /* hold thread ref */
			dapl_os_lock(&cm->lock);
			if (cm->state == MCM_FREE ||
			    hca->ib_trans.cm_state != IB_THREAD_RUN) {
				dapl_os_unlock(&cm->lock);
				dapl_log(DAPL_DBG_TYPE_CM, 
					 " CM destroy: cm %p ep %p st=%s refs=%d\n",
					 cm, cm->ep, mcm_state_str(cm->state),
					 cm->ref_count);

				dapls_cm_release(cm); /* release alloc ref */
				dapli_cm_dequeue(cm); /* release workq ref */
				dapls_cm_release(cm); /* release thread ref */
				continue;
			}
			dapl_os_unlock(&cm->lock);
			mcm_check_timers(cm, &time_ms);
			dapls_cm_release(cm); /* release thread ref */
		}

		/* set to exit and all resources destroyed */
		if ((hca->ib_trans.cm_state != IB_THREAD_RUN) &&
		    (dapl_llist_is_empty(&hca->ib_trans.list)))
			break;

		dapl_os_unlock(&hca->ib_trans.lock);
		dapl_select(set, time_ms);

		if (!MFO_EP(&hca->ib_trans.addr) || !hca->ib_trans.self.node)
		{
			if (dapl_poll(hca->ib_trans.rch_fd,
				      DAPL_FD_READ) == DAPL_FD_READ) {
				mcm_recv(&hca->ib_trans);
			}
		}
		ret = dapl_poll(hca->ib_trans.scif_ev_ep, DAPL_FD_READ);
		if (ret == DAPL_FD_READ)
			dapli_mix_recv(hca, hca->ib_trans.scif_ev_ep);
		else if (ret == DAPL_FD_ERROR) {
			struct	ibv_async_event event;

			dapl_log(1, " cm_thread: dev_id %d scif_ev_ep %d ERR\n",
				 hca->ib_trans.dev_id, hca->ib_trans.scif_ev_ep);

			event.event_type = IBV_EVENT_DEVICE_FATAL;
			if (!MFO_EP(&hca->ib_trans.addr) || !hca->ib_trans.self.node)
			{
				dapl_evd_un_async_error_callback(hca->ib_hca_handle,
								 &event,
								 hca->ib_trans.async_un_ctx);
			}
			dapl_os_lock(&hca->ib_trans.lock);
			hca->ib_trans.cm_state = IB_THREAD_CANCEL;
			continue;
		}
		if (!MFO_EP(&hca->ib_trans.addr) || !hca->ib_trans.self.node)
		{
			if (dapl_poll(hca->ib_hca_handle->async_fd,
				      DAPL_FD_READ) == DAPL_FD_READ) {
				dapli_async_event_cb(&hca->ib_trans);
			}
			if (dapl_poll(hca->ib_trans.ib_cq->fd,
				      DAPL_FD_READ) == DAPL_FD_READ) {
				dapli_cq_event_cb(&hca->ib_trans);
			}
		}
		while (dapl_poll(hca->ib_trans.signal.scm[0], 
				 DAPL_FD_READ) == DAPL_FD_READ) {
			recv(hca->ib_trans.signal.scm[0], rbuf, 2, 0);
		}
		dapl_os_lock(&hca->ib_trans.lock);
		
		/* set to exit and all resources destroyed */
		if ((hca->ib_trans.cm_state != IB_THREAD_RUN) &&
		    (dapl_llist_is_empty(&hca->ib_trans.list)))
			break;
	}

	dapl_os_unlock(&hca->ib_trans.lock);
	free(set);
out:
	hca->ib_trans.cm_state = IB_THREAD_EXIT;
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, " cm_thread(hca %p) exit\n", hca);
}

static void mcm_log_addrs(int lvl, struct dat_mcm_msg *msg, int state, int in)
{
	if (in) {
		if (MXF_EP(&msg->daddr1) && MXF_EP(&msg->saddr1)) {
			dapl_log(lvl, " QPr_t addr2: %s 0x%x %x 0x%x %s <- QPt_r addr2: 0x%x %x 0x%x %s\n",
				mcm_state_str(state), htons(msg->daddr2.lid),
				htonl(msg->daddr2.qpn), htons(msg->dport),
				mcm_map_str(msg->daddr2.ep_map),
				htons(msg->saddr2.lid), htonl(msg->saddr2.qpn),
				htons(msg->sport), mcm_map_str(msg->saddr2.ep_map));
		} else {
			dapl_log(lvl, " QPr addr1: %s 0x%x %x 0x%x %s <- QPt addr2: 0x%x %x 0x%x %s\n",
				mcm_state_str(state), htons(msg->daddr1.lid),
				htonl(msg->daddr1.qpn), htons(msg->dport),
				mcm_map_str(msg->daddr1.ep_map),
				htons(msg->saddr2.lid), htonl(msg->saddr2.qpn),
				htons(msg->sport), mcm_map_str(msg->saddr2.ep_map));
			dapl_log(lvl, " QPt addr2: %s 0x%x %x 0x%x %s <- QPr addr1: 0x%x %x 0x%x %s\n",
				mcm_state_str(state),htons(msg->daddr2.lid),
				htonl(msg->daddr2.qpn), htons(msg->dport),
				mcm_map_str(msg->daddr2.ep_map),
				htons(msg->saddr1.lid), htonl(msg->saddr1.qpn),
				htons(msg->sport), mcm_map_str(msg->saddr1.ep_map));
		}
	} else {
		if (MXF_EP(&msg->saddr1) && MXF_EP(&msg->daddr1)) {
			dapl_log(lvl, " QPr_t addr2: %s 0x%x %x 0x%x %s -> QPt_r addr2: 0x%x %x 0x%x %s\n",
				mcm_state_str(state), htons(msg->saddr2.lid),
				htonl(msg->saddr2.qpn), htons(msg->sport),
				mcm_map_str(msg->saddr2.ep_map),
				htons(msg->daddr2.lid), htonl(msg->daddr2.qpn),
				htons(msg->dport), mcm_map_str(msg->daddr2.ep_map));
		} else {
			dapl_log(lvl, " QPr addr1: %s 0x%x %x 0x%x %s -> QPt addr2: 0x%x %x 0x%x %s\n",
				mcm_state_str(state), htons(msg->saddr1.lid),
				htonl(msg->saddr1.qpn), htons(msg->sport),
				mcm_map_str(msg->saddr1.ep_map),
				htons(msg->daddr2.lid), htonl(msg->daddr2.qpn),
				htons(msg->dport), mcm_map_str(msg->daddr2.ep_map));
			dapl_log(lvl, " QPt addr2: %s 0x%x %x 0x%x %s -> QPr addr1: 0x%x %x 0x%x %s\n",
				mcm_state_str(state), htons(msg->saddr2.lid),
				htonl(msg->saddr2.qpn), htons(msg->sport),
				mcm_map_str(msg->saddr2.ep_map),
				htons(msg->daddr1.lid), htonl(msg->daddr1.qpn),
				htons(msg->dport), mcm_map_str(msg->daddr1.ep_map));
		}
	}
}

#ifdef DAPL_COUNTERS
static char _ctr_host_[128];
/* Debug aid: List all Connections in process and state */
void dapls_print_cm_list(IN DAPL_IA *ia_ptr)
{
	/* Print in process CM's for this IA, if debug type set */
	int i = 0;
	dp_ib_cm_handle_t cm, next_cm;
	struct dapl_llist_entry	**list;
	DAPL_OS_LOCK *lock;

	/* LISTEN LIST */
	list = &ia_ptr->hca_ptr->ib_trans.llist;
	lock = &ia_ptr->hca_ptr->ib_trans.llock;

	dapl_os_lock(lock);
	if (!dapl_llist_is_empty((DAPL_LLIST_HEAD*)list))
		next_cm = dapl_llist_peek_head((DAPL_LLIST_HEAD*)list);
 	else
		next_cm = NULL;

	gethostname(_ctr_host_, sizeof(_ctr_host_));
	printf("\n [%s:%x] DAPL IA LISTEN/CONNECTIONS IN PROCESS:\n",
		_ctr_host_ , dapl_os_getpid());

	while (next_cm) {
		cm = next_cm;
		next_cm = dapl_llist_next_entry((DAPL_LLIST_HEAD*)list,
						(DAPL_LLIST_ENTRY*)&cm->local_entry);

		printf( "  LISTEN[%d]: sp %p %s uCM_QP: %x %x c_%x l_pid %x \n",
			i, cm->sp, dapl_cm_state_str(cm->state),
			ntohs(cm->msg.saddr1.lid), ntohs(cm->msg.sport),
			ntohl(cm->msg.sqpn),
			ntohl(cm->msg.s_id));
		i++;
	}
	dapl_os_unlock(lock);

	/* CONNECTION LIST */
	list = &ia_ptr->hca_ptr->ib_trans.list;
	lock = &ia_ptr->hca_ptr->ib_trans.lock;

	dapl_os_lock(lock);
	if (!dapl_llist_is_empty((DAPL_LLIST_HEAD*)list))
		next_cm = dapl_llist_peek_head((DAPL_LLIST_HEAD*)list);
 	else
		next_cm = NULL;

        while (next_cm) {
		cm = next_cm;
		next_cm = dapl_llist_next_entry((DAPL_LLIST_HEAD*)list,
						(DAPL_LLIST_ENTRY*)&cm->local_entry);

		printf( "  CONN[%d]: ep %p cm %p %s %s"
			"  %x %x c_%x i_%x %s %x %x c_%x i_%x r_pid %x\n",
			i, cm->ep, cm,
			cm->msg.saddr1.qp_type == IBV_QPT_RC ? "RC" : "UD",
			dapl_cm_state_str(cm->state),
			ntohs(cm->msg.saddr1.lid),
			ntohs(cm->msg.sport),
			ntohl(cm->msg.sqpn),
			ntohl(cm->msg.saddr1.qpn),
			cm->sp ? "<-" : "->",
			ntohs(cm->msg.daddr1.lid),
			ntohs(cm->msg.dport),
			ntohl(cm->msg.dqpn),
			ntohl(cm->msg.daddr1.qpn),
			ntohl(cm->msg.d_id));
		i++;
	}
	printf("\n");
	dapl_os_unlock(lock);
}

void dapls_print_cm_free_list(IN DAPL_IA *ia_ptr)
{
	DAPL_EP	*ep, *next_ep;
	dp_ib_cm_handle_t cm, next_cm;
	int i = 0;

	gethostname(_ctr_host_, sizeof(_ctr_host_));
	printf("\n [%s:%x] DAPL EP CM FREE LIST:\n",
		_ctr_host_ , dapl_os_getpid());

	dapl_os_lock(&ia_ptr->header.lock);
	ep = (dapl_llist_is_empty(&ia_ptr->ep_list_head) ?
		NULL : dapl_llist_peek_head(&ia_ptr->ep_list_head));
	while (ep != NULL) {
		next_ep = dapl_llist_next_entry(&ia_ptr->ep_list_head,
					        &ep->header.ia_list_entry);
		dapl_os_lock(&ep->header.lock);
		cm = (dapl_llist_is_empty(&ep->cm_list_head) ?
			NULL : dapl_llist_peek_head(&ep->cm_list_head));
	 	while (cm) {
	 		dapl_os_lock(&cm->lock);
			next_cm = dapl_llist_next_entry(&ep->cm_list_head,
							&cm->list_entry);
			if (cm->state == DCM_FREE) {
				printf( "  CONN[%d]: ep %p cm %p %s %s"
					" %x %x c_%x i_%x l_pid %x %s"
					" %x %x c_%x i_%x r_pid %x\n",
					i, cm->ep, cm,
					cm->msg.saddr1.qp_type == IBV_QPT_RC ? "RC" : "UD",
					dapl_cm_state_str(cm->state),
					ntohs(cm->msg.saddr1.lid),
					ntohs(cm->msg.sport),
					ntohl(cm->msg.sqpn),
					ntohl(cm->msg.saddr1.qpn),
					ntohl(cm->msg.s_id),
					cm->sp ? "<-" : "->",
					ntohs(cm->msg.daddr1.lid),
					ntohs(cm->msg.dport),
					ntohl(cm->msg.dqpn),
					ntohl(cm->msg.daddr1.qpn),
					ntohl(cm->msg.d_id));
				i++;
			}
			dapl_os_unlock(&cm->lock);
			cm = next_cm;
		}
	 	dapl_os_unlock(&ep->header.lock);
		ep = next_ep;
	}
	dapl_os_unlock(&ia_ptr->header.lock);
}
#endif

