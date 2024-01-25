/*
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

/***************************************************************************
 *
 *   Module:		 uDAPL
 *
 *   Filename:		 dapl_ib_cm.c
 *
 *   Author:		 Arlin Davis
 *
 *   Created:		 3/10/2005
 *
 *   Description: 
 *
 *   The uDAPL openib provider - connection management
 *
 ****************************************************************************
 *		   Source Control System Information
 *
 *    $Id: $
 *
 *	Copyright (c) 2005-2015 Intel Corporation.  All rights reserved.
 *
 **************************************************************************/

#if defined(_WIN32)
#define FD_SETSIZE 1024
#define DAPL_FD_SETSIZE FD_SETSIZE
#endif

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_cr_util.h"
#include "dapl_name_service.h"
#include "dapl_ib_util.h"
#include "dapl_ep_util.h"
#include "dapl_sp_util.h"
#include "dapl_osd.h"

extern char *gid_str;

#define SCM_BC_DIFF 2 /* cm_msg adjust, pre v8 */

/* forward declarations */
static DAT_RETURN
dapli_socket_connect(DAPL_EP * ep_ptr,
		     DAT_IA_ADDRESS_PTR r_addr,
		     DAT_CONN_QUAL r_qual, DAT_COUNT p_size, DAT_PVOID p_data, int retries);

#ifdef DAPL_DBG
/* Check for EP linking to IA and proper connect state */
void dapli_ep_check(DAPL_EP *ep)
{
	DAPL_IA *ia_ptr = ep->header.owner_ia;
	DAPL_EP	*ep_ptr, *next_ep_ptr;
	int found = 0;

	dapl_os_lock(&ia_ptr->header.lock);
	ep_ptr = (dapl_llist_is_empty (&ia_ptr->ep_list_head)
		? NULL : dapl_llist_peek_head (&ia_ptr->ep_list_head));

	while (ep_ptr != NULL) {
		next_ep_ptr = 
			dapl_llist_next_entry(&ia_ptr->ep_list_head,
					      &ep_ptr->header.ia_list_entry);
		if (ep == ep_ptr) {
			found++;
			if ((ep->cr_ptr && ep->param.ep_state 
				!= DAT_EP_STATE_COMPLETION_PENDING) ||
			    (!ep->cr_ptr && ep->param.ep_state 
				!= DAT_EP_STATE_ACTIVE_CONNECTION_PENDING))
				goto err;
			else 
				goto match;
		}
		ep_ptr = next_ep_ptr;
	}
err:
	dapl_log(DAPL_DBG_TYPE_ERR,
		 " dapli_ep_check ERR: %s %s ep=%p state=%d magic=0x%x\n", 
		 ep->cr_ptr ? "PASSIVE":"ACTIVE", 
		 found ? "WRONG_STATE":"NOT_FOUND" ,
		 ep, ep->param.ep_state, ep->header.magic);
match:
	dapl_os_unlock(&ia_ptr->header.lock);
	return;
}
#else
#define dapli_ep_check(ep)
#endif

#if defined(_WIN32) || defined(_WIN64)
enum DAPL_FD_EVENTS {
	DAPL_FD_READ = 0x1,
	DAPL_FD_WRITE = 0x2,
	DAPL_FD_ERROR = 0x4
};

static int dapl_config_socket(DAPL_SOCKET s)
{
	unsigned long nonblocking = 1;
	int ret, opt = 1;

	ret = ioctlsocket(s, FIONBIO, &nonblocking);

	/* no delay for small packets */
	if (!ret)
		ret = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, 
				 (char *)&opt, sizeof(opt));
	return ret;
}

static int dapl_connect_socket(DAPL_SOCKET s, struct sockaddr *addr,
			       int addrlen)
{
	int err;

	err = connect(s, addr, addrlen);
	if (err == SOCKET_ERROR)
		err = WSAGetLastError();
	return (err == WSAEWOULDBLOCK) ? EAGAIN : err;
}

struct dapl_fd_set {
	struct fd_set set[3];
};

static struct dapl_fd_set *dapl_alloc_fd_set(void)
{
	return dapl_os_alloc(sizeof(struct dapl_fd_set));
}

static void dapl_fd_zero(struct dapl_fd_set *set)
{
	FD_ZERO(&set->set[0]);
	FD_ZERO(&set->set[1]);
	FD_ZERO(&set->set[2]);
}

static int dapl_fd_set(DAPL_SOCKET s, struct dapl_fd_set *set,
		       enum DAPL_FD_EVENTS event)
{
	FD_SET(s, &set->set[(event == DAPL_FD_READ) ? 0 : 1]);
	FD_SET(s, &set->set[2]);
	return 0;
}

static enum DAPL_FD_EVENTS dapl_poll(DAPL_SOCKET s, enum DAPL_FD_EVENTS event)
{
	struct fd_set rw_fds;
	struct fd_set err_fds;
	struct timeval tv;
	int ret;

	FD_ZERO(&rw_fds);
	FD_ZERO(&err_fds);
	FD_SET(s, &rw_fds);
	FD_SET(s, &err_fds);

	tv.tv_sec = 0;
	tv.tv_usec = 0;

	if (event == DAPL_FD_READ)
		ret = select(1, &rw_fds, NULL, &err_fds, &tv);
	else
		ret = select(1, NULL, &rw_fds, &err_fds, &tv);

	if (ret == 0)
		return 0;
	else if (ret == SOCKET_ERROR)
		return DAPL_FD_ERROR;
	else if (FD_ISSET(s, &rw_fds))
		return event;
	else
		return DAPL_FD_ERROR;
}

static int dapl_select(struct dapl_fd_set *set)
{
	int ret;

	dapl_dbg_log(DAPL_DBG_TYPE_CM, " dapl_select: sleep\n");
	ret = select(0, &set->set[0], &set->set[1], &set->set[2], NULL);
	dapl_dbg_log(DAPL_DBG_TYPE_CM, " dapl_select: wakeup\n");

	if (ret == SOCKET_ERROR)
		dapl_dbg_log(DAPL_DBG_TYPE_THREAD,
			     " dapl_select: error 0x%x\n", WSAGetLastError());

	return ret;
}

static int dapl_socket_errno(void)
{
	int err;

	err = WSAGetLastError();
	switch (err) {
	case WSAEACCES:
	case WSAEADDRINUSE:
		return EADDRINUSE;
	case WSAECONNRESET:
		return ECONNRESET;
	default:
		return err;
	}
}
#else				// _WIN32 || _WIN64
enum DAPL_FD_EVENTS {
	DAPL_FD_READ = POLLIN,
	DAPL_FD_WRITE = POLLOUT,
	DAPL_FD_ERROR = POLLERR
};

static int dapl_config_socket(DAPL_SOCKET s)
{
	int ret, opt = 1;

	/* non-blocking */
	ret = fcntl(s, F_GETFL);
	if (ret >= 0)
		ret = fcntl(s, F_SETFL, ret | O_NONBLOCK);

	/* no delay for small packets */
	if (!ret)
		ret = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, 
				 (char *)&opt, sizeof(opt));
	return ret;
}

static int dapl_connect_socket(DAPL_SOCKET s, struct sockaddr *addr,
			       int addrlen)
{
	int ret;

	ret = connect(s, addr, addrlen);

	return (errno == EINPROGRESS) ? EAGAIN : ret;
}

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
	if (set->index == DAPL_FD_SETSIZE - 1) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 "SCM ERR: cm_thread exceeded FD_SETSIZE %d\n",
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

	fds.fd = s;
	fds.events = event;
	fds.revents = 0;
	ret = poll(&fds, 1, 0);
	dapl_log(DAPL_DBG_TYPE_THREAD, " dapl_poll: fd=%d ret=%d, evnts=0x%x\n",
		 s, ret, fds.revents);
	if (ret == 0)
		return 0;
	else if (ret < 0 || (fds.revents & (POLLERR | POLLHUP | POLLNVAL))) 
		return DAPL_FD_ERROR;
	else 
		return event;
}

static int dapl_select(struct dapl_fd_set *set)
{
	int ret;

	dapl_dbg_log(DAPL_DBG_TYPE_THREAD, " dapl_select: sleep, fds=%d\n", set->index);
	ret = poll(set->set, set->index, -1);
	dapl_dbg_log(DAPL_DBG_TYPE_THREAD, " dapl_select: wakeup, ret=0x%x\n", ret);
	return ret;
}

#define dapl_socket_errno() errno
#endif

static void dapli_cm_thread_signal(dp_ib_cm_handle_t cm_ptr) 
{
	if (cm_ptr->hca)
		send(cm_ptr->hca->ib_trans.scm[1], "w", sizeof "w", 0);
}

static void dapli_cm_free(dp_ib_cm_handle_t cm_ptr) 
{
	dapl_os_lock(&cm_ptr->lock);
	cm_ptr->state = DCM_FREE;
	dapl_os_unlock(&cm_ptr->lock);
	dapli_cm_thread_signal(cm_ptr);
}

static void dapli_cm_dealloc(dp_ib_cm_handle_t cm_ptr) 
{
	dapl_os_assert(!cm_ptr->ref_count);
	
	if (cm_ptr->socket != DAPL_INVALID_SOCKET) {
		shutdown(cm_ptr->socket, SHUT_RDWR);
		closesocket(cm_ptr->socket);
	}
	if (cm_ptr->ah) 
		ibv_destroy_ah(cm_ptr->ah);
	
	dapl_os_lock_destroy(&cm_ptr->lock);
	dapl_os_wait_object_destroy(&cm_ptr->event);
	dapl_os_free(cm_ptr, sizeof(*cm_ptr));
}

void dapls_cm_acquire(dp_ib_cm_handle_t cm_ptr)
{
	dapl_os_lock(&cm_ptr->lock);
	cm_ptr->ref_count++;
	dapl_os_unlock(&cm_ptr->lock);
}

void dapls_cm_release(dp_ib_cm_handle_t cm_ptr)
{
	dapl_os_lock(&cm_ptr->lock);
	cm_ptr->ref_count--;
	if (cm_ptr->ref_count) {
                if (cm_ptr->ref_count == 1)
                        dapl_os_wait_object_wakeup(&cm_ptr->event);
                dapl_os_unlock(&cm_ptr->lock);
		return;
	}
	dapl_os_unlock(&cm_ptr->lock);
	dapli_cm_dealloc(cm_ptr);
}

static dp_ib_cm_handle_t dapli_cm_alloc(DAPL_EP *ep_ptr)
{
	dp_ib_cm_handle_t cm_ptr;

	/* Allocate CM, init lock, and initialize */
	if ((cm_ptr = dapl_os_alloc(sizeof(*cm_ptr))) == NULL)
		return NULL;

	(void)dapl_os_memzero(cm_ptr, sizeof(*cm_ptr));
	if (dapl_os_lock_init(&cm_ptr->lock))
		goto bail;

	if (dapl_os_wait_object_init(&cm_ptr->event)) {
		dapl_os_lock_destroy(&cm_ptr->lock);
		goto bail;
	}
	dapl_llist_init_entry((DAPL_LLIST_ENTRY *)&cm_ptr->list_entry);
	dapl_llist_init_entry((DAPL_LLIST_ENTRY *)&cm_ptr->local_entry);

	cm_ptr->msg.ver = htons(DCM_VER);
	cm_ptr->socket = DAPL_INVALID_SOCKET;
	cm_ptr->retry = SCM_CR_RETRY;
	dapls_cm_acquire(cm_ptr);
		
	/* Link EP and CM */
	if (ep_ptr != NULL) {
		dapl_ep_link_cm(ep_ptr, cm_ptr); /* ref++ */
		cm_ptr->ep = ep_ptr;
		cm_ptr->hca = ((DAPL_IA *)ep_ptr->param.ia_handle)->hca_ptr;
	}
	return cm_ptr;
bail:
	dapl_os_free(cm_ptr, sizeof(*cm_ptr));
	return NULL;
}

/* queue socket for processing CM work */
static void dapli_cm_queue(dp_ib_cm_handle_t cm_ptr)
{
	/* add to work queue for cr thread processing */
	dapl_os_lock(&cm_ptr->hca->ib_trans.lock);
	dapls_cm_acquire(cm_ptr);
	dapl_llist_add_tail(&cm_ptr->hca->ib_trans.list,
			    (DAPL_LLIST_ENTRY *)&cm_ptr->local_entry, cm_ptr);
	dapl_os_unlock(&cm_ptr->hca->ib_trans.lock);
	dapli_cm_thread_signal(cm_ptr);
}

/* called with local LIST lock */
static void dapli_cm_dequeue(dp_ib_cm_handle_t cm_ptr)
{
	/* Remove from work queue, cr thread processing */
	dapl_llist_remove_entry(&cm_ptr->hca->ib_trans.list,
				(DAPL_LLIST_ENTRY *)&cm_ptr->local_entry);
	dapls_cm_release(cm_ptr);
}

/* BLOCKING: called from dapl_ep_free, EP link will be last ref, cleanup UD CR */
void dapls_cm_free(dp_ib_cm_handle_t cm_ptr)
{
	DAPL_SP *sp_ptr = cm_ptr->sp;

	dapl_log(DAPL_DBG_TYPE_CM,
		 " cm_free: cm %p %s ep %p sp %p refs=%d\n",
		 cm_ptr, dapl_cm_state_str(cm_ptr->state),
		 cm_ptr->ep, sp_ptr, cm_ptr->ref_count);

	dapl_os_lock(&cm_ptr->lock);
	if (sp_ptr && cm_ptr->state == DCM_CONNECTED &&
	    cm_ptr->msg.daddr.ib.qp_type == IBV_QPT_UD) {
		DAPL_CR *cr_ptr;

		dapl_os_lock(&sp_ptr->header.lock);
		cr_ptr = dapl_sp_search_cr(sp_ptr, cm_ptr);
		if (cr_ptr != NULL) {
			dapl_sp_remove_cr(sp_ptr, cr_ptr);
			dapls_cr_free(cr_ptr);
		}
		dapl_os_unlock(&sp_ptr->header.lock);
	}
	
	/* free from internal workq, wait until EP is last ref */
	cm_ptr->state = DCM_FREE;

	if (cm_ptr->ref_count != 1) {
		dapli_cm_thread_signal(cm_ptr);
		dapl_os_unlock(&cm_ptr->lock);
		dapl_os_wait_object_wait(&cm_ptr->event, DAT_TIMEOUT_INFINITE);
		dapl_os_lock(&cm_ptr->lock);
	}
	dapl_os_unlock(&cm_ptr->lock);

	/* unlink, dequeue from EP. Final ref so release will destroy */
	dapl_ep_unlink_cm(cm_ptr->ep, cm_ptr);
}

DAT_RETURN dapls_ud_cm_free(DAPL_EP *ep_ptr, dp_ib_cm_handle_t cm_ptr)
{
	return DAT_NOT_IMPLEMENTED;
}

/*
 * ACTIVE/PASSIVE: called from CR thread or consumer via ep_disconnect
 *                 or from ep_free. 
 */
DAT_RETURN dapli_socket_disconnect(dp_ib_cm_handle_t cm_ptr)
{
	DAT_UINT32 disc_data = htonl(0xdead);

	dapl_os_lock(&cm_ptr->lock);
	if (cm_ptr->state != DCM_CONNECTED || 
	    cm_ptr->state == DCM_DISCONNECTED) {
		dapl_os_unlock(&cm_ptr->lock);
		return DAT_SUCCESS;
	}
	cm_ptr->state = DCM_DISCONNECTED;
	send(cm_ptr->socket, (char *)&disc_data, sizeof(disc_data), 0);
	dapl_os_unlock(&cm_ptr->lock);

	/* disconnect events for RC's only */
	if (cm_ptr->ep->param.ep_attr.service_type == DAT_SERVICE_TYPE_RC) {
		dapl_os_lock(&cm_ptr->ep->header.lock);
		dapls_modify_qp_state(cm_ptr->ep->qp_handle->qp, IBV_QPS_ERR, 0,0,0);
		dapl_os_unlock(&cm_ptr->ep->header.lock);
		if (cm_ptr->ep->cr_ptr) {
			dapls_cr_callback(cm_ptr,
					  IB_CME_DISCONNECTED,
					  NULL, 0, cm_ptr->sp);
		} else {
			dapl_evd_connection_callback(cm_ptr,
						     IB_CME_DISCONNECTED,
						     NULL, 0, cm_ptr->ep);
		}
	}
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_DREQ_TX);
	
	/* release from workq */
	dapli_cm_free(cm_ptr);

	/* scheduled destroy via disconnect clean in callback */
	return DAT_SUCCESS;
}

/*
 * ACTIVE: socket connected, send QP information to peer 
 */
static void dapli_socket_connected(dp_ib_cm_handle_t cm_ptr, int err)
{
	int len, exp;
	struct iovec iov[2];
	struct dapl_ep *ep_ptr = cm_ptr->ep;

	if (err) {
		dapl_log(DAPL_DBG_TYPE_CM_WARN,
			 " CONN_PENDING: %s ERR %s -> %s PORT L-%x R-%x %s cnt=%d\n",
			 err == -1 ? "POLL" : "SOCKOPT",
			 err == -1 ? strerror(dapl_socket_errno()) : strerror(err), 
			 inet_ntoa(((struct sockaddr_in *)&cm_ptr->addr)->sin_addr),
			 ntohs(((struct sockaddr_in *)&cm_ptr->msg.daddr.so)->sin_port),
			 ntohs(((struct sockaddr_in *)&cm_ptr->addr)->sin_port),
			 (err == ETIMEDOUT || err == ECONNREFUSED) ? 
			 "RETRYING...":"ABORTING", cm_ptr->retry);

		/* retry a timeout */
		if (((err == ETIMEDOUT) || (err == ECONNREFUSED)) && --cm_ptr->retry) {
			closesocket(cm_ptr->socket);
			cm_ptr->socket = DAPL_INVALID_SOCKET;
			dapli_socket_connect(cm_ptr->ep, (DAT_IA_ADDRESS_PTR)&cm_ptr->addr, 
					     ntohs(((struct sockaddr_in *)&cm_ptr->addr)->sin_port) - 1000,
					     ntohs(cm_ptr->msg.p_size), &cm_ptr->msg.p_data, cm_ptr->retry);
			dapl_ep_unlink_cm(cm_ptr->ep, cm_ptr);
			dapli_cm_free(cm_ptr);
			return;
		}
		DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_ERR_TIMEOUT);
		goto bail;
	}

	dapl_os_lock(&cm_ptr->lock);
	cm_ptr->state = DCM_REP_PENDING;
	dapl_os_unlock(&cm_ptr->lock);

	/* set max rdma inbound requests */
	cm_ptr->msg.rd_in = ep_ptr->param.ep_attr.max_rdma_read_in;

	/* send qp info and pdata to remote peer */
	exp = sizeof(ib_cm_msg_t) - DCM_MAX_PDATA_SIZE;
	if (cm_ptr->retry == SCM_CR_RETRY-1) {
		exp += SCM_BC_DIFF; /* retry with pre-v8 req */
		dapl_log(DAPL_DBG_TYPE_CM_WARN,
			 " CONN_REQ: retry pre-v8 protocol; peer != v8\n");
	}
	iov[0].iov_base = (void *)&cm_ptr->msg;
	iov[0].iov_len = exp;
	if (cm_ptr->msg.p_size) {
		iov[1].iov_base = cm_ptr->msg.p_data;
		iov[1].iov_len = ntohs(cm_ptr->msg.p_size);
		len = writev(cm_ptr->socket, iov, 2);
	} else {
		len = writev(cm_ptr->socket, iov, 1);
	}

	if (len != (exp + ntohs(cm_ptr->msg.p_size))) {
		int err = dapl_socket_errno();
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " CONN_PENDING len ERR 0x%x %s, wcnt=%d(%d) -> %s\n",
			 err, strerror(err), len, 
			 exp + ntohs(cm_ptr->msg.p_size), 
			 inet_ntoa(((struct sockaddr_in *)
				   ep_ptr->param.
				   remote_ia_address_ptr)->sin_addr));
		goto bail;
	}

	dapl_log(DAPL_DBG_TYPE_CM,
		 " CONN_REQ: (%d) SRC lid=0x%x,"
		 " qpn=0x%x, psize=%d GID %s rd_in %d rtns %d mtu %d rsv %d\n",
		 exp, ntohs(cm_ptr->msg.saddr.ib.lid),
		 ntohl(cm_ptr->msg.saddr.ib.qpn),
		 ntohs(cm_ptr->msg.p_size),
		 inet_ntop(AF_INET6, &cm_ptr->hca->ib_trans.gid,
		           gid_str, sizeof(gid_str)),
		 cm_ptr->msg.rd_in, cm_ptr->msg.rtns,
		 cm_ptr->msg.mtu, cm_ptr->msg.resv[0]);

	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_REQ_TX);
	return;

bail:
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_ERR);

	/* mark CM object for cleanup */
	dapli_cm_free(cm_ptr);
	dapl_evd_connection_callback(NULL, IB_CME_DESTINATION_REJECT, NULL, 0, ep_ptr);
}

/*
 * ACTIVE: Create socket, connect, defer exchange QP information to CR thread
 * to avoid blocking. 
 */
static DAT_RETURN
dapli_socket_connect(DAPL_EP * ep_ptr,
		     DAT_IA_ADDRESS_PTR r_addr,
		     DAT_CONN_QUAL r_qual, DAT_COUNT p_size, DAT_PVOID p_data, int retries)
{
	dp_ib_cm_handle_t cm_ptr;
	int ret;
	socklen_t sl;
	DAPL_IA *ia_ptr = ep_ptr->header.owner_ia;
	DAT_RETURN dat_ret = DAT_INSUFFICIENT_RESOURCES;

	dapl_dbg_log(DAPL_DBG_TYPE_EP, " connect: r_qual %d p_size=%d\n",
		     r_qual, p_size);

	cm_ptr = dapli_cm_alloc(ep_ptr);
	if (cm_ptr == NULL)
		return dat_ret;

	cm_ptr->retry = retries;

	/* create, connect, sockopt, and exchange QP information */
	if ((cm_ptr->socket =
	     socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == DAPL_INVALID_SOCKET) {
		int err = dapl_socket_errno();
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " connect: socket create ERR 0x%x %s\n", 
			 err, strerror(err));
		goto bail;
	}

	ret = dapl_config_socket(cm_ptr->socket);
	if (ret < 0) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " connect: config socket %d RET %d ERR 0x%x %s\n",
			 cm_ptr->socket, ret, 
			 dapl_socket_errno(), strerror(dapl_socket_errno()));
		dat_ret = DAT_INTERNAL_ERROR;
		goto bail;
	}

	/* save remote address */
	dapl_os_memcpy(&cm_ptr->addr, r_addr, sizeof(*r_addr));
	((struct sockaddr_in *)&cm_ptr->addr)->sin_port = htons(r_qual + 1000);
	ret = dapl_connect_socket(cm_ptr->socket, (struct sockaddr *)&cm_ptr->addr,
				  sizeof(cm_ptr->addr));
	if (ret && ret != EAGAIN) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " connect: dapl_connect_socket RET %d ERR 0x%x %s\n",
			 ret, dapl_socket_errno(), 
			 strerror(dapl_socket_errno()));
		dat_ret = DAT_INVALID_ADDRESS;
		goto bail;
	}

	/* REQ: QP info in msg.saddr, IA address in msg.daddr, and pdata */
	cm_ptr->hca = ia_ptr->hca_ptr;
	cm_ptr->msg.op = ntohs(DCM_REQ);
	cm_ptr->msg.mtu = ia_ptr->hca_ptr->ib_trans.ib_cm.mtu; /* local MTU to peer */
	cm_ptr->msg.saddr.ib.qpn = htonl(ep_ptr->qp_handle->qp->qp_num);
	cm_ptr->msg.saddr.ib.qp_type = ep_ptr->qp_handle->qp->qp_type;
	cm_ptr->msg.saddr.ib.lid = ia_ptr->hca_ptr->ib_trans.lid;
	dapl_os_memcpy(&cm_ptr->msg.saddr.ib.gid[0], 
		       &ia_ptr->hca_ptr->ib_trans.gid, 16);
	
	/* get local address information from socket */
	sl = sizeof(cm_ptr->msg.daddr.so);
	if (getsockname(cm_ptr->socket, (struct sockaddr *)&cm_ptr->msg.daddr.so, &sl)) {
		int err = dapl_socket_errno();
		dapl_log(DAPL_DBG_TYPE_ERR,
			" connect getsockname ERROR: 0x%x %s -> %s r_qual %d\n",
			err, strerror(err), 
			inet_ntoa(((struct sockaddr_in *)r_addr)->sin_addr),
			(unsigned int)r_qual);;
	}

	if (p_size) {
		cm_ptr->msg.p_size = htons(p_size);
		dapl_os_memcpy(cm_ptr->msg.p_data, p_data, p_size);
	}

	/* connected or pending, either way results via async event */
	if (ret == 0)
		dapli_socket_connected(cm_ptr, 0);
	else
		cm_ptr->state = DCM_CONN_PENDING;

	dapl_dbg_log(DAPL_DBG_TYPE_EP, " connect: p_data=%p %p\n",
		     cm_ptr->msg.p_data, cm_ptr->msg.p_data);

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " connect: %s r_qual %d pending, p_sz=%d, %d %d ...\n",
		     inet_ntoa(((struct sockaddr_in *)&cm_ptr->addr)->sin_addr), 
		     (unsigned int)r_qual, ntohs(cm_ptr->msg.p_size),
		     cm_ptr->msg.p_data[0], cm_ptr->msg.p_data[1]);

	/* queue up on work thread */
	dapli_cm_queue(cm_ptr);
	return DAT_SUCCESS;
bail:
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_ERR);

	dapl_log(DAPL_DBG_TYPE_ERR,
		 " connect ERROR: -> %s r_qual %d\n",
		 inet_ntoa(((struct sockaddr_in *)r_addr)->sin_addr),
		 (unsigned int)r_qual);

	/* Never queued, destroy */
	dapls_cm_release(cm_ptr);
	return dat_ret;
}

/*
 * ACTIVE: exchange QP information, called from CR thread
 */
static void dapli_socket_connect_rtu(dp_ib_cm_handle_t cm_ptr)
{
	DAPL_EP *ep_ptr = cm_ptr->ep;
	int len, exp = sizeof(ib_cm_msg_t) - DCM_MAX_PDATA_SIZE;
	ib_cm_events_t event = IB_CME_LOCAL_FAILURE;
	socklen_t sl;

	/* read DST information into cm_ptr, overwrite SRC info */
	len = recv(cm_ptr->socket, (char *)&cm_ptr->msg, exp, 0);

	if (ntohs(cm_ptr->msg.ver) < DCM_VER_XPS) {
		len += recv(cm_ptr->socket, (char *)&cm_ptr->msg+len, SCM_BC_DIFF, 0);
		exp += SCM_BC_DIFF;
	}

	dapl_log(DAPL_DBG_TYPE_CM,
		 " CONN_REP_IN: ver %d cm_sz %d, p_sz %d rd_in %d mtu %d rsv %d\n",
		 ntohs(cm_ptr->msg.ver), exp, ntohs(cm_ptr->msg.p_size),
		 cm_ptr->msg.rd_in, cm_ptr->msg.mtu, cm_ptr->msg.resv[0]);

	if (len != exp || ntohs(cm_ptr->msg.ver) < DCM_VER_MIN) {
		int err = dapl_socket_errno();
		dapl_log(DAPL_DBG_TYPE_CM_WARN,
			 " CONN_REP_PENDING: sk %d ERR 0x%x, rcnt=%d, v=%d ->"
			 " %s PORT L-%x R-%x %d\n",
			 cm_ptr->socket, err, len, ntohs(cm_ptr->msg.ver),
			 inet_ntoa(((struct sockaddr_in *)&cm_ptr->addr)->sin_addr),
			 ntohs(((struct sockaddr_in *)&cm_ptr->msg.daddr.so)->sin_port),
			 ntohs(((struct sockaddr_in *)&cm_ptr->addr)->sin_port),
			 cm_ptr->retry);

		/* Retry; corner case where server tcp stack resets under load */
		if ((err == ECONNRESET && --cm_ptr->retry) || (--cm_ptr->retry == SCM_CR_RETRY-1)) {
			closesocket(cm_ptr->socket);
			cm_ptr->socket = DAPL_INVALID_SOCKET;
			dapl_log(DAPL_DBG_TYPE_CM_WARN, "CONN_REQ: retry %d\n", cm_ptr->retry);
			dapli_socket_connect(cm_ptr->ep, (DAT_IA_ADDRESS_PTR)&cm_ptr->addr, 
					     ntohs(((struct sockaddr_in *)&cm_ptr->addr)->sin_port) - 1000,
					     ntohs(cm_ptr->msg.p_size), &cm_ptr->msg.p_data, cm_ptr->retry);
			dapl_ep_unlink_cm(cm_ptr->ep, cm_ptr);
			dapli_cm_free(cm_ptr);
			return;
		}
		goto bail;
	}
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_REP_RX);

	/* keep the QP, address info in network order */
	
	/* save remote address information, in msg.daddr */
	dapl_os_memcpy(&cm_ptr->addr,
		       &cm_ptr->msg.daddr.so,
		       sizeof(union dcm_addr));

	/* save local address information from socket */
	sl = sizeof(cm_ptr->addr);
	getsockname(cm_ptr->socket,(struct sockaddr *)&cm_ptr->addr, &sl);

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " CONN_RTU: DST %s %d lid=0x%x,"
		     " qpn=0x%x, qp_type=%d, psize=%d\n",
		     inet_ntoa(((struct sockaddr_in *)
				&cm_ptr->msg.daddr.so)->sin_addr),
		     ntohs(((struct sockaddr_in *)
				&cm_ptr->msg.daddr.so)->sin_port),
		     ntohs(cm_ptr->msg.saddr.ib.lid),
		     ntohl(cm_ptr->msg.saddr.ib.qpn), 
		     cm_ptr->msg.saddr.ib.qp_type, 
		     ntohs(cm_ptr->msg.p_size));

	/* validate private data size before reading */
	if (ntohs(cm_ptr->msg.p_size) > DCM_MAX_PDATA_SIZE) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " CONN_RTU read: psize (%d) wrong -> %s\n",
			 ntohs(cm_ptr->msg.p_size), 
			 inet_ntoa(((struct sockaddr_in *)
				   ep_ptr->param.
				   remote_ia_address_ptr)->sin_addr));
		goto bail;
	}

	/* read private data into cm_handle if any present */
	dapl_dbg_log(DAPL_DBG_TYPE_EP," CONN_RTU: read private data\n");
	exp = ntohs(cm_ptr->msg.p_size);
	if (exp) {
		len = recv(cm_ptr->socket, cm_ptr->msg.p_data, exp, 0);
		if (len != exp) {
			int err = dapl_socket_errno();
			dapl_log(DAPL_DBG_TYPE_CM_WARN,
				 " CONN_RTU read pdata: ERR 0x%x %s"
				 " rcv %d !=  exp %d -> %s\n",
				 err, strerror(err), len, exp,
				 inet_ntoa(((struct sockaddr_in *)
					    ep_ptr->param.
					    remote_ia_address_ptr)->sin_addr));
			goto bail;
		}
	}

	/* check for consumer or protocol stack reject */
	if (ntohs(cm_ptr->msg.op) == DCM_REP)
		event = IB_CME_CONNECTED;
	else if (ntohs(cm_ptr->msg.op) == DCM_REJ_USER) 
		event = IB_CME_DESTINATION_REJECT_PRIVATE_DATA;
	else  
		event = IB_CME_DESTINATION_REJECT;
	
	if (event != IB_CME_CONNECTED) {
		dapl_log(DAPL_DBG_TYPE_CM,
			 " CONN_RTU: reject from %s %x\n",
			 inet_ntoa(((struct sockaddr_in *)
				    &cm_ptr->msg.daddr.so)->sin_addr),
			 ntohs(((struct sockaddr_in *)
				 &cm_ptr->msg.daddr.so)->sin_port));
		goto bail;
	}

	/* rdma_out, initiator, cannot exceed remote rdma_in max */
	if (ntohs(cm_ptr->msg.ver) >= DCM_VER_RR)
		ep_ptr->param.ep_attr.max_rdma_read_out =
				DAPL_MIN(ep_ptr->param.ep_attr.max_rdma_read_out,
					 cm_ptr->msg.rd_in);

	/* Set QP MTU, if negotiated. 2K for compatibility */
	ep_ptr->qp_handle->mtu = (ntohs(cm_ptr->msg.ver) >= DCM_VER_MTU) ?
				 DAPL_MIN(cm_ptr->msg.mtu, cm_ptr->hca->ib_trans.ib_cm.mtu):
				 getenv("DAPL_IB_MTU") ? cm_ptr->hca->ib_trans.ib_cm.mtu : IBV_MTU_2048;

	/* modify QP to RTR and then to RTS with remote info */
	dapl_os_lock(&ep_ptr->header.lock);
	if (dapls_modify_qp_state(ep_ptr->qp_handle->qp,
				  IBV_QPS_RTR, 
				  cm_ptr->msg.saddr.ib.qpn,
				  cm_ptr->msg.saddr.ib.lid,
				  (ib_gid_handle_t)cm_ptr->msg.saddr.ib.gid) != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " CONN_RTU: QPS_RTR ERR %s (%d,%d,%x,%x,%x) -> %s %x\n",
			 strerror(errno), ep_ptr->qp_handle->qp->qp_type,
			 ep_ptr->qp_state, ep_ptr->qp_handle->qp->qp_num,
			 ntohl(cm_ptr->msg.saddr.ib.qpn), 
			 ntohs(cm_ptr->msg.saddr.ib.lid),
			 inet_ntoa(((struct sockaddr_in *)
				    &cm_ptr->msg.daddr.so)->sin_addr),
			 ntohs(((struct sockaddr_in *)
				 &cm_ptr->msg.daddr.so)->sin_port));
		dapl_os_unlock(&ep_ptr->header.lock);
		goto bail;
	}
	if (dapls_modify_qp_state(ep_ptr->qp_handle->qp,
				  IBV_QPS_RTS, 
				  cm_ptr->msg.saddr.ib.qpn,
				  cm_ptr->msg.saddr.ib.lid,
				  NULL) != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " CONN_RTU: QPS_RTS ERR %s (%d,%d,%x,%x,%x) -> %s %x\n",
			 strerror(errno), ep_ptr->qp_handle->qp->qp_type,
			 ep_ptr->qp_state, ep_ptr->qp_handle->qp->qp_num,
			 ntohl(cm_ptr->msg.saddr.ib.qpn), 
			 ntohs(cm_ptr->msg.saddr.ib.lid),
			 inet_ntoa(((struct sockaddr_in *)
				    &cm_ptr->msg.daddr.so)->sin_addr),
			 ntohs(((struct sockaddr_in *)
				 &cm_ptr->msg.daddr.so)->sin_port));
	  	dapl_os_unlock(&ep_ptr->header.lock);
		goto bail;
	}
  	dapl_os_unlock(&ep_ptr->header.lock);
	dapl_dbg_log(DAPL_DBG_TYPE_EP, " connect_rtu: send RTU\n");

	/* complete handshake after final QP state change, Just ver+op */
	dapl_os_lock(&cm_ptr->lock);
	cm_ptr->state = DCM_CONNECTED;
	dapl_os_unlock(&cm_ptr->lock);

	cm_ptr->msg.op = ntohs(DCM_RTU);
	cm_ptr->msg.mtu = ep_ptr->qp_handle->mtu; /* send negotiated MTU */
	if (send(cm_ptr->socket, (char *)&cm_ptr->msg, 4, 0) == -1) {
		int err = dapl_socket_errno();
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " CONN_RTU: write ERR = 0x%x %s\n", 
			 err, strerror(err));
		goto bail;
	}
	/* post the event with private data */
	event = IB_CME_CONNECTED;
	dapl_dbg_log(DAPL_DBG_TYPE_EP, " ACTIVE: connected!\n");
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_RTU_TX);
	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_ACTIVE_EST);

#ifdef DAT_EXTENSIONS
ud_bail:
	if (cm_ptr->msg.saddr.ib.qp_type == IBV_QPT_UD) {
		DAT_IB_EXTENSION_EVENT_DATA xevent;
		ib_pd_handle_t pd_handle = 
			((DAPL_PZ *)ep_ptr->param.pz_handle)->pd_handle;

		if (event == IB_CME_CONNECTED) {
			cm_ptr->ah = dapls_create_ah(cm_ptr->hca, pd_handle,
						     ep_ptr->qp_handle->qp,
						     cm_ptr->msg.saddr.ib.lid, 
						     NULL);
			if (cm_ptr->ah) {
				/* post UD extended EVENT */
				xevent.status = 0;
				xevent.type = DAT_IB_UD_REMOTE_AH;
				xevent.remote_ah.ah = cm_ptr->ah;
				xevent.remote_ah.qpn = ntohl(cm_ptr->msg.saddr.ib.qpn);
				dapl_os_memcpy(&xevent.remote_ah.ia_addr,
						&ep_ptr->remote_ia_address,
						sizeof(union dcm_addr));
				event = DAT_IB_UD_CONNECTION_EVENT_ESTABLISHED;

				dapl_log(DAPL_DBG_TYPE_CM, 
					" CONN_RTU: UD AH %p for lid 0x%x"
					" qpn 0x%x\n", 
					cm_ptr->ah, 
					ntohs(cm_ptr->msg.saddr.ib.lid),
					ntohl(cm_ptr->msg.saddr.ib.qpn));

				DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)),
					    DCNT_IA_CM_AH_RESOLVED);
	
			} else 
				event = DAT_IB_UD_CONNECTION_ERROR_EVENT;
			
		} else if (event == IB_CME_LOCAL_FAILURE) {
			event = DAT_IB_UD_CONNECTION_ERROR_EVENT;
		} else  
			event = DAT_IB_UD_CONNECTION_REJECT_EVENT;

		dapls_evd_post_connection_event_ext(
				(DAPL_EVD *) ep_ptr->param.connect_evd_handle,
				event,
				(DAT_EP_HANDLE) ep_ptr,
				(DAT_COUNT) exp,
				(DAT_PVOID *) cm_ptr->msg.p_data,
				(DAT_PVOID *) &xevent);

		/* cleanup and release from local list */
		dapli_cm_free(cm_ptr);
	
	} else
#endif
	{
		dapli_ep_check(cm_ptr->ep);
		dapl_evd_connection_callback(cm_ptr, event, cm_ptr->msg.p_data,
					     DCM_MAX_PDATA_SIZE, ep_ptr);
	}
	dapl_log(DAPL_DBG_TYPE_CM_EST,
		 " SCM ACTIVE CONN: %x -> %s %x mtu %d\n",
		 ntohs(((struct sockaddr_in *) &cm_ptr->addr)->sin_port),
		 inet_ntoa(((struct sockaddr_in *) &cm_ptr->msg.daddr.so)->sin_addr),
		 ntohs(((struct sockaddr_in *) &cm_ptr->msg.daddr.so)->sin_port)-1000,
		 ep_ptr->qp_handle->mtu);
	return;

bail:

#ifdef DAT_EXTENSIONS
	if (cm_ptr->msg.saddr.ib.qp_type == IBV_QPT_UD) 
		goto ud_bail;
#endif
	/* close socket, and post error event */
	dapl_os_lock(&cm_ptr->lock);
	cm_ptr->state = DCM_REJECTED;
	dapl_os_unlock(&cm_ptr->lock);

	dapl_evd_connection_callback(NULL, event, cm_ptr->msg.p_data,
				     DCM_MAX_PDATA_SIZE, ep_ptr);
	dapli_cm_free(cm_ptr);
}

/*
 * PASSIVE: Create socket, listen, accept, exchange QP information 
 */
DAT_RETURN
dapli_socket_listen(DAPL_IA * ia_ptr, DAT_CONN_QUAL serviceID, DAPL_SP * sp_ptr)
{
	struct sockaddr_in addr;
	ib_cm_srvc_handle_t cm_ptr = NULL;
	DAT_RETURN dat_status = DAT_SUCCESS;
	int opt = 1;

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		     " setup listen(ia_ptr %p ServiceID %d sp_ptr %p)\n",
		     ia_ptr, serviceID, sp_ptr);

	cm_ptr = dapli_cm_alloc(NULL);
	if (cm_ptr == NULL)
		return DAT_INSUFFICIENT_RESOURCES;

	cm_ptr->sp = sp_ptr;
	cm_ptr->hca = ia_ptr->hca_ptr;

	/* bind, listen, set sockopt, accept, exchange data */
	if ((cm_ptr->socket =
	     socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == DAPL_INVALID_SOCKET) {
		int err = dapl_socket_errno();
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " listen: socket create: ERR 0x%x %s\n",
			 err, strerror(err));
		dat_status = DAT_INSUFFICIENT_RESOURCES;
		goto bail;
	}

	setsockopt(cm_ptr->socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
	addr.sin_port = htons(serviceID + 1000);
	addr.sin_family = AF_INET;
	addr.sin_addr = ((struct sockaddr_in *) &ia_ptr->hca_ptr->hca_address)->sin_addr;

	if ((bind(cm_ptr->socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	    || (listen(cm_ptr->socket, 128) < 0)) {
		int err = dapl_socket_errno();
		if (err == EADDRINUSE)
			dat_status = DAT_CONN_QUAL_IN_USE;
		else {
			dapl_log(DAPL_DBG_TYPE_CM_WARN,
				 " listen: ERROR 0x%x %s on port %d\n",
				 err, strerror(err), serviceID + 1000);
			dat_status = DAT_INVALID_PARAMETER;
		}
		goto bail;
	}

	/* set cm_handle for this service point, save listen socket */
	sp_ptr->cm_srvc_handle = cm_ptr;
	dapl_os_memcpy(&cm_ptr->addr, &addr, sizeof(addr)); 

	/* queue up listen socket to process inbound CR's */
	cm_ptr->state = DCM_LISTEN;
	dapli_cm_queue(cm_ptr);

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		     " setup listen: port %d cr %p s_fd %d\n",
		     serviceID + 1000, cm_ptr, cm_ptr->socket);

	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_LISTEN);

	return dat_status;
bail:
	/* Never queued, destroy here */
	dapls_cm_release(cm_ptr);
	return dat_status;
}

/*
 * PASSIVE: accept socket 
 */
static void dapli_socket_accept(ib_cm_srvc_handle_t cm_ptr)
{
	dp_ib_cm_handle_t acm_ptr;
	int ret, len, opt = 1;
	socklen_t sl;

	/* 
	 * Accept all CR's on this port to avoid half-connection (SYN_RCV)
	 * stalls with many to one connection storms
	 */
	do {
		/* Allocate accept CM and initialize */
		if ((acm_ptr = dapli_cm_alloc(NULL)) == NULL)
			return;

		acm_ptr->sp = cm_ptr->sp;
		acm_ptr->hca = cm_ptr->hca;

		len = sizeof(union dcm_addr);
		acm_ptr->socket = accept(cm_ptr->socket,
					(struct sockaddr *)
					&acm_ptr->msg.daddr.so,
					(socklen_t *) &len);
		if (acm_ptr->socket == DAPL_INVALID_SOCKET) {
			int err = dapl_socket_errno();
			dapl_log(DAPL_DBG_TYPE_ERR,
				" ACCEPT: ERR 0x%x %s on FD %d l_cr %p\n",
				err, strerror(err), cm_ptr->socket, cm_ptr);
			dapls_cm_release(acm_ptr);
			return;
		}
		dapl_dbg_log(DAPL_DBG_TYPE_CM, " accepting from %s %x\n",
			     inet_ntoa(((struct sockaddr_in *)
					&acm_ptr->msg.daddr.so)->sin_addr),
			     ntohs(((struct sockaddr_in *)
					&acm_ptr->msg.daddr.so)->sin_port));

		/* no delay for small packets */
		ret = setsockopt(acm_ptr->socket, IPPROTO_TCP, TCP_NODELAY,
			   (char *)&opt, sizeof(opt));
		if (ret) {
			int err = dapl_socket_errno();
			dapl_log(DAPL_DBG_TYPE_ERR,
				 " ACCEPT: NODELAY setsockopt:"
				 " RET %d ERR 0x%x %s\n",
			 	 ret, err, strerror(err));
		}

		/* get local address information from socket */
		sl = sizeof(acm_ptr->addr);
		getsockname(acm_ptr->socket, (struct sockaddr *)&acm_ptr->addr, &sl);
		acm_ptr->state = DCM_ACCEPTING;
		dapli_cm_queue(acm_ptr);
	
	} while (dapl_poll(cm_ptr->socket, DAPL_FD_READ) == DAPL_FD_READ);
}

/*
 * PASSIVE: receive peer QP information, private data, post cr_event 
 */
static void dapli_socket_accept_data(ib_cm_srvc_handle_t acm_ptr)
{
	int len, exp = sizeof(ib_cm_msg_t) - DCM_MAX_PDATA_SIZE;
	void *p_data = NULL;

	dapl_dbg_log(DAPL_DBG_TYPE_EP, " socket accepted, read QP data\n");

	/* read in DST QP info, IA address. check for private data */
	len = recv(acm_ptr->socket, (char *)&acm_ptr->msg, exp, 0);

	if (ntohs(acm_ptr->msg.ver) < DCM_VER_XPS) {
		len += recv(acm_ptr->socket, (char *)&acm_ptr->msg+len, SCM_BC_DIFF, 0);
		exp += SCM_BC_DIFF;
	}

	if (len != exp || ntohs(acm_ptr->msg.ver) < DCM_VER_MIN) {
		int err = dapl_socket_errno();
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " ACCEPT read: ERR 0x%x %s, rcnt=%d, ver=%d\n",
			 err, strerror(err), len, ntohs(acm_ptr->msg.ver));
		goto bail;
	}

	/* keep the QP, address info in network order */

	/* validate private data size before reading */
	exp = ntohs(acm_ptr->msg.p_size);
	if (exp > DCM_MAX_PDATA_SIZE) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			     " accept read: psize (%d) wrong\n",
			     acm_ptr->msg.p_size);
		goto bail;
	}

	/* read private data into cm_handle if any present */
	if (exp) {
		len = recv(acm_ptr->socket, acm_ptr->msg.p_data, exp, 0);
		if (len != exp) {
			int err = dapl_socket_errno();
			dapl_log(DAPL_DBG_TYPE_ERR,
				 " accept read pdata: ERR 0x%x %s, rcnt=%d\n",
				 err, strerror(err), len);
			goto bail;
		}
		p_data = acm_ptr->msg.p_data;
	}
	dapl_os_lock(&acm_ptr->lock);
	acm_ptr->state = DCM_ACCEPTING_DATA;
	dapl_os_unlock(&acm_ptr->lock);

	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&acm_ptr->hca->ia_list_head)), DCNT_IA_CM_REQ_RX);

	dapl_log(DAPL_DBG_TYPE_CM,
		 " ACCEPT: DST %s %x lid=0x%x, qpn=0x%x, psz=%d"
		 " rd_in %d mtu %d rsv %d \n",
		 inet_ntoa(((struct sockaddr_in *)
			     &acm_ptr->msg.daddr.so)->sin_addr),
		 ntohs(((struct sockaddr_in *)
		         &acm_ptr->msg.daddr.so)->sin_port),
		 ntohs(acm_ptr->msg.saddr.ib.lid),
		 ntohl(acm_ptr->msg.saddr.ib.qpn), exp,
		 acm_ptr->msg.rd_in, acm_ptr->msg.mtu,
		 acm_ptr->msg.resv[0]);

#ifdef DAT_EXTENSIONS
	if (acm_ptr->msg.saddr.ib.qp_type == IBV_QPT_UD) {
		DAT_IB_EXTENSION_EVENT_DATA xevent;

		/* post EVENT, modify_qp created ah */
		xevent.status = 0;
		xevent.type = DAT_IB_UD_CONNECT_REQUEST;

		dapls_evd_post_cr_event_ext(acm_ptr->sp,
					    DAT_IB_UD_CONNECTION_REQUEST_EVENT,
					    acm_ptr,
					    (DAT_COUNT) exp,
					    (DAT_PVOID *) acm_ptr->msg.p_data,
					    (DAT_PVOID *) &xevent);

		DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&acm_ptr->hca->ia_list_head)),
			    DCNT_IA_CM_AH_REQ_RX);
	} else
#endif
		/* trigger CR event and return SUCCESS */
		dapls_cr_callback(acm_ptr,
				  IB_CME_CONNECTION_REQUEST_PENDING,
				  p_data, exp, acm_ptr->sp);
	return;
bail:
	/* mark for destroy, active will see socket close as rej */
	dapli_cm_free(acm_ptr);
	return;
}

/*
 * PASSIVE: consumer accept, send local QP information, private data, 
 * queue on work thread to receive RTU information to avoid blocking
 * user thread. 
 */
static DAT_RETURN
dapli_socket_accept_usr(DAPL_EP * ep_ptr,
			DAPL_CR * cr_ptr, DAT_COUNT p_size, DAT_PVOID p_data)
{
	DAPL_IA *ia_ptr = ep_ptr->header.owner_ia;
	dp_ib_cm_handle_t cm_ptr = cr_ptr->ib_cm_handle;
	ib_cm_msg_t local;
	struct iovec iov[2];
	int len, exp = sizeof(ib_cm_msg_t) - DCM_MAX_PDATA_SIZE;
	DAT_RETURN ret = DAT_INTERNAL_ERROR;
	socklen_t sl;

	if (p_size > DCM_MAX_PDATA_SIZE) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " accept_usr: psize(%d) too large\n", p_size);
		return DAT_LENGTH_ERROR;
	}

	/* must have a accepted socket */
	if (cm_ptr->socket == DAPL_INVALID_SOCKET) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " accept_usr: cm socket invalid\n");
		goto bail;
	}

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		     " ACCEPT_USR: remote lid=0x%x"
		     " qpn=0x%x qp_type %d, psize=%d\n",
		     ntohs(cm_ptr->msg.saddr.ib.lid),
		     ntohl(cm_ptr->msg.saddr.ib.qpn), 
		     cm_ptr->msg.saddr.ib.qp_type, 
		     ntohs(cm_ptr->msg.p_size));

#ifdef DAT_EXTENSIONS
	if (cm_ptr->msg.saddr.ib.qp_type == IBV_QPT_UD &&
	    ep_ptr->qp_handle->qp->qp_type != IBV_QPT_UD) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " ACCEPT_USR: ERR remote QP is UD,"
			 ", but local QP is not\n");
		ret = (DAT_INVALID_HANDLE | DAT_INVALID_HANDLE_EP);
		goto bail;
	}
#endif
	/* rdma_out, initiator, cannot exceed remote rdma_in max */
	if (ntohs(cm_ptr->msg.ver) >= DCM_VER_RR)
		ep_ptr->param.ep_attr.max_rdma_read_out =
				DAPL_MIN(ep_ptr->param.ep_attr.max_rdma_read_out,
					 cm_ptr->msg.rd_in);

	if (ntohs(cm_ptr->msg.ver) <  DCM_VER_XPS)
		exp += SCM_BC_DIFF;

	/* Set QP MTU, if negotiated. 2K for compatibility */
	ep_ptr->qp_handle->mtu = (ntohs(cm_ptr->msg.ver) >= DCM_VER_MTU) ?
				 DAPL_MIN(cm_ptr->msg.mtu, cm_ptr->hca->ib_trans.ib_cm.mtu):
				 getenv("DAPL_IB_MTU") ? cm_ptr->hca->ib_trans.ib_cm.mtu : IBV_MTU_2048;

	/* modify QP to RTR and then to RTS with remote info already read */
	dapl_os_lock(&ep_ptr->header.lock);
	if (dapls_modify_qp_state(ep_ptr->qp_handle->qp,
				  IBV_QPS_RTR, 
				  cm_ptr->msg.saddr.ib.qpn,
				  cm_ptr->msg.saddr.ib.lid,
				  (ib_gid_handle_t)cm_ptr->msg.saddr.ib.gid) != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " ACCEPT_USR: QPS_RTR ERR %s -> %s\n",
			 strerror(errno), 
			 inet_ntoa(((struct sockaddr_in *)
				     &cm_ptr->msg.daddr.so)->sin_addr));
		dapl_os_unlock(&ep_ptr->header.lock);
		goto bail;
	}
	if (dapls_modify_qp_state(ep_ptr->qp_handle->qp,
				  IBV_QPS_RTS, 
				  cm_ptr->msg.saddr.ib.qpn,
				  cm_ptr->msg.saddr.ib.lid,
				  NULL) != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " ACCEPT_USR: QPS_RTS ERR %s -> %s\n",
			 strerror(errno), 
			 inet_ntoa(((struct sockaddr_in *)
				     &cm_ptr->msg.daddr.so)->sin_addr));
		dapl_os_unlock(&ep_ptr->header.lock);
		goto bail;
	}
	dapl_os_unlock(&ep_ptr->header.lock);

	/* save remote address information */
	dapl_os_memcpy(&ep_ptr->remote_ia_address,
		       &cm_ptr->msg.daddr.so,
		       sizeof(union dcm_addr));

	/* send our QP info, IA address, pdata. Don't overwrite dst data */
	(void)dapl_os_memzero(&local, sizeof(ib_cm_msg_t));
	local.ver = htons(DCM_VER);
	local.op = htons(DCM_REP);
	local.rd_in = ep_ptr->param.ep_attr.max_rdma_read_in;
	local.mtu = ep_ptr->qp_handle->mtu; /* send negotiated MTU */
	local.saddr.ib.qpn = htonl(ep_ptr->qp_handle->qp->qp_num);
	local.saddr.ib.qp_type = ep_ptr->qp_handle->qp->qp_type;
	local.saddr.ib.lid = ia_ptr->hca_ptr->ib_trans.lid;
	dapl_os_memcpy(&local.saddr.ib.gid[0], 
		       &ia_ptr->hca_ptr->ib_trans.gid, 16);
	
	/* Get local address information from socket */
	sl = sizeof(local.daddr.so);
	getsockname(cm_ptr->socket, (struct sockaddr *)&local.daddr.so, &sl);

	cm_ptr->hca = ia_ptr->hca_ptr;
	dapl_os_lock(&cm_ptr->lock);
	cm_ptr->state = DCM_ACCEPTED;
	dapl_os_unlock(&cm_ptr->lock);

	/* Link CM to EP, already queued on work thread, !PSP !RSP */
	if (!cm_ptr->sp->ep_handle && !cm_ptr->sp->psp_flags)
		dapl_ep_link_cm(ep_ptr, cm_ptr);
	cm_ptr->ep = ep_ptr;

	local.p_size = htons(p_size);
	iov[0].iov_base = (void *)&local;
	iov[0].iov_len = exp;
	
	if (p_size) {
		iov[1].iov_base = p_data;
		iov[1].iov_len = p_size;
		len = writev(cm_ptr->socket, iov, 2);
	} else 
		len = writev(cm_ptr->socket, iov, 1);
	
	if (len != (p_size + exp)) {
		int err = dapl_socket_errno();
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " ACCEPT_USR: ERR 0x%x %s, wcnt=%d -> %s\n",
			 err, strerror(err), len, 
			 inet_ntoa(((struct sockaddr_in *)
				   &cm_ptr->msg.daddr.so)->sin_addr));
		dapl_ep_unlink_cm(ep_ptr, cm_ptr);
		cm_ptr->ep = NULL;
		goto bail;
	}

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		     " ACCEPT_USR: local GID %s lid=0x%x qpn=0x%x psz=%d\n",
		     inet_ntop(AF_INET6, &cm_ptr->hca->ib_trans.gid,
			       gid_str, sizeof(gid_str)),
		     ntohs(local.saddr.ib.lid), ntohl(local.saddr.ib.qpn),
		     ntohs(local.p_size));

	dapl_dbg_log(DAPL_DBG_TYPE_EP, " PASSIVE: accepted!\n");

	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_REP_TX);

	return DAT_SUCCESS;
bail:
	/* schedule cleanup from workq */
	dapli_cm_free(cm_ptr);
	return ret;
}

/*
 * PASSIVE: read RTU from active peer, post CONN event
 */
static void dapli_socket_accept_rtu(dp_ib_cm_handle_t cm_ptr)
{
	int len;
	ib_cm_events_t event = IB_CME_CONNECTED;

	/* complete handshake after final QP state change, VER and OP */
	len = recv(cm_ptr->socket, (char *)&cm_ptr->msg, 4, 0);
	if (len != 4 || ntohs(cm_ptr->msg.op) != DCM_RTU) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " ACCEPT_RTU: rcv ERR, rcnt=%d op=%x <- %s\n",
			 len, ntohs(cm_ptr->msg.op),
			 inet_ntoa(((struct sockaddr_in *)
				    &cm_ptr->msg.daddr.so)->sin_addr));
		event = IB_CME_DESTINATION_REJECT;
		goto bail;
	}

	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_RTU_RX);

	/* save state and reference to EP, queue for disc event */
	dapl_os_lock(&cm_ptr->lock);
	cm_ptr->state = DCM_CONNECTED;
	dapl_os_unlock(&cm_ptr->lock);

	/* final data exchange if remote QP state is good to go */
	dapl_dbg_log(DAPL_DBG_TYPE_EP, " PASSIVE: connected!\n");

#ifdef DAT_EXTENSIONS
ud_bail:
	if (cm_ptr->msg.saddr.ib.qp_type == IBV_QPT_UD) {
		DAT_IB_EXTENSION_EVENT_DATA xevent;

		ib_pd_handle_t pd_handle = 
			((DAPL_PZ *)cm_ptr->ep->param.pz_handle)->pd_handle;
		
		if (event == IB_CME_CONNECTED) {
			cm_ptr->ah = dapls_create_ah(cm_ptr->hca, pd_handle,
						cm_ptr->ep->qp_handle->qp,
						cm_ptr->msg.saddr.ib.lid, 
						NULL);
			if (cm_ptr->ah) { 
				/* post EVENT, modify_qp created ah */
				xevent.status = 0;
				xevent.type = DAT_IB_UD_PASSIVE_REMOTE_AH;
				xevent.remote_ah.ah = cm_ptr->ah;
				xevent.remote_ah.qpn = ntohl(cm_ptr->msg.saddr.ib.qpn);
				dapl_os_memcpy(&xevent.remote_ah.ia_addr,
					&cm_ptr->msg.daddr.so,
					sizeof(union dcm_addr));
				event = DAT_IB_UD_CONNECTION_EVENT_ESTABLISHED;
			} else 
				event = DAT_IB_UD_CONNECTION_ERROR_EVENT;
		} else 
			event = DAT_IB_UD_CONNECTION_ERROR_EVENT;

		dapl_log(DAPL_DBG_TYPE_CM, 
			" CONN_RTU: UD AH %p for lid 0x%x qpn 0x%x\n", 
			cm_ptr->ah, ntohs(cm_ptr->msg.saddr.ib.lid),
			ntohl(cm_ptr->msg.saddr.ib.qpn));

		dapls_evd_post_connection_event_ext(
				(DAPL_EVD *) 
				cm_ptr->ep->param.connect_evd_handle,
				event,
				(DAT_EP_HANDLE) cm_ptr->ep,
				(DAT_COUNT) ntohs(cm_ptr->msg.p_size),
				(DAT_PVOID *) cm_ptr->msg.p_data,
				(DAT_PVOID *) &xevent);

		DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)), DCNT_IA_CM_AH_RESOLVED);

                /* cleanup and release from local list, still on EP list */
		dapli_cm_free(cm_ptr);
                
	} else 
#endif
	{
		dapli_ep_check(cm_ptr->ep);
		dapls_cr_callback(cm_ptr, event, NULL, 0, cm_ptr->sp);
	}
	dapl_log(DAPL_DBG_TYPE_CM_EST,
		 " SCM PASSIVE CONN: %x <- %s %x mtu %d\n",
		 cm_ptr->sp->conn_qual,
		 inet_ntoa(((struct sockaddr_in *) &cm_ptr->msg.daddr.so)->sin_addr),
		 ntohs(((struct sockaddr_in *) &cm_ptr->msg.daddr.so)->sin_port),
		 cm_ptr->ep->qp_handle->mtu);
	return;
      
bail:
#ifdef DAT_EXTENSIONS
	if (cm_ptr->msg.saddr.ib.qp_type == IBV_QPT_UD) 
		goto ud_bail;
#endif
	dapl_os_lock(&cm_ptr->lock);
	cm_ptr->state = DCM_REJECTED;
	dapl_os_unlock(&cm_ptr->lock);

	dapls_cr_callback(cm_ptr, event, NULL, 0, cm_ptr->sp);
	dapli_cm_free(cm_ptr);
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
		 IN DAT_IA_ADDRESS_PTR r_address,
		 IN DAT_CONN_QUAL r_qual,
		 IN DAT_COUNT private_data_size, IN void *private_data)
{
	DAPL_EP *ep_ptr = (DAPL_EP *) ep_handle;
	struct sockaddr_in *scm_ia = (struct sockaddr_in *)r_address;
	
	dapl_log(DAPL_DBG_TYPE_CM, " SCM connect -> IP %s port 0x%x,%d)\n",
		 inet_ntoa(scm_ia->sin_addr), r_qual + 1000, r_qual + 1000);

	return (dapli_socket_connect(ep_ptr, r_address, r_qual,
				     private_data_size, private_data, SCM_CR_RETRY));
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
dapls_ib_disconnect(IN DAPL_EP * ep_ptr, IN DAT_CLOSE_FLAGS close_flags)
{
	dp_ib_cm_handle_t cm_ptr = dapl_get_cm_from_ep(ep_ptr);

	dapl_os_lock(&ep_ptr->header.lock);
	if (ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED ||
	    ep_ptr->param.ep_attr.service_type != DAT_SERVICE_TYPE_RC ||
	    cm_ptr == NULL) {
		dapl_os_unlock(&ep_ptr->header.lock);
		return DAT_SUCCESS;
	} 
	dapl_os_unlock(&ep_ptr->header.lock);
	return (dapli_socket_disconnect(cm_ptr));
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
dapls_ib_disconnect_clean(IN DAPL_EP * ep_ptr,
			  IN DAT_BOOLEAN active,
			  IN const ib_cm_events_t ib_cm_event)
{
	if (ib_cm_event == IB_CME_TIMEOUT) {
		dp_ib_cm_handle_t cm_ptr;

		if ((cm_ptr = dapl_get_cm_from_ep(ep_ptr)) == NULL)
			return;

		dapl_log(DAPL_DBG_TYPE_WARN,
			"dapls_ib_disc_clean: CONN_TIMEOUT ep %p cm %p %s\n",
			ep_ptr, cm_ptr, dapl_cm_state_str(cm_ptr->state));
		
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
dapls_ib_setup_conn_listener(IN DAPL_IA * ia_ptr,
			     IN DAT_UINT64 ServiceID, IN DAPL_SP * sp_ptr)
{
	return (dapli_socket_listen(ia_ptr, ServiceID, sp_ptr));
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
dapls_ib_remove_conn_listener(IN DAPL_IA * ia_ptr, IN DAPL_SP * sp_ptr)
{
	ib_cm_srvc_handle_t cm_ptr = sp_ptr->cm_srvc_handle;

	/* free cm_srvc_handle, release will cleanup */
	if (cm_ptr != NULL) {
		/* cr_thread will free */
		sp_ptr->cm_srvc_handle = NULL;
		dapli_cm_free(cm_ptr);
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
			   IN DAT_COUNT p_size, IN const DAT_PVOID p_data)
{
	DAPL_CR *cr_ptr;
	DAPL_EP *ep_ptr;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     "dapls_ib_accept_connection(cr %p ep %p prd %p,%d)\n",
		     cr_handle, ep_handle, p_data, p_size);

	cr_ptr = (DAPL_CR *) cr_handle;
	ep_ptr = (DAPL_EP *) ep_handle;

	/* allocate and attach a QP if necessary */
	if (ep_ptr->qp_state == DAPL_QP_STATE_UNATTACHED) {
		DAT_RETURN status;
		status = dapls_ib_qp_alloc(ep_ptr->header.owner_ia,
					   ep_ptr, ep_ptr);
		if (status != DAT_SUCCESS)
			return status;
	}
	return (dapli_socket_accept_usr(ep_ptr, cr_ptr, p_size, p_data));
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
dapls_ib_reject_connection(IN dp_ib_cm_handle_t cm_ptr,
			   IN int reason,
			   IN DAT_COUNT psize, IN const DAT_PVOID pdata)
{
	struct iovec iov[2];
	int len;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " reject(cm %p reason %x, pdata %p, psize %d)\n",
		     cm_ptr, reason, pdata, psize);

        if (psize > DCM_MAX_PDATA_SIZE)
                return DAT_LENGTH_ERROR;

	/* write reject data to indicate reject */
	if (reason == IB_CM_REJ_REASON_CONSUMER_REJ)
		cm_ptr->msg.op = htons(DCM_REJ_USER);
	else
		cm_ptr->msg.op = htons(DCM_REJ_CM);

	cm_ptr->msg.p_size = htons(psize);
	
	iov[0].iov_base = (void *)&cm_ptr->msg;
	iov[0].iov_len = sizeof(ib_cm_msg_t) - DCM_MAX_PDATA_SIZE;
	if (psize) {
		iov[1].iov_base = pdata;
		iov[1].iov_len = psize;
		len = writev(cm_ptr->socket, iov, 2);
	} else {
		len = writev(cm_ptr->socket, iov, 1);
	}

	if (len != iov[0].iov_len + psize) {
		dapl_log(DAPL_DBG_TYPE_WARN,
			 " CONN_REJ writev ERR %s len = %d, exp %d\n",
			 strerror(errno), len,
			 iov[0].iov_len + psize);
		goto bail;
	}

	DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cm_ptr->hca->ia_list_head)),
			  reason == IB_CM_REJ_REASON_CONSUMER_REJ ?
			  DCNT_IA_CM_USER_REJ_TX : DCNT_IA_CM_ERR_REJ_TX);
bail:
	/* release and cleanup CM object */
	dapli_cm_free(cm_ptr);
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
	dp_ib_cm_handle_t conn;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     "dapls_ib_cm_remote_addr(dat_handle %p, ....)\n",
		     dat_handle);

	header = (DAPL_HEADER *) dat_handle;

	if (header->magic == DAPL_MAGIC_EP)
		conn = dapl_get_cm_from_ep((DAPL_EP *) dat_handle);
	else if (header->magic == DAPL_MAGIC_CR)
		conn = ((DAPL_CR *) dat_handle)->ib_cm_handle;
	else
		return DAT_INVALID_HANDLE;

	dapl_os_memcpy(remote_ia_address,
		       &conn->msg.daddr.so, sizeof(DAT_SOCK_ADDR6));

	return DAT_SUCCESS;
}

int dapls_ib_private_data_size(
	IN DAPL_HCA *hca_ptr)
{
	return DCM_MAX_PDATA_SIZE;
}

/* outbound/inbound CR processing thread to avoid blocking applications */
void cr_thread(void *arg)
{
	struct dapl_hca *hca_ptr = arg;
	dp_ib_cm_handle_t cr, next_cr;
	int opt, ret;
	socklen_t opt_len;
	char rbuf[2];
	struct dapl_fd_set *set;
	enum DAPL_FD_EVENTS event;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, " cr_thread: ENTER hca %p\n", hca_ptr);
	set = dapl_alloc_fd_set();
	if (!set)
		goto out;

	dapl_os_lock(&hca_ptr->ib_trans.lock);
	hca_ptr->ib_trans.cr_state = IB_THREAD_RUN;

	while (1) {
		dapl_fd_zero(set);
		dapl_fd_set(hca_ptr->ib_trans.scm[0], set, DAPL_FD_READ);

		if (!dapl_llist_is_empty(&hca_ptr->ib_trans.list))
			next_cr = dapl_llist_peek_head(&hca_ptr->ib_trans.list);
		else
			next_cr = NULL;

		while (next_cr) {
			cr = next_cr;
			next_cr = dapl_llist_next_entry(&hca_ptr->ib_trans.list,
							(DAPL_LLIST_ENTRY *) 
							&cr->local_entry);
			dapls_cm_acquire(cr); /* hold thread ref */
			dapl_os_lock(&cr->lock);
			if (cr->state == DCM_FREE || 
			    hca_ptr->ib_trans.cr_state != IB_THREAD_RUN) {
				dapl_log(DAPL_DBG_TYPE_CM, 
					 " CM FREE: %p ep=%p st=%s sck=%d refs=%d\n", 
					 cr, cr->ep, dapl_cm_state_str(cr->state), 
					 cr->socket, cr->ref_count);

				if (cr->socket != DAPL_INVALID_SOCKET) {
					shutdown(cr->socket, SHUT_RDWR);
					closesocket(cr->socket);
					cr->socket = DAPL_INVALID_SOCKET;
				}
				dapl_os_unlock(&cr->lock);
				dapls_cm_release(cr); /* release alloc ref */
				dapli_cm_dequeue(cr); /* release workq ref */
				dapls_cm_release(cr); /* release thread ref */
				continue;
			}

			event = (cr->state == DCM_CONN_PENDING) ?
					DAPL_FD_WRITE : DAPL_FD_READ;

			if (dapl_fd_set(cr->socket, set, event)) {
				dapl_log(DAPL_DBG_TYPE_ERR,
					 " cr_thread: fd_set ERR st=%d fd %d"
					 " -> %s\n", cr->state, cr->socket,
					 inet_ntoa(((struct sockaddr_in *)
						&cr->msg.daddr.so)->sin_addr));
				dapl_os_unlock(&cr->lock);
				dapls_cm_release(cr); /* release ref */
				continue;
			}
			dapl_os_unlock(&cr->lock);
			dapl_os_unlock(&hca_ptr->ib_trans.lock);
			
			ret = dapl_poll(cr->socket, event);

			dapl_dbg_log(DAPL_DBG_TYPE_THREAD,
				     " poll ret=0x%x %s sck=%d\n",
				     ret, dapl_cm_state_str(cr->state), 
				     cr->socket);

			/* data on listen, qp exchange, and on disc req */
			dapl_os_lock(&cr->lock);
			if ((ret == DAPL_FD_READ) || 
			    (cr->state != DCM_CONN_PENDING && ret == DAPL_FD_ERROR)) {
				if (cr->socket != DAPL_INVALID_SOCKET) {
					switch (cr->state) {
					case DCM_LISTEN:
						dapl_os_unlock(&cr->lock);
						dapli_socket_accept(cr);
                                                break;
					case DCM_ACCEPTING:
						dapl_os_unlock(&cr->lock);
						dapli_socket_accept_data(cr);
						break;
					case DCM_ACCEPTED:
						dapl_os_unlock(&cr->lock);
						dapli_socket_accept_rtu(cr);
						break;
					case DCM_REP_PENDING:
						dapl_os_unlock(&cr->lock);
						dapli_socket_connect_rtu(cr);
						break;
					case DCM_CONNECTED:
						dapl_os_unlock(&cr->lock);
						DAPL_CNTR(((DAPL_IA *)dapl_llist_peek_head(&cr->hca->ia_list_head)),
							    DCNT_IA_CM_DREQ_RX);
						dapli_socket_disconnect(cr);
						break;
					case DCM_DISCONNECTED:
						cr->state = DCM_FREE;
						dapl_os_unlock(&cr->lock);
						break;
					default:
						if (ret == DAPL_FD_ERROR)
							cr->state = DCM_FREE;
						dapl_os_unlock(&cr->lock);
						break;
					}
				} else 
					dapl_os_unlock(&cr->lock);

			/* ASYNC connections, writable, readable, error; check status */
			} else if (ret == DAPL_FD_WRITE ||
				   (cr->state == DCM_CONN_PENDING && 
				    ret == DAPL_FD_ERROR)) {
				
				opt = 0;
				opt_len = sizeof(opt);
				ret = getsockopt(cr->socket, SOL_SOCKET,
						 SO_ERROR, (char *)&opt,
						 &opt_len);
				dapl_os_unlock(&cr->lock);
				if (!ret && !opt)
					dapli_socket_connected(cr, opt);
				else
					dapli_socket_connected(cr, opt ? opt : dapl_socket_errno());
			} else 
				dapl_os_unlock(&cr->lock);

			dapls_cm_release(cr); /* release ref */
			dapl_os_lock(&hca_ptr->ib_trans.lock);
		}

		/* set to exit and all resources destroyed */
		if ((hca_ptr->ib_trans.cr_state != IB_THREAD_RUN) &&
		    (dapl_llist_is_empty(&hca_ptr->ib_trans.list)))
			break;

		dapl_os_unlock(&hca_ptr->ib_trans.lock);
		dapl_select(set);

		/* if pipe used to wakeup, consume */
		while (dapl_poll(hca_ptr->ib_trans.scm[0], 
				 DAPL_FD_READ) == DAPL_FD_READ) {
			if (recv(hca_ptr->ib_trans.scm[0], rbuf, 2, 0) == -1)
				dapl_log(DAPL_DBG_TYPE_THREAD,
					 " cr_thread: read pipe error = %s\n",
					 strerror(errno));
		}
		dapl_os_lock(&hca_ptr->ib_trans.lock);
		
		/* set to exit and all resources destroyed */
		if ((hca_ptr->ib_trans.cr_state != IB_THREAD_RUN) &&
		    (dapl_llist_is_empty(&hca_ptr->ib_trans.list)))
			break;
	}

	dapl_os_unlock(&hca_ptr->ib_trans.lock);
	dapl_os_free(set, sizeof(struct dapl_fd_set));
out:
	hca_ptr->ib_trans.cr_state = IB_THREAD_EXIT;
	dapl_dbg_log(DAPL_DBG_TYPE_THREAD, " cr_thread(hca %p) exit\n", hca_ptr);
}


#ifdef DAPL_COUNTERS
/* Debug aid: List all Connections in process and state */
void dapls_print_cm_list(IN DAPL_IA *ia_ptr)
{
	/* Print in process CR's for this IA, if debug type set */
	int i = 0;
	dp_ib_cm_handle_t cr, next_cr;

	dapl_os_lock(&ia_ptr->hca_ptr->ib_trans.lock);
	if (!dapl_llist_is_empty((DAPL_LLIST_HEAD*)
				 &ia_ptr->hca_ptr->ib_trans.list))
				 next_cr = dapl_llist_peek_head((DAPL_LLIST_HEAD*)
				 &ia_ptr->hca_ptr->ib_trans.list);
 	else
		next_cr = NULL;

        printf("\n DAPL IA CONNECTIONS IN PROCESS:\n");
	while (next_cr) {
		cr = next_cr;
		next_cr = dapl_llist_next_entry((DAPL_LLIST_HEAD*)
				 &ia_ptr->hca_ptr->ib_trans.list,
				(DAPL_LLIST_ENTRY*)&cr->local_entry);

		printf( "  CONN[%d]: sp %p ep %p sock %d %s %s %s %s %s %s "
			" PORT L-%x R-%x \n",
			i, cr->sp, cr->ep, cr->socket,
			cr->msg.saddr.ib.qp_type == IBV_QPT_RC ? "RC" : "UD",
			dapl_cm_state_str(cr->state), dapl_cm_op_str(ntohs(cr->msg.op)),
			ntohs(cr->msg.op) == DCM_REQ ? /* local address */
				inet_ntoa(((struct sockaddr_in *)&cr->msg.daddr.so)->sin_addr) :
				inet_ntoa(((struct sockaddr_in *)&cr->addr)->sin_addr),
			cr->sp ? "<-" : "->",
                       	ntohs(cr->msg.op) == DCM_REQ ? /* remote address */
				inet_ntoa(((struct sockaddr_in *)&cr->addr)->sin_addr) :
				inet_ntoa(((struct sockaddr_in *)&cr->msg.daddr.so)->sin_addr),

			ntohs(cr->msg.op) == DCM_REQ ? /* local port */
				ntohs(((struct sockaddr_in *)&cr->msg.daddr.so)->sin_port) :
				ntohs(((struct sockaddr_in *)&cr->addr)->sin_port),

			ntohs(cr->msg.op) == DCM_REQ ? /* remote port */
				ntohs(((struct sockaddr_in *)&cr->addr)->sin_port) :
				ntohs(((struct sockaddr_in *)&cr->msg.daddr.so)->sin_port) );
		i++;
	}
	printf("\n");
	dapl_os_unlock(&ia_ptr->hca_ptr->ib_trans.lock);
}
#endif

