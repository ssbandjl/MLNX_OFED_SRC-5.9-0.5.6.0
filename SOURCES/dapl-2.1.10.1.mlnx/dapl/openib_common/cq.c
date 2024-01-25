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
#include "openib_osd.h"
#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_lmr_util.h"
#include "dapl_evd_util.h"
#include "dapl_ring_buffer_util.h"

/*
 * Map all verbs DTO completion codes to the DAT equivelent.
 *
 * Not returned by verbs: DAT_DTO_ERR_PARTIAL_PACKET
 */
static struct ib_status_map {
	int ib_status;
	DAT_DTO_COMPLETION_STATUS dat_status;
} ib_status_map[] = {
/* 00 */  {IBV_WC_SUCCESS, DAT_DTO_SUCCESS},
/* 01 */  {IBV_WC_LOC_LEN_ERR, DAT_DTO_ERR_LOCAL_LENGTH},
/* 02 */  {IBV_WC_LOC_QP_OP_ERR, DAT_DTO_ERR_LOCAL_EP},
/* 03 */  {IBV_WC_LOC_EEC_OP_ERR, DAT_DTO_ERR_TRANSPORT},
/* 04 */  {IBV_WC_LOC_PROT_ERR, DAT_DTO_ERR_LOCAL_PROTECTION},
/* 05 */  {IBV_WC_WR_FLUSH_ERR, DAT_DTO_ERR_FLUSHED},
/* 06 */  {IBV_WC_MW_BIND_ERR, DAT_RMR_OPERATION_FAILED},
/* 07 */  {IBV_WC_BAD_RESP_ERR, DAT_DTO_ERR_BAD_RESPONSE},
/* 08 */  {IBV_WC_LOC_ACCESS_ERR, DAT_DTO_ERR_LOCAL_PROTECTION},
/* 09 */  {IBV_WC_REM_INV_REQ_ERR, DAT_DTO_ERR_REMOTE_RESPONDER},
/* 10 */  {IBV_WC_REM_ACCESS_ERR, DAT_DTO_ERR_REMOTE_ACCESS},
/* 11 */  {IBV_WC_REM_OP_ERR, DAT_DTO_ERR_REMOTE_RESPONDER},
/* 12 */  {IBV_WC_RETRY_EXC_ERR, DAT_DTO_ERR_TRANSPORT},
/* 13 */  {IBV_WC_RNR_RETRY_EXC_ERR, DAT_DTO_ERR_RECEIVER_NOT_READY},
/* 14 */  {IBV_WC_LOC_RDD_VIOL_ERR, DAT_DTO_ERR_LOCAL_PROTECTION},
/* 15 */  {IBV_WC_REM_INV_RD_REQ_ERR, DAT_DTO_ERR_REMOTE_RESPONDER},
/* 16 */  {IBV_WC_REM_ABORT_ERR, DAT_DTO_ERR_REMOTE_RESPONDER},
/* 17 */  {IBV_WC_INV_EECN_ERR, DAT_DTO_ERR_TRANSPORT},
/* 18 */  {IBV_WC_INV_EEC_STATE_ERR, DAT_DTO_ERR_TRANSPORT},
/* 19 */  {IBV_WC_FATAL_ERR, DAT_DTO_ERR_TRANSPORT},
/* 20 */  {IBV_WC_RESP_TIMEOUT_ERR, DAT_DTO_ERR_RECEIVER_NOT_READY},
/* 21 */  {IBV_WC_GENERAL_ERR, DAT_DTO_ERR_TRANSPORT},
};

/*
 * dapls_ib_get_dto_status
 *
 * Return the DAT status of a DTO operation
 *
 * Input:
 *	cqe_ptr		pointer to completion queue entry
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	Value from ib_status_map table above
 */

DAT_DTO_COMPLETION_STATUS
dapls_ib_get_dto_status(IN ib_work_completion_t * cqe_ptr)
{
	uint32_t ib_status;
	int i;

	ib_status = DAPL_GET_CQE_STATUS(cqe_ptr);

	/*
	 * Due to the implementation of verbs completion code, we need to
	 * search the table for the correct value rather than assuming
	 * linear distribution.
	 */
	for (i = 0; i <= IBV_WC_GENERAL_ERR; i++) {
		if (ib_status == ib_status_map[i].ib_status) {
			if (ib_status != IBV_WC_SUCCESS) {
				dapl_log(DAPL_DBG_TYPE_DTO_COMP_ERR,
					 " DTO completion ERROR: %d:"
					 " op %#x\n",
					 ib_status,
					 DAPL_GET_CQE_OPTYPE(cqe_ptr));
			}
			return ib_status_map[i].dat_status;
		}
	}

	return DAT_DTO_FAILURE;
}

DAT_RETURN dapls_ib_get_async_event(IN ib_error_record_t * err_record,
				    OUT DAT_EVENT_NUMBER * async_event)
{
	DAT_RETURN dat_status = DAT_SUCCESS;
	int err_code = err_record->event_type;

	dapl_log(DAPL_DBG_TYPE_EXCEPTION, " %s %s\n", __FUNCTION__,
				dapl_ib_async_str(err_code));

	switch (err_code)
	{
		/* OVERFLOW error */
		case IBV_EVENT_CQ_ERR:
			*async_event = DAT_ASYNC_ERROR_EVD_OVERFLOW;
			break;

		/* INTERNAL errors */
		case IBV_EVENT_DEVICE_FATAL:
		case IBV_EVENT_PORT_ERR:
		case IBV_EVENT_LID_CHANGE:
		case IBV_EVENT_PKEY_CHANGE:
		case IBV_EVENT_SM_CHANGE:
		/* CATASTROPHIC errors */
			*async_event = DAT_ASYNC_ERROR_IA_CATASTROPHIC;
			break;

		/* BROKEN QP error */
		case IBV_EVENT_SQ_DRAINED:
		case IBV_EVENT_QP_FATAL:
		case IBV_EVENT_QP_REQ_ERR:
		case IBV_EVENT_QP_ACCESS_ERR:
		case IBV_EVENT_SRQ_ERR:
		case IBV_EVENT_SRQ_LIMIT_REACHED:
		case IBV_EVENT_QP_LAST_WQE_REACHED:
			*async_event = DAT_ASYNC_ERROR_EP_BROKEN;
			break;

		/* connection completion */
		case IBV_EVENT_COMM_EST:
			*async_event = DAT_CONNECTION_EVENT_ESTABLISHED;
			break;

		/* non-catastrophic events */
		case IBV_EVENT_PATH_MIG:
		case IBV_EVENT_PATH_MIG_ERR:
		case IBV_EVENT_PORT_ACTIVE:
		case IBV_EVENT_CLIENT_REREGISTER:
			break;

		default:
			dat_status = DAT_ERROR(DAT_NOT_IMPLEMENTED, 0);
	}
	return dat_status;
}

/*
 * dapl_ib_cq_alloc
 *
 * Alloc a CQ
 *
 * Input:
 *	ia_handle		IA handle
 *	evd_ptr			pointer to EVD struct
 *	cqlen			minimum QLen
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_cq_alloc(IN DAPL_IA * ia_ptr,
		  IN DAPL_EVD * evd_ptr, IN DAT_COUNT * cqlen)
{
	struct ibv_comp_channel *channel = NULL;
	int opts, ret = ENOMEM;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		     "dapls_ib_cq_alloc: evd %p cqlen=%d \n", evd_ptr, *cqlen);

	/* create CQ object */
	evd_ptr->ib_cq_handle = dapl_os_alloc(sizeof(struct dcm_ib_cq));
	if (!evd_ptr->ib_cq_handle)
		goto err;

	dapl_os_memzero(evd_ptr->ib_cq_handle, sizeof(struct dcm_ib_cq));
	evd_ptr->ib_cq_handle->tp = &ia_ptr->hca_ptr->ib_trans;
	evd_ptr->ib_cq_handle->evd = evd_ptr;

#ifdef _OPENIB_MCM_
	/* shadow support for TX, MPXYD */
	if (ia_ptr->hca_ptr->ib_trans.scif_ep) {
		ret = dapli_mix_cq_create(evd_ptr->ib_cq_handle, *cqlen);
		if (ret)
			goto err;

		/* cross-socket: shadow both RX and TX, no IB CQ on MIC */
		if (MXF_EP(&ia_ptr->hca_ptr->ib_trans.addr))
			return DAT_SUCCESS;
	}
	dapl_llist_init_entry(&evd_ptr->ib_cq_handle->entry);
#endif
	if (!evd_ptr->cno_ptr)
		channel = ibv_create_comp_channel(ia_ptr->hca_ptr->ib_hca_handle);
	else
		channel = ia_ptr->hca_ptr->ib_trans.ib_cq;

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
	evd_ptr->ib_cq_handle->cq =
		ibv_create_cq(ia_ptr->hca_ptr->ib_hca_handle,
			      *cqlen, evd_ptr, channel, 0);

	if (!evd_ptr->ib_cq_handle->cq)
		goto err;

	/* arm cq for events */
	dapls_set_cq_notify(ia_ptr, evd_ptr);

	/* update with returned cq entry size */
	*cqlen = evd_ptr->ib_cq_handle->cq->cqe;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		     "dapls_ib_cq_alloc: new_cq %p cqlen=%d \n",
		     evd_ptr->ib_cq_handle, *cqlen);

	return DAT_SUCCESS;

err:
	dapl_log(DAPL_DBG_TYPE_ERR,
		 "ib_cq_alloc ERR (%d): new_cq %p cqlen=%d ret %d %s\n",
		 evd_ptr->ib_cq_handle, *cqlen, ret, strerror(errno));

	if (evd_ptr->ib_cq_handle)
		dapl_os_free(evd_ptr->ib_cq_handle, sizeof(struct dcm_ib_cq));

	if (!evd_ptr->cno_ptr && channel)
		ibv_destroy_comp_channel(channel);

	return dapl_convert_errno(ret, "cq_allocate" );
}

/*
 * dapls_ib_cq_free
 *
 * destroy a CQ
 *
 * Input:
 *	ia_handle		IA handle
 *	evd_ptr			pointer to EVD struct
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN dapls_ib_cq_free(IN DAPL_IA * ia_ptr, IN DAPL_EVD * evd_ptr)
{
	DAT_EVENT event;
	ib_work_completion_t wc;
	struct ibv_comp_channel *channel;

	if (evd_ptr->ib_cq_handle != IB_INVALID_HANDLE) {

#ifdef _OPENIB_MCM_
		/* remove from device PI processing list  */
		dapl_os_lock(&ia_ptr->hca_ptr->ib_trans.cqlock);
		if (evd_ptr->ib_cq_handle->entry.list_head)
			dapl_llist_remove_entry(&ia_ptr->hca_ptr->ib_trans.cqlist,
					    	&evd_ptr->ib_cq_handle->entry);
		dapl_os_unlock(&ia_ptr->hca_ptr->ib_trans.cqlock);

		/* shadow support, MPXYD */
		if (ia_ptr->hca_ptr->ib_trans.scif_ep) {
			dapli_mix_cq_free(evd_ptr->ib_cq_handle);
			if (!evd_ptr->ib_cq_handle->cq) {
				dapl_os_free(evd_ptr->ib_cq_handle,
					     sizeof(struct dcm_ib_cq));
				evd_ptr->ib_cq_handle = IB_INVALID_HANDLE;
				return DAT_SUCCESS;
			}
		}
#endif
		/* pull off CQ and EVD entries and toss */
		while (ibv_poll_cq(evd_ptr->ib_cq_handle->cq, 1, &wc) == 1) ;
		while (dapl_evd_dequeue(evd_ptr, &event) == DAT_SUCCESS) ;

		channel = evd_ptr->ib_cq_handle->cq->channel;
		if (ibv_destroy_cq(evd_ptr->ib_cq_handle->cq))
			return (dapl_convert_errno(errno, "ibv_destroy_cq"));
		if (!evd_ptr->cno_ptr)
			ibv_destroy_comp_channel(channel);

		dapl_os_free(evd_ptr->ib_cq_handle, sizeof(struct dcm_ib_cq));
		evd_ptr->ib_cq_handle = IB_INVALID_HANDLE;
	}
	return DAT_SUCCESS;
}

DAT_RETURN
dapls_evd_dto_wakeup(IN DAPL_EVD * evd_ptr)
{
	dapl_log(DAPL_DBG_TYPE_EVD, " cq_object_wakeup: EVD %p CQ %p\n",
		 evd_ptr, evd_ptr->ib_cq_handle);

	/*  EVD with CNO; waiting on OS wait object */
	if (evd_ptr->cno_ptr) {
		dapl_os_wait_object_wakeup(&evd_ptr->wait_object);
		return DAT_SUCCESS;
	}

#ifdef _OPENIB_MCM_
{
	int flags = evd_ptr->ib_cq_handle->flags;
	if (((flags & DCM_CQ_TX) && (flags & DCM_CQ_TX_INDIRECT)) ||
	    ((flags & DCM_CQ_RX) && (flags & DCM_CQ_RX_INDIRECT)))
		dapl_os_wait_object_wakeup(&evd_ptr->wait_object);
}
#endif
	/* otherwise, no wake up mechanism */
	return DAT_SUCCESS;
}

#if defined(_WIN32)
static int
dapls_wait_comp_channel(IN struct ibv_comp_channel *channel, IN uint32_t timeout)
{
	channel->comp_channel.Milliseconds =
		(timeout == DAT_TIMEOUT_INFINITE) ? INFINITE : timeout / 1000;
	return 0;
}

#else // WIN32

static int
dapls_wait_comp_channel(IN struct ibv_comp_channel *channel, IN uint32_t timeout)
{
	int status, timeout_ms;
	struct pollfd cq_fd = {
		.fd = channel->fd,
		.events = POLLIN,
		.revents = 0
	};

	/* uDAPL timeout values in usecs */
	timeout_ms = (timeout == DAT_TIMEOUT_INFINITE) ? -1 : timeout / 1000;
	status = poll(&cq_fd, 1, timeout_ms);
	if (status > 0)
		return 0;
	else if (status == 0)
		return ETIMEDOUT;
	else
		return errno;
}
#endif

DAT_RETURN
dapls_evd_dto_wait(IN DAPL_EVD * evd_ptr, IN uint32_t timeout)
{
	struct ibv_comp_channel *channel;
	struct ibv_cq *ibv_cq = NULL;
	void *context;
	int status;

	dapl_log(DAPL_DBG_TYPE_EVD,
		 " cq_object_wait: EVD %p CQ %p time %d\n",
		 evd_ptr, evd_ptr->ib_cq_handle, timeout);

#ifdef _OPENIB_MCM_
{
	int flags = evd_ptr->ib_cq_handle->flags;
	if (((flags & DCM_CQ_TX) && (flags & DCM_CQ_TX_INDIRECT)) ||
	    ((flags & DCM_CQ_RX) && (flags & DCM_CQ_RX_INDIRECT))) {
		return (dapl_os_wait_object_wait(&evd_ptr->wait_object, timeout));
	}
}
#endif

	channel = evd_ptr->ib_cq_handle->cq->channel;
	status = dapls_wait_comp_channel(channel, timeout);
	if (!status) {
		if (!ibv_get_cq_event(channel, &ibv_cq, &context)) {
			ibv_ack_cq_events(ibv_cq, 1);
		}
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		     " cq_object_wait: RET evd %p ibv_cq %p %s\n",
		     evd_ptr, ibv_cq, strerror(status));

	return dapl_convert_errno(status, "cq_wait_object_wait");
}

void dapli_cq_event_cb(struct _ib_hca_transport *tp)
{
	/* check all comp events on this device */
	struct dapl_evd *evd = NULL;
	struct ibv_cq   *ibv_cq = NULL;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL," dapli_cq_event_cb(%p)\n", tp);

	while (!ibv_get_cq_event(tp->ib_cq, &ibv_cq, (void*)&evd)) {

		if (!DAPL_BAD_HANDLE(evd, DAPL_MAGIC_EVD)) {
			/* Both EVD or EVD->CNO event via callback */
			dapl_evd_dto_callback(tp->ib_ctx, 
					      evd->ib_cq_handle, (void*)evd);
		}
		ibv_ack_cq_events(ibv_cq, 1);
	} 
}

/*
 * dapl_ib_cq_resize
 *
 * Alloc a CQ
 *
 * Input:
 *	ia_handle		IA handle
 *	evd_ptr			pointer to EVD struct
 *	cqlen			minimum QLen
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_cq_resize(IN DAPL_IA * ia_ptr,
		   IN DAPL_EVD * evd_ptr, IN DAT_COUNT * cqlen)
{
	ib_cq_handle_t old_cq, new_cq;
	DAT_RETURN ret;

	old_cq = evd_ptr->ib_cq_handle;
	ret = dapls_ib_cq_alloc(ia_ptr, evd_ptr, cqlen);
	if (ret)
		goto err;

	new_cq = evd_ptr->ib_cq_handle;
	evd_ptr->ib_cq_handle = old_cq;
	dapls_ib_cq_free(ia_ptr, evd_ptr);
	evd_ptr->ib_cq_handle = new_cq;
	return DAT_SUCCESS;

err:
	evd_ptr->ib_cq_handle = old_cq;
	return ret;
}

/*
 * dapls_set_cq_notify
 *
 * Set the CQ notification for next
 *
 * Input:
 *	hca_handl		hca handle
 *	DAPL_EVD		evd handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	dapl_convert_errno 
 */
DAT_RETURN dapls_set_cq_notify(IN DAPL_IA * ia_ptr, IN DAPL_EVD * evd_ptr)
{
	if (evd_ptr->ib_cq_handle->cq &&
	    ibv_req_notify_cq(evd_ptr->ib_cq_handle->cq, 0))
		return (dapl_convert_errno(errno, "notify_cq"));
	else
		return DAT_SUCCESS;
}

/*
 * dapls_ib_completion_notify
 *
 * Set the CQ notification type
 *
 * Input:
 *	hca_handl		hca handle
 *	evd_ptr			evd handle
 *	type			notification type
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	dapl_convert_errno
 */
DAT_RETURN dapls_ib_completion_notify(IN ib_hca_handle_t hca_handle,
				      IN DAPL_EVD * evd_ptr,
				      IN ib_notification_type_t type)
{
	if (evd_ptr->ib_cq_handle->cq &&
	    ibv_req_notify_cq(evd_ptr->ib_cq_handle->cq, type))
		return (dapl_convert_errno(errno, "notify_cq_type"));
	else
		return DAT_SUCCESS;
}

/*
 * dapls_ib_completion_poll
 *
 * CQ poll for completions
 *
 * Input:
 *	hca_handl		hca handle
 *	evd_ptr			evd handle
 *	wc_ptr			work completion
 *
 * Output:
 * 	none
 *
 * Returns: 
 * 	DAT_SUCCESS
 *	DAT_QUEUE_EMPTY
 *	
 */
DAT_RETURN dapls_ib_completion_poll(IN DAPL_HCA * hca_ptr,
				    IN DAPL_EVD * evd_ptr,
				    IN ib_work_completion_t * wc_ptr)
{
	int ret;

#ifdef _OPENIB_MCM_
	if (!evd_ptr->ib_cq_handle->cq) /* proxy service, no direct CQ */
		return DAT_QUEUE_EMPTY;
#endif
	ret = ibv_poll_cq(evd_ptr->ib_cq_handle->cq, 1, wc_ptr);

#ifdef DAT_EXTENSIONS
	if (ret==1) {
		DAPL_COOKIE *cookie = (DAPL_COOKIE *)(uintptr_t) DAPL_GET_CQE_WRID(wc_ptr);
		dapl_os_assert((NULL != cookie));

		/* some rNICs don't set wc_flags correctly for immed data */
		if (cookie->val.dto.type == DAPL_DTO_TYPE_EXTENSION_IMM)
			wc_ptr->wc_flags |= IBV_WC_WITH_IMM;
	}
#endif

#ifdef _OPENIB_MCM_
	/*
	 * HST->MXS, we need to intercept direct TX WC in flight
	 * because there is no way to know if indirect or direct CQ
	 * service is needed at the time of QP creation.
	 */
	if (ret==1) {
		DAPL_EP *ep_ptr;
		DAPL_COOKIE *cookie = (DAPL_COOKIE *)(uintptr_t) DAPL_GET_CQE_WRID(wc_ptr);

		dapl_os_assert((NULL != cookie));
		ep_ptr = cookie->ep;
		dapl_os_assert((NULL != ep_ptr));
		if ((!ep_ptr->qp_handle->tp->scif_ep) &&
		    (MXF_EP(ep_ptr->qp_handle)) &&
		    ((DAPL_GET_CQE_OPTYPE(wc_ptr) == OP_RDMA_WRITE_IMM) ||
		     (DAPL_GET_CQE_OPTYPE(wc_ptr) == OP_RDMA_WRITE))) {
			dapl_log(DAPL_DBG_TYPE_EP,
				 " cq_dto_event: MCM RW_pi: evd %p ep %p st %d op %s ln %d wr_id %p\n",
				 evd_ptr, ep_ptr,
				 DAPL_GET_CQE_STATUS(wc_ptr),
				 DAPL_GET_CQE_OP_STR(wc_ptr),
				 cookie->val.dto.size, cookie);
			ret = 0; /* WR RW_imm to PI, WC pending from PI */
		} else {
			dapl_log(DAPL_DBG_TYPE_EP,
				 " cq_dto_event: MCM RW_direct: evd %p ep %p st %d op %s ln %d wr_id %p\n",
				 evd_ptr, ep_ptr,
				 DAPL_GET_CQE_STATUS(wc_ptr),
				 DAPL_GET_CQE_OP_STR(wc_ptr),
				 cookie->val.dto.size, cookie);
		}
	}
#endif
	if (ret == 1)
		return DAT_SUCCESS;

	return DAT_QUEUE_EMPTY;
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
