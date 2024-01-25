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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_ep_util.h"
#include <infiniband/sa.h>
#include <rdma/rdma_cma.h>

/*
 * dapl_ib_qp_alloc
 *
 * Alloc a QP
 *
 * Input:
 *	*ep_ptr		pointer to EP INFO
 *	ib_hca_handle	provider HCA handle
 *	ib_pd_handle	provider protection domain handle
 *	cq_recv		provider recv CQ handle
 *	cq_send		provider send CQ handle
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
dapls_ib_qp_alloc(IN DAPL_IA * ia_ptr,
		  IN DAPL_EP * ep_ptr, IN DAPL_EP * ep_ctx_ptr)
{
	DAT_EP_ATTR *attr;
	DAPL_EVD *rcv_evd, *req_evd;
	DAPL_SRQ *dapl_srq = (DAPL_SRQ *)ep_ptr->param.srq_handle;
	ib_cq_handle_t rcv_cq, req_cq;
	ib_pd_handle_t ib_pd_handle;
	ib_srq_handle_t ib_srq_handle = NULL;
	int ret = EINVAL;
	int max_inline = ia_ptr->hca_ptr->ib_trans.ib_cm.max_inline;
	struct ibv_qp_init_attr qp_create;
#ifdef _OPENIB_CMA_
	dp_ib_cm_handle_t conn;
#endif

	attr = &ep_ptr->param.ep_attr;
	ib_pd_handle = ((DAPL_PZ *) ep_ptr->param.pz_handle)->pd_handle;
	if (dapl_srq)
		ib_srq_handle = dapl_srq->srq_handle;
	rcv_evd = (DAPL_EVD *) ep_ptr->param.recv_evd_handle;
	req_evd = (DAPL_EVD *) ep_ptr->param.request_evd_handle;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " qp_alloc: ia %p ep %p ctx %p: SQ %d,%d evd %p - RQ %d,%d evd %p\n",
		     ia_ptr, ep_ptr, ep_ctx_ptr,
		     attr->max_request_dtos, attr->max_request_iov, req_evd,
		     attr->max_recv_dtos, attr->max_recv_iov, rcv_evd);

	/* 
	 * DAT allows usage model of EP's with no EVD's but IB does not. 
	 * Create a CQ with zero entries under the covers to support and 
	 * catch any invalid posting. 
	 */
	if ((!rcv_evd || !req_evd) && !ia_ptr->hca_ptr->ib_trans.ib_cq_empty) {
		struct ibv_comp_channel *channel;

		channel = ibv_create_comp_channel(ia_ptr->hca_ptr->ib_hca_handle);
		if (!channel)
			return (dapl_convert_errno(ENOMEM, "QP create_cq_chan"));
		  
		/* Call IB verbs to create CQ */
		rcv_cq = dapl_os_alloc(sizeof(struct dcm_ib_cq));
		if (!rcv_cq)
			return (dapl_convert_errno(ENOMEM, "QP  alloc cq"));

		dapl_os_memzero(rcv_cq, sizeof(struct dcm_ib_cq));

		rcv_cq->cq = ibv_create_cq(ia_ptr->hca_ptr->ib_hca_handle,
				       	       1, NULL, channel, 0);

		if (!rcv_cq->cq) {
			ibv_destroy_comp_channel(channel);
			return (dapl_convert_errno(ENOMEM, "QP create_cq"));
		}
		ia_ptr->hca_ptr->ib_trans.ib_cq_empty = rcv_cq;
	}

	if (rcv_evd)
		rcv_cq = rcv_evd->ib_cq_handle;
	else
		rcv_cq = ia_ptr->hca_ptr->ib_trans.ib_cq_empty;

	if (req_evd)
		req_cq = req_evd->ib_cq_handle;
	else
		req_cq = ia_ptr->hca_ptr->ib_trans.ib_cq_empty;

	/* create QP object */
	ep_ptr->qp_handle = dapl_os_alloc(sizeof(struct dcm_ib_qp));
	if (!ep_ptr->qp_handle)
		return (dapl_convert_errno(errno, "create_qp"));

	dapl_os_memzero(ep_ptr->qp_handle, sizeof(struct dcm_ib_qp));
	ep_ptr->qp_handle->tp = &ia_ptr->hca_ptr->ib_trans;
	ep_ptr->qp_handle->ep = ep_ptr;

	/* 
	 * IMPLEMENTATION NOTE:
	 * uDAPL allows consumers to post buffers on the EP after creation
	 * and before a connect request (outbound and inbound). This forces
	 * a binding to a device during the hca_open call and requires the
	 * consumer to predetermine which device to listen on or connect from.
	 * This restriction eliminates any option of listening or connecting 
	 * over multiple devices. uDAPL should add API's to resolve addresses 
	 * and bind to the device at the approriate time (before connect 
	 * and after CR arrives). Discovery should happen at connection time 
	 * based on addressing and not on static configuration during open.
	 */

#ifdef _OPENIB_CMA_
	/* Allocate CM and initialize lock */
	if ((conn = dapls_ib_cm_create(ep_ptr)) == NULL) {
		ret = ENOMEM;
		goto err;
	}
	/* open identifies the local device; per DAT specification */
	if (rdma_bind_addr(conn->cm_id,
		(struct sockaddr *)&ia_ptr->hca_ptr->hca_address)) {
		dapls_cm_free(conn);
		ret = EAFNOSUPPORT;
		goto err;
	}
#endif
	/* Setup attributes and create qp */
	dapl_os_memzero((void *)&qp_create, sizeof(qp_create));
	qp_create.recv_cq = rcv_cq->cq;
	qp_create.cap.max_recv_wr = rcv_evd ? attr->max_recv_dtos:0;
	qp_create.cap.max_recv_sge = rcv_evd ? attr->max_recv_iov:0;
	qp_create.send_cq = req_cq->cq;
	qp_create.cap.max_send_wr = req_evd ? attr->max_request_dtos:0;
	qp_create.cap.max_send_sge = req_evd ? attr->max_request_iov:0;
	qp_create.cap.max_inline_data = max_inline;
	qp_create.qp_type = IBV_QPT_RC;
	qp_create.qp_context = (void *)ep_ptr;
	qp_create.srq = ib_srq_handle;

#ifdef DAT_EXTENSIONS 
	if ((int)attr->service_type == (int)DAT_IB_SERVICE_TYPE_UD) {
#ifdef _OPENIB_CMA_
		goto err;
#endif
		qp_create.qp_type = IBV_QPT_UD;
		if (attr->max_message_size >
		    (128 << ia_ptr->hca_ptr->ib_trans.ib_cm.mtu)) {
			goto err;
		}
		ep_ptr->qp_handle->ah =
			(ib_ah_handle_t*) dapl_os_alloc(sizeof(ib_ah_handle_t) * DCM_AH_SPACE);

		if (!ep_ptr->qp_handle->ah)
			goto err;

		dapl_os_memzero(ep_ptr->qp_handle->ah, sizeof(ib_ah_handle_t) * DCM_AH_SPACE);
	}
#endif

#ifdef _OPENIB_CMA_
	if (rdma_create_qp(conn->cm_id, ib_pd_handle, &qp_create)) {
		dapls_cm_free(conn);
		ret = errno;
		goto err;
	}
	ep_ptr->qp_handle->qp = conn->cm_id->qp;
	ep_ptr->qp_state = IBV_QPS_INIT;

	ep_ptr->param.local_port_qual = rdma_get_src_port(conn->cm_id);
#else

#ifdef _OPENIB_MCM_
	if (dapl_os_lock_init(&ep_ptr->qp_handle->lock))
		goto err;

	/* mark type of CQ, ref to QP */
	req_cq->flags |= DCM_CQ_TX;
	rcv_cq->flags |= DCM_CQ_RX;

	/* save resources, 1st QP is receiver, 2nd is sender */
	if (ia_ptr->hca_ptr->ib_trans.scif_ep) {
		qp_create.cap.max_inline_data = 0;
		qp_create.cap.max_send_wr = 1;
		qp_create.cap.max_send_sge = 1;
	}

	/* Don't create any QP if MIC xsocket, QPt and QPr both on MPXYD */
	if (!ia_ptr->hca_ptr->ib_trans.scif_ep ||
	    (ia_ptr->hca_ptr->ib_trans.scif_ep &&
	    !MXF_EP(&ia_ptr->hca_ptr->ib_trans.addr))) {
		/* QP1 needed for RX only, set QP1 req_cq empty */
		qp_create.send_cq = ia_ptr->hca_ptr->ib_trans.ib_cq_empty->cq;
	} else {
		goto skip_qp;
	}
#endif
	ep_ptr->qp_handle->qp =	ibv_create_qp(ib_pd_handle, &qp_create);
	if (!ep_ptr->qp_handle->qp) {
		dapl_log(1," qp_alloc ERR %d %s on device %s\n",
			   errno, strerror(errno),
			   ibv_get_device_name(ia_ptr->hca_ptr->ib_trans.ib_dev));
		dapl_log(1," qp_attr: SQ %d,%d cq %p RQ %d,%d cq %p SRQ %p [inl %d typ %d]\n",
			    qp_create.cap.max_send_wr, qp_create.cap.max_send_sge,
			    req_cq, qp_create.cap.max_recv_wr,
			    qp_create.cap.max_recv_sge, rcv_cq,
			    qp_create.srq, qp_create.cap.max_inline_data,
			    qp_create.qp_type);
		ret = errno;
		goto err;
	}
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " QP_ALLOC: QPr %p-0x%x SQ %d,%d cq %p, RQ %d,%d cq %p\n",
		     ep_ptr->qp_handle->qp, ep_ptr->qp_handle->qp->qp_num,
		     qp_create.cap.max_send_wr, qp_create.cap.max_send_sge,
		     req_cq, qp_create.cap.max_recv_wr,
		     qp_create.cap.max_recv_sge, rcv_cq);

#ifdef _OPENIB_MCM_
skip_qp:
	/* shadow support, MPXYD */
	ep_ptr->qp_handle->qp_id = 0;
	if (ia_ptr->hca_ptr->ib_trans.scif_ep) { /* MIC: shadow QPt on proxy */
		req_cq->flags |= DCM_CQ_TX_INDIRECT;
		qp_create.send_cq = req_cq->cq;
		qp_create.cap.max_inline_data = max_inline;
		qp_create.cap.max_send_wr = attr->max_request_dtos;
		qp_create.cap.max_send_sge = attr->max_request_iov;
		if (ep_ptr->qp_handle->qp) { /* MIC: unused shadow QPr on proxy */
			qp_create.cap.max_recv_wr = 1;
			qp_create.cap.max_recv_sge = 1;
		} else { /* MIC: shadow QPr on proxy */
			rcv_cq->flags |= DCM_CQ_RX_INDIRECT;
			qp_create.cap.max_recv_wr = attr->max_recv_dtos;
			qp_create.cap.max_recv_sge = attr->max_recv_iov;
		}
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
			     " QP_ALLOC: QPt (MPXYD) SQ %d,%d %s RQ %d,%d\n",
			     qp_create.cap.max_send_wr, qp_create.cap.max_send_sge,
			     ep_ptr->qp_handle->qp ? "":"QPr",
			     qp_create.cap.max_recv_wr, qp_create.cap.max_recv_sge);

		ret = dapli_mix_qp_create(ep_ptr->qp_handle, &qp_create, req_cq, rcv_cq);
		if (ret)
			goto err;
	} else {
		/* NON-MIC: need QPt, in case of shadowed QP's on remote MIC's */
		/* Prep for HST -> MXS: xfers via remote PI instead of direct */

		/* create CQ for peer PI, HST->MXS case */
		if (mcm_create_pi_cq(ep_ptr->qp_handle, MCM_WRC_QLEN))
			goto err;
		qp_create.recv_cq = ep_ptr->qp_handle->rcv_cq->cq;
		qp_create.send_cq = req_cq->cq;
		qp_create.cap.max_recv_wr = MCM_WRC_QLEN;
		qp_create.cap.max_recv_sge = 1;
		qp_create.cap.max_send_wr = DAPL_MAX(MCM_WRC_QLEN, attr->max_request_dtos);
		qp_create.cap.max_send_sge = attr->max_request_iov;
		if (max_inline)
			qp_create.cap.max_inline_data =
				DAPL_MAX(sizeof(struct mcm_wr_rx), max_inline);

		ep_ptr->qp_handle->qp2 = ibv_create_qp(ib_pd_handle, &qp_create);
		if (!ep_ptr->qp_handle->qp2) {
			ret = errno;
			goto err;
		}
		/* enable RR from remote PI */
		if (dapls_modify_qp_state(ep_ptr->qp_handle->qp2,
					  IBV_QPS_INIT, 0, 0, 0) != DAT_SUCCESS) {
			ret = errno;
			goto err;
		}
		ep_ptr->qp_handle->req_cq = req_cq;

		dapl_dbg_log(DAPL_DBG_TYPE_EP,
			     " QP_ALLOC: QPt %p-0x%x SQ %d,%d cq %p, RQ %d,%d cq %p, il %d\n",
			     ep_ptr->qp_handle->qp2, ep_ptr->qp_handle->qp2->qp_num,
			     qp_create.cap.max_send_wr, qp_create.cap.max_send_sge,
			     ep_ptr->qp_handle->rcv_cq, qp_create.cap.max_recv_wr,
			     qp_create.cap.max_recv_sge, ep_ptr->qp_handle->req_cq,
			     qp_create.cap.max_inline_data);
	}
	if (!ep_ptr->qp_handle->qp) { /* QPr and QPs both shadowed */
		ep_ptr->qp_state = IBV_QPS_INIT;
		return DAT_SUCCESS;
	}
#endif
	/* Setup QP attributes for INIT state on the way out */
	if (dapls_modify_qp_state(ep_ptr->qp_handle->qp,
				  IBV_QPS_INIT, 0, 0, 0) != DAT_SUCCESS) {
		ret = errno;
		goto err;
	}
#endif
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " qp_alloc: qpn 0x%x type %d sq %d,%d rq %d,%d\n",
		     ep_ptr->qp_handle->qp->qp_num,
		     ep_ptr->qp_handle->qp->qp_type,
		     qp_create.cap.max_send_wr, qp_create.cap.max_send_sge,
		     qp_create.cap.max_recv_wr, qp_create.cap.max_recv_sge);

	return DAT_SUCCESS;
err:
	if (ep_ptr->qp_handle) {
		if (ep_ptr->qp_handle->qp)
			ibv_destroy_qp(ep_ptr->qp_handle->qp);
#ifdef _OPENIB_MCM_
		if (ep_ptr->qp_handle->qp2)
			ibv_destroy_qp(ep_ptr->qp_handle->qp2);
#endif
		if (ep_ptr->qp_handle->ah)
			dapl_os_free(ep_ptr->qp_handle->ah,
				     sizeof(ib_ah_handle_t) * DCM_AH_SPACE);

		dapl_os_free(ep_ptr->qp_handle, sizeof(struct dcm_ib_qp));
	}
	ep_ptr->qp_handle = IB_INVALID_HANDLE;
	return (dapl_convert_errno(ret, "create_qp"));
}

/*
 * dapl_ib_qp_free
 *
 * Free a QP
 *
 * Input:
 *	ia_handle	IA handle
 *	*ep_ptr		pointer to EP INFO
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *  dapl_convert_errno
 *
 */
DAT_RETURN dapls_ib_qp_free(IN DAPL_IA * ia_ptr, IN DAPL_EP * ep_ptr)
{
	struct ibv_qp *qp;

	dapl_log(DAPL_DBG_TYPE_EP,
		 " dapls_ib_qp_free: ep_ptr %p qp_handle %p\n",
		 ep_ptr, ep_ptr->qp_handle);

#ifdef _OPENIB_CMA_
	dp_ib_cm_handle_t cm_ptr = dapl_get_cm_from_ep(ep_ptr);
	if (!cm_ptr)
		return DAT_SUCCESS;
#endif

	dapl_os_lock(&ep_ptr->header.lock);
	if (ep_ptr->qp_handle) {
		qp = ep_ptr->qp_handle->qp;
		dapl_os_unlock(&ep_ptr->header.lock);
		if (qp) {
			dapls_modify_qp_state(qp, IBV_QPS_ERR, 0, 0, 0);
			dapls_ep_flush_cqs(ep_ptr);
		}

#ifdef _OPENIB_CMA_
		rdma_destroy_qp(cm_ptr->cm_id);
		cm_ptr->cm_id->qp = NULL;
		qp = NULL;
#endif

#ifdef _OPENIB_MCM_
		if (ep_ptr->qp_handle->qp2)
			dapls_modify_qp_state(ep_ptr->qp_handle->qp2,
					      IBV_QPS_ERR, 0, 0, 0);

		/* MIC: shadow support on MPXYD node */
		if (ia_ptr->hca_ptr->ib_trans.scif_ep)
			dapli_mix_qp_free(ep_ptr->qp_handle);

		dapls_ep_flush_cqs(ep_ptr);

		if (ep_ptr->qp_handle->qp2)
			ibv_destroy_qp(ep_ptr->qp_handle->qp2);

		dapl_os_lock_destroy(&ep_ptr->qp_handle->lock);
#endif
		if (qp)
			ibv_destroy_qp(qp);
	} else {
		dapl_os_unlock(&ep_ptr->header.lock);
	}

#ifdef _OPENIB_MCM_
	if (ep_ptr->qp_handle) {
		mcm_destroy_pi_cq(ep_ptr->qp_handle);
		mcm_destroy_wc_q(ep_ptr->qp_handle);
	}
#endif
	/* destroy any UD address handles */
	if (ep_ptr->qp_handle->ah) {
		int i;

		for (i = 0; i < DCM_AH_SPACE; i++) {
			if (ep_ptr->qp_handle->ah[i])
				ibv_destroy_ah(ep_ptr->qp_handle->ah[i]);
		}
		dapl_os_free(ep_ptr->qp_handle->ah, sizeof(ib_ah_handle_t) * DCM_AH_SPACE);
	}

	dapl_os_free(ep_ptr->qp_handle, sizeof(struct dcm_ib_qp));
	ep_ptr->qp_handle = IB_INVALID_HANDLE;
	return DAT_SUCCESS;
}

/*
 * dapl_ib_qp_modify
 *
 * Set the QP to the parameters specified in an EP_PARAM
 *
 * The EP_PARAM structure that is provided has been
 * sanitized such that only non-zero values are valid.
 *
 * Input:
 *	ib_hca_handle		HCA handle
 *	qp_handle		QP handle
 *	ep_attr		        Sanitized EP Params
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
dapls_ib_qp_modify(IN DAPL_IA * ia_ptr,
		   IN DAPL_EP * ep_ptr, IN DAT_EP_ATTR * attr)
{
	struct ibv_qp_attr qp_attr;

	if (ep_ptr->qp_handle == IB_INVALID_HANDLE)
		return DAT_INVALID_PARAMETER;

	/* 
	 * EP state, qp_handle state should be an indication
	 * of current state but the only way to be sure is with
	 * a user mode ibv_query_qp call which is NOT available 
	 */

	/* move to error state if necessary */
	if ((ep_ptr->qp_state == IB_QP_STATE_ERROR) &&
	    (ep_ptr->qp_handle->qp->state != IBV_QPS_ERR)) {
		return (dapls_modify_qp_state(ep_ptr->qp_handle->qp,
					      IBV_QPS_ERR, 0, 0, 0));
	}

	/* consumer ep_modify, init state */
	if (ep_ptr->qp_handle->qp->state == IBV_QPS_INIT) {
		return (dapls_modify_qp_state(ep_ptr->qp_handle->qp,
					      IBV_QPS_INIT, 0, 0, 0));
	}

	/*
	 * Check if we have the right qp_state to modify attributes
	 */
	if ((ep_ptr->qp_handle->qp->state != IBV_QPS_RTR) &&
	    (ep_ptr->qp_handle->qp->state != IBV_QPS_RTS))
		return DAT_INVALID_STATE;

	/* Adjust to current EP attributes */
	dapl_os_memzero((void *)&qp_attr, sizeof(qp_attr));
	qp_attr.cap.max_send_wr = attr->max_request_dtos;
	qp_attr.cap.max_recv_wr = attr->max_recv_dtos;
	qp_attr.cap.max_send_sge = attr->max_request_iov;
	qp_attr.cap.max_recv_sge = attr->max_recv_iov;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     "modify_qp: qp_h %p sq %d,%d, rq %d,%d\n",
		     ep_ptr->qp_handle,
		     qp_attr.cap.max_send_wr, qp_attr.cap.max_send_sge,
		     qp_attr.cap.max_recv_wr, qp_attr.cap.max_recv_sge);

	if (ibv_modify_qp(ep_ptr->qp_handle->qp, &qp_attr, IBV_QP_CAP)) {
		dapl_log(DAPL_DBG_TYPE_EP,
			 "modify_qp: modify ep %p qp_h %p failed, state=%d\n",
			  ep_ptr, ep_ptr->qp_handle->qp, ep_ptr->qp_state);
		return (DAT_INVALID_STATE);
	}

	return DAT_SUCCESS;
}

/*
 * dapls_ib_reinit_ep
 *
 * Move the QP to INIT state again.
 *
 * Input:
 *	ep_ptr		DAPL_EP
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	void
 *
 */
#if defined(_WIN32) || defined(_WIN64) || defined(_OPENIB_CMA_)
void dapls_ib_reinit_ep(IN DAPL_EP * ep_ptr)
{
	dp_ib_cm_handle_t cm_ptr, next_cm_ptr;

	/* work around bug in low level driver - 3/24/09 */
	/* RTS -> RESET -> INIT -> ERROR QP transition crashes system */
	if (ep_ptr->qp_handle != IB_INVALID_HANDLE) {
		dapls_ib_qp_free(ep_ptr->header.owner_ia, ep_ptr);
		
		/* free any CM object's created */
		cm_ptr = (dapl_llist_is_empty(&ep_ptr->cm_list_head)
			  ? NULL : dapl_llist_peek_head(&ep_ptr->cm_list_head));
		while (cm_ptr != NULL) {
             		next_cm_ptr = dapl_llist_next_entry(&ep_ptr->cm_list_head,
							    &cm_ptr->list_entry);
			dapls_cm_free(cm_ptr); 
			cm_ptr = next_cm_ptr;
		}
		dapls_ib_qp_alloc(ep_ptr->header.owner_ia, ep_ptr, ep_ptr);
	}
}
#else				// _WIN32 || _WIN64
void dapls_ib_reinit_ep(IN DAPL_EP * ep_ptr)
{
	if (ep_ptr->qp_handle != IB_INVALID_HANDLE &&
	    ep_ptr->qp_handle->qp->qp_type != IBV_QPT_UD) {
		/* move to RESET state and then to INIT */
		dapls_modify_qp_state(ep_ptr->qp_handle->qp, IBV_QPS_RESET,0,0,0);
		dapls_modify_qp_state(ep_ptr->qp_handle->qp, IBV_QPS_INIT,0,0,0);
	}
}
#endif				// _WIN32 || _WIN64

#if DAPL_USE_IBACM
#ifndef RAI_NOROUTE 
#define RAI_NOROUTE 0
#endif
uint8_t dapls_get_sl(DAPL_HCA *hca_ptr, uint16_t dlid)
{
	struct rdma_addrinfo hint, *res;
	struct ibv_path_record path;
	uint8_t sl = hca_ptr->ib_trans.sl;
	int ret;

	memset(&path, 0, sizeof path);
	path.reversible_numpath = IBV_PATH_RECORD_REVERSIBLE | 1;
	path.slid = hca_ptr->ib_trans.lid;
	path.dlid = dlid;

	memset(&hint, 0, sizeof hint);
	hint.ai_flags = RAI_NOROUTE;
	hint.ai_route = &path;
	hint.ai_route_len = sizeof(path);

	ret = rdma_getaddrinfo(NULL, NULL, &hint, &res);
	if (ret)
		goto out;
	
	if (res->ai_route_len)
		sl = ntohs(((struct ibv_path_record *) res->ai_route)->
			   qosclass_sl) & 0xF;
	else 
		dapl_log(DAPL_DBG_TYPE_CM_WARN,
			" dapls_get_sl: Warning, route miss 0x%x -> 0x%x\n",
			path.slid, path.dlid);

	rdma_freeaddrinfo(res);
out:	
	return sl;
}
#else
uint8_t dapls_get_sl(DAPL_HCA *hca_ptr, uint16_t dlid)
{
	return hca_ptr->ib_trans.ib_cm.sl;
}
#endif

/* 
 * Generic QP modify for init, reset, error, RTS, RTR
 * For UD, create_ah on RTR, qkey on INIT
 * CM msg provides QP attributes, info in network order
 */
DAT_RETURN
dapls_modify_qp_state(IN struct ibv_qp		*qp_handle,
		      IN ib_qp_state_t		qp_state, 
		      IN uint32_t		qpn,
		      IN uint16_t		lid,
		      IN ib_gid_handle_t	gid)
{
	struct ibv_qp_attr qp_attr;
	enum ibv_qp_attr_mask mask = IBV_QP_STATE;
	DAPL_EP *ep_ptr = (DAPL_EP *) qp_handle->qp_context;
	DAPL_IA *ia_ptr = ep_ptr->header.owner_ia;
	int ret;

	dapl_os_memzero((void *)&qp_attr, sizeof(qp_attr));
	qp_attr.qp_state = qp_state;
	
	switch (qp_state) {
	case IBV_QPS_RTR:
		mask |= IBV_QP_AV |
			IBV_QP_PATH_MTU |
			IBV_QP_DEST_QPN |
			IBV_QP_RQ_PSN |
			IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

		qp_attr.dest_qp_num = ntohl(qpn);
		qp_attr.rq_psn = 1;
		qp_attr.min_rnr_timer =	ia_ptr->hca_ptr->ib_trans.ib_cm.rnr_timer;
		qp_attr.path_mtu = ep_ptr->qp_handle->mtu ?
				   ep_ptr->qp_handle->mtu :
				   ia_ptr->hca_ptr->ib_trans.ib_cm.mtu;
#ifdef _OPENIB_MCM_
		qp_attr.max_dest_rd_atomic = ia_ptr->hca_ptr->ib_trans.ib_cm.rd_atom_in;
#else
		qp_attr.max_dest_rd_atomic = ep_ptr->param.ep_attr.max_rdma_read_in;
#endif
		dapl_log(DAPL_DBG_TYPE_EP,
		  	 " QPS_RTR: type %d l_qpn %x qpn %x lid 0x%x"
			 " port %d ep %p qp_state %d rd_atomic %d mtu %d lmtu %d\n",
			 qp_handle->qp_type, qp_handle->qp_num,
			 ntohl(qpn), ntohs(lid), ia_ptr->hca_ptr->port_num,
			 ep_ptr, ep_ptr->qp_state, qp_attr.max_dest_rd_atomic,
			 qp_attr.path_mtu, ia_ptr->hca_ptr->ib_trans.ib_cm.mtu);

		/* address handle. RC and UD */
		qp_attr.ah_attr.dlid = ntohs(lid);
		if (gid && ia_ptr->hca_ptr->ib_trans.ib_cm.global) {
			dapl_dbg_log(DAPL_DBG_TYPE_EP, 
				     " QPS_RTR: GID Subnet 0x" F64x " ID 0x" F64x "\n", 
				     (unsigned long long)htonll(gid->global.subnet_prefix),
				     (unsigned long long)htonll(gid->global.interface_id));

			qp_attr.ah_attr.is_global = 1;
			qp_attr.ah_attr.grh.dgid.global.subnet_prefix = 
				gid->global.subnet_prefix;
			qp_attr.ah_attr.grh.dgid.global.interface_id = 
				gid->global.interface_id;
			qp_attr.ah_attr.grh.hop_limit =
				ia_ptr->hca_ptr->ib_trans.ib_cm.hop_limit;
			qp_attr.ah_attr.grh.traffic_class =
				ia_ptr->hca_ptr->ib_trans.ib_cm.tclass;
		}
		qp_attr.ah_attr.sl = dapls_get_sl(ia_ptr->hca_ptr, lid);
		qp_attr.ah_attr.src_path_bits = 0;
		qp_attr.ah_attr.port_num = ia_ptr->hca_ptr->port_num;

		/* UD: already in RTR, RTS state */
		if (qp_handle->qp_type == IBV_QPT_UD) {
			mask = IBV_QP_STATE;
			if (ep_ptr->qp_state == IBV_QPS_RTR ||
				ep_ptr->qp_state == IBV_QPS_RTS)
				return DAT_SUCCESS;
		}
		break;
	case IBV_QPS_RTS:
		if (qp_handle->qp_type == IBV_QPT_RC) {
			mask |= IBV_QP_SQ_PSN |
				IBV_QP_TIMEOUT |
				IBV_QP_RETRY_CNT |
				IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC;
			qp_attr.timeout =
				ia_ptr->hca_ptr->ib_trans.ib_cm.ack_timer;
			qp_attr.retry_cnt =
				ia_ptr->hca_ptr->ib_trans.ib_cm.ack_retry;
			qp_attr.rnr_retry =
				ia_ptr->hca_ptr->ib_trans.ib_cm.rnr_retry;
#ifdef _OPENIB_MCM_
			qp_attr.max_rd_atomic = ia_ptr->hca_ptr->ib_trans.ib_cm.rd_atom_out;
#else
			qp_attr.max_rd_atomic = ep_ptr->param.ep_attr.max_rdma_read_out;
#endif
		}
		/* RC and UD */
		qp_attr.qp_state = IBV_QPS_RTS;
		qp_attr.sq_psn = 1;

		dapl_dbg_log(DAPL_DBG_TYPE_EP,
				" QPS_RTS: psn %x rd_atomic %d ack %d "
				" retry %d rnr_retry %d ep %p qp_state %d\n",
				qp_attr.sq_psn, qp_attr.max_rd_atomic,
				qp_attr.timeout, qp_attr.retry_cnt,
				qp_attr.rnr_retry, ep_ptr,
				ep_ptr->qp_state);

		if (qp_handle->qp_type == IBV_QPT_UD) {
			/* already RTS, multi remote AH's on QP */
			if (ep_ptr->qp_state == IBV_QPS_RTS)
				return DAT_SUCCESS;
			else
				mask = IBV_QP_STATE | IBV_QP_SQ_PSN;
		}
		break;
	case IBV_QPS_INIT:
		mask |= IBV_QP_PKEY_INDEX | IBV_QP_PORT;
		if (qp_handle->qp_type == IBV_QPT_RC) {
			mask |= IBV_QP_ACCESS_FLAGS;
			qp_attr.qp_access_flags =
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_ATOMIC |
				IBV_ACCESS_MW_BIND;
		}

		if (qp_handle->qp_type == IBV_QPT_UD) {
			/* already INIT, multi remote AH's on QP */
			if (ep_ptr->qp_state == IBV_QPS_INIT)
				return DAT_SUCCESS;
			mask |= IBV_QP_QKEY;
			qp_attr.qkey = DAT_UD_QKEY;
		}

		qp_attr.pkey_index = ia_ptr->hca_ptr->ib_trans.ib_cm.pkey_idx;
		qp_attr.port_num = ia_ptr->hca_ptr->port_num;

		dapl_dbg_log(DAPL_DBG_TYPE_EP,
				" QPS_INIT: pi %x port %x acc %x qkey 0x%x\n",
				qp_attr.pkey_index, qp_attr.port_num,
				qp_attr.qp_access_flags, qp_attr.qkey);
		break;
	default:
		break;
	}

	ret = ibv_modify_qp(qp_handle, &qp_attr, mask);
	if (ret == 0) {
		ep_ptr->qp_state = qp_state;
		return DAT_SUCCESS;
	} else {
		dapl_log(DAPL_DBG_TYPE_ERR,
			" modify_qp_state: ERR type %d qpn 0x%x gid %p (%d) lid 0x%x"
			" port %d state %d mtu %d rd %d rnr %d sl %d\n",
			qp_handle->qp_type, ntohl(qpn), gid,
			ia_ptr->hca_ptr->ib_trans.ib_cm.global,
			ntohs(lid), ia_ptr->hca_ptr->port_num,
			ep_ptr->qp_state,
			qp_attr.path_mtu, qp_attr.max_dest_rd_atomic,
			qp_attr.min_rnr_timer, qp_attr.ah_attr.sl);

		return (dapl_convert_errno(errno, "modify_qp_state"));
	}
}

/* Modify UD type QP from init, rtr, rts, info network order */
DAT_RETURN 
dapls_modify_qp_ud(IN DAPL_HCA *hca, IN struct ibv_qp *qp)
{
	struct ibv_qp_attr qp_attr;

	/* modify QP, setup and prepost buffers */
	dapl_os_memzero((void *)&qp_attr, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_INIT;
        qp_attr.pkey_index = hca->ib_trans.ib_cm.pkey_idx;
        qp_attr.port_num = hca->port_num;
#ifdef _OPENIB_MCM_
        qp_attr.qkey = DAT_MCM_UD_QKEY; /* MCM gets different key */
#else
        qp_attr.qkey = DAT_UD_QKEY;
#endif
        if (ibv_modify_qp(qp, &qp_attr,
			  IBV_QP_STATE		|
			  IBV_QP_PKEY_INDEX	|
                          IBV_QP_PORT		|
                          IBV_QP_QKEY)) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			" modify_ud_qp INIT: ERR %s\n", strerror(errno));
		return (dapl_convert_errno(errno, "modify_qp"));
	}
	dapl_os_memzero((void *)&qp_attr, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_RTR;
	if (ibv_modify_qp(qp, &qp_attr,IBV_QP_STATE)) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			" modify_ud_qp RTR: ERR %s\n", strerror(errno));
		return (dapl_convert_errno(errno, "modify_qp"));
	}
	dapl_os_memzero((void *)&qp_attr, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_RTS;
	qp_attr.sq_psn = 1;
	if (ibv_modify_qp(qp, &qp_attr,
			  IBV_QP_STATE | IBV_QP_SQ_PSN)) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			" modify_ud_qp RTS: ERR %s\n", strerror(errno));
		return (dapl_convert_errno(errno, "modify_qp"));
	}
	return DAT_SUCCESS;
}

/* Create address handle for remote QP, info in network order */
ib_ah_handle_t 
dapls_create_ah(IN DAPL_HCA		*hca,
		IN ib_pd_handle_t	pd,
		IN struct ibv_qp	*qp,
		IN uint16_t		lid,
		IN ib_gid_handle_t	gid)
{
	struct ibv_qp_attr qp_attr;
	ib_ah_handle_t	ah;

	if (qp->qp_type != IBV_QPT_UD) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " create_ah ERR: QP_type != UD\n");
		return NULL;
	}

	dapl_os_memzero((void *)&qp_attr, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QP_STATE;

	/* address handle. RC and UD */
	qp_attr.ah_attr.dlid = ntohs(lid);
	if (gid != NULL) {
		dapl_log(DAPL_DBG_TYPE_CM, "dapl_create_ah: with GID\n");
		qp_attr.ah_attr.is_global = 1;
		qp_attr.ah_attr.grh.dgid.global.subnet_prefix = 
				ntohll(gid->global.subnet_prefix);
		qp_attr.ah_attr.grh.dgid.global.interface_id = 
				ntohll(gid->global.interface_id);
		qp_attr.ah_attr.grh.hop_limit =	hca->ib_trans.ib_cm.hop_limit;
		qp_attr.ah_attr.grh.traffic_class = hca->ib_trans.ib_cm.tclass;
	}
	qp_attr.ah_attr.sl = dapls_get_sl(hca, lid);
	qp_attr.ah_attr.src_path_bits = 0;
	qp_attr.ah_attr.port_num = hca->port_num;

	dapl_log(DAPL_DBG_TYPE_CM, 
			" dapls_create_ah: port %x lid %x pd %p ctx %p handle 0x%x\n", 
			hca->port_num,qp_attr.ah_attr.dlid, pd, pd->context, pd->handle);

	/* UD: create AH for remote side */
	ah = ibv_create_ah(pd, &qp_attr.ah_attr);
	if (!ah) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			" create_ah: ERR %s\n", strerror(errno));
		return NULL;
	}

	dapl_log(DAPL_DBG_TYPE_CM, 
			" dapls_create_ah: AH %p for lid %x\n", 
			ah, qp_attr.ah_attr.dlid);

	return ah;
}

DAT_RETURN dapls_modify_qp_rtu(struct ibv_qp *qp, uint32_t qpn, uint16_t lid, ib_gid_handle_t gid)
{
	DAT_RETURN ret;

	ret = dapls_modify_qp_state(qp, IBV_QPS_RTR, qpn, lid, gid);
	if (ret != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " MODIFY_QP_RTU: RTR err=%s qpn %x -> lid %x iqp %x\n",
			 strerror(errno), qp->qp_num, ntohs(lid), ntohl(qpn));
		return ret;
	}

	ret = dapls_modify_qp_state(qp, IBV_QPS_RTS, qpn, lid, NULL);
	if (ret != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " MODIFY_QP_RTU: RTS err=%s qpn %x -> lid %x iqp %x\n",
			 strerror(errno), qp->qp_num, ntohs(lid), ntohl(qpn));
		return ret;
	}
	return DAT_SUCCESS;
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
