/*
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
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

/**********************************************************************
 * 
 * MODULE: dapl_evd_qp_async_error_callback.c
 *
 * PURPOSE: implements QP callbacks from verbs
 *
 * $Id:$
 **********************************************************************/

#include "dapl.h"
#include "dapl_evd_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_evd_qp_async_error_callback
 *
 * The callback function registered with verbs for qp async erros
 *
 * Input:
 * 	ib_cm_handle,
 * 	ib_cm_event
 * 	cause_ptr
 * 	context (evd)
 *
 * Output:
 * 	None
 *
 */

void
dapl_evd_qp_async_error_callback(IN ib_hca_handle_t ib_hca_handle,
				 IN ib_qp_handle_t ib_qp_handle,
				 IN ib_error_record_t * cause_ptr,
				 IN void *context)
{
	DAPL_IA *ia_ptr;
	DAPL_EP *ep_ptr;
	DAPL_EVD *async_evd;
	DAT_EVENT_NUMBER async_event;
	DAT_RETURN dat_status;

#ifdef _VENDOR_IBAL_
	dapl_dbg_log(DAPL_DBG_TYPE_EXCEPTION, "%s() IB err %s\n",
		     __FUNCTION__, ib_get_async_event_str(cause_ptr->code));
#else
	dapl_dbg_log(DAPL_DBG_TYPE_EXCEPTION, "%s() IB async QP err - ctx=%p\n",
		     __FUNCTION__, context);
#endif

	ep_ptr = (DAPL_EP *) context;
	if (!ep_ptr) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, "%s() NULL context?\n",
			     __FUNCTION__);
		return;
	}

	ia_ptr = ep_ptr->header.owner_ia;
	async_evd = (DAPL_EVD *) ia_ptr->async_error_evd;
	DAPL_CNTR(ia_ptr, DCNT_IA_ASYNC_QP_ERROR);

	dapl_log(DAPL_DBG_TYPE_EXCEPTION, " -- %s: ep %p qp %p (%x) state %d\n",
		 __FUNCTION__,  ep_ptr, ep_ptr->qp_handle,
		 ep_ptr->qpn, ep_ptr->param.ep_state);

	/*
	 * Transition to ERROR if we are connected; other states need to
	 * complete first (e.g. pending states) unless it's SRQ LAST_WQE_REACHED
	 * which is a regular async event in case of disconnect.
	 */
	if (ep_ptr->param.ep_state == DAT_EP_STATE_CONNECTED) {
		if (!ep_ptr->param.srq_handle || cause_ptr->event_type != IBV_EVENT_QP_LAST_WQE_REACHED) {
			dapl_os_lock(&ep_ptr->header.lock);
			ep_ptr->param.ep_state = DAT_EP_STATE_ERROR;
			dapl_os_unlock(&ep_ptr->header.lock);
		}
	}

	dapl_os_assert(async_evd != NULL);

	dat_status = dapls_ib_get_async_event(cause_ptr, &async_event);
	if (dat_status == DAT_SUCCESS) {
		/*
		 * If dapls_ib_get_async_event is not successful,
		 * an event has been generated by the provide that
		 * we are not interested in.
		 */
		(void)dapls_evd_post_async_error_event(async_evd,
						       async_event,
						       (DAT_HANDLE) ep_ptr);
	}
	dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK | DAPL_DBG_TYPE_EXCEPTION,
		     "%s() returns\n", __FUNCTION__);
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */