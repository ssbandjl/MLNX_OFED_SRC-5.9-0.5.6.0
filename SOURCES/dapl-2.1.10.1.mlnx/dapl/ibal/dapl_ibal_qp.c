
/*
 * Copyright (c) 2005-2007 Intel Corporation. All rights reserved.
 * Copyright (c) 2002, Network Appliance, Inc. All rights reserved. 
 * 
 * This Software is licensed under the terms of the "Common Public
 * License" a copy of which is in the file LICENSE.txt in the root
 * directory. The license is also available from the Open Source
 * Initiative, see http://www.opensource.org/licenses/cpl.php.
 *
 */

/**********************************************************************
 * 
 * MODULE: dapl_ibal_qp.c
 *
 * PURPOSE: IB QP routines  for access to IBAL APIs
 *
 * $Id: dapl_ibal_qp.c 33 2005-07-11 19:51:17Z ftillier $
 *
 **********************************************************************/

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_ibal_util.h"
#include "dapl_ep_util.h"

#define DAPL_IBAL_QKEY              0
#define DAPL_IBAL_START_PSN         0

extern DAT_RETURN
dapls_ib_cq_late_alloc ( IN  ib_pd_handle_t        pd_handle,
                         IN  DAPL_EVD              *evd_ptr );

static void
dapli_ib_qp_async_error_cb( IN  ib_async_event_rec_t* p_err_rec )
{
	DAPL_EP			*ep_ptr = (DAPL_EP *)p_err_rec->context;
	DAPL_EVD		*evd_ptr;
	DAPL_IA			*ia_ptr;
	dapl_ibal_ca_t		*p_ca;
        dapl_ibal_evd_cb_t	*evd_cb;

        dapl_dbg_log (DAPL_DBG_TYPE_ERR,"--> DiQpAEC QP event %s qp ctx %p\n", 
		ib_get_async_event_str(p_err_rec->code), p_err_rec->context);
        dapl_dbg_log (DAPL_DBG_TYPE_ERR,"--> DiQpAEC qp_handle %p qpn %u\n", 
		((DAPL_EP *)p_err_rec->context)->qp_handle, 
		((DAPL_EP *)p_err_rec->context)->qpn);

	/*
	 * Verify handles EP, EVD, and hca_handle
	 */
	if (DAPL_BAD_HANDLE (ep_ptr, DAPL_MAGIC_EP ) ||
	    DAPL_BAD_HANDLE (ep_ptr->param.connect_evd_handle, DAPL_MAGIC_EVD))
	{
		dapl_dbg_log (DAPL_DBG_TYPE_ERR,
				"--> DiQpAEC: invalid EP %p \n", ep_ptr);
		return;
	}
	ia_ptr = ep_ptr->header.owner_ia;
	evd_ptr = ia_ptr->async_error_evd;

	if (DAPL_BAD_HANDLE (evd_ptr, DAPL_MAGIC_EVD) ||
	    ! (evd_ptr->evd_flags & DAT_EVD_ASYNC_FLAG))
	{
		dapl_dbg_log (DAPL_DBG_TYPE_ERR,
				"--> DiQpAEC: invalid EVD %p \n", evd_ptr);
		return;
	}
	p_ca = (dapl_ibal_ca_t *) ia_ptr->hca_ptr->ib_hca_handle;
	if (p_ca == NULL)
	{
		dapl_dbg_log (DAPL_DBG_TYPE_ERR,
				"--> DiQpAEC: can't find %s HCA\n", 
				(ia_ptr->header.provider)->device_name);
		return;
	}

	/* find QP error callback using ia_ptr for context */
	evd_cb = dapli_find_evd_cb_by_context (ia_ptr, p_ca);
	if ((evd_cb == NULL) || (evd_cb->pfn_async_qp_err_cb == NULL))
	{
		dapl_dbg_log (DAPL_DBG_TYPE_ERR,
			"--> DiQpAEC: no ERROR cb on p_ca %p found\n", p_ca);
		return;
	}

	dapl_os_lock (&ep_ptr->header.lock);
	ep_ptr->param.ep_state = DAT_EP_STATE_DISCONNECT_PENDING;
	dapl_os_unlock (&ep_ptr->header.lock);

	/* force disconnect, QP error state, to insure DTO's get flushed */
	dapls_ib_disconnect ( ep_ptr, DAT_CLOSE_ABRUPT_FLAG );
	
	/* maps to dapl_evd_qp_async_error_callback(), context is EP */
	evd_cb->pfn_async_qp_err_cb(	(ib_hca_handle_t)p_ca, 
				     ep_ptr->qp_handle,
					(ib_error_record_t*)&p_err_rec->code,
				     ep_ptr );
}

/*
 * dapls_ib_qp_alloc
 *
 * Alloc a QP
 *
 * Input:
 *        *ia_ptr                pointer to DAPL IA
 *        *ep_ptr                pointer to DAPL EP
 *        *ep_ctx_ptr            pointer to DAPL EP context
 *
 * Output:
 *         none
 *
 * Returns:
 *        DAT_SUCCESS
 *        DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_qp_alloc (
        IN  DAPL_IA                *ia_ptr,
        IN  DAPL_EP                *ep_ptr,
	IN  DAPL_EP                *ep_ctx_ptr)
{
    DAT_EP_ATTR           *attr;
    DAPL_EVD              *recv_evd_ptr, *request_evd_ptr;
    DAT_RETURN            dat_status;
    ib_api_status_t       ib_status;
    ib_qp_create_t        qp_create;
    ib_pd_handle_t        ib_pd_handle;
    ib_cq_handle_t        cq_recv;
    ib_cq_handle_t        cq_send;
    dapl_ibal_ca_t        *p_ca;
    dapl_ibal_port_t      *p_active_port;
    ib_qp_attr_t          qp_attr;
    dp_ib_cm_handle_t     cm_ptr;

    attr = &ep_ptr->param.ep_attr;

    dapl_os_assert ( ep_ptr->param.pz_handle != NULL );

    ib_pd_handle    = ((DAPL_PZ *)ep_ptr->param.pz_handle)->pd_handle;
    dapl_os_assert(ib_pd_handle);
    recv_evd_ptr    = (DAPL_EVD *) ep_ptr->param.recv_evd_handle;
    request_evd_ptr = (DAPL_EVD *) ep_ptr->param.request_evd_handle;
    
    cq_recv = IB_INVALID_HANDLE;
    cq_send = IB_INVALID_HANDLE;

    dapl_os_assert ( recv_evd_ptr != DAT_HANDLE_NULL );
    {
        cq_recv = (ib_cq_handle_t) recv_evd_ptr->ib_cq_handle;
        
        if ((cq_recv == IB_INVALID_HANDLE) && 
            ( 0 != (recv_evd_ptr->evd_flags & ~DAT_EVD_SOFTWARE_FLAG) ))
        {
            dat_status = dapls_ib_cq_late_alloc ( ib_pd_handle, recv_evd_ptr);
            if (dat_status != DAT_SUCCESS)
            {
                dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                              "--> %s: failed to create CQ\n","DsQA");
                return (dat_status);
            }

            dat_status = dapls_set_cq_notify (ia_ptr, recv_evd_ptr);

            if (dat_status != DAT_SUCCESS)
            {
                dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                              "--> %s: failed to enable notify CQ\n","DsQA");
                return (dat_status);
            }
        
            cq_recv = (ib_cq_handle_t) recv_evd_ptr->ib_cq_handle;
            dapl_dbg_log (DAPL_DBG_TYPE_EP, 
                          "--> DsQA: alloc_recv_CQ = %p\n", cq_recv); 
        
        }
    }

    dapl_os_assert ( request_evd_ptr != DAT_HANDLE_NULL );
    {
        cq_send = (ib_cq_handle_t) request_evd_ptr->ib_cq_handle;
        
        if ((cq_send == IB_INVALID_HANDLE) && 
            ( 0 != (request_evd_ptr->evd_flags & ~DAT_EVD_SOFTWARE_FLAG) ))
        {
            dat_status = dapls_ib_cq_late_alloc (ib_pd_handle, request_evd_ptr);
            if (dat_status != DAT_SUCCESS)
            {
                dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                              "--> %s: failed to create CQ\n","DsQA");
                return (dat_status);
            }

            dat_status = dapls_set_cq_notify (ia_ptr, request_evd_ptr);

            if (dat_status != DAT_SUCCESS)
            {
                dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                              "--> %s: failed to enable notify CQ\n","DsQA");
                return (dat_status);
            }

            cq_send = (ib_cq_handle_t) request_evd_ptr->ib_cq_handle;
            dapl_dbg_log (DAPL_DBG_TYPE_EP, 
                          "--> DsQA: alloc_send_CQ = %p\n", cq_send); 
        }
    }

    /*
     * Get the CA structure
     */
    p_ca = (dapl_ibal_ca_t *) ia_ptr->hca_ptr->ib_hca_handle;

    dapl_os_memzero (&qp_create, sizeof (qp_create));
    qp_create.qp_type     = IB_QPT_RELIABLE_CONN;
    qp_create.sq_depth    = attr->max_request_dtos;
    qp_create.rq_depth    = attr->max_recv_dtos;
    qp_create.sq_sge      = attr->max_recv_iov;
    qp_create.rq_sge      = attr->max_request_iov;			  
    qp_create.h_sq_cq     = cq_send;
    qp_create.h_rq_cq     = cq_recv;
    qp_create.sq_signaled = FALSE;

    dapl_dbg_log (DAPL_DBG_TYPE_EP, 
                  "--> DsQA: sqd,iov=%d,%d rqd,iov=%d,%d\n", 
                  attr->max_request_dtos, attr->max_request_iov,
                  attr->max_recv_dtos, attr->max_recv_iov); 
    
    ib_status = ib_create_qp ( 
                       ib_pd_handle,
                       &qp_create,
                       (void *) ep_ctx_ptr /* context */,
                       dapli_ib_qp_async_error_cb,
                       &ep_ptr->qp_handle);

    if (ib_status != IB_SUCCESS)
    {
	dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> DsQA: Create QP failed = %s\n",
                      ib_get_err_str(ib_status));
	return (DAT_INSUFFICIENT_RESOURCES);
    }
    /* EP-CM linking */
    cm_ptr = ibal_cm_alloc();
    if (!cm_ptr) 
    {
	dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> DsQA: Create CM failed\n");
	return (DAT_INSUFFICIENT_RESOURCES);
    }
    cm_ptr->ib_cm.h_qp = ep_ptr->qp_handle;
    cm_ptr->ep = ep_ptr;
    dapl_ep_link_cm(ep_ptr, cm_ptr); 

    dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsQA: EP=%p, tEVD=%p, rEVD=%p QP=%p\n",
                  ep_ptr, ep_ptr->param.request_evd_handle,
                  ep_ptr->param.recv_evd_handle,
                  ep_ptr->qp_handle ); 

    ep_ptr->qp_state = IB_QPS_RESET;

    p_active_port = dapli_ibal_get_port(p_ca,(uint8_t)ia_ptr->hca_ptr->port_num);

    if (NULL == p_active_port)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> DsQA: Port %d is not available = %d\n",
                      ia_ptr->hca_ptr->port_num, __LINE__);
        return (DAT_INVALID_STATE);
    }

    ib_status = dapls_modify_qp_state_to_init ( ep_ptr->qp_handle, 
						&ep_ptr->param.ep_attr,
                                                p_active_port );

    if ( ib_status != IB_SUCCESS )
    {
	dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> DsQA: Change QP state to INIT failed = %s\n",
                      ib_get_err_str(ib_status));
	return (DAT_INVALID_HANDLE);
    }
    ib_status = ib_query_qp ( ep_ptr->qp_handle, &qp_attr );

    ep_ptr->qp_state = qp_attr.state;
    ep_ptr->qpn = qp_attr.num;
    
    dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsQAQA: EP:%p new_QP %p state %s\n",
                  ep_ptr,
                  ep_ptr->qp_handle,
                  ib_get_port_state_str(ep_ptr->qp_state));

    return (DAT_SUCCESS);
}


/*
 * dapls_ib_qp_free
 *
 * Free a QP
 *
 * Input:
 *        *ia_ptr                pointer to IA structure
 *        *ep_ptr                pointer to EP structure
 *
 * Output:
 *         none
 *
 * Returns:
 *         none
 *
 */
DAT_RETURN
dapls_ib_qp_free (
        IN  DAPL_IA                *ia_ptr,
        IN  DAPL_EP                *ep_ptr )
{
	ib_qp_handle_t qp;

	UNREFERENCED_PARAMETER(ia_ptr);

	dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsQF: free %p, state %s\n", 
                      ep_ptr->qp_handle,
                      ib_get_port_state_str(ep_ptr->qp_state));

	dapl_os_lock(&ep_ptr->header.lock);
	if (( ep_ptr->qp_handle != IB_INVALID_HANDLE ))
	{
		qp  = ep_ptr->qp_handle;
		ep_ptr->qp_handle = IB_INVALID_HANDLE;
		dapl_os_unlock(&ep_ptr->header.lock);

		dapls_modify_qp_state_to_error(qp);
		dapls_ep_flush_cqs(ep_ptr);

		ib_destroy_qp ( qp, ib_sync_destroy );
		dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsQF: freed QP %p\n",
				ep_ptr->qp_handle ); 
	} else {
		dapl_os_unlock(&ep_ptr->header.lock);
	}

    return DAT_SUCCESS;
}


/*
 * dapls_ib_qp_modify
 *
 * Set the QP to the parameters specified in an EP_PARAM
 *
 * We can't be sure what state the QP is in so we first obtain the state
 * from the driver. The EP_PARAM structure that is provided has been
 * sanitized such that only non-zero values are valid.
 *
 * Input:
 *        *ia_ptr                pointer to DAPL IA
 *        *ep_ptr                pointer to DAPL EP
 *        *ep_attr               pointer to DAT EP attribute
 *
 * Output:
 *         none
 *
 * Returns:
 *         DAT_SUCCESS
 *        DAT_INSUFFICIENT_RESOURCES
 *        DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_qp_modify (
        IN  DAPL_IA                        *ia_ptr,
        IN  DAPL_EP                        *ep_ptr,
        IN  DAT_EP_ATTR                    *ep_attr )
{
    ib_qp_attr_t                  qp_attr;
    ib_api_status_t               ib_status;
    ib_qp_handle_t                qp_handle;
    ib_qp_state_t                 qp_state;
    ib_qp_mod_t                   qp_mod;
    ib_av_attr_t                  *p_av_attr;
    ib_qp_opts_t                  *p_qp_opts;
    uint32_t                      *p_sq_depth, *p_rq_depth;
    DAT_BOOLEAN                   need_modify;
    DAT_RETURN                    dat_status;

    qp_handle     = ep_ptr->qp_handle;
    need_modify   = DAT_FALSE;
    dat_status    = DAT_SUCCESS;
    if ( ia_ptr == NULL || ia_ptr->header.magic != DAPL_MAGIC_IA )
    {
	dat_status = DAT_INVALID_HANDLE;
	goto bail;
    }
    /* 
     * Query the QP to get the current state.
     */
    ib_status = ib_query_qp ( qp_handle, &qp_attr );
                       
    if ( ib_status != IB_SUCCESS )
    {
	dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> DsIQM: Query QP failed = %s\n",
			ib_get_err_str(ib_status));
        dat_status = DAT_INTERNAL_ERROR;
        goto bail;
    }

    qp_state = qp_attr.state;

    dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsIQM: modify qp state=%d\n",qp_state);
    /*
     * Check if we have the right qp_state or not
     */
    if ( (qp_state != IB_QPS_RTR ) && (qp_state != IB_QPS_RTS ) )
    {
	dapl_dbg_log (DAPL_DBG_TYPE_EP,
                      "--> DsIQM: postpone to modify qp to EP values later\n");
        dat_status = DAT_SUCCESS;
        goto bail;
    }

    dapl_os_memzero (&qp_mod, sizeof (ib_qp_mod_t));

    if (qp_state == IB_QPS_RTR)
    {
        p_av_attr   = &qp_mod.state.rtr.primary_av;
        p_qp_opts   = &qp_mod.state.rtr.opts;
        p_sq_depth  = &qp_mod.state.rtr.sq_depth;
        p_rq_depth  = &qp_mod.state.rtr.rq_depth;
    }
    else
    {
        /*
	 * RTS does not have primary_av field
	 */
        p_av_attr   = &qp_mod.state.rts.alternate_av;
        p_qp_opts   = &qp_mod.state.rts.opts;
        p_sq_depth  = &qp_mod.state.rts.sq_depth;
        p_rq_depth  = &qp_mod.state.rts.rq_depth;
    }

    if ( (ep_attr->max_recv_dtos > 0) &&
		((DAT_UINT32)ep_attr->max_recv_dtos != qp_attr.rq_depth) )
    {
	dapl_dbg_log (DAPL_DBG_TYPE_EP,"--> DsIQM: rq_depth modified (%d,%d)\n",
			qp_attr.rq_depth, ep_attr->max_recv_dtos);

        *p_rq_depth = ep_attr->max_recv_dtos;
        *p_qp_opts |= IB_MOD_QP_RQ_DEPTH;
        need_modify = DAT_TRUE;
    }

    if ( (ep_attr->max_request_dtos > 0) &&
		((DAT_UINT32)ep_attr->max_request_dtos != qp_attr.sq_depth) ) 
    {
	dapl_dbg_log (DAPL_DBG_TYPE_EP,
			"--> DsIQM: sq_depth modified (%d,%d)\n",
			qp_attr.sq_depth, ep_attr->max_request_dtos);

        *p_sq_depth = ep_attr->max_request_dtos;
        *p_qp_opts |= IB_MOD_QP_SQ_DEPTH;
        need_modify = DAT_TRUE;
    }

    qp_mod.req_state  = qp_state;

    if ( need_modify == DAT_TRUE )
    {
	ib_status = ib_modify_qp (qp_handle, &qp_mod);
        if ( ib_status != IB_SUCCESS)
        {
	    dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> %s: ib_status = %d\n",
                          "DsIQM", ib_status);
	    dat_status = DAT_INTERNAL_ERROR;
        }
    }

bail:

    return dat_status;
}


ib_api_status_t 
dapls_modify_qp_state_to_error ( ib_qp_handle_t  qp_handle )
{
    ib_qp_mod_t      qp_mod;
    ib_api_status_t  ib_status;

    dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsIQM_Err: QP state change --> Err\n");

    dapl_os_memzero (&qp_mod, sizeof (ib_qp_mod_t));

    qp_mod.req_state  = IB_QPS_ERROR;

    ib_status = ib_modify_qp (qp_handle, &qp_mod);

    return (ib_status);
}


ib_api_status_t 
dapls_modify_qp_state_to_reset ( ib_qp_handle_t  qp_handle )
{
    ib_qp_mod_t      qp_mod;
    ib_api_status_t  ib_status;

    dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsIQM_RESET: QP state change\n");

    dapl_os_memzero (&qp_mod, sizeof (ib_qp_mod_t));

    qp_mod.req_state  = IB_QPS_RESET;

    ib_status = ib_modify_qp (qp_handle, &qp_mod);

    return (ib_status);
}


ib_api_status_t 
dapls_modify_qp_state_to_init (
        IN    ib_qp_handle_t         qp_handle,
        IN    DAT_EP_ATTR            *p_attr,
        IN    dapl_ibal_port_t       *p_port )
{
    ib_qp_mod_t                   qp_mod;
    ib_api_status_t               ib_status;

    dapl_os_memzero (&qp_mod, sizeof (ib_qp_mod_t));

    qp_mod.req_state               = IB_QPS_INIT;
    qp_mod.state.init.primary_port = p_port->p_attr->port_num;
    qp_mod.state.init.qkey         = DAPL_IBAL_QKEY;
    qp_mod.state.init.pkey_index   = 0;
    qp_mod.state.init.access_ctrl = IB_AC_LOCAL_WRITE |
					IB_AC_RDMA_WRITE |
					IB_AC_MW_BIND |
					IB_AC_ATOMIC;
    if ((p_attr->max_rdma_read_in > 0) || (p_attr->max_rdma_read_out > 0))
    {
	qp_mod.state.init.access_ctrl |= IB_AC_RDMA_READ;
    }
    ib_status = ib_modify_qp (qp_handle, &qp_mod);

    dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsIQM_INIT: QP(%p) state change, %s\n",
                  qp_handle, ib_get_err_str(ib_status));

    return (ib_status);
}


ib_api_status_t 
dapls_modify_qp_state_to_rtr (
        ib_qp_handle_t          qp_handle,
        ib_net32_t              dest_qp,
        ib_lid_t                dest_lid,
        dapl_ibal_port_t        *p_port)
{
    ib_qp_mod_t                 qp_mod;
    ib_api_status_t             ib_status;

    dapl_os_memzero (&qp_mod, sizeof (ib_qp_mod_t));

    qp_mod.req_state                        = IB_QPS_RTR;
    qp_mod.state.rtr.rq_psn                 = DAPL_IBAL_START_PSN;
    qp_mod.state.rtr.dest_qp                = dest_qp;
    qp_mod.state.rtr.primary_av.port_num    = p_port->p_attr->port_num;
    qp_mod.state.rtr.primary_av.sl          = 0;
    qp_mod.state.rtr.primary_av.dlid        = dest_lid;
    qp_mod.state.rtr.primary_av.grh_valid   = 0; /* FALSE */
    qp_mod.state.rtr.primary_av.static_rate = IB_PATH_RECORD_RATE_10_GBS;
    qp_mod.state.rtr.primary_av.path_bits   = 0;
    qp_mod.state.rtr.primary_av.conn.path_mtu = p_port->p_attr->mtu;
    qp_mod.state.rtr.primary_av.conn.local_ack_timeout = 7;
    qp_mod.state.rtr.primary_av.conn.seq_err_retry_cnt = 7;
    qp_mod.state.rtr.primary_av.conn.rnr_retry_cnt = IB_RNR_RETRY_CNT;
    qp_mod.state.rtr.resp_res               = 4; // in-flight RDMAs
    qp_mod.state.rtr.rnr_nak_timeout        = IB_RNR_NAK_TIMEOUT;
 
    ib_status = ib_modify_qp (qp_handle, &qp_mod);
    
    dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsIQM_RTR: QP(%p) state change %s\n",
                  qp_handle, ib_get_err_str(ib_status));

    return (ib_status);
}

ib_api_status_t 
dapls_modify_qp_state_to_rts ( ib_qp_handle_t  qp_handle )
{
    ib_qp_mod_t        qp_mod;
    ib_api_status_t    ib_status;

    dapl_os_memzero (&qp_mod, sizeof (ib_qp_mod_t));

    qp_mod.req_state                   = IB_QPS_RTS;
    qp_mod.state.rts.sq_psn            = DAPL_IBAL_START_PSN;
    qp_mod.state.rts.retry_cnt         = 7;
    qp_mod.state.rts.rnr_retry_cnt     = IB_RNR_RETRY_CNT;
    qp_mod.state.rtr.rnr_nak_timeout   = IB_RNR_NAK_TIMEOUT;
    qp_mod.state.rts.local_ack_timeout = 7;
    qp_mod.state.rts.init_depth        = 4; 

    ib_status = ib_modify_qp (qp_handle, &qp_mod);

    dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsIQM_RTS: QP(%p) state change %s\n",
                  qp_handle, ib_get_err_str(ib_status));

    return (ib_status);
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
void
dapls_ib_reinit_ep ( IN DAPL_EP  *ep_ptr )
{
    DAPL_IA                  *ia_ptr;
    ib_api_status_t          ib_status;
    dapl_ibal_ca_t           *p_ca;
    dapl_ibal_port_t         *p_active_port;
	
    dapl_dbg_log (DAPL_DBG_TYPE_EP,
                  "--> DsIQM_REINIT: EP(%p) QP(%p) state change\n", 
                  ep_ptr, ep_ptr->qp_handle );

    if ( ep_ptr->param.ep_state != DAT_EP_STATE_DISCONNECTED )
    {
    	dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> DsIRE: EP invalid state(%d)\n",
                      ep_ptr->param.ep_state);
    	return /*DAT_INVALID_STATE*/;
    }

    ia_ptr = ep_ptr->header.owner_ia;

    /* Re-create QP if cleaned up, alloc will return init state */
    if ( ep_ptr->qp_handle == IB_INVALID_HANDLE )
    {
        dapl_dbg_log (DAPL_DBG_TYPE_EP,
                      "--> DsIRE: !EP(%p)->qp_handle, re-create QP\n",ep_ptr);
        ib_status = dapls_ib_qp_alloc ( ia_ptr, ep_ptr, ep_ptr );
        if ( ib_status != IB_SUCCESS )
        {
            dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> DsIRE: failed to move qp to RESET status = %s\n", 
                      ib_get_err_str(ib_status));
        }
        return /*ib_status*/;
    }

    ib_status = dapls_modify_qp_state_to_reset (ep_ptr->qp_handle);

    if ( ib_status != IB_SUCCESS )
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> DsIRE: failed to move qp to RESET status = %s\n", 
                      ib_get_err_str(ib_status));
        return /*DAT_INTERNAL_ERROR*/;
    }

    ep_ptr->qp_state = IB_QPS_RESET;

    p_ca   = (dapl_ibal_ca_t *) ia_ptr->hca_ptr->ib_hca_handle;
    p_active_port = dapli_ibal_get_port ( p_ca,
                                          (uint8_t)ia_ptr->hca_ptr->port_num );
    if (NULL == p_active_port)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                     "--> DsIRE: Port %d is not available = %d\n",
                     ia_ptr->hca_ptr->port_num, __LINE__);
        return /*DAT_INTERNAL_ERROR*/;
    }

	/* May fail if QP still RESET and in timewait, keep in reset state */
    ib_status = dapls_modify_qp_state_to_init ( ep_ptr->qp_handle,
                                                &ep_ptr->param.ep_attr,
                                                p_active_port);
    if ( ib_status != IB_SUCCESS )
    {
        ep_ptr->qp_state = IB_QPS_RESET;

        dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> DsIRE: failed to move qp to INIT status %s\n", 
                      ib_get_err_str(ib_status));
        return /*DAT_INTERNAL_ERROR*/;
    }
    ep_ptr->qp_state = IB_QPS_INIT;
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */

