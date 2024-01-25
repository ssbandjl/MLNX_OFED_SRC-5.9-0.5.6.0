
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
 * MODULE: dapl_ibal_cm.c
 *
 * PURPOSE: IB Connection routines for access to IBAL APIs
 *
 * $Id: dapl_ibal_cm.c 584 2007-02-07 13:12:18Z sleybo $
 *
 **********************************************************************/

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_cr_util.h"
#include "dapl_sp_util.h"
#include "dapl_ep_util.h"
#include "dapl_ia_util.h"
#include "dapl_ibal_util.h"
#include "dapl_name_service.h"
#include "dapl_ibal_name_service.h"
#include "dapl_cookie.h"

#define IB_INFINITE_SERVICE_LEASE   0xFFFFFFFF
#define  DAPL_ATS_SERVICE_ID        ATS_SERVICE_ID //0x10000CE100415453
#define  DAPL_ATS_NAME              ATS_NAME
#define  HCA_IPV6_ADDRESS_LENGTH    16

/* until dapl_ibal_util.h define of IB_INVALID_HANDLE which overlaps the
 * Windows ib_types.h typedef enu ib_api_status_t IB_INVALID_HANDLE is fixed.
 */
#undef IB_INVALID_HANDLE
#define DAPL_IB_INVALID_HANDLE NULL

int g_dapl_loopback_connection = 0;
extern dapl_ibal_root_t        dapl_ibal_root;

static void dapli_ib_cm_drep_cb (
	IN    ib_cm_drep_rec_t          *p_cm_drep_rec );

/*
 * Prototypes
 */

char *
dapli_ib_cm_event_str(ib_cm_events_t e)
{
#ifdef DBG
    char        *cp;
    static char *event_str[13] = {
        "IB_CME_CONNECTED",
        "IB_CME_DISCONNECTED",
        "IB_CME_DISCONNECTED_ON_LINK_DOWN",
        "IB_CME_CONNECTION_REQUEST_PENDING",
        "IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA",
        "IB_CME_DESTINATION_REJECT",
        "IB_CME_DESTINATION_REJECT_PRIVATE_DATA",
        "IB_CME_DESTINATION_UNREACHABLE",
        "IB_CME_TOO_MANY_CONNECTION_REQUESTS",
        "IB_CME_LOCAL_FAILURE",
        "IB_CME_REPLY_RECEIVED",
        "IB_CME_REPLY_RECEIVED_PRIVATE_DATA",
        "IB_CM_LOCAL_FAILURE"
    };

    if (e > IB_CM_LOCAL_FAILURE || e < IB_CME_CONNECTED)
	cp =  "BAD EVENT";
    else
        cp = event_str[e];

    return cp;
#else
    static char num[8];
    sprintf(num,"%d",e);
    return num;
#endif
}


#if defined(DAPL_DBG)

void dapli_print_private_data( char *prefix, const uint8_t *pd, int len )
{
    int i;
            
    if ( !pd || len <= 0 )
	return;

    dapl_log ( DAPL_DBG_TYPE_CM, "--> %s: private_data(len %d)\n    ",prefix,len);

    if (len > IB_MAX_REP_PDATA_SIZE)
    {
    	dapl_log ( DAPL_DBG_TYPE_ERR,
		"    Private data size(%d) > Max(%d), ignored.\n    ",
					len,DAPL_MAX_PRIVATE_DATA_SIZE);
	len = IB_MAX_REP_PDATA_SIZE;
    }

    for ( i = 0 ; i < len; i++ )
    {
	dapl_log ( DAPL_DBG_TYPE_CM, "%2x ", pd[i]);
	if ( ((i+1) % 5) == 0 ) 
	    dapl_log ( DAPL_DBG_TYPE_CM, "\n    ");
    }
   dapl_log ( DAPL_DBG_TYPE_CM, "\n");
}
#endif

/* EP-CM linking support */
dp_ib_cm_handle_t ibal_cm_alloc(void)
{
	dp_ib_cm_handle_t cm_ptr;

	/* Allocate CM, init lock, and initialize */
	if ((cm_ptr = dapl_os_alloc(sizeof(*cm_ptr))) == NULL)
		return NULL;

	(void)dapl_os_memzero(cm_ptr, sizeof(*cm_ptr));
	cm_ptr->ref_count = 1;

	if (dapl_os_lock_init(&cm_ptr->lock)) {
		dapl_os_free(cm_ptr, sizeof(*cm_ptr));
		return NULL;
	}

	dapl_llist_init_entry((DAPL_LLIST_ENTRY *)&cm_ptr->list_entry);
	
	return cm_ptr;
}

/* free CM object resources */
static void ibal_cm_dealloc(dp_ib_cm_handle_t cm_ptr) 
{
	dapl_os_assert(!cm_ptr->ref_count);
	dapl_os_lock_destroy(&cm_ptr->lock);
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
                dapl_os_unlock(&cm_ptr->lock);
		return;
	}
	dapl_os_unlock(&cm_ptr->lock);
	ibal_cm_dealloc(cm_ptr);
}

/* blocking: called from user thread dapl_ep_free() only */
void dapls_cm_free(dp_ib_cm_handle_t cm_ptr)
{
	dapl_ep_unlink_cm(cm_ptr->ep, cm_ptr);

	/* final reference, alloc */
	dapls_cm_release(cm_ptr);
}

static void 
dapli_ib_cm_apr_cb (
        IN    ib_cm_apr_rec_t          *p_cm_apr_rec )
{
    UNUSED_PARAM( p_cm_apr_rec );

    dapl_dbg_log (DAPL_DBG_TYPE_CM, 
                  "--> DiCAcb: CM callback APR (Alternate Path Request)\n");
}

static void 
dapli_ib_cm_lap_cb (
        IN    ib_cm_lap_rec_t          *p_cm_lap_rec )
{
    UNUSED_PARAM( p_cm_lap_rec );

    dapl_dbg_log (DAPL_DBG_TYPE_CM, 
                  "--> DiCLcb: CM callback LAP (Load Alternate Path)\n");
}

static DAT_RETURN dapli_send_ib_cm_dreq(ib_cm_handle_t h_cm)
{
	ib_cm_dreq_t cm_dreq;

	dapl_os_memzero(&cm_dreq, sizeof(ib_cm_dreq_t));

	cm_dreq.flags = IB_FLAGS_SYNC;
	cm_dreq.qp_type = IB_QPT_RELIABLE_CONN;
	cm_dreq.h_qp = h_cm.h_qp;
	cm_dreq.pfn_cm_drep_cb = dapli_ib_cm_drep_cb;

	return dapl_ib_status_convert(ib_cm_dreq(&cm_dreq));
}

static DAT_RETURN dapli_send_ib_cm_drep(ib_cm_handle_t h_cm)
{
    ib_cm_drep_t cm_drep;

    dapl_os_memzero(&cm_drep, sizeof(ib_cm_drep_t));
	return dapl_ib_status_convert(ib_cm_drep(h_cm, &cm_drep));
}

/*
 * Connection Disconnect Request callback
 * We received a DREQ, return a DREP (disconnect reply).
 */

static void 
dapli_ib_cm_dreq_cb (
        IN    ib_cm_dreq_rec_t          *p_cm_dreq_rec )
{
    DAPL_EP             *ep_ptr;
    dp_ib_cm_handle_t	cm_ptr;
    
    dapl_os_assert (p_cm_dreq_rec);

    ep_ptr  = (DAPL_EP * __ptr64) p_cm_dreq_rec->qp_context;
    if ( DAPL_BAD_PTR(ep_ptr) )
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, 
                      "--> %s: BAD_PTR EP %lx\n", __FUNCTION__, ep_ptr);
        goto send_drep;
    }
    if ( ep_ptr->header.magic != DAPL_MAGIC_EP  )
    {
        if ( ep_ptr->header.magic == DAPL_MAGIC_INVALID )
            goto send_drep;

        dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> %s: EP %p BAD_EP_MAGIC %x != wanted %x\n",
		       __FUNCTION__, ep_ptr, ep_ptr->header.magic,
		       DAPL_MAGIC_EP );
        goto send_drep;
    }
    cm_ptr = dapl_get_cm_from_ep(ep_ptr);
    if (!cm_ptr)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> %s: !CM_PTR on EP %p\n", __FUNCTION__, ep_ptr);
        goto send_drep;
    }
    dapl_os_assert(cm_ptr->ib_cm.h_qp == p_cm_dreq_rec->h_cm_dreq.h_qp);

    dapl_dbg_log (DAPL_DBG_TYPE_CM, 
                  "--> %s() EP %p, %s\n",
                  __FUNCTION__,ep_ptr,
                  dapl_get_ep_state_str(ep_ptr->param.ep_state));

    dapl_os_lock (&ep_ptr->header.lock);
    if ( ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED )
    {
        dapl_dbg_log (DAPL_DBG_TYPE_CM, 
                      "--> DiCDcb: EP %lx QP %lx already Disconnected\n",
                      ep_ptr, ep_ptr->qp_handle);
        goto unlock;
    }

    ep_ptr->param.ep_state = DAT_EP_STATE_DISCONNECT_PENDING;

    if (cm_ptr->state == IBAL_CM_CONNECT)
    {
	    cm_ptr->state = IBAL_CM_DREQ;
	    cm_ptr->ib_cm = p_cm_dreq_rec->h_cm_dreq;
    }
    else
    {
	    dapli_send_ib_cm_drep(p_cm_dreq_rec->h_cm_dreq);
    }
    dapl_os_unlock (&ep_ptr->header.lock);

    if (ep_ptr->cr_ptr)
    {
        /* passive side */
        dapls_cr_callback ( cm_ptr,
                            IB_CME_DISCONNECTED,
                            (void * __ptr64) p_cm_dreq_rec->p_dreq_pdata,
							IB_DREQ_PDATA_SIZE,
                            (void *) (((DAPL_CR *) ep_ptr->cr_ptr)->sp_ptr) );
    }
    else
    {
        /* active side */
        dapl_evd_connection_callback (
                                  cm_ptr,
                                  IB_CME_DISCONNECTED,
                                  (void * __ptr64)
                                  p_cm_dreq_rec->p_dreq_pdata,
								  IB_DREQ_PDATA_SIZE,
                                  p_cm_dreq_rec->qp_context );
    }
    return;

unlock:
	dapl_os_unlock (&ep_ptr->header.lock);
send_drep:
    dapli_send_ib_cm_drep(p_cm_dreq_rec->h_cm_dreq);
}

/*
 * Connection Disconnect Reply callback
 * We sent a DREQ and received a DREP.
 */

static void 
dapli_ib_cm_drep_cb (
        IN    ib_cm_drep_rec_t          *p_cm_drep_rec )
{
    DAPL_EP            *ep_ptr;
    dp_ib_cm_handle_t	cm_ptr;
    
    dapl_os_assert (p_cm_drep_rec != NULL);

    ep_ptr  = (DAPL_EP * __ptr64) p_cm_drep_rec->qp_context;

    if (p_cm_drep_rec->cm_status)
    {
         dapl_dbg_log (DAPL_DBG_TYPE_CM,
                  "--> %s: DREP cm_status(%s) EP=%p\n", __FUNCTION__,
                  ib_get_err_str(p_cm_drep_rec->cm_status), ep_ptr); 
    }

    if ( DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP) )
    {
         dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                  "--> %s: BAD EP Handle EP=%lx\n", __FUNCTION__,ep_ptr); 
        return;
    }
    cm_ptr = dapl_get_cm_from_ep(ep_ptr);
    if (!cm_ptr)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> %s: !CM_PTR on EP %p\n", __FUNCTION__, ep_ptr);
        return;
    }
    dapl_os_assert(cm_ptr->ib_cm.h_qp == p_cm_drep_rec->h_qp);
    
    dapl_dbg_log (DAPL_DBG_TYPE_CM, 
		"--> DiCDpcb: EP %p state %s cm_hdl %p\n",ep_ptr,
		dapl_get_ep_state_str(ep_ptr->param.ep_state), cm_ptr);

    if ( ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED )
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, 
                      "--> DiCDpcb: EP %lx QP %lx already Disconnected\n",
                      ep_ptr, ep_ptr->qp_handle);
        return;
    }

    if (ep_ptr->cr_ptr)
    {
        /* passive connection side */
        dapls_cr_callback ( cm_ptr,
                            IB_CME_DISCONNECTED,
                           (void * __ptr64) p_cm_drep_rec->p_drep_pdata,
						   IB_DREP_PDATA_SIZE,
                           (void *) (((DAPL_CR *) ep_ptr->cr_ptr)->sp_ptr) );
    }
    else
    {
        /* active connection side */
        dapl_evd_connection_callback (
                                   cm_ptr,
                                   IB_CME_DISCONNECTED,
                                   (void * __ptr64) p_cm_drep_rec->p_drep_pdata,
								   IB_DREP_PDATA_SIZE,
                                   p_cm_drep_rec->qp_context );
    }
}

/*
 * CM reply callback
 */

static void 
dapli_ib_cm_rep_cb (
        IN    ib_cm_rep_rec_t          *p_cm_rep_rec )
{
    ib_api_status_t     ib_status; 
    ib_cm_rtu_t         cm_rtu;
    uint8_t             cm_cb_op;
    DAPL_PRIVATE        *prd_ptr;
    DAPL_EP             *ep_ptr;
    dapl_ibal_ca_t      *p_ca;
    dp_ib_cm_handle_t	cm_ptr;
        
    dapl_os_assert (p_cm_rep_rec != NULL);

    ep_ptr  = (DAPL_EP * __ptr64) p_cm_rep_rec->qp_context;

    if ( DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP) )
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> %s: EP %lx invalid or FREED\n",
                      __FUNCTION__, ep_ptr);
        return;
    }
    cm_ptr = dapl_get_cm_from_ep(ep_ptr);
    if (!cm_ptr)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> %s: !CM_PTR on EP %p\n", __FUNCTION__, ep_ptr);
        return;
    }
    dapl_os_assert(cm_ptr->ib_cm.h_qp == p_cm_rep_rec->h_cm_rep.h_qp);

    dapl_dbg_log (DAPL_DBG_TYPE_CM, 
                  "--> DiCRpcb: EP %lx local_max_rdma_read_in %d\n", 
                  ep_ptr, p_cm_rep_rec->resp_res);

    p_ca   = (dapl_ibal_ca_t *) 
             ep_ptr->header.owner_ia->hca_ptr->ib_hca_handle;

    dapl_os_memzero (&cm_rtu, sizeof ( ib_cm_rtu_t ));
    cm_rtu.pfn_cm_apr_cb  = dapli_ib_cm_apr_cb;
    cm_rtu.pfn_cm_dreq_cb = dapli_ib_cm_dreq_cb;
    cm_rtu.p_rtu_pdata    = NULL;
    cm_rtu.access_ctrl = 
		IB_AC_LOCAL_WRITE|IB_AC_RDMA_WRITE|IB_AC_MW_BIND|IB_AC_ATOMIC;
    if ((ep_ptr->param.ep_attr.max_rdma_read_in > 0) || 
		(ep_ptr->param.ep_attr.max_rdma_read_out > 0))
    {
    	cm_rtu.access_ctrl |= IB_AC_RDMA_READ;
    }
	    
    cm_rtu.rq_depth       = 0;
    cm_rtu.sq_depth       = 0;
       
    ib_status = ib_cm_rtu (p_cm_rep_rec->h_cm_rep, &cm_rtu);

    if (ib_status == IB_SUCCESS)
    {
        cm_cb_op = IB_CME_CONNECTED;
        dapl_dbg_log (DAPL_DBG_TYPE_CM, 
                  "--> DiCRpcb: EP %lx Connected req_count %d\n", 
                  ep_ptr, dapls_cb_pending(&ep_ptr->req_buffer));
    }
    else
    {
        cm_cb_op = IB_CME_LOCAL_FAILURE;
    }

    prd_ptr = (DAPL_PRIVATE * __ptr64) p_cm_rep_rec->p_rep_pdata;

#if defined(DAPL_DBG) && 0
    dapli_print_private_data( "DiCRpcb",
			      prd_ptr->private_data,
			      IB_MAX_REP_PDATA_SIZE);
#endif

    dapl_evd_connection_callback ( 
                            cm_ptr,
                            cm_cb_op,
                            (void *) prd_ptr,
			    IB_REP_PDATA_SIZE,
                            (void * __ptr64) p_cm_rep_rec->qp_context);
}


static void 
dapli_ib_cm_rej_cb (
        IN    ib_cm_rej_rec_t          *p_cm_rej_rec )
{
    DAPL_EP         *ep_ptr;
    ib_cm_events_t  cm_event;
    dp_ib_cm_handle_t	cm_ptr;

    dapl_os_assert (p_cm_rej_rec);

    ep_ptr = (DAPL_EP * __ptr64) p_cm_rej_rec->qp_context;

    if ( DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP) )
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> %s: EP %lx invalid or FREED\n",
                      __FUNCTION__, ep_ptr);
        return;
    }
    cm_ptr = dapl_get_cm_from_ep(ep_ptr);
    if (!cm_ptr)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, 
                      "--> %s: !CM_PTR on EP %p\n", __FUNCTION__, ep_ptr);
        return;
    }
    dapl_os_assert(cm_ptr->ib_cm.h_qp == p_cm_rej_rec->h_qp);

    dapl_dbg_log (DAPL_DBG_TYPE_CM, 
                  "--> DiCRjcb: EP = %lx QP = %lx rej reason = 0x%x\n", 
                  ep_ptr,ep_ptr->qp_handle,CL_NTOH16(p_cm_rej_rec->rej_status));

    switch (p_cm_rej_rec->rej_status)
    {
        case IB_REJ_INSUF_RESOURCES:
        case IB_REJ_INSUF_QP:
        case IB_REJ_INVALID_COMM_ID:
        case IB_REJ_INVALID_COMM_INSTANCE:
        case IB_REJ_INVALID_PKT_RATE:
        case IB_REJ_INVALID_ALT_GID:
        case IB_REJ_INVALID_ALT_LID:
        case IB_REJ_INVALID_ALT_SL:
        case IB_REJ_INVALID_ALT_TRAFFIC_CLASS:
        case IB_REJ_INVALID_ALT_PKT_RATE:
        case IB_REJ_INVALID_ALT_HOP_LIMIT:
        case IB_REJ_INVALID_ALT_FLOW_LBL:
        case IB_REJ_INVALID_GID:
        case IB_REJ_INVALID_LID:
        case IB_REJ_INVALID_SID:
        case IB_REJ_INVALID_SL:
        case IB_REJ_INVALID_TRAFFIC_CLASS:
        case IB_REJ_PORT_REDIRECT:
        case IB_REJ_INVALID_MTU:
        case IB_REJ_INSUFFICIENT_RESP_RES:
        case IB_REJ_INVALID_CLASS_VER:
        case IB_REJ_INVALID_FLOW_LBL:
            cm_event = IB_CME_DESTINATION_REJECT;
            break;

        case IB_REJ_TIMEOUT:
            cm_event = IB_CME_DESTINATION_UNREACHABLE;
            dapl_dbg_log (DAPL_DBG_TYPE_CM, "--> DiCRjcb: CR TIMEOUT\n");
            break;

        case IB_REJ_USER_DEFINED:
            cm_event = IB_CME_DESTINATION_REJECT;
            dapl_dbg_log (DAPL_DBG_TYPE_CM, 
                               "--> DiCRjcb: user defined rej reason %s\n",
                               p_cm_rej_rec->p_ari);
            break;

        default:
            cm_event = IB_CME_LOCAL_FAILURE;
            dapl_dbg_log (DAPL_DBG_TYPE_CM, 
                               "--> DiCRjcb: with unknown status %x\n", 
                               p_cm_rej_rec->rej_status);
            break;
     }

    /* FIXME - Vu
     * We do not take care off the user defined rej reason with additional 
     * rejection information (p_ari)
     */

    if (ep_ptr->cr_ptr)
    {
        dapls_cr_callback ( cm_ptr,
                            cm_event,
                            (void * __ptr64) p_cm_rej_rec->p_rej_pdata,
			    IB_REJ_PDATA_SIZE,
                            (void *) ((DAPL_CR *) ep_ptr->cr_ptr)->sp_ptr);
    }
    else
    {
        dapl_evd_connection_callback (
                                   cm_ptr,
                                   cm_event,
                                   (void * __ptr64) p_cm_rej_rec->p_rej_pdata,
				   IB_REJ_PDATA_SIZE,
                                   (void * __ptr64) p_cm_rej_rec->qp_context );
    }

}



static void 
dapli_ib_cm_req_cb ( IN  ib_cm_req_rec_t  *p_cm_req_rec )
{
    DAPL_SP              *sp_ptr;
    DAT_SOCK_ADDR6       dest_ia_addr;
    dp_ib_cm_handle_t    cm_ptr;

    dapl_os_assert (p_cm_req_rec);

    sp_ptr = (DAPL_SP * __ptr64) p_cm_req_rec->context;

    dapl_os_assert (sp_ptr);

    /*
     * The context pointer could have been cleaned up in a racing
     * CM callback, check to see if we should just exit here
     */
    if (sp_ptr->header.magic == DAPL_MAGIC_INVALID)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_CM,
                     "%s: BAD-Magic in SP %lx, racing CM callback?\n",
                      __FUNCTION__, sp_ptr );
	return;
    }

    dapl_os_assert ( sp_ptr->header.magic == DAPL_MAGIC_PSP || 
                     sp_ptr->header.magic == DAPL_MAGIC_RSP );

    /* preserve ibal's connection handle storage so we have a consistent
     * pointer value. The reasons this is done dynamically instead of a static
     * allocation in an end_point is the pointer value is set in the SP list
     * of CR's here and searched for from disconnect callbacks. If the pointer
     * value changes, you never find the CR on the sp list...
     * EP struct deallocation is where this memory is released or prior in the
     * error case.
     */
    cm_ptr = ibal_cm_alloc();
    if (!cm_ptr)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "%s: FAILED to alloc IB CM handle storage?\n",
                       __FUNCTION__);
        return;
    }

    /*
     * Save the cm_srvc_handle to avoid the race condition between
     * the return of the ib_cm_listen and the notification of a conn req
     */
    if (sp_ptr->cm_srvc_handle != p_cm_req_rec->h_cm_listen)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_CM | DAPL_DBG_TYPE_CALLBACK, 
                           "--> DiCRqcb: cm_service_handle is changed\n"); 
        sp_ptr->cm_srvc_handle = p_cm_req_rec->h_cm_listen;
    }

    dapl_os_memzero (&dest_ia_addr, sizeof (dest_ia_addr));

#ifdef NO_NAME_SERVICE

    {
        DAPL_PRIVATE *prd_ptr;
        
        prd_ptr = (DAPL_PRIVATE *)p_cm_req_rec->p_req_pdata;

        dapl_os_memcpy ((void *)&dest_ia_addr,
                        (void *)&prd_ptr->hca_address,
                        sizeof (DAT_SOCK_ADDR6));        
    }
    
#else

    {
        GID            dest_gid;

        dapl_os_memzero (&dest_gid, sizeof (dest_gid));

        dest_gid.guid = p_cm_req_rec->primary_path.dgid.unicast.interface_id;
        dest_gid.gid_prefix = p_cm_req_rec->primary_path.dgid.unicast.prefix;

        if (DAT_SUCCESS != dapls_ns_map_ipaddr (
                                 sp_ptr->header.owner_ia->hca_ptr,
                                 dest_gid,
                                 (DAT_IA_ADDRESS_PTR)&dest_ia_addr))
        {
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                           "cm_req_cb: SP = %lx failed mapping GID-IPaddr\n",
                           sp_ptr);
        }
    }

#endif /* NO_NAME_SERVICE */

    /* preserve CR cm handle data */
    dapl_os_memcpy( (void*)&cm_ptr->ib_cm,
                    (void*)&p_cm_req_rec->h_cm_req,
                    sizeof(ib_cm_handle_t));

    /* preserve remote IP address */
    dapl_os_memcpy( (void*)&cm_ptr->dst_ip_addr,
                    (void*)&dest_ia_addr,
                    sizeof(dest_ia_addr));

#if defined(DAPL_DBG)
    {
        char ipa[20];
  
        //rval = ((struct sockaddr_in *) (&dest_ia_addr))->sin_addr.s_addr;

        dapl_dbg_log (DAPL_DBG_TYPE_CM|DAPL_DBG_TYPE_CALLBACK, 
                      "%s: query SA (CM %lx)->dst_ip_addr: %s\n",
                      __FUNCTION__,cm_ptr,
                      dapli_get_ip_addr_str(
				(DAT_SOCK_ADDR6*) &cm_ptr->dst_ip_addr, ipa) );
    }
#endif

    /* FIXME - Vu
     * We have NOT used/saved the primary and alternative path record
     * ie. p_cm_req_rec->p_primary_path and p_cm_req_rec->p_alt_path
     * We should cache some fields in path record in the Name Service DB
     * such as: dgid, dlid
     * Also we do not save resp_res (ie. max_oustanding_rdma_read/atomic)
     * rnr_retry_cnt and flow_ctrl fields
     */
    dapl_dbg_log (DAPL_DBG_TYPE_CM,
                  "%s: SP %lx max_rdma_read %d PrivateData %lx\n",
                  __FUNCTION__, sp_ptr, p_cm_req_rec->resp_res,
                  p_cm_req_rec->p_req_pdata);

    dapls_cr_callback ( cm_ptr,
                        IB_CME_CONNECTION_REQUEST_PENDING,
                        (void * __ptr64) p_cm_req_rec->p_req_pdata,
						IB_REQ_PDATA_SIZE,
                        (void * __ptr64) sp_ptr );
}


static void 
dapli_ib_cm_mra_cb (
        IN    ib_cm_mra_rec_t          *p_cm_mra_rec )
{
	UNUSED_PARAM( p_cm_mra_rec );
	dapl_dbg_log (DAPL_DBG_TYPE_CM | DAPL_DBG_TYPE_CALLBACK, 
                       "--> DiCMcb: CM callback MRA\n");
}

static void 
dapli_ib_cm_rtu_cb (
        IN    ib_cm_rtu_rec_t          *p_cm_rtu_rec )
{
    DAPL_EP         	*ep_ptr;
    dp_ib_cm_handle_t	cm_ptr;

    dapl_os_assert (p_cm_rtu_rec != NULL);
   
    ep_ptr = (DAPL_EP * __ptr64) p_cm_rtu_rec->qp_context;

    if ( DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP) )
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> %s: EP %lx invalid or FREED\n",
                      __FUNCTION__, ep_ptr);
        return;
    }
    cm_ptr = dapl_get_cm_from_ep(ep_ptr);
    if (!cm_ptr)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> %s: !CM_PTR on EP %p\n", __FUNCTION__, ep_ptr);
        return;
    }
    dapl_os_assert(cm_ptr->ib_cm.h_qp == p_cm_rtu_rec->h_qp);

    dapl_dbg_log (DAPL_DBG_TYPE_CM | DAPL_DBG_TYPE_CALLBACK, 
                  "--> DiCRucb: EP %lx QP %lx CR %lx\n",
                  ep_ptr, ep_ptr->qp_handle, ep_ptr->cr_ptr); 

    if (ep_ptr->cr_ptr)
    {
        DAPL_SP  *sp_ptr;

        sp_ptr = ((DAPL_CR *) ep_ptr->cr_ptr)->sp_ptr;

        /* passive connection side */
        dapls_cr_callback ( cm_ptr,
                            IB_CME_CONNECTED,
                            (void * __ptr64) p_cm_rtu_rec->p_rtu_pdata,
                            IB_RTU_PDATA_SIZE,
                            (void *) sp_ptr);
                            
    }
    else
    {
        dapl_evd_connection_callback ( 
                            cm_ptr,
                            IB_CME_CONNECTED,
                            (void * __ptr64) p_cm_rtu_rec->p_rtu_pdata,
			    IB_RTU_PDATA_SIZE,
                            (void *) ep_ptr);
    }
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
dapls_ib_cm_remote_addr (
    IN      DAT_HANDLE          dat_handle,
    OUT     DAT_SOCK_ADDR6      *remote_address )
{

    DAPL_HEADER        *header;
    dp_ib_cm_handle_t  cm;
    char               ipa[20];
    char               *rtype;

    header = (DAPL_HEADER *)dat_handle;

    if (header->magic == DAPL_MAGIC_EP) 
    {
    	cm = dapl_get_cm_from_ep((DAPL_EP *)dat_handle);
	rtype = "EP";
    }
    else if (header->magic == DAPL_MAGIC_CR) 
    {
    	cm = ((DAPL_CR *) dat_handle)->ib_cm_handle;
	rtype = "CR";
    }
    else 
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_CM,
                       "%s: hdr->magic %x, dat_handle(%lx)\n",
                       __FUNCTION__, header->magic, dat_handle );
    	return DAT_INVALID_HANDLE;
    }

    dapl_os_memcpy( remote_address, &cm->dst_ip_addr, sizeof(DAT_SOCK_ADDR6) );

    dapl_dbg_log ( DAPL_DBG_TYPE_CM, "%s: returns %s remote Addrs %s\n",
                   __FUNCTION__, rtype,
                   dapli_get_ip_addr_str((DAT_SOCK_ADDR6*)remote_address,ipa) );

    return DAT_SUCCESS;
}


/*
 * dapls_ib_connect
 *
 * Initiate a connection with the passive listener on another node
 *
 * Input:
 *        ep_handle,
 *        remote_ia_address,
 *        remote_conn_qual,
 *          prd_size                size of private data and structure
 *          prd_prt                pointer to private data structure
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
dapls_ib_connect (
        IN        DAT_EP_HANDLE                ep_handle,
        IN        DAT_IA_ADDRESS_PTR           remote_ia_address,
        IN        DAT_CONN_QUAL                remote_conn_qual,
        IN        DAT_COUNT                    private_data_size,
        IN        DAT_PVOID                    private_data )
{
    DAPL_EP                      *ep_ptr;
    DAPL_IA                      *ia_ptr;
    ib_api_status_t              ib_status;
    dapl_ibal_port_t             *p_active_port;
    dapl_ibal_ca_t               *p_ca;
    ib_cm_req_t                  cm_req;
    ib_path_rec_t                path_rec;
    GID                          dest_GID;
    ib_query_req_t               query_req;
    ib_gid_pair_t                gid_pair;
    ib_service_record_t          service_rec;
    int                          retry_cnt;
    DAT_RETURN                   dat_status;

    ep_ptr         = (DAPL_EP *) ep_handle;
    ia_ptr         = ep_ptr->header.owner_ia;
    ep_ptr->cr_ptr = NULL;
    retry_cnt      = 0;
    dat_status     = DAT_SUCCESS;

    p_ca = (dapl_ibal_ca_t *) ia_ptr->hca_ptr->ib_hca_handle;

    /*
     * We are using the first active port in the list for
     * communication. We have to get back here when we decide to support
     * fail-over and high-availability.
     */
    p_active_port = dapli_ibal_get_port ( p_ca,
                                          (uint8_t)ia_ptr->hca_ptr->port_num );

    if (NULL == p_active_port)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"--> DsC: Port %d not available %d\n",
                       ia_ptr->hca_ptr->port_num, __LINE__ );
        return (DAT_INVALID_STATE);
    }

    dapl_os_memzero (&dest_GID, sizeof (GID));
    dapl_os_memzero (&cm_req, sizeof (ib_cm_req_t));
    dapl_os_memzero (&path_rec, sizeof (ib_path_rec_t));
    dapl_os_memzero (&service_rec, sizeof (ib_service_record_t));
    dapl_os_memzero (&query_req, sizeof (ib_query_req_t));
    dapl_os_memzero (&gid_pair, sizeof (ib_gid_pair_t));
    dapl_os_memzero (&ep_ptr->remote_ia_address, sizeof (DAT_SOCK_ADDR6));

    dapl_os_memcpy (&ep_ptr->remote_ia_address, 
                    remote_ia_address, 
                    sizeof (ep_ptr->remote_ia_address));


#ifdef NO_NAME_SERVICE

    if (DAT_SUCCESS !=
        (dat_status = dapls_ns_lookup_address (
                                         ia_ptr,
                                         remote_ia_address,
                                         &dest_GID         )))
    {
        /*
         * Remote address not in the table, this is a
         * strange return code!
         */
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"--> DsC: exits status = %x\n", dat_status);
        return dat_status;
    }

    dest_GID.guid = CL_HTON64 (dest_GID.guid);
    dest_GID.gid_prefix = CL_HTON64 (dest_GID.gid_prefix);

#else

    /*
     * We query the SA to get the dest_gid with the 
     * {uDAPL_svc_id, IP-address} as the key to get GID.
     */
    if (DAT_SUCCESS !=
        (dat_status = dapls_ns_map_gid (ia_ptr->hca_ptr, 
                                        remote_ia_address,
                                        &dest_GID)))
        
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR, "--> DsC: fail to map remote_ia_addr "
                       "(sa_family %d) to gid\n",
                       remote_ia_address->sa_family); 
        return dat_status;
    }
#endif /* NO_NAME_SERVICE */

    gid_pair.dest_gid.unicast.interface_id = dest_GID.guid;
    gid_pair.dest_gid.unicast.prefix       = dest_GID.gid_prefix;

    dapl_dbg_log (DAPL_DBG_TYPE_CM, 
                  "dapls_ib_connect: EP %lx QP %lx SERVER GID{0x" F64x
                  ", 0x" F64x "}\n", 
                  ep_ptr, ep_ptr->qp_handle,
                  cl_hton64 (gid_pair.dest_gid.unicast.prefix),
                  cl_hton64 (gid_pair.dest_gid.unicast.interface_id));

    gid_pair.src_gid = p_active_port->p_attr->p_gid_table[0];
/*
    if ((gid_pair.src_gid.unicast.interface_id == 
         gid_pair.dest_gid.unicast.interface_id   ) &&
        (gid_pair.src_gid.unicast.prefix == 
         gid_pair.dest_gid.unicast.prefix   ))
    {
        path_rec.dgid     = gid_pair.dest_gid;
        path_rec.sgid     = gid_pair.src_gid;
        path_rec.slid     = path_rec.dlid = p_active_port->p_attr->lid;
        path_rec.pkey     = p_active_port->p_attr->p_pkey_table[0];
        path_rec.mtu      = p_active_port->p_attr->mtu;
		path_rec.pkt_life = 18;  // 1 sec
		path_rec.rate     = IB_PATH_RECORD_RATE_10_GBS;
	
	}
    else
    {
  */
        /*
         * Query SA to get the path record from pair of GIDs
         */
        dapl_os_memzero (&query_req, sizeof (ib_query_req_t));
        query_req.query_type      = IB_QUERY_PATH_REC_BY_GIDS;
        query_req.p_query_input   = (void *) &gid_pair;
        query_req.flags           = IB_FLAGS_SYNC;  
        query_req.timeout_ms      = 1 * 1000;       /* 1 second */
        query_req.retry_cnt       = 3;
        /* query SA using this port */
        query_req.port_guid       = p_active_port->p_attr->port_guid;
        query_req.query_context   = (void *) &path_rec;
        query_req.pfn_query_cb    = dapli_ib_sa_query_cb;
 
        ib_status = ib_query (dapl_ibal_root.h_al, &query_req, NULL);

        if ((ib_status != IB_SUCCESS) || (!path_rec.dlid))
        {
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"--> DsC: EP %lx QP %lx query "
                           "pair_gids status = %s\n", 
                           ep_ptr, ep_ptr->qp_handle,ib_get_err_str(ib_status));
            return DAT_INVALID_PARAMETER;
        }

    //}

	/*
	 * Tavor has a HW bug that causes bandwidth with 2K MTU to be less than
	 * with 1K MTU.  Cap the MTU based on device ID to compensate for this.
	 */
	if( (p_ca->p_ca_attr->dev_id == 0x5A44) &&
		(ib_path_rec_mtu( &path_rec ) > IB_MTU_LEN_1024) )
	{
            /* Local endpoint is Tavor - cap MTU to 1K for extra bandwidth. */
            path_rec.mtu &= IB_PATH_REC_SELECTOR_MASK;
            path_rec.mtu |= IB_MTU_LEN_1024;
	}

	/* 
     * prepare the Service ID from conn_qual 
     */
    cm_req.svc_id           = remote_conn_qual;
    cm_req.p_primary_path   = &path_rec;
    cm_req.p_alt_path       = NULL;
    cm_req.h_qp             = ep_ptr->qp_handle;
    cm_req.qp_type          = IB_QPT_RELIABLE_CONN;
    cm_req.p_req_pdata      = (uint8_t *) private_data;
    cm_req.req_length       = (uint8_t)
				min(private_data_size,IB_MAX_REQ_PDATA_SIZE);
    /* cm retry to send this request messages, IB max of 4 bits */
    cm_req.max_cm_retries   = 15; /* timer outside of call, s/be infinite */
    /* qp retry to send any wr */
    cm_req.retry_cnt        = 5;
    /* max num of oustanding RDMA read/atomic support */
    cm_req.resp_res         = (uint8_t)ep_ptr->param.ep_attr.max_rdma_read_in;
    /* max num of oustanding RDMA read/atomic will use */
    cm_req.init_depth       = (uint8_t)ep_ptr->param.ep_attr.max_rdma_read_out;

    /* time wait before retrying a pkt after receiving a RNR NAK */
    cm_req.rnr_nak_timeout  = IB_RNR_NAK_TIMEOUT;
    
	/* 
     * number of time local QP should retry after receiving RNR NACK before
     * reporting an error
     */
    cm_req.rnr_retry_cnt       = IB_RNR_RETRY_CNT;

    cm_req.remote_resp_timeout = 16;	/* 250ms */
    cm_req.local_resp_timeout  = 16;	/* 250ms */
    
    cm_req.flow_ctrl           = TRUE;
    cm_req.flags               = 0;
    /*
     * We do not use specific data buffer to check for specific connection
     */
    cm_req.p_compare_buffer    = NULL;
    cm_req.compare_offset      = 0;
    cm_req.compare_length      = 0;

    dapl_dbg_log (DAPL_DBG_TYPE_CM, "--> DsConn: EP=%lx QP=%lx rio=%d,%d pl=%d "
                  "mtu=%d slid=%#x dlid=%#x\n", 
                  ep_ptr, ep_ptr->qp_handle,  cm_req.resp_res, 
                  cm_req.init_depth, ib_path_rec_pkt_life(&path_rec),
                  ib_path_rec_mtu(&path_rec),
                  cm_req.p_primary_path->slid,
                  cm_req.p_primary_path->dlid);

    /*
     * We do not support peer_to_peer; therefore, we set pfn_cm_req_cb = NULL
     */
    cm_req.pfn_cm_req_cb       = NULL;
    cm_req.pfn_cm_rep_cb       = dapli_ib_cm_rep_cb;
    cm_req.pfn_cm_rej_cb       = dapli_ib_cm_rej_cb;
    /* callback when a message received acknowledgement is received */
    cm_req.pfn_cm_mra_cb       = dapli_ib_cm_mra_cb;

    ib_status = ib_cm_req (&cm_req);
    
    if ( ib_status != IB_SUCCESS )
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsC: EP %lx QP %lx conn_request failed = %s\n", 
                       ep_ptr, ep_ptr->qp_handle, ib_get_err_str(ib_status));

        return  (dapl_ib_status_convert (ib_status));
    }

    return DAT_SUCCESS;
}


/*
 * dapls_ib_disconnect
 *
 * Disconnect an EP
 *
 * Input:
 *        ep_handle,
 *        disconnect_flags
 *           DAT_CLOSE_ABRUPT_FLAG - no callback
 *           DAT_CLOSE_GRACEFUL_FLAG - callback desired.
 *
 * Output:
 *         none
 *
 * Returns:
 *        DAT_SUCCESS
 *        DAT_INSUFFICIENT_RESOURCES
 *        DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_disconnect ( IN   DAPL_EP           *ep_ptr,
                      IN   DAT_CLOSE_FLAGS   disconnect_flags )
{
	DAT_RETURN dat_status = DAT_SUCCESS;
	ib_cm_dreq_t	cm_dreq;
	dp_ib_cm_handle_t	cm_ptr;
	ib_cm_handle_t h_cm;
	enum dapl_ibal_cm_state state;

	dapl_os_assert(ep_ptr);

	if ( DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP) )
	{
		dapl_dbg_log (DAPL_DBG_TYPE_CM,
			"--> %s: BAD EP Magic EP=%lx\n", __FUNCTION__,ep_ptr); 
		return DAT_SUCCESS;
	}

	cm_ptr = dapl_get_cm_from_ep(ep_ptr);
	if (!cm_ptr)
	{
		dapl_dbg_log (DAPL_DBG_TYPE_ERR, 
			"--> %s: !CM_PTR on EP %p\n", __FUNCTION__, ep_ptr);
		return DAT_SUCCESS;
	}
 
	dapl_dbg_log (DAPL_DBG_TYPE_CM,
		"--> %s() EP %p %s Close %s\n", __FUNCTION__,
		ep_ptr, dapl_get_ep_state_str(ep_ptr->param.ep_state),
		(disconnect_flags == DAT_CLOSE_ABRUPT_FLAG ? "Abrupt":"Graceful"));

	//if ( disconnect_flags == DAT_CLOSE_ABRUPT_FLAG )
	//{
	//    dapl_dbg_log(DAPL_DBG_TYPE_CM,
	//		"%s() calling legacy_post_disconnect()\n",__FUNCTION__);
	//	dapl_ep_legacy_post_disconnect(ep_ptr, disconnect_flags);
	//}

	dapl_os_lock(&ep_ptr->header.lock);
	if (ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED)
	{
		dapl_os_unlock(&ep_ptr->header.lock);
		return dat_status;
	}

	h_cm = cm_ptr->ib_cm;
	state = cm_ptr->state;
	cm_ptr->state = IBAL_CM_DISCONNECT;
	dapl_os_unlock(&ep_ptr->header.lock);

	if (state == IBAL_CM_DREQ)
		dapli_send_ib_cm_drep(h_cm);
	else
		dapli_send_ib_cm_dreq(cm_ptr->ib_cm);

	return DAT_SUCCESS;
}


/*
 * dapl_ib_setup_conn_listener
 *
 * Have the CM set up a connection listener.
 *
 * Input:
 *        ibm_hca_handle           HCA handle
 *        qp_handle                QP handle
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
dapls_ib_setup_conn_listener (
        IN  DAPL_IA               *ia_ptr,
        IN  DAT_UINT64            ServiceID,
        IN  DAPL_SP               *sp_ptr )
{
    ib_api_status_t               ib_status;
    ib_cm_listen_t                cm_listen;
    dapl_ibal_ca_t                *p_ca;
    dapl_ibal_port_t              *p_active_port;

    p_ca = (dapl_ibal_ca_t *) ia_ptr->hca_ptr->ib_hca_handle;

    /*
     * We are using the first active port in the list for
     * communication. We have to get back here when we decide to support
     * fail-over and high-availability.
     */
    p_active_port = dapli_ibal_get_port( p_ca,
					(uint8_t)ia_ptr->hca_ptr->port_num );

    if (NULL == p_active_port)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"%s: SP %lx port %d not available\n",
                __FUNCTION__, sp_ptr, ia_ptr->hca_ptr->port_num );
        return (DAT_INVALID_STATE);
    }

    if (p_active_port->p_attr->lid == 0)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsSCL: SP %lx SID 0x" F64x " port %d\n", 
                       sp_ptr, cl_hton64(ServiceID),
                       p_active_port->p_attr->port_num);
        return (DAT_INVALID_STATE);
    }

    dapl_dbg_log (DAPL_DBG_TYPE_CM,
         "%s: SP %lx port %d GID{0x" F64x ", 0x" F64x "} and SID 0x" F64x "\n", 
         __FUNCTION__,
         sp_ptr, p_active_port->p_attr->port_num,
         cl_hton64 (p_active_port->p_attr->p_gid_table[0].unicast.prefix),
         cl_hton64 (p_active_port->p_attr->p_gid_table[0].unicast.interface_id),
         cl_hton64 (ServiceID));
    
    dapl_os_memzero (&cm_listen, sizeof (ib_cm_listen_t));

    /*
     * Listen for all request on  this specific CA
     */
    cm_listen.ca_guid = (p_ca->p_ca_attr->ca_guid);
    cm_listen.svc_id  = ServiceID;
    cm_listen.qp_type = IB_QPT_RELIABLE_CONN; 

    /*
     * We do not use specific data buffer to check for specific connection
     */
    cm_listen.p_compare_buffer = NULL;//(uint8_t*)&sp_ptr->conn_qual;
    cm_listen.compare_offset   = 0;//IB_MAX_REQ_PDATA_SIZE - sizeof(DAT_CONN_QUAL);
    cm_listen.compare_length   = 0;//sizeof(DAT_CONN_QUAL);

    /*
     * We can pick a port here for communication and the others are reserved
     * for fail-over / high-availability - TBD
     */
    cm_listen.port_guid     = p_active_port->p_attr->port_guid;
    cm_listen.lid           = p_active_port->p_attr->lid;
    cm_listen.pkey          = p_active_port->p_attr->p_pkey_table[0];

    /*
     * Register request or mra callback functions
     */
    cm_listen.pfn_cm_req_cb = dapli_ib_cm_req_cb;

    ib_status = ib_cm_listen ( dapl_ibal_root.h_al,
                               &cm_listen,
                               (void *) sp_ptr,
                               &sp_ptr->cm_srvc_handle );

    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "%s: SP %lx SID 0x" F64x " listen failed %s\n", 
                       __FUNCTION__, sp_ptr, cl_hton64 (ServiceID),
                       ib_get_err_str(ib_status));
    }

    return dapl_ib_status_convert (ib_status);
}


/*
 * dapl_ib_remove_conn_listener
 *
 * Have the CM remove a connection listener.
 *
 * Input:
 *      ia_handle               IA handle
 *      ServiceID               IB Channel Service ID
 *
 * Output:
 *      none
 *
 * Returns:
 *      DAT_SUCCESS
 *      DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_remove_conn_listener (
        IN  DAPL_IA        *ia_ptr,
        IN  DAPL_SP        *sp_ptr )
{
    ib_api_status_t        ib_status;
    DAT_RETURN             dat_status = DAT_SUCCESS;
	
    UNUSED_PARAM( ia_ptr );

    dapl_os_assert ( sp_ptr );

    dapl_os_assert ( sp_ptr->header.magic == DAPL_MAGIC_PSP ||
         sp_ptr->header.magic == DAPL_MAGIC_RSP );

    dapl_dbg_log ( DAPL_DBG_TYPE_CM, "%s() cm_srvc_handle %lx\n",
                   __FUNCTION__, sp_ptr->cm_srvc_handle );

    if (sp_ptr->cm_srvc_handle)
    {
        ib_status = ib_cm_cancel ( sp_ptr->cm_srvc_handle, 
                                   NULL );
        
        if (ib_status != IB_SUCCESS)
        {
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                           "--> DsRCL: SP %lx ib_cm_cancel failed(0x%x) %s\n", 
                           sp_ptr, sp_ptr->cm_srvc_handle,
                           ib_get_err_str(ib_status));
            sp_ptr->cm_srvc_handle = NULL;
            return (DAT_INVALID_PARAMETER);
        }

        sp_ptr->cm_srvc_handle = NULL;
    }

    return dat_status;
}

/*
 * dapls_ib_reject_connection
 *
 * Perform necessary steps to reject a connection
 *
 * Input:
 *        cr_handle
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
dapls_ib_reject_connection ( IN  dp_ib_cm_handle_t   ib_cm_handle,
                             IN  int                 reject_reason,
                             IN  DAT_COUNT           private_data_size,
                             IN  const DAT_PVOID     private_data)
{
    ib_api_status_t        ib_status;
    ib_cm_rej_t            cm_rej;
    static char            *rej_table[] =
    {
        "INVALID_REJ_REASON",
        "INVALID_REJ_REASON",
        "INVALID_REJ_REASON",
        "INVALID_REJ_REASON",
        "INVALID_REJ_REASON",
        "IB_CME_DESTINATION_REJECT",
        "IB_CME_DESTINATION_REJECT_PRIVATE_DATA",
        "IB_CME_DESTINATION_UNREACHABLE",
        "IB_CME_TOO_MANY_CONNECTION_REQUESTS",
        "IB_CME_LOCAL_FAILURE",
        "IB_CM_LOCAL_FAILURE"
    };

#define REJ_TABLE_SIZE  IB_CM_LOCAL_FAILURE

    reject_reason = __min( reject_reason & 0xff, REJ_TABLE_SIZE);

    cm_rej.rej_status   = IB_REJ_USER_DEFINED;
    cm_rej.p_ari        = (ib_ari_t *)&rej_table[reject_reason]; 
    cm_rej.ari_length   = (uint8_t)strlen (rej_table[reject_reason]);

    cm_rej.p_rej_pdata  = private_data;
    cm_rej.rej_length   = private_data_size;

#if defined(DAPL_DBG) && 0
    dapli_print_private_data("DsRjC",private_data,private_data_size);
#endif

    ib_status = ib_cm_rej(ib_cm_handle->ib_cm, &cm_rej);

    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsRjC: cm_handle %p reject failed %s\n", 
                       ib_cm_handle, ib_get_err_str(ib_status) );
    }

    return ( dapl_ib_status_convert ( ib_status ) );
}



#if 0
static void
dapli_query_qp( ib_qp_handle_t qp_handle, ib_qp_attr_t  *qpa )
{
    ib_api_status_t        ib_status;
    
    ib_status = ib_query_qp ( qp_handle, qpa );
    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,"ib_query_qp(%lx) '%s'\n",
                qp_handle, ib_get_err_str(ib_status) );
    }
    else
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_CM, "--> QP(%lx) state %s "
                       "type %d init %d acc %x\n",
                       qp_handle,
                       ib_get_port_state_str(qpa->state),
                       qpa->qp_type,
                       qpa->init_depth,
                       qpa->access_ctrl );
    }
}
#endif


/*
 * dapls_ib_accept_connection
 *
 * Perform necessary steps to accept a connection
 *
 * Input:
 *        cr_handle
 *        ep_handle
 *        private_data_size
 *        private_data
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
dapls_ib_accept_connection (
        IN        DAT_CR_HANDLE            cr_handle,
        IN        DAT_EP_HANDLE            ep_handle,
        IN        DAT_COUNT                private_data_size,
        IN const  DAT_PVOID                private_data )
{
    DAPL_CR                *cr_ptr;
    DAPL_EP                *ep_ptr;
    DAPL_IA                *ia_ptr;
    DAT_RETURN             dat_status;
    ib_api_status_t        ib_status;
    dapl_ibal_ca_t         *p_ca;
    dapl_ibal_port_t       *p_active_port;
    ib_cm_rep_t            cm_rep;
    ib_qp_attr_t           qpa;
    dp_ib_cm_handle_t      cm_ptr;

    cr_ptr = (DAPL_CR *) cr_handle;
    ep_ptr = (DAPL_EP *) ep_handle;
    ia_ptr = ep_ptr->header.owner_ia;

    if ( ep_ptr->qp_state == DAPL_QP_STATE_UNATTACHED )
    {
        /*
         * If we are lazy attaching the QP then we may need to
         * hook it up here. Typically, we run this code only for
         * DAT_PSP_PROVIDER_FLAG
         */
        dat_status = dapls_ib_qp_alloc ( ia_ptr, ep_ptr, ep_ptr );

        if ( dat_status != DAT_SUCCESS)
        {
            /* This is not a great error code, but all the spec allows */
            dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                           "-->  DsIBAC: CR %lx EP %lx alloc QP failed 0x%x\n",
                           cr_ptr, ep_ptr, dat_status );
            return (dat_status);
        }
    }

    p_ca = (dapl_ibal_ca_t *) ia_ptr->hca_ptr->ib_hca_handle;
    p_active_port = dapli_ibal_get_port ( p_ca,
                                          (uint8_t)ia_ptr->hca_ptr->port_num );
    if (NULL == p_active_port)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsIBAC: CR %lx EP %lx port %d is not available\n",
                       cr_ptr, ep_ptr, ia_ptr->hca_ptr->port_num);
        return (DAT_INVALID_STATE);
    }

    cr_ptr->param.local_ep_handle = ep_handle;

    /*
     * assume ownership, in that once the EP is released the dynamic
     * memory containing the IBAL CM handle (ib_cm_handle_t) struct will
     * be released; see dapl_ep_dealloc().
     */
   
    /* EP-CM, save/release CR CM object, use EP CM object already linked */
    cm_ptr = dapl_get_cm_from_ep(ep_ptr);
    if (!cm_ptr) {
	dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsIBAC: CM linking to EP %p not available\n",
                       ep_ptr);
	return (DAT_INVALID_STATE);
    }
     
    /* set remote IP addr fields. IP addr data is deduced from Connection
     * Request record (gid/lib) and stashed away for use here. DAPL 1.1
     * had an interface for passing the IP info down, interface went away
     * in 2.0?
     */
    dapl_os_memcpy( (void*)&ep_ptr->remote_ia_address,
                    (void*)&cr_ptr->ib_cm_handle->dst_ip_addr,
                    sizeof(DAT_SOCK_ADDR6) );

    dapl_os_memcpy( (void*)&cr_ptr->remote_ia_address,
                    (void*)&ep_ptr->remote_ia_address,
                    sizeof(DAT_SOCK_ADDR6) );

#if defined(DAPL_DBG)
    {
        char ipa[20];

        dapl_dbg_log (DAPL_DBG_TYPE_CM|DAPL_DBG_TYPE_CALLBACK, 
                      "%s: EP(%lx) RemoteAddr: %s\n",
                      __FUNCTION__, ep_ptr,
                     dapli_get_ip_addr_str(
                            (DAT_SOCK_ADDR6*)&ep_ptr->remote_ia_address, ipa) );
    }
#endif

    dapl_os_memcpy( (void*)&cm_ptr->dst_ip_addr,
                    (void*)&cr_ptr->ib_cm_handle->dst_ip_addr,
                    sizeof(DAT_SOCK_ADDR6) );

    /* get h_al and connection ID from CR CM object, h_qp already set */
    cm_ptr->ib_cm.cid = cr_ptr->ib_cm_handle->ib_cm.cid; 
    cm_ptr->ib_cm.h_al = cr_ptr->ib_cm_handle->ib_cm.h_al;
    dapls_cm_release(cr_ptr->ib_cm_handle);

    cr_ptr->ib_cm_handle = cm_ptr; /* for dapli_get_sp_ep() upcall */

    ep_ptr->cr_ptr        = cr_ptr;

    dapl_os_memzero ( (void*)&cm_rep, sizeof (ib_cm_rep_t) );

    cm_rep.h_qp           = ep_ptr->qp_handle;
    cm_rep.qp_type        = IB_QPT_RELIABLE_CONN;

    if (private_data_size > IB_MAX_REP_PDATA_SIZE) {
    	dapl_dbg_log (DAPL_DBG_TYPE_ERR,
			"--> DsIBAC: private_data_size(%d) > Max(%d)\n",
			private_data_size, IB_MAX_REP_PDATA_SIZE);
	return DAT_ERROR(DAT_LENGTH_ERROR, DAT_NO_SUBTYPE);
                                 
        }
    cm_rep.p_rep_pdata    = (const uint8_t *)private_data;
    cm_rep.rep_length     = private_data_size;
                            
#if defined(DAPL_DBG) && 0
    dapli_print_private_data( "DsIBAC",
			      (const uint8_t*)private_data,
 			      private_data_size );
#endif

    cm_rep.pfn_cm_rej_cb = dapli_ib_cm_rej_cb;
    cm_rep.pfn_cm_mra_cb = dapli_ib_cm_mra_cb;
    cm_rep.pfn_cm_rtu_cb  = dapli_ib_cm_rtu_cb;
    cm_rep.pfn_cm_lap_cb  = dapli_ib_cm_lap_cb;
    cm_rep.pfn_cm_dreq_cb = dapli_ib_cm_dreq_cb;

    /*
     * FIXME - Vu
     *         Pay attention to the attributes. 
     *         Some of them are desirably set by DAT consumers
     */
    /*
     * We enable the qp associate with this connection ep all the access right
     * We enable the flow_ctrl, retry till success
     * We will limit the access right and flow_ctrl upon DAT consumers 
     * requirements
     */
    cm_rep.access_ctrl =
		IB_AC_LOCAL_WRITE|IB_AC_RDMA_WRITE|IB_AC_MW_BIND|IB_AC_ATOMIC;

    if ((ep_ptr->param.ep_attr.max_rdma_read_in > 0) 
		|| (ep_ptr->param.ep_attr.max_rdma_read_out > 0))
    {
	cm_rep.access_ctrl |= IB_AC_RDMA_READ;
    }

    cm_rep.sq_depth          = 0;
    cm_rep.rq_depth          = 0;
    cm_rep.init_depth        = (uint8_t)ep_ptr->param.ep_attr.max_rdma_read_out;
    cm_rep.flow_ctrl         = TRUE;
    cm_rep.flags             = 0;
    cm_rep.failover_accepted = IB_FAILOVER_ACCEPT_UNSUPPORTED;
    cm_rep.target_ack_delay  = 14;
    cm_rep.rnr_nak_timeout   = IB_RNR_NAK_TIMEOUT;
    cm_rep.rnr_retry_cnt     = IB_RNR_RETRY_CNT;
    cm_rep.pp_recv_failure   = NULL;
    cm_rep.p_recv_wr         = NULL;
     
    dapl_dbg_log (DAPL_DBG_TYPE_CM,
                 "--> DsIBAC: cm_rep: acc %x init %d qp_type %x req_count %d\n",
	         cm_rep.access_ctrl, cm_rep.init_depth,cm_rep.qp_type,
                 dapls_cb_pending(&ep_ptr->req_buffer));

    ib_status = ib_cm_rep ( cm_ptr->ib_cm, &cm_rep );

    if (ib_status != IB_SUCCESS)
    {
	dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsIBAC: EP %lx QP %lx CR reply failed '%s'\n",
                       ep_ptr, ep_ptr->qp_handle, ib_get_err_str(ib_status) );
    }
 
    return ( dapl_ib_status_convert ( ib_status ) );
}



/*
 * dapls_ib_disconnect_clean
 *
 * Clean up outstanding connection data. This routine is invoked
 * after the final disconnect callback has occurred. Only on the
 * ACTIVE side of a connection.
 *
 * Input:
 *        ep_ptr                DAPL_EP
 *
 * Output:
 *         none
 *
 * Returns:
 *         void
 *
 */
void
dapls_ib_disconnect_clean (
        IN  DAPL_EP                     *ep_ptr,
        IN  DAT_BOOLEAN                 active,
        IN  const ib_cm_events_t        ib_cm_event )
{
    DAPL_IA		*ia_ptr;
    ib_qp_attr_t	qp_attr;
    ib_api_status_t     ib_status;

    dapl_dbg_log ( DAPL_DBG_TYPE_CM, "%s(%s): cm_event: %s \n", __FUNCTION__,
                   (active?"A":"P"), dapli_ib_cm_event_str(ib_cm_event));

    ia_ptr = ep_ptr->header.owner_ia;
    
    if ( ia_ptr == NULL || ia_ptr->header.magic != DAPL_MAGIC_IA )
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_CM,
                       ">>>DSCONN_CLEAN(%s): cm_event: %s Invalid IA_ptr\n",
                       (active?"Act":"Pas"),dapli_ib_cm_event_str(ib_cm_event));
        return;
    }
    dapl_os_assert ( ep_ptr->header.magic == DAPL_MAGIC_EP );
    
    ib_status = ib_query_qp ( ep_ptr->qp_handle, &qp_attr );
    if ( ib_status != IB_SUCCESS )
    {
	    dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       ">>>DSCONN_CLEAN(%s): Query QP failed = %s\n",
                       (active?"Act":"Pas"),ib_get_err_str(ib_status) );
		return;
    }
    
    ep_ptr->qp_state = qp_attr.state;

    dapl_dbg_log ( DAPL_DBG_TYPE_CM, ">>>DSCONN_CLEAN(%s): cm_event: %d "
                   "ep_ptr %lx ep_state %s qp_state %#x\n", 
                   (active?"A":"P"), ib_cm_event, ep_ptr,
                   dapl_get_ep_state_str(ep_ptr->param.ep_state),
                   ep_ptr->qp_state );

    if ( ep_ptr->qp_state != IB_QPS_ERROR &&
         ep_ptr->qp_state != IB_QPS_RESET &&
         ep_ptr->qp_state != IB_QPS_INIT )
    {
        ep_ptr->qp_state = IB_QPS_ERROR;
        dapls_modify_qp_state_to_error (ep_ptr->qp_handle);
    }
}


#ifdef NOT_USED
/*
 * dapls_ib_cr_handoff
 *
 * Hand off the connection request to another service point  
 *
 * Input:
 *        cr_handle                DAT_CR_HANDLE
 *        handoff_serv_id          DAT_CONN_QUAL
 *
 * Output:
 *         none
 *
 * Returns:
 *         DAT_SUCCESS
 *         DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN 
dapls_ib_cr_handoff (
        IN  DAT_CR_HANDLE      cr_handle,
        IN  DAT_CONN_QUAL      handoff_serv_id )
{
    DAPL_CR                *cr_ptr;
    ib_api_status_t        ib_status;
    
    cr_ptr = (DAPL_CR *) cr_handle;

    if (cr_ptr->ib_cm_handle->ib_cm.cid == 0xFFFFFFFF)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsCH: CR = %lx invalid cm handle\n", cr_ptr);
        return DAT_INVALID_PARAMETER;
    }

    if (cr_ptr->sp_ptr == DAPL_IB_INVALID_HANDLE)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsCH: CR = %lx invalid psp handle\n", cr_ptr);
        return DAT_INVALID_PARAMETER;
    }

    ib_status = ib_cm_handoff (cr_ptr->ib_cm_handle->ib_cm, handoff_serv_id);

    if (ib_status != IB_SUCCESS)
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsCH: CR = %lx handoff failed = %s\n", 
                       cr_ptr, ib_get_err_str(ib_status) );

        return dapl_ib_status_convert (ib_status);
    }

    dapl_dbg_log ( DAPL_DBG_TYPE_CM,
                   "--> %s(): remove CR %lx from SP %lx Queue\n",
                   __FUNCTION__, cr_ptr, cr_ptr->sp_ptr);
    /* Remove the CR from the queue */
    dapl_sp_remove_cr (cr_ptr->sp_ptr, cr_ptr);

    /*
     * If this SP has been removed from service, free it
     * up after the last CR is removed
     */
    dapl_os_lock (&cr_ptr->sp_ptr->header.lock);
    if ( cr_ptr->sp_ptr->listening != DAT_TRUE && 
         cr_ptr->sp_ptr->cr_list_count == 0 &&
         cr_ptr->sp_ptr->state != DAPL_SP_STATE_FREE )
    {
        dapl_dbg_log (DAPL_DBG_TYPE_CM, 
                      "--> DsCH: CR = %lx disconnect dump SP = %lx \n", 
                      cr_ptr, cr_ptr->sp_ptr);
        /* Decrement the ref count on the EVD */
        if (cr_ptr->sp_ptr->evd_handle)
        {
            dapl_os_atomic_dec (& ((DAPL_EVD *)cr_ptr->sp_ptr->evd_handle)->evd_ref_count);
            cr_ptr->sp_ptr->evd_handle = NULL;
        }
        cr_ptr->sp_ptr->state = DAPL_SP_STATE_FREE;
        dapl_os_unlock (&cr_ptr->sp_ptr->header.lock);
        (void)dapls_ib_remove_conn_listener ( cr_ptr->sp_ptr->header.owner_ia,
                                              cr_ptr->sp_ptr );
        dapls_ia_unlink_sp ( (DAPL_IA *)cr_ptr->sp_ptr->header.owner_ia,
                             cr_ptr->sp_ptr );
        dapls_sp_free_sp ( cr_ptr->sp_ptr );
    }
    else
    {
        dapl_os_unlock (&cr_ptr->sp_ptr->header.lock);
    }

    /*
     * Clean up and dispose of the resource
     */
    dapls_cr_free (cr_ptr);

    return (DAT_SUCCESS);
}
#endif

int
dapls_ib_private_data_size (
	IN	DAPL_HCA		*hca_ptr)
{
    return IB_MAX_REQ_PDATA_SIZE;
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */

