
/*
 * Copyright (c) 2007 Intel Corporation.  All rights reserved.
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
 * MODULE: dapl_ibal_cq.c
 *
 * PURPOSE: CQ (Completion Qeueu) access routine using IBAL APIs
 *
 * $Id$
 *
 **********************************************************************/

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_cr_util.h"
#include "dapl_lmr_util.h"
#include "dapl_rmr_util.h"
#include "dapl_cookie.h"
#include "dapl_ring_buffer_util.h"

#ifndef NO_NAME_SERVICE
#include "dapl_name_service.h"
#endif /* NO_NAME_SERVICE */


static void
dapli_ibal_cq_async_error_callback ( IN  ib_async_event_rec_t  *p_err_rec )
{
    DAPL_EVD		*evd_ptr = (DAPL_EVD*)((void *)p_err_rec->context);
    DAPL_EVD		*async_evd_ptr;
    DAPL_IA		*ia_ptr;
    dapl_ibal_ca_t	*p_ca;
    dapl_ibal_evd_cb_t	*evd_cb;
	
    dapl_dbg_log (DAPL_DBG_TYPE_ERR,
	    "--> DiCqAEC: CQ error %d for EVD context %lx\n", 
            p_err_rec->code, p_err_rec->context);

    if (DAPL_BAD_HANDLE (evd_ptr, DAPL_MAGIC_EVD))
    {
    	dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> DiCqAEC: invalid EVD %lx\n", evd_ptr);
    	return;
    }
		
    ia_ptr = evd_ptr->header.owner_ia;
    async_evd_ptr = ia_ptr->async_error_evd;
    if (async_evd_ptr == NULL)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR,"--> DiCqAEC: can't find async_error_evd on %s HCA\n", 
                (ia_ptr->header.provider)->device_name );
        return;
    }

    p_ca = (dapl_ibal_ca_t *) ia_ptr->hca_ptr->ib_hca_handle;
    if (p_ca == NULL)
    {
        dapl_dbg_log (DAPL_DBG_TYPE_ERR,"--> DiCqAEC: can't find %s HCA\n", 
                (ia_ptr->header.provider)->device_name);
        return;
    }

    /* find CQ error callback using ia_ptr for context */
    evd_cb = dapli_find_evd_cb_by_context ( async_evd_ptr, p_ca );
    if ((evd_cb == NULL) || (evd_cb->pfn_async_cq_err_cb == NULL))
    {
    	dapl_dbg_log (DAPL_DBG_TYPE_ERR,
                      "--> DiCqAEC: no ERROR cb on %lx found \n", p_ca);
    	return;
    }

    /* maps to dapl_evd_cq_async_error_callback(), context is EVD */
    evd_cb->pfn_async_cq_err_cb( (ib_hca_handle_t)p_ca, 
				 evd_ptr->ib_cq_handle,
				 (ib_error_record_t*)&p_err_rec->code,
				 evd_ptr );

}


/*
 * dapli_ibal_cq_competion_callback
 *
 * Completion callback for a CQ
 *
 * Input:
 *	cq_context		 User context
 *
 * Output:
 * 	none
 *
 * Returns:
 */
static void
dapli_ib_cq_completion_cb (
        IN   const   ib_cq_handle_t   h_cq,
        IN   void                     *cq_context )
{
    DAPL_EVD           *evd_ptr;
    dapl_ibal_ca_t     *p_ca;

    evd_ptr = (DAPL_EVD *) cq_context;

    dapl_dbg_log (DAPL_DBG_TYPE_CALLBACK, 
                  "--> DiICCC: cq_completion_cb evd %lx CQ %lx\n", 
                  evd_ptr, evd_ptr->ib_cq_handle);

    dapl_os_assert (evd_ptr != DAT_HANDLE_NULL);

    p_ca = (dapl_ibal_ca_t *) evd_ptr->header.owner_ia->hca_ptr->ib_hca_handle;

    dapl_os_assert( h_cq == evd_ptr->ib_cq_handle );

    dapl_evd_dto_callback ( (ib_hca_handle_t) p_ca, h_cq, cq_context);
}


/*
 * dapl_ib_cq_late_alloc
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
dapls_ib_cq_late_alloc (
	IN  ib_pd_handle_t        pd_handle,
        IN  DAPL_EVD              *evd_ptr )
{
    ib_cq_create_t  cq_create;
    ib_api_status_t ib_status;
    DAT_RETURN      dat_status;
    dapl_ibal_ca_t  *ibal_ca;
    
    dat_status            = DAT_SUCCESS;
    cq_create.size        = evd_ptr->qlen;
    
    ibal_ca = (dapl_ibal_ca_t*)evd_ptr->header.owner_ia->hca_ptr->ib_hca_handle;
	
    cq_create.h_wait_obj  = NULL;
    cq_create.pfn_comp_cb = dapli_ib_cq_completion_cb;

    ib_status = ib_create_cq (
                        (ib_ca_handle_t)ibal_ca->h_ca,
                        &cq_create,
                        evd_ptr /* context */,
                        dapli_ibal_cq_async_error_callback,
                        &evd_ptr->ib_cq_handle);

    dat_status = dapl_ib_status_convert (ib_status);

    if ( dat_status != DAT_SUCCESS )
    {
        dapl_dbg_log ( DAPL_DBG_TYPE_ERR,
                       "--> DsICLA: failed to create CQ for EVD %lx\n",evd_ptr);
        goto bail;
    }

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                  "--> DsCQ_alloc: pd=%lx cq=%lx CQsz=%d EVD->Qln=%d\n",
                  pd_handle, evd_ptr->ib_cq_handle,
                  cq_create.size, evd_ptr->qlen);

    /*
     * As long as the CQ size is >= the evd size, then things are OK; sez Arlin.
     */
    if ( cq_create.size < (uint32_t)evd_ptr->qlen )
    {
        dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
                      "--> DsCQ_alloc: created CQ size(%d) < evd->qlen(%d)?\n",
                      cq_create.size, evd_ptr->qlen);
    	dat_status = dapl_ib_status_convert (IB_INVALID_CQ_SIZE);
    }
    
bail: 
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


/*
 * dapl_ib_cq_free
 *
 * Dealloc a CQ
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
 *	DAT_INVALID_HANDLE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_cq_free (
        IN  DAPL_IA                *ia_ptr,
        IN  DAPL_EVD                *evd_ptr)
{
    ib_api_status_t             ib_status;
	
	if ( ia_ptr == NULL || ia_ptr->header.magic != DAPL_MAGIC_IA )
	{
		return DAT_INVALID_HANDLE;
	}

    ib_status = ib_destroy_cq (evd_ptr->ib_cq_handle, 
                               /* destroy_callback */ NULL);
                     
    return dapl_ib_status_convert (ib_status);
}

/*
 * dapls_cq_resize
 *
 * Resize CQ completion notifications
 *
 * Input:
 *	ia_handle		IA handle
 *	evd_ptr			pointer to EVD struct
 *	cqlen			minimum QLen 
 *
 * Output:
 * 	cqlen			may round up for optimal memory boundaries 
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */

DAT_RETURN
dapls_ib_cq_resize (
         IN  DAPL_IA             *ia_ptr,
         IN  DAPL_EVD            *evd_ptr,
         IN  DAT_COUNT           *cqlen )
{
    ib_api_status_t             ib_status = IB_SUCCESS;

    if ( ia_ptr == NULL || ia_ptr->header.magic != DAPL_MAGIC_IA )
    {
    	return DAT_INVALID_HANDLE;
    }
    /* 
     * Resize CQ only if CQ handle is valid, may be delayed waiting
     * for PZ allocation with IBAL 
     */
#if defined(_VENDOR_IBAL_)
    if ( evd_ptr->ib_cq_handle != IB_INVALID_HANDLE ) 
#endif /* _VENDOR_IBAL_ */
    {
    	ib_status = ib_modify_cq ( evd_ptr->ib_cq_handle, 
    		                       (uint32_t *)cqlen );
    	dapl_dbg_log (DAPL_DBG_TYPE_EVD,
                      "ib_modify_cq ( new cqlen = %d, status=%d ) \n",
                      *cqlen, ib_status );
    }          
    return dapl_ib_status_convert (ib_status);
}


/*
 * dapl_set_cq_notify
 *
 * Set up CQ completion notifications
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
 *	DAT_INVALID_HANDLE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_set_cq_notify (
    IN  DAPL_IA            *ia_ptr,
    IN  DAPL_EVD           *evd_ptr )
{
    ib_api_status_t             ib_status;
	if ( ia_ptr == NULL || ia_ptr->header.magic != DAPL_MAGIC_IA )
	{
		return DAT_INVALID_HANDLE;
	}
    ib_status = ib_rearm_cq ( 
                         evd_ptr->ib_cq_handle,
                         FALSE /* next event but not solicited event */ );

    return dapl_ib_status_convert (ib_status);
}


/*
 * dapls_ib_cqd_create
 *
 * Set up CQ notification event thread
 *
 * Input:
 *	ia_handle	HCA handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_cqd_create ( IN  DAPL_HCA  *p_hca )
{
    /*
     * We do not have CQD concept
     */
    p_hca->ib_trans.ib_cqd_handle = IB_INVALID_HANDLE;

    return DAT_SUCCESS;
}


/*
 * dapl_cqd_destroy
 *
 * Destroy CQ notification event thread
 *
 * Input:
 *	ia_handle		IA handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_cqd_destroy ( IN  DAPL_HCA  *p_hca )
{
    p_hca->ib_trans.ib_cqd_handle = IB_INVALID_HANDLE;
    return (DAT_SUCCESS);
}



DAT_RETURN
dapls_ib_n_completions_notify (
        IN ib_hca_handle_t    hca_handle,
        IN ib_cq_handle_t     cq_handle,
        IN uint32_t           n_cqes )
{
    ib_api_status_t        ib_status;
    UNREFERENCED_PARAMETER(hca_handle);

    ib_status = ib_rearm_n_cq ( 
                         cq_handle,
                         n_cqes );

    return dapl_ib_status_convert (ib_status);
}


DAT_RETURN
dapls_ib_peek_cq (
        IN ib_cq_handle_t cq_handle,
        OUT uint32_t* p_n_cqes)
{
    ib_api_status_t        ib_status;

    ib_status = ib_peek_cq ( cq_handle, p_n_cqes );

    return dapl_ib_status_convert (ib_status);
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */

