
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
 * MODULE: dapl_ibal_dto.h
 *
 * PURPOSE: Utility routines for data transfer operations using the
 * IBAL APIs
 *
 * $Id: dapl_ibal_dto.h 33 2005-07-11 19:51:17Z ftillier $
 *
 **********************************************************************/

#ifndef _DAPL_IBAL_DTO_H
#define _DAPL_IBAL_DTO_H

#include "dapl_ibal_util.h"

#ifdef DAT_EXTENSIONS
#include <dat2/dat_ib_extensions.h>
#endif

extern DAT_RETURN
dapls_ib_cq_late_alloc (
	IN  ib_pd_handle_t      pd_handle,
	IN  DAPL_EVD            *evd_ptr);

#define	DAPL_DEFAULT_DS_ENTRIES 8

#ifdef NOT_SUPPORTED
extern DAT_RETURN 
dapls_ib_post_recv_defered (
	IN  DAPL_EP		   	*ep_ptr,
	IN  DAPL_COOKIE			*cookie,
	IN  DAT_COUNT	   		num_segments,
	IN  DAT_LMR_TRIPLET	   	*local_iov); // dapl_ibal_util.c
#endif

static _INLINE_ char * dapls_dto_op_str(int dto);

/*
 * dapls_ib_post_recv
 *
 * Provider specific Post RECV function
 */
STATIC _INLINE_ DAT_RETURN 
dapls_ib_post_recv (
	IN  DAPL_EP		   	*ep_ptr,
	IN  DAPL_COOKIE			*cookie,
	IN  DAT_COUNT	   		num_segments,
	IN  DAT_LMR_TRIPLET	   	*local_iov)
{
    ib_api_status_t     ib_status;
    ib_recv_wr_t	recv_wr, *failed_wr_p;
    ib_local_ds_t       ds_array[DAPL_DEFAULT_DS_ENTRIES], *ds_array_p;
    DAT_COUNT           i, total_len;

#ifdef NOT_SUPPORTED
    if (ep_ptr->qp_state == IB_QPS_INIT)
    {
        return dapls_ib_post_recv_defered ( ep_ptr,
                                            cookie,
                                            num_segments,
                                            local_iov);
    }
#endif
    dapl_os_memzero(&recv_wr, sizeof(ib_recv_wr_t));
    recv_wr.wr_id        = (DAT_UINT64) cookie;
    recv_wr.num_ds       = num_segments;

    if( num_segments <= DAPL_DEFAULT_DS_ENTRIES )
    {
        ds_array_p = ds_array;
    }
    else
    {
        ds_array_p = dapl_os_alloc(num_segments*sizeof(ib_local_ds_t));
    }
    recv_wr.ds_array     = ds_array_p;

    if (NULL == ds_array_p)
    {
	return (DAT_INSUFFICIENT_RESOURCES);
    }

    for (total_len = i = 0; i < num_segments; i++, ds_array_p++)
    {
        ds_array_p->length = (uint32_t)local_iov[i].segment_length;
        ds_array_p->lkey  = htonl(local_iov[i].lmr_context);
        ds_array_p->vaddr = local_iov[i].virtual_address;
        total_len        += ds_array_p->length;
    }

    if (cookie != NULL)
    {
	cookie->val.dto.size            =  total_len;

        dapl_dbg_log (DAPL_DBG_TYPE_EP,
                      "--> DsPR: EP = %p QP = %p cookie= %p, num_seg= %d\n", 
                      ep_ptr, ep_ptr->qp_handle, cookie, num_segments);
    }

    recv_wr.p_next = NULL;

    ib_status = ib_post_recv( ep_ptr->qp_handle, &recv_wr, &failed_wr_p );

    if( num_segments > DAPL_DEFAULT_DS_ENTRIES )
    	dapl_os_free( recv_wr.ds_array, num_segments * sizeof(ib_local_ds_t) );

    if (IB_SUCCESS == ib_status)
    {
	return DAT_SUCCESS;
    }

        dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsPR: post_recv status %s\n", 
                      ib_get_err_str(ib_status));
        /*
         * Moving QP to error state; 
         */
    (void) dapls_modify_qp_state_to_error ( ep_ptr->qp_handle);
        ep_ptr->qp_state = IB_QPS_ERROR;

	return (dapl_ib_status_convert (ib_status));
}


/*
 * dapls_ib_post_send
 *
 * Provider specific Post SEND function
 */
STATIC _INLINE_ DAT_RETURN 
dapls_ib_post_send (
	IN  DAPL_EP		   	*ep_ptr,
	IN  ib_send_op_type_t         	op_type,
	IN  DAPL_COOKIE			*cookie,
	IN  DAT_COUNT	   		num_segments,
	IN  DAT_LMR_TRIPLET	   	*local_iov,
	IN  const DAT_RMR_TRIPLET	*remote_iov,
	IN  DAT_COMPLETION_FLAGS	completion_flags)
{
    ib_api_status_t 	ib_status;
    ib_send_wr_t	send_wr, *failed_wr_p;
    ib_local_ds_t       ds_array[DAPL_DEFAULT_DS_ENTRIES], *ds_array_p;
    DAT_COUNT		i, total_len;

    if (ep_ptr->param.ep_state != DAT_EP_STATE_CONNECTED)
    {
    	ib_qp_attr_t             qp_attr;

    	ib_query_qp ( ep_ptr->qp_handle, &qp_attr );

    	dapl_dbg_log (DAPL_DBG_TYPE_ERR, "--> DsPS: !CONN EP (%p) ep_state=%d "
                      "QP_state=%d\n", 
                      ep_ptr, ep_ptr->param.ep_state, qp_attr.state );

        return (DAT_ERROR(DAT_INVALID_STATE,DAT_INVALID_STATE_EP_DISCONNECTED));
    }

    dapl_os_memzero (&send_wr, sizeof(ib_send_wr_t));
    send_wr.wr_type		= op_type;
    send_wr.num_ds		= num_segments;

    if( num_segments <= DAPL_DEFAULT_DS_ENTRIES )
    {
    	ds_array_p = ds_array;
    }
    else
    {
    	ds_array_p = dapl_os_alloc( num_segments * sizeof(ib_local_ds_t) );
    }
    send_wr.ds_array     = ds_array_p;

    if (NULL == ds_array_p)
    {
	return (DAT_INSUFFICIENT_RESOURCES);
    }

    total_len                   = 0;

    for (i = 0; i < num_segments; i++, ds_array_p++)
    {
      ds_array_p->length = (uint32_t)local_iov[i].segment_length;
	ds_array_p->lkey   = htonl(local_iov[i].lmr_context);
	ds_array_p->vaddr  = local_iov[i].virtual_address;
	total_len         += ds_array_p->length;
    }

    if (cookie != NULL)
    {
	cookie->val.dto.size            =  total_len;

    	dapl_dbg_log (DAPL_DBG_TYPE_EP,
    		"--> DsPS: EVD=%p EP=%p QP=%p type=%d, sg=%d "
		"ln=%d, ck=%p 0x" F64x "\n", 
    		ep_ptr->param.request_evd_handle, ep_ptr, ep_ptr->qp_handle, 
    		op_type, num_segments, total_len,
    		cookie, cookie->val.dto.cookie.as_64 );
    }

    send_wr.wr_id		= (DAT_UINT64)cookie;

    /* RC for now */
    if (total_len > 0)
    {
        send_wr.remote_ops.vaddr = remote_iov->virtual_address;
        send_wr.remote_ops.rkey	 = htonl(remote_iov->rmr_context);
    }

    send_wr.send_opt	= 0;

    send_wr.send_opt	|= (DAT_COMPLETION_BARRIER_FENCE_FLAG & 
		    	   completion_flags) ? IB_SEND_OPT_FENCE : 0;
    send_wr.send_opt	|= (DAT_COMPLETION_SUPPRESS_FLAG & 
		    	   completion_flags) ? 0 : IB_SEND_OPT_SIGNALED;
    send_wr.send_opt	|= (DAT_COMPLETION_SOLICITED_WAIT_FLAG & 
		    	   completion_flags) ? IB_SEND_OPT_SOLICITED : 0;

    dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsPS: EP=%p QP=%p send_opt=0x%x,"
                  "rem_addr=%p, rem_rkey=0x%x completion_flags=0x%x\n",
                  ep_ptr, ep_ptr->qp_handle,  
                  send_wr.send_opt, (void *)(uintptr_t)send_wr.remote_ops.vaddr,
                  send_wr.remote_ops.rkey, completion_flags);

    send_wr.p_next = NULL;

    ib_status = ib_post_send( ep_ptr->qp_handle, &send_wr, &failed_wr_p );

    if( num_segments > DAPL_DEFAULT_DS_ENTRIES )
    	dapl_os_free( send_wr.ds_array, num_segments * sizeof(ib_local_ds_t) );

    if (IB_SUCCESS == ib_status)
	return DAT_SUCCESS;

    dapl_dbg_log (DAPL_DBG_TYPE_EP, "--> DsPS: EP=%p post_send status = %s\n", 
                  ep_ptr, ib_get_err_str(ib_status));
    /*
     * Moving QP to error state; 
     */
    (void) dapls_modify_qp_state_to_error ( ep_ptr->qp_handle);
    ep_ptr->qp_state = IB_QPS_ERROR;

    return (dapl_ib_status_convert (ib_status));
}

/*
 * dapls_ib_optional_prv_dat
 *
 * Allocate space for private data to be used in CR calls
 *
 * Input:
 *	cr_ptr			CR handle
 *	event_data		data provided by the provider callback function
 *	cr_pp			Pointer for private data
 *
 * Output:
 * 	cr_pp			Area 
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
STATIC _INLINE_ DAT_RETURN
dapls_ib_optional_prv_dat (
	IN  DAPL_CR		*cr_ptr,
	IN  const void		*event_data,
	OUT DAPL_CR             **cr_pp)
{
	DAT_RETURN dat_status = DAT_SUCCESS;
	DAPL_PRIVATE *p_prv_data = (DAPL_PRIVATE *)event_data;

	if ( ! cr_ptr->param.private_data_size )
	{
		cr_ptr->param.private_data_size = sizeof(cr_ptr->private_data);
		cr_ptr->param.private_data = cr_ptr->private_data;
		dapl_os_memcpy( cr_ptr->private_data,
				p_prv_data->private_data,							cr_ptr->param.private_data_size );
		*cr_pp = (DAPL_CR *)cr_ptr->param.private_data;
	}
    return dat_status;
}


STATIC _INLINE_ int
dapls_cqe_opcode_convert (ib_work_completion_t *cqe_p)
{
#ifdef DAPL_DBG
    int dop;
    switch (((ib_work_completion_t *)cqe_p)->wc_type)
    {
        case IB_WC_SEND:
            dop = (OP_SEND);
            break;

        case IB_WC_RDMA_WRITE:
            dop = (OP_RDMA_WRITE);
            if (cqe_p->recv.conn.recv_opt & IB_RECV_OPT_IMMEDIATE)
                dop = (OP_RDMA_WRITE_IMM);
            break;

        case IB_WC_RECV:	
        case IB_WC_RECV_RDMA_WRITE:
            dop = (OP_RECEIVE);
            if (cqe_p->recv.conn.recv_opt & IB_RECV_OPT_IMMEDIATE)
                dop = (OP_RECEIVE_IMM);
            break;

        case IB_WC_RDMA_READ:
            dop = (OP_RDMA_READ);
            break;

        case IB_WC_MW_BIND:
            dop = (OP_BIND_MW);
            break;

        case IB_WC_FETCH_ADD:
            dop = (OP_FETCH_AND_ADD);
            break;

        case IB_WC_COMPARE_SWAP:
            dop = (OP_COMP_AND_SWAP);
            break;

        default :	
            /* error */ 
            dapl_dbg_log(DAPL_DBG_TYPE_ERR, "%s() Unknown IB_WC_TYPE %d?\n",
				__FUNCTION__, cqe_p->wc_type);
            dop = (OP_BAD_OPCODE);
            break;
    }
#if 0
    dapl_dbg_log(DAPL_DBG_TYPE_ERR, "--> DsCqeCvt %s --> %s\n",
					ib_get_wc_type_str(cqe_p->wc_type),
					dapls_dto_op_str(dop));
#endif
    return dop;

#else /* ! DAPL_DBG */

    switch (((ib_work_completion_t *)cqe_p)->wc_type)
    {
        case IB_WC_SEND:
            return (OP_SEND);

        case IB_WC_RDMA_WRITE:
            if (cqe_p->recv.conn.recv_opt & IB_RECV_OPT_IMMEDIATE)
                return (OP_RDMA_WRITE_IMM);
            return (OP_RDMA_WRITE);

        case IB_WC_RECV:	
        case IB_WC_RECV_RDMA_WRITE:
            if (cqe_p->recv.conn.recv_opt & IB_RECV_OPT_IMMEDIATE)
                return (OP_RECEIVE_IMM);
            return (OP_RECEIVE);

        case IB_WC_RDMA_READ:
            return (OP_RDMA_READ);

        case IB_WC_MW_BIND:
            return (OP_BIND_MW);

        case IB_WC_FETCH_ADD:
            return (OP_FETCH_AND_ADD);

        case IB_WC_COMPARE_SWAP:
            return (OP_COMP_AND_SWAP);

        default :	
           /* error */ 
            return (IB_ERROR);
    }
#endif
}

STATIC _INLINE_ char *
dat_dtos_type_str(DAT_DTOS dto)
{
    static char err[20];
    char *ops[] = {
        "DAT_DTO_SEND",
	"DAT_DTO_RDMA_WRITE",
	"DAT_DTO_RDMA_READ",
	"DAT_DTO_RECEIVE",
	"DAT_DTO_RECEIVE_WITH_INVALIDATE",
	"DAT_DTO_BIND_MW",  /* DAT 2.0, binds are reported via DTO events */
	"DAT_DTO_LMR_FMR", 		/* kdat specific		*/
	"DAT_DTO_LMR_INVALIDATE"	/* kdat specific		*/
    };

#ifdef DAT_EXTENSIONS
    /* "DAT_DTO_EXTENSION_BASE" used by DAT extensions as a starting point of
     * extension DTOs.
     */
    char *ext_ops[] = {
	"DAT_IB_DTO_RDMA_WRITE_IMMED",
	"DAT_IB_DTO_RECV_IMMED",
	"DAT_IB_DTO_FETCH_ADD",
	"DAT_IB_DTO_CMP_SWAP"
    };

    if (dto >= DAT_DTO_EXTENSION_BASE)
    {
        dto -= DAT_DTO_EXTENSION_BASE;
        return ext_ops[dto];
    }
#endif
    return ops[dto];
}

/* map Work Completions to DAT WR operations */
STATIC _INLINE_ DAT_DTOS dapls_cqe_dtos_opcode(ib_work_completion_t *cqe_p)
{
#ifdef DAPL_DBG
    DAT_DTOS dto;
    switch (cqe_p->wc_type) {

	case IB_WC_SEND:
		dto = (DAT_DTO_SEND);
		break;

	case IB_WC_MW_BIND:
		dto = (DAT_DTO_BIND_MW);
		break;

#ifdef DAT_EXTENSIONS
	case IB_WC_RDMA_WRITE:
		dto = (DAT_DTO_RDMA_WRITE);
		if (cqe_p->recv.conn.recv_opt & IB_RECV_OPT_IMMEDIATE)
			dto = (DAT_IB_DTO_RDMA_WRITE_IMMED);
		break;

	case IB_WC_COMPARE_SWAP:
		dto = (DAT_IB_DTO_CMP_SWAP);
		break;

	case IB_WC_FETCH_ADD:
		dto = (DAT_IB_DTO_FETCH_ADD);
		break;

        case IB_WC_RDMA_READ:
		dto = (DAT_DTO_RDMA_READ);
		break;

	case IB_WC_RECV:
        case IB_WC_RECV_RDMA_WRITE:
		dto = (DAT_DTO_RECEIVE);
		if (cqe_p->recv.conn.recv_opt & IB_RECV_OPT_IMMEDIATE)
			dto = (DAT_IB_DTO_RECV_IMMED);
		break;
#else
        case IB_WC_RDMA_READ:
		dto = (DAT_DTO_RDMA_READ);
		break;

	case IB_WC_RDMA_WRITE:
        case IB_WC_RECV_RDMA_WRITE:
		dto = (DAT_DTO_RDMA_WRITE);
		break;

	case IB_WC_RECV:
		dto = (DAT_DTO_RECEIVE);
		break;
#endif
	default:
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, "%s() Unknown IB_WC_TYPE %d?\n",
				__FUNCTION__, cqe_p->wc_type);
		dto = (0xff);
		break;
    }
#if 0
    dapl_dbg_log(DAPL_DBG_TYPE_ERR, "--> DsIBDTO %s --> %s\n",
				ib_get_wc_type_str(cqe_p->wc_type),
				dat_dtos_type_str(dto));
#endif
    return dto;

#else /* !DAPL_DBG */

    switch (cqe_p->wc_type) {

	case IB_WC_SEND:
		return (DAT_DTO_SEND);

	case IB_WC_MW_BIND:
		return (DAT_DTO_BIND_MW);

#ifdef DAT_EXTENSIONS
	case IB_WC_RDMA_WRITE:
		if (cqe_p->recv.conn.recv_opt & IB_RECV_OPT_IMMEDIATE)
			return (DAT_IB_DTO_RDMA_WRITE_IMMED);
		else
			return (DAT_DTO_RDMA_WRITE);

	case IB_WC_COMPARE_SWAP:
		return (DAT_IB_DTO_CMP_SWAP);

	case IB_WC_FETCH_ADD:
		return (DAT_IB_DTO_FETCH_ADD);

        case IB_WC_RDMA_READ:
		return (DAT_DTO_RDMA_READ);

	case IB_WC_RECV:
        case IB_WC_RECV_RDMA_WRITE:
		if (cqe_p->recv.conn.recv_opt & IB_RECV_OPT_IMMEDIATE)
			return (DAT_IB_DTO_RECV_IMMED);
		else
			return (DAT_DTO_RECEIVE);
#else
        case IB_WC_RDMA_READ:
		return (DAT_DTO_RDMA_READ);

	case IB_WC_RDMA_WRITE:
		return (DAT_DTO_RDMA_WRITE);

	case IB_WC_RECV:
        case IB_WC_RECV_RDMA_WRITE:
		return (DAT_DTO_RECEIVE);
#endif
	default:
		return (0xff);
    }
#endif
}

#define DAPL_GET_CQE_DTOS_OPTYPE(cqe_p) dapls_cqe_dtos_opcode(cqe_p)

#define DAPL_GET_CQE_WRID(cqe_p) ((ib_work_completion_t *)cqe_p)->wr_id
#define DAPL_GET_CQE_OPTYPE(cqe_p) dapls_cqe_opcode_convert(cqe_p)
#define DAPL_GET_CQE_BYTESNUM(cqe_p) ((ib_work_completion_t *)cqe_p)->length
#define DAPL_GET_CQE_STATUS(cqe_p) ((ib_work_completion_t *)cqe_p)->status
#define DAPL_GET_CQE_IMMED_DATA(cqe_p) \
		((ib_work_completion_t*)cqe_p)->recv.conn.immediate_data

static _INLINE_ char *
dapls_dto_op_str(int op)
{
    /* must match OP_SEND... defs in dapl_ibal_util.h */ 
    static char *optable[] =
    {
	"BAD OPcode",
	"OP_SEND",
    	"OP_RDMA_WRITE",
	"OP_RDMA_READ",
	"OP_COMP_AND_SWAP", // 4
	"OP_FETCH_AND_ADD", // 5
	"OP_RECEIVE_RDMA_WRITE",
	"PAD1",
	"OP_RECEIVE",	// (8)
	"OP_BIND_MW",
	"OP_RDMA_WRITE_IMM",
	"OP_RECEIVE_IMM",
	"OP_SEND_IMM"
    };
    return ((op < 0 || op > 12) ? "Invalid DTO opcode?" : optable[op]);
}

static _INLINE_ char *
dapls_cqe_op_str(IN ib_work_completion_t *cqe_ptr)
{
    return dapls_dto_op_str(DAPL_GET_CQE_OPTYPE (cqe_ptr)); 
}

#define DAPL_GET_CQE_OP_STR(cqe) dapls_cqe_op_str(cqe)


#ifdef DAT_EXTENSIONS
/*
 * dapls_ib_post_ext_send
 *
 * Provider specific extended Post SEND function for atomics
 *	OP_COMP_AND_SWAP and OP_FETCH_AND_ADD
 */
STATIC _INLINE_ DAT_RETURN 
dapls_ib_post_ext_send (
	IN  DAPL_EP			*ep_ptr,
	IN  ib_send_op_type_t		op_type,
	IN  DAPL_COOKIE			*cookie,
	IN  DAT_COUNT			num_segs,
	IN  DAT_LMR_TRIPLET		*local_iov,
	IN  const DAT_RMR_TRIPLET	*remote_iov,
	IN  DAT_UINT32			immed_data,
	IN  DAT_UINT64			compare_add,
	IN  DAT_UINT64			swap,
	IN  DAT_COMPLETION_FLAGS	completion_flags)
{
	ib_api_status_t ib_status;
	ib_data_segment_t ds_array[DAPL_DEFAULT_DS_ENTRIES], *ds_array_p;
	ib_send_wr_t wr, *bad_wr;
	DAT_COUNT i, total_len;
	
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     "  post_ext_send: ep %p op %d ck %p numSegs %d\n"
		     "    loc_iov %p rem_iov %p flgs %d\n",
		     ep_ptr, op_type, cookie, num_segs, local_iov, 
		     remote_iov, completion_flags);

	if (num_segs <= DAPL_DEFAULT_DS_ENTRIES) 
		ds_array_p = ds_array;
	else
		ds_array_p = dapl_os_alloc(num_segs*sizeof(ib_data_segment_t));

	if (NULL == ds_array_p)
	{
#ifdef DAPL_DBG
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,"  %s() os_alloc(%d) failed?\n",
			     __FUNCTION__,(num_segs*sizeof(ib_data_segment_t)));
#endif
		return (DAT_INSUFFICIENT_RESOURCES);
	}
	
	/* setup the work request */
	dapl_os_memzero (&wr, sizeof(ib_send_wr_t));
	wr.wr_type = op_type;
	wr.wr_id = (uint64_t)(uintptr_t)cookie;
	wr.ds_array = ds_array_p;

	total_len = 0;

	for (i = 0; i < num_segs; i++ ) {
		if ( !local_iov[i].segment_length )
			continue;

		ds_array_p->vaddr = (uint64_t) local_iov[i].virtual_address;
		ds_array_p->length = local_iov[i].segment_length;
		ds_array_p->lkey = htonl(local_iov[i].lmr_context);
		
		dapl_dbg_log(DAPL_DBG_TYPE_EP, 
			     " post_snd: lkey 0x%x va %p len %d\n",
			     ds_array_p->lkey, ds_array_p->vaddr, 
			     ds_array_p->length );

		total_len += ds_array_p->length;
		wr.num_ds++;
		ds_array_p++;
	}

	if (cookie != NULL) 
		cookie->val.dto.size = total_len;

	switch (op_type) {

	  case OP_RDMA_WRITE_IMM:
		wr.immediate_data = immed_data;
		wr.send_opt |= IB_SEND_OPT_IMMEDIATE;
		/* fall thru */
	  case OP_RDMA_WRITE:
		wr.wr_type = WR_RDMA_WRITE;
#if 1 // XXX
		if ( immed_data == 0 ) {
		        dapl_dbg_log(DAPL_DBG_TYPE_EP,
                                    "%s() immediate data == 0?\n",__FUNCTION__);
			break;
		}
#endif
		dapl_dbg_log(DAPL_DBG_TYPE_EP, 
			     " post_ext: OP_RDMA_WRITE_IMM rkey 0x%x va "
			     "%#016Lx immed=0x%x\n",
			     remote_iov->rmr_context, 
			     remote_iov->virtual_address, immed_data);

		wr.remote_ops.vaddr = remote_iov->virtual_address;
		wr.remote_ops.rkey = htonl(remote_iov->rmr_context);
		break;

	  case OP_COMP_AND_SWAP:
		wr.wr_type = WR_COMPARE_SWAP;
		dapl_dbg_log(DAPL_DBG_TYPE_ERR/*DAPL_DBG_TYPE_EP XXX*/, 
			     " post_ext: OP_COMP_AND_SWAP=%llx,%llx rkey 0x%x "
			     "va %llx\n",
			     compare_add, swap, remote_iov->rmr_context,
			     remote_iov->virtual_address);
		
		wr.remote_ops.vaddr = remote_iov->virtual_address;
		wr.remote_ops.rkey = htonl(remote_iov->rmr_context);
		wr.remote_ops.atomic1 = compare_add;
		wr.remote_ops.atomic2 = swap;
		break;

	  case OP_FETCH_AND_ADD:
		wr.wr_type = WR_FETCH_ADD;
		dapl_dbg_log(DAPL_DBG_TYPE_EP, 
			     " post_ext: OP_FETCH_AND_ADD=%lx,%lx rkey 0x%x\n",
				remote_iov->virtual_address, compare_add,
				remote_iov->rmr_context);

		wr.remote_ops.vaddr = remote_iov->virtual_address;
		wr.remote_ops.rkey = htonl(remote_iov->rmr_context);
		wr.remote_ops.atomic1 = compare_add;
		wr.remote_ops.atomic2 = 0;
		break;

	  default:
		break;
	}

	/* set completion flags in work request */
	wr.send_opt |= (DAT_COMPLETION_SUPPRESS_FLAG & 
				completion_flags) ? 0 : IB_SEND_OPT_SIGNALED;
	wr.send_opt |= (DAT_COMPLETION_BARRIER_FENCE_FLAG & 
				completion_flags) ? IB_SEND_OPT_FENCE : 0;
	wr.send_opt |= (DAT_COMPLETION_SOLICITED_WAIT_FLAG & 
				completion_flags) ? IB_SEND_OPT_SOLICITED : 0;

	dapl_dbg_log(DAPL_DBG_TYPE_EP, " post_snd1: wr_type 0x%x snd_opt 0x%x "
					"ds_arry %llx num_ds %d\n", 
		     wr.wr_type, wr.send_opt, wr.ds_array, wr.num_ds);

	ib_status = ib_post_send(ep_ptr->qp_handle, &wr, &bad_wr);

	if (num_segs > DAPL_DEFAULT_DS_ENTRIES)
	    dapl_os_free(wr.ds_array, num_segs * sizeof(ib_local_ds_t));

	if ( ib_status == IB_SUCCESS )
		return DAT_SUCCESS;

        dapl_dbg_log (DAPL_DBG_TYPE_EP,
                      "--> DsPS: EP=%p post_send status = %s\n", 
                      ep_ptr, ib_get_err_str(ib_status));
        /*
         * Moving QP to error state; 
         */
        ib_status = dapls_modify_qp_state_to_error ( ep_ptr->qp_handle);
        ep_ptr->qp_state = IB_QPS_ERROR;

	return (dapl_ib_status_convert (ib_status));
}

#endif	/* DAT_EXTENSIONS */

#endif /* _DAPL_IBAL_DTO_H */
