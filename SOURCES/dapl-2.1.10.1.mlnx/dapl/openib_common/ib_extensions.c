/*
 * Copyright (c) 2007-2009 Intel Corporation.  All rights reserved.
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
#include "dapl_ib_util.h"
#include "dapl_ep_util.h"
#include "dapl_ia_util.h"
#include "dapl_cookie.h"
#include "dapl_provider.h"

#include <stdarg.h>

#ifdef DAT_IB_COLLECTIVES
#include "collectives/ib_collectives.h"
#endif

DAT_RETURN
dapli_post_ext(IN DAT_EP_HANDLE ep_handle,
	       IN DAT_UINT64 cmp_add,
	       IN DAT_UINT64 swap,
	       IN DAT_UINT32 immed_data,
	       IN DAT_COUNT segments,
	       IN DAT_LMR_TRIPLET * local_iov,
	       IN DAT_DTO_COOKIE user_cookie,
	       IN const DAT_RMR_TRIPLET * remote_iov,
	       IN int op_type,
	       IN DAT_COMPLETION_FLAGS flags, IN DAT_IB_ADDR_HANDLE * ah);

DAT_RETURN
dapli_open_query_ext(IN const DAT_NAME_PTR name,
		     OUT DAT_IA_HANDLE * ia_handle,
		     IN DAT_IA_ATTR_MASK ia_mask,
		     OUT DAT_IA_ATTR * ia_attr,
		     IN DAT_PROVIDER_ATTR_MASK pr_mask,
		     OUT DAT_PROVIDER_ATTR * pr_attr);

/*
 * dapl_extensions
 *
 * Process extension requests
 *
 * Input:
 *	ext_type,
 *	...
 *
 * Output:
 * 	Depends....
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_NOT_IMPLEMENTED
 *      .....
 *
 */
DAT_RETURN
dapl_extensions(IN DAT_HANDLE dat_handle,
		IN DAT_EXTENDED_OP ext_op,
		IN va_list args)
{
	DAT_EP_HANDLE ep;
	DAT_IB_ADDR_HANDLE *ah = NULL;
	DAT_LMR_TRIPLET *lmr_p;
	DAT_DTO_COOKIE cookie;
	const DAT_RMR_TRIPLET *rmr_p;
	DAT_UINT64 dat_uint64a, dat_uint64b;
	DAT_UINT32 dat_uint32;
	DAT_COUNT segments = 1;
	DAT_COMPLETION_FLAGS comp_flags;
	DAT_RETURN status = DAT_NOT_IMPLEMENTED;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
		     "dapl_extensions(hdl %p operation %d, ...)\n",
		     dat_handle, ext_op);

	switch ((int)ext_op) {

	case DAT_IB_OPEN_QUERY_OP:
	{
		dapl_dbg_log(DAPL_DBG_TYPE_RTN,
			     " OPEN_QUERY extension call\n");

		DAT_IA_HANDLE *ia_handle = va_arg(args, DAT_IA_HANDLE *);
		DAT_IA_ATTR_MASK ia_mask = va_arg(args, DAT_IA_ATTR_MASK);
		DAT_IA_ATTR *ia_attr = va_arg(args, DAT_IA_ATTR *);
		DAT_PROVIDER_ATTR_MASK pr_mask = va_arg(args, DAT_PROVIDER_ATTR_MASK);
		DAT_PROVIDER_ATTR *pr_attr = va_arg(args, DAT_PROVIDER_ATTR *);
		DAT_NAME_PTR name = (DAT_NAME_PTR) dat_handle;

		status = dapli_open_query_ext(name, ia_handle, ia_mask,
					      ia_attr, pr_mask, pr_attr);
		break;
	}
	case DAT_IB_CLOSE_QUERY_OP:
		dapl_dbg_log(DAPL_DBG_TYPE_RTN,
			     " CLOSE_QUERY extension call\n");

		status = dapl_ia_close(dat_handle, DAT_CLOSE_ABRUPT_FLAG);
		break;

	case DAT_IB_RDMA_WRITE_IMMED_OP:
		dapl_dbg_log(DAPL_DBG_TYPE_RTN,
			     " WRITE_IMMED_DATA extension call\n");

		ep = dat_handle;	/* ep_handle */
		segments = va_arg(args, DAT_COUNT);	/* num segments */
		lmr_p = va_arg(args, DAT_LMR_TRIPLET *);
		cookie = va_arg(args, DAT_DTO_COOKIE);
		rmr_p = va_arg(args, const DAT_RMR_TRIPLET *);
		dat_uint32 = va_arg(args, DAT_UINT32);	/* immed data */
		comp_flags = va_arg(args, DAT_COMPLETION_FLAGS);

		status = dapli_post_ext(ep, 0, 0, dat_uint32, segments, lmr_p,
					cookie, rmr_p, OP_RDMA_WRITE_IMM,
					comp_flags, ah);
		break;

	case DAT_IB_CMP_AND_SWAP_OP:
		dapl_dbg_log(DAPL_DBG_TYPE_RTN,
			     " CMP_AND_SWAP extension call\n");

		ep = dat_handle;	/* ep_handle */
		dat_uint64a = va_arg(args, DAT_UINT64);	/* cmp_value */
		dat_uint64b = va_arg(args, DAT_UINT64);	/* swap_value */
		lmr_p = va_arg(args, DAT_LMR_TRIPLET *);
		cookie = va_arg(args, DAT_DTO_COOKIE);
		rmr_p = va_arg(args, const DAT_RMR_TRIPLET *);
		comp_flags = va_arg(args, DAT_COMPLETION_FLAGS);

		status = dapli_post_ext(ep, dat_uint64a, dat_uint64b,
					0, segments, lmr_p, cookie, rmr_p,
					OP_COMP_AND_SWAP, comp_flags, ah);
		break;

	case DAT_IB_FETCH_AND_ADD_OP:
		dapl_dbg_log(DAPL_DBG_TYPE_RTN,
			     " FETCH_AND_ADD extension call\n");

		ep = dat_handle;	/* ep_handle */
		dat_uint64a = va_arg(args, DAT_UINT64);	/* add value */
		lmr_p = va_arg(args, DAT_LMR_TRIPLET *);
		cookie = va_arg(args, DAT_DTO_COOKIE);
		rmr_p = va_arg(args, const DAT_RMR_TRIPLET *);
		comp_flags = va_arg(args, DAT_COMPLETION_FLAGS);

		status = dapli_post_ext(ep, dat_uint64a, 0, 0, segments,
					lmr_p, cookie, rmr_p,
					OP_FETCH_AND_ADD, comp_flags, ah);
		break;

	case DAT_IB_UD_SEND_OP:
		dapl_dbg_log(DAPL_DBG_TYPE_RTN,
			     " UD post_send extension call\n");

		ep = dat_handle;	/* ep_handle */
		segments = va_arg(args, DAT_COUNT);	/* segments */
		lmr_p = va_arg(args, DAT_LMR_TRIPLET *);
		ah = va_arg(args, DAT_IB_ADDR_HANDLE *);
		cookie = va_arg(args, DAT_DTO_COOKIE);
		comp_flags = va_arg(args, DAT_COMPLETION_FLAGS);

		status = dapli_post_ext(ep, 0, 0, 0, segments,
					lmr_p, cookie, NULL,
					OP_SEND_UD, comp_flags, ah);
		break;

	case DAT_IB_UD_CM_FREE_OP:
	{
		ib_cm_srvc_handle_t cm;

		dapl_dbg_log(DAPL_DBG_TYPE_RTN,
			     " UD cm_free extension call\n");

		ep = dat_handle;
		cm = (ib_cm_srvc_handle_t) va_arg(args, DAT_UINT64);

		if (DAPL_BAD_HANDLE(ep, DAPL_MAGIC_EP))
			status = DAT_ERROR(DAT_INVALID_HANDLE,
					   DAT_INVALID_HANDLE_EP);
		else {
			status = dapls_ud_cm_free(ep, cm);
		}
		break;
	}
	case DAT_IB_UD_AH_FREE_OP:
	{
		DAT_IB_ADDR_HANDLE *dat_ah;
		uint16_t lid;

		dapl_dbg_log(DAPL_DBG_TYPE_RTN,
			     " UD ah_free extension call\n");

		ep = dat_handle;
		dat_ah = va_arg(args, DAT_IB_ADDR_HANDLE *);

		if (DAPL_BAD_HANDLE(ep, DAPL_MAGIC_EP)) {
			status = DAT_ERROR(DAT_INVALID_HANDLE,
					   DAT_INVALID_HANDLE_EP);
		} else {
			lid = ntohs(((union dcm_addr *)&dat_ah->ia_addr)->ib.lid);

			if (lid > DCM_AH_SPACE) {
				status = DAT_ERROR(DAT_INVALID_PARAMETER,
						   DAT_INVALID_ARG2);
				break;
			}

			errno = 0;
			if (!((DAPL_EP *)ep)->qp_handle->ah[lid])
				ibv_destroy_ah(dat_ah->ah);

			status = dapl_convert_errno(errno, "destroy_ah");
		}
		break;
	}
#ifdef DAPL_COUNTERS
	case DAT_QUERY_COUNTERS_OP:
		{
			int cntr, reset;
			DAT_UINT64 *p_cntr_out;

			dapl_dbg_log(DAPL_DBG_TYPE_RTN,
				     " Query counter extension call\n");

			cntr = va_arg(args, int);
			p_cntr_out = va_arg(args, DAT_UINT64 *);
			reset = va_arg(args, int);

			status = dapl_query_counter(dat_handle, cntr,
						    p_cntr_out, reset);
			break;
		}
	case DAT_PRINT_COUNTERS_OP:
		{
			int cntr, reset;

			dapl_dbg_log(DAPL_DBG_TYPE_RTN,
				     " Print counter extension call\n");

			cntr = va_arg(args, int);
			reset = va_arg(args, int);

			dapl_print_counter(dat_handle, cntr, reset);
			status = DAT_SUCCESS;
			break;
		}
	case DAT_IB_START_COUNTERS_OP:
		{
			DAT_IA_COUNTER_TYPE type;

			dapl_dbg_log(DAPL_DBG_TYPE_RTN,
				     " Start counter extension call\n");

			type = va_arg(args, int);

			dapl_start_counters(dat_handle, type);
			status = DAT_SUCCESS;
			break;
		}
	case DAT_IB_STOP_COUNTERS_OP:
		{
			DAT_IA_COUNTER_TYPE type;

			dapl_dbg_log(DAPL_DBG_TYPE_RTN,
				     " Start counter extension call\n");

			type = va_arg(args, int);

			dapl_stop_counters(dat_handle, type);
			status = DAT_SUCCESS;
			break;
		}
#endif				/* DAPL_COUNTERS */
#ifdef DAT_IB_COLLECTIVES
	case DAT_IB_COLLECTIVE_CREATE_MEMBER_OP:
	{
		void *progress_func;
		DAT_IB_COLLECTIVE_MEMBER *member_p;
		DAT_COUNT *size_p;

		dapl_dbg_log(DAPL_DBG_TYPE_EXTENSION,
			     " COLLECTIVE_CREATE_MEMBER extension call\n");

		progress_func = va_arg(args, void *);
		member_p = va_arg(args, DAT_IB_COLLECTIVE_MEMBER *);
		size_p   = va_arg(args, DAT_COUNT *);

		return dapli_create_collective_member(dat_handle,
						      progress_func,
						      size_p,
						      member_p);
	}
	case DAT_IB_COLLECTIVE_FREE_MEMBER_OP:
	{
		DAT_IB_COLLECTIVE_MEMBER member;

		dapl_dbg_log(DAPL_DBG_TYPE_EXTENSION,
				" COLLECTIVE_FREE_MEMBER extension call\n");

		member = va_arg(args, DAT_IB_COLLECTIVE_MEMBER);
		return dapli_free_collective_member(dat_handle, member);
	}
	case DAT_IB_COLLECTIVE_CREATE_GROUP_OP:
	{
		DAT_CONTEXT context;
		DAT_IB_COLLECTIVE_MEMBER *members;
		DAT_IB_COLLECTIVE_GROUP *grp;
		DAT_IB_COLLECTIVE_RANK rank;
		DAT_IB_COLLECTIVE_ID id;
		DAT_PZ_HANDLE pd;
		DAT_COUNT size;

		dapl_dbg_log(DAPL_DBG_TYPE_EXTENSION,
				" DAT_IB_COLLECTIVE_CREATE_GROUP extension call\n");

		members = va_arg(args, DAT_IB_COLLECTIVE_MEMBER *);/* array */
		size    = va_arg(args, DAT_COUNT);/* member count */
		rank    = va_arg(args, DAT_IB_COLLECTIVE_RANK);/* rank */
		id      = va_arg(args, DAT_IB_COLLECTIVE_ID);/* group id */
		grp     = va_arg(args, DAT_IB_COLLECTIVE_GROUP *);/* group info */
		pd      = va_arg(args, DAT_PZ_HANDLE);/* prot domain */
		context = va_arg(args, DAT_CONTEXT);

		return  dapli_create_collective_group(dat_handle, pd, members,
						      size, rank, id, grp, context);
	}
	case DAT_IB_COLLECTIVE_FREE_GROUP_OP:
	{
		dapl_dbg_log(DAPL_DBG_TYPE_EXTENSION,
				" DAT_IB_COLLECTIVE_FREE_GROUP extension call\n");

		return dapli_free_collective_group(dat_handle);
	}
	case DAT_IB_COLLECTIVE_BARRIER_OP:
	{
		DAT_CONTEXT context;

		dapl_dbg_log(DAPL_DBG_TYPE_EXTENSION,
                        "Got DAT_IB_COLLECTIVE_BARRIER extension call\n");

                context    = va_arg(args, DAT_CONTEXT);
                comp_flags = va_arg(args, DAT_COMPLETION_FLAGS);

                return dapli_collective_barrier(dat_handle, context, comp_flags);
	}
        case DAT_IB_COLLECTIVE_BROADCAST_OP:
        {
        	DAT_CONTEXT context;
        	DAT_PVOID buf;
        	DAT_COUNT size;
        	DAT_IB_COLLECTIVE_RANK root;

                dapl_dbg_log(DAPL_DBG_TYPE_EXTENSION,
                        "Got DAT_IB_COLLECTIVE_BROADCAST extension call\n");

                buf        = va_arg(args, DAT_PVOID);
                size       = va_arg(args, DAT_COUNT);
                root       = va_arg(args, DAT_IB_COLLECTIVE_RANK);
                context    = va_arg(args, DAT_CONTEXT);
                comp_flags = va_arg(args, DAT_COMPLETION_FLAGS);

                return dapli_collective_broadcast(dat_handle, buf, size,
                                                  root, context, comp_flags);

        }
        case DAT_IB_COLLECTIVE_REDUCE_OP:
        {
        	DAT_CONTEXT context;
		DAT_IB_COLLECTIVE_RANK root;
		DAT_PVOID sbuf, rbuf;
		DAT_COUNT slen, rlen;
		DAT_IB_COLLECTIVE_REDUCE_DATA_OP op;
		DAT_IB_COLLECTIVE_DATA_TYPE type;

                dapl_dbg_log(DAPL_DBG_TYPE_EXTENSION,
                        "Got DAT_IB_COLLECTIVE_REDUCE extension call\n");

                sbuf       = va_arg(args, DAT_PVOID);
                slen       = va_arg(args, DAT_COUNT);
                rbuf       = va_arg(args, DAT_PVOID);
                rlen       = va_arg(args, DAT_COUNT);
                op         = va_arg(args, DAT_IB_COLLECTIVE_REDUCE_DATA_OP);
                type       = va_arg(args, DAT_IB_COLLECTIVE_DATA_TYPE);
                root       = va_arg(args, DAT_IB_COLLECTIVE_RANK);
                context    = va_arg(args, DAT_CONTEXT);
                comp_flags = va_arg(args, DAT_COMPLETION_FLAGS);

                return dapli_collective_reduce(dat_handle, sbuf, slen,
                			       rbuf, rlen, op, type, root,
                			       context, comp_flags);
        }
        case DAT_IB_COLLECTIVE_ALLREDUCE_OP:
        {
        	DAT_CONTEXT context;
		DAT_PVOID sbuf, rbuf;
		DAT_COUNT slen, rlen;
		DAT_IB_COLLECTIVE_REDUCE_DATA_OP op;
		DAT_IB_COLLECTIVE_DATA_TYPE type;

                dapl_dbg_log(DAPL_DBG_TYPE_EXTENSION,
                        "Got DAT_IB_COLLECTIVE_ALLREDUCE extension call\n");

                sbuf       = va_arg(args, DAT_PVOID);
                slen       = va_arg(args, DAT_COUNT);
                rbuf       = va_arg(args, DAT_PVOID);
                rlen       = va_arg(args, DAT_COUNT);
                op         = va_arg(args, DAT_IB_COLLECTIVE_REDUCE_DATA_OP);
                type       = va_arg(args, DAT_IB_COLLECTIVE_DATA_TYPE);
                context    = va_arg(args, DAT_CONTEXT);
                comp_flags = va_arg(args, DAT_COMPLETION_FLAGS);

                return dapli_collective_allreduce(dat_handle, sbuf, slen,
                				  rbuf, rlen, op, type,
                				  context, comp_flags);
        }
        case DAT_IB_COLLECTIVE_ALLGATHER_OP:
        {
        	DAT_CONTEXT context;
		DAT_PVOID sbuf, rbuf;
		DAT_COUNT slen, rlen;

                dapl_dbg_log(DAPL_DBG_TYPE_EXTENSION,
                        "Got DAT_IB_COLLECTIVE_ALLGATHER extension call\n");

                sbuf       = va_arg(args, DAT_PVOID);
                slen       = va_arg(args, DAT_COUNT);
                rbuf       = va_arg(args, DAT_PVOID);
                rlen       = va_arg(args, DAT_COUNT);
                context    = va_arg(args, DAT_CONTEXT);
                comp_flags = va_arg(args, DAT_COMPLETION_FLAGS);

                return dapli_collective_allgather(dat_handle, sbuf, slen,
                				  rbuf, rlen, context,
                				  comp_flags);
        }
        case DAT_IB_COLLECTIVE_ALLGATHERV_OP:
        {
        	DAT_CONTEXT context;
		DAT_PVOID sbuf, rbuf;
		DAT_COUNT slen;
		DAT_COUNT *rlens;
		DAT_COUNT *displs;

                dapl_dbg_log(DAPL_DBG_TYPE_EXTENSION,
                        "Got DAT_IB_COLLECTIVE_ALLGATHERV extension call\n");

                sbuf       = va_arg(args, DAT_PVOID);
                slen       = va_arg(args, DAT_COUNT);
                rbuf       = va_arg(args, DAT_PVOID);
                rlens      = va_arg(args, DAT_COUNT *);
                displs     = va_arg(args, DAT_COUNT *);
                context    = va_arg(args, DAT_CONTEXT);
                comp_flags = va_arg(args, DAT_COMPLETION_FLAGS);

                return dapli_collective_allgatherv(dat_handle, sbuf, slen,
                				   rbuf, rlens, displs,
                				   context, comp_flags);
        }

#endif
	default:
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			     "unsupported extension(%d)\n", (int)ext_op);
	}

	return (status);
}

DAT_RETURN
dapli_post_ext(IN DAT_EP_HANDLE ep_handle,
	       IN DAT_UINT64 cmp_add,
	       IN DAT_UINT64 swap,
	       IN DAT_UINT32 immed_data,
	       IN DAT_COUNT segments,
	       IN DAT_LMR_TRIPLET * local_iov,
	       IN DAT_DTO_COOKIE user_cookie,
	       IN const DAT_RMR_TRIPLET * remote_iov,
	       IN int op_type,
	       IN DAT_COMPLETION_FLAGS flags, IN DAT_IB_ADDR_HANDLE * ah)
{
	DAPL_EP *ep_ptr;
	DAPL_COOKIE *cookie = NULL;
	DAT_RETURN dat_status = DAT_SUCCESS;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
		     " post_ext_op: ep %p cmp_val %d "
		     "swap_val %d cookie 0x%x, r_iov %p, flags 0x%x, ah %p\n",
		     ep_handle, (unsigned)cmp_add, (unsigned)swap,
		     (unsigned)user_cookie.as_64, remote_iov, flags, ah);

	if (DAPL_BAD_HANDLE(ep_handle, DAPL_MAGIC_EP))
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));

	ep_ptr = (DAPL_EP *) ep_handle;

	/*
	 * Synchronization ok since this buffer is only used for send
	 * requests, which aren't allowed to race with each other.
	 */
	dat_status = dapls_dto_cookie_alloc(&ep_ptr->req_buffer,
					    op_type == OP_RDMA_WRITE_IMM ?
						DAPL_DTO_TYPE_EXTENSION_IMM:
						DAPL_DTO_TYPE_EXTENSION,
					    user_cookie, &cookie);
	if (dat_status != DAT_SUCCESS)
		goto bail;

	/*
	 * Take reference before posting to avoid race conditions with
	 * completions
	 */
	dapl_os_atomic_inc(&ep_ptr->req_count);

	/*
	 * Invoke provider specific routine to post DTO
	 */
	dat_status = dapls_ib_post_ext_send(ep_ptr, op_type, cookie, segments,	/* data segments */
					    local_iov, remote_iov, immed_data,	/* immed data */
					    cmp_add,	/* compare or add */
					    swap,	/* swap */
					    flags, ah);

	if (dat_status != DAT_SUCCESS) {
		dapl_os_atomic_dec(&ep_ptr->req_count);
		dapls_cookie_dealloc(&ep_ptr->req_buffer, cookie);
	}

      bail:
	return dat_status;

}

/* 
 * New provider routine to process extended DTO events 
 */
void
dapls_cqe_to_event_extension(IN DAPL_EP * ep_ptr,
			     IN DAPL_COOKIE * cookie,
			     IN ib_work_completion_t * cqe_ptr,
			     IN DAT_EVENT * event_ptr)
{
	uint32_t ibtype;
	DAT_DTO_COMPLETION_EVENT_DATA *dto =
	    &event_ptr->event_data.dto_completion_event_data;
	DAT_IB_EXTENSION_EVENT_DATA *ext_data = (DAT_IB_EXTENSION_EVENT_DATA *)
	    & event_ptr->event_extension_data[0];
	DAT_DTO_COMPLETION_STATUS dto_status;

	/* Get status from cqe */
	dto_status = dapls_ib_get_dto_status(cqe_ptr);

	dapl_dbg_log(DAPL_DBG_TYPE_EVD,
		     " cqe_to_event_ext: dto_ptr %p ext_ptr %p status %d\n",
		     dto, ext_data, dto_status);

	event_ptr->event_number = DAT_IB_DTO_EVENT;
	dto->ep_handle = cookie->ep;
	dto->user_cookie = cookie->val.dto.cookie;
	dto->operation = DAPL_GET_CQE_DTOS_OPTYPE(cqe_ptr);	/* new for 2.0 */
	dto->status = ext_data->status = dto_status;

	if (dto_status != DAT_DTO_SUCCESS)
		return;

	/* 
	 * Get operation type from CQ work completion entry and
	 * if extented operation then set extended event data
	 */
	ibtype = DAPL_GET_CQE_OPTYPE(cqe_ptr);

	switch (ibtype) {

	case OP_RDMA_WRITE_IMM:
		dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			     " cqe_to_event_ext: OP_RDMA_WRITE_IMMED\n");

		/* type and outbound rdma write transfer size */
		dto->transfered_length = cookie->val.dto.size;
		ext_data->type = DAT_IB_RDMA_WRITE_IMMED;
		break;
	case OP_RECEIVE_IMM:
		dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			     " cqe_to_event_ext: OP_RECEIVE_RDMA_IMMED\n");

		/* immed recvd, type and inbound rdma write transfer size */
		dto->transfered_length = DAPL_GET_CQE_BYTESNUM(cqe_ptr);
		ext_data->type = DAT_IB_RDMA_WRITE_IMMED_DATA;
		ext_data->val.immed.data = DAPL_GET_CQE_IMMED_DATA(cqe_ptr);
		break;
	case OP_RECEIVE_MSG_IMM:
		dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			     " cqe_to_event_ext: OP_RECEIVE_MSG_IMMED\n");

		/* immed recvd, type and inbound recv message transfer size */
		dto->transfered_length = DAPL_GET_CQE_BYTESNUM(cqe_ptr);
		ext_data->type = DAT_IB_RECV_IMMED_DATA;
		ext_data->val.immed.data = DAPL_GET_CQE_IMMED_DATA(cqe_ptr);
		break;
	case OP_COMP_AND_SWAP:
		dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			     " cqe_to_event_ext: COMP_AND_SWAP_RESP\n");

		/* original data is returned in LMR provided with post */
		ext_data->type = DAT_IB_CMP_AND_SWAP;
		dto->transfered_length = DAPL_GET_CQE_BYTESNUM(cqe_ptr);
		break;
	case OP_FETCH_AND_ADD:
		dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			     " cqe_to_event_ext: FETCH_AND_ADD_RESP\n");

		/* original data is returned in LMR provided with post */
		ext_data->type = DAT_IB_FETCH_AND_ADD;
		dto->transfered_length = DAPL_GET_CQE_BYTESNUM(cqe_ptr);
		break;
	case OP_SEND_UD:
		dapl_dbg_log(DAPL_DBG_TYPE_EVD, " cqe_to_event_ext: UD_SEND\n");

		/* type and outbound send transfer size */
		ext_data->type = DAT_IB_UD_SEND;
		dto->transfered_length = cookie->val.dto.size;
		break;
	case OP_RECV_UD:
		dapl_dbg_log(DAPL_DBG_TYPE_EVD, " cqe_to_event_ext: UD_RECV\n");

		/* type and inbound recv message transfer size */
		ext_data->type = DAT_IB_UD_RECV;
		dto->transfered_length = DAPL_GET_CQE_BYTESNUM(cqe_ptr);
		break;

	default:
		/* not extended operation */
		ext_data->status = DAT_IB_OP_ERR;
		dto->status = DAT_DTO_ERR_TRANSPORT;
		break;
	}
}

/*
 * dapli_open_query_ext
 *
 *
 * Direct link to provider for quick provider query without full IA device open
 *
 * Input:
 *	provider name
 *	ia_attr
 *	provider_attr
 *
 * Output:
 * 	ia_attr
 *	provider_attr
 *
 * Return Values:
 * 	DAT_SUCCESS
 * 	DAT_INSUFFICIENT_RESOURCES
 * 	DAT_INVALID_PARAMETER
 * 	DAT_INVALID_HANDLE
 * 	DAT_PROVIDER_NOT_FOUND	(returned by dat registry if necessary)
 */
DAT_RETURN
dapli_open_query_ext(IN const DAT_NAME_PTR name,
		     OUT DAT_IA_HANDLE * ia_handle_ptr,
		     IN DAT_IA_ATTR_MASK ia_mask,
		     OUT DAT_IA_ATTR * ia_attr,
		     IN DAT_PROVIDER_ATTR_MASK pr_mask,
		     OUT DAT_PROVIDER_ATTR * pr_attr)
{
	DAT_RETURN dat_status = DAT_SUCCESS;
	DAT_PROVIDER *provider;
	DAPL_HCA *hca_ptr = NULL;
	DAT_IA_HANDLE ia_ptr = NULL;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		 "dapli_open_query_ext (%s, 0x%llx, %p, 0x%x, %p)\n",
		     name, ia_mask, ia_attr, pr_mask, pr_attr);

	dat_status = dapl_provider_list_search(name, &provider);
	if (DAT_SUCCESS != dat_status) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG1);
		goto bail;
	}

	/* ia_handle_ptr and async_evd_handle_ptr cannot be NULL */
	if ((ia_attr == NULL) && (pr_attr == NULL)) {
		return DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG5);
	}

	/* initialize the caller's OUT param */
	*ia_handle_ptr = DAT_HANDLE_NULL;

	/* get the hca_ptr */
	hca_ptr = (DAPL_HCA *) provider->extension;

	/* log levels could be reset and set between open_query calls  */
	if (dapl_os_get_env_val("DAPL_DBG_TYPE", 0))
		g_dapl_dbg_type =  dapl_os_get_env_val("DAPL_DBG_TYPE", 0);

	/*
	 * Open the HCA if it has not been done before.
	 */
	dapl_os_lock(&hca_ptr->lock);
	if (hca_ptr->ib_hca_handle == IB_INVALID_HANDLE) {
		/* open in query mode */
		dat_status = dapls_ib_open_hca(hca_ptr->name,
					       hca_ptr, DAPL_OPEN_QUERY);
		if (dat_status != DAT_SUCCESS) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
				     "dapls_ib_open_hca failed %x\n",
				     dat_status);
			dapl_os_unlock(&hca_ptr->lock);
			goto bail;
		}
	}
	/* Take a reference on the hca_handle */
	dapl_os_atomic_inc(&hca_ptr->handle_ref_count);
	dapl_os_unlock(&hca_ptr->lock);

	/* Allocate and initialize ia structure */
	ia_ptr = (DAT_IA_HANDLE) dapl_ia_alloc(provider, hca_ptr);
	if (!ia_ptr) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES, DAT_RESOURCE_MEMORY);
		goto cleanup;
	}

	dat_status = dapl_ia_query(ia_ptr, NULL, ia_mask, ia_attr, pr_mask, pr_attr);
	if (dat_status != DAT_SUCCESS) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			     "dapls_ib_query_hca failed %x\n", dat_status);
		goto cleanup;
	}

	*ia_handle_ptr = ia_ptr;
	return DAT_SUCCESS;

cleanup:
	/* close device and release HCA reference */
	if (ia_ptr) {
		dapl_ia_close(ia_ptr, DAT_CLOSE_ABRUPT_FLAG);
	} else {
		dapl_os_lock(&hca_ptr->lock);
		dapls_ib_close_hca(hca_ptr);
		hca_ptr->ib_hca_handle = IB_INVALID_HANDLE;
		dapl_os_atomic_dec(&hca_ptr->handle_ref_count);
		dapl_os_unlock(&hca_ptr->lock);
	}
bail:
	return dat_status;
}

