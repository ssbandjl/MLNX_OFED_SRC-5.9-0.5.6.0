/*
 * Copyright (c) 2011 Intel Corporation.  All rights reserved.
 * 
 * This Software is licensed under one of the following licenses:
 * 
 * 1) under the terms of the "Common Public License 1.0" a copy of which is
 *    in the file LICENSE.txt in the root directory. The license is also
 *    available from the Open Source Initiative, see 
 *    http://www.opensource.org/licenses/cpl.php.
 * 
 * 2) under the terms of the "The BSD License" a copy of which is in the file
 *    LICENSE2.txt in the root directory. The license is also available from
 *    the Open Source Initiative, see
 *    http://www.opensource.org/licenses/bsd-license.php.
 * 
 * 3) under the terms of the "GNU General Public License (GPL) Version 2" a
 *    copy of which is in the file LICENSE3.txt in the root directory. The
 *    license is also available from the Open Source Initiative, see
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
#ifndef _IB_COLLECTIVES_H_
#define _IB_COLLECTIVES_H_

#ifdef DAT_IB_COLLECTIVES

/* DAPL handle magic for collective */
#define	DAPL_MAGIC_COLL	0xbabeface

/* IB Collective Provider */
#ifdef DAT_FCA_PROVIDER
#include <collectives/fca_provider.h>
#endif 

/* IB Collective Provider Prototypes */
int  dapli_create_collective_service(IN struct dapl_hca *hca);
void dapli_free_collective_service(IN struct dapl_hca *hca);

DAT_RETURN
dapli_create_collective_member(
	IN  DAT_IA_HANDLE		ia_handle,
	IN  void			*progress_func,
	OUT DAT_COUNT			*member_size,
	OUT DAT_IB_COLLECTIVE_MEMBER	*member);

DAT_RETURN
dapli_free_collective_member(
	IN  DAT_IA_HANDLE		ia_handle,
	IN DAT_IB_COLLECTIVE_MEMBER	member);

DAT_RETURN
dapli_create_collective_group(
	IN  DAT_EVD_HANDLE		evd_handle,
	IN  DAT_PZ_HANDLE		pz,
	IN  DAT_IB_COLLECTIVE_MEMBER	*members,
	IN  DAT_COUNT			ranks,
	IN  DAT_IB_COLLECTIVE_RANK	self,
	IN  DAT_IB_COLLECTIVE_ID	id,
	IN  DAT_IB_COLLECTIVE_GROUP	*g_info,
	IN  DAT_DTO_COOKIE		user_ctx);

DAT_RETURN
dapli_free_collective_group(
        IN DAT_IB_COLLECTIVE_HANDLE	coll_handle);

DAT_RETURN
dapli_collective_barrier(
        IN DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN DAT_DTO_COOKIE		user_context,
        IN DAT_COMPLETION_FLAGS		comp_flags);

DAT_RETURN
dapli_collective_broadcast(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			buffer,
 	IN  DAT_COUNT			byte_count,
	IN  DAT_IB_COLLECTIVE_RANK	root,
	IN  DAT_CONTEXT			user_context,
	IN  DAT_COMPLETION_FLAGS	comp_flags);

DAT_RETURN
dapli_collective_reduce(
	IN  DAT_IB_COLLECTIVE_HANDLE		coll_handle,
	IN  DAT_PVOID				snd_buf,
 	IN  DAT_COUNT				snd_len,
	IN  DAT_PVOID				rcv_buf,
 	IN  DAT_COUNT				rcv_len,
	IN  DAT_IB_COLLECTIVE_REDUCE_DATA_OP	op,
	IN  DAT_IB_COLLECTIVE_DATA_TYPE		type,
	IN  DAT_IB_COLLECTIVE_RANK		root,
	IN  DAT_CONTEXT				user_context,
	IN  DAT_COMPLETION_FLAGS		comp_flags);

DAT_RETURN
dapli_collective_allreduce(
	IN  DAT_IB_COLLECTIVE_HANDLE		coll_handle,
	IN  DAT_PVOID				snd_buf,
 	IN  DAT_COUNT				snd_len,
	IN  DAT_PVOID				rcv_buf,
 	IN  DAT_COUNT				rcv_len,
	IN  DAT_IB_COLLECTIVE_REDUCE_DATA_OP	op,
	IN  DAT_IB_COLLECTIVE_DATA_TYPE		type,
	IN  DAT_CONTEXT				context,
	IN  DAT_COMPLETION_FLAGS		comp_flags);

DAT_RETURN
dapli_collective_scatter(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			rcv_buf,
 	IN  DAT_COUNT			rcv_len,
	IN  DAT_IB_COLLECTIVE_RANK	root,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags);

DAT_RETURN
dapli_collective_scatterv(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			*snd_bufs,
 	IN  DAT_COUNT			*snd_lens,
 	IN  DAT_COUNT			*displs,
	IN  DAT_PVOID			rcv_buf,
 	IN  DAT_COUNT			rcv_len,
	IN  DAT_IB_COLLECTIVE_RANK	root,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags);

DAT_RETURN
dapli_collective_gather(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			rcv_buf,
 	IN  DAT_COUNT			rcv_len,
	IN  DAT_IB_COLLECTIVE_RANK	root,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags);

DAT_RETURN
dapli_collective_gatherv(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			*rcv_bufs,
 	IN  DAT_COUNT			*rcv_lens,
 	IN  DAT_COUNT			*displs,
	IN  DAT_IB_COLLECTIVE_RANK	root,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags);

DAT_RETURN
dapli_collective_allgather(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			rcv_buf,
 	IN  DAT_COUNT			rcv_len,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags);

DAT_RETURN
dapli_collective_allgatherv(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			*rcv_bufs,
 	IN  DAT_COUNT			*rcv_lens,
 	IN  DAT_COUNT			*displs,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags);

DAT_RETURN
dapli_collective_alltoall(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			rcv_buf,
 	IN  DAT_COUNT			rcv_len,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags);

DAT_RETURN
dapli_collective_alltoallv(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			*snd_bufs,
 	IN  DAT_COUNT			*snd_lens,
 	IN  DAT_COUNT			*snd_displs,
	IN  DAT_PVOID			*rcv_bufs,
 	IN  DAT_COUNT			*rcv_lens,
 	IN  DAT_COUNT			*rcv_displs,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags);

DAT_RETURN
dapli_collective_reduce_scatter(
	IN  DAT_IB_COLLECTIVE_HANDLE		coll_handle,
	IN  DAT_PVOID				snd_buf,
 	IN  DAT_COUNT				snd_len,
	IN  DAT_PVOID				rcv_buf,
 	IN  DAT_COUNT				*rcv_lens,
	IN  DAT_IB_COLLECTIVE_REDUCE_DATA_OP	op,
	IN  DAT_IB_COLLECTIVE_DATA_TYPE		type,
	IN  DAT_CONTEXT				user_context,
	IN  DAT_COMPLETION_FLAGS		comp_flags);

DAT_RETURN
dapli_collective_scan(
	IN  DAT_IB_COLLECTIVE_HANDLE		coll_handle,
	IN  DAT_PVOID				snd_buf,
 	IN  DAT_COUNT				snd_len,
	IN  DAT_PVOID				rcv_buf,
 	IN  DAT_COUNT				rcv_len,
	IN  DAT_IB_COLLECTIVE_REDUCE_DATA_OP	op,
	IN  DAT_IB_COLLECTIVE_DATA_TYPE		type,
	IN  DAT_CONTEXT				user_context,
	IN  DAT_COMPLETION_FLAGS		comp_flags);

#endif /* DAT_IB_COLLECTIVES */
#endif /* _IB_COLLECTIVES_H_ */
