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

/*
 * dapl_ib_srq_alloc
 *
 * Alloc a SRQ
 *
 * Input:
 *	ia_handle	SRQ handle
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
dapls_ib_srq_alloc(IN DAPL_SRQ *srq_ptr)
{
	struct ibv_srq_init_attr srq_init_attr;
	ib_pd_handle_t ib_pd_handle;

	dapl_dbg_log(DAPL_DBG_TYPE_SRQ,
		     " srq alloc: srq %p\n", srq_ptr);

	ib_pd_handle = ((DAPL_PZ *) srq_ptr->param.pz_handle)->pd_handle;
	srq_init_attr.srq_context = NULL;
	srq_init_attr.attr.max_wr = srq_ptr->param.max_recv_dtos;
	srq_init_attr.attr.max_sge = srq_ptr->param.max_recv_iov;
	srq_init_attr.attr.srq_limit = 0;

	srq_ptr->srq_handle = ibv_create_srq(ib_pd_handle, &srq_init_attr);
	if (!srq_ptr->srq_handle)
		goto err;

	return DAT_SUCCESS;

err:
	dapl_log(DAPL_DBG_TYPE_ERR, "ib_srq_alloc ERR %s\n", strerror(errno));

	return dapl_convert_errno(ENOMEM, "srq_allocate" );
}

/*
 * dapl_ib_srq_free
 *
 * Free a SRQ
 *
 * Input:
 *	ia_handle	SRQ handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_PARAMETER
 * 	dapl_convert_errno
 */
DAT_RETURN
dapls_ib_srq_free(IN DAPL_SRQ *srq_ptr)
{

	dapl_dbg_log(DAPL_DBG_TYPE_SRQ, " srq free: srq %p\n", srq_ptr);

	if (srq_ptr->srq_handle == IB_INVALID_HANDLE)
		return DAT_INVALID_PARAMETER;

	if (ibv_destroy_srq(srq_ptr->srq_handle)) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			" srq_free: ibv_destroy_srq error - %s\n",
			strerror(errno));
		return (dapl_convert_errno(errno, "srq_free"));
	}

	return DAT_SUCCESS;
}

/*
 * dapl_ib_srq_resize
 *
 *Resize a SRQ
 *
 * Input:
 *	SRQ handle
 *	New size
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
dapls_ib_srq_resize(IN DAPL_SRQ *srq_ptr, IN uint32_t new_max_wr)
{
	struct ibv_srq_attr srq_attr;

	dapl_dbg_log(DAPL_DBG_TYPE_SRQ, " srq resize: srq %p\n", srq_ptr);

	srq_attr.max_wr = new_max_wr;

	if (ibv_modify_srq(srq_ptr->srq_handle, &srq_attr, IBV_SRQ_MAX_WR)) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " srq_resize: ibv_modify_srq error - %s\n",
			 strerror(errno));
		return (dapl_convert_errno(errno, "srq_resize"));
	}

	return DAT_SUCCESS;
}
