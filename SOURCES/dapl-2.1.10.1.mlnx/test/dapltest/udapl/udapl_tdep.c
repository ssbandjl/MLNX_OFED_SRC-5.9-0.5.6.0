/*
 * Copyright (c) 2002-2005, Network Appliance, Inc. All rights reserved.
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

#include "dapl_proto.h"

void DT_Tdep_Init(void)
{
	DT_Mdep_LockInit(&g_PerfTestLock);	/* For kDAPL, this is done in kdapl_module.c */
}

void DT_Tdep_End(void)
{
	DT_Mdep_LockDestroy(&g_PerfTestLock);	/* For kDAPL, this is done in kdapl_module.c */
}

DAT_RETURN DT_Tdep_Execute_Test(Params_t * params_ptr)
{
	return DT_Execute_Test(params_ptr);
}

DAT_RETURN
DT_Tdep_lmr_create(DAT_IA_HANDLE ia_handle,
		   DAT_MEM_TYPE mem_type,
		   DAT_REGION_DESCRIPTION region,
		   DAT_VLEN len,
		   DAT_PZ_HANDLE pz_handle,
		   DAT_MEM_PRIV_FLAGS priv_flag,
		   DAT_LMR_HANDLE * lmr_handle_ptr,
		   DAT_LMR_CONTEXT * lmr_context_ptr,
		   DAT_RMR_CONTEXT * rmr_context_ptr,
		   DAT_VLEN * reg_size_ptr, DAT_VADDR * reg_addr_ptr)
{
	return dat_lmr_create(ia_handle,
			      mem_type,
			      region,
			      len,
			      pz_handle,
			      priv_flag,
			      DAT_VA_TYPE_VA,
			      lmr_handle_ptr,
			      lmr_context_ptr,
			      rmr_context_ptr, reg_size_ptr, reg_addr_ptr);
}

DAT_RETURN
DT_Tdep_evd_create(DAT_IA_HANDLE ia_handle,
		   DAT_COUNT evd_min_qlen,
		   DAT_CNO_HANDLE cno_handle,
		   DAT_EVD_FLAGS evd_flags, DAT_EVD_HANDLE * evd_handle_ptr)
{
	return dat_evd_create(ia_handle,
			      evd_min_qlen,
			      DAT_HANDLE_NULL, evd_flags, evd_handle_ptr);
}

DAT_RETURN DT_Tdep_evd_free(DAT_EVD_HANDLE evd_handle)
{
	return dat_evd_free(evd_handle);
}

DAT_RETURN
DT_Tdep_evd_wait(DAT_EVD_HANDLE evd_handle,
		 DAT_TIMEOUT timeout, DAT_EVENT * event)
{
	DAT_COUNT count;

	return dat_evd_wait(evd_handle, timeout, 1, event, &count);
}

void DT_Tdep_PT_Printf(DT_Tdep_Print_Head * phead, const char *fmt, ...)
{
	char buffer[256];
	va_list args;

	va_start(args, fmt);
	vsprintf(buffer, fmt, args);
	va_end(args);

	printf("%s", buffer);
}

DAT_RETURN DT_Tdep_evd_dequeue(DAT_EVD_HANDLE evd_handle, DAT_EVENT * event)
{
	return dat_evd_dequeue(evd_handle, event);
}
