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

#define CONN_STATE 1
#define TIMEOUT_TEST 2
#define DATAXFER_TEST 3

int DT_dataxfer_client_generic(DT_Tdep_Print_Head * phead,
			       FFT_Cmd_t * cmd, int flag)
{
	int res = 1;
	FFT_Connection_t conn;
	DAT_RETURN rc = 0;

	DT_fft_init_client(phead, cmd, &conn);
	DT_assert_dat(phead, conn.ia_handle != NULL)

	    DT_assert(phead, DT_fft_connect(phead, &conn));

	if (flag == CONN_STATE) {
		res = 1;
		goto cleanup;
	} else if (flag == TIMEOUT_TEST) {

	} else if (flag == DATAXFER_TEST) {
		conn.bpool = DT_BpoolAlloc(0,
					   phead,
					   conn.ia_handle,
					   conn.pz_handle,
					   NULL,
					   NULL,
					   4096,
					   2,
					   DAT_OPTIMAL_ALIGNMENT, false, false);
		DT_assert(phead, conn.bpool != 0);
		rc = DT_post_send_buffer(phead, conn.ep_handle, conn.bpool, 0,
					 DT_Bpool_GetBuffSize(conn.bpool, 0));
		DT_assert_dat(phead, rc == DAT_SUCCESS);
		rc = dat_evd_wait(conn.send_evd, 10 * 1000000, 1, &conn.event,
				  &conn.count);
		DT_assert_dat(phead, rc == DAT_SUCCESS);
		res = 1;
		goto cleanup;
	}
	// cleanup
      cleanup:

	if (conn.ep_handle) {
		// disconnect
		DT_Tdep_PT_Printf(phead, "Disconnect\n");
		rc = dat_ep_disconnect(conn.ep_handle, DAT_CLOSE_ABRUPT_FLAG);
		DT_assert_clean(phead, rc == DAT_SUCCESS);
	}
	rc = DT_fft_destroy_conn_struct(phead, &conn);
	DT_assert_clean(phead, rc == DAT_SUCCESS);

	return res;
}

int DT_dataxfer_client_case0(DT_Tdep_Print_Head * phead, FFT_Cmd_t * cmd)
{
	DT_Tdep_PT_Printf(phead, "\
	Description: This is a helper case on the client side for dataxfer case0.\n");
	return DT_dataxfer_client_generic(phead, cmd, CONN_STATE);
}

void DT_dataxfer_client_test(DT_Tdep_Print_Head * phead, FFT_Cmd_t * cmd)
{
	int i;
	int res;
	FFT_Testfunc_t cases_func[] = {
		{DT_dataxfer_client_case0},
	};

	for (i = 0; i < cmd->size; i++) {
		if (cmd->cases_flag[i]) {
			DT_Tdep_PT_Printf(phead, "\
		*********************************************************************\n");
			DT_Tdep_PT_Printf(phead, "\
		Function feature: Dataxfer client         case: %d\n", i);
			res = cases_func[i].fun(phead, cmd);
			if (res == 1) {
				DT_Tdep_PT_Printf(phead, "Result: PASS\n");
			} else if (res == 0) {
				DT_Tdep_PT_Printf(phead, "Result: FAIL\n");
			} else if (res == -1) {

				DT_Tdep_PT_Printf(phead,
						  "Result: use other test tool\n");
			} else if (res == -2) {
				DT_Tdep_PT_Printf(phead,
						  "Result: not support or next stage to develop\n");
			}

			DT_Tdep_PT_Printf(phead, "\
		*********************************************************************\n");
		}
	}
	return;
}
