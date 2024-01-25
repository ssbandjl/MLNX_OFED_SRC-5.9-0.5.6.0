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

/*--------------------------------------------------------*/
int DT_dataxfer_generic(DT_Tdep_Print_Head * phead, FFT_Cmd_t * cmd,
			int test_case)
{
	FFT_Connection_t conn;
	DAT_RETURN rc = 0;
	int res = 1;
	DT_fft_init_server(phead, cmd, &conn);
	DT_assert(phead, NULL != conn.ia_handle);

	DT_fft_listen(phead, &conn);

	switch (test_case) {
	case 0:
		{
			DT_Tdep_PT_Printf(phead, "Posting null send buffer\n");
			rc = DT_post_send_buffer(phead, 0, conn.bpool, 0,
						 DT_Bpool_GetBuffSize(conn.
								      bpool,
								      0));
			DT_assert_dat(phead,
				      DAT_GET_TYPE(rc) == DAT_INVALID_HANDLE);
			break;
		}
	case 1:
		{
			DT_Tdep_PT_Printf(phead,
					  "Call evd wait with null evd\n");
			rc = dat_evd_wait(0, DAT_TIMEOUT_INFINITE, 1,
					  &conn.event, &conn.count);
			DT_assert_dat(phead,
				      DAT_GET_TYPE(rc) == DAT_INVALID_HANDLE);
			break;
		}
	case 2:
		{
			DT_Tdep_PT_Printf(phead,
					  "Call evd wait with empty send queue\n");
			rc = dat_evd_wait(conn.send_evd, 10 * 1000000, 1,
					  &conn.event, &conn.count);
			DT_assert_dat(phead,
				      DAT_GET_TYPE(rc) == DAT_TIMEOUT_EXPIRED);
			break;
		}
	case 3:
		{
			DT_Tdep_PT_Printf(phead, "Posting null recv buffer\n");
			rc = DT_post_recv_buffer(phead, 0, conn.bpool, 0,
						 DT_Bpool_GetBuffSize(conn.
								      bpool,
								      0));
			DT_assert_dat(phead,
				      DAT_GET_TYPE(rc) == DAT_INVALID_HANDLE);
			break;
		}
	}
      cleanup:
	DT_assert_clean(phead, DT_fft_destroy_conn_struct(phead, &conn));
	return res;
}

int DT_dataxfer_case0(DT_Tdep_Print_Head * phead, FFT_Cmd_t * cmd)
{
	DT_Tdep_PT_Printf(phead, "\
	Description: Call dat_ep_post_send with null ep_handle.\n");
	return DT_dataxfer_generic(phead, cmd, 0);
}

int DT_dataxfer_case1(DT_Tdep_Print_Head * phead, FFT_Cmd_t * cmd)
{
	DT_Tdep_PT_Printf(phead, "\
	Description: Call dat_evd_wait with null evd.\n");
	return DT_dataxfer_generic(phead, cmd, 1);
}

int DT_dataxfer_case2(DT_Tdep_Print_Head * phead, FFT_Cmd_t * cmd)
{
	DT_Tdep_PT_Printf(phead, "\
	Description: Call dat_evd_wait with null evd.\n");
	return DT_dataxfer_generic(phead, cmd, 2);
}

int DT_dataxfer_case3(DT_Tdep_Print_Head * phead, FFT_Cmd_t * cmd)
{
	DT_Tdep_PT_Printf(phead, "\
	Description: Call dat_evd_wait with null evd.\n");
	return DT_dataxfer_generic(phead, cmd, 3);
}

/*-------------------------------------------------------------*/
void DT_dataxfer_test(DT_Tdep_Print_Head * phead, FFT_Cmd_t * cmd)
{
	int i;
	int res;
	FFT_Testfunc_t cases_func[] = {
		{DT_dataxfer_case0},
		{DT_dataxfer_case1},
		{DT_dataxfer_case2},
		{DT_dataxfer_case3},
	};

	for (i = 0; i < cmd->size; i++) {
		if (cmd->cases_flag[i]) {
			DT_Tdep_PT_Printf(phead, "\
		*********************************************************************\n");
			DT_Tdep_PT_Printf(phead, "\
		Function feature: Protection Zone management         case: %d\n", i);
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
