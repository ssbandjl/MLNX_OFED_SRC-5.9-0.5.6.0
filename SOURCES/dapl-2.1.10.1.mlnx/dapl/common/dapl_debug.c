/*
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
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
#if !defined(__KDAPL__)
#include <stdarg.h>
#include <stdlib.h>
#endif				/* __KDAPL__ */

DAPL_DBG_TYPE g_dapl_dbg_level;	/* debug type override */
DAPL_DBG_TYPE g_dapl_dbg_type;	/* initialized in dapl_init.c */
DAPL_DBG_DEST g_dapl_dbg_dest;	/* initialized in dapl_init.c */
int           g_dapl_dbg_mem;	/* initialized in dapl_init.c */

static char *_ptr_host_ = NULL;
static char _hostname_[128];
static DAPL_OS_TIMEVAL start_t, current_t, last_t; /* microsecond timeStamp STDOUT */
static int delta_t, total_t;

void dapl_internal_dbg_log(DAPL_DBG_TYPE type, const char *fmt, ...)
{
	va_list args;

	if (_ptr_host_ == NULL) {
		gethostname(_hostname_, sizeof(_hostname_));
		_ptr_host_ = _hostname_;
		dapl_os_get_time(&start_t);
		last_t = start_t;
	}

	if ((type & g_dapl_dbg_type) || (type & g_dapl_dbg_level)) {
		if (DAPL_DBG_DEST_STDOUT & g_dapl_dbg_dest) {
			dapl_os_get_time(&current_t);
			delta_t = current_t - last_t;
			total_t = current_t - start_t;
			last_t  = current_t;
			va_start(args, fmt);
			fprintf(stdout, "%s:%s:%x:%x: %d us(%d us%s): ",
				_ptr_host_, PROVIDER_NAME,
				dapl_os_getpid(), dapl_os_gettid(),
				total_t, delta_t, delta_t > 500000 ? "!!!":"");
			dapl_os_vprintf(fmt, args);
			va_end(args);
		}

		if (DAPL_DBG_DEST_SYSLOG & g_dapl_dbg_dest) {
			va_start(args, fmt);
			dapl_os_syslog(fmt, args);
			va_end(args);
		}
	}
}

#ifdef DAPL_COUNTERS

static int rd_ctr(const char *dev,
		  const char *file,
		  int port,
		  DAT_IA_COUNTER_TYPE type,
		  DAT_UINT64 *value)
{
	char *f_path;
	int len, fd;
	char vstr[21];
	char pstr[2];

	sprintf(pstr, "%d", port);
	*value = 0;

	switch (type) {
	case DCNT_IA_CM:
		if (asprintf(&f_path, "/sys/class/infiniband_cm/%s/%s/%s", dev, pstr, file) < 0)
			return -1;
		break;
	case DCNT_IA_LNK:
		if (asprintf(&f_path, "%s/ports/%s/counters/%s", dev, pstr, file) < 0)
			return -1;
		break;
	case DCNT_IA_DIAG:
		if (asprintf(&f_path, "%s/diag_counters/%s", dev, file) < 0)
			return -1;
		break;
	default:
		return -1;
	}

	fd = open(f_path, O_RDONLY);
	if (fd < 0) {
		free(f_path);
		return -1;
	}

	len = read(fd, vstr, 21);

	if (len > 0 && vstr[--len] == '\n')
		vstr[len] = '\0';

	*value = (DAT_UINT64)atoi(vstr);

	close(fd);
	free(f_path);
	return 0;
}

#ifdef _OPENIB_CMA_
static void dapl_start_cm_cntrs(DAT_HANDLE dh)
{
	DAPL_IA *ia = (DAPL_IA *)dh;
	const char *dev = ibv_get_device_name(ia->hca_ptr->ib_trans.ib_dev);
	int port = ia->hca_ptr->port_num;
	DAT_UINT64 *cntrs = (DAT_UINT64 *)ia->cntrs;

	rd_ctr(dev,"cm_tx_msgs/req", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_REQ_TX]);
	rd_ctr(dev,"cm_tx_msgs/rep", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_REP_TX]);
	rd_ctr(dev,"cm_tx_msgs/rtu", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_RTU_TX]);
	rd_ctr(dev,"cm_tx_msgs/rej", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_USER_REJ_TX]);
	rd_ctr(dev,"cm_tx_msgs/mra", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_MRA_TX]);
	rd_ctr(dev,"cm_tx_msgs/dreq", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_DREQ_TX]);
	rd_ctr(dev,"cm_tx_msgs/drep", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_DREP_TX]);

	rd_ctr(dev,"cm_rx_msgs/req", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_REQ_RX]);
	rd_ctr(dev,"cm_rx_msgs/rep", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_REP_RX]);
	rd_ctr(dev,"cm_rx_msgs/rtu", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_RTU_RX]);
	rd_ctr(dev,"cm_rx_msgs/rej", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_USER_REJ_RX]);
	rd_ctr(dev,"cm_rx_msgs/mra", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_MRA_RX]);
	rd_ctr(dev,"cm_rx_msgs/dreq", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_DREQ_RX]);
	rd_ctr(dev,"cm_rx_msgs/drep", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_DREP_RX]);

	rd_ctr(dev,"cm_tx_retries/req", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_REQ_RETRY]);
	rd_ctr(dev,"cm_tx_retries/rep", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_REP_RETRY]);
	rd_ctr(dev,"cm_tx_retries/rtu", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_RTU_RETRY]);
	rd_ctr(dev,"cm_tx_retries/mra", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_MRA_RETRY]);
	rd_ctr(dev,"cm_tx_retries/dreq", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_DREQ_RETRY]);
	rd_ctr(dev,"cm_tx_retries/drep", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_DREP_RETRY]);

	rd_ctr(dev,"cm_tx_duplicates/req", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_REQ_DUP]);
	rd_ctr(dev,"cm_tx_duplicates/rep", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_REP_DUP]);
	rd_ctr(dev,"cm_tx_duplicates/rtu", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_RTU_DUP]);
	rd_ctr(dev,"cm_tx_duplicates/mra", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_MRA_DUP]);
	rd_ctr(dev,"cm_tx_duplicates/dreq", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_DREQ_DUP]);
	rd_ctr(dev,"cm_tx_duplicates/drep", port, DCNT_IA_CM, &cntrs[DCNT_IA_CM_ERR_DREP_DUP]);
}

static void dapl_stop_cm_cntrs(DAT_HANDLE dh)
{
	DAPL_IA *ia = (DAPL_IA *)dh;
	const char *dev = ibv_get_device_name(ia->hca_ptr->ib_trans.ib_dev);
	int port = ia->hca_ptr->port_num;
	DAT_UINT64 *cntrs = (DAT_UINT64 *)ia->cntrs;
	DAT_UINT64 val = 0;

	rd_ctr(dev,"cm_tx_msgs/req", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_REQ_TX] = val - cntrs[DCNT_IA_CM_REQ_TX];
	rd_ctr(dev,"cm_tx_msgs/rep", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_REP_TX] = val - cntrs[DCNT_IA_CM_REP_TX];
	rd_ctr(dev,"cm_tx_msgs/rtu", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_RTU_TX] = val - cntrs[DCNT_IA_CM_RTU_TX];
	rd_ctr(dev,"cm_tx_msgs/rej", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_USER_REJ_TX] = val - cntrs[DCNT_IA_CM_USER_REJ_TX];
	rd_ctr(dev,"cm_tx_msgs/mra", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_MRA_TX] = val - cntrs[DCNT_IA_CM_MRA_TX];
	rd_ctr(dev,"cm_tx_msgs/dreq", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_DREQ_TX] = val - cntrs[DCNT_IA_CM_DREQ_TX];
	rd_ctr(dev,"cm_tx_msgs/drep", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_DREP_TX] = val - cntrs[DCNT_IA_CM_DREP_TX];

	rd_ctr(dev,"cm_rx_msgs/req", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_REQ_RX] = val - cntrs[DCNT_IA_CM_REQ_RX];
	rd_ctr(dev,"cm_rx_msgs/rep", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_REP_RX] = val - cntrs[DCNT_IA_CM_REP_RX];
	rd_ctr(dev,"cm_rx_msgs/rtu", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_RTU_RX] = val - cntrs[DCNT_IA_CM_RTU_RX];
	rd_ctr(dev,"cm_rx_msgs/rej", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_USER_REJ_RX] = val - cntrs[DCNT_IA_CM_USER_REJ_RX];
	rd_ctr(dev,"cm_rx_msgs/mra", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_MRA_RX] = val - cntrs[DCNT_IA_CM_MRA_RX];
	rd_ctr(dev,"cm_rx_msgs/dreq", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_DREQ_RX] = val - cntrs[DCNT_IA_CM_DREQ_RX];
	rd_ctr(dev,"cm_rx_msgs/drep", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_DREP_RX] = val - cntrs[DCNT_IA_CM_DREP_RX];

	rd_ctr(dev,"cm_tx_retries/req", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_REQ_RETRY] = val - cntrs[DCNT_IA_CM_ERR_REQ_RETRY];
	rd_ctr(dev,"cm_tx_retries/rep", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_REP_RETRY] = val - cntrs[DCNT_IA_CM_ERR_REP_RETRY];
	rd_ctr(dev,"cm_tx_retries/rtu", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_RTU_RETRY] = val - cntrs[DCNT_IA_CM_ERR_RTU_RETRY];
	rd_ctr(dev,"cm_tx_retries/mra", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_MRA_RETRY] = val - cntrs[DCNT_IA_CM_ERR_MRA_RETRY];
	rd_ctr(dev,"cm_tx_retries/dreq", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_DREQ_RETRY] = val - cntrs[DCNT_IA_CM_ERR_DREQ_RETRY];
	rd_ctr(dev,"cm_tx_retries/drep", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_DREP_RETRY] = val - cntrs[DCNT_IA_CM_ERR_DREP_RETRY];

	rd_ctr(dev,"cm_tx_duplicates/req", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_REQ_DUP] = val - cntrs[DCNT_IA_CM_ERR_REQ_DUP];
	rd_ctr(dev,"cm_tx_duplicates/rep", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_REP_DUP] = val - cntrs[DCNT_IA_CM_ERR_REP_DUP];
	rd_ctr(dev,"cm_tx_duplicates/rtu", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_RTU_DUP] = val - cntrs[DCNT_IA_CM_ERR_RTU_DUP];
	rd_ctr(dev,"cm_tx_duplicates/mra", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_MRA_DUP] = val - cntrs[DCNT_IA_CM_ERR_MRA_DUP];
	rd_ctr(dev,"cm_tx_duplicates/dreq", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_DREQ_DUP] = val - cntrs[DCNT_IA_CM_ERR_DREQ_DUP];
	rd_ctr(dev,"cm_tx_duplicates/drep", port, DCNT_IA_CM, &val);
	cntrs[DCNT_IA_CM_ERR_DREP_DUP] = val - cntrs[DCNT_IA_CM_ERR_DREP_DUP];
}
#endif

/* map selective IB port counters to dapl counters */
static void dapl_start_lnk_cntrs(DAT_HANDLE dh)
{
	DAPL_IA *ia = (DAPL_IA *)dh;
	char *dev = ia->hca_ptr->ib_hca_handle->device->ibdev_path;
	int port = ia->hca_ptr->port_num;
	DAT_UINT64 *cntrs = (DAT_UINT64 *)ia->cntrs;

	rd_ctr(dev,"port_rcv_errors", port, DCNT_IA_LNK, &cntrs[DCNT_IA_LNK_ERR_RCV]);
	rd_ctr(dev,"port_rcv_remote_physical_errors", port, DCNT_IA_LNK, &cntrs[DCNT_IA_LNK_ERR_RCV_REM_PHYS]);
	rd_ctr(dev,"port_rcv_contraint_errors", port, DCNT_IA_LNK, &cntrs[DCNT_IA_LNK_ERR_RCV_CONSTRAINT]);
	rd_ctr(dev,"port_xmit_discards", port, DCNT_IA_LNK, &cntrs[DCNT_IA_LNK_ERR_XMT_DISCARDS]);
	rd_ctr(dev,"port_xmit_contraint", port, DCNT_IA_LNK, &cntrs[DCNT_IA_LNK_ERR_XMT_CONTRAINT]);
	rd_ctr(dev,"local_link_integrity_errors", port, DCNT_IA_LNK, &cntrs[DCNT_IA_LNK_ERR_INTEGRITY]);
	rd_ctr(dev,"excessive_buffer_overrun_errors", port, DCNT_IA_LNK, &cntrs[DCNT_IA_LNK_ERR_EXC_BUF_OVERRUN]);
	rd_ctr(dev,"port_xmit_wait", port, DCNT_IA_LNK, &cntrs[DCNT_IA_LNK_WARN_XMT_WAIT]);
	rd_ctr(dev,"port_rcv_switch_relay_errors", port, DCNT_IA_LNK, &cntrs[DCNT_IA_LNK_WARN_RCV_SW_RELAY]);
}

static void dapl_stop_lnk_cntrs(DAT_HANDLE dh)
{
	DAPL_IA *ia = (DAPL_IA *)dh;
	char *dev = ia->hca_ptr->ib_hca_handle->device->ibdev_path;
	int port = ia->hca_ptr->port_num;
	DAT_UINT64 *cntrs = (DAT_UINT64 *)ia->cntrs;
	DAT_UINT64 val = 0;

	rd_ctr(dev,"port_rcv_errors", port, DCNT_IA_LNK, &val);
	cntrs[DCNT_IA_LNK_ERR_RCV] = val - cntrs[DCNT_IA_LNK_ERR_RCV];
	rd_ctr(dev,"port_rcv_remote_physical_errors", port, DCNT_IA_LNK, &val);
	cntrs[DCNT_IA_LNK_ERR_RCV_REM_PHYS] = val - cntrs[DCNT_IA_LNK_ERR_RCV_REM_PHYS];
	rd_ctr(dev,"port_rcv_contraint_errors", port, DCNT_IA_LNK, &val);
	cntrs[DCNT_IA_LNK_ERR_RCV_CONSTRAINT] =	val - cntrs[DCNT_IA_LNK_ERR_RCV_CONSTRAINT];
	rd_ctr(dev,"port_xmit_discards", port, DCNT_IA_LNK, &val);
	cntrs[DCNT_IA_LNK_ERR_XMT_DISCARDS] = val - cntrs[DCNT_IA_LNK_ERR_XMT_DISCARDS];
	rd_ctr(dev,"port_xmit_contraint", port, DCNT_IA_LNK, &val);
	cntrs[DCNT_IA_LNK_ERR_XMT_CONTRAINT] = val - cntrs[DCNT_IA_LNK_ERR_XMT_CONTRAINT];
	rd_ctr(dev,"local_link_integrity_errors", port, DCNT_IA_LNK, &val);
	cntrs[DCNT_IA_LNK_ERR_INTEGRITY]  = val - cntrs[DCNT_IA_LNK_ERR_INTEGRITY] ;
	rd_ctr(dev,"excessive_buffer_overrun_errors", port, DCNT_IA_LNK, &val);
	cntrs[DCNT_IA_LNK_ERR_EXC_BUF_OVERRUN] = val - cntrs[DCNT_IA_LNK_ERR_EXC_BUF_OVERRUN];
	rd_ctr(dev,"port_rcv_switch_relay_errors", port, DCNT_IA_LNK, &val);
	cntrs[DCNT_IA_LNK_WARN_RCV_SW_RELAY] = val - cntrs[DCNT_IA_LNK_WARN_RCV_SW_RELAY];
	rd_ctr(dev,"port_xmit_wait", port, DCNT_IA_LNK, &val);
	cntrs[DCNT_IA_LNK_WARN_XMT_WAIT] = val - cntrs[DCNT_IA_LNK_WARN_XMT_WAIT];
}

/* map selective IB diag_counters to dapl counters */
static void dapl_start_diag_cntrs(DAT_HANDLE dh)
{
	DAPL_IA *ia = (DAPL_IA *)dh;
	char *dev = ia->hca_ptr->ib_hca_handle->device->ibdev_path;
	int port = ia->hca_ptr->port_num;
	DAT_UINT64 *cntrs = (DAT_UINT64 *)ia->cntrs;

	rd_ctr(dev,"rq_num_rae", port, DCNT_IA_DIAG, &cntrs[DCNT_IA_DIAG_ERR_RQ_RAE]);
	rd_ctr(dev,"rq_num_oos", port, DCNT_IA_DIAG, &cntrs[DCNT_IA_DIAG_ERR_RQ_OOS]);
	rd_ctr(dev,"rq_num_rire", port, DCNT_IA_DIAG, &cntrs[DCNT_IA_DIAG_ERR_RQ_RIRE]);
	rd_ctr(dev,"rq_num_udsdprd", port, DCNT_IA_DIAG, &cntrs[DCNT_IA_DIAG_ERR_RQ_UDSDPRD]);
	rd_ctr(dev,"sq_num_rae", port, DCNT_IA_DIAG, &cntrs[DCNT_IA_DIAG_ERR_SQ_RAE]);
	rd_ctr(dev,"sq_num_oos", port, DCNT_IA_DIAG, &cntrs[DCNT_IA_DIAG_ERR_SQ_OOS]);
	rd_ctr(dev,"sq_num_rire", port, DCNT_IA_DIAG, &cntrs[DCNT_IA_DIAG_ERR_SQ_RIRE]);
	rd_ctr(dev,"sq_num_rree", port, DCNT_IA_DIAG, &cntrs[DCNT_IA_DIAG_ERR_SQ_RREE]);
	rd_ctr(dev,"sq_num_tree", port, DCNT_IA_DIAG, &cntrs[DCNT_IA_DIAG_ERR_SQ_TREE]);
}

static void dapl_stop_diag_cntrs(DAT_HANDLE dh)
{
	DAPL_IA *ia = (DAPL_IA *)dh;
	char *dev = ia->hca_ptr->ib_hca_handle->device->ibdev_path;
	int port = ia->hca_ptr->port_num;
	DAT_UINT64 *cntrs = (DAT_UINT64 *)ia->cntrs;
	DAT_UINT64 val = 0;

	rd_ctr(dev,"rq_num_rae", port, DCNT_IA_DIAG, &val);
	cntrs[DCNT_IA_DIAG_ERR_RQ_RAE] = val - cntrs[DCNT_IA_DIAG_ERR_RQ_RAE];
	rd_ctr(dev,"rq_num_oos", port, DCNT_IA_DIAG, &val);
	cntrs[DCNT_IA_DIAG_ERR_RQ_OOS] = val - cntrs[DCNT_IA_DIAG_ERR_RQ_OOS];
	rd_ctr(dev,"rq_num_rire", port, DCNT_IA_DIAG, &val);
	cntrs[DCNT_IA_DIAG_ERR_RQ_RIRE] = val - cntrs[DCNT_IA_DIAG_ERR_RQ_RIRE];
	rd_ctr(dev,"rq_num_udsdprd", port, DCNT_IA_DIAG, &val);
	cntrs[DCNT_IA_DIAG_ERR_RQ_UDSDPRD] = val - cntrs[DCNT_IA_DIAG_ERR_RQ_UDSDPRD];
	rd_ctr(dev,"sq_num_rae", port, DCNT_IA_DIAG, &val);
	cntrs[DCNT_IA_DIAG_ERR_SQ_RAE] = val - cntrs[DCNT_IA_DIAG_ERR_SQ_RAE];
	rd_ctr(dev,"sq_num_oos", port, DCNT_IA_DIAG, &val);
	cntrs[DCNT_IA_DIAG_ERR_SQ_OOS] = val - cntrs[DCNT_IA_DIAG_ERR_SQ_OOS];
	rd_ctr(dev,"sq_num_rire", port, DCNT_IA_DIAG, &val);
	cntrs[DCNT_IA_DIAG_ERR_SQ_RIRE] = val - cntrs[DCNT_IA_DIAG_ERR_SQ_RIRE];
	rd_ctr(dev,"sq_num_rree", port, DCNT_IA_DIAG, &val);
	cntrs[DCNT_IA_DIAG_ERR_SQ_RREE] = val - cntrs[DCNT_IA_DIAG_ERR_SQ_RREE];
	rd_ctr(dev,"sq_num_tree", port, DCNT_IA_DIAG, &val);
	cntrs[DCNT_IA_DIAG_ERR_SQ_TREE] = val - cntrs[DCNT_IA_DIAG_ERR_SQ_TREE];
}

void dapl_start_counters(DAT_HANDLE dh, DAT_IA_COUNTER_TYPE type)
{
	switch (type) {
	case DCNT_IA_CM:
#ifdef _OPENIB_CMA_
		dapl_start_cm_cntrs(dh); /* ib cm timers, cma only */
#endif
		break;
	case DCNT_IA_LNK:
		dapl_start_lnk_cntrs(dh);
		break;
	case DCNT_IA_DIAG:
		dapl_start_diag_cntrs(dh);
		break;
	default:
		break;
	}
}

void dapl_stop_counters(DAT_HANDLE dh, DAT_IA_COUNTER_TYPE type)
{
	switch (type) {
	case DCNT_IA_CM:
#ifdef _OPENIB_CMA_
		dapl_stop_cm_cntrs(dh);
#endif
		break;
	case DCNT_IA_LNK:
		dapl_stop_lnk_cntrs(dh);
		break;
	case DCNT_IA_DIAG:
		dapl_stop_diag_cntrs(dh);
		break;
	default:
		break;

	}
}

void dapli_start_counters(DAT_HANDLE dh)
{
#ifdef _OPENIB_CMA_
	if (g_dapl_dbg_type & (DAPL_DBG_TYPE_CM_ERRS | DAPL_DBG_TYPE_CM_STATS))
		dapl_start_cm_cntrs(dh);
#endif
	if (g_dapl_dbg_type & DAPL_DBG_TYPE_LINK_ERRS)
		dapl_start_lnk_cntrs(dh);
	if (g_dapl_dbg_type & DAPL_DBG_TYPE_DIAG_ERRS)
		dapl_start_diag_cntrs(dh);
}

void dapli_stop_counters(DAT_HANDLE dh)
{
#ifdef _OPENIB_CMA_
	if (g_dapl_dbg_type & (DAPL_DBG_TYPE_CM_ERRS | DAPL_DBG_TYPE_CM_STATS))
		dapl_stop_cm_cntrs(dh);
#endif
	if (g_dapl_dbg_type & DAPL_DBG_TYPE_LINK_ERRS)
		dapl_stop_lnk_cntrs(dh);
	if (g_dapl_dbg_type & DAPL_DBG_TYPE_DIAG_ERRS)
		dapl_stop_diag_cntrs(dh);

	if (g_dapl_dbg_type & DAPL_DBG_TYPE_IA_STATS)
		dapl_print_counter_str(dh, DCNT_IA_ALL_COUNTERS, 1, "_IA");
	if (g_dapl_dbg_type & DAPL_DBG_TYPE_CM_STATS)
		dapl_print_counter_str(dh, DCNT_IA_ALL_COUNTERS, 1, "_CM");
	else if (g_dapl_dbg_type & DAPL_DBG_TYPE_CM_ERRS)
		dapl_print_counter_str(dh, DCNT_IA_ALL_COUNTERS, 1, "_CM_ERR");
	if (g_dapl_dbg_type & DAPL_DBG_TYPE_LINK_ERRS)
		dapl_print_counter_str(dh, DCNT_IA_ALL_COUNTERS, 1, "_LNK_ERR");
	if (g_dapl_dbg_type & DAPL_DBG_TYPE_LINK_WARN)
		dapl_print_counter_str(dh, DCNT_IA_ALL_COUNTERS, 1, "_LNK_WARN");
	if (g_dapl_dbg_type & DAPL_DBG_TYPE_DIAG_ERRS)
		dapl_print_counter_str(dh, DCNT_IA_ALL_COUNTERS, 1, "_DIAG_ERR");
}

/*
 * The order of this list must match the DAT counter definitions 
 */
static char *ia_cntr_names[] = {
	"DCNT_IA_PZ_CREATE",
	"DCNT_IA_PZ_FREE",
	"DCNT_IA_LMR_CREATE",
	"DCNT_IA_LMR_FREE",
	"DCNT_IA_RMR_CREATE",
	"DCNT_IA_RMR_FREE",
	"DCNT_IA_PSP_CREATE",
	"DCNT_IA_PSP_CREATE_ANY",
	"DCNT_IA_PSP_FREE",
	"DCNT_IA_RSP_CREATE",
	"DCNT_IA_RSP_FREE",
	"DCNT_IA_EVD_CREATE",
	"DCNT_IA_EVD_FREE",
	"DCNT_IA_EP_CREATE",
	"DCNT_IA_EP_FREE",
	"DCNT_IA_SRQ_CREATE",
	"DCNT_IA_SRQ_FREE",
	"DCNT_IA_SP_CR",
	"DCNT_IA_SP_CR_ACCEPTED",
	"DCNT_IA_SP_CR_REJECTED",
	"DCNT_IA_MEM_ALLOC",
	"DCNT_IA_MEM_ALLOC_DATA",
	"DCNT_IA_MEM_FREE",
	"DCNT_IA_ASYNC_ERROR",
	"DCNT_IA_ASYNC_QP_ERROR",
	"DCNT_IA_ASYNC_CQ_ERROR",
	"DCNT_IA_CM_LISTEN",
	"DCNT_IA_CM_REQ_TX",
	"DCNT_IA_CM_REQ_RX",
	"DCNT_IA_CM_REP_TX",
	"DCNT_IA_CM_REP_RX",
	"DCNT_IA_CM_RTU_TX",
	"DCNT_IA_CM_RTU_RX",
	"DCNT_IA_CM_USER_REJ_TX",
	"DCNT_IA_CM_USER_REJ_RX",
	"DCNT_IA_CM_ACTIVE_EST",
	"DCNT_IA_CM_PASSIVE_EST",
	"DCNT_IA_CM_AH_REQ_TX",
	"DCNT_IA_CM_AH_REQ_RX",
	"DCNT_IA_CM_AH_RESOLVED",
	"DCNT_IA_CM_DREQ_TX",
	"DCNT_IA_CM_DREQ_RX",
	"DCNT_IA_CM_DREP_TX",
	"DCNT_IA_CM_DREP_RX",
	"DCNT_IA_CM_MRA_TX",
	"DCNT_IA_CM_MRA_RX",
	"DCNT_IA_CM_REQ_FULLQ_POLL",
	"DCNT_IA_CM_ERR",
	"DCNT_IA_CM_ERR_REQ_FULLQ",
	"DCNT_IA_CM_ERR_REQ_DUP",
	"DCNT_IA_CM_ERR_REQ_RETRY",
	"DCNT_IA_CM_ERR_REP_DUP",
	"DCNT_IA_CM_ERR_REP_RETRY",
	"DCNT_IA_CM_ERR_RTU_DUP",
	"DCNT_IA_CM_ERR_RTU_RETRY",
	"DCNT_IA_CM_ERR_REFUSED",
	"DCNT_IA_CM_ERR_RESET",
	"DCNT_IA_CM_ERR_TIMEOUT",
	"DCNT_IA_CM_ERR_REJ_TX",
	"DCNT_IA_CM_ERR_REJ_RX",
	"DCNT_IA_CM_ERR_DREQ_DUP",
	"DCNT_IA_CM_ERR_DREQ_RETRY",
	"DCNT_IA_CM_ERR_DREP_DUP",
	"DCNT_IA_CM_ERR_DREP_RETRY",
	"DCNT_IA_CM_ERR_MRA_DUP",
	"DCNT_IA_CM_ERR_MRA_RETRY",
	"DCNT_IA_CM_ERR_UNEXPECTED",
	"DCNT_IA_LNK_ERR_RCV",
	"DCNT_IA_LNK_ERR_RCV_REM_PHYS",
	"DCNT_IA_LNK_ERR_RCV_CONSTRAINT",
	"DCNT_IA_LNK_ERR_XMT_DISCARDS",
	"DCNT_IA_LNK_ERR_XMT_CONTRAINT",
	"DCNT_IA_LNK_ERR_INTEGRITY",
	"DCNT_IA_LNK_ERR_EXC_BUF_OVERRUN",
	"DCNT_IA_LNK_WARN_RCV_SW_RELAY",
	"DCNT_IA_LNK_WARN_XMT_WAIT",
	"DCNT_IA_DIAG_ERR_RQ_RAE",
	"DCNT_IA_DIAG_ERR_RQ_OOS",
	"DCNT_IA_DIAG_ERR_RQ_RIRE",
	"DCNT_IA_DIAG_ERR_RQ_UDSDPRD",
	"DCNT_IA_DIAG_ERR_SQ_RAE",
	"DCNT_IA_DIAG_ERR_SQ_OOS",
	"DCNT_IA_DIAG_ERR_SQ_RIRE",
	"DCNT_IA_DIAG_ERR_SQ_RREE",
	"DCNT_IA_DIAG_ERR_SQ_TREE",
};


static char *ep_cntr_names[] = {
	"DCNT_EP_CONNECT",
	"DCNT_EP_DISCONNECT",
	"DCNT_EP_POST_SEND",
	"DCNT_EP_POST_SEND_DATA",
	"DCNT_EP_POST_SEND_UD",
	"DCNT_EP_POST_SEND_UD_DATA",
	"DCNT_EP_POST_RECV",
	"DCNT_EP_POST_RECV_DATA",
	"DCNT_EP_POST_WRITE",
	"DCNT_EP_POST_WRITE_DATA",
	"DCNT_EP_POST_WRITE_IMM",
	"DCNT_EP_POST_WRITE_IMM_DATA",
	"DCNT_EP_POST_READ",
	"DCNT_EP_POST_READ_DATA",
	"DCNT_EP_POST_CMP_SWAP",
	"DCNT_EP_POST_FETCH_ADD",
	"DCNT_EP_RECV",
	"DCNT_EP_RECV_DATA",
	"DCNT_EP_RECV_UD",
	"DCNT_EP_RECV_UD_DATA",
	"DCNT_EP_RECV_IMM",
	"DCNT_EP_RECV_IMM_DATA",
	"DCNT_EP_RECV_RDMA_IMM",
	"DCNT_EP_RECV_RDMA_IMM_DATA",
};

static char *evd_cntr_names[] = {
	"DCNT_EVD_WAIT",
	"DCNT_EVD_WAIT_BLOCKED",
	"DCNT_EVD_WAIT_NOTIFY",
	"DCNT_EVD_DEQUEUE",
	"DCNT_EVD_DEQUEUE_FOUND",
	"DCNT_EVD_DEQUEUE_NOT_FOUND",
	"DCNT_EVD_DEQUEUE_POLL",
	"DCNT_EVD_DEQUEUE_POLL_FOUND",
	"DCNT_EVD_CONN_CALLBACK",
	"DCNT_EVD_DTO_CALLBACK",
};

DAT_RETURN dapl_query_counter(DAT_HANDLE dh,
			      int counter, void *p_cntrs_out, int reset)
{
	int i, max;
	DAT_UINT64 *p_cntrs;
	DAT_HANDLE_TYPE type = 0;

	dat_get_handle_type(dh, &type);

	switch (type) {
	case DAT_HANDLE_TYPE_IA:
		max = DCNT_IA_ALL_COUNTERS;
		p_cntrs = ((DAPL_IA *) dh)->cntrs;
		break;
	case DAT_HANDLE_TYPE_EP:
		max = DCNT_EP_ALL_COUNTERS;
		p_cntrs = ((DAPL_EP *) dh)->cntrs;
		break;
	case DAT_HANDLE_TYPE_EVD:
		max = DCNT_EVD_ALL_COUNTERS;
		p_cntrs = ((DAPL_EVD *) dh)->cntrs;
		break;
	default:
		return DAT_INVALID_HANDLE;
	}

	for (i = 0; i < max; i++) {
		if ((counter == i) || (counter == max)) {
			((DAT_UINT64 *) p_cntrs_out)[i] = p_cntrs[i];
			if (reset)
				p_cntrs[i] = 0;
		}
	}
	return DAT_SUCCESS;
}

char *dapl_query_counter_name(DAT_HANDLE dh, int counter)
{
	DAT_HANDLE_TYPE type = 0;

	dat_get_handle_type(dh, &type);

	switch (type) {
	case DAT_HANDLE_TYPE_IA:
		if (counter < DCNT_IA_ALL_COUNTERS)
			return ia_cntr_names[counter];
		break;
	case DAT_HANDLE_TYPE_EP:
		if (counter < DCNT_EP_ALL_COUNTERS)
			return ep_cntr_names[counter];
		break;
	case DAT_HANDLE_TYPE_EVD:
		if (counter < DCNT_EVD_ALL_COUNTERS)
			return evd_cntr_names[counter];
		break;
	default:
		return NULL;
	}
	return NULL;
}

void dapl_print_counter(DAT_HANDLE dh, int counter, int reset)
{
	int i, max;
	DAT_UINT64 *p_cntrs;
	DAT_HANDLE_TYPE type = 0;

	dat_get_handle_type(dh, &type);

	switch (type) {
	case DAT_HANDLE_TYPE_IA:
		max = DCNT_IA_ALL_COUNTERS;
		p_cntrs = ((DAPL_IA *) dh)->cntrs;
		break;
	case DAT_HANDLE_TYPE_EP:
		max = DCNT_EP_ALL_COUNTERS;
		p_cntrs = ((DAPL_EP *) dh)->cntrs;
		break;
	case DAT_HANDLE_TYPE_EVD:
		max = DCNT_EVD_ALL_COUNTERS;
		p_cntrs = ((DAPL_EVD *) dh)->cntrs;
		break;
	default:
		return;
	}

	for (i = 0; i < max; i++) {
		if ((counter == i) || (counter == max)) {
			printf(" %s:0x%x: %s = " F64u " \n",
				_hostname_, dapl_os_getpid(),
			       	dapl_query_counter_name(dh, i), p_cntrs[i]);
			if (reset)
				p_cntrs[i] = 0;
		}
	}

	/* Print in process CR's for this IA, if debug type set */
	if ((type == DAT_HANDLE_TYPE_IA) && 
	    (g_dapl_dbg_type & DAPL_DBG_TYPE_CM_LIST)) {
		dapls_print_cm_list((DAPL_IA*)dh);
	}
}

void dapl_print_counter_str(DAT_HANDLE dh, int counter, int reset, const char *pattern)
{
	int i, max;
	DAT_UINT64 *p_cntrs;
	DAT_HANDLE_TYPE type = 0;

	dat_get_handle_type(dh, &type);

	switch (type) {
	case DAT_HANDLE_TYPE_IA:
		max = DCNT_IA_ALL_COUNTERS;
		p_cntrs = ((DAPL_IA *) dh)->cntrs;
		break;
	case DAT_HANDLE_TYPE_EP:
		max = DCNT_EP_ALL_COUNTERS;
		p_cntrs = ((DAPL_EP *) dh)->cntrs;
		break;
	case DAT_HANDLE_TYPE_EVD:
		max = DCNT_EVD_ALL_COUNTERS;
		p_cntrs = ((DAPL_EVD *) dh)->cntrs;
		break;
	default:
		return;
	}

	/* print only counters with pattern string match and non-zero values */
	for (i = 0; i < max; i++) {
		if ((counter == i) || (counter == max)) {
			if (p_cntrs[i] && !dapl_os_pstrcmp(pattern, dapl_query_counter_name(dh, i))) {
				printf(" %s:0x%x: %s = " F64u " \n",
					_hostname_, dapl_os_getpid(),
			        	dapl_query_counter_name(dh, i), p_cntrs[i]);
				if (reset)
					p_cntrs[i] = 0;
			}
		}
	}
}

#endif				/* DAPL_COUNTERS */
