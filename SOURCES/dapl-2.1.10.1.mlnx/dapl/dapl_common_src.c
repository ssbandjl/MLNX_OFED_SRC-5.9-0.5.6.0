/*
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

#include "common\dapl_cno_util.c"
#include "common\dapl_cookie.c"
#include "common\dapl_cr_accept.c"
#include "common\dapl_cr_callback.c"
#include "common\dapl_cr_handoff.c"
#include "common\dapl_cr_query.c"
#include "common\dapl_cr_reject.c"
#include "common\dapl_cr_util.c"
#include "common\dapl_csp.c"
#include "common\dapl_debug.c"
#include "common\dapl_ep_connect.c"
#include "common\dapl_ep_create.c"
#include "common\dapl_ep_disconnect.c"
#include "common\dapl_ep_dup_connect.c"
#include "common\dapl_ep_free.c"
#include "common\dapl_ep_get_status.c"
#include "common\dapl_ep_modify.c"
#include "common\dapl_ep_post_rdma_read.c"
#include "common\dapl_ep_post_rdma_read_to_rmr.c"
#include "common\dapl_ep_post_rdma_write.c"
#include "common\dapl_ep_post_recv.c"
#include "common\dapl_ep_post_send.c"
#include "common\dapl_ep_post_send_invalidate.c"
#include "common\dapl_ep_query.c"
#include "common\dapl_ep_recv_query.c"
#include "common\dapl_ep_reset.c"
#include "common\dapl_ep_set_watermark.c"
#include "common\dapl_ep_util.c"
#include "common\dapl_evd_connection_callb.c"
#include "common\dapl_evd_cq_async_error_callb.c"
#include "common\dapl_evd_dequeue.c"
#include "common\dapl_evd_dto_callb.c"
#include "common\dapl_evd_free.c"
#include "common\dapl_evd_post_se.c"
#include "common\dapl_evd_qp_async_error_callb.c"
#include "common\dapl_evd_resize.c"
#include "common\dapl_evd_un_async_error_callb.c"
#include "common\dapl_evd_util.c"
#include "common\dapl_get_consumer_context.c"
#include "common\dapl_get_handle_type.c"
#include "common\dapl_hash.c"
#include "common\dapl_hca_util.c"
#include "common\dapl_ia_close.c"
#include "common\dapl_ia_ha.c"
#include "common\dapl_ia_open.c"
#include "common\dapl_ia_query.c"
#include "common\dapl_ia_util.c"
#include "common\dapl_llist.c"
#include "common\dapl_lmr_free.c"
#include "common\dapl_lmr_query.c"
#include "common\dapl_lmr_sync_rdma_read.c"
#include "common\dapl_lmr_sync_rdma_write.c"
#include "common\dapl_lmr_util.c"
#include "common\dapl_mr_util.c"
#include "common\dapl_name_service.c"
#include "common\dapl_provider.c"
#include "common\dapl_psp_create.c"
#include "common\dapl_psp_create_any.c"
#include "common\dapl_psp_free.c"
#include "common\dapl_psp_query.c"
#include "common\dapl_pz_create.c"
#include "common\dapl_pz_free.c"
#include "common\dapl_pz_query.c"
#include "common\dapl_pz_util.c"
#include "common\dapl_ring_buffer_util.c"
#include "common\dapl_rmr_bind.c"
#include "common\dapl_rmr_create.c"
#include "common\dapl_rmr_free.c"
#include "common\dapl_rmr_query.c"
#include "common\dapl_rmr_util.c"
#include "common\dapl_rsp_create.c"
#include "common\dapl_rsp_free.c"
#include "common\dapl_rsp_query.c"
#include "common\dapl_set_consumer_context.c"
#include "common\dapl_sp_util.c"
#include "common\dapl_ep_create_with_srq.c"
#include "common\dapl_srq_create.c"
#include "common\dapl_srq_free.c"
#include "common\dapl_srq_post_recv.c"
#include "common\dapl_srq_query.c"
#include "common\dapl_srq_resize.c"
#include "common\dapl_srq_set_lw.c"
#include "common\dapl_srq_util.c"
#include "common\dapl_timer_util.c"
