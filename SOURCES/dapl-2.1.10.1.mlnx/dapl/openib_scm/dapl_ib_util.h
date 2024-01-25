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

#ifndef _DAPL_IB_UTIL_H_
#define _DAPL_IB_UTIL_H_
#define _OPENIB_SCM_ 

#include <infiniband/verbs.h>
#include "openib_osd.h"
#include "dapl_ib_common.h"

/* DAPL CM objects MUST include list_entry, ref_count, event for EP linking */
struct ib_cm_handle
{ 
	struct dapl_llist_entry	list_entry;
	struct dapl_llist_entry	local_entry;
        DAPL_OS_WAIT_OBJECT	event;
	DAPL_OS_LOCK		lock;
	int			ref_count;
	int			state;
	int 			retry;
	DAPL_SOCKET		socket;
	struct dapl_hca		*hca;
	struct dapl_sp		*sp;	
	struct dapl_ep 		*ep;
	ib_cm_msg_t		msg;
	struct ibv_ah		*ah;
	DAT_SOCK_ADDR6          addr; 
};

typedef struct ib_cm_handle 	*dp_ib_cm_handle_t;
typedef dp_ib_cm_handle_t	ib_cm_srvc_handle_t;

/* Definitions */
#define IB_INVALID_HANDLE	NULL

/* inline send rdma threshold */
#define	INLINE_SEND_DEFAULT	200

/* RC timer - retry count defaults */
#define SCM_ACK_TIMER	20 /* 5 bits, 4.096us*2^ack_timer. 16== 268ms, 20==4.2s */
#define SCM_ACK_RETRY	7  /* 3 bits, 7 * 4.2  == 30 seconds */
#define SCM_RNR_TIMER 12 /* 5 bits, 12 =.64ms, 28 =163ms, 31 =491ms */
#define SCM_RNR_RETRY 7  /* 3 bits, 7 == infinite */
#define SCM_CR_RETRY  5  /* retries for busy server, connect refused */

/* Global routing defaults */
#define SCM_GLOBAL	0	/* global routing is disabled */
#define SCM_HOP_LIMIT	0xff
#define SCM_TCLASS	0

/* ib_hca_transport_t, specific to this implementation */
typedef struct _ib_hca_transport
{ 
	struct dapl_llist_entry	entry;
	int			destroy;
	union ibv_gid		gid;
	struct	ibv_device	*ib_dev;
	struct	ibv_context	*ib_ctx;
	ib_cq_handle_t		ib_cq_empty;
	DAPL_OS_LOCK		cq_lock;	
	int			max_inline_send;
	ib_thread_state_t       cq_state;
	DAPL_OS_THREAD		cq_thread;
	struct ibv_comp_channel *ib_cq;
	int			cr_state;
	DAPL_OS_THREAD		thread;
	DAPL_OS_LOCK		lock;	
	struct dapl_llist_entry	*list;	
	ib_async_handler_t	async_unafiliated;
	void			*async_un_ctx;
	ib_async_cq_handler_t	async_cq_error;
	ib_async_dto_handler_t	async_cq;
	ib_async_qp_handler_t	async_qp_error;
	uint16_t		lid;
	ib_cm_attr_t		ib_cm;  /* dev attr for QP and CM */
	DAPL_SOCKET		scm[2];
	uint64_t		guid;
	char 			guid_str[32];
	char 			gid_str[48];
	ib_named_attr_t		na;
#ifdef DAT_IB_COLLECTIVES
	/* Collective member device and address information */
	ib_thread_state_t 	coll_thread_state;
	DAPL_OS_THREAD 		coll_thread;
	DAPL_OS_LOCK 		coll_lock;
	DAPL_OS_WAIT_OBJECT 	coll_event;
	struct dapl_llist_entry *grp_list;
	user_progress_func_t 	*user_func;
	int 			l_sock;
	struct sockaddr_in	m_addr;
	void 			*m_ctx;
	void			*m_info;
	void			*f_info;
	int			m_size;
	int			f_size;
	int			t_id;
#endif
} ib_hca_transport_t;

/* prototypes */
void cr_thread(void *arg);
int dapli_cq_thread_init(struct dapl_hca *hca_ptr);
void dapli_cq_thread_destroy(struct dapl_hca *hca_ptr);
void dapli_async_event_cb(struct _ib_hca_transport *tp);
void dapli_cq_event_cb(struct _ib_hca_transport *tp);
void dapls_cm_acquire(dp_ib_cm_handle_t cm_ptr);
void dapls_cm_release(dp_ib_cm_handle_t cm_ptr);
void dapls_cm_free(dp_ib_cm_handle_t cm_ptr);
DAT_RETURN dapls_ud_cm_free(DAPL_EP *ep_ptr, dp_ib_cm_handle_t cm_ptr);

#ifdef DAPL_COUNTERS
void dapls_print_cm_list(IN DAPL_IA *ia_ptr);
#endif

#endif /*  _DAPL_IB_UTIL_H_ */
