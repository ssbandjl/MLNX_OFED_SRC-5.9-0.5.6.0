/*
 * Copyright (c) 2005-2009 Intel Corporation.  All rights reserved.
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
/* 
 * Definitions specific to OpenIB CMA provider.
 *   Connection manager - rdma_cma, provided in separate library.
 */
#ifndef _DAPL_IB_UTIL_H_
#define _DAPL_IB_UTIL_H_
#define _OPENIB_CMA_ 

#include <infiniband/verbs.h>
#include "openib_osd.h"
#include "dapl_ib_common.h"

#define IB_RC_RETRY_COUNT      7
#define IB_RNR_RETRY_COUNT     7
#define IB_CM_RESPONSE_TIMEOUT  23	/* 16 sec */
#define IB_CM_RETRIES           15	/* 240 sec total default */
#define IB_ARP_TIMEOUT		4000	/* 4 sec */
#define IB_ARP_RETRY_COUNT	15	/* 60 sec total */
#define IB_ROUTE_TIMEOUT	4000	/* 4 sec */
#define IB_ROUTE_RETRY_COUNT	15	/* 60 sec total */
#define IB_MAX_AT_RETRY		3

/* CMA private data areas, use CMA max with known transport definitions */
#ifndef RDMA_MAX_PRIVATE_DATA
#if defined(_WIN64) || defined(_WIN32)
#define RDMA_MAX_PRIVATE_DATA 64 
#else
#define RDMA_MAX_PRIVATE_DATA 256
#endif
#endif

#define CMA_PDATA_HDR		36
#define	IB_MAX_REQ_PDATA_SIZE	DAPL_MIN((92-CMA_PDATA_HDR),RDMA_MAX_PRIVATE_DATA)
#define	IB_MAX_REP_PDATA_SIZE	DAPL_MIN((196-CMA_PDATA_HDR),RDMA_MAX_PRIVATE_DATA)
#define	IB_MAX_REJ_PDATA_SIZE	DAPL_MIN((148-CMA_PDATA_HDR),RDMA_MAX_PRIVATE_DATA)
#define	IB_MAX_DREQ_PDATA_SIZE	DAPL_MIN((220-CMA_PDATA_HDR),RDMA_MAX_PRIVATE_DATA)
#define	IB_MAX_DREP_PDATA_SIZE	DAPL_MIN((224-CMA_PDATA_HDR),RDMA_MAX_PRIVATE_DATA)
#define	IWARP_MAX_PDATA_SIZE	DAPL_MIN((512-CMA_PDATA_HDR),RDMA_MAX_PRIVATE_DATA)

/* DAPL CM objects MUST include list_entry, ref_count, event for EP linking */
struct dapl_cm_id {
	struct dapl_llist_entry		list_entry;
	struct dapl_llist_entry		local_entry;
	DAPL_OS_WAIT_OBJECT		event;
	DAPL_OS_LOCK			lock;
	int				ref_count;
	int				arp_retries;
	int				arp_timeout;
	int				route_retries;
	int				route_timeout;
	struct rdma_cm_id		*cm_id;
	struct dapl_hca			*hca;
	struct dapl_sp			*sp;
	struct dapl_ep			*ep;
	struct rdma_conn_param		params;
	DAT_SOCK_ADDR6			r_addr;
	int				p_len;
	unsigned char			p_data[256]; /* dapl max private data size */
	ib_cm_msg_t			dst;
	struct ibv_ah			*ah;
};

typedef struct dapl_cm_id	*dp_ib_cm_handle_t;
typedef struct dapl_cm_id	*ib_cm_srvc_handle_t;

/* ib_hca_transport_t, specific to this implementation */
typedef struct _ib_hca_transport
{ 
	struct dapl_llist_entry	entry;
	int			destroy;
	struct rdma_cm_id 	*cm_id;
	struct ibv_comp_channel *ib_cq;
	ib_cq_handle_t		ib_cq_empty;
	ib_async_handler_t	async_unafiliated;
	void			*async_un_ctx;
	ib_async_cq_handler_t	async_cq_error;
	ib_async_dto_handler_t	async_cq;
	ib_async_qp_handler_t	async_qp_error;
	uint8_t			max_cm_timeout;
	uint8_t			max_cm_retries;
	struct	ibv_context	*ib_ctx;
	struct	ibv_device	*ib_dev;
	/* dapls_modify_qp_state */
	ib_cm_attr_t		ib_cm;  /* dev attr for QP and CM */
	uint64_t		guid;
	char			guid_str[32];
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
void dapli_thread(void *arg);
DAT_RETURN  dapli_ib_thread_init(void);
void dapli_ib_thread_destroy(void);
void dapli_cma_event_cb(void);
void dapli_async_event_cb(struct _ib_hca_transport *tp);
void dapli_cq_event_cb(struct _ib_hca_transport *tp);
dp_ib_cm_handle_t dapls_ib_cm_create(DAPL_EP *ep);
void dapls_cm_acquire(dp_ib_cm_handle_t cm);
void dapls_cm_release(dp_ib_cm_handle_t cm);
void dapls_cm_free(dp_ib_cm_handle_t cm_ptr);
DAT_RETURN dapls_ud_cm_free(DAPL_EP *ep_ptr, dp_ib_cm_handle_t cm_ptr);

#ifdef DAPL_COUNTERS
STATIC _INLINE_ void dapls_print_cm_list(IN DAPL_IA * ia_ptr)
{
	return;
}
#endif

#endif /*  _DAPL_IB_UTIL_H_ */
