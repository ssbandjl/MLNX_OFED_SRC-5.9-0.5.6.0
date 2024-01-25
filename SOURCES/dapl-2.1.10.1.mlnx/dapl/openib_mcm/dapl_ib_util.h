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

#ifndef _DAPL_IB_UTIL_H_
#define _DAPL_IB_UTIL_H_
#define _OPENIB_MCM_

#include <infiniband/verbs.h>
#include <scif.h>
#include "openib_osd.h"
#include "dapl_mic_common.h"
#include "dapl_ib_common.h"

#define MCM_RETRY_CNT   10
#define MCM_REP_TIME    4000	/* reply timeout in m_secs */
#define MCM_RTU_TIME    2000	/* rtu timeout in m_secs */

/* DAPL CM objects MUST include list_entry, ref_count, event for EP linking */
struct ib_cm_handle
{ 
	struct dapl_llist_entry		list_entry;
	struct dapl_llist_entry		local_entry;
	DAPL_OS_WAIT_OBJECT		d_event;
	DAPL_OS_WAIT_OBJECT		f_event;
	DAPL_OS_LOCK			lock;
	DAPL_OS_TIMEVAL			timer;
	uint32_t			cm_id;	/* local id */
	uint32_t			scm_id; /* shadow id */
	uint64_t			cm_ctx;	/* local context */
	uint64_t			scm_ctx;	/* shadow context */
	int				ref_count;
	int				state;
	int				retries;
	struct _ib_hca_transport 	*tp;
	struct dapl_hca			*hca;
	struct dapl_sp			*sp;
	struct dapl_ep 			*ep;
	struct ibv_ah			*ah;
	uint16_t			p_size; /* accept p_data, for retries */
	uint8_t				p_data[DAT_MCM_PDATA_SIZE];
	dat_mcm_msg_t			msg;
};

typedef struct ib_cm_handle	*dp_ib_cm_handle_t;
typedef dp_ib_cm_handle_t	ib_cm_srvc_handle_t;

/* Definitions */
#define IB_INVALID_HANDLE	NULL

/* ib_hca_transport_t, specific to this implementation */
typedef struct _ib_hca_transport
{ 
	struct	ibv_device	*ib_dev;
	struct	dapl_hca	*hca;
        struct  ibv_context     *ib_ctx;
        struct ibv_comp_channel *ib_cq;
        ib_cq_handle_t          ib_cq_empty;
	int			destroy;
	int			cm_state;
	DAPL_OS_THREAD		thread;
	DAPL_OS_LOCK		lock;	/* connect list */
	struct dapl_llist_entry	*list;	
	DAPL_OS_LOCK		llock;	/* listen list */
	struct dapl_llist_entry	*llist;	
	DAPL_OS_LOCK		cqlock;	/* CQ list for PI WC's */
	struct dapl_llist_entry	*cqlist;
	ib_async_handler_t	async_unafiliated;
	void			*async_un_ctx;
	ib_async_cq_handler_t	async_cq_error;
	ib_async_dto_handler_t	async_cq;
	ib_async_qp_handler_t	async_qp_error;
	struct dat_mcm_addr	addr;	/* lid, port, qp_num, gid */
	struct dapl_thread_signal signal;
	ib_cm_attr_t		ib_cm;  /* dev attr for QP and CM */
	int			cqe;
	int			qpe;
	int			burst;
	int			retries;
	int			cm_timer;
	int			rep_time;
	int			rtu_time;
	DAPL_OS_LOCK		slock;	
	int			s_hd;
	int			s_tl;
	struct ibv_pd		*pd; 
	struct ibv_cq		*scq;
	struct ibv_cq		*rcq;
	struct ibv_qp		*qp;
	struct ibv_mr		*mr_rbuf;
	struct ibv_mr		*mr_sbuf;
	dat_mcm_msg_t		*sbuf;
	dat_mcm_msg_t		*rbuf;
	struct ibv_comp_channel *rch;
	int			rch_fd;
	struct ibv_ah		**ah;  
	DAPL_OS_LOCK		plock;
	uint16_t		lid;
	uint8_t			*sid;  /* Sevice IDs, port space, bitarray? */

	/* SCIF MIC indirect, EP to MPXYD services, if running on MIC */
	uint32_t		dev_id;		/* proxy device id */
	struct scif_portID	self;
	scif_epd_t 		scif_ep;	/* FD operation and CM processing */
	scif_epd_t 		scif_ev_ep;	/* unsolicited events processing */
	scif_epd_t 		scif_tx_ep;	/* FD data path processing */
	struct scif_portID 	peer;		/* MPXYD op EP proxy addr info */
	struct scif_portID	peer_ev;	/* MPXYD event EP proxy addr info */
	struct scif_portID	peer_tx;	/* MPXYD data EP proxy addr info */
	uint64_t		sys_guid;	/* system image guid, network order */
	uint64_t		guid;		/* host order */
	char 			guid_str[32];
	char 			gid_str[48];
	char 			fam_str[8];
	char 			mod_str[8];
	char 			ver_str[8];
	ib_named_attr_t		na;
	dat_mix_prov_attr_t	pr_attr;	/* attributes from proxy */

	/* Direct memory mapping for post_send WR entries, MIC to HOST */
	dat_mix_mmap_wr_t	*mm_s_addr;		/* sbuf for post_send WR to host with MMAP */
	int 			mm_s_head;		/* next location in PEER array to write WR */
	dat_mix_mmap_wr_t	*mm_s_peer_addr;	/* writes goto remote MMAP address on host */
	off_t			mm_s_peer_addr_off;	/* PEER scif registered memory for sbuf WR array */
	int			*mm_s_place_holder;	/* local not used local memory for mmap */
	volatile int 		*mm_r_addr;		/* host mmap this rbuf mem and updates tail */
	off_t			mm_r_addr_off;		/* SCIF registration for rbuf, host writes */

} ib_hca_transport_t;

/* prototypes */
void cm_thread(void *arg);
void dapli_queue_conn(dp_ib_cm_handle_t cm);
void dapli_dequeue_conn(dp_ib_cm_handle_t cm);
void mcm_connect_rtu(dp_ib_cm_handle_t cm, dat_mcm_msg_t *msg);
void mcm_disconnect_final(dp_ib_cm_handle_t cm);
void dapli_async_event_cb(struct _ib_hca_transport *tp);
void dapli_cq_event_cb(struct _ib_hca_transport *tp);
void dapls_cm_acquire(dp_ib_cm_handle_t cm_ptr);
void dapls_cm_release(dp_ib_cm_handle_t cm_ptr);
void dapls_cm_free(dp_ib_cm_handle_t cm_ptr);
DAT_RETURN dapls_ud_cm_free(DAPL_EP *ep_ptr, dp_ib_cm_handle_t cm_ptr);
dp_ib_cm_handle_t dapls_cm_create(DAPL_HCA *hca, DAPL_EP *ep);
DAT_RETURN dapls_modify_qp_rtu(struct ibv_qp *qp, uint32_t qpn, uint16_t lid, ib_gid_handle_t gid);

/* HST->MXS (MIC xsocket) remote PI communication, proxy.c */
int  mcm_send_pi(ib_qp_handle_t m_qp, int len, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr);
int  mcm_post_rcv_wc(struct dcm_ib_qp *m_qp, int cnt);
void mcm_dto_event(struct dcm_ib_cq *m_cq);
int  mcm_create_wc_q(struct dcm_ib_qp *m_qp, int entries);
void mcm_destroy_wc_q(struct dcm_ib_qp *m_qp);
int  mcm_create_pi_cq(struct dcm_ib_qp *m_qp, int len);
void mcm_destroy_pi_cq(struct dcm_ib_qp *m_qp);

/* MIC eXchange (MIX) operations, mix.c */
int  dapli_mix_mode(ib_hca_transport_t *tp, char *name);
int  dapli_mix_open(ib_hca_transport_t *tp, char *name, int port, int query);
int  dapli_mix_mmap_free(ib_hca_transport_t *tp, uint8_t stat);
int  dapli_mix_mmap_alloc(ib_hca_transport_t *tp);
void dapli_mix_close(ib_hca_transport_t *tp);
int  dapli_mix_get_attr(ib_hca_transport_t *tp, dat_mix_prov_attr_t *pr_attr);
int  dapli_mix_query_device(ib_hca_transport_t *tp, struct ibv_device_attr *dev_attr);
int  dapli_mix_query_port(ib_hca_transport_t *tp, unsigned long port_num, struct ibv_port_attr *port_attr);
int  dapli_mix_listen(dp_ib_cm_handle_t cm, uint16_t sid);
int  dapli_mix_listen_free(dp_ib_cm_handle_t cm);
int  dapli_mix_qp_create(ib_qp_handle_t m_qp, struct ibv_qp_init_attr *attr,
	 		 ib_cq_handle_t req_cq, ib_cq_handle_t rcv_cq);
int  dapli_mix_qp_free(ib_qp_handle_t m_qp);
int  dapli_mix_cq_create(ib_cq_handle_t m_cq, int cq_len);
int  dapli_mix_cq_free(ib_cq_handle_t m_cq);
int  dapli_mix_cq_wait(ib_cq_handle_t m_cq, int time);
int  dapli_mix_cq_poll(ib_cq_handle_t m_cq, struct ibv_wc *wc);
int  dapli_mix_pz_create(DAPL_IA * ia_ptr, DAPL_PZ *m_pz);
DAT_RETURN dapls_ib_pd_free(IN DAPL_PZ * pz);
int  dapli_mix_pz_free(DAPL_PZ *m_pz);
int  dapli_mix_cm_req_out(dp_ib_cm_handle_t m_cm, ib_qp_handle_t m_qp);
int  dapli_mix_cm_rtu_out(dp_ib_cm_handle_t m_cm);
void dapli_mix_cm_dreq_out(dp_ib_cm_handle_t m_cm);
int  dapli_mix_cm_rep_out(dp_ib_cm_handle_t m_cm, int p_size, void *p_data);
int  dapli_mix_cm_rej_out(dp_ib_cm_handle_t m_cm, int p_size, void *p_data, int reason);
int  dapli_mix_post_send(ib_qp_handle_t m_qp, int len, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr);
int  dapli_mix_post_recv(ib_qp_handle_t m_qp, int len, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr);
int  dapli_mix_recv(DAPL_HCA *hca, int scif_ep);
int  dapli_mix_mr_create(ib_hca_transport_t *tp, DAPL_LMR * lmr);
int  dapli_mix_mr_free(ib_hca_transport_t *tp, DAPL_LMR * lmr);

#ifdef DAPL_COUNTERS
void dapls_print_cm_list(IN DAPL_IA *ia_ptr);
#endif

#endif /*  _DAPL_IB_UTIL_H_ */

