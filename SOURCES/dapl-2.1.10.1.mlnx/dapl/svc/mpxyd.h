/*
 * Copyright (c) 2012-2014 Intel Corporation. All rights reserved.
 *
 * This software is available to you under the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef _MPXYD_H_
#define _MPXYD_H_

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <byteswap.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <malloc.h>
#include <stdarg.h>
#include <getopt.h>
#include <fcntl.h>
#include <signal.h>
#include <scif.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include "dat2/udat.h"
#include "dapl_mic_common.h"

#define min(a, b) ((a < b) ? (a) : (b))
#define max(a, b) ((a > b) ? (a) : (b))

#define MCM_IB_INLINE		(sizeof(mcm_wr_rx_t))
#define MIX_MAX_MSG_SIZE	(8*1024*1024)

#define MIX_MIN  4 		/* oldest version supported */
#define MIX_COMP 4 		/* compatibility version */
#define MIX_MAX DAT_MIX_VER
/* #define MCM_PROFILE 1 */

/* locking */
typedef pthread_mutex_t      mpxy_lock_t;
#define mpxy_lock_init(x,y)  pthread_mutex_init(x,y)
#define mpxy_lock_destroy(x) pthread_mutex_destroy(x)
#define mpxy_lock(x)         pthread_mutex_lock(x)
#define mpxy_unlock(x)       pthread_mutex_unlock(x)

/* lists, fds, etc., include tid for lists  */
typedef struct _llist_entry
{
    struct _llist_entry	*next;
    struct _llist_entry	*prev;
    struct _llist_entry	*head;
    void		*data;
    uint32_t		tid;

} LLIST_ENTRY;

#define MCM_PORT_SPACE 0xffff
#define MCM_FD_SETSIZE 16384
struct mcm_fd_set {
	int index;
	struct pollfd set[MCM_FD_SETSIZE];
};

/* Support for IB devices - One service per device: UD QP for fabric CM services */
typedef struct mcm_ib_dev {
	LLIST_ENTRY 		entry;
	LLIST_ENTRY		smd_list;	/* MIC client open instances */
	mpxy_lock_t		slock;		/* SCIF client device lock */
	mpxy_lock_t		plock;		/* port space lock */
	mpxy_lock_t		txlock;		/* MCM UD CM tx lock */
	/* MCM - IB Device Resources */
	struct ibv_device	*ibdev;
	struct ibv_context	*ibctx;
	struct mcm_client	*mc; 		/* parent MIC client */
	int			ref_cnt;
	uint16_t		port; 		/* IB device port */
	struct ibv_pd		*pd;
	struct ibv_cq		*scq;
	struct ibv_cq		*rcq;
	struct ibv_qp		*qp;
	struct ibv_mr		*mr_rbuf;
	struct ibv_mr		*mr_sbuf;
	struct ibv_comp_channel *rch;
	struct ibv_ah		**ah;
	struct dat_mcm_msg	*sbuf;
	struct dat_mcm_msg	*rbuf;
	uint64_t		*ports;	/* SCIF device open clients, cm_id*/
	struct dat_mcm_addr	addr;
	uint16_t		lid;
	uint16_t		m_lid; /* intra-node, ibscif HST lid != MICx lids */
	uint8_t			m_gid[16];
	struct dat_mix_dev_attr	dev_attr; /* provided with mix_open */
	int			s_hd;
	int			s_tl;
	int			cqe;
	int			qpe;
	int			signal;
	int			retries;
	int			cm_timer;
	int			rep_time;
	int			rtu_time;
	int 			numa_node;
	int			indata;
	void			*cntrs;

} mcm_ib_dev_t;

/*
 *  MPXYD shared proxy buffer management, work completion
 *  Required for out of order completions across multiple QP's
 */
typedef struct mcm_buf_wc {
	uint32_t		m_idx;
	uint32_t		done;
#ifdef MCM_PROFILE
	uint32_t		hd;
	uint32_t		tl;
	uint32_t		ref;
	uint32_t		ts;
	void 			*wr;
#endif
} mcm_buf_wc_t;

/* performance profiling */
enum mcm_prof_type
{
	MCM_QP_WT,
	MCM_QP_RF,
	MCM_QP_IB_RW,
	MCM_QP_IB_RR,
	MCM_QP_PO_POST,
	MCM_QP_PO_PI_RW,
	MCM_QP_ALL
};

typedef struct mcm_qp_prof_val {
	uint32_t	min;
	uint32_t	max;
	uint32_t	avg;
	uint32_t	all;
	uint32_t	cnt;
	uint32_t	start;
	uint32_t	stop;
} mcm_qp_prof_val_t;

typedef struct mcm_qp_prof {
	mcm_qp_prof_val_t	wt; /* scif_writeto  */
	mcm_qp_prof_val_t	rf; /* scif_readfrom  */
	mcm_qp_prof_val_t	rw; /* IB write */
	mcm_qp_prof_val_t	rr; /* IB read */
	mcm_qp_prof_val_t	ps; /* Mix post_send times */
	mcm_qp_prof_val_t	po; /* IO proxy-out: FirstSeg to LastSeg */
} mcm_qp_prof_t;

/*  DAPL MCM QP object, id in entry */
typedef struct mcm_qp {
	LLIST_ENTRY		t_entry;
	LLIST_ENTRY		r_entry;
	struct mcm_scif_dev	*smd;
	struct mcm_cm		*cm;
	struct ibv_qp		*ib_qp1;	/* RX proxy QP, MIC_XSOCK_DEV */
	struct ibv_qp		*ib_qp2;	/* TX proxy QP, all cases */
	mpxy_lock_t		txlock;		/* QP lock, pool and cookies, TX proxy-out side */
	mpxy_lock_t		rxlock;		/* QP lock, pool and cookies, RX proxy-in side */
	dat_mix_qp_attr_t	qp_attr1;	/* RX attributes, QP1 */
	dat_mix_qp_attr_t	qp_attr2;	/* TX attributes, QP2  */
	struct mcm_cq		*m_cq_rx;	/* RX CQ proxy-in service */
	struct mcm_cq		*m_cq_tx;	/* TX CQ proxy-out service */
	/* Proxy-out: WR local queue, local on TX side */
	char			*wr_buf;	/* WR entries, 128 bytes * qp_t->max_send_wr */
	off_t 			wr_off;		/* SCIF registered, for scif_fence_signal @ wr->wr_id */
	int			wr_hd;		/* work request pool head  */
	int 			wr_tl;		/* work request pool tail  */
	int			wr_tl_rf; 	/* work requets pool RF tail */
	int			wr_end;		/* work request pool end  */
	int			wr_len;		/* work request pool size */
	int			wr_pp;		/* work request pending */
	int			wr_sz;		/* work request entry size, 64 byte aligned */
	int 			post_cnt;	/* completion management to avoid WR depletion */
	int			post_sig_cnt;
	int			comp_cnt;
	char			*wr_buf_rx;	/* mcm_wr_rx_t entries, for devices without inline data  */
	struct ibv_mr		*wr_buf_rx_mr;
	int			p2p_data; 	/* Max number of bytes to pass from proxy to proxy in the WR */
	/* Proxy-in: WR management, remote view from TX side */
	mcm_wrc_info_t		wrc_rem;	/* WR and WC buffers: remote, in CM req and reply */
	int			wr_pp_rem;	/* work request pending */
	int			wr_sz_rem;	/* work request entry size, 64 byte aligned */
	int			wc_tl;		/* WC tail update, back to proxy_in via wr_rx writes */
	/* Proxy-in: WC management, remote view from RX side */
	int			wc_hd_rem;	/* work completion pool head  */
	int 			wc_tl_rem;	/* work completion pool tail  */
	int			wc_sz_rem;	/* work request entry size, 64 byte aligned */
	/* Proxy-in: WR and WC buffer resources, local on RX side */
	mcm_wrc_info_t		wrc;		/* WR and WC buffers: local, addr, key, len, end */
	off_t 			wr_off_r;	/* SCIF registered, for scif_fence_signal @ wr->wr_id */
	struct ibv_mr		*wr_rbuf_mr;	/* IB WR - MR address and key */
	int			wr_hd_r;	/* RX side, WR pool head  */
	int 			wr_tl_r;	/* RX side, WR pool tail  */
	int 			wr_tl_r_wt;	/* RX side, WR pool tail, writeto pending tail  */
	struct ibv_mr		*wc_rbuf_mr;	/* RX WC - IB MR address and key */
	int			post_cnt_rr;	/* RX WR - total RR posted count */
	int			pi_rw_cnt;	/* Proxy-in pending, RW_imm for WC's */
	int			post_cnt_wt;	/* RX WR, proxy-in, scif_writeto post pending */
	int 			pi_rr_cnt;	/* RX WR, proxy-in, IB Rdma Reads pending */
	int 			stall_cnt_rr;	/* RX WR, proxy-in, IB Rdma Reads stalled */
	char			*wc_buf_rx;	/* mcm_wc_rx_t entries, for devices without inline data  */
	struct ibv_mr		*wc_buf_rx_mr;
	/* Proxy-in: send/recv message queue, local on RX side */
	char			*sr_buf;	/* Send-Recv message work request queue */
	int 			sr_hd;		/* SR WR head */
	int 			sr_tl;		/* SR WR tail */
	int 			sr_end;		/* SR WR end */
	int 			sr_len;		/* SR WR buffer pool len */
	int			sr_sz;		/* SR WR entry size */
	int			post_sr;
	uint8_t			mtu;		/* negotiated QP MTU */
#ifdef MCM_PROFILE
	mcm_qp_prof_t		ts;
	uint32_t		last_wr_sig;
	uint32_t		last_wr_pst;
	uint32_t		last_rf;
	uint32_t		last_ps;
#endif

} mcm_qp_t;

/*  DAPL MCM CQ object, id in entry */
typedef struct mcm_cq {
	LLIST_ENTRY		entry;
	struct mcm_scif_dev	*smd;
	struct ibv_cq		*ib_cq;
	struct ibv_comp_channel	*ib_ch;
	uint32_t		cq_len;
	uint32_t		cq_id;	/* MIC client */
	uint64_t		cq_ctx; /* MIC client */
	uint64_t 		prev_id;
	int			ref_cnt;

} mcm_cq_t;

/*  DAPL MCM PZ object */
typedef struct mcm_pz {
	LLIST_ENTRY		entry;
	struct mcm_scif_dev	*smd;
	struct ibv_pd		*ib_pd;
	uint64_t		pd_ctx; /* MIC client */
} mcm_pz_t;

/*  DAPL MCM MR object, id in entry */
typedef struct mcm_mr {
	LLIST_ENTRY		entry;
	struct mcm_scif_dev	*smd;
	int 			busy;
	dat_mix_mr_t		mre;

} mcm_mr_t;

/*  DAPL MCM Connection/Listen object */
typedef struct mcm_cm {
	LLIST_ENTRY		entry;
	mpxy_lock_t		lock;
	struct mcm_ib_dev	*md;	/* mcm_ib_dev parent reference */
	struct mcm_scif_dev	*smd;	/* mcm_scif_dev parent reference */
	struct mcm_cm		*l_ep;	/* listen reference, passive */
	uint16_t		sid;	/* service ID for endpoint */
	uint32_t		cm_id;	/* id of client, QPr */
	uint64_t		cm_ctx; /* ctx of client, QPr  */
	uint64_t		sp_ctx; /* ctx of client, listen SP */
	uint64_t		timer;
        int			ref_cnt;
	int			state;
	int			retries;
	struct mcm_qp		*m_qp;	/* pair of QP's, qp_t and qp_r */
	uint16_t		p_size; /* accept p_data, for retries */
	uint8_t			p_data[DAT_MCM_PDATA_SIZE];
	struct dat_mcm_msg	msg;

} mcm_cm_t;

/*
 * per MIC MCM client open, SCIF device object:
 */
typedef struct mcm_scif_dev {
	LLIST_ENTRY		entry;
	LLIST_ENTRY		clist;		/* LISTS: cm list */
	LLIST_ENTRY		llist;		/* listen list */
	LLIST_ENTRY		qptlist;	/* qp proxy out service */
	LLIST_ENTRY		qprlist;	/* qp proxy in service */
	LLIST_ENTRY		cqlist;		/* client cq create list */
	LLIST_ENTRY		cqrlist;	/* mpxyd cq list for proxy in service */
	LLIST_ENTRY		mrlist;		/* mr list */
	LLIST_ENTRY		pzlist;		/* pz list */
	mpxy_lock_t		clock;		/* LOCKS: cm lock */
	mpxy_lock_t		llock;		/* listen lock */
	mpxy_lock_t		plock;		/* port space lock */
	mpxy_lock_t		qptlock;	/* qpt list lock */
	mpxy_lock_t		qprlock;	/* qpr list lock */
	mpxy_lock_t		cqlock;		/* cq tx lock */
	mpxy_lock_t		cqrlock;	/* cq rx lock */
	mpxy_lock_t		mrlock;		/* mr lock */
	mpxy_lock_t		pzlock;		/* pz lock */
	mpxy_lock_t		evlock;		/* DTO event lock, multi-threads on ev_ep */
	int			destroy;	/* destroying device, all resources */
	int			ref_cnt;	/* child references */
	int 			th_ref_cnt;	/* work thread references */
	struct mcm_ib_dev	*md;		/* mcm_ib_dev, parent */
	uint16_t		cm_id;		/* port ID MIC client, md->ports */
	uint64_t		*ports;		/* EP port space MIC client */
	scif_epd_t 		scif_op_ep;	/* SCIF EP, MIX operations, CM messages */
	scif_epd_t 		scif_ev_ep;	/* SCIF Event EP, MIX dto, cm, async */
	scif_epd_t 		scif_tx_ep;	/* SCIF CM EP, MIX data xfer */
	struct scif_portID 	peer;		/* SCIF EP peer, MIC adapter */
	struct scif_portID 	peer_cm;	/* SCIF CM EP peer, MIC adapter */

	mpxy_lock_t	tblock;		/* TX proxy buffer lock */
	char			*m_buf;		/* MIC TX proxy buffer, SCIF and IB  */
	struct ibv_mr		*m_mr;		/* ib registration */
	off_t 			m_offset;	/* SCIF registration */
	int			m_hd;		/* buffer pool head */
	int			m_tl;		/* buffer pool tail */
	int			m_len;		/* TX buffer size */
	int			m_seg;		/* segment size, same for TX and RX proxy */
	struct 	mcm_buf_wc	*m_buf_wc;	/* Proxy Buffer work completion queue */
	int			m_buf_tl;	/* Proxy Buffer WC queue tl */
	int			m_buf_hd;	/* Proxy Buffer WC queue hd */
	int			m_buf_end;	/* Proxy Buffer WC queue end */

	mpxy_lock_t	rblock;		/* RX proxy buffer lock */
	char			*m_buf_r;	/* MIC RX proxy buffer, SCIF and IB  */
	struct ibv_mr		*m_mr_r;	/* Rcv proxy buffer, ib registration */
	off_t 			m_offset_r;	/* Rcv proxy buffer, SCIF registration */
	int			m_hd_r;		/* Rcv buffer pool head */
	int			m_tl_r;		/* Rcv buffer pool tail */
	int			m_len_r;	/* Rcv proxy buffer size */
	struct 	mcm_buf_wc	*m_buf_wc_r;	/* Proxy Buffer work completion queue */
	int			m_buf_tl_r;	/* Proxy Buffer WC queue tl */
	int			m_buf_hd_r;	/* Proxy Buffer WC queue hd */
	int			m_buf_end_r;	/* Proxy Buffer WC queue end */
	char			*cmd_buf;	/* operation command buffer  */
	struct dat_mix_dev_attr	dev_attr;	/* Manage attributes per MIC client open */
	uint8_t			mtu_env;	/* mtu override with DAPL_IB_MTU */

	dat_mix_mmap_wr_t	*mm_r_addr;	/* Address of post_send WR array, updated from MIC via writes */
	int			mm_r_len;	/* total bytes of WR array */
	off_t			mm_r_addr_off;	/* WR entry rcv buffer, map from MIC via mmap, SCIF registration */
	int			mm_r_head;	/* location for new posted WR entries from MIC */
	int			mm_r_last;	/* mmap WR array size */
	off_t			mm_s_peer_addr_off; 	/* peer scif address for tail update */
	volatile int 		*mm_s_peer_addr; 	/* writing to this address is writing to remote mem */
	int			*mm_s_place_holder;	/* alloc local memory for scif_mmap, not referenced */

#ifdef MCM_PROFILE
	uint16_t		m_hd_ro;	/* HD,TL tracking */
	uint16_t		m_tl_ro;
	uint16_t		m_hd_ro_r;
	uint16_t		m_tl_ro_r;
#endif

} mcm_scif_dev_t;

/* 1-8 MIC nodes, 1-8 IB ports, 4 threads (op/events, CM, TX, RX) each node */
#define MCM_IB_MAX 8
#define MCM_CLIENT_MAX 8
typedef struct mcm_client {
	uint16_t ver;
	uint16_t scif_id;
	int numa_node;
	int op_pipe[2];
	int tx_pipe[2];
	int rx_pipe[2];
	int cm_pipe[2];
	int tx_busy;
	int rx_busy;
	cpu_set_t op_mask;
	cpu_set_t tx_mask;
	cpu_set_t rx_mask;
	cpu_set_t cm_mask;
	mpxy_lock_t oplock;
	mpxy_lock_t txlock;
	mpxy_lock_t rxlock;
	mpxy_lock_t cmlock;
	pthread_t tx_thread;
	pthread_t rx_thread;
	pthread_t op_thread;
	pthread_t cm_thread;
	mcm_ib_dev_t mdev[MCM_IB_MAX];
} mcm_client_t;

typedef enum mcm_counters
{
	MCM_IA_OPEN,
	MCM_IA_CLOSE,
	MCM_PD_CREATE,
	MCM_PD_FREE,
	MCM_MR_CREATE,
	MCM_MR_FREE,
	MCM_CQ_CREATE,
	MCM_CQ_FREE,
	MCM_CQ_POLL,
	MCM_CQ_REARM,
	MCM_CQ_EVENT,
	MCM_MX_SEND,
	MCM_MX_SEND_INLINE,
	MCM_MX_WRITE,
	MCM_MX_WRITE_SEG,
	MCM_MX_WRITE_INLINE,
	MCM_MX_WR_STALL,
	MCM_MX_MR_STALL,
	MCM_MX_RR_STALL,
	MCM_QP_CREATE,
	MCM_QP_SEND,
	MCM_QP_SEND_INLINE,
	MCM_QP_WRITE,
	MCM_QP_WRITE_INLINE,
	MCM_QP_WRITE_DONE,
	MCM_QP_READ,
	MCM_QP_READ_DONE,
	MCM_QP_RECV,
	MCM_QP_FREE,
	MCM_QP_EVENT,
	MCM_SRQ_CREATE,
	MCM_SRQ_FREE,
	MCM_MEM_ALLOC,
	MCM_MEM_ALLOC_DATA,
	MCM_MEM_FREE,
	MCM_ASYNC_ERROR,
	MCM_ASYNC_QP_ERROR,
	MCM_ASYNC_CQ_ERROR,
	MCM_SCIF_SEND,
	MCM_SCIF_RECV,
	MCM_SCIF_READ_FROM,
	MCM_SCIF_READ_FROM_DONE,
	MCM_SCIF_WRITE_TO,
	MCM_SCIF_WRITE_TO_DONE,
	MCM_SCIF_SIGNAL,
	MCM_LISTEN_CREATE,
	MCM_LISTEN_CREATE_ANY,
	MCM_LISTEN_FREE,
	MCM_CM_CONN_EVENT,
	MCM_CM_DISC_EVENT,
	MCM_CM_TIMEOUT_EVENT,
	MCM_CM_ERR_EVENT,
	MCM_CM_TX_POLL,
	MCM_CM_RX_POLL,
	MCM_CM_MSG_OUT,
	MCM_CM_MSG_IN,
	MCM_CM_MSG_POST,
	MCM_CM_REQ_OUT,
	MCM_CM_REQ_IN,
	MCM_CM_REQ_ACCEPT,
	MCM_CM_REP_OUT,
	MCM_CM_REP_IN,
	MCM_CM_RTU_OUT,
	MCM_CM_RTU_IN,
	MCM_CM_REJ_OUT,
	MCM_CM_REJ_IN,
	MCM_CM_REJ_USER_OUT,
	MCM_CM_REJ_USER_IN,
	MCM_CM_ACTIVE_EST,
	MCM_CM_PASSIVE_EST,
	MCM_CM_AH_REQ_OUT,
	MCM_CM_AH_REQ_IN,
	MCM_CM_AH_RESOLVED,
	MCM_CM_DREQ_OUT,
	MCM_CM_DREQ_IN,
	MCM_CM_DREQ_DUP,
	MCM_CM_DREP_OUT,
	MCM_CM_DREP_IN,
	MCM_CM_MRA_OUT,
	MCM_CM_MRA_IN,
	MCM_CM_REQ_FULLQ_POLL,
	MCM_CM_ERR,
	MCM_CM_ERR_REQ_FULLQ,
	MCM_CM_ERR_REQ_DUP,
	MCM_CM_ERR_REQ_RETRY,
	MCM_CM_ERR_REP_DUP,
	MCM_CM_ERR_REP_RETRY,
	MCM_CM_ERR_RTU_DUP,
	MCM_CM_ERR_RTU_RETRY,
	MCM_CM_ERR_REFUSED,
	MCM_CM_ERR_RESET,
	MCM_CM_ERR_TIMEOUT,
	MCM_CM_ERR_REJ_TX,
	MCM_CM_ERR_REJ_RX,
	MCM_CM_ERR_DREQ_DUP,
	MCM_CM_ERR_DREQ_RETRY,
	MCM_CM_ERR_DREP_DUP,
	MCM_CM_ERR_DREP_RETRY,
	MCM_CM_ERR_MRA_DUP,
	MCM_CM_ERR_MRA_RETRY,
	MCM_CM_ERR_UNEXPECTED_STATE,
	MCM_CM_ERR_UNEXPECTED_MSG,
	MCM_ALL_COUNTERS,  /* MUST be last */

} MCM_COUNTERS;
#define MCNTR(mdev, cntr) ((uint64_t *)mdev->cntrs)[cntr]++

/* prototypes */

/* mpxyd - daemon services, thread processing */
void mpxy_destroy_md(struct mcm_ib_dev *md);
void mpxy_destroy_smd(struct mcm_scif_dev *smd);
void mpxy_destroy_bpool(struct mcm_scif_dev *smd);
void mpxy_op_thread(void *mic_client);
void mpxy_tx_thread(void *mic_client);
void mpxy_cm_thread(void *mic_client);
void mpxy_rx_thread(void *mic_client);
mcm_scif_dev_t *mix_open_device(dat_mix_open_t *msg,
				scif_epd_t op_ep,
				scif_epd_t ev_ep,
				scif_epd_t tx_ep,
				uint16_t node);
#ifdef MCM_PROFILE
void mcm_check_io();
#endif

/* mcm.c, cm services */
void mcm_get_attr(dat_mix_prov_attr_t *pr_attr);
int mcm_init_cm_service(mcm_ib_dev_t *md);
mcm_cm_t *m_cm_create(mcm_scif_dev_t *smd, mcm_qp_t *m_qp, dat_mcm_addr_t *dst);
void m_cm_free(mcm_cm_t *cm);
void mcm_cm_disc(mcm_cm_t *m_cm);
int mcm_cm_req_out(mcm_cm_t *m_cm);
int mcm_cm_rtu_out(mcm_cm_t *m_cm);
int mcm_cm_rep_out(mcm_cm_t *cm);
int mcm_cm_rej_out(mcm_ib_dev_t *md, dat_mcm_msg_t *msg, DAT_MCM_OP type, int swap);
void mcm_check_timers(mcm_scif_dev_t *smd, int *timer);
void mcm_ib_recv(mcm_ib_dev_t *md);
int mcm_ib_async_event(struct mcm_ib_dev *md);
void mcm_qlisten(mcm_scif_dev_t *smd, mcm_cm_t *cm);
void mcm_dqlisten_free(mcm_scif_dev_t *smd, mcm_cm_t *cm);
void mcm_qconn(mcm_scif_dev_t *smd, mcm_cm_t *cm);
void mcm_dqconn_free(mcm_scif_dev_t *smd, mcm_cm_t *cm);
int mcm_modify_qp(struct ibv_qp *qp_handle, enum ibv_qp_state qp_state,
		  uint32_t qpn, uint16_t lid, union ibv_gid *gid);
void mcm_flush_qp(struct mcm_qp *m_qp);
void mcm_dump_cm_lists(mcm_scif_dev_t *smd);

/* mix.c, MIC message exchange (MIX) services */
void m_cq_free(struct mcm_cq *m_cq);
void m_qp_free(struct mcm_qp *m_qp);
void m_mr_free(struct mcm_mr *m_mr);
int mix_scif_recv(mcm_scif_dev_t *smd, scif_epd_t scif_ep);
int mix_post_send_ext(mcm_scif_dev_t *smd);
int mix_cm_disc_in(mcm_cm_t *m_cm);
int mix_cm_rtu_in(mcm_cm_t *m_cm, dat_mcm_msg_t *pkt, int pkt_len);
int mix_cm_req_in(mcm_cm_t *cm, dat_mcm_msg_t *pkt, int pkt_len);
int mix_cm_rep_in(mcm_cm_t *m_cm, dat_mcm_msg_t *pkt, int pkt_len);
int mix_cm_rej_in(mcm_cm_t *m_cm, dat_mcm_msg_t *pkt, int pkt_len);
void mix_close_device(mcm_ib_dev_t *md, mcm_scif_dev_t *smd);
void mix_scif_accept(scif_epd_t listen_ep);
void mix_cm_event(mcm_cm_t *m_cm, uint32_t event);
void mix_dto_event(struct mcm_cq *m_cq, struct dat_mix_wc *wc, int nc);

/* util.c, helper funtions */
FILE *mpxy_open_log(void);
void mpxy_set_options(int debug_mode);
void mpxy_log_options(void);
int mpxy_open_lock_file(void);
void mpxyd_release_lock_file( void );
void mpxy_write(int level, const char *format, ...);
void mpxy_pr_addrs(int lvl, struct dat_mcm_msg *msg, int state, int in);
int mpxy_cpuinfo_atoi(const char *v_str);
#ifdef MCM_PROFILE
void mcm_qp_prof_pr(struct mcm_qp *m_qp, int type);
void mcm_qp_prof_ts(struct mcm_qp *m_qp, int type, uint32_t start, uint32_t qcnt, uint32_t ccnt);
#endif

struct mcm_fd_set *mcm_alloc_fd_set(void);
void mcm_fd_zero(struct mcm_fd_set *set);
int mcm_fd_set(int fd, struct mcm_fd_set *set, int event);
int mcm_config_fd(int fd);
int mcm_poll(int fd, int event);
int mcm_select(struct mcm_fd_set *set, int time_ms);
uint16_t mcm_get_port(uint64_t *p_port, uint16_t port, uint64_t ctx);
uint64_t mcm_get_port_ctx(uint64_t *p_port, uint16_t port);

int rd_dev_file(char *path, char *file, char *v_str, int len);
void md_cntr_log(mcm_ib_dev_t *md, int counter, int reset);

/* mpxy_out.c, proxy_out services, rdma write, message req side */
void m_po_destroy_bpool(struct mcm_qp *m_qp);
int m_po_create_bpool(struct mcm_qp *m_qp, int max_req_wr);
void m_po_pending_wr(struct mcm_qp *m_qp, int *data);
int m_po_proxy_data(mcm_scif_dev_t *smd, dat_mix_sr_t *pmsg, struct mcm_qp *m_qp);
void m_po_wc_event(struct mcm_qp *m_qp, struct mcm_wc_rx *wc_rx, int wc_idx);
void m_req_event(struct mcm_cq *m_cq, int *events);
int m_po_buf_hd(mcm_scif_dev_t *smd, int m_idx, struct mcm_wr *wr);

/* mpxy_in.c, proxy_in services, rdma write, message rcv side */
void m_pi_destroy_wc_q(struct mcm_qp *m_qp);
void m_pi_destroy_bpool(struct mcm_qp *m_qp);
int m_pi_create_wr_q(struct mcm_qp *m_qp, int entries);
int m_pi_create_wc_q(struct mcm_qp *m_qp, int entries);
int m_pi_create_sr_q(struct mcm_qp *m_qp, int entries);
int m_pi_create_bpool(struct mcm_qp *m_qp, int max_recv_wr);
void m_qp_destroy_pi(struct mcm_qp *m_qp);
int m_qp_create_pi(mcm_scif_dev_t *smd, struct mcm_qp *m_qp);
void m_pi_pending_wt(struct mcm_qp *m_qp);
void m_pi_pending_wr(struct mcm_qp *m_qp, int *data);
void m_pi_pending_wc(struct mcm_qp *m_qp, int *events);
void m_pi_req_event(struct mcm_qp *m_qp, struct mcm_wr_rx *wr_rx, struct ibv_wc *wc, int type);
void m_rcv_event(struct mcm_cq *m_cq, int *events);
int m_pi_prep_rcv_q(struct mcm_qp *m_qp);


/* logging levels, bit control:
 * 0=errors
 * 1=warnings
 * 2=cm
 * 4=data
 * 8=info
 * 0x10=perf
 */
#define mlog(level, format, ...) \
	mpxy_write(level, "%s: "format, __func__, ## __VA_ARGS__)

/* inline functions */

/* link list helper resources */
static inline void init_list(LLIST_ENTRY *head)
{
        head->next = head;
        head->prev = head;
        head->data = NULL;
        head->tid = 0;
}

static inline int list_empty(LLIST_ENTRY *head)
{
        return head->next == head;
}

static inline void *get_head_entry(LLIST_ENTRY *head)
{
	if (list_empty(head))
		return NULL;
	else
		return head->next->data;
}

static inline void *get_next_entry(LLIST_ENTRY *entry, LLIST_ENTRY *head)
{
	if (entry->next == head)
		return NULL;
	else
		return entry->next->data;
}

static inline void insert_head(LLIST_ENTRY *entry, LLIST_ENTRY *head, void *data)
{
	head->tid++;	/* each insertion gets unique ID */
	entry->tid = head->tid;
	entry->next = head->next;
	entry->prev = head;
	entry->data = data;
	head->next->prev = entry;
	head->next = entry;
}

static inline void insert_tail(LLIST_ENTRY *entry, LLIST_ENTRY *head, void *data)
{
	if (entry->next != entry) {
		mlog(0, " WARNING: entry %p already on list %d\n", entry, entry->next);
		return;
	}
	head->tid++;	/* each insertion gets unique ID */
	entry->tid = head->tid;
	entry->data = data;
	entry->next = head->prev->next;
	entry->prev = head->prev;
	head->prev->next = entry;
	head->prev = entry;

}

static inline void remove_entry(LLIST_ENTRY *entry)
{
        entry->prev->next = entry->next;
        entry->next->prev = entry->prev;
        entry->data = NULL;
        entry->tid = 0;
}

extern int mcm_affinity;
static inline void sleep_usec(int usec)
{
	struct timespec sleep, remain;

	sleep.tv_sec = 0;
	sleep.tv_nsec = usec * 1000;
	nanosleep(&sleep, &remain);
	sched_yield();
}

static inline uint32_t mcm_ts_us(void)
{
        struct timeval curtime;
        timerclear(&curtime);
        gettimeofday(&curtime, NULL);
        return (uint32_t) (((curtime.tv_sec & 0xff) * 1000000) + curtime.tv_usec);
}

static inline uint64_t mcm_time_us(void)
{
        struct timeval curtime;
        timerclear(&curtime);
        gettimeofday(&curtime, NULL);
        return (uint64_t) curtime.tv_sec * 1000000 + (uint64_t) curtime.tv_usec;
}
#define mcm_time_ms() (mcm_time_us() / 1000)

static inline int pb_full(int start, int end, int head, int tail, int len, int size)
{
	if (((start < tail) && (end >= tail)) ||
	   (((head - tail) < 0) && (ALIGN_64(head) + len) >= tail) ||
	   (((ALIGN_64(head) + len) > size) && start >= tail))
		return 1;
	else
		return 0;
}

static inline void mcm_free_port(uint64_t *p_port, uint16_t port)
{
	p_port[port] = 0;
}

/* Blocking for now, eliminates the need for MPXYD level locking */
static inline int scif_send_msg(scif_epd_t ep, void *msg, int snd_len)
{
	int ret, len = snd_len;
	int off = 0;
	int flags = 0; /* !SCIF_SEND_BLOCK */

	while (len) {
		errno = 0;
		if (len == snd_len) mlog(8, "  scif_send - ep %d, msg %p len=%d \n", ep, msg+off, len);
		ret = scif_send(ep, msg+off, len, flags);
		if (len == snd_len) mlog(8, "  scif_sent - ep %d, len=%d ret=%d %s\n", ep, len, ret, strerror(errno));
		if ((ret == -1) || (flags == SCIF_SEND_BLOCK && (ret != len))) {
			mlog(0, "ERR: scif_send - ep %d, %s, (len %d != ret %d) msg(%p %p)\n",
				 ep, strerror(errno), len, ret, msg, msg+off);
			return -1;
		}
		if ((ret < len) && ret) {
			mlog(1, " WARN: scif_send - ep %d, msg %p off %d blocked len=%d, sent=%d\n",
			     ep, msg, off, len, ret);
		}
		off += ret;
		len -= ret;
	}
	return 0;
}

static inline void const_mix_wc(struct dat_mix_wc *mwc, struct ibv_wc *iwc, int entries)
{
	int i;

	for (i=0;i<entries;i++) {
		memset((void*)&mwc[i].wr_id, 0, sizeof(*mwc));
		mwc[i].wr_id = iwc[i].wr_id;
		mwc[i].status = iwc[i].status;
		mwc[i].opcode = iwc[i].opcode;
		mwc[i].vendor_err = iwc[i].vendor_err;
		mwc[i].byte_len = iwc[i].byte_len;
		mwc[i].imm_data = iwc[i].imm_data;
		mwc[i].qp_num = iwc[i].qp_num;
		mwc[i].src_qp = iwc[i].src_qp;
		mwc[i].wc_flags = iwc[i].wc_flags;
		mwc[i].pkey_index = iwc[i].pkey_index;
		mwc[i].slid = iwc[i].slid;
		mwc[i].sl = iwc[i].sl;
		mwc[i].dlid_path_bits = iwc[i].dlid_path_bits;
	}
}
/* rdma write */
static inline void const_ib_rw(struct ibv_send_wr *iwr, struct dat_mix_wr *mwr, struct ibv_sge *sg_ptr)
{
	memset((void*)iwr, 0, sizeof(*iwr));
	iwr->sg_list = sg_ptr;
	iwr->opcode = mwr->opcode;
	iwr->send_flags = mwr->send_flags;
	iwr->imm_data = mwr->imm_data;
	iwr->wr.rdma.remote_addr = mwr->wr.rdma.remote_addr;
	iwr->wr.rdma.rkey = mwr->wr.rdma.rkey;
}

/* rdma read, 4 sg entries */
/* sg[0] entry == proxy-out buffer, src for IB RR */
/* sg[1] entry == proxy-in buffer, dst for IB RR */
static inline void const_ib_rr(struct ibv_send_wr *iwr, struct dat_mix_wr *mwr, struct ibv_sge *sg)
{
	memset((void*)iwr, 0, sizeof(*iwr));
	iwr->num_sge = 1;
	iwr->sg_list = &sg[1];
	iwr->opcode = IBV_WR_RDMA_READ;
	iwr->send_flags = 0;
	iwr->imm_data = 0;
	iwr->wr.rdma.remote_addr = sg[0].addr;
	iwr->wr.rdma.rkey = sg[0].lkey;
}


static inline void mcm_pr_addrs(int lvl, struct dat_mcm_msg *msg, int state, int in)
{
	if (in) {
		if (MXF_EP(&msg->daddr1) && MXF_EP(&msg->saddr1)) {
			mlog(lvl, " QPr_t addr2: %s 0x%x %x 0x%x %s <- QPt_r addr2: 0x%x %x 0x%x %s\n",
				mcm_state_str(state), htons(msg->daddr2.lid),
				htonl(msg->daddr2.qpn), htons(msg->dport),
				mcm_map_str(msg->daddr2.ep_map),
				htons(msg->saddr2.lid), htonl(msg->saddr2.qpn),
				htons(msg->sport), mcm_map_str(msg->saddr2.ep_map));
		} else {
			mlog(lvl, " QPr addr1: %s 0x%x %x 0x%x %s <- QPt addr2: 0x%x %x 0x%x %s\n",
				mcm_state_str(state), htons(msg->daddr1.lid),
				htonl(msg->daddr1.qpn), htons(msg->dport),
				mcm_map_str(msg->daddr1.ep_map),
				htons(msg->saddr2.lid), htonl(msg->saddr2.qpn),
				htons(msg->sport), mcm_map_str(msg->saddr2.ep_map));
			mlog(lvl, " QPt addr2: %s 0x%x %x 0x%x %s <- QPr addr1: 0x%x %x 0x%x %s\n",
				mcm_state_str(state),htons(msg->daddr2.lid),
				htonl(msg->daddr2.qpn), htons(msg->dport),
				mcm_map_str(msg->daddr2.ep_map),
				htons(msg->saddr1.lid), htonl(msg->saddr1.qpn),
				htons(msg->sport), mcm_map_str(msg->saddr1.ep_map));
		}
	} else {
		if (MXF_EP(&msg->saddr1) && MXF_EP(&msg->daddr1)) {
			mlog(lvl, " QPr_t addr2: %s 0x%x %x 0x%x %s -> QPt_r addr2: 0x%x %x 0x%x %s\n",
				mcm_state_str(state), htons(msg->saddr2.lid),
				htonl(msg->saddr2.qpn), htons(msg->sport),
				mcm_map_str(msg->saddr2.ep_map),
				htons(msg->daddr2.lid), htonl(msg->daddr2.qpn),
				htons(msg->dport), mcm_map_str(msg->daddr2.ep_map));
		} else {
			mlog(lvl, " QPr addr1: %s 0x%x %x 0x%x %s -> QPt addr2: 0x%x %x 0x%x %s\n",
				mcm_state_str(state), htons(msg->saddr1.lid),
				htonl(msg->saddr1.qpn), htons(msg->sport),
				mcm_map_str(msg->saddr1.ep_map),
				htons(msg->daddr2.lid), htonl(msg->daddr2.qpn),
				htons(msg->dport), mcm_map_str(msg->daddr2.ep_map));
			mlog(lvl, " QPt addr2: %s 0x%x %x 0x%x %s -> QPr addr1: 0x%x %x 0x%x %s\n",
				mcm_state_str(state), htons(msg->saddr2.lid),
				htonl(msg->saddr2.qpn), htons(msg->sport),
				mcm_map_str(msg->saddr2.ep_map),
				htons(msg->daddr1.lid), htonl(msg->daddr1.qpn),
				htons(msg->dport), mcm_map_str(msg->daddr1.ep_map));
		}
	}
}

static inline int mcm_ib_inline_data (IN struct ibv_context *ib_ctx)
{
	struct ibv_qp_init_attr qp_create;
	struct ibv_pd *ib_pd = NULL;
	struct ibv_cq *ib_cq = NULL;
	struct ibv_qp *ib_qp = NULL;
	int ret = 0;

	ib_pd = ibv_alloc_pd(ib_ctx);
	if (!ib_pd)
		goto bail;

	ib_cq = ibv_create_cq(ib_ctx, 10, ib_ctx, NULL, 0);
	if (!ib_cq)
		goto bail;

	memset((void *)&qp_create, 0, sizeof(qp_create));
	qp_create.qp_type = IBV_QPT_RC;
	qp_create.send_cq = ib_cq;
	qp_create.recv_cq = ib_cq;
	qp_create.cap.max_send_wr = 1;
	qp_create.cap.max_send_sge = 1;
	qp_create.cap.max_inline_data = MCM_IB_INLINE;
	qp_create.qp_context = (void *)ib_ctx;

	ib_qp = ibv_create_qp(ib_pd, &qp_create);
	if (ib_qp && qp_create.cap.max_inline_data >= MCM_IB_INLINE)
		ret = 1;
bail:
	if (ib_qp)
		ibv_destroy_qp(ib_qp);
	if (ib_cq)
		ibv_destroy_cq(ib_cq);
	if (ib_pd)
		ibv_dealloc_pd(ib_pd);

	return ret;
}

#endif /*  _MPXYD_H_ */




