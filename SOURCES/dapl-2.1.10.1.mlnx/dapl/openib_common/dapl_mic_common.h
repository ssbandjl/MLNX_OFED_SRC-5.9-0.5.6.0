/*
 * Copyright (c) 2012-2014 Intel Corporation.  All rights reserved.
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

/**********************************************************************
 *
 * HEADER: dapl_mic_common.h
 *
 * PURPOSE: Definitions for MIC Proxy RDMA services
 *
 * 	MCM provider <-> MPXYD service
 *
 *	This service enables MIC based DAPL provider (MCM) to use
 *	proxy service (host CPU) for sends and RDMA write operations.
 *	proxy RDMA reads are not supported. This service
 *	communicates within a server platform over PCI-E bus using SCIF
 *	and a new MIX within messaging protocol. The MCM provider uses
 *	DAPL MCM messaging protocols on the wire. MIX protocol is defined
 *	as part of the communication protocol between MCM provider on MIC
 *	and the MPXYD service on the host CPU.
 *
 ***********************************************************************/
#ifndef _DAPL_MIC_COMMON_H_
#define _DAPL_MIC_COMMON_H_

#include <sys/socket.h>
#include <netinet/in.h>

/***** MIC Indirect CM (MCM) protocol over IB fabrics *****/
#define DAT_MCM_VER 		1
#define DAT_MCM_UD_QKEY		0x78655322
#define DAT_MCM_PDATA_SIZE      64
#define DAT_MCM_PROXY_DATA	40
#define DAT_MCM_SEG_PO2		17
#define DAT_MCM_P2P_INLINE	96

#define ALIGN_64(o)  ((o + 64 - 1) & ~(64-1))
#define ALIGN_P64(o) ((((uintptr_t)o) + 64 - 1)& ~(64-1))
#define ALIGN_DOWN_64(o) ((o) & ~(64-1))
#define OFFSET_64(o) ((o) & (64-1))
#define ALIGN_PAGE(o)  ((o + 4096 - 1) & ~(4096-1))
#define ALIGN_UP_PPAGE(o) ((((uintptr_t)o) + 4096 - 1)& ~(4096-1))
#define ALIGN_DOWN_PPAGE(o) ((((uintptr_t)o)) & ~(4096-1))
#define ALIGN_64_PAD(o) (ALIGN_64(o) - (o))

static inline char * mcm_qp_state_str(IN int st)
{
	static char *qp_state[] = {
		"RESET",
		"INIT",
		"RTR",
		"RTS",
		"SQD",
		"SQE",
		"ERR"
	};
        return ((st < 0 || st > 6) ? "Invalid QP state?" : qp_state[st]);
}

typedef enum dat_mcm_op
{
	MCM_INVALID,
	MCM_REQ,
	MCM_REP,
	MCM_REJ_USER, /* user reject */
	MCM_REJ_CM,   /* cm reject */
	MCM_RTU,
	MCM_DREQ,
	MCM_DREP

} DAT_MCM_OP;

static inline char * mcm_op_str(IN int op)
{
	static char *ops[] = {
		"INVALID",
		"REQ",
		"REP",
		"REJ_USER",
		"REJ_CM",
		"RTU",
		"DREQ",
		"DREP",
	};
	return ((op < 1 || op > 7) ? "Invalid OP?" : ops[op]);
}

typedef enum dat_mcm_state
{
	MCM_INIT,
	MCM_LISTEN,
	MCM_CONN_PENDING,
	MCM_REP_PENDING,
	MCM_REP_RCV,
	MCM_ACCEPTING,
	MCM_ACCEPTING_DATA,
	MCM_ACCEPTED,
	MCM_REJECTING,
	MCM_REJECTED,
	MCM_CONNECTED,
	MCM_RELEASE,
	MCM_DISC_PENDING,
	MCM_DISCONNECTED,
	MCM_DESTROY,
	MCM_RTU_PENDING,
	MCM_DISC_RECV,
	MCM_FREE,

} DAT_MCM_STATE;

static inline char * mcm_state_str(IN int st)
{
	static char *state[] = {
		"INIT",
		"LISTEN",
		"CONN_PENDING",
		"REP_PENDING",
		"REP_RECV",
		"ACCEPTING",
		"ACCEPTING_DATA",
		"ACCEPTED",
		"REJECTING",
		"REJECTED",
		"CONNECTED",
		"RELEASE",
		"DISC_PENDING",
		"DISCONNECTED",
		"DESTROY",
		"RTU_PENDING",
		"DISC_RECV",
		"FREE"
        };
        return ((st < 0 || st > 17) ? "Invalid CM state?" : state[st]);
}

static inline char * mcm_ib_async_str(IN int st)
{
	static char *state[] = {
		"IBV_EVENT_CQ_ERR",
		"IBV_EVENT_QP_FATAL",
		"IBV_EVENT_QP_REQ_ERR",
		"IBV_EVENT_QP_ACCESS_ERR",
		"IBV_EVENT_COMM_EST",
		"IBV_EVENT_SQ_DRAINED",
		"IBV_EVENT_PATH_MIG",
		"IBV_EVENT_PATH_MIG_ERR",
		"IBV_EVENT_DEVICE_FATAL",
		"IBV_EVENT_PORT_ACTIVE",
		"IBV_EVENT_PORT_ERR",
		"IBV_EVENT_LID_CHANGE",
		"IBV_EVENT_PKEY_CHANGE",
		"IBV_EVENT_SM_CHANGE",
		"IBV_EVENT_SRQ_ERR",
		"IBV_EVENT_SRQ_LIMIT_REACHED",
		"IBV_EVENT_QP_LAST_WQE_REACHED",
		"IBV_EVENT_CLIENT_REREGISTER",
        };
        return ((st < 0 || st > 17) ? "Invalid IB async event?" : state[st]);
}

/* ep_map: mappings hint: node type and locality to device */
#define HOST_SOCK_DEV  1  /* host to HCA, any socket */
#define MIC_SSOCK_DEV  2  /* MIC to HCA, same socket */
#define MIC_XSOCK_DEV  3  /* MIC to HCA, cross socket */
#define MIC_FULL_DEV   4  /* MIC to HCA, full proxy offload, no direct verbs */

#define UND_EP(x) ((x)->ep_map <  1 || (x)->ep_map > 4)
#define HST_EP(x) ((x)->ep_map == HOST_SOCK_DEV)
#define MSS_EP(x) ((x)->ep_map == MIC_SSOCK_DEV)
#define MXS_EP(x) ((x)->ep_map == MIC_XSOCK_DEV)
#define MFO_EP(x) ((x)->ep_map == MIC_FULL_DEV)
#define MXF_EP(x) ((x)->ep_map == MIC_XSOCK_DEV || (x)->ep_map == MIC_FULL_DEV)

static inline char * mcm_map_str(IN uint8_t ep_map)
{
	static char *map[] = {
		"",
		"HST",
		"MSS",
		"MXS",
		"MFO"
	};
	return ((ep_map < 1 || ep_map > 4) ? "???" : map[ep_map]);
}

/* MCM address, 28 bytes */
typedef struct dat_mcm_addr
{
 	uint16_t	family;
	uint16_t	lid;
	uint32_t	qpn;
	uint8_t		gid[16];
	uint8_t		port;
	uint8_t		ep_map;
	uint8_t		sl;
	uint8_t		qp_type;
} __attribute__((packed)) dat_mcm_addr_t;

/* MCM message extended after existing fields, 256 bytes */
typedef struct dat_mcm_msg
{
	uint16_t		ver;
	uint16_t		op;
	uint16_t		sport; /* src cm port */
	uint16_t		dport; /* dst cm port */
	uint32_t		sqpn;  /* src cm qpn */
	uint32_t		dqpn;  /* dst cm qpn */
	uint16_t		p_size;
	uint32_t		s_id;  /* src pid */
	uint32_t		d_id;  /* dst pid */
	uint8_t			rd_in; /* atomic_rd_in */
	uint8_t			mtu;   /* mtu */
	uint8_t			rsvd[3];
	uint8_t			seg_sz; /* data segment size in power of 2 */
	dat_mcm_addr_t		saddr1;	/* QPt local,  MPXY or MCM on non-MIC node */
	dat_mcm_addr_t		saddr2; /* QPr local,  MIC  or MCM on non-MIC node or MPXY */
	dat_mcm_addr_t		daddr1;	/* QPt remote, MPXY or MCM on non-MIC node */
	dat_mcm_addr_t		daddr2; /* QPr remote, MIC  or MCM on non-MIC node or MPXY */
	uint8_t			p_data[DAT_MCM_PDATA_SIZE];
	uint8_t			p_proxy[DAT_MCM_PROXY_DATA];
	uint64_t		sys_guid; /* system image guid */

} __attribute__((packed)) dat_mcm_msg_t;

/* MCM message, 208 bytes */
typedef struct dat_mcm_msg_compat
{
	uint16_t		ver;
	uint16_t		op;
	uint16_t		sport; /* src cm port */
	uint16_t		dport; /* dst cm port */
	uint32_t		sqpn;  /* src cm qpn */
	uint32_t		dqpn;  /* dst cm qpn */
	uint16_t		p_size;
	uint32_t		s_id;  /* src pid */
	uint32_t		d_id;  /* dst pid */
	uint8_t			rd_in; /* atomic_rd_in */
	uint8_t			resv[5];/* Shadow QP's, 2 connections */
	dat_mcm_addr_t		saddr;	/* QPt local,  MPXY or MCM on non-MIC node */
	dat_mcm_addr_t		saddr2; /* QPr local,  MIC  or MCM on non-MIC node */
	dat_mcm_addr_t		daddr;	/* QPt remote, MPXY or MCM on non-MIC node */
	dat_mcm_addr_t		daddr2; /* QPr remote, MIC  or MCM on non-MIC node */
	uint8_t			p_data[DAT_MCM_PDATA_SIZE];

} __attribute__((packed)) dat_mcm_msg_compat_t;

/***** MIC Indirect Exchange (MIX) protocol over SCIF ****/

/* Revisions:
 * v1 - Initial release
 * v2 - Support 3 separate EP's per device (Operations/CM, unsolicited events, transmit)
 * v3 - reduce SGE from 7 to 4, add post_send inline support
 * v4 - pack all command structures, replace verbs wr/wc types with defined MIX types
 * v5 - CM services with proxy_in, private data
 */
#define DAT_MIX_VER 		5
#define DAT_MIX_INLINE_MAX 	256
#define DAT_MIX_RDMA_MAX       (8*1024*1024)
#define DAT_MIX_WR_MAX         500

typedef enum dat_mix_ops
{
	MIX_IA_OPEN = 2,
	MIX_IA_CLOSE,
	MIX_LISTEN,
	MIX_LISTEN_FREE,
	MIX_MR_CREATE,
	MIX_MR_FREE,
	MIX_QP_CREATE,
	MIX_QP_MODIFY,
	MIX_QP_FREE,
	MIX_CQ_CREATE,
	MIX_CQ_FREE,
	MIX_CQ_POLL,
	MIX_CQ_POLL_NOTIFY,
	MIX_CM_REQ,
	MIX_CM_REP,
	MIX_CM_ACCEPT,
	MIX_CM_REJECT,
	MIX_CM_RTU,
	MIX_CM_EST,
	MIX_CM_DISC,
	MIX_CM_DREP,
	MIX_CM_EVENT,
	MIX_DTO_EVENT,
	MIX_SEND,
	MIX_WRITE,
	MIX_PROV_ATTR,
	MIX_RECV,
	MIX_CM_REJECT_USER,
	MIX_PZ_CREATE,
	MIX_PZ_FREE,
	MIX_QUERY_DEVICE,
	MIX_QUERY_PORT,
	MIX_MMAP_ALLOC,
	MIX_MMAP_FREE,
	MIX_LAST_OP,	/* Keep last */

} dat_mix_ops_t;

static inline char * mix_op_str(IN int op)
{
	static char *mix_ops[] = {
		"",
		"",
		"IA_OPEN",
		"IA_CLOSE",
		"LISTEN",
		"LISTEN_FREE",
		"MR_CREATE",
		"MR_FREE",
		"QP_CREATE",
		"QP_MODIFY",
		"QP_FREE",
		"CQ_CREATE",
		"CQ_FREE",
		"CQ_POLL",
		"CQ_POLL_NOTIFY",
		"CM_REQ",
		"CM_REP",
		"CM_ACCEPT",
		"CM_REJECT",
		"CM_RTU",
		"CM_EST",
		"CM_DISC",
		"CM_DREP",
		"CM_EVENT",
		"DTO_EVENT",
		"POST_SEND",
		"POST_WRITE",
		"PROV_ATTR",
		"POST_RECV",
		"CM_REJECT_USER",
		"PZ_CREATE",
		"PZ_FREE",
		"QUERY_DEVICE",
		"QUERY_PORT",
		"MMAP_ALLOC",
		"MMAP_FREE",
	};
	return ((op < 2 || op >= MIX_LAST_OP) ? "Invalid OP?" : mix_ops[op]);
}

typedef enum dat_mix_op_flags
{
    MIX_OP_REQ    = 0x01,
    MIX_OP_RSP    = 0x02,
    MIX_OP_SYNC   = 0x04,
    MIX_OP_ASYNC  = 0x08,
    MIX_OP_INLINE = 0x10,
    MIX_OP_SET    = 0x20,
    MIX_OP_MTU    = 0x40,

} dat_mix_op_flags_t;

typedef enum dat_mix_op_status
{
    MIX_SUCCESS = 0,
    MIX_EFAULT,		/* internal error */
    MIX_ENOMEM,		/* no space */
    MIX_EINVAL,		/* invalid parameter */
    MIX_ENOTCONN,	/* no active RDMA channels */
    MIX_ENODEV,		/* no device available */
    MIX_ECONNRESET, 	/* RDMA channel reset */
    MIX_EBADF,		/* RDMA channel or CM id invalid */
    MIX_EAGAIN,		/* busy */
    MIX_EADDRINUSE,	/* port or address in use */
    MIX_ENETUNREACH,	/* remote address unreachable */
    MIX_ETIMEDOUT,	/* connection time out */
    MIX_EAFNOSUPPORT, 	/* invalid address */
    MIX_EPERM,		/* invalid permission */
    MIX_EALREADY,	/* invalid state */
    MIX_ECONNREFUSED, 	/* connection rejected */
    MIX_EISCONN,	/* already connected */
    MIX_EOVERFLOW,	/* length error */

} dat_mix_op_status_t;

/* MIX message header, 8 bytes */
typedef struct dat_mix_hdr
{
	uint8_t		ver; 		/* version */
	uint8_t		op; 		/* operation type */
	uint8_t		flags;		/* operation flags */
	uint8_t		status;		/* operation status */
	uint32_t	req_id;		/* operation id, multiple operations */

} __attribute__((packed)) dat_mix_hdr_t;

/**** MIX device attributes, 16 bytes  *****/
typedef struct dat_mix_dev_attr
{
	uint8_t		ack_timer;
	uint8_t		ack_retry;
	uint8_t		rnr_timer;
	uint8_t		rnr_retry;
	uint8_t		global;
	uint8_t		hop_limit;
	uint8_t		tclass;
	uint8_t		sl;
	uint8_t		mtu;
	uint8_t		rd_atom_in;
	uint8_t		rd_atom_out;
	uint8_t		pkey_idx;
	uint16_t	pkey;
	uint16_t	max_inline;

}  __attribute__((packed)) dat_mix_dev_attr_t;

#define DAT_MIX_MMAP_CAP ( 1 << 0 )

/**** MIX attributes, 120 bytes *****/
typedef struct dat_mix_prov_attr
{
	uint32_t		max_msg_sz;
	uint32_t		max_tx_dtos;
	uint32_t		max_rx_dtos;
	uint32_t		max_tx_pool;
	uint32_t		max_rx_pool;
	uint32_t		tx_segment_sz;
	uint32_t		rx_segment_sz;
	uint32_t		cm_retry;
	uint32_t		cm_disc_retry;
	uint32_t		cm_rep_time_ms;
	uint32_t		cm_rtu_time_ms;
	uint32_t		cm_drep_time_ms;
	uint32_t		log_level;
	uint32_t		counters;
	dat_mix_dev_attr_t	dev_attr;
	uint64_t		system_guid;
	uint8_t			gid_idx;
	uint32_t		cpu_model;
	uint32_t		cpu_family;
	uint8_t			cap;
	uint8_t			resv[30];
}  __attribute__((packed)) dat_mix_prov_attr_t;

/***** MIX open, device address info returned */
typedef struct dat_mix_open
{
	dat_mix_hdr_t		hdr;
	char			name[64];
	uint16_t		port;		/* ib physical port number */
	dat_mix_dev_attr_t	dev_attr;
	dat_mcm_addr_t		dev_addr;
}  __attribute__((packed)) dat_mix_open_t;

/***** MIX PZ, PZ handle info returned */
typedef struct dat_mix_pz
{
	dat_mix_hdr_t		hdr;
	uint64_t		ctx;   /* client handle from mic */
	uint64_t		ib_pd; /* IB PZ handle from proxy */
}  __attribute__((packed)) dat_mix_pz_t;

/***** MIX QUERY PORT info returned */
typedef struct dat_mix_port_attr
{
	dat_mix_hdr_t           hdr;
	uint64_t                gid_tbl_len;
	uint32_t                port_cap_flags;
	uint32_t                max_msg_sz;
	uint32_t                bad_pkey_cntr;
	uint32_t                qkey_viol_cntr;
	uint16_t                pkey_tbl_len;
	uint16_t                lid;
	uint16_t                sm_lid;
	uint8_t                 lmc;
	uint8_t                 max_vl_num;
	uint8_t                 sm_sl;
	uint8_t                 subnet_timeout;
	uint8_t                 init_type_reply;
	uint8_t                 active_width;
	uint8_t                 active_speed;
	uint8_t                 phys_state;
	uint8_t                 link_layer;
	uint8_t                 state;
	uint8_t                 max_mtu;
	uint8_t                 active_mtu;
}  __attribute__((packed)) dat_mix_port_attr_t;

/***** MIX get,get device attributes, 289 bytes */
typedef struct dat_mix_device_attr
{
dat_mix_hdr_t           hdr;
	char                    fw_ver[64];
	uint64_t                node_guid;
	uint64_t                sys_image_guid;
	uint64_t                max_mr_size;
	uint64_t                page_size_cap;
	uint64_t                max_qp;
	uint64_t                max_qp_wr;
	uint64_t                device_cap_flags;
	uint64_t                max_sge;
	uint64_t                max_sge_rd;
	uint64_t                max_cq;
	uint64_t                max_cqe;
	uint64_t                max_mr;
	uint64_t                max_pd;
	uint64_t                max_qp_rd_atom;
	uint64_t                max_ee_rd_atom;
	uint64_t                max_res_rd_atom;
	uint64_t                max_qp_init_rd_atom;
	uint64_t                max_ee_init_rd_atom;
	uint64_t                max_ee;
	uint64_t                max_rdd;
	uint64_t                max_mw;
	uint64_t                max_raw_ipv6_qp;
	uint64_t                max_raw_ethy_qp;
	uint64_t                max_mcast_grp;
	uint64_t                max_mcast_qp_attach;
	uint64_t                max_total_mcast_qp_attach;
	uint64_t                max_ah;
	uint64_t                max_fmr;
	uint64_t                max_map_per_fmr;
	uint64_t                max_srq;
	uint64_t                max_srq_wr;
	uint64_t                max_srq_sge;
	uint32_t                vendor_id;
	uint32_t                vendor_part_id;
	uint32_t                hw_ver;
	uint16_t                max_pkeys;
	uint8_t                 local_ca_ack_delay;
	uint8_t                 phys_port_cnt;
	uint8_t                 atomic_cap;
}  __attribute__((packed)) dat_mix_device_attr_t;

/***** MIX get,set attributes, 128 bytes */
typedef struct dat_mix_attr
{
	dat_mix_hdr_t		hdr;
	dat_mix_prov_attr_t	attr;

}  __attribute__((packed)) dat_mix_attr_t;

/***** MIX memory registration, IB and SCIF *****/
typedef struct dat_mix_mr
{
	dat_mix_hdr_t		hdr;
	uint64_t		ctx;
	uint32_t		mr_id;
	uint32_t		mr_len;
	uint32_t		ib_lkey; 	/* ib rkey */
	uint32_t		ib_rkey; 	/* ib rkey */
	uint64_t		ib_addr;	/* ib addr mapping */
	uint64_t		sci_addr; 	/* scif addr, must be page aligned */
	uint32_t		sci_off; 	/* scif offset to starting address */

} __attribute__((packed)) dat_mix_mr_t;

typedef struct dat_mix_mr_compat
{
	dat_mix_hdr_t		hdr;
	uint32_t		mr_id;
	uint32_t		len;
	uint64_t		off;
	uint64_t		ctx;

} __attribute__((packed)) dat_mix_mr_compat_t;

/***** MIX listen, status returned, no data *****/
typedef struct dat_mix_listen
{
	dat_mix_hdr_t		hdr;
	uint64_t		sp_ctx;
	uint16_t 		sid;
	uint16_t		backlog;

}  __attribute__((packed)) dat_mix_listen_t;

/***** MIX create QP, 52 bytes *****/
typedef struct dat_mix_qp_attr
{
	uint8_t		qp_type;
	uint8_t		state;
	uint8_t		cur_state;
	uint8_t		sq_sig_all;
	uint32_t	qp_num;
	uint32_t	qkey;
	uint32_t	max_send_wr;
	uint32_t	max_recv_wr;
	uint32_t	max_send_sge;
	uint32_t	max_recv_sge;
	uint32_t	max_inline_data;
	uint32_t	qp_id;
	uint32_t	scq_id;
	uint32_t	rcq_id;
	uint64_t	ctx;

}  __attribute__((packed)) dat_mix_qp_attr_t;

/*
 * For initial prototyping write streams we don't have many
 * completions. SCIF should be 2x speeds so once we pipeline
 * it will keep up with IB speeds.
 */
typedef struct dat_mix_qp
{
	dat_mix_hdr_t		hdr;
	dat_mix_qp_attr_t	qp_t;	/* on Proxy */
	dat_mix_qp_attr_t	qp_r;	/* on MIC */
	uint64_t		m_off;	/* SCIF DMA buffer pool */
	uint64_t		wr_off;	/* SCIF work request buffer pool */
	uint32_t		m_len;	/* size */
	uint32_t		m_seg;	/* segment size */
	uint32_t		wr_len;	/* size */
	uint32_t		m_inline; /* mpxyd inline threshold for SCIF dma */

}  __attribute__((packed)) dat_mix_qp_t;

/***** MIX CQ operations, create, free, poll, event *****/
typedef struct dat_mix_cq
{
	dat_mix_hdr_t		hdr;
	uint64_t		cq_ctx;
	uint32_t		cq_len;
	uint32_t		cq_id;
	uint64_t		wr_id;
	uint32_t		status;
	uint32_t		opcode;
	uint32_t		vendor_err;
	uint32_t		byte_len;
	uint32_t		qp_num;
	uint32_t		src_qp;
	uint32_t		wc_flags;

}  __attribute__((packed)) dat_mix_cq_t;

typedef struct dat_mix_cm
{
	dat_mix_hdr_t		hdr;
	uint64_t		sp_ctx;
	uint64_t		cm_ctx;
	uint32_t		cm_id;
	uint32_t		qp_id;
	dat_mcm_msg_t		msg;

} dat_mix_cm_t;

typedef struct dat_mix_cm_compat
{
	dat_mix_hdr_t		hdr;
	uint64_t		sp_ctx;
	uint64_t		cm_ctx;
	uint32_t		cm_id;
	uint32_t		qp_id;
	dat_mcm_msg_compat_t	msg;

} dat_mix_cm_compat_t;

typedef struct dat_mix_cm_event
{
	dat_mix_hdr_t		hdr;
	uint64_t		cm_ctx;
	uint64_t		qp_ctx;
	uint32_t		cm_id;
	uint32_t		qp_id;
	uint32_t		event;

}  __attribute__((packed)) dat_mix_cm_event_t;

typedef struct dat_mix_wc
{
	uint64_t	wr_id;
	uint32_t	status;
	uint32_t	opcode;
	uint32_t	vendor_err;
	uint32_t	byte_len;
	uint32_t	imm_data;	/* in network byte order */
	uint32_t	qp_num;
	uint32_t	src_qp;
	uint32_t	wc_flags;
	uint16_t	pkey_index;
	uint16_t	slid;
	uint8_t		sl;
	uint8_t		dlid_path_bits;
}  __attribute__((packed)) dat_mix_wc_t;

typedef struct dat_mix_sge {
	uint64_t		addr;
	uint32_t		length;
	uint32_t		lkey;
} dat_mix_sge_t;

typedef struct dat_mix_wr {
	uint64_t		wr_id;
	uint32_t		num_sge;
	uint32_t		opcode;
	uint32_t		send_flags;
	uint32_t		imm_data;	/* in network byte order */
	union {
		struct {
			uint64_t	remote_addr;
			uint32_t	rkey;
		} rdma;
		struct {
			uint64_t	remote_addr;
			uint64_t	compare_add;
			uint64_t	swap;
			uint32_t	rkey;
		} atomic;
		struct {
			struct ibv_ah  *ah;
			uint32_t	remote_qpn;
			uint32_t	remote_qkey;
		} ud;
	} wr;
}  __attribute__((packed)) dat_mix_wr_t;

#define DAT_MIX_WC_MAX 4
typedef struct dat_mix_dto_comp
{
	dat_mix_hdr_t		hdr;
	uint64_t		cq_ctx;
	uint32_t		cq_id;
	uint32_t		wc_cnt;
	struct dat_mix_wc	wc[DAT_MIX_WC_MAX];

}  __attribute__((packed)) dat_mix_dto_comp_t;

#define DAT_MIX_SGE_MAX 4
typedef struct dat_mix_sr
{
	dat_mix_hdr_t		hdr;
	uint64_t		qp_ctx;
	uint32_t		qp_id;
	uint32_t		len;
	struct dat_mix_wr	wr;
	struct dat_mix_sge	sge[DAT_MIX_SGE_MAX];

}  __attribute__((packed)) dat_mix_sr_t;

/* DAT_MIX_MMAP_CAP support: fast post_send via scif MMAP */
typedef struct dat_mix_mmap_addr
{
	dat_mix_hdr_t		hdr;
	off_t			addr;
}  __attribute__((packed)) dat_mix_mmap_addr_t;

#define DAT_MIX_MMAP_WR_MAX 8

typedef struct dat_mix_mmap_wr
{
	dat_mix_sr_t msg;
	uint8_t inline_data[DAT_MIX_INLINE_MAX];
	volatile uint32_t flags;
	uint8_t tpad[ALIGN_64_PAD(sizeof(dat_mix_sr_t) + DAT_MIX_INLINE_MAX + sizeof(uint32_t))];

}  __attribute__((packed)) dat_mix_mmap_wr_t;

typedef union dat_mix_msg
{
	dat_mix_open_t		op;
	dat_mix_dev_attr_t	dev;
	dat_mix_prov_attr_t	prv;
	dat_mix_mr_t		mr;
	dat_mix_listen_t	ls;
	dat_mix_qp_t		qp;
	dat_mix_cq_t		cq;
	dat_mix_cm_t		cm;
	dat_mix_cm_compat_t	cm_comp;
	dat_mix_wc_t		wc;
	dat_mix_wr_t		wr;
	dat_mix_dto_comp_t	dto;
	dat_mix_sr_t		sr;
	dat_mix_mmap_addr_t 	mm_addr;
	dat_mix_mmap_wr_t 	mm_wr;
} DAT_MIX_MSG;

#define DAT_MIX_MSG_MAX  sizeof(DAT_MIX_MSG)

/*
 * MCM to MPXYD: work request and completion definitions
 *
 * 	Messaging Protocol between MCM Proxy-out and Proxy-in service agents
 * 	- WR and WC management vi IB RDMA write_imm and RDMA reads
 * 	- WR and WC written directly from remote proxy peer agent,
 * 	- Proxy-in buffer management on receive side, IB RR
 * 	- Proxy-out buffer management on send side
 * 		IB RW directly to user buffer if peer is MIC same socket
 * 		IB RW_imm to PI WR, PI RR, scif_writeto if MIC is remote socket
 *
 */
#if __BYTE_ORDER == __BIG_ENDIAN
#define htonll(x) (x)
#define ntohll(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define htonll(x)  bswap_64(x)
#define ntohll(x)  bswap_64(x)
#endif

/* WRC (work request/completion) imm_data definition, qdepth limits of 16 bits  */
#define WRC_MAX_QLEN 1 << 16;
#define MCM_WRC_QLEN 512

/* data types, WR or WC */
#define M_WR_TYPE 1
#define M_WC_TYPE 2

/* WR flags */
#define M_WR_FS 1
#define M_WR_LS 2

#define WRC_ID_DATA(x)    ((x) & 0x0000ffff)
#define WRC_TYPE_DATA(x)  (((x) >> 16) & 0x000000ff)
#define WRC_FLAGS_DATA(x) (((x) >> 24) & 0x000000ff)

/* wr aligned on 64 bytes, use 4 lower bits for type id */
#define WRID_TX_RW	0x1 /* proxy out, m_wr type, RW */
#define WRID_TX_RW_IMM  0x2 /* proxy out, m_wr type, RW_imm op  */
#define WRID_RX_RR     	0x3 /* proxy in,  m_wr_rx type, RR op  */
#define WRID_RX_RW_IMM  0x4 /* proxy in,  m_wr_rx type, RW_immed op  */
#define WRID_MASK 0xfffffffffffffff0
#define WRID_SET(x,y) (((uint64_t)(x) | (uint64_t)(y)))
#define WRID_TYPE(x) ((x & ~WRID_MASK))
#define WRID_ADDR(x) ((x &  WRID_MASK))

typedef struct wrc_idata {

	uint16_t id;		/* work request or completion slot */
	uint8_t type;		/* data types, WR, WC, etc */
	uint8_t flags;		/* flags */

} __attribute__((packed)) wrc_idata_t;

enum mcm_wr_flags {
	M_SEND_POSTED		= 1 << 0, /* m_wr already posted */
	M_SEND_CN_SIG		= 1 << 1, /* m_wr consumer signaled, IB completion */
	M_SEND_CN_EAGER_SIG 	= 1 << 2, /* m_wr consumer eager signaled, SCIF read completion */
	M_SEND_MP_SIG		= 1 << 3, /* m_wr mpxyd signaled, segmentation, manage proxy buf/wr resources */

	M_SEND_FS		= 1 << 4, /* m_wr - first segment */
	M_SEND_LS		= 1 << 5, /* m_wr - last segment */
	M_SEND_PI		= 1 << 6, /* m_wr - forwarded to proxy in service */
	M_SEND_INLINE		= 1 << 7, /* m_wr - data in cmd msg, no scif_readfrom  */

	M_READ_PAUSED		= 1 << 8, /* m_wr_rx waiting for proxy buffer */
	M_RECV_PAUSED		= 1 << 9, /* m_wr_rx waiting for posted rcv message */
	M_READ_POSTED		= 1 << 10, /* m_wr_rx ibv posted */
	M_READ_DONE		= 1 << 11, /* m_wr_rx ibv completed */

	M_READ_WRITE_TO		= 1 << 12, /* m_wr_rx read data forwarded to MIC scif_writeto */
	M_READ_WRITE_TO_DONE	= 1 << 13, /* m_wr_rx read data forwarded to MIC scif_writeto */
	M_READ_CN_SIG		= 1 << 14, /* m_wr_rx consumer signaled, IB completion needed */
	M_READ_MP_SIG		= 1 << 15, /* m_wr_rx mpxyd signaled, segmentation, manage proxy buf/wr resources */

	M_READ_FROM_DONE	= 1 << 16, /* m_wr mpxyd read_from_done, ready for posting */
	M_SEND_DIRECT		= 1 << 17, /* m_wr SEND direct from host memory, no proxy out buffer */
	M_PROXY_INLINE		= 1 << 18, /* m_wr contains the data */
};

/* 80 bytes */
typedef struct mcm_sr {
	uint64_t		wr_id;			/* from consumer post_recv */
	uint32_t		len;			/* total len */
	uint32_t		num_sge;		/* number of sglist entries, max 4 */
	uint32_t		m_idx;			/* proxy buffer, src */
	uint32_t		w_idx;			/* wr_rx WR idx, data xfer in process */
	uint32_t		s_idx;			/* my idx, sr_tl update */
	struct dat_mix_sge   	sg[DAT_MIX_SGE_MAX];	/* consumer buffer on MIC, off_t */
} mcm_sr_t;

/* 128 bytes */
typedef struct mcm_wr {
	struct ibv_send_wr	wr;
	struct ibv_sge	   	sg[DAT_MIX_SGE_MAX];
	uint64_t		org_id;
	uint64_t		context;
	uint32_t		m_idx;
	uint32_t		w_idx;
	uint32_t		flags;
} mcm_wr_t;

/* DAT_MCM_PROXY_DATA private data max (40 bytes), Proxy-in WR and WC info exchange */
typedef struct mcm_wrc_info {
	uint64_t	wr_addr;
	uint32_t	wr_rkey;
	uint32_t	wr_len;
	uint16_t	wr_sz;
	uint16_t	wr_end;
	uint64_t	wc_addr;
	uint32_t	wc_rkey;
	uint32_t	wc_len;
	uint16_t	wc_sz;
	uint16_t	wc_end;
} __attribute__((packed)) mcm_wrc_info_t;

/* WR: 256 bytes, direct RDMA write from remote Proxy-in service */
typedef struct mcm_wr_rx {
	struct dat_mix_wr	wr;
	struct dat_mix_sge   	sg[DAT_MIX_SGE_MAX];
	uint64_t		org_id;
	uint64_t		context;
	uint32_t		m_idx;
	uint32_t		w_idx;
	uint32_t		s_idx;
	uint32_t		flags;
	uint32_t		time;
	uint32_t		qcnt;
	char			inline_data[DAT_MCM_P2P_INLINE];
} __attribute__((packed)) mcm_wr_rx_t;

#define MCM_WR_RX_NO_DATA	(sizeof(mcm_wr_rx_t) - DAT_MCM_P2P_INLINE)

/* WC: 80 bytes, direct RDMA write from remote Proxy-in service */
typedef struct mcm_wc_rx {
	struct dat_mix_wc	wc;
	uint64_t		org_id;
	uint64_t		context;
	uint32_t		wr_idx;		/* proxy-out, proxy-in WR idx */
	uint32_t		wr_tl;		/* proxy-in WR tl update  */
	uint32_t		flags;
	uint8_t			rsv[6];
} __attribute__((packed)) mcm_wc_rx_t;

/* Helper functions */

/* construct WRC info to msg->p_proxy, network order, during outbound CM request or reply */
static inline void mcm_hton_wrc(mcm_wrc_info_t *dst, mcm_wrc_info_t *src)
{
	if (src->wr_addr) {
		dst->wr_addr = htonll(src->wr_addr);
		dst->wr_rkey = htonl(src->wr_rkey);
		dst->wr_len = htonl(src->wr_len);
		dst->wr_sz = htons(src->wr_sz);
		dst->wr_end = htons(src->wr_end);
	}
	if (src->wc_addr) {
		dst->wc_addr = htonll(src->wc_addr);
		dst->wc_rkey = htonl(src->wc_rkey);
		dst->wc_len = htonl(src->wc_len);
		dst->wc_sz = htons(src->wc_sz);
		dst->wc_end = htons(src->wc_end);
	}
}

/* get WRC info from msg->p_proxy, network order, during inbound CM request or reply */
static inline void mcm_ntoh_wrc(mcm_wrc_info_t *dst, mcm_wrc_info_t *src)
{
	dst->wr_addr = ntohll(src->wr_addr);
	dst->wr_rkey = ntohl(src->wr_rkey);
	dst->wr_len = ntohl(src->wr_len);
	dst->wr_sz = ntohs(src->wr_sz);
	dst->wr_end = ntohs(src->wr_end);

	dst->wc_addr = ntohll(src->wc_addr);
	dst->wc_rkey = ntohl(src->wc_rkey);
	dst->wc_len = ntohl(src->wc_len);
	dst->wc_sz = ntohs(src->wc_sz);
	dst->wc_end = ntohs(src->wc_end);
}

/* construct rx_wr, network order, to send to remote proxy-in service */
static inline void mcm_hton_wr_rx(struct mcm_wr_rx *m_wr_rx, struct mcm_wr *m_wr, int wc_tl)
{
	int i;

	memset((void*)m_wr_rx, 0, MCM_WR_RX_NO_DATA);
	m_wr_rx->org_id = (uint64_t) htonll((uint64_t)m_wr); /* proxy_out WR */
	m_wr_rx->flags = htonl(m_wr->flags);
	m_wr_rx->w_idx = htonl(wc_tl); /* snd back wc tail */
	m_wr_rx->wr.num_sge = htonl(m_wr->wr.num_sge);
	m_wr_rx->wr.opcode = htonl(m_wr->wr.opcode);
	m_wr_rx->wr.send_flags = htonl(m_wr->wr.send_flags);
	m_wr_rx->wr.imm_data = htonl(m_wr->wr.imm_data);
	m_wr_rx->wr.wr.rdma.remote_addr = htonll(m_wr->wr.wr.rdma.remote_addr); /* final dst on MIC */
	m_wr_rx->wr.wr.rdma.rkey = htonl(m_wr->wr.wr.rdma.rkey);

	for (i=0;i<m_wr->wr.num_sge;i++) {
		m_wr_rx->sg[i].addr = htonll(m_wr->sg[i].addr); /* proxy-out buffer */
		m_wr_rx->sg[i].lkey = htonl(m_wr->sg[i].lkey);
		m_wr_rx->sg[i].length = htonl(m_wr->sg[i].length);
	}
}

/* convert rx wr, arrived across fabric from remote proxy-out service in network order */
static inline void mcm_ntoh_wr_rx(struct mcm_wr_rx *m_wr_rx)
{
	int i;

	m_wr_rx->org_id = ntohll(m_wr_rx->org_id);  /* proxy_out WR */
	m_wr_rx->flags = ntohl(m_wr_rx->flags);
	m_wr_rx->w_idx = ntohl(m_wr_rx->w_idx);  /* WC tail update from proxy_out */
	m_wr_rx->wr.num_sge = ntohl(m_wr_rx->wr.num_sge);
	m_wr_rx->wr.opcode = ntohl(m_wr_rx->wr.opcode);
	m_wr_rx->wr.send_flags = ntohl(m_wr_rx->wr.send_flags);
	m_wr_rx->wr.imm_data = ntohl(m_wr_rx->wr.imm_data);
	m_wr_rx->wr.wr.rdma.remote_addr = ntohll(m_wr_rx->wr.wr.rdma.remote_addr); /* final dest on MIC */
	m_wr_rx->wr.wr.rdma.rkey = ntohl(m_wr_rx->wr.wr.rdma.rkey);

	for (i=0;i<m_wr_rx->wr.num_sge;i++) {
		m_wr_rx->sg[i].addr =  ntohll(m_wr_rx->sg[i].addr); /* proxy-out buffer segment, ibv */
		m_wr_rx->sg[i].lkey = ntohl(m_wr_rx->sg[i].lkey);
		m_wr_rx->sg[i].length = ntohl(m_wr_rx->sg[i].length);
	}

	/* For HST->MXS sg[0-3] can be direct SRC segments for RR, all others will be 1 seg */
	/* sg[1] == proxy-in buffer segment, ibv */
	/* sg[2] == proxy-in scif sendto src segment, scif offset */
	/* sg[3] == proxy-in scif sendto dst segment, scif offset */
}

/* construct a rx_wc in network order to send to remote proxy-in service */
static inline void mcm_hton_wc_rx(struct mcm_wc_rx *m_wc_rx, struct mcm_wr_rx *m_wr_rx, int wr_tl, int status)
{
	memset((void*)m_wc_rx, 0, sizeof(*m_wc_rx));
	m_wc_rx->wr_idx = htonl(m_wr_rx->w_idx); /* proxy-in WR idx == proxy-out WR idx */
	m_wc_rx->wr_tl = htonl(wr_tl); 		/* proxy-in WR tail update, moves slower than proxy-out */
	m_wc_rx->flags = htonl(m_wr_rx->flags);
	m_wc_rx->wc.wr_id = htonll(m_wr_rx->org_id);
	m_wc_rx->wc.status = htonl(status);
	m_wc_rx->wc.byte_len = htonl(m_wr_rx->sg[0].length);
	if (m_wr_rx->wr.opcode == IBV_WR_RDMA_WRITE_WITH_IMM) {
		m_wc_rx->wc.wc_flags = htonl(IBV_WC_WITH_IMM);
		m_wc_rx->wc.opcode = htonl(IBV_WC_RDMA_WRITE);
	}
	else if (m_wr_rx->wr.opcode == IBV_WR_RDMA_WRITE)
		m_wc_rx->wc.opcode = htonl(IBV_WC_RDMA_WRITE);
	else
		m_wc_rx->wc.opcode = htonl(IBV_WC_SEND);
}

/* convert rx wc, arrived across fabric from remote proxy-in service in network order */
static inline void mcm_ntoh_wc_rx(struct mcm_wc_rx *m_wc_rx)
{
	m_wc_rx->wr_idx = ntohl(m_wc_rx->wr_idx);
	m_wc_rx->wr_tl = ntohl(m_wc_rx->wr_tl);
	m_wc_rx->flags = ntohl(m_wc_rx->flags);
	m_wc_rx->wc.wr_id = ntohll(m_wc_rx->wc.wr_id);
	m_wc_rx->wc.status = ntohl(m_wc_rx->wc.status);
	m_wc_rx->wc.byte_len = ntohl(m_wc_rx->wc.byte_len);
	m_wc_rx->wc.opcode = ntohl(m_wc_rx->wc.opcode);
	m_wc_rx->wc.wc_flags = ntohl(m_wc_rx->wc.wc_flags);
}

static inline void mcm_const_mix_wr(struct dat_mix_wr *mwr, struct ibv_send_wr *iwr)
{
	memset((void*)mwr, 0, sizeof(*mwr));
	mwr->wr_id = iwr->wr_id;
	mwr->num_sge = iwr->num_sge;
	mwr->opcode = iwr->opcode;
	mwr->send_flags = iwr->send_flags;
	mwr->imm_data = iwr->imm_data;
	mwr->wr.rdma.remote_addr = iwr->wr.rdma.remote_addr;
	mwr->wr.rdma.rkey = iwr->wr.rdma.rkey;
}

static inline void mcm_const_ib_wc(struct ibv_wc *iwc, struct dat_mix_wc *mwc, int entries)
{
	int i;

	for (i=0;i<entries;i++) {
		memset((void*)&iwc[i].wr_id, 0, sizeof(*iwc));
		iwc[i].wr_id = mwc[i].wr_id;
		iwc[i].status = mwc[i].status;
		iwc[i].opcode = mwc[i].opcode;
		iwc[i].vendor_err = mwc[i].vendor_err;
		iwc[i].byte_len = mwc[i].byte_len;
		iwc[i].imm_data = mwc[i].imm_data;
		iwc[i].qp_num = mwc[i].qp_num;
		iwc[i].src_qp = mwc[i].src_qp;
		iwc[i].wc_flags = mwc[i].wc_flags;
		iwc[i].pkey_index = mwc[i].pkey_index;
		iwc[i].slid = mwc[i].slid;
		iwc[i].sl = mwc[i].sl;
		iwc[i].dlid_path_bits = mwc[i].dlid_path_bits;
	}
}

#endif 	/* _DAPL_MIC_COMMON_H_ */
