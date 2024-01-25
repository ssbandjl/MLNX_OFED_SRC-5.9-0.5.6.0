
/*
 * Copyright (c) 2005-2007 Intel Corporation. All rights reserved.
 * Copyright (c) 2002, Network Appliance, Inc. All rights reserved. 
 * 
 * This Software is licensed under the terms of the "Common Public
 * License" a copy of which is in the file LICENSE.txt in the root
 * directory. The license is also available from the Open Source
 * Initiative, see http://www.opensource.org/licenses/cpl.php.
 *
 */

/**********************************************************************
 * 
 * MODULE: dapl_ibal_util.h
 *
 * PURPOSE: Utility defs & routines for access to openib-windows IBAL APIs
 *
 * $Id: dapl_ibal_util.h 33 2005-07-11 19:51:17Z ftillier $
 *
 **********************************************************************/

#ifndef _DAPL_IBAL_UTIL_H_
#define _DAPL_IBAL_UTIL_H_

#include <iba/ib_al.h>
#include <complib/cl_spinlock.h>
#include <complib/cl_qlist.h>
#include <complib/cl_atomic.h>

#ifdef DAT_EXTENSIONS
#include <dat2\dat_ib_extensions.h>
#endif

/*
 * Typedefs to map IBAL types to more generic 'ib' types
 */
#ifdef SOCK_CM
typedef  struct ib_cm_handle           *dp_ib_cm_handle_t;
typedef  struct ib_cm_handle           *ib_cm_srvc_handle_t;
#else

enum dapl_ibal_cm_state
{
	IBAL_CM_CONNECT,
	IBAL_CM_DREQ,
	IBAL_CM_DISCONNECT
};

/* EP-CM linking requires list_entry, protected ref counting */
typedef struct dapl_ibal_cm
{ 
	struct dapl_llist_entry	list_entry;
	DAPL_OS_LOCK		lock;
	int			ref_count;
	DAT_SOCK_ADDR6		dst_ip_addr; 
	ib_cm_handle_t		ib_cm;  /* h_al, h_qp, cid */
	DAPL_EP 		*ep;
	enum dapl_ibal_cm_state	state;

} dapl_ibal_cm_t;

typedef  dapl_ibal_cm_t                *dp_ib_cm_handle_t;
typedef  ib_listen_handle_t            ib_cm_srvc_handle_t;

/* EP-CM linking prototypes */
extern void dapls_cm_acquire(dp_ib_cm_handle_t cm_ptr);
extern void dapls_cm_release(dp_ib_cm_handle_t cm_ptr);
extern void dapls_cm_free(dp_ib_cm_handle_t cm_ptr);
extern dp_ib_cm_handle_t ibal_cm_alloc(void);

#endif

typedef  ib_net64_t                    IB_HCA_NAME;
typedef  ib_ca_handle_t                ib_hca_handle_t;
typedef  DAT_PVOID                     ib_cqd_handle_t;
typedef  ib_async_event_rec_t          ib_error_record_t;
typedef  ib_wr_type_t                  ib_send_op_type_t;
typedef  ib_wc_t                       ib_work_completion_t;
typedef  uint32_t                      ib_hca_port_t;
typedef  uint32_t                      ib_uint32_t;
typedef  ib_local_ds_t                 ib_data_segment_t;

typedef  unsigned __int3264            cl_dev_handle_t;


typedef void (*ib_async_handler_t)(
    IN    ib_hca_handle_t    ib_hca_handle,
    IN    ib_error_record_t  *err_code,
    IN    void               *context);

typedef void (*ib_async_qp_handler_t)(
    IN    ib_hca_handle_t    ib_hca_handle,
    IN    ib_qp_handle_t     ib_qp_handle,
    IN    ib_error_record_t  *err_code,
    IN    void               *context);

typedef void (*ib_async_cq_handler_t)(
    IN    ib_hca_handle_t    ib_hca_handle,
    IN    ib_cq_handle_t     ib_cq_handle,
    IN    ib_error_record_t  *err_code,
    IN    void               *context);

typedef ib_net64_t   ib_guid_t;
typedef ib_net16_t   ib_lid_t;
typedef boolean_t    ib_bool_t;

typedef struct _GID
{
    uint64_t gid_prefix;
    uint64_t guid;
} GID;

typedef enum 
{
    IB_CME_CONNECTED,
    IB_CME_DISCONNECTED,
    IB_CME_DISCONNECTED_ON_LINK_DOWN,
    IB_CME_CONNECTION_REQUEST_PENDING,
    IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA,
    IB_CME_DESTINATION_REJECT,
    IB_CME_DESTINATION_REJECT_PRIVATE_DATA,
    IB_CME_DESTINATION_UNREACHABLE,
    IB_CME_TOO_MANY_CONNECTION_REQUESTS,
    IB_CME_LOCAL_FAILURE,
    IB_CME_REPLY_RECEIVED,
    IB_CME_REPLY_RECEIVED_PRIVATE_DATA,
    IB_CM_LOCAL_FAILURE
} ib_cm_events_t;


typedef enum
{
    IB_NOTIFY_ON_NEXT_COMP,
    IB_NOTIFY_ON_SOLIC_COMP
} ib_notification_type_t;

typedef struct _ib_hca_name
{
    DAT_NAME_PTR hca_name[DAT_NAME_MAX_LENGTH];
} ib_hca_name_t;


#define          IB_INVALID_HANDLE             NULL
#define          true                          TRUE
#define          false                         FALSE

#define          IB_MAX_REQ_PDATA_SIZE      92
#define          IB_MAX_REP_PDATA_SIZE      196
#define          IB_MAX_REJ_PDATA_SIZE      148
#define          IB_MAX_DREQ_PDATA_SIZE     220
#define          IB_MAX_DREP_PDATA_SIZE     224


/* Resource Not Ready
	1-6 is an actual retry count which is decremented to zero before
        an error condition is set.
    7 is 'magic' in that it implies Infinite retry, just keeps trying.
*/
#define		IB_RNR_RETRY_CNT   7

/*
IB 1.2 spec, page 331, table 45, RNR NAK timeout encoding (5-bits)
 
00000=655.36ms(milliseconds)
00001=0.01ms
00010=0.02ms
00011=0.03ms
00100=0.04ms
00101=0.06ms
00110=0.08ms
00111=0.12ms

11100=163.84ms 28d
11101=245.76ms 29d
11110=327.68ms 30d
11111=491.52ms 31d
*/
#define		IB_RNR_NAK_TIMEOUT   0


typedef void
(*dapl_ibal_pfn_destructor_t)(
    IN    void*    context );

typedef struct _dapl_ibal_refs
{
    atomic32_t                      count;        // number of references
    void*                         context;     // context for destructor
    dapl_ibal_pfn_destructor_t    destructor;   // called when reference goes to zero

} dapl_ibal_refs_t;


typedef struct _dapl_ibal_root
{
    ib_al_handle_t        h_al;        // handle to Access Layer
    cl_spinlock_t         ca_lock;     // CA list lock
    cl_qlist_t            ca_head;     // list head of CAs
    boolean_t             shutdown;    // when true, driver is shutting down
    boolean_t             initialized;    // when true, lib is initialized 

} dapl_ibal_root_t;


typedef struct _dapl_ibal_ca
{
    cl_list_item_t    next;        // peer CA list
    ib_ca_handle_t    h_ca;        // handle to open CA
    ib_ca_attr_t      *p_ca_attr;  // CA attributes
    uint32_t          ca_attr_size;// size of ca attribute
    dapl_ibal_refs_t  refs;        // reference counting
    cl_spinlock_t     port_lock;   // port list lock
    cl_qlist_t        port_head;   // port list head for this CA
    cl_spinlock_t     evd_cb_lock; // EVD async error cb list lock
    cl_qlist_t        evd_cb_head; // EVD async error cb list head for this CA
    cl_dev_handle_t   mlnx_device;
    DAT_PVOID         *ia_ptr;     // hook for CA async callbacks
} dapl_ibal_ca_t;


typedef struct _dapl_ibal_port
{
    cl_list_item_t    next;            // peer CA list
    dapl_ibal_ca_t    *ca;             // pointer to parent CA
    ib_port_attr_t    *p_attr;         // port attributes
    dapl_ibal_refs_t  refs;            // reference counting
} dapl_ibal_port_t;

typedef struct _dapl_ibal_evd_cb
{
    cl_list_item_t     next;        // peer CA list
    ib_async_handler_t pfn_async_err_cb;
    ib_async_qp_handler_t  pfn_async_qp_err_cb;
    ib_async_cq_handler_t  pfn_async_cq_err_cb;
    void               *context;
} dapl_ibal_evd_cb_t;

/*
 * Definitions to map DTO OPs to IBAL Work-Request ops.
 */
#define    OP_BAD_OPCODE      0
#define    OP_RDMA_READ       WR_RDMA_READ
#define    OP_RDMA_WRITE      WR_RDMA_WRITE
#define    OP_SEND            WR_SEND
#define    OP_COMP_AND_SWAP   WR_COMPARE_SWAP
#define    OP_FETCH_AND_ADD   WR_FETCH_ADD

#define    OP_RECEIVE         8		/* (8)  */
#define    OP_BIND_MW         9		/* no-equivalent */
#define    OP_RDMA_WRITE_IMM  10	/* RDMA_WRITE+Immediate data */
#define    OP_RECEIVE_IMM     11	/* no-equivalent */

/*
 * Definitions to map QP state
 */
#define IB_QP_STATE_RESET    IB_QPS_RESET
#define IB_QP_STATE_INIT     IB_QPS_INIT
#define IB_QP_STATE_RTR      IB_QPS_RTR
#define IB_QP_STATE_RTS      IB_QPS_RTS
#define IB_QP_STATE_SQE      IB_QPS_SQERR
#define IB_QP_STATE_SQD      IB_QPS_SQD
#define IB_QP_STATE_ERROR    IB_QPS_ERROR

/*
 * Definitions to map Memory OPs
 */
#define IB_ACCESS_LOCAL_WRITE      IB_AC_LOCAL_WRITE
#define IB_ACCESS_REMOTE_READ      IB_AC_RDMA_READ
#define IB_ACCESS_REMOTE_WRITE     IB_AC_RDMA_WRITE
#define IB_ACCESS_REMOTE_ATOMIC    IB_AC_ATOMIC
#define IB_ACCESS_MEM_WINDOW_BIND  IB_AC_MW_BIND

/*
 * CQE status 
 */
enum _dapl_comp_status
{
	IB_COMP_ST_SUCCESS              = IB_WCS_SUCCESS,
	IB_COMP_ST_LOCAL_LEN_ERR	= IB_WCS_LOCAL_LEN_ERR,
	IB_COMP_ST_LOCAL_OP_ERR		= IB_WCS_LOCAL_OP_ERR,
	IB_COMP_ST_LOCAL_PROTECT_ERR	= IB_WCS_LOCAL_PROTECTION_ERR,
	IB_COMP_ST_WR_FLUSHED_ERR	= IB_WCS_WR_FLUSHED_ERR,
	IB_COMP_ST_MW_BIND_ERR		= IB_WCS_MEM_WINDOW_BIND_ERR,
	IB_COMP_ST_REM_ACC_ERR		= IB_WCS_REM_ACCESS_ERR,
	IB_COMP_ST_REM_OP_ERR		= IB_WCS_REM_OP_ERR,
	IB_COMP_ST_RNR_COUNTER		= IB_WCS_RNR_RETRY_ERR,
	IB_COMP_ST_TRANSP_COUNTER	= IB_WCS_TIMEOUT_RETRY_ERR,
	IB_COMP_ST_REM_REQ_ERR		= IB_WCS_REM_INVALID_REQ_ERR,
	IB_COMP_ST_BAD_RESPONSE_ERR	= IB_WCS_UNMATCHED_RESPONSE,
	IB_COMP_ST_EE_STATE_ERR,
	IB_COMP_ST_EE_CTX_NO_ERR
};


/*
 * Macro to check the state of an EP/QP
 */
#define DAPLIB_NEEDS_INIT(ep)  ((ep)->qp_state == IB_QPS_ERROR)


/*
 * Resolve IBAL return codes to their DAPL equivelent.
 * Do not return invalid Handles, the user is not able
 * to deal with them.
 */
STATIC _INLINE_ DAT_RETURN 
dapl_ib_status_convert (
    IN     int32_t     ib_status)
{
    switch ( ib_status )
    {
    case IB_SUCCESS:
    {
        return DAT_SUCCESS;
    }
    case IB_INSUFFICIENT_RESOURCES:
    case IB_INSUFFICIENT_MEMORY:
    case IB_RESOURCE_BUSY:
    {
        return DAT_INSUFFICIENT_RESOURCES;
    }
    case IB_INVALID_CA_HANDLE:
    case IB_INVALID_CQ_HANDLE:
    case IB_INVALID_QP_HANDLE:
    case IB_INVALID_PD_HANDLE:
    case IB_INVALID_MR_HANDLE:
    case IB_INVALID_MW_HANDLE:
    case IB_INVALID_AL_HANDLE:
    case IB_INVALID_AV_HANDLE:
    {
        return DAT_INVALID_HANDLE;
    }
    case IB_INVALID_PKEY:
    {
        return DAT_PROTECTION_VIOLATION;
    }
    case IB_INVALID_LKEY:
    case IB_INVALID_RKEY:
    case IB_INVALID_PERMISSION:
    {
        return DAT_PRIVILEGES_VIOLATION;
    }
    case IB_INVALID_MAX_WRS:
    case IB_INVALID_MAX_SGE:
    case IB_INVALID_CQ_SIZE:
    case IB_INVALID_SETTING:
    case IB_INVALID_SERVICE_TYPE:
    case IB_INVALID_GID:
    case IB_INVALID_LID:
    case IB_INVALID_GUID:
    case IB_INVALID_PARAMETER:
    {
        return DAT_INVALID_PARAMETER;
    }
    case IB_INVALID_QP_STATE:
    case IB_INVALID_APM_STATE:
    case IB_INVALID_PORT_STATE:
    case IB_INVALID_STATE:
    {
        return DAT_INVALID_STATE;
    }
    case IB_NOT_FOUND:
    {
        return DAT_QUEUE_EMPTY;
    }
    case IB_OVERFLOW:
    {
        return DAT_QUEUE_FULL;
    }
    case IB_UNSUPPORTED:
    {
        return DAT_NOT_IMPLEMENTED;
    }
    case IB_TIMEOUT:
    {
        return DAT_TIMEOUT_EXPIRED;
    }
    case IB_CANCELED:
    {
        return DAT_ABORT;
    }
    default:
    {
        return DAT_INTERNAL_ERROR;
    }
    }
}
   
#define TAKE_LOCK( lock ) \
        cl_spinlock_acquire( &(lock) )

#define RELEASE_LOCK( lock ) \
        cl_spinlock_release( &(lock) )

#define LOCK_INSERT_HEAD( lock, head, item ) \
{ \
        TAKE_LOCK( lock ); \
        cl_qlist_insert_head( &head, (cl_list_item_t*)(&item) ); \
        RELEASE_LOCK( lock ); \
}

#define LOCK_INSERT_TAIL( lock, tail, item ) \
{ \
        TAKE_LOCK( lock ); \
        cl_qlist_insert_tail( &tail, (cl_list_item_t*)(&item) ); \
        RELEASE_LOCK( lock ); \
}

#define INIT_REFERENCE( p_ref, n, con, destruct ) \
{ \
        (p_ref)->count = n; \
        (p_ref)->context = con; \
        (p_ref)->destructor = destruct; \
}

#define TAKE_REFERENCE( p_ref ) \
        cl_atomic_inc( &(p_ref)->count )

#define REMOVE_REFERENCE( p_ref ) \
{ \
        if ( cl_atomic_dec( &(p_ref)->count ) == 0 ) \
            if ( (p_ref)->destructor ) \
                (p_ref)->destructor( (p_ref)->context ); \
}

/* 
 * dapl_llist_entry in dapl.h but dapl.h depends on provider 
 * typedef's in this file first. move dapl_llist_entry out of dapl.h
 */
struct ib_llist_entry
{
    struct dapl_llist_entry	*flink;
    struct dapl_llist_entry	*blink;
    void			*data;
    struct dapl_llist_entry	*list_head;
};

#ifdef SOCK_CM

typedef enum
{
	IB_THREAD_INIT,
	IB_THREAD_RUN,
	IB_THREAD_CANCEL,
	IB_THREAD_EXIT

} ib_thread_state_t;

typedef enum scm_state 
{
	SCM_INIT,
	SCM_LISTEN,
	SCM_CONN_PENDING,
	SCM_ACCEPTING,
	SCM_ACCEPTED,
	SCM_REJECTED,
	SCM_CONNECTED,
	SCM_DISCONNECTED,
	SCM_DESTROY

} SCM_STATE;

#endif	/* SOCK_CM */

typedef struct _ib_hca_transport
{ 
#ifdef SOCK_CM
    int				max_inline_send;
    ib_thread_state_t		cr_state;	/* CR thread */
    DAPL_OS_THREAD		thread;		/* CR thread */
    DAPL_OS_LOCK		lock;		/* CR serialization */
    struct ib_llist_entry	*list;		/* Connection Requests */
#endif
    struct dapl_hca		*d_hca;
    DAPL_OS_WAIT_OBJECT		wait_object;
    DAPL_ATOMIC			handle_ref_count; /* # of ia_opens on handle */
    ib_cqd_handle_t		ib_cqd_handle;	  /* cq domain handle */

    /* Name service support */
    void			*name_service_handle;

} ib_hca_transport_t;

/* provider specfic fields for shared memory support */
typedef uint32_t ib_shm_transport_t;

#ifdef SOCK_CM

/* inline send rdma threshold */
#define	INLINE_SEND_DEFAULT	128

/* CM mappings use SOCKETS */

/* destination info exchanged between dapl, define wire protocol version */
#define DSCM_VER 2

typedef struct _ib_qp_cm
{ 
	ib_net16_t	ver;
	ib_net16_t	rej;
	ib_net16_t		lid;
	ib_net16_t		port;
	ib_net32_t	qpn;
	ib_net32_t		p_size;
	DAT_SOCK_ADDR6		ia_address;
	GID		gid;

} ib_qp_cm_t;

struct ib_cm_handle
{ 
	struct ib_llist_entry	entry;
	DAPL_OS_LOCK		lock;
	SCM_STATE		state;
	int			socket;
	int			l_socket; 
	struct dapl_hca		*hca;
	DAT_HANDLE		sp;	
	DAT_HANDLE		cr;
	struct dapl_ep		*ep;
	ib_qp_cm_t		dst;
	unsigned char		p_data[256];
};

DAT_RETURN dapli_init_sock_cm ( IN DAPL_HCA  *hca_ptr );

#endif	/* SOCK_CM */

/*
 * Prototype
 */

extern ib_api_status_t 
dapls_modify_qp_state_to_error (
        ib_qp_handle_t                qp_handle );

extern ib_api_status_t 
dapls_modify_qp_state_to_reset (
    ib_qp_handle_t);

extern ib_api_status_t 
dapls_modify_qp_state_to_init ( 
    ib_qp_handle_t, DAT_EP_ATTR *, dapl_ibal_port_t *);

extern ib_api_status_t 
dapls_modify_qp_state_to_rtr (
    ib_qp_handle_t, ib_net32_t, ib_lid_t, dapl_ibal_port_t *);

extern ib_api_status_t 
dapls_modify_qp_state_to_rts (
    ib_qp_handle_t);

extern void
dapli_ibal_ca_async_error_callback(
    IN    ib_async_event_rec_t* p_err_rec );

extern dapl_ibal_port_t *
dapli_ibal_get_port (
    IN   dapl_ibal_ca_t    *p_ca,
    IN   uint8_t           port_num);

extern int32_t dapls_ib_init (void);
extern int32_t dapls_ib_release (void);

extern dapl_ibal_evd_cb_t *
dapli_find_evd_cb_by_context(
    IN    void           *context,
    IN    dapl_ibal_ca_t *ca);

extern IB_HCA_NAME
dapl_ib_convert_name(IN  char    *name);

STATIC _INLINE_ int32_t
dapli_ibal_convert_privileges (IN  DAT_MEM_PRIV_FLAGS  privileges )
{
    int32_t value = DAT_MEM_PRIV_NONE_FLAG;

    /*
     *    if (DAT_MEM_PRIV_LOCAL_READ_FLAG & privileges)
     *       do nothing
     */
    if (DAT_MEM_PRIV_LOCAL_WRITE_FLAG & privileges)
	value |= IB_ACCESS_LOCAL_WRITE;

    if (DAT_MEM_PRIV_REMOTE_WRITE_FLAG & privileges)
	value |= IB_ACCESS_REMOTE_WRITE;

    if (DAT_MEM_PRIV_REMOTE_READ_FLAG & privileges)
	value |= IB_ACCESS_REMOTE_READ;

#ifdef DAT_EXTENSIONS
    if (DAT_IB_MEM_PRIV_REMOTE_ATOMIC & privileges) 
        value |= IB_ACCESS_REMOTE_ATOMIC;
#endif

#ifdef DAPL_DBG
    if (value == DAT_MEM_PRIV_NONE_FLAG)
    {
	dapl_dbg_log(DAPL_DBG_TYPE_ERR,"%s() Unknown DAT_MEM_PRIV_ 0x%x\n",
                     __FUNCTION__,privileges);
    }
#endif
    return value;
}

#define dapl_rmr_convert_privileges(p) dapli_ibal_convert_privileges(p)
#define dapl_lmr_convert_privileges(p) dapli_ibal_convert_privileges(p)

#endif /*  _DAPL_IBAL_UTIL_H_ */
