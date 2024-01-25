/*
 * Copyright (c) 2002-2006, Network Appliance, Inc. All rights reserved.
 *
 * This Software is licensed under all of the following licenses:
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
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain both the above copyright
 * notice and one of the license notices.
 * 
 * Redistributions in binary form must reproduce both the above copyright
 * notice, one of the license notices in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of Network Appliance, Inc. nor the names of other DAT
 * Collaborative contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 */

/****************************************************************
 *
 * HEADER: kdat.h
 *
 * PURPOSE: defines the kernel DAT API
 *
 * Description: Header file for "kDAPL: Kernel Direct Access Programming
 *		Library, Version: 2.0"
 * Mapping rules:
 *      All global symbols are prepended with DAT_ or dat_
 *      All DAT objects have an 'api' tag which, such as 'ep' or 'lmr'
 *      The method table is in the provider definition structure.
 *
 *
 *
 ***************************************************************/

#ifndef _KDAT_H_
#define _KDAT_H_

#include <dat2/kdat_config.h>

#include <dat2/dat_platform_specific.h>

#if 1
#define EXPORT_SYMBOL_NOVERS(sym) EXPORT_SYMBOL(sym)
#endif

typedef enum dat_mem_type
{
	/* Shared between udat and kdat */
    DAT_MEM_TYPE_VIRTUAL        = 0x00,
    DAT_MEM_TYPE_LMR            = 0x01,
	/* kdat specific */
    DAT_MEM_TYPE_PHYSICAL       = 0x10,
    DAT_MEM_TYPE_PLATFORM       = 0x20,
    DAT_MEM_TYPE_IA             = 0x40,
    DAT_MEM_TYPE_BYPASS         = 0x80,
    DAT_MEM_TYPE_PHYSICAL_VAR_PAGES	= 0x100
} DAT_MEM_TYPE;

/* dat handle types */
typedef enum dat_handle_type
{
    DAT_HANDLE_TYPE_CR,
    DAT_HANDLE_TYPE_EP,
    DAT_HANDLE_TYPE_EVD,
    DAT_HANDLE_TYPE_IA,
    DAT_HANDLE_TYPE_LMR,
    DAT_HANDLE_TYPE_PSP,
    DAT_HANDLE_TYPE_PZ,
    DAT_HANDLE_TYPE_RMR,
    DAT_HANDLE_TYPE_RSP,
    DAT_HANDLE_TYPE_SRQ,
    DAT_HANDLE_TYPE_CSP
#ifdef DAT_EXTENSIONS
    ,DAT_HANDLE_TYPE_EXTENSION_BASE
#endif
} DAT_HANDLE_TYPE;

typedef enum dat_evd_param_mask
{
    DAT_EVD_FIELD_IA_HANDLE           = 0x01,
    DAT_EVD_FIELD_EVD_QLEN            = 0x02,
    DAT_EVD_FIELD_UPCALL_POLICY       = 0x04,
    DAT_EVD_FIELD_UPCALL              = 0x08,
    DAT_EVD_FIELD_EVD_FLAGS           = 0x10,
    DAT_EVD_FIELD_ALL                 = 0x1F
} DAT_EVD_PARAM_MASK;

typedef DAT_UINT64 DAT_PROVIDER_ATTR_MASK;

#include <dat2/dat.h>

typedef DAT_CONTEXT     DAT_LMR_COOKIE;

/* Upcall support */

typedef enum dat_upcall_policy
{
    DAT_UPCALL_DISABLE               = 0,   /* support no_upcalls           */
    DAT_UPCALL_SINGLE_INSTANCE       = 1,   /* support only one upcall      */
    DAT_UPCALL_MANY                  = 100, /* support multiple upcalls     */
    DAT_UPCALL_TEARDOWN              = -1   /* support no upcalls & return  *
					     * after all in progress        *
					     * UpCalls return               */
    ,DAT_UPCALL_NORIFY		= 2	/* support single upcall with       *
					 *  notification only		*/
} DAT_UPCALL_POLICY;

typedef void (*DAT_UPCALL_FUNC)(
	DAT_PVOID,		/* instance_data        */
	const DAT_EVENT *,	/* event                */
	DAT_BOOLEAN);		/* more_events          */

typedef struct dat_upcall_object
{
    DAT_PVOID                   instance_data;
    DAT_UPCALL_FUNC             upcall_func;
} DAT_UPCALL_OBJECT;

/* Define NULL upcall */

#define DAT_UPCALL_NULL \
	(DAT_UPCALL_OBJECT) { (DAT_PVOID) NULL, \
        (DAT_UPCALL_FUNC) NULL}

#define DAT_UPCALL_SAME		((DAT_UPCALL_OBJECT *) NULL)

	/* kDAT Upcall Invocation Policy */
typedef enum dat_upcall_flag
{
	DAT_UPCALL_INVOC_NEW	= 0,	/* invoke on a new event arrival */
	DAT_UPCALL_INVOC_ANY	= 1	/* invoke on any event on EVD	*/
} DAT_UPCALL_FLAG;

struct dat_evd_param
{
    DAT_IA_HANDLE               ia_handle;
    DAT_COUNT                   evd_qlen;
    DAT_UPCALL_POLICY           upcall_policy;
    DAT_UPCALL_OBJECT           upcall;
    DAT_EVD_FLAGS               evd_flags;
};

/*
 * Memory types
 *
 * Specifying memory type for LMR create. A Consumer must use a single
 * value when registering memory. The union of any of these
 * flags is used in the Provider parameters to indicate what memory
 * type Provider supports for LMR memory creation.
 */

/* memory data types */
#define DAT_MEM_OPT DAT_MEM_OPTIMIZE_FLAGS

typedef enum dat_mem_optimize_flags
{
    DAT_MEM_OPTIMIZE_DONT_CARE       = 0x00,
    DAT_MEM_OPTIMIZE_IA              = 0x01,
    DAT_MEM_OPTIMIZE_MIN_EXPOSURE    = 0x02,
    DAT_MEM_OPTIMIZE_EXACT_EXPOSURE  = 0x04
} DAT_MEM_OPTIMIZE_FLAGS;

typedef struct dat_physical_var_pages
{
	DAT_VLEN	page_size;
	void*		pages;
} DAT_PHYSICAL_VAR_PAGES;

typedef union dat_region_description
{
    DAT_PVOID                   for_va;
    DAT_LMR_HANDLE              for_lmr_handle;
    void *                      for_platform;	/* For kdapl only
						   for platform and bypass */
    DAT_PHYSICAL_VAR_PAGES	for_array;	/* for kdapl only */
    DAT_PADDR			*for_physical;  /* for kdapl only */
			/* array of physical pages of the same size */
    DAT_PADDR			for_ia;		/* for kdapl only */
} DAT_REGION_DESCRIPTION;

/* LMR Arguments */
typedef struct dat_lmr_state
{
	DAT_BOOLEAN		fmr_support;
	DAT_BOOLEAN		bound;
} DAT_LMR_STATE;

struct dat_lmr_param
{
    DAT_IA_HANDLE               ia_handle;
    DAT_MEM_TYPE                mem_type;
    DAT_REGION_DESCRIPTION      region_desc;
    DAT_VLEN                    length;
    DAT_PZ_HANDLE               pz_handle;
    DAT_MEM_PRIV_FLAGS          mem_priv;
    DAT_VA_TYPE			va_type;
    DAT_LMR_CONTEXT             lmr_context;
    DAT_RMR_CONTEXT             rmr_context;
    DAT_VLEN                    registered_size;
    DAT_VADDR                   registered_address;
    DAT_LMR_STATE		lmr_state;	/* kDAPL only */
};

/* LMR Arguments Mask */

enum dat_lmr_param_mask
{
	DAT_LMR_FIELD_IA_HANDLE          = 0x001,
	DAT_LMR_FIELD_MEM_TYPE           = 0x002,
	DAT_LMR_FIELD_REGION_DESC        = 0x004,
	DAT_LMR_FIELD_LENGTH             = 0x008,
	DAT_LMR_FIELD_PZ_HANDLE          = 0x010,
	DAT_LMR_FIELD_MEM_PRIV           = 0x020,
	DAT_LMR_FIELD_VA_TYPE            = 0x040,
	DAT_LMR_FIELD_LMR_CONTEXT        = 0x080,
	DAT_LMR_FIELD_RMR_CONTEXT        = 0x100,
	DAT_LMR_FIELD_REGISTERED_SIZE    = 0x200,
	DAT_LMR_FIELD_REGISTERED_ADDRESS = 0x400,
	DAT_LMR_FIELD_LMR_STATE		 = 0x800,

	DAT_LMR_FIELD_ALL                = 0xFFF
};

       /* kDAPL 1.3 addition */
       /* Defines LMR protection scope */
typedef enum dat_lmr_scope
{
	DAT_LMR_SCOPE_EP,  /* bound to at most one EP at a time.	*/
	DAT_LMR_SCOPE_PZ,  /* bound to a Protection Zone		*/
	DAT_LMR_SCOPE_ANY  /* Supports all types			*/
} DAT_LMR_SCOPE;

struct dat_ia_attr
{
	char                        adapter_name[DAT_NAME_MAX_LENGTH];
	char                        vendor_name[DAT_NAME_MAX_LENGTH];
	DAT_UINT32                  hardware_version_major;
	DAT_UINT32                  hardware_version_minor;
	DAT_UINT32                  firmware_version_major;
	DAT_UINT32                  firmware_version_minor;
	DAT_IA_ADDRESS_PTR          ia_address_ptr;
	DAT_COUNT                   max_eps;
	DAT_COUNT                   max_dto_per_ep;
	DAT_COUNT                   max_rdma_read_per_ep_in;
	DAT_COUNT                   max_rdma_read_per_ep_out;
	DAT_COUNT                   max_evds;
	DAT_COUNT                   max_evd_qlen;
	DAT_COUNT                   max_iov_segments_per_dto;
	DAT_COUNT                   max_lmrs;
	DAT_SEG_LENGTH              max_lmr_block_size;
	DAT_VADDR                   max_lmr_virtual_address;
	DAT_COUNT                   max_pzs;
	DAT_SEG_LENGTH              max_message_size;
	DAT_SEG_LENGTH              max_rdma_size;
	DAT_COUNT                   max_rmrs;
	DAT_VADDR                   max_rmr_target_address;
	DAT_COUNT                   max_srqs;
	DAT_COUNT                   max_ep_per_srq;
	DAT_COUNT                   max_recv_per_srq;
	DAT_COUNT                   max_iov_segments_per_rdma_read;
	DAT_COUNT                   max_iov_segments_per_rdma_write;
	DAT_COUNT                   max_rdma_read_in;
	DAT_COUNT                   max_rdma_read_out;
	DAT_BOOLEAN                 max_rdma_read_per_ep_in_guaranteed;
	DAT_BOOLEAN                 max_rdma_read_per_ep_out_guaranteed;
	DAT_BOOLEAN                 zb_supported;
	DAT_BOOLEAN		    reserved_lmr_supported;
#ifdef DAT_EXTENSIONS
	DAT_EXTENSION               extension_supported;
	DAT_COUNT                   extension_version;
#endif /* DAT_EXTENSIONS */
	DAT_COUNT                   num_transport_attr;
	DAT_NAMED_ATTR              *transport_attr;
	DAT_COUNT                   num_vendor_attr;
	DAT_NAMED_ATTR              *vendor_attr;
};

#define DAT_IA_FIELD_IA_RESERVED_LMR_SUPPORTED		UINT64_C(0x100000000)
#ifdef DAT_EXTENSIONS
#define DAT_IA_FIELD_IA_EXTENSION                       UINT64_C(0x200000000)
#define DAT_IA_FIELD_IA_EXTENSION_VERSION               UINT64_C(0x400000000)
#endif /* DAT_EXTENSIONS */

#define DAT_IA_FIELD_IA_NUM_TRANSPORT_ATTR               UINT64_C(0x800000000)
#define DAT_IA_FIELD_IA_TRANSPORT_ATTR                   UINT64_C(0x1000000000)
#define DAT_IA_FIELD_IA_NUM_VENDOR_ATTR                  UINT64_C(0x2000000000)
#define DAT_IA_FIELD_IA_VENDOR_ATTR                      UINT64_C(0x4000000000)
#define DAT_IA_FIELD_ALL                                 UINT64_C(0x7FFFFFFFFF)

#define DAT_EVENT_NULL		((DAT_EVENT) NULL)

/* General Provider attributes. kdat specific. */

#include <dat2/kdat_vendor_specific.h>

/* Provider should support merging of all event stream types. Provider
 * attribute specify support for merging different event stream types.
 * It is a 2D binary matrix where each row and column represents an event
 * stream type. Each binary entry is 1 if the event streams of its raw
 * and column can fed the same EVD, and 0 otherwise. The order of event
 * streams in row and column is the same as in the definition of
 * DAT_EVD_FLAGS: index 0 - Software Event, 1- Connection Request,
 * 2 - DTO Completion, 3 - Connection event, 4 - RMR Bind Completion,
 * 5 - Asynchronous event. By definition each diagonal entry is 1.
 * Consumer allocates an array for it and passes it IN as a pointer
 * for the array that Provider fills. Provider must fill the array
 * that Consumer passes.
 */

struct dat_provider_attr
{
    char                        provider_name[DAT_NAME_MAX_LENGTH];
    DAT_UINT32                  provider_version_major;
    DAT_UINT32                  provider_version_minor;
    DAT_UINT32                  dapl_version_major;
    DAT_UINT32                  dapl_version_minor;
    DAT_MEM_TYPE                lmr_mem_types_supported;
    DAT_IOV_OWNERSHIP           iov_ownership_on_return;
    DAT_QOS                     dat_qos_supported;
    DAT_COMPLETION_FLAGS        completion_flags_supported;
    DAT_BOOLEAN                 is_thread_safe;
    DAT_COUNT                   max_private_data_size;
    DAT_BOOLEAN                 supports_multipath;
    DAT_EP_CREATOR_FOR_PSP      ep_creator;
    DAT_UPCALL_POLICY           upcall_policy;
    DAT_UINT32                  optimal_buffer_alignment;
    const DAT_BOOLEAN           evd_stream_merging_supported[6][6];
    DAT_BOOLEAN                 srq_supported;
    DAT_COUNT                   srq_watermarks_supported;
    DAT_BOOLEAN                 srq_ep_pz_difference_supported;
    DAT_COUNT                   srq_info_supported;
    DAT_COUNT                   ep_recv_info_supported;
    DAT_BOOLEAN                 lmr_sync_req;
    DAT_BOOLEAN                 dto_async_return_guaranteed;
    DAT_BOOLEAN                 rdma_write_for_rdma_read_req;
    DAT_BOOLEAN                 rdma_read_lmr_rmr_context_exposure;
    DAT_RMR_SCOPE               rmr_scope_supported;
    DAT_BOOLEAN                 is_interrupt_safe;
    DAT_BOOLEAN			fmr_supported;
    DAT_LMR_SCOPE		lmr_for_fmr_scope_supported;
    DAT_BOOLEAN                 ha_supported;
    DAT_HA_LB                   ha_loadbalancing;

    DAT_COUNT                   num_provider_specific_attr;
    DAT_NAMED_ATTR *            provider_specific_attr;
};


#define DAT_PROVIDER_FIELD_PROVIDER_NAME                 UINT64_C(0x000000001)
#define DAT_PROVIDER_FIELD_PROVIDER_VERSION_MAJOR        UINT64_C(0x000000002)
#define DAT_PROVIDER_FIELD_PROVIDER_VERSION_MINOR        UINT64_C(0x000000004)
#define DAT_PROVIDER_FIELD_DAPL_VERSION_MAJOR            UINT64_C(0x000000008)
#define DAT_PROVIDER_FIELD_DAPL_VERSION_MINOR            UINT64_C(0x000000010)
#define DAT_PROVIDER_FIELD_LMR_MEM_TYPE_SUPPORTED        UINT64_C(0x000000020)
#define DAT_PROVIDER_FIELD_IOV_OWNERSHIP                 UINT64_C(0x000000040)
#define DAT_PROVIDER_FIELD_DAT_QOS_SUPPORTED             UINT64_C(0x000000080)
#define DAT_PROVIDER_FIELD_COMPLETION_FLAGS_SUPPORTED    UINT64_C(0x000000100)
#define DAT_PROVIDER_FIELD_IS_THREAD_SAFE                UINT64_C(0x000000200)
#define DAT_PROVIDER_FIELD_MAX_PRIVATE_DATA_SIZE         UINT64_C(0x000000400)
#define DAT_PROVIDER_FIELD_SUPPORTS_MULTIPATH            UINT64_C(0x000000800)
#define DAT_PROVIDER_FIELD_EP_CREATOR                    UINT64_C(0x000001000)
#define DAT_PROVIDER_FIELD_UPCALL_POLICY                 UINT64_C(0x000002000)
#define DAT_PROVIDER_FIELD_OPTIMAL_BUFFER_ALIGNMENT      UINT64_C(0x000004000)
#define DAT_PROVIDER_FIELD_EVD_STREAM_MERGING_SUPPORTED  UINT64_C(0x000008000)
#define DAT_PROVIDER_FIELD_SRQ_SUPPORTED                 UINT64_C(0x000010000)
#define DAT_PROVIDER_FIELD_SRQ_WATERMARKS_SUPPORTED      UINT64_C(0x000020000)
#define DAT_PROVIDER_FIELD_SRQ_EP_PZ_DIFFERENCE_SUPPORTED UINT64_C(0x000040000)
#define DAT_PROVIDER_FIELD_SRQ_INFO_SUPPORTED            UINT64_C(0x000080000)
#define DAT_PROVIDER_FIELD_EP_RECV_INFO_SUPPORTED        UINT64_C(0x000100000)
#define DAT_PROVIDER_FIELD_LMR_SYNC_REQ                  UINT64_C(0x000200000)
#define DAT_PROVIDER_FIELD_DTO_ASYNC_RETURN_GUARANTEED   UINT64_C(0x000400000)
#define DAT_PROVIDER_FIELD_RDMA_WRITE_FOR_RDMA_READ_REQ  UINT64_C(0x000800000)
#define DAT_PROVIDER_FIELD_RDMA_READ_LMR_RMR_CONTEXT_EXPOSURE   UINT64_C(0x001000000)
#define DAT_PROVIDER_FIELD_RMR_SCOPE_SUPPORTED		 UINT64_C(0x002000000)
#define DAT_PROVIDER_FIELD_IS_INTERRUPT_SAFE             UINT64_C(0x004000000)
#define DAT_PROVIDER_FIELD_FMR_SUPPORTED		 UINT64_C(0x008000000)
#define DAT_PROVIDER_FIELD_LMR_FOR_FMR_SCOPE		 UINT64_C(0x010000000)
#define DAT_PROVIDER_FIELD_HA_SUPPORTED                  UINT64_C(0x020000000)
#define DAT_PROVIDER_FIELD_HA_LB                         UINT64_C(0x040000000)
#define DAT_PROVIDER_FIELD_NUM_PROVIDER_SPECIFIC_ATTR    UINT64_C(0x080000000)
#define DAT_PROVIDER_FIELD_PROVIDER_SPECIFIC_ATTR        UINT64_C(0x100000000)

#define DAT_PROVIDER_FIELD_ALL                           UINT64_C(0x1FFFFFFFF)
#define DAT_PROVIDER_FIELD_NONE				 UINT64_C(0x0)

/**********************************************************************/

/*
 * Kernel DAT function call definitions,
 */

extern DAT_RETURN dat_lmr_kcreate (
	IN      DAT_IA_HANDLE,			/* ia_handle            */
	IN      DAT_MEM_TYPE,			/* mem_type             */
	IN      DAT_REGION_DESCRIPTION,		/* region_description   */
	IN      DAT_VLEN,			/* length               */
	IN      DAT_PZ_HANDLE,			/* pz_handle            */
	IN      DAT_MEM_PRIV_FLAGS,		/* privileges           */
	IN	DAT_VA_TYPE,			/* va_type 		*/
	IN      DAT_MEM_OPTIMIZE_FLAGS,		/* mem_optimization     */
	OUT     DAT_LMR_HANDLE *,		/* lmr_handle           */
	OUT     DAT_LMR_CONTEXT *,		/* lmr_context          */
	OUT     DAT_RMR_CONTEXT *,		/* rmr_context          */
	OUT     DAT_VLEN *,			/* registered_length    */
	OUT     DAT_VADDR * );			/* registered_address   */

extern DAT_RETURN dat_ia_memtype_hint (
	IN      DAT_IA_HANDLE,			/* ia_handle            */
	IN      DAT_MEM_TYPE,			/* mem_type             */
	IN      DAT_VLEN,			/* length               */
	IN      DAT_MEM_OPTIMIZE_FLAGS,		/* mem_optimization     */
	OUT     DAT_VLEN *,			/* preferred_length     */
	OUT     DAT_VADDR * );			/* preferred_alignment  */

extern DAT_RETURN dat_lmr_query (
	IN      DAT_LMR_HANDLE,			/* lmr_handle           */
	IN      DAT_LMR_PARAM_MASK,		/* lmr_param_mask       */
	OUT     DAT_LMR_PARAM *);		/* lmr_param            */

extern DAT_RETURN dat_lmr_allocate (
	IN      DAT_IA_HANDLE,			/* ia_handle            */
	IN      DAT_PZ_HANDLE,			/* pz_handle		*/
	IN      DAT_COUNT,			/* max # of physical pages */
	IN      DAT_LMR_SCOPE,			/* scope of lmr		*/
	OUT     DAT_LMR_HANDLE * );		/*lmr handle		*/ 

extern DAT_RETURN dat_lmr_fmr (
	IN      DAT_LMR_HANDLE,			/* lmr_handle            */
	IN      DAT_MEM_TYPE,			/* mem_type             */
	IN      DAT_REGION_DESCRIPTION,		/* region_description   */
	IN      DAT_VLEN,			/* number of pages	*/
	IN      DAT_MEM_PRIV_FLAGS,		/* mem_privileges	*/
	IN	DAT_VA_TYPE,			/* va_type 		*/
	IN      DAT_EP_HANDLE,			/* ep_handle		*/
	IN	DAT_LMR_COOKIE,			/* user_cookie		*/
	IN	DAT_COMPLETION_FLAGS,		/* completion_flags 	*/
	OUT	DAT_LMR_CONTEXT,		/* lmr_context		*/
	OUT     DAT_RMR_CONTEXT );		/* rmr_context		*/

extern DAT_RETURN dat_lmr_invalidate (
	IN      DAT_LMR_HANDLE,			/* lmr_handle           */
	IN      DAT_EP_HANDLE,			/* ep_handle		*/
	IN      DAT_LMR_COOKIE,			/* user_cookie		*/
	IN	DAT_COMPLETION_FLAGS );         /* completion_flags     */

extern DAT_RETURN dat_ia_reserved_lmr (
	IN      DAT_IA_HANDLE,          /* ia_handle			*/
	OUT     DAT_LMR_HANDLE *,       /* reserved_lmr_handle		*/
	OUT     DAT_LMR_CONTEXT * );    /* reserved_lmr_context		*/

extern DAT_RETURN dat_evd_kcreate (
	IN      DAT_IA_HANDLE,			/* ia_handle            */
	IN      DAT_COUNT,			/* evd_min_qlen         */
	IN      DAT_UPCALL_POLICY,		/* upcall_policy        */
	IN      const DAT_UPCALL_OBJECT *,	/* upcall               */
	IN      DAT_EVD_FLAGS,			/* evd_flags            */
	OUT     DAT_EVD_HANDLE * );		/* evd_handle           */

extern DAT_RETURN dat_evd_modify_upcall (
	IN      DAT_EVD_HANDLE,			/* evd_handle           */
	IN      DAT_UPCALL_POLICY,		/* upcall_policy        */
	IN      const DAT_UPCALL_OBJECT* ,	/* upcall               */
	IN	DAT_UPCALL_FLAG );		/* upcall invocation policy */

#endif /* _KDAT_H_ */
