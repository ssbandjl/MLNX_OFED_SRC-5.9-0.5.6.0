/*
 * Copyright (c) 2002-2006, Network Appliance, Inc. All rights reserved.
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
 * HEADER: dat_iw_extensions.h
 *
 * PURPOSE: extensions to the DAT API for iWARP transport specific services 
 *	    NOTE: 
 *	        Applications MUST recompile with new dat.h definitions
 *		  and include this file.
 *
 * Description: Header file for "uDAPL: User Direct Access Programming
 *		Library, Version: 2.0"
 *
 * Mapping rules:
 *      All global symbols are prepended with "DAT_" or "dat_"
 *      All DAT objects have an 'api' tag which, such as 'ep' or 'lmr'
 *      The method table is in the provider definition structure.
 *
 *
 **********************************************************************/
#ifndef _DAT_IW_EXTENSIONS_H_
#define _DAT_IW_EXTENSIONS_H_

/* 
 * Provider specific attribute strings for extension support 
 *	returned with dat_ia_query() and 
 *	DAT_PROVIDER_ATTR_MASK == DAT_PROVIDER_FIELD_PROVIDER_SPECIFIC_ATTR
 *
 *	DAT_NAMED_ATTR	name == extended operations and version, 
 *			version_value = version number of extension API
 */
#define DAT_EXTENSION_ATTR		 "DAT_EXTENSION_INTERFACE"
#define DAT_EXTENSION_ATTR_VERSION	 "DAT_EXTENSION_VERSION"
#define DAT_EXTENSION_ATTR_VERSION_VALUE "2.0.1"
#define DAT_IW_ATTR_SSP			 "DAT_IW_ATTR_SSP"


/*
 * The iWARP extension supports Socket Service Points
 * These enable establishing a TCP connection first, then converting
 * it to RDMA usage.
 */
typedef enum dat_handle_iw_ext_type {
	DAT_IW_HANDLE_TYPE_SSP = DAT_HANDLE_TYPE_EXTENSION_BASE,
} DAT_HANDLE_IW_EXT_TYPE;
typedef DAT_HANDLE DAT_IW_SSP_HANDLE;

typedef enum dat_iw_ssp_state
{
	DAT_IW_SSP_STATE_OPERATIONAL,
	DAT_IW_SSP_STATE_NON_OPERATIONAL
} DAT_IW_SSP_STATE;

/* The Socket ID is a local identifier for the socket. It is used for Socket
  * based connection model. The format of the DAT_IW_SOCKET follows the native
  * sockets programming practice of each target Operating System. The Consumer must
  * follow normal sockets programming procedures provided by the host platform.
  *
  * This include assumes that a socket handle is an int unless we are in
  * Linux Kernel code, in which case it is a struct socket pointer. This
  * distinction could be moved either to a distinct file (for iWARP specific,
  * platform specific types) or to dat_platform_specific.h (where the fact
  * that it was iWARP specific would be awkward). The coin flip was heads,
  * so the awkwardness of platform specific typing is in the iWARP specific
  * file instead.
 */
#if defined(__linux__)  &&  defined(__KERNEL__)
typyedef struct socket *DAT_IW_SOCKET;
#else
typedef int DAT_IW_SOCKET;
#endif

typedef struct dat_iw_ssp_param
{
	DAT_IA_HANDLE ia_handle;
	DAT_IW_SOCKET socket_id;
	DAT_EVD_HANDLE evd_handle;
	DAT_EP_HANDLE ep_handle;
	DAT_IW_SSP_STATE ssp_state;
} DAT_IW_SSP_PARAM;

typedef enum dat_iw_ssp_param_mask
{
	DAT_IW_SSP_FIELD_IA_HANDLE = 0x01,
	DAT_IW_SSP_FIELD_SOCKET_ID = 0x02,
	DAT_IW_SSP_FIELD_EVD_HANDLE = 0x04,
	DAT_IW_SSP_FIELD_EP_HANDLE = 0x08,
	DAT_IW_SSP_FIELD_SSP_STATE = 0x10,
	DAT_IW_SSP_FIELD_ALL = 0x1F
} DAT_IW_SSP_PARAM_MASK;


/* 
 * Extension operations 
 */
typedef enum dat_iw_op
{
	DAT_IW_SSP_CREATE_OP,
	DAT_IW_SSP_FREE_OP,
	DAT_IW_SSP_QUERY_OP,
	DAT_IW_SOCKET_CONNECT_OP
} DAT_IW_OP;

/* 
 * Extended IW transport specific APIs
 *  redirection via DAT extension function
 */

/* dat_iw_ssp_create creates an iWARP Socket Service Point given an
 * already connected Socket
 */

#define dat_iw_ssp_create (ia,socket_id,ep_handle,evd_handle,\
                           final_sm_msg,final_sm_msg_len,ssp_handle) \
		dat_extension_op (ia,DAT_IW_SSP_CREATE_OP,ia,socket_id, \
					ep_handle,evd_handle,final_sm_msg, \
					final_sm_msg_len,ssp_handle)

/* dat_iw_ssp_free destroys the specified instance of an SSP
 */
#define dat_iw_ssp_free (ssp_handle) \
	dat_extension_op (ssp_handle,DAT_IW_SSP_FREE_OP)

/* dat_iw_ssq_query obtains the SSP_PARAMs for an ssp
 */
#define dat_iw_ssp_query (ssp_handle,ssp_param_mask,ssp_param) \
	dat_extension_op (ssp_handle,DAT_IW_SSP_QUERY_OP, \
		ssp_param_maks,ssp_param)

/* dat_iw_socket_connect initates a connection using an SSP
 */
#define dat_iw_socket_connect (ep_handle,socket_id,timeout, \
				       private_data_size,private_data) \
	dat_extension_op (ep_handle,DAT_IW_SOCKET_CONNECT_OP,\
			      socket_id,timeout,private_data_size,\
				private_data)

#endif /* _DAT_IW_EXTENSIONS_H_ */

