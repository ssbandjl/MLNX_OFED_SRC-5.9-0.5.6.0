/*
 * Copyright (c) 2005-2007 Intel Corporation. All rights reserved.
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 *
 * This Software is licensed under either one of the following two licenses:
 *
 * 1) under the terms of the "Common Public License 1.0" a copy of which is
 *    in the file LICENSE.txt in the root directory. The license is also
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/cpl.php.
 * OR
 *
 * 2) under the terms of the "The BSD License" a copy of which is in the file
 *    LICENSE2.txt in the root directory. The license is also available from
 *    the Open Source Initiative, see
 *    http://www.opensource.org/licenses/bsd-license.php.
 *
 * Licensee has the right to choose either one of the above two licenses.
 *
 * Redistributions of source code must retain both the above copyright
 * notice and either one of the license notices.
 *
 * Redistributions in binary form must reproduce both the above copyright
 * notice, either one of the license notices in the documentation
 * and/or other materials provided with the distribution.
 */

/**********************************************************************
 * 
 * HEADER: dapl_ibal_name_service.h
 *
 * PURPOSE: Utility defs & routines supporting name services
 *
 * $Id: dapl_name_service.h 33 2005-07-11 19:51:17Z ftillier $
 *
 **********************************************************************/

#ifndef _DAPL_IBAL_NAME_SERVICE_H_
#define _DAPL_IBAL_NAME_SERVICE_H_ 1

#include "dapl.h"
#include "dapl_adapter_util.h"

/*
 * Prototypes for name service routines
 */

/* Return IPv4 address in 'dot' notation. */

char *
dapli_get_ip_addr_str (
        IN    DAT_SOCK_ADDR6       *ipa,
        OUT   char                 *str );

/* SA Query callback for locating GID/Path-rec */
void AL_API
dapli_ib_sa_query_cb (
        IN    ib_query_rec_t       *p_query_rec );


#ifdef NO_NAME_SERVICE

DAT_RETURN dapls_ns_lookup_address (
	IN  DAPL_IA		*ia_ptr,
	IN  DAT_IA_ADDRESS_PTR	remote_ia_address,
	OUT GID			*gid);


#else

DAT_RETURN dapls_ns_create_gid_map(DAPL_HCA *hca_ptr);

DAT_RETURN dapls_ns_remove_gid_map(DAPL_HCA *hca_ptr);

DAT_RETURN dapls_ns_map_gid (
	IN  DAPL_HCA		*hca_ptr,
	IN  DAT_IA_ADDRESS_PTR	remote_ia_address,
	OUT GID			*gid);

DAT_RETURN
dapls_ib_ns_map_gid (
        IN        DAPL_HCA                *hca_ptr,
        IN        DAT_IA_ADDRESS_PTR      p_ia_address,
        OUT       GID                     *p_gid);

DAT_RETURN dapls_ns_map_ipaddr (
	IN  DAPL_HCA		*hca_ptr,
	IN  GID			gid,
	OUT DAT_IA_ADDRESS_PTR	remote_ia_address);

DAT_RETURN
dapls_ib_ns_map_ipaddr (
        IN        DAPL_HCA                *hca_ptr,
        IN        GID                     gid,
        OUT       DAT_IA_ADDRESS_PTR      p_ia_address);

#endif /* NO_NAME_SERVICE */

#endif /* _DAPL_IBAL_NAME_SERVICE_H_ */
