
/*
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
 * MODULE: dapl_ibal_mrdb.h
 *
 * PURPOSE: Utility defs & routines for access to Intel IBAL APIs
 *
 * $Id: dapl_ibal_mrdb.h 33 2005-07-11 19:51:17Z ftillier $
 *
 **********************************************************************/

#ifndef _DAPL_IBAL_MRDB_H_
#define _DAPL_IBAL_MRDB_H_

#include <complib/comp_lib.h>
#include <iba/ib_types.h>

#define MVDAPL_BASE_SHMID       0xF00
#define MVDAPL_BASE_SVID        0xF
#define MVDAPL_MAX_SHMID        0xFFFFFFFF
#define MVDAPL_MAX_SVID         0xEFFFFFFF

#define IBAL_LMR_COOKIE_SIZE	40
typedef char     (* ib_lmr_cookie_t)[IBAL_LMR_COOKIE_SIZE];

typedef struct _mrdb_record_ioctl
{
    char             *shared_mem_id[IBAL_LMR_COOKIE_SIZE];
    void             *mr_handle;
    ib_net64_t       inout_f;
    ib_api_status_t  status;
} mrdb_record_ioctl_t;

typedef          mrdb_record_ioctl_t        mrdb_rec_dec_ioctl_t;
typedef          mrdb_record_ioctl_t        mrdb_rec_insert_ioctl_t;
typedef          mrdb_record_ioctl_t        mrdb_rec_query_ioctl_t;
typedef          mrdb_record_ioctl_t        mrdb_rec_update_ioctl_t;
typedef          mrdb_record_ioctl_t        psp_get_any_svid_ioctl_t;


#endif /* _DAPL_IBAL_MRDB_H_ */

