
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
 * MODULE: dapl_ibal_kmod.h
 *
 * PURPOSE: Utility defs & routines for access to Intel IBAL APIs
 *
 * $Id: dapl_ibal_kmod.h 33 2005-07-11 19:51:17Z ftillier $
 *
 **********************************************************************/

#ifndef _DAPL_IBAL_KMOD_H_
#define _DAPL_IBAL_KMOD_H_

#include <complib/comp_lib.h>
#include <iba/ib_types.h>
#include <dapl_ibal_mrdb.h>

#define  MVDAPL_DEV_KEY      'm'
#define  MVDAPL_GET_ANY_SVID        _IO ( MVDAPL_DEV_KEY, psp_get_any_svid )
#define  MVDAPL_MRDB_RECORD_INSERT  _IO ( MVDAPL_DEV_KEY, mrdb_record_insert )
#define  MVDAPL_MRDB_RECORD_DEC     _IO ( MVDAPL_DEV_KEY, mrdb_record_dec )
#define  MVDAPL_MRDB_RECORD_QUERY   _IO ( MVDAPL_DEV_KEY, mrdb_record_query )
#define  MVDAPL_MRDB_RECORD_UPDATE  _IO ( MVDAPL_DEV_KEY, mrdb_record_update )

typedef enum 
{
    psp_get_any_svid,
    mrdb_record_insert,
    mrdb_record_dec,
    mrdb_record_query,
    mrdb_record_update,
    mvdapl_max_ops
} mvdapl_dev_ops_t;

typedef struct _mvdapl_user_ctx
{
    cl_spinlock_t         oust_mrdb_lock;
    cl_qlist_t            oust_mrdb_head;
} mvdapl_user_ctx_t;    


typedef struct _mvdapl_ca_t
{
    cl_spinlock_t         mrdb_lock;
    cl_qlist_t            mrdb_head;
    boolean_t             initialized;
    cl_dev_handle_t       mrdb_dev_handle;
    ib_net64_t            ca_guid;
} mvdapl_ca_t;


typedef struct _mvdapl_root
{
    ib_al_handle_t        h_al;
    intn_t                guid_count;
    mvdapl_ca_t           *mvdapl_ca_tbl;

} mvdapl_root_t;

typedef struct _mrdb_record_t
{
    cl_list_item_t     next;
    ib_lmr_cookie_t    key_cookie;
    void               *mr_handle;
    int                ib_shmid;
    uint32_t           ref_count;
    boolean_t          initialized;
    cl_spinlock_t      record_lock;
} mrdb_record_t;


typedef struct _oust_mrdb_rec
{
    cl_list_item_t   next;
    mrdb_record_t    *p_record;
    uint32_t         ref_count;
} oust_mrdb_rec_t;


#endif /* _DAPL_IBAL_KMOD_H_ */
