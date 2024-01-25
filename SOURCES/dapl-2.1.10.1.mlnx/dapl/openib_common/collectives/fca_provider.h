/*
 * Copyright (c) 2011 Intel Corporation.  All rights reserved.
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
#ifndef _FCA_PROVIDER_H_
#define _FCA_PROVIDER_H_

#include <fca/fca_api.h>
#include <fca/config/fca_parse_specfile.h>

/* Collective Group Object */
struct coll_group {

    DAPL_HEADER			header;		/* collective type header, group lock */
    DAT_CONTEXT			user_context;	/* user context for group */
    struct dapl_llist_entry	list_entry;	/* group creation list for work thread */

    /* Basic group information */
    DAPL_EVD			*evd;	  /* DAT consumer evd for group, COLL type */
    DAPL_PZ			*pz;	  /* DAT protection domain */
    ib_hca_transport_t		*tp;      /* IA device transport object */
    int				id;	  /* group id */
    int				self;	  /* my rank index */
    int				ranks;	  /* nprocs in group */
    int				sock; 	  /* socket, needed to get grp comm_desc */
    int				*conn;	  /* connections to exchange member info */
    void			*op_pool; /* operations queue buffer pool */
    struct dapl_llist_entry	*op_pend; /* in-process, in-order operations */
    struct dapl_llist_entry	*op_free; /* free list for operations */
    DAPL_OS_LOCK 		op_lock;  /* operations queue lock */
    DAPL_OS_WAIT_OBJECT 	op_event; /* operations completion event */

    /* provider specific information */
    struct fca_context 		*ctx;       /* FCA device */
    void 			*fca_info;  /* FCA member info, element = tp->f_size */
    struct sockaddr_in		*addr_info; /* RANK address array, element = DAT_SOCK_ADDR */
    fca_comm_caps_t 		comm_caps;  /* FCA comm group capabilities */
    struct fca_rank_comm	*comm;      /* FCA comm group initialized */
    struct fca_comm_new_spec	comm_new;   /* comm new spec */
    int				comm_id;    /* FCA comm group id */
    fca_comm_desc_t 		comm_desc;  /* FCA comm group */
    fca_comm_init_spec_t 	comm_init;  /* FCA comm init parameters */
    DAT_IB_COLLECTIVE_GROUP	g_info;	    /* Process layout info */
};

/* Collective Operation Object, for non-blocking support */
#define COLL_OP_CNT	32

struct coll_op {
    struct dapl_llist_entry		list_entry;
    struct coll_group			*grp;
    DAT_IA_HANDLE 			ia;
    enum dat_ib_op			op;
    DAT_IB_COLLECTIVE_RANK		root;
    DAT_IB_COLLECTIVE_RANK 		self;
    DAT_CONTEXT				ctx;
    DAT_COMPLETION_FLAGS		cflgs;
    DAT_PVOID				sbuf;
    DAT_COUNT   			ssize;
    DAT_COUNT				*ssizes;
    DAT_COUNT				*sdispls;
    DAT_PVOID				rbuf;
    DAT_COUNT				rsize;
    DAT_COUNT				*rsizes;
    DAT_COUNT				*rdispls;
    DAT_IB_COLLECTIVE_REDUCE_DATA_OP 	reduce_op;
    DAT_IB_COLLECTIVE_DATA_TYPE 	reduce_type;
    DAT_UINT64				clock;
    void 				*progress_func;
    DAT_COUNT 				*member_size;
    DAT_IB_COLLECTIVE_MEMBER 		*member;
    DAT_RETURN				status;
};

#endif /* _FCA_PROVIDER_H_ */
