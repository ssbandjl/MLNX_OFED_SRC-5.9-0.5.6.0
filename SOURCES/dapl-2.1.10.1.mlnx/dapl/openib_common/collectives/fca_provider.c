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

/*
 * Mellanox ConnectX-2 MPI collective offload support - FCA (Fabric Collective Agent)
 */

#include <dlfcn.h>
#include "openib_osd.h"
#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_ib_util.h"
#include "dapl_ep_util.h"
#include "dapl_evd_util.h"
#include "dapl_cookie.h"

#ifdef DAT_IB_COLLECTIVES
#ifdef DAT_FCA_PROVIDER

#include <dat2/dat_ib_extensions.h>
#include <collectives/ib_collectives.h>

#define DAT_COLL_SID 0x2234

static char *fca_specfile = "/tmp/fca_spec.ini";
void *fca_lhandle = NULL;

static struct grp_req {
        int id;
        int sockfd;
        struct grp_req *next;
} *qhead = NULL, *qtail=NULL;

static int grp_req_queue(int id, int sockfd)
{
        struct grp_req *p;

        p = malloc(sizeof *p);
        if (p==NULL)
                return -ENOMEM;

        p->id = id;
        p->sockfd = sockfd;
        p->next = NULL;
        if (qtail) {
                qtail->next = p;
                qtail = p;
        }
        else
                qhead = qtail = p;

        return 0;
}

static int grp_req_dequeue(int id)
{
        struct grp_req *p, *q;
        int sockfd = -1;

        p = qhead;
        q = NULL;

        while (p) {
                if (p->id == id) {
                        sockfd = p->sockfd;
                        if (q)
                                q->next = p->next;
                        else
                                qhead = p->next;

                        if (p == qtail)
                                qtail = q;

                        free(p);
                        break;
                }
                q = p;
                p = p->next;
        }
        return sockfd;
}

static int fca_dtype( enum dat_ib_collective_data_type type )
{
	int fca_type;

	switch (type) {
	  case DAT_IB_COLLECTIVE_TYPE_INT8:
		fca_type = FCA_DTYPE_CHAR;
		break;
	  case DAT_IB_COLLECTIVE_TYPE_UINT8:
		fca_type = FCA_DTYPE_UNSIGNED_CHAR;
		break;
	  case DAT_IB_COLLECTIVE_TYPE_INT16:
		fca_type = FCA_DTYPE_SHORT;
		break;
	  case DAT_IB_COLLECTIVE_TYPE_UINT16:
		fca_type = FCA_DTYPE_UNSIGNED_SHORT;
		break;
	  case DAT_IB_COLLECTIVE_TYPE_INT32:
		fca_type = FCA_DTYPE_INT;
		break;
	  case DAT_IB_COLLECTIVE_TYPE_UINT32:
		fca_type = FCA_DTYPE_UNSIGNED;
		break;
	  case DAT_IB_COLLECTIVE_TYPE_INT64:
		fca_type = FCA_DTYPE_LONG;
		break;
	  case DAT_IB_COLLECTIVE_TYPE_UINT64:
		fca_type = FCA_DTYPE_UNSIGNED_LONG;
		break;
	  case DAT_IB_COLLECTIVE_TYPE_FLOAT:
		fca_type = FCA_DTYPE_FLOAT;
		break;
	  case DAT_IB_COLLECTIVE_TYPE_DOUBLE:
		fca_type = FCA_DTYPE_DOUBLE;
		break;
	  case DAT_IB_COLLECTIVE_TYPE_LONG_DOUBLE:
		/* no mapping to 128-bit quadruple precision */
	  default:
		fca_type = FCA_DTYPE_LAST+1; /* unsupported */
		break;
        }
	return fca_type;
}

static int fca_dsize( enum dat_ib_collective_data_type type )
{
	int type_size;

	switch (type) {
	  case DAT_IB_COLLECTIVE_TYPE_INT8:
	  case DAT_IB_COLLECTIVE_TYPE_UINT8:
		type_size = sizeof(uint8_t);
		break;
	  case DAT_IB_COLLECTIVE_TYPE_INT16:
	  case DAT_IB_COLLECTIVE_TYPE_UINT16:
		type_size = sizeof(uint16_t);
		break;
	  case DAT_IB_COLLECTIVE_TYPE_INT32:
	  case DAT_IB_COLLECTIVE_TYPE_UINT32:
		type_size = sizeof(uint32_t);
		break;
	  case DAT_IB_COLLECTIVE_TYPE_INT64:
	  case DAT_IB_COLLECTIVE_TYPE_UINT64:
		type_size = sizeof(uint64_t);
		break;
	  case DAT_IB_COLLECTIVE_TYPE_FLOAT:
		type_size = sizeof(float);
		break;
	  case DAT_IB_COLLECTIVE_TYPE_DOUBLE:
		type_size = sizeof(double);
		break;
	  case DAT_IB_COLLECTIVE_TYPE_LONG_DOUBLE:
		type_size = sizeof(long double);
		break;
	  default:
		type_size = 0;
		break;
        }

	return type_size;
}
static int fca_op( enum dat_ib_collective_reduce_data_op op )
{
	int fop = 0;

	switch (op) {
	  case DAT_IB_COLLECTIVE_REDUCE_OP_MAX:   fop = FCA_OP_MAX; break;
	  case DAT_IB_COLLECTIVE_REDUCE_OP_MIN:   fop = FCA_OP_MIN; break;
	  case DAT_IB_COLLECTIVE_REDUCE_OP_SUM:	  fop = FCA_OP_SUM; break;
	  case DAT_IB_COLLECTIVE_REDUCE_OP_PROD:  fop = FCA_OP_PROD; break;
	  case DAT_IB_COLLECTIVE_REDUCE_OP_LAND:  fop = FCA_OP_LAND; break;
	  case DAT_IB_COLLECTIVE_REDUCE_OP_BAND:  fop = FCA_OP_BAND; break;
	  case DAT_IB_COLLECTIVE_REDUCE_OP_LOR:   fop = FCA_OP_LOR; break;
	  case DAT_IB_COLLECTIVE_REDUCE_OP_BOR:   fop = FCA_OP_BOR; break;
	  case DAT_IB_COLLECTIVE_REDUCE_OP_LXOR:  fop = FCA_OP_LXOR; break;
	  case DAT_IB_COLLECTIVE_REDUCE_OP_BXOR:  fop = FCA_OP_BXOR; break;
	  case DAT_IB_COLLECTIVE_REDUCE_OP_MAXLOC:fop = FCA_OP_MAXLOC; break;
	  case DAT_IB_COLLECTIVE_REDUCE_OP_MINLOC:fop = FCA_OP_MINLOC; break;
        }
	return fop;
}

/* Progress function for consumer
 * Will be called from FCA collective operation context
 * periodically if FCA blocks there for too long.
 * Don't call with scheduled non-blocking operations
 */
void my_progress(void *arg)
{
	ib_hca_transport_t *tp = (ib_hca_transport_t *) arg;

	if ((tp->user_func) && (tp->t_id != dapl_os_gettid()) ) {
		dapl_log(DAPL_DBG_TYPE_THREAD, "calling progress_func(%p)\n",tp);
		(*tp->user_func)();
	}
}

/* forward prototypes */
DAT_RETURN dapli_free_collective_member(IN DAT_IA_HANDLE ia,
					IN DAT_IB_COLLECTIVE_MEMBER member);

/******************* Internal Collective Calls **************************/

static int create_service(struct dapl_hca *hca)
{
	ib_hca_transport_t *tp = &hca->ib_trans;
	struct fca_init_spec *fca_spec;
	struct fca_context *ctx;
	FILE *fp;
	int ret;

	/* create an empty spec file if it does not exist */
	fp = fopen(fca_specfile, "r");
	if (fp==NULL)
		fp = fopen(fca_specfile, "w");
	if (fp)
		fclose(fp);

	dapl_log(DAPL_DBG_TYPE_EXTENSION, "create_service: enter(%p)\n", tp);

	/* Read INI file into global structures before setting any spec */
	fca_spec = fca_parse_spec_file(fca_specfile);
	if (fca_spec == NULL)
		return 1;

	dapl_log(DAPL_DBG_TYPE_EXTENSION, "  fca_init_spec\n");
	fca_spec->element_type = FCA_ELEMENT_RANK;
        fca_spec->job_id = 0;
        fca_spec->rank_id = 0;
 	fca_spec->progress.func = my_progress;
	fca_spec->progress.arg = tp;
	if ((ret = fca_init(fca_spec, &ctx)))
		return 1;

	fca_free_init_spec(fca_spec);
	tp->m_ctx = ctx;

	return 0;
}

static int create_member(struct dapl_hca *hca)
{
	ib_hca_transport_t *tp = &hca->ib_trans;
	int size, ret = EFAULT;
	unsigned short lport = DAT_COLL_SID;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		 " create_member: tp=%p, ctx=%p\n", tp, tp->m_ctx);

	if (!tp->m_ctx)
		goto bail;

	/* FCA address information */
	tp->f_info = fca_get_rank_info(tp->m_ctx, &size);
	if (!tp->f_info) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			"create_member: fca_get_rank_info() ERR ret=%s ctx=%p\n",
			strerror(errno), tp->m_ctx);
		ret = errno;
		goto err;
	}

	tp->m_info = malloc(sizeof(DAT_SOCK_ADDR) + size);
	if (!tp->m_info) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			"create_member: malloc() ERR ret=%s ctx=%p\n",
			strerror(errno), tp->m_ctx);
		fca_free_rank_info(tp->f_info);
		goto err;
	}
	dapl_os_memzero(tp->m_info, sizeof(DAT_SOCK_ADDR) + size);

	if ((tp->l_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			"create_member: socket() ERR ret=%s \n",
			strerror(errno));
		ret = errno;
		goto err;
	}

	dapl_log(DAPL_DBG_TYPE_EXTENSION, " create_member listen socket\n");

	/*
	 * only rank0 needs listen, but we don't know who is rank0 yet.
	 * Everyone listen, start on seed port until find one unused
	 */
#ifdef _OPENIB_UCM_
	if (getlocalipaddr((char*)&tp->m_addr, sizeof(DAT_SOCK_ADDR))) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			"create_member: getlocaladdr ERR ret=%s \n", strerror(errno));
		ret = errno;
		goto err;
	}
	dapl_log(DAPL_DBG_TYPE_EXTENSION, " create_member: UCM local addr %s\n",
			inet_ntoa(((struct sockaddr_in *)&tp->m_addr)->sin_addr));
#else
	memcpy((void*)&tp->m_addr, (void*)&hca->hca_address, sizeof(DAT_SOCK_ADDR));
#endif

	do {
		tp->m_addr.sin_port = htons(lport++);
		ret = bind(tp->l_sock,
			   (struct sockaddr *)&tp->m_addr,
			   sizeof(DAT_SOCK_ADDR));

	} while (ret == -1 && errno == EADDRINUSE);

	if (ret == -1)
		goto err;

	if ((ret = listen(tp->l_sock, 1024)) < 0)
		goto err;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		"create_member: listen port 0x%x,%d \n",
		ntohs(tp->m_addr.sin_port),
		ntohs(tp->m_addr.sin_port));

	/* local fca_info and sock_addr to member buffer for MPI exchange */
	tp->f_size = size;
	tp->m_size = size + sizeof(DAT_SOCK_ADDR);
	memcpy(tp->m_info, tp->f_info, size);
	memcpy( ((char*)tp->m_info + size), &tp->m_addr, sizeof(DAT_SOCK_ADDR));

	/* free rank info after getting */
	fca_free_rank_info(tp->f_info);
	tp->f_info = NULL;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		 "create_member: m_ptr=%p, sz=%d exit SUCCESS\n",
		 tp->m_info, tp->m_size);

	return 0;
err:
	/* cleanup */
	if (tp->f_info) {
		fca_free_rank_info(tp->f_info);
		tp->f_info = NULL;
	}

	if (tp->m_info) {
		free(tp->m_info);
		tp->m_info = NULL;
	}
	if (tp->l_sock > 0)
		close(tp->l_sock);
bail:
	return 1;
}

static void create_group(struct coll_group *group)
{
 	int *conn = group->conn;
	int i, g_id, ret = 0;
	DAT_IB_EXTENSION_EVENT_DATA eventx;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		 " create_grp[%d]: group=%p, id=%d\n",
		 group->self, group, group->id);

	/* group creation event */
	eventx.status = DAT_IB_COLL_COMP_ERR;
	eventx.type = DAT_IB_COLLECTIVE_CREATE_DATA;
	eventx.coll.handle = NULL;
	eventx.coll.context = group->user_context;

	/* Create and distribute group info and close connections*/
	if (group->self == 0) {

		/* accept and send all ranks comm_desc info */
		for (i = 1; i < group->ranks; ) {
			/* check for queue'd group id request */
			conn[i] = grp_req_dequeue(group->id);
			if (conn[i] < 0) {
				conn[i] = accept(group->tp->l_sock, NULL, NULL);
				if (conn[i] < 0)
					goto error;

				/* Validate ID from ranks, all ranks have comm_desc */
				ret = recv(conn[i], &g_id, sizeof(g_id), 0);
				if ((ret < 0) || (ret != sizeof(g_id))) {
					dapl_log(DAPL_DBG_TYPE_ERR,
						 " create_grp[0]: rcv g_id ERR:\n");
					goto error;
				}
				/* no match, queue it for other response */
				if (g_id != group->id) {
					dapl_log(DAPL_DBG_TYPE_WARN,
						 " create_grp[0]:"
						 " rcv g_id %d != g_id %d\n",
						 g_id, group->id);
					grp_req_queue(g_id, conn[i]);
					continue; /* try conn[i] again */
				}
				dapl_log(DAPL_DBG_TYPE_EXTENSION,
					 " create_grp[0]: rcv g_id %d == g_id %d\n",
					 g_id, group->id);
			}

			/* Group match, send back FCA comm_desc information */
			ret = send(conn[i], &group->comm_desc, sizeof(group->comm_desc), 0);
			if (ret < 0) {
				dapl_log(DAPL_DBG_TYPE_ERR,
					 " create_grp[0]: snd %d comm: ERR:\n", i);
				goto error;
			}
			i++; /* next rank */
		}

		/* all have comm_desc, close all sockets */
		for (i = 1; i < group->ranks; ++i)
			close(conn[i]);

	} else {

		/* first group addr_info entry is rank 0 */
		dapl_log(DAPL_DBG_TYPE_EXTENSION,
			 " create_grp[%d]: connect -> %s 0x%x \n",
			 group->self, inet_ntoa(group->addr_info->sin_addr),
			 ntohs(group->addr_info->sin_port));

		group->sock = socket(AF_INET, SOCK_STREAM, 0);
		if (group->sock < 0) {
			dapl_log(DAPL_DBG_TYPE_ERR,
				 " create_grp: socket() ERR: %s\n",
				 strerror(errno));
			goto error;
		}
		ret = connect(group->sock,
			      (struct sockaddr *)group->addr_info,
			      sizeof(*group->addr_info));
		if (ret < 0) {
			dapl_log(DAPL_DBG_TYPE_ERR,
				 " create_grp: connect() ERR: %s\n",
				 strerror(errno));
			goto error;
		}
		/* send group ID to identify with multiple groups */
		ret = send(group->sock, &group->id, sizeof(group->id), 0);
		if (ret < 0) {
			dapl_log(DAPL_DBG_TYPE_ERR,
				 " create_grp: snd() ERR: %s g_id = %d\n",
				 strerror(errno), group->id);
			goto error;
		}

		/* recv FCA comm_desc for this group ID */
		ret = recv(group->sock, &group->comm_desc, sizeof(group->comm_desc), 0);
		if ((ret < 0) || (ret != sizeof(group->comm_desc))) {
			dapl_log(DAPL_DBG_TYPE_ERR,
				 " create_grp: recv() ERR: %s \n",
				 strerror(errno));
			goto error;
		}

		/* cleanup socket resources */
		close(group->sock);
		group->sock = 0;
	}

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		" create_grp[%d]: fca_comm_init_spec() ranks=%d comm_id=0x%04x"
		" job_id=0x%lx m_type %d grp_id=%d\n",
		group->self, group->ranks, group->comm_desc.comm_id,
		group->comm_desc.job_id, group->comm_desc.comm_maddr.type,
		group->id);

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		" create_grp[%d]: fca_comm_init_spec() m_addr -> "
		"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
		"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		group->self,group->comm_desc.comm_maddr.data[0],
		group->comm_desc.comm_maddr.data[1],
		group->comm_desc.comm_maddr.data[2],group->comm_desc.comm_maddr.data[3],
		group->comm_desc.comm_maddr.data[4],group->comm_desc.comm_maddr.data[5],
		group->comm_desc.comm_maddr.data[6],group->comm_desc.comm_maddr.data[7],
		group->comm_desc.comm_maddr.data[8],group->comm_desc.comm_maddr.data[9],
		group->comm_desc.comm_maddr.data[10],group->comm_desc.comm_maddr.data[11],
		group->comm_desc.comm_maddr.data[12],group->comm_desc.comm_maddr.data[13],
		group->comm_desc.comm_maddr.data[14],group->comm_desc.comm_maddr.data[15],
		group->comm_desc.comm_maddr.data[16],group->comm_desc.comm_maddr.data[17],
		group->comm_desc.comm_maddr.data[18],group->comm_desc.comm_maddr.data[19],
		group->comm_desc.comm_maddr.data[20],group->comm_desc.comm_maddr.data[21],
		group->comm_desc.comm_maddr.data[22],group->comm_desc.comm_maddr.data[23],
		group->comm_desc.comm_maddr.data[24],group->comm_desc.comm_maddr.data[25],
		group->comm_desc.comm_maddr.data[26],group->comm_desc.comm_maddr.data[27],
		group->comm_desc.comm_maddr.data[28],group->comm_desc.comm_maddr.data[29],
		group->comm_desc.comm_maddr.data[30],group->comm_desc.comm_maddr.data[31]);

	/* init communicator, node p_idx and procs, total ranks, all ranks */
	group->comm_init.desc = group->comm_desc;
	group->comm_init.rank = group->self;
	group->comm_init.size = group->ranks;
	group->comm_init.proc_idx = group->g_info.local_rank;
	group->comm_init.num_procs = group->g_info.local_size;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		" create_grp[%d]: fca_comm_init() ranks=%d local_rank=%d, local_size%d\n",
		group->self, group->ranks, group->g_info.local_rank, group->g_info.local_size);

	if (fca_comm_init(group->ctx, &group->comm_init, &group->comm)) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " create_grp: fca_comm_init() ERR: %s",
			 strerror(errno));
		goto error;
	}
	fca_comm_get_caps(group->comm, &group->comm_caps);

	eventx.status = DAT_OP_SUCCESS;
	eventx.coll.handle = group;

error:
	dapls_evd_post_event_ext(group->evd, DAT_IB_COLLECTIVE_EVENT, 0, (DAT_UINT64*)&eventx);
	if (eventx.status != DAT_OP_SUCCESS)
		dapli_free_collective_group((DAT_IB_COLLECTIVE_HANDLE)group);

	return;
}

/* worker thread to support non-blocking group creations and operations  */
static void coll_thread(void *arg)
{
	struct coll_group *grp, *next;
	struct dapl_hca *hca = (struct dapl_hca*)arg;
	ib_hca_transport_t *tp = &hca->ib_trans;

	dapl_os_lock(&tp->coll_lock);
	tp->coll_thread_state = IB_THREAD_RUN;
	tp->t_id = dapl_os_gettid();

	if (create_service(hca))
		goto err;

	if (create_member(hca))
		goto err;

	while (tp->coll_thread_state == IB_THREAD_RUN) {

		dapl_os_unlock(&tp->coll_lock);
		dapl_os_wait_object_wait(&tp->coll_event,
					 DAT_TIMEOUT_INFINITE);

		if (!dapl_llist_is_empty(&tp->grp_list))
			next = dapl_llist_peek_head(&tp->grp_list);
		else
			next = NULL;

		while (next) {
			grp = next;
			create_group(grp);

			next = dapl_llist_next_entry(&tp->grp_list,
						    (DAPL_LLIST_ENTRY *)
						    &grp->list_entry);
			dapl_llist_remove_entry(&tp->grp_list,
						(DAPL_LLIST_ENTRY *)
						&grp->list_entry);
		}
		dapl_os_lock(&tp->coll_lock);
	}
err:
	tp->coll_thread_state = IB_THREAD_EXIT;
	dapl_os_unlock(&tp->coll_lock);
}

static DAT_RETURN coll_thread_init(struct dapl_hca *hca)
{
	DAT_RETURN dat_status;
	ib_hca_transport_t *tp = &hca->ib_trans;

	dapl_os_lock(&tp->coll_lock);
	if (tp->coll_thread_state != IB_THREAD_INIT) {
		dapl_os_unlock(&tp->coll_lock);
		return DAT_SUCCESS;
	}
	tp->coll_thread_state = IB_THREAD_CREATE;
	dapl_os_unlock(&tp->coll_lock);

	/* thread to process group comm creation */
	dat_status = dapl_os_thread_create(coll_thread, (void*)hca, &tp->coll_thread);
	if (dat_status != DAT_SUCCESS)
		return (dapl_convert_errno(errno,
					   "create_coll_thread ERR:"
					   " check resource limits"));
	/* wait for thread to start */
	dapl_os_lock(&tp->coll_lock);
	while (tp->coll_thread_state != IB_THREAD_RUN) {
		dapl_os_unlock(&tp->coll_lock);
		dapl_os_sleep_usec(2000);
		dapl_os_lock(&tp->coll_lock);
	}
	dapl_os_unlock(&tp->coll_lock);

	return DAT_SUCCESS;
}

static void coll_thread_destroy(struct dapl_hca *hca)
{
	ib_hca_transport_t *tp = &hca->ib_trans;

	dapl_os_lock(&tp->coll_lock);
	if (tp->coll_thread_state != IB_THREAD_RUN)
		goto bail;

	tp->coll_thread_state = IB_THREAD_CANCEL;
	while (tp->coll_thread_state != IB_THREAD_EXIT) {
		dapl_os_wait_object_wakeup(&tp->coll_event);
		dapl_os_unlock(&tp->coll_lock);
		dapl_os_sleep_usec(2000);
		dapl_os_lock(&tp->coll_lock);
	}
bail:
	dapl_os_unlock(&tp->coll_lock);
}

/******************* External Collective Calls **************************/

/* Create context for FCA, get adapter and port from hca_ptr */
int dapli_create_collective_service(IN struct dapl_hca *hca)
{
	ib_hca_transport_t *tp = &hca->ib_trans;

	dapl_os_lock_init(&tp->coll_lock);
	dapl_llist_init_head(&tp->grp_list);
	dapl_os_wait_object_init(&tp->coll_event);

	/* non-blocking, FCA calls in work thread */
	if (coll_thread_init(hca))
		return 1;

	return 0;
}

void dapli_free_collective_service(IN struct dapl_hca *hca)
{
	ib_hca_transport_t *tp = &hca->ib_trans;

	if (tp->m_ctx) {
		fca_cleanup(tp->m_ctx);
		tp->m_ctx = NULL;
	}

	coll_thread_destroy(hca);
	dapl_os_wait_object_destroy(&tp->coll_event);
}

DAT_RETURN
dapli_create_collective_member( IN  DAT_IA_HANDLE ia,
				IN  void *progress_func,
				OUT DAT_COUNT *member_size,
				OUT DAT_IB_COLLECTIVE_MEMBER *member )
{
	struct dapl_hca *hca = ((DAPL_IA*)ia)->hca_ptr;
	ib_hca_transport_t *tp = &hca->ib_trans;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		"create_member: hca=%p, psz=%p pmem=%p tp=%p, ctx=%p\n",
		hca, member_size, member, tp, tp->m_ctx);

	if (!tp->m_ctx)
		return DAT_INVALID_PARAMETER;

	/* copy out member info, initialized in create_service */
	*member_size = tp->m_size;
	*member = tp->m_info;

	/* set the progress function, called during long offload delays */
	tp->user_func = progress_func;

	return DAT_SUCCESS;
}

DAT_RETURN
dapli_free_collective_member( IN DAT_IA_HANDLE ia,
			      IN DAT_IB_COLLECTIVE_MEMBER member )
{
	struct dapl_hca *hca = ((DAPL_IA*)ia)->hca_ptr;
	ib_hca_transport_t *tp = &hca->ib_trans;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		"free_member: enter hca=%p, member=%p \n",
		hca, member);

	if ((member == NULL) || (member != tp->m_info))
		return DAT_INVALID_PARAMETER;

	/* release FCA info */
	if (tp->f_info) {
		fca_free_rank_info(tp->f_info);
		tp->f_info = NULL;
	}

	/* free member buffer */
	if (tp->m_info) {
		free(tp->m_info);
		tp->m_info = NULL;
	}

	if (tp->l_sock > 0)
		close(tp->l_sock);

	return DAT_SUCCESS;
}

/*
 * This asynchronous call initiates the process of creating a collective 
 * group and must be called by all group members. The collective_group 
 * argument points to an array of address/connection qualifier pairs that 
 * identify the members of the group in rank order. The group_size argument 
 * specifies the size of the group and therefore the size of the coll_group 
 * array.  The self argument identifies the rank of the caller.  
 * The group_id argument specifies a network-unique identifier for this 
 * instance of the collective group.  All members of the group must specify 
 * the same group_id value for the same collective instance. The evd_handle 
 * argument specifies the EVD used for all asynchronous collective completions 
 * including this call. The user_context argument will be returned in the 
 * DAT_EXT_COLLECTIVE_CREATE_DATA event.
 *
 * On a successful completion, each group member will receive a 
 * DAT_EXT_COLLECTIVE_CREATE_DATA event on the EVD specified by evd_handle. 
 * The event contains the collective handle, the rank of the receiving 
 * endpoint within the collective group, the size of the group, and the 
 * caller specified user_context. The returned collective handle can be used 
 * in network clock, multicast, and other collective operations.
 *
 * Multiple collective groups can be defined and an endpoint may belong 
 * to more than one collective group. 
 */
DAT_RETURN
dapli_create_collective_group(
	IN  DAT_EVD_HANDLE		evd_handle,
	IN  DAT_PZ_HANDLE		pz,
	IN  DAT_IB_COLLECTIVE_MEMBER	*members,
	IN  DAT_COUNT			ranks,
	IN  DAT_IB_COLLECTIVE_RANK	self,
	IN  DAT_IB_COLLECTIVE_ID	id,
	IN  DAT_IB_COLLECTIVE_GROUP	*g_info,
	IN  DAT_CONTEXT			user_ctx)
{
	DAPL_EVD *evd = (DAPL_EVD*)evd_handle;
	DAPL_IA *ia;
	ib_hca_transport_t *tp;
	struct coll_group *group;
	DAT_RETURN dat_status;
	int i;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		" dapli create_grp[%d]: enter evd=%p cq=%p pz=%p "
		"m=%p *m=%p t_ranks=%d g_id=%d l_idx=%d l_ranks=%d\n",
		self, evd, evd->ib_cq_handle, pz,
		members, *members, ranks, id, g_info->local_rank,
		g_info->local_size);

	/* Validate EVD handle, extended flag MUST be set */
	if (DAPL_BAD_HANDLE(evd, DAPL_MAGIC_EVD) || 
	    DAPL_BAD_HANDLE(pz, DAPL_MAGIC_PZ))
		return(dapl_convert_errno(EINVAL, " coll_grp"));

	ia = (DAPL_IA*)evd->header.owner_ia;
	tp = &ia->hca_ptr->ib_trans;

	/* Allocate group object */
	group = (struct coll_group *)dapl_os_alloc(sizeof(*group));
	if (!group)
		return(dapl_convert_errno(ENOMEM," create_grp"));
	dapl_os_memzero(group, sizeof(*group));

	/* Initialize the header and save group info, COLLECTIVE handle */
	group->header.provider = ia->header.provider;
	group->header.handle_type = DAT_IB_HANDLE_TYPE_COLLECTIVE;
	group->header.magic = DAPL_MAGIC_COLL;
	group->header.owner_ia = ia;
	group->user_context = user_ctx;
	group->evd = (DAPL_EVD*)evd;
	group->pz = (DAPL_PZ*)pz;
	group->ranks = ranks;
	group->id = id;
	group->self = self;
	group->ctx = tp->m_ctx;
	group->tp = tp;

	/* Rank0 connected sockets for group, to exchange information */
	if (self == 0) {
		group->conn = (int *)dapl_os_alloc(ranks * sizeof(*group->conn));
		if (group->conn == NULL)
			return(dapl_convert_errno(ENOMEM," create_grp connections"));
		dapl_os_memzero(group->conn, ranks * sizeof(*group->conn));
	}

	/* need FCA information in array for new comm group call */
	group->fca_info = dapl_os_alloc(ranks * tp->f_size);
	if (!group->fca_info ) {
		dapl_os_free(group, sizeof(struct coll_group));
		return(dapl_convert_errno(ENOMEM," create_grp fca_info"));
	}
	dapl_os_memzero(group->fca_info, ranks * tp->f_size);

	/* need FCA information in array for new comm group call */
	group->addr_info = (struct sockaddr_in*)dapl_os_alloc(ranks * sizeof(struct sockaddr_in));
	if (!group->addr_info) {
		dapl_os_free(group->fca_info, ranks * tp->f_size);
		dapl_os_free(group, sizeof(struct coll_group));
		return(dapl_convert_errno(ENOMEM," create_grp fca_info"));
	}
	dapl_os_memzero(group->addr_info, ranks * sizeof(struct sockaddr_in));
	
	/* Separate group member info into Address and FCA arrays */
	for (i=0; i<ranks; i++) {
		memcpy((void*) ((char*)group->fca_info + (i * tp->f_size)),
		       (void*) *(members + i),
		       tp->f_size);
		memcpy((void*) ((char*)group->addr_info + (i * sizeof(struct sockaddr_in))),
		       (void*) ((char*)(*(members + i)) + tp->f_size),
		       sizeof(struct sockaddr_in));
	}

	/* Intranode and Internode process layout info */
	group->g_info = *g_info;

	if (group->self == 0) {
		/* rank 0 - create new communicator */
		group->comm_new.rank_info = group->fca_info;
		group->comm_new.rank_count = group->ranks;
		group->comm_new.is_comm_world = 0; /* FIX */

		dapl_log(DAPL_DBG_TYPE_EXTENSION,
			 " create_grp[%d]: calling comm_new..\n", group->self);

		if (fca_comm_new(group->ctx, &group->comm_new, &group->comm_desc)) {
			dapl_log(DAPL_DBG_TYPE_ERR,
				 " create_grp: fca_comm_new() ERR: %s",
				 strerror(errno));
			dat_status = dapl_convert_errno(errno, " fca_comm_new");
			goto error;
		}
	}

	/* initialize all lists, events, etc */
	dapl_llist_init_entry((DAPL_LLIST_ENTRY *)&group->list_entry);
	dapl_llist_init_head(&group->op_free);
	dapl_llist_init_head(&group->op_pend);
	dapl_os_wait_object_init(&group->op_event);

	/* allocate object pool for non-blocking collective operations */
	group->op_pool = (struct coll_op *)dapl_os_alloc(sizeof(struct coll_op) * COLL_OP_CNT);
	if (!group->op_pool)
		return(dapl_convert_errno(ENOMEM," create_grp"));
	dapl_os_memzero(group->op_pool, sizeof(*group));

	/* non-blocking, schedule on work thread */
	dapl_os_lock(&tp->coll_lock);
	dapl_llist_add_tail(&tp->grp_list, (DAPL_LLIST_ENTRY *)&group->list_entry, group);
	dapl_os_unlock(&tp->coll_lock);
	dapl_os_wait_object_wakeup(&tp->coll_event);

	return DAT_SUCCESS;	
error:
	/* clean up partial group */
	dapli_free_collective_group((DAT_IB_COLLECTIVE_HANDLE)group);
	return(dat_status);
};


/* 
 * This synchronous call destroys a previously created collective group 
 * associated with the collective_handle argument.  Any pending or 
 * in-process requests associated with the collective group will be 
 * terminated and be posted to the appropriate EVD.
 */
DAT_RETURN
dapli_free_collective_group(
        IN DAT_IB_COLLECTIVE_HANDLE	coll_handle)
{
	struct coll_group *group = (struct coll_group *)coll_handle;

	if (DAPL_BAD_HANDLE(coll_handle, DAPL_MAGIC_COLL))
		return(dapl_convert_errno(EINVAL, " free_grp"));

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
                 " free_coll_group[%d]: pz=%p gp=%p complete!\n",
		 group->self, group->pz, group );

	/* reset magic and free memory */
	group->header.magic = DAPL_MAGIC_INVALID;

	/* free client socket resources */
	if (group->sock)
		close(group->sock);

	if (group->conn)
		dapl_os_free(group->conn,
			     group->ranks *
			     sizeof(*group->conn));

	/* FCA and address info arrays */
	if (group->fca_info)
		dapl_os_free(group->fca_info,
			     group->ranks *
			     group->tp->m_size);
	if (group->addr_info)
		dapl_os_free(group->addr_info,
			     group->ranks *
			     group->tp->m_size);

	if (group->comm)
		fca_comm_destroy(group->comm);

	if (group->self == 0)
		fca_comm_end(group->ctx, group->comm_desc.comm_id);

	dapl_os_free(group, sizeof(struct coll_group));

	return DAT_SUCCESS;
};

/* 
 * This call will synchronize all endpoints of the collective
 * group specified by coll_handle. This is an asynchronous call that 
 * will post a completion to the collective EVD when all endpoints 
 * have synchronized. 
 */
DAT_RETURN
dapli_collective_barrier(
        IN DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN DAT_DTO_COOKIE		user_context,
        IN DAT_COMPLETION_FLAGS		comp_flags)
{
	DAT_IB_EXTENSION_EVENT_DATA eventx;
	struct coll_group *group = (struct coll_group *)coll_handle;
	int ret;
	
	if (DAPL_BAD_HANDLE(coll_handle, DAPL_MAGIC_COLL))
		return(dapl_convert_errno(EINVAL, " barrier"));

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		" coll_barrer: grp_hndl=%p u_ctx=%llx flgs=%d\n",
		coll_handle, user_context, comp_flags);

	ret = fca_do_barrier(group->comm);
	if (ret < 0)
		return(dapl_convert_errno(-ret, " fca_barrier"));

	/* setup and post successful barrier, make sync for now */
	eventx.type = DAT_IB_COLLECTIVE_BARRIER_STATUS;
	eventx.status = DAT_OP_SUCCESS;
	eventx.coll.handle = group;
	eventx.coll.context = user_context;
	dapls_evd_post_event_ext(group->evd, DAT_IB_COLLECTIVE_EVENT, 0, (DAT_UINT64*)&eventx);

	return DAT_SUCCESS;
};

/* 
 * This call performs a broadcast send operation that transfers
 * data specified by the buffer argument of the root into the buffer argument 
 * of all other endpoints in the collective group specified by coll_handle.  
 * The operation is completed on the collective EVD unless completions are 
 * suppressed through the completion flags.  All broadcasts are considered 
 * �in place� transfers.  The tables below show the result of a broadcast 
 * operation. 
 */
DAT_RETURN
dapli_collective_broadcast(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			buffer,
 	IN  DAT_COUNT			byte_count,
	IN  DAT_IB_COLLECTIVE_RANK	root,
	IN  DAT_CONTEXT			user_context,
	IN  DAT_COMPLETION_FLAGS	comp_flags)
{
	DAT_IB_EXTENSION_EVENT_DATA eventx;
	struct coll_group *group = (struct coll_group *)coll_handle;
	struct fca_bcast_spec bcast;
	int ret;

	if (DAPL_BAD_HANDLE(coll_handle, DAPL_MAGIC_COLL))
		return(dapl_convert_errno(EINVAL, " fca_bcast"));

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		 " coll_bcast[%d]: group=%p buf=%p size=%d root=%d"
		 " ctxt=%llx flgs=%d\n",
		 group->self, coll_handle, buffer, byte_count, root,
		 user_context, comp_flags );

	/* Run FCA BCAST, if  */
	bcast.root = root;
	bcast.buf = buffer;
	bcast.size = byte_count;

	ret = fca_do_bcast(group->comm, &bcast);
	if (ret < 0)
		return(dapl_convert_errno(-ret, " fca_bcast"));

	/* setup and post successful bcast, make sync for now */
	eventx.type = DAT_IB_COLLECTIVE_BROADCAST_STATUS;
	eventx.status = DAT_OP_SUCCESS;
	eventx.coll.handle = group;
	eventx.coll.context = user_context;
	dapls_evd_post_event_ext(group->evd, DAT_IB_COLLECTIVE_EVENT, 0, (DAT_UINT64*)&eventx);

	return DAT_SUCCESS;
};


DAT_RETURN
dapli_collective_reduce(
	IN  DAT_IB_COLLECTIVE_HANDLE		coll_handle,
	IN  DAT_PVOID				snd_buf,
 	IN  DAT_COUNT				snd_len,
	IN  DAT_PVOID				rcv_buf,
 	IN  DAT_COUNT				rcv_len,
	IN  DAT_IB_COLLECTIVE_REDUCE_DATA_OP	op,
	IN  DAT_IB_COLLECTIVE_DATA_TYPE		type,
	IN  DAT_IB_COLLECTIVE_RANK		root,
	IN  DAT_CONTEXT				user_context,
	IN  DAT_COMPLETION_FLAGS		comp_flags)
{
	DAT_IB_EXTENSION_EVENT_DATA eventx;
	struct coll_group *group = (struct coll_group *)coll_handle;
	fca_reduce_spec_t reduce;
	int ret;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		 " coll_reduce[%d]: group=%p sbuf=%p slen=%d rbuf=%p rlen=%d"
		 " root=%d op=%d type=%d ctxt=%llx cflgs=%d\n",
		 group->self, coll_handle, snd_buf, snd_len,
		 rcv_buf, rcv_len, root, op, type,
		 user_context, comp_flags );

	if (DAPL_BAD_HANDLE(coll_handle, DAPL_MAGIC_COLL))
		return(dapl_convert_errno(EINVAL, " reduce"));

	reduce.root = root;
	reduce.sbuf = snd_buf;
	reduce.rbuf = rcv_buf;
	reduce.buf_size = snd_len; /* bytes */
	reduce.dtype = fca_dtype(type);
	reduce.length = snd_len/fca_dsize(type);  /* bytes to elements */
	reduce.op = fca_op(op);

	if (group->self == root && snd_buf == NULL) /* MPI_IN_PLACE */
		reduce.sbuf = rcv_buf;

	ret = fca_do_reduce(group->comm, &reduce);
	if (ret < 0)
		return(dapl_convert_errno(-ret, " fca_reduce"));

	/* setup and post successful reduce, make sync for now */
	eventx.type = DAT_IB_COLLECTIVE_REDUCE_STATUS;
	eventx.status = DAT_OP_SUCCESS;
	eventx.coll.handle = group;
	eventx.coll.context = user_context;
	dapls_evd_post_event_ext(group->evd, DAT_IB_COLLECTIVE_EVENT, 0, (DAT_UINT64*)&eventx);

	return DAT_SUCCESS;
}

DAT_RETURN
dapli_collective_allreduce(
	IN  DAT_IB_COLLECTIVE_HANDLE		coll_handle,
	IN  DAT_PVOID				snd_buf,
 	IN  DAT_COUNT				snd_len,
	IN  DAT_PVOID				rcv_buf,
 	IN  DAT_COUNT				rcv_len,
	IN  DAT_IB_COLLECTIVE_REDUCE_DATA_OP	op,
	IN  DAT_IB_COLLECTIVE_DATA_TYPE		type,
	IN  DAT_CONTEXT				user_context,
	IN  DAT_COMPLETION_FLAGS		comp_flags)
{
	DAT_IB_EXTENSION_EVENT_DATA eventx;
	struct coll_group *group = (struct coll_group *)coll_handle;
	fca_reduce_spec_t reduce;
	int ret;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		 " coll_allreduce[%d]: group=%p sbuf=%p slen=%d,%d rbuf=%p rlen=%d"
		 " op=%d type=%d ctxt=%llx cflgs=%d\n",
		 group->self, coll_handle, snd_buf, snd_len,
		 snd_len/fca_dsize(type),
		 rcv_buf, rcv_len, op, type,
		 user_context, comp_flags );

	reduce.root = 0; /* ignored for allreduce */  
	reduce.sbuf = snd_buf;
	reduce.rbuf = rcv_buf;
	reduce.buf_size = snd_len; /* bytes */
	reduce.dtype = fca_dtype(type);
	reduce.length = snd_len/fca_dsize(type);  /* bytes to elements */
	reduce.op = fca_op(op);

	if (snd_buf == NULL) /* MPI_IN_PLACE */
		reduce.sbuf = rcv_buf;

	ret = fca_do_all_reduce(group->comm, &reduce);
	if (ret < 0)
		return(dapl_convert_errno(-ret, " fca_allreduce"));

	/* setup and post successful reduce, make sync for now */
	eventx.type = DAT_IB_COLLECTIVE_ALLREDUCE_STATUS;
	eventx.status = DAT_OP_SUCCESS;
	eventx.coll.handle = group;
	eventx.coll.context = user_context;
	dapls_evd_post_event_ext(group->evd, DAT_IB_COLLECTIVE_EVENT, 0, (DAT_UINT64*)&eventx);

	return DAT_SUCCESS;
}

/*
 * This call performs a scatter of the data specified by the
 * send_buffer argument to the collective group specified by coll_handle.  
 * Data is received in the buffer specified by the recv_buffer argument.  
 * The recv_byte_count argument specifies the size of the receive buffer.  
 * Data from the root send_buffer will be divided by the number of members 
 * in the collective group to form equal and contiguous memory partitions.  
 * Each member of the collective group will receive its rank relative 
 * partition.  An error is returned if the send_byte_count does not describe 
 * memory that can be evenly divided by the size of the collective group.  
 * An �in place� transfer for the root rank can be indicated by passing NULL 
 * as the recv_buffer argument. The send_buffer and send_byte_count 
 * arguments are ignored on non-root members. The operation is completed on 
 * the collective EVD unless completions are suppressed through the 
 * completion flags.
 */
DAT_RETURN
dapli_collective_scatter(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			rcv_buf,
 	IN  DAT_COUNT			rcv_len,
	IN  DAT_IB_COLLECTIVE_RANK	root,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags)
{
	return DAT_NOT_IMPLEMENTED;
}

/*
 * This call performs a non-uniform scatter of the data
 * specified by the send_buffers array argument to the collective group 
 * specified by coll_handle.  The send_buffers array contains one buffer 
 * pointer for each member of the collective group, in rank order. 
 * The send_byte_counts array contains a byte count for each corresponding 
 * send buffer pointer.  The recv_buffer and recev_byte_count arguments 
 * specify where received portions of the scatter are to be received.  
 * An �in place� transfer for the root rank can be indicated by passing 
 * NULL as the recv_buffer argument. The send_buffers and send_byte_counts 
 * arguments are ignored on non-root members.  The operation is completed 
 * on the collective EVD unless completions are suppressed through the 
 * completion flags.
 */
DAT_RETURN
dapli_collective_scatterv(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			*snd_bufs,
 	IN  DAT_COUNT			*snd_lens,
 	IN  DAT_COUNT			*displs,
	IN  DAT_PVOID			rcv_buf,
 	IN  DAT_COUNT			rcv_len,
	IN  DAT_IB_COLLECTIVE_RANK	root,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags)
{
	return DAT_NOT_IMPLEMENTED;
}

/* 
 * This call performs a gather of the data sent by all
 * members of the collective specified by the collective_handle argument.  
 * The data to be sent is specified by the send_buffer and send_byte_count 
 * arguments. Data is received by the collective member specified by the 
 * root argument in the buffer specified by the recv_buffer and 
 * recv_byte_count arguments.  Data is placed into the receive buffer in 
 * collective rank order.  An �in place� transfer for the root rank can 
 * be indicated by passing NULL as the send_buffer argument.  
 * The recv_buffer and recv_byte_count arguments are ignored on non-root 
 * members.  The operation is completed on the collective EVD unless 
 * completions are suppressed through the completion flags.  
 */
DAT_RETURN
dapli_collective_gather(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			rcv_buf,
 	IN  DAT_COUNT			rcv_len,
	IN  DAT_IB_COLLECTIVE_RANK	root,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags) 
{
	return DAT_NOT_IMPLEMENTED;
}

/*
 * This call performs a non-uniform gather of the data sent by
 * all members of the collective specified by the collective_handle argument.  
 * The data to be sent is specified by the send_buffer and send_byte_count 
 * arguments.  Data is received by the collective member specified by the 
 * root argument into the buffers specified by the recv_buffers and 
 * recv_byte_counts array arguments.  Data is placed into the receive buffer 
 * associated with the rank that sent it. An �in place� transfer for the root 
 * rank can be indicated by passing NULL as the send_buffer argument.  
 * The recv_buffers and recv_byte_counts arguments are ignored on non-root 
 * members.  The operation is completed on the collective EVD unless 
 * completions are suppressed through the completion flags.  
 */

DAT_RETURN
dapli_collective_gatherv(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			*rcv_bufs,
 	IN  DAT_COUNT			*rcv_lens,
 	IN  DAT_COUNT			*displs,
	IN  DAT_IB_COLLECTIVE_RANK	root,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags)
{
	return DAT_NOT_IMPLEMENTED;
}

/* 
 * This call is equivalent to having all members of a collective
 * group perform a dat_collective_gather() as the root.  This results in all 
 * members of the collective having identical contents in their receive buffer
 */
DAT_RETURN
dapli_collective_allgather(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			rcv_buf,
 	IN  DAT_COUNT			rcv_len,
	IN  DAT_CONTEXT			user_context,
	IN  DAT_COMPLETION_FLAGS	comp_flags)
{
	DAT_IB_EXTENSION_EVENT_DATA eventx;
	struct coll_group *group = (struct coll_group *)coll_handle;
	fca_gather_spec_t gather;
	int ret;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		 " coll_allgather[%d]: group=%p sbuf=%p slen=%d rbuf=%p rlen=%d"
		 " ctxt=%llx cflgs=%d\n",
		 group->self, coll_handle, snd_buf, snd_len,
		 rcv_buf, rcv_len, user_context, comp_flags );

	gather.sbuf = snd_buf;
	gather.size = snd_len;
	gather.rbuf = rcv_buf;

        if (snd_buf == NULL) /* MPI_IN_PLACE */
                gather.sbuf = rcv_buf + rcv_len * group->self;

	ret = fca_do_allgather(group->comm, &gather);
	if (ret < 0)
		return(dapl_convert_errno(-ret, " fca_allreduce"));

	/* setup and post successful reduce, make sync for now */
	eventx.type = DAT_IB_COLLECTIVE_ALLGATHER_STATUS;
	eventx.status = DAT_OP_SUCCESS;
	eventx.coll.handle = group;
	eventx.coll.context = user_context;
	dapls_evd_post_event_ext(group->evd, DAT_IB_COLLECTIVE_EVENT, 0, (DAT_UINT64*)&eventx);

	return DAT_SUCCESS;
}

/* 
 * This call performs a non-uniform dat_collective_allgather()
 * operation.  It is equivalent to having all members of a collective group 
 * perform a dat_collective_gatherv() as the root.  This results in all 
 * members of the collective having identical contents in their receive 
 * buffer. 
 */
DAT_RETURN
dapli_collective_allgatherv(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			*rcv_bufs,
 	IN  DAT_COUNT			*rcv_lens,
 	IN  DAT_COUNT			*displs,
	IN  DAT_CONTEXT			user_context,
	IN  DAT_COMPLETION_FLAGS	comp_flags)
{
	DAT_IB_EXTENSION_EVENT_DATA eventx;
	struct coll_group *group = (struct coll_group *)coll_handle;
	fca_gatherv_spec_t gatherv;
	int ret;

	dapl_log(DAPL_DBG_TYPE_EXTENSION,
		 " coll_gather[%d]: group=%p sbuf=%p slen=%d rbufs=%p rlens=%p"
		 " displs=%p ctxt=%llx cflgs=%d\n",
		 group->self, coll_handle, snd_buf, snd_len,
		 rcv_bufs, rcv_lens, displs, user_context, comp_flags );

	gatherv.sbuf = snd_buf;
	gatherv.sendsize = snd_len;
	gatherv.rbuf = rcv_bufs;
	gatherv.recvsizes = rcv_lens;
	gatherv.displs = displs;

	if (snd_buf == NULL) /* MPI_IN_PLACE */
		gatherv.sbuf = rcv_bufs + displs[group->self];

	ret = fca_do_allgatherv(group->comm, &gatherv);
	if (ret < 0)
		return(dapl_convert_errno(-ret, " fca_allreduce"));

	/* setup and post successful reduce, make sync for now */
	eventx.type = DAT_IB_COLLECTIVE_ALLGATHER_STATUS;
	eventx.status = DAT_OP_SUCCESS;
	eventx.coll.handle = group;
	eventx.coll.context = user_context;
	dapls_evd_post_event_ext(group->evd, DAT_IB_COLLECTIVE_EVENT, 0, (DAT_UINT64*)&eventx);

	return DAT_SUCCESS;
}

DAT_RETURN
dapli_collective_alltoall(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			snd_buf,
 	IN  DAT_COUNT			snd_len,
	IN  DAT_PVOID			rcv_buf,
 	IN  DAT_COUNT			rcv_len,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags)
{
	return DAT_NOT_IMPLEMENTED;
}

DAT_RETURN
dapli_collective_alltoallv(
	IN  DAT_IB_COLLECTIVE_HANDLE	coll_handle,
	IN  DAT_PVOID			*snd_bufs,
 	IN  DAT_COUNT			*snd_lens,
 	IN  DAT_COUNT			*snd_displs,
	IN  DAT_PVOID			*rcv_bufs,
 	IN  DAT_COUNT			*rcv_lens,
 	IN  DAT_COUNT			*rcv_displs,
	IN  DAT_CONTEXT			context,
	IN  DAT_COMPLETION_FLAGS	comp_flags)
{
	return DAT_NOT_IMPLEMENTED;
}

DAT_RETURN
dapli_collective_reduce_scatter(
	IN  DAT_IB_COLLECTIVE_HANDLE		coll_handle,
	IN  DAT_PVOID				snd_buf,
 	IN  DAT_COUNT				snd_len,
	IN  DAT_PVOID				rcv_buf,
 	IN  DAT_COUNT				*rcv_lens,
	IN  DAT_IB_COLLECTIVE_REDUCE_DATA_OP	op,
	IN  DAT_IB_COLLECTIVE_DATA_TYPE		type,
	IN  DAT_CONTEXT				user_context,
	IN  DAT_COMPLETION_FLAGS		comp_flags)
{
	return DAT_NOT_IMPLEMENTED;	
}

DAT_RETURN
dapli_collective_scan(
	IN  DAT_IB_COLLECTIVE_HANDLE		coll_handle,
	IN  DAT_PVOID				snd_buf,
 	IN  DAT_COUNT				snd_len,
	IN  DAT_PVOID				rcv_buf,
 	IN  DAT_COUNT				rcv_len,
	IN  DAT_IB_COLLECTIVE_REDUCE_DATA_OP	op,
	IN  DAT_IB_COLLECTIVE_DATA_TYPE		type,
	IN  DAT_CONTEXT				user_context,
	IN  DAT_COMPLETION_FLAGS		comp_flags)
{
	return DAT_NOT_IMPLEMENTED;	
}

#endif /* DAT_FCA_PROVIDER */
#endif /* DAT_IB_COLLECTIVES */

