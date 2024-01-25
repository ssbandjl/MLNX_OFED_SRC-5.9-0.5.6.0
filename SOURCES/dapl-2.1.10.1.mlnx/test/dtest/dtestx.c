/*
 * Copyright (c) 2007-2008 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id: $
 */
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <process.h>
#include <complib/cl_types.h>
#include "..\..\..\..\etc\user\getopt.c"
#define __BYTE_ORDER __LITTLE_ENDIAN

#define getpid() ((int)GetCurrentProcessId())
#define F64x "%I64x"
#define F64u "%I64u"
#define DAPL_PROVIDER "ibnic0v2"
#else
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#define DAPL_PROVIDER "ofa-v2-mlx4_0-1u"
#define F64x "%"PRIx64""
#define F64u "%"PRIu64""

#endif

#include "dat2/udat.h"
#include "dat2/dat_ib_extensions.h"

static int disconnect_ep(void);

#define _OK(status, str) \
{\
	const char  *maj_msg, *min_msg;\
	if (status != DAT_SUCCESS) {\
		dat_strerror(status, &maj_msg, &min_msg);\
		fprintf(stderr, str " returned %s : %s\n", maj_msg, min_msg);\
		dat_ia_close(ia, DAT_CLOSE_DEFAULT);\
		exit(1);\
	} else if (verbose) {\
		printf("dtestx: %s success\n",str);\
	}\
}

#define _OK2(status, str)\
{\
	const char  *maj_msg, *min_msg;\
	if (status != DAT_SUCCESS) {\
		dat_strerror(status, &maj_msg, &min_msg);\
		fprintf(stderr, str " returned %s : %s\n", maj_msg, min_msg);\
		dat_ia_close(ia, DAT_CLOSE_DEFAULT);\
		exit(1);\
	} else if (verbose) {\
		printf("dtestx: %s\n",str);\
	}\
}

/* byte swap helpers from Complib */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ntoh16(x) (uint16_t)( \
        (((uint16_t)(x) & 0x00FF) << 8) | \
        (((uint16_t)(x) & 0xFF00) >> 8))
#define hton16(x) ntoh16(x)
#define ntoh32(x) (uint32_t)( \
        (((uint32_t)(x) & 0x000000FF) << 24)| \
        (((uint32_t)(x) & 0x0000FF00) << 8) | \
        (((uint32_t)(x) & 0x00FF0000) >> 8) | \
        (((uint32_t)(x) & 0xFF000000) >> 24))
#define hton32(x) ntoh32(x)
#define ntoh64(x) (uint64_t)( \
        (((uint64_t)x & 0x00000000000000FFULL) << 56) | \
        (((uint64_t)x & 0x000000000000FF00ULL) << 40) | \
        (((uint64_t)x & 0x0000000000FF0000ULL) << 24) | \
        (((uint64_t)x & 0x00000000FF000000ULL) << 8 ) | \
        (((uint64_t)x & 0x000000FF00000000ULL) >> 8 ) | \
        (((uint64_t)x & 0x0000FF0000000000ULL) >> 24) | \
        (((uint64_t)x & 0x00FF000000000000ULL) >> 40) | \
        (((uint64_t)x & 0xFF00000000000000ULL) >> 56))
#define hton64(x) ntoh64(x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define hton16(x) (x)
#define ntoh16(x) (x)
#define hton32(x) (x)
#define ntoh32(x) (x)
#define hton64(x) (x)
#define ntoh64(x) (x)
#endif				/* __BYTE_ORDER == __BIG_ENDIAN */

#define MIN(a, b) ((a < b) ? (a) : (b))
#define MAX(a, b) ((a > b) ? (a) : (b))

#define DTO_TIMEOUT       (1000*1000*5)
#define CONN_TIMEOUT      (1000*1000*30)
#define SERVER_TIMEOUT    (DAT_TIMEOUT_INFINITE)
#define CLIENT_ID		31111
#define SERVER_ID		31112
#define BUF_SIZE		256
#define BUF_SIZE_ATOMIC		8
#define REG_MEM_COUNT		10
#define SND_RDMA_BUF_INDEX	0
#define RCV_RDMA_BUF_INDEX	1
#define SEND_BUF_INDEX		2
#define RECV_BUF_INDEX		3
#define MAX_EP_COUNT		1000
#define MAX_AH_COUNT		(MAX_EP_COUNT * 2)

static DAT_VADDR *atomic_buf;
static DAT_LMR_HANDLE lmr_atomic;
static DAT_LMR_CONTEXT lmr_atomic_context;
static DAT_RMR_CONTEXT rmr_atomic_context;
static DAT_VLEN reg_atomic_size;
static DAT_VADDR reg_atomic_addr;
static DAT_LMR_HANDLE lmr[REG_MEM_COUNT * MAX_EP_COUNT];
static DAT_LMR_CONTEXT lmr_context[REG_MEM_COUNT * MAX_EP_COUNT];
static DAT_RMR_CONTEXT rmr_context[REG_MEM_COUNT * MAX_EP_COUNT];
static DAT_VLEN reg_size[REG_MEM_COUNT * MAX_EP_COUNT];
static DAT_VADDR reg_addr[REG_MEM_COUNT * MAX_EP_COUNT];
static DAT_RMR_TRIPLET *buf[REG_MEM_COUNT * MAX_EP_COUNT];
static DAT_EP_HANDLE ep[MAX_EP_COUNT];
static DAT_EVD_HANDLE async_evd = DAT_HANDLE_NULL;
static DAT_IA_HANDLE ia = DAT_HANDLE_NULL;
static DAT_PZ_HANDLE pz = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE cr_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE con_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE dto_evd = DAT_HANDLE_NULL;
static DAT_PSP_HANDLE psp = DAT_HANDLE_NULL;
static int server = 1;
static int remote_host = 0;
static int ud_test = 0;
static int multi_eps = 0;
static int buf_size = BUF_SIZE;
static int msg_size = sizeof(DAT_RMR_TRIPLET);
static char provider[64] = DAPL_PROVIDER;
static char hostname[256] = { 0 };
static DAT_IB_ADDR_HANDLE remote_ah[MAX_EP_COUNT][MAX_AH_COUNT];
static int eps = 1;
static int verbose = 0;
static int counters = 0;
static int counters_ok = 0;
static int fetch_and_add_cap = 0;
static int cmp_and_swap_cap = 0;
static int query_only = 0;
static int ucm = 0;
static DAT_SOCK_ADDR6 remote;
static DAT_IA_ATTR ia_attr;
static DAT_PROVIDER_ATTR prov_attrs;

#define LOGPRINTF if (verbose) printf

#define CONN_PORT 15828
#define CONN_MSG_SIZE 128
#define CONN_MSG_FMT "%04hx:%08x:%08x:%08x:%s"

static void print_usage(void)
{
	printf("\n dtestx usage \n\n");
	printf("v: verbose\n");
	printf("p: print counters\n");
	printf("u  unreliable datagram test\n");
	printf("U: unreliable datagram test, UD endpoint count\n");
	printf("m  unreliable datagram test, multiple Server endpoints\n");
	printf("b: buf length to allocate\n");
	printf("h: hostname/address of Server, client and UDP server\n");
	printf("c: Client\n");
	printf("s: Server, default\n");
	printf("P: provider name (default = ofa-v2-mlx4_0-1u)\n");
	printf("\n");
}

#if defined(_WIN32) || defined(_WIN64)
static void sleep(int secs)
{
	Sleep(secs * 1000);
}

#define _WSACleanup() WSACleanup()
#else
#define	_WSACleanup()
#endif

static void print_ia_address(struct sockaddr *sa)
{
	char str[INET6_ADDRSTRLEN] = {" ??? "};

	switch(sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, str, INET6_ADDRSTRLEN);
		printf("%d Local Address AF_INET - %s port %d\n", getpid(), str, SERVER_ID);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, str, INET6_ADDRSTRLEN);
		printf("%d Local Address AF_INET6 - %s flowinfo(QPN)=0x%x, port(LID)=0x%x\n",
			getpid(), str,
			ntohl(((struct sockaddr_in6 *)sa)->sin6_flowinfo),
			ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
		break;
	default:
		printf("%d Local Address UNKOWN FAMILY - port %d\n", getpid(), SERVER_ID);
	}
}

static int conn_client_connect(const char *servername, int port)
{

	struct addrinfo *res, *t;
	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	char *service;
	int n;
	int sockfd = -1;

	if (asprintf(&service, "%d", port) < 0)
		return -1;

	n = getaddrinfo(servername, service, &hints, &res);

	if (n < 0) {
		fprintf(stderr, "%s for %s:%d\n",
			gai_strerror(n), servername, port);
		return n;
	}

	for (t = res; t; t = t->ai_next) {
		sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
		if (sockfd >= 0) {
			if (!connect(sockfd, t->ai_addr, t->ai_addrlen))
				break;
			close(sockfd);
			sockfd = -1;
		}
	}

	freeaddrinfo(res);

	if (sockfd < 0) {
		fprintf(stderr, "Couldn't connect to %s:%d\n",
			servername, port);
		return sockfd;
	}
	return sockfd;
}

static int conn_server_connect(int port)
{
	struct addrinfo *res, *t;
	struct addrinfo hints = {
		.ai_flags    = AI_PASSIVE,
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	char *service;
	int sockfd = -1, connfd;
	int n;

	if (asprintf(&service, "%d", port) < 0)
		return -1;

	n = getaddrinfo(NULL, service, &hints, &res);

	if (n < 0) {
		fprintf(stderr, "%s for port %d\n", gai_strerror(n), port);
		return n;
	}

	for (t = res; t; t = t->ai_next) {
		sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
		if (sockfd >= 0) {
			n = 1;

			setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &n,
				   sizeof n);

			if (!bind(sockfd, t->ai_addr, t->ai_addrlen))
				break;

			close(sockfd);
			sockfd = -1;
		}
	}

	freeaddrinfo(res);

	if (sockfd < 0) {
		fprintf(stderr, "Couldn't listen to port %d\n", port);
		return sockfd;
	}

	listen(sockfd, 1);
	connfd = accept(sockfd, NULL, 0);
	if (connfd < 0) {
		perror("server accept");
		fprintf(stderr, "accept() failed\n");
		close(sockfd);
		return connfd;
	}

	close(sockfd);
	return connfd;
}

static int get_server_params(struct sockaddr *my_sa)
{
	int connfd, parsed;
	in_port_t ser_lid = 0;
	uint32_t scope_id = 0, ser_qpn = 0, ser_scope_id = 0, ser_sin_addr = 0;
	struct in_addr sin_addr;	/* Internet address.  */
	char msg[CONN_MSG_SIZE];

	connfd = conn_client_connect(hostname, CONN_PORT);
	if (connfd < 0) {
		fprintf(stderr, "%d Could not connect to %s\n",
			getpid(), hostname);
		return -1;
	}

	if (read(connfd, msg, sizeof msg) != sizeof msg) {
		fprintf(stderr, "%d Couldn't read remote address\n", getpid());
		return -1;
	}

	parsed = sscanf(msg, CONN_MSG_FMT, &ser_lid, &ser_qpn, &ser_scope_id,
			&ser_sin_addr, provider);

	if (parsed != 5) {
		fprintf(stderr, "%d Couldn't parse line <%.*s>\n",
			getpid(), (int)sizeof msg, msg);
		return -1;
	}

	if (ser_sin_addr) {
		sin_addr.s_addr = ser_sin_addr;
		inet_ntop(AF_INET, &sin_addr, hostname, INET6_ADDRSTRLEN);
		LOGPRINTF("%d remote data: provider %s hostname %s\n",
			  getpid(), provider, hostname);
	} else if (ser_lid && ser_qpn) {
		remote.sin6_family = AF_INET6;
		remote.sin6_port = ser_lid;
		remote.sin6_flowinfo = ser_qpn;
		remote.sin6_scope_id = ntohl(ser_scope_id);
		ucm = 1;
		LOGPRINTF("%d remote data: provider %s Client QPN 0x%x,"
			  " LID = 0x%x, scope_id 0x%x\n",
			  getpid(), provider, ntohl(ser_qpn), ntohs(ser_lid),
			  ntohl(ser_scope_id));
	} else {
		fprintf(stderr, "%d No valid data was received"
			" from the server\n",
			getpid());
		return -1;
	}

	/* send client addr back to server */
	if (my_sa->sa_family == AF_INET6) {
		ser_qpn = ((struct sockaddr_in6 *)my_sa)->sin6_flowinfo;
		ser_lid = ((struct sockaddr_in6 *)my_sa)->sin6_port;
		scope_id = htonl(((struct sockaddr_in6 *)my_sa)->sin6_scope_id);
		LOGPRINTF("%d Client data to server: provider %s QPN 0x%x LID"
			  " = 0x%x SCCOPE_ID 0x%x\n",
			  getpid(), provider, ntohl(ser_qpn), ntohs(ser_lid),
			  ntohl(scope_id));
	} else if (my_sa->sa_family == AF_INET) {
		ser_sin_addr = ((struct sockaddr_in *)my_sa)->sin_addr.s_addr;
		LOGPRINTF("%d Server data to client: provider %s SIN_ADDR"
			  " 0x%x\n", getpid(), provider, ser_sin_addr);
	}

	sprintf(msg, CONN_MSG_FMT, ser_lid, ser_qpn, scope_id,
		ser_sin_addr, provider);
	if (write(connfd, msg, sizeof msg) != sizeof msg) {
		fprintf(stderr, "%d Couldn't send data", getpid());
		return -1;
	}
	return 0;
}

static int send_server_params(struct sockaddr *ser_sa)
{
	in_port_t ser_lid = 0;
	uint32_t scope_id = 0, ser_qpn = 0, ser_scope_id = 0, ser_sin_addr = 0;
	int parsed, connfd;
	struct in_addr sin_addr;	/* Internet address.  */
	char msg[CONN_MSG_SIZE];

	if (!ser_sa) {
		printf("%d no address\n", getpid());
		return -1;
	}

	if (ser_sa->sa_family == AF_INET6) {
		ser_qpn = ((struct sockaddr_in6 *)ser_sa)->sin6_flowinfo;
		ser_lid = ((struct sockaddr_in6 *)ser_sa)->sin6_port;
		scope_id =
			htonl(((struct sockaddr_in6 *)ser_sa)->sin6_scope_id);
		LOGPRINTF("%d Server data to client: provider %s QPN 0x%x LID"
			  " = 0x%x SCCOPE_ID 0x%x\n",
			  getpid(), provider, ntohl(ser_qpn), ntohs(ser_lid),
			  ntohl(scope_id));
	} else if (ser_sa->sa_family == AF_INET) {
		ser_sin_addr = ((struct sockaddr_in *)ser_sa)->sin_addr.s_addr;
		LOGPRINTF("%d Server data to client: provider %s SIN_ADDR"
			  " 0x%x\n",
			  getpid(), provider, ser_sin_addr);
	}

	connfd = conn_server_connect(CONN_PORT);
	if (connfd < 0) {
		fprintf(stderr, "%d Failed to connect to client\n", getpid());
		return -1;
	}

	sprintf(msg, CONN_MSG_FMT, ser_lid, ser_qpn, scope_id,
		ser_sin_addr, provider);
	if (write(connfd, msg, sizeof msg) != sizeof msg) {
		fprintf(stderr, "%d Couldn't send data", getpid());
		return -1;
	}

	ser_lid = ser_qpn = ser_scope_id = ser_sin_addr = 0;

	/* get remote address from Client */
	if (read(connfd, msg, sizeof msg) != sizeof msg) {
		fprintf(stderr, "%d Couldn't read remote address\n", getpid());
		return -1;
	}

	parsed = sscanf(msg, CONN_MSG_FMT, &ser_lid, &ser_qpn, &ser_scope_id,
			&ser_sin_addr, provider);

	if (parsed != 5) {
		fprintf(stderr, "%d Couldn't parse line <%.*s>\n",
			getpid(), (int)sizeof msg, msg);
		return -1;
	}

	if (ser_sin_addr) {
		sin_addr.s_addr = ser_sin_addr;
		inet_ntop(AF_INET, &sin_addr, hostname, INET6_ADDRSTRLEN);
		LOGPRINTF("%d remote data: provider %s hostname %s\n",
			  getpid(), provider, hostname);
	} else if (ser_lid && ser_qpn) {
		remote.sin6_family = AF_INET6;
		remote.sin6_port = ser_lid;
		remote.sin6_flowinfo = ser_qpn;
		remote.sin6_scope_id = ntohl(ser_scope_id);
		ucm = 1;
		LOGPRINTF("%d remote data: provider %s Client QPN 0x%x,"
			  " LID = 0x%x, scope_id 0x%x\n",
			  getpid(), provider, ntohl(ser_qpn), ntohs(ser_lid),
			  ntohl(ser_scope_id));
	} else {
		fprintf(stderr, "%d No valid data was received"
			" from the server\n",
			getpid());
		return -1;
	}
	return 0;
}

static void
send_msg(void *data,
	 DAT_COUNT size,
	 DAT_LMR_CONTEXT context,
	 DAT_DTO_COOKIE cookie, DAT_COMPLETION_FLAGS flags)
{
	DAT_LMR_TRIPLET iov;
	DAT_EVENT event;
	DAT_COUNT nmore;
	DAT_RETURN status;
	int i, ep_idx = 0, ah_idx = 0;
	DAT_DTO_COMPLETION_EVENT_DATA *dto_event =
	    &event.event_data.dto_completion_event_data;

	iov.lmr_context = context;
	iov.virtual_address = (DAT_VADDR) (uintptr_t) data;
	iov.segment_length = (DAT_VLEN) size;

	for (i = 0; i < eps; i++) {
		if (ud_test) {
			/* 
			 * single QP - ep[0] and ah[0] for client and server
			 * multi QP  - ep[i]->ah[i] for client, i to i
			 *             ep[0]->ah[i] for server, 0 to all
			 */
			if (multi_eps) {
				ah_idx = i;
				if (!server)
					ep_idx = i;
			}

			printf("%s send on ep=%p -> remote_ah[%d][%d]: ah=%p"
			       " qpn=0x%x\n",
			       server ? "Server" : "Client",
			       ep[ep_idx], ep_idx, ah_idx,
			       remote_ah[ep_idx][ah_idx].ah,
			       remote_ah[ep_idx][ah_idx].qpn);

			/* client expects all data in on first EP */
			status = dat_ib_post_send_ud(ep[ep_idx],
						     1,
						     &iov,
						     &remote_ah[ep_idx][ah_idx],
						     cookie, flags);

		} else {
			status = dat_ep_post_send(ep[0], 1, &iov,
						  cookie, flags);
		}
		_OK(status, "dat_ep_post_send");

		if (!(flags & DAT_COMPLETION_SUPPRESS_FLAG)) {
			status = dat_evd_wait(dto_evd, DTO_TIMEOUT,
					      1, &event, &nmore);
			_OK(status, "dat_evd_wait after dat_ep_post_send");

			if (event.event_number != DAT_DTO_COMPLETION_EVENT &&
			    ud_test && event.event_number !=
			    (DAT_EVENT_NUMBER) DAT_IB_DTO_EVENT) {
				printf("unexpected event waiting post_send "
				       "completion - 0x%x\n",
				       event.event_number);
				exit(1);
			}
			_OK((DAT_RETURN)dto_event->status, "event status for post_send");
		}
	}
}

/* RC - Server only, UD - Server and Client, one per EP */
static void process_cr(int idx)
{
	DAT_EVENT event;
	DAT_COUNT nmore;
	DAT_RETURN status;
	int pdata;
	DAT_CR_HANDLE cr = DAT_HANDLE_NULL;
	DAT_CONN_QUAL exp_qual = server ? SERVER_ID : CLIENT_ID;
	DAT_CR_PARAM cr_param;
	DAT_CR_ARRIVAL_EVENT_DATA *cr_event =
	    &event.event_data.cr_arrival_event_data;

	LOGPRINTF("%s waiting for connect[%d] request\n",
		  server ? "Server" : "Client", idx);

	status = dat_evd_wait(cr_evd, SERVER_TIMEOUT, 1, &event, &nmore);
	_OK(status, "CR dat_evd_wait");

	if (event.event_number !=
	    (DAT_EVENT_NUMBER) DAT_CONNECTION_REQUEST_EVENT &&
	    (ud_test && event.event_number != (DAT_EVENT_NUMBER)
	     DAT_IB_UD_CONNECTION_REQUEST_EVENT)) {
		printf("unexpected event,!conn req: 0x%x\n",
		       event.event_number);
		exit(1);
	}

	if ((cr_event->conn_qual != exp_qual) ||
	    (cr_event->sp_handle.psp_handle != psp)) {
		printf("wrong cr event data\n");
		exit(1);
	}

	cr = cr_event->cr_handle;
	status = dat_cr_query(cr, DAT_CSP_FIELD_ALL, &cr_param);
	_OK(status, "dat_cr_query");

	/* use private data to select EP */
	pdata = ntoh32(*((int *)cr_param.private_data));

	LOGPRINTF("%s recvd pdata=0x%x, send pdata=0x%x\n",
		  server ? "Server" : "Client", pdata,
		  *(int *)cr_param.private_data);

	status = dat_cr_accept(cr, ep[pdata], 4, cr_param.private_data);
	_OK(status, "dat_cr_accept");

	printf("%s accepted CR on EP[%d]=%p\n",
	       server ? "Server" : "Client", pdata, ep[pdata]);
}

/* RC - Client and Server: 1, UD - Client: 1 per EP, Server: 2 per EP's */
static void process_conn(int idx)
{
	DAT_EVENT event;
	DAT_COUNT nmore;
	DAT_RETURN status;
	int i, ep_r = 0, ep_l = 0, exp_event;
	DAT_IB_EXTENSION_EVENT_DATA *ext_event = (DAT_IB_EXTENSION_EVENT_DATA *)
	    &event.event_extension_data[0];
	DAT_CONNECTION_EVENT_DATA *conn_event =
	    &event.event_data.connect_event_data;

	LOGPRINTF("%s waiting for connect[%d] establishment\n",
		  server ? "Server" : "Client", idx);

	status = dat_evd_wait(con_evd, CONN_TIMEOUT, 1, &event, &nmore);
	_OK(status, "CONN dat_evd_wait");

	LOGPRINTF("%s got connect[%d] event 0x%x, pdata %p sz=%d\n",
		  server ? "Server" : "Client", idx,
		  event.event_number, conn_event->private_data, 
		  conn_event->private_data_size);

	if (ud_test) 
		exp_event = DAT_IB_UD_CONNECTION_EVENT_ESTABLISHED;
	else
		exp_event = DAT_CONNECTION_EVENT_ESTABLISHED;

	/* Waiting on CR's or CONN_EST */
	if (event.event_number != (DAT_EVENT_NUMBER) exp_event) {
		printf("unexpected event, !conn established: 0x%x\n",
		event.event_number);
		exit(1);
	}

	/* RC or PASSIVE CONN_EST we are done */
	if (!ud_test)
		return;

	/* Initialize local EP index */
	for (i=0;i<eps;i++) {
		if (ep[i] == conn_event->ep_handle) {
			ep_l = i;
			break;
		}
	}

	LOGPRINTF(" Client got private data: ep_idx = %d\n", ep_r);

	/* UD, save AH for sends, active side only
	 * NOTE: bi-directional AH resolution results in a CONN_EST
	 * for both outbound connect and inbound CR.
	 * Active pdata includes remote_ah EP idx.
	 *
	 * DAT_IB_UD_PASSIVE_REMOTE_AH == passive side CONN_EST
	 * DAT_IB_UD_REMOTE_AH == active side CONN_EST
	 */
	if (ext_event->type == DAT_IB_UD_REMOTE_AH) {
		ep_r = ntoh32(*((int *)conn_event->private_data));

		/* AH exists for this remote EP, FREE if provider supports */
		if (remote_ah[ep_l][ep_r].ah &&
		    ia_attr.extension_version >= 209)
			dat_ib_ud_ah_free(ep[ep_l], &ext_event->remote_ah);
		else
			remote_ah[ep_l][ep_r] = ext_event->remote_ah;

		printf("CONNECT EP_L[%d]=%p (%p) -> remote_ah[%d][%d]: ah=%p,"
		       "qpn=0x%x cm_ctx %p %lu\n",
		       ep_l, ep[ep_l], conn_event->ep_handle, ep_l, ep_r,
		       remote_ah[ep_l][ep_r].ah, remote_ah[ep_l][ep_r].qpn,
		       ext_event->context.as_ptr, sizeof(*ext_event));

	} else if (ext_event->type == DAT_IB_UD_PASSIVE_REMOTE_AH) {
		if (ia_attr.extension_version >= 209) {
			LOGPRINTF("PASSIVE EP_L[%d]=%p -> remote_ah %p qpn %d"
				  " AH_FREE\n",
				  ep_l, ep[ep_l], ext_event->remote_ah.ah,
				  ext_event->remote_ah.qpn);
			dat_ib_ud_ah_free(ep[ep_l], &ext_event->remote_ah);
		}
	} else {
		printf("wrong UD ext_event type: 0x%x\n", ext_event->type);
		exit(1);
	}

	if (ia_attr.extension_version >= 209) {
		LOGPRINTF("%s EP_L[%d]=%p -> cm %p CM_FREE\n",
			   ext_event->type == DAT_IB_UD_PASSIVE_REMOTE_AH ?
			  "PASSIVE":"ACTIVE ", ep_l, ep[ep_l],
			  ext_event->context.as_ptr);
		dat_ib_ud_cm_free(ep[ep_l], ext_event->context.as_ptr);
	}

}

static int connect_ep(char *hostname, struct sockaddr *ser_sa)
{
	DAT_IA_ADDRESS_PTR remote_addr = (DAT_IA_ADDRESS_PTR)&remote;
	DAT_EP_ATTR ep_attr;
	DAT_RETURN status;
	DAT_REGION_DESCRIPTION region;
	DAT_EVENT event;
	DAT_COUNT nmore;
	DAT_LMR_TRIPLET iov;
	DAT_RMR_TRIPLET *r_iov;
	DAT_DTO_COOKIE cookie;
	DAT_CONN_QUAL conn_qual;
	DAT_BOOLEAN in, out;
	int i, ii, pdata, ctx, qdepth = REG_MEM_COUNT;
	DAT_DTO_COMPLETION_EVENT_DATA *dto_event =
	    &event.event_data.dto_completion_event_data;

	/* make sure provider supports counters */
	if ((counters) && (!counters_ok)) {
		printf("Disable dat_query_counters:"
		       " Provider not built with counters\n");
		counters = 0;
	}

	status = dat_pz_create(ia, &pz);
	_OK(status, "dat_pz_create");

	status = dat_evd_create(ia, eps * 2, DAT_HANDLE_NULL, DAT_EVD_CR_FLAG,
				&cr_evd);
	_OK(status, "dat_evd_create CR");
	status = dat_evd_create(ia, eps * 2, DAT_HANDLE_NULL,
				DAT_EVD_CONNECTION_FLAG, &con_evd);
	_OK(status, "dat_evd_create CR");
	status = dat_evd_create(ia, eps * 10, DAT_HANDLE_NULL, DAT_EVD_DTO_FLAG,
				&dto_evd);
	_OK(status, "dat_evd_create DTO");

	memset(&ep_attr, 0, sizeof(ep_attr));
	if (ud_test) {
		msg_size += 40;
		ep_attr.service_type = DAT_IB_SERVICE_TYPE_UD;
		ep_attr.max_message_size = buf_size;
		ep_attr.max_rdma_read_in = 0;
		ep_attr.max_rdma_read_out = 0;
	} else {
		ep_attr.service_type = DAT_SERVICE_TYPE_RC;
		ep_attr.max_rdma_size = 0x10000;
		ep_attr.max_rdma_read_in = 4;
		ep_attr.max_rdma_read_out = 4;
	}
	cookie.as_64 = 0;
	ep_attr.qos = 0;
	ep_attr.recv_completion_flags = 0;
	if (ud_test && !multi_eps)
		qdepth = eps * REG_MEM_COUNT;
	ep_attr.max_recv_dtos = qdepth;
	ep_attr.max_request_dtos = qdepth;
	ep_attr.max_recv_iov = 1;
	ep_attr.max_request_iov = 1;
	ep_attr.request_completion_flags = DAT_COMPLETION_DEFAULT_FLAG;
	ep_attr.ep_transport_specific_count = 0;
	ep_attr.ep_transport_specific = NULL;
	ep_attr.ep_provider_specific_count = 0;
	ep_attr.ep_provider_specific = NULL;

	for (i = 0; i < eps; i++) {
		status = dat_ep_create(ia, pz, dto_evd, dto_evd,
				       con_evd, &ep_attr, &ep[i]);
		_OK(status, "dat_ep_create");
		LOGPRINTF(" create_ep[%d]=%p\n", i, ep[i]);
	}

	for (i = 0; i < REG_MEM_COUNT * eps; i++) {
		buf[i] = (DAT_RMR_TRIPLET *) malloc(buf_size);
		region.for_va = buf[i];
		status = dat_lmr_create(ia,
					DAT_MEM_TYPE_VIRTUAL,
					region,
					buf_size,
					pz,
					DAT_MEM_PRIV_ALL_FLAG |
					DAT_IB_MEM_PRIV_REMOTE_ATOMIC,
					DAT_VA_TYPE_VA,
					&lmr[i],
					&lmr_context[i],
					&rmr_context[i],
					&reg_size[i], &reg_addr[i]);
		_OK(status, "dat_lmr_create");
	}

	/* register atomic return buffer for original data */
	atomic_buf = (DAT_UINT64 *) malloc(BUF_SIZE_ATOMIC);
	region.for_va = atomic_buf;
	status = dat_lmr_create(ia,
				DAT_MEM_TYPE_VIRTUAL,
				region,
				BUF_SIZE_ATOMIC,
				pz,
				DAT_MEM_PRIV_ALL_FLAG |
				DAT_IB_MEM_PRIV_REMOTE_ATOMIC,
				DAT_VA_TYPE_VA,
				&lmr_atomic,
				&lmr_atomic_context,
				&rmr_atomic_context,
				&reg_atomic_size, &reg_atomic_addr);
	_OK(status, "dat_lmr_create atomic");

	for (ii = 0; ii < eps; ii++) {
		for (i = RECV_BUF_INDEX; i < REG_MEM_COUNT; i++) {
			int ep_idx = 0;
			cookie.as_64 = (ii * REG_MEM_COUNT) + i;
			iov.lmr_context = lmr_context[(ii * REG_MEM_COUNT) + i];
			iov.virtual_address =
				(DAT_VADDR) (uintptr_t) buf[(ii * REG_MEM_COUNT) + i];
			iov.segment_length = buf_size;
			LOGPRINTF(" post_recv buf[%d]=(%p) on ep[%d]=%p\n",
				(ii * REG_MEM_COUNT) + i,
				buf[(ii * REG_MEM_COUNT) + i], ii, ep[ii]);
			/* ep[0], unless multi EP's */
			if (multi_eps) {
				ep_idx = ii;
				cookie.as_64 = i;
			}
			status = dat_ep_post_recv(ep[ep_idx],
						  1,
						  &iov,
						  cookie,
						  DAT_COMPLETION_DEFAULT_FLAG);
			_OK(status, "dat_ep_post_recv");
		}
	}
	/* setup receive buffer to initial string to be overwritten */
	strcpy((char *)buf[RCV_RDMA_BUF_INDEX], "blah, blah, blah\n");

	if (server) {
		/* Exchange info with client */
		printf("%d Server - Client: waiting to snd addr\n", getpid());
		if (send_server_params(ser_sa)) {
			printf("%d Failed to send server params\n", getpid());
			return -1;
		}
	}

	/* ud can resolve_ah and connect both ways, same EP */
	if (server || (!server && ud_test)) {
		if (server) {
			conn_qual = SERVER_ID;
			strcpy((char *)buf[SND_RDMA_BUF_INDEX], "Server data");
		} else {
			conn_qual = CLIENT_ID;
			strcpy((char *)buf[SND_RDMA_BUF_INDEX], "Client data");
		}
		status = dat_psp_create(ia,
					conn_qual,
					cr_evd, DAT_PSP_CONSUMER_FLAG, &psp);
		_OK(status, "dat_psp_create");

		/* Server always waits for first CR from Client */
		if (server)
			process_cr(0);

	}

	/* ud can resolve_ah and connect both ways */
	if (!server || (server && ud_test)) {
		struct addrinfo *target;

		if (ucm)
			goto no_resolution;

		if (getaddrinfo(hostname, NULL, NULL, &target) != 0) {
			printf("Error getting remote address.\n");
			exit(1);
		}

		printf("Remote %s Name: %s \n",
		       server ? "Client" : "Server", hostname);
		printf("Remote %s Net Address: %s\n",
		       server ? "Client" : "Server",
		       inet_ntoa(((struct sockaddr_in *)
				  target->ai_addr)->sin_addr));

		strcpy((char *)buf[SND_RDMA_BUF_INDEX], "Client written data");
		
		remote_addr = (DAT_IA_ADDRESS_PTR)target->ai_addr; /* IP */
no_resolution:
		
		/* one Client EP, multiple Server EPs, same conn_qual 
		 * use private data to select EP on Server 
		 */
		for (i = 0; i < eps; i++) {
			int ep_l = 0;

			/* pdata selects Server EP, 
			 * support both muliple Server and single EP's 
			 */
			if (multi_eps) {
				if (!server)
					ep_l = i;
				pdata = hton32(i);
			} else
				pdata = 0;	/* just use first EP */

			status = dat_ep_connect(ep[ep_l],
						remote_addr,
						(server ? CLIENT_ID :
						 SERVER_ID), CONN_TIMEOUT, 4,
						(DAT_PVOID) &pdata, 0,
						DAT_CONNECT_DEFAULT_FLAG);
			_OK(status, "dat_ep_connect");

			printf("%s EP_L[%d]=%p connect to EP_R[%d]\n",
				  server ? "Server" : "Client",
				  ep_l, ep[ep_l],
				  ntoh32(pdata));

		}

		if (!ucm)
			freeaddrinfo(target);
	}

	/* UD: process CR's starting with 2nd on server, 1st for client */
	if (ud_test) {
		for (i = (server ? 1 : 0); i < eps; i++)
			process_cr(i);
	}

	/* RC and UD: process CONN EST events */
	for (i = 0; i < eps; i++)
		process_conn(i);

	/* UD: CONN EST events for CONN's and CR's */
	if (ud_test) {
		for (i = 0; i < eps; i++)
			process_conn(i);
	}

	printf("Connected! %d endpoints\n", eps);

	/*
	 *  Setup our remote memory and tell the other side about it
	 *  Swap to network order.
	 */
	r_iov = (DAT_RMR_TRIPLET *) buf[SEND_BUF_INDEX];
	r_iov->rmr_context = hton32(rmr_context[RCV_RDMA_BUF_INDEX]);
	r_iov->virtual_address =
	    hton64((DAT_VADDR) (uintptr_t) buf[RCV_RDMA_BUF_INDEX]);
	r_iov->segment_length = hton32(buf_size);

	printf("Send RMR message: r_key_ctx=0x%x,va=" F64x ",len=0x%x\n",
	       hton32(r_iov->rmr_context),
	       hton64(r_iov->virtual_address), hton32(r_iov->segment_length));

	send_msg(buf[SEND_BUF_INDEX],
		 sizeof(DAT_RMR_TRIPLET),
		 lmr_context[SEND_BUF_INDEX],
		 cookie, DAT_COMPLETION_SUPPRESS_FLAG);

	dat_ep_get_status(ep[0], NULL, &in, &out);
	printf("EP[0] status: posted buffers: Req=%d, Rcv=%d\n", in, out);

	/*
	 *  Wait for their RMR
	 */
	for (i = 0, ctx = 0; i < eps; i++, ctx++) {
		/* expected cookie, recv buf idx in every mem pool */
		ctx = (ctx % REG_MEM_COUNT) ? ctx : ctx + RECV_BUF_INDEX;
		LOGPRINTF("Waiting for remote to send RMR data\n");

		status = dat_evd_wait(dto_evd, DTO_TIMEOUT, 1, &event, &nmore);
		_OK(status, "dat_evd_wait for receive message");

		if ((event.event_number != DAT_DTO_COMPLETION_EVENT) &&
		    (ud_test && event.event_number !=
		    (DAT_EVENT_NUMBER) DAT_IB_DTO_EVENT)) {
			printf("unexpected event waiting for RMR context "
			       "- 0x%x\n", event.event_number);
			exit(1);
		}
		_OK((DAT_RETURN)dto_event->status, "event status for post_recv");

		/*
		 *  multi_eps - receive multi messages on single EP
		 * !mutli_eps - receive one message across multiple EPs
		 */
		if (!multi_eps) {
			if (dto_event->transfered_length != msg_size ||
			    dto_event->user_cookie.as_64 != ctx) {
				printf("unexpected event data on recv: len=%d"
				       " cookie=" F64x " expected %d/%d\n",
				       (int)dto_event->transfered_length,
				       dto_event->user_cookie.as_64,
				       msg_size, ctx);
				exit(1);
			}
		} else {
			if (dto_event->transfered_length != msg_size ||
			    dto_event->user_cookie.as_64 != RECV_BUF_INDEX) {
				printf("unexpected event data on recv: len=%d"
				       " cookie=" F64x " expected %d/%d\n",
				       (int)dto_event->transfered_length,
				       dto_event->user_cookie.as_64,
				       msg_size, RECV_BUF_INDEX);
				exit(1);
			}
		}

		/* swap RMR,address info to host order */
		if (!multi_eps)
			r_iov = (DAT_RMR_TRIPLET *) buf[ctx];
		else
			r_iov = (DAT_RMR_TRIPLET *) buf[((i * REG_MEM_COUNT) + RECV_BUF_INDEX)];

		if (ud_test)
			r_iov = (DAT_RMR_TRIPLET *) ((char *)r_iov + 40);

		r_iov->rmr_context = ntoh32(r_iov->rmr_context);
		r_iov->virtual_address = ntoh64(r_iov->virtual_address);
		r_iov->segment_length = ntoh32(r_iov->segment_length);

		printf("Recv RMR message: buf[%d] r_iov(%p):"
		       " r_key_ctx=%x,va=" F64x ","
		       " len=0x%x on EP=%p ck=" F64x " \n",
		       multi_eps ? ((i * REG_MEM_COUNT) + RECV_BUF_INDEX):ctx,
		       r_iov, r_iov->rmr_context,
		       r_iov->virtual_address,
		       r_iov->segment_length, dto_event->ep_handle,
		       dto_event->user_cookie.as_64);
	}
	return (0);
}

static int disconnect_ep(void)
{
	DAT_RETURN status;
	DAT_EVENT event;
	DAT_COUNT nmore;
	int i, ii;
	
	if (counters) {		/* examples of query and print */
		int ii;
		DAT_UINT64 ia_cntrs[DCNT_IA_ALL_COUNTERS];

		dat_query_counters(ia, DCNT_IA_ALL_COUNTERS, ia_cntrs, 0);
		printf(" IA Cntrs:");
		for (ii = 0; ii < DCNT_IA_ALL_COUNTERS; ii++)
			printf(" " F64u "", ia_cntrs[ii]);
		printf("\n");
		dat_print_counters(ia, DCNT_IA_ALL_COUNTERS, 0);
	}
	
	if (!ud_test) {
		status = dat_ep_disconnect(ep[0], DAT_CLOSE_DEFAULT);
		_OK2(status, "dat_ep_disconnect");

		status = dat_evd_wait(con_evd, DAT_TIMEOUT_INFINITE, 1,
				      &event, &nmore);
		_OK(status, "dat_evd_wait");
	}

	if (psp) {
		status = dat_psp_free(psp);
		_OK2(status, "dat_psp_free");
	}
	for (i = 0; i < REG_MEM_COUNT * eps; i++) {
		status = dat_lmr_free(lmr[i]);
		_OK2(status, "dat_lmr_free");
	}
	if (lmr_atomic) {
		status = dat_lmr_free(lmr_atomic);
		_OK2(status, "dat_lmr_free_atomic");
	}
	for (i = 0; i < eps; i++) {
		if (counters) {	/* examples of query and print */
			int ii;
			DAT_UINT64 ep_cntrs[DCNT_EP_ALL_COUNTERS];

			dat_query_counters(ep[i], DCNT_EP_ALL_COUNTERS,
					   ep_cntrs, 0);
			printf(" EP[%d] Cntrs:", i);
			for (ii = 0; ii < DCNT_EP_ALL_COUNTERS; ii++)
				printf(" " F64u "", ep_cntrs[ii]);
			printf("\n");
			dat_print_counters(ep[i], DCNT_EP_ALL_COUNTERS, 0);
		}

		/* free UD AH resources */
		if (ia_attr.extension_version >= 209) {
			for (ii = 0; ii < MAX_AH_COUNT; ii++) {
				if (remote_ah[i][ii].ah) {
					printf( "UD_AH_FREE on EP %p, AH EP[%d][%d]"
					        "ib_ah = %p\n",
						ep[i], i, ii,
						remote_ah[i][ii].ah);
					dat_ib_ud_ah_free(ep[i],
							  &remote_ah[i][ii]);
				}
				remote_ah[i][ii].ah = NULL;
			}
		}

		status = dat_ep_free(ep[i]);
		_OK2(status, "dat_ep_free");
	}
	if (counters) {		/* examples of query and print */
		int ii;
		DAT_UINT64 evd_cntrs[DCNT_EVD_ALL_COUNTERS];

		dat_query_counters(dto_evd, DCNT_EVD_ALL_COUNTERS,
				   evd_cntrs, 0);
		printf(" DTO_EVD Cntrs:");
		for (ii = 0; ii < DCNT_EVD_ALL_COUNTERS; ii++)
			printf(" " F64u "", evd_cntrs[ii]);
		printf("\n");
		dat_print_counters(dto_evd, DCNT_EVD_ALL_COUNTERS, 0);

		dat_query_counters(con_evd, DCNT_EVD_ALL_COUNTERS,
				   evd_cntrs, 0);
		printf(" CONN_EVD Cntrs:");
		for (ii = 0; ii < DCNT_EVD_ALL_COUNTERS; ii++)
			printf(" " F64u "", evd_cntrs[ii]);
		printf("\n");
		dat_print_counters(con_evd, DCNT_EVD_ALL_COUNTERS, 0);

		dat_query_counters(cr_evd, DCNT_EVD_ALL_COUNTERS, evd_cntrs, 0);
		printf(" CR_EVD Cntrs:");
		for (ii = 0; ii < DCNT_EVD_ALL_COUNTERS; ii++)
			printf(" " F64u "", evd_cntrs[ii]);
		printf("\n");
		dat_print_counters(cr_evd, DCNT_EVD_ALL_COUNTERS, 0);
	}
	status = dat_evd_free(dto_evd);
	_OK2(status, "dat_evd_free DTO");

	status = dat_evd_free(con_evd);
	_OK2(status, "dat_evd_free CON");

	status = dat_evd_free(cr_evd);
	_OK2(status, "dat_evd_free CR");

	status = dat_pz_free(pz);
	_OK2(status, "dat_pz_free");

	status = dat_ia_close(ia, DAT_CLOSE_DEFAULT);
	_OK2(status, "dat_ia_close");

	return (0);
}

static int do_immediate()
{
	DAT_EVENT event;
	DAT_COUNT nmore;
	DAT_LMR_TRIPLET iov;
	DAT_RMR_TRIPLET r_iov;
	DAT_DTO_COOKIE cookie;
	DAT_RETURN status;
	DAT_UINT32 immed_data;
	DAT_UINT32 immed_data_recv = 0;
	DAT_DTO_COMPLETION_EVENT_DATA *dto_event =
	    &event.event_data.dto_completion_event_data;
	DAT_IB_EXTENSION_EVENT_DATA *ext_event =
	    (DAT_IB_EXTENSION_EVENT_DATA *) & event.event_extension_data[0];

	printf("\nDoing RDMA WRITE IMMEDIATE DATA\n");

	if (server) {
		immed_data = 0x1111;
	} else {
		immed_data = 0x7777;
	}

	cookie.as_64 = 0x5555;

	/* RMR info already swapped back to host order in connect_ep */
	r_iov = *buf[RECV_BUF_INDEX];

	iov.lmr_context = lmr_context[SND_RDMA_BUF_INDEX];
	iov.virtual_address = (DAT_VADDR) (uintptr_t) buf[SND_RDMA_BUF_INDEX];
	iov.segment_length = buf_size;

	cookie.as_64 = 0x9999;

	status = dat_ib_post_rdma_write_immed(ep[0],	// ep_handle
					      1,	// segments
					      &iov,	// LMR
					      cookie,	// user_cookie
					      &r_iov,	// RMR
					      immed_data,
					      DAT_COMPLETION_DEFAULT_FLAG);
	_OK(status, "dat_ib_post_rdma_write_immed");

	/*
	 *  Collect first event, write completion or inbound recv with immed
	 */
	status = dat_evd_wait(dto_evd, DTO_TIMEOUT, 1, &event, &nmore);
	_OK(status, "dat_evd_wait after dat_ib_post_rdma_write");
	if (event.event_number != (DAT_EVENT_NUMBER) DAT_IB_DTO_EVENT) {
		printf("unexpected event #0x%x waiting for WR-IMMED #0x%x\n",
		       event.event_number, DAT_IB_DTO_EVENT);
		exit(1);
	}

	if (nmore)
		printf("%s() nmore %d\n", __FUNCTION__, nmore);
	_OK((DAT_RETURN)dto_event->status, "DTO event status");
	if (ext_event->type == DAT_IB_RDMA_WRITE_IMMED) {
		if ((dto_event->transfered_length != buf_size) ||
		    (dto_event->user_cookie.as_64 != 0x9999)) {
			printf
			    ("unexpected event data for rdma_write_immed: len=%d "
			     "cookie=0x%x\n", (int)dto_event->transfered_length,
			     (int)dto_event->user_cookie.as_64);
			exit(1);
		}
	} else if (ext_event->type == DAT_IB_RDMA_WRITE_IMMED_DATA) {
		if ((dto_event->transfered_length != buf_size) ||
		    (dto_event->user_cookie.as_64 != RECV_BUF_INDEX + 1)) {
			printf
			    ("unexpected event data of immediate write: len=%d "
			     "cookie=" F64x " expected %d/%d\n",
			     (int)dto_event->transfered_length,
			     dto_event->user_cookie.as_64, (int)sizeof(int),
			     RECV_BUF_INDEX + 1);
			exit(1);
		}

		/* get immediate data from event */
		immed_data_recv = ext_event->val.immed.data;
	} else {
		printf("unexpected extension type for event - 0x%x, 0x%x\n",
		       event.event_number, ext_event->type);
		exit(1);
	}

	/*
	 * Collect second event, write completion or inbound recv with immed
	 */
	status = dat_evd_wait(dto_evd, DTO_TIMEOUT, 1, &event, &nmore);
	_OK(status, "dat_evd_wait after dat_ib_post_rdma_write");
	if (event.event_number != (DAT_EVENT_NUMBER) DAT_IB_DTO_EVENT) {
		printf("unexpected event # waiting for WR-IMMED - 0x%x\n",
		       event.event_number);
		exit(1);
	}

	_OK((DAT_RETURN)dto_event->status, "event status");
	if (ext_event->type == DAT_IB_RDMA_WRITE_IMMED) {
		if ((dto_event->transfered_length != buf_size) ||
		    (dto_event->user_cookie.as_64 != 0x9999)) {
			printf
			    ("unexpected event data for rdma_write_immed: len=%d "
			     "cookie=0x%x\n", (int)dto_event->transfered_length,
			     (int)dto_event->user_cookie.as_64);
			exit(1);
		}
	} else if (ext_event->type == DAT_IB_RDMA_WRITE_IMMED_DATA) {
		if ((dto_event->transfered_length != buf_size) ||
		    (dto_event->user_cookie.as_64 != RECV_BUF_INDEX + 1)) {
			printf
			    ("unexpected event data of immediate write: len=%d "
			     "cookie=" F64x " expected %d/%d\n",
			     (int)dto_event->transfered_length,
			     dto_event->user_cookie.as_64, (int)sizeof(int),
			     RECV_BUF_INDEX + 1);
			exit(1);
		}

		/* get immediate data from event */
		immed_data_recv = ext_event->val.immed.data;
	} else {
		printf("unexpected extension type for event - 0x%x, 0x%x\n",
		       event.event_number, ext_event->type);
		exit(1);
	}

	if ((server) && (immed_data_recv != 0x7777)) {
		printf("ERROR: Server: unexpected imm_data_recv 0x%x/0x%x\n",
		       0x7777, immed_data_recv);
		exit(1);
	} else if ((!server) && (immed_data_recv != 0x1111)) {
		printf("ERROR: Client: unexpected imm_data_recv 0x%x/0x%x\n",
		       0x1111, immed_data_recv);
		exit(1);
	}

	if (server)
		printf("Server received immed_data=0x%x\n", immed_data_recv);
	else
		printf("Client received immed_data=0x%x\n", immed_data_recv);

	printf("rdma buffer %p contains: %s\n",
	       buf[RCV_RDMA_BUF_INDEX], (char *)buf[RCV_RDMA_BUF_INDEX]);

	printf("\n RDMA_WRITE_WITH_IMMEDIATE_DATA test - PASSED\n");
	return (0);
}

static int do_cmp_swap()
{
	DAT_DTO_COOKIE cookie;
	DAT_RETURN status;
	DAT_EVENT event;
	DAT_COUNT nmore;
	DAT_LMR_TRIPLET l_iov;
	DAT_RMR_TRIPLET r_iov;
	volatile DAT_UINT64 *target = (DAT_UINT64 *) buf[RCV_RDMA_BUF_INDEX];
	DAT_DTO_COMPLETION_EVENT_DATA *dto_event =
	    &event.event_data.dto_completion_event_data;
	DAT_IB_EXTENSION_EVENT_DATA *ext_event =
	    (DAT_IB_EXTENSION_EVENT_DATA *) & event.event_extension_data[0];

	if (!cmp_and_swap_cap) {
		printf("\nSkipping CMP and SWAP as it is not supported by HW\n");
		return 0;
	}

	printf("\nDoing CMP and SWAP\n");

	/* RMR info already swapped back to host order in connect_ep */
	r_iov = *buf[RECV_BUF_INDEX];

	l_iov.lmr_context = lmr_atomic_context;
	l_iov.virtual_address = (DAT_UINT64) (uintptr_t) atomic_buf;
	l_iov.segment_length = BUF_SIZE_ATOMIC;

	cookie.as_64 = 3333;

	if (server) {
		*target = 0x12345;
		sleep(1);
		/* Server does not compare and should not swap */
		printf("dtx svr - starting cmp_swap\n");
		status = dat_ib_post_cmp_and_swap(ep[0],
						  (DAT_UINT64) 0x654321,
						  (DAT_UINT64) 0x6789A,
						  &l_iov,
						  cookie,
						  &r_iov,
						  DAT_COMPLETION_DEFAULT_FLAG);
		printf("dtx svr - done cmp_swap, chk status\n");
	} else {
		*target = 0x54321;
		sleep(1);
		printf("dtx cli - starting cmp_swap\n");
		/* Client does compare and should swap */
		status = dat_ib_post_cmp_and_swap(ep[0],
						  (DAT_UINT64) 0x12345,
						  (DAT_UINT64) 0x98765,
						  &l_iov,
						  cookie,
						  &r_iov,
						  DAT_COMPLETION_DEFAULT_FLAG);
		printf("dtx cli - done cmp_swap, chk status\n");
	}
	_OK(status, "dat_ib_post_cmp_and_swap");
	status = dat_evd_wait(dto_evd, DTO_TIMEOUT, 1, &event, &nmore);
	_OK(status, "dat_evd_wait for compare and swap");
	if (event.event_number != (DAT_EVENT_NUMBER) DAT_IB_DTO_EVENT) {
		printf("unexpected event after post_cmp_and_swap: 0x%x\n",
		       event.event_number);
		exit(1);
	}

	_OK((DAT_RETURN)dto_event->status, "event status for CMP and SWAP");
	if (ext_event->type != DAT_IB_CMP_AND_SWAP) {
		printf("unexpected event data of cmp_swap: type=%d cookie=%d "
		       "original " F64x "\n",
		       (int)ext_event->type,
		       (int)dto_event->user_cookie.as_64, *atomic_buf);
		exit(1);
	}

	sleep(2);		/* wait for other side to complete swap */

	if (server) {
		printf("Server got original data        = " F64x ", expected "
		       "0x54321\n", *atomic_buf);
		printf("Client final result (on Server) = " F64x ", expected "
		       "0x98765\n", *target);

		if (*atomic_buf != 0x54321 || *target != 0x98765) {
			printf("ERROR: Server CMP_SWAP\n");
			exit(1);
		}
	} else {
		printf("Client got original data        = " F64x ", expected "
		       "0x12345\n", *atomic_buf);
		printf("Server final result (on Client) = 0x" F64x ", expected "
		       "0x54321\n", *target);

		if (*atomic_buf != 0x12345 || *target != 0x54321) {
			printf("ERROR: Client CMP_SWAP\n");
			exit(1);
		}
	}
	printf("\n CMP_SWAP test - PASSED\n");
	return (0);
}

static int do_fetch_add()
{
	DAT_DTO_COOKIE cookie;
	DAT_RETURN status;
	DAT_EVENT event;
	DAT_COUNT nmore;
	DAT_LMR_TRIPLET l_iov;
	DAT_RMR_TRIPLET r_iov;
	volatile DAT_UINT64 *target = (DAT_UINT64 *) buf[RCV_RDMA_BUF_INDEX];
	DAT_DTO_COMPLETION_EVENT_DATA *dto_event =
	    &event.event_data.dto_completion_event_data;
	DAT_IB_EXTENSION_EVENT_DATA *ext_event =
	    (DAT_IB_EXTENSION_EVENT_DATA *) & event.event_extension_data[0];

	if (!fetch_and_add_cap) {
		printf("\nSkipping FETCH and ADD as it is not supported by HW\n");
		return 0;
	}

	printf("\nDoing FETCH and ADD\n");

	/* RMR info already swapped back to host order in connect_ep */
	r_iov = *buf[RECV_BUF_INDEX];

	l_iov.lmr_context = lmr_atomic_context;
	l_iov.virtual_address = (DAT_UINT64) (uintptr_t) atomic_buf;
	l_iov.segment_length = BUF_SIZE_ATOMIC;

	cookie.as_64 = 0x7777;
	if (server) {
		/* Wait for Client to finish cmp_swap */
		while (*target != 0x98765)
			sleep(1);
		*target = 0x10;
		sleep(1);
		status = dat_ib_post_fetch_and_add(ep[0],
						   (DAT_UINT64) 0x100,
						   &l_iov,
						   cookie,
						   &r_iov,
						   DAT_COMPLETION_DEFAULT_FLAG);
	} else {
		/* Wait for Server, no swap so nothing to check */
		*target = 0x100;
		sleep(1);
		status = dat_ib_post_fetch_and_add(ep[0],
						   (DAT_UINT64) 0x10,
						   &l_iov,
						   cookie,
						   &r_iov,
						   DAT_COMPLETION_DEFAULT_FLAG);
	}
	_OK(status, "dat_ib_post_fetch_and_add");
	status = dat_evd_wait(dto_evd, DTO_TIMEOUT, 1, &event, &nmore);
	_OK(status, "dat_evd_wait for fetch and add");
	if (event.event_number != (DAT_EVENT_NUMBER) DAT_IB_DTO_EVENT) {
		printf("unexpected event after post_fetch_and_add: 0x%x\n",
		       event.event_number);
		exit(1);
	}

	_OK((DAT_RETURN)dto_event->status, "event status for FETCH and ADD");
	if (ext_event->type != DAT_IB_FETCH_AND_ADD) {
		printf("unexpected event data of fetch and add : type=%d "
		       "cookie=%d original%d\n",
		       (int)ext_event->type,
		       (int)dto_event->user_cookie.as_64, (int)*atomic_buf);
		exit(1);
	}

	if (server) {
		printf("Client original data (on Server) = " F64x ", expected "
		       "0x100\n", *atomic_buf);
	} else {
		printf("Server original data (on Client) = " F64x ", expected "
		       "0x10\n", *atomic_buf);
	}

	sleep(1);

	if (server) {
		status = dat_ib_post_fetch_and_add(ep[0],
						   (DAT_UINT64) 0x100,
						   &l_iov,
						   cookie,
						   &r_iov,
						   DAT_COMPLETION_DEFAULT_FLAG);
	} else {
		status = dat_ib_post_fetch_and_add(ep[0],
						   (DAT_UINT64) 0x10,
						   &l_iov,
						   cookie,
						   &r_iov,
						   DAT_COMPLETION_DEFAULT_FLAG);
	}

	status = dat_evd_wait(dto_evd, DTO_TIMEOUT, 1, &event, &nmore);
	_OK(status, "dat_evd_wait for second fetch and add");
	if (event.event_number != (DAT_EVENT_NUMBER) DAT_IB_DTO_EVENT) {
		printf("unexpected event after second post_fetch_and_add: "
		       "0x%x\n", event.event_number);
		exit(1);
	}

	_OK((DAT_RETURN)dto_event->status, "event status for second FETCH and ADD");
	if (ext_event->type != DAT_IB_FETCH_AND_ADD) {
		printf("unexpected event data of second fetch and add : "
		       "type=%d cookie=%d original%p\n",
		       (int)ext_event->type,
		       (int)dto_event->user_cookie.as_64, atomic_buf);
		exit(1);
	}

	sleep(1);		/* wait for other side to complete fetch_add */

	if (server) {
		printf("Server got original data         = " F64x ", expected "
		       "0x200\n", *atomic_buf);
		printf("Client final result (on Server)  = " F64x ", expected "
		       "0x30\n", *target);

		if (*atomic_buf != 0x200 || *target != 0x30) {
			printf("ERROR: Server FETCH_ADD\n");
			exit(1);
		}
	} else {
		printf("Server side original data        = " F64x ", expected "
		       "0x20\n", *atomic_buf);
		printf("Server final result (on Client)  = " F64x ", expected "
		       "0x300\n", *target);

		if (*atomic_buf != 0x20 || *target != 0x300) {
			printf("ERROR: Server FETCH_ADD\n");
			exit(1);
		}
	}
	printf("\n FETCH_ADD test - PASSED\n");
	return (0);
}


int main(int argc, char **argv)
{
	int i, rc;
	DAT_RETURN status;

	/* parse arguments */
	while ((rc = getopt(argc, argv, "qcsvumpU:h:b:P:")) != -1) {
		switch (rc) {
		case 'u':
			ud_test = 1;
			eps = 4;
			break;
		case 'm':
			multi_eps = 1;
			break;
		case 'c':
			server = 0;
			break;
		case 's':
			server = 1;
			break;
		case 'p':
			counters = 1;
			break;
		case 'h':
			remote_host = 1;
			strcpy(hostname, optarg);
			break;
		case 'b':
			buf_size = atoi(optarg);
			break;
		case 'U':
			ud_test = 1;
			eps = MIN(atoi(optarg), MAX_EP_COUNT);
			break;
		case 'P':
			strcpy(provider, optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'q':
			query_only = 1;
			break;
		default:
			print_usage();
			exit(-12);
		}
	}

#if defined(_WIN32) || defined(_WIN64)
	{
		WSADATA wsaData;
		int i;

		i = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (i != 0) {
			printf("%s WSAStartup(2.2) fail? (0x%x)\n", argv[0], i);
			fflush(stdout);
			exit(1);
		}
	}
#endif
	if (query_only) {
		memset(&ia_attr, 0, sizeof(ia_attr));
		memset(&prov_attrs, 0, sizeof(prov_attrs));
		status = dat_ib_open_query(provider, &ia,
					   DAT_IA_FIELD_ALL, &ia_attr,
					   DAT_PROVIDER_FIELD_ALL, &prov_attrs);
		_OK(status, "dat_ib_open_query");

		print_ia_address(ia_attr.ia_address_ptr);
		printf(" Open_Query: %s num_attrs = %d\n",
			provider, prov_attrs.num_provider_specific_attr);
		/* Print provider specific attributes */
		for (i = 0; i < prov_attrs.num_provider_specific_attr; i++) {
			printf(" Open_Query: Provider Specific Attribute[%d] %s=%s\n",
				  i, prov_attrs.provider_specific_attr[i].name,
				  prov_attrs.provider_specific_attr[i].value);
		}

		status = dat_ib_close_query(ia);
		_OK(status, "dat_ib_close_query");
		exit(0);
	}

	status = dat_ia_open(provider, 8, &async_evd, &ia);
	_OK(status, "dat_ia_open");

	memset(&prov_attrs, 0, sizeof(prov_attrs));
	status = dat_ia_query(ia, NULL,
			      DAT_IA_FIELD_ALL, &ia_attr,
			      DAT_PROVIDER_FIELD_ALL, &prov_attrs);
	_OK(status, "dat_ia_query");

	if (ia_attr.extension_supported != DAT_EXTENSION_IB) {
		printf("%d ERROR: IB extension not supported\n", getpid());
		exit(1);
	}

	print_ia_address(ia_attr.ia_address_ptr);

	/* Print provider specific attributes */
	for (i = 0; i < prov_attrs.num_provider_specific_attr; i++) {
		LOGPRINTF(" Provider Specific Attribute[%d] %s=%s\n",
			  i, prov_attrs.provider_specific_attr[i].name,
			  prov_attrs.provider_specific_attr[i].value);

		if (!strcmp(prov_attrs.provider_specific_attr[i].name, "DAT_IB_CMP_AND_SWAP"))
			cmp_and_swap_cap = !(strcmp(prov_attrs.provider_specific_attr[i].value, "TRUE"));

		if (!strcmp(prov_attrs.provider_specific_attr[i].name, "DAT_IB_FETCH_AND_ADD"))
			fetch_and_add_cap = !(strcmp(prov_attrs.provider_specific_attr[i].value, "TRUE"));

		rc = strcmp(prov_attrs.provider_specific_attr[i].name,
				"DAT_COUNTERS");
		if (!rc)
			counters_ok = 1;
	}


	/* for non UD tests, -h is always client */
	if (remote_host && !ud_test)
		server = 0;

	if (!server) {
		printf("%d Client: waiting for server input\n", getpid());
		if (get_server_params(ia_attr.ia_address_ptr)) {
			printf("%d Failed to get server parameters\n",
				getpid());
			exit(1);
		}
		printf("\nRunning as Client - %s %s %d endpoint(s) v%d\n",
		       provider, ud_test ? "UD test" : "", eps,
		       ia_attr.extension_version);
	} else {
		printf("\nRunning as Server - %s %s %d endpoint(s) v%d\n",
		       provider, ud_test ? "UD test" : "", eps,
		       ia_attr.extension_version);
	}

	/*
	 * connect
	 */
	if (connect_ep(hostname, ia_attr.ia_address_ptr)) {
		_WSACleanup();
		exit(1);
	}

	if (!ud_test) {
		if (do_immediate()) {
			_WSACleanup();
			exit(1);
		}
		if (do_cmp_swap()) {
			_WSACleanup();
			exit(1);
		}
		if (do_fetch_add()) {
			_WSACleanup();
			exit(1);
		}
	}

	rc = disconnect_ep();
	dat_ia_close(ia, DAT_CLOSE_DEFAULT);
	_WSACleanup();

	if (!rc)
		printf("\n IB extension test - %s test PASSED\n\n",
		       ud_test ? "UD" : "immed/atomic");
	return rc;
}
