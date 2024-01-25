/*
 * Copyright (c) 2005-2008 Intel Corporation.  All rights reserved.
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
#include <string.h>

#ifdef DAPL_PROVIDER
#undef DAPL_PROVIDER
#endif

#if defined(_WIN32) || defined(_WIN64)

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <process.h>
#include <complib/cl_types.h>
#include "..\..\..\..\etc\user\getopt.c"

#define getpid() ((int)GetCurrentProcessId())
#define F64x "%I64x"

#ifdef DBG
#define DAPL_PROVIDER "ibnic0v2d"
#else
#define DAPL_PROVIDER "ibnic0v2"
#endif

#define ntohll _byteswap_uint64
#define htonll _byteswap_uint64

#else // _WIN32 || _WIN64

#include <endian.h>
#include <byteswap.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <getopt.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>

#define DAPL_PROVIDER "ofa-v2-mlx4_0-1u"

#define F64x "%"PRIx64""

#if __BYTE_ORDER == __BIG_ENDIAN
#define htonll(x) (x)
#define ntohll(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define htonll(x)  bswap_64(x)
#define ntohll(x)  bswap_64(x)
#endif

#endif // _WIN32 || _WIN64

/* Debug: 1 == connect & close only, otherwise full-meal deal */
#define CONNECT_ONLY 0

#define MAX_POLLING_CNT 50000
#define MAX_RDMA_RD    4
#define MAX_PROCS      1000

#define min(a, b) ((a < b) ? (a) : (b))
#define max(a, b) ((a > b) ? (a) : (b))

/* Header files needed for DAT/uDAPL */
#include "dat2/udat.h"
#include "dat2/dat_ib_extensions.h"

/* definitions */
#define SERVER_CONN_QUAL  45248
#define DTO_TIMEOUT       DAT_TIMEOUT_INFINITE
#define CNO_TIMEOUT       (1000*1000*1)
#define DTO_FLUSH_TIMEOUT (1000*1000*2)
#define CONN_TIMEOUT      (1000*1000*100)
#define SERVER_TIMEOUT    DAT_TIMEOUT_INFINITE
#define RDMA_BUFFER_SIZE  (4*1024*1024)

/* Global DAT vars */
static DAT_IA_HANDLE h_ia = DAT_HANDLE_NULL;
static DAT_PZ_HANDLE h_pz = DAT_HANDLE_NULL;
static DAT_EP_HANDLE h_ep = DAT_HANDLE_NULL;
static DAT_PSP_HANDLE h_psp = DAT_HANDLE_NULL;
static DAT_CR_HANDLE h_cr = DAT_HANDLE_NULL;

static DAT_EVD_HANDLE h_async_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE h_dto_req_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE h_dto_rcv_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE h_cr_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE h_conn_evd = DAT_HANDLE_NULL;
static DAT_CNO_HANDLE h_dto_cno = DAT_HANDLE_NULL;

/* RDMA buffers */
static DAT_LMR_HANDLE h_lmr_send = DAT_HANDLE_NULL;
static DAT_LMR_HANDLE h_lmr_recv = DAT_HANDLE_NULL;
static DAT_LMR_CONTEXT lmr_context_send;
static DAT_LMR_CONTEXT lmr_context_recv;
static DAT_RMR_CONTEXT rmr_context_send;
static DAT_RMR_CONTEXT rmr_context_recv;
static DAT_VLEN registered_size_send;
static DAT_VLEN registered_size_recv;
static DAT_VADDR registered_addr_send;
static DAT_VADDR registered_addr_recv;

/* Initial msg receive buf, RMR exchange, and Rdma-write notification */
#define MSG_BUF_COUNT     3
#define MSG_IOV_COUNT     1
static DAT_LMR_HANDLE h_lmr_recv_msg = DAT_HANDLE_NULL;
static DAT_LMR_CONTEXT lmr_context_recv_msg;
static DAT_RMR_CONTEXT rmr_context_recv_msg;
static DAT_VLEN registered_size_recv_msg;
static DAT_VADDR registered_addr_recv_msg;

/* message send buffer */
static DAT_LMR_HANDLE h_lmr_send_msg = DAT_HANDLE_NULL;
static DAT_LMR_CONTEXT lmr_context_send_msg;
static DAT_RMR_CONTEXT rmr_context_send_msg;
static DAT_VLEN registered_size_send_msg;
static DAT_VADDR registered_addr_send_msg;
static DAT_EP_ATTR ep_attr;
char hostname[256] = { 0 };
char provider[64] = DAPL_PROVIDER;
char addr_str[INET_ADDRSTRLEN];

/* allocate RMR message buffers page aligned */
static DAT_RMR_TRIPLET *p_rmr_rcv;
static DAT_RMR_TRIPLET *p_rmr_snd;

/* rdma pointers */
static char *rbuf = NULL;
static char *sbuf = NULL;

/* timers */
static double start, stop;

struct dt_time {
	double total;
	double open;
	double reg;
	double unreg;
	double pzc;
	double pzf;
	double evdc;
	double evdf;
	double cnoc;
	double cnof;
	double epc;
	double epf;
	double rdma_wr;
	double rdma_rd[MAX_RDMA_RD];
	double rdma_rd_total;
	double rtt;
	double close;
	double conn;
};

static struct dt_time ts;

/* defaults */
static int all_data_sizes = 0;
static int increment = 0;
static int failed = 0;
static int uni_direction = 0;
static int align_data=1;
static int rdma_read = 0;
static int write_only = 0;
static int write_only_pp = 0;
static int write_immed = 0;
static int performance_times = 0;
static int connected = 0;
static int burst = 1000;
static int msg_burst = 100;
static int signal_rate = 10;
static int server = 1;
static int verbose = 0;
static int polling = 0;
static int poll_count = 0;
static int rdma_wr_poll_count = 0;
static int conn_poll_count = 0;
static int rdma_rd_poll_count[MAX_RDMA_RD] = { 0 };
static int delay = 0;
static int buf_len = RDMA_BUFFER_SIZE;
static int user_input_len = 0;
static int buf_len_p2;
static int use_cno = 0;
static int recv_msg_index = 0;
static int burst_msg_posted = 0;
static int burst_msg_index = 0;
static int ucm = 0;
static int rq_cnt, sq_cnt;
static DAT_SOCK_ADDR6 remote;
static int data_check = 0;

/* forward prototypes */
const char *DT_RetToStr(DAT_RETURN ret_value);
const char *DT_EventToStr(DAT_EVENT_NUMBER event_code);

static void print_usage(void);
static double get_time(void);
static void init_data(void);

static DAT_RETURN send_msg(void *data,
		    DAT_COUNT size,
		    DAT_LMR_CONTEXT context,
		    DAT_DTO_COOKIE cookie, DAT_COMPLETION_FLAGS flags);

static DAT_RETURN connect_ep(char *hostname,
		      DAT_CONN_QUAL conn_id,
		      struct sockaddr *ser_sa);
static void disconnect_ep(void);
static DAT_RETURN register_rdma_memory(void);
static DAT_RETURN unregister_rdma_memory(void);
static DAT_RETURN create_events(void);
static DAT_RETURN destroy_events(void);
static DAT_RETURN do_rdma_write_imm_with_msg(void);
static DAT_RETURN do_rdma_write_with_msg(void);
static DAT_RETURN do_rdma_write_ping_pong(int p2, int bytes);
static DAT_RETURN do_rdma_read_with_msg(void);
static DAT_RETURN do_ping_pong_msg(void);

#define LOGPRINTF if (verbose) printf
#define CONN_PORT 15828
#define CONN_MSG_SIZE 128
/* The Format of the message we pass through sockets */
#define CONN_MSG_FMT "%04hx:%08x:%08x:%08x:%s"

static void flush_evds(void)
{
	DAT_EVENT event;

	/* Flush async error queue */
	LOGPRINTF("%d: Checking ASYNC EVD...\n", getpid());
	while (dat_evd_dequeue(h_async_evd, &event) == DAT_SUCCESS) {
		LOGPRINTF("%d ERR: ASYNC EVD ENTRY: handle=%p reason=%d\n", getpid(),
			event.event_data.asynch_error_event_data.dat_handle,
			event.event_data.asynch_error_event_data.reason);
	}
	/* Flush receive queue */
	LOGPRINTF("%d: Checking RECEIVE EVD...\n", getpid());
	while (dat_evd_dequeue(h_dto_rcv_evd, &event) == DAT_SUCCESS) {
		LOGPRINTF(" RCV EVD ENTRY: op=%d stat=%d ln=%d ck="F64x"\n",
			event.event_data.dto_completion_event_data.operation,
			event.event_data.dto_completion_event_data.status,
			event.event_data.dto_completion_event_data.transfered_length,
			event.event_data.dto_completion_event_data.user_cookie.as_64);
	}
	/* Flush request queue */
	LOGPRINTF("%d: Checking REQUEST EVD...\n", getpid());
	while (dat_evd_dequeue(h_dto_req_evd, &event) == DAT_SUCCESS) {
		LOGPRINTF(" REQ EVD ENTRY: op=%d stat=%d ln=%d ck="F64x"\n",
			event.event_data.dto_completion_event_data.operation,
			event.event_data.dto_completion_event_data.status,
			event.event_data.dto_completion_event_data.transfered_length,
			event.event_data.dto_completion_event_data.user_cookie.as_64);
	}
}


static inline DAT_RETURN
collect_event(DAT_EVD_HANDLE dto_evd,
	      DAT_EVENT *event,
	      DAT_TIMEOUT timeout,
	      int *counter)
{
	DAT_EVD_HANDLE	evd = DAT_HANDLE_NULL;
	DAT_COUNT	nmore;
	DAT_RETURN	ret = DAT_SUCCESS;

	if (use_cno) {
retry:
		/* CNO wait could return EVD's in any order and
		 * may drop some EVD notification's if already
		 * triggered. Once woken, simply dequeue the 
		 * Evd the caller wants to collect and return.
		 * If notification without EVD, retry.
		 */
		ret = dat_cno_wait(h_dto_cno, CNO_TIMEOUT, &evd);
		if (dat_evd_dequeue(dto_evd, event) != DAT_SUCCESS) {
			if (ret == DAT_SUCCESS)
				printf(" WARNING: CNO notification:"
				       " without EVD?\n");
			goto retry;
		}
		ret = DAT_SUCCESS; /* cno timed out, but EVD dequeued */
		
	} else if (!polling) {

		/* use wait to dequeue */
		ret = dat_evd_wait(dto_evd, timeout, 1, event, &nmore);
		if (ret != DAT_SUCCESS)
			fprintf(stderr,
				"Error waiting on h_dto_evd %p: %s\n",
				dto_evd, DT_RetToStr(ret));
		
	} else {
		while (dat_evd_dequeue(dto_evd, event) == DAT_QUEUE_EMPTY)
			if (counter)
				(*counter)++;
	}
	return (ret);
}

static void print_ia_address(struct sockaddr *sa)
{
	char str[INET6_ADDRSTRLEN] = {" ??? "};

	switch(sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, str, INET6_ADDRSTRLEN);
		printf("%d Local Address AF_INET - %s port %d\n", getpid(), str, SERVER_CONN_QUAL);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, str, INET6_ADDRSTRLEN);
		printf("%d Local Address AF_INET6 - %s flowinfo(QPN)=0x%x, port(LID)=0x%x\n",
			getpid(), str, 
			ntohl(((struct sockaddr_in6 *)sa)->sin6_flowinfo),
			ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
		break;
	default:
		printf("%d Local Address UNKOWN FAMILY - port %d\n", getpid(), SERVER_CONN_QUAL);
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

static int get_server_params(void)
{
	int connfd, parsed;
	char msg[CONN_MSG_SIZE];
	in_port_t ser_lid = 0;
	uint32_t ser_qpn = 0, ser_scope_id = 0, ser_sin_addr = 0;
	struct in_addr sin_addr;	/* Internet address.  */

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

	return 0;
}

static int send_server_params(struct sockaddr *ser_sa)
{
	in_port_t ser_lid = 0;
	uint32_t ser_qpn = 0, scope_id = 0, ser_sin_addr = 0;
	int connfd;
	char msg[CONN_MSG_SIZE];

	if (!ser_sa) {
		printf("%d no address\n", getpid());
		return -1;
	}

	if  (ser_sa->sa_family == AF_INET6) {
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

	return 0;
}

int main(int argc, char **argv)
{
	int i, c;
	DAT_RETURN ret;
	DAT_EP_PARAM ep_param;
	DAT_IA_ATTR ia_attr;
	DAT_PROVIDER_ATTR pr_attr;

	/* parse arguments */
	while ((c = getopt(argc, argv, "UDauwWtscvpb:d:B:h:P:S:i:")) != -1) {
		switch (c) {
		case 'i':
			increment = atoi(optarg);
		case 'a':
			all_data_sizes = 1;
			fflush(stdout);
			break;
		case 'u':
			uni_direction = 1;
			fflush(stdout);
			break;
		case 'w':
			write_only = 1;
			fflush(stdout);
			break;
		case 'D':
			data_check = 1;
			printf("%d Running DATA CHECK mode\n", getpid());
			/* fall through */
		case 'W':
			write_only_pp = 1;
			uni_direction = 1;
			signal_rate = 1;
			burst = 1000;
			fflush(stdout);
			break;
		case 't':
			performance_times = 1;
			fflush(stdout);
			break;
		case 's':
			server = 1;
			fflush(stdout);
			break;
		case 'c':
			use_cno = 1;
			printf("%d Creating CNO for DTO EVD's\n", getpid());
			fflush(stdout);
			break;
		case 'v':
			verbose = 1;
			printf("%d Verbose\n", getpid());
			fflush(stdout);
			break;
		case 'p':
			polling = 1;
			printf("%d Polling\n", getpid());
			fflush(stdout);
			break;
		case 'B':
			burst = atoi(optarg);
			break;
		case 'd':
			delay = atoi(optarg);
			break;
		case 'b':
			buf_len = atoi(optarg);
			user_input_len = 1;
			break;
		case 'h':
			server = 0;
			strcpy(hostname, optarg);
			break;
		case 'P':
			strcpy(provider, optarg);
			break;
		case 'S':
			signal_rate = atoi(optarg);
			break;
		case 'U':
			/* fall through */
		default:
			print_usage();
			exit(-12);
		}
	}

	if (all_data_sizes && !write_only_pp) {
		printf("\n\t -a option only valid with -W option\n\n");
		exit(-12);
	}

#if defined(_WIN32) || defined(_WIN64)
	{
		WSADATA wsaData;

		i = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (i != 0) {
			printf("%s WSAStartup(2.2) failed? (0x%x)\n", argv[0],
			       i);
			fflush(stdout);
			exit(1);
		}
	}
#endif
	memset(&ts, 0, sizeof(struct dt_time));

	if (signal_rate > burst)
		signal_rate = burst;

	if (write_only || write_only_pp) {
		rq_cnt = MSG_BUF_COUNT * 2;
		sq_cnt = MSG_BUF_COUNT + MAX_RDMA_RD + signal_rate;
	} else {
		rq_cnt = MSG_BUF_COUNT + msg_burst;
		sq_cnt = MSG_BUF_COUNT + MAX_RDMA_RD + msg_burst;
	}

	if (!server) {
		printf("%d Running as client - waiting for server input\n",
			getpid());
		if (get_server_params()) {
			printf("%d Failed to get server parameters\n",
				getpid());
			exit(1);
		}
		printf("%d Running as %s client v2 \n", getpid(), provider);

	} else {
		printf("%d Running as server - %s v2 \n", getpid(), provider);
	}
	fflush(stdout);

	if (write_only_pp) {
		/* rdma write pingpong, set default to size to 1 byte unless specified by user */
		if (!all_data_sizes) {
			if (!data_check && !user_input_len)
				buf_len = 1;
		} else if (!increment) { /* power of 2 */
			buf_len_p2 = 1;
			i = 0;
			while (buf_len_p2 < buf_len) {
				buf_len_p2 <<= 1;
				i++;
			}
			buf_len_p2 = i;
		}
	}

	if (align_data) {
		/* allocate send and receive buffers */
		if (posix_memalign((void**)&rbuf, 4096, max(4096, buf_len * rq_cnt)) ||
		    posix_memalign((void**)&sbuf, 4096, max(4096, buf_len * rq_cnt))) {
			perror("malloc");
			exit(1);
		}
	} else {
		/* allocate send and receive buffers */
		if (((rbuf = malloc(max(64, buf_len * rq_cnt))) == NULL) ||
		    ((sbuf = malloc(max(64, buf_len * rq_cnt))) == NULL)) {
			perror("malloc");
			exit(1);
		}
	}
	init_data();
	LOGPRINTF("%d Allocated RDMA buffers (r:%p=%d,s:%p=%d) len %d \n",
		  getpid(), rbuf, *rbuf, sbuf, *sbuf, buf_len);

	if (posix_memalign((void**)&p_rmr_rcv, 4096, 4096) ||
	    posix_memalign((void**)&p_rmr_snd, 4096, 4096)) {
		perror("malloc");
		exit(1);
	}
	LOGPRINTF("%d Allocated RMR buffers (r:%p,s:%p) len %d \n",
		  getpid(), p_rmr_rcv, p_rmr_snd, 4096);

	/* dat_ia_open, dat_pz_create */
	h_async_evd = DAT_HANDLE_NULL;
	start = get_time();
	ret = dat_ia_open(provider, 8, &h_async_evd, &h_ia);
	stop = get_time();
	ts.open += ((stop - start) * 1.0e6);
	ts.total += ts.open;
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d: Error Adaptor open: %s\n",
			getpid(), DT_RetToStr(ret));
		exit(1);
	} else
		LOGPRINTF("%d Opened Interface Adaptor\n", getpid());

	ret = dat_ia_query(h_ia, 0,
			   DAT_IA_FIELD_ALL, &ia_attr,
			   DAT_PROVIDER_FIELD_PROVIDER_SPECIFIC_ATTR,
			   &pr_attr);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d: Error Adaptor query: %s\n",
			getpid(), DT_RetToStr(ret));
		exit(1);
	}
	print_ia_address(ia_attr.ia_address_ptr);

	if (ia_attr.extension_supported == DAT_EXTENSION_IB)
		write_immed = 1;

	/* Provider specific attributes */
	for (i=0; i<pr_attr.num_provider_specific_attr; i++) {
		LOGPRINTF("%d provider_specific_attr[%d] %s = %s \n",
			  getpid(), i,
			  pr_attr.provider_specific_attr[i].name,
			  pr_attr.provider_specific_attr[i].value);
		if (!strcmp(pr_attr.provider_specific_attr[i].name,"DAT_IB_RDMA_READ") &&
		    !strcmp(pr_attr.provider_specific_attr[i].value,"TRUE") && !write_only)
			rdma_read = 1;
	}
	LOGPRINTF("%d provider_attr->max_private_data_size = %d\n",
		   getpid(), pr_attr.max_private_data_size);

	/* Create Protection Zone */
	start = get_time();
	LOGPRINTF("%d Create Protection Zone\n", getpid());
	ret = dat_pz_create(h_ia, &h_pz);
	stop = get_time();
	ts.pzc += ((stop - start) * 1.0e6);
	ts.total += ts.pzc;
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error creating Protection Zone: %s\n",
			getpid(), DT_RetToStr(ret));
		exit(1);
	} else
		LOGPRINTF("%d Created Protection Zone\n", getpid());

	/* Register memory */
	LOGPRINTF("%d Register RDMA memory\n", getpid());
	ret = register_rdma_memory();
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error registering RDMA memory: %s\n",
			getpid(), DT_RetToStr(ret));
		goto cleanup;
	} else
		LOGPRINTF("%d Register RDMA memory done\n", getpid());

	LOGPRINTF("%d Create events\n", getpid());
	ret = create_events();
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error creating events: %s\n",
			getpid(), DT_RetToStr(ret));
		goto cleanup;
	} else {
		LOGPRINTF("%d Create events done\n", getpid());
	}

	/* create EP */
	memset(&ep_attr, 0, sizeof(ep_attr));
	ep_attr.service_type = DAT_SERVICE_TYPE_RC;
	ep_attr.max_rdma_size = 0x10000;
	ep_attr.qos = 0;
	ep_attr.recv_completion_flags = 0;
	ep_attr.max_recv_dtos = rq_cnt;
	ep_attr.max_request_dtos = sq_cnt;
	ep_attr.max_recv_iov = MSG_IOV_COUNT;
	ep_attr.max_request_iov = MSG_IOV_COUNT;
	ep_attr.max_rdma_read_in = MAX_RDMA_RD;
	ep_attr.max_rdma_read_out = MAX_RDMA_RD;
	ep_attr.request_completion_flags = DAT_COMPLETION_DEFAULT_FLAG;
	ep_attr.ep_transport_specific_count = 0;
	ep_attr.ep_transport_specific = NULL;
	ep_attr.ep_provider_specific_count = 0;
	ep_attr.ep_provider_specific = NULL;

	start = get_time();
	ret = dat_ep_create(h_ia, h_pz, h_dto_rcv_evd,
			    h_dto_req_evd, h_conn_evd, &ep_attr, &h_ep);
	stop = get_time();
	ts.epc += ((stop - start) * 1.0e6);
	ts.total += ts.epc;
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error dat_ep_create: %s\n",
			getpid(), DT_RetToStr(ret));
		goto cleanup;
	} else
		LOGPRINTF("%d EP created %p \n", getpid(), h_ep);

	/*
	 * register message buffers, establish connection, and
	 * exchange DMA RMR information info via messages
	 */
	ret = connect_ep(hostname, SERVER_CONN_QUAL, ia_attr.ia_address_ptr);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error connect_ep: %s\n",
			getpid(), DT_RetToStr(ret));
		goto cleanup;
	} else
		LOGPRINTF("%d connect_ep complete\n", getpid());

	/* Query EP for local and remote address information, print */
	ret = dat_ep_query(h_ep, DAT_EP_FIELD_ALL, &ep_param);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error dat_ep_query: %s\n",
			getpid(), DT_RetToStr(ret));
		goto cleanup;
	} else
		LOGPRINTF("%d EP queried %p \n", getpid(), h_ep);
#if defined(_WIN32)
	printf("\n%d Query EP: LOCAL addr %s port %lld\n", getpid(),
	       inet_ntoa(((struct sockaddr_in *)
			  ep_param.local_ia_address_ptr)->sin_addr),
	       (ep_param.local_port_qual));
#else
	inet_ntop(AF_INET,
		  &((struct sockaddr_in *)ep_param.local_ia_address_ptr)->
		  sin_addr, addr_str, sizeof(addr_str));
	printf("\n%d Query EP: LOCAL addr %s port " F64x "\n", getpid(),
	       addr_str, (ep_param.local_port_qual));
#endif
#if defined(_WIN32)
	printf("%d Query EP: REMOTE addr %s port %lld\n", getpid(),
	       inet_ntoa(((struct sockaddr_in *)
			  ep_param.local_ia_address_ptr)->sin_addr),
	       (ep_param.remote_port_qual));
#else
	inet_ntop(AF_INET,
		  &((struct sockaddr_in *)ep_param.remote_ia_address_ptr)->
		  sin_addr, addr_str, sizeof(addr_str));
	printf("%d Query EP: REMOTE addr %s port " F64x "\n", getpid(),
	       addr_str, (ep_param.remote_port_qual));
#endif
	fflush(stdout);

#if CONNECT_ONLY
#if defined(_WIN32) || defined(_WIN64)
	Sleep(1 * 1000);
#else
	sleep(1);
#endif
	goto cleanup;
#endif

	/*********** RDMA write data *************/
	if (write_only_pp) {
		int max, inc;

		if (all_data_sizes) {
			if (increment) {
				i = 1;
				inc = increment;
				max = buf_len/inc;
			} else {
				i = 0;
				inc = 0;
				max = buf_len_p2;
			}
		} else {
			if (data_check || user_input_len) {
				i = buf_len;
				max = buf_len;
				inc = 1;
			}
			else
			{
				i = buf_len;
				max = buf_len;
				inc = buf_len;
			}
		}
		printf("\n %d RDMA WRITE PINGPONG with%s DATA CHECK\n\n", getpid(),
			data_check ? "":"out");

		for (; i <= max; i++) {
			if (all_data_sizes) {
				int l_len = (i*inc) ? (i*inc) : 1 << i;

				if ( l_len > 4 && do_rdma_write_ping_pong(i, l_len - 1)) {
					fprintf(stderr, "%d Error do_rdma_write_ping_pong\n", getpid());
					goto cleanup;
				}
			}

			if (do_rdma_write_ping_pong(i, i*inc)) {
				fprintf(stderr, "%d Error do_rdma_write_ping_pong\n", getpid());
				goto cleanup;
			}

			if (all_data_sizes) {
				int l_len = (i*inc) ? (i*inc) : 1 << i;

				if ( l_len > 1 && l_len < buf_len && do_rdma_write_ping_pong(i, l_len + 1)) {
					fprintf(stderr, "%d Error do_rdma_write_ping_pong\n", getpid());
					goto cleanup;
				}
			}
		}
	}
	else if (write_immed && write_only) {
		ret = do_rdma_write_imm_with_msg();
	}
	else {
		ret = do_rdma_write_with_msg();
	}

	if (!write_only_pp && ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error do_rdma_write_%swith_msg: %s\n",
			getpid(), write_immed && write_only ? "imm_":"",
			DT_RetToStr(ret));
		goto cleanup;
	} else
		LOGPRINTF("%d rdma_write test complete\n", getpid());

	if (write_only_pp || write_only || !rdma_read)
		goto complete;

	/*********** RDMA read data *************/
	ret = do_rdma_read_with_msg();
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error do_rdma_read_with_msg: %s\n",
			getpid(), DT_RetToStr(ret));
		goto cleanup;
	} else
		LOGPRINTF("%d do_rdma_read_with_msg complete\n", getpid());

	/*********** PING PING messages ************/
	ret = do_ping_pong_msg();
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error do_ping_pong_msg: %s\n",
			getpid(), DT_RetToStr(ret));
		goto cleanup;
	} else {
		LOGPRINTF("%d do_ping_pong_msg complete\n", getpid());
		goto complete;
	}

cleanup:
	failed++;
complete:

	/* disconnect and free EP resources */
	if (h_ep != DAT_HANDLE_NULL) {
		/* unregister message buffers and tear down connection */
		LOGPRINTF("%d Disconnect and Free EP %p \n", getpid(), h_ep);
		disconnect_ep();

		/* free EP */
		LOGPRINTF("%d Free EP %p \n", getpid(), h_ep);
		start = get_time();
		ret = dat_ep_free(h_ep);
		stop = get_time();
		ts.epf += ((stop - start) * 1.0e6);
		ts.total += ts.epf;
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error freeing EP: %s\n",
				getpid(), DT_RetToStr(ret));
		} else {
			LOGPRINTF("%d Freed EP\n", getpid());
			h_ep = DAT_HANDLE_NULL;
		}
	}
	if (connected)
		flush_evds();

	/* free EVDs */
	LOGPRINTF("%d destroy events\n", getpid());
	ret = destroy_events();
	if (ret != DAT_SUCCESS)
		fprintf(stderr, "%d Error destroy_events: %s\n",
			getpid(), DT_RetToStr(ret));
	else
		LOGPRINTF("%d destroy events done\n", getpid());

	ret = unregister_rdma_memory();
	LOGPRINTF("%d unregister_rdma_memory \n", getpid());
	if (ret != DAT_SUCCESS)
		fprintf(stderr, "%d Error unregister_rdma_memory: %s\n",
			getpid(), DT_RetToStr(ret));
	else
		LOGPRINTF("%d unregister_rdma_memory done\n", getpid());

	/* Free protection domain */
	LOGPRINTF("%d Freeing pz\n", getpid());
	start = get_time();
	ret = dat_pz_free(h_pz);
	stop = get_time();
	ts.pzf += ((stop - start) * 1.0e6);
	ts.total += ts.pzf;
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error freeing PZ: %s\n",
			getpid(), DT_RetToStr(ret));
	} else {
		LOGPRINTF("%d Freed pz\n", getpid());
		h_pz = NULL;
	}

	/* close the device */
	LOGPRINTF("%d Closing Interface Adaptor\n", getpid());
	start = get_time();
	ret = dat_ia_close(h_ia, DAT_CLOSE_ABRUPT_FLAG);
	stop = get_time();
	ts.close += ((stop - start) * 1.0e6);
	ts.total += ts.close;
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d: Error Adaptor close: %s\n",
			getpid(), DT_RetToStr(ret));
	} else
		LOGPRINTF("%d Closed Interface Adaptor\n", getpid());

	/* free rdma buffers */
	free(rbuf);
	free(sbuf);

	if (ts.rtt && !all_data_sizes) {
		printf( "%d: %s PingPong: (%d x %d) Total %6.2lf us:"
			" latency %3.2lf us, BW %4.2lf MB/s\n",
			getpid(), write_only_pp ? "RDMA write":"Message",
			write_only_pp ? burst : msg_burst, buf_len, ts.rtt,
			write_only_pp ? ts.rtt/burst/2:ts.rtt/msg_burst/2,
			write_only_pp ? (double)(1/(ts.rtt/burst/2/buf_len)):
					(double)(1/(ts.rtt/msg_burst/2/buf_len)));
	}

	if (ts.rdma_wr && (!server || (server && !uni_direction))) {
		int msgs = uni_direction ? burst : burst * 2;

		printf("\n%d: RDMA write (%s): Total=%6.2lf usec, itime=%6.2lf us, poll=%d, %d x %d, %4.2lf MB/sec\n",
			getpid(), uni_direction ? "uni-direction" : "bi-direction",
			ts.rdma_wr, ts.rdma_wr / msgs, rdma_wr_poll_count, msgs, buf_len,
			(double)(1/(ts.rdma_wr/msgs/buf_len)));
	}

	if (!performance_times)
		goto finish;

	for (i = 0; i < MAX_RDMA_RD; i++) {
		printf("%d: RDMA read:   Total=%10.2lf usec,   %d bursts, "
		       "itime=%10.2lf usec, pc=%d\n",
		       getpid(), ts.rdma_rd_total, MAX_RDMA_RD,
		       ts.rdma_rd[i], rdma_rd_poll_count[i]);
	}
	printf("%d: open:      %10.2lf usec\n", getpid(), ts.open);
	printf("%d: close:     %10.2lf usec\n", getpid(), ts.close);
	printf("%d: PZ create: %10.2lf usec\n", getpid(), ts.pzc);
	printf("%d: PZ free:   %10.2lf usec\n", getpid(), ts.pzf);
	printf("%d: LMR create:%10.2lf usec\n", getpid(), ts.reg);
	printf("%d: LMR free:  %10.2lf usec\n", getpid(), ts.unreg);
	printf("%d: EVD create:%10.2lf usec\n", getpid(), ts.evdc);
	printf("%d: EVD free:  %10.2lf usec\n", getpid(), ts.evdf);
	if (use_cno) {
		printf("%d: CNO create:  %10.2lf usec\n", getpid(), ts.cnoc);
		printf("%d: CNO free:    %10.2lf usec\n", getpid(), ts.cnof);
	}
	printf("%d: EP create: %10.2lf usec\n", getpid(), ts.epc);
	printf("%d: EP free:   %10.2lf usec\n", getpid(), ts.epf);
	if (!server)
		printf("%d: connect:   %10.2lf usec, poll_cnt=%d\n", 
		       getpid(), ts.conn, conn_poll_count);
	printf("%d: TOTAL:     %10.2lf usec\n", getpid(), ts.total);

finish:
	printf("\n%d: DAPL Test Complete. %s\n\n",
		getpid(), failed ? "FAILED" : "PASSED");

	fflush(stderr);
	fflush(stdout);

#if defined(_WIN32) || defined(_WIN64)
	WSACleanup();
#endif
	return (0);
}

static double get_time(void)
{
	struct timeval tp;

	gettimeofday(&tp, NULL);
	return ((double)tp.tv_sec + (double)tp.tv_usec * 1e-6);
}

static void init_data(void)
{
	memset(rbuf, 'a', buf_len);
	memset(sbuf, 'b', buf_len);
}

static DAT_RETURN
send_msg(void *data,
	 DAT_COUNT size,
	 DAT_LMR_CONTEXT context,
	 DAT_DTO_COOKIE cookie, DAT_COMPLETION_FLAGS flags)
{
	DAT_LMR_TRIPLET iov;
	DAT_EVENT event;
	DAT_RETURN ret;

	iov.lmr_context = context;
#if defined(_WIN32)
	iov.virtual_address = (DAT_VADDR) data;
#else
	iov.virtual_address = (DAT_VADDR) (unsigned long)data;
#endif
	iov.segment_length = size;

	LOGPRINTF("%d calling post_send\n", getpid());
	cookie.as_64 = 0xaaaa;
	ret = dat_ep_post_send(h_ep, 1, &iov, cookie, flags);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d: ERROR: dat_ep_post_send() %s\n",
			getpid(), DT_RetToStr(ret));
		return ret;
	}

	if (!(flags & DAT_COMPLETION_SUPPRESS_FLAG)) {
		
		if (collect_event(h_dto_req_evd, 
				  &event, 
				  DTO_TIMEOUT, 
				  &poll_count) != DAT_SUCCESS)
			return (DAT_ABORT);

		/* validate event number, len, cookie, and status */
		if (event.event_number != DAT_DTO_COMPLETION_EVENT) {
			fprintf(stderr, "%d: ERROR: DTO event number %s\n",
				getpid(), 
				DT_EventToStr(event.event_number));
			return (DAT_ABORT);
		}

		if ((event.event_data.dto_completion_event_data.
		     transfered_length != size)
		    || (event.event_data.dto_completion_event_data.user_cookie.
			as_64 != 0xaaaa)) {
			fprintf(stderr,
				"%d: ERROR: DTO len %d or cookie " F64x " \n",
				getpid(),
				event.event_data.dto_completion_event_data.
				transfered_length,
				event.event_data.dto_completion_event_data.
				user_cookie.as_64);
			return (DAT_ABORT);

		}
		if (event.event_data.dto_completion_event_data.status !=
		    DAT_DTO_SUCCESS) {
			fprintf(stderr, "%d: ERROR: DTO event status %s\n",
				getpid(), DT_RetToStr(ret));
			return (DAT_ABORT);
		}
	}

	return DAT_SUCCESS;
}

static
DAT_RETURN connect_ep(char *hostname,
		      DAT_CONN_QUAL conn_id,
		      struct sockaddr *ser_sa)
{
	DAT_IA_ADDRESS_PTR remote_addr = (DAT_IA_ADDRESS_PTR)&remote;
	DAT_RETURN ret;
	DAT_REGION_DESCRIPTION region;
	DAT_EVENT event;
	DAT_COUNT nmore;
	DAT_LMR_TRIPLET l_iov;
	DAT_RMR_TRIPLET r_iov;
	DAT_DTO_COOKIE cookie;
	int i;
	unsigned char *buf;
	DAT_CR_PARAM cr_param = { 0 };
	unsigned char pdata[48] = { 0 };

	/* Register send message buffer */
	LOGPRINTF("%d Registering send Message Buffer %p, len %d\n",
		  getpid(), p_rmr_snd, (int)sizeof(DAT_RMR_TRIPLET));
	region.for_va = p_rmr_snd;
	ret = dat_lmr_create(h_ia,
			     DAT_MEM_TYPE_VIRTUAL,
			     region,
			     sizeof(DAT_RMR_TRIPLET),
			     h_pz,
			     DAT_MEM_PRIV_LOCAL_WRITE_FLAG,
			     DAT_VA_TYPE_VA,
			     &h_lmr_send_msg,
			     &lmr_context_send_msg,
			     &rmr_context_send_msg,
			     &registered_size_send_msg,
			     &registered_addr_send_msg);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error registering send msg buffer: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else
		LOGPRINTF("%d Registered send Message Buffer %p \n",
			  getpid(), region.for_va);

	/* Register Receive buffers */
	LOGPRINTF("%d Registering Receive Message Buffer %p\n",
		  getpid(), p_rmr_rcv);
	region.for_va = p_rmr_rcv;
	ret = dat_lmr_create(h_ia,
			     DAT_MEM_TYPE_VIRTUAL,
			     region,
			     sizeof(DAT_RMR_TRIPLET) * MSG_BUF_COUNT,
			     h_pz,
			     DAT_MEM_PRIV_LOCAL_WRITE_FLAG,
			     DAT_VA_TYPE_VA,
			     &h_lmr_recv_msg,
			     &lmr_context_recv_msg,
			     &rmr_context_recv_msg,
			     &registered_size_recv_msg,
			     &registered_addr_recv_msg);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error registering recv msg buffer: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else
		LOGPRINTF("%d Registered Receive Message Buffer %p\n",
			  getpid(), region.for_va);

	for (i = 0; i < MSG_BUF_COUNT; i++) {
		cookie.as_64 = i;
		l_iov.lmr_context = lmr_context_recv_msg;
#if defined(_WIN32)
		l_iov.virtual_address = (DAT_VADDR) &p_rmr_rcv[i];
#else
		l_iov.virtual_address = (DAT_VADDR) (unsigned long)&p_rmr_rcv[i];
#endif
		l_iov.segment_length = sizeof(DAT_RMR_TRIPLET);

		LOGPRINTF("%d Posting Receive Message Buffer %p\n",
			  getpid(), &p_rmr_rcv[i]);
		ret = dat_ep_post_recv(h_ep,
				       1,
				       &l_iov,
				       cookie, DAT_COMPLETION_DEFAULT_FLAG);

		if (ret != DAT_SUCCESS) {
			fprintf(stderr,
				"%d Error registering recv msg buffer: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else
			LOGPRINTF("%d Registered Receive Message Buffer %p\n",
				  getpid(), region.for_va);

	}

	/* setup receive rdma buffer to initial string to be overwritten */
	strcpy((char *)rbuf, "blah, blah, blah\n");

	/* clear event structure */
	memset(&event, 0, sizeof(DAT_EVENT));

	if (server) {		/* SERVER */

		/* Exchange info with client */
		printf("%d Server is waiting for client connection to send"
			" server info\n",
			getpid());
		fflush(stdout);
		if (send_server_params(ser_sa)) {
			printf("%d Failed to send server params\n", getpid());
			return -1;
		}

		/* create the service point for server listen */
		LOGPRINTF("%d Creating service point for listen\n", getpid());
		ret = dat_psp_create(h_ia,
				     conn_id,
				     h_cr_evd, DAT_PSP_CONSUMER_FLAG, &h_psp);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error dat_psp_create: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else
			LOGPRINTF("%d dat_psp_created for server listen\n",
				  getpid());

		printf("%d Server waiting for connect request on port " F64x
		       "\n", getpid(), conn_id);

		ret = dat_evd_wait(h_cr_evd, SERVER_TIMEOUT, 1, &event, &nmore);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error dat_evd_wait: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else
			LOGPRINTF("%d dat_evd_wait for cr_evd completed\n",
				  getpid());

		if (event.event_number != DAT_CONNECTION_REQUEST_EVENT) {
			fprintf(stderr, "%d Error unexpected cr event : %s\n",
				getpid(), 
				DT_EventToStr(event.event_number));
			return (DAT_ABORT);
		}
		if ((event.event_data.cr_arrival_event_data.conn_qual !=
		     SERVER_CONN_QUAL)
		    || (event.event_data.cr_arrival_event_data.sp_handle.
			psp_handle != h_psp)) {
			fprintf(stderr, "%d Error wrong cr event data : %s\n",
				getpid(), 
				DT_EventToStr(event.event_number));
			return (DAT_ABORT);
		}

		/* use to test rdma_cma timeout logic */
#if defined(_WIN32) || defined(_WIN64)
		if (delay)
			Sleep(delay * 1000);
#else
		if (delay)
			sleep(delay);
#endif

		/* accept connect request from client */
		h_cr = event.event_data.cr_arrival_event_data.cr_handle;
		LOGPRINTF("%d Accepting connect request from client\n",
			  getpid());

		/* private data - check and send it back */
		dat_cr_query(h_cr, DAT_CSP_FIELD_ALL, &cr_param);

		buf = (unsigned char *)cr_param.private_data;
		LOGPRINTF("%d CONN REQUEST Private Data %p[0]=%d [47]=%d\n",
			  getpid(), buf, buf[0], buf[47]);
		for (i = 0; i < 48; i++) {
			if (buf[i] != i + 1) {
				fprintf(stderr, "%d Error with CONNECT REQUEST"
					" private data: %p[%d]=%d s/be %d\n",
					getpid(), buf, i, buf[i], i + 1);
				dat_cr_reject(h_cr, 0, NULL);
				return (DAT_ABORT);
			}
			buf[i]++;	/* change for trip back */
		}

#ifdef TEST_REJECT_WITH_PRIVATE_DATA
		printf("%d REJECT request with 48 bytes of private data\n",
		       getpid());
		ret = dat_cr_reject(h_cr, 48, cr_param.private_data);
		printf("\n%d: DAPL Test Complete. %s\n\n",
		       getpid(), ret ? "FAILED" : "PASSED");
		exit(0);
#endif

		ret = dat_cr_accept(h_cr, h_ep, 48, cr_param.private_data);

		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error dat_cr_accept: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else
			LOGPRINTF("%d dat_cr_accept completed\n", getpid());
	} else {		/* CLIENT */
		struct addrinfo *target;
		int rval;

		if (ucm)
			goto no_resolution;

#if defined(_WIN32) || defined(_WIN64)
		if ((rval = getaddrinfo(hostname, "ftp", NULL, &target)) != 0) {
			printf("\n remote name resolution failed! %s\n",
			       gai_strerror(rval));
			exit(1);
		}
		rval = ((struct sockaddr_in *)target->ai_addr)->sin_addr.s_addr;
#else
		if (getaddrinfo(hostname, NULL, NULL, &target) != 0) {
			perror("\n remote name resolution failed!");
			exit(1);
		}
		rval = ((struct sockaddr_in *)target->ai_addr)->sin_addr.s_addr;
#endif
		printf("%d Server Name: %s \n", getpid(), hostname);
		printf("%d Server Net Address: %d.%d.%d.%d port " F64x "\n",
		       getpid(), (rval >> 0) & 0xff, (rval >> 8) & 0xff,
		       (rval >> 16) & 0xff, (rval >> 24) & 0xff, conn_id);

		remote_addr = (DAT_IA_ADDRESS_PTR)target->ai_addr; /* IP */
no_resolution:
		for (i = 0; i < 48; i++)	/* simple pattern in private data */
			pdata[i] = i + 1;

		LOGPRINTF("%d Connecting to server\n", getpid());
        	start = get_time();
		ret = dat_ep_connect(h_ep,
				     remote_addr,
				     conn_id,
				     CONN_TIMEOUT,
				     48,
				     (DAT_PVOID) pdata,
				     0, DAT_CONNECT_DEFAULT_FLAG);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error dat_ep_connect: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else
			LOGPRINTF("%d dat_ep_connect completed\n", getpid());

		if (!ucm)
			freeaddrinfo(target);
	}

	printf("%d Waiting for connect response\n", getpid());

	if (polling) 
		while (DAT_GET_TYPE(dat_evd_dequeue(h_conn_evd, &event)) == 
		       DAT_QUEUE_EMPTY)
			conn_poll_count++;
	else 
		ret = dat_evd_wait(h_conn_evd, DAT_TIMEOUT_INFINITE, 
				   1, &event, &nmore);

	if (!server) {
        	stop = get_time();
        	ts.conn += ((stop - start) * 1.0e6);
	}

#ifdef TEST_REJECT_WITH_PRIVATE_DATA
	if (event.event_number != DAT_CONNECTION_EVENT_PEER_REJECTED) {
		fprintf(stderr, "%d expected conn reject event : %s\n",
			getpid(), DT_EventToStr(event.event_number));
		return (DAT_ABORT);
	}
	/* get the reject private data and validate */
	buf = (unsigned char *)event.event_data.connect_event_data.private_data;
	printf("%d Received REJECT with private data %p[0]=%d [47]=%d\n",
	       getpid(), buf, buf[0], buf[47]);
	for (i = 0; i < 48; i++) {
		if (buf[i] != i + 2) {
			fprintf(stderr, "%d client: Error with REJECT event"
				" private data: %p[%d]=%d s/be %d\n",
				getpid(), buf, i, buf[i], i + 2);
			dat_ep_disconnect(h_ep, DAT_CLOSE_ABRUPT_FLAG);
			return (DAT_ABORT);
		}
	}
	printf("\n%d: DAPL Test Complete. PASSED\n\n", getpid());
	exit(0);
#endif

	if (event.event_number != DAT_CONNECTION_EVENT_ESTABLISHED) {
		fprintf(stderr, "%d Error unexpected conn event : 0x%x %s\n",
			getpid(), event.event_number,
			DT_EventToStr(event.event_number));
		return (DAT_ABORT);
	}

	/* check private data back from server  */
	if (!server) {
		buf =
		    (unsigned char *)event.event_data.connect_event_data.
		    private_data;
		LOGPRINTF("%d CONN Private Data %p[0]=%d [47]=%d\n", getpid(),
			  buf, buf[0], buf[47]);
		for (i = 0; i < 48; i++) {
			if (buf[i] != i + 2) {
				fprintf(stderr, "%d Error with CONNECT event"
					" private data: %p[%d]=%d s/be %d\n",
					getpid(), buf, i, buf[i], i + 2);
				dat_ep_disconnect(h_ep, DAT_CLOSE_ABRUPT_FLAG);
				LOGPRINTF
				    ("%d waiting for disconnect event...\n",
				     getpid());
				dat_evd_wait(h_conn_evd, DAT_TIMEOUT_INFINITE,
					     1, &event, &nmore);
				return (DAT_ABORT);
			}
		}
	}

	printf("\n%d CONNECTED!\n\n", getpid());
	connected = 1;
	fflush(stdout);

#if CONNECT_ONLY
	return 0;
#endif
	/*
	 *  Setup our remote memory and tell the other side about it
	 */
	p_rmr_snd->virtual_address = htonll((DAT_VADDR) (uintptr_t) rbuf);
	p_rmr_snd->segment_length = htonl(buf_len);
	p_rmr_snd->rmr_context = htonl(rmr_context_recv);

	printf("%d Send RMR msg to remote: r_key_ctx=0x%x,va=%p,len=0x%x\n",
	       getpid(), rmr_context_recv, rbuf, buf_len);

	ret = send_msg(p_rmr_snd,
		       sizeof(DAT_RMR_TRIPLET),
		       lmr_context_send_msg,
		       cookie, DAT_COMPLETION_DEFAULT_FLAG);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error send_msg: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else
		LOGPRINTF("%d send_msg completed\n", getpid());

	/*
	 *  Wait for remote RMR information for RDMA
	 */
	if (collect_event(h_dto_rcv_evd, 
			  &event, 
			  DTO_TIMEOUT, 
			  &poll_count) != DAT_SUCCESS)
		return (DAT_ABORT);
	
	printf("%d remote RMR data arrived!\n", getpid());

	if (event.event_number != DAT_DTO_COMPLETION_EVENT) {
		fprintf(stderr, "%d Error unexpected DTO event: 0x%x %s\n",
			getpid(), event.event_number,
			DT_EventToStr(event.event_number));
		return (DAT_ABORT);
	}
	if ((event.event_data.dto_completion_event_data.transfered_length !=
	     sizeof(DAT_RMR_TRIPLET)) ||
	    (event.event_data.dto_completion_event_data.user_cookie.as_64 !=
	     recv_msg_index)) {
		fprintf(stderr,
			"ERR recv event: len=%d cookie=" F64x
			" expected %d/%d\n",
			(int)event.event_data.dto_completion_event_data.
			transfered_length,
			event.event_data.dto_completion_event_data.user_cookie.
			as_64, (int)sizeof(DAT_RMR_TRIPLET), recv_msg_index);
		return (DAT_ABORT);
	}

	/* swap received RMR msg: network order to host order */
	r_iov = p_rmr_rcv[recv_msg_index];
	p_rmr_rcv[recv_msg_index].rmr_context = ntohl(r_iov.rmr_context);
	p_rmr_rcv[recv_msg_index].virtual_address = ntohll(r_iov.virtual_address);
	p_rmr_rcv[recv_msg_index].segment_length = ntohl(r_iov.segment_length);

	printf("%d Received RMR from remote: "
	       "r_iov: r_key_ctx=%x,va=" F64x ",len=0x%x\n",
	       getpid(), p_rmr_rcv[recv_msg_index].rmr_context,
	       p_rmr_rcv[recv_msg_index].virtual_address,
	       p_rmr_rcv[recv_msg_index].segment_length);

	recv_msg_index++;

	return (DAT_SUCCESS);
}

static void disconnect_ep(void)
{
	DAT_RETURN ret;
	DAT_EVENT event;
	DAT_COUNT nmore;

	if (connected) {

		/* 
		 * Only the client needs to call disconnect. The server _should_ be able
		 * to just wait on the EVD associated with connection events for a
		 * disconnect request and then exit.
		 */
		if (!server) {
			LOGPRINTF("%d dat_ep_disconnect\n", getpid());
			ret = dat_ep_disconnect(h_ep, DAT_CLOSE_DEFAULT);
			if (ret != DAT_SUCCESS) {
				fprintf(stderr,
					"%d Error dat_ep_disconnect: %s\n",
					getpid(), DT_RetToStr(ret));
			} else {
				LOGPRINTF("%d dat_ep_disconnect completed\n",
					  getpid());
			}
		} else {
			LOGPRINTF("%d Server waiting for disconnect...\n",
				  getpid());
		}

		ret =
		    dat_evd_wait(h_conn_evd, DAT_TIMEOUT_INFINITE, 1, &event,
				 &nmore);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error dat_evd_wait: %s\n",
				getpid(), DT_RetToStr(ret));
		} else {
			LOGPRINTF("%d dat_evd_wait for h_conn_evd completed\n",
				  getpid());
		}
	}

	/* destroy service point */
	if ((server) && (h_psp != DAT_HANDLE_NULL)) {
		ret = dat_psp_free(h_psp);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error dat_psp_free: %s\n",
				getpid(), DT_RetToStr(ret));
		} else {
			LOGPRINTF("%d dat_psp_free completed\n", getpid());
		}
	}

	/* Unregister Send message Buffer */
	if (h_lmr_send_msg != DAT_HANDLE_NULL) {
		LOGPRINTF("%d Unregister send message h_lmr %p \n", getpid(),
			  h_lmr_send_msg);
		ret = dat_lmr_free(h_lmr_send_msg);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr,
				"%d Error deregistering send msg mr: %s\n",
				getpid(), DT_RetToStr(ret));
		} else {
			LOGPRINTF("%d Unregistered send message Buffer\n",
				  getpid());
			h_lmr_send_msg = NULL;
		}
	}

	/* Unregister recv message Buffer */
	if (h_lmr_recv_msg != DAT_HANDLE_NULL) {
		LOGPRINTF("%d Unregister recv message h_lmr %p \n", getpid(),
			  h_lmr_recv_msg);
		ret = dat_lmr_free(h_lmr_recv_msg);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr,
				"%d Error deregistering recv msg mr: %s\n",
				getpid(), DT_RetToStr(ret));
		} else {
			LOGPRINTF("%d Unregistered recv message Buffer\n",
				  getpid());
			h_lmr_recv_msg = NULL;
		}
	}
	return;
}

static DAT_RETURN do_rdma_write_with_msg(void)
{
	DAT_EVENT event;
	DAT_DTO_COMPLETION_EVENT_DATA *dto_event;
	DAT_LMR_TRIPLET l_iov[MSG_IOV_COUNT];
	DAT_RMR_TRIPLET r_iov;
	DAT_DTO_COOKIE cookie;
	DAT_RETURN ret;
	DAT_COMPLETION_FLAGS flags;
	int i;

	printf("\n %d RDMA WRITE DATA with SEND MSG\n\n", getpid());

	dto_event = &event.event_data.dto_completion_event_data;

	if (recv_msg_index >= MSG_BUF_COUNT)
		return (DAT_ABORT);

	/* get RMR information from previously received message */
	r_iov = p_rmr_rcv[recv_msg_index - 1];

	if (server)
		strcpy((char *)sbuf, "server RDMA write data...");
	else
		strcpy((char *)sbuf, "client RDMA write data...");

	if  (uni_direction && server)
		goto rmsg;

	for (i = 0; i < MSG_IOV_COUNT; i++) {
		l_iov[i].lmr_context = lmr_context_send;
		l_iov[i].segment_length = buf_len / MSG_IOV_COUNT;
		l_iov[i].virtual_address = (DAT_VADDR) (uintptr_t)
		    (&sbuf[l_iov[i].segment_length * i]);

		LOGPRINTF("%d rdma_write iov[%d] buf=%p,len=%d\n",
			  getpid(), i, &sbuf[l_iov[i].segment_length * i],
			  l_iov[i].segment_length);
	}

	start = get_time();
	for (i = 0; i < burst; i++) {
		if (!((i+1) % signal_rate))
			flags =  DAT_COMPLETION_DEFAULT_FLAG;
		else
			flags = DAT_COMPLETION_SUPPRESS_FLAG;

		cookie.as_64 = i;
		LOGPRINTF("%d rdma_write # %d %s\n",
			  getpid(), i + 1, flags ? "SUPPRESS":"SIGNAL");
		ret = dat_ep_post_rdma_write(h_ep,	// ep_handle
					     MSG_IOV_COUNT,	// num_segments
					     l_iov,	// LMR
					     cookie,	// user_cookie
					     &r_iov,	// RMR
					     flags);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr,
				"%d: ERROR: dat_ep_post_rdma_write() %s\n",
				getpid(), DT_RetToStr(ret));
			return (DAT_ABORT);
		}
		if (flags == DAT_COMPLETION_DEFAULT_FLAG) {
			if (collect_event(h_dto_req_evd,
					  &event,
					  DTO_TIMEOUT,
					  &rdma_wr_poll_count) != DAT_SUCCESS) {
				printf("%d %s RDMA write buffer contains: %s\n",
				       getpid(), server ? "SERVER:" : "CLIENT:", rbuf);
				return (DAT_ABORT);
			}
			if (dto_event->status ||
			    dto_event->user_cookie.as_64 != i) {
				fprintf(stderr,	"ERROR rdma_write: cookie="
						" "F64x " exp 0x%x st 0x%x\n",
					dto_event->user_cookie.as_64, i,
					dto_event->status);
				return (DAT_ABORT);
			}
		}
		LOGPRINTF("%d rdma_write # %d completed\n", getpid(), i + 1);
	}

	if (server)
		goto rmsg;
smsg:
	printf("%d Sending RDMA WRITE completion message\n", getpid());

	ret = send_msg(p_rmr_snd,
		       sizeof(DAT_RMR_TRIPLET),
		       lmr_context_send_msg,
		       cookie, DAT_COMPLETION_SUPPRESS_FLAG);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error send_msg: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else {
		LOGPRINTF("%d send_msg completed\n", getpid());
	}
	if (server)
		goto acked;
rmsg:
	/* inbound recv event, send completion's suppressed */
	if (collect_event(h_dto_rcv_evd,
			  &event,
			  DTO_TIMEOUT,
			  &rdma_wr_poll_count) != DAT_SUCCESS) {
		printf("%d %s RDMA write buffer contains: %s\n",
			getpid(), server ? "SERVER:" : "CLIENT:", rbuf);
		return (DAT_ABORT);
	}
	stop = get_time();
	ts.rdma_wr = ((stop - start) * 1.0e6);

	/* validate event number and status */
	printf("%d inbound rdma_write; send message arrived!\n", getpid());
	if (event.event_number != DAT_DTO_COMPLETION_EVENT) {
		fprintf(stderr, "%d Error unexpected DTO event : %s\n",
			getpid(), DT_EventToStr(event.event_number));
		return (DAT_ABORT);
	}

	if ((event.event_data.dto_completion_event_data.transfered_length !=
	     sizeof(DAT_RMR_TRIPLET))
	    || (event.event_data.dto_completion_event_data.user_cookie.as_64 !=
		recv_msg_index)) {
		fprintf(stderr,
			"unexpected event data for receive: st=%d len=%d"
			"cookie=" F64x " exp %d/%d\n",
			event.event_data.dto_completion_event_data.status,
			(int)event.event_data.dto_completion_event_data.transfered_length,
			event.event_data.dto_completion_event_data.user_cookie.
			as_64, (int)sizeof(DAT_RMR_TRIPLET), recv_msg_index);

		return (DAT_ABORT);
	}
	if (server)
		goto smsg;
acked:

	/* swap received RMR msg: network order to host order */
	r_iov = p_rmr_rcv[recv_msg_index];
	p_rmr_rcv[recv_msg_index].virtual_address =
	    ntohll(p_rmr_rcv[recv_msg_index].virtual_address);
	p_rmr_rcv[recv_msg_index].segment_length =
	    ntohl(p_rmr_rcv[recv_msg_index].segment_length);
	p_rmr_rcv[recv_msg_index].rmr_context =
	    ntohl(p_rmr_rcv[recv_msg_index].rmr_context);

	printf("%d Received RMR from remote: "
	       "r_iov: r_key_ctx=%x,va=" F64x ",len=0x%x\n",
	       getpid(), p_rmr_rcv[recv_msg_index].rmr_context,
	       p_rmr_rcv[recv_msg_index].virtual_address,
	       p_rmr_rcv[recv_msg_index].segment_length);

	LOGPRINTF("%d inbound rdma_write; send msg event SUCCESS!!\n",
		  getpid());

	printf("%d %s RDMA write buffer contains: %s\n",
	       getpid(), server ? "SERVER:" : "CLIENT:", rbuf);

	recv_msg_index++;

	return (DAT_SUCCESS);
}

static DAT_RETURN do_rdma_write_imm_with_msg(void)
{
	DAT_EVENT event;
	DAT_LMR_TRIPLET l_iov[MSG_IOV_COUNT];
	DAT_RMR_TRIPLET r_iov;
	DAT_DTO_COOKIE cookie;
	DAT_RETURN ret;
	int i, flags = DAT_COMPLETION_SUPPRESS_FLAG;
	DAT_DTO_COMPLETION_EVENT_DATA *dto_event =
		&event.event_data.dto_completion_event_data;
	DAT_IB_EXTENSION_EVENT_DATA *ext_event =
		(DAT_IB_EXTENSION_EVENT_DATA*) event.event_extension_data;

	printf("\n %d RDMA WRITE IMM DATA with SEND MSG\n\n", getpid());

	cookie.as_64 = 0x5555;

	if (recv_msg_index >= MSG_BUF_COUNT)
		return (DAT_ABORT);

	/* get RMR information from previously received message */
	r_iov = p_rmr_rcv[recv_msg_index - 1];

	if (server)
		strcpy((char *)sbuf, "server RDMA write data...");
	else
		strcpy((char *)sbuf, "client RDMA write data...");

	for (i = 0; i < MSG_IOV_COUNT; i++) {
		l_iov[i].lmr_context = lmr_context_send;
		l_iov[i].segment_length = buf_len / MSG_IOV_COUNT;
		l_iov[i].virtual_address = (DAT_VADDR) (uintptr_t)
		    (&sbuf[l_iov[i].segment_length * i]);

		LOGPRINTF("%d rdma_write iov[%d] buf=%p,len=%d\n",
			  getpid(), i, &sbuf[l_iov[i].segment_length * i],
			  l_iov[i].segment_length);
	}

	if  (uni_direction && server)
		goto done;

	start = get_time();
	for (i = 0; i < burst; i++) {
		if (i==0)
			sprintf(&sbuf[25],"rdma_writes= ");

		sprintf(&sbuf[25], "rdma writes completed == %d", i+1);
		sbuf[buf_len-1] = i;
		if (!((i+1) % signal_rate))
			flags =  DAT_COMPLETION_DEFAULT_FLAG;
		else
			flags = DAT_COMPLETION_SUPPRESS_FLAG;

		cookie.as_64 = i;
		LOGPRINTF("%d rdma_write # %d %s\n", getpid(), i + 1, flags ? "SUPPRESS":"SIGNAL");
		/* last message is write_immed with buf_len as imm_data */
		if (i == (burst - 1)) {
			ret = dat_ib_post_rdma_write_immed(
				h_ep, MSG_IOV_COUNT, l_iov, cookie,
				&r_iov,  0x7777, flags);
		} else {
			ret = dat_ep_post_rdma_write(h_ep, MSG_IOV_COUNT,
					             l_iov, cookie, &r_iov,
					             flags);
		}
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d: ERROR: dat_rdma_write() %s\n",
					getpid(), DT_RetToStr(ret));
			return (DAT_ABORT);
		}
		LOGPRINTF("%d rdma_write # %d completed\n", getpid(), i + 1);

		if (flags == DAT_COMPLETION_DEFAULT_FLAG) {
			if (collect_event(h_dto_req_evd,
					  &event,
					  DTO_TIMEOUT,
					  &rdma_wr_poll_count) != DAT_SUCCESS)
				return (DAT_ABORT);
			if (dto_event->user_cookie.as_64 != i) {
				fprintf(stderr,	"ERROR rdma_write: cookie="
						" "F64x " exp 0x%x\n",
					dto_event->user_cookie.as_64, i);
				return (DAT_ABORT);
			}
		}
	}

	if (uni_direction && !server)
		goto smsg;
done:
	/* Wait to RECEIVE the LAST message, immediate data expected */
	LOGPRINTF("%d Waiting for final inbound RW_imm from peer\n", getpid());
	if (collect_event(h_dto_rcv_evd,
			  &event,
			  DTO_TIMEOUT,
			  &rdma_wr_poll_count) != DAT_SUCCESS)
		return (DAT_ABORT);

	if (event.event_number != (int)DAT_IB_DTO_EVENT ||
	    ext_event->type != DAT_IB_RDMA_WRITE_IMMED_DATA ||
	    ext_event->val.immed.data != 0x7777) {
		printf("unexpected event 0x%x type 0x%x or idata 0x%x"
		       ", waiting for RW-IMMED #0x%x\n",
		       event.event_number, ext_event->type,
		       ext_event->val.immed.data, DAT_IB_DTO_EVENT);
		return (DAT_ABORT);
	}
	recv_msg_index++;

	if (server)
		goto rmsg;
smsg:
	LOGPRINTF("%d sending LAST msg ACK to remote\n", getpid());
	/* Send last message received ACK message back */
	cookie.as_64 = 0x9999;
	ret = send_msg(p_rmr_snd,
		       sizeof(DAT_RMR_TRIPLET),
		       lmr_context_send_msg,
		       cookie, DAT_COMPLETION_SUPPRESS_FLAG);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error send_msg: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else {
		LOGPRINTF("%d send_msg completed\n", getpid());
	}

	if (server)
		goto acked;
rmsg:
	/* Wait for my LAST message ACK from remote side */
	LOGPRINTF("%d waiting for LAST msg ACK from remote\n", getpid());
	if (collect_event(h_dto_rcv_evd,
			  &event,
			  DTO_TIMEOUT,
			  &rdma_wr_poll_count) != DAT_SUCCESS)
		return (DAT_ABORT);

	LOGPRINTF("%d LAST rdma write ACK message arrived!\n", getpid());
	if (event.event_number != DAT_DTO_COMPLETION_EVENT) {
		fprintf(stderr, "%d Error unexpected DTO event : %s\n",
			getpid(), DT_EventToStr(event.event_number));
		return (DAT_ABORT);
	}

	if ((dto_event->transfered_length != sizeof(DAT_RMR_TRIPLET))
	    || (dto_event->user_cookie.as_64 != recv_msg_index)) {
		fprintf(stderr,
			"unexpected event data for receive: len=%d "
			"cookie=" F64x" exp %d/%d\n",
			(int)dto_event->transfered_length,
			dto_event->user_cookie.as_64,
			(int)sizeof(DAT_RMR_TRIPLET), recv_msg_index);
		return (DAT_ABORT);
	}
	LOGPRINTF("%d LAST RDMA_WRITE ACK from remote \n", getpid());

	if (server)
		goto smsg;
acked:
	stop = get_time();
	ts.rdma_wr = ((stop - start) * 1.0e6);

	LOGPRINTF("%d last rdma_write ACK'ed SUCCESS!!\n", getpid());

	if (server || (!server && !uni_direction))
		printf("%d %s RDMA write buffer contains: %s last byte=%d\n",
		       getpid(), server ? "SERVER:" : "CLIENT:", rbuf, rbuf[buf_len-1]);

	if (server && uni_direction)
		sleep(1);

	recv_msg_index++;
	return (DAT_SUCCESS);
}

#define PAT_NUM 5
static unsigned char pat[PAT_NUM] = { 0, 0xff, 0x55, 0xaa, 0 };

static void set_pat(unsigned int len, unsigned int pat_num)
{
	if (len <= 1)
		return;

	if (pat_num >= PAT_NUM) {
		printf("\n\tpat_num = %d. max valid number is %d.\n\n", pat_num, PAT_NUM - 1);
		exit(1);
	}

	if (server) {
		/* server */
		if (pat_num == PAT_NUM - 1) {
			/* future: random data, add checksum */
			;
		} else {
			/* check first byte only for some speed */
			if ((unsigned char)rbuf[0] != (unsigned char)pat[pat_num]) {
				fprintf(stderr,"%d: ERR: message len is %d,"
						" location 0. Rx 0x%x expected"
						" 0x%x, pat %d\n",
						getpid(), len, (unsigned char)rbuf[0],
						(unsigned char)pat[pat_num], pat_num);
			}
		}
		memcpy(sbuf, rbuf, len - 1);

	} else {
		/* client */
		int i;

		if (pat_num == PAT_NUM - 1) { /* set random values */
			struct timeval tv;

			gettimeofday(&tv, NULL);
			srand((unsigned int)tv.tv_usec);
			for (i = 0; i < len - 1; i++)
				sbuf[i] = (unsigned char)rand();
		} else {
			memset(sbuf, (unsigned char)pat[pat_num], len - 1);
		}
	}
}


/* always uni-direction */
static DAT_RETURN do_rdma_write_ping_pong(int p2, int bytes)
{
	DAT_EVENT event;
	DAT_LMR_TRIPLET l_iov[MSG_IOV_COUNT];
	DAT_RMR_TRIPLET r_iov;
	DAT_DTO_COOKIE cookie;
	DAT_RETURN ret;
	int i, len, suppress = DAT_COMPLETION_SUPPRESS_FLAG;
	DAT_DTO_COMPLETION_EVENT_DATA *dto_event =
		&event.event_data.dto_completion_event_data;
	volatile char *tx_buf, *rx_buf;
	uint32_t rx_cnt = 0;
	uint32_t tx_cnt = 0;
	unsigned char rx_idx = 0;

	len = bytes ? bytes : 1 << p2;

	tx_buf = (char*)&sbuf[len-1];
	rx_buf = (char*)&rbuf[len-1];

	/* RMR information from previously received message */
	r_iov = p_rmr_rcv[recv_msg_index - 1];

	for (i = 0; i < MSG_IOV_COUNT; i++) {
		l_iov[i].lmr_context = lmr_context_send;
		l_iov[i].segment_length = len / MSG_IOV_COUNT;
		l_iov[i].virtual_address = (DAT_VADDR) (uintptr_t)
					   (&sbuf[l_iov[i].segment_length*i]);
		LOGPRINTF("%d rdma_write iov[%d] buf=%p,len=%d\n",
			  getpid(), i,
			  &sbuf[l_iov[i].segment_length * i],
			  l_iov[i].segment_length);
	}
	start = get_time();
	for (i = 0; i <= burst; i++) {
		if (rx_cnt < burst && !(!server && !tx_cnt)) {
			rx_cnt++;
			while (*rx_buf != (char)rx_cnt);
			rx_idx = (unsigned char)*rx_buf;

			if (data_check && !server && memcmp(sbuf, rbuf, len)) {
				int l=0, ll;
				fprintf(stderr, "%d: ERR: Tx data from server wrong\n", getpid());

				while (sbuf[l] == rbuf[l] && l < len)
					l++;

				fprintf(stderr,"%d: len %d, 1st error at %d. Tx 0x%x Rx 0x%x\n",
						getpid(), len, l, (unsigned char)sbuf[l],
						(unsigned char)rbuf[l]);
				fprintf(stderr,"%d: rcnt %d (char = %d), tcnt %d, *rbuf %d\n",
						getpid(), rx_cnt, (char)rx_cnt, tx_cnt,
						(unsigned char)*rx_buf);
				fprintf(stderr, "Send:");

				for (ll=l; ll < len && ll < 1 + 64; ll++)
					fprintf(stderr,"%02x", (unsigned char)sbuf[ll]);

				fprintf(stderr, "\nRecv:");

				for (ll=l; ll < len && ll < 1 + 64; ll++)
					fprintf(stderr,"%02x", (unsigned char)rbuf[ll]);

				fprintf(stderr, "\n");
				return (DAT_ABORT);
			}
		}

		if (!((i+1) % signal_rate))
			suppress =  DAT_COMPLETION_DEFAULT_FLAG;
		else
			suppress = DAT_COMPLETION_SUPPRESS_FLAG;

		if (tx_cnt == burst)
			break;

		if (data_check)
			set_pat(len, tx_cnt % PAT_NUM);

		*tx_buf = (char)++tx_cnt;
		cookie.as_64 = tx_cnt;
		ret = dat_ep_post_rdma_write(h_ep, MSG_IOV_COUNT,
					     l_iov, cookie, &r_iov,
					     suppress);
		if (ret) {
			fprintf(stderr, "%d: ERROR: dat_rdma_write() %s\n",
					getpid(), DT_RetToStr(ret));
			return (DAT_ABORT);
		}
		if (!suppress) {
			while (dat_evd_dequeue(h_dto_req_evd, &event));
			if (dto_event->status) {
				fprintf(stderr,
					"ERROR rdma_write: status=0x%x ck="
					" "F64x " exp 0x%x\n",
					dto_event->status,
					dto_event->user_cookie.as_64, tx_cnt);
				return (DAT_ABORT);
			}
		}
		LOGPRINTF("%d %s RW pingpong: %p, *rbuf %d rcnt %d\n",
			  getpid(), server ? "SERVER:" : "CLIENT:",
			  rx_buf, (unsigned char)*rx_buf,
			  (unsigned char)rx_cnt);
	}
	stop = get_time();
	ts.rtt = ((stop - start) * 1.0e6);

	if (rx_idx != (unsigned char)rx_cnt) {
		printf( "%d %s RW pingpong: %p, last *buf %d != cnt %d\n",
			getpid(), server ? "SERVER:" : "CLIENT:",
			rx_buf, (unsigned char)*rx_buf,
			(unsigned char)rx_cnt);
		return (DAT_ABORT);
	}

	if (all_data_sizes) {
		printf( "%d: RDMA write PingPong: (%d x %d) Total %6.2lf us:"
			" latency %3.2lf us, BW %4.2lf MB/s\n",
			getpid(), burst, len, ts.rtt, ts.rtt/burst/2,
			(double)(1/(ts.rtt/burst/2/len)));
	}

	return (DAT_SUCCESS);
}

static DAT_RETURN do_rdma_read_with_msg(void)
{
	DAT_EVENT event;
	DAT_LMR_TRIPLET l_iov;
	DAT_RMR_TRIPLET r_iov;
	DAT_DTO_COOKIE cookie;
	DAT_RETURN ret;
	int i;

	printf("\n %d RDMA READ DATA with SEND MSG\n\n", getpid());

	if (recv_msg_index >= MSG_BUF_COUNT)
		return (DAT_ABORT);

	/* get RMR information from previously received message */
	r_iov = p_rmr_rcv[recv_msg_index - 1];

	/* setup rdma read buffer to initial string to be overwritten */
	strcpy((char *)sbuf, "blah, blah, blah\n");

	if (server)
		strcpy((char *)rbuf, "server RDMA read data...");
	else
		strcpy((char *)rbuf, "client RDMA read data...");

	l_iov.lmr_context = lmr_context_send;
	l_iov.virtual_address = (DAT_VADDR) (uintptr_t) sbuf;
	l_iov.segment_length = buf_len;

	for (i = 0; i < MAX_RDMA_RD; i++) {
		cookie.as_64 = 0x9999;
		start = get_time();
		ret = dat_ep_post_rdma_read(h_ep,	// ep_handle
					    1,	// num_segments
					    &l_iov,	// LMR
					    cookie,	// user_cookie
					    &r_iov,	// RMR
					    DAT_COMPLETION_DEFAULT_FLAG);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr,
				"%d: ERROR: dat_ep_post_rdma_read() %s\n",
				getpid(), DT_RetToStr(ret));
			return (DAT_ABORT);
		}

		/* RDMA read completion event */
		if (collect_event(h_dto_req_evd, 
				  &event, 
		 		  DTO_TIMEOUT, 
				  &rdma_rd_poll_count[i]) != DAT_SUCCESS)
			return (DAT_ABORT);

		/* validate event number, len, cookie, and status */
		if (event.event_number != DAT_DTO_COMPLETION_EVENT) {
			fprintf(stderr, "%d: ERROR: DTO event number %s\n",
				getpid(), DT_EventToStr(event.event_number));
			return (DAT_ABORT);
		}
		if ((event.event_data.dto_completion_event_data.
		     transfered_length != buf_len)
		    || (event.event_data.dto_completion_event_data.user_cookie.
			as_64 != 0x9999)) {
			fprintf(stderr,
				"%d: ERROR: DTO len %d or cookie " F64x "\n",
				getpid(),
				event.event_data.dto_completion_event_data.
				transfered_length,
				event.event_data.dto_completion_event_data.
				user_cookie.as_64);
			return (DAT_ABORT);
		}
		if (event.event_data.dto_completion_event_data.status !=
		    DAT_DTO_SUCCESS) {
			fprintf(stderr, "%d: ERROR: DTO event status %s\n",
				getpid(), DT_RetToStr(ret));
			return (DAT_ABORT);
		}
		stop = get_time();
		ts.rdma_rd[i] = ((stop - start) * 1.0e6);
		ts.rdma_rd_total += ts.rdma_rd[i];

		LOGPRINTF("%d rdma_read # %d completed\n", getpid(), i + 1);
	}

	/*
	 *  Send RMR information a 3rd time to indicate completion
	 *  NOTE: already swapped to network order in connect_ep
	 */
	printf("%d Sending RDMA read completion message\n", getpid());

	/* give remote chance to process read completes */
	if (use_cno) {
#if defined(_WIN32) || defined(_WIN64)
		Sleep(1000);
#else
		sleep(1);
#endif
	}

	ret = send_msg(p_rmr_snd,
		       sizeof(DAT_RMR_TRIPLET),
		       lmr_context_send_msg,
		       cookie, DAT_COMPLETION_SUPPRESS_FLAG);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error send_msg: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else {
		LOGPRINTF("%d send_msg completed\n", getpid());
	}

	printf("%d Waiting for inbound message....\n", getpid());

	if (collect_event(h_dto_rcv_evd, 
			  &event, 
		 	  DTO_TIMEOUT, 
			  &poll_count) != DAT_SUCCESS)
		return (DAT_ABORT);

	/* validate event number and status */
	printf("%d inbound rdma_read; send message arrived!\n", getpid());
	if (event.event_number != DAT_DTO_COMPLETION_EVENT) {
		fprintf(stderr, "%d Error unexpected DTO event : %s\n",
			getpid(), DT_EventToStr(event.event_number));
		return (DAT_ABORT);
	}

	if ((event.event_data.dto_completion_event_data.transfered_length !=
	     sizeof(DAT_RMR_TRIPLET))
	    || (event.event_data.dto_completion_event_data.user_cookie.as_64 !=
		recv_msg_index)) {

		fprintf(stderr,
			"unexpected event data for receive: len=%d cookie=" F64x
			" exp %d/%d\n",
			(int)event.event_data.dto_completion_event_data.
			transfered_length,
			event.event_data.dto_completion_event_data.user_cookie.
			as_64, (int)sizeof(DAT_RMR_TRIPLET), recv_msg_index);

		return (DAT_ABORT);
	}

	/* swap received RMR msg: network order to host order */
	r_iov = p_rmr_rcv[recv_msg_index];
	p_rmr_rcv[recv_msg_index].virtual_address =
	    ntohll(p_rmr_rcv[recv_msg_index].virtual_address);
	p_rmr_rcv[recv_msg_index].segment_length =
	    ntohl(p_rmr_rcv[recv_msg_index].segment_length);
	p_rmr_rcv[recv_msg_index].rmr_context =
	    ntohl(p_rmr_rcv[recv_msg_index].rmr_context);

	printf("%d Received RMR from remote: "
	       "r_iov: r_key_ctx=%x,va=" F64x ",len=0x%x\n",
	       getpid(), p_rmr_rcv[recv_msg_index].rmr_context,
	       p_rmr_rcv[recv_msg_index].virtual_address,
	       p_rmr_rcv[recv_msg_index].segment_length);

	LOGPRINTF("%d inbound rdma_write; send msg event SUCCESS!!\n",
		  getpid());

	printf("%d %s RCV RDMA read buffer contains: %s\n",
	       getpid(), server ? "SERVER:" : "CLIENT:", sbuf);

	recv_msg_index++;

	return (DAT_SUCCESS);
}

static DAT_RETURN do_ping_pong_msg()
{
	DAT_EVENT event;
	DAT_DTO_COOKIE cookie;
	DAT_LMR_TRIPLET l_iov;
	DAT_RETURN ret;
	int i;
	char *snd_buf;
	char *rcv_buf;

	printf("\n %d PING DATA with SEND MSG\n\n", getpid());

	snd_buf = sbuf;
	rcv_buf = rbuf;

	/* pre-post all buffers */
	for (i = 0; i < msg_burst; i++) {
		burst_msg_posted++;
		cookie.as_64 = i;
		l_iov.lmr_context = lmr_context_recv;
		l_iov.virtual_address = (DAT_VADDR) (uintptr_t) rcv_buf;
		l_iov.segment_length = buf_len;

		LOGPRINTF("%d Pre-posting Receive Message Buffer[%d] %p\n",
			  getpid(), i, rcv_buf);

		ret = dat_ep_post_recv(h_ep,
				       1,
				       &l_iov,
				       cookie, DAT_COMPLETION_DEFAULT_FLAG);

		if (ret != DAT_SUCCESS) {
			fprintf(stderr,
				"%d Error posting recv msg buffer: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else {
			LOGPRINTF("%d Posted Receive Message Buffer %p\n",
				  getpid(), rcv_buf);
		}

		/* next buffer */
		rcv_buf += buf_len;
	}
#if defined(_WIN32) || defined(_WIN64)
	Sleep(1000);
#else
	sleep(1);
#endif

	/* Initialize recv_buf and index to beginning */
	rcv_buf = rbuf;
	burst_msg_index = 0;

	/* client ping 0x55, server pong 0xAA in first byte */
	start = get_time();
	for (i = 0; i < msg_burst; i++) {
		/* walk the send and recv buffers */
		if (!server) {
			*snd_buf = 0x55;

			LOGPRINTF("%d %s SND buffer %p contains: 0x%x len=%d\n",
				  getpid(), server ? "SERVER:" : "CLIENT:",
				  snd_buf, *(unsigned char *)snd_buf, buf_len);

			ret = send_msg(snd_buf,
				       buf_len,
				       lmr_context_send,
				       cookie, DAT_COMPLETION_SUPPRESS_FLAG);

			if (ret != DAT_SUCCESS) {
				fprintf(stderr, "%d Error send_msg: %s\n",
					getpid(), DT_RetToStr(ret));
				return (ret);
			} else {
				LOGPRINTF("%d send_msg completed\n", getpid());
			}
		}

		/* recv message, send completions suppressed */
		event.event_number = 0;
		if (collect_event(h_dto_rcv_evd, 
				  &event, 
				  DTO_TIMEOUT, 
				  &poll_count) != DAT_SUCCESS)
			return (DAT_ABORT);

		
		/* start timer after first message arrives on server */
		if (i == 0) {
			start = get_time();
		}
		/* validate event number and status */
		LOGPRINTF("%d inbound message; message arrived!\n", getpid());
		if (event.event_number != DAT_DTO_COMPLETION_EVENT) {
			fprintf(stderr, "%d Error DTO event (0x%x): %s\n",
				getpid(), event.event_number,
				DT_EventToStr(event.event_number));
			return (DAT_ABORT);
		}
		if ((event.event_data.dto_completion_event_data.
		     transfered_length != buf_len)
		    || (event.event_data.dto_completion_event_data.user_cookie.
			as_64 != burst_msg_index)) {
			fprintf(stderr,
				"ERR: recv event: len=%d cookie=" F64x
				" exp %d/%d\n",
				(int)event.event_data.dto_completion_event_data.
				transfered_length,
				event.event_data.dto_completion_event_data.
				user_cookie.as_64, (int)buf_len,
				(int)burst_msg_index);

			return (DAT_ABORT);
		}

		LOGPRINTF("%d %s RCV buffer[%d] %p contains: 0x%x len=%d\n",
			  getpid(), server ? "SERVER:" : "CLIENT:",
			  i, rcv_buf, *(unsigned char *)rcv_buf, buf_len);

		burst_msg_index++;

		/* If server, change data and send it back to client */
		if (server) {
			*snd_buf = 0xaa;

			LOGPRINTF("%d %s SND buffer[%d] %p contains: 0x%x len=%d\n",
				  getpid(), server ? "SERVER:" : "CLIENT:",
				  i, snd_buf, *(unsigned char *)snd_buf, buf_len);

			ret = send_msg(snd_buf,
				       buf_len,
				       lmr_context_send,
				       cookie, DAT_COMPLETION_SUPPRESS_FLAG);

			if (ret != DAT_SUCCESS) {
				fprintf(stderr, "%d Error send_msg: %s\n",
					getpid(), DT_RetToStr(ret));
				return (ret);
			} else {
				LOGPRINTF("%d send_msg completed\n", getpid());
			}
		}

		/* next buffers */
		rcv_buf += buf_len;
		snd_buf += buf_len;
	}
	stop = get_time();
	ts.rtt = ((stop - start) * 1.0e6);

	return (DAT_SUCCESS);
}

/* Register RDMA Receive buffer */
static DAT_RETURN register_rdma_memory(void)
{
	DAT_RETURN ret;
	DAT_REGION_DESCRIPTION region;

	region.for_va = rbuf;
	start = get_time();
	ret = dat_lmr_create(h_ia,
			     DAT_MEM_TYPE_VIRTUAL,
			     region,
			     buf_len * rq_cnt,
			     h_pz,
			     DAT_MEM_PRIV_ALL_FLAG,
			     DAT_VA_TYPE_VA,
			     &h_lmr_recv,
			     &lmr_context_recv,
			     &rmr_context_recv,
			     &registered_size_recv, &registered_addr_recv);
	stop = get_time();
	ts.reg += ((stop - start) * 1.0e6);
	ts.total += ts.reg;

	if (ret != DAT_SUCCESS) {
		fprintf(stderr,
			"%d Error registering Receive RDMA buffer: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else {
		LOGPRINTF("%d Registered Receive RDMA Buffer %p\n",
			  getpid(), region.for_va);
	}

	/* Register RDMA Send buffer */
	region.for_va = sbuf;
	ret = dat_lmr_create(h_ia,
			     DAT_MEM_TYPE_VIRTUAL,
			     region,
			     buf_len * rq_cnt,
			     h_pz,
			     DAT_MEM_PRIV_ALL_FLAG,
			     DAT_VA_TYPE_VA,
			     &h_lmr_send,
			     &lmr_context_send,
			     &rmr_context_send,
			     &registered_size_send, &registered_addr_send);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error registering send RDMA buffer: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else {
		LOGPRINTF("%d Registered Send RDMA Buffer %p\n",
			  getpid(), region.for_va);
	}

	return DAT_SUCCESS;
}

/*
 * Unregister RDMA memory
 */
static DAT_RETURN unregister_rdma_memory(void)
{
	DAT_RETURN ret;

	/* Unregister Recv Buffer */
	if (h_lmr_recv != DAT_HANDLE_NULL) {
		LOGPRINTF("%d Unregister h_lmr %p \n", getpid(), h_lmr_recv);
		start = get_time();
		ret = dat_lmr_free(h_lmr_recv);
		stop = get_time();
		ts.unreg += ((stop - start) * 1.0e6);
		ts.total += ts.unreg;
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error deregistering recv mr: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else {
			LOGPRINTF("%d Unregistered Recv Buffer\n", getpid());
			h_lmr_recv = NULL;
		}
	}

	/* Unregister Send Buffer */
	if (h_lmr_send != DAT_HANDLE_NULL) {
		LOGPRINTF("%d Unregister h_lmr %p \n", getpid(), h_lmr_send);
		ret = dat_lmr_free(h_lmr_send);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error deregistering send mr: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else {
			LOGPRINTF("%d Unregistered send Buffer\n", getpid());
			h_lmr_send = NULL;
		}
	}
	return DAT_SUCCESS;
}

 /*
  * Create CNO, CR, CONN, and DTO events
  */
static DAT_RETURN create_events(void)
{
	DAT_RETURN ret;
	DAT_EVD_PARAM param;

	/* create CNO */
	if (use_cno) {
		start = get_time();
#if defined(_WIN32) || defined(_WIN64)
		{
			DAT_OS_WAIT_PROXY_AGENT pa = { NULL, NULL };
			ret = dat_cno_create(h_ia, pa, &h_dto_cno);
		}
#else
		ret =
		    dat_cno_create(h_ia, DAT_OS_WAIT_PROXY_AGENT_NULL,
				   &h_dto_cno);
#endif
		stop = get_time();
		ts.cnoc += ((stop - start) * 1.0e6);
		ts.total += ts.cnoc;
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error dat_cno_create: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else {
			LOGPRINTF("%d cr_evd created, %p\n", getpid(),
				  h_dto_cno);
		}
	}

	/* create cr EVD */
	start = get_time();
	ret =
	    dat_evd_create(h_ia, 10, DAT_HANDLE_NULL, DAT_EVD_CR_FLAG,
			   &h_cr_evd);
	stop = get_time();
	ts.evdc += ((stop - start) * 1.0e6);
	ts.total += ts.evdc;
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error dat_evd_create: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else {
		LOGPRINTF("%d cr_evd created %p\n", getpid(), h_cr_evd);
	}

	/* create conn EVD */
	ret = dat_evd_create(h_ia,
			     10,
			     DAT_HANDLE_NULL,
			     DAT_EVD_CONNECTION_FLAG, &h_conn_evd);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error dat_evd_create: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else {
		LOGPRINTF("%d con_evd created %p\n", getpid(), h_conn_evd);
	}

	/* create dto SND EVD, with CNO if use_cno was set */
	ret = dat_evd_create(h_ia,
			     (MSG_BUF_COUNT + MAX_RDMA_RD + burst) * 2,
			     h_dto_cno, DAT_EVD_DTO_FLAG, &h_dto_req_evd);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error dat_evd_create REQ: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else {
		LOGPRINTF("%d dto_req_evd created %p\n", getpid(),
			  h_dto_req_evd);
	}

	/* create dto RCV EVD, with CNO if use_cno was set */
	ret = dat_evd_create(h_ia,
			     MSG_BUF_COUNT + burst,
			     h_dto_cno, DAT_EVD_DTO_FLAG, &h_dto_rcv_evd);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error dat_evd_create RCV: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else {
		LOGPRINTF("%d dto_rcv_evd created %p\n", getpid(),
			  h_dto_rcv_evd);
	}

	/* query DTO req EVD and check size */
	ret = dat_evd_query(h_dto_req_evd, DAT_EVD_FIELD_EVD_QLEN, &param);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d Error dat_evd_query request evd: %s\n",
			getpid(), DT_RetToStr(ret));
		return (ret);
	} else if (param.evd_qlen < (MSG_BUF_COUNT + MAX_RDMA_RD + burst) * 2) {
		fprintf(stderr, "%d Error dat_evd qsize too small: %d < %d\n",
			getpid(), param.evd_qlen,
			(MSG_BUF_COUNT + MAX_RDMA_RD + burst) * 2);
		return (ret);
	}

	LOGPRINTF("%d dto_req_evd QLEN - requested %d and actual %d\n",
		  getpid(), (MSG_BUF_COUNT + MAX_RDMA_RD + burst) * 2,
		  param.evd_qlen);

	return DAT_SUCCESS;
}

/*
 * Destroy CR, CONN, CNO, and DTO events
 */

static DAT_RETURN destroy_events(void)
{
	DAT_RETURN ret;

	/* free cr EVD */
	if (h_cr_evd != DAT_HANDLE_NULL) {
		LOGPRINTF("%d Free cr EVD %p \n", getpid(), h_cr_evd);
		ret = dat_evd_free(h_cr_evd);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error freeing cr EVD: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else {
			LOGPRINTF("%d Freed cr EVD\n", getpid());
			h_cr_evd = DAT_HANDLE_NULL;
		}
	}

	/* free conn EVD */
	if (h_conn_evd != DAT_HANDLE_NULL) {
		LOGPRINTF("%d Free conn EVD %p \n", getpid(), h_conn_evd);
		ret = dat_evd_free(h_conn_evd);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error freeing conn EVD: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else {
			LOGPRINTF("%d Freed conn EVD\n", getpid());
			h_conn_evd = DAT_HANDLE_NULL;
		}
	}

	/* free RCV dto EVD */
	if (h_dto_rcv_evd != DAT_HANDLE_NULL) {
		LOGPRINTF("%d Free RCV dto EVD %p \n", getpid(), h_dto_rcv_evd);
		start = get_time();
		ret = dat_evd_free(h_dto_rcv_evd);
		stop = get_time();
		ts.evdf += ((stop - start) * 1.0e6);
		ts.total += ts.evdf;
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error freeing dto EVD: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else {
			LOGPRINTF("%d Freed dto EVD\n", getpid());
			h_dto_rcv_evd = DAT_HANDLE_NULL;
		}
	}

	/* free REQ dto EVD */
	if (h_dto_req_evd != DAT_HANDLE_NULL) {
		LOGPRINTF("%d Free REQ dto EVD %p \n", getpid(), h_dto_req_evd);
		ret = dat_evd_free(h_dto_req_evd);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error freeing dto EVD: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else {
			LOGPRINTF("%d Freed dto EVD\n", getpid());
			h_dto_req_evd = DAT_HANDLE_NULL;
		}
	}

	/* free CNO */
	if (h_dto_cno != DAT_HANDLE_NULL) {
		LOGPRINTF("%d Free dto CNO %p \n", getpid(), h_dto_cno);
		start = get_time();
		ret = dat_cno_free(h_dto_cno);
		stop = get_time();
		ts.cnof += ((stop - start) * 1.0e6);
		ts.total += ts.cnof;
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d Error freeing dto CNO: %s\n",
				getpid(), DT_RetToStr(ret));
			return (ret);
		} else {
			LOGPRINTF("%d Freed dto CNO\n", getpid());
			h_dto_cno = DAT_HANDLE_NULL;
		}
	}
	return DAT_SUCCESS;
}

/*
 * Map DAT_RETURN values to readable strings,
 * but don't assume the values are zero-based or contiguous.
 */
static char errmsg[512] = { 0 };
const char *DT_RetToStr(DAT_RETURN ret_value)
{
	const char *major_msg, *minor_msg;

	dat_strerror(ret_value, &major_msg, &minor_msg);

	strcpy(errmsg, major_msg);
	strcat(errmsg, " ");
	strcat(errmsg, minor_msg);

	return errmsg;
}

/*
 * Map DAT_EVENT_CODE values to readable strings
 */
const char *DT_EventToStr(DAT_EVENT_NUMBER event_code)
{
	unsigned int i;
	static struct {
		const char *name;
		DAT_RETURN value;
	} dat_events[] = {
#   define DATxx(x) { # x, x }
		DATxx(DAT_DTO_COMPLETION_EVENT),
		    DATxx(DAT_RMR_BIND_COMPLETION_EVENT),
		    DATxx(DAT_CONNECTION_REQUEST_EVENT),
		    DATxx(DAT_CONNECTION_EVENT_ESTABLISHED),
		    DATxx(DAT_CONNECTION_EVENT_PEER_REJECTED),
		    DATxx(DAT_CONNECTION_EVENT_NON_PEER_REJECTED),
		    DATxx(DAT_CONNECTION_EVENT_ACCEPT_COMPLETION_ERROR),
		    DATxx(DAT_CONNECTION_EVENT_DISCONNECTED),
		    DATxx(DAT_CONNECTION_EVENT_BROKEN),
		    DATxx(DAT_CONNECTION_EVENT_TIMED_OUT),
		    DATxx(DAT_CONNECTION_EVENT_UNREACHABLE),
		    DATxx(DAT_ASYNC_ERROR_EVD_OVERFLOW),
		    DATxx(DAT_ASYNC_ERROR_IA_CATASTROPHIC),
		    DATxx(DAT_ASYNC_ERROR_EP_BROKEN),
		    DATxx(DAT_ASYNC_ERROR_TIMED_OUT),
		    DATxx(DAT_ASYNC_ERROR_PROVIDER_INTERNAL_ERROR),
		    DATxx(DAT_SOFTWARE_EVENT)
#   undef DATxx
	};
#   define NUM_EVENTS (sizeof(dat_events)/sizeof(dat_events[0]))

	for (i = 0; i < NUM_EVENTS; i++) {
		if (dat_events[i].value == event_code) {
			return (dat_events[i].name);
		}
	}

	return ("Invalid_DAT_EVENT_NUMBER");
}

static void print_usage(void)
{
	printf("\n DAPL USAGE \n\n");
	printf("s: server\n");
	printf("u: unidirectional bandwidth (default=bidirectional\n");
	printf("w: rdma write only, streaming\n");
	printf("W: rdma write only, ping pong\n");
	printf("D: validate data in ping pong test\n");
	printf("t: performance times\n");
	printf("c: use cno\n");
	printf("a: all data sizes with rdma write pingpong \n");
	printf("i: increment size for all data size option\n");
	printf("v: verbose\n");
	printf("p: polling\n");
	printf("d: delay before accept\n");
	printf("b: buf length, upper bound for -W -a -i (WR_pp, all sizes, increment)\n");
	printf("B: burst count, rdma and msgs \n");
	printf("h: hostname/address of server, specified on client\n");
	printf("P: provider name (default = ofa-v2-mlx4_0-1u)\n");
	printf("S: signal_rate (default=10, completion every 10 iterations\n");
	printf("U: print this Usage page\n");
	printf("\n");
}

