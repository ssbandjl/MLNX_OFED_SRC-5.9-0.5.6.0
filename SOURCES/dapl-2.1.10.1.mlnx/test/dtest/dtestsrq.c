/*
 * Copyright (c) 2009 Intel Corporation.  All rights reserved.
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
#define F64d "%I64d"

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

#define DAPL_PROVIDER "ofa-v2-ib0"

#define F64x "%"PRIx64""
#define F64d "%"PRId64""


#if __BYTE_ORDER == __BIG_ENDIAN
#define htonll(x) (x)
#define ntohll(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define htonll(x)  bswap_64(x)
#define ntohll(x)  bswap_64(x)
#endif

#endif // _WIN32 || _WIN64

/* Header files needed for DAT/uDAPL */
#include "dat2/udat.h"
#include "dat2/dat_ib_extensions.h"

/* definitions */
#define SERVER_CONN_QUAL	45248
#define CONN_TIMEOUT		(1000*1000*100)
#define DTO_TIMEOUT		(1000*1000*5)
#define CR_TIMEOUT		DAT_TIMEOUT_INFINITE
#define MAX_CONN		100
#define MAX_BURST		100
#define MSG_IOV_COUNT		1

/* Global DAT vars */
static DAT_IA_HANDLE h_ia = DAT_HANDLE_NULL;
static DAT_PZ_HANDLE h_pz = DAT_HANDLE_NULL;
static DAT_SRQ_HANDLE h_srq = DAT_HANDLE_NULL;
static DAT_CR_HANDLE h_cr = DAT_HANDLE_NULL;
static DAT_PSP_HANDLE h_psp = DAT_HANDLE_NULL;
static DAT_IB_ADDR_HANDLE *remote_ah = DAT_HANDLE_NULL;
static DAT_EP_HANDLE *h_ep;

static DAT_EVD_HANDLE h_async_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE h_dto_req_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE h_dto_rcv_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE h_cr_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE h_conn_evd = DAT_HANDLE_NULL;

static DAT_EP_ATTR ep_attr;
static char hostname[256] = { 0 };
static char provider[64] = DAPL_PROVIDER;

/* defaults */
static int server = 1;
static int verbose = 0;
static int connections = 1;
static int bursts_number =  3;
static int burst_size = 1;
static int server_port_id = SERVER_CONN_QUAL;
static int client_port_id = SERVER_CONN_QUAL + 1;
static int ucm = 0;
static int ud_test = 0;
static int srq_test = 1;

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

static int tx_buf_len = 0, rx_buf_len;
static int connected = 0;
static char *rbuf = NULL;
static char *sbuf = NULL;
static DAT_SOCK_ADDR6 remote;

/* forward prototypes */
const char *DT_RetToString(DAT_RETURN ret_value);
const char *DT_EventToSTr(DAT_EVENT_NUMBER event_code);
static void print_usage(void);
static void flush_evds(void);
static void print_ia_address(struct sockaddr *sa);
static DAT_RETURN conn_client(void);
static DAT_RETURN conn_server(void);
static DAT_RETURN disconnect_eps(void);
static DAT_RETURN create_events(void);
static DAT_RETURN destroy_events(void);
static DAT_RETURN register_rdma_memory(void);
static void unregister_rdma_memory(void);
static DAT_RETURN send_msg(char *buff, char msg_head, DAT_UINT32 ep_num, DAT_UINT32 msg_num);
static DAT_RETURN process_cr(void);
static DAT_RETURN process_conn(void);
#define LOGPRINTF if (verbose) printf

int main(int argc, char **argv)
{
	int i, j, c, ep_post_num;
	DAT_RETURN ret;
	DAT_IA_ATTR ia_attr;
	DAT_SRQ_ATTR srq_attr;
	DAT_DTO_COOKIE cookie;
	DAT_LMR_TRIPLET l_iov;
	DAT_COUNT nmore;
	DAT_EVENT event;
	int tx_before = 0, ep_num, b_num, ib_mtu = 0;
	char *snd_buf;
	char *rcv_buf, *msg_buf;
	char incoming_header, recv_expected_header;
	DAT_UINT32 incoming_ep_num, incoming_msg_num;
	DAT_UINT32 *last_msg_num_from_ep;
	DAT_UINT64 recv_buf_index;
	DAT_PROVIDER_ATTR pr_attr;

	/* parse arguments */
	while ((c = getopt(argc, argv, "svuB:c:t:h:P:p:q:l:b:S:")) != -1) {
		switch (c) {
		case 's':
			server = 1;
			break;
		case 'v':
			verbose = 1;
			fflush(stdout);
			break;
		case 'c':
			connections = atoi(optarg);
			if (connections > MAX_CONN) {
				printf("Too many connections. Max %d.\n",
					MAX_CONN);
				exit(-12);
			}
			break;
		case 'b':
			tx_buf_len = atoi(optarg);
			if (tx_buf_len <= 0) {
				printf(" Buffer size need to be positive\n");
				exit(-12);
			}
			break;
		case 't':
			bursts_number = atoi(optarg);
			if (bursts_number < 0) {
				printf("Bursts number (%d) can't be negative.\n",
					bursts_number);
				exit(-12);
			}
			break;
		case 'p':
			server_port_id = atoi(optarg);
			client_port_id = server_port_id + 1;
			break;
		case 'S':
			srq_test = atoi(optarg);
			break;
		case 'B':
			burst_size = atoi(optarg);
			if (burst_size > MAX_BURST) {
				printf("Burst size is too big. Max %d\n",
					MAX_BURST);
				exit(-12);
			}
			break;
		case 'h':
			server = 0;
			strcpy(hostname, optarg);
			break;
		case 'P':
			strcpy(provider, optarg);
			break;
		case 'q':
			/* map UCM qpn into AF_INET6 sin6_flowinfo */
			remote.sin6_family = AF_INET6;
			remote.sin6_flowinfo = htonl(strtol(optarg,NULL,0));
			ucm = 1;
			server = 0;
			break;
		case 'l':
			/* map UCM lid into AF_INET6 sin6_port */
			remote.sin6_family = AF_INET6;
			remote.sin6_port = htons(strtol(optarg,NULL,0));
			ucm = 1;
			server = 0;
			break;
		case 'u':
			ud_test = 1;
			break;
	default:
			print_usage();
			exit(-12);
		}
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

	printf(" Running %s %s test as %s on %s with %d connections,"
		" %d burst%s of %d messages\n", ud_test ? "UD":"RC",
		srq_test ? "SRQ":"none SRQ",
		server ? "SERVER:" : "CLIENT:", provider, connections,
		bursts_number, bursts_number> 1 ? "s" : "", burst_size);
	fflush(stdout);

	/* allocate EP handles for all connections */
	h_ep = (DAT_EP_HANDLE*)malloc(connections * sizeof(DAT_EP_HANDLE));
	if (h_ep == NULL) {
		perror("malloc ep");
		exit(1);
	}
	memset(h_ep, 0, (connections * sizeof(DAT_EP_HANDLE)));

	if (ud_test) {
		remote_ah = (DAT_IB_ADDR_HANDLE*)malloc(connections * sizeof(DAT_IB_ADDR_HANDLE));
		if (remote_ah == NULL) {
			perror("malloc remote ah");
			exit(1);
		}
		memset(remote_ah, 0, connections * sizeof(DAT_IB_ADDR_HANDLE));
	}

	/* Save last message number for each ep */
	last_msg_num_from_ep = malloc(connections * sizeof(DAT_UINT32));
	if (last_msg_num_from_ep == NULL) {
		perror("malloc last_msg_num_from_ep");
		exit(1);
	}
	memset(last_msg_num_from_ep, 0, (connections * sizeof(DAT_UINT32)));

	/* dat_ia_open, dat_pz_create */
	h_async_evd = DAT_HANDLE_NULL;
	ret = dat_ia_open(provider, 8, &h_async_evd, &h_ia);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error Adaptor open: %s\n",
			DT_RetToString(ret));
		exit(1);
	} else
		LOGPRINTF(" Opened Interface Adaptor %p\n", h_ia);

	/* query for UCM addressing */
	ret = dat_ia_query(h_ia, 0, DAT_IA_FIELD_ALL, &ia_attr,
			   DAT_PROVIDER_FIELD_PROVIDER_SPECIFIC_ATTR,
			   &pr_attr);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Err Adaptor query: %s\n", DT_RetToString(ret));
		exit(1);
	}

	/* Set tx_buf_len to IB_MTU if it was not specified by the user */
	for (i = 0; i < pr_attr.num_provider_specific_attr; i++) {
		if (!strcmp (pr_attr.provider_specific_attr[i].name,
			    "DAT_IB_TRANSPORT_MTU"))
		{
			ib_mtu = atoi(pr_attr.provider_specific_attr[i].value);
			break;
		}
	}

	if (ud_test) {
		if (!ib_mtu) {
			fprintf(stderr, " Error: ud test: IB_MTU was not found"
				" in provider attr\n");
			exit(1);
		}
		if (tx_buf_len > ib_mtu) {
			fprintf(stderr, " Error: ud test: user buf len (%d)"
				"bigger than IB_MTU (%d)\n", tx_buf_len, ib_mtu);
			exit(1);
		}
	}

	if (!tx_buf_len) {
		/* no user input - set tx_buf_len to IB_MTU */
		if (!ib_mtu) {
			fprintf(stderr, " Error: no user input and IB_MTU was"
				" not found in provider attr\n");
			exit(1);
		}
		tx_buf_len = ib_mtu;
	}

	LOGPRINTF(" Tx buffer len set to device MTU %d\n", tx_buf_len);
	rx_buf_len = tx_buf_len;
	if (ud_test)
		rx_buf_len = tx_buf_len + 40;
	LOGPRINTF(" Rx buffer len set to %d\n", rx_buf_len);

	print_ia_address(ia_attr.ia_address_ptr);

	/* Create Protection Zone */
	LOGPRINTF(" Create Protection Zone\n");
	ret = dat_pz_create(h_ia, &h_pz);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error creating Protection Zone: %s\n",
			DT_RetToString(ret));
		exit(1);
	} else
		LOGPRINTF(" Created Protection Zone\n");

	LOGPRINTF(" Create events\n");
	ret = create_events();
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error creating events: %s\n",
			DT_RetToString(ret));
		goto cleanup;
	} else {
		LOGPRINTF(" Create events done\n");
	}

	/* Create SRQ */
	if (srq_test) {
		LOGPRINTF(" Create SRQ\n");
		srq_attr.max_recv_dtos = connections * burst_size;
		srq_attr.max_recv_iov  = MSG_IOV_COUNT;
		srq_attr.low_watermark = 0;

		ret = dat_srq_create(h_ia, h_pz, &srq_attr, &h_srq);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " Error dat_srq_create: %s\n",
				DT_RetToString(ret));
			goto cleanup;
		} else
			LOGPRINTF(" SRQ created %p \n", h_srq);
	}

	/* allocate send and receive buffers */
	if (((rbuf = malloc(connections * rx_buf_len * burst_size)) == NULL) ||
	    ((sbuf = malloc(connections * tx_buf_len * burst_size)) == NULL)) {
		fprintf(stderr, " Error allocating snd/rcv buffers\n");
		goto cleanup;
	}

	/* Register memory */
	LOGPRINTF(" Register RDMA memory\n");
	ret = register_rdma_memory();
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error registering RDMA memory: %s\n",
			DT_RetToString(ret));
		goto cleanup;
	} else
		LOGPRINTF(" Register RDMA memory done\n");

	/* create EP */
	memset(&ep_attr, 0, sizeof(ep_attr));
	if (ud_test) {
		ep_attr.service_type = DAT_IB_SERVICE_TYPE_UD;
		ep_attr.max_message_size = tx_buf_len;
	} else {
		ep_attr.service_type = DAT_SERVICE_TYPE_RC;
		ep_attr.max_message_size = 0;
	}
	ep_attr.max_request_dtos = (server ? burst_size : (connections * burst_size));
	ep_attr.max_recv_dtos = (server ? burst_size : (connections * burst_size));
	ep_attr.max_rdma_size = 0;
	ep_attr.qos = 0;
	ep_attr.recv_completion_flags = 0;
	ep_attr.max_recv_iov = MSG_IOV_COUNT;
	ep_attr.max_request_iov = MSG_IOV_COUNT;
	ep_attr.max_rdma_read_in = 0;
	ep_attr.max_rdma_read_out = 0;
	ep_attr.request_completion_flags = DAT_COMPLETION_DEFAULT_FLAG;
	ep_attr.ep_transport_specific_count = 0;
	ep_attr.ep_transport_specific = NULL;
	ep_attr.ep_provider_specific_count = 0;
	ep_attr.ep_provider_specific = NULL;

	for (i = 0; i < connections; i++) {
		if (srq_test)
			ret = dat_ep_create_with_srq(h_ia, h_pz, h_dto_rcv_evd,
				    h_dto_req_evd, h_conn_evd, h_srq,
				    &ep_attr, &h_ep[i]);
		else
			ret = dat_ep_create(h_ia, h_pz, h_dto_rcv_evd,
					    h_dto_req_evd, h_conn_evd,
					    &ep_attr, &h_ep[i]);

		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " Error dat_ep_create: %s\n",
				DT_RetToString(ret));
			goto cleanup;
		} else
			LOGPRINTF(" EP %d created %p\n", i, h_ep[i]);

		/* For client in UD test we use one EP to many EPs on server */
		if (!server && ud_test)
			break;
	}

	/* pre-post all buffers */
	rcv_buf = rbuf;
	for (i = 0; i < connections; i++) {
		for (j = 0; j < burst_size; j++) {
			cookie.as_64 = i * burst_size + j;
			l_iov.lmr_context = lmr_context_recv;
			l_iov.virtual_address = (DAT_VADDR) (uintptr_t) rcv_buf;
			l_iov.segment_length = rx_buf_len;

			if (srq_test) {
				LOGPRINTF(" Pre SRQ post receive msg buff %p cookie %ld.....",
					  rcv_buf, cookie.as_64);
				ret = dat_srq_post_recv(h_srq, 1, &l_iov, cookie);
			} else {
				if(server || !ud_test)
					ep_post_num = i;
				else
					ep_post_num = 0;

				LOGPRINTF(" Pre post receive for EP %d msg buff %p.....",
						ep_post_num, rcv_buf);
				ret = dat_ep_post_recv(h_ep[ep_post_num], 1, &l_iov,
						       cookie, DAT_COMPLETION_DEFAULT_FLAG);
			}

			if (ret != DAT_SUCCESS) {
				fprintf(stderr, "\n Error posting recv msg buffer: %s\n",
					DT_RetToString(ret));
				goto cleanup;
			} else
				LOGPRINTF("Done\n");

			/* next buffer */
			rcv_buf += rx_buf_len;
		}
	}

	/* create the service point for server listen */
	if (server) {
		LOGPRINTF(" Creating server service point\n");
		ret = dat_psp_create(h_ia,
				     server ? server_port_id : client_port_id,
				     h_cr_evd,
				     DAT_PSP_CONSUMER_FLAG,
				     &h_psp);

		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " ERR psp_create: %s\n",
				DT_RetToString(ret));
			goto cleanup;
		} else
			printf(" %s ready on port %d\n",
			       server ? "server" : "client",
			       server ? server_port_id : client_port_id);
	}

	/* Connect all */
	if (server)
		ret = conn_server();
	else
		ret = conn_client();

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error %s: %s\n",
			server ? "server()" : "client()",
			DT_RetToString(ret));
		goto cleanup;
	} else
		printf("\n ALL %d CONNECTED on %s!\n\n",
			connections, server ? "server" : "client");

	connected = 1;

	/*
	 * Client ping: 0x55, ep_num, ep msg_num
	 * Server pong: 0xAA, ep, ep smg_num
	 */
	if (server)
		recv_expected_header = 0x55;
	else
		recv_expected_header = 0xaa;

	for (b_num = 0; b_num < bursts_number; b_num++) {
		/* Initialize snd_buf to the beginning */
		snd_buf = sbuf;

		if (!server) { /* Send Ping */
			for (ep_num = 0; ep_num < connections; ep_num++) {
				for (i = 0; i < burst_size; i++) {
					/* walk the send */
					ret = send_msg(snd_buf, 0x55, ep_num,
						       tx_before + i + 1);
					if (ret != DAT_SUCCESS) {
						fprintf(stderr,
							" ERR: dat_ep_post_send() %s\n",
							DT_RetToString(ret));
						goto cleanup;
					} else
						LOGPRINTF(" send_msg completed\n");
					/* next buffers */
					snd_buf += tx_buf_len;
				}
			}
		}

		for (ep_num = 0; ep_num < connections; ep_num++) {
			for (i = 0; i < burst_size; i++) {
				/* walk the rcv */
				ret = dat_evd_wait(h_dto_rcv_evd, DTO_TIMEOUT, 1,
							&event, &nmore);
				if (ret != DAT_SUCCESS) {
					fprintf(stderr,
						" Error waiting on h_dto_evd %p: %s\n",
						h_dto_rcv_evd, DT_RetToString(ret));
					goto cleanup;
				}

				/* validate event number and status */
				LOGPRINTF(" inbound message; message arrived!\n");
				if (event.event_number != DAT_DTO_COMPLETION_EVENT &&
				    ud_test && event.event_number != (DAT_EVENT_NUMBER)
				    DAT_IB_DTO_EVENT) {
					fprintf(stderr, " Error unexpected DTO event (%d): %s\n",
							event.event_number,
							DT_EventToSTr(event.event_number));
					goto cleanup;
				}

				if (event.event_data.dto_completion_event_data.
						transfered_length != rx_buf_len) {
					fprintf(stderr, " ERR: recv event: len=%d "
						"cookie=" F64x " exp len %d\n",
						(int)event.event_data.dto_completion_event_data.
						transfered_length,
						event.event_data.dto_completion_event_data.
						user_cookie.as_64, (int)rx_buf_len);
					goto cleanup;
				}

				/* Check data */
				recv_buf_index = event.event_data.dto_completion_event_data.
									user_cookie.as_64;
				rcv_buf = rbuf + recv_buf_index * rx_buf_len;
				if (ud_test)
					msg_buf = rcv_buf + 40;
				else
					msg_buf = rcv_buf;

				incoming_header = *msg_buf;
				incoming_ep_num = ntohl(*((DAT_UINT32 *)(msg_buf + 4)));
				incoming_msg_num = ntohl(*((DAT_UINT32 *)(msg_buf + 8)));
				LOGPRINTF(" %s recv buffer %p (index %ld) buf len %d "
					  " incoming data: header %d, ep num %d, ep msg num %d "
					  " (nmore = %d)\n",
					  server ? "SERVER:" : "CLIENT:", rcv_buf,
					  recv_buf_index, rx_buf_len, incoming_header,
					  incoming_ep_num, incoming_msg_num, nmore);

				/* May have race condition between EPs therefore
				 * need to track each ep last message number */
				if (last_msg_num_from_ep[incoming_ep_num] + 1 != incoming_msg_num) {
					fprintf(stderr, " ERR: ep %d recv msg %d exp %d\n",
						incoming_ep_num, incoming_msg_num,
						last_msg_num_from_ep[incoming_ep_num] + 1);
					goto cleanup;
				}
				last_msg_num_from_ep[incoming_ep_num] = incoming_msg_num;

				if (incoming_header != recv_expected_header) {
					fprintf(stderr, " ERR: ep %d recv header"
						" 0x%x exp 0x%x\n",
						incoming_ep_num, incoming_header,
						recv_expected_header);
					goto cleanup;
				}

				/* Done with Recv buffer - post the buffer back */
				cookie.as_64 = recv_buf_index;
				l_iov.lmr_context = lmr_context_recv;
				l_iov.virtual_address = (DAT_VADDR) (uintptr_t) rcv_buf;
				l_iov.segment_length = rx_buf_len;

				if (srq_test) {
					LOGPRINTF(" Pre SRQ post receive msg buff %p.....",
						  (DAT_PVOID)l_iov.virtual_address);
					ret = dat_srq_post_recv(h_srq, 1, &l_iov, cookie);
				} else {
					LOGPRINTF(" Pre osted receive msg, "
						  "from ep %p buffer %p.....",
						  event.event_data.
						  dto_completion_event_data.
						  ep_handle , rcv_buf);
					ret = dat_ep_post_recv(event.event_data.
						  dto_completion_event_data.
						  ep_handle, 1, &l_iov, cookie,
						  DAT_COMPLETION_DEFAULT_FLAG);
				}

				if (ret != DAT_SUCCESS) {
					fprintf(stderr, "\n Error posting recv "
						"msg buffer: %s\n",
						DT_RetToString(ret));
					goto cleanup;
				} else
					LOGPRINTF("Done\n");
			}
		}

		if (server) { /* Send pong */
			for (ep_num = 0; ep_num < connections; ep_num++) {
				for (i = 0; i < burst_size; i++) {
					/* walk the send */
					ret = send_msg(snd_buf, 0xaa, ep_num,
						       tx_before + i + 1);
					if (ret != DAT_SUCCESS) {
						fprintf(stderr, " ERROR: dat_ep_post_send() %s\n",
								DT_EventToSTr(ret));
						goto cleanup;
					} else
						LOGPRINTF(" send_msg completed\n");
					/* next buffers */
					snd_buf += tx_buf_len;
				}
			}
		}

		tx_before += burst_size;
		/* clean req evd */
		for (ep_num = 0; ep_num < connections; ep_num++) {
			for (i = 0; i < burst_size; i++) {
				ret = dat_evd_wait(h_dto_req_evd, DTO_TIMEOUT, 1,
						   &event, &nmore);
				if (ret != DAT_SUCCESS) {
					fprintf(stderr,
						" Error waiting on h_req_evd %p: %s\n",
						h_dto_req_evd, DT_RetToString(ret));
					goto cleanup;
				}

				if ((event.event_data.dto_completion_event_data.
						transfered_length != tx_buf_len)
						|| event.event_data.dto_completion_event_data.
						status != DAT_DTO_SUCCESS) {
					fprintf(stderr, " ERROR: DTO REQ size %d, status %d\n",
						event.event_data.dto_completion_event_data.
						transfered_length,
						event.event_data.
						dto_completion_event_data.status);
					goto cleanup;
				}
			}
		}
	}

	goto complete;
cleanup:
	flush_evds();
	goto bail;
complete:

	/* disconnect and free EP resources */
	if (h_ep[0]) {
		/* unregister message buffers and tear down connection */
		LOGPRINTF(" Disconnect EPs\n");
		ret = disconnect_eps();
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " Error disconnect_eps: %s\n",
				DT_RetToString(ret));
			goto bail;
		} else {
			LOGPRINTF(" disconnect_eps complete\n");
		}
	}

	/* destroy server service point(s) */
	if (h_psp != DAT_HANDLE_NULL) {
		ret = dat_psp_free(h_psp);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " Error dat_psp_free: %s\n",
				DT_RetToString(ret));
			goto bail;
		} else {
			LOGPRINTF(" psp_free complete\n");
		}
	}

	unregister_rdma_memory();

	/* Free SRQ */
	if (h_srq != DAT_HANDLE_NULL) {
		LOGPRINTF(" Free SRQ %p \n", h_srq);
		ret = dat_srq_free(h_srq);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " Err freeing SRQ: %s\n",
					DT_RetToString(ret));
		} else {
			LOGPRINTF(" SRQ Freed\n");
			h_srq = DAT_HANDLE_NULL;
		}
	}

	/* free EVDs */
	LOGPRINTF(" destroy events\n");
	ret = destroy_events();
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error destroy_events: %s\n",
			DT_RetToString(ret));
		goto bail;
	} else
		LOGPRINTF(" destroy events done\n");

	/* Free protection domain */
	LOGPRINTF(" Freeing pz\n");
	ret = dat_pz_free(h_pz);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error freeing PZ: %s\n", DT_RetToString(ret));
		goto bail;
	} else {
		LOGPRINTF(" Freed pz\n");
		h_pz = NULL;
	}

	/* close the device */
	LOGPRINTF(" Closing Interface Adaptor\n");
	ret = dat_ia_close(h_ia, DAT_CLOSE_ABRUPT_FLAG);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error Adaptor close: %s\n",
			DT_RetToString(ret));
		goto bail;
	} else
		LOGPRINTF(" Closed Interface Adaptor\n");

	printf(" DAPL %s %s Test Complete.\n\n",
		ud_test ? "UD" : "RC", srq_test ? "SRQ" : "none SRQ");

	fflush(stderr);	fflush(stdout);
bail:
	free(h_ep);
	if(remote_ah)
		free(remote_ah);

#if defined(_WIN32) || defined(_WIN64)
	WSACleanup();
#endif
	return (0);
}

static DAT_RETURN process_cr()
{
	DAT_RETURN ret;
	DAT_EVENT event;
	DAT_COUNT nmore;
	DAT_CR_PARAM cr_param;
	int i, pdata;
	DAT_CR_ARRIVAL_EVENT_DATA *cr_event =
		&event.event_data.cr_arrival_event_data;

	printf(" Accepting...\n");
	fflush(stdout);
	for (i = 0; i < connections; i++) {
		/* Wait for CR's */
		ret = dat_evd_wait(h_cr_evd, CR_TIMEOUT, 1, &event, &nmore);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " ERR: CR dat_evd_wait() %s\n",
				DT_RetToString(ret));
			return ret;
		}

		if (event.event_number != DAT_CONNECTION_REQUEST_EVENT &&
				(ud_test && event.event_number !=
				(DAT_EVENT_NUMBER)
				DAT_IB_UD_CONNECTION_REQUEST_EVENT)) {
			fprintf(stderr, " Error unexpected cr event : %s\n",
				DT_EventToSTr(event.event_number));
			return (DAT_ABORT);
		}

		if ((event.event_data.cr_arrival_event_data.conn_qual !=
			(server ? server_port_id : client_port_id))
		    || (event.event_data.cr_arrival_event_data.sp_handle.
			psp_handle != h_psp)) {
			fprintf(stderr, " Error wrong cr event data : %s\n",
				DT_EventToSTr(event.event_number));
			return (DAT_ABORT);
		}

		/* accept connect request from client */
		h_cr = cr_event->cr_handle;
		ret = dat_cr_query(h_cr, DAT_CSP_FIELD_ALL, &cr_param);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " Error: unable to query cr\n");
			return (DAT_ABORT);
		}

		/* use private data to select EP */
		pdata = ntohl(*((int *)cr_param.private_data));

		LOGPRINTF(" Accepting connect request %d from client:\n", pdata);

		ret = dat_cr_accept(h_cr, h_ep[pdata], 4, cr_param.private_data);

		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " ERR dat_cr_accept: %s\n",
				DT_RetToString(ret));
			return (ret);
		} else
			LOGPRINTF(" Accept[%d] complete\n", i);

		event.event_number = 0;
	}
	return DAT_SUCCESS;
}

static DAT_RETURN process_conn()
{
	DAT_RETURN ret;
	DAT_EVENT event;
	DAT_COUNT nmore;
	int i, exp_event, pdata;
	DAT_IB_EXTENSION_EVENT_DATA *ext_event = (DAT_IB_EXTENSION_EVENT_DATA *)
	    & event.event_extension_data[0];
	DAT_CONNECTION_EVENT_DATA *conn_event =
	    &event.event_data.connect_event_data;

	if (ud_test)
		exp_event = DAT_IB_UD_CONNECTION_EVENT_ESTABLISHED;
	else
		exp_event = DAT_CONNECTION_EVENT_ESTABLISHED;

	/* process the RTU, ESTABLISHMENT event */
	printf(" Completing...\n");
        for (i = 0; i < connections; i++) {

        	/* process completions */
		ret = dat_evd_wait(h_conn_evd, CONN_TIMEOUT, 1, &event, &nmore);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " ERR: CONN evd_wait() %s\n",
				 DT_RetToString(ret));
			return ret;
		}
		if (event.event_number != exp_event) {
			fprintf(stderr, " Err unexpected conn event : 0x%x %s\n",
				event.event_number,
				DT_EventToSTr(event.event_number));
			return (DAT_ABORT);
		}
		event.event_number = 0;
		LOGPRINTF(" CONN_EST[%d] complete\n", i);

		/* RC we are done */
		if (!ud_test)
			continue;

		/* store each remote_ah according to remote EP index */
		pdata = ntohl(*((int *)conn_event->private_data));
		LOGPRINTF(" Got private data=0x%x\n", pdata);

		/* UD, get AH for sends.
		 * NOTE: bi-directional AH resolution results in a CONN_EST
		 * for both outbound connect and inbound CR.
		 * Use Active CONN_EST which includes server's CR
		 * pdata for remote_ah idx to send.
		 *
		 * DAT_IB_UD_PASSIVE_REMOTE_AH == passive side CONN_EST
		 * DAT_IB_UD_REMOTE_AH == active side CONN_EST
		 */
		if (ext_event->type == DAT_IB_UD_REMOTE_AH) {
			remote_ah[pdata] = ext_event->remote_ah;
			LOGPRINTF(" Active side - remote_ah[%d]: ah=%p, qpn=0x%x "
			          "addr=%s\n", pdata, remote_ah[pdata].ah,
			       remote_ah[pdata].qpn, inet_ntoa(((struct sockaddr_in *)
								&remote_ah[pdata].
								ia_addr)->sin_addr));
		} else if (ext_event->type == DAT_IB_UD_PASSIVE_REMOTE_AH) {
			remote_ah[pdata] = ext_event->remote_ah;
			LOGPRINTF(" Passive side - remote_ah[%d]: ah=%p, qpn=0x%x "
			          "addr=%s\n", pdata, remote_ah[pdata].ah,
			       remote_ah[pdata].qpn, inet_ntoa(((struct sockaddr_in *)
								&remote_ah[pdata].
								ia_addr)->sin_addr));
		} else {
			printf(" Error - unexpected UD ext_event type: 0x%x\n",
			       ext_event->type);
			exit(1);
		}
        }
	return DAT_SUCCESS;
}

static DAT_RETURN conn_server()
{
	DAT_RETURN ret;

	/* wait for conn REQ and accept */
	ret = process_cr();
	if (ret != DAT_SUCCESS)
		return ret;

	/* wait for conn EST */
	ret = process_conn();
	if (ret != DAT_SUCCESS)
		return ret;

	return DAT_SUCCESS;
}

static DAT_RETURN conn_client()
{
	DAT_IA_ADDRESS_PTR raddr = (DAT_IA_ADDRESS_PTR)&remote;
	DAT_RETURN ret;
	struct addrinfo *target;
	int rval, i, pdata;

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
	printf(" Connecting to Server: %s \n",  hostname);
	printf(" Address: %d.%d.%d.%d port %d\n",
		(rval >> 0) & 0xff, (rval >> 8) & 0xff,
		(rval >> 16) & 0xff, (rval >> 24) & 0xff,
		server_port_id);

	raddr = (DAT_IA_ADDRESS_PTR)target->ai_addr;

no_resolution:

       	printf(" Connecting...\n");
	for (i = 0; i < connections; i++) {
		/* Client in UD test is one EP to many */
		pdata = htonl(i);
		ret = dat_ep_connect(ud_test ? h_ep[0]: h_ep[i],
				     raddr, server_port_id, CONN_TIMEOUT,
				     4, &pdata, 0, DAT_CONNECT_DEFAULT_FLAG);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " ERR dat_ep_connect: %s\n",
				DT_RetToString(ret));
			return (ret);
		} else
			LOGPRINTF(" dat_ep_connect [%d] complete\n", i);
	}

	/* wait for conn EST */
	ret = process_conn();
	if (ret != DAT_SUCCESS)
		return ret;

	if (!ucm)
		freeaddrinfo(target);

	return (DAT_SUCCESS);
}

/* validate disconnected EP's and free them */
static DAT_RETURN disconnect_eps(void)
{
	DAT_RETURN ret;
	DAT_EVENT event, async_event;
	DAT_COUNT nmore;
	int i,ii;
	DAT_CONNECTION_EVENT_DATA *conn_event =
		&event.event_data.connect_event_data;

	if (!connected)
		return DAT_SUCCESS;

	if (ud_test) {
		for (ii = 0; ii < connections; ii++) {
			LOGPRINTF(" Free EP[%d] %p\n", ii, h_ep[ii]);
			ret = dat_ep_free(h_ep[ii]);
			if (ret != DAT_SUCCESS) {
				fprintf(stderr, "ERR free EP[%d] %p: %s\n",
					ii, h_ep[ii], DT_RetToString(ret));
			} else {
				LOGPRINTF(" Freed EP[%d] %p\n", ii, h_ep[ii]);
				h_ep[ii] = DAT_HANDLE_NULL;
			}
			/* Client use only EP zero in UD test */
			if (!server)
				break;
		}
		return DAT_SUCCESS;
	}
	/*
	 * Only the client needs to call disconnect. The server _should_ be able
	 * to just wait on the EVD associated with connection events for a
	 * disconnect request and then exit.
	 */
	for (i = 0; i < connections; i++) {
		if (!server) {
			LOGPRINTF(" dat_ep_disconnect[%d]\n",i);

			ret = dat_ep_disconnect(h_ep[i], DAT_CLOSE_DEFAULT);
			if (ret != DAT_SUCCESS) {
				fprintf(stderr, " Error disconnect: %s\n",
					DT_RetToString(ret));
				return ret;
			} else {
				LOGPRINTF(" disconnect completed[%d]\n", i);
			}
		}
		else {
			LOGPRINTF(" Server waiting for disconnect...\n");
		}

		LOGPRINTF(" Wait for Disc event\n");
		nmore = 0;
		event.event_number = 0;
		conn_event->ep_handle = NULL;
		ret = dat_evd_wait(h_conn_evd, DAT_TIMEOUT_INFINITE, 1, &event, &nmore);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " Error dat_evd_wait: %s\n", DT_RetToString(ret));
			return ret;
		} else
			LOGPRINTF(" disc event[%d] complete\n", i);

		if (srq_test) {
			LOGPRINTF(" Wait for EP async event\n");
			async_event.event_number = 0;
			ret = dat_evd_wait(h_async_evd, DAT_TIMEOUT_INFINITE,
					   1, &async_event, &nmore);
			if (ret != DAT_SUCCESS) {
				fprintf(stderr, " Error dat_evd_wait async evd: %s\n",
					DT_RetToString(ret));
				return ret;
			} else
				LOGPRINTF(" Async event 0x%x received for EP %p\n",
					  async_event.event_number,
					  async_event.event_data.asynch_error_event_data.dat_handle);

			if (async_event.event_number != DAT_ASYNC_ERROR_EP_BROKEN) {
				LOGPRINTF(" Invalid async event number 0x%x expected 0x%x\n",
					  async_event.event_number, DAT_ASYNC_ERROR_EP_BROKEN);
				return DAT_INVALID_HANDLE;
			}

			if (conn_event->ep_handle != async_event.
					event_data.asynch_error_event_data.dat_handle) {
				LOGPRINTF(" Invalid EP via async event. conn event EP = %p,"
					  " async event EP = %p\n", conn_event->ep_handle,
					  async_event.event_data.asynch_error_event_data.dat_handle);
				return DAT_INVALID_HANDLE;
			}
		}

		LOGPRINTF(" Check for valid EP and free it\n");
		/* check for valid EP in creation list */
		for (ii = 0; ii < connections; ii++) {
			if (h_ep[ii] == conn_event->ep_handle) {
				LOGPRINTF(" valid EP[%d] %p\n", ii, h_ep[ii]);
				ret = dat_ep_free(h_ep[ii]);
				if (ret != DAT_SUCCESS) {
					fprintf(stderr, " ERR free EP[%d] %p: %s\n",
						ii, h_ep[ii], DT_RetToString(ret));
					return ret;
				} else {
					LOGPRINTF(" Freed EP[%d] %p\n", ii, h_ep[ii]);
					h_ep[ii] = DAT_HANDLE_NULL;
				}
				break;
			}
		}
		if (ii == connections) {
			LOGPRINTF(" %s: invalid EP[%d] %p via DISC event!\n",
				  server ? "Server" : "Client",
				  i, conn_event->ep_handle);
			return DAT_INVALID_HANDLE;
		}
	}

	/* free EPs */
	LOGPRINTF(" Successfully disconnected all %d EP's\n", connections);
	return DAT_SUCCESS;
}

 /*
  * Create CR, CONN, and DTO events
  */
static DAT_RETURN create_events(void)
{
	DAT_RETURN ret;
	DAT_EVD_PARAM param;
	DAT_COUNT evd_min_qlen;

	/*** create CR EVD ***/
	evd_min_qlen = connections;
	ret = dat_evd_create(h_ia,
			     evd_min_qlen,
			     DAT_HANDLE_NULL,
			     DAT_EVD_CR_FLAG,
			     &h_cr_evd);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error dat_evd_create CR: %s\n",
			DT_RetToString(ret));
		return (ret);
	}

	/* query and check size */
	ret = dat_evd_query(h_cr_evd, DAT_EVD_FIELD_EVD_QLEN, &param);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Err dat_evd_query CR evd: %s\n",
			DT_RetToString(ret));
		return (ret);
	} else if (param.evd_qlen < evd_min_qlen)  {
		fprintf(stderr, " Error dat_evd qsize too small: %d < %d\n",
			param.evd_qlen, evd_min_qlen);
		return (ret);
	}

	LOGPRINTF(" cr_evd created (%p). QLEN - requested %d and actual %d\n",
			h_cr_evd, evd_min_qlen, param.evd_qlen);

	/*** create conn EVD ***/
	evd_min_qlen = connections * 2;
	ret = dat_evd_create(h_ia,
			     evd_min_qlen,
			     DAT_HANDLE_NULL,
			     DAT_EVD_CONNECTION_FLAG,
			     &h_conn_evd);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error dat_evd_create CONN: %s\n",
			DT_RetToString(ret));
		return (ret);
	}

	/* query and check size */
	ret = dat_evd_query(h_conn_evd, DAT_EVD_FIELD_EVD_QLEN, &param);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error dat_evd_query CONN evd: %s\n",
			DT_RetToString(ret));
		return (ret);
	} else if (param.evd_qlen < evd_min_qlen)  {
		fprintf(stderr, " Error dat_evd qsize too small: %d < %d\n",
			param.evd_qlen, evd_min_qlen);
		return (ret);
	}

	LOGPRINTF(" conn_evd created (%p). QLEN - requested %d and actual %d\n",
			h_conn_evd, evd_min_qlen, param.evd_qlen);

	/*** create dto SND EVD ***/
	evd_min_qlen = connections * burst_size;
	ret = dat_evd_create(h_ia,
			     evd_min_qlen,
			     NULL,
			     DAT_EVD_DTO_FLAG,
			     &h_dto_req_evd);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error dat_evd_create REQ: %s\n",
			DT_RetToString(ret));
		return (ret);
	}

	/* query and check size */
	ret = dat_evd_query(h_dto_req_evd, DAT_EVD_FIELD_EVD_QLEN, &param);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error dat_evd_query REQ evd: %s\n",
			DT_RetToString(ret));
		return (ret);
	} else if (param.evd_qlen < evd_min_qlen)  {
		fprintf(stderr, " Error dat_evd qsize too small: %d < %d\n",
			param.evd_qlen, evd_min_qlen);
		return (ret);
	}

	LOGPRINTF(" req_evd created (%p). QLEN - requested %d and actual %d\n",
			h_dto_req_evd, evd_min_qlen, param.evd_qlen);

	/*** create dto RCV EVD ***/
	evd_min_qlen = connections * burst_size;
	ret = dat_evd_create(h_ia,
			     evd_min_qlen,
			     NULL,
			     DAT_EVD_DTO_FLAG,
			     &h_dto_rcv_evd);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error dat_evd_create RCV: %s\n",
			DT_RetToString(ret));
		return (ret);
	}

	/* query and check size */
	ret = dat_evd_query(h_dto_rcv_evd, DAT_EVD_FIELD_EVD_QLEN, &param);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error dat_evd_query RCV evd: %s\n",
			DT_RetToString(ret));
		return (ret);
	} else if (param.evd_qlen < evd_min_qlen)  {
		fprintf(stderr, " Error dat_evd qsize too small: %d < %d\n",
			param.evd_qlen, evd_min_qlen);
		return (ret);
	}

	LOGPRINTF(" rcv_evd created (%p). QLEN - requested %d and actual %d\n",
			h_dto_rcv_evd, evd_min_qlen, param.evd_qlen);

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
		LOGPRINTF(" Free cr EVD %p \n",  h_cr_evd);
		ret = dat_evd_free(h_cr_evd);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " Error freeing cr EVD: %s\n",
				DT_RetToString(ret));
			return (ret);
		} else {
			LOGPRINTF(" Freed cr EVD\n");
			h_cr_evd = DAT_HANDLE_NULL;
		}
	}

	/* free conn EVD */
	if (h_conn_evd != DAT_HANDLE_NULL) {
		LOGPRINTF(" Free conn EVD %p\n",  h_conn_evd);
		ret = dat_evd_free(h_conn_evd);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " Error freeing conn EVD: %s\n",
				DT_RetToString(ret));
			return (ret);
		} else {
			LOGPRINTF(" Freed conn EVD\n");
			h_conn_evd = DAT_HANDLE_NULL;
		}
	}

	/* free RCV dto EVD */
	if (h_dto_rcv_evd != DAT_HANDLE_NULL) {
		LOGPRINTF(" Free RCV dto EVD %p\n",  h_dto_rcv_evd);
		ret = dat_evd_free(h_dto_rcv_evd);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " Error freeing dto EVD: %s\n",
				DT_RetToString(ret));
			return (ret);
		} else {
			LOGPRINTF(" Freed dto EVD\n");
			h_dto_rcv_evd = DAT_HANDLE_NULL;
		}
	}

	/* free REQ dto EVD */
	if (h_dto_req_evd != DAT_HANDLE_NULL) {
		LOGPRINTF(" Free REQ dto EVD %p\n",  h_dto_req_evd);
		ret = dat_evd_free(h_dto_req_evd);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, " Error freeing dto EVD: %s\n",
				DT_RetToString(ret));
			return (ret);
		} else {
			LOGPRINTF(" Freed dto EVD\n");
			h_dto_req_evd = DAT_HANDLE_NULL;
		}
	}

	return DAT_SUCCESS;
}

/*
 * Map DAT_RETURN values to readable strings,
 * but don't assume the values are zero-based or contiguous.
 */
static char errmsg[512] = { 0 };
const char *DT_RetToString(DAT_RETURN ret_value)
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
const char *DT_EventToSTr(DAT_EVENT_NUMBER event_code)
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

static void flush_evds(void)
{
	DAT_EVENT event;

	/* Flush async error queue */
	printf(" ERR: Checking ASYNC EVD...\n");
	while (dat_evd_dequeue(h_async_evd, &event) == DAT_SUCCESS) {
		printf(" ASYNC EVD ENTRY: handle=%p reason=%d\n",
			event.event_data.asynch_error_event_data.dat_handle,
			event.event_data.asynch_error_event_data.reason);
	}
}

static void print_ia_address(struct sockaddr *sa)
{
	char str[INET6_ADDRSTRLEN] = {" ??? "};

	switch(sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, str, INET6_ADDRSTRLEN);
		printf(" Local Address AF_INET - %s port %d\n", str, server_port_id);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, str, INET6_ADDRSTRLEN);
		printf(" Local Address AF_INET6 - %s flowinfo(QPN)=0x%x, port(LID)=0x%x\n",
			str,
			ntohl(((struct sockaddr_in6 *)sa)->sin6_flowinfo),
			ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
		break;
	default:
		printf(" Local Address UNKOWN FAMILY - port %d\n", server_port_id);
	}
}

/* Register RDMA Receive buffer */
static DAT_RETURN register_rdma_memory(void)
{
	DAT_RETURN ret;
	DAT_REGION_DESCRIPTION region;

	region.for_va = rbuf;
	ret = dat_lmr_create(h_ia,
			     DAT_MEM_TYPE_VIRTUAL,
			     region,
			     connections * rx_buf_len * burst_size,
			     h_pz,
			     DAT_MEM_PRIV_ALL_FLAG,
			     DAT_VA_TYPE_VA,
			     &h_lmr_recv,
			     &lmr_context_recv,
			     &rmr_context_recv,
			     &registered_size_recv, &registered_addr_recv);

	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error registering Receive RDMA buffer: %s\n",
			DT_RetToString(ret));
		return (ret);
	} else {
		LOGPRINTF(" Registered RCV RDMA Buffer  %p\n", region.for_va);
	}

	/* Register RDMA Send buffer */
	region.for_va = sbuf;
	ret = dat_lmr_create(h_ia,
			     DAT_MEM_TYPE_VIRTUAL,
			     region,
			     connections * tx_buf_len * burst_size,
			     h_pz,
			     DAT_MEM_PRIV_ALL_FLAG,
			     DAT_VA_TYPE_VA,
			     &h_lmr_send,
			     &lmr_context_send,
			     &rmr_context_send,
			     &registered_size_send, &registered_addr_send);
	if (ret != DAT_SUCCESS) {
		fprintf(stderr, " Error registering send RDMA buffer: %s\n",
			DT_RetToString(ret));
		return (ret);
	} else {
		LOGPRINTF(" Registered Send RDMA Buffer %p\n", region.for_va);
	}

	return DAT_SUCCESS;
}

static void unregister_rdma_memory()
{
	DAT_RETURN ret;

	/* Unregister Send message Buffer */
	if (h_lmr_send != DAT_HANDLE_NULL) {
		LOGPRINTF(" Unregister send message h_lmr %p \n", h_lmr_send);
		ret = dat_lmr_free(h_lmr_send);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr,
				" Error deregistering send msg mr: %s\n",
				DT_RetToString(ret));
		} else {
			LOGPRINTF(" Unregistered send message Buffer\n");
			h_lmr_send = NULL;
		}
	}

	/* Unregister recv message Buffer */
	if (h_lmr_recv != DAT_HANDLE_NULL) {
		LOGPRINTF(" Unregister recv message h_lmr %p \n", h_lmr_recv);
		ret = dat_lmr_free(h_lmr_recv);
		if (ret != DAT_SUCCESS) {
			fprintf(stderr,
				" Error deregistering recv msg mr: %s\n",
				DT_RetToString(ret));
		} else {
			LOGPRINTF(" Unregistered recv message Buffer\n");
			h_lmr_recv = NULL;
		}
	}
}

static DAT_RETURN send_msg(char *buff, char msg_head, DAT_UINT32 ep_num,
		    DAT_UINT32 msg_num)
{
	DAT_DTO_COOKIE cookie;
	DAT_LMR_TRIPLET l_iov;

	*buff = msg_head;
	*((DAT_UINT32 *)(buff + 4)) = htonl(ep_num);
	*((DAT_UINT32 *)(buff + 8)) = htonl(msg_num);

	l_iov.lmr_context = lmr_context_send;
#if defined(_WIN32)
	l_iov.virtual_address = (DAT_VADDR) buff;
#else
	l_iov.virtual_address = (DAT_VADDR)(unsigned long)buff;
#endif
	l_iov.segment_length = tx_buf_len;

	if (!ud_test) {
		LOGPRINTF(" %s RC SEND, ep %d, msg num %d, buffer %p len=%d\n",
			  server ? "SERVER:" : "CLIENT:",
			  ep_num, msg_num, buff, tx_buf_len);

		return dat_ep_post_send(h_ep[ep_num], 1, &l_iov, cookie,
				DAT_COMPLETION_DEFAULT_FLAG);
	} else {
		/* UD section */
		int ep_idx = (server ? ep_num : 0);
		int ah_idx = (server ? 0 : ep_num);
		LOGPRINTF(" %s UD SND, from ep %d to ep %d, msg num %d, buffer %p len %d\n",
			  server ? "SERVER:" : "CLIENT:",
			  ep_idx, ah_idx, msg_num, buff, tx_buf_len);
		LOGPRINTF(" %s sending on ep=%p to remote_ah %p"
		          " qpn=0x%x addr=%s\n",
		          server ? "Server" : "Client", h_ep[ep_idx], remote_ah[ah_idx].ah,
		          remote_ah[ah_idx].qpn, inet_ntoa(((struct sockaddr_in *)
				  &remote_ah[ah_idx].ia_addr)->sin_addr));

		/* client use all data in on first EP */
		return dat_ib_post_send_ud(h_ep[ep_idx],
					   1,
					   &l_iov,
					   &remote_ah[ah_idx],
					   cookie,
					   DAT_COMPLETION_DEFAULT_FLAG);
	}
}

static void print_usage(void)
{
	printf("\n DAPL SRQ USAGE \n\n");
	printf("s: server\n");
	printf("c: connections (default = 1, max = 100)\n");
	printf("B: burst messages per connection (default = 1, max = 100)\n");
	printf("t: bursts number per connection (default = 3)\n");
	printf("b: buffer length to allocate (default DAT_IB_TRANSPORT_MTU)\n");
	printf("v: verbose\n");
	printf("h: hostname/address of server, specified on client\n");
	printf("P: provider name (default = OpenIB-cma)\n");
	printf("l: server lid (required ucm provider)\n");
	printf("q: server qpn (required ucm provider)\n");
	printf("u  unreliable datagram test (default false)\n");
	printf("S  use SRQ (default = 1 = use SQR)\n");
	printf("\n");
}
