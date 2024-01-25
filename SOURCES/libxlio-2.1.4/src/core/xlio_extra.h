/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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
 */

#ifndef XLIO_EXTRA_H
#define XLIO_EXTRA_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

/*
 * Flags for recvfrom_zcopy()
 */
#define MSG_XLIO_ZCOPY_FORCE 0x01000000 // don't fallback to bcopy
#define MSG_XLIO_ZCOPY       0x00040000 // return: zero copy was done

/*
 * Options for setsockopt()/getsockopt()
 */
#define SO_XLIO_GET_API          2800
#define SO_XLIO_USER_DATA        2801
#define SO_XLIO_RING_ALLOC_LOGIC 2810
#define SO_XLIO_RING_USER_MEMORY 2811
#define SO_XLIO_FLOW_TAG         2820
#define SO_XLIO_SHUTDOWN_RX      2821
#define SO_XLIO_PD               2822
#define SCM_XLIO_PD              SO_XLIO_PD

enum { CMSG_XLIO_IOCTL_USER_ALLOC = 2900 };

/*
 * Flags for Dummy send API
 */
#define XLIO_SND_FLAGS_DUMMY MSG_SYN // equals to 0x400

/*
 * Magic value for xlio_get_api (NVDAXLIO)
 */
#define XLIO_MAGIC_NUMBER (0x4f494c584144564eULL)

/**
 * @brief Pass this structure as an argument into getsockopt() with @ref SO_XLIO_PD
 * 	to get protection domain information from ring used for current socket.
 * 	This information can be available after setting connection for TX ring
 * 	and bounding to device for RX ring.
 * 	By default getting PD for TX ring.
 * 	This case can be used with sendmsg(SCM_XLIO_PD) when the data portion contains
 * 	an array of the elements with datatype as struct xlio_pd_key. Number of elements in this
 * 	array should be equal to msg_iovlen value. Every data pointer in msg_iov has
 * 	correspondent memory key.
 *
 * @param flags - to specify needed information.
 * @param pd - protection domain (PD) for the RDMA device context
 */
struct xlio_pd_attr {
    uint32_t flags;
    void *ib_pd;
};

/**
 * @brief elements with this datatype can be passed into sendmsg(SCM_XLIO_PD)
 * as control message with correspondent pointer to data.
 *
 * @param flags - to specify needed information. By default mkey value is used.
 * @param mkey - memory key
 */
struct xlio_pd_key {
    uint32_t flags;
    uint32_t mkey;
};

/**
 * Represents one packet
 * Used in receive zero-copy extended API.
 */
struct __attribute__((packed)) xlio_recvfrom_zcopy_packet_t {
    void *packet_id; // packet identifier
    size_t sz_iov; // number of fragments
    struct iovec iov[]; // fragments size+data
};

/**
 * Represents received packets
 * Used in receive zero-copy extended API.
 */
struct __attribute__((packed)) xlio_recvfrom_zcopy_packets_t {
    size_t n_packet_num; // number of received packets
    struct xlio_recvfrom_zcopy_packet_t pkts[]; // array of received packets
};

/*
 * Structure holding additional information on the packet and socket
 * Note: Check structure size value for future library changes
 */
struct __attribute__((packed)) xlio_info_t {
    size_t
        struct_sz; /* Compare this value with sizeof(xlio_info_t) to check version compatability */
    void *packet_id; /* Handle to received packet buffer to be return if zero copy logic is used */

    /* Packet addressing information (in network byte order) */
    const struct sockaddr *src;
    const struct sockaddr *dst;

    /* Packet information */
    size_t payload_sz;

    /* Socket's information */
    uint32_t socket_ready_queue_pkt_count; /* Current count of packets waiting to be read from the
                                              socket */
    uint32_t socket_ready_queue_byte_count; /* Current count of bytes waiting to be read from the
                                               socket */

    /* Packet timestamping information */
    struct timespec hw_timestamp;
    struct timespec sw_timestamp;
};

struct xlio_rate_limit_t {
    uint32_t rate; /* rate limit in Kbps */
    uint32_t max_burst_sz; /* maximum burst size in bytes */
    uint16_t typical_pkt_sz; /* typical packet size in bytes */
};

typedef enum {
    RING_LOGIC_PER_INTERFACE = 0, //!< RING_LOGIC_PER_INTERFACE
    RING_LOGIC_PER_IP = 1, //!< RING_LOGIC_PER_IP
    RING_LOGIC_PER_SOCKET = 10, //!< RING_LOGIC_PER_SOCKET
    RING_LOGIC_PER_USER_ID = 11, //!< RING_LOGIC_PER_USER_ID
    RING_LOGIC_PER_THREAD = 20, //!< RING_LOGIC_PER_THREAD
    RING_LOGIC_PER_CORE = 30, //!< RING_LOGIC_PER_CORE
    RING_LOGIC_PER_CORE_ATTACH_THREADS = 31, //!< RING_LOGIC_PER_CORE_ATTACH_THREADS
    RING_LOGIC_LAST //!< RING_LOGIC_LAST
} ring_logic_t;

typedef enum {
    XLIO_RING_ALLOC_MASK_RING_USER_ID = (1 << 0),
    XLIO_RING_ALLOC_MASK_RING_INGRESS = (1 << 1),
    XLIO_RING_ALLOC_MASK_RING_ENGRESS = (1 << 2),
} xlio_ring_alloc_logic_attr_comp_mask;

/**
 * @brief pass this struct to process by the library using setsockopt with
 * @ref SO_XLIO_RING_ALLOC_LOGIC
 * 	to set the allocation logic of this FD when he requests a ring.
 * 	@note ring_alloc_logic is a mandatory
 * @param comp_mask - what fields are read when processing this struct
 * 	see @ref xlio_ring_alloc_logic_attr_comp_mask
 * @param ring_alloc_logic- allocation ratio to use
 * @param user_idx - when used RING_LOGIC_PER_USER_ID int @ref ring_alloc_logic
 * 	this is the user id to define. This lets you define the same ring for
 * 	few FD's regardless the interface\thread\core.
 * @param ingress - RX ring
 * @param engress - TX ring
 */
struct xlio_ring_alloc_logic_attr {
    uint32_t comp_mask;
    ring_logic_t ring_alloc_logic;
    uint32_t user_id;
    uint32_t ingress : 1;
    uint32_t engress : 1;
    uint32_t reserved : 30;
};

enum {
    XLIO_EXTRA_API_RECVFROM_ZCOPY = (1 << 1),
    XLIO_EXTRA_API_RECVFROM_ZCOPY_FREE_PACKETS = (1 << 2),
    XLIO_EXTRA_API_ADD_CONF_RULE = (1 << 3),
    XLIO_EXTRA_API_THREAD_OFFLOAD = (1 << 4),
    XLIO_EXTRA_API_GET_SOCKET_RINGS_NUM = (1 << 5),
    XLIO_EXTRA_API_GET_SOCKET_RINGS_FDS = (1 << 6),
    XLIO_EXTRA_API_DUMP_FD_STATS = (1 << 11),
    XLIO_EXTRA_API_IOCTL = (1 << 12),
};

/**
 * XLIO Extended Socket API
 */
struct __attribute__((packed)) xlio_api_t {

    /**
     * Used to verify that API structure returned from xlio_get_api call is
     * compatible with current XLIO library version.
     */
    uint64_t magic;

    /**
     * Used to identify which methods were initialized by XLIO as part of xlio_get_api().
     * The value content is based on cap_mask bit field.
     * Order of fields in this structure should not be changed to keep abi compatibility.
     */
    uint64_t cap_mask;

    /**
     * Zero-copy revcfrom implementation.
     *
     * @param s Socket file descriptor.
     * @param buf Buffer to fill with received data or pointers to data (see below).
     * @param flags Pointer to flags (see below).
     * @param from If not NULL, will be filled with source address (same as recvfrom).
     * @param fromlen If not NULL, will be filled with source address size (same as recvfrom).
     *
     * This function attempts to receive a packet without doing data copy.
     * The flags argument can contain the usual flags of recvmsg(), and also the
     * MSG_XLIO_ZCOPY_FORCE flag. If the latter is set, the function will not
     * fall back to data copy. Otherwise, the function falls back to data copy
     * if zero-copy cannot be performed. If zero-copy is done then MSG_XLIO_ZCOPY
     * flag is set upon exit.
     *
     * If zero copy is performed (MSG_XLIO_ZCOPY flag is returned), the buffer
     * is filled with a xlio_recvfrom_zcopy_packets_t structure, holding as much fragments
     * as `len' allows. The total size of all fragments is returned.
     * Otherwise the MSG_XLIO_ZCOPY flag is not set and the buffer is filled
     * with actual data and it's size is returned (same as recvfrom())
     * If no data was received the return value is zero.
     *
     * NOTE: The returned packet must be freed with free_packet() after
     * the application finished using it.
     */
    int (*recvfrom_zcopy)(int s, void *buf, size_t len, int *flags, struct sockaddr *from,
                          socklen_t *fromlen);

    /**
     * Frees a packet received by recvfrom_zcopy() or held by receive callback.
     *
     * @param s Socket from which the packet was received.
     * @param pkts Array of packet.
     * @param count Number of packets in the array.
     * @return 0 on success, -1 on failure
     *
     * errno is set to: EINVAL - not a offloaded socket
     *                  ENOENT - the packet was not received from `s'.
     */
    int (*recvfrom_zcopy_free_packets)(int s, struct xlio_recvfrom_zcopy_packet_t *pkts,
                                       size_t count);

    /*
     * Add a libxlio.conf rule to the top of the list.
     * This rule will not apply to existing sockets which already considered the conf rules.
     * (around connect/listen/send/recv ..)
     * @param config_line A char buffer with the exact format as defined in libxlio.conf, and should
     * end with '\0'.
     * @return 0 on success, or error code on failure.
     */
    int (*add_conf_rule)(const char *config_line);

    /*
     * Create sockets on pthread tid as offloaded/not-offloaded.
     * This does not affect existing sockets.
     * Offloaded sockets are still subject to libxlio.conf rules.
     * @param offload 1 for offloaded, 0 for not-offloaded.
     * @return 0 on success, or error code on failure.
     */
    int (*thread_offload)(int offload, pthread_t tid);

    /**
     * Returns the amount of rings that are associated with socket.
     *
     * @param fd File Descriptor number of the socket.
     * @return On success, return the amount of rings.
     *         On error, -1 is returned.
     *
     * errno is set to: EINVAL - not a offloaded fd
     */
    int (*get_socket_rings_num)(int fd);

    /**
     * Returns FDs of the RX rings that are associated with the socket.
     *
     * This function gets socket FD + int array + array size and populates
     * the array with FD numbers of the rings that are associated
     * with the socket.
     *
     * @param fd File Descriptor number.
     * @param ring_fds Array of ring fds
     * @param ring_fds_sz Size of the array
     * @return On success, return the number populated array entries.
     *         On error, -1 is returned.
     *
     * errno is set to: EINVAL - not a offloaded fd + TBD
     */
    int (*get_socket_rings_fds)(int fd, int *ring_fds, int ring_fds_sz);

    /*
     * Dump fd statistics using the library logger.
     * @param fd to dump, 0 for all open fds.
     * @param log_level dumping level corresponding vlog_levels_t enum (vlogger.h).
     * @return 0 on success, or error code on failure.
     *
     * errno is set to: EOPNOTSUPP
     */
    int (*dump_fd_stats)(int fd, int log_level);

    /**
     * This function allows to communicate with library using extendable protocol
     * based on struct cmshdr.
     *
     * Ancillary data is a sequence of cmsghdr structures with appended data.
     * The sequence of cmsghdr structures should never be accessed directly.
     * Instead, use only the following macros: CMSG_ALIGN, CMSG_SPACE, CMSG_DATA,
     * CMSG_LEN.
     *
     * @param cmsg_hdr - point to control message
     * @param cmsg_len - the byte count of the ancillary data,
     *                   which contains the size of the structure header.
     *
     * @return -1 on failure and 0 on success
     */
    int (*ioctl)(void *cmsg_hdr, size_t cmsg_len);
};

/**
 * Retrieve XLIO extended API.
 * This function can be called as an alternative to getsockopt() call
 * when library is preloaded using LD_PRELOAD
 * getsockopt() call should be used in case application loads library
 * using dlopen()/dlsym().
 *
 * @return Pointer to the XLIO Extended Socket API, of NULL if XLIO not found.
 */
static inline struct xlio_api_t *xlio_get_api()
{
    struct xlio_api_t *api_ptr = NULL;
    socklen_t len = sizeof(api_ptr);

    /* coverity[negative_returns] */
    int err = getsockopt(-2, SOL_SOCKET, SO_XLIO_GET_API, &api_ptr, &len);
    if (err < 0) {
        return NULL;
    }
    if (len < sizeof(struct xlio_api_t *) || api_ptr == NULL ||
        api_ptr->magic != XLIO_MAGIC_NUMBER) {
        return NULL;
    }
    return api_ptr;
}

#endif /* XLIO_EXTRA_H */
