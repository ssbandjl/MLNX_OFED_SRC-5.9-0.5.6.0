/*
 * Copyright (c) 2019 Mellanox Technologies, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "netdev-dpdk-vdpa.h"

#include <netinet/ip6.h>

#include <rte_atomic.h>
#include <rte_bus.h>
#include <rte_byteorder.h>
#include <rte_dev.h>
#include <rte_eth_vhost.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_flow.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_pci.h>
#include <rte_vdpa.h>

#include "netdev-provider.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "dp-packet.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(netdev_dpdk_vdpa);

#define NETDEV_DPDK_VDPA_SIZEOF_MBUF        (sizeof(struct rte_mbuf *))
#define NETDEV_DPDK_VDPA_MAX_QPAIRS         16
#define NETDEV_DPDK_VDPA_INVALID_QUEUE_ID   0xFFFF
#define NETDEV_DPDK_VDPA_STATS_MAX_STR_SIZE 128
#define NETDEV_DPDK_VDPA_RX_DESC_DEFAULT    512

enum netdev_dpdk_vdpa_port_type {
    NETDEV_DPDK_VDPA_PORT_TYPE_VM,
    NETDEV_DPDK_VDPA_PORT_TYPE_VF
};

struct netdev_dpdk_vdpa_relay_flow {
    struct rte_flow *flow;
    bool queues_en[RTE_MAX_QUEUES_PER_PORT];
    uint32_t priority;
};

struct netdev_dpdk_vdpa_qpair {
    uint16_t port_id_rx;
    uint16_t port_id_tx;
    uint16_t pr_queue;
    uint8_t mb_head;
    uint8_t mb_tail;
    struct rte_mbuf *pkts[NETDEV_MAX_BURST * 2];
};

enum netdev_dpdk_vdpa_mode {
    NETDEV_DPDK_VDPA_MODE_INIT,
    NETDEV_DPDK_VDPA_MODE_HW,
    NETDEV_DPDK_VDPA_MODE_SW,
};

struct netdev_dpdk_vdpa_relay {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct netdev_dpdk_vdpa_qpair qpair[NETDEV_DPDK_VDPA_MAX_QPAIRS * 2];
        uint16_t num_queues;
        struct netdev_dpdk_vdpa_relay_flow flow_params;
        int port_id_vm;
        int port_id_vf;
        uint16_t vf_mtu;
        int n_rxq;
        char *vf_devargs;
        char *vm_socket;
        char *vhost_name;
        bool started;
        enum netdev_dpdk_vdpa_mode hw_mode;
        struct rte_vdpa_device *vdpa_dev;
        struct rte_device *rte_dev;
        int vid;
        struct shash_node *map_item;
        struct ovs_mutex lock;
        );
};

static struct shash relays_map = SHASH_INITIALIZER(&relays_map);
static struct ovs_mutex relays_map_lock = OVS_MUTEX_INITIALIZER;

static void
relays_map_add(struct netdev_dpdk_vdpa_relay *relay)
{
    if (relay->map_item) {
        return;
    }

    ovs_mutex_lock(&relays_map_lock);
    relay->map_item = shash_add(&relays_map, relay->vhost_name, relay);
    ovs_mutex_unlock(&relays_map_lock);
}

static void
relays_map_remove(struct netdev_dpdk_vdpa_relay *relay)
{
    if (!relay->map_item) {
        return;
    }

    ovs_mutex_lock(&relays_map_lock);
    shash_delete(&relays_map, relay->map_item);
    relay->map_item = NULL;
    ovs_mutex_unlock(&relays_map_lock);
}

static int
netdev_dpdk_vdpa_port_from_name(const char *name)
{
    struct rte_eth_dev_info info;
    int port_id;
    size_t len;

    len = strlen(name);
    RTE_ETH_FOREACH_DEV (port_id) {
        rte_eth_dev_info_get(port_id, &info);
        if (!strncmp(name, rte_dev_name(info.device), len)) {
            return port_id;
        }
    }
    VLOG_ERR("No port was found for %s", name);
    return ENODEV;
}

static void
netdev_dpdk_vdpa_free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr);
    ptr = NULL;
}

static void
netdev_dpdk_vdpa_clear_relay(struct netdev_dpdk_vdpa_relay *relay)
{
    uint16_t q;
    uint8_t i;

    for (q = 0; q < relay->num_queues; q++) {
        for (i = relay->qpair[q].mb_head; i < relay->qpair[q].mb_tail; i++) {
            rte_pktmbuf_free(relay->qpair[q].pkts[i]);
        }
        relay->qpair[q].mb_head = 0;
        relay->qpair[q].mb_tail = 0;
        relay->qpair[q].port_id_rx = 0;
        relay->qpair[q].port_id_tx = 0;
        relay->qpair[q].pr_queue = NETDEV_DPDK_VDPA_INVALID_QUEUE_ID;
    }

    relay->started = false;
    relay->port_id_vm = 0;
    relay->port_id_vf = 0;
    relay->num_queues = 0;
    relay->flow_params.flow = NULL;
    memset(&relay->flow_params, 0, sizeof relay->flow_params);
}

static void
netdev_dpdk_vdpa_free_relay_strings(struct netdev_dpdk_vdpa_relay *relay)
{
    netdev_dpdk_vdpa_free(relay->vm_socket);
    netdev_dpdk_vdpa_free(relay->vf_devargs);
    netdev_dpdk_vdpa_free(relay->vhost_name);
}

static int
netdev_dpdk_vdpa_generate_rss_flow(struct netdev_dpdk_vdpa_relay *relay)
{
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[2];
    struct rte_flow_action action[2];
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;
    static struct rte_flow_action_rss action_rss = {
            .func = RTE_ETH_HASH_FUNCTION_DEFAULT,
            .level = 0,
            .types = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
            .key_len = 0,
            .key = NULL,
    };
    uint16_t queue[RTE_MAX_QUEUES_PER_PORT];
    uint32_t i;
    uint32_t j;
    int err = 0;

    memset(pattern, 0, sizeof pattern);
    memset(action, 0, sizeof action);
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    attr.priority = !relay->flow_params.priority;

    for (i = 0, j = 0; i < RTE_MAX_QUEUES_PER_PORT; i++) {
        if (relay->flow_params.queues_en[i]) {
            queue[j++] = i;
        }
    }

    action_rss.queue = queue;
    action_rss.queue_num = j;

    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &action_rss;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].spec = NULL;
    pattern[0].mask = NULL;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

    flow = rte_flow_create(relay->port_id_vf, &attr, pattern, action, &error);
    if (flow == NULL) {
        VLOG_ERR("Failed to create flow. msg: %s",
                 error.message ? error.message : "(no stated reason)");
        err = EINVAL;
        goto out;
    }

    if (relay->flow_params.flow != NULL) {
        err = rte_flow_destroy(relay->port_id_vf, relay->flow_params.flow,
                               &error);
        if (err < 0) {
            VLOG_ERR("Failed to destroy flow. msg: %s",
                     error.message ? error.message : "(no stated reason)");
            goto out;
        }
    }

    relay->flow_params.flow = flow;
    relay->flow_params.priority = attr.priority;
out:
    return err;
}

static int
netdev_dpdk_vdpa_queue_state(struct netdev_dpdk_vdpa_relay *relay,
                             uint16_t port)
{
    struct rte_eth_vhost_queue_event event;
    uint32_t q_id;
    int err = 0;

    while (!rte_eth_vhost_get_queue_event(port, &event)) {
        q_id = (event.rx ? event.queue_id * 2 : event.queue_id * 2 + 1);
        if ((event.queue_id >= relay->num_queues) && event.enable) {
            VLOG_ERR("netdev_dpdk_vdpa_queue_state: "
                     "Queue %u is higher than max queues configures for port "
                     "%u. Max queues configured: %u",
                     event.queue_id, port, relay->num_queues);
            return ENODEV;
        }
        relay->flow_params.queues_en[event.queue_id] = event.enable;
        /* Load balance the relay's queues on the pr's queues in round robin */
        relay->qpair[q_id].pr_queue = (event.enable ? event.queue_id % relay->n_rxq :
                                       NETDEV_DPDK_VDPA_INVALID_QUEUE_ID);
        if (!event.rx) {
            relay->flow_params.queues_en[event.queue_id] = event.enable;
            err = netdev_dpdk_vdpa_generate_rss_flow(relay);
            if (err) {
                VLOG_ERR("netdev_dpdk_vdpa_generate_rss_flow failed");
                return err;
            }
        }
    }

    return 0;
}

static int
netdev_dpdk_vdpa_queue_state_cb_fn(uint16_t port_id,
                                   enum rte_eth_event_type type OVS_UNUSED,
                                   void *param,
                                   void *ret_param OVS_UNUSED)
{
    struct netdev_dpdk_vdpa_relay *relay = param;
    int ret = 0;

    ret = netdev_dpdk_vdpa_queue_state(relay, port_id);
    if (ret) {
        VLOG_ERR("netdev_dpdk_vdpa_queue_state failed for port %u", port_id);
        return ret;
    }

    return 0;
}

static int
netdev_dpdk_vdpa_link_status_cb_fn(uint16_t port_id,
                                   enum rte_eth_event_type type OVS_UNUSED,
                                   void *param,
                                   void *ret_param OVS_UNUSED)
{
    struct netdev_dpdk_vdpa_relay *relay = param;
    struct rte_eth_link link;
    int q;

    rte_eth_link_get_nowait(port_id, &link);
    if (!link.link_status) {
        for (q = 0; q < NETDEV_DPDK_VDPA_MAX_QPAIRS; q++) {
            relay->qpair[q].pr_queue = NETDEV_DPDK_VDPA_INVALID_QUEUE_ID;
        }
        for (q = 0; q < RTE_MAX_QUEUES_PER_PORT; q++) {
            relay->flow_params.queues_en[q] = false;
        }
    }

    return 0;
}

static void
netdev_dpdk_vdpa_close_dev(struct netdev_dpdk_vdpa_relay *relay,
                           int port_id)
{
    rte_eth_dev_stop(port_id);
    if (rte_eth_dev_callback_unregister(port_id, RTE_ETH_EVENT_QUEUE_STATE,
                                        netdev_dpdk_vdpa_queue_state_cb_fn,
                                        relay)) {
        VLOG_ERR("rte_eth_dev_callback_unregister failed for port id %u"
                 "event type RTE_ETH_EVENT_QUEUE_STATE", port_id);
    }
    if (rte_eth_dev_callback_unregister(port_id, RTE_ETH_EVENT_INTR_LSC,
                                        netdev_dpdk_vdpa_link_status_cb_fn,
                                        relay)) {
        VLOG_ERR("rte_eth_dev_callback_unregister failed for port id %u"
                 "event type RTE_ETH_EVENT_INTR_LSC", port_id);
    }

    if (port_id == relay->port_id_vf) {
        if (relay->flow_params.flow != NULL) {
            struct rte_flow_error error;
            if (rte_flow_destroy(port_id, relay->flow_params.flow, &error)) {
                VLOG_ERR("rte_flow_destroy failed, Port id %u."
                         "rte flow destroy error: %u : message : %s",
                         port_id, error.type, error.message);
            }
        }
    }
    rte_eth_dev_close(port_id);
}

static int
netdev_dpdk_vdpa_port_init(struct netdev_dpdk_vdpa_relay *relay,
                           struct rte_mempool *mp,
                           enum netdev_dpdk_vdpa_port_type port_type)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    struct rte_eth_conf conf = {
            .rxmode = {
                .mq_mode = RTE_ETH_MQ_RX_RSS,
            },
            .txmode = {
                .mq_mode = RTE_ETH_MQ_TX_NONE,
            },
        };
    uint64_t csum_offloads, tso_offloads;
    bool csum_support, tso_support;
    uint16_t port = (port_type == NETDEV_DPDK_VDPA_PORT_TYPE_VM) ?
                     relay->port_id_vm : relay->port_id_vf;
    uint16_t q;
    int err = 0;

    if (!rte_eth_dev_is_valid_port(port)) {
        VLOG_ERR("rte_eth_dev_is_valid_port failed, invalid port %d", port);
        err = ENODEV;
        goto out;
    }
    if (relay->started) {
        rte_eth_dev_stop(port);
        relay->started = false;
    }
    rte_eth_dev_info_get(port, &dev_info);
    conf.rxmode.offloads = 0;

    conf.txmode.offloads = 0;
    if (port_type == NETDEV_DPDK_VDPA_PORT_TYPE_VF) {
        /* enable checksum and TSO for vf */
        csum_offloads = (RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
                         RTE_ETH_TX_OFFLOAD_TCP_CKSUM);
        tso_offloads = (RTE_ETH_TX_OFFLOAD_TCP_TSO |
                        RTE_ETH_TX_OFFLOAD_MULTI_SEGS);

        tso_support = (tso_offloads & dev_info.tx_offload_capa) ==
                       tso_offloads;
        csum_support = (csum_offloads & dev_info.tx_offload_capa) ==
                       csum_offloads;

        if ((!tso_support) || (!csum_support)) {
            VLOG_ERR("Device %s doesn't support needed features:%s%s",
                     rte_dev_name(dev_info.device),
                     tso_support ? "":" TSO offloads",
                     csum_support ? "":" checksum offloads");
            err = EINVAL;
            goto out;
        }

        conf.txmode.offloads |= (csum_offloads | tso_offloads);
    }

    err = rte_eth_dev_configure(port, relay->num_queues, relay->num_queues,
                                &conf);
    if (err < 0) {
        VLOG_ERR("rte_eth_dev_configure failed for port %d", port);
        goto out;
    }
    for (q = 0; q < relay->num_queues; q++) {
        err = rte_eth_rx_queue_setup(port, q,
                                     NETDEV_DPDK_VDPA_RX_DESC_DEFAULT,
                                     rte_eth_dev_socket_id(port),
                                     NULL, mp);
        if (err) {
            VLOG_ERR("rte_eth_rx_queue_setup failed for port %d, error %d",
                     port, err);
            goto dev_close;
        }
    }
    txconf = dev_info.default_txconf;
    txconf.offloads = conf.txmode.offloads;
    for (q = 0; q < relay->num_queues; q++) {
        err = rte_eth_tx_queue_setup(port, q,
                                     NETDEV_DPDK_VDPA_RX_DESC_DEFAULT,
                                     rte_eth_dev_socket_id(port),
                                     &txconf);
        if (err < 0) {
            VLOG_ERR("rte_eth_tx_queue_setup failed for port %d, error %d",
                     port, err);
            goto out;
        }
    }

    if (port_type == NETDEV_DPDK_VDPA_PORT_TYPE_VM) {
        err = netdev_dpdk_vdpa_queue_state(relay, port);
        if (err) {
            VLOG_ERR("netdev_dpdk_vdpa_queue_state failed for port %u", port);
            goto dev_close;
        }
    }

    err = rte_eth_dev_callback_register(port, RTE_ETH_EVENT_QUEUE_STATE,
                                        netdev_dpdk_vdpa_queue_state_cb_fn,
                                        relay);
    if (err < 0) {
        VLOG_ERR("rte_eth_dev_callback_register failed,"
                 "event QUEUE_STATE error %d", err);
        goto dev_close;
    }

    err = rte_eth_dev_callback_register(port, RTE_ETH_EVENT_INTR_LSC,
                                        netdev_dpdk_vdpa_link_status_cb_fn,
                                        relay);
    if (err < 0) {
        VLOG_ERR("rte_eth_dev_callback_register failed,"
                 "event INTR_LSC error %d", err);
        goto dev_close;
    }

    err = rte_eth_dev_start(port);
    if (err < 0) {
        VLOG_ERR("rte_eth_dev_start failed for port %d", port);
        goto dev_close;
    }
    relay->started = true;
    goto out;

dev_close:
    if (relay->started == true) {
        rte_eth_dev_stop(port);
        relay->started = false;
    }
    rte_eth_dev_close(port);
out:
    return err;
}

static void
netdev_dpdk_vdpa_parse_pkt(struct rte_mbuf *m, uint16_t mtu)
{
    const struct ovs_16aligned_ip6_frag *frag_hdr;
    const struct ovs_16aligned_ip6_hdr *ipv6;
    const struct vlan_header *vlan;
    const struct eth_header *eth;
    const struct ip_header *ipv4;
    const struct tcp_header *tcp;
    uint8_t nw_frag = 0;
    uint8_t l4_proto_id;
    uint64_t ol_flags;
    const void *data;
    uint32_t l2_len;
    uint32_t l3_len;
    uint32_t l4_len;
    ovs_be16 proto;
    size_t size;

    eth = rte_pktmbuf_mtod(m, const struct eth_header *);
    l2_len = sizeof *eth;
    vlan = (struct vlan_header *)(eth + 1);
    proto = eth->eth_type;

    while (eth_type_vlan(proto)) {
        l2_len += sizeof *vlan;
        proto = vlan->vlan_next_type;
        vlan++;
    }

    if ((rte_pktmbuf_pkt_len(m) - l2_len) <= mtu) {
        return;
    }

    switch (ntohs(proto)) {
    case ETH_TYPE_IP:
        ipv4 = (const struct ip_header *)vlan;
        l3_len = (ipv4->ip_ihl_ver & 0x0f) << 2;
        l4_proto_id = ipv4->ip_proto;
        if (l4_proto_id == IPPROTO_TCP) {
            tcp = ALIGNED_CAST(const struct tcp_header *,
                               ((char *)ipv4 + l3_len));
            l4_len = TCP_OFFSET(tcp->tcp_ctl) * 4;
            ol_flags = (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM);
        }
        break;
    case ETH_TYPE_IPV6:
        ipv6 = (const struct ovs_16aligned_ip6_hdr *)vlan;
        data = ipv6 + 1;
        size = rte_pktmbuf_data_len(m) - l2_len - sizeof *ipv6;
        l4_proto_id = ipv6->ip6_nxt;
        if (!parse_ipv6_ext_hdrs(&data, &size, &l4_proto_id, &nw_frag,
                                 &frag_hdr) || nw_frag) {
            return;
        }
        l3_len = (char *)data - (char *)ipv6;
        if (l4_proto_id == IPPROTO_TCP) {
            tcp = (const struct tcp_header *)data;
            l4_len = TCP_OFFSET(tcp->tcp_ctl) * 4;
            ol_flags = RTE_MBUF_F_TX_IPV6;
        }
        break;
    default:
        return;
    }

    if (l4_proto_id == IPPROTO_TCP) {
        ol_flags |= (RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_TCP_CKSUM);
        m->l2_len = l2_len;
        m->l3_len = l3_len;
        m->l4_len = l4_len;
        m->ol_flags = ol_flags;
        m->tso_segsz = mtu - l3_len - l4_len;
    }
}

static int
netdev_dpdk_vdpa_forward_traffic(struct netdev_dpdk_vdpa_qpair *qpair,
                                 uint16_t queue_id, uint16_t mtu)
{
    bool tx_vf = (queue_id & 1) ? true : false;
    uint16_t num_rx_packets = 0;
    uint8_t buffered_packets;
    uint16_t num_tx_packets;
    uint8_t num_packets;
    uint32_t fwd_rx = 0;
    int i;

    queue_id = queue_id >> 1;
    buffered_packets = qpair->mb_tail - qpair->mb_head;
    num_packets = buffered_packets;
    if (buffered_packets >= NETDEV_MAX_BURST) {
        goto send;
    }

    /* Allocate 2 * NETDEV_MAX_BURST packets entries to always allow a full
     * RX burst while not dropping any pending packets.
     * Move pending packets to the head of the array when there are not enough
     * consecutive entries for a full RX burst.
     */
    if (unlikely(qpair->mb_tail > NETDEV_MAX_BURST)) {
        rte_memcpy(&qpair->pkts[0], &qpair->pkts[qpair->mb_head],
                   num_packets * NETDEV_DPDK_VDPA_SIZEOF_MBUF);
        qpair->mb_head = 0;
        qpair->mb_tail = num_packets;
    }

    num_rx_packets = rte_eth_rx_burst(qpair->port_id_rx, queue_id,
                                      qpair->pkts + qpair->mb_tail,
                                      NETDEV_MAX_BURST);
    qpair->mb_tail += num_rx_packets;
    num_packets += num_rx_packets;
    fwd_rx += num_rx_packets;

send:
    if (tx_vf) {
        for (i = buffered_packets; i < num_packets; i++) {
             netdev_dpdk_vdpa_parse_pkt(qpair->pkts[qpair->mb_head + i], mtu);
        }
    }
    /* It is preferred to send a full burst of packets.
     * Send a partial burst only if no new packets were received during the
     * current poll iteration */
    if (((num_rx_packets == 0) && (num_packets > 0)) ||
        (num_packets > NETDEV_MAX_BURST)) {
        num_packets = MIN(num_packets,NETDEV_MAX_BURST);
    } else if (num_packets < NETDEV_MAX_BURST) {
        goto out;
    }

    num_tx_packets = rte_eth_tx_burst(qpair->port_id_tx, queue_id,
                                      qpair->pkts + qpair->mb_head,
                                      num_packets);
    qpair->mb_head += num_tx_packets;
    if (likely(qpair->mb_head == qpair->mb_tail)) {
        qpair->mb_head = 0;
        qpair->mb_tail = 0;
    }
out:
    return fwd_rx;
}

void *
netdev_dpdk_vdpa_alloc_relay(void)
{
    struct netdev_dpdk_vdpa_relay *relay;

    relay = rte_zmalloc("ovs_dpdk", sizeof(struct netdev_dpdk_vdpa_relay),
                        CACHE_LINE_SIZE);
    relay->vid = -1;
    ovs_mutex_init(&relay->lock);
    return relay;
}

int
netdev_dpdk_vdpa_rxq_recv_impl(struct netdev_dpdk_vdpa_relay *relay,
                               int pr_queue)
{
    uint32_t fwd_rx = 0;
    uint16_t q;

    if (!relay->started || relay->hw_mode == NETDEV_DPDK_VDPA_MODE_HW) {
        return 0;
    }
    /* Apply the multi core distribution policy by receiving only from queues
     * that are associated with the current port representor's queue. */
    for (q = 0; q < (relay->num_queues * 2); q++) {
        if (relay->qpair[q].pr_queue == pr_queue) {
            fwd_rx += netdev_dpdk_vdpa_forward_traffic(&relay->qpair[q], q,
                                                       relay->vf_mtu);
        } else if (relay->qpair[q].pr_queue ==
                   NETDEV_DPDK_VDPA_INVALID_QUEUE_ID) {
           break;
        }
    }
    return fwd_rx;
}

static int
netdev_dpdk_vdpa_new_device(int vid)
{
    char ifname[NETDEV_DPDK_VDPA_STATS_MAX_STR_SIZE];
    struct netdev_dpdk_vdpa_relay *relay;

    rte_vhost_get_ifname(vid, ifname, sizeof(ifname));
    ovs_mutex_lock(&relays_map_lock);
    relay = shash_find_data(&relays_map, ifname);
    ovs_mutex_unlock(&relays_map_lock);
    if (!relay) {
        VLOG_ERR("cannot find relay for ifname=%s", ifname);
        return -1;
    }
    relay->vid = vid;
    relay->started = true;
    VLOG_INFO("create device callback, vid=%d, ifname=%s", vid, ifname);

    return 0;
}

static void
netdev_dpdk_vdpa_destroy_device(int vid)
{
    char ifname[NETDEV_DPDK_VDPA_STATS_MAX_STR_SIZE];
    struct netdev_dpdk_vdpa_relay *relay;

    rte_vhost_get_ifname(vid, ifname, sizeof(ifname));
    ovs_mutex_lock(&relays_map_lock);
    relay = shash_find_data(&relays_map, ifname);
    ovs_mutex_unlock(&relays_map_lock);
    if (!relay) {
        VLOG_ERR("cannot find relay for vid=%d", vid);
        return;
    }
    ovs_mutex_lock(&relay->lock);
    relay->started = false;
    relay->vid = -1;
    ovs_mutex_unlock(&relay->lock);
    VLOG_INFO("destroy device callback, vid=%d, ifname=%s", vid,
              relay->vhost_name);
}

static const struct rte_vhost_device_ops netdev_dpdk_vdpa_sample_devops = {
        .new_device = netdev_dpdk_vdpa_new_device,
        .destroy_device = netdev_dpdk_vdpa_destroy_device,
};

static int
bus_name_cmp(const struct rte_bus *bus, const void *name)
{
    const char *bus_name = rte_bus_name(bus);

    return strncmp(bus_name, name, strlen(bus_name));
}

static bool
netdev_dpdk_vdpa_is_same_dev(const char *vf_devargs, const char *dev_name)
{
    size_t len;
    char *p;

    p = strstr(vf_devargs, dev_name);
    if (!p) {
        return false;
    }
    len = strlen(dev_name);
    /* The name ends with at least one devarg (class=vdpa). Check for end of
     * string or the delimiter is ','.
     */
    if (p[len] == '\0' || p[len] == ',') {
        return true;
    }
    return false;
}

static int
netdev_dpdk_vdpa_config_hw_impl(struct netdev_dpdk_vdpa_relay *relay)
{
    struct rte_dev_iterator dev_iter;
    struct rte_pci_addr pci_addr;
    const char *vhost_path;
    char *vf_devargs;
    char *comma;
    bool is_pci;
    int err;

    vf_devargs = xstrdup(relay->vf_devargs);
    vhost_path = relay->vm_socket;

    /* If bus is not explicitly provided, choose "pci"/"auxiliary" based
     * on provided string. */
    if (!rte_bus_find(NULL, bus_name_cmp, vf_devargs)) {
        /* If provided devargs, need to omit them for the pci check. */
        comma = strchr(vf_devargs, ',');
        if (comma) {
            *comma = '\0';
            is_pci = !rte_pci_addr_parse(vf_devargs, &pci_addr);
            *comma = ',';
        } else {
            is_pci = !rte_pci_addr_parse(vf_devargs, &pci_addr);
        }

        /* If not PCI, implicitly add auxiliary. */
        if (!is_pci) {
            char *new_vf_devargs;

            new_vf_devargs = xasprintf("auxiliary:%s", vf_devargs);
            free(vf_devargs);
            vf_devargs = new_vf_devargs;
        }
    }

    /* If not explicitly provided, add class=vdpa devarg. */
    if (!strstr(vf_devargs, ",class=vdpa")) {
        vf_devargs = xrealloc(vf_devargs, strlen(vf_devargs) +
                              strlen(",class=vdpa") + 1);
        strcat(vf_devargs, ",class=vdpa");
    }

    err = rte_dev_probe(vf_devargs);
    VLOG_INFO("Probe for VDPA device '%s'. User conf '%s'", vf_devargs,
              relay->vf_devargs);
    if (err) {
        VLOG_ERR("Failed to probe for VDPA device %s, working in SW mode",
                 vf_devargs);
        goto err_probe;
    }

    RTE_DEV_FOREACH (relay->rte_dev, "class=vdpa", &dev_iter) {
        const char *dev_name = rte_dev_name(relay->rte_dev);

        relay->vdpa_dev = rte_vdpa_find_device_by_name(dev_name);
        if (!relay->vdpa_dev) {
            VLOG_ERR("Failed to find vdpa device id for %s, working in SW "
                     "mode", dev_name);
            goto err_probe;
        }
        if (netdev_dpdk_vdpa_is_same_dev(vf_devargs, dev_name)) {
            break;
        }
        relay->vdpa_dev = NULL;
    }
    if (!relay->vdpa_dev) {
        VLOG_ERR("Failed to find vdpa device id for %s, working in SW mode",
                 rte_dev_name(relay->rte_dev));
        goto err_probe;
    }

    err = rte_vhost_driver_register(vhost_path, RTE_VHOST_USER_CLIENT);
    if (err) {
        VLOG_ERR("rte_vhost_driver_register failed, working in SW mode");
        goto err_find;
    }

    err = rte_vhost_driver_callback_register(vhost_path,
            &netdev_dpdk_vdpa_sample_devops);
    if (err) {
        VLOG_ERR("rte_vhost_driver_callback_register failed,"
                 "working in SW mode");
        goto err_cb_reg;
    }

    err = rte_vhost_driver_attach_vdpa_device(vhost_path, relay->vdpa_dev);
    if (err) {
        VLOG_ERR("Failed to attach vdpa device, working in SW mode");
        goto err_cb_reg;
    }

    err = rte_vhost_driver_start(vhost_path);
    if (err) {
        VLOG_ERR("Failed to start vhost driver: %s, working in SW mode",
                vhost_path);
        goto err_start;
    }

    netdev_dpdk_vdpa_free(relay->vhost_name);
    relay->vhost_name = xstrdup(vhost_path);
    relays_map_add(relay);
    relay->hw_mode = NETDEV_DPDK_VDPA_MODE_HW;
    goto out;

err_start:
    if (rte_vhost_driver_detach_vdpa_device(vhost_path)) {
        VLOG_ERR("Failed to detach vdpa device: %s", relay->vm_socket);
    }
err_cb_reg:
    if (rte_vhost_driver_unregister(relay->vm_socket)) {
        VLOG_ERR("Failed to unregister vhost driver for %s", relay->vm_socket);
    }
err_find:
    if (rte_dev_remove(relay->rte_dev)) {
        VLOG_ERR("Failed to rte_dev_remove %p", relay->vdpa_dev);
    }
err_probe:
    relay->hw_mode = NETDEV_DPDK_VDPA_MODE_SW;

out:
    free(vf_devargs);
    return err;
}

int
netdev_dpdk_vdpa_config_impl(struct netdev_dpdk_vdpa_relay *relay,
                             uint16_t port_id,
                             const char *vm_socket,
                             const char *vf_devargs,
                             int max_queues,
                             bool hw_mode)
{
    char *vhost_args;
    uint16_t q;
    int err = 0;

    /* if fwd_config already been done, don't run it again */
    if (relay->hw_mode != NETDEV_DPDK_VDPA_MODE_INIT) {
        goto out;
    }
    else {
        relay->vm_socket = xstrdup(vm_socket);
        relay->vf_devargs = xstrdup(vf_devargs);
        if (hw_mode) {
            err = netdev_dpdk_vdpa_config_hw_impl(relay);
            if (relay->hw_mode == NETDEV_DPDK_VDPA_MODE_HW) {
                goto out;
            }
        } else {
            relay->hw_mode = NETDEV_DPDK_VDPA_MODE_SW;
        }
    }

    if (max_queues < 0) {
        max_queues = NETDEV_DPDK_VDPA_MAX_QPAIRS;
    }

    relay->vhost_name = xasprintf("net_vhost%d",port_id);
    vhost_args = xasprintf("iface=%s,queues=%d,client=1",
                           relay->vm_socket, max_queues);

    /* create virtio vdev:*/
    err = rte_eal_hotplug_add("vdev", relay->vhost_name, vhost_args);
    if (err) {
        VLOG_ERR("rte_eal_hotplug_add failed for vdev, socket %s",
                 relay->vm_socket);
        goto err_clear_relay;
    }
    relay->port_id_vm = netdev_dpdk_vdpa_port_from_name(relay->vhost_name);
    if (relay->port_id_vm < 0) {
        VLOG_ERR("No port id was found for vm %s", relay->vhost_name);
        err = ENODEV;
        goto err_clear_vdev;
    }

    /* create vf:*/
    err = rte_eal_hotplug_add("pci", relay->vf_devargs, "");
    if (err) {
        VLOG_ERR("rte_eal_hotplug_add failed for pci %s", relay->vf_devargs);
        goto err_clear_vdev;
    }
    relay->port_id_vf = netdev_dpdk_vdpa_port_from_name(relay->vf_devargs);
    if (relay->port_id_vf < 0) {
        VLOG_ERR("No port id was found for vf %s", relay->vf_devargs);
        err = ENODEV;
        goto err_clear_vf;
    }

    relay->num_queues = max_queues;
    relay->flow_params.priority = 0;
    relay->flow_params.flow = NULL;
    memset(relay->flow_params.queues_en, false,
           sizeof(bool) * RTE_MAX_QUEUES_PER_PORT);

    for (q = 0; q < (relay->num_queues * 2); q++) {
        relay->qpair[q].pr_queue = NETDEV_DPDK_VDPA_INVALID_QUEUE_ID;
        if (q & 1) {
            relay->qpair[q].port_id_rx = relay->port_id_vm;
            relay->qpair[q].port_id_tx = relay->port_id_vf;
        } else {
            relay->qpair[q].port_id_rx = relay->port_id_vf;
            relay->qpair[q].port_id_tx = relay->port_id_vm;
        }
        relay->qpair[q].mb_head = 0;
        relay->qpair[q].mb_tail = 0;
    }

    goto out_clear;

err_clear_vf:
    rte_eal_hotplug_remove("pci", relay->vf_devargs);
err_clear_vdev:
    rte_eal_hotplug_remove("vdev", relay->vhost_name);
err_clear_relay:
    netdev_dpdk_vdpa_clear_relay(relay);
out_clear:
    netdev_dpdk_vdpa_free(vhost_args);
out:
    return err;
}

int
netdev_dpdk_vdpa_update_relay(struct netdev_dpdk_vdpa_relay *relay,
                              struct rte_mempool *mp,
                              int n_rxq)
{
    uint16_t mtu;
    int err = 0;

    if (relay->hw_mode == NETDEV_DPDK_VDPA_MODE_HW) {
        return err;
    }

    err = rte_eth_dev_get_mtu(relay->port_id_vf, &mtu);
    if (err < 0) {
        mtu = RTE_ETHER_MTU;
        err = 0;
    }
    relay->vf_mtu = mtu;
    relay->n_rxq = n_rxq;

    /* port init vf */
    err = netdev_dpdk_vdpa_port_init(relay, mp,
                                     NETDEV_DPDK_VDPA_PORT_TYPE_VF);
    if (err) {
        VLOG_ERR("port_init failed for port_id %u", relay->port_id_vf);
        goto clear_relay;
    }

    /* port init vm */
    err = netdev_dpdk_vdpa_port_init(relay, mp,
                                     NETDEV_DPDK_VDPA_PORT_TYPE_VM);
    if (err) {
        VLOG_ERR("port_init failed for port_id %u", relay->port_id_vm);
        goto vf_close;
    }

    goto out;

vf_close:
    rte_eth_dev_stop(relay->port_id_vf);
    rte_eth_dev_close(relay->port_id_vf);
clear_relay:
    rte_eal_hotplug_remove("pci", relay->vf_devargs);
    rte_eal_hotplug_remove("vdev", relay->vhost_name);
    netdev_dpdk_vdpa_clear_relay(relay);
out:
    return err;
}

static void
netdev_dpdk_hw_vdpa_destruct(struct netdev_dpdk_vdpa_relay *relay)
{
    relay->started = false;
    if (rte_vhost_driver_detach_vdpa_device(relay->vm_socket)) {
        VLOG_ERR("Failed to detach vdpa device: %s", relay->vm_socket);
    }

    if (rte_vhost_driver_unregister(relay->vm_socket)) {
        VLOG_ERR("Failed to unregister vhost driver for %s", relay->vm_socket);
    }
    relay->hw_mode = NETDEV_DPDK_VDPA_MODE_INIT;
    relays_map_remove(relay);
    rte_dev_remove(relay->rte_dev);
    netdev_dpdk_vdpa_free_relay_strings(relay);
}

void
netdev_dpdk_vdpa_destruct_impl(struct netdev_dpdk_vdpa_relay *relay)
{
    if (relay->hw_mode == NETDEV_DPDK_VDPA_MODE_HW) {
        netdev_dpdk_hw_vdpa_destruct(relay);
        return;
    }

    if (!(rte_eth_dev_is_valid_port(relay->port_id_vm))) {
        goto destruct_vf;
    }
    netdev_dpdk_vdpa_close_dev(relay, relay->port_id_vm);
    rte_eal_hotplug_remove("vdev", relay->vhost_name);

destruct_vf:
    if (!(rte_eth_dev_is_valid_port(relay->port_id_vf))) {
        goto out;
    }
    netdev_dpdk_vdpa_close_dev(relay, relay->port_id_vf);
    rte_eal_hotplug_remove("pci", relay->vf_devargs);

out:
    netdev_dpdk_vdpa_clear_relay(relay);
    netdev_dpdk_vdpa_free_relay_strings(relay);
}

static
void netdev_dpdk_vdpa_get_sw_stats(struct netdev_dpdk_vdpa_relay *relay,
                                   struct netdev_custom_stats *cstm_stats)
{
    enum stats_vals {
        VDPA_CUSTOM_STATS_HW_MODE,
        VDPA_CUSTOM_STATS_VM_RX_PACKETS,
        VDPA_CUSTOM_STATS_VM_RX_BYTES,
        VDPA_CUSTOM_STATS_VM_TX_PACKETS,
        VDPA_CUSTOM_STATS_VM_TX_BYTES,
        VDPA_CUSTOM_STATS_VF_RX_PACKETS,
        VDPA_CUSTOM_STATS_VF_RX_BYTES,
        VDPA_CUSTOM_STATS_VF_RX_ERRS,
        VDPA_CUSTOM_STATS_VF_RX_NOBUF,
        VDPA_CUSTOM_STATS_VF_RX_MISS,
        VDPA_CUSTOM_STATS_VF_TX_PACKETS,
        VDPA_CUSTOM_STATS_VF_TX_BYTES,
        VDPA_CUSTOM_STATS_VF_TX_ERRS,
        VDPA_CUSTOM_STATS_TOTAL_SIZE
    };
    const char *stats_names[] = {
        [VDPA_CUSTOM_STATS_HW_MODE] = "HW mode",
        [VDPA_CUSTOM_STATS_VM_RX_PACKETS] = "VM_rx_packets",
        [VDPA_CUSTOM_STATS_VM_RX_BYTES] = "VM_rx_bytes",
        [VDPA_CUSTOM_STATS_VM_TX_PACKETS] = "VM_tx_packets",
        [VDPA_CUSTOM_STATS_VM_TX_BYTES] = "VM_tx_bytes",
        [VDPA_CUSTOM_STATS_VF_RX_PACKETS] = "VF_rx_packets",
        [VDPA_CUSTOM_STATS_VF_RX_BYTES] = "VF_rx_bytes",
        [VDPA_CUSTOM_STATS_VF_RX_ERRS] = "VF_rx_errors",
        [VDPA_CUSTOM_STATS_VF_RX_NOBUF] = "VF_rx_no_mbuf",
        [VDPA_CUSTOM_STATS_VF_RX_MISS] = "VF_rx_miss",
        [VDPA_CUSTOM_STATS_VF_TX_PACKETS] = "VF_tx_packets",
        [VDPA_CUSTOM_STATS_VF_TX_BYTES] = "VF_tx_bytes",
        [VDPA_CUSTOM_STATS_VF_TX_ERRS] = "VF_tx_errors"
    };
    struct rte_eth_stats rte_stats;
    uint16_t i;
    uint16_t num_q = relay->num_queues;
    uint16_t start = 0;

    cstm_stats->size = VDPA_CUSTOM_STATS_TOTAL_SIZE + 9 * num_q;
    cstm_stats->counters = xcalloc(cstm_stats->size,
                                   sizeof *cstm_stats->counters);

    for (i = 0; i < VDPA_CUSTOM_STATS_TOTAL_SIZE; i++) {
        ovs_strlcpy(cstm_stats->counters[i].name, stats_names[i],
                    NETDEV_CUSTOM_STATS_NAME_SIZE);
    }

    if (rte_eth_stats_get(relay->port_id_vm, &rte_stats)) {
        VLOG_ERR("rte_eth_stats_get failed."
                 "Can't get ETH statistics for port id %u",
                 relay->port_id_vm);
        return;
    }
    cstm_stats->counters[VDPA_CUSTOM_STATS_VM_RX_PACKETS].value =
                                                    rte_stats.ipackets;
    cstm_stats->counters[VDPA_CUSTOM_STATS_VM_RX_BYTES].value =
                                                    rte_stats.ibytes;
    cstm_stats->counters[VDPA_CUSTOM_STATS_VM_TX_PACKETS].value =
                                                    rte_stats.opackets;
    cstm_stats->counters[VDPA_CUSTOM_STATS_VM_TX_BYTES].value =
                                                    rte_stats.obytes;

    start = start + VDPA_CUSTOM_STATS_TOTAL_SIZE;
    for (i = 0; i < num_q; i++) {
         snprintf(cstm_stats->counters[i * 2 + start].name,
                  NETDEV_CUSTOM_STATS_NAME_SIZE, "VM_rxq%u_pkts", i);
         snprintf(cstm_stats->counters[i * 2 + 1 + start].name,
                  NETDEV_CUSTOM_STATS_NAME_SIZE, "VM_rxq%u_bytes", i);

         if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
             cstm_stats->counters[i * 2 + start].value =
                                              rte_stats.q_ipackets[i];
             cstm_stats->counters[i * 2 + 1 + start].value =
                                              rte_stats.q_ibytes[i];
         }
    }

    start = start + 2 * num_q;
    for (i = 0; i < num_q; i++) {
         snprintf(cstm_stats->counters[i * 2 + start].name,
                  NETDEV_CUSTOM_STATS_NAME_SIZE, "VM_txq%u_pkts", i);
         snprintf(cstm_stats->counters[i * 2 + 1 + start].name,
                  NETDEV_CUSTOM_STATS_NAME_SIZE, "VM_txq%u_bytes", i);
         if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
             cstm_stats->counters[i * 2 + start].value =
                                              rte_stats.q_opackets[i];
             cstm_stats->counters[i * 2 + 1 + start].value =
                                              rte_stats.q_obytes[i];
         }
    }

    if (rte_eth_stats_get(relay->port_id_vf, &rte_stats)) {
        VLOG_ERR("rte_eth_stats_get failed."
                 "Can't get ETH statistics for port id %u",
                 relay->port_id_vf);
        return;
    }
    cstm_stats->counters[VDPA_CUSTOM_STATS_VF_RX_PACKETS].value =
                                                    rte_stats.ipackets;
    cstm_stats->counters[VDPA_CUSTOM_STATS_VF_RX_BYTES].value =
                                                    rte_stats.ibytes;
    cstm_stats->counters[VDPA_CUSTOM_STATS_VF_RX_ERRS].value =
                                                    rte_stats.ierrors;
    cstm_stats->counters[VDPA_CUSTOM_STATS_VF_RX_NOBUF].value =
                                                    rte_stats.rx_nombuf;
    cstm_stats->counters[VDPA_CUSTOM_STATS_VF_RX_MISS].value =
                                                    rte_stats.imissed;
    cstm_stats->counters[VDPA_CUSTOM_STATS_VF_TX_PACKETS].value =
                                                    rte_stats.opackets;
    cstm_stats->counters[VDPA_CUSTOM_STATS_VF_TX_BYTES].value =
                                                    rte_stats.obytes;
    cstm_stats->counters[VDPA_CUSTOM_STATS_VF_TX_ERRS].value =
                                                    rte_stats.oerrors;

    start = start + 2 * num_q;
    for (i = 0; i < num_q; i++) {
         snprintf(cstm_stats->counters[i * 3 + start].name,
                  NETDEV_CUSTOM_STATS_NAME_SIZE, "VF_rxq%u_pkts", i);
         snprintf(cstm_stats->counters[i * 3 + 1 + start].name,
                  NETDEV_CUSTOM_STATS_NAME_SIZE, "VF_rxq%u_bytes", i);
         snprintf(cstm_stats->counters[i * 3 + 2 + start].name,
                  NETDEV_CUSTOM_STATS_NAME_SIZE, "VF_rxq%u_errors", i);

         if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
             cstm_stats->counters[i * 3 + start].value =
                                              rte_stats.q_ipackets[i];
             cstm_stats->counters[i * 3 + 1 + start].value =
                                              rte_stats.q_ibytes[i];
             cstm_stats->counters[i * 3 + 2 + start].value =
                                              rte_stats.q_errors[i];
         }
    }

    start = start + 3 * num_q;
    for (i = 0; i < num_q; i++) {
         snprintf(cstm_stats->counters[i * 2 + start].name,
                  NETDEV_CUSTOM_STATS_NAME_SIZE, "VF_txq%u_pkts", i);
         snprintf(cstm_stats->counters[i * 2 + 1 + start].name,
                  NETDEV_CUSTOM_STATS_NAME_SIZE, "VF_txq%u_bytes", i);
         if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
             cstm_stats->counters[i * 2 + start].value =
                                              rte_stats.q_opackets[i];
             cstm_stats->counters[i * 2 + 1 + start].value =
                                              rte_stats.q_obytes[i];
         }
    }

    cstm_stats->counters[VDPA_CUSTOM_STATS_HW_MODE].value = 0;
}

static
void netdev_dpdk_vdpa_get_hw_stats(struct netdev_dpdk_vdpa_relay *relay,
                                   struct netdev_custom_stats *cstm_stats)
{
    enum stats_vals {
        VDPA_CUSTOM_STATS_HW_MODE,
        VDPA_CUSTOM_STATS_PACKETS,
        VDPA_CUSTOM_STATS_ERRORS,
        VDPA_CUSTOM_STATS_TOTAL_SIZE
    };
    const char *stats_names[] = {
        [VDPA_CUSTOM_STATS_HW_MODE] = "HW mode",
        [VDPA_CUSTOM_STATS_PACKETS] = "Packets",
        [VDPA_CUSTOM_STATS_ERRORS] = "Errors"
    };
    struct rte_vdpa_device *vdev = relay->vdpa_dev;
    struct rte_vdpa_stat_name *vdpa_stats_names;
    char name[NETDEV_CUSTOM_STATS_NAME_SIZE];
    uint16_t q, num_q, i, counter, index;
    struct rte_vdpa_stat *stats;
    int stats_n;

    if (!vdev) {
        VLOG_ERR("Failed to find vdpa device id for %s", relay->vf_devargs);
        return;
    }

    stats_n = rte_vdpa_get_stats_names(vdev, NULL, 0);
    if (stats_n <= 0) {
        VLOG_ERR("Failed to get names number of device %s.",
                 relay->vf_devargs);
        return;
    }

    vdpa_stats_names = rte_zmalloc(NULL, sizeof(*vdpa_stats_names) * stats_n,
                                   0);
    if (!vdpa_stats_names) {
        VLOG_ERR("Failed to allocate memory for stats names of device %s.",
                 relay->vf_devargs);
        return;
    }

    i = rte_vdpa_get_stats_names(vdev, vdpa_stats_names, stats_n);
    if (stats_n != i) {
        VLOG_ERR("Failed to get names of device %s.", relay->vf_devargs);
        goto err_names;
    }

    stats = rte_zmalloc(NULL, sizeof(*stats) * stats_n, 0);
    if (!stats) {
        VLOG_ERR("Failed to allocate memory for stats of device %s.",
                 relay->vf_devargs);
        goto err_names;
    }

    num_q = rte_vhost_get_vring_num(relay->vid);
    if (num_q == 0) {
        VLOG_ERR("Failed to get num of actual virtqs for device %s.",
                 relay->vf_devargs);
        goto err_stats;
    }

    cstm_stats->size = 2 * num_q + 1;
    cstm_stats->counters = xcalloc(cstm_stats->size,
                                   sizeof *cstm_stats->counters);

    for (q = 0; q < num_q; q++) {
        int ret = rte_vdpa_get_stats(vdev, q, stats, stats_n);

        if (ret == 0) {
            continue;
        } else if (ret < 0) {
            VLOG_ERR("Failed to get vdpa queue statistics for device %s "
                     "queue %d.", relay->vf_devargs, q);
            break;
        }

        for (i = 0; i < stats_n; ++i) {
            counter = 0;
            if (!strncmp(vdpa_stats_names[stats[i].id].name,
                         "completed_descriptors", RTE_VDPA_STATS_NAME_SIZE)) {
                index = VDPA_CUSTOM_STATS_PACKETS;
                counter = q * 2 + 1;
            } else if (!strncmp(vdpa_stats_names[stats[i].id].name,
                       "completion errors", RTE_VDPA_STATS_NAME_SIZE)) {
                index = VDPA_CUSTOM_STATS_ERRORS;
                counter = q * 2 + 1 + 1;
            }

            if (counter > 0) {
                snprintf(name, NETDEV_CUSTOM_STATS_NAME_SIZE, "%s queue_%u_%s",
                         stats_names[index], q / 2,
                         q % 2 == 0 ? "rx" : "tx");
                ovs_strlcpy(cstm_stats->counters[counter].name, name,
                            NETDEV_CUSTOM_STATS_NAME_SIZE);
                cstm_stats->counters[counter].value = stats[i].value;
            }
        }
    }

    ovs_strlcpy(cstm_stats->counters[VDPA_CUSTOM_STATS_HW_MODE].name,
                stats_names[VDPA_CUSTOM_STATS_HW_MODE],
                NETDEV_CUSTOM_STATS_NAME_SIZE);
    cstm_stats->counters[VDPA_CUSTOM_STATS_HW_MODE].value = 1;

err_stats:
    rte_free(stats);
err_names:
    rte_free(vdpa_stats_names);
}

static
void netdev_dpdk_vdpa_get_offline_stats(struct netdev_dpdk_vdpa_relay *relay,
                                        struct netdev_custom_stats *cstm_stats)
{
    enum stats_vals {
        VDPA_CUSTOM_STATS_HW_MODE,
        VDPA_CUSTOM_STATS_DISCONNECTED,
        VDPA_CUSTOM_STATS_TOTAL_SIZE
    };
    const char *stats_names[] = {
        [VDPA_CUSTOM_STATS_HW_MODE] = "HW mode",
        [VDPA_CUSTOM_STATS_DISCONNECTED] = "Disconnected",
    };

    cstm_stats->size = VDPA_CUSTOM_STATS_TOTAL_SIZE;
    cstm_stats->counters = xcalloc(cstm_stats->size,
                                   sizeof *cstm_stats->counters);

    ovs_strlcpy(cstm_stats->counters[VDPA_CUSTOM_STATS_HW_MODE].name,
                stats_names[VDPA_CUSTOM_STATS_HW_MODE],
                NETDEV_CUSTOM_STATS_NAME_SIZE);
    if (relay->hw_mode == NETDEV_DPDK_VDPA_MODE_HW) {
        cstm_stats->counters[VDPA_CUSTOM_STATS_HW_MODE].value = 1;
    } else {
        cstm_stats->counters[VDPA_CUSTOM_STATS_HW_MODE].value = 0;
    }

    ovs_strlcpy(cstm_stats->counters[VDPA_CUSTOM_STATS_DISCONNECTED].name,
                stats_names[VDPA_CUSTOM_STATS_DISCONNECTED],
                NETDEV_CUSTOM_STATS_NAME_SIZE);
    cstm_stats->counters[VDPA_CUSTOM_STATS_DISCONNECTED].value = 1;
}

int
netdev_dpdk_vdpa_get_custom_stats_impl(struct netdev_dpdk_vdpa_relay *relay,
                                       struct netdev_custom_stats *cstm_stats,
                                       struct ovs_mutex *dev_mutex,
                                       const struct netdev *netdev,
                                       int (*cb)(const struct netdev *,
                                                 struct netdev_custom_stats *))
{
    struct netdev_custom_stats rep_cstm_stats;
    struct netdev_custom_counter *add_counter;
    uint16_t i;

    ovs_mutex_lock(dev_mutex);
    if (ovs_mutex_trylock(&relay->lock)) {
        if (cb) {
            cb(netdev, cstm_stats);
        }
        ovs_mutex_unlock(dev_mutex);
        return 0;
    }

    if (!relay->started) {
        netdev_dpdk_vdpa_get_offline_stats(relay, cstm_stats);
    } else if (relay->hw_mode == NETDEV_DPDK_VDPA_MODE_HW) {
        netdev_dpdk_vdpa_get_hw_stats(relay, cstm_stats);
    } else {
        netdev_dpdk_vdpa_get_sw_stats(relay, cstm_stats);
    }
    ovs_mutex_unlock(&relay->lock);
    ovs_mutex_unlock(dev_mutex);

    if (cb) {
        memset(&rep_cstm_stats, 0, sizeof rep_cstm_stats);
        cb(netdev, &rep_cstm_stats);
        cstm_stats->counters =
            xrealloc(cstm_stats->counters,
                     (cstm_stats->size + rep_cstm_stats.size) *
                     sizeof *cstm_stats->counters);
        add_counter = &cstm_stats->counters[cstm_stats->size];
        cstm_stats->size += rep_cstm_stats.size;
        for (i = 0; i < rep_cstm_stats.size; i++, add_counter++) {
            add_counter->value = rep_cstm_stats.counters[i].value;
            ovs_strlcpy(add_counter->name, rep_cstm_stats.counters[i].name,
                        NETDEV_CUSTOM_STATS_NAME_SIZE);
        }
        netdev_free_custom_stats_counters(&rep_cstm_stats);
    }
    return 0;
}
