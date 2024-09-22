/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#include <linux/pkt_cls.h>
#include "include/xdp/parsing_helpers.h"

#include "neighsnoopd_shared.h"

#define ND_NEIGHBOR_ADVERT          136
#define ND_OPT_MAX_CHAIN            3
#define ND_OPT_TARGET_LINKADDR      2

struct nd_opt_hdr {
    __u8 nd_opt_type;
    __u8 nd_opt_len; // Length in units of 8 octets
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB
} neighbor_ringbuf SEC(".maps");

// Find ND Option Header of specified type
static __always_inline int find_nd_opt(struct hdr_cursor *nh,
                                       void *data_end,
                                       __u8 next_hdr_type)
{
    for (int i = 0; i < ND_OPT_MAX_CHAIN; ++i) {
        struct nd_opt_hdr *hdr = nh->pos;

        if ((void *)(hdr + 1) > data_end)
            return -1;

        if (((void *)hdr) + hdr->nd_opt_len * 8 > data_end)
            return -1;

        switch (hdr->nd_opt_type) {
            case ND_OPT_TARGET_LINKADDR:
                return 0;
            default:
                nh->pos = ((void *)hdr) + hdr->nd_opt_len * 8;
        }
    }

    return -1;
}

static __always_inline struct neighbor_reply *handle_nd_reply(
    struct hdr_cursor *nh, void *data_end, struct ethhdr *eth)
{
    struct neighbor_reply *neighbor_reply = NULL;
    struct ipv6hdr *ip;
    struct icmp6hdr *icmp6;
    struct in6_addr *target_ipv6;
    struct nd_opt_hdr *nd_opt_hdr;
    __u8 *target_mac;

    // Parse the IPv6 header
    if (parse_ip6hdr(nh, data_end, &ip) != IPPROTO_ICMPV6)
        goto out;

    // Check if the message is a Neighbor Advertisement
    if (parse_icmp6hdr(nh, data_end, &icmp6) != ND_NEIGHBOR_ADVERT)
        goto out;

    if ((void *)(icmp6 + 1) > data_end)
        goto out;
    nh->pos = icmp6 + 1;

    // Check if the message is long enough to contain the target IPv6 address
    target_ipv6 = nh->pos;
    if ((void *)(target_ipv6 + 1) > data_end)
        goto out;
    nh->pos = target_ipv6 + 1;

    // Parse options to find the Source Link-Layer Address (MAC address)
    if (find_nd_opt(nh, data_end, ND_OPT_TARGET_LINKADDR)) {
        target_mac = eth->h_source;
    } else {
        nd_opt_hdr = nh->pos;

        if ((void *)(nd_opt_hdr + 1) > data_end)
            goto out;

        target_mac = (void *)(nd_opt_hdr + 1);

        if ((void *)(target_mac + ETH_ALEN) > data_end)
            goto out;
    }

    // Add the data to the ringbuffer
    neighbor_reply = bpf_ringbuf_reserve(&neighbor_ringbuf,
                                         sizeof(*neighbor_reply), 0);
    if (!neighbor_reply)
        goto out;

    __builtin_memcpy(neighbor_reply->mac, target_mac, ETH_ALEN);
    __builtin_memcpy(&neighbor_reply->ip, target_ipv6, sizeof(*target_ipv6));

    neighbor_reply->in_family = AF_INET6;

out:
    return neighbor_reply;
}

static __always_inline struct neighbor_reply *handle_arp_reply(
    struct hdr_cursor *nh, void *data_end)
{
    struct neighbor_reply *neighbor_reply = NULL;
    struct arphdr *arp;
    __u8 *sender_ip;
    __u8 *sender_mac;

    if (nh->pos + sizeof(struct arphdr) > data_end)
        goto out;

    arp = nh->pos;
    if (arp->ar_op != bpf_htons(ARPOP_REPLY))
        goto out;

    // Extract IPv4 and MAC addresses
    sender_mac = (__u8 *)(arp + 1);
    if (sender_mac + 6 > (__u8 *)data_end)
        goto out;

    sender_ip = sender_mac + arp->ar_hln;
    if (sender_ip + 4 > (__u8 *)data_end)
        goto out;

    // Add the data to the ringbuffer
    neighbor_reply = bpf_ringbuf_reserve(&neighbor_ringbuf,
                                         sizeof(*neighbor_reply), 0);
    if (!neighbor_reply)
        goto out;

    __builtin_memcpy(neighbor_reply->mac, sender_mac, ETH_ALEN);
    map_ipv4_to_ipv6(&neighbor_reply->ip, *(__be32 *)sender_ip);

    neighbor_reply->in_family = AF_INET;

out:
    return neighbor_reply;
}

static __always_inline struct neighbor_reply *handle_neighbor_reply(
    void *data, void *data_end)
{
    struct neighbor_reply *neighbor_reply = NULL;
    struct collect_vlans vlans = { 0 };
    struct ethhdr *eth;
    int eth_type;
    struct hdr_cursor nh;
    nh.pos = data;

    eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
    if (eth_type == bpf_htons(ETH_P_IPV6))
        neighbor_reply = handle_nd_reply(&nh, data_end, eth);
    else if (eth_type == bpf_htons(ETH_P_ARP))
        neighbor_reply = handle_arp_reply(&nh, data_end);
    else
        goto out;

    if (!neighbor_reply)
        goto out;

    neighbor_reply->vlan_id = vlans.id[0];

out:
    return neighbor_reply;
}

SEC("xdp")
int handle_neighbor_reply_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(unsigned long long)ctx->data_end;
    void *data = (void *)(unsigned long long)ctx->data;

    struct neighbor_reply *neighbor_reply = handle_neighbor_reply(data,
                                                                  data_end);

    if (!neighbor_reply)
        goto out;

    neighbor_reply->ingress_ifindex = ctx->ingress_ifindex;

    // Send the data to userspace
    bpf_ringbuf_submit(neighbor_reply, 0);
out:
    return XDP_PASS;
}

SEC("tc")
int handle_neighbor_reply_tc(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct neighbor_reply *neighbor_reply = handle_neighbor_reply(data,
                                                                  data_end);

    if (!neighbor_reply)
        goto out;

    neighbor_reply->ingress_ifindex = skb->ifindex;

    neighbor_reply->vlan_id = skb->vlan_present ? skb->vlan_tci
        & VLAN_VID_MASK : 0;

    // Send the data to userspace
    bpf_ringbuf_submit(neighbor_reply, 0);
out:
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
