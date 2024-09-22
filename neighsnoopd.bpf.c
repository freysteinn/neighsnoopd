/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 1984 <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 Freyx Solutions <frey@freyx.com> */
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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB
} arp_ringbuf SEC(".maps");

static __always_inline struct arp_reply *handle_arp_reply(
    void *data, void *data_end)
{
        struct collect_vlans vlans = { 0 };
    struct ethhdr *eth;
    struct arphdr *arp;
    int eth_type;
    __u8 *sender_ip;
    __u8 *sender_mac;
    struct arp_reply *arp_reply = NULL;

    struct hdr_cursor nh;
    nh.pos = data;

    eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
    if (eth_type != bpf_htons(ETH_P_ARP))
        goto out;

    if (nh.pos + sizeof(struct arphdr) > data_end)
        goto out;

    arp = nh.pos;
    if (arp->ar_op != bpf_htons(ARPOP_REPLY))
        goto out;

    // Extract IPv4 and MAC addresses
    sender_mac = (__u8 *)(arp + 1);
    if (sender_mac + 6 > (__u8 *)data_end)
        goto out;

    sender_ip = sender_mac + arp->ar_hln;
    if (sender_ip + 4 > (__u8 *)data_end)
        goto out;

    arp_reply = bpf_ringbuf_reserve(&arp_ringbuf, sizeof(*arp_reply), 0);
    if (!arp_reply)
        goto out;

    __builtin_memcpy(arp_reply->mac, sender_mac, ETH_ALEN);
    __builtin_memcpy(arp_reply->ip_bytes, sender_ip,
             sizeof(arp_reply->ip_bytes));
    arp_reply->vlan_id = vlans.id[0];

out:
    return  arp_reply;
}


SEC("xdp")
int handle_arp_reply_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(unsigned long long)ctx->data_end;
    void *data = (void *)(unsigned long long)ctx->data;

    struct arp_reply *arp_reply = handle_arp_reply(data, data_end);

    if (!arp_reply)
        goto out;

    arp_reply->ingress_ifindex = ctx->ingress_ifindex;

    // Send the data to userspace
    bpf_ringbuf_submit(arp_reply, 0);
out:
    return XDP_PASS;
}

SEC("tc")
int handle_arp_reply_tc(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct arp_reply *arp_reply = handle_arp_reply(data, data_end);

    if (!arp_reply)
        goto out;

    arp_reply->ingress_ifindex = skb->ifindex;

    arp_reply->vlan_id = skb->vlan_present ? skb->vlan_tci
        & VLAN_VID_MASK : 0;

    // Send the data to userspace
    bpf_ringbuf_submit(arp_reply, 0);
out:
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
