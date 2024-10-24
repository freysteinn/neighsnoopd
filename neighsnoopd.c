/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <argp.h>
#include <time.h>
#include <ifaddrs.h>
#include <regex.h>
#include <string.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <arpa/inet.h>
#include "neighsnoopd.h"

#include "neighsnoopd_shared.h" // Shared struct neighbor_reply with BPF
#include "neighsnoopd.bpf.skel.h"

#include "version.in.h"

struct env env = {0};

const char *argp_program_version = "neighsnoopd v0.9\n"
    "Build date: " __DATE__ " " __TIME__ "\n" \
    "git commit: " GIT_COMMIT;

const char *argp_program_bug_address =
        "https://github.com/1984hosting/neighsnoopd";

const char argp_program_doc[] =
    "Listens for ARP and NA replies and adds the neighbor to the Neighbors"
    "table.\n";

static const struct argp_option opts[] = {
    { "ipv4", '4', NULL, 0, "Only handle IPv4 ARP Reply packets", 0 },
    { "ipv6", '6', NULL, 0, "Only handle IPv6 NA packets", 0 },
    { "count", 'c', "NUM", 0, "This option handles a fixed number of ARP or NA"
      "replies before terminating the program."
      "Use this for debugging purposes only", 0 },
    { "deny-filter", 'f', "REGEXP", 0,
      "Filters out interfaces with a regular expression exclude from adding to"
      "the neighbor cache. Example: -f '^br0|.*-v1$'", 0 },
    { "no-qfilter-present", 'q', NULL, 0, "Do not replace the present Qdisc"
      "filter if it is present on the Ingress device", 0 },
    { "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
    { "xdp", 'x', NULL, 0, "Attach XDP instead of TC. This option only works"
      "on devices with a VLAN header on the packets available to XDP.", 0},
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
    {},
};

static bool filter_deny_interfaces(char *ifname);

// Callback function to handle data from the BPF ring buffer
static int handle_neighbor_reply(void *ctx, void *data, size_t data_sz)
{
    struct neighbor_reply *neighbor_reply = (struct neighbor_reply *)data;
    struct link_network_cache *link_net;
    struct link_cache *link;
    struct fdb_cache *fdb;
    struct neigh_cache *neigh;
    __u8 mac_str[MAC_ADDR_STR_LEN];
    char ip_str[INET6_ADDRSTRLEN];

    if (!neighbor_reply) {
        pr_err(0, "Neighbor Reply: Invalid data");
        return 1;
    }

    if (env.only_ipv6 && neighbor_reply->in_family != AF_INET6)
        return 1;
    else if (env.only_ipv4 && neighbor_reply->in_family != AF_INET)
        return 1;

    env.count--;

    link_net = cache_get_link_network_by_reply(neighbor_reply);
    if (!link_net) {
        pr_err(0, "NIC with VLAN ID: %d Network: %d not found in cache",
               neighbor_reply->vlan_id, neighbor_reply->network_id);
        return 1;
    }
    link = link_net->link;

    fdb = cache_get_fdb_by_reply(neighbor_reply, link->ifindex);
    if (fdb) {
        pr_debug("Neighbor Reply: IP: %s MAC: %s nic: %s is externally learned. Skipping\n",
                 fdb->mac_str, link_net->network->network_str, fdb->link->ifname);
        return 0;
    }

    neigh = cache_get_neigh_by_reply(neighbor_reply, link->ifindex);
    if (neigh)
        pr_debug("Neighbor Reply: IP: %s MAC: %s nic: %s already cached\n",
                 neigh->ip_str, neigh->mac_str,
                 neigh->link_network->link->ifname);

    mac_to_string(mac_str, neighbor_reply->mac, sizeof(mac_str));
    format_ip_address(ip_str, sizeof(ip_str), &neighbor_reply->ip);
    pr_info("Neighbor Reply: Adding IP: %s MAC: %s nic: %s\n",
            ip_str, mac_str, link->ifname);

    netlink_send_neigh(neighbor_reply, link->ifindex);

    return 0;
}

// Append a VLAN tag to the Ethernet frame
static void append_vlan_tag(unsigned char *buffer, int vlan_id,
                            uint16_t ether_type) {
    struct ether_header *eth = (struct ether_header *)buffer;
    uint16_t *vlan_tci = (uint16_t *)(buffer + ETH_HLEN);
    uint16_t *vlan_etype = (uint16_t *)(buffer + ETH_HLEN + 2);
    __u16 VLAN_PRIORITY = 0; // Default priority (can be 0-7)

    eth->ether_type = htons(ETHERTYPE_VLAN);  // VLAN tag EtherType

    // Set VLAN TCI (Tag Control Information: Priority + VLAN ID)
    *vlan_tci = htons((VLAN_PRIORITY << 13) | vlan_id);
    *vlan_etype = htons(ether_type);  // EtherType for next protocol (IPv4/IPv6)
}

static int send_neighbor_solicitation(struct neigh_cache *neigh)
{
    struct link_network_cache *src = neigh->sending_link_network;
    int vlan_id = src->link->vlan_id; // Get VLAN ID from the link
    unsigned char buffer[90];         // Size for Ethernet frame with
                                      // VLAN and ICMPv6 NS

    // Zero out the buffer
    memset(buffer, 0, sizeof(buffer));

    // Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;
    memcpy(eth->h_dest, neigh->mac, 6);       // Target MAC address
    memcpy(eth->h_source, src->link->mac, 6); // Source MAC address

    // Add VLAN tag
    append_vlan_tag(buffer, vlan_id, ETH_P_IPV6);

    // IPv6 header (after VLAN tag)
    struct ipv6hdr *ip6 = (struct ipv6hdr *)(buffer + ETH_HLEN + 4);
    ip6->version = 6;
    ip6->payload_len = htons(sizeof(struct nd_neighbor_solicit) + 8);
    ip6->nexthdr = IPPROTO_ICMPV6;
    ip6->hop_limit = 255; // Required for NS messages
    memcpy(&ip6->saddr, &src->ip, sizeof(struct in6_addr));   // Source IPv6
    memcpy(&ip6->daddr, &neigh->ip, sizeof(struct in6_addr)); // Target IPv6

    // ICMPv6 Neighbor Solicitation (after IPv6 header)
    struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *)
        (buffer + ETH_HLEN + 4 + sizeof(struct ipv6hdr));
    ns->nd_ns_type = ND_NEIGHBOR_SOLICIT;
    ns->nd_ns_code = 0;
    ns->nd_ns_cksum = 0; // Checksum will be calculated by the kernel or needs to be manually set: TODO: Check
    ns->nd_ns_reserved = 0;
    memcpy(&ns->nd_ns_target, &neigh->ip,
           sizeof(struct in6_addr)); // Target address for NS

    // ICMPv6 option - Source Link-Layer Address (after NS)
    unsigned char *opt = buffer + ETH_HLEN + 4 + sizeof(struct ipv6hdr)
        + sizeof(struct nd_neighbor_solicit);
    opt[0] = 1; // Option type: Source Link-Layer Address
    opt[1] = 1; // Option length in units of 8 octets
    memcpy(opt + 2, src->link->mac, 6); // Source MAC address

    // Set up the destination address for sending
    struct sockaddr_ll dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_IPV6);
    dest_addr.sll_halen = ETH_ALEN;
    memcpy(dest_addr.sll_addr, neigh->mac, 6);
    dest_addr.sll_ifindex = src->link->ifindex;

    // Send the Neighbor Solicitation message
    if (sendto(env.packet_fd, buffer, sizeof(buffer), 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        pr_err(errno, "Neighbor Solicitation send failed");
        return -1;
    }

    pr_debug("Neighbor Solicitation (NS) sent to IP: %s on VLAN %d nic: %s\n",
             neigh->ip_str, neigh->link_network->link->ifname, vlan_id);
    return 0;
}

static int send_arp_request(struct neigh_cache *neigh)
{
    struct link_network_cache *src = neigh->sending_link_network;
    int vlan_id = src->link->vlan_id;
    unsigned char buffer[46]; // ARP request size for Ethernet with VLAN

    // Zero out the buffer
    memset(buffer, 0, sizeof(buffer));

    // Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;
    memcpy(eth->h_dest, neigh->mac, 6);       // Target MAC address
    memcpy(eth->h_source, src->link->mac, 6); // Source MAC address

    // Add VLAN tag
    append_vlan_tag(buffer, vlan_id, ETH_P_ARP);

    // ARP header (after VLAN tag)
    struct ether_arp *arp = (struct ether_arp *)(buffer + ETH_HLEN + 4);
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);    // Hardware type (Ethernet)
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);        // Protocol type (IPv4)
    arp->ea_hdr.ar_hln = ETH_ALEN;               // Hardware address length
    arp->ea_hdr.ar_pln = sizeof(struct in_addr); // Protocol address length
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);    // ARP operation (request)

    // Fill ARP request details
    memcpy(arp->arp_sha, src->link->mac, 6);     // Sender MAC address
    memcpy(arp->arp_spa, &src->ip, 4);           // Sender IP address
    memset(arp->arp_tha, 0, 6);                  // Target MAC address (unknown)
    memcpy(arp->arp_tpa, &neigh->ip, 4);         // Target IP address

    // Set up the destination address for sending
    struct sockaddr_ll dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ARP);
    dest_addr.sll_halen = ETH_ALEN;
    memcpy(dest_addr.sll_addr, neigh->mac, 6);
    dest_addr.sll_ifindex = if_nametoindex("eth0"); // Replace "eth0" with your interface name

    // Send the ARP request using the existing socket env.packet_fd
    if (sendto(env.packet_fd, buffer, sizeof(buffer), 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        pr_err(errno, "ARP request send failed");
        return -1;
    }

    pr_debug("Gratuitous ARP request sent to IP: %s on VLAN %d nic: %s\n",
             neigh->ip_str, neigh->link_network->link->ifname, vlan_id);
    return 0;
}

static void send_gratuitous_neighbor_request(struct neigh_cache *neigh)
{
    if (IN6_IS_ADDR_V4MAPPED(&neigh->ip))
        send_neighbor_solicitation(neigh);
    else
        send_arp_request(neigh);
}

static int handle_neigh_add(struct netlink_neigh_cmd *cmd)
{
    struct link_cache *link;
    struct neigh_cache *neigh;

    char ip_str[INET6_ADDRSTRLEN];
    __u8 mac_str[MAC_ADDR_STR_LEN];

    // Ignore neigh events until we are initialized
    if (!(env.has_links && env.has_networks && env.has_fdb))
        goto out;

    if (env.debug) {
        format_ip_address(ip_str, sizeof(ip_str), &cmd->ip);
        mac_to_string(mac_str, cmd->mac, sizeof(mac_str));
    }

    // Skip entries without an interface
    if (cmd->ifindex == 0) {
        pr_debug("Neigh: IP: %s MAC: %s has no interface\n",
                 ip_str, mac_str);
        goto out;
    }

    link = cache_get_link(cmd->ifindex);
    if (!link) // We might have gotten a notification before the links are cached
        goto out;

    // Skip incomplete entries
    if (is_zero_mac(cmd->mac))
        goto out;

    // We can skip externally learned entries
    if (cmd->is_externally_learned) {
        pr_debug("Neigh: IP: %s MAC: %s is externally learned\n",
                 ip_str, mac_str);
        goto out;
    }

    neigh = cache_get_neigh(cmd);

    if (neigh) { // Already cached
        pr_debug("Neigh: IP: %s MAC: %s already cached\n",
                 ip_str, mac_str);
        if (neigh->nud_state != cmd->nud_state)
            cache_neigh_update(cmd);

        // Send a Link layer address resolution request to check if the
        // neighbor is still there
        if (neigh->is_target && neigh->nud_state == NUD_STALE)
            send_gratuitous_neighbor_request(neigh);
    } else { // Create a new cache entry
        neigh = cache_add_neigh(cmd);
        if (!neigh) {
            pr_err(0, "Failed to add Neigh: IP: %s MAC: %s to cache\n",
                   ip_str, mac_str);
            goto out;
        }

        if (!neigh->link_network)
            goto out;

        pr_info("Neigh: IP: %s MAC: %s nic: %s added to cache\n",
                neigh->ip_str, neigh->mac_str,
                neigh->link_network->link->ifname);
    }

out:
    return 0;
}

static int handle_neigh_del(struct netlink_neigh_cmd *cmd)
{
    struct neigh_cache *neigh = cache_get_neigh(cmd);

    if (!neigh) // Not cached
        goto out;

    cache_del_neigh(cmd);

out:
    return 0;
}

static int handle_fdb_add(struct netlink_neigh_cmd *cmd)
{
    int ret = 0;
    struct link_cache *link;
    struct fdb_cache *fdb;
    __u8 mac_str[MAC_ADDR_STR_LEN];

    // Ignore neigh events until we are initialized
    if (!(env.has_links && env.has_networks))
        goto out;

    // Skip entries without an interface
    if (cmd->ifindex == 0)
        goto out;

    link = cache_get_link(cmd->ifindex);
    if (!link) {
        pr_err(0, "Failed to lookup interface %d", cmd->ifindex);
        goto out;
    }

    if (cmd->is_externally_learned) {
        mac_to_string(mac_str, cmd->mac, sizeof(mac_str));
        pr_debug("FDB: MAC: %s is externally learned: Not cached\n", mac_str);
        goto out;
    }

    fdb = cache_get_fdb(cmd);
    if (fdb) // Already cached
        goto out;

    fdb = cache_add_fdb(cmd);
    if (!fdb) {
        mac_to_string(mac_str, cmd->mac, sizeof(mac_str));
        pr_err(0, "Failed to add FDB: MAC: %s to cache\n", mac_str);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int handle_fdb_del(struct netlink_neigh_cmd *cmd)
{
    struct fdb_cache *fdb = cache_get_fdb(cmd);

    if (!fdb) // Not cached
        goto out;

    cache_del_fdb(cmd);

out:
    return 0;
}

static int handle_addr_add(struct netlink_addr_cmd *cmd)
{
    int ret = 0;
    struct network_cache *network;
    struct link_cache *link;
    struct link_cache *svi_link;
    char network_cidr_str[INET6_ADDRSTRLEN + 4]; // IPv6 address + / + prefixlen

    // Ignore neigh events until we are initialized
    if (!env.has_links)
        goto out;

    format_ip_address_cidr(network_cidr_str, sizeof(network_cidr_str),
                        &cmd->ip, cmd->prefixlen);

    network = cache_get_network(cmd);
    if (network) {
        pr_debug("Network: %s already cached\n", network_cidr_str);
        goto out;
    }

    link = cache_get_link(cmd->ifindex);
    if (!link) {
        pr_debug("Failed to lookup interface %d\n", cmd->ifindex);
        goto out;
    }

    if (!link->has_vlan) {
        goto out;
    }

    if (!link->is_svi || !link->link_ifindex) {
        pr_debug("Link: %s is not an SVI or not connected to an SVI\n",
                 link->ifname);
        goto out;
    }

    // Check if the link is either a target SVI or connected to a anycast_gateway
    if (!link->is_svi) {
        struct link_cache *link_svi = cache_get_link(link->link_ifindex);

        if (!link_svi)
            goto out;

        if (!link_svi->is_svi)
            goto out;
    }

    network = cache_add_network(cmd);
    if (!network) {
        pr_err(0, "Failed to add network %s to cache", network_cidr_str);
        ret = -1;
        goto out;
    }

    pr_info("Cache: Added: Network(%d): %s with link %s\n",
            network->id, network_cidr_str, link->ifname);

out:
    return ret;
}

static int handle_addr_del(struct netlink_addr_cmd *cmd)
{
    int ret = -1;
    struct network_cache *network = cache_get_network(cmd);

    if (!network) {
        pr_debug("Network: %s/%d not cached: Can't remove\n",
                 network->network_str, network->prefixlen);
        goto out;
    }

    cache_del_network(cmd);

    pr_info("Cache: Removing Network: %s/%d\n", network->network_str,
            network->prefixlen);

    ret = 0;

out:
    return ret;
}

static int handle_link_add(struct netlink_link_cmd *cmd)
{
    int ret = 0;
    struct link_cache *link;

    link = cache_get_link(cmd->ifindex);
    if (link) {
        pr_debug("Link: %d: %s already cached\n",
                 cmd->ifindex, cmd->ifname);
        cache_update_link(link, cmd);
        goto out;
    } else {
        link = cache_add_link(cmd);
        if (!link) {
            pr_err(errno, "Failed to add link %d: %s to cache",
                   cmd->ifindex, cmd->ifname);
            ret = -1;
            goto out;
        }
    }

    link->is_svi = cmd->link_ifindex == env.ifidx_mon ? true : false;

    if (filter_deny_interfaces(cmd->ifname)) {
        pr_debug("Link: %d: %s matches regexp filter: filtered\n",
                 cmd->ifindex, cmd->ifname);
        link->ignore_link = true;
    }

    if (link->is_svi)
        pr_info("Cache: Added: NIC: %s with vlan: %d\n",
            cmd->ifname, cmd->vlan_id);
    else
        pr_debug("Cache: Added: NIC: %s with vlan: %d\n",
            cmd->ifname, cmd->vlan_id);

out:
    return ret;
}

static int handle_link_del(struct netlink_link_cmd *cmd)
{
    int ret = 0;
    struct link_cache *link = cache_get_link(cmd->ifindex);

    if (!link) {
        pr_debug("Cache: Link: %s not cached: Can't remove\n", cmd->ifname);
        ret = -1;
        goto out;
    }

    cache_del_link(cmd);

    pr_info("Cache: Link: Removed: %s\n", cmd->ifname);

out:
    return ret;
}

static int handle_netlink_cmd(union netlink_cmd *cmd)
{
    int ret = 0;
    switch (cmd->cmd_type) {
        case CMD_NEIGH_ADD:
            ret = handle_neigh_add(&cmd->neigh);
            break;
        case CMD_NEIGH_DEL:
            ret = handle_neigh_del(&cmd->neigh);
            break;
        case CMD_FDB_ADD:
            ret = handle_fdb_add(&cmd->neigh);
            break;
        case CMD_FDB_DEL:
            ret = handle_fdb_del(&cmd->neigh);
            break;
        case CMD_ADDR_ADD:
            ret = handle_addr_add(&cmd->addr);
            break;
        case CMD_ADDR_DEL:
            ret = handle_addr_del(&cmd->addr);
            break;
        case CMD_LINK_ADD:
            ret = handle_link_add(&cmd->link);
            break;
        case CMD_LINK_DEL:
            ret = handle_link_del(&cmd->link);
            break;
        default:
            pr_err(0, "Unknown command\n");
            break;
    }

    return ret;
}

static int handle_netlink(void)
{
    union netlink_cmd *cmd;

    // Process all Netlink messages and prep the cmd queue
    netlink_process_rx_queue();

    while ((cmd = netlink_dequeue_cmd()))
        if (handle_netlink_cmd(cmd))
            return -1;

    return 0;
}

static int handle_signal(void)
{
    int err = 0;
    struct signalfd_siginfo fdsi;
    ssize_t s;

    s = read(env.signal_fd, &fdsi, sizeof(struct signalfd_siginfo));
    if (s != sizeof(struct signalfd_siginfo)) {
        pr_err(errno, "read");
        err = errno;
        goto out;
    }

    if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM) {
        err = 1;
    }

out:
    return err;
}

static int handle_ring_buffer(void)
{
    int err;

    err = ring_buffer__consume(env.ringbuf);
    if (err < 0) {
        pr_err(err, "bpf_ringbuf_consume");
        goto out;
    }
    err = 0; // The return value is the number of consumed records

out:
    return err;
}

static void main_loop(void)
{
    struct epoll_event events[env.number_of_fds];
    struct epoll_event event;
    int client_offset;
    int client_bytes_to_send;
    bool last_round = false;

    if (netlink_queue_send_next()) {
        pr_err(errno, "Failed to send Netlink message");
        return; // Failure
    }

    while (true) {
        int n;

        if (env.has_count) {
            if (last_round)
                break;
            if (env.count <= 0)
                last_round = true;
        }

        n = epoll_wait(env.epoll_fd, events, env.number_of_fds, -1);
        if (n == -1) {
            if (errno == EINTR)
                continue; // Ignore interrupted by signal
            pr_err(errno, "epoll_wait");
            return; // Failure
        }

        /*
         * We priorities the events from epoll as follows:
         * 1. Signal events
         * 2. Netlink events
         * 3. BPF ring buffer events
         * 4. Send Netlink messages from the tx queue
         * 5. Handle stats server socket requests
         * 6. Handle stats client socket
         */

        // Signal events
        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == env.signal_fd) {
                if (handle_signal())
                    return; // Failure or exiting
            }
        }

        // Netlink events
        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == env.nl_fd) {
                if (handle_netlink())
                    return; // Failure
            }
        }

        // BPF ring buffer events
        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == env.ringbuf_fd) {
                if (handle_ring_buffer()) {
                    pr_err(errno, "Failed to consume ring buffer");
                    return; // Failure
                }
            }
        }

        // Send Netlink messages from the tx queue
        if (netlink_queue_send_next()) {
            pr_err(errno, "Failed to send Netlink message");
            return; // Failure
        }

        // Handle server stats request
        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == env.stats_server_fd) {
                struct stat st;
                if (handle_stats_server_request())
                    return; // Failure

                // Add the client socket to the epoll
                event.events = EPOLLOUT;
                event.data.fd = env.stats_client_fd;
                if (epoll_ctl(env.epoll_fd, EPOLL_CTL_ADD, env.stats_client_fd,
                              &event) == -1) {
                    pr_err(errno, "epoll_ctl: stats_client_fd");
                    close(env.stats_client_fd);
                    env.stats_client_fd = -1;
                    close(env.memfd_fd);
                    env.memfd_fd = -1;
                    continue;
                }
                client_offset = 0;
                if (fstat(env.memfd_fd, &st) == -1) {
                    pr_err(errno, "fstat");
                    return; // Failure
                }
                client_bytes_to_send = st.st_size;
            }
        }

        // Handle client stats request
        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == env.stats_client_fd) {
                int bytes_read;
                int bytes_sent;
                char buf[4096];

                if (client_offset == client_bytes_to_send) {
                    close(env.stats_client_fd);
                    env.stats_client_fd = -1;
                    close(env.memfd_fd);
                    env.memfd_fd = -1;
                    continue;
                }

                bytes_read = pread(env.memfd_fd, buf, sizeof(buf),
                                   client_offset);
                if (bytes_read == -1) {
                    pr_err(errno, "pread");
                    return; // Failure
                }

                bytes_sent = send(env.stats_client_fd, buf, bytes_read, 0);
                if (bytes_sent == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        continue;
                    pr_err(errno, "send");
                    return; // Failure
                }

                client_offset += bytes_sent;

                if (client_offset == client_bytes_to_send) {
                    // Remove the client socket from the epoll
                    event.events = EPOLLOUT;
                    event.data.fd = env.stats_client_fd;
                    if (epoll_ctl(env.epoll_fd, EPOLL_CTL_DEL, env.stats_client_fd,
                                  &event) == -1) {
                        pr_err(errno, "epoll_ctl: stats_client_fd");
                        return; // Failure
                    }

                    // Close the client socket and the memfd
                    close(env.stats_client_fd);
                    env.stats_client_fd = -1;
                    close(env.memfd_fd);
                    env.memfd_fd = -1;
                }
            }
        }
    }
}

// Signal setup and cleanup
static int setup_signals(void)
{
    int err = 0;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);  // Handle SIGINT (Ctrl+C)
    sigaddset(&mask, SIGTERM); // Handle SIGTERM

    // Block these signals so they can be handled via signalfd
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        perror("sigprocmask");
        err = errno;
        goto out;
    }

    // Create a signalfd to receive the signals
    env.signal_fd = signalfd(-1, &mask, 0);
    if (env.signal_fd == -1) {
        perror("signalfd");
        err = errno;
        goto out;
    }

    env.number_of_fds++;

out:
    return err;
}

static void cleanup_signals(void)
{
    if (env.signal_fd >= 0)
        close(env.signal_fd);
}

// BPF setup and cleanup
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG && !env.debug)
        return 0;
    return vfprintf(stderr, format, args);
}

static int setup_bpf(void)
{
    int err = 0;

    libbpf_set_print(libbpf_print_fn);

    // Open the skeleton
    env.skel = neighsnoopd_bpf__open();
    if (!env.skel) {
        perror("Failed to open BPF skeleton\n");
        err = errno;
        env.skel = NULL;
        goto out;
    }

    // Load the BPF program
    err = neighsnoopd_bpf__load(env.skel);
    if (err) {
        perror("Failed to load BPF skeleton\n");
        err = errno;
        goto out;
    }

    env.target_networks_fd = bpf_map__fd(
        bpf_object__find_map_by_name(env.skel->obj, "target_networks"));

    // XDP
    struct bpf_link *xdp_link;

    // TC OPTS
    LIBBPF_OPTS(bpf_tc_hook, tc_hook,
                .ifindex = env.ifidx_mon,
                .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, tc_opts,
                .handle = 1,
                .priority = 1,
                .prog_fd = bpf_program__fd(
                    env.skel->progs.handle_neighbor_reply_tc));

    env.tc_opts = tc_opts;
    env.tc_hook = tc_hook;

    if (!env.fail_on_qfilter_present)
        env.tc_opts.flags |= BPF_TC_F_REPLACE;

    if (env.is_xdp) {
        // attach xdp program to interface
        xdp_link = bpf_program__attach_xdp(
            env.skel->progs.handle_neighbor_reply_xdp, env.ifidx_mon);
        if (!xdp_link) {
            perror("Failed to attach XDP hook");
            goto out;
        }
    } else {
        // Load TC hook instead of XDP
        // Attach the BPF program to the clsact qdisc for ingress

        /*
         * The TC Qdisc hook may already exist because:
         * 1. Other processes or users create it.
         * 2. By attaching to the TC ingress, the bpf_tc_hook_destroy does not
         * remove the Qdisc and may leave an egress filter in place since the last
         * invocation of the program.
         */
        err = bpf_tc_hook_create(&env.tc_hook);
        if (err && err != -EEXIST) {
            perror("Failed to create TC hook");
            goto out;
        }

        if (bpf_tc_attach(&env.tc_hook, &env.tc_opts)) {
            perror("Failed to attach TC hook");
            goto out;
        }
    }
    err = 0;

    // Parse Neighbor replies
    struct bpf_map *ringbuf_map =
        bpf_object__find_map_by_name(env.skel->obj, "neighbor_ringbuf");

    env.ringbuf = ring_buffer__new(bpf_map__fd(ringbuf_map),
                                              handle_neighbor_reply, NULL, NULL);
    if (!env.ringbuf) {
        perror("Failed to create ring buffer");
        err = errno;
        goto out;
    }

    env.ringbuf_fd = bpf_map__fd(ringbuf_map);
    if (env.ringbuf_fd < 0) {
        perror("Failed to get ringbuf map fd");
        err = env.ringbuf_fd;
        goto out;
    }

out:
    return err;
}

static bool filter_deny_interfaces(char *ifname)
{
    int ret;
    if (!env.has_deny_filter)
        return false;

    ret = regexec(&env.deny_filter, ifname, 0, NULL, 0);
    if (ret)
        return false;

    return true;
}

static void cleanup_bpf(void)
{
    int err;
    if (env.ringbuf_fd >= 0)
        close(env.ringbuf_fd);

    env.tc_opts.flags = env.tc_opts.prog_fd = env.tc_opts.prog_id = 0;
    if (!env.is_xdp) {
        pr_debug("Detaching the TC hook\n");
        err = bpf_tc_detach(&env.tc_hook, &env.tc_opts);
        if (err)
            perror("Failed to detach TC hook\n");
    } else {
        pr_debug("Destroying the TC hook\n");
        err = bpf_tc_hook_destroy(&env.tc_hook);
        if (err)
            perror("Failed to destroy TC hook");
    }
    neighsnoopd_bpf__destroy(env.skel);
}

// epoll setup and cleanup
static int setup_epoll(void)
{
    int err = 0;
    struct epoll_event event;

    env.epoll_fd = epoll_create1(0);

    // Add signalfd to epoll
    event.events = EPOLLIN;
    event.data.fd = env.signal_fd;
    if (epoll_ctl(env.epoll_fd, EPOLL_CTL_ADD, env.signal_fd, &event) == -1) {
        perror("epoll_ctl: signal_fd");
        err = errno;
        goto out;
    }

    // Add netlink socket to epoll
    event.events = EPOLLIN;
    event.data.fd = env.nl_fd;
    if (epoll_ctl(env.epoll_fd, EPOLL_CTL_ADD, env.nl_fd, &event) == -1) {
        perror("epoll_ctl: nl_fd");
        err = errno;
        goto out;
    }

    // Add BPF ring buffer to epoll
    event.events = EPOLLIN;
    event.data.fd = env.ringbuf_fd;
    if (epoll_ctl(env.epoll_fd, EPOLL_CTL_ADD, env.ringbuf_fd, &event) == -1) {
        perror("epoll_ctl: ringbuf_fd");
        err = errno;
        goto out;
    }

    event.events = EPOLLIN;
    event.data.fd = env.stats_server_fd;
    if (epoll_ctl(env.epoll_fd, EPOLL_CTL_ADD,
                  env.stats_server_fd, &event) == -1) {
        perror("epoll_ctl: stats_server_fd");
        err = errno;
        goto out;
    }

out:
    return err;
}

static void cleanup_epoll(void)
{
    if (env.epoll_fd >= 0)
        close(env.epoll_fd);
}

static int setup_filters(void)
{
    int ret = 0;
    if (env.has_deny_filter) {
        ret = regcomp(&env.deny_filter, env.str_deny_filter, REG_EXTENDED);
        if (ret) {
            perror("Failed to compile regular expression");
            goto out;
        }
    }

out:
    return ret;
}

static void cleanup_filters(void)
{
    if (env.has_deny_filter)
        regfree(&env.deny_filter);
}

static int setup_packet(void)
{
    env.packet_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (env.packet_fd == -1) {
        perror("Failed to open packet socket");
        return errno;
    }
    return 0;
}

static void cleanup_packet(void)
{
    if (env.packet_fd >= 0)
        close(env.packet_fd);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    static int pos_args;

    switch (key) {
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        case '4':
            if (env.only_ipv6) {
                fprintf(stderr, "Cannot specify both --ipv4 and --ipv6\n");
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            env.only_ipv4 = true;
            break;
        case '6':
            if (env.only_ipv4) {
                fprintf(stderr, "Cannot specify both --ipv4 and --ipv6\n");
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            env.only_ipv6 = true;
            break;
        case 'c':
            env.has_count = true;
            env.count = strtoul(arg, NULL, 0);
            if (env.count == 0) {
                perror("Invalid count");
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            break;
        case 'f':
            if (strlen(arg) == 0) {
                fprintf(stderr, "Invalid filter\n");
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            env.str_deny_filter = arg;
            env.has_deny_filter = true;
            break;
        case 'q':
            env.fail_on_qfilter_present = true;
            break;
        case 'v':
            if (env.debug)
                env.netlink = true;
            if (env.verbose)
                env.debug = true;
            env.verbose = true;
            break;
        case 'x':
            env.is_xdp = true;
            break;
        case ARGP_KEY_NO_ARGS:
            fprintf(stderr, "Missing network device <IFNAME_MON>\n");
            argp_usage(state);
            break;
        case ARGP_KEY_ARG:
            if (pos_args > 0) {
                fprintf(stderr, "Too many arguments: %s\n", arg);
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            env.ifidx_mon = if_nametoindex(arg);
            if (!env.ifidx_mon) {
                perror("Invalid network device");
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            strncpy(env.ifidx_mon_str, arg, sizeof(env.ifidx_mon_str));
            pos_args++;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
// This function is references by argp and not from this code
static void short_usage(FILE *fp, struct argp_state *state)
{
    fprintf(stderr, "Usage: %s [--help] [--verbose] <IFNAME_MON>\n",
            state->argv[0]);
}
#pragma GCC diagnostic pop

int main(int argc, char **argv)
{
    int err;

    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
        .args_doc = "<IFNAME_MON>",
    };

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        err = EXIT_FAILURE;
        goto cleanup0;
    }

    if (setup_filters()) {
        err = EXIT_FAILURE;
        goto cleanup0;
    }
    if (setup_packet()) {
        err = EXIT_FAILURE;
        goto cleanup1;
    }
    if (setup_cache()) {
        err = EXIT_FAILURE;
        goto cleanup2;
    }
    if (setup_signals()) {
        err = EXIT_FAILURE;
        goto cleanup3;
    }
    if (setup_netlink()) {
        err = EXIT_FAILURE;
        goto cleanup4;
    }
    if (setup_bpf()) {
        err = EXIT_FAILURE;
        goto cleanup5;
    }
    if (setup_stats()) {
        err = EXIT_FAILURE;
        goto cleanup6;
    }
    if (setup_epoll()) {
        err = EXIT_FAILURE;
        goto cleanup7;
    }

    // Main loop
    main_loop();

    // Cleanup
    cleanup_epoll();
cleanup7:
    cleanup_stats();
cleanup6:
    cleanup_bpf();
cleanup5:
    cleanup_netlink();
cleanup4:
    cleanup_signals();
cleanup3:
    cleanup_cache();
cleanup2:
    cleanup_packet();
cleanup1:
    cleanup_filters();
cleanup0:
    return err;
}
