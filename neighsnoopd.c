/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 1984 <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <argp.h>
#include <time.h>
#include <ifaddrs.h>
#include <regex.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/if_ether.h>

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#include "neighsnoopd.bpf.skel.h"

#include "neighsnoopd.h"

#define MAC_ADDR_STR_LEN 18

static struct env {
    int ifidx_mon;
    char *regexp_filter_ifname;
    regex_t regex_filter;
    bool has_filter;
    bool is_xdp;
    bool disable_macvlan_filter;
    bool verbose;
    bool debug;
    bool netlink;
} env;

static volatile sig_atomic_t exiting = 0;

static __u32 nlm_seq;
struct mnl_socket *nl;
__u32 mnl_portid;

const char *argp_program_version = "neighsnoopd 1.0";

const char *argp_program_bug_address =
        "https://www.github.com/freysteinn/neighsnoopd"; // Should be changed

const char argp_program_doc[] =
    "Listens for ARP replies and adds the neighbor to the Neighbors table.\n";

static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
    { "filter", 'f', "REGEXP", 0,
      "Regular expression to exclude interfaces from program", 0 },
    { "macvlan", 'm', NULL, 0, "Disable macvlan fitering", 0 },
    { "xdp", 'x', NULL, 0, "Attach XDP instead of TC", 0},
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
    {},
};

void mac_to_string(__u8 *buffer, const __u8 *mac, size_t buffer_size)
{
    if (buffer_size < MAC_ADDR_STR_LEN) { // "XX:XX:XX:XX:XX:XX" + null terminator
        buffer[0] = '\0'; // Not enough space, return an empty string
        return;
    }
    snprintf((char *)buffer, buffer_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void __pr_std(FILE * file, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);
}

// Prints info messages
#define pr_info(fmt, ...)                              \
    do {                                               \
        __pr_std(stdout, "INFO: " fmt, ##__VA_ARGS__); \
    } while (0)

// Print error message with error string
#define __pr_err(err, fmt, ...)                                           \
    do {                                                                  \
        if (err == 0)                                                     \
            __pr_std(stderr, fmt "\n", ##__VA_ARGS__);                    \
        else                                                              \
            __pr_std(stderr, fmt ": %s\n", ##__VA_ARGS__, strerror(err)); \
    } while (0)

// Prints error messages with function and line number
#define pr_err(err, fmt, ...)                                          \
    do {                                                               \
        __pr_err(err, "ERROR: [%-10.10s:%d] " fmt, __func__, __LINE__, \
                 ##__VA_ARGS__);                                       \
    } while (0)


// The pr_debug function prints debug messages if the debug flag is set
#define __pr_debug(fmt, ...)                  \
    do {                                      \
        if (!env.debug)                       \
            break;                            \
        __pr_std(stderr, fmt, ##__VA_ARGS__); \
    } while (0)

// Prints debug messages with function and line number
#define pr_debug(fmt, ...)                                                          \
    do {                                                                            \
        __pr_debug("DEBUG: [%-10.10s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)

// Prints netlink messages wihout prefix
#define __pr_nl(fmt, ...)                     \
    do {                                      \
        if (!env.netlink)                     \
            break;                            \
        __pr_std(stderr, fmt, ##__VA_ARGS__); \
    } while (0)


// Prints netlink messages with function and line number
#define pr_nl(fmt, ...)                                            \
    do {                                                           \
        __pr_nl("NETLINK: [%-10.10s:%d] " fmt, __func__, __LINE__, \
                ##__VA_ARGS__);                                    \
    } while (0)


static int pr_nl_attr_neigh(const struct nlattr *attr, void *data)
{
    int type = mnl_attr_get_type(attr);
    __u8 mac_str[MAC_ADDR_STR_LEN];
    __u16 vlanid;

    __pr_nl(">  [ATTR %d] %d octets", mnl_attr_get_type(attr),
             mnl_attr_get_len(attr));
    switch (type) {
        case NDA_UNSPEC:
            __pr_nl(" <UNSPEC>");
            break;
        case NDA_DST:
            __pr_nl(" <DST> IP: %s",
                     inet_ntoa(*(struct in_addr *)mnl_attr_get_payload(attr)));
            break;
        case NDA_LLADDR:
            if (mnl_attr_get_len(attr) >= ETH_ALEN) {
                mac_to_string(mac_str, mnl_attr_get_payload(attr), sizeof(mac_str));
                __pr_nl(" <LLADDR> MAC: %s", mac_str);
            } else {
                __pr_nl(" <LLADDR>");
            }
            break;
        case NDA_CACHEINFO:
            __pr_nl(" <CACHEINFO>");
            break;
        case NDA_PROBES:
            __pr_nl(" <PROBES>");
            break;
        case NDA_VLAN:
            __pr_nl(" <VLAN> LAN ID: %d", mnl_attr_get_u16(attr));
            break;
        case NDA_PORT:
            __pr_nl(" <PORT> PORT: %d", mnl_attr_get_u16(attr));
            break;
        case NDA_VNI:
            __pr_nl(" <VNI> VNI: %d", mnl_attr_get_u32(attr));
            break;
        case NDA_IFINDEX:
            __pr_nl(" <IFINDEX> IFINDEX: %d", mnl_attr_get_u32(attr));
            break;
        case NDA_MASTER:
            __pr_nl(" <MASTER>");
            break;
        case NDA_LINK_NETNSID:
            __pr_nl(" <LINK_NETNSID>");
            break;
        case NDA_SRC_VNI:
            __pr_nl(" <SRC_VNI> SRC_VNI: %d", mnl_attr_get_u32(attr));
            break;
        case NDA_PROTOCOL:
            __pr_nl(" <PROTOCOL> PROTOCOL: %d", mnl_attr_get_u32(attr));
            break;
        case NDA_NH_ID:
            __pr_nl(" <NH_ID>");
            break;
        case NDA_FDB_EXT_ATTRS:
            __pr_nl(" <FDB_EXT_ATTRS>");
            break;
        case NDA_FLAGS_EXT:
            __pr_nl(" <FLAGS_EXT>");
            break;
        case NDA_NDM_STATE_MASK:
            __pr_nl(" <NDM_STATE_MASK>");
            break;
        case NDA_NDM_FLAGS_MASK:
            __pr_nl(" <NDM_FLAGS_MASK>");
            break;
        default:
            __pr_nl(" <UNKNOWN(%d)>", type);
            break;
    }
    __pr_nl("\n");

    return MNL_CB_OK;
}

static int pr_nl_neigh_ndm(const struct nlmsghdr *nlh)
{
    struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);

    __pr_nl(">  [NEIGHBOR Header] %d octets\n", nlh->nlmsg_len);
    __pr_nl(">    .ndm_family = %d\n", ndm->ndm_family);
    __pr_nl(">    .ndm_ifindex = %d\n", ndm->ndm_ifindex);
    __pr_nl(">    .ndm_state = <");
    unsigned states = nlh->nlmsg_flags;
    while (states) {
        int bit_pos = __builtin_ctzll(states);
        int state = 1 << bit_pos;
        if (state & NLM_F_REQUEST)
            __pr_nl("REQUEST");
        if (state & NLM_F_MULTI)
            __pr_nl("MULTI");
        if (state & NLM_F_ACK)
            __pr_nl("ACK");
        if (state & NLM_F_ECHO)
            __pr_nl("ECHO");
        if (state & NLM_F_DUMP_INTR)
            __pr_nl("DUMP_INTR");
        if (state & NLM_F_DUMP_FILTERED)
            __pr_nl("DUMP_FILTERED");
        if (state >= NLM_F_DUMP_FILTERED)
            __pr_nl("UNKNOWN(0x%x)", state);
        if (__builtin_popcountll(states) > 1)
            __pr_nl(",");
        states &= (states - 1);
    }
    __pr_nl(">\n");
    __pr_nl(">    .ndm_flags = %d <", ndm->ndm_flags);
    unsigned flags = nlh->nlmsg_flags;
    while (flags) {
        int bit_pos = __builtin_ctzll(flags);
        int flag = 1 << bit_pos;
        if (flag & NTF_USE)
                __pr_nl("USE");
        if (flag & NTF_SELF)
            __pr_nl("SELF");
        if (flag & NTF_MASTER)
            __pr_nl("MASTER");
        if (flag & NTF_PROXY)
            __pr_nl("PROXY");
        if (flag & NTF_EXT_LEARNED)
            __pr_nl("EXT_LEARNED");
        if (flag & NTF_OFFLOADED)
            __pr_nl("OFFLOADED");
        if (flag & NTF_STICKY)
            __pr_nl("STICKY");
        if (flag & NTF_ROUTER)
            __pr_nl("ROUTER");
        if (flag > NTF_ROUTER)
            __pr_nl("UNKNOWN(0x%x)", flag);

        if (__builtin_popcountll(flags) > 1)
            __pr_nl(",");
        flags &= (flags - 1);
    }
    __pr_nl(">\n");
    __pr_nl(">    .ndm_type = %d\n", ndm->ndm_type);

    mnl_attr_parse(nlh, sizeof(*ndm), pr_nl_attr_neigh, NULL);

    return MNL_CB_OK;
}

static int pr_nl_attr(const struct nlattr *attr, void *data)
{
    pr_nl(">  [ATTR %d] %d octets", mnl_attr_get_type(attr),
             mnl_attr_get_len(attr));
    for (int i = 0; i < mnl_attr_get_len(attr); i++) {
        if (i % 16 == 0)
            __pr_nl("  ");
        __pr_nl("%02x ", ((unsigned char *)mnl_attr_get_payload(attr))[i]);
        if (i % 16 == 15)
            __pr_nl("\n>");
    }
    __pr_nl("\n");
    return MNL_CB_OK;
}

static int pr_nl_ndm(const struct nlmsghdr *nlh)
{
    struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);

    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
        __pr_nl(">  [ERROR] ", err->error);
        __pr_nl(">    .error = %d\n", err->error);
        __pr_nl(">    .msg = %s\n", strerror(-err->error));
        return MNL_CB_OK;
    }
    __pr_nl(">  [PAYLOAD] %d octets\n", nlh->nlmsg_len);
    __pr_nl(">");
    for (int i = 0; i < nlh->nlmsg_len; i++) {
        if (i % 16 == 0)
            __pr_nl("  ");
        __pr_nl("%02x ", ((unsigned char *)nlh)[i]);
        if (i % 16 == 15)
            __pr_nl("\n>");
    }
    __pr_nl("\n");

    mnl_attr_parse(nlh, sizeof(*ndm), pr_nl_attr, NULL);

    return MNL_CB_OK;
}

static void pr_nl_nlmsg(struct nlmsghdr *nlh, __u32 seq)
{
    int ret;

    if (!env.netlink)
        return;

    __pr_nl(">----------- BEGIN NETLINK MESSAGE -----------\n");
    __pr_nl(">  [NETLINK Header ] %d octets\n", nlh->nlmsg_len);

    __pr_nl(">    .nlmsg_len = %d\n", nlh->nlmsg_len);
    __pr_nl(">    .type = %d <", nlh->nlmsg_type, nlh->nlmsg_type);
    switch (nlh->nlmsg_type) {
        case NLMSG_NOOP:
            __pr_nl("NOOP");
            break;
        case NLMSG_ERROR:
            __pr_nl("ERROR");
            break;
        case NLMSG_DONE:
            __pr_nl("DONE");
            break;
        case NLMSG_OVERRUN:
            __pr_nl("OVERRUN");
            break;
        case RTM_NEWNEIGH:
            __pr_nl("NEWNEIGH");
            break;
        case RTM_GETNEIGH:
            __pr_nl("GETNEIGH");
            break;
        default:
            __pr_nl("UNKNOWN(%d)", nlh->nlmsg_type);
            break;
    }
    __pr_nl(">\n");
    __pr_nl(">    .flags = %d <", nlh->nlmsg_flags, nlh->nlmsg_flags);
    unsigned flags = nlh->nlmsg_flags;
    while (flags) {
        int bit_pos = __builtin_ctzll(flags);
        int flag = 1 << bit_pos;
        if (flag & NLM_F_REQUEST)
            __pr_nl("REQUEST");
        if (flag & NLM_F_MULTI)
            __pr_nl("MULTI");
        if (flag & NLM_F_ACK)
            __pr_nl("ACK");
        if (flag & NLM_F_ECHO)
            __pr_nl("ECHO");
        if (flag & NLM_F_DUMP_INTR)
            __pr_nl("DUMP_INTR");
        if (flag & NLM_F_DUMP_FILTERED)
            __pr_nl("DUMP_FILTERED");
        if (flag >= NLM_F_DUMP_FILTERED)
            __pr_nl("UNKNOWN(0x%x)", flag);
        if (__builtin_popcountll(flags) > 1)
            __pr_nl(",");
        flags &= (flags - 1);
    }
    __pr_nl(">\n");
    __pr_nl(">    .seq = %d\n", nlh->nlmsg_seq);
    __pr_nl(">    .port = %d\n", nlh->nlmsg_pid);

    if (nlh->nlmsg_type == RTM_NEWNEIGH || nlh->nlmsg_type == RTM_GETNEIGH)
        ret = pr_nl_neigh_ndm(nlh);
    else
        ret = pr_nl_ndm(nlh);
    if (ret <= MNL_CB_ERROR) {
        pr_nl(">>>error parsing netlink message<<<\n");
        return;
    }
    __pr_nl(">-----------  END NETLINK MESSAGE  -----------\n");
}

static int getneigh_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    /* skip unsupported attribute in user-space */
    if (mnl_attr_type_valid(attr, NDA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case NDA_DST:
    case NDA_LLADDR:
        if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
            pr_err(errno, "mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

struct arp_reply_lookup {
    const __u8 *mac_addr;
    struct arp_reply *arp_reply;
    bool found;
    bool is_ext_learned;
};

static int getneigh_find_mac_cb(const struct nlmsghdr *nlh, void *data)
{
    struct arp_reply_lookup *lookup = data;
    struct nlattr *tb[NDA_MAX + 1] = {};
    struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
    const __u8 *fdb_mac = NULL;
    bool is_ext_learned;

    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (err->error != 0)
            pr_err(err->error, "Netlink error");
        return MNL_CB_STOP;
    }

    if (nlh->nlmsg_type == NLMSG_DONE)
        return MNL_CB_STOP;


    if (nlh->nlmsg_type != RTM_NEWNEIGH)
        return MNL_CB_OK;

    mnl_attr_parse(nlh, sizeof(*ndm), getneigh_attr_cb, tb);

    if (tb[NDA_LLADDR] == NULL)
        return MNL_CB_OK;

    fdb_mac = mnl_attr_get_payload(tb[NDA_LLADDR]);
    if (memcmp(fdb_mac, lookup->mac_addr, ETH_ALEN) != 0)
        return MNL_CB_OK;

    lookup->found = true;
    if (!lookup->is_ext_learned)
        lookup->is_ext_learned = ndm->ndm_flags & NTF_EXT_LEARNED;

    return MNL_CB_OK;
}

// Function to check if the MAC address is in the FDB and has
// the "extern_learn" flag
static bool is_mac_local(const __u8 *mac_addr)
{
    // Query the FDB entries in AF_BRIDGE for the specified MAC address
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ndmsg *ndm;
    int ret;
    int err;
    struct arp_reply_lookup lookup = { mac_addr, false, false};

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    nlh->nlmsg_seq = ++nlm_seq;

    ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ndm));
    ndm->ndm_family = AF_BRIDGE;

    pr_nl("sending netlink message\n");
    pr_nl_nlmsg(nlh, nlm_seq);

    // Send Netlink request to fetch FDB entries
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        pr_err(errno, "mnl_socket_sendto");
        return false;
    }

    // Parse the response
    while ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
        pr_nl("received netlink message\n");
        pr_nl_nlmsg((struct nlmsghdr *)buf, nlm_seq);

        ret = mnl_cb_run(buf, ret, nlm_seq, mnl_portid, getneigh_find_mac_cb,
                         &lookup);

        if (ret <= MNL_CB_STOP)
            break;
    }
    if (ret < 0) {
        pr_err(errno, "Failed to parse FDB entries(%d)", ret);
        return false;
    }

    if (!lookup.found) {
        pr_debug("MAC address not found in FDB\n");
        return false;
    }
    if (lookup.is_ext_learned) {
        pr_debug("MAC address found in FDB, but not externally learned\n");
        return false;
    }
    return true;
}

static int add_neigh(struct arp_reply *arp_reply, int dest_ifindex)
{
    int err = -1; // the default return value is an error

    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ndmsg *ndm;
    int ret;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_NEWNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | NLM_F_EXCL;
    nlh->nlmsg_seq = ++nlm_seq;

    ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ndm));
    ndm->ndm_family = AF_INET;
    ndm->ndm_state = NUD_REACHABLE;
    ndm->ndm_ifindex = dest_ifindex;

    // Add IP address
    mnl_attr_put(nlh, NDA_DST, sizeof(arp_reply->ip), &arp_reply->ip);

    // Add MAC address
    mnl_attr_put(nlh, NDA_LLADDR, sizeof(arp_reply->mac), arp_reply->mac);

    // Add VLAN information if needed
    if (arp_reply->vlan_id > 0)
        mnl_attr_put(nlh, NDA_VLAN, sizeof(arp_reply->vlan_id),
                     &arp_reply->vlan_id);

    __u8 mac_str[MAC_ADDR_STR_LEN];
    char ifname[IFNAMSIZ];
    if (!if_indextoname(dest_ifindex, ifname)) {
        pr_err(errno, "if_indextoname");
        goto out;
    }

    if (env.verbose)
        mac_to_string(mac_str, arp_reply->mac, sizeof(mac_str));
    pr_debug("Requesting to add neighbor:\n");
    pr_debug("- Interface %d: %s\n", dest_ifindex, ifname);
    pr_debug("- IP address: %s\n", inet_ntoa(arp_reply->ip));
    pr_debug("- MAC address: %s\n", mac_str);

    pr_nl("sending netlink message\n");
    pr_nl_nlmsg(nlh, nlm_seq);

    // Send Netlink request update neigh table
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        pr_err(errno, "mnl_socket_sendto");
        goto out;
    }

    // Parse the response
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    if (ret < 0) {
        pr_err(errno, "mnl_socket_recvfrom");
        goto out;
    }

    pr_nl("%s(%d): received netlink message\n");
    pr_nl_nlmsg((struct nlmsghdr *)buf, nlm_seq);

    err = mnl_cb_run(buf, ret, nlm_seq, mnl_portid,
                     NULL, NULL);
    err = errno;
    if (!err)
        pr_info("Added MAC: %s to FDB on interface: %s\n",
                mac_str, ifname);
    if (err == EEXIST)
        pr_debug("Mac address already exists in FDB\n");

out:
    return err;
}

static int find_ifindex_from_ip(struct in_addr *given_ip, char *ifname,
                                size_t ifname_size)
{
    struct ifaddrs *ifaddr, *ifa;
    struct sockaddr_in *addr, *netmask;
    in_addr_t network, given_ip_network;
    const char* matching_ifname = NULL;
    int ret_ifindex = -1;

    if (ifname_size < IFNAMSIZ) {
        ifname[0] = '\0'; // Not enough space, return an empty string
        pr_err(0, "ifname buffer size is too small");
        return -1;
    }

    if (getifaddrs(&ifaddr) == -1)
        return -1;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_netmask == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            addr = (struct sockaddr_in *)ifa->ifa_addr;
            netmask = (struct sockaddr_in *)ifa->ifa_netmask;

            // Calculate the network address
            network = addr->sin_addr.s_addr & netmask->sin_addr.s_addr;
            given_ip_network = given_ip->s_addr & network;

            // Compare the network addresses
            if (network == given_ip_network) {
                matching_ifname = ifa->ifa_name;
                break;
            }
        }
    }
    freeifaddrs(ifaddr);

    if (!matching_ifname)
        return -1;
    memcpy(ifname, matching_ifname, IFNAMSIZ);

    ret_ifindex = if_nametoindex(matching_ifname);
    if (!ret_ifindex) {
        pr_err(errno, "if_nametoindex");
        return -1;
    }

    if (env.debug) {
        __u32 mask = ntohl(netmask->sin_addr.s_addr);
        char given_ip_str[INET_ADDRSTRLEN];
        char network_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, given_ip, given_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &network, network_str, INET_ADDRSTRLEN);
        pr_debug("Found IP: %s in %s/%d on %s\n",
                 given_ip_str,
                 network_str,
                 __builtin_popcountll(mask),
                 matching_ifname);
    }
    return ret_ifindex;
}

static bool filter_interfaces(char *ifname)
{
    int ret;
    if (!env.has_filter)
        return false;

    ret = regexec(&env.regex_filter, ifname, 0, NULL, 0);
    if (ret)
        return false;

    pr_debug("Filtered interface %s using filter: '%s'\n", ifname,
             env.regexp_filter_ifname);
    return true;
}

static int getlink_get_ifdevs_cb(const struct nlmsghdr *nlh, void *data)
{
    bool *is_macvlan = data;
    struct ifinfomsg *ifinfo = mnl_nlmsg_get_payload(nlh);
    struct nlattr *attr;
    char kind[IFNAMSIZ] = {0};

    // Loop through all attributes of the netlink message
    mnl_attr_for_each(attr, nlh, sizeof(*ifinfo)) {
        int type = mnl_attr_get_type(attr);

        // Skip unsupported attributes
        if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
            continue;

        // Parse nested attributes for the link info
        if (type == IFLA_LINKINFO) {
            struct nlattr *link_attr;
            mnl_attr_for_each_nested(link_attr, attr) {
                if (mnl_attr_get_type(link_attr) == IFLA_INFO_KIND)
                    snprintf(kind, sizeof(kind), "%s",
                             mnl_attr_get_str(link_attr));
            }
        }
    }

    // Check if the interface is a macvlan
    if (strcmp(kind, "macvlan") == 0) {
        *is_macvlan = true;
    }
    return MNL_CB_OK;
}

static bool check_ifindex_is_macvlan(int ifindex)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifm;
    int ret;

    bool is_macvlan = false;
    if (env.disable_macvlan_filter)
        goto out;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++nlm_seq;

    ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifm->ifi_family = AF_UNSPEC;
    ifm->ifi_index = ifindex;

    pr_nl("sending netlink message\n");
    pr_nl_nlmsg(nlh, nlm_seq);

    // Send Netlink request update neigh table
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        pr_err(errno, "mnl_socket_sendto");
        goto out;
    }

    pr_nl("%s(%d): received netlink message\n");
    pr_nl_nlmsg((struct nlmsghdr *)buf, nlm_seq);

    ret = mnl_cb_run(buf, ret, nlm_seq, mnl_portid, getneigh_find_mac_cb,
                     &is_macvlan);

    while ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
        ret = mnl_cb_run(buf, ret, nlm_seq, mnl_portid, getlink_get_ifdevs_cb,
                         &is_macvlan);
        if (ret <= 0)
            break;
    }
    if (ret < 0)
        pr_err(errno, "mnl_cb_run");

out:
    return is_macvlan;
}

// Callback function to handle data from the ring buffer
static int handle_arp_reply(void *ctx, void *data, size_t data_sz)
{
    struct arp_reply *arp_reply = (struct arp_reply *)data;
    __u8 mac_str[MAC_ADDR_STR_LEN];
    char ifname[IFNAMSIZ];
    int dest_ifindex;

    mac_to_string(mac_str, arp_reply->mac, sizeof(mac_str));
    pr_debug("Received ARP Reply MAC: %s - IP: %s\n", mac_str,
             inet_ntoa(arp_reply->ip));

    dest_ifindex = find_ifindex_from_ip(&arp_reply->ip, ifname, sizeof(ifname));

    if (dest_ifindex < 0) {
        pr_debug("No interface mached destination: filtered\n");
        return 1;
    }
    if (strlen(ifname) && filter_interfaces(ifname)) {
        pr_debug("Interface '%s' matches regexp filter: filtered\n", ifname);
        return 1;
    }
    if (check_ifindex_is_macvlan(dest_ifindex)) {
        pr_debug("Interface '%s' is a macvlan: filtered\n", ifname);
        return 1;
    }
    if (!is_mac_local(arp_reply->mac)) {
        pr_debug("MAC address is not connected locally: filtered\n");
        return 1;
    }

    pr_debug("MAC is locally connected. Adding neighbor.\n");
    if (add_neigh(arp_reply, dest_ifindex))
        return 1;

    return 0;
}

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.debug)
        return 0;
    return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    static int pos_args;

    switch (key) {
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        case 'v':
            if (env.debug)
                env.netlink = true;
            if (env.verbose)
                env.debug = true;
            env.verbose = true;
            break;
        case 'f':
            if (strlen(arg) == 0) {
                fprintf(stderr, "Invalid filter\n");
                argp_usage(state);
                exit(EXIT_FAILURE);
            }
            env.regexp_filter_ifname = arg;
            env.has_filter = true;
            break;
        case 'x':
            env.is_xdp = true;
            break;
        case 'm':
            env.disable_macvlan_filter = true;
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
            pos_args++;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static void short_usage(FILE *fp, struct argp_state *state)
{
    fprintf(stderr, "Usage: %s [--help] [--verbose] <IFNAME_MON>\n",
            state->argv[0]);
}

int main(int argc, char **argv)
{
    struct neighsnoopd_bpf *skel;
    int err;
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
        .args_doc = "<IFNAME_MON>",
    };

    nlm_seq = time(NULL);

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        goto cleanup1;

    err = 0;
    if (env.has_filter)
        err = regcomp(&env.regex_filter, env.regexp_filter_ifname, REG_EXTENDED);

    if (err) {
        fprintf(stderr, "Could not compile regex");
        goto cleanup1;
    }

    libbpf_set_print(libbpf_print_fn);

    nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl == NULL) {
        err = errno;
        perror("mnl_socket_open");
        goto cleanup1;
    }
    mnl_portid = mnl_socket_get_portid(nl);
    pr_nl("MNL port ID: %d\n", mnl_portid);

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        err = -errno;
        perror("mnl_socket_bind");
        goto cleanup2;
    }

    // Open the skeleton
    skel = neighsnoopd_bpf__open();
    if (!skel) {
        perror("Failed to open BPF skeleton\n");
        err = EXIT_FAILURE;
        goto cleanup2;
    }

    err = neighsnoopd_bpf__load(skel);
    if (err) {
        perror("Failed to load BPF skeleton\n");
        err = EXIT_FAILURE;
        goto cleanup2;
    }

    // XDP
    struct bpf_link * xdp_link;

    // TC OPTS
    LIBBPF_OPTS(bpf_tc_hook, tc_hook,
                .ifindex = env.ifidx_mon,
                .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, tc_opts,
                .handle = 1,
                .priority = 1,
                .prog_fd = bpf_program__fd(skel->progs.handle_arp_reply_tc));

    bool hook_created = false;
    if (env.is_xdp) {
        // attach xdp program to interface
        bpf_program__attach_xdp(skel->progs.handle_arp_reply_xdp, env.ifidx_mon);
        if (!xdp_link) {
            perror("Failed to attach XDP hook");
            goto cleanup3;
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
        err = bpf_tc_hook_create(&tc_hook);
        if (!err)
            hook_created = true;
        if (err && err != -EEXIST)
            goto cleanup3;

        if (bpf_tc_attach(&tc_hook, &tc_opts))
            goto cleanup4;
    }

    // Parse ARP replies
    struct bpf_map *ringbuf_map =
        bpf_object__find_map_by_name(skel->obj, "arp_ringbuf");

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(ringbuf_map),
                                              handle_arp_reply, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer");
        goto cleanup5;
    }

    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        err = errno;
        perror("Can't set signal handler");
        goto cleanup6;
    }

    // Main loop
    while (!exiting) {
        int err = ring_buffer__poll(rb, -1);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer");
            break;
        }
    }
    err = 0;

    // Cleanup
cleanup6:
    ring_buffer__free(rb);
    close(bpf_map__fd(ringbuf_map));
cleanup5:
    tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
    if (!env.is_xdp) {
        err = bpf_tc_detach(&tc_hook, &tc_opts);
        if (err)
            perror("Failed to detach TC hook");
    }
cleanup4:
    if (hook_created) {
        err = bpf_tc_hook_destroy(&tc_hook);
        if (err)
            perror("Failed to destroy TC hook");
    }
cleanup3:
    neighsnoopd_bpf__destroy(skel);
cleanup2:
    mnl_socket_close(nl);
cleanup1:
    return -err;
}
