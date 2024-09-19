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
    bool is_xdp;
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

    // Send Netlink request to fetch FDB entries
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        pr_err(errno, "mnl_socket_sendto");
        return false;
    }

    // Parse the response
    while ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
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

    libbpf_set_print(libbpf_print_fn);

    nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl == NULL) {
        err = errno;
        perror("mnl_socket_open");
        goto cleanup1;
    }
    mnl_portid = mnl_socket_get_portid(nl);

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
