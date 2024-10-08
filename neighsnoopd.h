/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#ifndef NEIGHSNOOPD_H_
#define NEIGHSNOOPD_H_

#include <stdio.h>
#include <stdbool.h>
#include <linux/types.h>
#include <net/if.h>
#include <regex.h>

#define MAC_ADDR_STR_LEN 18

struct env {
    int ifidx_mon;
    char ifidx_mon_str[IF_NAMESIZE];
    char *regexp_filter_ifname;
    regex_t regex_filter;
    bool has_filter;
    bool is_xdp;
    bool disable_macvlan_filter;
    bool fail_on_qfilter_present;
    bool verbose;
    bool debug;
    bool has_count;
    int count;
    bool netlink;
};

void mac_to_string(__u8 *buffer, const __u8 *mac, size_t buffer_size);

// Print functions
void __pr_std(FILE * file, const char *format, ...);

// Print functions for Netlink messages
int pr_nl_attr_neigh(const struct nlattr *attr, void *data);
int pr_nl_neigh_ndm(const struct nlmsghdr *nlh);
int pr_nl_attr(const struct nlattr *attr, void *data);
int pr_nl_ndm(const struct nlmsghdr *nlh);
void pr_nl_nlmsg(struct nlmsghdr *nlh, __u32 seq);

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

#endif // NEIGHSNOOPD_H_
