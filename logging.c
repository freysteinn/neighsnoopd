#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>

#include "neighsnoopd.h"

extern struct env env;

void mac_to_string(__u8 *buffer, const __u8 *mac, size_t buffer_size)
{
    if (buffer_size < MAC_ADDR_STR_LEN) { // "XX:XX:XX:XX:XX:XX" + null terminator
        buffer[0] = '\0'; // Not enough space, return an empty string
        return;
    }
    snprintf((char *)buffer, buffer_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void __pr_std(FILE * file, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);
}

int pr_nl_attr_neigh(const struct nlattr *attr, void *data)
{
    int type = mnl_attr_get_type(attr);
    __u8 mac_str[MAC_ADDR_STR_LEN];

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

int pr_nl_neigh_ndm(const struct nlmsghdr *nlh)
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

int pr_nl_attr(const struct nlattr *attr, void *data)
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

int pr_nl_ndm(const struct nlmsghdr *nlh)
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

void pr_nl_nlmsg(struct nlmsghdr *nlh, __u32 seq)
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
