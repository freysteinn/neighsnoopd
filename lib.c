/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 1984 <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "neighsnoopd.h"


void mac_to_string(__u8 *buffer, const __u8 *mac, size_t buffer_size)
{
    if (buffer_size < MAC_ADDR_STR_LEN) { // "XX:XX:XX:XX:XX:XX" + null terminator
        buffer[0] = '\0'; // Not enough space, return an empty string
        return;
    }
    snprintf((char *)buffer, buffer_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void calculate_network_address(const struct in6_addr *ip,
                               const struct in6_addr *netmask,
                               struct in6_addr *network)
{
    for (int i = 0; i < 16; i++)
        network->s6_addr[i] = ip->s6_addr[i] & netmask->s6_addr[i];
}

int compare_ipv6_addresses(const struct in6_addr *addr1,
                           const struct in6_addr *addr2)
{
    return memcmp(addr1, addr2, sizeof(struct in6_addr)) == 0;
}

/*
 * Handle printing IPv4 addresses without the ::ffff: prefix
 */
int format_ip_address(char *buf, size_t size, const struct in6_addr *addr)
{
    if (IN6_IS_ADDR_V4MAPPED(addr))
        return inet_ntop(AF_INET, &addr->s6_addr[12], buf, size) == 0;
    else
        return inet_ntop(AF_INET6, addr, buf, size) == 0;
}

/*
 * Function to calculate the CIDR of an IPv6 address
 */
int calculate_cidr(const struct in6_addr *addr) {
    int cidr = 0;

    // Check if the address is an IPv4-mapped IPv6 address
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        // Extract the IPv4 part (last 4 bytes)
        struct in_addr ipv4_addr;
        memcpy(&ipv4_addr, &addr->s6_addr[12], sizeof(ipv4_addr));

        cidr = __builtin_popcount(ntohl(ipv4_addr.s_addr));
    } else {
        // Count the number of set bits in the IPv6 address
        for (int i = 0; i < 4; i++)
            cidr += __builtin_popcountl(addr->__in6_u.__u6_addr32[i]);
    }
    return cidr;
}
