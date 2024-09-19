/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 1984 <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#ifndef NEIGHSNOOPD_H_
#define NEIGHSNOOPD_H_

struct arp_reply {
    __be16 vlan_id;
    union {
        struct in_addr ip;
        __u8 ip_bytes[4];
    };
    __u8 mac[6];
};

#endif // NEIGHSNOOPD_H_
