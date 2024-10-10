/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SPDX-FileCopyrightText: 2024 - 1984 Hosting Company <1984@1984.is> */
/* SPDX-FileCopyrightText: 2024 - Freyx Solutions <frey@freyx.com> */
/* SPDX-FileContributor: Freysteinn Alfredsson <freysteinn@freysteinn.com> */
/* SPDX-FileContributor: Julius Thor Bess Rikardsson <juliusbess@gmail.com> */

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <linux/neighbour.h>

#include "neighsnoopd.h"

extern struct env env;

static GHashTable *db_vlan_network_cache;
static GHashTable *db_link_cache;
static GHashTable *db_network_cache;
static GHashTable *db_fdb_cache;
static GHashTable *db_neigh_cache;

struct link_cache *cache_add_link(struct netlink_link_cmd *link)
{
    struct link_cache *cache = NULL;

    cache = g_new0(struct link_cache, 1);
    if (!cache) {
        pr_err(errno, "g_new0");
        goto out;
    }

    cache->ifindex = link->ifindex;
    snprintf(cache->ifname, sizeof(cache->ifname), "%s", link->ifname);
    snprintf(cache->kind, sizeof(cache->kind), "%s", link->kind);
    snprintf(cache->slave_kind, sizeof(cache->slave_kind), "%s", link->slave_kind);
    cache->vlan_id = link->vlan_id;
    cache->vlan_protocol = link->vlan_protocol;
    cache->has_vlan = link->has_vlan;

    cache->network_list = NULL;
    cache->fdb_list = NULL;

    cache->times.created = cache->times.referenced = get_time();
    cache->times.referenced = get_time();

    g_hash_table_insert(db_link_cache, GINT_TO_POINTER(cache->ifindex), cache);

out:
    return cache;
}

static guint vlan_network_cache_key_hash(gconstpointer key) {
    const struct vlan_network_cache_key *k = key;
    guint hash = 0;

    // Hash the Network ID
    hash = hash * 31 + g_int_hash(&k->network_id);

    // Hash the VLAN ID
    hash = hash * 31 + g_int_hash(&k->vlan_id);

    return hash;
}

static gboolean vlan_network_cache_key_equal(gconstpointer left, gconstpointer right) {
    const struct vlan_network_cache_key *key_left = left;
    const struct vlan_network_cache_key *key_right = right;

    // Compare Network ID
    if (key_left->network_id != key_right->network_id)
        return false;

    // Compare VLAN IDs
    if (key_left->vlan_id != key_right->vlan_id)
        return false;

    return true;
}

struct link_cache *cache_get_link(__u32 ifindex)
{
    struct link_cache *cache;

    cache = g_hash_table_lookup(db_link_cache, GINT_TO_POINTER(ifindex));
    if (!cache)
        return NULL;

    cache->times.referenced = get_time();
    cache->reference_count++;

    return cache;
}

int cache_del_link(struct netlink_link_cmd *link)
{
    int ret = -1;
    struct link_cache *cache = g_hash_table_lookup(db_link_cache,
                                                   GINT_TO_POINTER(link->ifindex));
    GList *iter;
    if (!cache)
        goto out;

    for (iter = cache->network_list; iter; iter = g_list_next(iter)) {
        struct network_cache *network = iter->data;
        struct vlan_network_cache *vlan_network_cache;

        struct vlan_network_cache_key key = {
            .network_id = network->id,
            .vlan_id = cache->vlan_id,
        };

        vlan_network_cache = g_hash_table_lookup(db_vlan_network_cache, &key);
        if (vlan_network_cache) {
            g_hash_table_remove(db_vlan_network_cache, &key);
            g_free(vlan_network_cache);
        } else {
            pr_err(0, "VLAN network cache not found for %d/%d\n",
                   network->id, cache->vlan_id);
        }

        g_hash_table_remove(db_network_cache, GINT_TO_POINTER(network->id));
    }

    for (iter = cache->fdb_list; iter; iter = g_list_next(iter)) {
        struct fdb_cache *fdb = iter->data;
        struct fdb_cache_key key = {
            .ifindex = fdb->link->ifindex,
            .vlan_id = fdb->vlan_id,
        };
        g_hash_table_remove(db_fdb_cache, &key);
    }

    g_hash_table_remove(db_link_cache, GINT_TO_POINTER(link->ifindex));
    g_free(cache);

    ret = 0;

out:
    return ret;
}

struct vlan_network_cache *cache_get_vlan_network_by_reply(
    struct neighbor_reply *neighbor_reply)
{
    struct vlan_network_cache *cache;
    struct vlan_network_cache_key key = {
        .network_id = neighbor_reply->network_id,
        .vlan_id = neighbor_reply->vlan_id,
    };

    cache = g_hash_table_lookup(db_vlan_network_cache, &key);

    return cache;
}

struct network_cache *cache_add_network(struct netlink_addr_cmd *addr)
{
    struct network_cache *cache = NULL;
    struct link_cache *link_cache;
    struct vlan_network_cache_key *vlan_network_cache_key;
    struct vlan_network_cache *vlan_network_cache;
    struct network_entry key;
    struct network_value value = {0};

    static __u32 id = 1;

    link_cache = cache_get_link(addr->ifindex);
    if (!link_cache)
        goto out;

    cache = g_new0(struct network_cache, 1);
    if (!cache) {
        pr_err(errno, "g_new0");
        goto out;
    }

    cache->id = id++;
    cache->network = addr->ip;
    cache->prefixlen = addr->prefixlen;
    cache->true_prefixlen = addr->true_prefixlen;
    format_ip_address(cache->network_str, sizeof(cache->network_str),
                      &cache->network);

    link_cache->network_list = g_list_append(link_cache->network_list, cache);

    // Add to the network cache
    g_hash_table_insert(db_network_cache, &cache->id, cache);

    // Add to the VLAN/Network cache
    vlan_network_cache = g_new0(struct vlan_network_cache, 1);
    if (!vlan_network_cache) {
        pr_err(errno, "g_new0");
        goto out;
    }

    // Add the VLAN/Network to the cache
    vlan_network_cache->network = cache;
    vlan_network_cache->link = link_cache;

    // Prep the key
    vlan_network_cache_key = g_new0(struct vlan_network_cache_key, 1);
    if (!vlan_network_cache_key) {
        pr_err(errno, "g_new0");
        goto out;
    }
    vlan_network_cache_key->network_id = cache->id;
    vlan_network_cache_key->vlan_id = link_cache->vlan_id;

    // Insert the VLAN/Network cache
    g_hash_table_insert(db_vlan_network_cache, vlan_network_cache_key,
                        vlan_network_cache);

    // Add the network to the eBPF
    key.prefixlen = cache->prefixlen;

    memcpy(&key.network, &cache->network, sizeof(cache->network));

    value.network_id = cache->id;
    if (bpf_map_update_elem(env.target_networks_fd, &key, &value,
                            BPF_ANY) < 0) {
        pr_err(errno, "bpf_map_update_elem");
        goto out;
    }

    cache->times.created = get_time();
    cache->times.referenced = cache->times.created;

out:
    return cache;
}

struct network_cache *cache_get_network_by_id(__u32 network_id)
{
    struct network_cache *cache = NULL;

    cache = g_hash_table_lookup(db_network_cache, &network_id);
    if (!cache)
        goto out;

    cache->times.referenced = get_time();
    cache->reference_count++;

out:
    return cache;
}

struct network_cache *cache_get_network(struct netlink_addr_cmd *cmd)
{
    struct network_cache *network;
    struct link_cache *link;
    GList *iter;

    link = cache_get_link(cmd->ifindex);
    if (!link)
        return NULL;

    // Check if the network is already cached
    for (iter = link->network_list; iter; iter = g_list_next(iter)) {
        network = iter->data;
        if (compare_ipv6_addresses(&network->network, &cmd->ip) &&
            network->prefixlen == cmd->prefixlen) {
            return network;
        }
    }
    return NULL;
}

int cache_del_network(struct netlink_addr_cmd *addr)
{
    struct link_cache *link_cache;
    GList *iter;
    struct network_cache *network;
    struct network_entry key = {0};
    bool found = false;

    link_cache = cache_get_link(addr->ifindex);
    if (!link_cache)
        return 0;

    for (iter = link_cache->network_list; iter; iter = g_list_next(iter)) {
        network = iter->data;
        if (compare_ipv6_addresses(&network->network, &addr->ip) &&
            network->prefixlen == addr->prefixlen) {

            link_cache->network_list = g_list_delete_link(link_cache->network_list, iter);
            g_hash_table_remove(db_network_cache, GINT_TO_POINTER(network->id));
            found = true;
            break;
        }
    }

    if (!found)
        return 0;

    // Remove the network from the eBPF
    key.prefixlen = addr->prefixlen;

    memcpy(&key.network, &addr->ip, sizeof(addr->ip));

    if (bpf_map_delete_elem(env.target_networks_fd, &key) < 0) {
        pr_err(errno, "bpf_map_delete_elem");
        return errno;
    }

    return 0;
}

static guint fdb_cache_key_hash(gconstpointer key) {
    const struct fdb_cache_key *k = key;
    guint hash = 0;

    // Hash the MAC address (treat as binary data)
    for (guint i = 0; i < ETH_ALEN; i++) {
        hash = hash * 31 + k->mac[i];
    }

    // Hash the ifindex
    hash = hash * 31 + g_int_hash(&k->ifindex);

    // Hash the VLAN ID
    hash = hash * 31 + g_int_hash(&k->vlan_id);

    return hash;
}

static gboolean fdb_cache_key_equal(gconstpointer left, gconstpointer right) {
    const struct fdb_cache_key *key_left = left;
    const struct fdb_cache_key *key_right = right;

    // Compare MAC addresses
    if (memcmp(key_left->mac, key_right->mac, ETH_ALEN) != 0)
        return false;

    // Compare ifindex
    if (key_left->ifindex != key_right->ifindex)
        return false;

    // Compare VLAN IDs
    if (key_left->vlan_id != key_right->vlan_id)
        return false;

    return true;
}

struct fdb_cache *cache_get_fdb(struct netlink_neigh_cmd *neigh)
{
    struct fdb_cache *cache = NULL;
    struct fdb_cache_key *key;

    key = g_new0(struct fdb_cache_key, 1);
    if (!key) {
        pr_err(errno, "g_new0");
        goto out;
    }

    memcpy(key->mac, neigh->mac, ETH_ALEN);
    key->ifindex = neigh->ifindex;
    key->vlan_id = neigh->vlan_id;

    cache = g_hash_table_lookup(db_fdb_cache, key);
    if (!cache)
        goto out;

    cache->times.referenced = get_time();
    cache->reference_count++;

out:
    return cache;
}

struct fdb_cache *cache_get_fdb_by_reply(struct neighbor_reply *neighbor_reply,
                                         int ifindex)
{
    struct netlink_neigh_cmd neigh = {
        .vlan_id = neighbor_reply->vlan_id,
        .ifindex = ifindex,
    };

    memcpy(neigh.mac, neighbor_reply->mac, ETH_ALEN);

    return cache_get_fdb(&neigh);
}

struct fdb_cache *cache_add_fdb(struct netlink_neigh_cmd *neigh)
{
    struct link_cache *link;
    struct fdb_cache *cache = NULL;
    struct fdb_cache_key *key;

    key = g_new0(struct fdb_cache_key, 1);
    if (!key) {
        pr_err(errno, "g_new0");
        goto out;
    }
    memcpy(key->mac, neigh->mac, ETH_ALEN);
    key->ifindex = neigh->ifindex;
    key->vlan_id = neigh->vlan_id;

    link = cache_get_link(neigh->ifindex);
    if (!link) {
        pr_err(0, "FDB cache: Lookup: NIC: %d > Not found\n", neigh->ifindex);
        goto out;
    }

    cache = g_new0(struct fdb_cache, 1);
    if (!cache) {
        pr_err(errno, "g_new0");
        goto out;
    }

    memcpy(cache->mac, neigh->mac, ETH_ALEN);
    cache->link = link;
    cache->vlan_id = neigh->vlan_id;

    mac_to_string(cache->mac_str, cache->mac, sizeof(cache->mac_str));

    cache->times.created = get_time();
    cache->times.referenced = cache->times.created;

    g_hash_table_insert(db_fdb_cache, key, cache);

out:
    return cache;
}

int cache_del_fdb(struct netlink_neigh_cmd *neigh)
{
    int ret = -1;
    struct fdb_cache *cache;
    struct fdb_cache_key key;

    memcpy(key.mac, neigh->mac, ETH_ALEN);
    key.ifindex = neigh->ifindex;
    key.vlan_id = neigh->vlan_id;

    cache = g_hash_table_lookup(db_fdb_cache, &key);
    if (!cache)
        goto out;

    g_hash_table_remove(db_fdb_cache, &key);
    ret = 0;
out:
    return ret;
}

static guint neigh_cache_key_hash(gconstpointer key) {
    const struct neigh_cache_key *k = key;
    guint hash = 0;

    // Hash the MAC address (treat as binary data)
    for (guint i = 0; i < ETH_ALEN; i++) {
        hash = hash * 31 + k->mac[i];
    }

    // Hash the ifindex
    hash = hash * 31 + g_int_hash(&k->ifindex);

    // Hash the IP address
    for (guint i = 0; i < sizeof(k->ip); i++)
        hash = hash * 31 + k->ip.s6_addr[i];

    return hash;
}

static gboolean neigh_cache_key_equal(gconstpointer left, gconstpointer right) {
    const struct neigh_cache_key *key_left = left;
    const struct neigh_cache_key *key_right = right;

    // Compare MAC addresses
    if (memcmp(key_left->mac, key_right->mac, ETH_ALEN) != 0)
        return false;

    // Compare ifindex
    if (key_left->ifindex != key_right->ifindex)
        return false;

    // Compare IP addresses
    if (memcmp(&key_left->ip, &key_right->ip, sizeof(key_left->ip)) != 0)
        return false;

    return true;
}

struct neigh_cache *cache_add_neigh(struct netlink_neigh_cmd *neigh)
{
    struct neigh_cache *cache = NULL;
    struct neigh_cache_key *key;

    key = g_new0(struct neigh_cache_key, 1);
    if (!key) {
        pr_err(errno, "g_new0");
        goto out;
    }

    memcpy(key->mac, neigh->mac, ETH_ALEN);
    key->ifindex = neigh->ifindex;
    memcpy(&key->ip, &neigh->ip, sizeof(key->ip));

    cache = g_new0(struct neigh_cache, 1);
    if (!cache) {
        pr_err(errno, "g_new0");
        goto out;
    }

    cache->link = cache_get_link(neigh->ifindex);
    if (!cache->link)
        goto out;

    memcpy(cache->mac, neigh->mac, ETH_ALEN);
    memcpy(&cache->ip, &neigh->ip, sizeof(cache->ip));
    mac_to_string(cache->mac_str, cache->mac, sizeof(cache->mac_str));
    format_ip_address(cache->ip_str, sizeof(cache->ip_str), &cache->ip);
    cache->nud_state = neigh->nud_state;

    cache->times.created = cache->times.referenced = get_time();
    cache->times.referenced = get_time();

    g_hash_table_insert(db_neigh_cache, key, cache);

out:
    return cache;
}

struct neigh_cache *cache_get_neigh(struct netlink_neigh_cmd *neigh)
{
    struct neigh_cache *cache = NULL;
    struct neigh_cache_key key;

    memcpy(key.mac, neigh->mac, ETH_ALEN);
    key.ifindex = neigh->ifindex;
    memcpy(&key.ip, &neigh->ip, sizeof(key.ip));

    cache = g_hash_table_lookup(db_neigh_cache, &key);
    if (!cache)
        goto out;

    cache->times.referenced = get_time();
    cache->reference_count++;

out:
    return cache;
}

struct neigh_cache *cache_get_neigh_by_reply(struct neighbor_reply *neighbor_reply,
                                             int ifindex)
{
    struct netlink_neigh_cmd neigh = {
        .ifindex = ifindex,
    };
    memcpy(neigh.mac, neighbor_reply->mac, ETH_ALEN);
    memcpy(&neigh.ip, &neighbor_reply->ip, sizeof(neigh.ip));

    return cache_get_neigh(&neigh);
}

int cache_neigh_update(struct netlink_neigh_cmd *neigh)
{
    struct neigh_cache *cache;
    struct neigh_cache_key key;

    memcpy(key.mac, neigh->mac, ETH_ALEN);
    key.ifindex = neigh->ifindex;
    memcpy(&key.ip, &neigh->ip, sizeof(key.ip));

    cache = g_hash_table_lookup(db_neigh_cache, &key);
    if (!cache)
        return -ENOENT;

    if (neigh->nud_state != cache->nud_state) {
        cache->nud_state = neigh->nud_state;
        cache->times.referenced = get_time();
        cache->times.updated = get_time();
        cache->update_count++;

        pr_debug("Neigh cache: Update: IP: %s MAC: %s nic: %s ",
                 cache->ip_str, cache->mac_str, cache->link->ifname);
        if (cache->nud_state == NUD_REACHABLE)
            __pr_debug("State: REACHABLE\n");
        else if (cache->nud_state == NUD_STALE)
            __pr_debug("State: STALE\n");
        else if (cache->nud_state == NUD_DELAY)
            __pr_debug("State: DELAY\n");
        else if (cache->nud_state == NUD_PROBE)
            __pr_debug("State: PROBE\n");
        else if (cache->nud_state == NUD_FAILED)
            __pr_debug("State: FAILED\n");
        else
            __pr_debug("State: UNKNOWN\n");
    }

    return 0;
}

int cache_del_neigh(struct netlink_neigh_cmd *neigh)
{
    int ret = -1;
    struct neigh_cache *cache;
    struct neigh_cache_key key;

    memcpy(key.mac, neigh->mac, ETH_ALEN);
    key.ifindex = neigh->ifindex;
    memcpy(&key.ip, &neigh->ip, sizeof(key.ip));

    cache = g_hash_table_lookup(db_neigh_cache, &key);
    if (!cache)
        goto out;

    g_hash_table_remove(db_neigh_cache, &key);
    g_free(cache);

    ret = 0;

out:
    return ret;
}

// Cache setup and cleanup functions
int setup_cache(void)
{
    db_vlan_network_cache = g_hash_table_new_full(vlan_network_cache_key_hash,
                                                  vlan_network_cache_key_equal,
                                                  g_free, g_free);
    if (!db_vlan_network_cache) {
        pr_err(errno, "g_hash_table_new");
        goto out;
    }

    db_link_cache = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!db_link_cache) {
        pr_err(errno, "g_hash_table_new");
        goto out;
    }

    db_network_cache = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!db_network_cache) {
        pr_err(errno, "g_hash_table_new");
        goto out;
    }

    db_fdb_cache = g_hash_table_new_full(fdb_cache_key_hash, fdb_cache_key_equal,
                                    g_free, g_free);
    if (!db_fdb_cache) {
        pr_err(errno, "g_hash_table_new");
        goto out;
    }

    db_neigh_cache = g_hash_table_new_full(neigh_cache_key_hash, neigh_cache_key_equal,
                                           g_free, g_free);
    if (!db_neigh_cache) {
        pr_err(errno, "g_hash_table_new");
        goto out;
    }

out:
    return errno;
}

void cleanup_cache(void)
{
    if (db_vlan_network_cache) {
        for (GList *iter = g_hash_table_get_values(db_vlan_network_cache);
             iter; iter = g_list_next(iter)) {
            g_free(iter->data);
        }
        g_hash_table_destroy(db_vlan_network_cache);
    }

    if (db_link_cache) {
        for (GList *iter = g_hash_table_get_values(db_link_cache);
             iter; iter = g_list_next(iter)) {
            cache_del_link(iter->data);
            g_free(iter->data);
        }
        g_hash_table_destroy(db_link_cache);
    }

    if (db_network_cache)
        g_hash_table_destroy(db_network_cache);

    if (db_fdb_cache)
        g_hash_table_destroy(db_fdb_cache);

    if (db_neigh_cache)
        g_hash_table_destroy(db_neigh_cache);
}
