#include "debug.h"

#include <linux/if.h>
#include <linux/etherdevice.h>
#include <linux/jhash.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/rwlock.h>
#include <linux/slab.h>

#include "routes.h"

#define TABLE_SIZE 5  // 5 bits = 32 entries
static DEFINE_HASHTABLE(backup_route_table, TABLE_SIZE);    /* backup routes table */

rwlock_t ti_mfa_rwlock;

u32 rt_hash(struct ti_mfa_link link)
{
    unsigned char *key_to_hash;
    int key_length = 0;

    key_length += ETH_ALEN * 2;
    key_to_hash = kcalloc(sizeof(char), key_length, GFP_KERNEL);

    if (ether_addr_to_u64(link.source) < ether_addr_to_u64(link.dest)) {
        ether_addr_copy(&key_to_hash[0], link.source);
        ether_addr_copy(&key_to_hash[ETH_ALEN], link.dest);
    } else {
        ether_addr_copy(&key_to_hash[0], link.dest);
        ether_addr_copy(&key_to_hash[ETH_ALEN], link.source);
    }

    return jhash(key_to_hash, key_length, 0);
}

bool links_equal(struct ti_mfa_link one, struct ti_mfa_link other)
{
    bool equal = false;
    pr_debug("Comparing links: %pM-%pM & %pM-%pM\n", one.source, one.dest, other.source, other.dest);
    equal = ether_addr_equal(one.source, other.dest)
        || ether_addr_equal(one.dest, other.dest)
        || ether_addr_equal(one.source, other.source);

    return equal;
}

struct ti_mfa_route *rt_lookup(const struct net *net, struct ti_mfa_link link)
{
    struct ti_mfa_route *found_rt;
    u32 key = rt_hash(link);
    hash_for_each_possible_rcu(backup_route_table, found_rt, hnode, key) {

        /* Possible TODO
         * Only accept one evasion route for each link failure for now
         */
        if (links_equal(found_rt->link, link) && found_rt->net_ns == net)
            return found_rt;
    }
    return NULL;
}

int rt_add(struct ti_mfa_route new_route)
{
    int ret = TI_MFA_RT_OK;
    u32 hash_key;
    struct ti_mfa_route *rt;

    if (new_route.net_ns == NULL) {
        new_route.net_ns = &init_net;
    }

    if (rt_lookup(new_route.net_ns, new_route.link)) {
        pr_err("Route already exists\n");
        ret = TI_MFA_RT_ROUTE_ALREADY_EXISTS;
        goto end;
    }

    rt = kmalloc(sizeof(*rt), GFP_KERNEL);
    if (!rt) {
        pr_err("Could not allocate memory for new route entry\n");
        ret = TI_MFA_RT_NO_MEMORY;
        goto end;
    }

    *rt = new_route;

    hash_key = rt_hash(rt->link);
    write_lock_bh(&ti_mfa_rwlock);
    hash_add_rcu(backup_route_table, &rt->hnode, hash_key);
    write_unlock_bh(&ti_mfa_rwlock);

end:
    return ret;
}

int rt_del(struct ti_mfa_route rt)
{
    int ret = TI_MFA_RT_ROUTE_DOES_NOT_EXIST;
    u32 key;
    struct ti_mfa_route *found_rt = NULL;

    if (hash_empty(backup_route_table)) {
        pr_debug("Routing table is empty\n");
        ret = TI_MFA_RT_ROUTING_TABLE_EMPTY;
        goto end;
    }

    key = rt_hash(rt.link);
    hash_for_each_possible_rcu(backup_route_table, found_rt, hnode, key) {
        if (found_rt->out_dev == rt.out_dev
                && links_equal(found_rt->link, rt.link)
                && found_rt->destination_label == rt.destination_label) {

            pr_debug("Deleting route for %pM <-> %pM to %u\n", found_rt->link.source,
                    found_rt->link.dest, found_rt->destination_label);

            /*
             * decrease dev ref counter, since we increased it when using
             * dev_get_by_name(rt.net_ns, attr.backup_dev_name) in genl.c
             * NOTE: decrease it 2 times?
            */
            dev_put(found_rt->out_dev);

            hash_del_rcu(&found_rt->hnode);

            /* FIXME: Figure out how to avoid freeze on free <19-04-22> */
            /* kfree(found_rt); */
            ret = TI_MFA_RT_OK;
        }
    }

end:
    return ret;
}

int rt_del_for_dev(const struct net_device *dev)
{
    int i = 0;
    struct ti_mfa_route *rt;
    hash_for_each_rcu(backup_route_table, i, rt, hnode) {
        if (rt->out_dev != dev)
            continue;

        pr_info("Deleted backup route with dev %s for link %pM-%pM\n", rt->out_dev->name, rt->link.dest, rt->link.source);

        /*
         * decrease dev ref counter, since we increased it when using
         * dev_get_by_name(rt.net_ns, attr.backup_dev_name) in genl.c
        */
        dev_put(rt->out_dev);
        hash_del_rcu(&rt->hnode);
    }

    return TI_MFA_RT_OK;
}

int rt_show(const struct net *net, char *dst, size_t size)
{
    int i = 0, ret = TI_MFA_RT_OK;
    struct ti_mfa_route *rt;

    if (hash_empty(backup_route_table)) {
        pr_debug("Routing table is empty\n");
        ret = TI_MFA_RT_ROUTING_TABLE_EMPTY;
        goto end;
    }

    strcat(dst, "TI-MFA Backup Routes:\n");
    strcat(dst, "=====================\n");

    rcu_read_lock();
    hash_for_each_rcu(backup_route_table, i, rt, hnode) {
        if (net != NULL && rt->net_ns != net)
            continue;

        sprintf(dst + strlen(dst), "\tDestination:         %u\n", rt->destination_label);
        sprintf(dst + strlen(dst), "\tLink Source:         %pM\n", rt->link.source);
        sprintf(dst + strlen(dst), "\tLink Dest:           %pM\n", rt->link.dest);
        sprintf(dst + strlen(dst), "\tOut dev:             %s\n", rt->out_dev->name);
        sprintf(dst + strlen(dst), "\tNet NS is init_net:  %s\n", rt->net_ns == &init_net ? "True" : "False");
        sprintf(dst + strlen(dst), "\tNet NS is NULL:      %s\n", rt->net_ns == NULL ? "True" : "False");

        sprintf(dst + strlen(dst), "------------------\n");
    }
    rcu_read_unlock();

end:
    return ret;
}

int rt_flush(void)
{
    int i, ret = TI_MFA_RT_OK;
    struct ti_mfa_route *rt;
    struct hlist_node   *tmp;

    if (hash_empty(backup_route_table)) {
        pr_debug("table with backup routes is empty");
        ret = TI_MFA_RT_ROUTING_TABLE_EMPTY;
        goto end;
    }

    pr_debug("Flushing routing table\n");

    hash_for_each_safe(backup_route_table, i, tmp, rt, hnode) {
        pr_debug("Deleting route for %u\n", rt->destination_label);

        /*
         * decrease dev ref counter, since we increased it when using
         * dev_get_by_name(rt.net_ns, attr.backup_dev_name) in genl.c
        */
        dev_put(rt->out_dev);
        hash_del_rcu(&rt->hnode);
        kfree(rt);
    }

end:
    return ret;
}

int storage_init(void)
{
    int ret = 0;

    hash_init(backup_route_table);

    pr_debug("Routing table initialized\n");

    return ret;
}

int storage_exit(void)
{
    int ret = 0;

    rt_flush();

    pr_debug("Routing table cleaned up\n");

    return ret;
}
