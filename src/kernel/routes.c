#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/if.h>
#include <linux/etherdevice.h>
#include <linux/jhash.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/rwlock.h>
#include <linux/slab.h>

#include "../include/routes.h"


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

struct ti_mfa_route *rt_lookup(struct ti_mfa_link link)
{
    struct ti_mfa_route *found_rt;
    u32 key = rt_hash(ink);
    hash_for_each_possible_rcu(backup_route_table, found_rt, hnode, key) {

        /* Possible TODO
         * Only accept one evasion route for each link failure for now
         */
        if (links_equal(found_rt->link, link))
            return found_rt;
    }
    return NULL;
}

int rt_add(struct ti_mfa_route new_route)
{
    int ret = -1;
    u32 hash_key;
    struct ti_mfa_route *rt;

    if (rt_lookup(new_route)) {
        pr_err("Route already exists\n");
        goto end;
    }

    rt = kmalloc(sizeof(*rt), GFP_KERNEL);
    if (!rt) {
        pr_err("Could not allocate memory for new route entry\n");
        ret = -ENOMEM;
        goto end;
    }

    *rt = new_route;

    hash_key = rt_hash(rt->link);
    write_lock_bh(&ti_mfa_rwlock);
    hash_add_rcu(backup_route_table, &rt->hnode, hash_key);
    write_unlock_bh(&ti_mfa_rwlock);

    ret = 0;
    goto end;

end:
    return ret;
}

int rt_del(struct ti_mfa_route rt)
{
    int ret = -1;
    u32 key;
    struct ti_mfa_route *found_rt = NULL;

    if (hash_empty(backup_route_table)) {
        pr_debug("Routing table is empty\n");
        goto end;
    }

    key = rt_hash(rt.link);
    hash_for_each_possible_rcu(backup_route_table, found_rt, hnode, key) {
        if (strcmp(found_rt->out_dev_name, rt.out_dev_name) == 0
                && links_equal(found_rt->link, rt.link)
                && found_rt->destination_label == rt.destination_label) {

            pr_debug("Deleting route for %u\n", found_rt->destination_label);
            hash_del_rcu(&found_rt->hnode);

            /* TODO: Figure out how to avoid freeze on free <19-04-22> */
            /* kfree(found_rt); */
            ret = 0;
       }
    }

end:
    return ret;
}

int rt_show(char *dst, size_t size)
{
    int i = 0, ret = -1;
    struct ti_mfa_route *rt;

    if (hash_empty(backup_route_table)) {
        pr_debug("Routing table is empty\n");
        goto end;
    }

    strcat(dst, "TI-MFA Backup Routes:\n");
    strcat(dst, "=====================\n");

    rcu_read_lock();
    hash_for_each_rcu(backup_route_table, i, rt, hnode) {
        sprintf(dst + strlen(dst), "\tDestination: %u\n", rt->destination_label);
        sprintf(dst + strlen(dst), "\tLink Source: %pM\n", rt->link.source);
        sprintf(dst + strlen(dst), "\tLink Dest:   %pM\n", rt->link.dest);
        sprintf(dst + strlen(dst), "\tOut dev:     %s\n", rt->out_dev_name);

        sprintf(dst + strlen(dst), "------------------\n");
    }
    rcu_read_unlock();

    ret = 0;

end:
    return ret;
}

int rt_flush(void)
{
    int i, ret = 0;
    struct ti_mfa_route *rt;
    struct hlist_node   *tmp;

    if (hash_empty(backup_route_table)) {
        pr_debug("table with backup routes is empty");
        goto end;
    }

    pr_debug("Flushing\n");

    hash_for_each_safe(backup_route_table, i, tmp, rt, hnode) {
        pr_debug("Deleting route for %u\n", rt->destination_label);
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

    return ret;
}

int storage_exit(void)
{
    int ret = 0;

    rt_flush();

    return ret;
}
