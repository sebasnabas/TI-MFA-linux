#ifndef TI_MFA_ROUTES_H
#define TI_MFA_ROUTES_H

#include <linux/hashtable.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/kernel.h>

struct ti_mfa_link {
    unsigned char source[ETH_ALEN];
    unsigned char dest[ETH_ALEN];
};

struct ti_mfa_route {
    struct ti_mfa_link link;
    unsigned int       destination_label;
    char               out_dev_name[IFNAMSIZ];
    struct hlist_node  hnode;
};

u32 rt_hash(struct ti_mfa_link link);
int rt_add(struct ti_mfa_route rt);
int rt_del(struct ti_mfa_route rt);
int rt_show(char *dst, size_t size);
int rt_flush(void);
int rt_lookup_link(struct ti_mfa_link link);
bool links_equal(struct ti_mfa_link one, struct ti_mfa_link other);

#define TABLE_SIZE 5  // 5 bits = 32 entries
static DEFINE_HASHTABLE(backup_route_table, TABLE_SIZE);    /* backup routes table */

#define for_each_route(link)      \
    struct ti_mfa_route *found_rt; \
    u32 key = rt_hash(link);        \
    rcu_read_lock();                 \
    hash_for_each_possible_rcu(backup_route_table, found_rt, hnode, key) {

#define end_for_each_route(void) } rcu_read_unlock();

#endif  /* TI_MFA_ROUTES_H */
