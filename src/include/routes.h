#ifndef TI_MFA_ROUTES_H
#define TI_MFA_ROUTES_H

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

int rt_add(struct ti_mfa_route rt);
int rt_del(struct ti_mfa_route rt);
int rt_show(char *dst, size_t size);
int rt_flush(void);
int rt_lookup_link(struct ti_mfa_link link);
bool links_equal(struct ti_mfa_link one, struct ti_mfa_link other);
#endif  /* TI_MFA_ROUTES_H */
