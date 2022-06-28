#ifndef TI_MFA_ROUTES_H
#define TI_MFA_ROUTES_H

#include <linux/hashtable.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/kernel.h>

#include "ti_mfa.h"

enum ti_mfa_route_exit_code {
    TI_MFA_RT_OK,
    TI_MFA_RT_NO_MEMORY,
    TI_MFA_RT_ROUTING_TABLE_EMPTY,
    TI_MFA_RT_ROUTE_ALREADY_EXISTS,
    TI_MFA_RT_ROUTE_DOES_NOT_EXIST
};

u32 rt_hash(struct ti_mfa_link link);
int rt_add(struct ti_mfa_route rt);
int rt_del(struct ti_mfa_route rt);
int rt_show(struct net *net, char *dst, size_t size);
int rt_flush(void);
struct ti_mfa_route *rt_lookup(const struct net *net, struct ti_mfa_link link);
bool links_equal(struct ti_mfa_link one, struct ti_mfa_link other);

int storage_init(void);
int storage_exit(void);

#endif  /* TI_MFA_ROUTES_H */
