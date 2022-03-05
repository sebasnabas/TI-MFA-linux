#ifndef TI_MFA_ALGO_H
#define TI_MFA_ALGO_H

#include "mpls.h"

// save deleted next_hops
extern struct ti_mfa_nh *deleted_nhs;

struct ti_mfa_nh {
    struct net_device  *nh_dev;
    u8 mac_address[ETH_ALEN];
};

struct ti_mfa_hdr {
    u8 link_source[ETH_ALEN];
    u8 link_dest[ETH_ALEN];
};

int run_timfa(struct sk_buff *skb);

#endif // TI_MFA_ALGO_H