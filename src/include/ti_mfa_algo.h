#ifndef TI_MFA_ALGO_H
#define TI_MFA_ALGO_H

#include "mpls.h"

// save deleted next_hops
extern struct ti_mfa_nh **deleted_nhs;

struct ti_mfa_nh {
    struct net_device  *nh_dev;
    u8 mac_address[ETH_ALEN];
};

struct ti_mfa_hdr {
    unsigned char link_source[ETH_ALEN];
    unsigned char link_dest[ETH_ALEN];
    u8 bos;
} __attribute__((packed));

int run_timfa(struct sk_buff *skb);

#endif // TI_MFA_ALGO_H