#ifndef TI_MFA_ALGO_H
#define TI_MFA_ALGO_H

#include "mpls.h"

/* run_ti_mfa() success codes */
#define TI_MFA_SUCCESS  0x00
#define TI_MFA_PASS     0x01    /* skb was not an mpls packet */
#define TI_MFA_ERROR    0x02
#define TI_MFA_RETRY    0x03

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

int run_ti_mfa(struct sk_buff *skb);

#endif // TI_MFA_ALGO_H
