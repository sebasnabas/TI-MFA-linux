#ifndef TI_MFA_ALGO_H
#define TI_MFA_ALGO_H

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include "mpls.h"

/* run_ti_mfa() success codes */
#define TI_MFA_SUCCESS  0x00
#define TI_MFA_PASS     0x01    /* skb was not an mpls packet */
#define TI_MFA_ERROR    0x02
#define TI_MFA_RETRY    0x03

#define TI_MFA_MPLS_EXTENSION_HDR   mpls_entry_encode(MPLS_LABEL_EXTENSION, 255, 0, true);

// save deleted next_hops
extern struct ti_mfa_neigh **deleted_nhs;

struct ti_mfa_neigh {
    struct net_device  *nh_dev;
    u8 mac_address[ETH_ALEN];
};

struct ti_mfa_shim_hdr {
    unsigned char link_source[ETH_ALEN];
    unsigned char link_dest[ETH_ALEN];
    u8 bos;
} __attribute__((packed));

int run_ti_mfa(struct sk_buff *skb);
void ti_mfa_ifdown(struct net_device *dev);

static inline struct ti_mfa_shim_hdr *ti_mfa_hdr(const struct sk_buff *skb)
{
	return (struct ti_mfa_shim_hdr *)skb_network_header(skb);
}

#endif // TI_MFA_ALGO_H
