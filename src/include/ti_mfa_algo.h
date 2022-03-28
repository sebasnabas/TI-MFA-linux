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

#define TI_MFA_MPLS_EXTENSION_LABEL     MPLS_LABEL_EXTENSION    /* Indicate that a ti-mfa header follows the mpls header */
#define TI_MFA_MPLS_EXTENSION_HDR       mpls_entry_encode(TI_MFA_MPLS_EXTENSION_LABEL, 255, 0, true);

struct ti_mfa_shim_hdr {
    unsigned char link_source[ETH_ALEN];
    unsigned char link_dest[ETH_ALEN];
    unsigned char node_source[ETH_ALEN];
    u8            bos;
} __attribute__((packed));


struct ti_mfa_neigh {
    struct net_device  *dev;
    u8                  ha[ETH_ALEN];
    u8                  label_count;
    u32                 labels[MAX_NEW_LABELS]; /* LSPs via that neighbor */
};

struct ti_mfa_nh {
    struct net_device       *dev;
    unsigned char           ha[ETH_ALEN];
    u8                      labels;
    u8                      link_failure_count;
    u32                     label[MAX_NEW_LABELS];
    struct ti_mfa_shim_hdr  link_failures[MAX_NEW_LABELS];
};

int run_ti_mfa(struct net *net, struct sk_buff *skb);
void ti_mfa_ifdown(struct net_device *dev);
void ti_mfa_ifup(struct net_device *dev);
int initialize_ti_mfa(void);
void cleanup_ti_mfa(void);

static inline struct ti_mfa_shim_hdr *ti_mfa_hdr(const struct sk_buff *skb)
{
    return (struct ti_mfa_shim_hdr *)skb_network_header(skb);
}

#endif // TI_MFA_ALGO_H
