#ifndef TI_MFA_H
#define TI_MFA_H

#include <linux/etherdevice.h>
#include <linux/skbuff.h>

// /* Copied from /net/mpls/internal.h */
#define MAX_NEW_LABELS 30

#define TI_MFA_MPLS_EXTENSION_LABEL     MPLS_LABEL_EXTENSION    /* Indicate that a ti-mfa header follows the mpls header */
#define TI_MFA_MPLS_EXTENSION_HDR       mpls_entry_encode(TI_MFA_MPLS_EXTENSION_LABEL, 255, 0, true);

struct ti_mfa_link {
    unsigned char source[ETH_ALEN];
    unsigned char dest[ETH_ALEN];
};

struct ti_mfa_route {
    struct ti_mfa_link link;
    unsigned int       destination_label;
    struct net_device  *out_dev;
    struct net         *net_ns;
    struct hlist_node  hnode;
};

struct ti_mfa_shim_hdr {
    unsigned char node_source[ETH_ALEN];
    struct ti_mfa_link link;
    u8            bos;
} __attribute__((packed));

struct ti_mfa_neigh {
    struct net         *net;
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
    bool                    is_dest;
};

static inline struct ti_mfa_shim_hdr *ti_mfa_hdr(const struct sk_buff *skb)
{
    return (struct ti_mfa_shim_hdr *)skb_network_header(skb);
}

static inline struct ti_mfa_link ti_mfa_hdr_to_link(const struct ti_mfa_shim_hdr hdr)
{
    struct ti_mfa_link link;
    ether_addr_copy(link.source, hdr.link.source);
    ether_addr_copy(link.dest, hdr.link.dest);
    return link;
}

#endif /* TI_MFA_H */
