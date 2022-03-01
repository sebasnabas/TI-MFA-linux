#ifndef TI_MFA_MPLS_H
#define TI_MFA_MPLS_H

#include <net/mpls.h>
#include <linux/mpls.h>

#define MPLS_LABEL(x)   (x & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
#define MPLS_TC(x)      (x & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT;
#define MPLS_STACK(x)   (x & MPLS_LS_TC_MASK) >> MPLS_LS_TC_SHIFT;
#define MPLS_TTL(x)     (x & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT;

static inline u32 mpls_decode_label(const struct mpls_shim_hdr *hdr){
    unsigned entry = be32_to_cpu(hdr->label_stack_entry);
    return MPLS_LABEL(entry);
}

static inline int parse_encap_mpls_labels(const struct mpls_shim_hdr *hdr, u32 label[], int len)
{
    u8 label_count = len / 4;
    int i;

    for (i = label_count - 1; i >= 0; i--)
    {
        label[i] = mpls_decode_label(hdr + i);
    }

    return 0;
}

#endif /* TI_MFA_MPLS_H */