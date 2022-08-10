#ifndef TI_MFA_MPLS_H
#define TI_MFA_MPLS_H

#include <linux/mpls.h>
#include <linux/rtnetlink.h>

#include "internal/mpls.h"
#include "ti_mfa.h"

extern bool mpls_output_possible(struct net_device *dev);

static inline int parse_encap_mpls_labels(struct mpls_shim_hdr *hdr,
					  u32 labels[], int len)
{
	u8 label_count = len / 4;
	int i;

	for (i = label_count - 1; i >= 0; i--) {
		labels[i] = mpls_entry_decode(hdr + i).label;
	}

	return 0;
}

bool is_not_mpls(struct sk_buff *skb);
uint get_number_of_mpls_capable_net_devices(struct net *net);
void debug_print_mpls_entries(uint label_count,
			      const struct mpls_entry_decoded entries[]);
uint flush_mpls_label_stack(struct sk_buff *skb,
			    struct mpls_entry_decoded mpls_entries[],
			    int max_labels);
void set_mpls_header(struct sk_buff *skb, uint label_count,
		     const struct mpls_entry_decoded new_label_stack[],
		     bool add_extension_hdr);

#endif /* TI_MFA_MPLS_H */
