#ifndef TI_MFA_MPLS_H
#define TI_MFA_MPLS_H

#include <net/mpls.h>
#include <linux/mpls.h>
#include <linux/rtnetlink.h>

#include "ti_mfa.h"

extern bool mpls_output_possible(struct net_device *dev);

#define MPLS_LABEL(x)   (x & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
#define MPLS_TC(x)      (x & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT;
#define MPLS_STACK(x)   (x & MPLS_LS_TC_MASK) >> MPLS_LS_TC_SHIFT;
#define MPLS_TTL(x)     (x & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT;


enum mpls_payload_type {
	MPT_UNSPEC, /* IPv4 or IPv6 */
	MPT_IPV4 = 4,
	MPT_IPV6 = 6,

	/* Other types not implemented:
	 *  - Pseudo-wire with or without control word (RFC4385)
	 *  - GAL (RFC5586)
	 */
};

struct mpls_nh { /* next hop label forwarding entry */
	struct net_device	*nh_dev;

	/* nh_flags is accessed under RCU in the packet path; it is
	 * modified handling netdev events with rtnl lock held
	 */
	unsigned int		nh_flags;
	u8			nh_labels;
	u8			nh_via_alen;
	u8			nh_via_table;
	u8			nh_reserved1;

	u32			nh_label[];
};

/* offset of via from beginning of mpls_nh */
#define MPLS_NH_VIA_OFF(num_labels) \
		ALIGN(sizeof(struct mpls_nh) + (num_labels) * sizeof(u32), \
		      VIA_ALEN_ALIGN)

/* all nexthops within a route have the same size based on the
 * max number of labels and max via length across all nexthops
 */
#define MPLS_NH_SIZE(num_labels, max_via_alen)		\
		(MPLS_NH_VIA_OFF((num_labels)) +	\
		ALIGN((max_via_alen), VIA_ALEN_ALIGN))

enum mpls_ttl_propagation {
	MPLS_TTL_PROP_DEFAULT,
	MPLS_TTL_PROP_ENABLED,
	MPLS_TTL_PROP_DISABLED,
};

/* The route, nexthops and vias are stored together in the same memory
 * block:
 *
 * +----------------------+
 * | mpls_route           |
 * +----------------------+
 * | mpls_nh 0            |
 * +----------------------+
 * | alignment padding    |   4 bytes for odd number of labels
 * +----------------------+
 * | via[rt_max_alen] 0   |
 * +----------------------+
 * | alignment padding    |   via's aligned on sizeof(unsigned long)
 * +----------------------+
 * | ...                  |
 * +----------------------+
 * | mpls_nh n-1          |
 * +----------------------+
 * | via[rt_max_alen] n-1 |
 * +----------------------+
 */
struct mpls_route { /* next hop label forwarding entry */
	struct rcu_head		rt_rcu;
	u8			rt_protocol;
	u8			rt_payload_type;
	u8			rt_max_alen;
	u8			rt_ttl_propagate;
	u8			rt_nhn;
	/* rt_nhn_alive is accessed under RCU in the packet path; it
	 * is modified handling netdev events with rtnl lock held
	 */
	u8			rt_nhn_alive;
	u8			rt_nh_size;
	u8			rt_via_offset;
	u8			rt_reserved1;
	struct mpls_nh		rt_nh[];
};

#define for_nexthops(rt) {						\
	int nhsel; struct mpls_nh *nh;  u8 *__nh;			\
	for (nhsel = 0, nh = (rt)->rt_nh, __nh = (u8 *)((rt)->rt_nh);	\
	     nhsel < (rt)->rt_nhn;					\
	     __nh += rt->rt_nh_size, nh = (struct mpls_nh *)__nh, nhsel++)

#define change_nexthops(rt) {						\
	int nhsel; struct mpls_nh *nh; u8 *__nh;			\
	for (nhsel = 0, nh = (struct mpls_nh *)((rt)->rt_nh),		\
			__nh = (u8 *)((rt)->rt_nh);			\
	     nhsel < (rt)->rt_nhn;					\
	     __nh += rt->rt_nh_size, nh = (struct mpls_nh *)__nh, nhsel++)

#define endfor_nexthops(rt) }

struct mpls_entry_decoded {
	u32 label;
	u8 ttl;
	u8 tc;
	u8 bos;
};

static inline struct mpls_entry_decoded mpls_entry_decode(struct mpls_shim_hdr *hdr)
{
	struct mpls_entry_decoded result;
	unsigned entry = be32_to_cpu(hdr->label_stack_entry);

	result.label = (entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
	result.ttl = (entry & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT;
	result.tc =  (entry & MPLS_LS_TC_MASK) >> MPLS_LS_TC_SHIFT;
	result.bos = (entry & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT;

	return result;
}

static inline struct mpls_dev *mpls_dev_get(const struct net_device *dev)
{
	return rcu_dereference_rtnl(dev->mpls_ptr);
}

static inline int parse_encap_mpls_labels(struct mpls_shim_hdr *hdr, u32 labels[], int len)
{
    u8 label_count = len / 4;
    int i;

    for (i = label_count - 1; i >= 0; i--)
    {
        labels[i] = mpls_entry_decode(hdr + i).label;
    }

    return 0;
}

/* Copied from /net/mpls/af_mpls.c */
static inline u8 *__mpls_nh_via(struct mpls_route *rt, struct mpls_nh *nh)
{
	return (u8 *)nh + rt->rt_via_offset;
}

static inline const u8 *mpls_nh_via(const struct mpls_route *rt,
			     const struct mpls_nh *nh)
{
	return __mpls_nh_via((struct mpls_route *)rt, (struct mpls_nh *)nh);
}

static inline struct mpls_route *mpls_route_input_rcu(struct net *net, unsigned index)
{
	struct mpls_route *rt = NULL;

	if (index < net->mpls.platform_labels) {
		struct mpls_route __rcu **platform_label =
			rcu_dereference(net->mpls.platform_label);
		rt = rcu_dereference(platform_label[index]);
	}
	return rt;
}

/* Copied from /net/mpls/af_mpls.c { */
static inline struct mpls_nh *mpls_get_nexthop(struct mpls_route *rt, u8 index)
{
    return (struct mpls_nh *)((u8 *)rt->rt_nh + index * rt->rt_nh_size);
}
/* } */

bool is_not_mpls(struct sk_buff *skb);
uint get_number_of_mpls_capable_net_devices(struct net *net);

uint flush_mpls_label_stack(struct sk_buff *skb, struct mpls_entry_decoded mpls_entries[], int max_labels);

#endif /* TI_MFA_MPLS_H */
