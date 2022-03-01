#include <linux/mpls_iptunnel.h>
#include <linux/nexthop.h>

#include "include/mpls.h"
#include "include/netlink.h"

/* From iproute2 lib/libnetlink.c */
static int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		       int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		pr_err("!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

static void parse_encap_mpls(struct rtattr *entry)
{
    struct rtattr *rta_table[MPLS_IPTUNNEL_MAX+1];
    u32 label;

    parse_rtattr_nested(rta_table, MPLS_IPTUNNEL_MAX, entry);

    if (rta_table[MPLS_IPTUNNEL_DST])
    {
        parse_encap_mpls_labels(RTA_DATA(rta_table[MPLS_IPTUNNEL_DST]), &label,
                                RTA_PAYLOAD(rta_table[MPLS_IPTUNNEL_DST]));

        pr_debug("Got mpls dst: %u\n", label);
    }
}

static void parse_nl_msg(struct nlmsghdr *nlh, int received_bytes)
{
    struct nhmsg *nhm;
    struct rtattr *rta_table[RTA_MAX+1];
    int len;

    /*
    * @TODO:
    *   - [X] parse deleted hop messages and display mpls label
    *   - [ ] save deleted hops together with their MPLS dst labels
    *   - [ ] removed hops from delete list on RTM_NEWHOP
    */

    if (nlh->nlmsg_type != RTM_DELNEXTHOP)
    {
        return;
    }

    nhm = NLMSG_DATA(nlh);
    len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(*nhm));

    parse_rtattr_flags(rta_table, NHA_MAX, RTM_NHA(nhm), len, NLA_F_NESTED);

    if (rta_table[NHA_GATEWAY] && rta_table[NHA_ENCAP] && rta_getattr_u16(rta_table[NHA_ENCAP_TYPE]) == LWTUNNEL_ENCAP_MPLS)
    {
        // @TODO: print doesn't work with IPv6 addresses
        pr_debug("NH gateway: %pI4\n", RTA_DATA(rta_table[NHA_GATEWAY]));
        parse_encap_mpls(rta_table[NHA_ENCAP]);
    }
}

void rcv_netlink_msg(struct sock *sk)
{
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlh = NULL;
    int received_bytes = 0;
    int err = 0;

    skb = skb_recv_datagram(sk, 0, 0, &err);
    if (err)
    {
        pr_err("Failed on skb_rev_datagram(), err=%d\n", -err);
        skb_free_datagram(sk, skb);
        return;
    }

    received_bytes = skb->len;

    if (received_bytes < 0)
    {
        pr_err("Got error on recv");
    }

    // From https://stackoverflow.com/questions/27322786/listening-for-netlink-broadcasts-in-a-kernel-module
    nlh = (struct nlmsghdr *) skb->data;
    if (!nlh || !NLMSG_OK(nlh, received_bytes))
    {
        pr_debug("Invalid netlink header data.\n");
        return;
    }

    if (nlh->nlmsg_type == NLMSG_DONE)
    {
        return;
    }

    for (; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes))
    {
        parse_nl_msg(nlh, received_bytes);
    }


    skb_free_datagram(sk, skb);
}
