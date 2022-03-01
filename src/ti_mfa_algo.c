#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#ifdef CONFIG_NETFILTER_EGRESS
#include <linux/netfilter_netdev.h>
#endif

#include <net/protocol.h>
#include <net/mpls.h>

#include "include/mpls.h"
#include "include/ti_mfa_algo.h"
#include "include/utils.h"

// static int ti_mfa_calculate_label_stack(void)
// {
//     // 1) Flush label stack except for destination t
//     // 2) Determine shortest path P to t based on all link failures
//     //    in the remaining network G"
//     // 3) Add segments to the label stack as follows:
//     //      Index the nodes on P as v=v1,v2,...,vx=t
//     //      Compute the node vi on P with the highest index so that
//     //      the shortest Path from v is identical in G' (with failures)
//     //      and G (without failures) and set it as the top of the label stack
//     //      If node is v, push link (v1,v2=vi) as the top of the label stack.
//     //      For the second item on the label stack, start over with
//     //      vi as starting node until vi=t
//     int return_code = 0;
//     return return_code;
// }

int run_timfa(struct sk_buff *skb)
{
    struct mpls_shim_hdr *hdr;
    unsigned entry;
    u32 label;
    struct ethhdr *ethh;
    struct rtable *rt; // routing table
    struct net *nt; // net namespace

    /* Create new skbuff, because sending original skb
    * via dev_queue_xmit() causes system crash
    */
    struct sk_buff *new_skb;

    new_skb = skb_copy(skb, GFP_KERNEL);

    if (new_skb == NULL)
    {
        pr_debug("Copying skb failed on [%s]", skb->dev->name);
        return -1;
    }

    hdr = mpls_hdr(new_skb);

    if (hdr == NULL)
    {
        return -1;
    }

    entry = be32_to_cpu(hdr->label_stack_entry);
    label = MPLS_LABEL(entry);
    ethh = eth_hdr(new_skb);

    pr_debug("[%s]:[(%s) %pM -> %pM] EGRESS: new skb with label %u.",
        HOST_NAME, new_skb->dev->name, new_skb->dev->dev_addr, ethh->h_dest, label);
    /*
    * @TODO:
    * [X] Get outgoing dev
    * [X] Get mac of adjacent machine on outgoing dev
    * [ ] Check if packet is lost / outgoing dev is down
    * [ ] Add link failure to packet header
    */

   // Get routing information
    // nt = dev_net(skb->dev);
    // rt  = ip_route_output();

    // Sending packet to detect link failure doesn't work, because routing was already done
    // Avoid recursion
    #ifdef CONFIG_NETFILTER_EGRESS
    nf_skip_egress(new_skb, true);
    #endif

    pr_debug("Sending on [%s]...", new_skb->dev->name);

    if (dev_queue_xmit(new_skb) != NET_XMIT_SUCCESS)
    {
        pr_debug("Sending failed on [%s]", new_skb->dev->name);
        return -1;
    }
    return 0;
}