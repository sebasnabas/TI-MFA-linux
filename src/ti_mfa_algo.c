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

struct ti_mfa_nh *deleted_nhs;

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
    struct mpls_shim_hdr *mpls_hdr_entry;
    struct mpls_entry_decoded mpls_entry;
    struct ti_mfa_nh *deleted_nh;
    u32 label = 0;
    struct ethhdr *ethh;
    struct ti_mfa_hdr *ti_mfa_h;
    int err = 0;
    int i = 0;
    /* Create new skbuff, because sending original skb
    * via dev_queue_xmit() causes system crash
    */
    struct sk_buff *new_skb;
    struct mpls_shim_hdr *new_mpls_hdr_entry ;
    struct ethhdr *new_eth_hdr;

    // Get pointer to first mpls stack entry
    mpls_hdr_entry = mpls_hdr(skb);

    if (mpls_hdr_entry == NULL)
    {
        err = -1;
        goto out_free;
    }

    new_skb = skb_copy_expand(skb, sizeof(struct ti_mfa_hdr) + skb_headroom(skb), 0, GFP_KERNEL);

    if (new_skb == NULL)
    {
        pr_debug("Copying skb failed on [%s]\n", skb->dev->name);
        return -1;
    }

    ethh = eth_hdr(skb);
    skb_pull(new_skb, sizeof(struct ethhdr));
    pr_debug("eth header pulled");

    skb_pull(new_skb, sizeof(struct mpls_shim_hdr));
    pr_debug("mpls header pulled\n");

    // Set TI-MFA header
    ti_mfa_h = skb_push(new_skb, sizeof(struct ti_mfa_hdr));

    for (i = 0; i < ETH_ALEN; i++)
    {
        ti_mfa_h->link_dest[i] = ethh->h_dest[i];
        ti_mfa_h->link_source[i] = ethh->h_source[i];
    }

    // deleted_nh = deleted_nhs[label];
    // if (deleted_nh != NULL)
    // {
    //     pr_debug("Got deleted next hop with dev [%s]", deleted_nh->nh_dev->name);
    // }

    /* @TODO:
    * doesn't work for stack size > 1
    */
    // while (!mpls_entry.bos)
    // {
        new_mpls_hdr_entry = skb_push(new_skb, sizeof(struct mpls_shim_hdr));
        memcpy(new_mpls_hdr_entry, mpls_hdr_entry, sizeof(struct mpls_shim_hdr));
    // // }

    pr_debug("Set mpls header\n");

    new_eth_hdr = skb_push(new_skb, sizeof(struct ethhdr));
    memcpy(new_eth_hdr, ethh, sizeof(struct ethhdr));
    pr_debug("Set eth header\n");

    // Sending packet to detect link failure doesn't work, because routing was already done
    // Avoid recursion
    #ifdef CONFIG_NETFILTER_EGRESS
    nf_skip_egress(new_skb, true);
    #endif

    pr_debug("[%s]:[(%s) %pM -> %pM] EGRESS: new skb with label %u.",
        HOST_NAME, new_skb->dev->name, new_skb->dev->dev_addr, ethh->h_dest, label);
    pr_debug("Sending on [%s]...", new_skb->dev->name);

    if (dev_queue_xmit(new_skb) != NET_XMIT_SUCCESS)
    {
        pr_debug("Sending failed on [%s]", new_skb->dev->name);
        err = -1;
        goto out_free;
    }

    return err;

out_free:
    kfree_skb(new_skb);
    return err;
}