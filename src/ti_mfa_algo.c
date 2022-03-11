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

struct ti_mfa_nh **deleted_nhs;

/* Step 1): Decode mpls labels, remove them from header and save them
*/
static uint flush_mpls_label_stack(struct sk_buff *skb, struct mpls_entry_decoded mpls_entries[], int max_labels)
{
    struct mpls_shim_hdr *mpls_hdr_entry;
    uint label_count = 0;
    do {
        mpls_hdr_entry = mpls_hdr(skb);
        mpls_entries[label_count] = mpls_entry_decode(mpls_hdr_entry);
        skb_pull(skb, sizeof(*mpls_hdr_entry));
        label_count++;

        if (label_count > max_labels)
        {
            break;
        }
    } while (!mpls_entries[label_count - 1].bos);

    pr_debug("Flushed label stack");

    return label_count;
}

static uint flush_link_failure_stack(struct sk_buff *skb, struct ti_mfa_hdr link_failures[], int max)
{
    struct ti_mfa_hdr *link_failure_entry;
    uint count = 0;
    do {
        if (!pskb_may_pull(skb, sizeof(*link_failure_entry)))
        {
            break;
        }

        link_failure_entry = skb_pull(skb, sizeof(*link_failure_entry));
        memcpy(&link_failures[count], link_failure_entry, sizeof(*link_failure_entry));
        count++;

        if (count > max)
        {
            break;
        }
    } while (!link_failures[count - 1].bos);

    pr_debug("Flushed ti-mfa stack");

    return count;
}

/* Step 2):
*    Determine shortest path P to t based on all link failures
*    in the remaining network G'
*/
static struct mpls_route * get_shortest_path(struct mpls_entry_decoded destination, struct ti_mfa_hdr link_failures[], uint link_failure_count)
{
    struct mpls_route *shortest_path = NULL;
    // @TODO
    return shortest_path;
}

/* Step 3):
*    Add segments to the label stack as follows:
*      Index the nodes on P as v=v_1,v_2,...,v_x=t
*      Compute the node vi on P with the highest index so that
*      the shortest Path from v is identical in G' (with failures)
*      and G (without failures) and set it as the top of the label stack
*      If node is v, push link (v_1,v_2=v_i) as the top of the label stack.
*      For the second item on the label stack, start over with
*      v_i as starting node until v_i=t
*/
void set_new_label_stack(struct sk_buff *skb, struct mpls_entry_decoded label_stack[], struct mpls_route *shortest_path)
{

    // Set TI-MFA header
    // ti_mfa_h = skb_push(new_skb, sizeof(*ti_mfa_h));
    // memcpy(ti_mfa_h->link_source, ethh->h_source, sizeof(ethh->h_source));
    // memcpy(ti_mfa_h->link_dest, ethh->h_dest, sizeof(ethh->h_dest));

    // pr_debug("Added ti-mfa header\nSrc: %pM; Dst: %pM (%pM)", ti_mfa_h->link_source, ti_mfa_h->link_dest, ethh->h_dest);

    // deleted_nh = deleted_nhs[label];
    // if (deleted_nh != NULL)
    // {
    //     pr_debug("Got deleted next hop with dev [%s]", deleted_nh->nh_dev->name);
    // }

    // @TODO:
    int i = 0;
    for (i = 0; i < shortest_path->rt_nh_size; i++)
    {

    }


}

/* TI-MFA algorithm:
*    1) Flush label stack except for destination t
*    2) Determine shortest path P to t based on all link failures
*       in the remaining network G'
*    3) Add segments to the label stack as follows:
*         Index the nodes on P as v=v_1,v_2,...,v_x=t
*         Compute the node vi on P with the highest index so that
*         the shortest Path from v is identical in G' (with failures)
*         and G (without failures) and set it as the top of the label stack
*         If node is v, push link (v_1,v_2=v_i) as the top of the label stack.
*         For the second item on the label stack, start over with
*         v_i as starting node until v_i=t
*/
int run_timfa(struct sk_buff *skb)
{
    struct mpls_entry_decoded label_stack[MAX_NEW_LABELS];
    struct ti_mfa_hdr link_failures[MAX_NEW_LABELS];
    struct ethhdr *ethh;
    struct ti_mfa_hdr *ti_mfa_h;
    int err = 0;
    uint mpls_label_count = 0;
    uint link_failure_count = 0;
    struct mpls_route *shortest_path;
    /* Create new skbuff, because sending original skb
    * via dev_queue_xmit() causes system crash
    */
    struct sk_buff *new_skb;
    struct ethhdr *new_eth_hdr;

    if (is_not_mpls(skb))
    {
        return 0;
    }

    new_skb = skb_copy_expand(skb, sizeof(*ti_mfa_h) + skb_headroom(skb), 0, GFP_ATOMIC);

    if (new_skb == NULL)
    {
        pr_debug("Copying skb failed on [%s]\n", skb->dev->name);
        return -1;
    }

    ethh = eth_hdr(new_skb);
    skb_pull(new_skb, sizeof(*ethh));
    pr_debug("eth header pulled");

    mpls_label_count = flush_mpls_label_stack(new_skb, label_stack, MAX_NEW_LABELS);
    link_failure_count = flush_link_failure_stack(new_skb, link_failures, MAX_NEW_LABELS);
    shortest_path = get_shortest_path(label_stack[mpls_label_count - 1], link_failures, link_failure_count);
    set_new_label_stack(new_skb, label_stack, shortest_path);

    new_eth_hdr = skb_push(new_skb, sizeof(*ethh));
    memcpy(new_eth_hdr, ethh, sizeof(*ethh));
    pr_debug("Set eth header\n");

    // Sending packet to detect link failure doesn't work, because routing was already done
    // Avoid recursion (?)
    #ifdef CONFIG_NETFILTER_EGRESS
    nf_skip_egress(new_skb, true);
    #endif

    pr_debug("Sending on [%s]...", new_skb->dev->name);

    if (dev_queue_xmit(new_skb) != NET_XMIT_SUCCESS)
    {
        // @TODO add ti-mfa here
        pr_debug("Sending failed on [%s]", new_skb->dev->name);
        err = -1;
        goto out_free;
    }

    return err;

out_free:
    kfree_skb(new_skb);
    return err;
}