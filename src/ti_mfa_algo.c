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

#include <net/arp.h>
#include <net/neighbour.h>
#include <net/protocol.h>
#include <net/mpls.h>

#include "include/mpls.h"
#include "include/ti_mfa_algo.h"
#include "include/utils.h"

struct ti_mfa_nh **deleted_nhs;

/* Step 1): Decode mpls labels, remove them from header and save them
*/
static uint get_mpls_label_stack(struct sk_buff *skb, struct mpls_entry_decoded mpls_entries[], int max_labels)
{
    uint label_count = 0;
    do {
        struct mpls_shim_hdr *mpls_hdr_entry = mpls_hdr(skb);
        mpls_entries[label_count] = mpls_entry_decode(mpls_hdr_entry);
        skb_pull(skb, sizeof(*mpls_hdr_entry));
        label_count++;

        if (label_count > max_labels)
        {
            break;
        }
    } while (!mpls_entries[label_count - 1].bos);

    return label_count;
}

static uint get_link_failure_stack(struct sk_buff *skb, struct ti_mfa_hdr link_failures[], int max)
{
    struct ti_mfa_hdr *link_failure_entry;
    uint count = 0;
    do {
        if (!pskb_may_pull(skb, sizeof(*link_failure_entry)))
        {
            break;
        }

        link_failure_entry = skb_pull(skb, sizeof(*link_failure_entry));
        memmove(&link_failures[count], link_failure_entry, sizeof(*link_failure_entry));
        count++;

        if (count > max)
        {
            break;
        }
    } while (!link_failures[count - 1].bos);

    return count;
}

static const char neigh_tables[4][4] = { "ARP", "IP6", "DEC", "NRT"};

/* Step 2): Determine shortest path P to t based on all link failures in the remaining network G'
*/
static struct mpls_route * get_shortest_path(u32 destination, struct ti_mfa_shim_hdr link_failures[], uint link_failure_count)
{
    struct mpls_route *rt = init_net.mpls.platform_label[destination];
    for_nexthops(rt) {
        int i = 0;
        // @TODO: Filter by link failures
        // @TODO: Support for IPv6
        u32 neigh_index = *((u32 *) mpls_nh_via(rt, nh));
        struct neighbour *neigh = __ipv4_neigh_lookup_noref(nh->nh_dev, neigh_index);

        pr_debug("NH: dev: %s, table: %s, mac: %pM\n",
                 nh->nh_dev->name, neigh_tables[nh->nh_via_table], neigh->ha
        );
        pr_debug("labels:\n");
        for (i = 0; i < nh->nh_labels; i++)
        {
            pr_debug("%u", *(nh->nh_label));

        }
        pr_debug("\n");
    } endfor_nexthops(rt);
    return rt;
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

static struct sk_buff *create_new_skb(struct sk_buff *skb)
{
    struct sk_buff *new_skb = skb_copy_expand(skb, sizeof(struct ti_mfa_hdr) + skb_headroom(skb), 0, GFP_ATOMIC);

    if (new_skb == NULL)
    {
        return new_skb;
    }

    // Sending packet to detect link failure doesn't work, because routing was already done
    // Avoid recursion (?)
    #ifdef CONFIG_NETFILTER_EGRESS
    nf_skip_egress(new_skb, true);
    #endif

    return new_skb;
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
static int __run_ti_mfa(struct sk_buff *skb)
{
    struct mpls_entry_decoded label_stack[MAX_NEW_LABELS];
    struct ti_mfa_hdr link_failures[MAX_NEW_LABELS];
    struct ethhdr *ethh;
    struct ti_mfa_hdr *ti_mfa_h;
    uint mpls_label_count = 0;
    uint link_failure_count = 0;
    struct mpls_route *shortest_path;
    struct ethhdr *new_eth_hdr;

    ethh = eth_hdr(skb);

    goto out_success;

    skb_pull(skb, sizeof(*ethh));
    pr_debug("eth header pulled");

    mpls_label_count = get_mpls_label_stack(skb, label_stack, MAX_NEW_LABELS);
    link_failure_count = get_link_failure_stack(skb, link_failures, MAX_NEW_LABELS);
    shortest_path = get_shortest_path(label_stack[mpls_label_count - 1].label, link_failures, link_failure_count);
    set_new_label_stack(skb, label_stack, shortest_path);

    new_eth_hdr = skb_push(skb, sizeof(*ethh));
    memcpy(new_eth_hdr, ethh, sizeof(*ethh));
    pr_debug("Set eth header\n");

    pr_debug("Sending on [%s]...", skb->dev->name);

    if (dev_queue_xmit(skb) != NET_XMIT_SUCCESS)
    {
        goto out_retry;
    }

    goto out_success;

out_success:
    return TI_MFA_SUCCESS;

out_error:
    /* kfree(skb); */
    return TI_MFA_ERROR;

out_retry:
    /* @TODO: add new link failure to header */
    return TI_MFA_RETRY;
}

int run_ti_mfa(struct sk_buff *skb)
{
    int return_code = TI_MFA_SUCCESS;
    struct sk_buff *new_skb = NULL;

    if (is_not_mpls(skb))
    {
        return TI_MFA_PASS;
    }

    /* Create new skbuff, because sending original skb
    * via dev_queue_xmit() causes system crash
    */
    new_skb = create_new_skb(skb);
    if (new_skb == NULL)
    {
        pr_debug("Copying skb failed on [%s]\n", skb->dev->name);
        return TI_MFA_ERROR;
    }

    pr_debug("Running ti-mfa algo\n");
    do
    {
       return_code = __run_ti_mfa(new_skb);
    } while (return_code == TI_MFA_RETRY);

    if (return_code == TI_MFA_ERROR)
    {
        kfree_skb(new_skb);
    }

    return return_code;
}
