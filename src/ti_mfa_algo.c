#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_netdev.h>

#include <net/arp.h>
#include <net/neighbour.h>
#include <net/protocol.h>
#include <net/mpls.h>

#include "include/mpls.h"
#include "include/ti_mfa_algo.h"
#include "include/utils.h"

struct ti_mfa_neigh **deleted_nhs;


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

static uint get_link_failure_stack(struct sk_buff *skb, struct ti_mfa_shim_hdr link_failures[], int max)
{
    struct ti_mfa_shim_hdr *link_failure_entry;
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
static struct mpls_route * get_shortest_path(struct net *net, u32 destination, struct ti_mfa_shim_hdr link_failures[], uint link_failure_count)
{
    struct mpls_route *rt = net->mpls.platform_label[destination];
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
*      Compute the node v_i on P with the highest index so that
*      the shortest Path from v is identical in G' (with failures)
*      and G (without failures) and set it as the top of the label stack
*      If node is v, push link (v_1,v_2=v_i) as the top of the label stack.
*      For the second item on the label stack, start over with
*      v_i as starting node until v_i=t
*/
int set_new_label_stack(struct sk_buff *skb, const struct mpls_entry_decoded orig_label_path[], unsigned int orig_label_count,
                        struct mpls_nh *nh, const struct ti_mfa_shim_hdr link_failures[], unsigned int link_failure_count)
{
    int error = 0;
    int i, j;
    unsigned int hh_len, mtu, ti_mfa_hdr_size, mpls_hdr_size, new_header_size;
    unsigned int label_count = 0;
    struct mpls_entry_decoded *new_label_stack = kmalloc_array(nh->nh_labels, sizeof(struct mpls_entry_decoded), GFP_ATOMIC);
    struct net_device *out_dev = nh->nh_dev;
    struct ti_mfa_shim_hdr *ti_mfa_h;
    struct mpls_shim_hdr *mpls_h;

    // @TODO: Validate the node computing
    for (i = 0; i < orig_label_count; i++) {
        for (j = 0; j < nh->nh_labels; j++) {
            if (nh->nh_label[j] != orig_label_path[i].label)
            {
                continue;
            }

            new_label_stack[label_count] = orig_label_path[i];
            label_count++;
        }
    }

    if (link_failure_count > 0)
    {
        /* +1 for extension label */
        label_count++;
    }
    mpls_hdr_size = label_count * sizeof(struct mpls_shim_hdr) ;
    ti_mfa_hdr_size =  link_failure_count * sizeof(struct ti_mfa_shim_hdr);
    new_header_size = mpls_hdr_size + ti_mfa_hdr_size;

    /* Copied from /net/mpls/af_mpls.c { */
    mtu = out_dev->mtu;
    /* Ensure there is enough space for the headers in the skb */
    if (!((skb->len <= mtu) || (skb_is_gso(skb) && skb_gso_validate_network_len(skb, mtu)))) {
        pr_err("New header is too big\n");
        error = -ENOMEM;
        goto out_free;
    }
    hh_len = LL_RESERVED_SPACE(out_dev);
    if (!out_dev->header_ops)
        hh_len = 0;
    if (skb_cow(skb, hh_len + new_header_size)) {
        error = -ENOMEM;
        goto out_free;
    }
    /* } */

    skb->dev = out_dev;

    if (link_failure_count > 0)
    {
        /* Set new ti-mfa header */
        skb_push(skb, ti_mfa_hdr_size);
        skb_reset_network_header(skb);
        ti_mfa_h = ti_mfa_hdr(skb);
        for (i = label_count + link_failure_count; i > label_count; i--) {
            ti_mfa_h[label_count + i] = link_failures[i];
        }
    }

    /* Set new mpls header */
    skb_push(skb, mpls_hdr_size);
    skb_reset_network_header(skb);
    mpls_h = mpls_hdr(skb);

    if (link_failure_count > 0)
    {
        mpls_h[label_count] = TI_MFA_MPLS_EXTENSION_HDR;
        label_count--;
    }
    for (i = label_count; i >= 0; i--) {
        struct mpls_entry_decoded mpls_entry = new_label_stack[i];
        mpls_h[i] = mpls_entry_encode(mpls_entry.label, mpls_entry.ttl, mpls_entry.tc, false);
    }

    pr_debug("Label count: %u\n", label_count);

    return error;

out_free:
    kfree(new_label_stack);
    return error;
}

static struct sk_buff *create_new_skb(struct sk_buff *skb)
{
    struct sk_buff *new_skb = skb_copy_expand(skb, sizeof(struct ti_mfa_shim_hdr) + skb_headroom(skb), 0, GFP_ATOMIC);

    if (new_skb == NULL)
    {
        return new_skb;
    }

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
    struct ti_mfa_shim_hdr link_failures[MAX_NEW_LABELS];
    struct ethhdr *ethh;
    uint mpls_label_count = 0;
    uint link_failure_count = 0;
    struct mpls_route *shortest_path;
    struct mpls_nh *nh;

    ethh = eth_hdr(skb);

    skb_pull(skb, sizeof(*ethh));

    mpls_label_count = get_mpls_label_stack(skb, label_stack, MAX_NEW_LABELS);
    link_failure_count = get_link_failure_stack(skb, link_failures, MAX_NEW_LABELS);
    shortest_path = get_shortest_path(dev_net(skb->dev), label_stack[mpls_label_count - 1].label, link_failures, link_failure_count);
    nh = shortest_path->rt_nh;
    pr_debug("Got shortest path");
    set_new_label_stack(skb, label_stack, mpls_label_count, nh, link_failures, link_failure_count);

    /* dev_hard_header(skb, skb->dev, skb->protocol, nh->nh_dev->ha */
    /* pr_debug("Xmitting on dev %s\n", skb->dev->name); */
    /* if (dev_queue_xmit(skb) != NET_XMIT_SUCCESS) */
    /* { */
    /*     pr_err("Error on xmit\n"); */
    /*     goto out_error; */
    /* } */
    if (neigh_xmit(nh->nh_via_table, skb->dev, mpls_nh_via(shortest_path, nh), skb) != NET_XMIT_SUCCESS)
    {
        pr_err("Error on xmit\n");
        goto out_retry;
    }

    goto out_success;

out_error:
    return TI_MFA_ERROR;

out_success:
    return TI_MFA_SUCCESS;

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

    // Sending packet to detect link failure doesn't work, because routing was already done
    // Avoid recursion (?)
    nf_skip_egress(new_skb, true);

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

void ti_mfa_ifdown(struct net_device *dev)
{
    struct mpls_route __rcu **platform_label;
    struct net *net = dev_net(dev);
    unsigned index;

    platform_label = rtnl_dereference(net->mpls.platform_label);
    for (index = 0; index < net->mpls.platform_labels; index++)
    {
        struct mpls_route *rt = rtnl_dereference(platform_label[index]);
        if (!rt)
            continue;


    }
}
