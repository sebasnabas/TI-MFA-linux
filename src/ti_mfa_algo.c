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

#define DELETED_NEIGHS_INITIAL_SIZE MAX_NEW_LABELS
static struct ti_mfa_neigh **deleted_neighs;
static uint number_of_deleted_neighs;

/* Step 1): Decode mpls labels, remove them from header and save them
*/
static uint get_mpls_label_stack(struct sk_buff *skb, struct mpls_entry_decoded mpls_entries[], int max_labels)
{
    uint label_count = 0;
    struct mpls_shim_hdr *mpls_hdr_entry = mpls_hdr(skb);
    do {
        mpls_entries[label_count] = mpls_entry_decode(&mpls_hdr_entry[label_count]);

        pr_debug("%u: label: %u\n", label_count, mpls_entries[label_count].label);
        label_count++;

        if (label_count > max_labels)
        {
            break;
        }
    } while (!mpls_entries[label_count - 1].bos);

    skb_pull(skb, sizeof(struct mpls_shim_hdr) * label_count);
    skb_reset_network_header(skb);

    return label_count;
}

static uint get_link_failure_stack(struct sk_buff *skb, struct ti_mfa_shim_hdr link_failures[], int max)
{
    uint count = 0;
        struct ti_mfa_shim_hdr *link_failure_entry = ti_mfa_hdr(skb);
    do {
        memmove(&link_failures[count], &link_failure_entry[count], sizeof(struct ti_mfa_shim_hdr));

        pr_debug("Link failure: node source: %pM, link source: %pM, link dest: %pM\n", link_failures[count].node_source, link_failures[count].link_source, link_failures[count].link_dest);
        count++;

        if (count > max)
        {
            break;
        }
    } while (!link_failures[count - 1].bos);

    skb_pull(skb, sizeof(struct ti_mfa_shim_hdr) * count);
    skb_reset_network_header(skb);

    return count;
}

/* Step 2): Determine shortest path P to t based on all link failures in the remaining network G' (Get next hop)
*/
static int get_shortest_path(struct net *net, const u32 destination,
                             const struct ti_mfa_shim_hdr link_failures[], const uint link_failure_count,
                             struct ti_mfa_nh *next_hop)
{
    int error = 0;
    int nh_index = 0;
    struct mpls_nh *mpls_next_hop = NULL;
    struct mpls_route *rt = mpls_route_input_rcu(net, destination);
    struct neighbour *neigh;

    if (!rt) {
        pr_err("No route found\n");
        return -1;
    }

    for_nexthops(rt) {
        bool skip = false;
        int i = 0;
        u32 neigh_index = *((u32 *) mpls_nh_via(rt, nh));
        struct net_device *nh_dev = nh->nh_dev;

        if (!nh_dev)
            continue;

        switch (nh->nh_via_table) {
            case NEIGH_ARP_TABLE:
                neigh = __ipv4_neigh_lookup_noref(nh_dev, neigh_index);
                break;
            default:
                // @TODO: Support for IPv6
                break;
        }

        pr_debug("NH: dev: %s, mac: %pM\n", nh_dev->name, neigh->ha);
        pr_debug("labels:\n");
        for (i = 0; i < nh->nh_labels; i++)
        {
            pr_debug("%u\n", nh->nh_label[i]);
        }

        for (i = 0; i < link_failure_count; i++) {
            struct ti_mfa_shim_hdr link_failure = link_failures[i];

            if (ether_addr_equal(neigh->ha, link_failure.link_source)
                || ether_addr_equal(neigh->ha, link_failure.link_dest)) {

                pr_debug("Found neighbor with broken link [%pM] == [src: %pM | dest: %pM] skipping...\n", neigh->ha, link_failure.link_source, link_failure.link_dest);
                skip = true;
                break;
            }
        }

        if (skip) continue;

        nh_index = nhsel;

    } endfor_nexthops(rt);

    mpls_next_hop = mpls_get_nexthop(rt, nh_index);

    if (mpls_next_hop == NULL) return -1;

    next_hop->dev = mpls_next_hop->nh_dev;
    next_hop->labels = mpls_next_hop->nh_labels;
    memmove(next_hop->label, mpls_next_hop->nh_label, sizeof(*(mpls_next_hop->nh_label)));
    ether_addr_copy(next_hop->ha, neigh->ha);
    pr_debug("NH mac: %pM, Neigh mac: %pM\n", next_hop->ha, neigh->ha);

    if (next_hop->label == NULL)
    {
        pr_debug("Next hop is null\n");
        return -1;
    }

    return error;
}

static void set_local_link_failures(struct net *net, u32 destination, struct ti_mfa_nh *next_hop)
{
    uint i = 0, j = 0, link_failures = 0;
    for (i = 0; i < number_of_deleted_neighs; i++) {
        struct ti_mfa_neigh *neigh = deleted_neighs[i];
        bool label_found;

        if (!neigh || neigh->net != net)
            continue;

        for (j = 0; j < neigh->label_count; j++) {
            if (neigh->labels[j] != destination)
                continue;

            label_found = true;
            break;
        }

        if (!label_found)
            continue;

        ether_addr_copy(next_hop->link_failures[link_failures].link_source, neigh->dev->dev_addr);
        ether_addr_copy(next_hop->link_failures[link_failures].link_dest, neigh->ha);
        /* Not setting link_failures[]->nod_source, beacuse it's the same for everyone */
        link_failures++;
    }
    next_hop->link_failure_count = link_failures;
}

static bool fill_link_failure_stack(const struct ti_mfa_shim_hdr link_failures[], const uint start, const uint count,
                                    struct ti_mfa_shim_hdr *hdr, bool bos)
{
    uint i;
    for (i = start; i >= 0; i--) {
        struct ti_mfa_shim_hdr ti_mfa_entry = link_failures[i];
        hdr[i] = ti_mfa_entry;
        hdr[i].bos = bos;

        bos = false;
        pr_debug("%u: node source: %pM, link source: %pM, link dest: %pM%s\n", i, hdr[i].node_source, hdr[i].link_source, hdr[i].link_dest, hdr[i].bos ? " [S]" : "");
    }

    return bos;
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
                        const struct ti_mfa_nh *nh, const struct ti_mfa_shim_hdr link_failures[], unsigned int link_failure_count,
                        bool flush_link_failure_stack)
{
    int error = 0;
    int i, j;
    unsigned int mtu, ti_mfa_hdr_size, mpls_hdr_size, headroom, new_header_size = 0;
    unsigned int label_count = 0;
    struct mpls_entry_decoded *new_label_stack = kmalloc_array(nh->labels, sizeof(struct mpls_entry_decoded), GFP_KERNEL);
    struct net_device *out_dev = nh->dev;
    struct ti_mfa_shim_hdr *ti_mfa_h;
    struct mpls_shim_hdr *mpls_h;
    bool bos = false;

    if (!flush_link_failure_stack)
        link_failure_count += nh->link_failure_count;

    // @TODO: Validate the node computing
    for (i = 0; i < orig_label_count; i++) {
        for (j = 0; j < nh->labels; j++) {
            if (nh->label[j] != orig_label_path[i].label)
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

    pr_debug("Calculated header size with label count: %u and link failure count %u\n", label_count, link_failure_count);


    if (skb_warn_if_lro(skb))
    {
        error = -1;
        goto out_free;
    }

    skb_forward_csum(skb);

    /* Annotate mtu read */
    mtu = READ_ONCE(out_dev->mtu);
    /* Ensure there is enough space for the headers in the skb */
    if (!((skb->len <= mtu) || (skb_is_gso(skb) && skb_gso_validate_network_len(skb, mtu)))) {
        pr_err("New header is too big\n");
        error = -1;
        goto out_free;
    }

    headroom = skb_headroom(skb);
    if (new_header_size - headroom <= 0)
    {
        if (skb_expand_head(skb, new_header_size)) {
            pr_debug("Cannot expand head. headroom: %u, new header size: %u\n", headroom, new_header_size);
            error = -1;
            goto out_free;
        }
    }

    skb->dev = out_dev;

    if (link_failure_count > 0)
    {
        bool bos = true;
        /* Set new ti-mfa header */
        pr_debug("Setting new ti-mfa header\n");
        skb_push(skb, ti_mfa_hdr_size);
        skb_reset_network_header(skb);

        ti_mfa_h = ti_mfa_hdr(skb);

        bos = fill_link_failure_stack(nh->link_failures, 0, nh->link_failure_count, ti_mfa_h, bos);

        if (!flush_link_failure_stack && link_failure_count < MAX_NEW_LABELS) {
            fill_link_failure_stack(link_failures, nh->link_failure_count, link_failure_count - nh->link_failure_count,
                                    ti_mfa_h, bos
            );
        }
    }

    /* Set new mpls header */
    skb_push(skb, mpls_hdr_size);
    skb_reset_network_header(skb);
    mpls_h = mpls_hdr(skb);

    if (link_failure_count > 0)
    {
        pr_debug("Setting ti-mfa mpls extension shim hdr\n");
        mpls_h[label_count-1] = TI_MFA_MPLS_EXTENSION_HDR;
        label_count--;
        bos = false;
    } else {
        bos = true;
    }
    for (i = label_count - 1; i >= 0; i--) {
        struct mpls_entry_decoded mpls_entry = new_label_stack[i];
        mpls_h[i] = mpls_entry_encode(mpls_entry.label, mpls_entry.ttl, mpls_entry.tc, bos);
        pr_debug("%u: label: %u\n", i, mpls_entry.label);

        bos = false;
    }

    pr_debug("Label count: %u\n", label_count);

out_free:
    pr_debug("Freeing label stack\n");
    kfree(new_label_stack);
    return error;
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
static int __run_ti_mfa(struct net *net, struct sk_buff *skb)
{
    struct mpls_entry_decoded label_stack[MAX_NEW_LABELS];
    struct ti_mfa_shim_hdr link_failures[MAX_NEW_LABELS];
    struct mpls_entry_decoded destination;
    uint mpls_label_count = 0;
    uint link_failure_count = 0;
    struct ti_mfa_nh next_hop;
    struct ethhdr ethh = *eth_hdr(skb);
    struct ethhdr *neweth;

    skb_pull(skb, sizeof(ethh));

    mpls_label_count = get_mpls_label_stack(skb, label_stack, MAX_NEW_LABELS);

    destination = label_stack[mpls_label_count - 1];
    if (destination.label == TI_MFA_MPLS_EXTENSION_LABEL) {
        pr_debug("Got ti-mfa extension label\n");
        mpls_label_count--;
        destination = label_stack[mpls_label_count - 1];
        link_failure_count = get_link_failure_stack(skb, link_failures, MAX_NEW_LABELS);
    }

    rcu_read_lock();
    if (get_shortest_path(net, destination.label, link_failures, link_failure_count, &next_hop) != 0)
        goto out_error;

    set_local_link_failures(net, destination.label, &next_hop);

    if (set_new_label_stack(skb, label_stack, mpls_label_count, &next_hop, link_failures, link_failure_count, false) != 0)
        goto out_error;
    rcu_read_unlock();

    ether_addr_copy(ethh.h_dest, next_hop.ha);
    ether_addr_copy(ethh.h_source, skb->dev->dev_addr);

    neweth = skb_push(skb, sizeof(ethh));
    *neweth = ethh;

    pr_debug("dest: %pM, src: %pM\n", ethh.h_dest, ethh.h_source);
    pr_debug("<== xmit via %s\n", skb->dev->name);

    if (dev_queue_xmit(skb) != NET_XMIT_SUCCESS)
    {
        pr_err("Error on xmit\n");
        goto out_retry;
    }

    goto out_success;

out_error:
    rcu_read_unlock();
    return TI_MFA_ERROR;

out_success:
    return TI_MFA_SUCCESS;

out_retry:
    /* @TODO: add new link failure to header */
    return TI_MFA_RETRY;
}

int run_ti_mfa(struct net *net, struct sk_buff *skb)
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
    new_skb = skb_copy(skb, GFP_ATOMIC);
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
       return_code = __run_ti_mfa(net, new_skb);
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
    unsigned index = 0, tmp = number_of_deleted_neighs;

    if (!dev)
        return;

    pr_debug("ifdown for dev %s\n", dev->name);

    platform_label = rtnl_dereference(net->mpls.platform_label);
    for (index = 0; index < net->mpls.platform_labels; index++)
    {
        struct mpls_route *rt = rtnl_dereference(platform_label[index]);
        if (!rt)
            continue;

        for_nexthops(rt) {
            struct neighbour *neigh;
            uint i = 0;
            u32 neigh_index = *((u32 *) mpls_nh_via(rt, nh));
            bool found_deleted_neigh = false;

            if (nh->nh_dev && nh->nh_dev != dev)
                continue;

            switch (nh->nh_via_table) {
                case NEIGH_ARP_TABLE:
                    neigh = __ipv4_neigh_lookup_noref(nh->nh_dev, neigh_index);
                    break;
                default:
                    // @TODO: Support for IPv6
                    break;
            }

            if (neigh == NULL || is_zero_ether_addr(neigh->ha) || neigh->dev != dev)
                continue;

            if (number_of_deleted_neighs > 0 && number_of_deleted_neighs % DELETED_NEIGHS_INITIAL_SIZE == 0) {
                pr_err("Not enough space in deleted neighbor array. Len: %u\n", number_of_deleted_neighs);
                break;
            }

            pr_debug("nh: %pM", neigh->ha);

            for (i = 0; i < tmp; i++) {
                if (deleted_neighs[i] == NULL)
                    continue;

                if (deleted_neighs[i]->dev == nh->nh_dev) {
                    uint j = 0;
                    struct ti_mfa_neigh *deleted_neigh = deleted_neighs[i];
                    found_deleted_neigh = true;

                    if (nh->nh_labels + deleted_neigh->label_count > MAX_NEW_LABELS) {
                        pr_err("Cannot save labels of affected next hop\n");
                        continue;
                    }

                    for (j = 0; j < nh->nh_labels; j++) {
                        uint index = j + deleted_neigh->label_count;
                        uint k = 0;
                        bool found = false;
                        for (k = 0; k < deleted_neigh->label_count; k++) {
                            if (deleted_neigh->labels[k] != nh->nh_label[k])
                                continue;

                            found = true;
                            break;
                        }
                        deleted_neigh->labels[index] = nh->nh_label[j];
                        pr_debug("Added label %u\n", deleted_neigh->labels[index]);
                    }

                    deleted_neigh->label_count += j;
                    continue;
                }
            }

            if (!found_deleted_neigh) {
                deleted_neighs[tmp] = kzalloc(sizeof(struct ti_mfa_neigh), GFP_KERNEL);
                deleted_neighs[tmp]->net = net;
                deleted_neighs[tmp]->dev = nh->nh_dev;
                ether_addr_copy(deleted_neighs[tmp]->ha, neigh->ha);
                tmp++;
            }
        } endfor_nexthops(rt);
    }
    number_of_deleted_neighs = tmp;
    pr_debug("deleted_neighs: %u\n", number_of_deleted_neighs);
}

void ti_mfa_ifup(struct net_device *dev)
{
    struct ti_mfa_neigh **tmp = kcalloc(DELETED_NEIGHS_INITIAL_SIZE, sizeof(struct ti_mfa_neigh *), GFP_KERNEL);
    uint i = 0, j = 0;

    if (tmp == NULL) {
        pr_err("Could not allocated tmp array\n");
        return;
    }

    for (i = 0; i < number_of_deleted_neighs; i++) {
        if (deleted_neighs[i] == NULL || deleted_neighs[i]->dev == NULL)
            continue;

        if (deleted_neighs[i]->dev == dev) {
            pr_debug("Freeing neigh with ha: %pM\n", deleted_neighs[i]->ha);
            kfree(deleted_neighs[i]);
            deleted_neighs[i] = NULL;
            continue;
        }

        tmp[j] = kzalloc(sizeof(struct ti_mfa_neigh), GFP_KERNEL);
        memmove(tmp[j], deleted_neighs[i], sizeof(struct ti_mfa_neigh));
        j++;
    }

    kfree(deleted_neighs);
    deleted_neighs = tmp;
    number_of_deleted_neighs = j;
}

int initialize_ti_mfa(void)
{
    number_of_deleted_neighs = 0;
    deleted_neighs = kcalloc(DELETED_NEIGHS_INITIAL_SIZE, sizeof(struct ti_mfa_neigh *), GFP_KERNEL);

    if (deleted_neighs == NULL) {
        pr_debug("Could not allocate deleted_neighs\n");
        return -ENOMEM;
    }

    return 0;
}

void cleanup_ti_mfa(void)
{
    uint i = 0;
    for (i = 0; i < number_of_deleted_neighs; i++) {
        if (deleted_neighs[i] == NULL) continue;

        kfree(deleted_neighs[i]);
    }
    kfree(deleted_neighs);
}
