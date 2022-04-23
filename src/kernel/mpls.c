#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/skbuff.h>
#include <net/arp.h>
#include <net/neighbour.h>

#include "mpls.h"
#include "ti_mfa.h"

/* Step 1): Decode mpls labels, remove them from header and save them
*/
uint flush_mpls_label_stack(struct sk_buff *skb, struct mpls_entry_decoded mpls_entries[], int max_labels)
{
    uint label_count = 0;
    struct mpls_shim_hdr *mpls_hdr_entry = mpls_hdr(skb);
    do {
        mpls_entries[label_count] = mpls_entry_decode(&mpls_hdr_entry[label_count]);

        pr_debug("%u: label: %u %s\n", label_count, mpls_entries[label_count].label, mpls_entries[label_count].bos ? "[S]" : "");
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

struct mpls_nh *get_failure_free_next_hop(struct net *net, const u32 destination,
                               const uint link_failure_count,
                               const struct ti_mfa_shim_hdr link_failures[])
{
    struct mpls_route *rt    = NULL;
    struct neighbour *neigh  = NULL;
    struct mpls_nh *next_hop = NULL;
    int nh_index = 0;

    rt = mpls_route_input_rcu(net, destination);
    if (!rt) {
        pr_err("No route found\n");
        return NULL;
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

        /* Go through each link failure and
         * check if the neighbor belonging to the next hop is affected
         */
        for (i = 0; i < link_failure_count; i++) {
            struct ti_mfa_shim_hdr link_failure = link_failures[i];

            if (ether_addr_equal(neigh->ha, link_failure.link_source)
                || ether_addr_equal(neigh->ha, link_failure.link_dest)
                || ether_addr_equal(neigh->ha, link_failure.node_source)) {

                pr_debug("Found neighbor with broken link [%pM] == [src: %pM | dest: %pM] skipping...\n", neigh->ha, link_failure.link_source, link_failure.link_dest);
                skip = true;
                break;
            }
        }

        if (skip) continue;

        nh_index = nhsel;

        next_hop = mpls_get_nexthop(rt, nh_index);

        /* Ignore next hop if there's no route towards it */
        if (next_hop == NULL)
            continue;
    } endfor_nexthops(rt);

    return next_hop;
}

