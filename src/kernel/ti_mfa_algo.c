#include "debug.h"

#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <net/arp.h>
#include <net/neighbour.h>
#include <net/protocol.h>
#include <net/mpls.h>

#include "mpls.h"
#include "routes.h"
#include "ti_mfa_algo.h"
#include "utils.h"

#define DELETED_NEIGHS_INITIAL_SIZE MAX_NEW_LABELS
static struct ti_mfa_neigh **deleted_neighs;
static uint number_of_deleted_neighs;

uint flush_link_failure_stack(struct sk_buff *skb, struct ti_mfa_shim_hdr link_failures[], int max)
{
    uint count = 0;
    struct ti_mfa_shim_hdr *link_failure_entry = ti_mfa_hdr(skb);
    do {
        memmove(&link_failures[count], &link_failure_entry[count], sizeof(struct ti_mfa_shim_hdr));

        pr_debug("Link failure: node source: %pM, link source: %pM, link dest: %pM %s\n", link_failures[count].node_source, link_failures[count].link.source, link_failures[count].link.dest, link_failures[count].bos ? "[S]" : "");
        count++;

        if (count > max)
        {
            break;
        }
    } while (!link_failures[count - 1].bos);

    skb_pull(skb, sizeof(*link_failure_entry) * count);
    skb_reset_network_header(skb);

    return count;
}

static bool is_link_failure(const struct ti_mfa_link link, const uint link_failure_count, const struct ti_mfa_shim_hdr link_failures[])
{
    uint i = 0;
    /* Go through each link failure and
     * check if the neighbor belonging to the next hop is affected
     */
    for (i = 0; i < link_failure_count; i++) {
        struct ti_mfa_shim_hdr link_failure = link_failures[i];

        bool src_on_failed_link = !is_zero_ether_addr(link.source) &&
            (ether_addr_equal(link.source, link_failure.link.source)
            || ether_addr_equal(link.source, link_failure.link.dest)
            || ether_addr_equal(link.source, link_failure.node_source)
            );
        bool dest_on_failed_link = !is_zero_ether_addr(link.dest) &&
            (ether_addr_equal(link.dest, link_failure.link.source)
            || ether_addr_equal(link.dest, link_failure.link.dest)
            || ether_addr_equal(link.dest, link_failure.node_source)
            );

        if (src_on_failed_link || dest_on_failed_link) {
            pr_debug("Found neighbor with broken link [src: %pM | dest: %pM] == [src: %pM | dest: %pM] skipping...\n",
                     link.source, link.dest, link_failure.link.source, link_failure.link.dest);
            return true;
        }
    }

    return false;
}

static struct ti_mfa_nh *get_failure_free_next_hop(struct net *net, const u32 destination,
                                                   const uint local_link_failure_count,
                                                   const struct ti_mfa_shim_hdr local_link_failures[],
                                                   const uint link_failure_count,
                                                   const struct ti_mfa_shim_hdr link_failures[])
{
    struct mpls_route *rt    = NULL;
    struct neighbour *neigh  = NULL;
    struct mpls_nh *next_mpls_hop = NULL;
    struct ti_mfa_nh *next_hop  = NULL;
    struct ti_mfa_link nh_link;
    bool is_dest = false;

    rt = mpls_route_input_rcu(net, destination);
    if (!rt) {
        pr_err("No route found\n");
        return NULL;
    }

    if (rt->rt_nhn == 1) {
        u32 neigh_index;
        struct net_device *nh_dev;
        next_mpls_hop = rt->rt_nh;
        is_dest = true;

        nh_dev = next_mpls_hop->nh_dev;
        neigh_index = *((u32 *) mpls_nh_via(rt, next_mpls_hop));

        switch (next_mpls_hop->nh_via_table) {
            case NEIGH_ARP_TABLE:
                neigh = __ipv4_neigh_lookup_noref(nh_dev, neigh_index);
                break;
            default:
                // @TODO: Support for IPv6
                break;
        }

        if (neigh == NULL) {
            eth_zero_addr(nh_link.dest);
        }
        else {
            ether_addr_copy(nh_link.dest, neigh->ha);
        }
        ether_addr_copy(nh_link.source, next_mpls_hop->nh_dev->dev_addr);

        pr_debug("NH: dev: %s, mac: %pM\n", next_mpls_hop->nh_dev->name, nh_link.dest);

        if (is_link_failure(nh_link, local_link_failure_count, local_link_failures)
            || is_link_failure(nh_link, link_failure_count, link_failures)) {

            pr_debug("Not using this next hop, since there's a link failure for %pM - %pM\n", nh_link.source, nh_link.dest);
            return NULL;
        }
    } else {
        int nh_index = 0;
        for_nexthops(rt) {
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

            if (neigh == NULL)
                continue;

            /* TODO: what if dev addr is not ethernet? */
            ether_addr_copy(nh_link.dest, neigh->ha);
            ether_addr_copy(nh_link.source, nh_dev->dev_addr);

            pr_debug("NH: dev: %s, mac: %pM\n", nh_dev->name, nh_link.dest);
            debug_print_labels(nh->nh_labels, nh->nh_label);


            if (is_link_failure(nh_link, local_link_failure_count, local_link_failures)
                || is_link_failure(nh_link, link_failure_count, link_failures)) {

                pr_debug("Not using this next hop, since there's a link failure for %pM\n", nh_link.dest);
                continue;
            }

            nh_index = nhsel;

            next_mpls_hop = mpls_get_nexthop(rt, nh_index);

            /* Ignore next hop if there's no route towards it */
            if (next_mpls_hop == NULL)
                continue;
            /* If there's a route, just take the first next hop */
            else
                break;
        } endfor_nexthops(rt);
    }

    if (next_mpls_hop == NULL)
    {
        return NULL;
    }

    next_hop = kmalloc(sizeof(struct ti_mfa_nh), GFP_KERNEL);

    /* TODO: Check if neighbor exists <02-05-22> */
    next_hop->dev = next_mpls_hop->nh_dev;
    next_hop->labels = next_mpls_hop->nh_labels;
    memmove(next_hop->label, next_mpls_hop->nh_label, sizeof(*(next_mpls_hop->nh_label)));
    ether_addr_copy(next_hop->ha, nh_link.dest);
    next_hop->is_dest = is_dest;

    return next_hop;
}

/* Step 2): Determine shortest path P to t based on all  link failures in the remaining network G' (Get next hop)
*/
static int get_shortest_path(struct net *net, const u32 original_destination,
                             const struct ti_mfa_shim_hdr link_failures[], const uint link_failure_count,
                             struct ti_mfa_nh *next_hop)
{
    int index = 0, error = 0, reroute_count = 0;
    struct mpls_route *rt;
    struct ti_mfa_nh *tmp_nh = NULL;
    struct net_device *out_dev = NULL;
    uint hop_min = UINT_MAX;
    u32 backup_dest = 0;

    /* TODO:  <20-04-22>
     * @Parameters: link failures, destination
     * 1) For each link failure
     *  1. look up the evasion route (mpls label)
     *  2. get the mpls route for it
     *  3. save the mpls route and defined outgoing dev
     * 2) For each saved mpls route (label and dev)
     *  1. Save next hop
     * 3) Calculate next hop with shortest path
     * @returns next hop
     */

    /* Step 1) */
    for (index = 0; index < link_failure_count; ++index) {
        struct ti_mfa_link failed_link = ti_mfa_hdr_to_link(link_failures[index]);

        /* Step 1.1 */
        struct ti_mfa_route *found_rt = rt_lookup(net, failed_link);
        if (!found_rt)
            continue;

        /* Step 1.2 */
        rt = mpls_route_input_rcu(net, found_rt->destination_label);
        if (!rt) {
            pr_err("No route found\n");
            continue;
        }

        pr_debug("Found backup route for link_failure: %pM-%pM: dest: %u\n",
                found_rt->link.source, found_rt->link.dest, found_rt->destination_label);

        /* Use number of hops as metric. I didn't find any route preference metric for mpls */
        if (rt->rt_nhn < hop_min) {
            struct net_device *out_dev_tmp = NULL;
            tmp_nh = get_failure_free_next_hop(net, found_rt->destination_label,
                                                 next_hop->link_failure_count, next_hop->link_failures,
                                                 link_failure_count, link_failures);

            if (tmp_nh == NULL)
                continue;

            out_dev_tmp = found_rt->out_dev;
            if (mpls_output_possible(out_dev_tmp))
                out_dev = out_dev_tmp;

            backup_dest = found_rt->destination_label;

            hop_min = rt->rt_nhn;
        }

        reroute_count++;
    }

    /* Step 1) for local  link failures */
    for (index = 0; index < next_hop->link_failure_count; ++index) {
        struct ti_mfa_link failed_link = ti_mfa_hdr_to_link(next_hop->link_failures[index]);

        /* Step 1.1 */
        struct ti_mfa_route *found_rt = rt_lookup(net, failed_link);
        if (!found_rt)
            continue;

        /* Step 1.2 */
        rt = mpls_route_input_rcu(net, found_rt->destination_label);
        if (!rt) {
            pr_err("No route found\n");
            continue;
        }

        pr_debug("Found backup route for link_failure: %pM-%pM: dest: %u\n",
                found_rt->link.source, found_rt->link.dest, found_rt->destination_label);

        /* Use number of hops as metric. I didn't find any route preference metric for mpls */
        if (rt->rt_nhn < hop_min) {
            struct net_device *out_dev_tmp = NULL;

            pr_debug("Looking up next hop to label %u\n", found_rt->destination_label);

            tmp_nh = get_failure_free_next_hop(net, found_rt->destination_label,
                                               next_hop->link_failure_count, next_hop->link_failures,
                                               link_failure_count, link_failures);

            if (tmp_nh == NULL) {
                pr_debug("Couldn't find a failure free nexthop for backup route\n");
                continue;
            }

            out_dev_tmp = found_rt->out_dev;
            if (mpls_output_possible(out_dev_tmp))
                out_dev = out_dev_tmp;

            pr_debug("Found backup route to label %u via dev %s\n",
                    found_rt->destination_label, out_dev->name);

            backup_dest = found_rt->destination_label;

            hop_min = rt->rt_nhn;
        }

        reroute_count++;
    }

    pr_debug("Found %d reroutes\n", reroute_count);

    /* Look for destination route if there's no backup route */
    if (reroute_count == 0) {
        pr_debug("Got 0 reroutes. Looking for next hop to original destination %u\n", original_destination);
        tmp_nh = get_failure_free_next_hop(net, original_destination,
                                           next_hop->link_failure_count, next_hop->link_failures,
                                           link_failure_count, link_failures);
    }

    if (out_dev)
        tmp_nh->dev = out_dev;

    if (tmp_nh == NULL)
    {
        pr_debug("No next hop found. Sending packet back\n");
        tmp_nh = kmalloc(sizeof(struct ti_mfa_nh), GFP_KERNEL);
        tmp_nh->label[0] = original_destination;
        tmp_nh->labels = 1;
        tmp_nh->dev = NULL;
        eth_zero_addr(tmp_nh->ha);
    }

    next_hop->dev = tmp_nh->dev;
    ether_addr_copy(next_hop->ha, tmp_nh->ha);
    next_hop->is_dest = tmp_nh->is_dest;
    next_hop->labels = 0;

    if (tmp_nh->label[0] != backup_dest && reroute_count > 0) {
        next_hop->label[0] = backup_dest;
        next_hop->labels++;
    }

    memmove(&next_hop->label[next_hop->labels], tmp_nh->label, sizeof(*(tmp_nh->label)));
    next_hop->labels += tmp_nh->labels;

    /* Add destination label if we do a detour */
    if (reroute_count > 0 || (next_hop->labels == 0 && !next_hop->is_dest)) {
        next_hop->label[next_hop->labels] = original_destination;
        next_hop->labels++;
        next_hop->is_dest = false;
    }

    debug_print_next_hop(*next_hop);

    kfree(tmp_nh);

    return error;
}

void set_local_link_failures(const struct net *net,
        const struct ti_mfa_shim_hdr existing_link_failures[], const uint link_failure_count,
        u32 destination, struct ti_mfa_nh *next_hop)
{
    uint i = 0, link_failures = 0;

    for (i = 0; i < number_of_deleted_neighs; i++) {
        struct ti_mfa_neigh *neigh = deleted_neighs[i];
        uint j = 0;
        bool label_found = false;
        bool link_failure_found = false;

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

        /* Don't add an already existing link failure */
        for (j = 0;  j < link_failure_count; j++) {
            struct ti_mfa_link exisiting_link = ti_mfa_hdr_to_link(existing_link_failures[j]);
            struct ti_mfa_link neigh_link;
            ether_addr_copy(neigh_link.source, neigh->dev->dev_addr);
            ether_addr_copy(neigh_link.dest, neigh->ha);

            if (links_equal(exisiting_link, neigh_link)) {
                link_failure_found = true;
                break;
            }
        }

        if (link_failure_found)
            continue;

        ether_addr_copy(next_hop->link_failures[link_failures].link.source, neigh->dev->dev_addr);
        ether_addr_copy(next_hop->link_failures[link_failures].link.dest, neigh->ha);

        /* Setting link_failures[]->node_source to empty, because it's the same for all of them */
        eth_zero_addr(next_hop->link_failures[link_failures].node_source);

        pr_debug("Adding link failure from %pM to %pM for label %u\n", next_hop->link_failures[link_failures].link.source, next_hop->link_failures[link_failures].link.dest, destination);
        link_failures++;
    }
    next_hop->link_failure_count = link_failures;
}

bool set_link_failure_stack(struct sk_buff *skb, const uint count,
                            const struct ti_mfa_shim_hdr link_failures[],
                            bool bos)
{
    int i = 0;
    struct ti_mfa_shim_hdr *hdr;

    skb_push(skb, sizeof(*hdr) * count);
    skb_reset_network_header(skb);
    hdr = ti_mfa_hdr(skb);

    for (i = count - 1; i >= 0; i--) {
        struct ti_mfa_shim_hdr ti_mfa_entry = link_failures[i];
        hdr[i] = ti_mfa_entry;
        hdr[i].bos = bos;

        if (is_zero_ether_addr(ti_mfa_entry.node_source)) {
            ether_addr_copy(hdr[i].node_source, skb->dev->dev_addr);
        }

        pr_debug("%u: node source: %pM, link source: %pM, link dest: %pM%s\n", i, hdr[i].node_source, hdr[i].link.source, hdr[i].link.dest, hdr[i].bos ? " [S]" : "");
        bos = false;
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
int set_new_label_stack(const struct net *net,struct sk_buff *skb,
                        const struct mpls_entry_decoded orig_label_path[], unsigned int orig_label_count,
                        struct ti_mfa_nh *nh, const struct ti_mfa_shim_hdr link_failures[], unsigned int link_failure_count,
                        bool flush_link_failure_stack)
{
    int error = 0;
    int i, j, headroom, new_header_size;
    unsigned int hh_len, mtu, ti_mfa_hdr_size, mpls_hdr_size = 0;
    unsigned int label_count = 0;
    const unsigned int max_labels = nh->labels == 0 ? orig_label_count : nh->labels;
    struct mpls_entry_decoded *new_label_stack = kmalloc_array(max_labels, sizeof(struct mpls_entry_decoded), GFP_KERNEL);
    struct net_device *out_dev = nh->dev;

    if (!flush_link_failure_stack)
        link_failure_count += nh->link_failure_count;
    else
        link_failure_count = nh->link_failure_count;

    pr_debug("Setting new label stack. orig_label_count: %u\n", orig_label_count);
    /* TODO: Validate node computing <22-04-22> */
    for (i = 0; i < nh->labels; i++) {
        struct mpls_entry_decoded entry;
        bool found = false;

        for (j = i; j < orig_label_count; j++) {
            if (nh->label[i] != orig_label_path[j].label)
            {
                continue;
            }

            found = true;
            entry = orig_label_path[j];
        }

        if (!found) {
            entry.bos = false;
            entry.label = nh->label[i];
            entry.ttl = net->mpls.default_ttl;
            entry.tc = 0;
        }

        new_label_stack[label_count] = entry;
        pr_debug("%u: set label: %u %s\n", label_count, new_label_stack[label_count].label, new_label_stack[label_count].bos ? "[S]" : "");
        label_count++;
    }

    if (nh->labels == 0 && orig_label_path > 0) {
        for (i = 0; i < orig_label_count; ++i) {
            new_label_stack[i] = orig_label_path[i];
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

    skb_orphan(skb);

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

    hh_len = LL_RESERVED_SPACE(out_dev);
	if (!out_dev->header_ops)
		hh_len = 0;

    headroom = skb_headroom(skb);
    if (new_header_size + hh_len > headroom)
    {
        if (skb_cow(skb, new_header_size + hh_len)) {
            pr_err("Cannot expand head. headroom: %d, new header size: %d\n", headroom, new_header_size + hh_len);
            error = -1;
            goto out_free;
        }
    }

    skb->dev = out_dev;

    if (link_failure_count > 0)
    {
        bool bos = true;
        uint old_link_failure_count = link_failure_count - nh->link_failure_count;

        /* Set new ti-mfa header */
        pr_debug("Setting new ti-mfa header\n");

        bos = set_link_failure_stack(skb, nh->link_failure_count, nh->link_failures, bos);

        if (!flush_link_failure_stack && link_failure_count < MAX_NEW_LABELS) {
            pr_debug("Not flushing link failure stack\n");
            set_link_failure_stack(skb, old_link_failure_count, link_failures, bos);
        }
    }

    set_mpls_header(skb, label_count, new_label_stack, link_failure_count > 0);

out_free:
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
int __run_ti_mfa(struct net *net, struct sk_buff *skb)
{
    bool flush_failure_stack = false;
    struct mpls_entry_decoded label_stack[MAX_NEW_LABELS];
    struct ti_mfa_shim_hdr link_failures[MAX_NEW_LABELS];
    struct mpls_entry_decoded destination;
    uint mpls_label_count = 0;
    uint link_failure_count = 0;
    struct ti_mfa_nh next_hop;
    struct ethhdr ethh = *eth_hdr(skb);

    pr_debug("==> rcv on %s from %pM\n", skb->dev->name, ethh.h_source);
    debug_print_packet(skb);

    mpls_label_count = flush_mpls_label_stack(skb, label_stack, MAX_NEW_LABELS);

    if (mpls_label_count == 0) {
        pr_err("Got zero mpls labels\n");
        return TI_MFA_ERROR;
    }

    destination = label_stack[mpls_label_count - 1];
    if (destination.label == TI_MFA_MPLS_EXTENSION_LABEL) {
        mpls_label_count--;
        destination = label_stack[mpls_label_count - 1];

        link_failure_count = flush_link_failure_stack(skb, link_failures, MAX_NEW_LABELS);
    }

    pr_debug("Label Stack: (%u Labels)\n", mpls_label_count);
    debug_print_mpls_entries(mpls_label_count, label_stack);

    rcu_read_lock();

    set_local_link_failures(net, link_failures, link_failure_count, destination.label, &next_hop);

    if (get_shortest_path(net, destination.label, link_failures, link_failure_count, &next_hop) != 0)
        goto out_error;

    if (next_hop.is_dest && next_hop.labels == 0 && next_hop.link_failure_count == 0) {
        struct ethhdr *new_eth;

        rcu_read_unlock();

        set_mpls_header(skb, mpls_label_count, label_stack, false);

        new_eth = eth_hdr(skb);
        *new_eth = ethh;

        pr_debug("OUT\n");
        debug_print_packet(skb);

        return TI_MFA_PASS;
    }
    else  {
        if ((next_hop.dev == NULL || next_hop.dev == skb->dev) && is_zero_ether_addr(next_hop.ha)) {
            /* No next hop was found, so we're sending the packet back */
            next_hop.dev = skb->dev;
            ether_addr_copy(next_hop.ha, ethh.h_source);
            pr_debug("Sending packet back to %pM via dev %s\n", next_hop.ha, next_hop.dev->name);

        }
        if (set_new_label_stack(net, skb, label_stack, mpls_label_count,
                                &next_hop, link_failures, link_failure_count, flush_failure_stack) != 0)
            goto out_error;
    }

    rcu_read_unlock();

    eth_header(skb, skb->dev, ntohs(skb->protocol), next_hop.ha, skb->dev->dev_addr, 0);
    skb_reset_mac_header(skb);

    ethh = *eth_hdr(skb);

    debug_print_packet(skb);

    pr_debug("Eth dest: %pM, src: %pM\n", ethh.h_dest, ethh.h_source);
    pr_debug("xmit via %s ==>\n", skb->dev->name);

    if (dev_queue_xmit(skb) != NET_XMIT_SUCCESS)
    {
        pr_err("Error on xmit\n");
        goto out_error;
    }

    goto out_success;

out_error:
    rcu_read_unlock();
    return TI_MFA_ERROR;

out_success:
    return TI_MFA_SUCCESS;
}

int run_ti_mfa(struct net *net, struct sk_buff *skb)
{
    int return_code = TI_MFA_SUCCESS;

    if (is_not_mpls(skb))
    {
        return TI_MFA_PASS;
    }

    return_code = __run_ti_mfa(net, skb);

    return return_code;
}

void ti_mfa_ifdown(struct net_device *dev)
{
    struct mpls_route __rcu **platform_label;
    struct net *net = dev_net(dev);
    unsigned label_index = 0, tmp = number_of_deleted_neighs;

    if (dev == NULL || net == NULL)
        return;

    pr_debug("ifdown for dev %s\n", dev->name);

    platform_label = rtnl_dereference(net->mpls.platform_label);
    for (label_index = 0; label_index < net->mpls.platform_labels; label_index++) {
        struct mpls_route *rt = rtnl_dereference(platform_label[label_index]);
        if (rt == NULL)
            continue;

        for_nexthops(rt) {
            struct neighbour *neigh = NULL;
            uint i = 0;
            u32 neigh_index = *((u32 *) mpls_nh_via(rt, nh));
            bool found_deleted_neigh = false;

            if (nh->nh_dev == NULL || (nh->nh_dev && nh->nh_dev != dev))
                continue;

            switch (nh->nh_via_table) {
                case NEIGH_ARP_TABLE:
                    neigh = __ipv4_neigh_lookup_noref(nh->nh_dev, neigh_index);
                    break;
                default:
                    // TODO: Support for IPv6
                    break;
            }

            if (neigh == NULL) {
                continue;
            }

            if (number_of_deleted_neighs > 0 && number_of_deleted_neighs % DELETED_NEIGHS_INITIAL_SIZE == 0) {
                pr_err("Not enough space in deleted neighbor array. Len: %u\n", number_of_deleted_neighs);
                break;
            }

            if (!(neigh == NULL || is_zero_ether_addr(neigh->ha) || neigh->dev != dev))
                /* pr_debug("nh: %pM", neigh->ha); */

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

                        if (found)
                            continue;

                        deleted_neigh->labels[index] = nh->nh_label[j];
                        pr_debug("Added label %u\n", deleted_neigh->labels[index]);
                    }

                    deleted_neigh->label_count += j;
                    continue;
                }
            }

            if (!found_deleted_neigh) {
                uint j = 0;
                deleted_neighs[tmp] = kzalloc(sizeof(struct ti_mfa_neigh), GFP_KERNEL);
                deleted_neighs[tmp]->net = net;
                deleted_neighs[tmp]->dev = nh->nh_dev;

                if (is_zero_ether_addr(neigh->ha) || neigh->dev != dev)
                    eth_zero_addr(deleted_neighs[tmp]->ha);
                else
                    ether_addr_copy(deleted_neighs[tmp]->ha, neigh->ha);

                for (j = 0; j < nh->nh_labels; j++) {
                    uint index = j + deleted_neighs[tmp]->label_count;
                    uint k = 0;
                    bool found = false;
                    for (k = 0; k < deleted_neighs[tmp]->label_count; k++) {
                        if (deleted_neighs[tmp]->labels[k] != nh->nh_label[k])
                            continue;

                        found = true;
                        break;
                    }
                    if (found)
                        continue;
                    deleted_neighs[tmp]->labels[index] = nh->nh_label[j];
                    pr_debug("Added label neigh %d [%d] = %u\n", tmp, index, deleted_neighs[tmp]->labels[index]);
                }

                if (nh->nh_labels == 0) {
                    deleted_neighs[tmp]->labels[j] = label_index;
                    pr_debug("Added label to neigh %d [%d] = %u\n", tmp, j, deleted_neighs[tmp]->labels[j]);
                    deleted_neighs[tmp]->label_count++;
                }

                pr_debug("Added neigh %u = %pM\n", tmp,  deleted_neighs[tmp]->ha);
                deleted_neighs[tmp]->label_count += j;
                tmp++;
            }
        } endfor_nexthops(rt);
    }

    number_of_deleted_neighs = tmp;
    pr_debug("deleted_neighs: %u\n", number_of_deleted_neighs);
}

void ti_mfa_ifup(const struct net_device *dev)
{
    /* FIXME: Use hash table for link failures instead <26-06-22> */
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

    pr_debug("local link failure table initialized\n");

    return 0;
}

void cleanup_ti_mfa(void)
{
    uint i = 0;

    pr_debug("Freeing up local link failure table\n");

    for (i = 0; i < number_of_deleted_neighs; i++) {
        if (deleted_neighs[i] == NULL) continue;

        pr_debug("Freeing local link failure for %s\n", deleted_neighs[i]->dev->name);
        kfree(deleted_neighs[i]);
    }
    kfree(deleted_neighs);

    pr_debug("local link failure table freed\n");
}

void ti_mfa_clean_dev(const struct net_device *dev)
{
    uint i = 0;
    for (i = 0; i < number_of_deleted_neighs; i++) {
        if (deleted_neighs[i] == NULL
                || dev == NULL
                || deleted_neighs[i]->dev != dev) {
            continue;
        }

        pr_debug("Freeing local link failure for %s\n", deleted_neighs[i]->dev->name);
        kfree(deleted_neighs[i]);
        deleted_neighs[i] = NULL;
    }
}
