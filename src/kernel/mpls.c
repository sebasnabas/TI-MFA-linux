#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/skbuff.h>
#include <net/arp.h>
#include <net/neighbour.h>

#include "mpls.h"
#include "ti_mfa.h"

bool is_not_mpls(struct sk_buff *skb)
{
    if (!pskb_may_pull(skb, sizeof(struct mpls_shim_hdr)) || mpls_hdr(skb) == NULL)
    {
        return true;
    }

    return false;
}

uint get_number_of_mpls_capable_net_devices(struct net *net)
{
    struct net_device *dev;
    int net_device_count;

    net_device_count = 0;

    rcu_read_lock();

    dev = first_net_device(net);
    while (dev)
    {
        if (rcu_dereference(dev->mpls_ptr) == NULL) continue;

        dev = next_net_device(dev);
        net_device_count++;
    }

    rcu_read_unlock();

    return net_device_count;
}

/* Step 1): Decode mpls labels, remove them from header and save them
*/
uint flush_mpls_label_stack(struct sk_buff *skb, struct mpls_entry_decoded mpls_entries[], int max_labels)
{
    uint label_count = 0;
    struct mpls_shim_hdr *mpls_hdr_entry = mpls_hdr(skb);
    do {
        mpls_entries[label_count] = mpls_entry_decode(&mpls_hdr_entry[label_count]);

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
