#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mpls.h>
#include <net/mpls.h>

#include "utils.h"

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
