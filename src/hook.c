#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/protocol.h>
#include <net/mpls.h>

#include "include/mpls.h"

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "TI-MFA"
#endif
#define DESC "TI-MFA"

MODULE_AUTHOR("Sebastian");
MODULE_DESCRIPTION(DESC);
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
// @TODO: Figure out to make this module dependent on mpls
// MODULE_SOFTDEP("post: mpls_router");

extern bool mpls_output_possible(struct net_device *dev);

static struct nf_hook_ops *timfa_hooks;
static int number_of_timfa_hooks;

static unsigned int timfa_hook(void *priv, struct sk_buff * skb,
                              const struct nf_hook_state * state)
{
    struct mpls_shim_hdr *hdr;

    if (!pskb_may_pull(skb, sizeof(*hdr)))
		goto accept;

    rcu_read_lock();

    hdr = mpls_hdr(skb);

    if (hdr != NULL)
    {
        // @TODO: calculate label correctly
        // pr_debug("%s got mpls packet with label %u", state->in->name, MPLS_LABEL(hdr->label_stack_entry));
    }
    rcu_read_unlock();

accept:
    return NF_ACCEPT;
}

static int get_number_of_mpls_capable_net_devices(void)
{
    struct net_device *dev;
    int net_device_count;

    net_device_count = 0;

    rcu_read_lock();

    dev = first_net_device(&init_net);
    while (dev)
    {
        if (!mpls_output_possible(dev))
        {
            continue;
        }

        dev = next_net_device(dev);
        net_device_count++;
    }

    rcu_read_unlock();

    pr_debug("Found %d mpls capable devices", net_device_count);
    return net_device_count;
}

static int initialize_hooks(void)
{
    int i, return_code, number_of_mpls_devices;
    struct net_device *dev;

    number_of_mpls_devices = get_number_of_mpls_capable_net_devices();
    return_code = 0;
    i = 0;

    pr_debug("Found %d mpls capable net devices", number_of_mpls_devices);

    timfa_hooks = kmalloc_array(number_of_mpls_devices, sizeof(struct nf_hook_ops), GFP_KERNEL);

    read_lock(&dev_base_lock);
    dev = first_net_device(&init_net);

    while (dev)
    {
        if (!mpls_output_possible(dev))
        {
            goto next_device;
        }

        timfa_hooks[i].hook = timfa_hook;
        timfa_hooks[i].hooknum = NF_NETDEV_INGRESS;
        timfa_hooks[i].pf = NFPROTO_NETDEV;
        timfa_hooks[i].priority = NF_IP_PRI_LAST;
        timfa_hooks[i].dev = dev;

        return_code = nf_register_net_hook(&init_net, &timfa_hooks[i]);

        if (return_code < 0)
        {
            pr_err("Registering failed for device %s, with %d\n", dev->name, return_code);
            return return_code;
        }

        pr_debug("TI-MFA hook successfully registered on device: %s!\n", dev->name);
        i++;

next_device:
        dev = next_net_device(dev);
    }

    read_unlock(&dev_base_lock);

    number_of_timfa_hooks = i;

    pr_debug("Registering %d hooks succeeded", number_of_timfa_hooks);

    return return_code;
}

static int __init timfa_init(void)
{
    int return_code;

    pr_info("TI-MFA started\n");
    pr_debug("Initializing hooks");

    rcu_read_lock();

    return_code = initialize_hooks();

    rcu_read_unlock();

    return return_code;
}

static void __exit timfa_exit(void)
{
    int i;
    pr_debug("TI-MFA shutting down\n");

    for (i = 0; i < number_of_timfa_hooks; i++)
    {
        pr_debug("Unregistering TI-MFA hook registered on device: %s!\n", timfa_hooks[i].dev->name);
        nf_unregister_net_hook(&init_net, &timfa_hooks[i]);
    }

    kfree(timfa_hooks);

    pr_info("TI-MFA shut down\n");
}

module_init(timfa_init);
module_exit(timfa_exit);