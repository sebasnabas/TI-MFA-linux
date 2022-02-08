#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/protocol.h>
#include <net/mpls.h>

#include "utils.h"

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "TI-MFA"
#endif
#define DESC "TI-MFA"

MODULE_AUTHOR("Sebastian");
MODULE_DESCRIPTION(DESC);
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");

extern bool mpls_output_possible(struct net_device *dev);

static struct nf_hook_ops timfa;

static struct nf_hook_ops create_hook(struct net_device *dev)
{
    struct nf_hook_ops hook;
    hook.hook = timfa_hook;
    hook.hooknum = NF_NETDEV_INGRESS;
    hook.pf = NFPROTO_NETDEV;
    hook.priority = NF_IP_PRI_LAST;
    hook.dev = dev;
    return hook;
}

static unsigned int timfa_hook(void *priv, struct sk_buff * skb,
                              const struct nf_hook_state * state)
{
    rcu_read_lock();

    if (eth_p_mpls(skb->protocol))
    {
        pr_debug("%s got mpls packet", state->in->name);
    }
    pr_debug("%s got packet", state->in->name);
    rcu_read_unlock();

    return NF_ACCEPT;
}

static int __init timfa_init(void)
{
    int return_code;
    struct net_device *dev;

    pr_info("TI-MFA started\n");
    pr_debug("Initializing hooks");

    rcu_read_lock();

    dev = first_net_device(&init_net);

    while(dev)
    {
        if(mpls_output_possible(dev) && strcmp(dev->name, "eth1") == 0)
        {
            pr_debug("Found device %s with possible mpls output", dev->name);
            break;
        }

        dev = next_net_device(dev);
    }

    rcu_read_unlock();
    timfa = create_hook(dev);
    return_code = nf_register_net_hook(&init_net, &timfa);
    if (return_code < 0)
    {
        pr_err("Registering failed for device %s, with %d\n", dev->name, return_code);
        return return_code;
    }
    pr_debug("TI-MFA hook successfully registered on device: %s!\n", dev->name);

    printk(KERN_INFO "TI-MFA hook successfully registered (%d)!\n", return_code);
    return return_code;
}

static void __exit timfa_exit(void)
{
    int i;
    pr_debug("TI-MFA shutting down\n");

    nf_unregister_net_hook(&init_net, &timfa);

    pr_info("TI-MFA shut down\n");
}

module_init(timfa_init);
module_exit(timfa_exit);
