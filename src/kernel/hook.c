#include "debug.h"

#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net_namespace.h>
#include <linux/notifier.h>
#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <net/mpls.h>
#include <net/net_namespace.h>
#include <net/protocol.h>
#include <net/sock.h>

#include "ti_mfa_genl.h"
#include "mpls.h"
#include "ti_mfa_algo.h"
#include "utils.h"

MODULE_AUTHOR("Sebastian");
MODULE_DESCRIPTION("Topology Independent Multi-Failure Alternate (TI-MFA)");
MODULE_VERSION("0.2");
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: mpls_router");

#define TABLE_SIZE 5  // 5 bits = 32 entries
static DEFINE_HASHTABLE(ti_mfa_nf_hook_table, TABLE_SIZE);

struct ti_mfa_nf_hook {
    struct nf_hook_ops nf_hook;
    struct hlist_node  hnode;
};

static unsigned int ti_mfa_ingress_hook(void *priv, struct sk_buff *skb,
                                       const struct nf_hook_state *state)
{
    unsigned int exit_code = NF_ACCEPT;

    if (!eth_p_mpls(skb->protocol))
    {
        goto exit;
    }

    switch(run_ti_mfa(state->net, skb))
    {
        case TI_MFA_SUCCESS:
            pr_debug("NF_STOLEN\n");
            exit_code = NF_STOLEN;
            break;

        case TI_MFA_ERROR:
            pr_debug("ti-mfa failed on [%s]. Dropping...\n", skb->dev->name);
            exit_code = NF_DROP;
            break;

        /* Handling TI_MFA_PASS */
        default:
            pr_debug("NF_ACCEPT\n");
            exit_code = NF_ACCEPT;
            break;
    }

exit:
    return exit_code;
}

u32 ti_mfa_nf_hook_hash(struct net_device *dev)
{
    return jhash(dev->name, IFNAMSIZ, 0);
}

static int ti_mfa_register_nf_hook(struct net *net, struct net_device *dev)
{
    struct ti_mfa_nf_hook *hook = NULL;
    int ret = 0;
    u32 key = ti_mfa_nf_hook_hash(dev);
    hash_for_each_possible_rcu(ti_mfa_nf_hook_table, hook, hnode, key) {

        /* Possible TODO
         * Only accept one evasion route for each link failure for now
         */
        if (hook->nf_hook.dev == dev) {
            pr_debug("Hook already in table for dev %s", dev->name);
            break;
        }
    }

    if (hook != NULL) {
        return 0;
    }

    hook = kmalloc(sizeof(*hook), GFP_KERNEL);
    if (hook == NULL) {
        pr_err("Could not allocate memory for new hook entry\n");
        return -ENOMEM;
    }
    hook->nf_hook.hook = ti_mfa_ingress_hook;
    hook->nf_hook.hooknum = NF_NETDEV_INGRESS;
    hook->nf_hook.pf = NFPROTO_NETDEV;
    hook->nf_hook.priority = NF_IP_PRI_LAST;
    hook->nf_hook.dev = dev;

    hash_add_rcu(ti_mfa_nf_hook_table, &hook->hnode, ti_mfa_nf_hook_hash(dev));

    ret = nf_register_net_hook(net, &(hook->nf_hook));

    if (ret != 0) {
        pr_err("nf hook register failed on %s", dev->name);
    } else {
        pr_debug("nf hook registered on %s", dev->name);
    }
    return ret;
}

static void ti_mfa_unregister_nf_hook(struct net *net, struct net_device *dev)
{
    struct ti_mfa_nf_hook *hook;

    if (dev == NULL || hash_empty(ti_mfa_nf_hook_table)) {
        return;
    }

    hash_for_each_possible_rcu(ti_mfa_nf_hook_table, hook,
                               hnode, ti_mfa_nf_hook_hash(dev)) {
        pr_debug("Unregistering TI-MFA hook for device: %s!\n", dev->name);
        nf_unregister_net_hook(net, &(hook->nf_hook));
    }
}

static int ti_mfa_notify(struct notifier_block *this, unsigned long event, void *ptr)
{
    struct net_device *dev = netdev_notifier_info_to_dev(ptr);
    struct net *net = dev_net(dev);
    struct mpls_dev *mdev;

    mdev = mpls_dev_get(dev);
    if (!mdev || !net) {

        return NOTIFY_OK;
    }

    switch (event) {
        case NETDEV_GOING_DOWN:
            ti_mfa_ifdown(dev);
            break;

        case NETDEV_UP:
            ti_mfa_ifup(dev);
            break;

        case NETDEV_REGISTER:
            ti_mfa_register_nf_hook(net, dev);
            break;

        case NETDEV_UNREGISTER:
            ti_mfa_unregister_nf_hook(net, dev);
            break;
        default:
            break;
    }

    return NOTIFY_OK;
}

static struct notifier_block ti_mfa_dev_notifier = {
    .notifier_call = ti_mfa_notify,
};

static int initialize_hooks(void)
{
    int return_code;
    uint i, number_of_mpls_devices;
    struct net_device *dev;

    number_of_mpls_devices = get_number_of_mpls_capable_net_devices(&init_net);
    return_code = 0;
    i = 0;

    pr_debug("Found %d mpls capable net devices\n", number_of_mpls_devices);

    read_lock(&dev_base_lock);
    dev = first_net_device(&init_net);

    while (dev)
    {
        return_code = ti_mfa_register_nf_hook(&init_net, dev);
        if (return_code < 0)
        {
            pr_err("Registering ingress hook failed for device %s, with %d\n", dev->name, return_code);

            goto exit;
        }

        pr_info("TI-MFA ingress hook registered on device: %s\n", dev->name);
        i++;
        dev = next_net_device(dev);
    }

exit:
    read_unlock(&dev_base_lock);

    return return_code;
}

static void unregister_hooks(void)
{
    int i = 0;
    struct ti_mfa_nf_hook *hook;
    hash_for_each_rcu(ti_mfa_nf_hook_table, i, hook, hnode) {
        pr_debug("Unregistering TI-MFA hook registered on device: %s!\n", hook->nf_hook.dev->name);
        nf_unregister_net_hook(&init_net, &(hook->nf_hook));
    }
}

static int __init ti_mfa_init(void)
{
    int err = 0;

    pr_info("TI-MFA started\n");

    hash_init(ti_mfa_nf_hook_table);
    err = initialize_hooks();
    if (err != 0)
        goto out;

    err = initialize_ti_mfa();
    if (err != 0)
        goto out_unregister;

    err = ti_mfa_genl_register();
    if (err != 0) {
        goto out_genl_unregister;
    }

    err = register_netdevice_notifier(&ti_mfa_dev_notifier);
    if (err != 0)
        goto out_genl_unregister;

out:
    return err;

out_genl_unregister:
    ti_mfa_genl_unregister();
    goto out_cleanup;

out_cleanup:
    cleanup_ti_mfa();
    goto out_unregister;

out_unregister:
    unregister_hooks();
    goto out;

}

static void __exit ti_mfa_exit(void)
{
    pr_debug("TI-MFA shutting down\n");

    unregister_netdevice_notifier(&ti_mfa_dev_notifier);
    cleanup_ti_mfa();
    ti_mfa_genl_unregister();
    unregister_hooks();

    pr_info("TI-MFA shut down\n");
}

module_init(ti_mfa_init);
module_exit(ti_mfa_exit);
