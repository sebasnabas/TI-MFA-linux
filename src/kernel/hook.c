#include "debug.h"

#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/notifier.h>
#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <net/mpls.h>
#include <net/protocol.h>
#include <net/sock.h>

#include "ti_mfa_genl.h"
#include "mpls.h"
#include "ti_mfa_algo.h"
#include "utils.h"

MODULE_AUTHOR("Sebastian");
MODULE_DESCRIPTION("Topology Independent Multi-Failure Alternate (TI-MFA)");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: mpls_router");

static struct nf_hook_ops *timfa_hooks;
static u32 number_of_timfa_hooks;

static int ti_mfa_notify(struct notifier_block *this, unsigned long event, void *ptr)
{
    struct net_device *dev = netdev_notifier_info_to_dev(ptr);
    struct mpls_dev *mdev;

    mdev = mpls_dev_get(dev);
    if (!mdev)
        return NOTIFY_OK;

    switch (event) {
        case NETDEV_GOING_DOWN:
            ti_mfa_ifdown(dev);
            break;

        case NETDEV_UP:
            ti_mfa_ifup(dev);
        default:
            break;
    }

    return NOTIFY_OK;
}

static struct notifier_block ti_mfa_dev_notifier = {
    .notifier_call = ti_mfa_notify,
};

static unsigned int timfa_ingress_hook(void *priv, struct sk_buff *skb,
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

static int initialize_hooks(void)
{
    int return_code;
    uint i, number_of_mpls_devices;
    struct net_device *dev;

    number_of_mpls_devices = get_number_of_mpls_capable_net_devices(&init_net);
    return_code = 0;
    i = 0;

    pr_debug("Found %d mpls capable net devices\n", number_of_mpls_devices);

    timfa_hooks = kmalloc_array(number_of_mpls_devices * 2, sizeof(struct nf_hook_ops), GFP_KERNEL);

    read_lock(&dev_base_lock);
    dev = first_net_device(&init_net);

    while (dev)
    {
        // START Ingress
        timfa_hooks[i].hook = timfa_ingress_hook;
        timfa_hooks[i].hooknum = NF_NETDEV_INGRESS;
        timfa_hooks[i].pf = NFPROTO_NETDEV;
        timfa_hooks[i].priority = NF_IP_PRI_LAST;
        timfa_hooks[i].dev = dev;

        return_code = nf_register_net_hook(&init_net, &timfa_hooks[i]);

        if (return_code < 0)
        {
            pr_err("Registering ingress hook failed for device %s, with %d\n", dev->name, return_code);

            goto exit;
        }

        pr_info("TI-MFA ingress hook registered on device: %s\n", dev->name);
        i++;
        dev = next_net_device(dev);
    }

    pr_debug("Registering %d hooks succeeded\n", i);

exit:
    read_unlock(&dev_base_lock);

    number_of_timfa_hooks = i;

    return return_code;
}

static void unregister_hooks(void)
{
    int i;
    for (i = 0; i < number_of_timfa_hooks; i++)
    {
        pr_debug("Unregistering TI-MFA hook registered on device: %s!\n", timfa_hooks[i].dev->name);
        nf_unregister_net_hook(&init_net, &timfa_hooks[i]);
    }
}

static int __init timfa_init(void)
{
    int err = 0;

    pr_info("TI-MFA started\n");

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

static void __exit timfa_exit(void)
{
    pr_debug("TI-MFA shutting down\n");

    unregister_netdevice_notifier(&ti_mfa_dev_notifier);
    cleanup_ti_mfa();
    ti_mfa_genl_unregister();
    unregister_hooks();
    kfree(timfa_hooks);

    pr_info("TI-MFA shut down\n");
}

module_init(timfa_init);
module_exit(timfa_exit);
