#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/module.h>
#include <linux/kernel.h>
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

#include "include/mpls.h"
#include "include/ti_mfa_algo.h"
#include "include/utils.h"

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

static unsigned int timfa_ingress_hook(void *priv, struct sk_buff * skb,
                                       const struct nf_hook_state * state)
{
    struct ethhdr eth;
    struct ethhdr *ethh;
    struct mpls_shim_hdr *hdr;
    struct mpls_entry_decoded mpls_entry;
    struct ti_mfa_shim_hdr *ti_mfa_h;

    if (!eth_p_mpls(skb->protocol))
    {
        goto accept;
    }

    if (!pskb_may_pull(skb, sizeof(*hdr)))
    {
        goto accept;

    }

    hdr = mpls_hdr(skb);

    if (hdr == NULL)
    {
        goto accept;
    }

    mpls_entry = mpls_entry_decode(hdr);
    pr_debug("[%s]:[%s] INGRESS Got mpls packet with label %u\n", HOST_NAME, state->in->name, mpls_entry.label);

    if (!mpls_entry.bos)
    {
        struct mpls_entry_decoded second_mpls_entry = mpls_entry_decode(&hdr[1]);
        if (second_mpls_entry.label != MPLS_LABEL_EXTENSION && !second_mpls_entry.bos)
        {
            goto accept;
        }
    } else {
        pr_debug("Got mpls packet without ti-mfa header\n");
        goto accept;
    }

    ethh = eth_hdr(skb);
    eth = *ethh;

    /* Pop regular & extension mpls label */
    skb_pull(skb, sizeof(*hdr));
    skb_pull(skb, sizeof(*hdr));
    skb_reset_network_header(skb);

    /* Pop ti-mfa shim headers */
    do {
        ti_mfa_h = ti_mfa_hdr(skb);
        skb_pull(skb, sizeof(*ti_mfa_h));
        pr_debug("TI-MFA header pulled:\n");
        pr_debug("node: %pM, Src: %pM; Dst: %pM %s\n",
                ti_mfa_h->node_source, ti_mfa_h->link_source, ti_mfa_h->link_dest,
                ti_mfa_h->bos ? "[S]" : ""
        );
    } while (!ti_mfa_h->bos);

    skb_reset_network_header(skb);

    /* Set regular mpls header and eth header again */
    skb_push(skb, sizeof(*hdr));
    skb_reset_network_header(skb);
    hdr = mpls_hdr(skb);
    *hdr = mpls_entry_encode(mpls_entry.label, mpls_entry.ttl, mpls_entry.tc, mpls_entry.bos);

    skb_push(skb, sizeof(*ethh));
    skb_reset_mac_header(skb);

    ethh = eth_hdr(skb);
    *ethh = eth;

accept:
    return NF_ACCEPT;
}

static unsigned int timfa_egress_hook(void *priv, struct sk_buff * skb,
                              const struct nf_hook_state * state)
{
    unsigned int exit_code = NF_ACCEPT;
    struct mpls_shim_hdr *hdr;

    if (!eth_p_mpls(skb->protocol))
    {
        goto exit;
    }

    if (!pskb_may_pull(skb, sizeof(*hdr)))
    {
        goto exit;

    }

    hdr = mpls_hdr(skb);

    if (hdr == NULL)
    {
        goto exit;
    }

    switch(run_ti_mfa(state->net, skb))
    {
        case TI_MFA_SUCCESS:
            exit_code = NF_STOLEN;
            break;

        case TI_MFA_ERROR:
            pr_debug("ti-mfa failed on [%s]. Dropping...\n", skb->dev->name);
            exit_code = NF_DROP;
            break;

        /* Handling TI_MFA_PASS */
        default:
            break;
    }

    if (exit_code == NF_STOLEN)
        kfree_skb(skb);

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
            return return_code;
        }

        pr_debug("TI-MFA ingress hook successfully registered on device: %s!\n", dev->name);
        i++;
        // END Ingress

        // START Egress
        timfa_hooks[i].hook = timfa_egress_hook;
        timfa_hooks[i].hooknum = NF_NETDEV_EGRESS;
        timfa_hooks[i].pf = NFPROTO_NETDEV;
        timfa_hooks[i].priority = NF_IP_PRI_LAST;
        timfa_hooks[i].dev = dev;

        return_code = nf_register_net_hook(&init_net, &timfa_hooks[i]);

        if (return_code < 0)
        {
            pr_err("Registering egress hook failed for device %s, with %d\n", dev->name, return_code);
            return return_code;
        }

        pr_debug("TI-MFA egress hook successfully registered on device: %s!\n", dev->name);
        i++;
        // END Egress

        dev = next_net_device(dev);
    }

    read_unlock(&dev_base_lock);

    number_of_timfa_hooks = i;

    pr_debug("Registering %d hooks succeeded\n", number_of_timfa_hooks);

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

    err = register_netdevice_notifier(&ti_mfa_dev_notifier);
    if (err != 0)
        goto out_cleanup;

out:
    return err;

out_cleanup:
    cleanup_ti_mfa();
    goto out_unregister;

out_unregister:
    unregister_hooks();
    goto out_cleanup;
}

static void __exit timfa_exit(void)
{
    pr_debug("TI-MFA shutting down\n");

    unregister_netdevice_notifier(&ti_mfa_dev_notifier);
    cleanup_ti_mfa();
    unregister_hooks();
    kfree(timfa_hooks);

    pr_info("TI-MFA shut down\n");
}

module_init(timfa_init);
module_exit(timfa_exit);
