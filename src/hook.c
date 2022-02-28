#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
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

extern bool mpls_output_possible(struct net_device *dev);

struct socket *nl_sk = NULL;

static struct nf_hook_ops *timfa_hooks;
static u32 number_of_timfa_hooks;

// save deleted next_hops
// static struct mpls_nh *deleted_nh;
// static u32 number_deleted_routes;

/*
* @TODO:
* Either:
// *   - pre-routing hook (INGRESS) -> lookup routing decision beforehand
// *       & set link-failure header
// * or
* @TODO:
*   - post-routing hook (EGRESS) -> get past routing decision
*       & set link-failure header
*/

static void parse_nl_msg(struct nlmsghdr *nlh, int received_bytes)
{
    struct rtmsg *route_entry;
    struct rtattr *route_attribute;
    int route_attribute_len = 0;
    char *destination_address = kmalloc(32, GFP_KERNEL);
    char *gateway_address = kmalloc(32, GFP_KERNEL);

    route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

    if (route_entry->rtm_table != RT_TABLE_MAIN)
    {
        return;
    }

    route_attribute = (struct rtattr *) RTM_RTA(route_entry);

    route_attribute_len = RTM_PAYLOAD(nlh);

    for (; RTA_OK(route_attribute, route_attribute_len);
            route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
    {
        if (route_attribute->rta_type == RTA_DST)
        {
            destination_address = RTA_DATA(route_attribute);
            pr_debug("Destination address: %pI4\n",
                destination_address);
        }
        if (route_attribute->rta_type == RTA_GATEWAY)
        {
            gateway_address = RTA_DATA(route_attribute);
            pr_debug("Gateway address: %pI4\n",
                gateway_address);
        }

        if (nlh->nlmsg_type == RTM_DELROUTE)
        {
            pr_debug("Deleting route to destination --> %pI4 and gateway %pI4\n",
                destination_address, gateway_address);
        }
        if (nlh->nlmsg_type == RTM_NEWROUTE)
            pr_debug("Adding route to destination --> %pI4 and gateway %pI4\n",
                    destination_address, gateway_address);
    }

    return;
}

static void rcv_netlink_msg(struct sock *sk)
{
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlh = NULL;
    int received_bytes = 0;
    int err = 0;

    skb = skb_recv_datagram(sk, 0, 0, &err);
    if (err)
    {
        pr_err("Failed on skb_rev_datagram(), err=%d", -err);
        skb_free_datagram(sk, skb);
        return;
    }

    received_bytes = skb->len;

    if (received_bytes < 0)
    {
        pr_err("Got error on recv");
    }

    // From https://stackoverflow.com/questions/27322786/listening-for-netlink-broadcasts-in-a-kernel-module
    nlh = (struct nlmsghdr *) skb->data;
    if (!nlh || !NLMSG_OK(nlh, received_bytes))
    {
        pr_err("Invalid netlink header data.");
        return;
    }

    if (nlh->nlmsg_type == NLMSG_DONE)
    {
        return;
    }

    for (; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes))
    {
        parse_nl_msg(nlh, received_bytes);
    }


    skb_free_datagram(sk, skb);
}


static unsigned int timfa_ingress_hook(void *priv, struct sk_buff * skb,
                              const struct nf_hook_state * state)
{
    struct mpls_shim_hdr *hdr;
    unsigned entry;
    u32 label;

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

    entry = be32_to_cpu(hdr->label_stack_entry);
    label = MPLS_LABEL(entry);

    pr_debug("[%s]:[%s] INGRESS Got mpls packet with label %u", HOST_NAME, state->in->name, label);

accept:
    return NF_ACCEPT;
}

static unsigned int timfa_egress_hook(void *priv, struct sk_buff * skb,
                              const struct nf_hook_state * state)
{
    struct mpls_shim_hdr *hdr;

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

    if (run_timfa(skb) != 0)
    {
        pr_debug("ti-mfa failed on [%s]. Dropping...", skb->dev->name);
        return NF_DROP;
    }

    // kfree(skb);
    // return NF_STOLEN;

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

    timfa_hooks = kmalloc_array(number_of_mpls_devices * 2, sizeof(struct nf_hook_ops), GFP_KERNEL);

    read_lock(&dev_base_lock);
    dev = first_net_device(&init_net);

    while (dev)
    {
        if (!mpls_output_possible(dev))
        {
            goto next_device;
        }

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
        #ifdef CONFIG_NETFILTER_EGRESS
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
        #endif
        // END Egress

next_device:
        dev = next_net_device(dev);
    }

    read_unlock(&dev_base_lock);

    number_of_timfa_hooks = i;

    pr_debug("Registering %d hooks succeeded", number_of_timfa_hooks);

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

static void release_socket(void)
{
    if (nl_sk)
    {
        sock_release(nl_sk);
    }
}

static int __init timfa_init(void)
{
    int err;
    struct sockaddr_nl addr;

    pr_info("TI-MFA started\n");

    err = sock_create_kern(&init_net, AF_NETLINK, SOCK_RAW, NETLINK_ROUTE, &nl_sk);
    if (err)
    {
        pr_crit("Error creating netlink socket");
        goto out;
    }

    addr.nl_family = AF_NETLINK;
    addr.nl_pid    = 0;

    err = kernel_bind(nl_sk, (struct sockaddr *) &addr, sizeof(addr));
    if (err)
    {
        pr_crit("Error binding netlink socket");
        goto out_release;
    }

    nl_sk->sk->sk_data_ready = rcv_netlink_msg;
    nl_sk->sk->sk_allocation = GFP_KERNEL;

    pr_debug("Created netlink socket");

    err = initialize_hooks();
    if (err)
        goto out_unregister;

out:
    return err;

out_release:
    release_socket();
    goto out;

out_unregister:
    unregister_hooks();
    goto out_release;
}

static void __exit timfa_exit(void)
{
    pr_debug("TI-MFA shutting down\n");

    unregister_hooks();

    kfree(timfa_hooks);

    release_socket();
    pr_debug("Released netlink socket");

    pr_info("TI-MFA shut down\n");
}

module_init(timfa_init);
module_exit(timfa_exit);