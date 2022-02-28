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

static const struct nla_policy rtm_mpls_policy[RTA_MAX+1] = {
	[RTA_DST]		= { .type = NLA_U32 },
};

// #define BUFFER_SIZE 4095

/* From iproute2 include/netlink.h */
static inline __u32 rta_getattr_u32(const struct rtattr *rta)
{
	return *(__u32 *)RTA_DATA(rta);
}

/* From iproute2 ip/ip_common.h */
static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
	__u32 table = r->rtm_table;

	if (tb[RTA_TABLE])
		table = rta_getattr_u32(tb[RTA_TABLE]);
	return table;
}

/* From iproute2 lib/libnetlink.c */
static int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		       int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		pr_err("!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}
static int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	return parse_rtattr_flags(tb, max, rta, len, 0);
}

/* From iproute2 lib/utils.c */
static int af_bit_len(int af)
{
	switch (af) {
	case AF_INET6:
		return 128;
	case AF_INET:
		return 32;
	case AF_MPLS:
		return 20;
	}

	return 0;
}

static void parse_nl_msg(struct nlmsghdr *nlh, int received_bytes)
{
    /* ------ iproute2 iproute.c:print_route ------ */
    // struct rtmsg *route_entry = NLMSG_DATA(nlh);
    // int len = nlh->nlmsg_len;
    // struct rtattr *route_attribute[RTA_MAX+1];
    // int family, host_len;
    // __u32 table;

    // if (nlh->nlmsg_type != RTM_NEWROUTE && nlh->nlmsg_type != RTM_DELROUTE) {
    //     pr_err("Not a route: %08x %08x %08x\n",
    //         nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_flags);
    // }

    // len -= NLMSG_LENGTH(sizeof(*route_entry));
    // if (len < 0)
    // {
    //     pr_err("BUG: wrong nlmsg len %d\n", len);
    // }

    // host_len = af_bit_len(route_entry->rtm_family);

    // parse_rtattr(route_attribute, RTA_MAX, RTM_RTA(route_entry), len);
    // table = rtm_get_table(route_entry, route_attribute);

    // // if (table != RT_TABLE_MAIN)
    // // {
    // //     pr_debug("Different routing table %u", table);
    // //     return;
    // // }

    // if (nlh->nlmsg_type == RTM_DELROUTE)
    // {
    //     pr_debug("Got DELROUTE");
    // }
    /* -------------------------------------------- */

    /* ------ Stackoverflow ------ */
    struct rtmsg *route_entry;
    struct rtattr *route_attribute;
    u8 label_count;
    int max_labels = 3;
    u32 label[max_labels];
    // int index;
    // int err;
    int route_attribute_len = 0;
    char *destination_address = kmalloc(32, GFP_KERNEL);
    char *gateway_address = kmalloc(32, GFP_KERNEL);

    route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

    if (route_entry->rtm_table != RT_TABLE_MAIN)
    {
        // pr_debug("Different routing table %u", route_entry->rtm_table);
        return;
    }

    route_attribute = (struct rtattr *) RTM_RTA(route_entry);

    route_attribute_len = RTM_PAYLOAD(nlh);

    for (; RTA_OK(route_attribute, route_attribute_len);
            route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
    {
        // pr_debug("Route attribute: %d", route_attribute->rta_type);
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

            // if (nla_get_labels(route_attribute, max_labels, &label_count, label, NULL))
            // {
            //     pr_debug("Got route deletion update with label %u", label[0]);
            //     break;
            // }
        }
        if (nlh->nlmsg_type == RTM_NEWROUTE)
            pr_debug("Adding route to destination --> %pI4 and gateway %pI4\n",
                    destination_address, gateway_address);
    }
    /* -------------------------------- */

    // if (nlmsg_parse(nlh, sizeof(*rtm), tb, RTA_MAX, rtm_mpls_policy, NULL))
    // {
    //     pr_err("Could not parse nlmsg");
    //     goto out;
    // }

    // rtm = nlmsg_data(nlh);

    // pr_debug("Parsing attributes now");
    // for (index = 0; index <= RTA_MAX; index++) {
    //     struct nlattr *nla = tb[index];
    //     if (!nla)
    //         continue;

    //     pr_debug("Got index %d", index);
    //     switch (index)
    //     {
    //         case RTM_DELROUTE:
    //             if (nla_get_labels(nla, max_labels, &label_count, label, NULL))
    //             {
    //                 pr_debug("Got route deletion update with label %u", label[0]);
    //                 break;
    //             }
    //             break;

    //         case RTM_NEWROUTE:
    //             break;

    //         default:
    //             continue;
    //     }
    // }

    goto out;

    // struct mpls_route_config *cfg;
    // unsigned index;
    // struct net *net;
    // struct mpls_route __rcu **platform_label;
	// struct mpls_route *rt;

    // cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
    // if (!cfg)
    //     return -ENOMEM;

    // err = rtm_to_route_config(skb, nlh, cfg, extack);
    // if (err < 0)
    //     goto out;

    // index = cfg->rc_label;
    // net = cfg->rc_nlinfo.nl_net;

    // ASSERT_RTNL();

    // platform_label = rtnl_dereference(net->mpls.platform_label);
    // rt = rtnl_dereference(platform_label[index]);

    // if ((deleted_nh = krealloc_array(deleted_nh, ++number_deleted_routes,
    //                                      sizeof(struct mpls_direct_nh), GFP_KERNEL)
    //     ) == NULL)
    // {
    //     pr_crit("Realloc for deleted_routes failed");
    //     err = -ENOMEM;
    //     goto out;
    // }

    // deleted_nh[number_deleted_routes - 1] = rt->rt_nh[0];

    // pr_debug("New deleted direct next hop with label %u added",
    //          deleted_nh[number_deleted_routes - 1].nh_label[0]
    // );

    // return mpls_rtm_delroute(skb, nlh, extack);

out:
    return;
}

// static void rcv_netlink_msg(struct sk_buff *skb)
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
        // kernel_sock_shutdown(nl_sk, SHUT_RDWR);
        sock_release(nl_sk);
    }
}

static int __init timfa_init(void)
{
    int err;
    // struct netlink_kernel_cfg cfg = {
    //     .groups = RTNLGRP_MPLS_ROUTE,
    //     .input = rcv_netlink_msg,
    // };
    struct sockaddr_nl addr;

    pr_info("TI-MFA started\n");
    /* create socket to monitor routing table changes
    * SOCK_RAW means we don't need to call kernel_connect() (?)
    */
    err = sock_create_kern(&init_net, AF_NETLINK, SOCK_RAW, NETLINK_ROUTE, &nl_sk);
    if (err)
    {
        pr_crit("Error creating netlink socket");
        goto out;
    }

    addr.nl_family = AF_NETLINK;
    addr.nl_pid    = 0;
    // addr.nl_groups = RTNLGRP_MPLS_NETCONF;

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

    // netlink_kernel_release(nl_sk);
    release_socket();
    pr_debug("Released netlink socket");

    pr_info("TI-MFA shut down\n");
}

module_init(timfa_init);
module_exit(timfa_exit);