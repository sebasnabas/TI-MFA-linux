#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "utils.h"

#define AUTHOR "TI-MFA"
#define DESC   "TI-MFA"

MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);
MODULE_LICENSE("GPL");

static struct nf_hook_ops timfa_hook;

static unsigned int run_timfa(void *priv, struct sk_buff * skb,
                              const struct nf_hook_state * state)
{
    dmesg("Accepting packet");
    return NF_ACCEPT;
}

int hook_v4_register(void)
{
    int return_code = 0;
    timfa_hook.hook = run_timfa;
    timfa_hook.hooknum = NF_INET_PRE_ROUTING;
    timfa_hook.pf = PF_INET;
    timfa_hook.priority = NF_IP_PRI_LAST;

    return_code = nf_register_net_hook(&init_net, &timfa_hook);

    if (return_code < 0)
    {
        printk(KERN_INFO "Registering failed %s, with %d\n", DESC, return_code);
        return return_code;
    }

    printk(KERN_INFO "TI-MFA hook successfully registered (%d)!\n", return_code);
    return return_code;
}

int timfa_init(void)
{
    printk(KERN_INFO "TI-MFA started\n");
    hook_v4_register();
    return 0;
}

void timfa_exit(void)
{
    printk(KERN_INFO "TI-MFA shutting down\n");
    nf_unregister_net_hook(&init_net, &timfa_hook);
}

module_init(timfa_init);
module_exit(timfa_exit);
