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
