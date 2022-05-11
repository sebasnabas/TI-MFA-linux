#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/skbuff.h>
#include <net/arp.h>
#include <net/neighbour.h>

#include "mpls.h"
#include "ti_mfa.h"
#include "utils.h"

static void add_mpls_labels(char *msg, uint label_count, const struct mpls_entry_decoded entries[])
{
    uint i = 0;
    for (i = 0; i < label_count; ++i) {
        sprintf(msg+ strlen(msg), "\t\t %u: %u\n", i, entries[i].label);
    }
}

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

void debug_print_mpls_entries(uint label_count, const struct mpls_entry_decoded labels[])
{
    char msg[1024];
    memset(msg, 0, sizeof(msg));

    sprintf(msg, "\nLabels:\n");

    add_mpls_labels(msg, label_count, labels);

    pr_debug("%s", msg);
}

/* Step 1): Decode mpls labels, remove them from header and save them
*/
uint flush_mpls_label_stack(struct sk_buff *skb, struct mpls_entry_decoded mpls_entries[], int max_labels)
{
    uint label_count = 0, mpls_hdr_len = 0;
    struct mpls_shim_hdr *mpls_hdr_entry;
    for (label_count = 0; label_count < max_labels; label_count++) {
        mpls_hdr_len += sizeof(*mpls_hdr_entry);
        if (!pskb_may_pull(skb, mpls_hdr_len)) {
            break;
        }

        mpls_hdr_entry = mpls_hdr(skb) + label_count;
        mpls_entries[label_count] = mpls_entry_decode(mpls_hdr_entry);

        pr_debug("Label: %u %s\n", mpls_entries[label_count].label, mpls_entries[label_count].bos ? "[S]" : "");

        if (!mpls_entries[label_count].bos)
        {
            continue;
        }

        label_count++;
        break;
    }

    /* skb_pull(skb, sizeof(*mpls_hdr_entry) * label_count); is not necessary, since we do a pskb_may_pull before: */
    skb_set_network_header(skb, -2); /* We have correct an offset somehow */

    return label_count;
}

void set_mpls_header(struct sk_buff *skb, uint label_count, const struct mpls_entry_decoded new_label_stack[], bool add_extension_hdr)
{
    int i = 0;
    bool bos = true;
    struct mpls_shim_hdr *mpls_h;

    /* Set new mpls header */
    skb_push(skb, sizeof(*mpls_h) * label_count);
    skb_reset_network_header(skb);
    mpls_h = mpls_hdr(skb);

    if (add_extension_hdr)
    {
        label_count--;
        pr_debug("Setting ti-mfa mpls extension shim hdr. Remaining label count = %u\n", label_count);
        mpls_h[label_count] = TI_MFA_MPLS_EXTENSION_HDR;
        bos = false;
    }

    for (i = label_count - 1; i >= 0; i--) {
        struct mpls_entry_decoded mpls_entry = new_label_stack[i];
        mpls_h[i] = mpls_entry_encode(mpls_entry.label, mpls_entry.ttl, mpls_entry.tc, bos);
        pr_debug("%u: pushing label: %u%s\n", i, mpls_entry.label, bos ? "[S]" : "");

        bos = false;
    }
}
