#include "debug.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mpls.h>
#include <net/mpls.h>

#include "ti_mfa.h"
#include "utils.h"

static void add_labels(char *msg, uint label_count, const u32 labels[])
{
    uint i = 0;
    for (i = 0; i < label_count; ++i) {
        sprintf(msg+ strlen(msg), "\t\t %u: %u\n", i, labels[i]);
    }
}

void debug_print_labels(uint label_count, const u32 labels[])
{
    char msg[1024];
    memset(msg, 0, sizeof(msg));

    sprintf(msg, "\nLabels:\n");

    add_labels(msg, label_count, labels);

    pr_debug("%s", msg);
}

static void add_link_failures(char *msg, uint link_failure_count,
                              const struct ti_mfa_shim_hdr link_failures[])
{
    uint i = 0;
    for (i = 0; i < link_failure_count; ++i) {
        struct ti_mfa_shim_hdr link_failure = link_failures[i];
        sprintf(msg+ strlen(msg), "\t\t %u: %pM <-> %pM \n\t\t\t from %pM %s\n",
                i, link_failure.link.source,
                link_failure.link.dest,
                link_failure.node_source, link_failure.bos ? "[S]" : "");
    }
}

void debug_print_link_failures(uint link_failure_count,
                               const struct ti_mfa_shim_hdr link_failures[])
{
    char msg[1024];
    memset(msg, 0, sizeof(msg));

    sprintf(msg, "\nLink failures:\n");

    add_link_failures(msg, link_failure_count, link_failures);

    pr_debug("%s", msg);
}

void debug_print_next_hop(struct ti_mfa_nh nh) {
    char msg[1024];
    memset(msg, 0, sizeof(msg));

    strcat(msg, "\nNext hop:\n");
    sprintf(msg + strlen(msg), "  Out dev: %s\n", nh.dev->name);
    sprintf(msg + strlen(msg), "  HA: %pM\n", nh.ha);
    sprintf(msg + strlen(msg), "  Labels:\n");

    add_labels(msg, nh.labels, nh.label);

    sprintf(msg + strlen(msg), "  Link failures:\n");

    add_link_failures(msg, nh.link_failure_count, nh.link_failures);

    pr_debug("%s", msg);
}
