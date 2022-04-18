#include <linux/if.h>
#include <linux/kernel.h>
#include <linux/if_ether.h>

struct ti_mfa_route {
    unsigned char       link_source[ETH_ALEN];
    unsigned char       link_dest[ETH_ALEN];
    unsigned int        destination_label;
    char                out_dev_name[IFNAMSIZ];
    struct hlist_node   hnode;
};

int rt_add(struct ti_mfa_route rt);
int rt_del(struct ti_mfa_route rt);
int rt_show(char *dst, size_t size);
int rt_flush(void);
