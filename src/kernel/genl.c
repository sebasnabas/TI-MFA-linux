#include "debug.h"

/* Modified from https://github.com/netgroup/srv6-net-prog/blob/master/srext/kernel/sr_genl.c
 */
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/rwlock.h>

#include "routes.h"
#include "ti_mfa_genl.h"


#define RESPONSE_ER "Error from kernel space."

rwlock_t ti_mfagenl_rwlock;

char *err_str[] = {
    "TI-MFA answers: OK.",
    "TI-MFA answers: [ERROR]: TI-MFA could not allocate memory.",
    "TI-MFA answers: [ERROR]: Backup route table has no entries.",
    "TI-MFA answers: [ERROR]: Missing arguments.",
    "TI-MFA answers: [ERROR]: Route already exists.",
    "TI-MFA answers: [ERROR]: Route does not exist."
};

static struct genl_family ti_mfa_genl_family = {
    /* .id = 1, */
    .hdrsize = 0,
    .name = TI_MFA_GNL_FAMILY_NAME,
    .version = TI_MFA_GNL_FAMILY_VERSION,
    .maxattr = TI_MFA_A_MAX,
};

static struct nla_policy ti_mfa_genl_policy[_TI_MFA_A_MAX + 1] = {
    [TI_MFA_A_UNSPEC]          = { .type = NLA_STRING },
    [TI_MFA_A_COMMAND]         = { .type = NLA_STRING },
    [TI_MFA_A_LINK_SOURCE]     = { .type = NLA_BINARY },
    [TI_MFA_A_LINK_DEST]       = { .type = NLA_BINARY },
    [TI_MFA_A_BACKUP_DEV_NAME] = { .type = NLA_STRING },
    [TI_MFA_A_BACKUP_LABEL]    = { .type = NLA_BINARY },
    [TI_MFA_A_RESPONSE]        = { .type = NLA_STRING },
    [TI_MFA_A_RESPONSE_LST]    = { .type = NLA_STRING }
};

static void set_msg_data(struct genl_msg_data *msg_data, int type,
                         void *data, int len)
{
    msg_data->atype = type;
    msg_data->data  = data;
    msg_data->len   = len + 1;
}

static void *extract_nl_attr(const struct genl_info *info, const int atype)
{
    struct nlattr *na;
    void *data = NULL;
    na = info->attrs[atype];
    if (na) data = nla_data(na);
    return data;
}

static void extract_ti_mfa_attrs(const struct genl_info *info, struct ti_mfa_param *a)
{
    a->command         = (char *) extract_nl_attr(info, TI_MFA_A_COMMAND);
    a->link_source     = (struct mac *) extract_nl_attr(info, TI_MFA_A_LINK_SOURCE);
    a->link_dest       = (struct mac *) extract_nl_attr(info, TI_MFA_A_LINK_DEST);

    a->dest            = (struct mpls_dest *) extract_nl_attr(info, TI_MFA_A_BACKUP_LABEL);
    a->backup_dev_name = (char *) extract_nl_attr(info, TI_MFA_A_BACKUP_DEV_NAME);
}

static void print_attributes(struct ti_mfa_param *ti_mfa_attr)
{
    if (ti_mfa_attr->link_source     != NULL) pr_info("Source: %pM\n", ti_mfa_attr->link_source->oct);
    if (ti_mfa_attr->link_dest       != NULL) pr_info("Dest: %pM\n", ti_mfa_attr->link_dest->oct);

    if (ti_mfa_attr->dest            != NULL) pr_info("Label: %u\n", ti_mfa_attr->dest->label);
    if (ti_mfa_attr->backup_dev_name != NULL) pr_info("NetDev: %s\n", ti_mfa_attr->backup_dev_name);
}

static int send_response(struct genl_info *info, unsigned int n_data,
                         struct genl_msg_data *msg_data)
{
    struct sk_buff *skb;
    void *skb_head;
    int i;

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
    if (skb == NULL) {
        pr_err("send_response - unable to allocate skb");
        return -1;
    }

    skb_head = genlmsg_put(skb, 0, info->snd_seq + 1, &ti_mfa_genl_family, 0, info->genlhdr->cmd);
    if (skb_head == NULL) {
        pr_err("send_response - unable to allocate skb_head");
        return -ENOMEM;
    }

    for (i = 0; i < n_data; i++) {
        int ret;
        if ((ret = nla_put(skb, msg_data[i].atype, msg_data[i].len, msg_data[i].data)) < 0) {
            pr_err("send_response - unable to put attribute %d for elem %d/%d: %d", msg_data[i].atype, i, n_data, ret);
            return -1;
        }
    }

    genlmsg_end(skb, skb_head);

    if (genlmsg_unicast(genl_info_net(info), skb, info->snd_portid ) != 0) {
        pr_err("send_response - unable to send response - info->snd_portid = %u", info->snd_portid);
        return -1;
    }

    return 0;
}

static int add_backup_route(struct ti_mfa_param attr, struct genl_info *info)
{
    int ret = 3;
    struct genl_msg_data data[1];

    if (attr.link_dest != NULL && attr.link_source != NULL
            && attr.dest != NULL && attr.backup_dev_name != NULL) {
        struct ti_mfa_route rt = {
            .destination_label = attr.dest->label,
        };

        ether_addr_copy(rt.link.source, attr.link_source->oct);
        ether_addr_copy(rt.link.dest, attr.link_dest->oct);
        strcpy(rt.out_dev_name, attr.backup_dev_name);

        switch (rt_add(rt)) {
            case TI_MFA_RT_OK:
                ret = 0;
                break;
            case TI_MFA_RT_NO_MEMORY:
                ret = 1;
                break;
            case TI_MFA_RT_ROUTE_ALREADY_EXISTS:
                ret = 4;
                break;
            default:
                break;
        }
    }

    set_msg_data(data, TI_MFA_A_RESPONSE, err_str[ret], strlen(err_str[ret]));
    ret =  send_response(info, 1, data);
    return ret;
}

/* ti_mfa_genl_add() - handles ti_mfaconf add commands
 */
static int ti_mfa_genl_add(struct sk_buff *skb, struct genl_info *info)
{
    struct ti_mfa_param attr;
    extract_ti_mfa_attrs(info, &attr);
    print_attributes(&attr);

    return add_backup_route(attr, info);
}

static int del_backup_route(struct ti_mfa_param attr, struct genl_info *info)
{
    int ret = 3;
    struct genl_msg_data data[1];
    if (attr.link_dest != NULL && attr.link_source != NULL
            && attr.dest != NULL && attr.backup_dev_name != NULL) {
        struct ti_mfa_route rt = {
            .destination_label = attr.dest->label,
        };

        ether_addr_copy(rt.link.source, attr.link_source->oct);
        ether_addr_copy(rt.link.dest, attr.link_dest->oct);
        strcpy(rt.out_dev_name, attr.backup_dev_name);

        ret = rt_del(rt);

        switch (ret) {
            case TI_MFA_RT_OK:
                ret = 0;
                break;
            case TI_MFA_RT_NO_MEMORY:
                ret = 1;
                break;
            case TI_MFA_RT_ROUTING_TABLE_EMPTY:
                ret = 2;
                break;
            case TI_MFA_RT_ROUTE_DOES_NOT_EXIST:
                ret = 5;
                break;
            default:
                break;
        }
    }

    set_msg_data(data, TI_MFA_A_RESPONSE, err_str[ret], strlen(err_str[ret]));
    ret =  send_response(info, 1, data);
    return ret;
}

static int show_all_routes(struct genl_info *info)
{
    int ret = 0 ;
    int len;
    char *message;
    struct genl_msg_data data[1];

    len = 4096;
    message = (char *) kzalloc(len, GFP_ATOMIC);

    ret = rt_show(message + strlen(message), 40);

    switch (ret) {
        case TI_MFA_RT_OK:
            if (strlen(message) > len)
                set_msg_data(data, TI_MFA_A_RESPONSE, RESPONSE_ER, strlen(RESPONSE_ER));
            else
                set_msg_data(data, TI_MFA_A_RESPONSE_LST, message, strlen(message));
            break;
        case TI_MFA_RT_ROUTING_TABLE_EMPTY: ;
            ret = 2;
            fallthrough;
        default:
            set_msg_data(data, TI_MFA_A_RESPONSE_LST, err_str[ret], strlen(err_str[ret]));
    }

    ret = send_response(info, 1, data);

    kfree(message);
    return ret;
}

static int flush_routes(struct ti_mfa_param attr, struct genl_info *info)
{
    int ret = 0;
    struct genl_msg_data data[1];
    ret = rt_flush();

    set_msg_data(data, TI_MFA_A_RESPONSE_LST, err_str[ret], strlen(err_str[ret]));

    ret = send_response(info, 1, data);
    return ret;
}

/* ti_mfa_genl_del() - handles ti_mfaconf del commands
 */
static int ti_mfa_genl_del(struct sk_buff *skb, struct genl_info *info)
{
    struct ti_mfa_param attr;
    extract_ti_mfa_attrs(info, &attr);
    print_attributes(&attr);

    return del_backup_route(attr, info);
}

/**
 * ti_mfa_genl_show - handle ti_mfaconf show commands
 */
static int ti_mfa_genl_show(struct sk_buff *skb, struct genl_info *info)
{
    int ret = 0;
    struct ti_mfa_param attr;
    struct genl_msg_data data[1];
    extract_ti_mfa_attrs(info, &attr);
    print_attributes(&attr);

    ret = show_all_routes(info);

    set_msg_data(data, TI_MFA_A_RESPONSE_LST, err_str[ret], strlen(err_str[ret]));

    ret = send_response(info, 1, data);
    return ret;
}

/**
 * ti_mfa_genl_flush - handle ti_mfaconf flush commands
 */
static int ti_mfa_genl_flush(struct sk_buff * skb, struct genl_info * info)
{
    struct ti_mfa_param attr;
    extract_ti_mfa_attrs(info, &attr);
    print_attributes(&attr);

    return flush_routes(attr, info);
}

static int ti_mfa_genl_dispatcher(struct sk_buff * skb, struct genl_info * info)
{
    int command;

    command = info->genlhdr->cmd;

    write_lock_bh(&ti_mfagenl_rwlock);

    switch (command) {
    case TI_MFA_C_ADD:
        pr_debug("TI_MFA_C_ADD genl command received\n");
        ti_mfa_genl_add(skb, info);
        break;
    case TI_MFA_C_DEL:
        pr_debug("TI_MFA_C_DEL genl command received\n");
        ti_mfa_genl_del(skb, info);
        break;
    case TI_MFA_C_SHOW:
        pr_debug("TI_MFA_C_SHOW genl command received\n");
        ti_mfa_genl_show(skb, info);
        break;
    case TI_MFA_C_FLUSH:
        pr_debug("TI_MFA_C_FLUSH genl command received\n");
        ti_mfa_genl_flush(skb, info);
        break;
    default:
        break;
    }

    write_unlock_bh(&ti_mfagenl_rwlock);

    return 0;
}
/***********************/
static struct genl_ops nvf_genl_ops[] = {
    {
        .cmd = TI_MFA_C_ADD,
        .flags = 0,
        .policy = ti_mfa_genl_policy,
        .doit = ti_mfa_genl_dispatcher,
        .dumpit = NULL,
    },
    {
        .cmd = TI_MFA_C_DEL,
        .flags = 0,
        .policy = ti_mfa_genl_policy,
        .doit = ti_mfa_genl_dispatcher,
        .dumpit = NULL,
    },
    {
        .cmd = TI_MFA_C_SHOW,
        .flags = 0,
        .policy = ti_mfa_genl_policy,
        .doit = ti_mfa_genl_dispatcher,
        .dumpit = NULL,
    },
    {
        .cmd = TI_MFA_C_FLUSH,
        .flags = 0,
        .policy = ti_mfa_genl_policy,
        .doit = ti_mfa_genl_dispatcher,
        .dumpit = NULL,
    },
};

int ti_mfa_genl_register()
{
    int rc;

    ti_mfa_genl_family.module    = THIS_MODULE;
    ti_mfa_genl_family.ops       = nvf_genl_ops;
    ti_mfa_genl_family.n_ops     = ARRAY_SIZE(nvf_genl_ops);
    ti_mfa_genl_family.mcgrps    = NULL;
    ti_mfa_genl_family.n_mcgrps  = 0;

    rc = genl_register_family(&ti_mfa_genl_family);

    if (rc != 0) {
        pr_err("Unable to register %s genetlink family\n", ti_mfa_genl_family.name);
        return -1;
    }
    pr_info("%s genetlink family successfully registered\n", ti_mfa_genl_family.name);

    return 0;
}

int ti_mfa_genl_unregister()
{
    int rc;
    rc = genl_unregister_family(&ti_mfa_genl_family);
    if (rc != 0) {
        pr_err("Unable to unregister %s genetlink family\n", ti_mfa_genl_family.name);
        return -1;
    }
    pr_info("%s genetlink family successfully unregistered\n", ti_mfa_genl_family.name);
    return 0;
}
