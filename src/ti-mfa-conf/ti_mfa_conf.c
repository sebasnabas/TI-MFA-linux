/* Modified from https://github.com/netgroup/SRv6-net-prog/blob/master/srext/tools/srconf.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <errno.h>
#include <net/if.h>

#include "../include/ti_mfa_conf.h"

int sd;
struct timeval tv = {5, 0};
int ti_mfa_fam_id;
struct genl_msg req, ans;
struct  nlattr *nl_attr[TI_MFA_A_MAX + 1];

struct ti_mfa_param params;

static void reset_parameters() {
    params.command            = NULL;
    free(params.link_source);
    params.link_source        = NULL;
    free(params.link_dest);
    params.link_dest          = NULL;
    free(params.dest);
    params.dest               = NULL;
    params.backup_dev_name    = NULL;
    free(params.net_ns);
    params.net_ns             = NULL;
}

static void print_nl_attrs()
{
    int i;
    void *data;

    for (i = 0; i <= TI_MFA_A_MAX; i++) {
        if (nl_attr[i] == NULL) continue;
        data = GENLMSG_NLA_DATA(nl_attr[i]);
        printf("%s\n", (char *) data);
    }
}

static void reset_nl_attrs(void)
{
    int i;
    for (i = 0; i <= TI_MFA_A_MAX; i++) {
        nl_attr[i] = NULL;
    }
}

static void parse_nl_attrs()
{
    unsigned int n_attrs = 0;
    struct nlattr *na;
    unsigned int data_len = GENLMSG_DATALEN(&ans.n);

    reset_nl_attrs();

    na = (struct nlattr *) GENLMSG_DATA(&ans);
    nl_attr[na->nla_type] = na;
    data_len -= NLA_ALIGN(na->nla_len);

    while (data_len > 0) {
        n_attrs++;
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        nl_attr[na->nla_type] = na;
        data_len -= NLA_ALIGN(na->nla_len);
    }
}

static int do_receive_response()
{
    int ret = 0;
    memset(ans.buf, 0, MAX_BUF_LEN);
    int rep_len = recv(sd, &ans, sizeof(ans), 0);

    if (ans.n.nlmsg_type == NLMSG_ERROR) {
        ret = -1;
    }
    if (rep_len < 0) {
        switch (errno) {
            case EAGAIN:
                fprintf(stderr, "Got socket receive timeout. Is the ti_mfa kernel module loaded?\n");
                break;
            default:
                fprintf(stderr, "do_receive_response - error %s receiving reply message.\n", strerror(errno));
        }
        exit(-1);
    }
    if (!NLMSG_OK((&ans.n), rep_len)) {
        fprintf(stderr, "do_receive_response - invalid reply message received.\n");
        exit(-1);
    }

    parse_nl_attrs();

    return ret;
}

static int receive_response()
{
    while (do_receive_response());
    print_nl_attrs();
    return 0;
}

static int sendto_fd(int s, const char *buf, int bufLen)
{
    int r;
    struct sockaddr_nl nladdr;

    memset(&nladdr, 0, sizeof(struct sockaddr_nl));
    nladdr.nl_family = AF_NETLINK;

    while ((r = sendto(s, buf, bufLen, 0, (struct sockaddr *) &nladdr,
                       sizeof(struct sockaddr_nl))) < bufLen) {
        if (r > 0) {
            buf += r;
            bufLen -= r;
        } else if (errno != EAGAIN) return -1;
    }
    return 0;
}

static void set_nl_attr(struct nlattr *na, const unsigned int type,
                        const void *data, const unsigned int len)
{
    int length;

    length = len + 1;
    na->nla_type = type;
    na->nla_len = length + NLA_HDRLEN;
    memcpy(GENLMSG_NLA_DATA(na), data, length);
}

static int create_nl_socket(void)
{
    int fd;


    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) {
        perror("create_nl_socket - unable to create netlink socket.");
        exit(0);
    }

    sd = fd;
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));

    return 0;
}

static void set_nl_header(int command)
{
    req.n.nlmsg_len     = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_type    = ti_mfa_fam_id;
    req.n.nlmsg_flags   = NLM_F_REQUEST;
    req.n.nlmsg_seq     = 60;
    req.n.nlmsg_pid     = getpid();
    req.g.cmd           = command;
}

int get_family_id()
{
    int id = 0;
    struct nlattr *na;

    if (strlen(TI_MFA_GNL_FAMILY_NAME) > 16) {
        printf("get_family_id - hostname too long.");
        exit(0);
    }

    set_nl_header(CTRL_CMD_GETFAMILY);

    req.n.nlmsg_type    = GENL_ID_CTRL;
    req.n.nlmsg_seq     = 0;
    req.g.version       = 0x1;

    na = (struct nlattr *) GENLMSG_DATA(&req);
    set_nl_attr(na, CTRL_ATTR_FAMILY_NAME, TI_MFA_GNL_FAMILY_NAME,
                strlen(TI_MFA_GNL_FAMILY_NAME));

    req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

    if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;

    while (do_receive_response());

    na = (struct nlattr *) GENLMSG_DATA(&ans);
    na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
    if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
        id = *(__u16 *) GENLMSG_NLA_DATA(na);
    }

    ti_mfa_fam_id = id;
    return 0;
}

static int genl_client_init()
{
    reset_nl_attrs();
    create_nl_socket();
    get_family_id();
    return 0;
}

static void set_attributes()
{
    struct nlattr *na = (struct nlattr *) GENLMSG_DATA(&req);

    if (params.link_source != NULL) {
        set_nl_attr(na,  TI_MFA_A_LINK_SOURCE, params.link_source, sizeof(struct mac));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.link_dest != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, TI_MFA_A_LINK_DEST, params.link_dest, sizeof(struct mac));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.dest != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, TI_MFA_A_BACKUP_LABEL, params.dest, sizeof(*params.dest));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.backup_dev_name != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, TI_MFA_A_BACKUP_DEV_NAME, params.backup_dev_name, strlen(params.backup_dev_name));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }

    if (params.net_ns != NULL) {
        na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
        set_nl_attr(na, TI_MFA_A_NET_NS_PID, params.net_ns, sizeof(*params.net_ns));
        req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);
    }
}

static int send_add_command()
{
    set_nl_header(TI_MFA_C_ADD);
    set_attributes();
    if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
    receive_response();
    return 0;
}

static int send_del_command()
{
    set_nl_header(TI_MFA_C_DEL);
    set_attributes();
    if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
    receive_response();
    return 0;
}

static int send_show_command()
{
    set_nl_header(TI_MFA_C_SHOW);
    set_attributes();
    if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
    receive_response();
    return 0;
}

static int send_flush_command()
{
    set_nl_header(TI_MFA_C_FLUSH);
    set_attributes();
    if (sendto_fd(sd, (char *) &req, req.n.nlmsg_len) < 0) return -1;
    receive_response();
    return 0;
}

static void print_mac(struct mac *mac, char *prefix)
{
    if (!mac) {
        printf("Ups\n");
        return;
    }
    printf("%s: \t\t%02x:%02x:%02x:%02x:%02x:%02x\n",
           prefix,
           mac->oct[0],
           mac->oct[1],
           mac->oct[2],
           mac->oct[3],
           mac->oct[4],
           mac->oct[5]);
}

static int is_esadecimal(char c)
{
    int i, ret = 0;
    char numbers[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    char lettersUp[] = {'a', 'b', 'c', 'd', 'e', 'f'};
    char lettersDw[] = {'A', 'B', 'C', 'D', 'E', 'F'};

    for (i = 0; i < strlen(numbers); i++)
        if (c == numbers[i])
            goto end;

    for (i = 0; i < strlen(lettersUp); i++)
        if (c == lettersUp[i])
            goto end;

    for (i = 0; i < strlen(lettersDw); i++)
        if (c == lettersDw[i])
            goto end;

    ret = -1;

end:
    return ret ;
}

static int validate_mac_token(char *token)
{
    int ret = -1;
    if (strlen(token) != 2)
        goto end;

    if (is_esadecimal(token[0]) < 0)
        goto end;

    if (is_esadecimal(token[1]) < 0)
        goto end;

    ret =  0;

end:
    return ret ;
}

static struct mac *parse_mac(char *string)
{
    int index;
    char *token = "";
    char string_copy[strlen(string)];
    unsigned long N;
    struct mac *addr;

    addr = malloc(sizeof(struct mac));

    strcpy(string_copy, string);

    index = 0;
    token = strtok(string_copy, ":");
    while ( token != NULL ) {
        if (validate_mac_token(token) < 0) {
            printf("MAC address is not valid.\n");
            goto err;
        }

        N = strtoul(token, NULL, 16);
        addr->oct[index] = N;

        token = strtok(NULL, ":");
        index++;
    }
    if (index != 6) {
        printf("MAC address is not valid.\n");
        goto err;
    }

    goto end;

err:
    free(addr);
    return NULL;
end:
    return addr;
}

static int parse_link(char *string)
{
    const char *delimiter = "-";
    int ret = -1;
    char *token = NULL;
    char string_copy[strlen(string)];
    char *src_mac = NULL;
    char *dst_mac = NULL;

    strcpy(string_copy, string);

    token = strtok(string_copy, delimiter);
    if (!token)
        goto end;

    src_mac = malloc(strlen(token));
    strcpy(src_mac, token);

    token = strtok(NULL, delimiter);
    if (!token)
        goto end;

    dst_mac = malloc(strlen(token));
    strcpy(dst_mac, token);

    params.link_source = parse_mac(src_mac);
    if (params.link_source == NULL)
        goto end;

    params.link_dest = parse_mac(dst_mac);
    if (params.link_dest == NULL)
        goto end;

    ret = 0;

end:
    if (src_mac) free(src_mac);
    if (dst_mac) free(dst_mac);
    return ret;
}

static void print_parameters()
{
    printf("--- Parsed parameters\n");
    if (params.command         != NULL)  printf("Command:           %s\n", params.command);
    if (params.link_source     != NULL)  print_mac(params.link_source, "link_source");
    if (params.link_dest       != NULL)  print_mac(params.link_dest, "link_dest");

    if (params.dest            != NULL)  printf("Backup Label:      %u\n", (unsigned int) params.dest->label);
    if (params.backup_dev_name != NULL)  printf("Backup net dev:    %s\n", params.backup_dev_name);
    if (params.net_ns          != NULL)  printf("NetNS PID:         %d\n", params.net_ns->pid);
    printf("---------------------\n");
}

static int usage(void)
{
    fprintf(stderr, "Usage: ti-mfa-conf { COMMAND | help}\n");
    fprintf(stderr, "       ti-mfa-conf show\n");
    fprintf(stderr, "       ti-mfa-conf flush\n");
    fprintf(stderr, "       ti-mfa-conf { add | del } ROUTE \n");
    fprintf(stderr, "ROUTE := MAC-MAC MPLSLABEL DEV [ NETNS_PID ]\n");

    return 0;
}

static int parse_add_del_args(int argc, char **argv)
{
    int ret = -1, if_len = 0;
    unsigned int mpls_label;
    int net_ns_pid = -1;

    if (argc < 5 ) {
        printf("Command line is not complete.\n");
        goto end;
    }

    if (parse_link(argv[2]) != 0) {
        printf("Error: a link in the format of {MAC}-{MAC} is expected rather than \"%s\".\n", argv[2]);
        goto end;
    }

    mpls_label = strtoul(argv[3], NULL, 10);
    if (mpls_label == EINVAL || mpls_label == ERANGE) {
        printf("Error: MPLS label is invalid: \"%s\"\n", argv[3]);
        goto end;
    }
    params.dest = malloc(sizeof(*params.dest));
    params.dest->label = mpls_label;

    if_len = strlen(argv[4]);
    params.backup_dev_name = calloc(sizeof(char), if_len);
    memmove(params.backup_dev_name, argv[4], if_len);

    if (argv[5] == 0)
    {
        params.net_ns = NULL;
    }
    else {
        net_ns_pid = strtoul(argv[5], NULL, 10);
        if (net_ns_pid == EINVAL || net_ns_pid == ERANGE) {
            printf("Error: PID is invalid: \"%s\"\n", argv[5]);
            goto end;
        }
        params.net_ns = malloc(sizeof(*params.net_ns));
        params.net_ns->pid = net_ns_pid;
    }

    print_parameters();

    ret = 0;
end:
    return ret;
}

/**
 * do_add(): handles "ti-mfa-conf add ..." command
*/

static int do_add(int argc, char **argv)
{
    int ret = -1;

    if (parse_add_del_args(argc, argv) != 0)
        goto end;

    ret = send_add_command();
end:
    return ret;
}

/**
 * do_del(): handles "ti-mfa-conf del ..." command
*/

static int do_del(int argc, char **argv)
{
    int ret = -1;

    if (parse_add_del_args(argc, argv) != 0)
        goto end;

    ret = send_del_command();
end:
    return ret;
}

static int do_show(int argc, char **argv)
{
    int ret = -1 ;

    if (argc > 2) {
        printf("Too many parameters. Please try \"ti-mfa-conf show help\" \n");
        goto end;
    }

    ret = send_show_command();

end:
    return ret;
}

static int do_flush(int argc, char **argv)
{
    int ret = -1;

    if (argc > 2) {
        printf("Too many parameters. Please try \"ti-mfa-conf help\" \n");
        goto end;
    }

    ret = send_flush_command();

end:
    return ret;
}

/**
 * main(): main method
 */

int main(int argc, char **argv)
{
    int ret = -1 ;

    reset_parameters();

    if (argc < 2 ) {
        ret = usage();
        goto end;
    }

    params.command = argv[1];

    if (strcmp(params.command, HELP) == 0)
        return usage();

    genl_client_init();

    if (strcmp(params.command, FLUSH) == 0)
        ret = do_flush(argc, argv);

    else if (strcmp(params.command, SHOW) == 0)
        ret = do_show(argc, argv);

    else if (strcmp(params.command, DEL) == 0)
        ret = do_del(argc, argv);

    else if (strcmp(params.command, ADD) == 0)
        ret = do_add(argc, argv);

    else
        printf("Unrecognized command. Please try \"ti-mfa-conf help\".\n");

    print_parameters();

end:
    return ret;
}
