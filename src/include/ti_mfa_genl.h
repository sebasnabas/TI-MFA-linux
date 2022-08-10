#ifndef GENETLINK_H_
#define GENETLINK_H_

/**
 * COMMANDS
 */

#define ADD "add"
#define DEL "del"
#define SHOW "show"
#define HELP "help"
#define FLUSH "flush"

/**
 * BEHAVIORS CODE
 */

enum TI_MFA_GNL_COMMANDS {
	TI_MFA_C_ECHO,
	TI_MFA_C_ADD,
	TI_MFA_C_DEL,
	TI_MFA_C_SHOW,
	TI_MFA_C_FLUSH,
	TI_MFA_C_CLEAR,
	_TI_MFA_C_MAX,
};

enum TI_MFA_GNL_ATTRIBUTES {
	TI_MFA_A_ZERO, //do not touch, this is for the attributes order
	TI_MFA_A_UNSPEC,

	TI_MFA_A_COMMAND,
	TI_MFA_A_LINK_SOURCE,
	TI_MFA_A_LINK_DEST,
	TI_MFA_A_BACKUP_LABEL,
	TI_MFA_A_BACKUP_DEV_NAME,
	TI_MFA_A_NET_NS_PID,

	TI_MFA_A_RESPONSE,
	TI_MFA_A_RESPONSE_LST,

	_TI_MFA_A_MAX,
};

#define TI_MFA_GNL_FAMILY_NAME "ti_GENL_FAMILY"
#define TI_MFA_GNL_FAMILY_VERSION 1
#define TI_MFA_A_MAX (_TI_MFA_A_MAX - 1)
#define TI_MFA_C_MAX (_TI_MFA_C_MAX - 1)
#define MAX_BUF_LEN 1024 * 5

struct genl_msg_data {
	int atype;
	void *data;
	int len;
};

struct mac {
	unsigned char oct[6];
};

struct mpls_dest {
	unsigned int label;
};

struct net_ns {
	unsigned int pid;
};

struct ti_mfa_param {
	char *command;
	struct mac *link_source;
	struct mac *link_dest;
	struct mpls_dest *dest;
	char *backup_dev_name;
	struct net_ns *net_ns;
};

int ti_mfa_genl_register(void);
int ti_mfa_genl_unregister(void);

#endif /* GENETLINK_H_ */
