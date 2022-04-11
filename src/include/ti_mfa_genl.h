#ifndef GENETLINK_H_
#define GENETLINK_H_

/**
 * TABLES
 */

#define TI_MFA_LINKS    "links"

/**
 * COMMANDS
 */

#define ADD 	"add"
#define DEL		"del"
#define SHOW 	"show"
#define HELP 	"help"
#define FLUSH 	"flush"

/**
 * BEHAVIORS
 */

#define END        		"end"

/**
 * BEHAVIORS CODE
 */

enum SR_GNL_COMMANDS {
	SR_C_ECHO,
	SR_C_ADD,
	SR_C_DEL,
	SR_C_SHOW,
	SR_C_FLUSH,
	SR_C_CLEAR,
	_SR_C_MAX,
};

enum SR_GNL_ATTRIBUTES {
	SR_A_ZERO, //do not touch, this is for the attributes order
	SR_A_UNSPEC,

	SR_A_TABLE,
	SR_A_COMMAND,
	SR_A_SID,
	SR_A_FUNC,
	SR_A_NEXT,
	SR_A_MAC,
	SR_A_OIF,
	SR_A_IIF,
	SR_A_SOURCE,
	SR_A_ADDR,
	SR_A_SEGS,
	SR_A_SID_LST,
	SR_A_LEFT,
	SR_A_NUMBER,
	SR_A_FLAGS,

	SR_A_RESPONSE,
	SR_A_RESPONSE_LST,

	_SR_A_MAX,
};

#define SR_GNL_FAMILY_NAME "SR_GENL_FAMILY"
#define SR_GNL_FAMILY_VERSION 1
#define SR_A_MAX (_SR_A_MAX - 1)
#define SR_C_MAX (_SR_C_MAX - 1)
#define MAX_BUF_LEN 1024*5

struct genl_msg_data {
	int		atype;
	void	*data;
	int		len;
};

struct sr_mac {
	char oct[6];
};

struct sr_param {
	char *table;
	char *command;
	char *sid;
	char *func;
	char *next;
	struct sr_mac *mac;
	char *oif;
	char *iif;

	char *source;
	char *addr;
	char *segs ;
	char *sid_lst;
	char *left;
	char *number;
	char *flags;
};

int sr_genl_register(void);
int sr_genl_unregister(void);

#endif /* GENETLINK_H_ */

