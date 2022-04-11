#ifndef NET_TI_MFA_CONF_H_
#define NET_TI_MFA_CONF_H_

#include "ti_mfa_genl.h"

struct genl_msg {
	struct nlmsghdr n;		//128 bit = 16 bytes
	struct genlmsghdr g;	//32  bit = 8  bytes

	//25 ---> ..
	char buf[MAX_BUF_LEN];
};

#define GENLMSG_DATA(glh) 			((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_DATALEN(glh) 		(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define GENLMSG_NLA_NEXT(na) 		(((void *)(na)) + NLA_ALIGN(na->nla_len))
#define GENLMSG_NLA_DATA(na) 		((void *)((char*)(na) + NLA_HDRLEN))
#define GENLMSG_NLA_DATALEN(na) 	(na->nla_len - NLA_HDRLEN - 1)

#endif /* NET_TI_MFA_CONF_H_ */
