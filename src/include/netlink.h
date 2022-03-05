#ifndef TI_MFA_NETLINK_H
#define TI_MFA_NETLINK_H

#include <linux/lwtunnel.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>

/* From iproute2 ip/ipnexthop.c */
#define RTM_NHA(h)  ((struct rtattr *)(((char *)(h)) + \
			NLMSG_ALIGN(sizeof(struct nhmsg))))

/* From iproute2 include/rtnetlink.h */
#define parse_rtattr_nested(tb, max, rta) \
	(parse_rtattr_flags((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta), \
			    NLA_F_NESTED))

/* From iproute2 route2 include/libnetlink.h */
static inline __u16 rta_getattr_u16(const struct rtattr *rta)
{
	return *(__u16 *)RTA_DATA(rta);
}
static inline __u32 rta_getattr_u32(const struct rtattr *rta)
{
	return *(__u32 *)RTA_DATA(rta);
}

void rcv_netlink_msg(struct sock *sk);

#endif /* TI_MFA_NETLINK_H */