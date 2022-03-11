#ifndef TI_MFA_UTILS_H
#define TI_MFA_UTILS_H

#include <linux/mpls.h>

#ifdef DEBUG
    #include <linux/utsname.h>
    #define HOST_NAME utsname()->nodename
#else
    #define HOST_NAME ""
#endif

bool is_not_mpls(struct sk_buff *skb);

#endif /* TI_MFA_UTILS_H */