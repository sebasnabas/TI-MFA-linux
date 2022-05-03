#ifndef TI_MFA_ALGO_H
#define TI_MFA_ALGO_H

#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include "mpls.h"
#include "routes.h"

/* run_ti_mfa() success codes */
#define TI_MFA_SUCCESS  0x00
#define TI_MFA_PASS     0x01    /* skb was not an mpls packet */
#define TI_MFA_ERROR    0x02
#define TI_MFA_RETRY    0x03

uint flush_link_failure_stack(struct sk_buff *skb, struct ti_mfa_shim_hdr link_failures[], int max);
int run_ti_mfa(struct net *net, struct sk_buff *skb);
int run_ti_mfa_ingress(struct net *net, struct sk_buff *skb);
void ti_mfa_ifdown(struct net_device *dev);
void ti_mfa_ifup(const struct net_device *dev);
int initialize_ti_mfa(void);
void cleanup_ti_mfa(void);

#endif // TI_MFA_ALGO_H
