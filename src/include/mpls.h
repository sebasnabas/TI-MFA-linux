#include <linux/mpls.h>

#define MPLS_LABEL(x)   (x & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
#define MPLS_TC(x)      (x & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT;
#define MPLS_STACK(x)   (x & MPLS_LS_TC_MASK) >> MPLS_LS_TC_SHIFT;
#define MPLS_TTL(x)     (x & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT;