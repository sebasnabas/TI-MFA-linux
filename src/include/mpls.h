#include <linux/mpls.h>

#define MPLS_LABEL(x)   (x & ~MPLS_LABEL_MASK)
#define MPLS_TC(x)      (x & ~MPLS_TC_MASK)
#define MPLS_BOS(x)     (x & ~MPLS_BOS_MASK)
#define MPLS_TTL(x)     (x & ~MPLS_TTL_MASK)