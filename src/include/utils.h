#ifndef TI_MFA_UTILS_H
#define TI_MFA_UTILS_H

#include "ti_mfa.h"


/* TODO: replace with #include <linux/compiler_attributes.h> */
#ifdef __clang__
    #define __fallthrough__ [[fallthrough]]
#else
    #define __fallthrough__ __attribute__ ((fallthrough))
#endif

void debug_print_labels(uint label_count, const u32 labels[]);
void debug_print_link_failures(uint link_failure_count,
                               const struct ti_mfa_shim_hdr link_failures[]);
void debug_print_next_hop(struct ti_mfa_nh nh);

#endif /* TI_MFA_UTILS_H */
