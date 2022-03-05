#ifndef TI_MFA_UTILS_H
#define TI_MFA_UTILS_H


#ifdef DEBUG
    #include <linux/utsname.h>
    #define HOST_NAME utsname()->nodename
#else
    #define HOST_NAME ""
#endif

#endif /* TI_MFA_UTILS_H */