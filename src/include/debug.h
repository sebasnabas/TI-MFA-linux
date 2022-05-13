#ifdef DEBUG
    #include <linux/utsname.h>
    #define HOST_NAME utsname()->nodename
#else
    #define HOST_NAME ""
#endif

#undef pr_fmt
#define pr_fmt(fmt) "[%s] %s:%s: " fmt, HOST_NAME, KBUILD_MODNAME, __func__
