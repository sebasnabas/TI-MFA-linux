#ifdef DEBUG
    #include <linux/utsname.h>

    #undef pr_fmt
    #define pr_fmt(fmt) "[%s] %s:%s: " fmt, utsname()->nodename, KBUILD_MODNAME, __func__
#else
    #undef pr_fmt
    #define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME
#endif
