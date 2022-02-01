#include <linux/kernel.h>
#include <linux/module.h>

#include "utils.h"
/**
 * dmesg()
 * Wrapping printk to add module name
 */
void dmesg( const char * format, ...)
{
    va_list ap;
    va_start(ap, format);
    printk("[TI-MFA]");
    vprintk(format, ap);
    va_end(ap);
}

/**
 * dmesg_err()
 * Wrapping printk to add module name and error string
 */
void dmesg_err( const char * format, ...)
{
    va_list ap;
    va_start(ap, format);
    printk("[TI-MFA][Error]");
    vprintk(format, ap);
    va_end(ap);
}
