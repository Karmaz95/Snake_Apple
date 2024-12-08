#include <mach/mach_types.h>
#include <libkern/libkern.h>

kern_return_t HelloWorld_start(kmod_info_t * ki, void *d);
kern_return_t HelloWorld_stop(kmod_info_t *ki, void *d);

kern_return_t HelloWorld_start(kmod_info_t * ki, void *d)
{
    printf("HelloWorld from kext start");
    return KERN_SUCCESS;
}

kern_return_t HelloWorld_stop(kmod_info_t *ki, void *d)
{
    printf("HelloWorld from kext stop");
    return KERN_SUCCESS;
}
