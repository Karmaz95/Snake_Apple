#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <service_name>\n", argv[0]);
        return 1;
    }

    const char *service_name = argv[1];
    mach_port_t bootstrap_port, service_port;
    kern_return_t kr;

    // Get the bootstrap port
    kr = task_get_bootstrap_port(mach_task_self(), &bootstrap_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get bootstrap port: %s\n", mach_error_string(kr));
        return 1;
    }

    // Look up the service
    kr = bootstrap_look_up(bootstrap_port, service_name, &service_port);
    if (kr != KERN_SUCCESS) {
        printf("Service '%s' not found: %s\n", service_name, mach_error_string(kr));
        return 1;
    }

    // Get port rights information
    mach_port_type_t type;
    kr = mach_port_type(mach_task_self(), service_port, &type);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get port type: %s\n", mach_error_string(kr));
        return 1;
    }

    printf("Service: %s\n", service_name);
    printf("Port: 0x%x\n", service_port);
    printf("Rights: ");
    if (type & MACH_PORT_TYPE_RECEIVE) printf("RECV ");
    if (type & MACH_PORT_TYPE_SEND) printf("SEND ");
    if (type & MACH_PORT_TYPE_SEND_ONCE) printf("ONCE ");
    if (type & MACH_PORT_TYPE_PORT_SET) printf("SET ");
    if (type & MACH_PORT_TYPE_DEAD_NAME) printf("DEAD ");
    printf("\n");

    // Cleanup
    mach_port_deallocate(mach_task_self(), service_port);
    mach_port_deallocate(mach_task_self(), bootstrap_port);

    return 0;
}