// client.c - MIG version
#include <stdio.h>
#include <string.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "message.h"  // MIG-generated header

int main(int argc, char *argv[]) {
    // Validate command line arguments
    if (argc != 2) {
        printf("Usage: %s <message>\n", argv[0]);
        return 1;
    }

    // Get bootstrap port for service lookup
    mach_port_t port;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, 
                                       "com.crimson.message_service", 
                                       &port);
    if (kr != KERN_SUCCESS) {
        printf("Service not found\n");
        return 1;
    }

    // Use MIG-generated function to send message
    // This handles all the message structure creation internally
    USER_send_message(port, (pointer_t)argv[1], strlen(argv[1]));
    return 0;
}