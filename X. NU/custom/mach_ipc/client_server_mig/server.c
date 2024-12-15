// server.c - MIG version
#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "message.h"

// Function prototype for MIG-generated server function
extern boolean_t message_server(
    mach_msg_header_t *InHeadP,
    mach_msg_header_t *OutHeadP);

// Implementation of our message handling function
// This is called by MIG-generated code when a message arrives
kern_return_t SERVER_send_message(
    mach_port_t server_port,
    vm_offset_t message,
    mach_msg_type_number_t messageCnt)
{
    // Simply print the received message
    printf("Received message: %s\n", (char*)message);
    return KERN_SUCCESS;
}

int main() {
    mach_port_t port;
    kern_return_t kr;

    // Register our service with the bootstrap server
    kr = bootstrap_check_in(bootstrap_port, "com.crimson.message_service", &port);
    if (kr != KERN_SUCCESS) {
        printf("bootstrap_check_in() failed with code 0x%x\n", kr);
        return 1;
    }

    // Start message handling loop using MIG-generated server function
    // 4096 is the maximum message size
    mach_msg_server(message_server, 4096, port, MACH_MSG_TIMEOUT_NONE);
    return 0;
}