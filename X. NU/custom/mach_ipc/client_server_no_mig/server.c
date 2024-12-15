// server.c
#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {
    // Step 1: Get the bootstrap port
    mach_port_t bootstrap_port;
    task_get_special_port(mach_task_self(), 
                         TASK_BOOTSTRAP_PORT, 
                         &bootstrap_port);

    // Step 2: Register our service with the bootstrap server
    // This allows clients to find us using the service name
    mach_port_t service_port;
    kern_return_t kr = bootstrap_check_in(bootstrap_port,
                                        "com.crimson.message_service",
                                        &service_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to register service\n");
        return 1;
    }

    printf("Server running...\n");

    // Allocate buffer for receiving messages
    // Buffer must be large enough for header + maximum message size
    char buffer[2048];
    mach_msg_header_t *msg = (mach_msg_header_t*)buffer;

    // Main message receive loop
    while (1) {
        // Receive message
        kr = mach_msg(
            msg,                    // Buffer to receive message
            MACH_RCV_MSG,          // Receive-only operation
            0,                     // Send size (unused for receive)
            sizeof(buffer),        // Maximum receive size
            service_port,          // Port to receive on
            MACH_MSG_TIMEOUT_NONE, // No timeout
            MACH_PORT_NULL         // No notify port
        );

        // Process received message
        if (kr == KERN_SUCCESS) {
            // Message data follows immediately after header
            char *data = (char*)(msg + 1);
            printf("Received: %s\n", data);
        } else {
            printf("Error receiving message\n");
        }
    }

    return 0;  // Never reached in this example
}