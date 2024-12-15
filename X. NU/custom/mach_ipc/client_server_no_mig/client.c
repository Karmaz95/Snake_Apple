// client.c
#include <stdio.h>
#include <string.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

/*
 * Message structure for IPC communication
 * Consists of two parts:
 * 1. mach_msg_header_t h - Standard Mach message header required for all IPC
 * 2. char d[1024] - Data buffer for the actual message content
 */
typedef struct {
    mach_msg_header_t h;  // Header must be first member
    char d[1024];         // Data buffer follows immediately after header
} msg_t;

int main(int argc, char *argv[]) {
    // Validate command line arguments
    if (argc != 2) {
        printf("Usage: %s <message>\n", argv[0]);
        return 1;
    }
    
    // Step 1: Get the bootstrap port
    // Bootstrap server is the central name server in Mach IPC
    mach_port_t bootstrap_port;
    task_get_special_port(mach_task_self(), 
                         TASK_BOOTSTRAP_PORT, 
                         &bootstrap_port);

    // Step 2: Look up the service port using bootstrap server
    // This finds our server process using the registered name
    mach_port_t service_port;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, 
                                       "com.crimson.message_service", 
                                       &service_port);
    if (kr != KERN_SUCCESS) {
        printf("Service not found\n");
        return 1;
    }

    // Step 3: Prepare the message structure
    // Initialize message structure to zero
    msg_t message = {0};
    
    // Configure message header
    message.h.msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_COPY_SEND);  // Set message type to copy-send
    message.h.msgh_size = sizeof(msg_t);                                    // Total size of message struct
    message.h.msgh_remote_port = service_port;                              // Destination port
    message.h.msgh_local_port = MACH_PORT_NULL;                            // No reply port needed
    message.h.msgh_id = 0;                                                 // Message ID (unused in this case)

    // Copy the user's message into data buffer
    // Using strncpy to prevent buffer overflow
    strncpy(message.d, argv[1], sizeof(message.d) - 1);
    message.d[sizeof(message.d) - 1] = '\0';  // Ensure null termination

    // Step 4: Send the message
    kr = mach_msg(
        &message.h,           // Message header pointer
        MACH_SEND_MSG,        // Send-only operation
        sizeof(msg_t),        // Size of entire message
        0,                    // Maximum receive size (unused for send)
        MACH_PORT_NULL,       // Destination port (unused for send)
        MACH_MSG_TIMEOUT_NONE,// No timeout
        MACH_PORT_NULL        // No notify port
    );

    // Step 5: Check for errors and return status
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message\n");
        return 1;
    }

    return 0;
}