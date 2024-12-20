// crimson_xpc_client.c
// This client demonstrates how to create and manage an XPC connection to communicate
// with a LaunchDaemon or LaunchAgent service

#include <xpc/xpc.h>            // XPC framework for secure inter-process communication
#include <dispatch/dispatch.h>  // GCD for asynchronous operations and event handling
#include <stdio.h>              // Standard I/O for error reporting and status messages
#include <stdlib.h>             // Standard library for program termination functions

int main(void) {
    // Initialize an XPC connection to a Mach service
    // The service name must match the label in the service's plist file
    // XPC_CONNECTION_MACH_SERVICE_PRIVILEGED indicates this client expects 
    // to connect to a privileged service (typically a LaunchDaemon)
    xpc_connection_t conn = xpc_connection_create_mach_service(
        "com.crimson.xpc.message_service",
        dispatch_get_main_queue(),    // Main queue handles all connection events
        XPC_CONNECTION_MACH_SERVICE_PRIVILEGED
    );
    
    // Configure an event handler for connection-level events
    // This handler processes XPC_TYPE_ERROR events, which occur on 
    // connection failures, service termination, or invalid messages
    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_ERROR) {
            fprintf(stderr, "Connection error: %s\n", 
                    xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION));
        }
    });
    
    // Activate the connection to begin processing events
    // Must be called before any messages can be sent
    xpc_connection_resume(conn);
    
    // Create an XPC dictionary to encapsulate the message data
    // XPC dictionaries are the primary container type for XPC messages
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "message_data", "Hello from Crimson!");
    
    // Send message and handle response asynchronously
    // The reply block executes when the service responds or on timeout
    xpc_connection_send_message_with_reply(conn, message, 
        dispatch_get_main_queue(), ^(xpc_object_t reply) {
            if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
                printf("Reply status: %s\n", 
                       xpc_dictionary_get_string(reply, "status"));
            }
            // Schedule program termination after reply processing
            // Using dispatch_async ensures clean shutdown
            dispatch_async(dispatch_get_main_queue(), ^{
                exit(0);
            });
    });
    
    // Decrement the message object's reference count
    // XPC uses manual reference counting for memory management
    xpc_release(message);
    
    // Run the main dispatch loop to process asynchronous events
    // This call never returns - program exits via the reply handler
    dispatch_main();
}