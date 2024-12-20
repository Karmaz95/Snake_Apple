// crimson_xpc_service.c
// This implements an XPC service that can be launched as a LaunchDaemon or LaunchAgent
// It demonstrates basic XPC message handling and connection management patterns

#include <xpc/xpc.h>            // XPC for inter-process communication
#include <dispatch/dispatch.h>  // GCD for asynchronous event handling
#include <stdio.h>              // Standard I/O for logging messages

int main(void) {
    // Initialize the XPC service listener
    // XPC_CONNECTION_MACH_SERVICE_LISTENER indicates this process will accept incoming connections
    // The service name must match both the client and the service's launchd plist MachServices entry
    xpc_connection_t service = xpc_connection_create_mach_service(
        "com.crimson.xpc.message_service",
        dispatch_get_main_queue(),    // Main queue handles all service events
        XPC_CONNECTION_MACH_SERVICE_LISTENER
    );
    
    // Set up handler for new client connections
    // This outer handler processes connection establishment events
    // Each new client connection creates a new peer object
    xpc_connection_set_event_handler(service, ^(xpc_object_t peer) {
        // Security check: Validate connection object type
        // Early return prevents processing of invalid connection attempts
        if (xpc_get_type(peer) != XPC_TYPE_CONNECTION) return;
        
        // Configure message handler for this specific client connection
        // Each client gets its own message handler to maintain separation
        xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            // Only process dictionary-type messages for protocol compliance
            if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
                // Extract message data with bounds checking via len parameter
                // This prevents buffer overflow vulnerabilities
                size_t len;
                const void* data = xpc_dictionary_get_data(message, "message_data", &len);
                if (data) printf("Received: %.*s\n", (int)len, (char*)data);
                
                // Create and send reply to the client
                // xpc_dictionary_create_reply maintains message context for proper routing
                xpc_object_t reply = xpc_dictionary_create_reply(message);
                xpc_dictionary_set_string(reply, "status", "received");
                xpc_connection_send_message(peer, reply);
                xpc_release(reply);  // Clean up reply object to prevent memory leaks
            }
        });
        
        // Activate this client's connection to begin processing its messages
        xpc_connection_resume(peer);
    });
    
    // Activate the service listener to begin accepting connections
    xpc_connection_resume(service);
    
    // Run the main dispatch loop
    // This service will continue running until terminated by launchd
    dispatch_main();
}