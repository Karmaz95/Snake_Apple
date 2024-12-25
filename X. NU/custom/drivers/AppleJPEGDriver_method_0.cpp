#include <IOKit/IOKitLib.h>
#include <stdio.h>

int main() {
    // Get service
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleJPEGDriver"));
    
    // Connect to service
    io_connect_t connect;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 1, &connect);
    IOObjectRelease(service);
    
    // Call external method
    kr = IOConnectCallMethod(connect, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
    printf("Method call result: 0x%x\n", kr);
    
    // Cleanup
    IOServiceClose(connect);
    return 0;
}