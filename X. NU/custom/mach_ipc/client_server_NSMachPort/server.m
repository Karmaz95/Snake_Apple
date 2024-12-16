// server.m
#import <Foundation/Foundation.h>
#import <servers/bootstrap.h>

@interface Server : NSObject <NSMachPortDelegate>
@end

@implementation Server
- (void)handlePortMessage:(NSPortMessage *)message {
    NSData *data = [[message components] firstObject];
    NSString *msg = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSLog(@"Received: %@", msg);
}
@end

int main() {
    @autoreleasepool {
        Server *server = [[Server alloc] init];
        mach_port_t bp;
        task_get_bootstrap_port(mach_task_self(), &bp);
        mach_port_t servicePort;
        kern_return_t kr = bootstrap_check_in(bp, "com.crimson.message_service", &servicePort);
        if (kr != KERN_SUCCESS) return 1;
        
        NSMachPort *port = [[NSMachPort alloc] initWithMachPort:servicePort];
        port.delegate = server;
        [[NSRunLoop currentRunLoop] addPort:port forMode:NSDefaultRunLoopMode];
        [[NSRunLoop currentRunLoop] run];
    }
    return 0;
}