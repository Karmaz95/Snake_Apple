// client.m
#import <Foundation/Foundation.h>
#import <servers/bootstrap.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc != 2) return 1;
        
        mach_port_t bp, port;
        task_get_bootstrap_port(mach_task_self(), &bp);
        bootstrap_look_up(bp, "com.crimson.message_service", &port);
        
        NSMachPort *machPort = [[NSMachPort alloc] initWithMachPort:port];
        NSData *data = [[NSString stringWithUTF8String:argv[1]] dataUsingEncoding:NSUTF8StringEncoding];
        NSMutableArray *components = [NSMutableArray arrayWithObject:data];
        [machPort sendBeforeDate:[NSDate date] msgid:0 components:components from:nil reserved:0];
    }
    return 0;
}