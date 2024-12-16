// server.m
// clang -framework Foundation server.m -o server
#import <Foundation/Foundation.h>

static CFDataRef callback(CFMessagePortRef port, SInt32 msgid, CFDataRef data, void *info) {
    NSLog(@"Received: %@", [[NSString alloc] initWithData:(__bridge NSData *)data encoding:NSUTF8StringEncoding]);
    return NULL;
}

int main() {
    @autoreleasepool {
        CFMessagePortRef port = CFMessagePortCreateLocal(NULL, CFSTR("com.crimson.message_service"), callback, NULL, NULL);
        CFRunLoopSourceRef source = CFMessagePortCreateRunLoopSource(NULL, port, 0);
        CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopCommonModes);
        [[NSRunLoop currentRunLoop] run];
    }
    return 0;
}