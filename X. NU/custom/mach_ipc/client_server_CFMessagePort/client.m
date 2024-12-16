#import <Foundation/Foundation.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc != 2) return 1;
        
        CFMessagePortRef port = CFMessagePortCreateRemote(NULL, CFSTR("com.crimson.message_service"));
        if (port) {
            NSString *msg = [NSString stringWithUTF8String:argv[1]];
            NSData *data = [msg dataUsingEncoding:NSUTF8StringEncoding];
            CFMessagePortSendRequest(port, 0, (__bridge CFDataRef)data, 1, 1, NULL, NULL);
            CFRelease(port);
        }
    }
    return 0;
}