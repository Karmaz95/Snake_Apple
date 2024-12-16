#import <Foundation/Foundation.h>

@interface MessageServer : NSObject
- (void)handleMessage:(NSString *)message;
@end

@implementation MessageServer
- (void)handleMessage:(NSString *)message {
    NSLog(@"Received: %@", message);
}
@end

int main() {
    @autoreleasepool {
        MessageServer *server = [[MessageServer alloc] init];
        NSConnection *connection = [NSConnection defaultConnection];
        [connection setRootObject:server];
        [connection registerName:@"com.crimson.message_service"];
        [[NSRunLoop currentRunLoop] run];
    }
    return 0;
}
