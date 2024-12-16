// server.m
#import <Foundation/Foundation.h>

@interface MessageServer : NSObject
- (void)handleMessage:(NSNotification *)notification;
@end

@implementation MessageServer
- (id)init {
    if (self = [super init]) {
        [[NSDistributedNotificationCenter defaultCenter] 
            addObserver:self
            selector:@selector(handleMessage:)
            name:@"com.crimson.message_service"
            object:nil];
    }
    return self;
}

- (void)handleMessage:(NSNotification *)notification {
    NSLog(@"Received: %@", notification.userInfo[@"message"]);
}
@end

int main() {
    @autoreleasepool {
        MessageServer *server = [[MessageServer alloc] init];
        [[NSRunLoop currentRunLoop] run];
    }
    return 0;
}