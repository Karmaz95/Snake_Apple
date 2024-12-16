// client.m
#import <Foundation/Foundation.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc != 2) {
            NSLog(@"Usage: %s <message>", argv[0]);
            return 1;
        }
        
        NSString *message = [NSString stringWithUTF8String:argv[1]];
        [[NSDistributedNotificationCenter defaultCenter]
            postNotificationName:@"com.crimson.message_service"
            object:nil
            userInfo:@{@"message": message}
            deliverImmediately:YES];
    }
    return 0;
}