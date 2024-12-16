#import <Foundation/Foundation.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc != 2) {
            NSLog(@"Usage: %s <message>", argv[0]);
            return 1;
        }
        
        NSConnection *connection = [NSConnection connectionWithRegisteredName:@"com.crimson.message_service" host:nil];
        id<NSObject> server = [connection rootProxy];
        
        NSString *message = [NSString stringWithUTF8String:argv[1]];
        [server handleMessage:message];
    }
    return 0;
}
