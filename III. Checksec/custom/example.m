// clang -fobjc-arc -framework Foundation example.m -o arc_example
#import <Foundation/Foundation.h>

@interface Person : NSObject
@property NSString *name;
@end

@implementation Person
@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Create a Person object
        Person *person = [[Person alloc] init];
        person.name = @"John Doe";
        
        // The person object will be automatically managed by ARC
        NSLog(@"Person's name: %@", person.name);
    }
    return 0;
}