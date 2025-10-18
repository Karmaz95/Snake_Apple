/**
 * @file IOVerify.c
 * @brief Standalone tool for IOKit driver communication verification.
 * clang IOVerify.c -o IOVerify -framework IOKit
 *
 * This tool allows for direct interaction with macOS IOKit drivers using IOConnectCallMethod.
 *
 * Usage:
 *   IOVerify -n <name> (-m <method> | -y <spec>) [options]
 *
 * Options:
 *   -n <name>      : The class name of the IOKit service to target (required).
 *   -t <type>      : The connection type (user client type) to open. Default: 0.
 *   -m <id>        : The selector ID of the method to call.
 *   -y <spec>      : Shorthand to specify method and buffer sizes.
 *                    Format: "ID:[IN_SCA,IN_STR,OUT_SCA,OUT_STR]"
 *                    Example: -y "0: [0, 96, 0, 96]"
 *   -p <payload>   : A string to be used as the input buffer.
 *   -f <file_name> : A file whose contents will be the input buffer.
 *   -b <hex_string>: A space-separated hex string for the input buffer (e.g., "00 11 22 aa").
 *   -i <size>      : The size of the input structure buffer.
 *   -o <size>      : The size of the output structure buffer.
 *   -s <val>       : A 64-bit scalar input value (can be used multiple times).
 *   -S <count>     : The number of scalar output values.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>      // For getopt
#include <stdbool.h>     // For bool type
#include <IOKit/IOKitLib.h>
#include <mach/mach_error.h> // For mach_error_string

// --- Structure Definitions ---
// IOKit has a hard limit of 16 scalar inputs/outputs maximum
#define IOKIT_MAX_SCALAR_COUNT 16
uint64_t scalar_inputs[IOKIT_MAX_SCALAR_COUNT] = {0};

typedef struct {
    const char* driver_name;
    uint64_t conn_type;
    uint64_t method;
    const char* payload;
    const char* file_name;
    uint64_t input_size;
    uint64_t output_size;
    uint64_t* scalar_input;
    size_t scalar_in_size;
    size_t scalar_out_size;
    const char* byte_payload;
} verify_args_t;

// --- Forward Declarations ---

io_service_t find_driver_service(const char* driver_name);
io_connect_t get_driver_connection_handle(io_service_t service, const char* driver_name, uint32_t conn_type);
kern_return_t verify_driver_communication(const verify_args_t* args);
void print_usage(const char* prog_name);

// --- Implementations ---

void log_with_args(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

void print_payload_hexdump(const unsigned char *data, size_t size) {
    if (!data || size == 0) {
        printf("[empty]\n");
        return;
    }
    for (size_t i = 0; i < size; ++i) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (size % 16 != 0) printf("\n");
}

void log_event_with_scalars(const char* event, const verify_args_t* args, kern_return_t result, const void* output_buffer, size_t output_size, const uint64_t* scalar_output, size_t scalar_out_size_actual, const void* input_buffer, size_t input_size) {
    printf("\n--- [%s] Event Log ---\n", event);
    printf("Driver:          %s\n", args->driver_name);
    printf("Connection Type: %llu\n", args->conn_type);
    printf("Method Selector: %llu\n", args->method);
    printf("Result:          0x%x (%s)\n", result, mach_error_string(result));
    
    printf("\n--- Scalar I/O ---\n");
    printf("Scalar In Cnt:   %zu\n", args->scalar_in_size);
    if (args->scalar_in_size > 0 && args->scalar_input) {
        printf("Scalar In:       ");
        for (size_t i = 0; i < args->scalar_in_size; ++i) printf("0x%llx ", args->scalar_input[i]);
        printf("\n");
    }
    printf("Scalar Out Cnt:  %zu\n", scalar_out_size_actual);
    if (scalar_out_size_actual > 0 && scalar_output) {
        printf("Scalar Out:      ");
        for (size_t i = 0; i < scalar_out_size_actual; ++i) printf("0x%llx ", scalar_output[i]);
        printf("\n");
    }

    printf("\n--- Structure I/O ---\n");
    printf("Input Size:  %zu bytes\n", input_size);
    printf("Input Data:\n");
    print_payload_hexdump(input_buffer, input_size);
    
    printf("\nOutput Size: %zu bytes\n", output_size);
    printf("Output Data:\n");
    print_payload_hexdump(output_buffer, output_size);
    printf("--- End of Log ---\n\n");
}

io_service_t find_driver_service(const char* driver_name) {
    return IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(driver_name));
}

io_connect_t get_driver_connection_handle(io_service_t service, const char* driver_name, uint32_t conn_type) {
    io_connect_t client = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), conn_type, &client);
    if (kr != KERN_SUCCESS) {
        log_with_args("Failed to open connection for driver '%s' (type %u). Error: 0x%x (%s)", driver_name, conn_type, kr, mach_error_string(kr));
        return MACH_PORT_NULL;
    }
    return client;
}

kern_return_t verify_driver_communication(const verify_args_t* args) {
    if (!args || !args->driver_name) {
        return KERN_INVALID_ARGUMENT;
    }

    const io_service_t driver_service = find_driver_service(args->driver_name);
    if (driver_service == MACH_PORT_NULL) {
        log_with_args("Driver service '%s' not found.", args->driver_name);
        return KERN_FAILURE;
    }

    const io_connect_t client = get_driver_connection_handle(driver_service, args->driver_name, args->conn_type);
    if (client == MACH_PORT_NULL) {
        IOObjectRelease(driver_service);
        return KERN_FAILURE;
    }

    void* input_buffer = NULL;
    size_t input_size = args->input_size;
    if (args->file_name) {
        FILE* file = fopen(args->file_name, "rb");
        if (file) {
            fseek(file, 0, SEEK_END);
            input_size = ftell(file);
            fseek(file, 0, SEEK_SET);
            input_buffer = calloc(1, input_size);
            if (input_buffer) fread(input_buffer, 1, input_size, file);
            fclose(file);
        }
    } else if (args->byte_payload) {
        char* bp_copy = strdup(args->byte_payload);
        char* p = bp_copy;
        size_t count = 0;
        while (*p) {
            if (*p != ' ' && (p == bp_copy || *(p-1) == ' ')) count++;
            p++;
        }
        input_size = count;
        input_buffer = calloc(1, input_size);
        p = bp_copy;
        size_t idx = 0;
        while(idx < input_size) {
            char* next;
            ((unsigned char*)input_buffer)[idx++] = (unsigned char)strtol(p, &next, 16);
            p = next;
            while(*p == ' ') p++;
        }
        free(bp_copy);
    } else if (args->payload) {
        input_size = strlen(args->payload);
        input_buffer = calloc(1, input_size + 1);
        if (input_buffer) memcpy(input_buffer, args->payload, input_size);
    } else if (input_size > 0) {
        input_buffer = calloc(1, input_size);
    }

    size_t scalar_output_count = args->scalar_out_size;
    uint64_t* scalar_output = (scalar_output_count > 0) ? calloc(scalar_output_count, sizeof(uint64_t)) : NULL;
    size_t output_size = args->output_size;
    void* output_buffer = (output_size > 0) ? calloc(1, output_size) : NULL;

    uint32_t scalar_output_count_32 = scalar_output_count;
    kern_return_t result = IOConnectCallMethod(client, args->method, args->scalar_input, args->scalar_in_size, input_buffer, input_size, scalar_output, &scalar_output_count_32, output_buffer, &output_size);

    log_event_with_scalars("VERIFY", args, result, output_buffer, output_size, scalar_output, scalar_output_count_32, input_buffer, input_size);

    free(input_buffer);
    free(output_buffer);
    free(scalar_output);
    IOServiceClose(client);
    IOObjectRelease(driver_service);
    return result;
}

void print_usage(const char* prog_name) {
    printf("Usage: %s -n <name> (-m <method> | -y <spec>) [options]\n", prog_name);
    printf("Options:\n");
    printf("  -n <name>      Target driver class name (required).\n");
    printf("  -t <type>      Connection type (default: 0).\n");
    printf("  -m <id>        Method selector ID.\n");
    printf("  -y <spec>      Specify method and buffer sizes in one string.\n");
    printf("                 Format: \"ID: [IN_SCA, IN_STR, OUT_SCA, OUT_STR]\"\n");
    printf("                 Example: -y \"0: [0, 96, 0, 96]\"\n");
    printf("  -p <string>    Payload as a string.\n");
    printf("  -f <file>      File path for payload.\n");
    printf("  -b <hex_str>   Space-separated hex string payload.\n");
    printf("  -i <size>      Input buffer size (ignored if -y is used).\n");
    printf("  -o <size>      Output buffer size (ignored if -y is used).\n");
    printf("  -s <value>     Scalar input (uint64_t). Can be specified multiple times.\n");
    printf("  -S <count>     Scalar output count (ignored if -y is used).\n");
    printf("  -h             Show this help message.\n");
}

int main(int argc, char *argv[]) {
    verify_args_t args = {0};
    int opt;
    uint64_t scalar_inputs[16] = {0};
    size_t scalar_input_idx = 0;
    bool method_is_set = false;
    bool y_flag_used = false;

    while ((opt = getopt(argc, argv, "hn:t:m:p:f:b:i:o:s:S:y:")) != -1) {
        switch (opt) {
            case 'h': print_usage(argv[0]); return 0;
            case 'n': args.driver_name = optarg; break;
            case 't': args.conn_type = strtoull(optarg, NULL, 0); break;
            case 'm': args.method = strtoull(optarg, NULL, 0); method_is_set = true; break;
            case 'y': {
                y_flag_used = true;
                unsigned long long m, si, is, so, os;
                int items = sscanf(optarg, "%llu : [ %llu , %llu , %llu , %llu ]", &m, &si, &is, &so, &os);
                if (items == 5) { // Adding Scalar In/Out count checks - can't be more than 16
                    if (si > IOKIT_MAX_SCALAR_COUNT) {
                        fprintf(stderr, "Error: Scalar input count %llu exceeds IOKit maximum of %d.\n", si, IOKIT_MAX_SCALAR_COUNT);
                        return 1;
                    }
                    if (so > IOKIT_MAX_SCALAR_COUNT) {
                        fprintf(stderr, "Error: Scalar output count %llu exceeds IOKit maximum of %d.\n", so, IOKIT_MAX_SCALAR_COUNT);
                        return 1;
                    }
                    args.method = m;
                    args.scalar_in_size = si;
                    args.input_size = is;
                    args.scalar_out_size = so;
                    args.output_size = os;
                    method_is_set = true;
                } else {
                    fprintf(stderr, "Error: Invalid format for -y. Use 'ID: [sc_in, st_in, sc_out, st_out]'.\n");
                    return 1;
                }
                break;
            }
            case 'p': args.payload = optarg; break;
            case 'f': args.file_name = optarg; break;
            case 'b': args.byte_payload = optarg; break;
            case 'i': if (!y_flag_used) args.input_size = strtoull(optarg, NULL, 0); break;
            case 'o': if (!y_flag_used) args.output_size = strtoull(optarg, NULL, 0); break;
            case 's': // Adding Scalar In count checks - can't be more than 16
                if (scalar_input_idx < IOKIT_MAX_SCALAR_COUNT) {
                    scalar_inputs[scalar_input_idx++] = strtoull(optarg, NULL, 0);
                } else {
                    fprintf(stderr, "Exceeded IOKit maximum of %d scalar inputs.\n", IOKIT_MAX_SCALAR_COUNT);
                }
                break;
            case 'S': if (!y_flag_used) args.scalar_out_size = strtoull(optarg, NULL, 0); break;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (!args.driver_name || !method_is_set) {
        fprintf(stderr, "Error: Driver name (-n) and method ID (-m or -y) are required.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (y_flag_used) {
        if (scalar_input_idx > args.scalar_in_size) {
             fprintf(stderr, "Warning: More scalars via -s (%zu) than in -y (%zu). Extra values ignored.\n", scalar_input_idx, args.scalar_in_size);
        } else if (scalar_input_idx < args.scalar_in_size) {
            fprintf(stderr, "Warning: Fewer scalars via -s (%zu) than in -y (%zu). Remaining values zeroed.\n", scalar_input_idx, args.scalar_in_size);
        }
    } else {
        args.scalar_in_size = scalar_input_idx;
    }
    
    args.scalar_input = scalar_inputs;

    printf("Starting verification for driver: %s\n", args.driver_name);
    verify_driver_communication(&args);

    return 0;
}
