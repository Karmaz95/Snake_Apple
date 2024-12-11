// clang CommPageParser.c -o CommPageParser -arch arm64
#include <stdio.h>
#include <stdint.h>

#define COMM_PAGE_BASE 0xfffffc000ULL

typedef struct {
    uint64_t TimeStamp_tick;
    uint64_t TimeStamp_sec;
    uint64_t TimeStamp_frac;
    uint64_t Ticks_scale;
    uint64_t Ticks_per_sec;
} new_commpage_timeofday_data_t;

typedef struct {
    uint64_t nt_tsc_base;
    uint32_t nt_scale;
    uint32_t nt_shift;
    uint64_t nt_ns_base;
    uint32_t nt_generation;
    uint32_t gtod_generation;
    uint64_t gtod_ns_base;
    uint64_t gtod_sec_base;
} time_data_t;

typedef struct {
    uint8_t signature[16];
    uint64_t cpu_capabilities64;
    uint8_t unused[6];
    uint16_t version;
    uint32_t cpu_capabilities;
    uint8_t ncpus;
    uint8_t user_page_shift_32;
    uint8_t user_page_shift_64;
    uint16_t cache_linesize;
    uint32_t unused4;
    uint32_t unused3;
    uint32_t memory_pressure;
    uint8_t active_cpus;
    uint8_t physical_cpus;
    uint8_t logical_cpus;
    uint8_t kernel_page_shift;
    uint64_t memory_size;
    uint32_t cpufamily;
    uint32_t dev_firm;
    uint64_t timebase_offset;
    uint8_t user_timebase;
    uint8_t cont_hwclock;
    uint8_t dtrace_dof_enabled;
    uint8_t unused0[5];
    time_data_t time_data;
    struct {
        uint64_t time;
        uint64_t time_supported;
        uint8_t _fill[48];
    } approx;
    uint64_t cont_timebase;
    uint64_t boottime_usec;
    new_commpage_timeofday_data_t new_time_data;
    uint64_t unused5;
    uint64_t dyld_flags;
    uint8_t cpu_to_cluster[256];
    uint64_t quiescent_counter;
    uint64_t asb_target_value;
    uint64_t asb_target_address;
    uint64_t asb_target_kern_value;
    uint64_t asb_target_kern_address;
} comm_page_t;

void print_cpu_capabilities64(uint64_t caps) {
    printf("CPU Capabilities64 details:\n");
    if (caps & 0x00000008) printf("  - FP16 Support\n");
    if (caps & 0x00000100) printf("  - Advanced SIMD\n");
    if (caps & 0x00000200) printf("  - Advanced SIMD half-precision\n");
    if (caps & 0x00000400) printf("  - VFP Support\n");
    if (caps & 0x00002000) printf("  - FMA Support\n");
    if (caps & 0x01000000) printf("  - ARMv8 Crypto\n");
    if (caps & 0x02000000) printf("  - ARMv8.1 Atomic instructions\n");
    if (caps & 0x04000000) printf("  - ARMv8 CRC32\n");
    if (caps & 0x80000000) printf("  - SHA512\n");
    // Extended capabilities
    if (caps & 0x0000000100000000) printf("  - SHA3\n");
    if (caps & 0x0000000200000000) printf("  - FCMA\n");
    if (caps & 0x0000000400000000) printf("  - AFP\n");
}

int main() {
    comm_page_t *comm = (comm_page_t *)COMM_PAGE_BASE;
    
    printf("Signature: ");
    for(int i = 0; i < 16; i++) printf("%02x", comm->signature[i]);
    printf("\n\n");
    
    printf("CPU Capabilities64: 0x%llx\n", comm->cpu_capabilities64);
    print_cpu_capabilities64(comm->cpu_capabilities64);
    printf("\nVersion: %d\n", comm->version);
    printf("CPU Capabilities32: 0x%x\n", comm->cpu_capabilities);
    
    printf("\nCPU Information:\n");
    printf("Physical CPUs: %d\n", comm->physical_cpus);
    printf("Logical CPUs: %d\n", comm->logical_cpus);
    printf("Active CPUs: %d\n", comm->active_cpus);
    printf("Number of configured CPUs: %d\n", comm->ncpus);
    
    printf("\nMemory Information:\n");
    printf("Cache Line Size: %d\n", comm->cache_linesize);
    printf("Memory Size: %lld bytes\n", comm->memory_size);
    printf("Memory Pressure: %d\n", comm->memory_pressure);
    printf("32-bit Page Shift: %d\n", comm->user_page_shift_32);
    printf("64-bit Page Shift: %d\n", comm->user_page_shift_64);
    printf("Kernel Page Shift: %d\n", comm->kernel_page_shift);
    
    printf("\nSystem Information:\n");
    printf("CPU Family: 0x%x\n", comm->cpufamily);
    printf("Device Firmware: 0x%x\n", comm->dev_firm);
    printf("DYLD System Flags: 0x%llx\n", comm->dyld_flags);
    printf("DTrace DOF Enabled: %d\n", comm->dtrace_dof_enabled);
    
    printf("\nTime Information:\n");
    printf("Timebase Offset: 0x%llx\n", comm->timebase_offset);
    printf("Boot Time: %lld μs\n", comm->boottime_usec);
    printf("Continuous Hardware Clock: %d\n", comm->cont_hwclock);
    printf("User Timebase: %d\n", comm->user_timebase);
    printf("Continuous Timebase: 0x%llx\n", comm->cont_timebase);
    
    printf("\nTime Data:\n");
    printf("TSC Base: 0x%llx\n", comm->time_data.nt_tsc_base);
    printf("Scale: %u\n", comm->time_data.nt_scale);
    printf("Shift: %u\n", comm->time_data.nt_shift);
    printf("NS Base: %lld\n", comm->time_data.nt_ns_base);
    printf("Generation: %u\n", comm->time_data.nt_generation);
    
    printf("\nNew Time Data:\n");
    printf("Timestamp tick: %lld\n", comm->new_time_data.TimeStamp_tick);
    printf("Timestamp sec: %lld\n", comm->new_time_data.TimeStamp_sec);
    printf("Ticks per sec: %lld\n", comm->new_time_data.Ticks_per_sec);
    
    printf("\nApproximate Time:\n");
    printf("Time: %lld\n", comm->approx.time);
    printf("Time Supported: %lld\n", comm->approx.time_supported);
    
    printf("\nSecurity Information:\n");
    printf("ASB Target Value: 0x%llx\n", comm->asb_target_value);
    printf("ASB Target Address: 0x%llx\n", comm->asb_target_address);
    printf("ASB Target Kernel Value: 0x%llx\n", comm->asb_target_kern_value);
    printf("ASB Target Kernel Address: 0x%llx\n", comm->asb_target_kern_address);
    
    printf("\nCPU Quiescent Counter: %lld\n", comm->quiescent_counter);
    
    return 0;
}