#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>

#define CSR_ALLOW_UNTRUSTED_KEXTS            0x1
#define CSR_ALLOW_UNRESTRICTED_FS            0x2
#define CSR_ALLOW_TASK_FOR_PID               0x4
#define CSR_ALLOW_KERNEL_DEBUGGER            0x8
#define CSR_ALLOW_APPLE_INTERNAL             0x10
#define CSR_ALLOW_UNRESTRICTED_DTRACE        0x20
#define CSR_ALLOW_UNRESTRICTED_NVRAM         0x40
#define CSR_ALLOW_DEVICE_CONFIGURATION       0x80
#define CSR_ALLOW_ANY_RECOVERY_OS            0x100
#define CSR_ALLOW_UNAPPROVED_KEXTS           0x200
#define CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE 0x400
#define CSR_ALLOW_UNAUTHENTICATED_ROOT       0x800

typedef int (*csr_get_active_config_t)(uint32_t *);

void print_sip_flags(uint32_t sip_int) {
    printf("SIP Configuration Flags:\n");
    printf("CSR_ALLOW_UNTRUSTED_KEXTS: %s\n", (sip_int & CSR_ALLOW_UNTRUSTED_KEXTS) ? "On" : "Off");
    printf("CSR_ALLOW_UNRESTRICTED_FS: %s\n", (sip_int & CSR_ALLOW_UNRESTRICTED_FS) ? "On" : "Off");
    printf("CSR_ALLOW_TASK_FOR_PID: %s\n", (sip_int & CSR_ALLOW_TASK_FOR_PID) ? "On" : "Off");
    printf("CSR_ALLOW_KERNEL_DEBUGGER: %s\n", (sip_int & CSR_ALLOW_KERNEL_DEBUGGER) ? "On" : "Off");
    printf("CSR_ALLOW_APPLE_INTERNAL: %s\n", (sip_int & CSR_ALLOW_APPLE_INTERNAL) ? "On" : "Off");
    printf("CSR_ALLOW_UNRESTRICTED_DTRACE: %s\n", (sip_int & CSR_ALLOW_UNRESTRICTED_DTRACE) ? "On" : "Off");
    printf("CSR_ALLOW_UNRESTRICTED_NVRAM: %s\n", (sip_int & CSR_ALLOW_UNRESTRICTED_NVRAM) ? "On" : "Off");
    printf("CSR_ALLOW_DEVICE_CONFIGURATION: %s\n", (sip_int & CSR_ALLOW_DEVICE_CONFIGURATION) ? "On" : "Off");
    printf("CSR_ALLOW_ANY_RECOVERY_OS: %s\n", (sip_int & CSR_ALLOW_ANY_RECOVERY_OS) ? "On" : "Off");
    printf("CSR_ALLOW_UNAPPROVED_KEXTS: %s\n", (sip_int & CSR_ALLOW_UNAPPROVED_KEXTS) ? "On" : "Off");
    printf("CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE: %s\n", (sip_int & CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE) ? "On" : "Off");
    printf("CSR_ALLOW_UNAUTHENTICATED_ROOT: %s\n", (sip_int & CSR_ALLOW_UNAUTHENTICATED_ROOT) ? "On" : "Off");
}

int main() {
    void *libSystem = dlopen("/usr/lib/libSystem.dylib", RTLD_LAZY);
    csr_get_active_config_t csr_get_active_config = dlsym(libSystem, "csr_get_active_config");
    uint32_t sip_int = 0;
    csr_get_active_config(&sip_int);
    print_sip_flags(sip_int);
    return 0;
}