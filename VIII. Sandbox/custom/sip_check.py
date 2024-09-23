import ctypes

# Define the constants
CSR_ALLOW_UNTRUSTED_KEXTS            = 0x1
CSR_ALLOW_UNRESTRICTED_FS            = 0x2
CSR_ALLOW_TASK_FOR_PID               = 0x4
CSR_ALLOW_KERNEL_DEBUGGER            = 0x8
CSR_ALLOW_APPLE_INTERNAL             = 0x10
CSR_ALLOW_UNRESTRICTED_DTRACE        = 0x20
CSR_ALLOW_UNRESTRICTED_NVRAM         = 0x40
CSR_ALLOW_DEVICE_CONFIGURATION       = 0x80
CSR_ALLOW_ANY_RECOVERY_OS            = 0x100
CSR_ALLOW_UNAPPROVED_KEXTS           = 0x200
CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE = 0x400
CSR_ALLOW_UNAUTHENTICATED_ROOT       = 0x800

# Load the System library
libSystem = ctypes.CDLL('/usr/lib/libSystem.dylib')

# Define the function prototype
libSystem.csr_get_active_config.argtypes = [ctypes.POINTER(ctypes.c_uint32)]
libSystem.csr_get_active_config.restype = ctypes.c_int

def print_sip_flags(sip_int):
    print("SIP Configuration Flags:")
    print(f"CSR_ALLOW_UNTRUSTED_KEXTS: {'On' if sip_int & CSR_ALLOW_UNTRUSTED_KEXTS else 'Off'}")
    print(f"CSR_ALLOW_UNRESTRICTED_FS: {'On' if sip_int & CSR_ALLOW_UNRESTRICTED_FS else 'Off'}")
    print(f"CSR_ALLOW_TASK_FOR_PID: {'On' if sip_int & CSR_ALLOW_TASK_FOR_PID else 'Off'}")
    print(f"CSR_ALLOW_KERNEL_DEBUGGER: {'On' if sip_int & CSR_ALLOW_KERNEL_DEBUGGER else 'Off'}")
    print(f"CSR_ALLOW_APPLE_INTERNAL: {'On' if sip_int & CSR_ALLOW_APPLE_INTERNAL else 'Off'}")
    print(f"CSR_ALLOW_UNRESTRICTED_DTRACE: {'On' if sip_int & CSR_ALLOW_UNRESTRICTED_DTRACE else 'Off'}")
    print(f"CSR_ALLOW_UNRESTRICTED_NVRAM: {'On' if sip_int & CSR_ALLOW_UNRESTRICTED_NVRAM else 'Off'}")
    print(f"CSR_ALLOW_DEVICE_CONFIGURATION: {'On' if sip_int & CSR_ALLOW_DEVICE_CONFIGURATION else 'Off'}")
    print(f"CSR_ALLOW_ANY_RECOVERY_OS: {'On' if sip_int & CSR_ALLOW_ANY_RECOVERY_OS else 'Off'}")
    print(f"CSR_ALLOW_UNAPPROVED_KEXTS: {'On' if sip_int & CSR_ALLOW_UNAPPROVED_KEXTS else 'Off'}")
    print(f"CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE: {'On' if sip_int & CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE else 'Off'}")
    print(f"CSR_ALLOW_UNAUTHENTICATED_ROOT: {'On' if sip_int & CSR_ALLOW_UNAUTHENTICATED_ROOT else 'Off'}")

def main():
    sip_int = ctypes.c_uint32(0)
    result = libSystem.csr_get_active_config(ctypes.byref(sip_int))
    if result == 0:
        print_sip_flags(sip_int.value)
    else:
        print("Failed to get SIP configuration")

if __name__ == "__main__":
    main()