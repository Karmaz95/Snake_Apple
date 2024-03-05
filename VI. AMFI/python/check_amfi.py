import sys
flags = {
    "AMFI_DYLD_OUTPUT_ALLOW_AT_PATH": 1,
    "AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS": 2,
    "AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE": 4,
    "AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS": 8,
    "AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS": 16,
    "AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION": 32,
    "AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING": 64,
    "AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS": 128
}
def check_flags(value):
    return [flag_name for flag_name, flag_value in flags.items() if value & flag_value]

input_value = int(sys.argv[1], 16)
set_flags = check_flags(input_value)

if set_flags:
    print("Flags set:")
    print(*set_flags, sep="\n"