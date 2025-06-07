import ida_bytes
import ida_name
import idc

def print_methods(start_addr, count, struct_type=0):
    """
    Print details of external methods or method templates.

    Args:
        start_addr: Start address of methods array
        count: Number of entries to process
        struct_type: 0 for IOExternalMethodDispatch2022
                     1 for IOExternalMethodDispatch
                     2 for getTargetAndMethodForIndex methodTemplate
    """
    if struct_type == 0:
        struct_size = 0x28
    elif struct_type == 1:
        struct_size = 0x18
    elif struct_type == 2:
        struct_size = 0x30
    else:
        print("Unsupported struct_type.")
        return

    all_methods = []

    print("Methods:")
    print("-" * 40)

    for i in range(count):
        current_addr = start_addr + (i * struct_size)

        func_ptr = idc.get_qword(current_addr)
        func_name = ida_name.get_name(func_ptr) if func_ptr else "Unknown"

        if struct_type == 2:
            allow_async = idc.get_wide_byte(current_addr + 0x8)
            scalar_input = idc.get_wide_dword(current_addr + 0x10)
            struct_input = idc.get_wide_dword(current_addr + 0x14)
            scalar_output = idc.get_wide_dword(current_addr + 0x18)
            struct_output = idc.get_wide_dword(current_addr + 0x1C)
            print(f"Method {i}: {func_name}")
            print(f"  Async: {bool(allow_async)}")
        else:
            print(f"Method {i}: {func_name}")
            scalar_input = idc.get_wide_dword(current_addr + 8)
            struct_input = idc.get_wide_dword(current_addr + 0xC)
            scalar_output = idc.get_wide_dword(current_addr + 0x10)
            struct_output = idc.get_wide_dword(current_addr + 0x14)

            if struct_type == 0:
                allow_async = idc.get_wide_byte(current_addr + 0x18)
                entitlement_ptr = idc.get_qword(current_addr + 0x20)
                if entitlement_ptr:
                    ent_str = idc.get_strlit_contents(entitlement_ptr, -1, idc.STRTYPE_C)
                    if ent_str:
                        print(f"  Entitlement: {ent_str.decode('utf-8')}")

        all_methods.append(f"{i}: [{scalar_input}, {struct_input}, {scalar_output}, {struct_output}]")

    print("\nMethod summary (ID: [SCALAR_IN, IN_SIZE, SCALAR_OUT, OUT_SIZE]):")
    for m in all_methods:
        print(m)

# Usage in IDA:
# print_methods(0xFFFFFE000835F490, 20, 2)  # For getTargetAndMethodForIndex
# print_methods(0xFFFFFE0007DCDBD8, 15, 1)  # For old format
# print_methods(0xFFFFFE0007F647A0, 10)     # For 2022 format