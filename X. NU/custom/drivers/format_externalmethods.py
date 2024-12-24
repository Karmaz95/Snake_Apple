from idaapi import *
import ida_bytes
import idc
import ida_name

def create_external_method_dispatch_struct():
    sid = idc.get_struc_id("IOExternalMethodDispatch2022")
    if sid != -1:
        # Structure already exists
        return sid
    
    sid = idc.add_struc(-1, "IOExternalMethodDispatch2022", 0)
    if sid == -1:
        print("Failed to create structure")
        return -1

    # Define structure members
    idc.add_struc_member(sid, "function", 0, ida_bytes.qword_flag(), -1, 8)
    idc.add_struc_member(sid, "checkScalarInputCount", 8, ida_bytes.dword_flag(), -1, 4)
    idc.add_struc_member(sid, "checkStructureInputSize", 0xC, ida_bytes.dword_flag(), -1, 4)
    idc.add_struc_member(sid, "checkScalarOutputCount", 0x10, ida_bytes.dword_flag(), -1, 4)
    idc.add_struc_member(sid, "checkStructureOutputSize", 0x14, ida_bytes.dword_flag(), -1, 4)
    idc.add_struc_member(sid, "allowAsync", 0x18, ida_bytes.byte_flag(), -1, 1)
    # Align to pointer size for checkEntitlement
    idc.add_struc_member(sid, "checkEntitlement", 0x20, ida_bytes.qword_flag(), -1, 8)
    
    return sid

def format_external_method_array(start_addr, count):
    # Create structure if it doesn't exist
    sid = create_external_method_dispatch_struct()
    if sid == -1:
        return
    
    struct_size = 0x28  # Size of IOExternalMethodDispatch2022
    
    # Create array
    for i in range(count):
        current_addr = start_addr + (i * struct_size)
        
        # Create structure instance
        idc.create_struct(current_addr, struct_size, "IOExternalMethodDispatch2022")
        
        # Get function pointer and try to get its name
        func_ptr = idc.get_qword(current_addr)
        if func_ptr != 0:
            func_name = ida_name.get_name(func_ptr)
            if func_name:
                print(f"Entry {i}: Function = {func_name}")
            else:
                print(f"Entry {i}: Function = 0x{func_ptr:x}")
        
        # Get other fields
        scalar_input = idc.get_wide_dword(current_addr + 8)
        struct_input = idc.get_wide_dword(current_addr + 0xC)
        scalar_output = idc.get_wide_dword(current_addr + 0x10)
        struct_output = idc.get_wide_dword(current_addr + 0x14)
        allow_async = idc.get_wide_byte(current_addr + 0x18)
        entitlement = idc.get_qword(current_addr + 0x20)
        
        print(f"  ScalarInput: {scalar_input}")
        print(f"  StructInput: {struct_input}")
        print(f"  ScalarOutput: {scalar_output}")
        print(f"  StructOutput: {struct_output}")
        print(f"  AllowAsync: {allow_async}")
        if entitlement != 0:
            ent_str = idc.get_strlit_contents(entitlement, -1, STRTYPE_C)
            if ent_str:
                print(f"  Entitlement: {ent_str.decode('utf-8')}")
        print("")

def main():
    if len(idc.ARGV) != 3:
        print("Usage: format_externalmethods.py <start_address> <count>")
        print("Example: format_externalmethods.py 0xFFFFFE0007E1B118 10")
        return
    
    start_addr = int(idc.ARGV[1], 16)
    count = int(idc.ARGV[2])
    
    format_external_method_array(start_addr, count)

if __name__ == '__main__':
    main()
