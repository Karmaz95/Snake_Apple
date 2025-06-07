"""
IDA script to format and analyze IOExternalMethodDispatch structures in iOS kernelcache.
Supports both IOExternalMethodDispatch (0x18 bytes) and IOExternalMethodDispatch2022 (0x28 bytes) formats.

Usage in IDA Python console:
    format_external_method_array(0xFFFFFE0007DCDBD8, 16, 1)  # For old format
    format_external_method_array(0xFFFFFE0007DCDBD8, 16)     # For 2022 format

Structure formats:
    IOExternalMethodDispatch (0x18):
        0x00 - function (ptr)
        0x08 - checkScalarInputCount
        0x0C - checkStructureInputSize
        0x10 - checkScalarOutputCount
        0x14 - checkStructureOutputSize

    IOExternalMethodDispatch2022 (0x28):
        [all fields from IOExternalMethodDispatch]
        0x18 - allowAsync
        0x20 - checkEntitlement (ptr)
"""

from idaapi import *
import ida_bytes
import idc
import ida_name

def create_external_method_dispatch_struct(struct_type=0):
    """
    Creates IDA structure for IOExternalMethodDispatch.
    
    Args:
        struct_type: 0 for IOExternalMethodDispatch2022 (0x28 bytes)
                    1 for IOExternalMethodDispatch (0x18 bytes)
    Returns:
        Structure ID or -1 on failure
    """
    struct_name = f"IOExternalMethodDispatch{2022 if struct_type == 0 else ''}"
    sid = idc.get_struc_id(struct_name)
    if sid != -1:
        return sid
    
    sid = idc.add_struc(-1, struct_name, 0)
    if sid == -1:
        print("Failed to create structure")
        return -1

    # Common fields for both types
    idc.add_struc_member(sid, "function", 0, ida_bytes.qword_flag(), -1, 8)
    idc.add_struc_member(sid, "checkScalarInputCount", 8, ida_bytes.dword_flag(), -1, 4)
    idc.add_struc_member(sid, "checkStructureInputSize", 0xC, ida_bytes.dword_flag(), -1, 4)
    idc.add_struc_member(sid, "checkScalarOutputCount", 0x10, ida_bytes.dword_flag(), -1, 4)
    idc.add_struc_member(sid, "checkStructureOutputSize", 0x14, ida_bytes.dword_flag(), -1, 4)

    if struct_type == 0:
        # Type 0 (2022) specific fields
        idc.add_struc_member(sid, "allowAsync", 0x18, ida_bytes.byte_flag(), -1, 1)
        # Align to pointer size for checkEntitlement
        idc.add_struc_member(sid, "checkEntitlement", 0x20, ida_bytes.qword_flag(), -1, 8)
    
    return sid

def format_external_method_array(start_addr, count, struct_type=0):
    """
    Formats and analyzes an array of IOExternalMethodDispatch structures.
    
    Args:
        start_addr: Start address of the methods array
        count: Number of entries to process
        struct_type: 0 for IOExternalMethodDispatch2022 (default)
                    1 for IOExternalMethodDispatch
    """
    sid = create_external_method_dispatch_struct(struct_type)
    if sid == -1:
        return
    
    struct_size = 0x28 if struct_type == 0 else 0x18
    
    for i in range(count):
        current_addr = start_addr + (i * struct_size)
        
        # Create structure instance
        idc.create_struct(current_addr, struct_size, f"IOExternalMethodDispatch{2022 if struct_type == 0 else ''}")

        # Get function pointer and try to get its name
        func_ptr = idc.get_qword(current_addr)
        if func_ptr != 0:
            func_name = ida_name.get_name(func_ptr)
            if func_name:
                print(f"Entry {i}: Function = {func_name}")
            else:
                print(f"Entry {i}: Function = 0x{func_ptr:x}")
        
        # Get common fields
        scalar_input = idc.get_wide_dword(current_addr + 8)
        struct_input = idc.get_wide_dword(current_addr + 0xC)
        scalar_output = idc.get_wide_dword(current_addr + 0x10)
        struct_output = idc.get_wide_dword(current_addr + 0x14)
        
        print(f"  ScalarInput: {scalar_input}")
        print(f"  StructInput: {struct_input}")
        print(f"  ScalarOutput: {scalar_output}")
        print(f"  StructOutput: {struct_output}")
        
        if struct_type == 0:
            # Type 0 (2022) specific fields
            allow_async = idc.get_wide_byte(current_addr + 0x18)
            entitlement = idc.get_qword(current_addr + 0x20)
            
            print(f"  AllowAsync: {allow_async}")
            if entitlement != 0:
                ent_str = idc.get_strlit_contents(entitlement, -1, STRTYPE_C)
                if ent_str:
                    print(f"  Entitlement: {ent_str.decode('utf-8')}")
        print("")

def main():
    if len(idc.ARGV) < 3:
        print("Usage: format_externalmethods.py <start_address> <count> [type]")
        print("In IDA: format_external_method_array(0xFFFFFE0007DCDBD8, 16, 1)")
        print("Type: 0 = IOExternalMethodDispatch2022 (0x28 bytes)")
        print("      1 = IOExternalMethodDispatch (0x18 bytes)")
        return
    
    start_addr = int(idc.ARGV[1], 16)
    count = int(idc.ARGV[2])
    struct_type = int(idc.ARGV[3]) if len(idc.ARGV) > 3 else 0
    
    format_external_method_array(start_addr, count, struct_type)

if __name__ == '__main__':
    main()


# format_external_method_array(0xFFFFFE0007F647A0, 10)
# format_external_method_array(0xFFFFFE0007DCDBD8, 15, 1)