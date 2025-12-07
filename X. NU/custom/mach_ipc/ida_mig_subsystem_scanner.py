"""
IDA Pro MIG Subsystem Scanner
Automatically identifies and labels Mach Interface Generator (MIG) subsystems
in XNU kernelcache, kext binaries and other Mach-based binaries.

Author: Karol Mazurek @karmaz95
Based on: https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py
Usage: Run from IDA Pro's script console or via File > Script file
"""

import idc
import idautils
import idaapi
import ida_bytes
import ida_name
import ida_segment
import ida_funcs


class MIGSubsystemScanner:
    """Scanner for MIG subsystem structures in Mach kernel binaries."""
    
    # Target segments where MIG subsystems are typically stored
    TARGET_SEGMENTS = [
        "__DATA:__const",
        "__CONST:__constdata", 
        "__DATA_CONST:__const",
        "__const"
    ]
    
    # MIG subsystem structure offsets (arm64)
    OFFSET_START = 0x08      # subsystem start ID (u32)
    OFFSET_END = 0x0C        # subsystem end ID (u32)
    OFFSET_RESERVED = 0x18   # reserved field (u64)
    OFFSET_ROUTINES = 0x20   # routine array start (u64)
    
    # MIG routine descriptor size
    ROUTINE_SIZE = 0x28      # 40 bytes per routine
    ROUTINE_STUB_OFFSET = 0x08  # stub_routine pointer offset
    
    def __init__(self):
        self.found_count = 0
        self.total_messages = 0
        
    def is_valid_subsystem(self, addr):
        """
        Validate potential MIG subsystem structure using heuristics.
        
        Args:
            addr: Address to check
            
        Returns:
            tuple: (is_valid, start_id, end_id) or (False, 0, 0)
        """
        # Check reserved field must be 0
        reserved = ida_bytes.get_qword(addr + self.OFFSET_RESERVED)
        if reserved != 0:
            return (False, 0, 0)
        
        # Check first routine impl must be 0 (first entry is always NULL)
        routine0_impl = ida_bytes.get_qword(addr + self.OFFSET_ROUTINES)
        if routine0_impl != 0:
            return (False, 0, 0)
        
        # Read subsystem ID range
        start_id = ida_bytes.get_dword(addr + self.OFFSET_START)
        end_id = ida_bytes.get_dword(addr + self.OFFSET_END)
        
        # Validate ID range
        num_msgs = end_id - start_id
        if start_id == 0 or num_msgs <= 0 or num_msgs >= 1024:
            return (False, 0, 0)
            
        return (True, start_id, end_id)
    
    def label_subsystem(self, addr, start_id, end_id):
        """
        Label MIG subsystem structure and its routine handlers.
        
        Args:
            addr: Address of subsystem structure
            start_id: Starting message ID
            end_id: Ending message ID
        """
        num_msgs = end_id - start_id
        subsys_name = f"MIG_subsystem_{start_id}"
        
        print(f"[+] Found {subsys_name} at {hex(addr)}")
        print(f"    Message range: {start_id} - {end_id} ({num_msgs} handlers)")
        
        # Label the subsystem structure
        ida_name.set_name(addr, subsys_name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
        idc.set_cmt(addr, f"MIG Subsystem {start_id}-{end_id}", 0)
        
        # Process each routine in the subsystem
        array_base = addr + self.OFFSET_ROUTINES
        labeled_count = 0
        
        for i in range(num_msgs):
            routine_addr = array_base + (i * self.ROUTINE_SIZE)
            stub_ptr_addr = routine_addr + self.ROUTINE_STUB_OFFSET
            stub_func_ea = ida_bytes.get_qword(stub_ptr_addr)
            msg_id = start_id + i
            
            # Skip NULL entries
            if stub_func_ea == 0 or stub_func_ea == 0xFFFFFFFFFFFFFFFF:
                continue
            
            # Verify pointer points to valid code segment
            if not ida_segment.getseg(stub_func_ea):
                continue
            
            # Create descriptive name for message handler
            handler_name = f"MIG_msg_{msg_id}_handler"
            
            # Label the handler function
            if ida_name.set_name(stub_func_ea, handler_name, ida_name.SN_NOWARN):
                labeled_count += 1
                
                # Make sure it's treated as a function
                if not ida_funcs.get_func(stub_func_ea):
                    ida_funcs.add_func(stub_func_ea)
                
                # Add comment at pointer location
                idc.set_cmt(stub_ptr_addr, f"Handler for MIG message {msg_id}", 0)
        
        print(f"    Labeled {labeled_count}/{num_msgs} handlers")
        self.total_messages += labeled_count
        self.found_count += 1
    
    def scan_segment(self, seg_ea):
        """
        Scan a single segment for MIG subsystems.
        
        Args:
            seg_ea: Segment address
        """
        seg_name = idc.get_segm_name(seg_ea)
        start = idc.get_segm_start(seg_ea)
        end = idc.get_segm_end(seg_ea)
        
        # Leave safety buffer for structure reads
        scan_end = end - self.ROUTINE_SIZE
        
        print(f"\n[*] Scanning {seg_name} ({hex(start)} - {hex(end)})")
        
        # Scan with 8-byte alignment (pointer size on arm64)
        for addr in range(start, scan_end, 8):
            is_valid, start_id, end_id = self.is_valid_subsystem(addr)
            
            if is_valid:
                self.label_subsystem(addr, start_id, end_id)
    
    def scan(self):
        """Main scanning routine - iterate all relevant segments."""
        print("=" * 70)
        print("MIG Subsystem Scanner for IDA Pro")
        print("=" * 70)
        
        # Find and scan target segments
        scanned_segments = 0
        for seg_ea in idautils.Segments():
            seg_name = idc.get_segm_name(seg_ea)
            
            if any(target in seg_name for target in self.TARGET_SEGMENTS):
                self.scan_segment(seg_ea)
                scanned_segments += 1
        
        # Print summary
        print("\n" + "=" * 70)
        print(f"Scan Complete!")
        print(f"  Segments scanned: {scanned_segments}")
        print(f"  Subsystems found: {self.found_count}")
        print(f"  Message handlers labeled: {self.total_messages}")
        print("=" * 70)


def main():
    """Entry point for the script."""
    scanner = MIGSubsystemScanner()
    scanner.scan()
    
    # Refresh IDA views to show new names
    idaapi.refresh_idaview_anyway()
    print("\n[*] IDA views refreshed. Check Functions window for MIG_msg_* handlers")


if __name__ == "__main__":
    main()