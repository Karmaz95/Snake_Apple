#!/usr/bin/env python
import lldb
import shlex

def hexdump(process, address, count):
    """
    Generates a formatted hexdump of a memory region.
    """
    err = lldb.SBError()
    data = process.ReadMemory(address, count, err)
    if not err.Success():
        return "error reading memory"
    
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        left = " ".join(f"{b:02x}" for b in chunk[0:8])
        right = " ".join(f"{b:02x}" for b in chunk[8:]) if len(chunk) > 8 else ""
        hex_str = left + ("  " + right if right else "")
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{address + i:08x}  {hex_str:<48s}  |{ascii_str:<16s}|")
    return "\n".join(lines)

def format_row(typ, name, value):
    """
    Formats a single row for the argument summary table.
    """
    return f"{typ:<26}{name:<40}{value:>20}"

def iokit_dump(debugger, command, result, internal_dict):
    """
    Main function for the 'iokit_dump' LLDB command.
    """
    # --- Argument Parsing ---
    try:
        args = shlex.split(command)
        dump_filename = args[0] if args else None
    except Exception as e:
        result.PutCString(f"Error parsing arguments: {e}")
        result.SetStatus(1) # Use 1 for lldb.eReturnStatusFailed
        return

    # --- LLDB Object Setup with validation ---
    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        result.PutCString("Error: No valid target selected.")
        result.SetStatus(1) # Use 1 for lldb.eReturnStatusFailed
        return
        
    process = target.GetProcess()
    if not process or not process.IsValid():
        result.PutCString("Error: No valid process running.")
        result.SetStatus(1) # Use 1 for lldb.eReturnStatusFailed
        return
        
    thread = process.GetSelectedThread()
    if not thread or not thread.IsValid():
        result.PutCString("Error: No valid thread selected.")
        result.SetStatus(1) # Use 1 for lldb.eReturnStatusFailed
        return
        
    frame = thread.GetFrameAtIndex(0)
    if not frame or not frame.IsValid():
        result.PutCString("Error: Could not get the current stack frame.")
        result.SetStatus(1) # Use 1 for lldb.eReturnStatusFailed
        return

    # --- Read Registers for inputStruct ---
    inputStruct_ptr = frame.FindRegister("x4").GetValueAsUnsigned()
    inputStructCnt = frame.FindRegister("x5").GetValueAsUnsigned()

    # --- New: Dump inputStruct to a file ---
    if dump_filename:
        if not inputStruct_ptr or inputStructCnt == 0:
            result.PutCString("No inputStruct data to dump (pointer is null or size is zero).")
            result.SetStatus(0) # Use 0 for lldb.eReturnStatusSuccess
            return

        err = lldb.SBError()
        data = process.ReadMemory(inputStruct_ptr, inputStructCnt, err)

        if not err.Success():
            result.PutCString(f"Error reading memory for inputStruct at {hex(inputStruct_ptr)}: {err}")
            result.SetStatus(1) # Use 1 for lldb.eReturnStatusFailed
            return

        try:
            with open(dump_filename, 'wb') as f:
                f.write(data)
            result.PutCString(f"Successfully dumped {inputStructCnt} bytes of inputStruct to '{dump_filename}'")
            result.SetStatus(0) # Use 0 for lldb.eReturnStatusSuccess
        except IOError as e:
            result.PutCString(f"Error writing to file '{dump_filename}': {e}")
            result.SetStatus(1) # Use 1 for lldb.eReturnStatusFailed
        return

    # --- Original: Print formatted argument summary ---
    # Read remaining registers
    connection          = frame.FindRegister("x0").GetValueAsUnsigned()
    selector            = frame.FindRegister("x1").GetValueAsUnsigned()
    input_ptr           = frame.FindRegister("x2").GetValueAsUnsigned()
    inputCnt            = frame.FindRegister("x3").GetValueAsUnsigned()
    output_ptr          = frame.FindRegister("x6").GetValueAsUnsigned()
    outputCnt_ptr       = frame.FindRegister("x7").GetValueAsUnsigned()
    outputStruct_ptr    = frame.FindRegister("x8").GetValueAsUnsigned()
    outputStructCnt_ptr = frame.FindRegister("x9").GetValueAsUnsigned()

    lines = ["kern_return_t IOConnectCallMethod", "-------------------------------------"]
    rows = [
        format_row("mach_port_t", "connection:", f"{hex(connection)}"),
        format_row("uint32_t", "selector:", f"{hex(selector)}"),
        format_row("const uint64_t *", "input:", f"{hex(input_ptr)}"),
        format_row("uint32_t", "inputCnt:", f"{hex(inputCnt)}"),
        format_row("const void *", "inputStruct:", f"{hex(inputStruct_ptr)}"),
        format_row("size_t", "inputStructCnt:", f"{hex(inputStructCnt)}"),
        format_row("uint64_t *", "output:", f"{hex(output_ptr)}"),
        format_row("uint32_t *", "outputCnt:", f"{hex(outputCnt_ptr)}"),
        format_row("void *", "outputStruct:", f"{hex(outputStruct_ptr)}"),
        format_row("size_t *", "outputStructCnt:", f"{hex(outputStructCnt_ptr)}"),
    ]
    lines.extend(rows)

    # Input/Output scalars and struct hexdumps...
    if inputStruct_ptr and inputStructCnt > 0:
        lines.append("\nInput Struct Hexdump (first 32 bytes):")
        dump = hexdump(process, inputStruct_ptr, min(inputStructCnt, 32))
        lines.append(dump)
    
    # (Additional logic for other pointers as in previous script)

    result.PutCString("\n".join(lines))
    result.SetStatus(0) # Use 0 for lldb.eReturnStatusSuccess

def __lldb_init_module(debugger, internal_dict):
    """
    Registers the 'iokit_dump' command when the script is loaded in LLDB.
    """
    debugger.HandleCommand('command script add -f iokitargs.iokit_dump iokit_dump')
    print("Loaded 'iokit_dump' command.")
    print("Usage: iokit_dump [FILENAME]")
