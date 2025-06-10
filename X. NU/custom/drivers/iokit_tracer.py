#!/usr/bin/env python
# iokit_tracer.py (v5 - Complete Data Inspection)

import lldb
import shlex
import threading
import os
import re

# --- Shared State & Locking ---
g_lock = threading.Lock()
connection_info_map = {}
pending_connections = {}

# --- Helper Functions ---
def hexdump(process, address, count):
    """Returns a formatted hexdump string for a memory region."""
    err = lldb.SBError()
    # Limit the dump to a reasonable size to avoid flooding the console
    count = min(count, 256)
    if count == 0:
        return "<empty>"
    data = process.ReadMemory(address, count, err)
    if not err.Success():
        return f"<error reading memory at {hex(address)}: {err.GetCString()}>"
    
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}: {hex_str:<48} |{ascii_str}|")
    return "\n".join(lines)

def resolve_service_name(frame, service_ptr):
    """Evaluates IORegistryEntryGetName to get the service name from a service object."""
    if not service_ptr: return "null_service"
    expr = (f'char n[128]={{0}}; extern int IORegistryEntryGetName(void*,char*); IORegistryEntryGetName((void*){service_ptr},n); n')
    val = frame.EvaluateExpression(expr)
    if val.IsValid() and val.GetSummary():
        s = val.GetSummary().strip('"')
        if s and not s.startswith('0x'): return s
    return f"0x{service_ptr:x}"

def sanitize_filename(s):
    return re.sub(r'[^A-Za-z0-9._-]', '_', s)

# --- LLDB Hook Functions ---
def ioserviceopen_hook(frame, bp_loc, internal_dict):
    """Hook at IOServiceOpen. Stores args in a pending dictionary for the thread."""
    thread = frame.GetThread()
    target = thread.GetProcess().GetTarget()
    service_ptr = frame.FindRegister("x0").GetValueAsUnsigned()
    connect_ptr_addr = frame.FindRegister("x3").GetValueAsUnsigned()
    if service_ptr and connect_ptr_addr:
        with g_lock:
            pending_connections[thread.GetThreadID()] = {
                "service_name": resolve_service_name(frame, service_ptr),
                "connect_ptr_addr": connect_ptr_addr,
                "pid": thread.GetProcess().GetProcessID(),
                "exe_path": target.GetModuleAtIndex(0).GetFileSpec().fullpath or "unknown",
                "type": frame.FindRegister("x2").GetValueAsUnsigned()
            }
    return False

corpus_dir = None
corpus_counter = 0

def ioconnectcallmethod_hook(frame, bp_loc, internal_dict):
    global corpus_counter
    thread = frame.GetThread()
    process = thread.GetProcess()
    connection = frame.FindRegister("x0").GetValueAsUnsigned()
    thread_id = thread.GetThreadID()
    
    with g_lock:
        info = connection_info_map.get(connection)
        if not info and thread_id in pending_connections:
            pending_info = pending_connections.pop(thread_id)
            err = lldb.SBError()
            handle = process.ReadUnsignedFromMemory(pending_info["connect_ptr_addr"], 4, err)
            if err.Success() and handle != 0:
                connection_info_map[handle] = pending_info
                if handle == connection: info = pending_info
    
    if info:
        # Read all argument registers
        selector = frame.FindRegister("x1").GetValueAsUnsigned()
        input_ptr = frame.FindRegister("x2").GetValueAsUnsigned()
        inputCnt = frame.FindRegister("x3").GetValueAsUnsigned()
        inputStruct_ptr = frame.FindRegister("x4").GetValueAsUnsigned()
        inputStructCnt = frame.FindRegister("x5").GetValueAsUnsigned()
        output_ptr = frame.FindRegister("x6").GetValueAsUnsigned()
        outputCnt_ptr = frame.FindRegister("x7").GetValueAsUnsigned()
        outputStruct_ptr = frame.FindRegister("x8").GetValueAsUnsigned()
        outputStructCnt_ptr = frame.FindRegister("x9").GetValueAsUnsigned()
        err = lldb.SBError()

        # --- Read output scalar count and output struct count for filename ---
        outputCnt_val = process.ReadUnsignedFromMemory(outputCnt_ptr, 4, err) if outputCnt_ptr else 0
        outputCnt_str = str(outputCnt_val) if err.Success() else "err"
        outputStructCnt_val = process.ReadUnsignedFromMemory(outputStructCnt_ptr, 8, err) if outputStructCnt_ptr else 0
        outputStructCnt_str = str(outputStructCnt_val) if err.Success() else "err"

        # --- Dump inputStruct to corpus directory if requested ---
        if corpus_dir and inputStruct_ptr and inputStructCnt > 0:
            try:
                data = process.ReadMemory(inputStruct_ptr, inputStructCnt, err)
                if err.Success():
                    service_name = sanitize_filename(info['service_name'])
                    type_val = info['type']
                    # Find the next available n for the filename
                    n = 0
                    while True:
                        fname = (
                            f"corpus_{service_name}_{type_val}_{selector}_"
                            f"{inputCnt}_{inputStructCnt}_{outputCnt_str}_{outputStructCnt_str}_{n}.bin"
                        )
                        full_path = os.path.join(corpus_dir, fname)
                        if not os.path.exists(full_path):
                            break
                        n += 1
                    with open(full_path, "wb") as f:
                        f.write(data)
                    print(f"[iokit_tracer] Dumped inputStruct ({inputStructCnt} bytes) to {full_path}")
            except Exception as e:
                print(f"[iokit_tracer] Error dumping inputStruct: {e}")

        # Read input scalars from memory
        input_scalars = []
        if input_ptr and inputCnt > 0:
            for i in range(inputCnt):
                val = process.ReadUnsignedFromMemory(input_ptr + i*8, 8, err)
                input_scalars.append(f"{hex(val)}" if err.Success() else "<read_err>")
        
        # Read output scalars (Note: This is post-call, data may not be valid yet on entry)
        # We read the *capacity* of the output buffer from the pointer.
        outputCnt_val = process.ReadUnsignedFromMemory(outputCnt_ptr, 4, err) if outputCnt_ptr else 0
        outputCnt_str = str(outputCnt_val) if err.Success() else "<read_err>"
        
        outputStructCnt_val = process.ReadUnsignedFromMemory(outputStructCnt_ptr, 8, err) if outputStructCnt_ptr else 0
        outputStructCnt_str = str(outputStructCnt_val) if err.Success() else "<read_err>"

        # Build output
        lines = [
            "----------------------------------------------------------------",
            f"PID: {info['pid']} | EXE: {info['exe_path']}",
            f"SERVICE: {info['service_name']} (Connection: {hex(connection)}) | TYPE: {info['type']}",
            f"SELECTOR: {selector} (0x{selector:x})",
            "--- INPUT ---",
            f"input Scalars ({inputCnt} values at {hex(input_ptr)}): [{', '.join(input_scalars)}]",
            f"inputStruct ({inputStructCnt} bytes at {hex(inputStruct_ptr)}):"
        ]
        lines.append(hexdump(process, inputStruct_ptr, inputStructCnt))
        lines.append("--- OUTPUT ---")
        lines.append(f"outputCnt: {outputCnt_str} (capacity pointer: {hex(outputCnt_ptr)})")
        lines.append(f"outputStructCnt: {outputStructCnt_str} (capacity pointer: {hex(outputStructCnt_ptr)})")
        lines.append("----------------------------------------------------------------\n")
        print("\n".join(lines))
        # After printing all trace info, try to get the return value from the previous frame (caller)
        result_code = None
        caller_frame = thread.GetFrameAtIndex(1) if thread.GetNumFrames() > 1 else None
        if caller_frame:
            # On macOS/ARM64, return value is in x0; on x86_64, it's rax
            reg = caller_frame.FindRegister("x0") if caller_frame.FindRegister("x0").IsValid() else caller_frame.FindRegister("rax")
            if reg and reg.IsValid():
                result_code = reg.GetValueAsUnsigned()
        # Print result code if available
        if result_code is not None:
            print(f"[iokit_tracer] IOConnectCallMethod return code: 0x{result_code:x} ({result_code})")
        else:
            print("[iokit_tracer] IOConnectCallMethod return code: <unavailable>")
    return False

def trace_iokit(debugger, command, result, internal_dict):
    """Command to attach or launch and set up the IOKit tracer."""
    global corpus_dir, corpus_counter
    args = shlex.split(command)
    pid, path, prog_args = None, None, []
    corpus_dir = None
    corpus_counter = 0
    # --- Parse -o/--out flag ---
    if "-o" in args:
        idx = args.index("-o")
        if idx + 1 < len(args):
            corpus_dir = args[idx + 1]
            del args[idx:idx+2]
    elif "--out" in args:
        idx = args.index("--out")
        if idx + 1 < len(args):
            corpus_dir = args[idx + 1]
            del args[idx:idx+2]
    if corpus_dir:
        os.makedirs(corpus_dir, exist_ok=True)
        print(f"[iokit_tracer] Will dump inputStructs to: {corpus_dir}")

    if "--pid" in args: pid = args[args.index("--pid") + 1]
    if "--executable_path" in args: path = args[args.index("--executable_path") + 1]
    if "--" in args: prog_args = args[args.index("--") + 1:]
    with g_lock: connection_info_map.clear(); pending_connections.clear()
    
    def setup_breakpoints(target):
        bp_open = target.BreakpointCreateByName("IOServiceOpen")
        bp_open.SetScriptCallbackFunction(f"{__name__}.ioserviceopen_hook")
        bp_open.SetAutoContinue(True)
        bp_call = target.BreakpointCreateByName("IOConnectCallMethod")
        bp_call.SetScriptCallbackFunction(f"{__name__}.ioconnectcallmethod_hook")
        bp_call.SetAutoContinue(True)

    if path:
        target = debugger.CreateTargetWithFileAndArch(path, lldb.LLDB_ARCH_DEFAULT)
        setup_breakpoints(target)
        err = lldb.SBError()
        target.Launch(debugger.GetListener(), prog_args, None, None, None, None, ".", 0, False, err)
        if err.Success(): print(f"Launched '{path}'. IOKit tracer is active.")
        else: result.PutCString(f"Error launching: {err.GetCString()}")
    elif pid:
        debugger.HandleCommand(f'process attach --pid {pid}')
        target = debugger.GetSelectedTarget()
        if target and target.GetProcess().IsValid():
            setup_breakpoints(target)
            print(f"Attached to PID {pid}. IOKit tracer is active.")
            debugger.HandleCommand('continue')
        else: result.PutCString(f"Error: Failed to attach to PID {pid}")
    else:
        # Try to use the currently selected target and process
        target = debugger.GetSelectedTarget()
        process = target.GetProcess() if target else None
        if target and process and process.IsValid() and process.GetState() in [lldb.eStateStopped, lldb.eStateRunning]:
            setup_breakpoints(target)
            print("Using current LLDB target/process. IOKit tracer is active.")
        else:
            result.PutCString("Error: Specify --pid <PID> or --executable_path <path>, or attach to a process first.")

def __lldb_init_module(debugger, internal_dict):
    """Registers the 'trace_iokit' command with LLDB."""
    debugger.HandleCommand(f'command script add -f {__name__}.trace_iokit trace_iokit')
    print("Loaded IOKit tracer. Use 'trace_iokit --pid <PID>' or 'trace_iokit --executable_path <path>'")
