"""
trace_ioserviceopen.py

Trace IOServiceOpen calls in a target process using LLDB Python scripting to get Service Names and User Client types.

How to use:
    1. In LLDB, import this script:
        (lldb) command script import trace_ioserviceopen.py

    2. Start tracing with:
        (lldb) setup_ioserviceopen --executable_path EXE_PATH -- [args...]
       or
        (lldb) setup_ioserviceopen --pid PID

What it does:
    - Sets a breakpoint on IOServiceOpen.
    - On every call, prints:
        - PID
        - Executable path
        - IOService name
        - Type
    - Does not stop or break execution; output is continuous and non-intrusive.

"""

import lldb
import shlex

def ioserviceopen_trace_hook(frame, bp_loc, dict):
    # Get target and process objects from the current frame
    target = frame.GetThread().GetProcess().GetTarget()
    process = frame.GetThread().GetProcess()
    pid = process.GetProcessID()
    # Get the main module (executable) path
    module = target.GetModuleAtIndex(0)
    exe_path = module.GetFileSpec().fullpath or "unknown"
    # x0 holds the IOService pointer, x2 holds the type argument
    service = frame.FindRegister("x0").GetValueAsUnsigned()
    type_val = frame.FindRegister("x2").GetValueAsUnsigned()

    # Try to resolve the IOService name using IORegistryEntryGetName.
    # This only works if the symbol is available and the process is not restricted.
    name_str = f"0x{service:x}"
    try:
        # Evaluate an expression in the target to call IORegistryEntryGetName.
        # This is safe if the symbol is present and the process allows it.
        expr = (
            'char name[128] = {0}; '
            'extern int IORegistryEntryGetName(void*, char*); '
            f'IORegistryEntryGetName((void*){service}, name); '
            'name'
        )
        val = frame.EvaluateExpression(expr)
        if val.IsValid() and val.GetSummary():
            s = val.GetSummary().strip('"')
            if s and not s.startswith('0x'):
                name_str = s
    except Exception:
        # If anything fails, just show the pointer value
        pass

    print(f"\nPID: {pid}\nEXE PATH: {exe_path}\nSERVICE: {name_str}\nTYPE: {type_val}\n")
    # Returning False tells LLDB to auto-continue without stopping at the breakpoint
    return False

def setup_ioserviceopen(debugger, command, result, internal_dict):
    args = shlex.split(command)
    executable_path = None
    pid = None
    program_args = []
    i = 0
    # Parse command-line arguments for executable path, pid, and any program arguments
    while i < len(args):
        if args[i] == "--executable_path" and i + 1 < len(args):
            executable_path = args[i + 1]
            i += 2
        elif args[i] == "--pid" and i + 1 < len(args):
            pid = args[i + 1]
            i += 2
        elif args[i] == "--" and i + 1 < len(args):
            program_args = args[i + 1:]
            break
        else:
            i += 1

    if executable_path and pid:
        print("Error: Specify either --executable_path or --pid", file=result)
        return
    if not executable_path and not pid:
        print("Error: Specify --executable_path or --pid", file=result)
        return

    # Set up the target and breakpoint, and ensure auto-continue is enabled
    if executable_path:
        debugger.HandleCommand(f'target create "{executable_path}"')
        bp = debugger.GetSelectedTarget().BreakpointCreateByName("IOServiceOpen")
        bp.SetScriptCallbackFunction("trace_ioserviceopen.ioserviceopen_trace_hook")
        bp.SetAutoContinue(True)
        debugger.HandleCommand(f'process launch -- {" ".join(shlex.quote(arg) for arg in program_args)}')
    elif pid:
        debugger.HandleCommand(f'process attach --pid {pid}')
        bp = debugger.GetSelectedTarget().BreakpointCreateByName("IOServiceOpen")
        bp.SetScriptCallbackFunction("trace_ioserviceopen.ioserviceopen_trace_hook")
        bp.SetAutoContinue(True)
    debugger.HandleCommand('continue')

def __lldb_init_module(debugger, internal_dict):
    # Register the setup command with LLDB
    debugger.HandleCommand('command script add -f trace_ioserviceopen.setup_ioserviceopen setup_ioserviceopen')