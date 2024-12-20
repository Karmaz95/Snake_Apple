import lldb

def set_xpc_breaks(debugger, command, result, internal_dict):
    """
    Set up tracing for XPC communication.
    This includes breakpoints for sending/receiving messages and connection creation.
    """
    target = debugger.GetSelectedTarget()
    if not target:
        result.PutCString("No target selected. Please attach to a process first.")
        return

    # List of XPC functions for setting breakpoints
    send_functions = [
        "xpc_connection_send_message",
        "xpc_connection_send_message_with_reply",
        "xpc_connection_send_message_with_reply_sync"
    ]
    recv_function = "xpc_connection_set_event_handler"
    connect_functions = [
        "xpc_connection_create",
        "xpc_connection_create_mach_service",
    ]

    # Set breakpoints for XPC connection creation
    for func in connect_functions:
        bp = target.BreakpointCreateByName(func)
        if bp.IsValid():
            result.PutCString(f"Breakpoint set on {func}")
        else:
            result.PutCString(f"Failed to set breakpoint on {func}")

    # Set breakpoints for sending functions
    for func in send_functions:
        bp = target.BreakpointCreateByName(func)
        if bp.IsValid():
            result.PutCString(f"Breakpoint set on {func}")
        else:
            result.PutCString(f"Failed to set breakpoint on {func}")

    # Set breakpoint for receiving messages
    bp_recv = target.BreakpointCreateByName(recv_function)
    if bp_recv.IsValid():
        result.PutCString(f"Breakpoint set on {recv_function}")
    else:
        result.PutCString(f"Failed to set breakpoint on {recv_function}")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f set_xpc_breaks.set_xpc_breaks set_xpc_breaks')
    print("The 'set_xpc_breaks' command has been loaded. Use 'set_xpc_breaks' to set up XPC message tracing.")
