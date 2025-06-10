#!/usr/bin/env python3
"""
dtrace_NewUserClient.py

A script to trace all kernel newUserClient calls using DTrace on macOS.
Prints the PID, full executable path, demangled kernel function name, and user call stack for each event.

Requirements:
    - Must be run as root (sudo).
    - System Integrity Protection (SIP) must be disabled for DTrace to work on macOS.
    - Tested on macOS with DTrace and c++filt available.

Usage:
    1. Make the script executable:
        chmod +x dtrace_NewUserClient.py
    2. Run with sudo:
        sudo ./dtrace_NewUserClient.py
    3. Press CTRL+C to stop tracing gracefully.

Output:
    For each newUserClient call, prints:
        - PID
        - Executable path
        - Demangled kernel function name
        - User call stack

Graceful termination is handled via signal (SIGINT/SIGTERM).
"""

import subprocess
import sys
import signal
import os
import threading

def main():
    """
    Runs dtrace to find newUserClient calls, captures the user stack,
    and formats the output to include PID, full path, the demangled
    kernel function name, and the call stack. Includes a robust signal
    handler for graceful termination.
    """
    if os.getuid() != 0:
        print("This script requires root privileges. Please run with sudo.", file=sys.stderr)
        sys.exit(1)

    dtrace_script = (
        "fbt::*NewUserClient*:entry, "
        "fbt::*newUserClient*:entry"
        "{"
        "    printf(\"DTRACE_EVENT|%d|%s|%s\\n\", pid, execname, probefunc);"
        "    ustack();"
        "    printf(\"DTRACE_END_EVENT\\n\");"
        "}"
    )

    dtrace_command = ["sudo", "dtrace", "-x", "switchrate=10hz", "-qn", dtrace_script]
    
    # Use preexec_fn=os.setsid to run dtrace in its own process group.
    # This prevents signals sent to the script from being forwarded to dtrace,
    # and vice-versa, providing better isolation.
    proc = subprocess.Popen(
        dtrace_command,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
        preexec_fn=os.setsid,
        errors="replace"  # <-- Add this argument to handle decode errors
    )

    # Use a thread-safe event to ensure the signal handler logic runs only once.
    stop_event = threading.Event()

    def signal_handler(sig, frame):
        if stop_event.is_set():
            return # Already handling signal
        stop_event.set()

        print("\nStopping dtrace...", file=sys.stderr)
        try:
            # Terminate the process group started by setsid
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                proc.kill() # Force kill if terminate fails
            except ProcessLookupError:
                pass # Process already gone
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        output_iterator = iter(proc.stdout.readline, '')
        for line in output_iterator:
            # Exit loop if the signal handler has been triggered
            if stop_event.is_set():
                break

            if not line.startswith("DTRACE_EVENT|"):
                continue
            
            parts = line.split('|', 3)
            if len(parts) != 4:
                continue
            _, pid_str, execname, func_raw = parts

            stack_trace = []
            for stack_line in output_iterator:
                if stop_event.is_set(): break
                stack_line = stack_line.strip()
                if stack_line == "DTRACE_END_EVENT": break
                stack_trace.append(stack_line)
            
            if stop_event.is_set(): break

            path = f"{execname} (process terminated before path lookup)"
            if pid_str.isdigit():
                ps_proc = subprocess.run(
                    ["/bin/ps", "-p", pid_str, "-o", "command="],
                    capture_output=True, text=True, check=False
                )
                if ps_proc.stdout.strip():
                    path = ps_proc.stdout.strip()
            
            func_clean = func_raw.split(':')[0]
            symbol_to_demangle = "_" + func_clean
            demangled_proc = subprocess.run(
                ["/usr/bin/c++filt"],
                input=symbol_to_demangle, capture_output=True, text=True, check=False
            )
            demangled_func = demangled_proc.stdout.strip()

            print(f"\nPID: {pid_str}")
            print(f"Path: {path}")
            print(f"Function: {demangled_func}")
            print("--- Call Stack---")
            for stack_line in stack_trace:
                print(stack_line)
            print("-" * 40)
            sys.stdout.flush()

    finally:
        if proc.poll() is None and not stop_event.is_set():
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)

if __name__ == "__main__":
    main()
