#!/usr/sbin/dtrace -s
#pragma D option flowindent

// Enable tracing when execve or __mac_execve syscalls are entered
syscall::execve:entry { self->tracing = 1; }
syscall::__mac_execve:entry { self->tracing = 1; }

// Disable tracing and exit when execve or __mac_execve syscalls return
syscall::execve:return { self->tracing = 0; exit(0); }
syscall::__mac_execve:return { self->tracing = 0; exit(0); }

// Print syscall arguments when tracing is active
fbt::: /self->tracing/ {
    // Print the first three arguments of the syscall in hexadecimal format
    printf("%x, %x, %x", arg0, arg1, arg2);
}