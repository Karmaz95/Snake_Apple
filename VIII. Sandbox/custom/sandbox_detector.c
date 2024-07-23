// clang -o sandbox_detector sandbox_detector.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>

// Prototype for the sandbox_check function
int sandbox_check(pid_t pid, int *operation, int flags);

// Function to check if a process exists
int pid_exists(pid_t pid) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc info;
    size_t info_size = sizeof(info);

    if (sysctl(mib, 4, &info, &info_size, NULL, 0) < 0) {
        return 0; // PID does not exist
    }

    return (info_size > 0) ? 1 : 0; // Check if info_size is non-zero
}

void usage() {
    fprintf(stderr, "Usage: %s <pid>\n", getprogname());
    fprintf(stderr, "Checks if the process with the specified PID is sandboxed.\n");
    fprintf(stderr, "\n");
    exit(1);
}

int main(int argc, char **argv) {
    if (argc != 2){
        usage();
    }

    pid_t pid = atoi(argv[1]);

    // Check if the PID exists
    if (pid_exists(pid) == 0) {
        fprintf(stderr, "%d: No such process\n", pid);
        exit(2);
    }

    // Check if the process is sandboxed
    int rc = sandbox_check(pid, 0, 0);
    if (rc == 0) {
        printf("Process %d is not sandboxed.\n", pid);
    }else{
        printf("Process %d is sandboxed.\n", pid);
    }

    return 0;
}