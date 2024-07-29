#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

enum sandbox_filter_type {
    SANDBOX_FILTER_NONE,
    SANDBOX_FILTER_PATH,
    SANDBOX_FILTER_GLOBAL_NAME,
    SANDBOX_FILTER_LOCAL_NAME,
    SANDBOX_FILTER_APPLEEVENT_DESTINATION,
    SANDBOX_FILTER_RIGHT_NAME,
    SANDBOX_FILTER_PREFERENCE_DOMAIN,
    SANDBOX_FILTER_KEXT_BUNDLE_ID,
    SANDBOX_FILTER_INFO_TYPE,
    SANDBOX_FILTER_NOTIFICATION,
    SANDBOX_FILTER_XPC_SERVICE_NAME = 12,
    SANDBOX_FILTER_IOKIT_CONNECTION,
};

const char* filter_type_strings[] = {
    "NONE",
    "PATH",
    "GLOBAL_NAME",
    "LOCAL_NAME",
    "APPLEEVENT_DESTINATION",
    "RIGHT_NAME",
    "PREFERENCE_DOMAIN",
    "KEXT_BUNDLE_ID",
    "INFO_TYPE",
    "NOTIFICATION",
    "XPC_SERVICE_NAME",
    "IOKIT_CONNECTION"
};

void print_filter_types() {
    printf("\nAvailable filter types:\n");
    for (size_t i = 0; i < sizeof(filter_type_strings) / sizeof(filter_type_strings[0]); i++) {
        printf("  %s\n", filter_type_strings[i]);
    }
}

int sandbox_check(pid_t, const char *operation, enum sandbox_filter_type, ...);

int pid_exists(pid_t pid) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    return (sysctl(mib, 4, &info, &info_size, NULL, 0) == 0 && info_size > 0);
}

void usage() {
    fprintf(stderr, "Usage: %s <pid> [<operation> [<filter_type> <filter_value>]]\n", getprogname());
    fprintf(stderr, "Checks if the specified process is sandboxed or if a specific operation is allowed.\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s 93298\n", getprogname());
    fprintf(stderr, "  %s 93298 \"file-read*\"\n", getprogname());
    fprintf(stderr, "  %s 93298 \"file-read*\" PATH \"/users/karmaz/.trash\"\n", getprogname());
    fprintf(stderr, "  %s 93298 \"authorization-right-obtain\" RIGHT_NAME \"system.burn\"\n", getprogname());
    print_filter_types();
    exit(1);
}

enum sandbox_filter_type get_filter_type(const char* filter_type_str) {
    for (size_t i = 0; i < sizeof(filter_type_strings) / sizeof(filter_type_strings[0]); i++) {
        if (strcmp(filter_type_str, filter_type_strings[i]) == 0) {
            return i;
        }
    }
    return SANDBOX_FILTER_NONE;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc == 4 || argc > 5) {
        usage();
    }

    pid_t pid = atoi(argv[1]);

    if (!pid_exists(pid)) {
        fprintf(stderr, "%d: No such process\n", pid);
        exit(2);
    }

    const char *operation = NULL;
    enum sandbox_filter_type filter_type = SANDBOX_FILTER_NONE;
    const char *filter_value = NULL;

    if (argc >= 3) {
        operation = argv[2];
    }

    if (argc == 5) {
        filter_type = get_filter_type(argv[3]);
        if (filter_type == SANDBOX_FILTER_NONE) {
            fprintf(stderr, "Invalid filter type: %s\n", argv[3]);
            exit(3);
        }
        filter_value = argv[4];
    }

    int rc = (argc == 2) 
        ? sandbox_check(pid, NULL, SANDBOX_FILTER_NONE)
        : sandbox_check(pid, operation, filter_type, filter_value);

    if (rc == 0) {
        printf("Operation '%s' is %s for process %d",
               (operation ? operation : "sandbox status"),
               (argc == 2 ? "not sandboxed" : "allowed"),
               pid);
    } else {
        printf("Operation '%s' is not allowed for process %d",
               (operation ? operation : "sandbox status"),
               pid);
    }

    if (argc == 5) {
        printf(" (Filter type: %s, Value: %s)", argv[3], filter_value);
    }
    printf("\n");

    return rc;
}
