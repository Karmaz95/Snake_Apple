#include <mach/mach.h>

int main() {
    mach_port_t port;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    return 0; // Port allocation directly interacts with kernelspace
}

