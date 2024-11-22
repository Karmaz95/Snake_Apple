#include <unistd.h>

int main() {
    const char *message = "Hello, Kernelspace!\n";
    write(1, message, 20); // Direct system call to write to stdout
    return 0;
}

