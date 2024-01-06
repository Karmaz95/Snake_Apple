#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    strcpy(buffer, "Hello, World!"); // Vulnerable operation
    printf("You entered: %s\n", buffer);
    return 0;
}