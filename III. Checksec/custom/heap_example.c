#include <stdio.h>
#include <stdlib.h>

int main() {
    // Allocate memory on the heap
    char *heapMemory = (char *)malloc(100 * sizeof(char));

    if (heapMemory == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    printf("Memory allocated. Press Enter to exit.\n");

    // Wait for Enter key press
    while (getchar() != '\n');

    // Free allocated memory
    free(heapMemory);

    return 0;
}

