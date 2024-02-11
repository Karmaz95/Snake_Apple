#include <stdio.h>

int main(int argc, char *argv[], char *envp[], char *apple[]) {
    printf("Argument count: %d\n", argc);
    
    printf("Standard arguments:\n");
    for (int i = 0; i < argc; i++) {
        printf("Argument %d: %s\n", i, argv[i]);
    }
    
    printf("Environment variables:\n");
    for (int i = 0; envp[i] != NULL; i++) {
        printf("Environment Variable %d: %s\n", i, envp[i]);
    }

    printf("Apple-specific arguments:\n");
    for (int i = 0; apple[i] != NULL; i++) {
        printf("Apple Argument %d: %s\n", i, apple[i]);
    }
    
    return 0;
}