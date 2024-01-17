//clang -dynamiclib lib2.c -o $PWD/lib2.dylib
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void callLib2Function() {
    printf("Now we are in lib2.dylib.\n");
    printf("Press enter to back to executable code...\n");
    getchar();
}
