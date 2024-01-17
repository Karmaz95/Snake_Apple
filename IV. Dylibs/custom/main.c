//clang main.c -o $PWD/executable -L. -l1
//codesign -s IDENTITY --option=runtime -f executable
#include <stdio.h>
#include "lib1.h"

int main() {
    printf("Main program\n");
    printf("Press enter to call lib1.dylib function...\n");
    getchar();
    callLib1Function();
    printf("Press Enter to exit...\n");
    getchar();
    return 0;
}

