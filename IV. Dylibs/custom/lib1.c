//clang -dynamiclib lib1.c -o $PWD/lib1.dylib -L. -l2
#include <stdio.h>
#include "lib1.h"
#include "lib2.h"

void callLib1Function() {
    printf("Now, wer are in lib1.dylib code.\n");
    printf("Press enter to enter lib2.dylib function\n");
    getchar();
    callLib2Function();
}
