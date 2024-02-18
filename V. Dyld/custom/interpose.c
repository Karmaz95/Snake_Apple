// clang -dynamiclib -o libinterpose.dylib interpose.c
#include <stdio.h>

// Define the interpose macro
#define DYLD_INTERPOSE(_replacement,_replacee) \
   __attribute__((used)) static struct { \
	   const void* replacement; \
	   const void* replacee; \
   } \
   _interpose_##_replacee \
            __attribute__ ((section ("__DATA,__interpose,interposing"))) = { \
		    (const void*)(unsigned long)&_replacement, \
		    (const void*)(unsigned long)&_replacee };

// Define the replacement function
int my_printf(const char *format, ...) {
    int ret = printf("Hello from my_printf!\n");
    return ret;
}

// Apply the interposing macro to replace printf with my_printf
DYLD_INTERPOSE(my_printf, printf)
