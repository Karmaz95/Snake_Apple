#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

// Constructor
__attribute__((constructor)) void crimson_constructor() {
    syslog(LOG_ERR, "[+] crimson_constructor called\n");
    printf("[+] crimson_constructor called\n");
}

// Destructor
__attribute__((destructor)) void crimson_destructor() {
    syslog(LOG_ERR, "[+] crimson_destructor called\n");
    printf("[+] crimson_destructor called\n");
}
