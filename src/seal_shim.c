#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <dlfcn.h>

/*
 * 1. Constructor runs before main()
 */
__attribute__((constructor))
static void enclave_seal_init(void) {
    if (prctl(PR_SET_DUMPABLE, 0) < 0) {
        perror("[SEAL SHIM] prctl(PR_SET_DUMPABLE, 0)");
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("[SEAL SHIM] prctl(PR_SET_NO_NEW_PRIVS)");
    }
}

/*
 * 2. Function interposer: Prevent game engines (Unity / Mono / Google Breakpad)
 *    from resetting PR_SET_DUMPABLE back to 1.
 */
int prctl(int option, ...) {
    va_list args;
    va_start(args, option);
    unsigned long arg2 = va_arg(args, unsigned long);
    unsigned long arg3 = va_arg(args, unsigned long);
    unsigned long arg4 = va_arg(args, unsigned long);
    unsigned long arg5 = va_arg(args, unsigned long);
    va_end(args);

    if (option == PR_SET_DUMPABLE && arg2 != 0) {
        /* Silently block attempt to unseal process */
        return 0;
    }

    static int (*real_prctl)(int, unsigned long, unsigned long, unsigned long, unsigned long) = NULL;
    if (!real_prctl) {
        real_prctl = dlsym(RTLD_NEXT, "prctl");
        if (!real_prctl) {
            return -1;
        }
    }

    return real_prctl(option, arg2, arg3, arg4, arg5);
}
