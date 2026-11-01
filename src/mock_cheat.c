#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

void test_proc_mem(pid_t target_pid, uintptr_t target_addr) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", target_pid);

    printf("\n[VECTOR 1] Attempting direct read via %s ...\n", path);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("  [-] open() FAILED: %s (errno=%d)\n", strerror(errno), errno);
        printf("  [+] SHIELD SUCCESS: Access to /proc/<pid>/mem was blocked!\n");
        return;
    }

    uint32_t val = 0;
    ssize_t bytes = pread(fd, &val, sizeof(val), (off_t)target_addr);
    if (bytes < 0) {
        printf("  [-] pread() FAILED: %s (errno=%d)\n", strerror(errno), errno);
        printf("  [+] SHIELD SUCCESS: Read operation was blocked!\n");
    } else {
        printf("  [!] VULNERABLE: Successfully read memory! Value = %u\n", val);
    }
    close(fd);
}

void test_process_vm_readv(pid_t target_pid, uintptr_t target_addr) {
    printf("\n[VECTOR 2] Attempting memory read via process_vm_readv() ...\n");
    uint32_t val = 0;
    struct iovec local[1];
    struct iovec remote[1];

    local[0].iov_base = &val;
    local[0].iov_len = sizeof(val);
    remote[0].iov_base = (void *)target_addr;
    remote[0].iov_len = sizeof(val);

    ssize_t nread = process_vm_readv(target_pid, local, 1, remote, 1, 0);
    if (nread < 0) {
        printf("  [-] process_vm_readv() FAILED: %s (errno=%d)\n", strerror(errno), errno);
        printf("  [+] SHIELD SUCCESS: Cross-process VM read was blocked!\n");
    } else {
        printf("  [!] VULNERABLE: Successfully read memory! Value = %u\n", val);
    }
}

void test_ptrace(pid_t target_pid) {
    printf("\n[VECTOR 3] Attempting debugger attach via ptrace(PTRACE_ATTACH) ...\n");
    long ret = ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
    if (ret < 0) {
        printf("  [-] ptrace(PTRACE_ATTACH) FAILED: %s (errno=%d)\n", strerror(errno), errno);
        printf("  [+] SHIELD SUCCESS: ptrace attachment was blocked!\n");
    } else {
        printf("  [!] VULNERABLE: Successfully attached to process via ptrace!\n");
        waitpid(target_pid, NULL, 0);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    }
}

uintptr_t auto_discover_address(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0x400000;
    char line[256];
    uintptr_t addr = 0x400000;
    if (fgets(line, sizeof(line), f)) {
        addr = (uintptr_t)strtoull(line, NULL, 16);
    }
    fclose(f);
    return addr ? addr : 0x400000;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target_pid> [hex_memory_address]\n", argv[0]);
        fprintf(stderr, "Example: %s $(pgrep -x cs2)\n", argv[0]);
        fprintf(stderr, "Note: If hex_memory_address is omitted, the base memory mapping is auto-detected.\n");
        return 1;
    }

    pid_t target_pid = (pid_t)atoi(argv[1]);
    if (target_pid <= 0) {
        fprintf(stderr, "[-] Invalid PID: '%s'. Make sure the game is launched first!\n", argv[1]);
        return 1;
    }

    uintptr_t target_addr = 0;
    if (argc >= 3) {
        target_addr = (uintptr_t)strtoull(argv[2], NULL, 16);
    } else {
        target_addr = auto_discover_address(target_pid);
    }

    printf("===================================================\n");
    printf("[MOCK CHEAT] Targeting PID: %d at address: 0x%lx\n", target_pid, target_addr);
    printf("[MOCK CHEAT] Running as UID: %d (eUID: %d)\n", getuid(), geteuid());
    printf("===================================================\n");

    test_proc_mem(target_pid, target_addr);
    test_process_vm_readv(target_pid, target_addr);
    test_ptrace(target_pid);

    return 0;
}
