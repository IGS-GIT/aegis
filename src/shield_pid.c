#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "aegis_shield.skel.h"

static volatile bool keep_running = true;

static void sig_handler(int sig) {
    (void)sig;
    keep_running = false;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <PID_TO_SHIELD>\n", argv[0]);
        return 1;
    }

    uint32_t target_pid = (uint32_t)atoi(argv[1]);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("===================================================\n");
    printf("[AEGIS SHIELD] Attaching eBPF LSM Shield to PID %u\n", target_pid);
    printf("===================================================\n");

    struct aegis_shield_bpf *skel = aegis_shield_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] Failed to load eBPF LSM skeleton (Run with sudo)\n");
        return 1;
    }

    int err = aegis_shield_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to attach eBPF LSM hook: %d\n", err);
        aegis_shield_bpf__destroy(skel);
        return 1;
    }

    uint8_t val = 1;
    int map_fd = bpf_map__fd(skel->maps.protected_pids);
    if (bpf_map_update_elem(map_fd, &target_pid, &val, BPF_ANY) < 0) {
        perror("[-] bpf_map_update_elem");
        aegis_shield_bpf__destroy(skel);
        return 1;
    }

    printf("[+] SUCCESS: Kernel eBPF LSM Shield is ACTIVE for PID %u!\n", target_pid);
    printf("[+] Memory and ptrace access are now locked at ring 0.\n");
    printf("[*] Shield is running. Press Ctrl+C to detach shield.\n");
    fflush(stdout);

    while (keep_running) {
        /* Check if process is still alive */
        if (kill(target_pid, 0) < 0) {
            printf("[*] Target PID %u terminated. Detaching shield.\n", target_pid);
            break;
        }
        sleep(1);
    }

    aegis_shield_bpf__destroy(skel);
    printf("[*] Shield detached cleanly.\n");
    return 0;
}
