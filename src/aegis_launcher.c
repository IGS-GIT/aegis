#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "landlock_sandbox.h"

#ifdef WITH_BPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "aegis_shield.skel.h"
#endif

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf(stderr, "===================================================\n");
        fprintf(stderr, "Aegis Game Launcher (v0.3.0 - Landlock + eBPF)\n");
        fprintf(stderr, "Usage: %s [--save-dir <dir>] <game_executable> [args...]\n", argv[0]);
        fprintf(stderr, "Example: %s ./bin/mock_game\n", argv[0]);
        fprintf(stderr, "===================================================\n");
        return 1;
    }

    int game_arg_idx = 1;
    const char *custom_save_dir = NULL;

    if (strcmp(argv[1], "--save-dir") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: --save-dir requires a directory path.\n");
            return 1;
        }
        custom_save_dir = argv[2];
        game_arg_idx = 3;
    }

    const char *game_bin = argv[game_arg_idx];

    /* Resolve real path to the game binary to identify game directory */
    char resolved_path[PATH_MAX];
    char game_dir_buf[PATH_MAX];
    const char *game_dir = NULL;

    if (realpath(game_bin, resolved_path) != NULL) {
        strncpy(game_dir_buf, resolved_path, sizeof(game_dir_buf) - 1);
        game_dir_buf[sizeof(game_dir_buf) - 1] = '\0';
        game_dir = dirname(game_dir_buf);
    }

    /* Seal parent process as well */
    prctl(PR_SET_DUMPABLE, 0);

    printf("[ENCLAVE] Initializing enclave runner...\n");
    if (game_dir) {
        printf("[AEGIS] Game directory identified: %s (Read-Only enforcement)\n", game_dir);
    }
    if (custom_save_dir) {
        printf("[AEGIS] Dedicated save directory: %s (Read-Write permitted)\n", custom_save_dir);
    }

#ifdef WITH_BPF
    struct aegis_shield_bpf *skel = NULL;
    skel = aegis_shield_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] Warning: Failed to load eBPF LSM skeleton (requires CAP_SYS_ADMIN/CAP_BPF)\n");
    } else {
        int err = aegis_shield_bpf__attach(skel);
        if (err) {
            fprintf(stderr, "[-] Warning: Failed to attach eBPF LSM programs: %d\n", err);
        } else {
            printf("[+] eBPF LSM Shield active and attached to kernel!\n");
        }
    }
#endif

    int sync_pipe[2];
    if (pipe(sync_pipe) < 0) {
        perror("pipe");
        return 1;
    }

    pid_t child_pid = fork();
    if (child_pid < 0) {
        perror("fork");
        return 1;
    }

    if (child_pid == 0) {
        /* CHILD PROCESS (Game) */
        close(sync_pipe[1]);

        /* Wait for parent to register PID in eBPF map */
        char sync_byte;
        if (read(sync_pipe[0], &sync_byte, 1) < 0) {
            perror("read sync");
        }
        close(sync_pipe[0]);

        /* Step 1: Inject seal shim so PR_SET_DUMPABLE persists across execve */
        char shim_path[PATH_MAX] = {0};
        const char *env_shim = getenv("AEGIS_SHIM_PATH");
        if (env_shim && access(env_shim, F_OK) == 0) {
            strncpy(shim_path, env_shim, sizeof(shim_path) - 1);
        } else {
            char self_exe[PATH_MAX];
            ssize_t elen = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
            if (elen > 0) {
                self_exe[elen] = '\0';
                char *dir = dirname(self_exe);
                snprintf(shim_path, sizeof(shim_path), "%s/libseal_shim.so", dir);
            }
            if (access(shim_path, F_OK) != 0) {
                snprintf(shim_path, sizeof(shim_path), "bin/libseal_shim.so");
            }
        }

        const char *existing_preload = getenv("LD_PRELOAD");
        char combined_preload[4096];
        if (existing_preload && strlen(existing_preload) > 0) {
            snprintf(combined_preload, sizeof(combined_preload), "%s:%s", shim_path, existing_preload);
        } else {
            snprintf(combined_preload, sizeof(combined_preload), "%s", shim_path);
        }
        setenv("LD_PRELOAD", combined_preload, 1);

        /* Step 2: Apply Landlock Filesystem Isolation */
        if (apply_landlock_sandbox(game_dir, custom_save_dir) < 0) {
            fprintf(stderr, "[-] Warning: Could not enforce Landlock sandbox.\n");
        }

        printf("[AEGIS:CHILD] Process and filesystem sealed. Executing %s...\n", game_bin);
        execvp(game_bin, &argv[game_arg_idx]);

        perror("execvp");
        exit(127);
    } else {
        /* PARENT PROCESS (Launcher) */
        close(sync_pipe[0]);

        printf("[AEGIS:PARENT] Spawned child process PID: %d\n", child_pid);

#ifdef WITH_BPF
        if (skel) {
            uint32_t pid_key = (uint32_t)child_pid;
            uint8_t val = 1;
            int map_fd = bpf_map__fd(skel->maps.protected_pids);
            if (bpf_map_update_elem(map_fd, &pid_key, &val, BPF_ANY) < 0) {
                perror("bpf_map_update_elem");
            } else {
                printf("[+] Registered PID %d into eBPF shield map.\n", child_pid);
            }
        }
#endif

        char sync_byte = 1;
        if (write(sync_pipe[1], &sync_byte, 1) < 0) {
            perror("write sync");
        }
        close(sync_pipe[1]);

        int status;
        waitpid(child_pid, &status, 0);

#ifdef WITH_BPF
        if (skel) {
            aegis_shield_bpf__destroy(skel);
        }
#endif
        printf("[AEGIS:PARENT] Game process exited.\n");
    }

    return 0;
}
