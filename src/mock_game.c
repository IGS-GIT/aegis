#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

volatile uint32_t g_player_health = 100;
volatile uint32_t g_player_score = 9999;

void test_filesystem_sandbox(const char *self_path) {
    printf("\n--- Running Enclave Filesystem Integrity Checks ---\n");

    /* TEST 1: Attempt to write to self / game directory (Asset Tampering Test) */
    printf("[FS TEST 1] Attempting to open own binary (%s) in WRITE mode...\n", self_path);
    int fd_self = open(self_path, O_RDWR);
    if (fd_self < 0) {
        printf("  [-] open(O_RDWR) FAILED: %s (errno=%d)\n", strerror(errno), errno);
        printf("  [+] SUCCESS: Binary and assets are IMMUTABLE (cannot be modified by cheats)!\n");
    } else {
        printf("  [!] VULNERABLE: Binary is writable by running process!\n");
        close(fd_self);
    }

    /* TEST 1B: Attempt to drop an unauthorized DLL or cheat script into game folder */
    char cheat_dll_path[1024];
    snprintf(cheat_dll_path, sizeof(cheat_dll_path), "%s_injected_mod.dll", self_path);
    printf("\n[FS TEST 1B] Attempting to drop rogue DLL into game dir (%s)...\n", cheat_dll_path);
    int fd_mod = open(cheat_dll_path, O_CREAT | O_WRONLY, 0755);
    if (fd_mod < 0) {
        printf("  [-] open(O_CREAT) FAILED: %s (errno=%d)\n", strerror(errno), errno);
        printf("  [+] SUCCESS: Landlock prevented dropping unauthorized libraries into game folder!\n");
    } else {
        printf("  [!] VULNERABLE: Cheat was able to drop a new file into game folder!\n");
        unlink(cheat_dll_path);
        close(fd_mod);
    }

    /* TEST 2: Attempt to read outside host files (Host Privacy / Snooping Test) */
    const char *sensitive_file = (getuid() == 0) ? "/root/.bashrc" : "/etc/shadow";
    printf("\n[FS TEST 2] Attempting to access sensitive host file (%s)...\n", sensitive_file);
    int fd_priv = open(sensitive_file, O_RDONLY);
    if (fd_priv < 0) {
        printf("  [-] open() FAILED: %s (errno=%d)\n", strerror(errno), errno);
        printf("  [+] SUCCESS: Host system files are invisible to game enclave!\n");
    } else {
        printf("  [!] VULNERABLE: Game has access to sensitive host files!\n");
        close(fd_priv);
    }

    /* TEST 3: Writable save game test */
    const char *save_file = "/tmp/enclave_savegame.dat";
    printf("\n[FS TEST 3] Attempting to write save game state to %s...\n", save_file);
    int fd_save = open(save_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd_save >= 0) {
        const char *data = "PLAYER_SAVE_DATA_OK\n";
        write(fd_save, data, strlen(data));
        close(fd_save);
        printf("  [+] SUCCESS: Writable save directory functions normally.\n");
    } else {
        printf("  [-] FAILED to write save file: %s (errno=%d)\n", strerror(errno), errno);
    }
    printf("---------------------------------------------------\n\n");
}

int main(int argc, char *argv[]) {
    (void)argc;
    pid_t pid = getpid();

    printf("===================================================\n");
    printf("[MOCK GAME] Started successfully!\n");
    printf("[MOCK GAME] Process ID (PID): %d\n", pid);
    printf("[MOCK GAME] Address of g_player_health: %p\n", (void *)&g_player_health);
    printf("[MOCK GAME] Address of g_player_score:  %p\n", (void *)&g_player_score);
    printf("===================================================\n");
    fflush(stdout);

    /* Run filesystem isolation tests */
    test_filesystem_sandbox(argv[0]);
    fflush(stdout);

    if (argc > 1 && strcmp(argv[1], "--test-and-exit") == 0) {
        printf("[MOCK GAME] Integrity checks completed. Exiting.\n");
        return 0;
    }

    int tick = 0;
    while (1) {
        printf("[MOCK GAME tick %d] Health: %u | Score: %u\n", tick++, g_player_health, g_player_score);
        fflush(stdout);
        sleep(2);
    }

    return 0;
}
