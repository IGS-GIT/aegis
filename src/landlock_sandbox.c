#define _GNU_SOURCE
#include "landlock_sandbox.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/landlock.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

/*
 * Landlock filesystem access flags
 */
#define ACCESS_FS_RO ( \
    LANDLOCK_ACCESS_FS_EXECUTE | \
    LANDLOCK_ACCESS_FS_READ_FILE | \
    LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_RW ( \
    ACCESS_FS_RO | \
    LANDLOCK_ACCESS_FS_WRITE_FILE | \
    LANDLOCK_ACCESS_FS_MAKE_REG | \
    LANDLOCK_ACCESS_FS_MAKE_DIR | \
    LANDLOCK_ACCESS_FS_REMOVE_FILE | \
    LANDLOCK_ACCESS_FS_REMOVE_DIR | \
    LANDLOCK_ACCESS_FS_MAKE_SOCK)

static int add_path_rule(int ruleset_fd, const char *path, uint64_t access) {
    if (!path)
        return 0;

    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }

    struct landlock_path_beneath_attr path_beneath = {
        .allowed_access = access,
        .parent_fd = fd,
    };

    int ret = syscall(__NR_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
    close(fd);
    return ret;
}

int apply_landlock_sandbox(const char *game_dir, const char *writable_dir) {
    int abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        return -ENOSYS;
    }

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = ACCESS_FS_RW,
    };

    int ruleset_fd = syscall(__NR_landlock_create_ruleset, &ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        return -errno;
    }

    /* System paths */
    add_path_rule(ruleset_fd, "/usr", ACCESS_FS_RO);
    add_path_rule(ruleset_fd, "/lib", ACCESS_FS_RO);
    add_path_rule(ruleset_fd, "/lib64", ACCESS_FS_RO);
    add_path_rule(ruleset_fd, "/etc", ACCESS_FS_RO);
    add_path_rule(ruleset_fd, "/proc", ACCESS_FS_RO);
    add_path_rule(ruleset_fd, "/sys", ACCESS_FS_RO);
    add_path_rule(ruleset_fd, "/var", ACCESS_FS_RO);
    add_path_rule(ruleset_fd, "/mnt", ACCESS_FS_RO);

    /* Display, Audio, Devices */
    add_path_rule(ruleset_fd, "/dev", ACCESS_FS_RW);
    add_path_rule(ruleset_fd, "/run", ACCESS_FS_RW);
    add_path_rule(ruleset_fd, "/tmp", ACCESS_FS_RW);

    /* User Home Game Configs and Steam Libraries */
    const char *home = getenv("HOME");
    if (home) {
        char config_path[1024];
        char local_path[1024];
        snprintf(config_path, sizeof(config_path), "%s/.config", home);
        snprintf(local_path, sizeof(local_path), "%s/.local", home);
        add_path_rule(ruleset_fd, config_path, ACCESS_FS_RW);
        add_path_rule(ruleset_fd, local_path, ACCESS_FS_RW);
    }

    /* Aegis runtime working directory */
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd))) {
        add_path_rule(ruleset_fd, cwd, ACCESS_FS_RO);
    }

    /* Game directory: STRICTLY READ-ONLY + EXECUTE (Immutability guarantee) */
    if (game_dir) {
        add_path_rule(ruleset_fd, game_dir, ACCESS_FS_RO);
    }
    if (writable_dir) {
        add_path_rule(ruleset_fd, writable_dir, ACCESS_FS_RW);
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        close(ruleset_fd);
        return -errno;
    }

    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) < 0) {
        close(ruleset_fd);
        return -errno;
    }

    close(ruleset_fd);
    return 0;
}
