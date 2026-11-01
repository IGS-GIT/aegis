#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "aegis_shield.skel.h"

static volatile bool g_running = true;

static void sig_handler(int sig) {
    (void)sig;
    g_running = false;
}

static int nl_connect(void) {
    int nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock < 0) {
        perror("[-] socket(PF_NETLINK)");
        return -1;
    }

    struct sockaddr_nl sa_nl;
    memset(&sa_nl, 0, sizeof(sa_nl));
    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = CN_IDX_PROC;
    sa_nl.nl_pid = getpid();

    if (bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl)) < 0) {
        perror("[-] bind(NETLINK_CONNECTOR)");
        close(nl_sock);
        return -1;
    }

    /* Send subscription message to kernel */
    struct {
        struct nlmsghdr nl_hdr;
        struct {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        } body;
    } msg;

    memset(&msg, 0, sizeof(msg));
    msg.nl_hdr.nlmsg_len = sizeof(msg);
    msg.nl_hdr.nlmsg_pid = getpid();
    msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    msg.body.cn_msg.id.idx = CN_IDX_PROC;
    msg.body.cn_msg.id.val = CN_VAL_PROC;
    msg.body.cn_msg.len = sizeof(enum proc_cn_mcast_op);
    msg.body.cn_mcast = PROC_CN_MCAST_LISTEN;

    if (send(nl_sock, &msg, sizeof(msg), 0) < 0) {
        perror("[-] send(PROC_CN_MCAST_LISTEN)");
        close(nl_sock);
        return -1;
    }

    return nl_sock;
}

static bool is_game_process(pid_t pid, char *out_name, size_t name_len) {
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);

    ssize_t len = readlink(exe_link, out_name, name_len - 1);
    if (len < 0) {
        return false;
    }
    out_name[len] = '\0';

    /* Ignore non-game steam runtime wrappers */
    if (strstr(out_name, "srt-bwrap") ||
        strstr(out_name, "pv-adverb") ||
        strstr(out_name, "reaper") ||
        strstr(out_name, "pressure-vessel") ||
        strstr(out_name, "steam-launch-wrapper")) {
        return false;
    }

    /* Match criteria: Steam games, Lutris, Heroic, Proton / Wine */
    if (strstr(out_name, "steamapps/common") != NULL ||
        strstr(out_name, "wineserver") != NULL ||
        strstr(out_name, "wine64-preloader") != NULL ||
        strstr(out_name, "wine-preloader") != NULL ||
        strstr(out_name, "Games") != NULL ||
        strstr(out_name, "games") != NULL) {
        return true;
    }

    return false;
}

static void scan_existing_games(int map_fd) {
    DIR *proc = opendir("/proc");
    if (!proc) return;

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;
        pid_t pid = (pid_t)atoi(entry->d_name);
        if (pid <= 1) continue;

        char name[512];
        if (is_game_process(pid, name, sizeof(name))) {
            uint32_t key = (uint32_t)pid;
            uint8_t val = 1;
            if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) == 0) {
                printf("[AUTO-SHIELD] *** Fortified existing running game ***\n");
                printf("  PID:  %d\n", pid);
                printf("  PATH: %s\n\n", name);
                fflush(stdout);
            }
        }
    }
    closedir(proc);
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("====================================================\n");
    printf("[AEGIS] Aegis Auto-Shield Daemon (aegisd v0.3.0)\n");
    printf("[AEGIS] Monitoring system for game launches...\n");
    printf("====================================================\n");
    fflush(stdout);

    /* Step 1: Load and Attach eBPF LSM Shield */
    struct aegis_shield_bpf *skel = aegis_shield_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] Fatal: Failed to load eBPF LSM skeleton (Run as root / sudo)\n");
        return 1;
    }

    if (aegis_shield_bpf__attach(skel) != 0) {
        fprintf(stderr, "[-] Fatal: Failed to attach eBPF LSM hooks\n");
        aegis_shield_bpf__destroy(skel);
        return 1;
    }

    int map_fd = bpf_map__fd(skel->maps.protected_pids);
    printf("[+] Kernel eBPF LSM Shield attached to Ring 0.\n");
    printf("[+] Task fork inheritance active.\n");

    /* Step 2: Connect to Netlink Process Connector */
    int nl_sock = nl_connect();
    if (nl_sock < 0) {
        fprintf(stderr, "[-] Fatal: Netlink connector failed\n");
        aegis_shield_bpf__destroy(skel);
        return 1;
    }

    printf("[+] Netlink Process Connector active (Zero-polling event monitor).\n");

    /* Step 3: Scan for games already running prior to daemon start */
    printf("[*] Scanning for already-running games...\n");
    scan_existing_games(map_fd);

    printf("[+] Ready! Monitoring for new and running games.\n\n");
    fflush(stdout);

    char buf[4096];
    while (g_running) {
        ssize_t len = recv(nl_sock, buf, sizeof(buf), 0);
        if (len < 0) {
            if (errno == EINTR) break;
            perror("[-] recv(nl_sock)");
            continue;
        }

        struct nlmsghdr *nlh;
        for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (size_t)len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
                struct cn_msg *cn_hdr = (struct cn_msg *)NLMSG_DATA(nlh);
                if (cn_hdr->id.idx == CN_IDX_PROC && cn_hdr->id.val == CN_VAL_PROC) {
                    struct proc_event *ev = (struct proc_event *)cn_hdr->data;
                    if (ev->what == PROC_EVENT_EXEC) {
                        pid_t pid = ev->event_data.exec.process_pid;
                        pid_t tgid = ev->event_data.exec.process_tgid;
                        char name[512];
                        pid_t target = tgid > 0 ? tgid : pid;
                        if (is_game_process(target, name, sizeof(name)) ||
                            (pid > 0 && is_game_process(pid, name, sizeof(name)))) {
                            uint32_t key_tgid = (uint32_t)target;
                            uint32_t key_pid = (uint32_t)pid;
                            uint8_t val = 1;
                            bpf_map_update_elem(map_fd, &key_tgid, &val, BPF_ANY);
                            if (key_pid != key_tgid && key_pid > 0) {
                                bpf_map_update_elem(map_fd, &key_pid, &val, BPF_ANY);
                            }
                            printf("[AUTO-SHIELD] *** Fortified new game process ***\n");
                            printf("  PID:  %d\n", key_tgid);
                            printf("  PATH: %s\n\n", name);
                            fflush(stdout);
                        }
                    } else if (ev->what == PROC_EVENT_EXIT) {
                        pid_t pid = ev->event_data.exit.process_pid;
                        pid_t tgid = ev->event_data.exit.process_tgid;
                        /* Only clean up when the main process group leader exits */
                        if (pid == tgid && pid > 0) {
                            uint32_t key = (uint32_t)pid;
                            bpf_map_delete_elem(map_fd, &key);
                        }
                    }
                }
            }
        }
    }

    printf("\n[AEGIS] Shutting down, detaching eBPF kernel hooks...\n");
    close(nl_sock);
    aegis_shield_bpf__destroy(skel);
    printf("[AEGIS] Clean shutdown complete.\n");
    return 0;
}
