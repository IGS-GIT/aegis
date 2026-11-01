/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EPERM 1

/* BPF Hash Map holding PIDs of protected processes */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);   /* tgid / pid */
    __type(value, u8);  /* status flags: 1 = shielded */
} protected_pids SEC(".maps");

/*
 * HOOK 1: bpf_lsm_ptrace_access_check
 *
 * In Linux, this single LSM hook protects:
 *  1. ptrace(PTRACE_ATTACH, pid, ...)
 *  2. open("/proc/<pid>/mem", ...)
 *  3. open("/proc/<pid>/maps", ...)
 *  4. process_vm_readv(pid, ...)
 *  5. process_vm_writev(pid, ...)
 *
 * Returning -EPERM here denies access even if caller has CAP_SYS_PTRACE or is UID 0 (root).
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(aegis_ptrace_access_check, struct task_struct *child, unsigned int mode)
{
    u32 target_tgid = BPF_CORE_READ(child, tgid);
    u32 target_pid = BPF_CORE_READ(child, pid);

    u8 *shielded = bpf_map_lookup_elem(&protected_pids, &target_tgid);
    if (!shielded)
        shielded = bpf_map_lookup_elem(&protected_pids, &target_pid);

    if (shielded && *shielded == 1) {
        bpf_printk("[AEGIS SHIELD] Denied memory/ptrace access to protected PID %u (tgid %u)\n", target_pid, target_tgid);
        return -EPERM;
    }

    return 0;
}

/*
 * HOOK 2: bpf_lsm_task_alloc
 *
 * Automatically inherits the shield when a protected game spawns child threads or worker processes.
 */
SEC("lsm/task_alloc")
int BPF_PROG(aegis_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
    struct task_struct *current_task = bpf_get_current_task_btf();
    if (!current_task)
        return 0;

    u32 parent_tgid = BPF_CORE_READ(current_task, tgid);
    u8 *parent_shielded = bpf_map_lookup_elem(&protected_pids, &parent_tgid);

    if (parent_shielded && *parent_shielded == 1) {
        u32 child_tgid = BPF_CORE_READ(task, tgid);
        u32 child_pid = BPF_CORE_READ(task, pid);
        u8 val = 1;
        if (child_tgid > 0)
            bpf_map_update_elem(&protected_pids, &child_tgid, &val, BPF_ANY);
        if (child_pid > 0)
            bpf_map_update_elem(&protected_pids, &child_pid, &val, BPF_ANY);
    }

    return 0;
}
