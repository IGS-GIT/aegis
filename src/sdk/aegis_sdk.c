#define _GNU_SOURCE
#include "aegis.h"
#include "tpm_attestation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif

bool aegis_is_supported(void) {
    /* 1. Check LSM BPF presence in kernel */
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) return false;

    char lsm_list[512];
    bool has_bpf = false;
    bool has_landlock = false;

    if (fgets(lsm_list, sizeof(lsm_list), f)) {
        if (strstr(lsm_list, "bpf")) has_bpf = true;
        if (strstr(lsm_list, "landlock")) has_landlock = true;
    }
    fclose(f);

    return (has_bpf && has_landlock);
}

int aegis_get_status(AegisSecurityStatus *status) {
    if (!status) return -EINVAL;
    memset(status, 0, sizeof(AegisSecurityStatus));

    status->protected_pid = (uint32_t)getpid();

    /* 1. Check dumpable status (PR_GET_DUMPABLE) */
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    status->kernel_ebpf_shield_active = (dumpable == 0);

    /* 2. Check Landlock availability */
    int abi = syscall(__NR_landlock_create_ruleset, NULL, 0, (1 << 0));
    status->landlock_filesystem_sealed = (abi >= 1);

    /* 3. Check TPM presence */
    status->hardware_tpm_present = (access("/dev/tpmrm0", F_OK) == 0);

    /* 4. Check Secure Boot (PCR 7 query) */
    bool secure_boot = false;
    FILE *fp = popen("tpm2_pcrread sha256:7 2>/dev/null", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            secure_boot = (strstr(line, "0x") != NULL);
        }
        pclose(fp);
    }
    status->secure_boot_enforced = secure_boot;

    return 0;
}

int aegis_request_attestation_quote(const uint8_t server_nonce[AEGIS_NONCE_LEN],
                                    AegisAttestationQuote *out_quote)
{
    if (!server_nonce || !out_quote) return -EINVAL;
    memset(out_quote, 0, sizeof(AegisAttestationQuote));

    /* Resolve path of calling binary */
    char exe_path[1024];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len < 0) {
        return -errno;
    }
    exe_path[len] = '\0';

    /* Locate eBPF shield object dynamically */
    char bpf_path[1024] = {0};
    const char *env_bpf = getenv("AEGIS_BPF_PATH");
    if (env_bpf && access(env_bpf, F_OK) == 0) {
        strncpy(bpf_path, env_bpf, sizeof(bpf_path) - 1);
    } else {
        char *dir = dirname(strdup(exe_path));
        snprintf(bpf_path, sizeof(bpf_path), "%s/aegis_shield.bpf.o", dir);
        if (access(bpf_path, F_OK) != 0) {
            snprintf(bpf_path, sizeof(bpf_path), "bin/aegis_shield.bpf.o");
        }
        free(dir);
    }

    AttestationReport report;
    if (generate_attestation_report(exe_path, bpf_path, server_nonce, &report) < 0) {
        return -1;
    }

    memcpy(out_quote->game_binary_hash, report.game_binary_hash, AEGIS_HASH_LEN);
    memcpy(out_quote->shield_module_hash, report.bpf_shield_hash, AEGIS_HASH_LEN);
    memcpy(out_quote->pcr7_digest, report.pcr7_digest, AEGIS_HASH_LEN);
    memcpy(out_quote->nonce, report.nonce, AEGIS_NONCE_LEN);
    memcpy(out_quote->hardware_signature, report.hardware_signature, report.signature_len);
    out_quote->signature_len = report.signature_len;

    return 0;
}

bool aegis_verify_quote(const AegisAttestationQuote *quote,
                        const uint8_t expected_game_hash[AEGIS_HASH_LEN],
                        const uint8_t expected_bpf_hash[AEGIS_HASH_LEN],
                        const uint8_t expected_nonce[AEGIS_NONCE_LEN])
{
    if (!quote || !expected_game_hash || !expected_bpf_hash || !expected_nonce) {
        return false;
    }

    /* 1. Validate Nonce Anti-Replay */
    if (memcmp(quote->nonce, expected_nonce, AEGIS_NONCE_LEN) != 0) {
        return false;
    }

    /* 2. Validate Game Binary Hash */
    if (memcmp(quote->game_binary_hash, expected_game_hash, AEGIS_HASH_LEN) != 0) {
        return false;
    }

    /* 3. Validate Kernel eBPF Shield Hash */
    if (memcmp(quote->shield_module_hash, expected_bpf_hash, AEGIS_HASH_LEN) != 0) {
        return false;
    }

    return true;
}
