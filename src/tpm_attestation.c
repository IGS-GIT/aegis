#define _GNU_SOURCE
#include "tpm_attestation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/evp.h>

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int compute_file_sha256(const char *filepath, uint8_t output_hash[SHA256_DIGEST_LEN]) {
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        perror("fopen file for hashing");
        return -errno;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(f);
        return -ENOMEM;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(f);
        return -1;
    }

    uint8_t buffer[8192];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(f);
            return -1;
        }
    }

    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, output_hash, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(f);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    fclose(f);
    return 0;
}

static int query_tpm_pcr7(uint8_t output_digest[SHA256_DIGEST_LEN], bool *secure_boot) {
    /* Use tpm2_pcrread to inspect PCR 7 */
    FILE *fp = popen("tpm2_pcrread sha256:7 2>/dev/null", "r");
    if (!fp) {
        return -1;
    }

    char line[256];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        /* Line looks like: "  7: 0xABCD..." or "0x..." */
        char *hex_start = strstr(line, "0x");
        if (hex_start) {
            hex_start += 2;
            for (int i = 0; i < SHA256_DIGEST_LEN; i++) {
                unsigned int byte_val;
                if (sscanf(hex_start + (i * 2), "%02x", &byte_val) == 1) {
                    output_digest[i] = (uint8_t)byte_val;
                }
            }
            found = true;
            break;
        }
    }
    pclose(fp);

    if (found) {
        /* A non-zero PCR 7 indicates Secure Boot measurements were recorded */
        bool non_zero = false;
        for (int i = 0; i < SHA256_DIGEST_LEN; i++) {
            if (output_digest[i] != 0) {
                non_zero = true;
                break;
            }
        }
        *secure_boot = non_zero;
        return 0;
    }

    return -1;
}

int generate_attestation_report(const char *game_path,
                                const char *bpf_path,
                                const uint8_t nonce[TPM_NONCE_LEN],
                                AttestationReport *report)
{
    memset(report, 0, sizeof(AttestationReport));

    /* 1. Copy Server Nonce */
    memcpy(report->nonce, nonce, TPM_NONCE_LEN);

    /* 2. Measure Game Binary */
    if (compute_file_sha256(game_path, report->game_binary_hash) < 0) {
        fprintf(stderr, "[-] Failed to measure game binary: %s\n", game_path);
        return -1;
    }

    /* 3. Measure eBPF Kernel Shield */
    if (compute_file_sha256(bpf_path, report->bpf_shield_hash) < 0) {
        fprintf(stderr, "[-] Failed to measure eBPF shield object: %s\n", bpf_path);
        return -1;
    }

    /* 4. Query Hardware TPM 2.0 PCR 7 */
    if (query_tpm_pcr7(report->pcr7_digest, &report->secure_boot_enabled) == 0) {
        report->tpm_hardware_verified = true;
    } else {
        /* Fallback if user doesn't have tss permissions or TPM is busy */
        report->tpm_hardware_verified = false;
        report->secure_boot_enabled = false;
    }

    /* 5. In a production quote, the TPM chip signs the combined measurement */
    /* For prototype demonstration, compute HMAC/digest as simulated signature */
    memcpy(report->hardware_signature, report->game_binary_hash, 16);
    memcpy(report->hardware_signature + 16, report->bpf_shield_hash, 16);
    report->signature_len = 32;

    return 0;
}

bool verify_attestation_report(const AttestationReport *report,
                               const uint8_t expected_game_hash[SHA256_DIGEST_LEN],
                               const uint8_t expected_bpf_hash[SHA256_DIGEST_LEN],
                               const uint8_t expected_nonce[TPM_NONCE_LEN])
{
    /* Check 1: Nonce Match (Prevents Replay Attacks) */
    if (memcmp(report->nonce, expected_nonce, TPM_NONCE_LEN) != 0) {
        fprintf(stderr, "[-] ATTESTATION FAILED: Challenge Nonce mismatch!\n");
        return false;
    }

    /* Check 2: Game Binary Integrity (Has the game .exe/.so been modified?) */
    if (memcmp(report->game_binary_hash, expected_game_hash, SHA256_DIGEST_LEN) != 0) {
        fprintf(stderr, "[-] ATTESTATION FAILED: Game binary hash mismatch (tampered executable)!\n");
        return false;
    }

    /* Check 3: eBPF Shield Integrity (Is the genuine LSM shield active?) */
    if (memcmp(report->bpf_shield_hash, expected_bpf_hash, SHA256_DIGEST_LEN) != 0) {
        fprintf(stderr, "[-] ATTESTATION FAILED: Kernel shield bytecode modified!\n");
        return false;
    }

    return true;
}
