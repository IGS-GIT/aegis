#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include "tpm_attestation.h"

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    const char *game_bin = "bin/mock_game";
    const char *bpf_bin = "bin/aegis_shield.bpf.o";

    printf("===================================================\n");
    printf("[ATTESTATION] Project Aegis - TPM 2.0 Engine\n");
    printf("===================================================\n");

    /* Step 1: Pre-compute clean reference hashes (Server side database) */
    uint8_t clean_game_hash[SHA256_DIGEST_LEN];
    uint8_t clean_bpf_hash[SHA256_DIGEST_LEN];

    if (compute_file_sha256(game_bin, clean_game_hash) < 0) {
        fprintf(stderr, "Cannot compute hash of %s. Run make first.\n", game_bin);
        return 1;
    }
    if (compute_file_sha256(bpf_bin, clean_bpf_hash) < 0) {
        fprintf(stderr, "Cannot compute hash of %s. Run make first.\n", bpf_bin);
        return 1;
    }

    printf("\n[SERVER REGISTRY] Registered Official Measurements:\n");
    print_hex("  Expected Game Hash ", clean_game_hash, SHA256_DIGEST_LEN);
    print_hex("  Expected Shield Hash", clean_bpf_hash, SHA256_DIGEST_LEN);

    /* Step 2: Anti-Cheat Server generates a random 32-byte challenge nonce */
    uint8_t server_nonce[TPM_NONCE_LEN];
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd >= 0) {
        read(urandom_fd, server_nonce, TPM_NONCE_LEN);
        close(urandom_fd);
    }
    printf("\n[SERVER] Issued Challenge Nonce for Multiplayer Matchmaking:\n");
    print_hex("  Challenge Nonce", server_nonce, TPM_NONCE_LEN);

    /* Step 3: Client generates hardware attestation report */
    printf("\n[CLIENT] Querying TPM 2.0 & computing local measurements...\n");
    AttestationReport report;
    if (generate_attestation_report(game_bin, bpf_bin, server_nonce, &report) < 0) {
        fprintf(stderr, "[-] Failed to generate client attestation report!\n");
        return 1;
    }

    if (report.tpm_hardware_verified) {
        printf("  [+] Hardware TPM 2.0 detected and queried!\n");
        print_hex("  [+] PCR 7 Digest (Secure Boot)", report.pcr7_digest, SHA256_DIGEST_LEN);
        printf("  [+] Secure Boot Measurement Status: %s\n",
               report.secure_boot_enabled ? "ACTIVE (Measured)" : "INACTIVE");
    } else {
        printf("  [i] TPM 2.0 hardware direct query skipped (requires user in tss group or root).\n");
    }

    /* Step 4: Server validates the authentic report */
    printf("\n[SERVER] Validating incoming client attestation report...\n");
    bool valid = verify_attestation_report(&report, clean_game_hash, clean_bpf_hash, server_nonce);
    if (valid) {
        printf("  [+] VERIFICATION SUCCESS: Client environment is genuine and untampered!\n");
        printf("  [+] Player admitted to multiplayer matchmaking server.\n");
    } else {
        printf("  [-] VERIFICATION REJECTED!\n");
    }

    /* Step 5: Test tampering detection (Simulate cheat modifying 1 byte of the game) */
    printf("\n--- SIMULATION: Hacker Modifies Game Executable on Disk ---\n");
    AttestationReport tampered_report = report;
    tampered_report.game_binary_hash[0] ^= 0xFF; // Corrupt hash

    printf("[SERVER] Validating tampered client report...\n");
    bool tampered_valid = verify_attestation_report(&tampered_report, clean_game_hash, clean_bpf_hash, server_nonce);
    if (!tampered_valid) {
        printf("  [+] SHIELD SUCCESS: Tampered client was caught and quarantined!\n");
    } else {
        printf("  [!] FAILURE: Tampered client was allowed in!\n");
    }
    printf("===================================================\n");

    return 0;
}
