#ifndef TPM_ATTESTATION_H
#define TPM_ATTESTATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define SHA256_DIGEST_LEN 32
#define TPM_NONCE_LEN     32
#define TPM_SIG_MAX_LEN   512

typedef struct {
    uint8_t game_binary_hash[SHA256_DIGEST_LEN];
    uint8_t bpf_shield_hash[SHA256_DIGEST_LEN];
    uint8_t pcr7_digest[SHA256_DIGEST_LEN];
    uint8_t nonce[TPM_NONCE_LEN];
    uint8_t hardware_signature[TPM_SIG_MAX_LEN];
    size_t  signature_len;
    bool    secure_boot_enabled;
    bool    tpm_hardware_verified;
} AttestationReport;

/**
 * Hash a file using SHA-256.
 */
int compute_file_sha256(const char *filepath, uint8_t output_hash[SHA256_DIGEST_LEN]);

/**
 * Generate a cryptographically signed TPM 2.0 attestation report for the given game.
 *
 * @param game_path   Path to the game binary.
 * @param bpf_path    Path to the compiled eBPF shield object.
 * @param nonce       Random 32-byte challenge from the game server.
 * @param report      Output report structure populated with measurements and hardware quote.
 * @return 0 on success, negative error code on failure.
 */
int generate_attestation_report(const char *game_path,
                                const char *bpf_path,
                                const uint8_t nonce[TPM_NONCE_LEN],
                                AttestationReport *report);

/**
 * Verify an attestation report (Simulates the Anti-Cheat Game Server verification).
 *
 * @param report              The report received from the client.
 * @param expected_game_hash  Known clean hash of the game binary.
 * @param expected_bpf_hash   Known clean hash of the eBPF shield.
 * @param expected_nonce      The challenge nonce previously sent to the client.
 * @return true if valid and trusted, false if rejected or tampered.
 */
bool verify_attestation_report(const AttestationReport *report,
                               const uint8_t expected_game_hash[SHA256_DIGEST_LEN],
                               const uint8_t expected_bpf_hash[SHA256_DIGEST_LEN],
                               const uint8_t expected_nonce[TPM_NONCE_LEN]);

/**
 * Helper to print a hex buffer.
 */
void print_hex(const char *label, const uint8_t *data, size_t len);

#endif /* TPM_ATTESTATION_H */
