/* SPDX-License-Identifier: MIT */
/*
 * Project Aegis - Public Client & Anti-Cheat SDK
 *
 * Copyright (c) 2026 John Cardullo
 *
 * This header defines the public C API for game engines, multiplayer matchmaking
 * clients, and anti-cheat runtimes (Easy Anti-Cheat, BattlEye, Valve Anti-Cheat)
 * to verify kernel process integrity and generate hardware TPM 2.0 attestation quotes.
 */

#ifndef AEGIS_H
#define AEGIS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AEGIS_HASH_LEN   32
#define AEGIS_NONCE_LEN  32
#define AEGIS_SIG_LEN    512

/* Compatibility aliases */
#define ENCLAVE_HASH_LEN  AEGIS_HASH_LEN
#define ENCLAVE_NONCE_LEN AEGIS_NONCE_LEN
#define ENCLAVE_SIG_LEN   AEGIS_SIG_LEN

/**
 * Status flags detailing active security layers on the host system.
 */
typedef struct {
    bool kernel_ebpf_shield_active;  /* Ring 0 memory protection (bpf_lsm) */
    bool landlock_filesystem_sealed; /* Process filesystem sandboxed */
    bool secure_boot_enforced;       /* UEFI Secure Boot measured in PCR 7 */
    bool hardware_tpm_present;       /* Physical TPM 2.0 silicon verified */
    uint32_t protected_pid;          /* Process ID currently shielded */
} AegisSecurityStatus;

typedef AegisSecurityStatus EnclaveSecurityStatus;

/**
 * Cryptographic hardware quote generated for server-side verification.
 */
typedef struct {
    uint8_t game_binary_hash[AEGIS_HASH_LEN];   /* SHA-256 of the running game */
    uint8_t shield_module_hash[AEGIS_HASH_LEN]; /* SHA-256 of kernel eBPF module */
    uint8_t pcr7_digest[AEGIS_HASH_LEN];        /* TPM 2.0 PCR 7 (Secure Boot state) */
    uint8_t nonce[AEGIS_NONCE_LEN];             /* Echoed server challenge nonce */
    uint8_t hardware_signature[AEGIS_SIG_LEN];  /* TPM hardware-signed payload */
    size_t  signature_len;
} AegisAttestationQuote;

typedef AegisAttestationQuote EnclaveAttestationQuote;

/**
 * Check if the host operating system supports Aegis security primitives.
 *
 * @return true if eBPF LSM and Landlock are available, false otherwise.
 */
bool aegis_is_supported(void);

/**
 * Query the security status of the calling process.
 *
 * @param status Output structure populated with current security metrics.
 * @return 0 on success, negative error code on failure.
 */
int aegis_get_status(AegisSecurityStatus *status);

/**
 * Request a hardware-attested cryptographic quote from the system's TPM 2.0 chip.
 * This function should be called during multiplayer authentication handshakes.
 *
 * @param server_nonce  32-byte cryptographic random nonce issued by the game server.
 * @param out_quote     Output quote structure populated with measurements and signature.
 * @return 0 on success, negative error code on failure.
 */
int aegis_request_attestation_quote(const uint8_t server_nonce[AEGIS_NONCE_LEN],
                                    AegisAttestationQuote *out_quote);

/**
 * Server-Side Verification Helper:
 * Validates an incoming client attestation quote against known clean measurements.
 *
 * @param quote               The quote received from the game client.
 * @param expected_game_hash  Official SHA-256 hash of the game binary release.
 * @param expected_bpf_hash   Official SHA-256 hash of the approved Aegis eBPF shield.
 * @param expected_nonce      The 32-byte challenge nonce issued to this client.
 * @return true if authentic and untampered, false if rejected or compromised.
 */
bool aegis_verify_quote(const AegisAttestationQuote *quote,
                        const uint8_t expected_game_hash[AEGIS_HASH_LEN],
                        const uint8_t expected_bpf_hash[AEGIS_HASH_LEN],
                        const uint8_t expected_nonce[AEGIS_NONCE_LEN]);

/* Backwards-compatibility aliases */
#define enclave_is_supported             aegis_is_supported
#define enclave_get_status                aegis_get_status
#define enclave_request_attestation_quote aegis_request_attestation_quote
#define enclave_verify_quote              aegis_verify_quote

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_H */
