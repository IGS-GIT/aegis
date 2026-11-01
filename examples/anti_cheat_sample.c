#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aegis.h"

int main(void) {
    printf("====================================================\n");
    printf("[SAMPLE] Aegis Multi-Player Anti-Cheat Sample\n");
    printf("====================================================\n");

    /* 1. Check if host platform supports Aegis */
    if (!aegis_is_supported()) {
        fprintf(stderr, "[-] Warning: Host OS does not have BPF LSM / Landlock enabled.\n");
    } else {
        printf("[+] Host OS verified: eBPF LSM and Landlock supported!\n");
    }

    /* 2. Query process security status */
    AegisSecurityStatus status;
    if (aegis_get_status(&status) == 0) {
        printf("\n[STATUS] Current Process Security Audit (PID %u):\n", status.protected_pid);
        printf("  - eBPF LSM Memory Shield : %s\n", status.kernel_ebpf_shield_active ? "ACTIVE" : "INACTIVE");
        printf("  - Landlock Sandboxing    : %s\n", status.landlock_filesystem_sealed ? "ACTIVE" : "INACTIVE");
        printf("  - Hardware TPM 2.0       : %s\n", status.hardware_tpm_present ? "PRESENT" : "MISSING");
        printf("  - UEFI Secure Boot       : %s\n", status.secure_boot_enforced ? "ENFORCED" : "NOT MEASURED");
    }

    /* 3. Simulate Server Challenge Nonce */
    uint8_t server_nonce[AEGIS_NONCE_LEN] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80
    };

    printf("\n[AUTHENTICATION] Requesting Hardware TPM 2.0 Attestation Quote...\n");
    AegisAttestationQuote quote;
    if (aegis_request_attestation_quote(server_nonce, &quote) == 0) {
        printf("  [+] Successfully generated hardware attestation quote!\n");
        printf("  [+] Signature bytes: %zu\n", quote.signature_len);
        printf("  [+] Token ready to transmit to Game Matchmaking Server.\n");
    } else {
        fprintf(stderr, "  [-] Failed to generate attestation quote.\n");
    }

    printf("====================================================\n");
    return 0;
}
