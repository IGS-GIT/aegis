# Project Aegis (`aegis`)

Hardware-Attested eBPF LSM Process Integrity & Memory Shield for Linux Gaming.

---

## 1. Overview

Project Aegis provides an open-source, non-invasive process integrity runtime
for native and Proton games on Linux.

By combining modern, upstream Linux kernel security primitives (**eBPF LSM**,
**Landlock**, and **TPM 2.0 Hardware Attestation**), Aegis mathematically
eliminates external process memory inspection and asset tampering without
requiring proprietary, invasive Windows-style Ring 0 rootkits.

---

## 2. High-Level Architecture

```
+-------------------------------------------------------------+
|                      ANTI-CHEAT CLOUD                       |
|           (Validates TPM Quote & Boot Integrity)            |
+------------------------------+------------------------------+
                               | Remote Attestation Handshake
+------------------------------+------------------------------+
|                         AEGIS HOST                          |
|                                                             |
|   [ Game Process / Proton ] <-- Automatic Netlink Detection |
|        |                                                    |
|        | (Locked by Landlock + prctl dumpable=0)            |
|   [ eBPF LSM Shield ] <-- Ring 0 Hook Enforcement           |
|        | (Denies ptrace, /proc/pid/mem, process_vm_readv)   |
|        | (Inherits to child threads & processes)            |
|   [ TPM 2.0 Module ] <-- Hardware Signing & PCR Measurement |
+-------------------------------------------------------------+
```

---

## 3. Core Components

* **`bin/aegisd`:** Zero-polling background daemon using Linux Netlink Process
  Connectors (`cn_proc`) to auto-shield games as they spawn.
* **`bin/aegis_shield.bpf.o`:** Kernel LSM hook (`bpf_lsm_ptrace_access_check`)
  that intercepts and denies external memory access requests.
* **`bin/libseal_shim.so`:** Preloaded constructor ensuring `PR_SET_DUMPABLE=0`
  persists across `execve()` transitions.
* **`bin/libaegis.so` / `include/aegis.h`:** Public C SDK providing runtime
  status queries and TPM 2.0 cryptographic quote generation.
* **`bin/aegis_launcher`:** Standalone wrapper applying Landlock filesystem
  immutability and process sealing before game execution.
* **`systemd/aegisd.service`:** Systemd unit for persistent background launch.

---

## 4. Quick Start

### Build All Binaries
```bash
make clean && make -j$(nproc)
```

### Run the Automated 11-Step Test Suite
```bash
./test_suite.sh
```

### Start the Auto-Shield Daemon
```bash
sudo ./bin/aegisd
```

### Probe a Running Game PID
```bash
./bin/mock_cheat $(pgrep -x cs2) (cs2 is used here as an example)
```

---

## 5. Live Validations

* **Counter-Strike 2 (Native Vulkan, Valve Anti-Cheat):**
  Auto-shielded in `SteamLinuxRuntime_sniper`. Probed via `mock_cheat`:
  `/proc/<pid>/mem`, `process_vm_readv`, and `ptrace` were all denied.
* **Brawlhalla (Windows / Proton Experimental):**
  Verified full memory vector denial across Wine/Proton PE translation.
* **RimWorld (Native Linux / Unity Engine):**
  Defeated Google Breakpad inline assembly dumpable overrides in Ring 0.

---

## 6. Documentation

See [docs/WHITEPAPER.md](docs/WHITEPAPER.md) for the complete Request for
Comments (RFC) whitepaper, threat model, and Valve integration roadmap.
