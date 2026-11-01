---
name: RFC Proposal
about: Propose an architecture, security, or game engine integration improvement
title: "[RFC]: "
labels: ["rfc", "enhancement"]
assignees: ""
---

### Proposal Summary
A concise description of the suggested enhancement or architectural change.

### Target Component (delete unselected options)
- [ ] eBPF LSM Memory Shield (`src/bpf/`)
- [ ] Landlock Filesystem Isolation (`src/landlock_sandbox.c`)
- [ ] TPM 2.0 Hardware Attestation Engine (`src/tpm_attestation.c`)
- [ ] Auto-Shield Daemon (`src/aegis_daemon.c`)
- [ ] Public C SDK (`include/aegis.h`, `libaegis.so`)
- [ ] SteamOS / Proton Integration Roadmap

### Motivation & Publisher / Game Use Case
Why is this change necessary? Which anti-cheat middleware or game engine
benefits from this?

### Proposed Technical Implementation
Details on the kernel hooks, syscalls, or API structures involved.
