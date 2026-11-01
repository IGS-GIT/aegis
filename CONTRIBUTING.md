# Contributing to Project Aegis

Thank you for your interest in contributing to Project Aegis. This project is
both a working reference implementation and an active Request for Comments
(RFC) aimed at eliminating Ring 0 anti-cheat rootkits on Linux.

---

## 1. Code of Conduct & Principles

* **User Privacy First:** Aegis strictly enforces process isolation and
  integrity from the outside in. We reject proprietary rootkits, invasive host
  surveillance, and opaque background drivers.
* **Upstream Standards:** All kernel features must rely exclusively on
  upstream Linux primitives (eBPF LSM, Landlock, TPM 2.0).
* **Documentation Quality:** Due to my involvement with the GNOME Project, I 
  urge contributors to follow GNOME documentation standards with lines
  hard-wrapped at 80 characters for readability across terminals and editors.

---

## 2. Development & Building

### Prerequisites
* Clang / LLVM (for eBPF compilation)
* GCC & Make
* `bpftool`
* `libbpf-devel` (or `libbpf-dev`)
* `openssl-devel` (or `libssl-dev`)
* `libelf-devel` and `zlib-devel`

### Build Command
```bash
make clean && make -j$(nproc)
```

### Running Tests
Before submitting a pull request, ensure all 11 automated checks pass:
```bash
./test_suite.sh
```

---

## 3. Commit Guidelines

We follow the Conventional Commits specification:
* `feat(bpf): ...` for changes to the eBPF LSM shield
* `feat(landlock): ...` for Landlock sandbox modifications
* `feat(tpm): ...` for TPM 2.0 attestation engine updates
* `feat(daemon): ...` for aegisd background service changes
* `feat(sdk): ...` for public C SDK improvements
* `test: ...` for test suite additions
* `docs: ...` for documentation and whitepaper revisions
