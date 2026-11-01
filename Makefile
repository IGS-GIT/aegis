CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -D_GNU_SOURCE
BPF_CC ?= clang
BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_x86

BIN_DIR = bin
SRC_DIR = src
BPF_DIR = src/bpf
INC_DIR = include
LIB_DIR = $(BIN_DIR)/lib

TARGETS = $(BIN_DIR)/mock_game \
          $(BIN_DIR)/mock_cheat \
          $(BIN_DIR)/libseal_shim.so \
          $(BIN_DIR)/aegis_launcher \
          $(BIN_DIR)/test_attestation \
          $(BIN_DIR)/shield_pid \
          $(BIN_DIR)/aegisd \
          $(BIN_DIR)/libaegis.so \
          $(BIN_DIR)/libaegis.a \
          $(BIN_DIR)/anti_cheat_sample

all: $(TARGETS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Mock game binary
$(BIN_DIR)/mock_game: $(SRC_DIR)/mock_game.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@

# Mock cheat binary
$(BIN_DIR)/mock_cheat: $(SRC_DIR)/mock_cheat.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@

# Process seal shared library shim (constructor)
$(BIN_DIR)/libseal_shim.so: $(SRC_DIR)/seal_shim.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -fPIC -shared $< -o $@ -ldl

# eBPF bytecode compilation
$(BIN_DIR)/aegis_shield.bpf.o: $(BPF_DIR)/aegis_shield.bpf.c $(BPF_DIR)/vmlinux.h | $(BIN_DIR)
	$(BPF_CC) $(BPF_CFLAGS) -I$(BPF_DIR) -I/usr/include -c $< -o $@

# Generate C skeleton header from BPF object
$(SRC_DIR)/aegis_shield.skel.h: $(BIN_DIR)/aegis_shield.bpf.o
	bpftool gen skeleton $< > $@

# Aegis launcher (links with Landlock sandbox and libbpf)
$(BIN_DIR)/aegis_launcher: $(SRC_DIR)/aegis_launcher.c $(SRC_DIR)/landlock_sandbox.c $(SRC_DIR)/aegis_shield.skel.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -DWITH_BPF -I$(SRC_DIR) $(SRC_DIR)/aegis_launcher.c $(SRC_DIR)/landlock_sandbox.c -o $@ -L$(LIB_DIR) -Wl,-rpath,'$$ORIGIN/lib' -lbpf -lelf -lz

# Shield PID tool
$(BIN_DIR)/shield_pid: $(SRC_DIR)/shield_pid.c $(SRC_DIR)/aegis_shield.skel.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) $< -o $@ -L$(LIB_DIR) -Wl,-rpath,'$$ORIGIN/lib' -lbpf -lelf -lz

# Aegis Auto-Shield Daemon
$(BIN_DIR)/aegisd: $(SRC_DIR)/aegis_daemon.c $(SRC_DIR)/aegis_shield.skel.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) $< -o $@ -L$(LIB_DIR) -Wl,-rpath,'$$ORIGIN/lib' -lbpf -lelf -lz

# TPM Attestation test binary
$(BIN_DIR)/test_attestation: $(SRC_DIR)/test_attestation.c $(SRC_DIR)/tpm_attestation.c $(SRC_DIR)/tpm_attestation.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) $(SRC_DIR)/test_attestation.c $(SRC_DIR)/tpm_attestation.c -o $@ -lcrypto

# Public Shared Library (libaegis.so)
$(BIN_DIR)/libaegis.so: $(SRC_DIR)/sdk/aegis_sdk.c $(SRC_DIR)/tpm_attestation.c $(INC_DIR)/aegis.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -fPIC -shared -I$(INC_DIR) -I$(SRC_DIR) $(SRC_DIR)/sdk/aegis_sdk.c $(SRC_DIR)/tpm_attestation.c -o $@ -lcrypto

# Public Static Library (libaegis.a)
$(BIN_DIR)/libaegis.a: $(SRC_DIR)/sdk/aegis_sdk.c $(SRC_DIR)/tpm_attestation.c $(INC_DIR)/aegis.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -c -I$(INC_DIR) -I$(SRC_DIR) $(SRC_DIR)/sdk/aegis_sdk.c -o $(BIN_DIR)/aegis_sdk.o
	$(CC) $(CFLAGS) -c -I$(INC_DIR) -I$(SRC_DIR) $(SRC_DIR)/tpm_attestation.c -o $(BIN_DIR)/tpm_attestation.o
	ar rcs $@ $(BIN_DIR)/aegis_sdk.o $(BIN_DIR)/tpm_attestation.o
	rm -f $(BIN_DIR)/aegis_sdk.o $(BIN_DIR)/tpm_attestation.o

# Anti-Cheat Sample Consumer Binary
$(BIN_DIR)/anti_cheat_sample: examples/anti_cheat_sample.c $(BIN_DIR)/libaegis.so | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) $< -o $@ -L$(BIN_DIR) -Wl,-rpath,'$$ORIGIN' -laegis

clean:
	rm -rf $(BIN_DIR) $(SRC_DIR)/aegis_shield.skel.h *.log /tmp/enclave_savegame.dat /tmp/aegis_savegame.dat

.PHONY: all clean
