# Getting Started

This guide walks you through building, installing, and testing `imds-canary`.

---

## Prerequisites

- **Go**: 1.22+
- **Linux Kernel**: 5.8+ (for eBPF ring buffer and `cgroup/connect4` support)
- **Privileges**: Root or capabilities `CAP_BPF` + `CAP_NET_ADMIN` (on Linux host for eBPF attachment)
- **Local Testing**: macOS / non-root supported via `-dry-run`

---

## Installation

### From Source

```bash
git clone https://github.com/smford/imds-canary.git
cd imds-canary

# Compile eBPF wrappers and standalone Go binary
make all
```

The resulting statically linked binary is placed at `bin/imds-canary`.

---

## Running

### Production Mode (Linux Host / Root)

```bash
sudo ./bin/imds-canary \
  -port 18080 \
  -cgroup /sys/fs/cgroup \
  -role production-infra-role \
  -access-key-id "AKIA-CANARY-TOKEN-ID" \
  -secret-access-key "SECRET-CANARY-KEY"
```

### Dry-Run Mode (Testing on macOS or Non-Root)

To test the HTTP honeypot and attribution logic without kernel hooks:

```bash
./bin/imds-canary -dry-run -port 18080
```

### Diagnostic Self-Test

You can verify the entire attribution and alerting pipeline in 1 second using `-test-intercept`:

```bash
./bin/imds-canary -test-intercept
```

---

## Verifying with Automated Validation

Run the end-to-end validation script:

```bash
make validate
# or
./scripts/validate.sh
```

The script queries the honeypot, asserts that valid AWS STS credentials were returned, and verifies that the daemon recorded the matching process attribution security log.
