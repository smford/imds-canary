# Getting Started

> **Get up and running with `imds-canary` in under 60 seconds.**

Whether deploying on production Amazon Linux 2023 / Ubuntu EC2 instances or experimenting locally on macOS without root, this guide walks you through installation, verification, and diagnostics.

---

## Prerequisites

| Requirement | Production Mode | Dry-Run Mode (Local Testing) |
| :--- | :--- | :--- |
| **Operating System** | Linux (Ubuntu, Debian, RHEL, Amazon Linux 2023) | macOS, Linux, BSD |
| **Linux Kernel** | 5.8+ (for eBPF ring buffer & `cgroup/connect4`) | Any |
| **Privileges** | `root` or `CAP_BPF` + `CAP_NET_ADMIN` | Non-root / Standard user |
| **Cgroup** | cgroup v2 unified hierarchy (`/sys/fs/cgroup`) | Not required |
| **Go (for source builds)** | Go 1.22+ | Go 1.22+ |

> [!NOTE]
> `imds-canary` uses pure Go and BPF CO-RE (Compile Once – Run Everywhere). **No CGo, BCC, or LLVM/Clang compiler tools are needed on host machines at runtime.**

---

## Installation

::: tabs
::: tab Prebuilt Binaries (Linux / macOS)
Download the latest statically compiled release for your architecture:

```bash
# Detect architecture and download
ARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
VERSION="0.1.0"

curl -sSL "https://github.com/smford/imds-canary/releases/download/v${VERSION}/imds-canary_${VERSION}_${OS}_${ARCH}.tar.gz" | tar -xz
sudo mv imds-canary /usr/local/bin/
imds-canary -version
```

::: tab Homebrew (macOS / Linux)
Install directly using Homebrew:

```bash
brew install smford/tap/imds-canary
imds-canary -version
```

::: tab Build from Source
Ensure Go 1.22+ is installed, then clone and compile:

```bash
git clone https://github.com/smford/imds-canary.git
cd imds-canary

# Builds static Go binary with pre-generated eBPF CO-RE bytecode
make build

# Output binary placed in bin/
./bin/imds-canary -version
```

::: tab Docker
Run the standalone container image:

```bash
# Pull and verify container
docker run --rm ghcr.io/smford/imds-canary:v0.1.0 -version
```
:::

---

## Verifying the Daemon

### 1. One-Second Diagnostic Self-Test

You can verify the entire attribution, formatting, and containment pipeline without sending any network traffic using the built-in diagnostic test:

```bash
imds-canary -test-intercept
```

**Expected Output:**
```
imds-canary 0.1.0 (commit: 2713cf6, date: 2026-10-24T01:45:00Z)
Copyright (c) 2026 smford
Licensed under the MIT License

2026/10/24 02:40:00 [TEST] Running mock interception event through attribution engine...
2026/10/24 02:40:00 [ALERT] IMDS query intercepted:
  PID: 4912
  Comm: curl
  Path: /usr/bin/curl
  Args: ["curl", "-s", "http://169.254.169.254/latest/meta-data/"]
  User: www-data (UID 33, GID 33)
  Working Dir: /var/www/vulnerable-app
  Parent Tree: systemd (1) -> gunicorn (4102) -> python3 (4890) -> curl (4912)
  Canary Token ID: canary-tripwire-01
2026/10/24 02:40:00 [TEST] Self-test completed successfully. All attribution pipelines operational.
```

---

### 2. Dry-Run Mode (macOS & Non-Root Testing)

Dry-run mode starts the internal HTTP honeypot on loopback without attaching eBPF kernel hooks. This is perfect for verifying honeypot responses, canary token vending, and process allowlists:

```bash
# Start honeypot on port 18080
imds-canary -dry-run -port 18080 -role staging-app-role
```

In a second terminal, query the honeypot:

```bash
# 1. Fetch AWS STS Security Credentials
curl -s http://127.0.0.1:18080/latest/meta-data/iam/security-credentials/staging-app-role | jq .

# 2. Test IMDSv2 Token Flow
TOKEN=$(curl -s -X PUT "http://127.0.0.1:18080/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://127.0.0.1:18080/latest/meta-data/instance-id
```

---

### 3. Production Deployment (Linux Host with eBPF)

To attach the kernel hook to all processes on the host:

```bash
sudo imds-canary \
  -port 18080 \
  -cgroup /sys/fs/cgroup \
  -role production-infra-role \
  -access-key-id "AKIA-CANARY-TOKEN-ID" \
  -secret-access-key "SECRET-CANARY-KEY" \
  -containment sigkill \
  -webhook-url "https://hooks.slack.com/services/T00/B00/X00"
```

> [!IMPORTANT]
> When `-containment sigkill` is enabled, any process not explicitly on the allowlist that initiates a connection to `169.254.169.254` is **immediately terminated** with `SIGKILL`. For initial deployments, start with `-containment monitor` to audit traffic without killing processes.

---

## Automated Validation Suite

The repository includes an automated end-to-end validation test script:

```bash
make validate
# or
bash scripts/validate.sh
```

This script:
1. Compiles the binary from source.
2. Launches `imds-canary` in a sandboxed daemon process.
3. Tests IMDSv1 and IMDSv2 metadata retrieval, instance ID lookups, and security credential vending.
4. Asserts that the daemon emitted formatted JSON security logs.
5. Verifies Prometheus `/metrics` exposition and `/healthz` liveliness.

---

## Next Steps

* [**Worked Tutorials**](worked-examples.md): Try out full simulations including SSRF defense and Slack alerting.
* [**Architecture & eBPF**](architecture.md): Learn how the kernel hook rewrites TCP connections.
* [**Configuration Reference**](configuration.md): Browse all available CLI flags and environment variables.
