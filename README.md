# imds-canary

`imds-canary` is a host security daemon written in Go that uses an eBPF socket hook to intercept processes attempting to query the AWS link-local Instance Metadata Service (IMDS: `169.254.169.254:80`).

The daemon transparently redirects outbound connections to a local Go HTTP honeypot (`127.0.0.1:18080`), resolves the calling process tree (including executable path, command-line arguments, working directory, and ancestor chain) via host `/proc`, and vends trackable AWS Canary tokens while emitting structured security alerts.

---

## Architecture & How It Works

```
                     ┌────────────────────────────────────────┐
                     │   Rogue Process (e.g., curl, python)   │
                     └──────────────────┬─────────────────────┘
                                        │ connect(169.254.169.254:80)
                                        ▼
             ┌────────────────────────────────────────────────────────┐
             │       Kernel eBPF Hook (cgroup/connect4)               │
             │       - Rewrites destination: 127.0.0.1:18080          │
             │       - Emits calling PID/TGID/UID into BPF Ring Buffer│
             └──────────────┬─────────────────────────┬───────────────┘
                            │                         │
     Redirected TCP Traffic │                         │ BPF Ring Buffer Event
                            ▼                         ▼
┌──────────────────────────────────────┐   ┌──────────────────────────────────┐
│        Go HTTP Honeypot              │   │   Process Attribution Engine     │
│ - IMDSv1 & IMDSv2 Support            │   │ - Resolves /proc/<pid>/exe       │
│ - PUT /latest/api/token (IMDSv2)     │   │ - Resolves /proc/<pid>/cmdline   │
│ - GET /latest/meta-data/iam/...      │   │ - Resolves /proc/<pid>/cwd       │
│ - Vends canary AWS STS credentials   │   │ - Traverses Parent/Grandparents  │
└──────────────────┬───────────────────┘   └──────────────────┬───────────────┘
                   │                                          │
                   └──────────────────┬───────────────────────┘
                                      ▼
             ┌────────────────────────────────────────────────────────┐
             │         Structured JSON Security Alert                 │
             │ (slog: alert_type, PID, exe, cmdline, canary credentials)
             └────────────────────────────────────────────────────────┘
```

1. **Kernel Hook & Transparent Redirection**:
   - Attached to the cgroup v2 root via `cgroup/connect4` (`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` on `BPF_CGROUP_INET4_CONNECT`).
   - When any socket initiates a connection to `169.254.169.254:80` (`0xFEA9FEA9` in network byte order):
     - The hook rewrites the destination IP to `127.0.0.1` and port to `18080` (or configured honeypot port).
     - Submits a telemetry event into a BPF Ring Buffer map (`events`) with caller `tgid`, `pid`, `uid`, `gid`, and target port.
     - Returns `1` (`allow`) to proceed with the transparently redirected connection.

2. **Process Attribution Engine**:
   - Consumes BPF Ring Buffer events asynchronously without blocking socket establishment.
   - Inspects `/proc/<pid>/` to extract:
     - Executable path (`/proc/<pid>/exe`)
     - Command-line arguments (`/proc/<pid>/cmdline`)
     - Current working directory (`/proc/<pid>/cwd`)
     - Full process ancestor hierarchy (parent, grandparent, etc., via `/proc/<pid>/status`).

3. **Honeypot HTTP Service**:
   - Standard library `net/http` server bound to `127.0.0.1:18080`.
   - **IMDSv2 Token Negotiation**: `PUT /latest/api/token` returns a base64 session token with configurable TTL (default 6 hours).
   - **Metadata Listing**: `GET /latest/meta-data/` returns standard directory structure.
   - **Canary Vending**: `GET /latest/meta-data/iam/security-credentials/<role>` returns standard AWS STS credentials populated with pre-configured Canary tokens.
   - Also responds to dynamic instance identity documents (`/latest/dynamic/instance-identity/document`) and standard metadata keys (`instance-id`, `ami-id`, `hostname`, `local-ipv4`, `public-ipv4`).

4. **SRE Operability & Graceful Lifecycle**:
   - Enforces privilege checks on Linux (`root` or `CAP_BPF` + `CAP_NET_ADMIN`).
   - Handles `SIGINT` / `SIGTERM` cleanly, ensuring eBPF programs are detached from cgroup attachment points so host networking is never left modified.
   - Emits structured JSON alerts using `log/slog`.

---

## Directory Layout

```
imds-canary/
├── bpf/
│   ├── connect_hook.c           # eBPF C source (cgroup/connect4)
│   └── vmlinux.h                # CO-RE kernel types
├── cmd/
│   └── imds-canary/
│       └── main.go              # Daemon entrypoint, flags, signal lifecycle
├── internal/
│   ├── bpf/
│   │   ├── gen.go               # go:generate bpf2go invocation
│   │   ├── loader.go            # cilium/ebpf attachment and ring buffer consumer
│   │   ├── bpf_bpfeb.go         # Generated big-endian BPF Go wrapper
│   │   ├── bpf_bpfel.go         # Generated little-endian BPF Go wrapper
│   │   └── bpf_bpf*.o           # Compiled BPF ELF objects
│   ├── honeypot/
│   │   ├── server.go            # Mock AWS IMDSv1/v2 HTTP handler
│   │   └── server_test.go       # Unit tests for token & credential vending
│   ├── proc/
│   │   ├── inspector.go         # /proc process lineage and metadata resolution
│   │   └── inspector_test.go    # Unit tests for ancestry parsing
│   └── config/
│       ├── config.go            # Canary token configuration and CLI flags
│       └── config_test.go       # Unit tests for configuration parsing
├── scripts/
│   └── validate.sh              # Automated end-to-end validation script
├── Makefile                     # bpf2go compilation and binary build
├── go.mod
└── go.sum
```

---

## Prerequisites

- **Go**: 1.22+
- **Linux Kernel**: 5.8+ (for `BPF_MAP_TYPE_RINGBUF` and `cgroup/connect4`)
- **LLVM / Clang**: with BPF target support (for generating eBPF bytecode via `make generate`)

---

## Building

```bash
# Generate BPF wrappers and build binary
make all

# Or individually:
make generate
make build
```

Binary is output to `bin/imds-canary`.

---

## Running

### Production Mode (Linux Host / Root)

```bash
sudo ./bin/imds-canary \
  -port 18080 \
  -cgroup /sys/fs/cgroup \
  -role production-infra-role \
  -access-key-id "AKIAEXAMPLECANARYKEY1" \
  -secret-access-key "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
  -session-token "AQoDYXdzEXAMPLETOKEN"
```

Environment variables are also supported:
- `CANARY_ROLE_NAME`
- `CANARY_ACCESS_KEY_ID`
- `CANARY_SECRET_ACCESS_KEY`
- `CANARY_SESSION_TOKEN`
- `CANARY_ACCOUNT_ID`

### Dry-Run Mode (Testing without eBPF / non-root)

```bash
./bin/imds-canary -dry-run -port 18080
```

---

## Testing & Automated Validation

Run all unit tests:
```bash
make test
```

Run the automated validation script:
```bash
make validate
# or directly:
./scripts/validate.sh
```

The validation script starts the daemon, issues:
```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/production-role
```
and asserts that the response contains the valid canary credentials while checking that the daemon emitted the matching process attribution security alert.

---

## Example Alert Log

When a rogue process queries IMDS, `imds-canary` outputs a structured JSON security alert:

```json
{
  "time": "2026-10-24T00:46:15Z",
  "level": "WARN",
  "msg": "SECURITY ALERT: AWS IMDS Interception",
  "alert_type": "IMDS_PROBE_DETECTED",
  "pid": 4821,
  "tid": 4821,
  "uid": 1000,
  "gid": 1000,
  "comm": "curl",
  "original_destination": "169.254.169.254:80",
  "redirected_destination": "127.0.0.1:18080",
  "exe": "/usr/bin/curl",
  "cmdline": ["curl", "-s", "http://169.254.169.254/latest/meta-data/iam/security-credentials/production-role"],
  "cwd": "/home/user/workspace",
  "ppid": 4810,
  "ancestry": [
    {
      "pid": 4810,
      "ppid": 4800,
      "name": "python3",
      "exe": "/usr/bin/python3",
      "cmdline": ["python3", "exploit.py"]
    },
    {
      "pid": 4800,
      "ppid": 1,
      "name": "bash",
      "exe": "/usr/bin/bash",
      "cmdline": ["bash", "-l"]
    }
  ],
  "process_exited": false
}
```

---

## License

Dual BSD/GPL license for eBPF code; Apache 2.0 / MIT for userspace Go daemon.
