# Architecture & eBPF Internals

`imds-canary` combines modern Linux eBPF CO-RE (Compile Once – Run Everywhere) with an asynchronous userspace attribution engine and HTTP honeypot.

---

## Technical Pipeline

```
[ Application Process ]
       │
       ▼ connect(169.254.169.254:80)
┌────────────────────────────────────────────────────────┐
│ Linux Kernel Socket Layer                              │
│ SEC("cgroup/connect4") hook attached to cgroup v2      │
│                                                        │
│ 1. Match destination: 169.254.169.254 (0xFEA9FEA9)    │
│ 2. Match port: 80 (htons(80))                          │
│ 3. Rewrite destination: 127.0.0.1 (0x0100007F)        │
│ 4. Rewrite port: 18080 (htons(18080))                 │
│ 5. bpf_ringbuf_submit(struct imds_event)               │
│ 6. return 1 (allow connection to proceed)              │
└──────────────────────────┬─────────────────────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         │ TCP Connection                    │ BPF Ring Buffer
         ▼                                   ▼
┌─────────────────────────┐         ┌─────────────────────────┐
│ Embedded Go Honeypot    │         │ Userspace Ringbuf Reader│
│ 127.0.0.1:18080         │         │ - bpfImdsEvent received │
│ - IMDSv1 & IMDSv2 API   │         │ - Inspects /proc/<tgid>/│
│ - Vends Canary STS JSON │         │ - Checks Allowlist      │
└─────────────────────────┘         │ - Executes Mitigation   │
                                    └────────────┬────────────┘
                                                 ▼
                                    Structured Alerts (JSON / CEF)
                                    & Webhook Notifications
```

---

## Kernel Hook: `cgroup/connect4`

The eBPF program is compiled into target bytecode and loaded as `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` attached to the root cgroup `/sys/fs/cgroup` under `BPF_CGROUP_INET4_CONNECT`.

When an application invokes the `connect()` syscall:
- `ctx->user_ip4`: Evaluated in network byte order (`0xFEA9FEA9`).
- `ctx->user_port`: Checked against `bpf_htons(80)`.
- If both match, destination IP is rewritten to `bpf_htonl(0x7F000001)` (`127.0.0.1`) and destination port is rewritten to `bpf_htons(redirect_port)`.
- Caller information is retrieved using `bpf_get_current_pid_tgid()`, `bpf_get_current_uid_gid()`, and `bpf_get_current_comm()`, then placed into a high-throughput, non-blocking `BPF_MAP_TYPE_RINGBUF` map (`events`).

---

## Userspace Attribution Engine

Rather than resolving heavy process metadata in kernel space, the userspace Go daemon consumes events from the ring buffer asynchronously:
1. **Executable Path**: Reads `/proc/<tgid>/exe` symlink.
2. **Command Line**: Reads `/proc/<tgid>/cmdline`, splitting on NUL bytes.
3. **Working Directory**: Reads `/proc/<tgid>/cwd` symlink.
4. **Ancestry Resolution**: Traverses parent PIDs by parsing `/proc/<pid>/status` recursively up to the root process (`systemd` / PID 1).
