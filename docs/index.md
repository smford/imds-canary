# imds-canary

> **eBPF AWS IMDS Honeypot, Canary Vending & Process Attribution Daemon**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/smford/imds-canary/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/smford/imds-canary)](https://github.com/smford/imds-canary/releases)

`imds-canary` is an open-source, production-grade host security daemon for Linux servers and containers that silently intercepts rogue processes attempting to steal cloud credentials from the AWS link-local Instance Metadata Service (IMDS: `169.254.169.254`).

```
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
                                │
                                ▼
         ┌──────────────────────────────────────────────┐
         │       Kernel eBPF Hook (cgroup/connect4)     │
         │       - Transparently rewrites to 127.0.0.1  │
         │       - Emits caller PID into Ring Buffer    │
         └──────────────────────┬───────────────────────┘
                                │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
┌─────────────────────────┐           ┌─────────────────────────┐
│     IMDS Honeypot       │           │   Attribution Engine    │
│ Vends Canary AWS keys   │           │ Resolves PID, exe, args │
└────────────┬────────────┘           └────────────┬────────────┘
             │                                     │
             └──────────────────┬──────────────────┘
                                ▼
                 Real-Time Slack / SIEM Alert
                 + Optional Process Termination
```

---

## Why `imds-canary`?

Every cloud security incident from the Capital One breach to modern supply chain attacks shares a common thread: **attackers query the AWS link-local IP (`169.254.169.254`) to steal IAM credentials**.

`imds-canary` turns this predictable attacker behavior into an inescapable tripwire:

1. **Zero Attacker Feedback**: Unlike firewalls or network policies that block the connection (alerting the intruder that they've been detected), `imds-canary` transparently feeds them trackable **Canary tokens**.
2. **Instant Process Forensics**: Traditional cloud logging (CloudTrail) only tells you that a credential was used from an IP. `imds-canary` tells you the exact binary path (`/usr/bin/curl`, `python3`), full command-line arguments, working directory, and parent process tree on the host.
3. **Active Containment**: Can automatically terminate (`SIGKILL`) or freeze (`SIGSTOP`) the offending process before credentials can be exfiltrated.
4. **Pure Go & BPF CO-RE**: Built with `cilium/ebpf` without runtime CGo or BCC dependencies.

---

## Navigation

- [**Getting Started**](getting-started.md): Installation, quickstart, and self-test mode.
- [**Architecture & eBPF**](architecture.md): Deep dive into the `cgroup/connect4` kernel hook and ringbuffer.
- [**Configuration**](configuration.md): Complete list of CLI flags and environment variables.
- [**Threat Model & Deception**](threat-model.md): Detailed analysis of SSRF and container attacks.
- [**Worked Examples**](worked-examples.md): Practical, real-world deployment tutorials.
- [**Observability & Metrics**](observability.md): Prometheus `/metrics` and SIEM integration.
