# Threat Model & Deception Philosophy

> **Understanding cloud credential theft vectors, attacker psychology, and deceptive defense strategies.**

---

## Real-World Attack Scenarios

### Scenario 1: Web Application SSRF (Capital One Vector)

An attacker identifies an input parameter that accepts external URLs (e.g. `https://example.com/api/fetch?url=...`). By pointing this URL to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, the vulnerable backend server issues an HTTP GET request to IMDS on the attacker's behalf and returns the response in the HTTP payload.

```
Attacker ➔ GET /fetch?url=http://169.254.169.254 ➔ Backend Server ➔ IMDS (Stolen IAM Role)
```

**With `imds-canary`**:
1. The backend server's `connect()` call is rewritten to the honeypot.
2. The attacker receives trackable Canarytokens.
3. `imds-canary` records that `/usr/bin/python3` running `/var/www/app/server.py` originated the query.
4. If `-containment sigkill` is enabled, the backend worker process is instantly terminated.

---

### Scenario 2: Compromised Container Pods & Supply Chain Attacks

A developer imports a popular npm, PyPI, or Go module that has been compromised via supply-chain poisoning. When the container boots, malicious setup code in the dependency queries `169.254.169.254` to harvest AWS credentials and send them to an external command-and-control server.

**Why IMDSv2 doesn't stop this**:
Because the code executes locally inside the container, it can easily issue `PUT /latest/api/token` and obtain a valid IMDSv2 token.

**With `imds-canary`**:
`imds-canary` hooks the unified host cgroup. Even though the malicious code is inside an isolated Docker or Kubernetes network namespace, the kernel hook fires, attributes the host PID, and vends canary credentials.

---

### Scenario 3: Compromised CI/CD Runners

Malicious pull requests or compromised GitHub Actions/GitLab CI runners execute untrusted code that attempts to harvest host IAM instance profiles. `imds-canary` acts as a host tripwire, isolating runner jobs immediately.

---

## Comparison with Alternative Defenses

| Threat Vector | Traditional IPTables / Firewalls | AWS IMDSv2 (`HttpPutResponseHopLimit: 1`) | `imds-canary` |
| :--- | :--- | :--- | :--- |
| **Basic SSRF (IMDSv1)** | Blocked (Connection refused) | Blocked (Missing token header) | **Deceptive Trap + Process Attributed** |
| **Advanced SSRF (Header Injection)** | Blocked | Vulnerable if headers can be passed | **Deceptive Trap + Process Attributed** |
| **Local Command Execution / Shell** | Blocked | **Bypassed** (`curl -X PUT` works) | **Neutralized (SIGKILL + Forensics)** |
| **Compromised NPM/PyPI Package** | Blocked | **Bypassed** | **Neutralized (SIGKILL + Forensics)** |
| **Attacker Awareness** | High (Immediate error triggers evasion) | Medium (Tells attacker to fetch token) | **Zero (Attacker believes theft succeeded)** |
| **Host Process Forensics** | None (IP packet only) | None | **Full PID, Path, Args, CWD, Ancestry** |

---

## The Philosophy of Deceptive Defense

### Why Outright Blocking Fails

When a security tool terminates a socket or drops packets with a firewall rule:
1. **The Attacker Learns Your Defenses**: The attacker observes `ECONNREFUSED` or timeout, understands that link-local traffic is blocked, and pivots to internal network scanning, memory scraping, or environment variable theft (`AWS_SECRET_ACCESS_KEY`).
2. **You Lose Actionable Intelligence**: You know a packet was dropped, but you don't know who the attacker is, what external command-and-control IP they are using, or what tools they have at their disposal.

### The Advantage of Canary Vending

By returning realistic, trackable AWS Canarytokens:
* The attacker believes their attack succeeded.
* They pause further exploitation and attempt to use the stolen credentials from their external machine or VPN.
* The moment they execute `aws s3 ls` or `aws sts get-caller-identity` with the canary key, AWS CloudTrail alerts your SOC with the attacker's **true external IP address**, ISP, user agent, and timestamp.

---

## Containment Policies

`imds-canary` supports 3 containment policies via `-containment`:

```
                 ┌────────────────────────────────┐
                 │  Unauthorized IMDS Request     │
                 └───────────────┬────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ -containment     │    │ -containment     │    │ -containment     │
│  monitor         │    │  sigstop         │    │  sigkill         │
├──────────────────┤    ├──────────────────┤    ├──────────────────┤
│ Silent honeypot  │    │ Freezes process  │    │ Instantly kills  │
│ trap + alerting  │    │ in kernel memory │    │ rogue process    │
│ (Zero disruption)│    │ for live analysis│    │ (Zero data leak) │
└──────────────────┘    └──────────────────┘    └──────────────────┘
```

1. **`monitor` (Default)**: Emits structured logs and webhook alerts, but does not interfere with process execution. Recommended for initial rollout and baseline discovery.
2. **`sigstop`**: Sends `SIGSTOP` to pause the offending process in memory. This freezes malicious activity while preserving process memory, open file descriptors, and network sockets for live forensic triage with `gdb` or memory acquisition tools.
3. **`sigkill`**: Sends immediate `SIGKILL` to neutralize rogue processes before exfiltration.

---

## Bypass Resistance Analysis

### Can an attacker bypass the eBPF hook?

* **Raw Sockets (`SOCK_RAW`)**: Bypassing socket hooks via raw packets requires `CAP_NET_RAW` or root privileges. Standard applications, web servers, and container users lack this capability.
* **DNS Rebinding**: Even if the attacker attempts to query `169.254.169.254` via a custom DNS domain that resolves to `169.254.169.254`, the kernel hook inspects the resolved IP (`user_ip4`) during `connect()`, so the redirection is applied regardless of hostnames.
* **Namespace Isolation**: Because the hook attaches to the root cgroup (`/sys/fs/cgroup`), all container namespaces (`pid`, `net`, `mnt`) inherit the hook automatically.
