# Configuration Reference

> **Comprehensive guide to command-line flags, environment variables, and policy configurations.**

`imds-canary` can be configured via command-line flags or environment variables. When both are provided, **command-line flags take precedence**.

---

## Configuration Parameter Reference

### Core & Kernel Settings

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :---: | :--- |
| `-port` | `CANARY_PORT` | `18080` | Port for the embedded IMDS honeypot server. |
| `-bind` | `CANARY_BIND_ADDR` | `127.0.0.1` | Network interface IP to bind honeypot (`0.0.0.0` for containers). |
| `-cgroup` | `CANARY_CGROUP` | `/sys/fs/cgroup` | Path to the cgroup v2 unified hierarchy root. |
| `-dry-run` | `CANARY_DRY_RUN` | `false` | Run honeypot without attaching eBPF kernel hooks. |
| `-test-intercept` | — | `false` | Execute 1-second diagnostic self-test and exit. |
| `-version` | — | `false` | Display version, commit, build date, and license banner. |

---

### Canary Vending Credentials

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :---: | :--- |
| `-role` | `CANARY_ROLE` | `imds-canary-role` | IAM role name vended to callers querying IMDS. |
| `-access-key-id` | `CANARY_ACCESS_KEY_ID` | `AKIA...` | AWS Access Key ID vended in STS JSON responses. |
| `-secret-access-key` | `CANARY_SECRET_ACCESS_KEY` | `SECRET...` | AWS Secret Access Key vended in STS responses. |
| `-token` | `CANARY_TOKEN` | `TOKEN...` | AWS Session Token payload vended in STS responses. |

---

### Threat Policy & Containment

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :---: | :--- |
| `-containment` | `CANARY_CONTAINMENT` | `monitor` | Action on unauthorized access: `monitor`, `sigstop`, or `sigkill`. |
| `-allowlist` | `CANARY_ALLOWLIST` | `""` | Comma-separated list of permitted binaries or process comms. |

#### Process Allowlist Syntax

The allowlist accepts both short process names (`comm`) and absolute binary filepaths:

```bash
# Allow Amazon SSM Agent and AWS CLI by binary path
-allowlist "/usr/bin/amazon-ssm-agent,/opt/aws/bin/aws,amazon-ssm-agent"
```

Any process whose `/proc/<pid>/exe` or comm matches an entry in the allowlist is permitted to connect without triggering alerts or containment actions.

---

### Alerting & SIEM Integration

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :---: | :--- |
| `-webhook-url` | `CANARY_WEBHOOK_URL` | `""` | Target URL for real-time JSON alert webhooks. |
| `-webhook-secret` | `CANARY_WEBHOOK_SECRET` | `""` | Shared secret for signing webhook payloads with HMAC-SHA256. |
| `-log-format` | `CANARY_LOG_FORMAT` | `json` | Structured log format: `json` or `cef` (Common Event Format). |

---

### Observability & Metrics

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :---: | :--- |
| `-metrics-addr` | `CANARY_METRICS_ADDR` | `:9090` | Address for Prometheus metrics (`/metrics`). |

---

## Production Systemd Configuration Example

For production deployments, store configuration in `/etc/default/imds-canary`:

```ini
# /etc/default/imds-canary
CANARY_PORT=18080
CANARY_BIND_ADDR=127.0.0.1
CANARY_CGROUP=/sys/fs/cgroup
CANARY_ROLE=production-workload-role

# Canary Credential Tripwire (from Thinkst Canarytokens or AWS IAM honeypot)
CANARY_ACCESS_KEY_ID=AKIA-CANARY-TRIPWIRE-9142
CANARY_SECRET_ACCESS_KEY=4Fk9xQv7B2wL1pM0rT5yH8nJ9sK4cZ1vX7mQ2zW6

# Containment & Allowlist
CANARY_CONTAINMENT=sigkill
CANARY_ALLOWLIST=/usr/bin/amazon-ssm-agent,amazon-ssm-agent,/usr/local/bin/aws

# SIEM Egress & Observability
CANARY_LOG_FORMAT=cef
CANARY_METRICS_ADDR=:9090
CANARY_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/XXXXX
CANARY_WEBHOOK_SECRET=7f2c8d9e1a3b5c7e9f0a2b4c6d8e0f1a
```
