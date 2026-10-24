# Configuration Reference

`imds-canary` can be configured using command-line flags or environment variables. Command-line flags take precedence over environment variables.

---

## Flags & Environment Variables

| Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `-port` | `CANARY_PORT` | `18080` | Local TCP port for the honeypot HTTP service |
| `-cgroup` | `CANARY_CGROUP` | `/sys/fs/cgroup` | Path to cgroup v2 root for eBPF attachment |
| `-role` | `CANARY_ROLE_NAME` | `production-infra-role` | Mock IAM role name advertised by IMDS |
| `-access-key-id` | `CANARY_ACCESS_KEY_ID` | `AKIAEXAMPLECANARYKEY1` | Canary AWS Access Key ID |
| `-secret-access-key` | `CANARY_SECRET_ACCESS_KEY` | *(sample)* | Canary AWS Secret Access Key |
| `-session-token` | `CANARY_SESSION_TOKEN` | *(sample)* | Canary AWS Session Token |
| `-webhook-url` | `CANARY_WEBHOOK_URL` | `""` | Asynchronous alert webhook URL (Slack, SIEM) |
| `-webhook-secret` | `CANARY_WEBHOOK_SECRET` | `""` | HMAC-SHA256 secret for `X-Canary-Signature` |
| `-allowlist` | `CANARY_ALLOWLIST` | `""` | Comma-separated process names/paths to permit |
| `-action` | `CANARY_ACTION` | `alert` | Mitigation action: `alert`, `pause`, `kill`, `none` |
| `-log-format` | `CANARY_LOG_FORMAT` | `json` | Log output format: `json`, `text`, `cef` |
| `-log-level` | `CANARY_LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `-dry-run` | `CANARY_DRY_RUN` | `false` | Run honeypot only without attaching eBPF |
| `-test-intercept` | - | `false` | Run a diagnostic mock interception and exit |
| `-version`, `-v` | - | - | Print version, commit, date, and license |

---

## Example Production Systemd Configuration

`/etc/default/imds-canary`:

```ini
CANARY_ROLE_NAME=production-infra-role
CANARY_ACCESS_KEY_ID=AKIAQAAAAAAAEXAMPLE1
CANARY_SECRET_ACCESS_KEY=1234567890abcdefEXAMPLESECRET
CANARY_WEBHOOK_URL=https://siem.internal/api/v1/alerts
CANARY_WEBHOOK_SECRET=f7d8c6b5a4e3...
CANARY_ALLOWLIST=amazon-ssm-agent,/usr/bin/amazon-ssm-agent
CANARY_ACTION=kill
CANARY_LOG_FORMAT=cef
```
