# Worked Example 3: Real-Time Slack & Webhook Alerting

This example demonstrates how to configure `imds-canary` to immediately dispatch real-time alerts to Slack, Discord, or your SIEM webhook endpoint with HMAC-SHA256 signature verification.

---

### Step 1: Start `imds-canary` with Webhook Notification Egress

```bash
sudo ./bin/imds-canary \
  -port 18080 \
  -webhook-url "https://hooks.slack.com/services/T000/B000/XXXXX" \
  -webhook-secret "my-hmac-shared-secret"
```

You can also configure via environment variables:
```bash
export CANARY_WEBHOOK_URL="https://siem.internal.company.com/api/v1/alerts"
export CANARY_WEBHOOK_SECRET="super-secret-hmac-key"
sudo -E ./bin/imds-canary
```

---

### Step 2: Test the Alerting Pipeline via Self-Test

Before putting the server into production, you can verify your webhook delivery without needing root or BPF privileges using `-test-intercept`:

```bash
./bin/imds-canary \
  -test-intercept \
  -webhook-url "https://webhook.site/your-unique-uuid" \
  -webhook-secret "test-secret"
```

Output:
```
{"time":"2026-10-24T02:00:00Z","level":"INFO","msg":"Executing diagnostic self-test interception probe"}
{"time":"2026-10-24T02:00:00Z","level":"WARN","msg":"DIAGNOSTIC SECURITY ALERT: Test Probe Executed",...}
[+] Diagnostic self-test completed successfully.
```

---

### Step 3: Webhook JSON Payload Schema

When a probe occurs, the webhook endpoint receives an HTTP POST with:
- Header `Content-Type: application/json`
- Header `X-Canary-Signature: sha256=<hex_hmac_sha256>`
- Body:

```json
{
  "timestamp": "2026-10-24T02:00:00Z",
  "alert_type": "IMDS_PROBE_DETECTED",
  "hostname": "prod-api-worker-01",
  "pid": 4821,
  "tid": 4821,
  "uid": 1000,
  "gid": 1000,
  "comm": "curl",
  "original_destination": "169.254.169.254:80",
  "redirect_destination": "127.0.0.1:18080",
  "canary_role": "production-infra-role",
  "process": {
    "pid": 4821,
    "ppid": 4810,
    "name": "curl",
    "exe": "/usr/bin/curl",
    "cmdline": ["curl", "-s", "http://169.254.169.254/latest/meta-data/iam/security-credentials/production-infra-role"],
    "cwd": "/tmp",
    "ancestry": [
      {
        "pid": 4810,
        "ppid": 1,
        "name": "bash",
        "exe": "/usr/bin/bash",
        "cmdline": ["bash"]
      }
    ]
  }
}
```
