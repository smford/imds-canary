# Worked Example 1: Quickstart in Dry-Run Mode

This example demonstrates how to run and test `imds-canary` on any developer laptop (macOS or Linux) without needing root privileges or Linux kernel eBPF support.

---

### Step 1: Start the Daemon in Dry-Run Mode

In terminal 1:

```bash
# Start the honeypot on local port 18080
./bin/imds-canary -dry-run -port 18080 -role staging-app-role
```

You will see:
```json
{"time":"2026-10-24T02:00:00Z","level":"INFO","msg":"Starting imds-canary daemon","honeypot_port":18080,"canary_role":"staging-app-role","dry_run":true}
{"time":"2026-10-24T02:00:00Z","level":"INFO","msg":"IMDS honeypot listening","addr":"127.0.0.1:18080"}
```

---

### Step 2: Query the IMDS Honeypot

In terminal 2:

```bash
# Query the IAM role name (IMDSv1 style)
curl -s http://127.0.0.1:18080/latest/meta-data/iam/security-credentials/
# Output: staging-app-role

# Query the credentials for the role
curl -s http://127.0.0.1:18080/latest/meta-data/iam/security-credentials/staging-app-role | jq .
```

Output:
```json
{
  "Code": "Success",
  "LastUpdated": "2026-10-24T02:00:05Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "AKIAEXAMPLECANARYKEY1",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "AQoDYXdzEJr11111111111111111111EXAMPLETOKEN",
  "Expiration": "2026-10-24T08:00:05Z"
}
```

---

### Step 3: Test IMDSv2 Token Negotiation

AWS IMDSv2 requires a session token obtained via `PUT /latest/api/token`:

```bash
# Request session token (valid for 6 hours)
TOKEN=$(curl -s -X PUT "http://127.0.0.1:18080/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

echo "Received Token: $TOKEN"

# Use the token to fetch security credentials
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://127.0.0.1:18080/latest/meta-data/iam/security-credentials/staging-app-role | jq .
```

---

### Step 4: Check Operational Health & Metrics

```bash
# Health check
curl -s http://127.0.0.1:18080/healthz | jq .

# Prometheus metrics
curl -s http://127.0.0.1:18080/metrics
```
