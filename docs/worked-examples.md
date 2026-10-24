# Worked Examples

Detailed step-by-step guides for deploying and testing `imds-canary` in various environments.

---

## Example 1: 60-Second Quickstart in Dry-Run Mode

Test the honeypot without requiring root or eBPF privileges:

```bash
# Terminal 1: Start honeypot
./bin/imds-canary -dry-run -port 18080 -role staging-app-role

# Terminal 2: Query credentials
curl -s http://127.0.0.1:18080/latest/meta-data/iam/security-credentials/staging-app-role | jq .
```

Full guide: [examples/01-quickstart-dry-run](https://github.com/smford/imds-canary/tree/main/examples/01-quickstart-dry-run)

---

## Example 2: Simulating & Catching an SSRF Attack

Demonstrates catching an SSRF vulnerability in a Python Flask application and generating the process attribution alert.

Full guide: [examples/02-ssrf-simulation](https://github.com/smford/imds-canary/tree/main/examples/02-ssrf-simulation)

---

## Example 3: Real-Time Slack & SIEM Webhook Alerting

Configuring automated HMAC-SHA256 signed JSON webhook notifications for Slack, Discord, or SOC SIEM platforms.

Full guide: [examples/03-slack-webhook-alerting](https://github.com/smford/imds-canary/tree/main/examples/03-slack-webhook-alerting)

---

## Example 4: Active Threat Containment with SIGKILL

Automatically terminating rogue processes with `SIGKILL` the moment they attempt to query IMDS.

Full guide: [examples/04-threat-containment-sigkill](https://github.com/smford/imds-canary/tree/main/examples/04-threat-containment-sigkill)

---

## Example 5: Integrating with AWS Canarytokens

How to generate free, trackable AWS API keys from Thinkst Canary and load them into `imds-canary`.

Full guide: [examples/05-aws-canarytokens-setup](https://github.com/smford/imds-canary/tree/main/examples/05-aws-canarytokens-setup)

---

## Example 6: Deploying on Amazon Linux 2023 or Ubuntu EC2 with Systemd

Complete guide to setting up `imds-canary` as a hardened systemd daemon on AWS EC2 instances.

Full guide: [examples/06-systemd-production-ec2](https://github.com/smford/imds-canary/tree/main/examples/06-systemd-production-ec2)
