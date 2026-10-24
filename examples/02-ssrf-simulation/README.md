# Worked Example 2: Simulating and Catching an SSRF Attack

Server-Side Request Forgery (SSRF) is one of the most common vulnerabilities used by cloud attackers (e.g., Capital One breach). When an attacker exploits an SSRF flaw in a web application (like an image previewer, PDF exporter, or webhook tester), they instruct the backend server to fetch `http://169.254.169.254`.

This example demonstrates how `imds-canary` detects the attack and attributes it to the exact web process.

---

### Step 1: Start `imds-canary` on the Host

On a Linux host with root:
```bash
sudo ./bin/imds-canary \
  -port 18080 \
  -role production-backend-role \
  -access-key-id "AKIA-CANARY-TRIPWIRE-1" \
  -secret-access-key "SECRET-CANARY-TRIPWIRE-1"
```

---

### Step 2: Simulate Vulnerable Web Application

Imagine a Python Flask application with an SSRF vulnerability:

```python
# vulnerable_app.py
import urllib.request
from flask import Flask, request

app = Flask(__name__)

@app.route("/preview")
def preview():
    url = request.args.get("url")
    # Vulnerable: Unvalidated server-side HTTP fetch
    resp = urllib.request.urlopen(url)
    return resp.read()

if __name__ == "__main__":
    app.run(port=5000)
```

---

### Step 3: Attacker Exploits the Vulnerability

The attacker sends an exploit payload targeting the link-local address:

```bash
curl "http://localhost:5000/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/production-backend-role"
```

The attacker receives the canary credentials:
```json
{
  "Code": "Success",
  "AccessKeyId": "AKIA-CANARY-TRIPWIRE-1",
  "SecretAccessKey": "SECRET-CANARY-TRIPWIRE-1",
  "Token": "AQoDYXdz..."
}
```

---

### Step 4: The Alert Emitted by `imds-canary`

While the attacker believes they successfully stole IAM credentials, `imds-canary` immediately captured the attack and emitted the following forensic alert:

```json
{
  "time": "2026-10-24T02:00:10Z",
  "level": "WARN",
  "msg": "SECURITY ALERT: AWS IMDS Interception",
  "alert_type": "IMDS_PROBE_DETECTED",
  "pid": 58310,
  "comm": "python3",
  "original_destination": "169.254.169.254:80",
  "redirected_destination": "127.0.0.1:18080",
  "exe": "/usr/bin/python3.11",
  "cmdline": ["python3", "vulnerable_app.py"],
  "cwd": "/var/www/vulnerable_app",
  "ppid": 1201,
  "ancestry": [
    {
      "pid": 1201,
      "ppid": 1,
      "name": "systemd",
      "exe": "/lib/systemd/systemd"
    }
  ]
}
```

The security team now knows:
1. Exactly which process made the request (`vulnerable_app.py`, PID 58310).
2. The working directory (`/var/www/vulnerable_app`).
3. That the attacker has `AKIA-CANARY-TRIPWIRE-1`, allowing AWS GuardDuty/CloudTrail to flag their IP address the moment they try using it!
