# Worked Example 4: Active Threat Containment with SIGKILL

While deception via Canarytokens is powerful, some security policies require immediate neutralisation of any unauthorized process probing for credentials.

`imds-canary` provides an automated containment engine capable of sending `SIGKILL` or `SIGSTOP` to rogue processes in microseconds.

---

### Step 1: Start `imds-canary` in Kill Mode

```bash
sudo ./bin/imds-canary \
  -port 18080 \
  -action kill \
  -allowlist "amazon-ssm-agent,/usr/bin/amazon-ssm-agent"
```

---

### Step 2: Rogue Process Attempts Query

Simulate an intruder attempting to probe IMDS:

```bash
# In another terminal:
curl -s http://169.254.169.254/latest/meta-data/
```

Result:
```bash
[1]    74910 killed     curl -s http://169.254.169.254/latest/meta-data/
```

The process is terminated instantly by `SIGKILL` before it can receive or write any data to disk or network.

---

### Step 3: Forensic Log Output

The daemon logs the containment action:

```json
{
  "time": "2026-10-24T02:00:00Z",
  "level": "WARN",
  "msg": "SECURITY ALERT: AWS IMDS Interception",
  "alert_type": "IMDS_PROBE_DETECTED",
  "pid": 74910,
  "comm": "curl",
  "exe": "/usr/bin/curl",
  "mitigation_action": "kill",
  "mitigation_result": "SIGKILL (process terminated)",
  "process_exited": true
}
```

---

### Freezing for Live Memory Forensics (`-action pause`)

If your incident response team prefers to preserve process memory for memory dumping and reverse engineering:

```bash
sudo ./bin/imds-canary -action pause
```

The rogue process will be placed into the `STOPPED` state (`T` state in `ps`), allowing investigators to attach GDB or inspect `/proc/<pid>/mem`.
