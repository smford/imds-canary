# Worked Example 6: Deploying on Amazon Linux 2023 or Ubuntu EC2 with Systemd

This guide explains how to install, configure, and manage `imds-canary` as a hardened system service in enterprise cloud environments.

---

### Step 1: Install Binary

```bash
# Build or download the binary
make build

# Copy to system path
sudo cp bin/imds-canary /usr/local/bin/imds-canary
sudo chmod 755 /usr/local/bin/imds-canary
```

---

### Step 2: Configure Environment File

Create `/etc/default/imds-canary`:

```bash
sudo mkdir -p /etc/default
sudo tee /etc/default/imds-canary <<'EOF'
CANARY_ROLE_NAME=production-infra-role
CANARY_ACCESS_KEY_ID=AKIAEXAMPLECANARYKEY1
CANARY_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
CANARY_SESSION_TOKEN=AQoDYXdzEJr11111111111111111111EXAMPLETOKEN
CANARY_WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/XXX
CANARY_WEBHOOK_SECRET=my-shared-hmac-secret
CANARY_ALLOWLIST=amazon-ssm-agent,/usr/bin/amazon-ssm-agent
CANARY_ACTION=alert
CANARY_LOG_FORMAT=json
EOF
sudo chmod 600 /etc/default/imds-canary
```

---

### Step 3: Install Systemd Service

Copy the hardened unit file from `init/imds-canary.service` to `/etc/systemd/system/`:

```bash
sudo cp init/imds-canary.service /etc/systemd/system/imds-canary.service

# Append EnvironmentFile loading
sudo sed -i '/\[Service\]/a EnvironmentFile=-/etc/default/imds-canary' /etc/systemd/system/imds-canary.service

sudo systemctl daemon-reload
sudo systemctl enable --now imds-canary
```

---

### Step 4: Verify Service Status

```bash
sudo systemctl status imds-canary
```

View live security alerts:
```bash
sudo journalctl -u imds-canary -f
```
