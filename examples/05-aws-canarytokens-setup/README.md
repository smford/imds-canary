# Worked Example 5: Integrating with AWS Canarytokens

Canarytokens (such as those provided by [Thinkst Canary](https://canarytokens.org) or AWS SpaceCrab) generate real, trackable AWS API keys that carry no IAM permissions. When an attacker attempts to use these keys with `aws s3 ls`, `aws sts get-caller-identity`, or the AWS SDK, an instant alert is triggered indicating the attacker's source IP and user agent.

---

### Step 1: Generate an AWS Canarytoken

1. Visit [canarytokens.org](https://canarytokens.org/generate) or use Thinkst Canary Console.
2. Select **AWS API Key**.
3. Provide your email or webhook URL.
4. Set a descriptive note: `EC2 Host prod-web-01 IMDS Canary`.
5. You will receive:
   - `Access Key ID`: e.g. `AKIAQAAAAAAAEXAMPLE1`
   - `Secret Access Key`: e.g. `1234567890abcdefEXAMPLESECRET`

---

### Step 2: Inject Canarytokens into `imds-canary`

Pass the credentials via environment variables or CLI flags:

```bash
export CANARY_ACCESS_KEY_ID="AKIAQAAAAAAAEXAMPLE1"
export CANARY_SECRET_ACCESS_KEY="1234567890abcdefEXAMPLESECRET"
export CANARY_ROLE_NAME="production-admin-role"

sudo -E ./bin/imds-canary
```

---

### Step 3: The Deception Cycle in Action

1. Attacker exploits SSRF or gains a shell.
2. Attacker runs:
   ```bash
   curl http://169.254.169.254/latest/meta-data/iam/security-credentials/production-admin-role
   ```
3. `imds-canary` intercepts the socket and returns the Canarytoken credentials.
4. Attacker copies the keys to their machine and executes:
   ```bash
   AWS_ACCESS_KEY_ID=AKIAQAAAAAAAEXAMPLE1 AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
   ```
5. AWS CloudTrail immediately detects the API call. Thinkst Canary triggers an email/pager alert with the attacker's public IP address, ISP, and timestamp!
