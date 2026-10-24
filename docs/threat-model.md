# Threat Model & Deception Strategy

Understanding the attack surface and how `imds-canary` disrupts credential theft workflows.

---

## The Attack Vectors

### 1. Server-Side Request Forgery (SSRF)

Web applications with URL-fetching capabilities (image downloaders, webhook dispatchers, PDF generators, XML parsers) are frequently coerced into making requests to internal addresses.

- **Attacker Goal**: Read `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
- **Canary Defense**: The server process making the outbound connection is transparently redirected to `127.0.0.1:18080`. The application receives Canary credentials, and `imds-canary` records the web process name, command line, and working directory.

### 2. Container Breakout / Compromised Container

When a container is compromised via vulnerable web frameworks or third-party dependencies:
- **Attacker Goal**: Query link-local address from inside the container network namespace.
- **Canary Defense**: Because `cgroup/connect4` is attached to the cgroup v2 hierarchy, socket calls originating from any container within the cgroup are trapped transparently.

### 3. Compromised CI/CD Runners & Supply-Chain Packages

Malicious packages injected into npm, PyPI, or RubyGems often include post-install scripts that scrape IMDS to exfiltrate credentials during build steps.
- **Attacker Goal**: Grab IAM keys during `npm install` or test suite execution.
- **Canary Defense**: The build process PID and full `npm`/`node` invocation arguments are captured. Optional `-action kill` instantly terminates the build step before malicious code can transmit the token.

---

## Deception vs. Blocking

| Approach | Attacker Experience | Security Team Outcome |
|---|---|---|
| **Firewall / IP Drop** | Connection timed out / connection refused. Attacker knows an egress rule is blocking IMDS; pivots to memory scraping or privilege escalation. | Attacker remains inside host; zero forensic breadcrumbs. |
| **AWS IMDSv2 Only** | Requires `PUT` with TTL header. Automated tools without IMDSv2 support fail; sophisticated attackers easily craft `PUT` token requests. | Still vends real credentials if attacker uses IMDSv2. |
| **`imds-canary`** | Request succeeds instantly (both IMDSv1 and IMDSv2). Attacker receives valid-looking STS keys, thinks they won, and stops searching. | Attacker is tricked into using canary keys on the internet, triggering CloudTrail alarms with their real IP. The host process is identified and optionally terminated. |
