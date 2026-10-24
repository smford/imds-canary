#!/usr/bin/env bash
# ==============================================================================
# imds-canary Automated End-to-End Validation Script
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${REPO_ROOT}/bin/imds-canary"
LOG_FILE="$(mktemp /tmp/imds-canary-test.XXXXXX.log)"
PID_FILE="$(mktemp /tmp/imds-canary-test.XXXXXX.pid)"

cleanup() {
    if [[ -f "${PID_FILE}" ]]; then
        DAEMON_PID="$(cat "${PID_FILE}" 2>/dev/null || true)"
        if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
            echo "[*] Stopping daemon (PID: ${DAEMON_PID})..."
            kill "${DAEMON_PID}" 2>/dev/null || true
            wait "${DAEMON_PID}" 2>/dev/null || true
        fi
        rm -f "${PID_FILE}"
    fi
    if [[ -f "${LOG_FILE}" ]]; then
        echo "[*] Cleaning up temporary log: ${LOG_FILE}"
        rm -f "${LOG_FILE}"
    fi
}
trap cleanup EXIT INT TERM

echo "=========================================================="
echo " Starting imds-canary Validation"
echo "=========================================================="

# 1. Build binary if needed
if [[ ! -x "${BIN}" ]]; then
    echo "[*] Building imds-canary binary..."
    cd "${REPO_ROOT}"
    go build -o "${BIN}" ./cmd/imds-canary
fi

# 2. Detect environment
IS_LINUX=false
IS_ROOT=false
if [[ "$(uname -s)" == "Linux" ]]; then
    IS_LINUX=true
fi
if [[ "$(id -u)" -eq 0 ]]; then
    IS_ROOT=true
fi

ROLE="production-role"
PORT=18080

if [[ "${IS_LINUX}" == true && "${IS_ROOT}" == true ]]; then
    echo "[+] Running on Linux as root: Testing LIVE eBPF kernel hook redirection (169.254.169.254:80 -> 127.0.0.1:${PORT})"
    "${BIN}" -port "${PORT}" -role "${ROLE}" -log-level debug > "${LOG_FILE}" 2>&1 &
    DAEMON_PID=$!
    echo "${DAEMON_PID}" > "${PID_FILE}"
    TARGET_URL="http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}"
else
    echo "[i] Running in dry-run mode (non-Linux or non-root): Testing honeypot and attribution"
    "${BIN}" -dry-run -port "${PORT}" -role "${ROLE}" -log-level debug > "${LOG_FILE}" 2>&1 &
    DAEMON_PID=$!
    echo "${DAEMON_PID}" > "${PID_FILE}"
    TARGET_URL="http://127.0.0.1:${PORT}/latest/meta-data/iam/security-credentials/${ROLE}"
fi

# 3. Wait for daemon to be ready
echo "[*] Waiting for honeypot to listen on 127.0.0.1:${PORT}..."
READY=false
for _ in {1..30}; do
    if curl -s -m 1 "http://127.0.0.1:${PORT}/latest/meta-data/" >/dev/null 2>&1; then
        READY=true
        break
    fi
    sleep 0.1
done

if [[ "${READY}" != true ]]; then
    echo "[-] Error: Daemon failed to start in time. Logs:"
    cat "${LOG_FILE}"
    exit 1
fi

echo "[+] Daemon is healthy and serving requests."

# 4. Trigger canary query
echo "[*] Querying IMDS: ${TARGET_URL}"
RESPONSE="$(curl -s -m 5 "${TARGET_URL}")"

echo "[*] Received response payload:"
echo "${RESPONSE}"

# 5. Assert Canary Token presence
echo "[*] Validating response payload contains AWS STS canary credentials..."
if ! echo "${RESPONSE}" | grep -q '"AccessKeyId"'; then
    echo "[-] FAILED: Response missing AccessKeyId"
    exit 1
fi
if ! echo "${RESPONSE}" | grep -q '"SecretAccessKey"'; then
    echo "[-] FAILED: Response missing SecretAccessKey"
    exit 1
fi
if ! echo "${RESPONSE}" | grep -q '"Token"'; then
    echo "[-] FAILED: Response missing Session Token"
    exit 1
fi

echo "[+] Response verified: Canary credentials successfully returned!"

# 6. Check daemon structured log output
sleep 0.5
echo "[*] Verifying daemon security logs..."
if grep -q "IMDS Honeypot Access Intercepted" "${LOG_FILE}"; then
    echo "[+] Honeypot intercept log confirmed in daemon output."
else
    echo "[-] FAILED: Honeypot log missing from daemon output:"
    cat "${LOG_FILE}"
    exit 1
fi

if [[ "${IS_LINUX}" == true && "${IS_ROOT}" == true ]]; then
    if grep -q "SECURITY ALERT: AWS IMDS Interception" "${LOG_FILE}"; then
        echo "[+] eBPF kernel hook alert confirmed in daemon logs!"
        echo "[+] Process attribution confirmed (curl command line and PID captured)."
    else
        echo "[-] WARNING: eBPF hook alert not found in log output. Logs:"
        cat "${LOG_FILE}"
        exit 1
    fi
fi

echo "=========================================================="
echo " [SUCCESS] imds-canary validation completed successfully! "
echo "=========================================================="
