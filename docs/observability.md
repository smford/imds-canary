# Observability & Metrics

`imds-canary` provides enterprise-grade observability through standard Prometheus metrics and ArcSight Common Event Format (CEF) logging.

---

## Prometheus Metrics (`/metrics`)

The daemon exposes an OpenMetrics / Prometheus endpoint on `GET /metrics`:

```bash
curl -s http://127.0.0.1:18080/metrics
```

Output:
```
# HELP imds_canary_uptime_seconds Total runtime uptime of imds-canary daemon in seconds.
# TYPE imds_canary_uptime_seconds gauge
imds_canary_uptime_seconds 3482.12

# HELP imds_canary_intercepts_total Total number of AWS IMDS access attempts intercepted.
# TYPE imds_canary_intercepts_total counter
imds_canary_intercepts_total 14

# HELP imds_canary_tokens_vended_total Total number of mock AWS Canary credentials vended.
# TYPE imds_canary_tokens_vended_total counter
imds_canary_tokens_vended_total 12

# HELP imds_canary_procs_resolved_total Total number of process attribution resolutions by status.
# TYPE imds_canary_procs_resolved_total counter
imds_canary_procs_resolved_total{status="success"} 14
imds_canary_procs_resolved_total{status="exited"} 0

# HELP imds_canary_intercepts_by_comm Total IMDS access attempts partitioned by caller comm.
# TYPE imds_canary_intercepts_by_comm counter
imds_canary_intercepts_by_comm{comm="curl"} 11
imds_canary_intercepts_by_comm{comm="python3"} 3
```

---

## Health & Liveness Probes

- **`/healthz`**: Returns `{"status":"ok","daemon":"imds-canary"}`. Use for load balancer healthchecks or Kubernetes liveness probes.
- **`/livez`**: Returns HTTP 200 OK for simple readiness checks.

Neither endpoint triggers security alert logs or metrics skew.

---

## ArcSight Common Event Format (CEF) Logging

When running with `-log-format cef`:

```
CEF:0|smford|imds-canary|1.0|IMDS_PROBE_DETECTED|AWS IMDS Access Intercepted|9|src=169.254.169.254:80 dst=127.0.0.1:18080 duser=1000 dpid=4821 dproc=curl act=redirected cs1=production-infra-role cs1Label=CanaryRole rt=1761271200000 filePath=/usr/bin/curl cs2=curl -s http://169.254.169.254 cs2Label=CommandLine
```

Directly ingestible by Splunk, Microsoft Sentinel, IBM QRadar, or Rsyslog.
