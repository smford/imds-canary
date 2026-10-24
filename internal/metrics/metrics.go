package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Registry manages and formats Prometheus-compatible operational metrics.
type Registry struct {
	startTime time.Time

	interceptsTotal   uint64
	tokensVendedTotal uint64
	procsResolved     uint64
	procsExited       uint64

	mu        sync.RWMutex
	commStats map[string]uint64
}

// Global default registry.
var Default = NewRegistry()

// NewRegistry creates a new metrics registry.
func NewRegistry() *Registry {
	return &Registry{
		startTime: time.Now(),
		commStats: make(map[string]uint64),
	}
}

// IncIntercepts increments total intercepted IMDS probes.
func (r *Registry) IncIntercepts(comm string) {
	atomic.AddUint64(&r.interceptsTotal, 1)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.commStats[comm]++
}

// IncTokensVended increments the counter for vended canary tokens.
func (r *Registry) IncTokensVended() {
	atomic.AddUint64(&r.tokensVendedTotal, 1)
}

// IncProcsResolved records attribution resolution status.
func (r *Registry) IncProcsResolved(exited bool) {
	if exited {
		atomic.AddUint64(&r.procsExited, 1)
	} else {
		atomic.AddUint64(&r.procsResolved, 1)
	}
}

// Handler returns an http.Handler serving metrics in standard Prometheus exposition format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		uptime := time.Since(r.startTime).Seconds()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		fmt.Fprintln(w, "# HELP imds_canary_uptime_seconds Total runtime uptime of imds-canary daemon in seconds.")
		fmt.Fprintln(w, "# TYPE imds_canary_uptime_seconds gauge")
		fmt.Fprintf(w, "imds_canary_uptime_seconds %.2f\n\n", uptime)

		fmt.Fprintln(w, "# HELP imds_canary_intercepts_total Total number of AWS IMDS access attempts intercepted.")
		fmt.Fprintln(w, "# TYPE imds_canary_intercepts_total counter")
		fmt.Fprintf(w, "imds_canary_intercepts_total %d\n\n", atomic.LoadUint64(&r.interceptsTotal))

		fmt.Fprintln(w, "# HELP imds_canary_tokens_vended_total Total number of mock AWS Canary credentials vended.")
		fmt.Fprintln(w, "# TYPE imds_canary_tokens_vended_total counter")
		fmt.Fprintf(w, "imds_canary_tokens_vended_total %d\n\n", atomic.LoadUint64(&r.tokensVendedTotal))

		fmt.Fprintln(w, "# HELP imds_canary_procs_resolved_total Total number of process attribution resolutions by status.")
		fmt.Fprintln(w, "# TYPE imds_canary_procs_resolved_total counter")
		fmt.Fprintf(w, "imds_canary_procs_resolved_total{status=\"success\"} %d\n", atomic.LoadUint64(&r.procsResolved))
		fmt.Fprintf(w, "imds_canary_procs_resolved_total{status=\"exited\"} %d\n\n", atomic.LoadUint64(&r.procsExited))

		r.mu.RLock()
		if len(r.commStats) > 0 {
			fmt.Fprintln(w, "# HELP imds_canary_intercepts_by_comm Total IMDS access attempts partitioned by caller comm.")
			fmt.Fprintln(w, "# TYPE imds_canary_intercepts_by_comm counter")
			for comm, count := range r.commStats {
				if comm == "" {
					comm = "unknown"
				}
				fmt.Fprintf(w, "imds_canary_intercepts_by_comm{comm=\"%s\"} %d\n", comm, count)
			}
		}
		r.mu.RUnlock()
	})
}
