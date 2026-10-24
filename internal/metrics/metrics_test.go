package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetrics_Exposition(t *testing.T) {
	reg := NewRegistry()
	reg.IncIntercepts("curl")
	reg.IncIntercepts("curl")
	reg.IncIntercepts("python")
	reg.IncTokensVended()
	reg.IncProcsResolved(false)
	reg.IncProcsResolved(true)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	output := string(body)

	if !strings.Contains(output, "imds_canary_intercepts_total 3") {
		t.Errorf("missing or invalid imds_canary_intercepts_total: %s", output)
	}
	if !strings.Contains(output, "imds_canary_tokens_vended_total 1") {
		t.Errorf("missing or invalid imds_canary_tokens_vended_total: %s", output)
	}
	if !strings.Contains(output, "imds_canary_intercepts_by_comm{comm=\"curl\"} 2") {
		t.Errorf("missing or invalid curl count: %s", output)
	}
	if !strings.Contains(output, "imds_canary_intercepts_by_comm{comm=\"python\"} 1") {
		t.Errorf("missing or invalid python count: %s", output)
	}
}
