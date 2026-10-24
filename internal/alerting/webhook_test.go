package alerting

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookSender_DeliveryAndSignature(t *testing.T) {
	secret := "super-secret-key-123"
	var receivedCount int32
	var mu sync.Mutex
	var lastReceivedBody []byte
	var lastSignature string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		lastReceivedBody = body
		lastSignature = r.Header.Get("X-Canary-Signature")
		mu.Unlock()
		atomic.AddInt32(&receivedCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := NewWebhookSender(server.URL, secret, nil)
	defer sender.Stop()

	alert := AlertPayload{
		Timestamp: time.Now().UTC(),
		AlertType: "TEST_INTERCEPT",
		Comm:      "rogue_probe",
		PID:       4242,
	}

	sender.Send(alert)

	// Await delivery
	for i := 0; i < 50; i++ {
		if atomic.LoadInt32(&receivedCount) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if atomic.LoadInt32(&receivedCount) != 1 {
		t.Fatalf("expected 1 received webhook, got %d", receivedCount)
	}

	mu.Lock()
	bodyCopy := make([]byte, len(lastReceivedBody))
	copy(bodyCopy, lastReceivedBody)
	sigCopy := lastSignature
	mu.Unlock()

	var parsed AlertPayload
	if err := json.Unmarshal(bodyCopy, &parsed); err != nil {
		t.Fatalf("failed to parse received webhook json: %v", err)
	}
	if parsed.Comm != "rogue_probe" || parsed.PID != 4242 {
		t.Errorf("unexpected payload content: %+v", parsed)
	}

	// Verify HMAC signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(bodyCopy)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if !strings.EqualFold(sigCopy, expectedSig) {
		t.Errorf("expected signature %s, got %s", expectedSig, sigCopy)
	}
}
