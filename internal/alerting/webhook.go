package alerting

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/smford/imds-canary/internal/proc"
)

// AlertPayload defines the structured notification sent to external webhooks.
type AlertPayload struct {
	Timestamp           time.Time             `json:"timestamp"`
	AlertType           string                `json:"alert_type"`
	HostName            string                `json:"hostname"`
	PID                 uint32                `json:"pid"`
	TID                 uint32                `json:"tid"`
	UID                 uint32                `json:"uid"`
	GID                 uint32                `json:"gid"`
	Comm                string                `json:"comm"`
	OriginalDestination string                `json:"original_destination"`
	RedirectDestination string                `json:"redirect_destination"`
	CanaryRole          string                `json:"canary_role"`
	ProcessSnapshot     *proc.ProcessSnapshot `json:"process,omitempty"`
}

// WebhookSender sends alert notifications to an external HTTP webhook.
type WebhookSender struct {
	url        string
	secret     string
	client     *http.Client
	queue      chan AlertPayload
	logger     *slog.Logger
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	bufferSize int
}

// NewWebhookSender creates a new WebhookSender.
func NewWebhookSender(url, secret string, logger *slog.Logger) *WebhookSender {
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())
	ws := &WebhookSender{
		url:    url,
		secret: secret,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		queue:      make(chan AlertPayload, 256),
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
		bufferSize: 256,
	}

	if url != "" {
		ws.wg.Add(1)
		go ws.worker()
	}

	return ws
}

// Send enqueues an alert for asynchronous transmission.
func (ws *WebhookSender) Send(alert AlertPayload) {
	if ws.url == "" {
		return
	}

	select {
	case ws.queue <- alert:
	default:
		ws.logger.Warn("alert webhook queue full, dropping alert notification",
			slog.Uint64("pid", uint64(alert.PID)),
			slog.String("comm", alert.Comm),
		)
	}
}

func (ws *WebhookSender) worker() {
	defer ws.wg.Done()

	for {
		select {
		case <-ws.ctx.Done():
			// Drain remaining alerts
			for {
				select {
				case alert := <-ws.queue:
					_ = ws.dispatch(alert)
				default:
					return
				}
			}
		case alert := <-ws.queue:
			if err := ws.dispatchWithRetry(alert, 3); err != nil {
				ws.logger.Error("failed to deliver alert webhook after retries",
					slog.String("url", ws.url),
					slog.String("error", err.Error()),
				)
			}
		}
	}
}

func (ws *WebhookSender) dispatchWithRetry(alert AlertPayload, maxRetries int) error {
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := ws.dispatch(alert)
		if err == nil {
			return nil
		}
		lastErr = err
		select {
		case <-ws.ctx.Done():
			return lastErr
		case <-time.After(time.Duration(attempt*250) * time.Millisecond):
		}
	}
	return lastErr
}

func (ws *WebhookSender) dispatch(alert AlertPayload) error {
	body, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ws.ctx, http.MethodPost, ws.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "imds-canary-webhook/1.0")

	if ws.secret != "" {
		mac := hmac.New(sha256.New, []byte(ws.secret))
		mac.Write(body)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Canary-Signature", fmt.Sprintf("sha256=%s", signature))
	}

	resp, err := ws.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook endpoint returned HTTP %d", resp.StatusCode)
	}

	ws.logger.Debug("alert webhook successfully delivered",
		slog.String("url", ws.url),
		slog.Uint64("pid", uint64(alert.PID)),
	)
	return nil
}

// Stop gracefully flushes pending alerts and stops the sender.
func (ws *WebhookSender) Stop() {
	ws.cancel()
	ws.wg.Wait()
}
