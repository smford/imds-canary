package honeypot

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/smford/imds-canary/internal/config"
)

func TestHoneypot_IMDSv2_TokenNegotiation(t *testing.T) {
	cfg := config.DefaultConfig()
	server := NewServer(cfg, nil)

	req := httptest.NewRequest(http.MethodPut, "/latest/api/token", nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "3600")
	w := httptest.NewRecorder()

	server.handleRoot(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	token := string(body)
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if resp.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") != "3600" {
		t.Errorf("expected ttl header 3600, got %s", resp.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"))
	}
}

func TestHoneypot_SecurityCredentials(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Credentials.RoleName = "production-infra-role"
	cfg.Credentials.AccessKeyID = "TESTACCESSKEY123"
	cfg.Credentials.SecretAccessKey = "TESTSECRETKEY456"
	cfg.Credentials.Token = "TESTTOKEN789"
	cfg.Credentials.Expiration = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

	server := NewServer(cfg, nil)

	// 1. Role listing
	req := httptest.NewRequest(http.MethodGet, "/latest/meta-data/iam/security-credentials/", nil)
	w := httptest.NewRecorder()
	server.handleRoot(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.TrimSpace(string(body)) != "production-infra-role" {
		t.Fatalf("expected role production-infra-role, got %s", string(body))
	}

	// 2. Role credentials
	reqCreds := httptest.NewRequest(http.MethodGet, "/latest/meta-data/iam/security-credentials/production-infra-role", nil)
	wCreds := httptest.NewRecorder()
	server.handleRoot(wCreds, reqCreds)

	respCreds := wCreds.Result()
	if respCreds.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", respCreds.StatusCode)
	}
	defer respCreds.Body.Close()

	var creds SecurityCredentialsResponse
	if err := json.NewDecoder(respCreds.Body).Decode(&creds); err != nil {
		t.Fatalf("failed to decode credentials JSON: %v", err)
	}

	if creds.Code != "Success" {
		t.Errorf("expected Code Success, got %s", creds.Code)
	}
	if creds.AccessKeyID != "TESTACCESSKEY123" {
		t.Errorf("expected AccessKeyId TESTACCESSKEY123, got %s", creds.AccessKeyID)
	}
	if creds.SecretAccessKey != "TESTSECRETKEY456" {
		t.Errorf("expected SecretAccessKey TESTSECRETKEY456, got %s", creds.SecretAccessKey)
	}
	if creds.Token != "TESTTOKEN789" {
		t.Errorf("expected Token TESTTOKEN789, got %s", creds.Token)
	}
}

func TestHoneypot_MetadataListing(t *testing.T) {
	cfg := config.DefaultConfig()
	server := NewServer(cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/latest/meta-data/", nil)
	w := httptest.NewRecorder()
	server.handleRoot(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	listing := string(body)
	for _, expected := range []string{"ami-id", "instance-id", "iam/"} {
		if !strings.Contains(listing, expected) {
			t.Errorf("listing missing %q", expected)
		}
	}
}
