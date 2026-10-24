package honeypot

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/smford/imds-canary/internal/config"
)

// SecurityCredentialsResponse represents the AWS STS security credentials JSON schema.
type SecurityCredentialsResponse struct {
	Code            string `json:"Code"`
	LastUpdated     string `json:"LastUpdated"`
	Type            string `json:"Type"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

// InstanceIdentityDocument represents the dynamic instance-identity JSON document.
type InstanceIdentityDocument struct {
	AccountID        string `json:"accountId"`
	Architecture     string `json:"architecture"`
	AvailabilityZone string `json:"availabilityZone"`
	InstanceID       string `json:"instanceId"`
	InstanceType     string `json:"instanceType"`
	Region           string `json:"region"`
	PrivateIP        string `json:"privateIp"`
}

// RequestAudit captures details of an HTTP request to the honeypot.
type RequestAudit struct {
	Timestamp  time.Time `json:"timestamp"`
	RemoteAddr string    `json:"remote_addr"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	UserAgent  string    `json:"user_agent"`
	TokenUsed  string    `json:"token_used,omitempty"`
}

// Server is the IMDS honeypot HTTP service.
type Server struct {
	cfg        *config.Config
	server     *http.Server
	listener   net.Listener
	mu         sync.RWMutex
	tokens     map[string]time.Time
	logger     *slog.Logger
	onAccessFn func(audit RequestAudit)
}

// NewServer initializes a new honeypot server.
func NewServer(cfg *config.Config, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		cfg:    cfg,
		tokens: make(map[string]time.Time),
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)

	s.server = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	return s
}

// SetOnAccess sets an optional callback when an HTTP endpoint is hit.
func (s *Server) SetOnAccess(fn func(audit RequestAudit)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onAccessFn = fn
}

// Start binds the listener and begins serving requests asynchronously.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = ln
	s.logger.Info("IMDS honeypot listening", slog.String("addr", ln.Addr().String()))

	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("honeypot server error", slog.String("error", err.Error()))
		}
	}()

	return nil
}

// Shutdown gracefully shuts down the honeypot HTTP service.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down IMDS honeypot HTTP server")
	return s.server.Shutdown(ctx)
}

// Addr returns the bound listener address.
func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	audit := RequestAudit{
		Timestamp:  time.Now().UTC(),
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Path:       r.URL.Path,
		UserAgent:  r.Header.Get("User-Agent"),
		TokenUsed:  r.Header.Get("X-aws-ec2-metadata-token"),
	}

	s.logger.Warn("IMDS Honeypot Access Intercepted",
		slog.String("remote_addr", audit.RemoteAddr),
		slog.String("method", audit.Method),
		slog.String("path", audit.Path),
		slog.String("user_agent", audit.UserAgent),
	)

	s.mu.RLock()
	onAccess := s.onAccessFn
	s.mu.RUnlock()
	if onAccess != nil {
		onAccess(audit)
	}

	path := r.URL.Path

	// 1. IMDSv2 Session Token Negotiation
	// PUT /latest/api/token
	if r.Method == http.MethodPut && (path == "/latest/api/token" || path == "/1.0/api/token") {
		s.handleTokenNegotiation(w, r)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. IMDS Directory and Metadata Handlers
	cleanPath := strings.Trim(path, "/")

	switch {
	case cleanPath == "latest" || cleanPath == "latest/meta-data":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ami-id")
		fmt.Fprintln(w, "hostname")
		fmt.Fprintln(w, "iam/")
		fmt.Fprintln(w, "instance-action")
		fmt.Fprintln(w, "instance-id")
		fmt.Fprintln(w, "instance-type")
		fmt.Fprintln(w, "local-ipv4")
		fmt.Fprintln(w, "placement/")
		fmt.Fprintln(w, "public-ipv4")

	case cleanPath == "latest/meta-data/iam":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "security-credentials/")

	case cleanPath == "latest/meta-data/iam/security-credentials":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, s.cfg.Credentials.RoleName)

	case strings.HasPrefix(cleanPath, "latest/meta-data/iam/security-credentials/"):
		s.handleSecurityCredentials(w, r, strings.TrimPrefix(cleanPath, "latest/meta-data/iam/security-credentials/"))

	case cleanPath == "latest/meta-data/instance-id":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "i-0123456789abcdef0")

	case cleanPath == "latest/meta-data/ami-id":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ami-0123456789abcdef0")

	case cleanPath == "latest/meta-data/hostname":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ip-10-0-0-1.ec2.internal")

	case cleanPath == "latest/meta-data/local-ipv4":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "10.0.0.1")

	case cleanPath == "latest/meta-data/public-ipv4":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "54.214.0.1")

	case cleanPath == "latest/meta-data/placement/availability-zone":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "us-east-1a")

	case cleanPath == "latest/dynamic/instance-identity/document":
		w.Header().Set("Content-Type", "application/json")
		doc := InstanceIdentityDocument{
			AccountID:        s.cfg.Credentials.AccountID,
			Architecture:     "x86_64",
			AvailabilityZone: "us-east-1a",
			InstanceID:       "i-0123456789abcdef0",
			InstanceType:     "m5.large",
			Region:           "us-east-1",
			PrivateIP:        "10.0.0.1",
		}
		_ = json.NewEncoder(w).Encode(doc)

	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleTokenNegotiation(w http.ResponseWriter, r *http.Request) {
	// Parse TTL header (defaults to 21600 = 6 hours)
	ttlSec := 21600
	if ttlStr := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"); ttlStr != "" {
		if parsed, err := strconv.Atoi(ttlStr); err == nil && parsed > 0 && parsed <= 21600 {
			ttlSec = parsed
		}
	}

	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	token := base64.StdEncoding.EncodeToString(rawToken)

	s.mu.Lock()
	s.tokens[token] = time.Now().Add(time.Duration(ttlSec) * time.Second)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-aws-ec2-metadata-token-ttl-seconds", strconv.Itoa(ttlSec))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}

func (s *Server) handleSecurityCredentials(w http.ResponseWriter, r *http.Request, role string) {
	now := time.Now().UTC()
	resp := SecurityCredentialsResponse{
		Code:            "Success",
		LastUpdated:     now.Format(time.RFC3339),
		Type:            "AWS-HMAC",
		AccessKeyID:     s.cfg.Credentials.AccessKeyID,
		SecretAccessKey: s.cfg.Credentials.SecretAccessKey,
		Token:           s.cfg.Credentials.Token,
		Expiration:      s.cfg.Credentials.Expiration.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
