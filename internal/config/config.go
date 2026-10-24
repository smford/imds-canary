package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// CanaryCredentials holds AWS STS credentials returned to rogue processes.
type CanaryCredentials struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
	RoleName        string    `json:"RoleName"`
	AccountID       string    `json:"AccountId"`
}

// Config represents daemon runtime configuration.
type Config struct {
	HoneypotPort uint16
	ListenAddr   string
	CgroupPath   string
	Credentials  CanaryCredentials
	LogLevel     string
	DryRun       bool // Useful for testing without attaching eBPF to cgroup
}

// DefaultConfig returns safe and functional default settings.
func DefaultConfig() *Config {
	return &Config{
		HoneypotPort: 18080,
		ListenAddr:   "127.0.0.1:18080",
		CgroupPath:   "/sys/fs/cgroup",
		Credentials: CanaryCredentials{
			AccessKeyID:     getEnvOrDefault("CANARY_ACCESS_KEY_ID", "AKIAEXAMPLECANARYKEY1"),
			SecretAccessKey: getEnvOrDefault("CANARY_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
			Token:           getEnvOrDefault("CANARY_SESSION_TOKEN", "AQoDYXdzEJr11111111111111111111EXAMPLETOKEN"),
			Expiration:      time.Now().Add(6 * time.Hour).UTC(),
			RoleName:        getEnvOrDefault("CANARY_ROLE_NAME", "production-infra-role"),
			AccountID:       getEnvOrDefault("CANARY_ACCOUNT_ID", "123456789012"),
		},
		LogLevel: "info",
		DryRun:   false,
	}
}

// ParseFlags parses command-line flags and environment variables.
func ParseFlags(args []string) (*Config, error) {
	cfg := DefaultConfig()

	fs := flag.NewFlagSet("imds-canary", flag.ContinueOnError)

	var port int
	fs.IntVar(&port, "port", int(cfg.HoneypotPort), "Honeypot HTTP listen port")
	fs.StringVar(&cfg.CgroupPath, "cgroup", cfg.CgroupPath, "Cgroup v2 root path for eBPF attachment")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level (debug, info, warn, error)")
	fs.StringVar(&cfg.Credentials.RoleName, "role", cfg.Credentials.RoleName, "Mock IAM role name")
	fs.StringVar(&cfg.Credentials.AccessKeyID, "access-key-id", cfg.Credentials.AccessKeyID, "Canary AWS Access Key ID")
	fs.StringVar(&cfg.Credentials.SecretAccessKey, "secret-access-key", cfg.Credentials.SecretAccessKey, "Canary AWS Secret Access Key")
	fs.StringVar(&cfg.Credentials.Token, "session-token", cfg.Credentials.Token, "Canary AWS Session Token")
	fs.BoolVar(&cfg.DryRun, "dry-run", false, "Run HTTP honeypot only without attaching eBPF")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}
	cfg.HoneypotPort = uint16(port)
	cfg.ListenAddr = fmt.Sprintf("127.0.0.1:%d", cfg.HoneypotPort)

	return cfg, nil
}

func getEnvOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
