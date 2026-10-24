package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/smford/imds-canary/internal/alerting"
	"github.com/smford/imds-canary/internal/bpf"
	"github.com/smford/imds-canary/internal/config"
	"github.com/smford/imds-canary/internal/honeypot"
	"github.com/smford/imds-canary/internal/metrics"
	"github.com/smford/imds-canary/internal/policy"
	"github.com/smford/imds-canary/internal/proc"
	"github.com/smford/imds-canary/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && (args[0] == "version" || args[0] == "-version" || args[0] == "--version" || args[0] == "-v") {
		version.Print()
		return nil
	}

	cfg, err := config.ParseFlags(args)
	if err != nil {
		return err
	}
	if cfg.ShowVersion {
		version.Print()
		return nil
	}

	// Initialize structured logger
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var handler slog.Handler
	if cfg.LogFormat == "text" {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	hostname, _ := os.Hostname()

	// Initialize Webhook Alerting Sender
	webhookSender := alerting.NewWebhookSender(cfg.WebhookURL, cfg.WebhookSecret, logger)
	defer webhookSender.Stop()

	// Initialize Process Attribution Inspector & Policy Allowlist
	inspector := proc.NewInspector()
	allowlist := policy.NewAllowlist(cfg.Allowlist)

	// Diagnostic self-test interception mode
	if cfg.TestIntercept {
		logger.Info("Executing diagnostic self-test interception probe")
		pid := uint32(os.Getpid())
		uid := uint32(os.Getuid())
		gid := uint32(os.Getgid())
		snap := inspector.Inspect(pid, uid, gid, "imds-canary-test")

		metrics.Default.IncIntercepts("imds-canary-test")
		metrics.Default.IncProcsResolved(snap.Exited)

		alert := alerting.AlertPayload{
			Timestamp:           time.Now().UTC(),
			AlertType:           "DIAGNOSTIC_SELF_TEST",
			HostName:            hostname,
			PID:                 pid,
			TID:                 pid,
			UID:                 uid,
			GID:                 gid,
			Comm:                "imds-canary-test",
			OriginalDestination: "169.254.169.254:80",
			RedirectDestination: cfg.ListenAddr,
			CanaryRole:          cfg.Credentials.RoleName,
			ProcessSnapshot:     snap,
		}

		if cfg.LogFormat == "cef" {
			fmt.Println(alerting.FormatCEF(alert, 5))
		} else {
			logger.Warn("DIAGNOSTIC SECURITY ALERT: Test Probe Executed",
				slog.String("alert_type", alert.AlertType),
				slog.Uint64("pid", uint64(pid)),
				slog.String("comm", alert.Comm),
				slog.String("exe", snap.Exe),
				slog.Any("cmdline", snap.Cmdline),
			)
		}

		if cfg.WebhookURL != "" {
			webhookSender.Send(alert)
			time.Sleep(500 * time.Millisecond) // Allow queue to flush
		}

		fmt.Println("[+] Diagnostic self-test completed successfully.")
		return nil
	}

	logger.Info("Starting imds-canary daemon",
		slog.String("version", version.Version),
		slog.Uint64("honeypot_port", uint64(cfg.HoneypotPort)),
		slog.String("cgroup_path", cfg.CgroupPath),
		slog.String("canary_role", cfg.Credentials.RoleName),
		slog.String("mitigation_action", cfg.Action),
		slog.Int("allowlist_rules", allowlist.Size()),
		slog.Bool("dry_run", cfg.DryRun),
		slog.Bool("webhook_configured", cfg.WebhookURL != ""),
	)

	// Check privileges unless dry-run
	if !cfg.DryRun && runtime.GOOS == "linux" {
		if os.Geteuid() != 0 {
			return fmt.Errorf("insufficient privileges: imds-canary requires root (or CAP_BPF / CAP_NET_ADMIN) to attach eBPF cgroup socket programs")
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Initialize IMDS Honeypot HTTP Service
	honeyServer := honeypot.NewServer(cfg, logger)
	if err := honeyServer.Start(); err != nil {
		return fmt.Errorf("failed to start honeypot HTTP server: %w", err)
	}
	defer func() {
		shutdownCtx, sCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer sCancel()
		_ = honeyServer.Shutdown(shutdownCtx)
	}()

	// Initialize and start eBPF Hook Loader unless dry-run
	var bpfLoader *bpf.Loader
	if !cfg.DryRun {
		bpfLoader = bpf.NewLoader(cfg.CgroupPath, cfg.HoneypotPort, logger)
		bpfLoader.SetHandler(func(evt bpf.Event) {
			metrics.Default.IncIntercepts(evt.Comm)

			// Resolve process lineage and command-line metadata asynchronously
			snap := inspector.Inspect(evt.TGID, evt.UID, evt.GID, evt.Comm)
			metrics.Default.IncProcsResolved(snap.Exited)

			// Check process allowlist
			if allowlist.IsAllowed(evt.Comm, snap.Exe) {
				logger.Info("IMDS access by allowlisted process",
					slog.String("status", "ALLOWLISTED"),
					slog.Uint64("pid", uint64(evt.TGID)),
					slog.String("comm", evt.Comm),
					slog.String("exe", snap.Exe),
				)
				return
			}

			// Apply containment mitigation action
			mitigationResult, mitErr := policy.ExecuteMitigation(policy.MitigationAction(cfg.Action), evt.TGID)
			if mitErr != nil {
				logger.Error("containment mitigation failed", slog.String("error", mitErr.Error()))
			}

			alert := alerting.AlertPayload{
				Timestamp:           time.Now().UTC(),
				AlertType:           "IMDS_PROBE_DETECTED",
				HostName:            hostname,
				PID:                 evt.TGID,
				TID:                 evt.PID,
				UID:                 evt.UID,
				GID:                 evt.GID,
				Comm:                evt.Comm,
				OriginalDestination: fmt.Sprintf("%s:%d", evt.OrigDstIP, evt.TargetPort),
				RedirectDestination: fmt.Sprintf("%s:%d", evt.RedirDstIP, evt.RedirPort),
				CanaryRole:          cfg.Credentials.RoleName,
				ProcessSnapshot:     snap,
			}

			if cfg.LogFormat == "cef" {
				fmt.Println(alerting.FormatCEF(alert, 9))
			} else {
				logger.Warn("SECURITY ALERT: AWS IMDS Interception",
					slog.String("alert_type", alert.AlertType),
					slog.Uint64("pid", uint64(evt.TGID)),
					slog.Uint64("tid", uint64(evt.PID)),
					slog.Uint64("uid", uint64(evt.UID)),
					slog.Uint64("gid", uint64(evt.GID)),
					slog.String("comm", evt.Comm),
					slog.String("original_destination", alert.OriginalDestination),
					slog.String("redirected_destination", alert.RedirectDestination),
					slog.String("exe", snap.Exe),
					slog.Any("cmdline", snap.Cmdline),
					slog.String("cwd", snap.Cwd),
					slog.Uint64("ppid", uint64(snap.PPID)),
					slog.Any("ancestry", snap.Ancestry),
					slog.String("mitigation_action", cfg.Action),
					slog.String("mitigation_result", mitigationResult),
					slog.Bool("process_exited", snap.Exited),
				)
			}

			// Dispatch webhook notification
			if cfg.WebhookURL != "" {
				webhookSender.Send(alert)
			}
		})

		if err := bpfLoader.Start(ctx); err != nil {
			return fmt.Errorf("failed to attach eBPF connect hook: %w", err)
		}
		defer bpfLoader.Close()
	} else {
		logger.Warn("running in dry-run mode: eBPF hook disabled; honeypot active")
	}

	logger.Info("imds-canary daemon running. Press Ctrl+C or send SIGTERM to stop.")

	<-ctx.Done()
	logger.Info("Received termination signal, initiating graceful shutdown...")

	return nil
}
