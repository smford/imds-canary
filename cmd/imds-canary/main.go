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

	"github.com/smford/imds-canary/internal/bpf"
	"github.com/smford/imds-canary/internal/config"
	"github.com/smford/imds-canary/internal/honeypot"
	"github.com/smford/imds-canary/internal/proc"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.ParseFlags(args)
	if err != nil {
		return err
	}

	// Initialize structured slog JSON logger
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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	logger.Info("Starting imds-canary daemon",
		slog.String("version", "1.0.0"),
		slog.Uint64("honeypot_port", uint64(cfg.HoneypotPort)),
		slog.String("cgroup_path", cfg.CgroupPath),
		slog.String("canary_role", cfg.Credentials.RoleName),
		slog.Bool("dry_run", cfg.DryRun),
	)

	// Check privileges unless dry-run
	if !cfg.DryRun && runtime.GOOS == "linux" {
		if os.Geteuid() != 0 {
			return fmt.Errorf("insufficient privileges: imds-canary requires root (or CAP_BPF / CAP_NET_ADMIN) to attach eBPF cgroup socket programs")
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Initialize Process Attribution Inspector
	inspector := proc.NewInspector()

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
			// Resolve process lineage and command-line metadata asynchronously
			snap := inspector.Inspect(evt.TGID, evt.UID, evt.GID, evt.Comm)

			logger.Warn("SECURITY ALERT: AWS IMDS Interception",
				slog.String("alert_type", "IMDS_PROBE_DETECTED"),
				slog.Uint64("pid", uint64(evt.TGID)),
				slog.Uint64("tid", uint64(evt.PID)),
				slog.Uint64("uid", uint64(evt.UID)),
				slog.Uint64("gid", uint64(evt.GID)),
				slog.String("comm", evt.Comm),
				slog.String("original_destination", fmt.Sprintf("%s:%d", evt.OrigDstIP, evt.TargetPort)),
				slog.String("redirected_destination", fmt.Sprintf("%s:%d", evt.RedirDstIP, evt.RedirPort)),
				slog.String("exe", snap.Exe),
				slog.Any("cmdline", snap.Cmdline),
				slog.String("cwd", snap.Cwd),
				slog.Uint64("ppid", uint64(snap.PPID)),
				slog.Any("ancestry", snap.Ancestry),
				slog.Bool("process_exited", snap.Exited),
			)
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
