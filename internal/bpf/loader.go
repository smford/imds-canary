package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Event is the parsed telemetry event emitted by the eBPF connect4 hook.
type Event struct {
	PID        uint32 `json:"pid"`
	TGID       uint32 `json:"tgid"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	TargetPort uint16 `json:"target_port"`
	RedirPort  uint16 `json:"redir_port"`
	OrigDstIP  string `json:"orig_dst_ip"`
	RedirDstIP string `json:"redir_dst_ip"`
	Comm       string `json:"comm"`
}

// Handler handles incoming BPF events.
type Handler func(Event)

// Loader manages loading, cgroup attachment, and ringbuffer streaming of eBPF programs.
type Loader struct {
	cgroupPath   string
	redirectPort uint16
	logger       *slog.Logger

	objs      bpfObjects
	link      link.Link
	reader    *ringbuf.Reader
	handler   Handler
	closeOnce sync.Once
}

// NewLoader instantiates a Loader.
func NewLoader(cgroupPath string, redirectPort uint16, logger *slog.Logger) *Loader {
	if logger == nil {
		logger = slog.Default()
	}
	return &Loader{
		cgroupPath:   cgroupPath,
		redirectPort: redirectPort,
		logger:       logger,
	}
}

// SetHandler sets the event callback handler.
func (l *Loader) SetHandler(h Handler) {
	l.handler = h
}

// Start loads the eBPF program, attaches to cgroup, and begins consuming ringbuffer events.
func (l *Loader) Start(ctx context.Context) error {
	// Remove memory limits for BPF maps and programs
	if err := rlimit.RemoveMemlock(); err != nil {
		l.logger.Warn("unable to remove memlock rlimit (might require CAP_SYS_RESOURCE)", slog.String("error", err.Error()))
	}

	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("failed to load BPF spec: %w", err)
	}

	// Override default redirect port if customized
	if l.redirectPort != 0 {
		if v, ok := spec.Variables["redirect_port"]; ok {
			if err := v.Set(l.redirectPort); err != nil {
				return fmt.Errorf("failed to set redirect_port variable in BPF spec: %w", err)
			}
		}
	}

	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects into kernel: %w", err)
	}

	// Attach to cgroup connect4 hook
	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    l.cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: l.objs.SockConnect4,
	})
	if err != nil {
		_ = l.objs.Close()
		return fmt.Errorf("failed to attach BPF program to cgroup (%s): %w", l.cgroupPath, err)
	}
	l.link = cgroupLink

	// Open ringbuffer reader
	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		_ = l.link.Close()
		_ = l.objs.Close()
		return fmt.Errorf("failed to open ringbuf reader: %w", err)
	}
	l.reader = rd

	l.logger.Info("eBPF socket hook successfully attached to cgroup",
		slog.String("cgroup", l.cgroupPath),
		slog.Uint64("redirect_port", uint64(l.redirectPort)),
	)

	// Stream events asynchronously
	go l.consume(ctx)

	return nil
}

func (l *Loader) consume(ctx context.Context) {
	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		record, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				l.logger.Debug("ringbuffer reader closed")
				return
			}
			l.logger.Error("error reading from BPF ringbuffer", slog.String("error", err.Error()))
			return
		}

		var raw bpfImdsEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			l.logger.Warn("failed to decode ringbuffer sample", slog.String("error", err.Error()))
			continue
		}

		evt := Event{
			PID:        raw.Pid,
			TGID:       raw.Tgid,
			UID:        raw.Uid,
			GID:        raw.Gid,
			TargetPort: raw.TargetPort,
			RedirPort:  raw.RedirPort,
			OrigDstIP:  ipFromU32(raw.OrigDstIp),
			RedirDstIP: ipFromU32(raw.RedirDstIp),
			Comm:       commToString(raw.Comm),
		}

		if l.handler != nil {
			l.handler(evt)
		}
	}
}

// Close detaches the eBPF program and cleans up kernel objects.
func (l *Loader) Close() error {
	var errs []error
	l.closeOnce.Do(func() {
		l.logger.Info("detaching eBPF program and closing kernel maps")
		if l.reader != nil {
			if err := l.reader.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if l.link != nil {
			if err := l.link.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if err := l.objs.Close(); err != nil {
			errs = append(errs, err)
		}
	})

	return errors.Join(errs...)
}

func ipFromU32(n uint32) string {
	ip := net.IPv4(byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
	return ip.String()
}

func commToString(rawComm [16]int8) string {
	b := make([]byte, 0, len(rawComm))
	for _, c := range rawComm {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return strings.TrimSpace(string(b))
}
