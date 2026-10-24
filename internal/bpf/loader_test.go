package bpf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestLoader_EventDecoding(t *testing.T) {
	raw := bpfImdsEvent{
		Pid:        1234,
		Tgid:       5678,
		Uid:        1000,
		Gid:        1000,
		TargetPort: 80,
		RedirPort:  18080,
		OrigDstIp:  0xfea9fea9, // 169.254.169.254
		RedirDstIp: 0x0100007f, // 127.0.0.1
	}
	copy(raw.Comm[:], []int8{'c', 'u', 'r', 'l', 0})

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &raw); err != nil {
		t.Fatalf("failed to serialize raw event: %v", err)
	}

	var decoded bpfImdsEvent
	if err := binary.Read(&buf, binary.LittleEndian, &decoded); err != nil {
		t.Fatalf("failed to decode event: %v", err)
	}

	if decoded.Tgid != 5678 {
		t.Errorf("expected TGID 5678, got %d", decoded.Tgid)
	}
	if decoded.Pid != 1234 {
		t.Errorf("expected PID 1234, got %d", decoded.Pid)
	}

	comm := commToString(decoded.Comm)
	if comm != "curl" {
		t.Errorf("expected comm 'curl', got %s", comm)
	}

	origIP := ipFromU32(decoded.OrigDstIp)
	if origIP != "169.254.169.254" {
		t.Errorf("expected orig IP 169.254.169.254, got %s", origIP)
	}

	redirIP := ipFromU32(decoded.RedirDstIp)
	if redirIP != "127.0.0.1" {
		t.Errorf("expected redir IP 127.0.0.1, got %s", redirIP)
	}
}
