package proc

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInspector_Inspect(t *testing.T) {
	tempDir := t.TempDir()

	// Create mock process tree:
	// PID 100 (Grandparent) -> PID 200 (Parent) -> PID 300 (Target)

	// PID 100
	pid100Dir := filepath.Join(tempDir, "100")
	if err := os.MkdirAll(pid100Dir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(pid100Dir, "status"), []byte("Name:\tinit\nPPid:\t0\n"), 0644)
	_ = os.WriteFile(filepath.Join(pid100Dir, "cmdline"), []byte("/sbin/init\x00"), 0644)

	// PID 200
	pid200Dir := filepath.Join(tempDir, "200")
	if err := os.MkdirAll(pid200Dir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(pid200Dir, "status"), []byte("Name:\tbash\nPPid:\t100\n"), 0644)
	_ = os.WriteFile(filepath.Join(pid200Dir, "cmdline"), []byte("bash\x00-l\x00"), 0644)

	// PID 300
	pid300Dir := filepath.Join(tempDir, "300")
	if err := os.MkdirAll(pid300Dir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(pid300Dir, "status"), []byte("Name:\tcurl\nPPid:\t200\n"), 0644)
	_ = os.WriteFile(filepath.Join(pid300Dir, "cmdline"), []byte("curl\x00http://169.254.169.254\x00"), 0644)

	inspector := NewInspectorWithRoot(tempDir)
	snap := inspector.Inspect(300, 1000, 1000, "curl")

	if snap.PID != 300 {
		t.Errorf("expected PID 300, got %d", snap.PID)
	}
	if snap.Name != "curl" {
		t.Errorf("expected name 'curl', got %s", snap.Name)
	}
	if snap.PPID != 200 {
		t.Errorf("expected PPID 200, got %d", snap.PPID)
	}
	expectedCmdline := []string{"curl", "http://169.254.169.254"}
	if !reflect.DeepEqual(snap.Cmdline, expectedCmdline) {
		t.Errorf("expected cmdline %v, got %v", expectedCmdline, snap.Cmdline)
	}
	if len(snap.Ancestry) != 2 {
		t.Fatalf("expected 2 ancestors, got %d", len(snap.Ancestry))
	}
	if snap.Ancestry[0].PID != 200 {
		t.Errorf("expected parent PID 200, got %d", snap.Ancestry[0].PID)
	}
	if snap.Ancestry[0].Name != "bash" {
		t.Errorf("expected parent name bash, got %s", snap.Ancestry[0].Name)
	}
	if snap.Ancestry[1].PID != 100 {
		t.Errorf("expected grandparent PID 100, got %d", snap.Ancestry[1].PID)
	}
	if snap.Ancestry[1].Name != "init" {
		t.Errorf("expected grandparent name init, got %s", snap.Ancestry[1].Name)
	}
}

func TestInspector_ExitedProcess(t *testing.T) {
	tempDir := t.TempDir()
	inspector := NewInspectorWithRoot(tempDir)

	snap := inspector.Inspect(99999, 1000, 1000, "shortlived")
	if !snap.Exited {
		t.Error("expected snap.Exited to be true")
	}
	if snap.Name != "shortlived" {
		t.Errorf("expected fallback comm 'shortlived', got %s", snap.Name)
	}
}
