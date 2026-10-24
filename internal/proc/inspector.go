package proc

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessNode represents a single process in the execution ancestry tree.
type ProcessNode struct {
	PID     uint32   `json:"pid"`
	PPID    uint32   `json:"ppid"`
	Name    string   `json:"name"`
	Exe     string   `json:"exe"`
	Cmdline []string `json:"cmdline"`
	Cwd     string   `json:"cwd,omitempty"`
}

// ProcessSnapshot contains full attribution information resolved for a target PID.
type ProcessSnapshot struct {
	PID      uint32        `json:"pid"`
	PPID     uint32        `json:"ppid"`
	UID      uint32        `json:"uid"`
	GID      uint32        `json:"gid"`
	Name     string        `json:"name"`
	Exe      string        `json:"exe"`
	Cmdline  []string      `json:"cmdline"`
	Cwd      string        `json:"cwd"`
	Ancestry []ProcessNode `json:"ancestry"`
	Exited   bool          `json:"exited"`
}

// Inspector resolves process metadata and hierarchy from procfs.
type Inspector struct {
	procRoot string
}

// NewInspector creates an Inspector using the default /proc filesystem.
func NewInspector() *Inspector {
	return NewInspectorWithRoot("/proc")
}

// NewInspectorWithRoot creates an Inspector using a specified procfs root (useful for testing).
func NewInspectorWithRoot(root string) *Inspector {
	return &Inspector{procRoot: root}
}

// Inspect collects metadata and builds the ancestor tree for the given PID.
func (i *Inspector) Inspect(pid, uid, gid uint32, fallbackComm string) *ProcessSnapshot {
	snap := &ProcessSnapshot{
		PID:  pid,
		UID:  uid,
		GID:  gid,
		Name: fallbackComm,
	}

	pidDir := filepath.Join(i.procRoot, strconv.FormatUint(uint64(pid), 10))
	if _, err := os.Stat(pidDir); err != nil {
		// Process likely already exited
		snap.Exited = true
		return snap
	}

	// Read /proc/<pid>/exe
	if exe, err := os.Readlink(filepath.Join(pidDir, "exe")); err == nil {
		snap.Exe = exe
	}

	// Read /proc/<pid>/cwd
	if cwd, err := os.Readlink(filepath.Join(pidDir, "cwd")); err == nil {
		snap.Cwd = cwd
	}

	// Read /proc/<pid>/cmdline
	snap.Cmdline = i.readCmdline(filepath.Join(pidDir, "cmdline"))

	// Read /proc/<pid>/status for PPID and Name
	if ppid, name, err := i.readStatus(filepath.Join(pidDir, "status")); err == nil {
		snap.PPID = ppid
		if name != "" {
			snap.Name = name
		}
	}

	// Build process lineage (parent, grandparent, etc.)
	snap.Ancestry = i.resolveAncestry(snap.PPID, 10)

	return snap
}

func (i *Inspector) readCmdline(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	raw := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
	args := make([]string, 0, len(raw))
	for _, arg := range raw {
		if len(arg) > 0 {
			args = append(args, string(arg))
		}
	}
	return args
}

func (i *Inspector) readStatus(path string) (uint32, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()

	var ppid uint32
	var name string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:\t") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:\t"))
		} else if strings.HasPrefix(line, "PPid:\t") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "PPid:\t"))
			if parsed, err := strconv.ParseUint(val, 10, 32); err == nil {
				ppid = uint32(parsed)
			}
		}
	}

	return ppid, name, scanner.Err()
}

func (i *Inspector) resolveAncestry(startPPID uint32, maxDepth int) []ProcessNode {
	var chain []ProcessNode
	currPID := startPPID

	visited := make(map[uint32]bool)

	for depth := 0; depth < maxDepth && currPID > 1; depth++ {
		if visited[currPID] {
			break // prevent loops
		}
		visited[currPID] = true

		pidDir := filepath.Join(i.procRoot, strconv.FormatUint(uint64(currPID), 10))
		if _, err := os.Stat(pidDir); err != nil {
			// Ancestor no longer running
			chain = append(chain, ProcessNode{
				PID:  currPID,
				Name: fmt.Sprintf("[pid %d exited]", currPID),
			})
			break
		}

		node := ProcessNode{PID: currPID}
		if exe, err := os.Readlink(filepath.Join(pidDir, "exe")); err == nil {
			node.Exe = exe
		}
		if cwd, err := os.Readlink(filepath.Join(pidDir, "cwd")); err == nil {
			node.Cwd = cwd
		}
		node.Cmdline = i.readCmdline(filepath.Join(pidDir, "cmdline"))

		if nextPPID, name, err := i.readStatus(filepath.Join(pidDir, "status")); err == nil {
			node.PPID = nextPPID
			node.Name = name
			currPID = nextPPID
		} else {
			break
		}

		chain = append(chain, node)
	}

	return chain
}
