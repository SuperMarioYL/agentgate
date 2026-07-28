// Package audit writes an append-only JSONL trail of every gated decision.
//
// One line per action keeps the log greppable and replayable. The log is the
// post-hoc answer to "what did the agent touch, and what did I allow?".
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/policy"
)

// Entry is one line in the audit log.
type Entry struct {
	Time     time.Time           `json:"time"`
	Action   agentctx.ActionKind `json:"action"`
	Target   string              `json:"target"`
	Intent   string              `json:"intent"`
	Agent    string              `json:"agent"`
	Decision policy.Decision     `json:"decision"`
	// Source records how the decision was reached: "rule", "default",
	// "operator", or "always".
	Source string `json:"source"`
}

// Logger appends entries to a JSONL file. Safe for concurrent use.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
	c  io.Closer
}

// Open opens (creating parent dirs as needed) the audit log for appending.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Logger{w: f, c: f}, nil
}

// NewWriter wraps an arbitrary writer (used in tests).
func NewWriter(w io.Writer) *Logger { return &Logger{w: w} }

// Record writes one entry as a single JSON line.
func (l *Logger) Record(e Entry) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

// Close releases the underlying file, if any.
func (l *Logger) Close() error {
	if l.c != nil {
		return l.c.Close()
	}
	return nil
}

// Read parses every entry from a JSONL audit log. A single malformed or
// truncated line (the common SIGKILLed-agent torn trailing entry, or a crash
// mid-Record's single Write) is SKIPPED, not fatal: the valid entries before
// and after it are still returned with a nil error, so `agentgate audit` stays
// readable without hand-editing the file.
//
// This replaces an earlier json.NewDecoder + `for dec.More()` loop that called
// Decode per entry and returned on the FIRST line that failed to decode — a
// single torn tail discarded even the valid entries decoded before the bad line
// (auditCmd treats any non-IsNotExist error as fatal, so the whole audit
// feature was unreadable until the file was hand-edited). A torn tail no longer
// aborts the read, so auditCmd needs no change.
func Read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []Entry
	s := bufio.NewScanner(f)
	// A single audit line is well under the default 64KiB scan limit, but raise
	// it anyway so a large intent string can never make a valid line unscannable.
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := s.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			// Skip the malformed/truncated line and keep going — a torn tail
			// must not make the whole audit feature unreadable.
			continue
		}
		entries = append(entries, e)
	}
	// Return the valid entries with a nil error so auditCmd prints them even
	// when the file had a torn tail; per the fix, a bad line no longer aborts.
	return entries, nil
}
