// Package audit writes an append-only JSONL trail of every gated decision.
//
// One line per action keeps the log greppable and replayable. The log is the
// post-hoc answer to "what did the agent touch, and what did I allow?".
package audit

import (
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

// Read parses every entry from a JSONL audit log.
func Read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []Entry
	dec := json.NewDecoder(f)
	for dec.More() {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			return entries, fmt.Errorf("decode audit entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}
