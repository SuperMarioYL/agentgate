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
	"strings"
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

// Read parses every entry from a JSONL audit log. It is robust to a single
// malformed or truncated line — the common case being a partial TRAILING entry
// left behind when an agent run is SIGKILLed mid-write: malformed lines are
// skipped rather than aborting the whole read, so `agentgate audit` stays
// readable after a crash. Valid entries before and after a bad line are returned.
//
// An append-only JSONL log's value is durability; one truncated byte must not make
// the entire trail unreadable (the v0.6.0 json.NewDecoder+dec.More loop aborted on
// the first malformed line, and auditCmd treated any error as fatal).
func Read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []Entry
	sc := bufio.NewScanner(f)
	// A single JSONL entry can be large (a long argv / intent string); raise the
	// per-line limit so we don't skip a legitimate entry under the default 64KiB cap.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // 1 MiB max per line
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			// Skip malformed lines instead of aborting the read; a truncated trailing
			// entry must not make the whole trail unreadable.
			continue
		}
		entries = append(entries, e)
	}
	// A real I/O error (not a malformed line) still propagates.
	if err := sc.Err(); err != nil {
		return entries, fmt.Errorf("read audit log: %w", err)
	}
	return entries, nil
}
