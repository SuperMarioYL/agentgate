package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/policy"
)

func TestRecordWritesJSONL(t *testing.T) {
	var buf bytes.Buffer
	lg := NewWriter(&buf)
	for i := 0; i < 3; i++ {
		if err := lg.Record(Entry{
			Action:   agentctx.ActionExec,
			Target:   "npm install chalk",
			Decision: policy.Allow,
			Source:   "operator",
		}); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1
	if lines != 3 {
		t.Fatalf("expected 3 JSONL lines, got %d:\n%s", lines, buf.String())
	}
	if !strings.Contains(buf.String(), `"action":"exec"`) {
		t.Fatalf("missing action field: %s", buf.String())
	}
}

func TestOpenAppendsAndReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.jsonl")
	lg, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = lg.Record(Entry{Action: agentctx.ActionNetEgress, Target: "evil.test:443", Decision: policy.Deny, Source: "rule"})
	_ = lg.Record(Entry{Action: agentctx.ActionExec, Target: "npm install chalk", Decision: policy.Allow, Source: "operator"})
	lg.Close()

	entries, err := Read(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	if entries[0].Decision != policy.Deny || entries[0].Target != "evil.test:443" {
		t.Fatalf("first entry wrong: %+v", entries[0])
	}
	if entries[0].Time.IsZero() {
		t.Fatal("Record should stamp a time")
	}
}

// v0.7.0 regression: a single malformed/truncated JSONL line — the common case
// being a partial TRAILING entry left when an agent run is SIGKILLed mid-write —
// must NOT make the whole audit log unreadable. Read skips malformed lines and
// returns the valid entries before (and after) the bad one. The v0.6.0
// json.NewDecoder+dec.More loop aborted on the first malformed line, and
// auditCmd treated any error as fatal, so one truncated byte nuked the whole trail.
func TestReadSkipsMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// Two valid entries, then a truncated trailing line, then a valid entry
	// after the bad line to prove the skip is non-fatal (reading resumes).
	content := `{"action":"net_egress","target":"a.test:443","intent":"x","agent":"c","decision":"deny","source":"rule","time":"2026-07-21T07:00:00Z"}
{"action":"exec","target":"npm install chalk","intent":"y","agent":"c","decision":"allow","source":"operator","time":"2026-07-21T07:01:00Z"}
{"action":"exec","target":"truncated
{"action":"net_egress","target":"after.test:443","intent":"z","agent":"c","decision":"deny","source":"rule","time":"2026-07-21T07:02:00Z"}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := Read(path)
	if err != nil {
		t.Fatalf("Read must not fail on a malformed line: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 valid entries (malformed line skipped, reading resumed), got %d: %+v", len(entries), entries)
	}
	if entries[0].Target != "a.test:443" || entries[1].Target != "npm install chalk" || entries[2].Target != "after.test:443" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}
