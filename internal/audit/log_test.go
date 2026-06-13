package audit

import (
	"bytes"
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
