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

// v0.9.0 regression (fix-audit-read-malformed-line): a single malformed or
// truncated JSONL line must not make Read (and therefore `agentgate audit`) fail
// closed and print nothing. The common case is a SIGKILLed-agent torn trailing
// entry or a crash mid-Record's single Write. The earlier json.NewDecoder +
// `for dec.More()` loop returned on the FIRST decode error, discarding even the
// valid entries decoded before the bad line; auditCmd treats any non-IsNotExist
// error as fatal, so the whole audit feature was unreadable until the file was
// hand-edited. Read now skips the bad line(s) and returns the valid entries
// with a nil error.
func TestReadSkipsMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// Two valid entries, a truncated line BETWEEN them, and a torn trailing
	// partial entry (no newline) at the end. Read must skip both bad lines and
	// return the two valid entries — including the one AFTER the middle bad line
	// (which the old decoder never reached).
	good1 := `{"action":"exec","target":"npm install chalk","decision":"allow","source":"operator"}`
	badMiddle := `{"action":"exec","target":"npm install ch` // truncated JSON (crash mid-Write)
	good2 := `{"action":"net_egress","target":"evil.test:443","decision":"deny","source":"rule"}`
	tornTail := `{"action":"fs_write","target":"/tmp/x","decision":"ask","source":"defa` // SIGKILLed torn entry
	content := good1 + "\n" + badMiddle + "\n" + good2 + "\n" + tornTail
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := Read(path)
	if err != nil {
		t.Fatalf("a malformed line must not make Read fail (skip and continue): %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 valid entries (malformed middle + torn tail skipped), got %d: %+v", len(entries), entries)
	}
	if entries[0].Target != "npm install chalk" || entries[0].Decision != policy.Allow {
		t.Fatalf("first valid entry wrong: %+v", entries[0])
	}
	if entries[1].Target != "evil.test:443" || entries[1].Decision != policy.Deny {
		t.Fatalf("second valid entry (after the malformed line) wrong: %+v", entries[1])
	}
}
