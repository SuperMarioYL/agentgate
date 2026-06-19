package audit

import (
	"testing"
	"time"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/policy"
)

func sampleEntries() []Entry {
	base := time.Date(2026, 6, 19, 8, 0, 0, 0, time.UTC)
	return []Entry{
		{Time: base, Action: agentctx.ActionExec, Target: "npm install chalk", Decision: policy.Allow},
		{Time: base.Add(time.Hour), Action: agentctx.ActionNetEgress, Target: "evil.test:443", Decision: policy.Deny},
		{Time: base.Add(2 * time.Hour), Action: agentctx.ActionFSWrite, Target: "/etc/passwd", Decision: policy.Deny},
		{Time: base.Add(3 * time.Hour), Action: agentctx.ActionNetEgress, Target: "registry.npmjs.org:443", Decision: policy.Allow},
	}
}

func TestFilterByDecision(t *testing.T) {
	got := Filter{Decision: policy.Deny}.Apply(sampleEntries())
	if len(got) != 2 {
		t.Fatalf("want 2 denied entries, got %d", len(got))
	}
	for _, e := range got {
		if e.Decision != policy.Deny {
			t.Fatalf("decision filter leaked a non-deny entry: %+v", e)
		}
	}
}

func TestFilterByAction(t *testing.T) {
	got := Filter{Action: agentctx.ActionNetEgress}.Apply(sampleEntries())
	if len(got) != 2 {
		t.Fatalf("want 2 net_egress entries, got %d", len(got))
	}
}

func TestFilterBySince(t *testing.T) {
	cut := time.Date(2026, 6, 19, 10, 30, 0, 0, time.UTC) // between entry[2] and entry[3]
	got := Filter{Since: cut}.Apply(sampleEntries())
	if len(got) != 1 || got[0].Target != "registry.npmjs.org:443" {
		t.Fatalf("since filter wrong: %+v", got)
	}
}

func TestFilterCombined(t *testing.T) {
	got := Filter{Decision: policy.Deny, Action: agentctx.ActionNetEgress}.Apply(sampleEntries())
	if len(got) != 1 || got[0].Target != "evil.test:443" {
		t.Fatalf("combined filter wrong: %+v", got)
	}
}

func TestEmptyFilterReturnsAll(t *testing.T) {
	if len(Filter{}.Apply(sampleEntries())) != 4 {
		t.Fatal("zero filter must return all entries")
	}
}

func TestFilterValidate(t *testing.T) {
	if err := (Filter{Decision: "maybe"}).Validate(); err == nil {
		t.Fatal("bad decision should fail validation")
	}
	if err := (Filter{Action: "telepathy"}).Validate(); err == nil {
		t.Fatal("bad action should fail validation")
	}
	if err := (Filter{Decision: policy.Deny, Action: agentctx.ActionExec}).Validate(); err != nil {
		t.Fatalf("valid filter rejected: %v", err)
	}
}

func TestParseSince(t *testing.T) {
	if z, err := ParseSince(""); err != nil || !z.IsZero() {
		t.Fatalf("empty --since should be zero time, no error: %v %v", z, err)
	}
	if _, err := ParseSince("2026-06-19T08:00:00Z"); err != nil {
		t.Fatalf("RFC3339 should parse: %v", err)
	}
	if _, err := ParseSince("2026-06-19"); err != nil {
		t.Fatalf("date should parse: %v", err)
	}
	rel, err := ParseSince("2h")
	if err != nil {
		t.Fatalf("duration should parse: %v", err)
	}
	if time.Since(rel) < time.Hour {
		t.Fatalf("2h ago should be at least an hour in the past, got %v", rel)
	}
	if _, err := ParseSince("not-a-time"); err == nil {
		t.Fatal("garbage --since should error")
	}
}
