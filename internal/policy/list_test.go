package policy

import (
	"bytes"
	"strings"
	"testing"
)

// (mustParse is defined in policy_test.go — reused here.)

// Effective lists every rule in first-match-wins order, then a synthetic default
// row, with empty action/glob rendered as "any".
func TestEffectiveOrderAndDefault(t *testing.T) {
	src := "default: deny\nrules:\n" +
		"  - match: {action: exec, target_glob: \"npm install*\"}\n" +
		"    decision: allow\n" +
		"  - match: {action: fs_write, target_glob: \"/proj/**\"}\n" +
		"    decision: allow\n" +
		"    scope: \"/proj\"\n" +
		"  - match: {}\n" +
		"    decision: ask\n"
	views := mustParse(t, src).Effective()

	if len(views) != 4 { // 3 rules + default row
		t.Fatalf("want 4 views (3 rules + default), got %d", len(views))
	}
	if views[0].Index != 1 || views[0].Action != "exec" || views[0].TargetGlob != "npm install*" || views[0].Decision != Allow {
		t.Fatalf("rule 1 wrong: %+v", views[0])
	}
	if views[1].Scope != "/proj" {
		t.Fatalf("rule 2 should carry scope, got %q", views[1].Scope)
	}
	// An action-less / glob-less rule renders both as "any".
	if views[2].Action != "any" || views[2].TargetGlob != "any" {
		t.Fatalf("empty match should render as any/any, got %+v", views[2])
	}
	// Last row is the synthetic default.
	last := views[len(views)-1]
	if !last.IsDefault || last.Index != 0 || last.Decision != Deny {
		t.Fatalf("default row wrong: %+v", last)
	}
}

// WriteTable emits a header, every rule, and the default marker, in order.
func TestWriteTableContainsRulesAndDefault(t *testing.T) {
	src := "default: deny\nrules:\n" +
		"  - match: {action: net_egress, target_glob: \"registry.npmjs.org\"}\n" +
		"    decision: allow\n"
	var buf bytes.Buffer
	if err := mustParse(t, src).WriteTable(&buf); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"effective policy", "net_egress", "registry.npmjs.org", "allow", "deny", "default"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table output missing %q\n---\n%s", want, out)
		}
	}
	// The default row must come AFTER the concrete rule (first-match-wins order).
	if strings.Index(out, "registry.npmjs.org") > strings.LastIndex(out, "deny") {
		t.Fatal("default row should render after the concrete rules")
	}
}

// An empty rule set still renders cleanly: just the default.
func TestWriteTableEmptyPolicy(t *testing.T) {
	var buf bytes.Buffer
	if err := mustParse(t, "default: ask\nrules: []\n").WriteTable(&buf); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	if !strings.Contains(buf.String(), "ask") {
		t.Fatalf("empty policy table should show the default decision\n%s", buf.String())
	}
}
