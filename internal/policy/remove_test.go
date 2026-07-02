package policy

import (
	"path/filepath"
	"testing"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
)

// mustParse is defined in policy_test.go — reused here.

const threeRulePolicy = "default: deny\nrules:\n" +
	"  - match: {action: exec, target_glob: \"npm install*\"}\n" +
	"    decision: allow\n" +
	"  - match: {action: fs_write, target_glob: \"/proj/**\"}\n" +
	"    decision: allow\n" +
	"    scope: \"/proj\"\n" +
	"  - match: {action: net_egress, target_glob: \"registry.npmjs.org\"}\n" +
	"    decision: allow\n"

// RemoveByIndex removes exactly the rule at the printed 1-based index, leaving the
// others in first-match-wins order, and reports the removed rule.
func TestRemoveByIndex(t *testing.T) {
	p := mustParse(t, threeRulePolicy)
	removed, err := p.RemoveByIndex(1)
	if err != nil {
		t.Fatalf("RemoveByIndex(1): %v", err)
	}
	if removed.Match.Action != agentctx.ActionExec || removed.Match.TargetGlob != "npm install*" {
		t.Fatalf("removed the wrong rule: %+v", removed)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("want 2 rules left, got %d", len(p.Rules))
	}
	// The rule that was #2 is now #1.
	if p.Rules[0].Match.Action != agentctx.ActionFSWrite {
		t.Fatalf("after removing #1, the fs_write rule should be first, got %+v", p.Rules[0])
	}

	// The removed exec rule no longer auto-allows: what it used to allow now falls
	// through to the default (deny) — i.e. the grant is genuinely revoked.
	res := p.Resolve(agentctx.GateRequest{Action: agentctx.ActionExec, Target: "npm install chalk"})
	if res.Decision != Deny || !res.FromDefault {
		t.Fatalf("after revoke, `npm install chalk` should hit the default deny, got %+v", res)
	}
}

// RemoveByMatch removes the first rule whose action+glob equal the arguments and
// reports its former index.
func TestRemoveByMatch(t *testing.T) {
	p := mustParse(t, threeRulePolicy)
	removed, idx, err := p.RemoveByMatch("net_egress", "registry.npmjs.org")
	if err != nil {
		t.Fatalf("RemoveByMatch: %v", err)
	}
	if idx != 3 {
		t.Fatalf("net_egress rule was at index 3, got %d", idx)
	}
	if removed.Match.TargetGlob != "registry.npmjs.org" {
		t.Fatalf("removed the wrong rule: %+v", removed)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("want 2 rules left, got %d", len(p.Rules))
	}
}

// A no-match RemoveByMatch is an error and does NOT mutate the policy.
func TestRemoveByMatchNoMatch(t *testing.T) {
	p := mustParse(t, threeRulePolicy)
	_, _, err := p.RemoveByMatch("exec", "pip install*")
	if err == nil {
		t.Fatal("expected an error for a non-matching rule")
	}
	if len(p.Rules) != 3 {
		t.Fatalf("policy must be untouched on no-match, got %d rules", len(p.Rules))
	}
}

// Out-of-range and default-row (index 0) removals error without mutating.
func TestRemoveByIndexOutOfRange(t *testing.T) {
	for _, bad := range []int{0, -1, 4, 99} {
		p := mustParse(t, threeRulePolicy)
		if _, err := p.RemoveByIndex(bad); err == nil {
			t.Fatalf("index %d should error", bad)
		}
		if len(p.Rules) != 3 {
			t.Fatalf("index %d must not mutate the policy, got %d rules", bad, len(p.Rules))
		}
	}
}

// SaveRoundTrip: write a policy, remove a rule, Save, reload — the rule is gone
// and the default survives.
func TestSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	p := mustParse(t, threeRulePolicy)
	p.path = path
	if err := p.Save(path); err != nil {
		t.Fatalf("Save seed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Rules) != 3 || loaded.Default != Deny {
		t.Fatalf("seed round-trip wrong: %d rules, default=%q", len(loaded.Rules), loaded.Default)
	}

	if _, err := loaded.RemoveByIndex(2); err != nil {
		t.Fatalf("RemoveByIndex(2): %v", err)
	}
	if err := loaded.Save(path); err != nil {
		t.Fatalf("Save after remove: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.Rules) != 2 {
		t.Fatalf("persisted policy should have 2 rules, got %d", len(reloaded.Rules))
	}
	if reloaded.Default != Deny {
		t.Fatalf("default should survive Save, got %q", reloaded.Default)
	}
	// The fs_write rule (was #2) must be gone.
	for _, r := range reloaded.Rules {
		if r.Match.Action == agentctx.ActionFSWrite {
			t.Fatalf("removed fs_write rule reappeared after reload: %+v", r)
		}
	}
}
