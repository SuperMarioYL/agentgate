package policy

import (
	"os"
	"path/filepath"
	"testing"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
)

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestFirstMatchWins(t *testing.T) {
	p := mustParse(t, `
default: ask
rules:
  - match: {action: exec, target_glob: "*npm install left-pad*"}
    decision: deny
  - match: {action: exec, target_glob: "*npm install*"}
    decision: allow
`)
	deny := p.Resolve(agentctx.GateRequest{Action: agentctx.ActionExec, Target: "npm install left-pad"})
	if deny.Decision != Deny {
		t.Fatalf("expected first (deny) rule to win, got %s", deny.Decision)
	}
	allow := p.Resolve(agentctx.GateRequest{Action: agentctx.ActionExec, Target: "npm install chalk"})
	if allow.Decision != Allow {
		t.Fatalf("expected second (allow) rule, got %s", allow.Decision)
	}
}

func TestDefaultFallthrough(t *testing.T) {
	p := mustParse(t, "rules: []") // no default specified -> ask
	res := p.Resolve(agentctx.GateRequest{Action: agentctx.ActionExec, Target: "anything"})
	if res.Decision != Ask || !res.FromDefault {
		t.Fatalf("want ask/default, got %s fromDefault=%v", res.Decision, res.FromDefault)
	}
}

func TestNetEgressSubstringGlob(t *testing.T) {
	p := mustParse(t, `
default: deny
rules:
  - match: {action: net_egress, target_glob: "registry.npmjs.org"}
    decision: allow
`)
	ok := p.Resolve(agentctx.GateRequest{Action: agentctx.ActionNetEgress, Target: "registry.npmjs.org:443"})
	if ok.Decision != Allow {
		t.Fatalf("host substring match failed: %s", ok.Decision)
	}
	bad := p.Resolve(agentctx.GateRequest{Action: agentctx.ActionNetEgress, Target: "evil.example.com:443"})
	if bad.Decision != Deny {
		t.Fatalf("undeclared host should hit default deny, got %s", bad.Decision)
	}
}

func TestDoubleStarGlob(t *testing.T) {
	if !globMatch("/proj/**", "/proj/a/b/c.txt") {
		t.Fatal("** should match nested path")
	}
	if globMatch("/proj/**", "/other/x") {
		t.Fatal("** should not match outside prefix")
	}
}

func TestWithinScope(t *testing.T) {
	r := &Rule{Scope: "/proj"}
	if !r.WithinScope("/proj/src/a.go") {
		t.Fatal("path inside scope should be within")
	}
	if r.WithinScope("/etc/passwd") {
		t.Fatal("path outside scope must be rejected")
	}
	if !(&Rule{}).WithinScope("/anything") {
		t.Fatal("empty scope imposes no confinement")
	}
}

func TestStarMatchSpansCommandLine(t *testing.T) {
	if !globMatch("*npm install*", "npm install left-pad") {
		t.Fatal("* should span the whole argv")
	}
	if !globMatch("*curl*", "curl -sS http://x/y") {
		t.Fatal("* must match across slashes in a command line")
	}
	if globMatch("*pip install*", "npm install chalk") {
		t.Fatal("non-matching command must not match")
	}
}

func TestInvalidDecisionRejected(t *testing.T) {
	if _, err := Parse([]byte("rules:\n  - match: {}\n    decision: maybe\n")); err == nil {
		t.Fatal("expected invalid decision to error")
	}
}

func TestAppendPersistsRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("default: ask\nrules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := Rule{Match: Match{Action: agentctx.ActionExec, TargetGlob: "npm install chalk"}, Decision: Allow}
	if err := Append(path, rule); err != nil {
		t.Fatalf("append: %v", err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	res := reloaded.Resolve(agentctx.GateRequest{Action: agentctx.ActionExec, Target: "npm install chalk"})
	if res.Decision != Allow {
		t.Fatalf("persisted always-rule not honoured after reload: %s", res.Decision)
	}
}
