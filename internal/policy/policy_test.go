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

// A bare host token must match on a host boundary, never a bare substring:
// an allow rule for `github.com` must not leak egress to look-alike hosts.
func TestHostTokenBoundary(t *testing.T) {
	p := mustParse(t, `
default: deny
rules:
  - match: {action: net_egress, target_glob: "github.com"}
    decision: allow
`)
	allow := []string{"github.com", "github.com:443"}
	for _, tgt := range allow {
		if got := p.Resolve(agentctx.GateRequest{Action: agentctx.ActionNetEgress, Target: tgt}).Decision; got != Allow {
			t.Errorf("declared host %q should be allowed, got %s", tgt, got)
		}
	}
	deny := []string{"github.com.evil.com:443", "notgithub.com:443", "evilgithub.com:443", "github.com.attacker:80"}
	for _, tgt := range deny {
		if got := p.Resolve(agentctx.GateRequest{Action: agentctx.ActionNetEgress, Target: tgt}).Decision; got == Allow {
			t.Errorf("look-alike host %q must NOT be allowed (egress allowlist bypass)", tgt)
		}
	}
}

// A leading-dot token scopes a rule to a subdomain tree without matching the
// apex, so `.github.com` covers `api.github.com` but not `github.com` itself.
func TestHostTokenSubdomain(t *testing.T) {
	p := mustParse(t, `
default: deny
rules:
  - match: {action: net_egress, target_glob: ".github.com"}
    decision: allow
`)
	if p.Resolve(agentctx.GateRequest{Action: agentctx.ActionNetEgress, Target: "api.github.com:443"}).Decision != Allow {
		t.Fatal("subdomain api.github.com should match .github.com")
	}
	if p.Resolve(agentctx.GateRequest{Action: agentctx.ActionNetEgress, Target: "github.com:443"}).Decision == Allow {
		t.Fatal(".github.com must not match the bare apex github.com")
	}
	if p.Resolve(agentctx.GateRequest{Action: agentctx.ActionNetEgress, Target: "evilgithub.com:443"}).Decision == Allow {
		t.Fatal(".github.com must not splice onto evilgithub.com")
	}
}

// Reproduction for the v0.3.0 fix: a `**` glob suffix must anchor to the END of
// the target, never match as a mid-string substring. Before the fix
// `/proj/**.env` over-matched `/proj/.env.backup/passwd`, silently widening
// allow/scope rules — the same over-match class the v0.2.0 net host-token fix
// closed, here for path/`**` globs.
func TestDoubleStarSuffixDoesNotOvermatchSubstring(t *testing.T) {
	if !globMatch("/proj/**.env", "/proj/config/app.env") {
		t.Fatal("`**.env` should match a path that genuinely ends in .env")
	}
	if globMatch("/proj/**.env", "/proj/.env.backup/passwd") {
		t.Fatal("`**.env` must NOT match a path where .env is only a mid-string substring (scope over-match)")
	}
	if globMatch("/proj/**.env", "/proj/secret.env.bak") {
		t.Fatal("`**.env` must NOT match when .env is not the actual suffix")
	}
	// The prefix is still required.
	if globMatch("/proj/**.env", "/other/app.env") {
		t.Fatal("`**.env` must still respect its prefix")
	}
}

// Reproduction for the v0.3.0 high-severity fix: a symlink that lives inside the
// declared scope but points outside it must NOT let a write escape confinement.
// The lexical-only check accepted the in-scope path; WithinScope now resolves
// symlinks first.
func TestWithinScopeRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	scope := filepath.Join(root, "scope")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink INSIDE scope pointing OUTSIDE it.
	link := filepath.Join(scope, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	r := &Rule{Scope: scope}

	// A real file directly inside scope is still fine.
	if !r.WithinScope(filepath.Join(scope, "ok.txt")) {
		t.Fatal("a path genuinely inside scope must be within")
	}
	// Writing THROUGH the symlink lands outside scope and must be rejected,
	// even though the lexical path scope/escape/secret is "inside" scope.
	if r.WithinScope(filepath.Join(link, "secret")) {
		t.Fatal("a write through an in-scope symlink that escapes scope must be rejected (sandbox bypass)")
	}
}

// A symlinked scope root itself must still confine writes correctly: resolving
// both sides means a legitimately in-scope write is not falsely rejected.
func TestWithinScopeResolvesScopeRootSymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	linkedScope := filepath.Join(root, "linked")
	if err := os.Symlink(real, linkedScope); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	r := &Rule{Scope: linkedScope}
	if !r.WithinScope(filepath.Join(linkedScope, "a.go")) {
		t.Fatal("a write inside a symlinked scope root must be within scope")
	}
	if !r.WithinScope(filepath.Join(real, "a.go")) {
		t.Fatal("a write to the resolved scope path must be within scope")
	}
	if r.WithinScope(filepath.Join(root, "elsewhere", "x")) {
		t.Fatal("a write outside the resolved scope must be rejected")
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
