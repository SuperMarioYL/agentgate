package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
)

// mustParse and threeRulePolicy are defined in policy_test.go / remove_test.go
// and reused here (same package test binary).

// v0.8.0 fix (fix-policy-write-non-atomic): the corruption failure mode that
// the atomic write (temp + fsync + rename) exists to prevent is a crash
// mid-os.WriteFile leaving a truncated / torn policy.yaml. A torn file must be
// REJECTED by Load (so it is never silently treated as an empty/garbage
// policy) — this is the premise that makes atomicity worth having. This is a
// characterization guard: it is green before AND after the fix (Load always
// validated), but it pins down what "a partial file" means so the atomic-write
// tests below have a well-defined failure mode to prevent.
func TestV080LoadRejectsCorruptPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	// Hand-write a truncated / torn YAML exactly like a crash mid-write would
	// leave: cut off in the middle of a double-quoted glob AND an unclosed flow
	// mapping. yaml.Unmarshal must reject this.
	corrupt := []byte("default: ask\nrules:\n  - match: {action: exec, target_glob: \"*npm install")
	if err := os.WriteFile(path, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load must reject a corrupt partial policy.yaml (torn mid-write), got nil")
	}
	// loadOrDefault (cmd/agentgate) delegates to Load when the file exists, so
	// rejecting here means the CLI path rejects the same torn file too.
}

// The atomic write enforces 0o644 on the destination EVEN WHEN the pre-existing
// file had a stricter mode. The old os.WriteFile(path, out, 0o644) only applied
// perm on O_CREATE and so left a 0o600 seed untouched — so this assertion is
// RED against the pre-fix Save and GREEN after. It also guards that the temp
// file is renamed away (no `.agentgate-policy-*` left behind) and that the
// written file is complete, reloadable YAML.
func TestV080SaveAtomicEnforces0644AndLeavesNoPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	// Seed with 0o600 (a mode the old write path would never widen).
	if err := os.WriteFile(path, []byte("default: ask\nrules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := mustParse(t, threeRulePolicy) // reuse the 3-rule seed from remove_test.go
	p.path = path
	if err := p.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// No leftover temp file from the atomic write.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".agentgate-policy-") {
			t.Fatalf("atomic Save leaked a temp file %q (no partial should remain after a successful write)", e.Name())
		}
	}
	// Perm enforced to 0o644 (pre-fix os.WriteFile left the 0o600 seed untouched).
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Fatalf("perm after Save: want 0o644, got %v (pre-fix os.WriteFile left the 0o600 seed untouched)", got)
	}
	// The written file is complete, valid YAML that reloads with all rules.
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload after Save: %v", err)
	}
	if len(reloaded.Rules) != 3 || reloaded.Default != Deny {
		t.Fatalf("round-trip after Save wrong: %d rules, default=%q", len(reloaded.Rules), reloaded.Default)
	}
}

// Same atomic-write contract for Append — the path the gate engine's `--always`
// persistence calls (gate.Engine.appendAlwaysRule -> policy.Append). RED before
// the fix (0o600 seed left untouched, no atomic guarantee) and GREEN after, with
// the appended rule actually firing on reload.
func TestV080AppendAtomicEnforces0644AndLeavesNoPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("default: ask\nrules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rule := Rule{Match: Match{Action: agentctx.ActionExec, TargetGlob: "npm install chalk"}, Decision: Allow}
	if err := Append(path, rule); err != nil {
		t.Fatalf("Append: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".agentgate-policy-") {
			t.Fatalf("atomic Append leaked a temp file %q", e.Name())
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Fatalf("perm after Append: want 0o644, got %v", got)
	}
	// The appended rule fires after reload.
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload after Append: %v", err)
	}
	res := reloaded.Resolve(agentctx.GateRequest{Action: agentctx.ActionExec, Target: "npm install chalk"})
	if res.Decision != Allow {
		t.Fatalf("appended always-rule not honoured after reload: %s", res.Decision)
	}
}

// v0.8.0 fix (fix-fswrite-targetglob-no-env-expand): Rule.matches matched
// TargetGlob literally while scope.go already expanded env in a Scope. The
// shipped `$PWD/**` allow rule therefore never resolved (a literal `$PWD/**`
// is not a prefix of any real path). Now matches applies os.ExpandEnv, mirroring
// scope.go, so `$PWD/**` genuinely covers the working directory.
//
// RED against the pre-fix matcher: `$PWD/**` matched literally matches nothing,
// so the inside path fell through to default deny. GREEN after the fix.
func TestV080TargetGlobEnvExpand(t *testing.T) {
	inside := t.TempDir()
	outside := t.TempDir()
	t.Setenv("PWD", inside) // control $PWD for the glob expansion

	p := mustParse(t, `
default: deny
rules:
  - match: {action: fs_write, target_glob: "$PWD/**"}
    decision: allow
`)
	// A path UNDER $PWD must match the expanded $PWD/** glob (allow).
	inTarget := filepath.Join(inside, "src", "a.go")
	if got := p.Resolve(agentctx.GateRequest{Action: agentctx.ActionFSWrite, Target: inTarget}).Decision; got != Allow {
		t.Errorf("path under $PWD should match the expanded $PWD/** glob, got %s (regression: TargetGlob not env-expanded)", got)
	}
	// A path OUTSIDE $PWD must NOT match (falls through to default deny).
	outTarget := filepath.Join(outside, "x.txt")
	if got := p.Resolve(agentctx.GateRequest{Action: agentctx.ActionFSWrite, Target: outTarget}).Decision; got != Deny {
		t.Errorf("path outside $PWD must NOT match $PWD/**, got %s (glob over-match)", got)
	}

	// The SHIPPED example policy's $PWD/** allow rule now actually resolves
	// against $PWD instead of being a dead letter (regression guard).
	ex, err := Load("policy.yaml.example")
	if err != nil {
		t.Fatalf("load shipped example policy: %v", err)
	}
	if got := ex.Resolve(agentctx.GateRequest{Action: agentctx.ActionFSWrite, Target: filepath.Join(inside, "y.go")}).Decision; got != Allow {
		t.Errorf("shipped example $PWD/** should now match a path under $PWD, got %s (the shipped allow rule was a no-op pre-fix)", got)
	}
}
