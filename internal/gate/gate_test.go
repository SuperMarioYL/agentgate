package gate

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SuperMarioYL/agentgate/internal/audit"
	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/policy"
	"github.com/SuperMarioYL/agentgate/internal/prompt"
)

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func buildNetReq(hostport string) agentctx.GateRequest {
	return agentctx.GateRequest{Action: agentctx.ActionNetEgress, Target: hostport}
}

func newEngine(t *testing.T, src, operatorInput string) (*Engine, *bytes.Buffer) {
	t.Helper()
	pol, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	var log bytes.Buffer
	pr := prompt.New(strings.NewReader(operatorInput), new(bytes.Buffer))
	pr.NoColor = true
	return NewEngine(pol, pr, audit.NewWriter(&log)), &log
}

// m2: filesystem writes are confined to declared paths.
func TestFSGateScopeConfinement(t *testing.T) {
	scope := t.TempDir()
	src := "default: deny\nrules:\n" +
		"  - match: {action: fs_write, target_glob: \"" + scope + "/**\"}\n" +
		"    decision: allow\n" +
		"    scope: \"" + scope + "\"\n"
	eng, _ := newEngine(t, src, "")
	fs := NewFSGate(eng)

	ok, _ := fs.CheckWrite(filepath.Join(scope, "src", "main.go"), "write code", "claude-code")
	if !ok {
		t.Fatal("write inside scope should be allowed")
	}
	bad, _ := fs.CheckWrite("/etc/passwd", "exfiltrate", "claude-code")
	if bad {
		t.Fatal("write outside scope must be denied")
	}
}

// m2: undeclared-host egress is blocked and lands in the audit trail.
func TestNetGateBlocksUndeclaredHost(t *testing.T) {
	src := "default: deny\nrules:\n" +
		"  - match: {action: net_egress, target_glob: \"registry.npmjs.org\"}\n" +
		"    decision: allow\n"
	eng, log := newEngine(t, src, "")
	ng := NewNetGate(eng, "claude-code")

	ok, _ := ng.CheckHost("registry.npmjs.org:443", "fetch chalk")
	if !ok {
		t.Fatal("declared registry should be allowed")
	}
	blocked, _ := ng.CheckHost("evil.example.com:443", "exfiltrate")
	if blocked {
		t.Fatal("undeclared host must be blocked")
	}
	if !strings.Contains(log.String(), "evil.example.com:443") ||
		!strings.Contains(log.String(), `"decision":"deny"`) {
		t.Fatalf("blocked egress not in audit trail:\n%s", log.String())
	}
}

// v0.2.0: Explain is a side-effect-free dry-run — it never prompts, never logs,
// and reports the same decision (including a scope downgrade) Decide would apply.
func TestExplainDryRun(t *testing.T) {
	scope := t.TempDir()
	src := "default: deny\nrules:\n" +
		"  - match: {action: net_egress, target_glob: \"registry.npmjs.org\"}\n" +
		"    decision: allow\n" +
		"  - match: {action: fs_write, target_glob: \"" + scope + "/**\"}\n" +
		"    decision: allow\n" +
		"    scope: \"" + scope + "\"\n"
	eng, log := newEngine(t, src, "")

	allow := eng.Explain(buildNetReq("registry.npmjs.org:443"))
	if allow.Decision != policy.Allow || allow.Source != "rule" {
		t.Fatalf("declared host: want allow/rule, got %s/%s", allow.Decision, allow.Source)
	}
	deny := eng.Explain(buildNetReq("evil.example.com:443"))
	if deny.Decision != policy.Deny || deny.Source != "default" {
		t.Fatalf("undeclared host: want deny/default, got %s/%s", deny.Decision, deny.Source)
	}
	escaped := eng.Explain(agentctx.GateRequest{Action: agentctx.ActionFSWrite, Target: "/etc/passwd"})
	if escaped.Decision != policy.Deny {
		t.Fatalf("write outside scope: want deny, got %s", escaped.Decision)
	}
	if log.Len() != 0 {
		t.Fatalf("Explain must not write to the audit log, got:\n%s", log.String())
	}
}

// m1+m3: an "ask" decision routed to a deny keypress blocks the action.
func TestAskOperatorDeny(t *testing.T) {
	eng, _ := newEngine(t, "default: ask\nrules: []\n", "d\n")
	fs := NewFSGate(eng)
	ok, _ := fs.CheckWrite("/tmp/whatever", "do a thing", "claude-code")
	if ok {
		t.Fatal("operator pressed deny; action must be blocked")
	}
}

// v0.3.0 m4: headless enforce mode. An engine built with a nil prompter (what
// `agentgate run --enforce` constructs) must resolve every "ask" to deny without
// blocking on a TTY — the deny-by-default posture CI relies on.
func TestHeadlessEnforceFailsClosed(t *testing.T) {
	pol, err := policy.Parse([]byte("default: ask\nrules: []\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var log bytes.Buffer
	eng := NewEngine(pol, nil, audit.NewWriter(&log)) // nil prompter == headless
	fs := NewFSGate(eng)

	ok, err := fs.CheckWrite("/tmp/whatever", "do a thing", "ci-agent")
	if err != nil {
		t.Fatalf("headless decide errored: %v", err)
	}
	if ok {
		t.Fatal("headless enforce must deny an `ask` (deny-by-default), not allow")
	}
	if !strings.Contains(log.String(), `"decision":"deny"`) {
		t.Fatalf("headless deny not recorded in audit trail:\n%s", log.String())
	}
}

// v0.3.0 fix: a write routed through a symlink that escapes the declared scope
// must be denied by the fs gate, end to end.
func TestFSGateRejectsSymlinkScopeEscape(t *testing.T) {
	root := t.TempDir()
	scope := filepath.Join(root, "scope")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(scope, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	src := "default: deny\nrules:\n" +
		"  - match: {action: fs_write, target_glob: \"" + scope + "/**\"}\n" +
		"    decision: allow\n" +
		"    scope: \"" + scope + "\"\n"
	eng, _ := newEngine(t, src, "")
	fs := NewFSGate(eng)

	if ok, _ := fs.CheckWrite(filepath.Join(scope, "ok.txt"), "legit", "claude-code"); !ok {
		t.Fatal("a genuine in-scope write must still be allowed")
	}
	if ok, _ := fs.CheckWrite(filepath.Join(link, "secret"), "exfiltrate", "claude-code"); ok {
		t.Fatal("a write through an in-scope symlink that escapes scope must be denied")
	}
}

// m3: an "ask" routed to [A]lways allows and persists a rule.
func TestAlwaysPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	src := "default: ask\nrules: []\n"
	if err := writeFile(path, src); err != nil {
		t.Fatal(err)
	}
	pol, _ := policy.Load(path)
	pr := prompt.New(strings.NewReader("A\n"), new(bytes.Buffer))
	pr.NoColor = true
	eng := NewEngine(pol, pr, audit.NewWriter(new(bytes.Buffer)))
	eng.SetPersistPath(path)

	ng := NewNetGate(eng, "claude-code")
	ok, _ := ng.CheckHost("api.example.com:443", "first time")
	if !ok {
		t.Fatal("Always choice should allow")
	}
	// A second, non-interactive engine loading the same file must now allow it.
	reloaded, _ := policy.Load(path)
	res := reloaded.Resolve(buildNetReq("api.example.com:443"))
	if res.Decision != policy.Allow {
		t.Fatalf("Always did not persist an allow rule: %s", res.Decision)
	}
}

// v0.4.0 regression: [A]lways on an exec action must persist a RE-USABLE glob, not
// the verbatim command line. Pressing [A]lways on `npm install left-pad` previously
// persisted target_glob="npm install left-pad" (no wildcards) so it only re-matched
// that exact argv; `npm install chalk` re-prompted, defeating --always. The fix
// derives "<bin> <subcommand>*" (e.g. "npm install*").
func TestAlwaysExecPersistsReusableGlob(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := writeFile(path, "default: ask\nrules: []\n"); err != nil {
		t.Fatal(err)
	}
	pol, _ := policy.Load(path)
	pr := prompt.New(strings.NewReader("A\n"), new(bytes.Buffer))
	pr.NoColor = true
	eng := NewEngine(pol, pr, audit.NewWriter(new(bytes.Buffer)))
	eng.SetPersistPath(path)

	// Operator presses [A]lways on `npm install left-pad`.
	first := agentctx.GateRequest{
		Action: agentctx.ActionExec,
		Target: "npm install left-pad",
		Args:   []string{"npm", "install", "left-pad"},
		Agent:  "claude-code",
	}
	if dec, _ := eng.Decide(first); dec != policy.Allow {
		t.Fatalf("Always on exec should allow, got %s", dec)
	}

	// A reloaded policy must now auto-ALLOW a sibling install without prompting.
	reloaded, _ := policy.Load(path)
	for _, sibling := range []string{"npm install chalk", "npm install left-pad --save"} {
		res := reloaded.Resolve(agentctx.GateRequest{
			Action: agentctx.ActionExec,
			Target: sibling,
			Args:   strings.Fields(sibling),
		})
		if res.Decision != policy.Allow {
			t.Fatalf("--always on `npm install left-pad` should auto-allow %q (re-usable glob), got %s",
				sibling, res.Decision)
		}
	}
	// But it must NOT over-broaden to a different binary/subcommand.
	pip := reloaded.Resolve(agentctx.GateRequest{
		Action: agentctx.ActionExec,
		Target: "pip install requests",
		Args:   []string{"pip", "install", "requests"},
	})
	if pip.Decision == policy.Allow {
		t.Fatal("--always on `npm install` must not allow `pip install requests`")
	}
}

// v0.9.0 regression (fix-always-netegress-hostport-verbatim): [A]lways on a
// net_egress action must persist the BARE host, not the verbatim host:port. The
// runtime net_egress Target is the host:port the redirect proxy passes to
// CheckHost, so [A]lways on registry.npmjs.org:443 previously persisted
// target_glob="registry.npmjs.org:443"; hostTokenMatch then only re-matched that
// exact host:port (it rejects :80), so the next egress to the same host on port
// :80 re-prompted — defeating the operator's "stop asking me" intent. The fix
// strips the port so a bare-host rule auto-allows the host on any port.
func TestAlwaysNetEgressPersistsBareHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := writeFile(path, "default: ask\nrules: []\n"); err != nil {
		t.Fatal(err)
	}
	pol, _ := policy.Load(path)
	pr := prompt.New(strings.NewReader("A\n"), new(bytes.Buffer))
	pr.NoColor = true
	eng := NewEngine(pol, pr, audit.NewWriter(new(bytes.Buffer)))
	eng.SetPersistPath(path)

	ng := NewNetGate(eng, "claude-code")
	if ok, _ := ng.CheckHost("registry.npmjs.org:443", "first time"); !ok {
		t.Fatal("[A]lways on :443 should allow")
	}
	// A reloaded policy must have persisted the BARE host glob, and that rule
	// must auto-ALLOW the same host on a DIFFERENT port (:80) without
	// re-prompting — hostTokenMatch handles any port on a bare-host rule.
	reloaded, _ := policy.Load(path)
	if len(reloaded.Rules) == 0 || reloaded.Rules[0].Match.TargetGlob != "registry.npmjs.org" {
		t.Fatalf("persisted glob should be bare host \"registry.npmjs.org\", got %+v", reloaded.Rules)
	}
	if res := reloaded.Resolve(buildNetReq("registry.npmjs.org:80")); res.Decision != policy.Allow {
		t.Fatalf("bare-host always rule should auto-allow :80, got %s", res.Decision)
	}
	// And it must NOT over-broaden to a different host (suffix/prefix attack),
	// which hostTokenMatch already rejects.
	if res := reloaded.Resolve(buildNetReq("registry.npmjs.org.evil.com:80")); res.Decision == policy.Allow {
		t.Fatal("bare-host rule must not allow a suffix-attack host")
	}
}

// v0.9.0 fix (fix-always-without-policy-file-lies-remembered wiring):
// SetPersistPath must propagate the persist state to the prompter, so the
// [A]lways prompt can honestly say "remembered" only when a policy file will
// actually be written (and "not remembered" otherwise). A non-empty path enables
// persistence; an empty path (no policy file / built-in default) disables it.
func TestSetPersistPathPropagatesToPrompter(t *testing.T) {
	pr := prompt.New(strings.NewReader(""), new(bytes.Buffer))
	pol, _ := policy.Parse([]byte("default: ask\nrules: []\n"))
	eng := NewEngine(pol, pr, nil)
	if pr.Persist {
		t.Fatal("a new prompter must default to Persist=false")
	}
	eng.SetPersistPath(filepath.Join(t.TempDir(), "policy.yaml"))
	if !pr.Persist {
		t.Fatal("SetPersistPath(non-empty) must set prompter.Persist=true so [A]lways can honestly say remembered")
	}
	eng.SetPersistPath("")
	if pr.Persist {
		t.Fatal("SetPersistPath(\"\") must set prompter.Persist=false so [A]lways honestly says not remembered")
	}
}

// captureStderr swaps os.Stderr for a pipe for the duration of fn, runs fn,
// then drains whatever the code under test wrote to stderr. The restore and the
// close happen in t.Cleanup so os.Stderr is put back even if fn calls
// t.Fatalf (which runtime.Goexits past the normal return path). The gate
// engine is single-goroutine and writes at most one short notice, so there is
// no cross-goroutine access to os.Stderr here.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = old
		_ = w.Close()
		_ = r.Close()
	})
	done := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	_ = w.Close() // signal EOF so the reader drains and returns
	return <-done
}

// v0.10.0 regression (fix-always-persist-swallow-misleads-operator): when the
// operator presses [A]lways but policy.Append fails (disk full, permission,
// file deleted between Load and the atomic write), the gate must NOT silently
// swallow the error after the prompt already said "remembered". The action
// stays allowed (the operator did press [A]lways), but the failure is surfaced
// on stderr and the audit row is attributed to the operator's live choice
// (Source="operator"), NOT to a remembered "always" rule that was never written.
// RED before the fix: appendAlwaysRule did `if err := Append(...); err != nil {
// return }` (swallowed) and resolveAsk returned Source="always" regardless.
func TestAlwaysPersistFailureSurfacedAndAttributedToOperator(t *testing.T) {
	pol, err := policy.Parse([]byte("default: ask\nrules: []\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var log bytes.Buffer
	pr := prompt.New(strings.NewReader("A\n"), new(bytes.Buffer))
	pr.NoColor = true
	eng := NewEngine(pol, pr, audit.NewWriter(&log))
	// Persist path inside a directory that does not exist: Append's Load
	// (os.ReadFile) fails, so the persist genuinely fails.
	eng.SetPersistPath(filepath.Join(t.TempDir(), "missing-subdir", "policy.yaml"))

	stderr := captureStderr(t, func() {
		dec, _ := eng.Decide(buildNetReq("api.example.com:443"))
		if dec != policy.Allow {
			t.Fatalf("operator pressed [A]lways; action must still be allowed even though persist failed, got %s", dec)
		}
	})
	if !strings.Contains(stderr, "persistence failed") || !strings.Contains(stderr, "rule NOT remembered") {
		t.Fatalf("a failed persist must be surfaced on stderr (the prompt already said \"remembered\"); got:\n%s", stderr)
	}
	// The audit row must reflect that no rule was actually persisted: Source
	// "operator" (the live choice), NOT "always" (a remembered rule).
	auditOut := log.String()
	if !strings.Contains(auditOut, `"source":"operator"`) {
		t.Fatalf("audit must record source=operator when persist failed, got:\n%s", auditOut)
	}
	if strings.Contains(auditOut, `"source":"always"`) {
		t.Fatalf("audit must NOT record source=always when persist failed, got:\n%s", auditOut)
	}
}

// v0.10.0 regression (fix-always-rule-prepend-shadows-explicit-deny), gate path:
// pressing [A]lways on an action matched by an ask rule must insert the allow
// rule immediately BEFORE that ask rule (plumbing the matched ask Rule's index
// from Decide through appendAlwaysRule into Append), not at the FRONT of the
// whole list. A front-prepend shadows every preceding explicit deny. Here
// `deny *npm install evil*` sits above `ask *npm install*`; after [A]lways on
// `npm install legit` the always-allow `npm install*` must NOT bypass the
// explicit deny, so `npm install evil-pkg` is still DENIED. RED before the fix.
func TestAlwaysDoesNotShadowExplicitDeny(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	src := "default: deny\nrules:\n" +
		"  - match: {action: exec, target_glob: \"*npm install evil*\"}\n" +
		"    decision: deny\n" +
		"  - match: {action: exec, target_glob: \"*npm install*\"}\n" +
		"    decision: ask\n"
	if err := writeFile(path, src); err != nil {
		t.Fatal(err)
	}
	pol, _ := policy.Load(path)
	pr := prompt.New(strings.NewReader("A\n"), new(bytes.Buffer))
	pr.NoColor = true
	eng := NewEngine(pol, pr, audit.NewWriter(new(bytes.Buffer)))
	eng.SetPersistPath(path)

	legit := agentctx.GateRequest{
		Action: agentctx.ActionExec,
		Target: "npm install legit",
		Args:   []string{"npm", "install", "legit"},
		Agent:  "claude-code",
	}
	if dec, _ := eng.Decide(legit); dec != policy.Allow {
		t.Fatalf("[A]lways on a legit install should allow, got %s", dec)
	}

	reloaded, _ := policy.Load(path)
	// The explicit deny ABOVE the ask rule must keep precedence: the always-allow
	// rule was inserted before the ask rule (not at the front), so an "evil"
	// install matching both the deny and the allow globs is still DENIED.
	evil := agentctx.GateRequest{Action: agentctx.ActionExec, Target: "npm install evil-pkg"}
	if got := reloaded.Resolve(evil).Decision; got != policy.Deny {
		t.Fatalf("explicit deny must NOT be shadowed by the --always allow; got %s", got)
	}
	// And the legit install the operator allowed is now auto-allowed (the ask
	// rule is shadowed, so --always genuinely stops re-prompting).
	if got := reloaded.Resolve(legit).Decision; got != policy.Allow {
		t.Fatalf("[A]lways should auto-allow the legit install on reload, got %s", got)
	}
}
