package gate

import (
	"bytes"
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
