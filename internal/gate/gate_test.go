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

// m1+m3: an "ask" decision routed to a deny keypress blocks the action.
func TestAskOperatorDeny(t *testing.T) {
	eng, _ := newEngine(t, "default: ask\nrules: []\n", "d\n")
	fs := NewFSGate(eng)
	ok, _ := fs.CheckWrite("/tmp/whatever", "do a thing", "claude-code")
	if ok {
		t.Fatal("operator pressed deny; action must be blocked")
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
