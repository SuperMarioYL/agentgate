package wrap

import (
	"bytes"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SuperMarioYL/agentgate/internal/audit"
	"github.com/SuperMarioYL/agentgate/internal/gate"
	"github.com/SuperMarioYL/agentgate/internal/policy"
	"github.com/SuperMarioYL/agentgate/internal/prompt"
)

// startBroker spins up just the broker half of the Runner over a unix socket
// and returns its path, so we can exercise the m1 gate decision without a real
// agent process.
func startBroker(t *testing.T, pol string, operatorInput string) (string, *bytes.Buffer) {
	t.Helper()
	p, err := policy.Parse([]byte(pol))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	var log bytes.Buffer
	pr := prompt.New(strings.NewReader(operatorInput), new(bytes.Buffer))
	pr.NoColor = true
	eng := gate.NewEngine(p, pr, audit.NewWriter(&log))
	r := NewRunner(eng, "claude-code", "agentgate")

	sock := filepath.Join(t.TempDir(), "broker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go r.serveBroker(ln)
	return sock, &log
}

func askBroker(t *testing.T, sock string, args []string) brokerReply {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial broker: %v", err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(brokerRequest{Args: args, Cwd: "/proj"}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var reply brokerReply
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return reply
}

// m1: a denied npm install is refused by the broker (so the shim never execs it),
// while an allowed one is permitted.
func TestBrokerGatesExec(t *testing.T) {
	pol := `
default: deny
rules:
  - match: {action: exec, target_glob: "*npm install chalk*"}
    decision: allow
  - match: {action: exec, target_glob: "*npm install*"}
    decision: deny
`
	sock, log := startBroker(t, pol, "")

	allowed := askBroker(t, sock, []string{"npm", "install", "chalk"})
	if !allowed.Allow {
		t.Fatalf("npm install chalk should be allowed, got %+v", allowed)
	}
	denied := askBroker(t, sock, []string{"npm", "install", "left-pad"})
	if denied.Allow {
		t.Fatalf("npm install left-pad should be denied, got %+v", denied)
	}

	// The intent string the agent never typed must show up in the audit trail.
	if !strings.Contains(log.String(), "agent wants to install npm package: left-pad") {
		t.Fatalf("intent not captured in audit log:\n%s", log.String())
	}
}

// m1: an "ask" exec resolved by an operator 'a' keypress is allowed.
func TestBrokerAskAllow(t *testing.T) {
	sock, _ := startBroker(t, "default: ask\nrules: []\n", "a\n")
	reply := askBroker(t, sock, []string{"pip", "install", "requests"})
	if !reply.Allow {
		t.Fatalf("operator pressed allow; expected allow, got %+v", reply)
	}
}

func TestInterceptedCommandsNonEmpty(t *testing.T) {
	if len(InterceptedCommands) == 0 {
		t.Fatal("no intercepted commands configured")
	}
	found := false
	for _, c := range InterceptedCommands {
		if c == "npm" {
			found = true
		}
	}
	if !found {
		t.Fatal("npm must be intercepted")
	}
}
