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

// v0.6.0 security fix: when AGENTGATE_BROKER is set (the process IS under
// `agentgate run`) but the broker is unreachable, the shim must FAIL CLOSED —
// return 126 (blocked) WITHOUT exec'ing the real binary ungated. Point the shim
// at a socket path that does not exist; a successful exec would replace the test
// process (or run the real binary), so reaching the assertion at all proves we
// did not exec.
func TestShimFailsClosedWhenBrokerUnreachable(t *testing.T) {
	dead := filepath.Join(t.TempDir(), "nonexistent-broker.sock")
	t.Setenv("AGENTGATE_BROKER", dead)

	// Use a command that is NOT on PATH so that, even if fail-closed regressed to
	// execReal, execReal would return 127 (not found) rather than replacing the
	// process — either way the code we assert on runs. The point of the assertion
	// is the 126 (fail-closed), distinct from 127 (would-have-exec'd-but-missing).
	code := ShimMain([]string{"npm", "install", "left-pad"})
	if code != 126 {
		t.Fatalf("broker unreachable must fail closed with 126 (no ungated exec), got %d", code)
	}
}

// The helper itself: fail-closed returns 126 and never runs anything.
func TestBrokerUnreachableReturns126(t *testing.T) {
	if code := brokerUnreachable([]string{"curl", "http://evil"}, net.ErrClosed); code != 126 {
		t.Fatalf("brokerUnreachable must return 126, got %d", code)
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

// envLookup returns the value of key in an env slice produced by childEnv.
func envLookup(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return kv[len(prefix):], true
		}
	}
	return "", false
}

// v0.9.0 regression (fix-no-net-strips-operator-proxy): `agentgate run --no-net`
// (NetProxy="") must NOT strip the operator's HTTP(S)_PROXY env vars. childEnv
// previously dropped them unconditionally and only re-added the agentgate
// redirect proxy when NetProxy was set, so under --no-net the operator's
// upstream corporate/forward proxy vanished and the wrapped agent's HTTP(S)
// egress failed outright (or went direct) with no notice. The fix gates the
// proxy-var drop on the net gate being active, so --no-net preserves the
// operator's proxy vars untouched.
func TestChildEnvNoNetPreservesOperatorProxy(t *testing.T) {
	const corp = "http://corp-proxy.example:8080"
	t.Setenv("HTTP_PROXY", corp)
	t.Setenv("HTTPS_PROXY", corp)
	t.Setenv("http_proxy", corp)
	t.Setenv("https_proxy", corp)

	r := NewRunner(nil, "claude-code", "agentgate") // NetProxy="" -> --no-net
	env := r.childEnv(t.TempDir(), filepath.Join(t.TempDir(), "broker.sock"))

	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if val, ok := envLookup(env, k); !ok || val != corp {
			t.Fatalf("--no-net must preserve the operator's %s, got %q (ok=%v)", k, val, ok)
		}
	}
}

// v0.9.0 fix counterpart: when the net gate IS active (NetProxy set), the
// operator's upstream proxy vars must still be REPLACED by the agentgate
// redirect proxy (the pre-fix behaviour, unchanged). This guards against an
// over-correction that would leave the operator's proxy in place alongside the
// redirect proxy.
func TestChildEnvNetGateReplacesOperatorProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://corp-proxy.example:8080")
	t.Setenv("HTTPS_PROXY", "http://corp-proxy.example:8080")

	r := NewRunner(nil, "claude-code", "agentgate")
	r.NetProxy = "127.0.0.1:9999" // net gate on
	env := r.childEnv(t.TempDir(), filepath.Join(t.TempDir(), "broker.sock"))

	want := "http://127.0.0.1:9999"
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if val, ok := envLookup(env, k); !ok || val != want {
			t.Fatalf("net gate on: %s must be the agentgate redirect proxy %q, got %q (ok=%v)", k, want, val, ok)
		}
	}
}

// v0.11.0 regression (fix-net-gate-no-proxy-bypass): when the net gate is ON
// (NetProxy set), an inherited NO_PROXY/no_proxy entry must NOT survive into
// the child env. The wrapped agent's HTTP client uses
// http.ProxyFromEnvironment, which honours NO_PROXY, so any host on the
// operator's bypass list (e.g. "127.0.0.1,localhost,.internal.corp") would
// otherwise connect DIRECTLY past the agentgate redirect proxy — silently
// defeating the net gate's egress-control guarantee for exactly the hosts an
// operator pre-approved for direct connection. The fix drops NO_PROXY/no_proxy
// (leaves them absent) when the net gate is active so no host is exempted and
// every egress is mediated.
func TestChildEnvNetGateDropsNoProxyBypass(t *testing.T) {
	const bypass = "127.0.0.1,localhost,.internal.corp"
	t.Setenv("NO_PROXY", bypass)
	t.Setenv("no_proxy", bypass)

	r := NewRunner(nil, "claude-code", "agentgate")
	r.NetProxy = "127.0.0.1:9999" // net gate on
	env := r.childEnv(t.TempDir(), filepath.Join(t.TempDir(), "broker.sock"))

	// Sanity: the redirect proxy is still wired, so dropping NO_PROXY routes
	// egress THROUGH the gate rather than leaving it un-proxied.
	if val, ok := envLookup(env, "HTTP_PROXY"); !ok || val != "http://127.0.0.1:9999" {
		t.Fatalf("net gate on: HTTP_PROXY must still be the agentgate redirect proxy, got %q (ok=%v)", val, ok)
	}

	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		if _, ok := envLookup(env, k); ok {
			t.Fatalf("net gate on: inherited %s must be dropped so it cannot bypass the redirect proxy, but it is present in child env", k)
		}
	}
}
