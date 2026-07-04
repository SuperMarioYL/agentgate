package main

import (
	"errors"
	"strings"
	"testing"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/policy"
)

// v0.6.0 fix (fix-netgate-listen-failure-fail-open): when the net gate's redirect
// proxy fails to bind, `agentgate run` used to swallow the error and run the agent
// with NO proxy env — its HTTP(S) egress went out completely ungated, silently.
// That is a fail-open. The run must now fail CLOSED: surface a clear error (which
// makes `agentgate run` exit non-zero) rather than proceeding ungated.
func TestNetGateStartFailsClosed(t *testing.T) {
	bindErr := errors.New("listen tcp 127.0.0.1:8080: bind: address already in use")
	err := netGateStartError(bindErr)
	if err == nil {
		t.Fatal("a net-gate bind failure must produce an error (fail-closed), not nil (fail-open)")
	}
	if !errors.Is(err, bindErr) {
		t.Fatal("the wrapped error must preserve the underlying bind failure")
	}
	if !strings.Contains(err.Error(), "--no-net") {
		t.Fatalf("the error should tell the operator how to proceed deliberately (--no-net), got: %v", err)
	}
}

// v0.6.0 fix (fix-fs-write-gate-not-wired-runtime): fs_write is CHECK/DRY-RUN-ONLY
// in this version — AgentGate does not intercept an agent's actual writes at
// runtime (no FSGate runtime caller). The default policy shipped by
// `agentgate init` must therefore NOT carry a blanket `deny fs_write` catch-all:
// a default that pretends to confine writes it can't stop at runtime is a false
// security promise. The documenting `allow $PWD/**` scope rule may remain (it is
// resolvable via `agentgate check`); the catch-all deny must be gone.
func TestDefaultPolicyHasNoBlanketFSWriteDeny(t *testing.T) {
	pol, err := policy.Parse(defaultPolicy)
	if err != nil {
		t.Fatalf("parse embedded default policy: %v", err)
	}
	for _, r := range pol.Rules {
		if r.Match.Action == agentctx.ActionFSWrite && r.Match.TargetGlob == "" && r.Decision == policy.Deny {
			t.Fatal("`agentgate init` default policy must NOT ship a blanket `deny fs_write` catch-all (fs_write is check/dry-run-only in this version)")
		}
	}
}

// The default policy must still be well-formed and enforce the surfaces that ARE
// runtime-enforced: exec installs surface (ask), and undeclared egress is denied.
func TestDefaultPolicyStillGatesExecAndEgress(t *testing.T) {
	pol, err := policy.Parse(defaultPolicy)
	if err != nil {
		t.Fatalf("parse embedded default policy: %v", err)
	}
	if got := pol.Resolve(agentctx.GateRequest{Action: agentctx.ActionExec, Target: "npm install left-pad"}).Decision; got != policy.Ask {
		t.Errorf("default policy should ASK on an install, got %s", got)
	}
	if got := pol.Resolve(agentctx.GateRequest{Action: agentctx.ActionNetEgress, Target: "telemetry.evil.example:443"}).Decision; got != policy.Deny {
		t.Errorf("default policy should DENY an undeclared egress host, got %s", got)
	}
}
