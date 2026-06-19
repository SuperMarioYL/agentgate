// Package gate ties policy resolution, the interactive prompt, audit logging,
// and `--always` persistence into a single decision engine shared by the exec,
// filesystem, and network gates.
package gate

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/SuperMarioYL/agentgate/internal/audit"
	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/policy"
	"github.com/SuperMarioYL/agentgate/internal/prompt"
)

// Engine resolves GateRequests. It is the seam every gate (fs/net/exec) calls.
type Engine struct {
	mu       sync.Mutex
	policy   *policy.Policy
	prompter *prompt.Prompter
	logger   *audit.Logger
	// persist, when set, appends `--always` allow rules back to this policy path.
	persist string
}

// NewEngine builds an Engine. logger and prompter may be nil for headless use
// (a nil prompter makes every "ask" fail closed to deny).
func NewEngine(p *policy.Policy, pr *prompt.Prompter, lg *audit.Logger) *Engine {
	return &Engine{policy: p, prompter: pr, logger: lg}
}

// SetPersistPath enables `--always` persistence to the given policy file.
func (e *Engine) SetPersistPath(path string) { e.persist = path }

// Decide resolves a request to a final allow/deny, prompting on "ask",
// persisting on "always", and recording the outcome to the audit log.
func (e *Engine) Decide(req agentctx.GateRequest) (policy.Decision, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	res := e.policy.Resolve(req)
	source := "rule"
	if res.FromDefault {
		source = "default"
	}

	final := res.Decision

	// fs_write allow rules may carry a scope; a write outside the scope is
	// downgraded to deny even though the rule matched.
	if final == policy.Allow && req.Action == agentctx.ActionFSWrite && res.Rule != nil {
		if !res.Rule.WithinScope(req.Target) {
			final = policy.Deny
			source = "scope"
		}
	}

	switch final {
	case policy.Ask:
		final, source = e.resolveAsk(req)
	case policy.Deny:
		if e.prompter != nil {
			e.prompter.DenialNotice(req)
		}
	}

	if e.logger != nil {
		_ = e.logger.Record(audit.Entry{
			Action:   req.Action,
			Target:   req.Target,
			Intent:   req.Intent,
			Agent:    req.Agent,
			Decision: final,
			Source:   source,
		})
	}
	return final, nil
}

func (e *Engine) resolveAsk(req agentctx.GateRequest) (policy.Decision, string) {
	if e.prompter == nil {
		return policy.Deny, "default" // headless: fail closed
	}
	choice, err := e.prompter.Ask(req)
	if err != nil {
		return policy.Deny, "operator"
	}
	if choice == prompt.ChoiceAlways && e.persist != "" {
		e.appendAlwaysRule(req)
		return policy.Allow, "always"
	}
	return prompt.ChoiceToDecision(choice), "operator"
}

// appendAlwaysRule writes an allow rule for the request's action+target to the
// persisted policy file and reloads the in-memory policy.
func (e *Engine) appendAlwaysRule(req agentctx.GateRequest) {
	glob := req.Target
	if req.Action == agentctx.ActionFSWrite {
		glob = filepath.Dir(req.Target) + string(os.PathSeparator) + "**"
	}
	rule := policy.Rule{
		Match:    policy.Match{Action: req.Action, TargetGlob: glob},
		Decision: policy.Allow,
	}
	if err := policy.Append(e.persist, rule); err != nil {
		return
	}
	if reloaded, err := policy.Load(e.persist); err == nil {
		e.policy = reloaded
	}
}

// Explanation is the side-effect-free outcome of evaluating a request: the
// decision the policy reaches, which rule fired (nil for the default), and how
// it was reached ("rule", "default", or "scope"). It never prompts and never
// records to the audit log — it backs the `agentgate check` dry-run.
type Explanation struct {
	Decision policy.Decision
	Rule     *policy.Rule
	Source   string
}

// Explain resolves a request against the policy without prompting, persisting,
// or logging. An "ask" rule is reported as Ask (the operator would be prompted
// at runtime); an fs_write allow that escapes its scope is reported as the
// scope-downgraded deny, exactly as Decide would apply it.
func (e *Engine) Explain(req agentctx.GateRequest) Explanation {
	e.mu.Lock()
	defer e.mu.Unlock()

	res := e.policy.Resolve(req)
	source := "rule"
	if res.FromDefault {
		source = "default"
	}
	decision := res.Decision

	if decision == policy.Allow && req.Action == agentctx.ActionFSWrite && res.Rule != nil {
		if !res.Rule.WithinScope(req.Target) {
			decision = policy.Deny
			source = "scope"
		}
	}
	return Explanation{Decision: decision, Rule: res.Rule, Source: source}
}

// Policy returns the engine's current (possibly reloaded) policy.
func (e *Engine) Policy() *policy.Policy { return e.policy }
