// Package gate ties policy resolution, the interactive prompt, audit logging,
// and `--always` persistence into a single decision engine shared by the exec,
// filesystem, and network gates.
package gate

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// SetPersistPath enables `--always` persistence to the given policy file. It
// also tells the prompter (if any) whether an [A]lways choice will actually be
// persisted, so the prompt can honestly say "remembered" only when a policy file
// will be written — an empty path (no policy file / built-in default) means the
// choice allows once but persists nothing, and the prompt must not lie that it
// was remembered.
func (e *Engine) SetPersistPath(path string) {
	e.persist = path
	if e.prompter != nil {
		e.prompter.Persist = path != ""
	}
}

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
		final, source = e.resolveAsk(req, res.RuleIndex)
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

func (e *Engine) resolveAsk(req agentctx.GateRequest, askRuleIdx int) (policy.Decision, string) {
	if e.prompter == nil {
		return policy.Deny, "default" // headless: fail closed
	}
	choice, err := e.prompter.Ask(req)
	if err != nil {
		return policy.Deny, "operator"
	}
	if choice == prompt.ChoiceAlways && e.persist != "" {
		if persistErr := e.appendAlwaysRule(req, askRuleIdx); persistErr != nil {
			// The operator pressed [A]lways, so the action stays allowed — but
			// the persist failed, so the rule was NOT remembered even though the
			// prompt already said "remembered". Surface the failure on stderr
			// and attribute the audit row to the operator's live choice, not to
			// a remembered "always" rule that was never written. The allow
			// decision itself is unchanged.
			fmt.Fprintf(os.Stderr, "agentgate: persistence failed: %v; rule NOT remembered\n", persistErr)
			return policy.Allow, "operator"
		}
		return policy.Allow, "always"
	}
	return prompt.ChoiceToDecision(choice), "operator"
}

// appendAlwaysRule writes an allow rule for the request's action+target to the
// persisted policy file (inserted before the matched ask rule at askRuleIdx so
// explicit deny rules above keep precedence) and reloads the in-memory policy.
// It returns the Append error so resolveAsk can surface a persist failure.
func (e *Engine) appendAlwaysRule(req agentctx.GateRequest, askRuleIdx int) error {
	glob := alwaysGlob(req)
	rule := policy.Rule{
		Match:    policy.Match{Action: req.Action, TargetGlob: glob},
		Decision: policy.Allow,
	}
	if err := policy.Append(e.persist, rule, askRuleIdx); err != nil {
		return err
	}
	if reloaded, err := policy.Load(e.persist); err == nil {
		e.policy = reloaded
	}
	return nil
}

// alwaysGlob derives the persisted-rule TargetGlob for an `--always` choice.
//
// An exec request's Target is the FULL joined command line (e.g.
// "npm install left-pad"), which carries no glob wildcards — so persisting it
// verbatim makes the rule match only that exact argv, and the next invocation
// ("npm install chalk", or even "npm install left-pad --save") re-prompts,
// defeating the operator's "stop asking me" intent. For exec we therefore anchor
// the glob on the binary + its first non-flag subcommand and append "*" (e.g.
// "npm install*"), so an --always on `npm install left-pad` afterwards covers
// `npm install chalk` too; with no subcommand we fall back to "<bin> *". fs_write
// keeps its directory/** scope glob. net_egress STRIPS the port from the
// host:port target and persists the bare host: the runtime net_egress Target is
// the host:port the redirect proxy passes to CheckHost, so persisting it verbatim
// (e.g. "registry.npmjs.org:443") would re-match only that exact host:port
// (hostTokenMatch rejects :80) and the next egress to the same host on :80 would
// re-prompt — the same verbatim-target class the v0.4.0 exec fix closed. A
// bare-host rule auto-allows the host on any port via hostTokenMatch (which also
// rejects suffix/prefix attacks).
func alwaysGlob(req agentctx.GateRequest) string {
	switch req.Action {
	case agentctx.ActionFSWrite:
		return filepath.Dir(req.Target) + string(os.PathSeparator) + "**"
	case agentctx.ActionExec:
		bin, sub := execBinAndSub(req)
		if bin == "" {
			// No structured argv available — widen the joined target so at least
			// argument variations after the same prefix re-match.
			return strings.TrimSpace(req.Target) + "*"
		}
		if sub != "" {
			return bin + " " + sub + "*"
		}
		return bin + " *"
	case agentctx.ActionNetEgress:
		// Strip the port so the persisted rule is the bare host; hostTokenMatch
		// then matches any port on that host (and rejects suffix/prefix attacks).
		// Fall back to the bare token if SplitHostPort reports it is not
		// host:port (e.g. an operator already typed a bare host).
		host, _, err := net.SplitHostPort(req.Target)
		if err != nil {
			return req.Target
		}
		return host
	default:
		return req.Target
	}
}

// execBinAndSub returns the binary name and its first non-flag subcommand for an
// exec request, preferring the structured Args (set by the wrap broker) and
// falling back to splitting the joined Target. Either may be empty.
func execBinAndSub(req agentctx.GateRequest) (bin, sub string) {
	fields := req.Args
	if len(fields) == 0 {
		fields = strings.Fields(req.Target)
	}
	if len(fields) == 0 {
		return "", ""
	}
	bin = fields[0]
	for _, f := range fields[1:] {
		if !strings.HasPrefix(f, "-") {
			sub = f
			break
		}
	}
	return bin, sub
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
