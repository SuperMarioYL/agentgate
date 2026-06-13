// Package prompt renders the interactive allow/deny/always prompt that carries
// the agent's intent so the operator can decide in context.
package prompt

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/policy"
)

// ANSI colour helpers. They no-op when the terminal does not support colour
// because the escape codes simply render as text; callers can disable via NoColor.
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	dim    = "\033[2m"
)

// Choice is what the operator picked at the prompt.
type Choice int

const (
	// ChoiceDeny blocks this single action.
	ChoiceDeny Choice = iota
	// ChoiceAllow permits this single action.
	ChoiceAllow
	// ChoiceAlways permits and persists an allow rule for matching actions.
	ChoiceAlways
)

// Prompter asks the operator to resolve an "ask" decision.
type Prompter struct {
	In      io.Reader
	Out     io.Writer
	NoColor bool
}

// New builds a Prompter over the given streams.
func New(in io.Reader, out io.Writer) *Prompter {
	return &Prompter{In: in, Out: out}
}

func (p *Prompter) c(code, s string) string {
	if p.NoColor {
		return s
	}
	return code + s + reset
}

// Ask renders the request and blocks for a single keypress line. It returns the
// operator's choice. EOF (non-interactive) is treated as a deny — fail closed.
func (p *Prompter) Ask(req agentctx.GateRequest) (Choice, error) {
	w := p.Out
	fmt.Fprintln(w)
	fmt.Fprintln(w, p.c(yellow+bold, "┌─ AgentGate · action paused ──────────────────"))
	fmt.Fprintf(w, "%s %s\n", p.c(bold, "│ agent  :"), req.Agent)
	fmt.Fprintf(w, "%s %s\n", p.c(bold, "│ action :"), p.c(cyan, string(req.Action)))
	fmt.Fprintf(w, "%s %s\n", p.c(bold, "│ target :"), req.Target)
	fmt.Fprintf(w, "%s %s\n", p.c(bold, "│ intent :"), p.c(dim, req.Intent))
	fmt.Fprintln(w, p.c(yellow+bold, "└──────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %s / %s / %s ? ",
		p.c(green, "[a]llow"), p.c(red, "[d]eny"), p.c(yellow, "[A]lways"))

	r := bufio.NewReader(p.In)
	line, err := r.ReadString('\n')
	if err == io.EOF && line == "" {
		fmt.Fprintln(w, p.c(red, "deny (no operator attached)"))
		return ChoiceDeny, nil
	}
	if err != nil && err != io.EOF {
		return ChoiceDeny, err
	}
	switch strings.TrimSpace(line) {
	case "a", "allow", "y", "yes":
		fmt.Fprintln(w, p.c(green, "allowed"))
		return ChoiceAllow, nil
	case "A", "always", "Always":
		fmt.Fprintln(w, p.c(yellow, "allowed + remembered"))
		return ChoiceAlways, nil
	default:
		fmt.Fprintln(w, p.c(red, "denied"))
		return ChoiceDeny, nil
	}
}

// DenialNotice prints a one-line blocked-action notice (used for deny rules that
// never prompt, e.g. an undeclared-host egress).
func (p *Prompter) DenialNotice(req agentctx.GateRequest) {
	fmt.Fprintf(p.Out, "%s %s %s\n",
		p.c(red+bold, "✗ AgentGate blocked"),
		p.c(cyan, string(req.Action)),
		p.c(red, req.Target))
}

// ChoiceToDecision maps an operator Choice to a policy Decision.
func ChoiceToDecision(c Choice) policy.Decision {
	switch c {
	case ChoiceAllow, ChoiceAlways:
		return policy.Allow
	default:
		return policy.Deny
	}
}
