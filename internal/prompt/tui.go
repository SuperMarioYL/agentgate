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
	// Persist reports whether an [A]lways choice will actually be written back
	// to a policy file. The engine sets it (via SetPersistPath) so the prompt can
	// honestly say "remembered" only when persistence is configured, instead of
	// claiming "remembered" and then persisting nothing (the built-in default
	// policy case).
	Persist bool

	// reader is a single buffered reader reused across Ask calls so that
	// unconsumed typed-ahead/piped bytes survive between prompts. A fresh
	// bufio.NewReader per Ask stranded the 2nd piped answer in a discarded
	// buffer (its first fill can pull more than one line) and the next Ask's
	// fresh reader saw EOF -> ChoiceDeny ("no operator attached").
	reader *bufio.Reader
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

	// Reuse ONE buffered reader across calls. A fresh bufio.NewReader per Ask
	// stranded the 2nd piped answer: its first fill can pull MORE than one line
	// from a pipe or strings.Reader (up to the 4KiB buffer) in a single read, so
	// the bytes for the next answer sat in a discarded buffer and the next Ask's
	// fresh reader saw EOF -> ChoiceDeny ("no operator attached"). A non-interactive
	// operator piping `printf 'a\na\n' | agentgate run` got the first action
	// allowed and every later one silently denied. A lazily-created shared reader
	// lets unconsumed buffered bytes survive between prompts.
	if p.reader == nil {
		p.reader = bufio.NewReader(p.In)
	}
	r := p.reader
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
		if p.Persist {
			fmt.Fprintln(w, p.c(yellow, "allowed + remembered"))
		} else {
			// No policy file / persist path configured (the built-in default):
			// this [A]lways allows the action ONCE but persists nothing, so the
			// next same-kind action re-prompts. Don't claim "remembered" when it
			// was not — say so honestly and point the operator at `agentgate init`.
			fmt.Fprintln(w, p.c(yellow, "allowed (not remembered — run `agentgate init`)"))
		}
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
