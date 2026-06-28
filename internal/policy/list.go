package policy

import (
	"fmt"
	"io"
	"strings"
)

// RuleView is a flattened, display-ready view of one effective policy rule plus
// its position in first-match-wins order. It is what `agentgate policy` renders
// so an operator can see — and trust — exactly what the gate will enforce,
// including rules an `--always` choice appended.
type RuleView struct {
	// Index is the rule's 1-based position in first-match-wins order. A higher
	// rule wins over a lower one; the synthetic default row has Index 0.
	Index int
	// Action is the rule's action scope ("" / "any" means it matches every action).
	Action string
	// TargetGlob is the rule's target pattern ("" / "any" means it matches every target).
	TargetGlob string
	// Decision is allow | deny | ask.
	Decision Decision
	// Scope is the fs_write confinement prefix, if any.
	Scope string
	// IsDefault marks the synthetic trailing row for Policy.Default.
	IsDefault bool
}

// Effective returns every rule in first-match-wins order followed by a synthetic
// row for the policy's Default, so a caller can render the complete decision
// table the resolver actually consults. The slice is a snapshot — mutating it
// does not affect the policy.
func (p *Policy) Effective() []RuleView {
	views := make([]RuleView, 0, len(p.Rules)+1)
	for i := range p.Rules {
		r := &p.Rules[i]
		views = append(views, RuleView{
			Index:      i + 1,
			Action:     dispActionEmpty(string(r.Match.Action)),
			TargetGlob: dispGlobEmpty(r.Match.TargetGlob),
			Decision:   r.Decision,
			Scope:      r.Scope,
		})
	}
	views = append(views, RuleView{
		Index:      0,
		Action:     "any",
		TargetGlob: "any",
		Decision:   p.Default,
		IsDefault:  true,
	})
	return views
}

// dispActionEmpty renders an empty action scope as "any" for display.
func dispActionEmpty(a string) string {
	if a == "" {
		return "any"
	}
	return a
}

// dispGlobEmpty renders an empty target glob as "any" for display.
func dispGlobEmpty(g string) string {
	if g == "" {
		return "any"
	}
	return g
}

// WriteTable renders the effective rule set as an aligned, human-readable table
// to w. First-match-wins order is top-to-bottom; the final row is the default
// applied when no rule matches. It returns the first write error, if any.
func (p *Policy) WriteTable(w io.Writer) error {
	views := p.Effective()
	header := fmt.Sprintf("# effective policy (%s) — first match wins, top to bottom\n", displayPath(p.Path()))
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}
	// Compute column widths.
	actW, tgtW, decW := len("ACTION"), len("TARGET"), len("DECISION")
	for _, v := range views {
		if l := len(v.Action); l > actW {
			actW = l
		}
		if l := len(v.TargetGlob); l > tgtW {
			tgtW = l
		}
		if l := len(string(v.Decision)); l > decW {
			decW = l
		}
	}
	fmt.Fprintf(w, "%-3s  %-*s  %-*s  %-*s  %s\n", "#", actW, "ACTION", tgtW, "TARGET", decW, "DECISION", "SCOPE")
	for _, v := range views {
		idx := fmt.Sprintf("%d", v.Index)
		if v.IsDefault {
			idx = "*"
		}
		scope := v.Scope
		if scope == "" {
			scope = "-"
		}
		fmt.Fprintf(w, "%-3s  %-*s  %-*s  %-*s  %s\n",
			idx, actW, v.Action, tgtW, v.TargetGlob, decW, string(v.Decision), scope)
	}
	if _, err := io.WriteString(w, "\n(* = default, applied when no rule above matches)\n"); err != nil {
		return err
	}
	return nil
}

// displayPath renders the policy source for the table header, falling back to a
// clear marker when the policy was parsed in-memory (no file).
func displayPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "built-in default"
	}
	return p
}
