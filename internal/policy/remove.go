package policy

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// RemoveByIndex removes the rule at the given 1-based index (the same index
// `agentgate policy` prints) from the in-memory policy, returning the removed
// rule. The 1-based numbering mirrors RuleView.Index / WriteTable so an operator
// can copy the number straight off the table. The synthetic default row (index 0,
// printed as `*`) is NOT a real rule and cannot be removed — index 0 and any
// out-of-range index return an error and leave the policy untouched.
func (p *Policy) RemoveByIndex(index int) (Rule, error) {
	if index < 1 || index > len(p.Rules) {
		if index == 0 {
			return Rule{}, fmt.Errorf("index 0 is the default row (shown as *), which is not a removable rule")
		}
		return Rule{}, fmt.Errorf("no rule at index %d (policy has %d rule(s); valid range is 1..%d)", index, len(p.Rules), len(p.Rules))
	}
	removed := p.Rules[index-1]
	p.Rules = append(p.Rules[:index-1:index-1], p.Rules[index:]...)
	return removed, nil
}

// RemoveByMatch removes the FIRST rule whose action and target glob both equal
// the given values, returning the removed rule and its former 1-based index. An
// empty action or glob argument matches a rule whose corresponding field is also
// empty (i.e. the arguments are compared verbatim against the stored rule, not
// glob-evaluated) so `agentgate policy rm --action exec --target "npm install*"`
// removes exactly the rule the table shows with that action + target. When no
// rule matches, it returns an error and leaves the policy untouched.
func (p *Policy) RemoveByMatch(action, targetGlob string) (Rule, int, error) {
	for i := range p.Rules {
		r := p.Rules[i]
		if string(r.Match.Action) == action && r.Match.TargetGlob == targetGlob {
			removed, _ := p.RemoveByIndex(i + 1)
			return removed, i + 1, nil
		}
	}
	return Rule{}, 0, fmt.Errorf("no rule matches action=%q target=%q (run `agentgate policy` to see the exact action/target of each rule)", dispEmpty(action), dispEmpty(targetGlob))
}

// Save writes the policy back to a file in the same YAML shape Append/Load use,
// so a removal persists exactly like an `--always` grant did. The Default is
// preserved. The file is written atomically (temp + fsync + rename) at 0o644,
// matching Append — a crash mid-write never leaves a torn policy.yaml that
// Load would reject.
func (p *Policy) Save(path string) error {
	out, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, out, 0o644)
}

// dispEmpty renders an empty match argument as "any" in error messages so a
// no-match error reads the same way the table displays that rule.
func dispEmpty(s string) string {
	if s == "" {
		return "any"
	}
	return s
}
