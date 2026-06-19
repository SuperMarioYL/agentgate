// Package policy loads, parses, and evaluates the AgentGate policy DSL.
//
// A policy is an ordered list of rules; the first rule whose match clause
// matches a GateRequest wins (first-match-wins). Each rule resolves to one of
// three decisions: allow, deny, or ask (prompt the operator at runtime).
package policy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"gopkg.in/yaml.v3"
)

// Decision is the resolution of a GateRequest against a Policy.
type Decision string

const (
	// Allow lets the action proceed without prompting.
	Allow Decision = "allow"
	// Deny blocks the action without prompting.
	Deny Decision = "deny"
	// Ask defers to the operator via the interactive prompt.
	Ask Decision = "ask"
)

// Match is the predicate half of a Rule.
type Match struct {
	// Action restricts the rule to one action kind; empty matches any.
	Action agentctx.ActionKind `yaml:"action,omitempty"`
	// TargetGlob is a glob matched against the request's Target; empty matches any.
	TargetGlob string `yaml:"target_glob,omitempty"`
}

// Rule pairs a Match with a Decision. Scope, when set on an fs_write allow rule,
// confines writes to that path prefix.
type Rule struct {
	Match    Match    `yaml:"match"`
	Decision Decision `yaml:"decision"`
	Scope    string   `yaml:"scope,omitempty"`
}

// Policy is an ordered set of rules plus a default applied when none match.
type Policy struct {
	// Rules are evaluated top-to-bottom; first match wins.
	Rules []Rule `yaml:"rules"`
	// Default is used when no rule matches. Defaults to Ask if unset.
	Default Decision `yaml:"default,omitempty"`

	path string
}

// Resolution is the outcome of evaluating a request, including which rule fired.
type Resolution struct {
	Decision    Decision
	Rule        *Rule
	FromDefault bool
}

// Load reads and parses a policy file from disk.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}
	p.path = path
	return p, nil
}

// Parse builds a Policy from raw YAML.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Default == "" {
		p.Default = Ask
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) validate() error {
	for i, r := range p.Rules {
		switch r.Decision {
		case Allow, Deny, Ask:
		default:
			return fmt.Errorf("rule %d: invalid decision %q (want allow|deny|ask)", i, r.Decision)
		}
	}
	switch p.Default {
	case Allow, Deny, Ask:
	default:
		return fmt.Errorf("invalid default decision %q", p.Default)
	}
	return nil
}

// Path returns the file the policy was loaded from (empty if parsed in-memory).
func (p *Policy) Path() string { return p.path }

// Resolve evaluates a request against the policy using first-match-wins.
func (p *Policy) Resolve(req agentctx.GateRequest) Resolution {
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.matches(req) {
			return Resolution{Decision: r.Decision, Rule: r}
		}
	}
	return Resolution{Decision: p.Default, FromDefault: true}
}

func (r *Rule) matches(req agentctx.GateRequest) bool {
	if r.Match.Action != "" && r.Match.Action != req.Action {
		return false
	}
	if r.Match.TargetGlob == "" {
		return true
	}
	return globMatch(r.Match.TargetGlob, req.Target)
}

// globMatch matches a glob pattern against a target. It supports a trailing or
// embedded "**" as a multi-segment wildcard in addition to filepath.Match's
// single-segment "*", which makes path-scope and host patterns ergonomic.
func globMatch(pattern, target string) bool {
	if pattern == "*" || pattern == "**" {
		return true
	}
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		prefix, suffix := parts[0], parts[1]
		if !strings.HasPrefix(target, prefix) {
			return false
		}
		// A non-empty suffix must anchor to the END of the target, not appear
		// anywhere inside it. A bare Contains here over-matches path globs: a
		// scope like `/proj/**.env` would otherwise match
		// `/proj/.env.backup/passwd`, widening allow/scope rules past intent —
		// the same over-match class the host-token boundary fix closed for net
		// egress, here for path/`**` globs.
		return suffix == "" || strings.HasSuffix(target, suffix)
	}
	if ok, _ := filepath.Match(pattern, target); ok {
		return true
	}
	// A bare token (e.g. a host name) matches the whole target or the host part
	// of a `host:port` target, so `registry.npmjs.org` matches
	// `registry.npmjs.org:443`. It must NOT match on a bare substring: a rule for
	// `github.com` must not allow egress to `github.com.evil.com` (suffix attack),
	// `notgithub.com` (prefix attack), or `evilgithub.com` — that would defeat the
	// egress allowlist entirely.
	if !strings.ContainsAny(pattern, "*?[") {
		return hostTokenMatch(pattern, target)
	}
	// For command lines (which contain '/' that filepath.Match treats as a hard
	// segment boundary) fall back to a wildcard matcher where '*' spans any
	// characters, so "*npm install*" and "*curl*" match an argv string.
	if strings.Contains(pattern, "*") {
		return starMatch(pattern, target)
	}
	return false
}

// hostTokenMatch matches a bare (wildcard-free) token against a target on a
// host boundary. It accepts an exact match, a `token:port` target (the common
// egress case), and `*.`-rooted subdomain matching when the token begins with a
// leading dot (".github.com" matches "api.github.com:443" but not "github.com").
// Everything else — substrings, prefix/suffix splices — is rejected.
func hostTokenMatch(token, target string) bool {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	if strings.HasPrefix(token, ".") {
		return strings.HasSuffix(host, token)
	}
	return host == token
}

// starMatch matches a pattern containing '*' wildcards against target, treating
// each '*' as ".*" (any run of characters, slashes included). '?'/'[' classes
// are not interpreted here; this is a pragmatic command-line matcher.
func starMatch(pattern, target string) bool {
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(target[pos:], part)
		if idx < 0 {
			return false
		}
		// A leading non-empty segment must match at the very start.
		if i == 0 && idx != 0 {
			return false
		}
		pos += idx + len(part)
	}
	// A trailing non-empty segment must reach the end of the target.
	if last := parts[len(parts)-1]; last != "" {
		return strings.HasSuffix(target, last)
	}
	return true
}

// Append persists an additional rule to a policy file. The rule is inserted
// before the final catch-all so it takes precedence (first-match-wins). This
// backs the `--always` operator choice.
func Append(path string, rule Rule) error {
	p, err := Load(path)
	if err != nil {
		return err
	}
	// Insert ahead of any trailing action-less default-ish rule so the new
	// allow rule actually fires.
	p.Rules = append([]Rule{rule}, p.Rules...)
	out, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// WithinScope reports whether path is confined to the rule's Scope prefix.
// A rule with no Scope imposes no confinement (returns true).
//
// Confinement is checked on the symlink-resolved paths (see confinedToScope),
// so a symlink that lives inside the scope but points outside it cannot smuggle
// a write past the sandbox.
func (r *Rule) WithinScope(path string) bool {
	if r == nil || r.Scope == "" {
		return true
	}
	return confinedToScope(r.Scope, path)
}
