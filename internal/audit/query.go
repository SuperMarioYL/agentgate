package audit

import (
	"fmt"
	"strings"
	"time"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/policy"
)

// Filter narrows a slice of audit entries. A zero-value field means "no
// constraint on this dimension"; all set fields must match (logical AND).
type Filter struct {
	// Decision keeps only entries with this decision (allow|deny|ask). Empty: any.
	Decision policy.Decision
	// Action keeps only entries with this action kind. Empty: any.
	Action agentctx.ActionKind
	// Since keeps only entries at or after this instant. Zero: any.
	Since time.Time
}

// ParseSince parses the --since value as either an RFC3339 timestamp
// (2026-06-19T08:00:00Z), a date (2026-06-19, interpreted as UTC midnight), or a
// relative duration ago (e.g. "2h", "30m", "24h" => now-2h).
func ParseSince(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().UTC().Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid --since %q: want RFC3339 (2006-01-02T15:04:05Z), a date (2006-01-02), or a duration ago (e.g. 2h, 30m)", s)
}

// Validate rejects nonsensical filter values up front so the operator gets a
// clear error instead of a silently-empty result.
func (f Filter) Validate() error {
	switch f.Decision {
	case "", policy.Allow, policy.Deny, policy.Ask:
	default:
		return fmt.Errorf("invalid --decision %q (want allow|deny|ask)", f.Decision)
	}
	switch f.Action {
	case "", agentctx.ActionExec, agentctx.ActionFSWrite, agentctx.ActionNetEgress:
	default:
		return fmt.Errorf("invalid --action %q (want exec|fs_write|net_egress)", f.Action)
	}
	return nil
}

// match reports whether a single entry satisfies every set field of the filter.
func (f Filter) match(e Entry) bool {
	if f.Decision != "" && e.Decision != f.Decision {
		return false
	}
	if f.Action != "" && e.Action != f.Action {
		return false
	}
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	return true
}

// Apply returns the subset of entries that satisfy the filter, preserving order.
// A nil/zero filter returns all entries.
func (f Filter) Apply(entries []Entry) []Entry {
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if f.match(e) {
			out = append(out, e)
		}
	}
	return out
}
