package policy

import (
	"os"
	"path/filepath"
	"strings"
)

// confinedToScope reports whether target stays inside scope after BOTH paths are
// resolved through any intervening symlinks.
//
// A lexical-only check (filepath.Abs + filepath.Rel) is unsafe: a symlink that
// lives inside the declared scope but points outside it lets a write escape the
// sandbox while still presenting an in-scope path. We therefore resolve the
// scope root and the target's deepest *existing* ancestor with
// filepath.EvalSymlinks before computing the relative path, so the check sees
// where a write would actually land — not where it lexically claims to.
//
// The target itself may not exist yet (the agent is about to create it), so we
// walk up to the nearest existing ancestor, resolve that, and re-attach the
// not-yet-existing trailing components. Resolving the scope root likewise
// follows symlinks on the scope side, so a symlinked scope still matches.
func confinedToScope(scope, target string) bool {
	absScope, err := filepath.Abs(os.ExpandEnv(scope))
	if err != nil {
		absScope = scope
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		absTarget = target
	}

	resolvedScope := resolveExisting(absScope)
	resolvedTarget := resolveExisting(absTarget)

	rel, err := filepath.Rel(resolvedScope, resolvedTarget)
	if err != nil {
		return false
	}
	return rel == "." || !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

// resolveExisting returns path with all symlinks in its deepest existing prefix
// resolved. Trailing components that do not exist yet are kept lexically (after
// a Clean) so a not-yet-created target is still evaluated against the real,
// symlink-resolved location of its parent directory.
func resolveExisting(path string) string {
	path = filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	// Walk up to the nearest existing ancestor, resolve it, then re-attach the
	// trailing not-yet-existing segments.
	var trailing []string
	cur := path
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			// Reached the root with nothing resolvable; fall back to lexical.
			return path
		}
		trailing = append([]string{filepath.Base(cur)}, trailing...)
		if resolved, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Join(append([]string{resolved}, trailing...)...)
		}
		cur = parent
	}
}
