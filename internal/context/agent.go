// Package context captures the agent's intent for each host-touching action.
//
// The intent string is the field no container or static scanner emits: it pairs
// a host-touching action ("agent wants to install npm package: chalk") with the
// concrete operation about to run, so the operator can make an informed
// allow/deny decision instead of a blind one.
package context

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ActionKind enumerates the host-touching surfaces AgentGate mediates.
type ActionKind string

const (
	// ActionExec is a subprocess the agent tried to spawn (npm install, a script).
	ActionExec ActionKind = "exec"
	// ActionFSWrite is a filesystem write outside the agent's declared scope.
	ActionFSWrite ActionKind = "fs_write"
	// ActionNetEgress is an outbound network connection to a host.
	ActionNetEgress ActionKind = "net_egress"
)

// GateRequest is the per-action authorization record — the core primitive.
//
// It is what AgentGate resolves against a Policy and what it writes to the audit
// log. The Intent and Agent fields are what make the decision intent-aware.
type GateRequest struct {
	Action ActionKind `json:"action"`
	// Target is the cmd line (exec), path (fs_write), or host:port (net_egress).
	Target string `json:"target"`
	// Intent is the agent's natural-language reason, captured from context.
	Intent string `json:"intent"`
	// Agent identifies the harness: "claude-code", "cursor", "cline", ...
	Agent string `json:"agent"`
	// Args carries the raw argv for an exec action (Target is the joined form).
	Args []string `json:"args,omitempty"`
}

// AgentName resolves the wrapped agent's identity for the current process tree.
//
// It prefers the explicit AGENTGATE_AGENT env var (set by `agentgate run`),
// falling back to a best-effort guess from the command name.
func AgentName() string {
	if v := os.Getenv("AGENTGATE_AGENT"); v != "" {
		return v
	}
	return "unknown-agent"
}

// InferIntent derives a human-readable intent string for an exec action when the
// agent did not supply one explicitly. It recognises the common package-manager
// and script patterns a coding agent spawns.
func InferIntent(args []string) string {
	if len(args) == 0 {
		return "agent wants to run an empty command"
	}
	if v := os.Getenv("AGENTGATE_INTENT"); v != "" {
		return v
	}
	bin := filepath.Base(args[0])
	rest := args[1:]
	switch bin {
	case "npm", "pnpm", "yarn", "bun":
		if pkg := pkgArg(rest, "install", "add", "i"); pkg != "" {
			return fmt.Sprintf("agent wants to install npm package: %s", pkg)
		}
		return fmt.Sprintf("agent wants to run %s: %s", bin, strings.Join(rest, " "))
	case "pip", "pip3", "uv", "poetry":
		if pkg := pkgArg(rest, "install", "add"); pkg != "" {
			return fmt.Sprintf("agent wants to install python package: %s", pkg)
		}
		return fmt.Sprintf("agent wants to run %s: %s", bin, strings.Join(rest, " "))
	case "go":
		if len(rest) > 0 && (rest[0] == "get" || rest[0] == "install") {
			return fmt.Sprintf("agent wants to fetch go module: %s", strings.Join(rest[1:], " "))
		}
	case "curl", "wget":
		return fmt.Sprintf("agent wants to fetch a URL via %s: %s", bin, strings.Join(rest, " "))
	case "sh", "bash", "zsh", "python", "python3", "node":
		return fmt.Sprintf("agent wants to execute a script via %s: %s", bin, strings.Join(rest, " "))
	}
	return fmt.Sprintf("agent wants to run: %s", strings.Join(args, " "))
}

// pkgArg returns the first non-flag argument following one of the given
// subcommands, treating it as the package name being installed.
func pkgArg(args []string, subcommands ...string) string {
	matched := false
	for _, a := range args {
		if !matched {
			for _, sc := range subcommands {
				if a == sc {
					matched = true
					break
				}
			}
			continue
		}
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}
