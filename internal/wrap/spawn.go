// Package wrap launches the agent process and intercepts the subprocesses it
// spawns (npm install, pip install, generated scripts).
//
// Interception is portable (Linux + macOS) and libpcap/ptrace-free: AgentGate
// builds a shim directory of wrapper executables for the commands a coding
// agent commonly spawns, prepends it to the agent's PATH, and runs a local
// broker over a unix-domain socket. When the agent invokes e.g. `npm`, it hits
// the shim, which forwards the argv to the broker; the broker resolves the
// action against policy (prompting on `ask`) and only then is the real binary
// exec'd. A denied subprocess never runs.
package wrap

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/gate"
	"github.com/SuperMarioYL/agentgate/internal/policy"
)

// InterceptedCommands are the binaries the shim wraps. Each maps to a host
// touching action a coding agent typically spawns.
var InterceptedCommands = []string{
	// package managers
	"npm", "pnpm", "yarn", "bun",
	"pip", "pip3", "uv", "poetry",
	"gem", "cargo", "go",
	// script interpreters an agent uses to run generated build/post-install scripts
	"node", "python", "python3", "ruby",
	// direct fetchers
	"curl", "wget",
}

// brokerRequest is the wire message a shim sends to the broker.
type brokerRequest struct {
	Args []string `json:"args"`
	Cwd  string   `json:"cwd"`
}

// brokerReply is the broker's verdict.
type brokerReply struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
}

// Runner wraps an agent process under the gate.
type Runner struct {
	Engine   *gate.Engine
	Agent    string
	NetProxy string // HTTP(S)_PROXY address, empty if net gate disabled
	selfPath string
}

// NewRunner builds a Runner. selfPath is the path to the agentgate binary used
// by the shim wrappers (os.Executable() in production).
func NewRunner(e *gate.Engine, agent, selfPath string) *Runner {
	return &Runner{Engine: e, Agent: agent, selfPath: selfPath}
}

// Run sets up the shim + broker and runs argv as the agent. It blocks until the
// agent exits and returns the agent's exit code.
func (r *Runner) Run(argv []string) (int, error) {
	if len(argv) == 0 {
		return 1, fmt.Errorf("no agent command given")
	}

	shimDir, err := os.MkdirTemp("", "agentgate-shim-")
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(shimDir)

	sockPath := filepath.Join(shimDir, "broker.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return 1, fmt.Errorf("broker listen: %w", err)
	}
	defer ln.Close()
	go r.serveBroker(ln)

	if err := r.writeShims(shimDir); err != nil {
		return 1, err
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = r.childEnv(shimDir, sockPath)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start agent: %w", err)
	}
	go func() {
		for s := range sig {
			_ = cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	if err == nil {
		return 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}
	return 1, err
}

// childEnv constructs the environment for the wrapped agent: PATH gets the shim
// dir prepended, the broker socket + agent identity are exported, and the net
// proxy (if any) is wired through HTTP(S)_PROXY.
func (r *Runner) childEnv(shimDir, sockPath string) []string {
	env := os.Environ()
	out := env[:0]
	for _, kv := range env {
		switch {
		case strings.HasPrefix(kv, "PATH="):
			out = append(out, "PATH="+shimDir+string(os.PathListSeparator)+kv[len("PATH="):])
		case strings.HasPrefix(kv, "HTTP_PROXY="), strings.HasPrefix(kv, "HTTPS_PROXY="),
			strings.HasPrefix(kv, "http_proxy="), strings.HasPrefix(kv, "https_proxy="):
			// drop; we re-add below if a proxy is configured
		default:
			out = append(out, kv)
		}
	}
	out = append(out,
		"AGENTGATE_BROKER="+sockPath,
		"AGENTGATE_AGENT="+r.Agent,
		"AGENTGATE_ACTIVE=1",
	)
	if r.NetProxy != "" {
		px := "http://" + r.NetProxy
		out = append(out, "HTTP_PROXY="+px, "HTTPS_PROXY="+px,
			"http_proxy="+px, "https_proxy="+px)
	}
	return out
}

// writeShims drops a wrapper script per intercepted command into dir. Each
// re-invokes the agentgate binary's hidden `__shim` command, which talks to the
// broker. Using a script (rather than a symlink) keeps the original command
// name in argv[0] so intent inference works.
func (r *Runner) writeShims(dir string) error {
	for _, name := range InterceptedCommands {
		p := filepath.Join(dir, name)
		script := fmt.Sprintf("#!/bin/sh\nexec %q __shim %q \"$@\"\n", r.selfPath, name)
		if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
			return err
		}
	}
	return nil
}

// serveBroker accepts shim connections and resolves each through the engine.
func (r *Runner) serveBroker(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go r.handleBrokerConn(conn)
	}
}

func (r *Runner) handleBrokerConn(conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(bufio.NewReader(conn))
	var req brokerRequest
	if err := dec.Decode(&req); err != nil {
		return
	}
	intent := agentctx.InferIntent(req.Args)
	greq := agentctx.GateRequest{
		Action: agentctx.ActionExec,
		Target: strings.Join(req.Args, " "),
		Intent: intent,
		Agent:  r.Agent,
		Args:   req.Args,
	}
	dec2, _ := r.Engine.Decide(greq)
	reply := brokerReply{Allow: dec2 == policy.Allow}
	if !reply.Allow {
		reply.Reason = "blocked by AgentGate policy"
	}
	_ = json.NewEncoder(conn).Encode(reply)
}

// ShimMain is the entrypoint for the hidden `agentgate __shim <name> <args...>`
// command run by the wrapper scripts. It asks the broker for a verdict and, on
// allow, exec's the real binary (the one further down PATH). On deny it prints a
// notice and exits non-zero without running anything.
func ShimMain(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "agentgate __shim: no command")
		return 2
	}
	name := args[0]
	rest := args[1:]
	sock := os.Getenv("AGENTGATE_BROKER")
	if sock == "" {
		// No broker attached — pass through to the real binary.
		return execReal(name, rest)
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return execReal(name, rest)
	}
	cwd, _ := os.Getwd()
	full := append([]string{name}, rest...)
	if err := json.NewEncoder(conn).Encode(brokerRequest{Args: full, Cwd: cwd}); err != nil {
		_ = conn.Close()
		return execReal(name, rest)
	}
	var reply brokerReply
	_ = json.NewDecoder(conn).Decode(&reply)
	_ = conn.Close()

	if !reply.Allow {
		fmt.Fprintf(os.Stderr, "agentgate: blocked %q (%s)\n", strings.Join(full, " "), reply.Reason)
		return 126
	}
	return execReal(name, rest)
}

// execReal finds the real binary for name (skipping the shim dir at the head of
// PATH) and execs it, replacing the current process.
func execReal(name string, args []string) int {
	real, err := lookReal(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentgate: %s not found on PATH: %v\n", name, err)
		return 127
	}
	full := append([]string{real}, args...)
	err = syscall.Exec(real, full, os.Environ())
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentgate: exec %s: %v\n", real, err)
		return 1
	}
	return 0 // unreachable on success
}

// lookReal resolves name on PATH, skipping any directory that contains our own
// shim (identified by a sibling broker.sock) so we don't recurse into the shim.
func lookReal(name string) (string, error) {
	pathEnv := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "broker.sock")); err == nil {
			continue // this is the shim dir; skip
		}
		cand := filepath.Join(dir, name)
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return "", fmt.Errorf("not found")
}
