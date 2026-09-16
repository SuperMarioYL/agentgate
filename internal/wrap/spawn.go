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
//
// The operator's upstream HTTP(S)_PROXY vars are only dropped when the net gate
// is ACTIVE (r.NetProxy != ""): when the net gate is on, the operator's proxy
// must be replaced by the agentgate redirect proxy (re-added below); when the
// net gate is off (--no-net) the operator's proxy vars are kept untouched so
// upstream corporate/forward proxy connectivity is preserved — previously they
// were dropped unconditionally and only re-added when NetProxy was set, so
// --no-net silently stripped the operator's proxy and the agent's HTTP(S)
// egress failed outright (or went direct) with no notice.
//
// When the net gate is on, NO_PROXY/no_proxy are also dropped (and NOT re-added)
// so the agent's http.ProxyFromEnvironment exempts no host and every egress is
// mediated by the agentgate redirect proxy. Inheriting the operator's bypass
// list verbatim would let a pre-approved host (e.g.
// "127.0.0.1,localhost,.internal.corp") connect DIRECTLY past the redirect
// proxy, silently defeating the net gate's egress-control guarantee for exactly
// the hosts an operator pre-approved for direct connection.
func (r *Runner) childEnv(shimDir, sockPath string) []string {
	env := os.Environ()
	out := env[:0]
	netGateOn := r.NetProxy != ""
	for _, kv := range env {
		switch {
		case strings.HasPrefix(kv, "PATH="):
			out = append(out, "PATH="+shimDir+string(os.PathListSeparator)+kv[len("PATH="):])
		case netGateOn && (strings.HasPrefix(kv, "HTTP_PROXY=") ||
			strings.HasPrefix(kv, "HTTPS_PROXY=") ||
			strings.HasPrefix(kv, "http_proxy=") ||
			strings.HasPrefix(kv, "https_proxy=") ||
			strings.HasPrefix(kv, "NO_PROXY=") ||
			strings.HasPrefix(kv, "no_proxy=")):
			// Net gate on: drop the operator's upstream proxy and any NO_PROXY
			// bypass list. The agentgate redirect proxy is re-added below; but
			// NO_PROXY/no_proxy are NOT re-added (left absent) so no host is
			// exempted and every egress is mediated by the gate. When the net
			// gate is OFF these vars are left untouched (fall through to default)
			// so upstream connectivity and the operator's bypass list are
			// preserved.
		default:
			out = append(out, kv)
		}
	}
	out = append(out,
		"AGENTGATE_BROKER="+sockPath,
		"AGENTGATE_AGENT="+r.Agent,
		"AGENTGATE_ACTIVE=1",
	)
	if netGateOn {
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

	full := append([]string{name}, rest...)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		// The process IS under `agentgate run` (AGENTGATE_BROKER is set) but the
		// broker is unreachable — fail CLOSED. Running the real binary here would
		// exec it ungated (no policy check), which for a security gate is worse
		// than refusing: a crashed/killed broker must not silently disable the
		// gate. This mirrors the reply-decode path below, which already denies on
		// a decode failure.
		return brokerUnreachable(full, err)
	}
	cwd, _ := os.Getwd()
	if err := json.NewEncoder(conn).Encode(brokerRequest{Args: full, Cwd: cwd}); err != nil {
		_ = conn.Close()
		return brokerUnreachable(full, err)
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

// brokerUnreachable is the fail-closed path for a shim that is under `agentgate
// run` (AGENTGATE_BROKER set) but cannot reach the broker to get a verdict. It
// refuses to run the command ungated: it prints a clear notice and returns 126
// (the same "blocked" code the deny path uses) WITHOUT exec'ing the real binary.
func brokerUnreachable(full []string, err error) int {
	fmt.Fprintf(os.Stderr,
		"agentgate: broker unreachable, refusing to run %q ungated (fail-closed): %v\n",
		strings.Join(full, " "), err)
	return 126
}

// execReal finds the real binary for name (skipping the shim dir at the head of
// PATH) and execs it, replacing the current process.
func execReal(name string, args []string) int {
	real, err := lookReal(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentgate: %s not found on PATH: %v\n", name, err)
		return 127
	}
	return execResolved(real, args)
}

// execResolved execs the resolved binary, replacing the current process.
//
// When the target is a shebang script of the universal package-manager shape
// ("#!/usr/bin/env node|python3|ruby" — npm, pip, gem and friends are all such
// wrappers), the kernel's binfmt handler re-execs "/usr/bin/env <interp>
// <script> <args>" USING THE SHIMMED ENVIRONMENT: /usr/bin/env resolves <interp>
// via PATH, finds the shim dir's wrapper first, and the interpreter shim asks the
// broker AGAIN for the very command the operator just resolved — a second prompt
// (or, with no operator input left, an EOF deny that blocks an action the
// operator already allowed, defeating --always persistence). We therefore
// resolve that interpreter hop OURSELVES via lookReal (which already skips the
// shim dir) and exec the real interpreter directly. Only this one hop is
// de-duplicated: every subsequent child the interpreter spawns still inherits
// the shimmed PATH and stays gated. Any unrecognised shebang form falls back to
// exec'ing the script as before (a direct absolute-path shebang bypasses PATH
// and never re-enters the shim, so it needs no rewrite).
func execResolved(real string, args []string) int {
	if argv, ok := shebangExecArgv(real, args); ok {
		if err := syscall.Exec(argv[0], argv, os.Environ()); err != nil {
			// The direct interpreter exec failed (unexpected); fall back to
			// exec'ing the script itself rather than failing the allowed action.
			fmt.Fprintf(os.Stderr, "agentgate: exec interpreter %s: %v (falling back to direct exec)\n", argv[0], err)
		} else {
			return 0 // unreachable on success
		}
	}
	full := append([]string{real}, args...)
	err := syscall.Exec(real, full, os.Environ())
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentgate: exec %s: %v\n", real, err)
		return 1
	}
	return 0 // unreachable on success
}

// shebangExecArgv reports the argv needed to run real's shebang interpreter
// directly, skipping the shim dir, when real is an `env <interp>` shebang script
// whose interp is one of the intercepted commands. ok is false for every other
// form, in which case the caller execs the script itself (today's behaviour).
func shebangExecArgv(real string, args []string) ([]string, bool) {
	interp, extra, ok := shebangEnvInterp(real)
	if !ok || !isIntercepted(interp) {
		return nil, false
	}
	realInterp, err := lookReal(interp)
	if err != nil {
		return nil, false
	}
	argv := make([]string, 0, 2+len(extra)+len(args))
	argv = append(argv, realInterp)
	argv = append(argv, extra...)
	argv = append(argv, real)
	argv = append(argv, args...)
	return argv, true
}

// isIntercepted reports whether name is one of the commands we wrap shims for.
func isIntercepted(name string) bool {
	for _, c := range InterceptedCommands {
		if c == name {
			return true
		}
	}
	return false
}

// shebangEnvInterp parses the shebang line of the file at path. It returns the
// interpreter name and extra argv only for the `#!/usr/bin/env <interp>
// [extra...]` form — the only form that resolves <interp> through PATH and can
// therefore re-enter the shim dir. `env` flags (-S/-i/...), absolute or
// relative interpreter paths, non-env shebangs, and non-scripts all return
// ok=false (the caller falls back to exec'ing the file, which is correct for
// those forms).
func shebangEnvInterp(path string) (interp string, extra []string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, false
	}
	defer f.Close()
	buf := make([]byte, 256)
	n, _ := f.Read(buf)
	line := strings.SplitN(string(buf[:n]), "\n", 2)[0]
	line = strings.TrimSuffix(line, "\r")
	if !strings.HasPrefix(line, "#!") {
		return "", nil, false
	}
	tokens := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(tokens) < 2 || filepath.Base(tokens[0]) != "env" {
		return "", nil, false
	}
	// tokens[1] must be a BARE interpreter name: an env flag (-S ...) or a path
	// (which bypasses PATH lookup and cannot re-enter the shim) is left alone.
	if strings.HasPrefix(tokens[1], "-") || strings.Contains(tokens[1], "/") {
		return "", nil, false
	}
	if len(tokens) > 2 {
		return tokens[1], tokens[2:], true
	}
	return tokens[1], nil, true
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
