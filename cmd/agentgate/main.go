// Command agentgate is a runtime per-action host sandbox for coding agents.
//
//	agentgate run -- <agent command>   wrap an agent; gate each subprocess
//	agentgate init                      drop a default policy.yaml
//	agentgate audit                     print the JSONL trail of gated actions
//	agentgate policy                    show the effective rule set (or --explain one action)
//
// It gates the subprocesses a coding agent spawns (dependency installs,
// generated scripts) and its network egress, per action, with the agent's
// intent attached — instead of all-or-nothing container isolation.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/SuperMarioYL/agentgate/internal/audit"
	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/gate"
	"github.com/SuperMarioYL/agentgate/internal/policy"
	"github.com/SuperMarioYL/agentgate/internal/prompt"
	"github.com/SuperMarioYL/agentgate/internal/wrap"
	"github.com/spf13/cobra"
)

// version is overridden at release time via -ldflags.
var version = "0.5.0"

//go:embed policy.default.yaml
var defaultPolicy []byte

func main() {
	// Hidden shim fast-path: the wrapper scripts invoke `agentgate __shim ...`.
	// Handle it before cobra so it stays out of help output and has zero overhead.
	if len(os.Args) >= 2 && os.Args[1] == "__shim" {
		os.Exit(wrap.ShimMain(os.Args[2:]))
	}
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "agentgate",
		Short:         "Per-action host sandbox for coding agents",
		Long:          "AgentGate gates the subprocesses a coding agent spawns (dependency installs, scripts) and its network egress, per action, with the agent's intent attached.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(runCmd(), initCmd(), auditCmd(), checkCmd(), policyCmd())
	return root
}

func defaultPolicyPath() string {
	if v := os.Getenv("AGENTGATE_POLICY"); v != "" {
		return v
	}
	return "policy.yaml"
}

func defaultAuditPath() string {
	if v := os.Getenv("AGENTGATE_AUDIT"); v != "" {
		return v
	}
	return filepath.Join(".agentgate", "audit.jsonl")
}

func initCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a sensible default policy.yaml into the current directory",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := defaultPolicyPath()
			if _, err := os.Stat(path); err == nil && !force {
				return fmt.Errorf("%s already exists (use --force to overwrite)", path)
			}
			if err := os.WriteFile(path, defaultPolicy, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s — edit it, then run: agentgate run -- <your agent>\n", path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing policy file")
	return cmd
}

func runCmd() *cobra.Command {
	var (
		policyPath string
		auditPath  string
		agentName  string
		noNet      bool
		always     bool
		enforce    bool
	)
	cmd := &cobra.Command{
		Use:   "run -- <agent command>",
		Short: "Wrap an agent and gate every subprocess + egress it triggers",
		Long: "Launches the given agent command. Each subprocess it spawns and each network host it tries to reach is resolved against the policy before it runs.\n\n" +
			"Pass --enforce for non-interactive CI: with no operator present, every `ask` " +
			"resolves to deny (deny-by-default) and the run never blocks on a TTY prompt.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if policyPath == "" {
				policyPath = defaultPolicyPath()
			}
			pol, err := loadOrDefault(policyPath)
			if err != nil {
				return err
			}
			lg, err := audit.Open(auditPath)
			if err != nil {
				return err
			}
			defer lg.Close()

			// Headless enforce mode: attach a nil prompter so the engine fails
			// closed (every `ask` becomes deny) without ever waiting on a TTY,
			// making agentgate usable in CI where no operator is present.
			var pr *prompt.Prompter
			if enforce {
				fmt.Fprintln(os.Stderr, "agentgate: --enforce (headless): no prompts, ask resolves to deny (deny-by-default)")
			} else {
				pr = prompt.New(os.Stdin, os.Stderr)
			}
			eng := gate.NewEngine(pol, pr, lg)
			// --always persistence requires an operator to choose [A]lways, so it
			// is meaningless (and disabled) under headless enforce.
			if always && !enforce && pol.Path() != "" {
				eng.SetPersistPath(pol.Path())
			}

			self, err := os.Executable()
			if err != nil {
				return err
			}
			runner := wrap.NewRunner(eng, agentName, self)

			if !noNet {
				ng := gate.NewNetGate(eng, agentName)
				addr, err := ng.Listen()
				if err == nil {
					runner.NetProxy = addr
					defer ng.Close()
				}
			}

			code, err := runner.Run(args)
			if err != nil {
				return err
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", "", "policy file (default: ./policy.yaml or $AGENTGATE_POLICY)")
	cmd.Flags().StringVar(&auditPath, "audit", defaultAuditPath(), "audit log path (JSONL)")
	cmd.Flags().StringVar(&agentName, "agent", "claude-code", "identifier for the wrapped agent")
	cmd.Flags().BoolVar(&noNet, "no-net", false, "disable the network egress gate")
	cmd.Flags().BoolVar(&always, "always", true, "persist [A]lways operator choices back to the policy file")
	cmd.Flags().BoolVar(&enforce, "enforce", false, "headless CI mode: no prompts, every `ask` resolves to deny (deny-by-default)")
	return cmd
}

func auditCmd() *cobra.Command {
	var (
		auditPath string
		decision  string
		action    string
		since     string
		jsonOut   bool
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Print (and optionally filter) the JSONL trail of every gated action",
		Long: "Reads the audit log and prints each gated decision. Filter to answer " +
			"\"what got blocked?\" without grepping:\n\n" +
			"  agentgate audit --decision deny\n" +
			"  agentgate audit --action net_egress --since 2h\n" +
			"  agentgate audit --decision deny --json   # raw JSONL passthrough\n\n" +
			"--since accepts an RFC3339 timestamp, a date (2006-01-02), or a duration ago (2h, 30m).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := audit.Read(auditPath)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintln(cmd.OutOrStdout(), "no audit log yet — run an agent under `agentgate run` first")
					return nil
				}
				return err
			}

			sinceT, err := audit.ParseSince(since)
			if err != nil {
				return err
			}
			filter := audit.Filter{
				Decision: policy.Decision(decision),
				Action:   agentctx.ActionKind(action),
				Since:    sinceT,
			}
			if err := filter.Validate(); err != nil {
				return err
			}
			entries = filter.Apply(entries)

			out := cmd.OutOrStdout()
			if jsonOut {
				enc := json.NewEncoder(out)
				for _, e := range entries {
					if err := enc.Encode(e); err != nil {
						return err
					}
				}
				return nil
			}
			for _, e := range entries {
				mark := "✓"
				if e.Decision == policy.Deny {
					mark = "✗"
				}
				fmt.Fprintf(out, "%s  %s  %-10s  %-7s  %s\n",
					mark, e.Time.Format("15:04:05"), e.Action, e.Decision, e.Target)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&auditPath, "audit", defaultAuditPath(), "audit log path (JSONL)")
	cmd.Flags().StringVar(&decision, "decision", "", "keep only entries with this decision: allow | deny | ask")
	cmd.Flags().StringVar(&action, "action", "", "keep only entries with this action: exec | fs_write | net_egress")
	cmd.Flags().StringVar(&since, "since", "", "keep only entries at/after this time (RFC3339, a date, or a duration ago like 2h)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit raw JSONL instead of the formatted table")
	return cmd
}

func checkCmd() *cobra.Command {
	var (
		policyPath string
		action     string
	)
	cmd := &cobra.Command{
		Use:   "check <target>",
		Short: "Dry-run how the policy would resolve an action, without running it",
		Long: "Resolves a hypothetical action against the policy and prints the decision " +
			"(allow / deny / ask) plus which rule fired — no subprocess is run, no egress " +
			"is dialed, nothing is written to the audit log.\n\n" +
			"The target is a command line for --action exec, a path for fs_write, or a " +
			"host[:port] for net_egress. Use it to sanity-check a policy before trusting an agent to it.\n\n" +
			"  agentgate check --action exec   \"npm install left-pad\"\n" +
			"  agentgate check --action net_egress telemetry.evil.example:443\n" +
			"  agentgate check --action fs_write  /etc/passwd",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if policyPath == "" {
				policyPath = defaultPolicyPath()
			}
			pol, err := loadOrDefault(policyPath)
			if err != nil {
				return err
			}

			kind := agentctx.ActionKind(action)
			req, err := buildCheckRequest(kind, args)
			if err != nil {
				return err
			}

			eng := gate.NewEngine(pol, nil, nil)
			exp := eng.Explain(req)

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "action  : %s\n", req.Action)
			fmt.Fprintf(out, "target  : %s\n", req.Target)
			fmt.Fprintf(out, "intent  : %s\n", req.Intent)
			fmt.Fprintf(out, "decision: %s (%s)\n", exp.Decision, describeSource(exp))
			return nil
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", "", "policy file (default: ./policy.yaml or $AGENTGATE_POLICY)")
	cmd.Flags().StringVar(&action, "action", "exec", "action kind: exec | fs_write | net_egress")
	return cmd
}

func policyCmd() *cobra.Command {
	var (
		policyPath string
		explain    bool
		action     string
	)
	cmd := &cobra.Command{
		Use:   "policy [target]",
		Short: "Show the effective rule set, explain one action, or revoke a rule (rm)",
		Long: "Prints the effective policy — every rule's action, target glob, decision, and " +
			"scope, in first-match-wins order, plus the default applied when none match. This " +
			"includes rules an `--always` operator choice appended, so you can review what you've " +
			"granted instead of trusting an invisible, growing rule set.\n\n" +
			"With --explain, resolves a single hypothetical action and prints which rule it hits " +
			"(reusing the same side-effect-free resolver as `agentgate check`). Use the `rm` " +
			"subcommand to revoke a rule you spotted here — so an over-broad `--always` grant is " +
			"as easy to take back as it was to make:\n\n" +
			"  agentgate policy                                  # list every effective rule\n" +
			"  agentgate policy --explain --action exec \"npm install left-pad\"\n" +
			"  agentgate policy --explain --action net_egress telemetry.evil.example:443\n" +
			"  agentgate policy rm 2                              # revoke the rule shown at index 2\n" +
			"  agentgate policy rm --action exec --target \"npm install*\"",
		RunE: func(cmd *cobra.Command, args []string) error {
			if policyPath == "" {
				policyPath = defaultPolicyPath()
			}
			pol, err := loadOrDefault(policyPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			if explain {
				if len(args) == 0 {
					return fmt.Errorf("--explain needs a target (a command line, path, or host[:port])")
				}
				kind := agentctx.ActionKind(action)
				req, err := buildCheckRequest(kind, args)
				if err != nil {
					return err
				}
				eng := gate.NewEngine(pol, nil, nil)
				exp := eng.Explain(req)
				fmt.Fprintf(out, "action  : %s\n", req.Action)
				fmt.Fprintf(out, "target  : %s\n", req.Target)
				fmt.Fprintf(out, "decision: %s (%s)\n", exp.Decision, describeSource(exp))
				if exp.Rule != nil {
					glob := exp.Rule.Match.TargetGlob
					if glob == "" {
						glob = "any"
					}
					fmt.Fprintf(out, "matched : action=%s target=%s -> %s\n",
						dispAction(string(exp.Rule.Match.Action)), glob, exp.Rule.Decision)
				}
				return nil
			}

			return pol.WriteTable(out)
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", "", "policy file (default: ./policy.yaml or $AGENTGATE_POLICY)")
	cmd.Flags().BoolVar(&explain, "explain", false, "resolve one hypothetical action and show which rule it hits")
	cmd.Flags().StringVar(&action, "action", "exec", "with --explain: action kind: exec | fs_write | net_egress")
	// share --policy with the rm subcommand so `agentgate policy rm --policy X` works.
	cmd.AddCommand(policyRmCmd(&policyPath))
	return cmd
}

// policyRmCmd revokes a persisted rule — the write half of `agentgate policy`.
// It takes either the 1-based index printed by `agentgate policy`, or a
// --action/--target match, rewrites the policy file with that rule removed, and
// re-prints the effective table so the operator sees the result. It refuses
// (non-zero exit, file untouched) on an out-of-range index, the default row, or a
// no-match, and it will not touch the built-in default policy (there is no file to
// rewrite until `agentgate init`).
func policyRmCmd(sharedPolicyPath *string) *cobra.Command {
	var (
		rmAction string
		rmTarget string
	)
	cmd := &cobra.Command{
		Use:   "rm [index]",
		Short: "Revoke a persisted rule by its printed index or by --action/--target match",
		Long: "Removes one rule from the policy file — the counterpart to the read-only listing " +
			"above, so a mistaken `--always` grant is as easy to revoke as it was to make.\n\n" +
			"Give the 1-based index `agentgate policy` printed, OR match a rule by its action + " +
			"target glob. The removed rule and the new effective table are printed. The default " +
			"row (shown as *) is not a rule and cannot be removed.\n\n" +
			"  agentgate policy rm 2\n" +
			"  agentgate policy rm --action exec --target \"npm install*\"",
		RunE: func(cmd *cobra.Command, args []string) error {
			policyPath := *sharedPolicyPath
			if policyPath == "" {
				policyPath = defaultPolicyPath()
			}
			// A removal must persist, so we need a real file — refuse to "remove"
			// from the built-in default (there is nothing to rewrite).
			if _, statErr := os.Stat(policyPath); statErr != nil {
				return fmt.Errorf("no policy file at %s to modify — run `agentgate init` first (nothing is persisted for the built-in default policy)", policyPath)
			}
			pol, err := policy.Load(policyPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			byMatch := cmd.Flags().Changed("action") || cmd.Flags().Changed("target")
			if byMatch && len(args) > 0 {
				return fmt.Errorf("give EITHER an index OR --action/--target, not both")
			}

			var removed policy.Rule
			var atIndex int
			switch {
			case byMatch:
				removed, atIndex, err = pol.RemoveByMatch(rmAction, rmTarget)
			case len(args) == 1:
				idx, convErr := strconv.Atoi(strings.TrimSpace(args[0]))
				if convErr != nil {
					return fmt.Errorf("index must be a number (the value shown in the # column of `agentgate policy`): %q", args[0])
				}
				atIndex = idx
				removed, err = pol.RemoveByIndex(idx)
			default:
				return fmt.Errorf("need a rule to remove: an index (e.g. `agentgate policy rm 2`) or --action/--target")
			}
			if err != nil {
				return err
			}

			if err := pol.Save(policyPath); err != nil {
				return fmt.Errorf("write policy after removal: %w", err)
			}

			glob := removed.Match.TargetGlob
			if glob == "" {
				glob = "any"
			}
			fmt.Fprintf(out, "removed rule #%d: action=%s target=%s -> %s\n\n",
				atIndex, dispAction(string(removed.Match.Action)), glob, removed.Decision)
			return pol.WriteTable(out)
		},
	}
	cmd.Flags().StringVar(&rmAction, "action", "", "match a rule by action: exec | fs_write | net_egress")
	cmd.Flags().StringVar(&rmTarget, "target", "", "match a rule by its exact target glob (as shown in `agentgate policy`)")
	return cmd
}

// dispAction renders an empty action scope as "any" for the explain output.
func dispAction(a string) string {
	if a == "" {
		return "any"
	}
	return a
}

// buildCheckRequest assembles a GateRequest from the check command's flags and
// positional target, mirroring how each gate constructs its own request so the
// dry-run resolves identically to a live action.
func buildCheckRequest(kind agentctx.ActionKind, args []string) (agentctx.GateRequest, error) {
	switch kind {
	case agentctx.ActionExec:
		return agentctx.GateRequest{
			Action: kind,
			Target: strings.Join(args, " "),
			Intent: agentctx.InferIntent(args),
			Agent:  "check",
			Args:   args,
		}, nil
	case agentctx.ActionFSWrite:
		abs, err := filepath.Abs(args[0])
		if err != nil {
			abs = args[0]
		}
		return agentctx.GateRequest{
			Action: kind,
			Target: abs,
			Intent: "agent wants to write " + abs,
			Agent:  "check",
		}, nil
	case agentctx.ActionNetEgress:
		return agentctx.GateRequest{
			Action: kind,
			Target: args[0],
			Intent: "agent wants to reach " + args[0],
			Agent:  "check",
		}, nil
	default:
		return agentctx.GateRequest{}, fmt.Errorf("unknown --action %q (want exec | fs_write | net_egress)", kind)
	}
}

// describeSource turns an Explanation into a short human reason for the decision.
func describeSource(exp gate.Explanation) string {
	switch exp.Source {
	case "default":
		return "no rule matched, fell through to default"
	case "scope":
		return "matched an allow rule but the path escapes its scope"
	default:
		return "matched a rule"
	}
}

// loadOrDefault loads the policy file, falling back to the embedded default
// (with a notice) when no policy exists yet so `run` works before `init`.
func loadOrDefault(path string) (*policy.Policy, error) {
	if _, err := os.Stat(path); err == nil {
		return policy.Load(path)
	}
	fmt.Fprintf(os.Stderr, "agentgate: no %s found, using built-in default policy (run `agentgate init` to customise)\n", path)
	return policy.Parse(defaultPolicy)
}
