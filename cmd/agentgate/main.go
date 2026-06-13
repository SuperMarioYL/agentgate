// Command agentgate is a runtime per-action host sandbox for coding agents.
//
//	agentgate run -- <agent command>   wrap an agent; gate each subprocess
//	agentgate init                      drop a default policy.yaml
//	agentgate audit                     print the JSONL trail of gated actions
//
// It gates the subprocesses a coding agent spawns (dependency installs,
// generated scripts) and its network egress, per action, with the agent's
// intent attached — instead of all-or-nothing container isolation.
package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SuperMarioYL/agentgate/internal/audit"
	"github.com/SuperMarioYL/agentgate/internal/gate"
	"github.com/SuperMarioYL/agentgate/internal/policy"
	"github.com/SuperMarioYL/agentgate/internal/prompt"
	"github.com/SuperMarioYL/agentgate/internal/wrap"
	"github.com/spf13/cobra"
)

// version is overridden at release time via -ldflags.
var version = "0.1.0"

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
	root.AddCommand(runCmd(), initCmd(), auditCmd())
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
	)
	cmd := &cobra.Command{
		Use:   "run -- <agent command>",
		Short: "Wrap an agent and gate every subprocess + egress it triggers",
		Long:  "Launches the given agent command. Each subprocess it spawns and each network host it tries to reach is resolved against the policy before it runs.",
		Args:  cobra.MinimumNArgs(1),
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

			pr := prompt.New(os.Stdin, os.Stderr)
			eng := gate.NewEngine(pol, pr, lg)
			if always && pol.Path() != "" {
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
	return cmd
}

func auditCmd() *cobra.Command {
	var auditPath string
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Print the JSONL trail of every gated action",
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := audit.Read(auditPath)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintln(cmd.OutOrStdout(), "no audit log yet — run an agent under `agentgate run` first")
					return nil
				}
				return err
			}
			for _, e := range entries {
				mark := "✓"
				if e.Decision == policy.Deny {
					mark = "✗"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %-10s  %-7s  %s\n",
					mark, e.Time.Format("15:04:05"), e.Action, e.Decision, e.Target)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&auditPath, "audit", defaultAuditPath(), "audit log path (JSONL)")
	return cmd
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
