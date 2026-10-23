package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SuperMarioYL/agentgate/internal/policy"
	"github.com/spf13/cobra"
)

// customPolicy is a two-rule policy used to prove `policy rm` can address a file
// that is NOT ./policy.yaml.
const customPolicy = "default: deny\nrules:\n" +
	"  - match: {action: exec, target_glob: \"npm install*\"}\n" +
	"    decision: allow\n" +
	"  - match: {action: exec}\n" +
	"    decision: ask\n"

// v0.14.0 fix (fix-policy-rm-missing-policy-flag): --policy was registered with
// cmd.Flags() on the `policy` command and the comment claimed it was shared with
// the rm subcommand. Cobra does not propagate non-persistent flags to
// subcommands, so the rm command had no --policy at all and both invocation
// forms died with "unknown flag: --policy" — the revoke half of the feature was
// unreachable for every policy that is not ./policy.yaml or $AGENTGATE_POLICY.
// RED before the fix: both subtests below failed with that unknown-flag error.
func TestPolicyRmAcceptsPolicyFlag(t *testing.T) {
	seed := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "custom.yaml")
		if err := os.WriteFile(path, []byte(customPolicy), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	run := func(t *testing.T, args ...string) (string, error) {
		t.Helper()
		root := rootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(args)
		err := root.Execute()
		return out.String(), err
	}
	ruleCount := func(t *testing.T, path string) int {
		t.Helper()
		loaded, err := policy.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return len(loaded.Rules)
	}

	// Form 1: the flag before the subcommand (what the reviewer of a custom
	// policy naturally types after running `agentgate policy --policy X`).
	path := seed(t)
	out, err := run(t, "policy", "--policy", path, "rm", "1")
	if err != nil {
		t.Fatalf("`policy --policy <file> rm 1` must work, got error: %v (output:\n%s)", err, out)
	}
	if n := ruleCount(t, path); n != 1 {
		t.Fatalf("the NAMED file must lose exactly one rule, got %d left", n)
	}
	if !strings.Contains(out, "removed rule #1") {
		t.Fatalf("removal should report the removed rule, got:\n%s", out)
	}

	// Form 2: the flag after the subcommand.
	path2 := seed(t)
	out2, err := run(t, "policy", "rm", "--policy", path2, "1")
	if err != nil {
		t.Fatalf("`policy rm --policy <file> 1` must work, got error: %v (output:\n%s)", err, out2)
	}
	if n := ruleCount(t, path2); n != 1 {
		t.Fatalf("the NAMED file must lose exactly one rule, got %d left", n)
	}

	// The matched rule is gone, and the surviving rule keeps first-match order.
	path3 := seed(t)
	if _, err := run(t, "policy", "--policy", path3, "rm", "1"); err != nil {
		t.Fatalf("rm: %v", err)
	}
	loaded, err := policy.Load(path3)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Rules[0].Match.Action != "exec" || loaded.Rules[0].Decision != "ask" {
		t.Fatalf("after removing rule #1 the ask rule should be first, got %+v", loaded.Rules[0])
	}

	// An out-of-range index still fails without mutating the named file.
	path4 := seed(t)
	if _, err := run(t, "policy", "--policy", path4, "rm", "99"); err == nil {
		t.Fatal("an out-of-range index must exit non-zero")
	}
	if n := ruleCount(t, path4); n != 2 {
		t.Fatalf("a rejected removal must leave the file untouched, got %d rules", n)
	}
}

// The --target usage string used to contain a backquoted cross-reference
// ("...as shown in `agentgate policy`"), and pflag's UnquoteUsage treats the
// FIRST backquoted substring as the flag's value placeholder — so
// `agentgate policy rm --help` rendered `--target agentgate policy` and dropped
// the cross-reference from the description. RED before the fix.
func TestPolicyRmTargetFlagRendersStringPlaceholder(t *testing.T) {
	root := rootCmd()
	var policyCmdFound *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "policy" {
			policyCmdFound = c
			break
		}
	}
	if policyCmdFound == nil {
		t.Fatal("no `policy` command in the tree")
	}
	var rm *cobra.Command
	for _, c := range policyCmdFound.Commands() {
		if c.Name() == "rm" {
			rm = c
			break
		}
	}
	if rm == nil {
		t.Fatal("no `policy rm` command in the tree")
	}

	flag := rm.Flag("target")
	if flag == nil {
		t.Fatal("policy rm has no --target flag")
	}
	if strings.Contains(flag.Usage, "`") {
		t.Fatalf("--target usage must not contain backquotes (pflag turns the first pair into the value placeholder): %q", flag.Usage)
	}
	usages := rm.Flags().FlagUsages()
	if !strings.Contains(usages, "--target string") {
		t.Fatalf("--target should render with the string placeholder, got:\n%s", usages)
	}
	if strings.Contains(usages, "--target agentgate policy") {
		t.Fatalf("--target is rendered with the mangled placeholder, got:\n%s", usages)
	}
}
