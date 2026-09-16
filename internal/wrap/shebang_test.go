package wrap

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeScript drops a file with the given content into dir and makes it
// executable, standing in for a shebang script or a fake interpreter.
func writeScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// TestShebangEnvInterp covers the parser: only the `#!/usr/bin/env <interp>
// [extra...]` form with a bare interpreter name yields ok=true — the only form
// whose PATH lookup can re-enter the shim dir. Everything else must fall back
// to exec'ing the script itself.
func TestShebangEnvInterp(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		content string
		interp  string
		extra   []string
		ok      bool
	}{
		{"env node", "#!/usr/bin/env node\nconsole.log(1)\n", "node", nil, true},
		{"env node CRLF", "#!/usr/bin/env node\r\nconsole.log(1)\n", "node", nil, true},
		{"env python3 with flag", "#!/usr/bin/env python3 -u\nprint(1)\n", "python3", []string{"-u"}, true},
		{"env ruby with flags", "#!/usr/bin/env ruby -w -x\n", "ruby", []string{"-w", "-x"}, true},
		{"direct path shebang", "#!/usr/bin/node\n", "", nil, false},
		{"relative path shebang", "#!/usr/bin/../bin/node\n", "", nil, false},
		{"env -S flag", "#!/usr/bin/env -S node -x\n", "", nil, false},
		{"env -i flag", "#!/usr/bin/env -i node\n", "", nil, false},
		{"non-env shebang", "#!/bin/sh\n", "", nil, false},
		{"no shebang", "console.log(1)\n", "", nil, false},
		{"empty file", "", "", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeScript(t, dir, strings.ReplaceAll(tc.name, " ", "_"), tc.content)
			interp, extra, ok := shebangEnvInterp(p)
			if ok != tc.ok || interp != tc.interp || !reflect.DeepEqual(extra, tc.extra) {
				t.Fatalf("shebangEnvInterp(%q) = (%q, %v, %v), want (%q, %v, %v)",
					tc.content, interp, extra, ok, tc.interp, tc.extra, tc.ok)
			}
		})
	}

	// A missing file is not a shebang script.
	if _, _, ok := shebangEnvInterp(filepath.Join(dir, "does-not-exist")); ok {
		t.Fatalf("missing file must not parse as an env shebang")
	}
}

// Regression test for fix-shebang-reentry-double-prompt: when the allowed exec
// target is an `env <interp>` shebang script whose interpreter is an intercepted
// command, the argv must exec the REAL interpreter (resolved past the shim dir)
// with the script path — so the kernel's shebang handling never re-enters the
// shim PATH and re-prompts the same action under the interpreter's name.
//
// Before the fix, ONE piped operator answer for `npm install left-pad` (npm
// installed as the universal "#!/usr/bin/env node" wrapper) allowed the npm
// shim, then the shebang's `env node` PATH lookup found the shim dir's node and
// prompted AGAIN — with stdin exhausted the SAME action was denied and the
// approved install never ran.
func TestShebangExecArgvSkipsShimForInterpreter(t *testing.T) {
	tmp := t.TempDir()
	shimDir := filepath.Join(tmp, "shim")
	realBin := filepath.Join(tmp, "real")
	for _, d := range []string{shimDir, realBin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A fake shim-dir node (what /usr/bin/env would wrongly find) and the real one.
	writeScript(t, shimDir, "node", "#!/bin/sh\nexec shim-node\n")
	// lookReal skips a PATH dir that contains broker.sock, so mark the shim dir.
	writeScript(t, shimDir, "broker.sock", "")
	realNode := writeScript(t, realBin, "node", "#!/bin/sh\nexec real-node\n")
	realPython3 := writeScript(t, realBin, "python3", "#!/bin/sh\nexec real-python3\n")
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+realBin)

	// The universal npm wrapper shape.
	script := writeScript(t, tmp, "npm", "#!/usr/bin/env node\nconsole.log(1)\n")
	argv, ok := shebangExecArgv(script, []string{"install", "left-pad"})
	if !ok {
		t.Fatalf("env-node shebang must be rewritten past the shim dir")
	}
	want := []string{realNode, script, "install", "left-pad"}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
	if argv[0] == filepath.Join(shimDir, "node") {
		t.Fatalf("interpreter resolved to the shim wrapper %s — the shebang hop would re-prompt", argv[0])
	}

	// Interpreter extras keep their position between the interpreter and the script.
	script = writeScript(t, tmp, "pip", "#!/usr/bin/env python3 -u\n")
	argv, ok = shebangExecArgv(script, []string{"install", "requests"})
	if !ok {
		t.Fatalf("env-python3 shebang must be rewritten")
	}
	if len(argv) != 5 || argv[0] != realPython3 || argv[1] != "-u" || argv[2] != script {
		t.Fatalf("argv = %v, want [realPython3 -u script install requests]", argv)
	}

	// A non-intercepted interpreter must NOT be rewritten (no shim exists for it,
	// so env's lookup already finds the real binary).
	script = writeScript(t, tmp, "tool", "#!/usr/bin/env awk\n")
	if _, ok := shebangExecArgv(script, nil); ok {
		t.Fatalf("non-intercepted interpreter must fall back to direct script exec")
	}

	// A direct-path shebang never re-enters the shim (no PATH lookup) — no rewrite.
	script = writeScript(t, tmp, "old", "#!/usr/bin/node\n")
	if _, ok := shebangExecArgv(script, nil); ok {
		t.Fatalf("direct-path shebang must fall back to direct script exec")
	}
}
