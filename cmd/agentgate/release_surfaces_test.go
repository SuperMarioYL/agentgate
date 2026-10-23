package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// findRepoFile walks up from the test working directory until it finds rel,
// returning the first match (the repo root is within a few levels).
func findRepoFile(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		cand := filepath.Join(dir, rel)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// shippedVersions is every version shipped to GitHub as a release/tag, oldest
// first (gh release list). Each one MUST have a `## [X.Y.Z]` header in
// CHANGELOG.md — v0.9.0 and v0.10.0 shipped (2026-07-28 / 2026-08-21) without
// entries and the header list jumped [0.11.0] -> [0.8.0], leaving two shipped
// versions with no changelog record. Extend this list when a new version ships.
var shippedVersions = []string{
	"0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.5.0", "0.6.0",
	"0.7.0", "0.8.0", "0.9.0", "0.10.0", "0.11.0", "0.12.0", "0.13.0", "0.14.0",
}

// TestChangelogCoversShippedVersions asserts every shipped version has a
// CHANGELOG header, so a release can never again go out without its entry.
func TestChangelogCoversShippedVersions(t *testing.T) {
	path := findRepoFile(t, "CHANGELOG.md")
	if path == "" {
		t.Skipf("CHANGELOG.md not found by walking up from %q (run via `go test ./...` from the repo root)", mustCwd(t))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(data)
	var missing []string
	for _, v := range shippedVersions {
		if !strings.Contains(text, "## ["+v+"]") {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("CHANGELOG.md is missing entries for shipped version(s): %s\n"+
			"these versions shipped as GitHub releases but carry no `## [X.Y.Z]` header — backfill them.", strings.Join(missing, ", "))
	}
}

// TestGoreleaserMatchesDeclaredPlatforms asserts the release artifact set stays
// inside the documented platform support (Linux + macOS; README platform badge).
// v0.12.0 shipped windows zip archives even though the runtime cannot work on
// windows: the shims are "#!/bin/sh" scripts and syscall.Exec returns EWINDOWS
// unconditionally there (go1.24 src/syscall/exec_windows.go:403), so those
// binaries install but can never gate anything.
func TestGoreleaserMatchesDeclaredPlatforms(t *testing.T) {
	path := findRepoFile(t, ".goreleaser.yaml")
	if path == "" {
		t.Skipf(".goreleaser.yaml not found by walking up from %q", mustCwd(t))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg struct {
		Builds []struct {
			Goos []string `yaml:"goos"`
		} `yaml:"builds"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(cfg.Builds) == 0 {
		t.Fatalf("no builds configured in %s", path)
	}
	for _, b := range cfg.Builds {
		for _, goos := range b.Goos {
			if goos == "windows" {
				t.Fatalf(".goreleaser.yaml ships goos=%q but the runtime is POSIX-only "+
					"(#!/bin/sh shims, syscall.Exec=EWINDOWS on windows) and the README "+
					"declares Linux | macOS only — drop windows from the release artifact set", goos)
			}
		}
	}
}
