package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionProvenanceLockstep asserts the shipped web/site.json content_version
// (with any leading "v" stripped) equals the main.version package var, so the
// product-site provenance surface cannot silently drift behind the binary.
//
// v0.11.0 shipped VERSION=0.11.0 / main.version="0.11.0" / CHANGELOG [0.11.0]
// but the v0.11.0 site refresh never landed: web/site.json content_version was
// still "v0.10.0" (verified on both the v0.11.0 tag and origin/main), so the
// live site claimed stale v0.10.0 content provenance while the binary reported
// 0.11.0. This test locks the invariant going forward.
//
// RED on v0.11.0: site content_version "v0.10.0" -> "0.10.0" != version "0.11.0".
// GREEN after the v0.12.0 bump: both at "0.12.0".
func TestVersionProvenanceLockstep(t *testing.T) {
	sitePath := findRepoSiteJSON(t)
	if sitePath == "" {
		t.Skipf("web/site.json not found by walking up from %q — lockstep test needs the repo layout (run via `go test ./...` from the repo root)", mustCwd(t))
	}

	data, err := os.ReadFile(sitePath)
	if err != nil {
		t.Fatalf("read %s: %v", sitePath, err)
	}
	var site struct {
		ContentVersion string `json:"content_version"`
	}
	if err := json.Unmarshal(data, &site); err != nil {
		t.Fatalf("parse %s: %v", sitePath, err)
	}
	if site.ContentVersion == "" {
		t.Fatalf("web/site.json has no content_version field")
	}

	// Normalise the site's form to the binary's no-"v" format: the v0.11.0
	// drift also mixed "v0.10.0" (site) with "0.11.0" (binary), so compare on
	// the canonical stripped form.
	got := strings.TrimPrefix(site.ContentVersion, "v")
	want := version
	if got != want {
		t.Fatalf("version provenance drift: web/site.json content_version=%q (stripped %q) != main.version %q\n"+
			"the site provenance surface lagged the binary (v0.11.0 shipped the binary at 0.11.0 but left site.json at v0.10.0); bump web/site.json content_version to match the binary.",
			site.ContentVersion, got, want)
	}
}

// findRepoSiteJSON walks up from the test working directory until it finds
// web/site.json, returning the first match. go test sets the working directory
// to the package source dir (cmd/agentgate), so the walk climbs cmd/agentgate
// -> cmd -> repo root, where web/site.json lives. It also covers a repo-root
// invocation. Returns "" if not found within a reasonable climb.
func findRepoSiteJSON(t *testing.T) string {
	t.Helper()
	dir := mustCwd(t)
	rel := filepath.Join("web", "site.json")
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

func mustCwd(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return dir
}
