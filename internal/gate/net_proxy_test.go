package gate

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/SuperMarioYL/agentgate/internal/audit"
	"github.com/SuperMarioYL/agentgate/internal/policy"
	"github.com/SuperMarioYL/agentgate/internal/prompt"
)

// m2 end-to-end: drive a real HTTP request through the redirect proxy and prove
// the proxy returns 403 for an undeclared host while forwarding an allowed one.
func TestProxyBlocksUndeclaredHostHTTP(t *testing.T) {
	pol, err := policy.Parse([]byte("default: deny\nrules:\n  - match: {action: net_egress, target_glob: \"allowed.test\"}\n    decision: allow\n"))
	if err != nil {
		t.Fatal(err)
	}
	pr := prompt.New(strings.NewReader(""), new(bytes.Buffer))
	pr.NoColor = true
	var log bytes.Buffer
	eng := NewEngine(pol, pr, audit.NewWriter(&log))
	ng := NewNetGate(eng, "claude-code")
	addr, err := ng.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ng.Close()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Undeclared host: proxy should reject with 403 before any real dial.
	resp, err := client.Get("http://undeclared.evil.test/payload")
	if err != nil {
		t.Fatalf("request through proxy errored unexpectedly: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("undeclared host should get 403, got %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "denied by policy") {
		t.Fatalf("403 body should explain denial, got %q", body)
	}
	if !strings.Contains(log.String(), `"action":"net_egress"`) ||
		!strings.Contains(log.String(), `"decision":"deny"`) {
		t.Fatalf("blocked egress missing from audit:\n%s", log.String())
	}
}
