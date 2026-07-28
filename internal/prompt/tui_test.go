package prompt

import (
	"bytes"
	"strings"
	"testing"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
)

func ask(t *testing.T, input string) (Choice, string) {
	t.Helper()
	var out bytes.Buffer
	p := New(strings.NewReader(input), &out)
	p.NoColor = true
	c, err := p.Ask(agentctx.GateRequest{
		Action: agentctx.ActionExec,
		Target: "npm install chalk",
		Intent: "agent wants to install npm package: chalk",
		Agent:  "claude-code",
	})
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	return c, out.String()
}

func TestAskChoices(t *testing.T) {
	if c, _ := ask(t, "a\n"); c != ChoiceAllow {
		t.Fatalf("'a' -> %v", c)
	}
	if c, _ := ask(t, "d\n"); c != ChoiceDeny {
		t.Fatalf("'d' -> %v", c)
	}
	if c, _ := ask(t, "A\n"); c != ChoiceAlways {
		t.Fatalf("'A' -> %v", c)
	}
}

func TestAskShowsIntent(t *testing.T) {
	_, out := ask(t, "a\n")
	if !strings.Contains(out, "agent wants to install npm package: chalk") {
		t.Fatalf("prompt did not surface the agent intent:\n%s", out)
	}
	if !strings.Contains(out, "claude-code") {
		t.Fatalf("prompt did not surface the agent name:\n%s", out)
	}
}

func TestAskEOFFailsClosed(t *testing.T) {
	if c, _ := ask(t, ""); c != ChoiceDeny {
		t.Fatalf("EOF should fail closed to deny, got %v", c)
	}
}

// v0.9.0 regression (fix-prompt-ask-per-call-bufio-reader-drops-answers): a
// non-interactive operator piping multiple answers must have every Ask read its
// OWN answer. Each Ask previously built a fresh bufio.NewReader(p.In); a
// bufio.Reader's first fill can pull MORE than one line from a pipe or
// strings.Reader (up to the 4KiB buffer) in a single read, so the bytes for the
// 2nd answer were stranded in a discarded buffer and the next Ask's fresh
// reader saw EOF -> ChoiceDeny ("no operator attached"). The operator piping
// `printf 'a\na\n' | agentgate run` got the FIRST action allowed and every
// subsequent one silently DENIED — a misclassified fail-closed. The fix reuses
// one buffered reader on the Prompter so unconsumed bytes survive between prompts.
func TestAskReusesBufferedPipedAnswers(t *testing.T) {
	var out bytes.Buffer
	p := New(strings.NewReader("a\na\n"), &out) // two piped answers
	p.NoColor = true

	for i := 0; i < 2; i++ {
		c, err := p.Ask(agentctx.GateRequest{
			Action: agentctx.ActionExec,
			Target: "npm install chalk",
			Intent: "agent wants to install npm package: chalk",
			Agent:  "claude-code",
		})
		if err != nil {
			t.Fatalf("ask #%d: %v", i, err)
		}
		if c != ChoiceAllow {
			t.Fatalf("ask #%d: piped 'a' should allow, got %v (2nd answer stranded in a discarded buffer)", i, c)
		}
	}
}

// v0.9.0 regression (fix-always-without-policy-file-lies-remembered): with no
// policy file / persist path configured, [A]lways allows the action once but
// persists NOTHING (the engine skips appendAlwaysRule when e.persist == ""), so
// the next same-kind action re-prompts. The prompt previously printed
// "allowed + remembered" unconditionally — lying that the grant was remembered.
// It must honestly say "not remembered" when persist is not configured, and only
// claim "remembered" when persistence is actually configured.
func TestAskAlwaysHonestAboutPersistence(t *testing.T) {
	req := agentctx.GateRequest{
		Action: agentctx.ActionExec,
		Target: "npm install chalk",
		Intent: "agent wants to install npm package: chalk",
		Agent:  "claude-code",
	}

	// No persist configured (built-in default policy, no file): must NOT claim
	// "remembered" — and must honestly say "not remembered".
	var out1 bytes.Buffer
	p1 := New(strings.NewReader("A\n"), &out1)
	p1.NoColor = true
	p1.Persist = false
	if c, _ := p1.Ask(req); c != ChoiceAlways {
		t.Fatalf("Always choice: want ChoiceAlways, got %v", c)
	}
	if strings.Contains(out1.String(), "allowed + remembered") {
		t.Fatalf("no persist: must not claim remembered, got:\n%s", out1.String())
	}
	if !strings.Contains(out1.String(), "not remembered") {
		t.Fatalf("no persist: must honestly say not remembered, got:\n%s", out1.String())
	}

	// Persist configured (policy file present): may claim "remembered".
	var out2 bytes.Buffer
	p2 := New(strings.NewReader("A\n"), &out2)
	p2.NoColor = true
	p2.Persist = true
	if c, _ := p2.Ask(req); c != ChoiceAlways {
		t.Fatalf("Always choice: want ChoiceAlways, got %v", c)
	}
	if !strings.Contains(out2.String(), "allowed + remembered") {
		t.Fatalf("persist configured: should claim remembered, got:\n%s", out2.String())
	}
}
