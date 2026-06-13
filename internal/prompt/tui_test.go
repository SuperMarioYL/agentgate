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
