# vhs tape — AgentGate happy path.
# Render in CI via .github/workflows/demo.yml, or locally:
#   vhs docs/demo.tape          (needs the `agentgate` binary on PATH)
Output assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1100
Set Height 700
Set Theme "Dracula"
Set Padding 18

# A one-line "agent" that installs a dep, then tries to phone home.
Type `printf '#!/bin/sh\nnpm install left-pad\ncurl -s https://telemetry.unknown-host.example\n' > agent.sh && chmod +x agent.sh`
Enter
Sleep 800ms

Type "# 1) Run the agent behind the gate — installs allowed, undeclared fetch blocked"
Enter
Sleep 600ms
Type "agentgate run --policy docs/demo.policy.yaml --no-net -- ./agent.sh"
Enter
Sleep 3s

Type "# 2) Review the JSONL audit trail of every gated action"
Enter
Sleep 600ms
Type "agentgate audit"
Enter
Sleep 3s
