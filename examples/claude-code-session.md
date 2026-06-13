# Walkthrough — gating a real autonomous agent run

This is what a session looks like end to end: you wrap your coding agent, it runs
in full autonomous mode, and AgentGate pauses only the host-touching actions.

## 1. Drop a policy

```bash
agentgate init        # writes ./policy.yaml (ask on installs, confine writes, gate egress)
```

## 2. Run the agent under the gate

```bash
agentgate run -- claude --autonomous "add the chalk dependency and wire it up"
```

The agent plans, edits files, and eventually decides to install a dependency.

## 3. The install is paused

The moment the agent spawns `npm install chalk`, AgentGate intercepts it and
shows the agent's own intent before anything runs:

```
┌─ AgentGate · action paused ──────────────────
│ agent  : claude-code
│ action : exec
│ target : npm install chalk
│ intent : agent wants to install npm package: chalk
└──────────────────────────────────────────────
  [a]llow / [d]eny / [A]lways ?
```

Press `a` to allow this once, `d` to block it, or `A` to allow and remember it
(an `allow` rule is appended to `policy.yaml`, so you are never asked again).

## 4. A post-install script tries to phone home

Suppose the freshly installed package runs a post-install script that opens a
connection to an undeclared host. AgentGate's egress gate blocks it per policy —
the agent keeps running, but the exfiltration attempt does not land:

```
✗ AgentGate blocked net_egress undeclared.evil.test
```

This is the Miasma-style supply-chain payload stopped *at execution*, not
discovered after the fact.

## 5. Review the trail

```bash
agentgate audit
```

```
✓  13:20:26  exec        allow    npm install chalk
✗  13:20:26  net_egress  deny     undeclared.evil.test
```

Every gated action — allowed or denied, with the agent and intent — is in the
append-only JSONL log at `.agentgate/audit.jsonl`.

## Try it without a real agent

Any program that spawns subprocesses works as the "agent". A one-line shell
script is enough to see the gate in action:

```bash
printf '#!/bin/sh\nnpm install left-pad\n' > agent.sh && chmod +x agent.sh
agentgate run -- ./agent.sh        # AgentGate pauses the install for approval
```
