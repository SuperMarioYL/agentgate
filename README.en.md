[简体中文](./README.md) · [Website](https://agentgate.lei6393.com) · [GitHub](https://github.com/SuperMarioYL/agentgate)

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/hero-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/hero-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/hero-dark.svg">
  <img src="./assets/presentation/hero-light.svg" width="960" alt="Hero diagram">
</picture>

# AgentGate

**Review an agent action before it runs.**

AgentGate wraps a coding session with command shims and an HTTP(S) proxy, resolves actions against an ordered YAML policy, and records decisions in JSONL.

## Why use it

Dependency installation and outbound traffic deserve different rules. A policy can ask before npm install, allow a package registry and deny an undeclared host; check previews those decisions before a session starts.

- **Preview a rule** — check explains a hypothetical decision without running it.
- **Separate action types** — Command and egress rules have independent matches.
- **Keep an audit trail** — Runtime decisions can be filtered by action, decision and time.

## Architecture

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/architecture-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/architecture-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/architecture-dark.svg">
  <img src="./assets/presentation/architecture-light.svg" width="960" alt="Architecture diagram">
</picture>

Configured PATH shims send intercepted commands to a Unix-socket broker. Proxied traffic enters the same gate engine, which uses the first matching policy rule and optionally prompts the operator. The audit module records runtime decisions. check evaluates a hypothetical action through policy resolution only.

| Component | Responsibility |
| --- | --- |
| `Command shims` | internal/wrap/spawn.go |
| `Socket broker + proxy` | internal/gate |
| `Ordered policy` | internal/policy |
| `Prompt + audit` | internal/prompt; internal/audit |

## Install and quickstart

Use the runtime version declared in the repository manifest. The source installation below makes the included example reproducible.

```bash
git clone https://github.com/SuperMarioYL/agentgate.git
cd agentgate
go build ./cmd/agentgate
```

The Python script checks four actions against the complete supply-chain policy. Python 3 is needed only for this demo driver.

```bash
python3 examples/presentation_demo.py
```

## Recorded demo

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/process-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/process-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/process-dark.svg">
  <img src="./assets/presentation/process-light.svg" width="960" alt="Process diagram">
</picture>

curl is denied; npm install asks; the registry is allowed; its look-alike hostname is denied.

```text
action  : exec
target  : curl http://evil.example
intent  : agent wants to fetch a URL via curl: http://evil.example
decision: deny (matched a rule)
action  : exec
target  : npm install left-pad
intent  : agent wants to install npm package: left-pad
decision: ask (matched a rule)
action  : net_egress
target  : registry.npmjs.org:443
intent  : agent wants to reach registry.npmjs.org:443
decision: allow (matched a rule)
action  : net_egress
target  : registry.npmjs.org.evil.example:443
intent  : agent wants to reach registry.npmjs.org.evil.example:443
decision: deny (matched a rule)
```

The complete command and output are recorded in [docs/demo-results.json](./docs/demo-results.json). Inputs and reproduction code are included in the repository.

![Existing terminal recording](./assets/demo.gif)

The existing recording is retained for context; the text example above documents the reproducible scenario.

## Usage

Run these commands from the repository root after installation. Replace paths for your own data.

```bash
go run ./cmd/agentgate init
go run ./cmd/agentgate policy --policy examples/policies/supply-chain.yaml
go run ./cmd/agentgate policy --policy examples/policies/supply-chain.yaml --explain --action exec "npm install chalk"
go run ./cmd/agentgate audit --decision deny --json
```

## Configuration

--policy or AGENTGATE_POLICY selects the policy; --audit or AGENTGATE_AUDIT selects the runtime log. --enforce makes ask resolve to deny without a TTY. --no-net disables the proxy gate. Rules use filepath-style globs, not regex or | alternation. Bare host tokens respect host boundaries; .github.com means its subdomains, excluding the apex. Review rule order before using policy rm to revoke a stored rule: --policy works on policy and its rm subcommand alike, so a rule can be revoked from the same file it was listed from. A rule whose action is not exec, fs_write or net_egress is rejected when the policy is parsed, so a mistyped rule cannot silently never fire. Each audit row records how its decision was reached: rule, default, operator, no-operator, always or enforce.

## Integrations and responsibilities

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/integrations-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/integrations-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/integrations-dark.svg">
  <img src="./assets/presentation/integrations-light.svg" width="960" alt="Integrations diagram">
</picture>

Choose the input and output route that matches your workflow. The local example below exercises the stated subset.

| Route | Implemented role |
| --- | --- |
| YAML policy | First match wins; allow / deny / ask |
| Configured executables | PATH shim interception |
| HTTP(S) proxy | Host-based egress decisions |
| JSONL | Runtime audit and filters |
| check / policy | Dry-run explanation and rule management |

## Limits and next steps

- This is not a complete host sandbox. Custom binaries, direct shell spawns and traffic bypassing the proxy are outside these interception paths.
- fs_write rules are check-only; runtime filesystem-write interception is not implemented.
- The demo resolves hypothetical actions only. It does not establish process isolation or live network enforcement.

Runtime filesystem interposition, broader harness adapters and shared team policies remain future work. The included supply-chain cookbook documents the currently supported matcher.

## License and contributions

See [LICENSE](./LICENSE). When reporting an issue, include a minimal input, the command, and the observed output.
