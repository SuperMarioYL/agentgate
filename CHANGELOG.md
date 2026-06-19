# Changelog

All notable changes to AgentGate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-19

First feature iteration on top of the initial release.

### Added

- **`agentgate check` — dry-run the policy.** Resolve a hypothetical action
  against the policy and print the decision (`allow` / `deny` / `ask`) plus how
  it was reached, without running any subprocess, dialing any host, or writing to
  the audit log. `agentgate check --action exec -- npm install left-pad`,
  `--action net_egress telemetry.evil.example:443`, and
  `--action fs_write /etc/passwd` let you sanity-check a policy before trusting an
  agent to it. Backed by a side-effect-free `Engine.Explain` that reproduces the
  same decision — scope downgrades included — that the live gate would apply.
- **Subdomain egress rules.** A leading-dot host token (`.github.com`) now scopes
  a `net_egress` rule to a subdomain tree (`api.github.com`) without matching the
  bare apex.

### Fixed

- **Egress allowlist bypass via substring host matching.** A bare host token in a
  `net_egress` rule matched any target that merely *contained* it, so an allow
  rule for `github.com` also permitted egress to `github.com.evil.com` (suffix
  splice), `notgithub.com` (prefix splice), and `evilgithub.com`. Host tokens now
  match on a host boundary — the whole target or the host part of a `host:port` —
  closing the exfiltration path the egress gate exists to block.

[0.2.0]: https://github.com/SuperMarioYL/agentgate/releases/tag/v0.2.0

## [0.1.0] - 2026-06-13

First public release. A runtime, per-action host sandbox for the subprocesses a
coding agent spawns — Linux + macOS, single binary, no daemon.

### Added

- **m1 — wrap & gate exec.** `agentgate run -- <agent command>` wraps an agent
  process and intercepts the subprocesses it spawns (npm/pip/uv/cargo/go
  installs, `node`/`python`/`ruby` scripts, `curl`/`wget`). Each spawned command
  is paused and resolved against the policy before it runs, with the agent's
  intent string surfaced in the prompt. A denied subprocess never executes; an
  allowed one runs normally. Interception is portable and ptrace/libpcap-free: a
  PATH shim forwards each intercepted command to a unix-socket broker that owns
  the gate decision.
- **m2 — scope filesystem & network.** A `policy.yaml` confines filesystem
  writes to declared paths (`scope:`) and gates network egress per host through a
  localhost redirect proxy wired into the agent via `HTTP(S)_PROXY`; an
  undeclared host is blocked with a 403 before any real dial. Every decision is
  appended to an append-only JSONL audit log readable via `agentgate audit`.
- **m3 — DSL & persistence.** The `allow` / `deny` / `ask` policy DSL with
  first-match-wins ordering, `**` multi-segment globs, and command-line `*`
  globs. The interactive prompt offers `[a]llow` / `[d]eny` / `[A]lways`; the
  `--always` choice persists an allow rule back to the policy file so steady
  state is near-silent. `agentgate init` drops a sensible default policy. A 60s
  asciinema demo (`docs/demo.cast`) shows a paused install and a blocked egress.

### Security

- The prompt fails closed: an `ask` decision with no operator attached (EOF /
  non-interactive) resolves to **deny**, never allow.

[0.1.0]: https://github.com/SuperMarioYL/agentgate/releases/tag/v0.1.0
