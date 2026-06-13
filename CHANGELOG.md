# Changelog

All notable changes to AgentGate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
