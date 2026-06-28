# Changelog

All notable changes to AgentGate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-06-29

Makes standing permissions trustworthy: `[A]lways` on a command now actually
sticks across that kind of command, and you can finally see every rule the gate
will enforce.

### Added

- **`agentgate policy` — show the effective rule set.** Prints every rule's
  action, target glob, decision, and scope in first-match-wins order, plus the
  default applied when none match — including rules an `--always` choice appended,
  so you can review what you've granted instead of trusting an invisible, growing
  rule set. `agentgate policy --explain --action <kind> <target>` resolves a single
  hypothetical action and reports which rule it hits, reusing the same
  side-effect-free resolver as `agentgate check`.

### Fixed

- **`--always` on an exec action only ever re-matched the exact command line.**
  Choosing `[A]lways` on `npm install left-pad` persisted the verbatim joined
  command (`"npm install left-pad"`) as the rule's target glob. That string has no
  wildcards, so the next install — `npm install chalk`, or even
  `npm install left-pad --save` — failed to match and re-prompted, defeating the
  whole point of `--always`. AgentGate now derives a re-usable glob anchored on the
  binary and its first subcommand (`npm install*`), so an `[A]lways` covers
  later installs of the same kind without re-broadening to a different binary
  (`pip install …` still asks). Filesystem (`dir/**`) and network (host token)
  `--always` rules are unchanged.

[0.4.0]: https://github.com/SuperMarioYL/agentgate/releases/tag/v0.4.0

## [0.3.0] - 2026-06-19

Hardens the filesystem sandbox, tightens path-glob matching, and makes AgentGate
usable in CI.

### Added

- **`agentgate run --enforce` — headless default-deny for CI.** With no operator
  present, `--enforce` runs the engine with no prompter, so every `ask` resolves
  to `deny` (deny-by-default) and the run never blocks on a TTY. AgentGate now
  fits in a pipeline step where there is no one to answer a prompt. `--always`
  persistence is disabled in this mode (there is no operator to choose `[A]lways`).
- **`agentgate audit` query filters.** `--decision allow|deny|ask`, `--action
  exec|fs_write|net_egress`, and `--since <when>` narrow the trail so you can
  answer "what got blocked?" without grepping. `--since` accepts an RFC3339
  timestamp, a date (`2026-06-19`), or a duration ago (`2h`, `30m`). `--json`
  emits the raw JSONL passthrough for piping into other tools.

### Fixed

- **Filesystem sandbox escape via an in-scope symlink.** `WithinScope` /
  `CheckWrite` confined `fs_write` on the lexical absolute path only and never
  resolved symlinks, so a symlink living inside the declared scope but pointing
  outside it let a write escape the sandbox while still presenting an in-scope
  path. Scope confinement now resolves the scope root and the target's deepest
  existing ancestor with `filepath.EvalSymlinks` before computing the relative
  path, and rejects a target that resolves outside scope.
- **`**` path-glob suffix over-matching as a substring.** A `**` glob accepted
  its suffix anywhere in the target, so `/proj/**.env` also matched
  `/proj/.env.backup/passwd`, silently widening allow/scope rules past intent. A
  non-empty `**` suffix now must anchor to the end of the target — the same
  over-match class the v0.2.0 host-token fix closed, here for path globs.

[0.3.0]: https://github.com/SuperMarioYL/agentgate/releases/tag/v0.3.0

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
