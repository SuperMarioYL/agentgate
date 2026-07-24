# Changelog

All notable changes to AgentGate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-07-25

A truth-and-durability release: three fixes, no new surface, no new deps. The
theme is that a gate's documented claims, its persisted state, and its shipped
policy must all actually do what they say.

### Fixed

- **The exec gate no longer claims to intercept every subprocess.** The README
  (architecture overview + m1 roadmap line, both languages) said the gate
  "intercepts every subprocess" an agent spawns. In fact `wrap.InterceptedCommands`
  only shims a hardcoded list (npm/pnpm/yarn/bun, pip/pip3/uv/poetry, gem/cargo/go,
  node/python/python3/ruby, curl/wget). The docs now honestly scope the exec claim
  to that configured shim list and call out that custom binaries and direct shell
  spawns run ungated — universal exec interposition is on the roadmap. `spawn.go`
  is unchanged; this is a docs/truth fix only.
- **Persisted policy writes are now atomic.** `policy.Append` (the `--always`
  persist path the gate engine calls) and `policy.Save` (the `agentgate policy rm`
  write path) used plain `os.WriteFile`, so a crash mid-write left a torn /
  truncated `policy.yaml` that `Load` would then reject — an operator's granted
  rules could vanish on the next restart. Both now write to a temp file in the
  same directory, `fsync`, `chmod`, and `os.Rename` over the target, so readers
  see either the previous good state or the fully new state, never a partial.
  The destination mode is normalised to 0o644 regardless of any pre-existing
  file's mode (the old `os.WriteFile` only applied `perm` on create, leaving a
  stricter seed untouched).
- **`fs_write` `target_glob` now expands env vars.** `Rule.matches` matched a
  rule's `TargetGlob` literally, while `scope.go` already expanded env vars in a
  `Scope`. The shipped `$PWD/**` allow rule in `policy.default.yaml` and
  `policy.yaml.example` was therefore a dead letter: a literal `$PWD/**` is not
  a prefix of any real path, so it matched nothing. `matches` now applies
  `os.ExpandEnv` to the glob before `globMatch`, mirroring `scope.go`, so
  `$PWD/**` genuinely covers the working directory.

## [0.7.0] - 2026-07-21

A correctness and durability release: three verified, revert-tested defects from
the source bug-hunt. No new surface, no new deps. The theme is that a gate's
promises and its operator's environment should survive real-world failure modes.

### Fixed

- **`agentgate audit` no longer goes unreadable after a crash.** The audit log
  reader aborted on the first malformed JSONL line, and `agentgate audit`
  treated any error as fatal — so a single truncated trailing entry (the common
  case when an agent run is SIGKILLed mid-write) made the entire audit trail
  unreadable. `Read` now walks the file line by line, skips and counts malformed
  lines, and returns every valid entry before and after the bad one. An
  append-only log's value is durability; one truncated byte must not nuke it.
- **`--always` on a network egress now persists the bare host, not a
  port-locked `host:port` glob.** At runtime a `net_egress` target is `host:port`
  (the redirect proxy passes `r.Host`, which is `host:port` for a CONNECT), so
  `[A]lways` on `registry.npmjs.org:443` previously matched only `:443` and
  re-prompted on `:80` (HTTP / an HTTPS→HTTP redirect, both common for registry
  mirrors) — the same verbatim-target class v0.4.0 fixed for exec. The
  persisted glob now strips the port; the host matcher already rejects
  suffix/prefix splices, so a bare host is safe and covers any port.
- **`agentgate run --no-net` no longer strips the operator's proxy.** The
  child environment dropped every pre-existing `HTTP(S)_PROXY` variable
  unconditionally, even when the net gate was off — so an operator behind a
  corporate or upstream proxy had it silently removed and the agent's egress
  broke. The drop is now conditional on the net gate being on; under `--no-net`
  the operator's proxy is preserved.

## [0.6.0] - 2026-07-04

A security-truth release: four fail-open / false-enforcement defects fixed, plus a
ready-to-use supply-chain policy cookbook. The theme is honesty — a gate should
enforce exactly what it claims, and fail closed when it can't.

### Fixed

- **`fs_write` no longer claims runtime enforcement it doesn't have.** The README
  said writes outside the project root were denied and `agentgate init` shipped a
  blanket `deny fs_write` catch-all — but no runtime path ever invoked the
  filesystem gate (it only ran under `agentgate check` and unit tests). `fs_write`
  is now documented as **CHECK/DRY-RUN-ONLY**: the default policy drops the
  misleading catch-all, the README security section states the real status, and
  true runtime write interposition (ptrace/eBPF/LD_PRELOAD) is on the v0.7.0+
  roadmap. Only `exec` and `net_egress` are runtime-enforced today.
- **The shim now fails CLOSED when the broker is unreachable.** Previously, if a
  process was under `agentgate run` (broker socket set) but the broker couldn't be
  reached — a crashed or killed parent — the shim ran the command **ungated**. A
  security gate must never silently disable itself: the shim now refuses (exit 126,
  no exec) with a clear notice, symmetric with the existing deny path.
- **The example policy's dangerous-one-liner rule actually fires now.** The shipped
  `policy.yaml.example` used `target_glob: "*curl*|*sh*"`, but the glob matcher has
  no `|` alternation (`filepath.Match` treats `|` as a literal), so that rule denied
  *neither* a bare `curl http://evil` *nor* `wget ... | sh`. It's replaced with
  glob-correct separate `*curl*` / `*wget*` deny rules, and a comment warns that `|`
  is literal so the mistake isn't reintroduced.
- **The network gate no longer silently disappears on a bind failure.** If the
  redirect proxy failed to bind, `agentgate run` swallowed the error and ran the
  agent with no proxy env — egress went out completely ungated, with no notice. It
  now fails closed: the run errors out (non-zero exit) and tells you to fix the bind
  or pass `--no-net` to disable the gate deliberately.

### Added

- **Supply-chain policy cookbook (`examples/policies/supply-chain.yaml`).**
  Ready-to-use, glob-correct `policy.yaml` recipes for real supply-chain attack
  behavior — deny `curl`/`wget` fetch-and-run one-liners, surface every dependency
  install, allowlist registries and deny undeclared egress. Copy the file (or paste
  the rules you want), then validate with `agentgate check`. A new README "Cookbook"
  section links each recipe to the attack it stops.
- **Reinforced boundary.** The out-of-scope ban now explicitly forbids learned /
  self-tuning authorization boundaries — AgentGate's decisions stay explicit and
  human-authored, never learned.

## [0.5.0] - 2026-07-02

Closes the inspect→edit loop `agentgate policy` opened: you can now revoke a
persisted rule from the CLI, so taking back an over-broad `[A]lways` grant is as
easy as making it was.

### Added

- **`agentgate policy rm` — revoke a persisted rule.** `agentgate policy` (v0.4.0)
  let you *see* every rule the gate enforces, but taking one back still meant
  hand-editing `policy.yaml`. `agentgate policy rm <index>` removes the rule at the
  1-based index the listing prints, and `agentgate policy rm --action <kind>
  --target <glob>` removes a rule by an exact action + target-glob match. The removed
  rule and the updated effective table are printed. An out-of-range index, the
  default row (`*`), a no-match, or a non-numeric index prints a clear error and
  exits non-zero **without modifying the policy file**; when no `policy.yaml` exists
  yet it points you at `agentgate init` rather than pretending to edit the built-in
  default. Once removed, the same-kind actions the rule used to auto-allow return to
  prompting / the default decision — the grant is genuinely revoked. Removal only:
  rewriting or reordering a rule stays remove-then-re-add or a hand-edit. No new
  dependencies; single binary preserved.

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
