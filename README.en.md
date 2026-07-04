<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/hero-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/hero-light.svg">
    <img src="./assets/hero-light.svg" width="880" alt="AgentGate — a runtime per-action host sandbox for coding agents">
  </picture>
</p>

<p align="center">
  <b>The runtime host guard that approves your coding agent's every install, script, and network call — per action, not all-or-nothing.</b>
</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://github.com/SuperMarioYL/agentgate/releases"><img src="https://img.shields.io/badge/release-v0.6.0-2563eb.svg" alt="Release" /></a>
  <a href="https://github.com/SuperMarioYL/agentgate/actions"><img src="https://img.shields.io/github/actions/workflow/status/SuperMarioYL/agentgate/ci.yml?branch=main&label=CI" alt="CI" /></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.24%2B-00ADD8.svg?logo=go&logoColor=white" alt="Go" /></a>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-334155.svg" alt="Platform" />
  <img src="https://img.shields.io/badge/Coding%20Agent-runtime%20gate-7c3aed.svg" alt="Coding Agent runtime gate" />
</p>

<p align="center">
  <b>English</b> | <a href="./README.md">简体中文</a>
</p>

---

**You put a Coding Agent into autonomous mode to pull deps and run scripts — but containers are all-or-nothing, and the moment you disable one for productivity your host is wide open. AgentGate intercepts each host-touching action the instant it happens and asks you, carrying the agent's own intent: allow it or deny it?**

## Table of contents

- [Why this exists](#why-this-exists)
- [Quickstart](#quickstart)
- [Demo](#demo)
- [The policy.yaml DSL](#the-policyyaml-dsl)
- [Configuration](#configuration)
- [Comparison](#comparison-vs-containers--static-scanners)
- [Roadmap](#roadmap)
- [License](#license)

## Why this exists

When you let a **Coding Agent** write code, pull dependencies, and run scripts, you delegate trust while keeping the responsibility — and there is no scoped checkpoint between you and the host. Containers do isolation, but they are all-or-nothing, so developers disable them for agent productivity; even when running, a container can't tell "this install is fine" from "that network call is exfiltration."

This is **not** a static dependency scanner. Supply-chain worms like Miasma target AI coding agents specifically — Miasma disabled 72+ repositories (including Microsoft's Azure Functions Action), and its payload only reveals itself at install / exec time, where static analysis reading the package beforehand never sees it. AgentGate is a **runtime, per-action** guard: it authorizes each install, script, and egress as it happens, so a supply-chain payload is stopped at execution instead of discovered after 72 repos go down.

> This is the trust-vs-control gap [@simonw](https://twitter.com/simonw) keeps flagging when agents run shell commands, and the missing piece for the autonomy-maximizing coding-agent harnesses (e.g. [affaan-m/ECC](https://github.com/affaan-m/ECC)) that ship no host gate at all — AgentGate is complementary to them, not a competitor.

## <img src="https://api.iconify.design/tabler:topology-star-3.svg?color=%232563eb&width=24" height="22" align="absmiddle" alt=""> Architecture

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/atlas-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/atlas-light.svg">
    <img src="./assets/atlas-light.svg" width="880" alt="Architecture: a coding agent's spawned subprocesses and network egress are intercepted by a PATH shim and an injected HTTP(S) proxy, forwarded to a unix-socket broker / Gate Engine that resolves each action against policy.yaml and prompts allow/deny/always; the verdict is recorded to a JSONL audit log — allowed actions run, denied ones never land">
  </picture>
</p>

The coding agent runs behind the gate: every subprocess it spawns is caught by a **PATH shim**, and every network call is redirected through an injected **HTTP(S) proxy**. Both paths converge on a single **unix-socket broker / Gate Engine** that resolves each action against `policy.yaml` first-match-wins — prompting `[a]llow / [d]eny / [A]lways` when needed. An allowed action `exec`s the real binary and proceeds; a denied one never lands. Every verdict is appended to a **JSONL audit log** you can replay with `agentgate audit`.

## Quickstart

Requires Go 1.24+ (Linux or macOS). Three commands from a cold start to your first prompt:

```bash
go install github.com/SuperMarioYL/agentgate@latest   # 1. install the single binary
agentgate init                                         # 2. drop a default policy.yaml here
agentgate run -- claude --autonomous "add a chart library and wire it up"  # 3. run your agent behind the gate
```

The first host-touching action pauses and shows the agent's own intent:

```
┌─ AgentGate · action paused ──────────────────
│ agent  : claude-code
│ action : exec
│ target : npm install chalk
│ intent : agent wants to install npm package: chalk
└──────────────────────────────────────────────
  [a]llow / [d]eny / [A]lways ?
```

Press `a` to allow once, `d` to deny, `A` to always allow (this writes a rule back into `policy.yaml`, so steady state is near-silent). Afterwards, `agentgate audit` prints the JSONL trail of every gated action:

```bash
agentgate audit
# ✓  13:20:26  exec        allow    npm install chalk
# ✗  13:20:26  net_egress  deny     telemetry.unknown-host.example

# Just show "what got blocked?" — filter by decision / action / time (v0.3.0)
agentgate audit --decision deny
agentgate audit --action net_egress --since 2h
agentgate audit --decision deny --json   # raw JSONL passthrough for piping
```

> `--since` accepts an RFC3339 timestamp, a date (`2026-06-19`), or a duration ago (`2h`, `30m`).

> Interception is portable and ptrace/libpcap-free: a PATH shim forwards each intercepted command to a unix-socket broker that owns the gate decision, and network egress is gated per host through a localhost redirect proxy wired in via `HTTP(S)_PROXY`. See [`examples/claude-code-session.md`](./examples/claude-code-session.md) for the full walkthrough.

## <img src="https://api.iconify.design/tabler:photo.svg?color=%232563eb&width=24" height="22" align="absmiddle" alt=""> Demo

An agent's `npm install` is paused for approval, a post-install egress to an undeclared host is blocked in red, and `agentgate audit` prints the full trail:

![demo](assets/demo.gif)

> The GIF is rendered in CI from [`docs/demo.tape`](./docs/demo.tape) via [vhs](https://github.com/charmbracelet/vhs) (see [`.github/workflows/demo.yml`](./.github/workflows/demo.yml)). A recorded [`docs/demo.cast`](./docs/demo.cast) also ships in this repo — replay it locally with `asciinema play docs/demo.cast`.

## The policy.yaml DSL

A policy is an **ordered, first-match-wins** list of rules. Each rule has a `match` (`action` + `target_glob`) and a `decision` (`allow` / `deny` / `ask`); anything no rule matches falls through to `default`.

```yaml
default: ask                 # fallback when no rule matches

rules:
  # exec — installs and scripts the agent spawns
  - match:
      action: exec
      target_glob: "*install*"
    decision: ask            # surface every install so you see what gets pulled

  # fs_write — CHECK/DRY-RUN-ONLY in this version (not runtime-enforced yet; see the security note below)
  - match:
      action: fs_write
      target_glob: "$PWD/**"
    decision: allow
    scope: "$PWD"            # documents the intended write scope for `agentgate check`

  # net_egress — allow common registries, gate everything else
  - match:
      action: net_egress
      target_glob: "registry.npmjs.org"
    decision: allow
  - match:
      action: net_egress
    decision: deny           # undeclared host -> blocked
```

Glob semantics: `*` matches a single path/host segment (`filepath.Match` semantics), `**` matches across segments (e.g. `$PWD/**`); a `**` pattern with a suffix (e.g. `/proj/**.env`) requires the target to *end* with that suffix and will not match it as a mid-string substring (so `/proj/.env.backup/passwd` is not waved through by `/proj/**.env`). A bare host token with no wildcard matches on a **host boundary** — the whole target, or the host part of a `host:port` target (so `registry.npmjs.org` matches `registry.npmjs.org:443`), but it will **not** wave through look-alike hosts such as `github.com.evil.com` or `evilgithub.com`. A leading-dot token (e.g. `.github.com`) matches the whole subdomain tree (`api.github.com`) but not the bare apex `github.com` itself. `agentgate init` drops a sensible built-in default policy you can edit.

> ⚠️ **Security note — what is actually enforced at runtime (read this).** AgentGate **enforces** two surfaces at runtime: `exec` (the subprocesses an agent spawns, resolved per-action through the PATH shim + broker) and `net_egress` (gated per host through a local HTTP(S) redirect proxy). **`fs_write` is CHECK/DRY-RUN-ONLY in this version**: the policy engine and `agentgate check --action fs_write` resolve write rules, but AgentGate does **not** yet intercept an agent's actual writes at runtime (runtime write interposition — Linux ptrace/eBPF, macOS LD_PRELOAD/sandbox-exec — is on the v0.7.0+ roadmap). Because of that, `agentgate init`'s default policy **no longer** ships a blanket `deny fs_write` catch-all that would imply writes are confined when they aren't. Use `agentgate check` to validate write rules, but do **not** rely on them firing on a live run yet — only `exec` and `net_egress` are runtime-enforced today.

### Dry-run first: `agentgate check`

Wrote a policy and want to know how it resolves a given action *before* trusting an agent to it? `agentgate check` runs a hypothetical action against the policy and prints the decision (`allow` / `deny` / `ask`) plus why — **without running any subprocess, dialing any host, or writing to the audit log.**

```bash
agentgate check --action exec -- npm install left-pad
# action  : exec
# target  : npm install left-pad
# intent  : agent wants to install npm package: left-pad
# decision: ask (matched a rule)

agentgate check --action net_egress github.com.evil.com:443
# decision: deny (no rule matched, fell through to default)

agentgate check --action fs_write /etc/passwd
# decision: deny (matched an allow rule but the path escapes its scope)
```

`--action` takes `exec` (default) / `fs_write` / `net_egress`; `--policy` selects the file to check.

### See what you've granted: `agentgate policy`

After a few `[A]lways` choices, rules quietly accumulate in `policy.yaml` — a runtime gate is only trustworthy if you can see exactly what it will enforce. `agentgate policy` prints every effective rule (including the ones `--always` appended) in first-match-wins order: action, target glob, decision, and scope, with a final row for the default applied when none match:

```bash
agentgate policy
# # effective policy (policy.yaml) — first match wins, top to bottom
# #    ACTION      TARGET              DECISION  SCOPE
# 1    net_egress  registry.npmjs.org  allow     -
# 2    fs_write    /proj/**            allow     /proj
# 3    exec        npm install*        allow     -
# *    any         any                 ask       -
```

Add `--explain` to resolve a single hypothetical action and see which rule it hits (reusing the same side-effect-free resolver as `agentgate check`):

```bash
agentgate policy --explain --action exec "npm install chalk"
# decision: allow (matched a rule)
# matched : action=exec target=npm install* -> allow
```

### Revoke a grant: `agentgate policy rm`

Seeing the rules is only half of it — if you find an `[A]lways` grant that turned out **too broad**, you need to take it back. Before v0.5.0 that meant hand-editing `policy.yaml`; now `agentgate policy rm` makes revoking a mistaken grant as easy as making it was. Remove by the **1-based index** listed above, or by an exact `--action` + `--target` match; the removed rule and the updated effective table are both printed:

```bash
# by index (the # column that `agentgate policy` prints)
agentgate policy rm 3
# removed rule #3: action=exec target=npm install* -> allow
# (then re-prints the effective rule table)

# or match a rule by action + target glob
agentgate policy rm --action net_egress --target "registry.npmjs.org"
```

An out-of-range index, the default row (`*`), or a no-match prints a clear error and exits non-zero **without touching** the policy file. Once a rule is removed, the same-kind actions it used to auto-allow go back to prompting / the default decision — the grant is genuinely revoked, not just hidden from the table. (This version does **removal** only: rewriting a rule's decision/glob or reordering rules stays remove-then-re-add, or a hand-edit of `policy.yaml`.)

> v0.4.0 fix: `[A]lways` on an exec action used to persist the **verbatim command line** (e.g. `npm install left-pad`) as the rule glob. With no wildcards it only ever re-matched that exact argv, so the next `npm install chalk` re-prompted — `--always` did nothing. AgentGate now derives a re-usable glob from the binary + its first subcommand (`npm install*`), covering later installs of the same kind without over-broadening to a different binary (`pip install …` still asks).

## Supply-chain policy cookbook

Authoring a policy from scratch is easy to get wrong. [`examples/policies/supply-chain.yaml`](./examples/policies/supply-chain.yaml) collects ready-to-use rules for **real supply-chain attack behavior** — each labeled with the attack it stops, and **all glob-correct** (no `|` pseudo-alternation; see below):

| Recipe | Attack it stops |
| --- | --- |
| `deny exec *curl*` / `deny exec *wget*` | Post-install scripts running `curl http://evil / wget … | sh` to fetch + run a remote payload (RCE / exfil) |
| `ask exec *npm install*` / `*pip install*` | Surface every dependency install so you see what's pulled (typosquat / poisoned package) |
| `deny net_egress` fallthrough + registry allowlist | A payload exfiltrating data to an undeclared host / calling back to C2 |
| `deny exec *chmod +x*` etc. | A post-install script granting itself execute / dropping an executable |

Copy a recipe into your `policy.yaml`, then confirm with `agentgate check` that it denies the named command:

```bash
cp examples/policies/supply-chain.yaml policy.yaml     # or paste specific rules into your existing policy
agentgate check --action exec -- curl http://evil.example
# decision: deny (matched a rule)
```

> **Why not a single `*curl*|*sh*` rule?** The glob matcher has **no** `|` alternation — `filepath.Match` treats `|` as a **literal character**. So `*curl*|*sh*` only matches a command containing that exact literal `curl … | … sh` sequence, and silently **misses** both `curl http://evil` (no literal pipe) and `wget … | sh` (no `curl`). The cookbook lists each pattern as its own rule (`*curl*`, `*wget*`); never use `|` as alternation.

## Configuration

Common `agentgate run` flags:

| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--policy` | string | `./policy.yaml` (or `$AGENTGATE_POLICY`) | policy file to use |
| `--audit` | string | `.agentgate/audit.jsonl` (or `$AGENTGATE_AUDIT`) | append-only JSONL audit log path |
| `--agent` | string | `claude-code` | identifier for the wrapped agent (shown in prompt + audit) |
| `--no-net` | bool | `false` | disable the network egress gate (gate exec / fs only) |
| `--always` | bool | `true` | persist `[A]lways` choices back to the policy file |
| `--enforce` | bool | `false` | headless CI mode: no prompts, every `ask` resolves to `deny` (deny-by-default) |

### Run it in CI: `--enforce`

A CI pipeline has no operator to answer a prompt. `agentgate run --enforce` starts the engine with no prompter — every `ask` falls to `deny` (deny-by-default) and the run **never waits on a TTY**:

```bash
agentgate run --enforce -- npm ci
# agentgate: --enforce (headless): no prompts, ask resolves to deny (deny-by-default)
```

Only actions the policy **explicitly `allow`s** proceed; everything else is blocked and recorded to the audit trail. `--always` persistence is disabled in this mode (there is no operator to choose `[A]lways`).

## Comparison vs containers / static scanners

An honest read — containers are far more mature at isolation; AgentGate solves a different problem: **per-action, intent-aware, at runtime.**

| Axis | AgentGate | Container / disposable VM | Static dependency scanner |
| --- | --- | --- | --- |
| Per-action authorization | ✓ | ✗ (all-or-nothing) | ✗ |
| Carries the agent's intent | ✓ | ✗ | ✗ |
| Catches payload at runtime | ✓ | partial (no per-action distinction inside the boundary) | ✗ (reads the package pre-install, misses runtime payloads) |
| Mature process isolation | partial (spawn + egress boundary) | ✓ | — |
| Stays on instead of being disabled for speed | ✓ | ✗ (often disabled because it slows the agent) | — |

## Roadmap

- [x] **m1 — wrap & gate exec**: wrap an agent, intercept each subprocess it spawns, prompt allow/deny with the captured intent.
- [x] **m2 — scope fs & net**: a `policy.yaml` gates egress per host with a JSONL audit log; `fs_write` rules are resolvable via `agentgate check` (**check/dry-run-only** — runtime enforcement is on the v0.7.0+ roadmap below).
- [x] **m3 — DSL & demo**: the `allow`/`deny`/`ask` DSL + `--always` persistence, an `agentgate init` default policy, a 60s asciinema demo, and the bilingual README.
- [x] **m4 — author & audit a policy**: `agentgate check` dry-runs any action against the policy, host-boundary egress matching closes the look-alike-host bypass, and `.host` tokens scope rules to a subdomain tree.
- [x] **m5 — CI & triage**: `agentgate run --enforce` for unattended default-deny (no more blocking on a TTY in CI); `agentgate audit` gains `--decision` / `--action` / `--since` filters and `--json` output; plus two sandbox fixes — a symlink-escape write bypass and a `**` path-glob substring over-match.
- [x] **m6 — inspect a policy & re-usable always**: `agentgate policy` prints every effective rule (including `--always`-appended ones) in first-match order, with `--explain` for a single action; fixes `[A]lways` on an exec persisting the verbatim command line (which re-prompted on the next same-kind install) — it now derives a re-usable binary+subcommand glob.
- [x] **m7 — revoke a policy (closing the inspect→edit loop)**: `agentgate policy rm <index>` / `--action --target` revokes a persisted rule from the CLI, so taking back an over-broad `[A]lways` grant is as easy as making it was — no more hand-editing `policy.yaml`.
- [x] **m8 — supply-chain cookbook + security honesty**: ships [`examples/policies/supply-chain.yaml`](./examples/policies/supply-chain.yaml) (ready-to-use recipes for real supply-chain behavior, see [Cookbook](#supply-chain-policy-cookbook)); and fixes four security-truth / fail-open defects — `fs_write` no longer claims runtime enforcement (it's check/dry-run-only), the shim now **fails closed** when the broker is unreachable (no ungated exec), the broken example `*curl*|*sh*` rule is replaced with glob-correct separate rules, and the net proxy now **errors out** on a bind failure instead of silently running the agent with ungated egress.
- [ ] **Runtime fs_write enforcement (v0.7.0+)**: Linux ptrace/eBPF, macOS LD_PRELOAD/sandbox-exec write interposition — upgrades `fs_write` from check-only to real runtime interception.
- [ ] Drop-in adapters and README safety-section integration for more harnesses (ECC / openfang, v0.7.0).
- [ ] Team-shared policies / audit dashboard (a v2+ exploration, not the current thesis).

> After pushing, set GitHub topics: `gh repo edit --add-topic agent --add-topic coding-agent --add-topic security --add-topic sandbox`

## License

AgentGate is free, MIT-licensed, single-binary OSS — no paywall, no hosted tier. File an [issue](https://github.com/SuperMarioYL/agentgate/issues) or open a PR to contribute.

## Share this

```
AgentGate — a runtime per-action host gate for your Coding Agent. It pauses each
install / script / egress with the agent's own intent, instead of all-or-nothing
containers. After the Miasma worm, your agent needs a seatbelt.
https://github.com/SuperMarioYL/agentgate
```

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>
