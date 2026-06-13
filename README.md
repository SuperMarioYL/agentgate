<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:1e293b,50:2563eb,100:0ea5e9&height=180&section=header&text=AgentGate&fontColor=ffffff&fontSize=64&fontAlignY=38&desc=%E7%BB%99%E7%BC%96%E7%A0%81%20Agent%20%E7%9A%84%E8%BF%90%E8%A1%8C%E6%97%B6%E4%B8%BB%E6%9C%BA%E6%B2%99%E7%AE%B1&descColor=cbd5e1&descSize=18&descAlignY=60" alt="AgentGate" />
</p>

<p align="center">
  <b>给编码 Agent 的运行时主机护栏——按每个动作授权它的安装、脚本与网络请求，而不是全有或全无。</b>
</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://github.com/SuperMarioYL/agentgate/releases"><img src="https://img.shields.io/badge/release-v0.1.0-2563eb.svg" alt="Release" /></a>
  <a href="https://github.com/SuperMarioYL/agentgate/actions"><img src="https://img.shields.io/github/actions/workflow/status/SuperMarioYL/agentgate/ci.yml?branch=main&label=CI" alt="CI" /></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.24%2B-00ADD8.svg?logo=go&logoColor=white" alt="Go" /></a>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-334155.svg" alt="Platform" />
  <img src="https://img.shields.io/badge/Coding%20Agent-runtime%20gate-7c3aed.svg" alt="Coding Agent runtime gate" />
</p>

<p align="center">
  <a href="./README.en.md">English</a> | <b>简体中文</b>
</p>

---

**你把 Agent 放进自主模式拉依赖、跑脚本——但容器是全有或全无的，关掉它换效率后，主机就彻底裸奔了。AgentGate 在每个触碰主机的动作发生的瞬间拦下来，带着 Agent 自己的意图问你一句：放行还是拒绝。**

## 目录

- [为什么需要它](#为什么需要它)
- [快速开始](#快速开始)
- [演示](#演示)
- [policy.yaml 策略 DSL](#policyyaml-策略-dsl)
- [配置项](#配置项)
- [对比](#对比-vs-容器--静态扫描器)
- [路线图](#路线图)
- [许可证](#许可证)

## 为什么需要它

当你让一个编码 **Agent** 写代码、拉依赖、跑脚本时，你把信任交给了它，但责任还在你身上——而你和主机之间没有一个带作用域的检查点。容器能做隔离，可它是全有或全无的，开发者为了 Agent 的效率往往把它关掉；就算开着，它也无法区分「这次安装没问题」和「那个网络请求是在外传数据」。

这不是一个静态依赖扫描器。Miasma 这类供应链蠕虫专门盯着 AI 编码 Agent——它瘫痪过 72+ 个仓库（含微软的 Azure Functions Action），而它的载荷只在安装 / 执行那一刻才暴露，静态分析在安装前读包根本看不到。AgentGate 是**运行时、按动作**的护栏：在安装、脚本、egress 发生的当下逐个授权，让供应链载荷在执行点被拦下，而不是等 72 个仓库挂掉后才发现。

> 这正是 [@simonw](https://twitter.com/simonw) 反复讨论的「Agent 跑 shell 命令时信任与控制的取舍」，也是那些把自主性拉满、却不带任何主机护栏的编码 Agent harness（如 [affaan-m/ECC](https://github.com/affaan-m/ECC)）缺的那一块——AgentGate 跟它们互补，而非竞争。

## 快速开始

需要 Go 1.24+（Linux 或 macOS）。从冷启动到第一个授权提示，三条命令：

```bash
go install github.com/SuperMarioYL/agentgate@latest   # 1. 安装单文件二进制
agentgate init                                         # 2. 在当前目录落一份默认 policy.yaml
agentgate run -- claude --autonomous "加个图表库并接好"   # 3. 把你的 Agent 跑在护栏后面
```

第一个触碰主机的动作就会暂停，并显示 Agent 自己的意图：

```
┌─ AgentGate · action paused ──────────────────
│ agent  : claude-code
│ action : exec
│ target : npm install chalk
│ intent : agent wants to install npm package: chalk
└──────────────────────────────────────────────
  [a]llow / [d]eny / [A]lways ?
```

按 `a` 放行一次、`d` 拒绝、`A` 永久放行（会把规则写回 `policy.yaml`，稳态下几乎不再打扰你）。事后用 `agentgate audit` 查看每个被门控动作的 JSONL 审计流：

```bash
agentgate audit
# ✓  13:20:26  exec        allow    npm install chalk
# ✗  13:20:26  net_egress  deny     telemetry.unknown-host.example
```

> 拦截方式可移植、无需 ptrace / libpcap：通过 PATH shim 把每个被拦的命令转发给一个 unix-socket broker，由它持有门控决策；网络 egress 则通过注入 `HTTP(S)_PROXY` 的本地重定向代理逐个主机门控。完整走查见 [`examples/claude-code-session.md`](./examples/claude-code-session.md)。

## 演示

60 秒：Agent 的 `npm install` 被暂停等待批准，安装后脚本对未声明主机的 egress 被红字拦下，最后 `agentgate audit` 打出完整轨迹。

[![asciicast](https://asciinema.org/a/PLACEHOLDER.svg)](https://asciinema.org/a/PLACEHOLDER)

> 📼 本仓库已附带录制好的 [`docs/demo.cast`](./docs/demo.cast)，可本地用 `asciinema play docs/demo.cast` 回放。上面的链接是占位符——发布后将 cast 上传到 asciinema.org 即可替换 `PLACEHOLDER` 为真实 ID。

## policy.yaml 策略 DSL

策略是**有序、首条匹配即生效**的规则列表。每条规则有一个 `match`（`action` + `target_glob`）和一个 `decision`（`allow` / `deny` / `ask`）；任何规则都没命中的动作落到 `default`。

```yaml
default: ask                 # 没有规则命中时的兜底决策

rules:
  # exec —— Agent 拉起的安装与脚本
  - match:
      action: exec
      target_glob: "*install*"
    decision: ask            # 每次安装都浮现出来，让你看清拉了什么

  # fs_write —— 把写入限制在项目目录内
  - match:
      action: fs_write
      target_glob: "$PWD/**"
    decision: allow
    scope: "$PWD"            # 写入必须留在项目根之内
  - match:
      action: fs_write
    decision: deny           # 项目根之外的任何写入一律拒绝

  # net_egress —— 放行常用 registry，门控其余一切
  - match:
      action: net_egress
      target_glob: "registry.npmjs.org"
    decision: allow
  - match:
      action: net_egress
    decision: deny           # 未声明的主机 -> 拦截
```

Glob 语义：`*` 匹配单个路径 / 主机段（`filepath.Match` 语义），`**` 跨段匹配（如 `$PWD/**`），不带通配的裸 token 按子串匹配（如 `registry.npmjs.org` 命中 egress 目标 `registry.npmjs.org:443`）。`agentgate init` 会落一份内置的合理默认策略，可直接编辑。

## 配置项

`agentgate run` 的常用开关：

| 选项 | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `--policy` | string | `./policy.yaml`（或 `$AGENTGATE_POLICY`） | 使用的策略文件 |
| `--audit` | string | `.agentgate/audit.jsonl`（或 `$AGENTGATE_AUDIT`） | 追加式 JSONL 审计日志路径 |
| `--agent` | string | `claude-code` | 被包裹 Agent 的标识，会带进提示与审计 |
| `--no-net` | bool | `false` | 关闭网络 egress 门控（仅门控 exec / fs） |
| `--always` | bool | `true` | 把 `[A]lways` 选择持久化写回策略文件 |

## 对比 vs 容器 / 静态扫描器

诚实的定位——容器在隔离上比我们成熟得多；AgentGate 解决的是另一个问题：**按动作、带意图、运行时**。

| 维度 | AgentGate | 容器 / 一次性 VM | 静态依赖扫描器 |
| --- | --- | --- | --- |
| 按动作逐个授权 | ✓ | ✗（全有或全无） | ✗ |
| 携带 Agent 意图 | ✓ | ✗ | ✗ |
| 运行时拦截载荷 | ✓ | 部分（边界内不区分动作） | ✗（安装前读包，错过运行时载荷） |
| 成熟的进程隔离 | 部分（spawn + egress 边界） | ✓ | — |
| 安装时不被关掉换效率 | ✓ | ✗（常因影响效率被禁用） | — |

## 路线图

- [x] **m1 —— wrap & gate exec**：包裹 Agent，拦截它拉起的每个子进程，带意图提示 allow/deny。
- [x] **m2 —— scope fs & net**：`policy.yaml` 把文件写入限制在声明路径内，按主机门控 egress，并写入 JSONL 审计。
- [x] **m3 —— DSL & 演示**：`allow`/`deny`/`ask` DSL + `--always` 持久化、`agentgate init` 默认策略、60 秒 asciinema 演示、双语 README。
- [ ] 更多 harness 的开箱适配与 README 安全章节集成（ECC / openfang）。
- [ ] 策略 cookbook：针对真实供应链行为的若干即用策略。
- [ ] 团队共享策略 / 审计仪表盘（v2+ 探索，非当前论点）。

> 推送仓库后可设置 GitHub topics：`gh repo edit --add-topic agent --add-topic coding-agent --add-topic security --add-topic sandbox`

## 许可证

AgentGate 免费、MIT 许可、单文件二进制的开源软件——没有付费墙，没有托管层。欢迎通过 [issue](https://github.com/SuperMarioYL/agentgate/issues) 反馈问题或提交 PR。

## Share this

```
AgentGate — a runtime per-action host gate for your Coding Agent. It pauses each
install / script / egress with the agent's own intent, instead of all-or-nothing
containers. After the Miasma worm, your agent needs a seatbelt.
https://github.com/SuperMarioYL/agentgate
```

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>
