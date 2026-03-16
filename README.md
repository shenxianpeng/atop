<div align="left">

```
 █████╗ ████████╗ ██████╗ ██████╗
██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████║   ██║   ██║   ██║██████╔╝
██╔══██║   ██║   ██║   ██║██╔═══╝
██║  ██║   ██║   ╚██████╔╝██║
╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝
```

**AI Agent Resource Monitor** — Know exactly what your AI tools are doing

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active_Development-brightgreen?style=flat-square)]()

</div>

---

## What is atop?

**atop** is an `htop`-style terminal dashboard that gives you **full visibility** into every AI coding assistant running on your machine — CPU, memory, GPU, disk I/O, and live API traffic to OpenAI, Anthropic, and more.

Stop wondering what Cursor, Copilot, or Claude Code are doing in the background. **atop** tells you exactly.

```
┌ atop — AI Agent Monitor ────────────────────────────────────────────────────────────────┐
│CPU   18.3% ███████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░│
│MEM   35.6%  11627/32768MB  swap 512/2048MB                                              │
│LOAD  1.24  0.98  0.87  (1/5/15 min)                                                     │
│CORES ▄▂▅▁▃▆▂▄▁▂▃▅▄▂▁▃▄▂▅▁▃▆▂▄▁▂▃▅▄▂▁▃                                                   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
┌ Processes ──────────────────────────────────────────────────────────────────────────────┐
│PID     NAME                 AGENT            CPU% ▼  MEM(MB)  RD_KB/s  WR_KB/s  UPTIME  │
│4821    Cursor               Cursor            18.3    1204     -        2       02:14:07│
│7103    claude               Claude Code        6.1     412     -        -       00:47:23│
│9204    Code Helper          VS Code            2.4     309     -        -       03:02:11│
│3801    copilot-agent        GitHub Copilot     1.2     198     -        1       01:33:44│
│1042    kernel_task          -                  0.8    4096     -        -       14:21:05│
└─────────────────────────────────────────────────────────────────────────────────────────┘
┌ AI API Traffic (pcap active) ───────────────────────────────────────────────────────────┐
│PID     AGENT            DOMAIN                           CONNS  RX_RECS  ~TOKENS  ~$COST│
│4821    Cursor           api.openai.com                    142      138     8960  $0.1344│
│7103    Claude Code      api.anthropic.com                  89       87     5632  $0.0845│
│3801    GitHub Copilot   api.openai.com                     34       31     2016  $0.0302│
│  ~ output token estimate (rx_bytes÷4); prices approximate                               │
└─────────────────────────────────────────────────────────────────────────────────────────┘
 q:Quit  ↑↓:Select  F5:Refresh  F6:Sort
```

---

## Why atop?

| Without atop | With atop |
|---|---|
| "Why is my laptop fan spinning?" | Cursor is using 18% CPU compiling context |
| "Where is my bandwidth going?" | Claude Code made 89 API calls, ~5600 tokens this session |
| "Did Copilot just send my code?" | See every TLS connection to `api.openai.com` in real time |
| "Which AI tool is eating my RAM?" | Per-process memory breakdown, sorted and live |
| "How much am I spending on AI APIs?" | ~$COST column estimates spend per agent in real time |

---

## Features

- **Process Monitor** — Live CPU%, memory, and disk I/O per process; AI agents highlighted automatically
- **System Summary** — CPU/MEM gauges with color-coded thresholds, swap usage, load average (1/5/15 min), and per-core sparkline
- **GPU Stats** — GPU utilization and VRAM usage (macOS via `ioreg`, Linux via `nvidia-smi` / AMD sysfs)
- **API Traffic Sniffing** — Captures TLS traffic via `libpcap`; no proxy or certificate installation required
- **SNI-based Detection** — Identifies AI endpoints from encrypted traffic without decrypting payloads
- **Token & Cost Estimation** — Estimates output tokens (`rx_bytes÷4`) and approximate API spend per agent
- **Agent SDK Integration** — Instruments your own agents to report exact token counts and latency via a Unix socket
- **Agent Recognition** — Automatically labels processes by tool (Cursor, Copilot, Claude Code, Windsurf, Aider, and more)
- **htop-style TUI** — Fast, keyboard-driven terminal UI built with [ratatui](https://github.com/ratatui-org/ratatui)
- **1-second Refresh** — Real-time updates, sortable by CPU or memory

---

## Supported AI Agents

| Agent | Detected By |
|---|---|
| **Cursor** | `cursor` in process name |
| **GitHub Copilot** | `copilot` in process name |
| **Claude Code** | `claude` in process name |
| **Windsurf** | `windsurf` in process name |
| **Aider** | `aider` in process name |
| **Amazon Q** | `amazonq` in process name |
| **OpenCode** | `opencode` in process name |
| **VS Code** | `code` in process name |

## Monitored API Endpoints

```
api.openai.com                      ← GPT-4, o1, Codex, ...
api.anthropic.com                   ← Claude 3/4 family
api.cohere.com                      ← Command R+
api.mistral.ai                      ← Mistral, Codestral
generativelanguage.googleapis.com   ← Gemini
```

---

## Getting Started

### Prerequisites

- **Rust** 1.85+ (2024 edition)
- **libpcap** — required for network capture
- **Root / sudo** — packet capture requires elevated privileges

```bash
# macOS
brew install libpcap

# Ubuntu / Debian
sudo apt install libpcap-dev
```

### Build

```bash
git clone https://github.com/shenxianpeng/atop.git
cd atop
cargo build --release
```

### Run

```bash
# Network monitoring requires root for raw packet access
sudo ./target/release/atop
```

> **Note:** Without root, atop falls back to process-only monitoring. The API Traffic panel will show a permission error and remain empty.

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `↑` / `↓` | Navigate process list |
| `F5` | Force immediate refresh |
| `F6` | Cycle sort key (CPU% ↔ MEM) |
| `q` | Quit |

---

## Agent SDK Integration

For exact token counts and latency (instead of pcap estimates), instrument your agent to emit JSON-Lines events to atop's Unix socket:

```
~/.local/share/atop/agent.sock
```

**Event schema:**
```json
{"ts":1710000000,"pid":1234,"model":"claude-3-5-sonnet","input_tokens":512,"output_tokens":1024,"latency_ms":843}
```

Only `pid` is required; all other fields are optional and default to `0` / empty string.

---

## How It Works

```
┌────────────────────────────────────────────────────────────────────┐
│                             atop                                   │
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────┐    │
│  │   sysinfo    │  │ pcap capture │  │   GPU    │  │ Agent SDK│    │
│  │  (process)   │  │  (TCP:443)   │  │collector │  │(UDS sock)│    │
│  └──────┬───────┘  └──────┬───────┘  └────┬─────┘  └────┬─────┘    │
│         │                 │               │              │         │
│         │   TLS SNI parse │               │              │         │
│         │  ◄──────────────┘               │              │         │
│         │                                 │              │         │
│         └──────────────────┬──────────────┘──────────────┘         │
│                            │                                       │
│                    ┌───────▼──────┐   ┌──────────────────┐         │
│                    │   Storage    │   │    Verifiers     │         │
│                    │ (ring buffer)│   │ (audit + verify) │         │
│                    └───────┬──────┘   └──────────────────┘         │
│                            │                                       │
│                      ┌─────▼──────┐                                │
│                      │  ratatui   │                                │
│                      │    TUI     │                                │
│                      └────────────┘                                │
└────────────────────────────────────────────────────────────────────┘
```

**Network capture pipeline:**
1. A background thread captures all TCP port 443 traffic via `libpcap`
2. Outgoing packets are inspected for TLS `ClientHello` — the SNI field reveals the target domain
3. When an AI API domain is detected, the connection is tracked by local port
4. `lsof` maps local ports to PIDs every second, linking API traffic to specific agent processes
5. Incoming `Application Data` records are counted; `rx_bytes÷4` estimates output tokens

**Data integrity:**
- Every process snapshot implements the `Verifiable` trait (PID, CPU%, memory bounds checked)
- Invalid snapshots are dropped and written to `~/.local/share/atop/audit.log` (JSON Lines)
- The ring buffer retains 60 snapshots (~1 minute) for historical sparkline rendering

---

## Roadmap

| Phase | Status | Goal |
|---|---|---|
| **P0** | ✅ Done | htop-style TUI layout |
| **P1** | ✅ Done | Process-level monitoring (CPU/mem/disk/GPU) |
| **P2** | ✅ Done | TLS sniffing for AI API traffic, token & cost estimation |
| **P3** | ✅ Done | Agent SDK (Unix socket) for exact token reporting |
| **PV** | ✅ Done | Verifier pipeline: audit log, ring buffer, snapshot rollback |

---

## Architecture

```
src/
├── main.rs                 # Entry point, event loop, keyboard handling
├── agents.rs               # Agent identification rules (keyword → display name)
├── app.rs                  # Application state & 1-second refresh logic
├── collectors/
│   ├── process.rs          # sysinfo-based process snapshots
│   ├── network.rs          # pcap-based TLS traffic capture + SNI parsing
│   ├── gpu.rs              # GPU stats (macOS ioreg / Linux nvidia-smi / AMD sysfs)
│   └── agent_sdk.rs        # Unix socket listener for SDK-instrumented agents
├── storage/
│   └── mod.rs              # Generic ring buffer (60-frame history, rollback_to)
├── verifiers/
│   ├── mod.rs              # Verifiable trait + VerificationResult
│   ├── process.rs          # Process snapshot validation rules
│   └── audit.rs            # JSON Lines audit log (~/.local/share/atop/audit.log)
└── view/
    └── mod.rs              # ratatui TUI rendering (4 panels + status bar)
```

---

## Contributing

Contributions are welcome! If you use an AI coding tool not yet recognized, open a PR to add it to `src/agents.rs` — it's just one line.

---

## License

Apache License 2.0 © [shenxianpeng](https://github.com/shenxianpeng)

---

<div align="center">

**Built with Rust** | Powered by `ratatui` · `sysinfo` · `pcap`

*If atop helps you understand your AI tools better, give it a ⭐*

</div>
