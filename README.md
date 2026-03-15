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

**atop** is an `htop`-style terminal dashboard that gives you **full visibility** into every AI coding assistant running on your machine — CPU, memory, disk I/O, and live API traffic to OpenAI, Anthropic, and more.

Stop wondering what Cursor, Copilot, or Claude Code are doing in the background. **atop** tells you exactly.

```
┌─ atop — AI Agent Monitor ──────────────────────────────────────────────────────┐
│ CPU: 34.2%   MEM: 11.4 / 32.0 GB                              [F5] Refresh     │
├────────────────────────────────────────────────────────────────────────────────┤
│ PID     AGENT           CPU%   MEM(MB)   DISK R   DISK W   UPTIME              │
│ 4821  ▶ Cursor          18.3%   1,204     0 KB/s   2 KB/s   2h 14m             │
│ 7103  ▶ Claude Code      6.1%     412     0 KB/s   0 KB/s   47m                │
│ 3309    Code Helper       2.4%     309     0 KB/s   0 KB/s   3h 02m            │
├─ API Traffic ──────────────────────────────────────────────────────────────────┤
│ AGENT          DOMAIN                    CONNS   RESPONSES   RX BYTES          │
│ Cursor         api.openai.com              142         138     4.1 MB          │
│ Claude Code    api.anthropic.com            89          87     2.8 MB          │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## Why atop?

| Without atop | With atop |
|---|---|
| "Why is my laptop fan spinning?" | Cursor is using 18% CPU compiling context |
| "Where is my bandwidth going?" | Claude Code made 89 API calls this session |
| "Did Copilot just send my code?" | See every TLS connection to `api.openai.com` in real time |
| "Which AI tool is eating my RAM?" | Per-process memory breakdown, sorted and live |

---

## Features

- **Process Monitor** — Live CPU, memory, and disk I/O per AI agent process
- **API Traffic Sniffing** — Captures TLS traffic via packet inspection; no proxy required
- **SNI-based Detection** — Identifies AI endpoints (`api.openai.com`, `api.anthropic.com`, etc.) from encrypted traffic without decrypting payloads
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
api.openai.com                 ← GPT-4, o1, Codex, ...
api.anthropic.com              ← Claude 3/4 family
api.cohere.com                 ← Command R+
api.mistral.ai                 ← Mistral, Codestral
generativelanguage.googleapis.com  ← Gemini
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
| `s` | Cycle sort key (CPU ↔ Memory) |
| `F5` | Force immediate refresh |
| `q` / `Esc` | Quit |

---

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                        atop                             │
│                                                         │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────┐  │
│  │   sysinfo   │    │ pcap capture │    │  Storage  │  │
│  │  collector  │    │   (TCP:443)  │    │ ring buf  │  │
│  └──────┬──────┘    └──────┬───────┘    └─────┬─────┘  │
│         │                  │                  │         │
│         │   TLS SNI parse  │                  │         │
│         │  ◄───────────────┘                  │         │
│         │                                     │         │
│         └──────────────────┬──────────────────┘         │
│                            │                            │
│                      ┌─────▼──────┐                     │
│                      │  ratatui   │                     │
│                      │    TUI     │                     │
│                      └────────────┘                     │
└─────────────────────────────────────────────────────────┘
```

**Network capture pipeline:**
1. A background thread captures all TCP port 443 traffic via `libpcap`
2. Outgoing packets are inspected for TLS `ClientHello` — the SNI field reveals the target domain
3. When an AI API domain is detected, the connection is tracked by local port
4. `lsof` maps local ports to PIDs every second, linking API traffic to specific agent processes
5. Incoming `Application Data` records are counted and byte-measured as API responses

---

## Roadmap

| Phase | Status | Goal |
|---|---|---|
| **P0** | ✅ Done | Static TUI layout |
| **P1** | ✅ Done | Process-level monitoring (CPU/mem/disk) |
| **P2** | 🔨 In progress | Protocol-layer TLS sniffing for API traffic |
| **P3** | 📋 Planned | SDK decorators for custom agent integration |

---

## Architecture

```
src/
├── main.rs                # Entry point, event loop
├── agents.rs              # Agent identification rules
├── app.rs                 # Application state & refresh logic
├── collectors/
│   ├── process.rs         # sysinfo-based process snapshots
│   └── network.rs         # pcap-based TLS traffic capture
├── storage/
│   └── mod.rs             # Ring buffer for snapshot history
├── verifiers/
│   ├── mod.rs             # Verification loop
│   ├── process.rs         # Process verifier
│   └── audit.rs           # Audit logging
└── view/
    └── mod.rs             # ratatui TUI rendering
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
