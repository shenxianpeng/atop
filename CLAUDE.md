# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**atop** is an `htop`-style terminal UI tool designed to monitor resource consumption of AI agents (e.g. Cursor, VSCode Copilot), including per-process CPU/memory usage and network requests to AI API endpoints (OpenAI, Anthropic, etc.).

Target stack: **Rust**, using the `sysinfo` crate for process monitoring and **ratatui + crossterm** as the TUI framework.

## Architecture

```
src/
├── main.rs
├── core/          # Core event loop, handles data flow
├── collectors/    # Multi-source data collection (process.rs, network.rs)
├── storage/       # Ring buffer indexed by snapshot_id, supports rollback_to()
├── verifiers/     # Verification loop (mod.rs, process.rs, audit.rs)
└── view/          # Reactive TUI rendering
```

## Development Roadmap

| Phase | Goal | Key Challenge |
|-------|------|---------------|
| P0 | Static TUI dashboard | Settle on UI layout that resembles `htop` |
| P1 | Process-level monitoring | Identify Cursor, VSCode Copilot and their resource usage |
| P2 | Protocol-layer sniffing | Capture HTTPS requests to `api.openai.com` / `api.anthropic.com` (core barrier) |
| P3 | Automation integration | Provide decorators for developers to plug their own agents into atop |

## Task Guidelines

Task descriptions must be **atomic and specific** — never vague.

- **Wrong**: "implement monitoring"
- **Right**: "using the `sysinfo` crate, implement a function in `collectors/process.rs` that returns CPU and memory snapshots for all processes whose name contains the keyword `cursor`"

Whenever a new technical decision is reached (e.g. how to filter AI traffic based on SNI), update the decision summary in `MEMORY.md` for future reference.

Never commit the contents of SPEC.md, PLAN.md, MEMORY.md, or CLAUDE.md to the repository.

All code comments and documentation should be in English.