# Personal Agentic AI (PAI)

> **A Stateless, Hardware-Aware, Recursive Self-Improving Personal Intelligence Engine**

**Status (2026-10-27):** 
- **Release N (`v1.0.0-rc1`, commit `8ce81cb`):** Memory-safe Rust policy core (`core/`, `pai-core`) is **default-on** for runtime operations, with authoritative Python fallback and strict kill switch (`PAI_RUST_FALLBACK_PYTHON=1`).
- **N+1 Evaluation Window:** Active 14-day operational shadow telemetry evaluation window is running with zero discrepancies across comparisons.
- **Packaging & Distribution (Release 1.1.0 & 1.2.0 Preview):** One-file installer (`PAI-Setup-<version>-x64.exe`), PowerShell one-liner bootstrap (`install.ps1`), hardware-aware model setup, download progress UI, and Linux preview (`install.sh`) are specified in [PACKAGING_SPEC.md](docs/PACKAGING_SPEC.md) and [ADR-013](docs/adr/ADR-013-installer-and-distribution.md). Milestones P1 and P1b are complete.

See [Roadmap](docs/ROADMAP.md) · [Packaging Spec](docs/PACKAGING_SPEC.md) · [Release Notes](docs/RELEASE_NOTES_N.md) · [Project Review](docs/PROJECT_REVIEW.md) · [Threat Model](docs/THREAT_MODEL.md) · [Decisions (ADRs)](docs/adr/README.md).

---

## 🌟 Executive Summary

**Personal Agentic AI** is a high-efficiency personal intelligence system built from first principles. Unlike conventional Large Language Models (LLMs) that store hundreds of gigabytes of memorized factual knowledge in static weights, Personal Agentic AI is designed around a **Stateless Reasoning Core**. It treats intelligence as an executable logic machine rather than an encyclopedia, acquiring knowledge dynamically via low-level network pipelines and executing autonomously with hardware self-awareness.

The system is developed across a synergistic three-tier language architecture:
1. **Rust (`core/`)**: High-performance, memory-safe stateless reasoning engine, security policy enforcement, and hot-swappable algorithm core.
2. **C / C++ (`hardware/`)**: Low-level hardware telemetry daemon (CPU, GPU, NPU, RAM) and zero-overhead raw socket networking.
3. **Python (`research/`)**: Dynamic research prototyping, agentic workflows, data verification pipelines, and algorithmic testbeds.

---

## 🏛️ The Three Architectural Pillars

```text
+-------------------------------------------------------------------------+
|                       Personal Agentic AI System                        |
+-------------------------------------------------------------------------+
|  1. Stateless Logic Core (Rust)                                         |
|     - Zero factual memorization footprint                               |
|     - Fast cognitive grammar & intent decomposition                     |
|     - Instant working-memory purge after task execution                 |
+-------------------------------------------------------------------------+
|  2. Hardware Self-Awareness Daemon (C/C++)                              |
|     - Real-time telemetry: CPU load, RAM pressure, NPU/GPU availability |
|     - Dynamic precision throttling (8-bit <-> 4-bit) under pressure     |
|     - Thermal and battery-aware compute budgeting                       |
+-------------------------------------------------------------------------+
|  3. Direct Network Ingestion Pipeline (C++/Rust)                        |
|     - Direct TCP/HTTP/WebSocket sockets bypassing heavy headless browsers|
|     - High-speed binary/text data streaming                             |
|     - Inline heuristic data verification and sanitization               |
+-------------------------------------------------------------------------+
```

1. **Stateless Logic Core**: The AI algorithm does not store factual databases inside weight parameters. It possesses linguistic structure, reasoning paths, and code generation faculties. All facts are ingested dynamically, processed within temporary RAM, and immediately scrubbed upon task completion.
2. **Hardware Self-Awareness**: The agent actively monitors the host machine's hardware state. If host RAM is strained, the engine compresses computation or offloads tasks; if an NPU/GPU is present, it routes matrix algebra to accelerated silicon.
3. **Direct Network Ingestion**: Instead of using heavy headless browsers (Chromium/Puppeteer), the agent speaks directly to internet protocols over raw sockets, parsing raw HTML/JSON directly into working memory in milliseconds.
4. **Safe Recursive Self-Improvement (RSI)**: The AI is engineered with coding as its primary skill. It iteratively improves its own performance through isolated sandboxes, adversarial auditing and scoped verification before a *signed* hot-swap of its executable engine.

> **Security stance:** The project aims for *defense in depth*, not an absolute-security promise. Every guarantee is tied to a named test or a named residual risk in [THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## 🚀 Quickstart: Developer CLI (`pai`)

If you are developing or running from a git checkout on Windows:

```powershell
# 1. One-click setup: registers repository 'bin' in your User PATH (PowerShell/cmd.exe)
.\install.bat

# 2. In any new terminal, run 'pai' commands directly:
pai doctor --skip-smoke                  # System diagnosis, Rust bridge handshake & telemetry status
pai analyze <folder>                     # Read-only structural, secret, and policy analysis of a codebase
pai chat "Explain Rust ownership"        # Local assistant chat routed through Ollama
pai docs <file.md|txt|csv>               # Local document exploration and factual question answering
pai code "Write a binary search in py"   # Sandboxed code synthesis with automated test verification gate
pai forecast --series <data.csv>         # Local time-series analysis and forecasting
```

Alternatively, invoke `pai.cmd` from the repository root:
```powershell
.\pai.cmd doctor --skip-smoke
```

---

## 📦 Packaging & Distribution Roadmap

The packaging subsystem ([ADR-013](docs/adr/ADR-013-installer-and-distribution.md), [PACKAGING_SPEC.md](docs/PACKAGING_SPEC.md)) delivers PAI as an easily installable, self-contained application:

- **Release 1.1.0 (Windows):**
  - **Primary:** `PAI-Setup-<version>-x64.exe` (per-user Inno Setup installer, no admin rights required).
  - **Agreement:** Mandatory acceptable-use terms page prior to installation.
  - **Prerequisites:** Automatic local Ollama server detection and guided setup.
  - **Hardware-Aware Model Selection:** Selects curated open-weights models matching host RAM, VRAM, and disk space with verified licenses.
  - **Progress UI:** Real-time download progress bar with layer aggregation, transfer speed, and ETA.
  - **PowerShell One-Liner:** Version-pinned bootstrap (`irm https://<host>/pai/v1.1.0/install.ps1 | iex`) with baked-in payload hash verification.
- **Release 1.2.0 (Linux Preview):**
  - Cross-platform payload support (`linux-x64`), `install.sh` POSIX script without sudo, standalone pinned CPython runtime.
- **Reproducible Payload Builder:** `packaging/build_payload.py` extracts release assets from git tags, checks `core/` and `research/` tree integrity, enforces PE/ELF binary formats, and generates canonical ADR-005 manifests.

---

## 📁 Repository Structure

```tree
personal_agentic_ai/
│
├── README.md
├── CHANGELOG.md                  # What changed and why
├── pai.cmd                       # Root developer CLI launcher
├── install.bat                   # One-click developer PATH registration
│
├── packaging/                    # Release packaging and distribution (Milestones P1-P5)
│   └── build_payload.py          # Reproducible payload builder (PE/ELF checks, git archive)
│
├── docs/
│   ├── ARCHITECTURE.md           # Architecture, IPC + telemetry schema v1
│   ├── ROADMAP.md                # Phases 1-5, release train, exit criteria
│   ├── PACKAGING_SPEC.md         # Packaging, installer, and model setup specification
│   ├── RELEASE_NOTES_N.md        # Release N (v1.0.0-rc1) evaluated binary notes
│   ├── THREAT_MODEL.md           # Assets, trust boundaries, threat register T1-T20
│   ├── PROJECT_REVIEW.md         # Review findings, strategic risks, reviewer approvals
│   ├── CONSTITUTION.md           # Safety Constitution v0.1 (pinned in trust root)
│   └── adr/                      # Architecture Decision Records 001-013
│
├── core/                         # Rust core (pai-core binary, default-on policy bridge)
│   ├── Cargo.toml
│   └── src/                      # Memory-safe tier, URL, secret, and release policies
│
├── hardware/                     # C / C++ Daemon (Phase 2)
│
├── research/                     # Python reference implementation & testbeds
│   ├── pai.py                    # Unified CLI command router (doctor, analyze, chat, etc.)
│   ├── pai_core_bridge.py        # IPC bridge to Rust pai-core with graceful fallback
│   ├── updater.py                # Signed-release updater (ADR-005, Ed25519)
│   ├── trust.json                # Public trust root keys and Constitution hash
│   └── tests/                    # Comprehensive unit and integration test suite
│
└── tools/                        # Verification tools, workload drivers, and corpus checkers
    ├── check_n_plus_1.py         # N+1 14-day evaluation window progress checker
    └── test_build_payload.py     # P1/P1b hostile-input test suite and updater verification
```

---

## 📜 License & Developer Credit

- **Author / Developer:** Developed by **Hirusha Suhan** ([@hirushasuhan](https://github.com/hirushasuhan)).
- **License:** Open Source. Source code is licensed under the repository's open source terms. Distributed binaries, installers, and models are subject to acceptable-use terms and individual model licenses.
- **Acceptable Use Notice:** PAI must not be used to break the law, harm or deceive others, attack or gain unauthorised access to systems, or distribute malware. Users remain responsible for their execution outputs.
