# Personal Agentic AI (PAI)

> **A Hardware-Aware, Privacy-Focused Personal Agentic AI Workstation**

**Status (2026-11-28):**
- **Release v1.5.1-beta.1 (Memory Optimizer, Local Sidecars, Keyless FLUX Fallback & MCP Hub):** Introduced active memory pressure monitoring and working set trimming via Win32 `EmptyWorkingSet`, isolated local inference sidecars (`llama-server`, `sd-cli`) on loopback `127.0.0.1:11435` with Gate 1 and Gate 3 admission controls, keyless FLUX fallback with PNG/JPEG magic byte verification, and multi-agent Model Context Protocol (MCP) hub with DPAPI credential encryption.
- **Release v1.5.0 (Deep Reasoning, Stuck-Recovery Cowork, Offline Air-Gap Mode & PC Control):** Added tree-of-thought deep reasoning engine with thought graph visualization, automated stuck-recovery watchdog in `cowork.py`, native Windows UI Automation (UIA) desktop driver, complete offline air-gap mode with fail-closed socket guards, and hardened release updater verifying GitHub manifest digests and non-downgrade SemVer rules.
- **Release v1.4.2 / v1.4.0 (Silent Startup, Background Update Applicator & Process Management):** Headless launcher without terminal console popups, atomic background update applicator (`apply_pending_update.py`), automatic cleanup of orphaned bridge server instances, and pause/resume download engine.
- **Release v1.3.0 (Software Auto-Updater & Multi-Channel Desktop Release):** Native auto-update manager with cryptographic verification, GitHub Releases API integration, configurable Stable and Beta/Preview release channels, dynamic in-app update progress telemetry, and atomic restart.
- **Release v1.2.0 (Tauri 2.0 Native Desktop Application):** Ultra-lightweight native desktop workstation for Windows (`desktop/`, `pai-desktop.exe`) featuring dual Clean Workstation Light and Deep Space Dark modes, headless native Windows folder picker dialogs, interactive Model Install modal with custom destination selection and real-time disk storage telemetry.
- **Release N (`v1.0.0-rc1`, commit `8ce81cb`):** Memory-safe Rust policy core (`core/`, `pai-core`) is **default-on** for runtime operations, with authoritative Python fallback and strict kill switch (`PAI_RUST_FALLBACK_PYTHON=1`).
- **N+1 Evaluation Window:** Operational shadow telemetry evaluation window is maintained with zero discrepancies across comparative runs.
- **Packaging & Distribution:** Standalone native desktop binary (`pai-desktop.exe`), local Inno Setup payload integration, and PowerShell bootstrap are fully aligned.

See [Roadmap](docs/ROADMAP.md) · [Packaging Spec](docs/PACKAGING_SPEC.md) · [Release Notes N](docs/RELEASE_NOTES_N.md) · [Project Review](docs/PROJECT_REVIEW.md) · [Threat Model](docs/THREAT_MODEL.md) · [Decisions (ADRs)](docs/adr/README.md).

---

## Executive Summary

**Personal Agentic AI (PAI)** is a high-efficiency personal intelligence system and desktop workstation built from first principles. Designed around an **Agentic Reasoning Core**, PAI runs locally on user hardware with adaptive resource awareness, executing tasks autonomously while keeping user data private and protected.

The system is developed across a synergistic three-tier architecture:
1. **Desktop Shell (`desktop/`, `pai-desktop.exe`)**: Ultra-lightweight native Windows desktop application built with Tauri 2.0 (Rust) and a local Python bridge daemon on `127.0.0.1`.
2. **Policy Core (`core/`, `pai-core`)**: High-performance, memory-safe Rust policy core enforcing resource tiers, URL validation, cryptographic verify-loop grading, and secret scanning.
3. **Execution & Research Engine (`research/`)**: Dynamic agentic tool workflows, model routing, hardware telemetry probes, sandboxed verification loops, deep reasoning, and Model Context Protocol (MCP) integrations.

---

## Architectural Pillars

```text
+-------------------------------------------------------------------------+
|                       Personal Agentic AI System                        |
+-------------------------------------------------------------------------+
|  1. Local-First Agentic Workstation (Tauri 2.0 + Python Bridge)         |
|     - Native standalone desktop application (Clean Light & Dark themes) |
|     - Local inference via Ollama and C++ sidecars (llama-server, sd-cli)|
|     - Complete offline air-gap mode with fail-closed socket guards      |
+-------------------------------------------------------------------------+
|  2. Hardware Self-Awareness & Memory Optimization (Win32 / Linux)       |
|     - Real-time telemetry: CPU load, RAM pressure, VRAM availability    |
|     - Dynamic compute tiers: HIGH, BALANCED, COMPRESSED context budget  |
|     - Active working set trimming (EmptyWorkingSet) and idle reaping    |
+-------------------------------------------------------------------------+
|  3. Defense-in-Depth Security & Sandboxed Verification (Rust & Python)  |
|     - Outbound URL policy (net_guard) blocking SSRF and private CIDRs   |
|     - Cryptographic nonce framing (--- UNTRUSTED DATA BEGIN ---)        |
|     - Isolated sandbox runners (AppContainer / Bubblewrap / AST guard)  |
+-------------------------------------------------------------------------+
|  4. Deep Reasoning & Extensible Tool Orchestration (MCP & Cowork)      |
|     - Tree-of-thought deep reasoning engine with thought graph tracking |
|     - Multi-agent cowork with stuck-recovery watchdog and auto-rollback |
|     - Native Windows UI Automation (UIA) desktop control                |
|     - Model Context Protocol (MCP) hub with DPAPI credential vault      |
+-------------------------------------------------------------------------+
```

1. **Local-First Agentic Workstation**: Runs locally on host hardware using Ollama and local C++ inference sidecars (`llama-server`, `sd-cli`) with optional cloud providers and a complete offline air-gap toggle.
2. **Hardware Self-Awareness & Memory Optimization**: Continuously monitors host CPU load, available RAM, and VRAM pressure via native Win32 `kernel32` APIs and memory probes to dynamically adjust compute tiers (`HIGH`, `BALANCED`, `COMPRESSED`) and trim working sets (`EmptyWorkingSet`).
3. **Defense-in-Depth Security & Sandboxing**: Strict URL policies (`net_guard`), secret detection in ingested data, unforgeable cryptographic nonce envelopes, and isolated sandbox execution (Win32 AppContainer, Linux Bubblewrap, AST guard) for model-generated code in a bounded verification loop.
4. **Deep Reasoning & Tool Orchestration**: Multi-agent cowork coordination with stuck-recovery watchdogs, tree-of-thought exploration, Windows UI Automation (UIA) desktop control, and Model Context Protocol (MCP) integrations with DPAPI encrypted credential vaulting.

> **Security stance:** The project aims for *defense in depth*, not an absolute-security promise. Every guarantee is tied to a named test or a named residual risk in [THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Quickstart: Developer CLI (`pai`)

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

## Quickstart: Running the Research Prototype Directly

Requires Python 3.8+ (standard library only; no external packages needed for core execution).

```powershell
cd research

# Interactive prototype menu
python main.py

# Scriptable CLI options
python main.py --telemetry                 # hardware snapshot (add --json for IPC message)
python main.py --ask "Explain Rust ownership"
python main.py --ask "Summarize" --topic "ශ්‍රී ලංකාව" --lang si   # Sinhala Wikipedia (--topic is explicit)
python main.py --ask "Explain Rust ownership" --model-url http://127.0.0.1:11434/v1 --model llama3.2   # local model (loopback only)
python main.py --ask "Explain Rust ownership" --offline --knowledge-dir ~/notes    # no network: answer from local files
python main.py --ask "Explain Rust ownership" --show-outbound                      # print exactly what left this machine
python main.py --benchmark                 # offline purge benchmark (add --online for network)
python main.py --check-code patch.py       # Tier-1 AST guard on a Python file

# Full test suite
python -m unittest discover -s tests -v
```

The prototype demonstrates:
* Real-time hardware telemetry (Windows `kernel32`, Linux `/proc`) driving an adaptive compute budget — no invented numbers when a source is unavailable.
* Direct HTTP(S) ingestion with an outbound policy (no `file://`, no private/metadata IPs) and an experimental raw-socket transport.
* Sanitisation, Unicode-aware quality scoring and prompt-injection screening.
* The execution cycle: **Perceive → Ingest → Reason → Purge**, where the purge is *verified* (buffers read back as all-zero) and runs even when a step fails.
* Privacy controls: domain allow-list, visible outbound log, offline mode, local-first knowledge.
* Blast-radius limits for prompt injection: a capability broker with taint tracking; signed-release updater; Windows Sandbox policy-as-code.

---

### Rust Core (`core/`)

Requires a Rust toolchain (`rustup`; MSVC build tools or MinGW C linker on Windows).

```powershell
cd core
cargo test                                           # unit tests
cargo run -- --conformance ../research/conformance   # golden vectors (tier + URL)
```

CI also runs `cargo fmt --check`, `cargo clippy -D warnings`, a vector drift check and a 10,000-case differential fuzz against the Python reference. The Rust core binary (`pai-core.exe`, SHA-256 `6f13d494...`) provides memory-safe tier, URL, secret scanning, and release verification policies.

---

### Models and Local Inference

The core repository does **not** bundle model weights. Real inference requires a locally served open-weights model reached over loopback (e.g. via Ollama on `http://127.0.0.1:11434`). The `pai` local assistant routes commands to local models based on host RAM and hardware limits (ADR-008, ADR-010).

---

## Packaging and Distribution

The packaging and distribution subsystem ([ADR-013](docs/adr/ADR-013-installer-and-distribution.md), [PACKAGING_SPEC.md](docs/PACKAGING_SPEC.md)) delivers standalone native executables, installers, and automated background update workflows:

- **Windows Desktop Workstation (`v1.2.0` – `v1.5.1`):**
  - **Standalone Application:** `pai-desktop.exe` (Tauri 2.0 + Rust shell embedding modern webview frontend and headless Python bridge server).
  - **Installer:** `PAI-Setup-<version>-x64.exe` (per-user Inno Setup installer, no administrator privileges required).
  - **Prerequisites & Model Management:** Automatic detection and guided configuration of local Ollama server and sidecar runtimes (`llama-server`, `sd-cli`).
  - **Hardware-Aware Model Selection:** Dynamically recommends verified open-weights models matching host RAM, VRAM, and storage headroom.
  - **Software Auto-Updater:** Integrated update manager with SHA-256 and manifest verification, background pending update applicator, and user-selectable Stable and Beta/Preview channels.
- **Payload Builder:** `packaging/build_payload.py` extracts release assets from git tags via `git archive`, validates `core/` and `research/` tree integrity, enforces PE/ELF binary formats, and generates canonical ADR-005 manifests.

---

## Repository Structure

```tree
pai/
│
├── README.md
├── CHANGELOG.md                  # Detailed release and feature history
├── pai.cmd                       # Root developer CLI launcher
├── install.bat                   # One-click developer PATH registration
│
├── desktop/                      # Native desktop workstation (Tauri 2.0 + Rust)
│   ├── src-tauri/                # Tauri backend (pai-desktop.exe)
│   ├── ui/                       # Frontend application assets (HTML/CSS/JS)
│   ├── bridge_server.py          # Local loopback HTTP bridge (127.0.0.1)
│   ├── apply_pending_update.py   # Atomic background update applicator
│   └── bin/                      # Native helper tools (pai_folder_picker.cs, pai_ui_agent.cs)
│
├── packaging/                    # Release packaging and distribution
│   ├── build_payload.py          # Reproducible payload builder (PE/ELF checks, git archive)
│   ├── pai.iss                   # Inno Setup Windows installer script
│   └── launcher/                 # Native C launcher (launcher.c -> pai.exe)
│
├── docs/
│   ├── ARCHITECTURE.md           # Architecture, IPC + telemetry schema v1, desktop workstation
│   ├── ROADMAP.md                # Phases 1-5, release train, exit criteria, decision gates
│   ├── PACKAGING_SPEC.md         # Packaging, installer, and model setup specification
│   ├── RELEASE_NOTES_N.md        # Release N (v1.0.0-rc1) evaluated binary notes
│   ├── RSI_SAFETY_SPEC.md        # Safety tiers & sandbox isolation (historical research)
│   ├── PROTOTYPE_SPEC.md         # Python prototype specification
│   ├── THREAT_MODEL.md           # Assets, trust boundaries, threat register T1-T40
│   ├── STRIDE_THREAT_MODEL.md    # STRIDE evaluations and mitigations
│   ├── TRUST_BOUNDARY_DIAGRAM.md # Mermaid trust boundary diagrams and inventory
│   ├── PROJECT_REVIEW.md         # Review findings, strategic risks, remediation status
│   ├── CONSTITUTION.md           # Safety Constitution v0.1 (hash pinned in updater trust root)
│   ├── ALGORITHM.md              # Evidence-atom reasoning engine specification
│   ├── NET_POLICY.md             # Outbound URL/IP policy shared by Python and Rust
│   ├── LOCAL_ASSISTANT_SPEC.md   # Local assistant specification (ADR-008)
│   ├── evidence/                 # Recorded gate evidence (sandbox smoke test, telemetry logs)
│   └── adr/                      # Architecture Decision Records 001-014
│
├── core/                         # Rust core (pai-core binary, default-on policy bridge)
│   ├── Cargo.toml
│   └── src/                      # Memory-safe tier, URL, secret, verify-loop, and release policies
│
├── hardware/                     # Hardware telemetry charter (Phase 2 probe plan)
│
├── research/                     # Python reference implementation & testbeds
│   ├── pai.py                    # Unified CLI command router (doctor, analyze, chat, etc.)
│   ├── pai_core_bridge.py        # IPC bridge to Rust pai-core with graceful fallback
│   ├── deep_reasoning.py         # Tree-of-thought exploration and reflection loops
│   ├── cowork.py                 # Multi-step task execution and stuck-recovery watchdog
│   ├── memory_optimizer.py       # Hardware-aware memory pressure and working set management
│   ├── local_sidecars.py         # Loopback process manager for llama-server and sd-cli
│   ├── mcp_hub.py                # Model Context Protocol multi-agent hub and vault
│   ├── context_engine.py         # Semantic context compression and token budgeting
│   ├── updater.py                # Signed-release updater (ADR-005, Ed25519)
│   ├── trust.json                # Public trust root keys and Constitution hash
│   ├── agent_core.py             # Perceive -> Ingest -> Reason -> Purge loop
│   ├── capabilities.py           # Deny-by-default tool broker, taint tracking (ADR-006)
│   ├── outbound_policy.py        # Domain allow-list, offline mode, visible outbound log (ADR-002)
│   └── tests/                    # Comprehensive unit and integration test suite
│
└── tools/                        # Verification tools, workload drivers, and release tooling
    ├── check_pins.py             # Tree hash and binary pin audit
    ├── check_secrets.py          # Tracked-file secret leak scanner
    ├── package_release.py        # Release distribution packaging script
    └── windows_parity_run.py     # Windows parity regression test suite
```

---

## In-Depth Documentation

* [System Architecture & Memory Model](docs/ARCHITECTURE.md)
* [Engineering Roadmap (Phases 1-5)](docs/ROADMAP.md)
* [Packaging Specification](docs/PACKAGING_SPEC.md)
* [Trust Boundary Diagrams](docs/TRUST_BOUNDARY_DIAGRAM.md)
* [STRIDE Threat Model](docs/STRIDE_THREAT_MODEL.md)
* [Threat Model](docs/THREAT_MODEL.md)
* [Safety Specification (Historical Research Archive)](docs/RSI_SAFETY_SPEC.md)
* [Python Research Prototype Specification](docs/PROTOTYPE_SPEC.md)
* [Local Assistant Specification](docs/LOCAL_ASSISTANT_SPEC.md)
* [Outbound Network Policy](docs/NET_POLICY.md)
* [Reasoning Algorithm (experimental)](docs/ALGORITHM.md)
* [Project Review & Open Decisions](docs/PROJECT_REVIEW.md)

---

## Terms of Use & Licensing

- **License & Terms Status:** The licensing approach and acceptable-use terms are specified in [PACKAGING_SPEC.md §3](docs/PACKAGING_SPEC.md#3-agreement-and-acceptable-use-notice) (Decision D8, open proposal awaiting legal review).
- **Acceptable Use Notice:** PAI must not be used to break the law, harm or deceive other people, attack or gain unauthorised access to systems or data, create or spread malware, infringe the rights of others, or for any other wrongful purpose. Users are responsible for their use and outputs.
- **Developer Credit:** Personal Agentic AI (PAI) was originated and developed by **Hirusha Suhan** ([@hirushasuhan](https://github.com/hirushasuhan)).
