# Personal Agentic AI (PAI)

> **A Stateless, Hardware-Aware, Recursive Self-Improving Personal Intelligence Engine**

**Status (2026-10-27):**
- **Release N (`v1.0.0-rc1`, commit `8ce81cb`):** Memory-safe Rust policy core (`core/`, `pai-core`) is **default-on** for runtime operations, with authoritative Python fallback and strict kill switch (`PAI_RUST_FALLBACK_PYTHON=1`).
- **N+1 Evaluation Window:** Active 14-day operational shadow telemetry evaluation window is running with zero discrepancies across comparisons.
- **Packaging & Distribution (Planned, not released):** A single `.exe` Inno Setup installer (`PAI-Setup-<version>-x64.exe`), PowerShell one-liner bootstrap (`install.ps1`), hardware-aware model setup, and Linux preview (`install.sh`) are specified in [PACKAGING_SPEC.md](docs/PACKAGING_SPEC.md) and [ADR-013](docs/adr/ADR-013-installer-and-distribution.md). Payload builder milestones P1 and P1b code are accepted; Milestone P2 is in progress.

See [Roadmap](docs/ROADMAP.md) · [Packaging Spec](docs/PACKAGING_SPEC.md) · [Release Notes N](docs/RELEASE_NOTES_N.md) · [Project Review](docs/PROJECT_REVIEW.md) · [Threat Model](docs/THREAT_MODEL.md) · [Decisions (ADRs)](docs/adr/README.md).

---

## 🌟 Executive Summary

**Personal Agentic AI** is a novel, high-efficiency personal intelligence system built from first principles. Unlike conventional Large Language Models (LLMs) that store hundreds of gigabytes of memorized factual knowledge in static weights, Personal Agentic AI is designed around a **Stateless Reasoning Core**. It treats intelligence as an executable logic machine rather than an encyclopedia, acquiring knowledge dynamically via low-level network pipelines and executing autonomously with hardware self-awareness.

The system is developed across a synergistic three-tier language architecture:
1. **Rust (`core/`)**: High-performance, memory-safe stateless reasoning engine, security policy enforcement, and hot-swappable algorithm core.
2. **C / C++ (`hardware/`)**: Low-level hardware telemetry daemon (CPU, GPU, NPU, RAM) and zero-overhead raw socket networking.
3. **Python (`research/`)**: Dynamic research prototyping, agentic tool workflows, data verification pipelines, and algorithmic testbeds.

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

## 🧪 Quickstart: Running the Research Prototype Directly

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
* The stateless cycle: **Perceive → Ingest → Reason → Purge**, where the purge is *verified* (buffers read back as all-zero) and runs even when a step fails.
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

## 📦 Packaging and Distribution (Planned, Not Released)

The packaging subsystem ([ADR-013](docs/adr/ADR-013-installer-and-distribution.md), [PACKAGING_SPEC.md](docs/PACKAGING_SPEC.md)) is in active development to provide end-user distribution:

- **Release 1.1.0 (Windows, Planned):**
  - **Installer:** `PAI-Setup-<version>-x64.exe` (per-user Inno Setup installer, no admin rights required).
  - **Agreement:** Mandatory acceptable-use terms page shown and accepted prior to installation.
  - **Prerequisites:** Guided detection and setup of the local Ollama server.
  - **Hardware-Aware Model Selection:** Designed to recommend verified open-weights models matching host RAM, VRAM, and disk headroom.
  - **Download Progress:** Real-time progress bar aggregating layer digests with transfer speed and ETA.
  - **PowerShell One-Liner Bootstrap:** Version-pinned script (`install.ps1`) fetching signed payloads.
- **Release 1.2.0 (Linux Preview, Planned):**
  - Cross-platform payload support (`linux-x64`), `install.sh` POSIX bootstrap without sudo, standalone pinned CPython runtime.
- **Payload Builder:** `packaging/build_payload.py` extracts release assets from git tags via `git archive`, validates `core/` and `research/` tree integrity, enforces PE/ELF binary formats, and generates canonical ADR-005 manifests.

---

## 📁 Repository Structure

```tree
pai/
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
│   ├── ARCHITECTURE.md           # Architecture, IPC + telemetry schema v1, prototype-vs-production table
│   ├── ROADMAP.md                # Phases 1-5, release train, exit criteria, decision gates
│   ├── PACKAGING_SPEC.md         # Packaging, installer, and model setup specification
│   ├── RELEASE_NOTES_N.md        # Release N (v1.0.0-rc1) evaluated binary notes
│   ├── RSI_SAFETY_SPEC.md        # Recursive self-improvement safety tiers + known weaknesses
│   ├── PROTOTYPE_SPEC.md         # Python prototype specification (matches the code)
│   ├── THREAT_MODEL.md           # Assets, trust boundaries, threat register T1-T20
│   ├── PROJECT_REVIEW.md         # Review findings, strategic risks, remediation status
│   ├── CONSTITUTION.md           # Safety Constitution v0.1 (hash pinned in updater's trust root)
│   ├── ALGORITHM.md              # Evidence-atom reasoning engine specification (experimental, ADR-007)
│   ├── NET_POLICY.md             # Outbound URL/IP policy shared by Python and Rust
│   ├── LOCAL_ASSISTANT_SPEC.md   # Local assistant specification (ADR-008)
│   ├── evidence/                 # Recorded gate evidence (sandbox smoke test, telemetry logs)
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
│   ├── agent_core.py             # Perceive -> Ingest -> Reason -> Purge loop
│   ├── capabilities.py           # Deny-by-default tool broker, taint tracking (ADR-006)
│   ├── outbound_policy.py        # Domain allow-list, offline mode, visible outbound log (ADR-002)
│   └── tests/                    # Comprehensive unit and integration test suite
│
└── tools/                        # Verification tools, workload drivers, and corpus checkers
    ├── check_n_plus_1.py         # N+1 14-day evaluation window progress checker
    └── test_build_payload.py     # P1/P1b hostile-input test suite and updater verification
```

---

## 📚 In-Depth Documentation

* [System Architecture & Memory Model](docs/ARCHITECTURE.md)
* [Engineering Roadmap (Phases 1-5)](docs/ROADMAP.md)
* [Packaging Specification](docs/PACKAGING_SPEC.md)
* [Recursive Self-Improvement (RSI) Safety Specification](docs/RSI_SAFETY_SPEC.md)
* [Python Research Prototype Specification](docs/PROTOTYPE_SPEC.md)
* [Threat Model](docs/THREAT_MODEL.md)
* [Local Assistant Specification](docs/LOCAL_ASSISTANT_SPEC.md)
* [Outbound Network Policy](docs/NET_POLICY.md)
* [Reasoning Algorithm (experimental)](docs/ALGORITHM.md)
* [Project Review & Open Decisions](docs/PROJECT_REVIEW.md)

---

## 📜 Terms of Use & Licensing

- **License & Terms Status:** The licensing approach and acceptable-use terms are specified in [PACKAGING_SPEC.md §3](docs/PACKAGING_SPEC.md#3-agreement-and-acceptable-use-notice) (Decision D8, open proposal awaiting legal review).
- **Acceptable Use Notice:** PAI must not be used to break the law, harm or deceive other people, attack or gain unauthorised access to systems or data, create or spread malware, infringe the rights of others, or for any other wrongful purpose. Users are responsible for their use and outputs.
- **Developer Credit:** Personal Agentic AI (PAI) was originated and developed by **Hirusha Suhan** ([@hirushasuhan](https://github.com/hirushasuhan)).
