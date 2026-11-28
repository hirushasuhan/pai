# Engineering Roadmap (Phases 1 - 5)

This roadmap outlines the systematic development of the **Personal Agentic AI (PAI)** from an agile Python research prototype to a high-performance, privacy-focused native intelligence engine and standalone desktop workstation.

_Last reviewed: 2026-11-28. Phase 1 closed at `05c9739`; Phase 2 Slices 1-2 verified; Track L (Local Assistant M1-M7) complete; Packaging (Inno Setup, native launcher) complete; Desktop Workstation Track (Tauri 2.0 shell, dual themes, model management) delivered in v1.2.0; Auto-Updater delivered in v1.3.0 and hardened in v1.4.0/v1.4.2; Deep Reasoning, Stuck-Recovery Cowork, Offline Air-Gap Mode, and UIA PC Automation delivered in v1.5.0; Memory Optimizer, Local Sidecars (llama-server, sd-cli), Keyless FLUX Fallback, and MCP Hub delivered in v1.5.1-beta.1. Risks R1–R16 mitigated or closed — see [PROJECT_REVIEW.md](PROJECT_REVIEW.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [STRIDE_THREAT_MODEL.md](STRIDE_THREAT_MODEL.md)._

---

## High-Level Phase Overview

```mermaid
gantt
    title Personal Agentic AI Development Roadmap
    dateFormat  YYYY-MM-DD
    section Phase 1: Research Prototype
    Python agentic loop, telemetry, hardening (done)     :done, 2026-10-01, 2026-10-05
    Risk remediation R1-R7 (done)                        :done, 2026-10-05, 2026-10-06
    Exit gate: sandbox, local model, CI, signing (done)  :done, 2026-10-06, 2026-10-07
    section Phase 2: Native layers
    VS2 Rust tier + URL policy conformance (done)        :done, 2026-10-06, 2026-10-07
    Phase 2 Slice 1: Rust safe ingestion (done)          :done, 2026-10-12, 2026-10-12
    Phase 2 Slice 2: Rust verify-loop & codec (done)     :done, 2026-10-13, 2026-10-14
    VS3 Rust Win32 telemetry & bridge (done)             :done, 2026-10-08, 2026-11-05
    section Track L: Local assistant (ADR-008)
    M1 bake-off, M1b router, M1c calibration (done)      :done, 2026-10-08, 2026-10-25
    M2 verify loop, M3 analyze, M4 docs, M5 forecast (done) :done, 2026-10-10, 2026-10-27
    M7 Singlish quality gate & interactive shell (done)  :done, 2026-10-27, 2026-11-03
    section Desktop Workstation & Distribution
    Packaging, Inno Setup installer, launcher.c (done)   :done, 2026-10-27, 2026-11-08
    v1.2.0 Tauri 2.0 shell, dual themes, folder picker   :done, 2026-11-08, 2026-11-14
    v1.3.0 Auto-updater & multi-channel flow (done)      :done, 2026-11-15, 2026-11-22
    v1.4.0 / v1.4.2 Background updater & silent start    :done, 2026-11-22, 2026-11-23
    section v1.5.0 & v1.5.1 Subsystems
    v1.5.0 Air-gap, Deep Reasoning, Cowork & UIA PC control :done, 2026-11-24, 2026-11-26
    v1.5.1-beta.1 Memory optimizer, sidecars, MCP hub    :done, 2026-11-26, 2026-11-28
    section Phase 4: Sandboxed Code Verification
    Windows Sandbox & AppContainer runner (done)         :done, 2026-10-10, 2026-10-25
    Verify loop & tagged codec parity (done)             :done, 2026-10-13, 2026-10-14
    section Phase 5: Autonomous Workstation Integration
    Hardware telemetry & dynamic budgeting (done)        :done, 2026-10-25, 2026-11-28
    UIA PC automation & local sidecars (done)            :done, 2026-11-24, 2026-11-28
```

---

## Phase 1: Python Research Prototype & Verification Lab (COMPLETE — exit gate closed 2026-10-07)
**Objective**: Build a working, testable prototype in Python to validate the 3-pillar concepts and the safety ideas before committing them to native compiled languages.

### Deliverables
- [x] Project scaffolding (`core/`, `hardware/`, `research/`, `docs/`).
- [x] `research/hardware_telemetry.py` — Windows `kernel32` + Linux `/proc`, RAM, CPU load, battery, single-source tier policy, JSON IPC form. *(Hardened 2026-10-05: no invented fallback values.)*
- [x] `research/network_pipeline.py` — direct HTTP(S) ingestion, Wikipedia search→summary (multi-language incl. Sinhala), DuckDuckGo fallback, typed errors.
- [x] `research/net_guard.py` — outbound URL policy (SSRF / `file://` protection). *(Added after review finding C1.)*
- [x] `research/raw_http.py` — experimental raw `socket`+`ssl` client with IP pinning and DNS-rebinding protection.
- [x] `research/data_verifier.py` — HTML-parser sanitiser, byte-safe truncation, Unicode-aware scoring, prompt-injection screening.
- [x] `research/secure_buffer.py`, `memory_probe.py` — wipe-and-verify purge primitive and RSS probe.
- [x] `research/reasoner.py` — `Reasoner` interface + honest stub.
- [x] `research/agent_core.py` — Perceive → Ingest → Reason → Purge with guaranteed purge (`finally`) and a measured `PurgeReport`.
- [x] `research/ast_guard.py` — Tier-1 static AST guard and import allowlist.
- [x] `research/benchmark.py` — purge benchmark that can actually fail.
- [x] `research/main.py` — interactive CLI + scriptable flags.
- [x] `research/tests/` — 170 unit tests at 2026-10-07 (stdlib `unittest`; 5 skipped on Windows).
- [x] Docs aligned with code; `THREAT_MODEL.md`, `PROJECT_REVIEW.md` added.
- [x] **Risk remediation (second pass)** — each risk has an ADR and tested code:
  - R1 `reasoner.py::LocalLLMReasoner` (ADR-001) · R2 `outbound_policy.py`, `local_knowledge.py` (ADR-002) · R3 claims lint `tests/test_claims.py`
  - R4 `ed25519_ref.py`, `updater.py`, `sign_release.py`, `docs/CONSTITUTION.md` (ADR-005) · R5 `sandbox_policy.py` (ADR-003)
  - R6 `conformance.py` + `conformance/*.json` golden vectors (ADR-004) · R7 `capabilities.py` + `context_tainted` (ADR-006)

### Phase 1 Exit Criteria (gate to Phase 2)
All must be true before Phase 2 starts:
- [x] `python -m unittest discover -s tests` is green **on the Windows development machine** (170 tests at the 2026-10-07 check).
- [x] Live ingestion verified on Windows: `main.py --ask "Explain Rust ownership"` and `--lang si`, with both `--transport urllib` and `--transport raw`.
- [x] `main.py --benchmark` passes on Windows; RSS trend recorded in `PROJECT_REVIEW.md`.
- [x] Telemetry JSON schema v1 and the tier-policy table are frozen (conformance tests for Rust/native core).
- [x] CI runs the test suite on Windows (GitHub Actions `windows-latest` run #37520707673 passed).
- [x] Owner confirms the default decisions D1–D4 (ADR-001…004 confirmed).
- [x] **Windows Sandbox smoke test** (ADR-003): verified 7/7 checks passed; recorded in `docs/evidence/sandbox_results.json`.
- [x] Run one real local model through `--model-url` and record RAM/latency per tier (ADR-001; Ollama 1B and 3B GPU offload measured).
- [x] Constitution text reviewed by the owner; signing key generated and public key placed in `research/trust.json` (ADR-005).

### Optional Phase 1 stretch (only if time remains)
- Benchmark two or three candidate local models (size/quantisation) against a small fixed evaluation set to choose the product-path model (ADR-001).
- Fuzz `DataVerifier` (random HTML, huge/unicode inputs) with the stdlib only.

---

## Phase 2: Native layers — Rust policy core (VS2 done), Rust safe-ingestion string primitives (Slice 1 done), Rust verify-loop & tagged value codec (Slice 2), Win32 telemetry (VS3), C++ probe (VS4)
_Status 2026-10-12: the Rust slice VS2 (tier + URL policy), Phase 2 Slice 1 (`core/src/ingest.rs` string-level safe-ingestion, secret-scanning with `re.ASCII` on all credential regexes, terminal/text/header sanitization, and cryptographic nonce-envelope primitives; file/folder traversal `ingest_file`, `ingest_folder`, and `assemble_untrusted_context` remain in Python `research/ingest.py`), and Phase 2 Slice 2 (`core/src/verify_loop.rs` tagged RPC value codec `encode_value`/`decode_value`/`decode_envelope_json`, constant-time HMAC-SHA256 verdict frame verification `verify_verdict_frame`, and bounded canonical example assertion extraction `extract_example_assertions`; subprocess orchestration, `ast_guard`, `prepare_test_suite`, and the repair loop remain in Python `research/verify_loop.py`) are implemented and verified against 200 tier vectors, 87 URL vectors, 113 ingest vectors, and 66 verify-loop vectors, 5,000+ case deterministic no-panic property tests in `ingest.rs` and `verify_loop.rs`, and multi-seed differential fuzzing (`--fuzz 10000` across 7 seeds `42`, `9001`, `1337`, `20261012`, `555`, `777`, `31337` — 43,330 cases per seed, 303,310 total cases, 0 mismatches, 0 panics)._

**Objective**: Native low-level Windows integration for hardware telemetry and a time-boxed spike to confirm Rust as the network and policy layer.

### Deliverables
- **Hardware Telemetry Integration**: Native Win32 integration (`GlobalMemoryStatusEx`, `GetSystemTimes`, `GetSystemPowerStatus`) in Python (`research/hardware_telemetry.py`) and Rust (`core/src/win32.rs`). Publishes **telemetry schema v1** (`ARCHITECTURE.md` §3.1) and enforces resource tier limits.
- **Conformance**: Passes `research/conformance/tier_policy_vectors.json` (200 vectors) across both Rust and Python runtimes.
- **Memory-protection hooks**: `VirtualLock` for working buffers, memory trimming via `EmptyWorkingSet`, and memory wipe routines.
- **Networking Architecture Evaluation**: Rust baseline (`hyper`/`rustls`/`ureq` patterns) and stdlib HTTP pipelines evaluated. Standalone C++ raw socket daemon dropped in favor of Rust policy core (`core/src/url_policy.rs`) and Python stdlib transport for memory safety and attack surface reduction.

---

## Phase 3: High-Performance Rust Core Engine
**Objective**: Replace Python orchestration with a zero-cost, memory-safe compiled Rust engine.

### Entry decision: Reasoner strategy — **ADR-001 accepted (default)**
Adopt a local open-weights model behind the `Reasoner` interface (Option A); a custom architecture is a parallel research track that must beat the adopted model on a fixed evaluation to replace it (Option B). The Python `LocalLLMReasoner` already exercises the contract; owner confirmed and selected the default models.

### Deliverables & Vertical Slices
- **Vertical Slice 2 (VS2), Phase 2 Slice 1 & Phase 2 Slice 2 — Policy Conformance, String-Level Safe Ingestion & Verify-Loop Primitives**:
  - Pure Rust implementations of resource tier policy (`src/tier.rs`), outbound URL policy with Canonical Blocked CIDRs (`src/url_policy.rs`), Phase 2 Slice 1 string-level safe-ingestion primitives (`src/ingest.rs`; filesystem traversal `ingest_file`, `ingest_folder`, and `assemble_untrusted_context` remain in Python `research/ingest.py`), and Phase 2 Slice 2 verify-loop & tagged value codec primitives (`src/verify_loop.rs`: `encode_value`, `decode_value`, `decode_envelope_json`, constant-time HMAC-SHA256 `verify_verdict_frame`, and `extract_example_assertions`; subprocess orchestration, `ast_guard`, and the repair loop remain in Python `research/verify_loop.py`).
  - Zero unsafe code blocks (`unsafe = 0` in `tier.rs`, `url_policy.rs`, `ingest.rs`, and `verify_loop.rs` with `#![forbid(unsafe_code)]`), zero network or regex crate dependencies (strictly `serde` + `serde_json` + `std::net`).
  - Passes 200 tier vectors, 87 URL vectors, 113 ingest vectors + `limits`, and 66 verify-loop vectors + `codec_policy` parity check (`pai-core --conformance`).
  - Multi-seed differential fuzz testing (`python research/conformance.py --fuzz 10000` across 7 seeds `42`, `9001`, `1337`, `20261012`, `555`, `777`, `31337`): 5,000 tier cases, 5,000 URL cases, 23,331 ingest cases, and 9,999 verify-loop cases (43,330 cases per seed; 303,310 total cases) compared with 0 mismatches and 0 panics between Python and Rust.
  - Windows CI job verifying `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, and drift checking.

---

## Phase 4: Sandboxed Code Verification & Execution (Verify Loop)
**Objective**: Enable safe, isolated execution and automated test verification of model-generated code without compromising host operating system security. (Note: In accordance with the system safety model, recursive self-modification of system binaries or source code is not implemented; code execution is confined strictly to task verification).

### Entry decision: Sandbox technology — **ADR-003 accepted (default)**
Windows Sandbox (networking disabled, one writable output folder) is evaluated for heavy untrusted workloads; AppContainer + Job Object runners (`research/sandbox_win32.py`) and Linux bubblewrap (`research/sandbox_linux.py`) are active for lightweight execution.

### Deliverables
- **Isolation environment** per the ADR with automated test execution pipeline, process-tree killing, wall-clock timeout enforcement, and complete network airgap.
- **Verify-Loop Orchestrator & AST Guard**: Generator proposes code; `ast_guard.py` enforces AST node allowlists; tests execute in isolated sandbox processes with HMAC-graded verdicts.
- **Cryptographic Updater (ADR-005)**: Maintained in `research/updater.py`, `core/src/updater.rs`, and `desktop/apply_pending_update.py` (Ed25519 manifest, per-file SHA-256, anti-rollback, pinned Constitution hash, atomic install, rollback).

---

## Phase 5: Autonomous Personal Intelligence Integration
**Objective**: Turn the engine into a personal daily companion working natively within Windows.

### Deliverables
- **OS Control**: Windows UI Automation routed through the **capability broker** (`desktop/bin/pai_ui_agent.cs`, `research/automation.py`, `research/capabilities.py`, ADR-006: deny-by-default grants, taint-aware human confirmation, audit chain) — delivered in v1.5.0-beta.3.
- **Local Sidecars & Ambient Audio**: Local inference runtime orchestration (`research/local_sidecars.py`) for `llama-server` and `sd-cli` — delivered in v1.5.1-beta.1.
- **Privacy controls**: Implemented in Phase 1 (ADR-002) and extended with complete Offline Air-Gap Mode in v1.5.0.

---

## Track L: Local Assistant `pai` (ADR-008) — Complete
**Objective**: A local assistant that analyzes code, documents, web pages and business datasets (with forecasts) and writes and tests code. Full specification: [LOCAL_ASSISTANT_SPEC.md](LOCAL_ASSISTANT_SPEC.md).

| Milestone | Deliverable | Acceptance Status |
|-----------|-------------|-------------------|
| M1 | Model bake-off + `pai code` generate-only | Complete — Evaluated across frozen coding, document, and Singlish sets. |
| M1.1 | Bake-off hardening | Complete — Subprocess runner, thinking control, and cold RAM measurements. |
| M1.2 | Standardized RAM measurements & batch evaluation | Complete — 5-run cold median recorded in `MEASUREMENT_PROCEDURE.md`. |
| M1b | Adaptive model router | Complete — `research/router.py`, 15 golden vectors pass, hardware-aware fallback. |
| M1c | Portability & calibration | Complete — `pai setup/doctor/calibrate/models`, dynamic profile validation. |
| M1d | Optional cloud providers | Complete — Off by default, DPAPI key storage, strict spend caps, card-host validation. |
| M2a | Sandbox Runner & Capability Probe | Complete — Win32 AppContainer + Job Object and Linux bubblewrap runners. |
| M2b | Verify loop & `pai code` | Complete & Frozen — Tagged RPC codec, AST guard, bounded repair loop, HMAC verdict grading. |
| M3 | `pai analyze <folder>` | Complete — Nonce-framed context, 35+ secret patterns, entry-point and risk extraction. |
| M4 | `pai docs <file>` | Complete — txt/md/csv safe ingestion, formula neutralization, terminal sanitization. |
| M5 | `pai forecast` | Complete — Backtested forecasting (naive, seasonal, moving average, linear, Holt-Winters). |
| M6 | Local web interface & desktop workstation | Complete — Replaced by native Tauri 2.0 desktop application (`pai-desktop.exe`). |
| M7 | Singlish response-quality gate | Complete — Frozen 25-prompt gate with automated heuristic scoring. |

---

## Desktop Workstation & Auto-Updater Track (Delivered v1.2.0 – v1.4.2)

- **v1.2.0 (Native Desktop Application)**: Tauri 2.0 + Rust shell (`pai-desktop.exe`), headless Python bridge server (`127.0.0.1:8765`), dual Workstation themes (Clean Light & Deep Space Dark), native Win32 `IFileOpenDialog` (`pai_folder_picker.exe`), interactive Model Install modal with custom destination selection and real-time disk storage telemetry.
- **v1.3.0 (Software Auto-Updater)**: Native update manager with cryptographic Ed25519 verification, GitHub Releases API integration, configurable Stable and Beta/Preview channels, in-app download telemetry, and atomic restart.
- **v1.4.0 (Background Applicator & Download Engine)**: Staged update applicator (`desktop/apply_pending_update.py`), pause/resume/cancel download engine with layer cache preservation, and automated cleanup of stale bridge servers.
- **v1.4.2 (Silent Launch & Parity)**: Headless workstation launcher without terminal console popups, unified release packaging, and cross-channel test validation.

---

## Release 1.5 Subsystems (Delivered in v1.5.0 & v1.5.1-beta.1)

### A. Automation & PC Control (Delivered in v1.5.0-beta.3)
- Native Windows UI Automation driver (`desktop/bin/pai_ui_agent.cs`) for accessibility-tree inspection and desktop action execution.
- Routed strictly through `research/automation.py`, `research/windows_mcp_server.py`, and `research/capabilities.py` (`ToolBroker`) requiring explicit human-in-the-loop confirmation.

### B. Offline Air-Gap Mode (Delivered in v1.5.0-beta.1 / beta.2)
- Complete offline enforcement toggle (`AIRGAP_OFFLINE` / `pai_airgap`) in `desktop/bridge_server.py` and workstation settings.
- Fail-closed socket filters blocking non-loopback connections and cloud AI routing when active.

### C. Deep Reasoning & Stuck-Recovery Cowork (Delivered in v1.5.0-beta.3)
- Tree-of-thought deep reasoning engine (`research/deep_reasoning.py`) with radial node exploration and reflection cycles.
- Multi-step Cowork watchdog (`research/cowork.py` `StuckDetectorWatchdog`) detecting repetition loops and heartbeat stalls, with automated rollback to valid reasoning checkpoints.

### D. Memory Optimizer & Hardware Pressure Engine (Delivered in v1.5.1-beta.1)
- Active RAM/VRAM pressure monitoring in `research/memory_optimizer.py` and `research/memory_probe.py`.
- Working set trimming via Win32 `EmptyWorkingSet` and exposed `/api/system/memory_status` / `/api/system/optimize_memory` endpoints.
- Dynamic hardware-adaptive context window budgeting preventing out-of-memory errors during long sessions.

### E. Local Inference Sidecars & Installer (Delivered in v1.5.1-beta.1)
- Background process orchestrator (`research/local_sidecars.py`) for `llama-server` and `sd-cli` bound strictly to loopback (`127.0.0.1:11435`).
- Pre-load Gate 1 disk and Gate 3 RAM/VRAM admission checks with 64-layer offload calculation and 300-second idle process reaping.
- Safe sidecar installer (`research/sidecar_installer.py`) with host allowlists, zip-slip defense, and archive size bounds.

### F. Keyless FLUX Image Synthesis (Delivered in v1.5.1-beta.1)
- Keyless Pollinations FLUX and local image synthesis fallbacks in `research/cloud_ai.py`.
- Hardened export endpoint (`/api/image/save_as`) with PNG/JPEG magic byte verification, directory escape prevention, and native folder picker integration.

### G. Model Context Protocol (MCP) Hub & Plugin Manager (Delivered in v1.5.1-beta.1)
- Multi-agent MCP client and hub (`research/mcp_hub.py`, `research/mcp_client.py`) supporting STDIO and Streamable HTTP/SSE transports.
- DPAPI token encryption via `MCPVaultManager`, `PluginScanner` security validation, `ToolFirewall` redaction, and `ContextEngine` observation masking.

---

## Roadmap Risks (Current Status as of 2026-11-28)

| ID | Risk | Status | Where handled |
|----|------|--------|---------------|
| R1 | Reasoning core size/capability unknown | **Mitigated**: Adopted local open models behind `Reasoner`; `LocalLLMReasoner` active | ADR-001, `research/reasoner.py` |
| R2 | Network queries conflict with "private/local" goal | **Mitigated**: Allow-list, visible log, offline mode, local knowledge, and offline air-gap mode | ADR-002, `research/outbound_policy.py`, `desktop/bridge_server.py` |
| R3 | Absolute-security claims | **Closed**: Strict defense-in-depth policy and automated test lint | `THREAT_MODEL.md` §5, `research/tests/test_claims.py` |
| R4 | Constitution hash defeatable | **Mitigated**: External signing, separate updater, pinned Constitution hash | ADR-005, `research/updater.py`, `desktop/apply_pending_update.py` |
| R5 | Sandbox containment on Windows | **Mitigated**: Windows Sandbox specification, AppContainer + Job Object runners | ADR-003, `research/sandbox_win32.py`, `research/sandbox_policy.py` |
| R6 | Multi-language development scope | **Mitigated**: Rust policy/ingest/verify core with conformance vectors and differential fuzzing | ADR-004, `core/src/`, `research/conformance.py` |
| R7 | Prompt injection via tools | **Mitigated**: Capability broker with taint tracking, human confirmation, audit logging | ADR-006, `research/capabilities.py`, `research/mcp_hub.py` |
| R8 | Small local model hallucinations/errors | **Mitigated**: Verify loop with tests, spec-bounded prompts, hidden test grading | ADR-008, `research/verify_loop.py`, `core/src/verify_loop.rs` |
| R9 | Self-training data poisoning | **Designed**: Self-play validation, tainted trajectory exclusion, promotion gates | ADR-008, `docs/THREAT_MODEL.md` T18 |
| R10 | Untrusted local files and documents | **Mitigated**: Cryptographic nonce envelopes, 35+ secret patterns, path containment | `research/ingest.py`, `core/src/ingest.rs` |
| R11 | Forecast overconfidence | **Mitigated**: Deterministic Python engines, backtest metrics, residual intervals | `research/forecast_engine.py` |
| R12 | Model supply chain & licensing | **Mitigated**: Model cards, manifest SHA-256 validation, license verification | `research/catalog.json`, `tools/sign_catalog.py` |
| R13 | Workflow inputs treated as instructions | **Mitigated**: Nonce fencing, strict untrusted data handling, ToolBroker taint gating | `research/capabilities.py`, `docs/CONSTITUTION.md` |
| R14 | Image model license/provenance misuse | **Mitigated**: Manifest checks, explicit model allowlists, sidecar provenance recording | `research/local_sidecars.py`, `research/cloud_ai.py` |
| R15 | Resource exhaustion from large models / sidecars | **Mitigated**: Gate 1 & 3 admission checks, memory optimizer, working set trimming, idle reaper | `research/memory_optimizer.py`, `research/local_sidecars.py` |
| R16 | MCP tool privilege escalation & credential harvesting | **Mitigated**: DPAPI vault, PluginScanner, ToolFirewall, elicitation schema blocks | `research/mcp_hub.py`, `research/plugin_manager.py` |
