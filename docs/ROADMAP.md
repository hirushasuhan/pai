# Engineering Roadmap (Phases 1 - 5)

This roadmap outlines the systematic development of the **Personal Agentic AI (PAI)** from an agile Python research prototype to a fully autonomous, recursive self-improving native intelligence daemon.

_Last reviewed: 2026-10-13. Phase 1 closed by reviewer at `05c9739`; Phase 1.1 fixes completed (`0d0f553`); Phase 2 Slice 1 (`core/src/ingest.rs`) verified against 113 golden vectors; Phase 2 Slice 2 (`core/src/verify_loop.rs` verify-loop framing and tagged value codec) complete and verified against 73 golden vectors and widened multi-seed differential fuzzing (seeds 101, 202, 303, 42, 555, 777, 31337) with 0 mismatches; M2b verification gate frozen at `6218fbc`; M3/M4/M5/M7 complete. Risks R1–R7 remediated, R8–R12 mitigated/closed in prototype — see [PROJECT_REVIEW.md](PROJECT_REVIEW.md) and the [ADRs](adr/README.md)._

---

## 🗺️ High-Level Phase Overview

```mermaid
gantt
    title Personal Agentic AI Development Roadmap (dates after 2026-10-07 are planning estimates)
    dateFormat  YYYY-MM-DD
    section Phase 1: Research Prototype
    Python agentic loop, telemetry, hardening (done)  :done, 2026-10-01, 2026-10-05
    Risk remediation R1-R7 (done)                     :done, 2026-10-05, 2026-10-06
    Exit gate: sandbox, local model, CI, signing (done) :done, 2026-10-06, 2026-10-07
    section Phase 2: Native layers
    VS2 Rust tier + URL policy conformance (done)     :done, 2026-10-06, 2026-10-07
    Phase 2 Slice 1: Rust safe ingestion (done)       :done, 2026-10-12, 2026-10-12
    VS3 Rust Win32 telemetry + parity (ADR-009)       :active, 2026-10-08, 2026-11-05
    C++ GPU/NPU probe (VS4, reduced charter)          :2026-11-05, 2026-11-30
    section Track L: Local assistant (ADR-008)
    M1 model bake-off + pai code (generate)           :2026-10-08, 2026-10-29
    M1b adaptive model router                         :2026-10-29, 2026-11-12
    M1c portability, calibration, model selection     :2026-11-12, 2026-11-26
    M1d optional cloud providers (ADR-010)            :2026-11-26, 2026-12-10
    M2 verify loop (restricted runner)                :2026-12-10, 2026-12-31
    M3 pai analyze (folders)                          :2026-12-31, 2027-01-14
    M4 docs, M5 forecast                              :2027-01-14, 2027-02-18
    M6 local web interface, M7 Singlish quality gate  :2027-02-18, 2027-03-18
    section Track M: Own model (gated research)
    Stage 0 tokenizer + tiny model (laptop)           :2026-11-15, 2027-01-15
    Self-play data engine + LoRA experiments          :2027-01-15, 2027-03-15
    section Phase 4: Sandboxed RSI
    Sandbox launch + result collection                :2027-02-01, 2027-03-01
    Signed hot-swap engine (Rust)                     :2027-03-01, 2027-04-01
    section Phase 5: Autonomous assistant
    OS control and voice                              :2027-04-01, 2027-06-01
```

---

## 📍 Phase 1: Python Research Prototype & Verification Lab (COMPLETE — exit gate closed 2026-10-07)
**Objective**: Build a working, testable prototype in Python to validate the 3-pillar concepts and the safety ideas before committing them to native compiled languages.

### Deliverables
- [x] Project scaffolding (`core/`, `hardware/`, `research/`, `docs/`).
- [x] `research/hardware_telemetry.py` — Windows `kernel32` + Linux `/proc`, RAM, CPU load, battery, single-source tier policy, JSON IPC form. *(Hardened 2026-10-05: no invented fallback values.)*
- [x] `research/network_pipeline.py` — direct HTTP(S) ingestion, Wikipedia search→summary (multi-language incl. Sinhala), DuckDuckGo fallback, typed errors.
- [x] `research/net_guard.py` — outbound URL policy (SSRF / `file://` protection). *(Added after review finding C1.)*
- [x] `research/raw_http.py` — experimental raw `socket`+`ssl` client modelling the Phase 2 Winsock design.
- [x] `research/data_verifier.py` — HTML-parser sanitiser, byte-safe truncation, Unicode-aware scoring, prompt-injection screening.
- [x] `research/secure_buffer.py`, `memory_probe.py` — wipe-and-verify purge primitive and RSS probe.
- [x] `research/reasoner.py` — `Reasoner` interface + honest stub.
- [x] `research/agent_core.py` — Perceive → Ingest → Reason → Purge with guaranteed purge (`finally`) and a measured `PurgeReport`.
- [x] `research/ast_guard.py` — RSI Tier-1 static gate prototype.
- [x] `research/benchmark.py` — purge benchmark that can actually fail.
- [x] `research/main.py` — interactive CLI + scriptable flags.
- [x] `research/tests/` — 170 unit tests at 2026-10-07 (stdlib `unittest`; 5 skipped on Windows).
- [x] Docs aligned with code; `THREAT_MODEL.md`, `PROJECT_REVIEW.md` added.
- [x] **Risk remediation (second pass)** — each risk has an ADR and tested code:
  - R1 `reasoner.py::LocalLLMReasoner` (ADR-001) · R2 `outbound_policy.py`, `local_knowledge.py` (ADR-002) · R3 claims lint `tests/test_claims.py`
  - R4 `ed25519_ref.py`, `updater.py`, `sign_release.py`, `docs/CONSTITUTION.md` (ADR-005) · R5 `sandbox_policy.py` (ADR-003)
  - R6 `conformance.py` + `conformance/*.json` golden vectors (ADR-004) · R7 `capabilities.py` + `context_tainted` (ADR-006)

### 🚦 Phase 1 Exit Criteria (gate to Phase 2)
All must be true before Phase 2 starts:
- [x] `python -m unittest discover -s tests` is green **on the Windows development machine** (170 tests at the 2026-10-07 check).
- [x] Live ingestion verified on Windows: `main.py --ask "Explain Rust ownership"` and `--lang si`, with both `--transport urllib` and `--transport raw`.
- [x] `main.py --benchmark` passes on Windows; RSS trend recorded in `PROJECT_REVIEW.md`.
- [x] Telemetry JSON schema v1 and the tier-policy table are frozen (they become the C++ daemon's conformance tests).
- [x] CI runs the test suite on Windows (GitHub Actions `windows-latest` run #37520707673 passed).
- [x] Owner confirms the default decisions D1–D4 (ADR-001…004 confirmed).
- [x] **Windows Sandbox smoke test** (ADR-003): verified 7/7 checks passed; recorded in `docs/evidence/sandbox_results.json`.
- [x] Run one real local model through `--model-url` and record RAM/latency per tier (ADR-001; Ollama 1B and 3B GPU offload measured).
- [x] Constitution text reviewed by the owner; signing key generated and public key placed in `research/trust.json` (ADR-005).

### Optional Phase 1 stretch (only if time remains)
- Benchmark two or three candidate local models (size/quantisation) against a small fixed evaluation set to choose the product-path model (ADR-001).
- Fuzz `DataVerifier` (random HTML, huge/unicode inputs) with the stdlib only.

---

## 📍 Phase 2: Native layers — Rust policy core (VS2 done), Rust safe-ingestion string primitives (Slice 1 done), Rust verify-loop & tagged value codec (Slice 2), Win32 telemetry (VS3), C++ probe (VS4)
_Status 2026-10-12: the Rust slice VS2 (tier + URL policy), Phase 2 Slice 1 (`core/src/ingest.rs` string-level safe-ingestion, secret-scanning with `re.ASCII` on all credential regexes, terminal/text/header sanitization, and cryptographic nonce-envelope primitives; file/folder traversal `ingest_file`, `ingest_folder`, and `assemble_untrusted_context` remain in Python `research/ingest.py`), and Phase 2 Slice 2 (`core/src/verify_loop.rs` tagged RPC value codec `encode_value`/`decode_value`/`decode_envelope_json`, constant-time HMAC-SHA256 verdict frame verification `verify_verdict_frame`, and bounded canonical example assertion extraction `extract_example_assertions`; subprocess orchestration, `ast_guard`, `prepare_test_suite`, and the repair loop remain in Python `research/verify_loop.py`) are implemented and verified against 200 tier vectors, 87 URL vectors, 113 ingest vectors, and 66 verify-loop vectors, 5,000+ case deterministic no-panic property tests in `ingest.rs` and `verify_loop.rs`, and multi-seed differential fuzzing (`--fuzz 10000` across 7 seeds `42`, `9001`, `1337`, `20261012`, `555`, `777`, `31337` — 43,330 cases per seed, 303,310 total cases, 0 mismatches, 0 panics)._

**Objective**: Native low-level Windows daemon for hardware telemetry (reduced C++ charter, ADR-004) and a time-boxed spike to confirm Rust as the network layer.

### Deliverables
- **Hardware Telemetry Daemon (`hardware/telemetry/`)**: Win32 (`GlobalMemoryStatusEx`, `GetSystemTimes`, `GetSystemPowerStatus`), PDH counters, NVIDIA NVML/CUDA/DXGI for GPU/NPU. Publishes **telemetry schema v1** (`ARCHITECTURE.md` §3.1) over `\\.\pipe\pai_telemetry` with an ACL limited to the current user.
- **Conformance**: the daemon must pass `research/conformance/tier_policy_vectors.json` (200 vectors) — a C++ runner for the golden files is part of the deliverable.
- **Memory-protection hooks**: `VirtualLock` for working buffers, disable Windows Error Reporting dumps for the engine process (threat T5).
- **Network spike (2 weeks, decision gate)**: Rust baseline (`hyper`/`rustls`) vs a minimal C++ Winsock/IOCP+TLS client on 100 sequential + 8 concurrent fetches. C++ is adopted only if it is ≥ 20 % better on p95 latency **and** ≥ 30 % lower on peak RSS **and** passes every URL-policy vector (87 at 2026-10-07) including IP pinning (ADR-004). Otherwise networking stays in Rust and the C++ network engine is dropped.

---

## 📍 Phase 3: High-Performance Rust Core Engine
**Objective**: Replace Python orchestration with a zero-cost, memory-safe compiled Rust engine.

### Entry decision: Reasoner strategy — **ADR-001 accepted (default)**
Adopt a local open-weights model behind the `Reasoner` interface (Option A); a custom architecture is a parallel research track that must beat the adopted model on a fixed evaluation to replace it (Option B). The Python `LocalLLMReasoner` already exercises the contract; owner to confirm and choose the model by 2026-11-10.

### Deliverables & Vertical Slices
- **Vertical Slice 2 (VS2), Phase 2 Slice 1 & Phase 2 Slice 2 — Stateless Core, Policy Conformance, String-Level Safe Ingestion & Verify-Loop Primitives**:
  - Pure Rust implementations of resource tier policy (`src/tier.rs`), outbound URL policy with Canonical Blocked CIDRs (`src/url_policy.rs`), Phase 2 Slice 1 string-level safe-ingestion primitives (`src/ingest.rs`; filesystem traversal `ingest_file`, `ingest_folder`, and `assemble_untrusted_context` remain in Python `research/ingest.py`), and Phase 2 Slice 2 verify-loop & tagged value codec primitives (`src/verify_loop.rs`: `encode_value`, `decode_value`, `decode_envelope_json`, constant-time HMAC-SHA256 `verify_verdict_frame`, and `extract_example_assertions`; subprocess orchestration, `ast_guard`, and the repair loop remain in Python `research/verify_loop.py`).
  - Zero unsafe code blocks (`unsafe = 0` in `tier.rs`, `url_policy.rs`, `ingest.rs`, and `verify_loop.rs` with `#![forbid(unsafe_code)]`), zero network or regex crate dependencies (strictly `serde` + `serde_json` + `std::net`).
  - Fake telemetry removed from skeleton per ADR-004.
  - Passes 200 tier vectors, 87 URL vectors, 113 ingest vectors + `limits`, and 66 verify-loop vectors + `codec_policy` parity check (`pai-core --conformance`).
  - Hardening found by independent review (commit `70fd7f6`): IPv6 transition/embedded-IPv4 prefixes (NAT64 `64:ff9b::/96`, `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/23`, IPv4-compatible `::/96`, SIIT, site-local `fec0::/10`) and `192.88.99.0/24` are blocked; leading-zero ports are rejected. Lesson recorded: a differential fuzzer proves two implementations agree, not that the shared policy table is complete — adversarial vectors from an independent source are required.
  - Multi-seed differential fuzz testing (`python research/conformance.py --fuzz 10000` across 7 seeds `42`, `9001`, `1337`, `20261012`, `555`, `777`, `31337`): 5,000 tier cases, 5,000 URL cases, 23,331 ingest cases, and 9,999 verify-loop cases (43,330 cases per seed; 303,310 total cases) compared with 0 mismatches and 0 panics between Python and Rust, plus 5,000+ case deterministic no-panic property tests in `core/src/ingest.rs` and `core/src/verify_loop.rs`.
  - Windows CI job verifying `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, and drift checking.
- **VS2 / Phase 2 Slices 1–2 Exit Criteria (Gate to VS3)**:
  - [x] Tier vectors (200), URL vectors (87), ingest vectors (113 + `limits`), and verify-loop vectors (66 + `codec_policy`) pass 100% in Rust (`pai-core --conformance`).
  - [x] Multi-seed differential fuzzer passes 43,330 cases per seed (5,000 tier + 5,000 URL + 23,331 ingest + 9,999 verify-loop) across 7 seeds (`42`, `9001`, `1337`, `20261012`, `555`, `777`, `31337`) with 0 mismatches and 0 panics.
  - [x] No `unsafe` blocks and no fake telemetry in Rust policy/ingest/verify-loop core.
  - [x] Windows CI workflow includes dedicated Rust job.
  - [x] `core/README.md` and `core/Cargo.lock` updated and committed.
- **Vertical Slice 3 (VS3) — Native telemetry first, then the full cycle in Rust** (entry decisions in ADR-009, proposed):
  - Step 3a: `core/src/win32.rs` is the only file allowed to contain `unsafe`; Rust readers must match the Python readers (available RAM within ±5 %, identical tier for identical inputs).
  - Step 3b onward as listed below.
  - Live OS telemetry via Win32 APIs (replacing Python `HardwareTelemetry`).
  - Direct Winsock / `hyper` + `rustls` network pipeline with IP pinning.
  - Local model reasoner integration behind `Reasoner` trait with pre-load headroom hysteresis.
- **Rust Cargo workspace (`core/Cargo.toml`)**: `pai-core`, `pai-telemetry-client`, `pai-network` (default: Rust networking).
- **Stateless Task Planner & Interpreter**: graph-based planner; Rust lifetimes ensure temporary data cannot outlive the reasoning scope.
- **Purge guarantees**: working buffers use the `zeroize` crate (guaranteed non-elided wipe) + `mlock`/`VirtualLock`; this replaces the Python prototype's best-effort purge.
- **Reasoner integration**: model runtime with dynamic precision switching (FP16 → INT8 → INT4) driven by the telemetry tier.
- **Safety plumbing**: `net_guard`/`outbound_policy`, injection screening and the **capability broker** (ADR-006) ported; reasoner receives untrusted context fenced and **without tool access** (threat T3).
- **FFI & IPC**: Rust ↔ C++ bridge; Python reduced to an optional research client.

---

## 📍 Phase 4: Sandboxed Recursive Self-Improvement (RSI)
**Objective**: Enable the AI to write, test, verify and upgrade its own code inside a physically isolated sandbox.

### Entry decision: Sandbox technology — **ADR-003 accepted (default)**
Windows Sandbox (networking disabled, one writable output folder) is primary; a Hyper-V VM without NIC is the fallback; Firecracker-in-WSL2 optional for Linux builds; containers alone are not acceptable. The isolation checklist already exists as code (`research/sandbox_policy.py`). **Gate:** a Windows smoke test must prove a probe inside the sandbox cannot reach the network or host files before any RSI code runs there.

### Deliverables
- **Isolation environment** per the ADR with automated compile + test pipeline and a complete network airgap.
- **Dual-Agent Auditor System**: Generator proposes; a separate Auditor fuzzes and red-teams.
- **Verification scope** (clarified): "formal verification" is applied to *narrow, specified properties* (memory bounds, forbidden API use, I/O contracts), combined with differential testing against the previous version — not to "all behaviour".
- **Signed Hot-Swap Engine (ADR-005)**: prototype in `research/updater.py` (Ed25519 manifest, per-file SHA-256, anti-rollback, pinned Constitution hash, atomic install, rollback). Remaining: run the updater under a separate Windows account with ACL-protected trust root, engine start-up check `trust_root_is_protected()`, key custody + rotation procedure, Rust port.
- Tier-0 (untrusted-input) and Tier-1 (AST guard, prototype in `research/ast_guard.py`) are production-hardened in Rust.

---

## 📍 Phase 5: Autonomous Personal Intelligence Integration
**Objective**: Turn the engine into a personal daily companion working natively within Windows.

### Deliverables
- **OS Control**: Windows UI Automation routed through the **capability broker** (`research/capabilities.py`, ADR-006: deny-by-default grants, taint-aware human confirmation, audit chain) — the main defence against prompt injection (T3) once the model has tools. Remaining: the confirmation UI and real tool adapters.
- **Voice & Ambient Awareness**: local speech-to-text (whisper.cpp) and low-latency responses.
- **Persistent Personal Knowledge Graph**: optional, encrypted local store for *user-approved* memory (explicit exception to statelessness, off by default).
- **Privacy controls**: implemented in Phase 1 (ADR-002) — extend with a GUI view of the outbound log.

---

## 🛤️ Track L: Local assistant `pai` (ADR-008) — runs in parallel with Phase 2/3
**Objective**: a simple local, stateless assistant that analyzes code, documents, web pages and business datasets (with forecasts) and writes and tests code. Full specification: [LOCAL_ASSISTANT_SPEC.md](LOCAL_ASSISTANT_SPEC.md).

| Milestone | Deliverable | Acceptance (summary) |
|-----------|-------------|----------------------|
| M1 | Model bake-off (`qwen2.5-coder:7b`/`1.5b`, `qwen3.5:4b`, `gemma4:e2b` vs `llama3.2:3b`) + `pai code` generate-only | Model cards (licence checked, hash, `host_delta_mb`, latency); frozen sets: 20 coding tasks (pass@1), 10 Singlish prompts, 10 document questions; thinking/truncation behaviour recorded |
| M1.1 | Bake-off hardening (subprocess runner, thinking control, frozen sets, re-measured RAM) | Done in `7795e7b` |
| M1.2 | Standardized RAM measurements & full 20-doc batch evaluation | Done (5-run cold median in `MEASUREMENT_PROCEDURE.md`, all 20 doc tasks scored, run metadata recorded, profiles reconciled with SPDX/HF cards) |
| M1.2 | Bake-off re-run with metadata, standard cold-RAM procedure, 20 document tasks | Done in `bcade6e`; open (M1.3): repeat runs with fixed seed for pass@1 variance, stricter document scoring, licence re-read on official cards |
| M1b | Adaptive model router (task class + machine condition → model, explained) | Done (research/router.py, 15 golden vectors pass, graceful degradation across equal RAM budgets, T21 defense, M1d cloud extensibility) |
| M1c | Portability: `pai setup/doctor/calibrate/models`, machine profile, user model allow-list | Conditionally accepted (research/pai.py CLI, doctor/calibrate/models/route, ADR-010 calibration, T22/T26 defenses, loopback/exact-match fixes, uncalibrated 1.5x rule on fresh machines, plausibility floor < 50%, auto live telemetry & foreign profile rejection, value secret scanning). Illustrative schema example moved to `docs/examples/example_machine_profile.json`; physical second-machine calibration acceptance item remains open pending WSL2 run (local host non-admin; Linux requirement met via GitHub Actions CI and reviewer Linux host). Canonical OS matching and strict expiration applied. |
| M1d | Optional cloud providers (ADR-010, proposed) | Mock-server tests: off by default, key never leaks, card hosts only, spend caps, `--offline`, content cannot enable cloud |
| M2a | Sandbox Runner & Capability Probe | Done — accepted by reviewer (M2a.4): Win32 AppContainer + Job Object and Linux bubblewrap runners, fail-closed behavioural probe, adversarial matrix A1-A11; Linux reproduced by reviewer (14 tests, 0 skips; matrix 10/10 on Ubuntu 22.04 / bwrap 0.6.1); Windows evidence owner-generated, not independently reproduced; carried item (A8 vacuous) resolved in M2b.1; WSL2 spec requirement met by CI + reviewer host |
| M2b | Verify loop & `pai code` | Complete & Frozen at `6218fbc`: H5 tagged RPC codec, H3 AST main-guard wrapping, H1 AST-allowlisted canonical example assertions, H6 specification-bounded test prompt, `--allow-unverified` staging (`solution.unverified.py`), and driver/worker HMAC-SHA256 hidden-test grading. Evaluated on 20 tuning tasks (English `8/20`, Singlish `6/20`, `0/42` mutants accepted) and one-shot 10-task holdouts (English `4/10` gated vs `5/10` gate-off [recall `4/5`], Singlish `3/10` [`3/8` excl. timeouts] gated vs `5/10` gate-off [recall `1/5` on the 5 gate-off-solvable tasks, plus `code_24` and `code_25` via repair loop where `code_25` rested on a weak suite accepting `code_25_mutant_2`]; `2/20` holdout mutants accepted, `2/62` overall). |
| M2c | Singlish bridge for `pai code` (owner idea 2026-10-08; adopted only if measured better) | **On Hold (Not Enabled — Known Limitation Recorded)** — Both the 20-task tuning set (`6/20` Singlish vs `8/20` English) and the 10-task holdout set (`1/5` vs `4/5` recall on the 5 gate-off-solvable tasks; `3/10` vs `4/10` overall, with `code_25` resting on a weak suite) show a gated acceptance gap in the same direction at small $N$ (neither proving nor excluding a Singlish effect). M2c remains on hold and this gap is recorded as a known limitation. |
| M3 | `pai analyze <folder>` | Complete — safe codebase analysis via `ingest.py`, unforgeable cryptographic nonce envelope (`--- UNTRUSTED DATA BEGIN [<nonce>] ---`), deterministic question-overlap context ranking (`_question_overlap_sort_key`, falling back to size order), content-based & filename secret rejection (`35` patterns + `scan_secret_content` covering token formats, embedded DB URL passwords, `AWS_SECRET_ACCESS_KEY`, quoted credential literals in code, and unquoted credential literals restricted to config files `.env/.ini/.cfg/.conf/.yaml/.yml/.toml/.properties`), structure/entry-point/dependency/risk extraction, fail-closed router refusal (exit 5), `test_pai_analyze_e2e.py`, and `4/4` pass on the keyword-match smoke test (`analyze_docs_questions.json` `ad_01`–`ad_04`). |
| M4 | `pai docs <file>` (txt/md/csv; PDF deferred with exit 3 pending ADR) | Complete — safe document ingestion via `ingest_file`, unforgeable cryptographic nonce envelope framing, CSV formula defense with numeric & lone sign empty marker preservation, export collision/source protection (exit 4, including hard link aliases via `os.path.samefile`), Python column profiling, hardened terminal sanitization (OSC/C1/bidi stripping), 14 e2e tests in `test_pai_docs_e2e.py`, and `4/4` pass on the keyword-match smoke test (`analyze_docs_questions.json` `ad_05`–`ad_08`). |
| M5 | `pai forecast` | Complete — deterministic Python backtested forecasting (`research/forecast_engine.py`: naive, seasonal naive, moving average, linear trend, Holt-Winters additive; rolling-origin sMAPE/MASE; residual intervals with explicit uncalibrated 2% floor disclosure; strict date/duplicate/gap/horizon validation; 4 frozen synthetic series; 18 unit/e2e tests; LLM explanation number verification `verify_forecast_explanation_numbers` with `MODEL_EXPLANATION_LABEL` and documented `0.15` absolute tolerance limitation — strict for large series, loose for series near `1.0`). Accepted by reviewer at `944f9cc` / `e71854c` / `0d0f553`. |
| M6 | Local web interface | loopback-only, token, Origin/Host checks tested (deferred per two-week compression plan) |
| M7 | ~~Singlish front-end~~ replaced (owner decision 2026-10-08): the interface stays English; no normalizer and no intent router. New scope: Singlish response-quality gate for models | **Complete (Automated Heuristic Gate Accepted by Owner)** — Frozen 25-prompt Singlish set (`research/eval_sets/singlish_quality_gate.json`: 5 agent-authored prompts per class across `code`, `analyze`, `docs`, `forecast`, `chat`) scored `0–2` via automated heuristic (required-facts keyword check + Singlish-reply detector; the owner accepted the automated heuristic scores in `docs/evidence/m7_hand_calibration_sample.json` rather than independently hand-scoring them). Router evaluates the **requested task class score** (`singlish_class_scores[task_class] >= 1.20`) and requires both a **passing quality check for that class** (`quality_checked_classes`) and a **verified licence** (`license_status == "verified"`): `qwen2.5-coder:7b` passes on `code` (`2.00`), `llama3.2:3b` (`chat: 2.00`, `Llama-3.2-Community`, relying on the automated heuristic scores) is preferred on Singlish `chat`, and unverified/unmeasured models (`qwen3.5:4b`, `gemma4:e2b`) are never auto-selected for `analyze`/`docs`/`forecast`. |

Every milestone needs: new tests (including hostile inputs), claims-lint green, CI green, and a threat-register update.

## 🛤️ Track M: Own model (gated research, ADR-008)
Budget: no paid cloud GPU. Stages: **0** bilingual tokenizer + 10–25M-parameter model on the laptop (learn the pipeline, no quality claim); **1** LoRA fine-tune of a small pretrained open base on verified self-play trajectories, scheduled only when the machine is idle on AC power; **2+** only if the promotion gate in ADR-008 is passed (beats the router baseline on frozen evaluations, safety suites not worse, signed release, rollback). Until then the router uses open-weights models and no claim is made that an "own" model exists.

---

## 🚀 Two-week compression plan (owner request 2026-10-08)

Goal: finish the Python assistant prototype's core in about two weeks without lowering the quality bar. Quality is protected by [DEFINITION_OF_DONE.md](DEFINITION_OF_DONE.md), not by extra review rounds. Reviewer estimate; the schedule depends on how many review rounds each report needs.

| Days | Work | Notes |
|---|---|---|
| 1-3 | M2b finish: hardening H1-H3, bounded repair loop, staging and `pai code --out`, eval with repeats | Security boundary: reviewed at each step |
| 4-6 | M3 `pai analyze`, M4 `pai docs` (txt/md/csv) | Share one safe-ingestion module (path escape, size caps, injection screening, secret files) written once |
| 5-8 | M5 `pai forecast` | Can run in parallel with M3/M4 by a second agent; independent module |
| 8-10 | M2c Singlish bridge, M7 Singlish quality gate | Reuse the M2b eval harness |
| 11-14 | Integration: one `pai` entry point, `pai doctor` end to end, final evidence, docs freeze | Python freeze, then the Rust-scope decision |

Deferred or reduced to fit: M1d cloud providers (design exists, build later), M6 local web interface (build only the minimal loopback server if time remains), PDF support, M1.3 leftovers except licence verification, second-machine calibration (needs the owner's second PC), Phases 3-5 and Track M. These are not cancelled; they come after the freeze.

Speed rules: one report per milestone, reviewer checks the whole milestone at once; independent milestones run in parallel; the agent self-checks against the Definition of Done before submitting.

---

## 🔭 Release 1.5.0 (planned, not committed): automation and creative generation

_Added 2026-10-23 at the owner's request. This section is a plan only. Nothing here starts until the 1.0.0 exit gate is closed. For this plan "1.0.0" is taken to mean: the Python core freeze, the Rust core as default (Release N) and removal of the Python fallback (Release N+1) are finished, and the owner has accepted the evidence. The owner may adjust that definition._

**Entry gate:** 1.0.0 closed; shadow-evaluation final report accepted; Finding BC telemetry fix merged; Finding AV completion confirmed by the owner.

**Guiding rule:** 1.5.0 adds optional capabilities around the core. It does not change the core's stateless design, its policies or its Constitution. Everything below is off by default and installable separately.

### A. Automation (n8n-style workflows) — integrate, do not rebuild
- PAI does not become a workflow engine. A visual editor, triggers, retries and a node library are a large product on their own and would pull the project away from its goal.
- PAI instead offers a stable machine interface that any orchestrator can call:
  - A1: freeze a versioned JSON output schema (`--json`) and documented exit codes for `code`, `analyze`, `docs`, `forecast`, `route`, `models` and `doctor`.
  - A2: optional `pai serve`: loopback-only (127.0.0.1) HTTP wrapper over the same commands, bearer token required, request size and rate caps, full audit log, no cloud-key access.
  - A3 (optional, small): `pai run recipe.json` for a fixed sequence of existing commands, with no loops or conditions. Anything more complex is left to an external orchestrator.
- n8n (self-hosted), Windows Task Scheduler or similar tools may call PAI through the command line or the loopback API. They are separate programs installed by the user. PAI does not bundle or redistribute them. The n8n licence is "fair-code" (Sustainable Use License, not an OSI open-source licence), so its terms must be re-read at adoption time.
- Safety rules: text that arrives through a workflow is untrusted data and never instructions (Constitution rule 2). A workflow cannot enable capabilities that the capability broker denies. Credentials stay inside the orchestrator and PAI never reads them. Scheduling state lives in the orchestrator, so PAI stays stateless.

### B. Image generation (optional local backend)
- `pai image` is an optional capability that talks to a local image backend through a loopback adapter, the same pattern used for local LLMs. The backend and the image model are chosen by the user. The core contains no model weights.
- Model supply chain (extends R12): each image model needs a model card with licence, SHA-256, VRAM and RAM measurements, and an explicit allow-list entry. Licences differ widely (permissive, community licences with revenue limits, non-commercial). Whether a licence permits the planned use, including commercial use, is checked per model at selection time and recorded. Do not assume a model labelled "open" permits commercial use.
- Resource policy: image models need much more GPU memory than the small language models. The router and telemetry tiers must refuse or degrade (smaller size, CPU fallback with a slow-path warning) instead of exhausting memory.
- Reproducibility: every output has a sidecar JSON with model hash, seed, sampler, parameters and prompt, so a result can be regenerated and audited.
- Output is written only to a user-chosen folder, with the same path-escape and size caps as `ingest`. Prompts taken from untrusted documents cannot trigger generation on their own.

### C. NFT-style collection generation (assets and metadata only)
- C1, deterministic layered composition: seeded combination of trait layers (PNG) with rarity weights, duplicate detection by content digest, a rarity report, and a manifest. This needs no image model.
- C2, model-assisted traits: the image backend from section B produces trait layers or base styles, which C1 then composes.
- C3, metadata export: one JSON file per item in the common marketplace layout (`name`, `description`, `image`, `attributes` as `trait_type`/`value`), plus a collection manifest with hashes.
- **Hard boundary:** PAI produces files only. It never holds wallet keys or seed phrases, never signs or sends transactions, never mints, and never uploads to marketplaces or storage networks. Those steps are done by the user in their own tools, with a human confirming each irreversible action.
- Legal and policy notes (not legal advice): copyright protection for purely AI-generated images varies by jurisdiction and may be limited; marketplaces have their own rules about AI-generated work; generating copies of existing collections, artists' styles claimed as their own, or branded characters is out of scope. The user is responsible for rights and for marketplace compliance, and the documentation must say so plainly.

### Milestones and acceptance (each also needs the normal Definition of Done)
| Milestone | Deliverable | Acceptance (summary) |
|---|---|---|
| 1.5-A1 | Frozen `--json` schemas and exit codes | Schema tests, golden vectors, backward-compatibility check |
| 1.5-A2 | `pai serve` loopback API | Binds loopback only, token required, hostile-input tests (oversize, malformed, path escape), audit log, threat-register entry |
| 1.5-A3 | Optional `pai run recipe.json` | Fixed sequence only, each step goes through the same policies as the CLI |
| 1.5-B1 | Image backend adapter, model cards, `pai image` | Licence and hash recorded, VRAM refusal tests, sidecar reproducibility test, no network except the loopback backend |
| 1.5-C1/C3 | Layer composer and metadata export | Same seed gives identical output, duplicates detected, manifest hashes verified, no key or wallet code present |
| 1.5-C2 | Model-assisted traits | Works only with allow-listed, licence-checked models; end-to-end sample collection with evidence |

**Order:** A1, A2, then B1, C1, C3, then C2 and A3. A is small and gives the owner the "automate my work" ability early. B and C depend on the machine available for testing (GPU), so their schedule is set after the first image model is measured.

**Out of scope for 1.5.0:** minting, wallet or marketplace integration, auto-posting, and hosted image APIs. A hosted image provider could be considered later under the same user-held-key pattern as ADR-010.

**New risks to register at 1.5.0 entry:** R13 workflow input treated as instructions; R14 image model licence or provenance misuse; R15 resource exhaustion from image generation; R16 users relying on generated assets without checking rights.

---

## 🔮 Future track (not scheduled): inference runtime and accelerators

Proposed in [ADR-012](adr/ADR-012-inference-runtime-strategy.md), 2026-10-23. Today the model is served by Ollama behind the `Reasoner` interface, on CPU and the NVIDIA GPU; the laptop's NPU is not used and not yet detected. The future plan: an NPU probe (VS4), then backend adapters (llama.cpp first), then a PAI-owned `pai runtime` manager, and an NPU backend only if measurements show a benefit. No custom inference kernels are planned. Nothing starts before 1.0.0 is closed.

---

## 📦 Packaging and first-run setup (planned, not scheduled)

Proposed in [ADR-013](adr/ADR-013-installer-and-distribution.md) and specified in [PACKAGING_SPEC.md](PACKAGING_SPEC.md), 2026-10-27: a single Inno Setup installer with an agreement page, `pai` on the user's PATH, the Ollama server as a verified prerequisite, and hardware-aware model selection from a signed catalog with a download progress bar. Milestones P1 to P5 live in `packaging/` and `tools/` and do not touch `research/` or `core/` while the N+1 window is open; P6 (moving the wizard into `pai setup`) follows the N+1 review. Planned as release **1.1.0** (after 1.0.0 and before 1.5.0); preview builds are tagged `v1.1.0-rcN`. See section 13 of the spec. Section 14 adds a PowerShell one-line install (an extra front door next to the installer, proposed for 1.1.0) and a Linux installer (proposed as release 1.2.0, labelled preview until a Linux evaluation is recorded).

---

## 💬 Interactive Shell and Managed Service (planned, post-N+1 window)

Proposed in [ADR-014](adr/ADR-014-interactive-shell-and-managed-ollama.md), 2026-10-27: an interactive terminal REPL launched by running `pai` without arguments (when `isatty` is true) with slash commands dispatching directly to existing canonical subcommands (`/analyze`, `/code`, `/docs`, `/forecast`, `/doctor`, `/chat`, `/help`, `/exit`), coupled with managed loopback startup of the local Ollama daemon. The managed starter checks the official per-user path, enforces Authenticode signature verification, never searches PATH, binds strictly to loopback (`127.0.0.1`), prompts for user consent, and tracks child process lifetime so only PAI-initiated servers are stopped on exit. Designed as a post-N+1 window deliverable built across two separately reviewed commits (service management first, shell second) with zero changes to `research/` or `core/` during the evaluation window.

---

## ⚠️ Roadmap Risks (status after the second review pass)

| ID | Risk | Status | Where handled |
|----|------|--------|---------------|
| R1 | Reasoning core size/capability unknown | **Mitigated**: adopt local model; research track separate | ADR-001, `LocalLLMReasoner` |
| R2 | Network queries conflict with "private/local" goal | **Mitigated**: allow-list, visible log, offline, local knowledge | ADR-002 |
| R3 | Absolute-security claims | **Closed**: policy + automatic lint | `THREAT_MODEL.md` §5, `test_claims.py` |
| R4 | "ROM constitution hash" defeatable | **Mitigated (prototype)**: external signing + separate updater | ADR-005 |
| R5 | Firecracker unavailable on Windows | **Decided (default)**: Windows Sandbox (smoke test verified 7/7, `docs/evidence/sandbox_results.json`) | ADR-003 |
| R6 | Three languages, one developer | **Mitigated**: Rust-first networking, C++ reduced, vertical slices, golden vectors | ADR-004 |
| R7 | Prompt injection once the model has tools | **Mitigated (prototype)**: capability broker + taint | ADR-006 |
| R8 | Small local models give wrong answers/code (observed with 1B and 3B) | **Planned mitigation**: verify loop with tests, frozen baselines, grounding checks, no unmeasured quality claims | ADR-008, M1–M2 |
| R9 | Self-training poisons or memorizes data; a bad model regresses the system | **Designed**: self-play data, tainted trajectories excluded, hardware-aware scheduling, promotion gate with rollback | ADR-008, T18 |
| R10 | Untrusted local files and documents (injection, path escape, secrets) | **Planned**: M3/M4 controls and tests | LOCAL_ASSISTANT_SPEC, T15 |
| R11 | Forecasts read as certainties | **Planned**: code-computed numbers, backtest error and intervals shown, refusal on thin data | LOCAL_ASSISTANT_SPEC §M5, T19 |
| R12 | Model supply chain and licences | **Planned**: model cards (licence, SHA-256), explicit allow-list of models | ADR-008, T20 |

Phase 1 exit items are all closed (evidence: `docs/evidence/sandbox_results.json`, `research/model_profiles.json`, CI runs). Open owner decisions: confirm ADR-009 (Rust `unsafe` boundary and toolchains) and the model licences chosen in M1.
