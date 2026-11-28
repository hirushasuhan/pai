# System Architecture Specification

## 1. Architectural Philosophy

Traditional Deep Learning models conflate **cognitive processing** with **factual memorization**. A 70-billion-parameter model allocates 90%+ of its parameter weights to storing trivia, historical dates, and encyclopedic facts. This leads to massive binary footprints (50GB - 140GB+), high memory overhead, rapid factual obsolescence, and continuous hallucination risks.

**Personal Agentic AI (PAI)** decouples reasoning from storage:
* **The Brain (Pure Reasoning Engine)**: Focuses on algorithmic structure, syntax comprehension, logic deduction, task decomposition, and code synthesis.
* **The Senses (Safe Ingestion Pipeline)**: Live real-time ingestion from network endpoints and local storage, filtered by strict URL policies and framed inside cryptographic nonce envelopes.
* **The Organism (Hardware Awareness Layer)**: Continuous introspection of physical host resources (CPU, RAM, VRAM, Battery) to modulate reasoning depth, manage context budgets, and prevent system resource exhaustion.

```mermaid
graph TD
    subgraph Hardware & OS Telemetry [Python ctypes & Win32]
        HW[Host Hardware: CPU, RAM, VRAM, Battery]
        TELEMETRY[Telemetry Engine: GlobalMemoryStatusEx / GetSystemTimes / /proc]
        MEM_OPT[Memory Optimizer: EmptyWorkingSet / Memory Pressure Monitor]
        HW <-->|Query Metrics| TELEMETRY
        TELEMETRY --> MEM_OPT
    end

    subgraph Desktop Shell & Loopback Bridge [Tauri 2.0 Rust & Python Daemon]
        DESKTOP[Native Desktop Shell: pai-desktop.exe]
        BRIDGE[Bridge Server on 127.0.0.1 with X-PAI-Token]
        DESKTOP <-->|HTTP / SSE| BRIDGE
    end

    subgraph Core Policy & Verification [Rust Core]
        POLICY[URL & Tier Policies: url_policy.rs / tier.rs]
        VERIFY_CODEC[Verify-Loop Framing: HMAC Verdicts & Tagged Codec]
        INGEST_RUST[Secret Scanning & Sanitization: ingest.rs]
    end

    subgraph Execution & Ingestion Engine [Python Research Modules]
        PLANNER[Task Planner & Reasoning Engine]
        INGEST[Safe Ingestion: net_guard.py & Nonce Envelope]
        VERIFY_LOOP[Sandboxed Code Verification: AppContainer / Bubblewrap]
        REASONER[Local Inference: Ollama & C++ Sidecars llama-server / sd-cli]
        
        BRIDGE --> PLANNER
        PLANNER --> INGEST
        PLANNER --> REASONER
        PLANNER --> VERIFY_LOOP
        BRIDGE <-->|JSON stdin/stdout| POLICY
    end
```

---

## 2. Component Specifications

### 2.1 The Policy & Verification Core (`core/` - Rust)
* **Language**: Rust (2021 Edition).
* **Guarantees**: Memory safety without a garbage collector (GC), deterministic latency, data-race freedom across multi-threaded executor pools.
* **Responsibilities**:
  * **Resource Tier Policy (`src/tier.rs`)**: Evaluates host telemetry to assign compute tiers (`HIGH`, `BALANCED`, `COMPRESSED`).
  * **Outbound URL Policy (`src/url_policy.rs`)**: Validates destination URLs against canonical blocked CIDRs, loopback escapes, and protocol smuggling.
  * **Safe Ingestion Primitives (`src/ingest.rs`)**: High-performance secret scanning (`re.ASCII`), credential pattern matching, terminal escape stripping, and nonce envelope framing.
  * **Verify-Loop Framing (`src/verify_loop.rs`)**: Tagged RPC value codec, HMAC-SHA256 verdict frame verification, and canonical assertion extraction.

### 2.2 Hardware Self-Awareness & Telemetry Subsystem (Python / Win32 / Linux)
* **Implementation**: `research/hardware_telemetry.py`, `research/memory_optimizer.py`, `research/memory_probe.py`, and `core/src/win32.rs`.
* **OS Target**: Windows (Win32 API via `ctypes`: `kernel32.GlobalMemoryStatusEx`, `GetSystemTimes`, `GetSystemPowerStatus`) and Linux (`/proc/meminfo`, `/proc/stat`, `/sys/class/power_supply`).
* **Telemetry Metrics Monitored**:
  * Total & Available Physical RAM (bytes).
  * System-wide CPU load percentage & per-core thermal headroom.
  * GPU Core utilization, VRAM allocation, and temperature.
  * Battery status (AC connected vs discharge rate).
* **Adaptive Control Policies**:
  * **Tier policy**: `COMPRESSED` when available RAM < 512 MB or load >= 90 % (emergency compression, clamps context budget); `BALANCED` below 2048 MB or load >= 75 %; otherwise `HIGH`.
  * **Memory Optimization**: Leverages Win32 `EmptyWorkingSet` to trim working sets of PAI-owned processes and child sidecars during model switching or memory pressure.

### 2.3 Safe Ingestion & Network Pipeline (Python & Rust)
* **Core Principle**: Secure HTTP(S) data fetching with strict SSRF defense, data sanitization, and cryptographic nonce isolation.
* **Modules**: `research/ingest.py`, `research/net_guard.py`, `core/src/url_policy.rs`, and `core/src/ingest.rs`.
* **Pipeline Stages**:
  1. **Destination Validation**: `net_guard` validates destination URLs against blocklists, RFC 1918 private CIDRs, cloud metadata (`169.254.169.254`), and non-HTTP schemes.
  2. **Streaming Parse & Sanitization**: Strips executable scripts (`<script>`, inline JS), terminal escape codes, bidirectional overrides, and CSV formula characters (`=`, `+`, `-`, `@`).
  3. **Secret Pattern Screening**: Filters 35+ credential and API key patterns via `scan_secret_content`.
  4. **Cryptographic Nonce Framing**: Encapsulates external untrusted data inside random per-task nonces (`--- UNTRUSTED DATA BEGIN [<nonce>] ---`) so the reasoner treats it strictly as data, not instructions.

---

## 3. Inter-Process Communication (IPC) Architecture

The multi-tier system communicates across local boundaries:

```
[ Tauri 2.0 (Rust) ] <─── Local HTTP / SSE (127.0.0.1, X-PAI-Token) ───> [ Bridge Server (Python) ]
                                                                                   │
                                         ┌─────────────────────────────────────────┴───────────────────────┐
                                         ▼                                                                 ▼
                    [ Rust Policy Core (pai-core) ]                                            [ Local Sidecars / Ollama ]
                    (JSON stdin/stdout subprocess)                                             (Loopback HTTP 127.0.0.1:11435)
```

1. **Tauri Shell $\leftrightarrow$ Bridge Server**:
   * Uses local HTTP and Server-Sent Events (SSE) bound strictly to `127.0.0.1` on a dynamic port.
   * Authenticated per session using the `X-PAI-Token` header.
2. **Python $\leftrightarrow$ Rust Policy Core Boundary**:
   * Python modules interface with `pai-core.exe` via standardized JSON-RPC over Standard I/O (stdin/stdout) with graceful fallback (`PAI_RUST_FALLBACK_PYTHON=1`).
3. **Bridge Server $\leftrightarrow$ Local Sidecars**:
   * Communicates with isolated child inference processes (`llama-server`, `sd-cli`) over loopback HTTP (`127.0.0.1:11435`).

---

### 3.1 Telemetry IPC schema v1 (frozen at Phase 1 exit)

The telemetry subsystem emits this standardized JSON object via `HardwareTelemetry.to_ipc_dict()` / `main.py --telemetry --json`:

```jsonc
{
  "schema_version": 1,
  "timestamp": 1791222978.77,          // seconds since epoch (float)
  "source": "win32-kernel32",          // win32-kernel32 | linux-procfs | psutil | unavailable
  "platform": "win32",
  "cpu_cores": 8,
  "cpu_load_pct": 23.5,                // null if unavailable
  "total_ram_gb": 15.9,                // null if unavailable (never invented)
  "avail_ram_gb": 6.2,
  "avail_ram_mb": 6348.8,
  "memory_load_pct": 61,
  "battery": { "percent": 80, "on_ac": true },   // null on desktops
  "budget": {
    "compute_tier": "HIGH",            // HIGH | BALANCED | COMPRESSED
    "max_context_bytes": 67108864,
    "allow_speculation": true,
    "thread_pool_limit": 8,
    "throttle_warning": "Normal operation. High performance tier enabled.",
    "reasons": []                      // e.g. ["memory-pressure","low-battery","cpu-saturated"]
  }
}
```

Rules: unknown values are `null`, never guessed; consumers must treat `source == "unavailable"` as BALANCED; any breaking change increments `schema_version`.

---

## 4. The Working Memory Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as Desktop Workstation (Tauri)
    participant Bridge as Bridge Server (Python)
    participant Telemetry as Telemetry & Memory (Win32)
    participant Ingest as Safe Ingestion (net_guard)
    participant Model as Local Inference (Ollama / Sidecars)
    participant Memory as Working Memory (RAM)

    User->>UI: Submit User Request
    UI->>Bridge: HTTP/SSE with X-PAI-Token
    Bridge->>Telemetry: Query Host Resource Budget
    Telemetry-->>Bridge: Returns Budget (e.g. BALANCED, Context Cap)
    Bridge->>Ingest: Fetch & Sanitize Untrusted Knowledge
    Ingest-->>Memory: Stream Nonce-Framed Context
    Bridge->>Model: Query Model (Local / Sidecar)
    Model-->>Memory: Synthesize Response
    Memory-->>UI: Stream Final Response
    Bridge->>Memory: Memory Purge & Working Set Trim (EmptyWorkingSet)
    Note over Memory: Ephemeral buffers zeroized and verified
```

---

## 5. Prototype vs Production Guarantees

| Property | Python prototype (Phase 1) | Production target |
|----------|----------------------------|-------------------|
| Buffers zeroed after task | Yes for `SecureBuffer` (memset + verified); **not** for `str` copies | All working memory (Rust `zeroize`, RAII) |
| Purge on error paths | Yes (`finally`) | Yes (Drop guards) |
| Pagefile / crash-dump exposure | Not handled | `VirtualLock`, dump control (Phase 2/3) |
| Outbound URL policy | `net_guard` (urllib: DNS re-resolved; raw: IP pinned); same table in Rust (`url_policy.rs`, conformance-tested) | Native client with IP pinning (VS3) |
| Reasoner | Stub (`TemplateReasoner`) or a local open-weights model through `LocalLLMReasoner`; symbolic engine is experimental | Router over verified models behind the same trait (ADR-008) |
| Telemetry | Polled in-process | 100 Hz push from daemon |

## 6. Privacy Note

Fetching knowledge from Wikipedia/DuckDuckGo reveals the user's topics to those services. Controls (ADR-002, implemented): domain allow-list, a visible outbound-request log showing the exact URLs sent, offline mode, and local-first knowledge from the user's own files. The product goal is therefore *local inference with minimal, visible, user-controlled outbound traffic*.

## 7. Cross-Cutting Safety Components

| Concern | Component | ADR |
|---------|-----------|-----|
| Untrusted data → instructions | `DataVerifier` screening + fenced context + `ToolBroker` taint rules | 006 |
| Self-update trust | External Ed25519 signing, separate updater, pinned Constitution hash | 005 |
| Code-execution isolation | Windows Sandbox checklist as code, hostile-output reader | 003 |
| Cross-language correctness | Golden conformance vectors | 004 |

## 8. Layering of the Local Assistant (ADR-008, Implemented)

```
 User ──► CLI / Shell / Tauri Desktop Workstation        (L1, own code)
              │
              ▼
        Planner + tool broker + verify loop                (L1, own code: AST guard → restricted runner → repair)
              │                    ▲
              ▼                    │ test results, evidence
        Reasoner interface ──► open-weights models         (L2, replaceable, model cards + licences)
              │
              ▼
        Memory purge ──► output only to the user-chosen folder

 Own-model research (L3): self-play data → fine-tune → promotion gate (ADR-008) → signed release (ADR-005)
```

Principles: the model is replaceable; numbers come from tested code; every input channel (files, documents, web, data sets, local web page) has a threat-register entry and tests; training never touches private data without explicit opt-in; no automatic weight update bypasses the promotion gate. Details: [LOCAL_ASSISTANT_SPEC.md](LOCAL_ASSISTANT_SPEC.md).

---

## 9. Native Desktop Workstation Architecture (v1.2.0 – v1.5.1)

The desktop application provides a standalone, native Windows workstation environment decoupling user interaction from external browsers:

```mermaid
graph TD
    subgraph Native Shell [Tauri 2.0 + Rust]
        EXE[pai-desktop.exe]
        WEBVIEW[Windows WebView2 Runtime]
        ASSETS[Embedded UI Assets: HTML / CSS / JS]
        EXE --> WEBVIEW
        ASSETS --> WEBVIEW
    end

    subgraph Local Bridge Subsystem [Python Daemon]
        BRIDGE[bridge_server.py on 127.0.0.1:port]
        TOKEN[Per-Session X-PAI-Token Auth]
        PICKER[Native Folder Picker: pai_folder_picker.exe]
        UIA[UI Automation Agent: pai_ui_agent.cs]
        BRIDGE --> TOKEN
        BRIDGE --> PICKER
        BRIDGE --> UIA
    end

    subgraph Local Inference & Sidecars
        OLLAMA[Managed Ollama Service on 127.0.0.1:11434]
        SIDECAR[Local Sidecars on 127.0.0.1:11435: llama-server, sd-cli]
    end

    WEBVIEW <-->|HTTP / SSE with X-PAI-Token| BRIDGE
    BRIDGE <-->|Loopback HTTP| OLLAMA
    BRIDGE <-->|Loopback HTTP| SIDECAR
```

### 9.1 Desktop Components
* **Tauri 2.0 Shell (`desktop/src-tauri/`)**: Standalone binary (`pai-desktop.exe`) orchestrating the workstation lifecycle and hosting frontend assets under a strict Content Security Policy (CSP).
* **Python Loopback Bridge (`desktop/bridge_server.py`)**: Headless daemon launched on a loopback interface (`127.0.0.1`) using a dynamically assigned port and authenticated via a per-session `X-PAI-Token` header.
* **Native Win32 Dialogs (`desktop/bin/pai_folder_picker.cs`)**: Compiled C# helper invoking Win32 `IFileOpenDialog` (`FOS_PICKFOLDERS`), preventing console flicker during directory selection.
* **UI Automation Agent (`desktop/bin/pai_ui_agent.cs`)**: Native driver exposing Windows UI Automation accessibility trees for desktop automation tasks.

---

## 10. Local Sidecar & Inference Runtime Architecture

To support inference beyond Ollama without introducing external server dependencies, PAI manages native sidecar processes:

```
[ bridge_server.py ] ──► Gate 1: Storage & Tool Verification
                            │
                            ▼
                         Gate 3: RAM / VRAM Pre-Load Check
                            │
                            ▼
                         Spawn Child Process (shell=False, loopback 127.0.0.1:11435)
                            ├── llama-server (llama.cpp GGUF inference)
                            └── sd-cli / sd.cpp (local image synthesis)
                            │
                            ▼
                         Idle Reaper: Terminate after 300s of inactivity
```

* **Process Isolation**: Sidecars are executed via `research/local_sidecars.py` with `shell=False`, strict loopback binding (`127.0.0.1:11435`), and absolute path pinning (`~/.pai/bin/` or `%LOCALAPPDATA%\Programs\`). PATH lookups and symlinks are rejected.
* **Admission Control**:
  * **Gate 1**: Verifies binary presence, executable integrity, and disk storage headroom.
  * **Gate 3**: Computes real-time RAM/VRAM requirements, calculates 64-layer offloading thresholds, enforces CPU offload for FLUX weights where VRAM is constrained, and auto-reaps idle runtimes after 300 seconds.
* **Sidecar Installer (`research/sidecar_installer.py`)**: Safe asset retrieval restricted to allowlisted GitHub and HuggingFace hosts, enforcing SHA-256 checks, zip-slip path traversal guards, and archive volume limits (512 MiB maximum).

---

## 11. Memory Optimizer & Hardware Pressure Engine

The memory subsystem (`research/memory_optimizer.py`, `research/memory_probe.py`) prevents resource exhaustion during heavy reasoning workloads:

* **Hardware Monitoring**: Real-time evaluation of host RAM pressure, VRAM availability, and system-wide CPU loads.
* **Working Set Trimming**: Leverages Win32 `EmptyWorkingSet` to trim working sets of PAI-owned processes and sidecar child processes during state transitions.
* **Adaptive Context Window Budgeting**: Computes token allocation limits dynamically (`COMPRESSED` $\le 4096$, `BALANCED` $\le 8192$, `HIGH` $\le 32768$), guarding against runtime out-of-memory faults.

---

## 12. Deep Reasoning & Stuck-Recovery Cowork

PAI implements structured reasoning and long-horizon task stability:

* **Deep Reasoning Engine (`research/deep_reasoning.py`)**:
  * Executes radial tree-of-thought exploration with step-by-step reflection loops.
  * Visualizes reasoning trees and branch pruning via the workstation thought inspector.
  * Sanitizes thought graph nodes to prevent token or secret leakage into persistence stores.
* **Stuck-Recovery Cowork Watchdog (`research/cowork.py`)**:
  * Tracks loop repetition counts, tool failure rates, and heartbeat timeouts via `StuckDetectorWatchdog`.
  * Automatically rolls back execution state to checkpointed valid branches upon detecting stalling (maximum 3 recovery attempts).
  * Enforces objective solution quality verification (`verify_task_quality`).

---

## 13. Model Context Protocol (MCP) Hub & Plugin Ecosystem

The tool execution boundary (`research/mcp_hub.py`, `research/mcp_client.py`, `research/plugin_manager.py`) coordinates multi-agent tool execution:

* **Transport Layer**: Supports both standard I/O (STDIO) subprocesses and Streamable HTTP/SSE remote transports.
* **Credential Vaulting**: Leverages `MCPVaultManager` with Windows DPAPI (`CryptProtectData`) to encrypt sensitive integration tokens at rest under `~/.pai/mcp_vault.json`. Plaintext keys are never stored in server configurations.
* **Tool Firewall & Schema Screening**:
  * `PluginScanner` checks incoming plugins and skills for instruction-override patterns, unpinned dependencies, and private network SSRF targets.
  * `ToolFirewall` redacts sensitive tokens, strips prompt-injection markers from tool responses, and blocks suspicious credential-harvesting `elicitation` forms.
* **Context Engine (`research/context_engine.py`)**: Implements observation masking, semantic sliding windows, and token budgeting across multi-step agent interactions.

---

## 14. Complete Offline Air-Gap Mode

To protect user confidentiality during sensitive local operations:

* **Network Boundary Enforcement**: When air-gap mode is active (`AIRGAP_OFFLINE`), `desktop/bridge_server.py` and `research/outbound_policy.py` block all non-loopback network connections.
* **Fail-Closed Gate**: Cloud provider endpoints and remote MCP services fail closed immediately, ensuring all inference, memory management, and code execution remain strictly on the local machine.

---

## 15. Software Auto-Updater Architecture

The update subsystem ensures cryptographically validated, non-disruptive software maintenance:

* **Update Verification**: `desktop/bridge_server.py` and `desktop/apply_pending_update.py` verify release manifests, validate SHA-256 digests against GitHub release assets, and enforce strict non-downgrade SemVer rules.
* **Background Staging**: Update archives are downloaded in the background with user controls (pause, resume, cancel) and staged under a dedicated update directory.
* **Atomic Applicator**: Updates are applied on application shutdown or restart using atomic directory swaps and rollback safety mechanisms.
