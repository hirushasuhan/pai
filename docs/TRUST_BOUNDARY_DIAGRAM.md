# Trust Boundary Diagram & Inventory

> **Living Security Architecture Document (synced 2026-11-26)**
>
> **Mandatory Maintenance Rule (see [AGENTS.md](../AGENTS.md)):** Whenever any feature, HTTP route, Tauri command, CLI subcommand, IPC channel, network integration, model/cloud provider, MCP server/plugin, automation target, persistent store, or sandbox/updater path is added, modified, or removed, this document and [STRIDE_THREAT_MODEL.md](STRIDE_THREAT_MODEL.md) **must be updated in the same change**.

---

## 1. End-to-End System Trust Boundaries

PAI follows a *defense in depth* architecture separating untrusted inputs, local orchestration, isolated execution, persistent local storage, and the offline-signed trust root. Every guarantee is tied to a named test or a named residual risk in [THREAT_MODEL.md](THREAT_MODEL.md) and [STRIDE_THREAT_MODEL.md](STRIDE_THREAT_MODEL.md).

```mermaid
flowchart TB
    subgraph Z_EXT["External Untrusted Zone"]
        WEB["Public Web / Search / Open-Meteo / Wikipedia"]
        GH["GitHub Releases API and Assets"]
        CLOUD["3rd-Party Cloud AI APIs and Custom Endpoints"]
        EXT_MCP["External MCP Servers (HTTP / STDIO)"]
    end

    subgraph Z_INPUT["Untrusted Local Content and Code Zone"]
        LOCAL_FILES["User Folders, Docs, CSVs, Workspaces"]
        GEN_CODE["Model-Generated Code and Repair Patches"]
    end

    subgraph Z_DESKTOP["Desktop Workstation Shell (Local Loopback)"]
        UI["PAI Studio Frontend (desktop/ui, strict CSP)"]
        TAURI["Tauri 2.0 Shell (pai-desktop.exe)"]
        BRIDGE["Python Bridge Server (127.0.0.1:dynamic_port + X-PAI-Token)"]
        PICKER["Win32 Folder Picker (pai_folder_picker.exe)"]
    end

    subgraph Z_CORE["Core Orchestration and Policy Enforcement"]
        LAUNCHER["Native Launcher (launcher.c / pai.exe)"]
        CLI["PAI CLI and REPL (pai.py / shell.py)"]
        NET_GUARD["Net Guard and Outbound Policy (net_guard.py / url_policy.rs)"]
        INGEST["Ingestion, Secret Scanner and Nonce Envelope (ingest.py / ingest.rs)"]
        RUST_CORE["Rust Policy Core (pai-core --bridge)"]
        ROUTER["Model Router and Config Validator (router.py / config.py)"]
        BROKER["Capability Broker and Audit Chain (capabilities.py)"]
        PURGE["Stateless Purge Controller (secure_buffer.py)"]
    end

    subgraph Z_EXEC["Isolated Execution and Local Inference Zone"]
        OLLAMA["Local Ollama Server (127.0.0.1:11434 via ServiceManager)"]
        SANDBOX["Tier-2 OS Sandbox (AppContainer / Bubblewrap / Windows Sandbox)"]
        AUTO_OS["Desktop Automation and Antigravity Driver (ToolBroker Gated)"]
    end

    subgraph Z_STORE["Host Local Persistence (~/.pai and App Install)"]
        MEM_STORE["Auto-Memory, Cowork Tasks, Chat Sessions (Secret-Scanned)"]
        KEY_STORE["Cloud Keys (DPAPI Encrypted at Rest) and Configs"]
        TRUST_ROOT["Trust Root (research/trust.json, CONSTITUTION.md, Updater)"]
    end

    %% Boundary crossings
    WEB <-->|"B2: HTTP(S) / Raw Socket"| NET_GUARD
    NET_GUARD -->|"B2: Sanitized Payload"| INGEST
    LOCAL_FILES -->|"B3: Realpath + Secret Scan"| INGEST
    INGEST -->|"B3: Fenced Nonce Context"| CLI
    INGEST -->|"B3: Fenced Nonce Context"| BRIDGE

    UI <-->|"B1: IPC / WebView (Strict CSP)"| TAURI
    UI <-->|"B1: HTTP + X-PAI-Token on 127.0.0.1:dynamic_port"| BRIDGE
    BRIDGE -->|"B1: Subprocess"| PICKER
    LAUNCHER -->|"B4: BCrypt SHA-256 + Clean Env"| CLI
    CLI <-->|"B4: JSON stdin/stdout"| RUST_CORE
    BRIDGE <-->|"B4: Policy Checks"| RUST_CORE

    ROUTER -->|"B5: Loopback Only + Allow-List"| OLLAMA
    BRIDGE -->|"B5: Loopback via ServiceManager"| OLLAMA
    CLI -->|"B5: Explicit Cloud Routing"| CLOUD
    BRIDGE -->|"B5: Cloud Pool / Net Guard SSRF Guard"| CLOUD

    GEN_CODE -->|"B6: Tier-1 AST + Tagged RPC"| SANDBOX
    CLI -->|"B6: ToolBroker Taint Gate"| BROKER
    BROKER -->|"B6: Allow-Listed Calls"| EXT_MCP
    BRIDGE -->|"B6: Scrubbed Env + ToolBroker Gating"| EXT_MCP
    BRIDGE -->|"B6: App Launch / No Skip-Perms"| AUTO_OS

    CLI -->|"B7: Zeroize on Exit"| PURGE
    BRIDGE <-->|"B7: JSON Persistence"| MEM_STORE
    BRIDGE <-->|"B7: DPAPI Encrypted Keys"| KEY_STORE
    GH -->|"B8: Release Download"| BRIDGE
    GH -->|"B8: Ed25519 + Constitution Check"| TRUST_ROOT
```

---

## 2. Detailed Sub-System Boundary Views

### 2.1 Desktop UI, Loopback Bridge & Local Persistence (`B1`, `B5`, `B7`, `B8`)

```mermaid
flowchart LR
    WEB_ORIGIN["Arbitrary Browser Tab (Untrusted Origin)"] -.->|"B1 Blocked: 403 on External Origin / Missing Token"| BRIDGE_API
    UI_APP["PAI Studio WebView (Strict CSP + sanitizeUrl)"] <-->|"Tauri IPC (get_bridge_config) + 127.0.0.1:port"| TAURI_HOST["pai-desktop.exe (Tauri Rust)"]
    TAURI_HOST -->|"Spawns pythonw.exe --port 0 with PAI_BRIDGE_TOKEN"| BRIDGE_API["bridge_server.py (127.0.0.1:dynamic_port)"]

    subgraph BRIDGE_CAPS["Bridge Capabilities and Crossings"]
        FS_API["/api/projects/file/* and /api/cowork/folders/*"]
        CLOUD_API["/api/cloud/* and cloud_ai.py"]
        MCP_API["/api/mcp/* and /api/plugins/*"]
        AGY_API["/api/antigravity/run and /api/team/*"]
        UPD_API["/api/update/* and apply_pending_update.py"]
    end

    BRIDGE_API --> FS_API
    BRIDGE_API --> CLOUD_API
    BRIDGE_API --> MCP_API
    BRIDGE_API --> AGY_API
    BRIDGE_API --> UPD_API

    FS_API -->|"Path containment + ingest secret scan + AST guard"| WORKSPACE["Project / Cowork Folders"]
    CLOUD_API <-->|"DPAPI Encrypted at Rest (credential_store.py)"| CLOUD_JSON["~/.pai/cloud_ai.json"]
    MCP_API -->|"Scrubbed env + ToolBroker confirmation"| MCP_JSON["~/.pai/mcp_servers.json"]
    AGY_API -->|"Spawns bounded agy (no skip-perms) / MultiAgentTeam"| AGY_PROC["Antigravity IDE / agy CLI"]
    UPD_API -->|"Extracts verified ZIP with Ed25519 signature + anti-rollback"| INSTALL_DIR["%LOCALAPPDATA%\\Programs\\PAI"]
```

### 2.2 Verify-Loop Code Execution & RSI Sandbox (`B4`, `B6`)

```mermaid
flowchart LR
    LLM["Local or Cloud Model Output (Untrusted)"] -->|"Candidate Python Code"| AST["Tier-1 AST Guard (ast_guard.py)"]
    AST -->|"Static Pass"| STAGE["Exclusive Staging O_CREAT|O_EXCL (verify_loop.py)"]
    STAGE -->|"Frozen Spec + Hidden Tests Kept in Driver"| DRIVER["Trusted Grader Driver (_pai_hidden_driver.py)"]

    subgraph OS_SANDBOX["Tier-2 OS Isolation Boundary"]
        direction TB
        PROBE["Startup Capability Probe (Fail-Closed Exit 5)"]
        RUNNER["Win32 AppContainer + Job Object / Linux bwrap --unshare-net"]
        WORKER["Untrusted Worker (_pai_hidden_worker.py)"]
        PROBE --> RUNNER --> WORKER
    end

    DRIVER <-->|"Tagged JSON RPC (value_codec.py / core/src/verify_loop.rs)"| WORKER
    WORKER -->|"Constant-Time HMAC-SHA256 Verdict Frame"| DRIVER
    DRIVER -->|"Verified Verdict + Bounded Repair N<=3"| HOST_OUT["User Workspace Output"]

    RSI_CODE["Phase 4 RSI Patch (Untrusted)"] -->|"Tier-2 WSB Policy (sandbox_policy.py)"| WSB["Windows Sandbox (Networking Disabled)"]
    WSB -->|"Hostile Output Channel: <=256KB results.json"| READER["read_sandbox_results()"]
```

### 2.3 Network Ingestion, Rust Policy Core & Update Trust Root (`B2`, `B3`, `B4`, `B8`)

```mermaid
flowchart LR
    EXT_NET["Internet Hosts"] -->|"URL Request"| URL_POL["url_policy.rs / net_guard.py"]
    URL_POL -->|"Scheme + Canonical CIDR + Redirect Check"| TRANS["raw_http.py (IP Pinned) / urllib"]
    TRANS -->|"Capped Stream + Timeout"| VERIF["data_verifier.py + core/src/ingest.rs"]
    VERIF -->|"Defang Markers + Per-Task Nonce"| ENVELOPE["--- UNTRUSTED DATA BEGIN [<nonce>] ---"]
    ENVELOPE -->|"tainted=True"| BROKER["ToolBroker (capabilities.py)"]
    BROKER -->|"Human Confirmation Required for Risk>=WRITE"| AUDIT["Hash-Chained Audit Log"]

    REL_SIGN["Offline Signer (sign_release.py)"] -->|"Ed25519 Manifest + Constitution Hash"| REL_PKG["Release Bundle"]
    REL_PKG -->|"Verify Signature, Anti-Rollback, TOCTOU"| UPD_CORE["updater.py / core/src/updater.rs"]
    TRUST_JSON["research/trust.json + CONSTITUTION.md"] -->|"Pinned Key + Hash"| UPD_CORE
```

---

## 3. Trust Boundary Inventory

| Boundary ID | Crossing | Untrusted Side | Trusted Side | Implemented Controls | Primary Source Files | Current Status / Known Gaps |
|---|---|---|---|---|---|---|
| **B1** | Browser / WebView / Local Client ↔ Desktop Bridge & Tauri | Browser pages, WebView DOM, unauthenticated local HTTP callers | `pai-desktop.exe`, `bridge_server.py`, host filesystem | Per-launch `X-PAI-Token` via `hmac.compare_digest` on `/api/*` and `/generated_images/*`, strict `Origin` echo (`tauri.localhost` / loopback port) with `Vary: Origin`, loopback `Host` check (403 on mismatch), ephemeral port (`--port 0`), strict Tauri CSP (`tauri.conf.json`), and DOM link sanitization via `sanitizeUrl`. Covers Deep Think / Cowork lifecycle endpoints (`/api/cowork/tasks/{pause,resume,cancel,graph}`). Single-instance Tauri plugin, path containment on project reads/saves. | `desktop/src-tauri/src/main.rs`, `desktop/src-tauri/tauri.conf.json`, `desktop/bridge_server.py`, `desktop/ui/app.js`, `research/cowork.py` | **Mitigated (FINDING-01, FINDING-09, FINDING-12):** Loopback bridge authentication, strict CORS, and CSP active. Residual: UI rendering allows `'unsafe-inline'` styles for custom theme variables. |
| **B2** | External Internet ↔ PAI Network & Grounding | Remote HTTP servers, DNS responses, redirects, HTML/JSON payloads | `DataVerifier`, `SecureBuffer`, Reasoner prompt | `net_guard.py` / `core/src/url_policy.rs` (87 golden vectors, blocked CIDRs incl. IPv6 transition prefixes), `outbound_policy.py` allowlist + `--offline` + visible log, byte/time caps, `DataVerifier` screening, `internet_service.py` and `graphql_agent.py` SSRF validation via `net_guard` and non-loopback cleartext HTTP rejection. Complete offline air-gap mode (`is_internet_enabled()`) immediately fails closed for all web search, live weather, geocoding, grounding, and fact-checking calls with zero socket allocation; interactive UI confirmation modal prompts before disconnect; web search inputs and fact-checking toggle disabled while offline. | `research/net_guard.py`, `core/src/url_policy.rs`, `research/outbound_policy.py`, `research/raw_http.py`, `research/network_pipeline.py`, `research/data_verifier.py`, `research/internet_service.py`, `research/graphql_agent.py`, `desktop/bridge_server.py`, `desktop/ui/app.js` | **Mitigated (FINDING-07, FINDING-13, T36):** SSRF protection and complete fail-closed offline air-gap enforced across search, weather, and fact-checking services. Residual: `raw_http.py` pins validated IPs while standard `urllib` calls perform standard resolution. |
| **B3** | Local Files / Folders ↔ Ingestion & Context Builder | Local repositories, user documents, CSVs, symlinks/junctions | LLM context window, terminal output, export paths | Realpath/junction containment, `is_secret_file` (35+ patterns), `scan_secret_content`, size/file/depth caps, `sanitize_terminal_output` (OSC/C1/bidi strip), cryptographic nonce envelopes (`[[SRC:<nonce>:<src>]]`). Desktop endpoints (`get_project_codebase_context`, `_handle_project_file_content`, `_handle_project_file_save`) enforce `is_secret_file`, `scan_secret_content`, symlink rejection, and `ast_guard` on `.py`. | `research/ingest.py`, `core/src/ingest.rs`, `research/pai.py`, `desktop/bridge_server.py`, `research/multi_agent.py` | **Mitigated (FINDING-04, FINDING-08):** Ingestion and codebase context filter secrets and reject symlink traversal across CLI and Desktop. |
| **B4** | Python Orchestrator ↔ Native Rust / C Launcher & Win32 | Caller environment (`PYTHONPATH`, `PAI_CORE_SHA256`), IPC payloads | `pai-core.exe`, `pai.py`, Win32 telemetry | `launcher.c` BCrypt SHA-256 check of `pai-core.exe` vs `manifest.json`, clears `PYTHONPATH`/`PYTHONHOME`/`PYTHONSTARTUP`, safe DLL search order; `pai_core_bridge.py` shadow differential comparison + `ast.parse` re-check; `#![deny(unsafe_code)]` outside `core/src/win32.rs`. | `packaging/launcher/launcher.c`, `research/pai_core_bridge.py`, `core/src/bridge.rs`, `core/src/win32.rs`, `core/src/lib.rs` | **Mitigated (CLI) / Partial (Direct Python):** Direct `python research/pai.py` or `desktop/bridge_server.py` bypasses `launcher.c`; `hardware/` C++ telemetry daemon named-pipe ACL (T9) remains Phase 2 work. |
| **B5** | Orchestrator ↔ Local Ollama & Cloud AI Providers | Untrusted prompts/context, model responses, remote cloud APIs, edited configs | Model router, API keys, host RAM/VRAM | `router.py` CLI-only task class + verified catalog allowlist; `thinking_engine.compute_adaptive_context_budget` scales Ollama `num_ctx` by `HardwareTelemetry` tier (clamped `<= 4096` on `COMPRESSED` to bound host OOM); `service_manager.py` pinned `%LOCALAPPDATA%\Programs\Ollama\ollama.exe` + WinVerifyTrust + `OLLAMA_HOST=127.0.0.1:11434`; `desktop/bridge_server.py` delegates Ollama daemon to `OllamaServiceManager`; `cloud_ai.py` encrypts keys at rest using DPAPI (`credential_store.py`), masks keys in `/api/cloud/config`, uses `X-Goog-Api-Key` headers for Gemini, and validates `custom_endpoint` with `net_guard` SSRF check; offline air-gap mode blocks cloud AI and image generation requests, disables cloud models in UI, and falls back to local Ollama models. | `research/router.py`, `research/thinking_engine.py`, `research/hardware_telemetry.py`, `research/service_manager.py`, `research/config.py`, `research/cloud_ai.py`, `research/credential_store.py`, `research/quota_engine.py`, `desktop/bridge_server.py`, `desktop/ui/app.js` | **Mitigated (FINDING-07, FINDING-10, FINDING-11, T36):** Ollama Authenticode verified via ServiceManager; adaptive context windows bounded by hardware tier; cloud keys encrypted at rest via DPAPI; custom endpoints screened; complete offline air-gap blocks cloud calls and enforces local model fallback. Residual: remote AI provider server-side data retention policies are external. |
| **B6** | Reasoner / User Commands ↔ Code Sandboxes, MCP & OS Automation | Model-generated code, external MCP servers, `agy` agent, desktop apps, screen/UIA text | Host OS, user files, credentials, network | `ast_guard.py` (Tier 1), `sandbox_win32.py` (AppContainer + Job Object), `sandbox_linux.py` (`bwrap --unshare-net` + rlimits), fail-closed startup probe, two-process driver/worker + HMAC-SHA256 verdict frame (`verify_loop.rs`), `ToolBroker` (`capabilities.py`). `mcp_client.py` scrubs child env vars to allowlist (stripping API keys), blocks unpinned `npx -y` and shell interpreters, and enforces `ToolBroker` confirmation gating (`confirm: true` on `/api/mcp/save`, `/api/mcp/toggle`). `antigravity_driver.py` removes `--dangerously-skip-permissions` from unattended runs, enforces `ToolBroker` confirmation on `/api/antigravity/run`. `automation.py` restricts desktop apps to `_APP_ALLOWLIST` with non-shell executable resolution (`_resolve_executable`), enforces `_DANGEROUS_CMD_GUARD` command injection rejection, and supports Telegram/WhatsApp/Email pre-fill. `desktop_control.py`, `pai_ui_agent.exe`, `windows_mcp_server.py`, and `desktop_orchestrator.py` govern UIA tree inspection, mouse/keyboard input (`SendInput`), and screenshot Vision fallback through `ToolBroker`, defang UIA text (`tainted=True`), enforce `(0,0)` failsafe + self-window click guards + blocked OS hotkeys, and require explicit HITL `Approve & Send` confirmation via `/api/desktop/confirm_action` and `/api/desktop/control_toggle`. | `research/ast_guard.py`, `research/sandbox_win32.py`, `research/sandbox_linux.py`, `research/sandbox_policy.py`, `research/verify_loop.py`, `core/src/verify_loop.rs`, `research/capabilities.py`, `research/mcp_client.py`, `research/automation.py`, `research/desktop_control.py`, `research/windows_mcp_server.py`, `research/desktop_orchestrator.py`, `desktop/bin/pai_ui_agent.cs`, `research/antigravity_driver.py`, `desktop/bridge_server.py` | **Mitigated (FINDING-04, FINDING-05, FINDING-06, T33, T37):** OS automation, UIA/mouse/keyboard steering, and MCP commands gated by ToolBroker confirmation, strict allowlists, failsafe abort, and HITL `Approve & Send`. Residual: AppContainer is weaker than full hardware-virtualized Hyper-V microVM; desktop input operates within the active user session. |
| **B7** | Ephemeral RAM ↔ Persistent Local Storage (`~/.pai`) | Working RAM buffers, swap/pagefile, crash dumps, untrusted session content, reasoning graphs | User privacy, credentials, future prompts | `SecureBuffer` wipe-and-verify (`finally` in `agent_core.py`), CLI shell `/history` memory-only. `credential_store.py` protects keys at rest using DPAPI (`CryptProtectData`) on Windows with atomic 0o600 fallback on POSIX. `auto_memory.py` scans and blocks secrets before persistence and defangs XML-like injection markers. `thought_graph.py` (`ThoughtGraph`, `SubconsciousBlackboard`) and `crash_reasoning_mcp.py` (`CRASHTracker`) sanitize all nodes via `ingest.scan_secret_content` and `defang_envelope_markers` and persist atomically under `~/.pai/cowork/`; `cowork.py` enforces `StuckDetectorWatchdog` stall bounds and objective quality checks (`verify_task_quality`). | `research/secure_buffer.py`, `research/agent_core.py`, `research/auto_memory.py`, `research/credential_store.py`, `research/cowork.py`, `research/thought_graph.py`, `research/crash_reasoning_mcp.py`, `desktop/bridge_server.py` | **Mitigated (FINDING-08, FINDING-11, T30b, T38):** Sensitive credentials encrypted at rest; auto-memory, ThoughtGraph, and SubconsciousBlackboard screened for secrets and defanged; long-horizon loops bounded by watchdog. Residual: unswappable RAM zeroization for Python runtime allocations relies on OS page zeroing. |
| **B8** | External Releases & Trust Root ↔ Updaters & Installers | GitHub release JSON, downloaded `.zip` payloads, staged update files | Install directory (`%LOCALAPPDATA%\Programs\PAI`), `trust.json`, `CONSTITUTION.md` | `research/updater.py` & `core/src/updater.rs`: Ed25519 manifest signature, revocation check, anti-rollback version, pinned Constitution SHA-256, per-file SHA-256, TOCTOU check, `trust_root_is_protected()`; `desktop/apply_pending_update.py` and `desktop/bridge_server.py` invoke `research.updater.Updater` to verify Ed25519 signatures, `trust.json`, anti-rollback SemVer, and Constitution hash before staging/extracting; fails closed on network errors. | `research/updater.py`, `core/src/updater.rs`, `core/src/ed25519.rs`, `research/trust.json`, `docs/CONSTITUTION.md`, `desktop/bridge_server.py`, `desktop/apply_pending_update.py`, `packaging/build_payload.py`, `tools/check_pins.py` | **Mitigated (FINDING-03):** Cryptographic Ed25519 signature and Constitution integrity verification integrated across Desktop and CLI updaters. |
