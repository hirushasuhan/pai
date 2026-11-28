# PAI Studio v1.5.1-beta.1 Release Notes

**Release Version:** `v1.5.1-beta.1`  
**Target Architecture:** Windows x86_64 (`pai-desktop.exe`, `pai.exe`)  
**Frontend Framework:** Tauri 2.0 (Rust) + Native Windows Webview + Python Bridge Daemon  
**Release Date:** 2026-11-28  

---

## Executive Overview

PAI Studio `v1.5.1-beta.1` introduces native memory optimization, local C++ inference runtime sidecars, keyless image synthesis fallbacks, and a multi-agent Model Context Protocol (MCP) hub, building upon the deep reasoning, stuck-recovery cowork, and complete offline air-gap protections delivered across the `v1.5.0` series.

The workstation operates under a strict defense-in-depth model: all local sidecar runtimes bind exclusively to loopback, credential tokens are encrypted at rest using Windows DPAPI, tool execution is gated by capabilities and human-in-the-loop confirmation, and offline air-gap mode enforces fail-closed network policies.

---

## Key Highlights & Subsystems

### 1. Memory Optimizer & Hardware Pressure Engine
- **Active Working Set Trimming**: Implemented `research/memory_optimizer.py` and `research/memory_probe.py`, providing dynamic RAM/VRAM pressure monitoring and working set trimming via Win32 `EmptyWorkingSet`.
- **System Memory Endpoints**: Exposed `/api/system/memory_status` and `/api/system/optimize_memory` on the local bridge server, offering process isolation and advisory resource recovery without terminating running user processes.
- **Hardware-Adaptive Context Budgeting**: Computes token allocation limits based on live system tier (`HIGH`, `BALANCED`, `COMPRESSED`), guarding against out-of-memory faults during extended sessions.

### 2. Local Inference Sidecars & Installer
- **Process Orchestration**: Introduced `research/local_sidecars.py` and `research/sidecar_installer.py` for managing external C++ inference runtimes (`llama-server`, `sd-cli`) as isolated background sidecars bound strictly to loopback (`127.0.0.1:11435`).
- **Admission Controls**: Enforces Gate 1 disk space and binary integrity checks alongside Gate 3 pre-load RAM/VRAM checks, calculating 64-layer offloading capacity and automated 300-second idle process reaping.
- **Safe Asset Provisioning**: The sidecar installer restricts downloads to allowlisted GitHub Releases and HuggingFace domains, enforcing SHA-256 checks, zip-slip path traversal guards, and archive volume caps (512 MiB maximum).

### 3. Keyless FLUX Image Synthesis & Polish
- **Image Pipeline Architecture**: Integrated Pollinations FLUX and local image synthesis fallbacks in `research/cloud_ai.py` with fail-closed offline air-gap enforcement.
- **Image Verification & Export**: Hardened the `/api/image/save_as` endpoint with PNG/JPEG magic byte verification, directory containment validation, and integration with the native Windows folder picker dialog.
- **Prompt Intent Detection**: Added heuristic routing (`_looks_like_image_generation_request`) to prevent accidental image generation on standard conversational queries.

### 4. Model Context Protocol (MCP) Hub & Plugin Manager
- **MCP Client & Hub**: Introduced `research/mcp_hub.py` and expanded `research/mcp_client.py` to support multi-agent MCP tool routing across STDIO and Streamable HTTP/SSE transports.
- **Credential Protection**: Implemented `MCPVaultManager` leveraging Windows DPAPI (`CryptProtectData`) to store tokens encrypted at rest under `~/.pai/mcp_vault.json` without plaintext leakage.
- **Security & Schema Screening**: Added `PluginScanner` and `ToolFirewall` enforcing schema verification, blocking secret-harvesting `elicitation` forms, redacting markers from tool outputs, and validating endpoints against `net_guard`.
- **Context Engine**: Implemented `research/context_engine.py` with observation masking, semantic window slicing, and token budget enforcement for multi-agent workflows.

### 5. Deep Reasoning Engine & Stuck-Recovery Cowork
- **Tree-of-Thought Exploration**: Implemented `research/deep_reasoning.py` featuring radial node expansion, thought graph serialization, step-by-step reflection cycles, and UI thought trace visualization.
- **Stuck-Recovery Watchdog**: Enhanced `research/cowork.py` with `StuckDetectorWatchdog`, tracking loop repetitions and heartbeat timeouts, automatically rolling back execution state to checkpointed valid branches upon detecting stalling.
- **Quality Verification**: Enforces objective task quality verification (`verify_task_quality`) before completing Cowork assignments.

### 6. Complete Offline Air-Gap Mode & Security Confirmation Gates
- **Air-Gap Architecture**: Added `AIRGAP_OFFLINE` / `pai_airgap` toggle in `desktop/bridge_server.py` and workstation settings.
- **Fail-Closed Network Enforcement**: Completely blocks non-loopback outbound socket connections and external API requests when air-gap mode is active.
- **Human-in-the-Loop Confirmation**: Integrated security confirmation dialogs for sensitive file system and system configuration operations.

### 7. Native Windows UI Automation & PC Control
- **UIA Agent Bridge**: Created `desktop/bin/pai_ui_agent.cs`, a compiled native C# UI Automation driver for Windows accessibility-tree element discovery, window management, and desktop action execution.
- **Capability Gating**: Routed all automation commands through `research/automation.py`, `research/windows_mcp_server.py`, and `research/capabilities.py` (`ToolBroker`), requiring explicit human confirmation.

### 8. Software Auto-Updater Hardening
- **Manifest Integrity Checks**: Hardened `desktop/apply_pending_update.py` and `desktop/bridge_server.py` to verify SHA-256 digests and release manifests against GitHub release metadata prior to extraction.
- **Safety Bounds**: Enforced strict non-downgrade SemVer evaluation, 250 MiB archive size caps, and automated rejection of archive entries with path traversals or symlinks.
- **Background Applicator**: Staged updates applied seamlessly on application restart with atomic directory swaps and rollback safety.

---

## Verification & Compliance

1. **Security Claims Compliance**: Verified with `research/tests/test_claims.py` (2 tests, 0 failures). No absolute-security claims or banned terminology exist across documentation or source files.
2. **Secret Scanner Audit**: Verified with `tools/check_secrets.py`. Zero tracked credentials, private keys, or API tokens detected.
3. **Threat Model Alignment**: All architectural boundaries (`B1`–`B8`) and threat rows (`T1`–`T40`) documented in `docs/TRUST_BOUNDARY_DIAGRAM.md`, `docs/STRIDE_THREAT_MODEL.md`, and `docs/THREAT_MODEL.md`.
4. **Safety Constitution Invariance**: `docs/CONSTITUTION.md` and `research/trust.json` remain untouched and cryptographically pinned.
