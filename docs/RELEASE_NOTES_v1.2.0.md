# PAI Studio v1.2.0 Release Notes

**Release Version:** `v1.2.0`  
**Target Architecture:** Windows x86_64 (`pai-desktop.exe`)  
**Frontend Framework:** Tauri 2.0 (Rust) + Native Webview + Python Bridge  
**Date:** 2026-11-14  

---

## Key Highlights & New Capabilities

### 1. Ultra-Lightweight Native Desktop Application (Tauri 2.0 + Rust)
- Fully compiled standalone binary (`pai-desktop.exe`) replacing browser-based execution.
- Embedded zero-latency UI assets with native Windows styling and hardware-accelerated rendering.
- Headless, invisible daemon management for the local PAI Bridge Server on `127.0.0.1:8765`.

### 2. Dual Workstation Themes (Clean Light & Deep Space Dark)
- Complete, pixel-perfect Light Mode overhaul across all cards, containers, inputs, dropdowns, code blocks, and chat threads.
- Dynamic theme switching via header toggle and hotkey (`Ctrl+Shift+L`) with automatic OS theme following.

### 3. Native Windows Folder & Workspace Browser
- Replaced browser JS prompts with true native Windows Folder Browser dialogs (`Common Item Dialog`).
- Powered by `pythonw.exe` subsystem to eliminate console/terminal flicker.

### 4. Interactive Model Install Modal & Storage Directory Selection
- Selecting "Install Model" now presents an informative modal displaying model metadata (tag, expected download size, and description).
- Dedicated path input field with a native "Browse..." button allowing users to direct weights storage to custom drives (e.g. `D:\AI_Models`).
- Real-time disk space telemetry with automatic drive capacity detection and low-storage warnings.
- Sleek "Reset to Default" pill button matching the workstation design system.

### 5. Advanced Model Download Engine (Pause / Cancel & Background Tracking)
- Real-time SSE streaming download progress displaying layer download status, percentage (`0%` - `100%`), and downloaded volume (MB/GB).
- Native pause / cancel capability via request aborting with automatic layer cache preservation.
- "Minimize to Background" feature with persistent top-navigation bar download pill and direct popup reopening.
- Downloading models update their catalog card button to active state (`Downloading (45%)...`) with an animated spinner, preventing duplicate pulls.

---

## Verification & Compliance
- Core Tree ID invariant verified.
- Research Tree ID invariant verified.
- All pre-freeze pin consistency audits pass (`tools/test_check_pins.py` 7/7, `tools/test_check_n_plus_1.py` 6/6).
