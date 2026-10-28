# ADR-014 - Interactive Shell and Managed Local Ollama Service

**Status:** Proposed (owner request, 2026-10-27).  
**Applies to:** Build Stage pre-freeze (Phase 2 Track L, Release 1.1.0-rc2+).  
**Dependencies:** ADR-001 (Local Reasoner), ADR-002 (Privacy Controls), ADR-006 (Capabilities & Taint), ADR-008 (Local Assistant), ADR-013 (Installer & Setup).  
**Related Reviewer Note:** `docs/PROJECT_REVIEW.md` (Reviewer note 2026-10-27; Reviewer addendum 2026-10-27).

---

## Context

The owner requested two ergonomic improvements for everyday usage of Personal Agentic AI (PAI):
1. **Interactive Shell:** Running `pai` without arguments in an interactive terminal should launch a stateful conversation shell where users can chat naturally and invoke existing subcommands via slash commands (`/analyze`, `/code`, `/docs`, `/forecast`, `/doctor`, `/chat`, `/help`, `/exit`).
2. **Managed Ollama Start:** When executing `pai chat` (or inside the shell) and the Ollama server is not running, PAI should detect this condition cleanly, ask for user consent, and start the local server automatically instead of displaying a confusing raw socket connection error (`WinError 10061`).

### Sequencing and Build Stage Timing

Per the user's decision to postpone the N+1 evaluation window, implementation occurs during the **Build Stage prior to the freeze**:
- **Timing:** Implemented in `research/` before the freeze candidate (e.g. `v1.1.0-rc2`) is tagged and before the 14-day evaluation window begins. Implementing features first avoids spending 14 days evaluating a tree that would subsequently be replaced.
- **Sequential Reviews:** Implemented across two separately reviewed commits in `research/`:
  1. Commit 1: Managed Ollama service start (`research/service_manager.py` or equivalent, loopback probe, Authenticode verification on `ollama.exe`, consent check, child PID tracking).
  2. Commit 2: Interactive shell REPL (`research/shell.py` or equivalent, terminal guard, slash dispatcher, signal handling, banner).
- **Invariants:**
  - ADR-012 addresses future inference runtime architectures (backend adapters, `pai runtime`), not starting the local Ollama desktop service.
  - Model residency and memory retention belong entirely to the Ollama server (configured by its keep-alive timer), not to the ephemeral PAI client process. The interactive shell saves Python interpreter startup latency, not model loading latency.
  - Local models operate on fixed training datasets without live clocks or internet access. The shell must never present generated outputs as verified current real-world facts, and documentation must avoid examples suggesting awareness of current political officeholders.

---

## Decision

The interactive shell and managed service features share a common service-detection boundary. They are architected together in a unified specification and implemented in the Build Stage across two sequentially reviewed commits:
1. **Commit 1 (Managed Service):** Local daemon detection, Authenticode-verified launch of `ollama.exe serve`, loopback binding, child PID tracking, and lifecycle cleanup.
2. **Commit 2 (Interactive Shell):** Terminal detection guard (`isatty`), REPL loop, slash-command dispatcher to existing canonical subcommand functions, interrupt handling, and banner display.

### 1. Interactive Shell Architecture

- **Invocation & Terminal Guard:**
  - Running `pai` with no arguments opens the interactive shell **only** when standard input and standard output are attached to an interactive terminal (`sys.stdin.isatty() and sys.stdout.isatty()`).
  - In a script, pipeline, or redirected environment (e.g. `pai < input.txt` or `echo "..." | pai`), `pai` without arguments preserves exact existing behaviour: displays the standard CLI help message and exits with the current status code.
- **Slash-Command Dispatcher:**
  - Slash commands map directly to existing, reviewed subcommand handler functions (`cmd_analyze`, `cmd_code`, `cmd_docs`, `cmd_forecast`, `cmd_doctor`, `cmd_chat`).
  - No duplicate command implementations are created; the capability broker, taint tracking, AST guard, and restricted execution boundaries hold identically.
  - Arguments to slash commands support paths containing spaces and non-ASCII characters (e.g. Sinhala Unicode `නාමය`).
  - Unrecognized slash commands (e.g. `/unknown`) are rejected locally with a clear error and are **never** forwarded to the language model.
- **Text Routing:**
  - Any input line not prefixed with a slash (`/`) is treated as conversational input routed to `chat`.
- **Session Control & Signal Handling:**
  - `Ctrl+C` (SIGINT) cancels the currently generating model response and safely returns to the interactive prompt without killing the shell session.
  - `Ctrl+D` (EOF), `Ctrl+Z` (Windows EOF), or `/exit` cleanly terminates the shell.
- **User Banner:**
  - On launch, the shell displays an honest banner stating:
    - Active model name and inference endpoint.
    - Honest capability disclaimer: local models rely on static training data and lack live clock/web access; answers regarding current events may be outdated.
- **History & Privacy:**
  - Command line editing and session history (Up/Down arrow navigation) are supported natively by standard terminal line editing (`input()` / `readline`).
  - No persistent cross-session history file is written to disk by default, maintaining the zero-unnecessary-storage privacy posture of ADR-002.

### 2. Managed Local Ollama Service Architecture

- **State Discovery Order:**
  1. *Online Check:* Probe HTTP `GET http://127.0.0.1:11434/api/tags` with a 1.0-second timeout. If the server responds with HTTP 200, use the running instance immediately.
  2. *Installed Check:* If connection fails, check for the official per-user Ollama server executable at `%LOCALAPPDATA%\Programs\Ollama\ollama.exe`. (A single launch binary is targeted: `ollama.exe serve` directly as a background child process, avoiding the tray GUI wrapper `ollama app.exe` to guarantee deterministic process lifecycle management).
  3. *Uninstalled Fallback:* If the executable is not found at the official path, do not attempt to download binaries from the shell. Present a concise, helpful message instructing the user to install Ollama or run `pai setup`.
- **Authenticode Verification & Execution Guard:**
  - Before starting the detected executable, verify its Windows Authenticode digital signature using WinVerifyTrust, validating that the publisher matches the pinned Ollama certificate subject (`OLLAMA_CERT_SUBJECT`). The signature check is performed on the exact binary that will be executed (`ollama.exe`).
  - **PATH Lookup Prohibited:** Never search the system or user `PATH` for `ollama.exe`. This prevents PATH hijacking from untrusted directories.
  - **Loopback Enforcement:** Enforce loopback binding only (`127.0.0.1:11434`). Reject non-loopback `OLLAMA_HOST` settings for auto-launch.
- **Consent & Lifecycle Management:**
  - Before launching the server for the first time, prompt the user for explicit consent.
  - Record user choice locally in `~/.pai/config.json`.
  - Open Decision (proposed as **D17**): Default consent mode for starting Ollama:
    - Option A: *Ask each time* (prompt each time Ollama is offline; answering 'always' or 'never' remembers the choice in `~/.pai/config.json`; answering 'y' starts for this session only without persisting).
    - Option B: *Always auto-start* (start automatically whenever installed but offline).
    - Option C: *Never auto-start* (strictly manual start by user).
  - **Child Process Tracking & Tree Termination:** Launch the daemon via `subprocess.Popen([str(ollama_exe), "serve"], creationflags=subprocess.CREATE_NO_WINDOW, env=clean_loopback_env)` with an explicit loopback environment (`OLLAMA_HOST=127.0.0.1:11434`, stripping any caller-defined `OLLAMA_*` network settings) and retain the child PID. On clean PAI exit (via `atexit` and signal handlers), terminate the whole process tree started by PAI via `%SystemRoot%\System32\taskkill.exe /F /T /PID <pid>` to clean up any runner child processes (e.g. `ollama_llama_server`) holding GPU VRAM. Pre-existing external Ollama services are never touched. Hard-kill note: If PAI is terminated forcibly (`SIGKILL` or Task Manager 'End Process'), Python `atexit` handlers do not execute; the daemon process tree continues running undisturbed and can be closed manually via the Ollama tray icon or Task Manager.
- **Error Simplification:**
  - Replace raw low-level connection errors (`[WinError 10061] No connection could be made because the target machine actively refused it`) with a single informative sentence:
    `"Local AI service (Ollama) is not running on 127.0.0.1:11434. Run 'pai setup' or start Ollama from the Start Menu."`

---

## Consequences

### Positive
- Simplifies everyday interaction for non-technical users while preserving scriptable CLI ergonomics.
- Reuses evaluated subcommand execution paths, exercising identical sandbox, capability, and telemetry invariants without duplicating command logic.
- Eliminates hostile PATH hijacking and prevents unverified binary execution through Authenticode verification on the exact target binary.
- Eliminates unhandled socket connection stack traces (`WinError 10061`) when servers are offline, replacing them with a single informative prompt.
- Deterministic process cleanup: PAI terminates only the exact child daemon it spawned.

### Negative / Trade-offs
- Process management on Windows requires careful child process tracking (PID / Job Objects) to ensure spawned instances terminate cleanly.
- Requires user decision on default start behavior (D17).

---

## Verification & Test Matrix

When implemented in Build Stage:
1. `test_shell_terminal_detection`: Asserts shell launches when isatty=True; asserts CLI help text and exit code parity when redirected/piped.
2. `test_shell_slash_dispatch`: Asserts `/doctor`, `/analyze`, `/code`, `/docs` invoke canonical functions without duplicate logic.
3. `test_shell_unknown_slash_command`: Asserts unknown slash command is rejected locally and never forwarded to reasoner.
4. `test_service_detection_states`: Mocks offline, online, and missing states.
5. `test_hostile_path_hijack_rejected`: Places a rogue `ollama.exe` earlier on `PATH` and asserts PAI ignores it and only inspects the pinned install root.
6. `test_authenticode_validation`: Rejects unsigned or improperly signed mock binaries.
7. `test_lifecycle_cleanup`: Confirms server started by PAI is cleanly shut down on exit, while external servers remain running.
