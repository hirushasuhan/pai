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
  - Slash commands map directly to existing, reviewed subcommand handler functions (`cmd_analyze`, `cmd_code`, `cmd_docs`, `cmd_forecast`, `cmd_doctor`, `cmd_chat`, `cmd_setup`, `cmd_models_list`, `cmd_route`).
  - **Excluded Maintenance Commands (Finding DV):** `/clear-shadow` and `/calibrate` are intentionally excluded from the shell to prevent accidental erasure of shadow comparison telemetry during evaluation windows; they remain accessible exclusively via explicit CLI invocation.
  - **Setup Download Guard (Finding DV):** `/setup` inside the shell prompts interactively for user confirmation before initiating any model weight downloads.
  - No duplicate command implementations are created; the capability broker, taint tracking, AST guard, and restricted execution boundaries hold identically.
  - **Windows Path Tokenizer (Finding DW):** Arguments to slash commands support unquoted and quoted Windows backslash paths (e.g. `C:\Users\hp\project`), UNC network shares (e.g. `\\server\share\file`), paths with spaces, and non-ASCII characters (e.g. Sinhala Unicode `නාමය`).
  - Unrecognized slash commands (e.g. `/unknown`, `/clear-shadow`) are rejected locally with a clear error and are **never** forwarded to the language model.
- **Text Routing & Dash Protection (Finding DX):**
  - Any input line not prefixed with a slash (`/`) is treated as conversational input routed to `chat` using a `--` sentinel, ensuring prompts beginning with a dash (e.g. `-5 is negative, why?`) are never misinterpreted by argparse as CLI option flags.
- **Session Control & Signal Handling:**
  - `Ctrl+C` (SIGINT) cancels the currently generating model response and safely returns to the interactive prompt without killing the shell session.
  - `Ctrl+D` (EOF), `Ctrl+Z` (Windows EOF), or `/exit` cleanly terminates the shell.
- **User Banner & Stateless Chat Mode (Finding DX):**
  - On launch, the shell displays an honest banner stating:
    - Active resident model name, or "no model loaded yet" if uninitialized.
    - Inference endpoint (`127.0.0.1:11434`).
    - Honest capability disclaimer: local models rely on static training data and lack live clock/web access; answers regarding current events may be outdated.
    - Stateless mode declaration: chat operates statelessly where each line is evaluated independently without cross-turn memory.
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

---

## Addendum (2026-10-28): Shell Presentation, ANSI Colours, and Finding ES Temporal Guardrails

### 1. Presentation & Developer Credit
The interactive shell banner features:
- A compact ASCII block-letter PAI logo (5 lines, fitting comfortably within 80-column terminals).
- Developer credit declaring provenance: `Developed by Hirusha Suhan`.
- Explicit capability disclaimers: PAI gives the model your computer's date and time. It has no web access and its knowledge ends at a training cut-off. Conversation chat operates in stateless mode without cross-turn memory.

### 2. ANSI Terminal Colours & Virtual Terminal Processing
- ANSI styling is activated only when standard output is an interactive TTY, the `NO_COLOR` environment variable is not set, `TERM` is not set to `dumb`, and on Windows, after successfully enabling Virtual Terminal processing via `SetConsoleMode` with `ENABLE_VIRTUAL_TERMINAL_PROCESSING` (0x0004).
- Safe fallback to unstyled plain text occurs when piped to a file, redirected, or in non-TTY environments.
- Styling scheme: Accent color (Bright Cyan) for logo and `pai>` prompt, Red for errors, Yellow for notices/warnings, Dim for hints.
- Output from models continues to be sanitized via `sanitize_terminal_output` to prevent model-generated escape code injection.

### 3. Noise Suppression
Repeated execution boundary notices (`Sandbox execution boundary verified fail-closed.`) are printed once at shell startup and suppressed during interactive subcommand turns via `PAI_SHELL_ACTIVE`. Non-interactive CLI commands retain the message on each execution, preserving CLI parity.

### 4. Finding ES: Offline Temporal & Fact Guardrails (D21: Layer 0-3 offline guardrails adopted for 1.1.0-rc2; web lookup is a separate future decision.)
To prevent local models from stating obsolete or confabulated facts regarding live events as if they were current, PAI adopts offline guardrail mechanisms (Layers 0 to 3) without external network lookups:
0. **Deterministic Clock Answer (Layer 0):** Plain date and time inquiries in English, Singlish, and Sinhala (e.g. "what is the date", "ada dawasa", "අද දිනය") are recognized deterministically as short complete questions (<= 8 words) via full template matching (Finding EZ) and answered directly from the system clock without calling the model or Ollama daemon. Complex inquiries, other timezones, programming tasks, and extra words pass to the model.
1. **Host Clock Context (Layer 1):** The current local date, time, and timezone are retrieved from the host system clock and supplied in the chat system prompt. A dedicated `/time` shell command answers directly from the system clock without invoking the model or Ollama daemon.
2. **Offline Prompt Boundaries (Layer 2):** System prompts state that the assistant operates fully offline, that knowledge ends at the model's training cut-off, and that for live or time-sensitive topics (office holders, news, market prices, weather, scores), it must state that it works offline and cannot verify current facts.
3. **Deterministic Heuristic Notice (Layer 3):** Prompts matching time-sensitive keywords across English, Singlish, and Sinhala trigger a deterministic post-response notice:
   > "PAI is offline. This answer comes from the model's training data and may be outdated. It was not checked against the internet."
   *Honest Limitation:* The keyword matching heuristic can miss novel temporal queries and may flag certain non-temporal questions that contain temporal keywords. Live web verification is deferred to future opt-in ADRs to preserve PAI's local execution boundaries.

---

## Addendum (2026-11-03): Milestone B Interactive Shell Layout, Pinned Scroll Region, Thinking Spinner, and Session History

### 1. Pinned Header & DECSTBM Scroll Region Architecture
To provide a clean, modern terminal interface while maintaining low screen footprint:
- **Header Layout (5 Rows Total)**:
  - Rows 1-3: Half-block Unicode logo (`█▀█ ▄▀█ █` / `█▀▀ █▀█ █` / `▀   ▀ ▀ ▀`) styled with a horizontal color gradient (Bright Cyan for 'P', Bright Blue for 'A', Bright Magenta for 'I'). If stream encoding cannot represent block characters (detected via `can_encode_blocks`), PAI falls back to a 3-row compact ASCII logo (` ___  _  ___` / `| _ \/_\  | ` / `|_|  / \ _|_`).
  - Row 4: Width-adaptive info line (`PAI v1.1.0 | Model: ... | Offline | Developed by Hirusha Suhan`).
  - Row 5: Horizontal box-drawing rule (`─` or `-` fallback) matching the terminal width (max 80 columns).
- **DECSTBM Margins (`\033[6;{rows}r`)**:
  - Activated when `is_interactive_terminal()` is True, `PAI_NO_PINNED_HEADER != "1"`, `TERM != "dumb"`, terminal height $\ge 20$, width $\ge 60$, and Windows VT processing is enabled.
  - Screen is cleared with `\033[2J\033[1;1H` (strictly avoiding `\033[3J` which clears terminal scrollback).
  - Header is drawn on rows 1..5; scrolling margin is pinned to rows 6..`rows`.
  - Terminal resizing is detected on each turn via `check_and_apply_resize`, dynamically updating header lines and DECSTBM margins.
  - On exit (`/exit`, EOF, Ctrl+C, SystemExit, or unexpected exception), `cleanup_pinned_layout` resets scroll margins (`\033[r`), restores the cursor to the bottom row, resets attributes, and restores original console mode.

### 2. Honest Terminal Scrollback Limitation & In-Memory Session History
- **Terminal Scrollback Limitation**: In standard terminal emulators (such as Windows Terminal and xterm), text scrolling past DECSTBM margins is discarded by the terminal and does not enter the host window scrollback buffer.
- **In-Memory `/history [N]` Command**: To provide full interaction review without compromising privacy:
  - Stores up to 200 items in memory, capped strictly at 1 MB (`MAX_HISTORY_BYTES = 1_000_000`).
  - Displays timestamps, commands, and outputs. Supports optional limit parameter (e.g. `/history 5`, defaulting to 20).
  - Zero disk writes: never written to disk, maintaining ADR-002 privacy invariants.
  - Memory buffer is wiped clean on shell exit.
  - History is never forwarded to language models or Ollama daemon.
- **Opt-Out Mechanism**: Users preferring traditional non-pinned terminal scrolling can disable pinned headers by setting `PAI_NO_PINNED_HEADER=1`.

### 3. Shell-Local `/clear` Command
- `/clear` (and `/cls`) clears the screen:
  - In pinned VT mode: clears strictly the scrolling region below row 5 (`\033[6;1H\033[J`), repositioning the cursor at line 6, col 1 without redrawing or breaking the pinned header.
  - In non-pinned mode: clears the screen (`\033[2J\033[1;1H`) and re-displays the startup banner.

### 4. Non-Blocking Thinking Spinner for `/chat`
- During local model generation in `/chat` (and conversational inputs routed to chat), an animated thinking spinner displays elapsed seconds (`\r{frame} Thinking... ({elapsed}s)`).
- Uses Unicode braille frames (`⠋⠙⠹...`) on UTF-8 streams and ASCII frames (`|/-\`) on non-UTF-8 streams.
- Runs on a non-blocking daemon thread; cleanly clears the spinner line (`\r\033[2K`) on the first byte of model output or during `finally` cleanup.
- Automatically disabled when standard output is not a TTY or `TERM == "dumb"`.

### 5. Model Output Hygiene & Terminal Margin Protection
- All model output passes through `sanitize_terminal_output` before printing, ensuring CSI margin escape codes (`\033[r`), cursor repositioning codes (`\033[H`), and screen clear codes are defanged, preventing untrusted model responses from altering terminal margins or corrupting the pinned header.

## Addendum (Milestone B2): Terminal Layout Polish & Piped Process Isolation (Findings FK, FL, FM, FN, FO)

### 1. Piped Process Isolation and Exit Cleanup Gating (Finding FK)
- Exit cleanup (`cleanup_pinned_layout`) registration is strictly deferred until `setup_pinned_layout` has successfully executed during an interactive session.
- Module-level `atexit.register` is eliminated.
- VT margin reset escape sequences (`\033[r`, `\033[{rows};1H`, `\033[0m\033[?25h`) are emitted strictly when `_pinned_active` is True and `sys.stdout.isatty()` is True.
- Zero escape bytes are output on module import (`import shell`) or during non-interactive, piped runs (e.g. `pai chat --json`).

### 2. Cursor Positioning and Header Height Derivation on Resize (Finding FL)
- In compliance with the VT100 standard, where DECSTBM margin commands (`\033[{top};{bottom}r`) reset the terminal cursor to home position `(1, 1)`, `check_and_apply_resize` explicitly positions the cursor at the bottom row of the updated dimensions (`\033[{rows};1H`). This guarantees that subsequent prompts or outputs never overwrite row 1 of the header logo.
- Header height is dynamically derived via `len(header_lines)` across all layout routines rather than hardcoded.

### 3. Honest Disclaimer Parity in Pinned Mode (Finding FM)
- Upon pinned shell startup, the chat scrolling area directly below the header displays the full capability and limitation disclaimers:
  - Fail-closed sandbox execution verification.
  - Resident model profile and endpoint address.
  - Computer clock date/time provisioning with training cut-off and zero live web access disclaimer.
  - Stateless turn isolation notice.
  - `/help` and `/exit` command hints.

### 4. Non-Pinned Clear and Multi-byte History Byte-Cap (Finding FN)
- `/clear` in non-pinned mode triggers screen erase (`\033[2J\033[1;1H`) based on stream TTY capability (`stream.isatty()`), functioning properly even when color styling is disabled via `NO_COLOR=1`.
- `NO_COLOR=1` suppresses ANSI styling colors only; it does not disable DECSTBM layout or block characters.
- In-memory session history cap (`MAX_HISTORY_BYTES = 1_000_000`) is computed from UTF-8 encoded bytes (`len(s.encode('utf-8'))`), ensuring multi-byte Unicode strings (such as Sinhala) do not exceed the memory budget.

### 5. Stdlib Virtual Terminal Screen Model & Test Protocol (Finding FO)
- Automated verification includes `VirtualTerminalScreen`, a pure-Python standard-library screen emulator simulating CUP, ED, EL, DECSTBM margin resets, and region scrolling.
- Automated tests verify screen integrity across 40 turns of chat, window resizes (smaller and larger), and `/clear` executions.
- In accordance with Finding FO, documentation explicitly records that the automated coding agent executed the stdlib emulator in unit tests without running a real physical terminal, leaving physical visual proof to the user.
