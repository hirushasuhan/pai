# Manual Verification Protocol: Milestone B Interactive Shell Layout & Look

This document establishes the test procedure and record template for manual verification of the PAI Milestone B Interactive Shell UI across host terminal emulators on Windows.

> [!NOTE]
> **Testing Methodology & Simulation Notice (Finding FO)**: The automated test suite for shell layout and scrolling (`research/tests/test_shell.py`) utilizes a simulated standard-library-only `VirtualTerminalScreen` model tracking character positioning, cursor coordinates (CUP), screen erasing (ED, EL), line feeds, and DECSTBM margins with VT100 cursor-home resets. The owner coding agent operates non-interactively in an automated environment and ran no real physical terminal window; physical multi-terminal visual proof is performed by the human user per the protocol below.

## Verification Matrix

| Test ID | Environment | Dimensions Tested | Pinned Header (5 Rows) | Resize Behavior | `/history [N]` Verification | `/clear` Behavior | Spinner Execution | Normal Exit & VT Reset | Result |
|---|---|---|---|---|---|---|---|---|---|
| M-UI-01 | Windows Terminal (wt.exe) | 80x24 -> 120x35 | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | Pending User Run |
| M-UI-02 | PowerShell Console Host (conhost.exe) | 80x25 | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | Pending User Run |
| M-UI-03 | Command Prompt (cmd.exe) | 80x25 | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | Pending User Run |
| M-UI-04 | VS Code Integrated Terminal | 100x30 | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | Pending User Run |
| M-UI-05 | `NO_COLOR=1` Environment (Color Suppression Only) | 80x24 | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | Pending User Run |
| M-UI-06 | `PAI_NO_PINNED_HEADER=1` Opt-out | 80x24 | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | [ ] Pass | Pending User Run |
| M-UI-07 | Piped Subcommand Isolation (`pai chat --json`) | Piped | N/A | N/A | N/A | N/A | N/A | [ ] Pass | Pending User Run |

---

## Step-by-Step Verification Procedure

### Test 1: Pinned Header Layout & 40-Turn Scroll Stability
1. Launch interactive shell in Windows Terminal:
   ```powershell
   python research/pai.py
   ```
2. Verify visual appearance:
   - Rows 1-3: Half-block Unicode logo (`█▀█ ▄▀█ █`) with horizontal gradient (Cyan -> Blue -> Magenta).
   - Row 4: Width-adaptive info line (`PAI v1.1.0 | Model: ... | Offline | Developed by Hirusha Suhan`).
   - Row 5: Horizontal box-drawing rule (`─` across terminal width).
   - Rows 6+: Startup disclaimers:
     - `Sandbox execution boundary verified fail-closed.`
     - `Model: ... | Endpoint: ...`
     - `Note: PAI gives the model your computer's date and time. It has no web access and its knowledge ends at a training cut-off.`
     - `Mode: Stateless (each line is evaluated independently without prior conversation memory).`
     - `Type /help for available commands or /exit to quit.`
   - Cursor positioned at `pai> ` prompt in the chat region below the notices.
3. Execute 40 turns of conversation or commands (e.g. alternating `/time`, `/models`, and conversational queries).
4. Verify that rows 1-5 remain strictly pinned in place while lines 6+ scroll naturally below.

### Test 2: Window Resize Handling
1. While at the `pai> ` prompt, drag the terminal window edge to change dimensions (e.g. from 80x24 to 120x35).
2. Press Enter or type a command.
3. Verify that:
   - Header is redrawn cleanly across the new width.
   - DECSTBM scrolling margin expands to the new bottom row without line artifacts or visual tearing.
   - The next `pai> ` prompt prints cleanly at the bottom of the chat region, never overwriting the logo header.

### Test 3: In-Memory `/history` Command
1. Enter `/history`. Verify the last 20 session interactions are displayed with timestamps and cyan command headers.
2. Enter `/history 5`. Verify only the last 5 entries are displayed.
3. Enter `/history abc` and `/history -1`. Verify helpful validation errors are displayed.
4. Verify that zero history files are written to disk.

### Test 4: Chat Region `/clear` Command
1. Enter `/clear`.
2. Verify that:
   - Pinned header (rows 1-5) remains completely intact.
   - Only the chat scroll region below line 5 is cleared.
   - Cursor returns to row 6, col 1.

### Test 5: Thinking Spinner for `/chat`
1. Enter a conversational prompt (e.g. `What is the capital of France?` or `/chat What is gravity?`).
2. Verify that while the model generates its response:
   - Animated braille spinner (`⠋⠙⠹...`) is displayed along with elapsed seconds: `⠋ Thinking... (1s)`.
   - On the first byte of model response output, the spinner line is cleanly cleared (`\r\033[2K`) without leaving leftover characters.

### Test 6: Signal Handling & VT Margin Restoration
1. Press `Ctrl+C` at the `pai> ` prompt. Verify notice `Type /exit to quit.` is displayed without crashing.
2. Enter `/exit`.
3. Verify that:
   - Shell outputs `Goodbye.`.
   - Terminal scroll margins are reset (`\033[r`).
   - Original Windows console mode is restored.
   - Terminal prompt returns to normal operating state.

### Test 7: `NO_COLOR=1` Color Suppression (Preserves Pinning)
1. Run in PowerShell:
   ```powershell
   $env:NO_COLOR="1"
   python research/pai.py
   ```
2. Verify ANSI color escape codes are omitted while Unicode block characters and DECSTBM pinning remain fully functional (Finding FN).
3. Clear environment variable:
   ```powershell
   Remove-Item Env:\NO_COLOR
   ```

### Test 8: `PAI_NO_PINNED_HEADER=1` Opt-out
1. Run in PowerShell:
   ```powershell
   $env:PAI_NO_PINNED_HEADER="1"
   python research/pai.py
   ```
2. Verify standard non-pinned startup banner is displayed; verify terminal behaves in classic scrolling mode without DECSTBM margin sequences.
3. Clear environment variable:
   ```powershell
   Remove-Item Env:\PAI_NO_PINNED_HEADER
   ```

### Test 9: Piped Subcommand Isolation (Finding FK)
1. Run in PowerShell:
   ```powershell
   python research/pai.py chat "what is the date" --json | python -c "import sys, json; data = json.load(sys.stdin); print('Parsed successfully:', data['success'])"
   ```
2. Verify output is `Parsed successfully: True` without JSON parsing failures, trailing escape sequences, or cursor jumps.

---

## Honest Limitations Record
- **Terminal Scrollback Limitation**: As documented in ADR-014, DECSTBM margins (`\033[top;bottom r`) in standard terminal emulators (such as Windows Terminal and xterm) prevent lines that scroll past the margin boundary from being retained in the host terminal window scrollback buffer. Users can review recent session history using the in-memory `/history [N]` command or disable pinned margins via `PAI_NO_PINNED_HEADER=1`.
- **Legacy Console Host (conhost.exe)**: On older Windows 10 releases lacking Virtual Terminal Processing support, PAI falls back cleanly to unstyled non-pinned banners and ASCII characters.
