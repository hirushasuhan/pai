# Manual Verification Checklist: ADR-014 Managed Ollama Service Lifecycle

**Document ID:** `docs/evidence/MANUAL_PROOF_OLLAMA_SERVICE.md`  
**Purpose:** Pre-freeze manual proof checklist for the repository owner on Windows host (Reviewer Addendum 2026-10-28).  
**Status:** Template prepared (to be executed by owner prior to freeze).  

---

## Environment & Machine Profile

| Field | Value / Observation |
|---|---|
| **Date & Time (Local / UTC):** | `[ Owner to fill: e.g. 2026-10-28 21:00 ]` |
| **Operating System:** | Windows 11 Pro 64-bit |
| **Git Commit / Ref:** | `[ Owner to fill: e.g. 7920c8b / master ]` |
| **Python Runtime:** | Python 3.14.0 |
| **Ollama Executable Path:** | `%LOCALAPPDATA%\Programs\Ollama\ollama.exe` |

---

## Verification Steps

### Step 1: Clean Startup with User Consent
- [ ] **Action:** Exit Ollama from the Windows system tray icon (right click -> Quit). Open Task Manager and confirm that zero `ollama.exe` processes are running.
- [ ] **Action:** In a fresh PowerShell or CMD terminal, run:
  ```powershell
  python research/pai.py chat "hi"
  ```
- [ ] **Observation:**
  - PAI displays prompt: `Start local Ollama service now? [y/N/always/never] (y: start now, asks each time; always/never are remembered): `
  - Type `y` and press Enter.
- [ ] **Verification:**
  - `ollama.exe serve` starts in the background without creating a GUI window.
  - Model generates response to `"hi"` and prints to terminal.

---

### Step 2: Deterministic Process Tree Termination
- [ ] **Action:** After Step 1 finishes and PAI exits back to the shell prompt, check Task Manager immediately.
- [ ] **Verification:**
  - Neither `ollama.exe` nor any child runner process (`ollama_llama_server.exe` / GPU runners) is running.
  - Process tree was cleanly and completely terminated on PAI exit.

---

### Step 3: Non-Interference with External Ollama Instances
- [ ] **Action:** Start Ollama manually from the Windows Start Menu. Confirm the Ollama icon appears in the system tray.
- [ ] **Action:** In terminal, run:
  ```powershell
  python research/pai.py chat "hi"
  ```
- [ ] **Observation:** PAI detects the running service immediately (no prompt shown); model responds.
- [ ] **Verification:**
  - After PAI command completes and exits, check the system tray and Task Manager.
  - The pre-existing Ollama service **remains running undisturbed**.

---

### Step 4: Strict Enforcement of "Never" Consent Mode
- [ ] **Action:** Exit Ollama from the system tray again (confirm no running `ollama.exe`).
- [ ] **Action:** In `~/.pai/config.json`, set or verify:
  ```json
  {
    "ollama_start_consent": "never"
  }
  ```
- [ ] **Action:** In terminal, run:
  ```powershell
  python research/pai.py chat "hi"
  ```
- [ ] **Verification:**
  - PAI prints clean single-sentence guidance:
    `Local AI service (Ollama) is not running on 127.0.0.1:11434. Run 'pai setup' or start Ollama from the Start Menu.`
  - No raw `[WinError 10061]` socket traceback is displayed.
  - Zero background processes are spawned.

---

## Owner Sign-off

- **Result:** [ ] PASS  /  [ ] FAIL
- **Notes / Observations:** __________________________________________________
- **Signed:** ____________________________  **Date:** ________________________
