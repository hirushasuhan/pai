# Release N+1 Freeze Checklist & Evaluation Window Guide

**Document ID:** `docs/FREEZE_CHECKLIST.md`  
**Purpose:** Defines the exact sequence, verification commands, and operational procedures required to freeze Release Candidate `v1.1.0-rc4` and execute the 14-day N+1 Evaluation Window.  
**Freeze Definition:** The "Freeze" is formally defined as the exact moment the git tag (e.g. `v1.1.0-rc4`) exists on the specific commit whose `research/` and `core/` tree IDs are recorded. From that moment forward, strictly NO code modifications to `research/` or `core/` may occur.

---

## 1. Freeze Preconditions (Reviewer Addendum 2026-10-28)

All preconditions must be verified and formally accepted before tagging the freeze candidate:

- [x] **Precondition 1 (EB & EC Fixes & Manual Proofs - Accepted in Commit `d13db15`):**
  - Findings EB (Ollama environment filtering preserves operational variables) and EC (double-quote-only Windows tokenizing) are committed and verified.
  - Owner ran manual proof checklists on real Windows host and recorded PASS:
    - Shell UI ([`docs/evidence/MANUAL_PROOF_SHELL_UI.md`](evidence/MANUAL_PROOF_SHELL_UI.md)): Rows M-UI-01 through M-UI-07 all verified PASS across terminal emulators.
    - Managed Ollama Service ([`docs/evidence/MANUAL_PROOF_OLLAMA_SERVICE.md`](evidence/MANUAL_PROOF_OLLAMA_SERVICE.md)): Steps 1 through 4 (including "never" consent mode) verified PASS and signed off.
- [ ] **Precondition 2 (CI Green on Candidate Commit):**
  - GitHub Actions CI runs on branch `build-stage` and reports green on all 3 jobs (`python-research`, `rust-core`, `linux-portability`).
- [x] **Precondition 3 (Decision D10 Decided):**
  - Formal confirmation of Decision D10: PAI never downloads Ollama directly; the installer's finished page provides direct guidance and link to the official installer.
- [x] **Precondition 4 (Signed Model Catalog Distribution & Freshness Decided - Finding EF & EH):**
  - Signed catalog is bundled as a payload file (`catalog.json` and signature) read by default from installation root (`Path(__file__).parent / "catalog.json"`).
  - Option A accepted: Bundled catalog has no freshness limit; version and signature protect it. External `--catalog` keeps the 90-day rule.
- [x] **Precondition 5 (Trust Root & Catalog Key Custody - Finding EH & EO):**
  - Offline Ed25519 private key for `rel-1` is held exclusively by repository owner (never committed or logged).
  - First canonical signed catalog is generated and committed to `research/catalog.json` via the 5-step procedure:
    1. Prepare `catalog_input.json` with model definitions, digests, and measured profiles. [Completed in commit `9734457`]
    2. Sign: `python tools/sign_catalog.py --catalog docs/catalog/catalog_input_2026-11-03.json --private-key-file <offline_key_path> --out research/catalog.json`. Verify the printed `Trust root:` line matches `research/trust.json`. [Completed]
    3. Commit `research/catalog.json` to git. [Completed in commit `e618920`]
    4. Regenerate evidence logs on the new clean tree via `python tools/save_unit_test_evidence.py`.
    5. Record new research tree ID and update pins:
       - **New Pinned Research Tree ID:** `9b71e2e4c597a22b86e53e08d3396a5321659939` (updated in Antigravity continuous agent, internet, fact-checking & desktop app)
       - Baseline `v1.0.0-rc1` research tree ID: `506e520b33a0af8c3f0276114483ce26b9bd3787`
    *(The private key path is never written to any file, log, or commit message).*
- [x] **Precondition 6 (Branding Touch-up & Icons Rebuilt - Accepted in Commit `d13db15`):**
  - Dedicated stylized PAI mark placed in `public/PAI Logo.png`. `tools/make_icons.py` updated with dynamic bounding box detection to rebuild `packaging/assets/pai.ico` (7 sizes), `wizard-large.bmp` (164x314), `wizard-small.bmp` (55x55), and `public/pai-logo-512.png` (< 200 KB).
- [x] **Precondition 7 (Licence Clarification - Finding EH & D8):**
  - Owner confirmed Decision D8: source code is released under the MIT License (`LICENSE` in repository root and installer agreement clause 6).
- [ ] **Precondition 8 (Manual Installer Checklist on New Build):**
  - Repeat short installer check (reject non-empty directory, per-user install, PATH verified in fresh shell, uninstall cleanly removes marker and files) in a clean Windows Sandbox/VM.
- [x] **Finding AV (Repository Visibility & Credential Rotation Confirmation - Closed 2026-11-08):**
  - Owner confirmation in chat (2026-11-08):
    1. Orphaned commit `f781919`: Formally accepted in writing the residual exposure of unreachable orphaned commit `f781919` without a support purge.
    2. Credential rotation: Confirmed all personal credentials/tokens from prior history were rotated on 2026-10-20.

---

## 2. Freeze Execution Commands (Milestone D2b Procedure)

When all preconditions above are marked complete, execute the freeze strictly in this sequence:

### Step 2.1: Pre-Freeze Push to `build-stage` and CI Verification
User approves in chat: push candidate commit to `build-stage`:
```powershell
git push origin master:build-stage
```
Wait for GitHub Actions run to complete green across all 3 jobs (`python-research`, `rust-core`, `linux-portability`).

### Step 2.2: Tag Candidate Commit (Declares the Freeze)
User approves in chat (after Finding AV confirmation):
Annotate tag `v1.1.0-rc4` on the exact candidate commit and push the tag only (never push master):
```powershell
git tag -a v1.1.0-rc4 <candidate_sha> -m "Release Candidate 1.1.0-rc4 for 14-day N+1 Evaluation Window"
git push origin v1.1.0-rc4
```

### Step 2.3: Verify Tagged Trees Invariant
Verify that the tag holds the exact pinned tree IDs:
```powershell
# 1. Verify Core Tree invariant (must match 14c60746ca9a41d91aafd88cc0c7d98719cfe3a9)
git rev-parse v1.1.0-rc4:core

# 2. Verify Research Tree invariant (must match 9b71e2e4c597a22b86e53e08d3396a5321659939)
git rev-parse v1.1.0-rc4:research

# 3. Verify evaluated binary SHA-256 with mandatory flag (must match 6f13d49463c757f2f3e43506f9743c37f602196544ce8fa85d5c5ce9332e3efe)
python tools/check_pins.py --ref v1.1.0-rc4 --require-binary
```

### Step 2.4: Build Final Payload & Installer from Tag
Build the complete installer directly from the tag:
```powershell
python packaging/build_installer.py --version 1.1.0-rc4 --tag v1.1.0-rc4
```
Verify the payload manifest fields:
- `catalog_source`: `research-tree`
- `bundled_catalog`: `true`
- `catalog_sha256`: matches SHA-256 of `research/catalog.json` in the tag.

Record the installer SHA-256:
```powershell
CertUtil -hashfile dist/PAI-Setup-1.1.0-rc2-x64.exe SHA256
```

### Step 2.5: User Runs Precondition 8 Installer Checklist
User runs the installer check in a clean Windows Sandbox/VM per Precondition 8. The 14-day evaluation window begins only after Precondition 8 is verified and accepted.

---

## 3. Launching the 14-Day N+1 Evaluation Window

### Day 0: Initial Clean Setup & Telemetry Reset
1. Run the generated installer `dist/PAI-Setup-1.1.0-rc2-x64.exe` to install PAI to `%LOCALAPPDATA%\Programs\PAI`.
2. Open a fresh terminal (PowerShell or CMD) and verify PATH:
   ```powershell
   where pai
   pai --version
   ```
3. Archive development/test comparisons and reset the active shadow log cleanly:
   ```powershell
   pai clear-shadow --yes
   ```
4. Verify window status is initialized at 0 organic comparisons:
   ```powershell
   python tools/check_n_plus_1.py --installed
   ```
5. **Record Window Start:** Create `docs/evidence/WINDOW_START_RECORD.md` with:
   - Window Start Time (UTC)
   - Installer SHA-256 hash (`dist/PAI-Setup-1.1.0-rc2-x64.exe`)
   - Three Evaluated Pins:
     - `core/` tree ID: `14c60746ca9a41d91aafd88cc0c7d98719cfe3a9`
     - `research/` tree ID: `9b71e2e4c597a22b86e53e08d3396a5321659939`
     - `pai-core.exe` SHA-256: `6f13d49463c757f2f3e43506f9743c37f602196544ce8fa85d5c5ce9332e3efe`

---

## 4. Daily Operational Protocol During the Window

The 14-day evaluation window runs strictly on the **installed copy of PAI from PATH**.

### Critical Window Invariants
- **Installed Binary Only:** During the window, use ONLY the installed `pai` command from PATH. **NEVER** run `python research/pai.py ...` from the repository, because it writes to the same `~/.pai` telemetry with potentially different code, which contaminates and invalidates the evaluation window.
- **Zero Tree Changes:** Do NOT edit, touch, or commit changes to `research/` or `core/`.
- **Zero Binary Rebuilds:** Do NOT recompile `core/target/release/pai-core.exe`. Only one binary hash (`6f13d494...`) may appear in shadow telemetry.
- **Permitted Work:** Work during the window is strictly restricted to `packaging/`, `tools/`, and documentation (`docs/`).

### Daily User Workflow (Days 1–14)
1. **Daily CLI Usage:** Use `pai` as your everyday assistant from terminal:
   - Coding: `pai code "<task prompt>"`
   - Analysis: `pai analyze "<folder>"`
   - Documentation: `pai docs "<document>"`
   - Forecasting: `pai forecast "<csv file>"`
   - Interactive Shell: `pai` (chat, `/doctor`, `/models`, etc.)
2. **Daily Telemetry Check:**
   At the end of each working day, check window progress:
   ```powershell
   python tools/check_n_plus_1.py --installed
   ```
   Confirm:
   - `Organic CLI Comparisons` is increasing towards $\ge 300$.
   - `Shadow Discrepancies` remains strictly `0`.
   - `Evaluated Tree Status` and `Binary Hash Count` remain 1.
   - Output reports: `VERDICT: Window in progress (...)`.

---

## 5. Window Exit Criteria (Release Gate for 1.1.0 Final)

At the completion of Day 14, verify all exit criteria:
1. $\ge 14.0$ continuous days of evaluation span elapsed.
2. $\ge 300$ organic CLI shadow comparisons recorded.
3. Strict $0$ discrepancy count across all runs.
4. Exactly $1$ binary hash recorded across all telemetry (`6f13d494...`).
5. Zero binary rebuilds.
6. Core tree and Research tree byte-identical to frozen pins.
7. `python tools/check_n_plus_1.py --installed` reports:  
   `VERDICT: Release N+1 operational criteria SATISFIED. Ready for candidate review.`
