# Release N+1 Freeze Checklist & Evaluation Window Guide

**Document ID:** `docs/FREEZE_CHECKLIST.md`  
**Purpose:** Defines the exact sequence, verification commands, and operational procedures required to freeze Release Candidate `v1.1.0-rc2` and execute the 14-day N+1 Evaluation Window.  
**Freeze Definition:** The "Freeze" is formally defined as the exact moment the git tag (e.g. `v1.1.0-rc2`) exists on the specific commit whose `research/` and `core/` tree IDs are recorded. From that moment forward, strictly NO code modifications to `research/` or `core/` may occur.

---

## 1. Freeze Preconditions (Reviewer Addendum 2026-10-28)

All preconditions must be verified and formally accepted before tagging the freeze candidate:

- [ ] **Precondition 1 (EB & EC Fixes & Manual Proof):**
  - Findings EB (Ollama environment filtering preserves operational variables) and EC (double-quote-only Windows tokenizing) are committed and verified.
  - Owner runs manual proof checklist ([`docs/evidence/MANUAL_PROOF_OLLAMA_SERVICE.md`](evidence/MANUAL_PROOF_OLLAMA_SERVICE.md)) on real Windows host and records PASS.
- [ ] **Precondition 2 (CI Green on Branch):**
  - GitHub Actions CI runs on branch `build-stage` and reports green on all 3 jobs (`python-research`, `rust-core`, `linux-portability`).
- [ ] **Precondition 3 (Decision D10 Decided):**
  - Formal confirmation of Decision D10: PAI never downloads Ollama directly; the installer's finished page provides direct guidance/link to the official installer.
- [ ] **Precondition 4 (Signed Model Catalog Distribution & Freshness Decided - Finding EF & EH):**
  - Signed catalog is bundled as a payload file (`catalog.json` and signature) read by default from installation root (`Path(__file__).parent / "catalog.json"`).
  - Option A accepted: Bundled catalog has no freshness limit; version and signature protect it. External `--catalog` keeps the 90-day rule.
- [ ] **Precondition 5 (Trust Root & Catalog Key Custody - Finding EH):**
  - Offline Ed25519 private key for `rel-1` is held exclusively by repository owner (never committed or logged).
  - First canonical signed catalog is generated via `tools/sign_catalog.py` and verified against `research/trust.json`.
- [ ] **Precondition 6 (Branding Touch-up & Icons Rebuilt):**
  - Minor stray mark on logo touched up; `tools/make_icons.py` re-run to regenerate final `.ico` and wizard BMPs.
- [ ] **Precondition 7 (Licence Clarification - Finding EH & D8):**
  - Owner defines the open-source licence (e.g. MIT, Apache-2.0) and adds `LICENSE` file referenced in installer agreement clause 6.
- [ ] **Precondition 8 (Manual Installer Checklist on New Build):**
  - Repeat short installer check (reject non-empty directory, per-user install, PATH verified in fresh shell, uninstall cleanly removes marker and files).

---

## 2. Freeze Execution Commands

When all preconditions above are marked complete, execute the freeze in a single administrative session:

### Step 2.1: Final Tree and Binary Hash Audit
Run verification and record exact tree IDs and binary SHA-256:
```powershell
# 1. Verify Core Tree invariant (must match 14c60746ca9a41d91aafd88cc0c7d98719cfe3a9)
git rev-parse HEAD:core

# 2. Record Research Tree ID to be pinned
git rev-parse HEAD:research

# 3. Verify evaluated binary SHA-256 (must match 6f13d49463c757f2f3e43506f9743c37f602196544ce8fa85d5c5ce9332e3efe)
CertUtil -hashfile core/target/release/pai-core.exe SHA256
```

### Step 2.2: Tag Freeze Candidate (Declares the Freeze)
The freeze begins the moment the candidate tag is created on the exact commit audited above:
```powershell
git tag -a v1.1.0-rc2 -m "Release Candidate 1.1.0-rc2 for 14-day N+1 Evaluation Window"
```

### Step 2.3: Build Final Payload & Installer
Build the complete installer using `packaging/build_installer.py`. Note that payload contents and catalog signatures are verified during the build; ADR-005 detached release-manifest signing is part of final post-window distribution and is NOT required for a candidate build.
```powershell
python packaging/build_installer.py --version 1.1.0-rc2 --tag v1.1.0-rc2
```
Output is compiled by Inno Setup into `dist/PAI-Setup-1.1.0-rc2-x64.exe`. Record its SHA-256:
```powershell
CertUtil -hashfile dist/PAI-Setup-1.1.0-rc2-x64.exe SHA256
```

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
     - `research/` tree ID: `<recorded from Step 2.1>`
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
