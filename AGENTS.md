# AGENTS.md — Personal Agentic AI (PAI)

Guidance for AI coding agents and contributors working in `personal_agentic_ai`.

---

## 1. Mandatory Rule: Keep Trust Boundary Diagram & STRIDE Updated With Features

**Every feature change MUST update the threat documentation.** Whenever you add, modify, or remove any feature or boundary-crossing behavior, you **MUST** update:
1. [docs/TRUST_BOUNDARY_DIAGRAM.md](docs/TRUST_BOUNDARY_DIAGRAM.md) — Update the Mermaid trust boundary diagrams and the `B1`–`B8`+ boundary inventory table.
2. [docs/STRIDE_THREAT_MODEL.md](docs/STRIDE_THREAT_MODEL.md) — Evaluate all 6 STRIDE categories (**S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege) for the feature and record implemented mitigations, tests, and honest open/residual gaps.
3. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — Add or update numbered Threat Register rows (`T1`–`T35`+) whenever threats, statuses, or boundaries change.

### Trigger Checklist (Updates Required When Any of These Change)
- **Desktop API / UI**: New or modified HTTP routes in `desktop/bridge_server.py`, CORS/auth headers, static assets/DOM rendering in `desktop/ui/`, or Tauri commands/permissions/CSP in `desktop/src-tauri/`.
- **CLI & Agent Commands**: New subcommands, slash commands, or flags in `research/pai.py`, `research/shell.py`, `research/main.py`, or `core/src/main.rs`.
- **Network & External Integrations**: New outbound URLs, cloud AI providers/custom endpoints (`research/cloud_ai.py`), web search/grounding (`research/internet_service.py`, `research/network_pipeline.py`), or GraphQL endpoints (`research/graphql_agent.py`).
- **Tools, MCP & Automation**: New MCP transports/servers (`research/mcp_client.py`), `ToolBroker` tools/grants (`research/capabilities.py`), desktop/browser automation (`research/automation.py`), or Antigravity steering (`research/antigravity_driver.py`).
- **Execution & Sandboxes**: Changes to `research/ast_guard.py`, `research/sandbox_win32.py`, `research/sandbox_linux.py`, `research/sandbox_policy.py`, `research/verify_loop.py`, `research/eval_harness.py`, or `core/src/verify_loop.rs`.
- **Local Storage, Secrets & Updates**: New persistent files under `~/.pai/` (`auto_memory.py`, `cowork.py`, `config.py`, `cloud_ai.json`), keyring/vault changes, or updater/installer changes (`research/updater.py`, `core/src/updater.rs`, `desktop/apply_pending_update.py`, `packaging/`).

### Accuracy Rules for Security Updates
- Never mark a control as enforced across the whole app if it only protects the CLI (`research/`) and is bypassed in `desktop/bridge_server.py` (or vice versa). Document the exact scope and open gaps honestly.
- Every new security guard requires at least one **negative-control test** per [docs/DEFINITION_OF_DONE.md](docs/DEFINITION_OF_DONE.md).

---

## 2. Repository Architecture

PAI uses a multi-tier architecture:
- **`core/` (Rust 2021, `pai-core`)**: Memory-safe policy core and JSON stdin/stdout bridge (`tier.rs`, `url_policy.rs`, `ingest.rs`, `verify_loop.rs`, `updater.rs`, `ed25519.rs`, `bridge.rs`, `conformance.rs`, `win32.rs`).
- **`research/` (Python 3.12+ CI target, stdlib-first)**: CLI (`pai.py`, `shell.py`, `main.py`), Rust IPC bridge (`pai_core_bridge.py` with shadow differential comparison), sandboxes (`sandbox_win32.py`, `sandbox_linux.py`, `sandbox_policy.py`, `ast_guard.py`), capability broker (`capabilities.py`), ingestion/network (`ingest.py`, `net_guard.py`, `outbound_policy.py`, `raw_http.py`, `data_verifier.py`), model routing/config (`router.py`, `config.py`, `service_manager.py`, `cloud_ai.py`, `quota_engine.py`), and agent orchestration (`agent_core.py`, `verify_loop.py`, `eval_harness.py`, `mcp_client.py`, `cowork.py`, `council.py`, `multi_agent.py`, `auto_memory.py`, `automation.py`, `antigravity_driver.py`).
- **`desktop/` (Tauri 2.0 + Python Loopback Bridge)**: Native Windows workstation (`desktop/src-tauri/`, `pai-desktop.exe`), frontend (`desktop/ui/`), local HTTP server on `127.0.0.1:8765` (`desktop/bridge_server.py`), Win32 folder picker (`desktop/bin/pai_folder_picker.cs`), and update applicator (`desktop/apply_pending_update.py`).
- **`hardware/` (C / C++)**: Phase 2 hardware telemetry daemon charter (see `hardware/README.md`).
- **`packaging/`**: Windows Inno Setup installer (`pai.iss`), reproducible payload builder (`build_payload.py`), and native C launcher (`packaging/launcher/launcher.c` -> `pai.exe`) enforcing BCrypt SHA-256 verification and clean Python env.
- **`tools/`**: Verification & release tooling (`check_pins.py`, `check_secrets.py`, `check_n_plus_1.py`, `test_shadow_ba_gate.py`, `windows_parity_run.py`, `sign_catalog.py`).
- **`docs/`**: Specifications, ADRs (`docs/adr/`), Safety Constitution (`docs/CONSTITUTION.md`), [TRUST_BOUNDARY_DIAGRAM.md](docs/TRUST_BOUNDARY_DIAGRAM.md), [STRIDE_THREAT_MODEL.md](docs/STRIDE_THREAT_MODEL.md), and [THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## 3. Hard Repository Invariants

1. **Security Claims Policy (`research/tests/test_claims.py`)**:
   - Do **not** write unfalsifiable claims in docs, code comments, or UI (such as `"100% secure"`, `"fully verified"`, `"cannot be hacked"`, or `"zero memory leak"` — see `BANNED` regex in `research/tests/test_claims.py`; lines quoting banned phrases must include `claims-lint: quote`). <!-- claims-lint: quote -->
   - Use *defense in depth* and tie every security claim to a named test or a named residual risk in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
2. **Rust `unsafe` Isolation (ADR-009)**:
   - `core/src/lib.rs` and `core/src/main.rs` enforce `#![deny(unsafe_code)]`.
   - `core/src/win32.rs` is the **only** file in `core/src/` permitted to contain `unsafe`. CI fails if `unsafe` appears in any other `.rs` file under `core/src/`.
3. **Cross-Language Conformance Parity (ADR-004)**:
   - Any logic shared between Python (`research/`) and Rust (`core/src/`) — `tier`, `url_policy`, `ingest`, `verify_loop`, `ed25519` — must update **both** implementations, regenerate/update `research/conformance/*.json`, and pass `conformance.py --fuzz 10000` and differential tests (`PAI_USE_RUST_CORE=0` and `1`).
4. **Safety Constitution & Trust Root (`docs/CONSTITUTION.md`, `research/trust.json`)**:
   - `research/trust.json` pins the SHA-256 hash of `docs/CONSTITUTION.md` and the Ed25519 public key (`rel-1`). Do **not** modify `docs/CONSTITUTION.md` or `research/trust.json` without explicit owner authorization.
5. **Secrets & Hygiene (`tools/check_secrets.py`, Threat T22)**:
   - Never commit `.env`, `cloud_ai.json`, `credentials.json`, `release.key`, `tokens.json`, or live API keys.
   - Secret-scanner test inputs in `research/conformance/` or `research/tests/` must be constructed dynamically at runtime (e.g., `text_parts` / `"".join(...)`) so `scan_secret_content` and `tools/check_secrets.py` stay clean at rest.
   - Do not record machine-specific absolute user paths (e.g., `C:\Users\...`) in `docs/evidence/` logs.
6. **Tree & Binary Pins (`tools/check_pins.py`, `tools/check_n_plus_1.py`)**:
   - `packaging/build_payload.py`, `tools/check_n_plus_1.py`, and `docs/FREEZE_CHECKLIST.md` pin git tree hashes for `core/` and `research/` plus `pai-core.exe` SHA-256. During an active release freeze or N+1 window, do not modify `core/` or `research/` without accounting for pin checks.
7. **Definition of Done (`docs/DEFINITION_OF_DONE.md`)**:
   - Every new check needs a failing negative control, platform test coverage must be reported honestly (never claim skipped checks passed), and numbers in docs/reports must come directly from tool output.

---

## 4. Build, Lint & Verification Commands

### Python Research & Policy Suites (run from `research/` unless noted)
```powershell
cd research
python -m unittest discover -s tests -v                         # Full unittest suite (incl. test_claims.py)
python -m unittest discover -s tests -p "test_claims.py" -v     # Security claims lint across repo docs/code
python conformance.py --fuzz 10000 --seed 42                    # Cross-language differential fuzz verification
```

### Rust Core (`core/`)
```powershell
cd core
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings -A clippy::needless_bool
cargo test
cargo run -- --conformance ../research/conformance
cargo build --release
```

### Cross-Repo, Differential & Pin Audits (run from repo root)
```powershell
python tools/check_secrets.py                        # Tracked-file secret leak scanner
python tools/check_pins.py                           # Core/research tree & binary pin audit
python tools/test_shadow_ba_gate.py                  # Shadow BA/BB gate tests
python tools/windows_parity_run.py                   # Windows real-tree parity regression gate
```

### Differential Rust-vs-Python Integration Suites (from `research/`)
Run both `$env:PAI_USE_RUST_CORE="0"` and `$env:PAI_USE_RUST_CORE="1"` against:
- `tests/test_bridge_differential.py`
- `tests/test_ingest_differential.py`
- `tests/test_updater_differential.py`

### Mandatory Post-Feature Check Before Finishing Any Task
1. Confirm whether your change crossed or altered any boundary in [docs/TRUST_BOUNDARY_DIAGRAM.md](docs/TRUST_BOUNDARY_DIAGRAM.md) or threat in [docs/STRIDE_THREAT_MODEL.md](docs/STRIDE_THREAT_MODEL.md) / [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and update all three if applicable.
2. Run `python -m unittest discover -s tests -p "test_claims.py" -v` (from `research/`) and `python tools/check_secrets.py` (from repo root) after final edits.
3. Run the relevant unit, conformance, and differential tests for the modified subsystem.
