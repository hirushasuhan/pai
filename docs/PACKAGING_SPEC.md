# Packaging, Installer and First-Run Model Setup (specification)

**Status:** Proposed. Written 2026-10-27 at the owner's request. Decision record: [ADR-013](adr/ADR-013-installer-and-distribution.md).
**Audience:** the owner and the coding agent. This document is a plan and a set of acceptance criteria. It is not legal advice.

## 0. What the owner asked for

1. One downloadable file that installs PAI (a "single .exe" release).
2. An agreement shown during installation, stating the software must not be used for wrongful purposes; installation stops if it is declined.
3. The installer also sets up what PAI needs: the Ollama server first, then local models, chosen to fit the specification of the PC.
4. An `install.bat` that configures the machine so any user can type `pai` in their own command prompt.
5. A progress bar with sizes while models download.
6. For a new user, the installer offers the latest open-weights models that suit that PC and their download sizes, from a list that is separate from the models the project itself was developed with.

## 1. Sequencing with the N+1 evaluation window (read first)

**Window Postponement (2026-10-27):** The N+1 window start tentatively recorded on 2026-10-27 for tag `v1.0.0-rc1` has been formally postponed by owner decision and accepted by the reviewer. The few hours of telemetry collected on 2026-10-27 are archived via `pai clear-shadow` and do not count toward evaluation quotas. Because any modification to `research/` or `core/` restarts the 14-day evaluation window, implementing planned features (setup in `pai`, managed Ollama start, interactive shell) upfront in the Build Stage avoids invalidating a 14-day run.

The sequenced release order:
1. **Build stage (no window running; each change reviewed sequentially):**
   - Close Milestone P5: Resolve Finding DK (safe manifest-scoped rollback, non-empty directory guard), run the owner's manual installer checklist on `1.1.0-rc1`, and confirm decisions D8 to D11.
   - Milestone P6: Move setup wizard into `pai setup` in `research/` (own reviewed commit).
   - ADR-014 Managed Ollama Start: Auto-start local Ollama daemon, Authenticode verification on `ollama.exe`, loopback binding, child PID tracking, consent prompt (own reviewed commit).
   - ADR-014 Interactive Shell: Terminal detection guard (`isatty`), conversational REPL, slash dispatcher to canonical subcommands, interrupt handling, banner (own reviewed commit).
   - Resolve Decision D17 (Ollama start consent default).
2. **Freeze:**
   - One candidate commit with CI green on all three jobs (`rust-core`, `python-research`, `linux-portability`) and reviewer acceptance of all build stage changes.
   - Tagged as a candidate release (e.g. `v1.1.0-rc2`).
   - The standalone installer is built from that tag.
   - Immutable hash pins recorded: `research/` tree, `core/` tree, `pai-core.exe` SHA-256, and installer SHA-256.
3. **Evaluation Window (at least 14 days, at least 300 organic CLI comparisons, 0 discrepancies, one binary hash, no rebuild, trees equal to pin):**
   - The user installs the candidate using `PAI-Setup-<version>-win-x64.exe` and uses the installed `pai` from PATH for daily work; this provides empirical evidence of the shipped product.
   - `pai clear-shadow` is executed once at the start of the window and the start timestamp is logged.
   - Neither `research/` nor `core/` may be modified during the window. Any change to the pinned trees restarts the 14-day window unless the reviewer rules otherwise in writing.
   - Allowed work during the window: documentation, `tools/`, installer packaging scripts, `install.ps1` (P2b), and Linux portability work that does not touch the evaluated trees.
4. **Post-Window:**
   - Reviewer audit of evaluation window evidence.
   - Removal of Python reference fallback (separate commit, separate review).
   - Tag `v1.0.0`.
   - The official 1.1.0 installer is built from that tag as specified below.

- **Note on reproducibility (Finding DH):** Only the payload directory and archive (`dist/payload`) are bit-for-bit reproducible across builds. The Inno Setup compiled installer (`PAI-Setup-*.exe`) embeds internal compilation timestamps into PE headers and table structures; distinct ISCC invocations therefore produce distinct file hashes despite identical input payloads.
- **Window note (2026-10-27, Finding DH):** `tools/check_n_plus_1.py` was adjusted to allow health check reports to continue when `pai doctor` exits non-zero due to low free host RAM, provided its JSON output contains `shadow_telemetry`. The script is located in `tools/` (outside evaluated `core/` and `research/` trees), does not loosen evaluation criteria, and strictly enforces tree identities and the pinned binary SHA-256.

Dev-checkout helpers that already exist in the repository root (`pai.cmd`, `install.bat`) are for people who run from a git checkout with their own Python. They are not the end-user installer: they need a system `python` on PATH and do not pin the core binary. They stay as the "developer install".

## 2. Distribution form

**Primary:** one file, `PAI-Setup-<version>-x64.exe`, built with Inno Setup (per-user install, no administrator rights). The wizard shows the agreement, installs the payload, adds `pai` to the user PATH, then runs the setup steps in section 4.

**Payload inside the installer** (all pinned by SHA-256 in a manifest signed under ADR-005):

- an embeddable CPython distribution (pinned version and hash);
- the `research/` tree exactly as tagged (not frozen, not repacked);
- `pai-core.exe` built from the tagged `core/` (hash recorded in the release notes);
- `pai.exe`, a tiny launcher that sets `PAI_CORE_BIN` to the installed binary and `PAI_CORE_SHA256` to its pinned hash, then runs `python research\pai.py %*`;
- `trust.json` (public keys only), the signed model catalog, licence texts, `LICENSE`/agreement files.

**Why not a PyInstaller one-file build as the primary form:** a frozen build changes how `research/` finds its files (`Path(__file__)` based lookups), so it would no longer be the code that was evaluated; it breaks the file-by-file manifest check of ADR-005; it unpacks to a temporary folder on every start; and one-file executables are flagged by antivirus products more often. It can be evaluated later as an extra form once there is a measured reason.

**Secondary (portable):** a zip with the same payload and an `install.bat` that performs the same steps without the wizard (section 7).

## 3. Agreement and acceptable-use notice

- The wizard shows the agreement on its own page; the Next button is enabled only after the user ticks acceptance. Declining ends the installation without changing the machine.
- Acceptance is stored locally (installed version, text hash, timestamp). Nothing is sent anywhere.
- `pai` itself never tells the user it "enforces" the agreement. The agreement is a legal statement of terms and cannot technically stop misuse; the documentation must not claim otherwise (claims-lint applies).
- **Licence compatibility (owner decision D8).** If the project is released under an OSI-approved open-source licence, the licence itself cannot add "no wrongful use" field-of-use restrictions without ceasing to be that licence. Two consistent options: (A, recommended) keep the open-source licence for the source code and present the acceptable-use statement as terms of use and disclaimer for the distributed installer and its documentation, plus a clear warranty disclaimer; (B) use a source-available licence that contains the restriction. A lawyer should review the final text.
- Third-party components have their own terms and must be shown and accepted separately: the Ollama installer (its own licence), and **each model** (some model families come with their own use policies). The model list shows the licence name and link for every model, and a model is installed only after the user has seen its terms.
- Draft text for the owner's lawyer is in Appendix A.

## 4. Install flow

1. **Welcome and agreement** (section 3).
2. **Location:** default `%LOCALAPPDATA%\Programs\PAI`, no administrator rights. Paths with spaces and non-ASCII characters (for example Sinhala user names) must work.
3. **Consent for network use.** The installer lists exactly what it will download and from which hosts before downloading anything (ADR-002, `NET_POLICY.md`): the official Ollama download, the Ollama model registry, and the project's catalog host. Every download is written to the local outbound log. An offline path exists: the user can point to an already-downloaded Ollama installer and to models already present.
4. **Hardware survey** (local only): total and available RAM, free disk on the drive that will hold models, NVIDIA/AMD GPU and dedicated VRAM, CPU features, Windows version. An NPU, if present, is reported as "detected, not used in this version" (ADR-012).
5. **Ollama.** If `ollama` already responds on `http://localhost:11434`, reuse it and record its version. If not, download the official `OllamaSetup.exe`, check its Authenticode publisher and size, then run it. The Ollama documentation lists only a `/DIR` option and no documented silent switches, so the first implementation runs the installer visibly (the user clicks through it) and the implementer tests undocumented unattended switches before relying on them. Ollama needs a recent NVIDIA driver for GPU use; the survey warns when the driver is older than the documented minimum. Fallback: open the official download page and wait. Alternative (decision D10): download the official standalone zip and run `ollama serve` as a child process managed by PAI (this is Stage 2 of ADR-012); it avoids a tray application and a system-wide install, and costs more work and update handling.
6. **Model selection** (section 5) with sizes and licences, then **download with progress** (section 6).
7. **Verify:** `pai doctor --skip-smoke`, then one short `pai chat` request against the chosen model with a time limit. Show the result. Offer `pai calibrate` (long) as optional.
8. **Finish:** explain that a new terminal window is needed for the PATH change and show `pai --help`.

The installer must be safe to re-run (repair/upgrade), and uninstall must remove the files and the PATH entry. It asks whether to keep downloaded models and leaves Ollama installed unless the user chooses otherwise.

## 5. Model catalog and hardware-aware selection

**Catalog.** The list of offered models is a signed JSON file (`catalog.json` plus a detached Ed25519 signature checked against `trust.json`; the catalog version only increases). Maintainers curate it: every entry has its licence read from the official model card, a size taken from the registry manifest, and a measured or estimated memory requirement. "Latest" therefore means "latest curated", not "whatever appeared upstream today" (risk R12). The catalog can be updated without a new installer (`pai models update`). Models already used for development are not special; the catalog is the single source for first-time users. An "advanced" field accepts any Ollama model tag but shows a warning (licence not verified, fit not measured) and requires explicit confirmation.

**Entry fields** (Appendix B has an example): id (Ollama tag), family, parameter count, quantisation, download size in bytes, expected disk size, minimum RAM and VRAM, licence name/link/`license_status` (`verified` or `unverified`), suitable tasks (code, chat, documents, forecast, Singlish/Sinhala), registry manifest digest, and any measured numbers with the machine they were measured on.

**Fit rules** (all inputs from the local survey; thresholds are starting values to be tuned by measurement):

- Disk: free space on the model drive must be at least 1.25 times the total size of the chosen models plus 2 GB; otherwise the model is shown disabled with the reason.
- GPU: a model is "fits on GPU" when its weights plus a context allowance are at most about 85 per cent of the dedicated VRAM; if only partly, mark "partial GPU offload, slower".
- RAM: a model that runs on CPU or partly on CPU must leave headroom for the system; the survey uses total RAM minus a fixed reserve and warns when available RAM at install time is low (close other programs).
- Only entries with `license_status = verified` are pre-selected. Unverified ones are listed under "advanced".
- Preselect one primary model (best verified fit for code and chat) and one small fallback. The user can tick or untick any model that fits, and sees the combined download size and the free space left before confirming.
- The existing router and `pai calibrate` (ADR-008, ADR-010) take over after installation; the installer only chooses starting models.

## 6. Download progress

Use Ollama's pull API (`POST /api/pull`, streamed). The stream sends newline-delimited JSON with `status`, and for downloads `digest`, `total` and `completed` bytes.

- Aggregate by `digest` (a model has several layers) to show one overall bar: overall percentage, downloaded/total in MB or GB, current speed (moving average over a few seconds) and estimated time left. Show the model name and the current status text (`pulling`, `verifying sha256 digest`, `writing manifest`).
- Before starting, read the registry manifest to know the total size, so the bar is determinate from the first second; if the size is unknown, show an indeterminate bar and the bytes so far.
- Console: one redrawn line (carriage return), width-aware, no flicker; if the output is not a terminal, print a line every 5 per cent instead.
- The same events feed the installer window: `pai setup --progress-json` (or `research/pai_setup.py`) writes one JSON object per line (Appendix C) and the Inno Setup page draws the bar from them. One implementation, two displays.
- Interrupted downloads resume (Ollama keeps partial layers). Provide Cancel, retry with back-off on network errors, and a clear message for disk-full and registry errors. A cancelled install leaves PAI usable if the core files were installed.

## 7. `pai` in every user's command prompt

- Add the install folder (or a `bin` subfolder holding `pai.exe`) to the **user** PATH entry in the registry with a script that reads the current value, skips it if the entry already exists, and appends otherwise, then notifies running programs of the change. Do **not** use `setx` for PATH: it can truncate long values. The existing `install.bat` follows the correct pattern (PowerShell, read, test, append); the release version must also handle the duplicate/case check and a PATH that is empty.
- New terminal windows pick up the change; already open windows do not. Say so.
- `where pai` and `pai --version` must work from a fresh `cmd.exe` and a fresh PowerShell after installation; this is an acceptance test.
- Launcher environment: `PAI_CORE_BIN` and `PAI_CORE_SHA256` are set by `pai.exe` (never by a global machine setting), so the binary-trust rules of Finding BE hold; `PATH` lookup of `pai-core` stays off.
- The portable zip's `install.bat` performs: copy payload, PATH step, then `pai setup`. The `pai progress` shortcut in `pai.cmd` is a developer convenience only.

## 8. Security and supply chain

- Publish the SHA-256 of `PAI-Setup-*.exe` with every release and sign the release manifest offline with the ADR-005 key (the key never leaves the offline machine and is never given to the coding agent).
- **Authenticode (Windows code signing) is a separate thing from the ADR-005 key.** Without it Windows SmartScreen warns on download. Options, according to Microsoft's current guidance: Azure Artifact Signing (individuals only in the USA and Canada), an OV certificate (about 150 to 300 USD a year, worldwide, reputation builds over time), SignPath Foundation (free for qualifying open-source projects; the project must be public, which conflicts with a private repository), or self-signed (blocks installation for the public; testing only). Early releases may ship unsigned with a documented warning and the published hash (owner decision D9).
- Downloaded executables (the Ollama installer) are checked (publisher, size, HTTPS only) before they run, and never run from a path another user can write.
- The installer does not bundle model weights (size, and each model's licence must be accepted by the user).
- Release builds keep `PAI_SHADOW_COMPARE` on and the log stays local in the user profile. The agreement must say plainly what is stored and that nothing is sent.
- New code gets hostile-input tests, a threat-register entry and claims-lint, as for every milestone.

### 8.1 Honest limits and operational boundaries (added 2026-10-27)

- **PowerShell ExecutionPolicy Bypass (Finding DF):** When invoking `tools/update_path.ps1` from the Inno Setup installer (`pai.iss`) or portable helper scripts (`install.bat`, `uninstall.bat`), `-ExecutionPolicy Bypass` is specified. This flag is process-scoped strictly to the execution of that specific helper script; it does not change machine-wide or user-wide PowerShell execution policies. This is standard for local installer helper scripts, but security scanners may flag the switch; it is restricted solely to this PATH-management invocation.
- **Test-Only Switches in Production Artifacts (Finding DG):** The Inno Setup installer accepts an optional `/REG_SUBKEY=` command-line parameter, and the PATH scripts inspect the `PAI_REG_SUBKEY` environment variable. These exist exclusively to allow automated test harnesses (such as `tools/test_installer_p5.py`) to redirect PATH modifications to isolated temporary registry test keys without mutating the real user `HKCU\Environment` key. The scripts enforce fail-closed validation: any subkey name that is not `Environment` and does not begin with `Test_` or `PAI_TEST_` is immediately rejected with an error. These switches are strictly test-isolation hooks and are not end-user features.
- **Post-Install Rollback on Failure (Findings DI and DK):** If writing `agreement_acceptance.json` fails or the user PATH update script (`tools/update_path.ps1`) exits non-zero during installation, the installer executes automated rollback: it reverts any partially modified PATH entry, deletes only the files placed by PAI (the installed manifest file list plus generated files `agreement_acceptance.json` and `unins000.*`), removes the target installation folder (`{app}`) only if it is completely empty, and terminates with non-zero exit code (exit code 2 for agreement write failure, exit code 3 for PATH update failure). Pre-existing user files are preserved, and the Inno uninstall registry key is cleaned up. In GUI mode, an informative dialog explains the rollback and termination.
- **Specific Installation Marker and Directory Validation (Finding DL):** To distinguish PAI installations from arbitrary folders containing common files like `manifest.json`, the installer places a dedicated marker file `.pai-install` in the installation root containing the AppId GUID (`{8B7B61CA-C450-4E87-9F1B-4198A82711C9}`). During directory selection and pre-install verification, non-empty directories are accepted only if they contain this verified marker file. Directories containing arbitrary foreign files (such as web application manifests) are rejected. Rollback cleans up generated files (`agreement_acceptance.json`, `AGREEMENT.txt`, `manifest.sig`, `manifest.json`, `manifest.files`, `.pai-install`, `unins*.*`) only when the directory contains the marker or was written by this install run. The `.pai-install` marker functions strictly as an operational accident guard (its GUID is publicly visible in the source repository), not as a security boundary against hostile actors who could synthesize the marker.
- **Flat Relative Path List Rollback and Path Safety (Finding DM):** Rollback reads `manifest.files` (a plain line-delimited relative path list generated by `build_payload.py`), completely avoiding fragile JSON parsing in installer script. Every listed path is strictly validated: any entry that is absolute, begins with `/` or `\`, contains a drive letter `:`, or contains directory traversal (`..`) is rejected and skipped. Hostile entries attempting to delete files outside `{app}` are neutralized.
- **Failed Upgrade Rollback Behavior (Finding DN):** When an upgrade or reinstallation is run over an existing PAI installation and post-install fails (e.g. due to PATH update failure or agreement write failure), rollback removes all files listed in `manifest.files`, the `.pai-install` marker, and the uninstaller registry key. Consequently, a failed upgrade completely removes the previous PAI installation rather than leaving a corrupted, hybrid partial install. The target directory `{app}` is removed only if it is left completely empty (unrelated user files are preserved). The user must re-run the installer to restore a clean installation.

## 9. Test matrix (acceptance)

Run in Windows Sandbox or a clean VM, never on the development profile during the N+1 window.

1. Windows 10 22H2 and Windows 11; no GPU; NVIDIA with 6 GB; AMD integrated GPU only.
2. No Ollama installed; Ollama already installed; Ollama installed but stopped.
3. Low disk space; models drive different from system drive; no network (offline path); network drops during a download (resume).
4. User name with non-ASCII characters and spaces in the install path.
5. Empty PATH; very long PATH; PAI already on PATH; upgrade over an existing install; repair; uninstall (PATH entry gone, files gone, models kept or removed as chosen).
6. Agreement declined: nothing installed, nothing changed.
7. `where pai`, `pai --version`, `pai doctor --skip-smoke`, `pai docs <file>` in a fresh `cmd.exe` and PowerShell.
8. Tampered downloads: a modified Ollama installer, a modified catalog (signature fails), a catalog with a lower version (rejected), a tampered `pai-core.exe` (pinned hash fails, fallback or refusal as designed).
9. Installer payload hash equals the release manifest; `research/` and `core/` tree ids inside the payload equal the tagged commit.
10. Antivirus check of the built installer (for example an online multi-engine scan) recorded in the release notes.

## 10. Milestones (one report each; reviewer checks the whole milestone)

| Milestone | Deliverable | Touches `research/`? |
|---|---|---|
| P0 | This specification, ADR-013, owner decisions D8 to D13 | no |
| P1 | `packaging/build_payload.py`: reproducible payload from a tag, manifest, hash checks | no |
| P2 | `pai.exe` launcher, portable zip with `install.bat` (PATH step, uninstall script) | no |
| P3 | `research/pai_setup.py` (`pai setup`): hardware survey, signed-catalog check, fit rules, Ollama detection and installation, `--progress-json` | no (imports read-only) |
| P4 | Download engine and progress UI (console and installer page), resume and cancel | no |
| P5 | Inno Setup script: agreement page, wizard pages, PATH, safe rollback (Finding DK), uninstall; test matrix of section 9 | no |
| P6 | Build stage (pre-freeze): move the setup wizard into `pai setup` (`research/`) | yes (separate reviewed commit) |
| Managed Ollama | Build stage (pre-freeze): managed local Ollama start, Authenticode check on `ollama.exe`, PID tracking (ADR-014) | yes (separate reviewed commit) |
| Interactive Shell | Build stage (pre-freeze): terminal guard, REPL, slash dispatcher to canonical subcommands (ADR-014) | yes (separate reviewed commit) |
| P1b | Extend `packaging/build_payload.py`: `--platform` (`win-x64`, `linux-x64`), platform field in the manifest, binary-format check (PE or ELF), `dist/` in `.gitignore` | no |
| P2b | `packaging/install.ps1`: the PowerShell one-line bootstrap (section 14); needs D11 and the P2 portable zip | no |
| P7 | Linux: CI build of `pai-core` for Linux, `packaging/install.sh`, Linux hardware survey and Ollama handling, Linux test matrix (section 14.3 to 14.5). Release 1.2.0, labelled preview | no (imports read-only; Linux-only fixes in `research/` only as separate reviewed commits) |

## 11. Decisions the owner must make

- **D8** agreement and licence approach (section 3, option A or B) and legal review.
- **D9** code-signing path (section 8): unsigned for early releases, OV certificate, SignPath (public repository needed), or Store distribution.
- **D10** Ollama: official installer (visible or tested silent) or managed standalone zip.
- **D11** where the catalog and installer are hosted (the repository's release assets are the simplest).
- **D12** minimum Windows version (the Ollama requirement is Windows 10 22H2 or newer).
- **D13** whether the installer may include a first small model for offline installs (default: no).
- **D14** whether the PowerShell one-line install ships with 1.1.0 (default: yes, as a second front door next to `PAI-Setup`, never the only one) and whether the project page shows it as the recommended method (default: no, the installer stays recommended).
- **D15** Linux Python runtime: A) a pinned standalone CPython build shipped in the payload (default, same behaviour on every distribution), or B) the system `python3` above a stated minimum version.
- **D16** Linux support level for 1.2.0: labelled "preview" until a Linux evaluation is recorded (default), or full support from the first release.
- **D17** default consent mode for starting Ollama (ADR-014): Ask once (recommended default), Always, or Never.

## 12. Instructions for the coding agent

1. During the Build Stage: complete P5, P6, managed Ollama start, and interactive shell with sequential reviews. Do not edit `research/` or `core/` once the freeze candidate tag (e.g. `v1.1.0-rc2`) is pinned and the 14-day evaluation window commences. Work during the window is strictly restricted to `packaging/`, `tools/`, and docs.
2. One report per milestone, each with: what changed, the trust-boundary table (installer, network, downloaded executables, catalog, PATH, launcher environment), hostile-input tests with a negative control for each, claims-lint green, CI green.
3. Do not invent model names, sizes or licences. Sizes come from registry manifests, licences from official model cards, and every catalog entry carries its source link and the date it was read.
4. Never ask for, store or generate signing keys. Signing steps are documented for the owner to run offline.
5. Test installers only in a sandbox or VM. Report which machine profile each result came from.

## 13. Versioning and release train (updated 2026-10-27 per postponed window)

The installer is a delivery mechanism, so it is built alongside the core and not left to the very end. The true end of the project (native engine, OS control; Phases 3 to 5) is far away, and waiting for it would delay all real-world testing for months. Problems that only an installer shows (PATH, antivirus and SmartScreen, Ollama and graphics driver differences, non-ASCII user names, low disk) are cheaper to find now.

| Version | Content | Rule |
|---|---|---|
| 1.0.0-rc1 | Baseline Release N preview (tag `v1.0.0-rc1`, commit `8ce81cb`) | Used for initial packaging prototypes (P1–P5) |
| 1.1.0-rc1 | Initial packaging preview build (tag `v1.1.0-rc1`) | Used for manual installer tests in sandbox/VM |
| 1.1.0-rc2 | Freeze candidate (after P5 close, P6 setup in `research/`, managed Ollama, interactive shell) | The 14-day N+1 evaluation window runs on this installed build |
| 1.0.0 | Post-window: Python fallback removed from reference core | Core finished; official v1.0.0 tag |
| 1.1.0 | First installable public release: installer, agreement, `pai` on PATH, Ollama check, hardware-aware model setup, progress bar, interactive shell, managed service | Built from the 1.0.0 tag; core behaviour unchanged; includes PowerShell one-line install if D14 is accepted |
| 1.2.0 | Linux installer (`install.sh`) and Linux `pai-core` build, labelled preview | Needs the Linux items of section 14; Windows 1.1.0 behaviour unchanged |
| 1.5.0 | Automation interface and optional image generation (`docs/ROADMAP.md`) | Entry gate in the ROADMAP |

**Preview builds.** Installer builds made before 1.1.0 are tagged `v1.1.0-rc1`, `-rc2` and so on, labelled "preview", and tested in a sandbox or VM. They are given only to the owner and a few trusted testers, because the evaluation window and the agreement review (D8) are not finished.

**Preview builds and the updater.** The updater keeps the highest version it has seen (anti-rollback). A preview build must not be signed with the number of the final release, and preview installs must not write that state, or the real release could be rejected as "not newer". Preview builds are installed by hand only, `pai --version` shows the tag (for example `1.1.0-rc2`), and the manifest's `tag` field is the source of that text.

**What 1.1.0 may change in `research/`.** Setup, catalog and model-download code (`pai setup`), managed service startup, and interactive shell REPL. The files that make up the evaluated core bridge path (`pai_core_bridge.py`, `ingest.py`, `verify_loop.py`, `updater.py` and the Rust `core/`) must remain byte-identical to the 1.0.0 tag. The release script prints the list of changed files between the two tags and fails if any core files appear in it.

**Release gates for 1.1.0.** The test matrix of section 9 passes on recorded machine profiles; the release manifest is signed offline (ADR-005); the installer's SHA-256 is published; an antivirus scan result is recorded; release notes state what was and was not evaluated; claims-lint and CI are green; decisions D8 to D13 and D17 are recorded.

**Where users download from.** If the repository stays private (Finding AV), release assets and the catalog are not reachable without a login, and the installer could not fetch the catalog. Public downloads need a public host (for example a separate public releases repository or a website). Decide this with D11 before building the download code.

## 14. One-line install (PowerShell) and Linux (added 2026-10-27, proposal until the owner confirms)

### 14.1 Position

The one-line commands are extra front doors to the same payload. They do not get their own logic: `install.ps1` and `install.sh` are thin bootstraps that fetch a version-pinned payload, verify it, show the agreement, unpack it and call the same `pai setup` for Ollama and model setup. `PAI-Setup-<version>-x64.exe` stays the primary, recommended path for ordinary users, because a signed (or at least inspectable) installer with a wizard is easier to trust and to support than a piped script.

### 14.2 PowerShell one-line install (Windows, release 1.1.0 if D14 is accepted)

Command shown on the project page (the version is part of the URL, never "latest"):

```
irm https://<host>/pai/v1.1.0/install.ps1 | iex
```

An inspect-first alternative is shown next to it: download `install.ps1`, compare its SHA-256 with the value on the release page, read it, then run it. For unattended use: `& ([scriptblock]::Create((irm <url>))) -AcceptTerms`, because arguments cannot be passed through a bare `| iex`.

What `install.ps1` does, in order. Each step stops with a plain message and leaves nothing half-installed (all work happens in a staging folder, then one rename):

1. Check Windows version (D12), 64-bit, PowerShell 5.1 or newer; refuse in Constrained Language Mode and point to `PAI-Setup`. Refuse to run elevated unless `-AllowElevated` is given (an elevated run would install into the administrator's profile).
2. Use TLS 1.2 or newer, HTTPS only, one host (the project host). No redirects to other hosts.
3. Download the portable zip of the same version. The script is generated per release and contains the expected SHA-256 of that zip; a mismatch aborts before anything is extracted. A hash fetched from the same place as the zip adds nothing, so the expected value is baked into the script, and the script's own SHA-256 is published on the release page and in the release notes.
4. Extract with path checks (no absolute paths, no `..`, no links), then verify the per-file manifest from P1 (every file's size and SHA-256). Verification of the ADR-005 Ed25519 signature is done by the embedded Python against the key in `trust.json`. Because `trust.json` arrives in the same payload, this proves consistency with that key and not who published it; the script therefore prints the key fingerprint and tells the user to compare it with the project page.
5. Print what will be installed, where (`%LOCALAPPDATA%\Programs\PAI`), the hosts it may contact, and the agreement summary with a link to the full text. Interactive runs require typing `YES`; non-interactive runs require `-AcceptTerms`. Acceptance is stored locally only (section 3).
6. Install per user, update the user PATH with the pattern of Appendix D (never `setx`), write an uninstall script and a per-user (HKCU) uninstall entry, then call `pai_setup.py` for the Ollama check and model selection (sections 4 to 6).

What it must never do: change the execution policy, add Defender exclusions, require administrator rights, add scheduled tasks or services, download anything that is not listed in the manifest or the signed catalog, send telemetry, or run content fetched from any other host. `iex` of a string is not subject to the execution policy, so the design does not rely on the policy as a safeguard; the safeguards are the baked-in hash and the manifest.

Honest limits, to be stated in the user documentation:

- A command that downloads text and pipes it into `iex` is a pattern that security tools look for; the Sigma rule "PowerShell Download and Execution Cradles" (rated high severity) flags `irm` with `iex`. Some managed or corporate machines will block or alert on it. The message printed on failure points to `PAI-Setup`.
- If the download host is compromised, an attacker can replace both the script and the hash that it contains. The mitigations are the published hash and key fingerprint on a second place (the release notes in the repository), version-pinned URLs, and the offline signature on the payload. The risk is smaller than with an unverified script but not zero.
- Authenticode signing of `install.ps1` is possible once a certificate exists (D9). It is not needed for `iex` to work.

### 14.3 Linux installer (release 1.2.0, preview)

Command:

```
curl -fsSL https://<host>/pai/v1.2.0/install.sh | sh
```

with the same download, check, read, run alternative. Design:

- **Script safety.** POSIX `sh` (tested with dash and bash), `set -eu`, and the whole body inside one function that is called on the last line, so a truncated download executes nothing. The expected SHA-256 of the tarball is baked in per release, as in 14.2. `sha256sum` is required; if `curl` is missing the script says so (a `wget` fallback is allowed but must use the same checks).
- **Never `sudo` by itself.** Everything lands under the user's home. When a step needs root (a package such as `bubblewrap`, a system-wide Ollama), the script prints the exact command for the user to run and continues or stops as the user chooses.
- **Layout.** `${XDG_DATA_HOME:-~/.local/share}/pai/<version>/` with a `current` symlink, and `~/.local/bin/pai`, a small wrapper that sets `PAI_CORE_BIN` and `PAI_CORE_SHA256` and runs the bundled Python on the tagged `research/` tree. If `~/.local/bin` is not on `PATH`, the script shows the exact lines and appends them to the user's shell profile only after a yes, inside a marked block (`# >>> pai >>>` to `# <<< pai <<<`) so that uninstall removes exactly that block.
- **Python runtime (D15).** Default: a pinned standalone CPython build in the payload, hash-pinned like the Windows one, so behaviour does not depend on the distribution. Alternative: system `python3` with a stated minimum version.
- **Targets.** x86_64 with glibc, built on an old enough base (Ubuntu 22.04 container) for wide compatibility. Tested on Ubuntu 22.04 and 24.04, Debian 12, a current Fedora, and WSL2 Ubuntu. aarch64 and musl (Alpine) are out of scope for 1.2.0 and the script says so instead of guessing. Package formats (`.deb`, `.rpm`, AppImage, Flatpak) are out of scope; Flatpak's own sandbox would also conflict with the agent's sandbox (ADR-011).
- **Sandbox prerequisites.** The Linux sandbox needs kernel and user-space features described in ADR-011. The agent must read ADR-011 and list the exact prerequisites from it, not from memory. The installer and `pai doctor` report which are present; if one is missing, the tools that need it stay disabled instead of running unsandboxed.
- **Ollama on Linux.** According to the official Linux page, the supported routes are the install script and a manual `.tar.zst` extracted into `/usr`; both use `sudo`, and the recommended service runs as an `ollama` system user with its models under `/usr/share/ollama`. Therefore: detect an existing Ollama and reuse it; otherwise show the official method and let the user run it (never pipe the Ollama script silently). A user-level extraction into the home folder with `ollama serve` run by the user may work but is not documented as a supported route; the agent tests it in a VM and reports the result, and uses it only if it works and is described to the user as unofficial. The disk-space rule must use the real models directory (the service's directory or `OLLAMA_MODELS`), not the home folder.
- **Hardware survey on Linux.** CPU and RAM from `/proc`, disks from `statvfs`, NVIDIA from `nvidia-smi`, AMD from the ROCm tools if present. Same fit rules and the same signed catalog; the catalog gains a `platforms` field per entry.
- **Uninstall.** `uninstall.sh` removes the version folders, the symlinks and the marked profile block. Models, Ollama and `~/.pai` stay unless the user asks, and the script prints what stays.
- **Evidence limit.** The Linux core was not part of the Windows shadow window. Release notes for 1.2.0 must say that Linux is covered by CI and the installer test matrix only, until a Linux evaluation (a smaller shadow run on at least two distributions, criteria agreed with the reviewer in advance) is recorded. This is why 1.2.0 is labelled preview (D16).

### 14.4 Shared changes to existing pieces

- `build_payload.py` (P1b): `--platform`, a `platform` key in the manifest, the expected binary format (PE for Windows, ELF for Linux), one binary hash pinned per platform. The Linux binary is built by CI from the tag on a clean runner; the reviewer checks that its hash in the manifest equals the CI output. Rust builds are not assumed to be byte-reproducible; the pin is the hash of the one built artifact, as for Windows.
- Manifest and catalog formats stay at `format: 1` with additive fields only; the verification code rejects unknown required fields.
- `pai_setup.py` is written cross-platform from P3 (OS-specific code in separate small modules), so Linux does not need a rewrite later.

### 14.5 Test matrix additions

| Case | Expected |
|---|---|
| Tampered zip or tarball (one byte) | Abort before extraction; nothing installed |
| Truncated `install.sh` or `install.ps1` | Nothing executed (Linux: function not called; Windows: parse error) |
| Archive entry with `..`, absolute path or link | Rejected; negative control with a clean archive |
| Ctrl-C during download or unpack | No partial install; re-run works |
| Re-run on an installed version, then upgrade | Idempotent; PATH entry or profile block not duplicated |
| Non-ASCII user name and a path with spaces | Works (Windows); works (Linux home with spaces) |
| Run as administrator or root | Refused unless the explicit flag is given |
| No network | Clear message; no half state |
| Windows Sandbox and a clean VM: PowerShell 5.1 and 7 | Works; `where pai` and `pai --version` in a new window |
| Constrained Language Mode, AppLocker or WDAC | Clear message pointing to `PAI-Setup` |
| Linux: Ubuntu 22.04 and 24.04, Debian 12, Fedora, WSL2; `/bin/sh` is dash and bash | Works; `pai --version` and `pai doctor` in a new shell |
| Linux: no `~/.local/bin` on PATH, `/tmp` mounted `noexec`, SELinux enforcing (Fedora), no `curl` | Correct message or working fallback |
| Uninstall (both) | Removes what was installed and only that |

Results are recorded per machine profile and per distribution, as in section 9.

### 14.6 Order and gates

P1b and P7 follow the same rules as the other milestones (one report each, trust-boundary table, hostile-input tests with negative controls, claims-lint and CI green, no signing keys handled by the agent). P2b comes after P2 and after D11 (the host) is decided: while the repository is private (Finding AV), a public one-line URL needs a separate public host. Linux work (P7) starts after 1.1.0 is released, so Windows findings from real users are fixed first.

## Appendix A. Draft agreement text (for legal review; not legal advice)

> **Personal Agentic AI (PAI) - Terms of use and notices**
> 1. *What this is.* PAI is software that runs on your computer and uses AI models that also run on your computer. It can make mistakes. Check its output before you rely on it.
> 2. *Acceptable use.* You will not use PAI, or anything it produces, to break the law, to harm or deceive other people, to attack or gain unauthorised access to systems or data, to create or spread malware, to infringe the rights of others, or for any other wrongful purpose. You are responsible for how you use it.
> 3. *Your data.* PAI processes the files you give it on your computer. It keeps a local log of technical information in your user profile and does not send it anywhere. Downloads happen only when you approve them in the installer and are listed there.
> 4. *Third-party software and models.* The Ollama server and each AI model have their own licences and use policies. They are shown to you before installation. You must accept them separately.
> 5. *No warranty.* The software is provided "as is", without warranty of any kind. To the extent the law allows, the authors are not liable for loss or damage arising from its use.
> 6. *Source-code licence.* The source code is licensed under the licence in the LICENSE file. These terms govern use of the installer and distributed binaries. [Owner and lawyer: complete after decision D8.]
> [ ] I have read and accept these terms.

## Appendix B. Catalog entry (illustrative; values must be measured and verified, not copied)

```json
{
  "catalog_version": 1,
  "issued_utc": "<date>",
  "models": [
    {
      "id": "<ollama-tag>",
      "family": "<family>",
      "parameters_b": 0.0,
      "quantization": "<q>",
      "download_bytes": 0,
      "disk_bytes": 0,
      "min_ram_mb": 0,
      "min_vram_mb": 0,
      "tasks": ["code", "chat", "documents", "forecast", "singlish"],
      "license": {"name": "<name>", "url": "<official card>", "license_status": "verified", "read_on": "<date>"},
      "registry_manifest_digest": "sha256:<digest>",
      "measured": {"machine": "<profile>", "tokens_per_sec": null, "host_delta_mb": null}
    }
  ],
  "signature": "<detached Ed25519 over the canonical JSON, checked with trust.json>"
}
```

## Appendix C. Progress events written by `pai_setup.py --progress-json`

```json
{"event":"download_start","model":"<id>","total_bytes":123456789}
{"event":"progress","model":"<id>","completed":1048576,"total":123456789,"bytes_per_sec":5242880,"eta_sec":23,"status":"pulling <digest-prefix>"}
{"event":"verifying","model":"<id>"}
{"event":"done","model":"<id>"}
{"event":"error","model":"<id>","code":"DISK_FULL","message":"<text>"}
```

## Appendix D. PATH update pattern (PowerShell, registry)

Revised 2026-10-27 after the P2 fix (Finding BQ). The earlier pattern used `[Environment]::GetEnvironmentVariable` and `SetEnvironmentVariable`. The owner's test on Windows 11 showed that this expands an entry such as `%USERPROFILE%\bin` into fixed text and writes the value back as a plain string, losing the "expandable string" type. The installer therefore reads and writes the registry value directly. The path is passed in an environment variable, never pasted into the command text, so apostrophes, spaces and `%` in a user name cannot break it.

```powershell
$dir = $env:PAI_BIN_DIR            # set by the calling script
$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
$raw = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
$kind = try { $key.GetValueKind('Path') } catch { [Microsoft.Win32.RegistryValueKind]::ExpandString }
$parts = if ($raw) { $raw -split ';' | Where-Object { $_ } } else { @() }
$have = $parts | Where-Object { $_.TrimEnd('\') -ieq $dir.TrimEnd('\') -or
                                [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ieq $dir.TrimEnd('\') }
if (-not $have) { $key.SetValue('Path', (($parts + $dir) -join ';'), $kind) }
$key.Close()
# then broadcast WM_SETTINGCHANGE ("Environment") so new windows see the change
```

Rules: never `setx` (it truncates long values); keep the original value type; remove only the exact entry on uninstall; tests run the real scripts against an isolated test subkey, with a PATH that contains an expandable entry.
