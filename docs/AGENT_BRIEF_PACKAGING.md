# Agent brief: installer and first-run setup (release 1.1.0)

Read first: [PACKAGING_SPEC.md](PACKAGING_SPEC.md) and [ADR-013](adr/ADR-013-installer-and-distribution.md). This brief is the order of work. The reviewer checks one report per milestone.

## Hard rules
1. Until the reviewer writes "N+1 window closed": do not edit `research/`, `core/`, or rebuild `pai-core`. Work only in `packaging/` and `tools/`. Import `research/` modules read-only.
2. Never touch the owner's real profile or log while testing. Use Windows Sandbox (a separate configuration that allows networking, used only for installer tests) or a clean VM, and say which machine profile produced each result.
3. Never ask for, store or generate signing keys. Signing steps are written as instructions for the owner's offline machine.
4. Do not invent model names, sizes or licences. Sizes come from registry manifests and licences from official model cards, each with a source link and the date read.
5. Every milestone: hostile-input tests with a negative control, trust-boundary table (installer, network, downloaded executables, catalog, PATH, launcher environment), claims-lint green, CI green.

## Order of work
| Step | Deliverable | Done when |
|---|---|---|
| P1 | `packaging/build_payload.py`: builds the payload from a git tag; writes a manifest (file, size, SHA-256); fails if `research/` or `core/` tree ids differ from the tag | Two builds from the same tag give identical manifests |
| P2 | `pai.exe` launcher (sets `PAI_CORE_BIN` and `PAI_CORE_SHA256`, runs the embedded Python), portable zip with `install.bat` and an uninstall script (user PATH update by the pattern in Appendix D of the spec) | `where pai` and `pai --version` work in a fresh cmd.exe and PowerShell; uninstall removes the PATH entry |
| P3 | `packaging/pai_setup.py`: hardware survey, signed-catalog verification (reject bad signature and lower version), fit rules, Ollama detection and installer download with publisher check | Unit tests for every fit rule and every rejection path |
| P4 | Download engine on Ollama's streamed pull API: per-digest aggregation, overall bar with sizes, speed and time left, resume, cancel, retry, disk-full message, `--progress-json` events | Simulated slow, dropped and corrupt streams behave as specified |
| P5 | Inno Setup script: agreement page (cannot continue without acceptance), wizard pages, consent page listing hosts, per-user install, PATH, uninstall; run the full test matrix (spec section 9) | Matrix report with results per machine profile; antivirus scan result recorded |
| P6 | After the reviewer opens it: move the setup entry point into `pai setup` in `research/` as a separate commit that only adds setup, catalog and download code | Release script confirms the evaluated core files are byte-identical to the 1.0.0 tag |
| P1b | Extend the payload builder for `--platform` (`win-x64`, `linux-x64`), binary-format check, `dist/` in `.gitignore` (spec section 14.4) | Existing P1 tests still pass; a Linux-platform build from a fixture is rejected when the binary is a PE file, and the reverse |
| P2b | `packaging/install.ps1` one-line bootstrap (spec section 14.2); only after D11 and P2 | Tampered zip aborts before extraction; hostile-archive tests; run in Windows Sandbox with PowerShell 5.1 and 7 |
| P7 | Linux build in CI, `packaging/install.sh`, Linux survey and Ollama handling (spec section 14.3 to 14.5); only after 1.1.0 | Matrix of section 14.5 per distribution; release labelled preview |

## What to hand back
For each step: files changed, commit ids, how to run it, the test output, the machine profile, and a list of anything not done. If a decision (D8 to D16 in the spec) blocks you, stop and say which one.
