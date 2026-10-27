# ADR-013 - Installer, agreement and hardware-aware first-run model setup

**Status:** Proposed (owner request, 2026-10-27). Details and acceptance criteria: [PACKAGING_SPEC.md](../PACKAGING_SPEC.md). Owner decisions D8 to D13 are open.

## Context
The owner wants a release that a new user can install with one downloaded file: it shows an agreement against wrongful use, adds `pai` to the command prompt, installs the Ollama server, and then offers local models that fit the PC, with a download progress bar. The shipped code must be the code that was evaluated (Release N, tag `v1.0.0-rc1`, and the N+1 window), and the trust rules of ADR-005, ADR-002 and Finding BE must hold.

## Decision (proposed)
1. **One installer file** built with Inno Setup (per-user, no administrator rights). Its payload is an embeddable Python, the tagged `research/` tree unchanged, the tagged `pai-core.exe` with a pinned SHA-256, a small `pai.exe` launcher, and public keys. The launcher sets `PAI_CORE_BIN` and `PAI_CORE_SHA256`.
2. **No frozen one-file executable** as the primary form: it would change the evaluated code's file lookups, defeat the per-file manifest, and raise antivirus false positives. It may be evaluated later.
3. **Agreement page** that must be accepted before anything is installed; third-party terms (Ollama and each model) are shown and accepted separately. Acceptance is stored locally only. The licence approach (D8) needs legal review.
4. **Ollama is a separate prerequisite**, reused if present, otherwise downloaded from the official source and verified before it runs. Model weights are never bundled.
5. **Signed model catalog** (Ed25519, ADR-005 pattern, increasing version) curated by maintainers; hardware survey and fit rules choose pre-selected verified models; unverified or free-form tags need explicit confirmation.
6. **Progress** from Ollama's streamed pull API, aggregated per digest, shown in the console and in the installer window from one set of events.
7. **Windows code signing** (Authenticode) is separate from the ADR-005 key and is decided in D9.
8. **Sequencing:** packaging lives in `packaging/` and `tools/` and does not touch `research/` or `core/` until the N+1 window is closed; moving the setup wizard into `pai setup` is a separate reviewed commit afterwards.

9. **Release train:** the installer ships as version 1.1.0, built from the 1.0.0 tag; the evaluated core files must stay byte-identical (PACKAGING_SPEC section 13). Preview builds are `v1.1.0-rcN`.

## Consequences
- The installer can be tested from `v1.0.0-rc1` without invalidating the N+1 window, provided tests run in a sandbox or VM.
- A first-run experience that downloads executables and models adds attack surface; the spec lists the checks and tests that make each step fail closed.
- Costs outside the code: legal review of the agreement and a code-signing certificate or an accepted SmartScreen warning.
