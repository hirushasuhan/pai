# Personal Agentic AI (PAI) - Release N Notes

**Release Name:** Release N (Rust Policy Core Default-On)  
**Evaluated Binary Commit (core/):** `9ac1bc5b056f53fb88c1206fec896df9ffc85c1f`  
**Core Tree Hash (core/):** `14c60746ca9a41d91aafd88cc0c7d98719cfe3a9` (strictly identical to evaluated commit)  
**Research Tree Hash (research/):** `62de28cd152be2d43654e86a8ae945c150b1e22f`  
**Target Release Binary Hash (SHA-256):** `6f13d49463c757f2f3e43506f9743c37f602196544ce8fa85d5c5ce9332e3efe`  
**Shadow Evaluation Window Status:** Complete (`window_complete: true`, $\ge 604,800$ s span, 0 discrepancies across 1,010 CLI comparisons).

---

## 1. Overview & Architecture

In Release N, the memory-safe Rust core (`core/`, `pai-core`) becomes **default-on** for all supported runtime operations.

- **Default-On Behavior:** When `pai-core` exists and passes the startup handshake, PAI automatically activates Rust core execution.
- **Graceful Fallback:** If the `pai-core` binary is missing or fails the protocol handshake, PAI gracefully falls back to the authoritative Python reference implementation and logs a warning notice.
- **Strict Explicit Mode:** If `PAI_USE_RUST_CORE=1` is explicitly provided in the environment, missing binary behavior remains strictly fail-closed (`CoreBridgeUnavailableError`).
- **Emergency Kill Switch:** Setting `PAI_RUST_FALLBACK_PYTHON=1` forces pure Python reference execution across all modules regardless of binary availability.
- **Binary Resolution Security (Finding BE):** In default mode, binary resolution searches only repository build locations (`core/target/{release,debug}`) or an explicitly specified `PAI_CORE_BIN`. System `PATH` lookup is disabled by default and requires explicit opt-in via `PAI_CORE_ALLOW_PATH=1`. Optional pinned binary SHA-256 verification is supported via `PAI_CORE_SHA256`. Failed lookups are cached per process to eliminate redundant filesystem I/O.
- **Continued Differential Shadowing:** Shadow evaluation (`PAI_SHADOW_COMPARE=1`) remains active by default to accumulate organic operational parity evidence for the upcoming Release N+1 window.

---

## 2. Code Provenance & Scope Separation

To ensure a clear audit trail and rigor, the code included in Release N is separated into two distinct provenance tiers:

1. **Evaluated Scope (7-Day Shadow Window):**
   - **Commit:** `9ac1bc5b056f53fb88c1206fec896df9ffc85c1f`
   - **Core Tree:** `14c60746ca9a41d91aafd88cc0c7d98719cfe3a9` (0 diff lines against pinned commit)
   - Evaluated continuously under the 7-day shadow evaluation window (span: 612,891.88 s; 1,010 CLI comparisons; 0 discrepancies; 0 corrupt lines; 0 write failures; single binary hash `6f13d494...`).
2. **Post-Window Enhancements (Release N Candidate Commits):**
   - **Finding BC Fix (`7153d8c`, `6bdb57b`):** Top-level `hashlib` import, `IngestedItem` digest attribute alignment, non-silent digest failure warning logging.
   - **Discrepancy Policy (`b3e3337`):** Authoritative fallback for value comparisons, deny-wins policy for accept/deny primitives.
   - **Default-On Flip & Graceful Fallback (`e3d0929`):** Flipped `PAI_USE_RUST_CORE` default to `1` with graceful fallback when unconfigured, plus kill switch.
   - **Binary Trust & Fail-Closed Metadata (Findings BE, BF, BG):** Secured binary resolution against unauthenticated `PATH` binaries, enforced fail-closed (`UpdateRejected`) on release metadata differentials, strict secret scanning wins, rejection-wins file ingestion, and distinct input documentation corrections (`research/` tree `62de28cd152be2d43654e86a8ae945c150b1e22f`).
   - *Provenance Note:* These post-window changes were **not** evaluated during the 7-day shadow window. Their correctness and safety are exercised by the comprehensive unit test suite, golden conformance vectors, differential fuzzing, and GitHub Actions CI.

---

## 3. Discrepancy & Fallback Policy

If any differential comparison between the Rust core and the Python reference produces a mismatch:
1. **Safety-Authoritative Fallback:** For data and extraction operations (`ingest_folder`, `extract_example_assertions`), the authoritative Python reference result is returned.
2. **Strict Secret Detection Wins:** For secret scanning (`scan_secret_content`), if either implementation detects a secret, the detection is returned.
3. **Rejection Wins for File Ingestion:** For file ingestion (`ingest_file`), if either implementation rejects the file (e.g. invalid filename, secret pattern, size/line limits), the rejection is returned.
4. **Deny-Wins Security Rule:** For accept/deny security primitives (`verify_ed25519`, `verify_verdict_frame`), if either implementation rejects the request, **deny wins** (fails closed).
5. **Signed Release Fail-Closed (Finding BF):** In `updater.py` (`verify_release`), if signatures are accepted by both implementations but metadata (`version`, `key_id`, or `files`) differs, the update **fails closed** (`UpdateRejected`), preventing differential parsing attacks on signed packages.
6. **Session Warning:** A single warning is emitted to `stderr` upon the first detected discrepancy per session:
   ```text
   WARNING: Shadow evaluation discrepancy detected in op '{op}'. Falling back to safe authoritative outcome (Python reference / fail-closed deny).
   ```
7. **Persistent Audit:** The incident is recorded in the shadow discrepancy log (`shadow_discrepancies.jsonl`) with operation name, timestamp, input content digest, and payload diffs for post-mortem analysis in `pai doctor`.

---

## 4. Mandatory Disclosed Limitations of Evaluation Evidence

In accordance with the 7-day shadow evaluation review protocol, the following 6 limitations are formally disclosed:

1. **Workload Synthetic Bias:** Of the 1,010 evaluated CLI comparisons, 969 were driven by the automated workload harness (`tools/run_shadow_workload.py`) and 41 arose from manual CLI sessions. The evaluation was primarily conducted on a single Windows 11 host.
2. **Digest Evidence Telemetry Shim (Finding BC):** Input content digests during the 7-day window were captured via the driver telemetry shim. Plain CLI runs did not record content digests until the Finding BC fix was committed.
3. **Verdict Frame Diversity:** The 38 evaluated `verify_verdict_frame` comparisons originated from 3 distinct underlying benchmark tasks.
4. **Input Pool Saturation:** Distinct input counts (**57 for `ingest_file`**, **39 for `ingest_folder`**) reflect the size of the prepared corpus pool rather than unconstrained real-world variety.
5. **Known Diagnostic Records:** Three non-CLI comparisons with `source: "unknown"` (zero discrepancies) occurred during initial bridge smoke testing on October 20 when modules were directly imported without initializing `pai.main()`.
6. **Out-of-Quota Bridged Operations:** Non-CLI bridged primitives (tier calculation, outbound URL policy, Ed25519 signatures, release verification, and secret scanning) were exercised via 10,000-case differential fuzzing, golden vectors (200 tier, 87 URL), and multi-platform CI rather than shadow evaluation window quotas. `extract_example_assertions` shadow evidence in the window comprises 3 CLI comparisons alongside extensive unit tests and conformance vectors.

---

## 5. Operational Controls & Environment Variables

| Variable | Default in Release N | Description |
| :--- | :--- | :--- |
| `PAI_USE_RUST_CORE` | `1` (if binary present) | Controls Rust core bridge invocation. Default-on with graceful fallback. Explicit `1` fails closed. |
| `PAI_RUST_FALLBACK_PYTHON` | `0` | **Emergency kill switch**. Set to `1` to completely bypass Rust core and force pure Python reference. |
| `PAI_CORE_BIN` | `""` | Explicit path override for `pai-core` binary executable. |
| `PAI_CORE_ALLOW_PATH` | `0` | Opt-in to search system `PATH` for `pai-core`. Disabled by default for binary trust safety. |
| `PAI_CORE_SHA256` | `""` | Optional pinned SHA-256 digest; if set, `pai-core` binary must match or startup aborts. |
| `PAI_SHADOW_COMPARE` | `1` | Enables background differential comparison against Python reference and logging of telemetry. |
| `PAI_TELEMETRY_DRIVER` | `""` | Marks comparisons initiated by automated evaluation drivers. |
| `PAI_TELEMETRY_SOURCE` | `"cli"` | Sets the telemetry source tag for provenance audit. |
