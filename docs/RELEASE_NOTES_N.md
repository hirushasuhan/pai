# Personal Agentic AI (PAI) - Release N Notes

**Release Name:** Release N (Rust Policy Core Default-On)  
**Evaluated Binary Commit (core/):** `9ac1bc5b056f53fb88c1206fec896df9ffc85c1f`  
**Target Release Binary Hash (SHA-256):** `6f13d49463c757f2f3e43506f9743c37f602196544ce8fa85d5c5ce9332e3efe`  
**Shadow Evaluation Window Status:** Complete (`window_complete: true`, $\ge 604,800$ s span, 0 discrepancies across 1,010 CLI comparisons).

---

## 1. Overview & Architecture

In Release N, the high-performance, memory-safe Rust core (`core/`, `pai-core`) becomes **default-on** for all supported runtime operations.

- **Default-On Behavior:** When `pai-core` exists and passes the startup handshake, PAI automatically activates Rust core execution.
- **Graceful Fallback:** If the `pai-core` binary is missing or fails the protocol handshake, PAI gracefully falls back to the authoritative Python reference implementation and logs a warning notice.
- **Strict Explicit Mode:** If `PAI_USE_RUST_CORE=1` is explicitly provided in the environment, missing binary behavior remains strictly fail-closed (`CoreBridgeUnavailableError`).
- **Emergency Kill Switch:** Setting `PAI_RUST_FALLBACK_PYTHON=1` forces pure Python reference execution across all modules regardless of binary availability.
- **Continued Differential Shadowing:** Shadow evaluation (`PAI_SHADOW_COMPARE=1`) remains active by default to accumulate organic operational parity evidence for the upcoming Release N+1 window.

---

## 2. Discrepancy & Fallback Policy

If any differential comparison between the Rust core and the Python reference produces a mismatch:
1. **Safety-Authoritative Fallback:** For data and extraction operations (`ingest_file`, `ingest_folder`, `scan_secret_content`, `extract_example_assertions`, metadata in `verify_release`), the authoritative Python reference result is returned.
2. **Deny-Wins Security Rule:** For accept/deny security primitives (`verify_ed25519`, `verify_verdict_frame`, update signature verification in `verify_release`), if either implementation rejects the request, **deny wins** (fails closed).
3. **Session Warning:** A single warning is emitted to `stderr` upon the first detected discrepancy per session:
   ```text
   WARNING: Shadow evaluation discrepancy detected in op '{op}'. Falling back to authoritative Python reference for safety.
   ```
4. **Persistent Audit:** The incident is recorded in the shadow discrepancy log (`shadow_discrepancies.jsonl`) with operation name, timestamp, input content digest, and payload diffs for post-mortem analysis in `pai doctor`.

---

## 3. Mandatory Disclosed Limitations of Evaluation Evidence

In accordance with the 7-day shadow evaluation review protocol, the following 6 limitations are formally disclosed:

1. **Workload Synthetic Bias:** Of the 1,010 evaluated CLI comparisons, 969 were driven by the automated workload harness (`tools/run_shadow_workload.py`) and 41 arose from manual CLI sessions. The evaluation was primarily conducted on a single Windows 11 host.
2. **Digest Evidence Telemetry Shim (Finding BC):** Input content digests during the 7-day window were captured via the driver telemetry shim. Plain CLI runs did not record content digests until the Finding BC fix was committed.
3. **Verdict Frame Diversity:** The 38 evaluated `verify_verdict_frame` comparisons originated from 3 distinct underlying benchmark tasks.
4. **Input Pool Saturation:** Distinct input counts (58 for `ingest_file`, 40 for `ingest_folder`) reflect the size of the prepared corpus pool rather than unconstrained real-world variety.
5. **Known Diagnostic Records:** Three non-CLI comparisons with `source: "unknown"` (zero discrepancies) occurred during initial bridge smoke testing on October 20 when modules were directly imported without initializing `pai.main()`.
6. **Out-of-Quota Bridged Operations:** Non-CLI bridged primitives (tier calculation, outbound URL policy, Ed25519 signatures, release verification, and secret scanning) were validated via 10,000-case differential fuzzing, golden vectors (200 tier, 87 URL), and multi-platform CI rather than shadow evaluation window quotas.

---

## 4. Operational Controls & Environment Variables

| Variable | Default in Release N | Description |
| :--- | :--- | :--- |
| `PAI_USE_RUST_CORE` | `1` (if binary present) | Controls Rust core bridge invocation. Default-on with graceful fallback. Explicit `1` fails closed. |
| `PAI_RUST_FALLBACK_PYTHON` | `0` | **Emergency kill switch**. Set to `1` to completely bypass Rust core and force pure Python reference. |
| `PAI_SHADOW_COMPARE` | `1` | Enables background differential comparison against Python reference and logging of telemetry. |
| `PAI_TELEMETRY_DRIVER` | `""` | Marks comparisons initiated by automated evaluation drivers. |
| `PAI_TELEMETRY_SOURCE` | `"cli"` | Sets the telemetry source tag for provenance audit. |
