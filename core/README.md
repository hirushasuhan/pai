# core/ — Rust Engine (`pai-core`)

Charter (ADR-004, ADR-011): engine, planner, stateless purge (`zeroize`), network client, URL policy, capability broker, safe ingestion primitives, hardware telemetry.

## Implemented Slices
1. `src/tier.rs` (VS2): Pure hardware budgeting policy mirroring Python `_calculate_budget`.
2. `src/url_policy.rs` (VS2): Pure URL validation and Canonical Blocked CIDR table (RFC 1918, RFC 3927, loopback, multicast, transition IPv6).
3. `src/win32.rs` (VS3): Native Win32 (`kernel32.dll`) telemetry (`GlobalMemoryStatusEx`, `GetSystemTimes`, `GetSystemPowerStatus`) with non-Windows safe stub fallback.
4. `src/ingest.rs` (Phase 2 Slice 1): Pure safe Rust (`#![forbid(unsafe_code)]`) implementation of the string-level safe-ingestion, secret-scanning, terminal/text/header sanitization, and nonce-envelope primitives (`get_ingest_limits`, `is_secret_file`, `is_junk_dir`, `scan_secret_content`, `sanitize_terminal_output`, `sanitize_text_content`, `sanitize_header`, `defang_envelope_markers`, `wrap_untrusted_envelope`).
   - **Slice 1 Scope Boundary**: Filesystem traversal, path/symlink boundary checks, and size/count quota enforcement (`ingest_file`, `ingest_folder`, `assemble_untrusted_context`) remain in Python (`research/ingest.py`) in Slice 1.
5. `src/conformance.rs` & `src/main.rs`: Golden vector runner (`--conformance <DIR>`) and panic-isolating (`catch_unwind`) differential fuzz validator (`--differential <FILE>`).

### Design & Safety Guarantees
- **Unsafe Code Policy**: `src/lib.rs` sets `#![deny(unsafe_code)]` at the crate root, and `src/ingest.rs` enforces `#![forbid(unsafe_code)]` with zero byte-slice indexing (`&str[a..b]`). Only `src/win32.rs` opts in via `#![allow(unsafe_code)]` on `#[cfg(windows)]` for the three `kernel32.dll` FFI calls.
- **Zero Network Crate Dependencies**: Strictly uses `serde` + `serde_json` and standard library types (`std::net`).
- **Conformance & Multi-Seed Differential Verification**: Verified against 200 tier vectors, 87 URL vectors, and 112 ingest vectors, plus multi-seed differential fuzzing (`--fuzz 10000` across seeds `42`, `9001`, `1337`, `20261012` — 5,000 tier, 5,000 URL, and 23,331 ingest cases per seed) and a 5,000-case random Unicode no-panic property test in `src/ingest.rs`.

