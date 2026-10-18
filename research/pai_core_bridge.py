"""
Personal Agentic AI - Rust Core Integration Bridge (Slice 3).

Stateless IPC JSON bridge between Python and pai-core binary.
Flags:
- PAI_USE_RUST_CORE: os.environ flag ("0" by default, "1" to enable).
When disabled, pure Python reference implementations are used.
When enabled, calls Rust pai-core --bridge via JSON-in/JSON-out over stdin/stdout,
re-parses every statement with ast.parse, defensively re-validates all shapes,
and runs in shadow mode comparing with Python reference to refuse on differential mismatch.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ingest import (
    DEFAULT_JUNK_DIR_PATTERNS,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_FILE_COUNT,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_LINE_LENGTH,
    DEFAULT_MAX_REJECTIONS_PER_REASON,
    DEFAULT_MAX_TOTAL_BYTES,
    DEFAULT_MAX_TOTAL_REJECTIONS,
    DEFAULT_SECRET_DENY_PATTERNS,
    IngestedItem,
    IngestionRejection,
    IngestionReport,
    _has_lone_surrogates,
    _is_invalid_filename,
    assemble_untrusted_context,
    defang_envelope_markers as py_defang_envelope_markers,
    format_untrusted_context,
    generate_envelope_nonce,
    get_ingest_limits as py_get_ingest_limits,
    ingest_file as py_ingest_file,
    ingest_folder as py_ingest_folder,
    is_junk_dir as py_is_junk_dir,
    is_secret_file as py_is_secret_file,
    sanitize_header as py_sanitize_header,
    sanitize_terminal_output as py_sanitize_terminal_output,
    sanitize_text_content as py_sanitize_text_content,
    scan_secret_content as py_scan_secret_content,
    wrap_untrusted_envelope as py_wrap_untrusted_envelope,
)
from value_codec import (
    CodecError,
    decode_envelope_json as py_decode_envelope_json,
    decode_value as py_decode_value,
)
from verify_loop import (
    extract_example_assertions as py_extract_example_assertions,
    verify_verdict_frame as py_verify_verdict_frame,
)

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("pai.core_bridge")

PAI_USE_RUST_CORE = os.environ.get("PAI_USE_RUST_CORE", "0").lower() in ("1", "true", "yes")
PAI_RUST_FALLBACK_PYTHON = os.environ.get("PAI_RUST_FALLBACK_PYTHON", "0").lower() in ("1", "true", "yes")
PAI_SHADOW_COMPARE = os.environ.get("PAI_SHADOW_COMPARE", "1").lower() in ("1", "true", "yes")


def is_python_fallback_forced() -> bool:
    """Returns True if the 1-release fallback to Python is active."""
    return bool(PAI_RUST_FALLBACK_PYTHON) or (os.environ.get("PAI_RUST_FALLBACK_PYTHON", "0").lower() in ("1", "true", "yes"))


def is_rust_core_enabled() -> bool:
    """Returns True if Rust core is enabled and Python fallback is not forced."""
    if is_python_fallback_forced():
        return False
    return bool(PAI_USE_RUST_CORE) or (os.environ.get("PAI_USE_RUST_CORE", "0").lower() in ("1", "true", "yes"))


def is_shadow_compare_enabled() -> bool:
    """Returns True if shadow comparison against the Python reference is enabled."""
    env_val = os.environ.get("PAI_SHADOW_COMPARE")
    if env_val is not None:
        return env_val.lower() in ("1", "true", "yes")
    return bool(PAI_SHADOW_COMPARE)

MAX_REQUEST_BYTES = 16 * 1024 * 1024  # 16 MiB

_CORE_BIN_CACHE: Optional[str] = None

_SHADOW_DISCREPANCIES: List[Dict[str, Any]] = []
_SHADOW_COMPARISONS_COUNT: int = 0
_LOG_WRITE_FAILURES_COUNT: int = 0


_CURRENT_TELEMETRY_SOURCE: str = "unknown"


def set_telemetry_source(source: str) -> None:
    """Sets the current telemetry source tag ('cli', 'doctor', 'runner', 'test', 'unknown')."""
    global _CURRENT_TELEMETRY_SOURCE
    _CURRENT_TELEMETRY_SOURCE = source


def get_telemetry_source() -> str:
    """Returns the active telemetry source, prioritizing PAI_TELEMETRY_SOURCE env var."""
    return os.environ.get("PAI_TELEMETRY_SOURCE") or _CURRENT_TELEMETRY_SOURCE


def _get_discrepancy_log_path() -> Path:
    override = os.environ.get("PAI_SHADOW_LOG")
    if override:
        return Path(override)
    pai_dir_env = os.environ.get("PAI_DIR")
    if pai_dir_env:
        return Path(pai_dir_env) / "shadow_discrepancies.jsonl"
    pai_dir = Path.home() / ".pai"
    try:
        pai_dir.mkdir(parents=True, exist_ok=True)
        probe = pai_dir / ".probe_write"
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        if probe.exists():
            probe.unlink()
        return pai_dir / "shadow_discrepancies.jsonl"
    except OSError:
        import tempfile
        temp_pai = Path(tempfile.gettempdir()) / "pai"
        temp_pai.mkdir(parents=True, exist_ok=True)
        return temp_pai / "shadow_discrepancies.jsonl"


class CoreBridgeUnavailableError(RuntimeError):
    """Raised when PAI_USE_RUST_CORE is requested but pai-core binary is unavailable or cannot execute."""
    pass


class BridgeProtocolError(CoreBridgeUnavailableError):
    """Raised when IPC communication with the pai-core bridge fails due to protocol or serialization errors."""
    pass


def record_shadow_comparison(op: str, **extra: Any) -> None:
    """Records that a shadow comparison was executed."""
    global _SHADOW_COMPARISONS_COUNT
    _SHADOW_COMPARISONS_COUNT += 1
    src = extra.pop("source", None) or get_telemetry_source()
    rec = {
        "timestamp": time.time(),
        "type": "comparison",
        "op": op,
        "source": src,
        **extra,
    }
    try:
        log_file = _get_discrepancy_log_path()
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.debug("Failed to persist shadow comparison: %s", e)


def record_shadow_discrepancy(op: str, detail: str, **extra: Any) -> None:
    """Records a shadow discrepancy for visibility in run reports and pai doctor."""
    src = extra.pop("source", None) or get_telemetry_source()
    rec = {
        "timestamp": time.time(),
        "type": "discrepancy",
        "op": op,
        "detail": detail,
        "source": src,
        **extra,
    }
    _SHADOW_DISCREPANCIES.append(rec)
    try:
        log_file = _get_discrepancy_log_path()
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        global _LOG_WRITE_FAILURES_COUNT
        _LOG_WRITE_FAILURES_COUNT += 1
        logger.warning("Failed to persist shadow discrepancy to file: %s", e)
    logger.warning("[SHADOW DISCREPANCY] op=%s source=%s: %s", op, src, detail)


def get_shadow_stats() -> Tuple[int, int, List[Dict[str, Any]]]:
    """
    Returns (comparisons_count, discrepancies_count, list_of_discrepancies).
    """
    comparisons = 0
    discrepancies: List[Dict[str, Any]] = []
    try:
        log_file = _get_discrepancy_log_path()
        if log_file.exists():
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            obj = json.loads(line)
                            if isinstance(obj, dict) and obj.get("type") == "comparison":
                                comparisons += 1
                            elif isinstance(obj, dict):
                                discrepancies.append(obj)
                            else:
                                discrepancies.append({"corrupted": line})
                        except Exception:
                            discrepancies.append({"corrupted": line})
            return comparisons, len(discrepancies), discrepancies
    except Exception as e:
        logger.warning("Failed to read shadow discrepancies log: %s", e)
    return _SHADOW_COMPARISONS_COUNT, len(_SHADOW_DISCREPANCIES), list(_SHADOW_DISCREPANCIES)


def get_shadow_discrepancies() -> List[Dict[str, Any]]:
    """Returns all recorded shadow discrepancies from the persistent log file."""
    _, _, disc = get_shadow_stats()
    return disc


def get_shadow_discrepancy_count() -> int:
    """Returns the total number of recorded shadow discrepancies."""
    _, count, _ = get_shadow_stats()
    return count


def _format_iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def get_shadow_telemetry_summary() -> Dict[str, Any]:
    """
    Returns aggregated shadow telemetry summary:
    - total_comparisons
    - total_discrepancies
    - corrupt_lines
    - cli_comparisons
    - cli_discrepancies
    - first_comparison_timestamp / first_comparison_iso
    - last_comparison_timestamp / last_comparison_iso
    - first_cli_comparison_timestamp / first_cli_comparison_iso
    - last_cli_comparison_timestamp / last_cli_comparison_iso
    - window_started
    - window_active
    - operations: mapping of op name to comparisons, discrepancies, first/last comparison ISO timestamps.
    - cli_operations: mapping of op name to comparisons, discrepancies, first/last comparison ISO timestamps for source='cli'.
    - sources: mapping of source name to comparisons and discrepancies.
    """
    total_comparisons = 0
    total_discrepancies = 0
    corrupt_lines = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    first_cli_ts: Optional[float] = None
    last_cli_ts: Optional[float] = None
    cli_comparisons = 0
    cli_discrepancies = 0

    ops: Dict[str, Dict[str, Any]] = {}
    cli_ops: Dict[str, Dict[str, Any]] = {}
    sources: Dict[str, Dict[str, int]] = {}

    def _ensure_op(target_dict: Dict[str, Dict[str, Any]], op_name: str) -> Dict[str, Any]:
        if op_name not in target_dict:
            target_dict[op_name] = {
                "comparisons": 0,
                "discrepancies": 0,
                "first_comparison_timestamp": None,
                "first_comparison_iso": None,
                "last_comparison_timestamp": None,
                "last_comparison_iso": None,
            }
        return target_dict[op_name]

    def _ensure_source(src_name: str) -> Dict[str, int]:
        if src_name not in sources:
            sources[src_name] = {"comparisons": 0, "discrepancies": 0}
        return sources[src_name]

    try:
        log_file = _get_discrepancy_log_path()
        if log_file.exists():
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        corrupt_lines += 1
                        total_discrepancies += 1
                        cli_discrepancies += 1
                        continue
                    if not isinstance(obj, dict):
                        corrupt_lines += 1
                        total_discrepancies += 1
                        cli_discrepancies += 1
                        continue

                    entry_type = obj.get("type")
                    op_name = str(obj.get("op") or "unknown")
                    source_name = str(obj.get("source") or "unknown")
                    ts = obj.get("timestamp")

                    if isinstance(ts, (int, float)):
                        if first_ts is None or ts < first_ts:
                            first_ts = ts
                        if last_ts is None or ts > last_ts:
                            last_ts = ts
                        if source_name == "cli":
                            if first_cli_ts is None or ts < first_cli_ts:
                                first_cli_ts = ts
                            if last_cli_ts is None or ts > last_cli_ts:
                                last_cli_ts = ts

                    op_rec = _ensure_op(ops, op_name)
                    src_rec = _ensure_source(source_name)
                    cli_op_rec = _ensure_op(cli_ops, op_name) if source_name == "cli" else None

                    if entry_type == "comparison":
                        total_comparisons += 1
                        op_rec["comparisons"] += 1
                        src_rec["comparisons"] += 1
                        if source_name == "cli":
                            cli_comparisons += 1
                            if cli_op_rec is not None:
                                cli_op_rec["comparisons"] += 1

                        if isinstance(ts, (int, float)):
                            if op_rec["first_comparison_timestamp"] is None or ts < op_rec["first_comparison_timestamp"]:
                                op_rec["first_comparison_timestamp"] = ts
                                op_rec["first_comparison_iso"] = _format_iso(ts)
                            if op_rec["last_comparison_timestamp"] is None or ts > op_rec["last_comparison_timestamp"]:
                                op_rec["last_comparison_timestamp"] = ts
                                op_rec["last_comparison_iso"] = _format_iso(ts)

                            if source_name == "cli" and cli_op_rec is not None:
                                if cli_op_rec["first_comparison_timestamp"] is None or ts < cli_op_rec["first_comparison_timestamp"]:
                                    cli_op_rec["first_comparison_timestamp"] = ts
                                    cli_op_rec["first_comparison_iso"] = _format_iso(ts)
                                if cli_op_rec["last_comparison_timestamp"] is None or ts > cli_op_rec["last_comparison_timestamp"]:
                                    cli_op_rec["last_comparison_timestamp"] = ts
                                    cli_op_rec["last_comparison_iso"] = _format_iso(ts)

                    elif entry_type == "discrepancy":
                        total_discrepancies += 1
                        op_rec["discrepancies"] += 1
                        src_rec["discrepancies"] += 1
                        if source_name == "cli":
                            cli_discrepancies += 1
                            if cli_op_rec is not None:
                                cli_op_rec["discrepancies"] += 1
                    else:
                        total_discrepancies += 1
                        op_rec["discrepancies"] += 1
                        src_rec["discrepancies"] += 1
                        if source_name == "cli":
                            cli_discrepancies += 1
                            if cli_op_rec is not None:
                                cli_op_rec["discrepancies"] += 1
    except Exception as e:
        logger.warning("Failed to parse shadow telemetry summary: %s", e)

    if total_comparisons == 0 and _SHADOW_COMPARISONS_COUNT > 0:
        total_comparisons = _SHADOW_COMPARISONS_COUNT
        total_discrepancies = len(_SHADOW_DISCREPANCIES)
        if get_telemetry_source() == "cli":
            cli_comparisons = total_comparisons
            cli_discrepancies = total_discrepancies

    REQUIRED_CLI_OP_QUOTAS: Dict[str, int] = {
        "ingest_file": 600,
        "ingest_folder": 150,
        "verify_verdict_frame": 25,
    }
    REQUIRED_TOTAL_CLI_COMPARISONS: int = 1000
    REQUIRED_WINDOW_SECONDS: float = 7.0 * 86400.0  # 604,800 seconds (7 full days)

    if _LOG_WRITE_FAILURES_COUNT > 0:
        total_discrepancies += _LOG_WRITE_FAILURES_COUNT
        cli_discrepancies += _LOG_WRITE_FAILURES_COUNT

    cli_span_seconds = 0.0
    if first_cli_ts is not None and last_cli_ts is not None:
        cli_span_seconds = max(0.0, last_cli_ts - first_cli_ts)

    window_started = bool(cli_comparisons > 0)
    window_active = bool(
        window_started
        and cli_discrepancies == 0
        and corrupt_lines == 0
        and _LOG_WRITE_FAILURES_COUNT == 0
    )

    quotas_met = bool(
        cli_comparisons >= REQUIRED_TOTAL_CLI_COMPARISONS
        and all(
            cli_ops.get(op, {}).get("comparisons", 0) >= req_min
            for op, req_min in REQUIRED_CLI_OP_QUOTAS.items()
        )
    )
    span_met = bool(cli_span_seconds >= REQUIRED_WINDOW_SECONDS)
    window_complete = bool(window_active and quotas_met and span_met)

    return {
        "total_comparisons": total_comparisons,
        "total_discrepancies": total_discrepancies,
        "corrupt_lines": corrupt_lines,
        "log_write_failures": _LOG_WRITE_FAILURES_COUNT,
        "cli_comparisons": cli_comparisons,
        "cli_discrepancies": cli_discrepancies,
        "first_comparison_timestamp": first_ts,
        "first_comparison_iso": _format_iso(first_ts),
        "last_comparison_timestamp": last_ts,
        "last_comparison_iso": _format_iso(last_ts),
        "first_cli_comparison_timestamp": first_cli_ts,
        "first_cli_comparison_iso": _format_iso(first_cli_ts),
        "last_cli_comparison_timestamp": last_cli_ts,
        "last_cli_comparison_iso": _format_iso(last_cli_ts),
        "cli_span_seconds": cli_span_seconds,
        "required_total_cli_comparisons": REQUIRED_TOTAL_CLI_COMPARISONS,
        "required_cli_quotas": REQUIRED_CLI_OP_QUOTAS,
        "required_window_seconds": REQUIRED_WINDOW_SECONDS,
        "quotas_met": quotas_met,
        "span_met": span_met,
        "window_started": window_started,
        "window_active": window_active,
        "window_complete": window_complete,
        "operations": ops,
        "cli_operations": cli_ops,
        "sources": sources,
    }


def archive_shadow_log() -> Optional[Path]:
    """
    Archives the persistent shadow comparison/discrepancy log file by renaming it
    to a timestamped backup and zeroing in-memory counters.
    """
    global _SHADOW_COMPARISONS_COUNT, _LOG_WRITE_FAILURES_COUNT
    _SHADOW_COMPARISONS_COUNT = 0
    _LOG_WRITE_FAILURES_COUNT = 0
    _SHADOW_DISCREPANCIES.clear()
    try:
        log_file = _get_discrepancy_log_path()
        if log_file.exists() and log_file.stat().st_size > 0:
            ts_str = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
            archive_name = f"shadow_discrepancies_archived_{ts_str}.jsonl"
            archive_path = log_file.parent / archive_name
            counter = 1
            while archive_path.exists():
                archive_name = f"shadow_discrepancies_archived_{ts_str}_{counter}.jsonl"
                archive_path = log_file.parent / archive_name
                counter += 1
            try:
                log_file.rename(archive_path)
                return archive_path
            except OSError:
                import shutil
                shutil.copy2(log_file, archive_path)
                with open(log_file, "w", encoding="utf-8") as f:
                    f.truncate(0)
                return archive_path
        elif log_file.exists():
            with open(log_file, "w", encoding="utf-8") as f:
                f.truncate(0)
    except Exception as e:
        logger.warning("Failed to archive shadow log: %s", e)
    return None


def clear_shadow_log() -> Optional[Path]:
    """Archives the persistent shadow log file and resets in-memory counters."""
    return archive_shadow_log()


def reset_shadow_discrepancies() -> None:
    """Resets both in-memory and persistent shadow discrepancies log safely via archiving."""
    archive_shadow_log()



def compute_repo_vectors_hash() -> str:
    """Computes SHA-256 over canonical conformance vector files in the repository."""
    import hashlib
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")
    vector_files = [
        "tier_policy_vectors.json",
        "url_policy_vectors.json",
        "ingest_vectors.json",
        "verify_loop_vectors.json",
        "ed25519_vectors.json",
    ]
    h = hashlib.sha256()
    for vf in vector_files:
        p = os.path.join(base_dir, vf)
        if os.path.exists(p):
            with open(p, "rb") as f:
                content = f.read().replace(b"\r\n", b"\n")
                h.update(vf.encode("utf-8"))
                h.update(content)
    return h.hexdigest()


def check_handshake(binary_path: str) -> Dict[str, Any]:
    """
    Performs handshake with pai-core binary, verifying protocol, platform,
    vector count, and compiled vector set hash.
    """
    req_json = json.dumps({"op": "handshake"})
    try:
        proc = subprocess.run(
            [binary_path, "--bridge"],
            input=req_json.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
    except Exception as exc:
        raise CoreBridgeUnavailableError(f"Failed to execute '{binary_path}' for handshake: {exc}") from exc

    if proc.returncode != 0:
        err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
        raise CoreBridgeUnavailableError(f"pai-core handshake failed with exit code {proc.returncode}: {err_msg}")

    stdout_str = proc.stdout.decode("utf-8", errors="replace").strip()
    try:
        resp = json.loads(stdout_str)
    except Exception as exc:
        raise CoreBridgeUnavailableError(f"pai-core handshake returned invalid JSON: {stdout_str[:100]}") from exc

    if not isinstance(resp, dict) or resp.get("status") != "ok":
        raise CoreBridgeUnavailableError(f"pai-core handshake rejected: {resp}")

    result = resp.get("result", {})
    if not isinstance(result, dict) or result.get("protocol_version") != 1:
        raise CoreBridgeUnavailableError(f"Incompatible pai-core protocol version: {result}")

    # Verify compiled vector-set hash against current repo vector files
    repo_vectors_hash = compute_repo_vectors_hash()
    binary_vectors_hash = result.get("conformance_vectors_hash")
    if binary_vectors_hash != repo_vectors_hash:
        raise CoreBridgeUnavailableError(
            f"pai-core binary was built with outdated vector set or source: "
            f"binary={binary_vectors_hash} vs repo={repo_vectors_hash}. "
            f"Run `cargo build --release --manifest-path core/Cargo.toml`."
        )

    return result


def find_core_binary() -> str:
    """
    Locates the platform-compatible pai-core binary, checking release, debug, and system PATH.
    Enforces that Windows looks for .exe and Unix looks for non-.exe ELF binaries with X_OK.
    """
    global _CORE_BIN_CACHE
    if _CORE_BIN_CACHE and os.path.isfile(_CORE_BIN_CACHE) and os.access(_CORE_BIN_CACHE, os.X_OK):
        return _CORE_BIN_CACHE

    root_dir = Path(__file__).resolve().parent.parent
    is_windows = sys.platform == "win32"
    bin_name = "pai-core.exe" if is_windows else "pai-core"

    candidates = [
        root_dir / "core" / "target" / "release" / bin_name,
        root_dir / "core" / "target" / "debug" / bin_name,
    ]
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            candidate_str = str(c)
            try:
                check_handshake(candidate_str)
                _CORE_BIN_CACHE = candidate_str
                return _CORE_BIN_CACHE
            except Exception as e:
                logger.debug("Candidate %s failed handshake: %s", candidate_str, e)
                continue

    on_path = shutil.which("pai-core")
    if on_path and os.access(on_path, os.X_OK):
        try:
            check_handshake(on_path)
            _CORE_BIN_CACHE = on_path
            return _CORE_BIN_CACHE
        except Exception as e:
            logger.debug("PATH candidate %s failed handshake: %s", on_path, e)

    raise CoreBridgeUnavailableError(
        f"Could not find compatible '{bin_name}' binary in core/target/{{release,debug}} or on PATH. "
        "Run `cargo build --release --manifest-path core/Cargo.toml` on this platform first."
    )


def call_core_bridge(op: str, **kwargs: Any) -> Any:
    """
    Executes a single IPC request against `pai-core --bridge` via JSON-in/JSON-out.
    Enforces 16 MiB payload size cap, strict shape validation, and error propagation.
    """
    binary = find_core_binary()
    payload = {"op": op, **kwargs}
    try:
        req_json = json.dumps(payload, ensure_ascii=False)
        req_bytes = req_json.encode("utf-8")
    except Exception as exc:
        raise BridgeProtocolError(f"Failed to serialize bridge payload: {exc}") from exc

    if len(req_bytes) > MAX_REQUEST_BYTES:
        raise ValueError(f"Request payload size ({len(req_bytes)} bytes) exceeds maximum limit of 16 MiB")

    try:
        proc = subprocess.run(
            [binary, "--bridge"],
            input=req_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"pai-core bridge timed out for op '{op}'") from exc
    except Exception as exc:
        raise BridgeProtocolError(f"Failed to spawn pai-core bridge: {exc}") from exc

    if proc.returncode != 0:
        err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
        raise BridgeProtocolError(f"pai-core bridge failed (exit code {proc.returncode}): {err_msg}")

    stdout_str = proc.stdout.decode("utf-8", errors="replace").strip()
    if not stdout_str:
        raise BridgeProtocolError(f"pai-core bridge returned empty output for op '{op}'")

    try:
        resp = json.loads(stdout_str)
    except Exception as exc:
        raise BridgeProtocolError(f"pai-core bridge returned invalid JSON: {stdout_str[:200]}") from exc

    if not isinstance(resp, dict):
        raise TypeError(f"pai-core bridge response must be a JSON object, got {type(resp).__name__}")

    status = resp.get("status")
    if status == "error":
        err_text = resp.get("error", "Unknown error from Rust core")
        err_type = resp.get("error_type", "")
        if err_type == "CodecError":
            raise CodecError(err_text)
        if err_type == "UpdateRejected":
            from updater import UpdateRejected
            raise UpdateRejected(err_text)
        if err_type == "JsonParseError":
            raise BridgeProtocolError(f"Rust core bridge JSON error: {err_text}")
        raise ValueError(f"Rust core bridge error ({err_type}): {err_text}")

    if status != "ok":
        raise BridgeProtocolError(f"Unexpected bridge status '{status}'")

    return resp.get("result")


# ============================================================================
# Ingest Primitives (with Rust Bridge & Defensive Verification)
# ============================================================================

def is_secret_file(file_path: str) -> bool:
    if not is_rust_core_enabled():
        return py_is_secret_file(file_path)
    if _is_invalid_filename(file_path):
        return py_is_secret_file(file_path)
    res = call_core_bridge("is_secret_file", path=file_path)
    if not isinstance(res, bool):
        raise TypeError(f"is_secret_file expected bool from bridge, got {type(res).__name__}")
    return res


def is_junk_dir(dirname: str) -> bool:
    if not is_rust_core_enabled():
        return py_is_junk_dir(dirname)
    if _is_invalid_filename(dirname):
        return py_is_junk_dir(dirname)
    res = call_core_bridge("is_junk_dir", dirname=dirname)
    if not isinstance(res, bool):
        raise TypeError(f"is_junk_dir expected bool from bridge, got {type(res).__name__}")
    return res


def scan_secret_content(text: str, file_path: Optional[str] = None) -> Optional[str]:
    if not is_rust_core_enabled():
        return py_scan_secret_content(text, file_path=file_path)
    if _has_lone_surrogates(text) or (file_path is not None and _is_invalid_filename(file_path)):
        return py_scan_secret_content(text, file_path=file_path)
    kwargs: Dict[str, Any] = {"text": text}
    if file_path is not None:
        kwargs["file_path"] = file_path
    res = call_core_bridge("scan_secret_content", **kwargs)
    if res is not None and not isinstance(res, str):
        raise TypeError(f"scan_secret_content expected str or None, got {type(res).__name__}")
    if is_shadow_compare_enabled():
        record_shadow_comparison("scan_secret_content")
        try:
            py_res = py_scan_secret_content(text, file_path=file_path)
            if py_res != res:
                record_shadow_discrepancy(
                    "scan_secret_content",
                    f"Python={py_res!r} vs Rust={res!r}",
                )
        except Exception as exc:
            record_shadow_discrepancy(
                "scan_secret_content",
                f"Python shadow comparison exception: {exc}",
            )
    return res


def sanitize_terminal_output(text: str) -> str:
    if not is_rust_core_enabled():
        return py_sanitize_terminal_output(text)
    res = call_core_bridge("sanitize_terminal_output", text=text)
    if not isinstance(res, str):
        raise TypeError(f"sanitize_terminal_output expected str, got {type(res).__name__}")
    return res


def sanitize_text_content(raw_utf8: str, max_line_length: int = 4096) -> str:
    if max_line_length <= 0 or max_line_length > 1_000_000:
        raise ValueError(f"max_line_length must be between 1 and 1000000, got {max_line_length}")
    if not is_rust_core_enabled():
        return py_sanitize_text_content(raw_utf8.encode("utf-8"), max_line_length=max_line_length)
    res = call_core_bridge("sanitize_text_content", text=raw_utf8, max_line_length=max_line_length)
    if not isinstance(res, str):
        raise TypeError(f"sanitize_text_content expected str, got {type(res).__name__}")
    return res


def sanitize_header(header: str) -> str:
    if not is_rust_core_enabled():
        return py_sanitize_header(header)
    res = call_core_bridge("sanitize_header", header=header)
    if not isinstance(res, str):
        raise TypeError(f"sanitize_header expected str, got {type(res).__name__}")
    return res


def defang_envelope_markers(text: str, nonce: Optional[str] = None) -> str:
    if not is_rust_core_enabled():
        return py_defang_envelope_markers(text, nonce=nonce)
    kwargs: Dict[str, Any] = {"text": text}
    if nonce is not None:
        kwargs["nonce"] = nonce
    res = call_core_bridge("defang_envelope_markers", **kwargs)
    if not isinstance(res, str):
        raise TypeError(f"defang_envelope_markers expected str, got {type(res).__name__}")
    return res


def wrap_untrusted_envelope(content: str, header: Optional[str] = None, nonce: str = "") -> str:
    if not is_rust_core_enabled():
        return py_wrap_untrusted_envelope(content, header=header, nonce=nonce)
    kwargs: Dict[str, Any] = {"content": content, "nonce": nonce}
    if header is not None:
        kwargs["header"] = header
    res = call_core_bridge("wrap_untrusted_envelope", **kwargs)
    if not isinstance(res, str):
        raise TypeError(f"wrap_untrusted_envelope expected str, got {type(res).__name__}")
    return res


def get_ingest_limits() -> Dict[str, Any]:
    if not is_rust_core_enabled():
        return py_get_ingest_limits()
    res = call_core_bridge("get_ingest_limits")
    if not isinstance(res, dict):
        raise TypeError(f"get_ingest_limits expected dict, got {type(res).__name__}")
    return res


# ============================================================================
# Codec & Verify Loop Primitives (with Defensive Verification & Shadow Mode)
# ============================================================================

def decode_envelope_json(raw_json: str) -> Any:
    """
    Decodes a tagged envelope JSON string.
    When PAI_USE_RUST_CORE is active, delegates strict parsing and envelope validation
    to Rust, receiving a canonical tagged envelope, which is then defensively decoded
    to Python types using `py_decode_value`.
    """
    if not is_rust_core_enabled():
        return py_decode_envelope_json(raw_json)

    # Call Rust bridge
    envelope = call_core_bridge("decode_envelope_json", raw_json=raw_json)
    if not isinstance(envelope, dict):
        raise CodecError(f"Bridge returned non-dictionary envelope: {type(envelope).__name__}")

    # Defensive decode in Python
    return py_decode_value(envelope)


def _validate_verdict_result_shape(res: Any) -> Dict[str, Any]:
    """Validates the exact closed schema and value types of VerificationResult."""
    if not isinstance(res, dict):
        raise TypeError(f"verdict result must be a dict, got {type(res).__name__}")
    required_keys = {"passed", "status", "error_type", "discovered", "executed", "failed", "errors"}
    if set(res.keys()) != required_keys:
        raise ValueError(f"verdict result keys mismatch: expected {required_keys}, got {set(res.keys())}")
    if not isinstance(res["passed"], bool):
        raise TypeError(f"'passed' must be bool, got {type(res['passed']).__name__}")
    if not isinstance(res["status"], str):
        raise TypeError(f"'status' must be str, got {type(res['status']).__name__}")
    if res["error_type"] is not None and not isinstance(res["error_type"], str):
        raise TypeError(f"'error_type' must be Optional[str], got {type(res['error_type']).__name__}")
    for k in ("discovered", "executed", "failed", "errors"):
        if not isinstance(res[k], int) or isinstance(res[k], bool):
            raise TypeError(f"'{k}' must be int, got {type(res[k]).__name__}")
    return res


def verify_verdict_frame(
    comb_out: str,
    parent_nonce: str,
    parent_hmac_key: str,
    expected_test_ids: Tuple[str, ...] = (),
    exit_code: int = 0,
    res_status: str = "ok",
    expected_test_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verifies an authenticated verdict frame.
    When PAI_USE_RUST_CORE is active:
    - Runs in shadow mode comparing Rust bridge output directly with Python reference
    - Defensively validates the return dictionary shape
    - Logs and refuses (returns fail-closed INTEGRITY_VIOLATION) on any difference
    """
    py_res = py_verify_verdict_frame(
        comb_out=comb_out,
        parent_nonce=parent_nonce,
        parent_hmac_key=parent_hmac_key,
        expected_test_ids=expected_test_ids,
        exit_code=exit_code,
        res_status=res_status,
        expected_test_hash=expected_test_hash,
    )
    if not is_rust_core_enabled():
        return py_res

    record_shadow_comparison("verify_verdict_frame")

    bridge_kwargs: Dict[str, Any] = {
        "comb_out": comb_out,
        "parent_nonce": parent_nonce,
        "parent_hmac_key": parent_hmac_key,
        "expected_test_ids": list(expected_test_ids),
        "exit_code": exit_code,
        "res_status": res_status,
    }
    if expected_test_hash is not None:
        bridge_kwargs["expected_test_hash"] = expected_test_hash

    try:
        raw_bridge_res = call_core_bridge("verify_verdict_frame", **bridge_kwargs)
        bridge_res = _validate_verdict_result_shape(raw_bridge_res)
    except CoreBridgeUnavailableError:
        raise
    except Exception as exc:
        record_shadow_discrepancy(
            "verify_verdict_frame",
            f"Bridge invocation exception: {exc}",
            exception=type(exc).__name__,
        )
        return {
            "passed": False,
            "status": "INTEGRITY_VIOLATION",
            "error_type": "VerdictBridgeExecutionError",
            "discovered": 0,
            "executed": 0,
            "failed": 0,
            "errors": 1,
        }

    if bridge_res != py_res:
        record_shadow_discrepancy(
            "verify_verdict_frame",
            f"Verdict mismatch between Python reference and Rust bridge: py={py_res!r} vs rust={bridge_res!r}",
            py_res=py_res,
            rust_res=bridge_res,
        )
        return {
            "passed": False,
            "status": "INTEGRITY_VIOLATION",
            "error_type": "VerdictDifferentialMismatchError",
            "discovered": 0,
            "executed": 0,
            "failed": 0,
            "errors": 1,
        }

    return bridge_res


def extract_example_assertions(prompt: str, entry_point: Optional[str] = None) -> List[str]:
    """
    Extracts canonical assertions from example docstring section.
    When PAI_USE_RUST_CORE is active:
    - Runs in shadow mode where Python reference remains authoritative (returned).
    - If pai-core binary is unavailable or fails handshake, raises CoreBridgeUnavailableError.
    - Re-parses every single returned statement from Rust with ast.parse.
    - Defensively validates that every statement is an assert or assignment.
    - If Rust differs from Python or bridge call throws, records the discrepancy in a counter and returns Python assertions.
    """
    py_stmts = py_extract_example_assertions(prompt, entry_point=entry_point)
    if not is_rust_core_enabled():
        return py_stmts

    record_shadow_comparison("extract_example_assertions")

    kwargs: Dict[str, Any] = {"prompt": prompt}
    if entry_point is not None:
        kwargs["entry_point"] = entry_point

    try:
        raw_stmts = call_core_bridge("extract_example_assertions", **kwargs)
    except CoreBridgeUnavailableError:
        raise
    except Exception as exc:
        record_shadow_discrepancy(
            "extract_example_assertions",
            f"Bridge invocation exception: {exc}",
            exception=type(exc).__name__,
        )
        return py_stmts

    if not isinstance(raw_stmts, list):
        record_shadow_discrepancy(
            "extract_example_assertions",
            f"Bridge returned non-list: {type(raw_stmts).__name__}",
        )
        return py_stmts

    verified_stmts: List[str] = []
    for s in raw_stmts:
        if not isinstance(s, str):
            continue
        try:
            tree = ast.parse(s)
            if len(tree.body) != 1:
                continue
            stmt = tree.body[0]
            if not isinstance(stmt, (ast.Assert, ast.Assign)):
                continue
            verified_stmts.append(s)
        except SyntaxError:
            continue

    if not any(s.startswith("assert ") for s in verified_stmts):
        rust_final: List[str] = []
    else:
        rust_final = verified_stmts

    if rust_final != py_stmts:
        record_shadow_discrepancy(
            "extract_example_assertions",
            f"Example assertion mismatch: py={py_stmts!r} vs rust={rust_final!r}",
            py_stmts=py_stmts,
            rust_stmts=rust_final,
        )

    # In shadow mode, Python reference is authoritative!
    return py_stmts


# ============================================================================
# Crypto & Updater Primitives (Slice 4)
# ============================================================================

def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verifies an Ed25519 signature over `message` with `public_key`.
    When PAI_USE_RUST_CORE is active (and fallback not forced), Rust core is authoritative.
    When PAI_SHADOW_COMPARE is active, shadow comparison against Python reference is performed.

    NOTE (Finding O): This bridge wrapper is maintained for vector conformance and differential
    testing; it is not called directly by product code during release updates. In production:
    - The Python path (`Updater.verify_release`) verifies signatures directly via `ed25519_ref`.
    - The Rust path (`Updater.verify_release` via bridge `verify_release`) verifies signatures
      internally inside the Rust core engine.
    """
    import ed25519_ref

    if not is_rust_core_enabled():
        return ed25519_ref.verify(public_key, message, signature)

    find_core_binary()

    try:
        rust_ver = call_core_bridge(
            "verify_ed25519",
            public_key_hex=public_key.hex(),
            message_hex=message.hex(),
            signature_hex=signature.hex(),
        )
    except (CoreBridgeUnavailableError, BridgeProtocolError):
        raise
    except Exception as exc:
        record_shadow_discrepancy(
            "verify_ed25519",
            f"Bridge invocation exception: {exc}",
            exception=type(exc).__name__,
        )
        raise BridgeProtocolError(f"Bridge invocation exception: {exc}") from exc

    if not isinstance(rust_ver, bool):
        record_shadow_discrepancy(
            "verify_ed25519",
            f"Bridge returned non-bool: {type(rust_ver).__name__}",
        )
        raise BridgeProtocolError(f"Bridge returned non-bool: {type(rust_ver).__name__}")

    if is_shadow_compare_enabled():
        record_shadow_comparison("verify_ed25519")
        py_ver = ed25519_ref.verify(public_key, message, signature)
        if py_ver != rust_ver:
            record_shadow_discrepancy(
                "verify_ed25519",
                f"Ed25519 verification mismatch: py={py_ver} vs rust={rust_ver}",
                py_res=py_ver,
                rust_res=rust_ver,
            )

    return rust_ver


def verify_release(
    release_dir: str,
    trust_config_json: str,
    expected_product: str = "pai-core",
    check_rollback: bool = True,
    highest_seen_version: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verifies a release directory via pai-core bridge.
    Raises UpdateRejected on verification failure.
    """
    find_core_binary()
    return call_core_bridge(
        "verify_release",
        release_dir=os.path.abspath(release_dir),
        trust_root_json=trust_config_json,
        expected_product=expected_product,
        check_rollback=check_rollback,
        highest_seen_version=highest_seen_version,
    )


# ============================================================================
# Ingestion Primitives (Slice 5)
# ============================================================================

def ingest_file(
    file_path: str,
    root_path: Optional[str] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    deny_patterns: Tuple[str, ...] = DEFAULT_SECRET_DENY_PATTERNS,
) -> Tuple[Optional[IngestedItem], Optional[IngestionRejection]]:
    """
    Safely ingests a single file.
    When PAI_USE_RUST_CORE is active (and fallback not forced), Rust core is authoritative.
    When PAI_SHADOW_COMPARE is active, shadow comparison against Python reference is performed.
    """
    if max_line_length <= 0 or max_line_length > 1_000_000:
        raise ValueError("max_line_length must be between 1 and 1000000")
    if max_file_size <= 0 or max_file_size > 100_000_000:
        raise ValueError("max_file_size must be between 1 and 100000000")

    if not is_rust_core_enabled():
        return py_ingest_file(
            file_path=file_path,
            root_path=root_path,
            max_file_size=max_file_size,
            max_line_length=max_line_length,
            deny_patterns=deny_patterns,
        )

    # Fast-path check for lone surrogates or unencodable paths that cannot cross the bridge.
    # Return Python reference fast-path rejection directly before bridge lookup.
    if _is_invalid_filename(file_path) or _is_invalid_filename(os.path.basename(file_path)) or (root_path is not None and _is_invalid_filename(root_path)):
        return py_ingest_file(
            file_path=file_path,
            root_path=root_path,
            max_file_size=max_file_size,
            max_line_length=max_line_length,
            deny_patterns=deny_patterns,
        )

    find_core_binary()

    bridge_kwargs: Dict[str, Any] = {
        "file_path": file_path,
        "max_file_size": max_file_size,
        "max_line_length": max_line_length,
    }
    if root_path is not None:
        bridge_kwargs["root_path"] = root_path
    if deny_patterns != DEFAULT_SECRET_DENY_PATTERNS:
        bridge_kwargs["deny_patterns"] = list(deny_patterns)

    try:
        raw_res = call_core_bridge("ingest_file", **bridge_kwargs)
        raw_item = raw_res.get("item")
        raw_rej = raw_res.get("rejection")
        rust_item = IngestedItem(**raw_item) if raw_item else None
        rust_rej = IngestionRejection(**raw_rej) if raw_rej else None
    except (CoreBridgeUnavailableError, ValueError, BridgeProtocolError):
        raise
    except Exception as exc:
        record_shadow_discrepancy(
            "ingest_file",
            f"Bridge invocation exception: {exc}",
            exception=type(exc).__name__,
        )
        raise BridgeProtocolError(f"Bridge invocation exception: {exc}") from exc

    if is_shadow_compare_enabled():
        record_shadow_comparison("ingest_file")
        py_item, py_rej = py_ingest_file(
            file_path=file_path,
            root_path=root_path,
            max_file_size=max_file_size,
            max_line_length=max_line_length,
            deny_patterns=deny_patterns,
        )
        if (rust_item != py_item) or (rust_rej != py_rej):
            record_shadow_discrepancy(
                "ingest_file",
                f"Ingest file mismatch: py=({py_item!r}, {py_rej!r}) vs rust=({rust_item!r}, {rust_rej!r})",
                py_item=py_item.to_dict() if py_item else None,
                rust_item=rust_item.to_dict() if rust_item else None,
                py_rej=py_rej.to_dict() if py_rej else None,
                rust_rej=rust_rej.to_dict() if rust_rej else None,
            )

    return rust_item, rust_rej


def ingest_folder(
    folder_path: str,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_file_count: int = DEFAULT_MAX_FILE_COUNT,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    deny_patterns: Tuple[str, ...] = DEFAULT_SECRET_DENY_PATTERNS,
    junk_patterns: Tuple[str, ...] = DEFAULT_JUNK_DIR_PATTERNS,
    include_junk: bool = False,
    max_rejections_per_reason: int = DEFAULT_MAX_REJECTIONS_PER_REASON,
    max_total_rejections: int = DEFAULT_MAX_TOTAL_REJECTIONS,
) -> IngestionReport:
    """
    Safely ingests a folder tree.
    When PAI_USE_RUST_CORE is active (and fallback not forced), Rust core is authoritative.
    When PAI_SHADOW_COMPARE is active, shadow comparison against Python reference is performed.
    """
    if max_line_length <= 0 or max_line_length > 1_000_000:
        raise ValueError("max_line_length must be between 1 and 1000000")
    if max_file_size <= 0 or max_file_size > 100_000_000:
        raise ValueError("max_file_size must be between 1 and 100000000")
    if max_total_bytes <= 0 or max_total_bytes > 1_000_000_000:
        raise ValueError("max_total_bytes must be between 1 and 1000000000")
    if max_file_count <= 0 or max_file_count > 1_000_000:
        raise ValueError("max_file_count must be between 1 and 1000000")
    if max_depth <= 0 or max_depth > 64:
        raise ValueError("max_depth must be between 1 and 64")
    if max_rejections_per_reason <= 0 or max_rejections_per_reason > 10_000:
        raise ValueError("max_rejections_per_reason must be between 1 and 10000")
    if max_total_rejections <= 0 or max_total_rejections > 50_000:
        raise ValueError("max_total_rejections must be between 1 and 50000")

    if not is_rust_core_enabled():
        return py_ingest_folder(
            folder_path=folder_path,
            max_file_size=max_file_size,
            max_total_bytes=max_total_bytes,
            max_file_count=max_file_count,
            max_depth=max_depth,
            max_line_length=max_line_length,
            deny_patterns=deny_patterns,
            junk_patterns=junk_patterns,
            include_junk=include_junk,
            max_rejections_per_reason=max_rejections_per_reason,
            max_total_rejections=max_total_rejections,
        )

    find_core_binary()

    bridge_kwargs: Dict[str, Any] = {
        "folder_path": folder_path,
        "max_file_size": max_file_size,
        "max_total_bytes": max_total_bytes,
        "max_file_count": max_file_count,
        "max_depth": max_depth,
        "max_line_length": max_line_length,
        "include_junk": include_junk,
        "max_rejections_per_reason": max_rejections_per_reason,
        "max_total_rejections": max_total_rejections,
    }
    if deny_patterns != DEFAULT_SECRET_DENY_PATTERNS:
        bridge_kwargs["deny_patterns"] = list(deny_patterns)
    if junk_patterns != DEFAULT_JUNK_DIR_PATTERNS:
        bridge_kwargs["junk_patterns"] = list(junk_patterns)

    try:
        raw_res = call_core_bridge("ingest_folder", **bridge_kwargs)
        rust_items = [IngestedItem(**it) for it in raw_res.get("items", [])]
        rust_rejections = [IngestionRejection(**rej) for rej in raw_res.get("rejections", [])]
        rust_report = IngestionReport(
            root=raw_res.get("root", ""),
            items=rust_items,
            rejections=rust_rejections,
            total_bytes=raw_res.get("total_bytes", 0),
            total_files=raw_res.get("total_files", 0),
            limits=raw_res.get("limits", {}),
            rejection_counts=raw_res.get("rejection_counts", {}),
            rejections_capped=raw_res.get("rejections_capped", False),
        )
    except (CoreBridgeUnavailableError, ValueError, BridgeProtocolError):
        raise
    except Exception as exc:
        record_shadow_discrepancy(
            "ingest_folder",
            f"Bridge invocation exception: {exc}",
            exception=type(exc).__name__,
        )
        raise BridgeProtocolError(f"Bridge invocation exception: {exc}") from exc

    if is_shadow_compare_enabled():
        record_shadow_comparison("ingest_folder")
        py_report = py_ingest_folder(
            folder_path=folder_path,
            max_file_size=max_file_size,
            max_total_bytes=max_total_bytes,
            max_file_count=max_file_count,
            max_depth=max_depth,
            max_line_length=max_line_length,
            deny_patterns=deny_patterns,
            junk_patterns=junk_patterns,
            include_junk=include_junk,
            max_rejections_per_reason=max_rejections_per_reason,
            max_total_rejections=max_total_rejections,
        )
        py_dict = py_report.to_dict()
        rust_dict = rust_report.to_dict()
        if py_dict != rust_dict:
            record_shadow_discrepancy(
                "ingest_folder",
                f"Ingest folder report mismatch: total_files (py={py_report.total_files} vs rust={rust_report.total_files}), total_bytes (py={py_report.total_bytes} vs rust={rust_report.total_bytes})",
                py_report=py_dict,
                rust_report=rust_dict,
            )

    return rust_report

