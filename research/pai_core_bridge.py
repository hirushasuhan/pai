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
    defang_envelope_markers as py_defang_envelope_markers,
    get_ingest_limits as py_get_ingest_limits,
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

MAX_REQUEST_BYTES = 16 * 1024 * 1024  # 16 MiB

_CORE_BIN_CACHE: Optional[str] = None

_SHADOW_DISCREPANCIES: List[Dict[str, Any]] = []


class CoreBridgeUnavailableError(RuntimeError):
    """Raised when PAI_USE_RUST_CORE is requested but pai-core binary is unavailable or cannot execute."""
    pass


def record_shadow_discrepancy(op: str, detail: str, **extra: Any) -> None:
    """Records a shadow discrepancy for visibility in run reports and pai doctor."""
    rec = {
        "timestamp": time.time(),
        "op": op,
        "detail": detail,
        **extra,
    }
    _SHADOW_DISCREPANCIES.append(rec)
    logger.warning("[SHADOW DISCREPANCY] op=%s: %s", op, detail)


def get_shadow_discrepancy_count() -> int:
    """Returns the total number of recorded shadow discrepancies."""
    return len(_SHADOW_DISCREPANCIES)


def get_shadow_discrepancies() -> List[Dict[str, Any]]:
    """Returns a copy of all recorded shadow discrepancies."""
    return list(_SHADOW_DISCREPANCIES)


def reset_shadow_discrepancies() -> None:
    """Resets the recorded shadow discrepancies."""
    _SHADOW_DISCREPANCIES.clear()


def compute_repo_vectors_hash() -> str:
    """Computes SHA-256 over canonical conformance vector files in the repository."""
    import hashlib
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")
    vector_files = [
        "tier_policy_vectors.json",
        "url_policy_vectors.json",
        "ingest_vectors.json",
        "verify_loop_vectors.json",
    ]
    h = hashlib.sha256()
    for vf in vector_files:
        p = os.path.join(base_dir, vf)
        if os.path.exists(p):
            with open(p, "rb") as f:
                h.update(vf.encode("utf-8"))
                h.update(f.read())
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
    req_json = json.dumps(payload, ensure_ascii=False)
    req_bytes = req_json.encode("utf-8")
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
        raise RuntimeError(f"Failed to spawn pai-core bridge: {exc}") from exc

    if proc.returncode != 0:
        err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"pai-core bridge failed (exit code {proc.returncode}): {err_msg}")

    stdout_str = proc.stdout.decode("utf-8", errors="replace").strip()
    if not stdout_str:
        raise RuntimeError(f"pai-core bridge returned empty output for op '{op}'")

    try:
        resp = json.loads(stdout_str)
    except Exception as exc:
        raise RuntimeError(f"pai-core bridge returned invalid JSON: {stdout_str[:200]}") from exc

    if not isinstance(resp, dict):
        raise TypeError(f"pai-core bridge response must be a JSON object, got {type(resp).__name__}")

    status = resp.get("status")
    if status == "error":
        err_text = resp.get("error", "Unknown error from Rust core")
        err_type = resp.get("error_type", "")
        if err_type == "CodecError":
            raise CodecError(err_text)
        raise ValueError(f"Rust core bridge error ({err_type}): {err_text}")

    if status != "ok":
        raise ValueError(f"Unexpected bridge status '{status}'")

    return resp.get("result")


# ============================================================================
# Ingest Primitives (with Rust Bridge & Defensive Verification)
# ============================================================================

def is_secret_file(file_path: str) -> bool:
    if not PAI_USE_RUST_CORE:
        return py_is_secret_file(file_path)
    res = call_core_bridge("is_secret_file", path=file_path)
    if not isinstance(res, bool):
        raise TypeError(f"is_secret_file expected bool from bridge, got {type(res).__name__}")
    return res


def is_junk_dir(dirname: str) -> bool:
    if not PAI_USE_RUST_CORE:
        return py_is_junk_dir(dirname)
    res = call_core_bridge("is_junk_dir", dirname=dirname)
    if not isinstance(res, bool):
        raise TypeError(f"is_junk_dir expected bool from bridge, got {type(res).__name__}")
    return res


def scan_secret_content(text: str, file_path: Optional[str] = None) -> Optional[str]:
    if not PAI_USE_RUST_CORE:
        return py_scan_secret_content(text, file_path=file_path)
    kwargs: Dict[str, Any] = {"text": text}
    if file_path is not None:
        kwargs["file_path"] = file_path
    res = call_core_bridge("scan_secret_content", **kwargs)
    if res is not None and not isinstance(res, str):
        raise TypeError(f"scan_secret_content expected str or None, got {type(res).__name__}")
    return res


def sanitize_terminal_output(text: str) -> str:
    if not PAI_USE_RUST_CORE:
        return py_sanitize_terminal_output(text)
    res = call_core_bridge("sanitize_terminal_output", text=text)
    if not isinstance(res, str):
        raise TypeError(f"sanitize_terminal_output expected str, got {type(res).__name__}")
    return res


def sanitize_text_content(raw_utf8: str, max_line_length: int = 4000) -> str:
    if max_line_length <= 0 or max_line_length > 1_000_000:
        raise ValueError(f"max_line_length must be between 1 and 1000000, got {max_line_length}")
    if not PAI_USE_RUST_CORE:
        return py_sanitize_text_content(raw_utf8.encode("utf-8"), max_line_length=max_line_length)
    res = call_core_bridge("sanitize_text_content", text=raw_utf8, max_line_length=max_line_length)
    if not isinstance(res, str):
        raise TypeError(f"sanitize_text_content expected str, got {type(res).__name__}")
    return res


def sanitize_header(header: str) -> str:
    if not PAI_USE_RUST_CORE:
        return py_sanitize_header(header)
    res = call_core_bridge("sanitize_header", header=header)
    if not isinstance(res, str):
        raise TypeError(f"sanitize_header expected str, got {type(res).__name__}")
    return res


def defang_envelope_markers(text: str, nonce: Optional[str] = None) -> str:
    if not PAI_USE_RUST_CORE:
        return py_defang_envelope_markers(text, nonce=nonce)
    kwargs: Dict[str, Any] = {"text": text}
    if nonce is not None:
        kwargs["nonce"] = nonce
    res = call_core_bridge("defang_envelope_markers", **kwargs)
    if not isinstance(res, str):
        raise TypeError(f"defang_envelope_markers expected str, got {type(res).__name__}")
    return res


def wrap_untrusted_envelope(content: str, header: Optional[str] = None, nonce: str = "") -> str:
    if not PAI_USE_RUST_CORE:
        return py_wrap_untrusted_envelope(content, header=header, nonce=nonce)
    kwargs: Dict[str, Any] = {"content": content, "nonce": nonce}
    if header is not None:
        kwargs["header"] = header
    res = call_core_bridge("wrap_untrusted_envelope", **kwargs)
    if not isinstance(res, str):
        raise TypeError(f"wrap_untrusted_envelope expected str, got {type(res).__name__}")
    return res


def get_ingest_limits() -> Dict[str, Any]:
    if not PAI_USE_RUST_CORE:
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
    if not PAI_USE_RUST_CORE:
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
    if not PAI_USE_RUST_CORE:
        return py_res

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
    if not PAI_USE_RUST_CORE:
        return py_stmts

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
