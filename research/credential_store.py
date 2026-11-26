"""OS-backed Credential Storage for PAI (Windows DPAPI + POSIX 0o600 fallback).

Provides DPAPI encryption at rest via crypt32.CryptProtectData / CryptUnprotectData
on Windows (`sys.platform == "win32"`) and atomic 0o600 permission-hardened file
helpers for POSIX platforms.

All Win32 ctypes usage in this module is strictly restricted to DPAPI and buffer
management APIs governed by ADR-011 Addendum (FINDING-11) and verified by
`research/tests/test_ctypes_allowlist.py`.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import os
import secrets
import sys
from ctypes import wintypes
from pathlib import Path

DPAPI_PREFIX = "dpapi:"
CRYPTPROTECT_UI_FORBIDDEN = 0x01


class CredentialStoreError(ValueError):
    """Raised when credential protection or unprotection fails closed."""


if sys.platform == "win32":
    # SAFETY: Restrict WinDLL imports strictly to crypt32 DPAPI and kernel32 LocalFree.
    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", wintypes.PBYTE),
        ]

    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DATA_BLOB),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptProtectData.restype = wintypes.BOOL

    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DATA_BLOB),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL

    _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    _kernel32.LocalFree.restype = wintypes.HLOCAL


def is_dpapi_protected(value: str) -> bool:
    """Return True if value carries the DPAPI ciphertext prefix."""
    return isinstance(value, str) and value.startswith(DPAPI_PREFIX)


def _dpapi_protect_bytes(raw_bytes: bytes) -> bytes:
    """Encrypt raw bytes with Windows DPAPI (current user scope, no UI)."""
    in_buf = (wintypes.BYTE * len(raw_bytes)).from_buffer_copy(raw_bytes)
    in_blob = _DATA_BLOB(
        wintypes.DWORD(len(raw_bytes)),
        ctypes.cast(in_buf, wintypes.PBYTE),
    )
    out_blob = _DATA_BLOB()
    try:
        # SAFETY: CryptProtectData allocates out_blob.pbData with LocalAlloc; freed in finally.
        ok = _crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            wintypes.DWORD(CRYPTPROTECT_UI_FORBIDDEN),
            ctypes.byref(out_blob),
        )
        if not ok:
            err = ctypes.get_last_error()
            raise CredentialStoreError(f"DPAPI CryptProtectData failed (Win32 error {err}).")
        if not out_blob.pbData or out_blob.cbData == 0:
            raise CredentialStoreError("DPAPI CryptProtectData returned an empty buffer.")
        return bytes(out_blob.pbData[: out_blob.cbData])
    finally:
        # SAFETY: Zeroize plaintext buffer before returning and free DPAPI allocation.
        ctypes.memset(in_buf, 0, len(raw_bytes))
        if out_blob.pbData:
            _kernel32.LocalFree(ctypes.cast(out_blob.pbData, wintypes.HLOCAL))


def _dpapi_unprotect_bytes(cipher_bytes: bytes) -> bytes:
    """Decrypt DPAPI ciphertext bytes for the current Windows user."""
    in_buf = (wintypes.BYTE * len(cipher_bytes)).from_buffer_copy(cipher_bytes)
    in_blob = _DATA_BLOB(
        wintypes.DWORD(len(cipher_bytes)),
        ctypes.cast(in_buf, wintypes.PBYTE),
    )
    out_blob = _DATA_BLOB()
    try:
        # SAFETY: CryptUnprotectData allocates out_blob.pbData with LocalAlloc; zeroized and freed in finally.
        ok = _crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            wintypes.DWORD(CRYPTPROTECT_UI_FORBIDDEN),
            ctypes.byref(out_blob),
        )
        if not ok:
            err = ctypes.get_last_error()
            raise CredentialStoreError(f"DPAPI CryptUnprotectData failed (Win32 error {err}).")
        if not out_blob.pbData:
            raise CredentialStoreError("DPAPI CryptUnprotectData returned a null buffer.")
        return bytes(out_blob.pbData[: out_blob.cbData])
    finally:
        if out_blob.pbData:
            ctypes.memset(out_blob.pbData, 0, out_blob.cbData)
            _kernel32.LocalFree(ctypes.cast(out_blob.pbData, wintypes.HLOCAL))


def protect_secret(plaintext: str) -> str:
    """Protect a secret string for at-rest storage.

    On Windows, encrypts with DPAPI and returns a `dpapi:<base64>` blob.
    On non-Windows platforms without DPAPI, returns plaintext and relies on
    `0o600` file permissions via `write_secret_file` / `harden_secret_file`.
    """
    if not isinstance(plaintext, str):
        raise TypeError("plaintext secret must be a str.")
    if plaintext == "":
        return ""
    if sys.platform != "win32":
        return plaintext
    raw_bytes = plaintext.encode("utf-8")
    cipher = _dpapi_protect_bytes(raw_bytes)
    return DPAPI_PREFIX + base64.b64encode(cipher).decode("ascii")


def unprotect_secret(blob: str) -> str:
    """Unprotect a stored secret string (DPAPI blob or legacy plaintext)."""
    if not isinstance(blob, str):
        raise TypeError("stored secret blob must be a str.")
    if not blob:
        return ""
    if not is_dpapi_protected(blob):
        return blob
    if sys.platform != "win32":
        raise CredentialStoreError("DPAPI-protected credentials can only be decrypted on Windows.")

    payload = blob[len(DPAPI_PREFIX) :]
    if not payload:
        raise CredentialStoreError("Empty DPAPI credential payload.")
    try:
        cipher = base64.b64decode(payload.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CredentialStoreError("Malformed DPAPI base64 payload.") from exc
    if not cipher:
        raise CredentialStoreError("Empty DPAPI ciphertext.")

    plain_bytes = _dpapi_unprotect_bytes(cipher)
    try:
        return plain_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CredentialStoreError("Decrypted DPAPI payload is not valid UTF-8.") from exc


def harden_secret_file(path: Path) -> None:
    """Enforce owner-only 0o600 permissions on POSIX secret files."""
    if os.name == "nt" or not path.exists():
        return
    try:
        mode = path.stat().st_mode
        if (mode & 0o077) != 0:
            os.chmod(path, 0o600)
    except OSError:
        pass


def write_secret_file(path: Path, text: str) -> None:
    """Atomically write secret content with owner-only (0o600 on POSIX) mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(tmp_path), flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(str(tmp_path), 0o600)
        os.replace(str(tmp_path), str(path))
        if os.name != "nt":
            os.chmod(str(path), 0o600)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
