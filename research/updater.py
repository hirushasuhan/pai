"""
Signed-release updater (review risk R4).

WHY: a self-modifying engine cannot protect itself - if it can rewrite its binary it can rewrite any
hash embedded in it. Trust must therefore come from OUTSIDE the engine:

  * releases are signed with an Ed25519 key that never exists on this machine (offline signing,
    see sign_release.py); this machine only holds PUBLIC keys
  * this updater is a SEPARATE program run with its own privileges. The trust root (public keys, the
    pinned Constitution hash) and the install directory are writable only by the updater's account,
    not by the engine's. `trust_root_is_protected()` lets the engine fail closed at start-up if not.
  * the updater - not the engine - owns the Constitution hash: a release whose Constitution differs
    from the pinned one is refused, so intent drift needs a human-signed trust-root change.

Checks on every release: signature over the EXACT manifest bytes (no re-serialisation), key not
revoked, product match, strictly increasing version (anti-rollback counter), pinned Constitution hash,
every file listed with size + SHA-256, safe relative paths, no unlisted files, and a second full
verification of the staged copy (TOCTOU). Install is atomic; the previous release is kept for rollback.

Prototype scope: file-level logic is real and tested; OS-level privilege separation (separate Windows
account / ACLs) is configuration the Phase 2/4 installer must perform.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import ed25519_ref
import pai_core_bridge

MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"
MAX_MANIFEST_BYTES = 1024 * 1024
_VERSION_RE = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+\Z")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class UpdateRejected(Exception):
    """A release failed verification; nothing was installed."""


@dataclass
class VerifiedRelease:
    version: str
    key_id: str
    files: List[str]
    manifest: Dict


def parse_version(v: str) -> Tuple[int, int, int]:
    if not isinstance(v, str) or not _VERSION_RE.fullmatch(v):
        raise UpdateRejected(f"bad version '{v}'")
    parts = v.split(".")
    nums = [int(p) for p in parts]
    if any(n > 4294967295 for n in nums):
        raise UpdateRejected(f"bad version '{v}' (exceeds u32)")
    return (nums[0], nums[1], nums[2])


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(release_dir: str, product: str, version: str, constitution_sha256: str) -> bytes:
    """Used by the signing tool: lists every payload file with size + SHA-256."""
    parse_version(version)
    files = {}
    for dirpath, _, names in os.walk(release_dir):
        for n in sorted(names):
            full = os.path.join(dirpath, n)
            rel = os.path.relpath(full, release_dir).replace(os.sep, "/")
            if rel in (MANIFEST, SIGNATURE):
                continue
            files[rel] = {"sha256": sha256_file(full), "size": os.path.getsize(full)}
    doc = {"format": 1, "product": product, "version": version, "constitution_sha256": constitution_sha256, "files": files}
    return json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")


def _atomic_write_json(path: str, obj) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def trust_root_is_protected(path: str) -> bool:
    """Engine-side start-up check: returns True only if THIS process cannot write into `path`.
    The engine must refuse to run (fail closed) if the trust root or install dir is writable by it."""
    probe = os.path.join(path, f".probe-{os.getpid()}")
    try:
        with open(probe, "x"):
            pass
    except OSError:
        return True
    try:
        os.unlink(probe)
    except OSError:
        pass
    return False


class Updater:
    def __init__(self, trust_root: str, install_root: str, product: str = "pai-core"):
        self.trust_root, self.install_root, self.product = trust_root, install_root, product
        with open(os.path.join(trust_root, "trust.json"), encoding="utf-8") as f:
            self._raw_trust_json = f.read()
            trust = json.loads(self._raw_trust_json)
        if not isinstance(trust.get("keys"), list) or len(trust["keys"]) == 0:
            raise ValueError("trust.json must contain a non-empty 'keys' list")
        const_sha = str(trust.get("constitution_sha256", ""))
        if not _SHA_RE.match(const_sha):
            raise ValueError(f"invalid constitution_sha256: {const_sha}")
        self.constitution_sha256: str = const_sha
        self.keys: Dict[str, bytes] = {}
        for k in trust["keys"]:
            hex_key = k.get("public_hex", "")
            if not isinstance(hex_key, str) or len(hex_key) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_key):
                raise ValueError(f"bad public key hex {k.get('id')}")
            try:
                pub = bytes.fromhex(hex_key)
            except ValueError as e:
                raise ValueError(f"bad public key {k.get('id')}: {e}") from e
            if len(pub) != 32:
                raise ValueError(f"bad public key length {k['id']}")
            if not ed25519_ref.validate_trust_public_key(pub):
                raise ValueError(f"invalid curve point or small-order key {k['id']}")
            if not k.get("revoked", False):
                self.keys[k["id"]] = pub
        os.makedirs(os.path.join(install_root, "releases"), exist_ok=True)
        self._state_path = os.path.join(install_root, "state.json")
        self._current_path = os.path.join(install_root, "current.json")

    # ------------------------------------------------------------------ state
    def _state(self) -> Dict:
        if os.path.exists(self._state_path):
            with open(self._state_path, encoding="utf-8") as f:
                return json.load(f)
        return {"highest_seen": "0.0.0"}

    def current_version(self) -> Optional[str]:
        if not os.path.exists(self._current_path):
            return None
        with open(self._current_path, encoding="utf-8") as f:
            return json.load(f)["version"]

    # ----------------------------------------------------------- verification
    def _verify_release_py(self, release_dir: str, check_rollback: bool = True) -> VerifiedRelease:
        mpath, spath = os.path.join(release_dir, MANIFEST), os.path.join(release_dir, SIGNATURE)
        if not (os.path.isfile(mpath) and os.path.isfile(spath)):
            raise UpdateRejected("manifest or signature missing")
        if os.path.getsize(mpath) > MAX_MANIFEST_BYTES:
            raise UpdateRejected("manifest too large")
        with open(mpath, "rb") as f:
            manifest_bytes = f.read()
        with open(spath, "rb") as f:
            raw_sig = f.read()
        sig = raw_sig  # 64 raw bytes (do NOT strip: a binary signature may end in whitespace-valued bytes)
        if len(raw_sig) != 64:
            try:
                sig_text = raw_sig.decode("ascii")
                # Strip at most an optional trailing newline (\r\n or \n)
                if sig_text.endswith("\r\n"):
                    trimmed = sig_text[:-2]
                elif sig_text.endswith("\n"):
                    trimmed = sig_text[:-1]
                else:
                    trimmed = sig_text
                # Must be exactly 128 hex characters with no spaces or whitespace
                if len(trimmed) == 128 and all(c in "0123456789abcdefABCDEF" for c in trimmed):
                    sig = bytes.fromhex(trimmed)
                else:
                    sig = b""
            except (ValueError, UnicodeDecodeError):
                sig = b""

        key_id = next((kid for kid, pub in self.keys.items() if ed25519_ref.verify(pub, manifest_bytes, sig)), None)
        if key_id is None:
            raise UpdateRejected("signature invalid or signed by an unknown/revoked key")

        try:
            m = json.loads(manifest_bytes.decode("utf-8"))
            files = m["files"]
            version, product, const = m["version"], m["product"], m["constitution_sha256"]
        except (ValueError, KeyError, TypeError):
            raise UpdateRejected("malformed manifest")
        fmt = m.get("format")
        if type(fmt) is not int or fmt != 1 or product != self.product:
            raise UpdateRejected("wrong manifest format or product")
        if const != self.constitution_sha256:
            raise UpdateRejected("Constitution hash differs from the pinned trust-root value")
        v = parse_version(version)
        if check_rollback and v <= parse_version(self._state()["highest_seen"]):
            raise UpdateRejected(f"version {version} is not newer than highest seen {self._state()['highest_seen']} (anti-rollback)")
        if not isinstance(files, dict) or not files:
            raise UpdateRejected("manifest lists no files")

        root = os.path.realpath(release_dir)
        for rel, meta in files.items():
            if (not isinstance(rel, str) or rel.startswith(("/", "\\")) or "\\" in rel or ":" in rel
                    or any(part in ("..", "", ".") for part in rel.split("/"))):
                raise UpdateRejected(f"unsafe path in manifest: {rel!r}")
            raw_path = os.path.join(root, *rel.split("/"))
            try:
                pre_lst = os.lstat(raw_path)
            except OSError:
                raise UpdateRejected(f"listed file missing: {rel}")
            if stat.S_ISLNK(pre_lst.st_mode):
                raise UpdateRejected(f"path escapes release directory: {rel!r}")
            full = os.path.realpath(raw_path)
            if os.path.commonpath([full, root]) != root:
                raise UpdateRejected(f"path escapes release directory: {rel!r}")
            if not isinstance(meta, dict) or not _SHA_RE.match(str(meta.get("sha256", ""))):
                raise UpdateRejected(f"bad digest entry for {rel}")
            sz = meta.get("size")
            if type(sz) is not int or sz < 0:
                raise UpdateRejected(f"bad size in manifest for {rel}")

            try:
                with open(full, "rb") as f:
                    st_handle = os.fstat(f.fileno())
                    if not stat.S_ISREG(st_handle.st_mode):
                        raise UpdateRejected(f"listed file missing: {rel}")
                    if st_handle.st_size != sz:
                        raise UpdateRejected(f"size mismatch: {rel}")
                    if (
                        hasattr(st_handle, "st_ino")
                        and hasattr(pre_lst, "st_ino")
                        and pre_lst.st_ino != 0
                    ):
                        if (st_handle.st_dev, st_handle.st_ino) != (
                            pre_lst.st_dev,
                            pre_lst.st_ino,
                        ):
                            raise UpdateRejected(f"listed file replaced during verification: {rel}")
                    h = hashlib.sha256()
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                    if h.hexdigest() != meta["sha256"]:
                        raise UpdateRejected(f"SHA-256 mismatch (tampered?): {rel}")
            except UpdateRejected:
                raise
            except (OSError, IOError):
                raise UpdateRejected(f"listed file missing: {rel}")

        listed = set(files) | {MANIFEST, SIGNATURE}

        def _verify_dir_entries(curr_dir: str) -> None:
            with os.scandir(curr_dir) as it:
                for entry in it:
                    if entry.is_symlink():
                        raise UpdateRejected(f"symlink in release: {entry.name}")
                    if entry.is_dir(follow_symlinks=False):
                        _verify_dir_entries(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        rel = os.path.relpath(entry.path, root).replace(os.sep, "/")
                        if rel not in listed:
                            raise UpdateRejected(f"unlisted file in release: {rel}")
                    else:
                        raise UpdateRejected(f"non-regular file in release: {entry.name}")

        _verify_dir_entries(root)
        return VerifiedRelease(version, key_id, sorted(files), m)

    def verify_release(self, release_dir: str, check_rollback: bool = True) -> VerifiedRelease:
        if not pai_core_bridge.PAI_USE_RUST_CORE:
            return self._verify_release_py(release_dir, check_rollback=check_rollback)

        # Fail-closed if binary missing or handshake fails
        pai_core_bridge.find_core_binary()
        pai_core_bridge.record_shadow_comparison("verify_release")

        trust_cfg_json = getattr(self, "_raw_trust_json", None)
        if trust_cfg_json is None:
            trust_cfg = {
                "keys": [{"id": kid, "public_hex": pub.hex(), "revoked": False} for kid, pub in self.keys.items()],
                "constitution_sha256": self.constitution_sha256,
            }
            trust_cfg_json = json.dumps(trust_cfg)
        highest = self._state()["highest_seen"] if check_rollback else None

        rust_res = None
        rust_err = None
        try:
            rust_res = pai_core_bridge.verify_release(
                release_dir=release_dir,
                trust_config_json=trust_cfg_json,
                expected_product=self.product,
                check_rollback=check_rollback,
                highest_seen_version=highest,
            )
        except Exception as e:
            rust_err = e

        py_res = None
        py_err = None
        try:
            py_res = self._verify_release_py(release_dir, check_rollback=check_rollback)
        except Exception as e:
            py_err = e

        if (py_res is None) != (rust_res is None):
            pai_core_bridge.record_shadow_discrepancy(
                "verify_release",
                f"Release verification outcome mismatch: py_res={py_res is not None} vs rust_res={rust_res is not None} (py_err={py_err}, rust_err={rust_err})",
            )
        elif py_res is not None and rust_res is not None:
            if py_res.version != rust_res.get("version") or py_res.key_id != rust_res.get("key_id") or py_res.files != rust_res.get("files"):
                pai_core_bridge.record_shadow_discrepancy(
                    "verify_release",
                    f"Release metadata mismatch: py=({py_res.version}, {py_res.key_id}, {len(py_res.files)}) vs rust=({rust_res.get('version')}, {rust_res.get('key_id')}, {len(rust_res.get('files', []))})",
                )

        if py_err is not None:
            raise py_err
        return py_res

    # ---------------------------------------------------------------- install
    def install(self, release_dir: str) -> VerifiedRelease:
        rel = self.verify_release(release_dir)
        releases = os.path.join(self.install_root, "releases")
        dest = os.path.join(releases, rel.version)
        if os.path.exists(dest):
            raise UpdateRejected(f"version {rel.version} already installed")
        tmp = tempfile.mkdtemp(prefix=".staging-", dir=releases)
        try:
            for name in rel.files + [MANIFEST, SIGNATURE]:
                target = os.path.join(tmp, *name.split("/"))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copyfile(os.path.join(release_dir, *name.split("/")), target)
            self.verify_release(tmp, check_rollback=True)  # TOCTOU: verify what we actually staged
            os.replace(tmp, dest)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        previous = self.current_version()
        _atomic_write_json(self._current_path, {"version": rel.version, "previous": previous})
        _atomic_write_json(self._state_path, {"highest_seen": rel.version})
        return rel

    def rollback(self) -> str:
        """Emergency reversion to the previously installed release (re-verified first).
        Deliberately does NOT lower the anti-rollback counter: nothing newer-than-current can be replayed."""
        if not os.path.exists(self._current_path):
            raise UpdateRejected("nothing installed")
        with open(self._current_path, encoding="utf-8") as f:
            cur = json.load(f)
        prev = cur.get("previous")
        if not prev:
            raise UpdateRejected("no previous release to roll back to")
        self.verify_release(os.path.join(self.install_root, "releases", prev), check_rollback=False)
        _atomic_write_json(self._current_path, {"version": prev, "previous": None})
        return prev
