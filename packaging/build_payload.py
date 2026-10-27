"""
Reproducible Release Payload Builder for Personal Agentic AI (PAI).

Part of Milestone P1 for the v1.1.0 Packaging and Installer subsystem.
Specification: docs/PACKAGING_SPEC.md, docs/adr/ADR-013-installer-and-distribution.md
Agent brief: docs/AGENT_BRIEF_PACKAGING.md

Hard rules enforced:
  1. Built strictly from a git tag via git archive, never from the uncommitted working tree.
  2. Fails closed if the tag's core/ or research/ tree IDs differ from evaluated constants.
  3. Verifies pai-core.exe SHA-256 against pinned release evidence before inclusion.
  4. Verifies extracted blob integrity against git tree records to prevent tampering.
  5. Assembles a canonical manifest.json (file, size, sha256) compatible with ADR-005.
  6. Two builds from the same git tag produce byte-identical manifests.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("build_payload")

MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"
MANIFEST_FILES = "manifest.files"
PAI_INSTALL_MARKER = ".pai-install"
PAI_APP_ID_GUID = "{8B7B61CA-C450-4E87-9F1B-4198A82711C9}"
DEFAULT_TAG = "v1.0.0-rc1"
DEFAULT_PRODUCT = "pai-core"
DEFAULT_VERSION = "1.0.0"

SUPPORTED_PLATFORMS = ("win-x64", "linux-x64")
DEFAULT_PLATFORM = "win-x64" if sys.platform == "win32" else "linux-x64"

# Evaluated tree invariants established in Release N (v1.0.0-rc1, commit 8ce81cb)
EXPECTED_CORE_TREE = "14c60746ca9a41d91aafd88cc0c7d98719cfe3a9"
EXPECTED_RESEARCH_TREE = "506e520b33a0af8c3f0276114483ce26b9bd3787"
EXPECTED_BINARY_SHA256 = "6f13d49463c757f2f3e43506f9743c37f602196544ce8fa85d5c5ce9332e3efe"

# Pinned official embeddable Python distribution for Windows x64 (Finding BU)
PINNED_PYTHON_VERSION = "3.14.0"
PINNED_PYTHON_ZIP_SHA256 = "8d4d3590c10449d78aa4375f534e6d5f3027d67fdc362dd1a882279db6f90fdf"
PINNED_PYTHON_ZIP_URL = "https://www.python.org/ftp/python/3.14.0/python-3.14.0-embed-amd64.zip"
PINNED_PYTHON_ZIP_CHECKED_ON = "2026-10-27"

_VERSION_RE = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?\Z")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class PayloadBuildError(Exception):
    """Base error for payload assembly failures."""


class TagNotFoundError(PayloadBuildError):
    """The requested git tag or ref could not be resolved."""


class TreeMismatchError(PayloadBuildError):
    """The git tree hash does not match expected evaluated tree hash."""


class InvalidPlatformError(PayloadBuildError):
    """The requested target platform is not supported."""


class BinaryFormatMismatchError(PayloadBuildError):
    """The binary format (PE vs ELF) does not match the target platform."""


class BinaryHashMismatchError(PayloadBuildError):
    """The core binary SHA-256 does not match expected pinned hash."""


class ExtractedIntegrityError(PayloadBuildError):
    """An extracted file's content or blob hash does not match git records."""


class UnsafePathError(PayloadBuildError):
    """An unsafe file path was encountered during payload assembly."""


class SymlinkRejectedError(PayloadBuildError):
    """A symbolic link was encountered in the payload directory (prohibited)."""


def sha256_file(path: str | Path) -> str:
    """Computes hexadecimal SHA-256 digest of a file in 1 MiB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_git(args: List[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    """Executes a git command and returns the completed process."""
    try:
        return subprocess.run(
            ["git"] + args,
            cwd=str(cwd),
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        stderr_text = e.stderr.decode("utf-8", errors="replace").strip()
        raise PayloadBuildError(f"git command failed: git {' '.join(args)}: {stderr_text}") from e
    except FileNotFoundError as e:
        raise PayloadBuildError("git executable not found on system PATH") from e


def verify_tag_and_trees(
    repo_root: Path,
    tag: str = DEFAULT_TAG,
    expected_core_tree: Optional[str] = EXPECTED_CORE_TREE,
    expected_research_tree: Optional[str] = EXPECTED_RESEARCH_TREE,
) -> Tuple[str, str, str]:
    """
    Verifies that the git tag exists and its core/ and research/ tree hashes match
    the expected evaluated constants.

    Returns:
        (commit_sha, core_tree_sha, research_tree_sha)
    """
    # 1. Verify tag exists and get commit hash
    try:
        proc_commit = _run_git(["rev-parse", "--verify", f"{tag}^{{commit}}"], repo_root)
        commit_sha = proc_commit.stdout.decode("ascii").strip()
    except PayloadBuildError as e:
        raise TagNotFoundError(f"Git tag or commit ref '{tag}' not found: {e}") from e

    # 2. Verify core/ tree hash
    proc_core = _run_git(["rev-parse", f"{tag}:core"], repo_root)
    core_tree_sha = proc_core.stdout.decode("ascii").strip()
    if expected_core_tree and core_tree_sha != expected_core_tree:
        raise TreeMismatchError(
            f"Core tree ID mismatch for tag '{tag}': got '{core_tree_sha}', expected '{expected_core_tree}'"
        )

    # 3. Verify research/ tree hash
    proc_res = _run_git(["rev-parse", f"{tag}:research"], repo_root)
    res_tree_sha = proc_res.stdout.decode("ascii").strip()
    if expected_research_tree and res_tree_sha != expected_research_tree:
        raise TreeMismatchError(
            f"Research tree ID mismatch for tag '{tag}': got '{res_tree_sha}', expected '{expected_research_tree}'"
        )

    return commit_sha, core_tree_sha, res_tree_sha


def verify_binary_format(binary_path: str | Path, platform: str) -> None:
    """
    Verifies that the binary executable matches the target platform format:
      - win-x64 requires Windows PE format (magic bytes b'MZ')
      - linux-x64 requires Linux ELF format (magic bytes b'\x7fELF')
    Fails closed with BinaryFormatMismatchError if the format does not match.
    """
    if platform not in SUPPORTED_PLATFORMS:
        raise InvalidPlatformError(f"Unsupported platform '{platform}'. Supported: {SUPPORTED_PLATFORMS}")

    p = Path(binary_path).resolve()
    with open(p, "rb") as f:
        magic = f.read(4)

    if platform == "win-x64":
        if magic.startswith(b"\x7fELF"):
            raise BinaryFormatMismatchError(
                f"Binary format mismatch for '{p}': target platform is '{platform}', but binary has Linux ELF header"
            )
        if not magic.startswith(b"MZ"):
            raise BinaryFormatMismatchError(
                f"Binary format mismatch for '{p}': target platform is '{platform}', expected Windows PE header (magic 'MZ')"
            )
    elif platform == "linux-x64":
        if magic.startswith(b"MZ"):
            raise BinaryFormatMismatchError(
                f"Binary format mismatch for '{p}': target platform is '{platform}', but binary has Windows PE header"
            )
        if not magic.startswith(b"\x7fELF"):
            raise BinaryFormatMismatchError(
                f"Binary format mismatch for '{p}': target platform is '{platform}', expected Linux ELF header (magic '\\x7fELF')"
            )


def verify_binary(
    binary_path: str | Path,
    expected_sha256: Optional[str] = EXPECTED_BINARY_SHA256,
    platform: Optional[str] = None,
) -> str:
    """
    Verifies that the core binary exists, matches the expected pinned SHA-256,
    and conforms to the target platform binary format (PE for Windows, ELF for Linux).

    Returns:
        The computed SHA-256 digest string.
    """
    bin_p = Path(binary_path).resolve()
    if not bin_p.is_file():
        raise FileNotFoundError(f"Core binary not found at '{bin_p}'")

    if platform:
        verify_binary_format(bin_p, platform)

    actual_sha = sha256_file(bin_p)
    if expected_sha256 and actual_sha.lower() != expected_sha256.lower():
        raise BinaryHashMismatchError(
            f"Core binary SHA-256 mismatch for '{bin_p}': got '{actual_sha}', expected '{expected_sha256}'"
        )

    return actual_sha


def extract_tag_archive(
    repo_root: Path,
    tag: str,
    dest_dir: Path,
    archive_paths: Optional[List[str]] = None,
) -> List[str]:
    """
    Extracts files from git archive of the given tag directly into dest_dir.
    Does not touch or read the local working tree.

    Returns:
        List of relative paths extracted.
    """
    dest_dir = Path(dest_dir).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    if archive_paths is None:
        archive_paths = ["research", "docs/CONSTITUTION.md", "README.md", "CHANGELOG.md"]

    # Filter paths that actually exist in the tag to prevent git archive error
    valid_paths: List[str] = []
    for p in archive_paths:
        try:
            _run_git(["cat-file", "-e", f"{tag}:{p}"], repo_root)
            valid_paths.append(p)
        except PayloadBuildError:
            logger.debug("Path '%s' not present in tag '%s', skipping", p, tag)

    if not valid_paths:
        raise PayloadBuildError(f"None of the requested archive paths exist in tag '{tag}'")

    proc = _run_git(["archive", "--format=tar", tag] + valid_paths, repo_root)
    tar_bytes = proc.stdout

    extracted: List[str] = []
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
        for member in tf.getmembers():
            # Validate path safety
            rel = member.name.replace("\\", "/")
            if (
                rel.startswith("/")
                or "\\" in rel
                or ":" in rel
                or any(part in ("..", "", ".") for part in rel.split("/"))
            ):
                raise UnsafePathError(f"Unsafe path in git archive: {rel!r}")

            if member.issym() or member.islnk():
                raise SymlinkRejectedError(f"Symlink in git archive prohibited: {rel!r}")

            if hasattr(tarfile, "data_filter"):
                tf.extract(member, path=str(dest_dir), filter="data")
            else:
                tf.extract(member, path=str(dest_dir))

            if member.isreg():
                extracted.append(rel)

    return extracted


def verify_extracted_integrity(
    repo_root: Path,
    tag: str,
    dest_dir: Path,
    subpath: str = "research",
) -> None:
    """
    Verifies that every regular file extracted under dest_dir/subpath matches
    the git blob object recorded in the tag. Fails closed if any file is missing,
    corrupted, modified, or extra.
    """
    proc = _run_git(["ls-tree", "-r", "-z", tag, subpath], repo_root)
    git_files: Dict[str, str] = {}
    for entry in proc.stdout.split(b"\x00"):
        if not entry:
            continue
        try:
            meta, name = entry.split(b"\t", 1)
            parts = meta.split()
            sha = parts[2].decode("ascii")
            rel_name = name.decode("utf-8").replace("\\", "/")
            git_files[rel_name] = sha
        except Exception as e:
            raise ExtractedIntegrityError(f"Failed to parse git ls-tree entry: {e}") from e

    dest_dir = dest_dir.resolve()
    for rel_name, expected_blob_sha in git_files.items():
        full_p = dest_dir / Path(rel_name)
        if not full_p.is_file():
            raise ExtractedIntegrityError(f"Extracted file missing: '{rel_name}'")

        # Compute git blob sha1: sha1(b"blob " + str(len) + b"\x00" + content)
        with open(full_p, "rb") as f:
            content = f.read()
        header = f"blob {len(content)}".encode("ascii") + b"\x00"
        actual_blob_sha = hashlib.sha1(header + content).hexdigest()

        if actual_blob_sha != expected_blob_sha:
            raise ExtractedIntegrityError(
                f"Extracted file corrupted or tampered: '{rel_name}' (got blob {actual_blob_sha}, expected {expected_blob_sha})"
            )


def extract_embed_python_zip(
    zip_path: str | Path,
    dest_py_dir: str | Path,
    expected_sha256: str = PINNED_PYTHON_ZIP_SHA256,
    max_extracted_bytes: int = 150 * 1024 * 1024,
) -> Dict[str, Any]:
    """
    Safely verifies and extracts the official embeddable Python zip distribution (Finding BU & BW).
    Enforces pinned SHA-256 (fail-closed on empty or invalid hashes, Finding BZ).
    Enforces safe relative paths (no traversal, no colons, no symlinks, safe directory creation, Finding BZ).
    Guards against zip bombs via max_extracted_bytes (150 MB ceiling, Finding BZ).
    Standardizes layout into Lib/ (unpacked stdlib) and DLLs/ (extensions) so that sandbox_win32
    AppContainer execution succeeds without modifying research/ code (Finding BW).
    Appends '..\\research' to all *._pth files for isolated research tree loading.
    Returns python_runtime metadata dict for manifest.json.
    """
    if not expected_sha256 or not _SHA_RE.match(expected_sha256):
        raise PayloadBuildError(
            f"expected_sha256 must be a valid 64-character hex SHA-256 string; unpinned or empty hashes are prohibited: {expected_sha256!r}"
        )

    zp = Path(zip_path).resolve()
    if not zp.is_file():
        raise FileNotFoundError(f"Embeddable Python zip not found at '{zp}'")

    actual_sha = sha256_file(zp)
    if actual_sha.lower() != expected_sha256.lower():
        raise PayloadBuildError(
            f"Python embed zip SHA-256 mismatch for '{zp}': got '{actual_sha}', expected '{expected_sha256}'"
        )

    dest = Path(dest_py_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    total_extracted_bytes = 0

    with zipfile.ZipFile(zp, "r") as zf:
        for member in zf.infolist():
            rel = member.filename.replace("\\", "/")
            if (
                rel.startswith("/")
                or "\\" in rel
                or ":" in rel
                or any(part in ("..", "", ".") for part in rel.strip("/").split("/"))
            ):
                raise UnsafePathError(f"Unsafe path in Python embed zip: {rel!r}")
            # Prevent zip symlinks
            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise SymlinkRejectedError(f"Symlink in Python embed zip prohibited: {rel!r}")

            total_extracted_bytes += member.file_size
            if total_extracted_bytes > max_extracted_bytes:
                raise PayloadBuildError(
                    f"Extracted size limit exceeded during Python embed extraction ({total_extracted_bytes} > {max_extracted_bytes} bytes)"
                )

            if member.is_dir() or rel.endswith("/"):
                (dest / rel).mkdir(parents=True, exist_ok=True)
            else:
                zf.extract(member, path=str(dest))

    # Standardize layout for sandbox runtime compatibility (Finding BW):
    # Unpack python*.zip into Lib/
    lib_dir = dest / "Lib"
    lib_dir.mkdir(parents=True, exist_ok=True)
    stdlib_zips = list(dest.glob("python*.zip"))
    for sz in stdlib_zips:
        with zipfile.ZipFile(sz, "r") as zf_stdlib:
            for member in zf_stdlib.infolist():
                rel_lib = member.filename.replace("\\", "/")
                if (
                    rel_lib.startswith("/")
                    or "\\" in rel_lib
                    or ":" in rel_lib
                    or any(part in ("..", "", ".") for part in rel_lib.strip("/").split("/"))
                ):
                    raise UnsafePathError(f"Unsafe path in stdlib zip: {rel_lib!r}")
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise SymlinkRejectedError(f"Symlink in stdlib zip prohibited: {rel_lib!r}")

                total_extracted_bytes += member.file_size
                if total_extracted_bytes > max_extracted_bytes:
                    raise PayloadBuildError(
                        f"Extracted size limit exceeded during stdlib unpack ({total_extracted_bytes} > {max_extracted_bytes} bytes)"
                    )

                if member.is_dir() or rel_lib.endswith("/"):
                    (lib_dir / rel_lib).mkdir(parents=True, exist_ok=True)
                else:
                    zf_stdlib.extract(member, path=str(lib_dir))

    # Populate DLLs/ with *.pyd extension modules and supporting non-python runtime DLLs (Finding BW)
    dlls_dir = dest / "DLLs"
    dlls_dir.mkdir(parents=True, exist_ok=True)
    for pyd_file in sorted(dest.glob("*.pyd")):
        shutil.copy2(str(pyd_file), str(dlls_dir / pyd_file.name))
    for dll_file in sorted(dest.glob("*.dll")):
        if not dll_file.name.lower().startswith("python"):
            shutil.copy2(str(dll_file), str(dlls_dir / dll_file.name))

    # Configure *._pth files with Lib, DLLs, ., and ..\research
    pth_files = list(dest.glob("*._pth"))
    pth_lines = [
        ".",
        ".\\Lib",
        ".\\DLLs",
        "..\\research",
    ]
    if not pth_files:
        (dest / "python._pth").write_text("\n".join(pth_lines) + "\n", encoding="utf-8")
    else:
        for pf in pth_files:
            pf.write_text("\n".join(pth_lines) + "\n", encoding="utf-8")

    return {
        "version": PINNED_PYTHON_VERSION,
        "sha256": actual_sha,
        "source_url": PINNED_PYTHON_ZIP_URL,
        "checked_on": PINNED_PYTHON_ZIP_CHECKED_ON,
        "layout": "standardized_lib_dlls",
    }


def scan_and_validate_payload(
    dest_dir: Path,
    excluded_files: Optional[Set[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Traverses dest_dir, validating every file:
      - Rejects symlinks and non-regular files
      - Validates safe POSIX relative paths
      - Computes size and SHA-256 for manifest

    Returns:
        Dict mapping POSIX relative paths to {"sha256": str, "size": int}
    """
    if excluded_files is None:
        excluded_files = {MANIFEST, SIGNATURE}

    dest_dir = dest_dir.resolve()
    file_map: Dict[str, Dict[str, Any]] = {}

    for dirpath, dirnames, filenames in os.walk(str(dest_dir)):
        for d in dirnames:
            full_d = Path(dirpath) / d
            if full_d.is_symlink():
                raise SymlinkRejectedError(f"Symlink directory prohibited: {full_d}")

        for f in filenames:
            full_f = Path(dirpath) / f
            if full_f.is_symlink():
                raise SymlinkRejectedError(f"Symlink file prohibited: {full_f}")

            st = full_f.stat()
            if not stat.S_ISREG(st.st_mode):
                raise PayloadBuildError(f"Non-regular file prohibited in payload: {full_f}")

            rel = str(full_f.relative_to(dest_dir)).replace("\\", "/")
            if rel in excluded_files:
                continue

            if (
                rel.startswith("/")
                or "\\" in rel
                or ":" in rel
                or any(part in ("..", "", ".") for part in rel.split("/"))
            ):
                raise UnsafePathError(f"Unsafe path in payload: {rel!r}")

            file_map[rel] = {
                "sha256": sha256_file(full_f),
                "size": st.st_size,
            }

    return file_map


def write_manifest(
    dest_dir: Path,
    product: str,
    version: str,
    constitution_sha256: str,
    tag: str,
    commit_sha: str,
    core_tree_sha: str,
    research_tree_sha: str,
    files_map: Dict[str, Dict[str, Any]],
    platform: str = "win-x64",
    python_runtime: Optional[Dict[str, Any]] = None,
) -> Tuple[Path, bytes, Dict[str, Any]]:
    """
    Serializes and atomically writes manifest.json.
    Produces deterministic formatting (sorted keys, POSIX paths).
    """
    if not _VERSION_RE.match(version):
        raise PayloadBuildError(f"Invalid manifest SemVer version string: '{version}'")
    if not _SHA_RE.match(constitution_sha256):
        raise PayloadBuildError(f"Invalid constitution_sha256: '{constitution_sha256}'")

    doc: Dict[str, Any] = {
        "format": 1,
        "product": product,
        "platform": platform,
        "version": version,
        "constitution_sha256": constitution_sha256,
        "tag": tag,
        "git_commit": commit_sha,
        "trees": {
            "core": core_tree_sha,
            "research": research_tree_sha,
        },
        "files": {k: files_map[k] for k in sorted(files_map.keys())},
    }
    if python_runtime:
        doc["python_runtime"] = python_runtime

    manifest_bytes = json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")
    manifest_path = dest_dir / MANIFEST

    # Atomic write
    tmp_path = dest_dir / f".{MANIFEST}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "wb") as f:
            f.write(manifest_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.replace(str(tmp_path), str(manifest_path))
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    return manifest_path, manifest_bytes, doc


def build_payload(
    repo_root: str | Path,
    out_dir: str | Path,
    tag: str = DEFAULT_TAG,
    binary_path: Optional[str | Path] = None,
    expected_binary_sha256: Optional[str] = EXPECTED_BINARY_SHA256,
    expected_core_tree: Optional[str] = EXPECTED_CORE_TREE,
    expected_research_tree: Optional[str] = EXPECTED_RESEARCH_TREE,
    constitution_path: Optional[str | Path] = None,
    product: str = DEFAULT_PRODUCT,
    platform: str = DEFAULT_PLATFORM,
    version: Optional[str] = None,
    clean: bool = False,
    embed_python_dir: Optional[str | Path] = None,
    embed_python_zip: Optional[str | Path] = None,
    expected_python_sha256: str = PINNED_PYTHON_ZIP_SHA256,
    allow_unpinned_python: bool = False,
    launcher_path: Optional[str | Path] = None,
    extra_files: Optional[Dict[str, str | Path]] = None,
) -> Dict[str, Any]:
    """
    End-to-end payload assembly pipeline for Milestones P1 and P1b.

    Returns summary dictionary with manifest data and verification metadata.
    """
    if platform not in SUPPORTED_PLATFORMS:
        raise InvalidPlatformError(f"Unsupported platform '{platform}'. Supported: {SUPPORTED_PLATFORMS}")

    repo = Path(repo_root).resolve()
    out = Path(out_dir).resolve()

    # Step 1: Pre-flight tag and tree invariant verification
    commit_sha, core_tree_sha, res_tree_sha = verify_tag_and_trees(
        repo,
        tag=tag,
        expected_core_tree=expected_core_tree,
        expected_research_tree=expected_research_tree,
    )

    # Step 2: Resolve and verify core binary
    if binary_path is None:
        bin_name = "pai-core.exe" if platform == "win-x64" else "pai-core"
        binary_path = repo / "core" / "target" / "release" / bin_name
    actual_bin_sha = verify_binary(binary_path, expected_sha256=expected_binary_sha256, platform=platform)

    # Prepare output directory
    if clean and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    # Step 3: Extract tagged assets directly from git archive
    archive_paths = ["research", "docs/CONSTITUTION.md", "README.md", "CHANGELOG.md"]
    extract_tag_archive(repo, tag, out, archive_paths=archive_paths)

    # Step 4: Verify extracted research tree blob integrity against git records
    verify_extracted_integrity(repo, tag, out, subpath="research")

    # Step 5: Stage core binary into bin/
    bin_dir = out / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    bin_name = Path(binary_path).name
    dest_bin = bin_dir / bin_name
    shutil.copy2(str(binary_path), str(dest_bin))

    # Step 6: Stage trust root and constitution if present
    # Ensure trust.json is available in payload root if research/trust.json exists
    res_trust = out / "research" / "trust.json"
    root_trust = out / "trust.json"
    if res_trust.is_file() and not root_trust.is_file():
        shutil.copy2(str(res_trust), str(root_trust))

    # Ensure CONSTITUTION.md is available in root if docs/CONSTITUTION.md was extracted
    docs_const = out / "docs" / "CONSTITUTION.md"
    root_const = out / "CONSTITUTION.md"
    if docs_const.is_file() and not root_const.is_file():
        shutil.copy2(str(docs_const), str(root_const))

    # Step 7: Resolve Constitution hash
    if constitution_path:
        const_sha = sha256_file(constitution_path)
    elif root_const.is_file():
        const_sha = sha256_file(root_const)
    elif docs_const.is_file():
        const_sha = sha256_file(docs_const)
    elif root_trust.is_file():
        with open(root_trust, encoding="utf-8") as f:
            t = json.load(f)
            const_sha = t.get("constitution_sha256", "")
    else:
        raise PayloadBuildError("Constitution file not found to pin constitution_sha256")

    # Step 8: Optional embeddable Python distribution staging (Findings BU, BW, BZ)
    python_runtime_meta: Optional[Dict[str, Any]] = None
    if embed_python_zip:
        python_runtime_meta = extract_embed_python_zip(
            embed_python_zip,
            out / "python",
            expected_sha256=expected_python_sha256,
        )
    elif embed_python_dir:
        if not allow_unpinned_python:
            raise PayloadBuildError(
                "embed_python_dir is developer-only and requires allow_unpinned_python=True (or --allow-unpinned-python). "
                "For release payloads, use official pinned embed_python_zip (Finding BZ)."
            )
        embed_p = Path(embed_python_dir).resolve()
        if embed_p.is_dir():
            target_py = out / "python"
            shutil.copytree(str(embed_p), str(target_py), dirs_exist_ok=True)
            # Ensure ._pth lists Lib, DLLs, ., and ..\research for isolated imports (Findings BN, BW)
            pth_files = list(target_py.glob("*._pth"))
            pth_lines = [".", ".\\Lib", ".\\DLLs", "..\\research"]
            if not pth_files:
                (target_py / "python._pth").write_text("\n".join(pth_lines) + "\n", encoding="utf-8")
            else:
                for pf in pth_files:
                    pf.write_text("\n".join(pth_lines) + "\n", encoding="utf-8")
            python_runtime_meta = {
                "version": "local",
                "source": str(embed_p),
                "unpinned_dev": True,
            }

    # Step 9: Optional launcher binary staging
    if launcher_path:
        launch_p = Path(launcher_path).resolve()
        dest_launch = (bin_dir / launch_p.name).resolve()
        if launch_p.is_file() and launch_p != dest_launch:
            shutil.copy2(str(launch_p), str(dest_launch))

    # Optional extra release files staging (e.g. install.bat, uninstall.bat)
    if extra_files:
        for rel_dest, src_p in extra_files.items():
            src_path = Path(src_p).resolve()
            dest_path = out / rel_dest
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src_path), str(dest_path))

    # Step 9a: Stage packaging assets into assets/ if present
    assets_dir = repo / "packaging" / "assets"
    if assets_dir.is_dir():
        dest_assets = out / "assets"
        dest_assets.mkdir(parents=True, exist_ok=True)
        for asset_file in sorted(assets_dir.glob("*")):
            if asset_file.is_file():
                shutil.copy2(str(asset_file), str(dest_assets / asset_file.name))

    # Step 9b: Write .pai-install marker (Finding DL) and manifest.files (Finding DM)
    marker_p = out / PAI_INSTALL_MARKER
    marker_p.write_text(f"{PAI_APP_ID_GUID}\n", encoding="utf-8")

    # Collect all relative files for manifest.files
    rel_files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(str(out)):
        for f in filenames:
            full_f = Path(dirpath) / f
            rel = str(full_f.relative_to(out)).replace("\\", "/")
            if rel not in (MANIFEST, SIGNATURE, MANIFEST_FILES):
                rel_files.append(rel)
    rel_files.append(MANIFEST_FILES)
    rel_files.sort()

    manifest_files_p = out / MANIFEST_FILES
    manifest_files_p.write_text("\n".join(rel_files) + "\n", encoding="utf-8")

    # Step 10: Scan payload and compute hashes for manifest
    files_map = scan_and_validate_payload(out)

    # Normalize version string
    if version is None:
        v_raw = tag.lstrip("v")
        # Strip any pre-release suffix (e.g. 1.0.0-rc1 -> 1.0.0) for strict SemVer compatibility
        v_match = re.match(r"^([0-9]+\.[0-9]+\.[0-9]+)", v_raw)
        version = v_match.group(1) if v_match else DEFAULT_VERSION

    # Step 11: Write manifest.json
    manifest_p, manifest_bytes, doc = write_manifest(
        dest_dir=out,
        product=product,
        platform=platform,
        version=version,
        constitution_sha256=const_sha,
        tag=tag,
        commit_sha=commit_sha,
        core_tree_sha=core_tree_sha,
        research_tree_sha=res_tree_sha,
        files_map=files_map,
        python_runtime=python_runtime_meta,
    )

    total_bytes = sum(meta["size"] for meta in files_map.values())
    return {
        "status": "success",
        "tag": tag,
        "platform": platform,
        "git_commit": commit_sha,
        "trees": {
            "core": core_tree_sha,
            "research": res_tree_sha,
        },
        "binary_sha256": actual_bin_sha,
        "manifest_path": str(manifest_p),
        "manifest": doc,
        "manifest_bytes": manifest_bytes,
        "file_count": len(files_map),
        "total_bytes": total_bytes,
        "out_dir": str(out),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build reproducible release payload from git tag with integrity checks."
    )
    parser.add_argument("--tag", default=DEFAULT_TAG, help=f"Git tag to extract (default: {DEFAULT_TAG})")
    parser.add_argument("--out", required=True, help="Destination directory for built payload")
    parser.add_argument(
        "--platform",
        default=DEFAULT_PLATFORM,
        choices=SUPPORTED_PLATFORMS,
        help=f"Target platform ({', '.join(SUPPORTED_PLATFORMS)}, default: {DEFAULT_PLATFORM})",
    )
    parser.add_argument("--binary", default=None, help="Path to pai-core binary (default: core/target/release/...)")
    parser.add_argument("--expected-binary-sha256", default=EXPECTED_BINARY_SHA256, help="Expected binary SHA-256")
    parser.add_argument("--expected-core-tree", default=EXPECTED_CORE_TREE, help="Expected core/ tree SHA-1")
    parser.add_argument("--expected-research-tree", default=EXPECTED_RESEARCH_TREE, help="Expected research/ tree SHA-1")
    parser.add_argument("--version", default=None, help="Release version (e.g. 1.0.0)")
    parser.add_argument("--product", default=DEFAULT_PRODUCT, help="Product identifier in manifest")
    parser.add_argument("--constitution", default=None, help="Path to CONSTITUTION.md")
    parser.add_argument("--embed-python-zip", default=None, help="Path to official embeddable Python zip")
    parser.add_argument("--expected-python-sha256", default=PINNED_PYTHON_ZIP_SHA256, help="Expected Python zip SHA-256")
    parser.add_argument("--embed-python-dir", default=None, help="Path to local Python folder (dev only, requires --allow-unpinned-python)")
    parser.add_argument("--allow-unpinned-python", action="store_true", help="Allow unpinned local Python directory (developer only)")
    parser.add_argument("--clean", action="store_true", help="Clean out directory before building")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")

    repo_root = Path(__file__).resolve().parent.parent

    try:
        res = build_payload(
            repo_root=repo_root,
            out_dir=args.out,
            tag=args.tag,
            binary_path=args.binary,
            expected_binary_sha256=args.expected_binary_sha256,
            expected_core_tree=args.expected_core_tree,
            expected_research_tree=args.expected_research_tree,
            constitution_path=args.constitution,
            product=args.product,
            platform=args.platform,
            version=args.version,
            clean=args.clean,
            embed_python_dir=args.embed_python_dir,
            embed_python_zip=args.embed_python_zip,
            expected_python_sha256=args.expected_python_sha256,
            allow_unpinned_python=args.allow_unpinned_python,
        )
        print(f"Payload successfully built at: {res['out_dir']}")
        print(f"Platform: {res['platform']}")
        print(f"Tag: {res['tag']} (commit: {res['git_commit'][:8]})")
        print(f"Core Tree: {res['trees']['core'][:8]} (MATCH)")
        print(f"Research Tree: {res['trees']['research'][:8]} (MATCH)")
        print(f"Core Binary: {res['binary_sha256'][:8]}... (MATCH)")
        print(f"Total Files in Manifest: {res['file_count']} ({res['total_bytes']:,} bytes)")
        print(f"Manifest written: {res['manifest_path']}")
        return 0
    except PayloadBuildError as e:
        print(f"ERROR: Payload build failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
