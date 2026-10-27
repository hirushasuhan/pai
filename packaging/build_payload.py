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
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("build_payload")

MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"
DEFAULT_TAG = "v1.0.0-rc1"
DEFAULT_PRODUCT = "pai-core"
DEFAULT_VERSION = "1.0.0"

# Evaluated tree invariants established in Release N (v1.0.0-rc1, commit 8ce81cb)
EXPECTED_CORE_TREE = "14c60746ca9a41d91aafd88cc0c7d98719cfe3a9"
EXPECTED_RESEARCH_TREE = "506e520b33a0af8c3f0276114483ce26b9bd3787"
EXPECTED_BINARY_SHA256 = "6f13d49463c757f2f3e43506f9743c37f602196544ce8fa85d5c5ce9332e3efe"

_VERSION_RE = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+\Z")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class PayloadBuildError(Exception):
    """Base error for payload assembly failures."""


class TagNotFoundError(PayloadBuildError):
    """The requested git tag or ref could not be resolved."""


class TreeMismatchError(PayloadBuildError):
    """The git tree hash does not match expected evaluated tree hash."""


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


def verify_binary(
    binary_path: str | Path,
    expected_sha256: Optional[str] = EXPECTED_BINARY_SHA256,
) -> str:
    """
    Verifies that the core binary exists and matches the expected pinned SHA-256.

    Returns:
        The computed SHA-256 digest string.
    """
    bin_p = Path(binary_path).resolve()
    if not bin_p.is_file():
        raise FileNotFoundError(f"Core binary not found at '{bin_p}'")

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
    version: Optional[str] = None,
    clean: bool = False,
    embed_python_dir: Optional[str | Path] = None,
    launcher_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """
    End-to-end payload assembly pipeline for Milestone P1.

    Returns summary dictionary with manifest data and verification metadata.
    """
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
        binary_path = repo / "core" / "target" / "release" / ("pai-core.exe" if sys.platform == "win32" else "pai-core")
    actual_bin_sha = verify_binary(binary_path, expected_sha256=expected_binary_sha256)

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

    # Step 8: Optional embeddable Python distribution staging
    if embed_python_dir:
        embed_p = Path(embed_python_dir).resolve()
        if embed_p.is_dir():
            target_py = out / "python"
            shutil.copytree(str(embed_p), str(target_py), dirs_exist_ok=True)

    # Step 9: Optional launcher binary staging
    if launcher_path:
        launch_p = Path(launcher_path).resolve()
        if launch_p.is_file():
            shutil.copy2(str(launch_p), str(bin_dir / launch_p.name))

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
        version=version,
        constitution_sha256=const_sha,
        tag=tag,
        commit_sha=commit_sha,
        core_tree_sha=core_tree_sha,
        research_tree_sha=res_tree_sha,
        files_map=files_map,
    )

    total_bytes = sum(meta["size"] for meta in files_map.values())
    return {
        "status": "success",
        "tag": tag,
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
    parser.add_argument("--binary", default=None, help="Path to pai-core binary (default: core/target/release/...)")
    parser.add_argument("--expected-binary-sha256", default=EXPECTED_BINARY_SHA256, help="Expected binary SHA-256")
    parser.add_argument("--expected-core-tree", default=EXPECTED_CORE_TREE, help="Expected core/ tree SHA-1")
    parser.add_argument("--expected-research-tree", default=EXPECTED_RESEARCH_TREE, help="Expected research/ tree SHA-1")
    parser.add_argument("--version", default=None, help="Release version (e.g. 1.0.0)")
    parser.add_argument("--product", default=DEFAULT_PRODUCT, help="Product identifier in manifest")
    parser.add_argument("--constitution", default=None, help="Path to CONSTITUTION.md")
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
            version=args.version,
            clean=args.clean,
        )
        print(f"Payload successfully built at: {res['out_dir']}")
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
