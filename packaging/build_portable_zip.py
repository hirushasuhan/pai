"""
Personal Agentic AI (PAI) - Portable Release Zip Builder.

Part of Milestone P2 for the v1.1.0 Packaging and Installer subsystem.
Specification: docs/PACKAGING_SPEC.md, docs/adr/ADR-013-installer-and-distribution.md
Agent brief: docs/AGENT_BRIEF_PACKAGING.md

Produces a self-contained portable release package:
  dist/PAI-Portable-<version>-<platform>.zip
containing:
  - ADR-005 manifest.json with full SHA-256 integrity map
  - bin/pai-core.exe (pinned Rust reasoning/security core)
  - bin/pai.exe (native fail-closed launcher)
  - research/ tree byte-for-byte from evaluated git tag
  - install.bat & uninstall.bat (safe per-user PATH configuration without setx)
  - Optional embedded Python runtime (if bundled)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from packaging.build_launcher import build_launcher
from packaging.build_payload import (
    DEFAULT_PLATFORM,
    DEFAULT_TAG,
    EXPECTED_BINARY_SHA256,
    EXPECTED_CORE_TREE,
    EXPECTED_RESEARCH_TREE,
    PINNED_PYTHON_ZIP_SHA256,
    SUPPORTED_PLATFORMS,
    PayloadBuildError,
    build_payload,
    sha256_file,
    verify_binary_format,
)

logger = logging.getLogger("build_portable_zip")

FIXED_ZIP_DATETIME = (2026, 1, 1, 0, 0, 0)


class PortableZipError(Exception):
    """Base error for portable zip packaging failures."""


class ZipSecurityError(PortableZipError):
    """Raised when an archive member violates safe path or link constraints."""


def sanitize_zip_path(arcname: str) -> str:
    """Validates that a relative archive path contains no traversal or absolute segments."""
    clean = arcname.replace("\\", "/")
    if clean.startswith("/"):
        raise ZipSecurityError(f"Absolute path detected in archive entry: {arcname}")
    norm = clean.strip("/")
    if ":" in norm:
        raise ZipSecurityError(f"Drive or protocol path detected in archive entry: {arcname}")
    parts = norm.split("/")
    if any(p in ("..", ".", "") for p in parts):
        raise ZipSecurityError(f"Unsafe path traversal detected in archive entry: {arcname}")
    return norm


def create_deterministic_zip(source_dir: Path, out_zip: Path) -> Tuple[Path, str, int]:
    """
    Creates a deterministic zip archive from source_dir.
    Files are ordered lexicographically by relative path with fixed timestamps.
    Returns (out_zip, sha256_hex, file_count).
    """
    source_dir = Path(source_dir).resolve()
    out_zip = Path(out_zip).resolve()
    out_zip.parent.mkdir(parents=True, exist_ok=True)

    # Collect all files
    all_files: List[Tuple[str, Path]] = []
    for root, dirs, files in os.walk(source_dir):
        dirs.sort()
        for f in sorted(files):
            full_p = Path(root) / f
            rel_p = full_p.relative_to(source_dir).as_posix()
            safe_rel = sanitize_zip_path(rel_p)
            all_files.append((safe_rel, full_p))

    all_files.sort(key=lambda x: x[0])

    tmp_zip = out_zip.with_suffix(".tmp.zip")
    if tmp_zip.exists():
        tmp_zip.unlink()

    with zipfile.ZipFile(tmp_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for arcname, file_path in all_files:
            data = file_path.read_bytes()
            zinfo = zipfile.ZipInfo(arcname, date_time=FIXED_ZIP_DATETIME)
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            # Standard file permissions (0o644 / 0o755)
            is_exec = arcname.endswith(".exe") or arcname.endswith(".bat") or arcname.endswith(".sh")
            zinfo.external_attr = (0o755 if is_exec else 0o644) << 16
            zf.writestr(zinfo, data)

    # Move to final destination
    if out_zip.exists():
        out_zip.unlink()
    tmp_zip.replace(out_zip)

    digest = sha256_file(out_zip)
    # Write accompanying .sha256 checksum file
    sha_file = out_zip.with_suffix(out_zip.suffix + ".sha256")
    sha_file.write_text(f"{digest} *{out_zip.name}\n", encoding="utf-8")

    return out_zip, digest, len(all_files)


def verify_portable_zip(zip_path: Path) -> Dict[str, Any]:
    """
    Exhaustively audits a portable zip package:
      1. Safe archive structure (no traversals, no links, valid zip header).
      2. Validates extracted manifest.json against all archived files.
      3. Verifies PE/ELF format of binaries.
      4. Verifies required launcher and core files are present.
    """
    zip_p = Path(zip_path).resolve()
    if not zip_p.is_file():
        raise PortableZipError(f"Zip archive does not exist at {zip_p}")

    temp_dir = Path(tempfile.mkdtemp(prefix="pai_verify_zip_"))
    try:
        with zipfile.ZipFile(zip_p, "r") as zf:
            infolist = zf.infolist()
            for info in infolist:
                sanitize_zip_path(info.filename)
                # Check for symlinks in external attributes
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ZipSecurityError(f"Symlink entry prohibited in zip: {info.filename}")
            zf.extractall(temp_dir)

        manifest_path = temp_dir / "manifest.json"
        if not manifest_path.is_file():
            raise PortableZipError("manifest.json missing from portable zip root")

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        files_map = manifest.get("files", {})
        if not files_map:
            raise PortableZipError("manifest.json contains empty files map")

        # Verify all files on disk match manifest exactly
        for rel_posix, meta in files_map.items():
            full_p = temp_dir / Path(rel_posix)
            if not full_p.is_file():
                raise PortableZipError(f"Manifest entry missing from disk: {rel_posix}")
            if full_p.stat().st_size != meta["size"]:
                raise PortableZipError(
                    f"File size mismatch for {rel_posix}: disk={full_p.stat().st_size} vs manifest={meta['size']}"
                )
            calc_sha = sha256_file(full_p)
            if calc_sha != meta["sha256"]:
                raise PortableZipError(
                    f"SHA-256 mismatch for {rel_posix}: disk={calc_sha} vs manifest={meta['sha256']}"
                )

        # Ensure no unlisted files exist on disk
        for root, _, files in os.walk(temp_dir):
            for file in files:
                full_p = Path(root) / file
                rel_p = full_p.relative_to(temp_dir).as_posix()
                if rel_p not in files_map and rel_p != "manifest.json":
                    raise PortableZipError(f"Unlisted file found in archive extraction: {rel_p}")

        # Check required components
        plat = manifest.get("platform", "win-x64")
        if plat == "win-x64":
            if "bin/pai.exe" not in files_map:
                raise PortableZipError("Required bin/pai.exe launcher missing from win-x64 archive")
            if "bin/pai-core.exe" not in files_map:
                raise PortableZipError("Required bin/pai-core.exe core missing from win-x64 archive")
            verify_binary_format(temp_dir / "bin" / "pai.exe", platform="win-x64")
            verify_binary_format(temp_dir / "bin" / "pai-core.exe", platform="win-x64")
            if "install.bat" not in files_map:
                raise PortableZipError("Required install.bat missing from win-x64 archive")
            if "uninstall.bat" not in files_map:
                raise PortableZipError("Required uninstall.bat missing from win-x64 archive")

        return {
            "valid": True,
            "manifest": manifest,
            "file_count": len(files_map),
            "archive_size": zip_p.stat().st_size,
            "archive_sha256": sha256_file(zip_p),
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def build_portable_zip(
    repo_root: Path | str = REPO_ROOT,
    out_zip: Optional[Path | str] = None,
    tag: str = DEFAULT_TAG,
    binary_path: Optional[Path | str] = None,
    platform: str = DEFAULT_PLATFORM,
    staging_dir: Optional[Path | str] = None,
    embed_python_dir: Optional[Path | str] = None,
    embed_python_zip: Optional[Path | str] = None,
    expected_python_sha256: Optional[str] = PINNED_PYTHON_ZIP_SHA256,
    clean: bool = True,
) -> Dict[str, Any]:
    """
    Assembles payload, builds launcher, includes install scripts, and produces
    the signed/audited portable zip package.
    """
    repo = Path(repo_root).resolve()
    packaging_dir = repo / "packaging"

    if platform not in SUPPORTED_PLATFORMS:
        raise PortableZipError(f"Unsupported platform: {platform}")

    temp_staging = None
    launcher_build_tmp = None
    if staging_dir:
        stage = Path(staging_dir).resolve()
    else:
        temp_staging = tempfile.mkdtemp(prefix="pai_stage_zip_")
        stage = Path(temp_staging).resolve()

    try:
        stage.mkdir(parents=True, exist_ok=True)

        # 1. Build launcher executable in an isolated temporary location
        launcher_bin = None
        if platform == "win-x64":
            launcher_build_tmp = tempfile.mkdtemp(prefix="pai_build_launcher_")
            launcher_target = Path(launcher_build_tmp) / "pai.exe"
            built_launcher = build_launcher(launcher_target)
            launcher_bin = built_launcher

        # 2. Prepare extra files (install.bat and uninstall.bat)
        extra_files: Dict[str, Path] = {}
        if platform == "win-x64":
            inst_bat = packaging_dir / "install.bat"
            uninst_bat = packaging_dir / "uninstall.bat"
            if not inst_bat.is_file():
                raise PortableZipError(f"install.bat not found at {inst_bat}")
            if not uninst_bat.is_file():
                raise PortableZipError(f"uninstall.bat not found at {uninst_bat}")
            extra_files["install.bat"] = inst_bat
            extra_files["uninstall.bat"] = uninst_bat

        # 3. Assemble payload and generate manifest.json
        payload_meta = build_payload(
            repo_root=repo,
            out_dir=stage,
            tag=tag,
            binary_path=binary_path,
            platform=platform,
            launcher_path=launcher_bin,
            extra_files=extra_files,
            embed_python_dir=embed_python_dir,
            embed_python_zip=embed_python_zip,
            expected_python_sha256=expected_python_sha256,
            clean=clean,
        )

        version = payload_meta["manifest"]["version"]
        if out_zip is None:
            dist_dir = repo / "dist"
            out_zip_path = dist_dir / f"PAI-Portable-{version}-{platform}.zip"
        else:
            out_zip_path = Path(out_zip).resolve()

        # Clean temporary build directory inside stage before archiving
        if (stage / "build_temp_launcher").exists():
            shutil.rmtree(stage / "build_temp_launcher", ignore_errors=True)

        # 4. Create deterministic zip
        final_zip, zip_sha, count = create_deterministic_zip(stage, out_zip_path)

        # 5. Immediate self-audit of generated zip
        audit_res = verify_portable_zip(final_zip)

        return {
            "status": "success",
            "zip_path": str(final_zip),
            "zip_sha256": zip_sha,
            "zip_size": final_zip.stat().st_size,
            "version": version,
            "platform": platform,
            "file_count": count,
            "manifest": payload_meta["manifest"],
            "audit": audit_res,
        }
    finally:
        if launcher_build_tmp and Path(launcher_build_tmp).exists():
            shutil.rmtree(launcher_build_tmp, ignore_errors=True)
        if temp_staging and Path(temp_staging).exists():
            shutil.rmtree(temp_staging, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build PAI portable distribution zip.")
    parser.add_argument("--tag", default=DEFAULT_TAG, help=f"Git tag to package (default: {DEFAULT_TAG})")
    parser.add_argument("--out", default=None, help="Output zip file path (default: dist/PAI-Portable-<version>-<platform>.zip)")
    parser.add_argument("--platform", default=DEFAULT_PLATFORM, choices=SUPPORTED_PLATFORMS, help=f"Target platform (default: {DEFAULT_PLATFORM})")
    parser.add_argument("--binary", default=None, help="Path to evaluated pai-core executable")
    parser.add_argument("--embed-python", default=None, help="Path to embedded Python runtime folder")
    parser.add_argument("--embed-python-zip", default=None, help="Path to official embeddable Python zip")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    res = build_portable_zip(
        repo_root=REPO_ROOT,
        out_zip=args.out,
        tag=args.tag,
        binary_path=args.binary,
        platform=args.platform,
        embed_python_dir=args.embed_python,
        embed_python_zip=args.embed_python_zip,
    )
    print(f"\nPortable zip created successfully:")
    print(f"  Path:       {res['zip_path']}")
    print(f"  SHA-256:    {res['zip_sha256']}")
    print(f"  Size:       {res['zip_size']:,} bytes ({res['file_count']} files)")
    print(f"  Platform:   {res['platform']}")
    print(f"  Version:    {res['version']}")


if __name__ == "__main__":
    main()
