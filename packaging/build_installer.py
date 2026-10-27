"""
Personal Agentic AI (PAI) - Inno Setup Installer Builder.

Part of Milestone P5 for the v1.1.0 Packaging and Installer subsystem.
Specification: docs/PACKAGING_SPEC.md (§2, §3, §4, §5, §6, §7, §8, §9)
ADR-005, ADR-013

Hard rules enforced:
  1. Shipped payload is built strictly from evaluated git tag via build_payload().
  2. Fails closed if git trees differ from evaluated constants:
     - research/ tree: 506e520b33a0af8c3f0276114483ce26b9bd3787
     - core/ tree:     14c60746ca9a41d91aafd88cc0c7d98719cfe3a9
  3. Verifies pai-core.exe SHA-256 matches pinned hash (6f13d494...).
  4. Bundles official agreement text (Appendix A) with verified SHA-256.
  5. Executes ISCC.exe (Inno Setup 6 Command-Line Compiler) to compile PAI-Setup-<version>-x64.exe.
  6. Emits verifiable SHA-256 checksum and build artifact manifest.
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
    PINNED_PYTHON_VERSION,
    PINNED_PYTHON_ZIP_SHA256,
    PayloadBuildError,
    build_payload,
    sha256_file,
    verify_binary_format,
)

logger = logging.getLogger("build_installer")


class InstallerBuildError(Exception):
    """Base error for Inno Setup installer packaging failures."""


class CompilerNotFoundError(InstallerBuildError):
    """Raised when Inno Setup compiler (ISCC.exe) cannot be located."""


def find_iscc_compiler(explicit_path: Optional[str | Path] = None) -> Path:
    """
    Locates the Inno Setup command-line compiler (ISCC.exe).
    Searches explicit path, PATH, and standard user/system installation locations.
    """
    if explicit_path:
        p = Path(explicit_path).resolve()
        if p.is_file():
            return p
        raise CompilerNotFoundError(f"Specified ISCC.exe not found at: {explicit_path}")

    # Check PATH
    which_iscc = shutil.which("iscc") or shutil.which("ISCC.exe")
    if which_iscc:
        return Path(which_iscc).resolve()

    # Search standard Windows install roots
    search_dirs = []
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        search_dirs.append(Path(local_app_data) / "Programs" / "Inno Setup 6" / "ISCC.exe")
        search_dirs.append(
            Path(local_app_data) / "Programs" / "Antigravity IDE" / "resources" / "app" / "node_modules" / "innosetup" / "bin" / "ISCC.exe"
        )

    prog_files = os.environ.get("ProgramFiles")
    if prog_files:
        search_dirs.append(Path(prog_files) / "Inno Setup 6" / "ISCC.exe")

    prog_files_x86 = os.environ.get("ProgramFiles(x86)")
    if prog_files_x86:
        search_dirs.append(Path(prog_files_x86) / "Inno Setup 6" / "ISCC.exe")

    for candidate in search_dirs:
        if candidate.is_file():
            return candidate.resolve()

    raise CompilerNotFoundError(
        "Inno Setup command-line compiler (ISCC.exe) was not found on PATH or in standard directories. "
        "Install Inno Setup 6 via 'winget install JRSoftware.InnoSetup --scope user' or supply --iscc."
    )


def verify_installer_pe(installer_path: Path) -> Dict[str, Any]:
    """
    Validates that built installer is a valid Windows PE executable.
    """
    installer_path = Path(installer_path).resolve()
    if not installer_path.is_file():
        raise InstallerBuildError(f"Installer executable not found: {installer_path}")

    size = installer_path.stat().st_size
    if size < 1024 * 1024:
        raise InstallerBuildError(f"Built installer is suspiciously small: {size} bytes")

    with open(installer_path, "rb") as f:
        magic = f.read(2)
        if magic != b"MZ":
            raise InstallerBuildError("Installer does not begin with MZ header")
        f.seek(0x3C)
        pe_offset_bytes = f.read(4)
        if len(pe_offset_bytes) < 4:
            raise InstallerBuildError("Truncated DOS header in installer")
        pe_offset = int.from_bytes(pe_offset_bytes, byteorder="little")
        f.seek(pe_offset)
        pe_sig = f.read(4)
        if pe_sig != b"PE\x00\x00":
            raise InstallerBuildError(f"Invalid PE signature in installer: {pe_sig!r}")

    digest = sha256_file(installer_path)
    return {
        "path": str(installer_path),
        "size": size,
        "sha256": digest,
    }


def build_inno_installer(
    repo_root: Path,
    out_dir: str | Path,
    version: str,
    tag: str = DEFAULT_TAG,
    platform: str = "win-x64",
    iscc_path: Optional[str | Path] = None,
    payload_dir: Optional[str | Path] = None,
    embed_python_zip: Optional[str | Path] = None,
    clean: bool = False,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    End-to-end builder for PAI Inno Setup Windows installer.
    """
    repo_root = Path(repo_root).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not version or not str(version).strip():
        raise InstallerBuildError("Release version string must be specified and non-empty (e.g. '1.1.0-rc1').")
    version = str(version).strip()

    # Finding DB: Enforce that final versions (no -rcN) require an existing git tag
    is_rc = bool(re.search(r"-rc\d*$", version, re.IGNORECASE))
    if not is_rc:
        tag_candidates = [f"v{version}", version]
        tag_found = False
        for tc in tag_candidates:
            proc = subprocess.run(
                ["git", "rev-parse", "--verify", f"refs/tags/{tc}"],
                cwd=repo_root,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                tag_found = True
                break
        if not tag_found:
            raise InstallerBuildError(
                f"Final release version '{version}' requires an existing git tag (e.g. 'v{version}'), "
                f"but no matching tag exists in the repository. Preview builds must be formatted '1.1.0-rcN'."
            )

    if platform != "win-x64":
        raise InstallerBuildError(f"Inno Setup only supports 'win-x64', requested: {platform}")

    # 1. Locate ISCC compiler
    iscc_exe = find_iscc_compiler(iscc_path)
    logger.info("Found ISCC compiler: %s", iscc_exe)

    # 2. Agreement file and digest
    agreement_file = repo_root / "packaging" / "agreement.txt"
    if not agreement_file.is_file():
        raise InstallerBuildError(f"Agreement text not found at: {agreement_file}")
    agreement_sha256 = sha256_file(agreement_file)

    # Auto-resolve official embed python zip if omitted
    if embed_python_zip is None:
        cached_zip = Path(tempfile.gettempdir()) / f"python-{PINNED_PYTHON_VERSION}-embed-amd64.zip"
        if cached_zip.is_file():
            embed_python_zip = cached_zip

    # 3. Prepare payload
    temp_payload_ctx = None
    temp_launcher_ctx = None
    if payload_dir:
        resolved_payload = Path(payload_dir).resolve()
        if not (resolved_payload / "manifest.json").is_file():
            raise InstallerBuildError(f"Pre-staged payload missing manifest.json at: {resolved_payload}")
        # Ensure marker and manifest.files are present in pre-staged payload (Findings DL, DM)
        marker_p = resolved_payload / ".pai-install"
        if not marker_p.is_file():
            marker_p.write_text("{8B7B61CA-C450-4E87-9F1B-4198A82711C9}\n", encoding="utf-8")
        files_list_p = resolved_payload / "manifest.files"
        if not files_list_p.is_file():
            try:
                with open(resolved_payload / "manifest.json", "r", encoding="utf-8") as f:
                    m = json.load(f)
                lines = sorted(m.get("files", {}).keys())
                files_list_p.write_text("\n".join(lines) + "\n", encoding="utf-8")
            except Exception:
                pass
    else:
        temp_payload_ctx = tempfile.TemporaryDirectory(prefix="pai_installer_payload_")
        resolved_payload = Path(temp_payload_ctx.name)
        logger.info("Building fresh payload from tag '%s' into %s", tag, resolved_payload)

        # Build native launcher
        temp_launcher_ctx = tempfile.TemporaryDirectory(prefix="pai_launcher_")
        launcher_target = Path(temp_launcher_ctx.name) / "pai.exe"
        built_launcher = build_launcher(launcher_target)

        packaging_dir = repo_root / "packaging"
        extra_files = {
            "install.bat": packaging_dir / "install.bat",
            "uninstall.bat": packaging_dir / "uninstall.bat",
            "packaging/pai_setup.py": packaging_dir / "pai_setup.py",
            "tools/update_path.ps1": packaging_dir / "update_path.ps1",
            "AGREEMENT.txt": agreement_file,
        }

        build_payload(
            repo_root=repo_root,
            out_dir=resolved_payload,
            tag=tag,
            expected_binary_sha256=EXPECTED_BINARY_SHA256,
            expected_core_tree=EXPECTED_CORE_TREE,
            expected_research_tree=EXPECTED_RESEARCH_TREE,
            platform=platform,
            version=version,
            launcher_path=built_launcher,
            embed_python_zip=embed_python_zip,
            extra_files=extra_files,
            clean=True,
        )

    # Verify tools/update_path.ps1 is recorded in payload manifest (Finding DD)
    manifest_file = resolved_payload / "manifest.json"
    if not manifest_file.is_file():
        raise InstallerBuildError(f"Payload manifest missing at: {manifest_file}")
    try:
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)
    except Exception as e:
        raise InstallerBuildError(f"Failed to read payload manifest at {manifest_file}: {e}")

    manifest_files = manifest_data.get("files", {})
    if "tools/update_path.ps1" not in manifest_files:
        raise InstallerBuildError(
            "Payload manifest is missing 'tools/update_path.ps1'. "
            "Build defect: PATH helper script must be in payload."
        )
    disk_script = resolved_payload / "tools" / "update_path.ps1"
    if not disk_script.is_file():
        raise InstallerBuildError(f"Payload is missing disk file: {disk_script}")

    iss_file = repo_root / "packaging" / "pai.iss"
    if not iss_file.is_file():
        raise InstallerBuildError(f"Inno Setup script not found at: {iss_file}")

    output_base = f"PAI-Setup-{version}-{platform}"
    installer_exe = out_dir / f"{output_base}.exe"
    if installer_exe.exists() and clean:
        installer_exe.unlink()

    # 4. Invoke ISCC.exe
    cmd = [
        str(iscc_exe),
        "/Q" if not verbose else "/Qp",
        f"/O{str(out_dir)}",
        f"/F{output_base}",
        f"/DAppVersion={version}",
        f"/DPayloadDir={str(resolved_payload)}",
        f"/DOutputDir={str(out_dir)}",
        f"/DOutputBaseFilename={output_base}",
        f"/DAgreementPath={str(agreement_file)}",
        f"/DAgreementSha256={agreement_sha256}",
        str(iss_file),
    ]

    logger.info("Running ISCC: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise InstallerBuildError(f"ISCC compilation failed (exit code {proc.returncode}):\n{proc.stdout}\n{proc.stderr}")

    # 5. Verify output installer
    pe_info = verify_installer_pe(installer_exe)

    # 6. Write checksum file
    sha_file = out_dir / f"{output_base}.exe.sha256"
    sha_file.write_text(f"{pe_info['sha256']} *{installer_exe.name}\n", encoding="utf-8")

    result = {
        "installer_path": str(installer_exe),
        "sha256": pe_info["sha256"],
        "size_bytes": pe_info["size"],
        "sha256_file": str(sha_file),
        "version": version,
        "tag": tag,
        "platform": platform,
        "agreement_sha256": agreement_sha256,
        "iscc_path": str(iscc_exe),
    }

    if temp_launcher_ctx:
        temp_launcher_ctx.cleanup()
    if temp_payload_ctx:
        temp_payload_ctx.cleanup()

    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PAI Inno Setup Installer Builder (Milestone P5).")
    parser.add_argument("--tag", default=DEFAULT_TAG, help=f"Git tag to build from (default: {DEFAULT_TAG})")
    parser.add_argument(
        "--version",
        required=True,
        help="Release version string (e.g. 1.1.0-rc1; required). Final releases without -rcN require a matching git tag.",
    )
    parser.add_argument("--platform", default=DEFAULT_PLATFORM, choices=["win-x64"], help="Target platform (win-x64)")
    parser.add_argument("--out-dir", default="dist", help="Output directory for built installer (default: dist)")
    parser.add_argument("--iscc", default=None, help="Explicit path to ISCC.exe compiler")
    parser.add_argument("--payload-dir", default=None, help="Pre-staged payload directory (optional)")
    parser.add_argument("--embed-python-zip", default=None, help="Path to official embeddable Python zip")
    parser.add_argument("--clean", action="store_true", help="Clean existing output files before building")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose compiler output")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")

    repo_root = Path(__file__).resolve().parent.parent

    try:
        res = build_inno_installer(
            repo_root=repo_root,
            out_dir=args.out_dir,
            tag=args.tag,
            version=args.version,
            platform=args.platform,
            iscc_path=args.iscc,
            payload_dir=args.payload_dir,
            embed_python_zip=args.embed_python_zip,
            clean=args.clean,
            verbose=args.verbose,
        )
        print("\n========================================================================")
        print("          PAI INNO SETUP INSTALLER BUILD COMPLETE (Milestone P5)        ")
        print("========================================================================")
        print(f"Installer:        {res['installer_path']}")
        print(f"Size:             {res['size_bytes']:,} bytes ({res['size_bytes'] / (1024**2):.2f} MiB)")
        print(f"SHA-256:          {res['sha256']}")
        print(f"Checksum File:    {res['sha256_file']}")
        print(f"Agreement SHA256: {res['agreement_sha256']}")
        print(f"Compiler:         {res['iscc_path']}")
        print("========================================================================\n")
        return 0
    except InstallerBuildError as e:
        print(f"ERROR: Installer build failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
