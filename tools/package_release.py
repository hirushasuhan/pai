#!/usr/bin/env python3
"""
PAI Release Packaging Utility (ADR-005 Compliant).

Deterministic, cross-platform packaging for PAI Desktop and Core binaries,
generating release zip archives, cryptographic SHA-256 digests, and ADR-005 manifests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import zipfile
from pathlib import Path

# Ensure UTF-8 console output on Windows runners
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

REPO_ROOT = Path(__file__).resolve().parent.parent


def sha256_file(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def find_binary(search_paths: list[Path], name: str) -> Path | None:
    for p in search_paths:
        if p.is_file():
            print(f"  [Found {name}]: {p} ({p.stat().st_size:,} bytes)")
            return p
    return None


def make_zip(source_dir: Path, zip_dest: Path) -> None:
    print(f"  [Compressing] {source_dir.name} -> {zip_dest.name}...")
    with zipfile.ZipFile(zip_dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(source_dir):
            for file in files:
                abs_path = Path(root) / file
                rel_path = abs_path.relative_to(source_dir)
                zf.write(abs_path, arcname=str(rel_path))


def package_release(version: str, channel: str, output_dir: Path) -> None:
    print("=" * 64)
    print(f"  [Packaging] PAI Release v{version} ({channel})")
    print("=" * 64)

    output_dir.mkdir(parents=True, exist_ok=True)
    staging_dir = output_dir / f"pai-desktop-v{version}-win-x64"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    # 1. Locate pai-desktop.exe
    desktop_candidates = [
        REPO_ROOT / "desktop" / "src-tauri" / "target" / "release" / "pai-desktop.exe",
        REPO_ROOT / "desktop" / "target" / "release" / "pai-desktop.exe",
        REPO_ROOT / "target" / "release" / "pai-desktop.exe",
        REPO_ROOT / "desktop" / "pai-desktop.exe",
    ]
    desktop_bin = find_binary(desktop_candidates, "pai-desktop.exe")
    if not desktop_bin:
        raise FileNotFoundError(
            f"Could not find pai-desktop.exe in any expected path:\n"
            + "\n".join(str(p) for p in desktop_candidates)
        )
    shutil.copy2(desktop_bin, staging_dir / "pai-desktop.exe")

    # 2. Locate pai-core.exe (optional but bundled if present)
    core_candidates = [
        REPO_ROOT / "core" / "target" / "release" / "pai-core.exe",
        REPO_ROOT / "core" / "pai-core.exe",
        REPO_ROOT / "target" / "release" / "pai-core.exe",
    ]
    core_bin = find_binary(core_candidates, "pai-core.exe")
    if core_bin:
        core_dir = staging_dir / "core"
        core_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(core_bin, core_dir / "pai-core.exe")

    # 3. Copy canonical UI directory
    ui_src = REPO_ROOT / "desktop" / "ui"
    if not ui_src.is_dir():
        raise FileNotFoundError(f"Canonical UI directory not found: {ui_src}")
    shutil.copytree(ui_src, staging_dir / "ui", dirs_exist_ok=True)
    ui_version = ui_src / "VERSION"
    if ui_version.is_file():
        shutil.copy2(ui_version, staging_dir / "VERSION")

    # 4. Copy Assets directory (prefer ui/assets, fallback to desktop/assets)
    assets_src = ui_src / "assets"
    if not assets_src.is_dir():
        assets_src = REPO_ROOT / "desktop" / "assets"
    if assets_src.is_dir():
        shutil.copytree(assets_src, staging_dir / "assets", dirs_exist_ok=True)

    # 5. Copy bridge_server.py & root files
    for fname in ["bridge_server.py", "apply_pending_update.py", "launch_desktop.bat", "desktop_launcher.py"]:
        src_f = REPO_ROOT / "desktop" / fname
        if src_f.is_file():
            shutil.copy2(src_f, staging_dir / fname)

    for bin_name in ("pai_folder_picker.exe", "pai_ui_agent.exe"):
        helper_exe = REPO_ROOT / "desktop" / "bin" / bin_name
        if helper_exe.is_file():
            (staging_dir / "bin").mkdir(parents=True, exist_ok=True)
            shutil.copy2(helper_exe, staging_dir / "bin" / bin_name)

    # 5b. Copy Python engine modules (`research/`) and trust metadata (excluding tests/caches)
    research_src = REPO_ROOT / "research"
    if research_src.is_dir():
        research_dst = staging_dir / "research"
        research_dst.mkdir(parents=True, exist_ok=True)
        for item in sorted(research_src.iterdir()):
            if item.is_file() and (item.suffix == ".py" or item.name == "trust.json"):
                shutil.copy2(item, research_dst / item.name)
    const_src = REPO_ROOT / "docs" / "CONSTITUTION.md"
    if const_src.is_file():
        (staging_dir / "docs").mkdir(parents=True, exist_ok=True)
        shutil.copy2(const_src, staging_dir / "docs" / "CONSTITUTION.md")

    # 6. Create Zip Archives
    payload_zip = output_dir / f"pai-payload-{version}-win-x64.zip"
    desktop_zip = output_dir / f"pai-desktop-{version}-win-x64.zip"

    make_zip(staging_dir, payload_zip)
    shutil.copy2(payload_zip, desktop_zip)

    # 7. Compute Checksums & Manifest
    hash_payload = sha256_file(payload_zip)
    hash_desktop = sha256_file(desktop_zip)
    size_payload = payload_zip.stat().st_size
    size_desktop = desktop_zip.stat().st_size

    manifest_data = {
        "format": 1,
        "product": "pai-desktop",
        "version": version,
        "channel": channel,
        "release_date": time.strftime("%Y-%m-%d"),
        "files": {
            f"pai-payload-{version}-win-x64.zip": {
                "sha256": hash_payload,
                "size": size_payload,
            },
            f"pai-desktop-{version}-win-x64.zip": {
                "sha256": hash_desktop,
                "size": size_desktop,
            },
        },
    }

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    checksums_path = output_dir / "SHA256SUMS.txt"
    checksums_content = (
        f"{hash_payload}  pai-payload-{version}-win-x64.zip\n"
        f"{hash_desktop}  pai-desktop-{version}-win-x64.zip\n"
    )
    checksums_path.write_text(checksums_content, encoding="utf-8")

    print(f"\n[OK] Release artifacts created successfully in {output_dir}")
    print(f"  - {payload_zip.name} ({size_payload:,} bytes, sha256: {hash_payload[:16]}...)")
    print(f"  - {desktop_zip.name} ({size_desktop:,} bytes, sha256: {hash_desktop[:16]}...)")
    print(f"  - {manifest_path.name}")
    print(f"  - {checksums_path.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Package PAI Desktop release artifacts.")
    parser.add_argument("--version", "-v", required=True, help="Release version (e.g. 1.3.0)")
    parser.add_argument("--channel", "-c", default="stable", help="Release channel (stable|beta)")
    parser.add_argument("--output-dir", "-o", default="dist", help="Output directory")

    args = parser.parse_args()
    version = args.version.lstrip("vV")
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir

    package_release(version, args.channel, output_dir)


if __name__ == "__main__":
    main()
