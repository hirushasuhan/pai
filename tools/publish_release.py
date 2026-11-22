#!/usr/bin/env python3
"""
PAI Multi-Channel Release Publisher CLI Tool.

Automates preparing, tagging, and publishing Stable and Beta/Preview releases
for Personal Agentic AI (PAI) to GitHub.

Usage Examples:
  # 1. Publish a Stable Release (e.g. v1.3.0):
  python tools/publish_release.py --version 1.3.0 --channel stable --push

  # 2. Publish a Beta / Preview Release (e.g. v1.4.0-beta.1):
  python tools/publish_release.py --version 1.4.0-beta.1 --channel beta --push

  # 3. Dry-run verification (test without creating or pushing tags):
  python tools/publish_release.py --version 1.3.0 --dry-run
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SEMVER_REGEX = re.compile(
    r"^v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:-(?P<prerelease>[0-9A-Za-z.-]+))?$"
)


def run_cmd(cmd: list[str], cwd: Path = REPO_ROOT, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def validate_version(ver_str: str) -> tuple[str, str, bool]:
    match = SEMVER_REGEX.match(ver_str.strip())
    if not match:
        sys.exit(f"❌ Error: Invalid semantic version format '{ver_str}'. Expected format: X.Y.Z or X.Y.Z-beta.N")
    
    clean_ver = ver_str.strip().lstrip("vV")
    prerelease = match.group("prerelease")
    is_prerelease = bool(prerelease)
    
    inferred_channel = "beta" if is_prerelease else "stable"
    return clean_ver, inferred_channel, is_prerelease


def check_git_status() -> None:
    res = run_cmd(["git", "status", "--porcelain"], check=False)
    if res.stdout.strip():
        print("⚠️ Warning: You have uncommitted changes in your working tree:")
        for line in res.stdout.strip().splitlines()[:5]:
            print(f"   {line}")
        print("   It is recommended to commit your changes before tagging a release.\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Publish Stable and Beta/Preview releases for Personal Agentic AI (PAI)."
    )
    parser.add_argument(
        "--version",
        "-v",
        required=True,
        help="Release version string (e.g. 1.3.0 or 1.4.0-beta.1)",
    )
    parser.add_argument(
        "--channel",
        "-c",
        choices=["stable", "beta"],
        help="Release channel: 'stable' or 'beta'. Inferred automatically if omitted.",
    )
    parser.add_argument(
        "--title",
        "-t",
        default="",
        help="Release title (e.g. 'PAI Studio v1.3.0 - Software Auto-Updater')",
    )
    parser.add_argument(
        "--notes",
        "-n",
        default="",
        help="Release notes markdown string or path to a .md file",
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="Automatically push git tag to origin, triggering the GitHub Actions release workflow",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview tag creation and payload parameters without modifying git or pushing",
    )

    args = parser.parse_args()

    clean_ver, inferred_chan, is_prerelease = validate_version(args.version)
    channel = args.channel or inferred_chan

    if channel == "stable" and is_prerelease:
        print(f"⚠️ Warning: Version '{clean_ver}' contains a prerelease identifier but channel is set to 'stable'.")
    elif channel == "beta" and not is_prerelease:
        clean_ver = f"{clean_ver}-beta.1"
        is_prerelease = True
        print(f"ℹ️ Notice: Appending pre-release suffix for Beta channel -> '{clean_ver}'")

    tag_name = f"v{clean_ver}"
    release_title = args.title or f"PAI Studio v{clean_ver} ({channel.capitalize()})"

    notes_text = args.notes
    if notes_text and os.path.isfile(notes_text):
        notes_text = Path(notes_text).read_text(encoding="utf-8")
    elif not notes_text:
        notes_text = (
            f"### Personal Agentic AI (PAI) {channel.capitalize()} Release v{clean_ver}\n\n"
            f"- Channel: **{channel.upper()}**\n"
            f"- Built with Tauri 2.0 Rust native architecture & memory-safe reasoning core.\n"
            f"- ADR-005 compliant Ed25519 cryptographic release manifests.\n"
            f"- Released: {time.strftime('%Y-%m-%d')}\n"
        )

    print("=" * 68)
    print("🚀 Personal Agentic AI - Release Publisher")
    print("=" * 68)
    print(f"  • Version:        v{clean_ver}")
    print(f"  • Channel:        {channel.upper()} ({'Pre-release / Preview' if is_prerelease else 'Official Stable'})")
    print(f"  • Git Tag:        {tag_name}")
    print(f"  • Release Title:  {release_title}")
    print("=" * 68)

    check_git_status()

    if args.dry_run:
        print("🔍 [Dry-Run Active]: No git tags or remote pushes will be executed.")
        print(f"  Would create tag: {tag_name}")
        print(f"  Would push to:    git push origin {tag_name}")
        print(f"  GitHub Release Workflow will mark prerelease={is_prerelease}")
        print("\n✅ Dry run validation successful.")
        return

    # Check if tag already exists locally
    check_tag = run_cmd(["git", "tag", "-l", tag_name], check=False)
    if tag_name in check_tag.stdout.split():
        print(f"⚠️ Local tag '{tag_name}' already exists.")
        ans = input(f"Overwrite existing local tag '{tag_name}'? [y/N]: ").strip().lower()
        if ans == "y":
            run_cmd(["git", "tag", "-d", tag_name])
        else:
            sys.exit("Aborted by user.")

    # Create annotated git tag
    print(f"📦 Creating local annotated git tag '{tag_name}'...")
    run_cmd(["git", "tag", "-a", tag_name, "-m", release_title])
    print(f"✅ Created tag '{tag_name}'.")

    if args.push:
        print(f"🌐 Pushing tag '{tag_name}' to GitHub (origin)...")
        push_res = run_cmd(["git", "push", "origin", tag_name], check=False)
        if push_res.returncode == 0:
            print(f"🎉 Successfully pushed '{tag_name}' to GitHub!")
            print("\n⚙️ GitHub Actions Workflow Triggered:")
            print("  1. GitHub Actions runner (.github/workflows/release.yml) is now building:")
            print("     - pai-desktop.exe (Tauri 2.0 Rust Native)")
            print("     - pai-core.exe (Memory-Safe Stateless Reasoning Core)")
            print("     - UI assets & bridge server bundle")
            print("  2. Payload packaging (pai-desktop-win-x64.zip, manifest.json, SHA256SUMS.txt)")
            print(f"  3. Automatic publishing to GitHub Releases (prerelease={is_prerelease})")
            print(f"\n🔗 Monitor release progress at:")
            print(f"   https://github.com/hirushasuhan/pai/actions")
            print(f"   https://github.com/hirushasuhan/pai/releases/tag/{tag_name}")
        else:
            print(f"❌ Error pushing tag: {push_res.stderr.strip()}")
            print("You can manually push the tag using:")
            print(f"   git push origin {tag_name}")
    else:
        print("\nℹ️ Tag created locally. To publish this release to GitHub, run:")
        print(f"   git push origin {tag_name}")
        print("\nOnce pushed, GitHub Actions will automatically compile binaries, package artifacts, and create the release!")


if __name__ == "__main__":
    main()
