#!/usr/bin/env python3
"""
Executes unit test suites and saves evidence logs with automated machine headers (Findings DA, EN).
Outputs:
  - docs/evidence/payload_tests/test_pai_setup.txt
  - docs/evidence/payload_tests/test_sign_catalog.txt
  - docs/evidence/payload_tests/test_service_manager.txt
  - docs/evidence/payload_tests/test_shell.txt
  - docs/evidence/payload_tests/test_build_payload.txt
  - docs/evidence/payload_tests/test_launcher_and_zip.txt
  - docs/evidence/payload_tests/test_installer_p5.txt

Finding EN rules:
  - Checks git status --porcelain and records "Working Tree: clean" or "Working Tree: DIRTY".
  - Calculates and records the real working-tree research tree id.
  - Refuses to run if working tree is dirty unless --allow-dirty is explicitly passed.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def get_working_tree_research_id() -> str:
    """Calculates the exact git tree SHA of the working tree research/ directory."""
    tmp_index = tempfile.mktemp(prefix="git_idx_")
    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = tmp_index
    try:
        subprocess.check_call(
            ["git", "add", "-A", "research"],
            cwd=REPO_ROOT,
            env=env,
            stderr=subprocess.DEVNULL,
        )
        return subprocess.check_output(
            ["git", "write-tree", "--prefix=research/"],
            cwd=REPO_ROOT,
            env=env,
        ).decode().strip()
    finally:
        if os.path.exists(tmp_index):
            os.remove(tmp_index)


def get_machine_header(suite_title: str, is_dirty: Optional[bool] = None) -> str:
    lines = [
        "=" * 80,
        f"{suite_title.upper()} - VERIFIED MACHINE & REPOSITORY HEADER (Findings DA, EN)",
        "=" * 80,
        f"Timestamp (UTC): {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
        f"Platform:        {platform.platform()}",
        f"Python Runtime:  {sys.executable}",
        f"Python Version:  {sys.version.splitlines()[0]}",
        f"Processor:       {platform.processor()}",
    ]
    try:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT).decode().strip()
        lines.append(f"Git HEAD:        {head}")

        # Finding EN & EQ: Check porcelain status and record clean/DIRTY.
        # Uses is_dirty snapshot taken once at start, or checks excluding docs/evidence/
        # so evidence log writing does not dirty the working tree check for subsequent suites.
        if is_dirty is None:
            porcelain = subprocess.check_output(
                ["git", "status", "--porcelain", "--", ":!docs/evidence"],
                cwd=REPO_ROOT,
            ).decode().strip()
            is_dirty = bool(porcelain)
        lines.append(f"Working Tree:    {'DIRTY' if is_dirty else 'clean'}")

        # Finding EN: Record real working-tree research tree id
        res_tree = get_working_tree_research_id()
        lines.append(f"Research Tree:   {res_tree}")

        core_tree = subprocess.check_output(["git", "rev-parse", "HEAD:core"], cwd=REPO_ROOT).decode().strip()
        lines.append(f"Core Tree:       {core_tree}")
        core_bin = REPO_ROOT / "core" / "target" / "release" / ("pai-core.exe" if sys.platform == "win32" else "pai-core")
        if core_bin.is_file():
            core_sha = hashlib.sha256(core_bin.read_bytes()).hexdigest()
            lines.append(f"pai-core SHA256: {core_sha}")
        pai_setup = REPO_ROOT / "research" / "pai_setup.py"
        if pai_setup.is_file():
            lines.append(f"pai_setup SHA256: {hashlib.sha256(pai_setup.read_bytes()).hexdigest()}")
        pai_iss = REPO_ROOT / "packaging" / "pai.iss"
        if pai_iss.is_file():
            lines.append(f"pai.iss SHA256:   {hashlib.sha256(pai_iss.read_bytes()).hexdigest()}")
        agreement = REPO_ROOT / "packaging" / "agreement.txt"
        if agreement.is_file():
            lines.append(f"agreement SHA256: {hashlib.sha256(agreement.read_bytes()).hexdigest()}")
        try:
            from packaging.build_launcher import get_toolchain_info
            tc = get_toolchain_info()
            lines.append(f"GCC Version:     {tc['compiler_version']}")
            lines.append(f"Windres Version: {tc['windres_version']}")
        except Exception:
            pass
    except Exception as e:
        lines.append(f"Git Info:        Failed ({e})")
    lines.append("=" * 80)
    return "\n".join(lines)


def run_suite_and_save(suite_script: str, output_path: Path, title: str, is_dirty: Optional[bool] = None) -> None:
    header = get_machine_header(title, is_dirty=is_dirty)
    print(f"Running {suite_script}...")
    res = subprocess.run(
        [sys.executable, suite_script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    full_log = f"{header}\n\nCommand: python {suite_script}\nExit Code: {res.returncode}\n\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(full_log, encoding="utf-8")
    print(f"[EVIDENCE] Wrote {output_path} (Exit: {res.returncode})")
    if res.returncode != 0:
        raise RuntimeError(f"Suite {suite_script} failed with exit code {res.returncode}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Save unit test evidence logs with verified machine headers.")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow running on a dirty working tree (header will record DIRTY)",
    )
    args = parser.parse_args()

    # Finding EN & EQ: Check working tree status at start (excluding docs/evidence/)
    porcelain = subprocess.check_output(
        ["git", "status", "--porcelain", "--", ":!docs/evidence"],
        cwd=REPO_ROOT,
    ).decode().strip()
    is_dirty = bool(porcelain)

    if is_dirty and not args.allow_dirty:
        print(
            "ERROR: Working tree is dirty. Clean or commit changes before saving evidence, "
            "or pass --allow-dirty.",
            file=sys.stderr,
        )
        sys.exit(1)

    evidence_dir = REPO_ROOT / "docs" / "evidence" / "payload_tests"
    run_suite_and_save(
        "research/tests/test_pai_setup.py",
        evidence_dir / "test_pai_setup.txt",
        "PAI Setup Unit Tests (32 Tests, Milestone P6 & Findings DP, DQ, DR, DY, EF, EH, EM, EP)",
        is_dirty=is_dirty,
    )
    run_suite_and_save(
        "tools/test_sign_catalog.py",
        evidence_dir / "test_sign_catalog.txt",
        "PAI Catalog Sign Tool Tests (9 Tests, ADR-013 & Findings EH, EK, EL, ER)",
        is_dirty=is_dirty,
    )
    run_suite_and_save(
        "research/tests/test_service_manager.py",
        evidence_dir / "test_service_manager.txt",
        "PAI Managed Ollama Service Lifecycle Tests (8 Tests, ADR-014, Findings DS, DT, DU, EA)",
        is_dirty=is_dirty,
    )
    run_suite_and_save(
        "research/tests/test_shell.py",
        evidence_dir / "test_shell.txt",
        "PAI Interactive Terminal Shell REPL Tests (ADR-014 Commit 2)",
        is_dirty=is_dirty,
    )
    run_suite_and_save(
        "tools/test_build_payload.py",
        evidence_dir / "test_build_payload.txt",
        "PAI Build Payload Unit Tests (17 Tests, Milestone P2/P3)",
        is_dirty=is_dirty,
    )
    run_suite_and_save(
        "tools/test_launcher_and_zip.py",
        evidence_dir / "test_launcher_and_zip.txt",
        "PAI Launcher and Portable Zip Tests (21 Tests, Milestone P2)",
        is_dirty=is_dirty,
    )
    run_suite_and_save(
        "tools/test_installer_p5.py",
        evidence_dir / "test_installer_p5.txt",
        "PAI Inno Setup Installer Tests (20 Tests, Icon & Findings DK, DL, DM, DN, Milestone P5)",
        is_dirty=is_dirty,
    )


if __name__ == "__main__":
    main()
