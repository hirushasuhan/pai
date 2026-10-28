#!/usr/bin/env python3
"""
Executes unit test suites and saves evidence logs with automated machine headers (Finding DA).
Outputs:
  - docs/evidence/payload_tests/test_pai_setup.txt
  - docs/evidence/payload_tests/test_build_payload.txt
"""

import datetime
import hashlib
import os
import platform
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def get_machine_header(suite_title: str) -> str:
    lines = [
        "=" * 80,
        f"{suite_title.upper()} - VERIFIED MACHINE & REPOSITORY HEADER (Finding DA)",
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
        res_tree = subprocess.check_output(["git", "rev-parse", "HEAD:research"], cwd=REPO_ROOT).decode().strip()
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


def run_suite_and_save(suite_script: str, output_path: Path, title: str) -> None:
    header = get_machine_header(title)
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
    evidence_dir = REPO_ROOT / "docs" / "evidence" / "payload_tests"
    run_suite_and_save(
        "research/tests/test_pai_setup.py",
        evidence_dir / "test_pai_setup.txt",
        "PAI Setup Unit Tests (28 Tests, Milestone P6 & Subcommand Parity)",
    )
    run_suite_and_save(
        "tools/test_build_payload.py",
        evidence_dir / "test_build_payload.txt",
        "PAI Build Payload Unit Tests (17 Tests, Milestone P2/P3)",
    )
    run_suite_and_save(
        "tools/test_launcher_and_zip.py",
        evidence_dir / "test_launcher_and_zip.txt",
        "PAI Launcher and Portable Zip Tests (21 Tests, Milestone P2)",
    )
    run_suite_and_save(
        "tools/test_installer_p5.py",
        evidence_dir / "test_installer_p5.txt",
        "PAI Inno Setup Installer Tests (20 Tests, Icon & Findings DK, DL, DM, DN, Milestone P5)",
    )


if __name__ == "__main__":
    main()
