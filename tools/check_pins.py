#!/usr/bin/env python3
"""
Personal Agentic AI (PAI) - Pre-Freeze Pin Consistency Audit Tool.

Milestone D1 (Pre-Freeze Pin Verification).
Verifies cryptographic tree and binary hash invariants across:
  1. packaging/build_payload.py constants (EXPECTED_CORE_TREE, EXPECTED_RESEARCH_TREE, EXPECTED_BINARY_SHA256)
  2. tools/check_n_plus_1.py constants (PINNED_CORE_TREE, PINNED_RESEARCH_TREE, PINNED_BINARY_SHA256)
  3. docs/FREEZE_CHECKLIST.md recorded pins
  4. Live git tree hashes (git rev-parse <ref>:core, git rev-parse <ref>:research)
  5. Local release binary SHA-256 (core/target/release/pai-core.exe) if present

Prints a clear PASS / FAIL tabular summary and exits with code 0 on full consistency or 1 on mismatch.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from packaging.build_payload import (
    EXPECTED_BINARY_SHA256,
    EXPECTED_CORE_TREE,
    EXPECTED_RESEARCH_TREE,
)
from tools.check_n_plus_1 import (
    PINNED_BINARY_SHA256,
    PINNED_CORE_TREE,
    PINNED_RESEARCH_TREE,
)


def sha256_file(path: Path) -> str:
    """Computes SHA-256 digest of a file in lowercase hex."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def get_git_tree_hash(ref: str, subtree: str) -> str:
    """Queries git for the exact tree SHA of a ref and subtree."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", f"{ref}:{subtree}"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout.strip().lower()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to query git tree for {ref}:{subtree}: {e.stderr.strip()}") from e


def parse_freeze_checklist_pins(checklist_path: Path) -> Dict[str, str]:
    """Parses evaluated tree IDs and binary SHA-256 from docs/FREEZE_CHECKLIST.md."""
    if not checklist_path.is_file():
        raise FileNotFoundError(f"Freeze checklist not found at: {checklist_path}")

    text = checklist_path.read_text(encoding="utf-8")
    pins: Dict[str, str] = {}

    m_core = re.search(r"`core/`\s+tree\s+ID:\s*`([0-9a-fA-F]{40})`", text)
    if m_core:
        pins["core_tree"] = m_core.group(1).lower()

    m_res = re.search(r"`research/`\s+tree\s+ID:\s*`([0-9a-fA-F]{40})`", text)
    if not m_res:
        m_res = re.search(r"New\s+Pinned\s+Research\s+Tree\s+ID:\s*`([0-9a-fA-F]{40})`", text)
    if m_res:
        pins["research_tree"] = m_res.group(1).lower()

    m_bin = re.search(r"`pai-core\.exe`\s+SHA-256:\s*`([0-9a-fA-F]{64})`", text)
    if m_bin:
        pins["binary_sha256"] = m_bin.group(1).lower()

    return pins


def check_pin_consistency(ref: str = "HEAD", require_binary: bool = False) -> Tuple[bool, List[str]]:
    """
    Performs full cross-validation of core tree, research tree, and binary SHA-256.
    Returns (all_passed, report_lines).
    """
    lines: List[str] = []
    all_ok = True

    lines.append("=" * 80)
    lines.append(f"PAI PRE-FREEZE PIN CONSISTENCY AUDIT (Milestone D1/D2, ref: {ref})")
    lines.append("=" * 80)

    # 1. Core Tree
    git_core = get_git_tree_hash(ref, "core")
    checklist_pins = parse_freeze_checklist_pins(REPO_ROOT / "docs" / "FREEZE_CHECKLIST.md")
    fc_core = checklist_pins.get("core_tree")

    core_sources = {
        "packaging/build_payload.py": EXPECTED_CORE_TREE.lower(),
        "tools/check_n_plus_1.py": PINNED_CORE_TREE.lower(),
        "docs/FREEZE_CHECKLIST.md": fc_core,
        f"git rev-parse {ref}:core": git_core,
    }
    core_values = set(core_sources.values())
    core_ok = (len(core_values) == 1 and None not in core_values)
    if not core_ok:
        all_ok = False

    lines.append(f"1. CORE TREE INVARIANT: {'PASS' if core_ok else 'FAIL'}")
    for src, val in core_sources.items():
        match_str = "MATCH" if (val and val == git_core) else "MISMATCH"
        lines.append(f"   [{match_str:8}] {src:30}: {val}")
    lines.append("")

    # 2. Research Tree
    git_res = get_git_tree_hash(ref, "research")
    fc_res = checklist_pins.get("research_tree")

    res_sources = {
        "packaging/build_payload.py": EXPECTED_RESEARCH_TREE.lower(),
        "tools/check_n_plus_1.py": PINNED_RESEARCH_TREE.lower(),
        "docs/FREEZE_CHECKLIST.md": fc_res,
        f"git rev-parse {ref}:research": git_res,
    }
    res_values = set(res_sources.values())
    res_ok = (len(res_values) == 1 and None not in res_values)
    if not res_ok:
        all_ok = False

    lines.append(f"2. RESEARCH TREE INVARIANT: {'PASS' if res_ok else 'FAIL'}")
    for src, val in res_sources.items():
        match_str = "MATCH" if (val and val == git_res) else "MISMATCH"
        lines.append(f"   [{match_str:8}] {src:30}: {val}")
    lines.append("")

    # 3. Core Binary SHA-256
    fc_bin = checklist_pins.get("binary_sha256")
    bin_file = REPO_ROOT / "core" / "target" / "release" / ("pai-core.exe" if sys.platform == "win32" else "pai-core")
    actual_bin_sha = sha256_file(bin_file) if bin_file.is_file() else None

    bin_sources = {
        "packaging/build_payload.py": EXPECTED_BINARY_SHA256.lower(),
        "tools/check_n_plus_1.py": PINNED_BINARY_SHA256.lower(),
        "docs/FREEZE_CHECKLIST.md": fc_bin,
    }

    recorded_vals = {
        EXPECTED_BINARY_SHA256.lower(),
        PINNED_BINARY_SHA256.lower(),
        fc_bin,
    }
    recorded_match = (len(recorded_vals) == 1 and None not in recorded_vals)

    file_label = f"file ({bin_file.name})"
    if actual_bin_sha:
        bin_sources[file_label] = actual_bin_sha
        file_match = (actual_bin_sha == EXPECTED_BINARY_SHA256.lower())
        bin_ok = recorded_match and file_match
    else:
        bin_sources[file_label] = "binary file not found, file hash not checked"
        if require_binary:
            bin_ok = False
        else:
            bin_ok = recorded_match

    if not bin_ok:
        all_ok = False

    lines.append(f"3. CORE BINARY SHA-256 INVARIANT: {'PASS' if bin_ok else 'FAIL'}")
    for src, val in bin_sources.items():
        if val == "binary file not found, file hash not checked":
            status_tag = "FAIL" if require_binary else "NOTE"
            lines.append(f"   [{status_tag:8}] {src:30}: {val}")
        else:
            match_str = "MATCH" if (val and val == EXPECTED_BINARY_SHA256.lower()) else "MISMATCH"
            lines.append(f"   [{match_str:8}] {src:30}: {val}")
    lines.append("")

    lines.append("=" * 80)
    lines.append(f"OVERALL PIN AUDIT VERDICT: {'PASS' if all_ok else 'FAIL'}")
    lines.append("=" * 80)

    return all_ok, lines


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify cryptographic pin consistency across build code, N+1 checker, checklist, and git ref."
    )
    parser.add_argument(
        "--ref",
        default="HEAD",
        help="Git commit reference to audit against (default: HEAD)",
    )
    parser.add_argument(
        "--require-binary",
        action="store_true",
        help="Require pai-core binary to be present on disk; fails if binary is missing (Finding GB).",
    )
    args = parser.parse_args(argv)

    try:
        passed, report_lines = check_pin_consistency(ref=args.ref, require_binary=args.require_binary)
        print("\n".join(report_lines))
        return 0 if passed else 1
    except Exception as e:
        print(f"ERROR: Pin audit failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
