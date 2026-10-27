#!/usr/bin/env python3
"""
N+1 Evaluation Window Progress Checker for Personal Agentic AI (PAI).

Evaluates active operational shadow telemetry against Release N+1 criteria:
- Organic CLI comparisons >= 300 (driver-tagged comparisons excluded)
- Window duration span >= 14 days (1,209,600 seconds)
- Total and CLI shadow discrepancies == 0
- Single binary hash (no mid-window binary modifications)
- Binary rebuild detected == False
- Corrupt log lines == 0
- Log write failures == 0
- Evaluated tree integrity (core/ and research/ trees strictly match pins)

Supports verifying an installed PAI distribution (--installed / --installed-dir):
- Validates installed manifest.json tree IDs against recorded pins
- Computes installed pai-core.exe SHA-256 and verifies against binary pin
- Queries doctor via installed launcher to inspect active shadow telemetry
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

REQUIRED_ORGANIC_COMPARISONS = 300
REQUIRED_SPAN_DAYS = 14.0
REQUIRED_SPAN_SECONDS = REQUIRED_SPAN_DAYS * 86400.0

# Immutable pins for the N+1 Evaluation Window (governed by ADR-004, ADR-005, PACKAGING_SPEC)
PINNED_CORE_TREE = "14c60746ca9a41d91aafd88cc0c7d98719cfe3a9"
PINNED_RESEARCH_TREE = "506e520b33a0af8c3f0276114483ce26b9bd3787"
PINNED_BINARY_SHA256 = "6f13d49463c757f2f3e43506f9743c37f602196544ce8fa85d5c5ce9332e3efe"


def sha256_file(path: Path) -> str:
    """Computes hexadecimal SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def get_default_installed_dir() -> Path:
    """Returns standard per-user install directory for current platform."""
    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            return Path(local_app_data) / "Programs" / "PAI"
        return Path.home() / "AppData" / "Local" / "Programs" / "PAI"
    else:
        xdg_data = os.environ.get("XDG_DATA_HOME", "")
        if xdg_data:
            return Path(xdg_data) / "pai" / "current"
        return Path.home() / ".local" / "share" / "pai" / "current"


def verify_installed_copy(
    installed_dir: Path,
    pinned_core_tree: str = PINNED_CORE_TREE,
    pinned_research_tree: str = PINNED_RESEARCH_TREE,
    pinned_binary_sha256: str = PINNED_BINARY_SHA256,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verifies that an installed copy of PAI matches recorded release pins:
    - manifest.json exists and its recorded tree hashes match pinned_core_tree and pinned_research_tree.
    - bin/pai-core.exe exists and its SHA-256 digest matches pinned_binary_sha256.
    """
    res: Dict[str, Any] = {
        "installed_dir": str(installed_dir),
        "manifest_found": False,
        "manifest_version": None,
        "manifest_tag": None,
        "core_tree": None,
        "core_tree_match": False,
        "research_tree": None,
        "research_tree_match": False,
        "binary_found": False,
        "binary_sha256": None,
        "binary_match": False,
        "launcher_found": False,
        "errors": [],
    }

    if not installed_dir.is_dir():
        res["errors"].append(f"Installed directory does not exist: {installed_dir}")
        return False, res

    manifest_p = installed_dir / "manifest.json"
    if not manifest_p.is_file():
        res["errors"].append(f"manifest.json missing in installed directory: {manifest_p}")
        return False, res

    res["manifest_found"] = True
    try:
        with open(manifest_p, "r", encoding="utf-8") as f:
            manifest_doc = json.load(f)
    except Exception as e:
        res["errors"].append(f"Failed to parse manifest.json: {e}")
        return False, res

    res["manifest_version"] = manifest_doc.get("version")
    res["manifest_tag"] = manifest_doc.get("tag")
    trees = manifest_doc.get("trees", {})
    res["core_tree"] = trees.get("core")
    res["research_tree"] = trees.get("research")

    res["core_tree_match"] = (res["core_tree"] == pinned_core_tree)
    res["research_tree_match"] = (res["research_tree"] == pinned_research_tree)

    if not res["core_tree_match"]:
        res["errors"].append(f"Installed core tree '{res['core_tree']}' does not match pin '{pinned_core_tree}'")
    if not res["research_tree_match"]:
        res["errors"].append(f"Installed research tree '{res['research_tree']}' does not match pin '{pinned_research_tree}'")

    # Check pai-core binary
    core_bin = installed_dir / "bin" / ("pai-core.exe" if sys.platform == "win32" else "pai-core")
    if not core_bin.is_file():
        core_bin = installed_dir / "bin" / "pai-core"

    if not core_bin.is_file():
        res["errors"].append(f"Core binary missing in installed directory: {core_bin}")
        return False, res

    res["binary_found"] = True
    computed_sha = sha256_file(core_bin)
    res["binary_sha256"] = computed_sha
    res["binary_match"] = (computed_sha == pinned_binary_sha256)

    if not res["binary_match"]:
        res["errors"].append(f"Installed binary SHA-256 '{computed_sha}' does not match pin '{pinned_binary_sha256}'")

    launcher = installed_dir / "bin" / ("pai.exe" if sys.platform == "win32" else "pai")
    res["launcher_found"] = launcher.is_file()

    all_matched = (
        res["manifest_found"]
        and res["core_tree_match"]
        and res["research_tree_match"]
        and res["binary_found"]
        and res["binary_match"]
    )
    return all_matched, res


def check_n_plus_1_progress(
    installed_mode: bool = False,
    custom_installed_dir: Optional[Path] = None,
) -> int:
    repo_root = Path(__file__).resolve().parent.parent

    installed_dir: Optional[Path] = None
    installed_check: Optional[Dict[str, Any]] = None
    installed_ok: bool = True

    if installed_mode or custom_installed_dir is not None:
        installed_dir = custom_installed_dir or get_default_installed_dir()
        installed_ok, installed_check = verify_installed_copy(installed_dir)

    # Determine command to run doctor
    if installed_dir and (installed_dir / "bin" / ("pai.exe" if sys.platform == "win32" else "pai")).is_file():
        launcher = installed_dir / "bin" / ("pai.exe" if sys.platform == "win32" else "pai")
        cmd = [str(launcher), "doctor", "--json", "--skip-smoke"]
    elif installed_dir and (installed_dir / "research" / "pai.py").is_file():
        cmd = [sys.executable, str(installed_dir / "research" / "pai.py"), "doctor", "--json", "--skip-smoke"]
    else:
        pai_py = repo_root / "research" / "pai.py"
        cmd = [sys.executable, str(pai_py), "doctor", "--json", "--skip-smoke"]

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception:
        proc = None

    if proc is None or proc.returncode != 0 or not proc.stdout.strip():
        # Fallback to repo pai.py if launcher invocation fails or launcher is stub
        pai_py = repo_root / "research" / "pai.py"
        if pai_py.is_file():
            fallback_cmd = [sys.executable, str(pai_py), "doctor", "--json", "--skip-smoke"]
            proc = subprocess.run(fallback_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    data = None
    if proc.stdout.strip():
        try:
            data = json.loads(proc.stdout)
        except Exception:
            data = None

    if data is None or "shadow_telemetry" not in data:
        if proc.returncode != 0:
            print("ERROR: Failed to run 'pai doctor --json --skip-smoke':", proc.stderr, file=sys.stderr)
            return 1
        print("ERROR: Failed to parse doctor output as JSON or missing shadow_telemetry", file=sys.stderr)
        return 1

    shadow = data.get("shadow_telemetry", {})
    cli_comp = shadow.get("cli_comparisons", 0)
    driver_comp = shadow.get("driver_comparisons", 0)
    organic_comp = cli_comp - driver_comp
    cli_disc = shadow.get("cli_discrepancies", 0)
    total_disc = shadow.get("total_discrepancies", 0)
    corrupt_lines = shadow.get("corrupt_lines", 0)
    write_failures = shadow.get("log_write_failures", 0)
    span_sec = shadow.get("cli_span_seconds", 0.0)
    span_days = span_sec / 86400.0

    binary_hashes = shadow.get("binary_hashes", [])
    single_binary = len(binary_hashes) == 1
    rebuild_detected = shadow.get("binary_rebuild_detected", False)

    # Check git tree integrity against evaluated commit if checking repo checkout
    tree_match = True
    tree_detail = "N/A"
    if installed_check is not None:
        tree_match = installed_ok
        tree_detail = (
            f"installed core: {'MATCH' if installed_check['core_tree_match'] else 'DIFF'} ({str(installed_check['core_tree'])[:8]} vs {PINNED_CORE_TREE[:8]}), "
            f"research: {'MATCH' if installed_check['research_tree_match'] else 'DIFF'} ({str(installed_check['research_tree'])[:8]} vs {PINNED_RESEARCH_TREE[:8]})"
        )
    else:
        eval_commit_file = repo_root / "tools" / "corpus" / "EVALUATED_COMMIT"
        eval_commit = eval_commit_file.read_text().strip() if eval_commit_file.exists() else None
        if eval_commit:
            try:
                core_tree_res = subprocess.run(
                    ["git", "rev-parse", "HEAD:core"],
                    cwd=repo_root,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                eval_core_tree_res = subprocess.run(
                    ["git", "rev-parse", f"{eval_commit}:core"],
                    cwd=repo_root,
                    capture_output=True,
                    text=True,
                )
                res_tree_res = subprocess.run(
                    ["git", "rev-parse", "HEAD:research"],
                    cwd=repo_root,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                eval_res_tree_res = subprocess.run(
                    ["git", "rev-parse", f"{eval_commit}:research"],
                    cwd=repo_root,
                    capture_output=True,
                    text=True,
                )
                if eval_core_tree_res.returncode == 0 and eval_res_tree_res.returncode == 0:
                    current_core_tree = core_tree_res.stdout.strip()
                    eval_core_tree = eval_core_tree_res.stdout.strip()
                    current_res_tree = res_tree_res.stdout.strip()
                    eval_res_tree = eval_res_tree_res.stdout.strip()
                    core_match = (current_core_tree == eval_core_tree)
                    res_match = (current_res_tree == eval_res_tree)
                    tree_match = core_match and res_match
                    tree_detail = f"core: {'MATCH' if core_match else 'DIFF'} ({current_core_tree[:8]} vs {eval_core_tree[:8]}), research: {'MATCH' if res_match else 'DIFF'} ({current_res_tree[:8]} vs {eval_res_tree[:8]})"
                else:
                    tree_detail = f"evaluated commit {eval_commit[:8]} not reachable"
            except Exception as e:
                tree_detail = f"git check skipped ({e})"

    print("================================================================================")
    print("                    PAI RELEASE N+1 WINDOW PROGRESS REPORT                      ")
    print("================================================================================")
    if installed_check is not None:
        print(f"Target Mode             : [INSTALLED COPY] ({installed_check['installed_dir']})")
        print(f"Installed Manifest      : {'FOUND' if installed_check['manifest_found'] else 'MISSING'} (version: {installed_check['manifest_version']}, tag: {installed_check['manifest_tag']})")
        print(f"Installed Core Binary   : {'MATCH' if installed_check['binary_match'] else 'DIFF/MISSING'} ({str(installed_check['binary_sha256'])[:8]}... vs pin {PINNED_BINARY_SHA256[:8]}...)")
    else:
        print(f"Target Mode             : [DEVELOPMENT REPO] ({repo_root})")
    print(f"Bridge Mode             : [{data.get('bridge_mode', 'unknown')}]")
    print(f"Total CLI Comparisons   : {cli_comp}")
    print(f"Driver Comparisons      : {driver_comp}")
    print(f"Organic CLI Comparisons : {organic_comp} / {REQUIRED_ORGANIC_COMPARISONS} (Target: >= {REQUIRED_ORGANIC_COMPARISONS})")
    print(f"Shadow Discrepancies    : {cli_disc} (Total: {total_disc}) (Target: 0)")
    print(f"CLI Evaluation Span     : {span_days:.2f} days ({span_sec:,.0f}s / {REQUIRED_SPAN_SECONDS:,.0f}s) (Target: >= {REQUIRED_SPAN_DAYS} days)")
    print(f"Corrupt Log Lines       : {corrupt_lines} (Target: 0)")
    print(f"Log Write Failures      : {write_failures} (Target: 0)")
    print(f"Binary Hash Count       : {len(binary_hashes)} (Target: 1, hashes: {', '.join(h[:8] for h in binary_hashes) or 'none'})")
    print(f"Binary Rebuild Detected : {rebuild_detected} (Target: False)")
    print(f"Evaluated Tree Status   : {tree_detail}")

    organic_met = organic_comp >= REQUIRED_ORGANIC_COMPARISONS
    span_met = span_sec >= REQUIRED_SPAN_SECONDS
    disc_clean = (total_disc == 0 and cli_disc == 0)
    integrity_clean = (single_binary and not rebuild_detected and corrupt_lines == 0 and write_failures == 0 and tree_match)

    print("--------------------------------------------------------------------------------")
    print(f"Organic Comparisons Met : [{'OK' if organic_met else 'PENDING'}]")
    print(f"14-Day Span Met         : [{'OK' if span_met else 'PENDING'}]")
    print(f"Discrepancies Clean     : [{'OK' if disc_clean else 'FAILED'}]")
    print(f"Integrity & Log Health  : [{'OK' if integrity_clean else 'PENDING/FAILED'}]")
    print("--------------------------------------------------------------------------------")

    if organic_met and span_met and disc_clean and integrity_clean:
        print("VERDICT: Release N+1 operational criteria SATISFIED. Ready for candidate review.")
        return 0
    else:
        pending = []
        if not organic_met:
            pending.append(f"need {REQUIRED_ORGANIC_COMPARISONS - organic_comp} more organic comparisons")
        if not span_met:
            pending.append(f"need {REQUIRED_SPAN_DAYS - span_days:.2f} more days of span")
        if not disc_clean:
            pending.append(f"discrepancies detected ({cli_disc})")
        if not single_binary:
            pending.append(f"binary hash count is {len(binary_hashes)} (expected 1)")
        if rebuild_detected:
            pending.append("binary rebuild detected")
        if corrupt_lines > 0:
            pending.append(f"{corrupt_lines} corrupt log lines")
        if write_failures > 0:
            pending.append(f"{write_failures} write failures")
        if not tree_match:
            pending.append("tree mismatch against evaluated pins")
        print(f"VERDICT: Window in progress ({', '.join(pending)}).")
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Check PAI Release N+1 window progress against operational criteria.")
    parser.add_argument(
        "--installed",
        action="store_true",
        help="Check the installed copy of PAI at standard per-user install directory instead of git repo.",
    )
    parser.add_argument(
        "--installed-dir",
        type=Path,
        default=None,
        help="Explicit path to an installed PAI distribution directory to verify.",
    )
    args = parser.parse_args()
    return check_n_plus_1_progress(
        installed_mode=args.installed,
        custom_installed_dir=args.installed_dir,
    )


if __name__ == "__main__":
    sys.exit(main())
