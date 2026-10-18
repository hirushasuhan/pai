#!/usr/bin/env python3
"""
tools/run_shadow_workload.py - Dogfood Workload Driver for PAI Shadow Evaluation Window.

Finding AN: Provides a scripted driver executing real `pai` CLI commands against real
files and repositories to generate legitimate `source="cli"` shadow comparisons.

Executes:
1. `pai docs <file>` - Single-file document analyses (drives `ingest_file`).
2. `pai analyze <folder>` - Multi-file repository analyses (drives `ingest_folder`).
3. `pai doctor` - Diagnostics and governance evaluation.

Usage:
  python tools/run_shadow_workload.py [--iterations N] [--docs-file PATH] [--analyze-folder PATH] [--status-only]
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List

# Ensure research/ is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = REPO_ROOT / "research"
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

import pai
import pai_core_bridge


def get_default_docs_files(repo_root: Path) -> List[Path]:
    """
    Finds candidate documents in the repo and projects to exercise `pai docs` (Finding AP).
    Ensures high corpus diversity with a minimum of 50 distinct real source/doc files.
    """
    ignore_parts = {"target", ".git", "__pycache__", ".pytest_cache", "venv", "env", ".pai"}
    valid_exts = {".py", ".md", ".rs", ".json", ".toml", ".yml", ".yaml"}
    discovered: List[Path] = []

    for p in repo_root.rglob("*"):
        if p.is_file() and not any(x in p.parts for x in ignore_parts) and p.suffix in valid_exts:
            discovered.append(p)

    discovered.sort()
    return discovered


def get_default_analyze_folders(repo_root: Path) -> List[Path]:
    """
    Finds candidate directory targets to exercise `pai analyze` (Finding AP).
    Ensures high corpus diversity with a minimum of 20 distinct real directories
    drawn from the repository.
    """
    ignore_parts = {"target", ".git", "__pycache__", ".pytest_cache", "venv", "env", ".pai"}
    discovered: List[Path] = []

    try:
        for p in repo_root.rglob("*"):
            try:
                if p.is_dir() and not any(x in p.parts for x in ignore_parts):
                    has_files = any(f.is_file() for f in p.iterdir() if f.is_file() and not f.name.startswith("."))
                    if has_files:
                        discovered.append(p)
            except (PermissionError, OSError):
                continue
    except (PermissionError, OSError):
        pass

    # Fallback to predefined repository directories if needed
    if len(discovered) < 20:
        candidates = [
            repo_root / "core",
            repo_root / "core" / "src",
            repo_root / "core" / "benches",
            repo_root / "docs",
            repo_root / "docs" / "adr",
            repo_root / "docs" / "evidence",
            repo_root / "docs" / "examples",
            repo_root / "docs" / "reports",
            repo_root / "hardware",
            repo_root / "research",
            repo_root / "research" / "conformance",
            repo_root / "research" / "eval_sets",
            repo_root / "research" / "eval_sets" / "forecast_series",
            repo_root / "research" / "eval_sets" / "hidden_tests",
            repo_root / "research" / "fixtures",
            repo_root / "research" / "releases",
            repo_root / "research" / "tests",
            repo_root / "tools",
            repo_root / "tools" / "corpus",
            repo_root / ".github",
            repo_root / ".github" / "workflows",
        ]
        for c in candidates:
            if c.exists() and c.is_dir() and c not in discovered:
                discovered.append(c)

    discovered.sort()
    return discovered


def run_workload(
    iterations: int = 10,
    docs_files: List[Path] | None = None,
    analyze_folders: List[Path] | None = None,
    model: str = "stub-model",
    dry_run: bool = False,
) -> int:
    """Executes the scripted dogfood workload across files and folders."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    print("=" * 70)
    print("         PAI SHADOW WORKLOAD DOGFOOD DRIVER (Findings AN & AP)")
    print("=" * 70)

    if not docs_files:
        docs_files = get_default_docs_files(REPO_ROOT)
    if not analyze_folders:
        analyze_folders = get_default_analyze_folders(REPO_ROOT)

    if not docs_files:
        print("Error: No valid docs files found to analyze.", file=sys.stderr)
        return 1
    if not analyze_folders:
        print("Error: No valid analyze folders found to analyze.", file=sys.stderr)
        return 1

    print(f"Docs targets count    : {len(docs_files)} distinct files (minimum 50 required)")
    print(f"Analyze targets count : {len(analyze_folders)} distinct directories (minimum 20 required)")
    print(f"Iterations            : {iterations}")
    print(f"Model                 : {model}")
    print()

    summary_before = pai_core_bridge.get_shadow_telemetry_summary()
    print("Initial Telemetry Summary:")
    print(f"  CLI Comparisons   : {summary_before.get('cli_comparisons', 0)}")
    print(f"  CLI Discrepancies : {summary_before.get('cli_discrepancies', 0)}")
    print(f"  Window Started    : {summary_before.get('window_started', False)}")
    print(f"  Window Active     : {summary_before.get('window_active', False)}")
    print(f"  Window Complete   : {summary_before.get('window_complete', False)}")
    print("-" * 70)

    if dry_run:
        print("Dry run requested; exiting without executing commands.")
        return 0

    # Tag all records created during this driver workload run with driver=True (Finding AP)
    os.environ["PAI_TELEMETRY_DRIVER"] = "1"
    pai_core_bridge.set_telemetry_driver(True)

    try:
        docs_idx = 0
        folder_idx = 0

        for it in range(1, iterations + 1):
            target_doc = docs_files[docs_idx % len(docs_files)]
            docs_idx += 1

            print(f"[{it}/{iterations}] Running 'pai docs {target_doc.name}' ...")
            rc_docs = pai.main(["docs", str(target_doc), "--model", model, "--json"])
            if rc_docs != 0:
                print(f"Warning: pai docs failed with code {rc_docs}", file=sys.stderr)

            target_folder = analyze_folders[folder_idx % len(analyze_folders)]
            folder_idx += 1

            print(f"[{it}/{iterations}] Running 'pai analyze {target_folder.name}' ...")
            rc_ana = pai.main(["analyze", str(target_folder), "--model", model, "--json"])
            if rc_ana != 0:
                print(f"Warning: pai analyze failed with code {rc_ana}", file=sys.stderr)
    finally:
        os.environ.pop("PAI_TELEMETRY_DRIVER", None)
        pai_core_bridge.set_telemetry_driver(False)

    print()
    print("=" * 70)
    print("Workload iteration cycle complete. Fetching updated telemetry...")
    summary_after = pai_core_bridge.get_shadow_telemetry_summary()
    comps_diff = summary_after.get("cli_comparisons", 0) - summary_before.get("cli_comparisons", 0)
    print(f"New CLI comparisons generated : {comps_diff}")
    print(f"Total CLI comparisons         : {summary_after.get('cli_comparisons', 0)}")
    print(f"Driver CLI comparisons        : {summary_after.get('driver_comparisons', 0)}")
    print(f"Manual CLI comparisons        : {summary_after.get('manual_comparisons', 0)}")
    print(f"Distinct content digests      : {summary_after.get('distinct_content_digests_count', 0)}")
    print(f"Total CLI discrepancies       : {summary_after.get('cli_discrepancies', 0)}")
    print(f"Window Started                : {summary_after.get('window_started', False)}")
    print(f"Window Active                 : {summary_after.get('window_active', False)}")
    print(f"Window Complete               : {summary_after.get('window_complete', False)}")
    print("=" * 70)
    return 0


def main_cli() -> int:
    parser = argparse.ArgumentParser(description="PAI Shadow Workload Dogfood Driver")
    parser.add_argument("--iterations", "-n", type=int, default=10, help="Number of workload iterations")
    parser.add_argument("--docs-file", type=str, help="Specific file to run pai docs on")
    parser.add_argument("--analyze-folder", type=str, help="Specific directory to run pai analyze on")
    parser.add_argument("--model", type=str, default="stub-model", help="Model name for commands")
    parser.add_argument("--status-only", action="store_true", help="Print current telemetry status and exit")
    parser.add_argument("--dry-run", action="store_true", help="Display execution plan without running")

    args = parser.parse_args()

    if args.status_only:
        summary = pai_core_bridge.get_shadow_telemetry_summary()
        import json
        print(json.dumps(summary, indent=2))
        return 0

    docs = [Path(args.docs_file)] if args.docs_file else None
    folders = [Path(args.analyze_folder)] if args.analyze_folder else None

    return run_workload(
        iterations=args.iterations,
        docs_files=docs,
        analyze_folders=folders,
        model=args.model,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    sys.exit(main_cli())
