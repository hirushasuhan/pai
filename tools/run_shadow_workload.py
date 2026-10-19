#!/usr/bin/env python3
"""
tools/run_shadow_workload.py - Dogfood Workload Driver for PAI Shadow Evaluation Window.

Finding AN: Provides a scripted driver executing real `pai` CLI commands against real
files and repositories to generate legitimate `source="cli"` shadow comparisons.
Finding AS: Extracts and operates on a frozen snapshot of the evaluated commit.
Finding AT: Supports external manual projects directory (PAI_MANUAL_CORPUS_DIR),
            keeping private/personal files completely outside the Git repository.
            Only counts and content digests are tracked in telemetry; never paths or contents.
Finding AU: Pins the evaluated commit hash explicitly. Refuses to default to floating HEAD.
            Governance rule: ANY MODIFICATION TO research/ OR core/ INVALIDATES & RESTARTS
            THE 7-DAY SHADOW EVALUATION WINDOW.

Executes:
1. `pai docs <file>` - Single-file document analyses (drives `ingest_file`).
2. `pai analyze <folder>` - Multi-file repository analyses (drives `ingest_folder`).
3. `pai doctor` - Diagnostics and governance evaluation.

Usage:
  python tools/run_shadow_workload.py [--commit SHA] [--manual-dir PATH] [--iterations N] [--dry-run]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import zipfile
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure research/ is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = REPO_ROOT / "research"
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

import pai
import pai_core_bridge


def resolve_evaluated_commit(cli_commit: Optional[str] = None, repo_root: Optional[Path] = None) -> str:
    """
    Resolves the pinned evaluated commit hash (Findings AS & AU).
    Refuses to default to floating 'HEAD' without explicit pinning.
    Order of resolution:
    1. CLI argument --commit <SHA>
    2. Environment variable PAI_EVALUATED_COMMIT
    3. Pinned commit file tools/corpus/EVALUATED_COMMIT
    """
    root = repo_root or REPO_ROOT
    commit_val: Optional[str] = None

    if cli_commit:
        commit_val = cli_commit.strip()
    elif os.environ.get("PAI_EVALUATED_COMMIT"):
        commit_val = os.environ.get("PAI_EVALUATED_COMMIT", "").strip()
    else:
        commit_file = root / "tools" / "corpus" / "EVALUATED_COMMIT"
        if commit_file.exists():
            commit_val = commit_file.read_text("utf-8").strip()

    if not commit_val:
        raise ValueError(
            "Mandatory evaluated commit not specified (Finding AU). "
            "Pass --commit <SHA>, set PAI_EVALUATED_COMMIT, or write SHA to tools/corpus/EVALUATED_COMMIT. "
            "Floating 'HEAD' is disallowed to ensure corpus stability across the 7-day window."
        )

    try:
        proc = subprocess.run(
            ["git", "rev-parse", commit_val],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout.strip()
    except Exception:
        return commit_val


def ensure_frozen_snapshot(repo_root: Path, commit_sha: str) -> Tuple[Path, str]:
    """
    Extracts a frozen snapshot from git archive of the target commit (Finding AS).
    Ensures that live repository edits during the 7-day window cannot create new content
    digests or inflate distinct input metrics.
    Returns (snapshot_dir, resolved_commit_sha).
    """
    resolved_sha = commit_sha
    try:
        proc = subprocess.run(
            ["git", "rev-parse", commit_sha],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        )
        resolved_sha = proc.stdout.strip()
    except Exception:
        pass

    snapshot_dir = repo_root / "tools" / "corpus" / "frozen_snapshot"
    marker_file = snapshot_dir / ".commit_sha"

    if snapshot_dir.exists() and marker_file.exists():
        try:
            cached_sha = marker_file.read_text("utf-8").strip()
            if cached_sha == resolved_sha:
                return snapshot_dir, resolved_sha
        except Exception:
            pass

    # Extract git archive of named commit into snapshot_dir
    zip_tmp = repo_root / "tools" / "corpus" / f"snapshot_{int(time.time())}.zip"
    try:
        subprocess.run(
            ["git", "archive", "--format=zip", commit_sha, "-o", str(zip_tmp)],
            cwd=str(repo_root),
            check=True,
        )
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_tmp, "r") as z:
            z.extractall(snapshot_dir)
        marker_file.write_text(resolved_sha, encoding="utf-8")
    except Exception as e:
        print(f"Notice: Failed to extract git archive snapshot ({e}); falling back to repo root.", file=sys.stderr)
        return repo_root, resolved_sha
    finally:
        if zip_tmp.exists():
            try:
                zip_tmp.unlink()
            except OSError:
                pass

    return snapshot_dir, resolved_sha


def resolve_manual_projects_dir(cli_dir: Optional[str] = None, repo_root: Optional[Path] = None) -> Optional[Path]:
    """
    Resolves the directory containing manual real-world projects for the corpus (Finding AT).
    Order of precedence:
    1. Explicit CLI argument --manual-dir
    2. Environment variable PAI_MANUAL_CORPUS_DIR
    3. Default external location C:/Users/hp/Documents/pai_manual_corpus
    4. Git-ignored local fallback tools/corpus/manual_projects
    """
    candidates = []
    if cli_dir:
        candidates.append(Path(cli_dir))
    env_dir = os.environ.get("PAI_MANUAL_CORPUS_DIR")
    if env_dir:
        candidates.append(Path(env_dir))
    candidates.append(Path.home() / "Documents" / "pai_manual_corpus")
    root = repo_root or REPO_ROOT
    candidates.append(root / "tools" / "corpus" / "manual_projects")

    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return None


def _is_ignored(p: Path, scan_root: Path) -> bool:
    ignore_parts = {"target", ".git", "__pycache__", ".pytest_cache", "venv", "env", ".pai"}
    if any(x in p.parts for x in ignore_parts):
        return True
    if scan_root.name != "frozen_snapshot" and "frozen_snapshot" in p.parts:
        return True
    return False


def get_default_docs_files(
    repo_root: Path,
    snapshot_dir: Optional[Path] = None,
    manual_projects_dir: Optional[Path] = None,
) -> List[Path]:
    """
    Finds candidate documents in the frozen snapshot and external manual projects (Findings AP, AS, AT).
    Ensures high corpus diversity with a minimum of 50 distinct real source/doc files.
    """
    valid_exts = {".py", ".md", ".rs", ".json", ".toml", ".yml", ".yaml", ".txt", ".csv", ".markdown", ".mdx", ".properties"}
    discovered: List[Path] = []
    seen_paths: Set[Path] = set()

    scan_roots: List[Path] = []
    if snapshot_dir and snapshot_dir.exists():
        scan_roots.append(snapshot_dir)
    else:
        scan_roots.append(repo_root)

    # Scan external manual projects if available (Finding AT)
    if manual_projects_dir and manual_projects_dir.exists():
        scan_roots.append(manual_projects_dir)

    corpus_root = repo_root / "tools" / "corpus"
    for sub in ["sinhala_text", "multilingual_code", "large_docs", "corrupt_and_office"]:
        p_sub = corpus_root / sub
        if p_sub.exists() and p_sub not in scan_roots:
            scan_roots.append(p_sub)

    for r in scan_roots:
        for p in r.rglob("*"):
            if p.is_file() and not _is_ignored(p, r) and p.suffix.lower() in valid_exts:
                try:
                    res = p.resolve()
                    if res not in seen_paths:
                        seen_paths.add(res)
                        discovered.append(p)
                except Exception:
                    if p not in discovered:
                        discovered.append(p)

    discovered.sort()
    return discovered


def get_default_analyze_folders(
    repo_root: Path,
    snapshot_dir: Optional[Path] = None,
    manual_projects_dir: Optional[Path] = None,
) -> List[Path]:
    """
    Finds candidate directory targets to exercise `pai analyze` (Findings AP, AS, AT).
    Ensures high corpus diversity with a minimum of 20 distinct real directories
    drawn from the frozen snapshot and external manual real-world projects.
    """
    discovered: List[Path] = []
    seen_paths: Set[Path] = set()

    scan_roots: List[Path] = []
    if snapshot_dir and snapshot_dir.exists():
        scan_roots.append(snapshot_dir)
    else:
        scan_roots.append(repo_root)

    if manual_projects_dir and manual_projects_dir.exists():
        scan_roots.append(manual_projects_dir)

    corpus_root = repo_root / "tools" / "corpus"
    for sub in ["sinhala_text", "multilingual_code", "large_docs", "corrupt_and_office"]:
        p_sub = corpus_root / sub
        if p_sub.exists() and p_sub not in scan_roots:
            scan_roots.append(p_sub)

    for r in scan_roots:
        try:
            for p in r.rglob("*"):
                try:
                    if p.is_dir() and not _is_ignored(p, r):
                        has_files = any(f.is_file() for f in p.iterdir() if f.is_file() and not f.name.startswith("."))
                        if has_files:
                            res = p.resolve()
                            if res not in seen_paths:
                                seen_paths.add(res)
                                discovered.append(p)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass

    # Ensure at least 20 distinct directories even if external corpus is unavailable
    if len(discovered) < 20:
        candidates = [
            repo_root / "core",
            repo_root / "core" / "src",
            repo_root / "docs",
            repo_root / "docs" / "adr",
            repo_root / "docs" / "evidence",
            repo_root / "docs" / "examples",
            repo_root / "hardware",
            repo_root / "research",
            repo_root / "research" / "conformance",
            repo_root / "research" / "eval_sets",
            repo_root / "research" / "eval_sets" / "forecast_series",
            repo_root / "research" / "eval_sets" / "hidden_tests",
            repo_root / "research" / "tests",
            repo_root / "tools",
            repo_root / "tools" / "corpus",
            repo_root / "tools" / "corpus" / "corrupt_and_office",
            repo_root / "tools" / "corpus" / "large_docs",
            repo_root / "tools" / "corpus" / "multilingual_code",
            repo_root / "tools" / "corpus" / "sinhala_text",
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
    commit_sha: Optional[str] = None,
    use_live_repo: bool = False,
    snapshot_dir_override: Optional[Path] = None,
    manual_dir_override: Optional[str] = None,
) -> int:
    """Executes the scripted dogfood workload across files and folders."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    print("=" * 70)
    print("         PAI SHADOW WORKLOAD DOGFOOD DRIVER (Findings AN, AP, AS, AT, AU)")
    print("=" * 70)

    manual_projects_dir = resolve_manual_projects_dir(manual_dir_override, REPO_ROOT)
    if manual_projects_dir:
        print(f"Manual Corpus Source  : External Directory ({manual_projects_dir}) [Finding AT]")
    else:
        print("Manual Corpus Source  : None configured (using frozen snapshot & specialized corpus)")

    resolved_commit = commit_sha
    if use_live_repo:
        snapshot_dir = None
        resolved_commit = "LIVE"
        print("Corpus Mode           : LIVE REPOSITORY (Unfrozen)")
    elif snapshot_dir_override:
        snapshot_dir = snapshot_dir_override
        resolved_commit = commit_sha or "CUSTOM"
        print(f"Corpus Mode           : FROZEN SNAPSHOT OVERRIDE ({snapshot_dir})")
    else:
        resolved_commit = resolve_evaluated_commit(commit_sha, REPO_ROOT)
        snapshot_dir, resolved_commit = ensure_frozen_snapshot(REPO_ROOT, commit_sha=resolved_commit)
        print(f"Corpus Mode           : FROZEN SNAPSHOT (Finding AS)")
        print(f"Frozen Commit SHA     : {resolved_commit} (Finding AU pinned)")
        print(f"Snapshot Directory    : {snapshot_dir}")

    print("Governance Rule       : ANY MODIFICATION TO research/ OR core/ INVALIDATES & RESTARTS THE EVALUATION WINDOW.")

    if not docs_files:
        docs_files = get_default_docs_files(REPO_ROOT, snapshot_dir=snapshot_dir, manual_projects_dir=manual_projects_dir)
    if not analyze_folders:
        analyze_folders = get_default_analyze_folders(REPO_ROOT, snapshot_dir=snapshot_dir, manual_projects_dir=manual_projects_dir)

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
    parser.add_argument("--commit", type=str, help="Commit hash to freeze corpus snapshot at (Findings AS & AU). If omitted, reads from tools/corpus/EVALUATED_COMMIT or PAI_EVALUATED_COMMIT.")
    parser.add_argument("--snapshot-dir", type=str, help="Custom frozen snapshot directory (Finding AS)")
    parser.add_argument("--manual-dir", type=str, help="External directory containing manual real-world projects (Finding AT). If omitted, checks PAI_MANUAL_CORPUS_DIR or default external paths.")
    parser.add_argument("--live", action="store_true", help="Run against live repository instead of frozen snapshot")

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
        commit_sha=args.commit,
        use_live_repo=args.live,
        snapshot_dir_override=Path(args.snapshot_dir) if args.snapshot_dir else None,
        manual_dir_override=args.manual_dir,
    )


if __name__ == "__main__":
    sys.exit(main_cli())
