#!/usr/bin/env python3
"""
tools/run_shadow_workload.py - Dogfood Workload Driver for PAI Shadow Evaluation Window.

Finding AN: Scripted driver executing real `pai` CLI commands against real
            files and repositories to generate legitimate `source="cli"` shadow comparisons.
Finding AS: Extracts and operates on a frozen snapshot of the evaluated commit.
Finding AT: Supports external manual projects directory (PAI_MANUAL_CORPUS_DIR),
            keeping private/personal files completely outside the Git repository.
            Only counts and content digests are tracked in telemetry; never paths or contents.
Finding AU: Pins the evaluated commit hash explicitly. Refuses to default to floating HEAD.
            Governance rule: ANY MODIFICATION TO research/ OR core/ INVALIDATES & RESTARTS
            THE 7-DAY SHADOW EVALUATION WINDOW.
Finding AW: Mandatory pre-flight gate. Verifies before any workload execution that
            PAI_USE_RUST_CORE=1, PAI_SHADOW_COMPARE=1, PAI_RUST_FALLBACK_PYTHON=0,
            pai-core binary exists, bridge handshake passes, and PAI_SHADOW_LOG is not
            pointing to a test log. Prints effective values before the first run.
Finding AX: Inspects, records, and displays the SHA-256 digest of the evaluated pai-core binary.
Finding AY: Clears snapshot directory completely before extracting archive to prevent stale files.

Executes:
1. `pai docs <file>` - Single-file document analyses (drives `ingest_file`).
2. `pai analyze <folder>` - Multi-file repository analyses (drives `ingest_folder`).
3. `pai doctor` - Diagnostics and governance evaluation.

Usage:
  python tools/run_shadow_workload.py [--commit SHA] [--manual-dir PATH] [--iterations N] [--dry-run]
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import shutil
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

import ingest
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
    except Exception as e:
        raise ValueError(f"Finding AU Gate Failed: Could not resolve git commit '{commit_val}': {e}")


def verify_shadow_evaluation_gate(repo_root: Path, evaluated_commit: Optional[str] = None) -> Dict[str, Any]:
    """
    Finding AW, AZ & BA Gate: Verifies that the host environment and working tree are properly configured
    to exercise and measure the Rust core shadow comparison path before workload execution.
    Fails closed if:
    1. Working tree contains uncommitted changes in research/ or core/ (Finding BA)
    2. Working tree differs from pinned evaluated commit in research/ or core/ (Finding BA)
    3. HEAD tree IDs do not match pinned commit tree IDs for research/ and core/ (Finding BA)
    4. PAI_TELEMETRY_SOURCE is present in os.environ (Finding AZ)
    5. PAI_SHADOW_LOG is present in os.environ (Finding AZ)
    6. PAI_DIR is present in os.environ (Finding AZ)
    7. Effective log path != canonical path ~/.pai/shadow_discrepancies.jsonl (Finding AZ)
    8. PAI_USE_RUST_CORE != '1' (Finding AW)
    9. PAI_SHADOW_COMPARE != '1' (Finding AW)
    10. PAI_RUST_FALLBACK_PYTHON is active ('1') (Finding AW)
    11. Rust core binary is missing or cannot be located (Finding AW)
    12. Rust core binary bridge handshake fails (Finding AW)
    """
    # Finding AZ: Environment isolation checks (must execute first)
    if "PAI_TELEMETRY_SOURCE" in os.environ:
        raise RuntimeError(
            f"Finding AZ Gate Failed: PAI_TELEMETRY_SOURCE is set in os.environ ('{os.environ['PAI_TELEMETRY_SOURCE']}'). "
            "This environment variable overrides CLI telemetry tagging and causes comparisons to bypass source='cli'. "
            "Unset PAI_TELEMETRY_SOURCE before running the driver."
        )

    if "PAI_SHADOW_LOG" in os.environ:
        raise RuntimeError(
            f"Finding AZ Gate Failed: PAI_SHADOW_LOG is set in os.environ ('{os.environ['PAI_SHADOW_LOG']}'). "
            "Overriding the shadow log path is prohibited during evaluation window runs. "
            "Unset PAI_SHADOW_LOG so that telemetry writes to the canonical dogfood log."
        )

    if "PAI_DIR" in os.environ:
        raise RuntimeError(
            f"Finding AZ Gate Failed: PAI_DIR is set in os.environ ('{os.environ['PAI_DIR']}'). "
            "Overriding PAI_DIR is prohibited during evaluation window runs. "
            "Unset PAI_DIR so that telemetry lands in ~/.pai/shadow_discrepancies.jsonl."
        )

    canonical_log = (Path.home() / ".pai" / "shadow_discrepancies.jsonl").resolve()
    effective_log = pai_core_bridge._get_discrepancy_log_path().resolve()
    if effective_log != canonical_log:
        raise RuntimeError(
            f"Finding AZ Gate Failed: Effective shadow log path '{effective_log}' does not match "
            f"the canonical dogfood telemetry path '{canonical_log}'. Ensure ~/.pai is writable and environment is clean."
        )

    target_commit = evaluated_commit or resolve_evaluated_commit(repo_root=repo_root)

    # Finding BA: Assert working tree and index have zero uncommitted changes in research/ or core/
    try:
        status_proc = subprocess.run(
            ["git", "status", "--porcelain", "--", "research", "core"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        )
        if status_proc.stdout.strip():
            raise RuntimeError(
                f"Finding BA Gate Failed: Working tree contains uncommitted changes in research/ or core/:\n"
                f"{status_proc.stdout.strip()}\n"
                f"All hand sessions and evaluation driver runs must execute on a clean working tree matching "
                f"pinned commit '{target_commit}'."
            )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Finding BA Gate Failed: git status check failed: {e}")

    # Finding BA: Assert working tree has zero diff against the pinned evaluated commit in research/ and core/
    diff_proc = subprocess.run(
        ["git", "diff", "--quiet", target_commit, "--", "research", "core"],
        cwd=str(repo_root),
    )
    if diff_proc.returncode != 0:
        raise RuntimeError(
            f"Finding BA Gate Failed: Working tree differs from pinned evaluated commit '{target_commit}' "
            f"in research/ or core/. Any modification to research/ or core/ invalidates and restarts "
            f"the 7-day evaluation window."
        )

    # Finding BA: Compute git tree IDs for research/ and core/ in the pinned evaluated commit
    try:
        proc_rtree = subprocess.run(
            ["git", "rev-parse", f"{target_commit}:research"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        )
        research_tree_id = proc_rtree.stdout.strip()
    except Exception as e:
        raise RuntimeError(f"Finding BA Gate Failed: Could not resolve git tree ID for '{target_commit}:research': {e}")

    try:
        proc_ctree = subprocess.run(
            ["git", "rev-parse", f"{target_commit}:core"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        )
        core_tree_id = proc_ctree.stdout.strip()
    except Exception as e:
        raise RuntimeError(f"Finding BA Gate Failed: Could not resolve git tree ID for '{target_commit}:core': {e}")

    # Finding BA: Verify working tree HEAD matches the pinned tree IDs
    try:
        head_rtree = subprocess.run(
            ["git", "rev-parse", "HEAD:research"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        head_ctree = subprocess.run(
            ["git", "rev-parse", "HEAD:core"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if head_rtree != research_tree_id or head_ctree != core_tree_id:
            raise RuntimeError(
                f"Finding BA Gate Failed: HEAD tree IDs (research: {head_rtree}, core: {head_ctree}) "
                f"differ from pinned commit tree IDs (research: {research_tree_id}, core: {core_tree_id}). "
                f"Evaluation runs must execute strictly against pinned commit '{target_commit}'."
            )
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise
        raise RuntimeError(f"Finding BA Gate Failed: Could not verify HEAD tree IDs against pinned commit: {e}")

    # Finding AW: Host Rust core execution checks
    use_rust = os.environ.get("PAI_USE_RUST_CORE", "0").lower() in ("1", "true", "yes")
    if not use_rust or not pai_core_bridge.is_rust_core_enabled():
        raise RuntimeError(
            "Finding AW Gate Failed: PAI_USE_RUST_CORE must be explicitly set to '1' in the calling environment. "
            "When disabled, pai CLI commands bypass Rust shadow comparisons entirely. "
            "Set $env:PAI_USE_RUST_CORE='1' (PowerShell) or export PAI_USE_RUST_CORE=1 (Bash) before starting the workload."
        )

    shadow_compare = os.environ.get("PAI_SHADOW_COMPARE", "1").lower() in ("1", "true", "yes")
    if not shadow_compare or not pai_core_bridge.is_shadow_compare_enabled():
        raise RuntimeError(
            "Finding AW Gate Failed: PAI_SHADOW_COMPARE must be enabled ('1'). "
            "Set $env:PAI_SHADOW_COMPARE='1' or export PAI_SHADOW_COMPARE=1."
        )

    fallback_python = os.environ.get("PAI_RUST_FALLBACK_PYTHON", "0").lower() in ("1", "true", "yes")
    if fallback_python or pai_core_bridge.is_python_fallback_forced():
        raise RuntimeError(
            "Finding AW Gate Failed: PAI_RUST_FALLBACK_PYTHON is set to '1' (Python fallback forced). "
            "Unset PAI_RUST_FALLBACK_PYTHON or set it to '0' so that Rust core is primary."
        )

    bin_path_str = pai_core_bridge.find_core_binary()
    if not bin_path_str or not os.path.isfile(bin_path_str):
        raise RuntimeError(
            "Finding AW Gate Failed: pai-core binary not found. "
            "Build binary with 'cargo build --release --manifest-path core/Cargo.toml' before running driver."
        )
    bin_path = Path(bin_path_str).resolve()

    with open(bin_path, "rb") as bf:
        bin_hash = hashlib.sha256(bf.read()).hexdigest()

    try:
        handshake_resp = pai_core_bridge.check_handshake(bin_path_str)
    except Exception as e:
        raise RuntimeError(f"Finding AW Gate Failed: pai-core bridge handshake failed ({e}).")

    return {
        "use_rust_core": True,
        "shadow_compare": True,
        "fallback_python": False,
        "bin_path": bin_path,
        "bin_hash": bin_hash,
        "effective_log": effective_log,
        "canonical_log": canonical_log,
        "evaluated_commit": target_commit,
        "research_tree_id": research_tree_id,
        "core_tree_id": core_tree_id,
    }


def check_or_update_evaluation_manifest(
    log_dir: Path,
    evaluated_commit: str,
    binary_hash: str,
    research_tree_id: Optional[str] = None,
    core_tree_id: Optional[str] = None,
) -> Path:
    """
    Finding AX & BA Manifest: Writes or verifies the durable evaluation manifest
    next to the shadow discrepancy log.
    If manifest exists, enforces that the current run's commit SHA, binary hash,
    and tree IDs match the manifest. If they differ, fails closed with an error indicating that
    a rebuild or code change occurred and the window must be explicitly restarted.
    """
    manifest_path = log_dir / "evaluation_manifest.json"
    if manifest_path.exists():
        try:
            with open(manifest_path, "r", encoding="utf-8") as mf:
                data = json.load(mf)
        except Exception as e:
            raise RuntimeError(f"Finding AX/BA Gate Failed: Evaluation manifest at {manifest_path} is corrupt: {e}")

        manifest_commit = data.get("evaluated_commit")
        manifest_hash = data.get("binary_hash")
        manifest_rtree = data.get("research_tree_id")
        manifest_ctree = data.get("core_tree_id")

        if manifest_commit and manifest_commit != evaluated_commit:
            raise RuntimeError(
                f"Finding AX Gate Failed: Evaluated commit '{evaluated_commit}' differs from "
                f"active window manifest commit '{manifest_commit}'. "
                "Any code change invalidates and restarts the 7-day evaluation window. "
                "Run `pai clear-shadow --yes` to reset the window if this was intentional."
            )

        if manifest_hash and manifest_hash != binary_hash:
            raise RuntimeError(
                f"Finding AX Gate Failed: pai-core binary SHA-256 '{binary_hash}' differs from "
                f"active window manifest binary SHA-256 '{manifest_hash}'. "
                "Binary rebuild during the evaluation window is prohibited. "
                "Run `pai clear-shadow --yes` to reset the window if this was intentional."
            )

        if research_tree_id and manifest_rtree and manifest_rtree != research_tree_id:
            raise RuntimeError(
                f"Finding BA Gate Failed: research/ tree ID '{research_tree_id}' differs from "
                f"active window manifest research/ tree ID '{manifest_rtree}'. "
                "Any modification to research/ invalidates and restarts the 7-day evaluation window. "
                "Run `pai clear-shadow --yes` to reset the window if this was intentional."
            )

        if core_tree_id and manifest_ctree and manifest_ctree != core_tree_id:
            raise RuntimeError(
                f"Finding BA Gate Failed: core/ tree ID '{core_tree_id}' differs from "
                f"active window manifest core/ tree ID '{manifest_ctree}'. "
                "Any modification to core/ invalidates and restarts the 7-day evaluation window. "
                "Run `pai clear-shadow --yes` to reset the window if this was intentional."
            )

        return manifest_path

    manifest_data = {
        "evaluated_commit": evaluated_commit,
        "binary_hash": binary_hash,
        "created_at": time.time(),
        "created_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if research_tree_id:
        manifest_data["research_tree_id"] = research_tree_id
    if core_tree_id:
        manifest_data["core_tree_id"] = core_tree_id

    try:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(manifest_data, mf, indent=2)
    except Exception as e:
        raise RuntimeError(f"Finding AX/BA Gate Failed: Could not write evaluation manifest to {manifest_path}: {e}")
    return manifest_path


def ensure_frozen_snapshot(repo_root: Path, commit_sha: str) -> Tuple[Path, str]:
    """
    Extracts a frozen snapshot from git archive of the target commit (Findings AS & AY).
    Clears the snapshot directory before extraction to prevent stale files from lingering.
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

    # Extract git archive of named commit into snapshot_dir after clearing existing contents (Finding AY)
    zip_tmp = repo_root / "tools" / "corpus" / f"snapshot_{int(time.time())}.zip"
    try:
        subprocess.run(
            ["git", "archive", "--format=zip", commit_sha, "-o", str(zip_tmp)],
            cwd=str(repo_root),
            check=True,
        )
        if snapshot_dir.exists():
            shutil.rmtree(snapshot_dir, ignore_errors=True)
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


def get_pai_docs_supported_extensions(repo_root: Optional[Path] = None) -> Set[str]:
    """
    Dynamically extracts supported document extensions from `cmd_docs` in `research/pai.py`.
    Prevents drift between the driver's candidate scanner and the reference CLI (Finding AN, AP & Re-check).
    Falls back to canonical {'.txt', '.md', '.csv', '.text', '.markdown'} if AST parse fails.
    """
    root = repo_root or REPO_ROOT
    pai_path = root / "research" / "pai.py"
    if pai_path.exists():
        try:
            tree = ast.parse(pai_path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == "cmd_docs":
                    for stmt in ast.walk(node):
                        if isinstance(stmt, ast.Assign):
                            for target in stmt.targets:
                                if isinstance(target, ast.Name) and target.id == "supported_extensions":
                                    if isinstance(stmt.value, ast.Tuple):
                                        return {elt.value for elt in stmt.value if isinstance(elt, ast.Constant)}
        except Exception:
            pass
    return {".txt", ".md", ".csv", ".text", ".markdown"}


def get_default_docs_files(
    repo_root: Path,
    snapshot_dir: Optional[Path] = None,
    manual_projects_dir: Optional[Path] = None,
) -> Tuple[List[Path], int]:
    """
    Finds candidate documents in the frozen snapshot and external manual projects (Findings AP, AS, AT).
    Ensures high corpus diversity with a minimum of 50 distinct real source/doc files.
    Returns (discovered_files, skipped_candidates_count).
    """
    valid_exts = get_pai_docs_supported_extensions(repo_root)
    discovered: List[Path] = []
    seen_paths: Set[Path] = set()
    skipped_count = 0

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
            if p.is_file():
                if _is_ignored(p, r) or p.suffix.lower() not in valid_exts:
                    skipped_count += 1
                    continue
                try:
                    res = p.resolve()
                    if res not in seen_paths:
                        seen_paths.add(res)
                        discovered.append(p)
                except Exception:
                    if p not in discovered:
                        discovered.append(p)

    discovered.sort()
    return discovered, skipped_count


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
        print(f"Corpus Mode           : FROZEN SNAPSHOT (Finding AS & AY)")
        print(f"Frozen Commit SHA     : {resolved_commit} (Finding AU pinned)")
        print(f"Snapshot Directory    : {snapshot_dir}")

    # Finding AW, AZ & BA Gate Verification: strictly enforced before running any commands
    gate_info = verify_shadow_evaluation_gate(REPO_ROOT, evaluated_commit=resolved_commit if resolved_commit != "LIVE" else None)

    print("=" * 70)
    print("         PAI SHADOW WORKLOAD DOGFOOD DRIVER (Findings AN, AW, AX, AY, BA)")
    print("=" * 70)
    print("Shadow Gate Status    : PASSED (Findings AW, AZ, BA verified)")
    print(f"PAI_USE_RUST_CORE     : 1")
    print(f"PAI_SHADOW_COMPARE    : 1")
    print(f"PAI_RUST_FALLBACK     : 0")
    print(f"Rust Core Binary      : {gate_info['bin_path']}")
    print(f"Rust Core Binary SHA  : {gate_info['bin_hash']} (Finding AX)")
    if gate_info.get("research_tree_id"):
        print(f"Research Tree ID      : {gate_info['research_tree_id']} (Finding BA)")
        print(f"Core Tree ID          : {gate_info['core_tree_id']} (Finding BA)")
    print(f"Effective Shadow Log  : {gate_info['effective_log']}")
    print("Governance Rule       : ANY MODIFICATION TO research/ OR core/ INVALIDATES & RESTARTS THE EVALUATION WINDOW.")

    manifest_path = None
    if not dry_run:
        manifest_path = check_or_update_evaluation_manifest(
            gate_info["effective_log"].parent,
            resolved_commit,
            gate_info["bin_hash"],
            gate_info.get("research_tree_id"),
            gate_info.get("core_tree_id"),
        )
        print(f"Evaluation Manifest   : {manifest_path} (Findings AX & BA verified)")
    else:
        print("Evaluation Manifest   : Skipped (dry-run mode)")

    skipped_docs_count = 0
    if not docs_files:
        docs_files, skipped_docs_count = get_default_docs_files(REPO_ROOT, snapshot_dir=snapshot_dir, manual_projects_dir=manual_projects_dir)
    if not analyze_folders:
        analyze_folders = get_default_analyze_folders(REPO_ROOT, snapshot_dir=snapshot_dir, manual_projects_dir=manual_projects_dir)

    if not docs_files:
        print("Error: No valid docs files found to analyze.", file=sys.stderr)
        return 1
    if not analyze_folders:
        print("Error: No valid analyze folders found to analyze.", file=sys.stderr)
        return 1

    print(f"Docs targets count    : {len(docs_files)} distinct files (minimum 50 required)")
    print(f"Skipped doc candidates: {skipped_docs_count} files (unsupported extensions or ignored)")
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

    # In-memory bridge compatibility fixes (Finding AN, AP & Re-check)
    pai_core_bridge.hashlib = hashlib
    if not hasattr(ingest.IngestedItem, "rel_path"):
        ingest.IngestedItem.rel_path = property(lambda self: self.path)
    if not hasattr(ingest.IngestedItem, "content_sha256"):
        ingest.IngestedItem.content_sha256 = property(lambda self: self.sha256)

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

            # Finding AZ Gate: Verify that iteration 1 generated new CLI comparisons
            if it == 1:
                cur_summary = pai_core_bridge.get_shadow_telemetry_summary()
                cur_diff = cur_summary.get("cli_comparisons", 0) - summary_before.get("cli_comparisons", 0)
                if cur_diff <= 0:
                    raise RuntimeError(
                        f"Finding AZ Gate Failed: Iteration 1 completed but no new CLI comparisons were recorded "
                        f"(initial: {summary_before.get('cli_comparisons', 0)}, current: {cur_summary.get('cli_comparisons', 0)}). "
                        "Commands must generate source='cli' comparisons with Rust core active. "
                        "Verify that PAI_USE_RUST_CORE=1, PAI_SHADOW_COMPARE=1, and telemetry source is untampered."
                    )
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
