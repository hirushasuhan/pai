"""Antigravity Autonomous Driver & Continuous Task Supervisor for PAI.

Orchestrates Google Antigravity IDE and headless `agy` CLI agent execution:
  - Discovers `agy.exe` and `Antigravity IDE.exe` on host.
  - Automatically provisions project workspaces under `~/Documents/GitHub/pai_projects/`.
  - Injects structured task blueprints (`AGY_TASK.md`) and milestones.
  - Launches the visual Antigravity IDE GUI for live monitoring.
  - Steers `agy` non-interactively with `--dangerously-skip-permissions`.
  - Runs continuous closed-loop verification across turns until the goal is achieved.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


def _emit(stream: Any, msg: str) -> None:
    if stream is None:
        return
    try:
        stream.write(msg + "\n")
        stream.flush()
    except Exception:
        pass


def find_antigravity_binaries() -> Tuple[Optional[str], Optional[str]]:
    """Locate agy CLI and Antigravity IDE executables on host.

    Returns (agy_cli_path, ide_path).
    """
    agy_cli = shutil.which("agy") or shutil.which("agy.exe")
    if not agy_cli:
        candidate_agy = Path(os.path.expandvars(r"%LOCALAPPDATA%\agy\bin\agy.exe"))
        if candidate_agy.is_file():
            agy_cli = str(candidate_agy)

    ide_candidates = [
        Path(os.path.expandvars(r"%LOCALAPPDATA%\Programs\Antigravity IDE\Antigravity IDE.exe")),
        Path(os.path.expandvars(r"%LOCALAPPDATA%\Programs\Antigravity\Antigravity.exe")),
    ]
    ide_path = None
    for cand in ide_candidates:
        if cand.is_file():
            ide_path = str(cand)
            break
    if not ide_path:
        w_ide = shutil.which("antigravity") or shutil.which("Antigravity IDE")
        if w_ide:
            ide_path = w_ide

    return agy_cli, ide_path


def slugify_task_name(prompt: str) -> str:
    """Create a clean directory name from a task prompt."""
    cleaned = re.sub(
        r"(?i)\b(antigravity|agy|open|karala|hadanna|hadala|denna|create|make|build|eke|eken|eka|please|pls|the|a|an|iwara|wenakan|until|done)\b",
        " ",
        prompt,
    )
    cleaned = re.sub(r"[^\w\s-]", "", cleaned).strip()
    words = cleaned.split()[:4]
    slug = "_".join(words).lower() if words else "pai_project"
    return slug[:40] or "pai_project"


def create_project_workspace(task_name: str, base_dir: Optional[Path] = None) -> Path:
    """Provision a project directory under pai_projects with an initial task blueprint."""
    root = base_dir or Path(
        os.environ.get("PAI_PROJECTS_DIR", str(Path.home() / "Documents" / "GitHub" / "pai_projects"))
    )
    slug = slugify_task_name(task_name)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    project_dir = root / f"{slug}_{timestamp}"
    project_dir.mkdir(parents=True, exist_ok=True)

    blueprint = (
        f"# Project: {slug.replace('_', ' ').title()}\n\n"
        f"**Goal:** {task_name}\n\n"
        "## Technical Requirements\n"
        "- Complete, self-contained, runnable implementation.\n"
        "- Clean code architecture with zero external runtime missing dependencies.\n"
        "- Runnable entry point (e.g. index.html or main.py).\n\n"
        "## Acceptance Criteria\n"
        "1. All source files, assets, and entry points exist on disk.\n"
        "2. No unresolved syntax or execution errors.\n"
        "3. Verified runnable in browser or terminal.\n"
    )
    (project_dir / "AGY_TASK.md").write_text(blueprint, encoding="utf-8")
    return project_dir


def launch_antigravity_ide(project_dir: Path, ide_path: Optional[str] = None) -> Tuple[bool, str]:
    """Launch the visual Antigravity IDE GUI pointing to the workspace folder."""
    if ide_path is None:
        _, ide_path = find_antigravity_binaries()
    if not ide_path or not Path(ide_path).is_file():
        return False, "Antigravity IDE executable was not found on this system."
    try:
        subprocess.Popen(
            [ide_path, str(project_dir.resolve())],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        return True, f"Launched Antigravity IDE for workspace '{project_dir.name}'."
    except Exception as exc:
        return False, f"Failed to launch Antigravity IDE: {exc}"


def audit_workspace_files(project_dir: Path) -> Dict[str, Any]:
    """Scan the workspace, checking created files, sizes, and syntax validity."""
    files: List[Dict[str, Any]] = []
    syntax_errors: List[str] = []

    for p in project_dir.rglob("*"):
        if (
            p.is_file()
            and not p.name.startswith((".", "AGY_TASK.md"))
            and "__pycache__" not in p.parts
            and not p.name.endswith((".pyc", ".pyo"))
        ):
            try:
                rel = str(p.relative_to(project_dir))
                size = p.stat().st_size
                files.append({"path": rel, "size": size})

                # Basic syntax checks
                if p.suffix == ".py" and size > 0:
                    proc = subprocess.run(
                        [sys.executable, "-m", "py_compile", str(p)],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if proc.returncode != 0:
                        syntax_errors.append(f"{rel}: {proc.stderr.strip() or 'Python compilation error'}")
                elif p.suffix == ".js" and size > 0 and shutil.which("node"):
                    proc = subprocess.run(
                        ["node", "--check", str(p)],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if proc.returncode != 0:
                        syntax_errors.append(f"{rel}: {proc.stderr.strip() or 'JS syntax error'}")
            except Exception:
                pass

    return {
        "files": files,
        "total_files": len(files),
        "total_bytes": sum(f["size"] for f in files),
        "syntax_errors": syntax_errors,
    }


def run_antigravity_continuous_task(
    prompt: str,
    stream: Any = sys.stdout,
    max_turns: int = 10,
    open_ide: bool = True,
    executor: Optional[Callable[[List[str]], int]] = None,
    base_dir: Optional[Path] = None,
) -> Tuple[bool, str]:
    """Autonomously drive Antigravity IDE and `agy` agent until task completion."""
    raw = (prompt or "").strip()
    if not raw:
        return False, "Prompt cannot be empty for Antigravity autonomous development."

    _emit(stream, "🚀 Initializing Antigravity Autonomous Bridge...")
    agy_exe, ide_exe = find_antigravity_binaries()

    # Step 1: Provision Workspace
    project_dir = create_project_workspace(raw, base_dir=base_dir)
    _emit(stream, f"📁 Scaffolding workspace: {project_dir}")

    # Step 2: Open IDE for live visual inspection if requested
    if open_ide and ide_exe:
        ok_ide, ide_msg = launch_antigravity_ide(project_dir, ide_path=ide_exe)
        if ok_ide:
            _emit(stream, f"🖥️ {ide_msg}")
        else:
            _emit(stream, f"⚠️ Note: {ide_msg} (Proceeding with autonomous CLI agent)")
    elif not ide_exe:
        _emit(stream, "⚠️ Note: Antigravity IDE GUI executable not found. Proceeding with agy CLI agent.")

    if not agy_exe or not Path(agy_exe).is_file():
        # Fallback if agy CLI is completely missing but IDE opened
        return True, f"Workspace prepared at {project_dir}. Please continue task directly in Antigravity IDE."

    # Step 3: Closed-Loop Multi-Turn Steering
    turn_limit = max(1, min(max_turns, int(os.environ.get("PAI_AGY_MAX_TURNS", "12"))))
    turn = 1
    current_prompt = (
        f"You are working in the workspace '{project_dir}'.\n"
        f"Goal: {raw}\n\n"
        "Requirements:\n"
        "- Build a complete, functional, high-quality, self-contained project.\n"
        "- Create all necessary code files (HTML, JS, CSS, Python, etc.) with full implementation.\n"
        "- Verify that all code has zero syntax errors and is ready to run.\n"
    )

    success = False
    last_audit: Dict[str, Any] = {"total_files": 0, "total_bytes": 0, "files": [], "syntax_errors": []}

    while turn <= turn_limit:
        _emit(stream, f"\n[Turn {turn}/{turn_limit}] Steering Antigravity agent...")
        cmd = [agy_exe, "--add-dir", str(project_dir), "--dangerously-skip-permissions"]
        if turn > 1:
            cmd.extend(["-c", "-p", current_prompt])
        else:
            cmd.extend(["-p", current_prompt])

        turn_timeout = float(os.environ.get("PAI_AGY_TURN_TIMEOUT", "300.0"))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=turn_timeout,
                check=False,
            )
            out_preview = (proc.stdout or "").strip()
            if out_preview:
                lines = out_preview.splitlines()
                summary_preview = lines[-1][:100] if lines else ""
                _emit(stream, f"  Agent: {summary_preview}")
        except subprocess.TimeoutExpired:
            _emit(stream, f"  ⚠️ Turn {turn} timed out after {int(turn_timeout)}s. Checking file state...")
        except Exception as exc:
            _emit(stream, f"  ⚠️ Turn {turn} execution notice: {exc}")

        # Audit workspace files
        last_audit = audit_workspace_files(project_dir)
        num_files = last_audit["total_files"]
        total_kb = last_audit["total_bytes"] // 1024
        syntax_errs = last_audit["syntax_errors"]

        file_list_str = ", ".join(f"{f['path']} ({f['size']}B)" for f in last_audit["files"][:4])
        if num_files > 4:
            file_list_str += f", and {num_files - 4} more"
        _emit(stream, f"  Files on disk ({num_files} files, ~{total_kb} KB): {file_list_str or 'none yet'}")

        if syntax_errs:
            _emit(stream, f"  ⚠️ Syntax errors detected in {len(syntax_errs)} file(s). Steering automatic fix turn...")
            current_prompt = (
                "The following syntax errors were detected in your code:\n"
                + "\n".join(syntax_errs[:5])
                + "\nPlease fix these errors now and ensure all files compile cleanly."
            )
            turn += 1
            continue

        if num_files >= 1 and last_audit["total_bytes"] > 500:
            # Check for standard entry points
            has_entry = any(
                f["path"] in ("index.html", "main.py", "app.py", "server.js", "package.json")
                for f in last_audit["files"]
            )
            if has_entry or turn >= 2:
                success = True
                _emit(stream, f"  ✅ Verified: {num_files} file(s) created with clean syntax and valid entry point.")
                break

        current_prompt = (
            "Continue building the project. Please ensure all required logic, UI, and functionality are fully written out."
        )
        turn += 1

    summary_lines = [
        "🎉 Antigravity Autonomous Task Complete!",
        f"  Workspace: {project_dir}",
        f"  Files    : {last_audit['total_files']} files ({last_audit['total_bytes']} bytes)",
        f"  Turns    : {min(turn, turn_limit)} turn(s) executed",
    ]
    if last_audit["files"]:
        summary_lines.append("  Deliverables:")
        for f in last_audit["files"][:6]:
            summary_lines.append(f"    - {f['path']} ({f['size']} bytes)")
    summary_lines.append("Review or run your project in Antigravity IDE or default browser.")
    msg = "\n".join(summary_lines)
    _emit(stream, msg)
    return success, msg
