"""Antigravity Autonomous Driver & Continuous Task Supervisor for PAI.

Orchestrates Google Antigravity IDE and headless `agy` CLI agent execution:
  - Discovers `agy.exe` and `Antigravity IDE.exe` on host.
  - Automatically provisions project workspaces under `~/Documents/GitHub/pai_projects/`.
  - Injects structured task blueprints (`AGY_TASK.md`) and milestones.
  - Launches the visual Antigravity IDE GUI for live monitoring.
  - Steers `agy` within the provisioned workspace with ToolBroker confirmation gating.
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
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from research import ingest
    from research.capabilities import (
        Grant,
        PermissionDenied,
        Risk,
        Tool,
        ToolBroker,
        ToolRequest,
    )
except ModuleNotFoundError:
    import ingest
    from capabilities import (
        Grant,
        PermissionDenied,
        Risk,
        Tool,
        ToolBroker,
        ToolRequest,
    )


def make_antigravity_broker(
    base_dir: Path,
    confirm: Optional[Callable[[ToolRequest], bool]] = None,
    max_calls: Optional[int] = None,
    expires: Optional[float] = None,
) -> ToolBroker:
    """Constructs a scoped ToolBroker governing Antigravity execution with Risk.DESTRUCTIVE."""
    root_real = os.path.realpath(os.path.abspath(str(base_dir)))
    tool = Tool(
        "antigravity_run",
        Risk.DESTRUCTIVE,
        lambda prompt="", base_dir="": True,
        path_args=("base_dir",),
    )
    grant = Grant(
        "antigravity_run",
        roots=(root_real,),
        expires=expires,
        max_calls=max_calls,
    )
    return ToolBroker(tools=[tool], grants=[grant], confirm=confirm)


def _is_contained_regular_file(path: Path, canonical_root: Path) -> bool:
    """Returns True only if `path` is a non-symlink regular file contained inside `canonical_root`."""
    try:
        root_real = Path(os.path.realpath(os.path.abspath(str(canonical_root))))
        p_str = str(path)
        if not os.path.lexists(p_str):
            return False
        if path.is_symlink() or ingest._is_symlink_or_reparse(p_str):
            return False
        if ingest.has_ads_colon(p_str) or ingest.is_reserved_device_name(path.name):
            return False
        try:
            rel = path.relative_to(canonical_root)
            cur = canonical_root
            for part in rel.parts[:-1]:
                if part in ("", ".", ".."):
                    return False
                cur = cur / part
                if os.path.lexists(str(cur)) and ingest._is_symlink_or_reparse(str(cur)):
                    return False
        except ValueError:
            pass
        resolved = Path(os.path.realpath(os.path.abspath(p_str)))
        if not resolved.is_relative_to(root_real) or resolved == root_real:
            return False
        if ingest._is_symlink_or_reparse(str(resolved)):
            return False
        return resolved.is_file()
    except Exception:
        return False


def _is_safe_relative_asset_ref(ref: str) -> bool:
    """Validates a local HTML src/href reference before joining with project_dir."""
    if not ref or any(ord(c) < 32 or ord(c) == 127 for c in ref):
        return False
    clean = ref.split("?", 1)[0].split("#", 1)[0].strip()
    if not clean or "\\" in clean or clean.startswith("/"):
        return False
    if ingest.has_ads_colon(clean):
        return False
    if Path(clean).is_absolute() or PureWindowsPath(clean).is_absolute():
        return False
    if len(clean) >= 2 and clean[1] == ":":
        return False
    parts = clean.split("/")
    if any(part in ("..", "") for part in parts):
        return False
    return True


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
    if os.path.lexists(str(root)) and ingest._is_symlink_or_reparse(str(root)):
        raise PermissionDenied("Workspace base_dir cannot be a symlink or reparse point")
    root_real = Path(os.path.realpath(os.path.abspath(str(root))))
    slug = slugify_task_name(task_name)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    project_dir = root_real / f"{slug}_{timestamp}"
    project_dir.mkdir(parents=True, exist_ok=True)
    if ingest._is_symlink_or_reparse(str(project_dir)) or not Path(os.path.realpath(str(project_dir))).is_relative_to(root_real):
        raise PermissionDenied("Provisioned workspace failed canonical containment check")

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
    task_file = project_dir / "AGY_TASK.md"
    if os.path.lexists(str(task_file)) and ingest._is_symlink_or_reparse(str(task_file)):
        raise PermissionDenied("AGY_TASK.md cannot be a symlink or reparse point")
    task_file.write_text(blueprint, encoding="utf-8")
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
    """Scan the workspace, checking created files, sizes, syntax validity, and referenced assets."""
    files: List[Dict[str, Any]] = []
    syntax_errors: List[str] = []
    missing_references: List[str] = []
    stub_files: List[str] = []

    if (
        project_dir is None
        or not os.path.lexists(str(project_dir))
        or ingest._is_symlink_or_reparse(str(project_dir))
        or not project_dir.is_dir()
    ):
        return {
            "files": files,
            "total_files": 0,
            "total_bytes": 0,
            "syntax_errors": syntax_errors,
            "missing_references": missing_references,
            "stub_files": stub_files,
            "has_script_logic": False,
            "has_style_sheet": False,
        }

    canonical_root = Path(os.path.realpath(os.path.abspath(str(project_dir))))

    for p in project_dir.rglob("*"):
        if (
            not p.name.startswith((".", "AGY_TASK.md"))
            and "__pycache__" not in p.parts
            and not p.name.endswith((".pyc", ".pyo"))
            and _is_contained_regular_file(p, canonical_root)
        ):
            try:
                rel = str(p.relative_to(project_dir)).replace("\\", "/")
                size = p.stat().st_size
                files.append({"path": rel, "size": size})

                # Check for tiny stub files
                if size < 120 and rel not in ("style.css", "AGY_TASK.md"):
                    stub_files.append(rel)

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

    # Inspect index.html for linked local scripts and stylesheets
    entry_html = project_dir / "index.html"
    has_script_logic = False
    has_style_sheet = False
    if _is_contained_regular_file(entry_html, canonical_root):
        try:
            html_text = entry_html.read_text(encoding="utf-8", errors="replace")
            # Extract script src
            for m in re.finditer(r'<script\b[^>]*\bsrc=["\']([^"\']+)["\']', html_text, re.IGNORECASE):
                src = m.group(1).strip()
                if not src.startswith(("http://", "https://", "//", "data:")):
                    clean_src = src.split("?", 1)[0].split("#", 1)[0].strip()
                    if not _is_safe_relative_asset_ref(src):
                        missing_references.append(src)
                        continue
                    target_file = canonical_root.joinpath(*clean_src.split("/"))
                    if not _is_contained_regular_file(target_file, canonical_root) or target_file.stat().st_size == 0:
                        missing_references.append(src)
                    else:
                        has_script_logic = True

            # Extract link href
            for m in re.finditer(r'<link\b[^>]*\bhref=["\']([^"\']+)["\']', html_text, re.IGNORECASE):
                href = m.group(1).strip()
                if not href.startswith(("http://", "https://", "//", "data:")):
                    clean_href = href.split("?", 1)[0].split("#", 1)[0].strip()
                    if not _is_safe_relative_asset_ref(href):
                        missing_references.append(href)
                        continue
                    target_file = canonical_root.joinpath(*clean_href.split("/"))
                    if not _is_contained_regular_file(target_file, canonical_root) or target_file.stat().st_size == 0:
                        missing_references.append(href)
                    else:
                        has_style_sheet = True

            if "<script" in html_text.lower() and len(html_text) > 800:
                has_script_logic = True
        except Exception:
            pass

    if any(f["path"].endswith(".js") and f["size"] > 150 for f in files):
        has_script_logic = True
    if any(f["path"].endswith(".css") and f["size"] > 80 for f in files):
        has_style_sheet = True

    return {
        "files": files,
        "total_files": len(files),
        "total_bytes": sum(f["size"] for f in files),
        "syntax_errors": syntax_errors,
        "missing_references": missing_references,
        "stub_files": stub_files,
        "has_script_logic": has_script_logic,
        "has_style_sheet": has_style_sheet,
    }


def run_antigravity_continuous_task(
    prompt: str,
    stream: Any = sys.stdout,
    max_turns: int = 10,
    open_ide: bool = True,
    open_browser: bool = True,
    executor: Optional[Callable[[List[str]], int]] = None,
    base_dir: Optional[Path] = None,
    broker: Optional[ToolBroker] = None,
    confirm: Optional[Callable[[ToolRequest], bool]] = None,
    tainted: bool = False,
    require_broker: bool = False,
) -> Tuple[bool, str]:
    """Autonomously drive Antigravity IDE and `agy` agent until task completion."""
    raw = (prompt or "").strip()
    if not raw:
        return False, "Prompt cannot be empty for Antigravity autonomous development."

    raw_base = base_dir or Path(
        os.environ.get("PAI_PROJECTS_DIR", str(Path.home() / "Documents" / "GitHub" / "pai_projects"))
    )
    if os.path.lexists(str(raw_base)) and ingest._is_symlink_or_reparse(str(raw_base)):
        raise PermissionDenied("Workspace base_dir cannot be a symlink or reparse point")
    resolved_base = Path(os.path.realpath(os.path.abspath(str(raw_base))))

    if broker is not None:
        broker.invoke(
            "antigravity_run",
            {"prompt": raw, "base_dir": str(resolved_base)},
            tainted=bool(tainted),
        )
    elif confirm is not None:
        req = ToolRequest(
            "antigravity_run",
            Risk.DESTRUCTIVE,
            raw[:200],
            bool(tainted),
            "autonomous Antigravity execution requires human confirmation",
        )
        try:
            approved = bool(confirm(req))
        except Exception as exc:
            raise PermissionDenied(f"Antigravity confirmation failed: {exc}") from exc
        if not approved:
            raise PermissionDenied("Antigravity execution declined by confirmation")
    elif require_broker or tainted:
        raise PermissionDenied("Antigravity execution requires ToolBroker or human confirmation when governed or tainted")

    _emit(stream, "🚀 Initializing Antigravity Autonomous Bridge...")
    agy_exe, ide_exe = find_antigravity_binaries()

    # Step 1: Provision Workspace
    project_dir = create_project_workspace(raw, base_dir=resolved_base)
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
    turn_limit = max(2, min(max_turns, int(os.environ.get("PAI_AGY_MAX_TURNS", "12"))))
    turn = 1
    current_prompt = (
        f"You are working in the workspace '{project_dir}'.\n"
        f"Goal: {raw}\n\n"
        "Milestone 1: Project Architecture & Entrypoint\n"
        "- Create 'index.html' with full semantic structure, viewport meta, canvas or UI container.\n"
        "- Include proper <link rel=\"stylesheet\" href=\"style.css\"> in <head>.\n"
        "- Include <script src=\"script.js\"></script> before </body>.\n"
        "- Ensure HTML contains necessary HUD elements (score, controls help, reset button).\n"
        "Do not leave empty stubs. Write clean, complete code."
    )

    success = False
    last_audit: Dict[str, Any] = {
        "total_files": 0,
        "total_bytes": 0,
        "files": [],
        "syntax_errors": [],
        "missing_references": [],
        "has_script_logic": False,
        "has_style_sheet": False,
    }

    while turn <= turn_limit:
        _emit(stream, f"\n[Turn {turn}/{turn_limit}] Steering Antigravity agent...")
        cmd = [agy_exe, "--add-dir", str(project_dir)]
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
        missing_refs = last_audit["missing_references"]
        has_logic = last_audit["has_script_logic"]

        file_list_str = ", ".join(f"{f['path']} ({f['size']}B)" for f in last_audit["files"][:4])
        if num_files > 4:
            file_list_str += f", and {num_files - 4} more"
        _emit(stream, f"  Files on disk ({num_files} files, ~{total_kb} KB): {file_list_str or 'none yet'}")

        # 1. If syntax errors exist, prioritize self-healing
        if syntax_errs:
            _emit(stream, f"  ⚠️ Syntax errors detected in {len(syntax_errs)} file(s). Steering automatic fix turn...")
            current_prompt = (
                "The following syntax errors were detected in your code:\n"
                + "\n".join(syntax_errs[:5])
                + "\nPlease fix these errors now and ensure all files compile cleanly."
            )
            turn += 1
            continue

        # 2. If referenced files are missing from disk, prompt to create them
        if missing_refs:
            _emit(stream, f"  ⚠️ Missing referenced file(s): {', '.join(missing_refs)}. Prompting agent to create them...")
            current_prompt = (
                f"The following files are referenced in your project but are missing from disk:\n"
                + "\n".join(f"- {ref}" for ref in missing_refs)
                + f"\nPlease create and fully implement these files now for '{raw}'."
            )
            turn += 1
            continue

        # 3. Check for completeness
        has_entry = any(
            f["path"] in ("index.html", "main.py", "app.py", "server.js")
            for f in last_audit["files"]
        )
        is_substantive = last_audit["total_bytes"] >= 1500 or (
            num_files >= 2 and last_audit["total_bytes"] >= 800
        )

        if has_entry and is_substantive and has_logic and turn >= 2:
            success = True
            _emit(stream, f"  ✅ Verified: {num_files} file(s) created with complete logic, zero syntax errors, and resolved references.")
            break

        # 4. Steering next milestone if not yet complete
        if not has_logic:
            current_prompt = (
                f"Milestone 2: Complete Application & Game Logic\n"
                f"Now create and implement 'script.js' with the full implementation of '{raw}'.\n"
                "Include:\n"
                "- Full game/application loop and canvas or DOM rendering.\n"
                "- Complete event listeners for keyboard, mouse/touch controls.\n"
                "- Built-in Web Audio API sound effects (laser sound, explosion, game over, chime) so no external files are needed.\n"
                "- State management (start screen, playing state, game over, score counter).\n"
                "Write the complete functional implementation without stubs."
            )
        elif not last_audit["has_style_sheet"]:
            current_prompt = (
                "Milestone 3: Visual Styling & HUD Design\n"
                "Now create and implement 'style.css' with sleek modern styling:\n"
                "- Dark theme (#0d1117 / #161b22), glowing neon accents, clean typography.\n"
                "- Centered responsive canvas layout.\n"
                "- Sleek HUD overlay for score, health, controls badges."
            )
        else:
            current_prompt = (
                "Final Polish & Verification Turn:\n"
                "Review all files in the workspace. Ensure all controls are responsive, game loop restarts cleanly on game over, and code compiles without errors."
            )

        turn += 1

    # Optional: Automatically open index.html in browser so user immediately sees the running project
    if success and open_browser:
        canonical_project = Path(os.path.realpath(os.path.abspath(str(project_dir))))
        entry_html = project_dir / "index.html"
        if _is_contained_regular_file(entry_html, canonical_project):
            try:
                import webbrowser
                webbrowser.open(entry_html.resolve().as_uri(), new=2)
                _emit(stream, f"🌐 Opened live preview in default browser: {entry_html.name}")
            except Exception:
                pass

    summary_lines = [
        "🎉 Antigravity Autonomous Task Complete!",
        f"  Workspace: {project_dir}",
        f"  Files    : {last_audit['total_files']} files ({last_audit['total_bytes']} bytes)",
        f"  Turns    : {min(turn, turn_limit)} turn(s) executed",
    ]
    if last_audit["files"]:
        summary_lines.append("  Deliverables:")
        for f in last_audit["files"][:8]:
            summary_lines.append(f"    - {f['path']} ({f['size']} bytes)")
    summary_lines.append("Review or run your project in Antigravity IDE or default browser.")
    msg = "\n".join(summary_lines)
    _emit(stream, msg)
    return success, msg
