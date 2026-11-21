"""PAI Cowork Workstation Engine.

Implements Anthropic's flagship Cowork paradigm:
  1. Dispatch Orchestrator:
     - User-facing, responsive coordinator ('texting, not writing a report').
     - Directs complex or long-running work to dedicated Task Sessions via start_task.
     - Separates internal scratchpad execution from user-facing SendUserMessage envelopes.
  2. Connected Folders Bridge:
     - Mounts local directories into the workspace context.
     - Resolves computer:// links to local host files.
  3. Persistent Task Registry & Artifact Deliverables:
     - Manages multi-step task checklists with verification gates.
     - Delivers completed files, diffs, and reports as download cards.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class CoworkTask:
    task_id: str
    title: str
    goal: str
    workspace_dir: str
    status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    checklist: List[Dict[str, Any]] = field(default_factory=list)
    deliverables: List[Dict[str, str]] = field(default_factory=list)  # [{'name': ..., 'path': ..., 'type': ...}]
    transcript: List[Dict[str, Any]] = field(default_factory=list)
    result_summary: str = ""
    error_message: Optional[str] = None


@dataclass
class ConnectedFolder:
    folder_id: str
    name: str
    host_path: str
    is_writable: bool = True
    added_at: float = field(default_factory=time.time)


class ConnectedFoldersManager:
    """Manages mounted local directories for PAI Cowork sessions."""

    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            base = Path.home() / ".pai" / "cowork"
            base.mkdir(parents=True, exist_ok=True)
            config_path = base / "connected_folders.json"
        self.config_path = config_path
        self._folders: Dict[str, ConnectedFolder] = self._load()

    def _load(self) -> Dict[str, ConnectedFolder]:
        if not self.config_path.is_file():
            return {}
        try:
            raw = json.loads(self.config_path.read_text(encoding="utf-8"))
            return {k: ConnectedFolder(**v) for k, v in raw.items()}
        except Exception:
            return {}

    def _save(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        raw = {k: asdict(v) for k, v in self._folders.items()}
        self.config_path.write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")

    def connect_folder(self, host_path: str, name: Optional[str] = None) -> ConnectedFolder:
        """Mounts a local folder into the Cowork environment."""
        p = Path(host_path).resolve()
        if not p.is_dir():
            raise FileNotFoundError(f"Folder path does not exist or is not a directory: {host_path}")

        folder_name = name or p.name or "workspace"
        clean_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", folder_name.lower())

        folder = ConnectedFolder(
            folder_id=clean_id,
            name=folder_name,
            host_path=str(p),
            is_writable=True,
            added_at=time.time(),
        )
        self._folders[clean_id] = folder
        self._save()
        return folder

    def disconnect_folder(self, folder_id: str) -> bool:
        """Unmounts a connected folder."""
        if folder_id in self._folders:
            del self._folders[folder_id]
            self._save()
            return True
        return False

    def list_folders(self) -> List[ConnectedFolder]:
        return list(self._folders.values())

    def resolve_computer_link(self, computer_url: str) -> Optional[Path]:
        """Resolves `computer://<folder_id>/<subpath>` to absolute host path."""
        m = re.match(r"^computer://([^/]+)(?:/(.*))?$", computer_url.strip())
        if not m:
            return None
        folder_id, subpath = m.group(1), m.group(2) or ""
        folder = self._folders.get(folder_id)
        if not folder:
            return None

        target = (Path(folder.host_path) / subpath).resolve()
        # Ensure path does not escape the connected root directory
        try:
            target.relative_to(Path(folder.host_path).resolve())
            return target
        except ValueError:
            return None


class CoworkOrchestrator:
    """Dispatch Orchestrator coordinating user interaction and background task sessions."""

    def __init__(self, workspace_path: Optional[str] = None):
        self.workspace_path = workspace_path
        self.folders_manager = ConnectedFoldersManager()
        self.storage_dir = Path.home() / ".pai" / "cowork" / "tasks"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._tasks: Dict[str, CoworkTask] = self._load_tasks()

    def _load_tasks(self) -> Dict[str, CoworkTask]:
        tasks: Dict[str, CoworkTask] = {}
        for f in self.storage_dir.glob("task_*.json"):
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
                tasks[d["task_id"]] = CoworkTask(**d)
            except Exception:
                pass
        return tasks

    def _save_task(self, task: CoworkTask) -> None:
        target = self.storage_dir / f"task_{task.task_id}.json"
        target.write_text(json.dumps(asdict(task), indent=2, ensure_ascii=False), encoding="utf-8")

    def start_task(
        self,
        title: str,
        goal: str,
        workspace_dir: Optional[str] = None,
        checklist_items: Optional[List[str]] = None,
    ) -> CoworkTask:
        """Spawns a new Cowork task session."""
        tid = uuid.uuid4().hex[:10]
        ws = workspace_dir or self.workspace_path or str(Path.cwd())

        checklist = []
        if checklist_items:
            for i, item in enumerate(checklist_items):
                checklist.append({"id": i + 1, "task": item, "completed": False})
        else:
            checklist = [
                {"id": 1, "task": "Analyze requirements & workspace context", "completed": False},
                {"id": 2, "task": "Execute code synthesis & modifications", "completed": False},
                {"id": 3, "task": "Run verification & tests", "completed": False},
            ]

        task = CoworkTask(
            task_id=tid,
            title=title.strip(),
            goal=goal.strip(),
            workspace_dir=ws,
            status="RUNNING",
            checklist=checklist,
            transcript=[
                {
                    "timestamp": time.time(),
                    "sender": "Dispatch",
                    "content": f"Task session '{title}' dispatched to worker.",
                }
            ],
        )

        self._tasks[tid] = task
        self._save_task(task)
        return task

    def update_task_progress(
        self,
        task_id: str,
        message: str,
        sender: str = "Worker",
        completed_step_id: Optional[int] = None,
    ) -> bool:
        """Appends an event to task transcript and updates checklist."""
        task = self._tasks.get(task_id)
        if not task:
            return False

        task.updated_at = time.time()
        task.transcript.append({
            "timestamp": time.time(),
            "sender": sender,
            "content": message,
        })

        if completed_step_id is not None:
            for item in task.checklist:
                if item.get("id") == completed_step_id:
                    item["completed"] = True

        self._save_task(task)
        return True

    def complete_task(
        self,
        task_id: str,
        summary: str,
        deliverables: Optional[List[Dict[str, str]]] = None,
    ) -> bool:
        """Marks task as completed and saves deliverables."""
        task = self._tasks.get(task_id)
        if not task:
            return False

        task.status = "COMPLETED"
        task.updated_at = time.time()
        task.result_summary = summary
        if deliverables:
            task.deliverables.extend(deliverables)

        for item in task.checklist:
            item["completed"] = True

        task.transcript.append({
            "timestamp": time.time(),
            "sender": "Worker",
            "content": f"Task completed successfully: {summary}",
        })

        self._save_task(task)
        return True

    def generate_author_handoff(
        self,
        task_id: str,
        decisions: List[str],
        risks: List[str],
        verified_commands: List[str],
    ) -> Optional[str]:
        """Generates a Cursor-style author handoff artifact for code review.

        Sections:
          <decision>: Why this architectural shape and alternatives set aside.
          <risk>: What a reviewer/engineer should be careful about.
          <verified>: Exact tests and commands executed with runtime evidence.
        """
        task = self._tasks.get(task_id)
        if not task:
            return None

        handoff_md = [
            f"# Code Tour & Author Handoff: {task.title}",
            "",
            "<decision>",
            "Architectural Decisions:",
        ]
        for d in decisions:
            handoff_md.append(f"- {d}")
        handoff_md.extend([
            "</decision>",
            "",
            "<risk>",
            "Reviewer & Runtime Considerations:",
        ])
        for r in risks:
            handoff_md.append(f"- {r}")
        handoff_md.extend([
            "</risk>",
            "",
            "<verified>",
            "Commands & Verification Executed:",
        ])
        for v in verified_commands:
            handoff_md.append(f"- `{v}`")
        handoff_md.extend([
            "</verified>",
            "",
        ])

        handoff_text = "\n".join(handoff_md)
        handoff_path = self.storage_dir / f"{task_id}-author-handoff.md"
        handoff_path.write_text(handoff_text, encoding="utf-8")

        # Add as deliverable
        task.deliverables.append({
            "name": "code-tour-author-handoff.md",
            "path": str(handoff_path),
            "type": "handoff",
        })
        self._save_task(task)
        return handoff_text

    def list_tasks(self, limit: int = 15) -> List[CoworkTask]:
        """Returns sorted list of most recent tasks."""
        return sorted(self._tasks.values(), key=lambda t: t.updated_at, reverse=True)[:limit]

    def get_task(self, task_id: str) -> Optional[CoworkTask]:
        return self._tasks.get(task_id)

    def format_cowork_dispatch_reply(self, message: str, task: Optional[CoworkTask] = None) -> Dict[str, Any]:
        """Encapsulates output in Anthropic SendUserMessage format."""
        envelope: Dict[str, Any] = {
            "type": "SendUserMessage",
            "message": message,
            "timestamp": time.time(),
        }
        if task:
            envelope["task"] = {
                "id": task.task_id,
                "title": task.title,
                "status": task.status,
                "checklist": task.checklist,
                "deliverables": task.deliverables,
            }
        return envelope
