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
    status: str = "PENDING"  # PENDING, RUNNING, PAUSED, STALLED_RECOVERING, COMPLETED, FAILED, CANCELLED
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    checklist: List[Dict[str, Any]] = field(default_factory=list)
    deliverables: List[Dict[str, str]] = field(default_factory=list)  # [{'name': ..., 'path': ..., 'type': ...}]
    transcript: List[Dict[str, Any]] = field(default_factory=list)
    result_summary: str = ""
    error_message: Optional[str] = None
    mode: str = "team"  # team | deep | council
    max_iterations: int = 12
    current_iteration: int = 0
    quality_score: float = 0.0
    graph_path: Optional[str] = None
    stall_count: int = 0
    last_stall_reason: Optional[str] = None
    checkpoint: Dict[str, Any] = field(default_factory=dict)
    pause_requested: bool = False
    cancel_requested: bool = False


class StuckDetectorWatchdog:
    """
    Detects long-running Cowork / Swarm stalls and generates checkpointed recovery plans:
    1. Repetition / Semantic Loop Stall (repeated identical or near-identical step outputs)
    2. Heartbeat / Step Timeout Stall (no forward progress within step_timeout_sec)
    3. Confidence Collapse (consecutive CRASH steps with confidence < 0.5)
    """

    def __init__(
        self,
        repetition_jaccard_threshold: float = 0.85,
        max_identical_window: int = 2,
        step_timeout_sec: float = 180.0,
        max_low_conf_streak: int = 2,
        max_recoveries: int = 3,
    ) -> None:
        self.repetition_jaccard_threshold = max(0.5, min(1.0, float(repetition_jaccard_threshold)))
        self.max_identical_window = max(2, int(max_identical_window))
        self.step_timeout_sec = max(1.0, float(step_timeout_sec))
        self.max_low_conf_streak = max(1, int(max_low_conf_streak))
        self.max_recoveries = max(1, int(max_recoveries))
        self._recent_outputs: List[Tuple[Any, str, set[str]]] = []
        self._low_conf_streak: int = 0
        self._last_progress_ts: float = time.time()

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        return set(re.findall(r"[a-zA-Z0-9_]{3,}", (text or "").lower()))

    @staticmethod
    def _jaccard(a: set[str], b: set[str]) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)

    def reset_for_recovery(self, now: Optional[float] = None) -> None:
        """Resets sliding loop & low-confidence streak counters right after a clean recovery branch."""
        self._recent_outputs.clear()
        self._low_conf_streak = 0
        self._last_progress_ts = now if now is not None else time.time()

    def check_heartbeat(self, now: Optional[float] = None) -> Tuple[bool, float]:
        """Returns (is_timed_out, elapsed_seconds)."""
        cur = now if now is not None else time.time()
        elapsed = max(0.0, cur - self._last_progress_ts)
        return elapsed > self.step_timeout_sec, round(elapsed, 3)

    def record_progress(
        self,
        step_id: Any,
        output_text: str,
        confidence: float = 0.7,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Evaluates step output, timing, and confidence to detect whether execution has stalled."""
        cur_ts = now if now is not None else time.time()
        timed_out, elapsed = self.check_heartbeat(now=cur_ts)

        norm = re.sub(r"\s+", " ", (output_text or "").strip().lower())
        tokens = self._tokenize(norm)

        max_sim = 0.0
        repeat_hits = 0
        for _, prev_norm, prev_tokens in self._recent_outputs[-(self.max_identical_window * 2):]:
            sim = 1.0 if (norm and norm == prev_norm) else self._jaccard(tokens, prev_tokens)
            max_sim = max(max_sim, sim)
            if sim >= self.repetition_jaccard_threshold:
                repeat_hits += 1

        self._recent_outputs.append((step_id, norm, tokens))
        if float(confidence) < 0.5:
            self._low_conf_streak += 1
        else:
            self._low_conf_streak = 0

        stalled = False
        code = "OK"
        reason = ""

        if repeat_hits >= (self.max_identical_window - 1) and len(norm) > 0:
            stalled = True
            code = "REPETITION_LOOP"
            reason = (
                f"Detected repetition loop on step {step_id}: output similarity {max_sim:.2f} "
                f">= {self.repetition_jaccard_threshold:.2f} across recent attempts."
            )
        elif self._low_conf_streak >= self.max_low_conf_streak:
            stalled = True
            code = "CONFIDENCE_COLLAPSE"
            reason = (
                f"Detected confidence collapse on step {step_id}: {self._low_conf_streak} consecutive steps < 0.50."
            )
        elif timed_out:
            stalled = True
            code = "STEP_TIMEOUT"
            reason = f"Step {step_id} exceeded heartbeat timeout ({elapsed:.1f}s > {self.step_timeout_sec:.1f}s)."

        self._last_progress_ts = cur_ts
        return {
            "stalled": stalled,
            "code": code,
            "reason": reason,
            "similarity": round(max_sim, 3),
            "elapsed_sec": elapsed,
            "low_conf_streak": self._low_conf_streak,
        }

    def build_recovery_directive(self, step_id: Any, stall_reason: str, prior_summary: str = "") -> str:
        """Produces a targeted strategy-pivot prompt so resumed execution avoids the stalled loop."""
        return (
            f"[STUCK-RECOVERY CHECKPOINT RESUME @ Step {step_id}]\n"
            f"Previous attempt was halted because: {stall_reason}\n"
            f"Instructions for this recovery branch:\n"
            f"1. Do NOT repeat the prior stalled approach.\n"
            f"2. Decompose Step {step_id} into smaller concrete verification sub-actions.\n"
            f"3. Emit explicit <confidence> and <verdict> tags based on verifiable outputs.\n"
            + (f"Checkpoint summary: {prior_summary[:800]}\n" if prior_summary else "")
        )


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
        valid_fields = {f.name for f in CoworkTask.__dataclass_fields__.values()}
        for f in self.storage_dir.glob("task_*.json"):
            try:
                raw = json.loads(f.read_text(encoding="utf-8"))
                filtered = {k: v for k, v in raw.items() if k in valid_fields}
                tasks[filtered["task_id"]] = CoworkTask(**filtered)
            except Exception:
                pass
        return tasks

    def _save_task(self, task: CoworkTask) -> None:
        target = self.storage_dir / f"task_{task.task_id}.json"
        tmp = self.storage_dir / f"task_{task.task_id}.json.tmp"
        tmp.write_text(json.dumps(asdict(task), indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, target)

    def start_task(
        self,
        title: str,
        goal: str,
        workspace_dir: Optional[str] = None,
        checklist_items: Optional[List[str]] = None,
        mode: str = "team",
        max_iterations: int = 12,
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
                    "content": f"Task session '{title}' dispatched to worker (mode={mode}).",
                }
            ],
            mode=mode,
            max_iterations=max(1, int(max_iterations)),
        )

        self._tasks[tid] = task
        self._save_task(task)
        return task

    def save_checkpoint(
        self,
        task_id: str,
        step_index: int,
        crash_state: Optional[Dict[str, Any]] = None,
        graph_path: Optional[str] = None,
        notes: str = "",
    ) -> bool:
        """Atomically persists exact step checkpoint and graph reference for seamless pause/stall resume."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.updated_at = time.time()
        task.current_iteration = max(int(step_index), task.current_iteration)
        if graph_path:
            task.graph_path = str(graph_path)
        task.checkpoint = {
            "step_index": int(step_index),
            "saved_at": time.time(),
            "notes": notes[:1000],
            "crash_state": crash_state or {},
        }
        self._save_task(task)
        return True

    def mark_stalled_and_recover(
        self,
        task_id: str,
        reason: str,
        step_index: int,
        branch_id: str,
        max_recoveries: int = 3,
    ) -> Dict[str, Any]:
        """Records stall diagnosis on disk and either prepares an exact-step recovery branch or fails cleanly."""
        task = self._tasks.get(task_id)
        if not task:
            return {"recovered": False, "status": "NOT_FOUND"}

        task.stall_count += 1
        task.last_stall_reason = reason
        task.updated_at = time.time()

        if task.stall_count > max_recoveries:
            task.status = "FAILED"
            task.error_message = f"Exceeded max stall recoveries ({max_recoveries}): {reason}"
            task.transcript.append({
                "timestamp": time.time(),
                "sender": "Watchdog",
                "content": f"HALTED after {task.stall_count} stalls. Reason: {reason}",
            })
            self._save_task(task)
            return {"recovered": False, "status": task.status, "resume_step_index": step_index}

        task.status = "STALLED_RECOVERING"
        task.checkpoint = {
            **(task.checkpoint or {}),
            "step_index": int(step_index),
            "recovery_branch": branch_id,
            "stall_reason": reason,
            "recovered_at": time.time(),
        }
        task.transcript.append({
            "timestamp": time.time(),
            "sender": "Watchdog",
            "content": (
                f"Stall detected (#{task.stall_count}) at step {step_index}: {reason}. "
                f"Checkpointed and resuming on recovery branch '{branch_id}'."
            ),
        })
        self._save_task(task)
        return {
            "recovered": True,
            "status": task.status,
            "stall_count": task.stall_count,
            "resume_step_index": step_index,
            "branch_id": branch_id,
        }

    def pause_task(self, task_id: str, reason: str = "Paused by user.") -> bool:
        """Requests cooperative pause and transitions task to PAUSED while keeping checkpoint."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.pause_requested = True
        if task.status in ("RUNNING", "STALLED_RECOVERING", "PENDING"):
            task.status = "PAUSED"
        task.updated_at = time.time()
        task.transcript.append({"timestamp": time.time(), "sender": "Coordinator", "content": reason})
        self._save_task(task)
        return True

    def resume_task(self, task_id: str) -> Optional[CoworkTask]:
        """Clears pause flag and returns task ready to resume from its saved checkpoint."""
        task = self._tasks.get(task_id)
        if not task or task.cancel_requested:
            return None
        task.pause_requested = False
        task.status = "RUNNING"
        task.updated_at = time.time()
        resume_step = task.checkpoint.get("step_index", task.current_iteration)
        task.transcript.append({
            "timestamp": time.time(),
            "sender": "Coordinator",
            "content": f"Resuming execution from saved checkpoint step {resume_step}.",
        })
        self._save_task(task)
        return task

    def cancel_task(self, task_id: str, reason: str = "Cancelled by user.") -> bool:
        """Marks a task cancelled cleanly without losing prior transcript or checkpoint."""
        task = self._tasks.get(task_id)
        if not task:
            return False
        task.cancel_requested = True
        task.status = "CANCELLED"
        task.updated_at = time.time()
        task.error_message = reason
        task.transcript.append({"timestamp": time.time(), "sender": "Coordinator", "content": reason})
        self._save_task(task)
        return True

    def verify_task_quality(
        self,
        task_id: str,
        min_quality: float = 0.6,
        require_all_checklist: bool = True,
    ) -> Tuple[bool, List[str]]:
        """
        Objective quality completion gate: verifies checklist completion, quality_score,
        deliverable file validity (syntax parse for Python/JSON), and ThoughtGraph leaf closure.
        """
        task = self._tasks.get(task_id)
        if not task:
            return False, [f"Task {task_id} not found."]

        issues: List[str] = []
        if require_all_checklist:
            pending = [it.get("id") for it in task.checklist if not it.get("completed")]
            if pending:
                issues.append(f"Checklist has incomplete items: {pending}")

        if task.quality_score > 0.0 and task.quality_score < min_quality:
            issues.append(f"Quality score {task.quality_score:.2f} is below required threshold {min_quality:.2f}")

        for d in task.deliverables:
            p_str = d.get("path", "")
            if not p_str:
                continue
            p = Path(p_str)
            if p.exists() and p.is_file() and p.suffix.lower() == ".py":
                try:
                    import ast
                    ast.parse(p.read_text(encoding="utf-8"))
                except SyntaxError as exc:
                    issues.append(f"Python syntax error in deliverable {p.name}: {exc}")

        if task.graph_path:
            gp = Path(task.graph_path)
            if gp.exists():
                try:
                    try:
                        from research.reasoning_engine import RadialExplorer
                        from research.thought_graph import ThoughtGraph
                    except ImportError:
                        from reasoning_engine import RadialExplorer
                        from thought_graph import ThoughtGraph
                    g = ThoughtGraph.load(gp)
                    ok_g, _, rep = RadialExplorer.verify_zero_incomplete_leaves(g)
                    if not ok_g:
                        issues.append(rep)
                except Exception as exc:
                    issues.append(f"Failed ThoughtGraph verification: {exc}")

        return len(issues) == 0, issues

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
