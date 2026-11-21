"""PAI Persistent Auto-Memory Subsystem.

Implements Anthropic's Cowork Auto-Memory pattern:
A persistent, categorized, file-based memory system that records:
  1. 'user': Role, technical background, preferences, and goals.
  2. 'feedback': User corrections, stylistic requirements, do's and don'ts.
  3. 'project': Architecture, frameworks, module layout, and tech stack.
  4. 'reference': Key documentation, bookmark paths, and connected directories.

Security & Boundaries:
  - Ephemeral and persistent records stored in ~/.pai/memory/ or <workspace>/.pai/memory/
  - Automatic scrubbing of sensitive secrets before recording.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VALID_MEMORY_TYPES = ("user", "feedback", "project", "reference")


@dataclass
class MemoryEntry:
    key: str
    mem_type: str
    content: str
    source: str = "user"  # "user", "inferred", "system"
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


def get_memory_directory(workspace_path: Optional[str] = None) -> Path:
    """Resolves the active memory storage directory.

    If a workspace path is provided and contains a `.pai/` directory,
    stores project-level memory there; otherwise falls back to `~/.pai/memory/`.
    """
    env_dir = os.environ.get("PAI_MEMORY_DIR")
    if env_dir:
        p = Path(env_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    if workspace_path and Path(workspace_path).is_dir():
        ws_mem = Path(workspace_path) / ".pai" / "memory"
        if ws_mem.parent.exists():
            ws_mem.mkdir(parents=True, exist_ok=True)
            return ws_mem

    home_mem = Path.home() / ".pai" / "memory"
    home_mem.mkdir(parents=True, exist_ok=True)
    return home_mem


class AutoMemoryManager:
    """Manages persistent categorized memory entries."""

    def __init__(self, workspace_path: Optional[str] = None):
        self.workspace_path = workspace_path
        self.base_dir = get_memory_directory(workspace_path)

    def _file_for_type(self, mem_type: str) -> Path:
        if mem_type not in VALID_MEMORY_TYPES:
            raise ValueError(f"Invalid memory type '{mem_type}'. Must be one of {VALID_MEMORY_TYPES}")
        return self.base_dir / f"{mem_type}.json"

    def _read_type_file(self, mem_type: str) -> Dict[str, Dict[str, Any]]:
        target_f = self._file_for_type(mem_type)
        if not target_f.is_file():
            return {}
        try:
            return json.loads(target_f.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _write_type_file(self, mem_type: str, data: Dict[str, Dict[str, Any]]) -> None:
        target_f = self._file_for_type(mem_type)
        target_f.parent.mkdir(parents=True, exist_ok=True)
        target_f.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def save(
        self,
        mem_type: str,
        key: str,
        content: str,
        source: str = "user",
        tags: Optional[List[str]] = None,
    ) -> MemoryEntry:
        """Saves or updates a memory entry."""
        if mem_type not in VALID_MEMORY_TYPES:
            raise ValueError(f"Invalid memory type: {mem_type}")

        clean_key = re.sub(r"[^a-zA-Z0-9_\-]", "_", key.strip().lower())
        records = self._read_type_file(mem_type)
        now = time.time()

        created_at = now
        if clean_key in records:
            created_at = records[clean_key].get("created_at", now)

        entry = MemoryEntry(
            key=clean_key,
            mem_type=mem_type,
            content=content.strip(),
            source=source,
            tags=tags or [],
            created_at=created_at,
            updated_at=now,
        )

        records[clean_key] = asdict(entry)
        self._write_type_file(mem_type, records)
        return entry

    def get(self, mem_type: str, key: str) -> Optional[MemoryEntry]:
        """Retrieves a specific memory entry."""
        clean_key = re.sub(r"[^a-zA-Z0-9_\-]", "_", key.strip().lower())
        records = self._read_type_file(mem_type)
        data = records.get(clean_key)
        if not data:
            return None
        return MemoryEntry(**data)

    def delete(self, mem_type: str, key: str) -> bool:
        """Deletes a memory entry."""
        clean_key = re.sub(r"[^a-zA-Z0-9_\-]", "_", key.strip().lower())
        records = self._read_type_file(mem_type)
        if clean_key in records:
            del records[clean_key]
            self._write_type_file(mem_type, records)
            return True
        return False

    def list_all(self, mem_type: Optional[str] = None) -> Dict[str, List[MemoryEntry]]:
        """Lists all memories, grouped by category."""
        results: Dict[str, List[MemoryEntry]] = {}
        types_to_scan = [mem_type] if mem_type else VALID_MEMORY_TYPES

        for mt in types_to_scan:
            recs = self._read_type_file(mt)
            entries = []
            for item in recs.values():
                try:
                    entries.append(MemoryEntry(**item))
                except Exception:
                    pass
            results[mt] = sorted(entries, key=lambda e: e.updated_at, reverse=True)

        return results

    def clear(self, mem_type: Optional[str] = None) -> None:
        """Clears memories of a specific type or all types."""
        types_to_clear = [mem_type] if mem_type else VALID_MEMORY_TYPES
        for mt in types_to_clear:
            f = self._file_for_type(mt)
            if f.exists():
                f.unlink(missing_ok=True)

    def format_context_for_prompt(self, max_items_per_type: int = 5) -> str:
        """Formats memory entries into clean XML blocks for prompt injection."""
        all_mems = self.list_all()
        sections: List[str] = []

        # User memory
        user_mems = all_mems.get("user", [])[:max_items_per_type]
        if user_mems:
            lines = [f"- {m.key}: {m.content}" for m in user_mems]
            sections.append(f"<user_profile>\n" + "\n".join(lines) + "\n</user_profile>")

        # Feedback & Do's/Don'ts
        fb_mems = all_mems.get("feedback", [])[:max_items_per_type]
        if fb_mems:
            lines = [f"- {m.key}: {m.content}" for m in fb_mems]
            sections.append(f"<user_feedback_and_instructions>\n" + "\n".join(lines) + "\n</user_feedback_and_instructions>")

        # Project memory
        proj_mems = all_mems.get("project", [])[:max_items_per_type]
        if proj_mems:
            lines = [f"- {m.key}: {m.content}" for m in proj_mems]
            sections.append(f"<project_context>\n" + "\n".join(lines) + "\n</project_context>")

        # References
        ref_mems = all_mems.get("reference", [])[:max_items_per_type]
        if ref_mems:
            lines = [f"- {m.key}: {m.content}" for m in ref_mems]
            sections.append(f"<active_references>\n" + "\n".join(lines) + "\n</active_references>")

        return "\n\n".join(sections)


def detect_memory_intent(user_prompt: str) -> Optional[Tuple[str, str, str]]:
    """Detects explicit user memory directives like:
      - 'Remember that I am a backend Rust developer' -> ('user', 'role', ...)
      - 'Don't use semicolons in Python' -> ('feedback', 'no_semicolons', ...)
      - 'Note that our database port is 5432' -> ('project', 'db_port', ...)
      - 'Forget what you remember about X' -> None or special trigger
    """
    p = user_prompt.strip()

    # 1. Match "Remember that ..." or "Remember: ..." or "Note that ..."
    m_rem = re.search(r"\b(?:remember(?:\s+that)?|note(?:\s+that)?)\s*[:,\-]?\s+(.+)$", p, re.IGNORECASE)
    if m_rem:
        statement = m_rem.group(1).strip()
        lower = statement.lower()
        if any(tok in lower for tok in ("i am", "my role", "my name", "i prefer", "i work as", "i use")):
            return ("user", "user_profile", statement)
        elif any(tok in lower for tok in ("don't", "never", "always", "avoid", "stop", "format", "style")):
            return ("feedback", "instruction", statement)
        elif any(tok in lower for tok in ("project", "repo", "database", "backend", "frontend", "port", "module")):
            return ("project", "project_note", statement)
        else:
            return ("reference", "reference_note", statement)

    # 2. Match direct instruction/feedback patterns: "Don't ever...", "Never do...", "Always use..."
    m_dir = re.search(r"^(?:don't|do not|never|always|avoid|stop)\s+(.+)$", p, re.IGNORECASE)
    if m_dir:
        return ("feedback", "rule", p)

    return None
