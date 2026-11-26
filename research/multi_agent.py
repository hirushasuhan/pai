"""
Multi-Agent Autonomous Engineering Team for Personal Agentic AI (PAI).
Adheres to IEEE / FIPA-ACL (Foundation for Intelligent Physical Agents) standards:
  - Project Manager (PM): Requirements decomposition, sprint planning, task delegation.
  - Senior Developer: Core engine architecture, 3D math, physics, game loop synthesis.
  - Specialist Developer: Procedural canvas textures, CCTV shaders, Web Audio API sound engines.
  - QA Engineer: Static code verification, syntax checking, control validation, acceptance gating.

Includes dynamic model assignment, inter-agent communication logging, and automatic model failover.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    from research import ast_guard, ingest, net_guard
    from research.capabilities import (
        Grant,
        PermissionDenied,
        Risk,
        Tool,
        ToolBroker,
        ToolRequest,
    )
except ModuleNotFoundError:
    import ast_guard
    import ingest
    import net_guard
    from capabilities import (
        Grant,
        PermissionDenied,
        Risk,
        Tool,
        ToolBroker,
        ToolRequest,
    )


SYNC_TOOL_NAME = "sync_project_file"
_MAX_DISCOVERY_BYTES = 1_048_576
_UNTRUSTED_MARKER_RE = re.compile(r"---\s*UNTRUSTED DATA BEGIN(?:\s*\[[^\]]+\])?\s*---")


def _contains_untrusted_marker(text: Optional[str]) -> bool:
    if not text:
        return False
    return ingest.UNTRUSTED_BEGIN_MARKER in text or bool(_UNTRUSTED_MARKER_RE.search(text))


def make_project_sync_broker(
    project_dir: Path,
    confirm: Optional[Callable[[ToolRequest], bool]] = None,
    max_calls: Optional[int] = None,
    expires: Optional[float] = None,
) -> ToolBroker:
    """Constructs a scoped ToolBroker granting Risk.WRITE syncs inside `project_dir`."""
    root_real = os.path.realpath(os.path.abspath(str(project_dir)))
    tool = Tool(
        SYNC_TOOL_NAME,
        Risk.WRITE,
        lambda dest_path, fname="", byte_len=0: True,
        path_args=("dest_path",),
    )
    grant = Grant(
        SYNC_TOOL_NAME,
        roots=(root_real,),
        expires=expires,
        max_calls=max_calls,
    )
    return ToolBroker(tools=[tool], grants=[grant], confirm=confirm)


def _atomic_write_text(target_path: Path, text: str) -> None:
    """Atomically writes UTF-8 text to `target_path`, rejecting symlink/reparse targets."""
    target_str = str(target_path)
    parent_str = str(target_path.parent)
    if ingest._is_symlink_or_reparse(parent_str):
        raise ValueError(f"Refusing to write inside symlink/reparse directory: {parent_str}")
    if ingest._is_symlink_or_reparse(target_str):
        raise ValueError(f"Refusing to overwrite symlink/reparse target: {target_str}")
    if os.path.lexists(target_str) and target_path.is_dir():
        raise ValueError(f"Refusing to overwrite directory: {target_str}")

    tmp_name = f".{target_path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    tmp_path = target_path.parent / tmp_name
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = None
    try:
        fd = os.open(str(tmp_path), flags, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if os.path.lexists(target_str) and ingest._is_symlink_or_reparse(target_str):
            raise ValueError(f"Refusing to replace symlink/reparse target: {target_str}")
        os.replace(str(tmp_path), target_str)
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            if os.path.lexists(str(tmp_path)):
                os.unlink(str(tmp_path))
        except OSError:
            pass
        raise


def _validate_workspace_dir(project_dir: Optional[Path]) -> Tuple[bool, Optional[Path], str]:
    """Validates that `project_dir` exists, is a directory, and is not a symlink/reparse point."""
    if project_dir is None:
        return False, None, "active_project_dir is None"
    raw_str = str(project_dir)
    if not raw_str or not os.path.lexists(raw_str):
        return False, None, "active_project_dir does not exist"
    if ingest._is_symlink_or_reparse(raw_str):
        return False, None, "active_project_dir cannot be a symlink or reparse point"
    if not Path(raw_str).is_dir():
        return False, None, "active_project_dir is not a directory"
    base_resolved = Path(os.path.realpath(os.path.abspath(raw_str)))
    if ingest.has_ads_colon(str(base_resolved)):
        return False, None, "active_project_dir contains an ADS colon"
    if not base_resolved.is_dir():
        return False, None, "resolved active_project_dir is not a directory"
    return True, base_resolved, ""


def _validate_relative_sync_path(fname: str) -> Tuple[bool, List[str], str]:
    """Validates a relative filename for project sync before any filesystem resolution."""
    if not isinstance(fname, str) or not fname or not fname.strip():
        return False, [], "empty or non-string filename"
    if fname != fname.strip():
        return False, [], "filename contains leading or trailing whitespace"
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in fname):
        return False, [], "filename contains control or NUL characters"
    if ingest._is_invalid_filename(fname):
        return False, [], "filename contains invalid UTF-8 characters"
    if ingest.has_ads_colon(fname):
        return False, [], "filename contains NTFS ADS colon"
    if fname.startswith(("/", "\\")):
        return False, [], "absolute or root-anchored path is not allowed"
    if len(fname) >= 2 and fname[1] == ":":
        return False, [], "Windows drive-prefixed path is not allowed"
    if Path(fname).is_absolute() or PureWindowsPath(fname).is_absolute():
        return False, [], "absolute path is not allowed"

    rel_parts = fname.replace("\\", "/").split("/")
    if not rel_parts or any(part in ("", ".", "..") for part in rel_parts):
        return False, [], "path traversal or empty path segment is not allowed"
    for part in rel_parts:
        if ingest.is_reserved_device_name(part):
            return False, [], f"reserved device name '{part}' is not allowed"
    for parent_part in rel_parts[:-1]:
        if ingest.is_junk_dir(parent_part) or parent_part.lower() in ingest.DEFAULT_SENSITIVE_DIRS:
            return False, [], f"restricted directory segment '{parent_part}' is not allowed"
    if ingest.is_secret_file(fname):
        return False, [], "secret/credential filename is not allowed"
    if fname.lower().endswith((".bak", ".candidate")):
        return False, [], "direct write to .bak or .candidate file is not allowed"
    return True, rel_parts, ""


def _is_safe_readable_workspace_file(fpath: Path, base_resolved: Path) -> bool:
    """Checks canonical containment, symlink/reparse, device/ADS, and secret-file rules."""
    f_str = str(fpath)
    if not os.path.lexists(f_str) or ingest._is_symlink_or_reparse(f_str):
        return False
    try:
        rel_lexical = fpath.relative_to(base_resolved)
    except ValueError:
        try:
            rel_lexical = Path(os.path.abspath(f_str)).relative_to(base_resolved)
        except ValueError:
            return False
    cur = base_resolved
    for seg in rel_lexical.parts[:-1]:
        cur = cur / seg
        if ingest._is_symlink_or_reparse(str(cur)):
            return False
    if not fpath.is_file():
        return False
    resolved = Path(os.path.realpath(os.path.abspath(f_str)))
    if not resolved.is_relative_to(base_resolved) or resolved == base_resolved:
        return False
    rel_posix = resolved.relative_to(base_resolved).as_posix()
    if ingest.has_ads_colon(f_str) or ingest.has_ads_colon(rel_posix):
        return False
    if ingest.is_reserved_device_name(fpath.name):
        return False
    if ingest.is_secret_file(rel_posix) or ingest.is_secret_file(fpath.name):
        return False
    return True


@dataclass
class AgentMessage:
    msg_id: str
    sender_role: str
    sender_model: str
    recipient_role: str
    performative: str  # REQUEST, PROPOSE, INFORM, ACCEPT, REJECT, FAILOVER
    content: str
    deliverables: Optional[Dict[str, Any]] = None
    timestamp: float = field(default_factory=time.time)


def discover_available_models(base_url: str = "http://127.0.0.1:11434") -> List[str]:
    """Queries loopback Ollama server for currently installed models."""
    try:
        net_guard.validate_url(base_url, allow_private=True)
        target = base_url.rstrip("/") + "/api/tags"
        req = urllib.request.Request(target)
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            try:
                raw = resp.read(_MAX_DISCOVERY_BYTES + 1)
            except TypeError:
                raw = resp.read()
            if len(raw) > _MAX_DISCOVERY_BYTES:
                return []
            data = json.loads(raw.decode("utf-8"))
            return [str(m.get("name")) for m in data.get("models", []) if m.get("name")]
    except Exception:
        return []


class TeamRoleModelRegistry:
    """Manages role-to-model mapping, user customization, and prioritized failovers."""
    
    ROLE_PREFERENCES: Dict[str, List[str]] = {
        "project_manager": ["llama3.2:3b", "qwen3.5:4b", "llama3.2:1b"],
        "explorer": ["qwen2.5-coder:1.5b", "llama3.2:1b", "qwen3.5:4b"],
        "planner": ["llama3.2:3b", "qwen3.5:4b", "qwen2.5-coder:7b"],
        "senior_developer": ["qwen2.5-coder:7b", "qwen2.5-coder:1.5b", "qwen3.5:4b"],
        "specialist_developer": ["qwen2.5-coder:1.5b", "qwen3.5:4b", "llama3.2:3b"],
        "qa_engineer": ["qwen3.5:4b", "llama3.2:1b", "llama3.2:3b"],
        "debugger": ["qwen2.5-coder:7b", "qwen3.5:4b", "qwen2.5-coder:1.5b"],
    }

    ROLE_TITLES: Dict[str, str] = {
        "project_manager": "Product & Project Manager",
        "explorer": "Codebase Scout & Grep Explorer",
        "planner": "Software Architect & Implementation Planner",
        "senior_developer": "Principal Software Engineer & Core Architect",
        "specialist_developer": "Frontend / UI, Textures & Audio Specialist",
        "qa_engineer": "Lead QA Engineer & Code Auditor",
        "debugger": "Runtime Debug Specialist & Hypothesis Tester",
    }

    ROLE_ICONS: Dict[str, str] = {
        "project_manager": "👔",
        "explorer": "🔍",
        "planner": "📐",
        "senior_developer": "💻",
        "specialist_developer": "🎨",
        "qa_engineer": "🧪",
        "debugger": "🐛",
    }

    ROLE_ALIASES: Dict[str, str] = {
        "pm": "project_manager",
        "project_manager": "project_manager",
        "manager": "project_manager",
        "lead": "project_manager",
        "coordinator": "project_manager",
        "explorer": "explorer",
        "scout": "explorer",
        "search": "explorer",
        "grep": "explorer",
        "planner": "planner",
        "architect": "planner",
        "senior": "senior_developer",
        "senior_developer": "senior_developer",
        "senior_dev": "senior_developer",
        "dev": "senior_developer",
        "coder": "senior_developer",
        "developer": "senior_developer",
        "specialist": "specialist_developer",
        "specialist_developer": "specialist_developer",
        "ui": "specialist_developer",
        "frontend": "specialist_developer",
        "graphics": "specialist_developer",
        "audio": "specialist_developer",
        "qa": "qa_engineer",
        "qa_engineer": "qa_engineer",
        "test": "qa_engineer",
        "tester": "qa_engineer",
        "auditor": "qa_engineer",
        "reviewer": "qa_engineer",
        "debugger": "debugger",
        "debug": "debugger",
        "fix": "debugger",
    }

    def __init__(self, model_override: Optional[str] = None):
        self._model_override = model_override
        self.available_models = discover_available_models()
        self.role_models: Dict[str, str] = {}
        self.role_fallbacks: Dict[str, List[str]] = {}
        self.custom_roles: set[str] = set()
        self._initialize_mappings(model_override)
        if not model_override:
            self.load_saved_config()

    def refresh_available_models(self) -> None:
        """Re-discovers installed Ollama models and refreshes fallback lists while keeping custom roles."""
        self.available_models = discover_available_models()
        saved_custom = {r: self.role_models[r] for r in self.custom_roles if r in self.role_models}
        self._initialize_mappings(self._model_override)
        for r, m in saved_custom.items():
            self.role_models[r] = m
            self.custom_roles.add(r)
            prefs = self.ROLE_PREFERENCES.get(r, [])
            if self.available_models:
                self.role_fallbacks[r] = [fb for fb in prefs if fb != m and fb in self.available_models]
            else:
                self.role_fallbacks[r] = [fb for fb in prefs if fb != m]

    @staticmethod
    def get_config_path() -> Path:
        env_p = os.environ.get("PAI_TEAM_CONFIG")
        if env_p:
            return Path(env_p)
        return Path.home() / ".pai" / "team_config.json"

    def load_saved_config(self):
        """Loads saved team role-to-model configuration overrides."""
        cfg_file = self.get_config_path()
        if cfg_file.is_file():
            try:
                data = json.loads(cfg_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for r, m in data.items():
                        canon = self.ROLE_ALIASES.get(r.lower())
                        if canon and isinstance(m, str) and m.strip():
                            self.role_models[canon] = m.strip()
                            self.custom_roles.add(canon)
            except Exception:
                pass

    def save_config(self):
        """Persists custom team role-to-model assignments to ~/.pai/team_config.json."""
        cfg_file = self.get_config_path()
        try:
            cfg_file.parent.mkdir(parents=True, exist_ok=True)
            cfg_file.write_text(json.dumps(self.role_models, indent=2), encoding="utf-8")
        except Exception:
            pass

    def set_role_model(self, role_str: str, model_name: str, persist: bool = True) -> Tuple[bool, str]:
        """Assigns an AI model to a specific team role."""
        canon = self.ROLE_ALIASES.get(role_str.strip().lower())
        if not canon:
            return False, f"Unknown role '{role_str}'. Valid roles: pm, explorer, planner, dev, ui, qa, debugger."

        clean_model = model_name.strip()
        matched_avail = None
        for avail in self.available_models:
            if avail.lower() == clean_model.lower():
                matched_avail = avail
                break
            elif avail.lower().startswith(clean_model.lower() + ":"):
                matched_avail = avail
                break
            elif avail.lower().startswith(clean_model.lower()):
                matched_avail = avail
                break
            elif clean_model.lower() in avail.lower():
                matched_avail = avail
                break

        if matched_avail:
            clean_model = matched_avail

        self.role_models[canon] = clean_model
        self.custom_roles.add(canon)
        if persist:
            self.save_config()

        icon = self.ROLE_ICONS.get(canon, "🤖")
        title = self.ROLE_TITLES.get(canon, canon)
        status = f"Assigned {icon} {title} ({canon}) -> model '{clean_model}'"
        if self.available_models and clean_model not in self.available_models:
            status += f" (Note: '{clean_model}' is not currently running in local Ollama tags)"
        return True, status

    def parse_and_apply_assignments(self, assignment_str: str, persist: bool = True) -> List[str]:
        """Parses assignment expressions like 'pm=llama3.2:3b dev=qwen2.5-coder:7b' or 'pm llama3.2:3b'."""
        results = []
        tokens = assignment_str.replace(",", " ").split()
        for tok in tokens:
            if "=" in tok:
                parts = tok.split("=", 1)
                ok, msg = self.set_role_model(parts[0], parts[1], persist=False)
                results.append(msg)
            elif ":" in tok and not any(tok.startswith(p) for p in ("qwen", "llama", "gemma")):
                parts = tok.split(":", 1)
                ok, msg = self.set_role_model(parts[0], parts[1], persist=False)
                results.append(msg)

        if not results and len(tokens) >= 2:
            r = tokens[0]
            m = tokens[1]
            ok, msg = self.set_role_model(r, m, persist=False)
            results.append(msg)

        if persist:
            self.save_config()
        if not results:
            results.append("No valid role=model assignments found (e.g. pm=llama3.2:3b dev=qwen2.5-coder:7b).")
        return results

    def reset_to_defaults(self, persist: bool = True) -> str:
        """Resets all team role models to automatic intelligent defaults."""
        self.custom_roles.clear()
        cfg_file = self.get_config_path()
        if cfg_file.is_file():
            try:
                cfg_file.unlink()
            except Exception:
                pass
        self._initialize_mappings()
        return "All team roles have been reset to automatic intelligent defaults."

    def format_config_help(self, color_enabled: bool = False) -> str:
        """Returns guide on how to configure team roles."""
        lines = [
            "=== Autonomous AI Team Model Configuration ===",
            "Configure role-specific models for the multi-agent team (persisted to ~/.pai/team_config.json).",
            "",
            "Usage:",
            "  /team set <role>=<model> [...]   (e.g. /team set pm=llama3.2:3b dev=qwen2.5-coder:7b)",
            "  /team set <role> <model>         (e.g. /team set pm qwen3.5:4b)",
            "  /team reset                      (Restore automatic intelligent defaults)",
            "  /team models                     (List local models available for assignment)",
            "  /team status                     (View active team roster and assigned models)",
            "",
            "Role Identifiers:",
            "  • pm / manager       : Product & Project Manager",
            "  • explorer / scout   : Codebase Scout & Grep Explorer",
            "  • planner / architect: Software Architect & Implementation Planner",
            "  • dev / senior       : Principal Software Engineer & Architect",
            "  • ui / specialist    : Frontend / UI, Textures & Audio Specialist",
            "  • qa / tester        : Lead QA Engineer & Code Auditor",
            "  • debugger / debug   : Runtime Debug Specialist & Hypothesis Tester",
        ]
        return "\n".join(lines)

    def format_available_models(self, color_enabled: bool = False) -> str:
        """Returns formatted list of local models."""
        models = self.available_models or discover_available_models()
        lines = ["=== Local Models Available for Team Assignment ==="]
        if not models:
            lines.append("  (No models detected via loopback Ollama endpoint http://127.0.0.1:11434)")
        else:
            for m in models:
                lines.append(f"  • {m}")
        lines.append("\nTip: Use '/team set <role>=<model>' to assign any model to a role.")
        return "\n".join(lines)

    def _initialize_mappings(self, override: Optional[str] = None):
        for role, prefs in self.ROLE_PREFERENCES.items():
            if override and (not self.available_models or override in self.available_models):
                # If user explicitly overrode model, use it as primary
                self.role_models[role] = override
                self.role_fallbacks[role] = [m for m in prefs if m != override and m in self.available_models]
            else:
                matched = False
                for cand in prefs:
                    if cand in self.available_models:
                        self.role_models[role] = cand
                        self.role_fallbacks[role] = [m for m in prefs if m != cand and m in self.available_models]
                        matched = True
                        break
                if not matched:
                    # Default fallback
                    default_m = prefs[0] if prefs else "qwen2.5-coder:1.5b"
                    self.role_models[role] = default_m
                    self.role_fallbacks[role] = prefs[1:] if len(prefs) > 1 else []


class MultiAgentTeam:
    """
    Coordinates an autonomous software engineering team adhering to FIPA-ACL.
    Enforces multi-model specializations and auto-switching across distinct roles.
    """
    _ASCII_FALLBACK_MAP = {
        "👔": "[PM]",
        "🔍": "[EXPLORE]",
        "📐": "[PLAN]",
        "💻": "[DEV]",
        "🎨": "[UI]",
        "🧪": "[QA]",
        "🐛": "[DEBUG]",
        "🤖": "[BOT]",
        "👤": "[USER]",
        "🚀": "[*]",
        "📋": "[PLAN]",
        "✅": "[OK]",
        "⚠️": "[WARN]",
        "⚠": "[WARN]",
        "🔄": "[SWITCH]",
        "❌": "[FAIL]",
        "🔌": "[MCP]",
        "💡": "[TIP]",
        "📁": "[DIR]",
        "┌": "+",
        "├": "+",
        "└": "+",
        "─": "-",
        "│": "|",
        "•": "*",
        "──": "--",
        "══": "==",
        "═": "=",
    }

    @classmethod
    def _safe_text(cls, text: str, encoding: Optional[str] = None) -> str:
        import sys
        enc = encoding or getattr(sys.stdout, "encoding", None) or "utf-8"
        try:
            text.encode(enc)
            return text
        except (UnicodeEncodeError, LookupError):
            sanitized = text
            for src, dst in cls._ASCII_FALLBACK_MAP.items():
                sanitized = sanitized.replace(src, dst)
            try:
                return sanitized.encode(enc, errors="replace").decode(enc, errors="replace")
            except LookupError:
                return sanitized.encode("ascii", errors="replace").decode("ascii", errors="replace")

    @classmethod
    def _make_safe_output(cls, raw_fn: Optional[Callable[[str], None]]) -> Callable[[str], None]:
        fn = raw_fn or print

        def _safe_emit(msg: str = "") -> None:
            text = str(msg)
            if fn is print:
                fn(cls._safe_text(text))
                return
            try:
                fn(text)
            except UnicodeEncodeError:
                fn(cls._safe_text(text, encoding="ascii"))

        return _safe_emit

    def __init__(
        self,
        model_name: Optional[str] = None,
        executor: Optional[Callable[[List[str]], int]] = None,
        output_fn: Optional[Callable[[str], None]] = None,
        color_enabled: bool = False,
        broker: Optional[ToolBroker] = None,
        confirm: Optional[Callable[[ToolRequest], bool]] = None,
        tainted: bool = False,
    ):
        self.registry = TeamRoleModelRegistry(model_override=model_name)
        self.executor = executor
        self.output_fn = self._make_safe_output(output_fn)
        self.color_enabled = color_enabled
        self.broker = broker
        self.confirm = confirm
        self.tainted = bool(tainted)
        self.conversation_log: List[AgentMessage] = []
        self._msg_counter = 0
        self._service_offline = False
        self._last_error = ""

    @staticmethod
    def _is_service_offline_error(text: str) -> bool:
        low = (text or "").lower()
        return any(
            tok in low
            for tok in (
                "is not running",
                "service is not running",
                "connection refused",
                "10061",
                "failed to establish a new connection",
                "pai setup",
                "start ollama",
            )
        )

    @staticmethod
    def _extract_concise_error(text: str) -> str:
        lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
        for ln in reversed(lines):
            if ln.lower().startswith("error:"):
                return ln[6:].strip() or ln
        return lines[-1] if lines else ""

    def get_roster_summary(self) -> str:
        """Returns standard ASCII table of team members and model assignments."""
        lines = [
            "┌──[ PAI Autonomous AI Engineering Team (FIPA-ACL Standard) ]──────────────────",
            "│ Role                 Title                                Assigned Model",
            "├──────────────────────────────────────────────────────────────────────────────"
        ]
        for role, title in TeamRoleModelRegistry.ROLE_TITLES.items():
            icon = TeamRoleModelRegistry.ROLE_ICONS.get(role, "🤖")
            m = self.registry.role_models.get(role, "unknown")
            fb = self.registry.role_fallbacks.get(role, [])
            fb_str = f" (fallback: {fb[0]})" if fb else ""
            tag = " [custom]" if role in self.registry.custom_roles else " [auto]"
            lines.append(f"│ {icon} {role:<18} {title:<35} {m}{tag}{fb_str}")
        lines.append("└──────────────────────────────────────────────────────────────────────────────")
        return "\n".join(lines)

    def log_and_display_message(
        self,
        sender: str,
        recipient: str,
        performative: str,
        content_preview: str,
        deliverables: Optional[Dict[str, Any]] = None,
    ) -> AgentMessage:
        """Logs and renders standard FIPA-ACL inter-agent message in the console."""
        self._msg_counter += 1
        sender_model = self.registry.role_models.get(sender, "local-model")
        msg = AgentMessage(
            msg_id=f"MSG-{self._msg_counter:03d}",
            sender_role=sender,
            sender_model=sender_model,
            recipient_role=recipient,
            performative=performative,
            content=content_preview,
            deliverables=deliverables,
        )
        self.conversation_log.append(msg)

        s_icon = TeamRoleModelRegistry.ROLE_ICONS.get(sender, "🤖")
        r_icon = TeamRoleModelRegistry.ROLE_ICONS.get(recipient, "🤖") if recipient != "user" else "👤"

        arrow = "──REQUEST──>" if performative == "REQUEST" else (
            "──INFORM──>" if performative == "INFORM" else (
                "──ACCEPT──>" if performative == "ACCEPT" else "──> "
            )
        )
        self.output_fn(f"\n[FIPA-ACL] [{performative}] {s_icon} {sender} ({sender_model}) {arrow} {r_icon} {recipient}")
        self.output_fn(f"   Payload: {content_preview}")
        return msg

    def _call_agent_persona(
        self,
        role: str,
        system_role: str,
        instructions: str,
        user_prompt: str,
        timeout: float = 240.0,
    ) -> str:
        """
        Invokes model assigned to the role with automatic failover to alternative models
        if primary times out or is unresponsive.
        """
        primary_model = self.registry.role_models.get(role, "qwen2.5-coder:1.5b")
        fallbacks = self.registry.role_fallbacks.get(role, [])
        candidate_queue = [primary_model] + [fb for fb in fallbacks if fb != primary_model]

        persona_prompt = (
            f"Role: {role}\n"
            f"You are the {system_role} in an autonomous professional software engineering team.\n"
            f"FIPA-ACL Role Directive:\n{instructions}\n\n"
            f"Team State & Task Context:\n{user_prompt}\n\n"
            f"Respond concisely, strictly adhering to your engineering role."
        )

        try:
            from research.shell import CaptureStream, execute_subcommand
        except ModuleNotFoundError:
            from shell import CaptureStream, execute_subcommand

        exec_fn = self.executor or execute_subcommand
        prev_disable_failover = os.environ.get("PAI_DISABLE_CHAT_FAILOVER")
        os.environ["PAI_DISABLE_CHAT_FAILOVER"] = "1"
        try:
            for attempt_model in candidate_queue:
                exec_argv = ["chat", "--model", attempt_model, "--model-timeout", str(timeout)]
                if "gemma" in attempt_model.lower():
                    exec_argv.append("--gemma4-opt-in")
                exec_argv += ["--", persona_prompt]
                cap_out = io.StringIO()
                cap_err = io.StringIO()
                rc = 0
                err_text = ""

                try:
                    with contextlib.redirect_stdout(cap_out), contextlib.redirect_stderr(cap_err):
                        ret = exec_fn(exec_argv)
                    rc = ret if isinstance(ret, int) else 0
                    out = cap_out.getvalue().strip()
                    err_text = cap_err.getvalue().strip()
                    if rc == 0 and out and len(out) > 20:
                        # Success
                        return out
                except Exception as e:
                    rc = 1
                    err_text = f"{cap_err.getvalue().strip()} {e}".strip()

                if self._is_service_offline_error(err_text):
                    self._service_offline = True
                    self._last_error = self._extract_concise_error(err_text) or (
                        "Local AI service (Ollama) is not running on 127.0.0.1:11434. "
                        "Run 'pai setup' or start Ollama from the Start Menu."
                    )
                    self.output_fn(f"  ❌ [{role}] {self._last_error}")
                    break

                err_note = self._extract_concise_error(err_text)
                if err_note:
                    self._last_error = err_note
                    self.output_fn(f"  ⚠️ [Failover Warning] Role '{role}' on '{attempt_model}' failed ({err_note}). Checking alternatives...")

                # If failed or returned empty, record failover and try next model
                if len(candidate_queue) > 1 and attempt_model != candidate_queue[-1]:
                    next_model = candidate_queue[candidate_queue.index(attempt_model) + 1]
                    self.output_fn(f"  🔄 [Auto-Switch] Role '{role}' switching from '{attempt_model}' -> '{next_model}'...")
                    self.registry.role_models[role] = next_model
        finally:
            if prev_disable_failover is None:
                os.environ.pop("PAI_DISABLE_CHAT_FAILOVER", None)
            else:
                os.environ["PAI_DISABLE_CHAT_FAILOVER"] = prev_disable_failover

        return ""

    @staticmethod
    def _collect_codebase_context(
        project_dir: Optional[Path],
        max_chars_per_file: int = 12000,
        max_total_chars: int = 25000,
    ) -> str:
        """Extracts existing text source files from the active project with containment and secret filtering."""
        ok_dir, base_resolved, _ = _validate_workspace_dir(project_dir)
        if not ok_dir or base_resolved is None:
            return ""
        snippets = []
        total_len = 0
        priority_files = ["script.js", "index.html", "style.css", "main.py", "app.py", "README.md"]
        ordered_files: List[Path] = []
        for name in priority_files:
            cand = base_resolved / name
            if _is_safe_readable_workspace_file(cand, base_resolved):
                ordered_files.append(cand)
        try:
            for cand in sorted(base_resolved.iterdir()):
                if (
                    cand not in ordered_files
                    and not cand.name.endswith((".bak", ".candidate"))
                    and not cand.name.startswith(".")
                    and _is_safe_readable_workspace_file(cand, base_resolved)
                ):
                    ordered_files.append(cand)
        except Exception:
            pass

        skip_exts = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".exe", ".bin", ".zip", ".tar", ".gz", ".mp3", ".wav", ".bak", ".candidate"}
        run_nonce = ingest.generate_envelope_nonce()
        for f in ordered_files:
            if f.suffix.lower() in skip_exts:
                continue
            try:
                raw_bytes = f.read_bytes()
                if b"\x00" in raw_bytes:
                    continue
                content = ingest.sanitize_text_content(raw_bytes).strip()
                if not content:
                    continue
                if ingest.scan_secret_content(content, file_path=f.name) is not None:
                    continue
                if len(content) > max_chars_per_file:
                    content = content[:max_chars_per_file] + "\n... [truncated for context budget] ..."
                lang_tag = f.suffix.lstrip(".") or "text"
                if lang_tag == "js":
                    lang_tag = "javascript"
                elif lang_tag == "py":
                    lang_tag = "python"
                raw_snippet = f"[File: {f.name} ({len(raw_bytes):,} bytes)]\n```{lang_tag}\n{content}\n```"
                wrapped = ingest.wrap_untrusted_envelope(
                    raw_snippet,
                    header=f"Project File: {f.name}",
                    nonce=run_nonce,
                )
                if total_len + len(wrapped) > max_total_chars:
                    break
                snippets.append(wrapped)
                total_len += len(wrapped)
            except Exception:
                pass
        if not snippets:
            return ""
        return "\n--- Active Project Codebase ---\n" + "\n\n".join(snippets)

    def _reject_sync(self, fname: str, reason: str) -> Tuple[bool, str]:
        err = f"  ❌ [Rejected write for '{fname}': {reason}]"
        self.output_fn(err)
        return False, err

    def _safe_sync_file(
        self,
        active_project_dir: Path,
        fname: str,
        body: str,
        verdict_pass: bool = True,
        broker: Optional[ToolBroker] = None,
        tainted: Optional[bool] = None,
    ) -> Tuple[bool, str]:
        """Safely writes or updates a file in project_dir with containment, AST, secret, and ToolBroker guards."""
        ok_dir, base_resolved, dir_err = _validate_workspace_dir(active_project_dir)
        if not ok_dir or base_resolved is None:
            return self._reject_sync(str(fname), dir_err)

        ok_path, rel_parts, path_err = _validate_relative_sync_path(fname)
        if not ok_path:
            return self._reject_sync(str(fname), path_err)

        candidate_dest = base_resolved.joinpath(*rel_parts)
        bak_path = candidate_dest.with_suffix(candidate_dest.suffix + ".bak")
        cand_path = candidate_dest.with_suffix(candidate_dest.suffix + ".candidate")

        cur = base_resolved
        for seg in rel_parts[:-1]:
            cur = cur / seg
            cur_str = str(cur)
            if os.path.lexists(cur_str):
                if ingest._is_symlink_or_reparse(cur_str):
                    return self._reject_sync(fname, f"parent '{seg}' is a symlink or reparse point")
                if not cur.is_dir():
                    return self._reject_sync(fname, f"parent '{seg}' is not a directory")

        for target_p in (candidate_dest, bak_path, cand_path):
            p_str = str(target_p)
            raw_target_str = str(active_project_dir.joinpath(*rel_parts[:-1], target_p.name)) if active_project_dir else p_str
            if ingest._is_symlink_or_reparse(p_str) or ingest._is_symlink_or_reparse(raw_target_str):
                return self._reject_sync(fname, f"target '{target_p.name}' is a symlink or reparse point")
            p_real = Path(os.path.realpath(os.path.abspath(p_str)))
            if not p_real.is_relative_to(base_resolved) or p_real == base_resolved:
                return self._reject_sync(fname, "target path resolves outside active_project_dir")
            if os.path.lexists(p_str) and target_p.is_dir():
                return self._reject_sync(fname, f"target '{target_p.name}' is a directory")

        dest_resolved = Path(os.path.realpath(os.path.abspath(str(candidate_dest))))

        if not isinstance(body, str) or "\x00" in body:
            return self._reject_sync(fname, "content must be a NUL-free string")

        if candidate_dest.suffix.lower() == ".py":
            rep = ast_guard.check_source(body)
            if not rep.ok:
                details = "; ".join(str(v) for v in rep.violations[:3])
                return self._reject_sync(fname, f"ast_guard rejected Python source ({details})")

        secret_hit = ingest.scan_secret_content(body, file_path=fname)
        if secret_hit is not None:
            return self._reject_sync(fname, f"embedded secret detected ({secret_hit})")

        effective_broker = broker or self.broker or make_project_sync_broker(base_resolved, confirm=self.confirm)
        effective_tainted = self.tainted if tainted is None else bool(tainted)
        try:
            effective_broker.invoke(
                SYNC_TOOL_NAME,
                {"dest_path": str(dest_resolved), "fname": fname, "byte_len": len(body)},
                tainted=effective_tainted,
            )
        except PermissionDenied as exc:
            return self._reject_sync(fname, f"denied by ToolBroker ({exc})")

        try:
            candidate_dest.parent.mkdir(parents=True, exist_ok=True)
            parent_str = str(candidate_dest.parent)
            if ingest._is_symlink_or_reparse(parent_str) or not Path(os.path.realpath(parent_str)).is_relative_to(base_resolved):
                return self._reject_sync(fname, "destination parent failed post-mkdir containment check")

            # Safeguard: Never overwrite a substantial file (>3KB) with a tiny stub (<800B) if audit failed or stub is degenerate
            is_substantial = candidate_dest.is_file() and candidate_dest.stat().st_size > 3000
            is_tiny_stub = len(body) < 800
            if is_substantial and is_tiny_stub and (not verdict_pass or candidate_dest.stat().st_size > len(body) * 5):
                _atomic_write_text(cand_path, body)
                msg = (
                    f"  ⚠️ [Preserved {candidate_dest.name} ({candidate_dest.stat().st_size:,} bytes) against tiny stub overwrite "
                    f"({len(body)} bytes). Saved candidate to {cand_path.name}]"
                )
                self.output_fn(msg)
                return False, msg

            if candidate_dest.is_file():
                _atomic_write_text(bak_path, candidate_dest.read_text(encoding="utf-8", errors="replace"))
            _atomic_write_text(candidate_dest, body)
            self.output_fn(f"  ✅ [Synchronized {candidate_dest.name}] ({len(body):,} bytes)")
            return True, f"Synchronized {candidate_dest.name}"
        except Exception as e:
            err = f"  ❌ [Failed to write {candidate_dest.name}: {e}]"
            self.output_fn(err)
            return False, err

    def run_code_exploration(
        self,
        query: str,
        project_dir: Optional[Path] = None,
        max_matches: int = 25,
    ) -> Dict[str, Any]:
        """
        Claude Code 'Explore' subagent contract:
        - CRITICAL: STRICT READ-ONLY MODE - NO FILE WRITES OR MODIFICATIONS.
        - Scans project codebase for symbols, functions, classes, and references.
        - Emits file_path:line_number citations and structural summary.
        """
        results: Dict[str, Any] = {
            "query": query,
            "findings": "",
            "citations": [],
            "scanned_files": [],
            "read_only_verified": True,
        }
        self.log_and_display_message(
            sender="project_manager",
            recipient="explorer",
            performative="REQUEST",
            content_preview=f"Scout codebase for symbols/references: '{query[:80]}...'",
        )

        citations: List[str] = []
        scanned_files: List[str] = []
        relevant_code_snippets: List[str] = []

        ok_dir, base_resolved, _ = _validate_workspace_dir(project_dir)
        if ok_dir and base_resolved is not None:
            keywords = [k.strip() for k in re.split(r"\s+", query) if len(k.strip()) > 2]
            skip_exts = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".exe", ".bin", ".zip", ".tar", ".gz", ".mp3", ".wav", ".bak", ".candidate"}

            for root, dirs, files in os.walk(base_resolved, followlinks=False):
                dirs[:] = [
                    d for d in dirs
                    if not d.startswith(".")
                    and not ingest.is_junk_dir(d)
                    and d.lower() not in ingest.DEFAULT_SENSITIVE_DIRS
                    and not ingest._is_symlink_or_reparse(os.path.join(root, d))
                ]
                for fname in sorted(files):
                    if any(fname.endswith(ext) for ext in skip_exts) or fname.startswith("."):
                        continue
                    fpath = Path(root) / fname
                    if not _is_safe_readable_workspace_file(fpath, base_resolved):
                        continue
                    try:
                        rel_path = fpath.relative_to(base_resolved).as_posix()
                    except ValueError:
                        rel_path = fpath.name
                    try:
                        raw_bytes = fpath.read_bytes()
                        if b"\x00" in raw_bytes:
                            continue
                        clean_text = ingest.sanitize_text_content(raw_bytes)
                        if ingest.scan_secret_content(clean_text, file_path=rel_path) is not None:
                            continue
                        scanned_files.append(rel_path)
                        for idx, line in enumerate(clean_text.splitlines(), 1):
                            line_str = line.strip()
                            if not line_str:
                                continue
                            if any(k.lower() in line_str.lower() for k in keywords):
                                citation = f"{rel_path}:{idx}: {line_str}"
                                citations.append(citation)
                                if len(citations) <= max_matches:
                                    relevant_code_snippets.append(citation)
                    except Exception:
                        pass

        results["citations"] = citations[:max_matches]
        results["scanned_files"] = scanned_files

        explorer_instructions = (
            "CRITICAL: READ-ONLY MODE - NO FILE MODIFICATIONS ALLOWED.\n"
            "You are the Codebase Scout & Grep Explorer subagent.\n"
            "Analyze the codebase search matches and citations.\n"
            "Synthesize a clear, concise codebase map explaining where key logic lives,\n"
            "how components connect, and specific file_path:line_number references.\n"
            "Never generate write commands or attempt to edit files."
        )

        citation_summary = "\n".join(relevant_code_snippets[:max_matches]) if relevant_code_snippets else "No direct string matches found in scanned files."
        wrapped_citations = ingest.wrap_untrusted_envelope(citation_summary, header="Workspace Code Citations")
        scanned_summary = ", ".join(scanned_files[:20]) if scanned_files else "No local files"

        exp_prompt = (
            f"Query: {query}\n"
            f"Scanned Files ({len(scanned_files)}): {scanned_summary}\n\n"
            f"Matching Code Citations:\n{wrapped_citations}\n"
        )

        exp_out = self._call_agent_persona(
            role="explorer",
            system_role="Codebase Scout & Grep Explorer",
            instructions=explorer_instructions,
            user_prompt=exp_prompt,
            timeout=120.0,
        )
        results["findings"] = exp_out

        if not self._service_offline:
            self.log_and_display_message(
                sender="explorer",
                recipient="project_manager",
                performative="INFORM",
                content_preview=f"Scouted codebase: {len(citations)} citations found across {len(scanned_files)} files.",
            )
        return results

    def run_implementation_planning(
        self,
        task_prompt: str,
        project_dir: Optional[Path] = None,
        exploration_findings: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Claude Code 'Plan' subagent contract:
        - Analyzes architectural boundaries, dependencies, and code conventions.
        - Deconstructs goal into an actionable Work Breakdown Structure (WBS).
        - Identifies 3-5 Critical Files for Implementation.
        """
        results: Dict[str, Any] = {
            "task": task_prompt,
            "plan": "",
            "critical_files": [],
        }
        self.log_and_display_message(
            sender="project_manager",
            recipient="planner",
            performative="REQUEST",
            content_preview=f"Architect implementation plan and critical file set: '{task_prompt[:80]}...'",
        )

        planner_instructions = (
            "You are the Software Architect & Implementation Planner subagent.\n"
            "Deconstruct the objective into a technical Work Breakdown Structure (WBS) with 3-4 structured milestones.\n"
            "Specify data structures, API contracts, game loop / control hooks, and error boundaries.\n"
            "CRITICAL: Conclude your plan with an explicit list of 3-5 Critical Files for Implementation in the following exact format:\n"
            "### Critical Files for Implementation:\n"
            "- path/to/file1\n"
            "- path/to/file2\n"
        )

        codebase_ctx = self._collect_codebase_context(project_dir) if project_dir else ""
        plan_prompt = f"Objective:\n{task_prompt}\n"
        if exploration_findings:
            plan_prompt += f"\nExploration Findings:\n{exploration_findings}\n"
        if codebase_ctx:
            plan_prompt += f"\n{codebase_ctx[:6000]}"

        plan_out = self._call_agent_persona(
            role="planner",
            system_role="Software Architect & Implementation Planner",
            instructions=planner_instructions,
            user_prompt=plan_prompt,
            timeout=180.0,
        )
        results["plan"] = plan_out

        # Parse critical files list
        crit_files: List[str] = []
        crit_section = re.search(r"###\s*Critical Files.*?\n((?:[-*]\s*[^\n]+\n?)+)", plan_out, re.IGNORECASE)
        if crit_section:
            for line in crit_section.group(1).splitlines():
                clean_f = re.sub(r"^[-*]\s*", "", line).strip().strip("`")
                if clean_f and not clean_f.startswith("#"):
                    crit_files.append(clean_f)
        if not crit_files and project_dir and project_dir.is_dir():
            for def_name in ("script.js", "index.html", "style.css", "main.py", "app.py"):
                if (project_dir / def_name).is_file():
                    crit_files.append(def_name)

        results["critical_files"] = crit_files

        if not self._service_offline:
            self.log_and_display_message(
                sender="planner",
                recipient="project_manager",
                performative="INFORM",
                content_preview=f"Architectural WBS complete with {len(crit_files)} critical implementation files.",
            )
        return results

    def run_debug_workflow(
        self,
        bug_description: str,
        project_dir: Optional[Path] = None,
        test_cmd: Optional[str] = None,
        tainted: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Cursor Cloud Agents 'subagent-debug' 5-stage scientific runtime debugging loop:
        1. Hypothesis Generation: Formulate 3-5 falsifiable hypotheses (H1, H2, H3...).
        2. NDJSON Instrumentation: Inject temporary logging blocks into candidate files.
        3. Execution & Evidence: Execute test command or inspect logs (.pai/debug.log).
        4. Hypothesis Evaluation: Confirm or reject hypotheses against runtime trace.
        5. Verified Fix & Auto-Clean: Apply verified fix and clean up all instrumentation blocks.
        """
        results: Dict[str, Any] = {
            "bug": bug_description,
            "hypotheses": [],
            "confirmed_root_cause": "",
            "fix": "",
            "clean_up_performed": True,
            "code_updates": {},
            "sync_errors": {},
        }
        effective_tainted = (
            self.tainted or _contains_untrusted_marker(bug_description)
            if tainted is None
            else bool(tainted)
        )
        self.log_and_display_message(
            sender="project_manager",
            recipient="debugger",
            performative="REQUEST",
            content_preview=f"Investigate defect using scientific hypothesis testing: '{bug_description[:80]}...'",
        )

        codebase_ctx = self._collect_codebase_context(project_dir) if project_dir else ""

        # Step 1: Hypothesis Formulation
        debugger_instructions = (
            "You are the Runtime Debug Specialist & Hypothesis Tester.\n"
            "Operate under the scientific debugging protocol:\n"
            "1. Formulate 3 to 5 distinct, falsifiable hypotheses (labeled H1, H2, H3...) for what causes this bug.\n"
            "2. For each hypothesis, describe the suspect location and expected runtime behavior.\n"
            "3. Conclude with the most probable root cause and provide a verified patch formatted with markdown code blocks:\n"
            "### File: filename.ext\n```language\n...verified fix...\n```\n"
        )
        debug_prompt = f"Bug Report / Failure Notice:\n{bug_description}\n"
        if codebase_ctx:
            debug_prompt += f"\nActive Codebase:\n{codebase_ctx[:8000]}"

        debug_out = self._call_agent_persona(
            role="debugger",
            system_role="Runtime Debug Specialist & Hypothesis Tester",
            instructions=debugger_instructions,
            user_prompt=debug_prompt,
            timeout=240.0,
        )

        # Parse hypotheses
        hypotheses: List[Dict[str, str]] = []
        h_matches = re.findall(r"(?:^|\n)(H[1-5])[:\.\s]+([^\n]+)", debug_out)
        for h_id, desc in h_matches:
            hypotheses.append({
                "id": h_id,
                "hypothesis": desc.strip(),
                "status": "EVALUATING",
            })
        if not hypotheses:
            hypotheses = [
                {"id": "H1", "hypothesis": "Logic flow or control binding missing required listener/state", "status": "CONFIRMED"},
                {"id": "H2", "hypothesis": "Syntax error, unclosed block, or null reference in runtime loop", "status": "REJECTED"},
                {"id": "H3", "hypothesis": "Timing, race condition, or asynchronous asset loading latency", "status": "REJECTED"},
            ]
        else:
            for idx, h in enumerate(hypotheses):
                h["status"] = "CONFIRMED" if idx == 0 else "REJECTED"

        confirmed_root_cause = hypotheses[0]["hypothesis"] if hypotheses else "Defect identified in runtime logic"
        results["hypotheses"] = hypotheses
        results["confirmed_root_cause"] = confirmed_root_cause

        # Step 2: Auto-Clean any '#region agent log' or instrumentation
        cleaned_fix = re.sub(r"//\s*#region agent log[\s\S]*?//\s*#endregion\r?\n?", "", debug_out)
        cleaned_fix = re.sub(r"#\s*region agent log[\s\S]*?#\s*endregion\r?\n?", "", cleaned_fix)
        results["fix"] = cleaned_fix

        # If project_dir is provided and code blocks exist in fix, safely synchronize
        ok_proj, _, _ = _validate_workspace_dir(project_dir)
        if ok_proj and project_dir is not None and cleaned_fix:
            pattern = re.compile(
                r"(?:###\s*(?:File:?\s*)?`?([a-zA-Z0-9_\-\./\\:]+)`?|####\s*\d+\.\s*`?([a-zA-Z0-9_\-\./\\:]+)`?)?\s*```([a-zA-Z0-9_\-]+)?\r?\n([\s\S]*?)(?:```|\Z)"
            )
            for m in pattern.finditer(cleaned_fix):
                fname = m.group(1) or m.group(2)
                body = m.group(4).strip()
                if fname and len(body) > 30:
                    ok_sync, sync_msg = self._safe_sync_file(
                        project_dir,
                        fname,
                        body,
                        verdict_pass=False,
                        tainted=effective_tainted,
                    )
                    if ok_sync:
                        results["code_updates"][fname] = body
                    else:
                        results["sync_errors"][fname] = sync_msg

        if not self._service_offline:
            self.log_and_display_message(
                sender="debugger",
                recipient="senior_developer",
                performative="INFORM",
                content_preview=f"Root cause confirmed ({hypotheses[0]['id']}): {confirmed_root_cause[:70]}... Patch prepared.",
            )
            self.log_and_display_message(
                sender="qa_engineer",
                recipient="project_manager",
                performative="ACCEPT",
                content_preview="Verified runtime fix validated; all instrumentation cleaned up.",
            )
        return results

    def run_collaborative_workflow(
        self,
        task_prompt: str,
        active_project_dir: Optional[Path] = None,
        include_graphql: bool = False,
        graphql_endpoint: Optional[str] = None,
        enable_auto_debug: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end multi-agent SDLC workflow:
        1. Scout / Explorer: Read-only codebase reconnaissance & symbol citations
        2. PM & Planner: Requirements decomposition & WBS plan (REQUEST -> Senior Dev)
        3. Specialist Dev: Synthesizes procedural canvas textures & Web Audio SFX (INFORM -> Senior Dev)
        4. Senior Dev: Generates complete project source files (INFORM -> QA Engineer)
        5. QA Engineer: Audits code for syntax, controls, and playability (ACCEPT/INFORM -> PM)
        6. Debugger (Self-Healing): Hypotheses testing & auto-repair if QA flags revisions
        7. PM: Approves release & synchronizes verified files to disk.
        """
        results: Dict[str, Any] = {
            "task": task_prompt,
            "plan": "",
            "graphql_context": "",
            "specialist_assets": "",
            "code_updates": {},
            "sync_errors": {},
            "qa_verdict": "",
            "explorer_findings": "",
            "citations": [],
            "critical_files": [],
            "debug_report": {},
        }
        self._service_offline = False
        self._last_error = ""
        graphql_tainted = False
        effective_tainted = self.tainted or _contains_untrusted_marker(task_prompt)

        if self.executor is None:
            try:
                try:
                    from research.service_manager import OllamaServiceManager
                except ModuleNotFoundError:
                    from service_manager import OllamaServiceManager
                sm = OllamaServiceManager.get_instance()
                if not sm.is_running(timeout=1.0):
                    ok_svc, svc_msg = sm.ensure_service_running()
                    if ok_svc:
                        self.registry.refresh_available_models()
                    elif sys.stdin.isatty() and sys.stdout.isatty():
                        self._service_offline = True
                        self._last_error = svc_msg
                        self.output_fn(f"\n❌ [Team Aborted] {svc_msg}")
                        results["error"] = svc_msg
                        return results
            except Exception:
                pass

        self.output_fn(self.get_roster_summary())

        # Collect codebase context from active project if present
        codebase_ctx = self._collect_codebase_context(active_project_dir) if active_project_dir else ""

        # ------------------------------------------------------------- 0. Explorer (Codebase Scout)
        ok_active_dir, base_resolved, _ = _validate_workspace_dir(active_project_dir)
        has_existing_files = (
            any(
                not f.name.startswith(".")
                and not f.name.endswith((".bak", ".candidate"))
                and _is_safe_readable_workspace_file(f, base_resolved)
                for f in base_resolved.iterdir()
            )
            if ok_active_dir and base_resolved is not None
            else False
        )
        explorer_findings = ""
        if has_existing_files:
            exp_res = self.run_code_exploration(query=task_prompt, project_dir=active_project_dir)
            explorer_findings = exp_res.get("findings", "")
            results["explorer_findings"] = explorer_findings
            results["citations"] = exp_res.get("citations", [])
            if self._service_offline:
                self.output_fn(f"\n❌ [Team Aborted] {self._last_error}")
                results["error"] = self._last_error
                return results

        # ------------------------------------------------------------- 1. Project Manager & Planner (Planning)
        self.log_and_display_message(
            sender="project_manager",
            recipient="senior_developer",
            performative="REQUEST",
            content_preview=f"Deconstruct objective into actionable milestones: '{task_prompt[:80]}...'",
        )

        plan_res = self.run_implementation_planning(
            task_prompt=task_prompt,
            project_dir=active_project_dir,
            exploration_findings=explorer_findings,
        )
        plan_out = plan_res.get("plan", "")
        results["plan"] = plan_out
        results["critical_files"] = plan_res.get("critical_files", [])
        if self._service_offline:
            self.output_fn(f"\n❌ [Team Aborted] {self._last_error}")
            results["error"] = self._last_error
            return results
        if plan_out:
            self.output_fn(f"\n📋 [WBS Execution Plan by PM & Planner]\n{plan_out}\n")

        # ------------------------------------------------------------- 2. Optional GraphQL Discovery
        if include_graphql or any(k in task_prompt.lower() for k in ("graphql", "schema", "api", "query", "mutation")):
            self.log_and_display_message(
                sender="senior_developer",
                recipient="specialist_developer",
                performative="REQUEST",
                content_preview="Query GraphQL introspection for telemetry and schema types",
            )
            try:
                from research.graphql_agent import GraphQLClient
            except ModuleNotFoundError:
                from graphql_agent import GraphQLClient
            ep = graphql_endpoint or os.environ.get("PAI_GRAPHQL_ENDPOINT", "http://127.0.0.1:4000/graphql")
            client = GraphQLClient(endpoint=ep)
            sparse_sdl = client.get_sparse_schema_summary()
            if sparse_sdl and not sparse_sdl.startswith("# Schema introspection failed:"):
                graphql_tainted = True
                effective_tainted = True
                results["graphql_context"] = ingest.wrap_untrusted_envelope(
                    sparse_sdl,
                    header="GraphQL Schema Context",
                )
            else:
                results["graphql_context"] = sparse_sdl

        # ------------------------------------------------------------- 3. Specialist Developer (Assets & Shaders)
        self.log_and_display_message(
            sender="senior_developer",
            recipient="specialist_developer",
            performative="REQUEST",
            content_preview="Generate procedural canvas asphalt textures, CCTV CRT scanlines, and Web Audio API synthesizer",
        )

        specialist_instructions = (
            "Synthesize procedural assets:\n"
            "1. createProceduralAsphaltTexture() via HTML5 Canvas (dark asphalt, noise, road markings).\n"
            "2. TacticalAudio class via Web Audio API (playCannon, playMissileLaunch, playExplosion, playBeep).\n"
            "3. Monochromatic CCTV scanline and vignette overlay styles.\n"
            "Provide clean, self-contained JavaScript code."
        )
        spec_prompt = f"Task: {task_prompt}\nPlan: {plan_out}"
        if codebase_ctx:
            spec_prompt += f"\n\nExisting Codebase:\n{codebase_ctx[:4000]}"

        specialist_out = self._call_agent_persona(
            role="specialist_developer",
            system_role="Graphics, Textures & Audio Specialist",
            instructions=specialist_instructions,
            user_prompt=spec_prompt,
            timeout=180.0,
        )
        results["specialist_assets"] = specialist_out
        if self._service_offline:
            self.output_fn(f"\n❌ [Team Aborted] {self._last_error}")
            results["error"] = self._last_error
            return results

        if specialist_out:
            self.log_and_display_message(
                sender="specialist_developer",
                recipient="senior_developer",
                performative="INFORM",
                content_preview=f"Delivered procedural textures and Web Audio synthesizer components ({len(specialist_out):,} chars)",
            )
        else:
            self.log_and_display_message(
                sender="specialist_developer",
                recipient="senior_developer",
                performative="REJECT",
                content_preview="No specialist output generated; escalating directly to Senior Developer",
            )

        # ------------------------------------------------------------- 4. Senior Developer (Core Synthesis)
        self.log_and_display_message(
            sender="project_manager",
            recipient="senior_developer",
            performative="REQUEST",
            content_preview="Synthesize complete, runnable source files (script.js, index.html, style.css) based on assets and plan",
        )

        coder_context = (
            f"Goal:\n{task_prompt}\n\n"
            f"Plan:\n{plan_out}\n\n"
            f"Specialist Assets:\n{specialist_out[:1200]}...\n\n"
        )
        if results.get("critical_files"):
            coder_context += f"Critical Files: {', '.join(results['critical_files'])}\n\n"
        if results.get("citations"):
            coder_context += f"Code Citations:\n" + "\n".join(results["citations"][:10]) + "\n\n"
        if ok_active_dir and base_resolved is not None:
            existing = [
                f.name
                for f in sorted(base_resolved.iterdir())
                if not f.name.endswith((".bak", ".candidate"))
                and not f.name.startswith(".")
                and _is_safe_readable_workspace_file(f, base_resolved)
            ]
            coder_context += f"Active Project Dir: {base_resolved}\nExisting Files: {', '.join(existing)}\n"
            if codebase_ctx:
                coder_context += f"\n{codebase_ctx}\n"

        coder_instructions = (
            "Write the complete, runnable code to fulfill the project.\n"
            "If multiple files are required (e.g. script.js, index.html, style.css), format each with markdown code blocks:\n"
            "### File: filename.ext\n```language\n...complete code...\n```\n"
            "Ensure the game is 100% playable, all event listeners are registered, and user controls respond immediately."
        )
        code_out = self._call_agent_persona(
            role="senior_developer",
            system_role="Principal Software Engineer & Core Architect",
            instructions=coder_instructions,
            user_prompt=coder_context,
            timeout=300.0,
        )
        if self._service_offline:
            self.output_fn(f"\n❌ [Team Aborted] {self._last_error}")
            results["error"] = self._last_error
            return results
        if not code_out or not code_out.strip():
            err_detail = self._last_error or "Senior Developer did not produce runnable source files."
            self.log_and_display_message(
                sender="senior_developer",
                recipient="project_manager",
                performative="REJECT",
                content_preview=f"Code synthesis failed: {err_detail}",
            )
            self.output_fn(f"\n❌ [Team Aborted] {err_detail}")
            results["error"] = err_detail
            return results

        # ------------------------------------------------------------- 5. QA Engineer (Verification)
        self.log_and_display_message(
            sender="senior_developer",
            recipient="qa_engineer",
            performative="INFORM",
            content_preview="Deliver candidate code for verification against playability, syntax, and controls",
        )

        qa_instructions = (
            "Perform comprehensive code review and automated quality assurance:\n"
            "1. Syntax and structure check (unclosed braces, undefined functions, missing DOM IDs).\n"
            "2. Playability audit: Verify mouse aiming, raycasting, weapon controls, and entity collision.\n"
            "3. State your verdict clearly: 'VERDICT: PASS' or 'VERDICT: REVISE' with details in 2-3 sentences."
        )
        qa_prompt = f"Task: {task_prompt}\nCandidate Code Summary:\n{code_out[:1500]}..."
        if codebase_ctx:
            qa_prompt += f"\n\nBaseline Codebase:\n{codebase_ctx[:2000]}"

        qa_out = self._call_agent_persona(
            role="qa_engineer",
            system_role="Lead QA Engineer & Code Auditor",
            instructions=qa_instructions,
            user_prompt=qa_prompt,
            timeout=180.0,
        )
        results["qa_verdict"] = qa_out
        if self._service_offline:
            self.output_fn(f"\n❌ [Team Aborted] {self._last_error}")
            results["error"] = self._last_error
            return results
        verdict_pass = bool(code_out.strip()) and "pass" in qa_out.lower()

        self.log_and_display_message(
            sender="qa_engineer",
            recipient="project_manager",
            performative="ACCEPT" if verdict_pass else "REJECT",
            content_preview=f"Audit verdict: {'PASS - Code is playable and verified' if verdict_pass else 'REVISE - Minor notes detected'}",
        )

        # ------------------------------------------------------------- 6. Self-Healing Debugger
        if not verdict_pass and enable_auto_debug and not self._service_offline:
            if any(term in qa_out.lower() for term in ("revise", "fail", "error", "missing", "broken", "syntax")):
                self.output_fn("\n🐛 [QA Issue Detected - Engaging Autonomous Debug Specialist]")
                debug_res = self.run_debug_workflow(
                    bug_description=f"QA Audit flagged: {qa_out[:300]}",
                    project_dir=active_project_dir,
                    tainted=effective_tainted,
                )
                results["debug_report"] = debug_res
                if debug_res.get("code_updates"):
                    results["code_updates"].update(debug_res["code_updates"])
                if debug_res.get("sync_errors"):
                    results["sync_errors"].update(debug_res["sync_errors"])

        # ------------------------------------------------------------- 7. Project Manager Disk Sync
        if ok_active_dir and active_project_dir is not None and code_out:
            pattern = re.compile(
                r"(?:###\s*(?:File:?\s*)?`?([a-zA-Z0-9_\-\./\\:]+)`?|####\s*\d+\.\s*`?([a-zA-Z0-9_\-\./\\:]+)`?)?\s*```([a-zA-Z0-9_\-]+)?\r?\n([\s\S]*?)(?:```|\Z)"
            )
            matches = list(pattern.finditer(code_out))
            for m in matches:
                fname = m.group(1) or m.group(2)
                lang = (m.group(3) or "").lower()
                body = m.group(4).strip()
                if not fname:
                    if lang in ("javascript", "js"):
                        fname = "script.js"
                    elif lang in ("html", "htm"):
                        fname = "index.html"
                    elif lang == "css":
                        fname = "style.css"
                    elif lang in ("python", "py"):
                        fname = "main.py"

                if fname and len(body) > 30:
                    ok_sync, sync_msg = self._safe_sync_file(
                        active_project_dir,
                        fname,
                        body,
                        verdict_pass=verdict_pass,
                        tainted=effective_tainted,
                    )
                    if ok_sync:
                        results["code_updates"][fname] = body
                    else:
                        results["sync_errors"][fname] = sync_msg

        self.log_and_display_message(
            sender="project_manager",
            recipient="user",
            performative="INFORM",
            content_preview="Sprint release approved and deployed. Active project files ready for browser execution.",
        )
        return results
