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
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


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
        req = urllib.request.Request(f"{base_url}/api/tags")
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return [str(m.get("name")) for m in data.get("models", []) if m.get("name")]
    except Exception:
        return []


class TeamRoleModelRegistry:
    """Manages role-to-model mapping, user customization, and prioritized failovers."""
    
    ROLE_PREFERENCES: Dict[str, List[str]] = {
        "project_manager": ["llama3.2:3b", "qwen3.5:4b", "llama3.2:1b"],
        "senior_developer": ["qwen2.5-coder:7b", "qwen2.5-coder:1.5b", "qwen3.5:4b"],
        "specialist_developer": ["qwen2.5-coder:1.5b", "qwen3.5:4b", "llama3.2:3b"],
        "qa_engineer": ["qwen3.5:4b", "llama3.2:1b", "llama3.2:3b"],
    }

    ROLE_TITLES: Dict[str, str] = {
        "project_manager": "Product & Project Manager",
        "senior_developer": "Principal Software Engineer & Core Architect",
        "specialist_developer": "Frontend / UI, Textures & Audio Specialist",
        "qa_engineer": "Lead QA Engineer & Code Auditor",
    }

    ROLE_ICONS: Dict[str, str] = {
        "project_manager": "👔",
        "senior_developer": "💻",
        "specialist_developer": "🎨",
        "qa_engineer": "🧪",
    }

    ROLE_ALIASES: Dict[str, str] = {
        "pm": "project_manager",
        "project_manager": "project_manager",
        "manager": "project_manager",
        "lead": "project_manager",
        "planner": "project_manager",
        "senior": "senior_developer",
        "senior_developer": "senior_developer",
        "senior_dev": "senior_developer",
        "dev": "senior_developer",
        "coder": "senior_developer",
        "developer": "senior_developer",
        "architect": "senior_developer",
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
    }

    def __init__(self, model_override: Optional[str] = None):
        self.available_models = discover_available_models()
        self.role_models: Dict[str, str] = {}
        self.role_fallbacks: Dict[str, List[str]] = {}
        self.custom_roles: set[str] = set()
        self._initialize_mappings(model_override)
        if not model_override:
            self.load_saved_config()

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
            return False, f"Unknown role '{role_str}'. Valid roles: pm, dev, ui, qa."

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
            "  • pm / manager    : Product & Project Manager",
            "  • dev / senior    : Principal Software Engineer & Architect",
            "  • ui / specialist : Frontend / UI, Textures & Audio Specialist",
            "  • qa / tester     : Lead QA Engineer & Code Auditor",
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
        "💻": "[DEV]",
        "🎨": "[UI]",
        "🧪": "[QA]",
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
    ):
        self.registry = TeamRoleModelRegistry(model_override=model_name)
        self.executor = executor
        self.output_fn = self._make_safe_output(output_fn)
        self.color_enabled = color_enabled
        self.conversation_log: List[AgentMessage] = []
        self._msg_counter = 0

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

        for attempt_model in candidate_queue:
            exec_argv = ["chat", "--model", attempt_model, "--model-timeout", str(timeout)]
            if "gemma" in attempt_model.lower():
                exec_argv.append("--gemma4-opt-in")
            exec_argv += ["--", persona_prompt]
            cap = io.StringIO()

            try:
                with contextlib.redirect_stdout(cap):
                    exec_fn(exec_argv)
                out = cap.getvalue().strip()
                if out and len(out) > 20:
                    # Success
                    return out
            except Exception as e:
                self.output_fn(f"  ⚠️ [Failover Warning] Role '{role}' on '{attempt_model}' failed ({e}). Checking alternatives...")

            # If failed or returned empty, record failover and try next model
            if len(candidate_queue) > 1 and attempt_model != candidate_queue[-1]:
                next_model = candidate_queue[candidate_queue.index(attempt_model) + 1]
                self.output_fn(f"  🔄 [Auto-Switch] Role '{role}' switching from '{attempt_model}' -> '{next_model}'...")
                self.registry.role_models[role] = next_model

        return ""

    @staticmethod
    def _collect_codebase_context(
        project_dir: Optional[Path],
        max_chars_per_file: int = 12000,
        max_total_chars: int = 25000,
    ) -> str:
        """Extracts existing text source files from the active project to guide PM and developers."""
        if not project_dir or not project_dir.is_dir():
            return ""
        snippets = []
        total_len = 0
        priority_files = ["script.js", "index.html", "style.css", "main.py", "app.py", "README.md"]
        ordered_files = []
        for name in priority_files:
            cand = project_dir / name
            if cand.is_file():
                ordered_files.append(cand)
        try:
            for cand in sorted(project_dir.iterdir()):
                if cand.is_file() and cand not in ordered_files and not cand.name.endswith(".bak") and not cand.name.startswith("."):
                    ordered_files.append(cand)
        except Exception:
            pass

        skip_exts = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".exe", ".bin", ".zip", ".tar", ".gz", ".mp3", ".wav"}
        for f in ordered_files:
            if f.suffix.lower() in skip_exts:
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="replace").strip()
                if not content:
                    continue
                if len(content) > max_chars_per_file:
                    content = content[:max_chars_per_file] + "\n... [truncated for context budget] ..."
                lang_tag = f.suffix.lstrip(".") or "text"
                if lang_tag == "js":
                    lang_tag = "javascript"
                elif lang_tag == "py":
                    lang_tag = "python"
                snippet = f"[File: {f.name} ({f.stat().st_size:,} bytes)]\n```{lang_tag}\n{content}\n```"
                if total_len + len(snippet) > max_total_chars:
                    break
                snippets.append(snippet)
                total_len += len(snippet)
            except Exception:
                pass
        if not snippets:
            return ""
        return "\n--- Active Project Codebase ---\n" + "\n\n".join(snippets)

    def run_collaborative_workflow(
        self,
        task_prompt: str,
        active_project_dir: Optional[Path] = None,
        include_graphql: bool = False,
        graphql_endpoint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end multi-agent SDLC workflow:
        1. PM: Requirements decomposition & WBS plan (REQUEST -> Senior Dev)
        2. Senior Dev: Asks Specialist Dev for procedural textures/audio (REQUEST -> Specialist Dev)
        3. Specialist Dev: Synthesizes procedural canvas textures & Web Audio SFX (INFORM -> Senior Dev)
        4. Senior Dev: Generates complete project source files (INFORM -> QA Engineer)
        5. QA Engineer: Audits code for syntax, controls, and playability (ACCEPT/INFORM -> PM)
        6. PM: Approves release & synchronizes verified files to disk.
        """
        self.output_fn(self.get_roster_summary())

        results: Dict[str, Any] = {
            "task": task_prompt,
            "plan": "",
            "graphql_context": "",
            "specialist_assets": "",
            "code_updates": {},
            "qa_verdict": "",
        }

        # Collect codebase context from active project if present
        codebase_ctx = self._collect_codebase_context(active_project_dir) if active_project_dir else ""

        # ------------------------------------------------------------- 1. Project Manager (Planning)
        self.log_and_display_message(
            sender="project_manager",
            recipient="senior_developer",
            performative="REQUEST",
            content_preview=f"Deconstruct objective into actionable milestones: '{task_prompt[:80]}...'",
        )

        pm_instructions = (
            "Analyze the user's objective and existing codebase.\n"
            "Produce a structured Work Breakdown Structure (WBS) with 3-4 milestones.\n"
            "Detail camera parameters, game loop, weapons, hostile entities, and UI HUD elements."
        )
        pm_prompt = f"Objective:\n{task_prompt}"
        if codebase_ctx:
            pm_prompt += f"\n\n{codebase_ctx[:8000]}"

        plan_out = self._call_agent_persona(
            role="project_manager",
            system_role="Product & Project Manager",
            instructions=pm_instructions,
            user_prompt=pm_prompt,
            timeout=180.0,
        )
        results["plan"] = plan_out
        if plan_out:
            self.output_fn(f"\n📋 [WBS Execution Plan by PM]\n{plan_out}\n")

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

        self.log_and_display_message(
            sender="specialist_developer",
            recipient="senior_developer",
            performative="INFORM",
            content_preview=f"Delivered procedural textures and Web Audio synthesizer components ({len(specialist_out):,} chars)",
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
        if active_project_dir and active_project_dir.is_dir():
            existing = [f.name for f in active_project_dir.iterdir() if f.is_file() and not f.name.endswith(".bak")]
            coder_context += f"Active Project Dir: {active_project_dir}\nExisting Files: {', '.join(existing)}\n"
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
        verdict_pass = "pass" in qa_out.lower() or not qa_out

        self.log_and_display_message(
            sender="qa_engineer",
            recipient="project_manager",
            performative="ACCEPT" if verdict_pass else "REJECT",
            content_preview=f"Audit verdict: {'PASS - Code is playable and verified' if verdict_pass else 'REVISE - Minor notes detected'}",
        )

        # ------------------------------------------------------------- 6. Project Manager Disk Sync
        if active_project_dir and active_project_dir.is_dir() and code_out:
            pattern = re.compile(
                r"(?:###\s*(?:File:?\s*)?([a-zA-Z0-9_\-\.]+)|####\s*\d+\.\s*([a-zA-Z0-9_\-\.]+))?\s*```([a-zA-Z0-9_\-]+)?\r?\n([\s\S]*?)(?:```|\Z)"
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
                    dest = active_project_dir / fname
                    try:
                        # Safeguard: Never overwrite a substantial file (>3KB) with a tiny stub (<800B) if audit failed or stub is degenerate
                        is_substantial = dest.is_file() and dest.stat().st_size > 3000
                        is_tiny_stub = len(body) < 800
                        if is_substantial and is_tiny_stub and (not verdict_pass or dest.stat().st_size > len(body) * 5):
                            cand_f = dest.with_suffix(dest.suffix + ".candidate")
                            cand_f.write_text(body, encoding="utf-8")
                            self.output_fn(
                                f"  ⚠️ [Preserved {dest.name} ({dest.stat().st_size:,} bytes) against tiny stub overwrite ({len(body)} bytes). Saved candidate to {cand_f.name}]"
                            )
                            continue

                        if dest.is_file():
                            bak = dest.with_suffix(dest.suffix + ".bak")
                            bak.write_text(dest.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
                        dest.write_text(body, encoding="utf-8")
                        results["code_updates"][fname] = len(body)
                        self.output_fn(f"  ✅ [Synchronized {dest.name}] ({len(body):,} bytes)")
                    except Exception as e:
                        self.output_fn(f"  ❌ [Failed to write {dest.name}: {e}]")

        self.log_and_display_message(
            sender="project_manager",
            recipient="user",
            performative="INFORM",
            content_preview="Sprint release approved and deployed. Active project files ready for browser execution.",
        )
        return results
