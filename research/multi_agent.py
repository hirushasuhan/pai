"""
Multi-Agent Orchestration Subsystem for Personal Agentic AI (PAI).
Coordinates specialized local agent personas:
  - Planner Agent: Decomposes goals into actionable milestones.
  - Coder Agent: Synthesizes, verifies, and modifies code.
  - GraphQL / Tool Agent: Interacts with strongly typed data graphs and MCP servers.
  - Reviewer Agent: Audits code quality, performance, and correctness.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class AgentMessage:
    sender: str
    role: str
    content: str
    timestamp: float = field(default_factory=time.time)


class MultiAgentTeam:
    """
    Coordinates collaborative multi-agent execution across specialized roles.
    """
    def __init__(
        self,
        model_name: Optional[str] = None,
        executor: Optional[Callable[[List[str]], int]] = None,
        output_fn: Optional[Callable[[str], None]] = None,
        color_enabled: bool = False,
    ):
        self.model_name = model_name
        self.executor = executor
        self.output_fn = output_fn or print
        self.color_enabled = color_enabled
        self.conversation_log: List[AgentMessage] = []

    def _call_agent_persona(self, system_role: str, instructions: str, user_prompt: str) -> str:
        """Invokes the resident local model under a specialized persona prompt."""
        persona_prompt = (
            f"You are the {system_role} in an autonomous Multi-Agent AI team.\n"
            f"Role Directive:\n{instructions}\n\n"
            f"Task Information & Team State:\n{user_prompt}\n\n"
            f"Deliver your response clearly, concisely, and specifically for your role."
        )

        exec_argv = ["chat"]
        if self.model_name:
            exec_argv += ["--model", self.model_name]
        exec_argv += ["--", persona_prompt]

        from research.shell import CaptureStream
        cap = CaptureStream()

        import contextlib
        try:
            from research.shell import execute_subcommand
            exec_fn = self.executor or execute_subcommand
            with contextlib.redirect_stdout(cap):
                exec_fn(exec_argv)
            return cap.getvalue().strip()
        except Exception as e:
            return f"Agent invocation error: {e}"

    def run_collaborative_workflow(
        self,
        task_prompt: str,
        active_project_dir: Optional[Path] = None,
        include_graphql: bool = False,
        graphql_endpoint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes a 3-stage or 4-stage multi-agent collaboration:
        1. Planner Agent designs the breakdown.
        2. (Optional) GraphQL / Tool Agent inspects schema and extracts sparse queries.
        3. Coder Agent implements and updates the code.
        4. Reviewer Agent audits the code and confirms completion.
        """
        results: Dict[str, Any] = {
            "task": task_prompt,
            "plan": "",
            "graphql_context": "",
            "code_updates": {},
            "review": "",
        }

        # ------------------------------------------------------------- Stage 1: Planner
        self.output_fn("🤖 [Planner Agent] Formulating structured execution plan...")
        planner_instructions = (
            "Analyze the user's objective. Break it down into clear, sequenced milestones.\n"
            "Identify key files to update, core Three.js / game / logic mechanics, UI elements, and API dependencies.\n"
            "Keep the plan concise (3-5 bullet points)."
        )
        plan_out = self._call_agent_persona(
            system_role="Master System Planner",
            instructions=planner_instructions,
            user_prompt=task_prompt,
        )
        results["plan"] = plan_out
        self.output_fn(f"\n📋 [Execution Plan]\n{plan_out}\n")

        # ------------------------------------------------------------- Stage 2: GraphQL / Tool Agent (Optional)
        if include_graphql or any(k in task_prompt.lower() for k in ("graphql", "schema", "api", "query", "mutation")):
            self.output_fn("🌐 [GraphQL / Tool Agent] Discovering schema and constructing sparse operations...")
            from research.graphql_agent import GraphQLClient
            ep = graphql_endpoint or os.environ.get("PAI_GRAPHQL_ENDPOINT", "http://127.0.0.1:4000/graphql")
            client = GraphQLClient(endpoint=ep)
            sparse_sdl = client.get_sparse_schema_summary()
            results["graphql_context"] = sparse_sdl
            self.output_fn(f"  • Retrieved sparse schema ({len(sparse_sdl)} chars)\n")

        # ------------------------------------------------------------- Stage 3: Coder Agent
        self.output_fn("💻 [Coder Agent] Writing and updating code based on the execution plan...")
        coder_context = f"Goal:\n{task_prompt}\n\nPlan:\n{plan_out}"
        if results.get("graphql_context"):
            coder_context += f"\n\nGraphQL Schema:\n{results['graphql_context']}"
        if active_project_dir and active_project_dir.is_dir():
            coder_context += f"\n\nActive Project: {active_project_dir}"
            existing_files = [f.name for f in active_project_dir.iterdir() if f.is_file() and not f.name.endswith(".bak")]
            coder_context += f"\nExisting files in project: {', '.join(existing_files)}"

        coder_instructions = (
            "Write the complete, runnable code to fulfill the plan.\n"
            "If multiple files are required (e.g. script.js, index.html), output each inside a markdown code block\n"
            "with a header indicating the filename, e.g.:\n"
            "### File: script.js\n```javascript\n...\n```\n"
            "Do not omit code or use placeholder comments."
        )
        code_out = self._call_agent_persona(
            system_role="Principal Software Engineer & Game Architect",
            instructions=coder_instructions,
            user_prompt=coder_context,
        )

        # ------------------------------------------------------------- Sync Code to Active Project
        if active_project_dir and active_project_dir.is_dir():
            # Robust code block extraction (including unclosed blocks)
            pattern = re.compile(r"(?:###\s*(?:File:?\s*)?([a-zA-Z0-9_\-\.]+)|####\s*\d+\.\s*([a-zA-Z0-9_\-\.]+))?\s*```([a-zA-Z0-9_\-]+)?\r?\n([\s\S]*?)(?:```|$)", re.MULTILINE)
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
                        if dest.is_file():
                            bak = dest.with_suffix(dest.suffix + ".bak")
                            bak.write_text(dest.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
                        dest.write_text(body, encoding="utf-8")
                        results["code_updates"][fname] = len(body)
                        self.output_fn(f"  ✅ [Updated {dest}] ({len(body):,} bytes)")
                    except Exception as e:
                        self.output_fn(f"  ❌ [Failed to write {dest}: {e}]")

        # ------------------------------------------------------------- Stage 4: Reviewer Agent
        self.output_fn("\n🔍 [Reviewer Agent] Auditing implementation against requirements...")
        rev_instructions = (
            "Review the plan and the generated code.\n"
            "Verify syntax, event loops, Three.js camera/materials, collision logic, and user aesthetic directives.\n"
            "Confirm whether requirements were fully satisfied in 2-3 sentences."
        )
        review_out = self._call_agent_persona(
            system_role="Senior Code Auditor & QA Lead",
            instructions=rev_instructions,
            user_prompt=f"Task:\n{task_prompt}\n\nGenerated Code Summary:\n{code_out[:1000]}...",
        )
        results["review"] = review_out
        self.output_fn(f"{review_out}\n")
        self.output_fn("✨ [Multi-Agent Collaboration Complete] All tasks delivered.")

        return results
