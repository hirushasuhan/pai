"""Context Engineering Engine & Progressive Agent Tool-Use Loop for PAI.

Implements:
  - ContextWindowAssembler: Token-budget-aware prompt layout preserving static KV-prefix ordering,
    allocating bounded slices for <learned_skills>, <mcp_tool_index>, <persistent_memory>,
    <attached_resources>, <grounded_web_context>, <project_codebase_files>, and <conversation_history>
    with automatic Observation Masking of bulky historical tool/web payloads.
  - AgentToolLoop: Progressive Tool Discovery + execution loop across Cloud native & local Ollama
    JSON-ReAct protocols, propagating taint, enforcing ToolBroker/MCPHubManager HITL gates,
    recording CRASH reasoning steps, and returning an inline Tool Timeline trace.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from research import crash_reasoning_mcp, ingest, mcp_hub
    from research.capabilities import PermissionDenied, ToolRequest
    from research.thinking_engine import ContextBudget
except ModuleNotFoundError:
    import crash_reasoning_mcp
    import ingest
    import mcp_hub
    from capabilities import PermissionDenied, ToolRequest
    from thinking_engine import ContextBudget


def estimate_tokens(text: str) -> int:
    """Fast cross-model token approximation (~4 UTF-8 chars per token)."""
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


@dataclass
class ContextTelemetry:
    num_ctx: int
    tier: str
    total_tokens_est: int
    utilization_pct: float
    compacted_turns: int
    sections: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ContextWindowAssembler:
    """Packs prompt layers into `ContextBudget.num_ctx` with Observation Masking & KV stability."""

    @staticmethod
    def compact_history_with_observation_masking(
        history_turns: List[Dict[str, str]],
        max_chars: int = 3600,
        recent_full_turns: int = 2,
        bulky_threshold: int = 900,
    ) -> Tuple[str, int]:
        """Compacts older verbose tool/code outputs while keeping recent turns intact."""
        if not history_turns:
            return "", 0
        compacted_count = 0
        total = len(history_turns)
        rendered: List[str] = []

        for idx, turn in enumerate(history_turns):
            role = str(turn.get("role", "user")).capitalize()
            content = str(turn.get("content", "")).strip()
            is_older = idx < max(0, total - recent_full_turns)
            if is_older and len(content) > bulky_threshold:
                head = content[:360].rstrip()
                tail = content[-180:].lstrip()
                content = f"{head}\n... [Observation masked: {len(content)} chars compacted] ...\n{tail}"
                compacted_count += 1
            rendered.append(f"{role}: {content}")

        joined = "\n".join(rendered)
        if len(joined) > max_chars:
            joined = "... [earlier turns truncated to fit context budget] ...\n" + joined[-(max_chars - 60) :]
        return joined, compacted_count

    @classmethod
    def assemble(
        cls,
        budget: ContextBudget,
        cognitive_system_prompt: str,
        user_query: str,
        tool_index_prompt: str = "",
        attached_resources: str = "",
        grounding_context: str = "",
        project_context: str = "",
        extra_guidance: str = "",
        history_turns: Optional[List[Dict[str, str]]] = None,
    ) -> Tuple[str, ContextTelemetry]:
        """Assembles prompt sections strictly bounded within `budget.num_ctx` tokens."""
        max_total_chars = max(4000, (budget.num_ctx - min(budget.max_tokens, budget.num_ctx // 3)) * 4)
        # Reserve space for system prompt + user query first
        sys_str = cognitive_system_prompt.strip()
        usr_str = user_query.strip()
        remaining = max(1200, max_total_chars - len(sys_str) - len(usr_str) - 256)

        sections: Dict[str, int] = {
            "system_core": estimate_tokens(sys_str),
            "user_query": estimate_tokens(usr_str),
        }

        def _take(label: str, raw: str, share: float) -> str:
            nonlocal remaining
            clean = (raw or "").strip()
            if not clean or remaining <= 120:
                return ""
            cap = min(remaining, max(300, int(remaining * share)))
            clipped = clean[:cap]
            if len(clean) > cap:
                clipped = clipped.rstrip() + "\n... [budget truncated]"
            remaining -= len(clipped)
            sections[label] = estimate_tokens(clipped)
            return clipped

        tool_blk = _take("mcp_tool_index", tool_index_prompt, 0.18)
        res_blk = _take("attached_resources", attached_resources, 0.22)
        web_blk = _take("grounded_web", grounding_context, 0.25)
        proj_blk = _take("project_files", project_context, 0.45)

        hist_text, compacted_turns = cls.compact_history_with_observation_masking(
            history_turns or [],
            max_chars=max(400, remaining),
        )
        if hist_text:
            sections["history"] = estimate_tokens(hist_text)

        parts = [sys_str]
        if tool_blk:
            parts.append(f"<mcp_tool_index>\n{tool_blk}\n</mcp_tool_index>")
        if res_blk:
            parts.append(f"<attached_resources>\n{res_blk}\n</attached_resources>")
        if web_blk:
            parts.append(f"<grounded_web_context>\n{web_blk}\n</grounded_web_context>")
        if proj_blk:
            parts.append(f"<project_codebase_files>\n{proj_blk}\n</project_codebase_files>")
        if hist_text:
            parts.append(f"<recent_conversation_context>\n{hist_text}\n</recent_conversation_context>")
        if extra_guidance.strip():
            parts.append(extra_guidance.strip())
        parts.append(f"User Query:\n{usr_str}")

        assembled = "\n\n".join(parts)
        total_tok = estimate_tokens(assembled)
        util = round(min(100.0, (total_tok / max(1, budget.num_ctx)) * 100.0), 1)
        telemetry = ContextTelemetry(
            num_ctx=budget.num_ctx,
            tier=budget.tier,
            total_tokens_est=total_tok,
            utilization_pct=util,
            compacted_turns=compacted_turns,
            sections=sections,
        )
        return assembled, telemetry


_TOOL_CALL_RE = re.compile(r"<tool_call>\s*(\{[\s\S]*?\})\s*</tool_call>", re.IGNORECASE)
_META_TOOL_PROTOCOL = """<mcp_meta_tool_protocol>
You have Progressive Tool Discovery meta-tools connected via PAI's MCP Hub.
When you need live external data or tool actions, emit EXACTLY ONE XML block and wait for its <tool_result>:
<tool_call>{"tool": "pai_search_tools", "args": {"query": "github issues"}}</tool_call>
Available meta-tools:
1. pai_search_tools(query, server?) -> Find relevant MCP tool names without loading giant schemas.
2. pai_describe_tool(server, tool_name) -> Fetch full JSON inputSchema for one tool.
3. pai_call_tool(server, tool_name, arguments) -> Execute a tool through PAI's ToolBroker firewall.
4. pai_read_resource(server, uri) -> Read an MCP URI resource cleanly inside <untrusted_content>.
Once you have enough evidence, reply directly to the user WITHOUT emitting <tool_call>.
</mcp_meta_tool_protocol>"""


@dataclass
class PendingHITLToolAction:
    server: str
    tool: str
    arguments: Dict[str, Any]
    risk: str
    tainted: bool
    reason: str


@dataclass
class ToolLoopOutcome:
    final_reply: str
    tool_trace: List[Dict[str, Any]] = field(default_factory=list)
    context_tainted: bool = False
    pending_hitl: Optional[PendingHITLToolAction] = None
    turns_used: int = 0


class AgentToolLoop:
    """Progressive Discovery + Safe ReAct Loop integrating MCPHubManager & CRASHTracker."""

    def __init__(
        self,
        hub: mcp_hub.MCPHubManager,
        llm_fn: Callable[[str, str], Tuple[bool, str]],
        max_turns: int = 5,
        crash: Optional[crash_reasoning_mcp.CRASHTracker] = None,
    ) -> None:
        self.hub = hub
        self.llm_fn = llm_fn
        self.max_turns = max(1, min(10, int(max_turns)))
        self.crash = crash

    @staticmethod
    def parse_tool_call(raw_output: str) -> Optional[Dict[str, Any]]:
        m = _TOOL_CALL_RE.search(raw_output or "")
        if not m:
            return None
        try:
            obj = json.loads(m.group(1))
            if isinstance(obj, dict) and obj.get("tool"):
                return obj
        except json.JSONDecodeError:
            return None
        return None

    def run(
        self,
        system_prompt: str,
        user_prompt: str,
        initial_tainted: bool = False,
        confirm_fn: Optional[Callable[[ToolRequest], bool]] = None,
    ) -> ToolLoopOutcome:
        """Runs bounded multi-turn discovery + tool execution when live MCP servers exist."""
        live_clients = self.hub.get_live_clients()
        if not live_clients:
            ok, reply = self.llm_fn(system_prompt, user_prompt)
            return ToolLoopOutcome(final_reply=reply if ok else "", context_tainted=initial_tainted, turns_used=1)

        tainted = bool(initial_tainted)
        trace: List[Dict[str, Any]] = []
        scratch: List[str] = []
        augmented_sys = f"{system_prompt}\n\n{_META_TOOL_PROTOCOL}"

        last_reply = ""
        for turn_idx in range(1, self.max_turns + 1):
            turn_user = user_prompt
            if scratch:
                turn_user = f"{user_prompt}\n\n<tool_execution_history>\n" + "\n".join(scratch[-6:]) + "\n</tool_execution_history>"

            ok, raw = self.llm_fn(augmented_sys, turn_user)
            if not ok:
                break
            last_reply = raw

            call_obj = self.parse_tool_call(raw)
            if not call_obj:
                clean = _TOOL_CALL_RE.sub("", raw).strip()
                return ToolLoopOutcome(
                    final_reply=clean,
                    tool_trace=trace,
                    context_tainted=tainted,
                    turns_used=turn_idx,
                )

            meta_name = str(call_obj.get("tool", "")).strip()
            args = call_obj.get("args") if isinstance(call_obj.get("args"), dict) else {}
            t0 = time.perf_counter()

            if meta_name == "pai_search_tools":
                res_list = self.hub.tool_index.search_tools(
                    query=str(args.get("query", "")),
                    server=args.get("server"),
                )
                obs = json.dumps(res_list, ensure_ascii=False)[:1800]
                trace.append({"turn": turn_idx, "tool": meta_name, "args": args, "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1)})
                scratch.append(f"<tool_result tool=\"{meta_name}\">{obs}</tool_result>")
            elif meta_name == "pai_describe_tool":
                srv = str(args.get("server", ""))
                tname = str(args.get("tool_name") or args.get("tool") or "")
                schema = self.hub.tool_index.describe_tool(srv, tname)
                obs = json.dumps(schema, ensure_ascii=False)[:2200] if schema else f"Tool '{srv}:{tname}' not found."
                trace.append({"turn": turn_idx, "tool": f"{srv}:{tname}", "args": args, "ok": bool(schema), "ms": round((time.perf_counter() - t0) * 1000, 1)})
                scratch.append(f"<tool_result tool=\"{meta_name}\">{obs}</tool_result>")
            elif meta_name == "pai_read_resource":
                srv = str(args.get("server", ""))
                uri = str(args.get("uri", ""))
                client = live_clients.get(srv)
                if not client:
                    obs = f"Error: MCP server '{srv}' not connected."
                    trace.append({"turn": turn_idx, "tool": meta_name, "args": args, "ok": False, "ms": 0.0})
                else:
                    try:
                        wrapped_res, redacted = client.read_resource(uri)
                        tainted = True
                        obs = wrapped_res[:2400]
                        trace.append({"turn": turn_idx, "tool": f"{srv}:resource", "args": {"uri": uri, "redacted": redacted}, "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1)})
                    except Exception as exc:
                        obs = f"Resource error: {exc}"
                        trace.append({"turn": turn_idx, "tool": meta_name, "args": args, "ok": False, "ms": 0.0})
                scratch.append(f"<tool_result tool=\"{meta_name}\">{obs}</tool_result>")
            elif meta_name == "pai_call_tool":
                srv = str(args.get("server", ""))
                tname = str(args.get("tool_name") or args.get("tool") or "")
                targs = args.get("arguments") if isinstance(args.get("arguments"), dict) else {}
                try:
                    t_res = self.hub.execute_tool(
                        server=srv,
                        tool_name=tname,
                        arguments=targs,
                        tainted=tainted,
                        confirm=confirm_fn,
                    )
                    tainted = tainted or t_res.tainted
                    obs = (t_res.sanitized_text or t_res.raw_text)[:2400]
                    trace.append({"turn": turn_idx, "tool": f"{srv}:{tname}", "args": targs, "ok": not t_res.is_error, "redacted": t_res.secret_redacted, "ms": round((time.perf_counter() - t0) * 1000, 1)})
                    scratch.append(f"<tool_result tool=\"{srv}:{tname}\">{obs}</tool_result>")
                except Exception as exc:
                    if isinstance(exc, PermissionDenied) or type(exc).__name__ == "PermissionDenied":
                        trace.append({"turn": turn_idx, "tool": f"{srv}:{tname}", "args": targs, "ok": False, "hitl_required": True, "error": str(exc)})
                        return ToolLoopOutcome(
                            final_reply=_TOOL_CALL_RE.sub("", raw).strip() or f"Action `{srv}:{tname}` paused for user confirmation.",
                            tool_trace=trace,
                            context_tainted=tainted,
                            pending_hitl=PendingHITLToolAction(
                                server=srv,
                                tool=tname,
                                arguments=targs,
                                risk="WRITE_OR_DESTRUCTIVE",
                                tainted=tainted,
                                reason=str(exc),
                            ),
                            turns_used=turn_idx,
                        )
                    obs = f"Tool error: {exc}"
                    trace.append({"turn": turn_idx, "tool": f"{srv}:{tname}", "args": targs, "ok": False, "error": str(exc)})
                    scratch.append(f"<tool_result tool=\"{srv}:{tname}\">{obs}</tool_result>")
            else:
                scratch.append(f"<tool_result tool=\"{meta_name}\">Unknown meta-tool. Use pai_search_tools, pai_describe_tool, or pai_call_tool.</tool_result>")

            if self.crash is not None:
                self.crash.record_step(
                    purpose="verification",
                    context=f"MCP tool turn {turn_idx}: {meta_name}",
                    thought=f"Invoked {meta_name} with args {json.dumps(args)[:200]}",
                    outcome=scratch[-1][:300] if scratch else "",
                    confidence=0.75 if trace and trace[-1].get("ok") else 0.45,
                )

        # Max turns reached: request crisp final synthesis without further tool calls
        synth_user = f"{user_prompt}\n\n<tool_execution_history>\n" + "\n".join(scratch[-6:]) + "\n</tool_execution_history>\nSynthesize your final response now with NO further tool_call tags."
        ok_fin, fin_reply = self.llm_fn(system_prompt, synth_user)
        final_out = fin_reply if ok_fin else _TOOL_CALL_RE.sub("", last_reply).strip()
        return ToolLoopOutcome(
            final_reply=final_out,
            tool_trace=trace,
            context_tainted=tainted,
            turns_used=self.max_turns,
        )
