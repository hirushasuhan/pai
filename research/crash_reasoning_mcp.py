"""
PAI CRASH Structured Reasoning Tracker & STDIO MCP Server.

Implements nikkoxgonzales/crash-mcp style Cascading Reasoning & Adaptive Step History:
- Structured step records: step_number, estimated_total, purpose, context, thought,
  outcome, confidence, revises_step, revision_reason, branch_from, branch_id, is_final_step
- Automatic low-confidence revision warning when confidence < 0.5
- Exact checkpoint serialization (`checkpoint_state` / `from_checkpoint`) for stuck-recovery resume
- Synchronized persistence into ThoughtGraph (including REVISION and BRANCH edges)
- Pure-stdlib JSON-RPC 2.0 STDIO MCP Server exposing `crash_think` and `crash_summary`
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from thought_graph import ThoughtGraph, sanitize_thought_text
except ImportError:  # pragma: no cover
    from research.thought_graph import ThoughtGraph, sanitize_thought_text


VALID_PURPOSES = (
    "analysis",
    "decomposition",
    "hypothesis",
    "verification",
    "revision",
    "synthesis",
)


@dataclass
class CrashStep:
    """Single CRASH reasoning trajectory entry."""
    step_number: int
    estimated_total: int
    purpose: str
    context: str
    thought: str
    outcome: str
    confidence: float
    revises_step: Optional[int] = None
    revision_reason: Optional[str] = None
    branch_from: Optional[int] = None
    branch_id: str = "main"
    is_final_step: bool = False
    node_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CRASHTracker:
    """
    Stateful tracker for CRASH structured reasoning chains, branching, revision tracking,
    and checkpointed recovery.
    """

    LOW_CONFIDENCE_THRESHOLD = 0.5

    def __init__(
        self,
        goal: str = "",
        graph: Optional[ThoughtGraph] = None,
    ) -> None:
        self.goal = sanitize_thought_text(goal)
        self.graph: ThoughtGraph = graph or ThoughtGraph(goal=self.goal or "CRASH Reasoning")
        self.steps: List[CrashStep] = []
        self._step_to_node: Dict[int, str] = {}
        self._revised_steps: set[int] = set()

    def record_step(
        self,
        purpose: str,
        context: str,
        thought: str,
        outcome: str,
        confidence: float,
        estimated_total: int = 5,
        step_number: Optional[int] = None,
        revises_step: Optional[int] = None,
        revision_reason: Optional[str] = None,
        branch_from: Optional[int] = None,
        branch_id: str = "main",
        is_final_step: bool = False,
        citations: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Records a CRASH reasoning step, updates ThoughtGraph, and checks confidence invariants."""
        next_num = int(step_number) if step_number is not None else (len(self.steps) + 1)
        clean_purpose = purpose.strip().lower() if purpose.strip().lower() in VALID_PURPOSES else "analysis"
        conf = max(0.0, min(1.0, float(confidence)))
        est = max(next_num, int(estimated_total))

        parent_ids: List[str] = []
        if branch_from is not None and branch_from in self._step_to_node:
            parent_ids.append(self._step_to_node[branch_from])
        elif revises_step is not None and revises_step in self._step_to_node:
            parent_ids.append(self._step_to_node[revises_step])
            self._revised_steps.add(revises_step)
        elif self.steps:
            last_node = self._step_to_node.get(self.steps[-1].step_number)
            if last_node:
                parent_ids.append(last_node)

        node_type = "revision" if revises_step is not None else (
            "synthesis" if is_final_step or clean_purpose == "synthesis" else "thought"
        )
        verdict = "PENDING" if conf < self.LOW_CONFIDENCE_THRESHOLD else "CONFIRMED"

        s_context = sanitize_thought_text(context)
        s_thought = sanitize_thought_text(thought)
        s_outcome = sanitize_thought_text(outcome)
        s_rev_reason = sanitize_thought_text(revision_reason) if revision_reason else None

        content = (
            f"[CRASH Step {next_num}/{est} | {clean_purpose} | conf={conf:.2f}]\n"
            f"Thought: {s_thought}\n"
            f"Outcome: {s_outcome}"
        )
        if revises_step is not None:
            content += f"\nRevises Step {revises_step}: {s_rev_reason or 'confidence recovery'}"
        elif branch_from is not None:
            content += f"\nBranched from Step {branch_from} on '{branch_id}'"

        node = self.graph.add_node(
            content=content,
            node_type=node_type,
            role="crash_tracker",
            branch_id=branch_id,
            parent_ids=parent_ids,
            confidence=conf,
            verdict=verdict,
            citations=citations or [f"crash:step_{next_num}"],
            metadata={
                "step_number": next_num,
                "purpose": clean_purpose,
                "context_preview": s_context[:300],
                "revises_step": revises_step,
                "branch_from": branch_from,
            },
        )

        step = CrashStep(
            step_number=next_num,
            estimated_total=est,
            purpose=clean_purpose,
            context=s_context,
            thought=s_thought,
            outcome=s_outcome,
            confidence=conf,
            revises_step=revises_step,
            revision_reason=s_rev_reason,
            branch_from=branch_from,
            branch_id=branch_id,
            is_final_step=bool(is_final_step),
            node_id=node.node_id,
        )
        self.steps.append(step)
        self._step_to_node[next_num] = node.node_id

        warnings: List[str] = []
        needs_revision = conf < self.LOW_CONFIDENCE_THRESHOLD
        if needs_revision:
            warnings.append(
                f"LOW_CONFIDENCE_REVISION_RECOMMENDED: Step {next_num} confidence {conf:.2f} < {self.LOW_CONFIDENCE_THRESHOLD:.2f}."
            )

        unresolved_low = [
            s.step_number
            for s in self.steps
            if s.confidence < self.LOW_CONFIDENCE_THRESHOLD and s.step_number not in self._revised_steps
        ]
        if is_final_step and unresolved_low and not needs_revision:
            # Allow final step warning if earlier low-confidence steps were never revised
            warnings.append(
                f"UNREVISED_LOW_CONFIDENCE_STEPS: Steps {unresolved_low} had confidence < 0.5 without explicit revision."
            )

        return {
            "recorded": True,
            "step": step.to_dict(),
            "node_id": node.node_id,
            "needs_revision": needs_revision,
            "consecutive_low_confidence": self.consecutive_low_confidence_count(),
            "warnings": warnings,
            "total_steps": len(self.steps),
        }

    def consecutive_low_confidence_count(self) -> int:
        """Counts trailing unrevised steps whose confidence fell below 0.5."""
        count = 0
        for step in reversed(self.steps):
            if step.confidence < self.LOW_CONFIDENCE_THRESHOLD:
                count += 1
            else:
                break
        return count

    def get_summary(self) -> Dict[str, Any]:
        """Returns overall trajectory statistics and current branch state."""
        avg_conf = (
            round(sum(s.confidence for s in self.steps) / len(self.steps), 3)
            if self.steps
            else 0.0
        )
        branches = sorted({s.branch_id for s in self.steps}) if self.steps else []
        return {
            "goal": self.goal,
            "step_count": len(self.steps),
            "average_confidence": avg_conf,
            "last_confidence": self.steps[-1].confidence if self.steps else 0.0,
            "consecutive_low_confidence": self.consecutive_low_confidence_count(),
            "branches": branches,
            "finalized": bool(self.steps and self.steps[-1].is_final_step),
            "graph_id": self.graph.graph_id,
        }

    def to_markdown(self) -> str:
        """Formats the CRASH reasoning trajectory as concise markdown."""
        lines = [f"### CRASH Reasoning Trajectory ({len(self.steps)} steps)"]
        for s in self.steps:
            rev = f" *(revises step {s.revises_step})*" if s.revises_step else ""
            lines.append(
                f"- **Step {s.step_number}/{s.estimated_total}** [`{s.purpose}` | `{s.branch_id}` | conf `{s.confidence:.2f}`]{rev}: {s.outcome}"
            )
        return "\n".join(lines)

    def checkpoint_state(self) -> Dict[str, Any]:
        """Exports serializable state for durable pause/stuck resume."""
        return {
            "goal": self.goal,
            "graph_id": self.graph.graph_id,
            "steps": [s.to_dict() for s in self.steps],
            "revised_steps": sorted(self._revised_steps),
        }

    @classmethod
    def from_checkpoint(
        cls,
        data: Dict[str, Any],
        graph: Optional[ThoughtGraph] = None,
    ) -> "CRASHTracker":
        """Restores a CRASHTracker cleanly from serialized checkpoint data."""
        tracker = cls(goal=str(data.get("goal", "")), graph=graph)
        tracker._revised_steps = set(int(x) for x in data.get("revised_steps", []))
        for item in data.get("steps", []):
            step = CrashStep(**item)
            tracker.steps.append(step)
            if step.node_id:
                tracker._step_to_node[step.step_number] = step.node_id
        return tracker


CRASH_TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "crash_think",
        "description": (
            "Record a structured CRASH reasoning step (analysis, decomposition, hypothesis, verification, "
            "revision, or synthesis) with confidence tracking, revision links, and branching."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "step_number": {"type": "integer", "minimum": 1},
                "estimated_total": {"type": "integer", "minimum": 1},
                "purpose": {"type": "string", "enum": list(VALID_PURPOSES)},
                "context": {"type": "string"},
                "thought": {"type": "string"},
                "outcome": {"type": "string"},
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "revises_step": {"type": "integer", "minimum": 1},
                "revision_reason": {"type": "string"},
                "branch_from": {"type": "integer", "minimum": 1},
                "branch_id": {"type": "string"},
                "is_final_step": {"type": "boolean"},
            },
            "required": ["purpose", "context", "thought", "outcome", "confidence"],
        },
    },
    {
        "name": "crash_summary",
        "description": "Return the current CRASH reasoning trajectory summary and confidence metrics.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class CrashMCPServer:
    """In-process and STDIO JSON-RPC 2.0 MCP server for CRASH reasoning."""

    def __init__(self, tracker: Optional[CRASHTracker] = None) -> None:
        self.tracker = tracker or CRASHTracker(goal="MCP Session")

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handles a single JSON-RPC 2.0 request object."""
        req_id = req.get("id")
        method = str(req.get("method", ""))
        params = req.get("params") or {}

        if method == "notifications/initialized":
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "pai-crash-reasoning", "version": "1.0.0"},
                    "capabilities": {"tools": {}},
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": CRASH_TOOL_DEFINITIONS},
            }

        if method == "tools/call":
            tool_name = str(params.get("name", ""))
            args = params.get("arguments") or {}
            ok, payload = self._dispatch_tool(tool_name, args)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(payload)}],
                    "isError": not ok,
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def _dispatch_tool(self, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        if tool_name == "crash_think":
            missing = [k for k in ("purpose", "context", "thought", "outcome", "confidence") if k not in args]
            if missing:
                return False, {"error": f"Missing required argument(s): {', '.join(missing)}"}
            try:
                res = self.tracker.record_step(
                    purpose=str(args["purpose"]),
                    context=str(args["context"]),
                    thought=str(args["thought"]),
                    outcome=str(args["outcome"]),
                    confidence=float(args["confidence"]),
                    estimated_total=int(args.get("estimated_total", 5)),
                    step_number=int(args["step_number"]) if args.get("step_number") is not None else None,
                    revises_step=int(args["revises_step"]) if args.get("revises_step") is not None else None,
                    revision_reason=str(args["revision_reason"]) if args.get("revision_reason") is not None else None,
                    branch_from=int(args["branch_from"]) if args.get("branch_from") is not None else None,
                    branch_id=str(args.get("branch_id", "main")),
                    is_final_step=bool(args.get("is_final_step", False)),
                )
                return True, res
            except Exception as exc:
                return False, {"error": str(exc)}

        if tool_name == "crash_summary":
            return True, self.tracker.get_summary()

        return False, {"error": f"Unknown tool: {tool_name}"}


def run_stdio_server() -> int:  # pragma: no cover
    """Runs the CRASH MCP server over newline-delimited JSON-RPC STDIO."""
    server = CrashMCPServer()
    for line in sys.stdin:
        raw = line.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError as exc:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {exc}"}}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue
        resp = server.handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run_stdio_server())
