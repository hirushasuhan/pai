"""Graph-of-Thought Store, Subconscious Blackboard & Hybrid BM25 Retrieval for PAI.

Synthesizes architectural concepts from:
  - satellitecomponent/Neurite (non-linear Graph-of-Thought preserving long-horizon context)
  - amor71/thinking-agents (shared Subconscious Blackboard across concurrent cognitive threads)
  - /ai-engineering §2.1 (BM25 + Graph-neighborhood hybrid retrieval and context compression)

Security invariants:
  - Every node/blackboard entry is screened with `ingest.scan_secret_content` (Threat T30b)
  - Untrusted labels/text are neutralized via `ingest.defang_envelope_markers`
  - Atomic JSON persistence under `~/.pai/cowork/graphs/` with symlink/reparse rejection
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
import time
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

try:
    from research import ingest
except ModuleNotFoundError:
    import ingest


_TOKEN_RE = re.compile(r"[a-zA-Z0-9_]{2,}")
_VALID_VERDICTS = frozenset({"PENDING", "CONFIRMED", "REFUTED", "PRUNED"})
_VALID_NODE_TYPES = frozenset({
    "root", "question", "thought", "branch", "critique", "evidence", "revision", "synthesis", "action", "stall"
})
_SECRET_SUBSTR_RE = re.compile(
    r"(?:sk-(?:proj-|ant-[a-z0-9-]+-)?[A-Za-z0-9_\-]{12,}|AIza[0-9A-Za-z\-_]{20,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9\-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def sanitize_thought_text(text: str, field_name: str = "thought_node") -> str:
    """Redacts secret-like tokens and defangs prompt/envelope injection markers."""
    raw = str(text or "")
    redacted = _SECRET_SUBSTR_RE.sub("[REDACTED]", raw)
    if ingest.scan_secret_content(redacted, file_path=field_name) is not None:
        # Fail-closed redaction if another secret shape was detected by ingest scanner
        redacted = f"[REDACTED_BY_SECRET_SCANNER in {field_name}]"
    safe = ingest.defang_envelope_markers(redacted)
    return safe.replace("[[SRC:", "[ [SRC:")


def _sanitize_text(text: str, field_name: str = "thought_node") -> str:
    """Internal alias delegating to sanitize_thought_text."""
    return sanitize_thought_text(text, field_name=field_name)


@dataclass
class ThoughtNode:
    node_id: str
    content: str
    node_type: str = "thought"  # root | thought | branch | critique | evidence | revision | synthesis | action | stall
    role: str = "reasoner"
    branch_id: str = "main"
    parent_ids: List[str] = field(default_factory=list)
    children_ids: List[str] = field(default_factory=list)
    confidence: float = 0.7
    verdict: str = "PENDING"  # PENDING | CONFIRMED | REFUTED
    citations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the ThoughtNode to a JSON-compatible dictionary."""
        return asdict(self)


class ThoughtGraph:
    """Thread-safe Graph-of-Thought (Tree + DAG) with Hybrid BM25 + Neighborhood Retrieval."""

    def __init__(self, graph_id: Optional[str] = None, goal: str = "", storage_dir: Optional[Path] = None):
        self.graph_id = graph_id or f"got_{uuid.uuid4().hex[:10]}"
        self.goal = _sanitize_text(goal, "goal") if goal else ""
        self.storage_dir = storage_dir or (Path.home() / ".pai" / "cowork" / "graphs")
        self.nodes: Dict[str, ThoughtNode] = {}
        self.root_id: Optional[str] = None
        self._lock = threading.RLock()
        if self.goal:
            self.add_node(content=self.goal, node_type="root", role="user", branch_id="main", confidence=1.0, verdict="CONFIRMED")

    def add_node(
        self,
        content: str,
        node_type: str = "thought",
        role: str = "reasoner",
        branch_id: str = "main",
        parent_ids: Optional[Sequence[str]] = None,
        confidence: float = 0.7,
        verdict: str = "PENDING",
        citations: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        node_id: Optional[str] = None,
    ) -> ThoughtNode:
        """Adds a sanitized node to the graph and links parent/child edges."""
        clean_content = _sanitize_text(content, f"node:{node_type}")
        nt = node_type if node_type in _VALID_NODE_TYPES else "thought"
        vd = verdict if verdict in _VALID_VERDICTS else "PENDING"
        conf = max(0.0, min(1.0, float(confidence)))
        clean_cites = [_sanitize_text(c, "citation")[:200] for c in (citations or []) if str(c).strip()]

        with self._lock:
            nid = node_id or f"n_{len(self.nodes) + 1}_{uuid.uuid4().hex[:6]}"
            parents = [p for p in (parent_ids or []) if p in self.nodes]
            if not parents and self.root_id and nt != "root":
                parents = [self.root_id]

            node = ThoughtNode(
                node_id=nid,
                content=clean_content,
                node_type=nt,
                role=_sanitize_text(role, "role")[:48],
                branch_id=_sanitize_text(branch_id, "branch")[:48],
                parent_ids=list(dict.fromkeys(parents)),
                confidence=conf,
                verdict=vd,
                citations=clean_cites,
                metadata=dict(metadata or {}),
            )
            self.nodes[nid] = node
            if self.root_id is None or nt == "root":
                self.root_id = nid
            for pid in node.parent_ids:
                parent = self.nodes.get(pid)
                if parent and nid not in parent.children_ids:
                    parent.children_ids.append(nid)
            return node

    def link_nodes(self, parent_id: str, child_id: str) -> bool:
        """Creates a DAG dependency edge between two existing nodes."""
        with self._lock:
            p = self.nodes.get(parent_id)
            c = self.nodes.get(child_id)
            if not p or not c or parent_id == child_id:
                return False
            if child_id not in p.children_ids:
                p.children_ids.append(child_id)
            if parent_id not in c.parent_ids:
                c.parent_ids.append(parent_id)
            return True

    def update_node_verdict(self, node_id: str, verdict: str, confidence: Optional[float] = None) -> bool:
        with self._lock:
            node = self.nodes.get(node_id)
            if not node:
                return False
            if verdict in _VALID_VERDICTS:
                node.verdict = verdict
            if confidence is not None:
                node.confidence = max(0.0, min(1.0, float(confidence)))
            return True

    # ------------------------------------------------------------------ Hybrid BM25 + Graph Retrieval
    def retrieve_relevant_context(self, query: str, top_k: int = 8, max_chars: int = 6000) -> str:
        """Retrieves high-signal nodes using BM25 + 1-hop graph neighborhood + confirmed boost."""
        with self._lock:
            if not self.nodes:
                return ""
            docs = list(self.nodes.values())
            q_tokens = [t.lower() for t in _TOKEN_RE.findall(query or "")]
            doc_tokens: Dict[str, List[str]] = {
                n.node_id: [t.lower() for t in _TOKEN_RE.findall(f"{n.role} {n.node_type} {n.content}")]
                for n in docs
            }
            avg_dl = sum(len(toks) for toks in doc_tokens.values()) / max(1, len(docs))

            # Document frequency for IDF
            df: Counter[str] = Counter()
            for toks in doc_tokens.values():
                for t in set(toks):
                    df[t] += 1

            n_docs = len(docs)
            k1, b = 1.5, 0.75
            scores: Dict[str, float] = {}
            for node in docs:
                toks = doc_tokens[node.node_id]
                tf = Counter(toks)
                dl = len(toks)
                bm25 = 0.0
                for qt in q_tokens:
                    if qt not in tf:
                        continue
                    idf = math.log(1.0 + (n_docs - df[qt] + 0.5) / (df[qt] + 0.5))
                    freq = tf[qt]
                    bm25 += idf * (freq * (k1 + 1.0)) / (freq + k1 * (1.0 - b + b * (dl / max(1.0, avg_dl))))

                # Boost confirmed evidence, syntheses, and high-confidence branches; penalize refuted dead ends
                verdict_boost = 0.8 if node.verdict == "CONFIRMED" else (-0.6 if node.verdict == "REFUTED" else 0.1)
                type_boost = 0.5 if node.node_type in ("synthesis", "evidence", "root") else 0.0
                scores[node.node_id] = bm25 + verdict_boost + type_boost + (0.25 * node.confidence)

            # Graph neighborhood propagation (1-hop boost from top BM25 nodes)
            propagated = dict(scores)
            for nid, sc in scores.items():
                if sc <= 0:
                    continue
                node = self.nodes[nid]
                for nb_id in node.parent_ids + node.children_ids:
                    if nb_id in propagated:
                        propagated[nb_id] += 0.25 * sc

            ranked = sorted(docs, key=lambda n: propagated.get(n.node_id, 0.0), reverse=True)[:top_k]
            lines: List[str] = []
            used = 0
            for n in ranked:
                cite_str = f" [cites: {', '.join(n.citations[:3])}]" if n.citations else ""
                snippet = f"[{n.node_id}|{n.node_type}|{n.role}|conf={n.confidence:.2f}|{n.verdict}]{cite_str}: {n.content[:650]}"
                if used + len(snippet) > max_chars:
                    break
                lines.append(snippet)
                used += len(snippet) + 1
            return "\n".join(lines)

    # ------------------------------------------------------------------ Serialization & Mermaid
    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "graph_id": self.graph_id,
                "goal": self.goal,
                "root_id": self.root_id,
                "nodes": [asdict(n) for n in self.nodes.values()],
            }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], storage_dir: Optional[Path] = None) -> "ThoughtGraph":
        g = cls(graph_id=data.get("graph_id"), goal="", storage_dir=storage_dir)
        g.goal = _sanitize_text(data.get("goal", ""), "goal")
        g.root_id = data.get("root_id")
        for raw_n in data.get("nodes", []):
            node = ThoughtNode(**raw_n)
            g.nodes[node.node_id] = node
        return g

    def save(self, filename: Optional[str] = None) -> Path:
        """Atomically persists the ThoughtGraph under storage_dir."""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", filename or self.graph_id)
        target = self.storage_dir / f"{safe_id}.json"
        if ingest._is_symlink_or_reparse(str(target)) or ingest._is_symlink_or_reparse(str(self.storage_dir)):
            raise ValueError("Refusing to write ThoughtGraph through symlink/reparse point")
        payload = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        tmp = self.storage_dir / f".{safe_id}.{os.getpid()}.tmp"
        tmp.write_text(payload, encoding="utf-8")
        os.replace(str(tmp), str(target))
        return target

    @classmethod
    def load(cls, path: Path) -> "ThoughtGraph":
        if ingest._is_symlink_or_reparse(str(path)):
            raise ValueError("Refusing to load ThoughtGraph symlink")
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(raw, storage_dir=Path(path).parent)

    def to_mermaid(self, max_nodes: int = 35) -> str:
        """Renders a safe Mermaid flowchart TD representation for UI inspection."""
        with self._lock:
            subset = list(self.nodes.values())[:max_nodes]
            keep_ids = {n.node_id for n in subset}
            lines = ["flowchart TD"]
            for n in subset:
                label = re.sub(r'["`\n\r\[\]\(\)]', " ", n.content[:44]).strip()
                tag = f"{n.node_type}:{n.verdict[:4]} ({n.confidence:.1f})"
                lines.append(f'    {n.node_id}["{tag}: {label}"]')
            for n in subset:
                for cid in n.children_ids:
                    if cid in keep_ids:
                        lines.append(f"    {n.node_id} --> {cid}")
            return "\n".join(lines)


class SubconsciousBlackboard:
    """Shared concurrent cognitive memory (amor71/thinking-agents pattern) with secret/taint safety."""

    def __init__(self, session_id: Optional[str] = None, storage_dir: Optional[Path] = None):
        self.session_id = session_id or f"bb_{uuid.uuid4().hex[:8]}"
        self.storage_dir = storage_dir or (Path.home() / ".pai" / "cowork" / "subconscious")
        self._entries: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

    def post(
        self,
        author: str,
        topic: str,
        insight: str,
        confidence: float = 0.7,
        citations: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Posts a verified/defanged discovery onto the shared blackboard."""
        clean_insight = _sanitize_text(insight, f"blackboard:{author}")
        clean_topic = _sanitize_text(topic, "blackboard_topic")[:80]
        clean_author = _sanitize_text(author, "blackboard_author")[:48]
        entry = {
            "id": f"bb_{len(self._entries) + 1}",
            "author": clean_author,
            "topic": clean_topic,
            "insight": clean_insight,
            "confidence": max(0.0, min(1.0, float(confidence))),
            "citations": [_sanitize_text(c, "citation")[:200] for c in (citations or [])],
            "timestamp": time.time(),
        }
        with self._lock:
            self._entries.append(entry)
        return entry

    def query(self, topic_filter: Optional[str] = None, limit: int = 12) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._entries)
            if topic_filter:
                tf = topic_filter.lower()
                items = [e for e in items if tf in e["topic"].lower() or tf in e["insight"].lower()]
            return items[-limit:]

    def format_context(self, max_chars: int = 3500) -> str:
        entries = self.query(limit=15)
        if not entries:
            return ""
        lines: List[str] = []
        total = 0
        for e in entries:
            line = f"- [{e['author']} | {e['topic']} | conf={e['confidence']:.2f}] {e['insight']}"
            if total + len(line) > max_chars:
                break
            lines.append(line)
            total += len(line) + 1
        return "\n".join(lines)

    def save(self) -> Path:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", self.session_id)
        target = self.storage_dir / f"{safe_id}.json"
        if ingest._is_symlink_or_reparse(str(target)):
            raise ValueError("Refusing to write SubconsciousBlackboard symlink")
        with self._lock:
            data = json.dumps({"session_id": self.session_id, "entries": self._entries}, indent=2, ensure_ascii=False)
        target.write_text(data, encoding="utf-8")
        return target
