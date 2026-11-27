"""Composable Plugin Bundle Manager & Security Scanner for PAI.

Inspired by `hashgraph-online/awesome-ai-plugins` (plugin-scanner + HOL Guard)
and `SKILL.md` modular agent behavioral packaging:
  - Scans plugin manifests, SKILL.md instructions, bundled MCP commands, and URLs
    to compute a deterministic Trust Score (0-100) and fail-closed block verdict.
  - Supports portable bundles under ~/.pai/plugins/<id>/pai-plugin.json (+ SKILL.md)
    as well as backward-compatible ~/.pai/plugins.json entries.
  - Feeds active behavioral skills cleanly into `format_cognitive_system_prompt(skills_context=...)`.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    from research import ingest, mcp_client, net_guard
except ModuleNotFoundError:
    import ingest
    import mcp_client
    import net_guard


_PLUGIN_INJECTION_PATTERNS = (
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"),
    re.compile(r"(?i)\boverride\s+(?:system|safety|all)\s+rules\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?instructions\b"),
    re.compile(r"(?i)\bexfiltrate\b.*\b(?:key|token|secret|password|\.env)\b"),
    re.compile(r"(?i)<\s*script[^>]*>"),
    re.compile(r"\[\[SRC:"),
)


@dataclass
class PluginScanResult:
    trust_score: int
    trust_badge: str  # VERIFIED | SCOPED | REVIEW | BLOCKED
    blocked: bool
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PluginScanner:
    """Static security & quality scanner for PAI custom plugins and SKILL.md bundles."""

    @staticmethod
    def scan(manifest: Dict[str, Any], skill_text: str = "") -> PluginScanResult:
        score = 100
        findings: List[str] = []
        critical_block = False

        combined_text = "\n".join([
            str(manifest.get("name", "")),
            str(manifest.get("description", "")),
            str(manifest.get("skill_prompt", "")),
            str(skill_text or ""),
        ])

        # 1. Secret leak scan
        secret_hit = ingest.scan_secret_content(combined_text)
        if secret_hit is not None:
            score -= 50
            critical_block = True
            findings.append(f"CRITICAL: Secret material detected ({secret_hit}).")

        # 2. Prompt injection / XSS scan
        for pat in _PLUGIN_INJECTION_PATTERNS:
            if pat.search(combined_text):
                score -= 45
                critical_block = True
                findings.append(f"CRITICAL: Unsafe instruction override/script pattern matched ({pat.pattern[:48]}).")

        if ingest.UNTRUSTED_BEGIN_MARKER in combined_text or ingest.UNTRUSTED_END_MARKER in combined_text:
            score -= 40
            critical_block = True
            findings.append("CRITICAL: Forged untrusted-envelope delimiter found inside plugin instructions.")

        # 3. Bundled MCP server command / URL checks
        bundled_mcps = manifest.get("mcp_servers") or []
        if isinstance(bundled_mcps, list):
            for srv in bundled_mcps:
                if not isinstance(srv, dict):
                    continue
                transport = str(srv.get("transport", "stdio")).lower()
                cmd = str(srv.get("command") or srv.get("url") or "").strip()
                if transport in ("http", "sse", "streamable_http"):
                    try:
                        net_guard.validate_url(cmd, allow_private=False)
                    except Exception as exc:
                        if not mcp_client._is_loopback_http_url(cmd):
                            score -= 35
                            critical_block = True
                            findings.append(f"CRITICAL: Bundled MCP URL blocked by SSRF policy ({exc}).")
                        else:
                            score -= 10
                            findings.append("NOTE: Uses loopback HTTP MCP endpoint.")
                elif cmd:
                    try:
                        mcp_client.parse_mcp_command_string(cmd, allow_unpinned=False)
                    except Exception as exc:
                        score -= 30
                        critical_block = True
                        findings.append(f"CRITICAL: Bundled MCP command failed hygiene check ({exc}).")

        # 4. Outbound domain allowlist check
        perms = manifest.get("permissions") or {}
        if isinstance(perms, dict) and perms.get("domains"):
            for dom in perms["domains"]:
                d_str = str(dom).strip()
                if d_str in ("*", "0.0.0.0", "127.0.0.1", "169.254.169.254"):
                    score -= 25
                    critical_block = True
                    findings.append(f"CRITICAL: Over-permissive/unsafe domain grant '{d_str}'.")

        # 5. Hygiene & completeness advisories
        if not str(manifest.get("description", "")).strip():
            score -= 10
            findings.append("Advisory: Missing plugin description.")
        if not str(manifest.get("category", "")).strip():
            score -= 5
            findings.append("Advisory: Missing plugin category.")

        score = max(0, min(100, score))
        blocked = bool(critical_block or score < 40)
        if blocked:
            badge = "BLOCKED"
        elif score >= 85:
            badge = "VERIFIED"
        elif score >= 65:
            badge = "SCOPED"
        else:
            badge = "REVIEW"
        return PluginScanResult(trust_score=score, trust_badge=badge, blocked=blocked, findings=findings)


class PluginBundleManager:
    """Manages ~/.pai/plugins.json + directory-based SKILL.md bundles and active skill prompt injection."""

    def __init__(
        self,
        plugins_json_path: Optional[Path] = None,
        bundles_dir: Optional[Path] = None,
    ) -> None:
        self.plugins_json_path = plugins_json_path or (Path.home() / ".pai" / "plugins.json")
        self.bundles_dir = bundles_dir or (Path.home() / ".pai" / "plugins")

    def _load_legacy_plugins(self) -> List[Dict[str, Any]]:
        if not self.plugins_json_path.is_file():
            return []
        try:
            data = json.loads(self.plugins_json_path.read_text(encoding="utf-8"))
            return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
        except Exception:
            return []

    def _load_directory_bundles(self) -> List[Dict[str, Any]]:
        if not self.bundles_dir.is_dir():
            return []
        out: List[Dict[str, Any]] = []
        for sub in sorted(self.bundles_dir.iterdir()):
            if not sub.is_dir():
                continue
            manifest_path = sub / "pai-plugin.json"
            if not manifest_path.is_file():
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if not isinstance(manifest, dict):
                    continue
                skill_md_path = sub / "SKILL.md"
                skill_text = skill_md_path.read_text(encoding="utf-8") if skill_md_path.is_file() else ""
                scan = PluginScanner.scan(manifest, skill_text=skill_text)
                manifest.setdefault("id", sub.name)
                manifest["skill_prompt"] = (skill_text or manifest.get("skill_prompt") or "").strip()
                manifest["trust_score"] = scan.trust_score
                manifest["trust_badge"] = scan.trust_badge
                manifest["scan_blocked"] = scan.blocked
                manifest["scan_findings"] = scan.findings
                if scan.blocked:
                    manifest["enabled"] = False
                out.append(manifest)
            except Exception:
                continue
        return out

    def load_all_custom_plugins(self) -> List[Dict[str, Any]]:
        """Loads directory bundles + legacy ~/.pai/plugins.json with Trust Scan metadata."""
        merged: Dict[str, Dict[str, Any]] = {}
        for item in self._load_legacy_plugins():
            pid = str(item.get("id") or "").strip()
            if not pid:
                continue
            scan = PluginScanner.scan(item, skill_text=str(item.get("skill_prompt", "")))
            enriched = dict(item)
            enriched["trust_score"] = scan.trust_score
            enriched["trust_badge"] = scan.trust_badge
            enriched["scan_blocked"] = scan.blocked
            enriched["scan_findings"] = scan.findings
            if scan.blocked:
                enriched["enabled"] = False
            merged[pid] = enriched

        for b in self._load_directory_bundles():
            pid = str(b.get("id") or "").strip()
            if pid:
                merged[pid] = b
        return list(merged.values())

    def save_plugin(self, plugin: Dict[str, Any], save_bundle_dir: bool = False) -> Tuple[bool, PluginScanResult]:
        """Validates with PluginScanner (rejecting unsafe plugins) and saves safely."""
        skill_text = str(plugin.get("skill_prompt") or "")
        scan = PluginScanner.scan(plugin, skill_text=skill_text)
        if scan.blocked:
            return False, scan

        clean_item = dict(plugin)
        clean_item["trust_score"] = scan.trust_score
        clean_item["trust_badge"] = scan.trust_badge
        clean_item["scan_findings"] = scan.findings

        if save_bundle_dir:
            pid = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(clean_item.get("id") or "custom_plugin"))
            target_dir = self.bundles_dir / pid
            target_dir.mkdir(parents=True, exist_ok=True)
            manifest_copy = {k: v for k, v in clean_item.items() if k != "skill_prompt"}
            (target_dir / "pai-plugin.json").write_text(json.dumps(manifest_copy, indent=2), encoding="utf-8")
            if skill_text.strip():
                (target_dir / "SKILL.md").write_text(skill_text.strip() + "\n", encoding="utf-8")
            return True, scan

        self.plugins_json_path.parent.mkdir(parents=True, exist_ok=True)
        curr = self._load_legacy_plugins()
        curr = [x for x in curr if x.get("id") != clean_item.get("id")]
        curr.append(clean_item)
        self.plugins_json_path.write_text(json.dumps(curr, indent=2), encoding="utf-8")
        return True, scan

    def format_active_skills_context(
        self,
        query: str = "",
        base_catalog: Optional[Sequence[Dict[str, Any]]] = None,
        max_chars: int = 2400,
    ) -> str:
        """Selects active custom plugin instructions & triggers for <learned_skills> injection."""
        all_custom = self.load_all_custom_plugins()
        candidates: List[Dict[str, Any]] = []
        q_tokens = set(re.findall(r"[a-zA-Z0-9_]{3,}", (query or "").lower()))

        for p in all_custom:
            if not p.get("enabled", True) or p.get("scan_blocked"):
                continue
            body = str(p.get("skill_prompt") or p.get("description") or "").strip()
            if not body:
                continue
            # Always keep sanitized passive/policy-bounded instruction lines
            clean_body = ingest.defang_envelope_markers(body).replace("[[SRC:", "[ [SRC:")
            hay = f"{p.get('name', '')} {p.get('category', '')} {clean_body}".lower()
            overlap = sum(1 for tok in q_tokens if tok in hay) if q_tokens else 1
            candidates.append({
                "score": overlap + (2 if p.get("pinned") else 0),
                "name": str(p.get("name", p.get("id", "plugin"))),
                "category": str(p.get("category", "Extension")),
                "body": clean_body[:600],
            })

        if base_catalog:
            active_builtin_names = [
                str(item.get("name"))
                for item in base_catalog
                if item.get("enabled") and item.get("name")
            ]
            if active_builtin_names:
                candidates.insert(0, {
                    "score": 999,
                    "name": "Active Core Capabilities",
                    "category": "Core",
                    "body": "Enabled built-in capabilities: " + ", ".join(active_builtin_names[:8]),
                })

        candidates.sort(key=lambda c: -int(c["score"]))
        lines: List[str] = []
        used = 0
        for c in candidates:
            entry = f"- [{c['category']}] {c['name']}: {c['body']}"
            if used + len(entry) + 1 > max_chars:
                break
            lines.append(entry)
            used += len(entry) + 1
        return "\n".join(lines)

    def collect_plugin_slash_commands(self) -> List[Dict[str, str]]:
        """Exports custom slash commands declared inside enabled plugin bundles."""
        cmds: List[Dict[str, str]] = []
        for p in self.load_all_custom_plugins():
            if not p.get("enabled", True) or p.get("scan_blocked"):
                continue
            for sc in (p.get("slash_commands") or []):
                if isinstance(sc, dict) and sc.get("cmd"):
                    cmds.append({
                        "cmd": str(sc["cmd"]),
                        "desc": str(sc.get("desc") or p.get("description") or "Plugin command"),
                        "cat": f"Plugin:{p.get('name', p.get('id', 'custom'))}",
                        "template": str(sc.get("template") or ""),
                    })
        return cmds
