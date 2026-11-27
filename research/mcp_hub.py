"""Live MCP Hub Lifecycle, Vaulted Credentials, Curated Registry & Progressive Tool Discovery.

Implements:
  - BUILTIN_MCP_REGISTRY_CATALOG (GitHub MCP Server, Official MCP Reference Servers, Windows-MCP)
  - MCPVaultManager (DPAPI at-rest encrypted tokens in ~/.pai/mcp_vault.json, zero plaintext leaks)
  - MCPHubManager (lifecycle, live connect/disconnect, health checks, GitHub toolsets/read-only/lockdown)
  - Progressive ToolIndex (search_tools -> describe_tool -> call_tool to eliminate context bloat)
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    from research import credential_store, ingest, mcp_client, net_guard
    from research.capabilities import PermissionDenied, Risk, ToolRequest
except ModuleNotFoundError:
    import credential_store
    import ingest
    import mcp_client
    import net_guard
    from capabilities import PermissionDenied, Risk, ToolRequest


BUILTIN_MCP_REGISTRY_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "github-mcp-official",
        "name": "github-mcp",
        "title": "GitHub Official MCP Server",
        "source": "github/github-mcp-server",
        "transport": "stdio",
        "command": "github-mcp-server stdio",
        "remote_url": "https://api.githubcopilot.com/mcp/",
        "toolsets": ["context", "repos", "issues", "pull_requests", "actions"],
        "supports_read_only": True,
        "supports_lockdown": True,
        "requires_secret_ref": "github_token",
        "secret_env_var": "GITHUB_PERSONAL_ACCESS_TOKEN",
        "trust_tier": "Official",
        "description": "Repositories, issues, PRs, code search, and Actions via modular toolsets, read-only & lockdown guardrails.",
    },
    {
        "id": "filesystem-mcp",
        "name": "filesystem-mcp",
        "title": "Sandboxed Filesystem MCP",
        "source": "modelcontextprotocol/servers",
        "transport": "stdio",
        "command": "npx @modelcontextprotocol/server-filesystem@2025.3.28 ./",
        "toolsets": ["files"],
        "supports_read_only": True,
        "supports_lockdown": False,
        "trust_tier": "Reference",
        "description": "Read, inspect, and edit workspace files constrained strictly within allowlisted directory roots.",
    },
    {
        "id": "memory-graph-mcp",
        "name": "memory-graph",
        "title": "Knowledge Graph Memory MCP",
        "source": "modelcontextprotocol/servers",
        "transport": "stdio",
        "command": "npx @modelcontextprotocol/server-memory@2025.3.28",
        "toolsets": ["knowledge_graph"],
        "supports_read_only": True,
        "supports_lockdown": False,
        "trust_tier": "Reference",
        "description": "Persistent entity-relation knowledge graph bridging across multi-turn Chat & Cowork sessions.",
    },
    {
        "id": "git-mcp",
        "name": "git-tools",
        "title": "Git Repository Inspector MCP",
        "source": "modelcontextprotocol/servers",
        "transport": "stdio",
        "command": "uvx mcp-server-git",
        "toolsets": ["git"],
        "supports_read_only": True,
        "supports_lockdown": False,
        "trust_tier": "Reference",
        "description": "Inspect git status, diffs, branch history, and staged commits locally.",
    },
    {
        "id": "fetch-mcp",
        "name": "web-fetch",
        "title": "Clean Web Fetch MCP",
        "source": "modelcontextprotocol/servers",
        "transport": "stdio",
        "command": "uvx mcp-server-fetch",
        "toolsets": ["web"],
        "supports_read_only": True,
        "supports_lockdown": True,
        "trust_tier": "Reference",
        "description": "Fetch web pages and APIs cleanly converted to LLM-ready Markdown (air-gap gated).",
    },
    {
        "id": "sequential-thinking-mcp",
        "name": "sequential-thinking",
        "title": "Sequential Thinking MCP",
        "source": "modelcontextprotocol/servers",
        "transport": "stdio",
        "command": "npx @modelcontextprotocol/server-sequential-thinking@2025.3.28",
        "toolsets": ["reasoning"],
        "supports_read_only": True,
        "supports_lockdown": False,
        "trust_tier": "Reference",
        "description": "Structured branching and revision problem-solving complement to PAI CRASH/ThoughtGraph.",
    },
    {
        "id": "pai-windows-mcp",
        "name": "pai-windows-desktop",
        "title": "PAI Built-in Windows UIA MCP",
        "source": "pai/windows_mcp_server",
        "transport": "stdio",
        "command": f"{sys.executable} -m windows_mcp_server",
        "toolsets": ["uia", "desktop", "clipboard"],
        "supports_read_only": True,
        "supports_lockdown": True,
        "trust_tier": "Native",
        "description": "Native PAI Windows UI Automation, screenshot, click, type, and app-launch MCP server.",
    },
]


class MCPVaultManager:
    """Stores MCP server bearer/PAT credentials encrypted with DPAPI (or 0o600 on POSIX)."""

    def __init__(self, vault_path: Optional[Path] = None) -> None:
        self.vault_path = vault_path or (Path.home() / ".pai" / "mcp_vault.json")
        self._lock = threading.Lock()

    def _load_raw(self) -> Dict[str, str]:
        if not self.vault_path.is_file():
            return {}
        try:
            data = json.loads(self.vault_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def set_secret(self, ref_name: str, plaintext_value: str) -> None:
        clean_ref = re.sub(r"[^a-zA-Z0-9_\-:.]", "_", (ref_name or "").strip())
        if not clean_ref:
            raise ValueError("Vault credential reference name cannot be empty.")
        if not isinstance(plaintext_value, str) or not plaintext_value.strip():
            raise ValueError("Credential secret value cannot be empty.")
        protected = credential_store.protect_secret(plaintext_value.strip())
        with self._lock:
            cur = self._load_raw()
            cur[clean_ref] = protected
            credential_store.write_secret_file(self.vault_path, json.dumps(cur, indent=2))

    def get_secret(self, ref_name: str) -> Optional[str]:
        clean_ref = re.sub(r"[^a-zA-Z0-9_\-:.]", "_", (ref_name or "").strip())
        if not clean_ref:
            return None
        with self._lock:
            blob = self._load_raw().get(clean_ref)
        if not blob:
            return None
        try:
            return credential_store.unprotect_secret(str(blob))
        except Exception:
            return None

    def delete_secret(self, ref_name: str) -> bool:
        clean_ref = re.sub(r"[^a-zA-Z0-9_\-:.]", "_", (ref_name or "").strip())
        with self._lock:
            cur = self._load_raw()
            if clean_ref not in cur:
                return False
            del cur[clean_ref]
            credential_store.write_secret_file(self.vault_path, json.dumps(cur, indent=2))
            return True

    def list_refs(self) -> List[str]:
        with self._lock:
            return sorted(self._load_raw().keys())


@dataclass
class ToolFirewallRecord:
    seq: int
    timestamp: float
    server: str
    tool: str
    risk: str
    allowed: bool
    reason: str
    tainted: bool
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ToolIndex:
    """Progressive Tool Discovery index to prevent context bloat on local & cloud LLMs.

    Exposes lightweight meta-operations:
      - `search_tools(query, server=None)`
      - `describe_tool(server, tool_name)`
      - `compact_index_prompt(max_chars=1200)`
    """

    def __init__(self, hub: "MCPHubManager") -> None:
        self._hub = hub

    def compact_index_prompt(self, max_chars: int = 1200) -> str:
        """Builds a compact (~20-40 token/server) catalog for LLM system prompts."""
        servers = self._hub.get_live_clients()
        if not servers:
            return ""
        lines: List[str] = [
            "Connected MCP Capability Servers (use pai_search_tools / pai_describe_tool before calling):"
        ]
        total = len(lines[0])
        for s_name, client in sorted(servers.items()):
            tools = list(client.available_tools.values())
            toolsets = sorted({t.toolset for t in tools if t.toolset})
            sample_names = [t.name for t in tools[:5]]
            mode_tags = []
            if client.policy.read_only:
                mode_tags.append("read-only")
            if client.policy.lockdown_mode:
                mode_tags.append("lockdown")
            tag_str = f" [{','.join(mode_tags)}]" if mode_tags else ""
            row = (
                f"- {s_name}{tag_str}: {len(tools)} tools "
                f"(toolsets={','.join(toolsets) or 'default'}; e.g. {', '.join(sample_names)})"
            )
            if total + len(row) + 1 > max_chars:
                lines.append("... (more servers available via pai_search_tools)")
                break
            lines.append(row)
            total += len(row) + 1
        return "\n".join(lines)

    def search_tools(
        self,
        query: str = "",
        server: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Searches connected MCP servers cleanly returning concise descriptors (no full schemas)."""
        tokens = [tok for tok in re.findall(r"[a-zA-Z0-9_]{2,}", (query or "").lower())]
        matches: List[Tuple[int, Dict[str, Any]]] = []
        clients = self._hub.get_live_clients()
        for s_name, client in clients.items():
            if server and s_name != server:
                continue
            for t in client.available_tools.values():
                hay = f"{s_name} {t.toolset} {t.name} {t.description}".lower()
                score = sum(2 if tok in t.name.lower() else 1 for tok in tokens if tok in hay) if tokens else 1
                if score > 0:
                    matches.append((
                        score,
                        {
                            "server": s_name,
                            "tool": t.name,
                            "toolset": t.toolset,
                            "risk": t.risk.name,
                            "description": t.description[:160],
                        },
                    ))
        matches.sort(key=lambda pair: (-pair[0], pair[1]["server"], pair[1]["tool"]))
        return [item for _, item in matches[: max(1, min(limit, 30))]]

    def describe_tool(self, server: str, tool_name: str) -> Optional[Dict[str, Any]]:
        """Hydrates the full JSON inputSchema for one tool on demand."""
        client = self._hub.get_live_clients().get(server)
        if not client:
            return None
        t = client.available_tools.get(tool_name)
        if not t:
            return None
        return {
            "server": server,
            "tool": t.name,
            "toolset": t.toolset,
            "risk": t.risk.name,
            "read_only_policy": client.policy.read_only,
            "lockdown_policy": client.policy.lockdown_mode,
            "description": t.description,
            "inputSchema": t.input_schema,
        }


class MCPHubManager:
    """Manages persistent MCP configs, runtime connections, ToolFirewall logs, and ToolIndex."""

    def __init__(
        self,
        config_path: Optional[Path] = None,
        vault: Optional[MCPVaultManager] = None,
        offline_check_fn: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.config_path = config_path or (Path.home() / ".pai" / "mcp_servers.json")
        self.vault = vault or MCPVaultManager()
        self.offline_check_fn = offline_check_fn
        self._lock = threading.Lock()
        self._firewall_log: List[ToolFirewallRecord] = []
        self._clients: Dict[str, mcp_client.MCPClient] = {}
        self.tool_index = ToolIndex(self)

    def get_live_clients(self) -> Dict[str, mcp_client.MCPClient]:
        with self._lock:
            return dict(self._clients)

    def record_firewall_event(
        self,
        server: str,
        tool: str,
        risk: str,
        allowed: bool,
        reason: str,
        tainted: bool,
        duration_ms: float = 0.0,
    ) -> None:
        with self._lock:
            rec = ToolFirewallRecord(
                seq=len(self._firewall_log) + 1,
                timestamp=time.time(),
                server=server,
                tool=tool,
                risk=risk,
                allowed=allowed,
                reason=reason[:220],
                tainted=tainted,
                duration_ms=round(duration_ms, 2),
            )
            self._firewall_log.append(rec)
            if len(self._firewall_log) > 250:
                self._firewall_log = self._firewall_log[-250:]

    def get_firewall_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in reversed(self._firewall_log[-max(1, limit) :])]

    @staticmethod
    def build_policy_from_config(cfg: Dict[str, Any]) -> mcp_client.MCPServerPolicy:
        cmd_or_url = str(cfg.get("command") or cfg.get("url") or "").strip()
        is_loopback = mcp_client._is_loopback_http_url(cmd_or_url)
        return mcp_client.MCPServerPolicy(
            read_only=bool(cfg.get("read_only", False)),
            lockdown_mode=bool(cfg.get("lockdown_mode", False)),
            dynamic_discovery=bool(cfg.get("dynamic_discovery", True)),
            toolsets=tuple(str(x) for x in (cfg.get("toolsets") or []) if str(x).strip()),
            allowed_tools=tuple(str(x) for x in (cfg.get("allowed_tools") or []) if str(x).strip()),
            excluded_tools=tuple(str(x) for x in (cfg.get("excluded_tools") or []) if str(x).strip()),
            allow_loopback_http=bool(cfg.get("allow_loopback", is_loopback)),
        )

    @staticmethod
    def _build_runtime_env_and_args(
        cfg: Dict[str, Any],
        cmd_tokens: List[str],
        secret_value: Optional[str],
    ) -> Tuple[List[str], Dict[str, str]]:
        """Applies GitHub MCP toolset/read-only/lockdown flags and vaulted env vars safely."""
        tokens = list(cmd_tokens)
        env: Dict[str, str] = {}
        name_low = str(cfg.get("name", "")).lower()
        is_github_mcp = "github" in name_low or any("github-mcp-server" in t for t in tokens)

        toolsets = [str(x).strip() for x in (cfg.get("toolsets") or []) if str(x).strip()]
        if is_github_mcp:
            if toolsets:
                env["GITHUB_TOOLSETS"] = ",".join(toolsets)
            if cfg.get("read_only"):
                env["GITHUB_READ_ONLY"] = "1"
            if cfg.get("lockdown_mode"):
                env["GITHUB_LOCKDOWN_MODE"] = "1"
            if cfg.get("dynamic_discovery", True):
                env["GITHUB_DYNAMIC_TOOLSETS"] = "1"

        secret_env = str(cfg.get("secret_env_var") or ("GITHUB_PERSONAL_ACCESS_TOKEN" if is_github_mcp else "")).strip()
        if secret_value and secret_env:
            env[secret_env] = secret_value
        return tokens, env

    def connect_server_config(
        self,
        cfg: Dict[str, Any],
        confirm_fn: Optional[Callable[[ToolRequest], bool]] = None,
        allow_unpinned: bool = False,
    ) -> Dict[str, Any]:
        """Connects a single configured MCP server live, returning tool/resource/prompt counts."""
        name = str(cfg.get("name") or "").strip()
        transport_kind = str(cfg.get("transport") or "stdio").strip().lower()
        cmd_or_url = str(cfg.get("command") or cfg.get("url") or "").strip()
        if not name or not cmd_or_url:
            raise ValueError("MCP config requires non-empty name and command/url.")

        policy = self.build_policy_from_config(cfg)
        secret_ref = str(cfg.get("credential_ref") or "").strip()
        secret_val = self.vault.get_secret(secret_ref) if secret_ref else None
        approver = confirm_fn or (lambda _req: True)

        if transport_kind in ("http", "sse", "streamable_http"):
            headers = dict(cfg.get("headers") or {})
            if secret_val and "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {secret_val}"
            if policy.toolsets:
                headers["X-MCP-Toolsets"] = ",".join(policy.toolsets)
            if policy.read_only:
                headers["X-MCP-Readonly"] = "1"
            if policy.lockdown_mode:
                headers["X-MCP-Lockdown"] = "1"
            transport: mcp_client.MCPTransport = mcp_client.StreamableHttpMCPTransport(
                url=cmd_or_url,
                headers=headers,
                allow_loopback=policy.allow_loopback_http,
                offline_check_fn=self.offline_check_fn,
                confirm=approver,
                require_confirmation=True,
            )
        else:
            parsed_tokens = mcp_client.parse_mcp_command_string(cmd_or_url, allow_unpinned=allow_unpinned)
            tokens, extra_env = self._build_runtime_env_and_args(cfg, parsed_tokens, secret_val)
            if secret_val and extra_env:
                # Explicitly scrub host env first, then bind only the vault-retrieved credential once
                base_env = mcp_client.build_safe_mcp_env({})
                base_env.update(extra_env)
                req = ToolRequest("mcp_connect", Risk.DESTRUCTIVE, json.dumps(tokens)[:200], False, "spawning MCP with vaulted secret")
                if not bool(approver(req)):
                    raise PermissionDenied("MCP launch with vaulted secret declined")
                import subprocess as _sp
                transport = mcp_client.StdioMCPTransport.__new__(mcp_client.StdioMCPTransport)
                transport.command = tokens
                transport._req_id = 0
                transport._lock = threading.Lock()
                transport._proc = _sp.Popen(
                    tokens,
                    stdin=_sp.PIPE,
                    stdout=_sp.PIPE,
                    stderr=_sp.PIPE,
                    text=True,
                    encoding="utf-8",
                    bufsize=1,
                    env=base_env,
                )
            else:
                transport = mcp_client.StdioMCPTransport(
                    command=tokens,
                    env=extra_env or None,
                    confirm=approver,
                    allow_unpinned=allow_unpinned,
                    require_confirmation=True,
                )

        client = mcp_client.MCPClient(name=name, transport=transport, policy=policy)
        try:
            client.initialize()
            tools = client.list_tools(apply_policy=True)
            resources = client.list_resources()
            prompts = client.list_prompts()
        except Exception:
            client.close()
            raise

        with self._lock:
            old = self._clients.pop(name, None)
            if old is not None:
                old.close()
            self._clients[name] = client
            mcp_client.MCPRegistry._servers[name] = client

        return {
            "name": name,
            "connected": True,
            "protocol_version": client.protocol_version,
            "tools_count": len(tools),
            "resources_count": len(resources),
            "prompts_count": len(prompts),
            "read_only": policy.read_only,
            "lockdown_mode": policy.lockdown_mode,
        }

    def disconnect_server(self, name: str) -> None:
        with self._lock:
            old = self._clients.pop(name, None)
            mcp_client.MCPRegistry._servers.pop(name, None)
        if old is not None:
            old.close()

    def register_client_for_session(self, client: mcp_client.MCPClient) -> None:
        """Registers an already-instantiated MCPClient (e.g. in-process WindowsMCP or test double)."""
        with self._lock:
            self._clients[client.name] = client
            mcp_client.MCPRegistry._servers[client.name] = client

    def execute_tool(
        self,
        server: str,
        tool_name: str,
        arguments: Dict[str, Any],
        tainted: bool = False,
        confirm: Optional[Callable[[ToolRequest], bool]] = None,
    ) -> mcp_client.MCPToolResult:
        """Executes an MCP tool through server policy, HITL confirmation, and ToolFirewall audit log."""
        t0 = time.perf_counter()
        client = self.get_live_clients().get(server)
        if client is None:
            self.record_firewall_event(server, tool_name, "UNKNOWN", False, "server not connected", tainted)
            raise KeyError(f"MCP server '{server}' is not connected.")

        tdef = client.available_tools.get(tool_name)
        risk_label = tdef.risk.name if tdef else "DESTRUCTIVE"
        try:
            res = client.call_tool(
                tool_name=tool_name,
                arguments=arguments or {},
                confirm=confirm,
                tainted=tainted,
            )
            dur = (time.perf_counter() - t0) * 1000.0
            self.record_firewall_event(
                server,
                tool_name,
                risk_label,
                not res.is_error,
                "secret redacted" if res.secret_redacted else ("tool error" if res.is_error else "allowed"),
                tainted or client.policy.lockdown_mode,
                duration_ms=dur,
            )
            return res
        except Exception as exc:
            dur = (time.perf_counter() - t0) * 1000.0
            self.record_firewall_event(server, tool_name, risk_label, False, str(exc), tainted, duration_ms=dur)
            raise

    @staticmethod
    def search_registry_catalog(query: str = "") -> List[Dict[str, Any]]:
        """Searches the offline curated MCP Registry catalog (no unrequested network calls)."""
        q = (query or "").strip().lower()
        if not q:
            return [dict(item) for item in BUILTIN_MCP_REGISTRY_CATALOG]
        return [
            dict(item)
            for item in BUILTIN_MCP_REGISTRY_CATALOG
            if q in f"{item['id']} {item['name']} {item['title']} {item['source']} {item['description']}".lower()
        ]
