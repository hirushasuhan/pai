"""
Model Context Protocol (MCP) Client for Personal Agentic AI (PAI).
Implements JSON-RPC 2.0 communication over STDIO and HTTP transports.
Bridges external MCP tool servers into PAI's sandboxed Capability Broker.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    from research import ingest
    from research.capabilities import (
        Grant,
        PermissionDenied,
        Risk,
        Tool,
        ToolBroker,
        ToolRequest,
    )
except ModuleNotFoundError:
    import ingest
    from capabilities import (
        Grant,
        PermissionDenied,
        Risk,
        Tool,
        ToolBroker,
        ToolRequest,
    )


SAFE_MCP_ENV_ALLOWLIST: Tuple[str, ...] = (
    "PATH",
    "SystemRoot",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOME",
    "LANG",
    "LC_ALL",
)

_BLOCKED_ENV_KEY_RE = re.compile(
    r"^(?:AWS_.*|PAI_(?:BRIDGE_TOKEN|HMAC_KEY|SESSION_NONCE)|"
    r".*(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|CREDENTIAL).*)$",
    re.IGNORECASE | re.ASCII,
)

_SHELL_INTERPRETERS = frozenset({
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "wscript",
    "wscript.exe",
    "cscript",
    "cscript.exe",
})

_SHELL_META_TOKENS = frozenset({"&&", "||", ";", "|"})

_PACKAGE_RUNNERS = frozenset({
    "npx",
    "npx.cmd",
    "npx.exe",
    "pnpx",
    "pnpx.cmd",
    "pnpx.exe",
    "bunx",
    "bunx.exe",
})

_PINNED_NPM_SPEC_RE = re.compile(
    r"^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+@[0-9]+(?:\.[0-9]+)*(?:-[A-Za-z0-9._-]+)?$"
)


def make_mcp_broker(
    confirm: Optional[Callable[[ToolRequest], bool]] = None,
    allow_register: bool = True,
    allow_connect: bool = True,
    allow_call_tool: bool = True,
    max_calls: Optional[int] = None,
    expires: Optional[float] = None,
) -> ToolBroker:
    """Constructs a ToolBroker configured with Risk.DESTRUCTIVE MCP governance tools."""
    tools = [
        Tool("mcp_register", Risk.DESTRUCTIVE, lambda name="", transport="", command="": True),
        Tool("mcp_connect", Risk.DESTRUCTIVE, lambda command=(): True),
        Tool("mcp_call_tool", Risk.DESTRUCTIVE, lambda server="", tool="", arguments=None: True),
    ]
    grants: List[Grant] = []
    if allow_register:
        grants.append(Grant("mcp_register", max_calls=max_calls, expires=expires))
    if allow_connect:
        grants.append(Grant("mcp_connect", max_calls=max_calls, expires=expires))
    if allow_call_tool:
        grants.append(Grant("mcp_call_tool", max_calls=max_calls, expires=expires))
    return ToolBroker(tools=tools, grants=grants, confirm=confirm)


def build_safe_mcp_env(
    env: Optional[Dict[str, str]] = None,
    extra_allowlist: Sequence[str] = (),
) -> Dict[str, str]:
    """Builds a scrubbed child environment copying only safe allowlisted host variables."""
    allowed_keys: List[str] = list(SAFE_MCP_ENV_ALLOWLIST)
    for extra in extra_allowlist:
        if not isinstance(extra, str) or not extra or "=" in extra or any(c in extra for c in ("\x00", "\r", "\n")):
            raise ValueError("Invalid extra_allowlist environment key")
        if _BLOCKED_ENV_KEY_RE.match(extra):
            raise ValueError(f"Blocked secret key in extra_allowlist: {extra}")
        allowed_keys.append(extra)

    safe_env: Dict[str, str] = {}
    if os.name == "nt":
        allowed_lower = {k.lower() for k in allowed_keys}
        for k, v in os.environ.items():
            if k.lower() in allowed_lower and not _BLOCKED_ENV_KEY_RE.match(k):
                safe_env[k] = v
    else:
        allowed_set = set(allowed_keys)
        for k in allowed_set:
            if k in os.environ and not _BLOCKED_ENV_KEY_RE.match(k):
                safe_env[k] = os.environ[k]

    if env is not None:
        if not isinstance(env, dict):
            raise ValueError("env must be a dictionary")
        for k, v in env.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ValueError("MCP environment keys and values must be strings")
            if not k or "=" in k or any(c in k for c in ("\x00", "\r", "\n")) or any(c in v for c in ("\x00", "\r", "\n")):
                raise ValueError(f"Invalid MCP environment variable key/value for '{k}'")
            if _BLOCKED_ENV_KEY_RE.match(k):
                raise ValueError(f"Blocked secret environment variable for MCP child process: {k}")
            if ingest.scan_secret_content(v) is not None or ingest.scan_secret_content(f"{k}={v}", file_path=".env") is not None:
                raise ValueError(f"Blocked secret value in MCP environment variable: {k}")
            if os.name == "nt":
                for existing_k in [ek for ek in safe_env if ek.lower() == k.lower()]:
                    del safe_env[existing_k]
            safe_env[k] = v
    return safe_env


def _extract_runner_package_spec(args: Sequence[str]) -> Optional[str]:
    skip_next = False
    for arg in args:
        if skip_next:
            return arg
        if arg in ("-p", "--package"):
            skip_next = True
            continue
        if arg.startswith("--package="):
            return arg.split("=", 1)[1]
        if arg.startswith("-"):
            continue
        return arg
    return None


def validate_mcp_command(command: Sequence[str], allow_unpinned: bool = False) -> List[str]:
    """Validates an MCP server command list, rejecting shells, meta-tokens, and unpinned npx -y."""
    if isinstance(command, (str, bytes)) or not isinstance(command, Sequence) or len(command) == 0:
        raise ValueError("MCP command must be a non-empty sequence of strings")

    validated: List[str] = []
    for arg in command:
        if not isinstance(arg, str) or not arg or any(c in arg for c in ("\x00", "\r", "\n")):
            raise ValueError("MCP command arguments must be non-empty NUL/newline-free strings")
        if arg in _SHELL_META_TOKENS:
            raise ValueError(f"Shell meta-token '{arg}' is not allowed in MCP command")
        validated.append(arg)

    exe_base = os.path.basename(validated[0]).lower()
    if exe_base in _SHELL_INTERPRETERS:
        raise ValueError(f"Shell interpreter '{exe_base}' is not allowed as an MCP command")

    if exe_base in _PACKAGE_RUNNERS:
        has_auto_yes = any(
            arg in ("-y", "--yes")
            or arg.startswith("--yes=")
            or (arg.startswith("-") and not arg.startswith("--") and "y" in arg[1:])
            for arg in validated[1:]
        )
        pkg_spec = _extract_runner_package_spec(validated[1:])
        is_pinned = bool(pkg_spec and _PINNED_NPM_SPEC_RE.match(pkg_spec))
        if (has_auto_yes or not is_pinned) and not allow_unpinned:
            raise ValueError("Unpinned or auto-installing package runner MCP command requires explicit confirmation")

    return validated


def parse_mcp_command_string(cmd_str: str, allow_unpinned: bool = False) -> List[str]:
    """Splits and validates a command string for MCP server configuration."""
    if not isinstance(cmd_str, str) or not cmd_str.strip() or any(c in cmd_str for c in ("\x00", "\r", "\n")):
        raise ValueError("MCP command string must be a non-empty NUL/newline-free string")
    raw_tokens = shlex.split(cmd_str, posix=(os.name != "nt"))
    if os.name == "nt":
        tokens = [
            tok[1:-1] if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ('"', "'") else tok
            for tok in raw_tokens
        ]
    else:
        tokens = raw_tokens
    return validate_mcp_command(tokens, allow_unpinned=allow_unpinned)


@dataclass
class MCPToolDefinition:
    name: str
    description: str
    input_schema: Dict[str, Any]
    server_name: str = "default"


@dataclass
class MCPToolResult:
    content: List[Dict[str, Any]]
    is_error: bool = False
    raw_text: str = ""


class MCPTransport:
    """Base transport interface for Model Context Protocol."""
    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class StdioMCPTransport(MCPTransport):
    """
    Subprocess STDIO transport for MCP servers.
    Communicates via newline-delimited JSON-RPC 2.0 over stdin/stdout.
    """
    def __init__(
        self,
        command: Sequence[str],
        env: Optional[Dict[str, str]] = None,
        broker: Optional[ToolBroker] = None,
        confirm: Optional[Callable[[ToolRequest], bool]] = None,
        tainted: bool = False,
        allow_unpinned: bool = False,
        require_confirmation: bool = False,
    ):
        validated_cmd = validate_mcp_command(command, allow_unpinned=allow_unpinned)
        scrubbed_env = build_safe_mcp_env(env)

        if allow_unpinned and broker is None and confirm is None:
            raise PermissionDenied("allow_unpinned requires broker or confirm channel")
        if broker is not None:
            broker.invoke("mcp_connect", {"command": list(validated_cmd)}, tainted=bool(tainted))
        elif confirm is not None:
            req = ToolRequest(
                "mcp_connect",
                Risk.DESTRUCTIVE,
                json.dumps(validated_cmd)[:200],
                bool(tainted),
                "spawning external MCP stdio process",
            )
            try:
                approved = bool(confirm(req))
            except Exception as exc:
                raise PermissionDenied(f"MCP stdio launch confirmation failed: {exc}") from exc
            if not approved:
                raise PermissionDenied("MCP stdio launch declined by confirmation")
        elif require_confirmation or tainted:
            raise PermissionDenied("MCP stdio launch requires ToolBroker or confirmation")

        self.command = validated_cmd
        self._proc: Optional[subprocess.Popen] = None
        self._req_id = 0
        self._lock = threading.Lock()
        try:
            self._proc = subprocess.Popen(
                validated_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
                env=scrubbed_env,
            )
        except Exception as e:
            raise ConnectionError(f"Failed to start MCP server process '{validated_cmd}': {e}")

    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self._proc or self._proc.poll() is not None:
            raise ConnectionError("MCP server process is not running.")
        with self._lock:
            self._req_id += 1
            payload = {
                "jsonrpc": "2.0",
                "id": self._req_id,
                "method": method,
            }
            if params is not None:
                payload["params"] = params
            req_line = json.dumps(payload) + "\n"
            try:
                self._proc.stdin.write(req_line)
                self._proc.stdin.flush()
                resp_line = self._proc.stdout.readline()
                if not resp_line:
                    err_out = self._proc.stderr.read() if self._proc.stderr else ""
                    raise ConnectionError(f"Empty response from MCP server. Stderr: {err_out}")
                resp_obj = json.loads(resp_line.strip())
                if "error" in resp_obj:
                    err = resp_obj["error"]
                    raise RuntimeError(f"MCP error {err.get('code')}: {err.get('message')}")
                return resp_obj.get("result", {})
            except Exception as e:
                raise RuntimeError(f"MCP communication failure during '{method}': {e}")

    def close(self) -> None:
        if self._proc:
            for pipe in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except Exception:
                        pass
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None


class MCPClient:
    """
    High-level Model Context Protocol client for discovering and executing external tools.
    """
    def __init__(self, name: str, transport: MCPTransport):
        self.name = name
        self.transport = transport
        self.server_info: Dict[str, Any] = {}
        self.available_tools: Dict[str, MCPToolDefinition] = {}
        self.is_initialized = False

    def initialize(self) -> Dict[str, Any]:
        """Performs initial MCP protocol handshake."""
        params = {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
                "resources": {},
            },
            "clientInfo": {
                "name": "PAI-Agent",
                "version": "1.1.0-rc4",
            },
        }
        res = self.transport.send_request("initialize", params)
        self.server_info = res
        self.is_initialized = True
        return res

    def list_tools(self) -> List[MCPToolDefinition]:
        """Discovers tools registered on the MCP server."""
        if not self.is_initialized:
            self.initialize()
        res = self.transport.send_request("tools/list", {})
        tools_raw = res.get("tools", [])
        self.available_tools.clear()
        tool_list = []
        for t in tools_raw:
            tool_def = MCPToolDefinition(
                name=t.get("name", ""),
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
                server_name=self.name,
            )
            self.available_tools[tool_def.name] = tool_def
            tool_list.append(tool_def)
        return tool_list

    def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        broker: Optional[ToolBroker] = None,
        tainted: bool = False,
    ) -> MCPToolResult:
        """Executes a tool on the MCP server with given JSON arguments."""
        if broker is not None:
            broker.invoke(
                "mcp_call_tool",
                {"server": self.name, "tool": tool_name, "arguments": arguments},
                tainted=bool(tainted),
            )
        if not self.is_initialized:
            self.initialize()
        params = {
            "name": tool_name,
            "arguments": arguments,
        }
        res = self.transport.send_request("tools/call", params)
        content = res.get("content", [])
        is_error = res.get("isError", False)
        text_parts = [item.get("text", "") for item in content if isinstance(item, dict) and "text" in item]
        raw_text = "\n".join(text_parts) if text_parts else str(res)
        return MCPToolResult(content=content, is_error=is_error, raw_text=raw_text)

    def close(self) -> None:
        self.transport.close()


class MCPRegistry:
    """Global registry of active MCP servers and bridged capability tools."""
    _servers: Dict[str, MCPClient] = {}

    @classmethod
    def register_server(
        cls,
        name: str,
        client: MCPClient,
        broker: Optional[ToolBroker] = None,
        confirm: Optional[Callable[[ToolRequest], bool]] = None,
        tainted: bool = False,
        require_confirmation: bool = True,
    ) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("MCP server name must be a non-empty string")
        clean_name = name.strip()
        if broker is not None:
            broker.invoke(
                "mcp_register",
                {"name": clean_name, "transport": type(client.transport).__name__},
                tainted=bool(tainted),
            )
        elif confirm is not None:
            req = ToolRequest(
                "mcp_register",
                Risk.DESTRUCTIVE,
                clean_name,
                bool(tainted),
                "registering external MCP server",
            )
            try:
                approved = bool(confirm(req))
            except Exception as exc:
                raise PermissionDenied(f"MCP server registration confirmation failed: {exc}") from exc
            if not approved:
                raise PermissionDenied("MCP server registration declined by confirmation")
        elif require_confirmation:
            raise PermissionDenied("MCP server registration requires ToolBroker or explicit confirmation")
        cls._servers[clean_name] = client

    @classmethod
    def connect_stdio(
        cls,
        name: str,
        command: Sequence[str],
        env: Optional[Dict[str, str]] = None,
        broker: Optional[ToolBroker] = None,
        confirm: Optional[Callable[[ToolRequest], bool]] = None,
        tainted: bool = False,
        allow_unpinned: bool = False,
    ) -> MCPClient:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("MCP server name must be a non-empty string")
        if broker is None and confirm is None:
            raise PermissionDenied("MCP stdio registration requires ToolBroker or explicit confirmation")
        transport = StdioMCPTransport(
            command=command,
            env=env,
            broker=broker,
            confirm=confirm,
            tainted=tainted,
            allow_unpinned=allow_unpinned,
            require_confirmation=True,
        )
        client = MCPClient(name=name.strip(), transport=transport)
        try:
            cls.register_server(
                name=name.strip(),
                client=client,
                broker=broker,
                confirm=confirm,
                tainted=tainted,
                require_confirmation=True,
            )
        except Exception:
            client.close()
            raise
        return client

    @classmethod
    def unregister_server(cls, name: str) -> Optional[MCPClient]:
        client = cls._servers.pop(name, None)
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        return client

    @classmethod
    def clear(cls) -> None:
        for client in list(cls._servers.values()):
            try:
                client.close()
            except Exception:
                pass
        cls._servers.clear()

    @classmethod
    def get_server(cls, name: str) -> Optional[MCPClient]:
        return cls._servers.get(name)

    @classmethod
    def list_servers(cls) -> Dict[str, MCPClient]:
        return dict(cls._servers)

    @classmethod
    def list_all_tools(cls) -> List[MCPToolDefinition]:
        all_tools = []
        for s in cls._servers.values():
            try:
                tools = s.list_tools()
                all_tools.extend(tools)
            except Exception:
                pass
        return all_tools

    @classmethod
    def format_status(cls, color_enabled: bool = False) -> str:
        lines = ["🔌 Model Context Protocol (MCP) Hub:"]
        if not cls._servers:
            lines.append("  (No active MCP servers connected. Use /mcp connect <command>)")
            lines.append("  Supported: STDIO servers (Apollo GraphQL, Filesystem, GitHub, Custom Tools)")
            return "\n".join(lines)
        for name, s in cls._servers.items():
            lines.append(f"  • Server: {name} (Running)")
            for t_name, t in s.available_tools.items():
                lines.append(f"    - Tool: {t_name}: {t.description}")
        return "\n".join(lines)
