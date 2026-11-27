"""
Model Context Protocol (MCP) Client for Personal Agentic AI (PAI).
Implements JSON-RPC 2.0 communication over STDIO and Streamable HTTP/SSE transports,
supporting Tools, Resources, Prompts, Elicitation safety validation, Tasks,
GitHub MCP Toolsets / Read-Only / Lockdown Mode, and Capability Broker firewalling.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    from research import ingest, net_guard
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
    import net_guard
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
    toolset: str = "default"
    read_only_hint: Optional[bool] = None
    destructive_hint: Optional[bool] = None
    risk: Risk = Risk.WRITE


@dataclass
class MCPResourceDefinition:
    uri: str
    name: str
    description: str = ""
    mime_type: str = "text/plain"
    server_name: str = "default"


@dataclass
class MCPPromptDefinition:
    name: str
    description: str = ""
    arguments: List[Dict[str, Any]] = field(default_factory=list)
    server_name: str = "default"


@dataclass
class MCPServerPolicy:
    """Governance policy applied to an MCP server (GitHub MCP + HOL Guard pattern)."""
    read_only: bool = False
    lockdown_mode: bool = False
    dynamic_discovery: bool = True
    toolsets: Tuple[str, ...] = ()
    allowed_tools: Tuple[str, ...] = ()
    excluded_tools: Tuple[str, ...] = ()
    allow_loopback_http: bool = False


@dataclass
class MCPToolResult:
    content: List[Dict[str, Any]]
    is_error: bool = False
    raw_text: str = ""
    sanitized_text: str = ""
    tainted: bool = True
    secret_redacted: bool = False


_READ_TOOL_PREFIXES = (
    "get_", "list_", "read_", "search_", "find_", "fetch_", "describe_",
    "inspect_", "state", "screenshot", "view_", "check_", "query_", "diff", "log",
)
_DESTRUCTIVE_TOOL_TOKENS = (
    "delete", "remove", "drop", "destroy", "force_push", "merge", "execute_command",
    "run_shell", "terminate", "kill", "purge", "revoke", "transfer",
)
_WRITE_TOOL_TOKENS = (
    "create", "update", "write", "edit", "patch", "post", "send", "push",
    "commit", "comment", "assign", "click", "type", "drag", "move", "launch",
    "shortcut", "clipboard", "set_", "add_", "save", "insert",
)
_SECRET_ELICIT_FIELD_RE = re.compile(
    r"(?:password|passwd|secret|api[_\-]?key|token|private[_\-]?key|credential|pin|ssn)",
    re.IGNORECASE,
)


def infer_mcp_tool_risk(
    name: str,
    annotations: Optional[Dict[str, Any]] = None,
    transport_is_remote: bool = False,
) -> Risk:
    """Conservatively infers ToolBroker Risk level for an external MCP tool."""
    ann = annotations or {}
    if ann.get("destructiveHint") is True:
        return Risk.DESTRUCTIVE
    if ann.get("readOnlyHint") is True:
        return Risk.READ

    low = (name or "").strip().lower().replace("-", "_")
    if any(tok in low for tok in _DESTRUCTIVE_TOOL_TOKENS):
        return Risk.DESTRUCTIVE
    if any(low.startswith(pref) or low == pref.rstrip("_") for pref in _READ_TOOL_PREFIXES):
        return Risk.READ
    if any(tok in low for tok in _WRITE_TOOL_TOKENS):
        return Risk.NETWORK_OUT if transport_is_remote else Risk.WRITE
    return Risk.NETWORK_OUT if transport_is_remote else Risk.DESTRUCTIVE


def is_secret_elicitation_schema(requested_schema: Dict[str, Any]) -> Optional[str]:
    """Per MCP Elicitation spec, Form Mode MUST NOT request secrets or passwords."""
    props = (requested_schema or {}).get("properties")
    if not isinstance(props, dict):
        return None
    for field_name, spec in props.items():
        if _SECRET_ELICIT_FIELD_RE.search(str(field_name)):
            return str(field_name)
        if isinstance(spec, dict):
            fmt = str(spec.get("format", "")).lower()
            desc = str(spec.get("description", ""))
            if fmt == "password" or _SECRET_ELICIT_FIELD_RE.search(desc):
                return str(field_name)
    return None


def redact_and_sanitize_mcp_text(text: str, source_label: str = "mcp") -> Tuple[str, bool]:
    """Scrubs leaked secrets and neutralizes injection markers in untrusted MCP output."""
    raw = str(text or "")
    secret_hit = ingest.scan_secret_content(raw)
    redacted = False
    if secret_hit is not None:
        raw = f"[REDACTED_SECRET:{secret_hit}] Output suppressed because an external MCP server emitted sensitive credential material."
        redacted = True
    clean = ingest.defang_envelope_markers(raw)
    clean = clean.replace("[[SRC:", "[ [SRC:")
    wrapped = ingest.wrap_untrusted_envelope(clean, header=source_label)
    return wrapped, redacted


def _is_loopback_http_url(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").strip().lower()
        if host == "localhost":
            return True
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except Exception:
        return False


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


class StreamableHttpMCPTransport(MCPTransport):
    """Streamable HTTP / SSE MCP transport (supports 2024-11-05, 2025-03-26, and stateless _meta).

    Routes target URLs through `net_guard.validate_url` to block SSRF, link-local
    metadata endpoints, and non-HTTP schemes. Private loopback (`127.0.0.1` / `localhost`)
    is permitted only when explicitly opted-in via `allow_loopback=True` AND gated via
    `ToolBroker` / confirmation.
    """

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout_sec: float = 15.0,
        allow_loopback: bool = False,
        offline_check_fn: Optional[Callable[[], bool]] = None,
        broker: Optional[ToolBroker] = None,
        confirm: Optional[Callable[[ToolRequest], bool]] = None,
        tainted: bool = False,
        require_confirmation: bool = False,
    ):
        clean_url = (url or "").strip()
        is_loopback = _is_loopback_http_url(clean_url)
        if allow_loopback and not is_loopback:
            raise PermissionDenied("allow_loopback=True only permits explicit localhost/127.0.0.1 MCP endpoints")

        try:
            net_guard.validate_url(clean_url, allow_private=bool(allow_loopback and is_loopback))
        except Exception as exc:
            raise ValueError(f"Rejected MCP HTTP endpoint URL: {exc}") from exc

        if not is_loopback and offline_check_fn is not None and not offline_check_fn():
            raise ConnectionError("Offline air-gap active: remote HTTP MCP endpoints are disabled.")

        if broker is not None:
            broker.invoke("mcp_connect", {"url": clean_url}, tainted=bool(tainted))
        elif confirm is not None:
            req = ToolRequest(
                "mcp_connect",
                Risk.NETWORK_OUT,
                clean_url[:200],
                bool(tainted),
                "connecting to HTTP/SSE MCP server",
            )
            if not bool(confirm(req)):
                raise PermissionDenied("MCP HTTP connection declined by confirmation")
        elif require_confirmation or tainted:
            raise PermissionDenied("MCP HTTP connection requires ToolBroker or confirmation")

        self.url = clean_url
        self.timeout_sec = max(1.0, float(timeout_sec))
        self.allow_loopback = allow_loopback
        self.is_loopback = is_loopback
        self.offline_check_fn = offline_check_fn
        self._headers = {str(k): str(v) for k, v in (headers or {}).items()}
        self._session_id: Optional[str] = None
        self._req_id = 0
        self._lock = threading.Lock()

    @staticmethod
    def _parse_sse_jsonrpc(raw_body: str, target_id: Optional[int]) -> Dict[str, Any]:
        last_obj: Optional[Dict[str, Any]] = None
        for line in raw_body.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            data_str = line[5:].strip()
            if not data_str or data_str == "[DONE]":
                continue
            try:
                obj = json.loads(data_str)
                if isinstance(obj, dict):
                    last_obj = obj
                    if target_id is not None and obj.get("id") == target_id:
                        return obj
            except json.JSONDecodeError:
                continue
        if last_obj is not None:
            return last_obj
        raise RuntimeError("No valid JSON-RPC payload found in SSE stream")

    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.is_loopback and self.offline_check_fn is not None and not self.offline_check_fn():
            raise ConnectionError("Offline air-gap active: blocking outbound MCP HTTP call.")
        net_guard.validate_url(self.url, allow_private=bool(self.allow_loopback and self.is_loopback))

        with self._lock:
            self._req_id += 1
            cur_id = self._req_id
            payload: Dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": cur_id,
                "method": method,
            }
            if params is not None:
                payload["params"] = params
            body_bytes = json.dumps(payload).encode("utf-8")

            req_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                **self._headers,
            }
            if self._session_id:
                req_headers["Mcp-Session-Id"] = self._session_id

            req = urllib.request.Request(self.url, data=body_bytes, headers=req_headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                    sid = resp.headers.get("Mcp-Session-Id")
                    if sid:
                        self._session_id = sid
                    ctype = (resp.headers.get("Content-Type") or "").lower()
                    raw_text = resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
            except urllib.error.HTTPError as exc:
                raise RuntimeError(f"MCP HTTP {exc.code} during '{method}'") from exc
            except Exception as exc:
                raise ConnectionError(f"MCP HTTP transport error during '{method}': {exc}") from exc

            if "text/event-stream" in ctype or raw_text.lstrip().startswith("event:") or raw_text.lstrip().startswith("data:"):
                resp_obj = self._parse_sse_jsonrpc(raw_text, cur_id)
            else:
                resp_obj = json.loads(raw_text.strip()) if raw_text.strip() else {}

            if "error" in resp_obj:
                err = resp_obj["error"]
                raise RuntimeError(f"MCP error {err.get('code')}: {err.get('message')}")
            return resp_obj.get("result", {})

    def close(self) -> None:
        self._session_id = None


class MCPClient:
    """
    High-level Model Context Protocol client for discovering and executing external tools,
    reading URI resources, rendering prompts, and polling long-running tasks.
    """
    SUPPORTED_PROTOCOL_VERSIONS = ("2025-03-26", "2024-11-05")

    def __init__(
        self,
        name: str,
        transport: MCPTransport,
        policy: Optional[MCPServerPolicy] = None,
    ):
        self.name = name
        self.transport = transport
        self.policy = policy or MCPServerPolicy()
        self.server_info: Dict[str, Any] = {}
        self.server_capabilities: Dict[str, Any] = {}
        self.protocol_version: str = "2024-11-05"
        self.available_tools: Dict[str, MCPToolDefinition] = {}
        self.available_resources: Dict[str, MCPResourceDefinition] = {}
        self.available_prompts: Dict[str, MCPPromptDefinition] = {}
        self.is_initialized = False

    def initialize(self) -> Dict[str, Any]:
        """Performs MCP protocol handshake (supports 2025-03-26 and 2024-11-05)."""
        last_err: Optional[Exception] = None
        for proto_ver in self.SUPPORTED_PROTOCOL_VERSIONS:
            params = {
                "protocolVersion": proto_ver,
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {},
                    "elicitation": {"form": {}},
                },
                "clientInfo": {
                    "name": "PAI-Agent",
                    "version": "1.5.0",
                },
            }
            try:
                res = self.transport.send_request("initialize", params)
                self.server_info = res
                self.server_capabilities = res.get("capabilities", {}) if isinstance(res, dict) else {}
                self.protocol_version = str(res.get("protocolVersion") or proto_ver)
                self.is_initialized = True
                return res
            except Exception as exc:
                last_err = exc
        raise RuntimeError(f"MCP initialize handshake failed: {last_err}")

    def _tool_permitted_by_policy(self, tool_def: MCPToolDefinition) -> bool:
        p = self.policy
        if p.excluded_tools and tool_def.name in p.excluded_tools:
            return False
        if p.allowed_tools and tool_def.name not in p.allowed_tools:
            return False
        if p.toolsets and tool_def.toolset not in ("default", "") and tool_def.toolset not in p.toolsets:
            return False
        if p.read_only and tool_def.risk != Risk.READ:
            return False
        return True

    def list_tools(self, apply_policy: bool = True) -> List[MCPToolDefinition]:
        """Discovers tools registered on the MCP server, enforcing policy/toolset filters."""
        if not self.is_initialized:
            self.initialize()
        res = self.transport.send_request("tools/list", {})
        tools_raw = res.get("tools", [])
        self.available_tools.clear()
        is_remote = isinstance(self.transport, StreamableHttpMCPTransport) and not self.transport.is_loopback
        tool_list: List[MCPToolDefinition] = []
        for t in tools_raw:
            ann = t.get("annotations") if isinstance(t.get("annotations"), dict) else {}
            meta = t.get("_meta") if isinstance(t.get("_meta"), dict) else {}
            toolset = str(meta.get("toolset") or t.get("toolset") or "default")
            name = str(t.get("name", ""))
            risk = infer_mcp_tool_risk(name, annotations=ann, transport_is_remote=is_remote)
            tool_def = MCPToolDefinition(
                name=name,
                description=str(t.get("description", "")),
                input_schema=t.get("inputSchema", {}),
                server_name=self.name,
                toolset=toolset,
                read_only_hint=ann.get("readOnlyHint"),
                destructive_hint=ann.get("destructiveHint"),
                risk=risk,
            )
            if apply_policy and not self._tool_permitted_by_policy(tool_def):
                continue
            self.available_tools[tool_def.name] = tool_def
            tool_list.append(tool_def)
        return tool_list

    def list_resources(self) -> List[MCPResourceDefinition]:
        """Discovers application-controlled URI resources exposed by the server."""
        if not self.is_initialized:
            self.initialize()
        try:
            res = self.transport.send_request("resources/list", {})
        except Exception:
            return []
        out: List[MCPResourceDefinition] = []
        self.available_resources.clear()
        for r in res.get("resources", []):
            rdef = MCPResourceDefinition(
                uri=str(r.get("uri", "")),
                name=str(r.get("name", r.get("uri", ""))),
                description=str(r.get("description", "")),
                mime_type=str(r.get("mimeType", "text/plain")),
                server_name=self.name,
            )
            if rdef.uri:
                self.available_resources[rdef.uri] = rdef
                out.append(rdef)
        return out

    def read_resource(self, uri: str) -> Tuple[str, bool]:
        """Reads an MCP resource URI, scans for secrets, and wraps as untrusted data."""
        if not self.is_initialized:
            self.initialize()
        res = self.transport.send_request("resources/read", {"uri": str(uri)})
        contents = res.get("contents", []) if isinstance(res, dict) else []
        chunks: List[str] = []
        for item in contents:
            if isinstance(item, dict) and "text" in item:
                chunks.append(str(item["text"]))
            elif isinstance(item, dict) and "blob" in item:
                chunks.append(f"[binary resource mime={item.get('mimeType', 'application/octet-stream')} bytes={len(str(item['blob']))}]")
        raw = "\n".join(chunks) if chunks else str(res)
        return redact_and_sanitize_mcp_text(raw, source_label=f"mcp_resource:{self.name}:{uri}")

    def list_prompts(self) -> List[MCPPromptDefinition]:
        """Discovers reusable user-triggered prompt templates from the server."""
        if not self.is_initialized:
            self.initialize()
        try:
            res = self.transport.send_request("prompts/list", {})
        except Exception:
            return []
        out: List[MCPPromptDefinition] = []
        self.available_prompts.clear()
        for p in res.get("prompts", []):
            pdef = MCPPromptDefinition(
                name=str(p.get("name", "")),
                description=str(p.get("description", "")),
                arguments=list(p.get("arguments", []) or []),
                server_name=self.name,
            )
            if pdef.name:
                self.available_prompts[pdef.name] = pdef
                out.append(pdef)
        return out

    def get_prompt(self, prompt_name: str, arguments: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Resolves a prompt template on the MCP server with user arguments."""
        if not self.is_initialized:
            self.initialize()
        return self.transport.send_request(
            "prompts/get",
            {"name": str(prompt_name), "arguments": arguments or {}},
        )

    def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        broker: Optional[ToolBroker] = None,
        confirm: Optional[Callable[[ToolRequest], bool]] = None,
        tainted: bool = False,
    ) -> MCPToolResult:
        """Executes a tool on the MCP server with policy firewall + ToolBroker checks."""
        if not self.is_initialized:
            self.initialize()

        tdef = self.available_tools.get(tool_name)
        is_remote = isinstance(self.transport, StreamableHttpMCPTransport) and not self.transport.is_loopback
        inferred_risk = tdef.risk if tdef else infer_mcp_tool_risk(tool_name, transport_is_remote=is_remote)

        if self.policy.excluded_tools and tool_name in self.policy.excluded_tools:
            raise PermissionDenied(f"Tool '{tool_name}' is excluded by server policy on '{self.name}'.")
        if self.policy.allowed_tools and tool_name not in self.policy.allowed_tools:
            raise PermissionDenied(f"Tool '{tool_name}' is not in server allowed_tools for '{self.name}'.")
        if self.policy.read_only and inferred_risk != Risk.READ:
            raise PermissionDenied(
                f"Read-only policy active on MCP server '{self.name}': blocked non-READ tool '{tool_name}'."
            )

        effective_tainted = bool(tainted or self.policy.lockdown_mode)
        needs_confirm = (inferred_risk >= Risk.DESTRUCTIVE) or (effective_tainted and inferred_risk >= Risk.WRITE)

        if broker is not None:
            broker.invoke(
                "mcp_call_tool",
                {"server": self.name, "tool": tool_name, "arguments": arguments},
                tainted=effective_tainted,
            )
        elif needs_confirm:
            if confirm is None:
                raise PermissionDenied(
                    f"MCP tool '{self.name}:{tool_name}' (risk={inferred_risk.name}, tainted={effective_tainted}) requires human confirmation."
                )
            req = ToolRequest(
                f"mcp:{self.name}:{tool_name}",
                inferred_risk,
                json.dumps(arguments, default=str)[:200],
                effective_tainted,
                "lockdown/tainted MCP side effect" if effective_tainted else "destructive/outbound MCP tool",
            )
            if not bool(confirm(req)):
                raise PermissionDenied(f"MCP tool '{self.name}:{tool_name}' declined by user.")

        params = {
            "name": tool_name,
            "arguments": arguments,
        }
        res = self.transport.send_request("tools/call", params)
        content = res.get("content", [])
        is_error = bool(res.get("isError", False))
        text_parts = [item.get("text", "") for item in content if isinstance(item, dict) and "text" in item]
        raw_text = "\n".join(text_parts) if text_parts else str(res)
        sanitized, redacted = redact_and_sanitize_mcp_text(raw_text, source_label=f"mcp:{self.name}:{tool_name}")
        return MCPToolResult(
            content=content,
            is_error=is_error,
            raw_text="" if redacted else raw_text,
            sanitized_text=sanitized,
            tainted=True,
            secret_redacted=redacted,
        )

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
        policy: Optional[MCPServerPolicy] = None,
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
        client = MCPClient(name=name.strip(), transport=transport, policy=policy)
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
    def connect_http(
        cls,
        name: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        allow_loopback: bool = False,
        offline_check_fn: Optional[Callable[[], bool]] = None,
        broker: Optional[ToolBroker] = None,
        confirm: Optional[Callable[[ToolRequest], bool]] = None,
        tainted: bool = False,
        policy: Optional[MCPServerPolicy] = None,
    ) -> MCPClient:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("MCP server name must be a non-empty string")
        if broker is None and confirm is None:
            raise PermissionDenied("MCP HTTP registration requires ToolBroker or explicit confirmation")
        transport = StreamableHttpMCPTransport(
            url=url,
            headers=headers,
            allow_loopback=allow_loopback,
            offline_check_fn=offline_check_fn,
            broker=broker,
            confirm=confirm,
            tainted=tainted,
            require_confirmation=True,
        )
        client = MCPClient(name=name.strip(), transport=transport, policy=policy)
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
    def list_all_resources(cls) -> List[MCPResourceDefinition]:
        all_res = []
        for s in cls._servers.values():
            try:
                all_res.extend(s.list_resources())
            except Exception:
                pass
        return all_res

    @classmethod
    def list_all_prompts(cls) -> List[MCPPromptDefinition]:
        all_prompts = []
        for s in cls._servers.values():
            try:
                all_prompts.extend(s.list_prompts())
            except Exception:
                pass
        return all_prompts

    @classmethod
    def format_status(cls, color_enabled: bool = False) -> str:
        lines = ["Model Context Protocol (MCP Hub Status):"]
        if not cls._servers:
            lines.append("  (No active MCP servers connected. Use /mcp connect <command>)")
            lines.append("  Supported: STDIO + Streamable HTTP/SSE (GitHub MCP, Filesystem, Memory, Git, Windows-MCP)")
            return "\n".join(lines)
        for name, s in cls._servers.items():
            flags = []
            if s.policy.read_only:
                flags.append("read-only")
            if s.policy.lockdown_mode:
                flags.append("lockdown")
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            lines.append(f"  - Server: {name} (Running{flag_str}, {len(s.available_tools)} tools)")
            for t_name, t in s.available_tools.items():
                lines.append(f"    * {t_name} [{t.risk.name}]: {t.description}")
        return "\n".join(lines)
