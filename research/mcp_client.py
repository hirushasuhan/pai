"""
Model Context Protocol (MCP) Client for Personal Agentic AI (PAI).
Implements JSON-RPC 2.0 communication over STDIO and HTTP transports.
Bridges external MCP tool servers into PAI's sandboxed Capability Broker.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


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
    def __init__(self, command: List[str], env: Optional[Dict[str, str]] = None):
        self.command = command
        self._proc: Optional[subprocess.Popen] = None
        self._req_id = 0
        self._lock = threading.Lock()
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        try:
            self._proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
                env=merged_env,
            )
        except Exception as e:
            raise ConnectionError(f"Failed to start MCP server process '{command}': {e}")

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

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> MCPToolResult:
        """Executes a tool on the MCP server with given JSON arguments."""
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
    def register_server(cls, name: str, client: MCPClient) -> None:
        cls._servers[name] = client

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
