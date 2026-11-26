"""Built-in Windows Desktop Automation MCP Server for PAI (JSON-RPC 2.0 STDIO).

Exposes structured tools inspired by `CursorTouch/Windows-MCP` and
`tanob/mcp-desktop-automation` over standard MCP JSON-RPC 2.0 (`stdin`/`stdout`),
enforcing PAI's `ToolBroker`, allowlisted app launching, and fail-closed safety.

Tools exposed:
  - State-Tool      : Active windows + Windows UIA accessibility tree
  - Launch-Tool     : Launch safe allowlisted desktop apps (no shell=True)
  - Click-Tool      : Mouse click at (x, y) or UIA element query
  - Move-Tool       : Move cursor to (x, y)
  - Drag-Tool       : Mouse drag from (x1, y1) to (x2, y2)
  - Scroll-Tool     : Scroll wheel at (x, y)
  - Type-Tool       : Type text via Unicode SendInput or UIA ValuePattern
  - Shortcut-Tool   : Execute keyboard key or hotkey combination
  - Window-Tool     : Focus a window by title or process name
  - Screenshot-Tool : Capture screen PNG (base64, capped width)
  - Clipboard-Tool  : Copy text safely to OS clipboard
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

RESEARCH_DIR = Path(__file__).resolve().parent
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

try:
    from research import automation
    from research.capabilities import PermissionDenied, ToolRequest
    from research.desktop_control import DesktopControlError, DesktopController
except ModuleNotFoundError:
    import automation
    from capabilities import PermissionDenied, ToolRequest
    from desktop_control import DesktopControlError, DesktopController


MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "pai-windows-mcp", "version": "1.0.0"}

TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "name": "State-Tool",
        "description": "Inspect visible Windows apps, foreground window, and interactive UIA accessibility elements.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hwnd": {"type": "integer", "description": "Optional window handle (defaults to foreground)"},
                "max_nodes": {"type": "integer", "description": "Maximum UIA nodes to collect (<= 120)"},
            },
        },
    },
    {
        "name": "Launch-Tool",
        "description": "Launch a safe allowlisted desktop application (e.g. chrome, telegram, whatsapp, notepad, calc, vscode).",
        "inputSchema": {
            "type": "object",
            "properties": {"app": {"type": "string", "description": "Allowlisted application name"}},
            "required": ["app"],
        },
    },
    {
        "name": "Click-Tool",
        "description": "Click at screen coordinates (x, y) or click an interactive UIA element by name/AutomationId.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x": {"type": "integer"},
                "y": {"type": "integer"},
                "element": {"type": "string", "description": "Optional UIA element name or AutomationId"},
                "button": {"type": "string", "enum": ["left", "right", "middle"]},
                "clicks": {"type": "integer"},
            },
        },
    },
    {
        "name": "Move-Tool",
        "description": "Move mouse cursor to screen coordinates (x, y).",
        "inputSchema": {
            "type": "object",
            "properties": {"x": {"type": "integer"}, "y": {"type": "integer"}},
            "required": ["x", "y"],
        },
    },
    {
        "name": "Drag-Tool",
        "description": "Drag mouse from (x1, y1) to (x2, y2).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x1": {"type": "integer"},
                "y1": {"type": "integer"},
                "x2": {"type": "integer"},
                "y2": {"type": "integer"},
            },
            "required": ["x1", "y1", "x2", "y2"],
        },
    },
    {
        "name": "Scroll-Tool",
        "description": "Scroll mouse wheel at (x, y). Positive delta scrolls up, negative scrolls down.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "x": {"type": "integer"},
                "y": {"type": "integer"},
                "delta": {"type": "integer"},
            },
            "required": ["x", "y", "delta"],
        },
    },
    {
        "name": "Type-Tool",
        "description": "Type text into the focused control or into a named UIA text input.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "element": {"type": "string", "description": "Optional UIA element name/AutomationId"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "Shortcut-Tool",
        "description": "Press a single key (e.g. 'enter', 'tab') or hotkey combo (e.g. 'ctrl+f', 'ctrl+k').",
        "inputSchema": {
            "type": "object",
            "properties": {"keys": {"type": "string"}},
            "required": ["keys"],
        },
    },
    {
        "name": "Window-Tool",
        "description": "Focus and restore a visible window matching title or process name.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "Screenshot-Tool",
        "description": "Capture the desktop screen as a resized PNG (base64).",
        "inputSchema": {
            "type": "object",
            "properties": {"max_width": {"type": "integer"}},
        },
    },
    {
        "name": "Clipboard-Tool",
        "description": "Copy text safely to the OS clipboard.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
]


class WindowsMCPServer:
    """In-process and STDIO JSON-RPC 2.0 handler for PAI Windows MCP tools."""

    def __init__(
        self,
        controller: Optional[DesktopController] = None,
        confirm: Optional[Callable[[ToolRequest], bool]] = None,
    ):
        self.controller = controller or DesktopController(confirm=confirm)

    def _call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        args = arguments or {}
        if name == "State-Tool":
            res = self.controller.get_state(
                hwnd=int(args.get("hwnd", 0) or 0),
                max_nodes=int(args.get("max_nodes", 120) or 120),
            )
            return {"content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}], "isError": False}

        if name == "Screenshot-Tool":
            res = self.controller.capture_screenshot(max_width=int(args.get("max_width", 1280) or 1280))
            return {"content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}], "isError": False}

        if name == "Launch-Tool":
            app_key = str(args.get("app", "")).strip().lower()
            if self.controller.broker._confirm is None:
                raise PermissionDenied("Launch-Tool requires active confirmation policy.")
            req = ToolRequest("Launch-Tool", 2, json.dumps({"app": app_key}), True, "launching allowlisted desktop app")
            if not self.controller.broker._confirm(req):
                raise PermissionDenied("Launch-Tool declined by confirmation.")
            ok, msg = automation._launch_app(app_key)
            return {"content": [{"type": "text", "text": msg}], "isError": not ok}

        if name == "Window-Tool":
            res = self.controller.focus_window(str(args.get("query", "")))
            return {"content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}], "isError": False}

        if name == "Move-Tool":
            res = self.controller.mouse_move(int(args["x"]), int(args["y"]))
            return {"content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}], "isError": False}

        if name == "Drag-Tool":
            res = self.controller.mouse_drag(int(args["x1"]), int(args["y1"]), int(args["x2"]), int(args["y2"]))
            return {"content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}], "isError": False}

        if name == "Scroll-Tool":
            res = self.controller.mouse_scroll(int(args["x"]), int(args["y"]), int(args.get("delta", -3)))
            return {"content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}], "isError": False}

        if name == "Click-Tool":
            elem = str(args.get("element", "")).strip()
            if elem:
                res = self.controller.uia_click(elem)
            elif "x" in args and "y" in args:
                res = self.controller.mouse_click(
                    int(args["x"]),
                    int(args["y"]),
                    button=str(args.get("button", "left")),
                    clicks=int(args.get("clicks", 1)),
                )
            else:
                raise DesktopControlError("Click-Tool requires either 'element' or ('x', 'y').")
            return {"content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}], "isError": False}

        if name == "Type-Tool":
            elem = str(args.get("element", "")).strip()
            text = str(args.get("text", ""))
            if elem:
                res = self.controller.uia_set_text(elem, text)
            else:
                res = self.controller.type_text(text)
            return {"content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}], "isError": False}

        if name == "Shortcut-Tool":
            keys = str(args.get("keys", "")).strip()
            if "+" in keys:
                res = self.controller.hotkey(keys)
            else:
                res = self.controller.press_key(keys)
            return {"content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}], "isError": False}

        if name == "Clipboard-Tool":
            ok = automation.copy_to_clipboard(str(args.get("text", "")))
            return {"content": [{"type": "text", "text": "Copied to clipboard." if ok else "Clipboard unavailable."}], "isError": not ok}

        raise DesktopControlError(f"Unknown tool: {name}")

    def handle_request(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        req_id = payload.get("id")
        method = payload.get("method", "")
        params = payload.get("params") or {}

        if method == "notifications/initialized":
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOL_SCHEMAS},
            }

        if method == "tools/call":
            tool_name = str(params.get("name", ""))
            tool_args = params.get("arguments") or {}
            try:
                res = self._call_tool(tool_name, tool_args)
                return {"jsonrpc": "2.0", "id": req_id, "result": res}
            except (PermissionDenied, DesktopControlError, KeyError, ValueError) as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": f"Error: {exc}"}], "isError": True},
                }
            except Exception as exc:
                if type(exc).__name__ == "PermissionDenied":
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": f"Error: {exc}"}], "isError": True},
                    }
                raise

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def serve_stdio(allow_control: bool = False) -> int:
    confirm_fn = (lambda _req: True) if allow_control else None
    server = WindowsMCPServer(confirm=confirm_fn)
    for line in sys.stdin:
        raw = line.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue
        resp = server.handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PAI Windows Desktop Automation MCP Server")
    parser.add_argument("--allow-control", action="store_true", help="Grant interactive desktop control confirmation")
    ns = parser.parse_args()
    raise SystemExit(serve_stdio(allow_control=ns.allow_control))
