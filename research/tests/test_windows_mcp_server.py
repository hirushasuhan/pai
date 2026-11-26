"""Tests for PAI Windows Desktop Automation MCP Server (research/windows_mcp_server.py)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

RESEARCH_DIR = Path(__file__).resolve().parent.parent
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

import desktop_control as dc_mod
import windows_mcp_server as wmcp


class TestWindowsMCPServer(unittest.TestCase):
    """Verify JSON-RPC 2.0 protocol, tool schemas, and ToolBroker fail-closed containment."""

    def test_initialize_and_tools_list(self) -> None:
        srv = wmcp.WindowsMCPServer(confirm=None)
        init = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(init["result"]["serverInfo"]["name"], "pai-windows-mcp")

        tools_resp = srv.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        names = {t["name"] for t in tools_resp["result"]["tools"]}
        for expected in ("State-Tool", "Launch-Tool", "Click-Tool", "Move-Tool", "Type-Tool", "Shortcut-Tool", "Screenshot-Tool"):
            self.assertIn(expected, names)

    def test_negative_control_denies_destructive_tools_without_confirm(self) -> None:
        ctrl = dc_mod.DesktopController(confirm=None, binary_path=Path(__file__))
        srv = wmcp.WindowsMCPServer(controller=ctrl)

        for tool, args in [
            ("Click-Tool", {"x": 200, "y": 200}),
            ("Type-Tool", {"text": "hello"}),
            ("Shortcut-Tool", {"keys": "ctrl+c"}),
            ("Launch-Tool", {"app": "notepad"}),
        ]:
            resp = srv.handle_request({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": tool, "arguments": args},
            })
            self.assertTrue(resp["result"]["isError"], f"Expected ToolBroker error for {tool} without confirmation")

    def test_confirmed_tool_calls_dispatch_cleanly(self) -> None:
        ctrl = dc_mod.DesktopController(confirm=lambda _r: True, binary_path=Path(__file__))
        srv = wmcp.WindowsMCPServer(controller=ctrl)

        with patch.object(ctrl, "_run_helper", return_value={"ok": True, "action": "mouse_click"}) as mock_run:
            resp = srv.handle_request({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "Click-Tool", "arguments": {"x": 350, "y": 420}},
            })
            self.assertFalse(resp["result"]["isError"])
            mock_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
