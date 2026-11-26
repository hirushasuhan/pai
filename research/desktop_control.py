"""ToolBroker-governed Windows Desktop Control & UIA Driver for PAI.

Provides PyAutoGUI-style mouse/keyboard primitives, pywinauto/Windows-MCP-style
Windows UI Automation (UIA) tree inspection, and screen capture through the
zero-dependency native helper `desktop/bin/pai_ui_agent.exe`, all gated by
`capabilities.ToolBroker` and a top-left `(0,0)` failsafe + abort event.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
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


_DEFAULT_TIMEOUT_SEC = 12.0
_MAX_UIA_NODES = 120
_MAX_TITLE_LEN = 140
_SELF_WINDOW_MARKERS = ("pai studio", "personal agentic ai", "pai-desktop")

# Hotkeys blocked from unattended execution to protect system state
_BLOCKED_HOTKEYS = frozenset({
    "alt+f4",
    "ctrl+alt+delete",
    "ctrl+alt+del",
    "win+l",
    "win+r",
})


class DesktopControlError(Exception):
    """Raised when desktop control invocation fails or helper is unavailable."""


class FailSafeTriggered(DesktopControlError):
    """Raised when the cursor reaches the top-left (0,0) corner or abort is set."""


def find_ui_agent_binary() -> Optional[Path]:
    """Locate compiled native Win32/UIA helper `pai_ui_agent.exe`."""
    here = Path(__file__).resolve()
    repo_root = here.parent.parent
    candidates = [
        repo_root / "desktop" / "bin" / "pai_ui_agent.exe",
        here.parent / "bin" / "pai_ui_agent.exe",
        Path(sys.executable).resolve().parent / "desktop" / "bin" / "pai_ui_agent.exe",
    ]
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _sanitize_label(text: str, max_len: int = _MAX_TITLE_LEN) -> str:
    """Defang untrusted screen/UIA text so prompt markers cannot spoof provenance."""
    clean = ingest.defang_envelope_markers(str(text or ""))
    clean = clean.replace("[[SRC:", "[ [SRC:")
    clean = " ".join(clean.split())
    return clean[:max_len]


def sanitize_desktop_state(raw_state: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize all untrusted window titles and UIA element names in a state snapshot."""
    state = dict(raw_state or {})
    fg = state.get("foreground")
    if isinstance(fg, dict):
        fg_copy = dict(fg)
        fg_copy["title"] = _sanitize_label(fg.get("title", ""))
        fg_copy["process"] = _sanitize_label(fg.get("process", ""), 64)
        state["foreground"] = fg_copy

    clean_windows: List[Dict[str, Any]] = []
    for w in (state.get("windows") or [])[:35]:
        if not isinstance(w, dict):
            continue
        wc = dict(w)
        wc["title"] = _sanitize_label(w.get("title", ""))
        wc["process"] = _sanitize_label(w.get("process", ""), 64)
        clean_windows.append(wc)
    state["windows"] = clean_windows

    clean_elems: List[Dict[str, Any]] = []
    for el in (state.get("elements") or [])[:_MAX_UIA_NODES]:
        if not isinstance(el, dict):
            continue
        ec = dict(el)
        ec["name"] = _sanitize_label(el.get("name", ""), 120)
        ec["aid"] = _sanitize_label(el.get("aid", ""), 80)
        ec["type"] = _sanitize_label(el.get("type", ""), 40)
        clean_elems.append(ec)
    state["elements"] = clean_elems
    state["tainted"] = True
    return state


def is_self_window(title: str, process: str = "") -> bool:
    """Return True if a window belongs to PAI Desktop itself (self-click guard)."""
    t_low = (title or "").lower()
    p_low = (process or "").lower()
    if "pai-desktop" in p_low:
        return True
    return any(marker in t_low for marker in _SELF_WINDOW_MARKERS)


class DesktopController:
    """ToolBroker-governed desktop UIA, mouse, keyboard, and screenshot controller."""

    def __init__(
        self,
        confirm: Optional[Callable[[ToolRequest], bool]] = None,
        abort_event: Optional[threading.Event] = None,
        binary_path: Optional[Path] = None,
        allow_self_window: bool = False,
        max_calls: Optional[int] = 120,
        expires: Optional[float] = None,
    ):
        self.abort_event = abort_event or threading.Event()
        self.binary_path = binary_path or find_ui_agent_binary()
        self.allow_self_window = allow_self_window
        self._last_state: Optional[Dict[str, Any]] = None

        tools = [
            Tool("desktop_state", Risk.READ, self._raw_state),
            Tool("desktop_screenshot", Risk.READ, self._raw_screenshot),
            Tool("desktop_focus_window", Risk.WRITE, self._raw_focus_window),
            Tool("desktop_mouse_move", Risk.WRITE, self._raw_mouse_move),
            Tool("desktop_scroll", Risk.WRITE, self._raw_mouse_scroll),
            Tool("desktop_click", Risk.DESTRUCTIVE, self._raw_mouse_click),
            Tool("desktop_drag", Risk.DESTRUCTIVE, self._raw_mouse_drag),
            Tool("desktop_type", Risk.DESTRUCTIVE, self._raw_type_text),
            Tool("desktop_key", Risk.DESTRUCTIVE, self._raw_key_press),
            Tool("desktop_hotkey", Risk.DESTRUCTIVE, self._raw_hotkey),
            Tool("desktop_uia_click", Risk.DESTRUCTIVE, self._raw_uia_click),
            Tool("desktop_uia_set_text", Risk.DESTRUCTIVE, self._raw_uia_set_text),
        ]
        grants = [Grant(t.name, max_calls=max_calls, expires=expires) for t in tools]
        self.broker = ToolBroker(tools=tools, grants=grants, confirm=confirm)

    def is_available(self) -> bool:
        return bool(self.binary_path and self.binary_path.is_file() and (sys.platform.startswith("win") or os.name == "nt"))

    def _check_abort(self) -> None:
        if self.abort_event.is_set():
            raise FailSafeTriggered("Desktop automation aborted by user stop signal.")

    def _run_helper(self, args: Sequence[str], timeout: float = _DEFAULT_TIMEOUT_SEC) -> Dict[str, Any]:
        self._check_abort()
        if not self.binary_path or not self.binary_path.is_file():
            raise DesktopControlError("Native UI agent binary 'pai_ui_agent.exe' is not available.")
        cmd = [str(self.binary_path)] + [str(a) for a in args]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise DesktopControlError(f"Desktop UI agent timed out after {timeout}s") from exc
        except Exception as exc:
            raise DesktopControlError(f"Failed to run desktop UI agent: {exc}") from exc

        raw_out = (proc.stdout or "").strip()
        if not raw_out:
            err = (proc.stderr or "").strip()
            raise DesktopControlError(f"Desktop UI agent produced no output (rc={proc.returncode}): {err}")
        try:
            data = json.loads(raw_out.splitlines()[-1])
        except json.JSONDecodeError as exc:
            raise DesktopControlError(f"Invalid JSON from desktop UI agent: {raw_out[:200]}") from exc

        if data.get("failsafe"):
            raise FailSafeTriggered(data.get("error") or "Aborted by top-left corner (0,0) failsafe.")
        if not data.get("ok"):
            raise DesktopControlError(data.get("error") or f"Desktop action failed (rc={proc.returncode})")
        return data

    def _guard_coordinates(self, x: int, y: int) -> Tuple[int, int]:
        xi, yi = int(x), int(y)
        if xi < -3840 or xi > 7680 or yi < -2160 or yi > 4320:
            raise DesktopControlError(f"Coordinates ({xi}, {yi}) outside safe virtual screen bounds.")
        if xi <= 2 and yi <= 2:
            raise FailSafeTriggered("Refusing click/move inside (0,0) failsafe zone.")
        return xi, yi

    def _guard_foreground_not_self(self) -> None:
        if self.allow_self_window or not self._last_state:
            return
        fg = self._last_state.get("foreground") or {}
        if is_self_window(fg.get("title", ""), fg.get("process", "")):
            raise PermissionDenied("Blocked unattended input targeting PAI Desktop window itself.")

    # ------------------------------------------------------------------ raw ops
    def _raw_state(self, hwnd: int = 0, max_nodes: int = _MAX_UIA_NODES) -> Dict[str, Any]:
        args = ["state", "--max-nodes", str(min(int(max_nodes), _MAX_UIA_NODES))]
        if hwnd:
            args.extend(["--hwnd", str(int(hwnd))])
        data = sanitize_desktop_state(self._run_helper(args))
        self._last_state = data
        return data

    def _raw_screenshot(self, max_width: int = 1280) -> Dict[str, Any]:
        return self._run_helper(["screenshot", "--max-width", str(int(max_width))], timeout=15.0)

    def _raw_focus_window(self, query: str) -> Dict[str, Any]:
        q = str(query or "").strip()
        if not q:
            raise DesktopControlError("Window focus query cannot be empty.")
        if not self.allow_self_window and is_self_window(q):
            raise PermissionDenied("Cannot focus PAI Desktop window for unattended automation.")
        return self._run_helper(["focus_window", q])

    def _raw_mouse_move(self, x: int, y: int) -> Dict[str, Any]:
        xi, yi = self._guard_coordinates(x, y)
        return self._run_helper(["mouse_move", str(xi), str(yi)])

    def _raw_mouse_click(self, x: int, y: int, button: str = "left", clicks: int = 1) -> Dict[str, Any]:
        xi, yi = self._guard_coordinates(x, y)
        self._guard_foreground_not_self()
        btn = button if button in ("left", "right", "middle") else "left"
        cnt = max(1, min(int(clicks), 3))
        return self._run_helper(["mouse_click", str(xi), str(yi), "--button", btn, "--clicks", str(cnt)])

    def _raw_mouse_drag(self, x1: int, y1: int, x2: int, y2: int) -> Dict[str, Any]:
        x1i, y1i = self._guard_coordinates(x1, y1)
        x2i, y2i = self._guard_coordinates(x2, y2)
        self._guard_foreground_not_self()
        return self._run_helper(["mouse_drag", str(x1i), str(y1i), str(x2i), str(y2i)])

    def _raw_mouse_scroll(self, x: int, y: int, delta: int = -3) -> Dict[str, Any]:
        xi, yi = self._guard_coordinates(x, y)
        d = max(-20, min(int(delta), 20))
        return self._run_helper(["mouse_scroll", str(xi), str(yi), str(d)])

    def _raw_type_text(self, text: str) -> Dict[str, Any]:
        self._guard_foreground_not_self()
        raw = str(text or "")
        if len(raw) > 4000:
            raise DesktopControlError("Text payload exceeds 4000 character single-step cap.")
        b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii")
        return self._run_helper(["type_text", "--b64", b64])

    def _raw_key_press(self, key: str) -> Dict[str, Any]:
        self._guard_foreground_not_self()
        k = str(key or "").strip().lower()
        if not k:
            raise DesktopControlError("Key name cannot be empty.")
        return self._run_helper(["key_press", k])

    def _raw_hotkey(self, keys: str) -> Dict[str, Any]:
        self._guard_foreground_not_self()
        norm = "+".join(p.strip().lower() for p in str(keys or "").split("+") if p.strip())
        if not norm:
            raise DesktopControlError("Hotkey cannot be empty.")
        if norm in _BLOCKED_HOTKEYS:
            raise PermissionDenied(f"Hotkey '{norm}' is blocked by desktop safety policy.")
        return self._run_helper(["hotkey", norm])

    def _raw_uia_click(self, query: str, hwnd: int = 0) -> Dict[str, Any]:
        self._guard_foreground_not_self()
        q = str(query or "").strip()
        if not q:
            raise DesktopControlError("UIA element query cannot be empty.")
        args = ["uia_click", q]
        if hwnd:
            args.extend(["--hwnd", str(int(hwnd))])
        return self._run_helper(args)

    def _raw_uia_set_text(self, query: str, text: str, hwnd: int = 0) -> Dict[str, Any]:
        self._guard_foreground_not_self()
        q = str(query or "").strip()
        raw = str(text or "")
        if not q:
            raise DesktopControlError("UIA element query cannot be empty.")
        if len(raw) > 4000:
            raise DesktopControlError("Text payload exceeds 4000 character single-step cap.")
        b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii")
        args = ["uia_set_text", q, "--b64", b64]
        if hwnd:
            args.extend(["--hwnd", str(int(hwnd))])
        return self._run_helper(args)

    # ------------------------------------------------------------------ public brokered API
    def get_state(self, hwnd: int = 0, max_nodes: int = _MAX_UIA_NODES) -> Dict[str, Any]:
        return self.broker.invoke("desktop_state", {"hwnd": hwnd, "max_nodes": max_nodes}, tainted=False)

    def capture_screenshot(self, max_width: int = 1280) -> Dict[str, Any]:
        return self.broker.invoke("desktop_screenshot", {"max_width": max_width}, tainted=False)

    def focus_window(self, query: str, tainted: bool = True) -> Dict[str, Any]:
        return self.broker.invoke("desktop_focus_window", {"query": query}, tainted=tainted)

    def mouse_move(self, x: int, y: int, tainted: bool = True) -> Dict[str, Any]:
        return self.broker.invoke("desktop_mouse_move", {"x": x, "y": y}, tainted=tainted)

    def mouse_scroll(self, x: int, y: int, delta: int = -3, tainted: bool = True) -> Dict[str, Any]:
        return self.broker.invoke("desktop_scroll", {"x": x, "y": y, "delta": delta}, tainted=tainted)

    def mouse_click(self, x: int, y: int, button: str = "left", clicks: int = 1, tainted: bool = True) -> Dict[str, Any]:
        return self.broker.invoke(
            "desktop_click",
            {"x": x, "y": y, "button": button, "clicks": clicks},
            tainted=tainted,
        )

    def mouse_drag(self, x1: int, y1: int, x2: int, y2: int, tainted: bool = True) -> Dict[str, Any]:
        return self.broker.invoke(
            "desktop_drag",
            {"x1": x1, "y1": y1, "x2": x2, "y2": y2},
            tainted=tainted,
        )

    def type_text(self, text: str, tainted: bool = True) -> Dict[str, Any]:
        return self.broker.invoke("desktop_type", {"text": text}, tainted=tainted)

    def press_key(self, key: str, tainted: bool = True) -> Dict[str, Any]:
        return self.broker.invoke("desktop_key", {"key": key}, tainted=tainted)

    def hotkey(self, keys: str, tainted: bool = True) -> Dict[str, Any]:
        return self.broker.invoke("desktop_hotkey", {"keys": keys}, tainted=tainted)

    def uia_click(self, query: str, hwnd: int = 0, tainted: bool = True) -> Dict[str, Any]:
        return self.broker.invoke("desktop_uia_click", {"query": query, "hwnd": hwnd}, tainted=tainted)

    def uia_set_text(self, query: str, text: str, hwnd: int = 0, tainted: bool = True) -> Dict[str, Any]:
        return self.broker.invoke("desktop_uia_set_text", {"query": query, "text": text, "hwnd": hwnd}, tainted=tainted)
