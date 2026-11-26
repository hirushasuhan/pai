"""Commander Desktop Orchestrator (Observe -> Plan -> Act -> Verify + HITL).

Combines architectural patterns from:
  - Orkas (`Commander` step planning + deterministic window/state verification gates)
  - Eigent (Human-in-the-Loop confirmation pause before irreversible Send/Delete actions)
  - Windows-MCP / pywinauto (UIA accessibility tree element targeting)
  - mcp-desktop-automation / PyAutoGUI (Screenshot + Vision LLM coordinate fallback)
"""

from __future__ import annotations

import json
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

try:
    from research import automation, ingest
    from research.capabilities import PermissionDenied, ToolRequest
    from research.desktop_control import DesktopControlError, DesktopController, FailSafeTriggered
except ModuleNotFoundError:
    import automation
    import ingest
    from capabilities import PermissionDenied, ToolRequest
    from desktop_control import DesktopControlError, DesktopController, FailSafeTriggered


MAX_STEPS = 10
_SENSITIVE_ACTION_KEYWORDS = ("send", "submit", "delete", "remove", "pay", "purchase", "confirm", "post")


@dataclass
class OrchestratorResult:
    ok: bool
    status: str  # "completed" | "pending_confirmation" | "aborted" | "error"
    summary: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    pending_action: Optional[Dict[str, Any]] = None
    vision_used: bool = False
    error: str = ""


def _parse_json_action(raw_text: str) -> Optional[Dict[str, Any]]:
    """Extract a single JSON object action from model output."""
    text = (raw_text or "").strip()
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    candidate = fence.group(1) if fence else text
    if not candidate.startswith("{"):
        brace = re.search(r"(\{.*\})", candidate, flags=re.DOTALL)
        if brace:
            candidate = brace.group(1)
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _is_sensitive_step(action: str, params: Dict[str, Any], target_app: str = "") -> bool:
    """Return True if an action requires explicit HITL Approve & Send confirmation."""
    act = (action or "").lower()
    if act == "ask_confirm":
        return True
    if act in ("click", "uia_click"):
        elem = str(params.get("element") or "").lower()
        if any(kw in elem for kw in _SENSITIVE_ACTION_KEYWORDS):
            return True
    if act == "key" and str(params.get("key") or "").lower() in ("enter", "return"):
        app_low = (target_app or "").lower()
        if any(m in app_low for m in ("telegram", "whatsapp", "mail", "gmail", "outlook")):
            return True
    return False


class DesktopOrchestrator:
    """Bounded desktop automation orchestrator with HITL approval and Vision fallback."""

    def __init__(
        self,
        controller: Optional[DesktopController] = None,
        plan_fn: Optional[Callable[[str], str]] = None,
        vision_fn: Optional[Callable[[str, str], str]] = None,
        session_confirm: Optional[Callable[[ToolRequest], bool]] = None,
    ):
        self.controller = controller or DesktopController(confirm=session_confirm)
        self.plan_fn = plan_fn
        self.vision_fn = vision_fn

    # ------------------------------------------------------------------ Messaging HITL workflows
    def prepare_messaging_send(
        self,
        app: str,
        recipient: str = "",
        phone: str = "",
        message: str = "",
    ) -> OrchestratorResult:
        """Prepare Telegram or WhatsApp message via UIA/input and pause for Approve & Send."""
        steps: List[Dict[str, Any]] = []
        app_norm = app.strip().lower()
        app_label = "Telegram" if app_norm == "telegram" else "WhatsApp"

        # Step 1: Launch / open URI
        if app_norm == "telegram":
            ok_open, open_msg = automation.open_telegram(
                contact=recipient,
                message=message,
                trigger_ui_search=False,
            )
        else:
            ok_open, open_msg = automation.open_whatsapp(
                contact=recipient,
                phone=phone,
                message=message,
            )
        steps.append({"step": 1, "action": "launch_app", "app": app_label, "ok": ok_open, "detail": open_msg})
        if not ok_open:
            return OrchestratorResult(ok=False, status="error", summary=open_msg, steps=steps, error=open_msg)

        # If native UIA controller is available and session is confirmed, focus & stage via UIA/shortcuts
        ui_staged = False
        if self.controller.is_available() and self.controller.broker._confirm is not None:
            try:
                focused = False
                for _ in range(8):
                    time.sleep(0.35)
                    try:
                        res = self.controller.focus_window(app_label)
                        if res.get("ok"):
                            focused = True
                            break
                    except DesktopControlError:
                        continue
                steps.append({"step": 2, "action": "focus_window", "target": app_label, "ok": focused})

                if focused and recipient:
                    search_hotkey = "ctrl+k" if app_norm == "telegram" else "ctrl+f"
                    self.controller.hotkey(search_hotkey)
                    time.sleep(0.2)
                    self.controller.type_text(recipient)
                    time.sleep(0.45)
                    self.controller.press_key("enter")
                    time.sleep(0.3)
                    steps.append({"step": 3, "action": "select_contact", "contact": recipient, "ok": True})

                    if message:
                        self.controller.type_text(message)
                        steps.append({"step": 4, "action": "stage_message", "chars": len(message), "ok": True})
                        ui_staged = True
            except (PermissionDenied, FailSafeTriggered, DesktopControlError) as exc:
                steps.append({"step": len(steps) + 1, "action": "ui_stage", "ok": False, "detail": str(exc)})

        if not message:
            return OrchestratorResult(
                ok=True,
                status="completed",
                summary=f"Opened {app_label}" + (f" for {recipient}" if recipient else "") + ".",
                steps=steps,
            )

        action_id = f"hitl_{uuid.uuid4().hex[:10]}"
        pending = {
            "action_id": action_id,
            "kind": "send_message",
            "app": app_label,
            "recipient": recipient or phone or "(selected chat)",
            "message": message,
            "ui_staged": ui_staged,
            "step_description": (
                f"Focus {app_label}, verify chat '{recipient or phone or 'current'}', and send message"
            ),
        }
        stage_note = (
            f"Staged message in {app_label} window."
            if ui_staged
            else f"Opened {app_label} and copied message to clipboard."
        )
        return OrchestratorResult(
            ok=True,
            status="pending_confirmation",
            summary=f"{stage_note} Click **Approve & Send** to transmit.",
            steps=steps,
            pending_action=pending,
        )

    def execute_confirmed_action(self, pending_action: Dict[str, Any]) -> OrchestratorResult:
        """Execute a user-approved HITL action (e.g. Approve & Send)."""
        if not pending_action:
            return OrchestratorResult(ok=False, status="error", summary="No pending action.", error="Missing pending_action")

        kind = pending_action.get("kind", "")
        steps: List[Dict[str, Any]] = []

        if kind == "send_message":
            app_label = pending_action.get("app", "Telegram")
            message = pending_action.get("message", "")
            ui_staged = bool(pending_action.get("ui_staged", False))

            if not self.controller.is_available():
                return OrchestratorResult(
                    ok=False,
                    status="error",
                    summary=f"Native UI helper unavailable to press Send in {app_label}. Please press Enter manually.",
                    error="ui_agent_unavailable",
                )
            try:
                self.controller.focus_window(app_label)
                time.sleep(0.2)
                state = self.controller.get_state()
                fg_title = (state.get("foreground") or {}).get("title", "")
                if app_label.lower() not in fg_title.lower() and app_label.lower() not in (state.get("foreground") or {}).get("process", "").lower():
                    return OrchestratorResult(
                        ok=False,
                        status="error",
                        summary=f"Verification gate failed: {app_label} is not the active foreground window ('{fg_title}'). Aborted send for safety.",
                        steps=steps,
                        error="foreground_verification_failed",
                    )
                if not ui_staged and message:
                    self.controller.type_text(message)
                    time.sleep(0.15)
                self.controller.press_key("enter")
                steps.append({"step": 1, "action": "approved_send", "app": app_label, "ok": True})
                return OrchestratorResult(
                    ok=True,
                    status="completed",
                    summary=f"Approved & sent message in {app_label} to {pending_action.get('recipient', 'recipient')}.",
                    steps=steps,
                )
            except (PermissionDenied, FailSafeTriggered, DesktopControlError) as exc:
                return OrchestratorResult(ok=False, status="error", summary=f"Send failed: {exc}", steps=steps, error=str(exc))

        if kind == "desktop_step":
            act = pending_action.get("action", "")
            params = pending_action.get("params") or {}
            try:
                res = self._dispatch_action(act, params)
                steps.append({"step": 1, "action": act, "params": params, "ok": True, "result": res})
                return OrchestratorResult(ok=True, status="completed", summary=f"Approved step '{act}' executed.", steps=steps)
            except (PermissionDenied, FailSafeTriggered, DesktopControlError) as exc:
                return OrchestratorResult(ok=False, status="error", summary=f"Step failed: {exc}", steps=steps, error=str(exc))

        return OrchestratorResult(ok=False, status="error", summary=f"Unknown pending action kind: {kind}", error="unknown_kind")

    # ------------------------------------------------------------------ General Observe-Plan-Act-Verify loop
    def _dispatch_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        act = (action or "").strip().lower()
        if act == "focus":
            return self.controller.focus_window(str(params.get("query", "")))
        if act == "move":
            return self.controller.mouse_move(int(params["x"]), int(params["y"]))
        if act == "click":
            elem = str(params.get("element", "")).strip()
            if elem:
                return self.controller.uia_click(elem)
            return self.controller.mouse_click(
                int(params["x"]),
                int(params["y"]),
                button=str(params.get("button", "left")),
                clicks=int(params.get("clicks", 1)),
            )
        if act == "uia_click":
            return self.controller.uia_click(str(params["element"]))
        if act == "drag":
            return self.controller.mouse_drag(
                int(params["x1"]), int(params["y1"]), int(params["x2"]), int(params["y2"])
            )
        if act == "scroll":
            return self.controller.mouse_scroll(
                int(params.get("x", 500)), int(params.get("y", 500)), int(params.get("delta", -4))
            )
        if act == "type":
            elem = str(params.get("element", "")).strip()
            text = str(params.get("text", ""))
            if elem:
                return self.controller.uia_set_text(elem, text)
            return self.controller.type_text(text)
        if act == "key":
            return self.controller.press_key(str(params["key"]))
        if act == "hotkey":
            return self.controller.hotkey(str(params["keys"]))
        if act == "launch":
            app_key = str(params.get("app", "")).strip().lower()
            ok, msg = automation._launch_app(app_key)
            if not ok:
                raise DesktopControlError(msg)
            return {"ok": True, "message": msg}
        if act == "wait":
            secs = max(0.1, min(float(params.get("seconds", 1.0)), 5.0))
            time.sleep(secs)
            return {"ok": True, "waited": secs}
        raise DesktopControlError(f"Unsupported desktop action: {act}")

    def run_goal(self, goal: str, max_steps: int = MAX_STEPS) -> OrchestratorResult:
        """Execute a multi-step desktop control goal with UIA observation and Vision fallback."""
        if not self.controller.is_available():
            return OrchestratorResult(
                ok=False,
                status="error",
                summary="Native desktop control helper (pai_ui_agent.exe) is unavailable on this host.",
                error="ui_agent_unavailable",
            )
        if self.plan_fn is None:
            return OrchestratorResult(
                ok=False,
                status="error",
                summary="No planner model function configured for multi-step desktop orchestration.",
                error="no_planner",
            )

        steps_log: List[Dict[str, Any]] = []
        vision_used = False
        cap = max(1, min(int(max_steps), MAX_STEPS))

        for step_idx in range(1, cap + 1):
            try:
                state = self.controller.get_state(max_nodes=80)
            except FailSafeTriggered as exc:
                return OrchestratorResult(ok=False, status="aborted", summary=str(exc), steps=steps_log, error=str(exc))
            except (PermissionDenied, DesktopControlError) as exc:
                return OrchestratorResult(ok=False, status="error", summary=str(exc), steps=steps_log, error=str(exc))

            fg = state.get("foreground") or {}
            elements = state.get("elements") or []
            windows = state.get("windows") or []
            nonce = secrets.token_hex(6)

            vision_hint = ""
            if len(elements) < 3 and self.vision_fn is not None:
                try:
                    shot = self.controller.capture_screenshot(max_width=1280)
                    b64 = shot.get("base64", "")
                    if b64:
                        vision_used = True
                        v_prompt = (
                            f"You are inspecting a Windows screenshot ({shot.get('width')}x{shot.get('height')}, "
                            f"original screen {shot.get('orig_width')}x{shot.get('orig_height')}). "
                            f"User goal: {goal}. Identify key clickable UI elements and approximate (x, y) coordinates "
                            "in original screen coordinates."
                        )
                        vision_hint = self.vision_fn(v_prompt, b64) or ""
                except Exception:
                    pass

            compact_elems = [
                {"id": e.get("id"), "type": e.get("type"), "name": e.get("name"), "cx": e.get("cx"), "cy": e.get("cy")}
                for e in elements[:45]
            ]
            compact_wins = [{"title": w.get("title"), "proc": w.get("process")} for w in windows[:12]]

            planner_prompt = (
                "You are PAI's Desktop Control Commander. Plan ONE safe next step to achieve the user goal.\n"
                "Respond with ONLY a single JSON object:\n"
                '{"action": "focus|launch|click|uia_click|move|drag|scroll|type|key|hotkey|wait|ask_confirm|done", '
                '"params": {...}, "reason": "short explanation"}\n'
                f"User Goal: {goal}\n"
                f"History ({len(steps_log)} steps): {json.dumps(steps_log[-4:], ensure_ascii=False, default=str)}\n"
                f"--- UNTRUSTED DESKTOP STATE BEGIN [{nonce}] ---\n"
                f"Screen: {json.dumps(state.get('screen'))}\n"
                f"Foreground: {json.dumps(fg, ensure_ascii=False)}\n"
                f"Windows: {json.dumps(compact_wins, ensure_ascii=False)}\n"
                f"Interactive UIA Elements: {json.dumps(compact_elems, ensure_ascii=False)}\n"
                + (f"Vision Observation: {ingest.defang_envelope_markers(vision_hint)[:600]}\n" if vision_hint else "")
                + f"--- UNTRUSTED DESKTOP STATE END [{nonce}] ---\n"
            )

            raw_plan = self.plan_fn(planner_prompt)
            plan = _parse_json_action(raw_plan)
            if not plan or not plan.get("action"):
                return OrchestratorResult(
                    ok=False,
                    status="error",
                    summary="Desktop planner could not produce a valid next action.",
                    steps=steps_log,
                    vision_used=vision_used,
                    error="invalid_plan_json",
                )

            act = str(plan.get("action", "")).strip().lower()
            params = plan.get("params") if isinstance(plan.get("params"), dict) else {}
            reason = str(plan.get("reason", ""))

            if act == "done":
                return OrchestratorResult(
                    ok=True,
                    status="completed",
                    summary=reason or "Desktop goal completed.",
                    steps=steps_log,
                    vision_used=vision_used,
                )

            if _is_sensitive_step(act, params, target_app=fg.get("title", "")):
                pending = {
                    "action_id": f"hitl_{uuid.uuid4().hex[:10]}",
                    "kind": "desktop_step",
                    "action": act,
                    "params": params,
                    "step_description": reason or f"Execute {act} ({params})",
                }
                return OrchestratorResult(
                    ok=True,
                    status="pending_confirmation",
                    summary=f"Paused before sensitive step: {pending['step_description']}. Click **Approve & Send** to continue.",
                    steps=steps_log,
                    pending_action=pending,
                    vision_used=vision_used,
                )

            try:
                res = self._dispatch_action(act, params)
                steps_log.append({"step": step_idx, "action": act, "params": params, "reason": reason, "ok": True, "result": res})
            except FailSafeTriggered as exc:
                return OrchestratorResult(ok=False, status="aborted", summary=str(exc), steps=steps_log, vision_used=vision_used, error=str(exc))
            except (PermissionDenied, DesktopControlError) as exc:
                steps_log.append({"step": step_idx, "action": act, "params": params, "ok": False, "error": str(exc)})
                return OrchestratorResult(ok=False, status="error", summary=f"Desktop step failed: {exc}", steps=steps_log, vision_used=vision_used, error=str(exc))

        return OrchestratorResult(
            ok=True,
            status="completed",
            summary=f"Reached maximum step budget ({cap} steps).",
            steps=steps_log,
            vision_used=vision_used,
        )
