"""Tests for PC Assistant and Automation capabilities (research/automation.py and desktop/bridge_server.py).

Verifies:
  1. WhatsApp intent parsing (English, Singlish, quotes, contacts, numbers) and execution
  2. Email intent parsing (roles, leave requests, Gmail/Outlook URLs, AI drafting fallback)
  3. YouTube and Web search intent parsing and browser launching
  4. Allowlisted desktop applications and candidate path resolution
  5. Negative controls: Command injection prevention, unallowlisted app rejection,
     and technical/coding question non-hijacking guards
  6. Desktop Bridge Server chat pipeline automation integration
"""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure research directory is in sys.path
RESEARCH_DIR = Path(__file__).resolve().parent.parent
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

import automation as auto_mod


class TestPCAutomation(unittest.TestCase):
    """Unit tests for PC Assistant & Automation capabilities."""

    # ------------------------------------------------------------------
    # 1. WhatsApp Intent Parsing & Execution
    # ------------------------------------------------------------------
    def test_whatsapp_quoted_message_and_contact(self) -> None:
        """Asserts quoted message and recipient are accurately extracted."""
        # Case 1: Direct user prompt with quotes
        res = auto_mod.parse_whatsapp_intent('can you open whatsapp and send message to chanaka "moko karanne?"')
        self.assertEqual(res["contact"], "chanaka")
        self.assertEqual(res["message"], "moko karanne?")

        # Case 2: Single quotes
        res2 = auto_mod.parse_whatsapp_intent("send whatsapp message to kasun 'meeting eka thiyenawa'")
        self.assertEqual(res2["contact"], "kasun")
        self.assertEqual(res2["message"], "meeting eka thiyenawa")

        # Case 3: Singlish phrasing with recipient suffix 'ta'
        res3 = auto_mod.parse_whatsapp_intent('chanaka ta "moko karanne?" kiyala whatsapp msg ekak danna')
        self.assertEqual(res3["contact"], "chanaka")
        self.assertEqual(res3["message"], "moko karanne?")

        # Case 4: Phone number routing
        res4 = auto_mod.parse_whatsapp_intent('/wa +94712345678 "Good morning"')
        self.assertEqual(res4["phone"], "+94712345678")
        self.assertEqual(res4["message"], "Good morning")

    def test_whatsapp_execution(self) -> None:
        """Asserts open_whatsapp copies message to clipboard and launches WhatsApp."""
        with patch.object(auto_mod, "copy_to_clipboard", return_value=True) as mock_clip, \
             patch.object(auto_mod.webbrowser, "open", return_value=True) as mock_web:
            ok, msg = auto_mod.open_whatsapp(
                contact="chanaka",
                message="moko karanne?",
                stream=io.StringIO(),
            )
            self.assertTrue(ok)
            mock_clip.assert_called_with("moko karanne?")
            self.assertIn("WhatsApp", msg)
            self.assertIn("chanaka", msg)

    # ------------------------------------------------------------------
    # 2. Email Intent Parsing & Drafting
    # ------------------------------------------------------------------
    def test_email_leave_request_intent_and_fallback(self) -> None:
        """Asserts role recipient 'Boss' and leave request body are synthesized cleanly."""
        prompt = "can you open my mail box and write a mail to my boss i want leave tomorrow"
        parsed = auto_mod.parse_email_intent(prompt)

        self.assertEqual(parsed["recipient_role"], "Boss")
        self.assertEqual(parsed["provider"], "gmail")
        self.assertIn("leave tomorrow", parsed["topic"])

        # Test deterministic leave request subject and body
        subj, body = auto_mod._build_fallback_email(prompt, parsed)
        self.assertIn("Leave Request", subj)
        self.assertIn("Boss", body)
        self.assertIn("leave for tomorrow", body)

    def test_email_compose_execution_and_url(self) -> None:
        """Asserts browser compose window is opened with pre-filled subject and body."""
        opened_urls = []
        with patch.object(auto_mod.webbrowser, "open", side_effect=lambda url, new=2: opened_urls.append(url) or True), \
             patch.object(auto_mod, "copy_to_clipboard", return_value=True):
            ok, msg = auto_mod.execute_automation_task(
                "can you open my mail box and write a mail to my boss i want leave tomorrow",
                stream=io.StringIO(),
            )
            self.assertTrue(ok)
            self.assertEqual(len(opened_urls), 1)
            self.assertIn("mail.google.com/mail", opened_urls[0])
            self.assertIn("Leave%20Request", opened_urls[0])
            self.assertIn("Boss", msg)

    def test_email_ai_drafting_with_model_fn(self) -> None:
        """Asserts model_fn callback is used when available to compose email."""
        def fake_model(p: str) -> str:
            return "SUBJECT: Urgent Leave Notification\nBODY:\nHi Boss,\n\nI will not be able to attend office tomorrow.\n\nBest regards,"

        subj, body, used_ai = auto_mod.compose_email_with_model(
            "boss ta leave ekak illala mail ekak danna",
            model_fn=fake_model,
        )
        self.assertTrue(used_ai)
        self.assertEqual(subj, "Urgent Leave Notification")
        self.assertIn("office tomorrow", body)

    # ------------------------------------------------------------------
    # 3. YouTube and Web Search Intent
    # ------------------------------------------------------------------
    def test_youtube_intent_variations(self) -> None:
        """Asserts Singlish and English YouTube play and search queries."""
        # Generic request opens YouTube home
        yt1 = auto_mod.parse_automation_intent("youtube eke monawa hari dala denna")
        self.assertIsNotNone(yt1)
        self.assertEqual(yt1["kind"], "web_search")
        self.assertEqual(yt1["engine"], "youtube")
        self.assertEqual(yt1["query"], "")

        # Specific video search
        yt2 = auto_mod.parse_automation_intent("youtube eke lofi hip hop play karanna")
        self.assertIsNotNone(yt2)
        self.assertEqual(yt2["kind"], "web_search")
        self.assertEqual(yt2["engine"], "youtube")
        self.assertIn("lofi hip hop", yt2["query"])

        # Slash command
        yt3 = auto_mod.parse_automation_intent("/youtube Alan Walker faded")
        self.assertIsNotNone(yt3)
        self.assertEqual(yt3["engine"], "youtube")
        self.assertIn("Alan Walker faded", yt3["query"])

    def test_web_search_intent(self) -> None:
        """Asserts web and google search routing."""
        s1 = auto_mod.parse_automation_intent("google eke search karanna python async tutorial")
        self.assertIsNotNone(s1)
        self.assertEqual(s1["kind"], "web_search")
        self.assertEqual(s1["engine"], "google")
        self.assertIn("python async tutorial", s1["query"])

        s2 = auto_mod.parse_automation_intent("web eke monawa hari search karala denna")
        self.assertIsNotNone(s2)
        self.assertEqual(s2["kind"], "web_search")
        self.assertEqual(s2["engine"], "google")

    # ------------------------------------------------------------------
    # 4. Allowlisted Desktop Applications & Negative Controls
    # ------------------------------------------------------------------
    def test_app_allowlist_expansion(self) -> None:
        """Asserts productivity apps and browsers are recognized in allowlist."""
        for app in ("chrome", "edge", "spotify", "vscode", "notepad", "calculator", "paint"):
            intent = auto_mod.parse_automation_intent(f"open {app}")
            self.assertIsNotNone(intent, f"Failed for app '{app}'")
            self.assertEqual(intent["kind"], "open_app")
            self.assertIn(intent["app"], auto_mod._APP_ALLOWLIST)

        # Singlish app open
        intent_singlish = auto_mod.parse_automation_intent("chrome eka open karanna")
        self.assertIsNotNone(intent_singlish)
        self.assertEqual(intent_singlish["kind"], "open_app")
        self.assertEqual(intent_singlish["app"], "chrome")

    def test_negative_control_dangerous_commands_rejected(self) -> None:
        """Asserts dangerous shell commands and unallowlisted binaries are rejected."""
        dangerous_inputs = [
            "rm -rf /",
            "cmd.exe /c del *.*",
            "powershell -Command Remove-Item -Recurse C:\\",
            "format C: /fs:NTFS",
            "open malware.exe",
            "launch unauthorized_trojan",
        ]
        for bad in dangerous_inputs:
            # Must either return None or fail safe in execute_automation_task
            ok, msg = auto_mod.execute_automation_task(bad, sub_action="auto", stream=io.StringIO())
            self.assertFalse(ok, f"Expected rejection for '{bad}' but succeeded")
            self.assertIn("Unsupported automation request", msg)

    def test_coding_and_informational_guards(self) -> None:
        """Asserts technical explanations and code questions are never hijacked as automation."""
        technical_queries = [
            "what is an email protocol?",
            "how to open a file in python",
            "how does whatsapp end-to-end encryption work?",
            "explain youtube recommendation algorithm",
            "define browser caching",
            "write a python script to search google",
        ]
        for q in technical_queries:
            intent = auto_mod.parse_automation_intent(q)
            self.assertIsNone(intent, f"Technical query '{q}' was incorrectly hijacked as automation!")

    # ------------------------------------------------------------------
    # 5. Desktop Bridge Server Integration
    # ------------------------------------------------------------------
    def test_bridge_server_chat_automation_interception(self) -> None:
        """Asserts bridge server _execute_chat_pipeline_sync intercepts automation without LLM fallback."""
        try:
            from desktop.bridge_server import PAIBridgeHandler
        except ImportError:
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "bridge_server",
                str(RESEARCH_DIR.parent / "desktop" / "bridge_server.py"),
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            PAIBridgeHandler = mod.PAIBridgeHandler

        # Mock handler instance
        handler = MagicMock(spec=PAIBridgeHandler)

        with patch.object(auto_mod.webbrowser, "open", return_value=True), \
             patch.object(auto_mod, "copy_to_clipboard", return_value=True):
            # Test WhatsApp via bridge
            res_wa = PAIBridgeHandler._execute_chat_pipeline_sync(
                handler,
                {"prompt": 'can you open whatsapp and send message to chanaka "moko karanne?"', "model": "llama3.2:3b"}
            )
            self.assertTrue(res_wa.get("success"))
            self.assertTrue(res_wa.get("is_automation"))
            self.assertEqual(res_wa.get("automation_kind"), "whatsapp")
            self.assertIn(res_wa.get("model"), ("PAI PC Automation Assistant", "PAI Desktop Orchestrator"))
            self.assertIn("WhatsApp Automation", res_wa.get("response", ""))
            self.assertIsNotNone(res_wa.get("pending_confirmation"))

            # Test Email via bridge
            res_em = PAIBridgeHandler._execute_chat_pipeline_sync(
                handler,
                {"prompt": "can you open my mail box and write a mail to my boss i want leave tomorrow", "model": "llama3.2:3b"}
            )
            self.assertTrue(res_em.get("success"))
            self.assertTrue(res_em.get("is_automation"))
            self.assertEqual(res_em.get("automation_kind"), "email")
            self.assertIn("Email Compose Automation", res_em.get("response", ""))
            self.assertTrue("Leave" in res_em.get("response", "") or "leave" in res_em.get("response", "").lower())


if __name__ == "__main__":
    unittest.main()
