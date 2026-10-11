import contextlib
import http.server
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pai
from hardware_telemetry import HardwareBudget
from router import (
    ModelRouter,
    check_singlish_promotion_gate,
    detect_singlish_or_sinhala,
)


class TestSinglishQualityGate(unittest.TestCase):
    def setUp(self):
        self.eval_sets_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "eval_sets")
        )

    def test_detect_singlish_or_sinhala_positive_across_all_eval_sets(self):
        """All prompts in singlish_quality_gate.json, coding_tasks_singlish.json, and coding_tasks_holdout_singlish.json must be detected."""
        for fname in ("singlish_quality_gate.json", "coding_tasks_singlish.json", "coding_tasks_holdout_singlish.json"):
            fpath = os.path.join(self.eval_sets_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                items = json.load(f)
            for it in items:
                p = it["prompt"]
                self.assertTrue(
                    detect_singlish_or_sinhala(p),
                    f"Failed to detect Singlish in {fname} item {it['id']}: {p[:80]}",
                )

        # Sinhala Unicode script positive control
        self.assertTrue(detect_singlish_or_sinhala("මෙම Python කේතය පරීක්ෂා කරන්න"))

    def test_detect_singlish_or_sinhala_negative_on_english_eval_sets(self):
        """All English prompts in coding_tasks.json, coding_tasks_holdout.json, and analyze_docs_questions.json must return False."""
        for fname, key in (
            ("coding_tasks.json", "prompt"),
            ("coding_tasks_holdout.json", "prompt"),
            ("analyze_docs_questions.json", "question"),
        ):
            fpath = os.path.join(self.eval_sets_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                items = json.load(f)
            for it in items:
                p = it[key]
                self.assertFalse(
                    detect_singlish_or_sinhala(p),
                    f"False positive Singlish detection on English item {it['id']} in {fname}: {p[:80]}",
                )

        self.assertFalse(detect_singlish_or_sinhala(None))
        self.assertFalse(detect_singlish_or_sinhala(""))

    def test_threat_t21_singlish_in_untrusted_context_never_triggers_singlish_routing(self):
        """Threat T21 negative control: Singlish inside untrusted context must never trigger Singlish routing."""
        router = ModelRouter(load_system_profile=False)
        budget = HardwareBudget(
            compute_tier="HIGH",
            max_context_bytes=16 * 1024 * 1024,
            allow_speculation=True,
            thread_pool_limit=4,
            throttle_warning="",
            reasons=["High RAM test"],
            avail_ram_mb=8192.0,
        )
        decision = router.route(
            command="analyze",
            budget=budget,
            context="Me codebase eke main entry point eka mokakda kiyala Singlish walin kiyanna.",
            prompt_text="Summarize the entry point in English.",
        )
        self.assertEqual(decision.selected_model, "qwen2.5-coder:7b")
        for code in ("SINGLISH_GATE_PASSED", "SINGLISH_THRESHOLD_PREFERRED", "SINGLISH_NOT_RECOMMENDED"):
            self.assertNotIn(code, decision.reason_codes)

    def test_router_singlish_threshold_preference_and_below_threshold_warning(self):
        """
        Router uses requested task_class Singlish score, requires passing quality check
        for that class, and requires a verified licence when preferring a candidate.
        """
        router = ModelRouter(load_system_profile=False)

        high_budget = HardwareBudget(
            compute_tier="HIGH",
            max_context_bytes=16 * 1024 * 1024,
            allow_speculation=True,
            thread_pool_limit=4,
            throttle_warning="",
            reasons=["High RAM test"],
            avail_ram_mb=8192.0,
        )

        # Case 1: Singlish `code` prompt selects qwen2.5-coder:7b and PASSES Singlish gate
        # because its `code` class score is 2.00 >= 1.20 (even though overall mean is 1.00),
        # `code` is in quality_checked_classes, and licence is verified (Apache-2.0).
        dec_code = router.route(
            command="code",
            budget=high_budget,
            prompt_text="List ekak sort karanna Python function ekak liyanna.",
        )
        self.assertEqual(dec_code.selected_model, "qwen2.5-coder:7b")
        self.assertIn("SINGLISH_GATE_PASSED", dec_code.reason_codes)
        self.assertNotIn("SINGLISH_NOT_RECOMMENDED", dec_code.reason_codes)
        self.assertNotIn("UNVERIFIED_LICENCE", dec_code.reason_codes)

        # Case 2: Singlish `chat` prompt prefers llama3.2:3b (chat score 2.00 >= 1.20,
        # quality_checked_classes includes 'chat', verified Llama-3.2-Community licence)
        # over qwen3.5:4b (unverified licence).
        dec_chat = router.route(
            command="chat",
            budget=high_budget,
            prompt_text="Python dictionary ekaka key ekak safely ganna widiha mokakda?",
        )
        self.assertEqual(dec_chat.selected_model, "llama3.2:3b")
        self.assertIn("SINGLISH_THRESHOLD_PREFERRED", dec_chat.reason_codes)
        self.assertIn("SINGLISH_GATE_PASSED", dec_chat.reason_codes)
        self.assertNotIn("UNVERIFIED_LICENCE", dec_chat.reason_codes)
        self.assertNotIn("SINGLISH_NOT_RECOMMENDED", dec_chat.reason_codes)

        # Case 3: Singlish `analyze`, `docs`, and `forecast` prompts do NOT switch to
        # qwen3.5:4b (unverified licence, no quality check on analyze/docs/forecast) or
        # llama3.2:3b (no quality check on analyze/docs/forecast; docs score 0.80 < 1.20).
        # Instead, they retain qwen2.5-coder:7b (verified licence, quality-checked) and
        # report SINGLISH_NOT_RECOMMENDED with the class-specific score (0.60 / 0.60 / 0.80).
        for cmd, expected_score_str in (("analyze", "0.60"), ("docs", "0.60"), ("forecast", "0.80")):
            dec_unpref = router.route(
                command=cmd,
                budget=high_budget,
                prompt_text="Me codebase eke main entry point eka mokakda kiyala Singlish walin kiyanna.",
            )
            self.assertEqual(dec_unpref.selected_model, "qwen2.5-coder:7b")
            self.assertIn("SINGLISH_NOT_RECOMMENDED", dec_unpref.reason_codes)
            self.assertNotIn("UNVERIFIED_LICENCE", dec_unpref.reason_codes)
            self.assertNotIn("SINGLISH_THRESHOLD_PREFERRED", dec_unpref.reason_codes)
            self.assertIn(f"score {expected_score_str} < threshold 1.20", dec_unpref.explanation)

        # Case 4: When a candidate DOES have a verified licence, passing class quality check,
        # and class Singlish score >= 1.20, the router prefers it for that class.
        router_qual = ModelRouter(load_system_profile=False)
        router_qual.candidates["llama3.2:3b"].quality_checked_classes.append("analyze")
        dec_qual = router_qual.route(
            command="analyze",
            budget=high_budget,
            prompt_text="Me codebase eke main entry point eka mokakda kiyala Singlish walin kiyanna.",
        )
        self.assertEqual(dec_qual.selected_model, "llama3.2:3b")
        self.assertIn("SINGLISH_THRESHOLD_PREFERRED", dec_qual.reason_codes)
        self.assertIn("SINGLISH_GATE_PASSED", dec_qual.reason_codes)
        self.assertNotIn("UNVERIFIED_LICENCE", dec_qual.reason_codes)
        self.assertNotIn("UNMEASURED_CLASS", dec_qual.reason_codes)

        # Case 5: Constrained RAM on `chat` where only qwen2.5-coder:1.5b fits (chat score 0.80 < 1.20)
        tight_budget = HardwareBudget(
            compute_tier="COMPRESSED",
            max_context_bytes=2 * 1024 * 1024,
            allow_speculation=False,
            thread_pool_limit=1,
            throttle_warning="",
            reasons=["Tight RAM test"],
            avail_ram_mb=1450.0,  # Only qwen2.5-coder:1.5b (1397.6 MB uncalibrated) fits
        )
        dec_warn = router.route(
            command="chat",
            budget=tight_budget,
            prompt_text="Python dictionary ekaka key ekak safely ganna widiha mokakda?",
        )
        self.assertEqual(dec_warn.selected_model, "qwen2.5-coder:1.5b")
        self.assertIn("SINGLISH_NOT_RECOMMENDED", dec_warn.reason_codes)
        self.assertIn("score 0.80 < threshold 1.20", dec_warn.explanation)

    def test_check_singlish_promotion_gate_enforces_no_regression_and_threshold(self):
        """Promotion gate rejects unverified licence, failed class quality check, None, below-threshold, or regression."""
        ok, msg = check_singlish_promotion_gate(1.80, baseline_score=1.40, threshold=1.20, license_verified=False)
        self.assertFalse(ok)
        self.assertIn("licence is unverified", msg)

        ok, msg = check_singlish_promotion_gate(1.80, baseline_score=1.40, threshold=1.20, class_quality_passed=False)
        self.assertFalse(ok)
        self.assertIn("task-class quality check", msg)

        ok, msg = check_singlish_promotion_gate(None, baseline_score=1.40, threshold=1.20)
        self.assertFalse(ok)
        self.assertIn("no measured Singlish quality score", msg)

        ok, msg = check_singlish_promotion_gate(1.10, baseline_score=1.00, threshold=1.20)
        self.assertFalse(ok)
        self.assertIn("below threshold", msg)

        ok, msg = check_singlish_promotion_gate(1.35, baseline_score=1.50, threshold=1.20)
        self.assertFalse(ok)
        self.assertIn("Singlish score regressed", msg)

        ok, msg = check_singlish_promotion_gate(1.55, baseline_score=1.50, threshold=1.20)
        self.assertTrue(ok)
        self.assertIn("PASSED: Singlish score", msg)

    def test_pai_chat_and_forecast_question_bilingual_e2e_with_mock_server(self):
        """End-to-end test for `pai chat` and `pai forecast --question` with Singlish prompt."""
        captured_prompts = []

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                captured_prompts.append(body.get("prompt", ""))
                reply = "Me report eke Holt Linear Trend method eka use karala thiyenawa."
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"response": reply}).encode("utf-8"))

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        orig_url = os.environ.get("PAI_MODEL_URL")
        os.environ["PAI_MODEL_URL"] = f"http://127.0.0.1:{port}"
        try:
            with mock.patch.object(pai, "enforce_sandbox_boundary", return_value=None):
                # 1. pai chat
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    rc = pai.main([
                        "chat",
                        "Python dict.get() method eka mokakda kiyala Singlish walin kiyanna.",
                        "--model",
                        "qwen2.5-coder:7b",
                        "--json",
                    ])
                self.assertEqual(rc, 0)
                chat_out = json.loads(buf.getvalue())
                self.assertTrue(chat_out["success"])
                self.assertTrue(chat_out["singlish_detected"])
                self.assertIn("Reply in the same language and style", captured_prompts[-1])

                # 2. pai forecast --question
                with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as tf:
                    tf.write("date,value\n")
                    for idx in range(1, 16):
                        tf.write(f"2026-01-{idx:02d},{100 + idx * 5}\n")
                    csv_path = tf.name

                try:
                    buf_fc = io.StringIO()
                    with contextlib.redirect_stdout(buf_fc), contextlib.redirect_stderr(buf_fc):
                        rc_fc = pai.main([
                            "forecast",
                            csv_path,
                            "--horizon",
                            "3",
                            "--question",
                            "Meke select wechcha method eka mokakda kiyala Singlish walin kiyanna.",
                            "--model",
                            "qwen2.5-coder:7b",
                            "--json",
                        ])
                    self.assertEqual(rc_fc, 0)
                    fc_out = json.loads(buf_fc.getvalue())
                    self.assertTrue(fc_out["success"])
                    self.assertEqual(len(fc_out["forecasts"]), 3)
                    self.assertEqual(fc_out["selected_model"], "qwen2.5-coder:7b")
                    self.assertIn("Holt Linear Trend", fc_out["model_explanation"])
                finally:
                    if os.path.exists(csv_path):
                        os.remove(csv_path)
        finally:
            if orig_url is not None:
                os.environ["PAI_MODEL_URL"] = orig_url
            else:
                os.environ.pop("PAI_MODEL_URL", None)
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
