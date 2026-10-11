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
        """Router prefers models meeting singlish_threshold, and warns ('Singlish not recommended') when only a below-threshold model fits."""
        router = ModelRouter(load_system_profile=False)

        # Case 1: High RAM -> selects a model meeting Singlish gate (>= 1.2)
        high_budget = HardwareBudget(
            compute_tier="HIGH",
            max_context_bytes=16 * 1024 * 1024,
            allow_speculation=True,
            thread_pool_limit=4,
            throttle_warning="",
            reasons=["High RAM test"],
            avail_ram_mb=8192.0,
        )
        dec_ok = router.route(
            command="chat",
            budget=high_budget,
            prompt_text="Python dictionary ekaka key ekak safely ganna widiha mokakda?",
        )
        self.assertIsNotNone(dec_ok.selected_model)
        self.assertIn("SINGLISH_GATE_PASSED", dec_ok.reason_codes)
        self.assertNotIn("SINGLISH_NOT_RECOMMENDED", dec_ok.reason_codes)

        # Case 2: Singlish analyze prompt prefers qwen3.5:4b (1.76 >= 1.20) over qwen2.5-coder:7b (1.00 < 1.20) at 8 GB,
        # and prefers llama3.2:3b (1.52 >= 1.20) when RAM is 3400 MB (where qwen3.5:4b uncalibrated 3614 MB does not fit)
        dec_analyze = router.route(
            command="analyze",
            budget=high_budget,
            prompt_text="Me codebase eke main entry point eka mokakda kiyala Singlish walin kiyanna.",
        )
        self.assertEqual(dec_analyze.selected_model, "qwen3.5:4b")
        self.assertIn("SINGLISH_THRESHOLD_PREFERRED", dec_analyze.reason_codes)
        self.assertIn("SINGLISH_GATE_PASSED", dec_analyze.reason_codes)

        router_3b = ModelRouter(load_system_profile=False)
        router_3b.user_config = {"allowed_models": ["qwen2.5-coder:7b", "llama3.2:3b", "qwen2.5-coder:1.5b"]}
        dec_analyze_3b = router_3b.route(
            command="analyze",
            budget=high_budget,
            prompt_text="Me codebase eke main entry point eka mokakda kiyala Singlish walin kiyanna.",
        )
        self.assertEqual(dec_analyze_3b.selected_model, "llama3.2:3b")
        self.assertIn("SINGLISH_THRESHOLD_PREFERRED", dec_analyze_3b.reason_codes)
        self.assertIn("SINGLISH_GATE_PASSED", dec_analyze_3b.reason_codes)

        # Case 3: Constrained RAM where only a below-threshold model fits (qwen2.5-coder:1.5b = 0.88 < 1.20)
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
            command="code",
            budget=tight_budget,
            prompt_text="List ekak sort karanna Python function ekak liyanna.",
        )
        self.assertEqual(dec_warn.selected_model, "qwen2.5-coder:1.5b")
        self.assertIn("SINGLISH_NOT_RECOMMENDED", dec_warn.reason_codes)
        self.assertIn("Singlish not recommended", dec_warn.explanation)

    def test_check_singlish_promotion_gate_enforces_no_regression_and_threshold(self):
        """Promotion gate rejects None, below-threshold, or regression against baseline."""
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
