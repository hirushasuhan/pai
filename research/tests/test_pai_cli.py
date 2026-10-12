"""
Unit Tests for PAI CLI (Milestone M1c / ADR-010)
Validates:
1. `pai doctor` (human-readable and JSON format)
2. `pai models list` (human-readable and JSON format)
3. `pai route <command>` with `--explain-route` and `--json`
4. Deferred execution commands notice (`pai generate`, `pai analyze`, `pai forecast`)
5. Loopback security check on model server probe
"""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pai import main, probe_gpu, probe_ollama_server


class TestPaiCLI(unittest.TestCase):
    def test_pai_doctor_text_and_json(self):
        """Verifies `pai doctor` output in standard and JSON mode, including smoke tests."""
        # 1. Standard text mode
        f_text = io.StringIO()
        with redirect_stdout(f_text):
            code = main(["doctor"])
        self.assertEqual(code, 0)
        out_text = f_text.getvalue()
        self.assertIn("PAI SYSTEM & HARDWARE DOCTOR", out_text)
        self.assertIn("RAM Total / Avail", out_text)
        self.assertIn("Candidate Eligibility Report", out_text)
        self.assertIn("End-to-End Doctor Pass/Fail Table", out_text)
        self.assertIn("smoke_code", out_text)
        self.assertIn("smoke_analyze", out_text)
        self.assertIn("smoke_docs", out_text)
        self.assertIn("smoke_forecast", out_text)

        # 2. JSON mode
        f_json = io.StringIO()
        with redirect_stdout(f_json):
            code = main(["doctor", "--json"])
        self.assertEqual(code, 0)
        parsed = json.loads(f_json.getvalue())
        self.assertTrue(parsed["all_passed"])
        self.assertIn("os", parsed)
        self.assertIn("telemetry", parsed)
        self.assertIn("candidates", parsed)
        self.assertIn("smoke_tests", parsed)
        self.assertIn("checks", parsed)
        self.assertEqual(len(parsed["smoke_tests"]), 4)
        self.assertTrue(all(sm["passed"] for sm in parsed["smoke_tests"]))
        self.assertTrue(len(parsed["candidates"]) >= 5)

    def test_pai_doctor_returns_nonzero_on_failed_check(self):
        """Negative control: `pai doctor` returns exit code 1 if any check (e.g. smoke test) fails."""
        failed_smokes = [
            {"command": "code", "passed": False, "exit_code": 1, "detail": "Simulated smoke failure"}
        ]
        f_json = io.StringIO()
        with patch("pai._run_doctor_smoke_tests", return_value=failed_smokes), redirect_stdout(f_json):
            code = main(["doctor", "--json"])
        self.assertEqual(code, 1)
        parsed = json.loads(f_json.getvalue())
        self.assertFalse(parsed["all_passed"])


    def test_pai_models_list(self):
        """Verifies `pai models list` output in standard and JSON mode."""
        f_text = io.StringIO()
        with redirect_stdout(f_text):
            code = main(["models", "list"])
        self.assertEqual(code, 0)
        out_text = f_text.getvalue()
        self.assertIn("PAI CANDIDATE MODELS CATALOG", out_text)
        self.assertIn("qwen2.5-coder:7b", out_text)

        f_json = io.StringIO()
        with redirect_stdout(f_json):
            code = main(["models", "list", "--json"])
        self.assertEqual(code, 0)
        parsed = json.loads(f_json.getvalue())
        self.assertTrue(isinstance(parsed, list))
        model_names = [m["name"] for m in parsed]
        self.assertIn("qwen2.5-coder:7b", model_names)
        self.assertIn("llama3.2:3b", model_names)

    def test_pai_route_and_explain(self):
        """Verifies `pai route` commands."""
        from hardware_telemetry import HardwareBudget
        mock_budget = HardwareBudget(
            compute_tier="standard",
            max_context_bytes=16 * 1024 * 1024,
            allow_speculation=True,
            thread_pool_limit=4,
            throttle_warning="",
            reasons=[],
            avail_ram_mb=16384.0,
        )
        mock_snapshot = {
            "budget": mock_budget,
            "telemetry": {},
            "candidates": [],
        }
        with patch("pai.HardwareTelemetry.get_system_snapshot", return_value=mock_snapshot):
            # Standard route
            f_out = io.StringIO()
            with redirect_stdout(f_out):
                code = main(["route", "code"])
            self.assertEqual(code, 0)
            self.assertIn("Selected model:", f_out.getvalue())

            # Route with --explain-route
            f_exp = io.StringIO()
            with redirect_stdout(f_exp):
                code = main(["route", "code", "--explain-route"])
            self.assertEqual(code, 0)
            exp_text = f_exp.getvalue()
            self.assertIn("ROUTE EXPLANATION", exp_text)
            self.assertIn("Data leaves machine:  No (Local inference)", exp_text)

            # Route with --json
            f_json = io.StringIO()
            with redirect_stdout(f_json):
                code = main(["route", "code", "--json"])
            self.assertEqual(code, 0)
            dec_dict = json.loads(f_json.getvalue())
            self.assertEqual(dec_dict["task_class"], "code")
            self.assertEqual(dec_dict["data_leaves_machine"], False)

    def test_pai_route_invalid_command_fails_closed(self):
        """Invalid commands to `pai route` return non-zero exit code."""
        f_err = io.StringIO()
        with redirect_stdout(f_err):
            code = main(["route", "malicious_injection_command"])
        self.assertEqual(code, 1)
        self.assertIn("Error: Unknown or invalid command", f_err.getvalue())

    def test_deferred_commands_notice(self):
        """Direct execution command (generate) prints deferred notice."""
        for cmd in ("generate",):
            f_out = io.StringIO()
            with redirect_stdout(f_out):
                code = main([cmd, "test argument"])
            self.assertEqual(code, 0)
            self.assertIn("deferred to Milestone M6+", f_out.getvalue())
            self.assertIn(f"pai route {cmd}", f_out.getvalue())

    def test_probe_ollama_server_rejects_non_loopback(self):
        """SSRF Defense: probe_ollama_server strictly rejects non-loopback URLs."""
        non_loopback_urls = [
            "http://192.168.1.1:11434",
            "http://10.0.0.1:11434",
            "http://attacker.local:11434",
        ]
        for url in non_loopback_urls:
            with self.assertRaises(ValueError):
                probe_ollama_server(url)

    def test_probe_gpu_returns_string(self):
        """GPU probe returns non-empty descriptive string."""
        desc = probe_gpu()
        self.assertTrue(isinstance(desc, str))
        self.assertTrue(len(desc) > 0)

    def test_pai_code_with_user_tests_meaningful(self):
        """pai code --tests with meaningful test file freezes tests and passes stub probe."""
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("from solution import add\nassert add(1, 2) == 3\n")
            test_path = f.name

        try:
            f_out = io.StringIO()
            with redirect_stdout(f_out):
                code = main(["code", "--tests", test_path])
            self.assertEqual(code, 0)
            val = f_out.getvalue()
            self.assertIn("[TESTS FROZEN]", val)
            self.assertIn("[STUB PROBE OK]", val)
        finally:
            if os.path.exists(test_path):
                os.remove(test_path)

    def test_pai_code_with_vacuous_tests_rejected(self):
        """pai code --tests with vacuous test file fails closed via stub probe."""
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("def test_v(): assert True\n")
            test_path = f.name

        try:
            f_err = io.StringIO()
            with io.StringIO() as f_out, patch("sys.stderr", f_err):
                code = main(["code", "--tests", test_path])
            self.assertEqual(code, 1)
            self.assertIn("Stub probe failed", f_err.getvalue())
        finally:
            if os.path.exists(test_path):
                os.remove(test_path)

    def test_subcommands_pass_live_budget_to_router_when_model_omitted(self):
        """
        Regression test (Dogfooding Finding):
        When `--model` is omitted on `code`, `analyze`, `docs`, `forecast --question`, and `chat`,
        each subcommand must pass the live HardwareBudget (`budget.avail_ram_mb is not None`)
        to `ModelRouter.route` rather than `budget=None`.
        """
        import shutil
        import tempfile
        from hardware_telemetry import HardwareBudget
        from router import ModelRouter

        tmp = tempfile.mkdtemp(prefix="pai_cli_route_budget_")
        repo_dir = os.path.join(tmp, "repo")
        os.makedirs(repo_dir, exist_ok=True)
        doc_file = os.path.join(repo_dir, "note.md")
        with open(doc_file, "w", encoding="utf-8") as f:
            f.write("# Note\nSome content.\n")
        csv_file = os.path.join(tmp, "series.csv")
        with open(csv_file, "w", encoding="utf-8") as f:
            f.write("date,val\n" + "\n".join(f"2026-01-{i:02d},{100 + i}" for i in range(1, 16)) + "\n")

        mock_budget = HardwareBudget(
            compute_tier="BALANCED",
            max_context_bytes=8 * 1024 * 1024,
            allow_speculation=True,
            thread_pool_limit=4,
            throttle_warning="",
            reasons=[],
            avail_ram_mb=8192.0,
        )
        mock_snap = {"budget": mock_budget, "avail_ram_mb": 8192.0, "total_ram_gb": 16.0}
        observed_budgets = []
        orig_route = ModelRouter.route

        def spy_route(router_self, command, *args, **kwargs):
            observed_budgets.append((command, kwargs.get("budget")))
            return orig_route(router_self, command, *args, **kwargs)

        try:
            with (
                patch("pai.enforce_sandbox_boundary", return_value=None),
                patch("pai.HardwareTelemetry.get_system_snapshot", return_value=mock_snap),
                patch.object(ModelRouter, "get_live_resident_model", return_value=None),
                patch.object(ModelRouter, "route", new=spy_route),
                patch("pai.call_model_generate", return_value="Mocked model output"),
            ):
                for argv in (
                    ["analyze", repo_dir, "--json"],
                    ["docs", doc_file, "--json"],
                    ["forecast", csv_file, "--horizon", "2", "--question", "Trend?", "--json"],
                    ["chat", "Hello PAI", "--json"],
                ):
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        rc = main(argv)
                    self.assertEqual(rc, 0, f"Subcommand {argv[0]} failed without --model: {buf.getvalue()}")

            self.assertEqual(len(observed_budgets), 4)
            for cmd_name, b in observed_budgets:
                self.assertIsNotNone(b, f"Subcommand '{cmd_name}' passed budget=None to router.route")
                self.assertEqual(b.avail_ram_mb, 8192.0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

