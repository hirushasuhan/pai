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
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pai import main, probe_gpu, probe_ollama_server


class TestPaiCLI(unittest.TestCase):
    def test_pai_doctor_text_and_json(self):
        """Verifies `pai doctor` output in standard and JSON mode, including smoke tests."""
        from hardware_telemetry import HardwareTelemetry
        real_snap = HardwareTelemetry().get_system_snapshot()
        mock_snap = dict(real_snap)
        mock_snap["avail_ram_mb"] = max(float(real_snap.get("avail_ram_mb") or 0.0), 8192.0)
        mock_snap["avail_ram_gb"] = max(float(real_snap.get("avail_ram_gb") or 0.0), 8.0)
        mock_snap["memory_load_pct"] = min(int(real_snap.get("memory_load_pct") or 50), 50)

        with patch("pai.HardwareTelemetry.get_system_snapshot", return_value=mock_snap):
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

    def test_all_subcommands_without_model_against_local_stub_server_unmocked_router(self):
        """
        Phase 1.1 (1): End-to-end integration test running every CLI subcommand
        (`code`, `analyze`, `docs`, `forecast`, `chat`) WITHOUT `--model` and
        WITHOUT mocking `ModelRouter` or `HardwareTelemetry`, against a live local
        HTTP stub server implementing `/api/tags`, `/api/ps`, and `/api/generate`.
        """
        import shutil
        import tempfile
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        recorded_requests = []

        class StubOllamaHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Silence HTTP server logs during test output

            def do_GET(self):
                recorded_requests.append(("GET", self.path))
                if self.path == "/api/version":
                    raw = json.dumps({"version": "0.35.1-stub"}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                elif self.path == "/api/tags":
                    payload = {
                        "models": [
                            {"name": "qwen2.5-coder:7b"},
                            {"name": "qwen2.5-coder:1.5b"},
                            {"name": "llama3.2:3b"},
                        ]
                    }
                    raw = json.dumps(payload).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                elif self.path == "/api/ps":
                    # Report qwen2.5-coder:1.5b as warm resident so routing succeeds
                    # deterministically even on low-RAM CI containers (>= 512 MB free).
                    payload = {"models": [{"name": "qwen2.5-coder:1.5b"}]}
                    raw = json.dumps(payload).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body_bytes = self.rfile.read(length) if length > 0 else b"{}"
                body = json.loads(body_bytes.decode("utf-8"))
                recorded_requests.append(("POST", self.path, body.get("model")))
                if self.path == "/api/generate":
                    prompt_text = body.get("prompt", "")
                    if "test engineer" in prompt_text.lower() or "write a python `unittest` test suite" in prompt_text.lower():
                        resp_text = (
                            "import unittest\n"
                            "from solution import add\n\n"
                            "class TestAdd(unittest.TestCase):\n"
                            "    def test_add_values(self):\n"
                            "        self.assertEqual(add(2, 3), 5)\n"
                            "        self.assertEqual(add(-4, 1), -3)\n"
                            "        self.assertEqual(add(0, 0), 0)\n"
                            "        self.assertEqual(add(10, 25), 35)\n"
                        )
                    elif "add(a: int, b: int)" in prompt_text:
                        resp_text = "def add(a: int, b: int) -> int:\n    return a + b\n"
                    else:
                        resp_text = "Stub explanation: point forecasts are 116.00 and 117.00."
                    raw = json.dumps({"response": resp_text, "done": True}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                else:
                    self.send_response(404)
                    self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), StubOllamaHandler)
        port = server.server_address[1]
        server_url = f"http://127.0.0.1:{port}"
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()

        tmp = tempfile.mkdtemp(prefix="pai_stub_e2e_")
        repo_dir = os.path.join(tmp, "repo")
        code_out_dir = os.path.join(tmp, "code_out")
        os.makedirs(repo_dir, exist_ok=True)
        doc_file = os.path.join(repo_dir, "ADR-011-restricted-execution-sandbox.md")
        with open(doc_file, "w", encoding="utf-8") as f:
            f.write("# ADR-011\nRestricted execution sandbox threat model guarantees.\n")
        csv_file = os.path.join(tmp, "series.csv")
        with open(csv_file, "w", encoding="utf-8") as f:
            f.write("date,val\n" + "\n".join(f"2026-01-{i:02d},{100 + i}" for i in range(1, 16)) + "\n")

        old_url = os.environ.get("PAI_MODEL_URL")
        os.environ["PAI_MODEL_URL"] = server_url
        try:
            # Verify /api/tags against the stub server
            tag_probe = probe_ollama_server(server_url)
            self.assertTrue(tag_probe["reachable"])
            self.assertIn("qwen2.5-coder:7b", tag_probe["models"])

            subcommand_runs = [
                (
                    "code",
                    [
                        "code",
                        "Write a Python function `add(a: int, b: int) -> int` that returns the sum of a and b.\nExample:\n  add(2, 3) -> 5",
                        "--out",
                        code_out_dir,
                        "--json",
                    ],
                ),
                (
                    "analyze",
                    [
                        "analyze",
                        repo_dir,
                        "--question",
                        "Summarize the threat model in ADR-011",
                        "--json",
                    ],
                ),
                (
                    "docs",
                    [
                        "docs",
                        doc_file,
                        "--question",
                        "What does ADR-011 cover?",
                        "--json",
                    ],
                ),
                (
                    "forecast",
                    [
                        "forecast",
                        csv_file,
                        "--horizon",
                        "2",
                        "--question",
                        "What are the point forecasts?",
                        "--json",
                    ],
                ),
                (
                    "chat",
                    [
                        "chat",
                        "Hello local assistant",
                        "--json",
                    ],
                ),
            ]

            for name, argv in subcommand_runs:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = main(argv)
                self.assertEqual(
                    rc,
                    0,
                    f"Unmocked subcommand '{name}' failed (rc={rc}): {buf.getvalue()}",
                )
                payload = json.loads(buf.getvalue())
                self.assertTrue(payload.get("success"), f"Subcommand '{name}' payload not success: {payload}")
                self.assertIsNotNone(payload.get("selected_model"), f"Subcommand '{name}' missing selected_model")

            post_Endpoints = [r for r in recorded_requests if r[0] == "POST" and r[1] == "/api/generate"]
            self.assertGreaterEqual(len(post_Endpoints), 6)
        finally:
            if old_url is None:
                os.environ.pop("PAI_MODEL_URL", None)
            else:
                os.environ["PAI_MODEL_URL"] = old_url
            server.shutdown()
            server.server_close()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_verify_forecast_explanation_numbers_and_label(self):
        """
        Phase 1.1 (3b): Verifies that `verify_forecast_explanation_numbers` catches
        when `model_explanation` cites confidence interval bounds (`372.45`, `387.45`, `402.45`)
        instead of point forecasts (`355`, `370`, `385`), and passes when point forecasts are cited.
        """
        from pai import MODEL_EXPLANATION_LABEL, verify_forecast_explanation_numbers

        report_dict = {
            "total_points": 24,
            "horizon": 3,
            "backtest": {
                "holdout_size": 3,
                "mae": 5.0,
                "rmse": 6.1,
                "naive_mae": 15.0,
            },
            "forecasts": [
                {"step": 1, "date": "2026-10-01", "point": 355.0, "lower_80": 337.55, "upper_80": 372.45, "lower_95": 328.0, "upper_95": 382.0},
                {"step": 2, "date": "2026-10-08", "point": 370.0, "lower_80": 352.55, "upper_80": 387.45, "lower_95": 343.0, "upper_95": 397.0},
                {"step": 3, "date": "2026-10-15", "point": 385.0, "lower_80": 367.55, "upper_80": 402.45, "lower_95": 358.0, "upper_95": 412.0},
            ],
        }

        # Case 1: Model confuses 80% CI upper bounds with point forecasts
        bad_exp = "The forecasted values for the next 3 steps are 372.45, 387.45, and 402.45."
        chk_bad = verify_forecast_explanation_numbers(bad_exp, report_dict)
        self.assertEqual(chk_bad["label"], MODEL_EXPLANATION_LABEL)
        self.assertFalse(chk_bad["numbers_match_report"])
        self.assertTrue(chk_bad["ci_bounds_cited_without_point_forecasts"])
        self.assertEqual(chk_bad["cited_point_forecasts"], [])
        self.assertEqual(chk_bad["cited_ci_bounds"], [372.45, 387.45, 402.45])
        self.assertTrue(len(chk_bad["warnings"]) >= 1)

        # Case 2: Model cites actual point forecasts accurately
        good_exp = (
            "For 2026-10-01 to 2026-10-15, the point forecasts are 355.00, 370.00, and 385.00 "
            "(with 80% upper bounds 372.45, 387.45, 402.45 and backtest MAE 5.0 vs Naive 15.0)."
        )
        chk_good = verify_forecast_explanation_numbers(good_exp, report_dict)
        self.assertTrue(chk_good["numbers_match_report"])
        self.assertFalse(chk_good["ci_bounds_cited_without_point_forecasts"])
        self.assertEqual(chk_good["cited_point_forecasts"], [355.0, 370.0, 385.0])
        self.assertEqual(chk_good["unmatched_numbers"], [])

    # -------------------------------------------------------------------------
    # Finding N: CLI Crash Fix Tests
    # -------------------------------------------------------------------------
    def test_cli_max_files_zero_clean_one_line_error_exit_2(self):
        """Verifies `pai analyze <folder> --max-files 0` catches ValueError and prints clean 1-line error with exit 2."""
        with tempfile.TemporaryDirectory() as td:
            f_err = io.StringIO()
            with redirect_stderr(f_err):
                rc = main(["analyze", td, "--max-files", "0"])
            self.assertEqual(rc, 2)
            err = f_err.getvalue()
            self.assertNotIn("Traceback", err)
            self.assertIn("Error: max_file_count must be between 1 and 1000000", err)
            # Exactly one non-empty line
            lines = [l for l in err.strip().splitlines() if l.strip()]
            self.assertEqual(len(lines), 1)

    def test_cli_missing_binary_clean_one_line_error_analyze_and_docs_exit_2(self):
        """Verifies pai analyze and pai docs catch CoreBridgeUnavailableError with clean 1-line message and exit 2."""
        from pai_core_bridge import CoreBridgeUnavailableError
        import pai_core_bridge

        old_core = os.environ.get("PAI_USE_RUST_CORE")
        old_fb = os.environ.get("PAI_RUST_FALLBACK_PYTHON")
        try:
            os.environ["PAI_USE_RUST_CORE"] = "1"
            os.environ.pop("PAI_RUST_FALLBACK_PYTHON", None)
            pai_core_bridge.PAI_USE_RUST_CORE = True
            pai_core_bridge.PAI_RUST_FALLBACK_PYTHON = False

            with tempfile.TemporaryDirectory() as td:
                test_doc = os.path.join(td, "doc.md")
                with open(test_doc, "w") as f:
                    f.write("# Sample Doc\n")

                with patch("pai_core_bridge.find_core_binary", side_effect=CoreBridgeUnavailableError("pai-core binary not found")):
                    # 1. pai analyze
                    f_err1 = io.StringIO()
                    with redirect_stderr(f_err1):
                        rc1 = main(["analyze", td])
                    self.assertEqual(rc1, 2)
                    err1 = f_err1.getvalue()
                    self.assertNotIn("Traceback", err1)
                    self.assertIn("Error: pai-core binary not found", err1)
                    self.assertIn("cargo build --release", err1)
                    self.assertIn("PAI_RUST_FALLBACK_PYTHON=1", err1)
                    lines1 = [l for l in err1.strip().splitlines() if l.strip()]
                    self.assertEqual(len(lines1), 1)

                    # 2. pai docs
                    f_err2 = io.StringIO()
                    with redirect_stderr(f_err2):
                        rc2 = main(["docs", test_doc])
                    self.assertEqual(rc2, 2)
                    err2 = f_err2.getvalue()
                    self.assertNotIn("Traceback", err2)
                    self.assertIn("Error: pai-core binary not found", err2)
                    self.assertIn("cargo build --release", err2)
                    self.assertIn("PAI_RUST_FALLBACK_PYTHON=1", err2)
                    lines2 = [l for l in err2.strip().splitlines() if l.strip()]
                    self.assertEqual(len(lines2), 1)
        finally:
            if old_core is not None:
                os.environ["PAI_USE_RUST_CORE"] = old_core
                pai_core_bridge.PAI_USE_RUST_CORE = (old_core == "1")
            else:
                os.environ.pop("PAI_USE_RUST_CORE", None)
                pai_core_bridge.PAI_USE_RUST_CORE = False

            if old_fb is not None:
                os.environ["PAI_RUST_FALLBACK_PYTHON"] = old_fb
                pai_core_bridge.PAI_RUST_FALLBACK_PYTHON = (old_fb == "1")
            else:
                os.environ.pop("PAI_RUST_FALLBACK_PYTHON", None)
                pai_core_bridge.PAI_RUST_FALLBACK_PYTHON = False

    def test_cli_missing_binary_doctor_reports_failed_core_bridge_and_continues(self):
        """Verifies pai doctor turns missing binary into a failed core_bridge check and continues remaining checks."""
        from pai_core_bridge import CoreBridgeUnavailableError
        import pai_core_bridge

        old_core = os.environ.get("PAI_USE_RUST_CORE")
        old_fb = os.environ.get("PAI_RUST_FALLBACK_PYTHON")
        try:
            os.environ["PAI_USE_RUST_CORE"] = "1"
            os.environ.pop("PAI_RUST_FALLBACK_PYTHON", None)
            pai_core_bridge.PAI_USE_RUST_CORE = True
            pai_core_bridge.PAI_RUST_FALLBACK_PYTHON = False

            with patch("pai_core_bridge.find_core_binary", side_effect=CoreBridgeUnavailableError("pai-core binary not found")):
                # 1. JSON mode
                f_json = io.StringIO()
                with redirect_stdout(f_json):
                    rc_json = main(["doctor", "--skip-smoke", "--json"])
                self.assertEqual(rc_json, 1)
                parsed = json.loads(f_json.getvalue())
                self.assertFalse(parsed["all_passed"])

                # Verify core_bridge check is marked failed with helpful message
                cb_check = next(c for c in parsed["checks"] if c["check"] == "core_bridge")
                self.assertFalse(cb_check["passed"])
                self.assertIn("pai-core binary not found", cb_check["detail"])
                self.assertIn("cargo build --release", cb_check["detail"])
                self.assertIn("PAI_RUST_FALLBACK_PYTHON=1", cb_check["detail"])

                # Verify other checks continued to run and passed
                check_names = [c["check"] for c in parsed["checks"]]
                self.assertIn("os_telemetry", check_names)
                self.assertIn("sandbox_boundary", check_names)
                self.assertIn("ram_admission", check_names)
                self.assertIn("ingest_limits", check_names)

                # 2. Text mode
                f_text = io.StringIO()
                with redirect_stdout(f_text):
                    rc_text = main(["doctor", "--skip-smoke"])
                self.assertEqual(rc_text, 1)
                text = f_text.getvalue()
                self.assertNotIn("Traceback", text)
                self.assertIn("core_bridge", text)
                self.assertIn("[FAIL]", text)
                self.assertIn("pai-core binary not found", text)
                self.assertIn("os_telemetry", text)
        finally:
            if old_core is not None:
                os.environ["PAI_USE_RUST_CORE"] = old_core
                pai_core_bridge.PAI_USE_RUST_CORE = (old_core == "1")
            else:
                os.environ.pop("PAI_USE_RUST_CORE", None)
                pai_core_bridge.PAI_USE_RUST_CORE = False

            if old_fb is not None:
                os.environ["PAI_RUST_FALLBACK_PYTHON"] = old_fb
                pai_core_bridge.PAI_RUST_FALLBACK_PYTHON = (old_fb == "1")
            else:
                os.environ.pop("PAI_RUST_FALLBACK_PYTHON", None)
                pai_core_bridge.PAI_RUST_FALLBACK_PYTHON = False


if __name__ == "__main__":
    unittest.main()


