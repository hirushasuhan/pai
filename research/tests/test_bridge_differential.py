"""
Unit and differential tests for Slice 3 Integration Bridge (research/pai_core_bridge.py).
Compares Rust core bridge directly against Python reference across ingest, codec,
verdict frames, and canonical example extraction.
Tests both default path (PAI_USE_RUST_CORE=False) and bridge path (PAI_USE_RUST_CORE=True),
strict fail-closed schema enforcement, and end-to-end product execution with flag against stub server.
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

import _bootstrap  # noqa: F401
import ingest
import pai
import pai_core_bridge
from pai_core_bridge import (
    call_core_bridge,
    decode_envelope_json,
    defang_envelope_markers,
    extract_example_assertions,
    find_core_binary,
    get_ingest_limits,
    ingest_file,
    ingest_folder,
    is_junk_dir,
    is_secret_file,
    sanitize_header,
    sanitize_terminal_output,
    sanitize_text_content,
    scan_secret_content,
    verify_verdict_frame,
    wrap_untrusted_envelope,
)
import value_codec
import verify_loop


class TestBridgeDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Platform binary check & handshake verification (skips test if no compatible binary)
        try:
            bin_path = find_core_binary()
            pai_core_bridge.check_handshake(bin_path)
        except Exception as exc:
            raise unittest.SkipTest(f"pai-core binary not available or incompatible for platform: {exc}")

    def test_default_wrappers_flag_off(self):
        """Tests that all wrappers work without error on default path (PAI_USE_RUST_CORE=False)."""
        orig_flag = pai_core_bridge.PAI_USE_RUST_CORE
        pai_core_bridge.PAI_USE_RUST_CORE = False
        try:
            # 1. get_ingest_limits
            limits = get_ingest_limits()
            self.assertIsInstance(limits, dict)
            self.assertIn("max_file_size_bytes", limits)
            self.assertIn("secret_deny_patterns", limits)
            self.assertIn("junk_dir_patterns", limits)

            # 2. verify_verdict_frame
            nonce = "test_nonce_123"
            key = "test_key_456"
            empty_stdout = "No verdict framing here"
            v_res = verify_verdict_frame(
                comb_out=empty_stdout,
                parent_nonce=nonce,
                parent_hmac_key=key,
                expected_test_ids=("test_a",),
                exit_code=0,
                res_status="ok",
            )
            self.assertIsInstance(v_res, dict)
            self.assertFalse(v_res["passed"])
            self.assertEqual(v_res["status"], "ERROR")
            self.assertEqual(v_res["error_type"], "DriverPreemptedError")

            # 3. is_secret_file and is_junk_dir
            self.assertTrue(is_secret_file(".env"))
            self.assertFalse(is_secret_file("main.py"))
            self.assertTrue(is_junk_dir("node_modules"))

            # 4. sanitize_text_content
            self.assertEqual(sanitize_text_content("hello\r\nworld", max_line_length=100), "hello\nworld")

            # 5. ingest_file and ingest_folder
            with tempfile.TemporaryDirectory(prefix="pai_bridge_ingest_test_") as tmp_d:
                clean_f = os.path.join(tmp_d, "sample.txt")
                with open(clean_f, "w", encoding="utf-8") as f:
                    f.write("Clean ingestion test payload\n")
                item, rej = ingest_file(clean_f)
                self.assertIsNotNone(item)
                self.assertIsNone(rej)
                self.assertTrue(item.bytes_read > 0)

                rep = ingest_folder(tmp_d)
                self.assertIsInstance(rep, ingest.IngestionReport)
                self.assertEqual(rep.total_files, 1)
        finally:
            pai_core_bridge.PAI_USE_RUST_CORE = orig_flag

    def test_wrappers_flag_on(self):
        """Tests that all wrappers work without error when PAI_USE_RUST_CORE=True."""
        orig_flag = pai_core_bridge.PAI_USE_RUST_CORE
        pai_core_bridge.PAI_USE_RUST_CORE = True
        try:
            # 1. get_ingest_limits
            limits = get_ingest_limits()
            self.assertIsInstance(limits, dict)
            self.assertIn("max_file_size_bytes", limits)
            self.assertEqual(limits["max_file_size_bytes"], ingest.DEFAULT_MAX_FILE_SIZE)

            # 2. verify_verdict_frame
            nonce = "test_nonce_123"
            key = "test_key_456"
            empty_stdout = "No verdict framing here"
            v_res = verify_verdict_frame(
                comb_out=empty_stdout,
                parent_nonce=nonce,
                parent_hmac_key=key,
                expected_test_ids=("test_a",),
                exit_code=0,
                res_status="ok",
            )
            self.assertIsInstance(v_res, dict)
            self.assertFalse(v_res["passed"])
            self.assertEqual(v_res["status"], "ERROR")
            self.assertEqual(v_res["error_type"], "DriverPreemptedError")

            # 3. extract_example_assertions
            prompt = "Write `solve(x)`.\nExample:\n  solve(1) -> 2\n"
            stmts = extract_example_assertions(prompt, entry_point="solve")
            self.assertEqual(stmts, ["assert solve(1) == 2"])

            # 4. ingest_file and ingest_folder via bridge
            with tempfile.TemporaryDirectory(prefix="pai_bridge_ingest_test_") as tmp_d:
                clean_f = os.path.join(tmp_d, "sample.txt")
                with open(clean_f, "w", encoding="utf-8") as f:
                    f.write("Clean ingestion test payload\n")
                item, rej = ingest_file(clean_f)
                self.assertIsNotNone(item)
                self.assertIsNone(rej)
                self.assertTrue(item.bytes_read > 0)

                rep = ingest_folder(tmp_d)
                self.assertIsInstance(rep, ingest.IngestionReport)
                self.assertEqual(rep.total_files, 1)
        finally:
            pai_core_bridge.PAI_USE_RUST_CORE = orig_flag

    def test_fail_closed_on_typos_and_unknown_fields(self):
        """Verifies Rust bridge fail-closed strictness on typos, unknown fields, and invalid types."""
        # 1. Typo in runner_status (Finding 4)
        with self.assertRaises(ValueError) as ctx:
            call_core_bridge(
                "verify_verdict_frame",
                comb_out="test",
                parent_nonce="n",
                parent_hmac_key="k",
                exit_code=0,
                runner_status="ok",
            )
        self.assertIn("unknown field `runner_status`", str(ctx.exception))

        # 2. String exit code (Finding 4)
        with self.assertRaises(ValueError) as ctx:
            call_core_bridge(
                "verify_verdict_frame",
                comb_out="test",
                parent_nonce="n",
                parent_hmac_key="k",
                exit_code="0",
                res_status="ok",
            )
        self.assertIn("invalid type: string", str(ctx.exception))

        # 3. Missing required exit_code
        with self.assertRaises(ValueError) as ctx:
            call_core_bridge(
                "verify_verdict_frame",
                comb_out="test",
                parent_nonce="n",
                parent_hmac_key="k",
                res_status="ok",
            )
        self.assertIn("missing field `exit_code`", str(ctx.exception))

        # 4. Unknown field in is_secret_file
        with self.assertRaises(ValueError) as ctx:
            call_core_bridge("is_secret_file", path=".env", extra_field=123)
        self.assertIn("unknown field `extra_field`", str(ctx.exception))

        # 5. Out of bounds max_line_length (Finding 5)
        with self.assertRaises(ValueError) as ctx:
            call_core_bridge("sanitize_text_content", text="hello", max_line_length=0)
        self.assertIn("max_line_length must be between 1 and 1000000", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            call_core_bridge("sanitize_text_content", text="hello", max_line_length=-5)
        self.assertIn("expected usize", str(ctx.exception))

    def test_bridge_ingest_primitives_parity(self):
        secret_files = [
            ".env",
            ".env.local",
            "id_rsa",
            "id_rsa.pub",
            "id_rsa*x",
            "aws_credentials",
            "main.py",
            "src/index.js",
            "secrets/token.json",
            "certs/server.pem",
        ]
        for f in secret_files:
            py_res = ingest.is_secret_file(f)
            rust_res = call_core_bridge("is_secret_file", path=f)
            self.assertEqual(py_res, rust_res, f"Mismatch for is_secret_file({f})")

        junk_dirs = [
            "node_modules",
            "__pycache__",
            ".venv",
            "build",
            "dist",
            ".git",
            "src",
            "components",
            "deep/nested/node_modules",
        ]
        for d in junk_dirs:
            py_res = ingest.is_junk_dir(d)
            rust_res = call_core_bridge("is_junk_dir", dirname=d)
            self.assertEqual(py_res, rust_res, f"Mismatch for is_junk_dir({d})")

        texts = [
            "sk-proj-" + "abcdefghijklmnopqrstuvwxyz1234567890",
            "xox" + "b-1234567890-1234567890-abcdefghijklmnop",
            "gh" + "p_1234567890abcdefghijklmnopqrstuvwxyz",
            "normal text without secrets",
            "api_key = " + "'abcdef'",
        ]
        for t in texts:
            py_res = ingest.scan_secret_content(t)
            rust_res = call_core_bridge("scan_secret_content", text=t)
            self.assertEqual(py_res, rust_res, f"Mismatch for scan_secret_content({t})")

        term_texts = [
            "\x1b[31mRed text\x1b[0m",
            "Normal line\r\nAnother line",
            "\x1b]0;Title\x07Body",
            "Clean terminal line",
        ]
        for tt in term_texts:
            py_res = ingest.sanitize_terminal_output(tt)
            rust_res = call_core_bridge("sanitize_terminal_output", text=tt)
            self.assertEqual(py_res, rust_res, f"Mismatch for sanitize_terminal_output({tt})")

    def test_bridge_codec_differential(self):
        valid_envelopes = [
            '{"t": "int", "v": 42}',
            '{"t": "int", "v": -9223372036854775808}',
            '{"t": "float", "v": 1.25}',
            '{"t": "float", "v": "inf"}',
            '{"t": "str", "v": "hello world"}',
            '{"t": "bool", "v": true}',
            '{"t": "none", "v": null}',
            '{"t": "list", "v": [{"t": "int", "v": 1}, {"t": "int", "v": 2}]}',
            '{"t": "set", "v": [{"t": "int", "v": 1}, {"t": "int", "v": 2}]}',
            '{"t": "dict", "v": [[{"t": "str", "v": "a"}, {"t": "int", "v": 1}]]}',
        ]
        for raw in valid_envelopes:
            py_decoded = value_codec.decode_envelope_json(raw)
            pai_core_bridge.PAI_USE_RUST_CORE = True
            try:
                bridge_decoded = decode_envelope_json(raw)
                self.assertEqual(py_decoded, bridge_decoded, f"Mismatch for {raw}")
            finally:
                pai_core_bridge.PAI_USE_RUST_CORE = False

        invalid_envelopes = [
            '{"t": "int", "v": 42.5}',
            '{"t": "int", "t": "int", "v": 1}',
            '{"t": "float", "v": "bad"}',
            '{"t": "str", "v": "lone surrogate \\ud800"}',
            '{"t": "set", "v": [{"t": "int", "v": 1}, {"t": "bool", "v": true}]}',
        ]
        for raw in invalid_envelopes:
            with self.assertRaises(value_codec.CodecError):
                value_codec.decode_envelope_json(raw)
            pai_core_bridge.PAI_USE_RUST_CORE = True
            try:
                with self.assertRaises(value_codec.CodecError):
                    decode_envelope_json(raw)
            finally:
                pai_core_bridge.PAI_USE_RUST_CORE = False

    def test_bridge_canonical_example_extraction_differential(self):
        prompts = [
            ("Write `solve(x)`.\nExample:\n  solve([1, 2]) -> 3\n", "solve"),
            ("Write `solve(x)`.\nExample:\n  solve(1) > (1)\n", "solve"),
            ("Write `solve(x)`.\nExample:\n  solve(1) > -(1)\n", "solve"),
            ("Write `solve(x)`.\nExample:\n  solve((1, 2)) > (1, 2)\n", "solve"),
            ("Write `solve(x)`.\nExample:\n  solve(1) -> 1,\n  solve(2) -> 2 ,\n", "solve"),
            ("Write `solve(x)`.\nExample:\n  solve(1) -> 1,,\n", "solve"),
            ("Write `solve(x)`.\nExample:\n  solve('\\ud800') -> 1\n", "solve"),
            ("Write `solve(x)`.\nExample:\n  solve(rb'x') -> 1\n", "solve"),
            ("def සිංහල(n):\nExample:\n  සිංහල(1) -> 2\n", None),
            ("def \uff4fpen(n):\nExample:\n  \uff4fpen(1) -> 2\n", None),
            ("def solve\u00b2(n):\nExample:\n  solve\u00b2(1) -> 2\n", None),
            ("Write `solve(x)`.\nExample:\n  solve('\\x4') -> 1\n", "solve"),
            ("Write `solve(x)`.\nExample:\n  solve('\\U00110000') -> 1\n", "solve"),
            ("Write `solve(x)`.\nExample:\n  solve('\\N{SPACE}') -> 1\n", "solve"),
            ("Write `solve(x)`.\nExample:\n  solve('\\0') -> 1\n", "solve"),
            ("Write `solve(x)`.\nExample:\n  solve('\x01') -> 1\n", "solve"),
        ]

        for p, ep in prompts:
            py_stmts = verify_loop.extract_example_assertions(p, entry_point=ep)
            pai_core_bridge.PAI_USE_RUST_CORE = True
            try:
                rust_stmts = extract_example_assertions(p, entry_point=ep)
                self.assertEqual(py_stmts, rust_stmts, f"Mismatch for prompt:\n{p}")
            finally:
                pai_core_bridge.PAI_USE_RUST_CORE = False

    def test_product_path_with_rust_core_flag_against_stub_server(self):
        """
        Runs `pai code` with `PAI_USE_RUST_CORE=1` against local loopback HTTP stub server.
        Verifies:
        1. Model test suite generation and canonical example extraction via Rust core bridge
        2. Test execution and verdict verification in sandbox via Rust core bridge
        3. Clean end-to-end pass (exit code 0).
        """
        if sys.platform.startswith("linux") and shutil.which("bwrap") is None:
            raise unittest.SkipTest("bwrap binary not found; sandbox execution unsupported in this Linux environment")

        class StubHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/api/tags":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"models": [{"name": "qwen2.5-coder:7b", "digest": "sha256:stub123"}]}).encode("utf-8"))
                elif self.path == "/api/ps":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"models": []}).encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                if self.path == "/api/generate":
                    content_length = int(self.headers.get("Content-Length", 0))
                    body = self.rfile.read(content_length).decode("utf-8")
                    req = json.loads(body)
                    prompt = req.get("prompt", "")

                    if "Write tests for" in prompt or "test suite" in prompt.lower():
                        resp_text = (
                            "```python\n"
                            "def test_double_basic():\n"
                            "    from solution import double\n"
                            "    assert double(10) == 20\n"
                            "```"
                        )
                    else:
                        resp_text = (
                            "```python\n"
                            "def double(x):\n"
                            "    return x * 2\n"
                            "```"
                        )

                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"response": resp_text}).encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), StubHandler)
        port = server.server_port
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        tmp_dir = tempfile.mkdtemp(prefix="pai_bridge_stub_")
        old_env_flag = os.environ.get("PAI_USE_RUST_CORE")
        old_model_url = os.environ.get("PAI_MODEL_URL")
        old_ollama_url = os.environ.get("OLLAMA_BASE_URL")
        try:
            os.environ["PAI_USE_RUST_CORE"] = "1"
            pai_core_bridge.PAI_USE_RUST_CORE = True
            stub_url = f"http://127.0.0.1:{port}"
            os.environ["PAI_MODEL_URL"] = stub_url
            os.environ["OLLAMA_BASE_URL"] = stub_url

            task_desc = "Write `double(x)` that returns twice x.\nExample:\n  double(2) -> 4\n  double(3) -> 6\n"
            from unittest import mock
            with mock.patch("sandbox.probe_system_boundary", return_value=(True, "OK")):
                rc = pai.main([
                    "code",
                    task_desc,
                    "--out", tmp_dir,
                    "--model", "test-model",
                    "--temperature", "0.0",
                    "--seed", "42",
                    "--overwrite",
                ])
            self.assertEqual(rc, 0, "Product path with PAI_USE_RUST_CORE=1 should pass against stub server")

            sol_path = os.path.join(tmp_dir, "solution.py")
            self.assertTrue(os.path.exists(sol_path), "solution.py must be staged on success")
            tests_path = os.path.join(tmp_dir, "test_solution.py")
            self.assertTrue(os.path.exists(tests_path), "test_solution.py must be staged on success")

            with open(tests_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("def test_pai_canonical_examples():", content)
            self.assertIn("assert double(2) == 4", content)
            self.assertIn("assert double(3) == 6", content)
        finally:
            server.shutdown()
            if old_env_flag is not None:
                os.environ["PAI_USE_RUST_CORE"] = old_env_flag
                pai_core_bridge.PAI_USE_RUST_CORE = old_env_flag.lower() in ("1", "true", "yes")
            else:
                os.environ.pop("PAI_USE_RUST_CORE", None)
                pai_core_bridge.PAI_USE_RUST_CORE = False

            if old_model_url is not None:
                os.environ["PAI_MODEL_URL"] = old_model_url
            else:
                os.environ.pop("PAI_MODEL_URL", None)

            if old_ollama_url is not None:
                os.environ["OLLAMA_BASE_URL"] = old_ollama_url
            else:
                os.environ.pop("OLLAMA_BASE_URL", None)

            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_handshake_conformance_vectors_hash(self):
        """Verifies that the compiled binary's conformance_vectors_hash matches the repository."""
        bin_path = find_core_binary()
        handshake = pai_core_bridge.check_handshake(bin_path)
        self.assertEqual(handshake["protocol_version"], 1)
        self.assertEqual(handshake["crate_version"], "0.1.0")
        self.assertEqual(handshake["conformance_vector_count"], 92)
        expected_hash = pai_core_bridge.compute_repo_vectors_hash()
        self.assertEqual(handshake["conformance_vectors_hash"], expected_hash)

    def test_verify_verdict_frame_matching_and_mismatching_test_hash(self):
        """Exercises verify_verdict_frame with matching and mismatching expected_test_hash on both paths."""
        from verify_loop import format_authenticated_verdict_frame

        nonce = "test_nonce_hash_123"
        key = "test_key_hash_456"
        matching_hash = "a" * 64
        mismatching_hash = "b" * 64

        payload = {
            "session_nonce": nonce,
            "status": "PASS",
            "passed": 2,
            "failed": 0,
            "errors": 0,
            "discovered": 2,
            "executed": 2,
            "failures": [],
            "executed_test_ids": ["test_1", "test_2"],
            "test_hash": matching_hash,
        }
        stdout = format_authenticated_verdict_frame(payload, key)

        for use_rust in (False, True):
            pai_core_bridge.PAI_USE_RUST_CORE = use_rust
            try:
                # 1. Matching hash -> PASS
                res_match = verify_verdict_frame(
                    stdout,
                    nonce,
                    key,
                    expected_test_ids=("test_1", "test_2"),
                    expected_test_hash=matching_hash,
                    exit_code=0,
                    res_status="ok",
                )
                self.assertTrue(res_match["passed"], f"Expected pass when hash matches (use_rust={use_rust})")
                self.assertEqual(res_match["status"], "PASS")

                # 2. Mismatching hash -> FAIL / INTEGRITY_VIOLATION
                res_mismatch = verify_verdict_frame(
                    stdout,
                    nonce,
                    key,
                    expected_test_ids=("test_1", "test_2"),
                    expected_test_hash=mismatching_hash,
                    exit_code=0,
                    res_status="ok",
                )
                self.assertFalse(res_mismatch["passed"], f"Expected fail when hash mismatches (use_rust={use_rust})")
                self.assertEqual(res_mismatch["status"], "mutation_error")
                self.assertEqual(res_mismatch["error_type"], "TestMutationError")
            finally:
                pai_core_bridge.PAI_USE_RUST_CORE = False

    def test_shadow_mode_extractor_discrepancy_authoritative(self):
        """Verifies that in shadow mode, Python reference remains authoritative and discrepancy is recorded."""
        from unittest import mock

        pai_core_bridge.reset_shadow_discrepancies()
        pai_core_bridge.PAI_USE_RUST_CORE = True
        try:
            # Mock bridge returning a divergent assertion
            with mock.patch("pai_core_bridge.call_core_bridge", return_value=["assert solve(1) == 999"]):
                prompt = "Write `solve(x)`.\nExample:\n  solve(1) -> 2\n"
                stmts = extract_example_assertions(prompt, entry_point="solve")
                # Authoritative Python reference must be returned (not the divergent mock)
                self.assertEqual(stmts, ["assert solve(1) == 2"])
                # Discrepancy counter must be incremented
                self.assertGreaterEqual(pai_core_bridge.get_shadow_discrepancy_count(), 1)
                discrepancies = pai_core_bridge.get_shadow_discrepancies()
                self.assertTrue(any(d["op"] == "extract_example_assertions" for d in discrepancies))
        finally:
            pai_core_bridge.PAI_USE_RUST_CORE = False
            pai_core_bridge.reset_shadow_discrepancies()

    def test_missing_binary_refusal_fail_closed(self):
        """Verifies that when PAI_USE_RUST_CORE=1 and binary is missing, both paths refuse fail-closed."""
        from unittest import mock

        old_env = os.environ.get("PAI_USE_RUST_CORE")
        os.environ["PAI_USE_RUST_CORE"] = "1"
        pai_core_bridge.PAI_USE_RUST_CORE = True
        try:
            with mock.patch("pai_core_bridge.find_core_binary", side_effect=pai_core_bridge.CoreBridgeUnavailableError("missing")):
                # Extractor refuses
                with self.assertRaises(pai_core_bridge.CoreBridgeUnavailableError):
                    extract_example_assertions("Write `solve(x)`.\nExample:\n  solve(1) -> 2\n", entry_point="solve")
                # Verifier refuses
                with self.assertRaises(pai_core_bridge.CoreBridgeUnavailableError):
                    verify_verdict_frame("stdout", "nonce", "key")
        finally:
            if old_env is not None:
                os.environ["PAI_USE_RUST_CORE"] = old_env
            else:
                os.environ.pop("PAI_USE_RUST_CORE", None)
            pai_core_bridge.PAI_USE_RUST_CORE = False

    def test_default_on_when_binary_present(self):
        """Verifies that in default mode (no env var), binary present means default-on."""
        from unittest import mock

        old_env = os.environ.pop("PAI_USE_RUST_CORE", None)
        old_fb = os.environ.pop("PAI_RUST_FALLBACK_PYTHON", None)
        old_flag = pai_core_bridge.PAI_USE_RUST_CORE
        pai_core_bridge.PAI_USE_RUST_CORE = True
        try:
            with mock.patch("pai_core_bridge.is_core_binary_available", return_value=True):
                self.assertTrue(pai_core_bridge.is_rust_core_enabled())
                self.assertEqual(pai_core_bridge.get_bridge_mode(), "default-on")
        finally:
            if old_env is not None:
                os.environ["PAI_USE_RUST_CORE"] = old_env
            if old_fb is not None:
                os.environ["PAI_RUST_FALLBACK_PYTHON"] = old_fb
            pai_core_bridge.PAI_USE_RUST_CORE = old_flag

    def test_default_on_graceful_fallback_when_binary_missing(self):
        """Verifies that in default mode without explicit env var, missing binary gracefully falls back to Python."""
        from unittest import mock

        old_env = os.environ.pop("PAI_USE_RUST_CORE", None)
        old_fb = os.environ.pop("PAI_RUST_FALLBACK_PYTHON", None)
        old_flag = pai_core_bridge.PAI_USE_RUST_CORE
        pai_core_bridge.PAI_USE_RUST_CORE = True
        pai_core_bridge.reset_fallback_warning()
        try:
            with mock.patch("pai_core_bridge.find_core_binary", side_effect=pai_core_bridge.CoreBridgeUnavailableError("missing")):
                self.assertFalse(pai_core_bridge.is_rust_core_enabled())
                self.assertEqual(pai_core_bridge.get_bridge_mode(), "binary-missing fallback")
                # Extractor gracefully uses Python reference without raising
                prompt = "Write `solve(x)`.\nExample:\n  solve(1) -> 2\n"
                stmts = extract_example_assertions(prompt, entry_point="solve")
                self.assertEqual(stmts, ["assert solve(1) == 2"])
        finally:
            if old_env is not None:
                os.environ["PAI_USE_RUST_CORE"] = old_env
            if old_fb is not None:
                os.environ["PAI_RUST_FALLBACK_PYTHON"] = old_fb
            pai_core_bridge.PAI_USE_RUST_CORE = old_flag

    def test_kill_switch_forces_pure_python(self):
        """Verifies that PAI_RUST_FALLBACK_PYTHON=1 forces pure Python mode regardless of binary."""
        from unittest import mock

        old_fb = os.environ.get("PAI_RUST_FALLBACK_PYTHON")
        os.environ["PAI_RUST_FALLBACK_PYTHON"] = "1"
        try:
            self.assertTrue(pai_core_bridge.is_python_fallback_forced())
            self.assertFalse(pai_core_bridge.is_rust_core_enabled())
            self.assertEqual(pai_core_bridge.get_bridge_mode(), "forced fallback (kill-switch)")
        finally:
            if old_fb is not None:
                os.environ["PAI_RUST_FALLBACK_PYTHON"] = old_fb
            else:
                os.environ.pop("PAI_RUST_FALLBACK_PYTHON", None)

    def test_shadow_mode_bridge_exception_handling(self):
        """Verifies that bridge exceptions in shadow mode record discrepancies and preserve Python assertions."""
        from unittest import mock

        pai_core_bridge.reset_shadow_discrepancies()
        pai_core_bridge.PAI_USE_RUST_CORE = True
        try:
            with mock.patch("pai_core_bridge.call_core_bridge", side_effect=RuntimeError("simulated IPC failure")):
                prompt = "Write `solve(x)`.\nExample:\n  solve(1) -> 2\n"
                stmts = extract_example_assertions(prompt, entry_point="solve")
                self.assertEqual(stmts, ["assert solve(1) == 2"])
                self.assertGreaterEqual(pai_core_bridge.get_shadow_discrepancy_count(), 1)
        finally:
            pai_core_bridge.PAI_USE_RUST_CORE = False
            pai_core_bridge.reset_shadow_discrepancies()

    def test_standalone_subprocess_docs_content_digest_not_null(self):
        """Verifies that standalone pai docs in a driver-less subprocess records non-null content_digest (Finding BC)."""
        import hashlib
        from pathlib import Path

        repo_root = Path(__file__).resolve().parent.parent

        with tempfile.TemporaryDirectory() as td:
            doc_file = Path(td) / "test_doc.md"
            doc_content = b"# Test Document\nTesting standalone telemetry content digest.\n"
            doc_file.write_bytes(doc_content)
            expected_digest = hashlib.sha256(doc_content).hexdigest()

            shadow_log = Path(td) / "test_shadow_log.jsonl"

            env = os.environ.copy()
            env["PAI_USE_RUST_CORE"] = "1"
            env["PAI_SHADOW_COMPARE"] = "1"
            env["PAI_SHADOW_LOG"] = str(shadow_log)
            env.pop("PAI_TELEMETRY_DRIVER", None)
            env.pop("PAI_TELEMETRY_SOURCE", None)

            # Invoke pai docs via clean subprocess without any driver shim
            cmd = [sys.executable, "pai.py", "docs", str(doc_file), "--json"]
            subprocess.run(
                cmd,
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertTrue(shadow_log.exists(), "Expected shadow log to be created by standalone pai docs")
            records = [
                json.loads(line)
                for line in shadow_log.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            ingest_records = [r for r in records if r.get("op") == "ingest_file"]
            self.assertTrue(len(ingest_records) >= 1, "Expected at least one ingest_file comparison record")

            record = ingest_records[0]
            self.assertIsNotNone(record.get("content_digest"), "content_digest must not be null in standalone pai docs")
            self.assertEqual(record.get("content_digest"), expected_digest, "content_digest must match file SHA-256")
            self.assertEqual(record.get("source"), "cli", "telemetry source must be 'cli'")

    def test_standalone_subprocess_analyze_content_digest_deterministic(self):
        """Verifies that standalone pai analyze records non-null and deterministic ingest_folder content_digest (Finding BC)."""
        import hashlib
        from pathlib import Path

        repo_root = Path(__file__).resolve().parent.parent

        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "project_folder"
            folder.mkdir()
            (folder / "file_a.txt").write_text("Hello from module A\n", encoding="utf-8")
            (folder / "file_b.md").write_text("# Module B Docs\n", encoding="utf-8")

            shadow_log_1 = Path(td) / "log_1.jsonl"
            shadow_log_2 = Path(td) / "log_2.jsonl"

            env_base = os.environ.copy()
            env_base["PAI_USE_RUST_CORE"] = "1"
            env_base["PAI_SHADOW_COMPARE"] = "1"
            env_base.pop("PAI_TELEMETRY_DRIVER", None)
            env_base.pop("PAI_TELEMETRY_SOURCE", None)

            # Run 1
            env_1 = env_base.copy()
            env_1["PAI_SHADOW_LOG"] = str(shadow_log_1)
            cmd = [sys.executable, "pai.py", "analyze", str(folder), "--json"]
            subprocess.run(cmd, cwd=str(repo_root), capture_output=True, text=True, env=env_1)

            # Run 2
            env_2 = env_base.copy()
            env_2["PAI_SHADOW_LOG"] = str(shadow_log_2)
            subprocess.run(cmd, cwd=str(repo_root), capture_output=True, text=True, env=env_2)

            self.assertTrue(shadow_log_1.exists(), "Expected shadow log 1 to be created")
            self.assertTrue(shadow_log_2.exists(), "Expected shadow log 2 to be created")

            records_1 = [json.loads(ln) for ln in shadow_log_1.read_text(encoding="utf-8").splitlines() if ln.strip()]
            records_2 = [json.loads(ln) for ln in shadow_log_2.read_text(encoding="utf-8").splitlines() if ln.strip()]

            folder_recs_1 = [r for r in records_1 if r.get("op") == "ingest_folder"]
            folder_recs_2 = [r for r in records_2 if r.get("op") == "ingest_folder"]

            self.assertTrue(len(folder_recs_1) >= 1, "Expected ingest_folder record in run 1")
            self.assertTrue(len(folder_recs_2) >= 1, "Expected ingest_folder record in run 2")

            d1 = folder_recs_1[0].get("content_digest")
            d2 = folder_recs_2[0].get("content_digest")

            self.assertIsNotNone(d1, "ingest_folder content_digest must not be null")
            self.assertEqual(len(d1), 64, "content_digest must be 64-hex SHA-256")
            self.assertEqual(d1, d2, "ingest_folder content_digest must be deterministic across runs")
            self.assertEqual(folder_recs_1[0].get("source"), "cli", "telemetry source must be 'cli'")

    def test_direct_verify_verdict_frame_content_digest_not_null(self):
        """Verifies that direct verify_verdict_frame call records non-null content_digest matching input frame (Finding BC)."""
        import hashlib
        from pathlib import Path
        from verify_loop import format_authenticated_verdict_frame

        with tempfile.TemporaryDirectory() as td:
            shadow_log = Path(td) / "verify_shadow.jsonl"
            old_log = os.environ.get("PAI_SHADOW_LOG")
            os.environ["PAI_SHADOW_LOG"] = str(shadow_log)

            pai_core_bridge.PAI_USE_RUST_CORE = True
            try:
                nonce = "test_nonce_digest_123"
                key = "test_key_digest_456"
                test_hash = "c" * 64
                payload = {
                    "session_nonce": nonce,
                    "status": "PASS",
                    "passed": 1,
                    "failed": 0,
                    "errors": 0,
                    "discovered": 1,
                    "executed": 1,
                    "failures": [],
                    "executed_test_ids": ["test_sample"],
                    "test_hash": test_hash,
                }
                stdout = format_authenticated_verdict_frame(payload, key)
                expected_digest = hashlib.sha256(stdout.encode("utf-8")).hexdigest()

                res = verify_verdict_frame(
                    stdout,
                    nonce,
                    key,
                    expected_test_ids=("test_sample",),
                    expected_test_hash=test_hash,
                    exit_code=0,
                    res_status="ok",
                )
                self.assertTrue(res["passed"])

                self.assertTrue(shadow_log.exists(), "Expected shadow log for verify_verdict_frame")
                records = [json.loads(ln) for ln in shadow_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
                verify_records = [r for r in records if r.get("op") == "verify_verdict_frame"]
                self.assertTrue(len(verify_records) >= 1, "Expected verify_verdict_frame comparison record")

                rec = verify_records[0]
                self.assertIsNotNone(rec.get("content_digest"), "verify_verdict_frame content_digest must not be null")
                self.assertEqual(rec.get("content_digest"), expected_digest, "content_digest must match stdout frame SHA-256")
            finally:
                pai_core_bridge.PAI_USE_RUST_CORE = False
                if old_log is not None:
                    os.environ["PAI_SHADOW_LOG"] = old_log
                else:
                    os.environ.pop("PAI_SHADOW_LOG", None)

    def test_discrepancy_policy_ingest_file_returns_python_and_logs(self):
        """Verifies that on shadow discrepancy in ingest_file, Python reference result is returned and discrepancy is logged."""
        from unittest import mock
        from ingest import IngestionRejection

        pai_core_bridge.reset_shadow_discrepancies()
        pai_core_bridge.PAI_USE_RUST_CORE = True
        pai_core_bridge.PAI_SHADOW_COMPARE = True
        try:
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
                tf.write("Benign file content\n")
                tf_path = tf.name

            try:
                # Monkeypatch py_ingest_file to return a secret rejection (mismatch against Rust's accepted item)
                mock_rej = IngestionRejection(path=tf_path, reason_code="SECRET_FILE", message="Mock secret rejection")
                with mock.patch("pai_core_bridge.py_ingest_file", return_value=(None, mock_rej)):
                    item, rej = pai_core_bridge.ingest_file(tf_path)

                # Python reference result must be returned on discrepancy!
                self.assertIsNone(item, "Expected Python rejection on mismatch (item=None)")
                self.assertIsNotNone(rej, "Expected Python rejection on mismatch")
                self.assertEqual(rej.reason_code, "SECRET_FILE")

                # Discrepancy must be recorded
                self.assertGreaterEqual(pai_core_bridge.get_shadow_discrepancy_count(), 1)
                discs = pai_core_bridge.get_shadow_discrepancies()
                self.assertTrue(any(d.get("op") == "ingest_file" for d in discs))
            finally:
                if os.path.exists(tf_path):
                    os.remove(tf_path)
        finally:
            pai_core_bridge.PAI_USE_RUST_CORE = False
            pai_core_bridge.reset_shadow_discrepancies()

    def test_discrepancy_policy_ingest_folder_returns_python_and_logs(self):
        """Verifies that on shadow discrepancy in ingest_folder, Python reference report is returned."""
        from pathlib import Path
        from unittest import mock
        from ingest import IngestionReport

        pai_core_bridge.reset_shadow_discrepancies()
        pai_core_bridge.PAI_USE_RUST_CORE = True
        pai_core_bridge.PAI_SHADOW_COMPARE = True
        try:
            with tempfile.TemporaryDirectory() as td:
                p = Path(td) / "sample.txt"
                p.write_text("sample", encoding="utf-8")

                mock_report = IngestionReport(
                    root=td,
                    items=[],
                    rejections=[],
                    total_bytes=12345,
                    total_files=999,  # Injected mismatch
                    limits={},
                    rejection_counts={},
                    rejections_capped=False,
                )
                with mock.patch("pai_core_bridge.py_ingest_folder", return_value=mock_report):
                    rep = pai_core_bridge.ingest_folder(td)

                # Authoritative Python reference report returned
                self.assertEqual(rep.total_files, 999)
                self.assertGreaterEqual(pai_core_bridge.get_shadow_discrepancy_count(), 1)
        finally:
            pai_core_bridge.PAI_USE_RUST_CORE = False
            pai_core_bridge.reset_shadow_discrepancies()

    def test_discrepancy_policy_deny_wins_ops(self):
        """Verifies that for accept/deny ops (verify_ed25519, verify_verdict_frame), deny wins on mismatch."""
        from unittest import mock
        from verify_loop import format_authenticated_verdict_frame

        pai_core_bridge.reset_shadow_discrepancies()
        pai_core_bridge.PAI_USE_RUST_CORE = True
        pai_core_bridge.PAI_SHADOW_COMPARE = True
        try:
            # 1. verify_ed25519: Python denies (returns False), Rust accepts (returns True) -> deny wins (False)
            with mock.patch("ed25519_ref.verify", return_value=False), \
                 mock.patch("pai_core_bridge.call_core_bridge", return_value=True):
                res = pai_core_bridge.verify_ed25519(b"\x00" * 32, b"msg", b"\x00" * 64)
                self.assertFalse(res, "deny-wins: verify_ed25519 must return False when Python denies")
                self.assertGreaterEqual(pai_core_bridge.get_shadow_discrepancy_count(), 1)

            # 2. verify_verdict_frame: Rust accepts (passed=True), Python denies (passed=False) -> deny wins
            fake_stdout = format_authenticated_verdict_frame({"status": "PASS", "passed": 1, "failed": 0, "errors": 0, "discovered": 1, "executed": 1, "failures": [], "executed_test_ids": ["t"], "test_hash": "a" * 64}, "k")
            mock_rust_res = {"passed": True, "status": "PASS", "error_type": None, "discovered": 1, "executed": 1, "failed": 0, "errors": 0}
            mock_py_res = {"passed": False, "status": "INTEGRITY_VIOLATION", "error_type": "TamperedSignature", "discovered": 0, "executed": 0, "failed": 0, "errors": 1}
            with mock.patch("pai_core_bridge.py_verify_verdict_frame", return_value=mock_py_res), \
                 mock.patch("pai_core_bridge.call_core_bridge", return_value=mock_rust_res):
                res_vf = pai_core_bridge.verify_verdict_frame(fake_stdout, "n", "k", expected_test_ids=("t",), expected_test_hash="a" * 64)
                self.assertFalse(res_vf["passed"], "deny-wins: verify_verdict_frame must fail-closed on mismatch")
                self.assertEqual(res_vf["status"], "INTEGRITY_VIOLATION")
        finally:
            pai_core_bridge.PAI_USE_RUST_CORE = False
            pai_core_bridge.reset_shadow_discrepancies()

    def test_discrepancy_policy_stderr_warning_emitted_exactly_once(self):
        """Verifies that discrepancy warning is emitted to stderr exactly once per session."""
        import io
        from unittest import mock

        pai_core_bridge.reset_discrepancy_warning()
        pai_core_bridge.reset_shadow_discrepancies()

        captured_stderr = io.StringIO()
        with mock.patch("sys.stderr", captured_stderr):
            # Trigger 3 discrepancies
            pai_core_bridge.record_shadow_discrepancy("op1", "detail 1")
            pai_core_bridge.record_shadow_discrepancy("op2", "detail 2")
            pai_core_bridge.record_shadow_discrepancy("op3", "detail 3")

        output = captured_stderr.getvalue()
        warning_count = output.count("WARNING: Shadow evaluation discrepancy detected")
        self.assertEqual(warning_count, 1, f"Expected warning to be emitted exactly once, got {warning_count}")
        self.assertIn("op 'op1'", output)

    def test_discrepancy_policy_shadow_compare_off_returns_rust(self):
        """Verifies that when PAI_SHADOW_COMPARE=0, no shadow comparison occurs and Rust result is returned."""
        from unittest import mock
        from ingest import IngestionRejection

        pai_core_bridge.reset_shadow_discrepancies()
        pai_core_bridge.PAI_USE_RUST_CORE = True
        pai_core_bridge.PAI_SHADOW_COMPARE = False
        try:
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
                tf.write("Benign content\n")
                tf_path = tf.name

            try:
                # If py_ingest_file were called, it would reject
                mock_rej = IngestionRejection(path=tf_path, reason_code="SECRET_FILE", message="Mock secret")
                with mock.patch("pai_core_bridge.py_ingest_file", return_value=(None, mock_rej)):
                    item, rej = pai_core_bridge.ingest_file(tf_path)

                # Shadow compare is OFF -> Rust result returned (accepted item, no rejection)
                self.assertIsNotNone(item, "Expected Rust result when PAI_SHADOW_COMPARE=0")
                self.assertIsNone(rej, "Expected no rejection when PAI_SHADOW_COMPARE=0")
                self.assertEqual(pai_core_bridge.get_shadow_discrepancy_count(), 0)
            finally:
                if os.path.exists(tf_path):
                    os.remove(tf_path)
        finally:
            pai_core_bridge.PAI_USE_RUST_CORE = False
            pai_core_bridge.PAI_SHADOW_COMPARE = True
            pai_core_bridge.reset_shadow_discrepancies()


if __name__ == "__main__":
    unittest.main()
