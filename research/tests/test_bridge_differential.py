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
            pai_core_bridge.PAI_USE_RUST_CORE = False

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


if __name__ == "__main__":
    unittest.main()
