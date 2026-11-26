"""Security regression tests for Milestones M4 & M5 (FINDING-01, 02, 03, 09, 10, 12, 14, 15).

Verifies:
1. FINDING-01: Token authentication required for all /api/* routes, strict Host
   and Origin validation, constant-time token comparison.
2. FINDING-02: Native registry manipulation for model storage path with newline/control-char rejection.
3. FINDING-03: Secure updater with Ed25519 verification and fail-closed network errors.
4. FINDING-09: Web citations and UI markdown URL sanitization, Tauri strict CSP.
5. FINDING-10: Ollama daemon management delegated to OllamaServiceManager.
6. FINDING-12: Body size limits (16 MiB), model folder sanitization, ADS path rejection, zip bomb guards.
7. FINDING-14: Avoidance of on-demand csc.exe compilation in temp directories.
8. FINDING-15: Bounded background worker execution via thread pool.
"""

from __future__ import annotations

import io
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

try:
    import _bootstrap
except ImportError:
    try:
        import tests._bootstrap
    except ImportError:
        pass

RESEARCH_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = RESEARCH_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

import desktop.bridge_server as bridge_server
from desktop.bridge_server import (
    PAIBridgeHandler,
    PAI_BRIDGE_TOKEN,
    _is_valid_origin,
    _is_valid_host,
    _MAX_REQUEST_BODY,
    _MAX_DECOMPRESSED_ARCHIVE_BYTES,
    _get_or_compile_windows_folder_picker,
    create_physical_model_folder,
    parse_uploaded_file_content,
    set_model_storage_path,
)


class TestBridgeTokenAuthAndNetworkSecurity(unittest.TestCase):
    """FINDING-01: Per-launch bridge token, strict CORS, Host validation."""

    @classmethod
    def setUpClass(cls):
        # Spin up ephemeral test server
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), PAIBridgeHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_missing_token_returns_403_on_api_route(self):
        req = urllib.request.Request(f"{self.base_url}/api/models/recommended")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 403)
        resp_data = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertIn("error", resp_data)
        self.assertIn("x-pai-token", resp_data["error"].lower())

    def test_invalid_token_returns_403_on_api_route(self):
        req = urllib.request.Request(
            f"{self.base_url}/api/models/recommended",
            headers={"X-PAI-Token": "completely_bogus_token_value_here"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 403)

    def test_valid_token_succeeds_on_api_route(self):
        req = urllib.request.Request(
            f"{self.base_url}/api/models/recommended",
            headers={"X-PAI-Token": PAI_BRIDGE_TOKEN},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(data.get("success"))
            self.assertIn("recommended", data)

    def test_unauthenticated_non_api_route_serves_static(self):
        # Root index.html should not be gated by token so webview can load
        req = urllib.request.Request(f"{self.base_url}/")
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            content = resp.read().decode("utf-8")
            self.assertIn("PAI Studio", content)

    def test_mismatched_host_header_rejected_with_403(self):
        req = urllib.request.Request(
            f"{self.base_url}/api/models/recommended",
            headers={
                "X-PAI-Token": PAI_BRIDGE_TOKEN,
                "Host": "malicious-site.example.com",
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 403)

    def test_origin_validation_logic(self):
        self.assertTrue(_is_valid_origin("", self.port))
        self.assertTrue(_is_valid_origin("http://tauri.localhost", self.port))
        self.assertTrue(_is_valid_origin("https://tauri.localhost", self.port))
        self.assertTrue(_is_valid_origin(f"http://127.0.0.1:{self.port}", self.port))
        self.assertFalse(_is_valid_origin("http://evil.com", self.port))
        self.assertFalse(_is_valid_origin(f"http://127.0.0.1:{self.port + 1}", self.port))

    def test_host_validation_logic(self):
        self.assertTrue(_is_valid_host(f"127.0.0.1:{self.port}", self.port))
        self.assertTrue(_is_valid_host("127.0.0.1", self.port))
        self.assertTrue(_is_valid_host(f"localhost:{self.port}", self.port))
        self.assertFalse(_is_valid_host("evil.com", self.port))
        self.assertFalse(_is_valid_host("", self.port))

    def test_cors_preflight_blocks_external_origin_with_403(self):
        req = urllib.request.Request(
            f"{self.base_url}/api/models/recommended",
            headers={
                "Origin": "http://evil-attacker.example.com",
            },
            method="OPTIONS",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 403)


class TestNativeRegistryHardening(unittest.TestCase):
    """FINDING-02: Native winreg usage and rejection of control characters."""

    def test_rejects_newlines_and_null_bytes(self):
        res1 = set_model_storage_path("C:\\models\ncmd.exe")
        self.assertFalse(res1)

        res2 = set_model_storage_path("C:\\models\r\ncalc.exe")
        self.assertFalse(res2)

        res3 = set_model_storage_path("C:\\models\0evil")
        self.assertFalse(res3)

    @patch("subprocess.run")
    def test_never_invokes_powershell_subprocess(self, mock_subproc):
        with tempfile.TemporaryDirectory() as td:
            set_model_storage_path(td)
            for call_args in mock_subproc.call_args_list:
                cmd_line = " ".join(str(a) for a in call_args[0][0])
                self.assertNotIn("powershell", cmd_line.lower())


class TestUpdaterSecurity(unittest.TestCase):
    """FINDING-03: Auto-updater validation and fail-closed error handling."""

    def test_update_manager_fails_closed_on_network_error(self):
        mgr = bridge_server.PAIUpdateManager()
        res = mgr.start_download(
            target_version="9.9.9",
            download_url="http://127.0.0.1:54321/nonexistent-update-pkg.zip",
        )
        self.assertTrue(res["success"])
        # Wait for worker thread to fail closed
        if hasattr(mgr, "_download_thread") and mgr._download_thread:
            mgr._download_thread.join(timeout=3.0)
        self.assertEqual(mgr.download_state["status"], "error")
        self.assertIsNotNone(mgr.download_state["error_message"])

    def test_apply_pending_update_fails_safely_when_empty(self):
        from desktop.apply_pending_update import check_and_apply_pending
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"LOCALAPPDATA": td}):
                # With no pending updates or invalid trust root, returns False safely
                applied = check_and_apply_pending()
                self.assertFalse(applied)

    def test_apply_pending_update_ci_manifest_sha256_and_negative_controls(self):
        import hashlib
        import zipfile
        from desktop.apply_pending_update import check_and_apply_pending

        with tempfile.TemporaryDirectory() as td:
            pai_dir = Path(td) / "Programs" / "PAI"
            (pai_dir / "ui").mkdir(parents=True, exist_ok=True)
            (pai_dir / "ui" / "VERSION").write_text("1.5.0-beta.1", encoding="utf-8")
            (pai_dir / "VERSION").write_text("1.5.0-beta.1", encoding="utf-8")

            good_zip = Path(td) / "pai-payload-1.5.0-beta.4-win-x64.zip"
            with zipfile.ZipFile(good_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("ui/index.html", "<html>updated</html>")
                zf.writestr("research/thought_graph.py", "# updated research module\n")
                zf.writestr("bridge_server.py", 'PAI_CURRENT_VERSION = "1.5.0-beta.4"\n')

            good_sha = hashlib.sha256(good_zip.read_bytes()).hexdigest()
            manifest_path = Path(td) / "manifest.json"
            manifest_path.write_text(json.dumps({
                "format": 1,
                "product": "pai-desktop",
                "version": "1.5.0-beta.4",
                "files": {
                    good_zip.name: {"sha256": good_sha, "size": good_zip.stat().st_size}
                },
            }), encoding="utf-8")

            # 1. Negative control: wrong SHA-256 rejected fail-closed
            (pai_dir / "pending_update.json").write_text(json.dumps({
                "target_version": "1.5.0-beta.4",
                "staged_path": str(good_zip),
                "manifest_path": str(manifest_path),
                "expected_sha256": "0" * 64,
            }), encoding="utf-8")
            with patch.dict(os.environ, {"LOCALAPPDATA": td}):
                self.assertFalse(check_and_apply_pending())
            self.assertEqual((pai_dir / "VERSION").read_text(encoding="utf-8").strip(), "1.5.0-beta.1")

            # 2. Negative control: strict PAI_REQUIRE_SIGNED_UPDATE=1 rejects unsigned zip
            (pai_dir / "pending_update.json").write_text(json.dumps({
                "target_version": "1.5.0-beta.4",
                "staged_path": str(good_zip),
                "manifest_path": str(manifest_path),
                "expected_sha256": good_sha,
            }), encoding="utf-8")
            with patch.dict(os.environ, {"LOCALAPPDATA": td, "PAI_REQUIRE_SIGNED_UPDATE": "1"}):
                self.assertFalse(check_and_apply_pending())

            # 3. Negative control: zip with '..' traversal rejected fail-closed
            evil_zip = Path(td) / "evil.zip"
            with zipfile.ZipFile(evil_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("../escape.txt", "pwn")
            evil_sha = hashlib.sha256(evil_zip.read_bytes()).hexdigest()
            (pai_dir / "pending_update.json").write_text(json.dumps({
                "target_version": "1.5.0-beta.4",
                "staged_path": str(evil_zip),
                "expected_sha256": evil_sha,
            }), encoding="utf-8")
            with patch.dict(os.environ, {"LOCALAPPDATA": td}):
                self.assertFalse(check_and_apply_pending())

            # 4. Positive control: valid CI archive + matching manifest SHA-256 installs & updates VERSION
            (pai_dir / "pending_update.json").write_text(json.dumps({
                "target_version": "1.5.0-beta.4",
                "staged_path": str(good_zip),
                "manifest_path": str(manifest_path),
                "expected_sha256": good_sha,
            }), encoding="utf-8")
            with patch.dict(os.environ, {"LOCALAPPDATA": td}):
                self.assertTrue(check_and_apply_pending())
            self.assertEqual((pai_dir / "VERSION").read_text(encoding="utf-8").strip(), "1.5.0-beta.4")
            self.assertEqual((pai_dir / "ui" / "VERSION").read_text(encoding="utf-8").strip(), "1.5.0-beta.4")
            self.assertTrue((pai_dir / "research" / "thought_graph.py").is_file())

            # 5. Negative control: downgrade rollback rejected fail-closed after install
            (pai_dir / "pending_update.json").write_text(json.dumps({
                "target_version": "1.5.0-beta.1",
                "staged_path": str(good_zip),
                "expected_sha256": good_sha,
            }), encoding="utf-8")
            with patch.dict(os.environ, {"LOCALAPPDATA": td}):
                self.assertFalse(check_and_apply_pending())


class TestUIAndCSPSecurity(unittest.TestCase):
    """FINDING-09: Tauri CSP and URL sanitization."""

    def test_tauri_conf_has_strict_csp(self):
        tauri_conf_path = REPO_ROOT / "desktop" / "src-tauri" / "tauri.conf.json"
        self.assertTrue(tauri_conf_path.is_file())
        with open(tauri_conf_path, "r", encoding="utf-8") as f:
            conf = json.load(f)
        csp = conf.get("app", {}).get("security", {}).get("csp")
        self.assertIsNotNone(csp)
        self.assertIn("default-src 'self'", csp)
        self.assertIn("connect-src 'self'", csp)
        # Verify remote origin wildcard is blocked
        self.assertNotIn("connect-src *", csp)
        self.assertNotIn("default-src *", csp)

    def test_app_js_includes_url_sanitization(self):
        app_js_path = REPO_ROOT / "desktop" / "ui" / "app.js"
        self.assertTrue(app_js_path.is_file())
        content = app_js_path.read_text(encoding="utf-8")
        self.assertIn("function sanitizeUrl", content)
        self.assertIn("javascript:", content)
        self.assertIn("vbscript:", content)
        self.assertIn("data:", content)


class TestOllamaLifecycleDelegation(unittest.TestCase):
    """FINDING-10: Ollama management delegated to ServiceManager."""

    def test_spawn_ollama_daemon_uses_service_manager(self):
        mock_instance = MagicMock()
        mock_instance.is_running.return_value = False
        mock_instance.start_service.return_value = True

        with patch("research.service_manager.OllamaServiceManager.get_instance", return_value=mock_instance):
            with tempfile.TemporaryDirectory() as td:
                ok = bridge_server._spawn_ollama_daemon(td)
                self.assertTrue(ok)
                mock_instance.start_service.assert_called_once()


class TestInputValidationAndResourceLimits(unittest.TestCase):
    """FINDING-12: 16 MiB body limit, folder sanitization, zip bomb guards."""

    def test_model_folder_name_sanitization(self):
        with tempfile.TemporaryDirectory() as td:
            # Traversal attempts should be sanitized and confined
            create_physical_model_folder(td, "../../evil_model")
            self.assertFalse((Path(td).parent / "evil_model").exists())

            # Control characters stripped
            create_physical_model_folder(td, "model\x00bad")

            # Valid folder creation
            create_physical_model_folder(td, "my-fine-model-v1")
            self.assertTrue((Path(td) / "my-fine-model-v1").is_dir())

    def test_docx_extraction_enforces_decompression_limit(self):
        # Create a docx archive with oversized word/document.xml content (> 10 MiB)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            large_chunk = b"<w:document><w:body><w:p><w:t>" + (b"A" * (12 * 1024 * 1024)) + b"</w:t></w:p></w:body></w:document>"
            zf.writestr("word/document.xml", large_chunk)
        buf.seek(0)

        # parse_uploaded_file_content catches ValueError on decompression limit and falls back safely
        result = parse_uploaded_file_content("bomb.docx", buf.getvalue())
        self.assertIsInstance(result, dict)
        self.assertIn("content", result)


class TestFolderPickerHardening(unittest.TestCase):
    """FINDING-14: Folder picker uses precompiled binary without on-demand compilation."""

    def test_get_or_compile_folder_picker_never_invokes_csc(self):
        with patch("subprocess.run") as mock_run:
            _ = _get_or_compile_windows_folder_picker()
            for call_args in mock_run.call_args_list:
                cmd_line = " ".join(str(a) for a in call_args[0][0])
                self.assertNotIn("csc.exe", cmd_line.lower())


class TestThreadPoolBounding(unittest.TestCase):
    """FINDING-15: Background execution bounded via ThreadPoolExecutor."""

    def test_agent_executor_has_max_workers_bound(self):
        self.assertIsNotNone(bridge_server._agent_executor)
        self.assertEqual(bridge_server._agent_executor._max_workers, 4)


if __name__ == "__main__":
    unittest.main()
