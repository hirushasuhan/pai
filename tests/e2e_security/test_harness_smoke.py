"""Smoke tests (positive and negative controls) for the E2E security harness."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from tests.e2e_security.harness import (
    DESKTOP_DIR,
    REPO_ROOT,
    RESEARCH_DIR,
    BridgeTestServer,
    IsolatedPaiHome,
    LocalMockHTTPServer,
    assert_no_unfalsifiable_claims_compliant,
    build_signed_update_bundle,
    dynamic_secret,
    ensure_research_on_path,
    make_dummy_token,
    make_symlink_zip_bytes,
    make_zip_bomb_bytes,
    make_zlib_bomb_pdf_bytes,
)


class TestIsolatedPaiHomeSmoke(unittest.TestCase):
    def test_isolated_home_redirects_paths_and_restores_cleanly(self) -> None:
        orig_userprofile = os.environ.get("USERPROFILE")
        orig_gemini = os.environ.get("GEMINI_API_KEY")
        os.environ["GEMINI_API_KEY"] = make_dummy_token("gemini")
        try:
            with IsolatedPaiHome() as home:
                self.assertEqual(Path.home().resolve(), home.home_dir.resolve())
                self.assertEqual(
                    Path(os.path.expanduser("~")).resolve(),
                    home.home_dir.resolve(),
                )
                self.assertEqual(Path(os.environ["APPDATA"]).resolve(), home.appdata.resolve())
                self.assertEqual(
                    Path(os.environ["LOCALAPPDATA"]).resolve(),
                    home.localappdata.resolve(),
                )
                self.assertTrue(home.install_dir.is_dir())
                self.assertNotIn("GEMINI_API_KEY", os.environ)
                root_path = home.root

            self.assertFalse(root_path.exists())
            self.assertEqual(os.environ.get("USERPROFILE"), orig_userprofile)
            self.assertIn("GEMINI_API_KEY", os.environ)
        finally:
            if orig_gemini is None:
                os.environ.pop("GEMINI_API_KEY", None)
            else:
                os.environ["GEMINI_API_KEY"] = orig_gemini

    def test_isolated_home_resets_quota_ledger_singleton(self) -> None:
        ensure_research_on_path()
        import quota_engine

        quota_engine.QuotaLedger._instance = object()
        try:
            with IsolatedPaiHome():
                self.assertIsNone(quota_engine.QuotaLedger._instance)
            self.assertIsNotNone(quota_engine.QuotaLedger._instance)
        finally:
            quota_engine.QuotaLedger._instance = None


class TestBridgeTestServerSmoke(unittest.TestCase):
    def test_bridge_server_ephemeral_port_request_and_raw_http(self) -> None:
        with BridgeTestServer() as srv:
            self.assertGreater(srv.port, 0)
            self.assertNotEqual(srv.port, 8765)

            resp = srv.request("GET", "/api/status")
            self.assertEqual(resp.status, 200)
            self.assertIsInstance(resp.json, dict)

            raw = (
                f"GET /api/status HTTP/1.0\r\n"
                f"Host: 127.0.0.1:{srv.port}\r\n"
                f"X-PAI-Token: {srv.token}\r\n"
                f"\r\n"
            ).encode("ascii")
            raw_resp = srv.raw_http(raw)
            self.assertEqual(raw_resp.status, 200)
            self.assertIsInstance(raw_resp.json, dict)

            for line in srv.stdout_lines:
                self.assertNotIn(srv.token, line)

    def test_require_native_cli_flag_behavior(self) -> None:
        if BridgeTestServer.supports_native_cli():
            with BridgeTestServer(require_native_cli=True) as srv:
                self.assertNotEqual(srv.port, 8765)
                resp = srv.request("GET", "/api/status")
                self.assertEqual(resp.status, 200)
        else:
            with self.assertRaises(AssertionError):
                with BridgeTestServer(require_native_cli=True):
                    pass


class TestLocalMockHTTPServerSmoke(unittest.TestCase):
    def test_mock_server_json_redirect_and_404_negative_control(self) -> None:
        import urllib.error
        import urllib.request

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(_NoRedirect())
        with LocalMockHTTPServer() as mock:
            mock.add_route("/api/ping", status=200, body={"ok": True, "source": "mock"})
            mock.add_redirect("/redir", f"{mock.base_url}/api/ping", status=302)

            with opener.open(f"{mock.base_url}/api/ping", timeout=5) as r:
                self.assertEqual(r.status, 200)
                data = json.loads(r.read().decode("utf-8"))
                self.assertEqual(data, {"ok": True, "source": "mock"})

            with self.assertRaises(urllib.error.HTTPError) as cm_redir:
                opener.open(f"{mock.base_url}/redir", timeout=5)
            self.assertEqual(cm_redir.exception.code, 302)
            self.assertEqual(cm_redir.exception.headers.get("Location"), f"{mock.base_url}/api/ping")
            cm_redir.exception.close()

            with self.assertRaises(urllib.error.HTTPError) as cm_404:
                opener.open(f"{mock.base_url}/not-registered", timeout=5)
            self.assertEqual(cm_404.exception.code, 404)
            cm_404.exception.close()

            paths = [rec.path for rec in mock.requests]
            self.assertEqual(paths, ["/api/ping", "/redir", "/not-registered"])


class TestSecretsAndComplianceSmoke(unittest.TestCase):
    def test_dynamic_tokens_trigger_runtime_secret_scanner_and_keep_repo_clean(self) -> None:
        ensure_research_on_path()
        import ingest

        for kind in ("gemini", "openai", "github", "aws", "slack", "pem"):
            tok = make_dummy_token(kind)
            findings = ingest.scan_secret_content(f"KEY = {tok!r}")
            self.assertTrue(findings, f"Expected ingest.scan_secret_content to detect {kind!r}")

        self.assertEqual(dynamic_secret("pre_", "suf"), "pre_suf")

        tools_dir = str(REPO_ROOT / "tools")
        if tools_dir not in sys.path:
            sys.path.insert(0, tools_dir)
        import check_secrets

        for p in (REPO_ROOT / "tests" / "e2e_security").glob("*.py"):
            content = p.read_text(encoding="utf-8")
            for pat, label in check_secrets.SECRET_PATTERNS:
                self.assertEqual(
                    pat.findall(content),
                    [],
                    f"Static {label} literal found in {p}",
                )

    def test_claims_lint_passes_on_suite_and_rejects_banned_negative_control(self) -> None:
        e2e_dir = REPO_ROOT / "tests" / "e2e_security"
        assert_no_unfalsifiable_claims_compliant([e2e_dir])

        # Negative control: dynamically build a banned claim string in a temp file
        bad_line = "".join(("This module is ", "100%", " ", "secure."))
        with tempfile.TemporaryDirectory(prefix="pai_claims_neg_") as tmp:
            bad_file = Path(tmp) / "bad_doc.md"
            bad_file.write_text(bad_line + "\n", encoding="utf-8")
            with self.assertRaises(AssertionError):
                assert_no_unfalsifiable_claims_compliant([bad_file])


class TestUpdaterAndArchiveFixturesSmoke(unittest.TestCase):
    def test_signed_update_bundle_positive_and_negative_variants(self) -> None:
        ensure_research_on_path()
        from updater import UpdateRejected, Updater

        with tempfile.TemporaryDirectory(prefix="pai_bundle_smoke_") as tmp:
            base = Path(tmp)
            valid = build_signed_update_bundle(base / "valid", version="1.5.0", variant="valid")
            install_root = base / "install"
            u = Updater(str(valid["trust_dir"]), str(install_root), product="pai-desktop")
            verified = u.install(str(valid["release_dir"]))
            self.assertEqual(verified.version, "1.5.0")
            self.assertTrue(valid["zip_path"].is_file())

            neg_variants = (
                "tampered_file",
                "tampered_manifest",
                "wrong_key",
                "revoked_key",
                "unsigned",
                "rolled_back",
                "altered_constitution",
                "unlisted_file",
                "path_traversal_in_manifest",
            )
            for variant in neg_variants:
                b_dir = base / f"neg_{variant}"
                ver = "0.1.0" if variant == "rolled_back" else "1.6.0"
                bundle = build_signed_update_bundle(b_dir, version=ver, variant=variant)
                u_neg = Updater(str(bundle["trust_dir"]), str(install_root), product="pai-desktop")
                with self.assertRaises(
                    UpdateRejected,
                    msg=f"Expected UpdateRejected for variant={variant!r}",
                ):
                    u_neg.verify_release(str(bundle["release_dir"]))

            sym_bundle = build_signed_update_bundle(
                base / "sym_zip", version="1.7.0", variant="symlink_in_zip"
            )
            with zipfile.ZipFile(sym_bundle["zip_path"], "r") as zf:
                sym_infos = [zi for zi in zf.infolist() if zi.filename == "evil_link.txt"]
                self.assertEqual(len(sym_infos), 1)
                self.assertTrue(stat.S_ISLNK(sym_infos[0].external_attr >> 16))

    def test_archive_and_pdf_bomb_builders(self) -> None:
        import io

        zip_bytes = make_zip_bomb_bytes(uncompressed_size=11 * 1024 * 1024)
        self.assertLess(len(zip_bytes), 200 * 1024)
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            info = zf.getinfo("word/document.xml")
            self.assertGreater(info.file_size, 10 * 1024 * 1024)

        pdf_bytes = make_zlib_bomb_pdf_bytes(uncompressed_size=11 * 1024 * 1024)
        self.assertLess(len(pdf_bytes), 200 * 1024)
        start = pdf_bytes.index(b"stream\n") + len(b"stream\n")
        end = pdf_bytes.index(b"\nendstream")
        decompressed = zlib.decompress(pdf_bytes[start:end])
        self.assertGreater(len(decompressed), 10 * 1024 * 1024)

        sym_zip = make_symlink_zip_bytes(
            link_name="escape.txt",
            target_path="../../secret.txt",
            extra_files={"ok.txt": b"hello"},
        )
        with zipfile.ZipFile(io.BytesIO(sym_zip), "r") as zf:
            info = zf.getinfo("escape.txt")
            self.assertTrue(stat.S_ISLNK(info.external_attr >> 16))
            self.assertEqual(zf.read("ok.txt"), b"hello")


if __name__ == "__main__":
    unittest.main()
