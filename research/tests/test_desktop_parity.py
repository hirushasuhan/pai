"""Parity and regression tests for Milestone M1 (FINDING-16 & FINDING-17).

Verifies:
1. Canonical layout consolidation in ``desktop/`` and ``desktop/ui/`` with
   ``research/desktop/`` and top-level ``desktop/`` UI duplicates removed.
2. Minimal forwarding shims in ``research/desktop_launcher.py`` and
   ``research/apply_pending_update.py`` (AST bounds, sys.path safety,
   flat-install fallback, and negative control on missing targets).
3. ``desktop/bridge_server.py`` ``ui/``-first static asset and ``VERSION``
   resolution with flat-install fallback over live HTTP.
4. ``FINDING-17`` symbol fix in ``_handle_antigravity_run`` resolving
   ``run_antigravity_continuous_task`` (and absence of broken symbol).
"""

from __future__ import annotations

import ast
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

try:
    import _bootstrap  # noqa: F401
except ImportError:
    pass

RESEARCH_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = RESEARCH_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

import desktop.bridge_server as bridge_server
from desktop.bridge_server import PAIBridgeHandler, _resolve_ui_dir, get_pai_version
from research import antigravity_driver


class TestCanonicalLayout(unittest.TestCase):
    """Verify duplicate mirrors and top-level UI copies are removed (FINDING-16)."""

    def test_research_desktop_mirror_removed(self):
        self.assertFalse((REPO_ROOT / "research" / "desktop").exists())

    def test_top_level_desktop_ui_duplicates_removed(self):
        for fname in ("app.js", "index.html", "style.css", "manifest.json", "VERSION"):
            self.assertFalse(
                (REPO_ROOT / "desktop" / fname).exists(),
                f"Stale duplicate desktop/{fname} should be removed",
            )

    def test_canonical_desktop_and_ui_files_exist(self):
        expected = [
            REPO_ROOT / "desktop" / "bridge_server.py",
            REPO_ROOT / "desktop" / "desktop_launcher.py",
            REPO_ROOT / "desktop" / "apply_pending_update.py",
            REPO_ROOT / "desktop" / "launch_desktop.bat",
            REPO_ROOT / "desktop" / "bin" / "pai_folder_picker.cs",
            REPO_ROOT / "desktop" / "ui" / "index.html",
            REPO_ROOT / "desktop" / "ui" / "app.js",
            REPO_ROOT / "desktop" / "ui" / "style.css",
            REPO_ROOT / "desktop" / "ui" / "manifest.json",
            REPO_ROOT / "desktop" / "ui" / "VERSION",
            REPO_ROOT / "desktop" / "ui" / "assets" / "pai.ico",
            REPO_ROOT / "desktop" / "ui" / "assets" / "pai-logo-512.png",
        ]
        for path in expected:
            self.assertTrue(path.is_file(), f"Missing canonical file: {path}")

    def test_no_stale_research_desktop_references_in_callers(self):
        callers = [
            REPO_ROOT / "desktop" / "bridge_server.py",
            REPO_ROOT / "desktop" / "desktop_launcher.py",
            REPO_ROOT / "desktop" / "apply_pending_update.py",
            REPO_ROOT / "desktop" / "src-tauri" / "src" / "main.rs",
            REPO_ROOT / "research" / "pai.py",
            REPO_ROOT / "research" / "shell.py",
            REPO_ROOT / "tools" / "package_release.py",
            REPO_ROOT / "tools" / "update_installed_desktop_pai.py",
            REPO_ROOT / "tools" / "create_desktop_shortcut.py",
        ]
        stale_pattern = re.compile(r"research[./\\]desktop(?![_a-zA-Z0-9])")
        for fpath in callers:
            text = fpath.read_text(encoding="utf-8")
            match = stale_pattern.search(text)
            self.assertIsNone(
                match,
                f"Stale reference {match.group(0)!r} found in {fpath.relative_to(REPO_ROOT)}" if match else "",
            )


class TestForwardingShims(unittest.TestCase):
    """Verify research/desktop_launcher.py and research/apply_pending_update.py shims."""

    def test_shims_are_minimal_without_duplicated_logic(self):
        for shim_name in ("desktop_launcher.py", "apply_pending_update.py"):
            shim_path = RESEARCH_DIR / shim_name
            self.assertTrue(shim_path.is_file(), f"Missing shim: {shim_path}")
            source = shim_path.read_text(encoding="utf-8")
            lines = source.splitlines()
            self.assertLessEqual(len(lines), 60, f"Shim {shim_name} exceeded 60 lines ({len(lines)})")

            tree = ast.parse(source, filename=shim_name)
            defs = [
                n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            ]
            self.assertEqual(defs, [], f"Shim {shim_name} must not duplicate function/class definitions")
            for forbidden in ("ctypes", "ThreadingHTTPServer", "zipfile", "taskkill"):
                self.assertNotIn(forbidden, source, f"Shim {shim_name} contains {forbidden!r}")

    def _run_py(self, code: str, cwd: Path, env_overrides: dict | None = None) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_desktop_launcher_shim_reexports_from_repo_and_research_syspath(self):
        code_repo = (
            "import desktop.desktop_launcher as c, research.desktop_launcher as s\n"
            "names = ['BRIDGE_URL', 'kill_stale_port_8765', 'is_bridge_server_running', "
            "'start_bridge_server', 'find_native_desktop_executable', "
            "'find_browser_app_executable', 'launch_desktop_app']\n"
            "for n in names:\n"
            "    assert getattr(s, n) is getattr(c, n), n\n"
            "print('OK')\n"
        )
        res_repo = self._run_py(code_repo, cwd=REPO_ROOT)
        self.assertEqual(res_repo.returncode, 0, res_repo.stderr)
        self.assertIn("OK", res_repo.stdout)

        code_research = (
            "import sys\n"
            "from pathlib import Path\n"
            f"repo = Path({str(REPO_ROOT)!r}).resolve()\n"
            "sys.path[:] = [p for p in sys.path if Path(p or '.').resolve() != repo]\n"
            "import desktop_launcher as s\n"
            "assert s.launch_desktop_app.__module__ == 'desktop.desktop_launcher', s.launch_desktop_app.__module__\n"
            "print('OK')\n"
        )
        res_research = self._run_py(code_research, cwd=RESEARCH_DIR)
        self.assertEqual(res_research.returncode, 0, res_research.stderr)
        self.assertIn("OK", res_research.stdout)

    def test_apply_pending_update_shim_reexports_from_repo_and_research_syspath(self):
        code_repo = (
            "import desktop.apply_pending_update as c, research.apply_pending_update as s\n"
            "for n in ('get_pai_install_dir', 'check_and_apply_pending', 'apply_and_restart'):\n"
            "    assert getattr(s, n) is getattr(c, n), n\n"
            "print('OK')\n"
        )
        res_repo = self._run_py(code_repo, cwd=REPO_ROOT)
        self.assertEqual(res_repo.returncode, 0, res_repo.stderr)
        self.assertIn("OK", res_repo.stdout)

        code_research = (
            "import sys\n"
            "from pathlib import Path\n"
            f"repo = Path({str(REPO_ROOT)!r}).resolve()\n"
            "sys.path[:] = [p for p in sys.path if Path(p or '.').resolve() != repo]\n"
            "import apply_pending_update as s\n"
            "assert s.check_and_apply_pending.__module__ == 'desktop.apply_pending_update', s.check_and_apply_pending.__module__\n"
            "print('OK')\n"
        )
        res_research = self._run_py(code_research, cwd=RESEARCH_DIR)
        self.assertEqual(res_research.returncode, 0, res_research.stderr)
        self.assertIn("OK", res_research.stdout)

    def test_shims_flat_install_fallback_and_negative_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            res_dir = root / "research"
            res_dir.mkdir(parents=True)
            shutil.copy2(RESEARCH_DIR / "desktop_launcher.py", res_dir / "desktop_launcher.py")

            # Negative control: without desktop/ or flat desktop_launcher.py, import must fail
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            neg = subprocess.run(
                [sys.executable, "-c", "import desktop_launcher"],
                cwd=str(res_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertNotEqual(neg.returncode, 0)

            # Positive flat-install fallback: root/desktop_launcher.py present (no desktop/ pkg)
            (root / "desktop_launcher.py").write_text(
                "BRIDGE_URL = 'http://127.0.0.1:8765'\n"
                "def kill_stale_port_8765(): pass\n"
                "def is_bridge_server_running(): return False\n"
                "def start_bridge_server(): return (False, None)\n"
                "def find_native_desktop_executable(): return None\n"
                "def find_browser_app_executable(): return None\n"
                "def launch_desktop_app(wait_for_exit=False): return (True, 'flat-ok')\n",
                encoding="utf-8",
            )
            pos = subprocess.run(
                [sys.executable, "-c", "import desktop_launcher; ok, m = desktop_launcher.launch_desktop_app(); assert ok and m == 'flat-ok'; print('FLAT_OK')"],
                cwd=str(res_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(pos.returncode, 0, pos.stderr)
            self.assertIn("FLAT_OK", pos.stdout)

    def test_apply_pending_update_main_entrypoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            env["LOCALAPPDATA"] = tmp
            res = subprocess.run(
                [sys.executable, "-m", "research.apply_pending_update"],
                cwd=str(REPO_ROOT),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stderr)


class TestBridgeStaticUIResolution(unittest.TestCase):
    """Verify ui/-first static asset and VERSION resolution with flat fallback."""

    def test_resolve_ui_dir_prefers_ui_subdir_and_falls_back_to_flat_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            # Case 1: flat layout (no ui/)
            (base / "index.html").write_text("FLAT_DIR", encoding="utf-8")
            self.assertEqual(_resolve_ui_dir(base), base)

            # Case 2: ui/ present alongside flat index.html -> prefers ui/
            ui_dir = base / "ui"
            ui_dir.mkdir()
            (ui_dir / "index.html").write_text("UI_DIR", encoding="utf-8")
            self.assertEqual(_resolve_ui_dir(base), ui_dir)

    def test_live_http_serves_ui_subdir_and_flat_fallback(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), PAIBridgeHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close()))

        # 1. Canonical repo ui/ serving
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), (REPO_ROOT / "desktop" / "ui" / "index.html").read_bytes())

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/app.js", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), (REPO_ROOT / "desktop" / "ui" / "app.js").read_bytes())

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/manifest.json", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), (REPO_ROOT / "desktop" / "ui" / "manifest.json").read_bytes())

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/favicon.ico", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.read(), (REPO_ROOT / "desktop" / "ui" / "assets" / "pai.ico").read_bytes())

        # Negative control: nonexistent static asset must return 404
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/assets/does_not_exist.png", timeout=5)
        self.assertEqual(ctx.exception.code, 404)
        ctx.exception.close()

        # 2. Flat install layout fallback
        with tempfile.TemporaryDirectory() as tmp:
            flat_dir = Path(tmp)
            (flat_dir / "index.html").write_text("FLAT_INDEX", encoding="utf-8")
            (flat_dir / "app.js").write_text("// FLAT_JS", encoding="utf-8")
            (flat_dir / "style.css").write_text("/* FLAT_CSS */", encoding="utf-8")
            (flat_dir / "manifest.json").write_text('{"name":"flat"}', encoding="utf-8")
            (flat_dir / "assets").mkdir()
            (flat_dir / "assets" / "pai.ico").write_bytes(b"ICO_FLAT")

            with patch.object(bridge_server, "__file__", str(flat_dir / "bridge_server.py")):
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.read(), b"FLAT_INDEX")
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/app.js", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.read(), b"// FLAT_JS")
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/favicon.ico", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.read(), b"ICO_FLAT")

    def test_get_pai_version_reads_ui_version(self):
        expected_v = (REPO_ROOT / "desktop" / "ui" / "VERSION").read_text(encoding="utf-8").strip()
        with patch.dict(os.environ, {"LOCALAPPDATA": ""}):
            self.assertEqual(get_pai_version(), expected_v)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            (tmp_dir / "VERSION").write_text("9.0.0-flat", encoding="utf-8")
            (tmp_dir / "ui").mkdir()
            (tmp_dir / "ui" / "VERSION").write_text("9.1.0-ui", encoding="utf-8")
            with patch.dict(os.environ, {"LOCALAPPDATA": ""}):
                with patch.object(bridge_server, "__file__", str(tmp_dir / "bridge_server.py")):
                    self.assertEqual(get_pai_version(), "9.1.0-ui")


class TestAntigravityRunSymbol(unittest.TestCase):
    """Verify FINDING-17 fix in _handle_antigravity_run."""

    def test_bridge_does_not_reference_broken_symbol(self):
        bridge_text = (REPO_ROOT / "desktop" / "bridge_server.py").read_text(encoding="utf-8")
        self.assertNotIn("run_antigravity_continuous_agent", bridge_text)
        self.assertIn("run_antigravity_continuous_task", bridge_text)

    def test_negative_broken_symbol_absent_in_driver(self):
        self.assertFalse(hasattr(antigravity_driver, "run_antigravity_continuous_agent"))
        self.assertTrue(callable(getattr(antigravity_driver, "run_antigravity_continuous_task", None)))

    def test_handle_antigravity_run_non_team_calls_continuous_task(self):
        handler = PAIBridgeHandler.__new__(PAIBridgeHandler)
        handler.wfile = io.BytesIO()
        handler.headers = {}
        sent = []
        handler._send_json = lambda data, status=200: sent.append((status, data))

        # Negative control: empty task returns 400 and does not call driver
        with patch("research.antigravity_driver.run_antigravity_continuous_task") as mock_neg:
            handler._handle_antigravity_run({"task": "   ", "use_team": False})
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0][0], 400)
            mock_neg.assert_not_called()

        sent.clear()
        called = threading.Event()

        def _fake_task(*args, **kwargs):
            called.set()
            return (True, "ok")

        with patch("desktop.bridge_server.ensure_ollama_server"), \
             patch("desktop.bridge_server.append_log"), \
             patch("research.antigravity_driver.run_antigravity_continuous_task", side_effect=_fake_task) as mock_task:
            handler._handle_antigravity_run({"task": "Build a demo app", "use_team": False})
            self.assertTrue(called.wait(timeout=3.0), "Background task did not invoke run_antigravity_continuous_task")

        mock_task.assert_called_once_with(
            "Build a demo app",
            max_turns=6,
            open_browser=True,
            base_dir=None,
        )
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0][0], 200)
        self.assertTrue(sent[0][1].get("success"))


if __name__ == "__main__":
    unittest.main()
