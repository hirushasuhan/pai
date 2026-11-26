"""
Negative-control and containment tests for Milestone M3:
  - FINDING-04: research/multi_agent.py (path containment, symlink/junction checks, ast_guard,
    secret scanning, ToolBroker taint/confirmation, context wrapping, URL validation)
  - FINDING-05: research/mcp_client.py (StdioMCPTransport env scrubbing, explicit secret blocking,
    command/unpinned-npx validation, ToolBroker/confirmation gating in registry & call_tool)
  - FINDING-06: research/antigravity_driver.py (removal of --dangerously-skip-permissions,
    ToolBroker/taint fail-closed gating, audit_workspace_files traversal & symlink containment)
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

try:
    import _bootstrap  # noqa: F401
except ImportError:
    import tests._bootstrap  # noqa: F401

try:
    from research import antigravity_driver, capabilities, ingest, mcp_client, multi_agent
except ModuleNotFoundError:
    import antigravity_driver
    import capabilities
    import ingest
    import mcp_client
    import multi_agent


def _rt_sk() -> str:
    return "sk-" + "proj-" + ("A" * 34)


def _rt_aiza() -> str:
    return "AIza" + "Sy" + ("B" * 33)


def _rt_gsk() -> str:
    return "gsk_" + ("C" * 44)


def _rt_ghp() -> str:
    return "ghp_" + ("D" * 36)


class TestMultiAgentContainment(unittest.TestCase):
    """Negative controls and governance checks for FINDING-04 (research/multi_agent.py)."""

    def test_safe_sync_file_rejects_traversal_and_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            proj = root / "proj"
            proj.mkdir()
            outside_target = root / "escape.py"

            team = multi_agent.MultiAgentTeam(output_fn=lambda _: None)
            bad_names = [
                "",
                "   ",
                "..",
                ".",
                "../escape.py",
                "..\\escape.py",
                "sub/../../escape.py",
                "/tmp/evil.py",
                "\\Windows\\evil.py",
                "C:\\Windows\\evil.py",
                "\\\\server\\share\\evil.py",
                "sub/\x00evil.py",
                " bad.py",
            ]
            for fname in bad_names:
                ok, msg = team._safe_sync_file(proj, fname, "x = 1\n")
                self.assertFalse(ok, f"Expected rejection for {fname!r}, got: {msg}")
            self.assertFalse(outside_target.exists())

    def test_safe_sync_file_rejects_ads_device_secret_and_junk_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            proj.mkdir()
            team = multi_agent.MultiAgentTeam(output_fn=lambda _: None)

            bad_names = [
                "script.js:$DATA",
                "CON.py",
                "NUL.js",
                "LPT1.txt",
                ".env",
                ".env.local",
                "credentials.json",
                "secrets.yaml",
                ".git/hooks/post-checkout",
                ".aws/credentials",
                "script.js.bak",
                "script.js.candidate",
            ]
            for fname in bad_names:
                ok, msg = team._safe_sync_file(proj, fname, "console.log('hi');\n")
                self.assertFalse(ok, f"Expected rejection for {fname!r}, got: {msg}")
            self.assertEqual(list(proj.rglob("*")), [])

    def test_safe_sync_file_rejects_symlink_and_junction_targets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            proj = root / "proj"
            proj.mkdir()
            outside = root / "outside.js"
            outside.write_text("original", encoding="utf-8")

            team = multi_agent.MultiAgentTeam(output_fn=lambda _: None)

            # 1. Symlinked destination, .bak, .candidate, or parent/project root
            link_dest = proj / "link.js"
            try:
                os.symlink(outside, link_dest)
                real_symlink_ok = True
            except OSError:
                real_symlink_ok = False

            if real_symlink_ok:
                ok, _ = team._safe_sync_file(proj, "link.js", "console.log('pwn');")
                self.assertFalse(ok)
                self.assertEqual(outside.read_text(encoding="utf-8"), "original")
            else:
                target_norm = os.path.normpath(str(link_dest))
                with patch.object(
                    multi_agent.ingest,
                    "_is_symlink_or_reparse",
                    side_effect=lambda p: os.path.normpath(p) == target_norm,
                ):
                    ok, msg = team._safe_sync_file(proj, "link.js", "console.log('pwn');")
                    self.assertFalse(ok, msg)

            # Symlinked .bak target must also be rejected
            (proj / "real.js").write_text("const a = 1;", encoding="utf-8")
            bak_norm = os.path.normpath(str(proj / "real.js.bak"))
            with patch.object(
                multi_agent.ingest,
                "_is_symlink_or_reparse",
                side_effect=lambda p: os.path.normpath(p) == bak_norm,
            ):
                ok_bak, _ = team._safe_sync_file(proj, "real.js", "const a = 2;")
                self.assertFalse(ok_bak)
                self.assertEqual((proj / "real.js").read_text(encoding="utf-8"), "const a = 1;")

            # Symlinked project root must be rejected
            proj_norm = os.path.normpath(str(proj))
            with patch.object(
                multi_agent.ingest,
                "_is_symlink_or_reparse",
                side_effect=lambda p: os.path.normpath(p) == proj_norm,
            ):
                ok_root, _ = team._safe_sync_file(proj, "safe.js", "const ok = 1;")
                self.assertFalse(ok_root)

            # 2. Windows directory junction test (skip only if mklink /J is unpermitted)
            if sys.platform == "win32":
                outside_dir = root / "outside_dir"
                outside_dir.mkdir()
                junc_dir = proj / "sub_junc"
                r = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(junc_dir), str(outside_dir)],
                    capture_output=True,
                    text=True,
                )
                if r.returncode != 0:
                    self.skipTest(f"mklink /J not permitted in current environment: {r.stderr}")
                try:
                    ok_junc, msg_junc = team._safe_sync_file(proj, "sub_junc/evil.js", "console.log(1);")
                    self.assertFalse(ok_junc, msg_junc)
                    self.assertFalse((outside_dir / "evil.js").exists())
                finally:
                    try:
                        os.rmdir(junc_dir)
                    except OSError:
                        pass

    def test_safe_sync_file_ast_guard_blocks_unsafe_python(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td)
            # Pre-seed a substantial .py file (>3000 bytes) to ensure ast_guard runs BEFORE .candidate write
            big_py = proj / "mod.py"
            big_py.write_text("# valid module\n" + ("x = 1\n" * 600), encoding="utf-8")

            team = multi_agent.MultiAgentTeam(output_fn=lambda _: None)
            unsafe_samples = [
                "import os\nos.system('calc')\n",
                "eval('1 + 1')\n",
                "open('secret.txt', 'r')\n",
                "x = ().__class__.__mro__\n",
                "def broken(:\n    pass\n",
            ]
            for bad_py in unsafe_samples:
                ok, msg = team._safe_sync_file(proj, "mod.py", bad_py, verdict_pass=False)
                self.assertFalse(ok, f"Expected ast_guard rejection for {bad_py!r}, got: {msg}")
                self.assertFalse((proj / "mod.py.candidate").exists())

            ok_good, msg_good = team._safe_sync_file(
                proj,
                "pure.py",
                "import math\n\ndef area(r: float) -> float:\n    return math.pi * r * r\n",
            )
            self.assertTrue(ok_good, msg_good)
            self.assertTrue((proj / "pure.py").is_file())

    def test_safe_sync_file_rejects_embedded_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td)
            team = multi_agent.MultiAgentTeam(output_fn=lambda _: None)

            ok1, _ = team._safe_sync_file(proj, "app.py", f'API_KEY = "{_rt_sk()}"\n')
            self.assertFalse(ok1)
            self.assertFalse((proj / "app.py").exists())

            ok2, _ = team._safe_sync_file(proj, "script.js", f'const k = "{_rt_aiza()}";\n')
            self.assertFalse(ok2)
            self.assertFalse((proj / "script.js").exists())

    def test_safe_sync_file_tool_broker_taint_and_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td)
            target = proj / "script.js"
            target.write_text("const v = 0;", encoding="utf-8")

            # 1. Tainted without confirmation -> denied, file untouched, audit chain intact
            broker_no_confirm = multi_agent.make_project_sync_broker(proj, confirm=None)
            team_tainted = multi_agent.MultiAgentTeam(output_fn=lambda _: None, broker=broker_no_confirm, tainted=True)
            ok, _ = team_tainted._safe_sync_file(proj, "script.js", "const v = 1;")
            self.assertFalse(ok)
            self.assertEqual(target.read_text(encoding="utf-8"), "const v = 0;")
            self.assertFalse(broker_no_confirm.audit[-1].allowed)
            self.assertTrue(broker_no_confirm.verify_audit_chain())

            # 2. Tainted with confirm=False -> denied
            broker_deny = multi_agent.make_project_sync_broker(proj, confirm=lambda req: False)
            team_deny = multi_agent.MultiAgentTeam(output_fn=lambda _: None, broker=broker_deny, tainted=True)
            ok_deny, _ = team_deny._safe_sync_file(proj, "script.js", "const v = 2;")
            self.assertFalse(ok_deny)
            self.assertEqual(target.read_text(encoding="utf-8"), "const v = 0;")

            # 3. Tainted with confirm=True -> allowed and audited
            broker_allow = multi_agent.make_project_sync_broker(proj, confirm=lambda req: True)
            team_allow = multi_agent.MultiAgentTeam(output_fn=lambda _: None, broker=broker_allow, tainted=True)
            ok_allow, _ = team_allow._safe_sync_file(proj, "script.js", "const v = 3;")
            self.assertTrue(ok_allow)
            self.assertEqual(target.read_text(encoding="utf-8"), "const v = 3;")
            self.assertTrue(broker_allow.audit[-1].confirmed)

            # 4. Untainted default MultiAgentTeam inside project_dir -> succeeds
            team_default = multi_agent.MultiAgentTeam(output_fn=lambda _: None)
            ok_def, _ = team_default._safe_sync_file(proj, "script.js", "const v = 4;")
            self.assertTrue(ok_def)
            self.assertEqual(target.read_text(encoding="utf-8"), "const v = 4;")

    def test_collaborative_and_debug_workflows_reject_traversal_code_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            proj = root / "proj"
            proj.mkdir()

            def mock_evil_exec(argv):
                prompt_text = " ".join(argv).lower()
                if "qa_engineer" in prompt_text:
                    print("VERDICT: PASS - Looks okay.")
                    return 0
                if "debugger" in prompt_text:
                    print(
                        "H1: Bug\n"
                        "### File: ../escape_dbg.py\n"
                        "```python\n"
                        "def leaked_escape():\n"
                        "    return 'must not write outside'\n"
                        "```\n"
                    )
                    return 0
                print(
                    "### File: ../../pwned.py\n"
                    "```python\n"
                    "def escaped_write():\n"
                    "    return 'traversal payload must not fall back to main.py'\n"
                    "```\n\n"
                    "### File: evil.py\n"
                    "```python\n"
                    "import subprocess\n"
                    "def bad_call():\n"
                    "    return subprocess.run(['echo', 'pwn'])\n"
                    "```\n"
                )
                return 0

            team = multi_agent.MultiAgentTeam(executor=mock_evil_exec, output_fn=lambda _: None)
            res = team.run_collaborative_workflow("Create safe helper", active_project_dir=proj)
            self.assertNotIn("../../pwned.py", res.get("code_updates", {}))
            self.assertNotIn("main.py", res.get("code_updates", {}))
            self.assertNotIn("evil.py", res.get("code_updates", {}))
            self.assertIn("../../pwned.py", res.get("sync_errors", {}))
            self.assertIn("evil.py", res.get("sync_errors", {}))
            self.assertFalse((root / "pwned.py").exists())
            self.assertFalse((proj / "main.py").exists())
            self.assertFalse((proj / "evil.py").exists())

            dbg_res = team.run_debug_workflow("Fix issue", project_dir=proj)
            self.assertNotIn("../escape_dbg.py", dbg_res.get("code_updates", {}))
            self.assertIn("../escape_dbg.py", dbg_res.get("sync_errors", {}))
            self.assertFalse((root / "escape_dbg.py").exists())

    def test_collect_codebase_context_and_exploration_filter_secrets_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            proj = root / "proj"
            proj.mkdir()

            outside_secret = root / "outside_secret.py"
            outside_secret.write_text("def outside_symbol():\n    return 'OUTSIDE_LEAK_MARKER'\n", encoding="utf-8")

            (proj / ".env").write_text(f"API_KEY={_rt_sk()}\n", encoding="utf-8")
            (proj / "credentials.json").write_text('{"secret": "CREDENTIALS_JSON_MARKER"}', encoding="utf-8")
            (proj / "app.py").write_text(f'GOOGLE_KEY = "{_rt_aiza()}"\nprint("APP_LEAK_MARKER")\n', encoding="utf-8")
            (proj / "main.py").write_text("def legitimate_symbol():\n    return 'SAFE_SYMBOL_OK'\n", encoding="utf-8")

            link_py = proj / "linked.py"
            try:
                os.symlink(outside_secret, link_py)
                symlink_created = True
            except OSError:
                symlink_created = False

            def mock_exp_exec(argv):
                print("Explored workspace symbols successfully.")
                return 0

            team = multi_agent.MultiAgentTeam(executor=mock_exp_exec, output_fn=lambda _: None)

            if symlink_created:
                ctx = team._collect_codebase_context(proj)
                exp = team.run_code_exploration("legitimate_symbol outside_symbol APP_LEAK_MARKER", project_dir=proj)
            else:
                # Plant a regular copy and simulate symlink/reparse detection when OS lacks symlink privilege
                link_py.write_text(outside_secret.read_text(encoding="utf-8"), encoding="utf-8")
                link_norm = os.path.normpath(str(link_py))
                with patch.object(
                    multi_agent.ingest,
                    "_is_symlink_or_reparse",
                    side_effect=lambda p: os.path.normpath(p) == link_norm,
                ):
                    ctx = team._collect_codebase_context(proj)
                    exp = team.run_code_exploration("legitimate_symbol outside_symbol APP_LEAK_MARKER", project_dir=proj)

            self.assertRegex(ctx, r"--- UNTRUSTED DATA BEGIN \[[0-9a-f]+\] ---")
            self.assertRegex(ctx, r"--- UNTRUSTED DATA END \[[0-9a-f]+\] ---")
            self.assertIn("SAFE_SYMBOL_OK", ctx)
            self.assertNotIn("CREDENTIALS_JSON_MARKER", ctx)
            self.assertNotIn("APP_LEAK_MARKER", ctx)
            self.assertNotIn("OUTSIDE_LEAK_MARKER", ctx)
            self.assertNotIn(_rt_sk(), ctx)
            self.assertNotIn(_rt_aiza(), ctx)

            scanned = exp.get("scanned_files", [])
            self.assertIn("main.py", scanned)
            self.assertNotIn(".env", scanned)
            self.assertNotIn("credentials.json", scanned)
            self.assertNotIn("app.py", scanned)
            self.assertNotIn("linked.py", scanned)

    def test_discover_available_models_rejects_disallowed_urls(self) -> None:
        with patch("urllib.request.urlopen") as mock_open:
            models = multi_agent.discover_available_models("file:///etc/passwd")
            self.assertEqual(models, [])
            mock_open.assert_not_called()


class TestMCPContainment(unittest.TestCase):
    """Negative controls and governance checks for FINDING-05 (research/mcp_client.py)."""

    def tearDown(self) -> None:
        mcp_client.MCPRegistry.clear()

    def test_stdio_mcp_transport_scrubs_secret_env_vars(self) -> None:
        secret_env = {
            "GEMINI_API_KEY": _rt_aiza(),
            "OPENAI_API_KEY": _rt_sk(),
            "GROQ_API_KEY": _rt_gsk(),
            "ANTHROPIC_API_KEY": _rt_sk(),
            "PAI_BRIDGE_TOKEN": "bridge-secret-token-value",
            "AWS_SECRET_ACCESS_KEY": "aws-secret-value-123456",
            "GITHUB_TOKEN": _rt_ghp(),
            "HF_TOKEN": "hf_" + ("E" * 34),
        }
        child_script = (
            "import json, os, sys; "
            "req = json.loads(sys.stdin.readline()); "
            "sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': dict(os.environ)}) + '\\n'); "
            "sys.stdout.flush()"
        )
        with patch.dict(os.environ, secret_env, clear=False):
            transport = mcp_client.StdioMCPTransport([sys.executable, "-c", child_script])
            try:
                child_env = transport.send_request("env_dump")
            finally:
                transport.close()

        child_keys_upper = {k.upper() for k in child_env}
        for blocked_key in secret_env:
            self.assertNotIn(blocked_key.upper(), child_keys_upper)
        self.assertIn("PATH", child_keys_upper)

    def test_stdio_mcp_transport_rejects_explicit_secret_env_vars(self) -> None:
        with patch("subprocess.Popen") as mock_popen:
            with self.assertRaises(ValueError):
                mcp_client.StdioMCPTransport(
                    [sys.executable, "-V"],
                    env={"OPENAI_API_KEY": _rt_sk()},
                )
            with self.assertRaises(ValueError):
                mcp_client.StdioMCPTransport(
                    [sys.executable, "-V"],
                    env={"CUSTOM_TOOL_CONFIG": _rt_sk()},
                )
            with self.assertRaises(ValueError):
                mcp_client.StdioMCPTransport(
                    [sys.executable, "-V"],
                    env={"BAD\nKEY": "value"},
                )
            mock_popen.assert_not_called()

    def test_stdio_mcp_transport_rejects_unpinned_npx_and_shells(self) -> None:
        bad_commands = [
            [],
            ["cmd.exe", "/c", "echo hi"],
            ["powershell.exe", "-Command", "Get-Process"],
            ["sh", "-c", "id"],
            ["node", "server.js", "&&", "whoami"],
            ["npx", "-y", "@modelcontextprotocol/server-filesystem", "./"],
            ["npx", "--yes", "@modelcontextprotocol/server-filesystem@1.0.0"],
            ["npx", "@modelcontextprotocol/server-filesystem@latest"],
            ["npx", "@modelcontextprotocol/server-filesystem"],
        ]
        with patch("subprocess.Popen") as mock_popen:
            for cmd in bad_commands:
                with self.assertRaises(ValueError, msg=f"Expected rejection for {cmd!r}"):
                    mcp_client.StdioMCPTransport(cmd)
            with self.assertRaises(capabilities.PermissionDenied):
                mcp_client.StdioMCPTransport(
                    ["npx", "-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
                    allow_unpinned=True,
                )
            mock_popen.assert_not_called()

        # Pinned npm spec passes command validation
        pinned = mcp_client.validate_mcp_command(
            ["npx", "@modelcontextprotocol/server-filesystem@1.2.3", "./"]
        )
        self.assertEqual(pinned[0], "npx")

    def test_mcp_registry_and_call_tool_fail_closed_without_confirmation(self) -> None:
        fake_transport = MagicMock(spec=mcp_client.MCPTransport)
        fake_transport.send_request.return_value = {"content": [{"text": "ok"}], "isError": False}
        client = mcp_client.MCPClient(name="test_srv", transport=fake_transport)
        client.is_initialized = True

        # 1. Missing broker/confirm fails closed
        with self.assertRaises(capabilities.PermissionDenied):
            mcp_client.MCPRegistry.register_server("test_srv", client)
        self.assertIsNone(mcp_client.MCPRegistry.get_server("test_srv"))

        # 2. Declined confirmation fails closed
        with self.assertRaises(capabilities.PermissionDenied):
            mcp_client.MCPRegistry.register_server("test_srv", client, confirm=lambda req: False)
        self.assertIsNone(mcp_client.MCPRegistry.get_server("test_srv"))

        # 3. Ungranted broker fails closed
        ungranted = mcp_client.make_mcp_broker(confirm=lambda req: True, allow_register=False)
        with self.assertRaises(capabilities.PermissionDenied):
            mcp_client.MCPRegistry.register_server("test_srv", client, broker=ungranted)
        self.assertIsNone(mcp_client.MCPRegistry.get_server("test_srv"))

        # 4. Granted + confirmed broker registers cleanly and logs hash-chained audit
        granted = mcp_client.make_mcp_broker(confirm=lambda req: True)
        mcp_client.MCPRegistry.register_server("test_srv", client, broker=granted)
        self.assertIs(mcp_client.MCPRegistry.get_server("test_srv"), client)
        self.assertTrue(granted.verify_audit_chain())
        self.assertTrue(granted.audit[-1].confirmed)

        # 5. call_tool gated by ToolBroker denies when unconfirmed
        deny_broker = mcp_client.make_mcp_broker(confirm=lambda req: False)
        with self.assertRaises(capabilities.PermissionDenied):
            client.call_tool("read_file", {"path": "a.txt"}, broker=deny_broker)
        fake_transport.send_request.assert_not_called()


class TestAntigravityContainment(unittest.TestCase):
    """Negative controls and governance checks for FINDING-06 (research/antigravity_driver.py)."""

    def test_unattended_antigravity_never_passes_dangerously_skip_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fake_bin = base / "fake_agy.exe"
            fake_bin.write_text("dummy", encoding="utf-8")
            fake_ide = base / "fake_ide.exe"
            fake_ide.write_text("dummy", encoding="utf-8")

            captured_cmds = []
            turn_count = 0

            def fake_run(cmd, *args, **kwargs):
                nonlocal turn_count
                if cmd and cmd[0] != str(fake_bin):
                    res = MagicMock()
                    res.returncode = 0
                    res.stdout = ""
                    res.stderr = ""
                    return res
                turn_count += 1
                captured_cmds.append(list(cmd))
                target_p = Path(cmd[2])
                res = MagicMock()
                res.returncode = 0
                res.stdout = "ok"
                if turn_count >= 1:
                    (target_p / "script.js").write_text(
                        "function tick() { requestAnimationFrame(tick); }\n" + ("// logic\n" * 30),
                        encoding="utf-8",
                    )
                    (target_p / "style.css").write_text("body { margin: 0; background: #000; }\n" * 5, encoding="utf-8")
                    (target_p / "index.html").write_text(
                        "<!DOCTYPE html><html><head><link rel='stylesheet' href='style.css'></head>"
                        "<body><script src='script.js'></script>" + ("<!-- pad -->" * 100) + "</body></html>",
                        encoding="utf-8",
                    )
                return res

            with patch.object(antigravity_driver, "find_antigravity_binaries", return_value=(str(fake_bin), str(fake_ide))), \
                 patch.object(antigravity_driver, "launch_antigravity_ide", return_value=(True, "ok")), \
                 patch("subprocess.run", side_effect=fake_run):
                ok, msg = antigravity_driver.run_antigravity_continuous_task(
                    "Build canvas game",
                    stream=io.StringIO(),
                    max_turns=3,
                    open_browser=False,
                    base_dir=base,
                )
            self.assertTrue(ok, msg)
            self.assertGreaterEqual(len(captured_cmds), 2)
            for cmd in captured_cmds:
                self.assertNotIn("--dangerously-skip-permissions", cmd)
                self.assertEqual(cmd[0], str(fake_bin))
                self.assertEqual(cmd[1], "--add-dir")

    def test_antigravity_tool_broker_and_taint_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            outside = base / "other"
            outside.mkdir()
            ws_root = base / "workspaces"
            ws_root.mkdir()

            with patch("subprocess.run") as mock_run:
                # 1. Broker with confirm=None -> PermissionDenied
                b_none = antigravity_driver.make_antigravity_broker(ws_root, confirm=None)
                with self.assertRaises(capabilities.PermissionDenied):
                    antigravity_driver.run_antigravity_continuous_task(
                        "Build game", base_dir=ws_root, broker=b_none, open_browser=False
                    )

                # 2. Broker with confirm=False -> PermissionDenied
                b_no = antigravity_driver.make_antigravity_broker(ws_root, confirm=lambda req: False)
                with self.assertRaises(capabilities.PermissionDenied):
                    antigravity_driver.run_antigravity_continuous_task(
                        "Build game", base_dir=ws_root, broker=b_no, open_browser=False
                    )

                # 3. Broker scoped to wrong root -> PermissionDenied
                b_wrong = antigravity_driver.make_antigravity_broker(outside, confirm=lambda req: True)
                with self.assertRaises(capabilities.PermissionDenied):
                    antigravity_driver.run_antigravity_continuous_task(
                        "Build game", base_dir=ws_root, broker=b_wrong, open_browser=False
                    )

                # 4. Tainted without confirm -> PermissionDenied
                with self.assertRaises(capabilities.PermissionDenied):
                    antigravity_driver.run_antigravity_continuous_task(
                        "Build game", base_dir=ws_root, tainted=True, open_browser=False
                    )

                # 5. require_broker=True without broker/confirm -> PermissionDenied
                with self.assertRaises(capabilities.PermissionDenied):
                    antigravity_driver.run_antigravity_continuous_task(
                        "Build game", base_dir=ws_root, require_broker=True, open_browser=False
                    )

                mock_run.assert_not_called()
                self.assertEqual(list(ws_root.iterdir()), [])

    def test_audit_workspace_files_blocks_path_traversal_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()

            outside_js = root / "outside.js"
            outside_js.write_text("console.log('outside js');\n" * 10, encoding="utf-8")
            outside_css = root / "outside.css"
            outside_css.write_text("body { color: red; }\n" * 10, encoding="utf-8")

            (ws / "index.html").write_text(
                "<!DOCTYPE html><html><head>"
                "<link rel='stylesheet' href='../outside.css'>"
                "<link rel='stylesheet' href='C:/Windows/win.ini'>"
                "</head><body>"
                "<script src='../../outside.js'></script>"
                "</body></html>",
                encoding="utf-8",
            )

            audit = antigravity_driver.audit_workspace_files(ws)
            self.assertFalse(audit["has_script_logic"])
            self.assertFalse(audit["has_style_sheet"])
            self.assertIn("../../outside.js", audit["missing_references"])
            self.assertIn("../outside.css", audit["missing_references"])
            self.assertIn("C:/Windows/win.ini", audit["missing_references"])

            # Symlinked .py file inside ws pointing outside must not be scanned or compiled
            outside_bad_py = root / "outside_bad.py"
            outside_bad_py.write_text("def broken(:\n", encoding="utf-8")
            sym_py = ws / "sym_bad.py"
            try:
                os.symlink(outside_bad_py, sym_py)
                sym_ok = True
            except OSError:
                sym_ok = False

            if sym_ok:
                audit_sym = antigravity_driver.audit_workspace_files(ws)
            else:
                sym_py.write_text("def broken(:\n", encoding="utf-8")
                sym_norm = os.path.normpath(str(sym_py))
                with patch.object(
                    antigravity_driver.ingest,
                    "_is_symlink_or_reparse",
                    side_effect=lambda p: os.path.normpath(p) == sym_norm,
                ):
                    audit_sym = antigravity_driver.audit_workspace_files(ws)

            audited_paths = [f["path"] for f in audit_sym["files"]]
            self.assertNotIn("sym_bad.py", audited_paths)
            self.assertEqual(audit_sym["syntax_errors"], [])


if __name__ == "__main__":
    unittest.main()
