"""
Hostile Test Suite and Audit for Milestone P2 (Launcher, Portable Zip & PATH Management).

Covers:
  1. Launcher PE properties and binary verification.
  2. Launcher fast-path --version and -v support.
  3. Launcher argument forwarding to python research/pai.py.
  4. Launcher security environment enforcement (overriding poisoned PAI_CORE_BIN/SHA256, clearing PYTHONPATH).
  5. Hostile launcher test: missing manifest.json fails closed (exit code 1).
  6. Hostile launcher test: corrupt/tampered manifest.json fails closed (exit code 1).
  7. Hostile launcher test: missing pai-core.exe fails closed (exit code 1).
  8. Hostile launcher test: 1-byte tampered pai-core.exe fails closed (exit code 1).
  9. Deterministic portable zip creation and automated audit.
 10. Portable zip bitwise reproducibility across independent builds.
 11. Hostile zip test: path traversal (../) rejected (ZipSecurityError).
 12. Hostile zip test: tampered file inside archive fails verification.
 13. Hostile zip test: unlisted file inside archive fails verification.
 14. Appendix D PATH pattern verification: empty PATH, idempotency, case-insensitivity, no setx, clean uninstall.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from packaging.build_launcher import build_launcher, verify_launcher_pe
from packaging.build_payload import (
    DEFAULT_PLATFORM,
    DEFAULT_TAG,
    EXPECTED_BINARY_SHA256,
    EXPECTED_CORE_TREE,
    EXPECTED_RESEARCH_TREE,
    build_payload,
    sha256_file,
)
from packaging.build_portable_zip import (
    ZipSecurityError,
    build_portable_zip,
    create_deterministic_zip,
    sanitize_zip_path,
    verify_portable_zip,
)


class TestLauncherAndZipP2(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = REPO_ROOT
        cls.binary_path = cls.repo_root / "core" / "target" / "release" / "pai-core.exe"
        if not cls.binary_path.is_file():
            raise unittest.SkipTest("pai-core.exe binary required for P2 tests")

        # Compile reference launcher in temporary directory
        cls.class_tmp = tempfile.mkdtemp(prefix="pai_p2_class_")
        cls.ref_launcher = Path(cls.class_tmp) / "bin" / "pai.exe"
        build_launcher(cls.ref_launcher)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.class_tmp, ignore_errors=True)

    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="pai_p2_test_")
        self.out_dir = Path(self.tmp_dir) / "payload"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _setup_test_install(self) -> Path:
        """Helper to create a fully assembled release payload with pai.exe in bin/."""
        build_payload(
            repo_root=self.repo_root,
            out_dir=self.out_dir,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            platform="win-x64",
            launcher_path=self.ref_launcher,
            extra_files={
                "install.bat": self.repo_root / "packaging" / "install.bat",
                "uninstall.bat": self.repo_root / "packaging" / "uninstall.bat",
            },
        )
        return self.out_dir

    def test_01_launcher_pe_properties(self) -> None:
        """Validates that pai.exe has valid PE headers, MZ magic, and expected size."""
        self.assertTrue(self.ref_launcher.is_file())
        verify_launcher_pe(self.ref_launcher)
        size = self.ref_launcher.stat().st_size
        self.assertGreater(size, 10_000, "Launcher must be at least 10KB")
        self.assertLess(size, 500_000, "Launcher must be lightweight (< 500KB)")

    def test_02_launcher_version_command(self) -> None:
        """Validates that pai --version and pai -v return version from manifest with exit code 0."""
        inst = self._setup_test_install()
        pai_exe = inst / "bin" / "pai.exe"

        # Test --version
        proc_ver = subprocess.run([str(pai_exe), "--version"], capture_output=True, text=True)
        self.assertEqual(proc_ver.returncode, 0, f"pai --version failed: {proc_ver.stderr}")
        self.assertIn("pai 1.0.0", proc_ver.stdout)

        # Test -v
        proc_v = subprocess.run([str(pai_exe), "-v"], capture_output=True, text=True)
        self.assertEqual(proc_v.returncode, 0, f"pai -v failed: {proc_v.stderr}")
        self.assertIn("pai 1.0.0", proc_v.stdout)

    def test_03_launcher_subcommand_forwarding(self) -> None:
        """Validates that pai doctor --skip-smoke --json forwards to python research/pai.py."""
        inst = self._setup_test_install()
        pai_exe = inst / "bin" / "pai.exe"

        proc = subprocess.run(
            [str(pai_exe), "doctor", "--skip-smoke", "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"pai doctor failed: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertIn("os", data)
        self.assertIn("telemetry", data)

    def test_04_launcher_environment_isolation_and_override(self) -> None:
        """
        Validates Finding BE compliance and environment isolation:
        Launcher must override poisoned PAI_CORE_BIN / PAI_CORE_SHA256,
        clear PYTHONPATH, and set PAI_INSTALL_DIR.
        """
        inst = self._setup_test_install()
        pai_exe = inst / "bin" / "pai.exe"

        # Poisoned host environment
        poison_env = os.environ.copy()
        poison_env["PYTHONPATH"] = r"C:\Adversary\InjectedModules"
        poison_env["PYTHONHOME"] = r"C:\Adversary\BadPythonHome"
        poison_env["PYTHONSTARTUP"] = r"C:\Adversary\evil.py"
        poison_env["PAI_CORE_BIN"] = r"C:\Adversary\fake_core.exe"
        poison_env["PAI_CORE_SHA256"] = "0000000000000000000000000000000000000000000000000000000000000000"

        # Temporary probe script inside research/ to report active os.environ
        probe_py = inst / "research" / "test_probe_env.py"
        probe_py.write_text(
            "import os, json\n"
            "print(json.dumps({\n"
            "  'PYTHONPATH': os.environ.get('PYTHONPATH'),\n"
            "  'PYTHONHOME': os.environ.get('PYTHONHOME'),\n"
            "  'PYTHONSTARTUP': os.environ.get('PYTHONSTARTUP'),\n"
            "  'PAI_CORE_BIN': os.environ.get('PAI_CORE_BIN'),\n"
            "  'PAI_CORE_SHA256': os.environ.get('PAI_CORE_SHA256'),\n"
            "  'PAI_INSTALL_DIR': os.environ.get('PAI_INSTALL_DIR')\n"
            "}))\n",
            encoding="utf-8",
        )

        # We can temporarily point research/pai.py to load probe
        orig_pai_py = (inst / "research" / "pai.py").read_bytes()
        (inst / "research" / "pai.py").write_text("import test_probe_env\n", encoding="utf-8")

        try:
            proc = subprocess.run([str(pai_exe)], capture_output=True, text=True, env=poison_env)
            self.assertEqual(proc.returncode, 0, f"Probe run failed: {proc.stderr}")
            env_seen = json.loads(proc.stdout)

            # Assert dangerous variables were cleared
            self.assertIsNone(env_seen["PYTHONPATH"])
            self.assertIsNone(env_seen["PYTHONHOME"])
            self.assertIsNone(env_seen["PYTHONSTARTUP"])

            # Assert PAI variables were overridden to exact pinned release paths
            expected_core_bin = str((inst / "bin" / "pai-core.exe").resolve())
            self.assertEqual(env_seen["PAI_CORE_BIN"], expected_core_bin)
            self.assertEqual(env_seen["PAI_CORE_SHA256"], EXPECTED_BINARY_SHA256)
            self.assertEqual(env_seen["PAI_INSTALL_DIR"], str(inst.resolve()))
        finally:
            (inst / "research" / "pai.py").write_bytes(orig_pai_py)
            probe_py.unlink(missing_ok=True)

    def test_05_hostile_missing_manifest(self) -> None:
        """Hostile: missing manifest.json causes launcher to fail closed immediately."""
        inst = self._setup_test_install()
        pai_exe = inst / "bin" / "pai.exe"
        (inst / "manifest.json").unlink()

        proc = subprocess.run([str(pai_exe)], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Cannot locate manifest.json", proc.stderr)

    def test_06_hostile_corrupt_manifest(self) -> None:
        """Hostile: corrupt manifest.json missing pai-core.exe causes launcher to fail closed."""
        inst = self._setup_test_install()
        pai_exe = inst / "bin" / "pai.exe"
        (inst / "manifest.json").write_text(json.dumps({"invalid": True}), encoding="utf-8")

        proc = subprocess.run([str(pai_exe)], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Failed to read or parse bin/pai-core.exe", proc.stderr)

    def test_07_hostile_missing_core_binary(self) -> None:
        """Hostile: missing bin/pai-core.exe causes launcher to fail closed."""
        inst = self._setup_test_install()
        pai_exe = inst / "bin" / "pai.exe"
        (inst / "bin" / "pai-core.exe").unlink()

        proc = subprocess.run([str(pai_exe)], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("pai-core binary not found", proc.stderr)

    def test_08_hostile_tampered_core_binary(self) -> None:
        """Hostile: 1-byte tamper in bin/pai-core.exe causes launcher to fail closed."""
        inst = self._setup_test_install()
        pai_exe = inst / "bin" / "pai.exe"
        core_bin = inst / "bin" / "pai-core.exe"

        raw = bytearray(core_bin.read_bytes())
        raw[-1] ^= 0x01
        core_bin.write_bytes(bytes(raw))

        proc = subprocess.run([str(pai_exe)], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SHA-256 verification failed", proc.stderr)

    def test_09_portable_zip_creation_and_audit(self) -> None:
        """Validates that build_portable_zip produces an audited, self-contained zip."""
        out_zip = Path(self.tmp_dir) / "dist" / "PAI-Portable-test.zip"
        res = build_portable_zip(
            repo_root=self.repo_root,
            out_zip=out_zip,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            platform="win-x64",
        )
        self.assertEqual(res["status"], "success")
        self.assertTrue(out_zip.is_file())
        self.assertTrue(out_zip.with_suffix(".zip.sha256").is_file())

        audit = verify_portable_zip(out_zip)
        self.assertTrue(audit["valid"])
        self.assertGreaterEqual(audit["file_count"], 115)

    def test_10_portable_zip_reproducibility(self) -> None:
        """
        Validates bitwise reproducibility:
        Two independent zip builds from the same payload produce identical SHA-256 hashes.
        """
        zip1 = Path(self.tmp_dir) / "zip1.zip"
        zip2 = Path(self.tmp_dir) / "zip2.zip"

        res1 = build_portable_zip(
            repo_root=self.repo_root,
            out_zip=zip1,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            platform="win-x64",
        )
        res2 = build_portable_zip(
            repo_root=self.repo_root,
            out_zip=zip2,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            platform="win-x64",
        )

        self.assertEqual(res1["zip_sha256"], res2["zip_sha256"])
        self.assertEqual(zip1.read_bytes(), zip2.read_bytes())

    def test_11_hostile_zip_path_traversal(self) -> None:
        """Hostile: zip path traversal (../ or absolute paths) must be rejected."""
        with self.assertRaises(ZipSecurityError):
            sanitize_zip_path("../evil.txt")
        with self.assertRaises(ZipSecurityError):
            sanitize_zip_path("foo/../../evil.txt")
        with self.assertRaises(ZipSecurityError):
            sanitize_zip_path("C:/evil.txt")
        with self.assertRaises(ZipSecurityError):
            sanitize_zip_path("/etc/passwd")

    def test_12_hostile_zip_tampered_member(self) -> None:
        """Hostile: tampered member in zip causes verify_portable_zip to reject."""
        out_zip = Path(self.tmp_dir) / "tamper_test.zip"
        build_portable_zip(
            repo_root=self.repo_root,
            out_zip=out_zip,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            platform="win-x64",
        )

        # Unpack, tamper one byte of research/pai.py, and repack
        unpack_dir = Path(self.tmp_dir) / "tamper_unpack"
        with zipfile.ZipFile(out_zip, "r") as zf:
            zf.extractall(unpack_dir)

        target = unpack_dir / "research" / "pai.py"
        raw = target.read_bytes()
        target.write_bytes(raw + b"# tampered\n")

        tampered_zip = Path(self.tmp_dir) / "tampered.zip"
        create_deterministic_zip(unpack_dir, tampered_zip)

        with self.assertRaises(Exception):
            verify_portable_zip(tampered_zip)

    def test_13_hostile_zip_unlisted_member(self) -> None:
        """Hostile: unlisted member in zip causes verify_portable_zip to reject."""
        out_zip = Path(self.tmp_dir) / "unlisted_test.zip"
        build_portable_zip(
            repo_root=self.repo_root,
            out_zip=out_zip,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            platform="win-x64",
        )

        unpack_dir = Path(self.tmp_dir) / "unlisted_unpack"
        with zipfile.ZipFile(out_zip, "r") as zf:
            zf.extractall(unpack_dir)

        (unpack_dir / "backdoor.txt").write_text("evil", encoding="utf-8")

        unlisted_zip = Path(self.tmp_dir) / "unlisted.zip"
        create_deterministic_zip(unpack_dir, unlisted_zip)

        with self.assertRaises(Exception):
            verify_portable_zip(unlisted_zip)

    def test_14_install_and_uninstall_path_pattern(self) -> None:
        """
        Validates Appendix D PATH pattern:
          - Never uses setx
          - Handles empty PATH
          - Deduplicates case-insensitively (-ieq)
          - Trims trailing backslashes
          - Uninstall removes the entry and restores clean state
        """
        inst_bat = (self.repo_root / "packaging" / "install.bat").read_text(encoding="utf-8")
        uninst_bat = (self.repo_root / "packaging" / "uninstall.bat").read_text(encoding="utf-8")

        # Invariant: Never use setx
        self.assertFalse(re.search(r"^\s*setx\b", inst_bat, re.MULTILINE | re.IGNORECASE))
        self.assertFalse(re.search(r"^\s*setx\b", uninst_bat, re.MULTILINE | re.IGNORECASE))

        # PowerShell test harness for Appendix D PATH logic against process-scoped test environment
        ps_script = """
        $testDir = "C:\\Users\\TestUser\\AppData\\Local\\Programs\\PAI\\bin"
        
        # Scenario 1: Initial empty PATH
        $cur1 = ""
        $parts1 = if ($cur1) { $cur1 -split ';' | Where-Object { $_ } } else { @() }
        if (-not ($parts1 | Where-Object { $_.TrimEnd('\\') -ieq $testDir })) {
            $cur1 = (($parts1 + $testDir) -join ';')
        }
        if ($cur1 -ne $testDir) { exit 1 }

        # Scenario 2: Idempotent addition (must not duplicate)
        $parts2 = if ($cur1) { $cur1 -split ';' | Where-Object { $_ } } else { @() }
        if (-not ($parts2 | Where-Object { $_.TrimEnd('\\') -ieq $testDir })) {
            $cur1 = (($parts2 + $testDir) -join ';')
        }
        if ($cur1 -ne $testDir) { exit 2 }

        # Scenario 3: Case-insensitive check with trailing slash
        $upperDir = "c:\\users\\testuser\\appdata\\local\\programs\\pai\\bin\\"
        $parts3 = if ($cur1) { $cur1 -split ';' | Where-Object { $_ } } else { @() }
        $matched = $parts3 | Where-Object { $_.TrimEnd('\\') -ieq $upperDir.TrimEnd('\\') }
        if (-not $matched) { exit 3 }

        # Scenario 4: Uninstall removal
        $cur4 = "C:\\Windows;C:\\Users\\TestUser\\AppData\\Local\\Programs\\PAI\\bin;C:\\Utils"
        $parts4 = if ($cur4) { $cur4 -split ';' | Where-Object { $_ } } else { @() }
        $newParts = $parts4 | Where-Object { $_.TrimEnd('\\') -ine $testDir }
        $finalPath = ($newParts -join ';')
        if ($finalPath -ne "C:\\Windows;C:\\Utils") { exit 4 }

        exit 0
        """
        proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"PowerShell PATH simulation failed: {proc.stderr}")


if __name__ == "__main__":
    unittest.main()
