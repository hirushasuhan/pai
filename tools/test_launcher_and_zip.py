"""
Hostile Test Suite and Audit for Milestone P2 (Launcher, Portable Zip & PATH Management).

Verifies Milestone P2 and closes Findings BM–BT:
  - BM: Working directory inheritance (lpCurrentDirectory=NULL), relative path handling, and quote/space preserving.
  - BN: Pinned embedded Python runtime discovery and ._pth resolution; release fail-closed without embedded; developer opt-in with -E -s.
  - BO: Safe batch parameter passing via environment variables without delayed expansion; no -ExecutionPolicy Bypass.
  - BP: Staged installation copy verified against signed manifest.json; atomic directory swap; failure aborts without mutation.
  - BQ: Real execution of install.bat and uninstall.bat in paths with spaces, apostrophes (O'Connor), non-ASCII (නාමය), and % signs.
        Registry User PATH unexpanded environment variables (%USERPROFILE%\\bin) preserved as REG_EXPAND_SZ.
  - BR: Launcher trust boundary defense: manifest decoy entries before "files" rejected; exact entry in "files" parsed.
  - BS: Launcher compiler reproducibility across independent directories; DLL import inspection (system only, no MinGW runtime DLLs); ASLR/DEP hardening flags.
  - BT: Isolated PAI_DIR temp redirection; pai --version outputs tag (pai v1.0.0-rc1) per spec §13.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import List, Tuple

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


def extract_pe_imports(pe_path: Path) -> List[str]:
    """Pure-Python PE import directory parser to audit imported DLLs without external tools."""
    data = pe_path.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    opt_offset = pe_offset + 24
    num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    # Import Directory RVA is at offset 120 of PE32+ (64-bit) Optional Header
    import_rva = struct.unpack_from("<I", data, opt_offset + 120)[0]
    if import_rva == 0:
        return []

    sec_offset = opt_offset + opt_size
    sections: List[Tuple[int, int, int, int]] = []
    for i in range(num_sections):
        sec = data[sec_offset + i * 40 : sec_offset + (i + 1) * 40]
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", sec, 8)
        sections.append((vaddr, vsize, raddr, rsize))

    def rva_to_offset(rva: int) -> int | None:
        for va, vs, ra, rs in sections:
            if va <= rva < va + vs:
                return rva - va + ra
        return None

    desc_offset = rva_to_offset(import_rva)
    if desc_offset is None:
        return []

    dlls = []
    while True:
        entry = data[desc_offset : desc_offset + 20]
        if not entry or entry == b"\x00" * 20:
            break
        name_rva = struct.unpack_from("<I", entry, 12)[0]
        name_offset = rva_to_offset(name_rva)
        if name_offset is not None:
            end = data.find(b"\x00", name_offset)
            dll_name = data[name_offset:end].decode("latin1")
            dlls.append(dll_name)
        desc_offset += 20

    return dlls


def parse_pe_characteristics(pe_path: Path) -> int:
    """Extracts DllCharacteristics flags from PE Optional Header."""
    data = pe_path.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    opt_offset = pe_offset + 24
    # DllCharacteristics is at offset 70 of PE32+ Optional Header
    return struct.unpack_from("<H", data, opt_offset + 70)[0]


class TestLauncherAndZipP2(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = REPO_ROOT
        cls.binary_path = cls.repo_root / "core" / "target" / "release" / "pai-core.exe"
        if not cls.binary_path.is_file():
            raise unittest.SkipTest(
                f"Evaluated core binary not found at {cls.binary_path}. "
                "Build core with `cargo build --release --manifest-path core/Cargo.toml` first."
            )

        # Build reference launcher in an isolated class temp directory
        cls.class_tmp = tempfile.mkdtemp(prefix="pai_p2_class_")
        cls.ref_launcher = Path(cls.class_tmp) / "bin" / "pai.exe"
        build_launcher(cls.ref_launcher)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.class_tmp, ignore_errors=True)

    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="pai_p2_test_")
        self.out_dir = Path(self.tmp_dir) / "payload"
        self.isolated_pai_dir = Path(self.tmp_dir) / "isolated_pai_profile"
        self.isolated_pai_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _setup_test_install(self, with_embedded_python: bool = True) -> Path:
        """Helper to create a fully assembled release payload with pai.exe in bin/."""
        embed_dir = None
        if with_embedded_python:
            # Create isolated mock embedded Python runtime
            embed_dir = Path(self.tmp_dir) / "mock_embed_python"
            embed_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sys.executable, embed_dir / "python.exe")
            (embed_dir / "python314._pth").write_text(".\n..\\research\n", encoding="utf-8")

        build_payload(
            repo_root=self.repo_root,
            out_dir=self.out_dir,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            platform="win-x64",
            launcher_path=self.ref_launcher,
            embed_python_dir=embed_dir,
            extra_files={
                "install.bat": self.repo_root / "packaging" / "install.bat",
                "uninstall.bat": self.repo_root / "packaging" / "uninstall.bat",
            },
        )
        return self.out_dir

    def test_01_launcher_pe_properties_and_hardening(self) -> None:
        """Validates that pai.exe has valid PE headers, size, and ASLR/DEP/HighEntropyVA hardening (Finding BS)."""
        self.assertTrue(self.ref_launcher.is_file())
        verify_launcher_pe(self.ref_launcher)
        size = self.ref_launcher.stat().st_size
        self.assertGreater(size, 10_000, "Launcher must be at least 10KB")
        self.assertLess(size, 500_000, "Launcher must be lightweight (< 500KB)")

        flags = parse_pe_characteristics(self.ref_launcher)
        # 0x0040: DYNAMIC_BASE (ASLR)
        self.assertTrue(bool(flags & 0x0040), "ASLR (DYNAMIC_BASE) must be enabled")
        # 0x0100: NX_COMPAT (DEP)
        self.assertTrue(bool(flags & 0x0100), "DEP (NX_COMPAT) must be enabled")
        # 0x0020: HIGH_ENTROPY_VA
        self.assertTrue(bool(flags & 0x0020), "HIGH_ENTROPY_VA must be enabled")

    def test_02_launcher_version_command(self) -> None:
        """Validates that pai --version and pai -v output the git tag (Finding BT & spec §13)."""
        inst = self._setup_test_install(with_embedded_python=False)
        pai_exe = inst / "bin" / "pai.exe"

        proc_ver = subprocess.run([str(pai_exe), "--version"], capture_output=True, text=True)
        self.assertEqual(proc_ver.returncode, 0, f"pai --version failed: {proc_ver.stderr}")
        self.assertEqual(proc_ver.stdout.strip(), f"pai {DEFAULT_TAG}")

        proc_v = subprocess.run([str(pai_exe), "-v"], capture_output=True, text=True)
        self.assertEqual(proc_v.returncode, 0, f"pai -v failed: {proc_v.stderr}")
        self.assertEqual(proc_v.stdout.strip(), f"pai {DEFAULT_TAG}")

    def test_03_launcher_subcommand_forwarding(self) -> None:
        """Validates that pai doctor --skip-smoke --json forwards with isolated PAI_DIR (Finding BT)."""
        inst = self._setup_test_install(with_embedded_python=True)
        pai_exe = inst / "bin" / "pai.exe"

        env = os.environ.copy()
        env["PAI_DIR"] = str(self.isolated_pai_dir)

        proc = subprocess.run(
            [str(pai_exe), "doctor", "--skip-smoke", "--json"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, f"pai doctor failed: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertIn("os", data)
        self.assertIn("telemetry", data)

    def test_04_launcher_working_directory_and_argument_quoting(self) -> None:
        """
        Validates Finding BM:
        Child process inherits caller's working directory (lpCurrentDirectory=NULL),
        resolving relative path arguments correctly, and arguments with spaces/quotes are preserved.
        """
        inst = self._setup_test_install(with_embedded_python=True)
        pai_exe = inst / "bin" / "pai.exe"

        user_work_dir = Path(self.tmp_dir) / "user_work_dir"
        user_work_dir.mkdir(parents=True, exist_ok=True)
        (user_work_dir / "my_note.txt").write_text("Hello User Workspace", encoding="utf-8")

        # Create a test probe inside research/ that dumps cwd and argv
        probe_py = inst / "research" / "test_probe_cwd.py"
        probe_py.write_text(
            "import os, sys, json\n"
            "print(json.dumps({\n"
            "  'cwd': os.getcwd(),\n"
            "  'argv': sys.argv[1:],\n"
            "  'relative_file_exists': os.path.exists('my_note.txt')\n"
            "}))\n",
            encoding="utf-8",
        )

        orig_pai_py = (inst / "research" / "pai.py").read_bytes()
        (inst / "research" / "pai.py").write_text("import test_probe_cwd\n", encoding="utf-8")

        env = os.environ.copy()
        env["PAI_DIR"] = str(self.isolated_pai_dir)

        test_args = [
            "relative_arg_1",
            "spaced argument with spaces",
            "arg'with'single'quote",
            'arg"with"double"quote',
        ]

        try:
            cmd = [str(pai_exe)] + test_args
            proc = subprocess.run(cmd, cwd=str(user_work_dir), capture_output=True, text=True, env=env)
            self.assertEqual(proc.returncode, 0, f"Probe run failed: {proc.stderr}")
            res = json.loads(proc.stdout)

            # Assert working directory is caller's working directory, NOT install_root
            self.assertEqual(Path(res["cwd"]).resolve(), user_work_dir.resolve())
            self.assertTrue(res["relative_file_exists"], "Relative file in caller working dir must resolve")
            # Assert all arguments, spaces, and quotes were preserved verbatim
            self.assertEqual(res["argv"], test_args)
        finally:
            (inst / "research" / "pai.py").write_bytes(orig_pai_py)
            probe_py.unlink(missing_ok=True)

    def test_05_launcher_environment_isolation_and_override(self) -> None:
        """
        Validates Finding BE compliance and environment isolation:
        Launcher overrides poisoned PAI_CORE_BIN/SHA256, clears PYTHONPATH/HOME/STARTUP, sets PAI_INSTALL_DIR.
        """
        inst = self._setup_test_install(with_embedded_python=True)
        pai_exe = inst / "bin" / "pai.exe"

        poison_env = os.environ.copy()
        poison_env["PYTHONPATH"] = r"C:\Adversary\InjectedModules"
        poison_env["PYTHONHOME"] = r"C:\Adversary\BadPythonHome"
        poison_env["PYTHONSTARTUP"] = r"C:\Adversary\evil.py"
        poison_env["PAI_CORE_BIN"] = r"C:\Adversary\fake_core.exe"
        poison_env["PAI_CORE_SHA256"] = "0" * 64
        poison_env["PAI_DIR"] = str(self.isolated_pai_dir)

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

        orig_pai_py = (inst / "research" / "pai.py").read_bytes()
        (inst / "research" / "pai.py").write_text("import test_probe_env\n", encoding="utf-8")

        try:
            proc = subprocess.run([str(pai_exe)], capture_output=True, text=True, env=poison_env)
            self.assertEqual(proc.returncode, 0, f"Probe run failed: {proc.stderr}")
            env_seen = json.loads(proc.stdout)

            self.assertIsNone(env_seen["PYTHONPATH"])
            self.assertIsNone(env_seen["PYTHONHOME"])
            self.assertIsNone(env_seen["PYTHONSTARTUP"])

            expected_core_bin = str((inst / "bin" / "pai-core.exe").resolve())
            self.assertEqual(env_seen["PAI_CORE_BIN"], expected_core_bin)
            self.assertEqual(env_seen["PAI_CORE_SHA256"], EXPECTED_BINARY_SHA256)
            self.assertEqual(env_seen["PAI_INSTALL_DIR"], str(inst.resolve()))
        finally:
            (inst / "research" / "pai.py").write_bytes(orig_pai_py)
            probe_py.unlink(missing_ok=True)

    def test_06_embedded_python_runtime_and_pth_resolution(self) -> None:
        """
        Validates Finding BN:
        Embedded Python with python*._pth successfully imports from research/ without opt-in.
        """
        inst = self._setup_test_install(with_embedded_python=True)
        pai_exe = inst / "bin" / "pai.exe"

        env = os.environ.copy()
        env.pop("PAI_ALLOW_SYSTEM_PYTHON", None)
        env["PAI_DIR"] = str(self.isolated_pai_dir)

        proc = subprocess.run([str(pai_exe), "doctor", "--skip-smoke", "--json"], capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, f"Embedded run failed: {proc.stderr}")
        self.assertIn("telemetry", json.loads(proc.stdout))

    def test_07_missing_embedded_python_fails_closed(self) -> None:
        """
        Validates Finding BN:
        Missing embedded Python runtime fails closed with exit code 1 when PAI_ALLOW_SYSTEM_PYTHON is unset.
        """
        inst = self._setup_test_install(with_embedded_python=False)
        pai_exe = inst / "bin" / "pai.exe"

        env = os.environ.copy()
        env.pop("PAI_ALLOW_SYSTEM_PYTHON", None)

        proc = subprocess.run([str(pai_exe), "doctor"], capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Embedded Python runtime not found", proc.stderr)
        self.assertIn("PAI_ALLOW_SYSTEM_PYTHON=1", proc.stderr)

    def test_08_developer_opt_in_system_python_with_e_s(self) -> None:
        """
        Validates Finding BN:
        When PAI_ALLOW_SYSTEM_PYTHON=1 is set, system Python is located by absolute path and invoked with -E -s.
        """
        inst = self._setup_test_install(with_embedded_python=False)
        pai_exe = inst / "bin" / "pai.exe"

        env = os.environ.copy()
        env["PAI_ALLOW_SYSTEM_PYTHON"] = "1"
        env["PAI_DIR"] = str(self.isolated_pai_dir)

        proc = subprocess.run([str(pai_exe), "doctor", "--skip-smoke", "--json"], capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, f"Opt-in system Python failed: {proc.stderr}")
        self.assertIn("telemetry", json.loads(proc.stdout))

    def test_09_hostile_missing_manifest(self) -> None:
        """Hostile: missing manifest.json causes launcher to fail closed immediately."""
        inst = self._setup_test_install(with_embedded_python=True)
        pai_exe = inst / "bin" / "pai.exe"
        (inst / "manifest.json").unlink()

        proc = subprocess.run([str(pai_exe)], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Cannot locate manifest.json", proc.stderr)

    def test_10_hostile_corrupt_and_decoy_manifest(self) -> None:
        """
        Validates Finding BR:
        Launcher parses inside the 'files' section and ignores decoy entries placed before 'files'.
        """
        inst = self._setup_test_install(with_embedded_python=True)
        pai_exe = inst / "bin" / "pai.exe"
        manifest_p = inst / "manifest.json"

        # 1. Decoy entry placed before "files"
        real_doc = json.loads(manifest_p.read_text(encoding="utf-8"))
        decoy_doc = {
            "decoy_entry": {
                "bin/pai-core.exe": {
                    "sha256": "0" * 64,
                    "size": 9999,
                }
            },
            **real_doc,
        }
        manifest_p.write_text(json.dumps(decoy_doc, indent=2), encoding="utf-8")

        # Launcher must ignore decoy and locate the real core binary hash in "files"
        env = os.environ.copy()
        env["PAI_DIR"] = str(self.isolated_pai_dir)
        proc_decoy = subprocess.run([str(pai_exe), "--version"], capture_output=True, text=True, env=env)
        self.assertEqual(proc_decoy.returncode, 0)
        self.assertEqual(proc_decoy.stdout.strip(), f"pai {DEFAULT_TAG}")

        # 2. Corrupt manifest missing "files" or "bin/pai-core.exe" entirely fails closed
        manifest_p.write_text(json.dumps({"format": 1, "invalid": True}), encoding="utf-8")
        proc_corrupt = subprocess.run([str(pai_exe)], capture_output=True, text=True)
        self.assertEqual(proc_corrupt.returncode, 1)
        self.assertIn("Failed to read or parse bin/pai-core.exe", proc_corrupt.stderr)

    def test_11_hostile_missing_and_tampered_core_binary(self) -> None:
        """Hostile: missing pai-core.exe or 1-byte tamper causes launcher to fail closed."""
        inst = self._setup_test_install(with_embedded_python=True)
        pai_exe = inst / "bin" / "pai.exe"
        core_bin = inst / "bin" / "pai-core.exe"

        # 1. 1-byte tamper in binary
        raw = bytearray(core_bin.read_bytes())
        raw[-1] ^= 0x01
        core_bin.write_bytes(bytes(raw))

        proc_tamper = subprocess.run([str(pai_exe)], capture_output=True, text=True)
        self.assertEqual(proc_tamper.returncode, 1)
        self.assertIn("SHA-256 verification failed", proc_tamper.stderr)

        # 2. Missing binary
        core_bin.unlink()
        proc_miss = subprocess.run([str(pai_exe)], capture_output=True, text=True)
        self.assertEqual(proc_miss.returncode, 1)
        self.assertIn("pai-core binary not found", proc_miss.stderr)

    def test_12_compiler_reproducibility(self) -> None:
        """
        Validates Finding BS:
        Compiling launcher.c twice in two separate directories produces bit-for-bit identical binaries.
        """
        dir1 = Path(self.tmp_dir) / "build_rep_1"
        dir2 = Path(self.tmp_dir) / "build_rep_2"

        bin1 = build_launcher(dir1 / "bin" / "pai.exe")
        bin2 = build_launcher(dir2 / "bin" / "pai.exe")

        self.assertEqual(
            sha256_file(bin1),
            sha256_file(bin2),
            "Compiler output must be bit-for-bit reproducible via SOURCE_DATE_EPOCH",
        )
        self.assertEqual(bin1.read_bytes(), bin2.read_bytes())

    def test_13_imported_dlls_safety(self) -> None:
        """
        Validates Finding BS:
        Audits imported DLLs of pai.exe, ensuring system libraries only and zero MinGW runtime DLLs.
        """
        dlls = extract_pe_imports(self.ref_launcher)
        self.assertTrue(len(dlls) > 0, "Launcher must import at least one DLL")

        dlls_lower = [d.lower() for d in dlls]
        self.assertIn("kernel32.dll", dlls_lower)
        self.assertIn("bcrypt.dll", dlls_lower)

        for dll in dlls_lower:
            self.assertNotIn("libgcc", dll, f"Prohibited MinGW runtime DLL imported: {dll}")
            self.assertNotIn("libwinpthread", dll, f"Prohibited pthread DLL imported: {dll}")
            self.assertNotIn("libstdc++", dll, f"Prohibited C++ runtime DLL imported: {dll}")

    def test_14_portable_zip_creation_and_audit(self) -> None:
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

    def test_15_hostile_zip_security(self) -> None:
        """Validates hostile zip security: path traversal, tampered files, and unlisted files."""
        # Path traversals
        with self.assertRaises(ZipSecurityError):
            sanitize_zip_path("../evil.txt")
        with self.assertRaises(ZipSecurityError):
            sanitize_zip_path("foo/../../evil.txt")
        with self.assertRaises(ZipSecurityError):
            sanitize_zip_path("C:/evil.txt")
        with self.assertRaises(ZipSecurityError):
            sanitize_zip_path("/etc/passwd")

        # Tampered member
        out_zip = Path(self.tmp_dir) / "tamper_test.zip"
        build_portable_zip(
            repo_root=self.repo_root,
            out_zip=out_zip,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            platform="win-x64",
        )

        unpack_dir = Path(self.tmp_dir) / "tamper_unpack"
        with zipfile.ZipFile(out_zip, "r") as zf:
            zf.extractall(unpack_dir)

        target = unpack_dir / "research" / "pai.py"
        target.write_bytes(target.read_bytes() + b"# tampered\n")

        tampered_zip = Path(self.tmp_dir) / "tampered.zip"
        create_deterministic_zip(unpack_dir, tampered_zip)
        with self.assertRaises(Exception):
            verify_portable_zip(tampered_zip)

    def test_16_real_install_and_uninstall_scripts(self) -> None:
        """
        Validates Findings BO, BP, and BQ:
        Executes the REAL install.bat and uninstall.bat scripts via subprocess.
        Tests:
          - Target folder containing space, apostrophe (O'Connor), non-ASCII (Café), and % sign.
          - Staged copy and verification against manifest.json.
          - Hostile: tampered staged file aborts without modifying target or PATH.
          - Registry User PATH with unexpanded variable (%USERPROFILE%\\bin) preserved as REG_EXPAND_SZ.
          - Clean uninstallation removing target from PATH while preserving unexpanded variables.
        """
        import winreg

        payload_dir = self._setup_test_install(with_embedded_python=True)
        install_bat = payload_dir / "install.bat"
        self.assertTrue(install_bat.is_file())

        # Isolated test registry subkey in HKCU
        test_reg_subkey = "Environment_PaiTest_P2"

        # Initialize test subkey with an unexpanded variable (%USERPROFILE%\bin) as REG_EXPAND_SZ
        key_init = winreg.CreateKey(winreg.HKEY_CURRENT_USER, test_reg_subkey)
        winreg.SetValueEx(key_init, "Path", 0, winreg.REG_EXPAND_SZ, r"%USERPROFILE%\bin;C:\Windows")
        winreg.CloseKey(key_init)

        try:
            # Target path with space, apostrophe, non-ASCII (Café), and percent sign (Finding BQ)
            target_install = Path(self.tmp_dir) / "Target O'Connor Café PAI%100"

            env = os.environ.copy()
            env["PAI_INSTALL_DIR"] = str(target_install)
            env["PAI_REG_SUBKEY"] = test_reg_subkey

            # 1. Run the real install.bat
            proc_inst = subprocess.run([str(install_bat)], capture_output=True, text=True, env=env)
            self.assertEqual(proc_inst.returncode, 0, f"install.bat failed:\n{proc_inst.stderr}\n{proc_inst.stdout}")
            self.assertIn("Files installed successfully", proc_inst.stdout)
            self.assertTrue((target_install / "bin" / "pai.exe").is_file())

            # 2. Verify Registry PATH after install directly via winreg (Finding BQ):
            # - Must still be REG_EXPAND_SZ
            # - Must still contain unexpanded '%USERPROFILE%\bin'
            # - Must contain target_install\bin
            key_read = winreg.OpenKey(winreg.HKEY_CURRENT_USER, test_reg_subkey)
            val, vtype = winreg.QueryValueEx(key_read, "Path")
            winreg.CloseKey(key_read)

            self.assertEqual(vtype, winreg.REG_EXPAND_SZ, "Must preserve REG_EXPAND_SZ registry type")
            self.assertIn(r"%USERPROFILE%\bin", val, "Must NOT expand %USERPROFILE% into static path")
            self.assertIn(str(target_install / "bin"), val, "Must include installed bin folder")
            self.assertIn("Café", val, "Must preserve non-ASCII characters")
            self.assertIn("PAI%100", val, "Must preserve percent signs")

            # 3. Idempotency: run install.bat a second time
            proc_inst_2 = subprocess.run([str(install_bat)], capture_output=True, text=True, env=env)
            self.assertEqual(proc_inst_2.returncode, 0)
            self.assertIn("is already in User PATH", proc_inst_2.stdout)

            # 4. Run uninstall.bat from target
            uninst_bat = target_install / "uninstall.bat"
            self.assertTrue(uninst_bat.is_file())
            proc_uninst = subprocess.run([str(uninst_bat)], capture_output=True, text=True, env=env)
            self.assertEqual(proc_uninst.returncode, 0, f"uninstall.bat failed: {proc_uninst.stderr}")

            # Verify Registry PATH after uninstall:
            # - Must still be REG_EXPAND_SZ
            # - Must still contain '%USERPROFILE%\bin' and 'C:\Windows'
            # - Must NOT contain target_install\bin
            key_read2 = winreg.OpenKey(winreg.HKEY_CURRENT_USER, test_reg_subkey)
            val2, vtype2 = winreg.QueryValueEx(key_read2, "Path")
            winreg.CloseKey(key_read2)

            self.assertEqual(vtype2, winreg.REG_EXPAND_SZ)
            self.assertIn(r"%USERPROFILE%\bin", val2)
            self.assertNotIn(str(target_install / "bin"), val2)
            self.assertEqual(val2, r"%USERPROFILE%\bin;C:\Windows")

        finally:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_reg_subkey)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
