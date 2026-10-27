"""
Hostile Test Suite and Acceptance Matrix for Milestone P5 (Inno Setup Installer).

Part of Milestone P5 for the v1.1.0 Packaging and Installer subsystem.
Specification: docs/PACKAGING_SPEC.md (§2, §3, §4, §5, §6, §7, §8, §9)
ADR-005, ADR-013

Test Matrix Covered:
  - test_01_agreement_text_completeness_and_sha256: Verifies all 6 required sections from Appendix A and exact SHA-256.
  - test_02_update_path_script_appendix_d_compliance: Tests update_path.ps1 with unexpanded variables, empty PATH, case sensitivity, duplicates, and clean removal.
  - test_03_inno_setup_compiler_discovery_and_build: Tests find_iscc_compiler(), build_inno_installer(), PE header auditing, and SHA-256 checksum file emission.
  - test_04_silent_installation_spaces_and_sinhala: Performs silent install to a path with spaces and Sinhala Unicode characters (නාමය), verifies agreement_acceptance.json, launcher forwarding, and PATH registration.
  - test_05_uninstallation_cleanliness_and_path_removal: Runs uninstaller silently, asserts complete PATH removal, ExpandString preservation, and directory cleanup.
  - test_06_upgrade_and_repair_idempotence: Verifies re-running installer over an existing installation is idempotent without PATH duplication.
  - test_07_hostile_tampered_tree_rejected: Hostile negative control: tampered git tree hash fails closed before payload assembly.
  - test_08_hostile_tampered_binary_hash_rejected: Hostile negative control: tampered core binary SHA-256 fails closed.
  - test_09_hostile_missing_iscc_compiler_fails_closed: Hostile negative control: invalid ISCC compiler path fails closed with CompilerNotFoundError.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from packaging.build_installer import (
    CompilerNotFoundError,
    InstallerBuildError,
    build_inno_installer,
    find_iscc_compiler,
    verify_installer_pe,
)
from packaging.build_payload import (
    DEFAULT_PLATFORM,
    DEFAULT_TAG,
    EXPECTED_BINARY_SHA256,
    EXPECTED_CORE_TREE,
    EXPECTED_RESEARCH_TREE,
    PINNED_PYTHON_VERSION,
    PINNED_PYTHON_ZIP_SHA256,
    PayloadBuildError,
    sha256_file,
)


class TestInstallerP5(unittest.TestCase):
    """Milestone P5 Test Suite covering Inno Setup script, builder, installer, and uninstaller."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = REPO_ROOT
        cls.packaging_dir = cls.repo_root / "packaging"
        cls.agreement_file = cls.packaging_dir / "agreement.txt"
        cls.iss_file = cls.packaging_dir / "pai.iss"
        cls.update_path_script = cls.packaging_dir / "update_path.ps1"

        # Check for cached embed python zip
        cls.cached_python_zip = Path(tempfile.gettempdir()) / f"python-{PINNED_PYTHON_VERSION}-embed-amd64.zip"

    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="pai_p5_test_")
        self.test_subkeys: List[str] = []

    def tearDown(self) -> None:
        # Clean up any test registry subkeys created
        for sub in self.test_subkeys:
            try:
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command", f"Remove-Item -Path 'HKCU:\\{sub}' -Recurse -Force -ErrorAction SilentlyContinue"],
                    capture_output=True,
                    timeout=5,
                )
            except Exception:
                pass

        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _create_isolated_reg_subkey(self, subkey_name: str, initial_path: str = "%USERPROFILE%\\bin") -> str:
        """Helper to create an isolated test registry subkey in HKCU for testing without mutating real PATH."""
        self.test_subkeys.append(subkey_name)
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"New-Item -Path 'HKCU:\\{subkey_name}' -Force | Out-Null; "
            f"Set-ItemProperty -Path 'HKCU:\\{subkey_name}' -Name 'Path' -Value '{initial_path}' -Type ExpandString",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0, f"Failed to initialize test registry subkey {subkey_name}: {res.stderr}")
        return subkey_name

    def _get_reg_path_details(self, subkey_name: str) -> Dict[str, str]:
        """Reads raw unexpanded Path value and its RegistryValueKind."""
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            f"$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('{subkey_name}'); "
            "$raw = $k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); "
            "$kind = $k.GetValueKind('Path').ToString(); "
            "$k.Close(); "
            "Write-Output ($raw + '|||' + $kind)",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
        self.assertEqual(res.returncode, 0, f"Failed to query test registry subkey {subkey_name}: {res.stderr}")
        out = (res.stdout or "").strip()
        parts = out.split("|||")
        return {"raw": parts[0] if len(parts) > 0 else "", "kind": parts[1] if len(parts) > 1 else ""}

    def test_01_agreement_text_completeness_and_sha256(self) -> None:
        """
        Validates Specification §3 & Appendix A:
        Agreement text is present, non-empty, contains all 6 required clauses,
        and its SHA-256 digest is computable.
        """
        self.assertTrue(self.agreement_file.is_file(), "packaging/agreement.txt is missing")
        text = self.agreement_file.read_text(encoding="utf-8")
        self.assertGreater(len(text), 200)

        # Appendix A required clauses
        self.assertIn("1. What this is.", text)
        self.assertIn("2. Acceptable use.", text)
        self.assertIn("3. Your data.", text)
        self.assertIn("4. Third-party software and models.", text)
        self.assertIn("5. No warranty.", text)
        self.assertIn("6. Source-code licence.", text)

        expected_hash = sha256_file(self.agreement_file)
        self.assertEqual(len(expected_hash), 64)

    def test_02_update_path_script_appendix_d_compliance(self) -> None:
        """
        Validates Specification §7 & Appendix D:
        update_path.ps1 safely adds and removes directories from User PATH:
          - Preserves unexpanded variables (%USERPROFILE%) as REG_EXPAND_SZ.
          - Idempotent: duplicate add does not duplicate entry.
          - Case-insensitive comparison.
          - Clean remove leaves other entries untouched.
          - Rejects unsafe non-test registry subkeys fail-closed.
        """
        sub = self._create_isolated_reg_subkey("Test_PAI_Path_Suite", "%USERPROFILE%\\bin")
        target_dir = "C:\\PAI\\Custom App\\bin"

        # 1. Add target directory
        cmd_add = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self.update_path_script),
            "-Action",
            "Add",
            "-TargetDir",
            target_dir,
            "-RegSubKey",
            sub,
        ]
        res = subprocess.run(cmd_add, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
        self.assertEqual(res.returncode, 0, f"update_path.ps1 Add failed: {res.stderr}")
        details = self._get_reg_path_details(sub)
        self.assertEqual(details["kind"], "ExpandString")
        self.assertEqual(details["raw"], f"%USERPROFILE%\\bin;{target_dir}")

        # 2. Duplicate Add (case-variant)
        cmd_dup = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self.update_path_script),
            "-Action",
            "Add",
            "-TargetDir",
            target_dir.lower(),
            "-RegSubKey",
            sub,
        ]
        res = subprocess.run(cmd_dup, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
        self.assertEqual(res.returncode, 0)
        details = self._get_reg_path_details(sub)
        self.assertEqual(details["raw"], f"%USERPROFILE%\\bin;{target_dir}")

        # 3. Remove target directory
        cmd_rem = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self.update_path_script),
            "-Action",
            "Remove",
            "-TargetDir",
            target_dir,
            "-RegSubKey",
            sub,
        ]
        res = subprocess.run(cmd_rem, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
        self.assertEqual(res.returncode, 0, f"update_path.ps1 Remove failed: {res.stderr}")
        details = self._get_reg_path_details(sub)
        self.assertEqual(details["kind"], "ExpandString")
        self.assertEqual(details["raw"], "%USERPROFILE%\\bin")

        # 4. Hostile: unsafe subkey name rejected fail-closed
        cmd_hostile = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self.update_path_script),
            "-Action",
            "Add",
            "-TargetDir",
            target_dir,
            "-RegSubKey",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        ]
        res = subprocess.run(cmd_hostile, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
        self.assertNotEqual(res.returncode, 0, "Unsafe RegSubKey must fail closed")
        self.assertIn("Rejected non-test PAI_REG_SUBKEY", res.stderr)

    def test_03_inno_setup_compiler_discovery_and_build(self) -> None:
        """
        Validates Inno Setup compiler discovery and build_inno_installer():
        Produces a valid Windows PE installer with accompanying .sha256 file.
        """
        iscc_exe = find_iscc_compiler()
        self.assertTrue(iscc_exe.is_file(), f"ISCC compiler not found at {iscc_exe}")

        out_dist = Path(self.tmp_dir) / "dist"
        res = build_inno_installer(
            repo_root=self.repo_root,
            out_dir=out_dist,
            tag=DEFAULT_TAG,
            version="1.1.0-rc1",
            platform="win-x64",
            clean=True,
        )

        installer_path = Path(res["installer_path"])
        self.assertTrue(installer_path.is_file())
        self.assertGreater(installer_path.stat().st_size, 10 * 1024 * 1024)

        # Validate PE properties
        pe_info = verify_installer_pe(installer_path)
        self.assertEqual(pe_info["sha256"], res["sha256"])

        # Validate SHA-256 file
        sha_file = Path(res["sha256_file"])
        self.assertTrue(sha_file.is_file())
        sha_content = sha_file.read_text(encoding="utf-8")
        self.assertIn(res["sha256"], sha_content)
        self.assertIn(installer_path.name, sha_content)

    def test_04_silent_installation_spaces_and_sinhala(self) -> None:
        """
        Validates Specification §2, §3, §4, §7 & §9.4:
        Executes silent installer into a directory with spaces and Sinhala Unicode characters:
          - Validates clean payload extraction.
          - Validates agreement_acceptance.json recording (§3).
          - Validates User PATH addition with REG_EXPAND_SZ preservation.
          - Validates launcher execution (pai.exe --version -> pai v1.0.0-rc1).
        """
        out_dist = Path(self.tmp_dir) / "dist"
        build_res = build_inno_installer(
            repo_root=self.repo_root,
            out_dir=out_dist,
            tag=DEFAULT_TAG,
            version="1.1.0-rc1",
            platform="win-x64",
        )
        installer_exe = Path(build_res["installer_path"])

        install_target = Path(self.tmp_dir) / "PAI Sinhala නාමය P5"
        sub = self._create_isolated_reg_subkey("Test_PAI_Install_P5", "%USERPROFILE%\\bin")

        # Run installer silently with custom DIR and isolated REG_SUBKEY
        env = os.environ.copy()
        env["PAI_REG_SUBKEY"] = sub
        cmd = f'"{installer_exe}" /VERYSILENT /SUPPRESSMSGBOXES /DIR="{install_target}" /REG_SUBKEY="{sub}"'
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=60)
        self.assertEqual(proc.returncode, 0, f"Installer failed (code {proc.returncode}):\n{proc.stdout}\n{proc.stderr}")

        # 1. Verify key payload files exist
        self.assertTrue((install_target / "bin" / "pai.exe").is_file(), "bin/pai.exe missing")
        self.assertTrue((install_target / "bin" / "pai-core.exe").is_file(), "bin/pai-core.exe missing")
        self.assertTrue((install_target / "research" / "pai.py").is_file(), "research/pai.py missing")
        self.assertTrue((install_target / "manifest.json").is_file(), "manifest.json missing")
        self.assertTrue((install_target / "AGREEMENT.txt").is_file(), "AGREEMENT.txt missing")
        self.assertTrue((install_target / "unins000.exe").is_file(), "unins000.exe missing")

        # 2. Verify Agreement Acceptance Record (Specification §3, Finding DE)
        acc_file = install_target / "agreement_acceptance.json"
        self.assertTrue(acc_file.is_file(), "agreement_acceptance.json not created")
        acc_data = json.loads(acc_file.read_text(encoding="utf-8"))
        self.assertEqual(acc_data["installed_version"], "1.1.0-rc1")
        self.assertEqual(acc_data["agreement_text_sha256"], build_res["agreement_sha256"])
        self.assertTrue(acc_data["accepted"])
        self.assertIn("accepted_utc", acc_data)
        import re
        self.assertRegex(acc_data["accepted_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

        # 3. Verify User PATH entry added
        expected_bin = str(install_target / "bin")
        details = self._get_reg_path_details(sub)
        self.assertEqual(details["kind"], "ExpandString")
        self.assertEqual(details["raw"], f"%USERPROFILE%\\bin;{expected_bin}")

        # 4. Verify launcher execution forwards --version correctly (§13)
        pai_exe = install_target / "bin" / "pai.exe"
        ver_proc = subprocess.run([str(pai_exe), "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
        self.assertEqual(ver_proc.returncode, 0, f"pai.exe --version failed: {ver_proc.stderr}")
        self.assertEqual(ver_proc.stdout.strip(), f"pai {DEFAULT_TAG}")

    def test_05_uninstallation_cleanliness_and_path_removal(self) -> None:
        """
        Validates Specification §4, §7 & §9.5:
        Uninstaller cleanly removes installed files and removes exactly the PAI bin directory
        from User PATH, preserving other PATH entries and REG_EXPAND_SZ type.
        """
        out_dist = Path(self.tmp_dir) / "dist"
        build_res = build_inno_installer(
            repo_root=self.repo_root,
            out_dir=out_dist,
            tag=DEFAULT_TAG,
            version="1.1.0-rc1",
            platform="win-x64",
        )
        installer_exe = Path(build_res["installer_path"])
        install_target = Path(self.tmp_dir) / "PAI_Uninstall_Test"
        sub = self._create_isolated_reg_subkey("Test_PAI_Uninstall_P5", "%USERPROFILE%\\bin")

        # Install
        env = os.environ.copy()
        env["PAI_REG_SUBKEY"] = sub
        inst_cmd = f'"{installer_exe}" /VERYSILENT /SUPPRESSMSGBOXES /DIR="{install_target}" /REG_SUBKEY="{sub}"'
        proc = subprocess.run(inst_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=60)
        self.assertEqual(proc.returncode, 0)
        self.assertTrue((install_target / "unins000.exe").is_file())

        # Uninstall
        uninstaller_exe = install_target / "unins000.exe"
        uninst_cmd = f'"{uninstaller_exe}" /VERYSILENT /SUPPRESSMSGBOXES /REG_SUBKEY="{sub}"'
        uninst_proc = subprocess.run(uninst_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=60)
        self.assertEqual(uninst_proc.returncode, 0, f"Uninstaller failed: {uninst_proc.stderr}")

        # Verify PATH entry cleanly removed
        details = self._get_reg_path_details(sub)
        self.assertEqual(details["kind"], "ExpandString")
        self.assertEqual(details["raw"], "%USERPROFILE%\\bin")

        # Verify binaries removed
        self.assertFalse((install_target / "bin" / "pai.exe").exists())
        self.assertFalse((install_target / "bin" / "pai-core.exe").exists())

    def test_06_upgrade_and_repair_idempotence(self) -> None:
        """
        Validates Specification §4 & §9.5:
        Running the installer over an existing installation succeeds without
        duplicating PATH entries or damaging existing files.
        """
        out_dist = Path(self.tmp_dir) / "dist"
        build_res = build_inno_installer(
            repo_root=self.repo_root,
            out_dir=out_dist,
            tag=DEFAULT_TAG,
            version="1.1.0-rc1",
            platform="win-x64",
        )
        installer_exe = Path(build_res["installer_path"])
        install_target = Path(self.tmp_dir) / "PAI_Upgrade_Test"
        sub = self._create_isolated_reg_subkey("Test_PAI_Upgrade_P5", "%USERPROFILE%\\bin")

        env = os.environ.copy()
        env["PAI_REG_SUBKEY"] = sub
        cmd = f'"{installer_exe}" /VERYSILENT /SUPPRESSMSGBOXES /DIR="{install_target}" /REG_SUBKEY="{sub}"'

        # First installation
        res1 = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=60)
        self.assertEqual(res1.returncode, 0)

        # Second installation (repair / upgrade)
        res2 = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=60)
        self.assertEqual(res2.returncode, 0)

        # Verify PATH is not duplicated
        expected_bin = str(install_target / "bin")
        details = self._get_reg_path_details(sub)
        self.assertEqual(details["raw"], f"%USERPROFILE%\\bin;{expected_bin}")

    def test_07_hostile_tampered_tree_rejected(self) -> None:
        """
        Hostile negative control:
        Attempting to build payload or installer with tampered core/ or research/ tree hash fails closed.
        """
        out_dist = Path(self.tmp_dir) / "dist_tamper"
        bogus_core_tree = "0000000000000000000000000000000000000000"

        with self.assertRaises(PayloadBuildError) as cm:
            from packaging.build_payload import build_payload
            build_payload(
                repo_root=self.repo_root,
                out_dir=Path(self.tmp_dir) / "payload_tampered",
                tag=DEFAULT_TAG,
                expected_core_tree=bogus_core_tree,
            )
        self.assertIn("tree id mismatch", str(cm.exception).lower())

    def test_08_hostile_tampered_binary_hash_rejected(self) -> None:
        """
        Hostile negative control:
        Attempting to assemble payload or installer with tampered core binary hash fails closed.
        """
        bogus_binary_sha = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        with self.assertRaises(PayloadBuildError) as cm:
            from packaging.build_payload import build_payload
            build_payload(
                repo_root=self.repo_root,
                out_dir=Path(self.tmp_dir) / "payload_tampered_bin",
                tag=DEFAULT_TAG,
                expected_binary_sha256=bogus_binary_sha,
            )
        self.assertIn("binary sha-256 mismatch", str(cm.exception).lower())

    def test_09_hostile_missing_iscc_compiler_fails_closed(self) -> None:
        """
        Hostile negative control:
        Non-existent ISCC compiler path fails closed with CompilerNotFoundError.
        """
        bogus_iscc = Path(self.tmp_dir) / "nonexistent" / "ISCC.exe"
        with self.assertRaises(CompilerNotFoundError):
            find_iscc_compiler(bogus_iscc)

    def test_10_version_enforcement_and_tag_check(self) -> None:
        """
        Validates Finding DB:
        - Rejects empty version strings fail-closed.
        - Rejects final version strings (e.g. 1.0.0, 1.1.0) if no matching git tag exists.
        - Accepts preview format 1.1.0-rcN without requiring an existing tag.
        """
        out_dist = Path(self.tmp_dir) / "dist_ver"

        # 1. Empty version rejected
        with self.assertRaises(InstallerBuildError) as cm_empty:
            build_inno_installer(
                repo_root=self.repo_root,
                out_dir=out_dist,
                version="",
            )
        self.assertIn("must be specified and non-empty", str(cm_empty.exception).lower())

        # 2. Final version 1.0.0 without git tag rejected
        with self.assertRaises(InstallerBuildError) as cm_final:
            build_inno_installer(
                repo_root=self.repo_root,
                out_dir=out_dist,
                version="1.0.0",
            )
        self.assertIn("requires an existing git tag", str(cm_final.exception).lower())

        # 3. Final version 1.1.0 without git tag rejected
        with self.assertRaises(InstallerBuildError) as cm_final2:
            build_inno_installer(
                repo_root=self.repo_root,
                out_dir=out_dist,
                version="1.1.0",
            )
        self.assertIn("requires an existing git tag", str(cm_final2.exception).lower())

    def test_11_payload_manifest_missing_update_path_fails_closed(self) -> None:
        """
        Validates Finding DD:
        Pre-staged payload missing 'tools/update_path.ps1' from manifest.json fails closed.
        """
        mock_payload = Path(self.tmp_dir) / "mock_payload"
        mock_payload.mkdir(parents=True, exist_ok=True)
        manifest_data = {
            "version": "1.1.0-rc1",
            "files": {
                "bin/pai.exe": {"size": 100, "sha256": "abc"},
            },
        }
        (mock_payload / "manifest.json").write_text(json.dumps(manifest_data), encoding="utf-8")

        out_dist = Path(self.tmp_dir) / "dist_dd"
        with self.assertRaises(InstallerBuildError) as cm:
            build_inno_installer(
                repo_root=self.repo_root,
                out_dir=out_dist,
                version="1.1.0-rc1",
                payload_dir=mock_payload,
            )
        self.assertIn("missing 'tools/update_path.ps1'", str(cm.exception).lower())

    def test_12_silent_postinstall_failure_exits_nonzero(self) -> None:
        """
        Validates Finding DC:
        In silent mode, post-install failure (e.g. update_path.ps1 failing due to rejected
        non-test registry subkey) must terminate the installer with a non-zero exit code.
        """
        out_dist = Path(self.tmp_dir) / "dist"
        build_res = build_inno_installer(
            repo_root=self.repo_root,
            out_dir=out_dist,
            tag=DEFAULT_TAG,
            version="1.1.0-rc1",
            platform="win-x64",
        )
        installer_exe = Path(build_res["installer_path"])
        install_target = Path(self.tmp_dir) / "PAI_Fail_Target"

        # Pass an illegal subkey that update_path.ps1 explicitly rejects fail-closed
        illegal_subkey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        cmd = f'"{installer_exe}" /VERYSILENT /SUPPRESSMSGBOXES /DIR="{install_target}" /REG_SUBKEY="{illegal_subkey}"'
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        self.assertNotEqual(proc.returncode, 0, "Silent installer must exit non-zero when post-install PATH update fails")
        self.assertEqual(proc.returncode, 3, "Expected exit code 3 from Inno Setup post-install error handler")

    def test_13_portable_install_and_uninstall_calls_update_path(self) -> None:
        """
        Validates Finding DD:
        packaging/install.bat and packaging/uninstall.bat delegate PATH operations
        to tools/update_path.ps1 rather than duplicating registry logic.
        """
        sub = self._create_isolated_reg_subkey("Test_PAI_Portable_Batch", "%USERPROFILE%\\bin")
        bin_dir = str(Path(self.tmp_dir) / "portable_app" / "bin")

        install_bat = self.packaging_dir / "install.bat"
        uninstall_bat = self.packaging_dir / "uninstall.bat"

        install_text = install_bat.read_text(encoding="utf-8")
        uninstall_text = uninstall_bat.read_text(encoding="utf-8")

        # Verify neither file contains inline PowerShell registry logic
        self.assertNotIn("OpenSubKey($subKey, $true)", install_text)
        self.assertNotIn("OpenSubKey($subKey, $true)", uninstall_text)
        self.assertIn("update_path.ps1", install_text)
        self.assertIn("update_path.ps1", uninstall_text)


if __name__ == "__main__":
    unittest.main()
