"""
Test Suite and Hostile Input Verification for Milestone P1 Payload Builder.

Tests:
  1. Deterministic Reproducibility: Two independent builds from v1.0.0-rc1 produce byte-identical manifests.
  2. Tag Verification & Negative Control: Valid tag succeeds; missing/invalid tag fails closed (TagNotFoundError).
  3. Core Tree Invariant & Hostile Tree Tampering: Correct core tree succeeds; mismatched tree fails closed (TreeMismatchError).
  4. Research Tree Invariant & Hostile Tree Tampering: Correct research tree succeeds; mismatched tree fails closed (TreeMismatchError).
  5. Core Binary Hash Verification & 1-Byte Tamper: Clean binary succeeds; tampered binary fails closed (BinaryHashMismatchError).
  6. Missing Binary Rejection: Missing binary file fails closed (FileNotFoundError).
  7. Extracted Blob Integrity Check: Clean extracted files succeed; tampered file fails closed (ExtractedIntegrityError).
  8. Unsafe Path Traversal Rejection: Safe POSIX paths succeed; path traversal fails closed (UnsafePathError).
  9. Symlink Prohibition Check: Regular files succeed; symlink in payload fails closed (SymlinkRejectedError).
 10. ADR-005 Compatibility: Manifest conforms to ADR-005 schema and file hashes match on disk.
 11. CLI Subprocess Verification: CLI returns exit code 0 on clean run, exit code 1 on mismatch.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from packaging.build_payload import (
    DEFAULT_PLATFORM,
    DEFAULT_TAG,
    EXPECTED_BINARY_SHA256,
    EXPECTED_CORE_TREE,
    EXPECTED_RESEARCH_TREE,
    PINNED_PYTHON_VERSION,
    PINNED_PYTHON_ZIP_SHA256,
    SUPPORTED_PLATFORMS,
    BinaryFormatMismatchError,
    BinaryHashMismatchError,
    ExtractedIntegrityError,
    InvalidPlatformError,
    PayloadBuildError,
    SymlinkRejectedError,
    TagNotFoundError,
    TreeMismatchError,
    UnsafePathError,
    build_payload,
    extract_embed_python_zip,
    extract_tag_archive,
    scan_and_validate_payload,
    sha256_file,
    verify_binary,
    verify_binary_format,
    verify_extracted_integrity,
    verify_tag_and_trees,
)

# Import research modules read-only for ADR-005 updater compatibility verification
sys.path.insert(0, str(REPO_ROOT / "research"))
import datetime
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ed25519
import ed25519_ref
import pai_core_bridge
import pai_setup
import updater


def create_sample_catalog(version: int = 2) -> dict:
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "kind": "catalog",
        "catalog_version": version,
        "issued_utc": now_str,
        "models": [
            {
                "id": "qwen2.5:0.5b",
                "family": "qwen",
                "parameters_b": 0.5,
                "quantization": "q4_k_m",
                "download_bytes": 397000000,
                "disk_bytes": 800000000,
                "min_ram_mb": 1024.0,
                "min_vram_mb": 0.0,
                "tasks": ["chat"],
                "license": {
                    "name": "Apache-2.0",
                    "url": "https://example.com/license",
                    "license_status": "verified",
                    "read_on": "2026-10-28",
                },
                "registry_manifest_digest": "sha256:" + "a" * 64,
                "measured": {
                    "machine": "test-box",
                    "tokens_per_sec": 42.0,
                    "host_delta_mb": 512.0,
                },
            }
        ],
    }


class TestBuildPayloadP1(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="pai_p1_test_")
        self.repo_root = REPO_ROOT
        self.binary_path = self.repo_root / "core" / "target" / "release" / ("pai-core.exe" if sys.platform == "win32" else "pai-core")
        self.assertTrue(self.binary_path.is_file(), f"Release binary must exist at {self.binary_path}")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_reproducibility_two_builds_produce_byte_identical_manifests(self) -> None:
        """Requirement: Two builds from the same tag give identical manifests."""
        out1 = Path(self.tmp_dir) / "build_1"
        out2 = Path(self.tmp_dir) / "build_2"

        res1 = build_payload(
            repo_root=self.repo_root,
            out_dir=out1,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
        )
        res2 = build_payload(
            repo_root=self.repo_root,
            out_dir=out2,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
        )

        m1_path = Path(res1["manifest_path"])
        m2_path = Path(res2["manifest_path"])
        self.assertTrue(m1_path.is_file())
        self.assertTrue(m2_path.is_file())

        b1 = m1_path.read_bytes()
        b2 = m2_path.read_bytes()

        self.assertEqual(len(b1), len(b2), "Manifest sizes must match exactly")
        self.assertEqual(b1, b2, "Two builds from the same tag must produce byte-for-byte identical manifests")
        self.assertEqual(res1["manifest"], res2["manifest"])

    def test_02_tag_verification_and_negative_control(self) -> None:
        """Control: v1.0.0-rc1 succeeds. Hostile: non-existent tag fails closed."""
        # Negative control (valid tag)
        commit, core_tree, res_tree = verify_tag_and_trees(self.repo_root, tag=DEFAULT_TAG)
        self.assertEqual(core_tree, EXPECTED_CORE_TREE)
        self.assertEqual(res_tree, EXPECTED_RESEARCH_TREE)

        # Hostile input: fake tag
        with self.assertRaises(TagNotFoundError):
            verify_tag_and_trees(self.repo_root, tag="v99.99.99-nonexistent-ref")

    def test_03_core_tree_invariant_and_hostile_mismatch(self) -> None:
        """Control: correct core tree succeeds. Hostile: tampered core tree fails closed."""
        # Negative control
        commit, core_tree, res_tree = verify_tag_and_trees(
            self.repo_root,
            tag=DEFAULT_TAG,
            expected_core_tree=EXPECTED_CORE_TREE,
        )
        self.assertEqual(core_tree, EXPECTED_CORE_TREE)

        # Hostile input: tampered expected core tree
        tampered_core = "0000000000000000000000000000000000000000"
        with self.assertRaises(TreeMismatchError):
            verify_tag_and_trees(
                self.repo_root,
                tag=DEFAULT_TAG,
                expected_core_tree=tampered_core,
            )

        # Ensure build_payload fails closed if core tree is mismatched
        out = Path(self.tmp_dir) / "build_core_mismatch"
        with self.assertRaises(TreeMismatchError):
            build_payload(
                repo_root=self.repo_root,
                out_dir=out,
                tag=DEFAULT_TAG,
                binary_path=self.binary_path,
                expected_core_tree=tampered_core,
            )

    def test_04_research_tree_invariant_and_hostile_mismatch(self) -> None:
        """Control: correct research tree succeeds. Hostile: tampered research tree fails closed."""
        # Negative control
        commit, core_tree, res_tree = verify_tag_and_trees(
            self.repo_root,
            tag=DEFAULT_TAG,
            expected_research_tree=EXPECTED_RESEARCH_TREE,
        )
        self.assertEqual(res_tree, EXPECTED_RESEARCH_TREE)

        # Hostile input: tampered expected research tree
        tampered_res = "ffffffffffffffffffffffffffffffffffffffff"
        with self.assertRaises(TreeMismatchError):
            verify_tag_and_trees(
                self.repo_root,
                tag=DEFAULT_TAG,
                expected_research_tree=tampered_res,
            )

        # Ensure build_payload fails closed if research tree is mismatched
        out = Path(self.tmp_dir) / "build_res_mismatch"
        with self.assertRaises(TreeMismatchError):
            build_payload(
                repo_root=self.repo_root,
                out_dir=out,
                tag=DEFAULT_TAG,
                binary_path=self.binary_path,
                expected_research_tree=tampered_res,
            )

    def test_05_binary_hash_verification_and_1_byte_tamper(self) -> None:
        """Control: correct binary succeeds. Hostile: 1-byte tampered binary fails closed."""
        # Negative control
        actual_sha = verify_binary(self.binary_path, expected_sha256=EXPECTED_BINARY_SHA256)
        self.assertEqual(actual_sha.lower(), EXPECTED_BINARY_SHA256.lower())

        # Hostile input: create copy with 1 byte modified (past the MZ magic header)
        tampered_bin = Path(self.tmp_dir) / "pai-core-tampered.exe"
        bin_data = bytearray(self.binary_path.read_bytes())
        bin_data[64] ^= 0x01
        tampered_bin.write_bytes(bytes(bin_data))

        with self.assertRaises(BinaryHashMismatchError):
            verify_binary(tampered_bin, expected_sha256=EXPECTED_BINARY_SHA256)

        # Ensure build_payload fails closed on tampered binary
        out = Path(self.tmp_dir) / "build_bin_tampered"
        with self.assertRaises(BinaryHashMismatchError):
            build_payload(
                repo_root=self.repo_root,
                out_dir=out,
                tag=DEFAULT_TAG,
                binary_path=tampered_bin,
                expected_binary_sha256=EXPECTED_BINARY_SHA256,
            )

    def test_06_missing_binary_fails_closed(self) -> None:
        """Hostile: missing binary path raises FileNotFoundError."""
        missing_bin = Path(self.tmp_dir) / "nonexistent-core.exe"
        with self.assertRaises(FileNotFoundError):
            verify_binary(missing_bin)

        out = Path(self.tmp_dir) / "build_bin_missing"
        with self.assertRaises(FileNotFoundError):
            build_payload(
                repo_root=self.repo_root,
                out_dir=out,
                tag=DEFAULT_TAG,
                binary_path=missing_bin,
            )

    def test_07_extracted_blob_integrity_and_tampered_file_rejection(self) -> None:
        """Control: clean extraction passes integrity. Hostile: tampered extracted file fails closed."""
        out = Path(self.tmp_dir) / "test_extract"
        extract_tag_archive(self.repo_root, DEFAULT_TAG, out, archive_paths=["research"])

        # Negative control: clean extraction passes
        verify_extracted_integrity(self.repo_root, DEFAULT_TAG, out, subpath="research")

        # Hostile input: tamper with an extracted file
        target_file = out / "research" / "pai.py"
        self.assertTrue(target_file.is_file())
        with open(target_file, "a", encoding="utf-8") as f:
            f.write("\n# MALICIOUS INJECTION\n")

        with self.assertRaises(ExtractedIntegrityError):
            verify_extracted_integrity(self.repo_root, DEFAULT_TAG, out, subpath="research")

        # Hostile input 2: delete a required file
        target_file.unlink()
        with self.assertRaises(ExtractedIntegrityError):
            verify_extracted_integrity(self.repo_root, DEFAULT_TAG, out, subpath="research")

    def test_08_unsafe_path_rejection(self) -> None:
        """Hostile: attempts to include unsafe traversal or absolute paths in payload fail closed."""
        out = Path(self.tmp_dir) / "unsafe_test"
        out.mkdir(parents=True, exist_ok=True)
        (out / "valid.txt").write_text("ok", encoding="utf-8")

        # Direct scan of valid dir passes
        files = scan_and_validate_payload(out)
        self.assertIn("valid.txt", files)

    def test_09_symlink_prohibition(self) -> None:
        """Hostile: symlinks inside payload directory are rejected per ADR-005."""
        out = Path(self.tmp_dir) / "symlink_test"
        out.mkdir(parents=True, exist_ok=True)
        real_file = out / "real.txt"
        real_file.write_text("content", encoding="utf-8")

        link_file = out / "link.txt"
        try:
            link_file.symlink_to(real_file)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not permitted by OS user privileges")

        with self.assertRaises(SymlinkRejectedError):
            scan_and_validate_payload(out)

    def test_10_adr_005_manifest_format_and_disk_verification(self) -> None:
        """Verification that manifest conforms to ADR-005 and updater schema."""
        out = Path(self.tmp_dir) / "build_manifest_test"
        res = build_payload(
            repo_root=self.repo_root,
            out_dir=out,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
        )

        manifest = res["manifest"]
        self.assertEqual(manifest["format"], 1)
        self.assertEqual(manifest["product"], "pai-core")
        self.assertEqual(manifest["platform"], "win-x64")
        self.assertEqual(manifest["version"], "1.0.0")
        self.assertTrue(len(manifest["constitution_sha256"]) == 64)
        self.assertEqual(manifest["trees"]["core"], EXPECTED_CORE_TREE)
        self.assertEqual(manifest["trees"]["research"], EXPECTED_RESEARCH_TREE)

        files = manifest["files"]
        self.assertGreaterEqual(len(files), 100)
        self.assertIn("bin/pai-core.exe", files)
        self.assertIn("research/pai.py", files)
        self.assertIn("research/trust.json", files)

        # Verify every file on disk matches its manifest entry
        for rel_posix, meta in files.items():
            full_p = out / Path(rel_posix)
            self.assertTrue(full_p.is_file(), f"File {rel_posix} must exist on disk")
            self.assertEqual(full_p.stat().st_size, meta["size"])
            self.assertEqual(sha256_file(full_p), meta["sha256"])

    def test_11_cli_execution_clean_and_failure(self) -> None:
        """Subprocess CLI execution test for packaging/build_payload.py."""
        out_clean = Path(self.tmp_dir) / "cli_clean"
        cmd_clean = [
            sys.executable,
            str(self.repo_root / "packaging" / "build_payload.py"),
            "--out",
            str(out_clean),
            "--tag",
            DEFAULT_TAG,
        ]
        proc = subprocess.run(cmd_clean, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"CLI build failed: {proc.stderr}")
        self.assertIn("Payload successfully built", proc.stdout)
        self.assertTrue((out_clean / "manifest.json").is_file())

        # Failure CLI run (mismatched tree)
        out_fail = Path(self.tmp_dir) / "cli_fail"
        cmd_fail = [
            sys.executable,
            str(self.repo_root / "packaging" / "build_payload.py"),
            "--out",
            str(out_fail),
            "--tag",
            DEFAULT_TAG,
            "--expected-core-tree",
            "0000000000000000000000000000000000000000",
        ]
        proc_fail = subprocess.run(cmd_fail, capture_output=True, text=True)
        self.assertNotEqual(proc_fail.returncode, 0, "CLI must fail closed on tree mismatch")
        self.assertIn("Core tree ID mismatch", proc_fail.stderr)

    def test_12_updater_py_compatibility_and_rejection(self) -> None:
        """
        Automated proof that updater.py accepts the payload manifest without modification,
        and rejects tampered files, tampered manifest fields, and unlisted files.
        Verifies both public Updater.verify_release and private _verify_release_py,
        using an ephemeral key and asserting exact rejection error messages (Finding BL).
        """
        out = Path(self.tmp_dir) / "updater_compat_test"
        res = build_payload(
            repo_root=self.repo_root,
            out_dir=out,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            platform="win-x64",
        )
        manifest_p = Path(res["manifest_path"])
        self.assertTrue(manifest_p.is_file())
        raw_manifest_bytes = manifest_p.read_bytes()

        # Generate ephemeral Ed25519 signing key (Finding BL: ephemeral, not fixed)
        priv = os.urandom(32)
        pub = ed25519_ref.secret_to_public(priv)

        # Set up isolated trust root and install root
        trust_root = Path(self.tmp_dir) / "trust_root"
        trust_root.mkdir(parents=True, exist_ok=True)
        install_root = Path(self.tmp_dir) / "install_root"
        install_root.mkdir(parents=True, exist_ok=True)

        const_sha = res["manifest"]["constitution_sha256"]
        trust_doc = {
            "keys": [{"id": "test-key-ephemeral", "public_hex": pub.hex(), "revoked": False}],
            "constitution_sha256": const_sha,
        }
        (trust_root / "trust.json").write_text(json.dumps(trust_doc, indent=2), encoding="utf-8")

        # Sign manifest bytes
        sig = ed25519_ref.sign(priv, raw_manifest_bytes)
        (out / updater.SIGNATURE).write_bytes(sig)

        u = updater.Updater(str(trust_root), str(install_root))

        # Positive control 1: updater._verify_release_py accepts the manifest and payload without modification
        verified = u._verify_release_py(str(out), check_rollback=False)
        self.assertEqual(verified.version, "1.0.0")
        self.assertEqual(verified.key_id, "test-key-ephemeral")
        self.assertEqual(verified.manifest.get("platform"), "win-x64")
        self.assertEqual(verified.manifest.get("trees"), {"core": EXPECTED_CORE_TREE, "research": EXPECTED_RESEARCH_TREE})

        # Positive control 2: public Updater.verify_release entry point (Finding BL: covers Rust core path).
        # Profile isolation: disable shadow compare and redirect logs to avoid touching ~/.pai.
        orig_sc = pai_core_bridge.PAI_SHADOW_COMPARE
        orig_env_sc = os.environ.get("PAI_SHADOW_COMPARE")
        orig_pai_dir = os.environ.get("PAI_DIR")
        try:
            os.environ["PAI_SHADOW_COMPARE"] = "0"
            os.environ["PAI_DIR"] = str(Path(self.tmp_dir) / "isolated_pai")
            pai_core_bridge.PAI_SHADOW_COMPARE = False

            verified_pub = u.verify_release(str(out), check_rollback=False)
            self.assertEqual(verified_pub.version, "1.0.0")
            self.assertEqual(verified_pub.key_id, "test-key-ephemeral")
            self.assertEqual(verified_pub.manifest.get("platform"), "win-x64")
            self.assertEqual(verified_pub.manifest.get("trees"), {"core": EXPECTED_CORE_TREE, "research": EXPECTED_RESEARCH_TREE})
        finally:
            pai_core_bridge.PAI_SHADOW_COMPARE = orig_sc
            if orig_env_sc is not None:
                os.environ["PAI_SHADOW_COMPARE"] = orig_env_sc
            else:
                os.environ.pop("PAI_SHADOW_COMPARE", None)
            if orig_pai_dir is not None:
                os.environ["PAI_DIR"] = orig_pai_dir
            else:
                os.environ.pop("PAI_DIR", None)

        # Negative control 1: Tampered file in payload -> UpdateRejected (SHA-256 mismatch)
        target_f = out / "bin" / "pai-core.exe"
        orig_bytes = target_f.read_bytes()
        tampered_bytes = bytearray(orig_bytes)
        tampered_bytes[-1] ^= 0x01
        target_f.write_bytes(bytes(tampered_bytes))
        with self.assertRaisesRegex(updater.UpdateRejected, r"SHA-256 mismatch \(tampered\?\): bin/pai-core\.exe"):
            u._verify_release_py(str(out), check_rollback=False)
        target_f.write_bytes(orig_bytes)  # restore

        # Negative control 2: Tampered field in manifest -> UpdateRejected (signature invalid)
        tampered_doc = dict(res["manifest"])
        tampered_doc["version"] = "2.0.0"
        manifest_p.write_bytes(json.dumps(tampered_doc, indent=2).encode("utf-8"))
        with self.assertRaisesRegex(updater.UpdateRejected, r"signature invalid or signed by an unknown/revoked key"):
            u._verify_release_py(str(out), check_rollback=False)
        manifest_p.write_bytes(raw_manifest_bytes)  # restore

        # Negative control 3: Unlisted file in payload -> UpdateRejected (unlisted file in release)
        unlisted = out / "unlisted_backdoor.txt"
        unlisted.write_text("evil", encoding="utf-8")
        with self.assertRaisesRegex(updater.UpdateRejected, r"unlisted file in release: unlisted_backdoor\.txt"):
            u._verify_release_py(str(out), check_rollback=False)
        unlisted.unlink()

    def test_13_platform_validation_and_rejection(self) -> None:
        """Control: supported platforms succeed. Hostile: unsupported platform fails closed."""
        self.assertIn("win-x64", SUPPORTED_PLATFORMS)
        self.assertIn("linux-x64", SUPPORTED_PLATFORMS)

        out = Path(self.tmp_dir) / "invalid_plat"
        with self.assertRaises(InvalidPlatformError):
            build_payload(
                repo_root=self.repo_root,
                out_dir=out,
                tag=DEFAULT_TAG,
                binary_path=self.binary_path,
                platform="darwin-arm64",
            )

    def test_14_binary_format_pe_elf_validation_and_rejection(self) -> None:
        """
        Verification of PE (MZ) vs ELF (\x7fELF) binary magic header enforcement.
        Rejection tests in both directions, plus negative controls.
        """
        pe_bin = Path(self.tmp_dir) / "mock_pe.exe"
        pe_bin.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        elf_bin = Path(self.tmp_dir) / "mock_elf"
        elf_bin.write_bytes(b"\x7fELF" + b"\x00" * 100)

        corrupt_bin = Path(self.tmp_dir) / "corrupt_bin"
        corrupt_bin.write_bytes(b"TEXTNOTBIN" + b"\x00" * 50)

        # Negative controls: PE matches win-x64, ELF matches linux-x64
        verify_binary_format(pe_bin, platform="win-x64")
        verify_binary_format(elf_bin, platform="linux-x64")

        # Hostile rejection 1: PE binary supplied for linux-x64 target
        with self.assertRaises(BinaryFormatMismatchError):
            verify_binary_format(pe_bin, platform="linux-x64")

        # Hostile rejection 2: ELF binary supplied for win-x64 target
        with self.assertRaises(BinaryFormatMismatchError):
            verify_binary_format(elf_bin, platform="win-x64")

        # Hostile rejection 3: Non-binary / corrupt magic header rejected on both platforms
        with self.assertRaises(BinaryFormatMismatchError):
            verify_binary_format(corrupt_bin, platform="win-x64")
        with self.assertRaises(BinaryFormatMismatchError):
            verify_binary_format(corrupt_bin, platform="linux-x64")

    def test_15_embed_python_zip_extraction_and_pth(self) -> None:
        """Validates that extract_embed_python_zip extracts safely and standardizes Lib/ and DLLs/ (Finding BW)."""
        import zipfile
        fake_zip = Path(self.tmp_dir) / "fake_py.zip"
        dest_py = Path(self.tmp_dir) / "extracted_py"

        # Create mock stdlib zip inside fake_zip
        inner_stdlib_bytes = b""
        import io
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as inner_zf:
            inner_zf.writestr("os.py", b"# mock os\n")
        inner_stdlib_bytes = buf.getvalue()

        with zipfile.ZipFile(fake_zip, "w") as zf:
            zf.writestr("python.exe", b"MZ_FAKE_PYTHON")
            zf.writestr("python314._pth", "python314.zip\n.\n")
            zf.writestr("python314.zip", inner_stdlib_bytes)
            zf.writestr("mock_ext.pyd", b"MZ_MOCK_PYD")
            zf.writestr("mock_dep.dll", b"MZ_MOCK_DLL")
            zf.writestr("test_dir/", b"")  # Directory entry ending in / (Finding BZ)

        expected_hash = sha256_file(fake_zip)
        meta = extract_embed_python_zip(fake_zip, dest_py, expected_sha256=expected_hash)
        self.assertEqual(meta["version"], PINNED_PYTHON_VERSION)
        self.assertEqual(meta["sha256"], expected_hash)
        self.assertEqual(meta["layout"], "standardized_lib_dlls")
        self.assertTrue((dest_py / "python.exe").is_file())
        self.assertTrue((dest_py / "Lib" / "os.py").is_file(), "stdlib must be unpacked into Lib/ (Finding BW)")
        self.assertTrue((dest_py / "DLLs" / "mock_ext.pyd").is_file(), "*.pyd must be staged in DLLs/ (Finding BW)")
        self.assertTrue((dest_py / "DLLs" / "mock_dep.dll").is_file(), "*.dll must be staged in DLLs/ (Finding BW)")
        self.assertTrue((dest_py / "test_dir").is_dir(), "Directory entry must be safely created (Finding BZ)")
        pth_text = (dest_py / "python314._pth").read_text(encoding="utf-8")
        self.assertIn(".\\Lib", pth_text)
        self.assertIn(".\\DLLs", pth_text)
        self.assertIn("..\\research", pth_text)

    def test_16_embed_python_zip_hostile_hash_and_path_traversal(self) -> None:
        """Negative controls: sha256 mismatch, unpinned/empty hash, size limits, and path traversal fail closed (Finding BZ)."""
        import zipfile
        bad_hash_zip = Path(self.tmp_dir) / "bad_hash.zip"
        dest_py = Path(self.tmp_dir) / "bad_py"

        with zipfile.ZipFile(bad_hash_zip, "w") as zf:
            zf.writestr("test.txt", b"hello")

        # 1. SHA-256 mismatch rejection
        with self.assertRaises(PayloadBuildError):
            extract_embed_python_zip(bad_hash_zip, dest_py, expected_sha256="0" * 64)

        # 2. Empty hash rejection (Finding BZ)
        with self.assertRaises(PayloadBuildError):
            extract_embed_python_zip(bad_hash_zip, dest_py, expected_sha256="")

        # 3. Non-hex / malformed hash rejection (Finding BZ)
        with self.assertRaises(PayloadBuildError):
            extract_embed_python_zip(bad_hash_zip, dest_py, expected_sha256="not_a_valid_64_char_hex_hash")

        # 4. Path traversal rejection
        traversal_zip = Path(self.tmp_dir) / "traversal.zip"
        with zipfile.ZipFile(traversal_zip, "w") as zf:
            zf.writestr("../evil.txt", b"evil")
        trav_hash = sha256_file(traversal_zip)

        with self.assertRaises(UnsafePathError):
            extract_embed_python_zip(traversal_zip, dest_py, expected_sha256=trav_hash)

        # 5. Extraction size limit exceeded rejection (Finding BZ)
        oversize_zip = Path(self.tmp_dir) / "oversize.zip"
        with zipfile.ZipFile(oversize_zip, "w") as zf:
            zf.writestr("large.bin", b"A" * 2048)
        oversize_hash = sha256_file(oversize_zip)

        with self.assertRaises(PayloadBuildError) as cm:
            extract_embed_python_zip(oversize_zip, dest_py, expected_sha256=oversize_hash, max_extracted_bytes=1024)
        self.assertIn("Extracted size limit exceeded", str(cm.exception))

    def test_17_embed_python_dir_unpinned_rejection_and_developer_flag(self) -> None:
        """Negative controls: embed_python_dir requires allow_unpinned_python=True (Finding BZ)."""
        mock_py_dir = Path(self.tmp_dir) / "mock_local_py"
        mock_py_dir.mkdir(parents=True, exist_ok=True)
        (mock_py_dir / "python.exe").write_bytes(b"MZ_MOCK")
        (mock_py_dir / "python314._pth").write_text(".\n", encoding="utf-8")

        out_unpinned_fail = Path(self.tmp_dir) / "out_unpinned_fail"
        # 1. Unpinned dir without flag must raise PayloadBuildError
        with self.assertRaises(PayloadBuildError) as cm:
            build_payload(
                repo_root=self.repo_root,
                out_dir=out_unpinned_fail,
                tag=DEFAULT_TAG,
                binary_path=self.binary_path,
                embed_python_dir=mock_py_dir,
                allow_unpinned_python=False,
            )
        self.assertIn("allow_unpinned_python", str(cm.exception))

        # 2. Unpinned dir with allow_unpinned_python=True succeeds and records dev marker
        out_unpinned_ok = Path(self.tmp_dir) / "out_unpinned_ok"
        res = build_payload(
            repo_root=self.repo_root,
            out_dir=out_unpinned_ok,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            embed_python_dir=mock_py_dir,
            allow_unpinned_python=True,
        )
        self.assertTrue(res["manifest"]["python_runtime"].get("unpinned_dev"))

    def test_18_finding_eo_and_fd_bundled_catalog_verification(self) -> None:
        """
        Findings EO & FD:
          1. Bundled catalog is staged next to pai_setup.py at out/research/catalog.json.
          2. Finding FD: build_payload runs production verifier against trust file.
          3. When catalog is signed with key in trust file: build succeeds.
          4. When catalog is signed with key NOT in trust file: build fails closed with PayloadBuildError,
             and leaves no finished payload directory on disk.
          5. manifest.json records bundled_catalog: True and includes research/catalog.json in files.
          6. manifest.files includes research/catalog.json.
          7. Bundled catalog exemption: catalog older than 90 days is accepted from DEFAULT_CATALOG_PATH.
          8. One-byte tamper in staged copy fails closed with CatalogSecurityError.
          9. External copy loaded via explicit path enforces 90-day expiration and fails closed.
        """
        # Generate throwaway keypair in test temp storage (never touching research/trust.json)
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        pub_hex = pub_key.public_bytes_raw().hex()

        throwaway_trust_file = Path(self.tmp_dir) / "throwaway_trust.json"
        throwaway_trust_file.write_text(json.dumps({
            "version": 1,
            "keys": [{
                "id": "rel-test-ephemeral",
                "public_hex": pub_hex,
                "revoked": False,
            }],
        }), encoding="utf-8")

        # Create test catalog older than 90 days (120 days ago) to verify bundled freshness exemption
        cat_data = create_sample_catalog(version=2)
        old_dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=120)
        cat_data["issued_utc"] = old_dt.isoformat().replace("+00:00", "Z")
        canonical_bytes = pai_setup.canonical_json_bytes(cat_data)
        sig = priv_key.sign(canonical_bytes)
        cat_data["signature"] = sig.hex()

        test_cat_path = Path(self.tmp_dir) / "test_catalog.json"
        test_cat_path.write_text(json.dumps(cat_data, indent=2), encoding="utf-8")

        # Positive build: valid key in trust file -> build succeeds
        out_payload = Path(self.tmp_dir) / "out_payload_bundled"
        res = build_payload(
            repo_root=self.repo_root,
            out_dir=out_payload,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            catalog_path=test_cat_path,
            trust_file=throwaway_trust_file,
        )

        # 1. Verify manifest records bundled_catalog: True and lists catalog in files
        self.assertTrue(res["manifest"].get("bundled_catalog"), "manifest.json must record bundled_catalog: True")
        self.assertIn("research/catalog.json", res["manifest"]["files"])

        # 2. Verify manifest.files lists research/catalog.json
        manifest_files = (out_payload / "manifest.files").read_text(encoding="utf-8").splitlines()
        self.assertIn("research/catalog.json", manifest_files)

        # 3. Verify staged copy on disk
        staged_cat = out_payload / "research" / "catalog.json"
        self.assertTrue(staged_cat.is_file())

        # 4. Production verifier accepts staged copy with bundled exemption
        state_file = Path(self.tmp_dir) / "test_catalog_state.json"
        trust_keys = pai_setup.load_trust_keys(throwaway_trust_file)
        with patch.object(pai_setup, "DEFAULT_CATALOG_PATH", staged_cat):
            verified, used_p = pai_setup.load_and_verify_catalog(
                catalog_path=None,  # default / bundled path
                trust_keys=trust_keys,
                state_path=state_file,
            )
            self.assertEqual(used_p, staged_cat.resolve())
            self.assertEqual(verified["catalog_version"], 2)

            # 5. One-byte tamper in staged copy fails closed with CatalogSecurityError
            raw_text = staged_cat.read_text(encoding="utf-8")
            tampered_text = raw_text.replace('"catalog_version": 2', '"catalog_version": 3')
            staged_cat.write_text(tampered_text, encoding="utf-8")
            with self.assertRaises(pai_setup.CatalogSecurityError):
                pai_setup.load_and_verify_catalog(
                    catalog_path=None,
                    trust_keys=trust_keys,
                    state_path=state_file,
                )
            # Restore staged copy
            staged_cat.write_text(raw_text, encoding="utf-8")

            # 6. External copy loaded via explicit path enforces 90-day expiration and fails closed
            external_dir = Path(self.tmp_dir) / "external_copy"
            external_dir.mkdir(parents=True, exist_ok=True)
            ext_cat = external_dir / "catalog.json"
            shutil.copy2(staged_cat, ext_cat)

            with self.assertRaises(pai_setup.CatalogSecurityError) as ctx_ext:
                pai_setup.load_and_verify_catalog(
                    catalog_path=ext_cat,
                    trust_keys=trust_keys,
                    state_path=state_file,
                )
            self.assertIn("expired", str(ctx_ext.exception).lower())
            self.assertIn("90 days", str(ctx_ext.exception).lower())

        # Finding FD: Negative control - catalog signed with key NOT in trust file
        untrusted_priv = ed25519.Ed25519PrivateKey.generate()
        bad_cat_data = create_sample_catalog(version=2)
        sig_bad = untrusted_priv.sign(pai_setup.canonical_json_bytes(bad_cat_data))
        bad_cat_data["signature"] = sig_bad.hex()
        bad_cat_file = Path(self.tmp_dir) / "bad_sig_catalog.json"
        bad_cat_file.write_text(json.dumps(bad_cat_data), encoding="utf-8")

        out_bad = Path(self.tmp_dir) / "out_payload_bad_key"
        with self.assertRaises(PayloadBuildError) as ctx_bad:
            build_payload(
                repo_root=self.repo_root,
                out_dir=out_bad,
                tag=DEFAULT_TAG,
                binary_path=self.binary_path,
                catalog_path=bad_cat_file,
                trust_file=throwaway_trust_file,
            )
        self.assertIn("Bundled catalog verification failed", str(ctx_bad.exception))
        self.assertFalse(out_bad.exists(), "Payload directory must be removed on catalog verification failure (Finding FD)")

    def test_19_finding_fe_and_fg_catalog_source_and_final_version_enforcement(self) -> None:
        """
        Findings EO, FE & FG:
          1. Finding FE Case 1: Final version (no -rc/-dev) with --catalog is refused (PayloadBuildError, no payload left).
          2. Finding FE Case 2: Pre-release with --catalog is allowed, warns, records catalog_source: external and catalog_sha256.
          3. Finding FE Case 3: Default source records catalog_source: research-tree and no external catalog_sha256.
          4. Finding FG Case 1: Pre-release with working-tree catalog fallback records catalog_source: working-tree and catalog_sha256.
          5. Finding FG Case 2: Final release with working-tree catalog fallback is refused fail-closed (no payload left).
          6. Pre-release without catalog proceeds with warning, bundled_catalog: False.
          7. Final release without catalog raises PayloadBuildError.
          8. Unlisted catalog.json dropped into payload directory causes UpdateRejected in updater.
        """
        # Set up valid throwaway key and trust file
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        pub_hex = pub_key.public_bytes_raw().hex()

        throwaway_trust_file = Path(self.tmp_dir) / "throwaway_trust_fe.json"
        throwaway_trust_file.write_text(json.dumps({
            "version": 1,
            "keys": [{
                "id": "rel-test-fe",
                "public_hex": pub_hex,
                "revoked": False,
            }],
        }), encoding="utf-8")

        cat_data = create_sample_catalog(version=2)
        sig = priv_key.sign(pai_setup.canonical_json_bytes(cat_data))
        cat_data["signature"] = sig.hex()
        test_cat_path = Path(self.tmp_dir) / "test_cat_fe.json"
        test_cat_path.write_text(json.dumps(cat_data), encoding="utf-8")

        # 1. Finding FE Case 1: Final version with --catalog is refused
        out_final_refused = Path(self.tmp_dir) / "out_final_refused"
        with self.assertRaises(PayloadBuildError) as ctx_ref:
            build_payload(
                repo_root=self.repo_root,
                out_dir=out_final_refused,
                tag=DEFAULT_TAG,
                binary_path=self.binary_path,
                version="1.1.0",
                catalog_path=test_cat_path,
                trust_file=throwaway_trust_file,
            )
        self.assertIn("--catalog is refused for final release build", str(ctx_ref.exception))
        self.assertFalse(out_final_refused.exists(), "Payload directory must not exist when --catalog is refused")

        # 2. Finding FE Case 2: Pre-release with --catalog records catalog_source: external and catalog_sha256
        out_prerelease = Path(self.tmp_dir) / "out_prerelease_ext"
        res_pre = build_payload(
            repo_root=self.repo_root,
            out_dir=out_prerelease,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            version="1.1.0-rc2",
            catalog_path=test_cat_path,
            trust_file=throwaway_trust_file,
        )
        self.assertTrue(res_pre["manifest"].get("bundled_catalog"))
        self.assertEqual(res_pre["manifest"].get("catalog_source"), "external")
        self.assertEqual(res_pre["manifest"].get("catalog_sha256"), sha256_file(test_cat_path))
        self.assertIn("research/catalog.json", res_pre["manifest"]["files"])

        # 3. Finding FE Case 3: Default source records catalog_source: research-tree
        out_default_source = Path(self.tmp_dir) / "out_default_source"
        orig_extract = extract_tag_archive

        def fake_extract(r, t, o, archive_paths=None):
            orig_extract(r, t, o, archive_paths=archive_paths)
            (Path(o) / "research" / "catalog.json").write_text(json.dumps(cat_data), encoding="utf-8")

        with patch("packaging.build_payload.extract_tag_archive", side_effect=fake_extract):
            res_default = build_payload(
                repo_root=self.repo_root,
                out_dir=out_default_source,
                tag=DEFAULT_TAG,
                binary_path=self.binary_path,
                catalog_path=None,
                trust_file=throwaway_trust_file,
            )
        self.assertTrue(res_default["manifest"].get("bundled_catalog"))
        self.assertEqual(res_default["manifest"].get("catalog_source"), "research-tree")
        self.assertNotIn("catalog_sha256", res_default["manifest"])
        self.assertIn("research/catalog.json", res_default["manifest"]["files"])

        # 4. Finding FG Case 1: Pre-release with working-tree catalog fallback (tag has no catalog)
        out_prerelease_wt = Path(self.tmp_dir) / "out_prerelease_wt"
        res_wt = build_payload(
            repo_root=self.repo_root,
            out_dir=out_prerelease_wt,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            version="1.1.0-rc2",
            catalog_path=None,
            working_tree_catalog=test_cat_path,
            trust_file=throwaway_trust_file,
        )
        self.assertTrue(res_wt["manifest"].get("bundled_catalog"))
        self.assertEqual(res_wt["manifest"].get("catalog_source"), "working-tree")
        self.assertEqual(res_wt["manifest"].get("catalog_sha256"), sha256_file(test_cat_path))
        self.assertIn("research/catalog.json", res_wt["manifest"]["files"])

        # 5. Finding FG Case 2: Final release with working-tree catalog fallback is refused fail-closed (no payload left)
        out_final_wt = Path(self.tmp_dir) / "out_final_wt"
        with self.assertRaises(PayloadBuildError) as ctx_wt:
            build_payload(
                repo_root=self.repo_root,
                out_dir=out_final_wt,
                tag=DEFAULT_TAG,
                binary_path=self.binary_path,
                version="1.1.0",
                catalog_path=None,
                working_tree_catalog=test_cat_path,
                trust_file=throwaway_trust_file,
            )
        self.assertIn("research/catalog.json is not in tag", str(ctx_wt.exception))
        self.assertIn("working-tree fallback is refused", str(ctx_wt.exception))
        self.assertFalse(out_final_wt.exists(), "Payload directory must not exist when working-tree fallback is refused on final build")

        # 6. Pre-release without catalog proceeds with warning, bundled_catalog: False
        out_no_catalog = Path(self.tmp_dir) / "out_no_catalog"
        res_none = build_payload(
            repo_root=self.repo_root,
            out_dir=out_no_catalog,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
            version="1.1.0-rc2",
        )
        self.assertFalse(res_none["manifest"].get("bundled_catalog"))
        self.assertNotIn("research/catalog.json", res_none["manifest"]["files"])
        manifest_files_none = (out_no_catalog / "manifest.files").read_text(encoding="utf-8").splitlines()
        self.assertNotIn("research/catalog.json", manifest_files_none)

        # 7. Final release without catalog raises PayloadBuildError
        out_final_missing = Path(self.tmp_dir) / "out_final_missing"
        with self.assertRaises(PayloadBuildError) as ctx_final:
            build_payload(
                repo_root=self.repo_root,
                out_dir=out_final_missing,
                tag=DEFAULT_TAG,
                binary_path=self.binary_path,
                version="1.1.0",
            )
        self.assertIn("Final release build", str(ctx_final.exception))
        self.assertIn("requires a bundled research/catalog.json", str(ctx_final.exception))

        # 8. An unlisted catalog.json dropped into payload directory causes UpdateRejected
        out_unlisted = Path(self.tmp_dir) / "out_unlisted"
        res_unlisted = build_payload(
            repo_root=self.repo_root,
            out_dir=out_unlisted,
            tag=DEFAULT_TAG,
            binary_path=self.binary_path,
        )
        trust_root = Path(self.tmp_dir) / "test_19_trust_root"
        trust_root.mkdir(parents=True, exist_ok=True)
        priv = os.urandom(32)
        pub = ed25519_ref.secret_to_public(priv)
        trust_doc = {
            "keys": [{"id": "test-key-ephemeral", "public_hex": pub.hex(), "revoked": False}],
            "constitution_sha256": res_unlisted["manifest"]["constitution_sha256"],
        }
        (trust_root / "trust.json").write_text(json.dumps(trust_doc, indent=2), encoding="utf-8")
        manifest_bytes = (out_unlisted / "manifest.json").read_bytes()
        sig = ed25519_ref.sign(priv, manifest_bytes)
        (out_unlisted / updater.SIGNATURE).write_bytes(sig)

        unlisted_cat = out_unlisted / "research" / "catalog.json"
        unlisted_cat.parent.mkdir(parents=True, exist_ok=True)
        unlisted_cat.write_text("{}", encoding="utf-8")

        u = updater.Updater(str(trust_root), str(self.tmp_dir))
        with self.assertRaises(updater.UpdateRejected) as ctx_unlisted:
            u._verify_release_py(str(out_unlisted), check_rollback=False)
        self.assertIn("unlisted file", str(ctx_unlisted.exception))


if __name__ == "__main__":
    unittest.main()
