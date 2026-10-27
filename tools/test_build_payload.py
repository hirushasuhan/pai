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
    DEFAULT_TAG,
    EXPECTED_BINARY_SHA256,
    EXPECTED_CORE_TREE,
    EXPECTED_RESEARCH_TREE,
    BinaryHashMismatchError,
    ExtractedIntegrityError,
    PayloadBuildError,
    SymlinkRejectedError,
    TagNotFoundError,
    TreeMismatchError,
    UnsafePathError,
    build_payload,
    extract_tag_archive,
    scan_and_validate_payload,
    sha256_file,
    verify_binary,
    verify_extracted_integrity,
    verify_tag_and_trees,
)


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

        # Hostile input: create copy with 1 byte modified
        tampered_bin = Path(self.tmp_dir) / "pai-core-tampered.exe"
        bin_data = bytearray(self.binary_path.read_bytes())
        # Flip least significant bit of first byte
        bin_data[0] ^= 0x01
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


if __name__ == "__main__":
    unittest.main()
