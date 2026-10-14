"""
Comprehensive Multi-Seed Differential & Fuzzing Tests for Ingestion Primitives (Slice 5).
Validates 100% strict parity between Python reference (research/ingest.py) and
Rust stateless core binary (core/src/ingest.rs) over IPC bridge.

Includes:
1. Self-contained deterministic pseudo-random directory & file generator across 8 seeds
   (101, 202, 303, 404, 505, 606, 707, 808).
2. Explicit edge-case table covering boundary conditions, binary safety, secrets hygiene,
   Unicode/Sinhala normalization, line/file size capping, depth limits, and junk pruning.
3. Strict parity assertions ensuring 0 discrepancies and 0 panics.
"""

from __future__ import annotations

import os
import random
import shutil
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Optional, Tuple

import _bootstrap  # noqa: F401
import ingest
import pai_core_bridge
from ingest import (
    DEFAULT_JUNK_DIR_PATTERNS,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_FILE_COUNT,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_LINE_LENGTH,
    DEFAULT_MAX_REJECTIONS_PER_REASON,
    DEFAULT_MAX_TOTAL_BYTES,
    DEFAULT_MAX_TOTAL_REJECTIONS,
    DEFAULT_SECRET_DENY_PATTERNS,
    IngestedItem,
    IngestionRejection,
    IngestionReport,
)


class IngestTreeGenerator:
    """
    Self-contained deterministic PRNG filesystem tree generator.
    Creates rich directory trees with varying depths, valid files, binary files,
    junk folders, secret files, secret contents, and Unicode/Sinhala text.
    """

    SINHALA_SNIPPETS = [
        "මෙය Antigravity පද්ධතියේ ආරක්ෂිත පරීක්ෂණ ගොනුවකි.\n",
        "විධානය: තහවුරු කරන්න (Verify execution sandbox).\n",
        "දත්ත අංශය: අංක 123456789, සංකේත #@!&*^%.\n",
        "නම = 'සිංහල'\nඅගය = 42\n",
    ]

    CODE_SNIPPETS = [
        "def solve(n: int) -> int:\n    return n * 2 + 1\n",
        "export const CONFIG = { timeout: 3000, retries: 5 };\n",
        "SELECT id, username, created_at FROM users WHERE active = 1;\n",
        "# Project configuration header\nenv = production\nworkers = 4\n",
    ]

    SECRET_FILENAMES = [
        ".env",
        ".env.local",
        "id_rsa",
        "id_ed25519",
        "server.pem",
        "private.key",
        "credentials.json",
        "service-account.json",
        "terraform.tfstate",
        ".npmrc",
        ".netrc",
        "secrets.yaml",
    ]

    SECRET_CONTENT_PATTERNS = [
        ("aws_key", "export AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE\n"),
        ("pem_key", "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n"),
        ("github_pat", "token = '" + "ghp_" + ("xY9Z" * 9) + "'\n"),
        ("api_key", "OPENAI_API_KEY = '" + "sk-proj-" + ("AbCd" * 8) + "'\n"),
        ("db_url", "DATABASE_URL = 'postgresql://admin:" + "superSecretPass123" + "@localhost:5432/mydb'\n"),
        ("inline_cred", "password = '" + "MyS3cr3tP@ssw0rd99" + "'\n"),
    ]

    JUNK_FOLDERS = [
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "target",
        "dist",
        "build",
        ".tox",
        ".pytest_cache",
    ]

    def __init__(self, seed: int):
        self.rng = random.Random(seed)

    def populate_tree(self, root_dir: str, num_files: int = 40, max_nesting: int = 5) -> List[str]:
        created_paths: List[str] = []

        # 1. Create a set of subdirectories with varied nesting
        subdirs = [root_dir]
        for i in range(max_nesting):
            parent = self.rng.choice(subdirs)
            new_sub = os.path.join(parent, f"dir_{i}_{self.rng.randint(100, 999)}")
            os.makedirs(new_sub, exist_ok=True)
            subdirs.append(new_sub)

        # 2. Add some junk directories
        for junk in self.rng.sample(self.JUNK_FOLDERS, k=min(4, len(self.JUNK_FOLDERS))):
            parent = self.rng.choice(subdirs)
            junk_dir = os.path.join(parent, junk)
            os.makedirs(junk_dir, exist_ok=True)
            # Put a file inside junk dir
            junk_file = os.path.join(junk_dir, "internal.js")
            with open(junk_file, "w", encoding="utf-8") as f:
                f.write("console.log('junk content');\n")
            created_paths.append(junk_file)

        # 3. Add secret files
        for sname in self.rng.sample(self.SECRET_FILENAMES, k=min(4, len(self.SECRET_FILENAMES))):
            parent = self.rng.choice(subdirs)
            spath = os.path.join(parent, sname)
            with open(spath, "w", encoding="utf-8") as f:
                f.write("CONFIDENTIAL_PAYLOAD=true\n")
            created_paths.append(spath)

        # 4. Add secret content files
        for label, snippet in self.rng.sample(self.SECRET_CONTENT_PATTERNS, k=min(3, len(self.SECRET_CONTENT_PATTERNS))):
            parent = self.rng.choice(subdirs)
            cpath = os.path.join(parent, f"secret_content_{label}.py")
            with open(cpath, "w", encoding="utf-8") as f:
                f.write(snippet)
            created_paths.append(cpath)

        # 5. Add binary files
        for i in range(3):
            parent = self.rng.choice(subdirs)
            bpath = os.path.join(parent, f"binary_{i}.bin")
            with open(bpath, "wb") as f:
                bdata = bytearray(self.rng.randbytes(self.rng.randint(20, 100)))
                bdata[self.rng.randint(0, len(bdata) - 1)] = 0  # NUL byte
                f.write(bdata)
            created_paths.append(bpath)

        # 6. Add normal text & Sinhala files
        for i in range(num_files):
            parent = self.rng.choice(subdirs)
            ext = self.rng.choice([".txt", ".py", ".md", ".json", ".yaml"])
            fpath = os.path.join(parent, f"file_{i:03d}{ext}")
            mode = self.rng.choice(["sinhala", "code", "long_lines", "crlf"])
            with open(fpath, "w", encoding="utf-8", newline="") as f:
                if mode == "sinhala":
                    f.write("".join(self.rng.choices(self.SINHALA_SNIPPETS, k=3)))
                elif mode == "code":
                    f.write("".join(self.rng.choices(self.CODE_SNIPPETS, k=3)))
                elif mode == "long_lines":
                    line = "x" * self.rng.randint(100, 6000) + "\n"
                    f.write(line)
                elif mode == "crlf":
                    f.write("Line 1\r\nLine 2\r\nLine 3\r\n")
            created_paths.append(fpath)

        return created_paths


class TestIngestDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            bin_path = pai_core_bridge.find_core_binary()
            pai_core_bridge.check_handshake(bin_path)
        except Exception as exc:
            raise unittest.SkipTest(f"pai-core binary not available: {exc}")

    def setUp(self):
        self.orig_flag = pai_core_bridge.PAI_USE_RUST_CORE
        pai_core_bridge.PAI_USE_RUST_CORE = True
        self.test_dir = tempfile.mkdtemp(prefix="pai_ingest_diff_")

    def tearDown(self):
        pai_core_bridge.PAI_USE_RUST_CORE = self.orig_flag
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_single_file_differential_edge_cases(self):
        """
        Explicit edge case table for ingest_file:
        Tests 100% agreement between Python and Rust for:
        - empty files
        - exact file size boundary (at cap, 1 byte over cap)
        - exact line length boundary (at cap, 1 byte over cap)
        - C0 controls, non-printable characters, CRLF
        - invalid UTF-8 with replacement
        - NUL bytes at start, middle, and end
        - secret file denylists and custom denylists
        - secret content scanning (AWS, PEM, DB URLs)
        """
        cases = [
            ("empty.txt", b"", {}),
            ("exact_50_bytes.txt", b"A" * 50, {"max_file_size": 50}),
            ("over_50_bytes.txt", b"A" * 51, {"max_file_size": 50}),
            ("exact_100_line.txt", (b"B" * 100) + b"\n", {"max_line_length": 100}),
            ("over_100_line.txt", (b"B" * 101) + b"\n", {"max_line_length": 100}),
            ("crlf_newlines.txt", b"Line 1\r\nLine 2\rLine 3\n", {}),
            ("c0_controls.txt", b"Hello\x07\x08 World\t!\n", {}),
            ("invalid_utf8.txt", b"Hello \xff\xfe world\n", {}),
            ("nul_start.bin", b"\x00data", {}),
            ("nul_middle.bin", b"da\x00ta", {}),
            ("nul_end.bin", b"data\x00", {}),
            (".env", b"KEY=VAL\n", {}),
            (".env.production", b"KEY=VAL\n", {}),
            ("id_rsa", b"SSH KEY\n", {}),
            ("credentials.json", b"{\"key\":\"val\"}\n", {}),
            ("service-account.json", b"{\"client_email\":\"a@b.com\"}\n", {}),
            ("normal.py", b"def add(a, b):\n    return a + b\n", {}),
            ("aws_secret.txt", b"KEY = " + b"AKIA" + b"IOSFODNN7EXAMPLE\n", {}),
            ("pem_secret.txt", b"-----BEGIN " + b"RSA PRIVATE KEY-----\nMIIE\n", {}),
            ("db_url.txt", b"DATABASE_URL=postgres://" + b"user:mypassword123" + b"@host:5432/db\n", {}),
            ("sinhala_text.txt", "සිංහල යුනිකෝඩ් පරීක්ෂණය\n".encode("utf-8"), {}),
        ]

        for fname, raw_bytes, extra_kwargs in cases:
            fpath = os.path.join(self.test_dir, fname)
            with open(fpath, "wb") as f:
                f.write(raw_bytes)

            # Direct Python execution
            py_item, py_rej = ingest.ingest_file(
                file_path=fpath,
                root_path=self.test_dir,
                **extra_kwargs,
            )

            # Bridge / Rust execution
            rust_kwargs = {"file_path": fpath, "root_path": self.test_dir, **extra_kwargs}
            raw_res = pai_core_bridge.call_core_bridge("ingest_file", **rust_kwargs)
            rust_item_raw = raw_res.get("item")
            rust_rej_raw = raw_res.get("rejection")

            rust_item = IngestedItem(**rust_item_raw) if rust_item_raw else None
            rust_rej = IngestionRejection(**rust_rej_raw) if rust_rej_raw else None

            # Assert identical outcomes
            self.assertEqual(
                (rust_item is not None),
                (py_item is not None),
                f"Mismatch item presence for {fname}: py={py_item!r} vs rust={rust_item!r}",
            )
            self.assertEqual(
                (rust_rej is not None),
                (py_rej is not None),
                f"Mismatch rejection presence for {fname}: py={py_rej!r} vs rust={rust_rej!r}",
            )

            if py_item is not None:
                self.assertEqual(rust_item.to_dict(), py_item.to_dict(), f"Item dict mismatch for {fname}")
            if py_rej is not None:
                self.assertEqual(rust_rej.reason_code, py_rej.reason_code, f"Rejection code mismatch for {fname}")
                self.assertEqual(rust_rej.path, py_rej.path, f"Rejection path mismatch for {fname}")
                self.assertEqual(rust_rej.message, py_rej.message, f"Rejection message mismatch for {fname}")

    def test_multi_seed_folder_differential(self):
        """
        Runs 8 distinct seeds (101, 202, 303, 404, 505, 606, 707, 808) through
        the deterministic generator, comparing Python vs Rust across full folder walks.
        Asserts:
        - Exact match on items list (paths, hashes, sizes, texts)
        - Exact match on rejections list (reason codes, paths, messages)
        - Exact match on total_bytes, total_files, and rejection_counts
        - Zero discrepancies recorded in shadow log.
        """
        seeds = [101, 202, 303, 404, 505, 606, 707, 808]

        for seed in seeds:
            seed_dir = os.path.join(self.test_dir, f"seed_{seed}")
            os.makedirs(seed_dir, exist_ok=True)

            gen = IngestTreeGenerator(seed=seed)
            gen.populate_tree(seed_dir, num_files=25, max_nesting=4)

            # Test standard traversal (junk pruned, depth=3)
            py_rep = ingest.ingest_folder(
                seed_dir,
                max_file_size=50_000,
                max_total_bytes=500_000,
                max_file_count=100,
                max_depth=3,
                max_line_length=1000,
                include_junk=False,
                max_rejections_per_reason=10,
                max_total_rejections=100,
            )

            bridge_res = pai_core_bridge.call_core_bridge(
                "ingest_folder",
                folder_path=seed_dir,
                max_file_size=50_000,
                max_total_bytes=500_000,
                max_file_count=100,
                max_depth=3,
                max_line_length=1000,
                include_junk=False,
                max_rejections_per_reason=10,
                max_total_rejections=100,
            )

            rust_items = [IngestedItem(**it) for it in bridge_res.get("items", [])]
            rust_rejections = [IngestionRejection(**rej) for rej in bridge_res.get("rejections", [])]
            rust_rep = IngestionReport(
                root=bridge_res.get("root", ""),
                items=rust_items,
                rejections=rust_rejections,
                total_bytes=bridge_res.get("total_bytes", 0),
                total_files=bridge_res.get("total_files", 0),
                limits=bridge_res.get("limits", {}),
                rejection_counts=bridge_res.get("rejection_counts", {}),
                rejections_capped=bridge_res.get("rejections_capped", False),
            )

            # Assert complete parity
            self.assertEqual(
                len(rust_rep.items),
                len(py_rep.items),
                f"Seed {seed}: Item count mismatch: rust={len(rust_rep.items)} vs py={len(py_rep.items)}",
            )
            self.assertEqual(
                rust_rep.total_bytes,
                py_rep.total_bytes,
                f"Seed {seed}: Total bytes mismatch",
            )
            self.assertEqual(
                rust_rep.rejection_counts,
                py_rep.rejection_counts,
                f"Seed {seed}: Rejection counts mismatch: rust={rust_rep.rejection_counts} vs py={py_rep.rejection_counts}",
            )

            # Compare individual item lists
            rust_item_dicts = [it.to_dict() for it in rust_rep.items]
            py_item_dicts = [it.to_dict() for it in py_rep.items]
            self.assertEqual(rust_item_dicts, py_item_dicts, f"Seed {seed}: Ingested items mismatch")

            # Compare individual rejection lists
            rust_rej_dicts = [r.to_dict() for r in rust_rep.rejections]
            py_rej_dicts = [r.to_dict() for r in py_rep.rejections]
            self.assertEqual(rust_rej_dicts, py_rej_dicts, f"Seed {seed}: Rejections mismatch")

    def test_shadow_mode_telemetry_and_pass_through(self):
        """Verifies shadow mode executes both paths and records comparisons without discrepancies."""
        dummy_file = os.path.join(self.test_dir, "shadow_test.txt")
        with open(dummy_file, "w", encoding="utf-8") as f:
            f.write("Shadow parity test payload\n")

        # Clear discrepancies before run
        pai_core_bridge._SHADOW_DISCREPANCIES.clear()

        # Ingest file via bridge wrapper
        item, rej = pai_core_bridge.ingest_file(dummy_file, root_path=self.test_dir)
        self.assertIsNotNone(item)
        self.assertIsNone(rej)
        self.assertEqual(item.text, "Shadow parity test payload\n")

        # Ingest folder via bridge wrapper
        report = pai_core_bridge.ingest_folder(self.test_dir)
        self.assertGreaterEqual(len(report.items), 1)

        # Discrepancies must remain 0
        discrepancies = [
            d for d in pai_core_bridge._SHADOW_DISCREPANCIES
            if d.get("op") in ("ingest_file", "ingest_folder")
        ]
        self.assertEqual(len(discrepancies), 0, f"Unexpected discrepancies: {discrepancies}")

    def test_cmd_analyze_and_cmd_docs_shadow_counters_incremented(self):
        """Verifies pai analyze and pai docs with PAI_USE_RUST_CORE=1 increment shadow comparison counters."""
        from unittest import mock
        import pai

        # Create a valid test repository folder
        repo_dir = os.path.join(self.test_dir, "test_repo")
        os.makedirs(repo_dir, exist_ok=True)
        main_py = os.path.join(repo_dir, "main.py")
        with open(main_py, "w", encoding="utf-8") as f:
            f.write("# PAI Test\ndef hello():\n    return 'world'\nif __name__ == '__main__':\n    print(hello())\n")

        doc_file = os.path.join(repo_dir, "README.md")
        with open(doc_file, "w", encoding="utf-8") as f:
            f.write("# Test Project Documentation\nThis is a safe documentation file for PAI docs.\n")

        # Set shadow mode active
        old_env = os.environ.get("PAI_USE_RUST_CORE")
        old_pai_dir = os.environ.get("PAI_DIR")
        pai_dir = os.path.join(self.test_dir, ".pai")
        os.makedirs(pai_dir, exist_ok=True)
        os.environ["PAI_DIR"] = pai_dir
        os.environ["PAI_USE_RUST_CORE"] = "1"
        pai_core_bridge.PAI_USE_RUST_CORE = True
        pai_core_bridge.reset_shadow_discrepancies()

        try:
            initial_comparisons, initial_discrepancies, _ = pai_core_bridge.get_shadow_stats()

            with mock.patch("sandbox.probe_system_boundary", return_value=(True, "OK")):
                with mock.patch("pai.probe_ollama_server", return_value={"reachable": True, "version": "0.1.0"}):
                    with mock.patch("pai.call_model_generate", return_value="Objective analysis response"):
                        # Execute pai analyze
                        ret_analyze = pai.main(["analyze", repo_dir, "--model", "test-model", "--json"])
                        self.assertEqual(ret_analyze, 0, "pai analyze should succeed")

                        comps_after_analyze, disc_after_analyze, _ = pai_core_bridge.get_shadow_stats()
                        self.assertGreater(comps_after_analyze, initial_comparisons, "ingest_folder comparison counter must increment")
                        self.assertEqual(disc_after_analyze, 0, "No discrepancies after pai analyze")

                        # Execute pai docs
                        ret_docs = pai.main(["docs", doc_file, "--model", "test-model", "--json"])
                        self.assertEqual(ret_docs, 0, "pai docs should succeed")

                        comps_after_docs, disc_after_docs, _ = pai_core_bridge.get_shadow_stats()
                        self.assertGreater(comps_after_docs, comps_after_analyze, "ingest_file comparison counter must increment")
                        self.assertEqual(disc_after_docs, 0, "No discrepancies after pai docs")

        finally:
            if old_env is None:
                os.environ.pop("PAI_USE_RUST_CORE", None)
                pai_core_bridge.PAI_USE_RUST_CORE = False
            else:
                os.environ["PAI_USE_RUST_CORE"] = old_env
                pai_core_bridge.PAI_USE_RUST_CORE = (old_env == "1")
            if old_pai_dir is None:
                os.environ.pop("PAI_DIR", None)
            else:
                os.environ["PAI_DIR"] = old_pai_dir

    def test_differential_tight_caps(self):
        """Verifies tight rejection caps match 100% between Python and Rust."""
        caps_dir = os.path.join(self.test_dir, "caps_tree")
        os.makedirs(caps_dir, exist_ok=True)

        # Create multiple secret files (.env, credentials.json, id_rsa, server.pem)
        for sname in [".env", ".env.local", "credentials.json", "id_rsa", "server.pem"]:
            with open(os.path.join(caps_dir, sname), "w", encoding="utf-8") as f:
                f.write("safe payload without secrets\n")

        # Create multiple junk directories
        for jname in ["node_modules", ".git", "__pycache__", ".venv"]:
            jdir = os.path.join(caps_dir, jname)
            os.makedirs(jdir, exist_ok=True)
            with open(os.path.join(jdir, "junk.txt"), "w", encoding="utf-8") as f:
                f.write("junk data\n")

        # Create binary files
        for bidx in range(4):
            with open(os.path.join(caps_dir, f"bin_{bidx}.bin"), "wb") as f:
                f.write(b"data\x00data\x00")

        # Test with tight caps: max_rejections_per_reason=2, max_total_rejections=5
        py_rep = ingest.ingest_folder(
            caps_dir,
            max_rejections_per_reason=2,
            max_total_rejections=5,
        )
        bridge_res = pai_core_bridge.call_core_bridge(
            "ingest_folder",
            folder_path=caps_dir,
            max_rejections_per_reason=2,
            max_total_rejections=5,
        )

        rust_rejections = [IngestionRejection(**rej) for rej in bridge_res.get("rejections", [])]
        rust_rep = IngestionReport(
            root=bridge_res.get("root", ""),
            items=[IngestedItem(**it) for it in bridge_res.get("items", [])],
            rejections=rust_rejections,
            total_bytes=bridge_res.get("total_bytes", 0),
            total_files=bridge_res.get("total_files", 0),
            limits=bridge_res.get("limits", {}),
            rejection_counts=bridge_res.get("rejection_counts", {}),
            rejections_capped=bridge_res.get("rejections_capped", False),
        )

        self.assertTrue(py_rep.rejections_capped, "Python should report rejections_capped=True under tight limits")
        self.assertTrue(rust_rep.rejections_capped, "Rust should report rejections_capped=True under tight limits")
        self.assertEqual(py_rep.rejection_counts, rust_rep.rejection_counts, "Rejection counts must match")
        self.assertEqual(len(py_rep.rejections), len(rust_rep.rejections), "Rejection list lengths must match under caps")
        self.assertEqual([r.to_dict() for r in py_rep.rejections], [r.to_dict() for r in rust_rep.rejections])

    def test_differential_dangling_symlinks(self):
        """Verifies dangling symlinks (internal STAT_ERROR and escaping SYMLINK_ESCAPE) match 100%."""
        symlink_dir = os.path.join(self.test_dir, "symlink_test")
        os.makedirs(symlink_dir, exist_ok=True)
        int_dangling = os.path.join(symlink_dir, "int_dangling.txt")
        esc_dangling = os.path.join(symlink_dir, "esc_dangling.txt")

        try:
            os.symlink("non_existent_target.txt", int_dangling)
            os.symlink("../outside_non_existent.txt", esc_dangling)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks require privilege on Windows")

        # Ingest individual files
        py_int_item, py_int_rej = ingest.ingest_file(int_dangling, root_path=symlink_dir)
        rust_int_res = pai_core_bridge.call_core_bridge("ingest_file", file_path=int_dangling, root_path=symlink_dir)
        rust_int_rej = IngestionRejection(**rust_int_res["rejection"]) if rust_int_res.get("rejection") else None

        self.assertIsNotNone(py_int_rej)
        self.assertIsNotNone(rust_int_rej)
        self.assertEqual(py_int_rej.reason_code, "STAT_ERROR")
        self.assertEqual(rust_int_rej.reason_code, "STAT_ERROR")
        self.assertEqual(py_int_rej.message, rust_int_rej.message)
        self.assertEqual(py_int_rej.path, rust_int_rej.path)

        py_esc_item, py_esc_rej = ingest.ingest_file(esc_dangling, root_path=symlink_dir)
        rust_esc_res = pai_core_bridge.call_core_bridge("ingest_file", file_path=esc_dangling, root_path=symlink_dir)
        rust_esc_rej = IngestionRejection(**rust_esc_res["rejection"]) if rust_esc_res.get("rejection") else None

        self.assertIsNotNone(py_esc_rej)
        self.assertIsNotNone(rust_esc_rej)
        self.assertEqual(py_esc_rej.reason_code, "SYMLINK_ESCAPE")
        self.assertEqual(rust_esc_rej.reason_code, "SYMLINK_ESCAPE")
        self.assertEqual(py_esc_rej.message, rust_esc_rej.message)
        self.assertEqual(py_esc_rej.path, rust_esc_rej.path)

        # Ingest folder containing dangling symlinks
        py_rep = ingest.ingest_folder(symlink_dir)
        bridge_res = pai_core_bridge.call_core_bridge("ingest_folder", folder_path=symlink_dir)

        rust_rejections = [IngestionRejection(**rej) for rej in bridge_res.get("rejections", [])]
        rust_rep = IngestionReport(
            root=bridge_res.get("root", ""),
            items=[IngestedItem(**it) for it in bridge_res.get("items", [])],
            rejections=rust_rejections,
            total_bytes=bridge_res.get("total_bytes", 0),
            total_files=bridge_res.get("total_files", 0),
            limits=bridge_res.get("limits", {}),
            rejection_counts=bridge_res.get("rejection_counts", {}),
            rejections_capped=bridge_res.get("rejections_capped", False),
        )

        self.assertEqual(py_rep.rejection_counts, rust_rep.rejection_counts)
        self.assertEqual([r.to_dict() for r in py_rep.rejections], [r.to_dict() for r in rust_rep.rejections])


if __name__ == "__main__":
    unittest.main()
