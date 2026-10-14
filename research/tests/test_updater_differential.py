"""
Differential test suite for Slice 4: Ed25519 Signature Verification & Signed-Release Updater.

Verifies exact behavioral parity between Python reference implementations
(`research/ed25519_ref.py`, `research/updater.py`) and Rust `pai-core` implementations
(`core/src/ed25519.rs`, `core/src/updater.rs`) across happy paths, attack surfaces,
and mutation fuzzing.
"""

import hashlib
import json
import os
import random
import shutil
import tempfile
import unittest

import _bootstrap  # noqa: F401
import ed25519_ref
import pai_core_bridge
from updater import (
    MANIFEST,
    SIGNATURE,
    UpdateRejected,
    Updater,
    build_manifest,
)

# Test-only signing key fixture (NEVER production; private keys never enter repo)
TEST_SEED = bytes(range(32))
OTHER_SEED = bytes(range(1, 33))
TEST_PUB = ed25519_ref.secret_to_public(TEST_SEED)
TEST_CONSTITUTION = b"1. Privacy first.\n"
TEST_CONST_SHA = hashlib.sha256(TEST_CONSTITUTION).hexdigest()


def make_test_release(base_dir, version="0.3.0", files=None, seed=TEST_SEED, const_sha=TEST_CONST_SHA, mutate=None):
    d = tempfile.mkdtemp(dir=base_dir)
    payload_files = files or {
        "pai_core.bin": b"engine v" + version.encode("utf-8"),
        "cfg/default.json": b"{}",
    }
    for name, data in payload_files.items():
        full_path = os.path.join(d, name)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(data)

    manifest = build_manifest(d, "pai-core", version, const_sha)
    if mutate:
        manifest = mutate(manifest)
    with open(os.path.join(d, MANIFEST), "wb") as f:
        f.write(manifest)
    with open(os.path.join(d, SIGNATURE), "wb") as f:
        f.write(ed25519_ref.sign(seed, manifest))
    return d


class TestEd25519Differential(unittest.TestCase):
    """Differential tests for Ed25519 signature verification."""

    @classmethod
    def setUpClass(cls):
        try:
            bin_path = pai_core_bridge.find_core_binary()
            pai_core_bridge.check_handshake(bin_path)
        except Exception as exc:
            raise unittest.SkipTest(f"pai-core binary not available or incompatible for platform: {exc}")

    def test_conformance_ed25519_vectors_parity(self):
        """Validates all 173 vectors in ed25519_vectors.json against both Python ref and Rust bridge."""
        vec_path = os.path.join(os.path.dirname(__file__), "..", "conformance", "ed25519_vectors.json")
        with open(vec_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for c in data["cases"]:
            pk = bytes.fromhex(c["public_key_hex"])
            msg = bytes.fromhex(c["message_hex"])
            sig = bytes.fromhex(c["signature_hex"])
            expected = c["expected"]

            py_res = ed25519_ref.verify(pk, msg, sig)
            rust_res = pai_core_bridge.call_core_bridge(
                "verify_ed25519",
                public_key_hex=c["public_key_hex"],
                message_hex=c["message_hex"],
                signature_hex=c["signature_hex"],
            )
            self.assertEqual(py_res, expected, f"Python ref mismatch on {c['id']}")
            self.assertEqual(rust_res, expected, f"Rust core mismatch on {c['id']}")

    def test_differential_against_cryptography(self):
        """Cross-checks known-answer vectors independently against OpenSSL via cryptography package."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
        except ImportError:
            raise unittest.SkipTest("cryptography package not installed")

        vec_path = os.path.join(os.path.dirname(__file__), "..", "conformance", "ed25519_vectors.json")
        with open(vec_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for c in data["cases"]:
            if not (c["id"].startswith("known_answer") or c["id"].startswith("rfc8032")):
                continue
            pk = bytes.fromhex(c["public_key_hex"])
            msg = bytes.fromhex(c["message_hex"])
            sig = bytes.fromhex(c["signature_hex"])

            k = Ed25519PublicKey.from_public_bytes(pk)
            try:
                k.verify(sig, msg)
                crypto_ok = True
            except InvalidSignature:
                crypto_ok = False

            rust_ok = pai_core_bridge.call_core_bridge(
                "verify_ed25519",
                public_key_hex=c["public_key_hex"],
                message_hex=c["message_hex"],
                signature_hex=c["signature_hex"],
            )
            self.assertEqual(crypto_ok, c["expected"], f"cryptography mismatch on {c['id']}")
            self.assertEqual(rust_ok, crypto_ok, f"Rust vs cryptography mismatch on {c['id']}")

    def test_rfc8032_test_vector_1(self):
        pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        msg = b""

        py_ok = ed25519_ref.verify(pk, msg, sig)
        rust_ok = pai_core_bridge.call_core_bridge(
            "verify_ed25519",
            public_key_hex=pk.hex(),
            message_hex=msg.hex(),
            signature_hex=sig.hex(),
        )
        self.assertTrue(py_ok)
        self.assertTrue(rust_ok)

        # Tampered message
        tampered_msg = b"x"
        self.assertFalse(ed25519_ref.verify(pk, tampered_msg, sig))
        self.assertFalse(pai_core_bridge.call_core_bridge(
            "verify_ed25519",
            public_key_hex=pk.hex(),
            message_hex=tampered_msg.hex(),
            signature_hex=sig.hex(),
        ))

    def test_malleated_signature_rejected_both(self):
        msg = b"test message"
        sig = ed25519_ref.sign(TEST_SEED, msg)
        s = int.from_bytes(sig[32:], "little") + ed25519_ref.q
        malleated_sig = sig[:32] + (s % (2 ** 256)).to_bytes(32, "little")

        py_ok = ed25519_ref.verify(TEST_PUB, msg, malleated_sig)
        rust_ok = pai_core_bridge.call_core_bridge(
            "verify_ed25519",
            public_key_hex=TEST_PUB.hex(),
            message_hex=msg.hex(),
            signature_hex=malleated_sig.hex(),
        )
        self.assertFalse(py_ok, "Python reference must reject malleated signature")
        self.assertFalse(rust_ok, "Rust core must reject malleated signature")

    def test_invalid_lengths_rejected_both(self):
        for bad_pk in (b"", b"short", b"\x00" * 31, b"\x00" * 33):
            self.assertFalse(ed25519_ref.verify(bad_pk, b"m", b"\x00" * 64))
            self.assertFalse(pai_core_bridge.call_core_bridge(
                "verify_ed25519",
                public_key_hex=bad_pk.hex(),
                message_hex=b"m".hex(),
                signature_hex=(b"\x00" * 64).hex(),
            ))

        for bad_sig in (b"", b"short", b"\x00" * 63, b"\x00" * 65):
            self.assertFalse(ed25519_ref.verify(TEST_PUB, b"m", bad_sig))
            self.assertFalse(pai_core_bridge.call_core_bridge(
                "verify_ed25519",
                public_key_hex=TEST_PUB.hex(),
                message_hex=b"m".hex(),
                signature_hex=bad_sig.hex(),
            ))

    def test_differential_mutation_fuzzing(self):
        """Runs 300 randomized mutations verifying 100% agreement between Python and Rust."""
        rng = random.Random(101)
        for _ in range(300):
            msg_len = rng.choice([0, 1, 13, 64, 128, 512])
            msg = bytes(rng.getrandbits(8) for _ in range(msg_len))
            sig = ed25519_ref.sign(TEST_SEED, msg)

            mut_type = rng.choice(["none", "flip_sig", "flip_pk", "flip_msg", "malleate_s", "random_sig"])
            mut_pk = bytearray(TEST_PUB)
            mut_sig = bytearray(sig)
            mut_msg = bytearray(msg)

            if mut_type == "flip_sig":
                idx = rng.randint(0, len(mut_sig) - 1)
                mut_sig[idx] ^= (1 << rng.randint(0, 7))
            elif mut_type == "flip_pk":
                idx = rng.randint(0, len(mut_pk) - 1)
                mut_pk[idx] ^= (1 << rng.randint(0, 7))
            elif mut_type == "flip_msg":
                if len(mut_msg) > 0:
                    idx = rng.randint(0, len(mut_msg) - 1)
                    mut_msg[idx] ^= (1 << rng.randint(0, 7))
                else:
                    mut_msg = bytearray(b"x")
            elif mut_type == "malleate_s":
                s_val = int.from_bytes(mut_sig[32:], "little") + ed25519_ref.q
                mut_sig[32:] = (s_val % (2 ** 256)).to_bytes(32, "little")
            elif mut_type == "random_sig":
                mut_sig = bytearray(rng.getrandbits(8) for _ in range(64))

            py_ver = ed25519_ref.verify(bytes(mut_pk), bytes(mut_msg), bytes(mut_sig))
            rust_ver = pai_core_bridge.call_core_bridge(
                "verify_ed25519",
                public_key_hex=bytes(mut_pk).hex(),
                message_hex=bytes(mut_msg).hex(),
                signature_hex=bytes(mut_sig).hex(),
            )
            self.assertEqual(py_ver, rust_ver, f"Mismatch on mutation {mut_type}")


class TestUpdaterDifferential(unittest.TestCase):
    """Differential tests for release verification."""

    @classmethod
    def setUpClass(cls):
        try:
            bin_path = pai_core_bridge.find_core_binary()
            pai_core_bridge.check_handshake(bin_path)
        except Exception as exc:
            raise unittest.SkipTest(f"pai-core binary not available or incompatible for platform: {exc}")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pai_updater_diff_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.trust_dir = os.path.join(self.tmp, "trust")
        self.install_dir = os.path.join(self.tmp, "install")
        self.src_dir = os.path.join(self.tmp, "src")
        os.makedirs(self.trust_dir)
        os.makedirs(self.install_dir)
        os.makedirs(self.src_dir)
        self.write_trust()

    def write_trust(self, revoked=False, const_sha=TEST_CONST_SHA):
        self.trust_cfg = {
            "keys": [{"id": "rel-1", "public_hex": TEST_PUB.hex(), "revoked": revoked}],
            "constitution_sha256": const_sha,
        }
        with open(os.path.join(self.trust_dir, "trust.json"), "w", encoding="utf-8") as f:
            json.dump(self.trust_cfg, f)

    def test_valid_release_differential(self):
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        u = Updater(self.trust_dir, self.install_dir)
        py_res = u.verify_release(rel_dir)

        rust_res = pai_core_bridge.call_core_bridge(
            "verify_release",
            release_dir=rel_dir,
            trust_root_json=json.dumps(self.trust_cfg),
            expected_product="pai-core",
            check_rollback=False,
        )

        self.assertEqual(py_res.version, rust_res["version"])
        self.assertEqual(py_res.key_id, rust_res["key_id"])
        self.assertEqual(py_res.files, rust_res["files"])

    def test_hex_text_signature_accepted_both(self):
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        spath = os.path.join(rel_dir, SIGNATURE)
        with open(spath, "rb") as f:
            raw = f.read()
        with open(spath, "w", encoding="ascii") as f:
            f.write(raw.hex() + "\n")

        u = Updater(self.trust_dir, self.install_dir)
        py_res = u.verify_release(rel_dir)
        rust_res = pai_core_bridge.call_core_bridge(
            "verify_release",
            release_dir=rel_dir,
            trust_root_json=json.dumps(self.trust_cfg),
            expected_product="pai-core",
            check_rollback=False,
        )
        self.assertEqual(py_res.version, rust_res["version"])

    def test_tampered_payload_rejected_both(self):
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        with open(os.path.join(rel_dir, "pai_core.bin"), "ab") as f:
            f.write(b"backdoor")

        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected) as cm_py:
            u.verify_release(rel_dir)
        self.assertIn("mismatch", str(cm_py.exception))

        with self.assertRaises(Exception) as cm_rust:
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )
        self.assertIn("mismatch", str(cm_rust.exception))

    def test_same_size_tamper_rejected_both(self):
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        p = os.path.join(rel_dir, "cfg", "default.json")
        with open(p, "wb") as f:
            f.write(b"[]")  # same length as "{}"

        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected) as cm_py:
            u.verify_release(rel_dir)
        self.assertIn("SHA-256 mismatch", str(cm_py.exception))

        with self.assertRaises(Exception) as cm_rust:
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )
        self.assertIn("SHA-256 mismatch", str(cm_rust.exception))

    def test_unlisted_file_rejected_both(self):
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        with open(os.path.join(rel_dir, "extra.dll"), "wb") as f:
            f.write(b"payload")

        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected) as cm_py:
            u.verify_release(rel_dir)
        self.assertIn("unlisted", str(cm_py.exception))

        with self.assertRaises(Exception) as cm_rust:
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )
        self.assertIn("unlisted", str(cm_rust.exception))

    def test_constitution_drift_rejected_both(self):
        drifted_sha = hashlib.sha256(b"weakened").hexdigest()
        rel_dir = make_test_release(self.src_dir, const_sha=drifted_sha)

        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected) as cm_py:
            u.verify_release(rel_dir)
        self.assertIn("Constitution", str(cm_py.exception))

        with self.assertRaises(Exception) as cm_rust:
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )
        self.assertIn("Constitution", str(cm_rust.exception))

    def test_path_traversal_rejected_both(self):
        for evil in ("../evil.bin", "/abs/evil.bin", "a\\..\\b", "a/../../b", "C:evil"):
            def mutate(m, evil=evil):
                doc = json.loads(m)
                doc["files"][evil] = {"sha256": "0" * 64, "size": 1}
                return json.dumps(doc).encode()

            rel_dir = make_test_release(self.src_dir, mutate=mutate)
            u = Updater(self.trust_dir, self.install_dir)
            with self.assertRaises(UpdateRejected) as cm_py:
                u.verify_release(rel_dir)
            self.assertIn("unsafe path", str(cm_py.exception))

            with self.assertRaises(Exception) as cm_rust:
                pai_core_bridge.call_core_bridge(
                    "verify_release",
                    release_dir=rel_dir,
                    trust_root_json=json.dumps(self.trust_cfg),
                    expected_product="pai-core",
                )
            self.assertIn("unsafe path", str(cm_rust.exception))

    def test_shadow_mode_parity_and_discrepancy_tracking(self):
        """Verifies updater behavior in shadow mode with PAI_USE_RUST_CORE=1."""
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        pai_core_bridge.reset_shadow_discrepancies()
        pai_core_bridge.PAI_USE_RUST_CORE = True
        try:
            u = Updater(self.trust_dir, self.install_dir)
            rel = u.verify_release(rel_dir)
            self.assertEqual(rel.version, "0.3.0")
            self.assertEqual(pai_core_bridge.get_shadow_discrepancy_count(), 0)
        finally:
            pai_core_bridge.PAI_USE_RUST_CORE = False

    def test_signature_internal_spaces_rejected_both(self):
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        spath = os.path.join(rel_dir, SIGNATURE)
        with open(spath, "rb") as f:
            raw = f.read()
        hex_str = raw.hex()
        spaced = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        with open(spath, "w", encoding="ascii") as f:
            f.write(spaced + "\n")

        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected):
            u.verify_release(rel_dir)
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )

    def test_signature_control_char_rejected_both(self):
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        spath = os.path.join(rel_dir, SIGNATURE)
        with open(spath, "rb") as f:
            raw = f.read()
        with open(spath, "wb") as f:
            f.write(b"\x1c" + raw.hex().encode("ascii") + b"\x1c")

        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected):
            u.verify_release(rel_dir)
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )

    def test_signature_nbsp_rejected_both(self):
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        spath = os.path.join(rel_dir, SIGNATURE)
        with open(spath, "rb") as f:
            raw = f.read()
        with open(spath, "w", encoding="utf-8") as f:
            f.write("\u00a0" + raw.hex() + "\u00a0")

        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected):
            u.verify_release(rel_dir)
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )

    def test_signature_exact_128_hex_trailing_newline_accepted_both(self):
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        spath = os.path.join(rel_dir, SIGNATURE)
        with open(spath, "rb") as f:
            raw = f.read()
        with open(spath, "wb") as f:
            f.write(raw.hex().encode("ascii") + b"\r\n")

        u = Updater(self.trust_dir, self.install_dir)
        py_res = u.verify_release(rel_dir)
        rust_res = pai_core_bridge.call_core_bridge(
            "verify_release",
            release_dir=rel_dir,
            trust_root_json=json.dumps(self.trust_cfg),
            expected_product="pai-core",
            check_rollback=False,
        )
        self.assertEqual(py_res.version, rust_res["version"])

    def test_version_trailing_newline_rejected_both(self):
        def mutate(m):
            doc = json.loads(m)
            doc["version"] = "0.3.0\n"
            return json.dumps(doc).encode()

        rel_dir = make_test_release(self.src_dir, mutate=mutate)
        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected):
            u.verify_release(rel_dir)
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )

    def test_version_arabic_indic_digits_rejected_both(self):
        def mutate(m):
            doc = json.loads(m)
            doc["version"] = "\u0660.\u0663.\u0660"  # ٠.٣.٠
            return json.dumps(doc).encode()

        rel_dir = make_test_release(self.src_dir, mutate=mutate)
        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected):
            u.verify_release(rel_dir)
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )

    def test_version_above_u32_rejected_both(self):
        def mutate(m):
            doc = json.loads(m)
            doc["version"] = "1.0.4294967296"
            return json.dumps(doc).encode()

        rel_dir = make_test_release(self.src_dir, mutate=mutate)
        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected):
            u.verify_release(rel_dir)
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )

    def test_manifest_format_boolean_rejected_both(self):
        def mutate(m):
            doc = json.loads(m)
            doc["format"] = True
            return json.dumps(doc).encode()

        rel_dir = make_test_release(self.src_dir, mutate=mutate)
        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected):
            u.verify_release(rel_dir)
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )

    def test_manifest_format_float_rejected_both(self):
        def mutate(m):
            doc = json.loads(m)
            doc["format"] = 1.0
            return json.dumps(doc).encode()

        rel_dir = make_test_release(self.src_dir, mutate=mutate)
        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected):
            u.verify_release(rel_dir)
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )

    def test_manifest_size_float_rejected_both(self):
        def mutate(m):
            doc = json.loads(m)
            for fmeta in doc["files"].values():
                fmeta["size"] = 5.0
                break
            return json.dumps(doc).encode()

        rel_dir = make_test_release(self.src_dir, mutate=mutate)
        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected):
            u.verify_release(rel_dir)
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )

    def test_trust_file_invalid_key_hard_error_both(self):
        invalid_trust = {
            "keys": [{"id": "bad-1", "public_hex": "zz" * 32, "revoked": False}],
            "constitution_sha256": TEST_CONST_SHA,
        }
        with open(os.path.join(self.trust_dir, "trust.json"), "w", encoding="utf-8") as f:
            json.dump(invalid_trust, f)

        # Python Updater constructor raises ValueError (hard error)
        with self.assertRaises(ValueError):
            Updater(self.trust_dir, self.install_dir)

        # Rust verify_release call raises hard error
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(invalid_trust),
                expected_product="pai-core",
            )

    def test_directory_walk_unlisted_symlink_dir_rejected_both(self):
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        outside_dir = tempfile.mkdtemp(dir=self.tmp)
        symlink_target = os.path.join(rel_dir, "symlink_dir")
        try:
            os.symlink(outside_dir, symlink_target, target_is_directory=True)
        except OSError:
            raise unittest.SkipTest("Symlinks not supported on this user/platform")

        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected):
            u.verify_release(rel_dir)
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )

    def test_directory_walk_dangling_symlink_rejected_both(self):
        rel_dir = make_test_release(self.src_dir, version="0.3.0")
        dangling_target = os.path.join(rel_dir, "dangling_link")
        try:
            os.symlink(os.path.join(self.tmp, "non_existent_file"), dangling_target)
        except OSError:
            raise unittest.SkipTest("Symlinks not supported on this user/platform")

        u = Updater(self.trust_dir, self.install_dir)
        with self.assertRaises(UpdateRejected):
            u.verify_release(rel_dir)
        with self.assertRaises(Exception):
            pai_core_bridge.call_core_bridge(
                "verify_release",
                release_dir=rel_dir,
                trust_root_json=json.dumps(self.trust_cfg),
                expected_product="pai-core",
            )

    def test_streaming_hash_large_payload_parity(self):
        large_data = b"PAI_STREAM_CHUNK" * (128 * 1024)  # 2 MiB
        rel_dir = make_test_release(self.src_dir, version="0.3.0", files={"large.bin": large_data})
        u = Updater(self.trust_dir, self.install_dir)
        py_res = u.verify_release(rel_dir)
        rust_res = pai_core_bridge.call_core_bridge(
            "verify_release",
            release_dir=rel_dir,
            trust_root_json=json.dumps(self.trust_cfg),
            expected_product="pai-core",
            check_rollback=False,
        )
        self.assertEqual(py_res.version, rust_res["version"])
        self.assertEqual(py_res.files, rust_res["files"])


if __name__ == "__main__":
    unittest.main()
