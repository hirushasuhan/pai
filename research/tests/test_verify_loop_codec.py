"""
Unit Tests and Security Controls for Value Codec (H5)
Tests round-trip fidelity, exact-type enforcement, tag forgery defense,
recursion limits, and equality-hijacking negative controls.
"""

from __future__ import annotations

import math
import os
import sys
import unittest

_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_DIR)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from value_codec import (
    CodecError,
    EqualityHijackError,
    MAX_COLLECTION_LENGTH,
    MAX_INT64,
    MAX_ITEM_COUNT,
    MAX_RECURSION_DEPTH,
    MIN_INT64,
    decode_value,
    encode_value,
    get_codec_policy,
)
from verify_loop import format_authenticated_verdict_frame, verify_verdict_frame


class TestValueCodecPositiveControls(unittest.TestCase):
    def test_primitives_roundtrip(self):
        cases = [
            42,
            -100,
            0,
            MAX_INT64,
            MIN_INT64,
            3.14159,
            -0.001,
            "hello world",
            "",
            "special \n \t \r characters",
            True,
            False,
            None,
            b"binary \x00\xff data",
            b"",
        ]
        for val in cases:
            enc = encode_value(val)
            dec = decode_value(enc)
            self.assertEqual(dec, val)
            self.assertIs(type(dec), type(val))

    def test_float_specials(self):
        # nan
        enc_nan = encode_value(float("nan"))
        dec_nan = decode_value(enc_nan)
        self.assertTrue(math.isnan(dec_nan))
        self.assertIs(type(dec_nan), float)

        # inf
        enc_inf = encode_value(float("inf"))
        dec_inf = decode_value(enc_inf)
        self.assertTrue(math.isinf(dec_inf) and dec_inf > 0)
        self.assertIs(type(dec_inf), float)

        # -inf
        enc_ninf = encode_value(float("-inf"))
        dec_ninf = decode_value(enc_ninf)
        self.assertTrue(math.isinf(dec_ninf) and dec_ninf < 0)
        self.assertIs(type(dec_ninf), float)

    def test_collections_roundtrip(self):
        cases = [
            [],
            [1, "a", 3.0, None, False],
            (),
            (1, 2, "three"),
            set(),
            {1, 2, 3, "four"},
            frozenset(),
            frozenset([10, 20, 30]),
            {},
            {"a": 1, "b": [2, 3]},
            # Non-string keys in dictionary!
            {1: "one", 2: "two", 3: "three"},
            {(1, 2): "tuple_key", (3, 4): "another_tuple_key"},
            {frozenset([1, 2]): "frozenset_key"},
        ]
        for val in cases:
            enc = encode_value(val)
            dec = decode_value(enc)
            self.assertEqual(dec, val)
            self.assertIs(type(dec), type(val))

    def test_nested_structures(self):
        val = {
            "intervals": [(1, 4), (4, 5)],
            "counts": [("a", 3), ("b", 2), ("c", 1)],
            "nested": {
                100: {
                    "tags": {"admin", "user"},
                    "bytes": b"\x01\x02\x03",
                    "flag": True,
                }
            },
        }
        enc = encode_value(val)
        dec = decode_value(enc)
        self.assertEqual(dec, val)
        self.assertIs(type(dec["intervals"][0]), tuple)
        self.assertIs(type(dec["nested"][100]["tags"]), set)


class TestValueCodecNegativeControls(unittest.TestCase):
    def test_tag_forgery_defense(self):
        """
        A candidate returning a dict resembling a tag envelope must NOT be decoded
        as that tagged type.
        """
        fake_envelope = {"t": "tuple", "v": [1, 2, 3]}
        enc = encode_value(fake_envelope)
        dec = decode_value(enc)

        # Must decode to a dict, NEVER a tuple!
        self.assertIs(type(dec), dict)
        self.assertNotIsInstance(dec, tuple)
        self.assertEqual(dec, {"t": "tuple", "v": [1, 2, 3]})

    def test_subclass_rejection(self):
        class SubTuple(tuple):
            pass

        class SubInt(int):
            pass

        class SubList(list):
            pass

        class SubDict(dict):
            pass

        class SubSet(set):
            pass

        with self.assertRaises(EqualityHijackError):
            encode_value(SubTuple([1, 2]))

        with self.assertRaises(EqualityHijackError):
            encode_value(SubInt(42))

        with self.assertRaises(EqualityHijackError):
            encode_value(SubList([1, 2]))

        with self.assertRaises(EqualityHijackError):
            encode_value(SubDict({"a": 1}))

        with self.assertRaises(EqualityHijackError):
            encode_value(SubSet([1, 2]))

    def test_equality_hijack_rejection(self):
        class HijackObject:
            def __eq__(self, other):
                return True

        with self.assertRaises(EqualityHijackError):
            encode_value(HijackObject())

    def test_circular_reference_rejection(self):
        a = []
        a.append(a)
        with self.assertRaises(CodecError) as ctx:
            encode_value(a)
        self.assertIn("Circular reference detected", str(ctx.exception))

    def test_recursion_depth_limit(self):
        # Construct deeply nested list > MAX_RECURSION_DEPTH (32)
        cur = 1
        for _ in range(MAX_RECURSION_DEPTH + 1):
            cur = [cur]

        with self.assertRaises(CodecError) as ctx:
            encode_value(cur)
        self.assertIn("recursion depth limit exceeded", str(ctx.exception).lower())

        env = {"t": "int", "v": 1}
        for _ in range(MAX_RECURSION_DEPTH + 1):
            env = {"t": "list", "v": [env]}
        with self.assertRaises(CodecError) as ctx2:
            decode_value(env)
        self.assertIn("recursion depth limit exceeded", str(ctx2.exception).lower())

    def test_collection_length_limit(self):
        too_long = list(range(MAX_COLLECTION_LENGTH + 1))
        with self.assertRaises(CodecError) as ctx:
            encode_value(too_long)
        self.assertIn("1001 > 1000", str(ctx.exception).lower())

        too_long_env = {"t": "list", "v": [{"t": "int", "v": 0}] * (MAX_COLLECTION_LENGTH + 1)}
        with self.assertRaises(CodecError) as ctx2:
            decode_value(too_long_env)
        self.assertIn("1001 > 1000", str(ctx2.exception).lower())

    def test_item_count_limit(self):
        # 60 nested lists of 900 items each = 54,000 items (> MAX_ITEM_COUNT=50,000) while each collection <= 1,000
        big_nested = [[0] * 900 for _ in range(60)]
        with self.assertRaises(CodecError) as ctx:
            encode_value(big_nested)
        self.assertIn("item limit exceeded", str(ctx.exception).lower())

    def test_int64_range_enforcement(self):
        for out_of_range in (MAX_INT64 + 1, MIN_INT64 - 1, 1 << 100, -(1 << 100)):
            with self.assertRaises(CodecError):
                encode_value(out_of_range)
            with self.assertRaises(CodecError):
                decode_value({"t": "int", "v": out_of_range})

    def test_rust_decoder_edge_case_policies(self):
        policy = get_codec_policy()
        self.assertEqual(policy["max_recursion_depth"], 32)
        self.assertEqual(policy["max_collection_length"], 1000)
        self.assertEqual(policy["min_int64"], MIN_INT64)
        self.assertEqual(policy["max_int64"], MAX_INT64)

        edge_bad_envelopes = [
            {"t": "float", "v": True},
            {"t": "float", "v": False},
            {"t": "int", "v": 42, "extra": "unexpected"},
            {
                "t": "dict",
                "v": [
                    [{"t": "str", "v": "dup"}, {"t": "int", "v": 1}],
                    [{"t": "str", "v": "dup"}, {"t": "int", "v": 2}],
                ],
            },
            {
                "t": "set",
                "v": [{"t": "int", "v": 7}, {"t": "int", "v": 7}],
            },
        ]
        for bad in edge_bad_envelopes:
            with self.assertRaises(CodecError, msg=repr(bad)):
                decode_value(bad)

    def test_malformed_decode_envelope(self):
        bad_cases = [
            "not a dict",
            {"missing_v": 1},
            {"t": "unknown_type", "v": 123},
            {"t": "int", "v": "not an int"},
            {"t": "int", "v": True},  # bool is not int
            {"t": "bool", "v": 1},    # 1 is not bool
            {"t": "tuple", "v": "not a list"},
            {"t": "dict", "v": [["only_one_item"]]},
        ]
        for bad in bad_cases:
            with self.assertRaises(CodecError):
                decode_value(bad)

    def test_verdict_frame_test_suite_hash_mismatch(self):
        nonce = "a" * 64
        key = "b" * 64
        payload = {
            "session_nonce": nonce,
            "status": "PASS",
            "discovered": 1,
            "executed": 1,
            "passed": 1,
            "failed": 0,
            "errors": 0,
            "executed_test_ids": ["test_one"],
            "per_test_outcomes": {"test_one": {"status": "PASS"}},
            "failures": [],
            "test_hash": "1111" * 16,
        }
        stdout = format_authenticated_verdict_frame(payload, key)
        res = verify_verdict_frame(
            stdout,
            nonce,
            key,
            expected_test_ids=("test_one",),
            expected_test_hash="2222" * 16,
            exit_code=0,
            res_status="ok",
        )
        self.assertEqual(res["status"], "mutation_error")
        self.assertEqual(res["error_type"], "TestMutationError")


if __name__ == "__main__":
    unittest.main()
