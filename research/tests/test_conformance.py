import json
import math
import os
import unittest

import _bootstrap  # noqa: F401
import conformance
from hardware_telemetry import HardwareTelemetry
from ingest import (
    defang_envelope_markers,
    get_ingest_limits,
    is_junk_dir,
    is_secret_file,
    sanitize_header,
    sanitize_terminal_output,
    sanitize_text_content,
    scan_secret_content,
    wrap_untrusted_envelope,
)
from net_guard import UrlRejected, validate_url
from value_codec import CodecError, decode_value, encode_value, get_codec_policy
from verify_loop import extract_example_assertions, verify_verdict_frame

DIR = conformance.OUT_DIR


def load(name):
    with open(os.path.join(DIR, name), encoding="utf-8") as f:
        return json.load(f)


class Vectors(unittest.TestCase):
    def test_tier_vectors_match_the_code(self):
        t = HardwareTelemetry(cpu_sample_ms=0)
        vectors = load("tier_policy_vectors.json")
        self.assertGreaterEqual(len(vectors), 200)
        for v in vectors:
            i, e = v["input"], v["expected"]
            t.cpu_count = i["cpu_cores"]
            b = t._calculate_budget(i["avail_ram_mb"], i["memory_load_pct"], i["cpu_load_pct"], i["battery"])
            got = {
                "compute_tier": b.compute_tier,
                "max_context_bytes": b.max_context_bytes,
                "allow_speculation": b.allow_speculation,
                "thread_pool_limit": b.thread_pool_limit,
                "reasons": b.reasons,
            }
            self.assertEqual(got, e, i)

    def test_url_vectors_match_the_code(self):
        for v in load("url_policy_vectors.json"):
            self.assertEqual(conformance.evaluate_url(v["url"]), v["expected"], v["url"])

    def test_ingest_vectors_match_the_code(self):
        vec = load("ingest_vectors.json")
        self.assertEqual(vec["limits"], get_ingest_limits())
        for c in vec["secret_file_cases"]:
            self.assertEqual(is_secret_file(c["path"]), c["expected"], c["path"])
        for c in vec["junk_dir_cases"]:
            self.assertEqual(is_junk_dir(c["dirname"]), c["expected"], c["dirname"])
        for c in vec["secret_content_cases"]:
            joined_text = "".join(c["text_parts"])
            self.assertEqual(
                scan_secret_content(joined_text, file_path=c["file_path"]),
                c["expected"],
                c["id"],
            )
            # Ensure individual stored pieces do not trigger secret scanners at rest
            for part in c["text_parts"]:
                self.assertIsNone(
                    scan_secret_content(part, file_path=c["file_path"]),
                    f"Piecewise fragment in {c['id']} triggered secret scanner at rest: {part!r}",
                )
        for c in vec["sanitize_terminal_cases"]:
            self.assertEqual(sanitize_terminal_output(c["input"]), c["expected"], c["id"])
        for c in vec["sanitize_text_cases"]:
            self.assertEqual(
                sanitize_text_content(c["raw_utf8"].encode("utf-8"), max_line_length=c["max_line_length"]),
                c["expected"],
                c["id"],
            )
        for c in vec["sanitize_header_cases"]:
            self.assertEqual(sanitize_header(c["header"]), c["expected"], c["id"])
        for c in vec["envelope_cases"]:
            self.assertEqual(
                defang_envelope_markers(c["content"], nonce=c["nonce"]),
                c["expected_defanged"],
                c["id"],
            )
            self.assertEqual(
                wrap_untrusted_envelope(c["content"], header=c["header"], nonce=c["nonce"]),
                c["expected_envelope"],
                c["id"],
            )

        # Verify that neither ingest_vectors.json nor conformance.py triggers scan_secret_content at rest
        with open(os.path.join(DIR, "ingest_vectors.json"), encoding="utf-8") as f:
            raw_json = f.read()
        self.assertIsNone(
            scan_secret_content(raw_json, file_path="research/conformance/ingest_vectors.json"),
            "ingest_vectors.json must not contain contiguous secret-shaped literals at rest",
        )
        with open(conformance.__file__, encoding="utf-8") as f:
            raw_py = f.read()
        self.assertIsNone(
            scan_secret_content(raw_py, file_path="research/conformance.py"),
            "conformance.py must not contain contiguous secret-shaped literals at rest",
        )

    def test_verify_loop_vectors_match_the_code(self):
        vec = load("verify_loop_vectors.json")
        self.assertEqual(vec["codec_policy"], get_codec_policy())
        for c in vec["codec_roundtrip_cases"]:
            decoded = decode_value(c["encoded"])
            self.assertEqual(type(decoded).__name__, c["python_type"], c["id"])
            re_encoded = encode_value(decoded)
            self.assertEqual(re_encoded, c["encoded"], c["id"])
            if isinstance(decoded, float) and math.isnan(decoded):
                self.assertEqual(c["encoded"]["v"], "nan")
        for c in vec["codec_invalid_envelope_cases"]:
            with self.assertRaises(CodecError, msg=c["id"]):
                decode_value(c["envelope"])
        for c in vec["verdict_frame_cases"]:
            got = verify_verdict_frame(
                c["stdout"],
                c["parent_nonce"],
                c["parent_hmac_key"],
                expected_test_ids=tuple(c["expected_test_ids"]),
                expected_test_hash=c.get("expected_test_hash"),
                exit_code=c["exit_code"],
                res_status=c["res_status"],
            )
            self.assertEqual(got, c["expected"], c["id"])
        for c in vec["canonical_example_extraction_cases"]:
            got_stmts = extract_example_assertions(c["prompt"], entry_point=c["entry_point"])
            self.assertEqual(got_stmts, c["expected_statements"], c["id"])

    def test_checked_in_files_are_in_sync_with_generators(self):
        """If this fails the policy changed: run `python conformance.py` AND review the vector diff."""
        self.assertEqual(load("tier_policy_vectors.json"), json.loads(json.dumps(conformance.tier_policy_vectors())))
        self.assertEqual(load("url_policy_vectors.json"), conformance.url_policy_vectors())
        self.assertEqual(load("ingest_vectors.json"), json.loads(json.dumps(conformance.ingest_vectors())))
        self.assertEqual(load("verify_loop_vectors.json"), json.loads(json.dumps(conformance.verify_loop_vectors())))

    def test_multicast_and_unspecified_addresses_are_rejected(self):
        for url in ("http://224.0.0.1/", "http://239.255.255.250/", "http://[ff02::1]/", "http://0.0.0.0/", "http://240.0.0.1/"):
            with self.assertRaises(UrlRejected, msg=url):
                validate_url(url)


if __name__ == "__main__":
    unittest.main()
