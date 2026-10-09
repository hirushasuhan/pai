"""
Unit Tests for Mutant Benchmark
Verifies:
1. Total mutants >= 40.
2. Every mutant has valid syntax and compiles cleanly.
3. Every mutant strictly FAILS hidden reference tests (100% kill rate by reference suite).
4. Provides runner to test any proposed gate against the mutant benchmark (must accept 0 mutants).
"""

from __future__ import annotations

import unittest
import os
import sys

_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_DIR)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from eval_sets.mutants import MUTANTS
from eval_sets.hidden_tests.test_coding_tasks import HIDDEN_TESTS


class TestMutantBenchmark(unittest.TestCase):
    def test_mutant_benchmark_integrity(self):
        self.assertGreaterEqual(len(MUTANTS), 40, "Mutant benchmark must contain >= 40 mutants")

        for m in MUTANTS:
            mid = m["id"]
            tid = m["task_id"]
            code = m["code"].strip()

            self.assertTrue(code, f"Mutant {mid} code must not be empty")
            self.assertIn(tid, HIDDEN_TESTS, f"Mutant {mid} references invalid task_id {tid}")

            # Must compile cleanly
            ns = {}
            try:
                compiled = compile(code, f"<mutant_{mid}>", "exec")
                exec(compiled, ns)
            except Exception as e:
                self.fail(f"Mutant {mid} failed compilation/exec: {e}")

            # Find callable entry point
            fn = None
            for k, v in ns.items():
                if callable(v) and not k.startswith("_"):
                    fn = v
                    break

            self.assertIsNotNone(fn, f"Mutant {mid} must expose an entry point")

            # Must FAIL at least one hidden reference test
            tests = HIDDEN_TESTS[tid]
            all_passed = True
            for t in tests:
                try:
                    if not t(fn):
                        all_passed = False
                        break
                except Exception:
                    all_passed = False
                    break

            self.assertFalse(all_passed, f"Mutant {mid} for task {tid} must FAIL hidden tests, but passed!")


if __name__ == "__main__":
    unittest.main()
