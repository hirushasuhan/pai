"""
PAI Payload Test Suite Runner and Exclusion Engine.

Addresses Finding CF / BX:
Executes the research/tests suite against an assembled release payload using its
embedded Python runtime, applying an explicit, documented exclusion list for tests
that depend on repository-only developer assets (tools/, docs/evidence/) that are
not shipped in the binary release payload (ADR-005, ADR-013).

Produces:
  1. Detailed per-test execution status.
  2. Baseline vs payload summary lines.
  3. Raw evidence output log.
"""

from __future__ import annotations

import argparse
import io
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = REPO_ROOT / "research"
TESTS_DIR = RESEARCH_DIR / "tests"

# Explicit Exclusion List with documented factual justifications (Finding CF):
PAYLOAD_EXCLUSIONS: Dict[str, str] = {
    # 1. Developer Evaluation Harness
    "test_eval_harness.TestEvalHarness.test_evidence_records_exist": (
        "Requires repo development benchmark artifacts in docs/evidence/eval_harness/ not shipped in release runtime payload (ADR-005, ADR-013)."
    ),
    "test_eval_harness.TestEvalHarness.test_evidence_checksum_verification": (
        "Requires repo development benchmark hashes in docs/evidence/eval_sets_hashes.json not shipped in release runtime payload."
    ),
    "test_eval_harness.TestEvalHarness.test_discrepancy_log_verification": (
        "Requires repo development discrepancy logs in docs/evidence/ not shipped in release runtime payload."
    ),
    # 2. Developer Sandbox Evidence Audits
    "test_sandbox_evidence.TestSandboxEvidence.test_containment_matrices": (
        "Requires repo development evidence audit log in docs/evidence/m2a_sandbox_raw.log not shipped in release runtime payload."
    ),
    "test_sandbox_evidence.TestSandboxEvidence.test_sandbox_audit_records": (
        "Requires repo development evidence files in docs/evidence/ not shipped in release runtime payload."
    ),
    "test_sandbox_evidence.TestSandboxEvidence.test_evidence_integrity_hashes": (
        "Requires repo development evidence files in docs/evidence/ not shipped in release runtime payload."
    ),
    # 3. Developer Tooling and Shadow Isolation Guard
    "test_shadow_isolation_guard.TestShadowIsolationGuard.test_default_log_immutability_during_parity_runner": (
        "Spawns tools/windows_parity_run.py via subprocess; developer scripts in tools/ are not shipped in release payload (ADR-013)."
    ),
    "test_shadow_isolation_guard.TestShadowIsolationGuard.test_default_log_immutability_during_workload_runner": (
        "Spawns tools/run_shadow_workload.py via subprocess; developer scripts in tools/ are not shipped in release payload (ADR-013)."
    ),
    "test_shadow_isolation_guard.TestShadowIsolationGuard.test_shadow_isolation_mutation_check": (
        "Subprocess execution expects _bootstrap module on sys.path relative to checkout repo root, not isolated payload."
    ),
    "test_shadow_isolation_guard.TestShadowIsolationGuard.test_shadow_worker_isolation": (
        "Subprocess execution spawns tools/ developer harness scripts not present in release payload."
    ),
}

# Entire test files that are developer-only evidence verification
EXCLUDED_TEST_FILES: Set[str] = {
    "test_eval_harness.py",
    "test_sandbox_evidence.py",
    "test_shadow_isolation_guard.py",
}


def create_filtered_suite(
    tests_dir: Path,
    exclude_files: Set[str],
    exclude_test_ids: Set[str],
) -> unittest.TestSuite:
    """Discovers tests and filters out excluded test suites or individual tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    for entry in sorted(tests_dir.glob("test_*.py")):
        if entry.name in exclude_files:
            continue
        mod_suite = loader.discover(str(tests_dir), pattern=entry.name)
        # Filter test cases by id
        filtered_sub = _filter_suite(mod_suite, exclude_test_ids)
        suite.addTest(filtered_sub)

    return suite


def _filter_suite(suite: unittest.TestSuite, exclude_ids: Set[str]) -> unittest.TestSuite:
    filtered = unittest.TestSuite()
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            filtered.addTest(_filter_suite(item, exclude_ids))
        else:
            test_id = item.id()
            # Check if short id or full id matches any excluded ID
            if any(test_id.endswith(ex) or ex in test_id for ex in exclude_ids):
                continue
            filtered.addTest(item)
    return filtered


def run_tests_with_runner(
    suite: unittest.TestSuite,
    stream: io.TextIOBase,
) -> unittest.TestResult:
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    return runner.run(suite)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PAI Payload Test Suite Runner.")
    parser.add_argument("--payload-dir", default=None, help="Path to assembled payload directory")
    parser.add_argument("--python-exe", default=None, help="Path to Python executable to run tests with")
    parser.add_argument("--all-tests", action="store_true", help="Run without exclusions to record unfiltered failures")
    parser.add_argument("--output-evidence", default="docs/evidence/payload_tests/run_payload_tests.txt", help="Evidence log path")

    args = parser.parse_args(argv)

    evidence_out = Path(args.output_evidence)
    evidence_out.parent.mkdir(parents=True, exist_ok=True)

    start_time = time.time()
    tests_dir = TESTS_DIR
    if args.payload_dir:
        payload_p = Path(args.payload_dir).resolve()
        tests_dir = payload_p / "research" / "tests"
        # Emulate launcher boundary: set PAI_CORE_BIN if payload contains core binary
        core_bin = payload_p / "bin" / ("pai-core.exe" if sys.platform == "win32" else "pai-core")
        if core_bin.is_file() and not os.environ.get("PAI_CORE_BIN"):
            os.environ["PAI_CORE_BIN"] = str(core_bin)

    exclude_files = set() if args.all_tests else EXCLUDED_TEST_FILES
    exclude_ids = set() if args.all_tests else set(PAYLOAD_EXCLUSIONS.keys())

    suite = create_filtered_suite(tests_dir, exclude_files, exclude_ids)

    log_buffer = io.StringIO()
    # Tee output to stdout and log_buffer
    class Tee:
        def __init__(self, s1, s2):
            self.s1 = s1
            self.s2 = s2
        def write(self, b):
            self.s1.write(b)
            self.s2.write(b)
        def flush(self):
            self.s1.flush()
            self.s2.flush()

    tee = Tee(sys.stderr, log_buffer)
    runner = unittest.TextTestRunner(stream=tee, verbosity=2)
    res = runner.run(suite)
    elapsed = time.time() - start_time

    # Record summary
    total = res.testsRun
    failures = len(res.failures)
    errors = len(res.errors)
    skipped = len(res.skipped)
    success = res.wasSuccessful()

    summary_line = (
        f"Ran {total} tests in {elapsed:.3f}s: "
        f"{'OK' if success else 'FAILED'} "
        f"(failures={failures}, errors={errors}, skipped={skipped})"
    )
    print(f"\n{summary_line}", file=sys.stderr)
    log_buffer.write(f"\n{summary_line}\n")

    evidence_out.write_text(log_buffer.getvalue(), encoding="utf-8")
    print(f"[EVIDENCE] Wrote test run log to {evidence_out}")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
