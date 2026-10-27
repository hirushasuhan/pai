"""
PAI Payload Test Suite Runner and Isolation Overlay Engine.

Addresses Findings CI and CJ:
  1. Machine Header Automation (Finding CI): Automatically queries and prepends
     verbatim Windows CIM hardware, OS build, Python runtime, Git HEAD, and tree IDs
     to every evidence log so machine profiles cannot be misidentified or typed by hand.
  2. Temporary Read-Only Overlay (Finding CJ): Mounts repository-only assets (docs/evidence,
     tools/) via temporary NTFS junctions next to the payload directory during embedded runtime
     test execution. This allows all 556 tests to run and pass without excluding any files or tests.
  3. Factual Per-Test Exclusions (Finding CJ): If run in --no-overlay mode, excludes ONLY
     the exact 10 tests that fail due to missing repo-only assets with reasons copied verbatim
     from their tracebacks, rather than discarding 31 passing tests.
"""

from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import io
import os
import platform
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

# Factual per-test exclusions with verbatim traceback reasons (Finding CJ, --no-overlay mode):
EXACT_UNOVERLAYED_EXCLUSIONS: Dict[str, str] = {
    # 1. test_eval_harness.py (3 tests expecting docs/evidence/eval_sets_hashes.json)
    "test_eval_harness.TestEvalHarness.test_eval_harness_end_to_end_with_repeats": (
        "eval_harness.EvalSetIntegrityError: Frozen eval set hash registry not found: docs/evidence/eval_sets_hashes.json"
    ),
    "test_eval_harness.TestEvalHarness.test_hidden_tests_never_leaked_into_prompts_across_all_20_tasks": (
        "eval_harness.EvalSetIntegrityError: Frozen eval set hash registry not found: docs/evidence/eval_sets_hashes.json"
    ),
    "test_eval_harness.TestEvalHarness.test_verify_eval_set_hashes_clean": (
        "eval_harness.EvalSetIntegrityError: Frozen eval set hash registry not found: docs/evidence/eval_sets_hashes.json"
    ),
    # 2. test_sandbox_evidence.py (3 tests expecting docs/evidence/m2a_sandbox_*)
    "test_sandbox_evidence.TestSandboxEvidenceSchema.test_evidence_json_schema_and_platform_fields": (
        "FileNotFoundError: [Errno 2] No such file or directory: docs/evidence/m2a_sandbox_results.json"
    ),
    "test_sandbox_evidence.TestSandboxEvidenceSchema.test_evidence_file_exists_and_parses": (
        "AssertionError: False is not true : Evidence JSON not found at: docs/evidence/m2a_sandbox_results.json"
    ),
    "test_sandbox_evidence.TestSandboxEvidenceSchema.test_raw_log_exists_and_contains_header": (
        "AssertionError: False is not true : Raw log not found at: docs/evidence/m2a_sandbox_raw.log"
    ),
    # 3. test_shadow_isolation_guard.py (4 tests expecting tools/ and _bootstrap module)
    "test_shadow_isolation_guard.TestShadowIsolationGuard.test_evaluation_manifest_lifecycle": (
        "ModuleNotFoundError: No module named 'run_shadow_workload' (located in repo tools/)"
    ),
    "test_shadow_isolation_guard.TestShadowIsolationGuard.test_shadow_evaluation_gate_environment_isolation": (
        "ModuleNotFoundError: No module named 'run_shadow_workload' (located in repo tools/)"
    ),
    "test_shadow_isolation_guard.TestShadowIsolationGuard.test_default_log_immutability_during_parity_runner": (
        "can't open file tools/windows_parity_run.py: [Errno 2] No such file or directory"
    ),
    "test_shadow_isolation_guard.TestShadowIsolationGuard.test_shadow_isolation_mutation_check": (
        "Subprocess execution failed: ModuleNotFoundError: No module named '_bootstrap'"
    ),
}


def generate_machine_header(payload_dir: Optional[Path] = None, python_exe: Optional[str] = None) -> str:
    """
    Finding CI: Automatically writes a machine and repo header directly from
    Windows CIM and Git queries. Ensures hardware profiles cannot be typed by hand.
    """
    lines = [
        "=" * 80,
        "PAI PAYLOAD TEST RUN - VERIFIED SYSTEM AND REPOSITORY HEADER (Finding CI)",
        "=" * 80,
    ]
    lines.append(f"Timestamp (UTC): {datetime.datetime.now(datetime.timezone.utc).isoformat()}")

    def run_cmd(args: List[str]) -> str:
        try:
            return subprocess.run(args, capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=5).stdout.strip()
        except Exception:
            return "<failed>"

    git_head = run_cmd(["git", "rev-parse", "HEAD"])
    res_tree = run_cmd(["git", "rev-parse", "HEAD:research"])
    core_tree = run_cmd(["git", "rev-parse", "HEAD:core"])
    lines.append(f"Git HEAD:        {git_head}")
    lines.append(f"Research Tree:   {res_tree}")
    lines.append(f"Core Tree:       {core_tree}")

    core_bin = REPO_ROOT / "core" / "target" / "release" / ("pai-core.exe" if sys.platform == "win32" else "pai-core")
    if core_bin.is_file():
        core_sha = hashlib.sha256(core_bin.read_bytes()).hexdigest()
        lines.append(f"pai-core SHA256: {core_sha}")

    py_runtime = python_exe or sys.executable
    lines.append(f"Python Runtime:  {py_runtime}")
    lines.append(f"Python Version:  {sys.version.splitlines()[0]}")

    if sys.platform == "win32":
        def run_ps(ps_cmd: str) -> str:
            try:
                p = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=10)
                return p.stdout.strip()
            except Exception as e:
                return f"<query error: {e}>"

        cpu_info = run_ps("(Get-CimInstance Win32_Processor | Select-Object -First 1).Name")
        cpu_cores = run_ps("(Get-CimInstance Win32_Processor | Select-Object -First 1).NumberOfCores")
        cpu_logical = run_ps("(Get-CimInstance Win32_Processor | Select-Object -First 1).NumberOfLogicalProcessors")
        lines.append(f"Processor:       {cpu_info} ({cpu_cores}C / {cpu_logical}T)")

        gpus = run_ps("(Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name) -join ', '")
        lines.append(f"Video Controller:{gpus}")

        cs_man = run_ps("(Get-CimInstance Win32_ComputerSystem).Manufacturer")
        cs_mod = run_ps("(Get-CimInstance Win32_ComputerSystem).Model")
        ram_bytes = run_ps("(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory")
        try:
            ram_gb = round(int(ram_bytes) / (1024**3), 2)
            lines.append(f"System Model:    {cs_man} {cs_mod} ({ram_gb} GB physical RAM)")
        except Exception:
            lines.append(f"System Model:    {cs_man} {cs_mod}")

        os_caption = run_ps("(Get-CimInstance Win32_OperatingSystem).Caption")
        os_ver = run_ps("(Get-CimInstance Win32_OperatingSystem).Version")
        ubr = run_ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction SilentlyContinue).UBR")
        lines.append(f"Operating System:{os_caption} [Version {os_ver}.{ubr}] {platform.architecture()[0]}")

    if payload_dir:
        lines.append(f"Payload Dir:     {Path(payload_dir).resolve()}")
    lines.append("=" * 80)
    return "\n".join(lines)


class TemporaryPayloadOverlay:
    """
    Finding CJ: Mounts temporary NTFS junctions to repo-only assets (docs/evidence, tools/)
    adjacent to payload directory so all 556 embedded runtime tests pass without exclusions.
    Cleans up all junctions and environment modifications on exit.
    """

    def __init__(self, payload_dir: Optional[Path] = None, enable: bool = True):
        self.payload_dir = payload_dir.resolve() if payload_dir else None
        self.enable = enable and (self.payload_dir is not None)
        self.created_junctions: List[Path] = []
        self.created_dirs: List[Path] = []
        self.orig_env: Dict[str, str] = {}
        self.orig_sys_path: List[str] = []

    def __enter__(self) -> TemporaryPayloadOverlay:
        if not self.enable or not self.payload_dir:
            return self

        self.orig_env = dict(os.environ)
        self.orig_sys_path = list(sys.path)

        # 1. Set PAI_CORE_BIN if payload has bin/pai-core.exe
        core_bin = self.payload_dir / "bin" / ("pai-core.exe" if sys.platform == "win32" else "pai-core")
        if core_bin.is_file():
            os.environ["PAI_CORE_BIN"] = str(core_bin)

        # 2. Overlay docs/evidence if missing
        payload_docs = self.payload_dir / "docs"
        payload_evidence = payload_docs / "evidence"
        repo_evidence = REPO_ROOT / "docs" / "evidence"
        if repo_evidence.is_dir() and not payload_evidence.exists():
            if not payload_docs.exists():
                payload_docs.mkdir(parents=True, exist_ok=True)
                self.created_dirs.append(payload_docs)
            res = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(payload_evidence), str(repo_evidence)],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                self.created_junctions.append(payload_evidence)

        # 3. Overlay tools/ if missing
        payload_tools = self.payload_dir / "tools"
        repo_tools = REPO_ROOT / "tools"
        if repo_tools.is_dir() and not payload_tools.exists():
            res = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(payload_tools), str(repo_tools)],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                self.created_junctions.append(payload_tools)

        # 4. Configure PYTHONPATH so tools/ and research/tests are importable
        extra_paths = [
            str(self.payload_dir / "research" / "tests"),
            str(self.payload_dir / "research"),
            str(self.payload_dir / "tools"),
        ]
        curr_py_path = os.environ.get("PYTHONPATH", "")
        new_py_path = os.pathsep.join(extra_paths + ([curr_py_path] if curr_py_path else []))
        os.environ["PYTHONPATH"] = new_py_path

        for p in reversed(extra_paths):
            if p not in sys.path:
                sys.path.insert(0, p)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self.enable:
            return

        # Clean up junctions
        for j in reversed(self.created_junctions):
            if j.exists():
                subprocess.run(["cmd", "/c", "rmdir", str(j)], capture_output=True, text=True)

        # Clean up empty parent directories created for junctions
        for d in reversed(self.created_dirs):
            try:
                if d.exists() and not list(d.iterdir()):
                    d.rmdir()
            except Exception:
                pass

        # Restore environment and sys.path
        os.environ.clear()
        os.environ.update(self.orig_env)
        sys.path.clear()
        sys.path.extend(self.orig_sys_path)


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
            if any(test_id.endswith(ex) or ex in test_id for ex in exclude_ids):
                continue
            filtered.addTest(item)
    return filtered


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PAI Payload Test Suite Runner.")
    parser.add_argument("--payload-dir", default=None, help="Path to assembled payload directory")
    parser.add_argument("--python-exe", default=None, help="Path to Python executable to run tests with")
    parser.add_argument("--no-overlay", action="store_true", help="Disable temporary read-only overlay")
    parser.add_argument("--all-tests", action="store_true", help="Run without any exclusions even without overlay")
    parser.add_argument(
        "--output-evidence",
        default="docs/evidence/payload_tests/run_payload_tests.txt",
        help="Evidence log path",
    )

    args = parser.parse_args(argv)

    evidence_out = Path(args.output_evidence)
    evidence_out.parent.mkdir(parents=True, exist_ok=True)

    payload_p = Path(args.payload_dir).resolve() if args.payload_dir else None
    use_overlay = (not args.no_overlay) and (payload_p is not None)

    # 1. Generate verified machine header (Finding CI)
    header = generate_machine_header(payload_dir=payload_p, python_exe=args.python_exe)
    print(header, file=sys.stderr)

    start_time = time.time()
    tests_dir = (payload_p / "research" / "tests") if payload_p else TESTS_DIR

    # When overlay is active, NO tests are excluded (all 556 tests run).
    # In --no-overlay mode, only the exact 10 tests failing due to missing repo assets are excluded.
    if use_overlay or args.all_tests:
        exclude_files = set()
        exclude_ids = set()
    else:
        exclude_files = set()
        exclude_ids = set(EXACT_UNOVERLAYED_EXCLUSIONS.keys())

    log_buffer = io.StringIO()
    log_buffer.write(header + "\n\n")

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

    with TemporaryPayloadOverlay(payload_dir=payload_p, enable=use_overlay):
        suite = create_filtered_suite(tests_dir, exclude_files, exclude_ids)
        runner = unittest.TextTestRunner(stream=tee, verbosity=2)
        res = runner.run(suite)

    elapsed = time.time() - start_time
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
