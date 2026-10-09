"""
Gate-Level Mutant Runner
Runs the Mutant Benchmark through the actual production verification pipeline (VerifyLoop)
against model-generated test suites from evaluation runs.

Pre-declared rule: The gate must accept strictly 0 mutants (100% mutant kill rate).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from eval_sets.mutants import MUTANTS
from eval_sets.mutants_holdout import MUTANTS_HOLDOUT
from verify_loop import FrozenTestSuite, VerifyLoop


def load_diag_jsonl(path: str) -> Dict[str, Dict[str, Any]]:
    records = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rec = json.loads(line)
                if rec.get("repeat_idx", 1) == 1:
                    records[rec["task_id"]] = rec
    return records


def run_mutants_against_gate(
    diag_jsonl_path: str,
    gate_off_jsonl_path: Optional[str] = None,
    mutants_list: Optional[List[Dict[str, Any]]] = None,
    timeout_sec: float = 10.0,
    memory_mb: float = 512.0,
) -> Dict[str, Any]:
    if mutants_list is None:
        mutants_list = MUTANTS

    gated_recs = load_diag_jsonl(diag_jsonl_path)
    loop = VerifyLoop(timeout_sec=timeout_sec, memory_mb=memory_mb)

    # 1. Collect known-good solutions to check test suite validity (discriminating power)
    known_good_sols: Dict[str, str] = {}
    if gate_off_jsonl_path:
        go_recs = load_diag_jsonl(gate_off_jsonl_path)
        for tid, r in go_recs.items():
            if r.get("hidden_test_result", {}).get("passed"):
                sol = r.get("candidate_solution")
                if sol:
                    known_good_sols[tid] = sol

    # Any task accepted by gated run also has a known-good candidate solution
    for tid, r in gated_recs.items():
        if r.get("pai_verdict") == "PASS" and r.get("candidate_solution"):
            known_good_sols[tid] = r["candidate_solution"]

    # 2. Check each task's generated test suite against known-good solution
    suite_validity: Dict[str, Dict[str, Any]] = {}
    for tid, r in gated_recs.items():
        gt_tests = r.get("generated_test_code")
        if not gt_tests:
            suite_validity[tid] = {
                "valid": False,
                "reason": f"No tests generated ({r.get('termination_stage')})",
            }
            continue

        ref_sol = known_good_sols.get(tid)
        if not ref_sol:
            suite_validity[tid] = {
                "valid": False,
                "reason": "No known-good reference solution available to verify suite",
            }
            continue

        try:
            frozen = FrozenTestSuite.create(gt_tests)
            ref_res = loop.execute_solution_tests(ref_sol, frozen)
            if ref_res.passed:
                suite_validity[tid] = {
                    "valid": True,
                    "reason": "Model test suite passed known-good solution",
                }
            else:
                suite_validity[tid] = {
                    "valid": False,
                    "reason": f"Model test suite failed known-good solution ({ref_res.status})",
                }
        except Exception as e:
            suite_validity[tid] = {
                "valid": False,
                "reason": f"Suite execution error on known-good: {e}",
            }

    results = []
    accepted_mutants = []
    rejected_mutants = []

    # Counters for discriminating vs uninformative tests
    discrim_tested = 0
    discrim_accepted = 0
    discrim_rejected = 0

    uninf_tested = 0
    uninf_accepted = 0
    uninf_rejected = 0

    for m in mutants_list:
        mid = m["id"]
        tid = m["task_id"]
        m_code = m["code"].strip()
        m_desc = m.get("description", "")

        gt_rec = gated_recs.get(tid, {})
        gt_tests = gt_rec.get("generated_test_code")
        val_info = suite_validity.get(tid, {"valid": False, "reason": "No suite information"})
        is_discrim = val_info["valid"]

        if is_discrim:
            discrim_tested += 1
        else:
            uninf_tested += 1

        # If the gated pipeline rejected the task before solution or tests:
        if not gt_tests:
            res_entry = {
                "mutant_id": mid,
                "task_id": tid,
                "description": m_desc,
                "suite_valid": False,
                "gate_status": "REJECTED",
                "reason": f"Gate rejected task before tests ({gt_rec.get('termination_stage')})",
                "test_status": None,
            }
            rejected_mutants.append(mid)
            if is_discrim:
                discrim_rejected += 1
            else:
                uninf_rejected += 1
            results.append(res_entry)
            continue

        # Execute mutant against the model's test suite inside the sandbox
        try:
            frozen = FrozenTestSuite.create(gt_tests)
            test_res = loop.execute_solution_tests(m_code, frozen)
            if test_res.passed:
                res_entry = {
                    "mutant_id": mid,
                    "task_id": tid,
                    "description": m_desc,
                    "suite_valid": is_discrim,
                    "gate_status": "ACCEPTED",
                    "reason": "Mutant passed model test suite (FALSE ACCEPT)",
                    "test_status": test_res.status,
                    "failures": [],
                }
                accepted_mutants.append(mid)
                if is_discrim:
                    discrim_accepted += 1
                else:
                    uninf_accepted += 1
            else:
                res_entry = {
                    "mutant_id": mid,
                    "task_id": tid,
                    "description": m_desc,
                    "suite_valid": is_discrim,
                    "gate_status": "REJECTED",
                    "reason": "Mutant failed model test suite",
                    "test_status": test_res.status,
                    "failures": [f.get("message", "")[:100] for f in (test_res.failures or [])[:2]],
                }
                rejected_mutants.append(mid)
                if is_discrim:
                    discrim_rejected += 1
                else:
                    uninf_rejected += 1
        except Exception as e:
            res_entry = {
                "mutant_id": mid,
                "task_id": tid,
                "description": m_desc,
                "suite_valid": is_discrim,
                "gate_status": "REJECTED",
                "reason": f"Execution error: {e}",
                "test_status": "ERROR",
            }
            rejected_mutants.append(mid)
            if is_discrim:
                discrim_rejected += 1
            else:
                uninf_rejected += 1

        results.append(res_entry)

    summary = {
        "diag_jsonl_path": diag_jsonl_path,
        "gate_off_jsonl_path": gate_off_jsonl_path,
        "total_mutants": len(mutants_list),
        "total_accepted_mutants": len(accepted_mutants),
        "total_rejected_mutants": len(rejected_mutants),
        "mutant_kill_rate": round(len(rejected_mutants) / len(mutants_list), 4) if mutants_list else 1.0,
        "discriminating_power": {
            "valid_suites_task_count": sum(1 for v in suite_validity.values() if v["valid"]),
            "mutants_tested": discrim_tested,
            "accepted_mutants": discrim_accepted,
            "rejected_mutants": discrim_rejected,
            "kill_rate": round(discrim_rejected / discrim_tested, 4) if discrim_tested else 1.0,
        },
        "uninformative_tests": {
            "invalid_or_broken_task_count": sum(1 for v in suite_validity.values() if not v["valid"]),
            "mutants_tested": uninf_tested,
            "accepted_mutants": uninf_accepted,
            "rejected_mutants": uninf_rejected,
        },
        "results": results,
    }
    return summary


def format_mutant_report(summary: Dict[str, Any]) -> str:
    lines = []
    lines.append("### Gate-Level Mutant Benchmark Report\n")
    lines.append(f"- **Evidence Source**: `{summary['diag_jsonl_path']}`")
    if summary.get("gate_off_jsonl_path"):
        lines.append(f"- **Known-Good Reference**: `{summary['gate_off_jsonl_path']}`")
    lines.append(f"- **Total Mutants Tested**: {summary['total_mutants']}")
    lines.append(f"- **Overall Accepted Mutants (Must be 0)**: **{summary['total_accepted_mutants']}**")
    lines.append(f"- **Overall Rejected Mutants**: **{summary['total_rejected_mutants']}**")
    lines.append(f"- **Overall Mutant Kill Rate**: **{summary['mutant_kill_rate'] * 100:.1f}%**\n")

    dp = summary["discriminating_power"]
    un = summary["uninformative_tests"]
    lines.append("#### Discriminating Power Breakdown:")
    lines.append(f"1. **Discriminating Tests (Suites Passing Known-Good Solution)**:")
    lines.append(f"   - **Valid Task Suites**: {dp['valid_suites_task_count']}")
    lines.append(f"   - **Mutants Tested**: **{dp['mutants_tested']}**")
    lines.append(f"   - **Accepted Mutants (False Accepts, Must be 0)**: **{dp['accepted_mutants']}**")
    lines.append(f"   - **Rejected Mutants**: **{dp['rejected_mutants']}**")
    lines.append(f"   - **Kill Rate on Valid Suites**: **{dp['kill_rate'] * 100:.1f}%**")
    lines.append(f"2. **Uninformative / Broken Suites (Suites Failing Known-Good or Pre-Rejected)**:")
    lines.append(f"   - **Broken / Pre-rejected Tasks**: {un['invalid_or_broken_task_count']}")
    lines.append(f"   - **Mutants Tested**: {un['mutants_tested']}")
    lines.append(f"   - **Accepted Mutants**: **{un['accepted_mutants']}**")
    lines.append(f"   - **Rejected Mutants**: **{un['rejected_mutants']}**\n")

    if summary["total_accepted_mutants"] > 0:
        lines.append("#### WARNING: Accepted Mutants Detected:")
        for r in summary["results"]:
            if r["gate_status"] == "ACCEPTED":
                lines.append(f"- `{r['mutant_id']}` (Task: `{r['task_id']}`)")
        lines.append("")

    lines.append("| Mutant ID | Task ID | Description | Suite Validity | Gate Verdict | Reason |")
    lines.append("|---|---|---|:---:|:---:|---|")
    for r in summary["results"]:
        verdict = f"**{r['gate_status']}**" if r['gate_status'] == "ACCEPTED" else r['gate_status']
        suite_val = "VALID" if r.get("suite_valid") else "BROKEN/PRE-REJECTED"
        lines.append(f"| `{r['mutant_id']}` | `{r['task_id']}` | {r['description']} | {suite_val} | {verdict} | {r['reason']} |")

    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gate-Level Mutant Runner")
    parser.add_argument("--diag-jsonl", type=str, required=True, help="Path to evaluation diag JSONL with generated tests")
    parser.add_argument("--gate-off-jsonl", type=str, default=None, help="Path to gate-off diag JSONL with known-good solutions")
    parser.add_argument("--mutants-set", type=str, choices=["tuning", "holdout", "all"], default="tuning", help="Mutant set to evaluate")
    parser.add_argument("--json", action="store_true", help="Output JSON format")

    args = parser.parse_args()
    if args.mutants_set == "tuning":
        m_list = MUTANTS
    elif args.mutants_set == "holdout":
        m_list = MUTANTS_HOLDOUT
    else:
        m_list = MUTANTS + MUTANTS_HOLDOUT

    summary = run_mutants_against_gate(
        args.diag_jsonl,
        gate_off_jsonl_path=args.gate_off_jsonl,
        mutants_list=m_list,
    )
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_mutant_report(summary))
