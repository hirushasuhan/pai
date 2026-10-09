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
    mutants_list: Optional[List[Dict[str, Any]]] = None,
    timeout_sec: float = 10.0,
    memory_mb: float = 512.0,
) -> Dict[str, Any]:
    if mutants_list is None:
        mutants_list = MUTANTS

    gated_recs = load_diag_jsonl(diag_jsonl_path)
    loop = VerifyLoop(timeout_sec=timeout_sec, memory_mb=memory_mb)

    results = []
    accepted_mutants = []
    rejected_mutants = []

    for m in mutants_list:
        mid = m["id"]
        tid = m["task_id"]
        m_code = m["code"].strip()
        m_desc = m.get("description", "")

        gt_rec = gated_recs.get(tid, {})
        gt_tests = gt_rec.get("generated_test_code")
        gated_verdict = gt_rec.get("pai_verdict")

        # If the gated pipeline rejected the task before solution or tests:
        # e.g., generator error or no tests
        if not gt_tests:
            res_entry = {
                "mutant_id": mid,
                "task_id": tid,
                "description": m_desc,
                "gate_status": "REJECTED",
                "reason": f"Gate rejected task before tests ({gt_rec.get('termination_stage')})",
                "test_status": None,
            }
            rejected_mutants.append(mid)
            results.append(res_entry)
            continue

        # Execute mutant against the model's test suite inside the sandbox
        try:
            frozen = FrozenTestSuite.create(gt_tests)
            test_res = loop.execute_solution_tests(m_code, frozen)
            if test_res.passed:
                # The mutant PASSED the model's test suite!
                # If the gate would have accepted this task, this is an accepted mutant!
                res_entry = {
                    "mutant_id": mid,
                    "task_id": tid,
                    "description": m_desc,
                    "gate_status": "ACCEPTED",
                    "reason": "Mutant passed model test suite (FALSE ACCEPT)",
                    "test_status": test_res.status,
                    "failures": [],
                }
                accepted_mutants.append(mid)
            else:
                res_entry = {
                    "mutant_id": mid,
                    "task_id": tid,
                    "description": m_desc,
                    "gate_status": "REJECTED",
                    "reason": "Mutant failed model test suite",
                    "test_status": test_res.status,
                    "failures": [f.get("message", "")[:100] for f in (test_res.failures or [])[:2]],
                }
                rejected_mutants.append(mid)
        except Exception as e:
            res_entry = {
                "mutant_id": mid,
                "task_id": tid,
                "description": m_desc,
                "gate_status": "REJECTED",
                "reason": f"Execution error: {e}",
                "test_status": "ERROR",
            }
            rejected_mutants.append(mid)

        results.append(res_entry)

    summary = {
        "diag_jsonl_path": diag_jsonl_path,
        "total_mutants": len(mutants_list),
        "accepted_mutants_count": len(accepted_mutants),
        "accepted_mutants": accepted_mutants,
        "rejected_mutants_count": len(rejected_mutants),
        "rejected_mutants": rejected_mutants,
        "mutant_kill_rate": round(len(rejected_mutants) / len(mutants_list), 4) if mutants_list else 1.0,
        "results": results,
    }
    return summary


def format_mutant_report(summary: Dict[str, Any]) -> str:
    lines = []
    lines.append("### Gate-Level Mutant Benchmark Report\n")
    lines.append(f"- **Evidence Source**: `{summary['diag_jsonl_path']}`")
    lines.append(f"- **Total Mutants Tested**: {summary['total_mutants']}")
    lines.append(f"- **Accepted Mutants (Must be 0)**: **{summary['accepted_mutants_count']}**")
    lines.append(f"- **Rejected Mutants**: **{summary['rejected_mutants_count']}**")
    lines.append(f"- **Mutant Kill Rate**: **{summary['mutant_kill_rate'] * 100:.1f}%**\n")

    if summary["accepted_mutants_count"] > 0:
        lines.append("#### WARNING: Accepted Mutants Detected:")
        for mid in summary["accepted_mutants"]:
            lines.append(f"- `{mid}`")
        lines.append("")

    lines.append("| Mutant ID | Task ID | Description | Gate Verdict | Reason |")
    lines.append("|---|---|---|:---:|---|")
    for r in summary["results"]:
        verdict = f"**{r['gate_status']}**" if r['gate_status'] == "ACCEPTED" else r['gate_status']
        lines.append(f"| `{r['mutant_id']}` | `{r['task_id']}` | {r['description']} | {verdict} | {r['reason']} |")

    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gate-Level Mutant Runner")
    parser.add_argument("--diag-jsonl", type=str, required=True, help="Path to evaluation diag JSONL with generated tests")
    parser.add_argument("--mutants-set", type=str, choices=["tuning", "holdout", "all"], default="tuning", help="Mutant set to evaluate")
    parser.add_argument("--json", action="store_true", help="Output JSON format")

    args = parser.parse_args()
    if args.mutants_set == "tuning":
        m_list = MUTANTS
    elif args.mutants_set == "holdout":
        m_list = MUTANTS_HOLDOUT
    else:
        m_list = MUTANTS + MUTANTS_HOLDOUT

    summary = run_mutants_against_gate(args.diag_jsonl, mutants_list=m_list)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_mutant_report(summary))
