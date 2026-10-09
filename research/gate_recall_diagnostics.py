"""
Gate Recall Step 0 Diagnostic & Cross-Check Analyzer
Analyzes gate recall drop between gate-off baselines and gated pai code pipeline.

Cross-checks model-written test suites against correct gate-off solutions:
1. If gate-off solution fails model tests -> Test-Wrongness (model wrote invalid/hallucinated tests).
2. If gate-off solution passes model tests -> Stub probe too strict, AST guard false positive, or repair loop drifted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from verify_loop import FrozenTestSuite, VerifyLoop


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def analyze_cross_check(
    gate_off_path: str,
    gated_path: str,
    arm_name: str,
    timeout_sec: float = 10.0,
    memory_mb: float = 512.0,
) -> Dict[str, Any]:
    gate_off_recs = load_jsonl(gate_off_path)
    gated_recs = load_jsonl(gated_path)

    # Map by task_id (using first repeat / repeat 1)
    gate_off_by_task = {r["task_id"]: r for r in gate_off_recs if r["repeat_idx"] == 1}
    gated_by_task = {r["task_id"]: r for r in gated_recs if r["repeat_idx"] == 1}

    loop = VerifyLoop(timeout_sec=timeout_sec, memory_mb=memory_mb)

    total_tasks = len(gate_off_by_task)
    raw_solvable = []
    gated_accepted = []

    diagnostic_rows = []

    test_wrongness_count = 0
    verifier_codec_h5_count = 0
    stub_probe_overstrict_count = 0
    ast_guard_fp_count = 0
    repair_drift_count = 0
    no_tests_count = 0

    for task_id in sorted(gate_off_by_task.keys()):
        go_rec = gate_off_by_task[task_id]
        gt_rec = gated_by_task.get(task_id, {})

        task_name = go_rec.get("task_name", task_id)
        go_passed = bool(go_rec.get("hidden_test_result", {}).get("passed", False))
        gt_passed = bool(gt_rec.get("pai_verdict") == "PASS")

        if go_passed:
            raw_solvable.append(task_id)
        if gt_passed:
            gated_accepted.append(task_id)

        go_sol = go_rec.get("candidate_solution")
        gt_tests = gt_rec.get("generated_test_code")
        gt_stage = gt_rec.get("termination_stage", "unknown")
        gt_err_type = gt_rec.get("error_type")
        failing_stub = gt_rec.get("failing_stub")

        row = {
            "task_id": task_id,
            "task_name": task_name,
            "raw_solvable": go_passed,
            "gated_accepted": gt_passed,
            "termination_stage": gt_stage,
            "error_type": gt_err_type,
            "failing_stub": failing_stub,
            "cross_check_status": None,
            "cross_check_detail": None,
            "root_cause_category": None,
        }

        # If not raw solvable, skip cross-check
        if not go_passed:
            row["root_cause_category"] = "MODEL_RAW_CAPABILITY_LIMIT"
            diagnostic_rows.append(row)
            continue

        # If gated already accepted it
        if gt_passed:
            row["cross_check_status"] = "ACCEPTED"
            row["root_cause_category"] = "ACCEPTED_PASS"
            diagnostic_rows.append(row)
            continue

        # Gated rejected a raw-solvable task! Cross-check model tests against gate-off solution
        if not gt_tests:
            row["cross_check_status"] = "NO_TESTS_GENERATED"
            row["root_cause_category"] = "TEST_GENERATION_FAILED"
            no_tests_count += 1
            diagnostic_rows.append(row)
            continue

        if not go_sol:
            row["cross_check_status"] = "NO_GATE_OFF_SOLUTION"
            row["root_cause_category"] = "DATA_ANOMALY"
            diagnostic_rows.append(row)
            continue

        # Run model tests against correct gate-off solution inside sandbox
        try:
            frozen = FrozenTestSuite.create(gt_tests)
            test_res = loop.execute_solution_tests(go_sol, frozen)
            if test_res.passed:
                row["cross_check_status"] = "PASSED_TESTS"
                # Correct solution passed the model tests! Why was it rejected?
                if gt_stage == "pre_solution_stub_probe":
                    row["root_cause_category"] = "STUB_PROBE_OVERSTRICT"
                    stub_probe_overstrict_count += 1
                elif gt_stage == "pre_solution_ast_violation":
                    row["root_cause_category"] = "AST_GUARD_FALSE_POSITIVE"
                    ast_guard_fp_count += 1
                elif gt_stage == "repair_exhausted":
                    row["root_cause_category"] = "REPAIR_LOOP_FAILURE"
                    repair_drift_count += 1
                else:
                    row["root_cause_category"] = f"GATE_REJECTION_OTHER_{gt_stage}"
            else:
                failure_msgs = " ".join(f.get("message", "") for f in (test_res.failures or []))
                detail_str = test_res.detail or test_res.stderr or ""
                all_text = detail_str + " " + failure_msgs
                row["cross_check_status"] = "FAILED_TESTS"
                row["cross_check_detail"] = (failure_msgs or detail_str)[:150]
                if "EqualityHijackError" in all_text:
                    row["root_cause_category"] = "VERIFIER_CODEC_LIMITATION_H5"
                    verifier_codec_h5_count += 1
                else:
                    row["root_cause_category"] = "TEST_WRONGNESS"
                    test_wrongness_count += 1
        except Exception as e:
            row["cross_check_status"] = "CROSS_CHECK_ERROR"
            row["cross_check_detail"] = str(e)
            if "EqualityHijackError" in str(e):
                row["root_cause_category"] = "VERIFIER_CODEC_LIMITATION_H5"
                verifier_codec_h5_count += 1
            else:
                row["root_cause_category"] = "TEST_WRONGNESS"
                test_wrongness_count += 1

        diagnostic_rows.append(row)

    rejected_raw_solvable = [t for t in raw_solvable if t not in gated_accepted]

    summary = {
        "arm": arm_name,
        "total_tasks": total_tasks,
        "raw_solvable_count": len(raw_solvable),
        "raw_solvable_tasks": raw_solvable,
        "gated_accepted_count": len(gated_accepted),
        "gated_accepted_tasks": gated_accepted,
        "rejected_raw_solvable_count": len(rejected_raw_solvable),
        "rejected_raw_solvable_tasks": rejected_raw_solvable,
        "breakdown_among_rejected": {
            "test_wrongness": test_wrongness_count,
            "verifier_codec_limitation_h5": verifier_codec_h5_count,
            "stub_probe_overstrict_h3": stub_probe_overstrict_count,
            "ast_guard_false_positive": ast_guard_fp_count,
            "repair_loop_failure": repair_drift_count,
            "no_tests_generated": no_tests_count,
        },
        "rows": diagnostic_rows,
    }
    return summary


def format_markdown_table(summary: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"### Gate Recall Step 0 Diagnostic: {summary['arm'].upper()} Arm\n")
    lines.append(f"- **Raw Solvable (Gate-Off)**: {summary['raw_solvable_count']} / {summary['total_tasks']} tasks")
    lines.append(f"- **Gated Accepted (`pai code`)**: {summary['gated_accepted_count']} / {summary['total_tasks']} tasks")
    lines.append(f"- **Gate Recall Drop**: {summary['rejected_raw_solvable_count']} tasks dropped\n")

    b = summary["breakdown_among_rejected"]
    lines.append("#### Root Cause Breakdown (Dropped Raw-Solvable Tasks):")
    lines.append(f"- **Test-Wrongness** (Model wrote invalid/impossible tests): **{b['test_wrongness']}**")
    lines.append(f"- **Verifier Codec Limitation (H5)** (EqualityHijackError on tuple/set/bytes): **{b['verifier_codec_limitation_h5']}**")
    lines.append(f"- **Stub Probe Overstrict (H3)** (Valid tests rejected by stub probe): **{b['stub_probe_overstrict_h3']}**")
    lines.append(f"- **Repair Loop Failure** (Valid tests, but candidate drifted/exhausted): **{b['repair_loop_failure']}**")
    lines.append(f"- **AST Guard False Positive**: **{b['ast_guard_false_positive']}**")
    lines.append(f"- **No Tests Generated** (Model timeout): **{b['no_tests_generated']}**\n")

    lines.append("| Task ID | Task Name | Raw Solvable? | Gated Accepted? | Stage | Failing Stub | Cross-Check Status | Root Cause Category |")
    lines.append("|---|---|:---:|:---:|---|---|---|---|")
    for r in summary["rows"]:
        raw_s = "Yes" if r["raw_solvable"] else "No"
        g_acc = "Yes" if r["gated_accepted"] else "No"
        stub = r["failing_stub"] or "-"
        stage = r["termination_stage"] or "-"
        cc = r["cross_check_status"] or "-"
        cat = r["root_cause_category"] or "-"
        lines.append(f"| `{r['task_id']}` | {r['task_name']} | {raw_s} | {g_acc} | `{stage}` | `{stub}` | {cc} | **{cat}** |")

    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gate Recall Diagnostics")
    parser.add_argument("--gate-off", type=str, required=True, help="Path to gate-off JSONL")
    parser.add_argument("--gated", type=str, required=True, help="Path to gated JSONL")
    parser.add_argument("--arm", type=str, default="english", help="Arm name")
    parser.add_argument("--json", action="store_true", help="Output summary in JSON format")

    args = parser.parse_args()
    summary = analyze_cross_check(args.gate_off, args.gated, args.arm)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_markdown_table(summary))
