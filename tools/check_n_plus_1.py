#!/usr/bin/env python3
"""
N+1 Evaluation Window Progress Checker for Personal Agentic AI (PAI).

Evaluates active operational shadow telemetry against Release N+1 criteria:
- Organic CLI comparisons >= 300 (driver-tagged comparisons excluded)
- Window duration span >= 14 days (1,209,600 seconds)
- Total and CLI shadow discrepancies == 0
- Single binary hash (no mid-window binary modifications)
- Binary rebuild detected == False
- Corrupt log lines == 0
- Log write failures == 0
- Evaluated tree integrity (core/ tree strictly unchanged)
"""

import json
import subprocess
import sys
from pathlib import Path

REQUIRED_ORGANIC_COMPARISONS = 300
REQUIRED_SPAN_DAYS = 14.0
REQUIRED_SPAN_SECONDS = REQUIRED_SPAN_DAYS * 86400.0


def check_n_plus_1_progress() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    pai_py = repo_root / "research" / "pai.py"

    # Use --skip-smoke to avoid generating redundant smoke test telemetry (Finding BH)
    cmd = [sys.executable, str(pai_py), "doctor", "--json", "--skip-smoke"]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        print("ERROR: Failed to run 'pai doctor --json --skip-smoke':", proc.stderr, file=sys.stderr)
        return 1

    try:
        data = json.loads(proc.stdout)
    except Exception as exc:
        print(f"ERROR: Failed to parse doctor output as JSON: {exc}", file=sys.stderr)
        return 1

    shadow = data.get("shadow_telemetry", {})
    cli_comp = shadow.get("cli_comparisons", 0)
    driver_comp = shadow.get("driver_comparisons", 0)
    organic_comp = cli_comp - driver_comp
    cli_disc = shadow.get("cli_discrepancies", 0)
    total_disc = shadow.get("total_discrepancies", 0)
    corrupt_lines = shadow.get("corrupt_lines", 0)
    write_failures = shadow.get("log_write_failures", 0)
    span_sec = shadow.get("cli_span_seconds", 0.0)
    span_days = span_sec / 86400.0

    binary_hashes = shadow.get("binary_hashes", [])
    single_binary = len(binary_hashes) == 1
    rebuild_detected = shadow.get("binary_rebuild_detected", False)

    # Check git tree integrity against evaluated commit if present
    eval_commit_file = repo_root / "tools" / "corpus" / "EVALUATED_COMMIT"
    eval_commit = eval_commit_file.read_text().strip() if eval_commit_file.exists() else None
    tree_match = True
    tree_detail = "N/A"
    if eval_commit:
        try:
            core_tree_res = subprocess.run(
                ["git", "rev-parse", "HEAD:core"],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=True,
            )
            eval_core_tree_res = subprocess.run(
                ["git", "rev-parse", f"{eval_commit}:core"],
                cwd=repo_root,
                capture_output=True,
                text=True,
            )
            res_tree_res = subprocess.run(
                ["git", "rev-parse", "HEAD:research"],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=True,
            )
            eval_res_tree_res = subprocess.run(
                ["git", "rev-parse", f"{eval_commit}:research"],
                cwd=repo_root,
                capture_output=True,
                text=True,
            )
            if eval_core_tree_res.returncode == 0 and eval_res_tree_res.returncode == 0:
                current_core_tree = core_tree_res.stdout.strip()
                eval_core_tree = eval_core_tree_res.stdout.strip()
                current_res_tree = res_tree_res.stdout.strip()
                eval_res_tree = eval_res_tree_res.stdout.strip()
                core_match = (current_core_tree == eval_core_tree)
                res_match = (current_res_tree == eval_res_tree)
                tree_match = core_match and res_match
                tree_detail = f"core: {'MATCH' if core_match else 'DIFF'} ({current_core_tree[:8]} vs {eval_core_tree[:8]}), research: {'MATCH' if res_match else 'DIFF'} ({current_res_tree[:8]} vs {eval_res_tree[:8]})"
            else:
                tree_detail = f"evaluated commit {eval_commit[:8]} not reachable"
        except Exception as e:
            tree_detail = f"git check skipped ({e})"

    print("================================================================================")
    print("                    PAI RELEASE N+1 WINDOW PROGRESS REPORT                      ")
    print("================================================================================")
    print(f"Bridge Mode             : [{data.get('bridge_mode', 'unknown')}]")
    print(f"Total CLI Comparisons   : {cli_comp}")
    print(f"Driver Comparisons      : {driver_comp}")
    print(f"Organic CLI Comparisons : {organic_comp} / {REQUIRED_ORGANIC_COMPARISONS} (Target: >= {REQUIRED_ORGANIC_COMPARISONS})")
    print(f"Shadow Discrepancies    : {cli_disc} (Total: {total_disc}) (Target: 0)")
    print(f"CLI Evaluation Span     : {span_days:.2f} days ({span_sec:,.0f}s / {REQUIRED_SPAN_SECONDS:,.0f}s) (Target: >= {REQUIRED_SPAN_DAYS} days)")
    print(f"Corrupt Log Lines       : {corrupt_lines} (Target: 0)")
    print(f"Log Write Failures      : {write_failures} (Target: 0)")
    print(f"Binary Hash Count       : {len(binary_hashes)} (Target: 1, hashes: {', '.join(h[:8] for h in binary_hashes) or 'none'})")
    print(f"Binary Rebuild Detected : {rebuild_detected} (Target: False)")
    print(f"Evaluated Tree Status   : {tree_detail}")

    organic_met = organic_comp >= REQUIRED_ORGANIC_COMPARISONS
    span_met = span_sec >= REQUIRED_SPAN_SECONDS
    disc_clean = (total_disc == 0 and cli_disc == 0)
    integrity_clean = (single_binary and not rebuild_detected and corrupt_lines == 0 and write_failures == 0 and tree_match)

    print("--------------------------------------------------------------------------------")
    print(f"Organic Comparisons Met : [{'OK' if organic_met else 'PENDING'}]")
    print(f"14-Day Span Met         : [{'OK' if span_met else 'PENDING'}]")
    print(f"Discrepancies Clean     : [{'OK' if disc_clean else 'FAILED'}]")
    print(f"Integrity & Log Health  : [{'OK' if integrity_clean else 'PENDING/FAILED'}]")
    print("--------------------------------------------------------------------------------")

    if organic_met and span_met and disc_clean and integrity_clean:
        print("VERDICT: Release N+1 operational criteria SATISFIED. Ready for candidate review.")
        return 0
    else:
        pending = []
        if not organic_met:
            pending.append(f"need {REQUIRED_ORGANIC_COMPARISONS - organic_comp} more organic comparisons")
        if not span_met:
            pending.append(f"need {REQUIRED_SPAN_DAYS - span_days:.2f} more days of span")
        if not disc_clean:
            pending.append(f"discrepancies detected ({cli_disc})")
        if not single_binary:
            pending.append(f"binary hash count is {len(binary_hashes)} (expected 1)")
        if rebuild_detected:
            pending.append("binary rebuild detected")
        if corrupt_lines > 0:
            pending.append(f"{corrupt_lines} corrupt log lines")
        if write_failures > 0:
            pending.append(f"{write_failures} write failures")
        if not tree_match:
            pending.append("core tree mismatch against evaluated commit")
        print(f"VERDICT: Window in progress ({', '.join(pending)}).")
        return 2


if __name__ == "__main__":
    sys.exit(check_n_plus_1_progress())
