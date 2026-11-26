"""
Unit and Negative-Control Tests for Upgraded Swarm, Model Council & Cowork Engine:
- ModelCouncilRunner with deep deliberation + swapped-order pairwise Judge (council.py)
- MultiAgentTeam domain routing, objective syntax/structural checks, & CRASH/ThoughtGraph (multi_agent.py)
- CoworkOrchestrator + StuckDetectorWatchdog loop/timeout/confidence detection, exact-step
  checkpoint resume, pause/cancel, and objective quality gate (cowork.py)
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

RESEARCH_DIR = Path(__file__).resolve().parents[1]
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

from council import ModelCouncilRunner
from cowork import CoworkOrchestrator, StuckDetectorWatchdog
from multi_agent import MultiAgentTeam
from thought_graph import ThoughtGraph


class TestModelCouncilV2(unittest.TestCase):
    def test_council_deep_deliberate_and_swapped_judge(self) -> None:
        runner = ModelCouncilRunner()
        seen_prompts = []

        def mock_gen(model: str, prompt: str) -> str:
            seen_prompts.append((model, prompt))
            if "qwen" in model:
                return "Use connection pooling and parameterized SQL statements with strict validation.\n```python\ndef safe_q(): pass\n```"
            return "Validate inputs cleanly and use parameterized queries plus timeouts."

        judge_calls = []

        def mock_judge(model: str, j_prompt: str) -> str:
            judge_calls.append(j_prompt)
            # First candidate always slightly ahead regardless of forward vs swapped presentation
            if "Candidate A (forward)" in j_prompt:
                return "SCORE_A=4.8 SCORE_B=4.0"
            return "SCORE_A=4.0 SCORE_B=4.8"

        res = runner.run(
            "How should we harden DB access?",
            models=["qwen3.5:4b", "llama3.2:3b"],
            generator_fn=mock_gen,
            deep_deliberate=True,
            judge_fn=mock_judge,
        )
        self.assertTrue(res.judge_used)
        self.assertEqual(len(judge_calls), 2)  # forward + swapped
        self.assertGreater(res.judge_scores["qwen3.5:4b"], res.judge_scores["llama3.2:3b"])
        self.assertTrue(all("Deep Deliberation Protocol" in p for _, p in seen_prompts))
        self.assertGreaterEqual(len(res.agreements), 2)


class TestMultiAgentTeamV2(unittest.TestCase):
    def test_domain_classification_separates_software_from_games(self) -> None:
        self.assertEqual(MultiAgentTeam._classify_task_domain("Build CCTV drone 3D simulation"), "game_simulation")
        self.assertEqual(MultiAgentTeam._classify_task_domain("Perform STRIDE threat audit on API bridge"), "security_audit")
        self.assertEqual(MultiAgentTeam._classify_task_domain("Research comparison between BFS and DFS ToT"), "research")
        self.assertEqual(MultiAgentTeam._classify_task_domain("Refactor Python CSV exporter module"), "software_engineering")

    def test_objective_verify_negative_control_rejects_broken_python(self) -> None:
        bad_blocks = [("app.py", "def broken_func(:\n    return 1\n")]
        ok, issues = MultiAgentTeam._objective_verify_code_blocks(bad_blocks)
        self.assertFalse(ok)
        self.assertTrue(any("SyntaxError" in msg for msg in issues))

        good_blocks = [("app.py", "def ok_func(x: int) -> int:\n    return x + 1\n")]
        ok2, issues2 = MultiAgentTeam._objective_verify_code_blocks(good_blocks)
        self.assertTrue(ok2)
        self.assertEqual(issues2, [])

    def test_collaborative_workflow_general_software_uses_deep_reasoning_and_no_cctv_bleed(self) -> None:
        prompts_seen = []

        def mock_exec(argv):
            p_text = argv[-1] if argv else ""
            prompts_seen.append(p_text)
            if "Lead QA Engineer" in p_text:
                print("VERDICT: PASS — Clean Python module verified.")
            elif "Principal Software Engineer" in p_text:
                print("### File: calculator.py\n```python\ndef add(a: int, b: int) -> int:\n    return a + b\n\ndef mul(a: int, b: int) -> int:\n    return a * b\n```")
            else:
                print("Structured engineering analysis <verdict>CONFIRMED</verdict><confidence>0.85</confidence>")
            return 0

        with tempfile.TemporaryDirectory() as td:
            p_dir = Path(td)
            team = MultiAgentTeam(executor=mock_exec)
            res = team.run_collaborative_workflow(
                "Create a clean Python arithmetic utility module",
                active_project_dir=p_dir,
                deep_think=True,
                max_quality_rounds=2,
            )
            self.assertEqual(res["domain"], "software_engineering")
            self.assertIn("calculator.py", res["code_updates"])
            self.assertTrue(res["objective_checks"]["passed"])
            self.assertGreaterEqual(res["crash_summary"]["step_count"], 3)
            self.assertTrue(res["zero_incomplete_leaves"])
            # Ensure CCTV/asphalt prompts did NOT bleed into general software engineering task
            joined_prompts = "\n".join(prompts_seen)
            self.assertNotIn("createProceduralAsphaltTexture", joined_prompts)


class TestCoworkStuckDetectorAndResume(unittest.TestCase):
    def test_watchdog_detects_repetition_timeout_and_confidence_collapse(self) -> None:
        # 1. Repetition loop negative control
        wd_loop = StuckDetectorWatchdog(repetition_jaccard_threshold=0.80, max_identical_window=2)
        r1 = wd_loop.record_progress(1, "Try importing config helper from utils module", confidence=0.75, now=100.0)
        self.assertFalse(r1["stalled"])
        r2 = wd_loop.record_progress(1, "Try importing config helper from utils module again", confidence=0.72, now=102.0)
        self.assertTrue(r2["stalled"])
        self.assertEqual(r2["code"], "REPETITION_LOOP")

        # 2. Confidence collapse negative control
        wd_conf = StuckDetectorWatchdog(max_low_conf_streak=2)
        wd_conf.record_progress(1, "Attempt alpha failed verification", confidence=0.30, now=100.0)
        c2 = wd_conf.record_progress(1, "Completely different attempt beta still uncertain", confidence=0.40, now=105.0)
        self.assertTrue(c2["stalled"])
        self.assertEqual(c2["code"], "CONFIDENCE_COLLAPSE")

        # 3. Step timeout heartbeat negative control
        wd_time = StuckDetectorWatchdog(step_timeout_sec=10.0)
        wd_time._last_progress_ts = 100.0
        timed_out, elapsed = wd_time.check_heartbeat(now=125.0)
        self.assertTrue(timed_out)
        self.assertGreater(elapsed, 10.0)

    def test_checkpoint_stall_recovery_and_exact_step_resume(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            orch = CoworkOrchestrator(workspace_path=td)
            orch.storage_dir = Path(td) / "tasks"
            orch.storage_dir.mkdir(parents=True, exist_ok=True)
            orch._tasks.clear()

            task = orch.start_task(
                title="Long Horizon Build",
                goal="Build and test pipeline",
                workspace_dir=td,
                checklist_items=["Analyze", "Implement", "Test"],
                mode="deep",
            )
            orch.update_task_progress(task.task_id, "Step 1 done", completed_step_id=1)
            orch.save_checkpoint(task.task_id, step_index=2, notes="Halted before step 2")

            rec = orch.mark_stalled_and_recover(
                task.task_id,
                reason="Repeated identical output on step 2",
                step_index=2,
                branch_id="recovery_1_s2",
                max_recoveries=2,
            )
            self.assertTrue(rec["recovered"])
            self.assertEqual(rec["resume_step_index"], 2)
            self.assertEqual(orch.get_task(task.task_id).status, "STALLED_RECOVERING")

            # Pause and resume preserves exact step checkpoint
            self.assertTrue(orch.pause_task(task.task_id))
            self.assertEqual(orch.get_task(task.task_id).status, "PAUSED")
            resumed = orch.resume_task(task.task_id)
            self.assertIsNotNone(resumed)
            self.assertEqual(resumed.status, "RUNNING")
            self.assertEqual(resumed.checkpoint["step_index"], 2)
            # Step 1 remains completed while steps 2 & 3 await resume
            self.assertTrue(resumed.checklist[0]["completed"])
            self.assertFalse(resumed.checklist[1]["completed"])

            # Negative control: exceeding max_recoveries fails cleanly
            orch.mark_stalled_and_recover(task.task_id, "Stall 2", step_index=2, branch_id="rec_2", max_recoveries=2)
            rec3 = orch.mark_stalled_and_recover(task.task_id, "Stall 3", step_index=2, branch_id="rec_3", max_recoveries=2)
            self.assertFalse(rec3["recovered"])
            self.assertEqual(rec3["status"], "FAILED")

    def test_negative_control_quality_gate_rejects_broken_deliverable_or_open_leaves(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            orch = CoworkOrchestrator(workspace_path=td)
            orch.storage_dir = Path(td) / "tasks"
            orch.storage_dir.mkdir(parents=True, exist_ok=True)
            orch._tasks.clear()

            task = orch.start_task("Check Quality Gate", "Verify deliverable gate", workspace_dir=td, checklist_items=["Step 1"])
            orch.update_task_progress(task.task_id, "Done", completed_step_id=1)

            bad_py = Path(td) / "broken.py"
            bad_py.write_text("def broken(:\n    pass\n", encoding="utf-8")
            task.deliverables.append({"name": "broken.py", "path": str(bad_py), "type": "python"})

            g = ThoughtGraph(goal="Open leaf test", storage_dir=Path(td))
            g.add_node("Still undecided", verdict="PENDING")
            task.graph_path = str(g.save("bad_graph.json"))
            task.quality_score = 0.85

            ok, issues = orch.verify_task_quality(task.task_id)
            self.assertFalse(ok)
            self.assertTrue(any("Syntax error" in i or "syntax error" in i.lower() for i in issues))
            self.assertTrue(any("Zero-Incomplete-Leaves" in i for i in issues))


if __name__ == "__main__":
    unittest.main()
