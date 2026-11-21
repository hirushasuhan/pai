"""
Unit tests for PAI Autonomous AI Engineering Team v2.
Verifies:
- 7-Role dynamic roster & FIPA-ACL messaging
- Claude Code 'Explore' read-only subagent with file:line citations
- Claude Code 'Plan' architect subagent with critical files extraction
- Cursor Cloud Agent 'subagent-debug' 5-stage runtime hypothesis testing & auto-cleanup
- End-to-end collaborative workflow with self-healing repair
"""

import os
import tempfile
import unittest
from pathlib import Path
from typing import List

try:
    from research.multi_agent import MultiAgentTeam, TeamRoleModelRegistry
except ImportError:
    from multi_agent import MultiAgentTeam, TeamRoleModelRegistry


class TestTeamV2Roster(unittest.TestCase):
    """Verifies registry configuration, aliases, and ASCII fallback for Team v2."""

    def test_all_seven_roles_registered(self):
        reg = TeamRoleModelRegistry()
        expected_roles = [
            "project_manager",
            "explorer",
            "planner",
            "senior_developer",
            "specialist_developer",
            "qa_engineer",
            "debugger",
        ]
        for role in expected_roles:
            self.assertIn(role, reg.ROLE_PREFERENCES, f"Role '{role}' missing from ROLE_PREFERENCES")
            self.assertIn(role, reg.ROLE_TITLES, f"Role '{role}' missing from ROLE_TITLES")
            self.assertIn(role, reg.ROLE_ICONS, f"Role '{role}' missing from ROLE_ICONS")
            self.assertIn(role, reg.role_models, f"Role '{role}' missing from initialized role_models")

    def test_role_aliases_resolution(self):
        reg = TeamRoleModelRegistry()
        self.assertEqual(reg.ROLE_ALIASES.get("scout"), "explorer")
        self.assertEqual(reg.ROLE_ALIASES.get("grep"), "explorer")
        self.assertEqual(reg.ROLE_ALIASES.get("search"), "explorer")
        self.assertEqual(reg.ROLE_ALIASES.get("architect"), "planner")
        self.assertEqual(reg.ROLE_ALIASES.get("planner"), "planner")
        self.assertEqual(reg.ROLE_ALIASES.get("debugger"), "debugger")
        self.assertEqual(reg.ROLE_ALIASES.get("debug"), "debugger")

    def test_set_role_model_for_v2_roles(self):
        reg = TeamRoleModelRegistry()
        ok, msg = reg.set_role_model("scout", "qwen2.5-coder:1.5b", persist=False)
        self.assertTrue(ok)
        self.assertEqual(reg.role_models["explorer"], "qwen2.5-coder:1.5b")

        ok, msg = reg.set_role_model("debug", "qwen2.5-coder:7b", persist=False)
        self.assertTrue(ok)
        self.assertEqual(reg.role_models["debugger"], "qwen2.5-coder:7b")

    def test_ascii_fallback_sanitization(self):
        sanitized = MultiAgentTeam._safe_text("Role: 🔍 Explorer, 📐 Planner, 🐛 Debugger", encoding="ascii")
        self.assertIn("[EXPLORE]", sanitized)
        self.assertIn("[PLAN]", sanitized)
        self.assertIn("[DEBUG]", sanitized)


class TestExplorerSubagent(unittest.TestCase):
    """Verifies Claude Code 'Explore' read-only subagent behavior."""

    def test_read_only_exploration_with_citations(self):
        with tempfile.TemporaryDirectory() as td:
            p_dir = Path(td)
            # Create sample files
            (p_dir / "engine.py").write_text(
                "class PhysicsEngine:\n"
                "    def __init__(self):\n"
                "        self.gravity = 9.81\n"
                "    def apply_impulse(self, force):\n"
                "        return force * self.gravity\n",
                encoding="utf-8",
            )
            (p_dir / "app.js").write_text(
                "function renderFLIRCCTV() {\n"
                "    const canvas = document.getElementById('flir');\n"
                "    return canvas.getContext('2d');\n"
                "}\n",
                encoding="utf-8",
            )

            # Record files before exploration
            before_files = sorted([f.name for f in p_dir.iterdir()])

            def mock_explorer_exec(argv: List[str]) -> int:
                print("Codebase Map:\n- engine.py: PhysicsEngine applies gravitational impulse\n- app.js: renderFLIRCCTV initializes canvas")
                return 0

            team = MultiAgentTeam(executor=mock_explorer_exec)
            res = team.run_code_exploration(query="gravity FLIRCCTV", project_dir=p_dir)

            self.assertTrue(res.get("read_only_verified"))
            citations = res.get("citations", [])
            self.assertTrue(any("engine.py" in c and "gravity" in c for c in citations))
            self.assertTrue(any("app.js" in c and "renderFLIRCCTV" in c for c in citations))

            # Strictly verify NO files were modified or created in p_dir
            after_files = sorted([f.name for f in p_dir.iterdir()])
            self.assertEqual(before_files, after_files, "Explorer subagent must strictly remain read-only!")


class TestPlannerSubagent(unittest.TestCase):
    """Verifies Claude Code 'Plan' architect subagent behavior."""

    def test_implementation_planning_extracts_critical_files(self):
        with tempfile.TemporaryDirectory() as td:
            p_dir = Path(td)
            (p_dir / "index.html").write_text("<div>App</div>", encoding="utf-8")
            (p_dir / "script.js").write_text("console.log('init');", encoding="utf-8")

            def mock_planner_exec(argv: List[str]) -> int:
                print(
                    "Architectural Milestones:\n"
                    "1. Define game loop\n"
                    "2. Bind tactical audio\n\n"
                    "### Critical Files for Implementation:\n"
                    "- script.js\n"
                    "- index.html\n"
                    "- style.css\n"
                )
                return 0

            team = MultiAgentTeam(executor=mock_planner_exec)
            res = team.run_implementation_planning("Create Tactical Drone Sim", project_dir=p_dir)

            crit_files = res.get("critical_files", [])
            self.assertIn("script.js", crit_files)
            self.assertIn("index.html", crit_files)
            self.assertIn("style.css", crit_files)
            self.assertIn("Architectural Milestones", res.get("plan", ""))


class TestRuntimeDebuggerSubagent(unittest.TestCase):
    """Verifies Cursor 'subagent-debug' 5-stage runtime hypothesis testing & auto-cleanup."""

    def test_debug_workflow_formulates_hypotheses_and_cleans_instrumentation(self):
        with tempfile.TemporaryDirectory() as td:
            p_dir = Path(td)
            (p_dir / "game.js").write_text("function shoot() { return null.fire(); }", encoding="utf-8")

            def mock_debug_exec(argv: List[str]) -> int:
                print(
                    "Hypothesis Analysis:\n"
                    "H1: Null pointer exception when weapon instance is uninitialized\n"
                    "H2: Keybinding event listener registered before DOM loaded\n"
                    "H3: Audio buffer underrun blocking requestAnimationFrame\n\n"
                    "Verified Patch:\n"
                    "### File: game.js\n"
                    "```javascript\n"
                    "// #region agent log\n"
                    "console.log('instrumentation');\n"
                    "// #endregion\n"
                    "function shoot() {\n"
                    "    if (!weapon) return false;\n"
                    "    return weapon.fire();\n"
                    "}\n"
                    "```\n"
                )
                return 0

            team = MultiAgentTeam(executor=mock_debug_exec)
            res = team.run_debug_workflow("TypeError: Cannot read properties of null (reading 'fire')", project_dir=p_dir)

            hypotheses = res.get("hypotheses", [])
            self.assertGreaterEqual(len(hypotheses), 3)
            self.assertEqual(hypotheses[0]["id"], "H1")
            self.assertEqual(hypotheses[0]["status"], "CONFIRMED")
            self.assertEqual(hypotheses[1]["status"], "REJECTED")

            # Verify auto-cleanup of '#region agent log' instrumentation
            cleaned_fix = res.get("fix", "")
            self.assertNotIn("#region agent log", cleaned_fix)
            self.assertNotIn("#endregion", cleaned_fix)
            self.assertTrue(res.get("clean_up_performed"))

            # Verify patched game.js on disk
            patched_code = (p_dir / "game.js").read_text(encoding="utf-8")
            self.assertIn("if (!weapon) return false;", patched_code)
            self.assertNotIn("#region agent log", patched_code)


class TestCollaborativeWorkflowV2(unittest.TestCase):
    """Verifies integrated end-to-end SDLC sprint with explorer, planner, and self-healing debugger."""

    def test_collaborative_workflow_with_self_healing(self):
        with tempfile.TemporaryDirectory() as td:
            p_dir = Path(td)
            (p_dir / "script.js").write_text("// baseline script", encoding="utf-8")

            def mock_sdlc_exec(argv: List[str]) -> int:
                prompt_text = " ".join(argv)
                if "qa_engineer" in prompt_text.lower():
                    # QA flags issue requiring revision
                    print("VERDICT: REVISE - Missing collision detection boundary checks.")
                    return 0
                elif "debugger" in prompt_text.lower():
                    # Debugger repairs the issue
                    print(
                        "H1: Collision bounds not clamped to world geometry\n"
                        "### File: script.js\n"
                        "```javascript\n"
                        "// CCTV FLIR Simulation with bounds check\n"
                        "function update() { clampBounds(); }\n"
                        "```\n"
                    )
                    return 0
                elif "planner" in prompt_text.lower():
                    print("### Critical Files for Implementation:\n- script.js")
                    return 0
                else:
                    # PM / Specialist / Senior Dev
                    print(
                        "### File: script.js\n"
                        "```javascript\n"
                        "// CCTV FLIR Simulation Candidate\n"
                        "function update() { step(); }\n"
                        "```\n"
                    )
                    return 0

            team = MultiAgentTeam(executor=mock_sdlc_exec)
            res = team.run_collaborative_workflow("Build CCTV FLIR Simulation", active_project_dir=p_dir)

            self.assertIn("script.js", res.get("code_updates", {}))
            self.assertTrue(res.get("debug_report"), "Auto-debug report must be generated on QA REVISE")
            self.assertIn("H1", [h["id"] for h in res["debug_report"].get("hypotheses", [])])
            self.assertTrue((p_dir / "script.js.bak").is_file())


if __name__ == "__main__":
    unittest.main()
