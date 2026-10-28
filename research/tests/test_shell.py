"""
Unit tests for ADR-014 Commit 2: Interactive Terminal Shell (REPL).
Verifies terminal detection, slash command dispatching, fail-safe unknown command rejection,
Windows backslash/UNC/Unicode tokenization (Finding DW), exclusion of maintenance commands (Finding DV),
leading dash handling and stateless banner honesty (Finding DX), and signal resilience.
"""

from __future__ import annotations

import io
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

RESEARCH_DIR = Path(__file__).resolve().parent.parent
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

from shell import (
    SHELL_BANNER,
    SHELL_HELP,
    execute_subcommand,
    get_shell_banner,
    is_interactive_terminal,
    parse_shell_line,
    run_interactive_shell,
    tokenize_windows_line,
)


class TestInteractiveShellADR014(unittest.TestCase):
    # -------------------------------------------------------------------------
    # 1. Terminal Detection Guard (ADR-014 §1)
    # -------------------------------------------------------------------------
    def test_shell_terminal_detection(self) -> None:
        """
        When isatty() is True on stdin/stdout, running pai without args enters shell.
        When isatty() is False (piped/redirected), prints help text and exits 0.
        """
        from pai import main as pai_main

        # Case A: Non-interactive (redirected/piped) -> prints CLI help and exits 0
        with patch("shell.is_interactive_terminal", return_value=False):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                exit_code = pai_main([])
                self.assertEqual(exit_code, 0)
                out = mock_stdout.getvalue()
                self.assertIn("Personal Agentic AI (PAI)", out)
                self.assertIn("subcommands", out.lower())

        # Case B: Interactive terminal -> enters shell
        with patch("shell.is_interactive_terminal", return_value=True):
            with patch("shell.run_interactive_shell", return_value=0) as mock_shell:
                exit_code = pai_main([])
                self.assertEqual(exit_code, 0)
                mock_shell.assert_called_once()

    # -------------------------------------------------------------------------
    # 2. Slash-Command Dispatcher (ADR-014 §1)
    # -------------------------------------------------------------------------
    def test_shell_slash_dispatch(self) -> None:
        """
        Asserts /doctor, /analyze, /code, /docs, /forecast, /setup, /models, /route
        map cleanly to canonical CLI arguments without duplicate implementations.
        """
        # /doctor
        act, argv = parse_shell_line("/doctor")
        self.assertEqual(act, "canonical")
        self.assertEqual(argv, ["doctor"])

        # /analyze with target directory
        act, argv = parse_shell_line('/analyze "src/components"')
        self.assertEqual(act, "canonical")
        self.assertEqual(argv, ["analyze", "src/components"])

        # /code with flags
        act, argv = parse_shell_line('/code "parse csv" --timeout 5.0')
        self.assertEqual(act, "canonical")
        self.assertEqual(argv, ["code", "parse csv", "--timeout", "5.0"])

        # /docs
        act, argv = parse_shell_line('/docs "README.md"')
        self.assertEqual(act, "canonical")
        self.assertEqual(argv, ["docs", "README.md"])

        # /forecast
        act, argv = parse_shell_line('/forecast "sales.csv"')
        self.assertEqual(act, "canonical")
        self.assertEqual(argv, ["forecast", "sales.csv"])

        # /setup
        act, argv = parse_shell_line("/setup")
        self.assertEqual(act, "canonical")
        self.assertEqual(argv, ["setup"])

        # /models
        act, argv = parse_shell_line("/models")
        self.assertEqual(act, "canonical")
        self.assertEqual(argv, ["models"])

        # /route
        act, argv = parse_shell_line('/route "write sorting algorithm"')
        self.assertEqual(act, "canonical")
        self.assertEqual(argv, ["route", "write sorting algorithm"])

        # /chat with unquoted arguments and leading dash protection (Finding DX)
        act, argv = parse_shell_line("/chat What is the speed of sound?")
        self.assertEqual(act, "canonical")
        self.assertEqual(argv, ["chat", "--", "What is the speed of sound?"])

    # -------------------------------------------------------------------------
    # 3. Fail-Safe Unknown Slash Command & Maintenance Command Rejection (Finding DV)
    # -------------------------------------------------------------------------
    def test_shell_unknown_slash_command(self) -> None:
        """
        Asserts unrecognized slash commands (e.g. /unknown_command) AND maintenance commands
        (/clear-shadow, /calibrate per Finding DV) are rejected locally with clear error
        and are NEVER forwarded to the language model or chat handler.
        """
        for rejected_cmd in ("/unknown_command", "/clear-shadow", "/calibrate"):
            outputs: list[str] = []
            inputs = iter([rejected_cmd, "/exit"])

            with patch("pai.main") as mock_pai_main:
                exit_code = run_interactive_shell(
                    input_fn=lambda _: next(inputs),
                    output_fn=outputs.append,
                )
                self.assertEqual(exit_code, 0)
                mock_pai_main.assert_not_called()

            combined = " ".join(outputs)
            self.assertIn(f"Unknown command '{rejected_cmd}'", combined)
            self.assertIn("Type /help", combined)

    # -------------------------------------------------------------------------
    # 4. Text Routing to Conversational Chat (ADR-014 §1, Finding DX)
    # -------------------------------------------------------------------------
    def test_shell_conversational_routing(self) -> None:
        """
        Asserts non-slash lines are automatically routed to canonical 'pai chat'
        with '--' sentinel to safely handle prompts starting with a dash.
        """
        act, argv = parse_shell_line("Explain the difference between mutex and semaphore.")
        self.assertEqual(act, "chat")
        self.assertEqual(argv, ["chat", "--", "Explain the difference between mutex and semaphore."])

        # Test within REPL loop
        inputs = iter(["Can you write a poem about rust?", "/exit"])
        outputs: list[str] = []

        with patch("shell.execute_subcommand") as mock_exec:
            exit_code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
            )
            self.assertEqual(exit_code, 0)
            mock_exec.assert_called_once_with(["chat", "--", "Can you write a poem about rust?"])

    def test_shell_leading_dash_prompt_not_mistaken_for_option(self) -> None:
        """
        Finding DX: Asserts prompts beginning with a dash (e.g. '-5 is negative, why?')
        are passed after '--' so argparse does not interpret them as CLI option flags.
        """
        prompt = "-5 is negative, why?"
        act, argv = parse_shell_line(prompt)
        self.assertEqual(act, "chat")
        self.assertEqual(argv, ["chat", "--", prompt])

        from pai import build_parser
        parser = build_parser()
        args = parser.parse_args(argv)
        self.assertEqual(args.subcommand, "chat")
        self.assertEqual(args.prompt, prompt)

    # -------------------------------------------------------------------------
    # 5. Session Control, Exit, and EOF (ADR-014 §1)
    # -------------------------------------------------------------------------
    def test_shell_exit_and_eof(self) -> None:
        """
        Asserts /exit, /quit, and EOFError cleanly terminate the shell session with code 0.
        """
        for exit_cmd in ("/exit", "/quit"):
            outputs: list[str] = []
            inputs = iter([exit_cmd])
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
            )
            self.assertEqual(code, 0)
            self.assertIn("Goodbye.", outputs)

        # EOFError (Ctrl+D / Ctrl+Z)
        def raise_eof(_):
            raise EOFError()

        outputs = []
        code = run_interactive_shell(
            input_fn=raise_eof,
            output_fn=outputs.append,
        )
        self.assertEqual(code, 0)
        self.assertIn("\nGoodbye.", outputs)

    # -------------------------------------------------------------------------
    # 6. Signal Handling: KeyboardInterrupt Resilience (ADR-014 §1)
    # -------------------------------------------------------------------------
    def test_shell_interrupt_handling(self) -> None:
        """
        Asserts Ctrl+C (KeyboardInterrupt):
          A. At prompt: prompts user how to exit without crashing shell.
          B. During subcommand execution: cancels current generation/task safely.
        """
        # Case A: KeyboardInterrupt at prompt then /exit
        prompt_inputs = iter([KeyboardInterrupt(), "/exit"])
        def mock_input(_):
            val = next(prompt_inputs)
            if isinstance(val, BaseException):
                raise val
            return val

        outputs_a: list[str] = []
        code_a = run_interactive_shell(input_fn=mock_input, output_fn=outputs_a.append)
        self.assertEqual(code_a, 0)
        self.assertIn("\nType /exit to quit.", outputs_a)

        # Case B: KeyboardInterrupt during execution
        exec_inputs = iter(["/doctor", "/exit"])
        outputs_b: list[str] = []

        def failing_exec(argv):
            raise KeyboardInterrupt()

        with patch("shell.execute_subcommand", side_effect=failing_exec):
            code_b = run_interactive_shell(
                input_fn=lambda _: next(exec_inputs),
                output_fn=outputs_b.append,
            )
            self.assertEqual(code_b, 0)
            self.assertIn("\n[Operation cancelled by user]", outputs_b)

    # -------------------------------------------------------------------------
    # 7. Windows Tokenizer: Backslashes, UNC, Spaces, Sinhala (Finding DW)
    # -------------------------------------------------------------------------
    def test_windows_tokenizer_backslashes_unc_and_unicode(self) -> None:
        """
        Finding DW: Asserts that Windows backslashes are never stripped or escaped,
        UNC network paths are preserved, paths with spaces are cleanly tokenized,
        and Sinhala Unicode characters are correctly parsed.
        """
        # 1. Unquoted Windows backslash path
        line1 = r"/analyze C:\Users\hp\my_project"
        act1, argv1 = parse_shell_line(line1)
        self.assertEqual(act1, "canonical")
        self.assertEqual(argv1, ["analyze", r"C:\Users\hp\my_project"])

        # 2. Quoted Windows path with backslashes and spaces
        line2 = r'/analyze "C:\Program Files\My Project\sub dir"'
        act2, argv2 = parse_shell_line(line2)
        self.assertEqual(act2, "canonical")
        self.assertEqual(argv2, ["analyze", r"C:\Program Files\My Project\sub dir"])

        # 3. UNC network path
        line3 = r"/docs \\server\share\team\notes.txt"
        act3, argv3 = parse_shell_line(line3)
        self.assertEqual(act3, "canonical")
        self.assertEqual(argv3, ["docs", r"\\server\share\team\notes.txt"])

        # 4. Sinhala Unicode path with backslashes
        line4 = r'/docs "D:\notes\නාමය.txt"'
        act4, argv4 = parse_shell_line(line4)
        self.assertEqual(act4, "canonical")
        self.assertEqual(argv4, ["docs", r"D:\notes\නාමය.txt"])

        # 5. Sinhala Unicode unquoted name
        line5 = r"/docs D:\ලේඛන\නාමය_පරීක්ෂණ.csv"
        act5, argv5 = parse_shell_line(line5)
        self.assertEqual(act5, "canonical")
        self.assertEqual(argv5, ["docs", r"D:\ලේඛන\නාමය_පරීක්ෂණ.csv"])

        # 6. Syntax error on unclosed quote handled gracefully without crashing
        err_act, err_argv = parse_shell_line('/analyze "unclosed quote')
        self.assertEqual(err_act, "error")
        self.assertIn("Error:", err_argv[0])

    # -------------------------------------------------------------------------
    # 8. Honest Startup Banner and Stateless Mode (Findings DX & DZ)
    # -------------------------------------------------------------------------
    def test_shell_banner_and_stateless_declaration(self) -> None:
        """
        Findings DX: Asserts the startup banner and /help text:
          - State 'no model loaded yet' when router has no resident model.
          - Accurately state inference endpoint (127.0.0.1:11434).
          - Explicitly declare that chat runs in stateless mode without cross-turn memory.
          - Explicitly declare local models rely on static training data without web/clock access.
        """
        # When no model is resident
        with patch("router.ModelRouter.get_live_resident_model", return_value=None):
            banner = get_shell_banner()
            self.assertIn("Personal Agentic AI (PAI) Interactive Shell", banner)
            self.assertIn("127.0.0.1:11434", banner)
            self.assertIn("no model loaded yet", banner)
            self.assertIn("static training data", banner)
            self.assertIn("Stateless", banner)
            self.assertIn("without prior conversation memory", banner)

        # When a model is resident
        with patch("router.ModelRouter.get_live_resident_model", return_value="qwen2.5:0.5b"):
            banner_loaded = get_shell_banner()
            self.assertIn("Model: qwen2.5:0.5b", banner_loaded)

        # /help text asserts stateless note and command list
        self.assertIn("stateless", SHELL_HELP.lower())
        self.assertNotIn("/clear-shadow", SHELL_HELP)
        self.assertNotIn("/calibrate", SHELL_HELP)
        self.assertIn("/setup", SHELL_HELP)


if __name__ == "__main__":
    unittest.main()
