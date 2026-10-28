"""
Unit tests for ADR-014 Commit 2: Interactive Terminal Shell (REPL).
Verifies terminal detection, slash command dispatching, fail-safe unknown command rejection,
conversational routing to chat, quote/Unicode handling, banner honesty, and signal resilience.
"""

from __future__ import annotations

import io
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
        Asserts /doctor, /analyze, /code, /docs, /forecast, /setup map cleanly
        to canonical CLI arguments without duplicate implementations.
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

        # /chat with unquoted arguments
        act, argv = parse_shell_line("/chat What is the speed of sound?")
        self.assertEqual(act, "canonical")
        self.assertEqual(argv, ["chat", "What is the speed of sound?"])

    # -------------------------------------------------------------------------
    # 3. Fail-Safe Unknown Slash Command Rejection (ADR-014 §1)
    # -------------------------------------------------------------------------
    def test_shell_unknown_slash_command(self) -> None:
        """
        Asserts unrecognized slash commands are rejected locally with clear error
        and are NEVER forwarded to the language model or chat handler.
        """
        outputs: list[str] = []
        inputs = iter(["/unknown_command", "/exit"])

        with patch("pai.main") as mock_pai_main:
            exit_code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
            )
            self.assertEqual(exit_code, 0)
            # pai.main must NOT be called for the unknown slash command
            mock_pai_main.assert_not_called()

        combined = " ".join(outputs)
        self.assertIn("Unknown command '/unknown_command'", combined)
        self.assertIn("Type /help", combined)

    # -------------------------------------------------------------------------
    # 4. Text Routing to Conversational Chat (ADR-014 §1)
    # -------------------------------------------------------------------------
    def test_shell_conversational_routing(self) -> None:
        """
        Asserts non-slash lines are automatically routed to canonical 'pai chat'.
        """
        act, argv = parse_shell_line("Explain the difference between mutex and semaphore.")
        self.assertEqual(act, "chat")
        self.assertEqual(argv, ["chat", "Explain the difference between mutex and semaphore."])

        # Test within REPL loop
        inputs = iter(["Can you write a poem about rust?", "/exit"])
        outputs: list[str] = []

        with patch("shell.execute_subcommand") as mock_exec:
            exit_code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
            )
            self.assertEqual(exit_code, 0)
            mock_exec.assert_called_once_with(["chat", "Can you write a poem about rust?"])

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
    # 7. Unicode and Argument Quoting Ergonomics (ADR-014 §1)
    # -------------------------------------------------------------------------
    def test_shell_unicode_and_spaces_in_arguments(self) -> None:
        """
        Asserts arguments containing spaces and Sinhala Unicode characters are correctly
        preserved and parsed without truncation or encoding corruption.
        """
        # Sinhala Unicode prompt and paths
        sinhala_line = '/analyze "ලේඛනය/නාමය පරීක්ෂණය"'
        act, argv = parse_shell_line(sinhala_line)
        self.assertEqual(act, "canonical")
        self.assertEqual(argv, ["analyze", "ලේඛනය/නාමය පරීක්ෂණය"])

        # Unmatched quote syntax error handled cleanly
        err_act, err_argv = parse_shell_line('/analyze "unclosed quote')
        self.assertEqual(err_act, "error")
        self.assertIn("Error:", err_argv[0])

    # -------------------------------------------------------------------------
    # 8. Honest Startup Banner and Limitations Disclaimer (ADR-014 §1)
    # -------------------------------------------------------------------------
    def test_shell_banner_honesty(self) -> None:
        """
        Asserts the startup banner contains:
          - Product title
          - Inference endpoint (127.0.0.1:11434)
          - Explicit disclaimer that local models rely on static training data and lack live clock/web access.
        """
        banner = get_shell_banner()
        self.assertIn("Personal Agentic AI (PAI) Interactive Shell", banner)
        self.assertIn("127.0.0.1:11434", banner)
        self.assertIn("static training data", banner)
        self.assertIn("lack live clock or web access", banner)


if __name__ == "__main__":
    unittest.main()
