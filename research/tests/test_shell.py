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
    DEVELOPER_CREDIT,
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

        # 6. Finding EC: Unquoted path with apostrophe/single quote
        line6 = r"/docs C:\Users\O'Brien\notes.txt"
        act6, argv6 = parse_shell_line(line6)
        self.assertEqual(act6, "canonical")
        self.assertEqual(argv6, ["docs", r"C:\Users\O'Brien\notes.txt"])

        # 7. Finding EC: /code prompt containing single quotes inside double quotes
        line7 = '/code "def get_greeting(): return \'hello world\'"'
        act7, argv7 = parse_shell_line(line7)
        self.assertEqual(act7, "canonical")
        self.assertEqual(argv7, ["code", "def get_greeting(): return 'hello world'"])

        # 8. Syntax error on unclosed double quote handled gracefully without crashing
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
            self.assertIn("PAI gives the model your computer's date and time", banner)
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

    # -------------------------------------------------------------------------
    # 9. Shell Polish: Large ASCII Logo, Developer Credit, and Color Invariants
    # -------------------------------------------------------------------------
    def test_shell_banner_logo_and_developer_credit(self) -> None:
        """
        Asserts the interactive shell startup banner:
          - Contains the large block-letter ASCII logo (max 8 lines, fits 80 cols).
          - Contains the developer credit imported from DEVELOPER_CREDIT constant (Finding EW).
          - Preserves existing model, endpoint, offline notice, and stateless declarations (Finding EU).
        """
        banner = get_shell_banner(color_enabled=False)
        self.assertIn("Personal Agentic AI (PAI) Interactive Shell", banner)
        self.assertIn(DEVELOPER_CREDIT, banner)
        self.assertIn("____   _    ___", banner)
        self.assertIn("|_| /_/   \\_\\___|", banner)
        self.assertIn("Model:", banner)
        self.assertIn("Endpoint: http://127.0.0.1:11434", banner)
        self.assertIn("Note: PAI gives the model your computer's date and time. It has no web access and its knowledge ends at a training cut-off.", banner)
        self.assertIn("Stateless", banner)

    def test_terminal_colors_detection_and_no_escape_bytes_when_piped(self) -> None:
        """
        Asserts ANSI colors policy (Finding EY):
          - No escape bytes when piped / not a TTY.
          - NO_COLOR environment variable disables colors.
          - TERM='dumb' disables colors.
          - Colors enabled when simulated TTY is active: styled prompt and yellow notice.
        """
        from shell import should_enable_color, colorize, BRIGHT_CYAN, RED, YELLOW

        # Case A: Not a TTY -> no colors, no escape bytes
        mock_non_tty = MagicMock()
        mock_non_tty.isatty.return_value = False
        self.assertFalse(should_enable_color(mock_non_tty))
        plain_banner = get_shell_banner(color_enabled=False)
        self.assertNotIn("\033[", plain_banner)
        plain_prompt = colorize("pai> ", BRIGHT_CYAN, False)
        self.assertEqual(plain_prompt, "pai> ")

        # Case B: NO_COLOR disables color even if isatty is True
        mock_tty = MagicMock()
        mock_tty.isatty.return_value = True
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(should_enable_color(mock_tty))

        # Case C: TERM=dumb disables color
        with patch.dict(os.environ, {"TERM": "dumb"}):
            self.assertFalse(should_enable_color(mock_tty))

        # Case D: Simulated TTY with color support enabled (Finding EY)
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NO_COLOR", None)
            os.environ.pop("TERM", None)
            with patch("shell.enable_windows_vt", return_value=True):
                self.assertTrue(should_enable_color(mock_tty))
                colored_text = colorize("PAI", BRIGHT_CYAN, True)
                self.assertIn("\033[96mPAI\033[0m", colored_text)
                colored_prompt = colorize("pai> ", BRIGHT_CYAN, True)
                self.assertIn("\033[96mpai> \033[0m", colored_prompt)
                colored_notice = colorize("Notice: time-sensitive", YELLOW, True)
                self.assertIn("\033[33mNotice: time-sensitive\033[0m", colored_notice)

    # -------------------------------------------------------------------------
    # 10. Finding ET: Shell Startup Sandbox Boundary Verification
    # -------------------------------------------------------------------------
    def test_finding_et_shell_startup_sandbox_enforcement(self) -> None:
        """
        Finding ET: Asserts enforce_sandbox_boundary() is called at shell startup:
          - If the check passes, 'Sandbox execution boundary verified fail-closed.' is printed once.
          - If the check fails (SystemExit 5), shell does not start and the message is NOT printed.
        """
        # Case A: Probe passes -> verification message printed exactly once
        outputs: list[str] = []
        inputs = iter(["/exit"])
        with patch("pai.enforce_sandbox_boundary") as mock_enforce:
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
            )
            self.assertEqual(code, 0)
            mock_enforce.assert_called_once()
        self.assertIn("Sandbox execution boundary verified fail-closed.", outputs)
        self.assertEqual(outputs.count("Sandbox execution boundary verified fail-closed."), 1)

        # Case B: Probe fails closed -> raises SystemExit(5), verification line is NOT printed
        outputs_fail: list[str] = []
        def fail_closed():
            raise SystemExit(5)

        with patch("pai.enforce_sandbox_boundary", side_effect=fail_closed):
            with self.assertRaises(SystemExit) as ctx:
                run_interactive_shell(
                    input_fn=lambda _: "/exit",
                    output_fn=outputs_fail.append,
                )
            self.assertEqual(ctx.exception.code, 5)
        self.assertNotIn("Sandbox execution boundary verified fail-closed.", outputs_fail)

    # -------------------------------------------------------------------------
    # 10. Finding ES (Layer 1): /time Command Answers from System Clock
    # -------------------------------------------------------------------------
    def test_shell_time_command_answers_from_clock_without_model(self) -> None:
        """
        Finding ES Layer 1: Asserts /time answers directly from the host system clock
        without invoking the reasoning model or Ollama daemon.
        """
        import datetime
        fake_time = datetime.datetime(2026, 10, 28, 23, 45, 12, tzinfo=datetime.timezone.utc)
        outputs: list[str] = []
        inputs = iter(["/time", "/exit"])

        with patch("datetime.datetime") as mock_dt, \
             patch("pai.main") as mock_pai_main:
            mock_dt.now.return_value.astimezone.return_value = fake_time
            mock_dt.side_effect = lambda *args, **kw: datetime.datetime(*args, **kw)

            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
            )
            self.assertEqual(code, 0)
            mock_pai_main.assert_not_called()

        combined = " ".join(outputs)
        self.assertIn("Current local time:", combined)
        self.assertIn("2026-10-28", combined)
        self.assertIn("23:45:12", combined)

    # -------------------------------------------------------------------------
    # 11. Finding ES (Layers 1 & 2): Chat Prompt Clock and Offline Boundaries
    # -------------------------------------------------------------------------
    def test_chat_prompt_contains_system_clock_and_offline_boundaries(self) -> None:
        """
        Finding ES Layers 1 & 2: Asserts the prompt sent to the model in cmd_chat:
          - Contains the current local date, time, and timezone from the system clock.
          - Explicitly instructs that the assistant is offline without internet access.
          - Explains that knowledge ends at training cut-off.
          - Explains that for live facts (office holders, news, weather, prices),
            it must state it cannot verify and may be outdated.
        """
        import argparse
        import datetime
        from pai import cmd_chat

        fake_now = datetime.datetime(2026, 10, 28, 14, 30, 0, tzinfo=datetime.timezone.utc)
        captured_prompt: list[str] = []

        def mock_call_generate(model_name, prompt, **kwargs):
            captured_prompt.append(prompt)
            return "Mock model response"

        args = argparse.Namespace(
            prompt="Hello there",
            model="qwen2.5:0.5b",
            json=True,
            gemma4_opt_in=False,
            model_timeout=None,
            temperature=0.0,
            seed=42,
        )

        with patch("datetime.datetime") as mock_dt, \
             patch("pai.call_model_generate", side_effect=mock_call_generate):
            mock_dt.now.return_value.astimezone.return_value = fake_now
            mock_dt.side_effect = lambda *args, **kw: datetime.datetime(*args, **kw)

            with patch("sys.stdout", new_callable=io.StringIO):
                rc = cmd_chat(args)
                self.assertEqual(rc, 0)

        self.assertTrue(len(captured_prompt) == 1)
        prompt_str = captured_prompt[0]
        self.assertIn("2026-10-28", prompt_str)
        self.assertIn("14:30:00", prompt_str)
        self.assertIn("Fully offline local execution without internet access", prompt_str)
        self.assertIn("training cut-off", prompt_str)
        self.assertIn("cannot verify live facts, and that your knowledge may be outdated", prompt_str)

    # -------------------------------------------------------------------------
    # 12. Finding ES (Layer 3): Deterministic Time-Sensitive Heuristic & Notice
    # -------------------------------------------------------------------------
    def test_time_sensitive_heuristic_and_deterministic_notice(self) -> None:
        """
        Finding ES Layer 3 & Finding EV: Asserts the regex word-boundary heuristic
        detects time-sensitive prompts in English, Singlish, and Sinhala without
        falling prey to substring false positives (quicksort, author, underscore, scoreboard).
        Appends the deterministic notice:
        'PAI is offline. This answer comes from the model's training data and may be outdated. It was not checked against the internet.'
        """
        import argparse
        from pai import cmd_chat, is_time_sensitive_prompt, TIME_SENSITIVE_NOTICE

        # Finding EV: Positive controls across domains and languages
        self.assertTrue(is_time_sensitive_prompt("what is the price of bitcoin"))
        self.assertTrue(is_time_sensitive_prompt("who won the world cup"))
        self.assertTrue(is_time_sensitive_prompt("is it raining now"))
        self.assertTrue(is_time_sensitive_prompt("who is the president in us"))
        self.assertTrue(is_time_sensitive_prompt("latest python version"))
        self.assertTrue(is_time_sensitive_prompt("dan president kawda?"))
        self.assertTrue(is_time_sensitive_prompt("iphone eke aluthma model eka monawada"))
        self.assertTrue(is_time_sensitive_prompt("වත්මන් ජනාධිපති කවුද?"))

        # Finding EV: Negative controls (eliminated substring false alarms)
        self.assertFalse(is_time_sensitive_prompt("what time complexity does quicksort have"))
        self.assertFalse(is_time_sensitive_prompt("who is the author of this function"))
        self.assertFalse(is_time_sensitive_prompt("rename my_underscore variable"))
        self.assertFalse(is_time_sensitive_prompt("explain the scoreboard class"))
        self.assertFalse(is_time_sensitive_prompt("write a python function to compute fibonacci"))
        self.assertFalse(is_time_sensitive_prompt("explain binary search trees"))

        # Execution assertion 1: Time-sensitive question displays notice
        args_temporal = argparse.Namespace(
            prompt="who is the president in us",
            model="qwen2.5:0.5b",
            json=False,
            gemma4_opt_in=False,
            model_timeout=None,
            temperature=0.0,
            seed=42,
        )
        with patch("pai.call_model_generate", return_value="The president is John Doe."):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                rc = cmd_chat(args_temporal)
                self.assertEqual(rc, 0)
                out = mock_out.getvalue()
                self.assertIn("The president is John Doe.", out)
                self.assertIn(f"Notice: {TIME_SENSITIVE_NOTICE}", out)

        # Execution assertion 2: Non-temporal question does NOT display notice
        args_coding = argparse.Namespace(
            prompt="write a python function to compute fibonacci",
            model="qwen2.5:0.5b",
            json=False,
            gemma4_opt_in=False,
            model_timeout=None,
            temperature=0.0,
            seed=42,
        )
        with patch("pai.call_model_generate", return_value="def solve(): return 42"):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                rc = cmd_chat(args_coding)
                self.assertEqual(rc, 0)
                out = mock_out.getvalue()
                self.assertIn("def solve(): return 42", out)
                self.assertNotIn(TIME_SENSITIVE_NOTICE, out)

    # -------------------------------------------------------------------------
    # 13. Finding EX (Layer 0): Deterministic System Clock Queries
    # -------------------------------------------------------------------------
    def test_finding_ex_layer_0_deterministic_clock_queries(self) -> None:
        """
        Finding EX / Layer 0: Asserts is_plain_datetime_query() recognises plain
        date/time/day queries in English, Singlish, and Sinhala, rejects non-temporal
        negative controls ('date palm', 'due date'), and answers directly from the
        operating system clock without calling the model in both text and JSON modes.
        """
        import argparse
        import json
        from pai import cmd_chat, is_plain_datetime_query

        # Recognizer positive controls (English, Singlish, Sinhala)
        self.assertTrue(is_plain_datetime_query("what is the date"))
        self.assertTrue(is_plain_datetime_query("current time and date"))
        self.assertTrue(is_plain_datetime_query("what day is today"))
        self.assertTrue(is_plain_datetime_query("what time is it"))
        self.assertTrue(is_plain_datetime_query("ada dawasa"))
        self.assertTrue(is_plain_datetime_query("welawa kiyada"))
        self.assertTrue(is_plain_datetime_query("අද දිනය"))
        self.assertTrue(is_plain_datetime_query("වෙලාව කීයද"))

        # Recognizer negative controls
        self.assertFalse(is_plain_datetime_query("what is a date palm"))
        self.assertFalse(is_plain_datetime_query("what is the due date of this assignment"))
        self.assertFalse(is_plain_datetime_query("explain date formatting in python"))

        # Execution assertion 1: Text mode returns system clock without calling model
        fake_clock = ("2026-10-28 (Wednesday)", "23:55:00", "UTC+0530")
        args_text = argparse.Namespace(
            prompt="what is the date",
            model="qwen2.5:0.5b",
            json=False,
            gemma4_opt_in=False,
            model_timeout=None,
            temperature=0.0,
            seed=42,
        )
        with patch("shell.get_current_system_clock_context", return_value=fake_clock), \
             patch("pai.call_model_generate") as mock_gen, \
             patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            rc = cmd_chat(args_text)
            self.assertEqual(rc, 0)
            mock_gen.assert_not_called()
            out = mock_out.getvalue()
            self.assertIn("Current local time: 2026-10-28 (Wednesday) 23:55:00 UTC+0530", out)

        # Execution assertion 2: JSON mode returns source: system_clock without calling model
        args_json = argparse.Namespace(
            prompt="welawa kiyada",
            model="qwen2.5:0.5b",
            json=True,
            gemma4_opt_in=False,
            model_timeout=None,
            temperature=0.0,
            seed=42,
        )
        with patch("shell.get_current_system_clock_context", return_value=fake_clock), \
             patch("pai.call_model_generate") as mock_gen, \
             patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            rc = cmd_chat(args_json)
            self.assertEqual(rc, 0)
            mock_gen.assert_not_called()
            data = json.loads(mock_out.getvalue())
            self.assertTrue(data.get("success"))
            self.assertEqual(data.get("source"), "system_clock")
            self.assertEqual(data.get("prompt"), "welawa kiyada")
            self.assertEqual(data.get("response"), "Current local time: 2026-10-28 (Wednesday) 23:55:00 UTC+0530")

    # -------------------------------------------------------------------------
    # 14. Subcommand Noise Suppression in Interactive Shell
    # -------------------------------------------------------------------------
    def test_subcommand_noise_suppression_when_shell_active(self) -> None:
        """
        Asserts that 'Sandbox execution boundary verified fail-closed.' is printed
        once at shell startup, but suppressed during subcommand turns within the shell.
        """
        # Direct CLI call: message is printed
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PAI_SHELL_ACTIVE", None)
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with patch("pai.enforce_sandbox_boundary"):
                    from pai import cmd_chat
                    cmd_chat(MagicMock(prompt="", json=False))
                    self.assertIn("Sandbox execution boundary verified fail-closed.", mock_out.getvalue())

        # Inside shell: message is suppressed
        with patch.dict(os.environ, {"PAI_SHELL_ACTIVE": "1"}):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with patch("pai.enforce_sandbox_boundary"):
                    from pai import cmd_chat
                    cmd_chat(MagicMock(prompt="", json=False))
                    self.assertNotIn("Sandbox execution boundary verified fail-closed.", mock_out.getvalue())


if __name__ == "__main__":
    unittest.main()
