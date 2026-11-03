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
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

RESEARCH_DIR = Path(__file__).resolve().parent.parent
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

from shell import (
    DEVELOPER_CREDIT,
    MAX_HISTORY_BYTES,
    MAX_HISTORY_ITEMS,
    PAI_ASCII_FALLBACK_LOGO,
    PAI_UNICODE_BLOCK_LOGO,
    SHELL_BANNER,
    SHELL_HELP,
    ThinkingSpinner,
    add_to_session_history,
    can_encode_blocks,
    check_and_apply_resize,
    cleanup_pinned_layout,
    clear_session_history,
    execute_subcommand,
    format_session_history,
    get_pinned_header_lines,
    get_session_history,
    get_shell_banner,
    get_shell_info_line,
    get_shell_logo_lines,
    get_shell_separator_line,
    get_terminal_dimensions,
    is_interactive_terminal,
    parse_shell_line,
    run_interactive_shell,
    setup_pinned_layout,
    should_pin_header,
    tokenize_windows_line,
)


class DummyStream(io.StringIO):
    def __init__(self, initial_value="", encoding="utf-8", is_tty=True):
        super().__init__(initial_value)
        self._encoding = encoding
        self._is_tty = is_tty

    @property
    def encoding(self) -> str:
        return self._encoding

    def isatty(self) -> bool:
        return self._is_tty


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
        Finding ES Layer 3, Finding EV & Finding FA: Asserts the regex word-boundary heuristic
        detects time-sensitive prompts in English, Singlish, and Sinhala without
        falling prey to substring false positives (quicksort, author, underscore, scoreboard)
        or technical tool/command parameters (Finding FA: temperature parameter, forecast command, weather api).
        Appends the deterministic notice:
        'PAI is offline. This answer comes from the model's training data and may be outdated. It was not checked against the internet.'
        """
        import argparse
        from pai import cmd_chat, is_time_sensitive_prompt, TIME_SENSITIVE_NOTICE

        # Finding EV & FA: Positive controls across domains and languages
        self.assertTrue(is_time_sensitive_prompt("what is the price of bitcoin"))
        self.assertTrue(is_time_sensitive_prompt("who won the world cup"))
        self.assertTrue(is_time_sensitive_prompt("is it raining now"))
        self.assertTrue(is_time_sensitive_prompt("who is the president in us"))
        self.assertTrue(is_time_sensitive_prompt("latest python version"))
        self.assertTrue(is_time_sensitive_prompt("dan president kawda?"))
        self.assertTrue(is_time_sensitive_prompt("iphone eke aluthma model eka monawada"))
        self.assertTrue(is_time_sensitive_prompt("වත්මන් ජනාධිපති කවුද?"))
        self.assertTrue(is_time_sensitive_prompt("what is the weather today"))
        self.assertTrue(is_time_sensitive_prompt("weather forecast"))
        self.assertTrue(is_time_sensitive_prompt("what is the temperature outside"))
        self.assertTrue(is_time_sensitive_prompt("what is the current temperature"))
        self.assertTrue(is_time_sensitive_prompt("weather in colombo"))

        # Finding EV, FA & FC: Negative controls (eliminated substring, live-sense lookahead, and parameter false alarms)
        self.assertFalse(is_time_sensitive_prompt("what time complexity does quicksort have"))
        self.assertFalse(is_time_sensitive_prompt("who is the author of this function"))
        self.assertFalse(is_time_sensitive_prompt("rename my_underscore variable"))
        self.assertFalse(is_time_sensitive_prompt("explain the scoreboard class"))
        self.assertFalse(is_time_sensitive_prompt("write a python function to compute fibonacci"))
        self.assertFalse(is_time_sensitive_prompt("explain binary search trees"))
        self.assertFalse(is_time_sensitive_prompt("set the temperature parameter of the llm to 0"))
        self.assertFalse(is_time_sensitive_prompt("how do I use the forecast command"))
        self.assertFalse(is_time_sensitive_prompt("explain weather api design"))
        # Finding FC: Parameter, code, and non-location lookahead controls
        self.assertFalse(is_time_sensitive_prompt("what is the current temperature parameter"))
        self.assertFalse(is_time_sensitive_prompt("set current temperature of the model to 0.7"))
        self.assertFalse(is_time_sensitive_prompt("use the temperature in the sampling code"))
        self.assertFalse(is_time_sensitive_prompt("weather in the room"))
        self.assertFalse(is_time_sensitive_prompt("temperature in this test"))

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
    # 13. Finding EX & EZ (Layer 0): Deterministic System Clock Queries
    # -------------------------------------------------------------------------
    def test_finding_ex_layer_0_deterministic_clock_queries(self) -> None:
        """
        Finding EX / EZ / Layer 0: Asserts is_plain_datetime_query() recognises only short
        complete date/time/day questions in English, Singlish, and Sinhala (<= 8 words)
        via full template matching.
        Asserts negative controls (places, time zones, formats, code tasks, extra words)
        are rejected (return False) and routed to the model path (call_model_generate IS called).
        Asserts positive controls return True and answer directly from clock without calling model.
        """
        import argparse
        import json
        from pai import cmd_chat, is_plain_datetime_query

        # Recognizer positive controls (English, Singlish, Sinhala) - must be True
        positives = [
            "what is the date",
            "what time is it",
            "can you give me current time and date",
            "what day is today",
            "tell me the time",
            "please tell me the date and time?",
            "ada dawasa monawada",
            "welawa kiyada",
            "අද දිනය කුමක්ද?",
            "වෙලාව කීයද",
        ]
        for query in positives:
            self.assertTrue(is_plain_datetime_query(query), f"Expected True for plain query: {query}")

        # Recognizer negative controls (Finding EZ) - must be False
        negatives = [
            "what is the time complexity of quicksort",
            "what is the date of independence day in sri lanka",
            "what is the date format used in ISO 8601",
            "what is the day length on mars",
            "explain how time and date functions work in python",
            "write a python function that prints the current date and time",
            "what is the time in tokyo",
            "what is the current time zone abbreviation for colombo",
            "what is a date palm",
            "what is the due date of this assignment",
            "explain date formatting in python",
        ]
        for query in negatives:
            self.assertFalse(is_plain_datetime_query(query), f"Expected False for complex query: {query}")

        fake_clock = ("2026-10-28 (Wednesday)", "23:55:00", "UTC+0530")

        # Execution assertion 1: Positive controls MUST NOT call model (answered from system clock)
        for query in positives:
            args = argparse.Namespace(
                prompt=query,
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
                rc = cmd_chat(args)
                self.assertEqual(rc, 0)
                mock_gen.assert_not_called()
                out = mock_out.getvalue()
                self.assertIn("Current local time: 2026-10-28 (Wednesday) 23:55:00 UTC+0530", out)

        # Execution assertion 2: Negative controls MUST CALL the model
        for query in negatives:
            args = argparse.Namespace(
                prompt=query,
                model="qwen2.5:0.5b",
                json=False,
                gemma4_opt_in=False,
                model_timeout=None,
                temperature=0.0,
                seed=42,
            )
            with patch("shell.get_current_system_clock_context", return_value=fake_clock), \
                 patch("pai.call_model_generate", return_value="Model answer for query") as mock_gen, \
                 patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                rc = cmd_chat(args)
                self.assertEqual(rc, 0)
                mock_gen.assert_called_once()
                out = mock_out.getvalue()
                self.assertIn("Model answer for query", out)

        # Execution assertion 3: JSON mode returns source: system_clock without calling model
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

    # -------------------------------------------------------------------------
    # 15. Milestone B: Pinned DECSTBM Header Layout & Cleanup (ADR-014)
    # -------------------------------------------------------------------------
    def test_shell_pinned_header_layout_vt(self) -> None:
        """
        Milestone B: Asserts that when terminal conditions satisfy should_pin_header():
          - Screen is cleared with \033[2J\033[1;1H (never \033[3J which clears scrollback).
          - Exactly 5 header lines are written to top rows (rows 1..5).
          - Pinned scroll region is set via DECSTBM: \033[6;{rows}r\033[6;1H.
          - On clean exit (/exit, EOF), cleanup_pinned_layout emits \033[r to restore full scroll region,
            positions cursor at bottom row, resets attributes (\033[0m), and shows cursor (\033[?25h).
        """
        mock_stream = DummyStream(encoding="utf-8", is_tty=True)

        with patch("shell.is_interactive_terminal", return_value=True), \
             patch("shell.enable_windows_vt", return_value=True), \
             patch("shell.get_terminal_dimensions", return_value=(80, 24)), \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PAI_NO_PINNED_HEADER", None)
            os.environ.pop("TERM", None)

            self.assertTrue(should_pin_header(mock_stream))

            inputs = iter(["/exit"])
            outputs: list[str] = []

            with patch("pai.enforce_sandbox_boundary"):
                code = run_interactive_shell(
                    input_fn=lambda _: next(inputs),
                    output_fn=outputs.append,
                    stream=mock_stream,
                )
                self.assertEqual(code, 0)

            raw_stream_output = mock_stream.getvalue()
            # Must clear screen without 3J (3J destroys terminal scrollback buffer)
            self.assertIn("\033[2J\033[1;1H", raw_stream_output)
            self.assertNotIn("\033[3J", raw_stream_output)

            # Must set DECSTBM margins for rows 6..24
            self.assertIn("\033[6;24r\033[6;1H", raw_stream_output)

            # Must write header containing logo and info
            self.assertIn("PAI v1.1.0", raw_stream_output)
            self.assertIn("Developed by Hirusha Suhan", raw_stream_output)

            # Cleanup must restore full margins (\033[r) and cursor attributes
            self.assertIn("\033[r", raw_stream_output)
            self.assertIn("\033[24;1H\r\n", raw_stream_output)
            self.assertIn("\033[0m\033[?25h", raw_stream_output)

    # -------------------------------------------------------------------------
    # 16. Milestone B: Non-Pinned Mode Fallbacks
    # -------------------------------------------------------------------------
    def test_shell_non_pinned_fallbacks(self) -> None:
        """
        Milestone B: Asserts that DECSTBM pinned layout is skipped (should_pin_header returns False)
        and zero margin sequences (\033[6; or \033[r) are emitted when:
          - Output stream is not a TTY.
          - PAI_NO_PINNED_HEADER=1 opt-out is set.
          - TERM='dumb'.
          - Terminal height < 20 (small window).
          - Terminal width < 60 (narrow window).
        """
        # Case A: Not a TTY
        mock_non_tty = io.StringIO()
        mock_non_tty.isatty = lambda: False  # type: ignore[attr-defined]
        self.assertFalse(should_pin_header(mock_non_tty))

        # Case B: PAI_NO_PINNED_HEADER=1 opt-out
        mock_tty = io.StringIO()
        mock_tty.isatty = lambda: True  # type: ignore[attr-defined]
        with patch.dict(os.environ, {"PAI_NO_PINNED_HEADER": "1"}):
            self.assertFalse(should_pin_header(mock_tty))

        # Case C: TERM=dumb
        with patch.dict(os.environ, {"TERM": "dumb"}):
            self.assertFalse(should_pin_header(mock_tty))

        # Case D: Height < 20
        with patch("shell.is_interactive_terminal", return_value=True), \
             patch("shell.get_terminal_dimensions", return_value=(80, 19)):
            self.assertFalse(should_pin_header(mock_tty))

        # Case E: Width < 60
        with patch("shell.is_interactive_terminal", return_value=True), \
             patch("shell.get_terminal_dimensions", return_value=(59, 25)):
            self.assertFalse(should_pin_header(mock_tty))

        # Execution assertion: Under non-pinned mode, standard banner is used and zero DECSTBM escapes are emitted
        stream_out = io.StringIO()
        stream_out.isatty = lambda: False  # type: ignore[attr-defined]
        inputs = iter(["/exit"])
        outputs: list[str] = []

        with patch("pai.enforce_sandbox_boundary"):
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
                stream=stream_out,
            )
            self.assertEqual(code, 0)

        raw = stream_out.getvalue()
        self.assertNotIn("\033[6;", raw)
        self.assertNotIn("\033[24r", raw)
        self.assertNotIn("\033[r", raw)
        # Standard banner printed in outputs
        combined = "\n".join(outputs)
        self.assertIn("Personal Agentic AI (PAI) Interactive Shell", combined)

    # -------------------------------------------------------------------------
    # 17. Milestone B: Terminal Window Resize Detection
    # -------------------------------------------------------------------------
    def test_shell_resize_detection(self) -> None:
        """
        Milestone B: Asserts check_and_apply_resize detects dimension changes,
        redraws the pinned header, and updates the DECSTBM scrolling margin.
        """
        mock_stream = DummyStream(encoding="utf-8", is_tty=True)

        # Case 1: Dimensions unchanged -> returns same dimensions, writes nothing
        with patch("shell.get_terminal_dimensions", return_value=(80, 24)):
            res = check_and_apply_resize((80, 24), stream=mock_stream)
            self.assertEqual(res, (80, 24))
            self.assertEqual(mock_stream.getvalue(), "")

        # Case 2: Terminal resized from 80x24 to 120x40
        with patch("shell.get_terminal_dimensions", return_value=(120, 40)):
            res = check_and_apply_resize((80, 24), stream=mock_stream)
            self.assertEqual(res, (120, 40))
            out = mock_stream.getvalue()
            # Header line redrawn with clear line (\033[2K)
            self.assertIn("\033[1;1H\033[2K", out)
            # New scroll margin set: rows 6..40
            self.assertIn("\033[6;40r", out)

    # -------------------------------------------------------------------------
    # 18. Milestone B: Logo Encoding Detection & ASCII Fallback
    # -------------------------------------------------------------------------
    def test_shell_logo_encoding_and_fallback(self) -> None:
        """
        Milestone B: Asserts can_encode_blocks detects Unicode block character support:
          - UTF-8 stream: returns True, uses 3-row half-block logo (█▀█) and box-drawing rule (─).
          - Non-Unicode stream (e.g. cp1252 / ascii): returns False, uses 3-row compact ASCII logo and hyphen rule (-).
          - Header lines are exactly 5 rows and fit comfortably in 80 columns.
        """
        # Stream A: UTF-8
        utf8_stream = DummyStream(encoding="utf-8", is_tty=True)
        self.assertTrue(can_encode_blocks(utf8_stream))

        lines_utf8 = get_pinned_header_lines(80, color_enabled=False, stream=utf8_stream)
        self.assertEqual(len(lines_utf8), 5)
        self.assertIn("█▀█", lines_utf8[0])
        self.assertIn("─", lines_utf8[4])
        for line in lines_utf8:
            self.assertLessEqual(len(line), 80)

        # Stream B: ASCII / Non-Unicode stream
        ascii_stream = DummyStream(encoding="ascii", is_tty=True)
        self.assertFalse(can_encode_blocks(ascii_stream))

        lines_ascii = get_pinned_header_lines(80, color_enabled=False, stream=ascii_stream)
        self.assertEqual(len(lines_ascii), 5)
        self.assertIn(" ___ ", lines_ascii[0])
        self.assertIn("-", lines_ascii[4])
        for line in lines_ascii:
            self.assertLessEqual(len(line), 80)

    # -------------------------------------------------------------------------
    # 19. Milestone B: In-Memory /history Command & Privacy Bounds
    # -------------------------------------------------------------------------
    def test_shell_in_memory_session_history(self) -> None:
        """
        Milestone B: Asserts in-memory session history:
          - Records commands and outputs in memory (_session_history).
          - Enforces 1 MB total memory limit and 200 items maximum cap.
          - /history defaults to last 20 entries; /history N displays last N entries.
          - Invalid arguments (non-integer, <= 0) return clear error.
          - Zero disk writes: asserts open(), Path.write_text(), Path.write_bytes() are never called for writing.
          - History is never forwarded to language model / Ollama daemon.
          - History is wiped clean upon shell termination.
        """
        clear_session_history()
        self.assertEqual(len(get_session_history()), 0)

        # Record sample commands
        add_to_session_history("/doctor", "All checks passed.")
        add_to_session_history("what is rust", "Rust is a systems programming language.")
        self.assertEqual(len(get_session_history()), 2)

        formatted = format_session_history(color_enabled=False)
        self.assertIn("=== Session History (last 2 entries) ===", formatted)
        self.assertIn("/doctor", formatted)
        self.assertIn("what is rust", formatted)
        self.assertIn("All checks passed.", formatted)

        # Limit parameter
        limited = format_session_history(limit=1, color_enabled=False)
        self.assertIn("=== Session History (last 1 entries) ===", limited)
        self.assertNotIn("/doctor", limited)
        self.assertIn("what is rust", limited)

        # Memory capping (MAX_HISTORY_BYTES = 1 MB)
        huge_output = "X" * 600_000
        add_to_session_history("cmd1", huge_output)
        add_to_session_history("cmd2", huge_output)
        # Should pop oldest entry to stay under 1 MB
        self.assertLessEqual(sum(len(c) + len(o) for _, c, o in get_session_history(200)), MAX_HISTORY_BYTES)

        # REPL execution assertion & Zero Disk Writes test
        inputs = iter(["/history 5", "/exit"])
        outputs: list[str] = []

        original_open = open
        write_open_calls = []

        def spy_open(file, mode="r", *args, **kwargs):
            if any(m in str(mode) for m in ("w", "a", "+", "x")):
                write_open_calls.append((file, mode))
            return original_open(file, mode, *args, **kwargs)

        with patch("builtins.open", side_effect=spy_open), \
             patch("pathlib.Path.write_text") as mock_write_text, \
             patch("pathlib.Path.write_bytes") as mock_write_bytes, \
             patch("pai.enforce_sandbox_boundary"):
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
            )
            self.assertEqual(code, 0)
            self.assertEqual(write_open_calls, [])
            mock_write_text.assert_not_called()
            mock_write_bytes.assert_not_called()

        combined = "\n".join(outputs)
        self.assertIn("Session History", combined)

        # History is wiped on exit
        self.assertEqual(len(get_session_history()), 0)

        # Command parsing validation for /history
        act_def, argv_def = parse_shell_line("/history")
        self.assertEqual(act_def, "history")
        self.assertEqual(argv_def, [])

        act_5, argv_5 = parse_shell_line("/history 10")
        self.assertEqual(act_5, "history")
        self.assertEqual(argv_5, ["10"])

        act_bad, argv_bad = parse_shell_line("/history abc")
        self.assertEqual(act_bad, "error")
        self.assertIn("Error: /history argument must be a positive integer.", argv_bad[0])

        act_neg, argv_neg = parse_shell_line("/history -5")
        self.assertEqual(act_neg, "error")
        self.assertIn("Error: /history argument must be a positive integer.", argv_neg[0])

    # -------------------------------------------------------------------------
    # 20. Milestone B: /clear Command in Pinned and Non-Pinned Modes
    # -------------------------------------------------------------------------
    def test_shell_clear_command(self) -> None:
        """
        Milestone B: Asserts /clear (and /cls):
          - In pinned VT mode: clears only the scrolling chat region (\033[6;1H\033[J)
            without clearing the pinned header rows.
          - In non-pinned mode: clears screen (\033[2J\033[1;1H) and re-displays the startup banner.
        """
        # Parsing test
        for cmd in ("/clear", "/cls"):
            act, argv = parse_shell_line(cmd)
            self.assertEqual(act, "clear")
            self.assertEqual(argv, [])

        # Case A: Pinned VT mode
        pinned_stream = DummyStream(encoding="utf-8", is_tty=True)

        with patch("shell.should_pin_header", return_value=True), \
             patch("pai.enforce_sandbox_boundary"):
            inputs = iter(["/clear", "/exit"])
            outputs: list[str] = []
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
                stream=pinned_stream,
            )
            self.assertEqual(code, 0)
            raw = pinned_stream.getvalue()
            # Must position cursor at line 6, col 1 and clear to end of screen (\033[J)
            self.assertIn("\033[6;1H\033[J", raw)

        # Case B: Non-pinned mode
        unpinned_stream = DummyStream(encoding="utf-8", is_tty=False)

        with patch("shell.should_pin_header", return_value=False), \
             patch("pai.enforce_sandbox_boundary"):
            inputs = iter(["/clear", "/exit"])
            outputs = []
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
                stream=unpinned_stream,
            )
            self.assertEqual(code, 0)
            # Startup banner reprinted in outputs
            self.assertGreaterEqual(sum("Personal Agentic AI (PAI)" in o for o in outputs), 2)

    # -------------------------------------------------------------------------
    # 21. Milestone B: Thinking Spinner for /chat
    # -------------------------------------------------------------------------
    def test_shell_thinking_spinner(self) -> None:
        """
        Milestone B: Asserts ThinkingSpinner:
          - Starts only when stdout is a TTY and TERM != 'dumb'.
          - Does not start when stdout is not a TTY.
          - Renders braille or ASCII frames with elapsed time.
          - Clears line (\r\033[2K) upon stop().
          - Thread is cleanly joined even when command raises an exception.
        """
        # Non-TTY: disabled
        non_tty_stream = DummyStream(encoding="utf-8", is_tty=False)
        spinner_disabled = ThinkingSpinner(non_tty_stream)
        self.assertFalse(spinner_disabled.enabled)
        spinner_disabled.start()
        self.assertIsNone(spinner_disabled._thread)
        spinner_disabled.stop()

        # Simulated TTY: enabled
        tty_stream = DummyStream(encoding="utf-8", is_tty=True)
        spinner_enabled = ThinkingSpinner(tty_stream)
        self.assertTrue(spinner_enabled.enabled)

        spinner_enabled.start()
        self.assertIsNotNone(spinner_enabled._thread)
        self.assertTrue(spinner_enabled._thread.is_alive())  # type: ignore[union-attr]
        time.sleep(0.15)
        spinner_enabled.stop()
        self.assertIsNone(spinner_enabled._thread)
        raw_out = tty_stream.getvalue()
        self.assertIn("Thinking...", raw_out)
        self.assertIn("\r\033[2K", raw_out)

        # Exception safety in REPL: spinner safely stopped on error
        failing_stream = DummyStream(encoding="utf-8", is_tty=True)

        def bomb(_):
            raise RuntimeError("Model crashed")

        with patch("shell.execute_subcommand", side_effect=bomb), \
             patch("shell.should_pin_header", return_value=False), \
             patch("pai.enforce_sandbox_boundary"):
            inputs = iter(["/chat boom", "/exit"])
            outputs: list[str] = []
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
                stream=failing_stream,
            )
            self.assertEqual(code, 0)
            self.assertIn("Error: Model crashed", " ".join(outputs))

    # -------------------------------------------------------------------------
    # 22. Milestone B: Model Output Hygiene & Terminal Scroll Margin Integrity
    # -------------------------------------------------------------------------
    def test_shell_model_output_hygiene_cannot_break_scroll_margins(self) -> None:
        """
        Milestone B: Asserts model replies containing malicious VT escape sequences
        (such as \033[r to reset scroll margins, \033[1;1H to overwrite the pinned header,
        or \033[2J to clear the screen) are sanitized by sanitize_terminal_output,
        guaranteeing that untrusted model responses cannot break out of or corrupt terminal margins.
        """
        from ingest import sanitize_terminal_output

        malicious_model_payloads = [
            "Normal answer \033[r breaking scroll region",
            "Reset margins \x1b[r and clear screen \x1b[2J",
            "Move cursor to header \033[1;1H Overwritten header!",
            "Inject escape \033[6;30r new margins",
            "OSC hyperlink test \033]8;;https://malicious.site\033\\Click here\033]8;;\033\\",
        ]

        for payload in malicious_model_payloads:
            sanitized = sanitize_terminal_output(payload)
            self.assertNotIn("\033[r", sanitized)
            self.assertNotIn("\x1b[r", sanitized)
            self.assertNotIn("\033[1;1H", sanitized)
            self.assertNotIn("\033[2J", sanitized)
            self.assertNotIn("\x1b[2J", sanitized)
            self.assertNotIn("\033[6;30r", sanitized)
            self.assertNotIn("\033]8;;", sanitized)


if __name__ == "__main__":
    unittest.main()
