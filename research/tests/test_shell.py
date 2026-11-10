"""
Unit tests for ADR-014 Commit 2: Interactive Terminal Shell (REPL).
Verifies terminal detection, slash command dispatching, fail-safe unknown command rejection,
Windows backslash/UNC/Unicode tokenization (Finding DW), exclusion of maintenance commands (Finding DV),
leading dash handling and stateless banner honesty (Finding DX), and signal resilience.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

RESEARCH_DIR = Path(__file__).resolve().parent.parent
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

import shell
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
    get_install_root_version,
    get_pinned_header_lines,
    get_pinned_shell_notice_lines,
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


class VirtualTerminalScreen:
    """
    Pure-Python standard-library-only VT100/ANSI terminal screen emulator (Finding FO).
    Simulates screen character matrix, cursor positioning (CUP), line & display erasing (ED, EL),
    DECSTBM scroll margins with VT100 cursor-home reset, and line-feed region scrolling.
    """
    def __init__(self, rows: int = 24, cols: int = 80):
        self.rows = rows
        self.cols = cols
        self.grid = [[" " for _ in range(cols)] for _ in range(rows)]
        self.cursor_row = 1  # 1-indexed (1..rows)
        self.cursor_col = 1  # 1-indexed (1..cols)
        self.top_margin = 1  # 1-indexed (1..rows)
        self.bottom_margin = rows
        self.saved_cursor = (1, 1)

    def resize(self, new_rows: int, new_cols: int) -> None:
        """Resizes the terminal screen and resets scroll margins to full screen."""
        new_grid = [[" " for _ in range(new_cols)] for _ in range(new_rows)]
        for r in range(min(self.rows, new_rows)):
            for c in range(min(self.cols, new_cols)):
                new_grid[r][c] = self.grid[r][c]
        self.rows = new_rows
        self.cols = new_cols
        self.grid = new_grid
        self.top_margin = 1
        self.bottom_margin = new_rows
        self.cursor_row = min(self.cursor_row, new_rows)
        self.cursor_col = min(self.cursor_col, new_cols)

    def write(self, text: str) -> None:
        """Parses and renders text and ANSI/VT escape sequences onto the screen."""
        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if ch in ("\033", "\x1b"):
                i += 1
                if i >= n:
                    break
                next_ch = text[i]
                if next_ch == "[":
                    i += 1
                    params = ""
                    while i < n and (text[i].isdigit() or text[i] in ";?"):
                        params += text[i]
                        i += 1
                    if i < n:
                        cmd = text[i]
                        i += 1
                        self._handle_csi(cmd, params)
                elif next_ch == "7":
                    self.saved_cursor = (self.cursor_row, self.cursor_col)
                    i += 1
                elif next_ch == "8":
                    self.cursor_row, self.cursor_col = self.saved_cursor
                    i += 1
                else:
                    i += 1
            elif ch == "\r":
                self.cursor_col = 1
                i += 1
            elif ch == "\n":
                self._handle_lf()
                i += 1
            elif ch == "\b":
                self.cursor_col = max(1, self.cursor_col - 1)
                i += 1
            elif ch == "\t":
                self.cursor_col = min(self.cols, ((self.cursor_col - 1) // 8 + 1) * 8 + 1)
                i += 1
            elif ord(ch) < 32:
                i += 1
            else:
                if 1 <= self.cursor_row <= self.rows and 1 <= self.cursor_col <= self.cols:
                    self.grid[self.cursor_row - 1][self.cursor_col - 1] = ch
                    self.cursor_col = min(self.cols, self.cursor_col + 1)
                i += 1

    def _handle_lf(self) -> None:
        """Handles line feed (LF): advances cursor down or scrolls within margin."""
        if self.cursor_row == self.bottom_margin:
            top_idx = self.top_margin - 1
            bot_idx = self.bottom_margin - 1
            for r in range(top_idx, bot_idx):
                self.grid[r] = list(self.grid[r + 1])
            self.grid[bot_idx] = [" " for _ in range(self.cols)]
        elif self.cursor_row < self.rows:
            self.cursor_row += 1

    def _handle_csi(self, cmd: str, params: str) -> None:
        """Processes CSI commands."""
        parts = [int(p) for p in params.split(";") if p.isdigit()]
        if cmd in ("H", "f"):
            r = parts[0] if parts and parts[0] > 0 else 1
            c = parts[1] if len(parts) >= 2 and parts[1] > 0 else 1
            self.cursor_row = max(1, min(self.rows, r))
            self.cursor_col = max(1, min(self.cols, c))
        elif cmd == "J":
            mode = parts[0] if parts else 0
            if mode == 2:
                self.grid = [[" " for _ in range(self.cols)] for _ in range(self.rows)]
            elif mode == 0:
                cur_r = self.cursor_row - 1
                cur_c = self.cursor_col - 1
                for c in range(cur_c, self.cols):
                    self.grid[cur_r][c] = " "
                for r in range(self.cursor_row, self.rows):
                    self.grid[r] = [" " for _ in range(self.cols)]
        elif cmd == "K":
            mode = parts[0] if parts else 0
            cur_r = self.cursor_row - 1
            if mode == 2:
                self.grid[cur_r] = [" " for _ in range(self.cols)]
            elif mode == 0:
                cur_c = self.cursor_col - 1
                for c in range(cur_c, self.cols):
                    self.grid[cur_r][c] = " "
        elif cmd == "r":
            if len(parts) >= 2:
                self.top_margin = max(1, min(self.rows, parts[0]))
                self.bottom_margin = max(self.top_margin, min(self.rows, parts[1]))
            else:
                self.top_margin = 1
                self.bottom_margin = self.rows
            # Per VT100 standard: DECSTBM resets cursor to home (1, 1)
            self.cursor_row = 1
            self.cursor_col = 1
        elif cmd == "s":
            self.saved_cursor = (self.cursor_row, self.cursor_col)
        elif cmd == "u":
            self.cursor_row, self.cursor_col = self.saved_cursor

    def get_row(self, row_idx: int) -> str:
        """Returns the text of 1-indexed row_idx as a string stripped of trailing spaces."""
        if 1 <= row_idx <= self.rows:
            return "".join(self.grid[row_idx - 1]).rstrip()
        return ""

    def get_screen_text(self) -> str:
        """Returns the full screen as a multi-line string."""
        return "\n".join(self.get_row(r) for r in range(1, self.rows + 1))


class VirtualTerminalStream(DummyStream):
    """Bridge stream connecting stdout writes directly to VirtualTerminalScreen."""
    def __init__(self, screen: VirtualTerminalScreen, encoding="utf-8", is_tty=True):
        super().__init__(encoding=encoding, is_tty=is_tty)
        self.screen = screen

    def write(self, s: str) -> int:
        super().write(s)
        self.screen.write(s)
        return len(s)
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
             patch.dict(os.environ, {"PAI_PINNED_HEADER": "1"}, clear=False):
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
            self.assertIn("PAI dev", raw_stream_output)
            self.assertIn("Developed by Hirusha Suhan", raw_stream_output)

            # Cleanup must restore full margins (\033[r) and cursor attributes
            self.assertIn("\033[r", raw_stream_output)
            self.assertIn("\033[24;1H", raw_stream_output)
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

    # -------------------------------------------------------------------------
    # 23. Milestone B2: Subprocess Isolation & Zero Import Pollution (Finding FK)
    # -------------------------------------------------------------------------
    def test_shell_finding_fk_subprocess_isolation(self) -> None:
        """
        Finding FK: Asserts that importing shell.py or invoking CLI commands
        never emits escape sequences into non-terminal or piped stdout:
          - 'pai chat "what is the date" --json' emits clean JSON with zero ESC (\\x1b) bytes.
          - 'pai chat "what is the date"' in plain-text emits clean text with zero ESC bytes.
          - 'python -c "import shell"' outputs exactly 0 bytes to both stdout and stderr.
        """
        repo_root = str(RESEARCH_DIR.parent)
        pai_py = str(RESEARCH_DIR / "pai.py")

        # 1. JSON mode with piped stdout
        res_json = subprocess.run(
            [sys.executable, pai_py, "chat", "what is the date", "--json"],
            capture_output=True,
            cwd=repo_root,
        )
        self.assertEqual(res_json.returncode, 0)
        self.assertNotIn(b"\x1b", res_json.stdout, "ESC byte found in JSON stdout")
        data = json.loads(res_json.stdout.decode("utf-8"))
        self.assertTrue(data.get("success"), "JSON response did not report success")
        self.assertIn("Current local time:", data.get("response", ""))

        # 2. Text mode with piped stdout
        res_text = subprocess.run(
            [sys.executable, pai_py, "chat", "what is the date"],
            capture_output=True,
            cwd=repo_root,
        )
        self.assertEqual(res_text.returncode, 0)
        self.assertNotIn(b"\x1b", res_text.stdout, "ESC byte found in plain text stdout")
        self.assertIn("Current local time:", res_text.stdout.decode("utf-8"))

        # 3. Import shell and exit: exactly 0 bytes on stdout and stderr
        cmd_import = "import sys; sys.path.insert(0, 'research'); import shell"
        res_import = subprocess.run(
            [sys.executable, "-c", cmd_import],
            capture_output=True,
            cwd=repo_root,
        )
        self.assertEqual(res_import.returncode, 0)
        self.assertEqual(res_import.stdout, b"", "import shell wrote unexpected bytes to stdout")
        self.assertEqual(res_import.stderr, b"", "import shell wrote unexpected bytes to stderr")

    # -------------------------------------------------------------------------
    # 24. Milestone B2: 40-Turn VT Scrolling Stability via Screen Model (Findings FL & FO)
    # -------------------------------------------------------------------------
    def test_shell_finding_fl_fo_screen_model_40_turns(self) -> None:
        """
        Findings FL & FO: Feeds 40 turns of interactive execution through the
        standard-library VirtualTerminalScreen emulator:
          - Verifies header rows 1..5 remain completely intact across all 40 turns.
          - Verifies prompt 'pai> ' is never printed onto header rows 1..5.
          - Verifies scrolling occurs strictly inside the DECSTBM chat margins (lines 6..24).
          - Verifies cursor position remains within the active chat region (row >= 6).
        """
        screen = VirtualTerminalScreen(rows=24, cols=80)
        stream = VirtualTerminalStream(screen, encoding="utf-8", is_tty=True)

        commands = ["/time" if i % 2 == 0 else "/models" for i in range(40)] + ["/exit"]
        inputs = iter(commands)

        snapshots: list[list[str]] = []

        def turn_input(prompt: str) -> str:
            # Record screen header snapshot at prompt time
            snapshots.append([screen.get_row(r) for r in range(1, 6)])
            cmd = next(inputs)
            stream.write(prompt + cmd + "\r\n")
            return cmd

        with patch("shell.should_pin_header", return_value=True), \
             patch("shell.get_terminal_dimensions", return_value=(80, 24)), \
             patch("pai.enforce_sandbox_boundary"):
            code = run_interactive_shell(
                input_fn=turn_input,
                output_fn=lambda msg: stream.write(msg + "\r\n"),
                stream=stream,
            )
            self.assertEqual(code, 0)

        # Retrieve reference header lines for 80 columns without color
        ref_lines = get_pinned_header_lines(80, color_enabled=False, stream=stream)
        self.assertEqual(len(ref_lines), 5)

        # Assert all 40 snapshots maintained exact intact header rows
        self.assertGreaterEqual(len(snapshots), 40)
        for turn_idx, snap in enumerate(snapshots):
            self.assertEqual(len(snap), 5, f"Turn {turn_idx}: header does not have 5 rows")
            self.assertEqual(snap[0], ref_lines[0].rstrip(), f"Turn {turn_idx}: Row 1 logo corrupted")
            self.assertEqual(snap[1], ref_lines[1].rstrip(), f"Turn {turn_idx}: Row 2 logo corrupted")
            self.assertEqual(snap[2], ref_lines[2].rstrip(), f"Turn {turn_idx}: Row 3 logo corrupted")
            self.assertEqual(snap[3], ref_lines[3].rstrip(), f"Turn {turn_idx}: Row 4 info corrupted")
            self.assertEqual(snap[4], ref_lines[4].rstrip(), f"Turn {turn_idx}: Row 5 separator corrupted")
            # Prompt must never be on rows 1..5
            for r in range(5):
                self.assertNotIn("pai>", snap[r], f"Turn {turn_idx}: prompt found on header row {r + 1}")

    # -------------------------------------------------------------------------
    # 25. Milestone B2: Window Resize and Cursor Position Protection (Findings FL & FO)
    # -------------------------------------------------------------------------
    def test_shell_finding_fl_fo_screen_resize_handling(self) -> None:
        """
        Findings FL & FO: Asserts that upon terminal resize:
          - check_and_apply_resize derives header height dynamically from len(header_lines).
          - Sets new DECSTBM scroll margins.
          - Explicitly positions cursor at bottom row of the new dimensions, counteracting
            the VT100 DECSTBM default home (1, 1) cursor reset.
          - Next prompt 'pai>' is rendered at the bottom of the chat region, NEVER overwriting logo row 1.
          - Verified across both smaller (20x70) and larger (35x100) resize events.
        """
        screen = VirtualTerminalScreen(rows=24, cols=80)
        stream = VirtualTerminalStream(screen, encoding="utf-8", is_tty=True)

        with patch("shell.should_enable_color", return_value=False), \
             patch("shell.get_terminal_dimensions", return_value=(80, 24)):
            setup_pinned_layout(stream)

        # Initial state: 24x80
        ref_80 = get_pinned_header_lines(80, color_enabled=False, stream=stream)
        self.assertEqual(screen.get_row(1), ref_80[0].rstrip())
        self.assertEqual(screen.cursor_row, 6)
        self.assertEqual(screen.cursor_col, 1)

        # Event A: Resize smaller to 20 rows, 70 cols
        screen.resize(20, 70)
        with patch("shell.should_enable_color", return_value=False), \
             patch("shell.get_terminal_dimensions", return_value=(70, 20)):
            new_dims = check_and_apply_resize((80, 24), stream=stream)
            self.assertEqual(new_dims, (70, 20))

            # Cursor must be placed at bottom row (row 20, col 1)
            self.assertEqual(screen.cursor_row, 20)
            self.assertEqual(screen.cursor_col, 1)

            # Prompt printed at current cursor position
            stream.write("pai> ")
            self.assertIn("pai>", screen.get_row(20))

            # Header row 1 must remain intact and must NOT contain "pai>"
            ref_70 = get_pinned_header_lines(70, color_enabled=False, stream=stream)
            self.assertEqual(screen.get_row(1), ref_70[0].rstrip())
            self.assertNotIn("pai>", screen.get_row(1))

        # Event B: Resize larger to 35 rows, 100 cols
        screen.resize(35, 100)
        with patch("shell.should_enable_color", return_value=False), \
             patch("shell.get_terminal_dimensions", return_value=(100, 35)):
            new_dims2 = check_and_apply_resize((70, 20), stream=stream)
            self.assertEqual(new_dims2, (100, 35))

            # Cursor must be placed at bottom row (row 35, col 1)
            self.assertEqual(screen.cursor_row, 35)
            self.assertEqual(screen.cursor_col, 1)

            # Prompt printed at row 35
            stream.write("pai> ")
            self.assertIn("pai>", screen.get_row(35))

            # Header row 1 intact and untouched
            ref_100 = get_pinned_header_lines(100, color_enabled=False, stream=stream)
            self.assertEqual(screen.get_row(1), ref_100[0].rstrip())
            self.assertNotIn("pai>", screen.get_row(1))

    # -------------------------------------------------------------------------
    # 26. Milestone B2: Pinned /clear via Screen Model (Findings FL & FO)
    # -------------------------------------------------------------------------
    def test_shell_finding_fl_fo_screen_clear_handling(self) -> None:
        """
        Findings FL & FO: Asserts that executing /clear in pinned mode:
          - Dynamically derives chat region start row (len(header_lines) + 1 = 6).
          - Clears lines 6..24 using \\033[6;1H\\033[J.
          - Leaves header rows 1..5 fully intact on the screen.
          - Positions cursor at row 6, col 1 ready for next input.
        """
        screen = VirtualTerminalScreen(rows=24, cols=80)
        stream = VirtualTerminalStream(screen, encoding="utf-8", is_tty=True)

        inputs = iter(["/time", "/clear", "/exit"])
        with patch("shell.should_pin_header", return_value=True), \
             patch("shell.get_terminal_dimensions", return_value=(80, 24)), \
             patch("pai.enforce_sandbox_boundary"):
            code = run_interactive_shell(
                input_fn=lambda prompt: next(inputs),
                output_fn=lambda msg: stream.write(msg + "\r\n"),
                stream=stream,
            )
            self.assertEqual(code, 0)

        # Header rows 1..5 remain intact
        ref_lines = get_pinned_header_lines(80, color_enabled=False, stream=stream)
        for r in range(1, 6):
            self.assertEqual(screen.get_row(r), ref_lines[r - 1].rstrip())

    # -------------------------------------------------------------------------
    # 27. Milestone B2: Honest Disclaimers and Help Hint in Pinned Mode (Finding FM)
    # -------------------------------------------------------------------------
    def test_shell_finding_fm_pinned_startup_honest_disclaimers(self) -> None:
        """
        Finding FM: Asserts that pinned interactive mode prints the complete set
        of honest notices and help hints in the chat region below the header:
          - 'Sandbox execution boundary verified fail-closed.'
          - 'Model: ... | Endpoint: ...'
          - Computer clock date/time notice (no web access, training cut-off)
          - Stateless mode notice
          - '/help' and '/exit' hint
        """
        outputs: list[str] = []
        inputs = iter(["/exit"])

        with patch("shell.should_pin_header", return_value=True), \
             patch("shell.setup_pinned_layout"), \
             patch("shell.get_resident_model_name", return_value="no model loaded yet"), \
             patch("pai.enforce_sandbox_boundary"):
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
            )
            self.assertEqual(code, 0)

        combined = "\n".join(outputs)
        self.assertIn("Sandbox execution boundary verified fail-closed.", combined)
        self.assertIn("Model: no model loaded yet | Endpoint: http://127.0.0.1:11434", combined)
        self.assertIn("PAI gives the model your computer's date and time", combined)
        self.assertIn("no web access and its knowledge ends at a training cut-off", combined)
        self.assertIn("Stateless", combined)
        self.assertIn("Type /help for available commands or /exit to quit.", combined)

    # -------------------------------------------------------------------------
    # 28. Milestone B2: Unpinned /clear TTY Check and UTF-8 History Limit (Finding FN)
    # -------------------------------------------------------------------------
    def test_shell_finding_fn_unpinned_clear_and_utf8_history_cap(self) -> None:
        """
        Finding FN:
          (a) /clear in non-pinned mode clears the screen when stream.isatty() is True,
              even if color is disabled (e.g. NO_COLOR=1).
          (b) MAX_HISTORY_BYTES (1 MB) calculates memory based on UTF-8 encoded bytes,
              correctly measuring multi-byte Unicode characters (Sinhala).
        """
        # (a) Unpinned /clear with isatty()=True and NO_COLOR=1
        tty_no_color_stream = DummyStream(encoding="utf-8", is_tty=True)
        inputs = iter(["/clear", "/exit"])
        outputs: list[str] = []

        with patch.dict(os.environ, {"NO_COLOR": "1"}), \
             patch("shell.should_pin_header", return_value=False), \
             patch("pai.enforce_sandbox_boundary"):
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
                stream=tty_no_color_stream,
            )
            self.assertEqual(code, 0)
            raw = tty_no_color_stream.getvalue()
            # Must emit screen clear escape even though NO_COLOR is set
            self.assertIn("\033[2J\033[1;1H", raw)

        # (b) Multi-byte UTF-8 calculation in session history
        clear_session_history()
        # Sinhala string: each character is 3 bytes in UTF-8
        sinhala_cmd = "නාමය_විමසුම"
        sinhala_bytes = len(sinhala_cmd.encode("utf-8"))
        sinhala_chars = len(sinhala_cmd)
        self.assertGreater(sinhala_bytes, sinhala_chars)

        # Two entries each with 200,000 Sinhala chars:
        # 200,000 * 3 bytes = 600,000 bytes each.
        # Under old character-counting: 200,000 + 200,000 = 400,000 chars <= 1,000,000 limit,
        # so both entries would be kept incorrectly.
        # Under UTF-8 encoded byte counting: 600,000 + 600,000 = 1,200,000 bytes > 1,000,000 limit,
        # so the older entry MUST be evicted to stay within the 1 MB budget.
        entry1_payload = "ප" * 200_000
        entry2_payload = "ර" * 200_000
        add_to_session_history("cmd1", entry1_payload)
        self.assertEqual(len(get_session_history()), 1)

        add_to_session_history("cmd2", entry2_payload)
        # Old entry must be evicted because 1.2 MB > 1 MB
        history_after = get_session_history()
        self.assertEqual(len(history_after), 1)
        self.assertEqual(history_after[0][1], "cmd2")

        # Total UTF-8 encoded bytes must stay <= MAX_HISTORY_BYTES
        total_encoded = sum(
            len(c.encode("utf-8")) + len(o.encode("utf-8"))
            for _, c, o in history_after
        )
        self.assertLessEqual(total_encoded, MAX_HISTORY_BYTES)

    # -------------------------------------------------------------------------
    # 29. Finding FP: Version Discovery from Install Root Manifest & Source Fallback
    # -------------------------------------------------------------------------
    def test_shell_finding_fp_manifest_version_installed(self) -> None:
        """
        Finding FP:
          - Installed environment: header version comes from manifest.json at install root.
          - When manifest.json contains {"version": "1.1.0-rc2"}, header shows '1.1.0-rc2'.
          - Discovery is module-relative: parent of research/ directory.
        """
        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td)
            manifest = temp_root / "manifest.json"
            manifest.write_text(json.dumps({"version": "1.1.0-rc2"}), encoding="utf-8")

            # Direct install_root call
            ver = get_install_root_version(temp_root)
            self.assertEqual(ver, "1.1.0-rc2")
            info = get_shell_info_line(80, color_enabled=False, install_root=temp_root)
            self.assertIn("1.1.0-rc2", info)
            self.assertIn("PAI 1.1.0-rc2", info)

            # Module-relative discovery via shell.__file__ resolution
            mock_file = str(temp_root / "research" / "shell.py")
            with patch.object(shell, "__file__", mock_file):
                self.assertEqual(get_install_root_version(), "1.1.0-rc2")
                header_lines = get_pinned_header_lines(80, color_enabled=False)
                self.assertIn("1.1.0-rc2", header_lines[3])
                self.assertIn("PAI 1.1.0-rc2", header_lines[3])

    def test_shell_finding_fp_manifest_missing_source_checkout(self) -> None:
        """
        Finding FP:
          - Missing manifest / source checkout: header shows 'dev'.
        """
        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td)
            ver = get_install_root_version(temp_root)
            self.assertEqual(ver, "dev")
            info = get_shell_info_line(80, color_enabled=False, install_root=temp_root)
            self.assertIn("dev", info)
            self.assertIn("PAI dev", info)

            mock_file = str(temp_root / "research" / "shell.py")
            with patch.object(shell, "__file__", mock_file):
                self.assertEqual(get_install_root_version(), "dev")
                header_lines = get_pinned_header_lines(80, color_enabled=False)
                self.assertIn("dev", header_lines[3])
                self.assertIn("PAI dev", header_lines[3])

        # Current source repository has no manifest.json at repo root -> must return 'dev'
        self.assertEqual(get_install_root_version(), "dev")
        current_header = get_pinned_header_lines(80, color_enabled=False)
        self.assertIn("PAI dev", current_header[3])

    def test_shell_finding_fp_manifest_malformed(self) -> None:
        """
        Finding FP:
          - Malformed manifest (syntax error, non-dict, missing version, non-string, whitespace) -> fails safe to 'dev'.
        """
        malformed_cases = [
            "{invalid-json-content",
            "[]",
            json.dumps({"name": "pai"}),
            json.dumps({"version": 110}),
            json.dumps({"version": "   "}),
            json.dumps({"version": None}),
        ]
        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td)
            manifest = temp_root / "manifest.json"
            for payload in malformed_cases:
                manifest.write_text(payload, encoding="utf-8")
                ver = get_install_root_version(temp_root)
                self.assertEqual(ver, "dev", f"Failed to fallback to 'dev' for payload: {payload}")
                info = get_shell_info_line(80, color_enabled=False, install_root=temp_root)
                self.assertIn("PAI dev", info)

    def test_shell_finding_fp_no_v110_literal_in_research_grep(self) -> None:
        """
        Finding FP:
          - Asserts that no hardcoded version string literal exists anywhere in research/.
          - Preserves invariant: pinned research tree must not change between rc and final release.
        """
        forbidden = "".join(["v", "1", ".", "1", ".", "0"])
        matches = []
        for root, dirs, files in os.walk(RESEARCH_DIR):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
            for fname in files:
                if fname.endswith((".pyc", ".pyo")):
                    continue
                fpath = Path(root) / fname
                try:
                    text = fpath.read_text(encoding="utf-8", errors="ignore")
                    if forbidden in text:
                        matches.append(str(fpath.relative_to(RESEARCH_DIR)))
                except Exception:
                    pass
        self.assertEqual(matches, [], f"Forbidden literal '{forbidden}' found in research/ files: {matches}")

    def test_shell_save_command_extracted_code_and_text(self) -> None:
        """Asserts /save extracts fenced code and writes files with directory creation."""
        from shell import save_session_output_to_file, clear_session_history, add_to_session_history

        clear_session_history()
        # Case A: Empty history
        ok, msg = save_session_output_to_file("test.txt")
        self.assertFalse(ok)
        self.assertIn("No previous output", msg)

        # Case B: History with fenced code
        with tempfile.TemporaryDirectory() as td:
            target_p = Path(td) / "subdir" / "output.py"
            add_to_session_history(
                "write a python func",
                "Here is the function:\n```python\ndef greet():\n    return 'hello'\n```\nHope this helps!"
            )
            ok, msg = save_session_output_to_file(str(target_p))
            self.assertTrue(ok)
            self.assertTrue(target_p.is_file())
            content = target_p.read_text(encoding="utf-8")
            self.assertEqual(content, "def greet():\n    return 'hello'")
        clear_session_history()

    def test_shell_cmd_and_run_command_execution(self) -> None:
        """Asserts /cmd and /run parse correctly and execute shell commands."""
        action, argv = parse_shell_line('/cmd echo "test_output"')
        self.assertEqual(action, "cmd")
        self.assertEqual(argv, ['echo "test_output"'])

        action, argv = parse_shell_line('/run dir')
        self.assertEqual(action, "cmd")
        self.assertEqual(argv, ['dir'])

        action, argv = parse_shell_line('/cmd')
        self.assertEqual(action, "error")

    def test_shell_wifi_command_and_format(self) -> None:
        """Asserts /wifi parses and format_wifi_report displays table with signals."""
        from shell import format_wifi_report

        action, argv = parse_shell_line("/wifi")
        self.assertEqual(action, "wifi")
        self.assertEqual(argv, [])

        # Formatting with sample networks
        sample = [
            {"ssid": "Home-Network", "signals": ["85%"], "band": "5 GHz", "auth": "WPA2-Personal"},
            {"ssid": "Office-Guest", "signals": ["45%"], "band": "2.4 GHz", "auth": "Open"},
        ]
        rep = format_wifi_report(sample, color_enabled=False)
        self.assertIn("Home-Network", rep)
        self.assertIn("85%", rep)
        self.assertIn("Office-Guest", rep)

    def test_shell_code_auto_out_default(self) -> None:
        """Asserts /code in interactive shell supplies --out pai_output when omitted."""
        executed_cmds: list[list[str]] = []
        inputs = iter(['/code "generate factorial"', '/exit'])
        outputs: list[str] = []

        with patch("shell.execute_subcommand", side_effect=lambda a: executed_cmds.append(a) or 0), \
             patch("pai.enforce_sandbox_boundary"):
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
                stream=io.StringIO(),
            )
            self.assertEqual(code, 0)

        self.assertEqual(len(executed_cmds), 1)
        self.assertIn("--out", executed_cmds[0])
        self.assertIn("pai_output", executed_cmds[0])

    def test_shell_smart_folder_save(self) -> None:
        """Asserts /save to directory targets automatically chooses smart filename."""
        from shell import save_session_output_to_file, clear_session_history, add_to_session_history

        clear_session_history()
        with tempfile.TemporaryDirectory() as td:
            temp_dir = Path(td)
            # HTML content auto-saves as game.html or index.html
            add_to_session_history(
                "create 3d web game",
                "Here is your game:\n```html\n<!DOCTYPE html><html><body><canvas></canvas></body></html>\n```"
            )
            ok, msg = save_session_output_to_file(str(temp_dir))
            self.assertTrue(ok)
            self.assertTrue((temp_dir / "game.html").is_file())
            self.assertIn("game.html", msg)

            # Python content auto-saves as app.py
            add_to_session_history(
                "create python script",
                "Here is python:\n```python\ndef solve(): pass\n```"
            )
            ok2, msg2 = save_session_output_to_file(str(temp_dir))
            self.assertTrue(ok2)
            self.assertTrue((temp_dir / "app.py").is_file())
            self.assertIn("app.py", msg2)

            # Backwards search in history when intervening status commands exist
            target_sub = temp_dir / "dron_sub"
            target_sub.mkdir(parents=True, exist_ok=True)
            add_to_session_history(
                "create 3d drone game",
                "Here is the game:\n```html\n<!DOCTYPE html><html><body><h1>Drone Simulator</h1><script src=\"three.min.js\"></script></body></html>\n```"
            )
            add_to_session_history(
                "create folder in downloads name it as dron simulator",
                "[Successfully initialized new project in Downloads\\dron simulator]"
            )
            ok_bw, msg_bw = save_session_output_to_file(str(target_sub))
            self.assertTrue(ok_bw)
            saved_file = target_sub / "game.html" if (target_sub / "game.html").is_file() else target_sub / "index.html"
            self.assertTrue(saved_file.is_file())
            self.assertIn("Drone Simulator", saved_file.read_text(encoding="utf-8"))

        # Natural language save intent parsing
        from shell import parse_shell_line
        act_s1, args_s1 = parse_shell_line("save that game in dron simulator folder in downloads")
        self.assertEqual(act_s1, "save")
        self.assertIn("dron simulator", args_s1[0].lower())

        act_s2, args_s2 = parse_shell_line("save this `Downloads/dron simulator` folder.")
        self.assertEqual(act_s2, "save")
        self.assertIn("dron simulator", args_s2[0].lower())

        act_s3, args_s3 = parse_shell_line("save it")
        self.assertEqual(act_s3, "save")

        act_s4, args_s4 = parse_shell_line("downloads eke dron simulator folder eke save karanna")
        self.assertEqual(act_s4, "save")
        self.assertIn("dron simulator", args_s4[0].lower())
        clear_session_history()

    def test_shell_terminal_title_and_compact_prompt(self) -> None:
        """Asserts set_terminal_title emits OSC 0 and compact prompt header contains PAI and model."""
        from shell import set_terminal_title, get_compact_prompt_header

        stream = DummyStream()
        set_terminal_title("Test Title", stream=stream)
        self.assertIn("\033]0;Test Title\007", stream.getvalue())

        hdr = get_compact_prompt_header(color_enabled=False)
        self.assertIn("PAI", hdr)
        self.assertIn("Hirusha Suhan", hdr)
        self.assertIn("┌──[", hdr)

    def test_shell_multiturn_chat_memory(self) -> None:
        """Asserts multi-turn chat in shell tracks turns and injects PAI_CHAT_HISTORY env var."""
        from shell import _session_chat_turns
        _session_chat_turns.clear()

        executed_cmds: list[list[str]] = []
        captured_history_envs: list[Optional[str]] = []
        inputs = iter(["first question", "second follow-up", "/exit"])
        outputs: list[str] = []

        def mock_exec(argv):
            executed_cmds.append(list(argv))
            captured_history_envs.append(os.environ.get("PAI_CHAT_HISTORY"))
            return 0

        with patch("shell.execute_subcommand", side_effect=mock_exec), \
             patch("pai.enforce_sandbox_boundary"):
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
                stream=io.StringIO(),
            )
            self.assertEqual(code, 0)

        # First chat call had no PAI_CHAT_HISTORY
        self.assertIsNone(captured_history_envs[0])
        # Second chat call had PAI_CHAT_HISTORY injected with first turn
        self.assertIsNotNone(captured_history_envs[1])
        self.assertIn("first question", captured_history_envs[1])
        # After shell exits, PAI_CHAT_HISTORY is cleaned up
        self.assertNotIn("PAI_CHAT_HISTORY", os.environ)
        _session_chat_turns.clear()

    def test_shell_resolve_target_file_and_edit_file(self) -> None:
        """Asserts resolve_target_file and edit_target_file correctly update file and create backup."""
        from shell import resolve_target_file, edit_target_file

        with tempfile.TemporaryDirectory() as td:
            temp_dir = Path(td)
            test_file = temp_dir / "game.html"
            test_file.write_text("<html><body>Original Game</body></html>", encoding="utf-8")

            # 1. resolve_target_file
            resolved = resolve_target_file(str(test_file))
            self.assertIsNotNone(resolved)
            self.assertEqual(resolved, test_file.resolve())

            non_existent = resolve_target_file(str(temp_dir / "does_not_exist.html"))
            self.assertIsNone(non_existent)

            # 2. edit_target_file with mock executor
            def mock_executor(argv):
                prompt = argv[-1]
                self.assertIn("Original Game", prompt)
                self.assertIn("add score counter", prompt)
                print("```html\n<html><body>Updated Game with Score</body></html>\n```")
                return 0

            ok, msg, updated = edit_target_file(
                str(test_file),
                "add score counter",
                stream=io.StringIO(),
                executor=mock_executor,
            )
            self.assertTrue(ok)
            self.assertIn("Successfully updated", msg)
            self.assertIn("Backup saved to", msg)

            # File updated
            self.assertEqual(test_file.read_text(encoding="utf-8"), "<html><body>Updated Game with Score</body></html>")
            # Backup exists
            bak_file = test_file.with_suffix(".html.bak")
            self.assertTrue(bak_file.is_file())
            self.assertEqual(bak_file.read_text(encoding="utf-8"), "<html><body>Original Game</body></html>")

    def test_shell_edit_parsing_and_repl_execution(self) -> None:
        """Asserts /edit, edit, and natural language file editing parse and execute in REPL."""
        from shell import parse_shell_line, _session_chat_turns
        _session_chat_turns.clear()

        # Parsing checks
        act1, args1 = parse_shell_line("/edit Downloads\\game.html add score")
        self.assertEqual(act1, "edit")
        self.assertEqual(args1[0], "Downloads\\game.html")
        self.assertEqual(args1[1], "add score")

        act2, args2 = parse_shell_line('edit "C:\\My Games\\game.html" add restart button')
        self.assertEqual(act2, "edit")
        self.assertEqual(args2[0], "C:\\My Games\\game.html")
        self.assertEqual(args2[1], "add restart button")

        act_err, args_err = parse_shell_line("/edit")
        self.assertEqual(act_err, "error")

        act_err2, args_err2 = parse_shell_line("/edit game.html")
        self.assertEqual(act_err2, "error")

        with tempfile.TemporaryDirectory() as td:
            temp_dir = Path(td)
            app_file = temp_dir / "app.py"
            app_file.write_text("print('hello')", encoding="utf-8")

            # Natural language line referencing existing file with 'wenas'
            act_nat, args_nat = parse_shell_line(f"{app_file} eka wenas karanna print goodbye danna")
            self.assertEqual(act_nat, "edit")
            self.assertEqual(args_nat[0], str(app_file.resolve()))

            # REPL execution with /edit
            inputs = iter([f"/edit {app_file} change to goodbye", "/exit"])
            outputs: list[str] = []

            def mock_exec(argv):
                print("```python\nprint('goodbye')\n```")
                return 0

            with patch("shell.execute_subcommand", side_effect=mock_exec), \
                 patch("pai.enforce_sandbox_boundary"):
                code = run_interactive_shell(
                    input_fn=lambda _: next(inputs),
                    output_fn=outputs.append,
                    stream=io.StringIO(),
                )
                self.assertEqual(code, 0)

            self.assertEqual(app_file.read_text(encoding="utf-8"), "print('goodbye')")
            self.assertTrue(app_file.with_suffix(".py.bak").is_file())
            combined = "\n".join(outputs)
            self.assertIn("Successfully updated", combined)
        _session_chat_turns.clear()

    def test_shell_model_switching(self) -> None:
        """Asserts model listing, resolving, switching, and REPL argv injection."""
        from shell import (
            get_available_models,
            resolve_model_name,
            switch_active_model,
            format_models_list,
            parse_shell_line,
        )

        avail = get_available_models()
        self.assertGreater(len(avail), 0)

        # 1. Resolving
        first = avail[0]
        res_exact = resolve_model_name(first)
        self.assertEqual(res_exact, first)

        prefix = first.split(":")[0]
        res_prefix = resolve_model_name(prefix)
        self.assertIsNotNone(res_prefix)

        # 2. Switch
        dummy_stream = DummyStream()
        ok, msg = switch_active_model(first, stream=dummy_stream)
        self.assertTrue(ok)
        self.assertIn(first, msg)
        self.assertEqual(os.environ.get("PAI_ACTIVE_MODEL"), first)

        # 3. Formatting
        formatted = format_models_list(color_enabled=False)
        self.assertIn("=== Available Local Models ===", formatted)
        self.assertIn(first, formatted)

        # 4. Parsing
        act_ls, _ = parse_shell_line("/model")
        self.assertEqual(act_ls, "model_list")

        act_sw, args_sw = parse_shell_line(f"/model {first}")
        self.assertEqual(act_sw, "model_switch")
        self.assertEqual(args_sw[0], first)

        act_nat, args_nat = parse_shell_line(f"change model to {first}")
        self.assertEqual(act_nat, "model_switch")

        act_sin, args_sin = parse_shell_line(f"model eka change karanna {first} ekata")
        self.assertEqual(act_sin, "model_switch")

        # REPL execution with model switch and auto-injection into chat
        executed_argvs: list[list[str]] = []
        inputs = iter([f"/model {first}", "hello test", "/exit"])
        outputs: list[str] = []

        def mock_exec(argv):
            executed_argvs.append(list(argv))
            return 0

        with patch("shell.execute_subcommand", side_effect=mock_exec), \
             patch("pai.enforce_sandbox_boundary"):
            code = run_interactive_shell(
                input_fn=lambda _: next(inputs),
                output_fn=outputs.append,
                stream=io.StringIO(),
            )
            self.assertEqual(code, 0)

        self.assertTrue(any("--model" in cmd and first in cmd for cmd in executed_argvs))
        # Ensure --model is placed before the '--' sentinel so argparse parses it as a valid flag
        matching_cmd = next((cmd for cmd in executed_argvs if "--model" in cmd and first in cmd), None)
        self.assertIsNotNone(matching_cmd)
        if "--" in matching_cmd:
            self.assertLess(matching_cmd.index("--model"), matching_cmd.index("--"))

        from pai import build_parser
        parser = build_parser()
        for cmd in executed_argvs:
            parsed = parser.parse_args(cmd)
            self.assertEqual(parsed.model, first)

    def test_shell_project_scaffold(self) -> None:
        """Asserts create_project_scaffold generates web, 3d, and python project files."""
        from shell import create_project_scaffold, parse_shell_line

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            web_dir = base / "my_web_game"
            ok_w, msg_w, files_w = create_project_scaffold(str(web_dir), "web game")
            self.assertTrue(ok_w)
            self.assertIn("index.html", files_w)
            self.assertIn("style.css", files_w)
            self.assertIn("script.js", files_w)
            self.assertTrue((web_dir / "index.html").is_file())

            # 3D Three.js game scaffold
            three_dir = base / "my_3d_game"
            ok_3d, msg_3d, files_3d = create_project_scaffold(str(three_dir), "create 3d web game with threejs")
            self.assertTrue(ok_3d)
            self.assertIn("index.html", files_3d)
            index_content = (three_dir / "index.html").read_text(encoding="utf-8")
            self.assertIn("three.min.js", index_content)
            script_content = (three_dir / "script.js").read_text(encoding="utf-8")
            self.assertIn("THREE.Scene", script_content)

            py_dir = base / "my_python_app"
            ok_p, msg_p, files_p = create_project_scaffold(str(py_dir), "python script")
            self.assertTrue(ok_p)
            self.assertIn("main.py", files_p)
            self.assertIn("requirements.txt", files_p)
            self.assertTrue((py_dir / "main.py").is_file())

            # Realistic 3D military drone shooting game scaffold
            drone_dir = base / "game_test_1"
            ok_dr, msg_dr, files_dr = create_project_scaffold(str(drone_dir), "create realistic military dron shooting game")
            self.assertTrue(ok_dr)
            self.assertIn("index.html", files_dr)
            self.assertIn("style.css", files_dr)
            self.assertIn("script.js", files_dr)
            self.assertIn("README.md", files_dr)
            drone_index = (drone_dir / "index.html").read_text(encoding="utf-8")
            self.assertIn("MQ-9 REAPER", drone_index)
            self.assertIn("Realistic Military Drone Shooter 3D", drone_index)
            drone_script = (drone_dir / "script.js").read_text(encoding="utf-8")
            self.assertIn("playLaser", drone_script)
            self.assertIn("droneBody", drone_script)
            self.assertIn("rotors", drone_script)

        # Parsing checks
        act_proj, args_proj = parse_shell_line("/project test_app web")
        self.assertEqual(act_proj, "project")
        self.assertEqual(args_proj[0], "test_app")

        act_fld, args_fld = parse_shell_line("/folder my_custom_folder")
        self.assertEqual(act_fld, "project")

        act_mk, args_mk = parse_shell_line("/mkdir test_dir")
        self.assertEqual(act_mk, "project")

        act_nat, args_nat = parse_shell_line("methana folder ekak hadala aluth project ekak patan ganna my_game")
        self.assertEqual(act_nat, "project")

        # Natural language folder creation in Downloads
        act_dl, args_dl = parse_shell_line("create folder in downloads name it as my game")
        self.assertEqual(act_dl, "project")
        self.assertIn("my game", args_dl[0].lower())
        self.assertIn("downloads", args_dl[0].lower())

        act_dl2, args_dl2 = parse_shell_line("make folder in downloads called my game")
        self.assertEqual(act_dl2, "project")
        self.assertIn("my game", args_dl2[0].lower())

        act_dl3, args_dl3 = parse_shell_line("downloads eke my game kiyala folder ekak hadanna")
        self.assertEqual(act_dl3, "project")
        self.assertIn("my game", args_dl3[0].lower())

        # Compound prompt with folder name and project prompt
        act_cp, args_cp = parse_shell_line("create folder in downloads name it as my game and create drone shooting game using three js")
        self.assertEqual(act_cp, "project")
        self.assertTrue(args_cp[0].lower().endswith("my game"))
        self.assertNotIn("and create", args_cp[0].lower())

        # Typo tolerance: 'name it ad game test 1' with trailing 'and save it on that folder'
        act_ad, args_ad = parse_shell_line("create folder in downloads name it ad game test 1 and create realistic military dron shooting game and save it on that folder")
        self.assertEqual(act_ad, "project")
        self.assertTrue(args_ad[0].lower().endswith("game test 1"))
        self.assertNotIn("save", args_ad[0].lower())

        # Creation prompt with trailing 'and save it on that folder' must route to chat, not save
        act_cr, args_cr = parse_shell_line("create create realistic military dron shooting game and save it on that folder")
        self.assertEqual(act_cr, "chat")
        self.assertIn("create realistic military", args_cr[-1].lower())

    def test_shell_bug_analysis_and_fix(self) -> None:
        """Asserts analyze_and_fix_bugs finds issues, creates backup, and writes fixed code."""
        from shell import analyze_and_fix_bugs, parse_shell_line

        with tempfile.TemporaryDirectory() as td:
            temp_dir = Path(td)
            buggy_file = temp_dir / "calc.py"
            buggy_file.write_text("def add(a, b):\n    return a - b  # BUG: subtracts instead of adds\n", encoding="utf-8")

            def mock_debugger(argv):
                prompt = argv[-1]
                self.assertIn("calc.py", prompt)
                print("Found bug: subtraction operator used instead of addition.\n```python\ndef add(a, b):\n    return a + b\n```")
                return 0

            ok, report, fixed = analyze_and_fix_bugs(
                str(buggy_file),
                "fix math logic",
                stream=io.StringIO(),
                executor=mock_debugger,
            )
            self.assertTrue(ok)
            self.assertEqual(len(fixed), 1)
            self.assertIn("add(a, b):", buggy_file.read_text(encoding="utf-8"))
            self.assertIn("return a + b", buggy_file.read_text(encoding="utf-8"))
            self.assertTrue(buggy_file.with_suffix(".py.bak").is_file())

        # Parsing checks
        act_fix, args_fix = parse_shell_line("/fix Downloads\\game.html fix score")
        self.assertEqual(act_fix, "fix")
        self.assertEqual(args_fix[0], "Downloads\\game.html")

        act_nat, args_nat = parse_shell_line("game.html eke bugs thiyenam hadanna")
        self.assertEqual(act_nat, "fix")

    def test_shell_browser_integration(self) -> None:
        """Asserts open_in_browser opens URLs, files, auto-detects index.html, and handles errors."""
        from shell import open_in_browser, parse_shell_line

        with patch("webbrowser.open", return_value=True) as mock_wb:
            # 1. URL opening
            ok, msg = open_in_browser("http://localhost:8080/index.html")
            self.assertTrue(ok)
            self.assertIn("Opened URL", msg)
            mock_wb.assert_called_with("http://localhost:8080/index.html")

            # 2. File opening
            with tempfile.TemporaryDirectory() as td:
                temp_dir = Path(td)
                test_html = temp_dir / "game.html"
                test_html.write_text("<h1>3D Game</h1>", encoding="utf-8")

                ok_f, msg_f = open_in_browser(str(test_html))
                self.assertTrue(ok_f)
                self.assertIn("game.html", msg_f)
                self.assertTrue(mock_wb.called)

            # 3. Nonexistent file
            ok_missing, msg_missing = open_in_browser("nonexistent_page_12345.html")
            self.assertFalse(ok_missing)
            self.assertIn("not found", msg_missing.lower())

        # 4. Command parsing
        act, argv = parse_shell_line("/open Downloads\\game.html")
        self.assertEqual(act, "browser_open")
        self.assertEqual(argv[0], "Downloads\\game.html")

        act_prev, argv_prev = parse_shell_line("/preview index.html")
        self.assertEqual(act_prev, "browser_open")
        self.assertEqual(argv_prev[0], "index.html")

        act_nat, argv_nat = parse_shell_line("game.html browser eke open karanna")
        self.assertEqual(act_nat, "browser_open")

        act_nat2, argv_nat2 = parse_shell_line("preview in browser index.html")
        self.assertEqual(act_nat2, "browser_open")

    def test_shell_skills_system(self) -> None:
        """Asserts starter skills seeding, listing, getting, saving, deleting, and matching."""
        from shell import (
            ensure_starter_skills,
            list_skills,
            get_skill,
            save_skill,
            delete_skill,
            find_matching_skills,
            format_skills_list,
            format_skill_detail,
            parse_shell_line,
        )

        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"PAI_SKILLS_DIR": td}):
                # 1. Seeding starter skills
                ensure_starter_skills()
                skills = list_skills()
                self.assertGreaterEqual(len(skills), 4)
                names = [s["name"] for s in skills]
                self.assertIn("web-3d-threejs", names)
                self.assertIn("bug-fixer", names)
                self.assertIn("web-app-scaffold", names)
                self.assertIn("python-automation", names)

                # 2. Get specific skill
                s_three = get_skill("web-3d-threejs")
                self.assertIsNotNone(s_three)
                self.assertEqual(s_three["name"], "web-3d-threejs")

                # 3. Find matching skills
                matches_3d = find_matching_skills("create a 3d web game with treejs")
                self.assertGreater(len(matches_3d), 0)
                self.assertEqual(matches_3d[0]["name"], "web-3d-threejs")

                matches_bug = find_matching_skills("fix this bug in script.py")
                self.assertGreater(len(matches_bug), 0)
                self.assertEqual(matches_bug[0]["name"], "bug-fixer")

                # 4. Save custom skill
                ok_s, msg_s = save_skill(
                    name="dark-mode-game",
                    description="Dark theme styling and neon graphics for canvas games",
                    guidance="Always use #121212 background and neon green #00ff88 accents.",
                )
                self.assertTrue(ok_s)
                self.assertIn("dark-mode-game", msg_s)

                s_custom = get_skill("dark-mode-game")
                self.assertIsNotNone(s_custom)
                self.assertIn("neon", s_custom["guidance"])

                matches_dark = find_matching_skills("game with neon accents")
                self.assertTrue(any(m["name"] == "dark-mode-game" for m in matches_dark))

                # 5. Format list and detail
                ls_fmt = format_skills_list(color_enabled=False)
                self.assertIn("web-3d-threejs", ls_fmt)
                self.assertIn("dark-mode-game", ls_fmt)

                det_fmt = format_skill_detail(s_custom, color_enabled=False)
                self.assertIn("Skill: dark-mode-game", det_fmt)
                self.assertIn("neon green", det_fmt)

                # 6. Delete skill
                ok_del, msg_del = delete_skill("dark-mode-game")
                self.assertTrue(ok_del)
                self.assertIsNone(get_skill("dark-mode-game"))

        # 7. Parsing checks
        act_ls, _ = parse_shell_line("/skills")
        self.assertEqual(act_ls, "skills_list")

        act_sh, args_sh = parse_shell_line("/skill web-3d-threejs")
        self.assertEqual(act_sh, "skill_show")
        self.assertEqual(args_sh[0], "web-3d-threejs")

        act_lrn, args_lrn = parse_shell_line("/learn my-skill Focus on unit testing and clean code")
        self.assertEqual(act_lrn, "skill_learn")
        self.assertEqual(args_lrn[0], "my-skill")

        act_fgt, args_fgt = parse_shell_line("/forget my-skill")
        self.assertEqual(act_fgt, "skill_delete")
        self.assertEqual(args_fgt[0], "my-skill")

        act_nat_ls, _ = parse_shell_line("skills monawada thiyenne")
        self.assertEqual(act_nat_ls, "skills_list")

        act_nat_lrn, args_nat_lrn = parse_shell_line("skill ekak hadanna clean-code Always write unit tests first")
        self.assertEqual(act_nat_lrn, "skill_learn")

    def test_shell_repl_browser_and_skills_dispatch(self) -> None:
        """Asserts REPL executes browser_open, skills commands, and injects PAI_SKILL_HINTS into chat."""
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"PAI_SKILLS_DIR": td}):
                captured_skill_hints: list[str] = []

                def mock_exec(argv):
                    if os.environ.get("PAI_SKILL_HINTS"):
                        captured_skill_hints.append(os.environ["PAI_SKILL_HINTS"])
                    print("Model response: Completed task successfully.")
                    return 0

                inputs = iter([
                    "/skills",
                    "/learn canvas-art Use HTML5 canvas 2D rendering context",
                    "/skill canvas-art",
                    "make a 3d game using threejs",
                    "/open test.html",
                    "/exit",
                ])
                outputs: list[str] = []

                with patch("shell.execute_subcommand", side_effect=mock_exec), \
                     patch("webbrowser.open", return_value=True), \
                     patch("pai.enforce_sandbox_boundary"):
                    code = run_interactive_shell(
                        input_fn=lambda _: next(inputs),
                        output_fn=outputs.append,
                        stream=io.StringIO(),
                    )
                    self.assertEqual(code, 0)

                combined = "\n".join(outputs)
                self.assertIn("Agentic Skills Library", combined)
                self.assertIn("successfully learned", combined)
                self.assertIn("Skill: canvas-art", combined)
                self.assertIn("Active Skill Applied: web-3d-threejs", combined)
                self.assertGreater(len(captured_skill_hints), 0)
                self.assertIn("web-3d-threejs", captured_skill_hints[0])

    def test_active_project_tracking_and_natural_file_modification(self) -> None:
        """Asserts active project tracking, status formatting, and natural file editing on project files."""
        from shell import (
            get_active_project_dir,
            set_active_project_dir,
            format_project_status,
            resolve_target_file,
            parse_shell_line,
            run_interactive_shell,
            _session_chat_turns,
        )
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            proj_dir = Path(td) / "drone_game"
            proj_dir.mkdir(parents=True, exist_ok=True)
            script_f = proj_dir / "script.js"
            index_f = proj_dir / "index.html"
            script_f.write_text("let speed = 5;\nfunction update() { speed += 1; }", encoding="utf-8")
            index_f.write_text("<!DOCTYPE html><html><body><h1>Drone</h1></body></html>", encoding="utf-8")

            # Test project dir set & get
            set_active_project_dir(proj_dir)
            self.assertEqual(get_active_project_dir(), proj_dir.resolve())

            # Test format_project_status
            status_text = format_project_status(proj_dir)
            self.assertIn("Active Project", status_text)
            self.assertIn("script.js", status_text)
            self.assertIn("index.html", status_text)

            # Test resolve_target_file checks active project first
            resolved_js = resolve_target_file("script.js")
            self.assertIsNotNone(resolved_js)
            self.assertEqual(resolved_js, script_f.resolve())

            # Test parse_shell_line project_status
            act, args = parse_shell_line("/project")
            self.assertEqual(act, "project_status")

            # Test natural modification commands route directly to edit target in active project
            act_nat, args_nat = parse_shell_line("game eke speed eka wedi karanna")
            self.assertEqual(act_nat, "edit")
            self.assertEqual(args_nat[0], str(script_f.resolve()))
            self.assertEqual(args_nat[1], "game eke speed eka wedi karanna")

            act_nat2, args_nat2 = parse_shell_line("make drone faster and add realistic physics")
            self.assertEqual(act_nat2, "edit")
            self.assertEqual(args_nat2[0], str(script_f.resolve()))

            # Test /open with no argument defaults to opening index.html in active project
            act_open, args_open = parse_shell_line("/open")
            self.assertEqual(act_open, "browser_open")

            # Test execution in interactive shell
            def mock_exec_sub(argv):
                # When edit prompt is sent to chat, return updated javascript block
                print("```javascript\nlet speed = 25;\nfunction update() { speed += 5; }\n```")
                return 0

            inputs = iter([
                "/project",
                "game eke speed eka wedi karanna",
                "/open",
                "/exit",
            ])
            outputs: list[str] = []
            with patch("shell.execute_subcommand", side_effect=mock_exec_sub), \
                 patch("webbrowser.open", return_value=True), \
                 patch("pai.enforce_sandbox_boundary"):
                code = run_interactive_shell(
                    input_fn=lambda _: next(inputs),
                    output_fn=outputs.append,
                    stream=io.StringIO(),
                )
                self.assertEqual(code, 0)

            # Verify file was updated on disk and backup created
            updated_code = script_f.read_text(encoding="utf-8")
            self.assertIn("speed = 25", updated_code)
            bak_file = script_f.with_suffix(".js.bak")
            self.assertTrue(bak_file.is_file())
            self.assertIn("speed = 5", bak_file.read_text(encoding="utf-8"))

            combined_out = "\n".join(outputs)
            self.assertIn("Active Project", combined_out)
            self.assertIn("Successfully updated", combined_out)
            self.assertIn("Tip: Refresh index.html", combined_out)

    def test_mcp_graphql_multiagent_and_cctv_drone_modification(self) -> None:
        """Asserts natural language CCTV drone modification, MCP hub, GraphQL engine, and multi-agent collaboration."""
        from shell import (
            get_active_project_dir,
            set_active_project_dir,
            parse_shell_line,
            run_interactive_shell,
            _session_chat_turns,
        )
        from mcp_client import MCPRegistry
        from graphql_agent import GraphQLClient
        from capabilities import create_agent_capability_broker, Risk
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            proj_dir = Path(td) / "game_test_2"
            proj_dir.mkdir(parents=True, exist_ok=True)
            script_f = proj_dir / "script.js"
            index_f = proj_dir / "index.html"
            script_f.write_text("// initial drone script\nlet speed = 5;", encoding="utf-8")
            index_f.write_text("<!DOCTYPE html><html><body><canvas></canvas></body></html>", encoding="utf-8")
            set_active_project_dir(proj_dir)

            # 1. Exact user prompt parsing check
            user_instruction = (
                "Add more textures to this. The drone doesn't need to be visible. "
                "Make it so it can fire missiles, bullets, and Hellfire missiles from above at the "
                "people walking below and the battle tanks, in black and white, exactly like looking through a CCTV camera."
            )
            act_cctv, args_cctv = parse_shell_line(user_instruction)
            self.assertEqual(act_cctv, "edit")
            self.assertEqual(args_cctv[0], str(script_f.resolve()))
            self.assertIn("CCTV camera", args_cctv[1])

            # 2. Test slash commands for agent, mcp, and graphql
            act_agent, args_agent = parse_shell_line("/agent Build autonomous drone surveillance")
            self.assertEqual(act_agent, "multi_agent")
            self.assertIn("surveillance", args_agent[0])

            act_mcp, args_mcp = parse_shell_line("/mcp status")
            self.assertEqual(act_mcp, "mcp_hub")

            act_gql, args_gql = parse_shell_line("/graphql introspect")
            self.assertEqual(act_gql, "graphql_cmd")
            self.assertEqual(args_gql[0], "introspect")

            # 3. Test GraphQL client validator and Capability Broker
            val_ok, val_err = GraphQLClient.validate_query("query { drone { id speed } }")
            self.assertTrue(val_ok)
            self.assertIsNone(val_err)

            inv_ok, inv_err = GraphQLClient.validate_query("query { unclosed")
            self.assertFalse(inv_ok)
            self.assertIsNotNone(inv_err)

            broker = create_agent_capability_broker()
            self.assertIn("execute_graphql", broker._tools)
            self.assertEqual(broker._tools["execute_graphql"].risk, Risk.NETWORK_OUT)

            # 4. Test REPL execution of CCTV drone modification with multi-file code update
            def mock_exec_cctv(argv):
                # Simulated model response outputting both index.html and script.js with CCTV features
                print("""### Files to Update:
#### 1. index.html
```html
<!DOCTYPE html>
<html>
<head><title>CCTV Drone Strike</title></head>
<body><div id="ui">CCTV ACTIVE</div><script src="script.js"></script></body>
</html>
```

#### 2. script.js
```javascript
// CCTV Grayscale & Missile System
const weapons = ['bullet', 'missile', 'hellfire'];
let currentWeapon = 'hellfire';
const matCCTV = { color: 0x808080 };
console.log('CCTV Drone Weapons Active');
```""")
                return 0

            inputs = iter([
                user_instruction,
                "/mcp",
                "/exit",
            ])
            outputs: list[str] = []
            with patch("shell.execute_subcommand", side_effect=mock_exec_cctv), \
                 patch("webbrowser.open", return_value=True), \
                 patch("pai.enforce_sandbox_boundary"):
                code = run_interactive_shell(
                    input_fn=lambda _: next(inputs),
                    output_fn=outputs.append,
                    stream=io.StringIO(),
                )
                self.assertEqual(code, 0)

            # 5. Verify both files were updated on disk and backups were created
            updated_js = script_f.read_text(encoding="utf-8")
            self.assertIn("CCTV Grayscale & Missile System", updated_js)
            self.assertIn("hellfire", updated_js)

            updated_html = index_f.read_text(encoding="utf-8")
            self.assertIn("CCTV Drone Strike", updated_html)

            # Verify backups
            self.assertTrue(script_f.with_suffix(".js.bak").is_file())
            self.assertTrue(index_f.with_suffix(".html.bak").is_file())

            combined_out = "\n".join(outputs)
            self.assertIn("Successfully updated", combined_out)
            self.assertIn("Model Context Protocol", combined_out)
            self.assertIn("Tip: Refresh index.html", combined_out)

    def test_multimodel_team_fipa_acl_and_auto_failover(self) -> None:
        """Verifies multi-model autonomous team roster, FIPA-ACL messaging, and model failover."""
        from shell import parse_shell_line
        try:
            from research.multi_agent import MultiAgentTeam, TeamRoleModelRegistry
        except ModuleNotFoundError:
            from multi_agent import MultiAgentTeam, TeamRoleModelRegistry

        # 1. Test natural language parsing for developer team and playability fixes
        act_team, args_team = parse_shell_line("developer team eka use karala meka hadanna")
        self.assertEqual(act_team, "multi_agent")
        self.assertIn("developer team", args_team[0])

        act_play, args_play = parse_shell_line(
            "it's not playble fix it and Add more textures to this. The drone doesn't need to be visible."
        )
        self.assertEqual(act_play, "edit")

        act_stat, args_stat = parse_shell_line("/team status")
        self.assertEqual(act_stat, "multi_agent")
        self.assertEqual(args_stat[0], "status")

        # 2. Test Team Roster & Model Registry
        registry = TeamRoleModelRegistry()
        self.assertIn("project_manager", registry.role_models)
        self.assertIn("senior_developer", registry.role_models)
        self.assertIn("specialist_developer", registry.role_models)
        self.assertIn("qa_engineer", registry.role_models)

        team = MultiAgentTeam()
        summary = team.get_roster_summary()
        self.assertIn("PAI Autonomous AI Engineering Team", summary)
        self.assertIn("FIPA-ACL Standard", summary)
        self.assertIn("project_manager", summary)
        self.assertIn("senior_developer", summary)
        self.assertIn("qa_engineer", summary)

        # 3. Test FIPA-ACL Message Logging & Performatives
        msg = team.log_and_display_message(
            sender="project_manager",
            recipient="senior_developer",
            performative="REQUEST",
            content_preview="Implement Three.js CCTV FLIR simulation",
        )
        self.assertEqual(msg.performative, "REQUEST")
        self.assertEqual(msg.sender_role, "project_manager")
        self.assertEqual(msg.recipient_role, "senior_developer")
        self.assertEqual(len(team.conversation_log), 1)

        # 4. Test MultiAgent Team workflow execution with mock executor
        with tempfile.TemporaryDirectory() as td:
            p_dir = Path(td)
            (p_dir / "script.js").write_text("// initial", encoding="utf-8")

            def mock_team_exec(argv):
                # When senior developer is called, output complete code
                print("""### File: script.js
```javascript
// CCTV Three.js Simulation
const audio = { playCannon: () => {} };
console.log('Playable Verified');
```""")
                return 0

            team_mock = MultiAgentTeam(executor=mock_team_exec)
            res = team_mock.run_collaborative_workflow("Build CCTV Game", active_project_dir=p_dir)
            self.assertIn("script.js", res["code_updates"])
            self.assertIn("Playable Verified", (p_dir / "script.js").read_text(encoding="utf-8"))
            self.assertTrue((p_dir / "script.js.bak").is_file())

        # 5. Test Team Model Configuration (Role Customization & Natural Language Intent)
        act_cfg, args_cfg = parse_shell_line("/team set pm=llama3.2:3b dev=qwen2.5-coder:7b")
        self.assertEqual(act_cfg, "team_config")
        self.assertEqual(args_cfg[0], "set")
        self.assertIn("pm=llama3.2:3b", args_cfg[1])

        # Test natural language model change intent
        act_nl_help, _ = parse_shell_line("apita team eke role walata dala inna model wenas karanna puluwan wenna hadanna")
        self.assertEqual(act_nl_help, "team_config")

        act_nl_set, args_nl_set = parse_shell_line("team eke pm model eka llama3.2:3b karanna")
        self.assertEqual(act_nl_set, "team_config")
        self.assertEqual(args_nl_set[0], "set")
        self.assertIn("pm=llama3.2:3b", args_nl_set[1])

        # Test Sinhala natural language intent: "mata gemma model eka pm dala hadla denna"
        act_gemma, args_gemma = parse_shell_line("mata gemma model eka pm dala hadla denna")
        self.assertEqual(act_gemma, "team_config")
        self.assertEqual(args_gemma[0], "set")
        self.assertIn("pm=gemma", args_gemma[1])

        # Test dynamic role assignment and reset on registry
        with tempfile.TemporaryDirectory() as td_cfg:
            cfg_p = Path(td_cfg) / "team_config.json"
            with patch.object(TeamRoleModelRegistry, "get_config_path", return_value=cfg_p):
                reg = TeamRoleModelRegistry()
                ok, msg = reg.set_role_model("pm", "llama3.2:3b")
                self.assertTrue(ok)
                self.assertEqual(reg.role_models["project_manager"], "llama3.2:3b")
                self.assertIn("project_manager", reg.custom_roles)
                self.assertTrue(cfg_p.is_file())

                # Test multiple assignments via string parsing
                res_msgs = reg.parse_and_apply_assignments("dev=qwen2.5-coder:7b qa=qwen3.5:4b")
                self.assertEqual(len(res_msgs), 2)
                self.assertEqual(reg.role_models["senior_developer"], "qwen2.5-coder:7b")
                self.assertEqual(reg.role_models["qa_engineer"], "qwen3.5:4b")

                # Test fuzzy model prefix/substring matching (e.g. 'gemma' -> 'gemma4:e2b')
                reg.available_models = ["gemma4:e2b", "qwen2.5-coder:7b", "qwen3.5:4b"]
                ok, msg = reg.set_role_model("pm", "gemma")
                self.assertTrue(ok)
                self.assertEqual(reg.role_models["project_manager"], "gemma4:e2b")

                # Test reset to defaults
                reset_msg = reg.reset_to_defaults()
                self.assertIn("reset", reset_msg)
                self.assertEqual(len(reg.custom_roles), 0)


if __name__ == "__main__":
    unittest.main()
