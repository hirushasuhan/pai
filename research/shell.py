"""
Personal Agentic AI (PAI) - Interactive Terminal Shell (REPL).
Part of ADR-014 (Commit 2: Interactive Shell).

Invariants Enforced:
1. Terminal guard: Invoked only when sys.stdin.isatty() and sys.stdout.isatty() are True.
   Non-interactive or piped invocation preserves exact CLI help and exit code parity.
2. Canonical slash dispatch: Slash commands (/analyze, /code, /docs, /forecast, /doctor, /chat,
   /setup, /models, /route) dispatch directly to reviewed subcommand handlers in pai.py with zero duplicated logic.
   Administrative maintenance commands (/clear-shadow, /calibrate) are excluded to protect evaluation window invariants (Finding DV).
3. Windows-aware tokenizer: Preserves backslashes in Windows paths (C:\\Users\\...), UNC paths (\\\\server\\share),
   quoted paths with spaces, and Sinhala/Unicode identifiers (Finding DW).
4. Fail-safe unknown slash rejection: Unrecognized slash commands are rejected locally and
   are never forwarded to the reasoning model.
5. Conversational routing: Non-slash input lines route to canonical 'pai chat' with '--' sentinel
   so prompts beginning with a dash are never treated as CLI option flags (Finding DX).
6. Signal and EOF handling: Ctrl+C (SIGINT) cancels the active command/generation without
   terminating the shell; Ctrl+D/Ctrl+Z (EOF) or /exit cleanly exits the session.
7. Honest banner: Accurately declares model ("no model loaded yet" if uninitialized), endpoint,
   and explicit disclaimers: local models rely on static training data without live web or clock access,
   and conversational chat operates in stateless mode without cross-turn memory (Finding DX).
8. Privacy: No persistent cross-session transcript is written to disk (ADR-002).
"""

from __future__ import annotations

import os
import sys
from typing import Callable, List, Optional, Tuple

CANONICAL_SLASH_COMMANDS = {
    "analyze",
    "code",
    "docs",
    "forecast",
    "doctor",
    "chat",
    "setup",
    "models",
    "route",
}

SHELL_BANNER = (
    "Personal Agentic AI (PAI) Interactive Shell\n"
    "Model: {model_name} | Endpoint: {endpoint}\n"
    "Note: Local models rely on static training data and lack live clock or web access.\n"
    "Mode: Stateless (each line is evaluated independently without prior conversation memory).\n"
    "Type /help for available commands or /exit to quit.\n"
)

SHELL_HELP = (
    "Personal Agentic AI (PAI) Interactive Shell Commands:\n"
    "  /chat <prompt>      Chat with the assistant (or enter prompt directly without slash)\n"
    "  /code <prompt>      Generate and verify Python code against sandbox tests\n"
    "  /analyze <path>     Analyze codebase architecture, dependencies, and risks\n"
    "  /docs <path>        Search and synthesize local documentation (.txt, .md, .csv)\n"
    "  /forecast <path>    Run time-series forecasting analysis on tabular data\n"
    "  /doctor             Verify local environment health and hardware telemetry\n"
    "  /setup              Run setup, hardware survey, and model configuration\n"
    "  /models             List verified local and catalog models\n"
    "  /route <prompt>     Evaluate routing decision for given task\n"
    "  /help               Show this help message\n"
    "  /exit, /quit        Exit the interactive shell\n"
    "Note: Chat is stateless; each query is evaluated independently without prior conversation memory.\n"
)


def is_interactive_terminal() -> bool:
    """Returns True only when both stdin and stdout are interactive TTYs (ADR-014)."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def tokenize_windows_line(line: str) -> List[str]:
    """
    Tokenizes a Windows command line without stripping backslashes (Findings DW & EC).
    Only double quotes (") are treated as quote delimiters on Windows (Finding EC).
    Single quotes / apostrophes (') are treated as literal characters (e.g. C:\\Users\\O'Brien\\notes.txt).
    Supports:
      - Normal unquoted arguments with backslashes (C:\\Users\\hp\\project, \\\\server\\share)
      - Quoted arguments with spaces ("C:\\Program Files\\app", "D:\\my notes")
      - Apostrophes in paths (C:\\Users\\O'Brien\\notes.txt) and code prompts (/code "def foo(): return 'bar'")
      - Sinhala and multilingual Unicode characters
      - Enclosing double quote removal for quoted tokens
    Raises ValueError on unclosed double quote.
    """
    tokens: List[str] = []
    current: List[str] = []
    in_quote = False
    i = 0
    n = len(line)

    while i < n:
        ch = line[i]
        if in_quote:
            if ch == '"':
                in_quote = False
            else:
                current.append(ch)
        else:
            if ch == '"':
                in_quote = True
            elif ch.isspace():
                if current:
                    tokens.append("".join(current))
                    current = []
            else:
                current.append(ch)
        i += 1

    if in_quote:
        raise ValueError("No closing quotation")

    if current:
        tokens.append("".join(current))

    return tokens


def get_shell_banner(endpoint: str = "http://127.0.0.1:11434") -> str:
    """Constructs the interactive shell startup banner stating active model and honest limitations."""
    model_name = "no model loaded yet"
    try:
        from router import ModelRouter
        router = ModelRouter(load_system_profile=True)
        resident = router.get_live_resident_model()
        if resident:
            model_name = resident
    except Exception:
        model_name = "no model loaded yet"
    return SHELL_BANNER.format(model_name=model_name, endpoint=endpoint)


def parse_shell_line(line: str) -> Tuple[str, List[str]]:
    """
    Parses a single shell input line using Windows-aware tokenizer (Finding DW).
    Returns (action: str, argv: List[str]).
    Actions:
      - 'empty': Blank line, no-op.
      - 'exit': Clean exit request (/exit, /quit).
      - 'help': Display shell command reference (/help, /?).
      - 'unknown_slash': Unrecognized slash command.
      - 'canonical': Recognized slash command mapped to canonical CLI argv.
      - 'chat': Non-slash text routed to canonical 'pai chat'.
      - 'error': Syntax or tokenization error.
    """
    stripped = line.strip()
    if not stripped:
        return "empty", []

    if stripped.startswith("/"):
        try:
            tokens = tokenize_windows_line(stripped)
        except ValueError as e:
            return "error", [f"Error: {e}"]

        if not tokens:
            return "empty", []

        raw_cmd = tokens[0].lstrip("/").lower()

        if raw_cmd in ("exit", "quit"):
            return "exit", []

        if raw_cmd in ("help", "?"):
            return "help", []

        if raw_cmd in CANONICAL_SLASH_COMMANDS:
            # Ergonomics for /chat: pass prompt after '--' sentinel so leading dashes are preserved (Finding DX)
            if raw_cmd == "chat":
                chat_prompt = stripped[len(tokens[0]):].strip()
                if not chat_prompt:
                    return "error", ["Error: /chat requires a prompt message."]
                return "canonical", ["chat", "--", chat_prompt]

            argv = [raw_cmd] + tokens[1:]
            return "canonical", argv

        # Fail-safe: Unrecognized slash commands are NEVER forwarded to the reasoner
        return "unknown_slash", [tokens[0]]

    # Conversational text without leading slash routes to canonical 'pai chat'
    # Use '--' sentinel so prompts beginning with a dash (e.g. '-5 is negative')
    # are never mistaken for CLI option flags (Finding DX)
    return "chat", ["chat", "--", stripped]


def execute_subcommand(argv: List[str]) -> int:
    """
    Executes canonical subcommand by delegating to pai.main().
    Exercises identical capability broker, sandbox, and telemetry invariants.
    Intercepts SystemExit so invalid arguments or --help do not terminate the REPL.
    """
    from pai import main as pai_main
    try:
        return pai_main(argv)
    except SystemExit as se:
        return int(se.code) if isinstance(se.code, int) else 1
    except Exception as e:
        print(f"Error executing command '{argv[0]}': {e}", file=sys.stderr)
        return 1


def run_interactive_shell(
    input_fn: Optional[Callable[[str], str]] = None,
    output_fn: Optional[Callable[[str], None]] = None,
    prompt_str: str = "pai> ",
) -> int:
    """
    Runs the PAI interactive terminal REPL (ADR-014).
    Accepts custom input/output callables for deterministic unit testing.
    """
    if input_fn is None:
        input_fn = input
    if output_fn is None:
        output_fn = print

    output_fn(get_shell_banner())

    while True:
        try:
            line = input_fn(prompt_str)
        except EOFError:
            output_fn("\nGoodbye.")
            return 0
        except KeyboardInterrupt:
            output_fn("\nType /exit to quit.")
            continue

        action, argv = parse_shell_line(line)

        if action == "empty":
            continue
        elif action == "exit":
            output_fn("Goodbye.")
            return 0
        elif action == "help":
            output_fn(SHELL_HELP)
            continue
        elif action == "unknown_slash":
            output_fn(f"Unknown command '{argv[0]}'. Type /help for available commands or /exit to quit.")
            continue
        elif action == "error":
            output_fn(argv[0])
            continue
        elif action in ("canonical", "chat"):
            try:
                execute_subcommand(argv)
            except KeyboardInterrupt:
                output_fn("\n[Operation cancelled by user]")
            except Exception as e:
                output_fn(f"Error: {e}")
