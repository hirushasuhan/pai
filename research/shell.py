"""
Personal Agentic AI (PAI) - Interactive Terminal Shell (REPL).
Part of ADR-014 (Commit 2: Interactive Shell & Milestone B: Shell Layout & Look).

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
9. Milestone B Layout & Pinned Scroll Region: Pinned DECSTBM header (5 rows) with Unicode block logo
   (or ASCII fallback) and horizontal color gradient. Honest terminal scrollback limit documented.
   In-memory /history and chat-clearing /clear commands provided. Non-blocking thinking spinner for /chat.
"""

from __future__ import annotations

import atexit
import collections
import contextlib
import datetime
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple
import webbrowser

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

PAI_ASCII_LOGO = (
    r"  ____   _    ___ " + "\n"
    r" |  _ \ / \  |_ _|" + "\n"
    r" | |_) / _ \  | | " + "\n"
    r" |  __/ ___ \ | | " + "\n"
    r" |_| /_/   \_\___|"
)

PAI_UNICODE_BLOCK_LOGO = [
    "█▀█ ▄▀█ █",
    "█▀▀ █▀█ █",
    "▀   ▀ ▀ ▀",
]

PAI_ASCII_FALLBACK_LOGO = [
    r" ___  _  ___",
    r"| _ \/_\  | ",
    r"|_|  / \ _|_",
]

DEVELOPER_CREDIT = "Developed by Hirusha Suhan"

SHELL_BANNER = (
    "{logo}\n"
    "Personal Agentic AI (PAI) Interactive Shell\n"
    "{developer_credit}\n"
    "Model: {model_name} | Endpoint: {endpoint}\n"
    "Note: PAI gives the model your computer's date and time. It has no web access and its knowledge ends at a training cut-off.\n"
    "Mode: Stateless (each line is evaluated independently without prior conversation memory).\n"
    "Type /help for available commands or /exit to quit.\n"
)

SHELL_HELP = (
    "Personal Agentic AI (PAI) Interactive Shell Commands:\n"
    "  /chat <prompt>      Chat with the assistant (or enter prompt directly without slash)\n"
    "  /code <prompt>      Generate and verify Python code against sandbox tests\n"
    "  /team [status|prompt] Run autonomous Multi-Model Developer Team (PM, Senior Dev, Specialist Dev, QA)\n"
    "  /team set <role>=<m> Configure model assigned to a team role (e.g. /team set pm=llama3.2:3b)\n"
    "  /agent <prompt>     Alias for /team multi-agent collaborative workflow\n"
    "  /edit <file> <prompt> Edit an existing file (HTML, Python, JS, etc.) with instructions\n"
    "  /fix <file|dir>     Analyze code for bugs, logic errors, and auto-fix with backup\n"
    "  /project [dir]      Scaffold project or show active project status\n"
    "  /open [path|url]    Open web page, HTML file, or active project in default browser\n"
    "  /mcp [status|tools] Inspect connected Model Context Protocol servers and tools\n"
    "  /graphql <query>    Execute GraphQL operation or inspect schema via introspection\n"
    "  /skills             List all learned and active agent skills\n"
    "  /skill <name>       View details and prompt guidance for a specific skill\n"
    "  /learn <name> <doc> Teach PAI a new skill to automatically apply in future tasks\n"
    "  /model [name]       View available models or switch active resident model on the fly\n"
    "  /analyze <path>     Analyze codebase architecture, dependencies, and risks\n"
    "  /docs <path>        Search and synthesize local documentation (.txt, .md, .csv)\n"
    "  /save <path>        Save the last response or extracted code block to a local file\n"
    "  /cmd <command>      Execute a Windows system command and display output\n"
    "  /wifi               Scan and display available Wi-Fi networks and signal strength\n"
    "  /forecast <path>    Run time-series forecasting analysis on tabular data\n"
    "  /doctor             Verify local environment health and hardware telemetry\n"
    "  /setup              Run setup, hardware survey, and model configuration\n"
    "  /models             List verified local and catalog models\n"
    "  /route <prompt>     Evaluate routing decision for given task\n"
    "  /time               Show current system date, time, and time zone\n"
    "  /history [N]        Show in-memory session history (last N entries, default 20)\n"
    "  /clear              Clear chat window (preserves pinned header in VT mode)\n"
    "  /help               Show this help message\n"
    "  /exit, /quit        Exit the interactive shell\n"
    "Note: Chat is stateless by default; in-memory multi-turn session memory is maintained in RAM.\n"
    "Note: In pinned VT mode, off-screen lines do not enter terminal scrollback; use /history to review session output.\n"
    "      Set PAI_NO_PINNED_HEADER=1 to disable pinned header mode.\n"
)

# ANSI terminal formatting (Milestone Step 2 & Milestone B)
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
BRIGHT_CYAN = "\033[96m"
BRIGHT_BLUE = "\033[94m"
BRIGHT_MAGENTA = "\033[95m"

_original_console_mode: Optional[int] = None


def enable_windows_vt() -> bool:
    """Enables Windows Virtual Terminal Processing with explicit ctypes argtypes/restype (Finding EY)."""
    global _original_console_mode
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32

        # Configure explicit ctypes argtypes and restype (Finding EY)
        kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetConsoleMode.restype = wintypes.BOOL
        kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.SetConsoleMode.restype = wintypes.BOOL

        STD_OUTPUT_HANDLE = ctypes.c_ulong(-11).value  # 0xFFFFFFF5
        hOut = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        INVALID_HANDLE = wintypes.HANDLE(-1).value
        if not hOut or hOut == INVALID_HANDLE:
            return False

        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(hOut, ctypes.byref(mode)):
            return False

        if _original_console_mode is None:
            _original_console_mode = mode.value

        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        if (mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0:
            if not kernel32.SetConsoleMode(hOut, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING):
                return False
        return True
    except Exception:
        return False


def restore_windows_console_mode() -> None:
    """Restores the original Windows console mode upon shell exit (Finding EY)."""
    global _original_console_mode
    if sys.platform != "win32" or _original_console_mode is None:
        return
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        STD_OUTPUT_HANDLE = ctypes.c_ulong(-11).value
        hOut = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        INVALID_HANDLE = wintypes.HANDLE(-1).value
        if hOut and hOut != INVALID_HANDLE:
            kernel32.SetConsoleMode(hOut, _original_console_mode)
    except Exception:
        pass
    finally:
        _original_console_mode = None


def should_enable_color(stream=sys.stdout) -> bool:
    """
    Returns True if ANSI color output is supported and not disabled by user.
    Disabled when:
      - NO_COLOR environment variable is set (https://no-color.org)
      - TERM == 'dumb'
      - Stream is not a TTY (piped, redirected, captured)
      - On Windows, if Virtual Terminal processing cannot be enabled
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        if not stream.isatty():
            return False
    except Exception:
        return False
    if sys.platform == "win32":
        return enable_windows_vt()
    return True


def colorize(text: str, color_code: str, enabled: bool) -> str:
    """Wraps text in ANSI color escape codes when enabled is True."""
    if not enabled:
        return text
    return f"{color_code}{text}{RESET}"


def can_encode_blocks(stream=sys.stdout) -> bool:
    """Returns True if the stream encoding can represent Unicode block and box drawing characters."""
    try:
        encoding = getattr(stream, "encoding", None) or "ascii"
        "█▀▄─".encode(encoding)
        return True
    except Exception:
        return False


def get_terminal_dimensions() -> Tuple[int, int]:
    """Returns (columns, lines) of the terminal, defaulting to (80, 24) on error."""
    try:
        size = shutil.get_terminal_size(fallback=(80, 24))
        return size.columns, size.lines
    except Exception:
        return 80, 24


_active_model_override: Optional[str] = None


def get_resident_model_name() -> str:
    """Retrieves active resident model name or returns 'no model loaded yet'."""
    global _active_model_override
    if _active_model_override:
        return _active_model_override
    env_override = os.environ.get("PAI_ACTIVE_MODEL")
    if env_override:
        return env_override
    try:
        from router import ModelRouter
        router = ModelRouter(load_system_profile=True)
        resident = router.get_live_resident_model()
        if resident:
            return resident
    except Exception:
        pass
    return "no model loaded yet"


def get_available_models() -> List[str]:
    """Returns list of installed local model names from Ollama, or fallback catalog."""
    try:
        from pai import probe_ollama_server
        info = probe_ollama_server()
        if info.get("reachable") and info.get("models"):
            return list(info["models"])
    except Exception:
        pass
    try:
        from router import ModelRouter
        router = ModelRouter(load_system_profile=True)
        return list(router.candidates.keys())
    except Exception:
        pass
    return ["qwen2.5-coder:7b", "qwen2.5-coder:1.5b", "llama3.2:3b", "llama3.2:1b"]


def resolve_model_name(query: str) -> Optional[str]:
    """Resolves exact or fuzzy model name to an available model."""
    q = query.strip().lower()
    avail = get_available_models()
    for m in avail:
        if m.lower() == q:
            return m
    for m in avail:
        base = m.split(":")[0].lower()
        if base == q:
            return m
    matches = [m for m in avail if q in m.lower()]
    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        for m in matches:
            if m.lower().startswith(q):
                return m
        return matches[0]
    return None


def switch_active_model(target_model_str: str, stream=sys.stdout) -> Tuple[bool, str]:
    """
    Switches active resident model override in the shell.
    Updates terminal title bar and status prompt.
    """
    global _active_model_override
    resolved = resolve_model_name(target_model_str)
    avail = get_available_models()
    if not resolved:
        avail_list = "\n  - " + "\n  - ".join(avail)
        return False, f"Error: Model '{target_model_str}' not found.\nAvailable installed models:{avail_list}"

    _active_model_override = resolved
    os.environ["PAI_ACTIVE_MODEL"] = resolved

    ver = get_install_root_version()
    set_terminal_title(f"PAI {ver} | Model: {resolved} | Developed by Hirusha Suhan", stream)
    return True, f"Active model switched to '{resolved}'"


def format_models_list(color_enabled: bool = False) -> str:
    """Formats available models with active indicator and memory info."""
    avail = get_available_models()
    current = get_resident_model_name()
    lines = [colorize("=== Available Local Models ===", BOLD, color_enabled)]
    for m in avail:
        if m == current:
            prefix = colorize(" ● [ACTIVE] ", GREEN, color_enabled)
        else:
            prefix = "   [      ] "
        lines.append(f"{prefix}{colorize(m, CYAN, color_enabled)}")
    lines.append(colorize("─" * 40, DIM, color_enabled))
    lines.append(colorize(f"To switch model, type: /model <name> (e.g. /model {avail[0]})", DIM, color_enabled))
    return "\n".join(lines)


def get_shell_logo_lines(color_enabled: bool = False, stream=sys.stdout) -> List[str]:
    """
    Returns 3 logo lines with horizontal gradient (Cyan -> Blue -> Magenta).
    Falls back to compact ASCII logo if stream cannot encode Unicode block characters.
    """
    use_blocks = can_encode_blocks(stream)
    lines: List[str] = []
    if use_blocks:
        for row in PAI_UNICODE_BLOCK_LOGO:
            p = row[0:4]
            a = row[4:8]
            i = row[8:]
            if color_enabled:
                lines.append(f"{BRIGHT_CYAN}{p}{RESET}{BRIGHT_BLUE}{a}{RESET}{BRIGHT_MAGENTA}{i}{RESET}")
            else:
                lines.append(f"{p}{a}{i}")
    else:
        for row in PAI_ASCII_FALLBACK_LOGO:
            p = row[0:5]
            a = row[5:9]
            i = row[9:]
            if color_enabled:
                lines.append(f"{BRIGHT_CYAN}{p}{RESET}{BRIGHT_BLUE}{a}{RESET}{BRIGHT_MAGENTA}{i}{RESET}")
            else:
                lines.append(f"{p}{a}{i}")
    return lines


def get_install_root_version(install_root: Optional[Path] = None) -> str:
    """Returns application version from manifest.json at the install root (field 'version').

    If manifest.json is missing, unreadable, or malformed, returns 'dev'.
    The install root is module-relative (the parent of research/). No environment variable chooses it.
    """
    try:
        if install_root is None:
            install_root = Path(__file__).resolve().parent.parent
        manifest_p = Path(install_root) / "manifest.json"
        if manifest_p.is_file():
            data = json.loads(manifest_p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                ver = data.get("version")
                if isinstance(ver, str) and ver.strip():
                    return ver.strip()
    except Exception:
        pass
    return "dev"


def get_shell_info_line(cols: int, color_enabled: bool = False, install_root: Optional[Path] = None) -> str:
    """Returns width-adaptive info line declaring model, offline/stateless mode, and provenance."""
    model_name = get_resident_model_name()
    ver = get_install_root_version(install_root)
    full_info = f"PAI {ver} | Model: {model_name} | Offline/Stateless | Developed by Hirusha Suhan"
    medium_info = f"PAI {ver} | Model: {model_name} | Offline | Developed by Hirusha Suhan"
    compact_info = f"PAI {ver} | Model: {model_name} | Offline | Hirusha Suhan"
    if len(full_info) <= cols:
        info_text = full_info
    elif len(medium_info) <= cols:
        info_text = medium_info
    elif len(compact_info) <= cols:
        info_text = compact_info
    else:
        info_text = f"PAI {ver} | {model_name} | Offline"
    return colorize(info_text, DIM, color_enabled)


def get_shell_separator_line(cols: int, color_enabled: bool = False, stream=sys.stdout) -> str:
    """Returns horizontal separator line fitting terminal width."""
    sep_char = "─" if can_encode_blocks(stream) else "-"
    sep_text = sep_char * min(cols, 80)
    return colorize(sep_text, DIM, color_enabled)


def get_pinned_header_lines(
    cols: int,
    color_enabled: bool = False,
    stream=sys.stdout,
    install_root: Optional[Path] = None,
) -> List[str]:
    """Returns exactly 5 header lines: 3 logo lines, 1 info line, 1 separator line."""
    logo_lines = get_shell_logo_lines(color_enabled=color_enabled, stream=stream)
    info_line = get_shell_info_line(cols, color_enabled=color_enabled, install_root=install_root)
    sep_line = get_shell_separator_line(cols, color_enabled=color_enabled, stream=stream)
    return logo_lines + [info_line, sep_line]


def should_pin_header(stream=sys.stdout) -> bool:
    """
    Returns True if pinned DECSTBM scroll region should be active.
    Default is False to preserve natural mouse-wheel scrollback on Windows Terminal / PowerShell.
    Set PAI_PINNED_HEADER=1 to opt-in to pinned VT mode.
    Requires interactive terminal, PAI_PINNED_HEADER == '1', PAI_NO_PINNED_HEADER != '1',
    TERM != 'dumb', successful Windows VT processing if on Windows, and lines >= 20, cols >= 60.
    """
    if os.environ.get("PAI_PINNED_HEADER") != "1":
        return False
    if os.environ.get("PAI_NO_PINNED_HEADER") == "1":
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    if not is_interactive_terminal():
        return False
    try:
        if not stream.isatty():
            return False
    except Exception:
        return False
    if sys.platform == "win32":
        if not enable_windows_vt():
            return False
    cols, lines = get_terminal_dimensions()
    if lines < 20 or cols < 60:
        return False
    return True


_pinned_active: bool = False
_atexit_registered: bool = False


def setup_pinned_layout(stream=sys.stdout) -> None:
    """
    Initializes DECSTBM pinned scroll region layout.
    Clears visible screen (\\033[2J), writes header on lines 1..n_header, sets scroll region
    to lines (n_header + 1)..rows (\\033[{n_header + 1};{rows}r), and positions cursor at \\033[{n_header + 1};1H.
    """
    global _pinned_active, _atexit_registered
    _pinned_active = True
    if not _atexit_registered:
        atexit.register(cleanup_pinned_layout)
        _atexit_registered = True

    cols, rows = get_terminal_dimensions()
    color_enabled = should_enable_color(stream)
    header_lines = get_pinned_header_lines(cols, color_enabled, stream)
    n_header = len(header_lines)

    stream.write("\033[2J\033[1;1H")
    for i, line in enumerate(header_lines, start=1):
        stream.write(f"\033[{i};1H{line}\r\n")
    stream.write(f"\033[{n_header + 1};{rows}r\033[{n_header + 1};1H")
    stream.flush()


def check_and_apply_resize(current_dims: Tuple[int, int], stream=sys.stdout) -> Tuple[int, int]:
    """Detects terminal resize, redraws pinned header, and updates DECSTBM scroll margins."""
    new_dims = get_terminal_dimensions()
    if new_dims == current_dims:
        return current_dims
    cols, rows = new_dims
    color_enabled = should_enable_color(stream)
    header_lines = get_pinned_header_lines(cols, color_enabled, stream)
    n_header = len(header_lines)

    for i, line in enumerate(header_lines, start=1):
        stream.write(f"\033[{i};1H\033[2K{line}\r\n")
    stream.write(f"\033[{n_header + 1};{rows}r")
    # Per VT100 standard, DECSTBM margin command resets cursor to home (1, 1).
    # Position cursor at the bottom row of the new scrolling region to avoid overwriting header (Finding FL).
    stream.write(f"\033[{rows};1H")
    stream.flush()
    return new_dims


def cleanup_pinned_layout(stream=sys.stdout) -> None:
    """
    Idempotent cleanup for pinned layout: resets scroll margins (\\033[r),
    moves cursor to bottom row, resets attributes, and restores Windows console mode.
    Only writes VT escape sequences if a pinned layout was active and stream is a TTY (Finding FK).
    """
    global _pinned_active
    was_active = _pinned_active
    _pinned_active = False
    try:
        if was_active:
            is_tty = False
            try:
                is_tty = bool(stream.isatty())
            except Exception:
                is_tty = False
            if is_tty:
                _, rows = get_terminal_dimensions()
                stream.write("\033[r")
                stream.write(f"\033[{rows};1H")
                stream.write("\033[0m\033[?25h")
                stream.flush()
    except Exception:
        pass
    finally:
        restore_windows_console_mode()

# Thinking Spinner for /chat
BRAILLE_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
ASCII_FRAMES = ["|", "/", "-", "\\"]


class ThinkingSpinner:
    """
    Renders non-blocking thinking spinner during chat model generation.
    Active only when stdout is a TTY and TERM != 'dumb'.
    """
    def __init__(self, stream=sys.stdout):
        self.stream = stream
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start_time: float = 0.0
        self.enabled = False
        try:
            if self.stream.isatty() and os.environ.get("TERM") != "dumb":
                self.enabled = True
        except Exception:
            self.enabled = False

    def start(self) -> None:
        if not self.enabled:
            return
        self._stop_event.clear()
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self) -> None:
        color_enabled = should_enable_color(self.stream)
        use_braille = can_encode_blocks(self.stream)
        frames = BRAILLE_FRAMES if use_braille else ASCII_FRAMES
        idx = 0
        while not self._stop_event.is_set():
            elapsed = int(time.time() - self._start_time)
            frame = frames[idx % len(frames)]
            styled_frame = colorize(frame, CYAN, color_enabled)
            msg = f"\r{styled_frame} Thinking... ({elapsed}s)"
            try:
                self.stream.write(msg)
                self.stream.flush()
            except Exception:
                break
            idx += 1
            self._stop_event.wait(0.1)

    def stop(self) -> None:
        if not self.enabled or self._thread is None:
            return
        self._stop_event.set()
        try:
            self._thread.join(timeout=1.0)
        except Exception:
            pass
        self._thread = None
        try:
            self.stream.write("\r\033[2K")
            self.stream.flush()
        except Exception:
            pass


# In-Memory Session History
MAX_HISTORY_ITEMS = 200
MAX_HISTORY_BYTES = 1_000_000  # 1 MB


def _entry_encoded_bytes(cmd: str, out: str) -> int:
    """Calculates UTF-8 encoded byte length of a history entry (Finding FN)."""
    return len(cmd.encode("utf-8", errors="replace")) + len(out.encode("utf-8", errors="replace"))


_session_history: Deque[Tuple[str, str, str]] = collections.deque(maxlen=MAX_HISTORY_ITEMS)
_session_chat_turns: List[dict] = []


def add_to_session_history(command: str, output: str) -> None:
    """
    Adds a command line and its execution output to in-memory session history.
    Enforces max 200 items and 1 MB memory cap based on UTF-8 encoded bytes (Finding FN).
    Never writes to disk.
    """
    now_str = datetime.datetime.now().strftime("%H:%M:%S")
    cleaned_out = output.strip()
    _session_history.append((now_str, command.strip(), cleaned_out))

    total_bytes = sum(_entry_encoded_bytes(c, o) for _, c, o in _session_history)
    while total_bytes > MAX_HISTORY_BYTES and len(_session_history) > 1:
        popped = _session_history.popleft()
        total_bytes -= _entry_encoded_bytes(popped[1], popped[2])


def get_session_history(limit: Optional[int] = None) -> List[Tuple[str, str, str]]:
    """Returns list of in-memory history entries up to limit (default 20)."""
    items = list(_session_history)
    if limit is not None and limit > 0:
        return items[-limit:]
    return items[-20:] if len(items) > 20 else items


def clear_session_history() -> None:
    """Clears in-memory session history."""
    _session_history.clear()


def format_session_history(limit: Optional[int] = None, color_enabled: bool = False) -> str:
    """Formats session history for console display."""
    items = get_session_history(limit)
    if not items:
        return "No command history in current session."

    count = len(items)
    header = f"=== Session History (last {count} entries) ==="
    lines = [colorize(header, BOLD, color_enabled)]

    for idx, (t, cmd, out) in enumerate(items, start=1):
        prompt_line = f"[{idx}] {t} > {cmd}"
        lines.append(colorize(prompt_line, CYAN, color_enabled))
        if out:
            lines.append(out)
        lines.append(colorize("-" * 40, DIM, color_enabled))

    lines.append(colorize("=" * len(header), BOLD, color_enabled))
    return "\n".join(lines)


class CaptureStream:
    """
    Tees output to underlying stream while capturing output in memory.
    Triggers on_first_write callback on first non-empty write.
    """
    def __init__(self, underlying_stream, on_first_write: Optional[Callable[[], None]] = None):
        self.underlying_stream = underlying_stream
        self.on_first_write = on_first_write
        self._first_write_done = False
        self._buffer = io.StringIO()

    def write(self, s: str) -> int:
        if s and not self._first_write_done and self.on_first_write:
            self._first_write_done = True
            try:
                self.on_first_write()
            except Exception:
                pass
        self._buffer.write(s)
        try:
            return self.underlying_stream.write(s)
        except Exception:
            return len(s)

    def flush(self) -> None:
        try:
            self.underlying_stream.flush()
        except Exception:
            pass

    def getvalue(self) -> str:
        return self._buffer.getvalue()

    def isatty(self) -> bool:
        try:
            return self.underlying_stream.isatty()
        except Exception:
            return False

    @property
    def encoding(self) -> str:
        return getattr(self.underlying_stream, "encoding", "utf-8")


def get_current_system_clock_context() -> Tuple[str, str, str]:
    """
    Returns current local date, time, and timezone from system clock.
    Format: ('2026-10-28 (Wednesday)', '23:30:00', 'Sri Lanka Standard Time (UTC+0530)')
    """
    now = datetime.datetime.now().astimezone()
    date_str = now.strftime("%Y-%m-%d (%A)")
    time_str = now.strftime("%H:%M:%S")
    tz_str = now.strftime("%Z (UTC%z)")
    return date_str, time_str, tz_str


def is_interactive_terminal() -> bool:
    """Returns True only when both stdin and stdout are interactive TTYs (ADR-014)."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def tokenize_windows_line(line: str) -> List[str]:
    """
    Tokenizes a Windows command line without stripping backslashes (Findings DW & EC).
    Only double quotes (\") are treated as quote delimiters on Windows (Finding EC).
    Single quotes / apostrophes (') are treated as literal characters (e.g. C:\\Users\\O'Brien\\notes.txt).
    Supports:
      - Normal unquoted arguments with backslashes (C:\\Users\\hp\\project, \\\\server\\share)
      - Quoted arguments with spaces (\"C:\\Program Files\\app\", \"D:\\my notes\")
      - Apostrophes in paths (C:\\Users\\O'Brien\\notes.txt) and code prompts (/code \"def foo(): return 'bar'\")
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


def scan_local_wifi(timeout: float = 8.0) -> List[dict]:
    """Scans visible Wi-Fi networks on Windows via netsh wlan show networks mode=bssid."""
    import subprocess
    if sys.platform != "win32":
        return []
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = proc.stdout
    except Exception:
        return []

    networks: List[dict] = []
    current: dict = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SSID"):
            if current and "ssid" in current:
                networks.append(current)
            parts = line.split(":", 1)
            ssid = parts[1].strip() if len(parts) > 1 else "Hidden"
            current = {"ssid": ssid, "signals": [], "auth": "Open", "band": "Unknown"}
        elif "Authentication" in line and current:
            current["auth"] = line.split(":", 1)[1].strip()
        elif "Signal" in line and current:
            current["signals"].append(line.split(":", 1)[1].strip())
        elif "Band" in line and current:
            current["band"] = line.split(":", 1)[1].strip()
    if current and "ssid" in current:
        networks.append(current)
    return networks


def format_wifi_report(networks: List[dict], color_enabled: bool = False, stream=sys.stdout) -> str:
    """Formats Wi-Fi networks into a clean, readable terminal table with signal indicators."""
    if not networks:
        return colorize("No Wi-Fi networks detected (or Wi-Fi adapter is turned off).", YELLOW, color_enabled)

    use_blocks = can_encode_blocks(stream)
    sep_char = "─" if use_blocks else "-"
    sep = sep_char * 70
    header = f"{'SSID':<26} {'Signal':<12} {'Band':<10} {'Security':<20}"
    lines = [
        colorize("Detected Wi-Fi Networks:", BOLD, color_enabled),
        colorize(sep, DIM, color_enabled),
        colorize(header, CYAN, color_enabled),
        colorize(sep, DIM, color_enabled),
    ]

    for net in networks:
        ssid = net.get("ssid") or "Hidden"
        sig_str = net["signals"][0] if net.get("signals") else "N/A"
        band = net.get("band", "Unknown")
        auth = net.get("auth", "Unknown")

        sig_val = 0
        try:
            sig_val = int(sig_str.replace("%", "").strip())
        except Exception:
            pass

        bar_len = min(5, max(1, sig_val // 20))
        if use_blocks:
            bar = "█" * bar_len + "░" * (5 - bar_len)
        else:
            bar = "#" * bar_len + "." * (5 - bar_len)
        sig_display = f"{sig_str} [{bar}]"

        sig_color = GREEN if sig_val >= 70 else (YELLOW if sig_val >= 40 else RED)
        styled_sig = colorize(f"{sig_display:<12}", sig_color, color_enabled)
        styled_ssid = colorize(f"{ssid:<26}", BRIGHT_CYAN, color_enabled)
        styled_band = colorize(f"{band:<10}", DIM, color_enabled)
        styled_auth = colorize(f"{auth:<20}", DIM, color_enabled)

        lines.append(f"{styled_ssid} {styled_sig} {styled_band} {styled_auth}")

    lines.append(colorize(sep, DIM, color_enabled))
    return "\n".join(lines)


def set_terminal_title(title: str, stream=sys.stdout) -> None:
    """Sets the terminal window / tab title using ANSI OSC 0 sequence."""
    try:
        if getattr(stream, "isatty", lambda: False)():
            stream.write(f"\033]0;{title}\007")
            stream.flush()
    except Exception:
        pass


def get_compact_prompt_header(color_enabled: bool = False, install_root: Optional[Path] = None) -> str:
    """Returns compact status bar displayed immediately above the prompt."""
    ver = get_install_root_version(install_root)
    model_name = get_resident_model_name()
    status_text = f" PAI {ver} | Model: {model_name} | Hirusha Suhan "
    bar = f"┌──[{status_text}]"
    return colorize(bar, DIM, color_enabled)


def resolve_target_dir(target_str: str) -> Path:
    """
    Resolves a target directory path, expanding ~ and special folders (Downloads, Desktop, Documents).
    """
    clean = target_str.strip().strip('"').strip("'").strip('`')
    if not clean:
        return Path.cwd() / "my_project"

    user_home = Path.home()
    c_lower = clean.lower()
    for prefix, folder in [
        ("downloads\\", user_home / "Downloads"),
        ("downloads/", user_home / "Downloads"),
        ("desktop\\", user_home / "Desktop"),
        ("desktop/", user_home / "Desktop"),
        ("documents\\", user_home / "Documents"),
        ("documents/", user_home / "Documents"),
    ]:
        if c_lower.startswith(prefix):
            remainder = clean[len(prefix):]
            return (folder / remainder).resolve()

    if c_lower == "downloads":
        return user_home / "Downloads"
    if c_lower == "desktop":
        return user_home / "Desktop"
    if c_lower == "documents":
        return user_home / "Documents"

    return Path(clean).expanduser().resolve()


def save_session_output_to_file(target_path_str: str) -> Tuple[bool, str]:
    """
    Saves the last command output or chat response from in-memory session history to target_path.
    Extracts fenced code if present (e.g. ```lang ... ```); otherwise saves full response.
    Supports directory targets (e.g. 'Downloads', 'Desktop', folders) with intelligent auto-naming.
    Creates parent directories if necessary.
    """
    history = get_session_history()
    if not history:
        return False, "No previous output in session history to save."

    # Search backwards for the most recent entry with code blocks or substantial text
    target_entry = None
    for entry in reversed(history):
        out = entry[2]
        if out.startswith("Saved ") and "bytes to" in out:
            continue
        if out.startswith("[Successfully initialized new project"):
            continue
        if "```" in out or len(out.strip()) > 80:
            target_entry = entry
            break
    if not target_entry:
        target_entry = history[-1]

    last_query = target_entry[1]
    last_output = target_entry[2]
    if not last_output or not last_output.strip():
        return False, "Previous command produced no output to save."

    import re
    code_matches = list(re.finditer(r"```(\w+)?\r?\n(.*?)\r?\n```", last_output, re.DOTALL))
    code_lang = ""
    target_clean = target_path_str.strip().strip('"').strip("'").strip('`')
    t_lower = target_clean.lower()

    if code_matches:
        chosen = code_matches[0]
        if t_lower.endswith((".html", ".htm")) or "html" in t_lower or "web" in t_lower:
            for m in code_matches:
                if (m.group(1) or "").lower() in ("html", "htm") or "<html" in m.group(2).lower() or "<!doctype" in m.group(2).lower():
                    chosen = m
                    break
        elif t_lower.endswith(".py") or "python" in t_lower:
            for m in code_matches:
                if (m.group(1) or "").lower() in ("python", "py"):
                    chosen = m
                    break
        code_lang = (chosen.group(1) or "").lower()
        content = chosen.group(2)
    else:
        # Check if output has unclosed code fence (e.g. truncated generation)
        unclosed = re.search(r"```(\w+)?\r?\n(.*)", last_output, re.DOTALL)
        if unclosed and len(unclosed.group(2).strip()) > 30:
            code_lang = (unclosed.group(1) or "").lower()
            content = unclosed.group(2).strip()
        else:
            content = last_output.strip()

    # Determine destination file path
    if t_lower.endswith((".html", ".htm", ".py", ".js", ".css", ".txt", ".json", ".md", ".rs", ".csv")):
        p = Path(target_clean)
        parent_dir = resolve_target_dir(str(p.parent)) if str(p.parent) != "." else Path.cwd()
        final_p = parent_dir / p.name
    else:
        base_dir = resolve_target_dir(target_clean)
        c_lower = content.lower()
        if "<html" in c_lower or "<!doctype" in c_lower or "three.js" in c_lower or code_lang in ("html", "htm"):
            default_name = "game.html" if ("game" in last_query.lower() or "canvas" in c_lower or "game" in c_lower) else "index.html"
        elif "def " in content or "import " in content or code_lang in ("python", "py"):
            default_name = "app.py" if ("app" in last_query.lower() or "script" in last_query.lower() or "solve" in c_lower) else "main.py"
        elif "function " in content or "const " in content or code_lang in ("javascript", "js"):
            default_name = "script.js"
        elif code_lang == "json" or (content.startswith("{") and content.endswith("}")):
            default_name = "data.json"
        elif code_lang in ("rust", "rs"):
            default_name = "main.rs"
        else:
            default_name = "output.txt"
        final_p = base_dir / default_name

    try:
        final_p.parent.mkdir(parents=True, exist_ok=True)
        final_p.write_text(content, encoding="utf-8")
        byte_count = len(content.encode("utf-8"))
        set_active_project_dir(final_p.parent)
        return True, f"Saved {byte_count:,} bytes to {final_p}"
    except Exception as e:
        return False, f"Failed to save file: {e}"


_session_active_project: Optional[Path] = None


def get_active_project_dir() -> Optional[Path]:
    """Returns the currently active project directory in this session, if set and exists."""
    global _session_active_project
    if _session_active_project and _session_active_project.is_dir():
        return _session_active_project

    env_proj = os.environ.get("PAI_ACTIVE_PROJECT")
    if env_proj:
        p = Path(env_proj).expanduser().resolve()
        if p.is_dir():
            _session_active_project = p
            return p

    # Check session history for recently created project
    for h_entry in reversed(get_session_history()):
        if "[Successfully initialized new project in " in h_entry[2]:
            m = re.search(r'\[Successfully initialized new project in ([^\]]+)\]', h_entry[2])
            if m:
                cand = Path(m.group(1).strip()).resolve()
                if cand.is_dir():
                    _session_active_project = cand
                    return cand

    # Check recent project directory in Downloads
    user_downloads = Path.home() / "Downloads"
    if user_downloads.is_dir():
        recent_candidates = []
        try:
            for sub in user_downloads.iterdir():
                if sub.is_dir() and any((sub / f).is_file() for f in ("index.html", "script.js", "main.py")):
                    recent_candidates.append(sub)
            if recent_candidates:
                recent_candidates.sort(key=lambda d: d.stat().st_mtime, reverse=True)
                _session_active_project = recent_candidates[0]
                return recent_candidates[0]
        except Exception:
            pass

    return None


def set_active_project_dir(path: Union[str, Path]) -> Optional[Path]:
    """Sets the active project directory for this session."""
    global _session_active_project
    try:
        p = Path(path).expanduser().resolve()
        if p.is_file():
            p = p.parent
        if p.is_dir():
            _session_active_project = p
            os.environ["PAI_ACTIVE_PROJECT"] = str(p)
            return p
    except Exception:
        pass
    return None


def _safe_console_emit(emit_fn, text: str) -> None:
    """Calls emit_fn(text) and falls back to ASCII-safe tags if stream encoding rejects Unicode."""
    try:
        emit_fn(text)
    except UnicodeEncodeError:
        sanitized = (
            text.replace("⚠️", "[WARN]")
            .replace("⚠", "[WARN]")
            .replace("📁", "[DIR]")
            .replace("💡", "[TIP]")
            .replace("🚀", "[*]")
            .replace("🔌", "[MCP]")
            .replace("•", "*")
        )
        emit_fn(sanitized.encode("ascii", errors="replace").decode("ascii"))


def format_project_status(active_p: Path, color_enabled: bool = False) -> str:
    """Formats a concise status view of the active project and its key files."""
    header = colorize(f"📁 Active Project: {active_p}", CYAN, color_enabled)
    lines = [header]
    try:
        files = [f for f in active_p.iterdir() if f.is_file() and not f.name.endswith(".bak")]
        if files:
            lines.append("Files in project:")
            for f in sorted(files, key=lambda x: x.name):
                sz = f.stat().st_size
                sz_str = f"{sz} B" if sz < 1024 else f"{sz / 1024:.1f} KB"
                lines.append(f"  - {f.name} ({sz_str})")
        else:
            lines.append("  (No files in this project folder yet)")
    except Exception:
        pass
    tip = colorize("💡 Any modification instructions (e.g. 'make drone faster', 'add sound') will directly update files here.", DIM, color_enabled)
    lines.append(tip)
    return "\n".join(lines)


def resolve_target_file(target_str: str) -> Optional[Path]:
    """
    Resolves a target file path from string.
    Supports absolute paths, relative paths, special directories (Downloads, Desktop, Documents),
    and bare filenames by searching active project, cwd, Downloads, Desktop, Documents.
    Returns Path if file exists, None otherwise.
    """
    clean = target_str.strip().strip('"').strip("'")
    if not clean:
        return None

    # 0. Check active project directory first!
    active_proj = get_active_project_dir()
    if active_proj and active_proj.is_dir():
        cand = (active_proj / clean).resolve()
        if cand.is_file():
            return cand
        for ext in (".js", ".html", ".css", ".py", ".json", ".md", ".txt"):
            cand_ext = (active_proj / f"{clean}{ext}").resolve()
            if cand_ext.is_file():
                return cand_ext

    try:
        p = Path(clean).expanduser()
        if p.is_file():
            return p.resolve()
    except Exception:
        pass

    user_home = Path.home()
    c_lower = clean.lower()
    for prefix, folder in [
        ("downloads\\", user_home / "Downloads"),
        ("downloads/", user_home / "Downloads"),
        ("desktop\\", user_home / "Desktop"),
        ("desktop/", user_home / "Desktop"),
        ("documents\\", user_home / "Documents"),
        ("documents/", user_home / "Documents"),
    ]:
        if c_lower.startswith(prefix):
            sub = clean[len(prefix):]
            candidate = folder / sub
            if candidate.is_file():
                return candidate.resolve()

    if "\\" not in clean and "/" not in clean:
        for loc in [Path.cwd(), user_home / "Downloads", user_home / "Desktop", user_home / "Documents"]:
            try:
                candidate = loc / clean
                if candidate.is_file():
                    return candidate.resolve()
            except Exception:
                pass

    return None


def edit_target_file(
    target_str: str,
    instructions: str,
    stream=sys.stdout,
    executor: Optional[Callable[[List[str]], int]] = None,
) -> Tuple[bool, str, Optional[str]]:
    """
    Reads an existing local file, applies user modification instructions using the resident model,
    creates a .bak backup file, and saves the updated content back to disk.
    Returns (success, message, updated_content).
    """
    resolved_path = resolve_target_file(target_str)
    if not resolved_path:
        return False, f"Error: File not found: '{target_str}'. Please check the file name or path.", None

    try:
        original_content = resolved_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            original_content = resolved_path.read_text(encoding="cp1252")
        except Exception as e:
            return False, f"Error reading file '{resolved_path}': {e}", None
    except Exception as e:
        return False, f"Error reading file '{resolved_path}': {e}", None

    if not original_content.strip():
        return False, f"Error: Target file '{resolved_path}' is empty.", None

    suffix = resolved_path.suffix.lstrip(".").lower()
    lang_map = {
        "html": "html",
        "htm": "html",
        "py": "python",
        "js": "javascript",
        "jsx": "javascript",
        "ts": "typescript",
        "tsx": "typescript",
        "rs": "rust",
        "json": "json",
        "css": "css",
        "md": "markdown",
        "txt": "text",
    }
    lang = lang_map.get(suffix, suffix or "text")

    active_parent = resolved_path.parent
    other_context = ""
    if (active_parent / "index.html").is_file() and resolved_path.name != "index.html":
        try:
            h_snip = (active_parent / "index.html").read_text(encoding="utf-8", errors="replace")[:1000]
            other_context += f"\nProject index.html overview:\n```html\n{h_snip}...\n```\n"
        except Exception:
            pass

    edit_prompt = (
        f"You are an expert programmer and game developer modifying the project in '{active_parent.name}'.\n"
        f"Below is the complete content of the file '{resolved_path.name}':\n"
        f"```{lang}\n{original_content}\n```\n"
        f"{other_context}\n"
        f"User Modification Request:\n{instructions}\n\n"
        f"Apply all requested changes carefully.\n"
        f"Output the complete runnable updated code in a markdown code block.\n"
        f"If multiple files need updating (e.g. index.html and script.js), prefix each with a header:\n"
        f"### File: filename.ext\n```{lang}\n...complete file...\n```\n"
        f"Do not omit code, do not use comments like '// rest unchanged', and provide complete runnable code."
    )

    if executor is None:
        exec_fn = execute_subcommand
    else:
        exec_fn = executor

    candidate_models: List[Optional[str]] = [_active_model_override]
    for fb in ("qwen3.5:4b", "qwen2.5-coder:1.5b", "llama3.2:3b", "llama3.2:1b"):
        if fb not in candidate_models:
            candidate_models.append(fb)

    model_out = ""
    spinner = ThinkingSpinner(stream)
    try:
        spinner.start()
        for idx, m_cand in enumerate(candidate_models):
            chat_cmd = ["chat"]
            if m_cand:
                chat_cmd += ["--model", m_cand]
            chat_cmd += ["--model-timeout", "300.0", "--", edit_prompt]
            capture = CaptureStream(stream, on_first_write=spinner.stop)
            try:
                with contextlib.redirect_stdout(capture):
                    exec_fn(chat_cmd)
                cand_out = capture.getvalue().strip()
                if cand_out and len(cand_out) >= 10 and "```" in cand_out:
                    model_out = cand_out
                    break
            except Exception:
                pass

            if not model_out and idx < len(candidate_models) - 1:
                next_m = candidate_models[idx + 1]
                if m_cand and next_m:
                    warn_line = f"\n⚠️ Model '{m_cand}' timed out or was unresponsive. Auto-switching to fallback model '{next_m}'...\n"
                    _safe_console_emit(stream.write, warn_line)
                    stream.flush()
    except KeyboardInterrupt:
        return False, "Operation cancelled by user.", None
    except Exception as e:
        return False, f"Error generating file update: {e}", None
    finally:
        spinner.stop()

    if not model_out or not model_out.strip():
        return False, "Error: Model returned empty response.", None

    import re
    # Robust extraction pattern supporting closed and unclosed blocks, and file headers
    block_pattern = re.compile(
        r"(?:(?:###|####)\s*(?:\d+\.\s*)?(?:File:?\s*)?([a-zA-Z0-9_\-\.]+)[^\n]*\r?\n)?```([a-zA-Z0-9_\-]+)?\r?\n([\s\S]*?)(?:\r?\n```|\Z)"
    )
    extracted_blocks = list(block_pattern.finditer(model_out))

    updated_files = []
    primary_updated_content = None

    if extracted_blocks:
        for m in extracted_blocks:
            fname = m.group(1)
            lang_tag = (m.group(2) or "").lower()
            body = m.group(3).strip()
            if not fname:
                if lang_tag in ("javascript", "js") and (active_parent / "script.js").is_file():
                    fname = "script.js"
                elif lang_tag in ("html", "htm") and (active_parent / "index.html").is_file():
                    fname = "index.html"
                elif lang_tag == "css" and (active_parent / "style.css").is_file():
                    fname = "style.css"
                elif lang_tag in ("python", "py") and (active_parent / "main.py").is_file():
                    fname = "main.py"
                else:
                    fname = resolved_path.name

            if len(body) > 15:
                dest = active_parent / fname
                try:
                    if dest.is_file():
                        bak = dest.with_suffix(dest.suffix + ".bak")
                        bak.write_text(dest.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
                    dest.write_text(body, encoding="utf-8")
                    updated_files.append(dest)
                    if dest == resolved_path or primary_updated_content is None:
                        primary_updated_content = body
                except Exception:
                    pass

    if not updated_files:
        updated_content = model_out.strip()
        bak_path = resolved_path.with_suffix(resolved_path.suffix + ".bak")
        try:
            bak_path.write_text(original_content, encoding="utf-8")
        except Exception:
            pass
        try:
            resolved_path.write_text(updated_content, encoding="utf-8")
            updated_files.append(resolved_path)
            primary_updated_content = updated_content
        except Exception as e:
            return False, f"Error writing updated file '{resolved_path}': {e}", None

    set_active_project_dir(resolved_path.parent)

    msg_lines = []
    for uf in updated_files:
        msg_lines.append(f"[Successfully updated {uf}]")
    bak_note = f"[Backup saved to {resolved_path.with_suffix(resolved_path.suffix + '.bak')}]"
    msg_lines.append(bak_note)

    return True, "\n".join(msg_lines), primary_updated_content


def parse_natural_folder_intent(line: str) -> Optional[Tuple[str, str]]:
    """
    Detects natural language intent to create a folder or project.
    Returns (target_dir_str, original_prompt) or None.
    Handles English, Sinhala/Singlish, and directory references (Downloads, Desktop, Documents).
    """
    stripped = line.strip()
    lower = stripped.lower()

    # Informational questions should route to chat, not create folders
    if any(q in lower for q in ("how to", "how do", "kohomada", "what is", "mokakda", "explain", "pahasili", "why")):
        return None

    folder_triggers = (
        "create folder", "make folder", "new folder", "add folder",
        "folder ekak", "folder hada", "hadanna folder", "folder hadanna",
        "create project", "new project", "start project", "aluth project", "project ekak"
    )
    is_trigger = any(t in lower for t in folder_triggers) or lower.startswith(("mkdir ", "folder ", "project "))
    if not is_trigger:
        return None

    # 1. Determine base directory
    user_home = Path.home()
    if "downloads" in lower:
        base = user_home / "Downloads"
    elif "desktop" in lower:
        base = user_home / "Desktop"
    elif "documents" in lower:
        base = user_home / "Documents"
    else:
        base = Path.cwd()

    # 2. Extract folder name
    cand_name = None
    # Check for quotes first
    quote_match = re.search(r'["\']([^"\']+)["\']', stripped)
    if quote_match and any(k in lower for k in ("folder", "project", "mkdir")):
        val = quote_match.group(1).strip()
        if "\\" in val or "/" in val:
            cand_name = val.split("\\")[-1].split("/")[-1]
        else:
            cand_name = val

    if not cand_name:
        # Patterns in English & Sinhala:
        # 1. name it as / name it ad / named as / called
        m = re.search(r'(?:name\s+it\s+(?:as|ad|a|to)?\s*|named\s+(?:as|ad|a|to)?\s*|called\s+(?:as|ad|a|to)?\s*)\s*([a-zA-Z0-9_\-\s]+?)(?:\s+(?:and|with|for|to|&|then|hadala|create|make|aluth)\b|$)', stripped, re.I)
        if m:
            cand_name = m.group(1).strip()

    if not cand_name:
        # 2. <name> kiyala / <name> namata
        m = re.search(r'([a-zA-Z0-9_\-]+(?:\s+[a-zA-Z0-9_\-]+)?)\s+(?:kiyala|namata|kiyana\s+namata)', stripped, re.I)
        if m:
            extracted = m.group(1).strip()
            cleaned = re.sub(r'\b(folder|project|ekak|hadala|hadanna|aluth|in|downloads|desktop|documents)\b', '', extracted, flags=re.I).strip()
            if cleaned:
                cand_name = cleaned

    if not cand_name:
        # 3. create folder <name> in downloads OR create folder <name>
        m = re.search(r'(?:create\s+folder|make\s+folder|new\s+folder|create\s+project|new\s+project)\s+(?:in\s+\w+\s+)?(?:called\s+|named\s+)?([a-zA-Z0-9_\-\s]+?)(?:\s+(?:and|with|for|to|&|then|hadala|create|make|aluth)\b|$)', stripped, re.I)
        if m:
            raw = m.group(1).strip()
            cleaned = re.sub(r'\b(in\s+downloads|in\s+desktop|in\s+documents|downloads|desktop|documents)\b', '', raw, flags=re.I).strip()
            cleaned = re.sub(r'\b(name\s+it\s+(?:as|ad|a|to)?|name\s+it|as|called|named)\b', '', cleaned, flags=re.I).strip()
            if cleaned:
                cand_name = cleaned

    if not cand_name:
        # 4. Check if the last token is an explicit name
        tokens = stripped.split()
        stopwords = {
            'ekak', 'hadala', 'hadanna', 'patan', 'ganna', 'aluth', 'new', 'in', 'as',
            'a', 'an', 'the', 'project', 'folder', 'karanna', 'danna', 'methana',
            'downloads', 'desktop', 'documents', 'eke', 'wala', 'namata', 'kiyala'
        }
        for t in reversed(tokens):
            clean_t = t.strip('.,;:?!"\'')
            if clean_t and clean_t.lower() not in stopwords:
                cand_name = clean_t
                break

    if not cand_name:
        cand_name = "my_project"

    cand_name = re.sub(r'^(?:a|an|the)\s+', '', cand_name, flags=re.I).strip()
    cand_name = re.sub(r'\s+(?:and|with|for|to|&|then|hadala|create|make|aluth|save)\b.*$', '', cand_name, flags=re.I).strip()
    target_path = base / cand_name
    return str(target_path), stripped


def parse_natural_save_intent(line: str) -> Optional[str]:
    """
    Detects natural language intent to save output or code from chat to a file or folder.
    Returns target path string (e.g. 'Downloads/dron simulator', 'Downloads', 'app.py') or None.
    Handles English, Sinhala/Singlish, backticks, quotes, and special directories.
    """
    stripped = line.strip()
    lower = stripped.lower()

    # Informational questions route to chat
    if any(q in lower for q in ("how to", "how do", "kohomada", "what is", "mokakda", "explain", "why")):
        return None

    # Guard: Prompts asking to create, make, build, write, code, or generate
    # are CREATION prompts (project scaffold or chat generation), NEVER save-last-response commands!
    creation_prefixes = (
        "create ", "make ", "new ", "start ", "build ", "generate ",
        "write ", "code ", "aluth ", "hadanna ", "hadala ", "patan "
    )
    if lower.startswith(creation_prefixes) or any(k in lower for k in ("create folder", "make folder", "new folder", "create project", "new project")):
        return None

    save_triggers = (
        "save it", "save this", "save that", "save code", "save file", "save game",
        "save project", "save to", "save in", "save into", "save karanna", "save karapan",
        "save karala", "save danna", "save wenna"
    )
    is_save = any(t in lower for t in save_triggers) or lower.startswith(("save ", "save:")) or lower in ("save", "save it", "save this", "save that")
    if not is_save and any(k in lower for k in ("save", "save.")) and any(k in lower for k in ("karanna", "karapan", "danna", "eke", "ekata", "folder")):
        is_save = True

    if not is_save:
        return None

    target = None

    # 1. Backticks: `path/to/folder`
    bt_match = re.search(r'`([^`]+)`', stripped)
    if bt_match:
        target = bt_match.group(1).strip()

    # 2. Quotes: 'path/to/folder' or "path/to/folder"
    if not target:
        q_match = re.search(r'["\']([^"\']+)["\']', stripped)
        if q_match:
            target = q_match.group(1).strip()

    # 3. 'in <name> folder in downloads' or 'to <name> folder in downloads'
    if not target:
        m = re.search(r'(?:in|to|into)\s+([a-zA-Z0-9_\-\s]+?)\s+folder\s+in\s+downloads', stripped, re.I)
        if m:
            folder_name = m.group(1).strip()
            target = f"Downloads/{folder_name}"

    # 4. 'in/to/into downloads\<name>' or 'downloads/<name>' (handling spaces and folder names)
    if not target:
        m = re.search(r'(?:in|to|into)\s+((?:downloads|desktop|documents)[\\\/][a-zA-Z0-9_\-\s\.]+?)(?:\s+folder|\.|$)', stripped, re.I)
        if m:
            target = m.group(1).strip()

    # 5. 'save it as <file> in <dir>'
    if not target:
        m = re.search(r'save\s+(?:it\s+)?as\s+([a-zA-Z0-9_\-\.]+)\s+in\s+([a-zA-Z0-9_\-\\\/\s]+)', stripped, re.I)
        if m:
            fname = m.group(1).strip()
            dname = m.group(2).strip().rstrip(".")
            target = f"{dname}/{fname}"

    # 6. Sinhala patterns: 'downloads eke <name> folder eke save karanna' or '<name> folder ekata save'
    if not target:
        m = re.search(r'(?:downloads\s+eke\s+)?([a-zA-Z0-9_\-]+(?:\s+[a-zA-Z0-9_\-]+)?)\s+(?:folder\s+eke|folder\s+ekata|ekata|eke)\s+save', stripped, re.I)
        if m:
            extracted = m.group(1).strip()
            cleaned = re.sub(r'\b(downloads|eke|folder|ekata|karanna|danna)\b', '', extracted, flags=re.I).strip()
            if cleaned:
                target = f"Downloads/{cleaned}" if "downloads" in lower else cleaned

    # 7. Sinhala: 'save karanna downloads eke <name> folder ekata'
    if not target and any(k in lower for k in ("save karanna", "save karapan", "save danna")):
        m = re.search(r'save\s+(?:karanna|karapan|danna)\s+(?:downloads\s+eke\s+)?([a-zA-Z0-9_\-]+(?:\s+[a-zA-Z0-9_\-]+)?)\s*(?:folder\s+ekata|folder\s+eke|ekata|eke)?', stripped, re.I)
        if m:
            extracted = m.group(1).strip()
            cleaned = re.sub(r'\b(downloads|eke|folder|ekata|karanna|karapan|danna|aluth)\b', '', extracted, flags=re.I).strip()
            if cleaned:
                target = f"Downloads/{cleaned}" if "downloads" in lower else cleaned

    # 8. 'in <dir> folder' or 'to <dir> folder'
    if not target:
        m = re.search(r'(?:in|to|into)\s+([a-zA-Z0-9_\-\s]+?)\s+folder', stripped, re.I)
        if m:
            cand = m.group(1).strip()
            cleaned = re.sub(r'\b(the|a|an|this|that|my)\b', '', cand, flags=re.I).strip()
            if cleaned and cleaned.lower() not in ("it", "this", "that", "code", "game"):
                target = f"Downloads/{cleaned}" if "downloads" in lower else cleaned

    # 9. 'save <path>' (direct path argument)
    if not target and lower.startswith("save "):
        cand = stripped[5:].strip()
        cleaned = re.sub(r'\b(it|this|that|the|a|an|file|code|game|folder|now|karanna|karapan)\b', '', cand, flags=re.I).strip()
        if cleaned:
            target = cleaned

    # Default to Downloads if no specific folder was given
    if not target or target.lower() in ("it", "this", "that", "file", "code", "game", "now", "folder"):
        if "downloads" in lower:
            target = "Downloads"
        elif "desktop" in lower:
            target = "Desktop"
        elif "documents" in lower:
            target = "Documents"
        else:
            target = "Downloads"

    # Clean trailing punctuation and keywords
    target = re.sub(r'[\.\,\;\:\?\!]+$', '', target).strip()
    target = re.sub(r'\s+folder$', '', target, flags=re.I).strip()
    return target


def create_project_scaffold(
    target_dir_str: str,
    project_type_or_prompt: str = "",
    stream=sys.stdout,
) -> Tuple[bool, str, List[str]]:
    """
    Creates a new project directory and scaffolds initial files based on type or instructions.
    Supports web (HTML/CSS/JS), Python, and custom project scaffolding.
    Returns (success, message, created_files).
    """
    clean_target = target_dir_str.strip().strip('"').strip("'")
    target_path = resolve_target_dir(clean_target)
    try:
        target_path.mkdir(parents=True, exist_ok=True)
        set_active_project_dir(target_path)
    except Exception as e:
        return False, f"Error creating directory '{target_path}': {e}", []

    prompt_lower = (project_type_or_prompt or "").lower()
    created_files: List[str] = []

    is_drone_game = any(k in prompt_lower for k in ("drone", "dron", "shooting", "military", "flight", "turret"))
    is_threejs = any(k in prompt_lower for k in ("three", "threejs", "treejs", "tree.js", "3d", "webgl")) or is_drone_game

    # 1. Web / HTML / Game project
    if any(k in prompt_lower for k in ("web", "html", "game", "threejs", "frontend", "canvas", "css", "js")) or not prompt_lower or is_threejs:
        index_html = target_path / "index.html"
        style_css = target_path / "style.css"
        script_js = target_path / "script.js"
        readme_md = target_path / "README.md"

        title = target_path.name.replace("_", " ").replace("-", " ").title()
        if not index_html.exists():
            if is_drone_game:
                html_body = (
                    f"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
                    f"  <meta charset=\"UTF-8\">\n"
                    f"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
                    f"  <title>{title} - Realistic Military Drone Shooter 3D</title>\n"
                    f"  <link rel=\"stylesheet\" href=\"style.css\">\n"
                    f"  <script src=\"https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js\"></script>\n"
                    f"</head>\n<body>\n"
                    f"  <div id=\"hud\">\n"
                    f"    <div class=\"hud-bar top-bar\">\n"
                    f"      <div class=\"hud-panel\"><span class=\"label\">UAV:</span> <strong>MQ-9 REAPER [ACTIVE]</strong></div>\n"
                    f"      <div class=\"hud-panel\"><span class=\"label\">TARGETS:</span> <span id=\"scoreVal\">0</span> / 8</div>\n"
                    f"      <div class=\"hud-panel\"><span class=\"label\">ALT:</span> <span id=\"altVal\">45</span>m | <span class=\"label\">SPD:</span> <span id=\"spdVal\">0</span> km/h</div>\n"
                    f"    </div>\n"
                    f"    <div id=\"crosshair\"><div class=\"reticle\"></div></div>\n"
                    f"    <div class=\"hud-bar bottom-bar\">\n"
                    f"      <div class=\"hud-panel\"><span class=\"label\">HULL:</span> <span id=\"hpVal\">100%</span></div>\n"
                    f"      <div class=\"hud-panel\"><span class=\"label\">AMMO:</span> <span id=\"ammoVal\">500</span> [SPACE TO FIRE]</div>\n"
                    f"      <div class=\"hud-panel controls-hint\">W/S: Pitch/Thrust | A/D: Turn | SPACE: Shoot | SHIFT: Boost | R: Reset</div>\n"
                    f"    </div>\n"
                    f"  </div>\n"
                    f"  <script src=\"script.js\"></script>\n"
                    f"</body>\n</html>\n"
                )
            elif is_threejs:
                html_body = (
                    f"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
                    f"  <meta charset=\"UTF-8\">\n"
                    f"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
                    f"  <title>{title} (3D Three.js)</title>\n"
                    f"  <link rel=\"stylesheet\" href=\"style.css\">\n"
                    f"  <script src=\"https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js\"></script>\n"
                    f"</head>\n<body>\n"
                    f"  <div id=\"overlay\" style=\"position:absolute;top:16px;left:16px;color:#00ff88;font-family:sans-serif;z-index:10;text-shadow:0 0 8px rgba(0,255,136,0.5);\">\n"
                    f"    <h1 style=\"margin:0;\">{title}</h1>\n"
                    f"    <p style=\"margin:4px 0 0;\">3D Web Game powered by Three.js</p>\n"
                    f"  </div>\n"
                    f"  <script src=\"script.js\"></script>\n"
                    f"</body>\n</html>\n"
                )
            else:
                html_body = (
                    f"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
                    f"  <meta charset=\"UTF-8\">\n"
                    f"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
                    f"  <title>{title}</title>\n"
                    f"  <link rel=\"stylesheet\" href=\"style.css\">\n"
                    f"</head>\n<body>\n"
                    f"  <div id=\"app\">\n"
                    f"    <h1>{title}</h1>\n"
                    f"    <canvas id=\"mainCanvas\"></canvas>\n"
                    f"  </div>\n"
                    f"  <script src=\"script.js\"></script>\n"
                    f"</body>\n</html>\n"
                )
            index_html.write_text(html_body, encoding="utf-8")
            created_files.append("index.html")

        if not style_css.exists():
            if is_drone_game:
                css_body = (
                    "body {\n"
                    "  margin: 0;\n"
                    "  padding: 0;\n"
                    "  overflow: hidden;\n"
                    "  background: #050a14;\n"
                    "  font-family: 'Courier New', Courier, monospace;\n"
                    "  color: #00ff88;\n"
                    "  user-select: none;\n"
                    "}\n"
                    "canvas {\n"
                    "  display: block;\n"
                    "  width: 100vw;\n"
                    "  height: 100vh;\n"
                    "}\n"
                    "#hud {\n"
                    "  position: absolute;\n"
                    "  top: 0; left: 0; width: 100%; height: 100%;\n"
                    "  pointer-events: none;\n"
                    "  display: flex;\n"
                    "  flex-direction: column;\n"
                    "  justify-content: space-between;\n"
                    "  box-sizing: border-box;\n"
                    "  padding: 16px 20px;\n"
                    "}\n"
                    ".hud-bar {\n"
                    "  display: flex;\n"
                    "  justify-content: space-between;\n"
                    "  align-items: center;\n"
                    "}\n"
                    ".hud-panel {\n"
                    "  background: rgba(5, 18, 30, 0.85);\n"
                    "  border: 1px solid #00ff88;\n"
                    "  box-shadow: 0 0 10px rgba(0, 255, 136, 0.3);\n"
                    "  padding: 6px 14px;\n"
                    "  border-radius: 4px;\n"
                    "  font-size: 13px;\n"
                    "  font-weight: bold;\n"
                    "  letter-spacing: 1px;\n"
                    "  text-shadow: 0 0 6px rgba(0, 255, 136, 0.8);\n"
                    "}\n"
                    ".hud-panel .label {\n"
                    "  color: #77bbaa;\n"
                    "  font-size: 11px;\n"
                    "}\n"
                    ".controls-hint {\n"
                    "  font-size: 12px;\n"
                    "  color: #aaffdd;\n"
                    "}\n"
                    "#crosshair {\n"
                    "  position: absolute;\n"
                    "  top: 50%; left: 50%;\n"
                    "  transform: translate(-50%, -50%);\n"
                    "  width: 40px; height: 40px;\n"
                    "}\n"
                    ".reticle {\n"
                    "  position: relative;\n"
                    "  width: 100%; height: 100%;\n"
                    "  border: 2px solid rgba(0, 255, 136, 0.8);\n"
                    "  border-radius: 50%;\n"
                    "  box-shadow: 0 0 8px #00ff88;\n"
                    "}\n"
                    ".reticle::before {\n"
                    "  content: '';\n"
                    "  position: absolute;\n"
                    "  top: 19px; left: -10px; width: 60px; height: 2px;\n"
                    "  background: rgba(0, 255, 136, 0.8);\n"
                    "}\n"
                    ".reticle::after {\n"
                    "  content: '';\n"
                    "  position: absolute;\n"
                    "  top: -10px; left: 19px; width: 2px; height: 60px;\n"
                    "  background: rgba(0, 255, 136, 0.8);\n"
                    "}\n"
                )
            elif is_threejs:
                css_body = (
                    "body {\n"
                    "  margin: 0;\n"
                    "  padding: 0;\n"
                    "  overflow: hidden;\n"
                    "  background: #0d0d1a;\n"
                    "}\n"
                    "canvas {\n"
                    "  display: block;\n"
                    "  width: 100vw;\n"
                    "  height: 100vh;\n"
                    "}\n"
                )
            else:
                css_body = (
                    "body {\n"
                    "  margin: 0;\n"
                    "  padding: 0;\n"
                    "  background: #111;\n"
                    "  color: #fff;\n"
                    "  font-family: sans-serif;\n"
                    "  display: flex;\n"
                    "  justify-content: center;\n"
                    "  align-items: center;\n"
                    "  min-height: 100vh;\n"
                    "}\n"
                    "#app {\n"
                    "  text-align: center;\n"
                    "}\n"
                    "canvas {\n"
                    "  border: 1px solid #333;\n"
                    "  border-radius: 8px;\n"
                    "  background: #000;\n"
                    "}\n"
                )
            style_css.write_text(css_body, encoding="utf-8")
            created_files.append("style.css")

        if not script_js.exists():
            if is_drone_game:
                js_content = (
                    f"// {title} - Realistic Military Drone Shooter 3D (Three.js)\n"
                    "window.addEventListener('DOMContentLoaded', () => {\n"
                    "  if (typeof THREE === 'undefined') {\n"
                    "    console.error('Three.js CDN not available');\n"
                    "    return;\n"
                    "  }\n\n"
                    "  // 1. Audio System (Procedural Web Audio API)\n"
                    "  let audioCtx = null;\n"
                    "  function initAudio() {\n"
                    "    if (!audioCtx) {\n"
                    "      audioCtx = new (window.AudioContext || window.webkitAudioContext)();\n"
                    "    }\n"
                    "  }\n"
                    "  function playLaser() {\n"
                    "    if (!audioCtx) return;\n"
                    "    const osc = audioCtx.createOscillator();\n"
                    "    const gain = audioCtx.createGain();\n"
                    "    osc.type = 'sawtooth';\n"
                    "    osc.frequency.setValueAtTime(880, audioCtx.currentTime);\n"
                    "    osc.frequency.exponentialRampToValueAtTime(110, audioCtx.currentTime + 0.12);\n"
                    "    gain.gain.setValueAtTime(0.2, audioCtx.currentTime);\n"
                    "    gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.12);\n"
                    "    osc.connect(gain);\n"
                    "    gain.connect(audioCtx.destination);\n"
                    "    osc.start();\n"
                    "    osc.stop(audioCtx.currentTime + 0.13);\n"
                    "  }\n"
                    "  function playBoom() {\n"
                    "    if (!audioCtx) return;\n"
                    "    const bufSize = audioCtx.sampleRate * 0.4;\n"
                    "    const buffer = audioCtx.createBuffer(1, bufSize, audioCtx.sampleRate);\n"
                    "    const data = buffer.getChannelData(0);\n"
                    "    for (let i = 0; i < bufSize; i++) data[i] = Math.random() * 2 - 1;\n"
                    "    const noise = audioCtx.createBufferSource();\n"
                    "    noise.buffer = buffer;\n"
                    "    const filter = audioCtx.createBiquadFilter();\n"
                    "    filter.type = 'lowpass';\n"
                    "    filter.frequency.setValueAtTime(600, audioCtx.currentTime);\n"
                    "    filter.frequency.exponentialRampToValueAtTime(40, audioCtx.currentTime + 0.4);\n"
                    "    const gain = audioCtx.createGain();\n"
                    "    gain.gain.setValueAtTime(0.4, audioCtx.currentTime);\n"
                    "    gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.4);\n"
                    "    noise.connect(filter);\n"
                    "    filter.connect(gain);\n"
                    "    gain.connect(audioCtx.destination);\n"
                    "    noise.start();\n"
                    "  }\n\n"
                    "  // 2. Scene, Camera, Lighting\n"
                    "  const scene = new THREE.Scene();\n"
                    "  scene.background = new THREE.Color(0x060c18);\n"
                    "  scene.fog = new THREE.FogExp2(0x060c18, 0.0035);\n"
                    "  const camera = new THREE.PerspectiveCamera(65, window.innerWidth / window.innerHeight, 0.1, 2000);\n"
                    "  const renderer = new THREE.WebGLRenderer({ antialias: true });\n"
                    "  renderer.setSize(window.innerWidth, window.innerHeight);\n"
                    "  renderer.setPixelRatio(window.devicePixelRatio);\n"
                    "  renderer.shadowMap.enabled = true;\n"
                    "  document.body.appendChild(renderer.domElement);\n\n"
                    "  const ambient = new THREE.AmbientLight(0x446688, 0.8);\n"
                    "  scene.add(ambient);\n"
                    "  const sun = new THREE.DirectionalLight(0xffffff, 1.2);\n"
                    "  sun.position.set(100, 200, 100);\n"
                    "  scene.add(sun);\n\n"
                    "  // 3. Ground & Environment\n"
                    "  const groundGeo = new THREE.PlaneGeometry(3000, 3000, 60, 60);\n"
                    "  const groundMat = new THREE.MeshStandardMaterial({ color: 0x0a141e, roughness: 0.8, metalness: 0.2 });\n"
                    "  const ground = new THREE.Mesh(groundGeo, groundMat);\n"
                    "  ground.rotation.x = -Math.PI / 2;\n"
                    "  scene.add(ground);\n"
                    "  const grid = new THREE.GridHelper(3000, 150, 0x00ff88, 0x112233);\n"
                    "  grid.position.y = 0.2;\n"
                    "  scene.add(grid);\n\n"
                    "  // Military bunkers and towers\n"
                    "  const buildingMat = new THREE.MeshStandardMaterial({ color: 0x1f2937, roughness: 0.5 });\n"
                    "  for (let i = 0; i < 40; i++) {\n"
                    "    const bx = (Math.random() - 0.5) * 1600;\n"
                    "    const bz = (Math.random() - 0.5) * 1600;\n"
                    "    const bh = 20 + Math.random() * 60;\n"
                    "    const bGeo = new THREE.BoxGeometry(30 + Math.random() * 30, bh, 30 + Math.random() * 30);\n"
                    "    const bMesh = new THREE.Mesh(bGeo, buildingMat);\n"
                    "    bMesh.position.set(bx, bh / 2, bz);\n"
                    "    scene.add(bMesh);\n"
                    "  }\n\n"
                    "  // 4. Player Military Drone Model\n"
                    "  const drone = new THREE.Group();\n"
                    "  const bodyMat = new THREE.MeshStandardMaterial({ color: 0x242e38, metalness: 0.8, roughness: 0.3 });\n"
                    "  const accentMat = new THREE.MeshStandardMaterial({ color: 0x00ff88, emissive: 0x00ff88, emissiveIntensity: 0.5 });\n"
                    "  const droneBody = new THREE.Mesh(new THREE.BoxGeometry(1.6, 0.4, 2.6), bodyMat);\n"
                    "  drone.add(droneBody);\n"
                    "  const wingMat = new THREE.MeshStandardMaterial({ color: 0x111827, metalness: 0.7 });\n"
                    "  const wings = new THREE.Mesh(new THREE.BoxGeometry(6.0, 0.1, 0.8), wingMat);\n"
                    "  wings.position.set(0, 0.1, 0.2);\n"
                    "  drone.add(wings);\n"
                    "  // Rotors\n"
                    "  const rotors = [];\n"
                    "  const rotorOffsets = [\n"
                    "    [-2.8, 0.3, 0.2], [2.8, 0.3, 0.2], [-1.0, 0.3, 1.4], [1.0, 0.3, 1.4]\n"
                    "  ];\n"
                    "  rotorOffsets.forEach(([rx, ry, rz]) => {\n"
                    "    const blade = new THREE.Mesh(new THREE.BoxGeometry(1.6, 0.04, 0.12), accentMat);\n"
                    "    blade.position.set(rx, ry, rz);\n"
                    "    drone.add(blade);\n"
                    "    rotors.push(blade);\n"
                    "  });\n"
                    "  drone.position.set(0, 45, 0);\n"
                    "  scene.add(drone);\n\n"
                    "  // 5. Hostile Enemy Drones\n"
                    "  const enemies = [];\n"
                    "  const enemyMat = new THREE.MeshStandardMaterial({ color: 0xaa2222, emissive: 0xff1111, emissiveIntensity: 0.4 });\n"
                    "  function spawnEnemy(x, y, z) {\n"
                    "    const eGroup = new THREE.Group();\n"
                    "    const eMesh = new THREE.Mesh(new THREE.OctahedronGeometry(2.2, 0), enemyMat);\n"
                    "    eGroup.add(eMesh);\n"
                    "    eGroup.position.set(x, y, z);\n"
                    "    eGroup.userData = { hp: 100, maxHp: 100, initialY: y, speed: 0.4 + Math.random() * 0.4 };\n"
                    "    scene.add(eGroup);\n"
                    "    enemies.push(eGroup);\n"
                    "  }\n"
                    "  for (let i = 0; i < 8; i++) {\n"
                    "    const ang = (i / 8) * Math.PI * 2;\n"
                    "    const dist = 120 + Math.random() * 180;\n"
                    "    spawnEnemy(Math.cos(ang) * dist, 35 + Math.random() * 30, Math.sin(ang) * dist);\n"
                    "  }\n\n"
                    "  // 6. Projectiles and Particle Explosions\n"
                    "  const bullets = [];\n"
                    "  const bulletMat = new THREE.MeshBasicMaterial({ color: 0x00ffff });\n"
                    "  const particles = [];\n"
                    "  function spawnExplosion(pos) {\n"
                    "    playBoom();\n"
                    "    for (let i = 0; i < 24; i++) {\n"
                    "      const p = new THREE.Mesh(new THREE.BoxGeometry(0.3, 0.3, 0.3), new THREE.MeshBasicMaterial({ color: Math.random() > 0.5 ? 0xff4400 : 0xffcc00 }));\n"
                    "      p.position.copy(pos);\n"
                    "      p.userData = {\n"
                    "        vx: (Math.random() - 0.5) * 1.6,\n"
                    "        vy: (Math.random() - 0.2) * 1.6,\n"
                    "        vz: (Math.random() - 0.5) * 1.6,\n"
                    "        life: 1.0\n"
                    "      };\n"
                    "      scene.add(p);\n"
                    "      particles.push(p);\n"
                    "    }\n"
                    "  }\n\n"
                    "  // 7. Flight Physics State\n"
                    "  const keys = {};\n"
                    "  let speed = 0;\n"
                    "  let droneYaw = 0;\n"
                    "  let dronePitch = 0;\n"
                    "  let droneRoll = 0;\n"
                    "  let score = 0;\n"
                    "  let ammo = 500;\n"
                    "  let hull = 100;\n"
                    "  let lastShotTime = 0;\n\n"
                    "  window.addEventListener('keydown', (e) => {\n"
                    "    keys[e.code] = true;\n"
                    "    initAudio();\n"
                    "    if (e.code === 'KeyR') {\n"
                    "      drone.position.set(0, 45, 0);\n"
                    "      speed = 0;\n"
                    "      hull = 100;\n"
                    "    }\n"
                    "  });\n"
                    "  window.addEventListener('keyup', (e) => { keys[e.code] = false; });\n\n"
                    "  function shoot() {\n"
                    "    if (ammo <= 0) return;\n"
                    "    const now = performance.now();\n"
                    "    if (now - lastShotTime < 140) return;\n"
                    "    lastShotTime = now;\n"
                    "    ammo--;\n"
                    "    playLaser();\n\n"
                    "    const forward = new THREE.Vector3(0, 0, -1).applyQuaternion(drone.quaternion);\n"
                    "    const b = new THREE.Mesh(new THREE.CylinderGeometry(0.08, 0.08, 1.4), bulletMat);\n"
                    "    b.quaternion.copy(drone.quaternion);\n"
                    "    b.rotateX(Math.PI / 2);\n"
                    "    b.position.copy(drone.position).add(forward.clone().multiplyScalar(2.0));\n"
                    "    b.userData = { vel: forward.multiplyScalar(4.5), life: 120 };\n"
                    "    scene.add(b);\n"
                    "    bullets.push(b);\n"
                    "  }\n\n"
                    "  // 8. Main Loop & Physics Update\n"
                    "  function animate() {\n"
                    "    requestAnimationFrame(animate);\n\n"
                    "    // Rotors spin\n"
                    "    rotors.forEach(r => { r.rotation.y += 0.8; });\n\n"
                    "    // Flight controls\n"
                    "    const accel = keys['ShiftLeft'] ? 0.06 : 0.03;\n"
                    "    const maxSpd = keys['ShiftLeft'] ? 2.8 : 1.6;\n"
                    "    if (keys['KeyW'] || keys['ArrowUp']) speed = Math.min(speed + accel, maxSpd);\n"
                    "    else if (keys['KeyS'] || keys['ArrowDown']) speed = Math.max(speed - accel * 1.5, -0.4);\n"
                    "    else speed *= 0.98; // Drag damping\n\n"
                    "    if (keys['KeyA'] || keys['ArrowLeft']) {\n"
                    "      droneYaw += 0.03;\n"
                    "      droneRoll = THREE.MathUtils.lerp(droneRoll, 0.4, 0.1);\n"
                    "    } else if (keys['KeyD'] || keys['ArrowRight']) {\n"
                    "      droneYaw -= 0.03;\n"
                    "      droneRoll = THREE.MathUtils.lerp(droneRoll, -0.4, 0.1);\n"
                    "    } else {\n"
                    "      droneRoll = THREE.MathUtils.lerp(droneRoll, 0, 0.1);\n"
                    "    }\n\n"
                    "    if (keys['Space']) shoot();\n\n"
                    "    // Update drone attitude & motion\n"
                    "    dronePitch = THREE.MathUtils.lerp(dronePitch, (speed / maxSpd) * 0.35, 0.1);\n"
                    "    drone.rotation.set(0, 0, 0);\n"
                    "    drone.rotation.y = droneYaw;\n"
                    "    drone.rotation.x = dronePitch;\n"
                    "    drone.rotation.z = droneRoll;\n\n"
                    "    const forward = new THREE.Vector3(0, 0, -1).applyQuaternion(drone.quaternion);\n"
                    "    drone.position.add(forward.multiplyScalar(speed));\n"
                    "    if (drone.position.y < 4) drone.position.y = 4;\n\n"
                    "    // Third-person camera follow\n"
                    "    const camOffset = new THREE.Vector3(0, 4.5, 12).applyAxisAngle(new THREE.Vector3(0, 1, 0), droneYaw);\n"
                    "    camera.position.lerp(drone.position.clone().add(camOffset), 0.15);\n"
                    "    camera.lookAt(drone.position.clone().add(forward.clone().multiplyScalar(20)));\n\n"
                    "    // Update projectiles\n"
                    "    for (let i = bullets.length - 1; i >= 0; i--) {\n"
                    "      const b = bullets[i];\n"
                    "      b.position.add(b.userData.vel);\n"
                    "      b.userData.life--;\n\n"
                    "      // Hit detection with enemies\n"
                    "      let hit = false;\n"
                    "      for (let j = enemies.length - 1; j >= 0; j--) {\n"
                    "        const e = enemies[j];\n"
                    "        if (b.position.distanceTo(e.position) < 3.5) {\n"
                    "          e.userData.hp -= 35;\n"
                    "          hit = true;\n"
                    "          if (e.userData.hp <= 0) {\n"
                    "            spawnExplosion(e.position);\n"
                    "            scene.remove(e);\n"
                    "            enemies.splice(j, 1);\n"
                    "            score++;\n"
                    "          }\n"
                    "          break;\n"
                    "        }\n"
                    "      }\n"
                    "      if (hit || b.userData.life <= 0 || b.position.y < 0) {\n"
                    "        scene.remove(b);\n"
                    "        bullets.splice(i, 1);\n"
                    "      }\n"
                    "    }\n\n"
                    "    // Update particle explosions\n"
                    "    for (let i = particles.length - 1; i >= 0; i--) {\n"
                    "      const p = particles[i];\n"
                    "      p.position.x += p.userData.vx;\n"
                    "      p.position.y += p.userData.vy;\n"
                    "      p.position.z += p.userData.vz;\n"
                    "      p.userData.life -= 0.03;\n"
                    "      p.scale.multiplyScalar(0.96);\n"
                    "      if (p.userData.life <= 0) {\n"
                    "        scene.remove(p);\n"
                    "        particles.splice(i, 1);\n"
                    "      }\n"
                    "    }\n\n"
                    "    // Enemy patrol\n"
                    "    const time = performance.now() * 0.001;\n"
                    "    enemies.forEach((e, idx) => {\n"
                    "      e.position.y = e.userData.initialY + Math.sin(time * 2 + idx) * 3;\n"
                    "      e.rotation.y += 0.02;\n"
                    "    });\n\n"
                    "    // Update HUD\n"
                    "    const altEl = document.getElementById('altVal');\n"
                    "    const spdEl = document.getElementById('spdVal');\n"
                    "    const scoreEl = document.getElementById('scoreVal');\n"
                    "    const hpEl = document.getElementById('hpVal');\n"
                    "    const ammoEl = document.getElementById('ammoVal');\n"
                    "    if (altEl) altEl.textContent = Math.round(drone.position.y);\n"
                    "    if (spdEl) spdEl.textContent = Math.round(Math.abs(speed) * 120);\n"
                    "    if (scoreEl) scoreEl.textContent = score;\n"
                    "    if (hpEl) hpEl.textContent = hull + '%';\n"
                    "    if (ammoEl) ammoEl.textContent = ammo;\n\n"
                    "    renderer.render(scene, camera);\n"
                    "  }\n"
                    "  animate();\n\n"
                    "  window.addEventListener('resize', () => {\n"
                    "    camera.aspect = window.innerWidth / window.innerHeight;\n"
                    "    camera.updateProjectionMatrix();\n"
                    "    renderer.setSize(window.innerWidth, window.innerHeight);\n"
                    "  });\n"
                    "});\n"
                )
            elif is_threejs:
                js_content = (
                    f"// {title} - Three.js 3D Game\n"
                    f"console.log('{title} 3D initialized.');\n\n"
                    "window.addEventListener('DOMContentLoaded', () => {\n"
                    "  if (typeof THREE === 'undefined') {\n"
                    "    console.warn('Three.js CDN not loaded; falling back to canvas.');\n"
                    "    return;\n"
                    "  }\n\n"
                    "  // 1. Scene, Camera, Renderer\n"
                    "  const scene = new THREE.Scene();\n"
                    "  scene.background = new THREE.Color(0x0d0d1a);\n"
                    "  const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);\n"
                    "  camera.position.set(0, 2, 5);\n\n"
                    "  const renderer = new THREE.WebGLRenderer({ antialias: true });\n"
                    "  renderer.setSize(window.innerWidth, window.innerHeight);\n"
                    "  renderer.setPixelRatio(window.devicePixelRatio);\n"
                    "  document.body.appendChild(renderer.domElement);\n\n"
                    "  // 2. Lighting\n"
                    "  const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);\n"
                    "  scene.add(ambientLight);\n"
                    "  const pointLight = new THREE.PointLight(0x00ff88, 2, 50);\n"
                    "  pointLight.position.set(5, 5, 5);\n"
                    "  scene.add(pointLight);\n\n"
                    "  // 3. 3D Mesh (Neon Cube)\n"
                    "  const geometry = new THREE.BoxGeometry(1.5, 1.5, 1.5);\n"
                    "  const material = new THREE.MeshStandardMaterial({\n"
                    "    color: 0x00ff88,\n"
                    "    roughness: 0.2,\n"
                    "    metalness: 0.8,\n"
                    "  });\n"
                    "  const cube = new THREE.Mesh(geometry, material);\n"
                    "  scene.add(cube);\n\n"
                    "  // 4. Ground Grid\n"
                    "  const grid = new THREE.GridHelper(20, 20, 0x00ff88, 0x333355);\n"
                    "  grid.position.y = -1.5;\n"
                    "  scene.add(grid);\n\n"
                    "  // 5. Window Resize Handler\n"
                    "  window.addEventListener('resize', () => {\n"
                    "    camera.aspect = window.innerWidth / window.innerHeight;\n"
                    "    camera.updateProjectionMatrix();\n"
                    "    renderer.setSize(window.innerWidth, window.innerHeight);\n"
                    "  });\n\n"
                    "  // 6. 60 FPS Animation Loop\n"
                    "  function animate() {\n"
                    "    requestAnimationFrame(animate);\n"
                    "    cube.rotation.x += 0.01;\n"
                    "    cube.rotation.y += 0.015;\n"
                    "    renderer.render(scene, camera);\n"
                    "  }\n"
                    "  animate();\n"
                    "});\n"
                )
            else:
                js_content = (
                    f"// {title} - Main JavaScript Entry\n"
                    f"console.log('{title} initialized.');\n"
                    "window.addEventListener('DOMContentLoaded', () => {\n"
                    "  const canvas = document.getElementById('mainCanvas');\n"
                    "  if (canvas) {\n"
                    "    canvas.width = 800;\n"
                    "    canvas.height = 600;\n"
                    "    const ctx = canvas.getContext('2d');\n"
                    "    ctx.fillStyle = '#00f';\n"
                    "    ctx.fillRect(50, 50, 100, 100);\n"
                    "  }\n"
                    "});\n"
                )
            script_js.write_text(js_content, encoding="utf-8")
            created_files.append("script.js")

        if not readme_md.exists():
            if is_drone_game:
                readme_body = (
                    f"# {title} - Realistic Military Drone Shooter 3D\n\n"
                    "Tactical 3D combat drone flight simulation built with Three.js.\n\n"
                    "## Controls\n"
                    "- **W / Up Arrow**: Pitch down & accelerate forward\n"
                    "- **S / Down Arrow**: Pitch up & brake / fly backward\n"
                    "- **A / Left Arrow**: Bank left & yaw heading left\n"
                    "- **D / Right Arrow**: Bank right & yaw heading right\n"
                    "- **Left Shift**: Afterburner boost (extra speed)\n"
                    "- **Spacebar**: Rapid-fire autocannon / laser bolts\n"
                    "- **R**: Reset UAV position and hull status\n\n"
                    "## Getting Started\n"
                    "Open `index.html` in any modern web browser (Chrome, Edge, Firefox).\n"
                )
            else:
                readme_body = f"# {title}\n\nProject initialized by PAI.\n\n## Getting Started\nOpen `index.html` in your web browser to run the project.\n"
            readme_md.write_text(readme_body, encoding="utf-8")
            created_files.append("README.md")

    # 2. Python project
    elif any(k in prompt_lower for k in ("python", "py", "script", "api", "backend", "ai")):
        main_py = target_path / "main.py"
        req_txt = target_path / "requirements.txt"
        readme_md = target_path / "README.md"
        gitignore = target_path / ".gitignore"

        title = target_path.name
        if not main_py.exists():
            main_py.write_text(
                f"#!/usr/bin/env python3\n\"\"\"{title} - Main application entry point.\"\"\"\n\ndef main():\n    print(\"Hello from {title}!\")\n\nif __name__ == \"__main__\":\n    main()\n",
                encoding="utf-8"
            )
            created_files.append("main.py")

        if not req_txt.exists():
            req_txt.write_text("# Dependencies\n", encoding="utf-8")
            created_files.append("requirements.txt")

        if not readme_md.exists():
            readme_md.write_text(
                f"# {title}\n\nProject initialized by PAI.\n\n## Run\n```bash\npython main.py\n```\n",
                encoding="utf-8"
            )
            created_files.append("README.md")

        if not gitignore.exists():
            gitignore.write_text("__pycache__/\n*.pyc\n.env\nvenv/\n", encoding="utf-8")
            created_files.append(".gitignore")

    # 3. Custom / General project
    else:
        title = target_path.name
        readme_md = target_path / "README.md"
        main_file = target_path / "main.py"

        if not readme_md.exists():
            readme_md.write_text(
                f"# {title}\n\nProject initialized by PAI.\nDescription: {project_type_or_prompt or 'New project'}\n",
                encoding="utf-8"
            )
            created_files.append("README.md")

        if not main_file.exists():
            main_file.write_text(
                f"# {title}\ndef main():\n    print('Project {title} initialized.')\n\nif __name__ == '__main__':\n    main()\n",
                encoding="utf-8"
            )
            created_files.append("main.py")

    file_bullets = "\n  - " + "\n  - ".join(created_files) if created_files else "  (directory already existed)"
    msg = (
        f"[Successfully initialized new project in {target_path}]\n"
        f"Files created:{file_bullets}"
    )
    return True, msg, created_files


def analyze_and_fix_bugs(
    target_str: str,
    instructions: str = "",
    stream=sys.stdout,
    executor: Optional[Callable[[List[str]], int]] = None,
) -> Tuple[bool, str, List[str]]:
    """
    Analyzes a target file or project folder for bugs, errors, and logic flaws,
    creates .bak backup(s), and applies fixes directly to the file(s).
    Returns (success, report, fixed_files).
    """
    clean_target = target_str.strip().strip('"').strip("'")
    if not clean_target:
        clean_target = "."

    resolved = resolve_target_file(clean_target)
    is_file = resolved is not None and resolved.is_file()
    is_dir = False
    if not is_file:
        cand_dir = Path(clean_target).expanduser().resolve()
        if cand_dir.is_dir():
            is_dir = True
            resolved = cand_dir

    if not is_file and not is_dir:
        return False, f"Error: Target '{clean_target}' not found (must be an existing file or project directory).", []

    fixed_files: List[str] = []
    reports: List[str] = []

    if is_file:
        files_to_check = [resolved]
    else:
        exts = (".html", ".htm", ".py", ".js", ".jsx", ".ts", ".tsx", ".css", ".rs", ".json")
        files_to_check = []
        for p in resolved.rglob("*"):
            if p.is_file() and p.suffix.lower() in exts:
                parts = p.parts
                if any(j in parts for j in (".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build")):
                    continue
                files_to_check.append(p)
                if len(files_to_check) >= 5:
                    break

    if not files_to_check:
        return False, f"No code files found in '{resolved}' to analyze.", []

    if executor is None:
        exec_fn = execute_subcommand
    else:
        exec_fn = executor

    for fpath in files_to_check:
        try:
            orig_content = fpath.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                orig_content = fpath.read_text(encoding="cp1252")
            except Exception:
                continue
        except Exception:
            continue

        if not orig_content.strip():
            continue

        suffix = fpath.suffix.lstrip(".").lower()
        lang_map = {
            "html": "html", "htm": "html", "py": "python",
            "js": "javascript", "ts": "typescript", "rs": "rust", "css": "css",
        }
        lang = lang_map.get(suffix, suffix or "text")

        fix_prompt = (
            f"You are an expert software debugger and code quality auditor.\n"
            f"Analyze the following file '{fpath.name}' for bugs, syntax errors, and runtime issues:\n"
            f"```{lang}\n{orig_content}\n```\n\n"
            f"User notes / issues:\n{instructions or 'Identify and fix all bugs, syntax errors, broken imports, and logic flaws.'}\n\n"
            f"Tasks:\n"
            f"1. State what bugs or issues were found and how they were fixed.\n"
            f"2. Output the complete, fixed code inside a single ```{lang} ... ``` code block.\n"
            f"Provide the complete ready-to-run file without any omissions."
        )

        spinner = ThinkingSpinner(stream)
        capture = CaptureStream(stream, on_first_write=spinner.stop)
        try:
            spinner.start()
            chat_cmd = ["chat"]
            if _active_model_override:
                chat_cmd += ["--model", _active_model_override]
            chat_cmd += ["--", fix_prompt]
            with contextlib.redirect_stdout(capture):
                exec_fn(chat_cmd)
        except KeyboardInterrupt:
            return False, "Operation cancelled by user.", fixed_files
        except Exception as e:
            reports.append(f"Error analyzing '{fpath.name}': {e}")
            continue
        finally:
            spinner.stop()

        model_out = capture.getvalue()
        if not model_out or not model_out.strip():
            continue

        import re
        code_blocks = re.findall(r"```(?:\w+)?\r?\n(.*?)\r?\n```", model_out, re.DOTALL)
        if code_blocks:
            fixed_code = max(code_blocks, key=len)
            explanation = model_out.split("```")[0].strip()
        else:
            fixed_code = model_out.strip()
            explanation = "Applied bug fixes to file."

        bak_path = fpath.with_suffix(fpath.suffix + ".bak")
        try:
            bak_path.write_text(orig_content, encoding="utf-8")
        except Exception:
            pass

        try:
            fpath.write_text(fixed_code, encoding="utf-8")
            fixed_files.append(str(fpath))
            summary_header = f"=== Bug Fix Report: {fpath.name} ==="
            expl_text = "\n".join(explanation.splitlines()[:6]) if explanation else "Identified and resolved code issues."
            reports.append(
                f"{summary_header}\n"
                f"{expl_text}\n"
                f"[Updated: {fpath}]\n"
                f"[Backup: {bak_path}]"
            )
        except Exception as e:
            reports.append(f"Error writing fixed file '{fpath}': {e}")

    if not fixed_files:
        return False, "No fixes applied. (Code was clean or model returned empty response)", []

    return True, "\n\n".join(reports), fixed_files


# =============================================================================
# Browser Integration
# =============================================================================

def open_in_browser(target: Optional[str] = None, stream=sys.stdout) -> Tuple[bool, str]:
    """
    Opens a file, project preview, or URL in the system's default web browser.
    Auto-detects index.html, game.html, or common web files if no target is provided.
    Works cross-platform (Windows, Linux, macOS) using standard library webbrowser.
    """
    target_str = (target or "").strip()

    # 1. URL handling (http://, https://, file://)
    if target_str.startswith(("http://", "https://", "file://")):
        try:
            webbrowser.open(target_str)
            return True, f"Opened URL in default browser: {target_str}"
        except Exception as e:
            return False, f"Failed to open URL in browser: {e}"

    # 2. File / Directory target resolution
    target_path: Optional[Path] = None
    if target_str:
        resolved = resolve_target_file(target_str)
        if resolved and resolved.exists():
            target_path = resolved
        else:
            cand = Path(target_str).expanduser()
            if not cand.is_absolute():
                cand = (Path.cwd() / cand).resolve()
            if cand.exists():
                target_path = cand
            else:
                cand_html = cand.with_suffix(".html")
                if cand_html.exists():
                    target_path = cand_html

    # 3. Auto-detection if no target or target not found
    if not target_path or not target_path.exists():
        if target_str:
            return False, f"File or path not found: '{target_str}'"

        cwd = Path.cwd()
        for common_name in ("index.html", "game.html", "main.html", "app.html"):
            cand = cwd / common_name
            if cand.is_file():
                target_path = cand
                break

        if not target_path:
            for sub_cand in cwd.glob("*/index.html"):
                if sub_cand.is_file():
                    target_path = sub_cand
                    break

        if not target_path:
            return False, (
                "No target specified and no index.html or game.html found in current directory.\n"
                "Usage: /open <file|url> (e.g. /open Downloads\\game.html or /open index.html)"
            )

    # 4. If directory, look for index.html or game.html inside it
    if target_path.is_dir():
        for sub_file in ("index.html", "game.html", "main.html", "app.html"):
            cand = target_path / sub_file
            if cand.is_file():
                target_path = cand
                break

    try:
        uri = target_path.resolve().as_uri()
        webbrowser.open(uri)
        return True, f"Opened '{target_path.name}' in default browser: {target_path}"
    except Exception as e:
        return False, f"Failed to open browser: {e}"


# =============================================================================
# Agentic Persistent Skills & Self-Learning System
# =============================================================================

STARTER_SKILLS = [
    {
        "name": "web-3d-threejs",
        "description": "Three.js 3D web games, scenes, animations, lighting, and camera loops",
        "tags": ["threejs", "treejs", "3d", "game", "webgl", "canvas", "scene", "animation"],
        "guidance": (
            "When creating 3D web applications or games using Three.js:\n"
            "1. Single-file bundle: embed CSS in <style> and JS in <script> tags for immediate offline browser execution.\n"
            "2. Script CDN: include Three.js via <script src=\"https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js\"></script>.\n"
            "3. Scene Setup: Initialize THREE.Scene(), THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000), and THREE.WebGLRenderer({ antialias: true }).\n"
            "4. Lighting: Always add THREE.AmbientLight(0xffffff, 0.6) and THREE.DirectionalLight(0xffffff, 0.8) with proper position.\n"
            "5. Geometries & Materials: Use standard meshes (THREE.BoxGeometry, THREE.SphereGeometry) with THREE.MeshStandardMaterial.\n"
            "6. Game Loop: Implement requestAnimationFrame(animate) with delta timing or rotation/position updates, calling renderer.render(scene, camera).\n"
            "7. Controls: Add window resize listeners and keyboard/mouse listeners (keydown, keyup) for player movement.\n"
            "8. UI Overlay: Provide HTML/CSS score counter, health bar, or restart button on top of canvas."
        ),
    },
    {
        "name": "bug-fixer",
        "description": "Root-cause diagnostic and precision code repair with automatic backup",
        "tags": ["bug", "fix", "error", "hadanna", "waradi", "repair", "debug", "broken", "syntax"],
        "guidance": (
            "Bug Analysis and Precision Repair Best Practices:\n"
            "1. Read and diagnose the full target file before modifying.\n"
            "2. Identify exact syntax errors, indentation issues, wrong operators, missing variables, or logic flaws.\n"
            "3. Always preserve existing code structure, comments, docstrings, and unrelated functions.\n"
            "4. Create a .bak backup before overwriting any file.\n"
            "5. Provide clear, minimal, self-contained fix within standard markdown code fences (```lang ... ```).\n"
            "6. Summarize the root cause and the specific lines repaired."
        ),
    },
    {
        "name": "web-app-scaffold",
        "description": "Modern responsive web applications with semantic HTML5, CSS3, and modular JS",
        "tags": ["project", "web", "html", "css", "javascript", "app", "website", "frontend", "responsive"],
        "guidance": (
            "Web Application Architecture Best Practices:\n"
            "1. Structure: Separation of concerns across index.html (semantic tags), style.css (modern responsive CSS), and script.js (clean DOM event handlers).\n"
            "2. Viewport: Include <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"> in <head>.\n"
            "3. Modern CSS: Use CSS custom properties (:root variables), Flexbox/Grid for layout, and media queries for mobile-friendly viewports.\n"
            "4. JavaScript: Wrap in DOMContentLoaded listener, use modern ES6+ (const/let, arrow functions, async/await), and maintain modular state.\n"
            "5. Accessibility: Use proper semantic HTML (<header>, <nav>, <main>, <section>, <footer>) and ARIA attributes where needed."
        ),
    },
    {
        "name": "python-automation",
        "description": "Robust cross-platform Python scripts and CLI automation",
        "tags": ["python", "script", "automation", "cli", "tools", "utility", "process"],
        "guidance": (
            "Python CLI and Automation Script Best Practices:\n"
            "1. Cross-platform paths: Use pathlib.Path instead of string concatenations.\n"
            "2. Safe execution: Use subprocess.run with check=False or try/except, capturing stdout/stderr safely.\n"
            "3. Arguments: Use standard library argparse with descriptive help and type validation.\n"
            "4. Error Handling: Graceful exit codes (0 for success, non-zero for failure) and user-friendly error messages on stderr.\n"
            "5. Encoding: Always specify encoding=\"utf-8\" when reading or writing text files."
        ),
    },
]


def get_skills_dir() -> Path:
    """Returns directory where persistent skills are stored (~/.pai/skills)."""
    env_dir = os.environ.get("PAI_SKILLS_DIR")
    if env_dir:
        skills_dir = Path(env_dir)
    else:
        skills_dir = Path.home() / ".pai" / "skills"
    skills_dir.mkdir(parents=True, exist_ok=True)
    return skills_dir


def ensure_starter_skills() -> None:
    """Seeds default starter skills if skills directory has no skill files."""
    skills_dir = get_skills_dir()
    for item in STARTER_SKILLS:
        skill_file = skills_dir / f"{item['name']}.json"
        if not skill_file.exists():
            data = {
                "name": item["name"],
                "description": item["description"],
                "tags": item["tags"],
                "guidance": item["guidance"],
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            try:
                skill_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except Exception:
                pass


def list_skills() -> List[Dict[str, Any]]:
    """Loads and returns all skills from ~/.pai/skills/ sorted by name."""
    ensure_starter_skills()
    skills_dir = get_skills_dir()
    skills = []
    for f in sorted(skills_dir.glob("*.json")):
        try:
            content = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(content, dict) and "name" in content:
                skills.append(content)
        except Exception:
            pass
    return skills


def get_skill(name: str) -> Optional[Dict[str, Any]]:
    """Finds a skill by exact or fuzzy name/slug."""
    q = name.strip().lower()
    for s in list_skills():
        if s.get("name", "").lower() == q:
            return s
    for s in list_skills():
        if q in s.get("name", "").lower():
            return s
    return None


def save_skill(
    name: str,
    description: str,
    guidance: str,
    tags: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """Saves or updates a persistent skill in ~/.pai/skills/{slug}.json."""
    ensure_starter_skills()
    slug = re.sub(r"[^a-zA-Z0-9_\-]+", "-", name.strip().lower()).strip("-")
    if not slug:
        return False, "Error: Invalid skill name. Use alphanumeric characters and hyphens."

    if not guidance.strip():
        return False, f"Error: Skill '{slug}' requires guidance instructions."

    if tags is None:
        raw_words = re.findall(r"\w+", f"{slug} {description} {guidance}".lower())
        tags = sorted(list({w for w in raw_words if len(w) >= 3 and w not in ("the", "and", "for", "with", "that", "this", "when", "use", "using")}))[:12]

    skills_dir = get_skills_dir()
    skill_file = skills_dir / f"{slug}.json"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    existing_created = now_iso
    if skill_file.exists():
        try:
            old = json.loads(skill_file.read_text(encoding="utf-8"))
            existing_created = old.get("created_at", now_iso)
        except Exception:
            pass

    data = {
        "name": slug,
        "description": description.strip() or f"Skill for {slug}",
        "tags": tags,
        "guidance": guidance.strip(),
        "created_at": existing_created,
        "updated_at": now_iso,
    }

    try:
        skill_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return True, f"Skill '{slug}' successfully learned and saved to {skill_file}"
    except Exception as e:
        return False, f"Failed to save skill '{slug}': {e}"


def delete_skill(name: str) -> Tuple[bool, str]:
    """Deletes a learned skill from ~/.pai/skills/."""
    skill = get_skill(name)
    if not skill:
        return False, f"Error: Skill '{name}' not found."
    slug = skill.get("name", name)
    skills_dir = get_skills_dir()
    skill_file = skills_dir / f"{slug}.json"
    if skill_file.is_file():
        try:
            skill_file.unlink()
            return True, f"Skill '{slug}' removed from persistent library."
        except Exception as e:
            return False, f"Failed to delete skill '{slug}': {e}"
    return False, f"Error: Skill file not found: {skill_file}"


def find_matching_skills(query: str, limit: int = 2) -> List[Dict[str, Any]]:
    """
    Finds skills that match keywords in the user query.
    Returns up to `limit` highest-scoring skills.
    """
    skills = list_skills()
    if not skills:
        return []

    query_tokens = set(re.findall(r"\w+", query.lower()))
    if not query_tokens:
        return []

    scored: List[Tuple[int, Dict[str, Any]]] = []
    for s in skills:
        score = 0
        name = s.get("name", "").lower()
        desc = s.get("description", "").lower()
        tags = [t.lower() for t in s.get("tags", [])]

        for tok in query_tokens:
            if tok in name:
                score += 5
            if tok in desc:
                score += 2
            if tok in tags:
                score += 4

        if any(w in query_tokens for w in ("threejs", "treejs", "3d", "webgl")) and name == "web-3d-threejs":
            score += 10
        if any(w in query_tokens for w in ("bug", "bugs", "error", "fix", "hadanna", "waradi")) and name == "bug-fixer":
            score += 10
        if any(w in query_tokens for w in ("project", "web", "html", "css", "website")) and name == "web-app-scaffold":
            score += 8
        if any(w in query_tokens for w in ("script", "automation", "python", "cli")) and name == "python-automation":
            score += 6

        if score > 0:
            scored.append((score, s))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [s for _, s in scored[:limit]]


def format_skills_list(color_enabled: bool = False) -> str:
    """Formats list of available learned skills."""
    skills = list_skills()
    lines = [colorize("=== Agentic Skills Library (~/.pai/skills) ===", BOLD, color_enabled)]
    if not skills:
        lines.append("  (No skills found)")
    else:
        for s in skills:
            name_str = colorize(f"● {s.get('name', 'unnamed')}", CYAN, color_enabled)
            desc_str = s.get("description", "")
            lines.append(f"  {name_str} - {desc_str}")
    lines.append(colorize("─" * 50, DIM, color_enabled))
    lines.append(colorize("Commands: /skill <name> to view | /learn <name> <doc> to teach | /forget <name> to remove", DIM, color_enabled))
    return "\n".join(lines)


def format_skill_detail(skill: Dict[str, Any], color_enabled: bool = False) -> str:
    """Formats detailed view of a skill."""
    name = skill.get("name", "")
    desc = skill.get("description", "")
    tags = ", ".join(skill.get("tags", []))
    guidance = skill.get("guidance", "")
    created = skill.get("created_at", "")[:10]

    lines = [
        colorize(f"=== Skill: {name} ===", BOLD, color_enabled),
        f"{colorize('Description:', CYAN, color_enabled)} {desc}",
        f"{colorize('Tags:', CYAN, color_enabled)}        {tags}",
        f"{colorize('Created:', CYAN, color_enabled)}     {created}",
        colorize("─" * 50, DIM, color_enabled),
        colorize("Guidance & Methodology:", BOLD, color_enabled),
        guidance,
        colorize("─" * 50, DIM, color_enabled),
        colorize(f"To use this skill, mention its keywords or ask tasks matching {name}.", DIM, color_enabled),
    ]
    return "\n".join(lines)


def get_shell_banner(
    endpoint: str = "http://127.0.0.1:11434",
    color_enabled: Optional[bool] = None,
    install_root: Optional[Path] = None,
    stream=sys.stdout,
) -> str:
    """Constructs the interactive shell startup banner stating active model, developer credit, and honest limitations."""
    if color_enabled is None:
        color_enabled = should_enable_color(stream)

    cols, _ = get_terminal_dimensions()
    model_name = get_resident_model_name()
    info_line = get_shell_info_line(cols, color_enabled=color_enabled, install_root=install_root)
    sep_line = get_shell_separator_line(cols, color_enabled=color_enabled, stream=stream)

    logo_text = colorize(PAI_ASCII_LOGO, BRIGHT_CYAN, color_enabled)
    dev_text = colorize(DEVELOPER_CREDIT, DIM, color_enabled)
    title_text = colorize("Personal Agentic AI (PAI) Interactive Shell", BOLD, color_enabled)
    hint_text = colorize("Type /help for available commands or /exit to quit.", DIM, color_enabled)

    return (
        f"{logo_text}\n"
        f"{title_text}\n"
        f"{dev_text}\n"
        f"{info_line}\n"
        f"{sep_line}\n"
        f"Model: {model_name} | Endpoint: {endpoint}\n"
        "Note: PAI gives the model your computer's date and time. It has no web access and its knowledge ends at a training cut-off.\n"
        "Mode: Stateless (each line is evaluated independently without prior conversation memory).\n"
        f"{hint_text}\n"
    )


def get_pinned_shell_notice_lines(
    endpoint: str = "http://127.0.0.1:11434",
    color_enabled: Optional[bool] = None,
) -> List[str]:
    """
    Constructs the honest disclaimer, model info, and help hint lines to display
    in the scrolling chat region upon pinned shell startup (Finding FM).
    """
    if color_enabled is None:
        color_enabled = should_enable_color()

    model_name = get_resident_model_name()
    hint_text = colorize("Type /help for available commands or /exit to quit.", DIM, color_enabled)

    return [
        f"Model: {model_name} | Endpoint: {endpoint}",
        "Note: PAI gives the model your computer's date and time. It has no web access and its knowledge ends at a training cut-off.",
        "Mode: Stateless (each line is evaluated independently without prior conversation memory).",
        hint_text,
    ]


def parse_shell_line(line: str) -> Tuple[str, List[str]]:
    """
    Parses a single shell input line using Windows-aware tokenizer (Finding DW).
    Returns (action: str, argv: List[str]).
    Actions:
      - 'empty': Blank line, no-op.
      - 'exit': Clean exit request (/exit, /quit).
      - 'help': Display shell command reference (/help, /?).
      - 'time': Current system clock context (/time).
      - 'clear': Clear chat screen/buffer (/clear, /cls).
      - 'history': In-memory session history (/history [N]).
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

        if raw_cmd in ("time", "clock"):
            return "time", []

        if raw_cmd in ("clear", "cls"):
            return "clear", []

        if raw_cmd in ("wifi", "wlan"):
            return "wifi", []

        if raw_cmd in ("cmd", "run"):
            subcmd = stripped[len(tokens[0]):].strip()
            if not subcmd:
                return "error", ["Error: /cmd requires a Windows command to execute (e.g. /cmd dir)."]
            return "cmd", [subcmd]

        if raw_cmd == "save":
            args = tokens[1:]
            if not args:
                return "error", ["Error: /save requires a destination file path (e.g. /save C:\\path\\to\\file.ext)."]
            target = stripped[len(tokens[0]):].strip()
            if len(args) == 1:
                target = args[0]
            return "save", [target]

        if raw_cmd in ("edit", "modify"):
            args = tokens[1:]
            active_p = get_active_project_dir()
            if not args:
                return "error", ["Error: /edit requires a target file path and instructions (e.g. /edit script.js add score counter)."]
            idx = stripped.find(tokens[0]) + len(tokens[0])
            rest = stripped[idx:].strip()

            has_file_indicator = ("." in args[0] or "\\" in args[0] or "/" in args[0])
            if not has_file_indicator and active_p and ((active_p / "script.js").is_file() or (active_p / "main.py").is_file()):
                target = str(active_p / "script.js") if (active_p / "script.js").is_file() else str(active_p / "main.py")
                instructions = rest
                return "edit", [target, instructions]

            target = args[0]
            if len(args) == 1:
                return "error", [f"Error: Please provide modification instructions (e.g. /edit {target} add score counter)."]
            if rest.startswith('"'):
                end_quote = rest.find('"', 1)
                instructions = rest[end_quote + 1:].strip() if end_quote != -1 else " ".join(args[1:])
            elif rest.startswith("'"):
                end_quote = rest.find("'", 1)
                instructions = rest[end_quote + 1:].strip() if end_quote != -1 else " ".join(args[1:])
            else:
                instructions = rest.split(None, 1)[1] if len(rest.split(None, 1)) > 1 else " ".join(args[1:])
            return "edit", [target, instructions]

        if raw_cmd == "model":
            args = tokens[1:]
            if not args or args[0].lower() in ("list", "ls", "show"):
                return "model_list", []
            target_model = args[1] if args[0].lower() in ("switch", "use", "set") and len(args) > 1 else args[0]
            return "model_switch", [target_model]

        if raw_cmd in ("switch", "use"):
            args = tokens[1:]
            if not args:
                return "model_list", []
            return "model_switch", [args[0]]

        if raw_cmd in ("project", "new", "folder", "mkdir"):
            args = tokens[1:]
            if not args and raw_cmd in ("project", "folder"):
                return "project_status", []
            target_dir = args[0] if args else "my_project"
            rest_idx = stripped.find(tokens[0]) + len(tokens[0])
            rest = stripped[rest_idx:].strip()
            if len(args) > 1:
                idx2 = rest.find(args[0]) + len(args[0])
                proj_prompt = rest[idx2:].strip()
            else:
                proj_prompt = ""
            return "project", [target_dir, proj_prompt]

        if raw_cmd in ("fix", "bugfix"):
            args = tokens[1:]
            target_file_or_dir = args[0] if args else "."
            rest_idx = stripped.find(tokens[0]) + len(tokens[0])
            rest = stripped[rest_idx:].strip()
            if len(args) > 1:
                idx2 = rest.find(args[0]) + len(args[0])
                fix_inst = rest[idx2:].strip()
            else:
                fix_inst = ""
            return "fix", [target_file_or_dir, fix_inst]

        if raw_cmd in ("open", "preview", "browse"):
            args = tokens[1:]
            target = stripped[len(tokens[0]):].strip() if args else ""
            return "browser_open", [target]

        if raw_cmd in ("agent", "team", "plan"):
            args = tokens[1:]
            if not args:
                return "multi_agent", ["status"]
            first_arg = args[0].lower()
            if first_arg in ("set", "assign", "config", "configure", "models", "reset", "roles"):
                rest = stripped[len(tokens[0]):].strip()
                idx = rest.find(args[0]) + len(args[0])
                sub_args = rest[idx:].strip()
                return "team_config", [first_arg, sub_args]
            rest = stripped[len(tokens[0]):].strip()
            return "multi_agent", [rest]

        if raw_cmd == "mcp":
            args = tokens[1:]
            sub = args[0].lower() if args else "status"
            rest = " ".join(args[1:]) if len(args) > 1 else ""
            return "mcp_hub", [sub, rest]

        if raw_cmd in ("graphql", "gql"):
            args = tokens[1:]
            rest = stripped[len(tokens[0]):].strip()
            if not rest:
                return "error", ["Error: /graphql requires a query or command (e.g. /graphql { drone { speed } } or /graphql introspect)."]
            return "graphql_cmd", [rest]

        if raw_cmd in ("skills", "skill"):
            args = tokens[1:]
            if not args or args[0].lower() in ("list", "ls"):
                return "skills_list", []
            sub = args[0].lower()
            if sub in ("learn", "add", "create", "new"):
                if len(args) < 2:
                    return "error", ["Error: /skill learn requires a skill name and guidance instructions."]
                name = args[1]
                idx = stripped.find(name) + len(name)
                guidance = stripped[idx:].strip()
                if not guidance:
                    return "error", [f"Error: Please provide guidance instructions for skill '{name}'."]
                return "skill_learn", [name, guidance]
            if sub in ("delete", "remove", "forget", "rm"):
                if len(args) < 2:
                    return "error", ["Error: /skill delete requires a skill name."]
                return "skill_delete", [args[1]]
            return "skill_show", [args[0]]

        if raw_cmd == "learn":
            args = tokens[1:]
            if not args:
                return "error", ["Error: /learn requires a skill name and guidance instructions (e.g. /learn web-game Focus on modular Three.js scripts)."]
            name = args[0]
            idx = stripped.find(name) + len(name)
            guidance = stripped[idx:].strip()
            if not guidance:
                return "error", [f"Error: Please provide guidance instructions for skill '{name}'."]
            return "skill_learn", [name, guidance]

        if raw_cmd in ("forget", "unlearn"):
            args = tokens[1:]
            if not args:
                return "error", ["Error: /forget requires a skill name to remove."]
            return "skill_delete", [args[0]]

        if raw_cmd == "history":
            args = tokens[1:]
            if args:
                try:
                    n = int(args[0])
                    if n <= 0:
                        return "error", ["Error: /history argument must be a positive integer."]
                except ValueError:
                    return "error", ["Error: /history argument must be a positive integer."]
            return "history", args

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
        # If tokens[0] contains internal slashes/backslashes (e.g. /tmp/app.py, /path/to/file)
        # or resolves to an existing filesystem entity, it is a POSIX path rather than a slash command.
        is_path_token = "/" in tokens[0][1:] or "\\" in tokens[0] or (
            resolve_target_file(tokens[0]) is not None or Path(tokens[0]).exists()
        )
        if not is_path_token:
            return "unknown_slash", [tokens[0]]

    # Check for unslashed 'edit' or 'modify' command
    lower_unslashed = stripped.lower()
    if lower_unslashed.startswith("edit ") or lower_unslashed.startswith("modify "):
        try:
            tokens = tokenize_windows_line(stripped)
            if len(tokens) >= 3:
                target_file = tokens[1]
                idx = stripped.find(tokens[0]) + len(tokens[0])
                rest = stripped[idx:].strip()
                if rest.startswith('"'):
                    end_quote = rest.find('"', 1)
                    instructions = rest[end_quote + 1:].strip() if end_quote != -1 else " ".join(tokens[2:])
                elif rest.startswith("'"):
                    end_quote = rest.find("'", 1)
                    instructions = rest[end_quote + 1:].strip() if end_quote != -1 else " ".join(tokens[2:])
                else:
                    instructions = rest.split(None, 1)[1] if len(rest.split(None, 1)) > 1 else " ".join(tokens[2:])
                return "edit", [target_file, instructions]
            elif len(tokens) == 2:
                return "error", [f"Error: Please provide modification instructions (e.g. {tokens[0]} Downloads\\game.html add score counter)."]
        except Exception:
            pass

    # Check for save intent (natural language or unslashed command)
    nat_save = parse_natural_save_intent(stripped)
    if nat_save is not None:
        return "save", [nat_save]

    # Check for folder / project creation intent (natural language or unslashed command)
    nat_folder = parse_natural_folder_intent(stripped)
    if nat_folder is not None:
        return "project", [nat_folder[0], nat_folder[1]]

    # Check for unslashed fix / bugfix command
    if lower_unslashed.startswith("fix ") or lower_unslashed.startswith("bugfix "):
        try:
            tokens = tokenize_windows_line(stripped)
            target = tokens[1] if len(tokens) > 1 else "."
            idx = stripped.find(target) + len(target)
            inst = stripped[idx:].strip() if idx < len(stripped) else ""
            return "fix", [target, inst]
        except Exception:
            pass

    # Check for natural language model change intent
    if any(k in lower_unslashed for k in ("change model", "switch model", "use model", "model eka change", "model eka wenas", "model maru", "aluth model")):
        if any(q in lower_unslashed for q in ("monawada", "what", "list", "show", "available", "thiyena")):
            return "model_list", []
        tokens = stripped.split()
        cand = None
        for t in reversed(tokens):
            clean_t = t.strip(".,;:?!'\"")
            if clean_t and clean_t.lower() not in ("model", "eka", "ekata", "change", "switch", "use", "to", "karanna", "maru", "wenas"):
                cand = clean_t
                break
        if cand:
            return "model_switch", [cand]
        return "model_list", []

    # Check for natural language bug analysis and fix intent
    if any(k in lower_unslashed for k in ("bug", "bugs", "error", "errors", "weradi")) and any(k in lower_unslashed for k in ("hadanna", "fix", "analyze", "check", "balala", "repair", "balanna")):
        target = "."
        for tok in stripped.split():
            clean_tok = tok.strip(".,;:?!'\"")
            res = resolve_target_file(clean_tok)
            if res is not None:
                target = str(res)
                break
            cand_p = Path(clean_tok).expanduser()
            if cand_p.is_dir() or cand_p.is_file():
                target = str(cand_p.resolve())
                break
        return "fix", [target, stripped]

    # Check for unslashed open / preview / browse command
    if lower_unslashed.startswith("open ") or lower_unslashed.startswith("preview ") or lower_unslashed.startswith("browse "):
        first_word = lower_unslashed.split()[0]
        rest_target = stripped[len(first_word):].strip()
        if any(rest_target.lower().endswith(ext) for ext in (".html", ".htm", ".js", ".css", ".py", ".md")) or rest_target.startswith(("http://", "https://", "localhost:")) or "browser" in lower_unslashed:
            clean_t = rest_target.replace("in browser", "").replace("browser eke", "").strip()
            return "browser_open", [clean_t]

    # Check for natural language browser open intent
    if any(k in lower_unslashed for k in ("browser eke", "browser eka", "open in browser", "preview in browser", "preview karanna", "open karanna browser", "open browser")):
        tokens = stripped.split()
        cand_target = ""
        for tok in tokens:
            clean_tok = tok.strip(".,;:?!'\"")
            if clean_tok.startswith(("http://", "https://", "localhost:")):
                cand_target = clean_tok
                break
            if any(clean_tok.lower().endswith(ext) for ext in (".html", ".htm", ".js", ".css", ".py", ".md")):
                cand_target = clean_tok
                break
            res = resolve_target_file(clean_tok)
            if res and res.is_file():
                cand_target = str(res)
                break
        return "browser_open", [cand_target]

    # Check for natural language skills intent
    if any(k in lower_unslashed for k in ("skills monawada", "skills list", "show skills", "list skills", "thiyena skills")):
        return "skills_list", []

    if any(k in lower_unslashed for k in ("skill eka pennanna", "view skill", "skill details")):
        tokens = stripped.split()
        cand_name = ""
        for tok in reversed(tokens):
            clean_tok = tok.strip(".,;:?!'\"")
            if clean_tok.lower() not in ("skill", "eka", "details", "pennanna", "view", "show"):
                cand_name = clean_tok
                break
        if cand_name:
            return "skill_show", [cand_name]
        return "skills_list", []

    if any(k in lower_unslashed for k in ("skill ekak hadanna", "skill hadanna", "aluth skill ekak", "learn skill", "create skill")):
        tokens = stripped.split()
        cand_name = "custom-skill"
        for idx, tok in enumerate(tokens):
            if tok.lower() in ("skill", "called", "namata", "name", "skill:") and idx + 1 < len(tokens):
                nxt = tokens[idx + 1].strip(".,;:?!'\"")
                if nxt.lower() not in ("ekak", "hadanna", "a", "new", "aluth"):
                    cand_name = nxt
                    break
        return "skill_learn", [cand_name, stripped]

    # Check for natural language team model configuration intent
    is_team_scope = any(k in lower_unslashed for k in ("team eke", "team model", "roles walata", "role walata", "team roles", "team set", "team config"))
    has_model_mention = any(k in lower_unslashed for k in ("model", "models", "role", "roles"))
    has_config_action = any(k in lower_unslashed for k in ("wenas", "maru", "change", "set", "danna", "dala", "configure", "assign", "switch")) or (
        has_model_mention and any(tok.lower().strip(".,;:?!'\"").startswith(("llama", "qwen", "gemma", "mistral", "phi")) for tok in stripped.split())
    )
    has_role_direct = any(
        r in lower_unslashed.split() or f" {r} " in f" {lower_unslashed} "
        for r in ("pm", "qa", "dev", "coder", "senior", "specialist", "tester", "manager", "lead")
    ) or any(r in lower_unslashed for r in ("project manager", "senior dev", "specialist dev", "qa engineer"))
    has_model_family = any(
        tok.lower().strip(".,;:?!'\"").startswith(("llama", "qwen", "gemma", "mistral", "phi"))
        for tok in stripped.split()
    )
    has_assign_verb = any(k in lower_unslashed for k in ("dala", "danna", "set", "wenas", "maru", "change", "hadla", "assign", "switch", "configure", "put"))
    is_role_model_assignment = has_role_direct and has_model_family and (has_assign_verb or "=" in stripped)

    if (is_team_scope and (has_model_mention or has_config_action)) or is_role_model_assignment:
        assignments = []
        for word in stripped.split():
            if "=" in word and any(r in word.lower().split("=")[0] for r in ("pm", "dev", "coder", "senior", "ui", "specialist", "qa", "tester", "manager", "lead")):
                assignments.append(word)
        if assignments:
            return "team_config", ["set", " ".join(assignments)]
        for r_key in ("project manager", "senior dev", "specialist dev", "qa engineer", "pm", "dev", "coder", "ui", "specialist", "qa", "senior"):
            if r_key in lower_unslashed.split() or f" {r_key} " in f" {lower_unslashed} ":
                for tok in stripped.split():
                    clean_tok = tok.strip(".,;:?!'\"")
                    if any(clean_tok.lower().startswith(m_prefix) for m_prefix in ("llama", "qwen", "gemma", "mistral", "phi")):
                        canon_key = r_key
                        if r_key == "project manager":
                            canon_key = "pm"
                        elif r_key == "senior dev":
                            canon_key = "dev"
                        elif r_key in ("specialist dev", "specialist"):
                            canon_key = "ui"
                        elif r_key == "qa engineer":
                            canon_key = "qa"
                        return "team_config", ["set", f"{canon_key}={clean_tok}"]
        return "team_config", ["help", ""]

    # Check for natural language multi-agent intent
    if lower_unslashed.startswith("agent ") or lower_unslashed.startswith("team ") or any(k in lower_unslashed for k in ("agent team", "multi agent", "agents use karala", "agents la", "developer team", "dev team", "team eka", "team ekata", "team ekath", "team ekath ekka")):
        return "multi_agent", [stripped]

    # Check for natural language editing intent referencing an existing file or active project
    is_creation_intent = lower_unslashed.startswith(("create ", "make a ", "build a ", "i want to create", "create a ", "make an "))
    edit_keywords = (
        "edit", "modify", "wenas", "update", "change", "hadanna",
        "danna", "ekathu", "wedi", "adu", "improve", "faster", "slower",
        "increase", "decrease", "add", "make", "put", "remove", "replace",
        "texture", "textures", "missile", "missiles", "bullet", "bullets",
        "hellfire", "cctv", "camera", "tank", "tanks", "drone", "game",
        "sound", "audio", "hud", "ui", "physics", "shoot", "laser", "enemy",
        "enemies", "weapon", "weapons", "graphics", "view", "controls",
        "playable", "playble", "not playable", "not playble", "fix", "fix it"
    )
    is_edit_verb = any(k in lower_unslashed for k in (
        "edit ", "modify ", "update ", "change ", "wenas", "hadanna",
        "wedi karanna", "adu karanna", "ekathu karanna", "danna", "add ",
        "make it", "put ", "texture", "missile", "bullet", "cctv", "shoot", "fire",
        "playable", "playble", "fix", "fix it"
    ))
    if not is_creation_intent and any(k in lower_unslashed for k in edit_keywords):
        try:
            tokens = tokenize_windows_line(stripped)
            for tok in tokens:
                resolved = resolve_target_file(tok)
                if resolved and resolved.is_file():
                    return "edit", [str(resolved), stripped]
        except Exception:
            pass

        # If no explicit file token, but there is an active project:
        active_p = get_active_project_dir()
        if active_p and active_p.is_dir() and (is_edit_verb or any(k in lower_unslashed for k in (
            "speed", "sound", "audio", "faster", "enemy", "enemies", "laser",
            "score", "game", "drone", "physics", "missile", "bullet", "cctv",
            "camera", "tank", "texture", "textures", "weapon", "weapons", "view"
        ))):
            target_f = None
            if any(k in lower_unslashed for k in ("style", "css", "color", "background", "theme")) and not any(k in lower_unslashed for k in ("speed", "physics", "shoot", "laser", "enemy", "drone", "missile", "cctv")):
                if (active_p / "style.css").is_file():
                    target_f = active_p / "style.css"
            elif any(k in lower_unslashed for k in ("index", "html", "title", "button", "hud", "ui")) and not any(k in lower_unslashed for k in ("speed", "physics", "enemy", "drone", "sound", "missile", "cctv")):
                if (active_p / "index.html").is_file():
                    target_f = active_p / "index.html"
            else:
                if (active_p / "script.js").is_file():
                    target_f = active_p / "script.js"
                elif (active_p / "index.html").is_file():
                    target_f = active_p / "index.html"
                elif (active_p / "main.py").is_file():
                    target_f = active_p / "main.py"
            if target_f and target_f.is_file():
                return "edit", [str(target_f), stripped]

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
    stream=sys.stdout,
) -> int:
    """
    Runs the PAI interactive terminal REPL (ADR-014).
    Accepts custom input/output callables and stream for deterministic unit testing.
    """
    global _active_model_override
    if input_fn is None:
        input_fn = input
    if output_fn is None:
        output_fn = print

    # Finding ET: Call enforce_sandbox_boundary() once at shell start (same exit code 5 on failure).
    # "Sandbox execution boundary verified fail-closed." is printed ONLY after it returns.
    from pai import enforce_sandbox_boundary
    enforce_sandbox_boundary()

    color_enabled = should_enable_color(stream)
    pinned = should_pin_header(stream)

    if pinned:
        setup_pinned_layout(stream)
        output_fn("Sandbox execution boundary verified fail-closed.")
        for notice_line in get_pinned_shell_notice_lines(color_enabled=color_enabled):
            output_fn(notice_line)
    else:
        output_fn("Sandbox execution boundary verified fail-closed.")
        output_fn(get_shell_banner(color_enabled=color_enabled))

    current_dims = get_terminal_dimensions()
    ver = get_install_root_version()
    model_name = get_resident_model_name()
    set_terminal_title(f"PAI {ver} | Model: {model_name} | Developed by Hirusha Suhan", stream)

    os.environ["PAI_SHELL_ACTIVE"] = "1"
    try:
        while True:
            if pinned:
                current_dims = check_and_apply_resize(current_dims, stream)

            prompt_top = get_compact_prompt_header(color_enabled=color_enabled)
            if os.environ.get("PAI_SIMPLE_PROMPT") == "1":
                styled_prompt = colorize(prompt_str, BRIGHT_CYAN, color_enabled)
            else:
                styled_prompt = f"{prompt_top}\n{colorize('└──pai> ', BRIGHT_CYAN, color_enabled)}"

            try:
                line = input_fn(styled_prompt)
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
            elif action == "clear":
                _session_chat_turns.clear()
                if pinned:
                    cols, _ = get_terminal_dimensions()
                    color_enabled = should_enable_color(stream)
                    header_lines = get_pinned_header_lines(cols, color_enabled, stream)
                    chat_top = len(header_lines) + 1
                    stream.write(f"\033[{chat_top};1H\033[J")
                    stream.flush()
                else:
                    is_tty = False
                    try:
                        is_tty = bool(stream.isatty())
                    except Exception:
                        is_tty = False
                    if is_tty:
                        stream.write("\033[2J\033[1;1H")
                        stream.flush()
                    output_fn(get_shell_banner(color_enabled=color_enabled))
                continue
            elif action == "history":
                limit = int(argv[0]) if argv else None
                hist_text = format_session_history(limit, color_enabled=color_enabled)
                output_fn(hist_text)
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "time":
                d, t, tz = get_current_system_clock_context()
                time_str = f"Current local time: {d} {t} {tz}"
                output_fn(time_str)
                add_to_session_history(line, time_str)
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "save":
                target_path = argv[0]
                ok, msg = save_session_output_to_file(target_path)
                color = GREEN if ok else RED
                output_fn(colorize(msg, color, color_enabled))
                add_to_session_history(line, msg)
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "edit":
                target_str = argv[0]
                instructions = argv[1] if len(argv) > 1 else ""
                output_fn(colorize(f"Modifying '{target_str}' with resident model...", CYAN, color_enabled))
                ok, msg, updated_content = edit_target_file(target_str, instructions, stream=stream)
                color = GREEN if ok else RED
                output_fn(colorize(msg, color, color_enabled))
                if ok:
                    tip = "💡 Tip: Refresh index.html in your browser (or run /open) to see your changes!"
                    _safe_console_emit(output_fn, colorize(tip, DIM, color_enabled))
                add_to_session_history(line, msg)
                if ok and updated_content:
                    _session_chat_turns.append({"role": "user", "content": f"Edit {target_str}: {instructions}"})
                    _session_chat_turns.append({"role": "assistant", "content": f"Updated {target_str}:\n{msg}"})
                    if len(_session_chat_turns) > 12:
                        del _session_chat_turns[:-12]
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "project_status":
                active_p = get_active_project_dir()
                if active_p:
                    output_fn(format_project_status(active_p, color_enabled=color_enabled))
                else:
                    output_fn(colorize("No active project currently set. Create one with /project <folder> or specify an existing folder.", YELLOW, color_enabled))
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "model_list":
                output_fn(format_models_list(color_enabled=color_enabled))
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "model_switch":
                target_model = argv[0]
                ok, msg = switch_active_model(target_model, stream=stream)
                color = GREEN if ok else RED
                output_fn(colorize(msg, color, color_enabled))
                add_to_session_history(line, msg)
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "project":
                target_folder = argv[0] if argv else "my_project"
                proj_prompt = argv[1] if len(argv) > 1 else ""
                output_fn(colorize(f"Creating folder/project in '{target_folder}'...", CYAN, color_enabled))
                ok, msg, created = create_project_scaffold(target_folder, proj_prompt, stream=stream)
                color = GREEN if ok else RED
                output_fn(colorize(msg, color, color_enabled))
                add_to_session_history(line, msg)
                if ok:
                    _session_chat_turns.append({"role": "user", "content": f"Create project in {target_folder}: {proj_prompt}"})
                    _session_chat_turns.append({"role": "assistant", "content": msg})
                    if len(_session_chat_turns) > 12:
                        del _session_chat_turns[:-12]
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "fix":
                target = argv[0] if argv else "."
                inst = argv[1] if len(argv) > 1 else ""
                output_fn(colorize(f"Analyzing and fixing bugs in '{target}' with resident model...", CYAN, color_enabled))
                ok, msg, fixed = analyze_and_fix_bugs(target, inst, stream=stream)
                color = GREEN if ok else RED
                output_fn(colorize(msg, color, color_enabled))
                add_to_session_history(line, msg)
                if ok and fixed:
                    _session_chat_turns.append({"role": "user", "content": f"Fix bugs in {target}: {inst}"})
                    _session_chat_turns.append({"role": "assistant", "content": f"Fixed bugs in {len(fixed)} file(s):\n{msg}"})
                    if len(_session_chat_turns) > 12:
                        del _session_chat_turns[:-12]
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "browser_open":
                target = argv[0] if argv else ""
                if not target:
                    active_p = get_active_project_dir()
                    if active_p and (active_p / "index.html").is_file():
                        target = str(active_p / "index.html")
                ok, msg = open_in_browser(target, stream=stream)
                color = GREEN if ok else RED
                output_fn(colorize(msg, color, color_enabled))
                add_to_session_history(line, msg)
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "multi_agent":
                agent_prompt = argv[0] if argv else ""
                active_p = get_active_project_dir()
                try:
                    from research.multi_agent import MultiAgentTeam
                except ModuleNotFoundError:
                    from multi_agent import MultiAgentTeam
                team = MultiAgentTeam(
                    model_name=_active_model_override,
                    output_fn=output_fn,
                    color_enabled=color_enabled,
                )
                if agent_prompt.strip().lower() in ("status", "roster", "info", "models", ""):
                    output_fn(team.get_roster_summary())
                else:
                    _safe_console_emit(output_fn, colorize("🚀 Launching Autonomous Engineering Team (FIPA-ACL Standard)...", CYAN, color_enabled))
                    res = team.run_collaborative_workflow(agent_prompt, active_project_dir=active_p)
                    add_to_session_history(line, f"[Multi-Agent workflow completed for: {agent_prompt}]")
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "team_config":
                sub = argv[0].lower() if argv else "help"
                rest = " ".join(argv[1:]) if len(argv) > 1 else ""
                try:
                    from research.multi_agent import MultiAgentTeam
                except ModuleNotFoundError:
                    from multi_agent import MultiAgentTeam
                team = MultiAgentTeam(
                    output_fn=output_fn,
                    color_enabled=color_enabled,
                )
                if sub in ("set", "assign"):
                    msgs = team.registry.parse_and_apply_assignments(rest)
                    for m in msgs:
                        output_fn(colorize(f"  {m}", GREEN if "Assigned" in m else YELLOW, color_enabled))
                    output_fn("\n" + team.get_roster_summary())
                elif sub == "reset":
                    msg = team.registry.reset_to_defaults()
                    output_fn(colorize(f"  {msg}", GREEN, color_enabled))
                    output_fn("\n" + team.get_roster_summary())
                elif sub == "models":
                    output_fn(team.registry.format_available_models(color_enabled=color_enabled))
                else:
                    output_fn(team.registry.format_config_help(color_enabled=color_enabled))
                    output_fn("\n" + team.get_roster_summary())
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "mcp_hub":
                try:
                    from research.mcp_client import MCPRegistry
                except ModuleNotFoundError:
                    from mcp_client import MCPRegistry
                output_fn(MCPRegistry.format_status(color_enabled=color_enabled))
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "graphql_cmd":
                gql_text = argv[0] if argv else ""
                try:
                    from research.graphql_agent import GraphQLClient
                except ModuleNotFoundError:
                    from graphql_agent import GraphQLClient
                ep = os.environ.get("PAI_GRAPHQL_ENDPOINT", "http://127.0.0.1:4000/graphql")
                client = GraphQLClient(endpoint=ep)
                if "introspect" in gql_text.lower() or "schema" in gql_text.lower():
                    output_fn(colorize("Introspecting GraphQL Schema...", CYAN, color_enabled))
                    schema_str = client.get_sparse_schema_summary()
                    output_fn(schema_str)
                else:
                    output_fn(colorize(f"Executing GraphQL against {ep}...", CYAN, color_enabled))
                    res = client.execute(gql_text)
                    output_fn(json.dumps(res, indent=2, ensure_ascii=False))
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "skills_list":
                output_fn(format_skills_list(color_enabled=color_enabled))
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "skill_show":
                skill_name = argv[0] if argv else ""
                skill = get_skill(skill_name)
                if skill:
                    output_fn(format_skill_detail(skill, color_enabled=color_enabled))
                else:
                    output_fn(colorize(f"Error: Skill '{skill_name}' not found. Type /skills to view all available skills.", RED, color_enabled))
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "skill_learn":
                skill_name = argv[0] if argv else "custom-skill"
                instructions = argv[1] if len(argv) > 1 else ""
                description = argv[2] if len(argv) > 2 else f"Custom learned skill for {skill_name}"
                ok, msg = save_skill(name=skill_name, description=description, guidance=instructions)
                color = GREEN if ok else RED
                output_fn(colorize(msg, color, color_enabled))
                add_to_session_history(line, msg)
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "skill_delete":
                skill_name = argv[0] if argv else ""
                ok, msg = delete_skill(skill_name)
                color = GREEN if ok else RED
                output_fn(colorize(msg, color, color_enabled))
                add_to_session_history(line, msg)
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "cmd":
                import subprocess
                cmd_to_run = argv[0]
                try:
                    proc = subprocess.run(cmd_to_run, shell=True, text=True, capture_output=True, timeout=30)
                    cmd_out = proc.stdout
                    if proc.stderr:
                        cmd_out += ("\n" if cmd_out else "") + proc.stderr
                    if not cmd_out:
                        cmd_out = "[Command executed successfully with no output]"
                    output_fn(cmd_out.rstrip())
                    add_to_session_history(line, cmd_out)
                except subprocess.TimeoutExpired:
                    err_msg = "Error: Command timed out after 30 seconds."
                    output_fn(colorize(err_msg, RED, color_enabled))
                    add_to_session_history(line, err_msg)
                except Exception as e:
                    err_msg = f"Error executing command: {e}"
                    output_fn(colorize(err_msg, RED, color_enabled))
                    add_to_session_history(line, err_msg)
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "wifi":
                nets = scan_local_wifi()
                report = format_wifi_report(nets, color_enabled=color_enabled)
                output_fn(report)
                add_to_session_history(line, report)
                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
                continue
            elif action == "unknown_slash":
                msg = f"Unknown command '{argv[0]}'. Type /help for available commands or /exit to quit."
                output_fn(colorize(msg, RED, color_enabled))
                continue
            elif action == "error":
                output_fn(colorize(argv[0], RED, color_enabled))
                continue
            elif action in ("canonical", "chat"):
                cmd_name = argv[0] if argv else ""
                exec_argv = list(argv)
                if cmd_name == "code" and "--out" not in exec_argv:
                    if "--" in exec_argv:
                        dash_idx = exec_argv.index("--")
                        exec_argv = exec_argv[:dash_idx] + ["--out", "pai_output"] + exec_argv[dash_idx:]
                    else:
                        exec_argv = exec_argv + ["--out", "pai_output"]

                if _active_model_override and "--model" not in exec_argv:
                    if cmd_name in ("chat", "code", "analyze", "docs", "forecast"):
                        if "--" in exec_argv:
                            dash_idx = exec_argv.index("--")
                            exec_argv = exec_argv[:dash_idx] + ["--model", _active_model_override] + exec_argv[dash_idx:]
                        else:
                            exec_argv = exec_argv + ["--model", _active_model_override]

                if cmd_name == "chat" and _session_chat_turns:
                    os.environ["PAI_CHAT_HISTORY"] = json.dumps(_session_chat_turns[-6:])
                else:
                    os.environ.pop("PAI_CHAT_HISTORY", None)

                if cmd_name == "chat":
                    chat_query = argv[-1] if len(argv) > 1 else line
                    matched_skills = find_matching_skills(chat_query)
                    if matched_skills:
                        skill_blocks = []
                        for s in matched_skills:
                            skill_blocks.append(f"- Skill: {s.get('name')}\n  Description: {s.get('description')}\n  Guidance:\n{s.get('guidance')}")
                        os.environ["PAI_SKILL_HINTS"] = "\n\n".join(skill_blocks)
                        top_s = matched_skills[0]
                        _safe_console_emit(output_fn, colorize(f"💡 Active Skill Applied: {top_s['name']} - {top_s['description']}", CYAN, color_enabled))
                    else:
                        os.environ.pop("PAI_SKILL_HINTS", None)
                else:
                    os.environ.pop("PAI_SKILL_HINTS", None)

                spinner = ThinkingSpinner(stream) if cmd_name == "chat" else None
                capture = CaptureStream(stream, on_first_write=spinner.stop if spinner else None)
                try:
                    if spinner:
                        spinner.start()
                    with contextlib.redirect_stdout(capture):
                        execute_subcommand(exec_argv)
                except KeyboardInterrupt:
                    output_fn("\n[Operation cancelled by user]")
                except Exception as e:
                    output_fn(colorize(f"Error: {e}", RED, color_enabled))
                finally:
                    if spinner:
                        spinner.stop()
                    os.environ.pop("PAI_CHAT_HISTORY", None)
                    os.environ.pop("PAI_SKILL_HINTS", None)

                cmd_out = capture.getvalue()
                add_to_session_history(line, cmd_out)
                if cmd_name == "chat":
                    chat_prompt = argv[-1] if argv else line
                    _session_chat_turns.append({"role": "user", "content": chat_prompt})
                    if cmd_out and cmd_out.strip():
                        _session_chat_turns.append({"role": "assistant", "content": cmd_out.strip()})
                    if len(_session_chat_turns) > 12:
                        del _session_chat_turns[:-12]

                    # Auto-save generated code if prompt asked to save it
                    if "```" in cmd_out:
                        lower_line = line.lower()
                        active_p = get_active_project_dir()
                        if active_p and active_p.is_dir() and any(k in lower_line for k in ("update", "save", "add", "change", "wenas", "hadanna", "project", "folder", "script", "code", "drone", "game")):
                            block_pattern = re.compile(
                                r"(?:(?:###|####)\s*(?:\d+\.\s*)?(?:File:?\s*)?([a-zA-Z0-9_\-\.]+)[^\n]*\r?\n)?```([a-zA-Z0-9_\-]+)?\r?\n([\s\S]*?)(?:\r?\n```|\Z)"
                            )
                            for m in block_pattern.finditer(cmd_out):
                                target_fname = m.group(1)
                                lang_tag = (m.group(2) or "").lower()
                                block_code = m.group(3).strip()
                                if not target_fname:
                                    if lang_tag in ("javascript", "js") and (active_p / "script.js").is_file():
                                        target_fname = "script.js"
                                    elif lang_tag in ("html", "htm") and (active_p / "index.html").is_file():
                                        target_fname = "index.html"
                                    elif lang_tag == "css" and (active_p / "style.css").is_file():
                                        target_fname = "style.css"
                                    elif lang_tag in ("python", "py") and (active_p / "main.py").is_file():
                                        target_fname = "main.py"

                                if target_fname and len(block_code) > 20:
                                    target_file = active_p / target_fname
                                    try:
                                        bak = target_file.with_suffix(target_file.suffix + ".bak")
                                        bak.write_text(target_file.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
                                        target_file.write_text(block_code, encoding="utf-8")
                                        output_fn(colorize(f"[Auto-synced updated code to {target_file}]", GREEN, color_enabled))
                                    except Exception:
                                        pass

                        if any(k in lower_line for k in ("and save it", "save it in", "save it to", "save it on", "save it into", "save this in", "save this to", "save that in", "save that to", "save it on that folder")):
                            auto_target = None
                            if any(k in lower_line for k in ("that folder", "this folder", "the folder")):
                                for h_entry in reversed(get_session_history()):
                                    if "[Successfully initialized new project in " in h_entry[2]:
                                        m_p = re.search(r'\[Successfully initialized new project in ([^\]]+)\]', h_entry[2])
                                        if m_p:
                                            auto_target = m_p.group(1).strip()
                                            break
                                if not auto_target:
                                    auto_target = "Downloads"
                            else:
                                if "downloads" in lower_line:
                                    auto_target = "Downloads"
                                elif "desktop" in lower_line:
                                    auto_target = "Desktop"
                                elif "documents" in lower_line:
                                    auto_target = "Documents"

                            if auto_target:
                                ok_s, msg_s = save_session_output_to_file(auto_target)
                                if ok_s:
                                    output_fn(colorize(f"[{msg_s}]", GREEN, color_enabled))

                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
    finally:
        set_terminal_title("", stream)
        os.environ.pop("PAI_SHELL_ACTIVE", None)
        os.environ.pop("PAI_ACTIVE_MODEL", None)
        os.environ.pop("PAI_SKILL_HINTS", None)
        _active_model_override = None
        clear_session_history()
        _session_chat_turns.clear()
        if pinned:
            cleanup_pinned_layout(stream)
        else:
            restore_windows_console_mode()
