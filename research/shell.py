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
import shutil
import sys
import threading
import time
from typing import Callable, Deque, List, Optional, Tuple

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
    "  /edit <file> <prompt> Edit an existing file (HTML, Python, JS, etc.) with instructions\n"
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


def get_resident_model_name() -> str:
    """Retrieves active resident model name or returns 'no model loaded yet'."""
    try:
        from router import ModelRouter
        router = ModelRouter(load_system_profile=True)
        resident = router.get_live_resident_model()
        if resident:
            return resident
    except Exception:
        pass
    return "no model loaded yet"


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

    last_entry = history[-1]
    last_query = last_entry[1]
    last_output = last_entry[2]
    if not last_output or not last_output.strip():
        return False, "Previous command produced no output to save."

    import re
    code_match = re.search(r"```(\w+)?\r?\n(.*?)\r?\n```", last_output, re.DOTALL)
    code_lang = ""
    if code_match:
        code_lang = (code_match.group(1) or "").lower()
        content = code_match.group(2)
    else:
        content = last_output.strip()

    target_clean = target_path_str.strip().strip('"').strip("'")
    target_lower = target_clean.lower()
    user_home = Path.home()

    if target_lower in ("downloads", "~/downloads"):
        base_dir = user_home / "Downloads"
        is_dir_target = True
    elif target_lower in ("desktop", "~/desktop"):
        base_dir = user_home / "Desktop"
        is_dir_target = True
    elif target_lower in ("documents", "~/documents"):
        base_dir = user_home / "Documents"
        is_dir_target = True
    else:
        candidate_p = Path(target_clean).expanduser().resolve()
        if candidate_p.is_dir() or (not candidate_p.suffix and not target_clean.endswith((".py", ".html", ".txt", ".json", ".js", ".md", ".rs", ".csv"))):
            base_dir = candidate_p
            is_dir_target = True
        else:
            base_dir = candidate_p.parent
            is_dir_target = False
            final_p = candidate_p

    if is_dir_target:
        c_lower = content.lower()
        if "<html" in c_lower or "<!doctype" in c_lower or "three.js" in c_lower or code_lang == "html":
            default_name = "game.html" if ("game" in last_query.lower() or "canvas" in c_lower or "game" in c_lower) else "index.html"
        elif "def " in content or "import " in content or code_lang in ("python", "py"):
            default_name = "app.py"
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
        return True, f"Saved {byte_count:,} bytes to {final_p}"
    except Exception as e:
        return False, f"Failed to save file: {e}"


def resolve_target_file(target_str: str) -> Optional[Path]:
    """
    Resolves a target file path from string.
    Supports absolute paths, relative paths, special directories (Downloads, Desktop, Documents),
    and bare filenames by searching cwd, Downloads, Desktop, Documents.
    Returns Path if file exists, None otherwise.
    """
    clean = target_str.strip().strip('"').strip("'")
    if not clean:
        return None

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

    edit_prompt = (
        f"You are an expert programmer and software editor.\n"
        f"Below is the complete content of the file '{resolved_path.name}':\n"
        f"```{lang}\n{original_content}\n```\n\n"
        f"User Modification Request:\n{instructions}\n\n"
        f"Apply all requested changes carefully.\n"
        f"Output the entire updated file inside a single ```{lang} ... ``` code block.\n"
        f"Do not omit code, do not use comments like '// rest unchanged', and provide the complete runnable file."
    )

    if executor is None:
        exec_fn = execute_subcommand
    else:
        exec_fn = executor

    spinner = ThinkingSpinner(stream)
    capture = CaptureStream(stream, on_first_write=spinner.stop)
    try:
        spinner.start()
        with contextlib.redirect_stdout(capture):
            exec_fn(["chat", "--", edit_prompt])
    except KeyboardInterrupt:
        return False, "Operation cancelled by user.", None
    except Exception as e:
        return False, f"Error generating file update: {e}", None
    finally:
        spinner.stop()

    model_out = capture.getvalue()
    if not model_out or not model_out.strip():
        return False, "Error: Model returned empty response.", None

    import re
    code_blocks = re.findall(r"```(?:\w+)?\r?\n(.*?)\r?\n```", model_out, re.DOTALL)
    if code_blocks:
        updated_content = max(code_blocks, key=len)
    else:
        updated_content = model_out.strip()

    bak_path = resolved_path.with_suffix(resolved_path.suffix + ".bak")
    try:
        bak_path.write_text(original_content, encoding="utf-8")
    except Exception:
        pass

    try:
        resolved_path.write_text(updated_content, encoding="utf-8")
    except Exception as e:
        return False, f"Error writing updated file '{resolved_path}': {e}", None

    msg = (
        f"[Successfully updated {resolved_path}]\n"
        f"[Backup saved to {bak_path}]"
    )
    return True, msg, updated_content


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
            if not args:
                return "error", ["Error: /edit requires a target file path and instructions (e.g. /edit Downloads\\game.html add score counter)."]
            if len(args) == 1:
                return "error", ["Error: Please provide modification instructions (e.g. /edit Downloads\\game.html add score counter)."]
            target = args[0]
            idx = stripped.find(tokens[0]) + len(tokens[0])
            rest = stripped[idx:].strip()
            if rest.startswith('"'):
                end_quote = rest.find('"', 1)
                instructions = rest[end_quote + 1:].strip() if end_quote != -1 else " ".join(args[1:])
            elif rest.startswith("'"):
                end_quote = rest.find("'", 1)
                instructions = rest[end_quote + 1:].strip() if end_quote != -1 else " ".join(args[1:])
            else:
                instructions = rest.split(None, 1)[1] if len(rest.split(None, 1)) > 1 else " ".join(args[1:])
            return "edit", [target, instructions]

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

    # Check for natural language editing intent referencing an existing file
    edit_keywords = ("edit", "modify", "wenas", "update", "change")
    if any(k in lower_unslashed for k in edit_keywords):
        try:
            tokens = tokenize_windows_line(stripped)
            for tok in tokens:
                resolved = resolve_target_file(tok)
                if resolved and resolved.is_file():
                    return "edit", [str(resolved), stripped]
        except Exception:
            pass

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
                    exec_argv = exec_argv + ["--out", "pai_output"]

                if cmd_name == "chat" and _session_chat_turns:
                    os.environ["PAI_CHAT_HISTORY"] = json.dumps(_session_chat_turns[-6:])
                else:
                    os.environ.pop("PAI_CHAT_HISTORY", None)

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

                cmd_out = capture.getvalue()
                add_to_session_history(line, cmd_out)
                if cmd_name == "chat":
                    chat_prompt = argv[-1] if argv else line
                    _session_chat_turns.append({"role": "user", "content": chat_prompt})
                    if cmd_out and cmd_out.strip():
                        _session_chat_turns.append({"role": "assistant", "content": cmd_out.strip()})
                    if len(_session_chat_turns) > 12:
                        del _session_chat_turns[:-12]

                cols, _ = get_terminal_dimensions()
                sep_char = "─" if can_encode_blocks(stream) else "-"
                output_fn(colorize(sep_char * min(cols, 80), DIM, color_enabled))
    finally:
        set_terminal_title("", stream)
        os.environ.pop("PAI_SHELL_ACTIVE", None)
        clear_session_history()
        _session_chat_turns.clear()
        if pinned:
            cleanup_pinned_layout(stream)
        else:
            restore_windows_console_mode()
