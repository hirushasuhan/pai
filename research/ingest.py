"""
Safe Ingestion Module for Phase 1 (ADR-011 / Days 2-3)
Enforces path boundaries, symlink safety, resource caps, binary detection,
secrets hygiene, and untrusted-data envelope wrapping.

Invariants:
1. Path resolution: os.path.realpath, rejects paths or symlinks escaping user root.
2. Device safety: rejects character/block devices, FIFOs, and sockets (fail-closed).
3. Secrets hygiene: denies sensitive files (.env, *.pem, id_rsa*, *.key, .npmrc, .netrc,
   .git-credentials, .pypirc, .htpasswd, *.tfstate*, *.p12, *.jks, credentials.json, etc.)
   and sensitive directories (.aws, .ssh, .gnupg, .docker) by name without reading.
4. Junk directory pruning: automatically skips known junk/build/cache directories
   (.git, node_modules, __pycache__, .venv, venv, dist, build, .tox, .idea, .vscode, target, etc.)
   with aggregated rejections so processing does not exhaust file limits or waste time.
5. Directory symlink safety: checks directory symlinks for escape or recursion loops, records
   relative rejections, and never silently drops.
6. Binary safety: detects NUL bytes (b'\\x00') and rejects binary files.
7. Text normalization: decodes UTF-8 (replace), normalizes newlines, strips non-printable control chars.
8. Bounded rejections: tracks exact rejection counts per reason code, capping individual item lists
   to prevent memory unbounded growth on massive trees.
9. Unforgeable envelope wrapping: wraps data in UNTRUSTED DATA envelopes using per-run / per-call
   cryptographic nonces and sanitizes headers/paths, preventing delimiter injection attacks.
10. Zero execution: never executes, imports, or evals any ingested content.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import hashlib
import os
import re
import secrets
import stat
from typing import Any, Dict, List, Optional, Set, Tuple

# -----------------------------------------------------------------------------
# Ingestion Limits & Defaults
# -----------------------------------------------------------------------------
DEFAULT_MAX_FILE_SIZE: int = 1_048_576      # 1 MB per file
DEFAULT_MAX_TOTAL_BYTES: int = 10_485_760   # 10 MB per run
DEFAULT_MAX_FILE_COUNT: int = 500           # 500 files per run
DEFAULT_MAX_DEPTH: int = 10                 # 10 subfolder levels
DEFAULT_MAX_LINE_LENGTH: int = 4096         # 4096 chars per line
DEFAULT_MAX_REJECTIONS_PER_REASON: int = 20 # Bounded rejections per reason code
DEFAULT_MAX_TOTAL_REJECTIONS: int = 500     # Bounded total rejections list size

DEFAULT_SECRET_DENY_PATTERNS: Tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.pem",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "*.key",
    "*.pfx",
    "*.pkcs12",
    "*.p12",
    "*.jks",
    "*.kdbx",
    "credentials.json",
    "service_account*.json",
    "service-account*.json",
    "service-account.json",
    ".kube/config",
    "docker/config.json",
    ".docker/config.json",
    ".npmrc",
    ".netrc",
    ".git-credentials",
    ".pypirc",
    ".htpasswd",
    "*.tfstate",
    "*.tfstate.*",
    "terraform.tfstate*",
    "credentials",
    "config.json",
    "secrets.yaml",
    "secrets.yml",
    "secrets.json",
    "token.txt",
    "*.enc",
)

DEFAULT_SENSITIVE_DIRS: Tuple[str, ...] = (
    ".aws",
    ".ssh",
    ".gnupg",
    ".docker",
    "docker",
    ".kube",
)

DEFAULT_JUNK_DIR_PATTERNS: Tuple[str, ...] = (
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".tox",
    ".idea",
    ".vscode",
    "target",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".coverage",
    "htmlcov",
)

UNTRUSTED_BEGIN_MARKER = "--- UNTRUSTED DATA BEGIN ---"
UNTRUSTED_END_MARKER = "--- UNTRUSTED DATA END ---"


def generate_envelope_nonce() -> str:
    """Generates an unforgeable 16-hex-char cryptographic nonce for envelope framing."""
    return secrets.token_hex(8)


def get_ingest_limits() -> Dict[str, Any]:
    """Returns canonical ingestion limits dict for inspectability and CLI --json output."""
    return {
        "max_file_size_bytes": DEFAULT_MAX_FILE_SIZE,
        "max_total_bytes": DEFAULT_MAX_TOTAL_BYTES,
        "max_file_count": DEFAULT_MAX_FILE_COUNT,
        "max_depth": DEFAULT_MAX_DEPTH,
        "max_line_length": DEFAULT_MAX_LINE_LENGTH,
        "max_rejections_per_reason": DEFAULT_MAX_REJECTIONS_PER_REASON,
        "max_total_rejections": DEFAULT_MAX_TOTAL_REJECTIONS,
        "secret_deny_patterns": list(DEFAULT_SECRET_DENY_PATTERNS),
        "sensitive_dirs": list(DEFAULT_SENSITIVE_DIRS),
        "junk_dir_patterns": list(DEFAULT_JUNK_DIR_PATTERNS),
    }


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class IngestedItem:
    path: str
    kind: str
    text: str
    truncated: bool
    sha256: str
    bytes_read: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "text": self.text,
            "truncated": self.truncated,
            "sha256": self.sha256,
            "bytes_read": self.bytes_read,
        }


@dataclasses.dataclass(frozen=True)
class IngestionRejection:
    path: str
    reason_code: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "reason_code": self.reason_code,
            "message": self.message,
        }


@dataclasses.dataclass
class IngestionReport:
    root: str
    items: List[IngestedItem]
    rejections: List[IngestionRejection]
    total_bytes: int
    total_files: int
    limits: Dict[str, Any]
    rejection_counts: Dict[str, int] = dataclasses.field(default_factory=dict)
    rejections_capped: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "items": [it.to_dict() for it in self.items],
            "rejections": [rej.to_dict() for rej in self.rejections],
            "rejection_counts": self.rejection_counts,
            "rejections_capped": self.rejections_capped,
            "total_bytes": self.total_bytes,
            "total_files": self.total_files,
            "limits": self.limits,
        }


@dataclasses.dataclass(frozen=True)
class UntrustedContextAssembly:
    text: str
    included_files: List[str]
    omitted_files: List[str]
    included_bytes: int
    omitted_bytes: int
    char_budget: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_files": len(self.included_files) + len(self.omitted_files),
            "included_files_count": len(self.included_files),
            "omitted_files_count": len(self.omitted_files),
            "included_files": list(self.included_files),
            "omitted_files": list(self.omitted_files),
            "included_bytes": self.included_bytes,
            "omitted_bytes": self.omitted_bytes,
            "char_budget": self.char_budget,
        }


# -----------------------------------------------------------------------------
# Sanitation & Normalization Helpers
# -----------------------------------------------------------------------------
# C0 control characters (excluding tab \t [0x09] and newline \n [0x0a])
_C0_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CONTROL_CHAR_RE = _C0_CONTROL_CHAR_RE

# Complete OSC escape sequences (e.g. \x1b]0;Title\x07 or \x1b]8;;url\x1b\ or 8-bit \x9d...)
# Matches OSC prefix up to BEL (\x07), ST (\x1b\ or \x9c), or end of line/string.
_OSC_ESCAPE_RE = re.compile(r"(?:\x1b\]|\x9d)[^\x07\x1b\x9c\r\n]*(?:\x07|\x1b\\|\x9c)?")

# ANSI CSI sequences (7-bit \x1b[ and 8-bit \x9b)
_CSI_ESCAPE_RE = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]")

# General 7-bit ESC sequences (\x1b followed by Fe / standard ESC bytes)
_GENERIC_ESC_RE = re.compile(r"\x1b[@-~]")

# C1 control characters (0x80 to 0x9f, including 0x9b 8-bit CSI and 0x9d 8-bit OSC)
_C1_CONTROL_CHAR_RE = re.compile(r"[\x80-\x9f]")

# Unicode Bidirectional (Bidi) text override and embedding controls:
# U+061C (ALM), U+200E (LRM), U+200F (RLM), U+202A-U+202E (LRE, RLE, PDF, LRO, RLO),
# U+2066-U+2069 (LRI, RLI, FSI, PDI)
_BIDI_CONTROL_RE = re.compile(r"[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def sanitize_terminal_output(text: str) -> str:
    """
    Sanitizes text intended for terminal display (model outputs, file paths, diagnostic text):
    - Normalizes carriage returns '\r\n' -> '\n'.
    - Strips complete OSC escape sequences (window titles, OSC 8 hyperlinks, URL parameters).
    - Strips ANSI CSI sequences (colors, cursor movements) including 8-bit CSI (\x9b).
    - Strips remaining 7-bit ESC sequences.
    - Strips C0 controls (preserving '\n' and '\t') and C1 controls (U+0080–U+009F).
    - Strips Unicode bidirectional (bidi) override controls (U+202A–202E, U+2066–2069, U+200E/F).
    """
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    # 1. Complete OSC sequences (must run first so OSC 8 hyperlink URLs/parameters are wholly stripped)
    t = _OSC_ESCAPE_RE.sub("", t)
    # 2. CSI sequences
    t = _CSI_ESCAPE_RE.sub("", t)
    # 3. Generic remaining ESC sequences
    t = _GENERIC_ESC_RE.sub("", t)
    # 4. C0 and C1 control characters (preserves \n and \t)
    t = _C0_CONTROL_CHAR_RE.sub("", t)
    t = _C1_CONTROL_CHAR_RE.sub("", t)
    # 5. Unicode Bidi override controls
    t = _BIDI_CONTROL_RE.sub("", t)
    return t


def sanitize_text_content(raw_bytes: bytes, max_line_length: int = DEFAULT_MAX_LINE_LENGTH) -> str:
    """
    Decodes raw bytes with explicit UTF-8 replacement policy, normalizes newlines,
    strips control characters (except newline and tab), and enforces line length caps.
    """
    text = raw_bytes.decode("utf-8", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_CHAR_RE.sub("", text)

    lines = text.split("\n")
    capped_lines = []
    for line in lines:
        if len(line) > max_line_length:
            capped_lines.append(line[:max_line_length] + " [TRUNCATED_LINE]")
        else:
            capped_lines.append(line)
    return "\n".join(capped_lines)


def sanitize_header(header: str) -> str:
    """
    Sanitizes header/path string: replaces newlines, strips non-printable control chars,
    and defangs untrusted markers.
    """
    h = header.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    h = _CONTROL_CHAR_RE.sub("", h)
    h = re.sub(r"---\s*UNTRUSTED DATA (BEGIN|END).*?---", "[STRIPPED_MARKER]", h)
    h = h.replace(UNTRUSTED_BEGIN_MARKER, "[STRIPPED_MARKER]")
    h = h.replace(UNTRUSTED_END_MARKER, "[STRIPPED_MARKER]")
    return h.strip()


def is_secret_file(
    file_path: str,
    deny_patterns: Tuple[str, ...] = DEFAULT_SECRET_DENY_PATTERNS,
    sensitive_dirs: Tuple[str, ...] = DEFAULT_SENSITIVE_DIRS,
) -> bool:
    """Returns True if filename or path matches any pattern in secret deny list or sensitive dirs."""
    norm = file_path.replace("\\", "/").lower()
    base = os.path.basename(norm)
    parts = [p for p in norm.split("/") if p]

    # 1. Check parent directory segments for sensitive directories
    for part in parts[:-1]:
        if part in sensitive_dirs:
            return True

    # 2. Check filename and path suffixes against deny patterns
    for pat in deny_patterns:
        pat_lower = pat.lower()
        if fnmatch.fnmatch(base, pat_lower):
            return True
        if "/" in pat_lower:
            if norm == pat_lower or norm.endswith("/" + pat_lower) or fnmatch.fnmatch(norm, f"*{pat_lower}*"):
                return True
    return False


_SECRET_CONTENT_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("pem_private_key", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", re.ASCII)),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b", re.ASCII)),
    ("api_secret_key", re.compile(r"\bsk-(?:proj-|ant-api03-)?[A-Za-z0-9_-]{20,}\b", re.ASCII)),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", re.ASCII)),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b", re.ASCII)),
)

_CRED_KEY_PART = (
    r"(?:[A-Za-z0-9_]*_)?"
    r"(?:password|passwd|pwd|api_key|apikey|secret_key|secret_access_key|aws_secret|"
    r"access_token|auth_token|refresh_token|private_key|client_secret|app_secret|jwt_secret)"
    r"(?:_[A-Za-z0-9_]+)?"
)

_NON_SECRET_KEY_SUFFIXES: Tuple[str, ...] = (
    "_hash",
    "_field",
    "_input",
    "_validator",
    "_policy",
    "_length",
    "_regex",
    "_pattern",
    "_error",
    "_label",
    "_prompt",
    "_header",
    "_name",
    "_path",
    "_file",
    "_type",
    "_column",
    "_form",
    "_widget",
    "_count",
    "_enabled",
    "_required",
)

_CONFIG_FILE_EXTENSIONS: Tuple[str, ...] = (
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".yaml",
    ".yml",
    ".toml",
    ".properties",
)

_INLINE_CREDENTIAL_QUOTED_RE = re.compile(
    rf"""(?:^|[\s,{{])(?:export\s+)?["']?(?P<key>{_CRED_KEY_PART})["']?[ \t]*(?:=|:)[ \t]*["'](?P<val>[^"'\r\n]{{6,}})["']""",
    re.IGNORECASE | re.MULTILINE | re.ASCII,
)

_INLINE_CREDENTIAL_UNQUOTED_RE = re.compile(
    rf"""(?:^|\n)[ \t]*(?:export[ \t]+)?(?P<key>{_CRED_KEY_PART})[ \t]*(?:=|:)[ \t]*(?P<val>[^\s#"'\r\n();,\[\]{{}}]{{6,}})[ \t]*(?:#[^\r\n]*)?(?=\r?\n|$)""",
    re.IGNORECASE | re.ASCII,
)

_DB_URL_PASSWORD_RE = re.compile(
    r"\b(?:postgres(?:ql)?(?:\+[a-z0-9_]+)?|mysql(?:\+[a-z0-9_]+)?|mariadb(?:\+[a-z0-9_]+)?|"
    r"mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql(?:\+[a-z0-9_]+)?)://"
    r"[^/\s:@\"']*:(?P<pw>[^/\s@\"']{4,})@[^/\s\"']+",
    re.IGNORECASE | re.ASCII,
)

_BENIGN_CREDENTIAL_VALUES = frozenset({
    "none",
    "null",
    "true",
    "false",
    "changeme",
    "password",
    "secret",
    "apikey",
    "api_key",
    "your_api_key",
    "your-api-key",
    "your_password",
    "your-password",
    "your_secret",
    "your_token",
    "example",
    "dummy",
    "placeholder",
    "redacted",
    "todo",
    "fixme",
    "test",
    "testing",
    "mock",
    "sample",
    "default",
    "empty",
    "unknown",
    "unverified",
    "postgres",
    "admin",
    "guest",
    "root",
})

_BENIGN_CREDENTIAL_PREFIXES = (
    "os.environ",
    "os.getenv",
    "environ.",
    "getenv(",
    "settings.",
    "config.",
    "args.",
    "self.",
    "cls.",
    "req.",
    "request.",
    "env.",
    "process.env",
    "std::env",
    "${",
    "$(",
    "%(",
    "{{",
    "your_",
    "your-",
    "example_",
    "example-",
    "dummy_",
    "placeholder_",
    "test_",
    "mock_",
    "user_input",
    "raw_",
    "hashed_",
    "input_",
)


def _is_non_secret_key_name(key_name: str) -> bool:
    """Returns True if the LHS variable/key name denotes a hash, UI field, validator, or metadata rather than a secret."""
    k = key_name.strip().lower()
    return any(k.endswith(suffix) for suffix in _NON_SECRET_KEY_SUFFIXES)


def _is_config_file_for_unquoted_secrets(file_path: Optional[str]) -> bool:
    """
    Returns True if unquoted `KEY = VALUE` credential scanning applies to `file_path`.
    When `file_path` is provided, only configuration-style files (.env, .ini, .cfg, .conf,
    .yaml, .yml, .toml, .properties) enable the unquoted rule; code files require quoted literals.
    """
    if file_path is None:
        return True
    norm = file_path.replace("\\", "/").lower()
    base = os.path.basename(norm)
    if base == ".env" or base.startswith(".env."):
        return True
    return base.endswith(_CONFIG_FILE_EXTENSIONS)


def _is_benign_credential_rhs(raw_val: str, min_len: int = 6) -> bool:
    """Returns True if a matched credential RHS is an env lookup, variable reference, or placeholder."""
    v = raw_val.strip()
    if len(v) < min_len:
        return True
    # Prose strings with spaces are not raw credential tokens/passwords
    if " " in v or "\t" in v:
        return True
    v_low = v.lower()
    if v_low in _BENIGN_CREDENTIAL_VALUES:
        return True
    if any(v_low.startswith(p) for p in _BENIGN_CREDENTIAL_PREFIXES):
        return True
    if (v.startswith("<") and v.endswith(">")) or set(v_low) <= {"*", "x", ".", "-", "_"}:
        return True
    return False


def _is_literal_like_unquoted_rhs(raw_val: str) -> bool:
    """
    Returns True if an unquoted RHS looks like a secret literal in a config file rather than
    a code identifier or attribute chain (e.g. `user_input_password`, `userInput`, `user.password`).
    """
    if _is_benign_credential_rhs(raw_val):
        return False
    v = raw_val.strip()
    # Pure ASCII alphabetic/underscore identifiers or dotted identifier chains without digits/symbols
    # (e.g. `user_input_password`, `userInput`, `getpass.getpass`, `user.password`) are code identifiers.
    parts = v.split(".")
    if all(p.isascii() and p.isidentifier() for p in parts) and not any(ch in "0123456789" for ch in v):
        return False
    return True


def scan_secret_content(text: str, file_path: Optional[str] = None) -> Optional[str]:
    """
    Scans text content for embedded high-confidence credential/private-key patterns:
    - Token formats: PEM private keys, AWS access keys (`AKIA`/`ASIA`), GitHub tokens (`ghp_`/`github_pat_`),
      OpenAI/Anthropic keys (`sk-`), Slack tokens (`xox`), Google API keys (`AIza`).
    - Database URLs with embedded passwords (`postgres://user:pass@host/db`, `mysql://...`, `redis://...`).
    - Quoted inline credential assignments (`password = "..."`, `API_KEY = "..."`, `AWS_SECRET_ACCESS_KEY = "..."`).
    - Unquoted inline credential assignments (`DB_PASSWORD=...`, `AWS_SECRET_ACCESS_KEY=...`) in
      configuration-style files (`.env`, `.ini`, `.cfg`, `.conf`, `.yaml`, `.yml`, `.toml`, `.properties`)
      where the right-hand side looks like a secret literal rather than a code expression or variable identifier.
    Returns the pattern label if a match is found, or None if clean. Never echoes the secret value.
    """
    if not text:
        return None
    for label, pattern in _SECRET_CONTENT_PATTERNS:
        if pattern.search(text):
            return label
    for m in _DB_URL_PASSWORD_RE.finditer(text):
        if not _is_benign_credential_rhs(m.group("pw"), min_len=4):
            return "database_url_password"
    for m in _INLINE_CREDENTIAL_QUOTED_RE.finditer(text):
        if _is_non_secret_key_name(m.group("key")):
            continue
        if not _is_benign_credential_rhs(m.group("val")):
            return "inline_secret_assignment"
    if _is_config_file_for_unquoted_secrets(file_path):
        for m in _INLINE_CREDENTIAL_UNQUOTED_RE.finditer(text):
            if _is_non_secret_key_name(m.group("key")):
                continue
            if _is_literal_like_unquoted_rhs(m.group("val")):
                return "inline_secret_assignment"
    return None


def is_junk_dir(dirname: str, junk_patterns: Tuple[str, ...] = DEFAULT_JUNK_DIR_PATTERNS) -> bool:
    """Returns True if dirname matches any junk directory pattern (platform-independent)."""
    norm = dirname.replace("\\", "/").rstrip("/")
    base = norm.rsplit("/", 1)[-1].lower()
    for pat in junk_patterns:
        if fnmatch.fnmatch(base, pat.lower()):
            return True
    return False


def defang_envelope_markers(text: str, nonce: Optional[str] = None) -> str:
    """
    Replaces embedded envelope markers and pattern variations to prevent
    prompt-injection delimiter hijacking.
    """
    sanitized = text.replace(UNTRUSTED_BEGIN_MARKER, "[STRIPPED_MARKER]")
    sanitized = sanitized.replace(UNTRUSTED_END_MARKER, "[STRIPPED_MARKER]")
    sanitized = re.sub(r"---\s*UNTRUSTED DATA (BEGIN|END).*?---", "[STRIPPED_MARKER]", sanitized)
    if nonce:
        sanitized = sanitized.replace(f"[{nonce}]", "[STRIPPED_NONCE]")
        sanitized = sanitized.replace(nonce, "[STRIPPED_NONCE]")
    return sanitized


def wrap_untrusted_envelope(
    content: str,
    header: Optional[str] = None,
    nonce: Optional[str] = None,
) -> str:
    """
    Wraps content inside standardized UNTRUSTED DATA envelope with internal marker defanging
    and cryptographic nonce protection.
    """
    n = nonce or generate_envelope_nonce()
    begin_marker = f"--- UNTRUSTED DATA BEGIN [{n}] ---"
    end_marker = f"--- UNTRUSTED DATA END [{n}] ---"

    clean_body = defang_envelope_markers(content, nonce=n)
    lines = [begin_marker]
    if header:
        clean_header = sanitize_header(header)
        clean_header = defang_envelope_markers(clean_header, nonce=n)
        lines.append(f"Source: {clean_header}")
    lines.append(clean_body)
    lines.append(end_marker)
    return "\n".join(lines)


_QUESTION_STOP_WORDS: Set[str] = {
    "what", "are", "the", "main", "and", "in", "of", "to", "for", "how",
    "is", "with", "from", "that", "this", "does", "why", "which", "when",
    "where", "who", "by", "on", "at", "an", "as", "be", "or", "it", "can",
    "explain", "describe", "tell", "me", "about", "defined", "used",
    "ekak", "eke", "eka", "gana", "monawada", "kohomada", "kiyanna", "thiyena",
}


def _extract_question_tokens(question: Optional[str]) -> Tuple[List[str], List[str]]:
    """
    Extracts deterministic lowercase compound identifiers (e.g. 'adr-011', 'ingest.py', '011')
    and individual word tokens from a user question for context file ranking.
    """
    if not question or not question.strip():
        return [], []
    q_lower = question.lower()
    # Compound tokens with hyphens, underscores, or dots (e.g. adr-011, verify_loop.py)
    compound_raw = re.findall(r"[a-z0-9]+(?:[-_.][a-z0-9]+)+", q_lower)
    word_raw = re.findall(r"[a-z0-9]{2,}", q_lower)

    compounds: List[str] = []
    seen_c: Set[str] = set()
    for c in compound_raw:
        if c not in seen_c:
            seen_c.add(c)
            compounds.append(c)
    for w in word_raw:
        if any(ch.isdigit() for ch in w) and w not in seen_c:
            seen_c.add(w)
            compounds.append(w)

    words: List[str] = []
    seen_w: Set[str] = set()
    for w in word_raw:
        if w not in _QUESTION_STOP_WORDS and w not in seen_w:
            seen_w.add(w)
            words.append(w)

    return compounds, words


def _question_overlap_sort_key(
    item: IngestedItem,
    compounds: List[str],
    words: List[str],
) -> Tuple[int, int, int, int, str]:
    """
    Returns a deterministic sort key ranking files by question overlap:
    1. File name / path compound & identifier token matches (descending)
    2. File name / path word token matches (descending)
    3. File content token matches (descending)
    4. File size in bytes (ascending tie-breaker)
    5. Relative file path (ascending tie-breaker)
    """
    if not compounds and not words:
        return (0, 0, 0, item.bytes_read, item.path)

    norm_path = item.path.replace("\\", "/").lower()
    base_name = os.path.basename(norm_path)
    text_lower = item.text.lower()

    fname_compound_hits = sum(1 for c in compounds if c in base_name or c in norm_path)
    fname_word_hits = sum(1 for w in words if w in base_name or w in norm_path)
    content_hits = sum(1 for c in compounds if c in text_lower) + sum(
        1 for w in words if w in text_lower
    )

    return (
        -fname_compound_hits,
        -fname_word_hits,
        -content_hits,
        item.bytes_read,
        item.path,
    )


def assemble_untrusted_context(
    report: IngestionReport,
    char_budget: int = 32_000,
    nonce: Optional[str] = None,
    include_manifest: bool = True,
    question: Optional[str] = None,
) -> UntrustedContextAssembly:
    """
    Assembles ingested items into an untrusted-data envelope block respecting a character budget.
    Includes a complete file manifest so the model has visibility into the entire codebase layout,
    ranks files deterministically by question overlap (file names first, then content overlap,
    then size/path tie-breaker), tracks included vs omitted files and bytes, and applies
    cryptographic nonces.
    """
    run_nonce = nonce or generate_envelope_nonce()
    manifest_lines = []
    if include_manifest and report.items:
        manifest_lines.append(f"=== COMPLETE FILE MANIFEST ({len(report.items)} files) ===")
        for it in report.items:
            clean_p = sanitize_header(it.path)
            manifest_lines.append(f"- {clean_p} ({it.bytes_read} bytes)")
        manifest_lines.append("=== END MANIFEST ===\n")

    manifest_block = "\n".join(manifest_lines)

    sections = []
    included_files = []
    omitted_files = []
    included_bytes = 0
    omitted_bytes = 0

    manifest_cost = len(manifest_block)
    effective_budget = max(0, char_budget - manifest_cost)
    current_chars = 0

    compounds, words = _extract_question_tokens(question)
    ordered_items = sorted(
        report.items,
        key=lambda it: _question_overlap_sort_key(it, compounds, words),
    )
    for item in ordered_items:
        clean_item_path = sanitize_header(item.path)
        item_header = f"File: {clean_item_path} (SHA-256: {item.sha256[:16]}...)"
        wrapped = wrap_untrusted_envelope(item.text, header=item_header, nonce=run_nonce)

        if current_chars + len(wrapped) > effective_budget:
            remaining = effective_budget - current_chars
            if remaining > 200 and not included_files:
                truncated_text = item.text[: max(0, remaining - 150)] + "\n... [CONTEXT_BUDGET_TRUNCATED]"
                wrapped_trunc = wrap_untrusted_envelope(truncated_text, header=item_header, nonce=run_nonce)
                sections.append(wrapped_trunc)
                current_chars += len(wrapped_trunc)
                included_files.append(item.path)
                included_bytes += len(truncated_text.encode("utf-8"))
            omitted_files.append(item.path)
            omitted_bytes += item.bytes_read
            continue

        sections.append(wrapped)
        current_chars += len(wrapped)
        included_files.append(item.path)
        included_bytes += item.bytes_read

    if omitted_files:
        omitted_summary = (
            f"\n[NOTICE: Context budget ({char_budget} chars) reached. "
            f"Full text included for {len(included_files)}/{len(report.items)} files. "
            f"{len(omitted_files)} files omitted from body (refer to manifest above).]"
        )
        sections.append(omitted_summary)

    full_text = (manifest_block + "\n\n".join(sections)).strip()

    return UntrustedContextAssembly(
        text=full_text,
        included_files=included_files,
        omitted_files=omitted_files,
        included_bytes=included_bytes,
        omitted_bytes=omitted_bytes,
        char_budget=char_budget,
    )


def format_untrusted_context(
    report: IngestionReport,
    char_budget: int = 32_000,
    nonce: Optional[str] = None,
    question: Optional[str] = None,
) -> str:
    """Convenience helper returning assembled context text."""
    return assemble_untrusted_context(
        report,
        char_budget=char_budget,
        nonce=nonce,
        question=question,
    ).text


# -----------------------------------------------------------------------------
# Core Ingestion Logic
# -----------------------------------------------------------------------------
def ingest_file(
    file_path: str,
    root_path: Optional[str] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    deny_patterns: Tuple[str, ...] = DEFAULT_SECRET_DENY_PATTERNS,
) -> Tuple[Optional[IngestedItem], Optional[IngestionRejection]]:
    """
    Safely ingests a single file, verifying boundaries, secrets hygiene, and content validity.
    Always reports relative paths in rejections.
    """
    if root_path is None:
        root_path = os.path.dirname(os.path.abspath(file_path))

    canonical_root = os.path.realpath(os.path.abspath(root_path))
    abs_target = os.path.abspath(file_path)

    # Relative display path
    try:
        rel_path = os.path.relpath(abs_target, canonical_root)
    except ValueError:
        rel_path = file_path

    # 1. Existence check
    if not os.path.lexists(abs_target):
        return None, IngestionRejection(
            path=rel_path,
            reason_code="NOT_FOUND",
            message=f"Target file does not exist: {os.path.basename(file_path)}",
        )

    # 2. Symlink escape check
    if os.path.islink(abs_target):
        target_dest = os.path.realpath(abs_target)
        try:
            common = os.path.commonpath([canonical_root, target_dest])
        except ValueError:
            common = ""
        if common != canonical_root:
            return None, IngestionRejection(
                path=rel_path,
                reason_code="SYMLINK_ESCAPE",
                message=f"Symlink points outside root boundary: {os.path.basename(target_dest)}",
            )

    # 3. Path boundary check
    real_target = os.path.realpath(abs_target)
    try:
        common = os.path.commonpath([canonical_root, real_target])
    except ValueError:
        common = ""
    if common != canonical_root:
        return None, IngestionRejection(
            path=rel_path,
            reason_code="OUTSIDE_ROOT",
            message=f"Target path resolves outside root boundary: {os.path.basename(real_target)}",
        )

    # 4. Device / Special file check
    try:
        lst = os.lstat(abs_target)
        if not stat.S_ISREG(lst.st_mode) and not stat.S_ISLNK(lst.st_mode):
            return None, IngestionRejection(
                path=rel_path,
                reason_code="SPECIAL_FILE",
                message=f"Target is a special device file or FIFO (mode {oct(lst.st_mode)})",
            )
        st = os.stat(real_target)
        if not stat.S_ISREG(st.st_mode):
            return None, IngestionRejection(
                path=rel_path,
                reason_code="SPECIAL_FILE",
                message=f"Target resolves to a non-regular file (mode {oct(st.st_mode)})",
            )
    except Exception as e:
        return None, IngestionRejection(
            path=rel_path,
            reason_code="STAT_ERROR",
            message=f"Failed to inspect file status: {e}",
        )

    # 5. Secrets hygiene check
    if is_secret_file(file_path, deny_patterns) or is_secret_file(abs_target, deny_patterns) or is_secret_file(real_target, deny_patterns):
        return None, IngestionRejection(
            path=rel_path,
            reason_code="SECRET_FILE",
            message=f"Access denied to secret file pattern: {os.path.basename(file_path)}",
        )

    # 6. Read content with size capping
    try:
        with open(real_target, "rb") as f:
            raw_data = f.read(max_file_size + 1)
    except Exception as e:
        return None, IngestionRejection(
            path=rel_path,
            reason_code="READ_ERROR",
            message=f"Failed to read file: {e}",
        )

    truncated = False
    if len(raw_data) > max_file_size:
        truncated = True
        raw_data = raw_data[:max_file_size]

    # 7. Binary check (NUL byte presence)
    if b"\x00" in raw_data:
        return None, IngestionRejection(
            path=rel_path,
            reason_code="BINARY_CONTENT",
            message="Binary content detected (contains NUL bytes)",
        )

    # 8. Sanitize and normalize text
    norm_text = sanitize_text_content(raw_data, max_line_length=max_line_length)

    # 9. Content-based secret scanning (PEM private keys, AWS AKIA/ASIA, GitHub ghp_, sk-*, Slack xox*, DB URLs, inline assignments)
    secret_match = scan_secret_content(norm_text, file_path=file_path)
    if secret_match is not None:
        return None, IngestionRejection(
            path=rel_path,
            reason_code="SECRET_CONTENT",
            message=f"Access denied: secret credential pattern ({secret_match}) detected in file content: {os.path.basename(file_path)}",
        )

    sha256_hash = hashlib.sha256(raw_data).hexdigest()

    item = IngestedItem(
        path=rel_path,
        kind="file",
        text=norm_text,
        truncated=truncated,
        sha256=sha256_hash,
        bytes_read=len(raw_data),
    )
    return item, None


def ingest_folder(
    folder_path: str,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_file_count: int = DEFAULT_MAX_FILE_COUNT,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    deny_patterns: Tuple[str, ...] = DEFAULT_SECRET_DENY_PATTERNS,
    junk_patterns: Tuple[str, ...] = DEFAULT_JUNK_DIR_PATTERNS,
    include_junk: bool = False,
    max_rejections_per_reason: int = DEFAULT_MAX_REJECTIONS_PER_REASON,
    max_total_rejections: int = DEFAULT_MAX_TOTAL_REJECTIONS,
) -> IngestionReport:
    """
    Recursively scans and safely ingests all text files within a folder boundary.
    Enforces total file count, total byte budget, max depth, symlink escapes, secrets denial,
    junk directory pruning (unless include_junk=True), and capped rejection tracking.
    """
    canonical_root = os.path.realpath(os.path.abspath(folder_path))
    limits = {
        "max_file_size_bytes": max_file_size,
        "max_total_bytes": max_total_bytes,
        "max_file_count": max_file_count,
        "max_depth": max_depth,
        "max_line_length": max_line_length,
        "include_junk": include_junk,
        "max_rejections_per_reason": max_rejections_per_reason,
        "max_total_rejections": max_total_rejections,
        "secret_deny_patterns": list(deny_patterns),
        "junk_dir_patterns": list(junk_patterns),
    }

    if not os.path.exists(canonical_root) or not os.path.isdir(canonical_root):
        rejections = [
            IngestionRejection(
                path=folder_path,
                reason_code="NOT_FOUND",
                message=f"Root directory does not exist or is not a directory: {folder_path}",
            )
        ]
        return IngestionReport(
            root=folder_path,
            items=[],
            rejections=rejections,
            total_bytes=0,
            total_files=0,
            limits=limits,
            rejection_counts={"NOT_FOUND": 1},
            rejections_capped=False,
        )

    items: List[IngestedItem] = []
    rejections: List[IngestionRejection] = []
    rejection_counts: Dict[str, int] = {}
    rejections_capped = False
    total_bytes = 0

    def add_rejection(rej: IngestionRejection) -> None:
        nonlocal rejections_capped
        code = rej.reason_code
        rejection_counts[code] = rejection_counts.get(code, 0) + 1
        if (
            rejection_counts[code] <= max_rejections_per_reason
            and len(rejections) < max_total_rejections
        ):
            rejections.append(rej)
        else:
            rejections_capped = True

    for current_dir, dirnames, filenames in os.walk(canonical_root, followlinks=False):
        rel_dir = os.path.relpath(current_dir, canonical_root)
        depth = 0 if rel_dir == "." else len(rel_dir.split(os.sep))

        if depth > max_depth:
            add_rejection(
                IngestionRejection(
                    path=rel_dir,
                    reason_code="MAX_DEPTH_EXCEEDED",
                    message=f"Recursion depth {depth} exceeds max depth limit {max_depth}",
                )
            )
            dirnames.clear()
            continue

        # Prune Junk Directories & Symlinked Directories
        pruned_dirs = []
        for d in list(dirnames):
            dpath = os.path.join(current_dir, d)
            rel_dpath = os.path.relpath(dpath, canonical_root)

            # Check if directory entry is a symlink
            if os.path.islink(dpath):
                pruned_dirs.append(d)
                target_dest = os.path.realpath(dpath)
                try:
                    common = os.path.commonpath([canonical_root, target_dest])
                except ValueError:
                    common = ""
                if common != canonical_root:
                    add_rejection(
                        IngestionRejection(
                            path=rel_dpath,
                            reason_code="SYMLINK_ESCAPE",
                            message=f"Symlinked directory points outside root boundary: {os.path.basename(target_dest)}",
                        )
                    )
                else:
                    add_rejection(
                        IngestionRejection(
                            path=rel_dpath,
                            reason_code="SYMLINK_DIRECTORY",
                            message=f"Skipped internal directory symlink: {rel_dpath}",
                        )
                    )
                continue

            # Check if directory is a junk / cache / build directory
            if not include_junk and is_junk_dir(d, junk_patterns=junk_patterns):
                pruned_dirs.append(d)
                add_rejection(
                    IngestionRejection(
                        path=rel_dpath,
                        reason_code="JUNK_DIRECTORY",
                        message=f"Skipped junk directory: {d}",
                    )
                )
                continue

        # Remove pruned directories in-place so os.walk will not descend
        for d in pruned_dirs:
            dirnames.remove(d)

        # Sort for deterministic processing order
        filenames.sort()
        dirnames.sort()

        for fname in filenames:
            fpath = os.path.join(current_dir, fname)
            rel_fpath = os.path.relpath(fpath, canonical_root)

            # Check file count limit
            if len(items) >= max_file_count:
                add_rejection(
                    IngestionRejection(
                        path=rel_fpath,
                        reason_code="FILE_COUNT_EXCEEDED",
                        message=f"Max file count limit reached ({max_file_count})",
                    )
                )
                continue

            # Check total byte budget limit
            if total_bytes >= max_total_bytes:
                add_rejection(
                    IngestionRejection(
                        path=rel_fpath,
                        reason_code="TOTAL_BYTES_EXCEEDED",
                        message=f"Total ingested byte budget reached ({max_total_bytes} bytes)",
                    )
                )
                continue

            item, rej = ingest_file(
                file_path=fpath,
                root_path=canonical_root,
                max_file_size=max_file_size,
                max_line_length=max_line_length,
                deny_patterns=deny_patterns,
            )

            if rej is not None:
                add_rejection(rej)
            elif item is not None:
                if total_bytes + item.bytes_read > max_total_bytes:
                    add_rejection(
                        IngestionRejection(
                            path=item.path,
                            reason_code="TOTAL_BYTES_EXCEEDED",
                            message=f"Ingesting {item.bytes_read} bytes would exceed total budget ({max_total_bytes})",
                        )
                    )
                else:
                    items.append(item)
                    total_bytes += item.bytes_read

    if rejections_capped:
        rejections.append(
            IngestionRejection(
                path="[REJECTIONS_SUMMARY]",
                reason_code="REJECTIONS_CAPPED",
                message=f"Rejection list capped for memory bounds. Total rejections by reason: {dict(rejection_counts)}",
            )
        )

    return IngestionReport(
        root=canonical_root,
        items=items,
        rejections=rejections,
        total_bytes=total_bytes,
        total_files=len(items),
        limits=limits,
        rejection_counts=rejection_counts,
        rejections_capped=rejections_capped,
    )
