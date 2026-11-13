#!/usr/bin/env python3
"""Pre-commit and CI Secret Leak Scanner for Personal Agentic AI (PAI).

Audits tracked files and staging area to ensure no API keys, credentials,
cloud tokens, or private key material are committed to the git repository.
Fails closed (exit code 1) upon detecting any forbidden secrets.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

# Patterns identifying cloud AI API keys and cryptographic secrets
SECRET_PATTERNS = [
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google Cloud / Gemini API Key"),
    (re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}"), "OpenAI API Key"),
    (re.compile(r"gsk_[A-Za-z0-9]{40,}"), "Groq API Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{50,}"), "GitHub Fine-Grained Token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Cryptographic Private Key"),
]

# Sensitive file names that must never be tracked in git
FORBIDDEN_FILE_NAMES = [
    "cloud_ai.json",
    ".env",
    "credentials.json",
    "release.key",
    "tokens.json",
]

# Paths allowed to contain mock/dummy tokens or hashes in tests/evidence
EXEMPT_PATHS = [
    Path("docs/evidence"),
    Path("research/tests/test_shell.py"),
]


def is_exempt(rel_path: Path) -> bool:
    for exempt in EXEMPT_PATHS:
        try:
            rel_path.relative_to(exempt)
            return True
        except ValueError:
            pass
    return False


def get_tracked_files(repo_root: Path) -> List[Path]:
    """Retrieve all files tracked by git in the repository."""
    try:
        out = subprocess.check_output(
            ["git", "ls-files"],
            cwd=str(repo_root),
            text=True,
            encoding="utf-8",
        )
        return [repo_root / line.strip() for line in out.splitlines() if line.strip()]
    except Exception:
        # Fallback: scan all non-ignored files
        files = []
        for root, dirs, filenames in os.walk(repo_root):
            if any(p in root for p in [".git", "target", "dist", ".venv", "__pycache__"]):
                continue
            for fn in filenames:
                files.append(Path(root) / fn)
        return files


def audit_repository_secrets(repo_root: Path) -> Tuple[bool, List[str]]:
    """Scan tracked repository files for leaks of credentials and forbidden filenames."""
    violations: List[str] = []
    tracked = get_tracked_files(repo_root)

    for fpath in tracked:
        rel = fpath.relative_to(repo_root)
        name_lower = fpath.name.lower()

        # 1. Filename check
        for forbidden in FORBIDDEN_FILE_NAMES:
            if name_lower == forbidden or name_lower.endswith(f".{forbidden}"):
                violations.append(f"[FORBIDDEN FILE] Tracked secret file: {rel}")

        # Skip binary files, images, zip files, and exempt paths
        if is_exempt(rel):
            continue
        if fpath.suffix.lower() in [".png", ".jpg", ".ico", ".exe", ".zip", ".bin", ".tar", ".gz"]:
            continue

        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # 2. Content pattern check
        for pattern, label in SECRET_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                # Discard obviously mocked strings (e.g., test-fake-key)
                if "fake" in match.lower() or "mock" in match.lower() or "placeholder" in match.lower():
                    continue
                snippet = match[:8] + "..." + match[-4:] if len(match) > 12 else "[SECRET]"
                violations.append(f"[LEAK DETECTED] {label} ({snippet}) in {rel}")

    passed = len(violations) == 0
    return passed, violations


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    print("=" * 80)
    print("PAI REPOSITORY SECRET & API KEY LEAK SCANNER")
    print(f"Target Repository: {repo_root}")
    print("=" * 80)

    passed, violations = audit_repository_secrets(repo_root)

    if not passed:
        print("\n❌ CRITICAL: Secrets or forbidden credential files detected in git tree:")
        for v in violations:
            print(f"  • {v}")
        print("\nAction Required:")
        print("  1. Remove sensitive files from git tracking: git rm --cached <file>")
        print("  2. Ensure credentials live in ~/.pai/cloud_ai.json or environment variables.")
        print("  3. Check .gitignore to confirm secret files are ignored.")
        return 1

    print("\n✅ PASS: No API keys, credentials, or private keys detected in repository.")
    print("   Security boundary verified: cloud_ai.json remains strictly untracked.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
