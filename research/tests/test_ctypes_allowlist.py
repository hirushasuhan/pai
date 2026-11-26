"""
Policy Test: Ctypes Import Allow-List Enforcement (ADR-011 / Safety Policy)

Enforces that arbitrary Python modules across the repository cannot import
the low-level 'ctypes' module without an explicit architecture review and inclusion
in the approved allow-list.

Approved production modules:
1. hardware_telemetry.py  (Win32 GlobalMemoryStatusEx, GetSystemPowerStatus)
2. memory_probe.py        (Win32 VirtualQueryEx, ProcessMemoryCounters)
3. secure_buffer.py       (C-runtime memset memory zeroization)
4. sandbox_win32.py       (Win32 AppContainer & Job Object restricted runner)
5. shell.py               (Win32 console mode query and Virtual Terminal Processing enablement/restoration per Finding EY, ADR-014)
6. credential_store.py    (Win32 DPAPI CryptProtectData/CryptUnprotectData + LocalFree per FINDING-11, ADR-011)
"""

import ast
import os
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

APPROVED_CTYPES_MODULES = {
    "hardware_telemetry.py",
    "memory_probe.py",
    "secure_buffer.py",
    "sandbox_win32.py",
    "shell.py",
    "credential_store.py",
}


class TestCtypesAllowlist(unittest.TestCase):
    def test_ctypes_imports_restricted_to_allowlist(self):
        """Ensures only specifically reviewed and approved modules import ctypes."""
        offending_modules = []

        for root, dirs, files in os.walk(ROOT_DIR):
            # Skip test directory, caches, and build artifacts
            if "tests" in root.replace("\\", "/").split("/"):
                continue
            if "__pycache__" in root or ".git" in root:
                continue

            for fname in files:
                if not fname.endswith(".py"):
                    continue

                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        tree = ast.parse(f.read(), filename=fname)
                except Exception:
                    continue

                has_ctypes = False
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name == "ctypes" or alias.name.startswith("ctypes."):
                                has_ctypes = True
                                break
                    elif isinstance(node, ast.ImportFrom):
                        if node.module == "ctypes" or (node.module and node.module.startswith("ctypes.")):
                            has_ctypes = True
                            break

                if has_ctypes and fname not in APPROVED_CTYPES_MODULES:
                    rel_path = os.path.relpath(fpath, ROOT_DIR)
                    offending_modules.append(rel_path)

        self.assertEqual(
            offending_modules,
            [],
            f"Unauthorized 'ctypes' imports detected outside policy allow-list: {offending_modules}. "
            f"Only {sorted(list(APPROVED_CTYPES_MODULES))} are permitted per ADR-011 and ADR-014."
        )

    def test_shell_ctypes_usage_restricted_to_approved_console_apis(self):
        """
        Finding FI: Ensures shell.py references NO ctypes or kernel32 attributes
        other than the three approved console mode functions and standard types.
        """
        shell_path = os.path.join(ROOT_DIR, "shell.py")
        self.assertTrue(os.path.isfile(shell_path), "shell.py must exist in research root")

        with open(shell_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename="shell.py")

        ALLOWED_KERNEL32_FUNCS = {"GetStdHandle", "GetConsoleMode", "SetConsoleMode"}
        ALLOWED_CTYPES_ATTRS = {"windll", "c_ulong", "POINTER", "byref"}
        ALLOWED_WINTYPES_ATTRS = {"HANDLE", "DWORD", "BOOL"}

        unauthorized = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name) and node.value.id == "kernel32":
                    if node.attr not in ALLOWED_KERNEL32_FUNCS:
                        unauthorized.append(f"kernel32.{node.attr}")
                elif isinstance(node.value, ast.Name) and node.value.id == "ctypes":
                    if node.attr not in ALLOWED_CTYPES_ATTRS:
                        unauthorized.append(f"ctypes.{node.attr}")
                elif isinstance(node.value, ast.Name) and node.value.id == "wintypes":
                    if node.attr not in ALLOWED_WINTYPES_ATTRS:
                        unauthorized.append(f"wintypes.{node.attr}")

        self.assertEqual(
            unauthorized,
            [],
            f"Unauthorized ctypes/kernel32 attribute usage detected in shell.py: {unauthorized}. "
            f"shell.py is restricted exclusively to {sorted(list(ALLOWED_KERNEL32_FUNCS))} per ADR-011 and ADR-014."
        )

    def test_credential_store_ctypes_usage_restricted_to_approved_dpapi_apis(self):
        """
        FINDING-11: Ensures credential_store.py imports only ctypes and wintypes, and
        references NO crypt32, kernel32, ctypes, or wintypes attributes outside the
        approved DPAPI allow-list.
        """
        cred_path = os.path.join(ROOT_DIR, "credential_store.py")
        self.assertTrue(os.path.isfile(cred_path), "credential_store.py must exist in research root")

        with open(cred_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename="credential_store.py")

        ALLOWED_CRYPT32_FUNCS = {"CryptProtectData", "CryptUnprotectData"}
        ALLOWED_KERNEL32_FUNCS = {"LocalFree"}
        ALLOWED_CTYPES_ATTRS = {
            "WinDLL", "Structure", "POINTER", "byref", "cast", "memset", "get_last_error"
        }
        ALLOWED_WINTYPES_ATTRS = {
            "DWORD", "PBYTE", "BYTE", "BOOL", "LPCWSTR", "LPWSTR", "LPVOID", "HLOCAL"
        }

        unauthorized = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "ctypes" or alias.name.startswith("ctypes."):
                        if alias.name != "ctypes":
                            unauthorized.append(f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module == "ctypes" or (node.module and node.module.startswith("ctypes.")):
                    if node.module != "ctypes" or [a.name for a in node.names] != ["wintypes"]:
                        unauthorized.append(f"from {node.module} import {[a.name for a in node.names]}")
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                target = node.value.id
                if target in ("crypt32", "_crypt32"):
                    if node.attr not in ALLOWED_CRYPT32_FUNCS:
                        unauthorized.append(f"{target}.{node.attr}")
                elif target in ("kernel32", "_kernel32"):
                    if node.attr not in ALLOWED_KERNEL32_FUNCS:
                        unauthorized.append(f"{target}.{node.attr}")
                elif target == "ctypes":
                    if node.attr not in ALLOWED_CTYPES_ATTRS:
                        unauthorized.append(f"ctypes.{node.attr}")
                elif target == "wintypes":
                    if node.attr not in ALLOWED_WINTYPES_ATTRS:
                        unauthorized.append(f"wintypes.{node.attr}")

        self.assertEqual(
            unauthorized,
            [],
            f"Unauthorized ctypes/DPAPI usage detected in credential_store.py: {unauthorized}. "
            f"Allowed crypt32={sorted(ALLOWED_CRYPT32_FUNCS)}, kernel32={sorted(ALLOWED_KERNEL32_FUNCS)} per ADR-011."
        )


if __name__ == "__main__":
    unittest.main()
