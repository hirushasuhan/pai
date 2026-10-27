"""
Personal Agentic AI (PAI) - Native Launcher Builder.

Part of Milestone P2 for the v1.1.0 Packaging and Installer subsystem.
Specification: docs/PACKAGING_SPEC.md, docs/adr/ADR-013-installer-and-distribution.md
Agent brief: docs/AGENT_BRIEF_PACKAGING.md

Builds `packaging/launcher/launcher.c` into a high-performance, zero-dependency,
fail-closed native PE executable (`pai.exe`).
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger("build_launcher")

LAUNCHER_SRC = Path(__file__).resolve().parent / "launcher" / "launcher.c"


class LauncherBuildError(Exception):
    """Raised when the native launcher cannot be compiled or validated."""


class CompilerNotFoundError(LauncherBuildError):
    """Raised when no compatible C compiler is found on the host system."""


def find_c_compiler() -> Tuple[str, str, List[str]]:
    """
    Discovers an available C compiler on Windows/host.
    Returns (compiler_name, executable_path, default_flags).
    """
    # 1. Check gcc (e.g. MinGW-w64 / LLVM-MinGW)
    gcc_path = shutil.which("gcc")
    if gcc_path:
        return "gcc", gcc_path, ["-O2", "-s", "-municode", "-lbcrypt"]

    # 2. Check clang
    clang_path = shutil.which("clang")
    if clang_path:
        return "clang", clang_path, ["-O2", "-s", "-municode", "-lbcrypt"]

    # 3. Check MSVC cl.exe
    cl_path = shutil.which("cl")
    if cl_path:
        return "cl", cl_path, ["/O2", "/W3", "/DUNICODE", "/D_UNICODE", "bcrypt.lib"]

    raise CompilerNotFoundError(
        "No compatible C compiler (gcc, clang, cl) found on PATH to compile launcher. "
        "Please install LLVM-MinGW, MinGW-w64, or Visual Studio Build Tools."
    )


def verify_launcher_pe(binary_path: Path) -> None:
    """Verifies that the compiled binary is a valid Windows PE file."""
    if not binary_path.is_file():
        raise LauncherBuildError(f"Compiled launcher binary does not exist at {binary_path}")

    size = binary_path.stat().st_size
    if size < 512:
        raise LauncherBuildError(f"Launcher binary too small ({size} bytes)")

    with open(binary_path, "rb") as f:
        magic = f.read(2)
        if magic != b"MZ":
            raise LauncherBuildError(
                f"Compiled launcher magic header is '{magic.hex()}', expected 'MZ' (4d5a) for Windows PE."
            )


def build_launcher(
    out_path: Path,
    source_path: Optional[Path] = None,
    compiler: Optional[str] = None,
) -> Path:
    """
    Compiles launcher.c into a native Windows executable at out_path.
    """
    src = Path(source_path) if source_path else LAUNCHER_SRC
    if not src.is_file():
        raise LauncherBuildError(f"Launcher source file not found at {src}")

    target = Path(out_path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    if compiler:
        comp_exec = shutil.which(compiler)
        if not comp_exec:
            raise CompilerNotFoundError(f"Specified compiler '{compiler}' not found on PATH.")
        comp_type = compiler.lower()
        if "cl" in comp_type:
            flags = ["/O2", "/W3", "/DUNICODE", "/D_UNICODE", "bcrypt.lib"]
        else:
            flags = ["-O2", "-s", "-municode", "-lbcrypt"]
    else:
        comp_type, comp_exec, flags = find_c_compiler()

    logger.info("Building native launcher using %s (%s)...", comp_type, comp_exec)

    if comp_type in ("gcc", "clang"):
        cmd = [comp_exec] + flags + [str(src), "-o", str(target)]
    elif comp_type == "cl":
        cmd = [comp_exec] + flags + [str(src), f"/Fe:{target}"]
    else:
        raise LauncherBuildError(f"Unsupported compiler type: {comp_type}")

    # Ensure bit-for-bit reproducible binary timestamps (reproducible build standard)
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = "1767225600"  # 2026-01-01 00:00:00 UTC

    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise LauncherBuildError(
            f"Launcher compilation failed with exit code {proc.returncode}:\n{proc.stderr}\n{proc.stdout}"
        )

    verify_launcher_pe(target)
    logger.info("Native launcher successfully compiled to %s (%d bytes)", target, target.stat().st_size)
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description="Compile PAI native Windows launcher.")
    parser.add_argument(
        "--out",
        "-o",
        required=True,
        help="Target output executable path (e.g. dist/bin/pai.exe)",
    )
    parser.add_argument(
        "--compiler",
        "-c",
        default=None,
        help="Force specific compiler executable (gcc, clang, cl)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    out_p = Path(args.out)
    built = build_launcher(out_p, compiler=args.compiler)
    print(f"Launcher built: {built} ({built.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
