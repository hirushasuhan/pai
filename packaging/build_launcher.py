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


HARDENING_FLAGS_GCC = [
    "-O2",
    "-s",
    "-municode",
    "-Wl,--dynamicbase",
    "-Wl,--nxcompat",
    "-Wl,--high-entropy-va",
    "-lbcrypt",
]
HARDENING_FLAGS_MSVC = [
    "/O2",
    "/W3",
    "/DUNICODE",
    "/D_UNICODE",
    "/DYNAMICBASE",
    "/NXCOMPAT",
    "/HIGHENTROPYVA",
    "bcrypt.lib",
]


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
        return "gcc", gcc_path, HARDENING_FLAGS_GCC

    # 2. Check clang
    clang_path = shutil.which("clang")
    if clang_path:
        return "clang", clang_path, HARDENING_FLAGS_GCC

    # 3. Check MSVC cl.exe
    cl_path = shutil.which("cl")
    if cl_path:
        return "cl", cl_path, HARDENING_FLAGS_MSVC

    raise CompilerNotFoundError(
        "No compatible C compiler (gcc, clang, cl) found on PATH to compile launcher. "
        "Please install LLVM-MinGW, MinGW-w64, or Visual Studio Build Tools."
    )


def get_toolchain_info(compiler: Optional[str] = None) -> Dict[str, str]:
    """
    Discovers toolchain compiler and resource compiler executables and single-line versions.
    Used for recording compiler provenance in installer build logs (Finding DO).
    """
    if compiler:
        comp_exec = shutil.which(compiler)
        comp_type = compiler.lower()
    else:
        try:
            comp_type, comp_exec, _ = find_c_compiler()
        except CompilerNotFoundError:
            comp_type, comp_exec = "unknown", None

    comp_ver = "unknown"
    if comp_exec:
        try:
            cmd = [comp_exec, "--version"] if "cl" not in comp_type else [comp_exec]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            lines = (p.stdout or p.stderr).strip().splitlines()
            if lines:
                comp_ver = lines[0].strip()
        except Exception as e:
            comp_ver = f"unavailable ({e})"

    rc_exec = None
    if comp_type in ("gcc", "clang"):
        rc_exec = shutil.which("windres")
    elif comp_type == "cl":
        rc_exec = shutil.which("rc")

    rc_ver = "none"
    if rc_exec:
        try:
            cmd = [rc_exec, "--version"] if "rc" not in Path(rc_exec).stem.lower() else [rc_exec, "/?"]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            lines = (p.stdout or p.stderr).strip().splitlines()
            if lines:
                rc_ver = lines[0].strip()
        except Exception as e:
            rc_ver = f"unavailable ({e})"

    return {
        "compiler_type": comp_type,
        "compiler_exec": comp_exec or "",
        "compiler_version": comp_ver,
        "windres_exec": rc_exec or "",
        "windres_version": rc_ver,
    }


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
    icon_path: Optional[Path] = None,
) -> Path:
    """
    Compiles launcher.c into a native Windows executable at out_path.
    Optionally embeds an icon resource if an icon file and resource compiler are available.
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
            flags = HARDENING_FLAGS_MSVC
        else:
            flags = HARDENING_FLAGS_GCC
    else:
        comp_type, comp_exec, flags = find_c_compiler()

    tc_info = get_toolchain_info(compiler=comp_exec)
    logger.info("Building native launcher using %s (%s)...", comp_type, comp_exec)
    logger.info(
        "Launcher build toolchain (Finding DO): compiler: %s, windres: %s",
        tc_info["compiler_version"],
        tc_info["windres_version"],
    )

    # Resolve icon
    if icon_path is None:
        default_ico = Path(__file__).resolve().parent / "assets" / "pai.ico"
        if default_ico.is_file():
            icon_path = default_ico

    res_obj: Optional[Path] = None
    temp_dir_ctx = None
    if icon_path and Path(icon_path).is_file():
        ico_resolved = Path(icon_path).resolve()
        import tempfile
        temp_dir_ctx = tempfile.TemporaryDirectory(prefix="pai_launcher_rc_")
        tmp_rc_dir = Path(temp_dir_ctx.name)
        rc_file = tmp_rc_dir / "launcher.rc"
        rc_file.write_text(f'1 ICON "{ico_resolved.as_posix()}"\n', encoding="utf-8")

        if comp_type in ("gcc", "clang"):
            windres = shutil.which("windres")
            if windres:
                out_res = tmp_rc_dir / "launcher_res.o"
                p_rc = subprocess.run([windres, "-i", str(rc_file), "-o", str(out_res)], capture_output=True, text=True)
                if p_rc.returncode == 0 and out_res.is_file():
                    res_obj = out_res
        elif comp_type == "cl":
            rc = shutil.which("rc")
            if rc:
                out_res = tmp_rc_dir / "launcher.res"
                p_rc = subprocess.run([rc, f"/fo{out_res}", str(rc_file)], capture_output=True, text=True)
                if p_rc.returncode == 0 and out_res.is_file():
                    res_obj = out_res

    try:
        extra_objs = [str(res_obj)] if res_obj else []
        if comp_type in ("gcc", "clang"):
            cmd = [comp_exec] + flags + [str(src)] + extra_objs + ["-o", str(target)]
        elif comp_type == "cl":
            cmd = [comp_exec] + flags + [str(src)] + extra_objs + [f"/Fe:{target}"]
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
    finally:
        if temp_dir_ctx:
            try:
                temp_dir_ctx.cleanup()
            except Exception:
                pass

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
