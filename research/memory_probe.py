"""
Process memory probes used to MEASURE the purge instead of just claiming it.
  rss_bytes()  - resident set size of this process (None if unreadable)
Python-level allocations are measured separately with tracemalloc by the callers.
"""

from __future__ import annotations

import os
import sys
import ctypes
from typing import Optional


def rss_bytes() -> Optional[int]:
    try:
        if sys.platform == "win32":
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
            psapi = ctypes.WinDLL("psapi", use_last_error=True)  # type: ignore[attr-defined]
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(pmc)
            if psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
                return int(pmc.WorkingSetSize)
        elif sys.platform.startswith("linux"):
            with open("/proc/self/statm", encoding="ascii") as f:
                return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except Exception:
        pass
    try:
        import psutil
        return int(psutil.Process().memory_info().rss)
    except Exception:
        return None


def get_windows_ram_stats() -> Optional[dict]:
    """Reads live physical and pagefile RAM metrics on Windows (approved ctypes boundary)."""
    if sys.platform != "win32":
        return None
    try:
        class _MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        ms = _MEMORYSTATUSEX()
        ms.dwLength = ctypes.sizeof(ms)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):
            return {
                "total_ram_mb": round(ms.ullTotalPhys / (1024 * 1024), 1),
                "avail_ram_mb": round(ms.ullAvailPhys / (1024 * 1024), 1),
                "memory_load_pct": float(ms.dwMemoryLoad),
                "page_avail_mb": round(ms.ullAvailPageFile / (1024 * 1024), 1),
            }
    except Exception:
        pass
    return None


def trim_current_process_working_set() -> int:
    """Safely empties unused pages from current Python process working set on Windows."""
    if sys.platform != "win32":
        return 0
    try:
        k32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        h_self = k32.GetCurrentProcess()
        psapi.EmptyWorkingSet(h_self)
        return 1
    except Exception:
        return 0
