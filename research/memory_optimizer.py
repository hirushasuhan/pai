"""Pre-Inference RAM/VRAM Memory Optimizer & Mutual-Exclusion Engine Swapper for PAI.

Reduces OOM blocks and inference timeouts on 16 GB RAM + 6–8 GB VRAM systems by:
  1. Evicting idle loopback Ollama weights (`keep_alive: 0`) and stopping competing sidecars
     (`llama-server.exe` vs `sd-cli.exe`) before booting a heavy engine (>= 4.5 GB).
  2. Running Python GC and safe Win32 `EmptyWorkingSet` trimming strictly on PAI's own
     bridge/worker processes and idle Ollama child processes (never killing user apps).
  3. Providing read-only telemetry on host RAM/VRAM and top external memory consumers so the
     desktop UI can surface actionable advisories before heavy 27B or FLUX runs.
"""

from __future__ import annotations

import gc
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from research import local_sidecars, memory_probe
except ModuleNotFoundError:
    import local_sidecars
    import memory_probe


def get_host_ram_stats() -> Dict[str, float]:
    """Reads live physical and pagefile memory metrics cleanly."""
    win_stats = memory_probe.get_windows_ram_stats()
    if isinstance(win_stats, dict):
        return win_stats
    try:
        from research.hardware_telemetry import HardwareTelemetry
    except ModuleNotFoundError:
        from hardware_telemetry import HardwareTelemetry
    snap = HardwareTelemetry().get_system_snapshot()
    return {
        "total_ram_mb": float(snap.get("total_ram_mb") or 0.0),
        "avail_ram_mb": float(snap.get("avail_ram_mb") or 0.0),
        "memory_load_pct": 0.0,
        "page_avail_mb": 0.0,
    }


def trim_own_and_sidecar_working_sets() -> int:
    """Safely trims working set of current PAI process (and child Ollama if active) on Windows."""
    gc.collect()
    return memory_probe.trim_current_process_working_set()


def list_loaded_ollama_models(timeout: float = 1.2) -> List[str]:
    """Queries loopback Ollama `/api/ps` for currently VRAM/RAM-resident models."""
    try:
        req = urllib.request.Request("http://127.0.0.1:11434/api/ps", headers={"User-Agent": "PAI-MemOpt/1.0"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read(1024 * 1024).decode("utf-8", errors="replace"))
        return [str(m.get("name") or m.get("model") or "").strip() for m in data.get("models", []) if m]
    except Exception:
        return []


def evict_ollama_loaded_models(except_model: Optional[str] = None, timeout: float = 2.0) -> List[str]:
    """Evicts resident Ollama models from VRAM/RAM immediately using keep_alive=0."""
    loaded = list_loaded_ollama_models(timeout=1.0)
    evicted: List[str] = []
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    except_low = (except_model or "").strip().lower()

    for m_name in loaded:
        if except_low and m_name.lower() == except_low:
            continue
        try:
            payload = json.dumps({"model": m_name, "keep_alive": 0, "prompt": "", "stream": False}).encode("utf-8")
            req = urllib.request.Request(
                "http://127.0.0.1:11434/api/generate",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "PAI-MemOpt/1.0"},
                method="POST",
            )
            with opener.open(req, timeout=timeout):
                pass
            evicted.append(m_name)
        except Exception:
            pass
    return evicted


def get_top_external_memory_consumers(limit: int = 5) -> List[Dict[str, Any]]:
    """Read-only survey of top non-system Windows desktop apps for user advisory (no killing)."""
    if sys.platform != "win32":
        return []
    ps_cmd = (
        "Get-Process | Where-Object { $_.WorkingSet64 -gt 120MB -and $_.ProcessName -notmatch "
        "'^(Memory Compression|System|Idle|Registry|svchost|dwm|csrss|lsass|MsMpEng|pai-desktop|pythonw|python)$' } | "
        "Group-Object ProcessName | ForEach-Object { [PSCustomObject]@{ name = $_.Name; "
        "ram_mb = [math]::Round((($_.Group | Measure-Object WorkingSet64 -Sum).Sum / 1MB), 1) } } | "
        f"Sort-Object ram_mb -Descending | Select-Object -First {int(limit)} | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=3.5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
        )
        if proc.returncode == 0 and proc.stdout.strip():
            raw = json.loads(proc.stdout)
            if isinstance(raw, dict):
                return [raw]
            if isinstance(raw, list):
                return raw
    except Exception:
        pass
    return []


def prepare_memory_for_engine(
    target_engine: str,
    sidecar_mgr: Optional[local_sidecars.SidecarRuntimeManager] = None,
    target_model: str = "",
    stop_all_sidecars: bool = False,
) -> Dict[str, Any]:
    """Prepares host RAM + VRAM before launching heavy inference (`llama.cpp`, `sd.cpp`, `ollama`, `manual`)."""
    before = get_host_ram_stats()
    actions: List[str] = []
    mgr = sidecar_mgr or local_sidecars.SidecarRuntimeManager()

    # 1. Mutual-exclusion swap between llama.cpp, stable-diffusion.cpp, and Ollama
    if stop_all_sidecars or target_engine in ("sd.cpp", "stable-diffusion.cpp", "ollama", "manual"):
        if mgr.is_llama_server_running(timeout=0.4) or getattr(mgr, "_llama_proc", None) is not None:
            mgr.stop_llama_server()
            actions.append("Stopped idle llama.cpp sidecar server")

    evicted_ol = evict_ollama_loaded_models(
        except_model=target_model if target_engine == "ollama" else None
    )
    if evicted_ol:
        actions.append(f"Evicted Ollama cached model(s): {', '.join(evicted_ol)}")

    # 2. Safe working-set trim & Python garbage collection
    trimmed_n = trim_own_and_sidecar_working_sets()
    if trimmed_n:
        actions.append("Trimmed PAI runtime working-set buffers")

    # Small yield so OS releases evicted child memory cleanly
    if evicted_ol or "Stopped idle llama.cpp sidecar server" in actions:
        time.sleep(0.35)

    after = get_host_ram_stats()
    freed_mb = round(max(0.0, after["avail_ram_mb"] - before["avail_ram_mb"]), 1)
    vram_mb = local_sidecars._detect_nvidia_vram_mb()

    advisory = ""
    if after["avail_ram_mb"] < 1500.0:
        advisory = (
            f"Free system RAM is low ({after['avail_ram_mb']:.0f} MB free). "
            "Close heavy unused apps/browser tabs for maximum speed on 27B/FLUX."
        )

    return {
        "target_engine": target_engine,
        "avail_ram_before_mb": before["avail_ram_mb"],
        "avail_ram_mb": after["avail_ram_mb"],
        "total_ram_mb": after["total_ram_mb"],
        "memory_load_pct": after["memory_load_pct"],
        "vram_mb": vram_mb,
        "freed_mb": freed_mb,
        "actions": actions,
        "advisory": advisory,
    }


def get_memory_optimizer_status(
    sidecar_mgr: Optional[local_sidecars.SidecarRuntimeManager] = None,
    include_top_apps: bool = False,
) -> Dict[str, Any]:
    """Returns live RAM, VRAM, active resident engines, and optional heavy-app advisory."""
    ram = get_host_ram_stats()
    vram_mb = local_sidecars._detect_nvidia_vram_mb()
    mgr = sidecar_mgr or local_sidecars.SidecarRuntimeManager()
    llama_up = mgr.is_llama_server_running(timeout=0.35)
    ollama_loaded = list_loaded_ollama_models(timeout=0.5)
    active_engines = []
    if llama_up:
        active_engines.append("llama.cpp (Ternary Bonsai 2.5)")
    if ollama_loaded:
        active_engines.append(f"Ollama ({', '.join(ollama_loaded)})")

    res = {
        **ram,
        "vram_mb": vram_mb,
        "llama_running": llama_up,
        "ollama_loaded_models": ollama_loaded,
        "active_engines": active_engines,
        "top_external_apps": get_top_external_memory_consumers(limit=4) if include_top_apps else [],
    }
    return res
