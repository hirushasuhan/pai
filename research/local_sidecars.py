"""Managed Local C++ Sidecar Runtimes for PAI (llama.cpp + stable-diffusion.cpp).

Supports:
  1. Ternary Bonsai 2.5 (Qwen3.8-27B 1.58-bit/Q2_0/PTQ1_0 GGUF) over loopback OpenAI API
     via `llama-server.exe` (`127.0.0.1:11435`) or compatible Ollama `hf.co/...` pulls.
  2. Offline Max-Quality Image Synthesis via `stable-diffusion.cpp` (`sd-cli.exe` / `sd-server.exe`)
     supporting FLUX.1-schnell Q4/GGUF, Z-Image-Turbo, SDXL-Turbo, and SD-Turbo.

Security Invariants:
  - Loopback-only HTTP communication (`127.0.0.1` / `localhost`), validated via `net_guard`.
  - No PATH lookup for executables; pinned exclusively under `~/.pai/bin/`,
    `%LOCALAPPDATA%/Programs/PAI/bin/`, or `%LOCALAPPDATA%/Programs/{llama.cpp,stable-diffusion.cpp}/`.
  - Symlink/reparse rejection and `shell=False` execution (`CREATE_NO_WINDOW` on Windows).
  - Fail-closed offline check before any Hugging Face / GitHub release download (`net_guard`).
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from research import hardware_telemetry, ingest, net_guard
except ModuleNotFoundError:
    import hardware_telemetry
    import ingest
    import net_guard


LLAMA_SIDECAR_ENDPOINT = "http://127.0.0.1:11435"
SD_SIDECAR_DEFAULT_PORT = 7860

BONSAI_MODEL_CATALOG: List[Dict[str, Any]] = [
    {
        "name": "ternary-bonsai-2.5-27b-q2_0",
        "tag": "ternary-bonsai-2.5-27b-q2_0",
        "ollama_hf_tag": "hf.co/prism-ml/Ternary-Bonsai-2.5-27B-GGUF:Q2_0",
        "hf_repo": "prism-ml/Ternary-Bonsai-2.5-27B-GGUF",
        "filename": "Ternary-Bonsai-2.5-27B-Q2_0.gguf",
        "download_url": "https://huggingface.co/prism-ml/Ternary-Bonsai-2.5-27B-GGUF/resolve/main/Ternary-Bonsai-2.5-27B-Q2_0.gguf",
        "files": [
            {
                "role": "model",
                "filename": "Ternary-Bonsai-2.5-27B-Q2_0.gguf",
                "url": "https://huggingface.co/prism-ml/Ternary-Bonsai-2.5-27B-GGUF/resolve/main/Ternary-Bonsai-2.5-27B-Q2_0.gguf",
            }
        ],
        "size": "7.67 GB",
        "size_gb": 7.67,
        "runtime": "llama.cpp",
        "model_type": "text",
        "min_p": 0.0,
        "category": "Coding & Agentic Reasoning (Ternary 27B)",
        "desc": "PrismML Ternary Bonsai 2.5 27B (Q2_0, stock llama.cpp b11556+ compatible) — Qwen3.8 agentic coding & deep reasoning.",
    },
    {
        "name": "ternary-bonsai-2.5-27b-ptq1_0",
        "tag": "ternary-bonsai-2.5-27b-ptq1_0",
        "ollama_hf_tag": "",
        "hf_repo": "prism-ml/Ternary-Bonsai-2.5-27B-GGUF",
        "filename": "Ternary-Bonsai-2.5-27B-PTQ1_0.gguf",
        "download_url": "https://huggingface.co/prism-ml/Ternary-Bonsai-2.5-27B-GGUF/resolve/main/Ternary-Bonsai-2.5-27B-PTQ1_0.gguf",
        "files": [
            {
                "role": "model",
                "filename": "Ternary-Bonsai-2.5-27B-PTQ1_0.gguf",
                "url": "https://huggingface.co/prism-ml/Ternary-Bonsai-2.5-27B-GGUF/resolve/main/Ternary-Bonsai-2.5-27B-PTQ1_0.gguf",
            }
        ],
        "size": "5.93 GB",
        "size_gb": 5.93,
        "runtime": "llama.cpp-ternary",
        "model_type": "text",
        "min_p": 0.0,
        "category": "Coding & Agentic Reasoning (Ternary 27B)",
        "desc": "PrismML Ternary Bonsai 2.5 27B (PTQ1_0 1.76-bit) — Ultra-compact 5.93 GB ternary coding model (llama.cpp sidecar).",
    },
]

LOCAL_IMAGE_MODEL_CATALOG: List[Dict[str, Any]] = [
    {
        "name": "flux-1-schnell-q4",
        "tag": "flux-1-schnell-q4",
        "hf_repo": "leejet/FLUX.1-schnell-gguf",
        "filename": "flux1-schnell-q4_k.gguf",
        "download_url": "https://huggingface.co/leejet/FLUX.1-schnell-gguf/resolve/main/flux1-schnell-q4_k.gguf",
        "files": [
            {
                "role": "diffusion_model",
                "filename": "flux1-schnell-q4_k.gguf",
                "url": "https://huggingface.co/leejet/FLUX.1-schnell-gguf/resolve/main/flux1-schnell-q4_k.gguf",
            },
            {
                "role": "vae",
                "filename": "ae.safetensors",
                "url": "https://huggingface.co/Comfy-Org/Lumina_Image_2.0_Repackaged/resolve/main/split_files/vae/ae.safetensors",
            },
            {
                "role": "clip_l",
                "filename": "clip_l.safetensors",
                "url": "https://huggingface.co/comfyanonymous/flux_text_encoders/resolve/main/clip_l.safetensors",
            },
            {
                "role": "t5xxl",
                "filename": "t5xxl_fp8_e4m3fn.safetensors",
                "url": "https://huggingface.co/comfyanonymous/flux_text_encoders/resolve/main/t5xxl_fp8_e4m3fn.safetensors",
            },
        ],
        "size": "11.5 GB (4-file FLUX bundle)",
        "size_gb": 11.5,
        "steps": 4,
        "width": 1024,
        "height": 1024,
        "cfg_scale": 1.0,
        "runtime": "stable-diffusion.cpp",
        "model_type": "image",
        "category": "Image Synthesis (Local Max Quality)",
        "desc": "FLUX.1 Schnell (Q4_K GGUF + VAE/CLIP/T5 via stable-diffusion.cpp CUDA/Vulkan) — Max quality 4-step offline image generation.",
    },
    {
        "name": "sdxl-turbo",
        "tag": "sdxl-turbo",
        "hf_repo": "stabilityai/sdxl-turbo",
        "filename": "sd_xl_turbo_1.0_fp16.safetensors",
        "download_url": "https://huggingface.co/stabilityai/sdxl-turbo/resolve/main/sd_xl_turbo_1.0_fp16.safetensors",
        "files": [
            {
                "role": "model",
                "filename": "sd_xl_turbo_1.0_fp16.safetensors",
                "url": "https://huggingface.co/stabilityai/sdxl-turbo/resolve/main/sd_xl_turbo_1.0_fp16.safetensors",
            }
        ],
        "size": "6.5 GB",
        "size_gb": 6.5,
        "steps": 4,
        "width": 512,
        "height": 512,
        "cfg_scale": 1.0,
        "runtime": "stable-diffusion.cpp",
        "model_type": "image",
        "category": "Image Synthesis (Local Balanced)",
        "desc": "SDXL Turbo (Single-file FP16 via stable-diffusion.cpp) — Rapid high-detail local image synthesis.",
    },
    {
        "name": "sd-turbo",
        "tag": "sd-turbo",
        "hf_repo": "stabilityai/sd-turbo",
        "filename": "sd_turbo.safetensors",
        "download_url": "https://huggingface.co/stabilityai/sd-turbo/resolve/main/sd_turbo.safetensors",
        "files": [
            {
                "role": "model",
                "filename": "sd_turbo.safetensors",
                "url": "https://huggingface.co/stabilityai/sd-turbo/resolve/main/sd_turbo.safetensors",
            }
        ],
        "size": "4.9 GB",
        "size_gb": 4.9,
        "steps": 2,
        "width": 512,
        "height": 512,
        "cfg_scale": 1.0,
        "runtime": "stable-diffusion.cpp",
        "model_type": "image",
        "category": "Image Synthesis (Local Ultra-Light)",
        "desc": "SD-Turbo (Single-file checkpoint via stable-diffusion.cpp) — Ultra-lightweight local diffusion.",
    },
]

FREE_CLOUD_IMAGE_CATALOG: List[Dict[str, Any]] = [
    {
        "name": "pollinations-flux",
        "tag": "pollinations-flux",
        "size": "0 GB (Free Keyless)",
        "size_gb": 0.0,
        "runtime": "cloud_free",
        "model_type": "image",
        "category": "Image Synthesis (Free Cloud FLUX)",
        "desc": "Pollinations AI FLUX — Zero-key, no-credit-card instant cloud image synthesis (Online only).",
    },
    {
        "name": "cloudflare-flux-schnell",
        "tag": "cloudflare-flux-schnell",
        "size": "0 GB (Free Keyless)",
        "size_gb": 0.0,
        "runtime": "cloud_free",
        "model_type": "image",
        "category": "Image Synthesis (Free Cloud FLUX)",
        "desc": "FLUX.1-schnell Cloud — Works zero-key out of the box (optional Cloudflare Workers AI key supported).",
    },
    {
        "name": "hf-flux-schnell",
        "tag": "hf-flux-schnell",
        "size": "0 GB (Free Keyless)",
        "size_gb": 0.0,
        "runtime": "cloud_free",
        "model_type": "image",
        "category": "Image Synthesis (Free Cloud FLUX)",
        "desc": "FLUX.1-schnell Serverless — Works zero-key out of the box (optional free Hugging Face token supported).",
    },
]


def _get_pai_home() -> Path:
    cfg = os.environ.get("PAI_CONFIG_DIR")
    base = Path(cfg) if cfg else (Path.home() / ".pai")
    base.mkdir(parents=True, exist_ok=True)
    return base


def resolve_storage_root(custom_path: Optional[str | Path] = None) -> Path:
    """Resolves active model storage root honoring UI custom destination path."""
    if custom_path:
        p = Path(str(custom_path)).expanduser()
        p.mkdir(parents=True, exist_ok=True)
        return p
    if not os.environ.get("PAI_CONFIG_DIR"):
        cfg_file = Path.home() / ".pai" / "desktop_config.json"
        if cfg_file.is_file():
            try:
                data = json.loads(cfg_file.read_text(encoding="utf-8"))
                mp = str(data.get("models_path") or "").strip()
                if mp and Path(mp).is_dir():
                    return Path(mp)
            except Exception:
                pass
    d = _get_pai_home() / "models"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_gguf_models_dir(storage_root: Optional[str | Path] = None) -> Path:
    root = resolve_storage_root(storage_root)
    d = root / ("pai_gguf" if root != (_get_pai_home() / "models") else "gguf")
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_image_models_dir(storage_root: Optional[str | Path] = None) -> Path:
    root = resolve_storage_root(storage_root)
    d = root / ("pai_image" if root != (_get_pai_home() / "models") else "image")
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_model_spec(model_tag: str) -> Optional[Dict[str, Any]]:
    low = (model_tag or "").strip().lower()
    for item in BONSAI_MODEL_CATALOG + LOCAL_IMAGE_MODEL_CATALOG + FREE_CLOUD_IMAGE_CATALOG:
        if item["tag"].lower() == low or item["name"].lower() == low:
            return dict(item)
    return None


def detect_gpu_backend() -> Dict[str, Any]:
    """Detects best GPU acceleration backend (cuda -> vulkan -> cpu)."""
    vram_mb = _detect_nvidia_vram_mb()
    if vram_mb and vram_mb > 0:
        return {"backend": "cuda", "vram_mb": vram_mb, "label": f"NVIDIA CUDA ({vram_mb} MB VRAM)"}
    if sys.platform == "win32":
        win_sys = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        if (win_sys / "vulkan-1.dll").is_file():
            return {"backend": "vulkan", "vram_mb": None, "label": "Vulkan GPU"}
    return {"backend": "cpu", "vram_mb": None, "label": "CPU (AVX2)"}


def get_disk_free_gb(target_path: Optional[str | Path] = None) -> float:
    try:
        p = Path(str(target_path)) if target_path else resolve_storage_root()
        p = p.expanduser().resolve()
        while not p.exists() and p != p.parent:
            p = p.parent
        _, _, free = shutil.disk_usage(str(p))
        return round(free / (1024 ** 3), 2)
    except Exception:
        return 0.0


def assess_install_and_run_readiness(
    model_tag: str,
    target_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Gate 1 & Gate 3 combined pre-flight resource check (Disk, GPU backend, VRAM/RAM)."""
    spec = get_model_spec(model_tag)
    size_gb = float(spec.get("size_gb", 0.0)) if spec else 4.0
    runtime = str(spec.get("runtime", "ollama")) if spec else "ollama"
    free_gb = get_disk_free_gb(target_path)
    gpu_info = detect_gpu_backend()

    if runtime == "cloud_free":
        return {
            "model": model_tag,
            "runtime": runtime,
            "install_ready": True,
            "run_ready": True,
            "disk_ok": True,
            "disk_free_gb": free_gb,
            "required_disk_gb": 0.0,
            "gpu_backend": gpu_info["backend"],
            "fit_mode": "CLOUD_FREE",
            "advisory": "Zero disk footprint (runs online via free cloud API).",
        }

    need_runtime_gb = 0.0
    if runtime in ("llama.cpp", "llama.cpp-ternary") and find_llama_server_binary() is None:
        need_runtime_gb = 0.25
    elif runtime == "stable-diffusion.cpp" and find_sd_cpp_binary() is None:
        need_runtime_gb = 0.25

    required_disk_gb = round(size_gb + need_runtime_gb + 1.5, 2)
    disk_ok = free_gb >= required_disk_gb
    hw_fit = assess_model_hardware_fit(model_tag, size_gb)
    ram_ok = (hw_fit.fit_mode != "LOW_HEADROOM_WARN") or (hw_fit.avail_ram_mb >= 2048.0)

    advisories: List[str] = [hw_fit.advisory]
    if not disk_ok:
        advisories.insert(0, f"Insufficient disk space: need ~{required_disk_gb:.1f} GB (incl. buffer), only {free_gb:.1f} GB free.")
    elif need_runtime_gb > 0:
        advisories.append(f"Auto-installs {runtime} ({gpu_info['label']}) sidecar automatically.")

    return {
        "model": model_tag,
        "runtime": runtime,
        "size_gb": size_gb,
        "install_ready": bool(disk_ok),
        "run_ready": bool(disk_ok and ram_ok),
        "disk_ok": bool(disk_ok),
        "disk_free_gb": free_gb,
        "required_disk_gb": required_disk_gb,
        "gpu_backend": gpu_info["backend"],
        "gpu_label": gpu_info["label"],
        "fit_mode": hw_fit.fit_mode,
        "avail_ram_mb": hw_fit.avail_ram_mb,
        "vram_mb": hw_fit.vram_mb,
        "recommended_gpu_layers": hw_fit.recommended_gpu_layers,
        "advisory": " | ".join(advisories),
    }


def _estimate_model_layers(model_name: str) -> int:
    """Returns realistic transformer block count so GPU layer offload percentage stays accurate."""
    low = (model_name or "").lower()
    if "70b" in low or "72b" in low:
        return 80
    if "27b" in low or "32b" in low:
        return 64
    if "14b" in low or "13b" in low:
        return 48
    if "7b" in low or "8b" in low or "9b" in low:
        return 32
    return 36


def _estimate_model_size_gb(model_name: str, explicit_size_gb: float = 0.0, streaming_image: bool = False) -> float:
    """Infers model parameter memory footprint cleanly (accounting for sequential streaming in sd.cpp)."""
    if streaming_image and "flux" in (model_name or "").lower():
        return 5.5
    if explicit_size_gb and explicit_size_gb > 0.0:
        return float(explicit_size_gb)
    spec = get_model_spec(model_name)
    if spec and float(spec.get("size_gb") or 0.0) > 0.0:
        return float(spec["size_gb"])
    low = (model_name or "").lower()
    m = re.search(r"(?:^|[:\-_])(\d+(?:\.\d+)?)b(?:\b|[:\-_])", low)
    if m:
        params_b = float(m.group(1))
        if params_b >= 65:
            return 40.0
        if params_b >= 25:
            return 18.0
        if params_b >= 12:
            return 8.5
        if params_b >= 6:
            return 4.7
        if params_b >= 2:
            return 2.3
        return 1.2
    return 4.0


def check_runtime_admission(
    model_name: str,
    size_gb: float = 0.0,
    streaming_image: bool = False,
) -> Dict[str, Any]:
    """Gate 3: Live pre-load RAM/VRAM admission check right before launching heavy inference."""
    est_gb = _estimate_model_size_gb(model_name, size_gb, streaming_image=streaming_image)
    hw_fit = assess_model_hardware_fit(model_name, est_gb)
    snap = hardware_telemetry.HardwareTelemetry().get_system_snapshot()
    avail_ram = float(snap.get("avail_ram_mb") or hw_fit.avail_ram_mb)
    tier = snap["budget"].compute_tier

    if avail_ram >= 9500.0:
        safe_ctx = 16384
    elif avail_ram >= 5500.0:
        safe_ctx = 8192
    elif avail_ram >= 2500.0:
        safe_ctx = 4096
    else:
        safe_ctx = 3072

    combined_mb = avail_ram + float(hw_fit.vram_mb or 0)
    # Require >= 1024 MB free OS RAM always, and for heavy models (>= 5GB) either >= 1.5 GB free RAM or >= 80% combined headroom
    allowed = True
    reason = hw_fit.advisory
    if avail_ram < 1024.0 or (est_gb >= 5.0 and avail_ram < 1500.0 and combined_mb < (est_gb * 1024.0 * 0.8)):
        allowed = False
        reason = (
            f"Admission blocked to prevent OOM freeze: '{model_name}' (~{est_gb:.1f} GB effective peak) needs more free memory "
            f"(only {avail_ram:.0f} MB free RAM, {hw_fit.vram_mb or 0} MB VRAM)."
        )

    return {
        "allowed": allowed,
        "tier": tier,
        "fit_mode": hw_fit.fit_mode,
        "recommended_gpu_layers": hw_fit.recommended_gpu_layers,
        "recommended_ctx_size": safe_ctx,
        "avail_ram_mb": round(avail_ram, 1),
        "vram_mb": hw_fit.vram_mb,
        "reason": reason,
    }


def _validate_loopback_url(url: str) -> str:
    parsed = urllib.parse.urlsplit((url or "").strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https") or host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
        raise ValueError(f"Sidecar URL must be loopback http(s), got: {url!r}")
    return url.rstrip("/")


def _has_missing_cuda_runtime_dlls(bin_dir: Path) -> bool:
    """Checks whether a Windows CUDA sidecar folder is missing required cudart/cublas DLLs."""
    if sys.platform != "win32":
        return False
    if not (bin_dir / "ggml-cuda.dll").is_file():
        return False
    local_ok = any((bin_dir / dll).is_file() for dll in ("cudart64_12.dll", "cudart64_13.dll")) and any(
        (bin_dir / dll).is_file() for dll in ("cublas64_12.dll", "cublas64_13.dll")
    )
    if local_ok:
        return False
    cuda_root = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "NVIDIA GPU Computing Toolkit"
    if cuda_root.is_dir():
        if any(cuda_root.glob("CUDA/v12.*/bin/cudart64_12.dll")) or any(cuda_root.glob("CUDA/v13.*/bin/cudart64_13.dll")):
            return False
    return True


def _find_pinned_binary(names: Tuple[str, ...], runtime_subdir: str, check_cuda_dlls: bool = True) -> Optional[Path]:
    """Resolves binary exclusively from pinned user/app directories (never PATH)."""
    roots: List[Path] = [_get_pai_home() / "bin" / runtime_subdir, _get_pai_home() / "bin"]
    local_app = os.environ.get("LOCALAPPDATA", "").strip()
    if local_app:
        roots.extend([
            Path(local_app) / "Programs" / "PAI" / "bin" / runtime_subdir,
            Path(local_app) / "Programs" / "PAI" / "bin",
            Path(local_app) / "Programs" / runtime_subdir,
        ])
    for root in roots:
        if not root.is_dir() or ingest._is_symlink_or_reparse(str(root)):
            continue
        if check_cuda_dlls and _has_missing_cuda_runtime_dlls(root):
            continue
        for exe_name in names:
            cand = root / exe_name
            try:
                if cand.is_file() and not ingest._is_symlink_or_reparse(str(cand)):
                    return cand
            except Exception:
                continue
    return None


def find_llama_server_binary(ternary_fork: bool = False) -> Optional[Path]:
    names = ("llama-server.exe", "server.exe") if sys.platform == "win32" else ("llama-server", "server")
    if ternary_fork:
        hit = _find_pinned_binary(names, "llama.cpp-ternary")
        if hit is not None:
            return hit
        return None
    return _find_pinned_binary(names, "llama.cpp") or _find_pinned_binary(names, "llama.cpp-ternary")


def find_sd_cpp_binary() -> Optional[Path]:
    names = ("sd-cli.exe", "sd.exe", "sd-server.exe") if sys.platform == "win32" else ("sd-cli", "sd", "sd-server")
    return _find_pinned_binary(names, "stable-diffusion.cpp")


def _detect_nvidia_vram_mb() -> Optional[int]:
    """Queries nvidia-smi cleanly with short timeout (never shell=True)."""
    if sys.platform != "win32":
        return None
    smi_candidates = [
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "nvidia-smi.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "NVIDIA Corporation" / "NVSMI" / "nvidia-smi.exe",
    ]
    smi = next((p for p in smi_candidates if p.is_file()), None)
    if smi is None:
        return None
    try:
        proc = subprocess.run(
            [str(smi), "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=2.0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode == 0 and proc.stdout.strip():
            vals = [int(x.strip()) for x in proc.stdout.strip().splitlines() if x.strip().isdigit()]
            if vals:
                return max(vals)
    except Exception:
        pass
    return None


@dataclass
class HardwareFitAssessment:
    model_name: str
    size_gb: float
    avail_ram_mb: float
    vram_mb: Optional[int]
    fit_mode: str  # GPU_FULL | HYBRID_GPU_RAM_OFFLOAD | CPU_RAM_ONLY | LOW_HEADROOM_WARN
    recommended_gpu_layers: int
    advisory: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def assess_model_hardware_fit(model_name: str, size_gb: float) -> HardwareFitAssessment:
    """Computes VRAM + RAM fit & accurate layer offload using real model block count."""
    snap = hardware_telemetry.HardwareTelemetry().get_system_snapshot()
    avail_ram_mb = float(snap.get("avail_ram_mb") or 0.0)
    vram_mb = _detect_nvidia_vram_mb()
    needed_mb = float(size_gb) * 1024.0 + 768.0
    total_layers = _estimate_model_layers(model_name)

    def _calc_offload_layers(vram: int) -> int:
        # Reserve ~1050 MB VRAM for KV cache + Windows DWM so WDDM never spills GPU tensors to slow shared RAM
        usable_mb = max(512.0, float(vram) - 1050.0)
        ratio = max(0.20, min(0.95, usable_mb / max(1.0, float(size_gb) * 1024.0)))
        return min(total_layers, max(8, int(round(total_layers * ratio))))

    if vram_mb and vram_mb >= needed_mb:
        return HardwareFitAssessment(
            model_name=model_name,
            size_gb=size_gb,
            avail_ram_mb=round(avail_ram_mb, 1),
            vram_mb=vram_mb,
            fit_mode="GPU_FULL",
            recommended_gpu_layers=99,
            advisory=f"Fits inside GPU VRAM ({vram_mb} MB available).",
        )
    if vram_mb and (vram_mb + avail_ram_mb) >= needed_mb:
        layers = _calc_offload_layers(vram_mb)
        return HardwareFitAssessment(
            model_name=model_name,
            size_gb=size_gb,
            avail_ram_mb=round(avail_ram_mb, 1),
            vram_mb=vram_mb,
            fit_mode="HYBRID_GPU_RAM_OFFLOAD",
            recommended_gpu_layers=layers,
            advisory=(
                f"GPU VRAM ({vram_mb} MB) < {size_gb:.1f} GB weight; hybrid GPU+RAM offload "
                f"(~{layers}/{total_layers} layers on CUDA + remainder in system RAM)."
            ),
        )
    if avail_ram_mb >= needed_mb:
        return HardwareFitAssessment(
            model_name=model_name,
            size_gb=size_gb,
            avail_ram_mb=round(avail_ram_mb, 1),
            vram_mb=vram_mb,
            fit_mode="CPU_RAM_ONLY",
            recommended_gpu_layers=0,
            advisory=f"Runs in system RAM ({avail_ram_mb:.0f} MB free, CPU inference).",
        )
    offload_layers = _calc_offload_layers(vram_mb) if (vram_mb and vram_mb >= 2048) else 0
    return HardwareFitAssessment(
        model_name=model_name,
        size_gb=size_gb,
        avail_ram_mb=round(avail_ram_mb, 1),
        vram_mb=vram_mb,
        fit_mode="LOW_HEADROOM_WARN",
        recommended_gpu_layers=offload_layers,
        advisory=(
            f"Low headroom warning: {size_gb:.2f} GB model may exceed free RAM/VRAM "
            f"(RAM free={avail_ram_mb:.0f} MB, VRAM={vram_mb or 0} MB; offloading ~{offload_layers}/{total_layers} GPU layers)."
        ),
    )


class SidecarRuntimeManager:
    """Manages local llama.cpp (Ternary Bonsai 2.5) and stable-diffusion.cpp processes & models."""

    def __init__(
        self,
        llama_endpoint: str = LLAMA_SIDECAR_ENDPOINT,
        storage_root: Optional[str | Path] = None,
    ) -> None:
        self.llama_endpoint = _validate_loopback_url(llama_endpoint)
        self.storage_root = Path(str(storage_root)) if storage_root else None
        self._llama_proc: Optional[subprocess.Popen] = None
        self._last_llama_used_ts: float = 0.0
        self._idle_reaper_started: bool = False

    def _start_idle_reaper(self, idle_timeout_sec: float = 300.0) -> None:
        if self._idle_reaper_started:
            return
        self._idle_reaper_started = True

        def _reap_loop() -> None:
            while True:
                time.sleep(30.0)
                try:
                    if (
                        self._llama_proc is not None
                        and self._llama_proc.poll() is None
                        and self._last_llama_used_ts > 0.0
                        and (time.time() - self._last_llama_used_ts) > idle_timeout_sec
                    ):
                        self.stop_llama_server()
                except Exception:
                    pass

        threading.Thread(target=_reap_loop, name="pai_llama_idle_reaper", daemon=True).start()

    def is_llama_server_running(self, timeout: float = 0.8) -> bool:
        try:
            url = _validate_loopback_url(self.llama_endpoint) + "/health"
            req = urllib.request.Request(url, headers={"User-Agent": "PAI-Sidecar/1.0"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=timeout) as resp:
                return resp.status == 200
        except Exception:
            return False

    def stop_llama_server(self) -> None:
        if self._llama_proc is not None and self._llama_proc.poll() is None:
            try:
                self._llama_proc.terminate()
                self._llama_proc.wait(timeout=3)
            except Exception:
                try:
                    self._llama_proc.kill()
                except Exception:
                    pass
        self._llama_proc = None

    def _gguf_search_dirs(self) -> List[Path]:
        dirs = [get_gguf_models_dir(self.storage_root)]
        fallback = _get_pai_home() / "models" / "gguf"
        if fallback not in dirs and fallback.is_dir():
            dirs.append(fallback)
        return dirs

    def _image_search_dirs(self) -> List[Path]:
        dirs = [get_image_models_dir(self.storage_root)]
        fallback = _get_pai_home() / "models" / "image"
        if fallback not in dirs and fallback.is_dir():
            dirs.append(fallback)
        return dirs

    def list_installed_gguf_models(self) -> List[Dict[str, Any]]:
        """Scans configured model storage & fallback ~/.pai/models/gguf for GGUF weights."""
        out: List[Dict[str, Any]] = []
        seen: set[str] = set()
        meta_by_file = {m["filename"].lower(): m for m in BONSAI_MODEL_CATALOG}
        for gdir in self._gguf_search_dirs():
            if not gdir.is_dir():
                continue
            for f in sorted(gdir.glob("*.gguf")):
                if ingest._is_symlink_or_reparse(str(f)):
                    continue
                meta = meta_by_file.get(f.name.lower())
                name = meta["name"] if meta else f.stem.lower()
                if name in seen:
                    continue
                seen.add(name)
                size_gb = round(f.stat().st_size / (1024 ** 3), 2)
                out.append({
                    "name": name,
                    "path": str(f),
                    "size_gb": size_gb,
                    "runtime": meta.get("runtime", "llama.cpp") if meta else "llama.cpp",
                    "model_type": "text",
                    "category": "Coding & Agentic Reasoning (Ternary 27B)",
                })
        return out

    def list_installed_local_image_models(self) -> List[Dict[str, Any]]:
        """Scans configured storage & ~/.pai/models/image for diffusion checkpoints."""
        out: List[Dict[str, Any]] = []
        seen: set[str] = set()
        meta_by_file = {m["filename"].lower(): m for m in LOCAL_IMAGE_MODEL_CATALOG}
        aux_files = {"ae.safetensors", "clip_l.safetensors", "t5xxl_fp8_e4m3fn.safetensors", "t5xxl_fp16.safetensors"}
        for idir in self._image_search_dirs():
            if not idir.is_dir():
                continue
            for f in sorted(idir.iterdir()):
                if not f.is_file() or ingest._is_symlink_or_reparse(str(f)):
                    continue
                if f.name.lower() in aux_files or f.suffix.lower() not in (".gguf", ".safetensors", ".ckpt"):
                    continue
                meta = meta_by_file.get(f.name.lower())
                name = meta["name"] if meta else f.stem.lower()
                if name in seen:
                    continue
                seen.add(name)
                size_gb = round(f.stat().st_size / (1024 ** 3), 2)
                out.append({
                    "name": name,
                    "tag": name,
                    "path": str(f),
                    "size_gb": meta.get("size_gb", size_gb) if meta else size_gb,
                    "runtime": "stable-diffusion.cpp",
                    "model_type": "image",
                    "category": meta.get("category", "Image Synthesis (Local)") if meta else "Image Synthesis (Local)",
                })
        return out

    def ensure_llama_server(self, model_path: Optional[Path] = None, timeout: float = 45.0) -> Tuple[bool, str]:
        """Ensures local llama-server is running on loopback after Gate 3 admission check."""
        if self.is_llama_server_running(timeout=0.8):
            return True, "llama.cpp sidecar already running on 127.0.0.1:11435."

        parsed = urllib.parse.urlsplit(self.llama_endpoint)
        port = str(parsed.port or 11435)

        # If a previously spawned server is still warming up, wait for it instead of double-spawning
        if self._llama_proc is not None and self._llama_proc.poll() is None:
            deadline = time.time() + max(5.0, timeout)
            while time.time() < deadline:
                if self.is_llama_server_running(timeout=0.6):
                    return True, f"Started llama-server on 127.0.0.1:{port}."
                if self._llama_proc.poll() is not None:
                    break
                time.sleep(0.5)

        target_gguf = model_path
        if target_gguf is None:
            installed = self.list_installed_gguf_models()
            if not installed:
                return False, "No GGUF model installed."
            target_gguf = Path(installed[0]["path"])

        is_ternary = "ptq1" in target_gguf.name.lower()
        bin_path = find_llama_server_binary(ternary_fork=is_ternary)
        if bin_path is None:
            return False, (
                f"llama-server executable not found for {'PrismML ternary' if is_ternary else 'llama.cpp'}. "
                "Click Install Model on ternary-bonsai-2.5-27b-q2_0 (or ptq1_0) to auto-provision."
            )

        if not target_gguf.is_file() or ingest._is_symlink_or_reparse(str(target_gguf)):
            return False, "Invalid or symlinked GGUF model path rejected."

        size_gb = max(1.0, target_gguf.stat().st_size / (1024 ** 3))
        # Pre-inference memory reclaim: evict idle Ollama models & trim buffers before checking admission
        try:
            try:
                from research import memory_optimizer
            except ModuleNotFoundError:
                import memory_optimizer
            memory_optimizer.prepare_memory_for_engine("llama.cpp", sidecar_mgr=self)
        except Exception:
            pass

        adm = check_runtime_admission(target_gguf.name, size_gb)
        if not adm["allowed"]:
            return False, adm["reason"]

        phys_threads = max(2, min(8, (os.cpu_count() or 4) // 2))
        cmd = [
            str(bin_path),
            "-m", str(target_gguf),
            "--host", "127.0.0.1",
            "--port", port,
            "--ctx-size", str(adm["recommended_ctx_size"]),
            "--min-p", "0.0",
            "-ngl", str(adm["recommended_gpu_layers"]),
            "--flash-attn", "on",
            "--cache-type-k", "q8_0",
            "--cache-type-v", "q8_0",
            "--threads", str(phys_threads),
            "--reasoning-budget", "512",
        ]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        try:
            self._llama_proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=flags,
            )
            self._last_llama_used_ts = time.time()
            self._start_idle_reaper()
        except Exception as exc:
            return False, f"Failed to launch llama-server: {exc}"

        deadline = time.time() + max(5.0, timeout)
        while time.time() < deadline:
            if self.is_llama_server_running(timeout=0.6):
                self._last_llama_used_ts = time.time()
                return True, f"Started llama-server on 127.0.0.1:{port} ({adm['fit_mode']}, ngl={adm['recommended_gpu_layers']}, ctx={adm['recommended_ctx_size']})."
            if self._llama_proc.poll() is not None:
                return False, "llama-server exited during startup (check model compatibility / RAM)."
            time.sleep(0.5)
        return False, "Timed out waiting for llama-server loopback readiness."

    @staticmethod
    def _clamp_prompt_for_ctx(prompt: str, max_chars: int = 9200) -> str:
        text = (prompt or "").strip()
        if len(text) <= max_chars:
            return text
        head = max_chars // 3
        tail = max_chars - head - 32
        return text[:head] + "\n...[context truncated for KV fit]...\n" + text[-tail:]

    def query_llama_cpp(
        self,
        prompt: str,
        model_name: str = "ternary-bonsai-2.5-27b-q2_0",
        temperature: float = 0.3,
        max_tokens: int = 2400,
        min_p: float = 0.0,
        timeout: float = 45.0,
    ) -> Tuple[bool, str]:
        """Queries loopback llama.cpp via SSE streaming with per-token stall tolerance & 503/500 resilience."""
        endpoint = _validate_loopback_url(self.llama_endpoint) + "/v1/chat/completions"
        if not self.is_llama_server_running(timeout=0.8):
            installed = self.list_installed_gguf_models()
            matched = next((m for m in installed if m["name"] == model_name.lower()), installed[0] if installed else None)
            if not matched:
                return False, f"Model '{model_name}' not installed in ~/.pai/models/gguf/."
            ok_up, msg_up = self.ensure_llama_server(model_path=Path(matched["path"]), timeout=50.0)
            if not ok_up:
                return False, msg_up

        self._last_llama_used_ts = time.time()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        safe_max_tokens = max(256, min(int(max_tokens), 4096))
        cur_prompt = self._clamp_prompt_for_ctx(prompt, max_chars=9200)
        trimmed_on_err = False
        per_token_timeout = max(20.0, min(float(timeout), 60.0))

        for attempt in range(4):
            payload = {
                "model": model_name,
                "messages": [{"role": "user", "content": cur_prompt}],
                "temperature": float(temperature),
                "max_tokens": safe_max_tokens,
                "stream": True,
            }
            if min_p and float(min_p) > 0.0:
                payload["min_p"] = float(min_p)
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "PAI-Sidecar/1.0"},
                method="POST",
            )
            pieces: List[str] = []
            reasoning_pieces: List[str] = []
            try:
                with opener.open(req, timeout=per_token_timeout) as resp:
                    hdrs = getattr(resp, "headers", None) or {}
                    ctype = str(hdrs.get("Content-Type") or "").lower()
                    if ("event-stream" in ctype or not ctype) and hasattr(resp, "readline"):
                        while True:
                            raw_line = resp.readline()
                            if not raw_line:
                                break
                            line = raw_line.decode("utf-8", errors="replace").strip()
                            if not line:
                                continue
                            if line.startswith("{"):
                                obj = json.loads(line)
                                msg_obj = obj.get("choices", [{}])[0].get("message", {})
                                full_c = msg_obj.get("content") or ""
                                full_r = msg_obj.get("reasoning_content") or ""
                                if full_c:
                                    pieces.append(full_c)
                                if full_r:
                                    reasoning_pieces.append(full_r)
                                break
                            if not line.startswith("data:"):
                                continue
                            data_str = line[5:].strip()
                            if data_str == "[DONE]":
                                break
                            try:
                                ev = json.loads(data_str)
                                ch0 = ev.get("choices", [{}])[0]
                                delta = ch0.get("delta", {})
                                tok = delta.get("content") or ""
                                rtok = delta.get("reasoning_content") or ""
                                if tok:
                                    pieces.append(tok)
                                if rtok:
                                    reasoning_pieces.append(rtok)
                                msg_full = ch0.get("message", {}).get("content") or ""
                                if msg_full and not pieces:
                                    pieces.append(msg_full)
                            except Exception:
                                pass
                    else:
                        raw_txt = resp.read(8 * 1024 * 1024).decode("utf-8", errors="replace").strip()
                        if raw_txt.startswith("data:"):
                            for line in raw_txt.splitlines():
                                line = line.strip()
                                if not line.startswith("data:"):
                                    continue
                                data_str = line[5:].strip()
                                if data_str == "[DONE]":
                                    break
                                try:
                                    ev = json.loads(data_str)
                                    delta = ev.get("choices", [{}])[0].get("delta", {})
                                    tok = delta.get("content") or ""
                                    rtok = delta.get("reasoning_content") or ""
                                    if tok:
                                        pieces.append(tok)
                                    if rtok:
                                        reasoning_pieces.append(rtok)
                                except Exception:
                                    pass
                        elif raw_txt:
                            obj = json.loads(raw_txt)
                            msg_obj = obj.get("choices", [{}])[0].get("message", {})
                            full_c = msg_obj.get("content") or ""
                            full_r = msg_obj.get("reasoning_content") or ""
                            if full_c:
                                pieces.append(full_c)
                            if full_r:
                                reasoning_pieces.append(full_r)

                self._last_llama_used_ts = time.time()
                content = "".join(pieces).strip()
                if content:
                    return True, content
                reasoning_txt = "".join(reasoning_pieces).strip()
                if reasoning_txt:
                    return True, reasoning_txt
                return False, "Empty response from llama-server."
            except urllib.error.HTTPError as exc:
                err_body = ""
                try:
                    err_body = exc.read(1024).decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
                if exc.code == 503 and attempt < 3:
                    time.sleep(2.5)
                    continue
                if exc.code in (400, 500) and not trimmed_on_err:
                    trimmed_on_err = True
                    cur_prompt = self._clamp_prompt_for_ctx(prompt, max_chars=4800)
                    safe_max_tokens = min(safe_max_tokens, 768)
                    continue
                detail = f" ({err_body[:180]})" if err_body else ""
                return False, f"llama.cpp sidecar query error: HTTP {exc.code}{detail}"
            except Exception as exc:
                partial = "".join(pieces).strip() or "".join(reasoning_pieces).strip()
                if len(partial) >= 60:
                    return True, partial + "\n\n*(Stream ended early after generating partial response)*"
                return False, f"llama.cpp sidecar query error: {exc}"
        return False, "llama.cpp sidecar did not return a valid completion."

    def generate_image_local_sdcpp(
        self,
        prompt: str,
        model_tag: str = "flux-1-schnell-q4",
        timeout: float = 300.0,
    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
        """Runs low-VRAM sequential offline image synthesis via stable-diffusion.cpp `sd-cli`."""
        clean_prompt = re.sub(r"[\x00-\x1f\x7f]", " ", (prompt or "").strip())
        if not clean_prompt:
            return False, "Prompt cannot be empty.", None, None

        bin_path = find_sd_cpp_binary()
        if bin_path is None:
            return False, (
                "stable-diffusion.cpp binary (sd-cli.exe) not found under ~/.pai/bin/stable-diffusion.cpp/. "
                "Place a stable-diffusion.cpp release binary there or enable Internet for Free Cloud FLUX."
            ), None, None

        installed = self.list_installed_local_image_models()
        chosen = next((m for m in installed if m["name"] == model_tag.lower()), installed[0] if installed else None)
        if not chosen:
            return False, "No local image model found in ~/.pai/models/image/.", None, None

        meta = next((m for m in LOCAL_IMAGE_MODEL_CATALOG if m["name"] == chosen["name"]), {})
        steps = int(meta.get("steps", 4))
        width = int(meta.get("width", 1024 if "flux" in chosen["name"] or "z-image" in chosen["name"] else 512))
        height = int(meta.get("height", width))

        images_dir = _get_pai_home() / "generated_images"
        images_dir.mkdir(parents=True, exist_ok=True)
        fname = f"pai_sdcpp_{int(time.time())}.png"
        out_path = images_dir / fname

        model_file = Path(chosen["path"])
        if not model_file.is_file() or ingest._is_symlink_or_reparse(str(model_file)):
            return False, "Rejected invalid or symlinked local image model path.", None, None

        cfg_scale = str(meta.get("cfg_scale", 1.0))
        is_flux = "flux" in chosen["name"]
        vae_f = clip_f = t5_f = None
        if is_flux:
            parent_dir = model_file.parent
            vae_f = parent_dir / "ae.safetensors"
            clip_f = parent_dir / "clip_l.safetensors"
            t5_f = next((parent_dir / n for n in ("t5xxl_fp8_e4m3fn.safetensors", "t5xxl-Q4_K.gguf", "t5xxl_fp16.safetensors") if (parent_dir / n).is_file()), None)
            missing_parts = []
            if not vae_f.is_file() or ingest._is_symlink_or_reparse(str(vae_f)):
                missing_parts.append("ae.safetensors")
            if not clip_f.is_file() or ingest._is_symlink_or_reparse(str(clip_f)):
                missing_parts.append("clip_l.safetensors")
            if t5_f is None or ingest._is_symlink_or_reparse(str(t5_f)):
                missing_parts.append("t5xxl_fp8_e4m3fn.safetensors")
            if missing_parts:
                return False, f"Missing required FLUX companion weights ({', '.join(missing_parts)}) in {parent_dir}. Click Install Model on FLUX to complete download.", None, None

        # Pre-inference reclaim: stop resident llama.cpp/Ollama engines so 100% VRAM + freed RAM go to sd-cli
        try:
            try:
                from research import memory_optimizer
            except ModuleNotFoundError:
                import memory_optimizer
            memory_optimizer.prepare_memory_for_engine("sd.cpp", sidecar_mgr=self)
        except Exception:
            pass

        adm = check_runtime_admission(chosen["name"], float(chosen.get("size_gb") or 4.0), streaming_image=True)
        if not adm["allowed"]:
            return False, adm["reason"], None, None

        phys_threads = max(2, min(8, (os.cpu_count() or 4) // 2))
        low_vram_flags = ["--offload-to-cpu", "--diffusion-fa", "--vae-tiling", "--threads", str(phys_threads)]
        if (adm.get("vram_mb") or 0) <= 8192:
            low_vram_flags.append("--clip-on-cpu")

        if is_flux:
            cmd = [
                str(bin_path),
                "--diffusion-model", str(model_file),
                "--vae", str(vae_f),
                "--clip_l", str(clip_f),
                "--t5xxl", str(t5_f),
                "-p", clean_prompt,
                "-o", str(out_path),
                "--steps", str(steps),
                "--cfg-scale", cfg_scale,
                "--sampling-method", "euler",
                "-W", str(width),
                "-H", str(height),
                *low_vram_flags,
            ]
        else:
            cmd = [
                str(bin_path),
                "-m", str(model_file),
                "-p", clean_prompt,
                "-o", str(out_path),
                "--steps", str(steps),
                "--cfg-scale", cfg_scale,
                "-W", str(width),
                "-H", str(height),
                *low_vram_flags,
            ]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=flags,
            )
            if proc.returncode != 0 or not out_path.is_file():
                raw_log = (proc.stderr or "") + "\n" + (proc.stdout or "")
                return False, _format_sdcpp_friendly_error(raw_log, chosen["name"]), None, None
            img_bytes = out_path.read_bytes()
            if not (img_bytes.startswith(b"\x89PNG\r\n\x1a\n") or img_bytes.startswith(b"\xff\xd8\xff")):
                out_path.unlink(missing_ok=True)
                return False, "Generated output failed PNG/JPEG header validation.", None, None
            b64 = base64.b64encode(img_bytes).decode("ascii")
            mime = "image/png" if img_bytes.startswith(b"\x89PNG") else "image/jpeg"
            return True, f"data:{mime};base64,{b64}", str(out_path), fname
        except Exception as exc:
            return False, f"Local image generation error: {re.sub(r'[A-Za-z]:\\\\Users\\\\[^\\\\\\s]+', '<user>', str(exc))}", None, None


def _format_sdcpp_friendly_error(raw_log: str, model_tag: str = "") -> str:
    """Extracts user-friendly actionable error from sd-cli output without exposing raw CUDA/DLL paths."""
    txt = (raw_log or "").strip()
    low = txt.lower()
    if "ram graph capacity exceeded" in low or "out of memory" in low or "bad_alloc" in low or "failed to allocate" in low:
        return (
            f"Not enough free memory (RAM/VRAM) to run '{model_tag or 'local image model'}' right now. "
            "Try clicking 'RAM' in the top bar -> 'Optimize & Free Memory Now', switch to lighter 'sd-turbo', "
            "or turn Internet ON to generate via Free Cloud FLUX."
        )
    if "unknown argument" in low or "invalid argument" in low:
        return f"Incompatible runtime option for '{model_tag or 'local image model'}'. Try updating or reinstalling the image runtime."
    err_lines = [
        ln.strip() for ln in txt.splitlines()
        if ln.strip().startswith("[E]") or ("error:" in ln.lower() and "load_backend" not in ln.lower() and "ggml_cuda_init" not in ln.lower())
    ]
    cleaned_line = err_lines[0] if err_lines else "Local image engine stopped unexpectedly."
    cleaned_line = re.sub(r"^\[E\]\s*", "", cleaned_line)
    cleaned_line = re.sub(r"\s*---\s*[A-Za-z0-9_.-]+\.(?:cpp|hpp):\d+$", "", cleaned_line)
    cleaned_line = re.sub(r"(?:[A-Za-z]:)?(?:\\\\|/)?(?:Users|home)(?:\\\\|/)[^\\\\/\s]+", "<user>", cleaned_line)
    return f"Could not generate image with '{model_tag or 'local engine'}': {cleaned_line[:180]}"

    def sidecar_status_summary(self) -> Dict[str, Any]:
        """Returns clean hardware fit + installed binary + model summary for UI & Router."""
        llama_bin = find_llama_server_binary()
        sd_bin = find_sd_cpp_binary()
        ggufs = self.list_installed_gguf_models()
        img_models = self.list_installed_local_image_models()
        bonsai_fit = assess_model_hardware_fit("ternary-bonsai-2.5-27b-q2_0", 7.67).to_dict()
        flux_fit = assess_model_hardware_fit("flux-1-schnell-q4", 6.8).to_dict()
        return {
            "llama_cpp_available": llama_bin is not None,
            "llama_cpp_running": self.is_llama_server_running(timeout=0.3),
            "sd_cpp_available": sd_bin is not None,
            "installed_gguf": ggufs,
            "installed_local_image": img_models,
            "hardware_fit": {
                "ternary_bonsai_2_5": bonsai_fit,
                "flux_1_schnell_q4": flux_fit,
            },
        }
