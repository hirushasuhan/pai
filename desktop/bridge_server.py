"""PAI Desktop Application Local Loopback API Bridge Server.

Binds strictly to 127.0.0.1:8765 (Threat T21 Compliant) and exposes
high-speed endpoints for the PAI Studio Desktop UI:
  - Streaming Chat & Reasoning (<think> blocks)
  - 3rd-Party Cloud AI Configuration & Masked Status
  - Local AI Model Downloader & Manager (Ollama /api/pull, /api/tags)
  - Live Fact-Checking & Web Grounding Engine
  - Project Workspace Manager (Folder Context, Code Editor & File Sync)
  - Autonomous Multi-Agent Engineering Team (IEEE / FIPA-ACL Standard)
  - Built-in Skills Catalog & Toggles
  - Antigravity Autonomous Agent Supervisor
  - Live Weather, Web Search, and System Health
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add research directory and repository root to sys.path
RESEARCH_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = RESEARCH_DIR.parent
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Guard against None stdio when running under pythonw.exe on Windows
if sys.stdout is None:
    try:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    except Exception:
        pass
if sys.stderr is None:
    try:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    except Exception:
        pass

try:
    from research.cloud_ai import (
        CLOUD_PROVIDERS,
        add_configured_model,
        generate_image_cloud,
        get_active_cloud_model,
        get_active_cloud_provider,
        get_configured_models,
        get_provider_key,
        is_cloud_model,
        list_available_cloud_models,
        load_cloud_config,
        query_cloud_ai,
        remove_configured_model,
        set_active_cloud_model,
        set_custom_endpoint,
        set_provider_key,
    )
    from research.fact_checker import (
        format_factcheck_report,
        is_factcheck_enabled,
        set_factcheck_enabled,
        verify_text_claims,
    )
    from research.internet_service import (
        fetch_live_weather,
        get_live_grounding_context,
        is_internet_enabled,
        search_web,
        set_internet_enabled,
    )
except ImportError:
    from cloud_ai import (
        CLOUD_PROVIDERS,
        add_configured_model,
        generate_image_cloud,
        get_active_cloud_model,
        get_active_cloud_provider,
        get_configured_models,
        get_provider_key,
        is_cloud_model,
        list_available_cloud_models,
        load_cloud_config,
        query_cloud_ai,
        remove_configured_model,
        set_active_cloud_model,
        set_custom_endpoint,
        set_provider_key,
    )
    from fact_checker import (
        format_factcheck_report,
        is_factcheck_enabled,
        set_factcheck_enabled,
        verify_text_claims,
    )
    from internet_service import (
        fetch_live_weather,
        get_live_grounding_context,
        is_internet_enabled,
        search_web,
        set_internet_enabled,
    )

HOST = "127.0.0.1"
PORT = 8765

# Active active model memory
_CURRENT_ACTIVE_MODEL: str = os.environ.get("PAI_ACTIVE_MODEL", "llama3.2:3b")


def get_current_model() -> str:
    global _CURRENT_ACTIVE_MODEL
    return _CURRENT_ACTIVE_MODEL


def set_current_model(m: str) -> None:
    global _CURRENT_ACTIVE_MODEL
    _CURRENT_ACTIVE_MODEL = m
    os.environ["PAI_ACTIVE_MODEL"] = m
    if is_cloud_model(m):
        set_active_cloud_model(m)


def ensure_ollama_server(timeout: float = 8.0) -> bool:
    """Ensure Ollama daemon is running on 127.0.0.1:11434 (Threat T21 Compliant)."""
    try:
        req = urllib.request.Request("http://127.0.0.1:11434/api/tags", headers={"User-Agent": "PAI-Desktop/1.1"})
        with urllib.request.urlopen(req, timeout=0.8) as r:
            if r.status == 200:
                return True
    except Exception:
        pass

    cand_paths = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama" / "ollama.exe",
        Path("C:/Program Files/Ollama/ollama.exe"),
        Path(os.path.expanduser("~")) / "AppData" / "Local" / "Programs" / "Ollama" / "ollama.exe",
    ]
    ollama_exe = None
    for cand in cand_paths:
        if cand.is_file():
            ollama_exe = cand
            break

    if not ollama_exe:
        which_path = shutil.which("ollama")
        if which_path:
            ollama_exe = Path(which_path)

    if not ollama_exe or not ollama_exe.is_file():
        return False

    env = os.environ.copy()
    env["OLLAMA_HOST"] = "127.0.0.1:11434"
    flags = 0
    startupinfo = None
    if sys.platform == "win32":
        flags = 0x08000000  # CREATE_NO_WINDOW solely to avoid terminal flash
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE
    try:
        subprocess.Popen(
            [str(ollama_exe), "serve"],
            env=env,
            creationflags=flags,
            startupinfo=startupinfo,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            close_fds=(sys.platform != "win32"),
        )
    except Exception:
        return False

    start_time = time.time()
    while time.time() - start_time < timeout:
        time.sleep(0.3)
        try:
            req = urllib.request.Request("http://127.0.0.1:11434/api/tags", headers={"User-Agent": "PAI-Desktop/1.1"})
            with urllib.request.urlopen(req, timeout=0.8) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass

    return False


def get_projects_config_path() -> Path:
    p = Path.home() / ".pai" / "projects.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def load_projects_data() -> Dict[str, Any]:
    cfg = get_projects_config_path()
    if cfg.is_file():
        try:
            return json.loads(cfg.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"active_project": "", "projects": []}


def save_projects_data(data: Dict[str, Any]) -> None:
    cfg = get_projects_config_path()
    cfg.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def get_project_codebase_context(folder_path: Path, max_chars: int = 12000) -> str:
    """Collect snippets of code from active project folder for LLM context."""
    if not folder_path.is_dir():
        return ""
    code_exts = {".js", ".html", ".css", ".py", ".json", ".md", ".ts", ".rs", ".sql"}
    snippets = []
    total = 0
    for root, dirs, files in os.walk(folder_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "dist", "build"}]
        for f in sorted(files):
            p = Path(root) / f
            if p.suffix.lower() in code_exts and p.is_file():
                try:
                    rel = p.relative_to(folder_path)
                    content = p.read_text(encoding="utf-8", errors="replace")[:2500]
                    snippet = f"--- File: {rel} ---\n{content}"
                    if total + len(snippet) > max_chars:
                        break
                    snippets.append(snippet)
                    total += len(snippet)
                except Exception:
                    pass
        if total >= max_chars:
            break
    return "\n\n".join(snippets)


SKILLS_CATALOG = [
    {
        "id": "factcheck",
        "name": "Live Fact-Checking Engine",
        "description": "Decomposes model answers into factual statements and verifies them against live web citations with confidence scores.",
        "category": "Reasoning & Grounding",
        "icon": "shield",
        "enabled": True,
    },
    {
        "id": "internet",
        "name": "Live Real-Time Web & Weather",
        "description": "Enables the assistant to query real-time Open-Meteo weather telemetry and privacy-preserving DuckDuckGo web grounding.",
        "category": "External Tools",
        "icon": "globe",
        "enabled": True,
    },
    {
        "id": "ai_team",
        "name": "Autonomous AI Engineering Team",
        "description": "IEEE / FIPA-ACL compliant 4-role multi-agent team (PM, Senior Architect, Specialist, QA Auditor) for end-to-end SDLC sprints.",
        "category": "Multi-Agent System",
        "icon": "users",
        "enabled": True,
    },
    {
        "id": "project_workspace",
        "name": "Project Workspace Context",
        "description": "Grounds chats directly in your active project files, allowing code analysis, in-app file editing, and automated sync.",
        "category": "Development",
        "icon": "folder",
        "enabled": True,
    },
    {
        "id": "image_gen",
        "name": "Neural Image Synthesis",
        "description": "Direct text-to-image synthesis using Google Imagen 3 and OpenAI DALL-E 3 with instant chat preview & PNG download.",
        "category": "Creative & Vision",
        "icon": "image",
        "enabled": True,
    },
    {
        "id": "antigravity",
        "name": "Antigravity Autonomous Supervisor",
        "description": "Multi-turn autonomous task runner that decomposes goals, executes tools, and verifies deliverables.",
        "category": "Agent Automation",
        "icon": "layers",
        "enabled": True,
    },
    {
        "id": "router",
        "name": "Adaptive Model Router",
        "description": "Hardware-calibrated routing engine matching queries to best-fit local and cloud models based on task and RAM.",
        "category": "Core Architecture",
        "icon": "cpu",
        "enabled": True,
    },
]


def get_all_installed_local_models() -> Tuple[List[Dict[str, Any]], bool]:
    """Scan local models from Ollama /api/tags AND from disk manifests (~/.ollama/models/manifests)."""
    models_dict: Dict[str, Dict[str, Any]] = {}
    ollama_online = False

    # 1. Probe Ollama live endpoint
    try:
        req = urllib.request.Request("http://127.0.0.1:11434/api/tags", headers={"User-Agent": "PAI-Desktop/1.1"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for m in data.get("models", []):
                name = m.get("name", "")
                if not name:
                    continue
                size_gb = round(m.get("size", 0) / (1024 ** 3), 2)
                models_dict[name.lower()] = {
                    "name": name,
                    "size_gb": size_gb,
                    "modified_at": m.get("modified_at", ""),
                    "is_active": name == get_current_model(),
                }
            ollama_online = True
    except Exception:
        pass

    # 2. Disk manifest scanning (~/.ollama/models/manifests)
    manifest_dir = Path.home() / ".ollama" / "models" / "manifests"
    if manifest_dir.is_dir():
        for f in manifest_dir.rglob("*"):
            if f.is_file():
                try:
                    rel = f.relative_to(manifest_dir)
                    parts = rel.parts
                    if len(parts) >= 3:
                        model_name = parts[-2]
                        tag = parts[-1]
                        full_name = f"{model_name}:{tag}"
                        if full_name.lower() in models_dict:
                            continue
                        size_gb = 0.0
                        try:
                            m_data = json.loads(f.read_text(encoding="utf-8"))
                            size_bytes = sum(l.get("size", 0) for l in m_data.get("layers", []))
                            size_gb = round(size_bytes / (1024 ** 3), 2)
                        except Exception:
                            pass
                        m_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(f.stat().st_mtime))
                        models_dict[full_name.lower()] = {
                            "name": full_name,
                            "size_gb": size_gb,
                            "modified_at": m_time,
                            "is_active": full_name == get_current_model(),
                        }
                except Exception:
                    pass

    model_list = sorted(list(models_dict.values()), key=lambda x: x["name"])
    return model_list, ollama_online


def delete_local_model(model_name: str) -> Tuple[bool, str]:
    """Uninstall and delete a local model via Ollama DELETE /api/delete to free disk space."""
    if not model_name or not model_name.strip():
        return False, "Model name cannot be empty."
    ensure_ollama_server(timeout=3.0)
    url = "http://127.0.0.1:11434/api/delete"
    payload = json.dumps({"name": model_name.strip()}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "PAI-Desktop/1.1"},
        method="DELETE",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status in (200, 204):
                return True, f"Model '{model_name}' successfully uninstalled."
            return False, f"Ollama returned HTTP status {resp.status}."
    except urllib.error.HTTPError as exc:
        try:
            err_data = json.loads(exc.read().decode("utf-8", errors="replace"))
            return False, err_data.get("error", f"HTTP Error {exc.code}")
        except Exception:
            return False, f"HTTP Error {exc.code}: {exc.reason}"
    except Exception as exc:
        return False, str(exc)


DEFAULT_RECOMMENDED_MODELS: List[Dict[str, Any]] = [
    {
        "name": "llama3.2:3b",
        "tag": "llama3.2:3b",
        "size": "2.0 GB",
        "desc": "Meta Llama 3.2 3B - Ultra fast, low RAM reasoning & chat",
        "category": "Chat & Fast Reasoning",
    },
    {
        "name": "qwen2.5-coder:7b",
        "tag": "qwen2.5-coder:7b",
        "size": "4.7 GB",
        "desc": "Qwen 2.5 Coder 7B - Best-in-class coding & architecture",
        "category": "Software Engineering",
    },
    {
        "name": "deepseek-r1:7b",
        "tag": "deepseek-r1:7b",
        "size": "4.7 GB",
        "desc": "DeepSeek R1 7B - Deep chain-of-thought mathematical reasoning",
        "category": "Deep Reasoning",
    },
    {
        "name": "mistral:7b",
        "tag": "mistral:7b",
        "size": "4.1 GB",
        "desc": "Mistral 7B Instruct - High precision versatile reasoning",
        "category": "General Intelligence",
    },
    {
        "name": "phi3.5:3.8b",
        "tag": "phi3.5:3.8b",
        "size": "2.2 GB",
        "desc": "Microsoft Phi-3.5 Mini - Lightweight agentic assistant",
        "category": "Compact Agent",
    },
    {
        "name": "llava:7b",
        "tag": "llava:7b",
        "size": "4.7 GB",
        "desc": "LLaVA 7B - Multimodal vision, image inspection & visual QA",
        "category": "Vision & Multimodal",
    },
    {
        "name": "moondream:latest",
        "tag": "moondream:latest",
        "size": "1.7 GB",
        "desc": "Moondream 2 - Ultra-compact, fast vision & captioning model",
        "category": "Vision & Multimodal",
    },
]


def get_recommended_catalog_path() -> Path:
    p = Path.home() / ".pai" / "recommended_catalog.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def load_recommended_catalog(installed_names: Optional[set] = None) -> List[Dict[str, Any]]:
    """Load recommended models from disk cache (~/.pai/recommended_catalog.json) or built-in default."""
    cfg_file = get_recommended_catalog_path()
    catalog_list = []
    if cfg_file.is_file():
        try:
            data = json.loads(cfg_file.read_text(encoding="utf-8"))
            if isinstance(data, list) and data:
                catalog_list = data
        except Exception:
            pass

    if not catalog_list:
        catalog_list = DEFAULT_RECOMMENDED_MODELS.copy()
        try:
            cfg_file.write_text(json.dumps(catalog_list, indent=2), encoding="utf-8")
        except Exception:
            pass

    if installed_names is None:
        local_models, _ = get_all_installed_local_models()
        installed_names = {m["name"].lower() for m in local_models}

    results = []
    for item in catalog_list:
        entry = dict(item)
        entry["is_installed"] = entry.get("tag", "").lower() in installed_names
        results.append(entry)
    return results


def refresh_recommended_catalog() -> List[Dict[str, Any]]:
    """Synchronize recommended catalog cache and return updated model list."""
    # Ensure all default curated models (including vision) are always present
    cfg_file = get_recommended_catalog_path()
    existing: Dict[str, Dict[str, Any]] = {}
    if cfg_file.is_file():
        try:
            raw = json.loads(cfg_file.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                for m in raw:
                    if "tag" in m:
                        existing[m["tag"].lower()] = m
        except Exception:
            pass

    for def_m in DEFAULT_RECOMMENDED_MODELS:
        if def_m["tag"].lower() not in existing:
            existing[def_m["tag"].lower()] = def_m

    updated_list = list(existing.values())
    try:
        cfg_file.write_text(json.dumps(updated_list, indent=2), encoding="utf-8")
    except Exception:
        pass

    return load_recommended_catalog()


def get_mcp_config_path() -> Path:
    p = Path.home() / ".pai" / "mcp_servers.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def load_mcp_servers() -> List[Dict[str, Any]]:
    p = get_mcp_config_path()
    if p.is_file():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except Exception:
            pass
    defaults = [
        {
            "name": "filesystem-mcp",
            "command": "npx -y @modelcontextprotocol/server-filesystem ./",
            "transport": "stdio",
            "enabled": True,
            "description": "Local filesystem sandboxed access & directory inspection",
        },
        {
            "name": "sqlite-mcp",
            "command": "npx -y @modelcontextprotocol/server-sqlite --db-path ./workspace.db",
            "transport": "stdio",
            "enabled": False,
            "description": "Relational SQLite query execution and schema analysis",
        },
        {
            "name": "github-mcp",
            "command": "npx -y @modelcontextprotocol/server-github",
            "transport": "stdio",
            "enabled": False,
            "description": "GitHub repository, issues, and commit tools",
        },
    ]
    try:
        p.write_text(json.dumps(defaults, indent=2), encoding="utf-8")
    except Exception:
        pass
    return defaults


def save_mcp_servers(servers: List[Dict[str, Any]]) -> bool:
    try:
        p = get_mcp_config_path()
        p.write_text(json.dumps(servers, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


def get_plugins_config_path() -> Path:
    p = Path.home() / ".pai" / "plugins.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def load_plugins_list() -> List[Dict[str, Any]]:
    p = get_plugins_config_path()
    custom_plugins = []
    if p.is_file():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                custom_plugins = data
        except Exception:
            pass

    all_plugins = list(SKILLS_CATALOG)
    seen_ids = {s["id"] for s in all_plugins}
    for cp in custom_plugins:
        if cp.get("id") not in seen_ids:
            all_plugins.append(cp)
    return all_plugins


def save_custom_plugin(plugin: Dict[str, Any]) -> bool:
    try:
        p = get_plugins_config_path()
        curr = []
        if p.is_file():
            try:
                curr = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                curr = []
        curr = [x for x in curr if x.get("id") != plugin.get("id")]
        curr.append(plugin)
        p.write_text(json.dumps(curr, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


def get_pai_config_path() -> Path:
    p = Path.home() / ".pai" / "config.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def get_model_storage_path() -> str:
    """Get active models storage path from environment or ~/.pai/config.json."""
    if "OLLAMA_MODELS" in os.environ and os.environ["OLLAMA_MODELS"]:
        return os.environ["OLLAMA_MODELS"]
    p = get_pai_config_path()
    if p.is_file():
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            if d.get("models_path") and os.path.isdir(d["models_path"]):
                return d["models_path"]
        except Exception:
            pass
    # Default Ollama models directory
    default_dir = Path.home() / ".ollama" / "models"
    return str(default_dir)


def set_model_storage_path(new_path: str) -> bool:
    """Update active models storage path and apply to process environment."""
    try:
        p_dir = Path(new_path).resolve()
        p_dir.mkdir(parents=True, exist_ok=True)
        os.environ["OLLAMA_MODELS"] = str(p_dir)
        cfg_path = get_pai_config_path()
        data = {}
        if cfg_path.is_file():
            try:
                data = json.loads(cfg_path.read_text(encoding="utf-8"))
            except Exception:
                data = {}
        data["models_path"] = str(p_dir)
        cfg_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


_HARDWARE_CACHE: Optional[Dict[str, Any]] = None


def detect_system_hardware() -> Dict[str, Any]:
    """Inspect local hardware: exact OS, CPU, GPU, RAM and Storage."""
    global _HARDWARE_CACHE
    if _HARDWARE_CACHE is not None:
        try:
            total, used, free = shutil.disk_usage("C:")
            _HARDWARE_CACHE["storage"]["total_gb"] = round(total / (1024**3), 1)
            _HARDWARE_CACHE["storage"]["free_gb"] = round(free / (1024**3), 1)
            _HARDWARE_CACHE["storage"]["used_gb"] = round(used / (1024**3), 1)
        except Exception:
            pass
        return _HARDWARE_CACHE

    os_caption = platform.platform()
    cpu_name = platform.processor() or "Multi-Core Processor"
    cores = os.cpu_count() or 4
    threads = cores
    gpus = []
    ram_bytes = 0

    if sys.platform == "win32":
        try:
            import base64
            ps_script = """
            $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 Name, NumberOfCores, NumberOfLogicalProcessors
            $gpus = @(Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name)
            $os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
            $mem = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
            [PSCustomObject]@{
                os_caption = $os.Caption
                os_build = $os.BuildNumber
                cpu = $cpu.Name
                cores = $cpu.NumberOfCores
                threads = $cpu.NumberOfLogicalProcessors
                gpus = $gpus
                ram_bytes = $mem
            } | ConvertTo-Json
            """
            enc = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
            flags = 0x08000000  # CREATE_NO_WINDOW
            raw = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
                creationflags=flags,
                stdin=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=12.0,
            ).decode("utf-8", errors="replace")
            idx = raw.find("{")
            if idx != -1:
                d = json.loads(raw[idx:])
                if d.get("os_caption"):
                    os_caption = f"{d['os_caption']} (Build {d.get('os_build', '')})".strip()
                if d.get("cpu"):
                    cpu_name = d["cpu"]
                if d.get("cores"):
                    cores = int(d["cores"])
                if d.get("threads"):
                    threads = int(d["threads"])
                if d.get("gpus"):
                    gpus = d["gpus"] if isinstance(d["gpus"], list) else [str(d["gpus"])]
                if d.get("ram_bytes"):
                    ram_bytes = int(d["ram_bytes"])
        except Exception:
            pass

    # Storage telemetry
    total, used, free = 0, 0, 0
    try:
        total, used, free = shutil.disk_usage("C:")
    except Exception:
        pass

    ram_total_gb = round(ram_bytes / (1024**3), 1) if ram_bytes else 16.0
    if not gpus:
        gpus = ["Integrated / Dedicated Graphics Adapter"]

    hw = {
        "os": os_caption,
        "cpu": cpu_name,
        "cores": cores,
        "threads": threads,
        "gpus": gpus,
        "ram_total_gb": ram_total_gb,
        "storage": {
            "drive": "C:",
            "total_gb": round(total / (1024**3), 1),
            "free_gb": round(free / (1024**3), 1),
            "used_gb": round(used / (1024**3), 1),
        },
    }
    _HARDWARE_CACHE = hw
    return hw


def open_native_folder_dialog(title: str = "Select Project Workspace Folder") -> Optional[str]:
    """Open native Windows folder picker dialog and return selected path."""
    if sys.platform == "win32":
        # 1. Primary: Python Tkinter native folder dialog with topmost window
        try:
            py_code = (
                "import sys, os, tkinter as tk, tkinter.filedialog as fd\n"
                "try:\n"
                "    r = tk.Tk()\n"
                "    r.withdraw()\n"
                "    r.attributes('-topmost', True)\n"
                "    r.focus_force()\n"
                "    t = sys.argv[1] if len(sys.argv) > 1 else 'Select Folder'\n"
                "    p = fd.askdirectory(parent=r, title=t)\n"
                "    r.destroy()\n"
                "    if p and os.path.isdir(p):\n"
                "        print(os.path.normpath(p))\n"
                "except Exception:\n"
                "    pass\n"
            )
            py_bin = sys.executable or "python.exe"
            flags = 0x08000000 if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            res = subprocess.run(
                [py_bin, "-c", py_code, title],
                capture_output=True,
                text=True,
                creationflags=flags,
                timeout=120.0,
            )
            out = res.stdout.strip()
            if out and os.path.isdir(out):
                return os.path.normpath(out)
        except Exception:
            pass

        # 2. Fallback: Shell.Application BrowseForFolder
        try:
            import base64
            ps_script = f"""
            $app = New-Object -ComObject Shell.Application
            $folder = $app.BrowseForFolder(0, '{title}', 0x00000010 + 0x00000040 + 0x00000200, 0)
            if ($folder -ne $null) {{
                [Console]::WriteLine($folder.Self.Path)
            }}
            """
            enc = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
            res = subprocess.run(
                ["powershell", "-NoProfile", "-STA", "-EncodedCommand", enc],
                capture_output=True,
                text=True,
                timeout=120.0,
            )
            for line in res.stdout.strip().splitlines():
                line = line.strip()
                if line and os.path.isdir(line):
                    return os.path.normpath(line)
        except Exception:
            pass

    return None


def parse_uploaded_file_content(filename: str, raw_bytes: bytes) -> Dict[str, Any]:
    """Extract readable text from txt, md, pdf, docx, xlsx, csv, and code files."""
    import io
    import os
    import re
    import xml.etree.ElementTree as ET
    import zipfile

    ext = os.path.splitext(filename)[1].lower().lstrip(".")
    text = ""
    try:
        # 1. Plain text, markdown, CSV, JSON, code files
        if ext in ("txt", "md", "csv", "json", "py", "js", "ts", "html", "css", "xml", "yaml", "yml", "sh", "bat", "log"):
            try:
                text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text = raw_bytes.decode("latin-1", errors="replace")

        # 2. Word documents (.docx, .doc)
        elif ext in ("docx", "doc"):
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
                    if "word/document.xml" in z.namelist():
                        xml_bytes = z.read("word/document.xml")
                        tree = ET.fromstring(xml_bytes)
                        paras = []
                        for p in tree.iter():
                            if p.tag.endswith("p"):
                                p_text = "".join(node.text for node in p.iter() if node.text and node.tag.endswith("t"))
                                if p_text.strip():
                                    paras.append(p_text.strip())
                        text = "\n\n".join(paras)
            except Exception:
                runs = re.findall(rb'[\x20-\x7E\r\n]{4,}', raw_bytes)
                text = "\n".join(r.decode("latin-1", errors="ignore") for r in runs if not r.startswith(rb"PK"))

        # 3. Excel Spreadsheets (.xlsx, .xls)
        elif ext in ("xlsx", "xls"):
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
                    shared_strings = []
                    if "xl/sharedStrings.xml" in z.namelist():
                        stree = ET.fromstring(z.read("xl/sharedStrings.xml"))
                        for si in stree.iter():
                            if si.tag.endswith("si"):
                                item_text = "".join(t.text for t in si.iter() if t.tag.endswith("t") and t.text)
                                shared_strings.append(item_text.strip())
                    
                    sheets = [n for n in z.namelist() if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")]
                    sheet_rows = []
                    for sheet_name in sheets[:3]:  # read up to 3 sheets
                        stree = ET.fromstring(z.read(sheet_name))
                        for row in stree.iter():
                            if row.tag.endswith("row"):
                                cols = []
                                for c in row.iter():
                                    if c.tag.endswith("c"):
                                        t_attr = c.attrib.get("t")
                                        val = "".join(node.text for node in c.iter() if node.tag.endswith("v") and node.text).strip()
                                        if t_attr == "s" and val.isdigit() and int(val) < len(shared_strings):
                                            cols.append(shared_strings[int(val)])
                                        elif val:
                                            cols.append(val)
                                if cols:
                                    sheet_rows.append(" | ".join(cols))
                    text = "\n".join(sheet_rows)
            except Exception:
                runs = re.findall(rb'[\x20-\x7E\r\n]{4,}', raw_bytes)
                text = "\n".join(r.decode("latin-1", errors="ignore") for r in runs if not r.startswith(rb"PK"))

        # 4. PDF Documents (.pdf)
        elif ext == "pdf":
            text_pieces = []
            streams = re.findall(rb'stream[\r\n]+([\s\S]*?)[\r\n]+endstream', raw_bytes)
            for s in streams:
                try:
                    import zlib
                    decomp = zlib.decompress(s)
                except Exception:
                    decomp = s
                matches = re.findall(rb'\(([^\)\\]*(?:\\.[^\)\\]*)*)\)\s*T[jJ]', decomp)
                for m in matches:
                    try:
                        dec = m.decode("utf-8", errors="replace").replace("\\(", "(").replace("\\)", ")")
                        if dec.strip():
                            text_pieces.append(dec.strip())
                    except Exception:
                        pass
            if text_pieces:
                text = " ".join(text_pieces)
            else:
                runs = re.findall(rb'[\x20-\x7E\r\n]{5,}', raw_bytes)
                text = "\n".join(r.decode("latin-1", errors="ignore") for r in runs if not r.startswith(rb"%PDF") and not r.startswith(rb"/"))

        else:
            try:
                text = raw_bytes.decode("utf-8")
            except Exception:
                runs = re.findall(rb'[\x20-\x7E\r\n]{4,}', raw_bytes)
                text = "\n".join(r.decode("latin-1", errors="ignore") for r in runs)
    except Exception as e:
        return {"success": False, "error": f"Failed to parse {filename}: {e}"}

    clean_text = text.strip()[:40000]
    return {
        "success": True,
        "filename": filename,
        "type": ext,
        "size": len(raw_bytes),
        "char_count": len(clean_text),
        "content": clean_text,
        "preview": clean_text[:200] + ("..." if len(clean_text) > 200 else ""),
    }


def get_system_preflight() -> Dict[str, Any]:
    """Inspect local prerequisites, start Ollama if offline, and scan models."""
    py_ver = platform.python_version()
    py_exe = sys.executable

    # 1. Auto-boot Ollama daemon if offline
    ollama_online = ensure_ollama_server(timeout=4.0)
    ollama_path = shutil.which("ollama")
    if not ollama_path:
        cand_paths = [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama" / "ollama.exe",
            Path("C:/Program Files/Ollama/ollama.exe"),
            Path.home() / "AppData" / "Local" / "Programs" / "Ollama" / "ollama.exe",
        ]
        for c in cand_paths:
            if c.is_file():
                ollama_path = str(c)
                break
    ollama_installed = bool(ollama_path and os.path.isfile(ollama_path))

    # 2. Local models scan
    models_list, _ = get_all_installed_local_models()
    model_count = len(models_list)

    # 3. Recommended models catalog
    installed_names = {m["name"].lower() for m in models_list}
    recommended_models = load_recommended_catalog(installed_names)

    # 4. Hardware telemetry
    hw = detect_system_hardware()
    ready = bool(ollama_online and model_count > 0)

    return {
        "success": True,
        "ready": ready,
        "python": {
            "version": py_ver,
            "executable": py_exe,
            "status": "healthy",
        },
        "ollama": {
            "installed": ollama_installed,
            "running": ollama_online,
            "path": str(ollama_path) if ollama_path else "",
            "download_url": "https://ollama.com/download/windows",
            "status": "healthy" if ollama_online else ("not_running" if ollama_installed else "missing"),
            "models_path": get_model_storage_path(),
        },
        "models": {
            "count": model_count,
            "installed": models_list,
            "recommended": recommended_models,
            "active_model": get_current_model(),
            "storage_path": get_model_storage_path(),
        },
        "hardware": hw,
    }


class PAIBridgeHandler(BaseHTTPRequestHandler):
    """Threaded HTTP handler serving desktop frontend requests on 127.0.0.1."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress or safely route HTTP access logs."""
        if sys.stderr is not None:
            try:
                sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))
            except Exception:
                pass

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def _send_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                raw = self.rfile.read(length).decode("utf-8")
                return json.loads(raw)
        except Exception:
            pass
        return {}

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # Static assets
        desktop_dir = Path(__file__).resolve().parent
        if path in ("/", "/index.html"):
            index_file = desktop_dir / "index.html"
            if index_file.is_file():
                content = index_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return
        elif path == "/style.css":
            css_file = desktop_dir / "style.css"
            if css_file.is_file():
                content = css_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/css; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return
        elif path == "/app.js":
            js_file = desktop_dir / "app.js"
            if js_file.is_file():
                content = js_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return
        elif path == "/manifest.json":
            manifest_file = desktop_dir / "manifest.json"
            if manifest_file.is_file():
                content = manifest_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/manifest+json; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return
        elif path == "/favicon.ico":
            ico_file = desktop_dir / "assets" / "pai.ico"
            if ico_file.is_file():
                content = ico_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "image/x-icon")
                self.send_header("Content-Length", str(len(content)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return
        elif path.startswith("/assets/"):
            fname = Path(path[len("/assets/"):]).name
            asset_file = desktop_dir / "assets" / fname
            if asset_file.is_file():
                content = asset_file.read_bytes()
                ctype = "image/png" if fname.endswith(".png") else "image/x-icon"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(content)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return
        elif path.startswith("/generated_images/"):
            fname = Path(path[len("/generated_images/"):]).name
            img_file = Path.home() / ".pai" / "generated_images" / fname
            if img_file.is_file():
                content = img_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(content)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return

        # 1. Status endpoint
        if path == "/api/status":
            self._handle_status()
        # 2. Models list
        elif path in ("/api/models", "/api/installed-models"):
            self._handle_get_models()
        # 2b. Recommended models catalog
        elif path == "/api/models/recommended":
            self._send_json({"success": True, "recommended": load_recommended_catalog()})
        # 3. Cloud config & key status
        elif path == "/api/cloud/config":
            self._handle_get_cloud_config()
        # 4. Projects list & active project
        elif path == "/api/projects":
            self._handle_projects_list()
        # 5. Project files
        elif path == "/api/projects/files":
            self._handle_project_files(query_params)
        # 6. Project file content
        elif path == "/api/projects/file/content":
            self._handle_project_file_content(query_params)
        # 7. AI Team roster
        elif path == "/api/team/roster":
            self._handle_team_roster()
        # 8. Skills list
        elif path == "/api/skills":
            self._handle_skills_list()
        # 9. Live weather
        elif path == "/api/weather":
            city = query_params.get("city", [""])[0]
            ok, msg, raw = fetch_live_weather(city)
            self._send_json({"success": ok, "message": msg, "data": raw})
        # 10. Live web search
        elif path == "/api/search":
            q = query_params.get("q", [""])[0]
            ok, msg, res = search_web(q)
            self._send_json({"success": ok, "message": msg, "results": res})
        # 10b. MCP Servers List
        elif path == "/api/mcp/list":
            servers = load_mcp_servers()
            self._send_json({"success": True, "servers": servers})
        # 10c. Plugins List
        elif path == "/api/plugins/list":
            plugins = load_plugins_list()
            self._send_json({"success": True, "plugins": plugins})
        # 11. Doctor / Hardware telemetry
        elif path in ("/api/doctor", "/api/system/hardware"):
            self._handle_doctor()
        # 11b. Model Storage Path & Telemetry
        elif path == "/api/models/storage":
            hw = detect_system_hardware()
            self._send_json({
                "success": True,
                "path": get_model_storage_path(),
                "storage": hw["storage"],
            })
        # 12. Preflight system health check
        elif path == "/api/system/preflight":
            self._handle_system_preflight()
        # 13. Native folder selection
        elif path == "/api/utils/select_folder":
            self._handle_select_folder()
        else:
            self._send_json({"error": f"Unknown endpoint: {path}"}, status=404)

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        body = self._read_json_body()

        # 1. Chat Completion & Grounding
        if path == "/api/chat":
            self._handle_chat(body)
                # 1b. Parse Uploaded Document Attachment (docs, txt, pdf, excel, md)
        elif path == "/api/chat/parse_file":
            import base64
            fname = body.get("name") or body.get("filename") or "document.txt"
            b64_data = body.get("base64") or body.get("data") or ""
            if b64_data:
                if "," in b64_data:
                    b64_data = b64_data.split(",", 1)[1]
                try:
                    raw_bytes = base64.b64decode(b64_data)
                except Exception as exc:
                    self._send_json({"success": False, "error": f"Invalid base64 payload: {exc}"}, status=400)
                    return
            else:
                raw_text = body.get("content", "")
                raw_bytes = raw_text.encode("utf-8")

            res = parse_uploaded_file_content(fname, raw_bytes)
            self._send_json(res)
        # 2. Local Model Pull (Download)
        elif path == "/api/models/pull":
            self._handle_pull_model(body)
        # 2b. Local Model Uninstall (Delete)
        elif path == "/api/models/delete":
            m_name = body.get("name", "").strip() or body.get("model", "").strip()
            if not m_name:
                self._send_json({"success": False, "error": "Model name is required for uninstallation."}, status=400)
            else:
                ok_del, msg_del = delete_local_model(m_name)
                self._send_json({"success": ok_del, "message": msg_del, "error": None if ok_del else msg_del})
        # 2c. Refresh Recommended Models Catalog
        elif path == "/api/models/recommended/refresh":
            recs = refresh_recommended_catalog()
            self._send_json({"success": True, "recommended": recs})
        # 2d. Model Storage Path Update
        elif path == "/api/models/storage":
            custom_p = body.get("path", "").strip()
            if not custom_p:
                self._send_json({"success": False, "error": "Storage path is required."}, status=400)
            else:
                ok_set = set_model_storage_path(custom_p)
                hw = detect_system_hardware()
                self._send_json({"success": ok_set, "path": get_model_storage_path(), "storage": hw["storage"]})
        # 2e. Validate or Create Project Directory Path
        elif path == "/api/projects/validate_path":
            target_p = body.get("path", "").strip()
            if not target_p:
                self._send_json({"success": False, "error": "Folder path cannot be empty."}, status=400)
            else:
                try:
                    norm = os.path.normpath(target_p)
                    os.makedirs(norm, exist_ok=True)
                    self._send_json({"success": True, "path": norm, "name": Path(norm).name or "Workspace"})
                except Exception as exc:
                    self._send_json({"success": False, "error": f"Invalid path: {exc}"}, status=400)
        # 3. Model Switch
        elif path == "/api/models/switch":
            m = body.get("model", "").strip()
            if m:
                set_current_model(m)
                self._send_json({"success": True, "active_model": m})
            else:
                self._send_json({"success": False, "error": "Model name required"}, status=400)
        # 4. Save Cloud Model (Dynamic Form)
        elif path == "/api/cloud/save_model":
            m_name = body.get("model_name", "").strip()
            p_url = body.get("provider_url", "").strip()
            key = body.get("api_key", "").strip()
            m_type = body.get("model_type", "chat").strip()
            prov = body.get("provider", "custom").strip()
            if m_name and p_url and key:
                saved = add_configured_model(m_name, p_url, key, m_type, prov)
                self._send_json({"success": True, "model": saved})
            else:
                self._send_json({"success": False, "error": "Model name, provider URL, and API key are required."}, status=400)
        # 5. Delete Cloud Model
        elif path == "/api/cloud/delete_model":
            m_name = body.get("model_name", "").strip()
            ok_del = remove_configured_model(m_name)
            self._send_json({"success": ok_del, "model_name": m_name})
        # 6. Generate Image Endpoint
        elif path == "/api/image/generate":
            prompt = body.get("prompt", "").strip()
            model = body.get("model", "")
            ok_img, data_url_or_err, fpath, fname = generate_image_cloud(prompt, model=model)
            if ok_img:
                self._send_json({
                    "success": True,
                    "is_image": True,
                    "image_url": data_url_or_err,
                    "image_path": fpath,
                    "filename": fname,
                    "prompt": prompt,
                    "model": model,
                })
            else:
                self._send_json({"success": False, "error": data_url_or_err}, status=500)
        # 7. Projects Endpoints
        elif path == "/api/projects/save":
            self._handle_project_save(body)
        elif path == "/api/projects/set_active":
            self._handle_project_set_active(body)
        elif path == "/api/projects/delete":
            self._handle_project_delete(body)
        elif path == "/api/projects/file/save":
            self._handle_project_file_save(body)
        # 8. AI Team Endpoints
        elif path == "/api/team/assign":
            self._handle_team_assign(body)
        elif path == "/api/team/run":
            self._handle_team_run(body)
        # 9. Skills Toggle
        elif path == "/api/skills/toggle":
            self._handle_skill_toggle(body)
        # 10. Toggle Internet / Factcheck
        elif path == "/api/settings/toggle":
            feature = body.get("feature", "")
            val = bool(body.get("value", False))
            if feature == "internet":
                set_internet_enabled(val)
                self._send_json({"success": True, "internet_enabled": is_internet_enabled()})
            elif feature == "factcheck":
                set_factcheck_enabled(val)
                self._send_json({"success": True, "factcheck_enabled": is_factcheck_enabled()})
            else:
                self._send_json({"success": False, "error": f"Unknown feature: {feature}"}, status=400)
        # 11. Fact-Check Text
        elif path == "/api/factcheck":
            text = body.get("text", "")
            claims = verify_text_claims(text)
            claims_data = [
                {
                    "statement": c.statement,
                    "verdict": c.verdict,
                    "confidence": c.confidence,
                    "citations": c.citations,
                    "notes": c.notes,
                }
                for c in claims
            ]
            report = format_factcheck_report(claims)
            self._send_json({"success": True, "claims": claims_data, "report": report})
        # 12. Antigravity Supervisor Run
        elif path == "/api/antigravity/run":
            self._handle_antigravity_run(body)
        # 13. Native Folder Picker
        elif path == "/api/utils/select_folder":
            self._handle_select_folder()
        # 14. MCP Save Server
        elif path == "/api/mcp/save":
            name = body.get("name", "").strip()
            cmd = body.get("command", "").strip()
            trans = body.get("transport", "stdio").strip()
            desc = body.get("description", "").strip()
            if not name or not cmd:
                self._send_json({"success": False, "error": "Server name and command/URL are required."}, status=400)
            else:
                servers = load_mcp_servers()
                existing = [s for s in servers if s.get("name") != name]
                existing.append({
                    "name": name,
                    "command": cmd,
                    "transport": trans,
                    "description": desc or f"Custom {trans.upper()} MCP server",
                    "enabled": True,
                })
                ok_s = save_mcp_servers(existing)
                self._send_json({"success": ok_s, "servers": existing})
        # 15. MCP Delete Server
        elif path == "/api/mcp/delete":
            name = body.get("name", "").strip()
            servers = load_mcp_servers()
            filtered = [s for s in servers if s.get("name") != name]
            ok_d = save_mcp_servers(filtered)
            self._send_json({"success": ok_d, "servers": filtered})
        # 16. MCP Toggle Server
        elif path == "/api/mcp/toggle":
            name = body.get("name", "").strip()
            val = bool(body.get("enabled", True))
            servers = load_mcp_servers()
            for s in servers:
                if s.get("name") == name:
                    s["enabled"] = val
            ok_t = save_mcp_servers(servers)
            self._send_json({"success": ok_t, "servers": servers})
        # 17. Save Custom Plugin
        elif path == "/api/plugins/save":
            p_name = body.get("name", "").strip()
            p_desc = body.get("description", "").strip()
            p_cat = body.get("category", "Custom Extensions").strip()
            if not p_name:
                self._send_json({"success": False, "error": "Plugin name is required."}, status=400)
            else:
                p_id = re.sub(r"[^a-z0-9_]+", "_", p_name.lower()).strip("_")
                new_plug = {
                    "id": p_id,
                    "name": p_name,
                    "description": p_desc or "Custom agentic plugin extension.",
                    "category": p_cat,
                    "icon": "zap",
                    "enabled": True,
                }
                ok_p = save_custom_plugin(new_plug)
                self._send_json({"success": ok_p, "plugin": new_plug, "plugins": load_plugins_list()})
        # 18. Delete Custom Plugin
        elif path == "/api/plugins/delete":
            p_id = body.get("id", "").strip()
            cfg_p = get_plugins_config_path()
            curr = []
            if cfg_p.is_file():
                try:
                    curr = json.loads(cfg_p.read_text(encoding="utf-8"))
                except Exception:
                    curr = []
            filtered = [x for x in curr if x.get("id") != p_id]
            try:
                cfg_p.write_text(json.dumps(filtered, indent=2), encoding="utf-8")
                self._send_json({"success": True, "plugins": load_plugins_list()})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
        else:
            self._send_json({"error": f"Unknown endpoint: {path}"}, status=404)

    def _handle_status(self) -> None:
        p_data = load_projects_data()
        self._send_json({
            "version": "1.1.0-rc4",
            "active_model": get_current_model(),
            "active_project": p_data.get("active_project", ""),
            "internet_enabled": is_internet_enabled(),
            "factcheck_enabled": is_factcheck_enabled(),
            "status": "ready",
        })

    def _handle_get_models(self) -> None:
        local_models, ollama_online = get_all_installed_local_models()
        # Return only cloud models that have active API keys configured
        cloud_models = [cm for cm in list_available_cloud_models() if cm.get("has_key")]
        self._send_json({
            "ollama_online": ollama_online,
            "local_models": local_models,
            "cloud_models": cloud_models,
            "active_model": get_current_model(),
        })

    def _handle_get_cloud_config(self) -> None:
        cfg = load_cloud_config()
        configured_models = cfg.get("configured_models", [])
        providers = []
        for prov_id, meta in CLOUD_PROVIDERS.items():
            if prov_id == "custom" and not cfg.get("custom_endpoint"):
                continue
            has_k = bool(get_provider_key(prov_id))
            providers.append({
                "id": prov_id,
                "name": meta["display_name"],
                "has_key": has_k,
                "default_model": meta.get("default_model", ""),
                "models": meta.get("models", []),
                "type": meta.get("type", "chat"),
            })
        self._send_json({
            "active_provider": cfg.get("active_provider", ""),
            "active_model": cfg.get("active_model", ""),
            "custom_endpoint": cfg.get("custom_endpoint", ""),
            "providers": providers,
            "configured_models": configured_models,
        })

    def _handle_doctor(self) -> None:
        # Accurate Hardware inspection
        hw = detect_system_hardware()
        self._send_json({
            "platform": hw["os"],
            "python_version": sys.version.split()[0],
            "ram": {
                "total_gb": hw["ram_total_gb"],
                "available_gb": hw["ram_total_gb"],
            },
            "hardware": hw,
            "internet_enabled": is_internet_enabled(),
            "factcheck_enabled": is_factcheck_enabled(),
            "active_model": get_current_model(),
        })

    def _handle_projects_list(self) -> None:
        data = load_projects_data()
        for p in data.get("projects", []):
            pth = Path(p.get("path", ""))
            p["exists"] = pth.is_dir()
            if p["exists"]:
                try:
                    p["file_count"] = sum(1 for _ in pth.rglob("*") if _.is_file())
                except Exception:
                    p["file_count"] = 0
            else:
                p["file_count"] = 0
        self._send_json(data)

    def _handle_project_save(self, body: Dict[str, Any]) -> None:
        name = body.get("name", "").strip()
        path_str = body.get("path", "").strip()
        desc = body.get("description", "").strip()
        if not name or not path_str:
            self._send_json({"error": "Project name and folder path are required."}, status=400)
            return

        folder = Path(os.path.expanduser(path_str)).resolve()
        folder.mkdir(parents=True, exist_ok=True)

        data = load_projects_data()
        projects = data.get("projects", [])
        existing = next((p for p in projects if p.get("name", "").lower() == name.lower()), None)
        item = {
            "name": name,
            "path": str(folder),
            "description": desc,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if existing:
            existing.update(item)
        else:
            item["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            projects.append(item)

        data["projects"] = projects
        data["active_project"] = name
        save_projects_data(data)
        self._send_json({"success": True, "project": item, "active_project": name})

    def _handle_project_set_active(self, body: Dict[str, Any]) -> None:
        name = body.get("name", "").strip()
        data = load_projects_data()
        data["active_project"] = name
        save_projects_data(data)
        self._send_json({"success": True, "active_project": name})

    def _handle_project_delete(self, body: Dict[str, Any]) -> None:
        name = body.get("name", "").strip()
        data = load_projects_data()
        data["projects"] = [p for p in data.get("projects", []) if p.get("name", "").lower() != name.lower()]
        if data.get("active_project", "").lower() == name.lower():
            data["active_project"] = ""
        save_projects_data(data)
        self._send_json({"success": True, "deleted": name})

    def _handle_project_files(self, query_params: Dict[str, List[str]]) -> None:
        p_str = query_params.get("path", [""])[0].strip()
        if not p_str:
            data = load_projects_data()
            act = data.get("active_project", "")
            for p in data.get("projects", []):
                if p.get("name", "").lower() == act.lower():
                    p_str = p.get("path", "")
                    break

        if not p_str or not Path(p_str).is_dir():
            self._send_json({"files": [], "error": "Folder not found"}, status=404)
            return

        base = Path(p_str).resolve()
        files = []
        max_files = 350
        excluded_dirs = {
            ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
            "dist", "build", "target", ".pai", ".idea", ".vscode", "bin",
            "obj", "pkg", ".next", "coverage", ".pytest_cache", ".cargo",
            "target", "debug", "release", ".gemini"
        }
        binary_exts = {
            ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".img",
            ".zip", ".tar", ".gz", ".7z", ".rar", ".png", ".jpg", ".jpeg",
            ".gif", ".ico", ".webp", ".mp3", ".mp4", ".wav", ".avi",
            ".pdf", ".docx", ".xlsx", ".pptx", ".pyc", ".pyd", ".wasm",
            ".pdb", ".obj", ".o", ".a", ".lib", ".class", ".jar"
        }

        try:
            for root, dirs, fnames in os.walk(base):
                # Filter out heavy/build directories in place
                dirs[:] = [d for d in dirs if d.lower() not in excluded_dirs and not d.startswith(".")]
                for fname in sorted(fnames):
                    f_path = Path(root) / fname
                    ext = f_path.suffix.lower()
                    if ext in binary_exts:
                        continue
                    try:
                        rel = str(f_path.relative_to(base)).replace("\\", "/")
                        stat = f_path.stat()
                        # Skip huge files (> 1.5MB) to prevent browser editor crashes
                        if stat.st_size > 1536 * 1024:
                            continue
                        files.append({
                            "name": fname,
                            "relative_path": rel,
                            "size": stat.st_size,
                            "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                            "ext": ext,
                        })
                        if len(files) >= max_files:
                            break
                    except Exception:
                        pass
                if len(files) >= max_files:
                    break
        except Exception as exc:
            pass

        self._send_json({"success": True, "path": str(base), "files": files, "count": len(files)})

    def _handle_project_file_content(self, query_params: Dict[str, List[str]]) -> None:
        p_str = query_params.get("path", [""])[0].strip()
        f_str = query_params.get("file", [""])[0].strip()
        if not p_str or not f_str:
            self._send_json({"error": "Path and file parameters required"}, status=400)
            return

        base = Path(p_str).resolve()
        target = (base / f_str).resolve()
        if not target.is_relative_to(base) or not target.is_file():
            self._send_json({"error": "File not found or access denied"}, status=404)
            return

        # Safeguard: prevent loading files > 1.5 MB into the in-app textarea
        try:
            stat = target.stat()
            if stat.st_size > 1536 * 1024:
                size_mb = round(stat.st_size / (1024 * 1024), 2)
                self._send_json({
                    "error": f"File is too large ({size_mb} MB) for in-app editor. Maximum supported size is 1.5 MB."
                }, status=400)
                return

            # Check if file is binary by inspecting first 4KB for null bytes
            with open(target, "rb") as bf:
                chunk = bf.read(4096)
                if b"\x00" in chunk:
                    self._send_json({
                        "error": "Binary file detected. This file cannot be opened in the text editor."
                    }, status=400)
                    return

            content = target.read_text(encoding="utf-8", errors="replace")
            self._send_json({"success": True, "file": f_str, "content": content})
        except Exception as exc:
            self._send_json({"error": f"Failed to read file: {exc}"}, status=500)

    def _handle_project_file_save(self, body: Dict[str, Any]) -> None:
        p_str = body.get("path", "").strip()
        f_str = body.get("file", "").strip()
        content = body.get("content", "")
        if not p_str or not f_str:
            self._send_json({"error": "Path and file are required."}, status=400)
            return

        base = Path(p_str).resolve()
        target = (base / f_str).resolve()
        if not target.is_relative_to(base):
            self._send_json({"error": "Path traversal detected; access denied."}, status=403)
            return

        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            self._send_json({"success": True, "file": f_str, "size": len(content)})
        except Exception as exc:
            self._send_json({"error": f"Failed to save file: {exc}"}, status=500)

    def _handle_team_roster(self) -> None:
        try:
            from research.multi_agent import TeamRoleModelRegistry
        except ImportError:
            from multi_agent import TeamRoleModelRegistry
        reg = TeamRoleModelRegistry()
        reg.load_saved_config()
        local_models, _ = get_all_installed_local_models()
        model_names = [m["name"] for m in local_models]
        roster = []
        for role, title in reg.ROLE_TITLES.items():
            curr_model = reg.role_models.get(role, "")
            prefs = reg.ROLE_PREFERENCES.get(role, [])
            icon = reg.ROLE_ICONS.get(role, "")
            desc = {
                "project_manager": "Analyzes goals, creates WBS sprint plans, and coordinates team deliverables.",
                "senior_developer": "Designs architecture, core logic, 3D/canvas math, algorithms, and code synthesis.",
                "specialist_developer": "Synthesizes UI components, canvas textures, shaders, and Web Audio synthesizers.",
                "qa_engineer": "Audits generated code for syntax errors, control mapping, safety, and playability.",
            }.get(role, "")
            roster.append({
                "role": role,
                "title": title,
                "icon": icon,
                "current_model": curr_model,
                "preferred_models": prefs,
                "description": desc,
            })
        self._send_json({
            "success": True,
            "roster": roster,
            "available_models": model_names,
        })

    def _handle_team_assign(self, body: Dict[str, Any]) -> None:
        role = body.get("role", "").strip()
        model = body.get("model", "").strip()
        if not role or not model:
            self._send_json({"error": "Role and model name required."}, status=400)
            return
        try:
            from research.multi_agent import TeamRoleModelRegistry
        except ImportError:
            from multi_agent import TeamRoleModelRegistry
        reg = TeamRoleModelRegistry()
        ok, msg = reg.set_role_model(role, model, persist=True)
        self._send_json({"success": ok, "message": msg, "role": role, "model": model})

    def _handle_team_run(self, body: Dict[str, Any]) -> None:
        task = body.get("task", "").strip()
        project_dir_str = body.get("project_dir", "").strip()
        if not task:
            self._send_json({"error": "Task description is required for AI Team sprint."}, status=400)
            return

        ensure_ollama_server()

        p_dir = Path(project_dir_str).resolve() if project_dir_str and Path(project_dir_str).is_dir() else None

        try:
            from research.multi_agent import MultiAgentTeam
        except ImportError:
            from multi_agent import MultiAgentTeam

        messages_log = []
        def _team_output(msg: str):
            messages_log.append(str(msg))

        team = MultiAgentTeam(output_fn=_team_output)
        res = team.run_collaborative_workflow(task_prompt=task, active_project_dir=p_dir)

        # Structure messages into FIPA-ACL events
        fipa_events = []
        for m in getattr(team, "conversation_log", []):
            fipa_events.append({
                "id": m.msg_id,
                "sender": m.sender_role,
                "sender_model": m.sender_model,
                "recipient": m.recipient_role,
                "performative": m.performative,
                "content": m.content,
                "timestamp": m.timestamp,
            })

        self._send_json({
            "success": not bool(res.get("error")),
            "error": res.get("error"),
            "task": task,
            "plan": res.get("plan", ""),
            "specialist_assets": res.get("specialist_assets", ""),
            "code_updates": res.get("code_updates", {}),
            "qa_verdict": res.get("qa_verdict", ""),
            "messages": fipa_events,
            "raw_log": "\n".join(messages_log),
        })

    def _handle_skills_list(self) -> None:
        self._send_json({"success": True, "skills": load_plugins_list()})

    def _handle_skill_toggle(self, body: Dict[str, Any]) -> None:
        s_id = body.get("skill", "").strip()
        val = bool(body.get("enabled", True))
        if s_id == "internet":
            set_internet_enabled(val)
        elif s_id == "factcheck":
            set_factcheck_enabled(val)
        for s in SKILLS_CATALOG:
            if s["id"] == s_id:
                s["enabled"] = val
        # Update custom plugins config if applicable
        p_cfg = get_plugins_config_path()
        if p_cfg.is_file():
            try:
                plist = json.loads(p_cfg.read_text(encoding="utf-8"))
                for p in plist:
                    if p.get("id") == s_id:
                        p["enabled"] = val
                p_cfg.write_text(json.dumps(plist, indent=2), encoding="utf-8")
            except Exception:
                pass
        self._send_json({"success": True, "skill": s_id, "enabled": val})

    def _handle_pull_model(self, body: Dict[str, Any]) -> None:
        """Stream Ollama model download progress back to frontend via SSE."""
        model_name = body.get("model", "").strip()
        if not model_name:
            self._send_json({"error": "Model name required"}, status=400)
            return

        custom_path = body.get("path", "").strip()
        if custom_path:
            set_model_storage_path(custom_path)

        ensure_ollama_server()

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        payload = json.dumps({"name": model_name, "stream": True}).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:11434/api/pull",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                for line in resp:
                    if line:
                        chunk = line.decode("utf-8").strip()
                        self.wfile.write(f"data: {chunk}\n\n".encode("utf-8"))
                        self.wfile.flush()
        except Exception as exc:
            err_data = json.dumps({"status": "error", "error": str(exc)})
            self.wfile.write(f"data: {err_data}\n\n".encode("utf-8"))
            self.wfile.flush()

    def _handle_select_folder(self) -> None:
        """Open native Windows folder picker dialog and return selected path."""
        folder = open_native_folder_dialog()
        if folder:
            self._send_json({"success": True, "path": folder, "name": Path(folder).name})
        else:
            self._send_json({"success": False, "cancelled": True})

    def _handle_system_preflight(self) -> None:
        """Provide detailed preflight diagnostics and auto-boot Ollama if offline."""
        data = get_system_preflight()
        self._send_json(data)

    def _handle_chat(self, body: Dict[str, Any]) -> None:
        """Execute chat completion, optionally ground in project files & fact-check."""
        raw_prompt = body.get("prompt", "").strip()
        model = body.get("model") or get_current_model()
        history = body.get("history", [])
        project_path = body.get("project_path", "").strip()
        is_team_mode = bool(body.get("is_team_mode", False))

        if not raw_prompt and not body.get("attachments"):
            self._send_json({"error": "Prompt or attachment required"}, status=400)
            return
        if not raw_prompt:
            raw_prompt = "Please analyze and summarize the attached document(s)."
        # Inject attached documents (docs, txt, pdf, excel, md) into prompt context
        attachments = body.get("attachments", [])
        if attachments and isinstance(attachments, list):
            att_blocks = []
            for att in attachments:
                a_name = att.get("name") or att.get("filename") or "document"
                a_type = att.get("type", "file")
                a_content = (att.get("content") or "").strip()
                if a_content:
                    att_blocks.append(
                        f"[ATTACHED DOCUMENT: {a_name} (Format: {a_type})]\n"
                        f"--- Content Begin ---\n"
                        f"{a_content}\n"
                        f"--- Content End ---"
                    )
            if att_blocks:
                raw_prompt = (
                    f"The user has attached the following document(s) for your review:\n\n"
                    f"{chr(10).join(att_blocks)}\n\n"
                    f"User Instruction / Query:\n{raw_prompt}"
                )


        # Handle collaborative AI Team mode inside Chat
        if is_team_mode:
            if not project_path or not Path(project_path).is_dir():
                self._send_json({
                    "success": False,
                    "error": "AI Team Mode requires an active project directory. Please select or browse for a project folder first."
                }, status=400)
                return

            ensure_ollama_server()

            p_dir = Path(project_path).resolve()
            # 1. Read existing codebase files first to understand structure before editing
            proj_context = get_project_codebase_context(p_dir, max_chars=14000)

            team_task = (
                f"Objective: {raw_prompt}\n\n"
                f"Project Workspace Directory: {p_dir}\n"
                f"Existing Codebase Content:\n{proj_context if proj_context else '[Workspace is currently empty - scaffold new project]'}\n\n"
                f"Team Instructions: Carefully review the existing files and architectural layout above. "
                f"Preserve existing architecture, dependencies, and code structure. "
                f"Produce needed component updates, new files, and tests."
            )

            try:
                from research.multi_agent import MultiAgentTeam
            except ImportError:
                from multi_agent import MultiAgentTeam

            team = MultiAgentTeam(model_name=model)
            res = team.run_collaborative_workflow(team_task, active_project_dir=p_dir)

            # Auto-save any code updates into the project directory
            saved_files = []
            for fname, code in (res.get("code_updates") or {}).items():
                try:
                    fpath = p_dir / fname
                    fpath.parent.mkdir(parents=True, exist_ok=True)
                    fpath.write_text(code, encoding="utf-8")
                    saved_files.append(fname)
                except Exception:
                    pass

            fipa_events = []
            for m in getattr(team, "conversation_log", []):
                fipa_events.append({
                    "sender": m.sender_role,
                    "recipient": m.recipient_role,
                    "performative": m.performative,
                    "content": m.content,
                    "timestamp": m.timestamp,
                })

            summary_lines = [
                f"### 🤝 Autonomous AI Team Sprint Completed",
                f"**Objective:** {raw_prompt}",
                f"",
                f"**Project Workspace:** `{p_dir}`",
                f"",
                f"#### 📋 Work Breakdown (PM Plan):",
                f"```text\n{res.get('plan', 'Sprint plan finalized.')}\n```",
                f"",
                f"#### 🛠️ Files Created / Updated in Project ({len(saved_files)}):",
                "\n".join([f"- `{f}`" for f in saved_files]) if saved_files else "- No code files written directly.",
                f"",
                f"#### 🛡️ QA Verification Verdict:",
                f"> {res.get('qa_verdict', 'QA Audit complete.')}",
            ]

            team_reply = "\n".join(summary_lines)

            self._send_json({
                "success": True,
                "is_team": True,
                "response": team_reply,
                "plan": res.get("plan", ""),
                "specialist_assets": res.get("specialist_assets", ""),
                "code_updates": res.get("code_updates", {}),
                "qa_verdict": res.get("qa_verdict", ""),
                "saved_files": saved_files,
                "messages": fipa_events,
            })
            return

        # Check if requested model or prompt is for image generation
        is_img_model = False
        cfg = load_cloud_config()
        for cm in cfg.get("configured_models", []):
            if cm.get("model_name") == model and cm.get("model_type") == "image":
                is_img_model = True
                break
        if any(tok in model.lower() for tok in ("imagen", "dall-e", "image")):
            is_img_model = True

        prompt_is_image = raw_prompt.strip().startswith(("/image ", "/img "))
        if is_img_model or prompt_is_image:
            clean_prompt = re.sub(r"^/(image|img)\s+", "", raw_prompt.strip())
            ok_img, data_url_or_err, fpath, fname = generate_image_cloud(clean_prompt, model=model)
            if ok_img:
                self._send_json({
                    "success": True,
                    "is_image": True,
                    "image_url": data_url_or_err,
                    "image_path": fpath,
                    "filename": fname,
                    "prompt": clean_prompt,
                    "model": model,
                    "response": f"Generated image for: \"{clean_prompt}\"",
                })
                return
            else:
                self._send_json({"success": False, "error": data_url_or_err}, status=500)
                return

        # Prepare prompt with project context if an active project is selected
        prompt = raw_prompt
        if project_path and Path(project_path).is_dir():
            proj_context = get_project_codebase_context(Path(project_path))
            if proj_context:
                prompt = (
                    f"You are working in the active project directory: {project_path}\n"
                    f"Relevant Project Files:\n{proj_context}\n\n"
                    f"User Request:\n{raw_prompt}"
                )

        # Real-time Web Grounding: Pre-inject authoritative live internet references
        grounding_citations = []
        if is_internet_enabled():
            has_ground, ground_ctx, cites = get_live_grounding_context(raw_prompt)
            if has_ground and ground_ctx:
                prompt = f"{ground_ctx}\n\nUser Question:\n{prompt}"
                grounding_citations = cites

        reply_text = ""
        think_text = ""
        error_msg = ""

        # 1. 3rd-Party Cloud AI Generation
        if is_cloud_model(model):
            ok_cloud, res_cloud = query_cloud_ai(
                prompt=prompt,
                model=model,
                temperature=float(body.get("temperature", 0.3)),
            )
            if ok_cloud:
                reply_text = res_cloud
            else:
                error_msg = res_cloud
        else:
            # 2. Local Ollama Generation
            server_ok = ensure_ollama_server(timeout=8.0)
            if not server_ok:
                self._send_json({
                    "success": False,
                    "error": (
                        "Local AI service (Ollama) is not running on 127.0.0.1:11434 and could not be started automatically. "
                        "Please ensure Ollama is installed from https://ollama.com, or switch to a Cloud AI model in the Cloud AI tab."
                    )
                }, status=503)
                return

            # Graceful local model resolution: verify model is installed or fallback to active installed model
            local_models, _ = get_all_installed_local_models()
            installed_names = [m["name"] for m in local_models]
            if model not in installed_names:
                # Prefer fast, responsive models over heavy 7B models on first run
                preferred = ["llama3.2:3b", "llama3.2:1b", "qwen2.5-coder:1.5b", "qwen3.5:4b", "gemma4:e2b", "qwen2.5-coder:7b"]
                picked = None
                for pref in preferred:
                    if pref in installed_names:
                        picked = pref
                        break
                model = picked or (installed_names[0] if installed_names else "llama3.2:3b")
                set_current_model(model)

            ctx_size = 4096 if not project_path else 8192
            ollama_url = "http://127.0.0.1:11434/api/generate"
            ollama_payload = {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": float(body.get("temperature", 0.3)),
                    "num_ctx": ctx_size,
                },
            }
            req_data = json.dumps(ollama_payload).encode("utf-8")

            # Execute with automatic retry on transient startup warm-up
            for attempt in range(2):
                req = urllib.request.Request(
                    ollama_url,
                    data=req_data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=150) as resp:
                        d = json.loads(resp.read().decode("utf-8"))
                        reply_text = d.get("response", "")
                        error_msg = ""
                        break
                except urllib.error.HTTPError as exc:
                    err_detail = ""
                    try:
                        raw_b = exc.read().decode("utf-8", errors="replace")
                        err_json = json.loads(raw_b)
                        err_detail = err_json.get("error", "")
                    except Exception:
                        pass
                    if not err_detail:
                        err_detail = exc.reason if hasattr(exc, "reason") and exc.reason else f"HTTP {exc.code}"
                    error_msg = f"Local model execution error ({model}): {err_detail}"
                    break
                except (TimeoutError, socket.timeout):
                    error_msg = (
                        f"Local model response timed out ({model}). "
                        f"The model took longer than 150 seconds to respond. "
                        f"If the model was cold-starting into RAM or your hardware is busy, "
                        f"try asking again or switch to a faster lightweight model (e.g. llama3.2:1b or llama3.2:3b)."
                    )
                    break
                except urllib.error.URLError as exc:
                    reason_s = str(exc.reason).strip() if getattr(exc, "reason", None) else ""
                    if not reason_s or "timed out" in reason_s.lower():
                        error_msg = (
                            f"Local model connection timed out ({model}). "
                            f"Ollama took too long to respond. Try asking again or switch to a faster model."
                        )
                    else:
                        error_msg = f"Local model connection error ({model}): {reason_s}"
                    if attempt == 0:
                        time.sleep(1.0)
                        continue
                    break
                except Exception as exc:
                    err_s = str(exc).strip() or exc.__class__.__name__
                    if "timed out" in err_s.lower() or "timeout" in err_s.lower():
                        error_msg = (
                            f"Local model response timed out ({model}). "
                            f"Ollama took too long to load or compute. Try switching to llama3.2:1b or llama3.2:3b."
                        )
                    else:
                        error_msg = f"Local model execution error ({model}): {err_s}"
                    if attempt == 0:
                        time.sleep(1.0)
                        continue
                    break

        if error_msg and not reply_text:
            self._send_json({"success": False, "error": error_msg}, status=500)
            return

        # Extract <think> reasoning trace if present
        think_match = re.search(r"<think>([\s\S]*?)</think>", reply_text)
        if think_match:
            think_text = think_match.group(1).strip()
            reply_text = re.sub(r"<think>[\s\S]*?</think>", "", reply_text).strip()

        # 3. Grounding & Fact-Checking Hook
        factcheck_claims = []
        factcheck_report = ""
        factcheck_score = 1.0
        if is_internet_enabled() and is_factcheck_enabled():
            try:
                claims = verify_text_claims(reply_text, max_claims=3)
                if claims:
                    factcheck_claims = [
                        {
                            "statement": c.statement,
                            "verdict": c.verdict,
                            "confidence": c.confidence,
                            "citations": c.citations,
                            "notes": c.notes,
                        }
                        for c in claims
                    ]
                    factcheck_report = format_factcheck_report(claims)
                    verified_count = sum(1 for c in claims if c.verdict == "VERIFIED")
                    factcheck_score = round(verified_count / len(claims), 2)
            except Exception:
                pass

        self._send_json({
            "success": True,
            "response": reply_text,
            "thinking": think_text,
            "model": model,
            "project_path": project_path,
            "grounding": grounding_citations,
            "factcheck": {
                "claims": factcheck_claims,
                "report": factcheck_report,
                "score": factcheck_score,
                "fidelity": int(factcheck_score * 100),
            },
        })

    def _handle_antigravity_run(self, body: Dict[str, Any]) -> None:
        """Run Antigravity continuous agent task supervisor in background with AI Team support."""
        task_prompt = body.get("task", "").strip()
        project_path = body.get("project_path", "").strip()
        use_team = bool(body.get("use_team", True))
        if not task_prompt:
            self._send_json({"error": "Task prompt required"}, status=400)
            return

        ensure_ollama_server()

        p_dir = Path(project_path).resolve() if project_path and Path(project_path).is_dir() else None

        def _bg_run():
            if use_team:
                try:
                    from research.multi_agent import MultiAgentTeam
                except ImportError:
                    from multi_agent import MultiAgentTeam
                team = MultiAgentTeam()
                team.run_collaborative_workflow(
                    f"[Antigravity Autonomous Sprint] {task_prompt}",
                    active_project_dir=p_dir,
                )
            else:
                try:
                    from research.antigravity_driver import run_antigravity_continuous_agent
                except ImportError:
                    from antigravity_driver import run_antigravity_continuous_agent
                run_antigravity_continuous_agent(task_prompt, max_turns=6, open_browser=True)

        t = threading.Thread(target=_bg_run, daemon=True)
        t.start()
        self._send_json({
            "success": True,
            "message": f"Autonomous agent supervisor started with AI Team for: '{task_prompt}'.",
            "project_dir": str(p_dir) if p_dir else "None",
        })


def run_bridge_server():
    try:
        server = ThreadingHTTPServer((HOST, PORT), PAIBridgeHandler)
    except Exception as e:
        log_path = Path.home() / ".pai" / "bridge_error.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(f"Server init error: {e}\n", encoding="utf-8")
        return

    print(f"================================================================================")
    print(f"PAI DESKTOP BRIDGE SERVER ACTIVE ON http://{HOST}:{PORT}")
    print(f"Strict loopback binding verified (Threat T21 Compliant).")
    print(f"================================================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down bridge server...")
        server.server_close()
    except Exception as e:
        log_path = Path.home() / ".pai" / "bridge_error.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(f"serve_forever error: {e}\n", encoding="utf-8")
        server.server_close()


if __name__ == "__main__":
    run_bridge_server()
