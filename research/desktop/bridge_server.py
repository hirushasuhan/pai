"""PAI Desktop Application Local Loopback API Bridge Server.

Binds strictly to 127.0.0.1:8765 (Threat T21 Compliant) and exposes
high-speed endpoints for the Rust/Tauri desktop UI:
  - Streaming Chat & Reasoning (<think> blocks)
  - 3rd-Party Cloud AI Configuration & Masked Status
  - Local AI Model Downloader & Manager (Ollama /api/pull, /api/tags)
  - Live Fact-Checking & Web Grounding Engine
  - Antigravity Autonomous Agent Supervisor
  - Live Weather, Web Search, and System Health
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

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
        elif path == "/api/models":
            self._handle_get_models()
        # 3. Cloud config & key status
        elif path == "/api/cloud/config":
            self._handle_get_cloud_config()
        # 4. Live weather
        elif path == "/api/weather":
            city = query_params.get("city", [""])[0]
            ok, msg, raw = fetch_live_weather(city)
            self._send_json({"success": ok, "message": msg, "data": raw})
        # 5. Live web search
        elif path == "/api/search":
            q = query_params.get("q", [""])[0]
            ok, msg, res = search_web(q)
            self._send_json({"success": ok, "message": msg, "results": res})
        # 6. Doctor / Hardware telemetry
        elif path == "/api/doctor":
            self._handle_doctor()
        else:
            self._send_json({"error": f"Unknown endpoint: {path}"}, status=404)

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        body = self._read_json_body()

        # 1. Chat Completion & Grounding
        if path == "/api/chat":
            self._handle_chat(body)
        # 2. Local Model Pull (Download)
        elif path == "/api/models/pull":
            self._handle_pull_model(body)
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
        # 7. Save Cloud API Key (Legacy)
        elif path == "/api/cloud/set_key":
            prov = body.get("provider", "").strip().lower()
            key = body.get("key", "").strip()
            if prov and key:
                set_provider_key(prov, key)
                self._send_json({"success": True, "provider": prov, "message": f"Saved API key for {prov.title()}"})
            else:
                self._send_json({"success": False, "error": "Provider and key required"}, status=400)
        # 8. Set Custom Endpoint
        elif path == "/api/cloud/set_endpoint":
            url = body.get("url", "").strip()
            set_custom_endpoint(url)
            self._send_json({"success": True, "url": url})
        # 9. Toggle Internet / Factcheck
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
        # 7. Fact-Check Text
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
        # 8. Antigravity Supervisor Run
        elif path == "/api/antigravity/run":
            self._handle_antigravity_run(body)
        else:
            self._send_json({"error": f"Unknown endpoint: {path}"}, status=404)

    def _handle_status(self) -> None:
        self._send_json({
            "version": "1.1.0-rc4",
            "active_model": get_current_model(),
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
        # Hardware inspection
        ram_info = {"total_gb": 16.0, "available_gb": 8.0}
        try:
            import psutil
            vm = psutil.virtual_memory()
            ram_info["total_gb"] = round(vm.total / (1024 ** 3), 1)
            ram_info["available_gb"] = round(vm.available / (1024 ** 3), 1)
        except Exception:
            pass

        self._send_json({
            "platform": sys.platform,
            "python_version": sys.version.split()[0],
            "ram": ram_info,
            "internet_enabled": is_internet_enabled(),
            "factcheck_enabled": is_factcheck_enabled(),
            "active_model": get_current_model(),
        })

    def _handle_pull_model(self, body: Dict[str, Any]) -> None:
        """Stream Ollama model download progress back to frontend via SSE."""
        model_name = body.get("model", "").strip()
        if not model_name:
            self._send_json({"error": "Model name required"}, status=400)
            return

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

    def _handle_chat(self, body: Dict[str, Any]) -> None:
        """Execute chat completion, optionally fact-check, and return response."""
        prompt = body.get("prompt", "").strip()
        model = body.get("model") or get_current_model()
        history = body.get("history", [])

        if not prompt:
            self._send_json({"error": "Prompt cannot be empty"}, status=400)
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

        prompt_is_image = prompt.strip().startswith(("/image ", "/img "))
        if is_img_model or prompt_is_image:
            clean_prompt = re.sub(r"^/(image|img)\s+", "", prompt.strip())
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
            try:
                from core_service import OllamaServiceManager
                OllamaServiceManager.get_instance().ensure_service_running()
            except Exception:
                pass

            ollama_url = "http://127.0.0.1:11434/api/generate"
            ollama_payload = {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": float(body.get("temperature", 0.3)),
                    "num_ctx": 8192,
                },
            }
            req = urllib.request.Request(
                ollama_url,
                data=json.dumps(ollama_payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    d = json.loads(resp.read().decode("utf-8"))
                    reply_text = d.get("response", "")
            except Exception as exc:
                error_msg = f"Local model execution error: {exc}"

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
            except Exception:
                pass

        self._send_json({
            "success": True,
            "response": reply_text,
            "thinking": think_text,
            "model": model,
            "factcheck": {
                "claims": factcheck_claims,
                "report": factcheck_report,
            },
        })

    def _handle_antigravity_run(self, body: Dict[str, Any]) -> None:
        """Run Antigravity continuous agent task supervisor in background."""
        task_prompt = body.get("task", "").strip()
        if not task_prompt:
            self._send_json({"error": "Task prompt required"}, status=400)
            return

        try:
            from research.antigravity_driver import run_antigravity_continuous_agent
        except ImportError:
            from antigravity_driver import run_antigravity_continuous_agent

        def _bg_run():
            run_antigravity_continuous_agent(task_prompt, max_turns=6, open_browser=True)

        t = threading.Thread(target=_bg_run, daemon=True)
        t.start()
        self._send_json({
            "success": True,
            "message": f"Autonomous agent supervisor started for: '{task_prompt}'.",
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
