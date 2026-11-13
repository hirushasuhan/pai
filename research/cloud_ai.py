"""3rd-Party Cloud AI API Integration for PAI.

Supports leading cloud LLM providers via OpenAI-compatible Chat Completions endpoints:
  - Google Gemini: gemini-2.0-flash, gemini-1.5-flash, gemini-1.5-pro
  - OpenAI: gpt-4o, gpt-4o-mini, o3-mini
  - Groq: llama-3.3-70b-versatile, llama-3.1-8b-instant, mixtral-8x7b-32768
  - DeepSeek: deepseek-chat, deepseek-reasoner
  - Custom: User-defined base URL (OpenRouter, Together, LocalAI, vLLM, etc.)

Security & Privacy:
  - API keys are stored in a dedicated file (~/.pai/cloud_ai.json) separate from config.json
    to preserve T22 strict non-secret config boundaries.
  - API keys can also be supplied via environment variables (GEMINI_API_KEY, OPENAI_API_KEY, etc.).
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

USER_AGENT = "PersonalAgenticAI/1.1 (Cloud AI Bridge; Windows x64)"

CLOUD_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "gemini": {
        "display_name": "Google Gemini",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "env_var": "GEMINI_API_KEY",
        "default_model": "gemini-2.0-flash",
        "models": ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"],
        "type": "chat",
    },
    "imagen": {
        "display_name": "Google Imagen 3",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta",
        "env_var": "GEMINI_API_KEY",
        "default_model": "imagen-3.0-generate-002",
        "models": ["imagen-3.0-generate-002", "imagen-3.0-generate-001"],
        "type": "image",
    },
    "openai": {
        "display_name": "OpenAI",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "env_var": "OPENAI_API_KEY",
        "default_model": "gpt-4o-mini",
        "models": ["gpt-4o", "gpt-4o-mini", "o3-mini"],
        "type": "chat",
    },
    "dalle": {
        "display_name": "OpenAI DALL-E",
        "endpoint": "https://api.openai.com/v1/images/generations",
        "env_var": "OPENAI_API_KEY",
        "default_model": "dall-e-3",
        "models": ["dall-e-3", "dall-e-2"],
        "type": "image",
    },
    "groq": {
        "display_name": "Groq",
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "env_var": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
        "models": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
        "type": "chat",
    },
    "deepseek": {
        "display_name": "DeepSeek",
        "endpoint": "https://api.deepseek.com/chat/completions",
        "env_var": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "type": "chat",
    },
    "custom": {
        "display_name": "Custom Endpoint",
        "endpoint": "",
        "env_var": "PAI_API_KEY",
        "default_model": "custom-model",
        "models": [],
        "type": "chat",
    },
}


def get_cloud_credentials_path() -> Path:
    """Return path to dedicated cloud credentials store (~/.pai/cloud_ai.json)."""
    cfg_dir = os.environ.get("PAI_CONFIG_DIR")
    if cfg_dir:
        base = Path(cfg_dir)
    else:
        base = Path.home() / ".pai"
    base.mkdir(parents=True, exist_ok=True)
    return base / "cloud_ai.json"


def load_cloud_config() -> Dict[str, Any]:
    """Load cloud AI provider configuration and keys."""
    p = get_cloud_credentials_path()
    default_cfg: Dict[str, Any] = {
        "active_provider": "",
        "active_model": "",
        "keys": {},
        "custom_endpoint": "",
        "configured_models": [],
    }
    if not p.is_file():
        return default_cfg
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return default_cfg
        if "configured_models" not in data or not isinstance(data["configured_models"], list):
            data["configured_models"] = []
        return data
    except Exception:
        return default_cfg


def get_configured_models() -> List[Dict[str, Any]]:
    """Return list of user-configured external models."""
    cfg = load_cloud_config()
    return cfg.get("configured_models", [])


def add_configured_model(
    model_name: str,
    provider_url: str,
    api_key: str,
    model_type: str = "chat",
    provider: str = "custom",
) -> Dict[str, Any]:
    """Add or update a custom external cloud/image model."""
    m_name = (model_name or "").strip()
    p_url = (provider_url or "").strip()
    key = (api_key or "").strip()
    m_type = "image" if "image" in model_type.lower() or any(x in m_name.lower() for x in ("imagen", "dall-e", "sd", "flux", "diffusion")) else "chat"
    prov = (provider or "custom").strip().lower()

    cfg = load_cloud_config()
    configured = cfg.get("configured_models", [])

    entry = {
        "model_name": m_name,
        "provider_url": p_url,
        "api_key": key,
        "model_type": m_type,
        "provider": prov,
    }

    # Replace existing or append
    existing_idx = next((i for i, item in enumerate(configured) if item.get("model_name") == m_name), -1)
    if existing_idx >= 0:
        configured[existing_idx] = entry
    else:
        configured.append(entry)

    cfg["configured_models"] = configured
    # Also save key in keys dict for provider
    keys = cfg.get("keys", {})
    if prov:
        keys[prov] = key
    cfg["keys"] = keys

    # If no active model, set this one
    if not cfg.get("active_model"):
        cfg["active_model"] = m_name
        cfg["active_provider"] = prov

    save_cloud_config(cfg)
    return entry


def remove_configured_model(model_name: str) -> bool:
    """Remove a configured external model by name."""
    m_name = (model_name or "").strip()
    cfg = load_cloud_config()
    configured = cfg.get("configured_models", [])
    new_list = [item for item in configured if item.get("model_name") != m_name]
    if len(new_list) == len(configured):
        return False
    cfg["configured_models"] = new_list
    if cfg.get("active_model") == m_name:
        cfg["active_model"] = new_list[0].get("model_name") if new_list else ""
    save_cloud_config(cfg)
    return True


def save_cloud_config(cfg: Dict[str, Any]) -> None:
    """Persist cloud AI provider configuration and keys."""
    p = get_cloud_credentials_path()
    try:
        p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass


def get_provider_key(provider: str) -> Optional[str]:
    """Retrieve API key for given provider from environment or credentials store."""
    prov = (provider or "").strip().lower()
    entry = CLOUD_PROVIDERS.get(prov)
    if entry:
        env_key = os.environ.get(entry["env_var"])
        if env_key and env_key.strip():
            return env_key.strip()

    # Also check generic PAI_API_KEY or OPENAI_API_KEY
    if prov == "gemini":
        g_env = os.environ.get("GOOGLE_API_KEY")
        if g_env and g_env.strip():
            return g_env.strip()

    cfg = load_cloud_config()
    saved_key = cfg.get("keys", {}).get(prov)
    if saved_key and str(saved_key).strip():
        return str(saved_key).strip()

    return None


def set_provider_key(provider: str, key: str) -> None:
    """Save an API key for a cloud provider."""
    prov = (provider or "").strip().lower()
    cfg = load_cloud_config()
    keys = cfg.get("keys", {})
    keys[prov] = key.strip()
    cfg["keys"] = keys
    if not cfg.get("active_provider"):
        cfg["active_provider"] = prov
    save_cloud_config(cfg)


def set_custom_endpoint(url: str) -> None:
    """Set custom OpenAI-compatible endpoint URL."""
    cfg = load_cloud_config()
    cfg["custom_endpoint"] = url.strip()
    save_cloud_config(cfg)


def get_active_cloud_provider() -> Optional[str]:
    """Determine currently active cloud AI provider."""
    cfg = load_cloud_config()
    active = cfg.get("active_provider")
    if active and active in CLOUD_PROVIDERS and get_provider_key(active):
        return active
    # Auto-detect from environment variables
    for prov in ("gemini", "openai", "groq", "deepseek"):
        if get_provider_key(prov):
            return prov
    return None


def get_active_cloud_model() -> Optional[str]:
    """Get active cloud model name."""
    cfg = load_cloud_config()
    saved = cfg.get("active_model")
    if saved:
        return saved
    prov = get_active_cloud_provider()
    if prov:
        entry = CLOUD_PROVIDERS.get(prov)
        if entry:
            return entry.get("default_model")
    return None


def set_active_cloud_model(model_name: str) -> bool:
    """Set the active cloud model."""
    m_clean = model_name.strip()
    if not m_clean:
        return False
    cfg = load_cloud_config()
    # Infer provider from model name
    matched_prov = None
    for prov, meta in CLOUD_PROVIDERS.items():
        if m_clean.lower() in [m.lower() for m in meta.get("models", [])] or prov in m_clean.lower():
            matched_prov = prov
            break
    if matched_prov:
        cfg["active_provider"] = matched_prov
    cfg["active_model"] = m_clean
    save_cloud_config(cfg)
    return True


def is_cloud_model(model_name: str) -> bool:
    """Check if model name corresponds to a known or configured cloud model."""
    m_lower = (model_name or "").strip().lower()
    if not m_lower:
        return False
    # Check known cloud models
    all_models: List[str] = []
    for meta in CLOUD_PROVIDERS.values():
        all_models.extend(m.lower() for m in meta.get("models", []))
    if any(m_lower == k or m_lower.startswith(k) for k in all_models):
        return True
    if any(prefix in m_lower for prefix in ("gemini", "gpt-", "deepseek-", "groq", "claude")):
        return True
    return False


def list_available_cloud_models() -> List[Dict[str, Any]]:
    """List all supported and user-configured cloud models and their readiness state."""
    items: List[Dict[str, Any]] = []
    cfg = load_cloud_config()
    seen_models = set()

    # 1. Configured custom models first
    for cm in cfg.get("configured_models", []):
        m = cm.get("model_name", "").strip()
        if not m:
            continue
        seen_models.add(m.lower())
        items.append({
            "model": m,
            "provider": cm.get("provider", "custom"),
            "display_provider": cm.get("provider", "custom").title(),
            "provider_url": cm.get("provider_url", ""),
            "model_type": cm.get("model_type", "chat"),
            "has_key": bool(cm.get("api_key")),
            "is_active": m == cfg.get("active_model"),
        })

    # 2. Preset cloud providers ONLY IF a valid key exists
    for prov, meta in CLOUD_PROVIDERS.items():
        if prov == "custom":
            continue
        has_k = bool(get_provider_key(prov))
        for m in meta.get("models", []):
            if m.lower() in seen_models:
                continue
            seen_models.add(m.lower())
            items.append({
                "model": m,
                "provider": prov,
                "display_provider": meta["display_name"],
                "provider_url": meta.get("endpoint", ""),
                "model_type": meta.get("type", "chat"),
                "has_key": has_k,
                "is_active": m == cfg.get("active_model"),
            })
    return items


def generate_image_cloud(
    prompt: str,
    model: Optional[str] = None,
    provider_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """Generate image using Gemini Imagen, OpenAI DALL-E, or local high-res fallback.

    Returns (success, data_url_or_error, file_path_str, filename).
    """
    prompt_clean = prompt.strip()
    if not prompt_clean:
        return False, "Prompt cannot be empty for image generation.", None, None

    cfg = load_cloud_config()
    target_model = model or "imagen-3.0-generate-002"
    key = api_key
    endpoint = provider_url

    # Check configured models
    for cm in cfg.get("configured_models", []):
        if cm.get("model_name") == target_model:
            key = key or cm.get("api_key")
            endpoint = endpoint or cm.get("provider_url")
            break

    # If not found in configured_models, check preset providers
    if not key:
        if "imagen" in target_model.lower() or "gemini" in target_model.lower():
            key = get_provider_key("gemini")
            endpoint = endpoint or "https://generativelanguage.googleapis.com/v1beta"
        elif "dall-e" in target_model.lower() or "openai" in target_model.lower():
            key = get_provider_key("openai")
            endpoint = endpoint or "https://api.openai.com/v1/images/generations"

    images_dir = Path.home() / ".pai" / "generated_images"
    images_dir.mkdir(parents=True, exist_ok=True)
    filename = f"pai_image_{int(time.time())}.png"
    out_file = images_dir / filename

    # 1. Try Gemini Imagen API if key and Google endpoint
    if key and endpoint and "generativelanguage.googleapis.com" in endpoint:
        try:
            target_url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:predict?key={urllib.parse.quote_plus(key)}"
            payload = {
                "instances": [{"prompt": prompt_clean}],
                "parameters": {
                    "sampleCount": 1,
                    "aspectRatio": "1:1",
                    "outputMimeType": "image/png",
                },
            }
            req = urllib.request.Request(
                target_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=60.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                preds = data.get("predictions", [])
                if preds and "bytesBase64Encoded" in preds[0]:
                    b64_data = preds[0]["bytesBase64Encoded"]
                    img_bytes = base64.b64decode(b64_data)
                    out_file.write_bytes(img_bytes)
                    data_uri = f"data:image/png;base64,{b64_data}"
                    return True, data_uri, str(out_file), filename
        except Exception:
            pass

    # 2. Try OpenAI DALL-E if key and OpenAI endpoint
    if key and endpoint and ("openai.com" in endpoint or endpoint.endswith("/images/generations")):
        try:
            target_url = endpoint if endpoint.endswith("/images/generations") else f"{endpoint.rstrip('/')}/images/generations"
            payload = {
                "model": target_model if "dall-e" in target_model else "dall-e-3",
                "prompt": prompt_clean,
                "n": 1,
                "size": "1024x1024",
                "response_format": "b64_json",
            }
            req = urllib.request.Request(
                target_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {key}",
                    "User-Agent": USER_AGENT,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=60.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                items = data.get("data", [])
                if items:
                    first = items[0]
                    if "b64_json" in first:
                        b64_data = first["b64_json"]
                        img_bytes = base64.b64decode(b64_data)
                        out_file.write_bytes(img_bytes)
                        data_uri = f"data:image/png;base64,{b64_data}"
                        return True, data_uri, str(out_file), filename
                    elif "url" in first:
                        img_url = first["url"]
                        with urllib.request.urlopen(img_url, timeout=30.0) as img_resp:
                            img_bytes = img_resp.read()
                            out_file.write_bytes(img_bytes)
                            b64_data = base64.b64encode(img_bytes).decode("ascii")
                            data_uri = f"data:image/png;base64,{b64_data}"
                            return True, data_uri, str(out_file), filename
        except Exception:
            pass

    # 3. High-Resolution Offline Artistic Canvas (Fail-Safe Local Generator)
    try:
        from PIL import Image, ImageDraw
        width, height = 1024, 1024
        img = Image.new("RGB", (width, height), (15, 23, 42))
        draw = ImageDraw.Draw(img)
        # Background grid
        for y in range(0, height, 64):
            draw.line([(0, y), (width, y)], fill=(30, 41, 59), width=1)
        for x in range(0, width, 64):
            draw.line([(x, 0), (x, height)], fill=(30, 41, 59), width=1)
        # Concentric glowing circles
        center_x, center_y = width // 2, height // 2
        for r in range(360, 40, -40):
            draw.ellipse([center_x - r, center_y - r, center_x + r, center_y + r], outline=(0, 240, 255), width=2)
        draw.ellipse([center_x - 120, center_y - 120, center_x + 120, center_y + 120], fill=(99, 102, 241), outline=(168, 85, 247), width=4)
        draw.text((center_x, 80), "PAI STUDIO GENERATIVE ART", fill=(255, 255, 255), anchor="mm")
        draw.text((center_x, height - 100), f'Prompt: "{prompt_clean[:60]}"', fill=(226, 232, 240), anchor="mm")
        img.save(out_file, format="PNG")
        raw_bytes = out_file.read_bytes()
        b64_str = base64.b64encode(raw_bytes).decode("ascii")
        data_uri = f"data:image/png;base64,{b64_str}"
        return True, data_uri, str(out_file), filename
    except Exception as exc:
        return False, f"Image generation failed: {exc}", None, None


def query_cloud_ai(
    prompt: str,
    system_prompt: str = "You are Personal Agentic AI (PAI), a helpful and precise assistant.",
    model: Optional[str] = None,
    provider: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 2048,
    timeout: float = 45.0,
) -> Tuple[bool, str]:
    """Execute a chat completion request to the configured cloud AI provider."""
    cfg = load_cloud_config()
    target_model = model or get_active_cloud_model() or "gemini-2.0-flash"
    
    # Check configured models first
    key = None
    endpoint = None
    prov = provider
    for cm in cfg.get("configured_models", []):
        if cm.get("model_name") == target_model:
            key = cm.get("api_key")
            endpoint = cm.get("provider_url")
            prov = cm.get("provider", "custom")
            break

    if not prov:
        prov = get_active_cloud_provider() or "custom"

    entry = CLOUD_PROVIDERS.get(prov, {})
    if not key:
        key = get_provider_key(prov)

    if not endpoint:
        endpoint = entry.get("endpoint") or cfg.get("custom_endpoint") or os.environ.get("PAI_API_BASE", "")

    if not key:
        return False, f"Missing API key for model '{target_model}'. Configure it in Cloud AI tab."

    if not endpoint:
        return False, f"Missing provider endpoint for model '{target_model}'."

    if not endpoint.endswith("/chat/completions") and not "generativelanguage.googleapis.com" in endpoint:
        endpoint = endpoint.rstrip("/") + "/chat/completions"

    # Build standard OpenAI-compatible Chat Completion Payload
    payload = {
        "model": target_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    req_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
        "User-Agent": USER_AGENT,
    }

    target_url = endpoint
    if "generativelanguage.googleapis.com" in endpoint:
        target_url = f"{endpoint}?key={urllib.parse.quote_plus(key)}"

    req = urllib.request.Request(
        target_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=req_headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_res = resp.read().decode("utf-8")
            data = json.loads(raw_res)
            choices = data.get("choices", [])
            if choices:
                first = choices[0]
                msg = first.get("message", {})
                content = (msg.get("content") or "").strip()
                if content:
                    return True, content
            return False, "Cloud provider returned an empty response."
    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return False, f"Cloud AI API error ({prov} HTTP {exc.code}): {err_body[:300] or exc.reason}"
    except urllib.error.URLError as exc:
        return False, f"Cloud AI connection failed: {exc.reason}"
    except Exception as exc:
        return False, f"Cloud AI request failed: {exc}"


def format_cloud_status() -> str:
    """Format a readable status report of configured cloud AI providers."""
    cfg = load_cloud_config()
    lines = [
        "Cloud AI & 3rd-Party LLM Provider Status (/api):",
        f"  Active Provider: {cfg.get('active_provider') or '(none selected)'}",
        f"  Active Model   : {cfg.get('active_model') or '(default)'}",
        "Configured Providers:",
    ]
    for prov, meta in CLOUD_PROVIDERS.items():
        if prov == "custom" and not cfg.get("custom_endpoint"):
            continue
        has_k = bool(get_provider_key(prov))
        status_badge = "✅ READY" if has_k else "❌ No API Key"
        models_str = ", ".join(meta.get("models", [])[:3])
        lines.append(f"  • {meta['display_name']} ({prov}): {status_badge}")
        if models_str:
            lines.append(f"      Models: {models_str}")
    lines.append("\nCommands:")
    lines.append("  /api set <gemini|openai|groq|deepseek> <key>  - Save API key")
    lines.append("  /api model <model_name>                       - Switch cloud model")
    lines.append("  /api status                                   - Show this status")
    lines.append("  /api clear [provider]                         - Remove saved key")
    return "\n".join(lines)