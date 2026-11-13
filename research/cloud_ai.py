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

import json
import os
import re
import sys
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
    },
    "openai": {
        "display_name": "OpenAI",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "env_var": "OPENAI_API_KEY",
        "default_model": "gpt-4o-mini",
        "models": ["gpt-4o", "gpt-4o-mini", "o3-mini"],
    },
    "groq": {
        "display_name": "Groq",
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "env_var": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
        "models": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
    },
    "deepseek": {
        "display_name": "DeepSeek",
        "endpoint": "https://api.deepseek.com/chat/completions",
        "env_var": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
        "models": ["deepseek-chat", "deepseek-reasoner"],
    },
    "custom": {
        "display_name": "Custom OpenAI-Compatible",
        "endpoint": "",
        "env_var": "PAI_API_KEY",
        "default_model": "custom-model",
        "models": [],
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
    if not p.is_file():
        return {"active_provider": "", "active_model": "", "keys": {}, "custom_endpoint": ""}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"active_provider": "", "active_model": "", "keys": {}, "custom_endpoint": ""}


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
    """List all supported cloud models and their readiness state."""
    items: List[Dict[str, Any]] = []
    cfg = load_cloud_config()
    for prov, meta in CLOUD_PROVIDERS.items():
        if prov == "custom" and not cfg.get("custom_endpoint"):
            continue
        has_k = bool(get_provider_key(prov))
        for m in meta.get("models", []):
            items.append({
                "model": m,
                "provider": prov,
                "display_provider": meta["display_name"],
                "has_key": has_k,
                "is_active": m == cfg.get("active_model"),
            })
    return items


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
    prov = provider or get_active_cloud_provider()
    if not prov:
        return False, "No cloud AI provider is configured. Use /api set <gemini|openai|groq|deepseek> <key> to set up."

    entry = CLOUD_PROVIDERS.get(prov)
    if not entry:
        return False, f"Unknown cloud AI provider: '{prov}'"

    key = get_provider_key(prov)
    if not key:
        return False, f"Missing API key for provider '{prov}'. Use /api set {prov} <your_key> or set ${entry['env_var']}."

    endpoint = entry["endpoint"]
    if prov == "custom":
        cfg = load_cloud_config()
        endpoint = cfg.get("custom_endpoint") or os.environ.get("PAI_API_BASE", "")
        if not endpoint:
            return False, "Custom provider endpoint URL is not configured (/api endpoint <url>)."
        if not endpoint.endswith("/chat/completions"):
            endpoint = endpoint.rstrip("/") + "/chat/completions"

    target_model = model or get_active_cloud_model() or entry.get("default_model") or "default"

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

    # For Gemini API's OpenAI compatibility endpoint, key in Bearer header is accepted,
    # or ?key=<API_KEY> query param can be appended.
    target_url = endpoint
    if prov == "gemini":
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