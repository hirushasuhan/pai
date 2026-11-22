"""Enhanced 3rd-Party Cloud LLM API Integration & Multi-Provider Pooling for PAI.

Supports leading free and commercial cloud LLM providers via OpenAI-compatible endpoints:
  - Google Gemini: gemini-2.5-flash, gemini-2.0-flash, gemini-1.5-flash, gemini-2.0-pro-exp
  - Groq: llama-3.3-70b-versatile, llama-3.1-8b-instant, mixtral-8x7b-32768, gemma2-9b-it
  - Cerebras: llama-3.3-70b, llama3.1-8b (ultra-fast 2000 tps)
  - OpenRouter Free Tier: meta-llama/llama-3.3-70b-instruct:free, deepseek/deepseek-r1:free, mistralai/mistral-small:free
  - Cloudflare Workers AI: @cf/meta/llama-3.3-70b-instruct, @cf/deepseek-ai/deepseek-r1-distill-qwen-32b
  - Mistral AI: mistral-small-latest, codestral-latest
  - DeepSeek: deepseek-chat, deepseek-reasoner
  - Pollinations.ai: zero-key free access (openai, mistral, qwen)
  - OpenAI: gpt-4o, gpt-4o-mini, o3-mini
  - Custom: User-defined OpenAI-compatible base URL (vLLM, LM Studio, Ollama remote, LocalAI, etc.)

Features:
  - Multi-Key Pooling & Rotation: Store and rotate multiple free keys per provider.
  - 4D Quota Ledger & In-Flight Leases: Tracks RPM, RPD, TPM, TPD and benches failing keys.
  - Automatic Failover Chain: If a provider hits 429 or 5xx, PAI falls over to the next healthy candidate.
  - Virtual Models: 'auto', 'auto:fast', 'auto:smart', and 'fusion' (multi-model panel synthesis).
  - T22 Security Compliance: Strict isolation of API keys in ~/.pai/cloud_ai.json.
"""

from __future__ import annotations

import base64
import concurrent.futures
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from quota_engine import QuotaLedger
except ImportError:
    from research.quota_engine import QuotaLedger

USER_AGENT = "PersonalAgenticAI/1.2 (Universal Cloud LLM Pool; Windows x64)"

CLOUD_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "gemini": {
        "display_name": "Google Gemini",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "env_var": "GEMINI_API_KEY",
        "default_model": "gemini-3.1-flash-lite",
        "models": [
            "gemini-2.0-flash",
            "gemini-4-hydrogen",
            "gemini-3.1-flash-lite",
            "gemini-3.5-flash",
            "gemini-3-flash-preview",
            "gemini-3.1-pro-preview",
            "gemini-4-carbon",
            "gemini-3.8-flash",
            "gemini-flash-latest",
            "gemini-pro-latest",
        ],
        "type": "chat",
        "speed_rank": 95,
        "intel_rank": 98,
        "rpm_cap": 15,
        "rpd_cap": 1500,
        "is_free": True,
    },
    "groq": {
        "display_name": "Groq",
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "env_var": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
        "models": [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "deepseek-r1-distill-llama-70b",
            "mixtral-8x7b-32768",
            "gemma2-9b-it",
        ],
        "type": "chat",
        "speed_rank": 98,
        "intel_rank": 85,
        "rpm_cap": 30,
        "rpd_cap": 14400,
        "is_free": True,
    },
    "cerebras": {
        "display_name": "Cerebras",
        "endpoint": "https://api.cerebras.ai/v1/chat/completions",
        "env_var": "CEREBRAS_API_KEY",
        "default_model": "llama-3.3-70b",
        "models": ["llama-3.3-70b", "llama3.1-8b"],
        "type": "chat",
        "speed_rank": 99,
        "intel_rank": 85,
        "rpm_cap": 30,
        "rpd_cap": 14400,
        "is_free": True,
    },
    "openrouter": {
        "display_name": "OpenRouter (Free Tier)",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "env_var": "OPENROUTER_API_KEY",
        "default_model": "meta-llama/llama-3.3-70b-instruct:free",
        "models": [
            "meta-llama/llama-3.3-70b-instruct:free",
            "deepseek/deepseek-r1:free",
            "mistralai/mistral-small:free",
            "qwen/qwen-2.5-coder-32b-instruct:free",
        ],
        "type": "chat",
        "speed_rank": 70,
        "intel_rank": 90,
        "rpm_cap": 20,
        "rpd_cap": 1000,
        "is_free": True,
    },
    "cloudflare": {
        "display_name": "Cloudflare Workers AI",
        "endpoint": "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1/chat/completions",
        "env_var": "CLOUDFLARE_API_KEY",
        "default_model": "@cf/meta/llama-3.3-70b-instruct",
        "models": ["@cf/meta/llama-3.3-70b-instruct", "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b"],
        "type": "chat",
        "speed_rank": 75,
        "intel_rank": 82,
        "rpm_cap": 20,
        "rpd_cap": 5000,
        "is_free": True,
    },
    "mistral": {
        "display_name": "Mistral AI",
        "endpoint": "https://api.mistral.ai/v1/chat/completions",
        "env_var": "MISTRAL_API_KEY",
        "default_model": "mistral-small-latest",
        "models": ["mistral-small-latest", "codestral-latest", "mistral-large-latest"],
        "type": "chat",
        "speed_rank": 80,
        "intel_rank": 88,
        "rpm_cap": 10,
        "rpd_cap": 1000,
        "is_free": True,
    },
    "deepseek": {
        "display_name": "DeepSeek",
        "endpoint": "https://api.deepseek.com/chat/completions",
        "env_var": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "type": "chat",
        "speed_rank": 75,
        "intel_rank": 96,
        "rpm_cap": 60,
        "rpd_cap": 10000,
        "is_free": False,
    },
    "pollinations": {
        "display_name": "Pollinations AI (Zero-Key)",
        "endpoint": "https://text.pollinations.ai/openai/chat/completions",
        "env_var": "POLLINATIONS_API_KEY",
        "default_model": "openai",
        "models": ["openai", "mistral", "qwen"],
        "type": "chat",
        "speed_rank": 60,
        "intel_rank": 80,
        "rpm_cap": 30,
        "rpd_cap": 5000,
        "is_free": True,
        "zero_key": True,
    },
    "openai": {
        "display_name": "OpenAI",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "env_var": "OPENAI_API_KEY",
        "default_model": "gpt-4o-mini",
        "models": ["gpt-4o", "gpt-4o-mini", "o3-mini"],
        "type": "chat",
        "speed_rank": 85,
        "intel_rank": 95,
        "rpm_cap": 60,
        "rpd_cap": 10000,
        "is_free": False,
    },
    "imagen": {
        "display_name": "Google Imagen 3",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta",
        "env_var": "GEMINI_API_KEY",
        "default_model": "imagen-3.0-generate-002",
        "models": ["imagen-3.0-generate-002", "imagen-3.0-generate-001"],
        "type": "image",
    },
    "dalle": {
        "display_name": "OpenAI DALL-E",
        "endpoint": "https://api.openai.com/v1/images/generations",
        "env_var": "OPENAI_API_KEY",
        "default_model": "dall-e-3",
        "models": ["dall-e-3", "dall-e-2"],
        "type": "image",
    },
    "custom": {
        "display_name": "Custom Endpoint",
        "endpoint": "",
        "env_var": "PAI_API_KEY",
        "default_model": "custom-model",
        "models": [],
        "type": "chat",
        "speed_rank": 70,
        "intel_rank": 70,
        "rpm_cap": 60,
        "rpd_cap": 10000,
    },
}

VIRTUAL_MODELS = {
    "auto": "Best healthy available model under quota",
    "auto:fast": "Fastest available healthy model (Cerebras / Groq)",
    "auto:smart": "Highest reasoning capability model (Gemini 2.5 / DeepSeek Reasoner)",
    "fusion": "Parallel multi-model panel synthesis with judge deliberation",
}


def get_cloud_credentials_path() -> Path:
    """Return path to dedicated cloud credentials store (~/.pai/cloud_ai.json)."""
    cfg_dir = os.environ.get("PAI_CONFIG_DIR")
    base = Path(cfg_dir) if cfg_dir else Path.home() / ".pai"
    base.mkdir(parents=True, exist_ok=True)
    return base / "cloud_ai.json"


def load_cloud_config() -> Dict[str, Any]:
    """Load cloud AI provider configuration, multi-key pools, and settings."""
    p = get_cloud_credentials_path()
    default_cfg: Dict[str, Any] = {
        "active_provider": "",
        "active_model": "",
        "keys": {},
        "custom_endpoint": "",
        "configured_models": [],
        "key_rotation_strategy": "round-robin",
    }
    if not p.is_file():
        return default_cfg
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return default_cfg
        if "configured_models" not in data or not isinstance(data["configured_models"], list):
            data["configured_models"] = []
        if "keys" not in data or not isinstance(data["keys"], dict):
            data["keys"] = {}
        return data
    except Exception:
        return default_cfg


def save_cloud_config(cfg: Dict[str, Any]) -> None:
    """Persist cloud AI provider configuration and keys."""
    p = get_cloud_credentials_path()
    try:
        p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass


def get_provider_keys(provider: str) -> List[str]:
    """Retrieve all API keys registered for a provider (environment + config store)."""
    prov = (provider or "").strip().lower()
    keys: List[str] = []

    # 1. Environment variables
    entry = CLOUD_PROVIDERS.get(prov)
    if entry:
        env_val = os.environ.get(entry.get("env_var", ""))
        if env_val and env_val.strip() and env_val.strip() not in keys:
            keys.append(env_val.strip())

    if prov == "gemini":
        g_env = os.environ.get("GOOGLE_API_KEY")
        if g_env and g_env.strip() and g_env.strip() not in keys:
            keys.append(g_env.strip())

    # 2. Configured keys in store
    cfg = load_cloud_config()
    raw_k = cfg.get("keys", {}).get(prov)
    if isinstance(raw_k, list):
        for k in raw_k:
            if k and str(k).strip() and str(k).strip() not in keys:
                keys.append(str(k).strip())
    elif isinstance(raw_k, str) and raw_k.strip() and raw_k.strip() not in keys:
        keys.append(raw_k.strip())

    # 3. If zero-key provider, return a dummy placeholder if no key
    if entry and entry.get("zero_key", False) and not keys:
        keys.append("zero-key-open")

    return keys


def get_provider_key(provider: str) -> Optional[str]:
    """Retrieve the primary or next healthy available API key for given provider."""
    keys = get_provider_keys(provider)
    if not keys:
        return None

    # Check with QuotaLedger to pick first non-cooldown key
    ledger = QuotaLedger.get_instance()
    for k in keys:
        if ledger.get_cooldown_remaining(provider, k) == 0.0:
            return k
    return keys[0]  # Return first if all are in cooldown


def set_provider_key(provider: str, key: str) -> None:
    """Save or set an API key for a provider (backward compatible single-key setter)."""
    prov = (provider or "").strip().lower()
    clean_k = key.strip()
    cfg = load_cloud_config()
    keys = cfg.get("keys", {})
    keys[prov] = clean_k
    cfg["keys"] = keys
    if not cfg.get("active_provider"):
        cfg["active_provider"] = prov
    save_cloud_config(cfg)


def add_provider_key(provider: str, key: str) -> bool:
    """Append a key to the provider's multi-key pool."""
    prov = (provider or "").strip().lower()
    clean_k = key.strip()
    if not clean_k:
        return False
    cfg = load_cloud_config()
    keys = cfg.get("keys", {})
    existing = keys.get(prov, [])
    if isinstance(existing, str):
        existing = [existing] if existing else []
    elif not isinstance(existing, list):
        existing = []

    if clean_k not in existing:
        existing.append(clean_k)
        keys[prov] = existing
        cfg["keys"] = keys
        if not cfg.get("active_provider"):
            cfg["active_provider"] = prov
        save_cloud_config(cfg)
        return True
    return False


def remove_provider_key(provider: str, key: str) -> bool:
    """Remove a specific key from the provider's multi-key pool."""
    prov = (provider or "").strip().lower()
    clean_k = key.strip()
    cfg = load_cloud_config()
    keys = cfg.get("keys", {})
    existing = keys.get(prov)
    if not existing:
        return False
    if isinstance(existing, str):
        if existing == clean_k:
            keys.pop(prov, None)
            cfg["keys"] = keys
            save_cloud_config(cfg)
            return True
        return False
    elif isinstance(existing, list):
        if clean_k in existing:
            existing.remove(clean_k)
            keys[prov] = existing
            cfg["keys"] = keys
            save_cloud_config(cfg)
            return True
    return False


def set_custom_endpoint(url: str) -> None:
    """Set custom OpenAI-compatible endpoint URL."""
    cfg = load_cloud_config()
    cfg["custom_endpoint"] = url.strip()
    save_cloud_config(cfg)


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

    existing_idx = next((i for i, item in enumerate(configured) if item.get("model_name") == m_name), -1)
    if existing_idx >= 0:
        configured[existing_idx] = entry
    else:
        configured.append(entry)

    cfg["configured_models"] = configured
    keys = cfg.get("keys", {})
    if prov and key:
        add_provider_key(prov, key)
    cfg["keys"] = keys

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


def get_active_cloud_provider() -> Optional[str]:
    """Determine currently active cloud AI provider."""
    cfg = load_cloud_config()
    active = cfg.get("active_provider")
    if active and active in CLOUD_PROVIDERS and get_provider_keys(active):
        return active
    for prov in ("gemini", "groq", "cerebras", "openrouter", "deepseek", "mistral", "pollinations"):
        if get_provider_keys(prov):
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
    m_clean = (model_name or "").strip()
    if not m_clean:
        return False
    if not is_cloud_model(m_clean):
        return False

    cfg = load_cloud_config()
    if m_clean in VIRTUAL_MODELS:
        cfg["active_model"] = m_clean
        cfg["active_provider"] = "auto"
        save_cloud_config(cfg)
        return True

    matched_prov = None
    for prov, meta in CLOUD_PROVIDERS.items():
        prov_models = [m.lower() for m in meta.get("models", [])]
        if m_clean.lower() in prov_models:
            matched_prov = prov
            break
    if matched_prov:
        cfg["active_provider"] = matched_prov
    cfg["active_model"] = m_clean
    save_cloud_config(cfg)
    return True


def is_cloud_model(model_name: str) -> bool:
    """
    Check if model name corresponds to a known, configured, or virtual cloud model.
    Accurately distinguishes local Ollama models (e.g. deepseek-r1:7b, mistral:7b, llama3.2:3b)
    from true 3rd-party Cloud AI models.
    """
    m_lower = (model_name or "").strip().lower()
    if not m_lower:
        return False

    # 1. Virtual routing models
    if m_lower in VIRTUAL_MODELS or m_lower.startswith("auto:"):
        return True

    # 2. User-configured custom cloud models
    cfg = load_cloud_config()
    for cm in cfg.get("configured_models", []):
        if cm.get("model_name", "").lower() == m_lower:
            return True

    # 3. Local Ollama parameter-tagged models (e.g. deepseek-r1:7b, mistral:7b, llama3.2:1b, qwen2.5-coder:7b)
    # OpenRouter free models have a slash '/' and end with ':free' (e.g. meta-llama/llama-3.3-70b-instruct:free)
    if ":" in m_lower and not m_lower.endswith(":free") and "/" not in m_lower:
        return False

    # 4. Exact match against registered cloud provider models (e.g. deepseek-chat, deepseek-reasoner, gemini-2.5-flash)
    for prov, meta in CLOUD_PROVIDERS.items():
        prov_models = [m.lower() for m in meta.get("models", [])]
        if m_lower in prov_models:
            return True

    # 5. Cloud-only prefixes (models that strictly only exist in cloud services)
    cloud_prefixes = ("gemini-", "gpt-", "claude-", "o1-", "o3-", "@cf/", "meta-llama/")
    if any(m_lower.startswith(p) for p in cloud_prefixes):
        return True

    return False


def has_usable_cloud_keys() -> bool:
    """Return True if user has configured at least one commercial/free cloud provider API key."""
    for prov in CLOUD_PROVIDERS:
        if prov == "pollinations":
            continue
        k_list = get_provider_keys(prov)
        if k_list and any(str(k).strip() for k in k_list):
            return True
    return False


def resolve_local_virtual_model(virtual_model: str, installed_models: List[str]) -> str:
    """
    Intelligently maps a virtual model directive ('auto', 'auto:fast', 'auto:smart', 'fusion')
    or an unavailable cloud model name to the optimal installed local Ollama model based on
    parameter sizing, domain keywords, and cognitive specialization:
      - Direct/partial name match (e.g. 'deepseek-r1' matches 'deepseek-r1:7b')
      - 'auto:fast' or 'flash'/'lite'/'mini': Ultra-low latency, smallest parameter size (e.g. 1b, 1.5b, 2b, 3b)
      - 'auto:smart' or 'reason'/'r1'/'pro': Deepest reasoning capability (e.g. DeepSeek R1, Qwen Coder, 7b, 8b, 14b)
      - 'auto' / 'fusion' or general: Balanced, highly reliable all-rounder
    """
    if not installed_models:
        return "llama3.2:3b"

    inst_map = {m.lower(): m for m in installed_models}
    inst_lower = list(inst_map.keys())

    vm = (virtual_model or "").lower().strip()

    # 1. Exact match or base-name match
    if vm in inst_map:
        return inst_map[vm]
    base_name = vm.split("/")[-1].split(":")[0]
    if base_name:
        for m in inst_lower:
            if base_name in m:
                return inst_map[m]

    def _find_first(patterns: List[str]) -> Optional[str]:
        for pat in patterns:
            for m in inst_lower:
                if pat in m:
                    return inst_map[m]
        return None

    # 2. Semantic / domain affinity mapping
    if vm == "auto:fast" or any(k in vm for k in ("flash", "lite", "mini", "fast", "speed", "turbo", "small", "e2b")):
        # Ultra low-latency, lightweight fast models: 1b -> 1.5b -> 2b -> 3b
        fast_patterns = [
            ":1b", "-1b", "1.5b", "e2b", ":2b", "-2b", ":3b", "-3b",
            "qwen2.5-coder:1.5b", "llama3.2:1b", "llama3.2:3b", "gemma4:e2b",
            "phi3:mini", "tiny"
        ]
        chosen = _find_first(fast_patterns)
        if chosen:
            return chosen
        return sorted(installed_models, key=lambda x: len(x))[0]

    elif vm == "auto:smart" or any(k in vm for k in ("deepseek", "r1", "reason", "smart", "pro", "coder", "code")):
        # Deep reasoning and code intelligence: DeepSeek R1 -> Coder -> 7b / 8b / 14b+
        smart_patterns = [
            "deepseek-r1", "r1:7b", "r1:8b", "r1:14b",
            "qwen2.5-coder:7b", "qwen2.5-coder:14b", "qwen2.5-coder:32b",
            "llama3.3", "llama3.1:8b", "mistral:7b", "qwen3.5:4b",
            ":14b", ":8b", ":7b", "reason"
        ]
        chosen = _find_first(smart_patterns)
        if chosen:
            return chosen
        return installed_models[0]

    else:  # "auto", "fusion", or default
        # Balanced all-rounder: quality + speed
        balanced_patterns = [
            "qwen2.5-coder:7b", "deepseek-r1:7b", "llama3.2:3b", "qwen3.5:4b",
            "mistral:7b", "llama3.1:8b", "llama3.2:1b", "qwen2.5-coder:1.5b"
        ]
        chosen = _find_first(balanced_patterns)
        if chosen:
            return chosen
        return installed_models[0]


def list_available_cloud_models() -> List[Dict[str, Any]]:
    """List all supported and user-configured cloud models and their readiness state."""
    items: List[Dict[str, Any]] = []
    cfg = load_cloud_config()
    seen_models = set()

    # 1. Virtual models
    for vm_id, vm_desc in VIRTUAL_MODELS.items():
        items.append({
            "model": vm_id,
            "provider": "virtual",
            "display_provider": "PAI Virtual Model",
            "provider_url": "",
            "model_type": "chat",
            "has_key": True,
            "is_active": vm_id == cfg.get("active_model"),
            "description": vm_desc,
        })
        seen_models.add(vm_id.lower())

    # 2. Configured custom models
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

    # 3. Preset cloud providers
    for prov, meta in CLOUD_PROVIDERS.items():
        if prov == "custom":
            continue
        keys = get_provider_keys(prov)
        has_k = bool(keys)
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
                "speed_rank": meta.get("speed_rank", 70),
                "intel_rank": meta.get("intel_rank", 70),
            })
    return items


# -----------------------------------------------------------------------------
# Image Generation Bridge (Imagen 3, DALL-E, Local fallback)
# -----------------------------------------------------------------------------
def generate_image_cloud(
    prompt: str,
    model: Optional[str] = None,
    provider_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """Generate image using Gemini Imagen, OpenAI DALL-E, or local high-res fallback."""
    prompt_clean = prompt.strip()
    if not prompt_clean:
        return False, "Prompt cannot be empty for image generation.", None, None

    cfg = load_cloud_config()
    target_model = model or "imagen-3.0-generate-002"
    key = api_key
    endpoint = provider_url

    for cm in cfg.get("configured_models", []):
        if cm.get("model_name") == target_model:
            key = key or cm.get("api_key")
            endpoint = endpoint or cm.get("provider_url")
            break

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

    # 1. Try Gemini Imagen
    if key and endpoint and "generativelanguage.googleapis.com" in endpoint:
        try:
            target_url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:predict?key={urllib.parse.quote_plus(key)}"
            payload = {
                "instances": [{"prompt": prompt_clean}],
                "parameters": {"sampleCount": 1, "aspectRatio": "1:1", "outputMimeType": "image/png"},
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

    # 2. Try OpenAI DALL-E
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
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}", "User-Agent": USER_AGENT},
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

    # 3. Local diffusion fallback
    for local_ep in ("http://127.0.0.1:7860/sdapi/v1/txt2img", "http://localhost:7860/sdapi/v1/txt2img"):
        try:
            sd_payload = json.dumps({"prompt": prompt_clean, "steps": 20, "width": 512, "height": 512}).encode("utf-8")
            sd_req = urllib.request.Request(local_ep, data=sd_payload, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(sd_req, timeout=8.0) as sd_resp:
                sd_data = json.loads(sd_resp.read().decode("utf-8"))
                if "images" in sd_data and sd_data["images"]:
                    b64_data = sd_data["images"][0]
                    img_bytes = base64.b64decode(b64_data)
                    out_file.write_bytes(img_bytes)
                    data_uri = f"data:image/png;base64,{b64_data}"
                    return True, data_uri, str(out_file), filename
        except Exception:
            pass

    return False, (
        "No AI Image Generation model is currently installed or configured. "
        "Please install sd-turbo from Local Models, or add your Google Gemini API Key (for Imagen 3) "
        "in the Cloud AI tab."
    ), None, None


# -----------------------------------------------------------------------------
# Resilient Fallback Chain & Query Execution Engine
# -----------------------------------------------------------------------------
def _resolve_candidate_chain(requested_model: str, requested_prov: Optional[str] = None) -> List[Dict[str, Any]]:
    """Build a prioritized candidate list of (provider, model, key) for fallback execution."""
    candidates: List[Dict[str, Any]] = []
    cfg = load_cloud_config()
    req_m = (requested_model or "").strip()
    req_p = (requested_prov or "").strip().lower()

    # 1. Check configured custom models first
    for cm in cfg.get("configured_models", []):
        if cm.get("model_name") == req_m:
            candidates.append({
                "provider": cm.get("provider", "custom"),
                "model": cm.get("model_name"),
                "endpoint": cm.get("provider_url"),
                "key": cm.get("api_key"),
                "rpm_cap": 60,
                "rpd_cap": 10000,
            })
            return candidates

    # 2. Virtual model routing
    if req_m in ("auto", "auto:fast", "auto:smart", ""):
        # Prioritize based on strategy
        preferred_provs = ["cerebras", "groq", "gemini", "openrouter", "mistral", "deepseek", "pollinations"]
        if req_m == "auto:fast":
            preferred_provs = ["cerebras", "groq", "gemini"]
        elif req_m == "auto:smart":
            preferred_provs = ["gemini", "deepseek", "openrouter", "groq"]

        for prov in preferred_provs:
            meta = CLOUD_PROVIDERS.get(prov, {})
            keys = get_provider_keys(prov)
            if keys:
                def_m = meta.get("default_model") or (meta.get("models", [""])[0])
                for k in keys:
                    candidates.append({
                        "provider": prov,
                        "model": def_m,
                        "endpoint": meta.get("endpoint"),
                        "key": k,
                        "rpm_cap": meta.get("rpm_cap", 30),
                        "rpd_cap": meta.get("rpd_cap", 10000),
                    })
        return candidates

    # 3. Explicit model requested
    target_prov = req_p
    if not target_prov:
        for prov, meta in CLOUD_PROVIDERS.items():
            if req_m.lower() in [m.lower() for m in meta.get("models", [])]:
                target_prov = prov
                break
    if not target_prov:
        target_prov = get_active_cloud_provider() or "custom"

    meta = CLOUD_PROVIDERS.get(target_prov, {})
    keys = get_provider_keys(target_prov)
    endpoint = meta.get("endpoint") or cfg.get("custom_endpoint") or os.environ.get("PAI_API_BASE", "")

    # Add primary candidates only if keys exist or provider supports zero-key access
    is_free_prov = meta.get("is_free", False)
    if keys:
        for k in keys:
            candidates.append({
                "provider": target_prov,
                "model": req_m,
                "endpoint": endpoint,
                "key": k,
                "rpm_cap": meta.get("rpm_cap", 30),
                "rpd_cap": meta.get("rpd_cap", 10000),
            })
        # If user selected a specific preview/heavy model, also add reliable default_model as secondary fallback on same key
        def_m = meta.get("default_model")
        if def_m and def_m != req_m:
            for k in keys:
                candidates.append({
                    "provider": target_prov,
                    "model": def_m,
                    "endpoint": endpoint,
                    "key": k,
                    "rpm_cap": meta.get("rpm_cap", 30),
                    "rpd_cap": meta.get("rpd_cap", 10000),
                })
    elif is_free_prov:
        candidates.append({
            "provider": target_prov,
            "model": req_m,
            "endpoint": endpoint,
            "key": "zero-key-open",
            "rpm_cap": meta.get("rpm_cap", 30),
            "rpd_cap": meta.get("rpd_cap", 10000),
        })

    # Add fallback providers in chain (Groq, Cerebras, Gemini, OpenRouter)
    for alt_prov in ("gemini", "groq", "cerebras", "openrouter"):
        if alt_prov != target_prov:
            alt_meta = CLOUD_PROVIDERS.get(alt_prov, {})
            alt_keys = get_provider_keys(alt_prov)
            if alt_keys:
                alt_m = alt_meta.get("default_model") or alt_meta.get("models", [""])[0]
                for k in alt_keys:
                    candidates.append({
                        "provider": alt_prov,
                        "model": alt_m,
                        "endpoint": alt_meta.get("endpoint"),
                        "key": k,
                        "rpm_cap": alt_meta.get("rpm_cap", 30),
                        "rpd_cap": alt_meta.get("rpd_cap", 10000),
                    })

    return candidates


def _execute_single_cloud_request(
    candidate: Dict[str, Any],
    prompt: str,
    system_prompt: str,
    temperature: float = 0.3,
    max_tokens: int = 2048,
    timeout: float = 45.0,
) -> Tuple[bool, str, int]:
    """Execute raw HTTP request against one candidate provider endpoint."""
    prov = candidate["provider"]
    model = candidate["model"]
    key = candidate.get("key") or ""
    endpoint = candidate.get("endpoint") or ""

    if not endpoint:
        return False, f"Missing endpoint for provider '{prov}'", 400

    if not endpoint.endswith("/chat/completions") and "generativelanguage.googleapis.com" not in endpoint:
        endpoint = endpoint.rstrip("/") + "/chat/completions"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    req_headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if key and key != "zero-key-open":
        req_headers["Authorization"] = f"Bearer {key}"

    target_url = endpoint
    if "generativelanguage.googleapis.com" in endpoint and key:
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
                    return True, content, 200
            return False, "Provider returned empty choices array.", 200
    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return False, f"HTTP {exc.code}: {err_body[:300] or exc.reason}", exc.code
    except urllib.error.URLError as exc:
        return False, f"Connection failed: {exc.reason}", 503
    except Exception as exc:
        return False, f"Request failed: {exc}", 500


def run_model_fusion(
    prompt: str,
    system_prompt: str = "You are Personal Agentic AI (PAI), a helpful and precise assistant.",
    temperature: float = 0.3,
    max_tokens: int = 2048,
    timeout: float = 45.0,
) -> Tuple[bool, str]:
    """Execute multi-model fusion: concurrently query 2-3 free models and synthesize with a judge model."""
    candidates = _resolve_candidate_chain("auto")
    unique_provs: Dict[str, Dict[str, Any]] = {}
    for c in candidates:
        if c["provider"] not in unique_provs and c.get("key"):
            unique_provs[c["provider"]] = c

    if len(unique_provs) < 2:
        # Fall back to single auto request if less than 2 providers configured
        return query_cloud_ai(prompt, system_prompt, model="auto", temperature=temperature, max_tokens=max_tokens)

    panel_candidates = list(unique_provs.values())[:3]
    draft_responses: List[Tuple[str, str]] = []

    def _worker(cand):
        ok, res, _ = _execute_single_cloud_request(cand, prompt, system_prompt, temperature, max_tokens, timeout)
        return cand["provider"], cand["model"], ok, res

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(panel_candidates)) as executor:
        futures = [executor.submit(_worker, c) for c in panel_candidates]
        for f in concurrent.futures.as_completed(futures):
            prov, mod, ok, text = f.result()
            if ok and text:
                draft_responses.append((f"{prov} ({mod})", text))

    if not draft_responses:
        return False, "All panel models in multi-model fusion failed to generate answers."

    if len(draft_responses) == 1:
        return True, draft_responses[0][1]

    # Judge synthesis prompt
    draft_blocks = []
    for idx, (source, content) in enumerate(draft_responses, 1):
        draft_blocks.append(f"### Draft {idx} [From {source}]:\n{content}\n")

    judge_prompt = (
        f"You are the Chief Intelligence Judge of Personal Agentic AI (PAI).\n"
        f"The user asked:\n\"{prompt}\"\n\n"
        f"A panel of independent free AI models provided the following candidate drafts:\n\n"
        f"{chr(10).join(draft_blocks)}\n\n"
        f"Synthesize the single best, most accurate, comprehensive, and well-structured final response. "
        f"Resolve any factual disagreements, eliminate fluff, and present the final polished solution directly."
    )

    judge_cand = panel_candidates[0]
    ok_j, judge_text, _ = _execute_single_cloud_request(judge_cand, judge_prompt, system_prompt, 0.2, max_tokens, timeout)
    if ok_j and judge_text:
        return True, judge_text

    # If judge synthesis fails, return the longest draft
    draft_responses.sort(key=lambda x: len(x[1]), reverse=True)
    return True, draft_responses[0][1]


def query_cloud_ai(
    prompt: str,
    system_prompt: str = "You are Personal Agentic AI (PAI), a helpful and precise assistant.",
    model: Optional[str] = None,
    provider: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 2048,
    timeout: float = 45.0,
) -> Tuple[bool, str]:
    """Execute a chat completion with 4D quota management, in-flight leases, and automatic failover."""
    target_model = model or get_active_cloud_model() or "auto"

    # Virtual 'fusion' model delegation
    if target_model.lower() == "fusion":
        return run_model_fusion(prompt, system_prompt, temperature, max_tokens, timeout)

    candidates = _resolve_candidate_chain(target_model, requested_prov=provider)
    if not candidates:
        return False, f"No cloud AI provider or API key configured for '{target_model}'. Add one in the Cloud AI tab."

    ledger = QuotaLedger.get_instance()
    attempt_errors: List[str] = []

    for attempt_idx, candidate in enumerate(candidates):
        prov = candidate["provider"]
        m_name = candidate["model"]
        key = candidate.get("key") or ""
        rpm = candidate.get("rpm_cap", 30)
        rpd = candidate.get("rpd_cap", 10000)

        # Quota and cooldown pre-check
        avail, reason = ledger.is_available(prov, key, rpm_cap=rpm, rpd_cap=rpd)
        if not avail:
            attempt_errors.append(f"{prov}/{m_name}: {reason}")
            continue

        # In-flight lease
        lease_id = ledger.acquire_lease(prov, key, estimated_tokens=max_tokens // 2)
        try:
            ok, resp_text, status_code = _execute_single_cloud_request(
                candidate=candidate,
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
            )
            if ok:
                est_toks = len(prompt.split()) + len(resp_text.split())
                ledger.release_lease(lease_id, success=True, status_code=200, actual_tokens=est_toks)
                return True, resp_text
            else:
                # If 503 (model-specific capacity spike), release lease without key cooldown so other models can run
                if status_code == 503:
                    ledger.release_lease(lease_id, success=False, status_code=200)
                else:
                    ledger.release_lease(lease_id, success=False, status_code=status_code)
                attempt_errors.append(f"{prov}/{m_name} (HTTP {status_code}): {resp_text}")
        except Exception as exc:
            ledger.release_lease(lease_id, success=False, status_code=200)
            attempt_errors.append(f"{prov}/{m_name}: {exc}")

    # All candidates in fallback chain exhausted
    summary_err = "; ".join(attempt_errors[-3:]) if attempt_errors else "All cloud endpoints were throttled or in cooldown."
    return False, f"Cloud AI fallback chain exhausted: {summary_err}"


def test_provider_connection(provider: str, key: Optional[str] = None) -> Tuple[bool, str, float]:
    """Test ping a cloud provider to verify connectivity, auth key, and latency."""
    prov = (provider or "").strip().lower()
    meta = CLOUD_PROVIDERS.get(prov, {})
    disp = meta.get("display_name", prov.title())
    ep = meta.get("endpoint")
    if not ep:
        return False, f"Unknown provider '{prov}'", 0.0

    k = key or get_provider_key(prov)
    if not k and not meta.get("zero_key", False):
        return False, f"No API key configured for {disp}. Please add an API key first.", 0.0

    m = meta.get("default_model") or "test"
    models_to_try = [m]
    if prov == "gemini":
        for alt_m in ["gemini-3.1-flash-lite", "gemini-3-flash-preview", "gemini-3.5-flash"]:
            if alt_m not in models_to_try:
                models_to_try.append(alt_m)

    t0 = time.time()
    last_reply = ""
    last_status = 0
    for try_model in models_to_try:
        cand = {
            "provider": prov,
            "model": try_model,
            "endpoint": ep,
            "key": k,
        }
        ok, reply, status_code = _execute_single_cloud_request(
            candidate=cand,
            prompt="Ping. Reply with exactly 'PONG'.",
            system_prompt="Be concise.",
            max_tokens=10,
            timeout=12.0,
        )
        elapsed = round(time.time() - t0, 3)
        if ok:
            return True, f"Connection verified in {elapsed}s: {reply[:50]}", elapsed
        last_reply = reply
        last_status = status_code
        if status_code in (401, 403):
            # Auth failure is deterministic; no need to retry with other models
            return False, f"Authentication failed (HTTP {status_code}): Invalid API key for {disp}.", elapsed

    elapsed = round(time.time() - t0, 3)
    if last_status == 429:
        return False, f"Rate limit reached (HTTP 429) for {disp}. Please try again shortly.", elapsed
    return False, f"{disp} ping failed (HTTP {last_status}): {last_reply}", elapsed


def format_cloud_status() -> str:
    """Format a readable status report of configured cloud AI providers and quota health."""
    cfg = load_cloud_config()
    ledger = QuotaLedger.get_instance()
    lines = [
        "Cloud AI & Multi-Provider Free LLM Pool Status (/api):",
        f"  Active Provider: {cfg.get('active_provider') or '(none selected)'}",
        f"  Active Model   : {cfg.get('active_model') or 'auto'}",
        "Available Providers & Quota Health:",
    ]
    for prov, meta in CLOUD_PROVIDERS.items():
        if prov == "custom" and not cfg.get("custom_endpoint"):
            continue
        keys = get_provider_keys(prov)
        key_count = len(keys)
        has_k = key_count > 0 or meta.get("zero_key", False)

        q_stat = ledger.get_provider_status(prov, keys)
        badge = "âœ… READY"
        if not has_k:
            badge = "â Œ No API Key"
        elif q_stat["status"] == "ALL_KEYS_COOLED_DOWN":
            badge = "âš ï¸  RATE LIMITED (In Cooldown)"
        elif q_stat["status"] == "PARTIAL_COOLDOWN":
            badge = "âœ… READY (Key Rotated)"

        free_tag = "[FREE TIER]" if meta.get("is_free") else ""
        lines.append(f"  â€¢ {meta['display_name']} ({prov}): {badge} {free_tag}")
        lines.append(f"      Keys Registered: {key_count} | Today's Reqs: {q_stat['daily_requests']}")
        models_str = ", ".join(meta.get("models", [])[:3])
        if models_str:
            lines.append(f"      Models: {models_str}")

    lines.append("\nVirtual Models:")
    for vm, desc in VIRTUAL_MODELS.items():
        lines.append(f"  â€¢ {vm}: {desc}")

    lines.append("\nCommands:")
    lines.append("  /api set <provider> <key>  - Add API key to provider pool")
    lines.append("  /api model <model|auto>    - Switch active model")
    lines.append("  /api test <provider>       - Test provider connectivity & latency")
    lines.append("  /api status                - Show this report")
    return "\n".join(lines)
