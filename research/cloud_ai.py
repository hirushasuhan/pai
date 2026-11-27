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
import copy
import ipaddress
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
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from credential_store import (
        CredentialStoreError,
        harden_secret_file,
        is_dpapi_protected,
        protect_secret,
        unprotect_secret,
        write_secret_file,
    )
    from net_guard import UrlRejected, validate_url
    from quota_engine import QuotaLedger
except ImportError:
    from research.credential_store import (
        CredentialStoreError,
        harden_secret_file,
        is_dpapi_protected,
        protect_secret,
        unprotect_secret,
        write_secret_file,
    )
    from research.net_guard import UrlRejected, validate_url
    from research.quota_engine import QuotaLedger

try:
    from internet_service import is_internet_enabled
except ImportError:
    try:
        from research.internet_service import is_internet_enabled
    except ImportError:
        def is_internet_enabled() -> bool:
            flag = os.environ.get("PAI_INTERNET_ENABLED", "1").strip().lower()
            return flag not in ("0", "false", "no", "off")

USER_AGENT = "PersonalAgenticAI/1.2 (Universal Cloud LLM Pool; Windows x64)"
_SENSITIVE_REDIRECT_HEADERS = {"authorization", "cookie", "x-goog-api-key", "x-api-key"}
_IPV4_THIS_HOST_NET = ipaddress.ip_network("0.0.0.0/8")


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    """Validates redirect targets with net_guard and strips credentials cross-origin."""

    max_redirections = 3

    def __init__(self, allow_private: bool = False) -> None:
        self.allow_private = bool(allow_private)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl, allow_private=self.allow_private)
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is not None:
            orig_origin = (urlsplit(req.full_url).scheme.lower(), urlsplit(req.full_url).netloc.lower())
            next_origin = (urlsplit(newurl).scheme.lower(), urlsplit(newurl).netloc.lower())
            if orig_origin != next_origin:
                for hdr_name, _ in list(new_req.header_items()):
                    if hdr_name.lower() in _SENSITIVE_REDIRECT_HEADERS:
                        new_req.remove_header(hdr_name)
        return new_req


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disallows HTTP redirects completely."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UrlRejected("HTTP redirects are not permitted on this endpoint")


def _read_bounded(resp: Any, max_bytes: int) -> Tuple[bytes, bool]:
    """Read up to max_bytes from resp while supporting zero-arg test mocks."""
    try:
        raw = resp.read(max_bytes + 1)
    except TypeError:
        raw = resp.read()
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    elif not isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw)
    truncated = len(raw) > max_bytes
    return bytes(raw[:max_bytes]), truncated


def _guarded_urlopen(
    req_or_url: Any,
    timeout: float = 45.0,
    allow_private: bool = False,
    allow_redirects: bool = True,
    redirect_allow_private: Optional[bool] = None,
) -> Any:
    """Validate URL via net_guard before opening, preserving mocked urllib.request.urlopen."""
    target_url = req_or_url.full_url if isinstance(req_or_url, urllib.request.Request) else str(req_or_url)
    validate_url(target_url, allow_private=allow_private)
    if getattr(urllib.request.urlopen, "__module__", None) != "urllib.request":
        return urllib.request.urlopen(req_or_url, timeout=timeout)
    handler = (
        _GuardedRedirect(allow_private=allow_private if redirect_allow_private is None else redirect_allow_private)
        if allow_redirects
        else _NoRedirect()
    )
    opener = urllib.request.build_opener(handler)
    return opener.open(req_or_url, timeout=timeout)


def _is_gemini_endpoint(endpoint: str) -> bool:
    return (urlsplit(endpoint or "").hostname or "").lower() == "generativelanguage.googleapis.com"


def _is_openai_image_endpoint(endpoint: str) -> bool:
    parsed = urlsplit(endpoint or "")
    host = (parsed.hostname or "").lower()
    return (
        host == "openai.com"
        or host.endswith(".openai.com")
        or parsed.path.rstrip("/").endswith("/images/generations")
    )


def _is_unconditionally_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return _is_unconditionally_blocked_ip(ip.ipv4_mapped)
    if ip.is_link_local or ip.is_unspecified:
        return True
    if ip.version == 4 and ip in _IPV4_THIS_HOST_NET:
        return True
    return False


def _validate_cloud_endpoint_url(url: str, allow_private: bool = False) -> str:
    """Validate a cloud or vetted local Ollama endpoint URL against SSRF rules."""
    clean = (url or "").strip()
    if not clean:
        raise UrlRejected("empty URL")

    parts, raw_ips = validate_url(clean, allow_private=True)
    resolved_ips = [ipaddress.ip_address(ip_str) for ip_str in raw_ips]
    for ip in resolved_ips:
        if _is_unconditionally_blocked_ip(ip):
            raise UrlRejected(f"address {ip} is blocked by outbound policy")

    port = parts.port if parts.port is not None else (443 if parts.scheme.lower() == "https" else 80)
    is_local_ollama = all(ip.is_loopback for ip in resolved_ips) and port == 11434

    if not is_local_ollama and not allow_private:
        validate_url(clean, allow_private=False)
        if parts.scheme.lower() != "https":
            raise UrlRejected("remote cloud endpoints must use https://")

    return clean

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


def _unprotect_stored_secret(raw_val: str, context: str) -> Tuple[Optional[str], bool]:
    """Decrypt a stored credential; returns (plaintext_or_None, needs_migration)."""
    s = str(raw_val or "").strip()
    if not s:
        return "", False
    needs_migration = sys.platform == "win32" and not is_dpapi_protected(s)
    try:
        return unprotect_secret(s), needs_migration
    except CredentialStoreError as exc:
        print(f"[cloud_ai] Warning: unable to decrypt stored credential ({context}): {exc}", file=sys.stderr)
        return None, False


def load_cloud_config() -> Dict[str, Any]:
    """Load cloud AI provider configuration, decrypting keys and migrating legacy plaintext."""
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
    harden_secret_file(p)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return default_cfg
        if "configured_models" not in data or not isinstance(data["configured_models"], list):
            data["configured_models"] = []
        if "keys" not in data or not isinstance(data["keys"], dict):
            data["keys"] = {}

        needs_migration = False
        decrypted_keys: Dict[str, Any] = {}
        for prov, val in data["keys"].items():
            if isinstance(val, list):
                items: List[str] = []
                for idx, entry in enumerate(val):
                    if not entry or not str(entry).strip():
                        continue
                    plain, mig = _unprotect_stored_secret(str(entry), f"keys.{prov}[{idx}]")
                    needs_migration = needs_migration or mig
                    if plain:
                        items.append(plain)
                decrypted_keys[prov] = items
            elif isinstance(val, str):
                if not val.strip():
                    decrypted_keys[prov] = ""
                else:
                    plain, mig = _unprotect_stored_secret(val, f"keys.{prov}")
                    needs_migration = needs_migration or mig
                    if plain:
                        decrypted_keys[prov] = plain
        data["keys"] = decrypted_keys

        for idx, cm in enumerate(data["configured_models"]):
            if not isinstance(cm, dict):
                continue
            raw_k = cm.get("api_key")
            if raw_k and str(raw_k).strip():
                plain, mig = _unprotect_stored_secret(str(raw_k), f"configured_models[{idx}]")
                needs_migration = needs_migration or mig
                cm["api_key"] = plain if plain is not None else ""

        if needs_migration:
            save_cloud_config(data)
        return data
    except Exception:
        return default_cfg


def save_cloud_config(cfg: Dict[str, Any]) -> None:
    """Persist cloud AI provider configuration with DPAPI/0o600 secret protection."""
    p = get_cloud_credentials_path()
    try:
        out_cfg = copy.deepcopy(cfg)
        keys = out_cfg.get("keys")
        if isinstance(keys, dict):
            protected_keys: Dict[str, Any] = {}
            for prov, val in keys.items():
                if isinstance(val, list):
                    protected_keys[prov] = [
                        v if (not v or is_dpapi_protected(str(v))) else protect_secret(str(v).strip())
                        for v in val
                        if str(v).strip()
                    ]
                elif isinstance(val, str):
                    clean_v = val.strip()
                    if not clean_v:
                        protected_keys[prov] = ""
                    elif is_dpapi_protected(clean_v):
                        protected_keys[prov] = clean_v
                    else:
                        protected_keys[prov] = protect_secret(clean_v)
                else:
                    protected_keys[prov] = val
            out_cfg["keys"] = protected_keys

        configured = out_cfg.get("configured_models")
        if isinstance(configured, list):
            for cm in configured:
                if isinstance(cm, dict) and cm.get("api_key"):
                    raw_k = str(cm["api_key"]).strip()
                    if raw_k and not is_dpapi_protected(raw_k):
                        cm["api_key"] = protect_secret(raw_k)

        write_secret_file(p, json.dumps(out_cfg, indent=2))
    except Exception:
        pass


def _mask_secret_preview(val: str) -> str:
    clean = str(val or "").strip()
    if not clean:
        return ""
    if len(clean) > 10:
        return f"{clean[:6]}...{clean[-4:]}"
    return "***"


def mask_cloud_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deep copy of cloud config with raw API keys masked or stripped."""
    masked = copy.deepcopy(cfg)
    raw_keys = masked.get("keys")
    if isinstance(raw_keys, dict):
        new_keys: Dict[str, Any] = {}
        for prov, val in raw_keys.items():
            if isinstance(val, list):
                new_keys[prov] = [_mask_secret_preview(str(v)) for v in val if str(v).strip()]
            elif isinstance(val, str):
                new_keys[prov] = _mask_secret_preview(val)
            else:
                new_keys[prov] = val
        masked["keys"] = new_keys

    configured = masked.get("configured_models")
    if isinstance(configured, list):
        for cm in configured:
            if isinstance(cm, dict):
                raw_k = str(cm.pop("api_key", "") or "").strip()
                cm["has_key"] = bool(raw_k)
    return masked


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


def set_custom_endpoint(url: str, allow_private: bool = False) -> None:
    """Set custom OpenAI-compatible endpoint URL after SSRF/scheme validation."""
    validated = _validate_cloud_endpoint_url(url, allow_private=allow_private)
    cfg = load_cloud_config()
    cfg["custom_endpoint"] = validated
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
    allow_private: bool = False,
) -> Dict[str, Any]:
    """Add or update a custom external cloud/image model."""
    m_name = (model_name or "").strip()
    p_url = _validate_cloud_endpoint_url(provider_url, allow_private=allow_private)
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
    if not isinstance(keys, dict):
        keys = {}
    if prov and key:
        existing_keys = keys.get(prov, [])
        if isinstance(existing_keys, str):
            existing_keys = [existing_keys] if existing_keys else []
        elif not isinstance(existing_keys, list):
            existing_keys = []
        if key not in existing_keys:
            existing_keys.append(key)
        keys[prov] = existing_keys
        if not cfg.get("active_provider"):
            cfg["active_provider"] = prov
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

    elif vm == "auto:smart" or any(k in vm for k in ("deepseek", "r1", "reason", "smart", "pro", "coder", "code", "bonsai", "ternary")):
        # Deep reasoning and code intelligence: Ternary Bonsai 2.5 -> DeepSeek R1 -> Coder -> 7b / 8b / 14b+
        smart_patterns = [
            "ternary-bonsai-2.5", "bonsai",
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
        # Balanced all-rounder: Ternary Bonsai -> Coder -> DeepSeek -> Llama 3.2
        balanced_patterns = [
            "ternary-bonsai-2.5", "bonsai",
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
    if not is_internet_enabled():
        return False, "Internet access is disabled in settings (Offline Mode active).", None, None

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
    backend_errors: List[str] = []

    def _sanitize_err_msg(err_obj: Any) -> str:
        msg = re.sub(r"\s+", " ", str(err_obj or "")).strip()
        msg = re.sub(r"(?:[A-Za-z]:)?(?:\\\\|/)?(?:Users|home)(?:\\\\|/)[^\\\\/\s]+", "<user>", msg)
        return msg[:180]

    # 1. Try Gemini Imagen
    if key and endpoint and _is_gemini_endpoint(endpoint):
        try:
            safe_model = urllib.parse.quote(target_model, safe="")
            target_url = f"https://generativelanguage.googleapis.com/v1beta/models/{safe_model}:predict"
            payload = {
                "instances": [{"prompt": prompt_clean}],
                "parameters": {"sampleCount": 1, "aspectRatio": "1:1", "outputMimeType": "image/png"},
            }
            req = urllib.request.Request(
                target_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": USER_AGENT,
                    "x-goog-api-key": key,
                },
                method="POST",
            )
            with _guarded_urlopen(req, timeout=60.0, allow_private=False) as resp:
                raw_resp, truncated = _read_bounded(resp, 16 * 1024 * 1024)
                if not truncated:
                    data = json.loads(raw_resp.decode("utf-8"))
                    preds = data.get("predictions", [])
                    if preds and "bytesBase64Encoded" in preds[0]:
                        b64_data = preds[0]["bytesBase64Encoded"]
                        img_bytes = base64.b64decode(b64_data)
                        out_file.write_bytes(img_bytes)
                        data_uri = f"data:image/png;base64,{b64_data}"
                        return True, data_uri, str(out_file), filename
        except Exception as exc:
            backend_errors.append(f"Gemini Imagen: {_sanitize_err_msg(exc)}")

    # 2. Try OpenAI DALL-E
    if key and endpoint and _is_openai_image_endpoint(endpoint):
        try:
            target_url = endpoint if endpoint.endswith("/images/generations") else f"{endpoint.rstrip('/')}/images/generations"
            target_url = _validate_cloud_endpoint_url(target_url, allow_private=False)
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
            with _guarded_urlopen(req, timeout=60.0, allow_private=False) as resp:
                raw_resp, truncated = _read_bounded(resp, 16 * 1024 * 1024)
                if truncated:
                    raise ValueError("Image API response exceeded size limit")
                data = json.loads(raw_resp.decode("utf-8"))
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
                        img_url = str(first["url"]).strip()
                        with _guarded_urlopen(img_url, timeout=30.0, allow_private=False) as img_resp:
                            img_bytes, img_truncated = _read_bounded(img_resp, 16 * 1024 * 1024)
                            if img_truncated:
                                raise ValueError("Downloaded image exceeded size limit")
                            out_file.write_bytes(img_bytes)
                            b64_data = base64.b64encode(img_bytes).decode("ascii")
                            data_uri = f"data:image/png;base64,{b64_data}"
                            return True, data_uri, str(out_file), filename
        except Exception as exc:
            backend_errors.append(f"OpenAI DALL-E: {_sanitize_err_msg(exc)}")

    # 3. Free Hugging Face Inference API (if huggingface key configured)
    hf_key = get_provider_key("huggingface")
    if hf_key and (target_model in ("hf-flux-schnell", "flux-schnell") or not key):
        try:
            hf_url = _validate_cloud_endpoint_url(
                "https://router.huggingface.co/hf-inference/models/black-forest-labs/FLUX.1-schnell",
                allow_private=False,
            )
            hf_req = urllib.request.Request(
                hf_url,
                data=json.dumps({"inputs": prompt_clean}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {hf_key}",
                    "User-Agent": USER_AGENT,
                },
                method="POST",
            )
            with _guarded_urlopen(hf_req, timeout=60.0, allow_private=False) as hf_resp:
                img_bytes, truncated = _read_bounded(hf_resp, 16 * 1024 * 1024)
                if not truncated and (img_bytes.startswith(b"\x89PNG\r\n\x1a\n") or img_bytes.startswith(b"\xff\xd8\xff")):
                    out_file.write_bytes(img_bytes)
                    b64_data = base64.b64encode(img_bytes).decode("ascii")
                    mime = "image/png" if img_bytes.startswith(b"\x89PNG") else "image/jpeg"
                    return True, f"data:{mime};base64,{b64_data}", str(out_file), filename
        except Exception as exc:
            backend_errors.append(f"HuggingFace: {_sanitize_err_msg(exc)}")

    # 4. Cloudflare Workers AI Free Tier (@cf/black-forest-labs/flux-1-schnell)
    cf_key = get_provider_key("cloudflare")
    cf_acct = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
    if cf_key and cf_acct and re.fullmatch(r"[a-zA-Z0-9_-]{8,64}", cf_acct):
        try:
            cf_url = _validate_cloud_endpoint_url(
                f"https://api.cloudflare.com/client/v4/accounts/{cf_acct}/ai/run/@cf/black-forest-labs/flux-1-schnell",
                allow_private=False,
            )
            cf_req = urllib.request.Request(
                cf_url,
                data=json.dumps({"prompt": prompt_clean, "steps": 4}).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {cf_key}", "User-Agent": USER_AGENT},
                method="POST",
            )
            with _guarded_urlopen(cf_req, timeout=60.0, allow_private=False) as cf_resp:
                raw_cf, cf_trunc = _read_bounded(cf_resp, 16 * 1024 * 1024)
                if not cf_trunc:
                    if raw_cf.startswith(b"\x89PNG\r\n\x1a\n") or raw_cf.startswith(b"\xff\xd8\xff"):
                        out_file.write_bytes(raw_cf)
                        b64_data = base64.b64encode(raw_cf).decode("ascii")
                        return True, f"data:image/png;base64,{b64_data}", str(out_file), filename
                    cf_json = json.loads(raw_cf.decode("utf-8", errors="replace"))
                    b64_cf = (cf_json.get("result") or {}).get("image")
                    if b64_cf:
                        img_bytes = base64.b64decode(b64_cf)
                        out_file.write_bytes(img_bytes)
                        return True, f"data:image/png;base64,{b64_cf}", str(out_file), filename
        except Exception as exc:
            backend_errors.append(f"Cloudflare: {_sanitize_err_msg(exc)}")

    # 5. Free Keyless Pollinations FLUX (Online Only, Zero-Key, net_guard SSRF validated)
    keyless_allowed = target_model in ("pollinations-flux", "hf-flux-schnell", "cloudflare-flux-schnell", "flux", "auto", "imagen-3.0-generate-002") or not key
    if keyless_allowed:
        try:
            encoded_prompt = urllib.parse.quote(prompt_clean[:500], safe="")
            pol_url = f"https://image.pollinations.ai/prompt/{encoded_prompt}?model=flux&width=768&height=768&nologo=true"
            pol_req = urllib.request.Request(
                pol_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PAI-Desktop/1.5"},
                method="GET",
            )
            with _guarded_urlopen(pol_req, timeout=50.0, allow_private=False) as pol_resp:
                img_bytes, pol_trunc = _read_bounded(pol_resp, 16 * 1024 * 1024)
                if not pol_trunc and (
                    img_bytes.startswith(b"\x89PNG\r\n\x1a\n")
                    or img_bytes.startswith(b"\xff\xd8\xff")
                    or (img_bytes.startswith(b"RIFF") and img_bytes[8:12] == b"WEBP")
                ):
                    out_file.write_bytes(img_bytes)
                    b64_data = base64.b64encode(img_bytes).decode("ascii")
                    mime = "image/png" if img_bytes.startswith(b"\x89PNG") else ("image/webp" if img_bytes.startswith(b"RIFF") else "image/jpeg")
                    return True, f"data:{mime};base64,{b64_data}", str(out_file), filename
                backend_errors.append("Pollinations returned a non-image payload")
        except urllib.error.HTTPError as he:
            retry_after = ""
            try:
                retry_after = str(he.headers.get("Retry-After") or "").strip() if he.headers else ""
            except Exception:
                pass
            if he.code in (402, 429):
                wait_hint = f" (wait ~{retry_after}s)" if retry_after else " (1 free image per ~45s cooldown)"
                backend_errors.append(f"Pollinations free tier cooldown{wait_hint}")
            else:
                backend_errors.append(f"Pollinations HTTP {he.code}")
        except Exception as exc:
            backend_errors.append(f"Pollinations: {_sanitize_err_msg(exc)}")

        # 5b. Secondary Free Keyless Cluster Fallback: AI Horde Anonymous API (no card or signup needed)
        if is_internet_enabled():
            try:
                horde_submit_url = _validate_cloud_endpoint_url("https://stablehorde.net/api/v2/generate/async", allow_private=False)
                horde_payload = json.dumps({
                    "prompt": prompt_clean[:500],
                    "params": {"width": 512, "height": 512, "steps": 16, "n": 1},
                    "nsfw": False,
                    "models": ["FLUX.1-schnell", "Deliberate", "AlbedoBase XL (SDXL)"],
                }).encode("utf-8")
                horde_req = urllib.request.Request(
                    horde_submit_url,
                    data=horde_payload,
                    headers={
                        "Content-Type": "application/json",
                        "apikey": "0000000000",
                        "Client-Agent": "PAI-Desktop:1.5:github",
                    },
                    method="POST",
                )
                with _guarded_urlopen(horde_req, timeout=15.0, allow_private=False) as h_resp:
                    raw_h, _ = _read_bounded(h_resp, 256 * 1024)
                    h_data = json.loads(raw_h.decode("utf-8", errors="replace"))
                    job_id = str(h_data.get("id") or "").strip()
                if job_id and re.fullmatch(r"[a-zA-Z0-9-]{8,64}", job_id):
                    check_url = _validate_cloud_endpoint_url(f"https://stablehorde.net/api/v2/generate/check/{job_id}", allow_private=False)
                    status_url = _validate_cloud_endpoint_url(f"https://stablehorde.net/api/v2/generate/status/{job_id}", allow_private=False)
                    poll_deadline = time.time() + 45.0
                    is_done = False
                    while time.time() < poll_deadline and is_internet_enabled():
                        time.sleep(3.0)
                        chk_req = urllib.request.Request(check_url, headers={"Client-Agent": "PAI-Desktop:1.5:github"}, method="GET")
                        with _guarded_urlopen(chk_req, timeout=10.0, allow_private=False) as c_resp:
                            raw_c, _ = _read_bounded(c_resp, 128 * 1024)
                            c_data = json.loads(raw_c.decode("utf-8", errors="replace"))
                            if c_data.get("done") or not c_data.get("is_possible", True):
                                is_done = bool(c_data.get("done"))
                                break
                    if is_done and is_internet_enabled():
                        st_req = urllib.request.Request(status_url, headers={"Client-Agent": "PAI-Desktop:1.5:github"}, method="GET")
                        with _guarded_urlopen(st_req, timeout=15.0, allow_private=False) as s_resp:
                            raw_s, _ = _read_bounded(s_resp, 1024 * 1024)
                            s_data = json.loads(raw_s.decode("utf-8", errors="replace"))
                            gens = s_data.get("generations") or []
                            if gens and gens[0].get("img"):
                                img_ref = str(gens[0]["img"]).strip()
                                if img_ref.startswith(("https://", "http://")):
                                    img_dl_req = urllib.request.Request(img_ref, headers={"User-Agent": USER_AGENT}, method="GET")
                                    with _guarded_urlopen(img_dl_req, timeout=25.0, allow_private=False) as img_r:
                                        img_bytes, img_trunc = _read_bounded(img_r, 16 * 1024 * 1024)
                                else:
                                    img_bytes = base64.b64decode(img_ref)
                                    img_trunc = False
                                if not img_trunc and (
                                    img_bytes.startswith(b"\x89PNG\r\n\x1a\n")
                                    or img_bytes.startswith(b"\xff\xd8\xff")
                                    or (img_bytes.startswith(b"RIFF") and img_bytes[8:12] == b"WEBP")
                                ):
                                    out_file.write_bytes(img_bytes)
                                    b64_data = base64.b64encode(img_bytes).decode("ascii")
                                    mime = "image/png" if img_bytes.startswith(b"\x89PNG") else ("image/webp" if img_bytes.startswith(b"RIFF") else "image/jpeg")
                                    return True, f"data:{mime};base64,{b64_data}", str(out_file), filename
                    backend_errors.append("AI Horde free cluster timed out waiting for worker")
            except Exception as exc:
                backend_errors.append(f"AI Horde: {_sanitize_err_msg(exc)}")

    # 6. Local diffusion loopback fallback (stable-diffusion.cpp server / A1111 / Forge on :7860)
    for local_ep in ("http://127.0.0.1:7860/sdapi/v1/txt2img", "http://localhost:7860/sdapi/v1/txt2img"):
        try:
            sd_payload = json.dumps({"prompt": prompt_clean, "steps": 20, "width": 512, "height": 512}).encode("utf-8")
            sd_req = urllib.request.Request(local_ep, data=sd_payload, headers={"Content-Type": "application/json"}, method="POST")
            with _guarded_urlopen(sd_req, timeout=8.0, allow_private=True, allow_redirects=False) as sd_resp:
                raw_sd, sd_truncated = _read_bounded(sd_resp, 16 * 1024 * 1024)
                if sd_truncated:
                    continue
                sd_data = json.loads(raw_sd.decode("utf-8"))
                if "images" in sd_data and sd_data["images"]:
                    b64_data = sd_data["images"][0]
                    img_bytes = base64.b64decode(b64_data)
                    out_file.write_bytes(img_bytes)
                    data_uri = f"data:image/png;base64,{b64_data}"
                    return True, data_uri, str(out_file), filename
        except Exception:
            pass

    detail_summary = "; ".join(backend_errors[:2]) if backend_errors else "Free image servers are temporarily busy."
    return False, (
        f"Image service is temporarily busy ({detail_summary}). "
        "Please wait ~30-45 seconds and click Retry, switch to your local 'sd-turbo' model, "
        "or add a free Gemini / HuggingFace / Cloudflare key in Cloud AI."
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
    images: Optional[List[str]] = None,
) -> Tuple[bool, str, int]:
    """Execute raw HTTP request against one candidate provider endpoint."""
    prov = candidate["provider"]
    model = candidate["model"]
    key = candidate.get("key") or ""
    endpoint = candidate.get("endpoint") or ""
    allow_private = bool(candidate.get("allow_private", False))

    if not endpoint:
        return False, f"Missing endpoint for provider '{prov}'", 400

    is_gemini = _is_gemini_endpoint(endpoint)
    if not endpoint.endswith("/chat/completions") and not is_gemini:
        endpoint = endpoint.rstrip("/") + "/chat/completions"

    try:
        target_url = _validate_cloud_endpoint_url(endpoint, allow_private=allow_private)
    except UrlRejected as exc:
        return False, f"URL rejected by outbound policy: {exc}", 400

    user_content: Any = prompt
    if images:
        parts: List[Dict[str, Any]] = [{"type": "text", "text": prompt}]
        for img_b64 in images[:3]:
            clean_b64 = (img_b64 or "").strip()
            if not clean_b64:
                continue
            url_val = clean_b64 if clean_b64.startswith("data:") else f"data:image/png;base64,{clean_b64}"
            parts.append({"type": "image_url", "image_url": {"url": url_val}})
        if len(parts) > 1:
            user_content = parts

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
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
        if is_gemini:
            req_headers["x-goog-api-key"] = key

    req = urllib.request.Request(
        target_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=req_headers,
        method="POST",
    )

    try:
        with _guarded_urlopen(
            req,
            timeout=timeout,
            allow_private=allow_private,
            redirect_allow_private=False,
        ) as resp:
            raw_bytes, truncated = _read_bounded(resp, 4 * 1024 * 1024)
            if truncated:
                return False, "Provider response exceeded maximum size limit.", 502
            data = json.loads(raw_bytes.decode("utf-8"))
            choices = data.get("choices", [])
            if choices:
                first = choices[0]
                msg = first.get("message", {})
                content = (msg.get("content") or "").strip()
                if content:
                    return True, content, 200
            return False, "Provider returned empty choices array.", 200
    except UrlRejected as exc:
        return False, f"URL rejected by outbound policy: {exc}", 400
    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_bytes, _ = _read_bounded(exc, 64 * 1024)
            err_body = err_bytes.decode("utf-8", errors="replace")
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
    if not is_internet_enabled():
        return False, "Internet access is disabled in settings (Offline Mode active)."

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
    images: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """Execute a chat completion with 4D quota management, in-flight leases, and automatic failover."""
    if not is_internet_enabled():
        return False, "Internet access is disabled in settings (Offline Mode active)."

    target_model = model or get_active_cloud_model() or "auto"

    # Virtual 'fusion' model delegation
    if target_model.lower() == "fusion" and not images:
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
                images=images,
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
    if not is_internet_enabled():
        return False, "Internet access is disabled in settings (Offline Mode active).", 0.0

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
