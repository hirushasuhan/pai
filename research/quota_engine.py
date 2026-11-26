"""4-Dimensional Quota Ledger & In-Flight Lease System for PAI Cloud AI.

Tracks RPM (Requests Per Minute), RPD (Requests Per Day), TPM (Tokens Per Minute),
and TPD (Tokens Per Day) to strictly keep PAI inside free-tier caps across all providers.
Also manages in-flight concurrency leases and escalating cooldown ladders upon 429/5xx errors.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from credential_store import harden_secret_file, write_secret_file
except ModuleNotFoundError:
    from research.credential_store import harden_secret_file, write_secret_file

COOLDOWN_LADDER_SECONDS = [30.0, 60.0, 300.0, 900.0, 1800.0]
MAX_LEASE_AGE_SECONDS = 120.0
_HEX16_RE = re.compile(r"^[0-9a-f]{16}$")


def _get_quota_store_path() -> Path:
    cfg_dir = os.environ.get("PAI_CONFIG_DIR")
    base = Path(cfg_dir) if cfg_dir else Path.home() / ".pai"
    base.mkdir(parents=True, exist_ok=True)
    return base / "quota_ledger.json"


class QuotaLedger:
    """Thread-safe 4D Quota Accounting and Cooldown Manager."""

    _instance: Optional[QuotaLedger] = None
    _singleton_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> QuotaLedger:
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = QuotaLedger()
            return cls._instance

    def __init__(self, persistent: bool = True):
        self._lock = threading.Lock()
        self._persistent = persistent
        self._usage: Dict[str, Dict[str, Any]] = {}
        self._leases: Dict[str, Dict[str, Any]] = {}
        self._cooldowns: Dict[str, Dict[str, Any]] = {}  # bucket -> {cooldown_until, ladder_idx}
        if self._persistent:
            self._load_state()

    def _hash_key(self, key: str) -> str:
        if not key:
            return "anonymous"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def _get_bucket(self, provider: str, key: str) -> str:
        return f"{provider.lower()}::{self._hash_key(key)}"

    @staticmethod
    def _is_valid_bucket(bucket: str) -> bool:
        if not isinstance(bucket, str) or "::" not in bucket:
            return False
        _, suffix = bucket.split("::", 1)
        return suffix == "anonymous" or bool(_HEX16_RE.match(suffix))

    def _load_state(self) -> None:
        p = _get_quota_store_path()
        if not p.is_file():
            return
        harden_secret_file(p)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                raw_usage = data.get("usage", {})
                raw_cool = data.get("cooldowns", {})
                pruned = False
                if isinstance(raw_usage, dict):
                    self._usage = {
                        k: v for k, v in raw_usage.items()
                        if self._is_valid_bucket(k) and isinstance(v, dict)
                    }
                    if len(self._usage) != len(raw_usage):
                        pruned = True
                now = time.time()
                # Restore only non-expired cooldowns with hashed buckets
                if isinstance(raw_cool, dict):
                    for k, v in raw_cool.items():
                        if not self._is_valid_bucket(k):
                            pruned = True
                            continue
                        if isinstance(v, dict) and v.get("cooldown_until", 0) > now:
                            self._cooldowns[k] = v
                if pruned:
                    self._save_state()
        except Exception:
            pass

    def _save_state(self) -> None:
        if not self._persistent:
            return
        p = _get_quota_store_path()
        try:
            payload = {
                "usage": self._usage,
                "cooldowns": self._cooldowns,
                "last_saved": time.time(),
            }
            write_secret_file(p, json.dumps(payload, indent=2))
        except Exception:
            pass

    def get_cooldown_remaining(self, provider: str, key: str) -> float:
        """Returns seconds remaining in cooldown, or 0.0 if healthy."""
        bucket = self._get_bucket(provider, key)
        with self._lock:
            entry = self._cooldowns.get(bucket)
            if not entry:
                return 0.0
            rem = entry.get("cooldown_until", 0.0) - time.time()
            if rem <= 0.0:
                self._cooldowns.pop(bucket, None)
                return 0.0
            return round(rem, 1)

    def is_available(
        self,
        provider: str,
        key: str,
        rpm_cap: int = 30,
        rpd_cap: int = 10000,
        tpm_cap: int = 100000,
        tpd_cap: int = 2000000,
    ) -> Tuple[bool, str]:
        """Check if provider+key is currently eligible to receive requests."""
        bucket = self._get_bucket(provider, key)
        now = time.time()
        today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        with self._lock:
            # 1. Cooldown Check
            cool = self._cooldowns.get(bucket)
            if cool:
                rem = cool.get("cooldown_until", 0.0) - now
                if rem > 0:
                    return False, f"Provider '{provider}' key is in cooldown ({int(rem)}s remaining after 429/5xx error)"
                else:
                    self._cooldowns.pop(bucket, None)

            # 2. In-flight lease cleanup & count
            expired_leases = [
                lid for lid, l in self._leases.items()
                if now - l.get("created_at", 0) > MAX_LEASE_AGE_SECONDS
            ]
            for lid in expired_leases:
                self._leases.pop(lid, None)

            active_lease_count = sum(
                1 for l in self._leases.values()
                if l.get("bucket") == bucket
            )
            active_lease_tokens = sum(
                l.get("estimated_tokens", 500) for l in self._leases.values()
                if l.get("bucket") == bucket
            )

            # 3. Usage Accounting
            b_usage = self._usage.setdefault(bucket, {
                "req_minute": [],
                "tokens_minute": [],
                "daily_date": today_utc,
                "daily_requests": 0,
                "daily_tokens": 0,
            })

            # Reset daily counters if day rolled over
            if b_usage.get("daily_date") != today_utc:
                b_usage["daily_date"] = today_utc
                b_usage["daily_requests"] = 0
                b_usage["daily_tokens"] = 0

            # Prune 60-second sliding windows
            b_usage["req_minute"] = [t for t in b_usage.get("req_minute", []) if now - t < 60.0]
            b_usage["tokens_minute"] = [
                (t, cnt) for (t, cnt) in b_usage.get("tokens_minute", []) if now - t < 60.0
            ]

            curr_rpm = len(b_usage["req_minute"]) + active_lease_count
            curr_tpm = sum(cnt for (_, cnt) in b_usage["tokens_minute"]) + active_lease_tokens
            curr_rpd = b_usage.get("daily_requests", 0) + active_lease_count
            curr_tpd = b_usage.get("daily_tokens", 0) + active_lease_tokens

            if rpm_cap > 0 and curr_rpm >= rpm_cap:
                return False, f"RPM cap reached ({curr_rpm}/{rpm_cap} req/min)"
            if rpd_cap > 0 and curr_rpd >= rpd_cap:
                return False, f"RPD daily cap reached ({curr_rpd}/{rpd_cap} req/day)"
            if tpm_cap > 0 and curr_tpm >= tpm_cap:
                return False, f"TPM cap reached ({curr_tpm}/{tpm_cap} tok/min)"
            if tpd_cap > 0 and curr_tpd >= tpd_cap:
                return False, f"TPD daily cap reached ({curr_tpd}/{tpd_cap} tok/day)"

            return True, "READY"

    def acquire_lease(self, provider: str, key: str, estimated_tokens: int = 500) -> str:
        """Acquire in-flight lease to prevent concurrency collisions."""
        bucket = self._get_bucket(provider, key)
        lease_id = str(uuid.uuid4())
        with self._lock:
            self._leases[lease_id] = {
                "bucket": bucket,
                "provider": provider,
                "created_at": time.time(),
                "estimated_tokens": estimated_tokens,
            }
        return lease_id

    def release_lease(
        self,
        lease_id: str,
        success: bool = True,
        status_code: int = 200,
        actual_tokens: int = 0,
        retry_after: Optional[float] = None,
    ) -> None:
        """Release an in-flight lease and record actual usage or trigger cooldown."""
        now = time.time()
        today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        with self._lock:
            lease = self._leases.pop(lease_id, None)
            if not lease:
                return
            bucket = lease["bucket"]
            provider = lease["provider"]

            b_usage = self._usage.setdefault(bucket, {
                "req_minute": [],
                "tokens_minute": [],
                "daily_date": today_utc,
                "daily_requests": 0,
                "daily_tokens": 0,
            })

            if success:
                # Reset cooldown ladder on success
                self._cooldowns.pop(bucket, None)

                # Record real usage
                toks = max(actual_tokens, lease.get("estimated_tokens", 100))
                b_usage["req_minute"].append(now)
                b_usage["tokens_minute"].append((now, toks))
                b_usage["daily_requests"] = b_usage.get("daily_requests", 0) + 1
                b_usage["daily_tokens"] = b_usage.get("daily_tokens", 0) + toks
            else:
                # Failure handling: Only true 429 (rate limits) trigger key cooldown.
                # 503 (model capacity spikes/preview busy) must not bench the entire API key.
                if status_code == 429:
                    self._apply_cooldown_ladder(bucket, retry_after)

            self._save_state()

    def record_failure(self, provider: str, key: str, status_code: int = 429, retry_after: Optional[float] = None) -> float:
        """Explicitly record rate limit / failure and bench the key."""
        bucket = self._get_bucket(provider, key)
        with self._lock:
            duration = self._apply_cooldown_ladder(bucket, retry_after)
            self._save_state()
            return duration

    def _apply_cooldown_ladder(self, bucket: str, retry_after: Optional[float] = None) -> float:
        now = time.time()
        if retry_after and retry_after > 0:
            duration = min(retry_after, 3600.0)
            ladder_idx = 0
        else:
            curr = self._cooldowns.get(bucket, {})
            ladder_idx = curr.get("ladder_idx", 0)
            duration = COOLDOWN_LADDER_SECONDS[min(ladder_idx, len(COOLDOWN_LADDER_SECONDS) - 1)]
            ladder_idx += 1

        self._cooldowns[bucket] = {
            "cooldown_until": now + duration,
            "ladder_idx": ladder_idx,
            "set_at": now,
        }
        return duration

    def get_provider_status(self, provider: str, keys: List[str]) -> Dict[str, Any]:
        """Return combined quota and health status for a provider across its keys."""
        now = time.time()
        today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        total_daily_reqs = 0
        total_daily_toks = 0
        healthy_keys = 0
        cooled_keys = 0

        with self._lock:
            for k in (keys or [""]):
                bucket = self._get_bucket(provider, k)
                cool = self._cooldowns.get(bucket)
                if cool and cool.get("cooldown_until", 0) > now:
                    cooled_keys += 1
                else:
                    healthy_keys += 1

                u = self._usage.get(bucket, {})
                if u.get("daily_date") == today_utc:
                    total_daily_reqs += u.get("daily_requests", 0)
                    total_daily_toks += u.get("daily_tokens", 0)

        status_str = "READY"
        if healthy_keys == 0 and cooled_keys > 0:
            status_str = "ALL_KEYS_COOLED_DOWN"
        elif healthy_keys > 0 and cooled_keys > 0:
            status_str = "PARTIAL_COOLDOWN"

        return {
            "status": status_str,
            "healthy_keys": healthy_keys,
            "cooldown_keys": cooled_keys,
            "daily_requests": total_daily_reqs,
            "daily_tokens": total_daily_toks,
        }
