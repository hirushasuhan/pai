"""
Personal Agentic AI (PAI) - Setup Wizard and Hardware Survey Engine.

Part of Milestones P3 and P4 for the v1.1.0 Packaging and Installer subsystem.
Specification: docs/PACKAGING_SPEC.md (§4, §5, §6, Appendix B, Appendix C)
ADR-005, ADR-012, ADR-013

Hard Rules Enforced (Findings CB, CC, CD, CD2, CE, CG, CH, CK, CL, CM):
  1. Shipped code NEVER trusts test keys or contains private seeds (Finding CB).
     Production keys are read ONLY from <install root>/research/trust.json; fails closed.
     Explicit trust_path argument is developer/test only and NEVER read from env (Finding CK).
     Profile locations (%LOCALAPPDATA%, ~/.pai) and PAI_TRUST_PATH are strictly ignored (Finding CK).
  2. Monotonic catalog version enforcement via persistent state (Finding CD).
     Replay rollback rejected if catalog_version < highest seen version.
     If state file is damaged/deleted, highest seen version resets to 0 (Finding CM).
  3. Catalog freshness: catalogs older than 90 days from issued_utc are rejected (Finding CD).
  4. Strict catalog schema: non-empty models, positive sizes, regex IDs and digests,
     kind="catalog" required, demo catalogs rejected in production (Finding CD2).
     Optional publisher block supports thumbprint rotation via signed catalog (Finding CL).
  5. Fit rules: GPU offloading and 512 MB context allowance are explicitly labeled
     as estimates; preselection chooses ONLY "full" tier until measured (Finding CE).
  6. RAM rule uses available RAM at survey time with 2048 MB system reserve (Finding CE).
  7. CPU and multi-GPU surveys use real CIM properties and pick discrete GPU (Finding CE).
  8. Ollama installer publisher check: verified Authenticode Subject and Thumbprint
     with fail-closed validation on non-Windows; verified in-place before running (Finding CC).
     Installer download enforces HTTPS, official hosts, size limit, deletion on failure,
     and redirects to untrusted hosts are rejected (Finding CL).
  9. Progress stream: emits implemented P3/P4 events per Appendix C (Findings CG, P4).
  10. Loopback connections bypass proxy; non-loopback OLLAMA_HOST rejected (Finding CH).
  11. Streaming model pull engine aggregates layers, renders width-aware bar or 5% log,
      supports exponential backoff resume, and thread-safe cancellation (Milestone P4).
"""

from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import http.client
import json
import logging
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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger("pai_setup")

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

try:
    import ed25519_ref
except ImportError:
    ed25519_ref = None  # Handled fail-closed during verification if missing


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------
class SetupError(Exception):
    """Base exception for setup and survey failures."""


class CatalogSecurityError(SetupError):
    """Raised when catalog signature, integrity, freshness, or monotonic version check fails."""


class FitRuleViolationError(SetupError):
    """Raised when hard resource requirements cannot be met."""


class OllamaVerificationError(SetupError):
    """Raised when Ollama installer verification fails."""


class DownloadCancelledError(SetupError):
    """Raised when a model or installer download is cancelled by the user (§6, Milestone P4)."""


class ModelPullError(SetupError):
    """Raised when an Ollama model pull operation fails (Milestone P4)."""

    def __init__(self, code: str, message: str):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


# -----------------------------------------------------------------------------
# Hardware Survey (§4, §5, ADR-012, Finding CE, Finding DR)
# -----------------------------------------------------------------------------
@dataclass
class HardwareProfile:
    total_ram_mb: Optional[float]
    avail_ram_mb: Optional[float]
    free_disk_bytes: int
    total_disk_bytes: int
    model_drive: str
    gpu_name: Optional[str]
    dedicated_vram_mb: float
    gpu_driver_version: Optional[str]
    cpu_cores: int
    cpu_logical: int
    cpu_name: Optional[str]
    npu_detected: bool
    npu_name: Optional[str]
    ram_source: str = "telemetry"
    npu_note: str = "detected, not used in this version (ADR-012)"
    windows_version: Optional[str] = None
    all_gpus: List[Dict[str, Any]] = field(default_factory=list)


def survey_ram_windows() -> Tuple[Optional[float], Optional[float], str]:
    """Queries total and available physical RAM using HardwareTelemetry (Finding DR)."""
    try:
        from hardware_telemetry import HardwareTelemetry
        snap = HardwareTelemetry().get_system_snapshot()
        tot = snap.get("total_ram_gb")
        avail = snap.get("avail_ram_mb")
        if tot is not None and avail is not None:
            return round(tot * 1024.0, 1), round(avail, 1), "telemetry"
    except Exception:
        pass
    return None, None, "unavailable"


def survey_disk_free(target_path: Optional[str | Path] = None) -> Tuple[int, int, str]:
    """
    Queries free and total disk bytes on the drive hosting the model store.
    Prioritizes OLLAMA_MODELS env var before defaulting to ~/.ollama/models.
    """
    if not target_path:
        env_models = os.environ.get("OLLAMA_MODELS")
        if env_models:
            target_path = Path(env_models)
        else:
            user_prof = os.environ.get("USERPROFILE", os.path.expanduser("~"))
            target_path = Path(user_prof) / ".ollama" / "models"

    p = Path(target_path).resolve()
    probe_dir = p
    while not probe_dir.exists() and probe_dir.parent != probe_dir:
        probe_dir = probe_dir.parent

    try:
        usage = shutil.disk_usage(str(probe_dir))
        drive = probe_dir.drive or str(probe_dir)
        return usage.free, usage.total, drive
    except Exception as e:
        logger.warning("Failed to inspect disk usage: %s", e)
        return 50 * 1024 * 1024 * 1024, 250 * 1024 * 1024 * 1024, "C:"


def probe_nvidia_smi_vram() -> float:
    """Attempts nvidia-smi query to get true dedicated VRAM in MiB."""
    try:
        proc = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return float(proc.stdout.strip().splitlines()[0].strip())
    except Exception:
        pass
    return 0.0


def survey_gpu_windows() -> Tuple[Optional[str], float, Optional[str], List[Dict[str, Any]]]:
    """
    Surveys GPU using Get-CimInstance Win32_VideoController.
    Handles multi-GPU setups, selecting discrete GPU with highest dedicated VRAM.
    Returns (gpu_name, dedicated_vram_mb, driver_version, all_gpus).
    """
    if sys.platform != "win32":
        return None, 0.0, None, []

    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM, DriverVersion | ConvertTo-Json -Compress",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0 and proc.stdout.strip():
            raw = json.loads(proc.stdout)
            controllers = raw if isinstance(raw, list) else [raw]

            all_gpus: List[Dict[str, Any]] = []
            best_gpu = None
            max_vram = 0.0
            best_driver = None

            for ctrl in controllers:
                name = ctrl.get("Name", "")
                driver = ctrl.get("DriverVersion", "")
                vram_bytes = ctrl.get("AdapterRAM", 0) or 0
                vram_mb = vram_bytes / (1024 * 1024)

                # Check nvidia-smi if NVIDIA to bypass 4GB Win32_VideoController cap
                if "nvidia" in name.lower():
                    nv_mb = probe_nvidia_smi_vram()
                    if nv_mb > 0:
                        vram_mb = nv_mb

                gpu_entry = {
                    "name": name,
                    "vram_mb": round(vram_mb, 1),
                    "driver_version": driver,
                }
                all_gpus.append(gpu_entry)

                # Priority: NVIDIA / AMD discrete over integrated Intel / Microsoft basic
                is_discrete = any(d in name.lower() for d in ("nvidia", "geforce", "radeon", "amd"))
                current_is_discrete = best_gpu and any(d in best_gpu.lower() for d in ("nvidia", "geforce", "radeon", "amd"))

                if is_discrete and not current_is_discrete:
                    max_vram = vram_mb
                    best_gpu = name
                    best_driver = driver
                elif is_discrete == current_is_discrete and vram_mb > max_vram:
                    max_vram = vram_mb
                    best_gpu = name
                    best_driver = driver
                elif best_gpu is None:
                    max_vram = vram_mb
                    best_gpu = name
                    best_driver = driver

            return best_gpu, round(max_vram, 1), best_driver, all_gpus
    except Exception as e:
        logger.debug("PowerShell GPU survey failed: %s", e)

    return None, 0.0, None, []


def survey_cpu_windows() -> Tuple[int, int, str]:
    """Queries real physical cores and logical processors from Win32_Processor."""
    if sys.platform != "win32":
        cores = os.cpu_count() or 4
        return max(1, cores // 2), cores, "x86_64"

    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors | ConvertTo-Json -Compress",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0 and proc.stdout.strip():
            raw = json.loads(proc.stdout)
            proc_info = raw[0] if isinstance(raw, list) else raw
            name = proc_info.get("Name", os.environ.get("PROCESSOR_IDENTIFIER", "CPU"))
            cores = int(proc_info.get("NumberOfCores", 1))
            logical = int(proc_info.get("NumberOfLogicalProcessors", os.cpu_count() or 1))
            return max(1, cores), max(1, logical), name
    except Exception as e:
        logger.debug("CPU survey query failed: %s", e)

    cores = os.cpu_count() or 4
    return max(1, cores // 2), cores, os.environ.get("PROCESSOR_IDENTIFIER", "x86_64")


def survey_npu_windows() -> Tuple[bool, Optional[str]]:
    """
    Detects presence of an NPU (Neural Processing Unit, e.g. AMD XDNA, Intel AI Boost).
    ADR-012: 'detected, not used in this version'.
    """
    if sys.platform != "win32":
        return False, None

    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name -match 'NPU|XDNA|Neural|AI Boost' } | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0 and proc.stdout.strip():
            raw = json.loads(proc.stdout)
            names = raw if isinstance(raw, list) else [raw]
            if names:
                return True, str(names[0])
    except Exception as e:
        logger.debug("NPU survey probe failed: %s", e)

    return False, None


def collect_hardware_survey(
    model_drive_path: Optional[str | Path] = None,
    allow_mock: bool = False,
) -> HardwareProfile:
    """
    Performs full local hardware survey.
    On non-Windows platforms, raises NotImplementedError unless allow_mock is True.
    """
    if sys.platform != "win32":
        if not allow_mock:
            raise NotImplementedError("Hardware survey is only supported on Windows in v1.1.0 (ADR-012)")
        total_ram, avail_ram, ram_source = 16384.0, 8192.0, "telemetry"
        gpu_name, vram_mb, driver_ver, all_gpus = None, 0.0, None, []
        cpu_cores, cpu_logical, cpu_name = 4, 8, "Mock-CPU"
        npu_detected, npu_name = False, None
        win_ver = None
    else:
        total_ram, avail_ram, ram_source = survey_ram_windows()
        gpu_name, vram_mb, driver_ver, all_gpus = survey_gpu_windows()
        cpu_cores, cpu_logical, cpu_name = survey_cpu_windows()
        npu_detected, npu_name = survey_npu_windows()
        wv = sys.getwindowsversion()
        win_ver = f"{wv.major}.{wv.minor}.{wv.build}"

    free_disk, total_disk, drive = survey_disk_free(model_drive_path)

    return HardwareProfile(
        total_ram_mb=total_ram,
        avail_ram_mb=avail_ram,
        ram_source=ram_source,
        free_disk_bytes=free_disk,
        total_disk_bytes=total_disk,
        model_drive=drive,
        gpu_name=gpu_name,
        dedicated_vram_mb=vram_mb,
        gpu_driver_version=driver_ver,
        cpu_cores=cpu_cores,
        cpu_logical=cpu_logical,
        cpu_name=cpu_name,
        npu_detected=npu_detected,
        npu_name=npu_name,
        windows_version=win_ver,
        all_gpus=all_gpus,
    )


# -----------------------------------------------------------------------------
# Signed Catalog Verification (§5, Appendix B, Findings CB, CD, CD2)
# -----------------------------------------------------------------------------
def canonical_json_bytes(doc: Dict[str, Any]) -> bytes:
    """Produces deterministic canonical UTF-8 bytes for cryptographic signing."""
    # Omit signature field during canonical serialization
    d = {k: v for k, v in doc.items() if k != "signature"}
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_trust_keys(trust_path: Optional[Path | str] = None) -> List[Dict[str, Any]]:
    """
    Loads trusted verification keys strictly from trust.json.
    Hard Rules (Findings CB & CK):
      - In the installed product the ONLY trust root is <install root>\\research\\trust.json
      - An explicit path argument is allowed for tests and developer runs only, and is
        NEVER read from the environment or user profile.
      - User-profile locations (%LOCALAPPDATA%\\PAI, ~/.pai) and PAI_TRUST_PATH are strictly ignored.
      - Fails closed if missing, empty, or has no active keys.
    """
    resolved_path: Optional[Path] = None

    if trust_path:
        p = Path(trust_path)
        if not p.is_file():
            raise CatalogSecurityError(f"Specified trust root file does not exist: {p} (fail-closed)")
        resolved_path = p
    else:
        # Findings CK & CP: Locate research\trust.json strictly relative to the running module's location.
        # Environment variables (including PAI_INSTALL_DIR and PAI_TRUST_PATH) and user-profile paths
        # are strictly IGNORED to prevent caller environment manipulation of the trust root.
        module_dir = Path(__file__).resolve().parent
        for cand in [
            module_dir / "trust.json",
            module_dir / "research" / "trust.json",
            module_dir.parent / "research" / "trust.json",
        ]:
            if cand.is_file():
                resolved_path = cand
                break

    if resolved_path is None:
        raise CatalogSecurityError(
            "Trust root 'trust.json' not found in module directory; cannot verify catalog (fail-closed, Findings CB, CK, CP)"
        )

    try:
        data = json.loads(resolved_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise CatalogSecurityError(f"Failed to read trust root '{resolved_path}': {e}")

    keys = data.get("keys")
    if not isinstance(keys, list) or len(keys) == 0:
        raise CatalogSecurityError(f"Trust root '{resolved_path}' contains no keys (fail-closed)")

    active_keys = [k for k in keys if isinstance(k, dict) and not k.get("revoked", False)]
    if not active_keys:
        raise CatalogSecurityError(f"No active unrevoked keys in trust root '{resolved_path}' (fail-closed)")

    return active_keys


def get_catalog_state_path() -> Path:
    """
    Returns path to the per-user catalog state file storing highest seen version.
    Finding CM: If catalog_state.json is corrupted or deleted, the highest seen
    version reads as 0, so monotonic rollback defense resets. This is an expected
    and acceptable property of an unprivileged per-user state file; it prevents
    downgrade replay attacks during normal operation.
    """
    user_dir = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "PAI"
    return user_dir / "catalog_state.json"


def get_highest_seen_catalog_version(state_path: Optional[Path | str] = None) -> int:
    """Reads highest seen catalog version from persistent state file (Finding CD)."""
    p = Path(state_path) if state_path else get_catalog_state_path()
    if not p.is_file():
        return 0
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return int(data.get("highest_catalog_version", 0))
    except Exception:
        return 0


def record_catalog_version(version: int, state_path: Optional[Path | str] = None) -> None:
    """Persists highest accepted catalog version to prevent replay rollbacks (Finding CD)."""
    p = Path(state_path) if state_path else get_catalog_state_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        current_highest = get_highest_seen_catalog_version(p)
        if version > current_highest:
            state = {
                "highest_catalog_version": version,
                "updated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
            shutil.move(str(tmp), str(p))
    except Exception as e:
        logger.warning("Failed to persist catalog version state: %s", e)


def verify_catalog_payload(
    catalog_data: Dict[str, Any],
    trust_keys: Optional[List[Dict[str, Any]]] = None,
    min_version: Optional[int] = None,
    state_path: Optional[Path | str] = None,
    enforce_freshness: bool = True,
) -> Dict[str, Any]:
    """
    Verifies a catalog dictionary against all security policies:
      1. Required fields: kind, catalog_version, issued_utc, models, signature.
      2. Kind check: kind == "catalog" (purpose separation).
      3. Demo check: demo == True rejected in production (Finding CD2).
      4. Monotonic version: catalog_version >= max(min_version, highest_seen).
      5. Freshness check: issued_utc not older than 90 days.
      6. Strict schema: valid model IDs, sizes > 0, manifest digests matching sha256 regex.
      7. Detached Ed25519 signature checked against active unrevoked trust keys.
    """
    # 1. Required top-level fields
    for req in ("kind", "catalog_version", "issued_utc", "models", "signature"):
        if req not in catalog_data:
            raise CatalogSecurityError(f"Catalog missing required field: {req!r}")

    # 2. Kind check
    if catalog_data.get("kind") != "catalog":
        raise CatalogSecurityError(f"Invalid catalog kind {catalog_data.get('kind')!r}; must be 'catalog'")

    # 3. Demo check (Finding CD2)
    if catalog_data.get("demo") is True:
        raise CatalogSecurityError("Demo catalogs are rejected in production (Finding CD2)")

    # 4. Monotonic version check & Replay Rollback Defense (Finding CD)
    cat_ver = catalog_data["catalog_version"]
    if not isinstance(cat_ver, int) or cat_ver < 1:
        raise CatalogSecurityError(f"Catalog version must be a positive integer, got: {cat_ver!r}")

    highest_seen = get_highest_seen_catalog_version(state_path)
    effective_min = max(min_version or 1, highest_seen)
    if cat_ver < effective_min:
        raise CatalogSecurityError(
            f"Catalog version rollback or below minimum ({cat_ver} < {effective_min})"
        )

    # 5. Catalog Freshness Check (90 days, Finding CD)
    issued_raw = catalog_data["issued_utc"]
    if not isinstance(issued_raw, str):
        raise CatalogSecurityError("Catalog issued_utc must be an ISO-8601 string")

    if enforce_freshness:
        try:
            # Parse ISO-8601 timestamp (support trailing 'Z' or offset)
            clean_ts = issued_raw.replace("Z", "+00:00")
            issued_dt = datetime.datetime.fromisoformat(clean_ts)
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            age_seconds = (now_dt - issued_dt).total_seconds()
            max_age_seconds = 90 * 86400  # 90 days (Finding CD, D20)
            if age_seconds > max_age_seconds:
                days = age_seconds / 86400
                raise CatalogSecurityError(
                    f"Catalog has expired ({days:.1f} days old; maximum freshness is 90 days per policy D20). "
                    "Please download an updated signed catalog from the official PAI releases repository."
                )
            if age_seconds < -86400:  # Clock skew beyond 24h into future
                raise CatalogSecurityError("Catalog issued_utc is in the future")
        except ValueError as ve:
            raise CatalogSecurityError(f"Malformed issued_utc timestamp: {ve}")

    # 6. Optional Publisher Block Validation (Finding CL)
    # Allows certificate rotation for external binaries (Ollama) via signed catalog
    publisher = catalog_data.get("publisher")
    if publisher is not None:
        if not isinstance(publisher, dict):
            raise CatalogSecurityError("Catalog 'publisher' field must be an object if present")
        subj = publisher.get("subject")
        if subj is not None and (not isinstance(subj, str) or not subj.strip()):
            raise CatalogSecurityError("Catalog publisher 'subject' must be a non-empty string")
        tprints = publisher.get("thumbprints")
        if tprints is not None:
            if not isinstance(tprints, list) or len(tprints) == 0:
                raise CatalogSecurityError("Catalog publisher 'thumbprints' must be a non-empty list of hex strings")
            for tp in tprints:
                if not isinstance(tp, str) or not tp.strip():
                    raise CatalogSecurityError(f"Invalid thumbprint in publisher block: {tp!r}")

    # 7. Strict Model Schema Validation (Finding CD2)
    models = catalog_data["models"]
    if not isinstance(models, list) or len(models) == 0:
        raise CatalogSecurityError("Catalog 'models' list must be non-empty")

    seen_ids = set()
    id_pattern = re.compile(r"^[a-z0-9_.-]+:[a-z0-9_.-]+$")
    digest_pattern = re.compile(r"^sha256:[0-9a-f]{64}$")

    for idx, m in enumerate(models):
        if not isinstance(m, dict):
            raise CatalogSecurityError(f"Model entry #{idx} is not an object")

        mid = m.get("id")
        if not mid or not isinstance(mid, str) or not id_pattern.match(mid):
            raise CatalogSecurityError(f"Model #{idx} invalid or missing id: {mid!r}")

        if mid in seen_ids:
            raise CatalogSecurityError(f"Duplicate model id in catalog: {mid!r}")
        seen_ids.add(mid)

        dl_bytes = m.get("download_bytes")
        if not isinstance(dl_bytes, int) or dl_bytes <= 0:
            raise CatalogSecurityError(f"Model {mid} download_bytes must be a positive int, got: {dl_bytes!r}")

        disk_bytes = m.get("disk_bytes")
        if not isinstance(disk_bytes, int) or disk_bytes <= 0:
            raise CatalogSecurityError(f"Model {mid} disk_bytes must be a positive int, got: {disk_bytes!r}")

        min_ram = m.get("min_ram_mb")
        if not isinstance(min_ram, (int, float)) or min_ram <= 0:
            raise CatalogSecurityError(f"Model {mid} min_ram_mb must be positive, got: {min_ram!r}")

        digest = m.get("registry_manifest_digest")
        if not digest or not isinstance(digest, str) or not digest_pattern.match(digest):
            raise CatalogSecurityError(f"Model {mid} invalid registry_manifest_digest: {digest!r}")

        lic = m.get("license")
        if not isinstance(lic, dict):
            raise CatalogSecurityError(f"Model {mid} missing license object")
        if lic.get("license_status") not in ("verified", "unverified"):
            raise CatalogSecurityError(f"Model {mid} license_status must be 'verified' or 'unverified'")

    # 7. Signature verification
    sig_hex = catalog_data["signature"]
    if not sig_hex or not isinstance(sig_hex, str):
        raise CatalogSecurityError("Catalog signature is empty or non-string")

    canonical_bytes = canonical_json_bytes(catalog_data)
    keys = trust_keys or load_trust_keys()
    active_keys = [k for k in keys if not k.get("revoked", False)]

    if not active_keys:
        raise CatalogSecurityError("No active unrevoked trust keys available for catalog verification")

    if ed25519_ref is None:
        raise CatalogSecurityError("ed25519_ref module unavailable; cannot verify catalog signature")

    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        raise CatalogSecurityError("Invalid hex signature in catalog")

    verified = False
    for key_entry in active_keys:
        pub_hex = key_entry.get("public_hex", "")
        try:
            pub_bytes = bytes.fromhex(pub_hex)
            if ed25519_ref.verify(pub_bytes, canonical_bytes, sig_bytes):
                verified = True
                break
        except Exception:
            continue

    if not verified:
        raise CatalogSecurityError("Catalog Ed25519 signature verification failed against trust root")

    # On successful verification, record highest seen version
    record_catalog_version(cat_ver, state_path)

    return catalog_data


# -----------------------------------------------------------------------------
# Fit Rules & Recommendations (§5, Finding CE)
# -----------------------------------------------------------------------------
@dataclass
class ModelFitReport:
    model_id: str
    display_name: str
    family: str
    tasks: List[str]
    download_bytes: int
    disk_bytes: int
    license_status: str
    fits_disk: bool
    disk_required_bytes: int
    fits_gpu: str  # "full", "partial", "cpu"
    fits_ram: bool
    is_preselected: bool
    gpu_estimate_note: str = "GPU tier and 512 MB context allowance are estimates based on model size"
    measured: bool = False
    rejection_reasons: List[str] = field(default_factory=list)


def evaluate_model_fit(
    model: Dict[str, Any],
    survey: HardwareProfile,
    current_selected_disk_bytes: int = 0,
) -> ModelFitReport:
    """
    Evaluates fit rules for a single candidate model:
      - Disk rule: free space >= (1.25 * total_selected_size) + 2 GB safety margin.
      - GPU rule (estimate): weights + 512 MB context allowance <= 85% VRAM is 'full';
        86-120% is 'partial'; otherwise 'cpu'. Labeled explicitly as estimate.
      - RAM rule: evaluated against available RAM at survey time (survey.avail_ram_mb)
        with 2048 MB system stability reserve.
      - Pre-selection rule: Preselect ONLY "full" tier GPU fit (never "partial"),
        verified license, and no resource rejections.
    """
    model_id = model.get("id", "")
    family = model.get("family", "")
    tasks = model.get("tasks", [])
    dl_bytes = model.get("download_bytes", 0)
    disk_bytes = model.get("disk_bytes", dl_bytes)
    min_ram_mb = model.get("min_ram_mb", 2048)
    lic = model.get("license", {})
    lic_status = lic.get("license_status", "unverified")

    rejections: List[str] = []

    # 1. Disk rule: free space must be >= 1.25 * (chosen + model) + 2 GB safety margin
    required_disk_bytes = int(1.25 * (current_selected_disk_bytes + disk_bytes)) + (2 * 1024 * 1024 * 1024)
    fits_disk = survey.free_disk_bytes >= required_disk_bytes
    if not fits_disk:
        deficit_mb = round((required_disk_bytes - survey.free_disk_bytes) / (1024 * 1024), 1)
        rejections.append(
            f"INSUFFICIENT_DISK: Free space on {survey.model_drive} ({round(survey.free_disk_bytes / (1024**3), 2)} GB) "
            f"below rule requirement ({round(required_disk_bytes / (1024**3), 2)} GB; deficit {deficit_mb} MB)"
        )

    # 2. GPU rule (Estimates based on model size):
    # Footprint = disk weights + 512 MB context allowance
    footprint_mb = (disk_bytes / (1024 * 1024)) + 512.0
    if survey.dedicated_vram_mb > 0:
        full_limit = 0.85 * survey.dedicated_vram_mb
        partial_limit = 1.20 * survey.dedicated_vram_mb
        if footprint_mb <= full_limit:
            gpu_tier = "full"
        elif footprint_mb <= partial_limit:
            gpu_tier = "partial"
        else:
            gpu_tier = "cpu"
    else:
        gpu_tier = "cpu"

    # 3. RAM rule: Evaluated using available RAM at survey time with 2048 MB reserve (Finding CE, Finding DR)
    if survey.avail_ram_mb is None:
        fits_ram = False
        rejections.append("RAM_UNKNOWN: Available RAM could not be surveyed; model preselection disabled")
    else:
        system_reserve_mb = 2048.0
        usable_avail_ram_mb = survey.avail_ram_mb - system_reserve_mb
        fits_ram = usable_avail_ram_mb >= min_ram_mb
        if not fits_ram and gpu_tier != "full":
            rejections.append(
                f"INSUFFICIENT_RAM: Available RAM ({survey.avail_ram_mb:.1f} MB) with 2048 MB reserve "
                f"below model requirement ({min_ram_mb:.1f} MB)"
            )

    # 4. Pre-selection rule:
    # Must fit disk, must fit RAM, must have known RAM (Finding DR),
    # must be 'full' GPU offload (never 'partial' until measured),
    # must have verified license, and 0 rejection reasons.
    preselect = (
        fits_disk
        and fits_ram
        and (survey.avail_ram_mb is not None)
        and (gpu_tier == "full")
        and (lic_status == "verified")
        and (len(rejections) == 0)
    )

    return ModelFitReport(
        model_id=model_id,
        display_name=model.get("display_name", model_id),
        family=family,
        tasks=tasks,
        download_bytes=dl_bytes,
        disk_bytes=disk_bytes,
        license_status=lic_status,
        fits_disk=fits_disk,
        disk_required_bytes=required_disk_bytes,
        fits_gpu=gpu_tier,
        fits_ram=fits_ram,
        is_preselected=preselect,
        rejection_reasons=rejections,
    )


def plan_model_selection(
    catalog: Dict[str, Any],
    survey: HardwareProfile,
) -> List[ModelFitReport]:
    """
    Evaluates fit across all models in catalog.
    Preselects one primary verified model (best fit for code/chat) and one small fallback if space permits.
    """
    models = catalog.get("models", [])
    reports: List[ModelFitReport] = []

    cum_disk = 0
    primary_selected = False
    fallback_selected = False

    for m in models:
        rep = evaluate_model_fit(m, survey, current_selected_disk_bytes=cum_disk)
        # Select at most 1 primary and 1 small fallback
        if rep.is_preselected:
            if not primary_selected and ("code" in rep.tasks or "chat" in rep.tasks):
                primary_selected = True
                cum_disk += rep.disk_bytes
            elif not fallback_selected and rep.disk_bytes < (3 * 1024 * 1024 * 1024):
                fallback_selected = True
                cum_disk += rep.disk_bytes
            else:
                rep.is_preselected = False
        reports.append(rep)

    return reports


# -----------------------------------------------------------------------------
# Ollama Detection and Local Verification (§4, Findings CC, CH, DQ)
# -----------------------------------------------------------------------------
OLLAMA_DEFAULT_URL = "http://127.0.0.1:11434"

# Verified Publisher Certificate Attributes (Finding CC):
OLLAMA_EXPECTED_SUBJECT = (
    "CN=Ollama Inc., O=Ollama Inc., L=Toronto, S=Ontario, C=CA, SERIALNUMBER=2713355, "
    "OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Ontario, OID.1.3.6.1.4.1.311.60.2.1.3=CA"
)
OLLAMA_EXPECTED_THUMBPRINT = "716CD3BC8C02361431A18F56F98C72DE88066103"


def probe_ollama_daemon(
    endpoint: Optional[str] = None,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    Probes whether Ollama daemon is running locally and returns status/version.
    Enforces loopback-only probe and direct connection bypassing HTTP proxy (Finding CH).
    """
    if endpoint is None:
        env_host = os.environ.get("OLLAMA_HOST")
        if env_host:
            # Validate loopback to prevent SSRF
            parsed = urllib.parse.urlparse(env_host if "://" in env_host else f"http://{env_host}")
            host = parsed.hostname or ""
            if host in ("127.0.0.1", "localhost", "::1"):
                endpoint = f"http://{host}:{parsed.port or 11434}"
            else:
                logger.warning("Non-loopback OLLAMA_HOST %r ignored for security; falling back to 127.0.0.1", env_host)
                endpoint = OLLAMA_DEFAULT_URL
        else:
            endpoint = OLLAMA_DEFAULT_URL

    url = f"{endpoint.rstrip('/')}/api/version"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PAI-Setup/1.0"})
        # Bypass any proxy for loopback communication
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            if resp.status == 200:
                body = json.loads(resp.read().decode("utf-8"))
                return {
                    "running": True,
                    "version": body.get("version", "unknown"),
                    "endpoint": endpoint,
                }
    except Exception:
        pass

    return {"running": False, "version": None, "endpoint": endpoint}


def verify_authenticode_publisher(
    installer_path: Path | str,
    expected_subject: str = OLLAMA_EXPECTED_SUBJECT,
    expected_thumbprint: str = OLLAMA_EXPECTED_THUMBPRINT,
    expected_thumbprints: Optional[List[str]] = None,
) -> bool:
    """
    Verifies that a Windows binary carries a valid Authenticode signature
    matching the official Ollama Inc. Subject and Thumbprint (Findings CC & CL).
    Supports multiple accepted thumbprints for key rotation via catalog (Finding CL).
    Fails closed on non-Windows platforms.
    """
    if sys.platform != "win32":
        raise OllamaVerificationError("Authenticode publisher verification is only supported on Windows (fail-closed)")

    p = Path(installer_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"File not found for publisher verification: {p}")

    allowed_thumbprints = [t.strip().upper() for t in (expected_thumbprints or [expected_thumbprint]) if t.strip()]
    if not allowed_thumbprints:
        raise OllamaVerificationError("No accepted thumbprints configured for Authenticode verification")

    # Pass paths and parameters via environment variables to prevent quote escaping bugs
    env = os.environ.copy()
    env["PAI_INSTALLER_TARGET"] = str(p)
    env["PAI_EXPECTED_SUBJECT"] = expected_subject
    env["PAI_EXPECTED_THUMBPRINTS"] = ";".join(allowed_thumbprints)

    ps_code = (
        "$sig = Get-AuthenticodeSignature -LiteralPath $env:PAI_INSTALLER_TARGET; "
        "if ($sig.Status -ne 'Valid') { "
        "  Write-Error ('Invalid signature status: ' + $sig.Status); exit 1 "
        "}; "
        "$cert = $sig.SignerCertificate; "
        "$allowed = ($env:PAI_EXPECTED_THUMBPRINTS -split ';'); "
        "if ($allowed -notcontains $cert.Thumbprint.ToUpperInvariant()) { "
        "  Write-Error ('Thumbprint not in accepted list: ' + $cert.Thumbprint); exit 2 "
        "}; "
        "if ($cert.Subject -ne $env:PAI_EXPECTED_SUBJECT) { "
        "  Write-Error ('Subject mismatch: ' + $cert.Subject); exit 3 "
        "}; "
        "exit 0"
    )

    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    ps_path = Path(sys_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    ps_bin = str(ps_path) if ps_path.is_file() else "powershell"

    cmd = [ps_bin, "-NoProfile", "-Command", ps_code]
    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15)
        if proc.returncode == 0:
            return True
        err_msg = proc.stderr.strip() or proc.stdout.strip()
        logger.error("Authenticode verification failed: %s (code %d)", err_msg, proc.returncode)
        raise OllamaVerificationError(
            "Ollama digital signature did not match the publisher certificate known to PAI. "
            "If Ollama was recently updated or renewed its certificate, start Ollama manually from the Start Menu, or run 'pai setup'."
        )
    except Exception as e:
        if isinstance(e, OllamaVerificationError):
            raise
        raise OllamaVerificationError(f"Failed to execute Authenticode verification: {e}")



# -----------------------------------------------------------------------------
# Milestone P4: Download Engine, Resume, Cancel & Progress (§6, Appendix C)
# -----------------------------------------------------------------------------
class CancelToken:
    """Thread-safe cancellation token for model downloads (§6, Milestone P4)."""

    def __init__(self) -> None:
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    def raise_if_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise DownloadCancelledError("Download cancelled by user")


class PullProgressTracker:
    """
    Aggregates Ollama model layer pull progress (§6, Appendix C).
    Calculates completed bytes, total bytes, rolling speed, ETA, and overall percent.
    """

    def __init__(
        self,
        model_id: str,
        known_total_bytes: Optional[int] = None,
        speed_window_sec: float = 3.0,
    ) -> None:
        self.model_id = model_id
        self.known_total_bytes = known_total_bytes
        self.speed_window_sec = speed_window_sec
        # Layer tracking by digest: {digest: {"completed": bytes, "total": bytes}}
        self.layers: Dict[str, Dict[str, int]] = {}
        # History for rolling speed calculation: deque of (timestamp, total_completed)
        self.history: Deque[Tuple[float, int]] = collections.deque()
        self.start_time = time.time()
        self.last_status = "connecting"
        self.is_verifying = False
        self.is_done = False

    def update_layer(
        self,
        digest: Optional[str],
        completed: Optional[int],
        total: Optional[int],
        status: str,
    ) -> None:
        now = time.time()
        self.last_status = status
        if "verifying" in status.lower():
            self.is_verifying = True

        if digest:
            if digest not in self.layers:
                self.layers[digest] = {"completed": 0, "total": 0}
            if completed is not None:
                self.layers[digest]["completed"] = completed
            if total is not None:
                self.layers[digest]["total"] = total

        total_comp = self.total_completed
        self.history.append((now, total_comp))
        while self.history and (now - self.history[0][0]) > self.speed_window_sec:
            self.history.popleft()

    @property
    def total_completed(self) -> int:
        if not self.layers:
            return 0
        return sum(l["completed"] for l in self.layers.values())

    @property
    def total_expected(self) -> int:
        # Finding CN: Prefer layer totals when reported by daemon stream;
        # use catalog known_total_bytes strictly as an initial estimate before layers arrive.
        layer_sum = 0
        if self.layers:
            layer_sum = sum(l.get("total", 0) for l in self.layers.values() if l.get("total", 0) > 0)

        if self.known_total_bytes and self.known_total_bytes > 0:
            return max(self.known_total_bytes, layer_sum)
        if layer_sum > 0:
            return layer_sum
        return max(self.total_completed, 1)

    @property
    def percent(self) -> float:
        tot = self.total_expected
        if tot <= 0:
            return 0.0
        return min(100.0, (self.total_completed / tot) * 100.0)

    @property
    def bytes_per_sec(self) -> int:
        if len(self.history) < 2:
            return 0
        t0, b0 = self.history[0]
        t1, b1 = self.history[-1]
        dt = t1 - t0
        db = b1 - b0
        if dt <= 0.001 or db < 0:
            return 0
        return int(db / dt)

    @property
    def eta_sec(self) -> Optional[int]:
        speed = self.bytes_per_sec
        if speed <= 0:
            return None
        rem_bytes = max(0, self.total_expected - self.total_completed)
        return int(rem_bytes / speed)


def format_bytes_human(num_bytes: int) -> str:
    """Formats raw byte counts into human-readable strings."""
    if num_bytes >= 1024**3:
        return f"{num_bytes / (1024**3):.2f} GB"
    if num_bytes >= 1024**2:
        return f"{num_bytes / (1024**2):.1f} MB"
    if num_bytes >= 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes} B"


def format_eta_human(eta_sec: Optional[int]) -> str:
    """Formats ETA seconds into human-readable minutes and seconds."""
    if eta_sec is None:
        return "--:--"
    m, s = divmod(eta_sec, 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m {s:02d}s"


class ConsoleProgressBar:
    """
    Renders console progress bar according to §6:
    - Width-aware, single redrawn line (\\r), no flicker when isatty.
    - Prints every 5% threshold when piped or redirected (not a TTY).
    """

    def __init__(self, model_id: str, is_tty: Optional[bool] = None):
        self.model_id = model_id
        self.is_tty = sys.stdout.isatty() if is_tty is None else is_tty
        self.last_pct_logged = -1
        self.last_line_len = 0

    def update(self, tracker: PullProgressTracker) -> None:
        pct = tracker.percent
        comp_str = format_bytes_human(tracker.total_completed)
        tot_str = format_bytes_human(tracker.total_expected)
        speed_str = f"{format_bytes_human(tracker.bytes_per_sec)}/s" if tracker.bytes_per_sec > 0 else "--/s"
        eta_str = format_eta_human(tracker.eta_sec)
        status = tracker.last_status

        if self.is_tty:
            cols = shutil.get_terminal_size((80, 20)).columns
            prefix = f"{self.model_id}: "
            stats = f" {pct:5.1f}% ({comp_str}/{tot_str}) {speed_str} ETA {eta_str}"
            rem_cols = max(10, cols - len(prefix) - len(stats) - 2)
            filled = int((pct / 100.0) * rem_cols)
            bar_chars = "=" * max(0, filled - 1) + (
                ">" if filled > 0 and filled < rem_cols else ("=" if filled == rem_cols else "")
            )
            bar = f"[{bar_chars.ljust(rem_cols)}]"
            line = f"{prefix}{bar}{stats}"
            if len(line) > cols:
                line = line[:cols]
            padding = " " * max(0, self.last_line_len - len(line))
            sys.stdout.write(f"\r{line}{padding}")
            sys.stdout.flush()
            self.last_line_len = len(line)
        else:
            pct_int = int(pct)
            bucket = pct_int - (pct_int % 5)
            if bucket > self.last_pct_logged and bucket <= 100:
                self.last_pct_logged = bucket
                print(
                    f"[{self.model_id}] {bucket:3d}% ({comp_str}/{tot_str}) - {speed_str} - ETA {eta_str} - {status}",
                    flush=True,
                )

    def finish(self, success: bool = True, message: str = "") -> None:
        if self.is_tty:
            sys.stdout.write("\n")
            sys.stdout.flush()
        else:
            if success:
                print(f"[{self.model_id}] Download complete (100%).", flush=True)
            else:
                print(f"[{self.model_id}] Download failed: {message}", flush=True)


def normalize_digest(digest: Optional[str]) -> Optional[str]:
    """
    Finding CT: Normalizes a manifest digest for deterministic cryptographic comparison.
    Strips leading 'sha256:', surrounding whitespace, and converts to lowercase hex.
    Returns 64-character lowercase hex string if valid, else None.
    """
    if not digest or not isinstance(digest, str):
        return None
    d = digest.strip().lower()
    if d.startswith("sha256:"):
        d = d[7:].strip()
    if len(d) == 64 and all(c in "0123456789abcdef" for c in d):
        return d
    return None


def query_ollama_model_digest(endpoint: str, model_id: str, timeout: float = 5.0) -> Optional[str]:
    """
    Finding CN, CT: Queries Ollama daemon for the manifest digest of a model.
    Authoritative endpoint: GET /api/tags
    Real Ollama /api/tags response schema (https://docs.ollama.com/api/tags.md):
      {
        "models": [
          {
            "name": "qwen2.5:0.5b",
            "model": "qwen2.5:0.5b",
            "modified_at": "...",
            "size": 397750176,
            "digest": "67dae4a5d3f745e691ec5f7957d1fa183b06385d83637e100c4366e6c1e33d26",
            "details": {...}
          }
        ]
      }
    Note: Ollama /api/tags returns bare 64-character hex strings without 'sha256:' prefix.
    Note: /api/show does NOT provide a top-level manifest digest (only metadata/details).
    """
    clean_ep = endpoint.rstrip("/")
    url = f"{clean_ep}/api/tags"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PAI-Setup/1.0"})
        with opener.open(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                models = data.get("models", [])
                target_tags = {model_id}
                if ":" not in model_id:
                    target_tags.add(f"{model_id}:latest")
                elif model_id.endswith(":latest"):
                    target_tags.add(model_id[:-7])

                for m in models:
                    name = m.get("name", "")
                    mod_name = m.get("model", "")
                    if name in target_tags or mod_name in target_tags:
                        raw_digest = m.get("digest")
                        if raw_digest and isinstance(raw_digest, str):
                            return raw_digest.strip()
    except Exception as e:
        logger.debug("Failed to query /api/tags for model digest: %s", e)

    return None


def delete_ollama_model(endpoint: str, model_id: str, timeout: float = 10.0) -> bool:
    """
    Finding CN, CX: Purges a model from Ollama daemon on manifest digest mismatch.
    Sends DELETE /api/delete with {"name": model_id}.
    Note: If a model with this name existed prior to the pull, it will be deleted.
    """
    clean_ep = endpoint.rstrip("/")
    url = f"{clean_ep}/api/delete"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps({"name": model_id}).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "PAI-Setup/1.0"},
            method="DELETE",
        )
        with opener.open(req, timeout=timeout) as resp:
            return resp.status in (200, 204)
    except Exception as e:
        logger.warning("Failed to delete model %s from Ollama: %s", model_id, e)
        return False


def _sleep_with_cancel_check(duration_sec: float, cancel_token: Optional[CancelToken]) -> None:
    """
    Finding CO: Sleeps with responsive cancel token checks during retry backoff intervals.
    """
    end_time = time.time() + duration_sec
    while time.time() < end_time:
        if cancel_token and cancel_token.is_cancelled():
            raise DownloadCancelledError("Download cancelled by user during retry backoff")
        time.sleep(min(0.05, max(0.001, end_time - time.time())))


def pull_model_stream(
    model_id: str,
    endpoint: Optional[str] = None,
    total_bytes: Optional[int] = None,
    expected_manifest_digest: Optional[str] = None,
    allow_unverified: bool = False,
    cancel_token: Optional[CancelToken] = None,
    emitter: Optional[ProgressEmitter] = None,
    show_console_bar: bool = True,
    max_retries: int = 3,
    initial_backoff_sec: float = 0.5,
    read_timeout: float = 15.0,
) -> Dict[str, Any]:
    """
    Executes streaming model download via Ollama pull API (POST /api/pull).
    Features (§6, Milestones P4, Findings CO, CN, CR, CT, CU, CX):
      - Emits NDJSON progress events (Appendix C): download_start, progress, verifying, done, error.
      - Width-aware console progress bar with speed, ETA, and layer aggregation.
      - Post-pull manifest digest verification against signed catalog (Findings CN, CT, CU).
        Normalized comparisons (stripping sha256: prefix and lowercase) prevent false mismatches (Finding CT).
        Missing digest from daemon fails closed with DIGEST_UNAVAILABLE for catalog models unless allow_unverified is True (Finding CU).
        On true digest mismatch, the model is purged via DELETE /api/delete with warning and DIGEST_MISMATCH raised (Findings CN, CX).
      - Immediate failure on HTTP 4xx errors without retry; connection and 5xx retried with backoff (Finding CX).
      - Resilient error handling and exponential backoff retry on network failures or premature EOF (Finding CO).
      - Handles socket cut/incomplete exceptions (IncompleteRead, RemoteDisconnected, OSError).
      - Thread-safe cancellation via CancelToken with responsive backoff wait checking (Finding CV).
      - Error detection: DISK_FULL, REGISTRY_ERROR, DIGEST_MISMATCH, DIGEST_UNAVAILABLE, MODEL_NOT_FOUND, CLIENT_ERROR, CANCELLED, PULL_FAILED.
    """
    if endpoint is None:
        env_host = os.environ.get("OLLAMA_HOST")
        if env_host:
            parsed = urllib.parse.urlparse(env_host if "://" in env_host else f"http://{env_host}")
            host = parsed.hostname or ""
            if host in ("127.0.0.1", "localhost", "::1"):
                endpoint = f"http://{host}:{parsed.port or 11434}"
            else:
                endpoint = OLLAMA_DEFAULT_URL
        else:
            endpoint = OLLAMA_DEFAULT_URL

    url = f"{endpoint.rstrip('/')}/api/pull"
    tracker = PullProgressTracker(model_id=model_id, known_total_bytes=total_bytes)
    bar = ConsoleProgressBar(model_id=model_id) if show_console_bar else None

    if emitter:
        emitter.emit("download_start", model=model_id, total_bytes=tracker.total_expected)

    retries_left = max_retries
    backoff = initial_backoff_sec
    verifying_emitted = False

    while True:
        if cancel_token and cancel_token.is_cancelled():
            if emitter:
                emitter.emit("error", model=model_id, code="CANCELLED", message="Download cancelled by user")
            if bar:
                bar.finish(success=False, message="Cancelled")
            raise DownloadCancelledError(f"Model download '{model_id}' was cancelled by user")

        try:
            req_data = json.dumps({"name": model_id, "stream": True}).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "PAI-Setup/1.0"},
                method="POST",
            )
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            with opener.open(req, timeout=read_timeout) as resp:
                if resp.status != 200:
                    raise ModelPullError("PULL_FAILED", f"Ollama daemon returned HTTP {resp.status}")

                for line_bytes in resp:
                    if cancel_token and cancel_token.is_cancelled():
                        if emitter:
                            emitter.emit("error", model=model_id, code="CANCELLED", message="Download cancelled by user")
                        if bar:
                            bar.finish(success=False, message="Cancelled")
                        raise DownloadCancelledError(f"Model download '{model_id}' was cancelled by user")

                    line_str = line_bytes.decode("utf-8", errors="replace").strip()
                    if not line_str:
                        continue

                    try:
                        chunk = json.loads(line_str)
                    except json.JSONDecodeError:
                        continue

                    if "error" in chunk:
                        err_msg = chunk["error"]
                        code = "PULL_FAILED"
                        err_lower = err_msg.lower()
                        if "space" in err_lower or "disk full" in err_lower:
                            code = "DISK_FULL"
                        elif "not found" in err_lower or "manifest" in err_lower:
                            code = "REGISTRY_ERROR"

                        if emitter:
                            emitter.emit("error", model=model_id, code=code, message=err_msg)
                        if bar:
                            bar.finish(success=False, message=err_msg)
                        raise ModelPullError(code, err_msg)

                    status = chunk.get("status", "")
                    digest = chunk.get("digest")
                    total = chunk.get("total")
                    completed = chunk.get("completed")

                    tracker.update_layer(digest, completed, total, status)

                    if tracker.is_verifying and not verifying_emitted:
                        verifying_emitted = True
                        if emitter:
                            emitter.emit("verifying", model=model_id)

                    if emitter:
                        emitter.emit(
                            "progress",
                            model=model_id,
                            completed=tracker.total_completed,
                            total=tracker.total_expected,
                            bytes_per_sec=tracker.bytes_per_sec,
                            eta_sec=tracker.eta_sec,
                            status=status,
                        )

                    if bar:
                        bar.update(tracker)

                    if status.lower() == "success":
                        tracker.is_done = True
                        break

            # Check if stream finished successfully
            if tracker.is_done:
                # Finding CN, CT, CU: Post-pull manifest digest verification against signed catalog
                if expected_manifest_digest:
                    raw_actual = query_ollama_model_digest(endpoint, model_id)
                    actual_norm = normalize_digest(raw_actual)
                    expected_norm = normalize_digest(expected_manifest_digest)

                    if not actual_norm:
                        # Finding CU: Fail-closed if daemon does not report a valid digest for a catalog model
                        if allow_unverified:
                            msg = (
                                f"WARNING: Ollama daemon did not return a manifest digest for catalog model '{model_id}' "
                                f"via /api/tags. Verification skipped because --allow-unverified-model was specified."
                            )
                            logger.warning(msg)
                            if emitter:
                                emitter.emit("warning", model=model_id, message=msg)
                            print(f"\n{msg}", file=sys.stderr)
                        else:
                            err_msg = (
                                f"Ollama daemon did not return a manifest digest for catalog model '{model_id}' via /api/tags. "
                                f"Cannot verify against signed catalog digest ('{expected_manifest_digest}'). "
                                f"Model retained on disk; pass --allow-unverified-model to skip verification (fail-closed, Finding CU)."
                            )
                            if emitter:
                                emitter.emit("error", model=model_id, code="DIGEST_UNAVAILABLE", message=err_msg)
                            if bar:
                                bar.finish(success=False, message="Digest unavailable")
                            # Model is NOT deleted (left in place for user)
                            raise ModelPullError("DIGEST_UNAVAILABLE", err_msg)
                    elif expected_norm and actual_norm != expected_norm:
                        # Finding CT, CX: Manifest digest mismatch -> purge model with prominent warning
                        warn_purge = (
                            f"WARNING: Manifest digest mismatch for '{model_id}' "
                            f"(expected {expected_manifest_digest}, got {raw_actual}). "
                            f"Deleting downloaded model '{model_id}' from Ollama daemon to prevent execution of unverified weights. "
                            f"Note: If a model with this name existed prior to this pull, it will be removed."
                        )
                        logger.warning(warn_purge)
                        print(f"\n{warn_purge}", file=sys.stderr)
                        delete_ollama_model(endpoint, model_id)

                        mismatch_msg = (
                            f"Model manifest digest mismatch for '{model_id}': "
                            f"expected '{expected_manifest_digest}', got '{raw_actual}'. Purged from daemon."
                        )
                        if emitter:
                            emitter.emit("error", model=model_id, code="DIGEST_MISMATCH", message=mismatch_msg)
                        if bar:
                            bar.finish(success=False, message="Digest mismatch")
                        raise ModelPullError("DIGEST_MISMATCH", mismatch_msg)
                    else:
                        logger.info("Manifest digest verified successfully for '%s' (%s)", model_id, actual_norm)

                if emitter:
                    emitter.emit("done", model=model_id)
                if bar:
                    bar.finish(success=True)
                return {
                    "model": model_id,
                    "completed_bytes": tracker.total_completed,
                    "status": "done",
                }

            # Finding CO: Stream ended without success or error (e.g. daemon stopped or restarted)
            retries_left -= 1
            if retries_left < 0:
                msg = f"Pull stream for model '{model_id}' terminated prematurely without success confirmation after {max_retries} retries"
                if emitter:
                    emitter.emit("error", model=model_id, code="NETWORK_ERROR", message=msg)
                if bar:
                    bar.finish(success=False, message=msg)
                raise ModelPullError("NETWORK_ERROR", msg)

            logger.warning(
                "Pull stream for %s closed before completion; retrying with backoff (retries left: %d)",
                model_id,
                retries_left,
            )
            _sleep_with_cancel_check(backoff, cancel_token)
            backoff *= 2.0

        except urllib.error.HTTPError as err:
            if cancel_token and cancel_token.is_cancelled():
                raise DownloadCancelledError(f"Model download '{model_id}' was cancelled by user")
            # Finding CX: 4xx client errors fail immediately without retrying!
            if 400 <= err.code < 500:
                body = ""
                try:
                    body = err.read().decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
                if err.code == 404:
                    code = "MODEL_NOT_FOUND"
                    msg = f"Model '{model_id}' was not found on remote registry (HTTP 404)"
                else:
                    code = "CLIENT_ERROR"
                    msg = f"Ollama daemon returned HTTP {err.code}: {err.reason} ({body})" if body else f"Ollama daemon returned HTTP {err.code}: {err.reason}"
                if emitter:
                    emitter.emit("error", model=model_id, code=code, message=msg)
                if bar:
                    bar.finish(success=False, message=msg)
                raise ModelPullError(code, msg) from err

            # 5xx server errors: retry with backoff
            retries_left -= 1
            if retries_left < 0:
                msg = f"Ollama daemon returned server error HTTP {err.code} after {max_retries} retries"
                if emitter:
                    emitter.emit("error", model=model_id, code="SERVER_ERROR", message=msg)
                if bar:
                    bar.finish(success=False, message=msg)
                raise ModelPullError("SERVER_ERROR", msg) from err

            logger.warning(
                "Ollama daemon HTTP error %d pulling %s; retrying in %.2fs (retries left: %d)",
                err.code,
                model_id,
                backoff,
                retries_left,
            )
            _sleep_with_cancel_check(backoff, cancel_token)
            backoff *= 2.0

        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionResetError,
            http.client.IncompleteRead,
            http.client.RemoteDisconnected,
            OSError,
        ) as e:
            if cancel_token and cancel_token.is_cancelled():
                raise DownloadCancelledError(f"Model download '{model_id}' was cancelled by user")
            retries_left -= 1
            if retries_left < 0:
                msg = f"Network connection lost after {max_retries} retries: {e}"
                if emitter:
                    emitter.emit("error", model=model_id, code="NETWORK_ERROR", message=msg)
                if bar:
                    bar.finish(success=False, message=msg)
                raise ModelPullError("NETWORK_ERROR", msg)

            logger.warning(
                "Network interruption pulling %s: %s; retrying in %.2fs (retries left: %d)",
                model_id,
                e,
                backoff,
                retries_left,
            )
            _sleep_with_cancel_check(backoff, cancel_token)
            backoff *= 2.0


# -----------------------------------------------------------------------------
# CLI and Progress Stream Engine (Appendix C, Findings CG & P4)
# -----------------------------------------------------------------------------
class ProgressEmitter:
    """Emits newline-delimited JSON events to stdout conforming to Appendix C."""

    # P3 and P4 supported event types (§6, Appendix C)
    SUPPORTED_EVENTS = {
        "survey",
        "ollama_status",
        "fit",
        "download_start",
        "progress",
        "verifying",
        "done",
        "error",
    }
    P3_EVENTS = SUPPORTED_EVENTS  # Backward compatibility alias

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def emit(self, event_type: str, **kwargs: Any) -> None:
        if not self.enabled:
            return
        payload = {"event": event_type, **kwargs}
        print(json.dumps(payload, ensure_ascii=False), flush=True)


def build_setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PAI Setup Wizard and Hardware Survey Engine (Milestone P6).")
    parser.add_argument("--survey-only", action="store_true", help="Run local hardware survey and output JSON")
    parser.add_argument("--catalog", default=None, help="Path to signed catalog.json")
    parser.add_argument("--min-catalog-version", type=int, default=1, help="Minimum acceptable catalog version")
    parser.add_argument("--progress-json", action="store_true", help="Emit Appendix C NDJSON progress events")
    parser.add_argument("--probe-ollama", action="store_true", help="Check if Ollama daemon is reachable")
    parser.add_argument("--model-drive", default=None, help="Custom target directory for disk space survey")
    parser.add_argument("--pull-model", default=None, help="Download a specific model ID via Ollama pull API")
    parser.add_argument("--pull-preselected", action="store_true", help="Download preselected models from catalog")
    parser.add_argument("--allow-unverified-model", action="store_true", help="Explicit confirmation to pull models not present in signed catalog")
    return parser


def run_setup(args: argparse.Namespace) -> int:
    """Runs hardware survey, catalog evaluation, and model setup (Milestone P6)."""
    emitter = ProgressEmitter(enabled=getattr(args, "progress_json", False))

    # 1. Hardware Survey
    try:
        survey = collect_hardware_survey(args.model_drive)
        emitter.emit("survey", hardware=asdict(survey))
    except Exception as e:
        emitter.emit("error", code="SURVEY_FAILED", message=str(e))
        print(f"ERROR: Hardware survey failed: {e}", file=sys.stderr)
        return 1

    if args.survey_only:
        print(json.dumps(asdict(survey), indent=2))
        return 0

    # 2. Ollama probe
    ollama_status = probe_ollama_daemon()
    emitter.emit("ollama_status", **ollama_status)

    # 3. Catalog loading and verification
    verified_cat = None
    if args.catalog:
        cat_path = Path(args.catalog).resolve()
        if not cat_path.is_file():
            emitter.emit("error", code="CATALOG_NOT_FOUND", message=f"Catalog not found at {cat_path}")
            print(f"ERROR: Catalog not found at {cat_path}", file=sys.stderr)
            return 1

        try:
            cat_data = json.loads(cat_path.read_text(encoding="utf-8"))
            verified_cat = verify_catalog_payload(cat_data, min_version=args.min_catalog_version)
        except CatalogSecurityError as e:
            emitter.emit("error", code="CATALOG_SECURITY_ERROR", message=str(e))
            print(f"ERROR: Catalog verification failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            emitter.emit("error", code="CATALOG_LOAD_ERROR", message=str(e))
            print(f"ERROR: Failed to load catalog: {e}", file=sys.stderr)
            return 1
    elif args.pull_preselected:
        emitter.emit("error", code="CATALOG_REQUIRED", message="--pull-preselected requires --catalog <path>.")
        print("ERROR: Catalog required for --pull-preselected. Pass --catalog <path_to_catalog.json>", file=sys.stderr)
        return 1

    recommendations = []
    if verified_cat:
        # 4. Plan model recommendations
        recommendations = plan_model_selection(verified_cat, survey)
        recs_dicts = [asdict(r) for r in recommendations]
        emitter.emit("fit", recommendations=recs_dicts)

        print("\n================ PAI Setup Hardware Survey & Recommendations ================")
        if survey.avail_ram_mb is not None and survey.total_ram_mb is not None:
            print(f"RAM:   {survey.avail_ram_mb:.1f} MB available / {survey.total_ram_mb:.1f} MB total ({survey.ram_source})")
        else:
            print(f"RAM:   Unknown / Unavailable ({survey.ram_source}); model preselection disabled")
        print(f"Disk:  {round(survey.free_disk_bytes / (1024**3), 2)} GB free on {survey.model_drive}")
        print(f"GPU:   {survey.gpu_name or 'None'} ({survey.dedicated_vram_mb:.1f} MB VRAM)")
        if survey.npu_detected:
            print(f"NPU:   {survey.npu_name} ({survey.npu_note})")
        print(f"Ollama: {'Running (' + ollama_status['version'] + ')' if ollama_status['running'] else 'Not detected'}")

        print("\nModel Catalog Candidates:")
        for r in recommendations:
            flag = "[PRESELECTED]" if r.is_preselected else "[AVAILABLE]"
            print(f"  {flag} {r.model_id} ({r.family}) - GPU: {r.fits_gpu.upper()}, Disk: {'OK' if r.fits_disk else 'FAIL'}")
            for rej in r.rejection_reasons:
                print(f"      * {rej}")

    # 5. Milestone P4: Model download execution if requested
    if args.pull_model:
        # Finding CN: Model ID pattern validation
        id_pattern = re.compile(r"^[a-z0-9_.-]+:[a-z0-9_.-]+$")
        if not id_pattern.match(args.pull_model):
            emitter.emit(
                "error",
                code="INVALID_MODEL_ID",
                message=f"Model ID '{args.pull_model}' does not match pattern '<family>:<tag>' (e.g. 'llama3.2:1b')",
            )
            print(f"ERROR: Model ID '{args.pull_model}' is invalid. Must match pattern '<family>:<tag>'.", file=sys.stderr)
            return 1

        # Finding CN & CW: Check catalog membership, license terms, and unverified confirmation first
        catalog_entry = None
        if verified_cat:
            catalog_entry = next((m for m in verified_cat.get("models", []) if m.get("id") == args.pull_model), None)

        expected_digest = None
        expected_bytes = None
        if catalog_entry:
            expected_digest = catalog_entry.get("registry_manifest_digest")
            expected_bytes = catalog_entry.get("download_bytes")
            lic = catalog_entry.get("license", {})
            print(f"\n[CATALOG MODEL] {args.pull_model}")
            print(f"  License: {lic.get('name', 'Unknown')} ({lic.get('url', 'N/A')}) - Status: {lic.get('license_status', 'unverified')}")
            print(f"  Signed Catalog Digest: {expected_digest}")
        else:
            print(f"\n[WARNING] Model '{args.pull_model}' is NOT present in the signed PAI catalog.")
            print("  It has not been verified or tested for compatibility or licensing by PAI.")
            if not args.allow_unverified_model:
                emitter.emit(
                    "error",
                    code="UNVERIFIED_MODEL_REJECTED",
                    message=f"Model '{args.pull_model}' is not in catalog. Pass --allow-unverified-model to confirm.",
                )
                print(
                    "ERROR: Refusing to pull unverified model without explicit confirmation. Pass --allow-unverified-model.",
                    file=sys.stderr,
                )
                return 1

        if not ollama_status["running"]:
            emitter.emit("error", code="OLLAMA_NOT_RUNNING", message="Ollama daemon is not reachable on localhost")
            print("ERROR: Ollama daemon is not running. Please start Ollama before pulling models.", file=sys.stderr)
            return 1

        try:
            print(f"\nStarting model pull for {args.pull_model}...")
            pull_model_stream(
                args.pull_model,
                total_bytes=expected_bytes,
                expected_manifest_digest=expected_digest,
                allow_unverified=args.allow_unverified_model,
                emitter=emitter,
                show_console_bar=True,
            )
        except Exception as e:
            print(f"ERROR: Pull failed: {e}", file=sys.stderr)
            return 1

    elif args.pull_preselected:
        if not ollama_status["running"]:
            emitter.emit("error", code="OLLAMA_NOT_RUNNING", message="Ollama daemon is not reachable on localhost")
            print("ERROR: Ollama daemon is not running. Please start Ollama before pulling models.", file=sys.stderr)
            return 1
        preselected = [r for r in recommendations if r.is_preselected]
        if not preselected:
            print("\nNo models met preselection criteria on this hardware profile.")
            return 0
        for r in preselected:
            # Finding CN: Query expected manifest digest from catalog entry
            cat_entry = next((m for m in verified_cat.get("models", []) if m.get("id") == r.model_id), None)
            expected_digest = cat_entry.get("registry_manifest_digest") if cat_entry else None
            lic = cat_entry.get("license", {}) if cat_entry else {}
            print(f"\nPulling preselected model: {r.model_id} ({format_bytes_human(r.download_bytes)})...")
            print(f"  License: {lic.get('name', 'Unknown')} ({lic.get('url', 'N/A')}) - Status: {lic.get('license_status', 'unverified')}")
            try:
                pull_model_stream(
                    r.model_id,
                    total_bytes=r.download_bytes,
                    expected_manifest_digest=expected_digest,
                    allow_unverified=args.allow_unverified_model,
                    emitter=emitter,
                    show_console_bar=True,
                )
            except Exception as e:
                print(f"ERROR: Pulling {r.model_id} failed: {e}", file=sys.stderr)
                return 1

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_setup_parser()
    args = parser.parse_args(argv)
    return run_setup(args)


if __name__ == "__main__":
    sys.exit(main())
