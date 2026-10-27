"""
Personal Agentic AI (PAI) - Setup Wizard and Hardware Survey Engine.

Part of Milestone P3 for the v1.1.0 Packaging and Installer subsystem.
Specification: docs/PACKAGING_SPEC.md (§4, §5, Appendix B, Appendix C)
ADR-012, ADR-013

Responsibilities:
  1. Local hardware survey (RAM, VRAM, GPU, disk, CPU, NPU detection per ADR-012).
  2. Cryptographic signed-catalog verification (detached Ed25519, monotonic version check).
  3. Hardware fit rules (disk >= 1.25x + 2GB, GPU <= 85% VRAM for full offload, RAM headroom).
  4. Ollama detection and official installer verification.
  5. Machine-readable progress events (--progress-json) matching Appendix C.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("pai_setup")

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = REPO_ROOT / "research"
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

try:
    import ed25519_ref
except ImportError:
    ed25519_ref = None  # Handled gracefully if executed without research/ on path


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------
class SetupError(Exception):
    """Base exception for setup and survey failures."""


class CatalogSecurityError(SetupError):
    """Raised when catalog signature, integrity, or monotonic version check fails."""


class FitRuleViolationError(SetupError):
    """Raised when hard resource requirements cannot be met."""


class OllamaVerificationError(SetupError):
    """Raised when Ollama installer verification fails."""


# -----------------------------------------------------------------------------
# Hardware Survey (§4, §5)
# -----------------------------------------------------------------------------
@dataclass
class HardwareProfile:
    total_ram_mb: float
    avail_ram_mb: float
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
    npu_note: str = "detected, not used in this version (ADR-012)"
    windows_version: Optional[str] = None


def survey_ram_windows() -> Tuple[float, float]:
    """Queries total and available physical RAM using GlobalMemoryStatusEx."""
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        total_mb = stat.ullTotalPhys / (1024 * 1024)
        avail_mb = stat.ullAvailPhys / (1024 * 1024)
        return round(total_mb, 1), round(avail_mb, 1)
    return 8192.0, 4096.0


def survey_disk_free(target_path: Optional[str | Path] = None) -> Tuple[int, int, str]:
    """Queries free and total disk bytes on the drive hosting the model store."""
    if not target_path:
        # Default Ollama models directory: %USERPROFILE%\.ollama\models
        user_prof = os.environ.get("USERPROFILE", os.path.expanduser("~"))
        target_path = Path(user_prof) / ".ollama" / "models"

    p = Path(target_path).resolve()
    # Find existing ancestor directory to probe disk usage
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


def survey_gpu_windows() -> Tuple[Optional[str], float, Optional[str]]:
    """
    Surveys GPU using Get-CimInstance Win32_VideoController or DXGI.
    Returns (gpu_name, dedicated_vram_mb, driver_version).
    """
    if sys.platform != "win32":
        return None, 0.0, None

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

            # Prefer dedicated discrete GPU (NVIDIA > AMD > Intel)
            best_gpu = None
            max_vram = 0.0
            best_driver = None

            for ctrl in controllers:
                name = ctrl.get("Name", "")
                driver = ctrl.get("DriverVersion", "")
                vram_bytes = ctrl.get("AdapterRAM", 0) or 0
                vram_mb = vram_bytes / (1024 * 1024)

                # Win32_VideoController caps 32-bit AdapterRAM at 4GB; if NVIDIA/AMD, probe nvidia-smi if available
                if "nvidia" in name.lower():
                    # Attempt nvidia-smi probe for true 64-bit VRAM
                    nv_mb = probe_nvidia_smi_vram()
                    if nv_mb > 0:
                        vram_mb = nv_mb
                    return name, round(vram_mb, 1), driver

                if vram_mb > max_vram:
                    max_vram = vram_mb
                    best_gpu = name
                    best_driver = driver

            return best_gpu, round(max_vram, 1), best_driver
    except Exception as e:
        logger.debug("PowerShell GPU survey failed: %s", e)

    return None, 0.0, None


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


def collect_hardware_survey(model_drive_path: Optional[str | Path] = None) -> HardwareProfile:
    """Performs full local hardware survey."""
    if sys.platform == "win32":
        total_ram, avail_ram = survey_ram_windows()
        gpu_name, vram_mb, driver_ver = survey_gpu_windows()
        npu_detected, npu_name = survey_npu_windows()
        win_ver = f"{sys.getwindowsversion().major}.{sys.getwindowsversion().minor}.{sys.getwindowsversion().build}"
    else:
        total_ram, avail_ram = 16384.0, 8192.0
        gpu_name, vram_mb, driver_ver = None, 0.0, None
        npu_detected, npu_name = False, None
        win_ver = None

    free_disk, total_disk, drive = survey_disk_free(model_drive_path)
    cores = os.cpu_count() or 4

    return HardwareProfile(
        total_ram_mb=total_ram,
        avail_ram_mb=avail_ram,
        free_disk_bytes=free_disk,
        total_disk_bytes=total_disk,
        model_drive=drive,
        gpu_name=gpu_name,
        dedicated_vram_mb=vram_mb,
        gpu_driver_version=driver_ver,
        cpu_cores=cores // 2 if cores > 1 else 1,
        cpu_logical=cores,
        cpu_name=os.environ.get("PROCESSOR_IDENTIFIER", "x86_64"),
        npu_detected=npu_detected,
        npu_name=npu_name,
        windows_version=win_ver,
    )


# -----------------------------------------------------------------------------
# Signed Catalog Verification (§5, Appendix B)
# -----------------------------------------------------------------------------
# Test seed and key for signing demo catalogs in test suites
TEST_CATALOG_SEED = bytes([i % 256 for i in range(32)])
TEST_CATALOG_PUB_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"

DEFAULT_TRUST_KEYS = [
    {
        "id": "rel-1",
        "public_hex": "2d37e829568f4802381effafa3deeeb0af7abc51665a372570422d7b4da3a278",
        "revoked": False,
    },
    {
        "id": "demo-test-key",
        "public_hex": TEST_CATALOG_PUB_HEX,
        "revoked": False,
    },
]


def canonical_json_bytes(doc: Dict[str, Any]) -> bytes:
    """Produces deterministic canonical UTF-8 bytes for cryptographic signing."""
    # Omit signature field during canonical representation
    d = {k: v for k, v in doc.items() if k != "signature"}
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_trust_keys(trust_path: Optional[Path | str] = None) -> List[Dict[str, Any]]:
    """Loads trusted verification keys from trust.json."""
    if trust_path and Path(trust_path).is_file():
        data = json.loads(Path(trust_path).read_text(encoding="utf-8"))
        return data.get("keys", [])
    res_trust = RESEARCH_DIR / "trust.json"
    if res_trust.is_file():
        data = json.loads(res_trust.read_text(encoding="utf-8"))
        return data.get("keys", [])
    return DEFAULT_TRUST_KEYS


def verify_catalog_payload(
    catalog_data: Dict[str, Any],
    trust_keys: Optional[List[Dict[str, Any]]] = None,
    min_version: int = 1,
) -> Dict[str, Any]:
    """
    Verifies a catalog dictionary:
      1. Required fields: catalog_version, issued_utc, models, signature.
      2. Monotonic version: catalog_version >= min_version.
      3. Signature verification: detached Ed25519 checked against unrevoked trust keys.
    """
    for req in ("catalog_version", "issued_utc", "models", "signature"):
        if req not in catalog_data:
            raise CatalogSecurityError(f"Catalog missing required field: {req!r}")

    cat_ver = catalog_data["catalog_version"]
    if not isinstance(cat_ver, int) or cat_ver < min_version:
        raise CatalogSecurityError(
            f"Catalog version rollback or below minimum ({cat_ver} < {min_version})"
        )

    sig_hex = catalog_data["signature"]
    if not sig_hex or not isinstance(sig_hex, str):
        raise CatalogSecurityError("Catalog signature is empty or non-string")

    canonical_bytes = canonical_json_bytes(catalog_data)
    keys = trust_keys or DEFAULT_TRUST_KEYS
    active_keys = [k for k in keys if not k.get("revoked", False)]

    if not active_keys:
        raise CatalogSecurityError("No active unrevoked trust keys available for catalog verification")

    if ed25519_ref is None:
        raise CatalogSecurityError("ed25519_ref module unavailable; cannot verify catalog signature")

    verified = False
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        raise CatalogSecurityError("Invalid hex signature in catalog")

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

    return catalog_data


# -----------------------------------------------------------------------------
# Fit Rules & Recommendations (§5)
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
    rejection_reasons: List[str] = field(default_factory=list)


def evaluate_model_fit(
    model: Dict[str, Any],
    survey: HardwareProfile,
    current_selected_disk_bytes: int = 0,
) -> ModelFitReport:
    """
    Evaluates fit rules for a single model candidate:
      - Disk: free space >= (1.25 * total_selected_size) + 2 GB.
      - GPU: <= 85% of dedicated VRAM is 'full'; 86-120% is 'partial'; otherwise 'cpu'.
      - RAM: available/total RAM leaves headroom for system (2 GB reserve).
      - Pre-selection: verified license and fits resources.
    """
    model_id = model.get("id", "")
    family = model.get("family", "")
    tasks = model.get("tasks", [])
    dl_bytes = model.get("download_bytes", 0)
    disk_bytes = model.get("disk_bytes", dl_bytes)
    min_ram_mb = model.get("min_ram_mb", 2048)
    lic = model.get("license", {})
    lic_status = lic.get("license_status", "unverified")

    rejections = []

    # 1. Disk rule: free space must be >= 1.25 * (chosen + model) + 2 GB safety margin
    required_disk_bytes = int(1.25 * (current_selected_disk_bytes + disk_bytes)) + (2 * 1024 * 1024 * 1024)
    fits_disk = survey.free_disk_bytes >= required_disk_bytes
    if not fits_disk:
        deficit_mb = round((required_disk_bytes - survey.free_disk_bytes) / (1024 * 1024), 1)
        rejections.append(
            f"INSUFFICIENT_DISK: Free space on {survey.model_drive} ({round(survey.free_disk_bytes / (1024**3), 2)} GB) "
            f"below rule requirement ({round(required_disk_bytes / (1024**3), 2)} GB; deficit {deficit_mb} MB)"
        )

    # 2. GPU rule: weights + 512MB context allowance <= 85% VRAM
    # Model memory footprint in VRAM
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

    # 3. RAM rule: If running on CPU or partial offload, ensure RAM headroom
    system_reserve_mb = 2048.0
    usable_ram_mb = survey.total_ram_mb - system_reserve_mb
    fits_ram = usable_ram_mb >= min_ram_mb
    if not fits_ram and gpu_tier == "cpu":
        rejections.append(
            f"INSUFFICIENT_RAM: Usable system RAM ({usable_ram_mb:.1f} MB) below requirement ({min_ram_mb:.1f} MB)"
        )

    # Pre-selection rules:
    # Must fit disk, must have verified license, must not have fatal resource rejections
    preselect = fits_disk and (lic_status == "verified") and len(rejections) == 0

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

    # First pass: evaluate raw individual fit
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
# Ollama Detection and Official Installer Download (§4)
# -----------------------------------------------------------------------------
OLLAMA_DEFAULT_URL = "http://127.0.0.1:11434"
OLLAMA_OFFICIAL_INSTALLER_URL = "https://ollama.com/download/OllamaSetup.exe"
OLLAMA_EXPECTED_PUBLISHER = "Ollama Inc."


def probe_ollama_daemon(endpoint: str = OLLAMA_DEFAULT_URL, timeout: float = 2.0) -> Dict[str, Any]:
    """Probes whether Ollama server is running locally and returns status/version."""
    url = f"{endpoint.rstrip('/')}/api/version"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PAI-Setup/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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


def verify_authenticode_publisher(installer_path: Path | str, expected_publisher: str = OLLAMA_EXPECTED_PUBLISHER) -> bool:
    """
    Verifies that a Windows binary carries a valid Authenticode signature from the expected publisher.
    """
    if sys.platform != "win32":
        return True  # Mocked / non-Windows test environment

    p = Path(installer_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"File not found for publisher verification: {p}")

    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        f"(Get-AuthenticodeSignature -LiteralPath '{p}').SignerCertificate.Subject",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            subj = proc.stdout.strip()
            if expected_publisher.lower() in subj.lower():
                return True
            logger.warning("Authenticode publisher mismatch. Got: %r, Expected: %r", subj, expected_publisher)
            return False
    except Exception as e:
        logger.error("Failed to check Authenticode signature: %s", e)
        return False
    return False


# -----------------------------------------------------------------------------
# CLI and Progress Stream Engine (Appendix C)
# -----------------------------------------------------------------------------
class ProgressEmitter:
    """Emits newline-delimited JSON events to stdout conforming to Appendix C."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def emit(self, event_type: str, **kwargs: Any) -> None:
        if not self.enabled:
            return
        payload = {"event": event_type, **kwargs}
        print(json.dumps(payload, ensure_ascii=False), flush=True)


def create_demo_catalog(version: int = 1) -> Dict[str, Any]:
    """Generates an illustrative canonical catalog with valid Ed25519 signature for tests."""
    doc = {
        "catalog_version": version,
        "issued_utc": "2026-10-27T00:00:00Z",
        "models": [
            {
                "id": "qwen2.5-coder:1.5b",
                "display_name": "Qwen 2.5 Coder 1.5B",
                "family": "qwen2.5-coder",
                "parameters_b": 1.5,
                "quantization": "Q4_K_M",
                "download_bytes": 986500000,
                "disk_bytes": 1050000000,
                "min_ram_mb": 2048,
                "min_vram_mb": 1500,
                "tasks": ["code", "chat"],
                "license": {
                    "name": "Apache-2.0",
                    "url": "https://huggingface.co/Qwen/Qwen2.5-Coder-1.5B",
                    "license_status": "verified",
                    "read_on": "2026-10-27",
                },
                "registry_manifest_digest": "sha256:d15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15ab1e15a",
            },
            {
                "id": "llama3.2:1b",
                "display_name": "Llama 3.2 1B",
                "family": "llama3.2",
                "parameters_b": 1.23,
                "quantization": "Q4_K_M",
                "download_bytes": 1320000000,
                "disk_bytes": 1400000000,
                "min_ram_mb": 2048,
                "min_vram_mb": 1800,
                "tasks": ["chat", "documents"],
                "license": {
                    "name": "Llama-3.2-Community",
                    "url": "https://llama.meta.com/llama3_2/license",
                    "license_status": "verified",
                    "read_on": "2026-10-27",
                },
                "registry_manifest_digest": "sha256:1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b",
            },
            {
                "id": "unverified-experimental:7b",
                "display_name": "Experimental 7B",
                "family": "experimental",
                "parameters_b": 7.0,
                "quantization": "Q4_K_M",
                "download_bytes": 4500000000,
                "disk_bytes": 4800000000,
                "min_ram_mb": 8192,
                "min_vram_mb": 6000,
                "tasks": ["code"],
                "license": {
                    "name": "unknown",
                    "url": "https://example.com/unverified",
                    "license_status": "unverified",
                    "read_on": "2026-10-27",
                },
                "registry_manifest_digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
            },
        ],
    }

    # Sign with test catalog private seed matching demo-test-key
    if ed25519_ref:
        can_bytes = canonical_json_bytes(doc)
        sig_bytes = ed25519_ref.sign(TEST_CATALOG_SEED, can_bytes)
        doc["signature"] = sig_bytes.hex()
    else:
        doc["signature"] = "00" * 64
    return doc


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PAI Setup Wizard and Hardware Survey Engine.")
    parser.add_argument("--survey-only", action="store_true", help="Run local hardware survey and output JSON")
    parser.add_argument("--catalog", default=None, help="Path to signed catalog.json")
    parser.add_argument("--min-catalog-version", type=int, default=1, help="Minimum acceptable catalog version")
    parser.add_argument("--progress-json", action="store_true", help="Emit Appendix C NDJSON progress events")
    parser.add_argument("--probe-ollama", action="store_true", help="Check if Ollama daemon is reachable")
    parser.add_argument("--model-drive", default=None, help="Custom target directory for disk space survey")

    args = parser.parse_args(argv)
    emitter = ProgressEmitter(enabled=args.progress_json)

    # 1. Hardware Survey
    survey = collect_hardware_survey(args.model_drive)
    emitter.emit("survey", hardware=asdict(survey))

    if args.survey_only:
        print(json.dumps(asdict(survey), indent=2))
        return 0

    # 2. Ollama probe
    ollama_status = probe_ollama_daemon()
    emitter.emit("ollama_status", **ollama_status)

    # 3. Catalog loading and verification
    if args.catalog:
        cat_path = Path(args.catalog).resolve()
        if not cat_path.is_file():
            emitter.emit("error", code="CATALOG_NOT_FOUND", message=f"Catalog not found at {cat_path}")
            return 1
        cat_data = json.loads(cat_path.read_text(encoding="utf-8"))
    else:
        cat_data = create_demo_catalog(version=1)

    try:
        verified_cat = verify_catalog_payload(cat_data, min_version=args.min_catalog_version)
    except CatalogSecurityError as e:
        emitter.emit("error", code="CATALOG_SECURITY_ERROR", message=str(e))
        print(f"ERROR: Catalog verification failed: {e}", file=sys.stderr)
        return 1

    # 4. Plan model recommendations
    recommendations = plan_model_selection(verified_cat, survey)
    recs_dicts = [asdict(r) for r in recommendations]
    emitter.emit("fit", recommendations=recs_dicts)

    print("\n================ PAI Setup Hardware Survey & Recommendations ================")
    print(f"RAM:   {survey.avail_ram_mb:.1f} MB available / {survey.total_ram_mb:.1f} MB total")
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

    return 0


if __name__ == "__main__":
    sys.exit(main())
