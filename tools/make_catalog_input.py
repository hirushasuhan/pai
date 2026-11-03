#!/usr/bin/env python3
"""
Personal Agentic AI (PAI) - Model Catalog Input Draft Generator.

Milestone C1 & C1b (Finding CD, Appendix B, ADR-013, Findings FQ, FR, FS, FT, FU).
Generates an unsigned draft `catalog_input_<date>.json` containing verified metadata,
cryptographic manifest digests, layer-sum byte sizes, and measured or conservative
resource requirements.

Strict Safety & Grounding Invariants:
1. NO signing: Does not sign, does not accept private keys, does not create or write research/catalog.json.
2. Read-only registry inspection: Fetches model manifests, config blobs, and license blobs via HTTP GET only (no model weights downloaded).
3. Exact schema parity: Conforms strictly to PACKAGING_SPEC Appendix B and research/pai_setup.py:verify_catalog_payload.
4. Explicit unverified licence default: license_status is strictly "unverified" for every entry.
5. Grounded license & config:
   - License blob fetched from layer with media type 'application/vnd.ollama.image.license'.
   - License name derived from known text headers; falls back to 'see licence text'.
   - License text saved to docs/catalog/licence_texts/<id>.txt.
   - Config blob fetched to extract quantization (file_type) and parameters_b (model_type).
6. Cold RAM measurements grounding: min_ram_mb is read strictly from docs/evidence/cold_ram_measurements.json
   when available; unmeasured models use pai_setup's conservative footprint rule (disk weights MB + 512 MB context).
7. Uniform min_vram_mb rule: weights size in MB (round(disk_bytes / (1024 * 1024), 1)); observed VRAM kept in measured.
8. Atomic file generation: Network or parsing errors fail visibly with non-zero exit and leave no partial output file.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODELS = [
    "qwen2.5:0.5b",
    "qwen2.5-coder:1.5b",
    "qwen2.5-coder:7b",
]
DEFAULT_REGISTRY_BASE = "https://registry.ollama.ai/v2/library"
DEFAULT_MEASUREMENTS_PATH = REPO_ROOT / "docs" / "evidence" / "cold_ram_measurements.json"
DEFAULT_CATALOG_DIR = REPO_ROOT / "docs" / "catalog"
DEFAULT_OUT_PATH = DEFAULT_CATALOG_DIR / "catalog_input_2026-11-03.json"
DEFAULT_LICENCE_TEXTS_DIR = DEFAULT_CATALOG_DIR / "licence_texts"

MODEL_ID_PATTERN = re.compile(r"^[a-z0-9_.-]+:[a-z0-9_.-]+$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
LICENSE_MEDIA_TYPE = "application/vnd.ollama.image.license"


def parse_model_tag(tag: str) -> Tuple[str, str]:
    """Parses a model tag into (family_or_name, version_tag)."""
    if not MODEL_ID_PATTERN.match(tag):
        raise ValueError(f"Invalid model tag '{tag}'; expected pattern '<name>:<version>'")
    parts = tag.split(":", 1)
    return parts[0], parts[1]


def safe_filename_for_tag(tag: str) -> str:
    """Returns a Windows-safe filename for a model tag (replaces ':' with '_')."""
    return tag.replace(":", "_")


def detect_license_name(license_text: str) -> str:
    """
    Derives license name from text only when matching known license headers;
    otherwise returns 'see licence text'.
    """
    if not license_text or not license_text.strip():
        return "see licence text"
    # Apache 2.0
    if re.search(r"Apache License", license_text, re.IGNORECASE) and re.search(r"Version 2\.0", license_text, re.IGNORECASE):
        return "Apache-2.0"
    # MIT
    if re.search(r"MIT License", license_text, re.IGNORECASE):
        return "MIT"
    # BSD-3-Clause
    if "Redistribution and use in source and binary forms" in license_text and "Neither the name" in license_text:
        return "BSD-3-Clause"
    # Qwen Research License
    if re.search(r"Qwen Research License", license_text, re.IGNORECASE):
        return "Qwen Research License"
    return "see licence text"


def parse_config_quantization(config_dict: Dict[str, Any], tag: str) -> str:
    """Extracts quantization from config file_type, failing visibly if missing."""
    file_type = config_dict.get("file_type")
    if not file_type or not isinstance(file_type, str) or not file_type.strip():
        raise ValueError(f"Model '{tag}' config missing or empty 'file_type' (quantization)")
    return file_type.strip()


def parse_config_parameters_b(config_dict: Dict[str, Any], tag: str) -> float:
    """Extracts parameters_b from config model_type, failing visibly if missing."""
    model_type = config_dict.get("model_type")
    if not model_type or not isinstance(model_type, str) or not model_type.strip():
        raise ValueError(f"Model '{tag}' config missing or empty 'model_type' (parameters_b)")
    m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([BMbm])$", model_type.strip())
    if not m:
        raise ValueError(f"Model '{tag}' cannot parse parameter size from config model_type: {model_type!r}")
    val, unit = float(m.group(1)), m.group(2).upper()
    if unit == "B":
        return round(val, 1)
    elif unit == "M":
        return round(val / 1000.0, 1)
    raise ValueError(f"Model '{tag}' unsupported unit in model_type: {unit}")


def fetch_registry_blob(
    name: str,
    digest: str,
    registry_base_url: str = DEFAULT_REGISTRY_BASE,
    timeout: float = 15.0,
) -> bytes:
    """
    Fetches a blob (config or license) from Ollama registry via read-only HTTP GET.
    Validates that the computed sha256 matches the requested digest.
    Raises RuntimeError on failure.
    """
    if not DIGEST_PATTERN.match(digest):
        raise ValueError(f"Invalid digest format: {digest!r}")
    url = f"{registry_base_url.rstrip('/')}/{name}/blobs/{digest}"
    headers = {
        "User-Agent": "PAI-Catalog-Builder/1.0",
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            computed_sha = f"sha256:{hashlib.sha256(data).hexdigest()}"
            if computed_sha != digest:
                raise ValueError(f"Blob digest mismatch for {url}: expected {digest}, got {computed_sha}")
            return data
    except Exception as e:
        raise RuntimeError(f"Failed to fetch blob '{digest}' for '{name}' from {url}: {e}") from e


def fetch_registry_manifest(
    model_tag: str,
    registry_base_url: str = DEFAULT_REGISTRY_BASE,
    timeout: float = 15.0,
) -> Tuple[str, Dict[str, Any]]:
    """
    Fetches OCI manifest from Ollama registry via read-only HTTP GET.
    Returns (manifest_digest, manifest_dict).
    Raises RuntimeError on HTTP/network or JSON parsing failure, or header digest mismatch.
    """
    name, ver = parse_model_tag(model_tag)
    url = f"{registry_base_url.rstrip('/')}/{name}/manifests/{ver}"
    headers = {
        "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json",
        "User-Agent": "PAI-Catalog-Builder/1.0",
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            try:
                manifest = json.loads(data.decode("utf-8"))
            except Exception as e:
                raise ValueError(f"Malformed manifest JSON from {url}: {e}") from e
            if not isinstance(manifest, dict):
                raise ValueError(f"Manifest from {url} is not a JSON object")

            computed_sha256 = hashlib.sha256(data).hexdigest()
            manifest_digest = f"sha256:{computed_sha256}"
            if not DIGEST_PATTERN.match(manifest_digest):
                raise ValueError(f"Computed digest '{manifest_digest}' does not match standard sha256 format")

            # Finding FR: Check Docker-Content-Digest or ollama-content-digest header when present
            header_digest = (
                resp.headers.get("Docker-Content-Digest")
                or resp.headers.get("ollama-content-digest")
                or resp.headers.get("docker-content-digest")
            )
            if header_digest and header_digest.strip() != manifest_digest:
                raise ValueError(
                    f"Manifest digest mismatch for {model_tag}: "
                    f"header='{header_digest.strip()}' vs computed='{manifest_digest}'"
                )

            return manifest_digest, manifest
    except Exception as e:
        raise RuntimeError(f"Failed to fetch manifest for '{model_tag}' from {url}: {e}") from e


def load_cold_ram_measurements(path: Path) -> Dict[str, Any]:
    """Loads cold RAM measurements file if present, returning a dictionary."""
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"WARNING: Could not parse cold RAM measurements at {path}: {e}", file=sys.stderr)
        return {}


def build_model_entry(
    tag: str,
    manifest: Dict[str, Any],
    manifest_digest: str,
    config: Dict[str, Any],
    license_text: Optional[str],
    license_digest: Optional[str],
    measurements: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Builds a single validated model catalog entry adhering strictly to
    docs/PACKAGING_SPEC.md Appendix B and research/pai_setup.py:verify_catalog_payload.
    """
    name, ver = parse_model_tag(tag)
    layers = manifest.get("layers", [])
    if not isinstance(layers, list) or len(layers) == 0:
        raise ValueError(f"Model '{tag}' manifest contains no layers")

    # Sum of layer sizes for download and disk (excludes config blob)
    download_bytes = sum(l.get("size", 0) for l in layers)
    if download_bytes <= 0:
        raise ValueError(f"Model '{tag}' layer sum is non-positive: {download_bytes}")
    disk_bytes = download_bytes

    # Finding FR: Quantization and parameters_b parsed from config blob
    quantization = parse_config_quantization(config, tag)
    parameters_b = parse_config_parameters_b(config, tag)

    # Finding FS: Single documented rule for min_vram_mb: weights size in MB
    disk_mb = disk_bytes / (1024 * 1024)
    min_vram_mb = round(disk_mb, 1)

    # Memory requirement resolution:
    # 1. Grounded cold RAM measurements if available
    # 2. Documented conservative rule from pai_setup.py: disk weights MB + 512 MB context
    if tag in measurements:
        m_data = measurements[tag]
        min_ram_mb = round(float(m_data.get("model_footprint_mb", 0.0)), 1)
        host_delta = m_data.get("host_delta_mb_max")
        measured: Optional[Dict[str, Any]] = {
            "machine": "RTX 4050 6GB / 16GB RAM",
            "tokens_per_sec": None,
            "host_delta_mb": float(host_delta) if host_delta is not None else None,
            "observed_vram_mb": round(float(m_data["model_vram_mb"]), 1) if "model_vram_mb" in m_data else None,
        }
    else:
        # Conservative formula from pai_setup.py line 723:
        # footprint_mb = (disk_bytes / (1024 * 1024)) + 512.0 MB
        min_ram_mb = round(disk_mb + 512.0, 1)
        measured = None

    # Tasks categorization based on model family and capabilities (editorial choice)
    if "coder" in tag:
        tasks = ["code", "chat", "documents"]
    else:
        tasks = ["chat", "documents", "code"]

    # Finding FQ: Derive license name from text; default to "see licence text"
    lic_name = detect_license_name(license_text or "")
    lic_url = f"https://ollama.com/library/{tag}"
    license_obj: Dict[str, Any] = {
        "name": lic_name,
        "url": lic_url,
        "license_status": "unverified",
        "read_on": None,
    }
    if license_digest:
        license_obj["sha256"] = license_digest

    return {
        "id": tag,
        "family": name,
        "parameters_b": parameters_b,
        "quantization": quantization,
        "download_bytes": download_bytes,
        "disk_bytes": disk_bytes,
        "min_ram_mb": min_ram_mb,
        "min_vram_mb": min_vram_mb,
        "tasks": tasks,
        "license": license_obj,
        "registry_manifest_digest": manifest_digest,
        "measured": measured,
    }


def generate_catalog_input_payload(
    model_tags: List[str],
    measurements_path: Path = DEFAULT_MEASUREMENTS_PATH,
    registry_base_url: str = DEFAULT_REGISTRY_BASE,
    licence_texts_dir: Optional[Path] = None,
    timeout: float = 15.0,
) -> Dict[str, Any]:
    """Fetches manifests, config blobs, and license blobs to construct the full catalog input draft dictionary."""
    measurements = load_cold_ram_measurements(measurements_path)
    models: List[Dict[str, Any]] = []

    for tag in model_tags:
        name, ver = parse_model_tag(tag)
        print(f"Fetching manifest for {tag} from {registry_base_url}...")
        digest, manifest = fetch_registry_manifest(tag, registry_base_url=registry_base_url, timeout=timeout)

        # Finding FR: Read config blob
        config_meta = manifest.get("config", {})
        config_digest = config_meta.get("digest")
        if not config_digest or not isinstance(config_digest, str):
            raise ValueError(f"Model '{tag}' manifest missing config blob digest")
        print(f"Fetching config blob {config_digest} for {tag}...")
        config_bytes = fetch_registry_blob(name, config_digest, registry_base_url=registry_base_url, timeout=timeout)
        try:
            config_dict = json.loads(config_bytes.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Malformed config JSON for model '{tag}': {e}") from e

        # Finding FQ: Fetch license blob if present in manifest layers
        layers = manifest.get("layers", [])
        lic_layer = next((l for l in layers if l.get("mediaType") == LICENSE_MEDIA_TYPE), None)
        lic_text: Optional[str] = None
        lic_digest: Optional[str] = None
        if lic_layer:
            lic_digest = lic_layer.get("digest")
            if lic_digest and isinstance(lic_digest, str):
                print(f"Fetching license blob {lic_digest} for {tag}...")
                lic_bytes = fetch_registry_blob(name, lic_digest, registry_base_url=registry_base_url, timeout=timeout)
                lic_text = lic_bytes.decode("utf-8", errors="replace")

                # Save license text to file if directory specified
                if licence_texts_dir is not None:
                    licence_texts_dir.mkdir(parents=True, exist_ok=True)
                    safe_filename = safe_filename_for_tag(tag) + ".txt"
                    lic_out = licence_texts_dir / safe_filename
                    lic_out.write_text(lic_text, encoding="utf-8")
                    print(f"Saved licence text to: {lic_out}")

        entry = build_model_entry(tag, manifest, digest, config_dict, lic_text, lic_digest, measurements)
        models.append(entry)

    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "kind": "catalog",
        "catalog_version": 1,
        "issued_utc": now_utc,
        "notes": (
            "Draft model catalog input generated by tools/make_catalog_input.py. "
            "Requires manual license inspection and offline signing with production key rel-1 (ADR-013, Milestone C1). "
            "download_bytes and disk_bytes are the sum of OCI layer sizes (excluding the small config blob). "
            "tasks is an editorial categorization based on model family and architecture. "
            "min_vram_mb follows the uniform rule of weights size in MB (round(disk_bytes / (1024 * 1024), 1)), "
            "with hardware-observed VRAM preserved in measured.observed_vram_mb. "
            "min_ram_mb is grounded in docs/evidence/cold_ram_measurements.json (model_footprint_mb) where measured, "
            "or derived via the conservative formula (disk weights MB + 512.0 MB context allowance) where unmeasured, "
            "as evaluated by pai_setup fit checks."
        ),
        "models": models,
        "signature": None,
    }


def write_catalog_input_atomically(catalog_data: Dict[str, Any], out_path: Path) -> None:
    """Writes catalog JSON atomically using a temporary file and rename."""
    out_path = Path(out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    temp_file = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=out_path.parent,
        prefix="tmp_cat_input_",
        suffix=".json",
        delete=False,
    )
    try:
        json.dump(catalog_data, temp_file, indent=2, ensure_ascii=False)
        temp_file.write("\n")
        temp_file.close()
        os.replace(temp_file.name, out_path)
    except Exception:
        if os.path.exists(temp_file.name):
            try:
                os.remove(temp_file.name)
            except OSError:
                pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate unsigned draft catalog_input_<date>.json from Ollama registry.")
    parser.add_argument(
        "--models",
        nargs="+",
        default=DEFAULT_MODELS,
        help="List of model tags (default: qwen2.5:0.5b qwen2.5-coder:1.5b qwen2.5-coder:7b)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT_PATH,
        help=f"Output file path (default: {DEFAULT_OUT_PATH})",
    )
    parser.add_argument(
        "--licence-texts-dir",
        type=Path,
        default=DEFAULT_LICENCE_TEXTS_DIR,
        help=f"Directory to save extracted license text files (default: {DEFAULT_LICENCE_TEXTS_DIR})",
    )
    parser.add_argument(
        "--measurements",
        type=Path,
        default=DEFAULT_MEASUREMENTS_PATH,
        help=f"Path to cold RAM measurements JSON (default: {DEFAULT_MEASUREMENTS_PATH})",
    )
    parser.add_argument(
        "--registry-url",
        default=DEFAULT_REGISTRY_BASE,
        help=f"Ollama registry base URL (default: {DEFAULT_REGISTRY_BASE})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP network timeout in seconds (default: 15.0)",
    )
    args = parser.parse_args()

    try:
        catalog_data = generate_catalog_input_payload(
            model_tags=args.models,
            measurements_path=args.measurements,
            registry_base_url=args.registry_url,
            licence_texts_dir=args.licence_texts_dir,
            timeout=args.timeout,
        )
        write_catalog_input_atomically(catalog_data, args.out)
        print(f"Successfully generated draft catalog input at: {args.out}")
        return 0
    except Exception as e:
        print(f"ERROR: Failed to generate catalog input: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
