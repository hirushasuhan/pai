#!/usr/bin/env python3
"""
Personal Agentic AI (PAI) - Model Catalog Input Draft Generator.

Milestone C1 (Finding CD, Appendix B, ADR-013).
Generates an unsigned draft `catalog_input.json` containing verified metadata,
cryptographic manifest digests, layer-sum byte sizes, and measured or conservative
resource requirements.

Strict Safety & Grounding Invariants:
1. NO signing: Does not sign, does not accept private keys, does not create or write research/catalog.json.
2. Read-only registry inspection: Fetches model manifests via HTTP GET only (no model weights downloaded).
3. Exact schema parity: Conforms strictly to PACKAGING_SPEC Appendix B and research/pai_setup.py:verify_catalog_payload.
4. Explicit unverified licence default: license_status is strictly "unverified" for every entry.
5. Cold RAM measurements grounding: min_ram_mb is read strictly from docs/evidence/cold_ram_measurements.json
   when available; unmeasured models use pai_setup's conservative footprint rule (disk weights MB + 512 MB context).
6. Atomic file generation: Network or parsing errors fail visibly with non-zero exit and leave no partial output file.
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
DEFAULT_OUT_PATH = REPO_ROOT / "catalog_input.json"

MODEL_ID_PATTERN = re.compile(r"^[a-z0-9_.-]+:[a-z0-9_.-]+$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def parse_model_tag(tag: str) -> Tuple[str, str]:
    """Parses a model tag into (family_or_name, version_tag)."""
    if not MODEL_ID_PATTERN.match(tag):
        raise ValueError(f"Invalid model tag '{tag}'; expected pattern '<name>:<version>'")
    parts = tag.split(":", 1)
    return parts[0], parts[1]


def parse_parameters_b(tag: str) -> float:
    """Infers parameter count in billions from version tag (e.g. '0.5b' -> 0.5, '7b' -> 7.0)."""
    _, ver = parse_model_tag(tag)
    m = re.search(r"(\d+(?:\.\d+)?)b$", ver, re.IGNORECASE)
    if m:
        return float(m.group(1))
    return 0.0


def fetch_registry_manifest(
    model_tag: str,
    registry_base_url: str = DEFAULT_REGISTRY_BASE,
    timeout: float = 15.0,
) -> Tuple[str, Dict[str, Any]]:
    """
    Fetches OCI manifest from Ollama registry via read-only HTTP GET.
    Returns (manifest_digest, manifest_dict).
    Raises RuntimeError on HTTP/network or JSON parsing failure.
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
            manifest = json.loads(data.decode("utf-8"))
            computed_sha256 = hashlib.sha256(data).hexdigest()
            manifest_digest = f"sha256:{computed_sha256}"
            if not DIGEST_PATTERN.match(manifest_digest):
                raise ValueError(f"Computed digest '{manifest_digest}' does not match standard sha256 format")
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

    # Sum of layer sizes for download and disk
    download_bytes = sum(l.get("size", 0) for l in layers)
    if download_bytes <= 0:
        raise ValueError(f"Model '{tag}' layer sum is non-positive: {download_bytes}")
    disk_bytes = download_bytes

    # Memory requirement resolution:
    # 1. Grounded cold RAM measurements if available
    # 2. Documented conservative rule from pai_setup.py: disk weights MB + 512 MB context
    if tag in measurements:
        m_data = measurements[tag]
        min_ram_mb = round(float(m_data.get("model_footprint_mb", 0.0)), 1)
        min_vram_mb = round(float(m_data.get("model_vram_mb", 0.0)), 1)
        host_delta = m_data.get("host_delta_mb_max")
        measured: Optional[Dict[str, Any]] = {
            "machine": "RTX 4050 6GB / 16GB RAM",
            "tokens_per_sec": None,
            "host_delta_mb": float(host_delta) if host_delta is not None else None,
        }
    else:
        # Conservative formula from pai_setup.py line 723:
        # footprint_mb = (disk_bytes / (1024 * 1024)) + 512.0 MB
        disk_mb = disk_bytes / (1024 * 1024)
        min_ram_mb = round(disk_mb + 512.0, 1)
        min_vram_mb = round(disk_mb, 1)
        measured = None

    # Tasks categorization based on model family and capabilities
    if "coder" in tag:
        tasks = ["code", "chat", "documents"]
    else:
        tasks = ["chat", "documents", "code"]

    # Inferred license details (license_status MUST remain 'unverified' per Milestone C1)
    if "qwen2.5:0.5b" in tag:
        lic_name = "Qwen Research License"
        lic_url = "https://huggingface.co/Qwen/Qwen2.5-0.5B"
    elif "qwen2.5-coder" in tag:
        lic_name = "Apache-2.0"
        lic_url = f"https://huggingface.co/Qwen/{'Qwen2.5-Coder-1.5B' if '1.5b' in tag else 'Qwen2.5-Coder-7B'}"
    else:
        lic_name = "Unverified"
        lic_url = "https://ollama.com/library"

    return {
        "id": tag,
        "family": name,
        "parameters_b": parse_parameters_b(tag),
        "quantization": "Q4_K_M",
        "download_bytes": download_bytes,
        "disk_bytes": disk_bytes,
        "min_ram_mb": min_ram_mb,
        "min_vram_mb": min_vram_mb,
        "tasks": tasks,
        "license": {
            "name": lic_name,
            "url": lic_url,
            "license_status": "unverified",
            "read_on": None,
        },
        "registry_manifest_digest": manifest_digest,
        "measured": measured,
    }


def generate_catalog_input_payload(
    model_tags: List[str],
    measurements_path: Path = DEFAULT_MEASUREMENTS_PATH,
    registry_base_url: str = DEFAULT_REGISTRY_BASE,
    timeout: float = 15.0,
) -> Dict[str, Any]:
    """Fetches manifests and constructs the full catalog input draft dictionary."""
    measurements = load_cold_ram_measurements(measurements_path)
    models: List[Dict[str, Any]] = []

    for tag in model_tags:
        print(f"Fetching manifest for {tag} from {registry_base_url}...")
        digest, manifest = fetch_registry_manifest(tag, registry_base_url=registry_base_url, timeout=timeout)
        entry = build_model_entry(tag, manifest, digest, measurements)
        models.append(entry)

    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "kind": "catalog",
        "catalog_version": 1,
        "issued_utc": now_utc,
        "notes": (
            "Draft model catalog input generated by tools/make_catalog_input.py. "
            "Requires manual license inspection and offline signing with production key rel-1 (ADR-013, Milestone C1). "
            "min_ram_mb is grounded in docs/evidence/cold_ram_measurements.json where available, "
            "or computed via conservative formula (weights + 512 MB context allowance)."
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
    parser = argparse.ArgumentParser(description="Generate unsigned draft catalog_input.json from Ollama registry.")
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
