#!/usr/bin/env python3
"""
Personal Agentic AI (PAI) - Model Catalog Signing Tool.

Specification: docs/PACKAGING_SPEC.md (Section 15.5)
ADR-013, Findings EH & EK

Rules enforced:
  1. Private key is strictly read from the path given via --private-key-file.
  2. Private key bytes, hex, or PEM are NEVER printed, logged, or included in exceptions.
  3. Uses deterministic canonical JSON serialization omitting the signature field.
  4. Self-verifies the Ed25519 signature before running the production verifier.
  5. Finding EK: Runs the production verifier verify_catalog_payload on the signed result
     against active trust keys (default research/trust.json, or --trust-file for tests)
     with an isolated temporary state_path and freshness enforced. If verification fails,
     fails closed with exit 1 and writes NO output file.
  6. Refuses --out equal to --catalog.
  7. Writes output atomically via temporary file and rename (os.replace).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = REPO_ROOT / "research"
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    ed25519 = None  # type: ignore
    serialization = None  # type: ignore

from pai_setup import CatalogSecurityError, load_trust_keys, verify_catalog_payload


def load_private_key_file(key_path: Path) -> ed25519.Ed25519PrivateKey:
    """
    Loads an Ed25519 private key from an explicit file path.
    Supports 32-byte raw binary seed, 64-character hex string, or PKCS#8 PEM.
    Never prints or leaks key material in error messages.
    """
    if ed25519 is None:
        raise RuntimeError("cryptography library is required for catalog signing")

    if not key_path.is_file():
        raise FileNotFoundError(f"Private key file not found: {key_path}")

    raw_data = key_path.read_bytes()
    if not raw_data:
        raise ValueError("Private key file is empty")

    # 1. Try PKCS#8 PEM format
    if b"-----BEGIN" in raw_data and serialization is not None:
        try:
            loaded = serialization.load_pem_private_key(raw_data, password=None)
            if isinstance(loaded, ed25519.Ed25519PrivateKey):
                return loaded
        except Exception:
            pass

    # 2. Try 64-character hex string
    text = raw_data.strip().decode("ascii", errors="ignore")
    if len(text) == 64:
        try:
            return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text))
        except Exception:
            pass

    # 3. Try 32 raw bytes
    if len(raw_data) == 32:
        try:
            return ed25519.Ed25519PrivateKey.from_private_bytes(raw_data)
        except Exception:
            pass

    raise ValueError(
        "Unable to parse Ed25519 private key. Expected 32-byte raw binary, "
        "64-character hex, or PKCS#8 PEM format."
    )


def canonical_catalog_bytes(catalog_data: Dict[str, Any]) -> bytes:
    """
    Produces deterministic canonical UTF-8 bytes for signing.
    The 'signature' field is omitted during canonical serialization.
    """
    d = {k: v for k, v in catalog_data.items() if k != "signature"}
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_catalog(
    catalog_path: Path,
    key_path: Path,
    out_path: Path,
    trust_file: Optional[Path] = None,
) -> Path:
    """
    Signs catalog JSON payload with Ed25519 key, validates against production trust root,
    and atomically writes signed JSON to out_path.
    """
    cat_resolved = catalog_path.resolve()
    out_resolved = out_path.resolve()
    if cat_resolved == out_resolved:
        raise ValueError(f"Output path cannot be identical to input catalog path: {out_path}")

    if not catalog_path.is_file():
        raise FileNotFoundError(f"Input catalog file not found: {catalog_path}")

    # Finding ER: Always print one line "Trust root: <path>" before signing.
    # Print a warning when the trust root is not research/trust.json.
    default_trust_path = (RESEARCH_DIR / "trust.json").resolve()
    effective_trust_path = Path(trust_file).resolve() if trust_file else default_trust_path
    print(f"Trust root: {effective_trust_path}")
    if effective_trust_path != default_trust_path:
        print(f"WARNING: Using non-default trust root file: {effective_trust_path}")

    private_key = load_private_key_file(key_path)

    cat_text = catalog_path.read_text(encoding="utf-8")
    cat_data = json.loads(cat_text)
    if not isinstance(cat_data, dict):
        raise ValueError("Catalog payload must be a JSON object (dict)")

    canonical_bytes = canonical_catalog_bytes(cat_data)
    sig_bytes = private_key.sign(canonical_bytes)

    # 1. Self-verification check before writing output
    public_key = private_key.public_key()
    try:
        public_key.verify(sig_bytes, canonical_bytes)
    except Exception as e:
        raise RuntimeError(f"Cryptographic self-verification failed: {e}")

    cat_data["signature"] = sig_bytes.hex()

    # 2. Production Trust Root Verification (Finding EK)
    # Verifies the signed catalog against the active trust root (or test trust file)
    # with freshness enforced at signing time and an isolated temporary state file.
    trust_keys = load_trust_keys(trust_file)
    with tempfile.TemporaryDirectory(prefix="pai_sign_state_") as tmp_state_dir:
        tmp_state_file = Path(tmp_state_dir) / "catalog_state.json"
        try:
            verify_catalog_payload(
                cat_data,
                trust_keys=trust_keys,
                state_path=tmp_state_file,
                enforce_freshness=True,
            )
        except Exception as e:
            raise CatalogSecurityError(
                f"Production trust root verification failed against "
                f"{'default trust root' if trust_file is None else str(trust_file)}: {e}"
            )

    # 3. Write output atomically via temporary file + rename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    temp_file = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=out_path.parent,
        prefix="tmp_catalog_",
        suffix=".json",
        delete=False,
    )
    try:
        temp_file.write(json.dumps(cat_data, indent=2, ensure_ascii=False) + "\n")
        temp_file.close()
        os.replace(temp_file.name, out_path)
    except Exception:
        if os.path.exists(temp_file.name):
            try:
                os.unlink(temp_file.name)
            except OSError:
                pass
        raise

    return out_path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline Deterministic Ed25519 Model Catalog Signing Tool (ADR-013, Findings EH & EK)."
    )
    parser.add_argument("--catalog", required=True, help="Path to unsigned or updated input catalog JSON")
    parser.add_argument(
        "--private-key-file",
        required=True,
        help="Path to file containing offline Ed25519 private key (never logged or printed)",
    )
    parser.add_argument("--out", required=True, help="Path where signed catalog JSON will be written")
    parser.add_argument(
        "--trust-file",
        default=None,
        help="Optional path to explicit trust.json file (default: research/trust.json, intended for tests)",
    )
    args = parser.parse_args(argv)

    try:
        trust_p = Path(args.trust_file) if args.trust_file else None
        out_p = sign_catalog(
            Path(args.catalog),
            Path(args.private_key_file),
            Path(args.out),
            trust_file=trust_p,
        )
        print(f"Successfully signed catalog and wrote to: {out_p}")
        return 0
    except Exception as e:
        print(f"ERROR: Catalog signing failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
