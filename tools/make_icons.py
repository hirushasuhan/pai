#!/usr/bin/env python3
"""
Personal Agentic AI (PAI) - Branding & Icon Asset Generator.

Generates:
  1. packaging/assets/pai.ico: Multi-resolution Windows icon (16, 24, 32, 48, 64, 128, 256)
     cropped strictly to the brain mark on dark background (square).
  2. packaging/assets/wizard-large.bmp: Inno Setup WizardImageFile (164 x 314 px) on dark background.
  3. packaging/assets/wizard-small.bmp: Inno Setup WizardSmallImageFile (55 x 55 px) on dark background.
  4. public/pai-logo-512.png: High-resolution optimized public web logo (< 200 KB).

Rules:
  - Original 4.4 MB 'public/PAI Logo.png' is ignored via .gitignore and never committed to git.
  - research/ and core/ trees are strictly untouched.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent


def generate_assets(
    source_logo: Path,
    assets_dir: Path,
    public_dir: Path,
) -> dict[str, Path]:
    if not source_logo.is_file():
        raise FileNotFoundError(f"Source logo not found at: {source_logo}")

    assets_dir.mkdir(parents=True, exist_ok=True)
    public_dir.mkdir(parents=True, exist_ok=True)

    im = Image.open(source_logo)
    bg_color = im.getpixel((0, 0))  # Sample canvas background (approx (3, 20, 44))

    results = {}

    # 1. Generate packaging/assets/pai.ico
    # Crop the brain mark only:
    # Brain mark occupies X: 750..2250, Y: 480..1480 (1500 x 1000 px).
    # Letters 'PAI' start below Y=1590.
    brain_crop = im.crop((750, 480, 2250, 1480))
    # Place onto a 1500 x 1500 square centered with background color
    square_brain = Image.new("RGB", (1500, 1500), bg_color)
    square_brain.paste(brain_crop, (0, 250))

    ico_path = assets_dir / "pai.ico"
    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    square_brain.save(ico_path, format="ICO", sizes=ico_sizes)
    results["ico"] = ico_path

    # 2. Generate Inno Setup WizardImageFile (164 x 314 px)
    # Background: dark blue canvas
    wizard_large = Image.new("RGB", (164, 314), bg_color)
    # Fit full logo (3000x3000) scaled to 156 x 156
    logo_fit = im.resize((156, 156), Image.Resampling.LANCZOS)
    wizard_large.paste(logo_fit, (4, (314 - 156) // 2))
    wizard_large_bmp = assets_dir / "wizard-large.bmp"
    wizard_large.save(wizard_large_bmp, format="BMP")
    results["wizard_large"] = wizard_large_bmp

    # 3. Generate Inno Setup WizardSmallImageFile (55 x 55 px)
    wizard_small = Image.new("RGB", (55, 55), bg_color)
    logo_small = square_brain.resize((50, 50), Image.Resampling.LANCZOS)
    wizard_small.paste(logo_small, (2, 2))
    wizard_small_bmp = assets_dir / "wizard-small.bmp"
    wizard_small.save(wizard_small_bmp, format="BMP")
    results["wizard_small"] = wizard_small_bmp

    # 4. Generate public/pai-logo-512.png (< 200 KB)
    logo_512 = im.resize((512, 512), Image.Resampling.LANCZOS)
    logo_512_q = logo_512.quantize(colors=256, method=Image.MEDIANCUT)
    public_logo_path = public_dir / "pai-logo-512.png"
    logo_512_q.save(public_logo_path, format="PNG", optimize=True)
    if public_logo_path.stat().st_size >= 200 * 1024:
        raise ValueError(f"public/pai-logo-512.png exceeded 200 KB limit: {public_logo_path.stat().st_size} bytes")
    results["public_logo"] = public_logo_path

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate PAI branding and icon assets from logo.")
    parser.add_argument(
        "--source",
        default=REPO_ROOT / "public" / "PAI Logo.png",
        help="Path to original PAI Logo.png",
    )
    parser.add_argument(
        "--assets-dir",
        default=REPO_ROOT / "packaging" / "assets",
        help="Destination directory for packaging assets",
    )
    parser.add_argument(
        "--public-dir",
        default=REPO_ROOT / "public",
        help="Destination directory for public web assets",
    )
    args = parser.parse_args()

    results = generate_assets(
        source_logo=Path(args.source),
        assets_dir=Path(args.assets_dir),
        public_dir=Path(args.public_dir),
    )

    print("Successfully generated branding assets:")
    for key, path in results.items():
        size_kb = path.stat().st_size / 1024
        print(f"  - {key}: {path.relative_to(REPO_ROOT)} ({size_kb:.1f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
