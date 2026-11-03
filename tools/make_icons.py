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
from PIL import Image, ImageChops

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
    bg_color = im.getpixel((0, 0))  # Sample canvas background

    results = {}

    # Detect content bounding box dynamically using background color difference
    bg_im = Image.new(im.mode, im.size, bg_color)
    diff = ImageChops.difference(im, bg_im)
    bbox = diff.getbbox()
    if bbox:
        x0, y0, x1, y1 = bbox
        w = x1 - x0
        h = y1 - y0
        # Create a centered square with comfortable margin around the logo mark
        side = int(max(w, h) * 1.15)
        square_logo = Image.new("RGB", (side, side), bg_color)
        square_logo.paste(im.crop(bbox), ((side - w) // 2, (side - h) // 2))
    else:
        side = max(im.width, im.height)
        square_logo = Image.new("RGB", (side, side), bg_color)
        square_logo.paste(im, ((side - im.width) // 2, (side - im.height) // 2))

    # 1. Generate packaging/assets/pai.ico
    ico_path = assets_dir / "pai.ico"
    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    square_logo.save(ico_path, format="ICO", sizes=ico_sizes)
    results["ico"] = ico_path

    # 2. Generate Inno Setup WizardImageFile (164 x 314 px)
    wizard_large = Image.new("RGB", (164, 314), bg_color)
    logo_fit = square_logo.resize((156, 156), Image.Resampling.LANCZOS)
    wizard_large.paste(logo_fit, (4, (314 - 156) // 2))
    wizard_large_bmp = assets_dir / "wizard-large.bmp"
    wizard_large.save(wizard_large_bmp, format="BMP")
    results["wizard_large"] = wizard_large_bmp

    # 3. Generate Inno Setup WizardSmallImageFile (55 x 55 px)
    wizard_small = Image.new("RGB", (55, 55), bg_color)
    logo_small = square_logo.resize((50, 50), Image.Resampling.LANCZOS)
    wizard_small.paste(logo_small, ((55 - 50) // 2, (55 - 50) // 2))
    wizard_small_bmp = assets_dir / "wizard-small.bmp"
    wizard_small.save(wizard_small_bmp, format="BMP")
    results["wizard_small"] = wizard_small_bmp

    # 4. Generate public/pai-logo-512.png (< 200 KB)
    logo_512 = square_logo.resize((512, 512), Image.Resampling.LANCZOS)
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
