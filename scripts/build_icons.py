"""Rebuild the One_link icon assets from the source ONE Glyph.

Outputs:
    src/one_link/web/assets/one-glyph.png   transparent glyph (black-on-alpha)
    src/one_link/web/assets/one-glyph.ico   multi-size Windows app icon
                                            (rounded-rect gradient + white glyph)

Run:
    python scripts/build_icons.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

REPO = Path(__file__).resolve().parent.parent
SRC = Path(r"$HOME\Projects\Coherence_Energy_Labs_Website\assets\brand\logos\ONE Glyph.png")
OUT_DIR = REPO / "src" / "one_link" / "web" / "assets"

# Brand colors (match index.html CSS tokens)
ACCENT_TOP = (124, 92, 255)
ACCENT_BOT = (78, 193, 255)


def luminance_to_alpha(im_rgba: Image.Image) -> Image.Image:
    """Convert a black-on-white-ish source to clean black-on-transparent.

    Each pixel's alpha = (255 - perceptual luminance). RGB is forced to (0,0,0).
    Anti-aliasing is preserved; near-white pixels become near-transparent.
    """
    arr = np.array(im_rgba).astype(np.float32)
    lum = 0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1] + 0.114 * arr[:, :, 2]
    alpha = np.clip(255.0 - lum, 0, 255).astype(np.uint8)
    out = np.zeros_like(arr, dtype=np.uint8)
    out[:, :, 3] = alpha
    return Image.fromarray(out, "RGBA")


def trim_to_glyph(im: Image.Image, padding: float = 0.06) -> Image.Image:
    """Crop transparent borders down to the visible glyph plus a small pad."""
    bbox = im.getbbox()
    if not bbox:
        return im
    cropped = im.crop(bbox)
    w, h = cropped.size
    side = max(w, h)
    pad = int(side * padding)
    side += pad * 2
    out = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    out.paste(cropped, ((side - w) // 2, (side - h) // 2), cropped)
    return out


def _vertical_gradient(size: int) -> Image.Image:
    bg = Image.new("RGB", (size, size))
    arr = np.zeros((size, size, 3), dtype=np.uint8)
    for y in range(size):
        t = y / max(1, size - 1)
        c = (
            int(ACCENT_TOP[0] + (ACCENT_BOT[0] - ACCENT_TOP[0]) * t),
            int(ACCENT_TOP[1] + (ACCENT_BOT[1] - ACCENT_TOP[1]) * t),
            int(ACCENT_TOP[2] + (ACCENT_BOT[2] - ACCENT_TOP[2]) * t),
        )
        arr[y, :, 0] = c[0]
        arr[y, :, 1] = c[1]
        arr[y, :, 2] = c[2]
    return Image.fromarray(arr, "RGB").convert("RGBA")


def make_app_icon(size: int, glyph_rgba: Image.Image) -> Image.Image:
    """Rounded-rect gradient background with a centered white glyph."""
    icon = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    bg = _vertical_gradient(size)

    # Rounded corners — radius ~22% of side (matches modern Win/Mac app icon look)
    radius = max(2, int(size * 0.22))
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, size - 1, size - 1), radius=radius, fill=255,
    )
    icon.paste(bg, (0, 0), mask)

    # Subtle inner highlight along the top — sells the 3D feel
    if size >= 64:
        hl = Image.new("L", (size, size), 0)
        ImageDraw.Draw(hl).rounded_rectangle(
            (1, 1, size - 2, size - 2), radius=radius - 1, outline=70, width=1,
        )
        white = Image.new("RGBA", (size, size), (255, 255, 255, 0))
        white.putalpha(hl)
        icon = Image.alpha_composite(icon, white)

    # White-tinted glyph centered. Glyph occupies ~60% of icon side.
    g_size = int(size * 0.60)
    g = glyph_rgba.resize((g_size, g_size), Image.LANCZOS)
    g_arr = np.array(g)
    # Force RGB to white (alpha is preserved → anti-aliasing intact)
    g_arr[:, :, 0] = 255
    g_arr[:, :, 1] = 255
    g_arr[:, :, 2] = 255
    g_white = Image.fromarray(g_arr, "RGBA")
    off = ((size - g_size) // 2, (size - g_size) // 2)
    icon.alpha_composite(g_white, dest=off)
    return icon


def main() -> int:
    if not SRC.exists():
        print(f"source not found: {SRC}", file=sys.stderr)
        return 2
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    raw = Image.open(SRC).convert("RGBA")
    print(f"source: {SRC}  size={raw.size}")

    # Clean transparent black-on-alpha glyph for in-app use
    transparent = luminance_to_alpha(raw)
    transparent = trim_to_glyph(transparent, padding=0.04)

    # Cap output size (the original is 1984x2080 — overkill for a 32px logo)
    if max(transparent.size) > 1024:
        transparent.thumbnail((1024, 1024), Image.LANCZOS)
    png_path = OUT_DIR / "one-glyph.png"
    transparent.save(png_path, "PNG", optimize=True)
    print(f"wrote {png_path}  size={transparent.size}  bytes={png_path.stat().st_size}")

    # Multi-resolution app icon
    sizes = [16, 24, 32, 48, 64, 128, 256]
    icons = [make_app_icon(s, transparent) for s in sizes]
    ico_path = OUT_DIR / "one-glyph.ico"
    icons[-1].save(
        ico_path,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=icons[:-1],
    )
    # Also save a PNG preview of the app icon for documentation
    preview = make_app_icon(512, transparent)
    preview_path = OUT_DIR / "one-glyph-app.png"
    preview.save(preview_path, "PNG", optimize=True)
    print(f"wrote {ico_path}  embedded sizes={sizes}  bytes={ico_path.stat().st_size}")
    print(f"wrote {preview_path}  size={preview.size}  bytes={preview_path.stat().st_size}")

    # Verify ICO embeds all sizes
    print("\nverifying ICO …")
    im = Image.open(ico_path)
    embedded = sorted(im.info.get("sizes", set()))
    print(f"  embedded sizes: {embedded}")
    if embedded != [(s, s) for s in sizes]:
        print("  WARNING: ICO did not embed all expected sizes")
        return 3
    print("  OK — all expected sizes present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
