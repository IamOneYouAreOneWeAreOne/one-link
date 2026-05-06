"""Rebuild the One_link icon assets from the source ONE Glyph.

Outputs:
    src/one_link/web/assets/one-glyph.png   transparent glyph (black-on-alpha)
    src/one_link/web/assets/one-glyph.ico   multi-size Windows app icon
                                            (black rounded-rect + white glyph)

Run:
    python scripts/build_icons.py
"""

from __future__ import annotations

import sys
import os
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

REPO = Path(__file__).resolve().parent.parent
OUT_DIR = REPO / "src" / "one_link" / "web" / "assets"
DEFAULT_SRC = OUT_DIR / "one-glyph.png"
SRC = Path(os.environ.get("ONE_LINK_GLYPH_SRC", str(DEFAULT_SRC))).expanduser()

APP_ICON_BG = (0, 0, 0)


def luminance_to_alpha(im_rgba: Image.Image) -> Image.Image:
    """Convert a black-on-white-ish source to clean black-on-transparent.

    Each pixel's alpha = (255 - perceptual luminance). RGB is forced to (0,0,0).
    Anti-aliasing is preserved; near-white pixels become near-transparent.
    """
    arr = np.array(im_rgba).astype(np.float32)
    lum = 0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1] + 0.114 * arr[:, :, 2]
    source_alpha = arr[:, :, 3]
    if np.min(source_alpha) < 255:
        alpha = source_alpha.astype(np.uint8)
    else:
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


def _radial_gradient(size: int) -> Image.Image:
    """Diagonal-radial gradient: top-left bright purple → bottom-right deep violet,
    with a vibrant cyan highlight in the upper-right. Pops on any wallpaper.
    Vectorized with numpy."""
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)
    cx_a, cy_a = size * 0.25, size * 0.18
    cx_b, cy_b = size * 0.85, size * 0.92
    cx_c, cy_c = size * 0.78, size * 0.18
    diag = float(((cx_b - cx_a) ** 2 + (cy_b - cy_a) ** 2) ** 0.5)
    d_a = np.sqrt((xx - cx_a) ** 2 + (yy - cy_a) ** 2)
    d_c = np.sqrt((xx - cx_c) ** 2 + (yy - cy_c) ** 2)
    t = np.clip(d_a / diag, 0.0, 1.0)
    r_base = 140 + (60 - 140) * t
    g_base = 80 + (38 - 80) * t
    b_base = 255 + (200 - 255) * t
    hl = np.clip(1.0 - d_c / (size * 0.42), 0.0, 1.0)
    r = np.clip(r_base + hl * 60, 0, 255).astype(np.uint8)
    g = np.clip(g_base + hl * 110, 0, 255).astype(np.uint8)
    b = np.clip(b_base + hl * 30, 0, 255).astype(np.uint8)
    arr = np.dstack([r, g, b])
    return Image.fromarray(arr, "RGB").convert("RGBA")


def make_app_icon(size: int, glyph_rgba: Image.Image) -> Image.Image:
    """Modern app icon: black rounded-rect, white glyph with soft glow."""
    # We render at 4x then downsample for crisp rounded corners + smooth gradient.
    s4 = size * 4 if size <= 128 else size * 2
    icon = Image.new("RGBA", (s4, s4), (0, 0, 0, 0))
    bg = Image.new("RGBA", (s4, s4), (*APP_ICON_BG, 255))

    # Rounded corners — radius ~22% of side
    radius = max(2, int(s4 * 0.22))
    mask = Image.new("L", (s4, s4), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, s4 - 1, s4 - 1), radius=radius, fill=255,
    )
    icon.paste(bg, (0, 0), mask)

    # Inner top-left sheen — diagonal highlight selling the 3D feel (vectorized)
    if s4 >= 64:
        yy, xx = np.mgrid[0:s4, 0:s4].astype(np.float32)
        sheen_arr = np.clip(32 - 24 * (xx + yy) / (s4 * 0.6), 0, 32).astype(np.uint8)
        sheen = Image.fromarray(sheen_arr, "L")
        sheen_mask = Image.new("L", (s4, s4), 0)
        ImageDraw.Draw(sheen_mask).rounded_rectangle(
            (0, 0, s4 - 1, s4 - 1), radius=radius, fill=255,
        )
        sheen = Image.composite(sheen, Image.new("L", (s4, s4), 0), sheen_mask)
        white = Image.new("RGBA", (s4, s4), (255, 255, 255, 0))
        white.putalpha(sheen)
        icon = Image.alpha_composite(icon, white)

    # Glyph: 64% of icon, with a soft outer glow underneath for depth
    g_size = int(s4 * 0.64)
    g = glyph_rgba.resize((g_size, g_size), Image.LANCZOS)
    g_arr = np.array(g)
    g_arr[:, :, 0] = 255
    g_arr[:, :, 1] = 255
    g_arr[:, :, 2] = 255
    g_white = Image.fromarray(g_arr, "RGBA")
    off = ((s4 - g_size) // 2, (s4 - g_size) // 2)

    # Glow: blurred copy of the glyph alpha, tinted darker (creates lift)
    if s4 >= 96:
        from PIL import ImageFilter
        glow_layer = Image.new("RGBA", (s4, s4), (0, 0, 0, 0))
        glow_layer.alpha_composite(g_white, dest=off)
        glow_layer = glow_layer.filter(ImageFilter.GaussianBlur(radius=s4 * 0.018))
        # Reduce alpha to ~25% for subtle lift
        ga = np.array(glow_layer)
        ga[:, :, 3] = (ga[:, :, 3].astype(np.float32) * 0.45).astype(np.uint8)
        glow_layer = Image.fromarray(ga, "RGBA")
        # Composite glow first, then the crisp glyph on top
        icon = Image.alpha_composite(icon, glow_layer)

    icon.alpha_composite(g_white, dest=off)

    # Final downsample to target size with high-quality filter
    return icon.resize((size, size), Image.LANCZOS)


def main() -> int:
    if not SRC.exists():
        print(
            f"source not found: {SRC}\n"
            "Set ONE_LINK_GLYPH_SRC to a source glyph PNG or keep the bundled "
            f"fallback at {DEFAULT_SRC}.",
            file=sys.stderr,
        )
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

    # Multi-resolution app icon. `one-link-black.ico` gives Windows Explorer
    # a fresh cache key after the old purple app tile.
    sizes = [16, 24, 32, 48, 64, 128, 256]
    icons = [make_app_icon(s, transparent) for s in sizes]

    for name in ("one-glyph.ico", "one-link-app.ico", "one-link-black.ico"):
        ico_path = OUT_DIR / name
        icons[-1].save(
            ico_path,
            format="ICO",
            sizes=[(s, s) for s in sizes],
            append_images=icons[:-1],
        )
        print(f"wrote {ico_path}  embedded sizes={sizes}  bytes={ico_path.stat().st_size}")

    # Save a PNG preview of the app icon for documentation
    preview = make_app_icon(512, transparent)
    preview_path = OUT_DIR / "one-glyph-app.png"
    preview.save(preview_path, "PNG", optimize=True)
    print(f"wrote {preview_path}  size={preview.size}  bytes={preview_path.stat().st_size}")

    # Verify ICOs embed all sizes
    print("\nverifying ICOs …")
    for name in ("one-glyph.ico", "one-link-app.ico", "one-link-black.ico"):
        im = Image.open(OUT_DIR / name)
        embedded = sorted(im.info.get("sizes", set()))
        if embedded != [(s, s) for s in sizes]:
            print(f"  WARNING: {name} missing sizes: got {embedded}")
            return 3
        print(f"  {name}: embedded sizes OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
