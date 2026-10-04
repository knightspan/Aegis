"""Render the Sanctum app icon at build time, in every format a package needs.

The one source is ``packaging/icon/sanctum-logo.png``: the Sanctum Forensics
logo, 1024x1024, square, on its own pink field. Every platform's icon is
scaled from it here, so a new logo is a one-file change and the packages never
drift apart.

    python packaging/make_icons.py build/icons
    -> sanctum.png (512)   Linux: .deb hicolor icon, AppImage
       sanctum.ico         Windows: the executable and the installer
       sanctum.icns        macOS: the .app bundle
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image

SOURCE = Path(__file__).resolve().parent / "icon" / "sanctum-logo.png"

ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def load() -> Image.Image:
    """The source, as square RGBA at 1024x1024."""
    image = Image.open(SOURCE).convert("RGBA")
    if image.width != image.height:
        raise SystemExit(
            f"{SOURCE} is {image.width}x{image.height}; an icon must be square"
        )
    if image.width != 1024:
        image = image.resize((1024, 1024), Image.Resampling.LANCZOS)
    return image


def main(out: str) -> int:
    target = Path(out)
    target.mkdir(parents=True, exist_ok=True)
    source = load()
    source.resize((512, 512), Image.Resampling.LANCZOS).save(target / "sanctum.png")
    # Pillow scales the larger image down to each size itself.
    source.save(target / "sanctum.ico", sizes=ICO_SIZES)
    source.save(target / "sanctum.icns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "build/icons"))
