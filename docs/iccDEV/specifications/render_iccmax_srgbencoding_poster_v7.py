#!/usr/bin/env python3
"""Render a no-logo bmp5-style ICC specimen poster."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[3]
PROFILE_PATH = ROOT / "test-profiles" / "sRgbEncoding.icc"
OUTPUT_PATH = ROOT / "docs" / "iccDEV" / "specifications" / "png" / "iccmax-srgbencoding-annotated-dump-v7.png"

WIDTH = 2264
HEIGHT = 1640
PAPER = "#eef3f7"
INK = "#202020"
MUTED = "#969da4"
ORANGE = "#f29c1f"
GREEN = "#76b82a"
BLUE = "#5a86ff"
PURPLE = "#b76cff"
RED = "#d83d32"
TEAL = "#18a6b8"
GRAY = "#a7acb3"
GOLD = "#c9a11e"


def load_font(candidates: Iterable[str], size: int) -> ImageFont.FreeTypeFont:
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default()


TITLE = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ],
    88,
)
TITLE_SMALL = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ],
    42,
)
FIELD = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    ],
    24,
)
BODY = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ],
    24,
)
MONO = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ],
    28,
)
MONO_SMALL = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ],
    18,
)


def text_size(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont) -> tuple[int, int]:
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    return right - left, bottom - top


def draw_colored_phrase(draw: ImageDraw.ImageDraw, x: int, y: int, parts: list[tuple[str, str]]) -> None:
    cursor = x
    for text, color in parts:
        draw.text((cursor, y), text, font=TITLE, fill=color)
        cursor += text_size(draw, text, TITLE)[0] + 10


def color_for_index(index: int) -> str:
    if index in range(0, 4):
        return RED
    if index in range(4, 8):
        return GRAY
    if index in range(8, 12):
        return GOLD
    if index in range(12, 16):
        return RED
    if index in range(16, 20):
        return GREEN
    if index in range(36, 40):
        return BLUE
    if index in range(128, 132):
        return GREEN
    if index in range(132, 136):
        return PURPLE
    if index in range(136, 144):
        return ORANGE
    if index in range(144, 148):
        return GOLD
    if index in range(152, 156):
        return TEAL
    return GRAY


def draw_group(draw: ImageDraw.ImageDraw, data: bytes, offsets: list[int], left: int, top: int, per_row: int, label: str) -> dict[int, tuple[int, int]]:
    anchors: dict[int, tuple[int, int]] = {}
    step_x = 66
    step_y = 58
    for i, off in enumerate(offsets[:per_row]):
        draw.text((left + 88 + i * step_x, top - 32), f"x{i:X}", font=MONO_SMALL, fill=MUTED)
    for i, off in enumerate(offsets):
        row = i // per_row
        col = i % per_row
        x = left + 88 + col * step_x
        y = top + row * step_y
        if col == 0:
            draw.text((left, y + 8), f"{label}{row:X}x", font=MONO_SMALL, fill=MUTED)
        draw.text((x, y), f"{data[off]:02X}", font=MONO, fill=color_for_index(off))
        anchors[off] = (x + 18, y + 16)
    return anchors


def draw_ledger(draw: ImageDraw.ImageDraw, x: int, y: int, title_parts: list[tuple[str, str]], rows: list[tuple[str, str, str]]) -> None:
    cursor = x
    for text, color in title_parts:
        draw.text((cursor, y), text, font=TITLE_SMALL, fill=color)
        cursor += text_size(draw, text, TITLE_SMALL)[0] + 8
    yy = y + 64
    for label, value, color in rows:
        draw.text((x + 360, yy), label, font=FIELD, fill=color)
        draw.text((x + 640, yy), value, font=BODY, fill=color)
        yy += 38


def draw_connector(draw: ImageDraw.ImageDraw, start: tuple[int, int], x_mid: int, end_y: int) -> None:
    draw.line([start, (x_mid, start[1]), (x_mid, end_y)], fill=MUTED, width=3)


def render() -> None:
    data = PROFILE_PATH.read_bytes()
    if len(data) != 160:
        raise SystemExit("Unexpected specimen size")
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    image = Image.new("RGB", (WIDTH, HEIGHT), PAPER)
    draw = ImageDraw.Draw(image)

    draw.text((100, 24), "profile specimen", font=TITLE_SMALL, fill=INK)
    draw_colored_phrase(
        draw,
        34,
        62,
        [
            ("B", ORANGE),
            ("YTE", INK),
            ("M", ORANGE),
            ("AP", INK),
            ("5", ORANGE),
        ],
    )

    anchors_header = draw_group(draw, data, list(range(0, 64)), 34, 248, 16, "0")
    anchors_tag = draw_group(draw, data, list(range(128, 144)), 106, 780, 8, "8")
    anchors_payload = draw_group(draw, data, list(range(144, 160)), 106, 1110, 8, "9")

    draw_connector(draw, anchors_header[0], 1010, 248)
    draw_connector(draw, anchors_header[36], 1010, 402)
    draw_connector(draw, anchors_tag[128], 1010, 770)
    draw_connector(draw, anchors_payload[144], 1010, 1162)

    draw_ledger(
        draw,
        1160,
        170,
        [("HEADER", INK)],
        [
            ("size", "0x000000A0", RED),
            ("cmm", "0x00000000", GRAY),
            ("version", "0x05000000", GOLD),
            ("class", "cenc", RED),
            ("color space", "RGB", GREEN),
            ("pcs", "0x00000000", GRAY),
            ("magic", "acsp", BLUE),
        ],
    )
    draw_ledger(
        draw,
        1160,
        730,
        [("TAG", ORANGE), ("TABLE", INK)],
        [
            ("count", "1", GREEN),
            ("signature", "rfnm", PURPLE),
            ("offset", "0x00000090", ORANGE),
            ("size", "0x0000000D", ORANGE),
        ],
    )
    draw_ledger(
        draw,
        1160,
        1090,
        [("DATA", INK)],
        [
            ("type", "utf8", GOLD),
            ("text", "sRGB", TEAL),
            ("padding", "00 00 00 00", GRAY),
        ],
    )

    draw.text((120, 1450), "a", font=TITLE, fill=INK)
    draw.text((206, 1450), "Bmp-like", font=TITLE, fill=ORANGE)
    draw.text((618, 1450), "profile", font=TITLE, fill=INK)
    draw.text((166, 1540), "BITMAP of header / tag table / payload", font=TITLE_SMALL, fill=INK)

    image.save(OUTPUT_PATH)


if __name__ == "__main__":
    render()
