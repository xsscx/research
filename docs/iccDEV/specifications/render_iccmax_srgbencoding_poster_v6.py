#!/usr/bin/env python3
"""Render a no-logo ico_png-style ICC specimen poster."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[3]
PROFILE_PATH = ROOT / "test-profiles" / "sRgbEncoding.icc"
OUTPUT_PATH = ROOT / "docs" / "iccDEV" / "specifications" / "png" / "iccmax-srgbencoding-annotated-dump-v6.png"

WIDTH = 2264
HEIGHT = 1640
PAPER = "#eef3f7"
INK = "#202020"
MUTED = "#91989f"
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
    78,
)
TITLE_SMALL = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ],
    40,
)
BODY = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ],
    28,
)
FIELD = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    ],
    26,
)
MONO = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ],
    34,
)
MONO_SMALL = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ],
    20,
)


def text_size(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont) -> tuple[int, int]:
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    return right - left, bottom - top


def draw_colored_phrase(draw: ImageDraw.ImageDraw, x: int, y: int, pieces: list[tuple[str, str]], font) -> None:
    cursor = x
    for text, color in pieces:
        draw.text((cursor, y), text, font=font, fill=color)
        cursor += text_size(draw, text, font)[0] + 10


def color_for_index(index: int) -> str:
    if index in range(0, 4):
        return ORANGE
    if index in range(8, 12):
        return PURPLE
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


def draw_capsule(draw: ImageDraw.ImageDraw, x: int, y: int, byte_text: str, color: str) -> None:
    box = (x, y, x + 74, y + 52)
    draw.rounded_rectangle(box, radius=12, fill="white", outline=color, width=4)
    tx = x + (74 - text_size(draw, byte_text, MONO_SMALL)[0]) / 2
    draw.text((tx, y + 11), byte_text, font=MONO_SMALL, fill=color)


def draw_cluster(
    draw: ImageDraw.ImageDraw,
    data: bytes,
    offsets: list[int],
    left: int,
    top: int,
    per_row: int,
    label_prefix: str,
) -> dict[int, tuple[int, int]]:
    anchors: dict[int, tuple[int, int]] = {}
    step_x = 82
    step_y = 72
    for i, off in enumerate(offsets[:per_row]):
        x = left + i * step_x
        draw.text((x + 14, top - 30), f"x{i:X}", font=MONO_SMALL, fill=MUTED)
    for i, off in enumerate(offsets):
        row = i // per_row
        col = i % per_row
        x = left + col * step_x
        y = top + row * step_y
        if col == 0:
            draw.text((left - 64, y + 8), f"{label_prefix}{row:X}x", font=MONO_SMALL, fill=MUTED)
        draw_capsule(draw, x, y, f"{data[off]:02X}", color_for_index(off))
        anchors[off] = (x + 37, y + 26)
    return anchors


def draw_ledger(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    title: str,
    rows: list[tuple[str, str, str]],
) -> None:
    draw.text((x, y), title, font=TITLE_SMALL, fill=MUTED)
    yy = y + 64
    for label, value, color in rows:
        draw.text((x, yy), label, font=FIELD, fill=color)
        draw.text((x + 260, yy), value, font=BODY, fill=color)
        yy += 38


def draw_connector(draw: ImageDraw.ImageDraw, start: tuple[int, int], x_mid: int, end: tuple[int, int], color: str) -> None:
    draw.line([start, (x_mid, start[1]), end], fill=color, width=3)


def render() -> None:
    data = PROFILE_PATH.read_bytes()
    if len(data) != 160:
        raise SystemExit("Unexpected specimen size")
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    image = Image.new("RGB", (WIDTH, HEIGHT), PAPER)
    draw = ImageDraw.Draw(image)

    draw_colored_phrase(
        draw,
        94,
        36,
        [
            ("an", INK),
            ("Ico-like", ORANGE),
            ("icc", INK),
            ("map", INK),
        ],
        TITLE,
    )
    draw.text((100, 130), "(png-style decomposition of sRgbEncoding.icc)", font=TITLE_SMALL, fill=INK)

    header_anchors = draw_cluster(draw, data, list(range(0, 20)), 126, 260, 8, "0")
    magic_anchors = draw_cluster(draw, data, list(range(36, 40)), 370, 500, 4, "2")
    tag_anchors = draw_cluster(draw, data, list(range(128, 144)), 116, 690, 8, "8")
    payload_anchors = draw_cluster(draw, data, list(range(144, 160)), 560, 930, 8, "9")

    draw.text((188, 1368), "an", font=TITLE, fill=INK)
    draw.text((332, 1368), "Ico-like", font=TITLE, fill=ORANGE)
    draw.text((726, 1368), "specimen", font=TITLE, fill=INK)
    draw.text((338, 1460), "(PNG-based layout study)", font=TITLE_SMALL, fill=INK)

    draw_ledger(
        draw,
        1400,
        116,
        "HEADER",
        [
            ("size", "0x000000A0", ORANGE),
            ("version", "5.0.0", PURPLE),
            ("class", "cenc", RED),
            ("space", "RGB", GREEN),
            ("magic", "acsp", BLUE),
        ],
    )
    draw_ledger(
        draw,
        1400,
        480,
        "TAG TABLE",
        [
            ("count", "1", GREEN),
            ("entry", "rfnm", PURPLE),
            ("offset", "0x90", ORANGE),
            ("size", "0x0D", ORANGE),
        ],
    )
    draw_ledger(
        draw,
        1400,
        790,
        "PAYLOAD",
        [
            ("type", "utf8", GOLD),
            ("text", "sRGB", TEAL),
            ("pad", "00 00 00 00", GRAY),
        ],
    )
    draw_ledger(
        draw,
        1400,
        1110,
        "NOTES",
        [
            ("rule", "header -> table -> data", INK),
            ("guard", "offset + size <= file", ORANGE),
            ("context", "ICC.2 cenc semantics", GREEN),
        ],
    )

    draw_connector(draw, header_anchors[0], 1220, (1380, 190), ORANGE)
    draw_connector(draw, header_anchors[8], 1220, (1380, 228), PURPLE)
    draw_connector(draw, header_anchors[12], 1220, (1380, 266), RED)
    draw_connector(draw, header_anchors[16], 1220, (1380, 304), GREEN)
    draw_connector(draw, magic_anchors[36], 1220, (1380, 342), BLUE)
    draw_connector(draw, tag_anchors[128], 1220, (1380, 554), GREEN)
    draw_connector(draw, tag_anchors[132], 1220, (1380, 592), PURPLE)
    draw_connector(draw, tag_anchors[136], 1220, (1380, 630), ORANGE)
    draw_connector(draw, payload_anchors[144], 1220, (1380, 864), GOLD)
    draw_connector(draw, payload_anchors[152], 1220, (1380, 902), TEAL)

    image.save(OUTPUT_PATH)


if __name__ == "__main__":
    render()
