#!/usr/bin/env python3
"""Render a higher-resolution v2 ICC specimen poster with a table-first layout."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[3]
PROFILE_PATH = ROOT / "test-profiles" / "sRgbEncoding.icc"
OUTPUT_PATH = (
    ROOT
    / "docs"
    / "iccDEV"
    / "specifications"
    / "png"
    / "iccmax-srgbencoding-annotated-dump-v2.png"
)

# Roughly 2x the total pixel count of the 1600x1160 v1 poster while preserving
# the same overall aspect ratio.
WIDTH = 2264
HEIGHT = 1640

PAPER = "#f6f1e8"
PANEL = "#fffdfa"
INK = "#171717"
MUTED = "#666666"
GRID = "#d8c9b3"
SHADOW = "#d6cab8"
ZERO = "#8d8d8d"
ORANGE = "#f18f01"
RED = "#dc493a"
BLUE = "#4b7bec"
GREEN = "#77b255"
PURPLE = "#8a63c7"
TEAL = "#0f9aa7"
GOLD = "#e6aa2c"
BLACKBOX = "#101010"

TABLE_LEFT = 72
TABLE_TOP = 188
ROW_LABEL_W = 92
COL_HEADER_H = 58
CELL = 82
GRID_W = 16 * CELL
GRID_H = 10 * CELL
RIGHT_X = 1620


def load_font(candidates: Iterable[str], size: int) -> ImageFont.FreeTypeFont:
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default()


SANS = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ],
    24,
)
SANS_SMALL = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ],
    22,
)
SANS_BOLD = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    ],
    36,
)
SANS_TITLE = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    ],
    68,
)
MONO = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ],
    18,
)
MONO_BOLD = load_font(
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
    15,
)


def text_size(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont) -> tuple[int, int]:
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    return right - left, bottom - top


def center_text(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    text: str,
    font: ImageFont.ImageFont,
    fill: str,
) -> None:
    w, h = text_size(draw, text, font)
    x = box[0] + (box[2] - box[0] - w) / 2
    y = box[1] + (box[3] - box[1] - h) / 2 - 2
    draw.text((x, y), text, font=font, fill=fill)


def wrap_text(draw: ImageDraw.ImageDraw, text: str, font, max_width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        probe = word if not current else current + " " + word
        if text_size(draw, probe, font)[0] <= max_width:
            current = probe
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def ascii_label(byte: int) -> str:
    if 32 <= byte <= 126:
        ch = chr(byte)
        if ch == " ":
            return "sp"
        return ch
    return "."


def color_map() -> dict[int, str]:
    mapping: dict[int, str] = {}
    for idx in range(0, 4):
        mapping[idx] = ORANGE
    for idx in range(8, 12):
        mapping[idx] = RED
    for idx in range(12, 16):
        mapping[idx] = BLUE
    for idx in range(16, 20):
        mapping[idx] = TEAL
    for idx in range(36, 40):
        mapping[idx] = GREEN
    for idx in range(128, 132):
        mapping[idx] = GREEN
    for idx in range(132, 136):
        mapping[idx] = PURPLE
    for idx in range(136, 140):
        mapping[idx] = GOLD
    for idx in range(140, 144):
        mapping[idx] = RED
    for idx in range(144, 148):
        mapping[idx] = TEAL
    for idx in range(152, 156):
        mapping[idx] = GREEN
    return mapping


def byte_anchor(index_start: int, index_end: int) -> tuple[int, int]:
    start_col = index_start % 16
    end_col = index_end % 16
    row = index_start // 16
    x = TABLE_LEFT + ROW_LABEL_W + ((start_col + end_col + 1) * CELL) / 2
    y = TABLE_TOP + COL_HEADER_H + row * CELL + CELL / 2
    return int(x), int(y)


def draw_callout(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    title: str,
    body: str,
    accent: str,
) -> None:
    shadow = (box[0] + 8, box[1] + 8, box[2] + 8, box[3] + 8)
    draw.rounded_rectangle(shadow, radius=20, fill=SHADOW)
    draw.rounded_rectangle(box, radius=20, fill=PANEL, outline=INK, width=3)
    draw.text((box[0] + 20, box[1] + 16), title, font=SANS_BOLD, fill=accent)
    y = box[1] + 66
    for line in wrap_text(draw, body, SANS_SMALL, box[2] - box[0] - 40):
        draw.text((box[0] + 20, y), line, font=SANS_SMALL, fill=INK)
        y += 28


def draw_connector(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    box: tuple[int, int, int, int],
    color: str,
) -> None:
    elbow_x = TABLE_LEFT + ROW_LABEL_W + GRID_W + 58
    target = (box[0], (box[1] + box[3]) // 2)
    draw.line([start, (elbow_x, start[1]), target], fill=color, width=4)
    draw.ellipse((start[0] - 5, start[1] - 5, start[0] + 5, start[1] + 5), fill=color)


def draw_legend_chip(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    color: str,
    label: str,
) -> int:
    chip_w = 32
    draw.rounded_rectangle((x, y, x + chip_w, y + 32), radius=8, fill=color, outline=INK, width=2)
    draw.text((x + chip_w + 12, y + 4), label, font=SANS_SMALL, fill=INK)
    return x + chip_w + 12 + text_size(draw, label, SANS_SMALL)[0] + 34


def draw_table(draw: ImageDraw.ImageDraw, data: bytes) -> None:
    outer = (
        TABLE_LEFT,
        TABLE_TOP,
        TABLE_LEFT + ROW_LABEL_W + GRID_W + 30,
        TABLE_TOP + COL_HEADER_H + GRID_H + 34,
    )
    draw.rounded_rectangle((outer[0] + 10, outer[1] + 10, outer[2] + 10, outer[3] + 10), radius=24, fill=SHADOW)
    draw.rounded_rectangle(outer, radius=24, fill=PANEL, outline=INK, width=4)

    for col in range(16):
        label = f"x{col:X}"
        x = TABLE_LEFT + ROW_LABEL_W + col * CELL
        center_text(draw, (x, TABLE_TOP, x + CELL, TABLE_TOP + COL_HEADER_H), label, MONO, MUTED)

    colors = color_map()
    for row in range(10):
        y = TABLE_TOP + COL_HEADER_H + row * CELL
        row_label = f"{row:02X}x"
        center_text(draw, (TABLE_LEFT, y, TABLE_LEFT + ROW_LABEL_W - 12, y + CELL), row_label, MONO, MUTED)
        for col in range(16):
            idx = row * 16 + col
            x = TABLE_LEFT + ROW_LABEL_W + col * CELL
            fill = colors.get(idx, ZERO if data[idx] == 0 else GRID)
            tile = (x + 4, y + 4, x + CELL - 8, y + CELL - 8)
            draw.rounded_rectangle(tile, radius=12, fill=fill, outline=INK, width=2)
            draw.text((tile[0] + 8, tile[1] + 8), f"{idx:02X}", font=MONO_SMALL, fill="white")
            center_text(draw, (tile[0], tile[1] + 4, tile[2], tile[3] - 10), f"{data[idx]:02X}", MONO_BOLD, "white")
            ascii_box = (tile[0], tile[3] - 24, tile[2], tile[3] - 2)
            center_text(draw, ascii_box, ascii_label(data[idx]), MONO_SMALL, "white")


def render() -> None:
    data = PROFILE_PATH.read_bytes()
    if len(data) != 160:
        raise SystemExit(f"Expected 160 bytes in {PROFILE_PATH}, got {len(data)}")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    image = Image.new("RGB", (WIDTH, HEIGHT), PAPER)
    draw = ImageDraw.Draw(image)

    draw.ellipse((-160, -140, 420, 430), fill="#f3dcc0")
    draw.ellipse((1890, 1190, 2480, 1770), fill="#dfe9f8")

    logo = (TABLE_LEFT + 16, 34, TABLE_LEFT + 220, 128)
    draw.rectangle(logo, fill=BLACKBOX, outline=INK, width=4)
    center_text(draw, logo, "ICC", SANS_TITLE, "white")
    draw.text((TABLE_LEFT + 18, 140), "table-first poster v2", font=SANS_SMALL, fill=GREEN)

    draw.text((TABLE_LEFT + 300, 44), "A MINIMAL ICC PROFILE", font=SANS_TITLE, fill=INK)
    draw.text((TABLE_LEFT + 302, 114), "160 bytes arranged like a byte table of elements", font=SANS_BOLD, fill=ORANGE)

    note_box = (RIGHT_X, 44, 2182, 190)
    draw.rounded_rectangle(note_box, radius=24, fill=PANEL, outline=INK, width=4)
    note = (
        "Read order: 128-byte header, 16-byte tag table, 16-byte payload. "
        "Every highlighted tile below is an exact byte from the specimen file."
    )
    y = note_box[1] + 18
    for line in wrap_text(draw, note, SANS_SMALL, note_box[2] - note_box[0] - 34):
        draw.text((note_box[0] + 18, y), line, font=SANS_SMALL, fill=INK)
        y += 28

    draw_table(draw, data)

    draw.text((TABLE_LEFT + 54, 1118), "AN ICC FILE", font=SANS_TITLE, fill=INK)
    draw.text((TABLE_LEFT + 356, 1196), "test-profiles/sRgbEncoding.icc", font=SANS_SMALL, fill=ORANGE)

    legend_y = 1286
    legend_x = TABLE_LEFT + 24
    legend_x = draw_legend_chip(draw, legend_x, legend_y, ORANGE, "size and tag offset math")
    legend_x = draw_legend_chip(draw, legend_x, legend_y, RED, "version and tag size")
    legend_x = draw_legend_chip(draw, legend_x, legend_y, BLUE, "profile identity")
    legend_x = draw_legend_chip(draw, legend_x, legend_y, GREEN, "ICC structure")
    legend_x = draw_legend_chip(draw, legend_x, legend_y, PURPLE, "tag signature")
    draw_legend_chip(draw, legend_x, legend_y, TEAL, "typed payload")

    callouts = [
        (
            (RIGHT_X, 234, 2182, 362),
            "SIZE 0x000000A0",
            "00-03 declare a 160-byte file. Compare this with the real file length before trusting offsets.",
            ORANGE,
            (0, 3),
        ),
        (
            (RIGHT_X, 392, 2182, 536),
            "V5 cenc / RGB",
            "08-13 identify an ICC.2 cenc profile with RGB data color space. This is iccMAX context.",
            BLUE,
            (8, 19),
        ),
        (
            (RIGHT_X, 566, 2182, 710),
            "ZERO HEADER REGION",
            "14-7F are mostly zero on purpose for this class. Zero PCS and zero profile ID are expected here.",
            ZERO,
            (20, 127),
        ),
        (
            (RIGHT_X, 740, 2182, 852),
            "acsp MAGIC",
            "24-27 spell acsp. Reject mislabeled carriers if this ICC signature is missing.",
            GREEN,
            (36, 39),
        ),
        (
            (RIGHT_X, 882, 2182, 1026),
            "TAG ENTRY AT 0x80",
            "80-8F declare one entry: rfnm at 0x90 with size 0x0D. Offset math must stay in-bounds.",
            PURPLE,
            (128, 143),
        ),
        (
            (RIGHT_X, 1056, 2182, 1184),
            "UTF8 DATA = sRGB",
            "90-9F begin with utf8 type bytes and carry the readable text sRGB.",
            TEAL,
            (144, 155),
        ),
        (
            (RIGHT_X - 70, 1318, 2182, 1528),
            "CONFORMANCE SNAPSHOT",
            "Conformant as a tiny ICC.2 cenc specimen. Generic ICC.1-style heuristics can still warn on this class.",
            GOLD,
            (132, 155),
        ),
    ]

    for box, title, body, accent, byte_range in callouts:
        draw_callout(draw, box, title, body, accent)
        draw_connector(draw, byte_anchor(*byte_range), box, accent)

    image.save(OUTPUT_PATH)


if __name__ == "__main__":
    render()
