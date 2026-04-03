#!/usr/bin/env python3
"""Render a corkami-style PNG poster for test-profiles/sRgbEncoding.icc."""

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
    / "iccmax-srgbencoding-annotated-dump.png"
)

WIDTH = 1600
HEIGHT = 1160

PAPER = "#f6f3ee"
INK = "#111111"
MUTED = "#6d6d6d"
GRID = "#4a4a4a"
LIGHT = "#fbfaf7"
ORANGE = "#f18f01"
GREEN = "#6eb257"
BLUE = "#4b7bec"
RED = "#c43d2f"
PURPLE = "#7d5ba6"
TEAL = "#008b8b"
ZERO = "#7a7a7a"
BLACKBOX = "#0f0f0f"

GRID_LEFT = 86
GRID_TOP = 230
ROW_LABEL_W = 60
COL_HEADER_H = 42
CELL = 34
GRID_W = 16 * CELL
GRID_H = 10 * CELL


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
    22,
)
SANS_SMALL = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ],
    17,
)
SANS_BOLD = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    ],
    28,
)
SANS_BIG = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    ],
    62,
)
SANS_TITLE = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    ],
    36,
)
MONO = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ],
    18,
)
MONO_SMALL = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ],
    14,
)


def text_size(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont) -> tuple[int, int]:
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    return right - left, bottom - top


def center_text(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], text: str, font, fill: str) -> None:
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


def draw_annotation(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    title: str,
    body: str,
    accent: str,
) -> None:
    draw.rounded_rectangle(box, radius=18, fill=LIGHT, outline=INK, width=3)
    draw.text((box[0] + 18, box[1] + 14), title, font=SANS_BOLD, fill=accent)
    y = box[1] + 56
    for line in wrap_text(draw, body, SANS_SMALL, box[2] - box[0] - 36):
        draw.text((box[0] + 18, y), line, font=SANS_SMALL, fill=INK)
        y += 24


def draw_connector(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end_x: int,
    end_y: int,
    color: str,
) -> None:
    elbow_x = GRID_LEFT + ROW_LABEL_W + GRID_W + 40
    draw.line([start, (elbow_x, start[1]), (end_x, end_y)], fill=color, width=3)
    draw.ellipse((start[0] - 4, start[1] - 4, start[0] + 4, start[1] + 4), fill=color)


def byte_anchor(index_start: int, index_end: int) -> tuple[int, int]:
    start_col = index_start % 16
    end_col = index_end % 16
    row = index_start // 16
    x = GRID_LEFT + ROW_LABEL_W + ((start_col + end_col + 1) * CELL) / 2
    y = GRID_TOP + COL_HEADER_H + row * CELL + CELL / 2
    return int(x), int(y)


def read_bytes() -> bytes:
    data = PROFILE_PATH.read_bytes()
    if len(data) != 160:
        raise SystemExit(f"Expected 160 bytes in {PROFILE_PATH}, got {len(data)}")
    return data


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
    for idx in range(136, 144):
        mapping[idx] = ORANGE
    for idx in range(144, 148):
        mapping[idx] = BLUE
    for idx in range(152, 156):
        mapping[idx] = GREEN
    return mapping


def draw_grid(draw: ImageDraw.ImageDraw, data: bytes) -> None:
    frame = (
        GRID_LEFT,
        GRID_TOP,
        GRID_LEFT + ROW_LABEL_W + GRID_W + 28,
        GRID_TOP + COL_HEADER_H + GRID_H + 28,
    )
    draw.rounded_rectangle(frame, radius=16, fill=LIGHT, outline=INK, width=3)

    for col in range(16):
        label = f"x{col:X}"
        x = GRID_LEFT + ROW_LABEL_W + col * CELL
        center_text(draw, (x, GRID_TOP, x + CELL, GRID_TOP + COL_HEADER_H - 4), label, MONO_SMALL, MUTED)

    colors = color_map()
    for row in range(10):
        row_label = f"{row:02X}x"
        y = GRID_TOP + COL_HEADER_H + row * CELL
        center_text(draw, (GRID_LEFT, y, GRID_LEFT + ROW_LABEL_W - 6, y + CELL), row_label, MONO, MUTED)
        for col in range(16):
            idx = row * 16 + col
            x = GRID_LEFT + ROW_LABEL_W + col * CELL
            byte = data[idx]
            fill = colors.get(idx, ZERO if byte == 0 else GRID)
            cell_box = (x, y, x + CELL - 3, y + CELL - 3)
            draw.rounded_rectangle(cell_box, radius=6, fill=fill)
            center_text(draw, cell_box, f"{byte:02X}", MONO_SMALL, "white")


def render() -> None:
    data = read_bytes()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    image = Image.new("RGB", (WIDTH, HEIGHT), PAPER)
    draw = ImageDraw.Draw(image)

    draw.ellipse((-160, -120, 360, 310), fill="#f4ddc6")
    draw.ellipse((1180, 820, 1700, 1260), fill="#e1ecf9")

    logo_box = (GRID_LEFT + 120, 54, GRID_LEFT + 300, 142)
    draw.rectangle(logo_box, fill=BLACKBOX, outline=INK, width=4)
    center_text(draw, logo_box, "ICC", SANS_BIG, "white")
    draw.line((logo_box[0], 158, logo_box[2], 158), fill=GREEN, width=4)
    draw.text((logo_box[0], 164), "iccMAX cenc specimen", font=SANS_SMALL, fill=GREEN)

    draw.text((430, 58), "A MINIMAL ICC PROFILE", font=SANS_TITLE, fill=INK)
    draw.text((430, 104), "Header, tags, payload, parser checks", font=SANS_BOLD, fill=ORANGE)

    bubble = (1040, 80, 1540, 244)
    draw.rounded_rectangle(bubble, radius=28, fill=LIGHT, outline=INK, width=4)
    bubble_text = (
        "Fixed 128-byte header. Tag table next. Typed payload after that. "
        "This sample keeps the whole ICC object visible in only 160 bytes."
    )
    y = bubble[1] + 22
    for line in wrap_text(draw, bubble_text, SANS_SMALL, bubble[2] - bubble[0] - 42):
        draw.text((bubble[0] + 22, y), line, font=SANS_SMALL, fill=INK)
        y += 24

    draw_grid(draw, data)

    draw.text((GRID_LEFT + 64, GRID_TOP + COL_HEADER_H + GRID_H + 42), "AN ICC FILE", font=SANS_BIG, fill=INK)
    draw.text(
        (GRID_LEFT + 292, GRID_TOP + COL_HEADER_H + GRID_H + 118),
        "test-profiles/sRgbEncoding.icc",
        font=SANS_SMALL,
        fill=ORANGE,
    )

    annotations = [
        (
            (980, 250, 1536, 346),
            "SIZE 0x000000A0",
            "Declared size is 160 bytes. Check this before trusting any later offset.",
            ORANGE,
            (0, 3),
        ),
        (
            (980, 362, 1536, 470),
            "VERSION 5 / CLASS cenc",
            "Bytes 0x08-0x13 mark an iccMAX v5 cenc profile with RGB data color space.",
            BLUE,
            (12, 15),
        ),
        (
            (980, 486, 1536, 594),
            "MAGIC acsp",
            "acsp marks an ICC root object. Reject mislabeled carriers if it is missing.",
            GREEN,
            (36, 39),
        ),
        (
            (980, 610, 1536, 718),
            "TAG COUNT = 1",
            "The tag table starts at 0x80 and holds one contiguous entry.",
            GREEN,
            (128, 131),
        ),
        (
            (980, 734, 1536, 852),
            "rfnm -> 0x90, size 0x0D",
            "This required reference name tag points to 0x90. Overflow-check offset plus size.",
            PURPLE,
            (132, 143),
        ),
        (
            (980, 868, 1536, 986),
            "utf8 payload = sRGB",
            "The payload starts with utf8 and carries the string sRGB.",
            TEAL,
            (144, 155),
        ),
    ]

    for box, title, body, accent, byte_range in annotations:
        draw_annotation(draw, box, title, body, accent)
        anchor = byte_anchor(*byte_range)
        draw_connector(draw, anchor, box[0], (box[1] + box[3]) // 2, accent)

    footer = (850, 1028, 1540, 1132)
    draw.rounded_rectangle(footer, radius=18, fill=LIGHT, outline=INK, width=3)
    footer_text = (
        "Conformant in ICC.2 cenc context. Generic ICC.1 heuristics may still "
        "warn because this class uses zero PCS and a minimal required-tag set."
    )
    y = footer[1] + 14
    for line in wrap_text(draw, footer_text, SANS_SMALL, footer[2] - footer[0] - 28):
        draw.text((footer[0] + 16, y), line, font=SANS_SMALL, fill=INK)
        y += 22

    image.save(OUTPUT_PATH)


if __name__ == "__main__":
    render()
