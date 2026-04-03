#!/usr/bin/env python3
"""Render a corkami TIFF_BE-style ICC specimen poster."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[3]
PROFILE_PATH = ROOT / "test-profiles" / "sRgbEncoding.icc"
LOGO_TOP_PATH = ROOT / "docs" / "iccDEV" / "ICC_logo_top.gif"
LOGO_TEXT_PATH = ROOT / "docs" / "iccDEV" / "ICC_logo_text.gif"
OUTPUT_PATH = ROOT / "docs" / "iccDEV" / "specifications" / "png" / "iccmax-srgbencoding-annotated-dump-v5.png"

WIDTH = 2264
HEIGHT = 1640
PAPER = "#fbfaf7"
INK = "#111111"
LINE = "#9d9d9d"
LIGHT = "#f0ece4"
ORANGE = "#f26522"
BLUE = "#4f74ff"
GREEN = "#77b255"
PURPLE = "#bf59ff"
RED = "#e8513c"
TEAL = "#1aa3b4"
GRAY = "#8c8c8c"
GOLD = "#c59a29"


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
    92,
)
TITLE_SMALL = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ],
    36,
)
SECTION = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ],
    50,
)
LABEL = load_font(
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
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    ],
    28,
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


def draw_colored_title(draw: ImageDraw.ImageDraw, x: int, y: int, parts: list[tuple[str, str]], gap: int = 16) -> None:
    cursor = x
    for text, color in parts:
        draw.text((cursor, y), text, font=TITLE, fill=color)
        cursor += text_size(draw, text, TITLE)[0] + gap


def resize_logo(path: Path, scale: float) -> Image.Image:
    image = Image.open(path).convert("RGBA")
    return image.resize((int(image.width * scale), int(image.height * scale)), Image.Resampling.LANCZOS)


def color_for_index(index: int) -> str:
    if index in range(0, 4):
        return PURPLE
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
    if index in range(136, 140):
        return RED
    if index in range(140, 144):
        return RED
    if index in range(144, 148):
        return GOLD
    if index in range(152, 156):
        return TEAL
    return GRAY


def draw_hex_dump(draw: ImageDraw.ImageDraw, data: bytes, left: int, top: int) -> dict[int, tuple[int, int]]:
    positions: dict[int, tuple[int, int]] = {}
    cell = 70
    row_h = 54
    for col in range(16):
        draw.text((left + 92 + col * cell, top), f"{col:X}", font=MONO_SMALL, fill=INK)
    for row in range(10):
        y = top + 48 + row * row_h
        draw.text((left, y), f"{row:02X}:", font=MONO_SMALL, fill=INK)
        for col in range(16):
            idx = row * 16 + col
            x = left + 92 + col * cell
            draw.text((x, y), f"{data[idx]:02X}", font=MONO, fill=color_for_index(idx))
            positions[idx] = (x + 18, y + 18)
    return positions


def draw_section_header(draw: ImageDraw.ImageDraw, x: int, y: int, title_parts: list[tuple[str, str]]) -> None:
    cursor = x
    for text, color in title_parts:
        draw.text((cursor, y), text, font=SECTION, fill=color)
        cursor += text_size(draw, text, SECTION)[0] + 12


def draw_field_value_table(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    title_parts: list[tuple[str, str]],
    rows: list[tuple[str, str, str]],
) -> None:
    draw.line((box[0], box[1], box[2], box[1]), fill=LINE, width=3)
    draw_section_header(draw, box[0] + 24, box[1] + 20, title_parts)
    field_x = box[0] + 460
    value_x = box[0] + 780
    draw.text((field_x, box[1] + 18), "FIELDS", font=LABEL, fill=INK)
    draw.text((value_x, box[1] + 18), "VALUES", font=LABEL, fill=INK)
    y = box[1] + 90
    for label, value, color in rows:
        draw.text((field_x, y), label, font=LABEL, fill=color)
        draw.text((value_x, y), value, font=BODY, fill=color)
        y += 38
    draw.line((box[0], box[3], box[2], box[3]), fill=LINE, width=3)


def draw_connector(draw: ImageDraw.ImageDraw, start: tuple[int, int], mid_x: int, end: tuple[int, int], dashed: bool = False) -> None:
    points = [start, (mid_x, start[1]), end]
    if not dashed:
        draw.line(points, fill=LINE, width=3)
        return
    # Crude dashed polyline over horizontal/vertical segments.
    sx, sy = start
    ex, ey = mid_x, sy
    tx, ty = end
    for x in range(min(sx, ex), max(sx, ex), 18):
        draw.line((x, sy, min(x + 10, ex), sy), fill=LINE, width=2)
    step = 18 if ey <= ty else -18
    current = ey
    while (current <= ty if step > 0 else current >= ty):
        nxt = current + (10 if step > 0 else -10)
        draw.line((ex, current, ex, nxt), fill=LINE, width=2)
        current += step
    for x in range(min(ex, tx), max(ex, tx), 18):
        draw.line((x, ty, min(x + 10, tx), ty), fill=LINE, width=2)


def render() -> None:
    data = PROFILE_PATH.read_bytes()
    if len(data) != 160:
        raise SystemExit("Unexpected specimen size")
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    image = Image.new("RGB", (WIDTH, HEIGHT), PAPER)
    draw = ImageDraw.Draw(image)

    draw.text((126, 16), "BIG ENDIAN", font=TITLE_SMALL, fill=INK)
    draw_colored_title(
        draw,
        34,
        48,
        [
            ("T", ORANGE),
            ("AGGED", INK),
            ("C", ORANGE),
            ("OLOR", INK),
            ("P", ORANGE),
            ("ROFILE", INK),
            ("F", ORANGE),
            ("ORMAT", INK),
        ],
    )

    specimen = resize_logo(LOGO_TOP_PATH, 2.8)
    specimen_x = 288
    specimen_y = 288
    draw.rectangle((specimen_x - 16, specimen_y - 16, specimen_x + specimen.width + 16, specimen_y + specimen.height + 16), fill="white", outline=INK, width=8)
    image.paste(specimen, (specimen_x, specimen_y), specimen)

    positions = draw_hex_dump(draw, data, 54, 580)

    draw_field_value_table(
        draw,
        (1220, 240, 2200, 596),
        [("PROFILE", INK), ("HEADER", INK)],
        [
            ("endianness", "big endian", PURPLE),
            ("size", "0x000000A0", GOLD),
            ("version", "0x05000000", GOLD),
            ("class", "cenc", RED),
            ("color space", "RGB", GREEN),
            ("magic", "acsp", BLUE),
            ("tag count", "1", GREEN),
        ],
    )
    draw_field_value_table(
        draw,
        (1220, 634, 2200, 1074),
        [("TAG", ORANGE), ("DIRECTORY", INK)],
        [
            ("entry", "rfnm", PURPLE),
            ("offset", "0x00000090", RED),
            ("size", "0x0000000D", RED),
            ("next tag", "none", GRAY),
        ],
    )
    draw_field_value_table(
        draw,
        (1220, 1112, 2200, 1452),
        [("DATA", INK)],
        [
            ("type", "utf8", GOLD),
            ("text", "sRGB", TEAL),
            ("padding", "00 00 00 00", GRAY),
        ],
    )

    draw_connector(draw, (specimen_x + specimen.width + 16, specimen_y + specimen.height // 2), 920, (1210, 310))
    draw_connector(draw, positions[36], 1020, (1210, 500), dashed=True)
    draw_connector(draw, positions[128], 1020, (1210, 716), dashed=True)
    draw_connector(draw, positions[132], 1020, (1210, 792), dashed=True)
    draw_connector(draw, positions[136], 1020, (1210, 868), dashed=True)
    draw_connector(draw, positions[144], 1020, (1210, 1186), dashed=True)
    draw_connector(draw, positions[152], 1020, (1210, 1262), dashed=True)

    draw.text((64, 1286), "ICC uses a fixed-size big-endian header and a tag directory.", font=SECTION, fill=INK)
    draw.text((64, 1350), "This sample has one tag entry, so the layout stays fully visible in one dump.", font=BODY, fill=INK)

    logo_text = resize_logo(LOGO_TEXT_PATH, 2.0)
    image.paste(logo_text, (64, 1494), logo_text)
    draw.text((862, 1506), "docs/iccDEV/specifications / inspired by corkami TIFF_BE poster structure", font=BODY, fill=INK)

    image.save(OUTPUT_PATH)


if __name__ == "__main__":
    render()
