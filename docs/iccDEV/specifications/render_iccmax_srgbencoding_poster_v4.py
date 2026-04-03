#!/usr/bin/env python3
"""Render a corkami GIF-style ICC specimen poster."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[3]
PROFILE_PATH = ROOT / "test-profiles" / "sRgbEncoding.icc"
LOGO_TOP_PATH = ROOT / "docs" / "iccDEV" / "ICC_logo_top.gif"
LOGO_TEXT_PATH = ROOT / "docs" / "iccDEV" / "ICC_logo_text.gif"
OUTPUT_PATH = ROOT / "docs" / "iccDEV" / "specifications" / "png" / "iccmax-srgbencoding-annotated-dump-v4.png"

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
    54,
)
SECTION = load_font(
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ],
    54,
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


def draw_colored_title(draw: ImageDraw.ImageDraw, x: int, y: int, words: list[tuple[str, str]]) -> None:
    cursor = x
    for text, color in words:
        draw.text((cursor, y), text, font=TITLE, fill=color)
        cursor += text_size(draw, text, TITLE)[0] + 18


def resize_logo(path: Path, scale: float) -> Image.Image:
    image = Image.open(path).convert("RGBA")
    return image.resize((int(image.width * scale), int(image.height * scale)), Image.Resampling.LANCZOS)


def color_for_index(index: int) -> str:
    if index in range(0, 4):
        return ORANGE
    if index in range(8, 12):
        return PURPLE
    if index in range(12, 16):
        return RED
    if index in range(16, 20):
        return GREEN
    if index in range(24, 28):
        return BLUE
    if index in range(36, 40):
        return RED
    if index in range(128, 132):
        return GREEN
    if index in range(132, 136):
        return PURPLE
    if index in range(136, 144):
        return RED
    if index in range(144, 148):
        return GOLD
    if index in range(152, 156):
        return TEAL
    return GRAY


def draw_hex_dump(draw: ImageDraw.ImageDraw, data: bytes, left: int, top: int) -> dict[int, tuple[int, int]]:
    positions: dict[int, tuple[int, int]] = {}
    cell = 74
    row_h = 56
    for col in range(16):
        draw.text((left + 96 + col * cell, top), f"{col:X}", font=MONO_SMALL, fill=INK)
    for row in range(10):
        y = top + 50 + row * row_h
        draw.text((left, y), f"{row:02X}:", font=MONO_SMALL, fill=INK)
        for col in range(16):
            idx = row * 16 + col
            x = left + 96 + col * cell
            positions[idx] = (x + 18, y + 18)
            draw.text((x, y), f"{data[idx]:02X}", font=MONO, fill=color_for_index(idx))
    return positions


def draw_section(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], title: str, rows: list[tuple[str, str, str]]) -> None:
    draw.line((box[0], box[1], box[2], box[1]), fill=LINE, width=3)
    draw.text((box[0] + 20, box[1] + 18), title, font=SECTION, fill=INK)
    field_x = box[0] + 390
    value_x = box[0] + 720
    draw.text((field_x, box[1] + 10), "FIELDS", font=LABEL, fill=INK)
    draw.text((value_x, box[1] + 10), "VALUES", font=LABEL, fill=INK)
    y = box[1] + 92
    for label, value, color in rows:
        draw.text((field_x, y), label, font=LABEL, fill=color)
        draw.text((value_x, y), value, font=BODY, fill=color)
        y += 38
    draw.line((box[0], box[3], box[2], box[3]), fill=LINE, width=3)


def draw_connector(draw: ImageDraw.ImageDraw, start: tuple[int, int], mid_x: int, end: tuple[int, int]) -> None:
    draw.line([start, (mid_x, start[1]), end], fill=LINE, width=4)


def render() -> None:
    data = PROFILE_PATH.read_bytes()
    if len(data) != 160:
        raise SystemExit("Unexpected specimen size")
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    image = Image.new("RGB", (WIDTH, HEIGHT), PAPER)
    draw = ImageDraw.Draw(image)

    draw_colored_title(
        draw,
        34,
        14,
        [
            ("I", ORANGE),
            ("NTERNATIONAL", INK),
            ("C", ORANGE),
            ("OLOR", INK),
            ("P", ORANGE),
            ("ROFILE", INK),
        ],
    )
    draw.text((1710, 112), "iccMAX sample", font=TITLE_SMALL, fill=ORANGE)

    specimen = resize_logo(LOGO_TOP_PATH, 3.2)
    specimen_x = 294
    specimen_y = 258
    draw.rectangle((specimen_x - 18, specimen_y - 18, specimen_x + specimen.width + 18, specimen_y + specimen.height + 18), fill="white", outline=INK, width=8)
    image.paste(specimen, (specimen_x, specimen_y), specimen)

    positions = draw_hex_dump(draw, data, 48, 512)

    draw_connector(draw, (specimen_x + specimen.width + 18, specimen_y + specimen.height // 2), 760, (980, 286))
    draw_connector(draw, (1160, 568), 1180, (1240, 286))
    draw_connector(draw, (1160, 850), 1180, (1240, 618))
    draw_connector(draw, (1160, 1030), 1180, (1240, 960))
    draw_connector(draw, (1160, 1168), 1180, (1240, 1230))

    draw_section(
        draw,
        (1240, 236, 2190, 560),
        "HEADER",
        [
            ("size", "160 bytes", ORANGE),
            ("version", "5.0.0", PURPLE),
            ("class", "cenc", RED),
            ("color space", "RGB", GREEN),
            ("magic", "acsp", RED),
        ],
    )
    draw_section(
        draw,
        (1240, 588, 2190, 910),
        "TAG TABLE",
        [
            ("tag count", "1", GREEN),
            ("signature", "rfnm", PURPLE),
            ("offset", "0x90", RED),
            ("size", "0x0D", RED),
        ],
    )
    draw_section(
        draw,
        (1240, 938, 2190, 1188),
        "PAYLOAD",
        [
            ("type", "utf8", GOLD),
            ("text", "sRGB", TEAL),
            ("padding", "00 00 00 00", GRAY),
        ],
    )
    draw_section(
        draw,
        (1240, 1216, 2190, 1464),
        "PARSER NOTES",
        [
            ("bounds", "offset + size <= file", ORANGE),
            ("layout", "table ends before data", BLUE),
            ("context", "ICC.2 cenc rules apply", GREEN),
        ],
    )

    draw.text((44, 1290), "ICC fixed header -> tag table -> typed payload", font=TITLE_SMALL, fill=INK)
    note = (
        "The header is always 128 bytes. The tag table follows immediately. "
        "This specimen declares one reference-name tag, carried as a utf8 payload."
    )
    y = 1390
    for line in wrap_text(draw, note, BODY, 1320):
        draw.text((48, y), line, font=BODY, fill=INK)
        y += 36

    logo_text = resize_logo(LOGO_TEXT_PATH, 2.0)
    image.paste(logo_text, (86, 1502), logo_text)
    draw.text((850, 1510), "docs/iccDEV/specifications / inspired by corkami GIF poster structure", font=BODY, fill=INK)

    image.save(OUTPUT_PATH)


if __name__ == "__main__":
    render()
