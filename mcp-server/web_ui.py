#!/usr/bin/env python3
"""
ICC Profile MCP Server - Web UI Backend

Thin REST API wrapping the MCP tool surface exposed by the server.
Uses Starlette + uvicorn (already installed as MCP SDK dependencies).

Usage:
    cd mcp-server && source .venv/bin/activate
    python web_ui.py                          # http://0.0.0.0:8000
    python web_ui.py --port 9000              # custom port
    python web_ui.py --host 127.0.0.1         # localhost only

Copyright (c) 2026 David H Hoyt LLC
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

# ---------------------------------------------------------------------------
# Import the MCP tool functions (same module the MCP server uses)
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))
from icc_profile_mcp import (  # noqa: E402
    ANALYZER_BIN,
    ANALYZER_V2_BIN,
    DEFAULT_ANALYSIS_ENGINE,
    DEFAULT_STRUCTURAL_ENGINE,
    TO_XML_SAFE_BIN,
    TO_XML_UNSAFE_BIN,
    _BATCH_TOOL_ALIASES,
    _get_analyzer,
    _map_flags,
    _require_binary,
    _resolve_profile,
    _run,
    _sanitize_output,
    _VALID_BUILD_TYPES,
    _VALID_CMAKE_OPTIONS,
    _VALID_COMPILERS,
    _VALID_DIAG_MODES,
    _VALID_GENERATORS,
    _VALID_SANITIZERS,
    _VALID_VCPKG_SOURCES,
    analyze_security,
    analyze_security_json,
    analyze_pawg_report,
    analyze_security_report,
    batch_test_profiles,
    build_tools,
    check_dependencies,
    cmake_build,
    cmake_configure,
    cmake_option_matrix,
    compare_profiles,
    coverage_report,
    create_all_profiles,
    find_build_artifacts,
    full_analysis,
    health_check,
    inspect_profile,
    list_test_profiles,
    profile_to_xml,
    register_allowed_base,
    run_iccdev_tests,
    scan_logs,
    upload_and_analyze,
    validate_roundtrip,
    validate_xml,
    windows_build,
    query_attack_surface,
    coverage_gaps,
    dump_all,
    diagnostic_load,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_INDEX_HTML = _HERE / "index.html"
_REPORT_HTML = _HERE / "report.html"
_CYTOSCAPE_JS = _HERE / "cytoscape.min.js"
_FAVICON_ICO = _HERE / "favicon.ico"
_HTML_CACHE: dict[str, str] = {}
MAX_PATH_LEN = 512
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB cap on file downloads
MAX_REPORT_BYTES = 64 * 1024  # keep the corkami-style page readable
# Allow only safe profile-path characters (alphanumeric, dash, underscore, dot, slash, tilde)
# Include backslash for Windows path compatibility
_SAFE_PATH_RE = re.compile(r"^[a-zA-Z0-9._/\\~ :+-]+$")
# Filename sanitization for Content-Disposition: keep only safe chars
_SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9._-]")

# Allowed directory names for list_test_profiles
_ALLOWED_DIRS = frozenset({"test-profiles", "extended-test-profiles"})

# Allowed directories for XML file listing
_ALLOWED_XML_DIRS = frozenset({
    "test-profiles", "extended-test-profiles",
    "fuzz/xml/icc", "fuzz/xml/icc/minimized",
})

_DOC_SOURCE_PATHS = (
    "docs/icc-format/ICC-Binary-Format-Reference.md",
    "docs/iccDEV/specifications/README.md",
    "docs/iccDEV/specifications/ICC.1-2022-05.pdf",
    "docs/iccDEV/specifications/ICC.2-2023.pdf",
)

_HEADER_FIELD_SPECS = (
    ("Profile size", 0, 4, "ICC.1-2022-05 Sec.7.2.2", "u32"),
    ("CMM type", 4, 4, "ICC.1-2022-05 Sec.7.2.3", "fourcc"),
    ("Version", 8, 4, "ICC.1-2022-05 Sec.7.2.4", "version"),
    ("Device class", 12, 4, "ICC.1-2022-05 Sec.7.2.5", "class"),
    ("Color space", 16, 4, "ICC.1-2022-05 Sec.7.2.6", "fourcc"),
    ("PCS", 20, 4, "ICC.1-2022-05 Sec.7.2.7", "fourcc"),
    ("Date/time", 24, 12, "ICC.1-2022-05 Sec.7.2.8", "datetime"),
    ("Magic", 36, 4, "ICC.1-2022-05 Sec.7.2.9", "magic"),
    ("Platform", 40, 4, "ICC.1-2022-05 Sec.7.2.10", "fourcc"),
    ("Profile flags", 44, 4, "ICC.1-2022-05 Sec.7.2.11", "flags"),
    ("Manufacturer", 48, 4, "ICC.1-2022-05 Sec.7.2.12", "fourcc"),
    ("Model", 52, 4, "ICC.1-2022-05 Sec.7.2.13", "fourcc"),
    ("Device attributes", 56, 8, "ICC.1-2022-05 Sec.7.2.14", "u64"),
    ("Rendering intent", 64, 4, "ICC.1-2022-05 Sec.7.2.15", "intent"),
    ("PCS illuminant", 68, 12, "ICC.1-2022-05 Sec.7.2.16", "xyz"),
    ("Creator", 80, 4, "ICC.1-2022-05 Sec.7.2.17", "fourcc"),
    ("Profile ID", 84, 16, "ICC.1-2022-05 Sec.7.2.18", "profile_id"),
    ("Reserved", 100, 28, "ICC.1-2022-05 Sec.7.2.19", "reserved"),
)

_PROFILE_CLASS_NAMES = {
    "scnr": "Input",
    "mntr": "Display",
    "prtr": "Output",
    "link": "DeviceLink",
    "spac": "ColorSpace",
    "abst": "Abstract",
    "nmcl": "NamedColor",
    "cenc": "ColorEncoding",
    "mid ": "MaterialID",
    "mvis": "MultiVisualization",
}

_RENDERING_INTENT_NAMES = {
    0: "Perceptual",
    1: "Relative Colorimetric",
    2: "Saturation",
    3: "Absolute Colorimetric",
}

_TAG_SIGNATURE_NAMES = {
    "A2B0": "AToB0Tag",
    "A2B1": "AToB1Tag",
    "A2B2": "AToB2Tag",
    "A2B3": "AToB3Tag",
    "B2A0": "BToA0Tag",
    "B2A1": "BToA1Tag",
    "B2A2": "BToA2Tag",
    "B2A3": "BToA3Tag",
    "bTRC": "blueTRCTag",
    "bXYZ": "blueMatrixColumnTag",
    "bkpt": "mediaBlackPointTag",
    "c2sp": "customToStandardPccTag",
    "chad": "chromaticAdaptationTag",
    "clro": "colorantOrderTag",
    "clrt": "colorantTableTag",
    "cprt": "copyrightTag",
    "desc": "profileDescriptionTag",
    "dmdd": "deviceModelDescTag",
    "dmnd": "deviceMfgDescTag",
    "gBD0": "gamutBoundaryDescription0Tag",
    "gBD1": "gamutBoundaryDescription1Tag",
    "gbd0": "gamutBoundaryDescription0Tag",
    "gbd1": "gamutBoundaryDescription1Tag",
    "gTRC": "greenTRCTag",
    "gXYZ": "greenMatrixColumnTag",
    "lumi": "luminanceTag",
    "meas": "measurementTag",
    "meta": "metadataTag",
    "ncl2": "namedColor2Tag",
    "rTRC": "redTRCTag",
    "rig0": "perceptualRenderingIntentGamutTag",
    "rig2": "saturationRenderingIntentGamutTag",
    "rXYZ": "redMatrixColumnTag",
    "s2cp": "standardToCustomPccTag",
    "svcn": "spectralViewingConditionsTag",
    "targ": "charTargetTag",
    "tech": "technologyTag",
    "vued": "viewingCondDescTag",
    "view": "viewingConditionsTag",
    "wtpt": "mediaWhitePointTag",
}

_TAG_TYPE_NAMES = {
    "XYZ ": "XYZArrayType",
    "chad": "chromaticAdaptationType",
    "curv": "curveType",
    "desc": "textDescriptionType",
    "gbd ": "gamutBoundaryDescType",
    "mAB ": "lutAToBType",
    "mBA ": "lutBToAType",
    "mft1": "lut8Type",
    "mft2": "lut16Type",
    "mluc": "multiLocalizedUnicodeType",
    "mpet": "multiProcessElementType",
    "ncl2": "namedColor2Type",
    "para": "parametricCurveType",
    "sf32": "s15Fixed16ArrayType",
    "sig ": "signatureType",
    "svcn": "spectralViewingConditionsType",
    "text": "textType",
    "view": "viewingConditionsType",
}

_PAWG_ITEM_RE = re.compile(r"^\[(OK|WARN|FAIL|N/A|GAP| -- )\]\s+([SCQ]\d+)\s+(.*)$")

# Limit concurrent subprocess executions
_MAX_CONCURRENT = 4
_semaphore: asyncio.Semaphore | None = None
_semaphore_lock = asyncio.Lock()

# Upload constraints
MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB max upload
_UPLOAD_DIR: Path | None = None  # lazily created temp dir for uploads

# Dynamic heuristic count from --registry (lazy, cached)
_HEURISTIC_COUNT: int | None = None


def _get_heuristic_count() -> int:
    """Query the analyzer binary for the total heuristic count."""
    global _HEURISTIC_COUNT
    if _HEURISTIC_COUNT is not None:
        return _HEURISTIC_COUNT
    try:
        import json as _json
        import subprocess
        analyzer = _get_analyzer(DEFAULT_ANALYSIS_ENGINE)
        r = subprocess.run(
            [str(analyzer), "--registry"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0 and r.stdout.strip():
            data = _json.loads(r.stdout)
            _HEURISTIC_COUNT = (
                data.get("totalHeuristics") or
                data.get("heuristics") or
                180
            )
            return _HEURISTIC_COUNT
    except Exception:  # noqa: E722 - intentional broad catch for graceful fallback
        _HEURISTIC_COUNT = 180  # registry count fallback
    return _HEURISTIC_COUNT


async def _get_semaphore() -> asyncio.Semaphore:
    """Lazy-init semaphore (must be created inside an event loop). Thread-safe."""
    global _semaphore
    if _semaphore is None:
        async with _semaphore_lock:
            if _semaphore is None:
                _semaphore = asyncio.Semaphore(_MAX_CONCURRENT)
    return _semaphore

# Security headers applied to every response
_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-DNS-Prefetch-Control": "off",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self'; "
        "script-src 'self'"
    ),
}

# CSP template with nonce placeholder for the index page
_CSP_NONCE_TEMPLATE = (
    "default-src 'self' blob:; "
    "style-src 'self' 'nonce-{nonce}' 'unsafe-inline'; "
    "script-src 'self' 'nonce-{nonce}'"
)

# Pre-encode for ASGI middleware (avoids re-encoding per request)
_SECURITY_HEADERS_ENCODED = [
    (k.lower().encode(), v.encode()) for k, v in _SECURITY_HEADERS.items()
]


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------
def _safe_error(exc: Exception) -> str:
    """Sanitize an exception message for safe JSON output.

    Mirrors sanitize-sed.sh sanitize_line: strip control chars, truncate.
    """
    msg = _sanitize_output(str(exc)).replace("\n", " ").strip()
    if len(msg) > 500:
        msg = msg[:497] + "..."
    return msg


def _safe_filename(stem: str, ext: str = ".xml") -> str:
    """Sanitize a filename for Content-Disposition header.

    Strips all characters except alphanumeric, dot, dash, underscore.
    Prevents header injection via quotes, newlines, or special chars.
    """
    clean = _SAFE_FILENAME_RE.sub("_", stem)[:200]
    if not clean:
        clean = "profile"
    return clean + ext


def _validate_path(value: str, param_name: str = "path") -> str:
    """Validate a user-supplied profile path. Raises ValueError on bad input."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{param_name} is required")
    value = value.strip()
    if len(value) > MAX_PATH_LEN:
        raise ValueError(f"{param_name} exceeds {MAX_PATH_LEN} characters")
    if "\x00" in value:
        raise ValueError(f"{param_name} contains null bytes")
    if ".." in value:
        raise ValueError(f"{param_name} contains path traversal sequence")
    # Allow absolute paths only if they resolve into the upload directory
    _is_absolute = value.startswith("/") or (len(value) >= 3 and value[1] == ":" and value[2] in "/\\")
    if _is_absolute:
        if _UPLOAD_DIR and Path(value).resolve().is_relative_to(_UPLOAD_DIR.resolve()):
            return value
        raise ValueError(f"{param_name} must be a relative path")
    if not _SAFE_PATH_RE.match(value):
        raise ValueError(f"{param_name} contains disallowed characters")
    return value


def _validate_directory(value: str) -> str:
    """Validate directory name for list_test_profiles."""
    value = value.strip()
    if value not in _ALLOWED_DIRS:
        raise ValueError(
            f"directory must be one of: {', '.join(sorted(_ALLOWED_DIRS))}"
        )
    return value


def _validate_xml_directory(value: str) -> str:
    """Validate directory name for XML file listing (allowlist only)."""
    value = value.strip()
    if value not in _ALLOWED_XML_DIRS:
        raise ValueError(
            f"directory must be one of: {', '.join(sorted(_ALLOWED_XML_DIRS))}"
        )
    return value

_KNOWN_PROFILE_CLASSES = {
    "scnr": "Input device profile",
    "mntr": "Display device profile",
    "prtr": "Output device profile",
    "link": "DeviceLink profile",
    "abst": "Abstract profile",
    "spac": "ColorSpace profile",
    "nmcl": "Named color profile",
}

_KNOWN_COLOR_SPACES = {
    "XYZ ": "nCIEXYZ",
    "Lab ": "CIELAB",
    "Luv ": "CIELUV",
    "YCbr": "YCbCr",
    "Yxy ": "CIEYxy",
    "RGB ": "RGB",
    "GRAY": "Gray",
    "HSV ": "HSV",
    "HLS ": "HLS",
    "CMYK": "CMYK",
    "CMY ": "CMY",
    "2CLR": "2-color",
    "3CLR": "3-color",
    "4CLR": "4-color",
    "5CLR": "5-color",
    "6CLR": "6-color",
    "7CLR": "7-color",
    "8CLR": "8-color",
    "9CLR": "9-color",
    "ACLR": "10-color",
    "BCLR": "11-color",
    "CCLR": "12-color",
    "DCLR": "13-color",
    "ECLR": "14-color",
    "FCLR": "15-color",
}

_KNOWN_PCS = {
    "XYZ ": "PCSXYZ",
    "Lab ": "PCSLAB",
}

_KNOWN_PLATFORMS = {
    "\x00\x00\x00\x00": "Unspecified",
    "APPL": "Apple Computer, Inc.",
    "MSFT": "Microsoft Corporation",
    "SGI ": "Silicon Graphics",
    "SUNW": "Sun Microsystems",
    "TGNT": "Taligent",
}

_RENDERING_INTENTS = {
    0: "Perceptual",
    1: "Media-relative colorimetric",
    2: "Saturation",
    3: "ICC-absolute colorimetric",
}

_OVERLAY_SECURITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def _hex_bytes(data: bytes) -> str:
    return data.hex().upper()


def _signature_text(data: bytes) -> str:
    if len(data) != 4:
        return _hex_bytes(data)
    chars = []
    for byte in data:
        if 32 <= byte <= 126:
            chars.append(chr(byte))
        else:
            chars.append(".")
    return "".join(chars)


def _is_printable_signature(data: bytes) -> bool:
    return len(data) == 4 and all(byte == 0 or 32 <= byte <= 126 for byte in data)


def _u16(data: bytes) -> int:
    return int.from_bytes(data, "big", signed=False)


def _u32(data: bytes) -> int:
    return int.from_bytes(data, "big", signed=False)


def _s15fixed16(data: bytes) -> float:
    return int.from_bytes(data, "big", signed=True) / 65536.0


def _carrier_from_bytes(data: bytes) -> str:
    if len(data) >= 40 and data[36:40] == b"acsp":
        return "ICC"
    if len(data) >= 4 and (data[:4] == b"II*\x00" or data[:4] == b"MM\x00*"):
        return "TIFF"
    if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if len(data) >= 2 and data[:2] == b"\xff\xd8":
        return "JPEG"
    if len(data) >= 4 and data[:4] == b"%PDF":
        return "PDF"
    return "Unknown"


def _date_tuple_ok(values: tuple[int, int, int, int, int, int]) -> bool:
    year, month, day, hour, minute, second = values
    return (
        1900 <= year <= 2100
        and 1 <= month <= 12
        and 1 <= day <= 31
        and 0 <= hour <= 23
        and 0 <= minute <= 59
        and 0 <= second <= 59
    )


def _build_header_cards(data: bytes, file_size: int) -> tuple[list[dict], dict]:
    if len(data) < 128:
        return [], {
            "ok": False,
            "reason": "File is smaller than the fixed 128-byte ICC header",
        }

    version_bytes = data[8:12]
    version_major = version_bytes[0]
    version_minor = version_bytes[1] >> 4
    version_bugfix = version_bytes[1] & 0x0F
    class_sig = data[12:16]
    class_text = _signature_text(class_sig)
    color_sig = data[16:20]
    color_text = _signature_text(color_sig)
    pcs_sig = data[20:24]
    pcs_text = _signature_text(pcs_sig)
    date_values = tuple(_u16(data[i:i + 2]) for i in range(24, 36, 2))
    date_ok = _date_tuple_ok(date_values)
    magic_ok = data[36:40] == b"acsp"
    platform_sig = data[40:44]
    platform_text = _signature_text(platform_sig)
    flags_value = _u32(data[44:48])
    intent_value = _u32(data[64:68])
    illuminant = (
        _s15fixed16(data[68:72]),
        _s15fixed16(data[72:76]),
        _s15fixed16(data[76:80]),
    )
    illuminant_ok = data[68:80] == bytes.fromhex("0000F6D6000100000000D32D")
    reserved_ok = data[100:128] == (b"\x00" * 28)

    fields = [
        {
            "offset": [0, 3],
            "name": "Profile size",
            "raw": _hex_bytes(data[0:4]),
            "decoded": _u32(data[0:4]),
            "ok": _u32(data[0:4]) == file_size and _u32(data[0:4]) >= 128,
            "specRef": "ICC.1-2022-05 Sec.7.2.2",
            "riskNotes": "Reject size mismatches before offset plus length arithmetic.",
        },
        {
            "offset": [4, 7],
            "name": "Preferred CMM type",
            "raw": _hex_bytes(data[4:8]),
            "decoded": _signature_text(data[4:8]),
            "ok": _is_printable_signature(data[4:8]),
            "specRef": "ICC.1-2022-05 Sec.7.2.3",
            "riskNotes": "Treat unknown signatures as data, not as trusted dispatch keys.",
        },
        {
            "offset": [8, 11],
            "name": "Profile version",
            "raw": _hex_bytes(version_bytes),
            "decoded": f"{version_major}.{version_minor}.{version_bugfix}",
            "ok": version_major in {2, 4, 5},
            "specRef": "ICC.1-2022-05 Sec.7.2.4",
            "riskNotes": "Stop before tag expectations branch on impossible version values.",
        },
        {
            "offset": [12, 15],
            "name": "Profile or device class",
            "raw": _hex_bytes(class_sig),
            "decoded": _KNOWN_PROFILE_CLASSES.get(class_text, f"Unknown ({class_text})"),
            "ok": class_text in _KNOWN_PROFILE_CLASSES,
            "specRef": "ICC.1-2022-05 Sec.7.2.5",
            "riskNotes": "Class drives required tags and transform semantics, so invalid values must fail closed.",
        },
        {
            "offset": [16, 19],
            "name": "Data color space",
            "raw": _hex_bytes(color_sig),
            "decoded": _KNOWN_COLOR_SPACES.get(color_text, f"Unknown ({color_text})"),
            "ok": color_text in _KNOWN_COLOR_SPACES,
            "specRef": "ICC.1-2022-05 Sec.7.2.6",
            "riskNotes": "Do not infer channel counts from unknown signatures.",
        },
        {
            "offset": [20, 23],
            "name": "PCS",
            "raw": _hex_bytes(pcs_sig),
            "decoded": _KNOWN_PCS.get(pcs_text, f"Unknown ({pcs_text})"),
            "ok": pcs_text in _KNOWN_PCS,
            "specRef": "ICC.1-2022-05 Sec.7.2.7",
            "riskNotes": "PCS must be validated before colorimetric math or tag traversal.",
        },
        {
            "offset": [24, 35],
            "name": "Creation date and time",
            "raw": _hex_bytes(data[24:36]),
            "decoded": (
                f"{date_values[0]:04d}-{date_values[1]:02d}-{date_values[2]:02d} "
                f"{date_values[3]:02d}:{date_values[4]:02d}:{date_values[5]:02d}"
            ),
            "ok": date_ok,
            "specRef": "ICC.1-2022-05 Sec.7.2.8",
            "riskNotes": "Malformed dates are a cheap corruption signal and should be surfaced early.",
        },
        {
            "offset": [36, 39],
            "name": "File signature",
            "raw": _hex_bytes(data[36:40]),
            "decoded": _signature_text(data[36:40]),
            "ok": magic_ok,
            "specRef": "ICC.1-2022-05 Sec.7.2.9",
            "riskNotes": "Fail fast on missing acsp magic and do not continue into tag loading.",
        },
        {
            "offset": [40, 43],
            "name": "Primary platform",
            "raw": _hex_bytes(platform_sig),
            "decoded": _KNOWN_PLATFORMS.get(platform_text, platform_text),
            "ok": platform_sig == b"\x00\x00\x00\x00" or _is_printable_signature(platform_sig),
            "specRef": "ICC.1-2022-05 Sec.7.2.10",
            "riskNotes": "Unknown platform codes are metadata, not permission to choose alternate parser paths.",
        },
        {
            "offset": [44, 47],
            "name": "Profile flags",
            "raw": _hex_bytes(data[44:48]),
            "decoded": (
                f"embedded={'yes' if flags_value & 0x1 else 'no'}, "
                f"independent={'no' if flags_value & 0x2 else 'yes'}"
            ),
            "ok": (flags_value & ~0x3) == 0,
            "specRef": "ICC.1-2022-05 Sec.7.2.11",
            "riskNotes": "Validate reserved flag bits before the object is treated as embedded or stand-alone.",
        },
        {
            "offset": [48, 51],
            "name": "Device manufacturer",
            "raw": _hex_bytes(data[48:52]),
            "decoded": _signature_text(data[48:52]),
            "ok": _is_printable_signature(data[48:52]),
            "specRef": "ICC.1-2022-05 Sec.7.2.12",
            "riskNotes": "Treat this as descriptive metadata only.",
        },
        {
            "offset": [52, 55],
            "name": "Device model",
            "raw": _hex_bytes(data[52:56]),
            "decoded": _signature_text(data[52:56]),
            "ok": _is_printable_signature(data[52:56]),
            "specRef": "ICC.1-2022-05 Sec.7.2.13",
            "riskNotes": "Do not build model-specific behavior on untrusted model bytes.",
        },
        {
            "offset": [56, 63],
            "name": "Device attributes",
            "raw": _hex_bytes(data[56:64]),
            "decoded": f"0x{_hex_bytes(data[56:64])}",
            "ok": True,
            "specRef": "ICC.1-2022-05 Sec.7.2.14",
            "riskNotes": "Decode attribute flags defensively and ignore unknown bits.",
        },
        {
            "offset": [64, 67],
            "name": "Rendering intent",
            "raw": _hex_bytes(data[64:68]),
            "decoded": _RENDERING_INTENTS.get(intent_value, f"Unknown ({intent_value})"),
            "ok": intent_value in _RENDERING_INTENTS,
            "specRef": "ICC.1-2022-05 Sec.7.2.15",
            "riskNotes": "Reject impossible enum values before transform selection.",
        },
        {
            "offset": [68, 79],
            "name": "PCS illuminant",
            "raw": _hex_bytes(data[68:80]),
            "decoded": f"X={illuminant[0]:.4f} Y={illuminant[1]:.4f} Z={illuminant[2]:.4f}",
            "ok": illuminant_ok,
            "specRef": "ICC.1-2022-05 Sec.7.2.16",
            "riskNotes": "Use fixed-value header checks as early reject points.",
        },
        {
            "offset": [80, 83],
            "name": "Profile creator",
            "raw": _hex_bytes(data[80:84]),
            "decoded": _signature_text(data[80:84]),
            "ok": _is_printable_signature(data[80:84]),
            "specRef": "ICC.1-2022-05 Sec.7.2.17",
            "riskNotes": "Creator bytes are provenance only and should never affect trust.",
        },
        {
            "offset": [84, 99],
            "name": "Profile ID",
            "raw": _hex_bytes(data[84:100]),
            "decoded": _hex_bytes(data[84:100]).lower(),
            "ok": True,
            "specRef": "ICC.1-2022-05 Sec.7.2.18",
            "riskNotes": "Treat the profile ID as descriptive unless independently recomputed.",
        },
        {
            "offset": [100, 127],
            "name": "Reserved",
            "raw": _hex_bytes(data[100:128]),
            "decoded": "all zeros" if reserved_ok else "non-zero reserved bytes",
            "ok": reserved_ok,
            "specRef": "ICC.1-2022-05 Sec.7.2.19",
            "riskNotes": "Reserved bytes should be zero before any deeper parsing continues.",
        },
    ]

    gate_ok = all(field["ok"] for field in fields)
    return fields, {
        "ok": gate_ok,
        "magicOk": magic_ok,
        "classSignature": class_text,
        "colorSpace": color_text,
        "pcs": pcs_text,
        "reason": "" if gate_ok else "One or more fixed-header invariants failed",
    }


def _parse_tag_table(data: bytes, *, display_limit: int = 32) -> tuple[list[dict], dict, set[str]]:
    if len(data) < 132:
        return [], {
            "ok": False,
            "count": 0,
            "displayCount": 0,
            "reason": "File is too small to contain a tag table",
            "duplicates": [],
            "overlapPairs": 0,
            "outOfBounds": 0,
            "tableEnd": 0,
            "truncatedDisplay": False,
        }, set()

    count = _u32(data[128:132])
    table_end = 132 + (count * 12)
    entries: list[dict] = []
    signatures: dict[str, int] = {}
    ranges: list[tuple[int, int]] = []
    out_of_bounds = 0
    misaligned = 0
    bad_offsets = 0
    valid_region = table_end <= len(data)
    max_parseable = max(0, (len(data) - 132) // 12)
    entries_to_read = min(count, max_parseable)

    for idx in range(entries_to_read):
        base = 132 + (idx * 12)
        sig = _signature_text(data[base:base + 4])
        offset = _u32(data[base + 4:base + 8])
        size = _u32(data[base + 8:base + 12])
        end = offset + size
        signatures[sig] = signatures.get(sig, 0) + 1
        in_bounds = size > 0 and offset >= table_end and end <= len(data)
        aligned = (offset % 4) == 0
        if not in_bounds:
            out_of_bounds += 1
        if not aligned:
            misaligned += 1
        if offset < table_end:
            bad_offsets += 1
        type_sig = ""
        if in_bounds and end <= len(data) and size >= 4:
            type_sig = _signature_text(data[offset:offset + 4])
            ranges.append((offset, end))
        if idx < display_limit:
            entries.append({
                "index": idx,
                "sig": sig,
                "offset": offset,
                "size": size,
                "type": type_sig or "OOB",
                "ok": in_bounds and aligned,
                "specRef": "ICC.1-2022-05 Sec.7.3.1",
                "riskNotes": "Validate offset plus size with overflow-safe arithmetic before reading tag payload bytes.",
            })

    duplicates = sorted(sig for sig, seen in signatures.items() if seen > 1)
    ranges.sort()
    overlap_pairs = 0
    active_ends: list[int] = []
    for start, end in ranges:
        while active_ends and active_ends[0] <= start:
            import heapq
            heapq.heappop(active_ends)
        overlap_pairs += len(active_ends)
        if end > start:
            import heapq
            heapq.heappush(active_ends, end)

    ok = (
        count > 0
        and valid_region
        and out_of_bounds == 0
        and misaligned == 0
        and bad_offsets == 0
        and not duplicates
        and overlap_pairs == 0
    )
    reason_parts = []
    if count == 0:
        reason_parts.append("tag count is zero")
    if not valid_region:
        reason_parts.append("tag table extends beyond EOF")
    if out_of_bounds:
        reason_parts.append(f"{out_of_bounds} tag entries extend beyond EOF")
    if misaligned:
        reason_parts.append(f"{misaligned} tag entries are not 4-byte aligned")
    if bad_offsets:
        reason_parts.append(f"{bad_offsets} tag entries point into the tag table itself")
    if duplicates:
        reason_parts.append("duplicate tag signatures are present")
    if overlap_pairs:
        reason_parts.append(f"{overlap_pairs} overlapping tag-data pairs detected")

    return entries, {
        "ok": ok,
        "count": count,
        "displayCount": len(entries),
        "tableEnd": table_end,
        "duplicates": duplicates[:12],
        "overlapPairs": overlap_pairs,
        "outOfBounds": out_of_bounds,
        "misaligned": misaligned,
        "truncatedDisplay": count > display_limit,
        "reason": "; ".join(reason_parts) if reason_parts else "",
    }, set(signatures)


def _infer_required_tags(class_sig: str, color_sig: str, tag_sigs: set[str]) -> tuple[list[str], str]:
    if class_sig == "spac":
        return ["desc", "cprt", "wtpt", "A2B0", "B2A0"], "ColorSpace baseline"
    if class_sig in {"mntr", "scnr", "prtr"}:
        if color_sig == "GRAY":
            return ["desc", "cprt", "wtpt", "kTRC"], "Gray device profile"
        if color_sig == "RGB " and {"rXYZ", "gXYZ", "bXYZ", "rTRC", "gTRC", "bTRC"}.issubset(tag_sigs):
            required = ["desc", "cprt", "wtpt", "rXYZ", "gXYZ", "bXYZ", "rTRC", "gTRC", "bTRC"]
            if "chad" in tag_sigs:
                required.append("chad")
            return required, "RGB matrix or TRC device profile"
        required = ["desc", "cprt", "wtpt"]
        if "A2B0" in tag_sigs:
            required.append("A2B0")
        if "B2A0" in tag_sigs:
            required.append("B2A0")
        if "chad" in tag_sigs:
            required.append("chad")
        return required, "LUT-based device profile"
    if class_sig == "abst":
        return ["desc", "cprt", "A2B0"], "Abstract profile"
    if class_sig == "link":
        return ["desc", "cprt", "A2B0"], "DeviceLink profile"
    if class_sig == "nmcl":
        return ["desc", "cprt", "ncl2"], "Named color profile"
    return ["desc", "cprt"], "Generic baseline"


def _build_required_tags(
    header_summary: dict,
    tag_sigs: set[str],
) -> tuple[list[dict], dict]:
    if not header_summary.get("magicOk"):
        return [], {
            "ok": False,
            "reachable": False,
            "basis": "Not evaluated because the root object failed ICC header identity checks",
        }

    class_sig = header_summary.get("classSignature", "")
    color_sig = header_summary.get("colorSpace", "")
    required, basis = _infer_required_tags(class_sig, color_sig, tag_sigs)
    cards = []
    for sig in required:
        cards.append({
            "sig": sig,
            "present": sig in tag_sigs,
            "specRef": "ICC.1-2022-05 Annex G",
            "riskNotes": "Missing required tags should stop semantic interpretation before transforms execute.",
        })
    return cards, {
        "ok": all(card["present"] for card in cards),
        "reachable": True,
        "basis": basis,
    }


def _build_transform_path(tag_sigs: set[str]) -> dict:
    forward = [sig for sig in ("A2B0", "A2B1", "A2B2", "D2B0", "D2B1", "D2B2") if sig in tag_sigs]
    reverse = [sig for sig in ("B2A0", "B2A1", "B2A2", "B2D0", "B2D1", "B2D2") if sig in tag_sigs]
    matrix = [sig for sig in ("rXYZ", "gXYZ", "bXYZ", "rTRC", "gTRC", "bTRC", "kTRC") if sig in tag_sigs]
    return {
        "forward": forward,
        "reverse": reverse,
        "matrix": matrix,
        "embedded": "ICC5" in tag_sigs,
        "summary": (
            "Forward and reverse transform tags should be typed and bounds-checked before traversal."
        ),
    }


def _select_security_findings(result: dict) -> tuple[list[dict], dict]:
    if "findings" in result:
        findings = []
        for item in result.get("findings", []):
            severity = str(item.get("severity", "INFO")).upper()
            findings.append({
                "id": str(item.get("id", "?")),
                "name": item.get("message", "Unnamed finding"),
                "severity": severity.lower(),
                "ok": False,
                "status": "finding",
                "specRef": item.get("detail", ""),
                "detail": item.get("detail", "") or item.get("cwe", ""),
            })
        findings.sort(key=lambda item: (_OVERLAY_SECURITY_ORDER.get(item["severity"].upper(), 9), item["id"]))
        stats = result.get("stats", {})
        severity_counts = stats.get("severity", {})
        warning_count = sum(
            int(severity_counts.get(level, 0))
            for level in ("LOW", "MEDIUM", "HIGH")
        )
        return findings[:12], {
            "warnings": warning_count,
            "critical": int(severity_counts.get("CRITICAL", 0)),
            "heuristicsRun": int(stats.get("checksRun", 0)),
            "totalHeuristics": int(stats.get("checksRun", 0)),
        }

    findings = []
    for item in result.get("results", []):
        status = str(item.get("status", "")).lower()
        if status in {"ok", "skip"}:
            continue
        severity = str(item.get("severity", "INFO")).upper()
        findings.append({
            "id": f"H{item.get('id', '?')}",
            "name": item.get("name", "Unnamed finding"),
            "severity": severity.lower(),
            "ok": False,
            "status": status,
            "specRef": item.get("specRef", ""),
            "detail": item.get("detail", ""),
        })
    findings.sort(key=lambda item: (_OVERLAY_SECURITY_ORDER.get(item["severity"].upper(), 9), item["id"]))
    summary = result.get("summary", {})
    return findings[:12], {
        "warnings": int(summary.get("warnings", 0)),
        "critical": int(summary.get("critical", 0)),
        "heuristicsRun": int(summary.get("heuristicsRun", 0)),
        "totalHeuristics": int(summary.get("totalHeuristics", 0)),
    }


def _overlay_score(gates: dict[str, bool], security_summary: dict) -> int:
    score = 100
    score -= security_summary.get("warnings", 0) * 2
    score -= security_summary.get("critical", 0) * 15
    if not gates.get("header", False):
        score = min(score, 35)
    if not gates.get("tagTable", False):
        score = min(score, 45)
    if not gates.get("requiredTags", False):
        score = min(score, 60)
    return max(0, score)


async def _build_profile_overlay(path: str) -> dict:
    profile = _resolve_profile(path)
    data = profile.read_bytes()
    file_size = len(data)
    carrier = _carrier_from_bytes(data)
    header_cards, header_summary = _build_header_cards(data, file_size)
    tag_entries, tag_summary, tag_sigs = _parse_tag_table(data)
    required_tags, required_summary = _build_required_tags(header_summary, tag_sigs)
    transform_path = _build_transform_path(tag_sigs)

    security_payload = {"results": [], "summary": {}}
    try:
        security_payload = json.loads(await analyze_security_json(path, engine="v2"))
    except Exception:
        try:
            security_payload = json.loads(await analyze_security_json(path, engine="v1"))
        except Exception:
            security_payload = {"results": [], "summary": {}}
    security_findings, security_summary = _select_security_findings(security_payload)

    gates = {
        "header": bool(header_summary.get("ok")),
        "tagTable": bool(tag_summary.get("ok")),
        "requiredTags": bool(required_summary.get("ok")),
    }
    if not all(gates.values()):
        status = "non_conformant"
    elif security_findings:
        status = "warning"
    else:
        status = "conformant"

    status_label = {
        "conformant": "Conformant",
        "warning": "Conformant with warnings",
        "non_conformant": "Non-conformant",
    }[status]

    extension = profile.suffix.lower().lstrip(".") or "none"
    extension_match = (
        (carrier == "ICC" and extension in {"icc", "icm", "icc2", "iccp"})
        or (carrier == "TIFF" and extension in {"tif", "tiff"})
        or carrier in {"Unknown", "PNG", "JPEG", "PDF"}
    )

    return {
        "file": {
            "name": profile.name,
            "path": path,
            "size": file_size,
            "carrier": carrier,
            "extension": extension,
            "extensionMatchesCarrier": extension_match,
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "conformance": {
            "status": status,
            "label": status_label,
            "score": _overlay_score(gates, security_summary),
            "spec": "ICC.1:2022",
            "gates": gates,
            "reasons": {
                "header": header_summary.get("reason", ""),
                "tagTable": tag_summary.get("reason", ""),
                "requiredTags": required_summary.get("basis", ""),
            },
        },
        "header": header_cards,
        "tagTable": tag_entries,
        "tagTableSummary": tag_summary,
        "requiredTags": required_tags,
        "requiredTagsSummary": required_summary,
        "transformPath": transform_path,
        "metadata": {
            "profileClass": header_summary.get("classSignature", ""),
            "colorSpace": header_summary.get("colorSpace", ""),
            "pcs": header_summary.get("pcs", ""),
            "carrier": carrier,
            "extensionMismatch": not extension_match,
        },
        "security": security_findings,
        "securitySummary": security_summary,
    }


def _render_html_template(template_path: Path, missing_html: str) -> HTMLResponse:
    """Serve a cached HTML template with a fresh CSP nonce."""
    key = str(template_path)
    if key not in _HTML_CACHE:
        if not template_path.is_file():
            return HTMLResponse(missing_html, status_code=500)
        _HTML_CACHE[key] = template_path.read_text(encoding="utf-8")

    nonce = secrets.token_urlsafe(32)
    html = _HTML_CACHE[key].replace("<style>", f'<style nonce="{nonce}">', 1)
    html = html.replace("<script>", f'<script nonce="{nonce}">', 1)

    headers = dict(_SECURITY_HEADERS)
    headers["Content-Security-Policy"] = _CSP_NONCE_TEMPLATE.format(nonce=nonce)
    return HTMLResponse(html, headers=headers)


def _read_u16be(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        return 0
    return int.from_bytes(data[offset:offset + 2], "big", signed=False)


def _read_u32be(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        return 0
    return int.from_bytes(data[offset:offset + 4], "big", signed=False)


def _read_u64be(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        return 0
    return int.from_bytes(data[offset:offset + 8], "big", signed=False)


def _raw_hex(raw: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in raw)


def _fourcc(raw: bytes) -> str:
    chars: list[str] = []
    for byte in raw[:4]:
        if 32 <= byte <= 126:
            chars.append(chr(byte))
        else:
            chars.append(".")
    return "".join(chars)


def _format_fourcc(raw: bytes) -> str:
    value = _fourcc(raw)
    if value == "....":
        return value
    return f"{value!r}"


def _decode_version(value: int) -> str:
    major = (value >> 24) & 0xFF
    minor = (value >> 20) & 0x0F
    bugfix = (value >> 16) & 0x0F
    return f"{major}.{minor}.{bugfix}"


def _decode_datetime(data: bytes, offset: int) -> str:
    parts = [_read_u16be(data, offset + i * 2) for i in range(6)]
    return (
        f"{parts[0]:04d}-{parts[1]:02d}-{parts[2]:02d} "
        f"{parts[3]:02d}:{parts[4]:02d}:{parts[5]:02d}"
    )


def _decode_s15fixed16(raw: bytes) -> float:
    if len(raw) != 4:
        return 0.0
    return int.from_bytes(raw, "big", signed=True) / 65536.0


def _decode_xyz(data: bytes, offset: int) -> str:
    x = _decode_s15fixed16(data[offset:offset + 4])
    y = _decode_s15fixed16(data[offset + 4:offset + 8])
    z = _decode_s15fixed16(data[offset + 8:offset + 12])
    return f"X={x:.4f}, Y={y:.4f}, Z={z:.4f}"


def _decode_profile_flags(value: int) -> str:
    bits: list[str] = []
    if value & 0x00000001:
        bits.append("Embedded")
    if value & 0x00000002:
        bits.append("Dependent")
    if value & 0x00000008:
        bits.append("HDR-to-SDR")
    labels = ", ".join(bits) if bits else "none"
    return f"0x{value:08X} ({labels})"


def _decode_reserved(raw: bytes) -> str:
    return "all zero" if all(byte == 0 for byte in raw) else "non-zero bytes present"


def _format_header_value(name: str, decoder: str, raw: bytes, data: bytes, offset: int) -> str:
    if decoder == "u32":
        value = _read_u32be(data, offset)
        return f"{value} (0x{value:08X})"
    if decoder == "u64":
        value = _read_u64be(data, offset)
        return f"0x{value:016X}"
    if decoder == "fourcc":
        text = _fourcc(raw)
        if name == "Platform" and text == "....":
            return "unspecified"
        return text if text == "...." else f"{text!r}"
    if decoder == "version":
        return _decode_version(_read_u32be(data, offset))
    if decoder == "class":
        sig = _fourcc(raw)
        label = _PROFILE_CLASS_NAMES.get(sig, "Unknown")
        return f"{sig!r} ({label})"
    if decoder == "datetime":
        return _decode_datetime(data, offset)
    if decoder == "magic":
        sig = _fourcc(raw)
        return f"{sig!r} {'OK' if sig == 'acsp' else 'INVALID'}"
    if decoder == "flags":
        return _decode_profile_flags(_read_u32be(data, offset))
    if decoder == "intent":
        value = _read_u32be(data, offset)
        label = _RENDERING_INTENT_NAMES.get(value, "Unknown")
        return f"{label} (0x{value:08X})"
    if decoder == "xyz":
        return _decode_xyz(data, offset)
    if decoder == "profile_id":
        return raw.hex()
    if decoder == "reserved":
        return _decode_reserved(raw)
    return _raw_hex(raw)


def _build_header_fields(data: bytes) -> list[dict[str, object]]:
    fields: list[dict[str, object]] = []
    for idx, (name, start, size, spec_ref, decoder) in enumerate(_HEADER_FIELD_SPECS):
        raw = data[start:start + size]
        fields.append({
            "id": f"hdr-{idx}",
            "name": name,
            "start": start,
            "size": size,
            "specRef": spec_ref,
            "rawHex": _raw_hex(raw),
            "value": _format_header_value(name, decoder, raw, data, start),
            "group": "header",
            "detail": f"{name} ({size} bytes) - {spec_ref}",
        })
    return fields


def _build_tag_entries(data: bytes) -> tuple[dict[str, object], list[dict[str, object]]]:
    raw_tag_count = _read_u32be(data, 128) if len(data) >= 132 else 0
    available_entries = max((len(data) - 132) // 12, 0) if len(data) > 132 else 0
    parsed_count = min(raw_tag_count, available_entries)
    tag_count = {
        "id": "tag-count",
        "name": "Tag count",
        "start": 128,
        "size": 4,
        "specRef": "ICC.1-2022-05 Sec.7.3",
        "rawHex": _raw_hex(data[128:132]),
        "value": raw_tag_count,
        "parsedCount": parsed_count,
        "availableEntries": available_entries,
        "group": "table",
        "detail": "Tag table entry count",
    }

    tags: list[dict[str, object]] = []
    for idx in range(parsed_count):
        entry_start = 132 + idx * 12
        sig_raw = data[entry_start:entry_start + 4]
        signature = _fourcc(sig_raw)
        data_offset = _read_u32be(data, entry_start + 4)
        data_size = _read_u32be(data, entry_start + 8)
        body_end = min(data_offset + data_size, len(data))
        raw_type = data[data_offset:data_offset + 4] if data_offset + 4 <= len(data) else b""
        type_signature = _fourcc(raw_type) if raw_type else "...."
        padding = (-data_size) % 4
        tags.append({
            "id": f"tag-{idx}",
            "index": idx,
            "signature": signature,
            "tagName": _TAG_SIGNATURE_NAMES.get(signature, "Unknown tag"),
            "typeSignature": type_signature,
            "typeName": _TAG_TYPE_NAMES.get(type_signature, "Unknown type"),
            "tableOffset": entry_start,
            "dataOffset": data_offset,
            "dataSize": data_size,
            "padding": padding,
            "bodyEnd": body_end,
            "group": "tag",
            "detail": (
                f"{signature!r} at 0x{data_offset:04X}, "
                f"{data_size} bytes, type {type_signature!r}"
            ),
        })
    return tag_count, tags


def _status_counts(items: list[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        status = str(item.get("status", "unknown")).lower()
        counts[status] = counts.get(status, 0) + 1
    return counts


def _line_ascii(raw: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in raw)


def _build_hex_lines(data: bytes, region_ids: list[int], regions: list[dict[str, object]]) -> list[dict[str, object]]:
    display = data[:MAX_REPORT_BYTES]
    lines: list[dict[str, object]] = []
    for offset in range(0, len(display), 16):
        chunk = display[offset:offset + 16]
        chunk_regions = region_ids[offset:offset + len(chunk)]
        runs: list[dict[str, object]] = []
        if chunk:
            run_start = 0
            current = chunk_regions[0]
            for idx in range(1, len(chunk)):
                if chunk_regions[idx] != current:
                    runs.append({
                        "start": run_start,
                        "end": idx,
                        "regionId": regions[current]["id"] if current >= 0 else "",
                    })
                    run_start = idx
                    current = chunk_regions[idx]
            runs.append({
                "start": run_start,
                "end": len(chunk),
                "regionId": regions[current]["id"] if current >= 0 else "",
            })
        lines.append({
            "offset": offset,
            "cells": [f"{byte:02X}" for byte in chunk],
            "ascii": _line_ascii(chunk),
            "runs": runs,
        })
    return lines


def _parse_pawg_report(text: str) -> dict[str, object]:
    categories: list[dict[str, object]] = []
    meta: dict[str, str] = {}
    coverage: list[str] = []
    current: dict[str, object] | None = None
    for raw_line in _sanitize_output(text).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line in {"Security", "Conformance", "Quality"}:
            current = {"name": line, "items": []}
            categories.append(current)
            continue
        if current is not None:
            match = _PAWG_ITEM_RE.match(line)
            if match:
                current["items"].append({
                    "status": match.group(1).strip(),
                    "id": match.group(2),
                    "text": match.group(3),
                })
                continue
        if line.startswith(("Date:", "File:", "SHA-256:", "Size:", "View:")):
            key, _, value = line.partition(":")
            meta[key.lower()] = value.strip()
        elif line.startswith(("Checks evaluated:", "Checks mapped:", "Registry total:", "Spec coverage:")):
            coverage.append(line)
    for category in categories:
        items = category.get("items", [])
        category["summary"] = _status_counts(items if isinstance(items, list) else [])
    return {"meta": meta, "coverage": coverage, "categories": categories}


async def _load_security_json_payload(path: str, engine: str) -> dict[str, object]:
    result = await analyze_security_json(path, engine=engine)
    sep = "\n--- stderr ---\n"
    if sep in result:
        result = result[:result.index(sep)]
    if result.lstrip().startswith("--- stderr ---"):
        result = ""
    result = result.strip()
    if not result or not result.startswith("{"):
        heuristic_count = _get_heuristic_count()
        if engine == "v1":
            return {
                "engine": engine,
                "crashRecovery": True,
                "results": [],
                "summary": {
                    "totalHeuristics": heuristic_count,
                    "heuristicsRun": 0,
                    "ok": 0,
                    "warnings": 0,
                    "critical": 1,
                    "crashRecovery": True,
                    "note": (
                        "Profile triggered crash recovery (SIGSEGV or SIGABRT) - "
                        "no JSON output available. Use /api/security for text analysis."
                    ),
                },
            }
        return {
            "engine": engine,
            "crashRecovery": True,
            "results": [],
            "stats": {
                "checksRun": 0,
                "findings": 0,
                "crashRecovery": True,
                "note": (
                    "Profile triggered crash recovery (SIGSEGV or SIGABRT) - "
                    "no JSON output available. Use /api/security for text analysis."
                ),
            },
        }
    return json.loads(result)


async def _build_profile_report(path: str, engine: str) -> dict[str, object]:
    profile = _resolve_profile(path)
    data = profile.read_bytes()
    display_bytes = min(len(data), MAX_REPORT_BYTES)

    header_fields = _build_header_fields(data)
    tag_count, tag_entries = _build_tag_entries(data)

    regions: list[dict[str, object]] = []
    regions.extend(header_fields)
    regions.append(tag_count)
    for tag in tag_entries:
        entry_start = int(tag["tableOffset"])
        signature = str(tag["signature"])
        data_offset = int(tag["dataOffset"])
        data_size = int(tag["dataSize"])
        padding = int(tag["padding"])
        type_signature = str(tag["typeSignature"])

        regions.append({
            "id": f"{tag['id']}-sig",
            "name": f"{signature} signature",
            "start": entry_start,
            "size": 4,
            "specRef": "ICC.1-2022-05 Sec.7.3",
            "group": "table",
            "detail": f"Tag entry {tag['index']} signature",
        })
        regions.append({
            "id": f"{tag['id']}-offset",
            "name": f"{signature} offset",
            "start": entry_start + 4,
            "size": 4,
            "specRef": "ICC.1-2022-05 Sec.7.3",
            "group": "table",
            "detail": f"Tag entry {tag['index']} data offset",
        })
        regions.append({
            "id": f"{tag['id']}-size",
            "name": f"{signature} size",
            "start": entry_start + 8,
            "size": 4,
            "specRef": "ICC.1-2022-05 Sec.7.3",
            "group": "table",
            "detail": f"Tag entry {tag['index']} data size",
        })
        if data_offset < len(data) and data_size > 0:
            regions.append({
                "id": f"{tag['id']}-body",
                "name": f"{signature} body",
                "start": data_offset,
                "size": min(data_size, len(data) - data_offset),
                "specRef": "ICC.1-2022-05 Sec.7.3.1",
                "group": "tag",
                "detail": (
                    f"{tag['tagName']} / {type_signature!r} "
                    f"({data_size} bytes)"
                ),
            })
            pad_start = data_offset + data_size
            if padding and pad_start < len(data):
                regions.append({
                    "id": f"{tag['id']}-pad",
                    "name": f"{signature} padding",
                    "start": pad_start,
                    "size": min(padding, len(data) - pad_start),
                    "specRef": "ICC.1-2022-05 Sec.7.3",
                    "group": "pad",
                    "detail": f"4-byte alignment padding after {signature!r}",
                })

    region_ids = [-1] * display_bytes
    for region_index, region in enumerate(regions):
        start = int(region["start"])
        end = min(start + int(region["size"]), display_bytes)
        if end <= 0 or start >= display_bytes:
            continue
        for pos in range(max(start, 0), end):
            if region_ids[pos] == -1:
                region_ids[pos] = region_index

    security_payload = await _load_security_json_payload(path, engine)
    pawg_report = await analyze_security_report(path, engine=engine)
    pawg = _parse_pawg_report(pawg_report)

    all_results = security_payload.get("results", [])
    if not isinstance(all_results, list):
        all_results = []
    conformance_all = [
        item for item in all_results
        if str(item.get("name", "")).startswith("CF-")
    ]
    conformance_non_ok = [
        item for item in conformance_all
        if str(item.get("status", "")).lower() not in {"ok", "skip"}
    ]
    heuristic_non_ok = [
        item for item in all_results
        if not str(item.get("name", "")).startswith("CF-")
        and str(item.get("status", "")).lower() not in {"ok", "skip"}
    ]

    return {
        "meta": {
            "requestPath": path,
            "resolvedPath": str(profile),
            "fileName": profile.name,
            "engine": engine,
            "size": len(data),
            "displayBytes": display_bytes,
            "truncated": len(data) > MAX_REPORT_BYTES,
            "maxDisplayBytes": MAX_REPORT_BYTES,
            "sha256": hashlib.sha256(data).hexdigest(),
            "tagCount": tag_count["value"],
            "parsedTags": tag_count["parsedCount"],
        },
        "docs": list(_DOC_SOURCE_PATHS),
        "headerFields": header_fields,
        "tagCount": tag_count,
        "tagEntries": tag_entries,
        "regions": regions,
        "hexLines": _build_hex_lines(data, region_ids, regions),
        "pawg": pawg,
        "conformance": {
            "summary": _status_counts(conformance_all),
            "nonOk": conformance_non_ok,
            "all": conformance_all,
        },
        "heuristics": {
            "summary": _status_counts(heuristic_non_ok),
            "nonOk": heuristic_non_ok,
        },
        "securityJson": security_payload.get("summary") or security_payload.get("stats") or {},
    }


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------
async def index(request: Request) -> Response:
    """Serve the single-page HTML UI with per-request CSP nonce."""
    return _render_html_template(_INDEX_HTML, "<h1>index.html not found</h1>")


async def report_page(request: Request) -> Response:
    """Serve the standalone ICC binary report page."""
    return _render_html_template(_REPORT_HTML, "<h1>report.html not found</h1>")


async def serve_cytoscape_js(request: Request) -> Response:
    """Serve cytoscape.min.js as a static asset (CSP-safe, no CDN dependency)."""
    if not _CYTOSCAPE_JS.is_file():
        return Response("Not found", status_code=404, media_type="text/plain")
    return Response(
        _CYTOSCAPE_JS.read_bytes(),
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=86400"},
    )


async def serve_favicon(request: Request) -> Response:
    """Serve favicon.ico for browser chrome and tab icons."""
    if not _FAVICON_ICO.is_file():
        return Response("Not found", status_code=404, media_type="text/plain")
    return Response(
        _FAVICON_ICO.read_bytes(),
        media_type="image/x-icon",
        headers={"Cache-Control": "public, max-age=86400"},
    )


async def no_content(request: Request) -> Response:
    """Return 204 for browser probe endpoints that should not emit 404 noise."""
    return Response(status_code=204)


async def api_list(request: Request) -> Response:
    """GET /api/list?directory=test-profiles"""
    try:
        directory = request.query_params.get("directory", "test-profiles")
        directory = _validate_directory(directory)
        result = await list_test_profiles(directory)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_list_xml(request: Request) -> Response:
    """GET /api/list-xml?directory=fuzz/xml/icc - list XML files in allowed directories."""
    try:
        directory = request.query_params.get("directory", "fuzz/xml/icc")
        directory = _validate_xml_directory(directory)
        target = (_HERE.parent / directory).resolve()
        repo_root = _HERE.parent.resolve()
        target.relative_to(repo_root)  # raises ValueError if traversal
        if not target.is_dir():
            return JSONResponse({"ok": True, "files": [], "directory": directory})
        xml_files = sorted(target.glob("*.xml"))
        items = []
        for xf in xml_files[:200]:
            try:
                size = xf.stat().st_size
            except OSError:
                size = 0
            items.append({"name": xf.name, "size": size, "path": f"{directory}/{xf.name}"})
        return JSONResponse({"ok": True, "files": items, "directory": directory})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_inspect(request: Request) -> Response:
    """GET /api/inspect?path=<profile>&engine=v1|v2|auto"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        engine = request.query_params.get("engine", DEFAULT_STRUCTURAL_ENGINE)
        async with (await _get_semaphore()):
            result = await inspect_profile(path, engine=engine)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_security(request: Request) -> Response:
    """GET /api/security?path=<profile>&engine=v1|v2|auto"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        engine = request.query_params.get("engine", DEFAULT_ANALYSIS_ENGINE)
        async with (await _get_semaphore()):
            result = await analyze_security(path, engine=engine)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_security_json(request: Request) -> Response:
    """GET /api/security-json?path=<profile>&engine=v1|v2|auto"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        engine = request.query_params.get("engine", DEFAULT_ANALYSIS_ENGINE)
        async with (await _get_semaphore()):
            result = await _load_security_json_payload(path, engine)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_security_report(request: Request) -> Response:
    """GET /api/security-report?path=<profile>&engine=v1|v2|auto"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        engine = request.query_params.get("engine", DEFAULT_ANALYSIS_ENGINE)
        async with (await _get_semaphore()):
            result = await analyze_security_report(path, engine=engine)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_pawg(request: Request) -> Response:
    """GET /api/pawg?path=<profile>&engine=v1|v2|auto"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        engine = request.query_params.get("engine", DEFAULT_ANALYSIS_ENGINE)
        async with (await _get_semaphore()):
            result = await analyze_pawg_report(path, engine=engine)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_roundtrip(request: Request) -> Response:
    """GET /api/roundtrip?path=<profile>&engine=v1|v2|auto"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        engine = request.query_params.get("engine", DEFAULT_STRUCTURAL_ENGINE)
        async with (await _get_semaphore()):
            result = await validate_roundtrip(path, engine=engine)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_full(request: Request) -> Response:
    """GET /api/full?path=<profile>&engine=v1|v2|auto"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        engine = request.query_params.get("engine", DEFAULT_ANALYSIS_ENGINE)
        async with (await _get_semaphore()):
            result = await full_analysis(path, engine=engine)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_xml(request: Request) -> Response:
    """GET /api/xml?path=<profile>"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        async with (await _get_semaphore()):
            result = await profile_to_xml(path)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_xml_download(request: Request) -> Response:
    """GET /api/xml/download?path=<profile> - full XML as file download."""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        async with (await _get_semaphore()):
            profile = _resolve_profile(path)

            # Convert via iccToXml / iccToXml_unsafe
            fd, tmp_path = tempfile.mkstemp(suffix=".xml")
            os.close(fd)
            try:
                success = False
                _safe_bin = os.path.normpath(str(TO_XML_SAFE_BIN))
                if os.path.isfile(_safe_bin) and os.access(_safe_bin, os.X_OK):
                    try:
                        await _run([str(TO_XML_SAFE_BIN), str(profile), tmp_path])
                        if Path(tmp_path).exists() and Path(tmp_path).stat().st_size > 0:
                            success = True
                    except Exception:
                        success = False  # safe tool failed; fall through to unsafe
                if not success:
                    _require_binary(TO_XML_UNSAFE_BIN, "iccToXml_unsafe")
                    Path(tmp_path).unlink(missing_ok=True)
                    fd2, tmp_path2 = tempfile.mkstemp(suffix=".xml")
                    os.close(fd2)
                    tmp_path = tmp_path2
                    await _run([str(TO_XML_UNSAFE_BIN), str(profile), tmp_path])

                xml_p = Path(tmp_path)
                if xml_p.exists() and xml_p.stat().st_size > 0:
                    fsize = xml_p.stat().st_size
                    if fsize > MAX_DOWNLOAD_BYTES:
                        return JSONResponse(
                            {"ok": False, "error": f"XML file too large ({fsize:,} bytes)"},
                            status_code=400,
                        )
                    content = xml_p.read_text(errors="replace")
                    content = _sanitize_output(content)
                    filename = _safe_filename(profile.stem)
                    return Response(
                        content,
                        media_type="application/xml",
                        headers={
                            "Content-Disposition": f'attachment; filename="{filename}"',
                            **_SECURITY_HEADERS,
                        },
                    )
                return JSONResponse(
                    {"ok": False, "error": "No XML output produced"}, status_code=400
                )
            finally:
                Path(tmp_path).unlink(missing_ok=True)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_compare(request: Request) -> Response:
    """GET /api/compare?path_a=<profile>&path_b=<profile>"""
    try:
        path_a = _validate_path(request.query_params.get("path_a", ""), "path_a")
        path_b = _validate_path(request.query_params.get("path_b", ""), "path_b")
        async with (await _get_semaphore()):
            result = await compare_profiles(path_a, path_b)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_report(request: Request) -> Response:
    """GET /api/report?path=<profile>&engine=v1|v2|auto"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        engine = request.query_params.get("engine", DEFAULT_ANALYSIS_ENGINE)
        async with (await _get_semaphore()):
            result = await _build_profile_report(path, engine)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_health(request: Request) -> Response:
    """GET /api/health - liveness check."""
    v1_ok = ANALYZER_BIN.is_file() and os.access(ANALYZER_BIN, os.X_OK)
    v2_ok = ANALYZER_V2_BIN.is_file() and os.access(ANALYZER_V2_BIN, os.X_OK)
    resp = {
        "ok": True,
        "tools": 28,
        "engines": {"v1": v1_ok, "v2": v2_ok},
        "defaultAnalysisEngine": DEFAULT_ANALYSIS_ENGINE,
        "defaultStructuralEngine": DEFAULT_STRUCTURAL_ENGINE,
    }
    return JSONResponse(resp)


async def api_registry(request: Request) -> Response:
    """GET /api/registry - heuristic database (source of truth for all counts)."""
    try:
        engine = request.query_params.get("engine", "v1")
        analyzer = _get_analyzer(engine)
        result = await _run([str(analyzer), "--registry"], include_stderr=False)
        result = result.strip()
        if result.startswith("{"):
            import json as _json
            data = _json.loads(result)
            return JSONResponse({"ok": True, "engine": engine, "registry": data})
        return JSONResponse({"ok": False, "error": "Invalid registry output"}, status_code=500)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_profile_overlay(request: Request) -> Response:
    """GET /api/profile-overlay?path=<profile> - structured three-layer overlay view."""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        async with (await _get_semaphore()):
            result = await _build_profile_overlay(path)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


# ---------------------------------------------------------------------------
# Maintainer tool endpoints (POST - they trigger builds / side-effects)
# ---------------------------------------------------------------------------
def _validate_build_dir(value: str) -> str:
    """Validate build_dir param: alphanumeric, dash, underscore, dot only."""
    value = value.strip()
    if not value:
        return ""
    if len(value) > 200:
        raise ValueError("build_dir exceeds 200 characters")
    if not re.match(r"^[a-zA-Z0-9._-]+$", value):
        raise ValueError("build_dir contains disallowed characters")
    if ".." in value:
        raise ValueError("build_dir contains path traversal sequence")
    return value


def _validate_choice(value: str, valid: set, param_name: str) -> str:
    """Validate a parameter against a set of valid choices."""
    value = value.strip()
    if value not in valid:
        raise ValueError(f"{param_name} must be one of: {', '.join(sorted(valid))}")
    return value


def _constant_time_equals(lhs: str, rhs: str) -> bool:
    return len(lhs) == len(rhs) and secrets.compare_digest(lhs, rhs)


def _constant_time_prefix(lhs: str, prefix: str) -> bool:
    prefix_with_sep = prefix + "_"
    return len(lhs) > len(prefix) and len(lhs) >= len(prefix_with_sep) and secrets.compare_digest(
        lhs[: len(prefix_with_sep)], prefix_with_sep
    )


def _validate_extra_cmake_args(value: str) -> str:
    """Validate extra cmake args: length limit, no shell metacharacters.

    Defense-in-depth: also rejects known dangerous CMake variable names
    that could enable RCE (e.g. CMAKE_PROJECT_INCLUDE, CMAKE_TOOLCHAIN_FILE).
    The primary allowlist enforcement is in _sanitize_cmake_args().
    """
    value = value.strip()
    if not value:
        return ""
    if len(value) > 500:
        raise ValueError("extra_cmake_args exceeds 500 characters")
    # Reject obvious shell injection
    for ch in [";", "|", "`", "$", "(", ")", "<", ">", "&", "\n", "\r", "\x00"]:
        if ch in value:
            raise ValueError(f"extra_cmake_args contains disallowed character: {repr(ch)}")
    # Reject dangerous CMake variable names (defense-in-depth)
    _DANGEROUS_CMAKE_PREFIXES = (
        "CMAKE_PROJECT_INCLUDE", "CMAKE_TOOLCHAIN_FILE",
        "CMAKE_C_COMPILER", "CMAKE_CXX_COMPILER",
        "CMAKE_MAKE_PROGRAM", "CMAKE_COMMAND",
        "CMAKE_LINKER", "CMAKE_AR", "CMAKE_RANLIB",
        "CMAKE_MODULE_PATH", "CMAKE_PREFIX_PATH",
        "CMAKE_SYSROOT", "CMAKE_FIND_ROOT",
        "CMAKE_C_FLAGS", "CMAKE_CXX_FLAGS",
        "CMAKE_EXE_LINKER_FLAGS", "CMAKE_SHARED_LINKER_FLAGS",
    )
    for token in value.split():
        if token.startswith("-D"):
            var_name = token[2:].split("=", 1)[0]
            normalized = var_name.upper()
            for prefix in _DANGEROUS_CMAKE_PREFIXES:
                if _constant_time_equals(normalized, prefix) or _constant_time_prefix(
                    normalized, prefix
                ):
                    raise ValueError(
                        f"extra_cmake_args contains blocked variable: {var_name}"
                    )
    return value


async def api_cmake_configure(request: Request) -> Response:
    """POST /api/cmake/configure - run cmake configure with given options."""
    try:
        body = await request.json()
        build_type = _validate_choice(
            body.get("build_type", "Debug"), _VALID_BUILD_TYPES, "build_type"
        )
        enable_tools = bool(body.get("enable_tools", False))
        sanitizers = _validate_choice(
            body.get("sanitizers", "asan+ubsan"), _VALID_SANITIZERS, "sanitizers"
        )
        compiler = _validate_choice(
            body.get("compiler", "clang"), _VALID_COMPILERS, "compiler"
        )
        generator = _validate_choice(
            body.get("generator", "default"), _VALID_GENERATORS, "generator"
        )
        extra_cmake_args = _validate_extra_cmake_args(
            body.get("extra_cmake_args", "")
        )
        build_dir = _validate_build_dir(body.get("build_dir", ""))

        async with (await _get_semaphore()):
            result = await cmake_configure(
                build_type=build_type,
                enable_tools=enable_tools,
                sanitizers=sanitizers,
                compiler=compiler,
                generator=generator,
                extra_cmake_args=extra_cmake_args,
                build_dir=build_dir,
            )
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_cmake_build(request: Request) -> Response:
    """POST /api/cmake/build - build iccDEV in a configured build directory."""
    try:
        body = await request.json()
        build_dir = _validate_build_dir(body.get("build_dir", ""))
        target = body.get("target", "")
        if isinstance(target, str):
            target = target.strip()[:100]
        else:
            target = ""
        jobs = body.get("jobs", 0)
        if not isinstance(jobs, int) or jobs < 0:
            jobs = 0

        async with (await _get_semaphore()):
            result = await cmake_build(
                build_dir=build_dir,
                target=target,
                jobs=jobs,
            )
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_create_profiles(request: Request) -> Response:
    """POST /api/create-profiles - run CreateAllProfiles.sh."""
    try:
        body = await request.json()
        build_dir = _validate_build_dir(body.get("build_dir", ""))
        async with (await _get_semaphore()):
            result = await create_all_profiles(build_dir=build_dir)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_run_tests(request: Request) -> Response:
    """POST /api/run-tests - run iccDEV RunTests.sh."""
    try:
        body = await request.json()
        build_dir = _validate_build_dir(body.get("build_dir", ""))
        async with (await _get_semaphore()):
            result = await run_iccdev_tests(build_dir=build_dir)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_option_matrix(request: Request) -> Response:
    """POST /api/cmake/option-matrix - test cmake options independently."""
    try:
        body = await request.json()
        options = body.get("options", "ENABLE_COVERAGE,ICC_ENABLE_ASSERTS,ICC_TRACE_NAN_ENABLED")
        if not isinstance(options, str):
            raise ValueError("options must be a comma-separated string")
        opt_list = [o.strip() for o in options.split(",") if o.strip()]
        invalid = [o for o in opt_list if o not in _VALID_CMAKE_OPTIONS]
        if invalid:
            raise ValueError(f"Unknown cmake options: {', '.join(invalid)}")
        build_type = _validate_choice(
            body.get("build_type", "Release"), _VALID_BUILD_TYPES, "build_type"
        )
        compiler = _validate_choice(
            body.get("compiler", "clang"), _VALID_COMPILERS, "compiler"
        )
        async with (await _get_semaphore()):
            result = await cmake_option_matrix(
                options=options,
                build_type=build_type,
                compiler=compiler,
            )
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_windows_build(request: Request) -> Response:
    """POST /api/cmake/windows-build - Windows MSVC + vcpkg build."""
    try:
        body = await request.json()
        build_type = _validate_choice(
            body.get("build_type", "Debug"), _VALID_BUILD_TYPES, "build_type"
        )
        vcpkg_deps = _validate_choice(
            body.get("vcpkg_deps", "release"), _VALID_VCPKG_SOURCES, "vcpkg_deps"
        )
        enable_tools = bool(body.get("enable_tools", True))
        extra_cmake_args = _validate_extra_cmake_args(
            body.get("extra_cmake_args", "")
        )
        build_dir = _validate_build_dir(body.get("build_dir", ""))

        async with (await _get_semaphore()):
            result = await windows_build(
                build_type=build_type,
                vcpkg_deps=vcpkg_deps,
                enable_tools=enable_tools,
                extra_cmake_args=extra_cmake_args,
                build_dir=build_dir,
            )
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


# ---------------------------------------------------------------------------
# Operations tool endpoints
# ---------------------------------------------------------------------------
async def api_health_check(request: Request) -> Response:
    """GET /api/health-check - full health check via MCP tool."""
    try:
        async with (await _get_semaphore()):
            result = await health_check()
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_build_tools(request: Request) -> Response:
    """POST /api/build-tools - build analysis tools from source."""
    try:
        body = await request.json()
        target = body.get("target", "all")
        if not isinstance(target, str):
            target = "all"
        valid_targets = {"all", "iccanalyzer-lite", "icctest", "colorbleed_tools"}
        if target not in valid_targets:
            raise ValueError(f"target must be one of: {', '.join(sorted(valid_targets))}")
        async with (await _get_semaphore()):
            result = await build_tools(target=target)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_check_dependencies(request: Request) -> Response:
    """GET /api/check-dependencies - check build dependency availability."""
    try:
        async with (await _get_semaphore()):
            result = await check_dependencies()
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_find_build_artifacts(request: Request) -> Response:
    """GET /api/find-artifacts - find binaries in build directories."""
    try:
        build_dir = _validate_build_dir(
            request.query_params.get("build_dir", "")
        )
        async with (await _get_semaphore()):
            result = await find_build_artifacts(build_dir=build_dir)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_batch_test_profiles(request: Request) -> Response:
    """POST /api/batch-test - run tools over profile set."""
    try:
        body = await request.json()
        directory = body.get("directory", "")
        if isinstance(directory, str):
            directory = directory.strip()[:500]
        else:
            directory = ""
        tool = body.get("tool", "all")
        if not isinstance(tool, str):
            tool = "all"
        tool = _BATCH_TOOL_ALIASES.get(tool, tool)
        valid_tools = {"dump", "toxml", "fromxml", "roundtrip", "all"}
        if tool not in valid_tools:
            raise ValueError(f"tool must be one of: {', '.join(sorted(valid_tools))}")
        raw_build_dir = body.get("build_dir", "")
        build_dir = _validate_build_dir(raw_build_dir) if raw_build_dir else ""
        async with (await _get_semaphore()):
            result = await batch_test_profiles(
                directory=directory, tool=tool, build_dir=build_dir
            )
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_validate_xml(request: Request) -> Response:
    """POST /api/validate-xml - validate ICC XML files with xmllint."""
    try:
        body = await request.json()
        directory = body.get("directory", "")
        if isinstance(directory, str):
            directory = directory.strip()[:500]
        else:
            directory = ""
        checks = body.get("checks", "all")
        if not isinstance(checks, str):
            checks = "all"
        valid_checks = {"wellformed", "encoding", "size", "safety", "all"}
        check_list = [c.strip() for c in checks.split(",")]
        invalid = [c for c in check_list if c not in valid_checks]
        if invalid:
            raise ValueError(f"Unknown check(s): {', '.join(invalid)}. Choose: {', '.join(sorted(valid_checks))}")
        async with (await _get_semaphore()):
            result = await validate_xml(directory=directory, checks=checks)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_coverage_report(request: Request) -> Response:
    """POST /api/coverage-report - merge profraw and generate coverage report."""
    try:
        body = await request.json()
        build_dir = _validate_build_dir(body.get("build_dir", ""))
        async with (await _get_semaphore()):
            result = await coverage_report(build_dir=build_dir)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_scan_logs(request: Request) -> Response:
    """POST /api/scan-logs - scan log files for errors and findings."""
    try:
        body = await request.json()
        directory = body.get("directory", "")
        if isinstance(directory, str):
            directory = directory.strip()[:500]
        else:
            directory = ""
        categories = body.get("categories", "all")
        if not isinstance(categories, str):
            categories = "all"
        async with (await _get_semaphore()):
            result = await scan_logs(directory=directory, categories=categories)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_upload_and_analyze(request: Request) -> Response:
    """POST /api/upload-and-analyze - upload base64 ICC file and analyze."""
    try:
        body = await request.json()
        data_base64 = body.get("data_base64", "")
        if not isinstance(data_base64, str) or not data_base64.strip():
            raise ValueError("data_base64 is required")
        filename = body.get("filename", "upload.icc")
        if not isinstance(filename, str):
            filename = "upload.icc"
        mode = body.get("mode", "security")
        if not isinstance(mode, str):
            mode = "security"
        engine = body.get("engine")
        if engine is not None and not isinstance(engine, str):
            engine = None
        async with (await _get_semaphore()):
            result = await upload_and_analyze(
                data_base64=data_base64, filename=filename, mode=mode, engine=engine
            )
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


def _get_upload_dir() -> Path:
    """Return (and lazily create) a secure temp directory for uploaded files."""
    global _UPLOAD_DIR
    if _UPLOAD_DIR is None or not _UPLOAD_DIR.is_dir():
        _UPLOAD_DIR = Path(tempfile.mkdtemp(prefix="mcp_uploads_"))
        if sys.platform != "win32":
            os.chmod(_UPLOAD_DIR, 0o700)
        register_allowed_base(_UPLOAD_DIR)
    return _UPLOAD_DIR


async def api_upload(request: Request) -> Response:
    """POST /api/upload - accept a local ICC file for analysis.

    Returns a server-side path that can be used in all tool inputs.
    File is stored in a secure temp directory with a random name.
    """
    try:
        content_type = request.headers.get("content-type", "")
        if "multipart/form-data" not in content_type:
            return JSONResponse(
                {"ok": False, "error": "Content-Type must be multipart/form-data"},
                status_code=400,
            )

        # Reject obviously oversized bodies before parsing the multipart form
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit():
            if int(content_length) > MAX_UPLOAD_BYTES + 4096:  # small overhead for multipart framing
                return JSONResponse(
                    {"ok": False, "error": f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit"},
                    status_code=400,
                )

        form = await request.form()
        upload = form.get("file")
        if upload is None:
            return JSONResponse(
                {"ok": False, "error": "No file field in upload"},
                status_code=400,
            )

        # Validate filename
        orig_name = getattr(upload, "filename", "") or "upload.icc"
        clean_name = _SAFE_FILENAME_RE.sub("_", Path(orig_name).name)[:200]
        if not clean_name:
            clean_name = "upload.icc"

        # Reject dangerous file extensions that could enable RCE if
        # referenced by CMake variables or other tooling
        _DANGEROUS_EXTENSIONS = {
            ".cmake", ".py", ".sh", ".bash", ".bat", ".cmd", ".ps1",
            ".exe", ".dll", ".so", ".dylib", ".rb", ".pl", ".php",
        }
        ext = Path(clean_name).suffix.lower()
        if ext in _DANGEROUS_EXTENSIONS:
            return JSONResponse(
                {"ok": False, "error": f"File extension '{ext}' is not allowed"},
                status_code=400,
            )

        # Read with size limit
        data = await upload.read()
        if len(data) > MAX_UPLOAD_BYTES:
            return JSONResponse(
                {"ok": False, "error": f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit"},
                status_code=400,
            )
        if len(data) == 0:
            return JSONResponse(
                {"ok": False, "error": "File is empty"},
                status_code=400,
            )

        # Store with random prefix to prevent name collisions and guessing
        upload_dir = _get_upload_dir()
        prefix = secrets.token_hex(8)
        dest = upload_dir / f"{prefix}_{clean_name}"
        dest.write_bytes(data)
        if sys.platform != "win32":
            os.chmod(dest, 0o600)

        # Return the path relative to upload dir - the resolver will find it
        return JSONResponse({
            "ok": True,
            "path": str(dest),
            "filename": clean_name,
            "size": len(data),
        })
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_output_download(request: Request) -> Response:
    """POST /api/output/download - save arbitrary tool output as a file.

    Accepts JSON body: {tool, text, filename?}
    Returns the text as a downloadable file attachment.
    """
    try:
        # Reject oversized request bodies before JSON parsing
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit():
            if int(content_length) > MAX_DOWNLOAD_BYTES + 4096:
                return JSONResponse(
                    {"ok": False, "error": f"Output exceeds {MAX_DOWNLOAD_BYTES // (1024*1024)} MB limit"},
                    status_code=400,
                )
        body = await request.json()
        text = body.get("text", "")
        if not isinstance(text, str) or not text.strip():
            return JSONResponse(
                {"ok": False, "error": "No text to download"},
                status_code=400,
            )
        if len(text) > MAX_DOWNLOAD_BYTES:
            return JSONResponse(
                {"ok": False, "error": f"Output exceeds {MAX_DOWNLOAD_BYTES // (1024*1024)} MB limit"},
                status_code=400,
            )

        tool = body.get("tool", "output")
        if not isinstance(tool, str):
            tool = "output"
        tool = _SAFE_FILENAME_RE.sub("_", tool)[:50]
        user_filename = body.get("filename", "")
        if user_filename:
            filename = _safe_filename(
                _SAFE_FILENAME_RE.sub("_", user_filename)[:200],
                ext=".txt"
            )
        else:
            filename = _safe_filename(f"icc_{tool}", ext=".txt")

        return Response(
            _sanitize_output(text),
            media_type="text/plain; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                **_SECURITY_HEADERS,
            },
        )
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


# ---------------------------------------------------------------------------
# Security middleware
# ---------------------------------------------------------------------------
class SecurityHeadersMiddleware:
    """Add security headers to every response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                for k, v in _SECURITY_HEADERS_ENCODED:
                    if k not in headers:  # don't override per-response headers (e.g. nonce CSP)
                        headers[k] = v
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ---------------------------------------------------------------------------
# Graph / knowledge-graph endpoints
# ---------------------------------------------------------------------------

async def api_attack_surface(request: Request) -> Response:
    """GET /api/attack-surface - rank nodes by betweenness centrality."""
    try:
        top_n_raw = request.query_params.get("top_n", "15")
        try:
            top_n = max(1, min(100, int(top_n_raw)))

        except (ValueError, TypeError):
            top_n = 15
        async with (await _get_semaphore()):
            result = await query_attack_surface(top_n=top_n)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_coverage_gaps(request: Request) -> Response:
    """GET /api/coverage-gaps - identify heuristics/patches/components lacking coverage."""
    try:
        severity_filter = request.query_params.get("severity_filter", "")
        if not isinstance(severity_filter, str):
            severity_filter = ""
        severity_filter = severity_filter.strip().upper()[:20]
        if severity_filter == "ALL":
            severity_filter = ""
        async with (await _get_semaphore()):
            result = await coverage_gaps(severity_filter=severity_filter)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_dump_all(request: Request) -> Response:
    """GET /api/dump-all - deep tag dump via iccDumpAll."""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        if not path:
            return JSONResponse({"ok": False, "error": "path is required"}, status_code=400)
        verbosity_raw = request.query_params.get("verbosity", "100")
        try:
            verbosity = max(1, min(100, int(verbosity_raw)))
        except (ValueError, TypeError):
            verbosity = 100
        use_read = request.query_params.get("use_read", "").lower() in ("true", "1", "yes")
        diag = request.query_params.get("diag", "").lower() in ("true", "1", "yes")
        async with (await _get_semaphore()):
            result = await dump_all(
                path=path, verbosity=verbosity, use_read=use_read, diag=diag,
            )
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_diagnostic_load(request: Request) -> Response:
    """GET /api/diagnostic-load - deep diagnostic load analysis."""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        if not path:
            return JSONResponse({"ok": False, "error": "path is required"}, status_code=400)
        mode = request.query_params.get("mode", "all").strip().lower()[:20]
        if mode not in _VALID_DIAG_MODES:
            valid = ", ".join(sorted(_VALID_DIAG_MODES))
            return JSONResponse(
                {"ok": False, "error": f"mode must be one of: {valid}"},
                status_code=400,
            )
        async with (await _get_semaphore()):
            result = await diagnostic_load(path=path, mode=mode)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_knowledge_graph_json(request: Request) -> Response:
    """GET /api/knowledge-graph.json - serve the knowledge graph data for the viewer."""
    import json as _json

    _REPO_ROOT = _HERE.parent
    kg_path = _REPO_ROOT / "call-graph" / "knowledge-graph.json"
    if not kg_path.is_file():
        return JSONResponse(
            {"ok": False, "error": "knowledge-graph.json not found. Run: python3 call-graph/scripts/build-knowledge-graph.py"},
            status_code=404,
        )
    try:
        data = _json.loads(kg_path.read_text(encoding="utf-8"))
        return JSONResponse(data)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=500)


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
routes = [
    Route("/", index, methods=["GET"]),
    Route("/report", report_page, methods=["GET"]),
    Route("/favicon.ico", serve_favicon, methods=["GET"]),
    Route("/.well-known/appspecific/com.chrome.devtools.json", no_content, methods=["GET"]),
    Route("/static/cytoscape.min.js", serve_cytoscape_js, methods=["GET"]),
    Route("/api/health", api_health, methods=["GET"]),
    Route("/api/registry", api_registry, methods=["GET"]),
    Route("/api/profile-overlay", api_profile_overlay, methods=["GET"]),
    Route("/api/list", api_list, methods=["GET"]),
    Route("/api/list-xml", api_list_xml, methods=["GET"]),
    Route("/api/inspect", api_inspect, methods=["GET"]),
    Route("/api/security", api_security, methods=["GET"]),
    Route("/api/security-json", api_security_json, methods=["GET"]),
    Route("/api/security-report", api_security_report, methods=["GET"]),
    Route("/api/pawg", api_pawg, methods=["GET"]),
    Route("/api/roundtrip", api_roundtrip, methods=["GET"]),
    Route("/api/full", api_full, methods=["GET"]),
    Route("/api/xml", api_xml, methods=["GET"]),
    Route("/api/xml/download", api_xml_download, methods=["GET"]),
    Route("/api/compare", api_compare, methods=["GET"]),
    Route("/api/report", api_report, methods=["GET"]),
    Route("/api/upload", api_upload, methods=["POST"]),
    Route("/api/output/download", api_output_download, methods=["POST"]),
    Route("/api/cmake/configure", api_cmake_configure, methods=["POST"]),
    Route("/api/cmake/build", api_cmake_build, methods=["POST"]),
    Route("/api/create-profiles", api_create_profiles, methods=["POST"]),
    Route("/api/run-tests", api_run_tests, methods=["POST"]),
    Route("/api/cmake/option-matrix", api_option_matrix, methods=["POST"]),
    Route("/api/cmake/windows-build", api_windows_build, methods=["POST"]),
    Route("/api/health-check", api_health_check, methods=["GET"]),
    Route("/api/build-tools", api_build_tools, methods=["POST"]),
    Route("/api/check-dependencies", api_check_dependencies, methods=["GET"]),
    Route("/api/find-artifacts", api_find_build_artifacts, methods=["GET"]),
    Route("/api/batch-test", api_batch_test_profiles, methods=["POST"]),
    Route("/api/validate-xml", api_validate_xml, methods=["POST"]),
    Route("/api/coverage-report", api_coverage_report, methods=["POST"]),
    Route("/api/scan-logs", api_scan_logs, methods=["POST"]),
    Route("/api/upload-and-analyze", api_upload_and_analyze, methods=["POST"]),
    Route("/api/attack-surface", api_attack_surface, methods=["GET"]),
    Route("/api/coverage-gaps", api_coverage_gaps, methods=["GET"]),
    Route("/api/dump-all", api_dump_all, methods=["GET"]),
    Route("/api/diagnostic-load", api_diagnostic_load, methods=["GET"]),
    Route("/api/knowledge-graph.json", api_knowledge_graph_json, methods=["GET"]),
]

app = Starlette(
    routes=routes,
    middleware=[Middleware(SecurityHeadersMiddleware)],
)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="ICC Profile MCP Web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    args = parser.parse_args()

    if args.host == "0.0.0.0":
        print("[WARN] WARNING: Binding to 0.0.0.0 exposes the server on all network interfaces.")
        print("   No authentication is configured. Use --host 127.0.0.1 for local-only access.")
    print(f"ICC Profile MCP Web UI -> http://{args.host}:{args.port}")
    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    finally:
        # Clean up uploaded temp files
        if _UPLOAD_DIR and _UPLOAD_DIR.is_dir():
            shutil.rmtree(_UPLOAD_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
