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
_CYTOSCAPE_JS = _HERE / "cytoscape.min.js"
_FAVICON_ICO = _HERE / "favicon.ico"
_INDEX_CONTENT: str | None = None  # cached on first request
MAX_PATH_LEN = 512
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB cap on file downloads
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


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------
async def index(request: Request) -> Response:
    """Serve the single-page HTML UI with per-request CSP nonce."""
    global _INDEX_CONTENT
    if _INDEX_CONTENT is None:
        if not _INDEX_HTML.is_file():
            return HTMLResponse("<h1>index.html not found</h1>", status_code=500)
        _INDEX_CONTENT = _INDEX_HTML.read_text(encoding="utf-8")

    # Generate a fresh nonce for each request
    nonce = secrets.token_urlsafe(32)
    html = _INDEX_CONTENT.replace("<style>", f'<style nonce="{nonce}">', 1)
    html = html.replace("<script>", f'<script nonce="{nonce}">', 1)

    headers = dict(_SECURITY_HEADERS)
    headers["Content-Security-Policy"] = _CSP_NONCE_TEMPLATE.format(nonce=nonce)
    return HTMLResponse(html, headers=headers)


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
        import json as _json
        path = _validate_path(request.query_params.get("path", ""), "path")
        engine = request.query_params.get("engine", DEFAULT_ANALYSIS_ENGINE)
        async with (await _get_semaphore()):
            result = await analyze_security_json(path, engine=engine)
        # Defense-in-depth: strip any residual stderr if present
        sep = "\n--- stderr ---\n"
        if sep in result:
            result = result[: result.index(sep)]
        if result.lstrip().startswith("--- stderr ---"):
            result = ""
        # Handle crash recovery: if no JSON output, return structured error
        result = result.strip()
        if not result or not result.startswith("{"):
            _h_count = _get_heuristic_count()
            crash_payload = {
                "engine": engine,
                "crashRecovery": True,
                "results": [],
            }
            if engine == "v1":
                crash_payload["summary"] = {
                    "totalHeuristics": _h_count,
                    "heuristicsRun": 0,
                    "ok": 0,
                    "warnings": 0,
                    "critical": 1,
                    "crashRecovery": True,
                    "note": (
                        "Profile triggered crash recovery (SIGSEGV/SIGABRT) - "
                        "no JSON output available. Use /api/security for text analysis."
                    ),
                }
            else:
                crash_payload["stats"] = {
                    "checksRun": 0,
                    "findings": 0,
                    "crashRecovery": True,
                    "note": (
                        "Profile triggered crash recovery (SIGSEGV/SIGABRT) - "
                        "no JSON output available. Use /api/security for text analysis."
                    ),
                }
            return JSONResponse({
                "ok": True,
                "result": crash_payload,
            })
        return JSONResponse({"ok": True, "result": _json.loads(result)})
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
    Route("/favicon.ico", serve_favicon, methods=["GET"]),
    Route("/.well-known/appspecific/com.chrome.devtools.json", no_content, methods=["GET"]),
    Route("/static/cytoscape.min.js", serve_cytoscape_js, methods=["GET"]),
    Route("/api/health", api_health, methods=["GET"]),
    Route("/api/registry", api_registry, methods=["GET"]),
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
