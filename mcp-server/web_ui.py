#!/usr/bin/env python3
"""
ICC Profile MCP Server — Web UI Backend

Thin REST API wrapping the 15 MCP tool functions (9 analysis + 6 maintainer).
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
    TO_XML_SAFE_BIN,
    TO_XML_UNSAFE_BIN,
    _require_binary,
    _resolve_profile,
    _run,
    _sanitize_output,
    _VALID_BUILD_TYPES,
    _VALID_CMAKE_OPTIONS,
    _VALID_COMPILERS,
    _VALID_GENERATORS,
    _VALID_SANITIZERS,
    _VALID_VCPKG_SOURCES,
    analyze_security,
    cmake_build,
    cmake_configure,
    compare_profiles,
    create_all_profiles,
    cmake_option_matrix,
    full_analysis,
    inspect_profile,
    list_test_profiles,
    profile_to_xml,
    register_allowed_base,
    run_iccdev_tests,
    validate_roundtrip,
    windows_build,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_INDEX_HTML = _HERE / "index.html"
_INDEX_CONTENT: str | None = None  # cached on first request
MAX_PATH_LEN = 512
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB cap on file downloads
# Allow only safe profile-path characters (alphanumeric, dash, underscore, dot, slash, tilde)
# Include backslash for Windows path compatibility
_SAFE_PATH_RE = re.compile(r"^[a-zA-Z0-9._/\\~ :-]+$")
# Filename sanitization for Content-Disposition: keep only safe chars
_SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9._-]")

# Allowed directory names for list_test_profiles
_ALLOWED_DIRS = frozenset({"test-profiles", "extended-test-profiles", "xif", "fuzz/graphics/icc"})

# Limit concurrent subprocess executions
_MAX_CONCURRENT = 4
_semaphore: asyncio.Semaphore | None = None
_semaphore_lock = asyncio.Lock()

# Upload constraints
MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB max upload
_UPLOAD_DIR: Path | None = None  # lazily created temp dir for uploads


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
    "style-src 'self' 'nonce-{nonce}'; "
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


async def api_list(request: Request) -> Response:
    """GET /api/list?directory=test-profiles"""
    try:
        directory = request.query_params.get("directory", "test-profiles")
        directory = _validate_directory(directory)
        result = await list_test_profiles(directory)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_inspect(request: Request) -> Response:
    """GET /api/inspect?path=<profile>"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        async with (await _get_semaphore()):
            result = await inspect_profile(path)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_security(request: Request) -> Response:
    """GET /api/security?path=<profile>"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        async with (await _get_semaphore()):
            result = await analyze_security(path)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_roundtrip(request: Request) -> Response:
    """GET /api/roundtrip?path=<profile>"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        async with (await _get_semaphore()):
            result = await validate_roundtrip(path)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_full(request: Request) -> Response:
    """GET /api/full?path=<profile>"""
    try:
        path = _validate_path(request.query_params.get("path", ""), "path")
        async with (await _get_semaphore()):
            result = await full_analysis(path)
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
    """GET /api/xml/download?path=<profile> — full XML as file download."""
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
    """GET /api/health — liveness check."""
    return JSONResponse({"ok": True, "tools": 16})


# ---------------------------------------------------------------------------
# Maintainer tool endpoints (POST — they trigger builds / side-effects)
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


def _validate_extra_cmake_args(value: str) -> str:
    """Validate extra cmake args: length limit, no shell metacharacters."""
    value = value.strip()
    if not value:
        return ""
    if len(value) > 500:
        raise ValueError("extra_cmake_args exceeds 500 characters")
    # Reject obvious shell injection
    for ch in [";", "|", "`", "$", "(", ")", "<", ">", "&", "\n", "\r", "\x00"]:
        if ch in value:
            raise ValueError(f"extra_cmake_args contains disallowed character: {repr(ch)}")
    return value


async def api_cmake_configure(request: Request) -> Response:
    """POST /api/cmake/configure — run cmake configure with given options."""
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
    """POST /api/cmake/build — build iccDEV in a configured build directory."""
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
    """POST /api/create-profiles — run CreateAllProfiles.sh."""
    try:
        body = await request.json()
        build_dir = _validate_build_dir(body.get("build_dir", ""))
        async with (await _get_semaphore()):
            result = await create_all_profiles(build_dir=build_dir)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_run_tests(request: Request) -> Response:
    """POST /api/run-tests — run iccDEV RunTests.sh."""
    try:
        body = await request.json()
        build_dir = _validate_build_dir(body.get("build_dir", ""))
        async with (await _get_semaphore()):
            result = await run_iccdev_tests(build_dir=build_dir)
        return JSONResponse({"ok": True, "result": result})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_option_matrix(request: Request) -> Response:
    """POST /api/cmake/option-matrix — test cmake options independently."""
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
    """POST /api/cmake/windows-build — Windows MSVC + vcpkg build."""
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
    """POST /api/upload — accept a local ICC file for analysis.

    Returns a server-side relative path that can be used in all tool inputs.
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

        # Return the path relative to upload dir — the resolver will find it
        return JSONResponse({
            "ok": True,
            "path": str(dest),
            "filename": clean_name,
            "size": len(data),
        })
    except Exception as exc:
        return JSONResponse({"ok": False, "error": _safe_error(exc)}, status_code=400)


async def api_output_download(request: Request) -> Response:
    """POST /api/output/download — save arbitrary tool output as a file.

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
# Application
# ---------------------------------------------------------------------------
routes = [
    Route("/", index, methods=["GET"]),
    Route("/api/health", api_health, methods=["GET"]),
    Route("/api/list", api_list, methods=["GET"]),
    Route("/api/inspect", api_inspect, methods=["GET"]),
    Route("/api/security", api_security, methods=["GET"]),
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
    print(f"ICC Profile MCP Web UI → http://{args.host}:{args.port}")
    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    finally:
        # Clean up uploaded temp files
        if _UPLOAD_DIR and _UPLOAD_DIR.is_dir():
            shutil.rmtree(_UPLOAD_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
