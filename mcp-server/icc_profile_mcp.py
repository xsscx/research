#!/usr/bin/env python3
"""
ICC Profile MCP Server

Exposes iccanalyzer-lite and colorbleed_tools as MCP tools for interactive
ICC color profile analysis, security scanning, and structural inspection.

Build prerequisites:
    cd iccanalyzer-lite && ./build.sh
    cd colorbleed_tools && make setup && make
"""

import asyncio
import base64
import hashlib
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

def _init_repo_root() -> Path:
    """Resolve REPO_ROOT with path validation to prevent path-injection."""
    raw = os.environ.get("ICC_MCP_ROOT", str(Path(__file__).resolve().parent.parent))
    resolved = os.path.realpath(raw)
    if not os.path.isdir(resolved):
        raise RuntimeError(f"REPO_ROOT is not a directory: {resolved}")
    return Path(resolved)


REPO_ROOT = _init_repo_root()
ANALYZER_BIN = REPO_ROOT / "iccanalyzer-lite" / "iccanalyzer-lite"
TO_XML_SAFE_BIN = REPO_ROOT / "colorbleed_tools" / "iccToXml"
TO_XML_UNSAFE_BIN = REPO_ROOT / "colorbleed_tools" / "iccToXml_unsafe"
TEST_PROFILES = REPO_ROOT / "test-profiles"
EXTENDED_PROFILES = REPO_ROOT / "extended-test-profiles"
XIF_DIR = REPO_ROOT / "xif"
FUZZ_ICC_DIR = REPO_ROOT / "fuzz" / "graphics" / "icc"
ICCDEV_DIR = REPO_ROOT / "iccanalyzer-lite" / "iccDEV"

# Allowed base directories for profile resolution (resolved at import time)
_ALLOWED_BASES = [REPO_ROOT, TEST_PROFILES, EXTENDED_PROFILES, XIF_DIR, FUZZ_ICC_DIR]
_ALLOWED_BASES_RESOLVED = [b.resolve() for b in _ALLOWED_BASES]


def register_allowed_base(base: Path) -> None:
    """Register an additional allowed base directory for profile resolution."""
    resolved = base.resolve()
    if resolved not in _ALLOWED_BASES_RESOLVED:
        _ALLOWED_BASES.append(base)
        _ALLOWED_BASES_RESOLVED.append(resolved)

MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB cap on subprocess output
MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB cap on uploaded profiles
_UPLOAD_DIR: Path | None = None  # lazily created secure temp dir

# Matches sanitize-sed.sh: strip C0 control chars except LF (\n), plus DEL (0x7F).
# Keeps tab (\t) for formatted output readability.
# Strip ANSI escape sequences (e.g. \x1b[32m, \x1b[0m) before stripping bare control chars
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_CTRL_CHAR_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)


def _sanitize_output(text: str) -> str:
    """Strip dangerous control characters from subprocess output.

    Mirrors sanitize-sed.sh _strip_ctrl_keep_newlines + collapse excessive
    blank lines.  Keeps \\n and \\t for readability.
    """
    text = text.replace("\r", "")
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _CTRL_CHAR_RE.sub("", text)
    # Collapse runs of 4+ newlines to 3 (prevent giant junk gaps)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text


mcp = FastMCP(
    "icc-profile-analyzer",
    instructions="Interactive ICC color profile analysis, security scanning, and inspection",
)


def _resolve_profile(path: str) -> Path:
    """Resolve a profile path, checking common directories if not absolute.

    Security: resolves symlinks and verifies the real path stays within
    allowed directories to prevent path traversal and symlink attacks.
    """
    p = Path(path)
    # Reject obviously malicious input
    if "\x00" in path:
        raise ValueError("Path contains null bytes")

    for base, base_resolved in zip(_ALLOWED_BASES, _ALLOWED_BASES_RESOLVED):
        candidate = (base / p).resolve()
        # Normalize and verify path stays within allowed base (CodeQL sanitizer)
        safe_path = os.path.normpath(str(candidate))
        safe_base = os.path.normpath(str(base_resolved))
        if not (safe_path == safe_base or safe_path.startswith(safe_base + os.sep)):
            continue
        if os.path.isfile(safe_path):
            return Path(safe_path)

    raise FileNotFoundError(
        f"Profile not found: {path}. "
        f"Searched: repo root, test-profiles/, extended-test-profiles/, "
        f"xif/, fuzz/graphics/icc/"
    )


def _require_binary(bin_path: Path, name: str) -> None:
    safe = os.path.normpath(str(bin_path))
    if not os.path.isfile(safe):
        raise FileNotFoundError(
            f"{name} not found at {bin_path}. "
            f"Build it first (see docstring)."
        )


async def _run(cmd: list[str], timeout: int = 60) -> str:
    """Run a command and return combined stdout+stderr.

    Enforces output size limit (MAX_OUTPUT_BYTES) and proper process cleanup.
    Uses a minimal subprocess environment to reduce attack surface.
    """
    # Minimal env: only what the binaries need to locate libraries and run
    _default_path = (
        os.defpath if os.defpath else
        "C:\\Windows\\system32;C:\\Windows" if sys.platform == "win32"
        else "/usr/bin:/bin"
    )
    env = {
        "PATH": os.environ.get("PATH", _default_path),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "ASAN_OPTIONS": "detect_leaks=0",
        "MallocNanoZone": "0",
        "GCOV_PREFIX": "/dev/null",
    }
    if sys.platform != "win32":
        env["HOME"] = "/nonexistent"
    else:
        env["USERPROFILE"] = os.environ.get("USERPROFILE", "C:\\Users\\Default")
    # LD_LIBRARY_PATH needed if iccDEV was built as shared libs
    ld_path = os.environ.get("LD_LIBRARY_PATH")
    if ld_path:
        env["LD_LIBRARY_PATH"] = ld_path

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return f"[TIMEOUT after {timeout}s]"
    except asyncio.CancelledError:
        proc.kill()
        await proc.wait()
        raise

    # Enforce output size limit
    if len(stdout) > MAX_OUTPUT_BYTES:
        stdout = stdout[:MAX_OUTPUT_BYTES]
        truncated = True
    else:
        truncated = False

    output = stdout.decode(errors="replace")
    if stderr:
        stderr_text = stderr.decode(errors="replace")
        # Filter out gcov/gcda profiling noise from --coverage builds
        stderr_text = "\n".join(
            line for line in stderr_text.splitlines()
            if not line.startswith("profiling:")
        )
        if stderr_text.strip():
            remaining = MAX_OUTPUT_BYTES - len(stdout)
            if remaining > 0:
                stderr_encoded = stderr_text.encode("utf-8")
                if len(stderr_encoded) > remaining:
                    stderr_text = stderr_encoded[:remaining].decode("utf-8", errors="ignore")
                    truncated = True
            else:
                stderr_text = ""
                truncated = True
            output += "\n--- stderr ---\n" + stderr_text
    if truncated:
        output += "\n[OUTPUT TRUNCATED at 10MB]"
    return _sanitize_output(output.strip())


@mcp.tool()
async def inspect_profile(path: str) -> str:
    """Inspect an ICC profile's header, tag table, and structure.

    Uses ninja-full mode for complete structural dump without truncation.

    Args:
        path: Path to .icc file (absolute, or filename to search in test-profiles/)
    """
    _require_binary(ANALYZER_BIN, "iccanalyzer-lite")
    profile = _resolve_profile(path)
    return await _run([str(ANALYZER_BIN), "-nf", str(profile)])


@mcp.tool()
async def analyze_security(path: str) -> str:
    """Run 19-phase security heuristic analysis on an ICC profile.

    Detects: fingerprint matches, tag anomalies, overflow indicators,
    malformed signatures, fuzzing vectors, memory safety issues, and more.

    Args:
        path: Path to .icc file
    """
    _require_binary(ANALYZER_BIN, "iccanalyzer-lite")
    profile = _resolve_profile(path)
    return await _run([str(ANALYZER_BIN), "-h", str(profile)])


@mcp.tool()
async def validate_roundtrip(path: str) -> str:
    """Validate bidirectional transform support (AToB/BToA, DToB/BToD, Matrix/TRC).

    Args:
        path: Path to .icc file
    """
    _require_binary(ANALYZER_BIN, "iccanalyzer-lite")
    profile = _resolve_profile(path)
    return await _run([str(ANALYZER_BIN), "-r", str(profile)])


@mcp.tool()
async def full_analysis(path: str) -> str:
    """Run comprehensive analysis combining security, validation, and metadata.

    This is the most thorough mode — combines heuristics, round-trip, and inspection.

    Args:
        path: Path to .icc file
    """
    _require_binary(ANALYZER_BIN, "iccanalyzer-lite")
    profile = _resolve_profile(path)
    return await _run([str(ANALYZER_BIN), "-a", str(profile)], timeout=120)


@mcp.tool()
async def profile_to_xml(path: str) -> str:
    """Convert an ICC profile to XML for human-readable inspection.

    Tries the safe iccToXml first; falls back to iccToXml_unsafe
    if the safe version is unavailable or fails (e.g. for malformed profiles).
    Output may be large for complex profiles.

    Args:
        path: Path to .icc file
    """
    profile = _resolve_profile(path)
    max_xml_chars = 50000

    fd, tmp_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    used_tool = "iccToXml"
    result = ""
    try:
        # Try safe iccToXml first
        success = False
        if TO_XML_SAFE_BIN.is_file() and os.access(TO_XML_SAFE_BIN, os.X_OK):
            try:
                result = await _run([str(TO_XML_SAFE_BIN), str(profile), tmp_path])
                xml_path = Path(tmp_path)
                if xml_path.exists() and xml_path.stat().st_size > 0:
                    success = True
            except Exception:
                success = False  # safe tool failed; fall through to unsafe

        # Fall back to iccToXml_unsafe
        if not success:
            _require_binary(TO_XML_UNSAFE_BIN, "iccToXml_unsafe")
            used_tool = "iccToXml_unsafe"
            Path(tmp_path).unlink(missing_ok=True)
            fd2, tmp_path2 = tempfile.mkstemp(suffix=".xml")
            os.close(fd2)
            tmp_path = tmp_path2
            result = await _run([str(TO_XML_UNSAFE_BIN), str(profile), tmp_path])

        xml_path = Path(tmp_path)
        if xml_path.exists() and xml_path.stat().st_size > 0:
            file_size = xml_path.stat().st_size
            with open(tmp_path, "r", errors="replace") as fh:
                content = fh.read(max_xml_chars + 1)
            content = _sanitize_output(content)
            header = f"[Converted with {used_tool}]\n\n"
            if len(content) > max_xml_chars:
                content = content[:max_xml_chars]
                return header + content + f"\n\n[TRUNCATED — full XML is ~{file_size:,} bytes]"
            return header + content
        return result or "[No XML output produced]"
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@mcp.tool()
async def compare_profiles(path_a: str, path_b: str) -> str:
    """Compare two ICC profiles side-by-side.

    Runs ninja-full inspection on both profiles and shows a unified diff
    of their structural dumps.

    Args:
        path_a: Path to first .icc file
        path_b: Path to second .icc file
    """
    _require_binary(ANALYZER_BIN, "iccanalyzer-lite")
    profile_a = _resolve_profile(path_a)
    profile_b = _resolve_profile(path_b)

    output_a, output_b = await asyncio.gather(
        _run([str(ANALYZER_BIN), "-nf", str(profile_a)]),
        _run([str(ANALYZER_BIN), "-nf", str(profile_b)]),
    )

    fd_a, fa_path = tempfile.mkstemp(suffix=".txt")
    fd_b = None
    fb_path = None
    try:
        fd_b, fb_path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd_a, "w") as fa:
            fa.write(output_a)
        fd_a = -1  # mark as consumed by fdopen
        with os.fdopen(fd_b, "w") as fb:
            fb.write(output_b)
        fd_b = -1  # mark as consumed by fdopen

        diff = await _run(
            ["diff", "-u",
             "--label", profile_a.name, fa_path,
             "--label", profile_b.name, fb_path],
            timeout=10,
        )
        return diff or "[Profiles are structurally identical]"
    finally:
        if fd_a >= 0:
            os.close(fd_a)
        if fd_b is not None and fd_b >= 0:
            os.close(fd_b)
        Path(fa_path).unlink(missing_ok=True)
        if fb_path:
            Path(fb_path).unlink(missing_ok=True)


@mcp.tool()
async def list_test_profiles(directory: str = "test-profiles") -> str:
    """List available ICC test profiles.

    Args:
        directory: Which profile set — "test-profiles", "extended-test-profiles",
                   "xif", or "fuzz/graphics/icc"
    """
    dirs = {
        "test-profiles": TEST_PROFILES,
        "extended-test-profiles": EXTENDED_PROFILES,
        "xif": XIF_DIR,
        "fuzz/graphics/icc": FUZZ_ICC_DIR,
    }
    target = dirs.get(directory)
    if not target:
        return f"Unknown directory. Choose from: {', '.join(dirs.keys())}"
    if not target.exists():
        return f"{directory}/ directory not found"

    files = sorted(target.iterdir())
    icc_files = [f for f in files if f.suffix.lower() in (".icc", ".icm", ".iccp") or not f.suffix]
    lines = []
    for f in icc_files:
        try:
            if f.is_file():
                lines.append(f"{f.name}  ({f.stat().st_size:,} bytes)")
        except OSError:
            continue
    header = f"{directory}/ — {len(lines)} profiles:\n"
    return header + "\n".join(lines)


def _get_upload_dir() -> Path:
    """Return (and lazily create) a secure temp directory for uploaded profiles."""
    global _UPLOAD_DIR
    if _UPLOAD_DIR is None or not _UPLOAD_DIR.is_dir():
        _UPLOAD_DIR = Path(tempfile.mkdtemp(prefix="mcp_uploads_"))
        _UPLOAD_DIR.chmod(0o700)
        register_allowed_base(_UPLOAD_DIR)
    return _UPLOAD_DIR


@mcp.tool()
async def upload_and_analyze(
    data_base64: str,
    filename: str = "uploaded.icc",
    mode: str = "security",
) -> str:
    """Upload an ICC profile (base64-encoded) and run analysis on it.

    Accepts a base64-encoded ICC profile, saves it to a secure temp directory,
    and runs the requested analysis mode. The file is cleaned up after analysis.

    Args:
        data_base64: Base64-encoded ICC profile data
        filename: Original filename (used for display, sanitized before use)
        mode: Analysis mode — "security" (default), "inspect", "roundtrip",
              "full", "xml", or "all" (runs security + inspect + roundtrip)
    """
    # Decode and validate
    try:
        raw = base64.b64decode(data_base64, validate=True)
    except Exception:
        return "[FAIL] Invalid base64 data. Encode the ICC file with: base64 < profile.icc"

    if len(raw) < 128:
        return "[FAIL] Data too small to be a valid ICC profile (min 128 bytes for header)"
    if len(raw) > MAX_UPLOAD_BYTES:
        return f"[FAIL] Profile too large ({len(raw):,} bytes, max {MAX_UPLOAD_BYTES:,})"

    # Sanitize filename
    safe_name = re.sub(r"[^\w.\-]", "_", os.path.basename(filename))
    if not safe_name or safe_name.startswith("."):
        safe_name = "uploaded.icc"
    if not safe_name.lower().endswith((".icc", ".icm", ".iccp")):
        safe_name += ".icc"

    # Write to secure temp dir
    upload_dir = _get_upload_dir()
    prefix = hashlib.sha256(raw[:256]).hexdigest()[:12]
    dest = upload_dir / f"{prefix}_{safe_name}"
    dest.write_bytes(raw)

    try:
        _require_binary(ANALYZER_BIN, "iccanalyzer-lite")
        profile_path = str(dest)

        modes = {
            "security": ["-h"],
            "inspect": ["-nf"],
            "roundtrip": ["-r"],
            "full": ["-a"],
        }

        if mode == "xml":
            result = await profile_to_xml(profile_path)
            return f"[OK] Uploaded: {safe_name} ({len(raw):,} bytes)\n\n{result}"

        if mode == "all":
            parts = [f"[OK] Uploaded: {safe_name} ({len(raw):,} bytes)"]
            for m_name, m_flags in [("security", ["-h"]), ("inspect", ["-nf"]), ("roundtrip", ["-r"])]:
                out = await _run([str(ANALYZER_BIN)] + m_flags + [profile_path])
                parts.append(f"\n{'='*70}\n  {m_name.upper()} MODE ({' '.join(m_flags)})\n{'='*70}\n{out}")
            return "\n".join(parts)

        flags = modes.get(mode)
        if not flags:
            return f"[FAIL] Unknown mode '{mode}'. Choose: security, inspect, roundtrip, full, xml, all"

        result = await _run([str(ANALYZER_BIN)] + flags + [profile_path], timeout=120)
        return f"[OK] Uploaded: {safe_name} ({len(raw):,} bytes)\n\n{result}"
    finally:
        dest.unlink(missing_ok=True)


@mcp.tool()
async def build_tools(target: str = "all") -> str:
    """Build the native analysis tools required by this MCP server.

    Builds iccanalyzer-lite and/or colorbleed_tools from source using their
    respective build scripts. Requires clang/clang++ and system dependencies.

    For more control over cmake configuration (build types, sanitizers,
    ENABLE_TOOLS), use cmake_configure + cmake_build instead. For generating
    ICC test profiles, use create_all_profiles. For running the iccDEV test
    suite, use run_iccdev_tests.

    Args:
        target: What to build — "all", "iccanalyzer-lite", or "colorbleed_tools"
    """
    targets = {
        "iccanalyzer-lite": ("iccanalyzer-lite", "./build.sh"),
        "colorbleed_tools": ("colorbleed_tools", "make setup && make"),
    }

    if target == "all":
        build_list = list(targets.items())
    elif target in targets:
        build_list = [(target, targets[target])]
    else:
        return f"Unknown target '{target}'. Choose: all, iccanalyzer-lite, colorbleed_tools"

    results = []
    for name, (subdir, _) in build_list:
        build_dir = REPO_ROOT / subdir
        if not build_dir.is_dir():
            results.append(f"[FAIL] {name}: directory not found at {build_dir}")
            continue

        if name == "colorbleed_tools":
            # Two-step: make setup && make
            setup_out = await _run_build(
                ["make", "setup"], cwd=str(build_dir), timeout=120
            )
            build_out = await _run_build(
                ["make"], cwd=str(build_dir), timeout=120
            )
            output = setup_out + "\n" + build_out
        else:
            output = await _run_build(
                ["bash", "./build.sh"], cwd=str(build_dir), timeout=300
            )

        # Check for build artifacts
        if name == "iccanalyzer-lite":
            binary = build_dir / "iccanalyzer-lite"
            if binary.is_file():
                results.append(f"[OK] {name}: built successfully ({binary})")
            else:
                results.append(f"[FAIL] {name}: binary not found after build\n{output}")
        elif name == "colorbleed_tools":
            bins = [build_dir / b for b in ("iccToXml_unsafe", "iccFromXml_unsafe")]
            found = [b.name for b in bins if b.is_file()]
            if found:
                results.append(f"[OK] {name}: built {', '.join(found)}")
            else:
                results.append(f"[FAIL] {name}: no binaries found after build\n{output}")

    return "\n".join(results)


async def _run_build(cmd: list[str], cwd: str, timeout: int = 300) -> str:
    """Run a build command in a specified working directory.

    Unlike _run(), inherits the full environment (needed for build tools)
    but still sanitizes output.
    """
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    env["MallocNanoZone"] = "0"
    env["GCOV_PREFIX"] = "/dev/null"

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=cwd,
        env=env,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return f"[TIMEOUT after {timeout}s]"

    output = stdout.decode(errors="replace")
    if len(output) > MAX_OUTPUT_BYTES:
        output = output[:MAX_OUTPUT_BYTES] + "\n[OUTPUT TRUNCATED at 10MB]"
    return _sanitize_output(output.strip())


# ── Helpers for cmake / iccDEV maintainer tools ─────────────────────

# Allowed cmake arg patterns — reject shell metacharacters
_CMAKE_ARG_RE = re.compile(r"^-D[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_.+\-]*$")
_CMAKE_FLAG_RE = re.compile(r"^-W[a-z\-]+$")

_VALID_BUILD_TYPES = {"Debug", "Release", "RelWithDebInfo", "MinSizeRel"}
_VALID_SANITIZERS = {"none", "asan", "ubsan", "asan+ubsan", "coverage"}
_VALID_COMPILERS = {"clang", "gcc"}
_VALID_GENERATORS = {"default", "Ninja", "Xcode", "Unix Makefiles"}
_VALID_VCPKG_SOURCES = {"release", "local"}

# Known cmake option toggles from iccDEV CMakeLists.txt (all ON/OFF booleans)
_VALID_CMAKE_OPTIONS = {
    "ENABLE_TOOLS", "ENABLE_TESTS", "ENABLE_ICCXML",
    "ENABLE_STATIC_LIBS", "ENABLE_SHARED_LIBS",
    "ENABLE_COVERAGE", "ENABLE_FUZZING",
    "ENABLE_ASAN", "ENABLE_UBSAN", "ENABLE_TSAN", "ENABLE_MSAN", "ENABLE_LSAN",
    "ICC_LOG_SAFE", "ICC_TRACE_NAN_ENABLED", "ICC_CLUT_DEBUG", "ICC_ENABLE_ASSERTS",
}


def _sanitize_cmake_args(raw: str) -> list[str]:
    """Parse and validate extra cmake arguments.

    Only allows -DVAR=VALUE and -Wflag patterns to prevent injection.
    """
    if not raw or not raw.strip():
        return []
    args = []
    for token in raw.split():
        if _CMAKE_ARG_RE.match(token) or _CMAKE_FLAG_RE.match(token):
            args.append(token)
        else:
            raise ValueError(
                f"Rejected cmake arg: '{token}'. "
                f"Only -DVAR=VALUE and -Wflag patterns are allowed."
            )
    return args


def _resolve_iccdev_dir() -> Path:
    """Locate the iccDEV source tree."""
    if ICCDEV_DIR.is_dir():
        return ICCDEV_DIR
    raise FileNotFoundError(
        f"iccDEV not found at {ICCDEV_DIR}. "
        f"Clone it first: git clone https://github.com/InternationalColorConsortium/iccDEV.git {ICCDEV_DIR}"
    )


def _resolve_build_dir(build_dir: str) -> Path:
    """Resolve and validate a build directory name under iccDEV/Build/.

    Security: prevents path traversal out of iccDEV/Build/.
    """
    iccdev = _resolve_iccdev_dir()
    base = iccdev / "Build"

    # Sanitize: only allow simple directory names
    clean = re.sub(r"[^\w.\-]", "_", build_dir)
    if not clean or clean.startswith("."):
        clean = "build-mcp"

    target = (base / clean).resolve()
    safe_base = base.resolve()
    if not (str(target) == str(safe_base) or str(target).startswith(str(safe_base) + os.sep)):
        raise ValueError(f"Build directory escapes iccDEV/Build/: {build_dir}")

    return target


def _find_iccdev_tools(build_dir: Path) -> list[str]:
    """Find executable tool directories under a build directory."""
    tool_dirs: list[str] = []
    if not build_dir.is_dir():
        return tool_dirs
    for root, dirs, files in os.walk(str(build_dir)):
        if "Tools" in root:
            for f in files:
                fp = os.path.join(root, f)
                if os.access(fp, os.X_OK):
                    d = os.path.dirname(fp)
                    if d not in tool_dirs:
                        tool_dirs.append(d)
    return tool_dirs


def _build_tool_path(build_dir: Path) -> str:
    """Construct a PATH string with iccDEV tool directories prepended."""
    tool_dirs = _find_iccdev_tools(build_dir)
    base_path = os.environ.get("PATH", os.defpath or "/usr/bin:/bin")
    if tool_dirs:
        return os.pathsep.join(tool_dirs) + os.pathsep + base_path
    return base_path


def _patch_iccdev_source(iccdev: Path) -> list[str]:
    """Apply known source patches to iccDEV tree.

    1. Strip stray U+FE0F (emoji variation selector) from IccSignatureUtils.h
    2. Patch out wxWidgets find_package if wx libs are not available

    Returns list of patches applied.
    """
    patches: list[str] = []

    # Strip U+FE0F from IccSignatureUtils.h (upstream bug, all workflows patch this)
    sig_utils = iccdev / "IccProfLib" / "IccSignatureUtils.h"
    if sig_utils.is_file():
        content = sig_utils.read_bytes()
        # U+FE0F = UTF-8 bytes \xef\xb8\x8f
        if b"\xef\xb8\x8f" in content:
            cleaned = content.replace(b"\xef\xb8\x8f", b"")
            sig_utils.write_bytes(cleaned)
            patches.append("Stripped U+FE0F from IccSignatureUtils.h")

    # Patch out wxWidgets if not available (prevents cmake configure failure)
    cmake_file = iccdev / "Build" / "Cmake" / "CMakeLists.txt"
    if cmake_file.is_file() and not shutil.which("wx-config"):
        content = cmake_file.read_text(errors="replace")
        modified = False
        for pattern in [
            "find_package(wxWidgets",
            "ADD_SUBDIRECTORY(Tools/wxProfileDump)",
        ]:
            uncommented = f"  {pattern}"
            commented = f"#  {pattern}"
            if uncommented in content and commented not in content:
                content = content.replace(uncommented, commented)
                modified = True
        if modified:
            cmake_file.write_text(content)
            patches.append("Patched out wxWidgets (not installed)")

    return patches


@mcp.tool()
async def cmake_configure(
    build_type: str = "Debug",
    enable_tools: bool = False,
    sanitizers: str = "asan+ubsan",
    compiler: str = "clang",
    generator: str = "default",
    extra_cmake_args: str = "",
    build_dir: str = "",
) -> str:
    """Configure iccDEV with cmake, allowing build type, sanitizer, and tool selection.

    This is for maintainers who need different build configurations — e.g.,
    Release builds, coverage instrumentation, or ENABLE_TOOLS=ON to run
    CreateAllProfiles.sh and the iccDEV test suite.

    Cross-platform: supports Unix Makefiles (Linux), Xcode (macOS), and
    Ninja generators. Use cmake_build after this to compile.

    Args:
        build_type: CMake build type — "Debug" (default), "Release",
                    "RelWithDebInfo", or "MinSizeRel"
        enable_tools: Build iccDEV CLI tools (iccFromXml, iccApplyProfiles,
                      iccDumpProfile, etc.). Required for CreateAllProfiles.sh
        sanitizers: Sanitizer config — "asan+ubsan" (default), "asan", "ubsan",
                    "coverage", or "none"
        compiler: Compiler family — "clang" (default) or "gcc"
        generator: CMake generator — "default" (auto-detect), "Ninja",
                   "Xcode" (macOS), or "Unix Makefiles"
        extra_cmake_args: Additional cmake -D flags (e.g. "-DICC_LOG_SAFE=ON")
        build_dir: Name for build directory under iccDEV/Build/
                   (default: auto-generated from settings)
    """
    if build_type not in _VALID_BUILD_TYPES:
        return f"[FAIL] Invalid build_type '{build_type}'. Choose: {', '.join(sorted(_VALID_BUILD_TYPES))}"
    if sanitizers not in _VALID_SANITIZERS:
        return f"[FAIL] Invalid sanitizers '{sanitizers}'. Choose: {', '.join(sorted(_VALID_SANITIZERS))}"
    if compiler not in _VALID_COMPILERS:
        return f"[FAIL] Invalid compiler '{compiler}'. Choose: {', '.join(sorted(_VALID_COMPILERS))}"
    if generator not in _VALID_GENERATORS:
        return f"[FAIL] Invalid generator '{generator}'. Choose: {', '.join(sorted(_VALID_GENERATORS))}"

    try:
        extra = _sanitize_cmake_args(extra_cmake_args)
    except ValueError as e:
        return f"[FAIL] {e}"

    try:
        iccdev = _resolve_iccdev_dir()
    except FileNotFoundError as e:
        return f"[FAIL] {e}"

    # Auto-patch source tree (U+FE0F strip, wxWidgets)
    patches = _patch_iccdev_source(iccdev)

    # Auto-generate build dir name if not specified
    if not build_dir:
        parts = [f"build-{build_type.lower()}"]
        if sanitizers != "none":
            parts.append(sanitizers.replace("+", "-"))
        if enable_tools:
            parts.append("tools")
        build_dir = "-".join(parts)

    try:
        target_dir = _resolve_build_dir(build_dir)
    except (FileNotFoundError, ValueError) as e:
        return f"[FAIL] {e}"
    target_dir.mkdir(parents=True, exist_ok=True)

    # Resolve compiler
    if compiler == "clang":
        cxx = "clang++"
        for suffix in ("", "-18", "-17", "-16"):
            if shutil.which(f"clang++{suffix}"):
                cxx = f"clang++{suffix}"
                break
        cc = cxx.replace("++", "")
    else:
        cxx = "g++"
        cc = "gcc"

    # Build cmake command
    cmd = [
        "cmake", str(iccdev / "Build" / "Cmake"),
        f"-DCMAKE_BUILD_TYPE={build_type}",
        f"-DCMAKE_C_COMPILER={cc}",
        f"-DCMAKE_CXX_COMPILER={cxx}",
        f"-DENABLE_TOOLS={'ON' if enable_tools else 'OFF'}",
        "-DENABLE_STATIC_LIBS=ON",
        "-Wno-dev",
    ]

    # Generator selection
    if generator != "default":
        cmd.extend(["-G", generator])

    # Use iccDEV native cmake sanitizer options + raw compiler flags
    c_flags = []
    linker_flags = []
    if sanitizers == "asan+ubsan":
        cmd.extend(["-DENABLE_ASAN=ON", "-DENABLE_UBSAN=ON"])
        c_flags = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-O1"]
        linker_flags = ["-fsanitize=address,undefined"]
    elif sanitizers == "asan":
        cmd.append("-DENABLE_ASAN=ON")
        c_flags = ["-fsanitize=address", "-fno-omit-frame-pointer", "-g", "-O1"]
        linker_flags = ["-fsanitize=address"]
    elif sanitizers == "ubsan":
        cmd.append("-DENABLE_UBSAN=ON")
        c_flags = ["-fsanitize=undefined", "-fno-omit-frame-pointer", "-g", "-O1"]
        linker_flags = ["-fsanitize=undefined"]
    elif sanitizers == "coverage":
        cmd.append("-DENABLE_COVERAGE=ON")
        c_flags = ["-fprofile-instr-generate", "-fcoverage-mapping"]
        linker_flags = ["-fprofile-instr-generate"]

    if c_flags:
        flags_str = " ".join(c_flags)
        cmd.append(f"-DCMAKE_C_FLAGS={flags_str}")
        cmd.append(f"-DCMAKE_CXX_FLAGS={flags_str} -std=c++17")
    if linker_flags:
        link_str = " ".join(linker_flags)
        cmd.append(f"-DCMAKE_EXE_LINKER_FLAGS={link_str}")

    cmd.extend(extra)

    # Summary header
    patch_str = "; ".join(patches) if patches else "(none needed)"
    summary = (
        f"[INFO] cmake configure\n"
        f"  Build type:    {build_type}\n"
        f"  Sanitizers:    {sanitizers}\n"
        f"  Compiler:      {cc} / {cxx}\n"
        f"  Generator:     {generator}\n"
        f"  Enable tools:  {enable_tools}\n"
        f"  Build dir:     {target_dir}\n"
        f"  Extra args:    {extra_cmake_args or '(none)'}\n"
        f"  Source patches: {patch_str}\n"
    )

    output = await _run_build(cmd, cwd=str(target_dir), timeout=120)

    # Check for CMake success indicators
    if "Generating done" in output or "Build files have been written" in output:
        return summary + f"\n[OK] cmake configured successfully\n\n{output}"
    return summary + f"\n[WARN] cmake may have failed — check output:\n\n{output}"


@mcp.tool()
async def cmake_build(
    build_dir: str = "",
    target: str = "",
    jobs: int = 0,
) -> str:
    """Build iccDEV in a previously configured build directory.

    Uses cmake --build for cross-platform support (Unix Makefiles, Ninja,
    Xcode, etc.). Run cmake_configure first to set up the build directory.

    Args:
        build_dir: Build directory name under iccDEV/Build/
                   (e.g. "build-debug-asan-ubsan-tools")
        target: Build target (default: all)
        jobs: Parallel jobs (default: nproc)
    """
    if not build_dir:
        return (
            "[FAIL] build_dir is required. Run cmake_configure first to create one.\n"
            "Example: cmake_configure(enable_tools=True) creates 'build-debug-asan-ubsan-tools'"
        )

    try:
        target_dir = _resolve_build_dir(build_dir)
    except (FileNotFoundError, ValueError) as e:
        return f"[FAIL] {e}"
    if not (target_dir / "CMakeCache.txt").is_file():
        return (
            f"[FAIL] {target_dir} has no CMakeCache.txt — run cmake_configure first.\n"
            f"Example: cmake_configure(build_dir='{build_dir}')"
        )

    import multiprocessing
    if jobs <= 0:
        jobs = multiprocessing.cpu_count()

    # Use cmake --build for cross-platform support (works with all generators)
    cmd = ["cmake", "--build", str(target_dir), "--parallel", str(jobs)]
    if target:
        cmd.extend(["--target", target])

    output = await _run_build(cmd, cwd=str(target_dir), timeout=600)

    # Inventory built tools
    tools = _find_iccdev_tools(target_dir)
    tool_bins: list[str] = []
    for d in tools:
        for f in os.listdir(d):
            fp = os.path.join(d, f)
            if os.access(fp, os.X_OK) and os.path.isfile(fp):
                tool_bins.append(f)

    summary = f"[INFO] cmake --build (parallel={jobs}) in {target_dir.name}\n"
    if tool_bins:
        summary += f"  Tools built: {', '.join(sorted(set(tool_bins)))}\n"
    else:
        summary += "  Tools: none (ENABLE_TOOLS was OFF?)\n"

    # Check for errors
    if "Error" in output and ("make" in output or "FAILED" in output or "error" in output.lower()):
        return summary + f"\n[FAIL] Build errors detected:\n\n{output}"
    return summary + f"\n[OK] Build complete\n\n{output}"


@mcp.tool()
async def create_all_profiles(build_dir: str = "") -> str:
    """Run iccDEV's CreateAllProfiles.sh to generate the full ICC profile corpus.

    Requires a build with enable_tools=True. The script uses iccDEV CLI tools
    (iccFromXml, iccApplyProfiles, etc.) to create ~80+ ICC profiles from XML
    specifications in the Testing/ directory.

    Args:
        build_dir: Build directory name under iccDEV/Build/ that was configured
                   with enable_tools=True
    """
    if not build_dir:
        return (
            "[FAIL] build_dir is required. First run:\n"
            "  1. cmake_configure(enable_tools=True)\n"
            "  2. cmake_build(build_dir='...')\n"
            "  3. create_all_profiles(build_dir='...')"
        )

    try:
        iccdev = _resolve_iccdev_dir()
        target_dir = _resolve_build_dir(build_dir)
    except (FileNotFoundError, ValueError) as e:
        return f"[FAIL] {e}"
    testing_dir = iccdev / "Testing"
    script = testing_dir / "CreateAllProfiles.sh"

    if not script.is_file():
        return f"[FAIL] CreateAllProfiles.sh not found at {script}"

    tools = _find_iccdev_tools(target_dir)
    if not tools:
        return (
            f"[FAIL] No tools found in {target_dir}. "
            f"Build with enable_tools=True first:\n"
            f"  cmake_configure(enable_tools=True, build_dir='{build_dir}')\n"
            f"  cmake_build(build_dir='{build_dir}')"
        )

    # Set up environment with tools on PATH
    env = os.environ.copy()
    env["PATH"] = _build_tool_path(target_dir)
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    env["MallocNanoZone"] = "0"
    env["GCOV_PREFIX"] = "/dev/null"

    # Count profiles before
    before_count = len(list(testing_dir.glob("**/*.icc")))

    proc = await asyncio.create_subprocess_exec(
        "bash", str(script),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(testing_dir),
        env=env,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return "[TIMEOUT] CreateAllProfiles.sh exceeded 300s"

    output = stdout.decode(errors="replace")
    if len(output) > MAX_OUTPUT_BYTES:
        output = output[:MAX_OUTPUT_BYTES] + "\n[OUTPUT TRUNCATED at 10MB]"
    output = _sanitize_output(output.strip())

    # Count profiles after
    after_profiles = sorted(testing_dir.glob("**/*.icc"))
    after_count = len(after_profiles)
    new_count = after_count - before_count

    summary = (
        f"[INFO] CreateAllProfiles.sh completed (exit code {proc.returncode})\n"
        f"  Profiles before: {before_count}\n"
        f"  Profiles after:  {after_count}\n"
        f"  New profiles:    {new_count}\n"
        f"  Testing dir:     {testing_dir}\n"
    )

    # List generated profiles (last 20 lines for brevity)
    if after_profiles:
        profile_list = "\n".join(
            f"  {p.relative_to(testing_dir)}  ({p.stat().st_size:,} bytes)"
            for p in after_profiles[:50]
        )
        if after_count > 50:
            profile_list += f"\n  ... and {after_count - 50} more"
        summary += f"\nGenerated profiles:\n{profile_list}\n"

    if proc.returncode == 0:
        return summary + f"\n[OK] Profile generation complete\n\n{output}"
    return summary + f"\n[WARN] Script exited with code {proc.returncode}\n\n{output}"


@mcp.tool()
async def run_iccdev_tests(build_dir: str = "") -> str:
    """Run iccDEV's RunTests.sh test suite against generated profiles.

    Requires a build with enable_tools=True and profiles from
    create_all_profiles(). Tests validate round-trip fidelity,
    profile application, and tool interoperability.

    Args:
        build_dir: Build directory name under iccDEV/Build/ that was configured
                   with enable_tools=True
    """
    if not build_dir:
        return (
            "[FAIL] build_dir is required. First run:\n"
            "  1. cmake_configure(enable_tools=True)\n"
            "  2. cmake_build(build_dir='...')\n"
            "  3. create_all_profiles(build_dir='...')\n"
            "  4. run_iccdev_tests(build_dir='...')"
        )

    try:
        iccdev = _resolve_iccdev_dir()
        target_dir = _resolve_build_dir(build_dir)
    except (FileNotFoundError, ValueError) as e:
        return f"[FAIL] {e}"
    testing_dir = iccdev / "Testing"
    script = testing_dir / "RunTests.sh"

    if not script.is_file():
        return f"[FAIL] RunTests.sh not found at {script}"

    tools = _find_iccdev_tools(target_dir)
    if not tools:
        return (
            f"[FAIL] No tools found in {target_dir}. "
            f"Build with enable_tools=True first."
        )

    env = os.environ.copy()
    env["PATH"] = _build_tool_path(target_dir)
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    env["MallocNanoZone"] = "0"
    env["GCOV_PREFIX"] = "/dev/null"

    proc = await asyncio.create_subprocess_exec(
        "bash", str(script),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(testing_dir),
        env=env,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return "[TIMEOUT] RunTests.sh exceeded 300s"

    output = stdout.decode(errors="replace")
    if len(output) > MAX_OUTPUT_BYTES:
        output = output[:MAX_OUTPUT_BYTES] + "\n[OUTPUT TRUNCATED at 10MB]"
    output = _sanitize_output(output.strip())

    # Parse pass/fail from output
    pass_count = output.lower().count("pass")
    fail_count = output.lower().count("fail")

    summary = (
        f"[INFO] RunTests.sh completed (exit code {proc.returncode})\n"
        f"  Build dir:  {target_dir}\n"
    )
    if pass_count or fail_count:
        summary += f"  Matches:    ~{pass_count} pass, ~{fail_count} fail (approximate from output)\n"

    if proc.returncode == 0:
        return summary + f"\n[OK] Tests passed\n\n{output}"
    return summary + f"\n[WARN] Tests exited with code {proc.returncode}\n\n{output}"


@mcp.tool()
async def cmake_option_matrix(
    options: str = "ENABLE_COVERAGE,ICC_ENABLE_ASSERTS,ICC_TRACE_NAN_ENABLED",
    build_type: str = "Release",
    compiler: str = "clang",
) -> str:
    """Run a build-option matrix: configure+build iccDEV once per cmake option toggle.

    Tests each cmake boolean option independently to verify it compiles.
    Useful for maintainers validating that all cmake options still build cleanly.

    Args:
        options: Comma-separated cmake option names from CMakeLists.txt.
                 Each is tested as -DOPTION=ON in its own build directory.
                 Valid options: ENABLE_COVERAGE, ICC_ENABLE_ASSERTS,
                 ICC_TRACE_NAN_ENABLED, ENABLE_SHARED_LIBS, ENABLE_STATIC_LIBS,
                 ENABLE_TOOLS, ENABLE_TESTS, ENABLE_ICCXML, ICC_LOG_SAFE, etc.
        build_type: CMake build type for all builds (default: "Release")
        compiler: Compiler family (default: "clang")
    """
    if build_type not in _VALID_BUILD_TYPES:
        return f"[FAIL] Invalid build_type '{build_type}'. Choose: {', '.join(sorted(_VALID_BUILD_TYPES))}"
    if compiler not in _VALID_COMPILERS:
        return f"[FAIL] Invalid compiler '{compiler}'. Choose: {', '.join(sorted(_VALID_COMPILERS))}"

    opt_list = [o.strip() for o in options.split(",") if o.strip()]
    if not opt_list:
        return "[FAIL] No options specified"
    if len(opt_list) > 10:
        return "[FAIL] Too many options (max 10 per matrix call)"

    invalid = [o for o in opt_list if o not in _VALID_CMAKE_OPTIONS]
    if invalid:
        return (
            f"[FAIL] Unknown cmake options: {', '.join(invalid)}. "
            f"Valid: {', '.join(sorted(_VALID_CMAKE_OPTIONS))}"
        )

    try:
        iccdev = _resolve_iccdev_dir()
    except FileNotFoundError as e:
        return f"[FAIL] {e}"

    _patch_iccdev_source(iccdev)

    if compiler == "clang":
        cxx = "clang++"
        for suffix in ("", "-18", "-17", "-16"):
            if shutil.which(f"clang++{suffix}"):
                cxx = f"clang++{suffix}"
                break
        cc = cxx.replace("++", "")
    else:
        cc, cxx = "gcc", "g++"

    results: list[str] = []
    cmake_dir = str(iccdev / "Build" / "Cmake")

    for opt in opt_list:
        dir_name = f"build-opt-{opt.lower()}"
        try:
            target_dir = _resolve_build_dir(dir_name)
        except (FileNotFoundError, ValueError) as e:
            results.append(f"[FAIL] {opt}: {e}")
            continue
        target_dir.mkdir(parents=True, exist_ok=True)

        cmd_cfg = [
            "cmake", cmake_dir,
            f"-DCMAKE_BUILD_TYPE={build_type}",
            f"-DCMAKE_C_COMPILER={cc}",
            f"-DCMAKE_CXX_COMPILER={cxx}",
            f"-D{opt}=ON",
            "-Wno-dev",
        ]

        cfg_out = await _run_build(cmd_cfg, cwd=str(target_dir), timeout=120)
        if "[FAIL]" in cfg_out or "Error" in cfg_out:
            results.append(f"[FAIL] {opt}: configure failed\n{cfg_out[-200:]}")
            continue

        cmd_build = [
            "cmake", "--build", str(target_dir),
            "--parallel", str(min(os.cpu_count() or 2, 4)),
        ]
        build_out = await _run_build(cmd_build, cwd=str(target_dir), timeout=300)
        if "[FAIL]" in build_out:
            results.append(f"[FAIL] {opt}: build failed\n{build_out[-200:]}")
        else:
            results.append(f"[OK] {opt}")

    passed = sum(1 for r in results if r.startswith("[OK]"))
    failed = len(results) - passed
    header = f"[INFO] Option matrix: {passed}/{len(results)} passed, {failed} failed\n"
    header += f"  Build type: {build_type}, Compiler: {compiler}\n\n"
    return header + "\n".join(results)


@mcp.tool()
async def windows_build(
    build_type: str = "Debug",
    vcpkg_deps: str = "release",
    enable_tools: bool = True,
    extra_cmake_args: str = "",
    build_dir: str = "",
) -> str:
    """Configure and build iccDEV for Windows using MSVC and vcpkg dependencies.

    Downloads pre-built vcpkg dependencies from the iccDEV GitHub release,
    configures with the vcpkg toolchain file, and builds with MSBuild.

    This tool generates the correct cmake and build commands for Windows.
    On non-Windows hosts it produces a dry-run script for copy-paste execution.

    Args:
        build_type: CMake build type — "Debug" (default) or "Release"
        vcpkg_deps: Dependency source — "release" (download zip from
                    iccDEV v2.3.1 GitHub release) or "local" (assume
                    vcpkg deps already extracted)
        enable_tools: Build iccDEV CLI tools (default: True)
        extra_cmake_args: Additional cmake -D flags
        build_dir: Build directory name (default: auto-generated)
    """
    if build_type not in _VALID_BUILD_TYPES:
        return (
            f"[FAIL] Invalid build_type '{build_type}'. "
            f"Choose: {', '.join(sorted(_VALID_BUILD_TYPES))}"
        )
    if vcpkg_deps not in _VALID_VCPKG_SOURCES:
        return (
            f"[FAIL] Invalid vcpkg_deps '{vcpkg_deps}'. "
            f"Choose: {', '.join(sorted(_VALID_VCPKG_SOURCES))}"
        )

    try:
        extra = _sanitize_cmake_args(extra_cmake_args)
    except ValueError as e:
        return f"[FAIL] {e}"

    try:
        iccdev = _resolve_iccdev_dir()
    except FileNotFoundError as e:
        return f"[FAIL] {e}"

    # Auto-generate build dir name
    if not build_dir:
        build_dir = f"build-win-{build_type.lower()}"
        if enable_tools:
            build_dir += "-tools"

    try:
        target_dir = _resolve_build_dir(build_dir)
    except (FileNotFoundError, ValueError) as e:
        return f"[FAIL] {e}"

    cmake_dir = str(iccdev / "Build" / "Cmake")
    toolchain = str(iccdev / "scripts" / "buildsystems" / "vcpkg.cmake")

    # vcpkg download command
    vcpkg_url = (
        "https://github.com/InternationalColorConsortium/"
        "iccDEV/releases/download/v2.3.1/vcpkg-exported-deps.zip"
    )

    # Build cmake configure command
    cfg_args = [
        "cmake", cmake_dir,
        "-B", str(target_dir),
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
        "-DVCPKG_MANIFEST_MODE=OFF",
        f"-DCMAKE_BUILD_TYPE={build_type}",
        f"-DENABLE_TOOLS={'ON' if enable_tools else 'OFF'}",
        "-Wno-dev",
    ]
    cfg_args.extend(extra)

    build_args = [
        "cmake", "--build", str(target_dir),
        "--config", build_type,
        "--parallel",
    ]

    is_windows = sys.platform == "win32"

    summary = (
        f"[INFO] Windows build configuration\n"
        f"  Build type:    {build_type}\n"
        f"  Enable tools:  {enable_tools}\n"
        f"  vcpkg deps:    {vcpkg_deps}\n"
        f"  Build dir:     {target_dir.name}\n"
        f"  Platform:      {'native Windows' if is_windows else 'cross-platform script'}\n"
        f"  Extra args:    {extra_cmake_args or '(none)'}\n"
    )

    if not is_windows:
        # Generate a PowerShell script for Windows execution
        script_lines = [
            "# Windows build script for iccDEV (PowerShell)",
            "$ErrorActionPreference = 'Stop'",
            "",
        ]
        if vcpkg_deps == "release":
            script_lines.extend([
                "# Download vcpkg dependencies",
                f'Invoke-WebRequest -Uri "{vcpkg_url}" -OutFile "deps.zip"',
                'tar -xf deps.zip',
                "",
            ])
        script_lines.extend([
            "# Configure",
            " ".join(cfg_args).replace("/", "\\"),
            "",
            "# Build (run twice for MSBuild reliability)",
            " ".join(build_args),
            " ".join(build_args),
            "",
            "# Set PATH for tool discovery",
            (
                '$exeDirs = Get-ChildItem -Recurse -File -Include *.exe '
                f'-Path .\\{build_dir}\\ |'
            ),
            (
                '    Where-Object {{ $_.FullName -match "icc" -and '
                '$_.FullName -notmatch "\\\\CMakeFiles\\\\" }} |'
            ),
            '    ForEach-Object {{ Split-Path $_.FullName -Parent }} |',
            '    Sort-Object -Unique',
            '$env:PATH = ($exeDirs -join ";") + ";" + $env:PATH',
            "",
            "# Run profile creation",
            "cd Testing",
            ".\\CreateAllProfiles.bat",
        ])
        script = "\n".join(script_lines)
        return (
            summary
            + "\n[INFO] Not running on Windows. Generated PowerShell script:\n\n"
            + f"```powershell\n{script}\n```\n"
        )

    # Native Windows execution
    target_dir.mkdir(parents=True, exist_ok=True)

    results: list[str] = []

    # Step 1: Download vcpkg deps if requested
    if vcpkg_deps == "release":
        deps_zip = iccdev / "deps.zip"
        if not deps_zip.is_file():
            dl_cmd = [
                "powershell", "-Command",
                f'Invoke-WebRequest -Uri "{vcpkg_url}" '
                f'-OutFile "{deps_zip}"',
            ]
            dl_out = await _run_build(dl_cmd, cwd=str(iccdev), timeout=120)
            results.append(f"[INFO] vcpkg download: {dl_out[:200]}")

            extract_cmd = ["tar", "-xf", str(deps_zip), "-C", str(iccdev)]
            ex_out = await _run_build(extract_cmd, cwd=str(iccdev), timeout=60)
            results.append(f"[INFO] vcpkg extract: {ex_out[:200]}")

    # Step 2: Configure
    cfg_out = await _run_build(cfg_args, cwd=str(target_dir), timeout=180)
    if "Generating done" in cfg_out or "Build files have been written" in cfg_out:
        results.append("[OK] cmake configured")
    else:
        results.append(f"[WARN] cmake configure output:\n{cfg_out[-500:]}")

    # Step 3: Build (twice for MSBuild reliability)
    for attempt in (1, 2):
        build_out = await _run_build(build_args, cwd=str(target_dir), timeout=600)
        if "FAILED" in build_out or "Error" in build_out:
            results.append(
                f"[WARN] Build attempt {attempt}:\n{build_out[-300:]}"
            )
        else:
            results.append(f"[OK] Build attempt {attempt} complete")

    # Step 4: Find built tools
    tools = _find_iccdev_tools(target_dir)
    tool_bins: list[str] = []
    for d in tools:
        for f in os.listdir(d):
            fp = os.path.join(d, f)
            if os.path.isfile(fp) and (
                os.access(fp, os.X_OK) or fp.endswith(".exe")
            ):
                tool_bins.append(f)

    if tool_bins:
        results.append(
            f"[OK] Tools found: {', '.join(sorted(set(tool_bins)))}"
        )
    else:
        results.append("[WARN] No tool executables found")

    return summary + "\n" + "\n".join(results)


def run_server() -> None:
    """Entry point for console_scripts."""
    mcp.run()


if __name__ == "__main__":
    mcp.run()
