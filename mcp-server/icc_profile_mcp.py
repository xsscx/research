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
async def health_check() -> str:
    """Verify MCP server status and availability of analysis binaries.

    Returns a summary of server health: tool count, binary availability,
    and profile directory status.
    """
    lines = ["[ICC Profile MCP Server — Health Check]", ""]

    # Binary status
    analyzer_ok = ANALYZER_BIN.is_file() and os.access(ANALYZER_BIN, os.X_OK)
    xml_unsafe_ok = TO_XML_UNSAFE_BIN.is_file() and os.access(TO_XML_UNSAFE_BIN, os.X_OK)
    xml_safe_ok = TO_XML_SAFE_BIN.is_file() and os.access(TO_XML_SAFE_BIN, os.X_OK)

    lines.append("Binaries:")
    lines.append(f"  iccanalyzer-lite : {'[OK]' if analyzer_ok else '[MISSING]'}")
    lines.append(f"  iccToXml_unsafe  : {'[OK]' if xml_unsafe_ok else '[MISSING]'}")
    lines.append(f"  iccToXml (safe)  : {'[OK]' if xml_safe_ok else '[MISSING]'}")
    lines.append("")

    # Profile directory status
    test_count = sum(1 for f in TEST_PROFILES.iterdir()
                     if f.suffix.lower() in (".icc", ".icm", ".iccp")) if TEST_PROFILES.exists() else 0
    ext_count = sum(1 for f in EXTENDED_PROFILES.iterdir()
                    if f.suffix.lower() in (".icc", ".icm", ".iccp")) if EXTENDED_PROFILES.exists() else 0
    lines.append("Profile directories:")
    lines.append(f"  test-profiles/          : {test_count} profiles")
    lines.append(f"  extended-test-profiles/ : {ext_count} profiles")
    lines.append("")

    # Tool count (9 analysis tools + 7 maintainer + 6 operations = 22 tools)
    lines.append("Tools: 22 registered (9 analysis + 7 maintainer + 6 operations)")
    lines.append("")

    overall = "ok" if (analyzer_ok and xml_unsafe_ok) else "degraded"
    lines.append(f"Status: {overall}")

    return "\n".join(lines)


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
    """Run 115-heuristic security analysis on an ICC profile.

    Detects: fingerprint matches, tag anomalies, overflow indicators,
    malformed signatures, fuzzing vectors, memory safety issues,
    NaN/float-to-integer casts, AddXform ownership UAF patterns, and more.
    Covers 44+ CWE categories mapped from 77+ CVEs.

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


# ── Operations tools (from iccDEV shell helpers) ────────────────────


# Grep pattern categories for scan_logs (from Unix helpers)
_LOG_PATTERNS = {
    "errors": r"ERROR|WARN|WARNING|FAIL|FAILED|FATAL|ASSERT|ABORT|PANIC|EXCEPTION|CRASH|CORE|RUNTIME",
    "signals": r"SEGFAULT|SIG(SEGV|ABRT|BUS|ILL)",
    "invalid": r"INVALID|CORRUPT|MALFORMED|TRUNCATED|UNSUPPORTED|UNKNOWN|UNDEFINED",
    "overflow": r"OVERFLOW|UNDERFLOW|OUT OF RANGE",
    "memory": r"ALLOC|FREE|LEAK|OOM|OUT OF MEMORY|NULL",
    "hangs": r"TIMEOUT|DEADLOCK|HANG",
    "sanitizer": r"AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:|SCARINESS|LeakSanitizer",
}


@mcp.tool()
async def check_dependencies() -> str:
    """Check whether iccDEV build dependencies are installed on the current system.

    Detects the platform (Ubuntu/Debian, macOS, or Windows) and checks for
    required packages: cmake, compilers, libpng, libtiff, libxml2,
    nlohmann-json, wxwidgets, and more.

    Returns a table of dependency status with install commands for missing ones.
    """
    lines = ["[iccDEV Dependency Check]", ""]
    is_linux = sys.platform.startswith("linux")
    is_mac = sys.platform == "darwin"
    is_win = sys.platform == "win32"

    if is_linux:
        lines.append("Platform: Linux")
        # Check for apt-based distro
        has_apt = shutil.which("apt") is not None or shutil.which("dpkg") is not None
        if has_apt:
            lines.append("Package manager: apt (Debian/Ubuntu)")
            apt_pkgs = {
                "cmake": "cmake",
                "make": "make",
                "clang": "clang",
                "clang++": "clang",
                "g++": "g++",
                "git": "git",
                "curl": "curl",
                "xmllint": "libxml2-utils",
            }
            # Library checks via dpkg
            lib_pkgs = [
                "libpng-dev", "libjpeg-dev", "libtiff-dev",
                "libxml2-dev", "nlohmann-json3-dev",
                "build-essential", "clang-tools",
            ]
        else:
            lines.append("Package manager: unknown (not apt-based)")
            apt_pkgs = {}

        results: list[tuple[str, bool]] = []
        for binary, pkg in apt_pkgs.items():
            found = shutil.which(binary) is not None
            results.append((f"{binary} ({pkg})", found))

        if has_apt:
            # Check dpkg for library packages
            for pkg in lib_pkgs:
                proc = await asyncio.create_subprocess_exec(
                    "dpkg", "-s", pkg,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
                results.append((pkg, proc.returncode == 0))

        missing = [name for name, ok in results if not ok]
        for name, ok in results:
            lines.append(f"  {'[OK]' if ok else '[MISSING]':>10}  {name}")

        if missing:
            lines.append("")
            missing_pkgs = " ".join(
                name.split("(")[-1].rstrip(")") if "(" in name else name
                for name in missing
            )
            lines.append(f"Install missing: sudo apt install -y {missing_pkgs}")

    elif is_mac:
        lines.append("Platform: macOS")
        lines.append("Package manager: Homebrew")
        brew_pkgs = {
            "cmake": "cmake",
            "clang++": "(Xcode CLT)",
            "git": "git",
            "xmllint": "(system)",
        }
        brew_libs = ["libpng", "nlohmann-json", "libxml2", "wxwidgets", "libtiff", "jpeg"]

        results = []
        for binary, pkg in brew_pkgs.items():
            found = shutil.which(binary) is not None
            results.append((f"{binary} {pkg}", found))

        has_brew = shutil.which("brew") is not None
        if has_brew:
            # Check brew for library packages
            proc = await asyncio.create_subprocess_exec(
                "brew", "list", "--formula",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            installed = stdout.decode().split()
            for lib in brew_libs:
                results.append((f"brew:{lib}", lib in installed))

        missing = [name for name, ok in results if not ok]
        for name, ok in results:
            lines.append(f"  {'[OK]' if ok else '[MISSING]':>10}  {name}")

        if missing:
            brew_missing = [
                n.replace("brew:", "") for n in missing if n.startswith("brew:")
            ]
            if brew_missing:
                lines.append(f"\nInstall missing: brew install {' '.join(brew_missing)}")

    elif is_win:
        lines.append("Platform: Windows")
        win_bins = ["cmake", "git", "cl", "msbuild"]
        results = []
        for b in win_bins:
            results.append((b, shutil.which(b) is not None))

        vcpkg = shutil.which("vcpkg")
        results.append(("vcpkg", vcpkg is not None))

        for name, ok in results:
            lines.append(f"  {'[OK]' if ok else '[MISSING]':>10}  {name}")

        if not vcpkg:
            lines.append("\nvcpkg setup:")
            lines.append("  git clone https://github.com/microsoft/vcpkg.git")
            lines.append("  .\\vcpkg\\bootstrap-vcpkg.bat -disableMetrics")
            lines.append("  .\\vcpkg\\vcpkg.exe integrate install")
    else:
        lines.append(f"Platform: {sys.platform} (unknown)")

    # Common tools
    lines.append("")
    lines.append("Common tools:")
    for tool in ["llvm-profdata", "llvm-cov", "llvm-objdump", "ar", "readelf"]:
        found = shutil.which(tool) is not None
        lines.append(f"  {'[OK]' if found else '[---]':>10}  {tool}")

    ok_count = sum(1 for _, ok in results if ok) if results else 0
    total = len(results) if results else 0
    lines.append(f"\nSummary: {ok_count}/{total} dependencies found")

    return "\n".join(lines)


@mcp.tool()
async def find_build_artifacts(build_dir: str = "") -> str:
    """Find built binaries, libraries, and checksums in an iccDEV build directory.

    Discovers executables, static/shared libraries, and generates SHA-256
    checksums. Optionally verifies static vs dynamic linkage.

    Useful after cmake_build() to see what was produced.

    Args:
        build_dir: Build directory name under iccDEV/Build/ (e.g., "build-debug-asan-ubsan").
                   If empty, searches all build-* directories.
    """
    try:
        iccdev = _resolve_iccdev_dir()
    except FileNotFoundError as e:
        return f"[FAIL] {e}"

    base = iccdev / "Build"
    search_dirs: list[Path] = []

    if build_dir:
        try:
            target = _resolve_build_dir(build_dir)
        except (FileNotFoundError, ValueError) as e:
            return f"[FAIL] {e}"
        if not target.is_dir():
            return f"[FAIL] Build directory does not exist: {target}"
        search_dirs.append(target)
    else:
        # Find all build-* directories
        if base.is_dir():
            search_dirs = sorted(
                d for d in base.iterdir()
                if d.is_dir() and d.name.startswith("build")
            )
        if not search_dirs:
            return "[FAIL] No build directories found under iccDEV/Build/"

    lines = ["[iccDEV Build Artifacts]", ""]
    total_exes = 0
    total_libs = 0

    for search_dir in search_dirs:
        lines.append(f"── {search_dir.name}/ ──")
        exes: list[Path] = []
        libs: list[Path] = []

        for root, _dirs, files in os.walk(str(search_dir)):
            if "CMakeFiles" in root or ".git" in root:
                continue
            for f in files:
                fp = Path(root) / f
                if f.endswith((".exe", "")) and os.access(str(fp), os.X_OK) and not f.endswith((".a", ".so", ".dylib", ".sh", ".cmake", ".txt", ".log")):
                    # Verify it's actually an executable (not a script or data file)
                    if fp.suffix in ("", ".exe") and fp.stat().st_size > 1024:
                        exes.append(fp)
                if f.endswith((".a", ".so", ".dylib", ".lib", ".dll")):
                    libs.append(fp)

        if exes:
            lines.append(f"  Executables ({len(exes)}):")
            for exe in sorted(exes)[:30]:
                size = exe.stat().st_size
                sha = hashlib.sha256(exe.read_bytes()).hexdigest()[:16]
                rel = exe.relative_to(search_dir)
                lines.append(f"    {rel}  ({size:,} bytes)  sha256:{sha}…")
            if len(exes) > 30:
                lines.append(f"    ... and {len(exes) - 30} more")

        if libs:
            lines.append(f"  Libraries ({len(libs)}):")
            for lib in sorted(libs)[:20]:
                size = lib.stat().st_size
                rel = lib.relative_to(search_dir)
                lines.append(f"    {rel}  ({size:,} bytes)")
            if len(libs) > 20:
                lines.append(f"    ... and {len(libs) - 20} more")

        # Check linkage on Unix
        if sys.platform != "win32" and exes and shutil.which("ldd"):
            lines.append("  Linkage check (ICC libs):")
            for exe in sorted(exes)[:5]:
                proc = await asyncio.create_subprocess_exec(
                    "ldd", str(exe),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await proc.communicate()
                ldd_out = stdout.decode(errors="replace")
                icc_refs = [
                    line.strip() for line in ldd_out.splitlines()
                    if "Icc" in line or "icc" in line
                ]
                rel = exe.relative_to(search_dir)
                if icc_refs:
                    lines.append(f"    {rel.name}: dynamic ({', '.join(icc_refs[:3])})")
                else:
                    lines.append(f"    {rel.name}: static ICC linkage")

        total_exes += len(exes)
        total_libs += len(libs)
        lines.append("")

    lines.append(f"Total: {total_exes} executables, {total_libs} libraries across {len(search_dirs)} build dir(s)")
    return "\n".join(lines)


@mcp.tool()
async def batch_test_profiles(
    directory: str = "",
    tool: str = "all",
    build_dir: str = "",
) -> str:
    """Run iccDEV CLI tools over all ICC profiles in a directory with per-file results.

    Iterates over .icc/.icm files and runs the selected tool(s) against each,
    capturing exit codes and error output. Much more detailed than run_iccdev_tests
    which only runs RunTests.sh.

    Args:
        directory: Directory containing .icc profiles to test.
                   Defaults to iccDEV/Testing/ tree.
        tool: Which tool to run — "dump" (iccDumpProfile), "toxml" (iccToXml),
              "fromxml" (iccFromXml), "roundtrip" (iccRoundTrip), or "all".
        build_dir: Build directory with tool executables (from cmake_build).
    """
    if not build_dir:
        return (
            "[FAIL] build_dir is required. First build with enable_tools=True:\n"
            "  1. cmake_configure(enable_tools=True)\n"
            "  2. cmake_build(build_dir='...')\n"
            "  3. batch_test_profiles(build_dir='...')"
        )

    try:
        iccdev = _resolve_iccdev_dir()
        target_dir = _resolve_build_dir(build_dir)
    except (FileNotFoundError, ValueError) as e:
        return f"[FAIL] {e}"

    tool_dirs = _find_iccdev_tools(target_dir)
    if not tool_dirs:
        return f"[FAIL] No tools found in {target_dir}. Build with enable_tools=True first."

    env = os.environ.copy()
    env["PATH"] = _build_tool_path(target_dir)
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    env["MallocNanoZone"] = "0"

    # Resolve test directory
    if directory:
        test_dir = Path(directory).resolve()
        if not test_dir.is_dir():
            return f"[FAIL] Directory not found: {directory}"
    else:
        test_dir = iccdev / "Testing"
        if not test_dir.is_dir():
            return f"[FAIL] Testing directory not found: {test_dir}"

    # Find profiles
    profiles = sorted(
        p for p in test_dir.rglob("*")
        if p.suffix.lower() in (".icc", ".icm") and p.is_file()
    )
    if not profiles:
        return f"[FAIL] No .icc/.icm files found in {test_dir}"

    valid_tools = {"dump", "toxml", "fromxml", "roundtrip", "all"}
    if tool not in valid_tools:
        return f"[FAIL] Invalid tool '{tool}'. Choose: {', '.join(sorted(valid_tools))}"

    tool_cmds = {
        "dump": ("iccDumpProfile", ["-v"]),
        "toxml": ("iccToXml", []),
        "roundtrip": ("iccRoundTrip", []),
    }
    if tool == "all":
        run_tools = ["dump", "toxml", "roundtrip"]
    else:
        run_tools = [tool]

    lines = [f"[Batch Profile Testing — {len(profiles)} profiles]", ""]
    summary: dict[str, dict[str, int]] = {}

    for t in run_tools:
        if t == "fromxml":
            continue  # fromxml needs XML input, skip in batch ICC testing
        binary_name, base_args = tool_cmds[t]
        binary = shutil.which(binary_name, path=env["PATH"])
        if not binary:
            lines.append(f"[SKIP] {binary_name}: not found in PATH")
            continue

        lines.append(f"── {binary_name} ──")
        passed = 0
        failed = 0
        errors: list[str] = []

        for prof in profiles[:200]:  # Cap at 200 to avoid timeout
            args = [binary] + base_args + [str(prof)]
            if t == "toxml":
                xml_out = str(prof) + ".xml"
                args.append(xml_out)

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                errors.append(f"  [TIMEOUT] {prof.name}")
                failed += 1
                continue

            if proc.returncode == 0:
                passed += 1
            else:
                failed += 1
                stderr_text = stderr.decode(errors="replace")[:200]
                # Check for sanitizer findings
                if "ERROR: AddressSanitizer" in stderr_text or "runtime error:" in stderr_text:
                    errors.append(f"  [SANITIZER] {prof.name}: {stderr_text[:100]}")
                else:
                    errors.append(f"  [EXIT {proc.returncode}] {prof.name}")

            # Clean up XML output files
            if t == "toxml":
                Path(xml_out).unlink(missing_ok=True)

        lines.append(f"  Passed: {passed}/{passed + failed}")
        if errors:
            lines.append(f"  Failures ({len(errors)}):")
            for e in errors[:20]:
                lines.append(e)
            if len(errors) > 20:
                lines.append(f"  ... and {len(errors) - 20} more")
        summary[binary_name] = {"passed": passed, "failed": failed}
        lines.append("")

    if len(profiles) > 200:
        lines.append(f"[NOTE] Capped at 200 profiles (found {len(profiles)})")

    # Overall summary
    total_pass = sum(s["passed"] for s in summary.values())
    total_fail = sum(s["failed"] for s in summary.values())
    lines.append(f"Overall: {total_pass} passed, {total_fail} failed across {len(summary)} tool(s)")

    return "\n".join(lines)


@mcp.tool()
async def validate_xml(
    directory: str = "",
    checks: str = "all",
) -> str:
    """Validate ICC XML files using xmllint with multiple check types.

    Runs well-formedness, encoding, size limit, and entity safety checks
    on XML files generated by iccToXml. Useful for catching malformed
    output from profile conversion.

    Args:
        directory: Directory containing .xml files to validate.
                   Defaults to iccDEV/Testing/.
        checks: Comma-separated check types — "wellformed", "encoding",
                "size", "safety", or "all" (default).
    """
    xmllint = shutil.which("xmllint")
    if not xmllint:
        return "[FAIL] xmllint not found. Install: apt install libxml2-utils (Linux) or brew install libxml2 (macOS)"

    # Resolve directory
    if directory:
        xml_dir = Path(directory).resolve()
    else:
        try:
            iccdev = _resolve_iccdev_dir()
            xml_dir = iccdev / "Testing"
        except FileNotFoundError:
            xml_dir = REPO_ROOT / "test-profiles"

    if not xml_dir.is_dir():
        return f"[FAIL] Directory not found: {xml_dir}"

    xml_files = sorted(xml_dir.rglob("*.xml"))
    if not xml_files:
        return f"[FAIL] No .xml files found in {xml_dir}"

    valid_checks = {"wellformed", "encoding", "size", "safety", "all"}
    if checks == "all":
        run_checks = ["wellformed", "encoding", "size", "safety"]
    else:
        run_checks = [c.strip() for c in checks.split(",")]
        invalid = [c for c in run_checks if c not in valid_checks]
        if invalid:
            return f"[FAIL] Unknown check(s): {', '.join(invalid)}. Choose: {', '.join(sorted(valid_checks))}"

    check_args: dict[str, list[str]] = {
        "wellformed": ["--noout"],
        "encoding": ["--noout", "--encode", "UTF-8"],
        "size": ["--noout", "--maxmem", "104857600"],
        "safety": ["--noout", "--noent", "--nonet"],
    }

    lines = [f"[XML Validation — {len(xml_files)} files, {len(run_checks)} check(s)]", ""]
    cap = min(len(xml_files), 100)

    for check_name in run_checks:
        args = check_args[check_name]
        passed = 0
        failed = 0
        failures: list[str] = []

        for xf in xml_files[:cap]:
            cmd = [xmllint] + args + [str(xf)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                failures.append(f"  [TIMEOUT] {xf.name}")
                failed += 1
                continue

            if proc.returncode == 0:
                passed += 1
            else:
                failed += 1
                err_text = stderr.decode(errors="replace").strip()[:150]
                failures.append(f"  [FAIL] {xf.name}: {err_text}")

        lines.append(f"── {check_name} ──")
        lines.append(f"  Passed: {passed}/{passed + failed}")
        if failures:
            for f in failures[:10]:
                lines.append(f)
            if len(failures) > 10:
                lines.append(f"  ... and {len(failures) - 10} more")
        lines.append("")

    if len(xml_files) > cap:
        lines.append(f"[NOTE] Capped at {cap} files (found {len(xml_files)})")

    return "\n".join(lines)


@mcp.tool()
async def coverage_report(build_dir: str = "") -> str:
    """Merge profraw data and generate an LLVM coverage report.

    Finds all .profraw files in the build directory, merges them with
    llvm-profdata, and runs llvm-cov report to show line/function
    coverage percentages.

    Requires a build with sanitizers="coverage" or manual
    -fprofile-instr-generate -fcoverage-mapping flags.

    Args:
        build_dir: Build directory containing .profraw files and instrumented
                   binaries (from cmake_build with coverage config).
    """
    profdata_bin = shutil.which("llvm-profdata")
    cov_bin = shutil.which("llvm-cov")
    if not profdata_bin:
        return "[FAIL] llvm-profdata not found. Install: apt install llvm (Linux) or Xcode CLT (macOS)"
    if not cov_bin:
        return "[FAIL] llvm-cov not found. Install: apt install llvm (Linux) or Xcode CLT (macOS)"

    if not build_dir:
        return (
            "[FAIL] build_dir is required. Build with coverage first:\n"
            "  1. cmake_configure(sanitizers='coverage')\n"
            "  2. cmake_build(build_dir='...')\n"
            "  3. (run tools to generate .profraw files)\n"
            "  4. coverage_report(build_dir='...')"
        )

    try:
        target_dir = _resolve_build_dir(build_dir)
    except (FileNotFoundError, ValueError) as e:
        return f"[FAIL] {e}"

    if not target_dir.is_dir():
        return f"[FAIL] Build directory not found: {target_dir}"

    # Find profraw files
    profraw_files = sorted(target_dir.rglob("*.profraw"))
    if not profraw_files:
        return (
            f"[FAIL] No .profraw files found in {target_dir}.\n"
            "  Run instrumented tools first to generate profile data.\n"
            "  Set LLVM_PROFILE_FILE=path/${fuzzer_name}_%m_%p.profraw when running tools.\n"
            "  The %m pattern produces numeric hashes; include the fuzzer name prefix for identification."
        )

    # Find instrumented binaries
    tool_dirs = _find_iccdev_tools(target_dir)
    binaries: list[Path] = []
    for d in tool_dirs:
        for f in os.listdir(d):
            fp = Path(d) / f
            if fp.is_file() and os.access(str(fp), os.X_OK):
                binaries.append(fp)

    if not binaries:
        return f"[FAIL] No instrumented binaries found in {target_dir}"

    # Merge profraw → profdata
    profdata_out = target_dir / "merged.profdata"
    merge_cmd = [
        profdata_bin, "merge", "-sparse",
        *[str(p) for p in profraw_files],
        "-o", str(profdata_out),
    ]

    merge_result = await _run_build(merge_cmd, cwd=str(target_dir), timeout=120)
    if not profdata_out.is_file():
        return f"[FAIL] Merge failed:\n{merge_result}"

    lines = [
        "[Coverage Report]",
        "",
        f"  Profraw files:  {len(profraw_files)}",
        f"  Merged output:  {profdata_out.name} ({profdata_out.stat().st_size:,} bytes)",
        f"  Binaries:       {len(binaries)}",
        "",
    ]

    # Run llvm-cov report against the first binary (usually the main tool)
    primary = binaries[0]
    cov_cmd = [
        cov_bin, "report", str(primary),
        f"-instr-profile={profdata_out}",
    ]
    # Add additional object files
    for b in binaries[1:5]:
        cov_cmd.extend(["-object", str(b)])

    cov_result = await _run_build(cov_cmd, cwd=str(target_dir), timeout=60)
    lines.append("── Coverage Summary ──")
    lines.append(cov_result)

    return "\n".join(lines)


@mcp.tool()
async def scan_logs(
    directory: str = "",
    categories: str = "all",
) -> str:
    """Scan build/test log files for errors, crashes, and sanitizer findings.

    Searches .log files using pattern categories derived from iccDEV maintainer
    experience: errors, signals, invalid data, overflow, memory issues, hangs.

    Args:
        directory: Directory containing .log files to scan.
                   Defaults to current working directory.
        categories: Comma-separated categories — "errors", "signals", "invalid",
                    "overflow", "memory", "hangs", or "all" (default).
    """
    if categories == "all":
        active = list(_LOG_PATTERNS.keys())
    else:
        active = [c.strip() for c in categories.split(",")]
        invalid = [c for c in active if c not in _LOG_PATTERNS]
        if invalid:
            return f"[FAIL] Unknown category: {', '.join(invalid)}. Choose: {', '.join(sorted(_LOG_PATTERNS.keys()))}, all"

    # Resolve directory
    if directory:
        scan_dir = Path(directory).resolve()
    else:
        try:
            iccdev = _resolve_iccdev_dir()
            scan_dir = iccdev / "Testing"
        except FileNotFoundError:
            scan_dir = Path.cwd()

    if not scan_dir.is_dir():
        return f"[FAIL] Directory not found: {scan_dir}"

    log_files = sorted(scan_dir.rglob("*.log"))
    if not log_files:
        return f"[FAIL] No .log files found in {scan_dir}"

    lines = [f"[Log Scanner — {len(log_files)} files, {len(active)} categories]", ""]
    total_matches = 0
    cap = min(len(log_files), 50)

    for cat in active:
        pattern = _LOG_PATTERNS[cat]
        cat_matches: list[str] = []

        for lf in log_files[:cap]:
            try:
                content = lf.read_text(errors="replace")
            except OSError:
                continue
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(pattern, line, re.IGNORECASE):
                    cat_matches.append(f"  {lf.name}:{i}: {line.strip()[:120]}")
                    if len(cat_matches) >= 50:
                        break
            if len(cat_matches) >= 50:
                break

        lines.append(f"── {cat} ({len(cat_matches)} matches) ──")
        if cat_matches:
            for m in cat_matches[:15]:
                lines.append(m)
            if len(cat_matches) > 15:
                lines.append(f"  ... and {len(cat_matches) - 15} more")
        else:
            lines.append("  (none)")
        lines.append("")
        total_matches += len(cat_matches)

    if len(log_files) > cap:
        lines.append(f"[NOTE] Capped at {cap} files (found {len(log_files)})")
    lines.append(f"Total: {total_matches} findings across {len(active)} categories")

    return "\n".join(lines)


def run_server() -> None:
    """Entry point for console_scripts."""
    mcp.run()


if __name__ == "__main__":
    mcp.run()
