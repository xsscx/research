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
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/nonexistent",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "ASAN_OPTIONS": "detect_leaks=0",
        "MallocNanoZone": "0",
    }
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

    # Enforce output size limit
    if len(stdout) > MAX_OUTPUT_BYTES:
        stdout = stdout[:MAX_OUTPUT_BYTES]
        truncated = True
    else:
        truncated = False

    output = stdout.decode(errors="replace")
    if stderr:
        stderr_text = stderr.decode(errors="replace")
        remaining = MAX_OUTPUT_BYTES - len(stdout)
        if remaining > 0:
            # Truncate by encoded byte length to respect the limit accurately
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


def run_server() -> None:
    """Entry point for console_scripts."""
    mcp.run()


if __name__ == "__main__":
    mcp.run()
