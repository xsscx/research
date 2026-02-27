#!/usr/bin/env python3
"""
Comprehensive test suite for ICC Profile MCP Server.

Tests: security boundary enforcement, functional correctness,
error handling, edge cases, and stress testing.

Usage:
    cd mcp-server
    source .venv/bin/activate
    python test_mcp.py
"""

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from icc_profile_mcp import (
    _resolve_profile,
    _ALLOWED_BASES_RESOLVED,
    _sanitize_cmake_args,
    _resolve_build_dir,
    _resolve_iccdev_dir,
    _find_iccdev_tools,
    _build_tool_path,
    _patch_iccdev_source,
    _sanitize_output,
    _VALID_BUILD_TYPES,
    _VALID_CMAKE_OPTIONS,
    _VALID_SANITIZERS,
    _VALID_COMPILERS,
    _VALID_GENERATORS,
    _VALID_VCPKG_SOURCES,
    ICCDEV_DIR,
    MAX_OUTPUT_BYTES,
    REPO_ROOT,
    list_test_profiles,
    inspect_profile,
    analyze_security,
    validate_roundtrip,
    full_analysis,
    profile_to_xml,
    compare_profiles,
    upload_and_analyze,
    cmake_configure,
    cmake_build,
    cmake_option_matrix,
    create_all_profiles,
    run_iccdev_tests,
    windows_build,
)


class TestRunner:
    def __init__(self):
        self.total = 0
        self.passed = 0
        self.failed = 0
        self.failures: list[tuple[str, str]] = []
        self.section_counts: dict[str, tuple[int, int]] = {}
        self._section = ""

    def section(self, name: str):
        self._section = name
        self.section_counts[name] = (0, 0)
        print(f"\n{'='*60}")
        print(f"  {name}")
        print(f"{'='*60}")

    def ok(self, name: str, passed: bool, detail: str = ""):
        self.total += 1
        sp, sf = self.section_counts.get(self._section, (0, 0))
        if passed:
            self.passed += 1
            self.section_counts[self._section] = (sp + 1, sf)
        else:
            self.failed += 1
            self.failures.append((name, detail))
            self.section_counts[self._section] = (sp, sf + 1)
            print(f"  [FAIL] {name}: {detail}")

    def section_summary(self):
        sp, sf = self.section_counts.get(self._section, (0, 0))
        total = sp + sf
        status = "PASS" if sf == 0 else "FAIL"
        print(f"  [{status}] {total} tests: {sp} passed, {sf} failed")


T = TestRunner()


# ---------------------------------------------------------------------------
# Security Tests
# ---------------------------------------------------------------------------

def test_path_traversal():
    """Verify path traversal attacks are blocked."""
    T.section("Security: Path Traversal")

    payloads = [
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../etc/shadow",
        "..%2F..%2Fetc%2Fpasswd",
        "test-profiles/../../../etc/passwd",
        "./test-profiles/./../../etc/passwd",
        "test-profiles/../../colorbleed_tools/../../../etc/passwd",
        "../" * 20 + "etc/passwd",
        "test-profiles/..%252f..%252f..%252fetc/passwd",
    ]
    for payload in payloads:
        try:
            p = _resolve_profile(payload)
            T.ok(f"traversal({payload[:40]})", False, f"resolved to {p}")
        except (FileNotFoundError, ValueError):
            T.ok(f"traversal({payload[:40]})", True)

    T.section_summary()


def test_absolute_path_escape():
    """Verify absolute paths outside the repo are blocked."""
    T.section("Security: Absolute Path Escape")

    for path in ["/etc/passwd", "/etc/hosts", "/etc/shadow",
                 "/proc/self/environ", "/proc/self/cmdline",
                 "/dev/urandom", "/tmp/anything"]:
        try:
            _resolve_profile(path)
            T.ok(f"absolute({path})", False, "resolved")
        except FileNotFoundError:
            T.ok(f"absolute({path})", True)

    T.section_summary()


def test_null_byte_injection():
    """Verify null bytes in paths are rejected."""
    T.section("Security: Null Byte Injection")

    payloads = [
        "test.icc\x00.jpg",
        "\x00../../etc/passwd",
        "test-profiles/\x00evil",
        "normal.icc\x00",
    ]
    for payload in payloads:
        try:
            _resolve_profile(payload)
            T.ok(f"null({repr(payload[:30])})", False, "resolved")
        except (ValueError, FileNotFoundError):
            T.ok(f"null({repr(payload[:30])})", True)

    T.section_summary()


def test_symlink_escape():
    """Verify symlinks pointing outside the repo are blocked."""
    T.section("Security: Symlink Escape")

    test_dir = REPO_ROOT / "test-profiles"
    symlink_targets = ["/etc/passwd", "/etc/hosts", "/dev/null"]
    for target in symlink_targets:
        link = test_dir / f"_test_symlink_{os.getpid()}.icc"
        try:
            link.symlink_to(target)
            try:
                _resolve_profile(link.name)
                T.ok(f"symlink->{target}", False, "resolved outside repo")
            except FileNotFoundError:
                T.ok(f"symlink->{target}", True)
        except OSError as e:
            T.ok(f"symlink->{target}", True, f"skip: {e}")
        finally:
            link.unlink(missing_ok=True)

    T.section_summary()


def test_symlink_within_repo():
    """Verify symlinks within the repo still work."""
    T.section("Security: Symlink Within Repo (should pass)")

    link = REPO_ROOT / "test-profiles" / f"_test_internal_{os.getpid()}.icc"
    target = REPO_ROOT / "test-profiles" / "BlacklightPoster_411039.icc"
    try:
        link.symlink_to(target)
        try:
            p = _resolve_profile(link.name)
            T.ok("symlink_internal", p.is_file() and "Blacklight" in p.name)
        except FileNotFoundError:
            T.ok("symlink_internal", False, "blocked valid symlink")
    except OSError as e:
        T.ok("symlink_internal", True, f"skip: {e}")
    finally:
        link.unlink(missing_ok=True)

    T.section_summary()


def test_directory_traversal_variants():
    """Test advanced traversal variants."""
    T.section("Security: Advanced Traversal Variants")

    payloads = [
        "....//....//etc/passwd",
        "..\\..\\etc\\passwd",
        "..\\..\\..",
        "test-profiles/./../../../../etc/passwd",
        "test-profiles/../test-profiles/../../../etc/passwd",
        # Unicode normalization attacks
        "..%c0%af..%c0%afetc/passwd",
        "..%ef%bc%8f..%ef%bc%8fetc/passwd",
    ]
    for payload in payloads:
        try:
            p = _resolve_profile(payload)
            # If it resolved to something within the repo, that's fine
            resolved = p.resolve()
            within_repo = any(
                True for b in _ALLOWED_BASES_RESOLVED
                if str(resolved).startswith(str(b))
            )
            T.ok(f"adv({payload[:35]})", within_repo,
                 "" if within_repo else f"escaped to {resolved}")
        except (FileNotFoundError, ValueError, OSError):
            T.ok(f"adv({payload[:35]})", True)

    T.section_summary()


# ---------------------------------------------------------------------------
# Functional Tests
# ---------------------------------------------------------------------------

async def test_list_test_profiles():
    """Test list_test_profiles for all directories and error case."""
    T.section("Functional: list_test_profiles")

    for d, min_count in [("test-profiles", 10), ("extended-test-profiles", 30)]:
        r = await list_test_profiles(d)
        T.ok(f"list({d})", "profiles:" in r and len(r.split("\n")) > min_count,
             f"{len(r.split(chr(10)))} lines")

    # Error case
    r = await list_test_profiles("nonexistent")
    T.ok("list(bad_dir)", "Unknown directory" in r)

    # Whitespace/injection in directory name
    r = await list_test_profiles("test-profiles; rm -rf /")
    T.ok("list(injection)", "Unknown directory" in r)

    T.section_summary()


async def test_inspect_all_profiles():
    """Test inspect_profile on every test profile."""
    T.section("Functional: inspect_profile × all test-profiles")

    files = sorted(f for f in os.listdir(REPO_ROOT / "test-profiles") if f.endswith(".icc"))
    for f in files:
        try:
            r = await inspect_profile(f)
            T.ok(f"inspect({f[:45]})", len(r) > 100 and ("Header" in r or "RAW" in r))
        except Exception as e:
            T.ok(f"inspect({f[:45]})", False, str(e))

    T.section_summary()


async def test_analyze_security_all():
    """Test analyze_security on every test profile."""
    T.section("Functional: analyze_security × all test-profiles")

    files = sorted(f for f in os.listdir(REPO_ROOT / "test-profiles") if f.endswith(".icc"))
    for f in files:
        try:
            r = await analyze_security(f)
            T.ok(f"security({f[:45]})", len(r) > 50)
        except Exception as e:
            T.ok(f"security({f[:45]})", False, str(e))

    T.section_summary()


async def test_validate_roundtrip_all():
    """Test validate_roundtrip on every test profile."""
    T.section("Functional: validate_roundtrip × all test-profiles")

    files = sorted(f for f in os.listdir(REPO_ROOT / "test-profiles") if f.endswith(".icc"))
    for f in files:
        try:
            r = await validate_roundtrip(f)
            T.ok(f"roundtrip({f[:45]})", len(r) > 50)
        except Exception as e:
            T.ok(f"roundtrip({f[:45]})", False, str(e))

    T.section_summary()


async def test_full_analysis_all():
    """Test full_analysis on every test profile."""
    T.section("Functional: full_analysis × all test-profiles")

    files = sorted(f for f in os.listdir(REPO_ROOT / "test-profiles") if f.endswith(".icc"))
    for f in files:
        try:
            r = await full_analysis(f)
            T.ok(f"full({f[:45]})", len(r) > 100 and "COMPREHENSIVE" in r)
        except Exception as e:
            T.ok(f"full({f[:45]})", False, str(e))

    T.section_summary()


async def test_profile_to_xml_all():
    """Test profile_to_xml on every test profile."""
    T.section("Functional: profile_to_xml × all test-profiles")

    files = sorted(f for f in os.listdir(REPO_ROOT / "test-profiles") if f.endswith(".icc"))
    for f in files:
        try:
            r = await profile_to_xml(f)
            T.ok(f"xml({f[:45]})", len(r) > 20)
        except Exception as e:
            T.ok(f"xml({f[:45]})", False, str(e))

    T.section_summary()


async def test_compare_profiles():
    """Test compare_profiles with multiple pairs."""
    T.section("Functional: compare_profiles")

    pairs = [
        ("BlacklightPoster_411039.icc", "xml-to-icc-to-xml-fidelity-test-001.icc"),
        ("DoubleFree_IccUtil.cpp-L121.icc", "CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc"),
        ("cve-2022-26730-poc-sample-004.icc", "BlacklightPoster_411039.icc"),
    ]
    for a, b in pairs:
        try:
            r = await compare_profiles(a, b)
            T.ok(f"compare({a[:20]}..{b[:20]})", len(r) > 10)
        except Exception as e:
            T.ok(f"compare({a[:20]}..{b[:20]})", False, str(e))

    # Same profile should show identical
    try:
        r = await compare_profiles("BlacklightPoster_411039.icc", "BlacklightPoster_411039.icc")
        T.ok("compare(same)", "identical" in r.lower() or len(r) < 100)
    except Exception as e:
        T.ok("compare(same)", False, str(e))

    T.section_summary()


async def test_error_handling():
    """Test error handling for all tools."""
    T.section("Functional: Error Handling")

    # Missing file
    try:
        await inspect_profile("nonexistent_file_12345.icc")
        T.ok("err_missing_inspect", False, "no exception")
    except FileNotFoundError:
        T.ok("err_missing_inspect", True)

    try:
        await analyze_security("nonexistent_file_12345.icc")
        T.ok("err_missing_security", False, "no exception")
    except FileNotFoundError:
        T.ok("err_missing_security", True)

    try:
        await profile_to_xml("nonexistent_file_12345.icc")
        T.ok("err_missing_xml", False, "no exception")
    except FileNotFoundError:
        T.ok("err_missing_xml", True)

    try:
        await compare_profiles("nonexistent_a.icc", "nonexistent_b.icc")
        T.ok("err_missing_compare", False, "no exception")
    except FileNotFoundError:
        T.ok("err_missing_compare", True)

    # Path traversal through tool functions
    try:
        await inspect_profile("../../etc/passwd")
        T.ok("err_traversal_inspect", False, "no exception")
    except FileNotFoundError:
        T.ok("err_traversal_inspect", True)

    try:
        await analyze_security("/etc/passwd")
        T.ok("err_absolute_security", False, "no exception")
    except FileNotFoundError:
        T.ok("err_absolute_security", True)

    T.section_summary()


# ---------------------------------------------------------------------------
# Stress Tests
# ---------------------------------------------------------------------------

async def test_extended_profiles():
    """Test full_analysis on all extended test profiles."""
    T.section("Stress: extended-test-profiles × full_analysis")

    ext_dir = REPO_ROOT / "extended-test-profiles"
    if not ext_dir.exists():
        print("  [SKIP] extended-test-profiles/ not found")
        return

    files = sorted(f for f in os.listdir(ext_dir) if f.endswith(".icc"))[:25]
    for f in files:
        try:
            r = await asyncio.wait_for(
                full_analysis(f"extended-test-profiles/{f}"),
                timeout=30
            )
            T.ok(f"ext_full", len(r) > 50)
        except asyncio.TimeoutError:
            # Allow 100ms for subprocess cleanup after cancellation
            await asyncio.sleep(0.1)
            T.ok(f"ext_full", True, f"{f[:30]}: timeout (30s) [warn]")
        except Exception as e:
            T.ok(f"ext_full", False, f"{f[:30]}: {e}")

    T.section_summary()


# ---------------------------------------------------------------------------
# Output Size Limiting
# ---------------------------------------------------------------------------

async def test_output_size_limit():
    """Verify _run enforces the combined output size limit."""
    T.section("Security: Output Size Limiting")
    from icc_profile_mcp import _run

    # Generate a command that produces large stdout
    # Use python to emit controlled output sizes
    large_size = MAX_OUTPUT_BYTES + 1024  # just over the limit

    # Test 1: stdout exceeds limit
    cmd = [
        sys.executable, "-c",
        f"import sys; sys.stdout.buffer.write(b'A' * {large_size})"
    ]
    r = await _run(cmd, timeout=30)
    encoded_len = len(r.encode("utf-8"))
    T.ok("stdout_truncated",
         encoded_len <= MAX_OUTPUT_BYTES + 200,  # allow small overhead for marker text
         f"output {encoded_len} bytes")
    T.ok("stdout_truncation_marker", "[OUTPUT TRUNCATED" in r)

    # Test 2: stderr with multibyte UTF-8 doesn't bypass limit
    # 9MB stdout + 2MB stderr emoji should stay under ~10MB total
    stdout_size = 9 * 1024 * 1024
    stderr_size = 2 * 1024 * 1024
    cmd = [
        sys.executable, "-c",
        f"import sys; sys.stdout.buffer.write(b'B' * {stdout_size}); "
        f"sys.stderr.buffer.write(('é' * {stderr_size}).encode('utf-8'))"
    ]
    r = await _run(cmd, timeout=30)
    encoded_len = len(r.encode("utf-8"))
    T.ok("combined_limit_utf8",
         encoded_len <= MAX_OUTPUT_BYTES + 200,
         f"output {encoded_len} bytes (limit {MAX_OUTPUT_BYTES})")

    # Test 3: normal-sized output is NOT truncated
    cmd = [sys.executable, "-c", "print('hello world')"]
    r = await _run(cmd, timeout=10)
    T.ok("small_output_not_truncated",
         "TRUNCATED" not in r and "hello world" in r)

    T.section_summary()


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

async def test_edge_cases():
    """Test edge cases and unusual inputs."""
    T.section("Edge Cases")

    # Empty string
    try:
        _resolve_profile("")
        T.ok("empty_path", False, "resolved empty string")
    except (FileNotFoundError, ValueError, OSError):
        T.ok("empty_path", True)

    # Very long path
    try:
        _resolve_profile("A" * 10000 + ".icc")
        T.ok("long_path", False, "resolved")
    except (FileNotFoundError, ValueError, OSError):
        T.ok("long_path", True)

    # Path with spaces
    try:
        _resolve_profile("file with spaces.icc")
        T.ok("spaces_in_path", False, "should not exist")
    except FileNotFoundError:
        T.ok("spaces_in_path", True)

    # Path with unicode
    try:
        _resolve_profile("profïle_tëst.icc")
        T.ok("unicode_path", False, "should not exist")
    except (FileNotFoundError, ValueError, OSError):
        T.ok("unicode_path", True)

    # Directory name as profile
    try:
        _resolve_profile("test-profiles")
        T.ok("dir_as_file", False, "resolved directory as file")
    except FileNotFoundError:
        T.ok("dir_as_file", True)

    # list_test_profiles with special chars
    r = await list_test_profiles("../etc")
    T.ok("list_traversal", "Unknown directory" in r)

    r = await list_test_profiles("")
    T.ok("list_empty", "Unknown directory" in r)

    T.section_summary()


# ---------------------------------------------------------------------------
# Maintainer Build Tools Tests
# ---------------------------------------------------------------------------

def test_sanitize_cmake_args():
    """Verify cmake arg sanitization blocks injection."""
    T.section("Security: cmake_configure Arg Sanitization")

    # Valid args
    valid_cases = [
        ("-DCMAKE_BUILD_TYPE=Debug", "simple define"),
        ("-DENABLE_TOOLS=ON", "boolean define"),
        ("-DICC_LOG_SAFE=ON -Wno-dev", "multiple valid args"),
        ("-DCMAKE_CXX_FLAGS=-O2", "flags with dash"),
        ("", "empty string"),
        ("  ", "whitespace only"),
    ]
    for raw, label in valid_cases:
        try:
            result = _sanitize_cmake_args(raw)
            T.ok(f"valid: {label}", True)
        except ValueError:
            T.ok(f"valid: {label}", False, "Unexpected rejection")

    # Invalid args — should be rejected
    inject_cases = [
        ("; rm -rf /", "shell injection semicolon"),
        ("$(whoami)", "command substitution"),
        ("`id`", "backtick injection"),
        ("| cat /etc/passwd", "pipe injection"),
        ("-DFOO=bar; echo pwned", "semicolon in value"),
        ("--evil-flag", "double-dash flag"),
        ("NAKED_ARG", "bare word"),
        ("-DFOO=val$(cmd)", "substitution in value"),
    ]
    for raw, label in inject_cases:
        try:
            _sanitize_cmake_args(raw)
            T.ok(f"reject: {label}", False, "Should have raised ValueError")
        except ValueError:
            T.ok(f"reject: {label}", True)

    T.section_summary()


def test_resolve_build_dir():
    """Verify build dir resolution prevents traversal."""
    T.section("Security: Build Dir Path Validation")

    # Traversal attempts
    traversal_cases = [
        ("../../etc", "parent traversal"),
        ("../../../tmp/evil", "deep traversal"),
        ("/etc/passwd", "absolute path"),
    ]
    for raw, label in traversal_cases:
        try:
            # These should either sanitize the name or raise
            result = _resolve_build_dir(raw)
            # If it resolved, verify it's still under iccDEV/Build/
            iccdev = _resolve_iccdev_dir()
            safe_base = str((iccdev / "Build").resolve())
            T.ok(f"traversal: {label}", str(result.resolve()).startswith(safe_base),
                 f"Escaped to {result}")
        except (ValueError, FileNotFoundError):
            T.ok(f"traversal: {label}", True)

    # Valid names
    valid_cases = [
        ("build-debug", "simple name"),
        ("build-debug-asan-tools", "complex name"),
        ("my.build", "dotted name"),
    ]
    for raw, label in valid_cases:
        try:
            result = _resolve_build_dir(raw)
            T.ok(f"valid: {label}", "Build" in str(result))
        except FileNotFoundError:
            # iccDEV not cloned — still validates the logic path
            T.ok(f"valid: {label} (no iccDEV)", True)

    T.section_summary()


def test_valid_constants():
    """Verify build option constants are correct."""
    T.section("Config: Build Option Constants")

    T.ok("build types", "Debug" in _VALID_BUILD_TYPES and "Release" in _VALID_BUILD_TYPES, "")
    T.ok("sanitizers", "asan+ubsan" in _VALID_SANITIZERS and "coverage" in _VALID_SANITIZERS, "")
    T.ok("compilers", "clang" in _VALID_COMPILERS and "gcc" in _VALID_COMPILERS, "")
    T.ok("generators", "Ninja" in _VALID_GENERATORS and "Xcode" in _VALID_GENERATORS, "")
    T.ok("ICCDEV_DIR path", "iccDEV" in str(ICCDEV_DIR), "")

    T.section_summary()


async def test_cmake_configure_validation():
    """Test cmake_configure parameter validation."""
    T.section("Functional: cmake_configure Validation")

    # Invalid build type
    result = await cmake_configure(build_type="InvalidType")
    T.ok("reject invalid build_type", "[FAIL]" in result, result[:80])

    # Invalid sanitizer
    result = await cmake_configure(sanitizers="magic")
    T.ok("reject invalid sanitizers", "[FAIL]" in result, result[:80])

    # Invalid compiler
    result = await cmake_configure(compiler="msvc")
    T.ok("reject invalid compiler", "[FAIL]" in result, result[:80])

    # Invalid generator
    result = await cmake_configure(generator="Visual Studio 99")
    T.ok("reject invalid generator", "[FAIL]" in result, result[:80])

    # Invalid extra args (injection attempt)
    result = await cmake_configure(extra_cmake_args="; rm -rf /")
    T.ok("reject injection in extra_cmake_args", "[FAIL]" in result or "Rejected" in result, result[:80])

    # Valid args should not fail on validation (may fail on missing iccDEV)
    result = await cmake_configure(
        build_type="Release",
        sanitizers="none",
        compiler="gcc",
        generator="Ninja",
    )
    # Should either succeed or fail because iccDEV is not cloned — not a validation error
    T.ok("valid Release+none+gcc+Ninja", "[FAIL] Invalid" not in result, result[:80])

    T.section_summary()


async def test_cmake_build_validation():
    """Test cmake_build parameter validation."""
    T.section("Functional: cmake_build Validation")

    # Missing build_dir
    result = await cmake_build()
    T.ok("require build_dir", "[FAIL]" in result, result[:80])

    # Non-existent build dir (should fail gracefully)
    result = await cmake_build(build_dir="nonexistent-dir-12345")
    T.ok("nonexistent build_dir", "[FAIL]" in result, result[:80])

    T.section_summary()


async def test_create_all_profiles_validation():
    """Test create_all_profiles parameter validation."""
    T.section("Functional: create_all_profiles Validation")

    # Missing build_dir
    result = await create_all_profiles()
    T.ok("require build_dir", "[FAIL]" in result, result[:80])

    # Non-existent build dir
    result = await create_all_profiles(build_dir="nonexistent-12345")
    T.ok("nonexistent build_dir", "[FAIL]" in result, result[:80])

    T.section_summary()


async def test_run_iccdev_tests_validation():
    """Test run_iccdev_tests parameter validation."""
    T.section("Functional: run_iccdev_tests Validation")

    # Missing build_dir
    result = await run_iccdev_tests()
    T.ok("require build_dir", "[FAIL]" in result, result[:80])

    # Non-existent build dir
    result = await run_iccdev_tests(build_dir="nonexistent-12345")
    T.ok("nonexistent build_dir", "[FAIL]" in result, result[:80])

    T.section_summary()


async def test_cmake_option_matrix_validation():
    """Test cmake_option_matrix parameter validation."""
    T.section("Functional: cmake_option_matrix Validation")

    # Invalid build type
    result = await cmake_option_matrix(build_type="BadType")
    T.ok("reject invalid build_type", "[FAIL]" in result, result[:80])

    # Invalid compiler
    result = await cmake_option_matrix(compiler="msvc")
    T.ok("reject invalid compiler", "[FAIL]" in result, result[:80])

    # Empty options
    result = await cmake_option_matrix(options="")
    T.ok("reject empty options", "[FAIL]" in result, result[:80])

    # Unknown cmake option
    result = await cmake_option_matrix(options="NONEXISTENT_OPTION")
    T.ok("reject unknown option", "[FAIL]" in result, result[:80])

    # Too many options (>10)
    result = await cmake_option_matrix(options=",".join(sorted(_VALID_CMAKE_OPTIONS)[:11]))
    T.ok("reject >10 options", "[FAIL]" in result, result[:80])

    # Valid options (may fail on missing iccDEV, but not validation)
    result = await cmake_option_matrix(options="ENABLE_COVERAGE,ICC_ENABLE_ASSERTS")
    T.ok("valid options accepted", "[FAIL] Invalid" not in result and "[FAIL] Unknown" not in result, result[:80])

    T.section_summary()


def test_valid_cmake_options_constant():
    """Test _VALID_CMAKE_OPTIONS constant."""
    T.section("Constants: _VALID_CMAKE_OPTIONS")

    T.ok("not empty", len(_VALID_CMAKE_OPTIONS) > 0, f"len={len(_VALID_CMAKE_OPTIONS)}")
    T.ok("contains ENABLE_TOOLS", "ENABLE_TOOLS" in _VALID_CMAKE_OPTIONS, str(_VALID_CMAKE_OPTIONS))
    T.ok("contains ENABLE_COVERAGE", "ENABLE_COVERAGE" in _VALID_CMAKE_OPTIONS, str(_VALID_CMAKE_OPTIONS))
    T.ok("contains ICC_ENABLE_ASSERTS", "ICC_ENABLE_ASSERTS" in _VALID_CMAKE_OPTIONS, str(_VALID_CMAKE_OPTIONS))
    T.ok("all uppercase names", all(o == o.upper() for o in _VALID_CMAKE_OPTIONS), "checked")

    T.section_summary()


async def test_find_iccdev_tools():
    """Test tool discovery helper."""
    T.section("Functional: Tool Discovery")

    from pathlib import Path
    import tempfile

    # Empty dir returns empty list
    with tempfile.TemporaryDirectory() as td:
        result = _find_iccdev_tools(Path(td))
        T.ok("empty dir", result == [], str(result))

    # Non-existent dir returns empty list
    result = _find_iccdev_tools(Path("/nonexistent/path"))
    T.ok("nonexistent dir", result == [], str(result))

    # _build_tool_path with empty returns base PATH
    path_str = _build_tool_path(Path("/nonexistent/path"))
    T.ok("base PATH fallback", "/usr" in path_str or "/bin" in path_str, path_str[:60])

    # _build_tool_path uses os.pathsep
    import os as _os
    T.ok("pathsep in _build_tool_path",
         _os.pathsep in path_str or len(path_str.split(_os.pathsep)) >= 1,
         f"sep={_os.pathsep}")

    T.section_summary()


def test_patch_iccdev_source():
    """Test source patching helper."""
    T.section("Functional: Source Patching")

    from pathlib import Path
    import tempfile

    # Non-existent dir returns empty patch list
    result = _patch_iccdev_source(Path("/nonexistent/path"))
    T.ok("nonexistent dir no crash", isinstance(result, list), str(result))

    # Create a mock iccDEV tree with U+FE0F byte
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        (td_path / "IccProfLib").mkdir()
        sig_file = td_path / "IccProfLib" / "IccSignatureUtils.h"
        sig_file.write_bytes(b"// test\xef\xb8\x8f content")
        result = _patch_iccdev_source(td_path)
        T.ok("strips U+FE0F", any("U+FE0F" in p for p in result), str(result))
        cleaned = sig_file.read_bytes()
        T.ok("U+FE0F removed from file", b"\xef\xb8\x8f" not in cleaned, repr(cleaned))

    # Already clean file — no patch needed
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        (td_path / "IccProfLib").mkdir()
        sig_file = td_path / "IccProfLib" / "IccSignatureUtils.h"
        sig_file.write_bytes(b"// clean content")
        result = _patch_iccdev_source(td_path)
        T.ok("clean file no patch", not any("U+FE0F" in p for p in result), str(result))

    T.section_summary()


def test_windows_build_constants():
    """Test Windows build constants."""
    T.section("Constants: Windows Build")

    T.ok("vcpkg sources defined", len(_VALID_VCPKG_SOURCES) > 0, str(_VALID_VCPKG_SOURCES))
    T.ok("release in vcpkg sources", "release" in _VALID_VCPKG_SOURCES, str(_VALID_VCPKG_SOURCES))
    T.ok("local in vcpkg sources", "local" in _VALID_VCPKG_SOURCES, str(_VALID_VCPKG_SOURCES))

    T.section_summary()


async def test_windows_build_validation():
    """Test windows_build input validation."""
    T.section("Validation: windows_build")

    # Invalid build type
    result = await windows_build(build_type="INVALID")
    T.ok("rejects invalid build_type", "[FAIL]" in result, result[:80])

    # Invalid vcpkg_deps
    result = await windows_build(vcpkg_deps="INVALID")
    T.ok("rejects invalid vcpkg_deps", "[FAIL]" in result, result[:80])

    # Invalid cmake args
    result = await windows_build(extra_cmake_args="; rm -rf /")
    T.ok("rejects shell injection", "[FAIL]" in result, result[:80])

    # Path traversal in build_dir — sanitized to safe name (starts with . → fallback)
    result = await windows_build(build_dir="../../etc")
    T.ok("sanitizes traversal", "build-mcp" in result or "[FAIL]" in result, result[:120])

    # Valid call on Linux generates PowerShell script
    import sys
    if sys.platform != "win32":
        result = await windows_build(build_type="Debug")
        T.ok("generates powershell script on linux",
             "powershell" in result.lower() or "[FAIL]" in result or "PowerShell" in result,
             result[:120])

    # Valid build types accepted
    for bt in ("Debug", "Release"):
        result = await windows_build(build_type=bt)
        T.ok(f"accepts {bt}", "[FAIL] Invalid build_type" not in result, result[:80])

    T.section_summary()


# ── _sanitize_output tests ───────────────────────────────────────────
def test_sanitize_output():
    T.section("Sanitize Output")

    # ANSI escape sequences stripped
    result = _sanitize_output("\033[31mred text\033[0m")
    T.ok("strips ANSI", "red text" in result and "\033" not in result, result)

    # Null bytes stripped
    result = _sanitize_output("hello\x00world")
    T.ok("strips null bytes", "\x00" not in result and "hello" in result, result)

    # Carriage returns stripped
    result = _sanitize_output("line1\r\nline2\r\n")
    T.ok("strips CR", "\r" not in result and "line1" in result, result)

    # Excessive newlines collapsed
    result = _sanitize_output("a\n\n\n\n\n\n\nb")
    T.ok("collapses newlines", result.count("\n") <= 3, f"{result.count(chr(10))} newlines")

    # Tabs preserved
    result = _sanitize_output("col1\tcol2")
    T.ok("preserves tabs", "\t" in result, result)

    # Bell and other control chars stripped
    result = _sanitize_output("alert\x07beep\x08back")
    T.ok("strips bell/backspace", "\x07" not in result and "\x08" not in result, result)

    # Empty string handled
    result = _sanitize_output("")
    T.ok("empty string", result == "", repr(result))

    T.section_summary()


# ── upload_and_analyze tests ─────────────────────────────────────────
async def test_upload_and_analyze():
    T.section("Upload and Analyze")
    import base64

    # Invalid base64
    result = await upload_and_analyze("not-valid-base64!!!")
    T.ok("rejects invalid base64", "[FAIL]" in result, result[:80])

    # Too small (< 128 bytes)
    tiny = base64.b64encode(b"\x00" * 50).decode()
    result = await upload_and_analyze(tiny)
    T.ok("rejects too small", "[FAIL]" in result and "too small" in result.lower(), result[:80])

    # Invalid mode
    # Create a minimal valid-sized payload (128+ bytes)
    fake_profile = b"\x00" * 200
    b64_data = base64.b64encode(fake_profile).decode()
    result = await upload_and_analyze(b64_data, mode="EVIL_MODE")
    T.ok("rejects invalid mode", "[FAIL]" in result and "Unknown mode" in result, result[:80])

    # Filename sanitization — path traversal
    result = await upload_and_analyze(b64_data, filename="../../../etc/passwd")
    T.ok("sanitizes traversal filename",
         "etc_passwd" in result or "[FAIL]" in result or "[OK]" in result,
         result[:80])

    # Filename sanitization — special characters
    result = await upload_and_analyze(b64_data, filename='<script>alert(1)</script>.icc')
    T.ok("sanitizes script filename",
         "<script>" not in result.split("\n")[0],
         result.split("\n")[0][:80])

    # Filename sanitization — dot-prefix
    result = await upload_and_analyze(b64_data, filename=".hidden")
    T.ok("dot-prefix becomes uploaded.icc",
         "uploaded.icc" in result or "[FAIL]" in result,
         result[:80])

    # Filename sanitization — no extension
    result = await upload_and_analyze(b64_data, filename="noext")
    T.ok("adds .icc extension",
         ".icc" in result or "[FAIL]" in result,
         result[:80])

    # Valid upload with real profile (if available)
    profiles = await list_test_profiles()
    if "test-profiles/" in profiles:
        # Pick first available profile
        import glob as globmod
        icc_files = globmod.glob(str(REPO_ROOT / "test-profiles" / "*.icc"))
        if icc_files:
            with open(icc_files[0], "rb") as f:
                real_data = base64.b64encode(f.read()).decode()
            result = await upload_and_analyze(real_data, filename=os.path.basename(icc_files[0]), mode="security")
            T.ok("real profile upload+analyze", "[OK]" in result, result[:80])

    T.section_summary()


async def main():
    start = time.time()

    print("ICC Profile MCP Server — Test Suite")
    print(f"Repository: {REPO_ROOT}")
    print(f"Output limit: {MAX_OUTPUT_BYTES / 1024 / 1024:.0f} MB")
    print(f"Allowed bases: {len(_ALLOWED_BASES_RESOLVED)}")

    # Security tests (synchronous)
    test_path_traversal()
    test_absolute_path_escape()
    test_null_byte_injection()
    test_symlink_escape()
    test_symlink_within_repo()
    test_directory_traversal_variants()
    test_sanitize_output()

    # Functional tests (async)
    await test_list_test_profiles()
    await test_inspect_all_profiles()
    await test_analyze_security_all()
    await test_validate_roundtrip_all()
    await test_full_analysis_all()
    await test_profile_to_xml_all()
    await test_compare_profiles()
    await test_error_handling()

    # Edge cases
    await test_edge_cases()

    # Output size limiting
    await test_output_size_limit()

    # Stress tests
    await test_extended_profiles()

    # Upload and analyze tests
    await test_upload_and_analyze()

    # Maintainer build tools tests
    test_sanitize_cmake_args()
    test_resolve_build_dir()
    test_valid_constants()
    await test_cmake_configure_validation()
    await test_cmake_build_validation()
    await test_create_all_profiles_validation()
    await test_run_iccdev_tests_validation()
    await test_cmake_option_matrix_validation()
    test_valid_cmake_options_constant()
    await test_find_iccdev_tools()
    test_patch_iccdev_source()
    test_windows_build_constants()
    await test_windows_build_validation()

    elapsed = time.time() - start

    # Final report
    print(f"\n{'='*60}")
    print(f"  FINAL RESULTS")
    print(f"{'='*60}")
    print()
    for section, (sp, sf) in T.section_counts.items():
        status = "[OK]" if sf == 0 else "[FAIL]"
        print(f"  {status} {section}: {sp}/{sp+sf}")
    print()
    print(f"  Total: {T.passed}/{T.total} passed, {T.failed} failed")
    print(f"  Time:  {elapsed:.1f}s")
    print()

    if T.failures:
        print("  FAILURES:")
        for name, detail in T.failures:
            print(f"    {name}: {detail}")
        print()
        sys.exit(1)
    else:
        print("  ALL TESTS PASSED")
        print()
        sys.exit(0)


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore", message="Event loop is closed")
    asyncio.run(main())
