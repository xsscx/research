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
    MAX_OUTPUT_BYTES,
    REPO_ROOT,
    list_test_profiles,
    inspect_profile,
    analyze_security,
    validate_roundtrip,
    full_analysis,
    profile_to_xml,
    compare_profiles,
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

    files = sorted(f for f in os.listdir(ext_dir) if f.endswith(".icc"))
    for f in files:
        try:
            r = await full_analysis(f"extended-test-profiles/{f}")
            T.ok(f"ext_full", len(r) > 50)
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
# Main
# ---------------------------------------------------------------------------

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

    elapsed = time.time() - start

    # Final report
    print(f"\n{'='*60}")
    print(f"  FINAL RESULTS")
    print(f"{'='*60}")
    print()
    for section, (sp, sf) in T.section_counts.items():
        status = "✓" if sf == 0 else "✗"
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
    asyncio.run(main())
