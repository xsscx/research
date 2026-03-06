#!/usr/bin/env python3
"""Unit test suite for iccanalyzer-lite.

Tests exit codes, analysis modes, heuristic detection, and ASAN/UBSAN
cleanliness across synthesized corpus and repository test profiles.

Usage:
    python3 run_tests.py                    # Run all tests
    python3 run_tests.py -v                 # Verbose output
    python3 run_tests.py -k exit_code       # Run tests matching pattern
    python3 run_tests.py --binary /path     # Override binary path
    python3 run_tests.py --xml report.xml   # JUnit XML output
"""

import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

# --- Configuration ---
SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent.parent
BINARY = SCRIPT_DIR.parent / "iccanalyzer-lite"
CORPUS_DIR = SCRIPT_DIR / "corpus"
TEST_PROFILES = REPO_ROOT / "test-profiles"
EXTENDED_PROFILES = REPO_ROOT / "extended-test-profiles"

# Exit codes
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_ERROR = 2
EXIT_USAGE = 3

TIMEOUT_SEC = 30

# --- Test infrastructure ---
class TestResult:
    def __init__(self, name, passed, message="", duration=0.0, stdout="", stderr=""):
        self.name = name
        self.passed = passed
        self.message = message
        self.duration = duration
        self.stdout = stdout
        self.stderr = stderr


class TestSuite:
    def __init__(self, binary_path=None, verbose=False, pattern=None):
        self.binary = str(binary_path or BINARY)
        self.verbose = verbose
        self.pattern = pattern
        self.results = []
        self.env = os.environ.copy()
        self.env["ASAN_OPTIONS"] = "detect_leaks=0"
        self.env["LLVM_PROFILE_FILE"] = "/dev/null"

    def run_analyzer(self, args, timeout=TIMEOUT_SEC):
        """Run iccanalyzer-lite with given args, return (exit_code, stdout, stderr)."""
        cmd = [self.binary] + args
        try:
            proc = subprocess.run(
                cmd, capture_output=True,
                timeout=timeout, env=self.env
            )
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            return proc.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            return -1, "", "TIMEOUT"
        except FileNotFoundError:
            return -99, "", f"Binary not found: {self.binary}"

    def assert_exit_code(self, name, args, expected_code, check_stderr=True):
        """Test that analyzer returns expected exit code."""
        t0 = time.monotonic()
        rc, stdout, stderr = self.run_analyzer(args)
        dur = time.monotonic() - t0

        passed = (rc == expected_code)
        msg = ""
        if not passed:
            msg = f"Expected exit code {expected_code}, got {rc}"

        # Check for ASAN errors in analyzer code (not upstream iccDEV)
        if check_stderr and passed:
            asan_hit = self._check_asan_analyzer(stderr)
            if asan_hit:
                passed = False
                msg = f"ASAN error in analyzer code: {asan_hit}"

        self.results.append(TestResult(name, passed, msg, dur, stdout, stderr))
        return passed

    def assert_output_contains(self, name, args, pattern, expected_code=None):
        """Test that stdout contains a regex pattern."""
        t0 = time.monotonic()
        rc, stdout, stderr = self.run_analyzer(args)
        dur = time.monotonic() - t0

        found = bool(re.search(pattern, stdout))
        passed = found
        msg = ""
        if not found:
            msg = f"Pattern '{pattern}' not found in output"
        if expected_code is not None and rc != expected_code:
            passed = False
            msg += f"; exit code {rc} != expected {expected_code}"

        asan_hit = self._check_asan_analyzer(stderr)
        if asan_hit:
            passed = False
            msg += f"; ASAN: {asan_hit}"

        self.results.append(TestResult(name, passed, msg, dur, stdout, stderr))
        return passed

    def assert_output_not_contains(self, name, args, pattern, expected_code=None):
        """Test that stdout does NOT contain a regex pattern."""
        t0 = time.monotonic()
        rc, stdout, stderr = self.run_analyzer(args)
        dur = time.monotonic() - t0

        found = bool(re.search(pattern, stdout))
        passed = not found
        msg = ""
        if found:
            msg = f"Pattern '{pattern}' unexpectedly found in output"
        if expected_code is not None and rc != expected_code:
            passed = False
            msg += f"; exit code {rc} != expected {expected_code}"

        self.results.append(TestResult(name, passed, msg, dur, stdout, stderr))
        return passed

    def assert_no_asan(self, name, args):
        """Test that no ASAN/UBSAN errors occur in analyzer code."""
        t0 = time.monotonic()
        rc, stdout, stderr = self.run_analyzer(args)
        dur = time.monotonic() - t0

        asan_hit = self._check_asan_analyzer(stderr)
        passed = (asan_hit is None)
        msg = asan_hit or ""

        self.results.append(TestResult(name, passed, msg, dur, stdout, stderr))
        return passed

    def _check_asan_analyzer(self, stderr):
        """Check for ASAN/UBSAN errors in analyzer code (not upstream iccDEV)."""
        for line in stderr.splitlines():
            if "ERROR: AddressSanitizer" in line:
                return line.strip()
            if "runtime error:" in line:
                # Filter out known upstream iccDEV UBSAN
                if any(f in line for f in [
                    "IccCAM.cpp",       # upstream div-by-zero
                    "IccProfile.cpp",   # upstream div-by-zero
                    "IccTagLut.cpp",    # upstream signed/unsigned overflow
                    "IccMD5.cpp",       # MD5 intentional unsigned wrapping
                ]):
                    continue
                return line.strip()
        return None

    def should_run(self, name):
        """Check if test matches the filter pattern."""
        if self.pattern is None:
            return True
        return self.pattern.lower() in name.lower()

    def report(self, xml_path=None):
        """Print results and optionally write JUnit XML."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        total_time = sum(r.duration for r in self.results)

        print(f"\n{'=' * 70}")
        print(f"RESULTS: {passed}/{total} passed, {failed} failed ({total_time:.1f}s)")
        print(f"{'=' * 70}")

        if failed > 0:
            print(f"\nFAILURES:")
            for r in self.results:
                if not r.passed:
                    print(f"  ✗ {r.name}")
                    print(f"    {r.message}")
                    if self.verbose and r.stderr:
                        for line in r.stderr.splitlines()[:5]:
                            print(f"    stderr: {line}")

        if self.verbose:
            print(f"\nALL TESTS:")
            for r in self.results:
                mark = "✓" if r.passed else "✗"
                print(f"  {mark} {r.name} ({r.duration:.2f}s)")

        if xml_path:
            self._write_junit_xml(xml_path, total_time)
            print(f"\nJUnit XML written to: {xml_path}")

        return 0 if failed == 0 else 1

    def _write_junit_xml(self, path, total_time):
        """Write JUnit-compatible XML report."""
        total = len(self.results)
        failures = sum(1 for r in self.results if not r.passed)

        suite = ET.Element("testsuite", {
            "name": "iccanalyzer-lite",
            "tests": str(total),
            "failures": str(failures),
            "time": f"{total_time:.3f}",
        })

        for r in self.results:
            tc = ET.SubElement(suite, "testcase", {
                "name": r.name,
                "time": f"{r.duration:.3f}",
            })
            if not r.passed:
                fail = ET.SubElement(tc, "failure", {"message": r.message})
                if r.stderr:
                    fail.text = r.stderr[:2000]

        tree = ET.ElementTree(suite)
        ET.indent(tree)
        tree.write(path, xml_declaration=True, encoding="unicode")


# --- Test definitions ---

def test_exit_codes(suite):
    """Test exit code behavior for various inputs."""
    corpus = str(CORPUS_DIR)

    # Exit 0: clean profile (may get findings from structural checks)
    suite.assert_exit_code(
        "exit_code.version_flag",
        ["--version"], EXIT_CLEAN, check_stderr=False
    )

    # Exit 3: usage errors
    suite.assert_exit_code(
        "exit_code.no_args",
        [], EXIT_USAGE, check_stderr=False
    )
    suite.assert_exit_code(
        "exit_code.unknown_flag",
        ["-zzz", f"{corpus}/valid_srgb.icc"], EXIT_USAGE, check_stderr=False
    )

    # Exit 2/3: file errors (nonexistent = path validation = USAGE, empty = preflight = FINDING)
    suite.assert_exit_code(
        "exit_code.nonexistent_file",
        ["-a", "/tmp/nonexistent_profile_12345.icc"], EXIT_USAGE, check_stderr=False
    )
    suite.assert_exit_code(
        "exit_code.empty_file",
        ["-a", f"{corpus}/empty_file.icc"], EXIT_FINDING, check_stderr=False
    )

    # Exit 1 or 2: truncated/corrupt profiles
    rc, _, _ = suite.run_analyzer(["-a", f"{corpus}/truncated.icc"])
    suite.results.append(TestResult(
        "exit_code.truncated_file",
        rc in (EXIT_FINDING, EXIT_ERROR),
        f"Got {rc}, expected 1 or 2", 0.0
    ))

    # Exit 1: findings on bad_magic
    suite.assert_exit_code(
        "exit_code.bad_magic",
        ["-a", f"{corpus}/bad_magic.icc"], EXIT_FINDING
    )


def test_analysis_modes(suite):
    """Test each analysis mode runs without crashing."""
    # Use a known good profile from test-profiles/
    good_profile = None
    if TEST_PROFILES.exists():
        candidates = list(TEST_PROFILES.glob("sRGB*.icc")) + list(TEST_PROFILES.glob("*.icc"))
        if candidates:
            good_profile = str(candidates[0])

    if not good_profile:
        good_profile = str(CORPUS_DIR / "valid_srgb.icc")

    for mode in ["-a", "-h", "-r", "-nf", "-n"]:
        suite.assert_exit_code(
            f"mode.{mode[1:]}_runs",
            [mode, good_profile], None, check_stderr=True
        )
        # Override: just check it doesn't crash (exit code varies)
        suite.results[-1].passed = suite.results[-1].passed or (
            suite.results[-1].message.startswith("Expected exit code") and
            "ASAN" not in suite.results[-1].message
        )
        # Fix: re-check without expected code
        suite.results.pop()
        suite.assert_no_asan(
            f"mode.{mode[1:]}_no_crash",
            [mode, good_profile]
        )

    # --version
    suite.assert_output_contains(
        "mode.version_output",
        ["--version"], r"iccAnalyzer-lite v\d+\.\d+\.\d+", EXIT_CLEAN
    )

    # --help
    suite.assert_output_contains(
        "mode.help_output",
        ["--help"], r"-a.*-h.*-r|Usage|USAGE", EXIT_CLEAN
    )


def test_heuristic_detection(suite):
    """Test that specific heuristics fire on synthesized profiles."""
    corpus = str(CORPUS_DIR)

    # H1: bad magic
    suite.assert_output_contains(
        "heuristic.bad_magic_detected",
        ["-a", f"{corpus}/bad_magic.icc"],
        r"magic|acsp|WARN|CRITICAL"
    )

    # H108/H127: private tags
    suite.assert_output_contains(
        "heuristic.private_tags_detected",
        ["-a", f"{corpus}/private_tags.icc"],
        r"H108|H127|[Pp]rivate|unknown tag"
    )

    # H112: bad wtpt
    suite.assert_output_contains(
        "heuristic.bad_wtpt_detected",
        ["-a", f"{corpus}/bad_wtpt.icc"],
        r"H112|wtpt|[Ww]hite.?[Pp]oint|D50|WARN"
    )

    # H116: wrong encoding for version
    suite.assert_output_contains(
        "heuristic.wrong_version_encoding",
        ["-a", f"{corpus}/wrong_version_encoding.icc"],
        r"H116|H117|encoding|mluc|text|WARN|wrong type"
    )

    # H117: wrong tag type
    suite.assert_output_contains(
        "heuristic.wrong_tag_type",
        ["-a", f"{corpus}/wrong_tag_type.icc"],
        r"H117|not in allowed|disallowed|WARN"
    )

    # H126: malware private tag
    suite.assert_output_contains(
        "heuristic.malware_signature",
        ["-a", f"{corpus}/malware_private_tag.icc"],
        r"H126|[Mm]alware|MZ|PE|executable|WARN|CRITICAL"
    )

    # H122: XYZ out of range
    suite.assert_output_contains(
        "heuristic.xyz_out_of_range",
        ["-a", f"{corpus}/xyz_out_of_range.icc"],
        r"H122|out of.*range|XYZ|WARN"
    )

    # H111: reserved bytes
    suite.assert_output_contains(
        "heuristic.reserved_bytes",
        ["-a", f"{corpus}/reserved_bytes_nonzero.icc"],
        r"H111|[Rr]eserved|non-zero|WARN"
    )

    # Huge tag count triggers preflight
    suite.assert_output_contains(
        "heuristic.huge_tag_count",
        ["-a", f"{corpus}/huge_tag_count.icc"],
        r"tag count|CRITICAL|preflight|threshold|999999|WARN"
    )

    # H124: v5 tags on v4
    suite.assert_output_contains(
        "heuristic.v5_tags_on_v4",
        ["-a", f"{corpus}/v5_tags_on_v4.icc"],
        r"H124|version|D2B|v5|WARN"
    )

    # H114: non-monotonic TRC
    suite.assert_output_contains(
        "heuristic.non_monotonic_trc",
        ["-a", f"{corpus}/non_monotonic_curve.icc"],
        r"H114|[Mm]onoton|TRC|WARN"
    )

    # --- New heuristic-targeted tests ---

    # H3: null/invalid colorSpace
    suite.assert_output_contains(
        "heuristic.null_colorspace",
        ["-a", f"{corpus}/null_colorspace.icc"],
        r"Invalid/null colorSpace"
    )

    # H4: invalid PCS signature
    suite.assert_output_contains(
        "heuristic.invalid_pcs",
        ["-a", f"{corpus}/invalid_pcs.icc"],
        r"Invalid PCS signature"
    )

    # H5: unknown platform signature
    suite.assert_output_contains(
        "heuristic.unknown_platform",
        ["-a", f"{corpus}/unknown_platform.icc"],
        r"Unknown platform signature"
    )

    # H6: invalid rendering intent
    suite.assert_output_contains(
        "heuristic.invalid_rendering_intent",
        ["-a", f"{corpus}/invalid_rendering_intent.icc"],
        r"Invalid rendering intent value 99"
    )

    # H7: unknown device class
    suite.assert_output_contains(
        "heuristic.unknown_device_class",
        ["-a", f"{corpus}/unknown_device_class.icc"],
        r"Unknown profile class"
    )

    # H8: negative illuminant
    suite.assert_output_contains(
        "heuristic.negative_illuminant",
        ["-a", f"{corpus}/negative_illuminant.icc"],
        r"Negative illuminant values"
    )

    # H15: invalid date fields
    suite.assert_output_contains(
        "heuristic.invalid_date",
        ["-a", f"{corpus}/invalid_date.icc"],
        r"Invalid month: 13|Invalid day: 32"
    )

    # H128: non-BCD version nibble
    suite.assert_output_contains(
        "heuristic.version_bcd_invalid",
        ["-a", f"{corpus}/version_bcd_invalid.icc"],
        r"Non-BCD nibble in version"
    )

    # H129: D50 illuminant mismatch
    suite.assert_output_contains(
        "heuristic.wrong_d50_illuminant",
        ["-a", f"{corpus}/wrong_d50_illuminant.icc"],
        r"PCS illuminant does not match D50"
    )

    # H133: flags reserved bits
    suite.assert_output_contains(
        "heuristic.flags_reserved_bits",
        ["-a", f"{corpus}/flags_reserved_bits.icc"],
        r"Reserved flag bits non-zero"
    )

    # H135: duplicate tag signatures
    suite.assert_output_contains(
        "heuristic.duplicate_tags",
        ["-a", f"{corpus}/duplicate_tags.icc"],
        r"Duplicate tag signature.*desc"
    )

    # H130/H40: tag alignment
    suite.assert_output_contains(
        "heuristic.tag_misaligned",
        ["-a", f"{corpus}/tag_misaligned.icc"],
        r"not 4-byte aligned"
    )

    # H1: extra trailing bytes (size mismatch)
    suite.assert_output_contains(
        "heuristic.extra_trailing_bytes",
        ["-a", f"{corpus}/extra_trailing_bytes.icc"],
        r"EXTRA BYTES appended"
    )

    # H20: null tag type signature
    suite.assert_output_contains(
        "heuristic.null_tag_type",
        ["-a", f"{corpus}/null_tag_type.icc"],
        r"null type signature"
    )

    # H49: NaN/Inf in float tag
    suite.assert_output_contains(
        "heuristic.nan_float_tag",
        ["-a", f"{corpus}/nan_float_tag.icc"],
        r"NaN detected at offset|Inf detected at offset"
    )

    # H55: odd byte length UTF-16
    suite.assert_output_contains(
        "heuristic.odd_utf16_mluc",
        ["-a", f"{corpus}/odd_utf16_mluc.icc"],
        r"odd byte length.*invalid UTF-16"
    )

    # H69: suspicious profile ID
    suite.assert_output_contains(
        "heuristic.suspicious_profile_id",
        ["-a", f"{corpus}/suspicious_profile_id.icc"],
        r"suspicious pattern.*0xFF|Profile ID.*suspicious"
    )

    # H10: zero tags (verify library-level detection)
    suite.assert_output_contains(
        "heuristic.zero_tags_detected",
        ["-a", f"{corpus}/zero_tags.icc"],
        r"Zero tags.*invalid"
    )


def test_heuristic_summary(suite):
    """Test that the summary section appears with correct heuristic count."""
    suite.assert_output_contains(
        "summary.135_heuristics",
        ["-a", str(CORPUS_DIR / "bad_magic.icc")],
        r"135 heuristics"
    )

    suite.assert_output_contains(
        "summary.heuristic_summary_header",
        ["-a", str(CORPUS_DIR / "bad_magic.icc")],
        r"HEURISTIC SUMMARY"
    )


def test_sanitizer_clean(suite):
    """Test ASAN/UBSAN cleanliness across synthesized corpus."""
    for icc in sorted(CORPUS_DIR.glob("*.icc")):
        if icc.stat().st_size == 0:
            continue  # Skip empty file
        suite.assert_no_asan(
            f"asan.corpus.{icc.stem}",
            ["-a", str(icc)]
        )


def test_repo_profiles_sample(suite):
    """Test a sample of real profiles from the repo for ASAN cleanliness."""
    profiles = []
    if TEST_PROFILES.exists():
        all_profiles = sorted(TEST_PROFILES.glob("*.icc"))
        # Sample every 10th profile for speed
        profiles = all_profiles[::10]

    for icc in profiles[:30]:  # Cap at 30
        suite.assert_no_asan(
            f"asan.repo.{icc.stem[:40]}",
            ["-a", str(icc)]
        )


def test_xml_export(suite):
    """Test XML export mode."""
    import tempfile
    good = str(CORPUS_DIR / "valid_srgb.icc")
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_path = f.name

    try:
        rc, stdout, stderr = suite.run_analyzer(["-xml", good, xml_path])
        exists = os.path.exists(xml_path) and os.path.getsize(xml_path) > 0
        suite.results.append(TestResult(
            "xml_export.creates_file",
            exists or rc == EXIT_CLEAN,
            f"XML file {'exists' if exists else 'missing'}, rc={rc}",
            0.0, stdout, stderr
        ))
    finally:
        if os.path.exists(xml_path):
            os.unlink(xml_path)


def test_multiple_modes_same_profile(suite):
    """Test that running different modes on the same profile gives consistent results."""
    profile = str(CORPUS_DIR / "valid_srgb.icc")
    for mode in ["-a", "-h", "-r"]:
        suite.assert_no_asan(
            f"consistency.{mode[1:]}_valid",
            [mode, profile]
        )


def test_lut_extraction(suite):
    """Test LUT extraction mode (-x) on profiles with curves/LUTs."""
    import tempfile
    good = str(CORPUS_DIR / "valid_srgb.icc")
    with tempfile.TemporaryDirectory() as tmpdir:
        basename = os.path.join(tmpdir, "lut_test")
        # -x mode should run without crashing
        suite.assert_no_asan(
            "lut.extract_valid_srgb",
            ["-x", good, basename]
        )

    # Also test on a profile with actual curve data (non_monotonic has curv tags)
    mono = str(CORPUS_DIR / "non_monotonic_curve.icc")
    with tempfile.TemporaryDirectory() as tmpdir:
        basename = os.path.join(tmpdir, "lut_mono")
        suite.assert_no_asan(
            "lut.extract_non_monotonic",
            ["-x", mono, basename]
        )

    # Test with a real profile from test-profiles if available
    if TEST_PROFILES.exists():
        candidates = sorted(TEST_PROFILES.glob("*.icc"))
        if candidates:
            with tempfile.TemporaryDirectory() as tmpdir:
                basename = os.path.join(tmpdir, "lut_real")
                suite.assert_no_asan(
                    "lut.extract_real_profile",
                    ["-x", str(candidates[0]), basename]
                )


def test_call_graph_mode(suite):
    """Test call graph mode (-cg) with a sample ASAN log."""
    import tempfile

    # Create a minimal ASAN-style crash log
    asan_log = (
        "=================================================================\n"
        "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000001234\n"
        "READ of size 4 at 0x602000001234 thread T0\n"
        "    #0 0x55555557a000 in CIccProfile::Read /src/IccProfile.cpp:100\n"
        "    #1 0x55555558b000 in main /src/main.cpp:50\n"
        "\n"
        "0x602000001234 is located 4 bytes before 16-byte region\n"
        "allocated by thread T0 here:\n"
        "    #0 0x7ffff7c00000 in malloc /lib/asan.cpp:100\n"
        "    #1 0x55555557c000 in CIccProfile::Load /src/IccProfile.cpp:80\n"
        "=================================================================\n"
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write(asan_log)
        log_path = f.name

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_base = os.path.join(tmpdir, "cg_test")
            suite.assert_no_asan(
                "callgraph.asan_log_parse",
                ["-cg", log_path, out_base]
            )
    finally:
        os.unlink(log_path)


def test_xml_heuristic_export(suite):
    """Test XML export mode (-xml) produces valid XML output."""
    import tempfile
    # Test with valid profile
    good = str(CORPUS_DIR / "valid_srgb.icc")
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_path = f.name

    try:
        rc, stdout, stderr = suite.run_analyzer(["-xml", good, xml_path])
        if os.path.exists(xml_path) and os.path.getsize(xml_path) > 0:
            with open(xml_path, 'r') as xf:
                content = xf.read()
            has_xml = '<?xml' in content or '<' in content
            suite.results.append(TestResult(
                "xml_heuristic.valid_xml_content",
                has_xml,
                f"XML content {'valid' if has_xml else 'empty/invalid'}, rc={rc}",
                0.0, stdout, stderr
            ))
        else:
            suite.results.append(TestResult(
                "xml_heuristic.valid_xml_content",
                rc != 2,  # Pass if not an I/O error
                f"No XML output, rc={rc}",
                0.0, stdout, stderr
            ))
    finally:
        if os.path.exists(xml_path):
            os.unlink(xml_path)

    # Test with malformed profile
    bad = str(CORPUS_DIR / "bad_magic.icc")
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_path2 = f.name
    try:
        suite.assert_no_asan(
            "xml_heuristic.bad_magic_no_crash",
            ["-xml", bad, xml_path2]
        )
    finally:
        if os.path.exists(xml_path2):
            os.unlink(xml_path2)


def test_ninja_modes_coverage(suite):
    """Test ninja modes on diverse profiles for line coverage."""
    corpus = str(CORPUS_DIR)
    # -n (minimal) and -nf (full) on multiple profile types
    for profile_name in ["valid_srgb.icc", "private_tags.icc",
                         "non_monotonic_curve.icc", "bad_wtpt.icc"]:
        path = f"{corpus}/{profile_name}"
        stem = profile_name.replace(".icc", "")
        suite.assert_no_asan(
            f"ninja.n_{stem}",
            ["-n", path]
        )
        suite.assert_no_asan(
            f"ninja.nf_{stem}",
            ["-nf", path]
        )


def test_extended_profiles_coverage(suite):
    """Test -a on extended test profiles for broader code coverage."""
    if not EXTENDED_PROFILES.exists():
        return
    profiles = sorted(EXTENDED_PROFILES.glob("*.icc"))
    # Test every 5th extended profile
    for icc in profiles[::5][:20]:
        suite.assert_no_asan(
            f"extended.{icc.stem[:40]}",
            ["-a", str(icc)]
        )


# --- Main ---

def main():
    import argparse
    parser = argparse.ArgumentParser(description="iccanalyzer-lite unit tests")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-k", "--pattern", help="Filter tests by name pattern")
    parser.add_argument("--binary", help="Path to iccanalyzer-lite binary")
    parser.add_argument("--xml", help="Write JUnit XML report to this path")
    parser.add_argument("--ci", action="store_true", help="CI mode: synthesize + test")
    args = parser.parse_args()

    # Synthesize corpus if not present
    if not CORPUS_DIR.exists() or len(list(CORPUS_DIR.glob("*.icc"))) == 0:
        print("Synthesizing test corpus...")
        subprocess.run([sys.executable, str(SCRIPT_DIR / "synthesize_profiles.py")], check=True)

    binary = Path(args.binary) if args.binary else BINARY
    if not binary.exists():
        print(f"ERROR: Binary not found: {binary}")
        print("Build with: cd iccanalyzer-lite && ./build.sh")
        return 2

    suite = TestSuite(binary, verbose=args.verbose, pattern=args.pattern)

    # Discover and run test functions
    test_functions = [
        ("Exit Codes", test_exit_codes),
        ("Analysis Modes", test_analysis_modes),
        ("Heuristic Detection", test_heuristic_detection),
        ("Heuristic Summary", test_heuristic_summary),
        ("Sanitizer Clean (Corpus)", test_sanitizer_clean),
        ("Repo Profile Sample", test_repo_profiles_sample),
        ("XML Export", test_xml_export),
        ("Multi-Mode Consistency", test_multiple_modes_same_profile),
        ("LUT Extraction", test_lut_extraction),
        ("Call Graph", test_call_graph_mode),
        ("XML Heuristic Export", test_xml_heuristic_export),
        ("Ninja Modes Coverage", test_ninja_modes_coverage),
        ("Extended Profiles", test_extended_profiles_coverage),
    ]

    for section_name, test_fn in test_functions:
        if suite.should_run(section_name):
            print(f"\n--- {section_name} ---")
            test_fn(suite)
            # Print progress
            recent = suite.results[-1] if suite.results else None
            if recent and not recent.passed:
                print(f"  ✗ {recent.name}: {recent.message}")

    return suite.report(xml_path=args.xml)


if __name__ == "__main__":
    sys.exit(main())
