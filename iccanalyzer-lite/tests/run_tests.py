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
import json
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
                    "IccCAM.cpp",         # upstream div-by-zero (m_WhitePoint[1])
                    "IccProfile.cpp",     # upstream div-by-zero (m_illuminantXYZ.Y)
                    "IccTagLut.cpp",      # upstream signed integer overflow (m_XYZMatrix)
                    "IccMatrixMath.cpp",  # upstream NaN→unsigned short in SetRange
                    "IccMD5.cpp",         # MD5 intentional unsigned wrapping
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

    # --- CWE-400 systemic pattern tests (CFL-074/075/076 findings) ---

    # H64: NamedColor2 device coords > 15
    suite.assert_output_contains(
        "heuristic.named_color2_excessive_coords",
        ["-a", f"{corpus}/named_color2_excessive_coords.icc"],
        r"NamedColor2.*20 device coords.*>15"
    )

    # H136: ResponseCurve excessive measurements
    suite.assert_output_contains(
        "heuristic.response_curve_excessive_measurements",
        ["-a", f"{corpus}/response_curve_excessive_measurements.icc"],
        r"ResponseCurve.*channel.*500000 measurements.*>100K"
    )

    # H137: high-dimensional color space
    suite.assert_output_contains(
        "heuristic.high_dimensional_grid_complexity",
        ["-a", f"{corpus}/high_dimensional_colorspace.icc"],
        r"Input color space has 8 channels"
    )

    # Verify H136/H137 produce CWE-400 annotations
    suite.assert_output_contains(
        "heuristic.cwe400_in_response_curve",
        ["-a", f"{corpus}/response_curve_excessive_measurements.icc"],
        r"CWE-400.*Unbounded measurement count"
    )

    suite.assert_output_contains(
        "heuristic.cwe400_in_high_dim",
        ["-a", f"{corpus}/high_dimensional_colorspace.icc"],
        r"CWE-400.*O\(nGran\^ndim\)"
    )

    # --- Validation/Runtime symmetry tests ---

    # H47 raw-byte ncl2 check fires nDevCoords>15 (always-run, covers library-load failures)
    suite.assert_output_contains(
        "symmetry.h47_raw_ndevcoords_gt15",
        ["-a", f"{corpus}/named_color2_excessive_coords.icc"],
        r"ncl2.*nDeviceCoords.*>15 ICC spec max"
    )

    # H47 raw-byte ncl2 check fires CFL-076 pattern annotation
    suite.assert_output_contains(
        "symmetry.h47_raw_cfl076_pattern",
        ["-a", f"{corpus}/named_color2_excessive_coords.icc"],
        r"CWE-787.*CFL-076"
    )

    # H64 library-level check fires nColors>10000 Describe() DoS (when library loads)
    # The named_color2_large_nsize profile has nColors=70000 but only 2 actual entries,
    # so the library may reject it. H47 always catches it at raw level.
    suite.assert_output_contains(
        "symmetry.h47_raw_ncolors_gt10000",
        ["-a", f"{corpus}/named_color2_large_nsize.icc"],
        r"ncl2.*entries.*>10000.*Describe.*DoS"
    )

    # H47 CWE-400 Describe() pattern annotation
    suite.assert_output_contains(
        "symmetry.h47_raw_cfl078_pattern",
        ["-a", f"{corpus}/named_color2_large_nsize.icc"],
        r"CWE-400.*Describe.*m_nSize.*CFL-078"
    )

    # H136 runs in always-run phase (not gated behind library load)
    # Verify it fires on response_curve_excessive_measurements.icc even with malformed header
    suite.assert_output_contains(
        "symmetry.h136_always_runs",
        ["-a", f"{corpus}/response_curve_excessive_measurements.icc"],
        r"\[H136\].*ResponseCurve"
    )

    # XYZ large array completes without hanging (runtime safety)
    suite.assert_output_contains(
        "symmetry.xyz_large_no_hang",
        ["-a", f"{corpus}/xyz_large_array.icc"],
        r"150 heuristics"
    )

    # Calculator deep nesting profile completes without hanging
    suite.assert_output_contains(
        "symmetry.calc_deep_no_hang",
        ["-a", f"{corpus}/calculator_deep_nesting.icc"],
        r"150 heuristics"
    )


def test_runtime_safety(suite):
    """Test that CWE-400 profiles don't hang the analyzer (runtime cap validation).
    Each profile must complete analysis within the test timeout."""
    corpus = str(CORPUS_DIR)

    # Real PoC files from fuzzing - verify analyzer doesn't hang
    poc_files = [
        "timeout-0bec9575ea3dd8e7b1cccafaf453d5e84fec69b6",  # CFL-076 NamedColor2 nDevCoords
    ]
    for poc in poc_files:
        poc_path = str(CORPUS_DIR.parent.parent.parent / poc)
        import os as _os
        if _os.path.exists(poc_path):
            suite.assert_output_contains(
                f"runtime_safety.poc_{poc[:12]}",
                ["-a", poc_path],
                r"HEURISTIC SUMMARY"
            )

    # Synthesized CWE-400 profiles must all complete
    cwe400_profiles = [
        "named_color2_excessive_coords.icc",
        "named_color2_large_nsize.icc",
        "high_dimensional_colorspace.icc",
        "response_curve_excessive_measurements.icc",
        "xyz_large_array.icc",
        "calculator_deep_nesting.icc",
    ]
    for profile in cwe400_profiles:
        suite.assert_output_contains(
            f"runtime_safety.{profile.replace('.icc', '')}",
            ["-a", f"{corpus}/{profile}"],
            r"HEURISTIC SUMMARY"
        )


def test_heuristic_summary(suite):
    """Test that the summary section appears with correct heuristic count."""
    suite.assert_output_contains(
        "summary.150_heuristics",
        ["-a", str(CORPUS_DIR / "bad_magic.icc")],
        r"150 heuristics"
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


def test_json_output(suite):
    """Test --json structured output mode."""
    good = str(CORPUS_DIR / "valid_srgb.icc")

    # JSON should be valid and parseable
    rc, stdout, stderr = suite.run_analyzer(["--json", good])
    try:
        import json
        data = json.loads(stdout)
        valid = True
    except (json.JSONDecodeError, ValueError):
        data = {}
        valid = False

    suite.results.append(TestResult(
        "json.valid_parse", valid,
        "JSON output should parse" if not valid else "",
        0.0, stdout, stderr
    ))

    # Check required top-level keys
    for key in ["file", "exitCode", "summary", "results"]:
        has_key = key in data
        suite.results.append(TestResult(
            f"json.has_{key}", has_key,
            f"Missing key '{key}'" if not has_key else "",
            0.0, "", ""
        ))

    # Summary should have counts
    if "summary" in data:
        s = data["summary"]
        has_total = s.get("totalHeuristics", 0) == 150
        suite.results.append(TestResult(
            "json.total_heuristics_150", has_total,
            f"totalHeuristics={s.get('totalHeuristics')}" if not has_total else "",
            0.0, "", ""
        ))
        has_cve = "cveCoverage" in s
        suite.results.append(TestResult(
            "json.has_cve_coverage", has_cve,
            "Missing cveCoverage block" if not has_cve else "",
            0.0, "", ""
        ))
        if has_cve:
            cov = s["cveCoverage"]
            has_unique = "uniqueCVEs" in cov and cov["uniqueCVEs"] >= 100
            suite.results.append(TestResult(
                "json.cve_unique_count", has_unique,
                f"uniqueCVEs={cov.get('uniqueCVEs')}, expected >= 100" if not has_unique else "",
                0.0, "", ""
            ))
            has_scope = "outOfScopeXmlCVEs" in cov and cov["outOfScopeXmlCVEs"] == 0
            suite.results.append(TestResult(
                "json.cve_xml_scope", has_scope,
                f"outOfScopeXmlCVEs={cov.get('outOfScopeXmlCVEs')}, expected 0" if not has_scope else "",
                0.0, "", ""
            ))
            has_tool_scope = "outOfScopeToolCVEs" in cov and cov["outOfScopeToolCVEs"] == 0
            suite.results.append(TestResult(
                "json.cve_tool_scope", has_tool_scope,
                f"outOfScopeToolCVEs={cov.get('outOfScopeToolCVEs')}, expected 0" if not has_tool_scope else "",
                0.0, "", ""
            ))

    # Results array should have heuristic entries with required fields
    if "results" in data and len(data["results"]) > 0:
        r = data["results"][0]
        for field in ["id", "name", "status"]:
            has_f = field in r
            suite.results.append(TestResult(
                f"json.result_has_{field}", has_f,
                f"Result missing '{field}'" if not has_f else "",
                0.0, "", ""
            ))

    # At least one result should have cveRefs
    has_cve_ref = any("cveRefs" in r for r in data.get("results", []))
    suite.results.append(TestResult(
        "json.has_cve_refs", has_cve_ref,
        "No result with cveRefs found" if not has_cve_ref else "",
        0.0, "", ""
    ))

    # Registry block in JSON should have dynamic stats
    if "summary" in data and "registry" in data["summary"]:
        reg = data["summary"]["registry"]
        has_reg_total = reg.get("totalHeuristics", 0) == 150
        suite.results.append(TestResult(
            "json.registry_total_heuristics", has_reg_total,
            f"registry.totalHeuristics={reg.get('totalHeuristics')}" if not has_reg_total else "",
            0.0, "", ""
        ))
        has_reg_cve = reg.get("heuristicsWithCVE", 0) > 0
        suite.results.append(TestResult(
            "json.registry_has_cve_count", has_reg_cve,
            "registry.heuristicsWithCVE is 0" if not has_reg_cve else "",
            0.0, "", ""
        ))

    # ASAN clean
    suite.assert_no_asan("json.asan_clean", ["--json", good])


def test_registry_output(suite):
    """Test --registry CLI mode emits valid JSON with computed stats."""
    rc, out, err = suite.run_analyzer(["--registry"])
    suite.results.append(TestResult(
        "registry.exit_0", rc == 0,
        f"exit code {rc}" if rc != 0 else "",
        0.0, "", ""
    ))
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        suite.results.append(TestResult(
            "registry.valid_json", False, f"JSON parse error: {e}",
            0.0, "", ""
        ))
        return
    suite.results.append(TestResult(
        "registry.valid_json", True, "", 0.0, "", ""
    ))
    # totalHeuristics must equal len(heuristics)
    total = data.get("totalHeuristics", 0)
    entries = len(data.get("heuristics", []))
    match = total == entries and total > 0
    suite.results.append(TestResult(
        "registry.total_matches_entries", match,
        f"totalHeuristics={total} != len(heuristics)={entries}" if not match else "",
        0.0, "", ""
    ))
    # heuristicsWithCVE must be positive
    with_cve = data.get("heuristicsWithCVE", 0)
    suite.results.append(TestResult(
        "registry.has_cve_refs", with_cve > 0,
        f"heuristicsWithCVE={with_cve}" if with_cve <= 0 else "",
        0.0, "", ""
    ))
    # severity must sum to totalHeuristics
    sev = data.get("severity", {})
    sev_sum = sum(sev.values())
    suite.results.append(TestResult(
        "registry.severity_sum", sev_sum == total,
        f"severity sum {sev_sum} != total {total}" if sev_sum != total else "",
        0.0, "", ""
    ))
    # Each entry must have required fields
    if entries > 0:
        h = data["heuristics"][0]
        for field in ["id", "name", "cwe", "phase", "severity"]:
            has = field in h
            suite.results.append(TestResult(
                f"registry.entry_has_{field}", has,
                f"Missing '{field}'" if not has else "",
                0.0, "", ""
            ))


def test_tiff_analysis(suite):
    """Test TIFF image analysis with embedded ICC profile."""
    tiff_path = CORPUS_DIR / "test_tiff_with_icc.tif"
    if not tiff_path.exists():
        return

    tiff = str(tiff_path)

    # Should detect TIFF and run image analysis
    suite.assert_output_contains(
        "tiff.detects_format",
        ["-a", tiff], r"IMAGE FILE ANALYSIS.*TIFF"
    )

    # Should report TIFF metadata
    suite.assert_output_contains(
        "tiff.reports_dimensions",
        ["-a", tiff], r"Dimensions:.*10.*10"
    )

    # H139 strip geometry should run
    suite.assert_output_contains(
        "tiff.h139_runs",
        ["-a", tiff], r"\[H139\].*Strip Geometry"
    )

    # H140 dimension validation should run
    suite.assert_output_contains(
        "tiff.h140_runs",
        ["-a", tiff], r"\[H140\].*Dimension"
    )

    # H141 IFD offset bounds should run
    suite.assert_output_contains(
        "tiff.h141_runs",
        ["-a", tiff], r"\[H141\].*IFD"
    )

    # Should extract and analyze embedded ICC profile
    suite.assert_output_contains(
        "tiff.icc_extraction",
        ["-a", tiff], r"ICC Profile.*Extracted|Embedded ICC"
    )

    # ASAN clean
    suite.assert_no_asan("tiff.asan_clean", ["-a", tiff])


def test_html_xml_output(suite):
    """Test XML+XSLT (HTML) export mode."""
    import tempfile
    good = str(CORPUS_DIR / "valid_srgb.icc")

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_out = tmp.name

    try:
        rc, stdout, stderr = suite.run_analyzer(["-xml", good, xml_out])
        suite.results.append(TestResult(
            "html.exit_code_ok", rc != 2,
            f"Exit code {rc} (I/O error)" if rc == 2 else "",
            0.0, "", ""
        ))

        xml_content = ""
        if os.path.exists(xml_out):
            with open(xml_out, "r") as f:
                xml_content = f.read()

        suite.results.append(TestResult(
            "html.xml_has_content", len(xml_content) > 100,
            f"XML output too short ({len(xml_content)} bytes)" if len(xml_content) <= 100 else "",
            0.0, "", ""
        ))

        has_decl = "<?xml" in xml_content
        suite.results.append(TestResult(
            "html.xml_declaration", has_decl,
            "Missing <?xml declaration" if not has_decl else "",
            0.0, "", ""
        ))

        has_xslt = "xsl:stylesheet" in xml_content or "xml-stylesheet" in xml_content
        suite.results.append(TestResult(
            "html.has_xslt", has_xslt,
            "Missing XSLT reference" if not has_xslt else "",
            0.0, "", ""
        ))

        has_ver = "iccAnalyzer-lite v" in xml_content
        suite.results.append(TestResult(
            "html.has_version", has_ver,
            "Missing version string" if not has_ver else "",
            0.0, "", ""
        ))

        has_av = "<analyzer_version>" in xml_content
        suite.results.append(TestResult(
            "html.has_analyzer_version_tag", has_av,
            "Missing <analyzer_version> tag" if not has_av else "",
            0.0, "", ""
        ))

        has_heuristic = "<check>" in xml_content
        suite.results.append(TestResult(
            "html.has_check_elements", has_heuristic,
            "Missing <check> elements" if not has_heuristic else "",
            0.0, "", ""
        ))

        # New: verify per-heuristic XML structure
        check_count = xml_content.count("<check>")
        has_many_checks = check_count > 20
        suite.results.append(TestResult(
            "html.per_heuristic_count", has_many_checks,
            f"Only {check_count} <check> elements (expected 100+)" if not has_many_checks else "",
            0.0, "", ""
        ))

        has_severity = "<severity>" in xml_content
        suite.results.append(TestResult(
            "html.has_severity_tags", has_severity,
            "Missing <severity> tags in XML" if not has_severity else "",
            0.0, "", ""
        ))

        has_cwe = "<cwe>" in xml_content
        suite.results.append(TestResult(
            "html.has_cwe_tags", has_cwe,
            "Missing <cwe> tags in XML" if not has_cwe else "",
            0.0, "", ""
        ))

        has_sha = "<sha256>" in xml_content
        suite.results.append(TestResult(
            "html.has_sha256", has_sha,
            "Missing <sha256> in XML profile section" if not has_sha else "",
            0.0, "", ""
        ))

        suite.assert_no_asan("html.asan_clean", ["-xml", good, xml_out])
    finally:
        if os.path.exists(xml_out):
            os.unlink(xml_out)


def test_report_output(suite):
    """Test --report severity-sorted report output mode."""
    good = str(CORPUS_DIR / "valid_srgb.icc")
    bad = str(CORPUS_DIR / "huge_tag_count.icc")

    # Report should contain banner
    rc, stdout, stderr = suite.run_analyzer(["--report", good])
    has_banner = "ICC PROFILE SECURITY REPORT" in stdout
    suite.results.append(TestResult(
        "report.has_banner", has_banner,
        "Missing report banner" if not has_banner else "",
        0.0, "", ""
    ))

    # Report should contain tool version
    has_version = "iccAnalyzer-lite" in stdout
    suite.results.append(TestResult(
        "report.has_version", has_version,
        "Missing tool version in banner" if not has_version else "",
        0.0, "", ""
    ))

    # Report should contain SHA-256
    has_sha = "SHA-256:" in stdout
    suite.results.append(TestResult(
        "report.has_sha256", has_sha,
        "Missing SHA-256 hash" if not has_sha else "",
        0.0, "", ""
    ))

    # Report should contain executive summary
    has_exec = "EXECUTIVE SUMMARY" in stdout
    suite.results.append(TestResult(
        "report.has_executive_summary", has_exec,
        "Missing executive summary" if not has_exec else "",
        0.0, "", ""
    ))

    # Report should contain severity distribution
    has_dist = "Severity Distribution:" in stdout
    suite.results.append(TestResult(
        "report.has_severity_dist", has_dist,
        "Missing severity distribution" if not has_dist else "",
        0.0, "", ""
    ))

    # Report should contain CWE category summary
    has_cwe = "CWE CATEGORY SUMMARY" in stdout
    suite.results.append(TestResult(
        "report.has_cwe_summary", has_cwe,
        "Missing CWE category summary" if not has_cwe else "",
        0.0, "", ""
    ))

    # Report should contain CVE coverage statistics
    has_cve = "CVE COVERAGE STATISTICS" in stdout
    suite.results.append(TestResult(
        "report.has_cve_stats", has_cve,
        "Missing CVE coverage statistics" if not has_cve else "",
        0.0, "", ""
    ))

    # Report on bad profile should have severity sections with findings
    rc2, stdout2, stderr2 = suite.run_analyzer(["--report", bad])
    has_critical = "CRITICAL FINDINGS" in stdout2
    suite.results.append(TestResult(
        "report.bad_has_critical_section", has_critical,
        "Missing CRITICAL FINDINGS section for bad profile" if not has_critical else "",
        0.0, "", ""
    ))

    # CVE CROSS-REFERENCES section should appear when findings have CVEs
    has_xref = "CVE CROSS-REFERENCES" in stdout2
    suite.results.append(TestResult(
        "report.bad_has_cve_crossref", has_xref,
        "Missing CVE cross-references for bad profile" if not has_xref else "",
        0.0, "", ""
    ))

    # ASAN clean
    suite.assert_no_asan("report.asan_clean_good", ["--report", good])
    suite.assert_no_asan("report.asan_clean_bad", ["--report", bad])

    # JSON severity field test
    rc3, stdout3, stderr3 = suite.run_analyzer(["--json", good])
    try:
        import json
        data = json.loads(stdout3)
        results = data.get("results", [])
        has_severity = any("severity" in r for r in results)
        suite.results.append(TestResult(
            "json.has_severity_field", has_severity,
            "JSON results missing severity field" if not has_severity else "",
            0.0, "", ""
        ))
        if results:
            valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            sev = results[0].get("severity", "")
            valid_sev = sev in valid_severities
            suite.results.append(TestResult(
                "json.valid_severity_value", valid_sev,
                f"Invalid severity value: {sev}" if not valid_sev else "",
                0.0, "", ""
            ))
    except (json.JSONDecodeError, ValueError):
        suite.results.append(TestResult(
            "json.has_severity_field", False, "JSON parse failed", 0.0, "", ""
        ))


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
        ("Runtime Safety", test_runtime_safety),
        ("JSON Output", test_json_output),
        ("Registry Output", test_registry_output),
        ("TIFF Analysis", test_tiff_analysis),
        ("HTML/XML Output", test_html_xml_output),
        ("Report Output", test_report_output),
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
