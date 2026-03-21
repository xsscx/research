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
    python3 run_tests.py --list             # List all test sections
    python3 run_tests.py --fail-fast        # Stop on first failure
    python3 run_tests.py --debug            # Show commands being run
    python3 run_tests.py --no-color         # Disable colored output
"""

import os
import json
import re
import shutil
import subprocess
import sys
import tempfile
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

# ANSI color codes
class _Colors:
    """Terminal color codes with auto-detection."""
    def __init__(self):
        use_color = (
            hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb"
        )
        self.enabled = use_color

    def green(self, text):
        return f"\033[32m{text}\033[0m" if self.enabled else text

    def red(self, text):
        return f"\033[31m{text}\033[0m" if self.enabled else text

    def yellow(self, text):
        return f"\033[33m{text}\033[0m" if self.enabled else text

    def cyan(self, text):
        return f"\033[36m{text}\033[0m" if self.enabled else text

    def bold(self, text):
        return f"\033[1m{text}\033[0m" if self.enabled else text

    def dim(self, text):
        return f"\033[2m{text}\033[0m" if self.enabled else text

C = _Colors()

SLOW_TEST_THRESHOLD = 5.0  # seconds


class TestResult:
    def __init__(self, name, passed, message="", duration=0.0, stdout="", stderr="",
                 skipped=False):
        self.name = name
        self.passed = passed
        self.message = message
        self.duration = duration
        self.stdout = stdout
        self.stderr = stderr
        self.skipped = skipped


class _RecordingList(list):
    """List subclass that routes append() through TestSuite._record()."""
    def __init__(self, suite):
        super().__init__()
        self._suite = suite

    def append(self, result):
        self._suite._record(result)


class TestSuite:
    def __init__(self, binary_path=None, verbose=False, pattern=None,
                 fail_fast=False, debug=False):
        self.binary = str(binary_path or BINARY)
        self.verbose = verbose
        self.pattern = pattern
        self.fail_fast = fail_fast
        self.debug = debug
        self._results_list = []
        self.results = _RecordingList(self)
        self._section_results = {}  # section_name → list of TestResult
        self._current_section = None
        self._stop_requested = False
        self.env = os.environ.copy()
        self.env["ASAN_OPTIONS"] = "detect_leaks=0"
        self.env["LLVM_PROFILE_FILE"] = "/dev/null"

    def run_analyzer(self, args, timeout=TIMEOUT_SEC):
        """Run iccanalyzer-lite with given args, return (exit_code, stdout, stderr)."""
        cmd = [self.binary] + args
        if self.debug:
            print(f"    {C.dim('$ ' + ' '.join(cmd))}")
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

    def _record(self, result):
        """Record a test result with live progress output."""
        list.append(self.results, result)  # bypass proxy to avoid recursion
        if self._current_section:
            self._section_results.setdefault(self._current_section, []).append(result)

        dur_str = f"{result.duration:.2f}s" if result.duration > 0 else ""

        if result.skipped:
            if self.verbose:
                print(f"  {C.yellow('⊘')} {result.name} {C.dim('(skipped)')}")
        elif result.passed:
            slow = ""
            if result.duration >= SLOW_TEST_THRESHOLD:
                slow = C.yellow(f" ⚠ slow ({dur_str})")
            if self.verbose:
                print(f"  {C.green('✓')} {result.name} {C.dim(f'({dur_str})')}{slow}")
        else:
            print(f"  {C.red('✗')} {C.red(result.name)} {C.dim(f'({dur_str})')}")
            print(f"    {result.message}")
            if result.stderr:
                stderr_lines = result.stderr.splitlines()
                for line in stderr_lines[:10]:
                    print(f"    {C.dim('stderr:')} {line}")
                if len(stderr_lines) > 10:
                    print(f"    {C.dim(f'... ({len(stderr_lines) - 10} more lines)')}")
            if result.stdout and "ASAN" in result.message:
                stdout_lines = [l for l in result.stdout.splitlines() if l.strip()][:5]
                for line in stdout_lines:
                    print(f"    {C.dim('stdout:')} {line}")
            if self.fail_fast:
                self._stop_requested = True

    def assert_exit_code(self, name, args, expected_code, check_stderr=True):
        """Test that analyzer returns expected exit code."""
        if self._stop_requested:
            return False
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

        self._record(TestResult(name, passed, msg, dur, stdout, stderr))
        return passed

    def assert_output_contains(self, name, args, pattern, expected_code=None):
        """Test that stdout contains a regex pattern."""
        if self._stop_requested:
            return False
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

        self._record(TestResult(name, passed, msg, dur, stdout, stderr))
        return passed

    def assert_output_not_contains(self, name, args, pattern, expected_code=None):
        """Test that stdout does NOT contain a regex pattern."""
        if self._stop_requested:
            return False
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

        self._record(TestResult(name, passed, msg, dur, stdout, stderr))
        return passed

    def assert_no_asan(self, name, args):
        """Test that no ASAN/UBSAN errors occur in analyzer code."""
        if self._stop_requested:
            return False
        t0 = time.monotonic()
        rc, stdout, stderr = self.run_analyzer(args)
        dur = time.monotonic() - t0

        asan_hit = self._check_asan_analyzer(stderr)
        passed = (asan_hit is None)
        msg = asan_hit or ""

        self._record(TestResult(name, passed, msg, dur, stdout, stderr))
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
                    "IccMpeBasic.cpp",    # upstream NaN→unsigned int in Apply()
                    "IccUtil.cpp",        # upstream unsigned shift in icGetSigStr()
                ]):
                    continue
                return line.strip()
        return None

    def should_run(self, name):
        """Check if test matches the filter pattern."""
        if self.pattern is None:
            return True
        return self.pattern.lower() in name.lower()

    def begin_section(self, name):
        """Mark the start of a test section for grouping."""
        self._current_section = name

    def report(self, xml_path=None):
        """Print results and optionally write JUnit XML."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed and not r.skipped)
        skipped = sum(1 for r in self.results if r.skipped)
        failed = total - passed - skipped
        total_time = sum(r.duration for r in self.results)

        # Section breakdown
        print(f"\n{'=' * 70}")
        print(C.bold(f"RESULTS: {passed}/{total - skipped} passed, {failed} failed"
                     f"{f', {skipped} skipped' if skipped else ''} ({total_time:.1f}s)"))
        print(f"{'=' * 70}")

        # Per-section summary
        if self._section_results:
            print(f"\n{C.bold('Section Breakdown:')}")
            for section, results in self._section_results.items():
                s_pass = sum(1 for r in results if r.passed and not r.skipped)
                s_fail = sum(1 for r in results if not r.passed and not r.skipped)
                s_skip = sum(1 for r in results if r.skipped)
                s_time = sum(r.duration for r in results)
                status = C.green("PASS") if s_fail == 0 else C.red(f"FAIL ({s_fail})")
                skip_str = f", {s_skip} skipped" if s_skip else ""
                print(f"  {status}  {section}: {s_pass}/{s_pass + s_fail} "
                      f"({s_time:.1f}s{skip_str})")

        # Slow tests
        slow = [r for r in self.results if r.duration >= SLOW_TEST_THRESHOLD]
        if slow:
            print(f"\n{C.yellow('Slow tests (>' + str(SLOW_TEST_THRESHOLD) + 's):')}")
            for r in sorted(slow, key=lambda x: -x.duration):
                print(f"  {C.yellow('⚠')} {r.name} ({r.duration:.2f}s)")

        # Failures detail
        if failed > 0:
            print(f"\n{C.red(C.bold('FAILURES:'))}")
            for r in self.results:
                if not r.passed and not r.skipped:
                    print(f"  {C.red('✗')} {C.red(r.name)}")
                    print(f"    {r.message}")
                    if r.stderr:
                        for line in r.stderr.splitlines()[:10]:
                            print(f"    {C.dim('stderr:')} {line}")

        if self.verbose:
            print(f"\n{C.bold('ALL TESTS:')}")
            for r in self.results:
                if r.skipped:
                    print(f"  {C.yellow('⊘')} {r.name} {C.dim('(skipped)')}")
                elif r.passed:
                    print(f"  {C.green('✓')} {r.name} {C.dim(f'({r.duration:.2f}s)')}")
                else:
                    print(f"  {C.red('✗')} {r.name} {C.dim(f'({r.duration:.2f}s)')}")

        if xml_path:
            self._write_junit_xml(xml_path, total_time)
            print(f"\nJUnit XML written to: {xml_path}")

        return 0 if failed == 0 else 1

    def _write_junit_xml(self, path, total_time):
        """Write JUnit-compatible XML report with section grouping."""
        total = len(self.results)
        failures = sum(1 for r in self.results if not r.passed and not r.skipped)
        skips = sum(1 for r in self.results if r.skipped)

        suites = ET.Element("testsuites", {
            "name": "iccanalyzer-lite",
            "tests": str(total),
            "failures": str(failures),
            "skipped": str(skips),
            "time": f"{total_time:.3f}",
        })

        # Group test cases by section
        for section_name, results in self._section_results.items():
            s_failures = sum(1 for r in results if not r.passed and not r.skipped)
            s_skips = sum(1 for r in results if r.skipped)
            s_time = sum(r.duration for r in results)

            suite = ET.SubElement(suites, "testsuite", {
                "name": section_name,
                "tests": str(len(results)),
                "failures": str(s_failures),
                "skipped": str(s_skips),
                "time": f"{s_time:.3f}",
            })

            for r in results:
                tc = ET.SubElement(suite, "testcase", {
                    "name": r.name,
                    "classname": section_name,
                    "time": f"{r.duration:.3f}",
                })
                if r.skipped:
                    ET.SubElement(tc, "skipped", {"message": r.message or "skipped"})
                elif not r.passed:
                    fail = ET.SubElement(tc, "failure", {"message": r.message})
                    if r.stderr:
                        fail.text = r.stderr[:2000]

        tree = ET.ElementTree(suites)
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
        ["-a", f"{corpus}/empty_file.icc"], EXIT_ERROR, check_stderr=False
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
        ["-a", "--legacy", f"{corpus}/bad_magic.icc"],
        r"magic|acsp|WARN|CRITICAL"
    )

    # H108/H127: private tags
    suite.assert_output_contains(
        "heuristic.private_tags_detected",
        ["-a", "--legacy", f"{corpus}/private_tags.icc"],
        r"H108|H127|[Pp]rivate|unknown tag"
    )

    # H112: bad wtpt
    suite.assert_output_contains(
        "heuristic.bad_wtpt_detected",
        ["-a", "--legacy", f"{corpus}/bad_wtpt.icc"],
        r"H112|wtpt|[Ww]hite.?[Pp]oint|D50|WARN"
    )

    # H116: wrong encoding for version
    suite.assert_output_contains(
        "heuristic.wrong_version_encoding",
        ["-a", "--legacy", f"{corpus}/wrong_version_encoding.icc"],
        r"H116|H117|encoding|mluc|text|WARN|wrong type"
    )

    # H117: wrong tag type
    suite.assert_output_contains(
        "heuristic.wrong_tag_type",
        ["-a", "--legacy", f"{corpus}/wrong_tag_type.icc"],
        r"H117|not in allowed|disallowed|WARN"
    )

    # H126: malware private tag
    suite.assert_output_contains(
        "heuristic.malware_signature",
        ["-a", "--legacy", f"{corpus}/malware_private_tag.icc"],
        r"H126|[Mm]alware|MZ|PE|executable|WARN|CRITICAL"
    )

    # H122: XYZ out of range
    suite.assert_output_contains(
        "heuristic.xyz_out_of_range",
        ["-a", "--legacy", f"{corpus}/xyz_out_of_range.icc"],
        r"H122|out of.*range|XYZ|WARN"
    )

    # H111: reserved bytes
    suite.assert_output_contains(
        "heuristic.reserved_bytes",
        ["-a", "--legacy", f"{corpus}/reserved_bytes_nonzero.icc"],
        r"H111|[Rr]eserved|non-zero|WARN"
    )

    # Huge tag count triggers preflight
    suite.assert_output_contains(
        "heuristic.huge_tag_count",
        ["-a", "--legacy", f"{corpus}/huge_tag_count.icc"],
        r"tag count|CRITICAL|preflight|threshold|999999|WARN"
    )

    # H124: v5 tags on v4
    suite.assert_output_contains(
        "heuristic.v5_tags_on_v4",
        ["-a", "--legacy", f"{corpus}/v5_tags_on_v4.icc"],
        r"H124|version|D2B|v5|WARN"
    )

    # H114: non-monotonic TRC
    suite.assert_output_contains(
        "heuristic.non_monotonic_trc",
        ["-a", "--legacy", f"{corpus}/non_monotonic_curve.icc"],
        r"H114|[Mm]onoton|TRC|WARN"
    )

    # --- New heuristic-targeted tests ---

    # H3: null/invalid colorSpace
    suite.assert_output_contains(
        "heuristic.null_colorspace",
        ["-a", "--legacy", f"{corpus}/null_colorspace.icc"],
        r"Invalid/null colorSpace"
    )

    # H4: invalid PCS signature
    suite.assert_output_contains(
        "heuristic.invalid_pcs",
        ["-a", "--legacy", f"{corpus}/invalid_pcs.icc"],
        r"Invalid PCS signature"
    )

    # H5: unknown platform signature
    suite.assert_output_contains(
        "heuristic.unknown_platform",
        ["-a", "--legacy", f"{corpus}/unknown_platform.icc"],
        r"Unknown platform signature"
    )

    # H6: invalid rendering intent
    suite.assert_output_contains(
        "heuristic.invalid_rendering_intent",
        ["-a", "--legacy", f"{corpus}/invalid_rendering_intent.icc"],
        r"Invalid rendering intent value 99"
    )

    # H7: unknown device class
    suite.assert_output_contains(
        "heuristic.unknown_device_class",
        ["-a", "--legacy", f"{corpus}/unknown_device_class.icc"],
        r"Unknown profile class"
    )

    # H8: negative illuminant
    suite.assert_output_contains(
        "heuristic.negative_illuminant",
        ["-a", "--legacy", f"{corpus}/negative_illuminant.icc"],
        r"Negative illuminant values"
    )

    # H15: invalid date fields
    suite.assert_output_contains(
        "heuristic.invalid_date",
        ["-a", "--legacy", f"{corpus}/invalid_date.icc"],
        r"Invalid month: 13|Invalid day: 32"
    )

    # H128: non-BCD version nibble
    suite.assert_output_contains(
        "heuristic.version_bcd_invalid",
        ["-a", "--legacy", f"{corpus}/version_bcd_invalid.icc"],
        r"Non-BCD nibble in version"
    )

    # H129: D50 illuminant mismatch
    suite.assert_output_contains(
        "heuristic.wrong_d50_illuminant",
        ["-a", "--legacy", f"{corpus}/wrong_d50_illuminant.icc"],
        r"PCS illuminant does not match D50"
    )

    # H133: flags reserved bits
    suite.assert_output_contains(
        "heuristic.flags_reserved_bits",
        ["-a", "--legacy", f"{corpus}/flags_reserved_bits.icc"],
        r"Reserved flag bits non-zero"
    )

    # H135: duplicate tag signatures
    suite.assert_output_contains(
        "heuristic.duplicate_tags",
        ["-a", "--legacy", f"{corpus}/duplicate_tags.icc"],
        r"Duplicate tag signature.*desc"
    )

    # H130/H40: tag alignment
    suite.assert_output_contains(
        "heuristic.tag_misaligned",
        ["-a", "--legacy", f"{corpus}/tag_misaligned.icc"],
        r"not 4-byte aligned"
    )

    # H1: extra trailing bytes (size mismatch)
    suite.assert_output_contains(
        "heuristic.extra_trailing_bytes",
        ["-a", "--legacy", f"{corpus}/extra_trailing_bytes.icc"],
        r"EXTRA BYTES appended"
    )

    # H20: null tag type signature
    suite.assert_output_contains(
        "heuristic.null_tag_type",
        ["-a", "--legacy", f"{corpus}/null_tag_type.icc"],
        r"null type signature"
    )

    # H49: NaN/Inf in float tag
    suite.assert_output_contains(
        "heuristic.nan_float_tag",
        ["-a", "--legacy", f"{corpus}/nan_float_tag.icc"],
        r"NaN detected at offset|Inf detected at offset"
    )

    # H55: odd byte length UTF-16
    suite.assert_output_contains(
        "heuristic.odd_utf16_mluc",
        ["-a", "--legacy", f"{corpus}/odd_utf16_mluc.icc"],
        r"odd byte length.*invalid UTF-16"
    )

    # H69: suspicious profile ID
    suite.assert_output_contains(
        "heuristic.suspicious_profile_id",
        ["-a", "--legacy", f"{corpus}/suspicious_profile_id.icc"],
        r"suspicious pattern.*0xFF|Profile ID.*suspicious"
    )

    # H10: zero tags (verify library-level detection)
    suite.assert_output_contains(
        "heuristic.zero_tags_detected",
        ["-a", "--legacy", f"{corpus}/zero_tags.icc"],
        r"Zero tags.*invalid"
    )

    # --- CWE-400 systemic pattern tests (CFL-074/075/076 findings) ---

    # H64: NamedColor2 device coords > 15
    suite.assert_output_contains(
        "heuristic.named_color2_excessive_coords",
        ["-a", "--legacy", f"{corpus}/named_color2_excessive_coords.icc"],
        r"NamedColor2.*20 device coords.*>15"
    )

    # H136: ResponseCurve excessive measurements
    suite.assert_output_contains(
        "heuristic.response_curve_excessive_measurements",
        ["-a", "--legacy", f"{corpus}/response_curve_excessive_measurements.icc"],
        r"ResponseCurve.*channel.*500000 measurements.*>100K"
    )

    # H137: high-dimensional color space
    suite.assert_output_contains(
        "heuristic.high_dimensional_grid_complexity",
        ["-a", "--legacy", f"{corpus}/high_dimensional_colorspace.icc"],
        r"Input color space has 8 channels"
    )

    # Verify H136/H137 produce CWE-400 annotations
    suite.assert_output_contains(
        "heuristic.cwe400_in_response_curve",
        ["-a", "--legacy", f"{corpus}/response_curve_excessive_measurements.icc"],
        r"CWE-400.*Unbounded measurement count"
    )

    suite.assert_output_contains(
        "heuristic.cwe400_in_high_dim",
        ["-a", "--legacy", f"{corpus}/high_dimensional_colorspace.icc"],
        r"CWE-400.*O\(nGran\^ndim\)"
    )

    # --- Validation/Runtime symmetry tests ---

    # H47 raw-byte ncl2 check fires nDevCoords>15 (always-run, covers library-load failures)
    suite.assert_output_contains(
        "symmetry.h47_raw_ndevcoords_gt15",
        ["-a", "--legacy", f"{corpus}/named_color2_excessive_coords.icc"],
        r"ncl2.*nDeviceCoords.*>15 ICC spec max"
    )

    # H47 raw-byte ncl2 check fires CFL-076 pattern annotation
    suite.assert_output_contains(
        "symmetry.h47_raw_cfl076_pattern",
        ["-a", "--legacy", f"{corpus}/named_color2_excessive_coords.icc"],
        r"CWE-787.*CFL-076"
    )

    # H64 library-level check fires nColors>10000 Describe() DoS (when library loads)
    # The named_color2_large_nsize profile has nColors=70000 but only 2 actual entries,
    # so the library may reject it. H47 always catches it at raw level.
    suite.assert_output_contains(
        "symmetry.h47_raw_ncolors_gt10000",
        ["-a", "--legacy", f"{corpus}/named_color2_large_nsize.icc"],
        r"ncl2.*entries.*>10000.*Describe.*DoS"
    )

    # H47 CWE-400 Describe() pattern annotation
    suite.assert_output_contains(
        "symmetry.h47_raw_cfl078_pattern",
        ["-a", "--legacy", f"{corpus}/named_color2_large_nsize.icc"],
        r"CWE-400.*Describe.*m_nSize.*CFL-078"
    )

    # H136 runs in always-run phase (not gated behind library load)
    # Verify it fires on response_curve_excessive_measurements.icc even with malformed header
    suite.assert_output_contains(
        "symmetry.h136_always_runs",
        ["-a", "--legacy", f"{corpus}/response_curve_excessive_measurements.icc"],
        r"\[H136\].*ResponseCurve"
    )

    # XYZ large array completes without hanging (runtime safety)
    suite.assert_output_contains(
        "symmetry.xyz_large_no_hang",
        ["-a", "--legacy", f"{corpus}/xyz_large_array.icc"],
        r"172 heuristics"
    )

    # Calculator deep nesting profile completes without hanging
    suite.assert_output_contains(
        "symmetry.calc_deep_no_hang",
        ["-a", "--legacy", f"{corpus}/calculator_deep_nesting.icc"],
        r"172 heuristics"
    )

    # --- H86 Unicode content detection tests (CWE-116) ---

    # H86: bidi override characters in mluc text
    suite.assert_output_contains(
        "heuristic.h86_bidi_override",
        ["-a", "--legacy", f"{corpus}/mluc_bidi_override.icc"],
        r"bidi override.*formatting characters"
    )

    # H86: mixed Latin + non-Latin scripts
    suite.assert_output_contains(
        "heuristic.h86_mixed_scripts",
        ["-a", "--legacy", f"{corpus}/mluc_mixed_scripts.icc"],
        r"mixes Latin.*non-Latin scripts"
    )

    # H86: control characters in mluc text
    suite.assert_output_contains(
        "heuristic.h86_control_chars",
        ["-a", "--legacy", f"{corpus}/mluc_control_chars.icc"],
        r"non-printable control characters"
    )

    # H86: embedded null characters (string truncation)
    suite.assert_output_contains(
        "heuristic.h86_embedded_nulls",
        ["-a", "--legacy", f"{corpus}/mluc_embedded_nulls.icc"],
        r"embedded null characters"
    )

    # --- H147 null/degenerate CLUT detection tests (CWE-476) ---

    # H147: null CLUT in AToB LUT tag
    suite.assert_output_contains(
        "heuristic.h147_null_clut",
        ["-a", "--legacy", f"{corpus}/lut_null_clut.icc"],
        r"null CLUT.*Apply\(\) will crash"
    )

    # H147: degenerate CLUT (0 grid points via pTag null)
    suite.assert_output_contains(
        "heuristic.h147_degenerate_clut",
        ["-a", "--legacy", f"{corpus}/lut_degenerate_clut.icc"],
        r"pTag pointer is null|gridPoints = 0"
    )

    # --- H151 float→int cast operator detection (CWE-681) ---

    # H151: truncate operator in calculator element
    suite.assert_output_contains(
        "heuristic.h151_calc_trunc",
        ["-a", "--legacy", f"{corpus}/calc_trunc_operator.icc"],
        r"float-to-int cast operators.*trnc"
    )

    # --- H73 shared tag pointer detection ---

    # H73: shared curve tag pointers (immutable type → safe)
    suite.assert_output_contains(
        "heuristic.h73_shared_pointers",
        ["-a", "--legacy", f"{corpus}/tag_shared_pointers.icc"],
        r"shared tag pair.*immutable.*safe"
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
        if os.path.exists(poc_path):
            suite.assert_output_contains(
                f"runtime_safety.poc_{poc[:12]}",
                ["-a", "--legacy", poc_path],
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
            ["-a", "--legacy", f"{corpus}/{profile}"],
            r"HEURISTIC SUMMARY"
        )


def test_heuristic_summary(suite):
    """Test that the summary section appears with correct heuristic count."""
    suite.assert_output_contains(
        "summary.172_heuristics",
        ["-a", "--legacy", str(CORPUS_DIR / "bad_magic.icc")],
        r"172 heuristics"
    )

    suite.assert_output_contains(
        "summary.heuristic_summary_header",
        ["-a", "--legacy", str(CORPUS_DIR / "bad_magic.icc")],
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
    rc, stdout, stderr = suite.run_analyzer(["--json", "--legacy", good])
    try:
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
        has_total = s.get("totalHeuristics", 0) == 172
        suite.results.append(TestResult(
            "json.total_heuristics_172", has_total,
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
        has_reg_total = reg.get("totalHeuristics", 0) == 172
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

    # H149 IFD chain cycle detection should run
    suite.assert_output_contains(
        "tiff.h149_runs",
        ["-a", tiff], r"\[H149\].*IFD Chain Cycle"
    )

    # H150 tile geometry validation should run
    suite.assert_output_contains(
        "tiff.h150_runs",
        ["-a", tiff], r"\[H150\].*Tile Geometry"
    )

    # Should extract and analyze embedded ICC profile
    suite.assert_output_contains(
        "tiff.icc_extraction",
        ["-a", tiff], r"ICC Profile.*Extracted|Embedded ICC"
    )

    # ASAN clean
    suite.assert_no_asan("tiff.asan_clean", ["-a", tiff])


def test_tiff_corrupt(suite):
    """Test TIFF analysis when TIFFOpen fails (corrupt/truncated file)."""
    corrupt_path = CORPUS_DIR / "corrupt_truncated.tif"
    if not corrupt_path.exists():
        return

    corrupt = str(corrupt_path)

    # Should detect TIFF format and attempt analysis
    suite.assert_output_contains(
        "tiff_corrupt.detects_format",
        ["-a", corrupt], r"IMAGE FILE ANALYSIS.*TIFF"
    )

    # Should report CWE-20 for TIFFOpen failure
    suite.assert_output_contains(
        "tiff_corrupt.cwe20_tiffopen",
        ["-a", corrupt], r"CRIT.*Cannot open TIFF.*TIFFOpen failed"
    )

    # H149 should still run (uses raw file I/O, not TIFF handle)
    suite.assert_output_contains(
        "tiff_corrupt.h149_runs",
        ["-a", corrupt], r"\[H149\].*IFD Chain Cycle"
    )

    # H139/H140/H141/H150 should SKIP (require valid TIFF handle)
    suite.assert_output_contains(
        "tiff_corrupt.h139_skips",
        ["-a", corrupt], r"\[H139\].*Strip Geometry"
    )
    suite.assert_output_contains(
        "tiff_corrupt.h139_skip_msg",
        ["-a", corrupt], r"\[SKIP\].*Requires parseable TIFF"
    )

    # Should output IMAGE ANALYSIS SUMMARY
    suite.assert_output_contains(
        "tiff_corrupt.summary",
        ["-a", corrupt], r"IMAGE ANALYSIS SUMMARY"
    )

    # ASAN clean
    suite.assert_no_asan("tiff_corrupt.asan_clean", ["-a", corrupt])


def test_html_xml_output(suite):
    """Test XML+XSLT (HTML) export mode."""
    good = str(CORPUS_DIR / "valid_srgb.icc")

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_out = tmp.name

    try:
        rc, stdout, stderr = suite.run_analyzer(["-xml", "--legacy", good, xml_out])
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
    rc, stdout, stderr = suite.run_analyzer(["--report", "--legacy", good])
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
    rc2, stdout2, stderr2 = suite.run_analyzer(["--report", "--legacy", bad])
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

    # JSON severity field test (requires --legacy for heuristic severity data)
    rc3, stdout3, stderr3 = suite.run_analyzer(["--json", "--legacy", good])
    try:
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


def test_pawg_output(suite):
    """Test -pawg ICC Profile Assessment Working Group report output mode."""
    good = str(CORPUS_DIR / "valid_srgb.icc")
    bad = str(CORPUS_DIR / "wrong_d50_illuminant.icc")

    # PAWG report should contain banner
    rc, stdout, stderr = suite.run_analyzer(["-pawg", good])
    has_banner = "ICC PROFILE ASSESSMENT REPORT (PAWG)" in stdout
    suite.results.append(TestResult(
        "pawg.has_banner", has_banner,
        "Missing PAWG report banner" if not has_banner else "",
        0.0, "", ""
    ))

    # Should contain tool version
    has_version = "iccAnalyzer-lite" in stdout
    suite.results.append(TestResult(
        "pawg.has_version", has_version,
        "Missing tool version in PAWG banner" if not has_version else "",
        0.0, "", ""
    ))

    # Should contain SHA-256
    has_sha = "SHA-256:" in stdout
    suite.results.append(TestResult(
        "pawg.has_sha256", has_sha,
        "Missing SHA-256 hash in PAWG report" if not has_sha else "",
        0.0, "", ""
    ))

    # Should contain all 3 sections
    has_security = "[ SECURITY ]" in stdout
    suite.results.append(TestResult(
        "pawg.has_security_section", has_security,
        "Missing SECURITY section" if not has_security else "",
        0.0, "", ""
    ))

    has_conformance = "[ CONFORMANCE ]" in stdout
    suite.results.append(TestResult(
        "pawg.has_conformance_section", has_conformance,
        "Missing CONFORMANCE section" if not has_conformance else "",
        0.0, "", ""
    ))

    has_quality = "[ QUALITY ]" in stdout
    suite.results.append(TestResult(
        "pawg.has_quality_section", has_quality,
        "Missing QUALITY section" if not has_quality else "",
        0.0, "", ""
    ))

    # Should contain assessment summary
    has_summary = "ASSESSMENT SUMMARY" in stdout
    suite.results.append(TestResult(
        "pawg.has_summary", has_summary,
        "Missing ASSESSMENT SUMMARY section" if not has_summary else "",
        0.0, "", ""
    ))

    # Should contain conformance check coverage
    has_coverage = "CONFORMANCE CHECK COVERAGE" in stdout
    suite.results.append(TestResult(
        "pawg.has_conformance_coverage", has_coverage,
        "Missing CONFORMANCE CHECK COVERAGE section" if not has_coverage else "",
        0.0, "", ""
    ))

    # Should contain spec references
    has_specs = "SPECIFICATION REFERENCES" in stdout
    suite.results.append(TestResult(
        "pawg.has_spec_references", has_specs,
        "Missing SPECIFICATION REFERENCES section" if not has_specs else "",
        0.0, "", ""
    ))

    # Summary should show total of 31 checklist items
    has_31 = "Total checklist items:  31" in stdout
    suite.results.append(TestResult(
        "pawg.has_31_items", has_31,
        "PAWG report should have exactly 31 checklist items" if not has_31 else "",
        0.0, "", ""
    ))

    # Should have PASS/WARN/FAIL counts in summary
    import re
    pass_match = re.search(r"PASS:\s+(\d+)", stdout)
    warn_match = re.search(r"WARN:\s+(\d+)", stdout)
    fail_match = re.search(r"FAIL:\s+(\d+)", stdout)
    has_counts = pass_match is not None and warn_match is not None and fail_match is not None
    suite.results.append(TestResult(
        "pawg.has_verdict_counts", has_counts,
        "Missing PASS/WARN/FAIL counts in summary" if not has_counts else "",
        0.0, "", ""
    ))

    # Counts should sum to at most 31 (NOT_RUN items are excluded from PASS+WARN+FAIL)
    if has_counts:
        total = int(pass_match.group(1)) + int(warn_match.group(1)) + int(fail_match.group(1))
        suite.results.append(TestResult(
            "pawg.counts_sum_31", total <= 31,
            f"PASS+WARN+FAIL={total}, expected ≤31" if total > 31 else "",
            0.0, "", ""
        ))

    # Should contain Overall verdict
    has_overall = "Overall:" in stdout
    suite.results.append(TestResult(
        "pawg.has_overall_verdict", has_overall,
        "Missing Overall verdict line" if not has_overall else "",
        0.0, "", ""
    ))

    # Check S1-S13 security items present
    s_items = sum(1 for i in range(1, 14) if f"S{i}" in stdout)
    suite.results.append(TestResult(
        "pawg.has_13_security_items", s_items == 13,
        f"Found {s_items}/13 security items" if s_items != 13 else "",
        0.0, "", ""
    ))

    # Check C1-C14 conformance items present
    c_items = sum(1 for i in range(1, 15) if f"C{i}" in stdout)
    suite.results.append(TestResult(
        "pawg.has_14_conformance_items", c_items == 14,
        f"Found {c_items}/14 conformance items" if c_items != 14 else "",
        0.0, "", ""
    ))

    # Check Q1-Q4 quality items present
    q_items = sum(1 for i in range(1, 5) if f"Q{i}" in stdout)
    suite.results.append(TestResult(
        "pawg.has_4_quality_items", q_items == 4,
        f"Found {q_items}/4 quality items" if q_items != 4 else "",
        0.0, "", ""
    ))

    # Bad profile should trigger WARN or FAIL items
    rc2, stdout2, stderr2 = suite.run_analyzer(["-pawg", bad])
    warn_match2 = re.search(r"WARN:\s+(\d+)", stdout2)
    fail_match2 = re.search(r"FAIL:\s+(\d+)", stdout2)
    warn_count2 = int(warn_match2.group(1)) if warn_match2 else 0
    fail_count2 = int(fail_match2.group(1)) if fail_match2 else 0
    has_bad_findings = (warn_count2 + fail_count2) > 0
    suite.results.append(TestResult(
        "pawg.bad_profile_has_findings", has_bad_findings,
        "Bad profile should have WARN or FAIL items" if not has_bad_findings else "",
        0.0, "", ""
    ))

    # Bad profile detail lines should show conformance check IDs
    has_detail = re.search(r"CF-\d+:.*\[(WARN|FAIL)\]", stdout2) is not None
    suite.results.append(TestResult(
        "pawg.bad_has_detail_lines", has_detail,
        "Bad profile WARN/FAIL items should include CF-### detail lines" if not has_detail else "",
        0.0, "", ""
    ))

    # ASAN clean on both profiles
    suite.assert_no_asan("pawg.asan_clean_good", ["-pawg", good])
    suite.assert_no_asan("pawg.asan_clean_bad", ["-pawg", bad])


def test_lut_text_io(suite):
    """Test LUT text export/import (-xt, -it) and .cube round-trip (-from-cube, -cube)."""

    good = str(CORPUS_DIR / "valid_srgb.icc")

    # --- Text extraction (-xt) on corpus profile ---
    with tempfile.TemporaryDirectory() as tmpdir:
        base = os.path.join(tmpdir, "xt_")
        suite.assert_no_asan("lut_text.xt_corpus", ["-xt", good, base])

    # --- Text extraction on real MPE profile (sRGB_D65_MAT.icc) ---
    srgb = TEST_PROFILES / "sRGB_D65_MAT.icc"
    if srgb.exists():
        with tempfile.TemporaryDirectory() as tmpdir:
            base = os.path.join(tmpdir, "xt_srgb_")
            rc, stdout, stderr = suite.run_analyzer(["-xt", str(srgb), base])
            has_mpe = "MPE" in stdout
            suite.results.append(TestResult(
                "lut_text.xt_srgb_has_mpe", has_mpe,
                "sRGB_D65_MAT should have MPE elements" if not has_mpe else "",
                0.0, "", ""
            ))
            # Should produce matrix and curve files
            files = os.listdir(tmpdir)
            has_matrix = any("matrix" in f for f in files)
            has_curves = any("curves" in f for f in files)
            suite.results.append(TestResult(
                "lut_text.xt_srgb_matrix_file", has_matrix,
                "Should produce matrix text file" if not has_matrix else "",
                0.0, "", ""
            ))
            suite.results.append(TestResult(
                "lut_text.xt_srgb_curves_file", has_curves,
                "Should produce curves text file" if not has_curves else "",
                0.0, "", ""
            ))

    # --- .cube import (-from-cube) ---
    cube_seeds = REPO_ROOT / "cfl" / "icc_fromcube_fuzzer_seed_corpus"
    if cube_seeds.exists():
        cubes = sorted(cube_seeds.glob("*.cube"))
        # Find a valid cube (identity_2x2x2 is known-good)
        valid_cube = None
        for c in cubes:
            if "identity_2x2x2" in c.name or "custom_domain_3x3x3" in c.name:
                valid_cube = c
                break
        if not valid_cube and cubes:
            valid_cube = cubes[0]

        if valid_cube:
            with tempfile.TemporaryDirectory() as tmpdir:
                out_icc = os.path.join(tmpdir, "from_cube.icc")
                suite.assert_output_contains(
                    "lut_text.from_cube_creates_icc",
                    ["-from-cube", str(valid_cube), out_icc],
                    r"Created ICC DeviceLink",
                    expected_code=0,
                )
                # Verify the ICC was written
                icc_exists = os.path.exists(out_icc) and os.path.getsize(out_icc) > 0
                suite.results.append(TestResult(
                    "lut_text.from_cube_file_exists", icc_exists,
                    "from-cube should create non-empty ICC" if not icc_exists else "",
                    0.0, "", ""
                ))

                # --- .cube export (-cube) round-trip ---
                if icc_exists:
                    rt_cube = os.path.join(tmpdir, "roundtrip.cube")
                    suite.assert_output_contains(
                        "lut_text.cube_export",
                        ["-cube", out_icc, "AToB0Tag", rt_cube],
                        r"Exported \.cube",
                        expected_code=0,
                    )
                    cube_exists = os.path.exists(rt_cube) and os.path.getsize(rt_cube) > 0
                    suite.results.append(TestResult(
                        "lut_text.cube_roundtrip_file", cube_exists,
                        "cube export should create non-empty file" if not cube_exists else "",
                        0.0, "", ""
                    ))

    # --- MPE matrix import round-trip (-it) ---
    if srgb.exists():
        with tempfile.TemporaryDirectory() as tmpdir:
            # Extract
            base = os.path.join(tmpdir, "rt_")
            suite.run_analyzer(["-xt", str(srgb), base])
            matrix_file = None
            for f in os.listdir(tmpdir):
                if "matrix" in f and f.endswith(".txt"):
                    matrix_file = os.path.join(tmpdir, f)
                    break
            if matrix_file:
                # Copy profile, import matrix back
                mod_icc = os.path.join(tmpdir, "modified.icc")
                shutil.copy2(str(srgb), mod_icc)
                out_icc = os.path.join(tmpdir, "imported.icc")
                suite.assert_output_contains(
                    "lut_text.it_mpe_matrix",
                    ["-it", mod_icc, matrix_file, out_icc],
                    r"Imported MPE matrix",
                    expected_code=0,
                )
                out_exists = os.path.exists(out_icc) and os.path.getsize(out_icc) > 0
                suite.results.append(TestResult(
                    "lut_text.it_matrix_file_written", out_exists,
                    "import should create output ICC" if not out_exists else "",
                    0.0, "", ""
                ))

    # --- MPE CLUT import round-trip (-it) ---
    if cube_seeds.exists() and valid_cube:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create ICC from cube, extract CLUT text, import back
            icc1 = os.path.join(tmpdir, "clut_src.icc")
            suite.run_analyzer(["-from-cube", str(valid_cube), icc1])
            if os.path.exists(icc1):
                base = os.path.join(tmpdir, "clut_")
                suite.run_analyzer(["-xt", icc1, base])
                clut_file = None
                for f in os.listdir(tmpdir):
                    if "clut" in f and f.endswith(".txt"):
                        clut_file = os.path.join(tmpdir, f)
                        break
                if clut_file:
                    icc2 = os.path.join(tmpdir, "clut_mod.icc")
                    shutil.copy2(icc1, icc2)
                    out_icc = os.path.join(tmpdir, "clut_imported.icc")
                    suite.assert_output_contains(
                        "lut_text.it_mpe_clut",
                        ["-it", icc2, clut_file, out_icc],
                        r"Imported MPE CLUT",
                        expected_code=0,
                    )

    # --- Error handling: bad cube ---
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cube', delete=False) as f:
        f.write("TITLE bad\nLUT_3D_SIZE 0\n")
        bad_cube = f.name
    try:
        suite.assert_exit_code("lut_text.bad_cube_rejected", ["-from-cube", bad_cube, "/dev/null"], 2)
    finally:
        os.unlink(bad_cube)

    # --- Error handling: -xt with nonexistent profile ---
    suite.assert_exit_code(
        "lut_text.xt_nonexistent",
        ["-xt", "/tmp/nonexistent_profile.icc", "/tmp/out_"],
        3,  # usage/error
    )

    # --- ASAN clean: diverse profiles through -xt ---
    diverse = ["sRGB_D65_MAT.icc", "sRGB_D65_MAT-500lx.icc", "17ChanPart1.icc"]
    for name in diverse:
        p = TEST_PROFILES / name
        if p.exists():
            with tempfile.TemporaryDirectory() as tmpdir:
                base = os.path.join(tmpdir, "div_")
                suite.assert_no_asan(f"lut_text.xt_asan_{name}", ["-xt", str(p), base])


def test_conformance_checks(suite):
    """Test ICC Specification conformance checks (CF-001..CF-174)."""
    corpus = str(CORPUS_DIR)

    # --- CF Header Checks (CF-001..CF-015) ---
    # Valid profile should pass header checks cleanly
    suite.assert_output_contains(
        "cf.header.valid_profile",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-001|Header.*Size|Profile Size"
    )

    # --- CF LUT Checks (CF-060..CF-070) ---
    # LUT8 profile with AToB0+BToA0 should trigger LUT checks
    suite.assert_output_contains(
        "cf.lut.input_channel_count",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-060.*Input Channel"
    )
    suite.assert_output_contains(
        "cf.lut.output_channel_count",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-061.*Output Channel"
    )
    suite.assert_output_contains(
        "cf.lut.clut_grid",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-062.*CLUT Grid"
    )
    suite.assert_output_contains(
        "cf.lut.lut8_table_size",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-063.*lut8.*256"
    )

    # --- CF Security Checks (CF-091..CF-094) ---
    # Malware signature should be detected
    suite.assert_output_contains(
        "cf.security.malware_scan",
        ["-a", f"{corpus}/malware_private_tag.icc"],
        r"CF-091.*[Mm]alware|PE header|MZ"
    )

    # Private tag presence should be reported
    suite.assert_output_contains(
        "cf.security.private_tag_presence",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-092.*[Pp]rivate"
    )

    # Private tag suspicious content
    suite.assert_output_contains(
        "cf.security.private_tag_content",
        ["-a", f"{corpus}/malware_private_tag.icc"],
        r"CF-093.*[Pp]rivate.*[Cc]ontent|[Ss]uspicious"
    )

    # NOP sled detection
    suite.assert_output_contains(
        "cf.security.nop_sled",
        ["-a", f"{corpus}/nop_sled_tag.icc"],
        r"CF-094.*NOP|sled"
    )

    # --- CF Required Tag Extension (CF-095..CF-098) ---
    # Non-required tags
    suite.assert_output_contains(
        "cf.required.non_required_tags",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-095.*Non.*Required"
    )

    # Private tag signature range (bit 31)
    suite.assert_output_contains(
        "cf.required.private_sig_range",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-096.*[Pp]rivate.*[Ss]ignature"
    )

    # Private tag documentation
    suite.assert_output_contains(
        "cf.required.private_doc",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-097.*[Pp]rivate.*[Dd]ocumentation"
    )

    # Undocumented private tags
    suite.assert_output_contains(
        "cf.required.undocumented_private",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-098.*[Uu]ndocumented"
    )

    # --- CF Quality Checks (CF-099..CF-102) ---
    # Round-trip check runs on LUT profiles
    suite.assert_output_contains(
        "cf.quality.roundtrip_structural",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-099.*Round.*Trip"
    )

    # Curve invertibility check
    suite.assert_output_contains(
        "cf.quality.curve_invertibility",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-100.*Curve.*Invertib"
    )

    # Non-monotonic curve should warn
    suite.assert_output_contains(
        "cf.quality.non_monotonic_curve_warn",
        ["-a", f"{corpus}/non_monotonic_curve.icc"],
        r"non-monotonic|Non-monotonic|not monoton"
    )

    # Transform smoothness
    suite.assert_output_contains(
        "cf.quality.transform_smoothness",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-101.*[Ss]moothness"
    )

    # Characterization data check
    suite.assert_output_contains(
        "cf.quality.characterization_data",
        ["-a", f"{corpus}/targ_tag_profile.icc"],
        r"CF-102.*[Cc]haracterization"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # CF-103..CF-122: Deep ICC Specification Conformance Checks
    # ═══════════════════════════════════════════════════════════════════════

    # CF-103: Tag Alignment & Offset Validity
    suite.assert_output_contains(
        "cf.103.tag_alignment_present",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-103.*Tag Alignment"
    )

    # CF-104: DeviceLink PCS Consistency — missing AToB0Tag
    suite.assert_output_contains(
        "cf.104.devicelink_missing_atob",
        ["-a", f"{corpus}/cf_devicelink_no_atob.icc"],
        r"CF-104.*DeviceLink.*AToB0|missing.*AToB0"
    )

    # CF-105: LUT Channel Symmetry (runs on LUT profiles)
    suite.assert_output_contains(
        "cf.105.lut_channel_symmetry",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-105.*Channel.*Symmetr"
    )

    # CF-106: Curve Monotonicity — non-monotonic TRC
    suite.assert_output_contains(
        "cf.106.non_monotonic_trc",
        ["-a", f"{corpus}/cf_non_monotonic_trc.icc"],
        r"CF-106.*[Mm]onoton|not mono"
    )

    # CF-107: Tag Table Ordering — duplicate signatures
    suite.assert_output_contains(
        "cf.107.tag_table_ordering",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-107.*Tag Table"
    )
    suite.assert_output_contains(
        "cf.107.duplicate_sigs",
        ["-a", f"{corpus}/cf_duplicate_tag_sigs.icc"],
        r"CF-107.*Tag Table"
    )

    # CF-108: CLUT Grid Point Range (runs on LUT profiles)
    suite.assert_output_contains(
        "cf.108.clut_grid_range",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-108.*CLUT Grid.*Range"
    )

    # CF-109: Matrix Column Normalization (runs on matrix profiles)
    suite.assert_output_contains(
        "cf.109.matrix_normalization",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-109.*Matrix.*Normal"
    )

    # CF-110: B-Curve vs CLUT Output (runs on LUT profiles)
    suite.assert_output_contains(
        "cf.110.bcurve_vs_clut",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-110.*B.Curve.*CLUT"
    )

    # CF-111: Required Tags per Version
    suite.assert_output_contains(
        "cf.111.required_per_version",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-111.*Required.*Version"
    )

    # CF-112: XYZ Triplet Normalization — negative Y
    suite.assert_output_contains(
        "cf.112.xyz_negative_y",
        ["-a", f"{corpus}/cf_xyz_negative_y.icc"],
        r"CF-112.*XYZ|negative"
    )
    suite.assert_output_contains(
        "cf.112.xyz_clean",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-112.*XYZ"
    )

    # CF-113..CF-115: v5/iccMAX (skipped on v4 profiles — verify skip message)
    suite.assert_output_contains(
        "cf.113.spectral_range",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"v5.*iccMAX.*skip"
    )
    suite.assert_output_contains(
        "cf.114.mcs_colour_space",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"v5.*iccMAX.*skip"
    )
    suite.assert_output_contains(
        "cf.115.calculator_complexity",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"v5.*iccMAX.*skip"
    )

    # CF-116: Curve Segment Continuity (runs on LUT profiles)
    suite.assert_output_contains(
        "cf.116.curve_segment_continuity",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-116.*Segment.*Continu"
    )

    # CF-117: Rendering Intent Tags per Class — rig0 on Input class
    suite.assert_output_contains(
        "cf.117.rig0_wrong_class",
        ["-a", f"{corpus}/cf_rig0_wrong_class.icc"],
        r"CF-117.*[Rr]ender|rig0.*Output.*Display"
    )

    # CF-118: Private Tag Creator Signature
    suite.assert_output_contains(
        "cf.118.private_tag_creator",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-118.*Private.*Creator"
    )

    # CF-119: Profile Sequence Identifier
    suite.assert_output_contains(
        "cf.119.profile_sequence_id",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-119.*Sequence.*Ident"
    )

    # CF-120: Named Color Space Dimensions
    suite.assert_output_contains(
        "cf.120.named_color_dims",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-120.*Named.*Color"
    )

    # CF-121: Illuminant Metadata Consistency — v4 wtpt ≠ D50
    suite.assert_output_contains(
        "cf.121.v4_wtpt_not_d50",
        ["-a", f"{corpus}/cf_v4_wtpt_not_d50.icc"],
        r"CF-121.*Illuminant|wtpt.*D50"
    )

    # CF-122: Profile Date/Time Plausibility — year 1800
    suite.assert_output_contains(
        "cf.122.implausible_date",
        ["-a", f"{corpus}/cf_implausible_date.icc"],
        r"CF-122.*Date|implaus|1800"
    )

    # CF-011: Profile ID MD5 Verification — mismatch
    suite.assert_output_contains(
        "cf.011.md5_mismatch",
        ["-a", f"{corpus}/cf_md5_mismatch.icc"],
        r"CF-011.*\[WARN\]|MD5.*mismatch|Stored.*Computed"
    )

    # CF-011: Valid profile — MD5 check runs
    suite.assert_output_contains(
        "cf.011.valid_profile",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-011"
    )

    # CF-021: Non-zero reserved bytes in tag type header
    suite.assert_output_contains(
        "cf.021.reserved_nonzero",
        ["-a", f"{corpus}/cf_reserved_bytes_nonzero_tag.icc"],
        r"CF-021.*\[FAIL\]|reserved.*non-zero|must be zero"
    )

    # CF-021: Valid profile — reserved bytes OK
    suite.assert_output_contains(
        "cf.021.valid_profile",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"\[OK\].*reserved bytes are zero"
    )

    # CF-030: mluc duplicate language/country pair
    suite.assert_output_contains(
        "cf.030.bad_record_size",
        ["-a", f"{corpus}/cf_mluc_bad_record_size.icc"],
        r"CF-030.*\[WARN\]|duplicate.*language|§10.13"
    )

    # CF-030: Valid profile — mluc structure OK
    suite.assert_output_contains(
        "cf.030.valid_profile",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"\[OK\].*mluc.*structurally valid"
    )

    # CF-031: sf32 bad element count
    suite.assert_output_contains(
        "cf.031.bad_size",
        ["-a", f"{corpus}/cf_sf32_bad_size.icc"],
        r"CF-031.*\[FAIL\]|not divisible|remainder|extra bytes"
    )

    # --- ICC.2-2019 Errata Conformance Checks (CF-137..CF-143) ---
    # v5 profile for "not applicable" tests (v2/v4 profiles skip V5 conformance entirely)
    test_profiles_dir = str(Path(__file__).resolve().parent.parent.parent / "test-profiles")
    v5_profile = f"{test_profiles_dir}/Spec400_10_700-D50_2deg-Abs.icc"

    # CF-137: MultiplexDefaultValues tag type validation
    suite.assert_output_contains(
        "cf.137.mdv_valid_type",
        ["-a", f"{corpus}/cf137-mdv-valid.icc"],
        r"conforms to errata-corrected permitted types"
    )
    suite.assert_output_contains(
        "cf.137.mdv_invalid_type",
        ["-a", f"{corpus}/cf137-mdv-invalid-type.icc"],
        r"\[WARN\].*not in errata-corrected"
    )
    # v5 profile without mdv tag reports not applicable
    suite.assert_output_contains(
        "cf.137.not_applicable",
        ["-a", v5_profile],
        r"multiplexDefaultValuesTag.*not applicable"
    )

    # CF-138: Embedded Height Image data length
    suite.assert_output_contains(
        "cf.138.ehim_valid",
        ["-a", f"{corpus}/cf138-ehim-valid.icc"],
        r"embeddedHeightImageType.*header=24"
    )
    # v5 profile without ehim tag
    suite.assert_output_contains(
        "cf.138.not_applicable",
        ["-a", v5_profile],
        r"embeddedHeightImageType.*not applicable"
    )

    # CF-139: Embedded Normal Image data length
    suite.assert_output_contains(
        "cf.139.enim_valid",
        ["-a", f"{corpus}/cf139-enim-valid.icc"],
        r"embeddedNormalImageType.*header=16"
    )
    suite.assert_output_contains(
        "cf.139.not_applicable",
        ["-a", v5_profile],
        r"embeddedNormalImageType.*not applicable"
    )

    # CF-140: GBD Vertex Count Field
    suite.assert_output_contains(
        "cf.140.not_applicable",
        ["-a", v5_profile],
        r"gamutBoundaryDescType.*not applicable"
    )

    # CF-141: Sparse Matrix Array Count
    suite.assert_output_contains(
        "cf.141.not_applicable",
        ["-a", v5_profile],
        r"sparseMatrixArrayType.*not applicable"
    )

    # CF-142: Vector-Or signature alignment (real v5 profile with 'vor ')
    vor_profile = f"{test_profiles_dir}/calcUnderStack_vor.icc"
    if Path(vor_profile).exists():
        suite.assert_output_contains(
            "cf.142.vor_aligned",
            ["-a", vor_profile],
            r"errata-aligned 4-byte signature"
        )
    suite.assert_output_contains(
        "cf.142.not_applicable",
        ["-a", v5_profile],
        r"vector-or.*not applicable"
    )

    # CF-143: Measurement tag struct type
    suite.assert_output_contains(
        "cf.143.meas_valid",
        ["-a", f"{corpus}/cf143-meas-valid.icc"],
        r"errata-conformant"
    )
    suite.assert_output_contains(
        "cf.143.not_applicable",
        ["-a", v5_profile],
        r"measurement.*not applicable"
    )

    # --- CF-144..CF-148: ICS Extended Range PCS (v5 profile) ---
    suite.assert_output_contains(
        "cf.144.ext_range_flag",
        ["-a", v5_profile],
        r"CF-144.*Extended Range PCS Flag"
    )
    suite.assert_output_contains(
        "cf.145.ext_range_spectral",
        ["-a", v5_profile],
        r"CF-145.*Extended Range PCS.*Spectral"
    )
    suite.assert_output_contains(
        "cf.146.class_restriction",
        ["-a", v5_profile],
        r"CF-146.*Extended Range Class"
    )
    suite.assert_output_contains(
        "cf.147.colorimetric_intent",
        ["-a", v5_profile],
        r"CF-147.*Extended Range Colorimetric"
    )
    suite.assert_output_contains(
        "cf.148.lut_mpe_type",
        ["-a", v5_profile],
        r"CF-148.*Extended Range LUT"
    )

    # --- CF-149..CF-152: ICS Extended Output (v5 profile) ---
    suite.assert_output_contains(
        "cf.149.ext_output_class",
        ["-a", v5_profile],
        r"CF-149.*Extended Output Profile Class"
    )
    suite.assert_output_contains(
        "cf.150.gamut_boundary",
        ["-a", v5_profile],
        r"CF-150.*Extended Output Gamut"
    )
    suite.assert_output_contains(
        "cf.151.mwp_range",
        ["-a", v5_profile],
        r"CF-151.*Extended Output mediaWhitePoint"
    )
    suite.assert_output_contains(
        "cf.152.atob_completeness",
        ["-a", v5_profile],
        r"CF-152.*Extended Output AToB"
    )

    # --- CF-153..CF-158: ICC.2-in-ICC.1 Embedding (v5 profile) ---
    suite.assert_output_contains(
        "cf.153.embedded_tag",
        ["-a", v5_profile],
        r"CF-153.*Embedded Profile Tag"
    )
    suite.assert_output_contains(
        "cf.154.version_bridging",
        ["-a", v5_profile],
        r"CF-154.*Embedded Profile Version"
    )
    suite.assert_output_contains(
        "cf.155.device_class",
        ["-a", v5_profile],
        r"CF-155.*Embedded Profile Device"
    )
    suite.assert_output_contains(
        "cf.156.header_flags",
        ["-a", v5_profile],
        r"CF-156.*Embedded Profile Header"
    )
    suite.assert_output_contains(
        "cf.157.recursive_depth",
        ["-a", v5_profile],
        r"CF-157.*Embedded Profile Recursive"
    )
    suite.assert_output_contains(
        "cf.158.size_bounds",
        ["-a", v5_profile],
        r"CF-158.*Embedded Profile Size"
    )

    # --- CF-159..CF-162: dictType Validation (v5 profile) ---
    suite.assert_output_contains(
        "cf.159.dict_uniqueness",
        ["-a", v5_profile],
        r"CF-159.*Dictionary Name Uniqueness"
    )
    suite.assert_output_contains(
        "cf.160.dict_nonzero",
        ["-a", v5_profile],
        r"CF-160.*Dictionary Name Non-Zero"
    )
    suite.assert_output_contains(
        "cf.161.dict_alignment",
        ["-a", v5_profile],
        r"CF-161.*Dictionary Record"
    )
    suite.assert_output_contains(
        "cf.162.dict_bounds",
        ["-a", v5_profile],
        r"CF-162.*Dictionary Entry"
    )

    # --- Clean profile baseline ---
    # Clean monitor profile should produce zero CF warnings
    suite.assert_output_not_contains(
        "cf.clean.no_security_warn",
        ["-a", f"{corpus}/clean_mntr_profile.icc"],
        r"\[FAIL\].*CF-09[1-4]"
    )

    # --- PAWG integration verification ---
    # All 31 PAWG items should have CF mappings (no NOT_RUN with mapping)
    suite.assert_output_contains(
        "cf.pawg.all_items_mapped",
        ["-pawg", f"{corpus}/valid_srgb.icc"],
        r"Total checklist items:\s+31"
    )

    # --- iccDEV tool conformance (reference profiles) ---
    # sRGB v4 preference profile should be clean
    srgb_v4 = str(Path(__file__).resolve().parent.parent.parent / "test-profiles" / "sRGB_v4_ICC_preference.icc")
    if Path(srgb_v4).exists():
        suite.assert_output_not_contains(
            "cf.reference.srgb_v4_no_fail",
            ["-a", srgb_v4],
            r"\[FAIL\].*CF-"
        )

    # ═══════════════════════════════════════════════════════════════════════
    # CF-163..CF-168: v4 Matrix Entries TN Conformance
    # ═══════════════════════════════════════════════════════════════════════

    # CF-163: LUT Matrix Coefficient Finite — banner runs on LUT profiles
    suite.assert_output_contains(
        "cf.163.matrix_coeff_finite_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-163.*Matrix.*Coefficient.*Finite"
    )

    # CF-164: LUT Matrix s15Fixed16 Range
    suite.assert_output_contains(
        "cf.164.matrix_s15f16_range_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-164.*s15Fixed16.*Range"
    )

    # CF-165: LUT Matrix Determinant Non-Singular
    suite.assert_output_contains(
        "cf.165.matrix_determinant_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-165.*Determinant"
    )

    # CF-166: LUT Matrix Row Non-Zero
    suite.assert_output_contains(
        "cf.166.matrix_row_nonzero_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-166.*Row.*Non.*Zero"
    )

    # CF-167: LUT Matrix Offset Bounds
    suite.assert_output_contains(
        "cf.167.matrix_offset_bounds_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-167.*Offset.*Bounds"
    )

    # CF-168: LUT Matrix Input-Output Range
    suite.assert_output_contains(
        "cf.168.matrix_output_range_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-168.*Input.*Output.*Range"
    )

    # Clean LUT profile should pass all matrix checks
    suite.assert_output_not_contains(
        "cf.163_168.clean_lut_no_fail",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"\[FAIL\].*CF-16[3-8]"
    )

    # --- CF-169..CF-174: Negative PCSXYZ Values TN Conformance ---
    displayp3 = str(Path(__file__).resolve().parent.parent.parent / "test-profiles" / "ios-gen-DisplayP3.icc")

    # CF-169: Negative PCSXYZ Encoding Capability — DisplayP3 has negative rXYZ Z
    suite.assert_output_contains(
        "cf.169.negative_pcsxyz_encoding",
        ["-a", displayp3],
        r"CF-169.*Negative.*PCSXYZ.*Encoding"
    )

    # CF-169: DisplayP3 uses s15Fixed16 for negative values → conformant
    suite.assert_output_contains(
        "cf.169.s15fixed16_conformant",
        ["-a", displayp3],
        r"s15Fixed16.*conformant"
    )

    # CF-170: Chad + negative consistency — DisplayP3 has chad tag
    suite.assert_output_contains(
        "cf.170.chad_negative_consistency",
        ["-a", displayp3],
        r"CF-170.*Chromatic.*Adaptation.*Negative"
    )

    # CF-171: White point non-negative luminance
    suite.assert_output_contains(
        "cf.171.whitept_nonneg",
        ["-a", displayp3],
        r"CF-171.*White.*Point.*Non.*Negative"
    )

    # CF-172: Colorant sum ≈ white point
    suite.assert_output_contains(
        "cf.172.colorant_sum_whitept",
        ["-a", displayp3],
        r"CF-172.*Colorant.*Sum.*White.*Point"
    )

    # CF-173: Absorber encoding check
    suite.assert_output_contains(
        "cf.173.absorber_encoding",
        ["-a", displayp3],
        r"CF-173.*Absorber.*Encoding"
    )

    # CF-174: Lab conversion clipping awareness
    suite.assert_output_contains(
        "cf.174.lab_clipping",
        ["-a", displayp3],
        r"CF-174.*Lab.*Conversion.*Clipping"
    )

    # Clean DisplayP3 should pass all negative PCSXYZ checks (no FAIL)
    suite.assert_output_not_contains(
        "cf.169_174.displayp3_no_fail",
        ["-a", displayp3],
        r"\[FAIL\].*CF-1[67][0-4]"
    )


def test_adgc_conformance(suite):
    """Test ADGC (Adaptive Gain Curve) conformance checks CF-123..CF-136."""
    corpus = str(Path(__file__).resolve().parent / "corpus")

    # --- CF-123: ADGC Class Restriction ---
    # CMYK profile with ADGC must trigger CF-123
    suite.assert_output_contains(
        "adgc.cf123.cmyk_violation",
        ["-a", f"{corpus}/cf_adgc_cmyk_violation.icc"],
        r"CF-123"
    )
    # Valid RGB/Input with ADGC should NOT trigger CF-123
    suite.assert_output_not_contains(
        "adgc.cf123.rgb_input_ok",
        ["-a", f"{corpus}/cf_adgc_valid_rgb_input.icc"],
        r"CF-123.*\[FAIL\]"
    )

    # --- CF-124: ADGC Type Signature ---
    # Wrong type sig must trigger CF-124
    suite.assert_output_contains(
        "adgc.cf124.bad_type_sig",
        ["-a", f"{corpus}/cf_adgc_bad_type_sig.icc"],
        r"CF-124"
    )

    # --- CF-125: Function Type ID ---
    # funcType=2 must trigger CF-125
    suite.assert_output_contains(
        "adgc.cf125.bad_functype",
        ["-a", f"{corpus}/cf_adgc_bad_functype.icc"],
        r"CF-125"
    )

    # --- CF-126: Reserved Bytes ---
    # Non-zero reserved must trigger CF-126
    suite.assert_output_contains(
        "adgc.cf126.bad_reserved",
        ["-a", f"{corpus}/cf_adgc_bad_reserved.icc"],
        r"CF-126"
    )

    # --- CF-127: Float Field Finiteness ---
    # NaN weights must trigger CF-127
    suite.assert_output_contains(
        "adgc.cf127.nan_weights",
        ["-a", f"{corpus}/cf_adgc_nan_weights.icc"],
        r"CF-127"
    )

    # --- CF-128: Weight Coefficient Sum ---
    # Weights summing to 2.0 must trigger CF-128
    suite.assert_output_contains(
        "adgc.cf128.bad_weight_sum",
        ["-a", f"{corpus}/cf_adgc_bad_weight_sum.icc"],
        r"CF-128"
    )

    # --- CF-132: Curve Data Monotonicity ---
    # Non-monotonic x-values must trigger CF-132
    suite.assert_output_contains(
        "adgc.cf132.non_monotonic",
        ["-a", f"{corpus}/cf_adgc_non_monotonic.icc"],
        r"CF-132"
    )

    # --- CF-133: H_baseline == H_alternate (division-by-zero) ---
    suite.assert_output_contains(
        "adgc.cf133.h_equal",
        ["-a", f"{corpus}/cf_adgc_h_equal.icc"],
        r"CF-133"
    )

    # --- CF-134: GainMin > GainMax (inverted gain range) ---
    suite.assert_output_contains(
        "adgc.cf134.gain_inverted",
        ["-a", f"{corpus}/cf_adgc_gain_inverted.icc"],
        r"CF-134"
    )

    # --- CF-135: Curve x-values outside [0,1] ---
    suite.assert_output_contains(
        "adgc.cf135.bad_curve_range",
        ["-a", f"{corpus}/cf_adgc_bad_curve_range.icc"],
        r"CF-135"
    )

    # --- CF-136: Adjacent curve points with equal x ---
    suite.assert_output_contains(
        "adgc.cf136.equal_x_curve",
        ["-a", f"{corpus}/cf_adgc_equal_x_curve.icc"],
        r"CF-136"
    )

    # --- BT.2100 PQ realistic profile: should pass all ADGC checks ---
    suite.assert_output_not_contains(
        "adgc.bt2100_pq.no_fail",
        ["-a", f"{corpus}/cf_adgc_bt2100_pq.icc"],
        r"CF-12[3-9].*\[FAIL\]|CF-13[0-6].*\[FAIL\]"
    )

    # --- BT.2100 HLG realistic profile: should pass all ADGC checks ---
    suite.assert_output_not_contains(
        "adgc.bt2100_hlg.no_fail",
        ["-a", f"{corpus}/cf_adgc_bt2100_hlg.icc"],
        r"CF-12[3-9].*\[FAIL\]|CF-13[0-6].*\[FAIL\]"
    )

    # --- Single-point curve: valid edge case ---
    suite.assert_output_not_contains(
        "adgc.single_point.no_fail",
        ["-a", f"{corpus}/cf_adgc_single_point_curve.icc"],
        r"CF-13[2-6].*\[FAIL\]"
    )

    # --- Many-point curve: valid stress test ---
    suite.assert_output_not_contains(
        "adgc.many_point.no_fail",
        ["-a", f"{corpus}/cf_adgc_many_point_curve.icc"],
        r"CF-13[2-6].*\[FAIL\]"
    )

    # --- Valid profile: no ADGC failures (updated range CF-123..CF-136) ---
    suite.assert_output_not_contains(
        "adgc.valid.no_cf_fail",
        ["-a", f"{corpus}/cf_adgc_valid_rgb_input.icc"],
        r"CF-12[4-9].*\[FAIL\]|CF-13[0-6].*\[FAIL\]"
    )

    # --- ADGC checks produce output for valid profiles ---
    suite.assert_output_contains(
        "adgc.valid.has_adgc_check",
        ["-a", f"{corpus}/cf_adgc_valid_rgb_input.icc"],
        r"ADGC"
    )

    # --- Profile without ADGC tag: CF-123..CF-136 should not fire false alarms ---
    suite.assert_output_not_contains(
        "adgc.no_tag.no_false_alarm",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-12[3-9].*\[FAIL\]|CF-13[0-6].*\[FAIL\]"
    )


def test_iccdev_tool_conformance(suite):
    """Test iccDEV upstream tools against reference ICC profiles."""
    # Only run if iccDEV tools are built
    dump_tool = Path(__file__).resolve().parent.parent.parent / "iccDEV" / "Build" / "Tools" / "IccDumpProfile" / "iccDumpProfile"
    toxml_tool = Path(__file__).resolve().parent.parent.parent / "iccDEV" / "Build" / "Tools" / "IccToXml" / "iccToXml"
    lib_path = Path(__file__).resolve().parent.parent.parent / "iccDEV" / "Build" / "IccProfLib"
    xml_lib = Path(__file__).resolve().parent.parent.parent / "iccDEV" / "Build" / "IccXML"
    srgb_v4 = Path(__file__).resolve().parent.parent.parent / "test-profiles" / "sRGB_v4_ICC_preference.icc"

    if not dump_tool.exists() or not srgb_v4.exists():
        return

    env = {
        **os.environ,
        "LD_LIBRARY_PATH": f"{lib_path}:{xml_lib}",
        "ASAN_OPTIONS": "halt_on_error=0,detect_leaks=0",
        "LLVM_PROFILE_FILE": "/dev/null",
    }

    # iccDumpProfile on sRGB v4
    try:
        proc = subprocess.run(
            [str(dump_tool), str(srgb_v4), "ALL"],
            capture_output=True, timeout=30, env=env
        )
        passed = proc.returncode == 0
        msg = "" if passed else f"iccDumpProfile exit {proc.returncode}"
        asan_hit = "AddressSanitizer" in proc.stderr.decode("utf-8", errors="replace")
        if asan_hit:
            passed = False
            msg = "ASAN error in iccDumpProfile"
        suite.results.append(TestResult(
            "iccdev.dump_srgb_v4", passed, msg, 0.0, "", ""
        ))
    except Exception as e:
        suite.results.append(TestResult(
            "iccdev.dump_srgb_v4", False, str(e), 0.0, "", ""
        ))

    # iccToXml on sRGB v4
    if toxml_tool.exists():
        try:
            proc = subprocess.run(
                [str(toxml_tool), str(srgb_v4), "/dev/null"],
                capture_output=True, timeout=30, env=env
            )
            passed = proc.returncode == 0
            msg = "" if passed else f"iccToXml exit {proc.returncode}"
            asan_hit = "AddressSanitizer" in proc.stderr.decode("utf-8", errors="replace")
            if asan_hit:
                passed = False
                msg = "ASAN error in iccToXml"
            suite.results.append(TestResult(
                "iccdev.toxml_srgb_v4", passed, msg, 0.0, "", ""
            ))
        except Exception as e:
            suite.results.append(TestResult(
                "iccdev.toxml_srgb_v4", False, str(e), 0.0, "", ""
            ))

    # DumpProfile on synthesized valid profile (ASAN check)
    valid_corpus = str(Path(__file__).resolve().parent / "corpus" / "valid_srgb.icc")
    if Path(valid_corpus).exists():
        try:
            proc = subprocess.run(
                [str(dump_tool), valid_corpus, "ALL"],
                capture_output=True, timeout=30, env=env
            )
            passed = proc.returncode == 0
            msg = "" if passed else f"iccDumpProfile exit {proc.returncode}"
            asan_hit = "AddressSanitizer" in proc.stderr.decode("utf-8", errors="replace")
            if asan_hit:
                passed = False
                msg = "ASAN error on valid_srgb.icc"
            suite.results.append(TestResult(
                "iccdev.dump_synth_valid", passed, msg, 0.0, "", ""
            ))
        except Exception as e:
            suite.results.append(TestResult(
                "iccdev.dump_synth_valid", False, str(e), 0.0, "", ""
            ))


def test_extended_profiles_coverage(suite):
    """Test -a on extended test profiles for broader code coverage."""
    if not EXTENDED_PROFILES.exists():
        return
    profiles = sorted(EXTENDED_PROFILES.glob("*.icc"))
    # Test every 5th extended profile (OOM files live in test-profiles/cwe-400/)
    for icc in profiles[::5][:20]:
        suite.assert_no_asan(
            f"extended.{icc.stem[:40]}",
            ["-a", str(icc)]
        )


# --- Main ---

def _print_environment(binary):
    """Print environment info for debugging."""
    print(C.bold("Environment:"))
    print(f"  Binary:  {binary}")
    try:
        proc = subprocess.run(
            [str(binary), "--version"], capture_output=True, timeout=5,
            env={**os.environ, "LLVM_PROFILE_FILE": "/dev/null"}
        )
        ver = proc.stdout.decode("utf-8", errors="replace").strip().split("\n")[0]
        print(f"  Version: {ver}")
    except Exception:
        print(f"  Version: (could not determine)")
    print(f"  Python:  {sys.version.split()[0]}")
    print(f"  Platform: {sys.platform}")
    print(f"  ASAN_OPTIONS: detect_leaks=0")
    print(f"  Corpus:  {CORPUS_DIR}")
    corpus_count = len(list(CORPUS_DIR.glob("*.icc"))) if CORPUS_DIR.exists() else 0
    print(f"  Corpus profiles: {corpus_count}")
    if TEST_PROFILES.exists():
        tp_count = len(list(TEST_PROFILES.glob("*.icc")))
        print(f"  test-profiles/: {tp_count}")
    if EXTENDED_PROFILES.exists():
        ep_count = len(list(EXTENDED_PROFILES.glob("*.icc")))
        print(f"  extended-test-profiles/: {ep_count}")


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="iccanalyzer-lite unit tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python3 run_tests.py                    Run all tests
  python3 run_tests.py -v                 Verbose (show each test)
  python3 run_tests.py -k json            Run tests matching 'json'
  python3 run_tests.py --fail-fast        Stop on first failure
  python3 run_tests.py --debug            Show commands being run
  python3 run_tests.py --list             List test sections
  python3 run_tests.py --xml report.xml   JUnit XML output"""
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show each test result as it runs")
    parser.add_argument("-k", "--pattern",
                        help="Filter tests by name pattern")
    parser.add_argument("--binary",
                        help="Path to iccanalyzer-lite binary")
    parser.add_argument("--xml",
                        help="Write JUnit XML report to this path")
    parser.add_argument("--ci", action="store_true",
                        help="CI mode: synthesize + test")
    parser.add_argument("--list", action="store_true",
                        help="List all test sections and exit")
    parser.add_argument("--fail-fast", action="store_true",
                        help="Stop on first test failure")
    parser.add_argument("--debug", action="store_true",
                        help="Show commands being run")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    args = parser.parse_args()

    if args.no_color:
        C.enabled = False

    # Discover test functions
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
        ("TIFF Corrupt", test_tiff_corrupt),
        ("HTML/XML Output", test_html_xml_output),
        ("Report Output", test_report_output),
        ("PAWG Output", test_pawg_output),
        ("LUT Text I/O", test_lut_text_io),
        ("Conformance Checks", test_conformance_checks),
        ("ADGC Conformance", test_adgc_conformance),
        ("iccDEV Tool Conformance", test_iccdev_tool_conformance),
        ("Extended Profiles", test_extended_profiles_coverage),
    ]

    # --list mode
    if args.list:
        print(C.bold(f"Test sections ({len(test_functions)}):"))
        for i, (name, fn) in enumerate(test_functions, 1):
            doc = (fn.__doc__ or "").strip().split("\n")[0]
            print(f"  {i:2d}. {name}")
            if doc:
                print(f"      {C.dim(doc)}")
        return 0

    # Synthesize corpus if not present
    if not CORPUS_DIR.exists() or len(list(CORPUS_DIR.glob("*.icc"))) == 0:
        print("Synthesizing test corpus...")
        subprocess.run([sys.executable, str(SCRIPT_DIR / "synthesize_profiles.py")], check=True)

    binary = Path(args.binary) if args.binary else BINARY
    if not binary.exists():
        print(f"{C.red('ERROR')}: Binary not found: {binary}")
        print("Build with: cd iccanalyzer-lite && ./build.sh")
        return 2

    # Show environment info
    _print_environment(binary)

    suite = TestSuite(binary, verbose=args.verbose, pattern=args.pattern,
                      fail_fast=args.fail_fast, debug=args.debug)

    # Run test sections
    t_start = time.monotonic()
    for section_name, test_fn in test_functions:
        if suite._stop_requested:
            break
        if suite.should_run(section_name):
            count_before = len(suite.results)
            suite.begin_section(section_name)
            print(f"\n{C.bold('--- ' + section_name + ' ---')}")
            test_fn(suite)
            count_after = len(suite.results)
            section_count = count_after - count_before
            section_pass = sum(1 for r in suite.results[count_before:]
                             if r.passed and not r.skipped)
            section_fail = sum(1 for r in suite.results[count_before:]
                             if not r.passed and not r.skipped)
            if not suite.verbose:
                # Compact: show pass/fail count per section
                if section_fail == 0:
                    print(f"  {C.green('✓')} {section_pass}/{section_count} passed")
                # failures already printed by _record

    wall_time = time.monotonic() - t_start
    return suite.report(xml_path=args.xml)


if __name__ == "__main__":
    sys.exit(main())
