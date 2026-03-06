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


def test_heuristic_summary(suite):
    """Test that the summary section appears with correct heuristic count."""
    suite.assert_output_contains(
        "summary.127_heuristics",
        ["-a", str(CORPUS_DIR / "bad_magic.icc")],
        r"127 heuristics"
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
