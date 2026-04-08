#!/usr/bin/env bash
###############################################################
# Copyright (©) 2024-2026 David H Hoyt. All rights reserved.
###############################################################
#                 https://srd.cx
#
# Last Updated: 02-JAN-2026 2100Z by David Hoyt
#
# Intent: Try Sanitizing User Controllable Inputs
#
# File: .github/scripts/sanitize-sed.sh
#
#
# Comment: Sanitizing User Controllable Input
#          - is a Moving Target
#          - needs ongoing updates
#          - needs additional unit tests
#          - v3: Unicode control/bidi/ZWJ stripping, ANSI escape removal
#
#
#
###############################################################

# --- Configuration ---
# Maximum lengths
SANITIZE_LINE_MAXLEN=${SANITIZE_LINE_MAXLEN:-1000}   # single-line max
SANITIZE_PRINT_MAXLEN=${SANITIZE_PRINT_MAXLEN:-8000} # multi-line max

# --- Low-level helpers -------------------------------------------------------

# escape_html STRING
# Replace &, <, >, " and ' with HTML entities.
# Uses sed to avoid bash parameter expansion issues with & in replacement.
escape_html() {
  local s="$1"
  # Order matters: escape & first
  # Use multiple sed passes to avoid quoting complexity
  s=$(printf '%s' "$s" | \
    sed 's/&/\&amp;/g' | \
    sed 's/</\&lt;/g' | \
    sed 's/>/\&gt;/g' | \
    sed 's/"/\&quot;/g' | \
    sed "s/'/\&#39;/g")
  printf '%s' "$s"
}

# _strip_unicode_control STRING
# Remove Unicode control/formatting characters that enable Trojan Source,
# invisible padding, and homoglyph attacks:
#   - Bidi overrides/embeddings (U+202A-202E, U+2066-2069)
#   - Zero-width chars (U+200B-200F, U+2060, U+FEFF)
#   - Tag characters (U+E0001-E007F)
# Uses perl for reliable multi-byte removal; falls back to sed byte patterns.
_strip_unicode_control() {
  local s="$1"
  if command -v perl >/dev/null 2>&1; then
    s="$(printf '%s' "$s" | perl -CS -pe '
      s/[\x{200B}-\x{200F}]//g;
      s/[\x{2028}-\x{202F}]//g;
      s/[\x{2060}-\x{2069}]//g;
      s/[\x{FEFF}]//g;
      s/[\x{FFF9}-\x{FFFB}]//g;
    ')"
  else
    # Fallback: strip known UTF-8 byte sequences for the most dangerous chars
    s="$(printf '%s' "$s" | sed -E '
      s/\xe2\x80[\x8b-\x8f]//g;
      s/\xe2\x80[\xa8-\xaf]//g;
      s/\xe2\x81[\xa0-\xa9]//g;
      s/\xef\xbb\xbf//g;
      s/\xef\xbf[\xb9-\xbb]//g;
    ')"
  fi
  printf '%s' "$s"
}

# _strip_ctrl_keep_newlines STRING
# Remove control characters except newline (0x0A). Also remove NUL.
# Strips ANSI escape sequences (CSI, OSC, etc.) to prevent log spoofing.
# Strips Unicode control/formatting characters to prevent Trojan Source attacks.
_strip_ctrl_keep_newlines() {
  local s="$1"
  # remove CRs explicitly
  s="${s//$'\r'/}"
  # strip ANSI escape sequences: CSI (\x1b[...m), OSC (\x1b]...\x07), then any remaining bare ESC
  s="$(printf '%s' "$s" | sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g; s/\x1b\][^\x07]*\x07//g; s/\x1b//g')"
  # strip Unicode bidi overrides, zero-width chars, and formatting controls
  s="$(_strip_unicode_control "$s")"
  # remove NUL and other C0 control chars except LF (0x0A), plus DEL (0x7F)
  s="$(printf '%s' "$s" | tr -d '\000-\011\013\014\016-\037\177')"
  printf '%s' "$s"
}

# _strip_ctrl_remove_newlines STRING
# Remove control characters and newlines (useful for single-line outputs).
# Strips ANSI escape sequences (CSI, OSC, etc.) to prevent log spoofing.
# Strips Unicode control/formatting characters to prevent Trojan Source attacks.
_strip_ctrl_remove_newlines() {
  local s="$1"
  # remove CRs and LFs
  s="${s//$'\r'/}"
  s="${s//$'\n'/ }"
  # strip ANSI escape sequences: CSI (\x1b[...m), OSC (\x1b]...\x07), then any remaining bare ESC
  s="$(printf '%s' "$s" | sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g; s/\x1b\][^\x07]*\x07//g; s/\x1b//g')"
  # strip Unicode bidi overrides, zero-width chars, and formatting controls
  s="$(_strip_unicode_control "$s")"
  # remove other control characters (NUL, etc.) plus DEL (0x7F)
  s="$(printf '%s' "$s" | tr -d '\000-\011\013\014\016-\037\177')"
  printf '%s' "$s"
}

# _trim_whitespace STRING -> trimmed
# Trim leading and trailing whitespace. Uses awk for portability.
_trim_whitespace() {
  local s="$1"
  # awk will treat the entire input as one record if we avoid newlines.
  printf '%s' "$s" | awk '{$1=$1; print}'
}

# _truncate STRING MAXLEN -> truncated (with ellipsis if truncated)
_truncate() {
  local s="$1"
  local maxlen="$2"
  local len
  len=${#s}
  if (( len <= maxlen )); then
    printf '%s' "$s"
    return 0
  fi
  # keep a small tail to help debugging
  local head
  head="${s:0:((maxlen-3))}"
  printf '%s' "${head}..."
}

# --- Public sanitizers ------------------------------------------------------

# sanitize_line STRING
# Produce a single-line safe string:
# - remove CR/LF, control chars
# - trim
# - escape HTML entities
# - truncate to SANITIZE_LINE_MAXLEN
sanitize_line() {
  local input="$1"
  local s
  s="$(_strip_ctrl_remove_newlines "$input")"
  s="$(_trim_whitespace "$s")"
  s="$(escape_html "$s")"
  s="$(_truncate "$s" "$SANITIZE_LINE_MAXLEN")"
  printf '%s' "$s"
}

# sanitize_print STRING
# Produce a multi-line safe string suitable for step summaries:
# - remove CR and other dangerous control chars but preserve LF
# - escape HTML entities
# - collapse too-many-consecutive-newlines into max 3
# - truncate total length to SANITIZE_PRINT_MAXLEN
sanitize_print() {
  local input="$1"
  local s
  s="$(_strip_ctrl_keep_newlines "$input")"
  # Normalize different newline sequences to LF (already removed CR).
  # Collapse runs of more than 3 newlines to 3 to prevent giant junk.
  # Use sed to operate on the whole buffer (single-line command).
  s="$(printf '%s' "$s" | sed -E ':a;N;$!ba;s/\n{4,}/\n\n\n/g')"
  s="$(escape_html "$s")"
  s="$(_truncate "$s" "$SANITIZE_PRINT_MAXLEN")"
  printf '%s' "$s"
}

# sanitize_codeblock STRING
# Like sanitize_print but WITHOUT HTML escaping — for content inside
# markdown fenced code blocks (``` ``` ```). Code blocks inherently
# prevent HTML injection so escape_html would double-escape.
SANITIZE_CODEBLOCK_MAXLEN=${SANITIZE_CODEBLOCK_MAXLEN:-32000}
sanitize_codeblock() {
  local input="$1"
  local s
  s="$(_strip_ctrl_keep_newlines "$input")"
  s="$(printf '%s' "$s" | sed -E ':a;N;$!ba;s/\n{4,}/\n\n\n/g')"
  s="$(_truncate "$s" "$SANITIZE_CODEBLOCK_MAXLEN")"
  printf '%s' "$s"
}

# sanitize_ref STRING
# Sanitize branch, tag or ref names for use in filenames, concurrency groups, etc.
# - replace disallowed chars with '-'
# - collapse multiple '-' into single '-'
# - trim leading/trailing '-'
sanitize_ref() {
  local input="$1"
  local s
  s="$(printf '%s' "$input" | tr -d '\000')"
  # remove CR/LF
  s="${s//$'\r'/}"
  s="${s//$'\n'/}"
  # replace any character not in the allowed set [A-Za-z0-9._/-] with '-'
  # LC_ALL=C ensures byte-level matching (prevents overlong UTF-8 bypass)
  s="$(printf '%s' "$s" | LC_ALL=C sed -E 's#[^A-Za-z0-9._/-]#-#g')"
  # collapse multiple hyphens
  s="$(printf '%s' "$s" | sed -E 's/-+/-/g')"
  # trim leading/trailing hyphen
  s="$(printf '%s' "$s" | sed -E 's/^-+//; s/-+$//')"
  # fallback to sha-like short id if empty
  if [[ -z "$s" ]]; then
    s="ref-unknown"
  fi
  printf '%s' "$s"
}

# sanitize_filename STRING
# Produce a filename-safe string (no slashes)
sanitize_filename() {
  local input="$1"
  local s
  s="$(sanitize_ref "$input")"
  # replace forward slashes with underscores (do not allow directory traversal)
  s="${s//\//_}"
  printf '%s' "$s"
}

# safe_echo_for_summary STRING...
# Echo arguments after sanitizing as print (multi-line). Useful as a drop-in.
safe_echo_for_summary() {
  local joined
  # join args with spaces
  joined="$*"
  sanitize_print "$joined"
  printf '\n'
}

# ---------------------------------------------------------------------------
# detect_hidden_chars  -- DETECTION system, NOT a filter
# ---------------------------------------------------------------------------
# Returns 0 if hidden chars FOUND (dangerous), 1 if clean.
# Emits [CRITICAL] diagnostics to stderr (not stdout -- safe for pipe chains).
# Achieves parity with GitHub UI warning:
#   "The head ref may contain hidden characters"
#
# Usage:
#   if detect_hidden_chars "$GITHUB_HEAD_REF" "HEAD_REF"; then
#     echo "[CRITICAL] Hidden chars detected" >&2
#   fi
# ---------------------------------------------------------------------------
detect_hidden_chars() {
  local input="${1:-}"
  local label="${2:-input}"

  # Empty string is clean
  [ -z "$input" ] && return 1

  local found=0
  local details=""

  # 1. BOM / Zero-Width No-Break Space (U+FEFF) -- the PR #786 trigger
  if LC_ALL=C grep -qP '\xef\xbb\xbf' <<< "$input" 2>/dev/null; then
    details="${details}  - U+FEFF (BOM / Zero-Width No-Break Space)\n"
    found=1
  fi

  # 2. Bidi overrides (U+202A-202E) -- Trojan Source attacks
  if LC_ALL=C grep -qP '[\xe2\x80\xaa-\xe2\x80\xae]' <<< "$input" 2>/dev/null; then
    details="${details}  - U+202A-202E (Bidi Override/Embedding)\n"
    found=1
  fi

  # 3. Bidi isolates (U+2066-2069)
  if LC_ALL=C grep -qP '[\xe2\x81\xa6-\xe2\x81\xa9]' <<< "$input" 2>/dev/null; then
    details="${details}  - U+2066-2069 (Bidi Isolate)\n"
    found=1
  fi

  # 4. Zero-width chars (U+200B-200F)
  if LC_ALL=C grep -qP '[\xe2\x80\x8b-\xe2\x80\x8f]' <<< "$input" 2>/dev/null; then
    details="${details}  - U+200B-200F (Zero-Width Space/Joiner/Mark)\n"
    found=1
  fi

  # 5. Word joiner (U+2060)
  if LC_ALL=C grep -qP '\xe2\x81\xa0' <<< "$input" 2>/dev/null; then
    details="${details}  - U+2060 (Word Joiner)\n"
    found=1
  fi

  # 6. Line/Paragraph separators (U+2028-2029)
  if LC_ALL=C grep -qP '[\xe2\x80\xa8-\xe2\x80\xa9]' <<< "$input" 2>/dev/null; then
    details="${details}  - U+2028-2029 (Line/Paragraph Separator)\n"
    found=1
  fi

  # 7. Interlinear annotation (U+FFF9-FFFB)
  if LC_ALL=C grep -qP '[\xef\xbf\xb9-\xef\xbf\xbb]' <<< "$input" 2>/dev/null; then
    details="${details}  - U+FFF9-FFFB (Interlinear Annotation)\n"
    found=1
  fi

  # 8. Broad: any non-printable byte (control chars 0x00-0x1F, DEL 0x7F, non-ASCII 0x80+)
  if [ "$found" -eq 0 ]; then
    if LC_ALL=C grep -qP '[^\x20-\x7E]' <<< "$input" 2>/dev/null; then
      details="${details}  - Non-ASCII byte(s) detected (unknown category)\n"
      found=1
    fi
  fi

  if [ "$found" -eq 1 ]; then
    local hex_bytes
    hex_bytes="$(printf '%s' "$input" | xxd -p | tr -d '\n' | head -c 120)"
    local sanitized
    sanitized="$(sanitize_ref "$input")"

    {
      printf '[CRITICAL] Hidden Unicode characters detected in %s\n' "$label"
      printf '%b' "$details"
      printf '  Raw bytes: %s\n\n' "$hex_bytes"
      printf '  Sanitized: %s\n' "$sanitized"
      printf '  GitHub UI parity: this finding matches GitHub warning\n'
      printf '    "The head ref may contain hidden characters"\n'
    } >&2

    return 0  # found = dangerous
  fi

  return 1  # clean
}

# ---------------------------------------------------------------------------
# validate_ref  -- detect + sanitize wrapper
# ---------------------------------------------------------------------------
# Emits detection diagnostics to stderr, returns sanitized ref on stdout.
# Usage:
#   CLEAN_REF="$(validate_ref "$GITHUB_HEAD_REF" "HEAD_REF")"
# ---------------------------------------------------------------------------
validate_ref() {
  local input="${1:-}"
  local label="${2:-ref}"

  detect_hidden_chars "$input" "$label" || true
  sanitize_ref "$input"
}

# Provide a minimal no-op marker so callers can check we're present
sanitizer_version() {
  printf 'research-sanitizer-v4\n'
}

# End of sanitize-sed.sh
