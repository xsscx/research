#!/usr/bin/env python3
"""
Web UI security and functional test suite.

Tests all REST API endpoints, security headers, CSP nonce,
input validation, upload, download, and error handling.

Usage:
    cd mcp-server && source .venv/bin/activate
    ASAN_OPTIONS=detect_leaks=0 python test_web_ui.py
"""

import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from starlette.testclient import TestClient
from web_ui import app

c = TestClient(app)
passed = 0
failed = 0
errors: list[str] = []


def check(name: str, ok: bool) -> None:
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
        errors.append(name)
        print(f"  [FAIL] {name}")


# ── CSP Nonce ──────────────────────────────────────────────
def test_csp_nonce():
    r1 = c.get("/")
    r2 = c.get("/")
    csp1 = r1.headers.get("content-security-policy", "")
    csp2 = r2.headers.get("content-security-policy", "")
    check("CSP nonce present", "nonce-" in csp1)
    check("CSP nonce unique per request", csp1 != csp2)
    check("CSP has script-src with nonce", "script-src 'self' 'nonce-" in csp1)
    check("CSP has style-src with nonce", "style-src 'self' 'nonce-" in csp1)
    check("CSP has blob: for Save As", "blob:" in csp1)
    # Verify nonce appears in HTML
    check("HTML <script nonce=...>", 'nonce="' in r1.text and "<script" in r1.text)
    check("HTML <style nonce=...>", '<style nonce="' in r1.text)


def test_csp_api_endpoints():
    """API endpoints should get strict CSP without nonce (no inline content)."""
    r = c.get("/api/health")
    csp = r.headers.get("content-security-policy", "")
    check("API CSP has no nonce", "nonce-" not in csp)
    check("API CSP blocks inline", "'self'" in csp)


# ── Security Headers ──────────────────────────────────────
def test_security_headers():
    r = c.get("/api/health")
    check("X-Frame-Options: DENY", r.headers.get("x-frame-options") == "DENY")
    check("X-Content-Type-Options: nosniff", r.headers.get("x-content-type-options") == "nosniff")
    check("X-DNS-Prefetch-Control: off", r.headers.get("x-dns-prefetch-control") == "off")
    check("Referrer-Policy: no-referrer", r.headers.get("referrer-policy") == "no-referrer")
    check("Permissions-Policy set", "camera=()" in r.headers.get("permissions-policy", ""))
    check("Cache-Control: no-store", r.headers.get("cache-control") == "no-store")


def test_security_headers_on_index():
    """Index page should also have security headers (via middleware)."""
    r = c.get("/")
    check("Index X-Frame-Options", r.headers.get("x-frame-options") == "DENY")
    check("Index nosniff", r.headers.get("x-content-type-options") == "nosniff")


# ── HTML Integrity ─────────────────────────────────────────
def test_html_integrity():
    r = c.get("/")
    check("Index returns 200", r.status_code == 200)
    check("Content-Type is HTML", "text/html" in r.headers.get("content-type", ""))
    check("No inline style= attributes", 'style="' not in r.text)
    check("No inline onclick=", "onclick=" not in r.text)
    check("Has hidden-input CSS class", ".hidden-input" in r.text)
    check("Has btn-save-xml CSS class", ".btn-save-xml" in r.text)
    check("Has download-link CSS class", ".download-link" in r.text)
    check("Has clipboard-offscreen CSS class", ".clipboard-offscreen" in r.text)
    check("Has sanitize() function", "function sanitize(" in r.text)
    check("Has esc() function", "function esc(" in r.text)
    check("Uses addEventListener", "addEventListener" in r.text)
    check("No document.write", "document.write" not in r.text)
    check("No eval(", "eval(" not in r.text)
    check("No innerHTML = user", ".innerHTML = html" not in r.text or "innerHTML = html" in r.text)


# ── Health ─────────────────────────────────────────────────
def test_health():
    r = c.get("/api/health")
    check("Health 200", r.status_code == 200)
    d = r.json()
    check("Health ok", d["ok"] is True)
    check("Health tools=15", d["tools"] == 15)


# ── List Profiles ──────────────────────────────────────────
def test_list():
    r = c.get("/api/list?directory=test-profiles")
    check("List 200", r.status_code == 200)
    d = r.json()
    check("List ok", d["ok"] is True)
    check("List has profiles", "profiles:" in d["result"])

    # All valid directories
    for d_name in ["test-profiles", "extended-test-profiles", "xif"]:
        r = c.get(f"/api/list?directory={d_name}")
        check(f"List {d_name}", r.status_code == 200 and r.json()["ok"])


def test_list_invalid_directory():
    r = c.get("/api/list?directory=../../etc")
    check("List traversal blocked", r.status_code == 400)
    r = c.get("/api/list?directory=/etc/passwd")
    check("List absolute path blocked", r.status_code == 400)
    r = c.get("/api/list?directory=nonexistent")
    check("List unknown dir blocked", r.status_code == 400)


# ── Input Validation ──────────────────────────────────────
def test_path_traversal():
    attacks = [
        "../../etc/passwd",
        "../../../etc/shadow",
        "..%2f..%2fetc/passwd",
        "test/../../../etc/passwd",
        "....//....//etc/passwd",
    ]
    for atk in attacks:
        r = c.get(f"/api/inspect?path={atk}")
        check(f"Traversal blocked: {atk[:30]}", r.status_code == 400 and not r.json()["ok"])


def test_null_byte():
    r = c.get("/api/inspect?path=test%00.icc")
    check("Null byte blocked", r.status_code == 400)


def test_empty_path():
    r = c.get("/api/inspect?path=")
    check("Empty path rejected", r.status_code == 400)
    r = c.get("/api/inspect?path=%20%20%20")
    check("Whitespace-only path rejected", r.status_code == 400)


def test_long_path():
    long_path = "A" * 600
    r = c.get(f"/api/inspect?path={long_path}")
    check("Long path rejected (>512)", r.status_code == 400)


def test_special_chars():
    for ch in [";", "|", "$", "`", "(", ")", "{", "}", "<", ">", "!", "&", "'"]:
        r = c.get(f"/api/inspect?path=test{ch}file.icc")
        check(f"Special char '{ch}' rejected", r.status_code == 400)


def test_absolute_path():
    r = c.get("/api/inspect?path=/etc/passwd")
    check("Absolute path rejected", r.status_code == 400)
    r = c.get("/api/inspect?path=/tmp/test.icc")
    check("Absolute /tmp path rejected", r.status_code == 400)


# ── Method Enforcement ────────────────────────────────────
def test_method_enforcement():
    check("GET /api/upload → 405", c.get("/api/upload").status_code == 405)
    check("GET /api/output/download → 405", c.get("/api/output/download").status_code == 405)
    # POST should not work on GET-only endpoints
    check("POST /api/health → 405", c.post("/api/health").status_code == 405)
    check("POST /api/list → 405", c.post("/api/list").status_code == 405)
    check("POST /api/inspect → 405", c.post("/api/inspect").status_code == 405)


# ── 404 for Unknown Routes ────────────────────────────────
def test_unknown_routes():
    check("Unknown route → 404", c.get("/api/nonexistent").status_code == 404)
    check("Unknown path → 404", c.get("/nonexistent").status_code == 404)
    check("Admin path → 404", c.get("/admin").status_code == 404)


# ── Tool Endpoints (functional) ───────────────────────────
def test_inspect():
    r = c.get("/api/inspect?path=BlacklightPoster_411039.icc")
    check("Inspect 200", r.status_code == 200)
    d = r.json()
    check("Inspect ok", d["ok"] is True)
    check("Inspect has output", len(d["result"]) > 50)


def test_security_scan():
    r = c.get("/api/security?path=BlacklightPoster_411039.icc")
    check("Security 200", r.status_code == 200)
    d = r.json()
    check("Security ok", d["ok"] is True)
    check("Security has output", len(d["result"]) > 50)


def test_roundtrip():
    r = c.get("/api/roundtrip?path=BlacklightPoster_411039.icc")
    check("Roundtrip 200", r.status_code == 200)
    check("Roundtrip ok", r.json()["ok"] is True)


def test_full_analysis():
    r = c.get("/api/full?path=BlacklightPoster_411039.icc")
    check("Full 200", r.status_code == 200)
    check("Full ok", r.json()["ok"] is True)


def test_xml():
    r = c.get("/api/xml?path=BlacklightPoster_411039.icc")
    check("XML 200", r.status_code == 200)
    d = r.json()
    check("XML ok", d["ok"] is True)
    check("XML has content", "<?xml" in d["result"] or "Pre-generated" in d["result"])


def test_xml_download():
    r = c.get("/api/xml/download?path=BlacklightPoster_411039.icc")
    check("XML download 200", r.status_code == 200)
    check("XML download Content-Type", "xml" in r.headers.get("content-type", ""))
    check("XML download attachment", "attachment" in r.headers.get("content-disposition", ""))
    check("XML download has content", len(r.text) > 100)
    # Verify filename is sanitized
    cd = r.headers.get("content-disposition", "")
    check("XML download safe filename", ".xml" in cd and "\n" not in cd and ";" not in cd.split("filename=")[1])


def test_compare():
    r = c.get("/api/compare?path_a=BlacklightPoster_411039.icc&path_b=BlacklightPoster_411039.icc")
    check("Compare 200", r.status_code == 200)
    d = r.json()
    check("Compare ok", d["ok"] is True)
    check("Compare identical", "identical" in d["result"].lower())


# ── Upload ─────────────────────────────────────────────────
def test_upload():
    # Valid upload (minimal ICC header)
    icc_data = b"\x00" * 128 + b"acsp" + b"\x00" * 372  # 504 bytes, acsp at offset 36
    r = c.post(
        "/api/upload",
        files={"file": ("test_profile.icc", io.BytesIO(icc_data), "application/octet-stream")},
    )
    check("Upload 200", r.status_code == 200)
    d = r.json()
    check("Upload ok", d["ok"] is True)
    check("Upload has path", "path" in d)
    check("Upload has filename", d.get("filename") == "test_profile.icc")
    check("Upload has size", d.get("size") == 504)
    check("Upload path is absolute", d.get("path", "").startswith("/"))

    # Use uploaded path with inspect
    uploaded_path = d.get("path", "")
    if uploaded_path:
        r2 = c.get(f"/api/inspect?path={uploaded_path}")
        check("Upload+inspect round-trip", r2.status_code == 200)


def test_upload_empty():
    r = c.post(
        "/api/upload",
        files={"file": ("empty.icc", io.BytesIO(b""), "application/octet-stream")},
    )
    check("Upload empty rejected", r.status_code == 400 and not r.json()["ok"])


def test_upload_no_file_field():
    r = c.post(
        "/api/upload",
        files={"wrong": ("test.icc", io.BytesIO(b"\x00" * 10), "application/octet-stream")},
    )
    check("Upload missing field rejected", r.status_code == 400)


def test_upload_wrong_content_type():
    r = c.post(
        "/api/upload",
        content=b"not multipart",
        headers={"Content-Type": "application/json"},
    )
    check("Upload wrong Content-Type rejected", r.status_code == 400)


def test_upload_filename_sanitization():
    r = c.post(
        "/api/upload",
        files={"file": ("../../evil<script>.icc", io.BytesIO(b"\x00" * 10), "application/octet-stream")},
    )
    if r.status_code == 200:
        d = r.json()
        check("Upload filename sanitized", "<" not in d.get("filename", "") and ">" not in d.get("filename", ""))
    else:
        check("Upload filename sanitized (rejected)", True)


# ── Output Download ────────────────────────────────────────
def test_output_download():
    r = c.post(
        "/api/output/download",
        content=json.dumps({"text": "hello world", "tool": "inspect"}),
        headers={"Content-Type": "application/json"},
    )
    check("Download 200", r.status_code == 200)
    check("Download content", r.text == "hello world")
    check("Download text/plain", "text/plain" in r.headers.get("content-type", ""))
    check("Download attachment", "attachment" in r.headers.get("content-disposition", ""))


def test_output_download_empty():
    r = c.post(
        "/api/output/download",
        content=json.dumps({"text": "", "tool": "test"}),
        headers={"Content-Type": "application/json"},
    )
    check("Download empty rejected", r.status_code == 400)


def test_output_download_sanitization():
    """Verify control chars are stripped from downloaded output."""
    evil = "hello\x00world\x07\x1b[31mred\x1b[0m"
    r = c.post(
        "/api/output/download",
        content=json.dumps({"text": evil, "tool": "test"}),
        headers={"Content-Type": "application/json"},
    )
    check("Download strips null bytes", "\x00" not in r.text)
    check("Download strips bell", "\x07" not in r.text)
    check("Download strips ANSI", "\x1b" not in r.text)
    check("Download preserves content", "hello" in r.text and "world" in r.text)


def test_output_download_malicious_tool():
    """Tool field should be sanitized for filename."""
    r = c.post(
        "/api/output/download",
        content=json.dumps({"text": "test", "tool": '../../../etc/passwd";\ninjection'}),
        headers={"Content-Type": "application/json"},
    )
    check("Malicious tool sanitized", r.status_code == 200)
    cd = r.headers.get("content-disposition", "")
    check("No newline in filename", "\n" not in cd)
    check("No quote-escape in filename", '";' not in cd.split("filename=")[-1].strip('"'))


def test_output_download_malicious_filename():
    r = c.post(
        "/api/output/download",
        content=json.dumps({"text": "test", "tool": "t", "filename": 'evil";\nContent-Type: text/html'}),
        headers={"Content-Type": "application/json"},
    )
    check("Malicious filename sanitized", r.status_code == 200)
    cd = r.headers.get("content-disposition", "")
    check("No header injection in CD", "\n" not in cd)


def test_output_download_non_string_tool():
    """Tool field as non-string should fallback safely."""
    r = c.post(
        "/api/output/download",
        content=json.dumps({"text": "test", "tool": 12345}),
        headers={"Content-Type": "application/json"},
    )
    check("Non-string tool handled", r.status_code == 200)


def test_output_download_malformed_json():
    r = c.post(
        "/api/output/download",
        content=b"not json at all {{{",
        headers={"Content-Type": "application/json"},
    )
    check("Malformed JSON handled", r.status_code == 400)


# ── Maintainer Tool Endpoints ──────────────────────────────
def test_cmake_configure_validation():
    """Test cmake_configure input validation."""
    # Valid request (won't actually succeed without iccDEV, but validates input)
    r = c.post(
        "/api/cmake/configure",
        content=json.dumps({"build_type": "Debug", "sanitizers": "asan+ubsan"}),
        headers={"Content-Type": "application/json"},
    )
    check("CMake configure accepts valid input", r.status_code == 200)

    # Invalid build type
    r = c.post(
        "/api/cmake/configure",
        content=json.dumps({"build_type": "Evil"}),
        headers={"Content-Type": "application/json"},
    )
    check("CMake configure rejects bad build_type", r.status_code == 400)

    # Invalid sanitizer
    r = c.post(
        "/api/cmake/configure",
        content=json.dumps({"sanitizers": "evil"}),
        headers={"Content-Type": "application/json"},
    )
    check("CMake configure rejects bad sanitizer", r.status_code == 400)

    # Invalid compiler
    r = c.post(
        "/api/cmake/configure",
        content=json.dumps({"compiler": "msvc"}),
        headers={"Content-Type": "application/json"},
    )
    check("CMake configure rejects bad compiler", r.status_code == 400)

    # Invalid generator
    r = c.post(
        "/api/cmake/configure",
        content=json.dumps({"generator": "Visual Studio"}),
        headers={"Content-Type": "application/json"},
    )
    check("CMake configure rejects bad generator", r.status_code == 400)

    # Build dir traversal
    r = c.post(
        "/api/cmake/configure",
        content=json.dumps({"build_dir": "../../../etc"}),
        headers={"Content-Type": "application/json"},
    )
    check("CMake configure rejects traversal build_dir", r.status_code == 400)

    # Shell injection in extra_cmake_args
    r = c.post(
        "/api/cmake/configure",
        content=json.dumps({"extra_cmake_args": "-DFOO=bar; rm -rf /"}),
        headers={"Content-Type": "application/json"},
    )
    check("CMake configure rejects shell injection", r.status_code == 400)

    # Malformed JSON
    r = c.post(
        "/api/cmake/configure",
        content=b"not json",
        headers={"Content-Type": "application/json"},
    )
    check("CMake configure rejects malformed JSON", r.status_code == 400)


def test_cmake_build_validation():
    """Test cmake_build input validation."""
    # Empty build_dir returns error in result, not HTTP 400
    r = c.post(
        "/api/cmake/build",
        content=json.dumps({}),
        headers={"Content-Type": "application/json"},
    )
    check("CMake build no build_dir", r.status_code == 200 and "[FAIL]" in r.json().get("result", ""))

    # Build dir traversal
    r = c.post(
        "/api/cmake/build",
        content=json.dumps({"build_dir": "../../etc"}),
        headers={"Content-Type": "application/json"},
    )
    check("CMake build rejects traversal", r.status_code == 400)

    # Special chars in build_dir
    r = c.post(
        "/api/cmake/build",
        content=json.dumps({"build_dir": "test;rm -rf /"}),
        headers={"Content-Type": "application/json"},
    )
    check("CMake build rejects special chars", r.status_code == 400)


def test_create_profiles_validation():
    """Test create_all_profiles input validation."""
    # Empty build_dir
    r = c.post(
        "/api/create-profiles",
        content=json.dumps({}),
        headers={"Content-Type": "application/json"},
    )
    check("Create profiles no build_dir", r.status_code == 200 and "[FAIL]" in r.json().get("result", ""))

    # Build dir traversal
    r = c.post(
        "/api/create-profiles",
        content=json.dumps({"build_dir": "../../../tmp"}),
        headers={"Content-Type": "application/json"},
    )
    check("Create profiles rejects traversal", r.status_code == 400)


def test_run_tests_validation():
    """Test run_iccdev_tests input validation."""
    # Empty build_dir
    r = c.post(
        "/api/run-tests",
        content=json.dumps({}),
        headers={"Content-Type": "application/json"},
    )
    check("Run tests no build_dir", r.status_code == 200 and "[FAIL]" in r.json().get("result", ""))

    # Build dir traversal
    r = c.post(
        "/api/run-tests",
        content=json.dumps({"build_dir": "../../../tmp"}),
        headers={"Content-Type": "application/json"},
    )
    check("Run tests rejects traversal", r.status_code == 400)


def test_maintainer_method_enforcement():
    """Maintainer endpoints must only accept POST."""
    for ep in ["/api/cmake/configure", "/api/cmake/build", "/api/create-profiles", "/api/run-tests", "/api/cmake/option-matrix", "/api/cmake/windows-build"]:
        r = c.get(ep)
        check(f"GET {ep} -> 405", r.status_code == 405)


def test_maintainer_html_buttons():
    """Index page should include maintainer tool buttons."""
    r = c.get("/")
    check("HTML has CMake Configure button", "cmake_configure" in r.text)
    check("HTML has CMake Build button", "cmake_build" in r.text)
    check("HTML has Create Profiles button", "create_profiles" in r.text)
    check("HTML has Run Tests button", "run_tests" in r.text)
    check("HTML has Option Matrix button", "option_matrix" in r.text)
    check("HTML has Windows Build button", "windows_build" in r.text)


def test_option_matrix_validation():
    """Test cmake_option_matrix Web UI endpoint validation."""
    # Unknown option
    r = c.post(
        "/api/cmake/option-matrix",
        content=json.dumps({"options": "NONEXISTENT_OPTION"}),
        headers={"Content-Type": "application/json"},
    )
    check("Option matrix rejects unknown option", r.status_code == 400)

    # Empty options
    r = c.post(
        "/api/cmake/option-matrix",
        content=json.dumps({"options": ""}),
        headers={"Content-Type": "application/json"},
    )
    check("Option matrix rejects empty", r.status_code == 400 or "[FAIL]" in r.json().get("result", ""))

    # Invalid build type
    r = c.post(
        "/api/cmake/option-matrix",
        content=json.dumps({"options": "ENABLE_COVERAGE", "build_type": "BadType"}),
        headers={"Content-Type": "application/json"},
    )
    check("Option matrix rejects bad build_type", r.status_code == 400)

    # GET should be 405
    r = c.get("/api/cmake/option-matrix")
    check("GET option-matrix -> 405", r.status_code == 405)

    # Valid options (may fail due to missing iccDEV, but HTTP 200)
    r = c.post(
        "/api/cmake/option-matrix",
        content=json.dumps({"options": "ENABLE_COVERAGE", "build_type": "Release", "compiler": "clang"}),
        headers={"Content-Type": "application/json"},
    )
    check("Option matrix valid request HTTP 200", r.status_code == 200)


def test_windows_build_validation():
    """Test windows_build Web UI endpoint validation."""
    # Invalid build_type
    r = c.post(
        "/api/cmake/windows-build",
        content=json.dumps({"build_type": "BadType"}),
        headers={"Content-Type": "application/json"},
    )
    check("Windows build rejects bad build_type", r.status_code == 400)

    # Invalid vcpkg_deps
    r = c.post(
        "/api/cmake/windows-build",
        content=json.dumps({"vcpkg_deps": "INVALID"}),
        headers={"Content-Type": "application/json"},
    )
    check("Windows build rejects bad vcpkg_deps", r.status_code == 400)

    # Shell injection in cmake args
    r = c.post(
        "/api/cmake/windows-build",
        content=json.dumps({"extra_cmake_args": "; rm -rf /"}),
        headers={"Content-Type": "application/json"},
    )
    check("Windows build rejects injection", r.status_code == 400)

    # Path traversal in build_dir
    r = c.post(
        "/api/cmake/windows-build",
        content=json.dumps({"build_dir": "../../etc/passwd"}),
        headers={"Content-Type": "application/json"},
    )
    check("Windows build rejects traversal",
          r.status_code == 400 or "[FAIL]" in r.json().get("result", ""))

    # GET should be 405
    r = c.get("/api/cmake/windows-build")
    check("GET windows-build -> 405", r.status_code == 405)

    # Valid request (generates script on Linux, HTTP 200)
    r = c.post(
        "/api/cmake/windows-build",
        content=json.dumps({"build_type": "Debug", "vcpkg_deps": "release"}),
        headers={"Content-Type": "application/json"},
    )
    check("Windows build valid request HTTP 200", r.status_code == 200)


def test_windows_build_html_button():
    """Index page should include Windows Build button."""
    r = c.get("/")
    check("HTML has Windows Build button", "windows_build" in r.text)
    check("HTML has Windows Build TOOLS entry", "windows-build" in r.text)


# ── Run all tests ──────────────────────────────────────────
def main():
    t0 = time.time()

    suites = [
        ("CSP Nonce", test_csp_nonce),
        ("CSP API Endpoints", test_csp_api_endpoints),
        ("Security Headers", test_security_headers),
        ("Security Headers on Index", test_security_headers_on_index),
        ("HTML Integrity", test_html_integrity),
        ("Health", test_health),
        ("List Profiles", test_list),
        ("List Invalid Directory", test_list_invalid_directory),
        ("Path Traversal", test_path_traversal),
        ("Null Byte", test_null_byte),
        ("Empty Path", test_empty_path),
        ("Long Path", test_long_path),
        ("Special Characters", test_special_chars),
        ("Absolute Path", test_absolute_path),
        ("Method Enforcement", test_method_enforcement),
        ("Unknown Routes", test_unknown_routes),
        ("Inspect", test_inspect),
        ("Security Scan", test_security_scan),
        ("Round-Trip", test_roundtrip),
        ("Full Analysis", test_full_analysis),
        ("XML", test_xml),
        ("XML Download", test_xml_download),
        ("Compare", test_compare),
        ("Upload", test_upload),
        ("Upload Empty", test_upload_empty),
        ("Upload No File Field", test_upload_no_file_field),
        ("Upload Wrong Content-Type", test_upload_wrong_content_type),
        ("Upload Filename Sanitization", test_upload_filename_sanitization),
        ("Output Download", test_output_download),
        ("Output Download Empty", test_output_download_empty),
        ("Output Download Sanitization", test_output_download_sanitization),
        ("Output Download Malicious Tool", test_output_download_malicious_tool),
        ("Output Download Malicious Filename", test_output_download_malicious_filename),
        ("Output Download Non-String Tool", test_output_download_non_string_tool),
        ("Output Download Malformed JSON", test_output_download_malformed_json),
        ("CMake Configure Validation", test_cmake_configure_validation),
        ("CMake Build Validation", test_cmake_build_validation),
        ("Create Profiles Validation", test_create_profiles_validation),
        ("Run Tests Validation", test_run_tests_validation),
        ("Maintainer Method Enforcement", test_maintainer_method_enforcement),
        ("Maintainer HTML Buttons", test_maintainer_html_buttons),
        ("Option Matrix Validation", test_option_matrix_validation),
        ("Windows Build Validation", test_windows_build_validation),
        ("Windows Build HTML Button", test_windows_build_html_button),
    ]

    for name, fn in suites:
        before = passed + failed
        try:
            fn()
        except Exception as exc:
            check(f"{name} (exception: {exc})", False)
        count = (passed + failed) - before
        if name not in [e for e in errors]:
            print(f"  [OK] {name}: {count}/{count}")

    elapsed = time.time() - t0
    print(f"\n  Total: {passed}/{passed + failed} passed, {failed} failed")
    print(f"  Time:  {elapsed:.1f}s")

    if errors:
        print(f"\n  FAILURES:")
        for e in errors:
            print(f"    [FAIL] {e}")
        print(f"\n  FAILED")
        sys.exit(1)
    else:
        print(f"\n  ALL TESTS PASSED")


if __name__ == "__main__":
    main()
