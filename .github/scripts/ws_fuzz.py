#!/usr/bin/env python3
"""
ws_fuzz.py — WebSocket integration test harness for BeyondRGB backend.

Sends various request types with image files from a corpus directory
to exercise the backend's image processing pipeline. Supports auto-
reconnect when the server restarts between test iterations.

Logging:
    --log <file>   Write JSONL (one JSON object per line) to <file>.
                    Each entry records: timestamp, phase, request_id,
                    request_type, image(s), status (ok/error), elapsed_ms,
                    binary_bytes, error message, sender, and full stack trace.

    After the run a human-readable summary is appended.  If addr2line is
    available and --binary points at the server executable, hex addresses
    in stack traces are symbolized automatically.

    ASAN / UBSAN logs written by the server (ASAN_OPTIONS=log_path=…) are
    collected via --asan-log-prefix and appended to the JSONL log.

Usage:
    python ws_fuzz.py --port 9222 --corpus /path/to/images [--proxy host:port]
    python ws_fuzz.py --port 9500 --corpus ./test-corpus --log /tmp/ws-test.jsonl \
        --binary ./build/Debug/beyond-rgb-backend \
        --asan-log-prefix /tmp/beyondrgb-asan.log

Requires: pip install websocket-client
"""

import argparse
import datetime
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time

try:
    import websocket
except ImportError:
    print("Install websocket-client: pip install websocket-client")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

class TestLogger:
    """JSONL file logger with optional addr2line symbolization."""

    def __init__(self, path=None, binary=None):
        self._fh = open(path, "w") if path else None
        self._binary = binary
        self._addr2line = shutil.which("addr2line")
        self._records = []
        self._start = time.monotonic()
        self._session_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        if self._fh:
            self._write_meta()

    # -- public API --

    def log(self, phase, request_id, request_type, images, status,
            elapsed_ms, binary_bytes, error_msg, sender, raw_trace, responses):
        """Append one test-case record."""
        trace_lines = self._symbolize(raw_trace) if raw_trace else []
        rec = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "session": self._session_id,
            "phase": phase,
            "request_id": request_id,
            "request_type": request_type,
            "images": images,
            "status": status,
            "elapsed_ms": round(elapsed_ms, 1),
            "binary_bytes": binary_bytes,
            "error_msg": error_msg,
            "sender": sender,
            "trace_raw": raw_trace,
            "trace_symbolized": trace_lines,
            "response_count": len(responses),
            "response_types": [r.get("ResponseType", "_binary") for r in responses
                               if isinstance(r, dict)],
        }
        self._records.append(rec)
        if self._fh:
            self._fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            self._fh.flush()

    def collect_asan_logs(self, prefix):
        """Glob ASAN/UBSAN log files and append each as a log record."""
        if not prefix or not self._fh:
            return 0
        count = 0
        for path in sorted(glob.glob(f"{prefix}*")):
            try:
                with open(path) as f:
                    text = f.read()
                if not text.strip():
                    continue
                rec = {
                    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "session": self._session_id,
                    "phase": "ASAN_LOG",
                    "log_file": path,
                    "log_size": len(text),
                    "log_text": text,
                }
                self._fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
                count += 1
            except Exception:
                pass
        if count:
            self._fh.flush()
        return count

    def write_summary(self, all_results):
        """Append a human-readable summary block to the log file."""
        if not self._fh:
            return
        elapsed = time.monotonic() - self._start
        errors = [r for r in self._records if r["status"] == "error"]
        unique_traces = set()
        for r in errors:
            key = (r.get("sender", ""), r.get("error_msg", ""))
            unique_traces.add(key)

        lines = [
            "",
            f"# ═══════════════════════════════════════════════════",
            f"# ws_fuzz.py session {self._session_id}",
            f"# Total requests:  {len(self._records)}",
            f"# Errors:          {len(errors)}",
            f"# Unique errors:   {len(unique_traces)}",
            f"# Elapsed:         {elapsed:.1f}s",
            f"# ═══════════════════════════════════════════════════",
        ]
        for phase_name, r in all_results.items():
            lines.append(f"# {phase_name}: sent={r['sent']} ok={r['ok']} errors={r['errors']}")

        if errors:
            lines.append("#")
            lines.append("# --- Error detail (unique sender+message pairs) ---")
            for sender, msg in sorted(unique_traces):
                lines.append(f"# [{sender}] {msg}")
                for rec in errors:
                    if rec.get("sender") == sender and rec.get("error_msg") == msg:
                        for img in rec["images"]:
                            lines.append(f"#   file: {img}")
                        if rec["trace_symbolized"]:
                            for tl in rec["trace_symbolized"][:15]:
                                lines.append(f"#     {tl}")
                        elif rec["trace_raw"]:
                            for tl in rec["trace_raw"].split("\n")[:10]:
                                lines.append(f"#     {tl.strip()}")
                        break

        self._fh.write("\n".join(lines) + "\n")
        self._fh.flush()

    def close(self):
        if self._fh:
            self._fh.close()

    # -- internals --

    def _write_meta(self):
        meta = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "session": self._session_id,
            "phase": "META",
            "binary": self._binary,
            "addr2line": self._addr2line,
            "argv": sys.argv,
            "cwd": os.getcwd(),
        }
        self._fh.write(json.dumps(meta, separators=(",", ":")) + "\n")

    def _symbolize(self, raw_trace):
        """Parse hex addresses from cpptrace output and resolve via addr2line.

        PIE binaries (position-independent executables) are loaded at a
        runtime base address (typically 0x555555554000 on Linux).  The raw
        addresses from cpptrace are virtual addresses that include this
        base offset.  addr2line expects file-relative offsets, so we must
        detect and subtract the PIE base before resolving.
        """
        if not raw_trace:
            return []
        lines = raw_trace.replace("\\n", "\n").split("\n")
        if not (self._addr2line and self._binary):
            return [l.strip() for l in lines if l.strip()]

        addr_re = re.compile(r"0x[0-9a-fA-F]+")
        # Collect (raw_hex, binary_name) for each frame
        raw_addrs = []       # original hex strings
        binary_names = []    # the "at <lib>" portion
        for line in lines:
            m = addr_re.search(line)
            if m:
                raw_addrs.append(m.group())
                # Extract " at <binary>" suffix if present
                at_match = re.search(r"at\s+(\S+)", line)
                binary_names.append(at_match.group(1) if at_match else "")

        if not raw_addrs:
            return [l.strip() for l in lines if l.strip()]

        # Detect PIE base: typical Linux ASLR loads PIE at 0x55555555_xxxx.
        # Use the lowest address that starts with 0x5555 as base indicator,
        # then round down to page boundary (0x...4000).
        pie_base = 0
        binary_basename = os.path.basename(self._binary) if self._binary else ""
        pie_addrs = []
        for addr_s, bname in zip(raw_addrs, binary_names):
            val = int(addr_s, 16)
            # Only PIE-adjust addresses from the main binary (not libc, libasan, etc.)
            if binary_basename and binary_basename in bname:
                pie_addrs.append(val)
            elif bname in ("", "./beyond-rgb-backend") or "beyond-rgb" in bname:
                pie_addrs.append(val)

        if pie_addrs:
            # Standard Linux PIE base: align lowest binary address down to 0x...4000
            lowest = min(pie_addrs)
            # PIE binaries on x86-64 Linux typically load at 0x555555554000
            # Detect by checking if addresses are in the 0x5555... range
            if lowest > 0x555555000000:
                pie_base = 0x555555554000
            elif lowest > 0x100000:
                # Fallback: read ELF entry point and compute base
                try:
                    res = subprocess.run(
                        ["readelf", "-h", self._binary],
                        capture_output=True, text=True, timeout=5,
                    )
                    for eline in res.stdout.split("\n"):
                        if "Entry point" in eline:
                            entry = int(eline.split("0x")[1].strip(), 16)
                            # base = lowest_addr - (lowest_addr_file_offset)
                            # Approximation: if entry < lowest, base = lowest - entry
                            if entry < lowest:
                                pie_base = lowest - entry
                                # Page-align
                                pie_base = pie_base & ~0xFFF
                            break
                except Exception:
                    pass

        # Build addr2line input: subtract PIE base for binary frames
        query_addrs = []
        for addr_s, bname in zip(raw_addrs, binary_names):
            val = int(addr_s, 16)
            is_binary = (binary_basename and binary_basename in bname) or \
                        bname in ("", "./beyond-rgb-backend") or "beyond-rgb" in bname
            if is_binary and pie_base:
                query_addrs.append(hex(val - pie_base))
            else:
                query_addrs.append(addr_s)

        try:
            result = subprocess.run(
                [self._addr2line, "-Cfpie", self._binary] + query_addrs,
                capture_output=True, text=True, timeout=10,
            )
            symbols = result.stdout.strip().split("\n")
        except Exception:
            symbols = []

        sym_map = {}
        for addr_s, sym in zip(raw_addrs, symbols):
            if sym and sym != "??" and "?" not in sym[:3]:
                # Shorten paths for readability
                sym = re.sub(r".*/backend/", "", sym)
                sym_map[addr_s] = sym

        out = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            m = addr_re.search(line)
            if m and m.group() in sym_map:
                out.append(f"{line}  →  {sym_map[m.group()]}")
            else:
                out.append(line)
        return out


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def find_images(corpus_dir, extensions=("tiff", "tif", "png", "jpg", "jpeg", "gif")):
    """Recursively find image files in corpus directory."""
    images = []
    for ext in extensions:
        images.extend(glob.glob(os.path.join(corpus_dir, "**", f"*.{ext}"), recursive=True))
    return sorted(images)


def connect(port, proxy_host=None, proxy_port=None, retries=5):
    """Connect to WebSocket with retry logic."""
    for attempt in range(retries):
        try:
            ws = websocket.WebSocket()
            kwargs = {}
            if proxy_host:
                kwargs["http_proxy_host"] = proxy_host
                kwargs["http_proxy_port"] = proxy_port
            ws.connect(f"ws://127.0.0.1:{port}", **kwargs)
            return ws
        except Exception:
            if attempt < retries - 1:
                time.sleep(2)
            else:
                return None
    return None


def send_request(ws, request_id, request_type, request_data, timeout=10):
    """Send a request and collect all responses (JSON + binary frames)."""
    payload = json.dumps({
        "RequestID": request_id,
        "RequestType": request_type,
        "RequestData": request_data,
    })
    ws.send(payload)
    ws.settimeout(timeout)
    responses = []
    try:
        while True:
            r = ws.recv()
            try:
                responses.append(json.loads(r))
            except json.JSONDecodeError:
                responses.append({"_binary": True, "_size": len(r)})
    except (websocket.WebSocketTimeoutException, websocket.WebSocketConnectionClosedException):
        pass
    except Exception:
        pass
    return responses


# ---------------------------------------------------------------------------
# Formatting helpers (console output)
# ---------------------------------------------------------------------------

# Module-level symbolizer reference (set in main() when --binary is provided)
_module_logger = None


def format_trace(resp):
    """Extract and format stack trace from an error response for console."""
    data = resp.get("ResponseData", {})
    msg = data.get("message", "")
    trace = data.get("trace", "")
    sender = data.get("sender", "")
    lines = [f"    [{sender}] {msg}"]
    if trace:
        # Use the module logger's symbolizer if available
        if _module_logger and _module_logger._binary:
            sym_lines = _module_logger._symbolize(trace)
            for frame in sym_lines:
                lines.append(f"      {frame}")
        else:
            for frame in trace.replace("\\n", "\n").split("\n"):
                frame = frame.strip()
                if frame:
                    lines.append(f"      {frame}")
    return "\n".join(lines)


def _extract_error_fields(resps):
    """Return (error_msg, sender, raw_trace) from first error response."""
    for r in resps:
        if isinstance(r, dict) and r.get("ResponseType") == "Error":
            d = r.get("ResponseData", {})
            return d.get("message", ""), d.get("sender", ""), d.get("trace", "")
    return "", "", ""


def _binary_bytes(resps):
    """Sum binary response sizes."""
    return sum(r.get("_size", 0) for r in resps
               if isinstance(r, dict) and r.get("_binary"))


# ---------------------------------------------------------------------------
# Phase runners
# ---------------------------------------------------------------------------

def phase_preview(ws, images, start_id, logger):
    """Phase A: HalfSizePreview — one image at a time."""
    results = {"sent": 0, "errors": 0, "ok": 0}
    for i, img in enumerate(images):
        rid = start_id + i
        t0 = time.monotonic()
        resps = send_request(ws, rid, "HalfSizePreview", {"names": [img]})
        elapsed = (time.monotonic() - t0) * 1000
        results["sent"] += 1
        error_resps = [r for r in resps if isinstance(r, dict) and r.get("ResponseType") == "Error"]
        if error_resps:
            results["errors"] += 1
            emsg, sender, raw_trace = _extract_error_fields(resps)
            print(f"  ✗ {os.path.basename(img)}")
            for er in error_resps:
                print(format_trace(er))
            logger.log("A_preview", rid, "HalfSizePreview", [img], "error",
                       elapsed, 0, emsg, sender, raw_trace, resps)
        else:
            results["ok"] += 1
            bb = _binary_bytes(resps)
            sz = f" ({bb} bytes)" if bb else ""
            print(f"  ✓ {os.path.basename(img)}{sz}")
            logger.log("A_preview", rid, "HalfSizePreview", [img], "ok",
                       elapsed, bb, "", "", "", resps)
        if i % 50 == 0 and i > 0:
            print(f"  --- {i}/{len(images)} sent, {results['errors']} errors ---")
    return results


def phase_thumbnails(ws, images, start_id, logger):
    """Phase B: Thumbnails — batch of 6 at a time."""
    results = {"sent": 0, "errors": 0, "ok": 0}
    batch_size = 6
    for i in range(0, len(images), batch_size):
        batch = images[i:i + batch_size]
        rid = start_id + i
        t0 = time.monotonic()
        resps = send_request(ws, rid, "Thumbnails", {"names": batch})
        elapsed = (time.monotonic() - t0) * 1000
        results["sent"] += 1
        error_resps = [r for r in resps if isinstance(r, dict) and r.get("ResponseType") == "Error"]
        if error_resps:
            results["errors"] += 1
            emsg, sender, raw_trace = _extract_error_fields(resps)
            names = ", ".join(os.path.basename(b) for b in batch)
            print(f"  ✗ batch [{names}]")
            for er in error_resps:
                print(format_trace(er))
            logger.log("B_thumbnails", rid, "Thumbnails", batch, "error",
                       elapsed, 0, emsg, sender, raw_trace, resps)
        else:
            results["ok"] += 1
            bb = _binary_bytes(resps)
            print(f"  ✓ batch ({len(batch)} images, {bb} bytes)")
            logger.log("B_thumbnails", rid, "Thumbnails", batch, "ok",
                       elapsed, bb, "", "", "", resps)
    return results


def phase_process(ws, images, start_id, logger):
    """Phase P: Process pipeline — triplets of (art, white, dark)."""
    results = {"sent": 0, "errors": 0, "ok": 0}
    for i in range(0, len(images) - 2, 3):
        art, white, dark = images[i], images[i + 1], images[i + 2]
        rid = start_id + i
        t0 = time.monotonic()
        resps = send_request(ws, rid, "Process", {
            "batch": False,
            "images": [{"art": art, "white": white, "dark": dark}],
            "outputFileName": f"fuzz_test_{i}",
            "destinationDirectory": os.environ.get("FUZZ_OUTPUT", "/tmp/fuzz_out"),
        }, timeout=15)
        elapsed = (time.monotonic() - t0) * 1000
        imgs = [art, white, dark]
        results["sent"] += 1
        error_resps = [r for r in resps if isinstance(r, dict) and r.get("ResponseType") == "Error"]
        if error_resps:
            results["errors"] += 1
            emsg, sender, raw_trace = _extract_error_fields(resps)
            print(f"  ✗ process [{os.path.basename(art)} + {os.path.basename(white)} + {os.path.basename(dark)}]")
            for er in error_resps:
                print(format_trace(er))
            logger.log("P_process", rid, "Process", imgs, "error",
                       elapsed, 0, emsg, sender, raw_trace, resps)
        else:
            results["ok"] += 1
            bb = _binary_bytes(resps)
            print(f"  ✓ process [{os.path.basename(art)} + {os.path.basename(white)} + {os.path.basename(dark)}]")
            logger.log("P_process", rid, "Process", imgs, "ok",
                       elapsed, bb, "", "", "", resps)
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="BeyondRGB WebSocket integration test harness")
    parser.add_argument("--port", type=int, default=9222, help="Backend WebSocket port")
    parser.add_argument("--corpus", required=True, help="Directory containing test images")
    parser.add_argument("--proxy", default=None, help="HTTP proxy (host:port) for inspection")
    parser.add_argument("--phases", default="ABP", help="Phases to run: A=preview, B=thumbnail, P=process")
    parser.add_argument("--limit", type=int, default=0, help="Max images per phase (0=all)")
    parser.add_argument("--log", default=None, help="JSONL log output file path")
    parser.add_argument("--binary", default=None,
                        help="Path to server binary (enables addr2line symbolization of traces)")
    parser.add_argument("--asan-log-prefix", default=None,
                        help="Glob prefix for ASAN/UBSAN log files (e.g. /tmp/beyondrgb-asan.log)")
    args = parser.parse_args()

    logger = TestLogger(path=args.log, binary=args.binary)

    global _module_logger
    _module_logger = logger

    proxy_host = proxy_port = None
    if args.proxy:
        parts = args.proxy.split(":")
        proxy_host = parts[0]
        proxy_port = int(parts[1]) if len(parts) > 1 else 8080

    images = find_images(args.corpus)
    if not images:
        print(f"No images found in {args.corpus}")
        sys.exit(1)

    tiffs = [f for f in images if f.lower().endswith((".tiff", ".tif"))]
    pngs = [f for f in images if f.lower().endswith(".png")]
    jpgs = [f for f in images if f.lower().endswith((".jpg", ".jpeg", ".gif"))]

    if args.limit:
        tiffs = tiffs[:args.limit]
        pngs = pngs[:args.limit]
        jpgs = jpgs[:args.limit]

    print(f"Corpus: {len(tiffs)} TIFF, {len(pngs)} PNG, {len(jpgs)} JPG/GIF")
    print(f"Port: {args.port}, Phases: {args.phases}")
    if args.log:
        print(f"Log: {args.log}")
    print()

    ws = connect(args.port, proxy_host, proxy_port)
    if not ws:
        print("Cannot connect to backend")
        sys.exit(1)

    all_results = {}

    if "A" in args.phases.upper():
        print("--- Phase A: HalfSizePreview (TIFF) ---")
        try:
            all_results["preview_tiff"] = phase_preview(ws, tiffs, 1000, logger)
        except Exception:
            ws = connect(args.port, proxy_host, proxy_port)
        print(f"  Result: {all_results.get('preview_tiff', 'skipped')}")

        if pngs:
            print("--- Phase A: HalfSizePreview (PNG) ---")
            if not ws:
                ws = connect(args.port, proxy_host, proxy_port)
            if ws:
                try:
                    all_results["preview_png"] = phase_preview(ws, pngs, 3000, logger)
                except Exception:
                    ws = connect(args.port, proxy_host, proxy_port)
                print(f"  Result: {all_results.get('preview_png', 'skipped')}")

    if "B" in args.phases.upper():
        print("--- Phase B: Thumbnails ---")
        if not ws:
            ws = connect(args.port, proxy_host, proxy_port)
        if ws:
            try:
                all_results["thumbnails"] = phase_thumbnails(ws, tiffs + pngs[:50], 5000, logger)
            except Exception:
                ws = connect(args.port, proxy_host, proxy_port)
            print(f"  Result: {all_results.get('thumbnails', 'skipped')}")

    if "P" in args.phases.upper():
        print("--- Phase P: Process pipeline ---")
        if not ws:
            ws = connect(args.port, proxy_host, proxy_port)
        if ws:
            try:
                all_results["process"] = phase_process(ws, tiffs, 8000, logger)
            except Exception:
                ws = connect(args.port, proxy_host, proxy_port)
            print(f"  Result: {all_results.get('process', 'skipped')}")

    if ws:
        ws.close()

    # Collect ASAN / UBSAN logs
    if args.asan_log_prefix:
        n = logger.collect_asan_logs(args.asan_log_prefix)
        if n:
            print(f"\nCollected {n} ASAN/UBSAN log file(s)")

    # Summary
    print()
    print("=== Summary ===")
    for phase, r in all_results.items():
        print(f"  {phase}: sent={r['sent']} ok={r['ok']} errors={r['errors']}")

    if args.log:
        logger.write_summary(all_results)
        print(f"\nFull log written to: {args.log}")

    logger.close()


if __name__ == "__main__":
    main()
