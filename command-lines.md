# ICC Profile MCP Server — Command-Line Reference

Reproducible one-liner commands for local testing of the MCP server.
All commands run from the **repository root** (`research/`).

---

## Prerequisites

```bash
# Activate the Python virtual environment (required for every command below)
source mcp-server/.venv/bin/activate
```

> **Note:** Set `ASAN_OPTIONS=detect_leaks=0` when running commands that invoke
> iccanalyzer-lite (built with AddressSanitizer).

---

## 1 · Run the Full Test Suite (302 tests)

```bash
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python mcp-server/test_mcp.py
```

---

## 2 · Verify the Server Loads (7 tools)

```bash
source mcp-server/.venv/bin/activate && python -c "import sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import mcp; tools=mcp._tool_manager._tools; print(f'{len(tools)} tools:'); [print(f'  - {n}') for n in sorted(tools)]"
```

---

## 3 · List Available Test Profiles

```bash
# Default directory (test-profiles/)
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import list_test_profiles; print(asyncio.run(list_test_profiles()))"

# Extended test profiles
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import list_test_profiles; print(asyncio.run(list_test_profiles('extended-test-profiles')))"

# Crash/fuzz corpus (xif/)
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import list_test_profiles; print(asyncio.run(list_test_profiles('xif')))"
```

---

## 4 · Inspect a Profile (header + tag table + raw dump)

```bash
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import inspect_profile; print(asyncio.run(inspect_profile('BlacklightPoster_411039.icc')))"
```

Replace `BlacklightPoster_411039.icc` with any `.icc` filename from `test-profiles/`,
`extended-test-profiles/`, or `xif/`.

---

## 5 · Security Heuristic Scan (14-phase)

```bash
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import analyze_security; print(asyncio.run(analyze_security('cve-2022-26730-poc-sample-004.icc')))"
```

---

## 6 · Validate Round-Trip Support (AToB/BToA tag pairs)

```bash
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import validate_roundtrip; print(asyncio.run(validate_roundtrip('BlacklightPoster_411039.icc')))"
```

---

## 7 · Full Comprehensive Analysis (security + roundtrip + metadata)

```bash
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import full_analysis; print(asyncio.run(full_analysis('xsscx-poison-enum-signature-fields-0x5F-0xFF-oXFE.icc')))"
```

---

## 8 · Convert Profile to XML

```bash
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import profile_to_xml; print(asyncio.run(profile_to_xml('xml-to-icc-to-xml-fidelity-test-001.icc')))"
```

---

## 9 · Compare Two Profiles (unified diff)

```bash
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import compare_profiles; print(asyncio.run(compare_profiles('BlacklightPoster_411039.icc','cve-2022-26730-poc-sample-004.icc')))"
```

---

## 10 · Batch Security Scan All Test Profiles

```bash
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python -c "
import asyncio,sys,os; sys.path.insert(0,'mcp-server')
from icc_profile_mcp import analyze_security
async def main():
    ok=fail=0
    for f in sorted(os.listdir('test-profiles')):
        if not f.endswith('.icc'): continue
        try: r=await analyze_security(f); ok+=1; print(f'  ✓ {f}')
        except Exception as e: fail+=1; print(f'  ✗ {f}: {e}')
    print(f'\n{ok} passed, {fail} failed')
asyncio.run(main())
"
```

---

## 11 · Security Boundary Tests (should all reject)

```bash
# Path traversal — must reject
source mcp-server/.venv/bin/activate && python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import inspect_profile; print(asyncio.run(inspect_profile('../../etc/passwd')))" 2>&1 | grep -o 'FileNotFoundError.*'

# Absolute path escape — must reject
source mcp-server/.venv/bin/activate && python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import inspect_profile; print(asyncio.run(inspect_profile('/etc/shadow')))" 2>&1 | grep -o 'FileNotFoundError.*'

# Null byte injection — must reject
source mcp-server/.venv/bin/activate && python -c "import asyncio,sys; sys.path.insert(0,'mcp-server'); from icc_profile_mcp import inspect_profile; print(asyncio.run(inspect_profile('test.icc\x00.png')))" 2>&1 | grep -o 'ValueError.*'
```

Expected: each command prints the error class confirming rejection.

---

## 12 · Start the MCP Server (for client connections)

```bash
# stdio transport (used by Copilot CLI, Claude Desktop, VS Code)
source mcp-server/.venv/bin/activate && cd mcp-server && mcp run icc_profile_mcp.py:mcp

# Interactive MCP Inspector (opens web UI on localhost)
source mcp-server/.venv/bin/activate && cd mcp-server && mcp dev icc_profile_mcp.py:mcp
```

---

## 13 · Build Everything from Scratch

```bash
# 1. Build iccDEV + iccanalyzer-lite
cd iccanalyzer-lite && git clone --depth 1 https://github.com/InternationalColorConsortium/DemoIccMAX.git iccDEV && cd iccDEV/Build && cmake Cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -std=c++17" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" -DENABLE_TOOLS=OFF -DENABLE_STATIC_LIBS=ON -Wno-dev && make -j$(nproc) && cd ../.. && bash build.sh && cd ..

# 2. Build colorbleed_tools
cd colorbleed_tools && make setup && make clean all && make test && cd ..

# 3. Setup Python environment
cd mcp-server && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && cd ..

# 4. Run tests
source mcp-server/.venv/bin/activate && ASAN_OPTIONS=detect_leaks=0 python mcp-server/test_mcp.py
```

---

## Quick Reference

| # | Command | What it does |
|---|---------|-------------|
| 1 | `python mcp-server/test_mcp.py` | Full 302-test suite (security + functional + stress) |
| 2 | Verify server loads | Confirms 7 tools registered |
| 3 | `list_test_profiles()` | List `.icc` files in a directory |
| 4 | `inspect_profile(path)` | Raw header dump + tag table |
| 5 | `analyze_security(path)` | 14-phase security heuristic scan |
| 6 | `validate_roundtrip(path)` | Check AToB/BToA tag pair symmetry |
| 7 | `full_analysis(path)` | Combined security + roundtrip + metadata |
| 8 | `profile_to_xml(path)` | Binary ICC → XML conversion |
| 9 | `compare_profiles(a, b)` | Unified diff of two profiles |
| 10 | Batch scan | Security scan every profile in a directory |
| 11 | Security boundaries | Verify path traversal / null byte rejection |
| 12 | `mcp run` / `mcp dev` | Start server for client connections / inspector |
| 13 | Full build | Build all binaries + venv from scratch |
