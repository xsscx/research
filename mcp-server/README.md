# ICC Profile MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io/) server that lets AI assistants interactively analyze ICC color profiles for security research, validation, and forensic inspection.

---

## What This Does

ICC color profiles control how colors are translated between devices (cameras, monitors, printers). Malformed profiles have been the source of real-world vulnerabilities (CVE-2022-26730, CVE-2023-46602, CVE-2024-38427). This MCP server connects your AI assistant to purpose-built analysis tools so you can inspect, compare, and security-scan ICC profiles through natural conversation.

**You say:**
> "Analyze the security of the CVE-2022-26730 proof-of-concept profile"

**Your AI assistant calls** `analyze_security("cve-2022-26730-poc-sample-004.icc")` and returns a 19-phase heuristic report covering header validation, tag anomalies, overflow indicators, malicious patterns, date validation, signature analysis, spectral range checks, technology signatures, and tag overlap detection.

---

## I Just Want to Test a Profile (No Setup Required)

If you have an ICC profile and just want a report, here are the fastest paths — no C++ builds, no cloning, no terminal commands.

### Option A: GitHub Issue (easiest)

1. Rename your file from `profile.icc` to `profile.icc.txt` (GitHub does not allow `.icc` or `.bin` attachments)
2. Open an issue at [github.com/xsscx/research/issues](https://github.com/xsscx/research/issues)
3. Attach the `.icc.txt` file to the issue
4. Use this prompt (or similar):

> **Analyze the attached ICC profile**
>
> Run the full analysis workflow:
> 1. Rename the attached `.icc.txt` to `.icc`
> 2. Run `iccanalyzer-lite -a` (comprehensive analysis) and include the **complete raw output**
> 3. Run `iccanalyzer-lite -nf` (ninja full dump) and include the **complete raw output**
> 4. Run `iccanalyzer-lite -r` (round-trip test) and include the **complete raw output**
> 5. Include the exit code from each command and any ASAN/UBSAN stderr
> 6. Add your analysis **after** the raw tool output — do not replace it with a summary

5. The Copilot coding agent picks up the issue, runs the tools, and posts the report as a PR

### Option B: Web UI (browser-based)

```bash
# If Docker is installed, one command:
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web
```

Then open `http://127.0.0.1:8080` in your browser:
1. Click **Security Scan** (or any tool button)
2. Click **Choose File** and select your `.icc` file from your computer
3. Click **Run**
4. Read the report — click **Copy** or **Save As** to keep it

### Option C: Copilot CLI or VS Code Chat

If you have [Copilot CLI](https://github.com/github/copilot-cli) or VS Code with Copilot Chat:

1. Open a terminal in this repo (or open the repo in VS Code)
2. Say: *"Analyze the security of my-profile.icc"* — if the file is in `test-profiles/`
3. Or provide your own file: *"Here is my ICC profile (base64-encoded): [paste]. Run a security scan."*

To base64-encode a file on your machine:
```bash
# macOS/Linux:
base64 < my-profile.icc | pbcopy    # copies to clipboard

# Windows PowerShell:
[Convert]::ToBase64String([IO.File]::ReadAllBytes("my-profile.icc")) | Set-Clipboard
```

### What You Get Back

Every analysis mode produces a plain-text report. Here is what a security scan looks like:

```
[H1] Profile Size: 16680 bytes — [OK] Size within normal range
[H2] Magic Bytes: acsp — [OK] Valid ICC magic signature
[H3] Data ColorSpace: Lab — [OK] Valid colorSpace
...
[H16] Signature Pattern Analysis — [WARN] repeat-byte pattern (fuzz artifact?)

HEURISTIC SUMMARY: 12 WARNING(S) DETECTED
  - Malformed/corrupted data
  - Resource exhaustion attempts
  - Enum confusion vulnerabilities
```

---

## Quick Start

### 1. Build the analysis tools

```bash
# From the repository root:

# Clone and build iccDEV, then build iccanalyzer-lite
cd iccanalyzer-lite
git clone https://github.com/InternationalColorConsortium/iccDEV.git iccDEV
cd iccDEV/Build
cmake Cmake \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -std=c++17" \
  -DENABLE_TOOLS=OFF \
  -DENABLE_STATIC_LIBS=ON \
  -Wno-dev
make -j$(nproc)
cd ../..
./build.sh
cd ..

# Build the XML conversion tools
cd colorbleed_tools
make setup && make
cd ..
```

### 2. Install the MCP server

```bash
cd mcp-server
pip install -e ".[dev]"
```

Or install from PyPI (once published):
```bash
pip install icc-profile-mcp
```

### 3. Connect to your AI assistant

See [Client Configuration](#client-configuration) below for your specific tool.

---

## Docker

Skip the C++ build entirely by using the pre-built Docker image:

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/xsscx/icc-profile-mcp:latest

# Run as MCP stdio server
docker run --rm -i ghcr.io/xsscx/icc-profile-mcp:latest

# Run the Web UI on port 8080
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web
```

Or build locally:

```bash
docker build -t icc-profile-mcp .
docker run --rm -p 8080:8080 icc-profile-mcp web
```

### Docker with Claude Desktop

```json
{
  "mcpServers": {
    "icc-profile-analyzer": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/xsscx/icc-profile-mcp:latest"]
    }
  }
}
```

---

## Web UI

A browser-based interface for interactive ICC profile analysis — no AI assistant required.

### Prerequisites

The Web UI requires the same C++ analysis tools as the MCP server. If you haven't built them yet, follow [Quick Start → Build the analysis tools](#1-build-the-analysis-tools) first.

Install the Python dependencies:

```bash
cd mcp-server
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Start the server

**Method 1 — Build script (recommended):**

```bash
cd mcp-server
./build.sh web              # http://0.0.0.0:8000 (all interfaces)
./build.sh web 8080         # custom port
./build.sh web 8080 1.2.3.4 # specific IP and port
```

**Method 2 — Direct (development):**

```bash
cd mcp-server
source .venv/bin/activate
ASAN_OPTIONS=detect_leaks=0 python web_ui.py
```

Server starts at `http://0.0.0.0:8000` (all interfaces).

**Method 3 — Entry point (after pip install):**

```bash
ASAN_OPTIONS=detect_leaks=0 icc-profile-web
```

**Method 4 — Docker (no build required):**

```bash
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web
```

Then open `http://127.0.0.1:8080`.

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` | Bind address. Use `127.0.0.1` for localhost only |
| `--port` | `8000` | Port number |

> **Note:** `ASAN_OPTIONS=detect_leaks=0` is required — the C++ analysis binaries are built with AddressSanitizer, and the leak checker can crash the Python process on intentionally malformed inputs.

### Using the Web UI

Open `http://127.0.0.1:8000` (local) or `http://127.0.0.1:8080` (Docker) in your browser.

#### Tool selector

The toolbar across the top provides all 7 analysis tools:

| Button | What it does |
|--------|-------------|
| **List Profiles** | Browse available ICC profiles by directory (`test-profiles`, `extended-test-profiles`, `xif`) |
| **Inspect** | Dump raw header bytes, tag table, and parsed field values |
| **Security Scan** | Run 19-phase heuristic security analysis |
| **Round-Trip** | Validate bidirectional color transform support |
| **Full Analysis** | Combined security + round-trip + structural inspection |
| **To XML** | Convert binary ICC profile to human-readable XML |
| **Compare** | Unified diff of two profiles side by side |

#### Typical workflow

1. **Select a tool** — click a button in the toolbar (e.g., *Security Scan*)
2. **Choose a profile** — type a filename or select from the dropdown (auto-populated from *List Profiles*)
3. **Run** — click the green **▶ Run** button
4. **Read the output** — results appear in the output pane below
5. **Copy or save** — use **Copy** (top-right of output) or **Save As** to download results as a text file

#### Upload your own profiles

Any tool that takes a profile path also has a **Choose File** button. Click it to upload an ICC profile from your local machine (up to 20 MB). The uploaded file is placed in a secure temp directory and becomes immediately available for analysis.

#### Save XML

When using **To XML**, an additional **Save XML** button appears. Click it to download the full XML conversion as a `.xml` file — useful for offline inspection or diffing.

#### Deep linking

Every tool has a URL hash (e.g., `#security`, `#xml`, `#compare`). You can bookmark or share direct links:

```
http://127.0.0.1:8000/#security
http://127.0.0.1:8000/#compare
```

#### Security

The Web UI enforces the same security protections as the MCP server — path traversal prevention, symlink boundary checks, null byte rejection, output size caps, and subprocess isolation. All responses include strict security headers (CSP with per-request nonce, X-Content-Type-Options, X-Frame-Options, Referrer-Policy).

---

## Tools Reference

### `inspect_profile`

**What it does:** Dumps the complete internal structure of an ICC profile — raw header bytes, tag table, and parsed field values.

**When to use:** You want to see what's actually inside a profile at the byte level.

**Example request:**
> "Inspect the structure of BlacklightPoster_411039.icc"

**Sample output:**
```
=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 41 28 41 44 42 45  02 10 00 00 61 62 73 74  |..A(ADBE....abst|
0x0010: 4C 61 62 20 4C 61 62 20  07 DB 00 0B 00 07 00 02  |Lab Lab ........|
0x0020: 00 31 00 01 61 63 73 70  41 50 50 4C 00 00 00 00  |.1..acspAPPL....|

Header Fields (RAW - no validation):
  Profile Size:    0x00004128 (16680 bytes) OK
  CMM:             0x41444245  'ADBE'
  Version:         0x02100000
  Device Class:    0x61627374  'abst'
```

---

### `analyze_security`

**What it does:** Runs a 19-phase security heuristic scan checking for fingerprint matches, tag anomalies, overflow indicators, malformed signatures, known attack patterns, date validation, repeat-byte signatures, spectral range anomalies, technology signatures, and tag offset/size overlap detection.

**When to use:** You want to know if a profile is suspicious, malformed, or potentially malicious.

**Example request:**
> "Run a security scan on cve-2022-26730-poc-sample-004.icc"

**Sample output:**
```
=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

[H1] Profile Size: 16680 bytes (0x00004128)
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x4C616220 (Lab )
     [OK] Known colorSpace: LabData
```

---

### `validate_roundtrip`

**What it does:** Checks whether a profile supports bidirectional color transforms by looking for symmetric tag pairs (AToB/BToA, DToB/BToD, Matrix/TRC).

**When to use:** You want to verify a profile can convert colors in both directions without data loss.

**Example request:**
> "Can the fidelity test profile do round-trip transforms?"

**Sample output:**
```
Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [[X]] [[X]]  [X] Round-trip capable
  AToB1/BToA1 (Rel. Colorimetric): [[X]] [[X]]  [X] Round-trip capable
  AToB2/BToA2 (Saturation):        [[X]] [[X]]  [X] Round-trip capable

[OK] RESULT: Profile supports round-trip validation
```

---

### `full_analysis`

**What it does:** Runs all analysis modes combined — security heuristics, round-trip validation, and structural inspection in one pass.

**When to use:** You want the most thorough analysis of a single profile.

**Example request:**
> "Give me a complete analysis of this suspicious ICC profile"

---

### `profile_to_xml`

**What it does:** Converts a binary ICC profile into human-readable XML showing all tags, elements, and data values.

**When to use:** You want to read the actual content of tags (color values, curves, descriptions) rather than just structural metadata.

**Example request:**
> "Convert BlacklightPoster_411039.icc to XML so I can read the tag contents"

**Sample output:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<IccProfile>
  <Header>
    <PreferredCMMType>ADBE</PreferredCMMType>
    <ProfileVersion>4.20</ProfileVersion>
    <DataColourSpace>RGB </DataColourSpace>
    <PCS>XYZ </PCS>
  </Header>
  <Tags>
    <copyrightTag>
      <multiLocalizedUnicodeType>
        <LocalizedText LanguageCountry="enUS">
          <![CDATA[Copyright 2007 Adobe Systems Incorporated]]>
        </LocalizedText>
      </multiLocalizedUnicodeType>
    </copyrightTag>
    ...
```

---

### `compare_profiles`

**What it does:** Runs structural inspection on two profiles and produces a unified diff showing exactly what differs between them.

**When to use:** You want to understand how two profiles (or two versions of the same profile) differ at a structural level.

**Example request:**
> "Compare the CVE PoC profile with the BlacklightPoster profile"

**Sample output:**
```diff
--- cve-2022-26730-poc-sample-004.icc
+++ BlacklightPoster_411039.icc
@@ -5,7 +5,7 @@
-Raw file size: 147564 bytes (0x2406C)
+Raw file size: 16680 bytes (0x4128)

-  Device Class:    0x6D6E7472  'mntr'
+  Device Class:    0x61627374  'abst'
```

---

### `list_test_profiles`

**What it does:** Lists all available ICC profiles in one of three directories, with file sizes.

**When to use:** You want to see what's available to analyze.

**Directories:**
| Directory | Contents |
|-----------|----------|
| `test-profiles` | 18 curated test cases — clean profiles and known-bug reproductions |
| `extended-test-profiles` | 54 profiles — CVE PoCs, crash samples, edge cases |
| `xif` | ~3,500 fuzzer-generated crash samples for regression testing |

**Example request:**
> "List the extended test profiles"

---

### `upload_and_analyze`

**What it does:** Accepts a base64-encoded ICC profile from any source, saves it to a secure temp directory, runs the requested analysis, and cleans up the file afterward.

**When to use:** You have your own ICC profile that is not already in the repository.

**Parameters:**
| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `data_base64` | Yes | — | Base64-encoded ICC profile data |
| `filename` | No | `uploaded.icc` | Original filename (for display only, sanitized) |
| `mode` | No | `security` | Analysis mode: `security`, `inspect`, `roundtrip`, `full`, `xml`, or `all` |

**Example requests:**
> "Here is my ICC profile (base64): AABBCCdd... — run a security scan"

> "Analyze this uploaded profile in all modes"

**How to get base64 from a file:**
```bash
# macOS / Linux
base64 < my-profile.icc

# Windows PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("my-profile.icc"))
```

**Security:** 20 MB size cap, 128-byte minimum, filename sanitization, secure temp dir (mode 700), auto-cleanup after analysis.

---

### `build_tools`

**What it does:** Builds the native C++ analysis tools (iccanalyzer-lite and/or colorbleed_tools) from source.

**When to use:** First-time setup, or after code changes to the analysis tools.

**Parameters:**
| Parameter | Default | Options |
|-----------|---------|---------|
| `target` | `all` | `all`, `iccanalyzer-lite`, `colorbleed_tools` |

**Example request:**
> "Build all the analysis tools"

---

## Profile Path Resolution

You can reference profiles by:

- **Filename only:** `BlacklightPoster_411039.icc` — searches `test-profiles/`, `extended-test-profiles/`, `xif/`, and the repo root
- **Directory-qualified:** `extended-test-profiles/cve-2023-46602.icc`
- **Absolute path:** `/full/path/to/profile.icc` (must be within the repository)

Paths that attempt to escape the repository (e.g., `../../etc/passwd`) are blocked by the security boundary validation.

---

## Client Configuration

### GitHub Copilot CLI

Add to `~/.config/github-copilot/mcp.json`:

```json
{
  "mcpServers": {
    "icc-profile-analyzer": {
      "command": "<REPO_ROOT>/mcp-server/.venv/bin/python",
      "args": ["<REPO_ROOT>/mcp-server/icc_profile_mcp.py"]
    }
  }
}
```

Or if installed via `pip install icc-profile-mcp`:
```json
{
  "mcpServers": {
    "icc-profile-analyzer": {
      "command": "icc-profile-mcp",
      "args": []
    }
  }
}
```

### VS Code (GitHub Copilot)

Add to `.vscode/mcp.json` in the workspace:

```json
{
  "servers": {
    "icc-profile-analyzer": {
      "command": "${workspaceFolder}/mcp-server/.venv/bin/python",
      "args": ["${workspaceFolder}/mcp-server/icc_profile_mcp.py"]
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json` (typically at `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "icc-profile-analyzer": {
      "command": "<REPO_ROOT>/mcp-server/.venv/bin/python",
      "args": ["<REPO_ROOT>/mcp-server/icc_profile_mcp.py"]
    }
  }
}
```

Or with Docker (no C++ build required):
```json
{
  "mcpServers": {
    "icc-profile-analyzer": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/xsscx/icc-profile-mcp:latest"]
    }
  }
}
```

### Cursor

Add to Cursor settings → MCP Servers, or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "icc-profile-analyzer": {
      "command": "<REPO_ROOT>/mcp-server/.venv/bin/python",
      "args": ["<REPO_ROOT>/mcp-server/icc_profile_mcp.py"]
    }
  }
}
```

> Replace `<REPO_ROOT>` with the absolute path to the repository root in all configs above.

---

## Security Model

This server processes untrusted binary files (fuzzer-generated crash samples, CVE PoCs). The following protections are in place:

| Protection | Detail |
|------------|--------|
| **Path traversal prevention** | All paths are resolved and validated against allowed base directories using `Path.resolve()` + `relative_to()` |
| **Symlink boundary enforcement** | Symlinks are followed but the resolved target must remain within the repository |
| **Null byte rejection** | Paths containing null bytes are rejected before any filesystem access |
| **Command injection prevention** | All subprocess calls use `exec` (argument list), never `shell=True` |
| **Output size cap** | Combined stdout+stderr limited to 10 MB to prevent memory exhaustion |
| **Process timeout** | All tool invocations have timeouts (60–120s) with proper process cleanup |
| **Temp file safety** | Temp files created with `mkstemp()` (secure, no race window) and cleaned up in `finally` blocks |
| **Sanitizer isolation** | `ASAN_OPTIONS=detect_leaks=0` prevents leak-checker noise on intentionally malformed inputs |

---

## Troubleshooting

### "iccanalyzer-lite not found"

The analysis binary hasn't been built. Run:
```bash
cd iccanalyzer-lite && ./build.sh
```
This requires `clang++`, `libxml2-dev`, `libssl-dev`, `liblzma-dev`, and iccDEV libraries built first.

### "iccToXml_unsafe not found"

The XML conversion tool hasn't been built. Run:
```bash
cd colorbleed_tools && make setup && make
```

### "Profile not found"

The server only looks in `test-profiles/`, `extended-test-profiles/`, `xif/`, and the repo root. Provide an absolute path for profiles stored elsewhere (must be within the repository).

### Tool returns stderr with ASAN output

This is expected — the binaries are compiled with AddressSanitizer instrumentation. ASAN output in stderr indicates the tool detected a memory safety issue in the profile being analyzed (which is useful information for security research).

### Large profiles produce truncated XML

XML output is capped at 50,000 characters to avoid overwhelming AI context windows. The full XML size is reported in the truncation notice.

---

## Example Workflows

### Triage a suspicious ICC profile

```
You: "List the extended test profiles"
You: "Run a security scan on cve-2023-46602.icc"
You: "Now inspect its raw structure — I want to see the tag table"
You: "Convert it to XML so I can read the actual tag contents"
```

### Analyze your own ICC profile

```
You: "Here is my ICC profile (base64-encoded): [paste base64 data]
      Run a full analysis."
```

Or in all modes at once:
```
You: "Upload and analyze this profile in all modes: [paste base64 data]"
```

### Compare a CVE PoC with a known-good profile

```
You: "Compare cve-2022-26730-poc-sample-004.icc with BlacklightPoster_411039.icc"
You: "What are the key structural differences?"
```

### Batch review crash samples

```
You: "List profiles in xif"
You: "Analyze the security of the first few crash samples"
You: "Which ones have malformed signatures or suspicious tags?"
```

### Validate a profile for production use

```
You: "Can xml-to-icc-to-xml-fidelity-test-001.icc do round-trip transforms?"
You: "Give me a full analysis to check for any issues"
```

### Full analysis workflow (for GitHub Issues / Copilot coding agent)

When filing an issue to analyze a profile, the agent should run these steps in order and include all raw output:

| Step | Command / MCP Tool | What to include |
|------|--------------------|-----------------|
| 1 | Rename `.icc.txt` → `.icc` | — |
| 2 | `iccanalyzer-lite -a <file>` or `analyze_security` | Complete raw output (security heuristics `[H1]`–`[H19]` + round-trip + structural) |
| 3 | `iccanalyzer-lite -nf <file>` or `inspect_profile` | Complete raw full dump — no truncation |
| 4 | `iccanalyzer-lite -r <file>` or `validate_roundtrip` | Complete raw round-trip accuracy output |
| 5 | Check exit code + stderr | Exit code per command (0=clean, 1=finding, 2=error) and any ASAN/UBSAN output |
| 6 | Written analysis | Your interpretation — placed **after** raw output, never replacing it |

**iccanalyzer-lite modes reference:**
| Flag | Mode | Description |
|------|------|-------------|
| `-a` | Comprehensive | All modes combined (security + round-trip + structural) |
| `-nf` | Ninja full | Full structural dump, no truncation |
| `-n` | Ninja | Structural dump (truncated) |
| `-r` | Round-trip | Bidirectional transform accuracy test |
| `-h` | Heuristics | Security heuristics only |

The raw iccanalyzer-lite output uses `[OK]`, `[WARN]`, `[FAIL]`, `[CRITICAL]` labels. This output MUST appear verbatim in the report — do not summarize or omit it.
