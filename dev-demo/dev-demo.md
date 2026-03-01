# ICC Profile Security Research — Developer Guide

> **Audience**: Developers integrating ICC profile security analysis into their workflow
> **Paths**: Clone & GitHub Issues · Docker Image & API · WebUI
> **Time to first result**: < 2 minutes (Docker) · < 5 minutes (clone)

---

## 🚀 Quickstart — Try It in 60 Seconds

**Prerequisites:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.

**Step 1 — Pull and run** (copy-paste this into your terminal):

```bash
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-demo:latest
```

**Step 2 — Open your browser** to <http://127.0.0.1:8080>

You'll see an interactive demo page with built-in ICC profile security analysis tools. Click any button to start — 126 test profiles are included, no setup needed.

**Step 3 — Try the API** (open a new terminal tab):

```bash
# Check the server is running
curl http://127.0.0.1:8080/api/health

# Run a security scan on a sample profile
curl 'http://127.0.0.1:8080/api/security?path=sRGB_D65_MAT.icc'
```

**To stop:** press `Ctrl+C` in the terminal where Docker is running, or run `docker stop $(docker ps -q --filter ancestor=ghcr.io/xsscx/icc-profile-demo)`.

---

## Table of Contents

- [Quickstart](#-quickstart--try-it-in-60-seconds)
- [Path 1 — Clone the Repo & Use GitHub Issues](#path-1--clone-the-repo--use-github-issues)
- [Path 2 — Docker Image & REST API](#path-2--docker-image--rest-api)
- [Path 3 — WebUI (Browser-Based)](#path-3--webui-browser-based)
- [Developer Use Cases](#developer-use-cases)
- [API Reference](#api-reference)
- [MCP Integration for AI-Assisted Development](#mcp-integration-for-ai-assisted-development)
- [Troubleshooting](#troubleshooting)

---

## Path 1 — Clone the Repo & Use GitHub Issues

The simplest workflow: clone, open an issue with your ICC profile, and the Copilot coding agent runs the full analysis automatically.

### Step 1: Clone

```bash
git clone https://github.com/xsscx/research.git
cd research
```

### Step 2: Submit a Profile for Analysis

GitHub does not allow `.icc` file attachments. Rename first:

```bash
# Rename your profile
cp my-profile.icc my-profile.icc.txt
```

Open an issue at [github.com/xsscx/research/issues](https://github.com/xsscx/research/issues) and attach the `.icc.txt` file with this template:

```markdown
## Analyze ICC Profile

Please analyze the attached ICC profile.

Run the full analysis workflow:
1. Rename the attached `.icc.txt` to `.icc`
2. Run `iccanalyzer-lite -a` (comprehensive analysis) — include complete raw output
3. Run `iccanalyzer-lite -nf` (ninja full dump) — include complete raw output
4. Run `iccanalyzer-lite -r` (round-trip test) — include complete raw output
5. Include the exit code from each command and any ASAN/UBSAN stderr
6. Add your analysis after the raw tool output — do not replace it with a summary
```

### What Happens Next

1. The **Copilot coding agent** picks up the issue automatically
2. It downloads the attachment, renames `.icc.txt` → `.icc`
3. Runs `analyze-profile.sh` which executes all 3 analysis commands
4. Posts the complete report as a **pull request**
5. Report includes raw output, exit codes, ASAN/UBSAN findings, and analysis summary

### Step 3: Build Locally (Optional)

If you want to run analysis on your own machine:

```bash
# Prerequisites: clang/clang++ 18+, cmake 3.15+, libxml2-dev, libtiff-dev

# Build iccanalyzer-lite (ASAN + UBSAN + coverage)
cd iccanalyzer-lite && ./build.sh && cd ..

# Build XML conversion tools
cd colorbleed_tools && make setup && make && cd ..
```

Run analysis directly:

```bash
# Comprehensive analysis (all 32 heuristics + structure + round-trip)
./iccanalyzer-lite/iccanalyzer-lite -a path/to/profile.icc

# Full analysis via orchestration script (generates markdown report)
./analyze-profile.sh path/to/profile.icc
# Report written to analysis-reports/
```

### Exit Code Reference

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings |
| `1` | Finding — security heuristic triggered |
| `2` | Error — malformed input or tool failure |
| `3` | Usage — incorrect command-line arguments |

---

## Path 2 — Docker Image & REST API

Skip all builds. The Docker image includes pre-built binaries and the REST API server.

### Pull & Run

```bash
# Developer demo (recommended — includes interactive HTML report + all API endpoints)
docker pull ghcr.io/xsscx/icc-profile-demo:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-demo:latest
# Routes: / (demo report), /ui (interactive WebUI), /api (endpoint index), /api/* (analysis)

# Custom port
docker run --rm -p 8083:8083 ghcr.io/xsscx/icc-profile-demo:latest --port 8083

# Production image (WebUI at /, API at /api/*)
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web

# MCP stdio server (for AI assistants — works with either image)
docker run --rm -i ghcr.io/xsscx/icc-profile-demo:latest mcp
```

### Health Check

```bash
curl -s http://127.0.0.1:8080/api/health | python3 -m json.tool
# {"ok": true, "tools": 15}
```

### API Examples — curl

#### List Available Profiles

```bash
# List profiles in test-profiles/
curl -s 'http://127.0.0.1:8080/api/list?directory=test-profiles' | python3 -m json.tool
```

#### Security Scan

```bash
# Run 32-heuristic security scan on a profile
curl -s 'http://127.0.0.1:8080/api/security?path=sRGB_D65_MAT.icc'
```

#### Inspect Profile Structure

```bash
# Dump header, tag table, and parsed field values
curl -s 'http://127.0.0.1:8080/api/inspect?path=sRGB_D65_MAT.icc'
```

#### Round-Trip Validation

```bash
# Check bidirectional transform support
curl -s 'http://127.0.0.1:8080/api/roundtrip?path=sRGB_D65_MAT.icc'
```

#### Full Analysis (All Modes Combined)

```bash
# Security + round-trip + structural inspection
curl -s 'http://127.0.0.1:8080/api/full?path=sRGB_D65_MAT.icc'
```

#### Convert to XML

```bash
# Binary ICC → human-readable XML
curl -s 'http://127.0.0.1:8080/api/xml?path=sRGB_D65_MAT.icc'
```

#### Compare Two Profiles

```bash
# Unified diff between two profiles
curl -s 'http://127.0.0.1:8080/api/compare?path_a=sRGB_D65_MAT.icc&path_b=sRGB_v4_ICC_preference.icc'
```

#### Upload & Analyze Your Own Profile

```bash
# Upload a local .icc file for security analysis
curl -s -X POST 'http://127.0.0.1:8080/api/upload' \
  -F 'file=@/path/to/my-profile.icc'
```

After upload, the profile is available for all tools:

```bash
# Run security scan on uploaded file
curl -s 'http://127.0.0.1:8080/api/security?path=my-profile.icc'
```

#### Download Results

```bash
# Save tool output as a file
curl -s -X POST 'http://127.0.0.1:8080/api/output/download' \
  -H 'Content-Type: application/json' \
  -d '{"text": "...", "filename": "report.txt"}' \
  -o report.txt
```

### Scripting Example — Batch Analysis

```bash
#!/usr/bin/env bash
set -euo pipefail

API="http://127.0.0.1:8080/api"

# Get list of profiles
profiles=$(curl -s "$API/list?directory=test-profiles" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for line in data.get('output','').split('\n'):
    if line.strip().endswith('.icc'):
        print(line.strip().split()[-1])
")

# Run security scan on each
for p in $profiles; do
    echo "=== Scanning: $p ==="
    curl -s "$API/security?path=$p" | head -20
    echo ""
done
```

### Scripting Example — CI/CD Integration

```bash
#!/usr/bin/env bash
# Validate ICC profiles before deployment
set -euo pipefail

PROFILE="$1"
API="http://127.0.0.1:8080/api"

result=$(curl -s "$API/security?path=$PROFILE")

if echo "$result" | grep -q "CRITICAL"; then
    echo "BLOCKED: Critical security finding in $PROFILE"
    echo "$result"
    exit 1
elif echo "$result" | grep -q "WARNING"; then
    echo "WARNING: Security findings in $PROFILE (review required)"
    echo "$result"
    exit 0
else
    echo "PASS: $PROFILE is clean"
    exit 0
fi
```

### Docker Compose — Persistent Analysis Service

```yaml
# docker-compose.yml
services:
  icc-analyzer:
    image: ghcr.io/xsscx/icc-profile-demo:latest
    ports:
      - "8080:8080"
    restart: unless-stopped
    # Mount a local directory of profiles to analyze
    volumes:
      - ./my-profiles:/app/my-profiles:ro
```

```bash
docker compose up -d
# Now your profiles in ./my-profiles/ are accessible via the API
curl -s 'http://127.0.0.1:8080/api/security?path=my-profiles/custom.icc'
```

---

## Path 3 — WebUI (Browser-Based)

A single-page dark-themed interface for interactive analysis — no terminal required.

### Launch

```bash
# Docker (recommended — no dependencies)
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-demo:latest

# Local (after pip install)
cd mcp-server
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
ASAN_OPTIONS=detect_leaks=0 python3 web_ui.py
# Server starts at http://0.0.0.0:8000
```

Open your browser to `http://127.0.0.1:8080` (Docker) or `http://127.0.0.1:8000` (local).

### WebUI Walkthrough

#### 1. Browse Profiles
Click **List Profiles** → select a directory (`test-profiles`, `extended-test-profiles`, or `xif`). The dropdown populates with available `.icc` files.

#### 2. Run a Tool
Select a profile from the dropdown (or type a filename), click any tool button:

| Button | What You Get |
|--------|-------------|
| **Inspect** | Raw header bytes, tag table, parsed field values |
| **Security Scan** | 32-heuristic security report with `[OK]`/`[WARN]`/`[FAIL]`/`[CRITICAL]` labels |
| **Round-Trip** | AToB/BToA and DToB/BToD tag pair completeness check |
| **Full Analysis** | Combined security + round-trip + structural inspection |
| **To XML** | Human-readable XML conversion of all tags and values |
| **Compare** | Unified diff between two selected profiles |

#### 3. Upload Your Own Profile
Click **Choose File** → select any `.icc` file (up to 20 MB). The file uploads, appears in the profile list, and is immediately available for all tools.

#### 4. Save Results
- **Copy** — copies output to clipboard
- **Save As** — downloads the output as a `.txt` file
- **Save XML** — (after To XML) downloads the full XML conversion

#### 5. Deep Linking
Share direct links to specific tools:
```
http://127.0.0.1:8080/#security
http://127.0.0.1:8080/#compare
http://127.0.0.1:8080/#xml
```

### WebUI Security Model

| Control | Detail |
|---------|--------|
| CSP | Per-request nonce — no inline scripts allowed |
| Headers | X-Frame-Options: DENY, X-Content-Type-Options: nosniff |
| Path validation | Realpath jail — profiles must resolve within allowed directories |
| Upload limits | 20 MB max, filename sanitization, null byte rejection |
| Concurrency | Async semaphore caps at 4 simultaneous analyses |

---

## Developer Use Cases

### Use Case 1: Pre-Deployment Profile Validation

*You're building an app that accepts user-uploaded ICC profiles. Validate them before use.*

```bash
# Start the analyzer
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-demo:latest &

# In your upload handler, validate the profile
curl -s "http://127.0.0.1:8080/api/security?path=user-upload.icc" \
  | grep -c "CRITICAL"
# 0 = safe to use, >0 = reject
```

### Use Case 2: CVE Reproduction & Analysis

*A CVE references a malformed ICC profile. Analyze the PoC.*

```bash
# The repo includes CVE PoCs in extended-test-profiles/
curl -s 'http://127.0.0.1:8080/api/list?directory=extended-test-profiles' \
  | grep -i cve

# Analyze the CVE-2022-26730 PoC
curl -s 'http://127.0.0.1:8080/api/full?path=cve-2022-26730-poc-sample-004.icc'

# Compare PoC with a clean profile to see what's different
curl -s 'http://127.0.0.1:8080/api/compare?path_a=cve-2022-26730-poc-sample-004.icc&path_b=sRGB_D65_MAT.icc'
```

### Use Case 3: Fuzzing Triage

*Your fuzzer produced 500 crash samples. Triage them.*

```bash
# Copy crash samples into the container
docker run --rm -p 8080:8080 \
  -v ./crash-samples:/app/crash-samples:ro \
  ghcr.io/xsscx/icc-profile-demo:latest &

# Batch security scan
for f in crash-samples/*.icc; do
    name=$(basename "$f")
    echo "--- $name ---"
    curl -s "http://127.0.0.1:8080/api/security?path=crash-samples/$name" \
      | grep -E "CRITICAL|WARN|FAIL"
done
```

### Use Case 4: Color Pipeline Testing

*You're developing a color management pipeline. Verify your profiles support round-trip transforms.*

```bash
# Check if a profile can convert colors bidirectionally
curl -s 'http://127.0.0.1:8080/api/roundtrip?path=my-output-profile.icc'

# Look for:
#   "Round-trip capable" = good
#   "Forward only"       = one-direction only (may lose data)
#   "No transform tags"  = profile can't do color transforms
```

### Use Case 5: Profile Forensics

*Investigate a suspicious profile — what's actually in it?*

```bash
# Step 1: Raw structure (header bytes, tag table)
curl -s 'http://127.0.0.1:8080/api/inspect?path=suspicious.icc'

# Step 2: Security heuristics (27 checks)
curl -s 'http://127.0.0.1:8080/api/security?path=suspicious.icc'

# Step 3: Human-readable XML (every tag value)
curl -s 'http://127.0.0.1:8080/api/xml?path=suspicious.icc'

# Step 4: Compare with a known-good profile
curl -s 'http://127.0.0.1:8080/api/compare?path_a=suspicious.icc&path_b=sRGB_D65_MAT.icc'
```

### Use Case 6: GitHub Issue Automation

*Integrate profile analysis into your team's issue workflow.*

```bash
# 1. Clone the repo
git clone https://github.com/xsscx/research.git && cd research

# 2. Create an issue with the profile attached
#    (rename .icc → .icc.txt first for GitHub)
cp suspect.icc suspect.icc.txt
gh issue create \
  --title "Analyze suspect.icc" \
  --body "$(cat <<'EOF'
## Analyze ICC Profile

Please analyze the attached ICC profile.

Run the full analysis workflow:
1. Rename the attached `.icc.txt` to `.icc`
2. Run `iccanalyzer-lite -a` — include complete raw output
3. Run `iccanalyzer-lite -nf` — include complete raw output
4. Run `iccanalyzer-lite -r` — include complete raw output
5. Include exit codes and any ASAN/UBSAN stderr
EOF
)" --label "analyze"

# 3. Attach the file via GitHub web UI
#    (gh cli doesn't support issue file attachments yet)

# 4. The Copilot coding agent picks it up and creates a PR with the report
```

---

## API Reference

### Endpoints

All endpoints return plain text or JSON. Base URL: `http://127.0.0.1:8080`

| Method | Endpoint | Parameters | Description |
|--------|----------|------------|-------------|
| `GET` | `/` | — | WebUI single-page app |
| `GET` | `/api/health` | — | Health check: `{"ok": true, "tools": 15}` |
| `GET` | `/api/list` | `directory` | List profiles: `test-profiles`, `extended-test-profiles`, `xif` |
| `GET` | `/api/inspect` | `path` | Structural dump (header + tag table) |
| `GET` | `/api/security` | `path` | 32-heuristic security scan |
| `GET` | `/api/roundtrip` | `path` | Round-trip transform validation |
| `GET` | `/api/full` | `path` | Combined analysis (security + round-trip + structure) |
| `GET` | `/api/xml` | `path` | Binary ICC → XML conversion |
| `GET` | `/api/compare` | `path_a`, `path_b` | Unified diff of two profiles |
| `POST` | `/api/upload` | `file` (multipart) | Upload `.icc` file (20 MB max) |
| `POST` | `/api/output/download` | `text`, `filename` (JSON) | Download tool output as file |
| `POST` | `/api/cmake/configure` | JSON body | Configure iccDEV cmake build |
| `POST` | `/api/cmake/build` | JSON body | Compile configured build |
| `POST` | `/api/cmake/option-matrix` | JSON body | Test cmake option toggles |
| `POST` | `/api/cmake/windows-build` | JSON body | Windows MSVC build config |

### Response Format

Analysis endpoints return JSON:

```json
{
  "tool": "analyze_security",
  "profile": "sRGB_D65_MAT.icc",
  "output": "[H1] Profile Size: 3212 bytes...\n[H2] Magic Bytes: acsp...",
  "exit_code": 0
}
```

### Error Responses

```json
{
  "error": "Profile not found: nonexistent.icc",
  "status": 404
}
```

```json
{
  "error": "Path traversal blocked: ../../etc/passwd",
  "status": 400
}
```

---

## MCP Integration for AI-Assisted Development

### VS Code Copilot Chat

Already configured in `.vscode/mcp.json` — open the repo in VS Code and tools auto-register.

```bash
cd mcp-server && pip install -e .
```

Then in Copilot Chat: *"Analyze the security of sRGB_D65_MAT.icc"*

### Copilot CLI

```bash
# Install the MCP server
cd mcp-server && pip install -e .

# Add to Copilot CLI config (~/.config/github-copilot/mcp.json)
cat > ~/.config/github-copilot/mcp.json << 'EOF'
{
  "mcpServers": {
    "icc-profile-analyzer": {
      "command": "icc-profile-mcp",
      "args": []
    }
  }
}
EOF

# Or use /mcp command in Copilot CLI to add interactively
```

### Claude Desktop

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

### Available MCP Tools (15)

| # | Tool | Category | Description |
|---|------|----------|-------------|
| 1 | `inspect_profile` | Analysis | Header, tag table, field values |
| 2 | `analyze_security` | Analysis | 32-heuristic security scan |
| 3 | `validate_roundtrip` | Analysis | AToB/BToA completeness |
| 4 | `full_analysis` | Analysis | All modes combined |
| 5 | `profile_to_xml` | Analysis | ICC → XML conversion |
| 6 | `compare_profiles` | Analysis | Unified diff of two profiles |
| 7 | `list_test_profiles` | Analysis | Browse available profiles |
| 8 | `upload_and_analyze` | Analysis | Base64 upload + analysis |
| 9 | `build_tools` | Maintainer | Build C++ analysis tools |
| 10 | `cmake_configure` | Maintainer | Configure iccDEV cmake |
| 11 | `cmake_build` | Maintainer | Compile cmake build |
| 12 | `create_all_profiles` | Maintainer | Generate ~80+ ICC test profiles |
| 13 | `run_iccdev_tests` | Maintainer | Validate generated profiles |
| 14 | `cmake_option_matrix` | Maintainer | Test 17 cmake toggles |
| 15 | `windows_build` | Maintainer | MSVC + vcpkg build |

---

## Troubleshooting

### "iccanalyzer-lite not found"

Build it locally:
```bash
cd iccanalyzer-lite && ./build.sh
```
Requires: `clang++` 18+, `cmake` 3.15+, `libxml2-dev`, `libtiff-dev`

Or use Docker to skip the build entirely:
```bash
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-demo:latest
```

### ASAN/UBSAN output in stderr

This is **expected and useful**. The analysis binaries are compiled with AddressSanitizer instrumentation. When ASAN fires, it means the profile triggered a real memory safety bug in the upstream library — that's a finding, not an error.

### "Profile not found"

The server searches these directories in order:
1. `test-profiles/`
2. `extended-test-profiles/`
3. `xif/`
4. Repository root

Provide an absolute path for profiles outside these directories (must be within the repository boundary).

### Large profiles produce truncated XML

XML output is capped at 50,000 characters. The full size is reported in the truncation notice. Use `iccanalyzer-lite -nf` for untruncated structural output.

### Docker container can't see my profiles

Mount your profile directory:
```bash
docker run --rm -p 8080:8080 \
  -v /path/to/my-profiles:/app/my-profiles:ro \
  ghcr.io/xsscx/icc-profile-demo:latest
```

Then reference as `my-profiles/filename.icc` in API calls.

### WebUI not loading

Check the server is running:
```bash
curl -s http://127.0.0.1:8080/api/health
```

If using local install, ensure `ASAN_OPTIONS=detect_leaks=0` is set:
```bash
ASAN_OPTIONS=detect_leaks=0 python3 web_ui.py
```
