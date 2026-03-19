# How to Run CodeQL on iccDEV

## Prerequisites

### 1. Install CodeQL CLI

```bash
# Via GitHub CLI extension (recommended)
gh extensions install github/gh-codeql

# Verify
gh codeql version
# Expected: CodeQL CLI 2.24.1+ (or newer)
```

### 2. Build Dependencies

```bash
# Ubuntu/Debian
sudo apt install -y clang-18 clang++-18 cmake \
  libxml2-dev libtiff-dev libpng-dev libjpeg-dev libssl-dev

# Verify
clang++-18 --version
```

### 3. Query Pack Dependencies

The query pack lock file is already committed at
`iccanalyzer-lite/codeql-queries/codeql-pack.lock.yml`.
Do NOT re-download query packs — they resolve automatically.

## Building the CodeQL Database

### Option A: iccDEV Library Only (recommended for maintainers)

```bash
# Uses the committed build script — do NOT create ad-hoc build scripts
gh codeql database create /tmp/codeql-db-iccdev \
  --language=cpp --overwrite \
  --command=".github/scripts/codeql-build.sh" \
  --source-root="$(git rev-parse --show-toplevel)"
```

The build script compiles IccProfLib, IccXML, and the CLI tools
with all necessary include paths and defines.

### Option B: Reuse Existing Database

If iccDEV source has not changed since the last database build:

```bash
ls -la /tmp/codeql-db-iccdev/db-cpp/
# If it exists and source hasn't changed, skip database creation
```

## Running Queries

### Full Security Suite (42 queries)

```bash
gh codeql database analyze /tmp/codeql-db-iccdev \
  --format=sarif-latest \
  --output=/tmp/codeql-iccdev-results.sarif \
  --threads=0 \
  iccanalyzer-lite/codeql-queries/security-research-suite.qls
```

### Single Query

```bash
gh codeql query run \
  iccanalyzer-lite/codeql-queries/iccdev-describe-param-bounds.ql \
  -d /tmp/codeql-db-iccdev \
  --output=/tmp/single-result.bqrs

# Decode results
gh codeql bqrs decode /tmp/single-result.bqrs --format=csv
```

### Maintainer Queries Only (7 new queries from CFL-048–057)

```bash
for q in iccdev-describe-param-bounds iccdev-describe-null-array \
         iccdev-format-specifier iccdev-signed-unsigned-format \
         iccdev-uninitialized-constructor iccdev-wrong-variable-index \
         iccdev-dumplut-missing-arg; do
  echo "=== $q ==="
  gh codeql query run \
    iccanalyzer-lite/codeql-queries/${q}.ql \
    -d /tmp/codeql-db-iccdev \
    --output=/tmp/${q}.bqrs
  gh codeql bqrs decode /tmp/${q}.bqrs --format=csv
done
```

## Interpreting Results

### SARIF Output

```bash
# Count results per rule
python3 -c "
import json
from collections import Counter
with open('/tmp/codeql-iccdev-results.sarif') as f:
    sarif = json.load(f)
counts = Counter()
for r in sarif['runs'][0]['results']:
    counts[r['ruleId']] += 1
for rule, count in counts.most_common():
    print(f'{count:4d}  {rule}')
print(f'Total: {sum(counts.values())} results across {len(counts)} rules')
"
```

### Filter to Specific Files

```bash
# Only IccProfLib results (core library)
python3 -c "
import json
with open('/tmp/codeql-iccdev-results.sarif') as f:
    sarif = json.load(f)
for r in sarif['runs'][0]['results']:
    uri = r['locations'][0]['physicalLocation']['artifactLocation']['uri']
    if 'IccProfLib' in uri:
        line = r['locations'][0]['physicalLocation']['region']['startLine']
        msg = r['message']['text'][:100]
        print(f'{r[\"ruleId\"]} @ {uri}:{line}')
        print(f'  {msg}')
"
```

### Filter by CWE

```bash
# Only CWE-125 (Out-of-bounds Read) results
python3 -c "
import json
with open('/tmp/codeql-iccdev-results.sarif') as f:
    sarif = json.load(f)
for r in sarif['runs'][0]['results']:
    tags = r.get('properties', {}).get('tags', [])
    if any('cwe-125' in t for t in tags):
        uri = r['locations'][0]['physicalLocation']['artifactLocation']['uri']
        line = r['locations'][0]['physicalLocation']['region']['startLine']
        print(f'{r[\"ruleId\"]} @ {uri}:{line}')
"
```

## Common Issues

### "No compilation commands found"
The build script must produce at least one compiled object.
Verify: `cat /tmp/codeql-db-iccdev/log/build-tracer.log | tail -20`

### Query takes too long
Use `--threads=0` (auto-detect cores). For single queries, limit scope:
```bash
gh codeql query run query.ql -d /tmp/codeql-db-iccdev --timeout=300
```

### "Pack resolution failed"
The lock file at `codeql-queries/codeql-pack.lock.yml` pins dependencies.
If it fails, delete and regenerate:
```bash
cd iccanalyzer-lite/codeql-queries && gh codeql pack install
```

### Database is stale
After pulling new iccDEV commits, rebuild the database:
```bash
gh codeql database create /tmp/codeql-db-iccdev \
  --language=cpp --overwrite \
  --command=".github/scripts/codeql-build.sh" \
  --source-root="$(git rev-parse --show-toplevel)"
```
