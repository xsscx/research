# CodeQL Security Analysis for iccDEV

Static analysis queries targeting vulnerability patterns in the
[iccDEV](https://github.com/InternationalColorConsortium/iccDEV) ICC profile library.

## Quick Start

```bash
# Build CodeQL database (one-time, reuse if source unchanged)
gh codeql database create /tmp/codeql-db-iccdev \
  --language=cpp --overwrite \
  --command=".github/scripts/codeql-build.sh" \
  --source-root="$(git rev-parse --show-toplevel)"

# Run all 42 security research queries
gh codeql database analyze /tmp/codeql-db-iccdev \
  --format=sarif-latest --output=/tmp/codeql-results.sarif --threads=0 \
  iccanalyzer-lite/codeql-queries/security-research-suite.qls

# Filter to iccDEV library code only (exclude test/tool code)
python3 -c "
import json
with open('/tmp/codeql-results.sarif') as f:
    sarif = json.load(f)
for r in sarif['runs'][0]['results']:
    uri = r['locations'][0]['physicalLocation']['artifactLocation']['uri']
    if 'IccProfLib' in uri or 'IccXML' in uri:
        line = r['locations'][0]['physicalLocation']['region']['startLine']
        print(f'{r[\"ruleId\"]} @ {uri}:{line}')
"
```

## Query Categories

| Category | Count | CWE Coverage | Source |
|----------|-------|-------------|--------|
| Memory safety | 14 | CWE-119/122/125/787 | Buffer overflows, OOB reads |
| Type safety | 6 | CWE-681/843 | Enum casts, NaN→int |
| Null safety | 4 | CWE-476 | Null deref after Read() |
| Allocation | 5 | CWE-789/762/908 | Oversized alloc, mismatch |
| Output correctness | 4 | CWE-134/688 | Format strings, missing args |
| Data flow | 4 | CWE-787/125/457 | Wrong index, uninitialized |
| Tool-specific | 5 | CWE-131/416 | DumpLut args, ownership |

## Documentation

| Document | Description |
|----------|-------------|
| [how-to-run.md](how-to-run.md) | Step-by-step setup and execution guide |
| [query-catalog.md](query-catalog.md) | All 42 queries with CWE mappings and CFL cross-references |
| [maintainer-workflow.md](maintainer-workflow.md) | CI integration, PR review, false positive management |

## Prerequisites

- `gh codeql` CLI extension (v2.24.1+)
- clang-18 / clang++-18
- libxml2-dev, libtiff-dev, libssl-dev
- Built iccDEV source tree

## Relationship to iccanalyzer-lite

CodeQL queries find bugs at **build time** via static analysis.
iccanalyzer-lite heuristics (H1-H173) detect the **same patterns at runtime**
by scanning raw ICC profile bytes. Both approaches are complementary:

| Query | Runtime Heuristic | CFL Patch |
|-------|------------------|-----------|
| `iccdev-describe-param-bounds.ql` | H171 | CFL-050/051 |
| `iccdev-describe-null-array.ql` | H98 | CFL-056 |
| `iccdev-format-specifier.ql` | — (output quality) | CFL-053/054 |
| `iccdev-signed-unsigned-format.ql` | — (output quality) | CFL-055 |
| `iccdev-uninitialized-constructor.ql` | — (design flaw) | CFL-057 |
| `iccdev-wrong-variable-index.ql` | — (data corruption) | CFL-052 |
| `iccdev-dumplut-missing-arg.ql` | — (output quality) | CFL-048/049 |
