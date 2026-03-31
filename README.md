# Security Research Tools for ICC Color Profiles

## Overview

<img width="3672" height="1917" alt="image" src="https://github.com/user-attachments/assets/8092db67-8705-4cef-8aef-f2a25afaa421" />

This monorepo centers on ICC profile security analysis, parity validation,
fuzzing, and an MCP/Web delivery surface for local and remote workflows.

## Project Snapshot

| Tool | LOC | Description |
|------|-----|-------------|
| **iccanalyzer-lite** | 22,400+ | V1 security analyzer with 173 heuristics, ASAN/UBSAN, TIFF image analysis, JSON/XML/report output, callgraph support, OOM protection, and Ninja mode |
| **icctest** | — | V2 rewrite and parity harness for `iccanalyzer-lite`; current saved baseline is raw parity `delta=0`, image parity `delta=0`, and `1822/1822` unit tests passed |
| **cfl** (13 fuzzers) | ~2,800 | LibFuzzer harnesses targeting upstream `iccDEV` tool and library paths |
| **colorbleed_tools** | 224 | Unsafe ICC↔XML converters for mutation testing |
| **mcp-server** | — | 26-tool ICC Profile MCP server with Web UI + REST API; security endpoints default to V2 while structural/reporting paths keep V1 where needed |

## Security Posture

| Check | Status | Details |
|-------|--------|---------|
| **CodeQL** | 0 alerts | v4, 3 targets × 14 custom queries + security-and-quality |
| **scan-build** | 0 bugs | 14 modules (12 `iccanalyzer-lite` + 2 `colorbleed_tools`) |
| **Action Pinning** | 100% | All actions SHA-pinned (actions/checkout v5.0.0: `08c6903`) |
| **Fuzzers** | 13/13 | Build + smoke test pass, aligned to project tool scope |
| **CFL Patches** | 44 active, 93 retired | Current patch catalog in [`cfl/patches/README.md`](cfl/patches/README.md) and the analyzer coverage matrix in [`docs/analysis/ICCANALYZER_CFL_PATCH_COVERAGE_MATRIX.md`](docs/analysis/ICCANALYZER_CFL_PATCH_COVERAGE_MATRIX.md) |

## Build

```bash
# iccanalyzer-lite (ASAN + UBSAN + coverage)
cd iccanalyzer-lite && ./build.sh

# icctest (V2 rewrite + parity harness)
cd iccanalyzer-lite/icctest && ./build.sh

# CFL fuzzers (auto-applies security patches to iccDEV)
cd cfl && ./build.sh

# colorbleed_tools
cd colorbleed_tools && make setup && make

# mcp-server (venv + tests)
cd mcp-server && ./build.sh test
```

## Test

```bash
# iccanalyzer-lite regression suite
python3 iccanalyzer-lite/tests/run_tests.py -v

# icctest unit + parity targets
ctest --test-dir iccanalyzer-lite/icctest/build --output-on-failure

# mcp-server and Web UI suites
cd mcp-server && ./build.sh test
```

## Fuzzing

```bash
cd cfl && ./ramdisk-fuzz.sh     # automated tmpfs workflow
cat .github/scripts/ramdisk-cheatsheet.sh  # copy-paste one-liners
```

`cfl/` builds 13 LibFuzzer harnesses against upstream `iccDEV` with the current
45-file security patch kit.

- Harness overview: [`cfl/README.md`](cfl/README.md)
- Active patch catalog: [`cfl/patches/README.md`](cfl/patches/README.md)
- Retired patch archive: [`cfl/patches-retired/README.md`](cfl/patches-retired/README.md)
- Analyzer-to-patch coverage matrix:
  [`docs/analysis/ICCANALYZER_CFL_PATCH_COVERAGE_MATRIX.md`](docs/analysis/ICCANALYZER_CFL_PATCH_COVERAGE_MATRIX.md)

## MCP Container and Web UI

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web
curl -fsS http://127.0.0.1:8080/api/health
```

Open `http://127.0.0.1:8080/`.

<img width="3742" height="1936" alt="image" src="https://github.com/user-attachments/assets/30a8c93f-6c78-4d1e-a67e-c38eb0cb8186" />

Current surface:

- `/` interactive Web UI with deep links such as `#security`,
  `#security_report`, `#pawg`, `#inspect`, `#graph_viewer`,
  `#coverage_gaps`, and `#scan_logs`
- `/api/health` liveness plus the current tool and engine metadata
- `/api/health-check` full bundled-tool health verification
- `/api/security-report`, `/api/pawg`, `/api/inspect`, `/api/full`,
  `/api/coverage-gaps`, `/api/attack-surface`, and `/api/scan-logs`
- `/api/knowledge-graph.json` backing the graph viewer

For stdio client configuration, upload flow, and the full REST surface, see
[`mcp-server/README.md`](mcp-server/README.md).

## Documentation Map

Start with [`docs/INDEX.md`](docs/INDEX.md) for task-based navigation and
[`docs/README.md`](docs/README.md) for the directory map.

Useful entry points:

- [`docs/analysis/ICCANALYZER_PARITY_AND_MCP_RELEASE_STATUS_2026-03-29.md`](docs/analysis/ICCANALYZER_PARITY_AND_MCP_RELEASE_STATUS_2026-03-29.md)
  for the saved parity, Docker, and workflow checkpoint
- [`docs/Testing/results/icctest-verify-parity-summary-2026-03-29.json`](docs/Testing/results/icctest-verify-parity-summary-2026-03-29.json)
  for the saved parity artifact
- [`docs/icc-format/ICC-Binary-Format-Reference.md`](docs/icc-format/ICC-Binary-Format-Reference.md)
  for ICC binary layout, CWE mapping, and analyzer notes

## Reusable Prompts

The repo currently ships 22 prompt templates in [`.github/prompts/`](.github/prompts/).
Good starting points:

- **analyze-icc-profile** — Full ICC security scan
- **health-check** — MCP server verification
- **icctest-parity-release** — V1/V2 parity, Docker, and workflow validation
- **remote-analysis** — REST API workflow for remote agents
- **triage-cve-poc** — CVE PoC analysis with cross-references

## ICC Specification References

Analysis heuristics and conformance checks are grounded in the official ICC
specification and related technotes:

| Document | Description |
|----------|-------------|
| [ICC.1-2022-05](https://www.color.org/specification/ICC.1-2022-05.pdf) | Profile specification v4.4 (primary reference) |
| [TN-06-2025 Tristimulus](https://archive.color.org/files/technotes/ICC_TN-06-2025_Recommendations_on_calculation_of_tristimulus_values.pdf) | Tristimulus value calculation |
| [Profile Embedding](https://archive.color.org/files/technotes/ICC-Technote-ProfileEmbedding.pdf) | Embedding in TIFF/JPEG/EPS |
| [Partial Adaptation](https://archive.color.org/files/technotes/ICC-Technote-PartialAdaptation.pdf) | Chromatic adaptation tag |
| [Negative PCS XYZ](https://archive.color.org/files/technotes/Guidelines_on_the_use_of_negative_PCSXYZ_values.pdf) | Wide-gamut XYZ ranges |
| [V4 Matrix Entries](https://archive.color.org/files/v4_matrix_entries.pdf) | Matrix precision constraints |
| [V2 in V4](https://archive.color.org/files/v2profiles_v4.pdf) | Version interoperability |
| [PSD TechNote](https://archive.color.org/files/PSD_TechNote.pdf) | Profile sequence description |
| [RFC 1321](https://www.ietf.org/rfc/rfc1321.txt) | MD5 (profile ID calculation) |

## Related Projects

| Project | Repository | Description |
|---------|-----------|-------------|
| **xnuimagetools** | [xsscx/xnuimagetools](https://github.com/xsscx/xnuimagetools) | Umbrella workspace — image generation + VideoToolbox fuzzer. Uses `xnuimagefuzzer` as a git submodule |
| **xnuimagefuzzer** | [xsscx/xnuimagefuzzer](https://github.com/xsscx/xnuimagefuzzer) | Primary iOS/macOS image fuzzer (15 bitmap contexts, 22+ formats) |
