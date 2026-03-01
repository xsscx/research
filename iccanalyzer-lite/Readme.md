## iccAnalyzer-lite

Last Updated: 2026-03-01 01:55:00 UTC

tl;dr ICC Profile Analysis Tool for Security Research

## Target Audience
- Security Researcher
- NVD Analyst
- Developer

## Security Heuristics (H1–H27)

### Header-Level (H1–H8, H15–H17)
| ID | Check | Risk |
|----|-------|------|
| H1 | Profile size bounds | Oversized/zero-length profiles |
| H2 | Magic bytes (`acsp`) | Corrupted header |
| H3 | Data ColorSpace | Invalid colorspace enum |
| H4 | PCS ColorSpace | Invalid PCS enum |
| H5 | Platform signature | Unknown platform |
| H6 | Rendering Intent | Out-of-range intent |
| H7 | Profile Class | Unknown device class |
| H8 | Illuminant XYZ | NaN/Inf/negative illuminant |
| H15 | Date validation | Malformed timestamp |
| H16 | Signature patterns | Suspicious repeat-byte patterns |
| H17 | Spectral range | Invalid spectral parameters |

### Tag-Level (H9–H14, H18–H19)
| ID | Check | Risk |
|----|-------|------|
| H9 | Text tag presence | Missing description/copyright |
| H10 | Tag count | Excessive (>200) or zero tags |
| H11 | CLUT entry limit | >16M CLUT entries (OOM) |
| H12 | MPE chain depth | Excessive element chains |
| H13 | Per-tag size | Tags >64MB |
| H14 | TagArrayType (tary) | UAF via type confusion |
| H18 | Technology signature | Non-standard technology |
| H19 | Tag offset overlap | Overlapping tag data regions |

### Deep Content Analysis (H20–H24)
| ID | Check | Risk |
|----|-------|------|
| H20 | Tag type signature validation | Non-printable/null type bytes → corrupted tag data |
| H21 | tagStruct member inspection | Malformed struct members, invalid member types |
| H22 | NumArray scalar expectation | Multi-value array in scalar context → **SBO** (patch 027, SCARINESS:51) |
| H23 | NumArray value ranges | NaN/Inf values → FPE/div-by-zero |
| H24 | Nesting depth | Recursive struct/array depth >4 → stack overflow (patch 061) |

### Raw File Analysis (H25–H27)
| ID | Check | Risk |
|----|-------|------|
| H25 | Tag offset/size OOB | Tag data extends past file/profile bounds → **HBO** (issues #623, #625) |
| H26 | NamedColor2 string validation | Prefix/suffix with XML-expandable chars overflow icFixXml 256-byte buffer → **SBO** (issue #624, SCARINESS:55) |
| H27 | MPE matrix dimensions | Matrix with <3 output channels → **HBO** in pushXYZConvert (issue #625) |

## Build

The analyzer links against **unpatched upstream iccDEV** to detect bugs in the original library code.

```bash
cd iccanalyzer-lite && ./build.sh
```

## Run

```
   docker pull ghcr.io/xsscx/icc-profile-mcp:dev
   docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:dev icc-profile-web --host 0.0.0.0 --port 8080
```
<img width="3742" height="1936" alt="image" src="https://github.com/user-attachments/assets/30a8c93f-6c78-4d1e-a67e-c38eb0cb8186" />
