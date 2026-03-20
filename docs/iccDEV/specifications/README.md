# ICC Specification Documents — Ground Truth Reference

These PDFs are the authoritative source of truth for all ICC profile conformance
checks in iccanalyzer-lite. Every conformance check (CF-*) and PAWG checklist
item traces back to a specific section in one of these documents.

**Total: 25 documents | 143 conformance checks (CF-001..CF-143) | 171 security heuristics (H1-H171)**

## Primary Specifications

| Document | Version | Scope | CF Checks |
|----------|---------|-------|-----------|
| **ICC.1-2022-05.pdf** | v4.4 (126 pages) | Main profile specification — header layout, tag table, required tags, data types, PCS | CF-001..CF-122 |
| **ICC.2-2023.pdf** | v5.1 (iccMAX) | Extended profile specification — spectral PCS, MPE, calculator elements | CF-080..CF-089, CF-113..CF-115 |
| **ICC.1_Adaptive_Gain_Curve.pdf** | April 2025 amendment | ADGC tag — RGB+Input/Display only | CF-123..CF-136 |

## Older Specifications

| Document | Scope |
|----------|-------|
| **ICC.2-2019.pdf** | v5.0 (iccMAX) — superseded by ICC.2-2023 |

## Errata

| Document | Scope | CF Checks |
|----------|-------|-----------|
| **ICC.2-2019_Cumulative_Errata_List_2021-03-08.pdf** | Errata for ICC.2-2019 (March 2021) | CF-137..CF-143 |
| **ICC.2-2019_Cumulative_Errata_List_2021-09-09.pdf** | Errata for ICC.2-2019 (September 2021) | — |

## ICS (Interoperability Conformance Specifications)

These documents define the ICC Specification (ICS) framework for extended color
workflows. They are **new additions** — conformance checks are not yet implemented.

| Document | Scope | Coverage Status |
|----------|-------|-----------------|
| **ICS-ExtendedOutput-Part1.pdf** | Extended output color space modeling and device profile validation | ❌ Not yet implemented |
| **ICS-ExtendedRange-Part1.pdf** | Extended gamut color representations — Part 1 | ❌ Not yet implemented |
| **ICS-ExtendedRange-Part2.pdf** | Extended gamut color representations — Part 2 | ❌ Not yet implemented |
| **ICS-ExtendedRange-Part3.pdf** | Extended gamut color representations — Part 3 | ❌ Not yet implemented |

## Technical Notes

| Document | Scope |
|----------|-------|
| **ICC-Technote-ProfileEmbedding.pdf** | Rules for embedding ICC profiles in TIFF/JPEG/EPS |
| **ICC-Technote-PartialAdaptation.pdf** | Chromatic adaptation tag validation, chad matrix |
| **ICC_TN-06-2025_Recommendations_on_calculation_of_tristimulus_values.pdf** | Tristimulus weighting functions, observer data |
| **PSD_TechNote.pdf** | Profile Sequence Descriptor parsing pitfalls, size inference attacks |
| **Embedding_an_ICC.2_profile_in_an_ICC.1_profile.pdf** | Rules for nesting ICC.2 (v5/iccMAX) profiles inside ICC.1 (v4) profiles — version bridging constraints |

## Specification Revisions

| Document | Scope |
|----------|-------|
| **ICCSpecRevision_25-02-10_dictType.pdf** | Dictionary type metadata structure revision (§10.22) |
| **ICCSpecRevision_25-02-10_dictType-1.pdf** | Dictionary type metadata (variant) |

## White Papers

| Document | Scope |
|----------|-------|
| **ICC_white_paper_21-SampleICCProfileCompliance.pdf** | Sample compliance testing methodology |
| **ICC_White_Paper_54_Introduction_to_ICS.pdf** | Introduction to ICC Specification (ICS) framework |
| **ICC_White_Paper_57_Introduction_to_core_ICS_specifications.pdf** | Core ICS specification overview |

## Reference Documents

| Document | Scope |
|----------|-------|
| **v2profiles_v4.pdf** | Version interop — CIELAB encoding differences between v2 and v4 |
| **v4_matrix_entries.pdf** | s15Fixed16Number precision, matrix column constraints |
| **Guidelines_on_the_use_of_negative_PCSXYZ_values.pdf** | Wide-gamut (BT.2020/DCI-P3) XYZ ranges |
| **rfc1321.txt** | MD5 message-digest algorithm (profile ID calculation) |

## Other

| Document | Scope |
|----------|-------|
| **icc-individual-cla.pdf** | Contributor license agreement |

## Conformance Check Coverage Map

These documents are referenced by iccanalyzer-lite conformance checks:

| Module | CF Range | Spec Reference |
|--------|----------|---------------|
| `IccConformanceHeader.cpp` | CF-001..CF-015, CF-107, CF-121..CF-122 | ICC.1 §7.2 |
| `IccConformanceTagTypes.cpp` | CF-020..CF-034, CF-112, CF-123..CF-136 | ICC.1 §9-10, ADGC |
| `IccConformanceRequired.cpp` | CF-040..CF-053, CF-095..CF-098, CF-103..CF-104, CF-111, CF-117..CF-120 | ICC.1 §8.2-8.9 |
| `IccConformanceLUT.cpp` | CF-060..CF-070, CF-105..CF-106, CF-108..CF-110, CF-116 | ICC.1 §10.8-10.11 |
| `IccConformanceV5.cpp` | CF-080..CF-089, CF-113..CF-115, CF-137..CF-143 | ICC.2 §7-10, Errata |
| `IccConformanceSecurity.cpp` | CF-091..CF-094 | Security (malware, NOP/shellcode) |
| `IccConformanceQuality.cpp` | CF-099..CF-102 | Transform quality metrics |
| `IccAnalyzerPAWG.cpp` | — | PAWG 31-item assessment (maps to CF-* checks) |

**Total: 143 conformance checks (CF-001..CF-143)**

## Coverage Gaps — Candidate CF Checks

| Priority | Spec Document | Estimated Checks | Target Range |
|----------|--------------|-----------------|--------------|
| HIGH | ICS-ExtendedOutput-Part1.pdf | 8-12 | CF-144+ |
| HIGH | ICS-ExtendedRange-Part1/2/3.pdf | 15-25 | CF-156+ |
| HIGH | Embedding_an_ICC.2_profile_in_an_ICC.1_profile.pdf | 5-8 | CF-181+ |
| MEDIUM | ICCSpecRevision_25-02-10_dictType.pdf | 3-5 | CF-189+ |
