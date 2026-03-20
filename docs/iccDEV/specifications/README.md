# ICC Specification Documents — Ground Truth Reference

These PDFs are the authoritative source of truth for all ICC profile conformance
checks in iccanalyzer-lite. Every conformance check (CF-*) and PAWG checklist
item traces back to a specific section in one of these documents.

## Primary Specifications

| Document | Version | Scope |
|----------|---------|-------|
| **ICC.1-2022-05.pdf** | v4.4 (126 pages) | Main profile specification — header layout, tag table, required tags, data types, PCS |
| **ICC.2-2023.pdf** | v5.1 (iccMAX) | Extended profile specification — spectral PCS, MPE, calculator elements |
| **ICC.1_Adaptive_Gain_Curve.pdf** | April 2025 amendment | ADGC tag — RGB+Input/Display only |

## Older Specifications

| Document | Scope |
|----------|-------|
| **ICC.2-2019.pdf** | v5.0 (iccMAX) — superseded by ICC.2-2023 |

## Errata

| Document | Scope |
|----------|-------|
| **ICC.2-2019_Cumulative_Errata_List_2021-03-08.pdf** | Errata for ICC.2-2019 (March 2021) |
| **ICC.2-2019_Cumulative_Errata_List_2021-09-09.pdf** | Errata for ICC.2-2019 (September 2021) |

## Technical Notes

| Document | Scope |
|----------|-------|
| **ICC-Technote-ProfileEmbedding.pdf** | Rules for embedding ICC profiles in TIFF/JPEG/EPS |
| **ICC-Technote-PartialAdaptation.pdf** | Chromatic adaptation tag validation, chad matrix |
| **ICC_TN-06-2025_Recommendations_on_calculation_of_tristimulus_values.pdf** | Tristimulus weighting functions, observer data |

## Specification Revisions

| Document | Scope |
|----------|-------|
| **ICCSpecRevision_25-02-10_dictType.pdf** | Dictionary type metadata structure revision |
| **ICCSpecRevision_25-02-10_dictType-1.pdf** | Dictionary type metadata (variant) |

## White Papers

| Document | Scope |
|----------|-------|
| **ICC_white_paper_21-SampleICCProfileCompliance.pdf** | Sample compliance testing methodology |
| **ICC_White_Paper_54_Introduction_to_ICS.pdf** | Introduction to ICC Specification (ICS) |
| **ICC_White_Paper_57_Introduction_to_core_ICS_specifications.pdf** | Core ICS specification overview |

## Other

| Document | Scope |
|----------|-------|
| **icc-individual-cla.pdf** | Contributor license agreement |

## Usage

These documents are referenced by iccanalyzer-lite conformance checks:
- `IccConformanceHeader.cpp` — CF-001..CF-015 (ICC.1 §7.2)
- `IccConformanceTagTypes.cpp` — CF-020..CF-034 (ICC.1 §9-10)
- `IccConformanceRequired.cpp` — CF-040..CF-053 (ICC.1 §8.2-8.9)
- `IccConformanceLUT.cpp` — CF-060..CF-070 (ICC.1 §10.8-10.11)
- `IccConformanceV5.cpp` — CF-080..CF-089 (ICC.2 §7-10)
- `IccAnalyzerPAWG.cpp` — PAWG 31-item assessment (maps to CF-* checks)
