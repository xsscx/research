# CodeQL Security Analysis for ColorBleed Tools

**Purpose:** Security analysis of unsafe ICC XML tools for vulnerability research  
**Target Tools:** `iccFromXml_unsafe`, `iccToXml_unsafe`  
**Analysis Date:** 2026-02-07

## Overview

This directory contains CodeQL security queries specifically targeting the ColorBleed ICC XML conversion tools. These tools intentionally bypass validation for security research purposes.

## Query Categories

### Memory Safety (3 queries)
- **buffer-overflow.ql** - Buffer overflow detection in ICC profile parsing
- **use-after-free.ql** - Use-after-free vulnerabilities
- **integer-overflow-allocation.ql** - Integer overflow in memory allocations

### Integer Safety (2 queries)
- **integer-overflow-multiply.ql** - Multiplication overflow detection
- **type-confusion.ql** - Type confusion vulnerabilities

### Injection Attacks (3 queries)
- **injection-attacks.ql** - General injection vectors
- **xml-external-entity-attacks.ql** - XXE vulnerabilities
- **xml-all-attacks.ql** - Comprehensive XML attack patterns

### API Misuse (2 queries)
- **unchecked-io-return.ql** - Unchecked return values
- **enum-undefined-behavior.ql** - Enum undefined behavior

### Tool-Specific (3 queries)
- **all-tools-enum-reachability.ql** - Enum reachability for all tools
- **all-vulnerabilities-all-tools.ql** - Comprehensive vulnerability scan
- **iccdumpprofile-enum-reachability.ql** - Tool-specific analysis

## Usage

### Create CodeQL Database
```bash
cd colorbleed_tools
codeql database create \
  --language=cpp \
  --command="make -C ../../unsafe_source all" \
  codeql-db-colorbleed
```

### Run Security Analysis
```bash
codeql database analyze \
  codeql-db-colorbleed \
  codeql-queries/security-research-suite.qls \
  --format=sarif-latest \
  --output=colorbleed-tools-security.sarif
```

### Run Individual Query
```bash
codeql query run \
  codeql-queries/buffer-overflow.ql \
  --database=codeql-db-unsafe-tools \
  --output=buffer-overflow-results.bqrs
```

## Configuration

**File:** `codeql-config.yml`  
**Language:** C++17  
**Paths Analyzed:**
- `IccXML/CmdLine/IccFromXml/IccFromXml_unsafe.cpp`
- `IccXML/CmdLine/IccToXml/IccToXml_unsafe.cpp`

## Expected Findings

### High Priority
- Unchecked XML parsing errors
- Potential buffer overflows in profile size handling
- Integer overflows in LUT calculations
- XXE vulnerabilities in XML parser

### Medium Priority
- Missing input validation
- Resource leaks
- Type confusion in tag handling

### Research Focus
These tools are **intentionally unsafe** for security research. Findings should be documented and used to:
1. Validate fuzzer effectiveness
2. Develop exploit techniques for defense
3. Inform secure coding practices in main tools

## Integration

### Local Analysis
```bash
./run-codeql-analysis.sh
```

### CI/CD Integration
See `.github/workflows/` for automated CodeQL scanning workflows.

## References

- **Main CodeQL Config:** `../codeql-config.yml`
- **Governance:** `../../llmcjf/governance/ICCANALYZER_DEVELOPMENT_GUIDE.md`
- **Unsafe Tool Source:** `../../unsafe_source/`
- **Build Instructions:** `../../unsafe_source/BUILD.md`

---
**Last Updated:** 2026-02-07  
**Maintainer:** Security Research Team
