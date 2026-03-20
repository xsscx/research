# iccDumpAll Tool - Comprehensive Analysis

## Overview

**iccDumpAll** is an enhanced ICC profile dumping tool based on the upstream `iccDumpProfile` from iccDEV. It extends the standard profile dump functionality with specific enhancements for v5/iccMAX profiles, particularly:
- **MPE element type visualization** 
- **Spectral/BRDF tag detection**
- **Late-binding element identification**
- **Enhanced element chain I/O flow reporting**

**Location**: `/home/xss/research/colorbleed_tools/IccDumpAll.cpp` (510 lines)  
**Binary**: `/home/xss/research/colorbleed_tools/bin/sanitizer/iccDumpAll` (18 MB)  
**Version**: Built with IccProfLib 2.3.1.5

---

## 1. What iccDumpAll Does Beyond iccDumpProfile

### Key Enhancements

| Feature | iccDumpProfile | iccDumpAll |
|---------|---|---|
| **Profile Header Dump** | ✓ | ✓ |
| **Tag Enumeration** | ✓ | ✓ |
| **Tag Offset/Size/Padding** | ✓ | ✓ |
| **MPE Element Chain Summary** | ✗ | **✓** |
| **MPE Element Type Signatures** | ✗ | **✓** |
| **V5/iccMAX Profile Summary** | ✗ | **✓** |
| **Late-Binding Element Detection** | ✗ | **✓** |
| **BRDF Tag Counting** | ✗ | **✓** |
| **Spectral Tag Enumeration** | ✗ | **✓** |
| **MCS Color Space Detection** | ✗ | **✓** |

### New Output Sections in iccDumpAll

#### A. MPE Element Chain Visualization (per tag)
```
  === MPE Element Chain: 1 elements, 3->3 channels ===
  [1] Calculator Element ('calc' = 63616C63) 3->3
  ===
```

#### B. Version 5 / iccMAX Profile Summary Section
```
Version 5 / iccMAX Profile Summary
----------------------------------

  Spectral Tags:
    Spectral Viewing Conditions (svcn)     PRESENT
    Spectral Data Info (sdin)              ---
    Spectral White Point (swpt)            ---
    Custom-to-Standard PCC (c2sp)          PRESENT
    Standard-to-Custom PCC (s2cp)          PRESENT

  BRDF Tags:                  0 of 16 present
  Gamut Boundary Desc:        gbd0=--- gbd1=---
  MCS Color Space:            Not Defined

  MPE Tags:                   4 (multiProcessElementType)
  Late-Binding Elements:      0 (spectral observer/emission)
```

---

## 2. Source Files Implementing iccDumpAll

### Primary Implementation

**File**: `/home/xss/research/colorbleed_tools/IccDumpAll.cpp`

#### Key Functions:
```cpp
// Helper: Get late-binding notation for spectral elements
static const char* GetLateBindingNote(icElemTypeSignature sig)

// Enhanced tag dump with MPE element chain visualization
void DumpTagCore(CIccTag *pTag, icTagSignature sig, int nVerboseness)

// Wrapper: lookup tag by signature and dump it
void DumpTagSig(CIccProfile *pIcc, icTagSignature sig, int nVerboseness)

// Wrapper: lookup tag by entry and dump it
void DumpTagEntry(CIccProfile *pIcc, IccTagEntry &entry, int nVerboseness)

// NEW: v5/iccMAX profile summary section
void DumpV5Summary(CIccProfile *pIcc)

// Entry point
int main(int argc, char* argv[])

// Usage printer
void printUsage(void)
```

### Dependencies (iccDEV Library)

**Header Files** (in `/home/xss/research/colorbleed_tools/iccDEV/IccProfLib/`):

| File | Purpose |
|------|---------|
| `IccProfile.h` | Core profile object, `CIccProfile`, `TagEntryList`, `FindTag()` |
| `IccTag.h` | Base tag class `CIccTag`, tag types |
| `IccUtil.h` | `CIccInfo` - formatter for signatures and names |
| `IccTagMPE.h` | MPE classes: `CIccTagMultiProcessElement`, `CIccMultiProcessElement` |
| `IccProfLibVer.h` | Version string macro `ICCPROFLIBVER` |
| `icProfileHeader.h` | Constants: tag signatures, element signatures, version numbers |

**Library Components Used**:
- **iccDEV/IccProfLib** - Core ICC library (built by build.sh)
- **iccDEV/IccXML** - XML support (not used by iccDumpAll, included for build compatibility)

---

## 3. V5/iccMAX Features Detected and Reported

### Function: `DumpV5Summary(CIccProfile *pIcc)`  
**Location**: IccDumpAll.cpp:112-201  
**Trigger**: Only runs if `pHdr->version >= icVersionNumberV5` (0x05000000)

### A. Spectral Tags (5 tags checked)

```cpp
// Lines 124-130: Tag signatures
icSigSpectralViewingConditionsTag    // 'svcn' = 0x7376636e
icSigSpectralDataInfoTag              // 'sdin' = 0x7364696e
icSigSpectralWhitePointTag            // 'swpt' (not shown in output)
icSigCustomToStandardPccTag           // 'c2sp' = 0x63327370
icSigStandardToCustomPccTag           // 's2cp' = 0x73326370
```

**Report Format**:
```
  Spectral Tags:
    Spectral Viewing Conditions (svcn)     PRESENT/---
    Spectral Data Info (sdin)              PRESENT/---
    Spectral White Point (swpt)            PRESENT/---
    Custom-to-Standard PCC (c2sp)          PRESENT/---
    Standard-to-Custom PCC (s2cp)          PRESENT/---
```

**Detection Logic** (Lines 140-143):
```cpp
for (int i = 0; i < 5; i++) {
  CIccTag *pTag = pIcc->FindTag(spectralTags[i]);
  printf("    %-38s %s\n", spectralNames[i], pTag ? "PRESENT" : "---");
}
```

### B. BRDF Tags (16 tags counted)

```cpp
// Lines 147-151: 16 BRDF tag signatures
// 4 AToB variants: bAB0, bAB1, bAB2, bAB3
// 4 DToB variants: bDB0, bDB1, bDB2, bDB3
// 4 MToB variants: bMB0, bMB1, bMB2, bMB3
// 4 MToS variants: bMS0, bMS1, bMS2, bMS3
```

**Report Format**:
```
  BRDF Tags:                  X of 16 present
```

**Detection Logic** (Lines 152-157):
```cpp
int brdfCount = 0;
for (int i = 0; i < 16; i++) {
  if (pIcc->FindTag(brdfTags[i]))
    brdfCount++;
}
printf("\n  BRDF Tags:                  %d of 16 present\n", brdfCount);
```

### C. Gamut Boundary Description Tags (2 tags)

```cpp
// Lines 160-163
CIccTag *gbd0 = pIcc->FindTag(icSigGamutBoundaryDescription0Tag);  // 'gbd0'
CIccTag *gbd1 = pIcc->FindTag(icSigGamutBoundaryDescription1Tag);  // 'gbd1'
printf("  Gamut Boundary Desc:        gbd0=%s gbd1=%s\n", ...);
```

### D. MCS Color Space (from header)

```cpp
// Lines 166-168
if (pHdr->mcs) {
  printf("  MCS Color Space:            %s\n", 
         Fmt.GetColorSpaceSigName((icColorSpaceSignature)pHdr->mcs));
}
```

### E. MPE and Late-Binding Element Counting

**Detection Logic** (Lines 171-192):

```cpp
int mpeCount = 0;
int lateBindCount = 0;
TagEntryList::iterator it;

for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); ++it) {
  CIccTag *pTag = pIcc->FindTag(*it);
  
  // Count all MPE tags
  if (pTag && pTag->GetType() == icSigMultiProcessElementType) {
    CIccTagMultiProcessElement *pMpe = 
      static_cast<CIccTagMultiProcessElement*>(pTag);
    mpeCount++;
    
    // Iterate through elements in this MPE tag
    for (icUInt32Number j = 0; j < pMpe->NumElements(); j++) {
      CIccMultiProcessElement *pElem = pMpe->GetElement(j);
      if (pElem) {
        icElemTypeSignature eSig = pElem->GetType();
        
        // Count late-binding spectral elements
        if (eSig == icSigEmissionMatrixElemType ||
            eSig == icSigInvEmissionMatrixElemType ||
            eSig == icSigEmissionObserverElemType ||
            eSig == icSigReflectanceObserverElemType) {
          lateBindCount++;
        }
      }
    }
  }
}
```

**Late-Binding Elements** (spectral observer/emission):
- `icSigEmissionMatrixElemType` ('emtx') = 0x656d7478
- `icSigInvEmissionMatrixElemType` ('iemx') = 0x69656d78
- `icSigEmissionObserverElemType` ('eobs') = 0x656f6273
- `icSigReflectanceObserverElemType` ('robs') = 0x726f6273

**Report Format**:
```
  MPE Tags:                   X (multiProcessElementType)
  Late-Binding Elements:      Y (spectral observer/emission)
    NOTE: Late-binding elements require Profile Connection Conditions (PCC)
          with spectralViewingConditionsTag (svcn) for proper rendering.
```

---

## 4. MPE Visualization and Element Chain Display

### Function: `DumpTagCore(CIccTag *pTag, icTagSignature sig, int nVerboseness)`
**Location**: IccDumpAll.cpp:52-97

### Enhancement: MPE Element Chain Summary

**Trigger** (Line 69):
```cpp
if (pTag->GetType() == icSigMultiProcessElementType) {
```

### Output Format

```
Contents of AToB1Tag tag ('A2B1' = 41324231)
Type: multiProcessElementType ('mpet' = 6D706574)

  === MPE Element Chain: N elements, IN->OUT channels ===
  [1] Element Name ('sig1') IN1->OUT1 [LATE-BINDING SPECTRAL]
  [2] Element Name ('sig2') IN2->OUT2
  ...
  [N] Element Name ('sigN') INN->OUTN
  ===
```

### Implementation Details

```cpp
// Lines 70-88
CIccTagMultiProcessElement *pMpe = 
  static_cast<CIccTagMultiProcessElement*>(pTag);

icUInt32Number nElements = pMpe->NumElements();

printf("\n  === MPE Element Chain: %u elements, %u->%u channels ===\n",
       nElements, 
       pMpe->NumInputChannels(), 
       pMpe->NumOutputChannels());

for (icUInt32Number j = 0; j < nElements; j++) {
  CIccMultiProcessElement *pElem = pMpe->GetElement(j);
  if (pElem) {
    icElemTypeSignature elemSig = pElem->GetType();
    
    printf("  [%u] %s (%s) %u->%u%s\n",
           j + 1,
           Fmt.GetElementTypeSigName(elemSig),      // Human-readable name
           icGetSig(buf, bufSize, elemSig),         // 4-char signature
           pElem->NumInputChannels(),
           pElem->NumOutputChannels(),
           GetLateBindingNote(elemSig));            // Spectral annotation
  }
}

printf("  ===\n");
```

### MPE Data Structures

**Key Classes** (from IccTagMPE.h):

```cpp
class CIccTagMultiProcessElement : public CIccTag {
  // Returns count of elements in this MPE tag
  icUInt32Number NumElements() const { 
    return m_list ? (icUInt32Number)(m_list->size()) : 0; 
  }
  
  // Get element by index
  CIccMultiProcessElement *GetElement(int nIndex);
  
  // Input/output channel info for entire chain
  icUInt16Number NumInputChannels() const { return m_nInputChannels; }
  icUInt16Number NumOutputChannels() const { return m_nOutputChannels; }
  
private:
  CIccMultiProcessElementList *m_list;  // std::list of elements
  icUInt16Number m_nInputChannels;
  icUInt16Number m_nOutputChannels;
};

class CIccMultiProcessElement {
  // Get this element's type signature
  virtual icElemTypeSignature GetType() const = 0;
  
  // I/O channel count for this element
  virtual icUInt16Number NumInputChannels() const { return m_nInputChannels; }
  virtual icUInt16Number NumOutputChannels() const { return m_nOutputChannels; }
  
  // Describe element in detail
  virtual void Describe(std::string &sDescription, int nVerboseness) = 0;
};
```

### Late-Binding Annotation

**Function**: `GetLateBindingNote(icElemTypeSignature sig)` (Lines 38-49)

```cpp
static const char* GetLateBindingNote(icElemTypeSignature sig) {
  switch (sig) {
    case icSigEmissionMatrixElemType:
    case icSigInvEmissionMatrixElemType:
    case icSigEmissionObserverElemType:
    case icSigReflectanceObserverElemType:
      return " [LATE-BINDING SPECTRAL]";
    default:
      return "";
  }
}
```

**Output Example**:
```
  [2] Emission Observer Element ('eobs') 3->3 [LATE-BINDING SPECTRAL]
```

---

## 5. Tag Enumeration and Reporting

### Function: `main()` - Tag Enumeration Section
**Location**: IccDumpAll.cpp:348-392

### Tag Table Output

```cpp
// Line 348: Print tag count
printf("\nProfile Tags (%d)\n", (int)pIcc->m_Tags.size());

// Lines 351-352: Header row
printf("%28s    ID    %8s\t%8s\t%8s\n", "Tag",  "Offset", "Size", "Pad");
printf("%28s  ------  %8s\t%8s\t%8s\n", "----", "------", "----", "---");
```

**Output Format**:
```
Profile Tags (8)
------------
                         Tag    ID      Offset    Size     Pad
                        ----  ------    ------    ----     ---
       profileDescriptionTag  'desc'       228      66       2
                    AToB1Tag  'A2B1'       296     988       0
```

### Tag Table Computation

**Purpose**: Determine padding/gaps between tags

**Algorithm** (Lines 357-377):

```cpp
// Sort tag offsets to find gaps
typedef std::vector<icUInt32Number> offsetVector;
offsetVector sortedTagOffsets;
sortedTagOffsets.resize(pIcc->m_Tags.size());

for (n = 0, i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i, n++) {
  sortedTagOffsets[n] = i->TagInfo.offset;
}
std::sort(sortedTagOffsets.begin(), sortedTagOffsets.end());

// For each tag, find the next tag's offset
for (n = 0, i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i, n++) {
  // Find upper bound of current tag's offset in sorted list
  offsetVector::const_iterator match = 
    std::upper_bound(sortedTagOffsets.cbegin(), 
                     sortedTagOffsets.cend(), 
                     i->TagInfo.offset);
  
  if (match == sortedTagOffsets.cend())
    closest = (int)pHdr->size;  // Last tag - pad to EOF
  else
    closest = *match;           // Next tag's offset
  
  closest = std::min(closest, (int)pHdr->size);
  
  // Padding = next tag offset - current tag's end
  pad = closest - i->TagInfo.offset - i->TagInfo.size;
  
  printf("%28s  %s  %8d\t%8d\t%8d\n", 
         Fmt.GetTagSigName(i->TagInfo.sig),
         icGetSig(buf, bufSize, i->TagInfo.sig, false), 
         i->TagInfo.offset, 
         i->TagInfo.size, 
         pad);
}
```

### Duplicate Tag Detection

**Location**: IccDumpAll.cpp:381-392

```cpp
// Report duplicated tag signatures
typedef std::unordered_map<icTagSignature, int> tag_lookup_map;
tag_lookup_map tag_lookup;

for (n = 0, i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); ++i, n++) {
  tag_lookup_map::const_iterator found = tag_lookup.find(i->TagInfo.sig);
  
  if (found != tag_lookup.end()) {
    // Duplicate found!
    printf("%28s is duplicated at positions %d and %d!\n", 
           Fmt.GetTagSigName(i->TagInfo.sig), 
           n, 
           found->second);
    nStatus = icMaxStatus(nStatus, icValidateWarning);
  } else {
    tag_lookup[i->TagInfo.sig] = n;
  }
}
```

### Tag Data Iteration

**Data Structure**: `TagEntryList` (from IccProfile.h:109)

```cpp
// std::list<IccTagEntry>
struct IccTagEntry {
  struct {
    icTagSignature sig;      // Tag signature (4-byte)
    icUInt32Number offset;   // File offset
    icUInt32Number size;     // Tag data size
  } TagInfo;
  // ... more fields
};

// Access in iccDumpAll:
// for (TagEntryList::iterator it = pIcc->m_Tags.begin(); 
//      it != pIcc->m_Tags.end(); ++it)
//   it->TagInfo.sig
//   it->TagInfo.offset
//   it->TagInfo.size
```

### Tag Lookup Methods

```cpp
// Method 1: Find by signature
CIccTag *pTag = pIcc->FindTag(icTagSignature sig);

// Method 2: Find by TagEntry
CIccTag *pTag = pIcc->FindTag(IccTagEntry &entry);
```

---

## 6. Usage and Command-Line Interface

### Usage Information

```
Usage: iccDumpAll {-v} {int} profile {tagId/"ALL"}

Enhanced ICC profile dump with full v5/iccMAX MPE element detail.
The -v option causes profile validation to be performed.
The optional integer parameter specifies verboseness of output (1-100, default=100).
iccDumpAll built with IccProfLib version 2.3.1.5
```

### Command-Line Argument Parsing

**Location**: IccDumpAll.cpp:213-271

```cpp
int main(int argc, char* argv[]) {
  int nArg = 1;
  int verbosity = 100;
  bool bDumpValidation = false;
  
  // Option 1: -v [verbosity] profile [tag]
  if (!strncmp(argv[1], "-V", 2) || !strncmp(argv[1], "-v", 2)) {
    // Enable validation mode
    // Parse optional verbosity (default 100)
    // Call: pIcc = ValidateIccProfile(argv[nArg], sReport, nStatus);
    bDumpValidation = true;
  }
  // Option 2: [verbosity] profile [tag]
  else {
    // No validation
    // Parse optional verbosity (default 100)
    // Call: pIcc = OpenIccProfile(argv[nArg]);
  }
}
```

### Parameter Details

| Parameter | Type | Default | Range | Purpose |
|-----------|------|---------|-------|---------|
| `-v` or `-V` | flag | off | on/off | Enable profile validation |
| `verbosity` | int | 100 | 1-100 | Detail level for tag descriptions |
| `profile` | string | required | - | ICC profile file path |
| `tagId` or `ALL` | string | optional | - | Specific tag to dump (4-char sig) or "ALL" |

### Execution Examples

```bash
# Dump entire profile with validation
./iccDumpAll -v 100 profile.icc

# Dump without validation, max verbosity
./iccDumpAll 100 profile.icc

# Dump specific tag
./iccDumpAll 50 profile.icc A2B0

# Dump all tags
./iccDumpAll profile.icc ALL

# Dump with defaults (no validation, verbosity=100)
./iccDumpAll profile.icc
```

### Profile Loading

```cpp
// With validation
CIccProfile *pIcc = ValidateIccProfile(
  const char *szFilename,      // File path
  std::string &sReport,        // Validation report
  icValidateStatus &nStatus    // Result code
);

// Without validation
CIccProfile *pIcc = OpenIccProfile(const char *szFilename);
```

---

## 7. Data Structures and Key Classes

### CIccProfile (from IccProfile.h)

```cpp
class CIccProfile {
public:
  // Header
  icHeader m_Header;
  
  // Tag list
  TagEntryList m_Tags;  // std::list<IccTagEntry>
  
  // Methods
  CIccTag* FindTag(icSignature sig);
  CIccTag* FindTag(IccTagEntry &entry);
  const CIccTag* FindTagConst(icSignature sig) const;
  
  // Other methods for validation, I/O, etc.
  // ...
};
```

### CIccInfo (from IccUtil.h)

```cpp
class CIccInfo {
public:
  // Signature formatters
  const icChar *GetTagSigName(icTagSignature sig);
  const icChar *GetElementTypeSigName(icElemTypeSignature sig);
  const icChar *GetColorSpaceSigName(icColorSpaceSignature sig);
  const icChar *GetDeviceAttrName(icUInt32Number attr);
  const icChar *GetCmmSigName(icCmmSignature sig);
  const icChar *GetVersionName(icUInt32Number version);
  // ... many more
};
```

---

## 8. Build Configuration

### Build System

**File**: `/home/xss/research/colorbleed_tools/Makefile`

```makefile
TARGETS = iccToXml_unsafe iccFromXml_unsafe iccDumpAll

setup:
@CXX=$(CXX) CC=$(CC) ./build.sh $(CONFIG)
```

**File**: `/home/xss/research/colorbleed_tools/build.sh` (lines 38-39)

```bash
TOOL_SOURCES=(IccToXml_unsafe IccFromXml_unsafe IccDumpAll)
TOOL_BINS=(iccToXml_unsafe iccFromXml_unsafe iccDumpAll)
```

### Compilation

```bash
# Compiler flags
CXX = clang++
CC = clang
INCLUDE = -I./iccDEV/IccProfLib -I./iccDEV/IccXML/IccLibXML
LINK_LIBS = -lxml2 -lz -llzma -lm -lpthread

# Command (from build.sh)
clang++ -g -O1 -fsanitize=address,undefined \
  -I./iccDEV/IccProfLib -I./iccDEV/IccXML/IccLibXML \
  -I/usr/include/libxml2 \
  -o bin/sanitizer/iccDumpAll IccDumpAll.cpp \
  iccDEV/Build-sanitizer/IccProfLib/libIccProfLib.a \
  iccDEV/Build-sanitizer/IccXML/libIccXML.a \
  -lxml2 -lz -llzma -lm -lpthread -Wl,--allow-multiple-definition
```

### Build Output

```
Binary: /home/xss/research/colorbleed_tools/bin/sanitizer/iccDumpAll
Size: 18 MB (with debug symbols and sanitizers)
```

---

## 9. Summary: Functional Flow

```
main()
  ├─ Parse arguments
  │   ├─ Check for -v (validation flag)
  │   ├─ Parse optional verbosity (1-100, default 100)
  │   └─ Get profile filename & optional tag ID
  │
  ├─ Load profile
  │   ├─ If -v: ValidateIccProfile() → sReport, nStatus
  │   └─ Else: OpenIccProfile()
  │
  ├─ Dump profile header
  │   ├─ Profile filename, ID, size
  │   ├─ Header attributes (CMM, version, color spaces)
  │   ├─ Spectral PCS info, BiSpectral range
  │   └─ MCS color space
  │
  ├─ Dump tag table
  │   ├─ Print all tags with name, offset, size, padding
  │   ├─ Compute padding via offset sorting & gap detection
  │   └─ Detect & report duplicate tag signatures
  │
  ├─ DumpV5Summary() [NEW in iccDumpAll]
  │   ├─ Check version >= 5.0
  │   ├─ Spectral Tags (svcn, sdin, swpt, c2sp, s2cp)
  │   ├─ BRDF Tags (count 0-16)
  │   ├─ Gamut Boundary Desc (gbd0, gbd1)
  │   ├─ MCS Color Space
  │   ├─ MPE Tag Count
  │   └─ Late-Binding Element Count (spectral observer/emission)
  │
  ├─ Dump tag details
  │   ├─ If "ALL": iterate all tags via m_Tags
  │   └─ For each tag: DumpTagEntry()
  │       └─ DumpTagCore()
  │           ├─ Print tag name & type
  │           ├─ If MPE: Print element chain summary [NEW]
  │           │   ├─ NumElements, I/O channels
  │           │   └─ Each element: type, signature, I/O, late-binding flag
  │           └─ Call pTag->Describe() for full details
  │
  └─ Validation report (if -v flag)
      ├─ File size alignment
      ├─ Tag offset/size bounds
      ├─ Tag overlap detection
      ├─ Unnecessary padding detection
      └─ Validation status (OK/Warning/NonCompliant/CriticalError)
```

---

## 10. Key Differences from iccDumpProfile

| Aspect | iccDumpProfile | iccDumpAll |
|--------|---|---|
| **Lines of Code** | 497 | 510 |
| **MPE Enhancement** | None | Full element chain visualization |
| **V5 Detection** | Basic version number | Detailed v5/iccMAX feature detection |
| **Spectral Tags** | Not reported | 5 spectral tags enumerated |
| **BRDF Tags** | Not reported | 16 BRDF tags counted |
| **Late-Binding Detection** | Not implemented | 4 spectral element types detected |
| **Element Type Names** | Not displayed | Full type names + hex signatures |
| **I/O Channel Flow** | Not shown | Per-element input/output channels |

---

## Reference: Element Type Signatures

### Late-Binding Spectral (v5/iccMAX)

```cpp
icSigEmissionMatrixElemType       = 0x656d7478   /* 'emtx' */
icSigInvEmissionMatrixElemType    = 0x69656d78   /* 'iemx' */
icSigEmissionObserverElemType     = 0x656f6273   /* 'eobs' */
icSigReflectanceObserverElemType  = 0x726f6273   /* 'robs' */
```

### Common v4/v5 Elements

```cpp
icSigCurveSetElemType             = 0x63767374   /* 'cvst' */
icSigMatrixElemType               = 0x6d617472   /* 'matr' */
icSigCLUTElemType                 = 0x636c7574   /* 'clut' */
icSigBAcsElemType                 = 0x62616373   /* 'bacs' */
icSigEAcsElemType                 = 0x65616373   /* 'eacs' */
icSigCalculatorElemType           = 0x63616c63   /* 'calc' */
icSigSegmentedCurveType           = 0x73637576   /* 'scuv' */
```

