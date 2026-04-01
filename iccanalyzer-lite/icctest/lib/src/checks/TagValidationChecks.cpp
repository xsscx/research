/*
 * IccTest Library - TagValidationChecks.cpp
 * Heuristic checks H9-H32: Tag table structure validation.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

#include "IccSignatureUtils.h"
#include "IccProfile.h"
#include "IccMpeCalc.h"
#include "IccMpeBasic.h"
#include "IccTagBasic.h"
#include "IccTagComposite.h"
#include "IccTagMPE.h"
#include "IccUtil.h"

#include <algorithm>
#include <cmath>
#include <set>
#include <vector>

namespace icctest {

// -- H9: Tag Count Validation --
static CheckResult check_h9_tag_count(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 132) return CheckResult::skip("File too small for tag table");

    const uint8_t* d = pv.rawData();
    uint32_t tagCount = readU32BE(d + 128);

    if (tagCount == 0) {
        cb.warn("Zero tags in tag table");
    }
    if (tagCount > 1000) {
        cb.high(sfmt("Excessive tag count %u (>1000) - potential DoS", tagCount),
                "CWE-400: Uncontrolled Resource Consumption");
    }

    // Check if tag table extends beyond file
    uint64_t tableEnd = 132ULL + tagCount * 12ULL;
    if (tableEnd > pv.rawSize()) {
        cb.critical(sfmt("Tag table (%u entries) extends beyond EOF (need %llu, have %zu)",
                          tagCount, (unsigned long long)tableEnd, pv.rawSize()),
                    "CWE-125: Out-of-bounds Read");
    }

    return cb.done("Tag count validated");
}

// -- H10: Tag Offset/Size Bounds --
static CheckResult check_h10_tag_bounds(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& tags = pv.rawTagTable();

    for (const auto& t : tags) {
        uint64_t tagEnd = static_cast<uint64_t>(t.offset) + static_cast<uint64_t>(t.size);
        if (tagEnd > pv.rawSize()) {
            cb.critical(sfmt("Tag '%s' offset+size (%u+%u=%llu) exceeds file size %zu",
                              sigStr(t.signature).c_str(), t.offset, t.size,
                              static_cast<unsigned long long>(tagEnd), pv.rawSize()),
                        "CWE-125: Out-of-bounds Read");
        }
        if (t.offset < 128 && t.size > 0) {
            cb.high(sfmt("Tag '%s' offset %u overlaps header (< 128)",
                          sigStr(t.signature).c_str(), t.offset),
                    "CWE-787: Out-of-bounds Write");
        }
    }

    return cb.done("Tag offset/size bounds validated");
}

// -- H11: Duplicate Tag Signatures --
static CheckResult check_h11_dup_tags(const ProfileView& pv) {
    CheckBuilder cb;
    std::set<uint32_t> seen;
    for (const auto& t : pv.rawTagTable()) {
        if (seen.count(t.signature)) {
            cb.high(sfmt("Duplicate tag signature '%s' (0x%08X)",
                          sigStr(t.signature).c_str(), t.signature),
                    "CWE-694: Use of Multiple Resources with Duplicate Identifier");
        }
        seen.insert(t.signature);
    }
    return cb.done("No duplicate tags");
}

// -- H12: Tag Alignment --
static CheckResult check_h12_alignment(const ProfileView& pv) {
    CheckBuilder cb;
    for (const auto& t : pv.rawTagTable()) {
        if (t.offset % 4 != 0) {
            cb.warn(sfmt("Tag '%s' offset %u not 4-byte aligned - ICC.1-2022-05 Sec.7.3",
                          sigStr(t.signature).c_str(), t.offset));
        }
    }
    return cb.done("Tag alignment validated");
}

// -- H13: Required Tags Per Class --
static CheckResult check_h13_required_tags(const ProfileView& pv) {
    CheckBuilder cb;

    // All classes require: desc, wtpt, cprt
    if (!pv.hasTag(static_cast<icTagSignature>(kSigDesc))) {
        cb.high("Missing required profileDescriptionTag ('desc')");
    }
    if (!pv.hasTag(static_cast<icTagSignature>(kSigWtpt))) {
        cb.high("Missing required mediaWhitePointTag ('wtpt')");
    }
    if (!pv.hasTag(static_cast<icTagSignature>(kSigCprt))) {
        cb.warn("Missing recommended copyrightTag ('cprt')");
    }

    return cb.done("Required tags present");
}

// -- H14: Tag Type Signature Validation --
static CheckResult check_h14_tag_type(const ProfileView& pv) {
    CheckBuilder cb;

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 4) continue;
        if (!rawRangeAccessible(pv.rawSize(), t.offset, 4)) continue;

        uint32_t typeSig = readU32BE(pv.rawData() + t.offset);
        // Type signature should be printable ASCII
        bool printable = true;
        for (int i = 0; i < 4; i++) {
            uint8_t c = (typeSig >> (24 - i*8)) & 0xFF;
            if (c < 0x20 || c > 0x7E) { printable = false; break; }
        }
        if (!printable) {
            cb.warn(sfmt("Tag '%s' has non-printable type signature 0x%08X",
                          sigStr(t.signature).c_str(), typeSig));
        }
    }

    return cb.done("Tag type signatures valid");
}

// -- H19: Tag Overlap Detection --
static CheckResult check_h19_overlap(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 132) return CheckResult::skip("File too small for tag table");
    const uint8_t* d = pv.rawData();
    if (readU32BE(d + 36) != kIccMagic) return CheckResult::skip("Invalid ICC magic");
    uint32_t declaredTagCount = readU32BE(d + 128);
    size_t maxTags = (pv.rawSize() - 132) / 12;
    if (declaredTagCount > maxTags || declaredTagCount > 10000) {
        return CheckResult::skip("Tag count out of range");
    }
    const auto& tags = pv.rawTagTable();

    for (size_t i = 0; i < tags.size(); i++) {
        for (size_t j = i + 1; j < tags.size(); j++) {
            if (tags[i].offset == tags[j].offset && tags[i].size == tags[j].size) {
                continue; // Shared tag data (valid per spec)
            }
            uint64_t s1 = tags[i].offset;
            uint64_t e1 = static_cast<uint64_t>(tags[i].offset) + tags[i].size;
            uint64_t s2 = tags[j].offset;
            uint64_t e2 = static_cast<uint64_t>(tags[j].offset) + tags[j].size;
            if (s1 < e2 && s2 < e1) {
                // Partial overlap
                cb.critical(sfmt("Tags '%s' and '%s' partially overlap: [%u,%u) vs [%u,%u)",
                                  sigStr(tags[i].signature).c_str(),
                                  sigStr(tags[j].signature).c_str(),
                                  static_cast<unsigned>(s1),
                                  static_cast<unsigned>(e1),
                                  static_cast<unsigned>(s2),
                                  static_cast<unsigned>(e2)),
                            "CWE-119: Improper Restriction of Operations within Buffer Bounds");
            }
        }
    }

    return cb.done("No tag overlaps");
}

// -- Registration (representative subset, H9-H14, H19) --

REGISTER_HEURISTIC(9, "Tag Count Validation",
    "ICC.1-2022-05 Sec.7.3", "ICC.1-2022-05",
    "CWE-400", "", Severity::HIGH, CheckPhase::TAG_TABLE, check_h9_tag_count);

REGISTER_HEURISTIC(10, "Tag Offset/Size Bounds",
    "ICC.1-2022-05 Sec.7.3", "ICC.1-2022-05",
    "CWE-125", "", Severity::CRITICAL, CheckPhase::TAG_TABLE, check_h10_tag_bounds);

REGISTER_HEURISTIC(11, "Duplicate Tag Detection",
    "ICC.1-2022-05 Sec.7.3", "ICC.1-2022-05",
    "CWE-694", "", Severity::HIGH, CheckPhase::TAG_TABLE, check_h11_dup_tags);

REGISTER_HEURISTIC(12, "Tag Alignment Validation",
    "ICC.1-2022-05 Sec.7.3.2", "ICC.1-2022-05",
    "CWE-188", "", Severity::LOW, CheckPhase::TAG_TABLE, check_h12_alignment);

REGISTER_HEURISTIC(13, "Required Tags Per Class",
    "ICC.1-2022-05 Sec.7.2.5", "ICC.1-2022-05",
    "CWE-20", "", Severity::HIGH, CheckPhase::TAG_TABLE, check_h13_required_tags);

REGISTER_HEURISTIC(14, "Tag Type Signature Validation",
    "ICC.1-2022-05 Sec.10", "ICC.1-2022-05",
    "CWE-20", "", Severity::MEDIUM, CheckPhase::TAG_TABLE, check_h14_tag_type);

REGISTER_HEURISTIC(19, "Tag Offset Overlap",
    "ICC.1-2022-05 Sec.7.3", "ICC.1-2022-05",
    "CWE-119", "", Severity::CRITICAL, CheckPhase::TAG_TABLE, check_h19_overlap);


// -- Additional registrations for TagValidationChecks --

static bool raw_has_tag_signature(const ProfileView& pv, uint32_t sig) {
    for (const auto& tag : pv.rawTagTable()) {
        if (tag.signature == sig) return true;
    }
    return false;
}

static bool raw_has_tag_type_signature(const ProfileView& pv, uint32_t typeSig) {
    if (!pv.rawData()) return false;
    for (const auto& tag : pv.rawTagTable()) {
        if (tag.size < 4) continue;
        if (!rawRangeAccessible(pv.rawSize(), tag.offset, 4)) continue;
        if (readU32BE(pv.rawData() + tag.offset) == typeSig) return true;
    }
    return false;
}

static bool raw_has_any_tag_type_signature(const ProfileView& pv,
                                           const uint32_t* typeSigs,
                                           size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (raw_has_tag_type_signature(pv, typeSigs[i])) return true;
    }
    return false;
}

static CheckResult check_h18_technology_signature(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) {
        auto rawTech = pv.rawTag(static_cast<uint32_t>(icSigTechnologyTag));
        if (!rawTech) {
            return cb.done("No technology tag present");
        }
        if (rawTech->size < 12 ||
            !rawRangeAccessible(pv.rawSize(), rawTech->offset, 12)) {
            return CheckResult::skip("Library parse failed");
        }

        const uint8_t* ptr = pv.rawData() + rawTech->offset;
        if (readU32BE(ptr) != static_cast<uint32_t>(icSigSignatureType)) {
            return CheckResult::skip("Library parse failed");
        }

        icTechnologySignature techSig =
            static_cast<icTechnologySignature>(readU32BE(ptr + 8));
        if (IsValidTechnologySignature(techSig)) {
            CIccInfo techInfo;
            return cb.done(sfmt("Valid technology: %s",
                                techInfo.GetTechnologySigName(techSig)));
        }

        cb.warn(sfmt("Unknown technology signature: 0x%08X",
                     static_cast<unsigned>(techSig)),
                "Risk: Non-standard technology, possible parser issue");
        return cb.done("Technology signature invalid");
    }
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::skip("No profile");
    auto* pSigTag = dynamic_cast<CIccTagSignature*>(p->FindTag(icSigTechnologyTag));
    if (!pSigTag) {
        return cb.done("No technology tag present");
    }

    icTechnologySignature techSig =
        static_cast<icTechnologySignature>(pSigTag->GetValue());
    if (IsValidTechnologySignature(techSig)) {
        CIccInfo techInfo;
        return cb.done(sfmt("Valid technology: %s",
                            techInfo.GetTechnologySigName(techSig)));
    }

    cb.warn(sfmt("Unknown technology signature: 0x%08X",
                 static_cast<unsigned>(techSig)),
            "Risk: Non-standard technology, possible parser issue");
    return cb.done("Technology signature invalid");
}

REGISTER_HEURISTIC(18, "Technology Signature",
    "Sec.9.2.27", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::TAG_TABLE,
    check_h18_technology_signature);

static CheckResult check_h20_tag_type_signature(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.rawData() || pv.rawSize() < 132) {
        return pv.libraryLoaded() ? CheckResult::ok("File too small")
                                  : CheckResult::skip("Library parse failed");
    }
    bool sawTagType = false;

    for (const auto& tag : pv.rawTagTable()) {
        if (tag.size < 4) continue;
        if (!rawRangeAccessible(pv.rawSize(), tag.offset, 4)) continue;
        sawTagType = true;

        const uint8_t* typeBuf = pv.rawData() + tag.offset;
        bool allPrintable = true;
        bool allZero = true;
        for (int b = 0; b < 4; ++b) {
            if (typeBuf[b] != 0) allZero = false;
            if (typeBuf[b] < 0x20 || typeBuf[b] > 0x7E) allPrintable = false;
        }

        if (allZero) {
            cb.warn(
                sfmt("Tag '%s' has null type signature (0x00000000)",
                     sigStr(tag.signature).c_str()),
                "Risk: Corrupted tag data - parser may misinterpret");
        } else if (!allPrintable) {
            cb.warn(
                sfmt("Tag '%s' has non-ASCII type: 0x%02X%02X%02X%02X",
                     sigStr(tag.signature).c_str(),
                     typeBuf[0], typeBuf[1], typeBuf[2], typeBuf[3]),
                "Risk: Malformed type bytes - possible type confusion");
        }

    }

    if (!pv.libraryLoaded() && cb.empty() && !sawTagType) {
        return CheckResult::skip("Library parse failed");
    }
    return cb.done("All tag type signatures are valid ASCII");
}

REGISTER_HEURISTIC(20, "Tag Type Signature",
    "Sec.10", "ICC.1-2022-05",
    "CWE-843", "CVE-2026-21505,CVE-2026-24856,GHSA-j577-8285-qrf9,GHSA-w585-cv3v-c396",
    Severity::HIGH, CheckPhase::TAG_TABLE,
    check_h20_tag_type_signature);

static CheckResult check_h21_tag_struct_member_inspection(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) {
        if (!raw_has_tag_type_signature(pv, static_cast<uint32_t>(icSigTagStructType))) {
            return cb.done("No tagStruct tags present");
        }
        return CheckResult::skip("Library parse failed");
    }
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::skip("No profile");

    bool foundStruct = false;
    for (auto it = p->m_Tags.begin(); it != p->m_Tags.end(); ++it) {
        IccTagEntry* entry = &(*it);
        auto* pStruct = dynamic_cast<CIccTagStruct*>(p->FindTag(entry->TagInfo.sig));
        if (!pStruct) continue;
        foundStruct = true;

        TagEntryList* elems = pStruct->GetElemList();
        struct StructMemberInfo {
            icTagSignature sig;
            icUInt32Number size;
        };
        std::vector<StructMemberInfo> members;
        if (elems) {
            members.reserve(elems->size());
            for (const auto& elem : *elems) {
                members.push_back({elem.TagInfo.sig, elem.TagInfo.size});
            }
        }
        int memberCount = static_cast<int>(members.size());
        if (memberCount > 100) {
            cb.warn(sfmt("Tag '%s': excessive member count %d (limit 100)",
                         sigStr(static_cast<uint32_t>(entry->TagInfo.sig)).c_str(),
                         memberCount),
                    "Risk: Resource exhaustion via struct expansion");
        }

        for (const auto& member : members) {
            std::string memberSig = sigStr(static_cast<uint32_t>(member.sig));
            CIccTag* mTag = pStruct->FindElem(member.sig);
            if (!mTag) {
                cb.warn(sfmt("Member '%s': size=%u [UNREADABLE]",
                             memberSig.c_str(),
                             static_cast<unsigned>(member.size)));
                continue;
            }

            uint32_t typeVal = static_cast<uint32_t>(mTag->GetType());
            bool allPrintable = true;
            for (int b = 0; b < 4; ++b) {
                uint8_t c = static_cast<uint8_t>((typeVal >> (24 - b * 8)) & 0xFFu);
                if (c < 0x20 || c > 0x7Eu) {
                    allPrintable = false;
                    break;
                }
            }

            if (typeVal == 0) {
                cb.warn(sfmt("Member '%s' has null type (0x00000000)",
                             memberSig.c_str()));
            } else if (!allPrintable) {
                cb.warn(sfmt("Member '%s' has non-ASCII type: 0x%08X",
                             memberSig.c_str(), typeVal));
            }
        }
    }

    if (!foundStruct) {
        return cb.done("No tagStruct tags present");
    }
    return cb.done("tagStruct members appear well-formed");
}

REGISTER_HEURISTIC(21, "Tag Struct Member Inspection",
    "Sec.10.32", "ICC.1-2022-05",
    "CWE-843", "",
    Severity::MEDIUM, CheckPhase::TAG_TABLE,
    check_h21_tag_struct_member_inspection);

static CheckResult check_h22_num_array_scalar_expectation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) {
        if (!raw_has_tag_signature(pv, static_cast<uint32_t>(icSigColorEncodingParamsTag))) {
            return cb.done("No cept (ColorEncodingParams) tag - check not applicable");
        }
        return CheckResult::skip("Library parse failed");
    }
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::skip("No profile");

    auto* pCept = dynamic_cast<CIccTagStruct*>(p->FindTag(icSigColorEncodingParamsTag));
    if (!pCept) {
        return cb.done("No cept (ColorEncodingParams) tag - check not applicable");
    }

    struct ScalarMember {
        icSignature sig;
        const char* name;
    };
    static const ScalarMember scalarMembers[] = {
        { icSigCeptWhitePointLuminanceMbr,        "wlum (WhitePointLuminance)" },
        { icSigCeptAmbientWhitePointLuminanceMbr, "awlm (AmbientWPLuminance)" },
        { icSigCeptViewingSurroundMbr,            "srnd (ViewingSurround)" },
        { icSigCeptMediumWhitePointLuminanceMbr,  "mwpl (MediumWPLuminance)" },
    };

    for (const auto& member : scalarMembers) {
        CIccTag* mTag = pCept->FindElem(member.sig);
        if (!mTag || !mTag->IsNumArrayType()) continue;

        auto* pNum = dynamic_cast<CIccTagNumArray*>(mTag);
        if (!pNum) continue;

        icUInt32Number numVals = pNum->GetNumValues();
        if (numVals > 1) {
            cb.warn(sfmt("%s has %u values (expected 1 scalar)",
                         member.name, static_cast<unsigned>(numVals)),
                    "Risk: Stack buffer overflow in GetElemNumberValue -> GetValues");
        }
    }

    return cb.done("NumArray scalar expectations met");
}

REGISTER_HEURISTIC(22, "Num Array Scalar Expectation",
    "Sec.10.21", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::TAG_TABLE,
    check_h22_num_array_scalar_expectation);

static CheckResult check_h23_num_array_value_range(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) {
        static const uint32_t numArrayTypes[] = {
            static_cast<uint32_t>(icSigS15Fixed16ArrayType),
            static_cast<uint32_t>(icSigU16Fixed16ArrayType),
            static_cast<uint32_t>(icSigUInt8ArrayType),
            static_cast<uint32_t>(icSigUInt16ArrayType),
            static_cast<uint32_t>(icSigUInt32ArrayType),
            static_cast<uint32_t>(icSigUInt64ArrayType),
            static_cast<uint32_t>(icSigFloat16ArrayType),
            static_cast<uint32_t>(icSigFloat32ArrayType),
            static_cast<uint32_t>(icSigFloat64ArrayType),
        };
        bool hasNumArray =
            raw_has_any_tag_type_signature(pv, numArrayTypes, sizeof(numArrayTypes) / sizeof(numArrayTypes[0]));
        if (!hasNumArray &&
            !raw_has_tag_type_signature(pv, static_cast<uint32_t>(icSigTagStructType))) {
            return cb.done("All NumArray values within normal ranges");
        }
        return CheckResult::skip("Library parse failed");
    }
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::skip("No profile");

    auto scanNumArray = [&](const char* owner,
                            uint32_t ownerSig,
                            CIccTagNumArray* pNum,
                            uint32_t memberSig,
                            bool nested) {
        icUInt32Number numVals = pNum->GetNumValues();
        if (!nested) {
            if (numVals == 0) {
                cb.warn(sfmt("Tag '%s': empty NumArray (0 values)",
                             sigStr(ownerSig).c_str()));
                return;
            }
            if (numVals > 1048576u) {
                cb.warn(sfmt("Tag '%s': excessive NumArray (%u values)",
                             sigStr(ownerSig).c_str(),
                             static_cast<unsigned>(numVals)));
                return;
            }
        } else if (numVals == 0 || numVals > 1048576u) {
            return;
        }

        icUInt32Number sampleSize = numVals < 64u ? numVals : 64u;
        std::vector<icFloatNumber> vals(sampleSize);
        if (!pNum->GetValues(vals.data(), 0, sampleSize)) {
            return;
        }

        int nanCount = 0;
        int infCount = 0;
        for (icUInt32Number i = 0; i < sampleSize; ++i) {
            if (std::isnan(vals[i])) nanCount++;
            if (std::isinf(vals[i])) infCount++;
        }
        if (!nanCount && !infCount) {
            return;
        }

        if (!nested) {
            if (nanCount) {
                cb.warn(sfmt("Tag '%s': %d NaN value(s) in NumArray",
                             sigStr(ownerSig).c_str(), nanCount),
                        "CWE-681: NaN/Inf propagation -> UB in IccIO Write");
            }
            if (infCount) {
                cb.warn(sfmt("Tag '%s': %d Inf value(s) in NumArray",
                             sigStr(ownerSig).c_str(), infCount),
                        "CWE-681: NaN/Inf propagation -> UB in IccIO Write");
            }
            return;
        }

        std::string detail = sfmt("Struct '%s' member '%s':",
                                  sigStr(ownerSig).c_str(),
                                  sigStr(memberSig).c_str());
        if (nanCount) detail += sfmt(" %d NaN", nanCount);
        if (infCount) detail += sfmt(" %d Inf", infCount);
        detail += " value(s)";
        cb.warn(detail, "CWE-681: NaN/Inf propagation -> UB in IccIO Write");
    };

    for (auto it = p->m_Tags.begin(); it != p->m_Tags.end(); ++it) {
        IccTagEntry* entry = &(*it);
        CIccTag* pTag = p->FindTag(entry->TagInfo.sig);
        if (!pTag || !pTag->IsNumArrayType()) continue;
        auto* pNum = dynamic_cast<CIccTagNumArray*>(pTag);
        if (!pNum) continue;
        scanNumArray("tag", static_cast<uint32_t>(entry->TagInfo.sig), pNum, 0, false);
    }

    for (auto it = p->m_Tags.begin(); it != p->m_Tags.end(); ++it) {
        IccTagEntry* entry = &(*it);
        auto* pStruct = dynamic_cast<CIccTagStruct*>(p->FindTag(entry->TagInfo.sig));
        if (!pStruct) continue;

        TagEntryList* elems = pStruct->GetElemList();
        if (!elems) continue;
        for (auto eit = elems->begin(); eit != elems->end(); ++eit) {
            IccTagEntry* me = &(*eit);
            CIccTag* mTag = pStruct->FindElem(me->TagInfo.sig);
            if (!mTag || !mTag->IsNumArrayType()) continue;
            auto* pNum = dynamic_cast<CIccTagNumArray*>(mTag);
            if (!pNum) continue;
            scanNumArray("member", static_cast<uint32_t>(entry->TagInfo.sig), pNum,
                         static_cast<uint32_t>(me->TagInfo.sig), true);
        }
    }

    return cb.done("All NumArray values within normal ranges");
}

REGISTER_HEURISTIC(23, "Num Array Value Range",
    "Sec.10.21", "ICC.1-2022-05",
    "CWE-681", "",
    Severity::MEDIUM, CheckPhase::TAG_TABLE,
    check_h23_num_array_value_range);

static CheckResult check_h24_tag_struct_nesting_depth(const ProfileView& pv) {
    CheckBuilder cb;
    constexpr int kMaxSafeDepth = 4;
    if (!pv.libraryLoaded()) {
        bool hasStruct = raw_has_tag_type_signature(pv, static_cast<uint32_t>(icSigTagStructType));
        bool hasArray = raw_has_tag_type_signature(pv, static_cast<uint32_t>(icSigTagArrayType));
        if (!hasStruct && !hasArray) {
            return cb.done("Max nesting depth: 0 (safe limit: 4)");
        }

        int maxDepth = hasStruct || hasArray ? 1 : 0;
        const uint8_t* raw = pv.rawData();
        size_t rawLen = pv.rawSize();
        if (raw) {
            for (const auto& tag : pv.rawTagTable()) {
                if (tag.size < 16 || !rawRangeAccessible(rawLen, tag.offset, 16)) continue;
                const uint8_t* ptr = raw + tag.offset;
                if (readU32BE(ptr) != static_cast<uint32_t>(icSigTagArrayType)) continue;

                uint32_t elemCount = readU32BE(ptr + 12);
                uint64_t ownerEnd = static_cast<uint64_t>(tag.offset) + tag.size;
                for (uint32_t i = 0; i < elemCount && i < 64; ++i) {
                    uint64_t recOff = static_cast<uint64_t>(tag.offset) + 16ull + static_cast<uint64_t>(i) * 8ull;
                    if (!rawRangeAccessible(rawLen, static_cast<size_t>(recOff), 8)) break;

                    uint32_t childOff = readU32BE(raw + recOff);
                    uint32_t childSize = readU32BE(raw + recOff + 4);
                    if (!childOff || childSize < 4) continue;

                    uint64_t childAbs = static_cast<uint64_t>(tag.offset) + childOff;
                    if (childAbs + 4 > rawLen || childAbs + childSize > ownerEnd) continue;

                    uint32_t childType = readU32BE(raw + childAbs);
                    if (childType == static_cast<uint32_t>(icSigTagStructType) ||
                        childType == static_cast<uint32_t>(icSigTagArrayType)) {
                        maxDepth = std::max(maxDepth, 2);
                    }
                }
            }
        }

        if (maxDepth > kMaxSafeDepth) {
            cb.warn(sfmt("Nesting depth %d exceeds safe limit (%d)",
                         maxDepth, kMaxSafeDepth),
                    "Risk: Stack overflow via recursive Read/Describe");
        }
        return cb.done(sfmt("Max nesting depth: %d (safe limit: %d)", maxDepth, kMaxSafeDepth));
    }
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::skip("No profile");

    struct DepthEntry {
        CIccTag* tag;
        int depth;
    };

    std::vector<DepthEntry> stack;
    for (auto it = p->m_Tags.begin(); it != p->m_Tags.end(); ++it) {
        IccTagEntry* entry = &(*it);
        CIccTag* tag = p->FindTag(entry->TagInfo.sig);
        if (tag) stack.push_back({tag, 0});
    }

    int maxDepth = 0;
    while (!stack.empty()) {
        DepthEntry cur = stack.back();
        stack.pop_back();
        maxDepth = std::max(maxDepth, cur.depth);

        if (cur.depth > kMaxSafeDepth) {
            cb.warn(sfmt("Nesting depth %d exceeds safe limit (%d)",
                         cur.depth, kMaxSafeDepth),
                    "Risk: Stack overflow via recursive Read/Describe");
            continue;
        }

        if (auto* pStruct = dynamic_cast<CIccTagStruct*>(cur.tag)) {
            TagEntryList* elems = pStruct->GetElemList();
            if (elems) {
                for (auto eit = elems->begin(); eit != elems->end(); ++eit) {
                    CIccTag* child = pStruct->FindElem((*eit).TagInfo.sig);
                    if (child) stack.push_back({child, cur.depth + 1});
                }
            }
        }

        if (auto* pArr = dynamic_cast<CIccTagArray*>(cur.tag)) {
            icUInt32Number arrSize = pArr->GetSize();
            icUInt32Number limit = arrSize < 64u ? arrSize : 64u;
            for (icUInt32Number i = 0; i < limit; ++i) {
                CIccTag* child = pArr->GetIndex(i);
                if (child) stack.push_back({child, cur.depth + 1});
            }
        }
    }

    return cb.done(sfmt("Max nesting depth: %d (safe limit: %d)",
                        maxDepth, kMaxSafeDepth));
}

REGISTER_HEURISTIC(24, "Tag Struct Nesting Depth",
    "Sec.10.32", "ICC.1-2022-05",
    "CWE-674", "CVE-2026-30980,GHSA-w478-77q7-2hc2",
    Severity::HIGH, CheckPhase::TAG_TABLE,
    check_h24_tag_struct_nesting_depth);

static CheckResult check_h25_tag_offset_oob(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.rawData() || pv.rawSize() < 132) return cb.done("File too small");

    uint32_t hdrProfileSize = readU32BE(pv.rawData());
    size_t bound = std::min<size_t>(pv.rawSize(), hdrProfileSize);
    int oobCount = 0;

    for (const auto& tag : pv.rawTagTable()) {
        uint64_t tagEnd = static_cast<uint64_t>(tag.offset) + tag.size;
        if (tag.offset >= bound) {
            cb.warn(
                sfmt("Tag '%s' offset 0x%X beyond file/profile bounds (%zu bytes)",
                     sigStr(tag.signature).c_str(), tag.offset, bound),
                "Risk: Heap-buffer-overflow when loading OOB tags");
            ++oobCount;
        } else if (tagEnd > bound) {
            cb.warn(
                sfmt("Tag '%s' [offset=0x%X, size=%u] extends %llu bytes past bounds (%zu)",
                     sigStr(tag.signature).c_str(), tag.offset, tag.size,
                     static_cast<unsigned long long>(tagEnd - bound), bound),
                "Risk: Heap-buffer-overflow when loading OOB tags");
            ++oobCount;
        }
    }

    if (oobCount > 0) {
        cb.info(sfmt("%d tag(s) reference data beyond file/profile bounds", oobCount));
    }
    return cb.done("All tag offsets/sizes within bounds");
}

REGISTER_HEURISTIC(25, "Tag Offset OOB",
    "Sec.7.3.1", "ICC.1-2022-05",
    "CWE-125", "CVE-2026-21487,GHSA-xq7x-9524-f7cp",
    Severity::CRITICAL, CheckPhase::TAG_TABLE,
    check_h25_tag_offset_oob);

static CheckResult check_h26_named_color2string_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.rawData() || pv.rawSize() < 132) {
        return pv.libraryLoaded() ? CheckResult::ok("File too small")
                                  : CheckResult::skip("Library parse failed");
    }
    bool sawNamedColor2 = false;

    auto countXmlExpand = [](const uint8_t* buf, int len) {
        int ct = 0;
        for (int j = 0; j < len && buf[j] != 0; ++j) {
            if (buf[j] == '\'' || buf[j] == '"' || buf[j] == '&' ||
                buf[j] == '<'  || buf[j] == '>') {
                ++ct;
            }
        }
        return ct;
    };

    for (const auto& tag : pv.rawTagTable()) {
        if (tag.size < 84) continue;
        if (!rawRangeAccessible(pv.rawSize(), tag.offset, 84)) continue;

        const uint8_t* ptr = pv.rawData() + tag.offset;
        if (readU32BE(ptr) != 0x6E636C32u) continue; // 'ncl2'
        sawNamedColor2 = true;

        const uint8_t* prefix = ptr + 20;
        const uint8_t* suffix = ptr + 52;
        int prefixLen = 0, suffixLen = 0;
        while (prefixLen < 32 && prefix[prefixLen]) ++prefixLen;
        while (suffixLen < 32 && suffix[suffixLen]) ++suffixLen;

        int prefixExpand = countXmlExpand(prefix, 32);
        int suffixExpand = countXmlExpand(suffix, 32);
        int prefixExpanded = prefixLen + prefixExpand * 5;
        int suffixExpanded = suffixLen + suffixExpand * 5;

        if (prefixExpanded > 255) {
            cb.critical(
                sfmt("Prefix (%d bytes, %d XML-expandable) overflows icFixXml buffer (expanded: %d > 255)",
                     prefixLen, prefixExpand, prefixExpanded),
                "Risk: Stack-buffer-overflow in icFixXml() (SCARINESS:55 class)");
        } else if (prefixExpand > 0 && prefixLen > 20) {
            cb.warn(
                sfmt("Prefix has %d XML-expandable chars in %d-byte string (expanded: %d)",
                     prefixExpand, prefixLen, prefixExpanded));
        }

        if (suffixExpanded > 255) {
            cb.critical(
                sfmt("Suffix (%d bytes, %d XML-expandable) overflows icFixXml buffer (expanded: %d > 255)",
                     suffixLen, suffixExpand, suffixExpanded),
                "Risk: Stack-buffer-overflow in icFixXml() (SCARINESS:55 class)");
        } else if (suffixExpand > 0 && suffixLen > 20) {
            cb.warn(
                sfmt("Suffix has %d XML-expandable chars in %d-byte string (expanded: %d)",
                     suffixExpand, suffixLen, suffixExpanded));
        }

        bool prefixUnterminated = true, suffixUnterminated = true;
        for (int j = 0; j < 32; ++j) {
            if (prefix[j] == 0) prefixUnterminated = false;
            if (suffix[j] == 0) suffixUnterminated = false;
        }
        if (prefixUnterminated) {
            cb.warn("Prefix not null-terminated (all 32 bytes non-zero)",
                    "Risk: strlen overflow, icFixXml reads past buffer boundary");
        }
        if (suffixUnterminated) {
            cb.warn("Suffix not null-terminated (all 32 bytes non-zero)",
                    "Risk: strlen overflow, icFixXml reads past buffer boundary");
        }
    }

    if (!pv.libraryLoaded() && cb.empty() && !sawNamedColor2) {
        return cb.done("No NamedColor2 tags with risky strings");
    }
    return cb.done("No NamedColor2 tags with risky strings");
}

REGISTER_HEURISTIC(26, "Named Color2String Validation",
    "Sec.10.20", "ICC.1-2022-05",
    "CWE-170", "",
    Severity::HIGH, CheckPhase::TAG_TABLE,
    check_h26_named_color2string_validation);

static CheckResult check_h27_mpe_matrix_output_channel(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("All MPE matrix/calculator dimensions valid");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::skip("No profile");

    icUInt32Number mpeSigs[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
        icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
        icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag
    };

    for (auto sig : mpeSigs) {
        auto* pMpe = dynamic_cast<CIccTagMultiProcessElement*>(p->FindTag(static_cast<icTagSignature>(sig)));
        if (!pMpe) continue;

        icUInt32Number numElements = pMpe->NumElements();
        for (icUInt32Number ei = 0; ei < numElements && ei < 64u; ++ei) {
            CIccMultiProcessElement* pElem = pMpe->GetElement(ei);
            if (!pElem) continue;

            if (auto* pMatrix = dynamic_cast<CIccMpeMatrix*>(pElem)) {
                icUInt16Number numOut = pMatrix->NumOutputChannels();
                icUInt16Number numIn = pMatrix->NumInputChannels();
                if (numOut == 0 || numIn == 0) {
                    cb.warn(sfmt("Tag '%s' elem %u: Matrix %ux%u - zero dimension",
                                 sigStr(sig).c_str(), static_cast<unsigned>(ei),
                                 static_cast<unsigned>(numIn),
                                 static_cast<unsigned>(numOut)),
                            "Risk: Division by zero or null-pointer in matrix operations");
                } else if (numOut < 3) {
                    cb.warn(sfmt("Tag '%s' elem %u: Matrix has %u output channels (XYZ needs 3)",
                                 sigStr(sig).c_str(),
                                 static_cast<unsigned>(ei),
                                 static_cast<unsigned>(numOut)),
                            sfmt("Risk: HBO in pushXYZConvert accessing pOffset[0..2] on %u-channel matrix",
                                 static_cast<unsigned>(numOut)));
                }
            }

            if (auto* pCalc = dynamic_cast<CIccMpeCalculator*>(pElem)) {
                icUInt16Number calcOut = pCalc->NumOutputChannels();
                icUInt16Number calcIn = pCalc->NumInputChannels();
                if (calcOut == 0 || calcIn == 0) {
                    cb.warn(sfmt("Tag '%s' elem %u: Calculator %ux%u - zero dimension",
                                 sigStr(sig).c_str(),
                                 static_cast<unsigned>(ei),
                                 static_cast<unsigned>(calcIn),
                                 static_cast<unsigned>(calcOut)));
                }
            }
        }
    }

    return cb.done("All MPE matrix/calculator dimensions valid");
}

REGISTER_HEURISTIC(27, "MPE Matrix Output Channel",
    "Sec.10.26", "ICC.1-2022-05",
    "CWE-131", "CVE-2026-27692,GHSA-3869-prw8-gjqr",
    Severity::CRITICAL, CheckPhase::TAG_TABLE,
    check_h27_mpe_matrix_output_channel);

static CheckResult check_h28_lut_dimension_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.rawData() || pv.rawSize() < 132) return cb.done("File too small");

    constexpr uint32_t kLut8 = 0x6D667431u;  // 'mft1'
    constexpr uint32_t kLut16 = 0x6D667432u; // 'mft2'
    constexpr uint64_t kMaxLutPoints = 16ull * 1024ull * 1024ull;

    for (const auto& tag : pv.rawTagTable()) {
        if (tag.size < 11) continue;
        if (!rawRangeAccessible(pv.rawSize(), tag.offset, 11)) continue;

        const uint8_t* lutHdr = pv.rawData() + tag.offset;
        uint32_t lutType = readU32BE(lutHdr);
        if (lutType != kLut8 && lutType != kLut16) continue;

        uint8_t nInput = lutHdr[8];
        uint8_t nOutput = lutHdr[9];
        uint8_t nGrid = lutHdr[10];
        const char* lutName = lutType == kLut8 ? "LUT8" : "LUT16";

        if (nInput > 16 || nOutput > 16) {
            cb.warn(
                sfmt("Tag '%s' (%s): nInput=%u nOutput=%u exceeds spec max (16)",
                     sigStr(tag.signature).c_str(), lutName, nInput, nOutput),
                "Risk: Buffer overflow in grid point arrays (max 16 channels)");
            continue;
        }

        uint64_t points = 1;
        bool overflow = false;
        for (uint8_t ch = 0; ch < nInput; ++ch) {
            uint64_t prev = points;
            points *= nGrid;
            if (nGrid > 0 && points / nGrid != prev) {
                overflow = true;
                break;
            }
        }
        if (!overflow) {
            uint64_t prev = points;
            points *= nOutput;
            if (nOutput > 0 && points / nOutput != prev) {
                overflow = true;
            }
        }

        if (overflow || points > kMaxLutPoints) {
            cb.warn(
                sfmt("Tag '%s' (%s): nInput=%u nOutput=%u nGrid=%u -> %s CLUT points",
                     sigStr(tag.signature).c_str(), lutName, nInput, nOutput, nGrid,
                     overflow ? "OVERFLOW" : sfmt("%llu",
                         static_cast<unsigned long long>(points)).c_str()),
                sfmt("Risk: OOM - allocation of %s bytes in CIccCLUT::Init()",
                     overflow ? ">2^64" : sfmt("%llu",
                         static_cast<unsigned long long>(points * 4ull)).c_str()));
        }
    }

    return cb.done("All LUT dimensions within safe limits");
}

REGISTER_HEURISTIC(28, "LUT Dimension Validation",
    "Sec.10.10", "ICC.1-2022-05",
    "CWE-400", "CVE-2026-21490,CVE-2026-21494,GHSA-9q9c-699q-xr2q,GHSA-hjxv-xr7w-84fc,GHSA-x9hr-pxxc-h38p",
    Severity::HIGH, CheckPhase::TAG_TABLE,
    check_h28_lut_dimension_validation);

static CheckResult check_h29_colorant_table_string_validation(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.rawData() || pv.rawSize() < 132) {
        return pv.libraryLoaded() ? CheckResult::ok("File too small")
                                  : CheckResult::skip("Library parse failed");
    }

    for (const auto& tag : pv.rawTagTable()) {
        if (tag.size < 12) continue;
        if (!rawRangeAccessible(pv.rawSize(), tag.offset, 12)) continue;

        const uint8_t* ptr = pv.rawData() + tag.offset;
        if (readU32BE(ptr) != 0x636C7274u) continue; // 'clrt'

        uint32_t colorantCount = readU32BE(ptr + 8);
        if (colorantCount > 256) {
            cb.warn(sfmt("ColorantTable: count=%u (>256) - excessive allocation risk",
                         colorantCount));
            continue;
        }

        uint32_t unterminatedCount = 0;
        for (uint32_t i = 0; i < colorantCount && i < 256; ++i) {
            uint64_t namePos = static_cast<uint64_t>(tag.offset) + 12ull +
                               static_cast<uint64_t>(i) * 38ull;
            if (!rawRangeAccessible(pv.rawSize(), static_cast<size_t>(namePos), 32)) break;

            const uint8_t* name = pv.rawData() + namePos;
            bool hasNull = false;
            for (int j = 0; j < 32; ++j) {
                if (name[j] == 0) {
                    hasNull = true;
                    break;
                }
            }
            if (!hasNull) {
                cb.critical(
                    sfmt("Colorant[%u] name not null-terminated (all 32 bytes non-zero)", i),
                    "GHSA-4wqv-pvm8-5h27: HBO read via unterminated colorant name[32]");
                ++unterminatedCount;
            }
        }

        if (unterminatedCount > 1) {
            size_t allocSize = static_cast<size_t>(colorantCount) * 38u;
            cb.critical(
                sfmt("%u/%u colorant entries lack null terminator",
                     unterminatedCount, colorantCount),
                sfmt("Allocation: calloc(%u, 38) = %zu bytes - strlen reads past entire buffer",
                     colorantCount, allocSize));
        }
    }

    if (!pv.libraryLoaded() && cb.empty()) {
        return cb.done("No ColorantTable string issues detected");
    }
    return cb.done("No ColorantTable string issues detected");
}

REGISTER_HEURISTIC(29, "Colorant Table String Validation",
    "Sec.10.4", "ICC.1-2022-05",
    "CWE-125/CWE-170", "CVE-2026-34556,GHSA-4wqv-pvm8-5h27,GHSA-p9wm-xfv4-43qg",
    Severity::CRITICAL, CheckPhase::TAG_TABLE,
    check_h29_colorant_table_string_validation);

static CheckResult check_h30_gamut_boundary_desc_allocation(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 132) return CheckResult::skip("File too small for tag table");

    auto scanGbdRecord = [&](const std::string& ownerSig,
                             const uint8_t* hdr,
                             uint32_t logicalSize) {
        uint16_t nPCSCh = static_cast<uint16_t>(hdr[8]) << 8 | hdr[9];
        uint16_t nDevCh = static_cast<uint16_t>(hdr[10]) << 8 | hdr[11];
        uint32_t nVerts = readU32BE(hdr + 12);
        uint32_t nTris  = readU32BE(hdr + 16);

        uint64_t triAlloc = static_cast<uint64_t>(nTris) * 12ull;
        uint64_t vertAlloc = static_cast<uint64_t>(nVerts) *
                             (12ull + static_cast<uint64_t>(nPCSCh) * 4ull +
                              static_cast<uint64_t>(nDevCh) * 4ull);
        uint64_t totalAlloc = triAlloc + vertAlloc + 24ull;

        if (totalAlloc > static_cast<uint64_t>(logicalSize) * 4ull) {
            cb.warn(sfmt("Tag '%s' (gbd): %u vertices, %u triangles, PCS=%u Dev=%u",
                         ownerSig.c_str(), nVerts, nTris, nPCSCh, nDevCh),
                    sfmt("Allocation: %llu bytes vs tag size %u bytes; Risk: OOM in CIccTagGamutBoundaryDesc::Read()",
                         static_cast<unsigned long long>(totalAlloc), logicalSize));
        }
        if (nPCSCh > 3 || nDevCh > 15) {
            cb.warn(sfmt("Tag '%s' (gbd): PCS channels=%u, Device channels=%u - out of range",
                         ownerSig.c_str(), nPCSCh, nDevCh),
                    "Risk: Signed/unsigned confusion in allocation size");
        }
    };

    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    for (const auto& tag : pv.rawTagTable()) {
        if (!rawRangeAccessible(rawLen, tag.offset, 20) || tag.size < 20) {
            continue;
        }

        uint32_t typeSig = readU32BE(raw + tag.offset);
        if (typeSig == 0x67626420) {  // 'gbd '
            scanGbdRecord(sigStr(tag.signature), raw + tag.offset, tag.size);
            continue;
        }

        if (typeSig != 0x74617279 || tag.size < 16) {  // 'tary'
            continue;
        }

        if (!rawRangeAccessible(rawLen, tag.offset, 16)) {
            continue;
        }
        uint32_t elemCount = readU32BE(raw + tag.offset + 12);
        if (elemCount == 0 || elemCount > 256) {
            continue;
        }

        uint64_t tableStart = static_cast<uint64_t>(tag.offset) + 16ull;
        uint64_t tableEnd = tableStart + static_cast<uint64_t>(elemCount) * 8ull;
        uint64_t ownerEnd = static_cast<uint64_t>(tag.offset) + static_cast<uint64_t>(tag.size);
        if (tableEnd > rawLen || tableEnd > ownerEnd) {
            continue;
        }

        for (uint32_t i = 0; i < elemCount; i++) {
            size_t recOff = tag.offset + 16 + static_cast<size_t>(i) * 8;
            uint32_t childOff = readU32BE(raw + recOff);
            uint32_t childSz  = readU32BE(raw + recOff + 4);
            if (!childOff || childSz < 20) {
                continue;
            }

            uint64_t childAbs = static_cast<uint64_t>(tag.offset) + static_cast<uint64_t>(childOff);
            if (childAbs + 20 > rawLen || childAbs + childSz > ownerEnd) {
                continue;
            }

            const uint8_t* child = raw + childAbs;
            if (readU32BE(child) != 0x67626420) {
                continue;
            }

            scanGbdRecord(sfmt("%s[tary]", sigStr(tag.signature).c_str()), child, childSz);
        }
    }

    return cb.done("No GamutBoundaryDesc allocation issues");
}

REGISTER_HEURISTIC(30, "Gamut Boundary Desc Allocation",
    "Sec.10.12", "ICC.1-2022-05",
    "CWE-400", "GHSA-rc3h-95ph-j363",
    Severity::HIGH, CheckPhase::TAG_TABLE,
    check_h30_gamut_boundary_desc_allocation);

static CheckResult check_h31_mpe_channel_count(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("All MPE channel counts within safe limits");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::skip("No profile");

    icUInt32Number mpeSigs[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
        icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
        icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag
    };

    for (auto sig : mpeSigs) {
        auto* mpe = dynamic_cast<CIccTagMultiProcessElement*>(p->FindTag((icTagSignature)sig));
        if (!mpe) continue;

        icUInt16Number mpeIn = mpe->NumInputChannels();
        icUInt16Number mpeOut = mpe->NumOutputChannels();
        std::string sigName = sigStr(sig);

        if (mpeIn > 32 || mpeOut > 32) {
            cb.warn(
                sfmt("Tag '%s': MPE channels in=%u out=%u (>32)",
                     sigName.c_str(), mpeIn, mpeOut),
                "Risk: memcpy-param-overlap in Apply(), stack buffer overflow");
        }

        icUInt32Number nElems = mpe->NumElements();
        for (icUInt32Number i = 0; i < nElems && i < 64; ++i) {
            CIccMultiProcessElement* elem = mpe->GetElement(i);
            if (!elem) continue;

            icUInt16Number elemIn = elem->NumInputChannels();
            icUInt16Number elemOut = elem->NumOutputChannels();
            if (elemIn > 64 || elemOut > 64) {
                cb.warn(
                    sfmt("Tag '%s' elem %u: channels in=%u out=%u (extreme)",
                         sigName.c_str(), i, elemIn, elemOut),
                    "Risk: Stack buffer overflow in element Apply()");
            }
        }
    }

    return cb.done("All MPE channel counts within safe limits");
}

REGISTER_HEURISTIC(31, "MPE Channel Count",
    "Sec.10.26", "ICC.1-2022-05",
    "CWE-131", "",
    Severity::CRITICAL, CheckPhase::TAG_TABLE,
    check_h31_mpe_channel_count);

static CheckResult check_h32_tag_data_type_confusion(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.rawData() || pv.rawSize() < 132) {
        return pv.libraryLoaded() ? CheckResult::ok("File too small")
                                  : CheckResult::skip("Library parse failed");
    }
    bool allowUnknownPrintable = pv.libraryLoaded();
    bool sawTagType = false;

    static const uint32_t knownTypes[] = {
        0x63757276u, 0x70617261u, 0x6D667431u, 0x6D667432u, 0x6D414220u,
        0x6D424120u, 0x6D706574u, 0x58595A20u, 0x74657874u, 0x64657363u,
        0x6D6C7563u, 0x73663332u, 0x75663332u, 0x73696720u, 0x64617461u,
        0x6474696Du, 0x76696577u, 0x6D656173u, 0x6E636C32u, 0x636C7274u,
        0x636C726Fu, 0x63727064u, 0x75693038u, 0x75693136u, 0x75693332u,
        0x75693634u, 0x666C3136u, 0x666C3332u, 0x666C3634u, 0x67626420u,
        0x63696370u, 0x73706563u, 0x736D6174u, 0x74617279u, 0x74737472u,
        0x7A757466u, 0x7A786D6Cu, 0x75746638u, 0x64696374u, 0x656D6274u,
        0x636F6C52u, 0x636F6C53u, 0x7376636Eu, 0x7364696Eu, 0x736D7769u,
    };

    for (const auto& tag : pv.rawTagTable()) {
        if (pv.libraryLoaded() && tag.size < 4) continue;
        if (!rawRangeAccessible(pv.rawSize(), tag.offset, 4)) continue;
        sawTagType = true;

        uint32_t dataType = readU32BE(pv.rawData() + tag.offset);

        if (!pv.libraryLoaded()) {
            bool validFourCc = true;
            for (int b = 0; b < 4; ++b) {
                uint8_t c = static_cast<uint8_t>((dataType >> (24 - b * 8)) & 0xFFu);
                if (c < 0x20 || c > 0x7Eu) {
                    validFourCc = false;
                    break;
                }
            }
            bool tagSigPrintable = true;
            for (int b = 0; b < 4; ++b) {
                uint8_t c = static_cast<uint8_t>((tag.signature >> (24 - b * 8)) & 0xFFu);
                if (c < 0x20 || c > 0x7Eu) {
                    tagSigPrintable = false;
                    break;
                }
            }
            bool isKnown = false;
            for (uint32_t known : knownTypes) {
                if (dataType == known) {
                    isKnown = true;
                    break;
                }
            }
            if (!isKnown) {
                if (!validFourCc) {
                    if (!tagSigPrintable) {
                        cb.warn(
                            sfmt("Tag '%s' at 0x%08X: type signature 0x%02X%02X%02X%02X is non-printable",
                                 sigStr(tag.signature).c_str(), tag.offset,
                                 static_cast<unsigned>((dataType >> 24) & 0xFFu),
                                 static_cast<unsigned>((dataType >> 16) & 0xFFu),
                                 static_cast<unsigned>((dataType >> 8) & 0xFFu),
                                 static_cast<unsigned>(dataType & 0xFFu)),
                            "Risk: Type confusion -> wrong parser invoked -> memory corruption");
                    }
                    continue;  // H20 owns non-printable type signatures, even on failed-load profiles.
                }
                cb.warn(
                    sfmt("Tag '%s': unknown type signature '%s' (0x%08X)",
                         sigStr(tag.signature).c_str(),
                         sigStr(dataType).c_str(),
                         dataType),
                    "Risk: Type confusion -> wrong parser invoked -> memory corruption");
            }
            continue;
        }

        bool allPrintable = true;
        for (int b = 0; b < 4; ++b) {
            uint8_t c = static_cast<uint8_t>((dataType >> (24 - b * 8)) & 0xFFu);
            if (c < 0x20 || c > 0x7E) {
                allPrintable = false;
                break;
            }
        }

        bool isKnown = false;
        for (uint32_t known : knownTypes) {
            if (dataType == known) {
                isKnown = true;
                break;
            }
        }
        if (isKnown) continue;
        if (!allPrintable) continue;  // H20 already owns non-printable types on loadable profiles.
        if (!allowUnknownPrintable) continue;

        cb.warn(
            sfmt("Tag '%s': unknown type signature '%s' (0x%08X)",
                 sigStr(tag.signature).c_str(), sigStr(dataType).c_str(), dataType),
            "Risk: Type confusion -> wrong parser invoked -> memory corruption");
    }

    if (!pv.libraryLoaded() && cb.empty() && !sawTagType) {
        return CheckResult::skip("Library parse failed");
    }
    return cb.done(pv.libraryLoaded()
                       ? "All tag type signatures are known ICC types"
                       : "All tag type signatures are printable ICC 4CC codes");
}

REGISTER_HEURISTIC(32, "Tag Data Type Confusion",
    "Sec.10", "ICC.1-2022-05",
    "CWE-843", "CVE-2021-30942,CVE-2026-21683,CVE-2026-21688,CVE-2026-21691,CVE-2026-25503,GHSA-3r2x-j7v3-pg6f,GHSA-c9q5-x498-jv92,GHSA-f2wp-j3fr-938w,GHSA-pf84-4c7q-x764",
    Severity::CRITICAL, CheckPhase::TAG_TABLE,
    check_h32_tag_data_type_confusion);


} // namespace icctest
