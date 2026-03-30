/**
 * @file iccproflib_demo.cpp
 * @brief Demonstrates IccProfLib usage — ICC profile parsing, inspection,
 *        and validation using the iccDEV reference implementation.
 *
 * Originally created for the BeyondRGB project (Imaging Art Beyond RGB)
 * to show college students how the ICC.1-2022-05 reference library works.
 *
 * Build:  cd iccproflib_demo && ./build.sh
 * Run:    ./iccproflib_demo [path/to/profile.icc ...]
 *
 * Learning objectives:
 *   1. How to open an ICC profile from a file (OpenIccProfile)
 *   2. How to read header fields (version, class, color space, PCS)
 *   3. How to iterate the tag table and inspect tag types
 *   4. How to run the ICC specification validator (CIccProfile::Validate)
 *   5. Understanding the ICC profile binary format (ICC.1-2022-05)
 *
 * Key ICC concepts demonstrated:
 *   - Profile header (128 bytes): size, version, class, color space, PCS,
 *     rendering intent, D50 illuminant, creator signature
 *   - Tag table: list of (signature, offset, size) entries pointing to
 *     typed data blocks within the profile
 *   - Profile classes: Input (scnr), Display (mntr), Output (prtr),
 *     DeviceLink (link), ColorSpace (spac), Abstract (abst), NamedColor (nmcl)
 *   - Validation: checks profile against ICC specification requirements
 *
 * References:
 *   - ICC.1-2022-05: https://www.color.org/specification/ICC.1-2022-05.pdf
 *   - iccDEV: https://github.com/InternationalColorConsortium/iccDEV
 *   - BeyondRGB: https://github.com/BeyondRGB
 */

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ── IccProfLib headers (from iccDEV) ───────────────────────────────────
#include "IccProfile.h"
#include "IccTag.h"
#include "IccUtil.h"
#include "IccIO.h"

// ── Helpers ────────────────────────────────────────────────────────────

/// Convert a 4-byte ICC signature to a printable string.
/// ICC uses 4-character ASCII signatures to identify profile classes,
/// color spaces, tag types, etc. (ICC.1-2022-05 §4.1)
static std::string sig_to_str(icUInt32Number sig) {
    char buf[5];
    buf[0] = static_cast<char>((sig >> 24) & 0xFF);
    buf[1] = static_cast<char>((sig >> 16) & 0xFF);
    buf[2] = static_cast<char>((sig >>  8) & 0xFF);
    buf[3] = static_cast<char>((sig      ) & 0xFF);
    buf[4] = '\0';
    return std::string(buf);
}

/// Describe a profile class enum in plain English.
/// These are the 7 ICC profile classes (ICC.1-2022-05 §7.2.5)
static const char *class_name(icProfileClassSignature cls) {
    switch (cls) {
    case icSigInputClass:      return "Input (Scanner/Camera)";
    case icSigDisplayClass:    return "Display (Monitor)";
    case icSigOutputClass:     return "Output (Printer)";
    case icSigLinkClass:       return "DeviceLink";
    case icSigColorSpaceClass: return "ColorSpace";
    case icSigAbstractClass:   return "Abstract";
    case icSigNamedColorClass: return "NamedColor";
    default:                   return "Unknown";
    }
}

/// Describe a rendering intent (ICC.1-2022-05 §7.2.15)
static const char *intent_name(icRenderingIntent intent) {
    switch (intent) {
    case icPerceptual:           return "Perceptual";
    case icRelativeColorimetric: return "Relative Colorimetric";
    case icSaturation:           return "Saturation";
    case icAbsoluteColorimetric: return "Absolute Colorimetric";
    default:                     return "Unknown";
    }
}

// ── Core demo: analyze one profile ─────────────────────────────────────

static void analyze_profile(CIccProfile *pIcc, const char *label) {
    const icHeader *hdr = &pIcc->m_Header;

    printf("\n");
    printf("================================================================\n");
    printf("  ICC Profile: %s\n", label);
    printf("================================================================\n");

    // ── 1. Header fields (ICC.1-2022-05 §7.2) ─────────────────────────
    //
    // Every ICC profile starts with a 128-byte header containing fixed
    // metadata. The iccDEV library parses this into the icHeader struct.
    printf("\n  -- Header (128 bytes, ICC.1-2022-05 §7.2) ----------------------\n");
    printf("  Profile size     : %u bytes\n", hdr->size);
    printf("  Version          : %d.%d.%d\n",
           hdr->version >> 24,
           (hdr->version >> 20) & 0xF,
           (hdr->version >> 16) & 0xF);
    printf("  Profile class    : '%s'  (%s)\n",
           sig_to_str(hdr->deviceClass).c_str(),
           class_name((icProfileClassSignature)hdr->deviceClass));
    printf("  Color space      : '%s'\n",
           sig_to_str(hdr->colorSpace).c_str());
    printf("  PCS              : '%s'\n",
           sig_to_str(hdr->pcs).c_str());
    printf("  Rendering intent : %s\n",
           intent_name((icRenderingIntent)(hdr->renderingIntent)));
    printf("  Creator          : '%s'\n",
           sig_to_str(hdr->creator).c_str());

    // D50 illuminant — ICC spec requires this to be X=0.9642 Y=1.0 Z=0.8249
    printf("  Illuminant (D50) : X=%.4f  Y=%.4f  Z=%.4f\n",
           icFtoD(hdr->illuminant.X),
           icFtoD(hdr->illuminant.Y),
           icFtoD(hdr->illuminant.Z));

    // ── 2. Tag table (ICC.1-2022-05 §7.3) ─────────────────────────────
    //
    // After the header, a tag table lists all data elements in the profile.
    // Each tag has a 4-byte signature, an offset, and a size.
    // Tags contain the actual color data (LUTs, curves, matrices, text).
    TagEntryList &tagList = pIcc->m_Tags;
    printf("\n  -- Tag Table (%zu tags, ICC.1-2022-05 §7.3) ---------------------\n",
           tagList.size());
    printf("  %-6s  %-30s  %10s  %10s\n", "Sig", "Type", "Offset", "Size");
    printf("  %-6s  %-30s  %10s  %10s\n", "------", "------------------------------",
           "----------", "----------");

    for (auto it = tagList.begin(); it != tagList.end(); ++it) {
        const icTag &entry = it->TagInfo;
        CIccTag *pTag = pIcc->FindTag((icTagSignature)entry.sig);
        const char *typeName = pTag ? pTag->GetClassName() : "?";
        printf("  '%-4s'  %-30s  %10u  %10u\n",
               sig_to_str(entry.sig).c_str(),
               typeName,
               entry.offset,
               entry.size);
    }

    // ── 3. Validate against ICC specification ──────────────────────────
    //
    // CIccProfile::Validate() checks the profile against the ICC spec.
    // It catches missing required tags, invalid header values, LUT
    // dimension errors, and more.
    printf("\n  -- Validation ---------------------------------------------------\n");
    std::string report;
    icValidateStatus status = pIcc->Validate(report);

    const char *status_str;
    switch (status) {
    case icValidateOK:              status_str = "OK (valid)";          break;
    case icValidateWarning:         status_str = "Warning";             break;
    case icValidateNonCompliant:    status_str = "Non-Compliant";       break;
    case icValidateCriticalError:   status_str = "Critical Error";      break;
    default:                        status_str = "Unknown";             break;
    }
    printf("  Status: %s\n", status_str);

    if (!report.empty()) {
        printf("  Details:\n");
        int lines = 0;
        size_t pos = 0;
        while (pos < report.size() && lines < 12) {
            size_t nl = report.find('\n', pos);
            if (nl == std::string::npos) nl = report.size();
            std::string line = report.substr(pos, nl - pos);
            if (!line.empty())
                printf("    %s\n", line.c_str());
            pos = nl + 1;
            lines++;
        }
        if (pos < report.size())
            printf("    ... (%zu more characters)\n", report.size() - pos);
    }

    // ── 4. Profile description tag ────────────────────────────────────
    //
    // The 'desc' tag (profileDescriptionTag) contains a human-readable
    // name for the profile, stored as multiLocalizedUnicode in v4+.
    printf("\n  -- Profile Description ------------------------------------------\n");
    CIccTag *descTag = pIcc->FindTag(icSigProfileDescriptionTag);
    if (descTag) {
        std::string desc;
        descTag->Describe(desc, 0);
        if (desc.size() > 600) desc.resize(600);
        printf("  %s", desc.c_str());
        if (desc.size() == 600) printf("\n    ...(truncated)...");
        printf("\n");
    } else {
        printf("  (no 'desc' tag found)\n");
    }
}

// ── main ───────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    printf("================================================================\n");
    printf("  IccProfLib Demo\n");
    printf("  Library: iccDEV / IccProfLib2 (ICC.1-2022-05 reference impl)\n");
    printf("  Origin:  BeyondRGB — Imaging Art Beyond RGB\n");
    printf("================================================================\n");

    // Collect profiles to analyze from CLI arguments
    std::vector<const char *> profiles;

    if (argc > 1) {
        for (int i = 1; i < argc; i++)
            profiles.push_back(argv[i]);
    } else {
        // Try common default locations
        const char *defaults[] = {
            "../iccDEV/Testing/sRGB_v4_ICC_preference.icc",
            "../test-profiles/sRGB_D65_MAT.icc",
            "../test-profiles/sRGB_D65_MAT-500lx.icc",
            nullptr
        };
        for (int i = 0; defaults[i]; i++) {
            FILE *f = fopen(defaults[i], "rb");
            if (f) {
                fclose(f);
                profiles.push_back(defaults[i]);
                break;
            }
        }

        if (profiles.empty()) {
            fprintf(stderr, "  No .icc file found. Pass profile paths as arguments.\n");
            fprintf(stderr, "  Usage: %s <profile1.icc> [profile2.icc ...]\n", argv[0]);
            return 1;
        }

        printf("\n  (No arguments — using default: %s)\n", profiles[0]);
        printf("  Tip: pass .icc file paths as arguments to analyze them.\n");
    }

    int demo_num = 0;
    for (const char *path : profiles) {
        demo_num++;
        printf("\n>> Demo %d: Reading ICC profile from: %s\n", demo_num, path);
        CIccProfile *pIcc = OpenIccProfile(path);
        if (pIcc) {
            analyze_profile(pIcc, path);
            delete pIcc;
        } else {
            fprintf(stderr, "  ERROR: Could not open '%s'\n", path);
        }
    }

    printf("\n================================================================\n");
    printf("  Demo complete.  IccProfLib is linked and working!\n");
    printf("================================================================\n");
    return 0;
}
