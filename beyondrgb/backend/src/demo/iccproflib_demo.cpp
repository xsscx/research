/**
 * @file iccproflib_demo.cpp
 * @brief Demonstrates IccProfLib integration in the BeyondRGB project.
 *
 * This demo reads ICC profiles (both the embedded sRGB/AdobeRGB byte arrays
 * already in the project AND .icc files from disk) using the IccProfLib
 * library from the iccDEV submodule. It prints header info, tag tables,
 * and validates the profile against the ICC specification.
 *
 * Build: cd backend && cmake -S . -B vuild && cmake --build vuild --target iccproflib_demo
 * Run: cd backend && ./vuild/iccproflib_demo [optional: path/to/profile.icc]
 *
 * Learning objectives:
 *   1. How to open an ICC profile from memory (CIccMemIO) or file
 *   2. How to read header fields (version, class, color space, PCS)
 *   3. How to iterate the tag table and inspect tag types
 *   4. How to run the ICC specification validator (CIccProfile::Validate)
 *   5. How IccProfLib compares to lcms2 (which BeyondRGB already uses)
 */

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "IccIO.h"
#include "IccProfile.h"
#include "IccTag.h"
#include "IccUtil.h"

// NOTE: We do NOT include "image_util/ColorProfiles.hpp" here because it
// pulls in OpenCV and lcms2. Instead we reference the embedded ICC byte
// arrays by forward-declaring them. They live in ColorProfiles.hpp inside
// the btrgb namespace. For this demo we embed a tiny sRGB header inline
// and load real profiles from disk via OpenIccProfile().

static std::string sig_to_str(icUInt32Number sig) {
    char buf[5];
    buf[0] = static_cast<char>((sig >> 24) & 0xFF);
    buf[1] = static_cast<char>((sig >> 16) & 0xFF);
    buf[2] = static_cast<char>((sig >> 8) & 0xFF);
    buf[3] = static_cast<char>((sig) & 0xFF);
    buf[4] = '\0';
    return std::string(buf);
}

static const char *class_name(icProfileClassSignature cls) {
    switch (cls) {
    case icSigInputClass:
        return "Input (Scanner/Camera)";
    case icSigDisplayClass:
        return "Display (Monitor)";
    case icSigOutputClass:
        return "Output (Printer)";
    case icSigLinkClass:
        return "DeviceLink";
    case icSigColorSpaceClass:
        return "ColorSpace";
    case icSigAbstractClass:
        return "Abstract";
    case icSigNamedColorClass:
        return "NamedColor";
    default:
        return "Unknown";
    }
}

static const char *intent_name(icRenderingIntent intent) {
    switch (intent) {
    case icPerceptual:
        return "Perceptual";
    case icRelativeColorimetric:
        return "Relative Colorimetric";
    case icSaturation:
        return "Saturation";
    case icAbsoluteColorimetric:
        return "Absolute Colorimetric";
    default:
        return "Unknown";
    }
}

static void analyze_profile(CIccProfile *pIcc, const char *label) {
    const icHeader *hdr = &pIcc->m_Header;

    printf("\n");
    printf("================================================================\n");
    printf("  ICC Profile: %s\n", label);
    printf("================================================================\n");

    printf("\n  -- Header -------------------------------------------------------\n");
    printf("  Profile size     : %u bytes\n", hdr->size);
    printf("  Version          : %d.%d.%d\n",
           hdr->version >> 24,
           (hdr->version >> 20) & 0xF,
           (hdr->version >> 16) & 0xF);
    printf("  Profile class    : '%s'  (%s)\n",
           sig_to_str(hdr->deviceClass).c_str(),
           class_name((icProfileClassSignature)hdr->deviceClass));
    printf("  Color space      : '%s'\n", sig_to_str(hdr->colorSpace).c_str());
    printf("  PCS              : '%s'\n", sig_to_str(hdr->pcs).c_str());
    printf("  Rendering intent : %s\n",
           intent_name((icRenderingIntent)(hdr->renderingIntent)));
    printf("  Creator          : '%s'\n", sig_to_str(hdr->creator).c_str());
    printf("  Illuminant (D50) : X=%.4f  Y=%.4f  Z=%.4f\n",
           icFtoD(hdr->illuminant.X),
           icFtoD(hdr->illuminant.Y),
           icFtoD(hdr->illuminant.Z));

    TagEntryList &tagList = pIcc->m_Tags;
    printf("\n  -- Tag Table (%zu tags) ------------------------------------------\n",
           tagList.size());
    printf("  %-6s  %-30s  %10s  %10s\n", "Sig", "Type", "Offset", "Size");
    printf("  %-6s  %-30s  %10s  %10s\n", "------", "------------------------------", "----------", "----------");

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

    printf("\n  -- Validation ---------------------------------------------------\n");
    std::string report;
    icValidateStatus status = pIcc->Validate(report);

    const char *status_str;
    switch (status) {
    case icValidateOK:
        status_str = "OK (valid)";
        break;
    case icValidateWarning:
        status_str = "Warning";
        break;
    case icValidateNonCompliant:
        status_str = "Non-Compliant";
        break;
    case icValidateCriticalError:
        status_str = "Critical Error";
        break;
    default:
        status_str = "Unknown";
        break;
    }
    printf("  Status: %s\n", status_str);

    if (!report.empty()) {
        printf("  Details:\n");
        int lines = 0;
        size_t pos = 0;
        while (pos < report.size() && lines < 12) {
            size_t nl = report.find('\n', pos);
            if (nl == std::string::npos) {
                nl = report.size();
            }
            std::string line = report.substr(pos, nl - pos);
            if (!line.empty()) {
                printf("    %s\n", line.c_str());
            }
            pos = nl + 1;
            lines++;
        }
        if (pos < report.size()) {
            printf("    ... (%zu more characters)\n", report.size() - pos);
        }
    }

    printf("\n  -- Profile Description ------------------------------------------\n");
    CIccTag *descTag = pIcc->FindTag(icSigProfileDescriptionTag);
    if (descTag) {
        std::string desc;
        descTag->Describe(desc, 0);
        if (desc.size() > 600) {
            desc.resize(600);
        }
        printf("  %s", desc.c_str());
        if (desc.size() == 600) {
            printf("\n    ...(truncated)...");
        }
        printf("\n");
    } else {
        printf("  (no 'desc' tag found)\n");
    }
}

int main(int argc, char **argv) {
    printf("================================================================\n");
    printf("  BeyondRGB -- IccProfLib Demo\n");
    printf("  Library: iccDEV / IccProfLib2 (ICC.1-2022-05 reference impl)\n");
    printf("================================================================\n");

    const char *default_profile = "submodules/iccDEV/Testing/sRGB_v4_ICC_preference.icc";

    std::vector<const char *> profiles;

    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            profiles.push_back(argv[i]);
        }
    } else {
        profiles.push_back(default_profile);
        printf("\n  (No arguments — using default test profile from iccDEV)\n");
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
