/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * This software and associated documentation files (the "Software") are the
 * exclusive intellectual property of David H Hoyt LLC.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "David H Hoyt LLC" must not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID H HOYT LLC "AS IS" AND ANY EXPRESSED
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL DAVID H HOYT LLC BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Contact: https://hoyt.net
 */

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "IccIO.h"
#include "IccProfile.h"
#include "IccTag.h"
#include "IccUtil.h"
#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"

namespace {

constexpr size_t kMaxProfileSize = 1024 * 1024;
using ProfileBytes = std::vector<uint8_t>;
using ProfileSeed = std::tuple<ProfileBytes, uint8_t>;

std::string GetEnvironmentOrDefault(const char *name,
                                    const char *default_value) {
    const char *value = std::getenv(name);
    return value && *value ? value : default_value;
}

std::vector<ProfileSeed> LoadProfileSeeds() {
    const std::string repo_root = GetEnvironmentOrDefault(
        "ICC_FUZZTEST_REPO_ROOT", ICC_FUZZTEST_DEFAULT_REPO_ROOT);
    const std::string manifest_path = GetEnvironmentOrDefault(
        "ICC_FUZZTEST_SEED_MANIFEST", ICC_FUZZTEST_DEFAULT_SEED_MANIFEST);
    std::ifstream manifest(manifest_path);
    std::vector<ProfileSeed> seeds;
    std::string relative_path;

    while (std::getline(manifest, relative_path)) {
        if (relative_path.empty() || relative_path[0] == '#')
            continue;

        const std::string path = repo_root + "/" + relative_path;
        std::ifstream input(path, std::ios::binary);
        if (!input)
            continue;

        input.seekg(0, std::ios::end);
        const std::streamoff input_size = input.tellg();
        if (input_size <= 0 ||
            static_cast<uint64_t>(input_size) > kMaxProfileSize) {
            continue;
        }
        input.seekg(0, std::ios::beg);

        ProfileBytes bytes(static_cast<size_t>(input_size));
        input.read(reinterpret_cast<char *>(bytes.data()),
                   static_cast<std::streamsize>(input_size));
        if (!input)
            continue;

        const uint8_t mode = static_cast<uint8_t>(seeds.size() % 4);
        seeds.emplace_back(std::move(bytes), mode);
    }

    return seeds;
}

std::unique_ptr<CIccProfile> OpenProfile(const ProfileBytes &bytes,
                                         uint8_t mode,
                                         std::string &report) {
    if (bytes.size() > std::numeric_limits<icUInt32Number>::max())
        return nullptr;

    const uint8_t *data = bytes.data();
    const icUInt32Number size = static_cast<icUInt32Number>(bytes.size());
    switch (mode & 3) {
        case 0:
            return std::unique_ptr<CIccProfile>(
                OpenIccProfile(data, size, false));
        case 1:
            return std::unique_ptr<CIccProfile>(
                OpenIccProfile(data, size, true));
        case 2:
            return std::unique_ptr<CIccProfile>(
                ReadIccProfile(data, size, false));
        default: {
            CIccMemIO *io = new (std::nothrow) CIccMemIO();
            if (!io)
                return nullptr;
            if (!io->Attach(const_cast<icUInt8Number *>(data), size, false)) {
                delete io;
                return nullptr;
            }

            icValidateStatus status = icValidateOK;
            return std::unique_ptr<CIccProfile>(
                ValidateIccProfile(io, report, status));
        }
    }
}

void ExerciseProfile(CIccProfile &profile, uint8_t mode,
                     std::string &report) {
    profile.Validate(report);

    const int verbosity = static_cast<int>(mode & 3) * 34;
    for (IccTagEntry &entry : profile.m_Tags) {
        CIccTag *tag = profile.FindTag(entry);
        if (!tag)
            continue;

        std::string description;
        std::string tag_report;
        tag->Describe(description, verbosity);
        tag->Validate(icGetSigPath(entry.TagInfo.sig), tag_report, &profile);
        (void)tag->GetType();
        (void)tag->IsArrayType();
        (void)tag->IsSupported();
        (void)tag->GetTagArrayType();
        (void)tag->GetTagStructType();

        std::unique_ptr<CIccMemIO> tag_io(profile.GetTagIO(entry.TagInfo.sig));
        if (tag_io) {
            icUInt8Number byte = 0;
            (void)tag_io->Read8(&byte, 1);
        }
    }

    (void)profile.GetSpaceSamples();
    (void)profile.GetParentSpaceSamples();
    (void)profile.GetParentColorSpace();
    (void)profile.AreTagsUnique();
    (void)profile.ReadPccTags();
    (void)profile.getPccViewingConditions();
    (void)profile.getCustomToStandardPcc();
    (void)profile.getStandardToCustomPcc();
    (void)profile.getPccIlluminant();
    (void)profile.getPccCCT();
    (void)profile.getPccObserver();

    icFloatNumber xyz[3] = {};
    profile.getNormIlluminantXYZ(xyz);
    profile.getLumIlluminantXYZ(xyz);
    (void)profile.getMediaWhiteXYZ(xyz);
    (void)profile.calcNormIlluminantXYZ(xyz, &profile);
    (void)profile.calcLumIlluminantXYZ(xyz, &profile);
    (void)profile.calcMediaWhiteXYZ(xyz, &profile);

    CIccProfile copy(profile);
    CIccNullIO output;
    output.Open();
    (void)copy.Write(
        &output, static_cast<icProfileIDSaveMethod>((mode & 3) % 3));
}

void ProfileOperationsDoNotCrash(ProfileBytes bytes, uint8_t mode) {
    if (bytes.size() > kMaxProfileSize)
        return;

    std::string report;
    std::unique_ptr<CIccProfile> profile = OpenProfile(bytes, mode, report);
    if (profile)
        ExerciseProfile(*profile, mode, report);
}

TEST(IccProfileFuzzTest, CuratedSeedsOpen) {
    const std::vector<ProfileSeed> seeds = LoadProfileSeeds();
    ASSERT_FALSE(seeds.empty());

    for (const ProfileSeed &seed : seeds) {
        for (uint8_t mode = 0; mode < 4; ++mode) {
            std::string report;
            std::unique_ptr<CIccProfile> profile =
                OpenProfile(std::get<0>(seed), mode, report);
            ASSERT_NE(profile, nullptr);
        }
    }
}

FUZZ_TEST(IccProfileFuzzTest, ProfileOperationsDoNotCrash)
    .WithDomains(
        fuzztest::Arbitrary<ProfileBytes>().WithMaxSize(kMaxProfileSize),
        fuzztest::InRange<uint8_t>(0, 3))
    .WithSeeds(LoadProfileSeeds);

}  // namespace
