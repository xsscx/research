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
#include <iterator>
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

constexpr size_t kMaxProfileSize = 4 * 1024 * 1024;
constexpr size_t kGeneratedProfileSoftMaxSize = 64 * 1024;
constexpr size_t kMaxSerializedProfileSize = 16 * 1024 * 1024;
constexpr uint8_t kReaderModeCount = 4;
constexpr uint8_t kProfileOperationCount = 4;
constexpr uint8_t kMaxProfileControl = std::numeric_limits<uint8_t>::max();
constexpr size_t kFuzzSeedProfileIndices[] = {0, 1, 2, 3};
constexpr uint8_t kFuzzSeedControls[] = {0, 5, 10, 15};
constexpr size_t kFuzzSeedCount =
    sizeof(kFuzzSeedControls) / sizeof(kFuzzSeedControls[0]);
static_assert(kFuzzSeedCount ==
              sizeof(kFuzzSeedProfileIndices) /
                  sizeof(kFuzzSeedProfileIndices[0]));
using ProfileBytes = std::vector<uint8_t>;
using ProfileSeed = std::tuple<ProfileBytes, uint8_t>;
using ProfileRoundTripSeed = std::tuple<ProfileBytes, uint8_t, uint8_t>;
using ProfileTagLookupSeed =
    std::tuple<ProfileBytes, uint32_t, uint32_t, uint8_t>;

std::unique_ptr<CIccProfile> OpenProfile(const ProfileBytes &bytes,
                                         uint8_t mode,
                                         std::string &report);

std::string GetEnvironmentOrDefault(const char *name,
                                    const char *default_value) {
    const char *value = std::getenv(name);
    return value && *value ? value : default_value;
}

size_t CountConfiguredProfileSeeds() {
    const std::string manifest_path = GetEnvironmentOrDefault(
        "ICC_FUZZTEST_SEED_MANIFEST", ICC_FUZZTEST_DEFAULT_SEED_MANIFEST);
    std::ifstream manifest(manifest_path);
    size_t seed_count = 0;
    std::string relative_path;

    while (std::getline(manifest, relative_path)) {
        if (!relative_path.empty() && relative_path[0] != '#')
            ++seed_count;
    }

    return seed_count;
}

std::vector<ProfileBytes> LoadProfileBytes() {
    const std::string repo_root = GetEnvironmentOrDefault(
        "ICC_FUZZTEST_REPO_ROOT", ICC_FUZZTEST_DEFAULT_REPO_ROOT);
    const std::string manifest_path = GetEnvironmentOrDefault(
        "ICC_FUZZTEST_SEED_MANIFEST", ICC_FUZZTEST_DEFAULT_SEED_MANIFEST);
    std::ifstream manifest(manifest_path);
    std::vector<ProfileBytes> profiles;
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

        profiles.emplace_back(std::move(bytes));
    }

    return profiles;
}

std::vector<ProfileSeed> LoadProfileSeeds() {
    std::vector<ProfileSeed> seeds;
    const std::vector<ProfileBytes> profiles = LoadProfileBytes();

    if (profiles.empty())
        return seeds;

    for (size_t i = 0; i < kFuzzSeedCount; ++i) {
        seeds.emplace_back(
            profiles[kFuzzSeedProfileIndices[i] % profiles.size()],
            kFuzzSeedControls[i]);
    }

    return seeds;
}

std::vector<ProfileRoundTripSeed> LoadProfileRoundTripSeeds() {
    std::vector<ProfileRoundTripSeed> round_trip_seeds;
    const std::vector<ProfileBytes> profiles = LoadProfileBytes();

    if (profiles.empty())
        return round_trip_seeds;

    for (size_t i = 0; i < kFuzzSeedCount; ++i) {
        const uint8_t control = kFuzzSeedControls[i];
        round_trip_seeds.emplace_back(
            profiles[kFuzzSeedProfileIndices[i] % profiles.size()], control,
            static_cast<uint8_t>(i % 3U));
    }

    return round_trip_seeds;
}

std::vector<ProfileTagLookupSeed> LoadProfileTagLookupSeeds() {
    std::vector<ProfileTagLookupSeed> tag_lookup_seeds;
    const std::vector<ProfileBytes> profiles = LoadProfileBytes();
    const size_t seed_profile_count =
        profiles.size() < 4U ? profiles.size() : 4U;

    for (size_t profile_index = 0; profile_index < seed_profile_count;
         ++profile_index) {
        const ProfileBytes &bytes = profiles[profile_index];
        const uint8_t mode =
            static_cast<uint8_t>(profile_index % kReaderModeCount);
        std::string report;
        std::unique_ptr<CIccProfile> profile = OpenProfile(bytes, mode, report);
        if (!profile || profile->m_Tags.empty())
            continue;

        for (IccTagEntry &entry : profile->m_Tags) {
            CIccTag *tag = profile->FindTag(entry);
            if (!tag)
                continue;

            const uint32_t tag_signature =
                static_cast<uint32_t>(entry.TagInfo.sig);
            const uint32_t type_signature =
                static_cast<uint32_t>(tag->GetType());
            tag_lookup_seeds.emplace_back(
                bytes, tag_signature, type_signature, mode);
            if (profile_index == 0) {
                tag_lookup_seeds.emplace_back(
                    bytes, tag_signature, type_signature ^ 1U, mode);
                tag_lookup_seeds.emplace_back(bytes, 0U, 0U, mode);
            }
            break;
        }
    }

    return tag_lookup_seeds;
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

bool SerializeProfile(const CIccProfile &profile, uint8_t save_method,
                      ProfileBytes &serialized) {
    const icProfileIDSaveMethod method =
        static_cast<icProfileIDSaveMethod>(save_method % 3);
    std::unique_ptr<CIccProfile> measure_profile(profile.NewCopy());
    CIccNullIO measure;
    measure.Open();
    if (!measure_profile || !measure_profile->Write(&measure, method))
        return false;

    const size_t serialized_size = measure.GetLength();
    if (!serialized_size || serialized_size > kMaxSerializedProfileSize)
        return false;

    CIccMemIO output;
    if (!output.Alloc(serialized_size, true))
        return false;

    std::unique_ptr<CIccProfile> output_profile(profile.NewCopy());
    if (!output_profile || !output_profile->Write(&output, method) ||
        output.GetLength() != serialized_size) {
        return false;
    }

    serialized.assign(output.GetData(), output.GetData() + serialized_size);
    return true;
}

void ExerciseProfileValidation(CIccProfile &profile, std::string &report) {
    profile.Validate(report);
}

void ExerciseProfileTags(CIccProfile &profile, uint8_t control) {
    if (profile.m_Tags.empty())
        return;

    const size_t selected_index =
        static_cast<size_t>(control >> 4U) % profile.m_Tags.size();
    auto entry_it = profile.m_Tags.begin();
    std::advance(entry_it, selected_index);
    IccTagEntry &entry = *entry_it;
    CIccTag *tag = profile.FindTag(entry);
    if (!tag)
        return;

    std::string description;
    std::string tag_report;
    const int verbosity = static_cast<int>(control & 3U) * 34;
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

void ExerciseProfileAccessors(CIccProfile &profile) {
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
}

void ExerciseProfileCopyWrite(CIccProfile &profile, uint8_t mode) {
    CIccProfile copy(profile);
    CIccNullIO output;
    output.Open();
    (void)copy.Write(
        &output, static_cast<icProfileIDSaveMethod>((mode >> 4U) % 3U));
}

void ExerciseProfile(CIccProfile &profile, uint8_t control,
                     std::string &report) {
    switch ((control / kReaderModeCount) % kProfileOperationCount) {
        case 0:
            ExerciseProfileValidation(profile, report);
            break;
        case 1:
            ExerciseProfileTags(profile, control);
            break;
        case 2:
            ExerciseProfileAccessors(profile);
            break;
        default:
            ExerciseProfileCopyWrite(profile, control);
            break;
    }
}

void ProfileOperationsDoNotCrash(const ProfileBytes &bytes, uint8_t control) {
    if (bytes.size() > kMaxProfileSize)
        return;

    std::string report;
    std::unique_ptr<CIccProfile> profile = OpenProfile(bytes, control, report);
    if (profile)
        ExerciseProfile(*profile, control, report);
}

void ProfileSerializationDoesNotCrash(const ProfileBytes &bytes,
                                      uint8_t control, uint8_t save_method) {
    if (bytes.size() > kMaxProfileSize)
        return;

    std::string report;
    std::unique_ptr<CIccProfile> profile = OpenProfile(bytes, control, report);
    if (!profile)
        return;

    ProfileBytes serialized;
    if (!SerializeProfile(*profile, save_method, serialized))
        return;

    report.clear();
    const uint8_t reparse_control = static_cast<uint8_t>(
        (control & static_cast<uint8_t>(~3U)) | ((control + 1U) & 3U));
    std::unique_ptr<CIccProfile> reparsed =
        OpenProfile(serialized, reparse_control, report);
    if (reparsed)
        ExerciseProfile(*reparsed, reparse_control, report);
}

void ProfileTagLookupDoesNotCrash(const ProfileBytes &bytes,
                                  uint32_t tag_signature,
                                  uint32_t type_signature, uint8_t mode) {
    if (bytes.size() > kMaxProfileSize)
        return;

    std::string report;
    std::unique_ptr<CIccProfile> profile = OpenProfile(bytes, mode, report);
    if (!profile)
        return;

    const icSignature tag_sig = static_cast<icSignature>(tag_signature);
    const icTagTypeSignature type_sig =
        static_cast<icTagTypeSignature>(type_signature);
    CIccTag *tag = profile->FindTag(tag_sig);
    (void)profile->FindTagOfType(tag_sig, type_sig);

    const CIccProfile &const_profile = *profile;
    (void)const_profile.FindTagConst(tag_sig);

    std::unique_ptr<CIccMemIO> tag_io(profile->GetTagIO(tag_sig));
    if (tag_io) {
        icUInt8Number byte = 0;
        (void)tag_io->Read8(&byte, 1);
    }

    if (tag) {
        std::string description;
        std::string tag_report;
        tag->Describe(description, static_cast<int>(mode & 3) * 34);
        tag->Validate(icGetSigPath(tag_sig), tag_report, profile.get());
    }
}

TEST(IccProfileFuzzTest, CuratedSeedsOpen) {
    const std::vector<ProfileBytes> profiles = LoadProfileBytes();
    ASSERT_FALSE(profiles.empty());
    ASSERT_EQ(profiles.size(), CountConfiguredProfileSeeds());
    ASSERT_EQ(LoadProfileSeeds().size(), kFuzzSeedCount);

    for (const ProfileBytes &bytes : profiles) {
        for (uint8_t mode = 0; mode < kReaderModeCount; ++mode) {
            std::string report;
            std::unique_ptr<CIccProfile> profile =
                OpenProfile(bytes, mode, report);
            ASSERT_NE(profile, nullptr);
        }
    }
}

TEST(IccProfileFuzzTest, CuratedSeedsSerializeAndReopen) {
    const std::vector<ProfileBytes> profiles = LoadProfileBytes();
    ASSERT_FALSE(profiles.empty());
    ASSERT_EQ(LoadProfileRoundTripSeeds().size(), kFuzzSeedCount);

    for (const ProfileBytes &bytes : profiles) {
        for (uint8_t mode = 0; mode < kReaderModeCount; ++mode) {
            std::string report;
            std::unique_ptr<CIccProfile> profile =
                OpenProfile(bytes, mode, report);
            ASSERT_NE(profile, nullptr);

            for (uint8_t save_method = 0; save_method < 3; ++save_method) {
                ProfileBytes serialized;
                ASSERT_TRUE(
                    SerializeProfile(*profile, save_method, serialized));
                ASSERT_LE(serialized.size(), kMaxSerializedProfileSize);

                report.clear();
                std::unique_ptr<CIccProfile> reparsed =
                    OpenProfile(serialized, 0, report);
                ASSERT_NE(reparsed, nullptr);
            }
        }
    }
}

TEST(IccProfileFuzzTest, CuratedSeedsReachTagLookup) {
    const std::vector<ProfileBytes> profiles = LoadProfileBytes();
    ASSERT_FALSE(LoadProfileTagLookupSeeds().empty());

    size_t readable_tag_count = 0;
    for (const ProfileBytes &bytes : profiles) {
        for (uint8_t mode = 0; mode < kReaderModeCount; ++mode) {
            std::string report;
            std::unique_ptr<CIccProfile> profile =
                OpenProfile(bytes, mode, report);
            ASSERT_NE(profile, nullptr);
            for (IccTagEntry &entry : profile->m_Tags) {
                CIccTag *tag = profile->FindTag(entry);
                if (!tag)
                    continue;
                EXPECT_EQ(profile->FindTagOfType(entry.TagInfo.sig,
                                                 tag->GetType()),
                          tag);
                ++readable_tag_count;
            }
        }
    }
    ASSERT_GT(readable_tag_count, 0U);
}

FUZZ_TEST(IccProfileFuzzTest, ProfileOperationsDoNotCrash)
    .WithDomains(
        fuzztest::Arbitrary<ProfileBytes>().WithSoftMaxSize(
            kGeneratedProfileSoftMaxSize),
        fuzztest::InRange<uint8_t>(0, kMaxProfileControl))
    .WithSeeds(LoadProfileSeeds);

FUZZ_TEST(IccProfileFuzzTest, ProfileSerializationDoesNotCrash)
    .WithDomains(
        fuzztest::Arbitrary<ProfileBytes>().WithSoftMaxSize(
            kGeneratedProfileSoftMaxSize),
        fuzztest::InRange<uint8_t>(0, kMaxProfileControl),
        fuzztest::InRange<uint8_t>(0, 2))
    .WithSeeds(LoadProfileRoundTripSeeds);

FUZZ_TEST(IccProfileFuzzTest, ProfileTagLookupDoesNotCrash)
    .WithDomains(
        fuzztest::Arbitrary<ProfileBytes>().WithSoftMaxSize(
            kGeneratedProfileSoftMaxSize),
        fuzztest::Arbitrary<uint32_t>(),
        fuzztest::Arbitrary<uint32_t>(),
        fuzztest::InRange<uint8_t>(0, 3))
    .WithSeeds(LoadProfileTagLookupSeeds);

}  // namespace
