/*
 * Copyright (c) 2026 David H Hoyt LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <random>
#include <string>
#include <utility>
#include <vector>

struct afl_state;
using afl_state_t = struct afl_state;

namespace {

constexpr std::size_t kHeaderSize = 128;
constexpr std::size_t kTagCountOffset = 128;
constexpr std::size_t kTagTableOffset = 132;
constexpr std::size_t kTagEntrySize = 12;
constexpr std::size_t kMaxTags = 1024;
constexpr std::size_t kMaxParsedPayloadBytes = 16U * 1024U * 1024U;

constexpr std::uint32_t make_signature(char a, char b, char c, char d) {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(a)) << 24U) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(b)) << 16U) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(c)) << 8U) |
           static_cast<std::uint32_t>(static_cast<unsigned char>(d));
}

constexpr std::uint32_t kAcspSignature = make_signature('a', 'c', 's', 'p');

constexpr std::array<std::uint32_t, 24> kTagSignatures = {
    make_signature('A', '2', 'B', '0'), make_signature('A', '2', 'B', '1'),
    make_signature('A', '2', 'B', '2'), make_signature('B', '2', 'A', '0'),
    make_signature('B', '2', 'A', '1'), make_signature('B', '2', 'A', '2'),
    make_signature('D', '2', 'B', '0'), make_signature('B', '2', 'D', '0'),
    make_signature('p', 'r', 'e', '0'), make_signature('p', 'r', 'e', '1'),
    make_signature('p', 'r', 'e', '2'), make_signature('g', 'a', 'm', 't'),
    make_signature('c', 'h', 'a', 'd'), make_signature('c', 'i', 'c', 'p'),
    make_signature('c', 'p', 'r', 't'), make_signature('d', 'e', 's', 'c'),
    make_signature('d', 'm', 'n', 'd'), make_signature('d', 'm', 'd', 'd'),
    make_signature('l', 'u', 'm', 'i'), make_signature('m', 'e', 'a', 's'),
    make_signature('n', 'c', 'l', '2'), make_signature('p', 'r', 'o', 'f'),
    make_signature('v', 'u', 'e', 'd'), make_signature('w', 't', 'p', 't')};

constexpr std::array<std::uint32_t, 20> kTypeSignatures = {
    make_signature('c', 'u', 'r', 'v'), make_signature('p', 'a', 'r', 'a'),
    make_signature('m', 'f', 't', '1'), make_signature('m', 'f', 't', '2'),
    make_signature('m', 'A', 'B', ' '), make_signature('m', 'B', 'A', ' '),
    make_signature('m', 'p', 'e', 't'), make_signature('c', 'l', 'u', 't'),
    make_signature('X', 'Y', 'Z', ' '), make_signature('m', 'l', 'u', 'c'),
    make_signature('t', 'e', 'x', 't'), make_signature('d', 'e', 's', 'c'),
    make_signature('d', 'a', 't', 'a'), make_signature('d', 'i', 'c', 't'),
    make_signature('m', 'e', 'a', 's'), make_signature('s', 'f', '3', '2'),
    make_signature('u', 'i', '1', '6'), make_signature('u', 'i', '3', '2'),
    make_signature('u', 'i', '6', '4'), make_signature('v', 'i', 'e', 'w')};

constexpr std::array<std::uint32_t, 8> kDeviceClasses = {
    make_signature('s', 'c', 'n', 'r'), make_signature('m', 'n', 't', 'r'),
    make_signature('p', 'r', 't', 'r'), make_signature('l', 'i', 'n', 'k'),
    make_signature('s', 'p', 'a', 'c'), make_signature('a', 'b', 's', 't'),
    make_signature('n', 'm', 'c', 'l'), make_signature('c', 'o', 'l', 'r')};

constexpr std::array<std::uint32_t, 12> kColorSpaces = {
    make_signature('R', 'G', 'B', ' '), make_signature('C', 'M', 'Y', 'K'),
    make_signature('G', 'R', 'A', 'Y'), make_signature('L', 'a', 'b', ' '),
    make_signature('X', 'Y', 'Z', ' '), make_signature('2', 'C', 'L', 'R'),
    make_signature('3', 'C', 'L', 'R'), make_signature('4', 'C', 'L', 'R'),
    make_signature('5', 'C', 'L', 'R'), make_signature('8', 'C', 'L', 'R'),
    make_signature('F', 'C', 'L', 'R'), make_signature('s', 'p', 'e', 'c')};

constexpr std::array<std::uint32_t, 8> kBoundaryValues = {
    0U, 1U, 2U, 0x7fffU, 0xffffU, 0x7fffffffU, 0x80000000U,
    0xffffffffU};

struct TagRecord {
    std::uint32_t signature = 0;
    std::vector<std::uint8_t> payload;
};

struct IccProfile {
    std::array<std::uint8_t, kHeaderSize> header{};
    std::vector<TagRecord> tags;
};

struct MutatorState {
    explicit MutatorState(unsigned int seed) : rng(seed) {}

    std::mt19937_64 rng;
    std::vector<std::uint8_t> output;
    std::string description = "icc-init";
};

std::uint32_t read_be32(const std::uint8_t *data) {
    return (static_cast<std::uint32_t>(data[0]) << 24U) |
           (static_cast<std::uint32_t>(data[1]) << 16U) |
           (static_cast<std::uint32_t>(data[2]) << 8U) |
           static_cast<std::uint32_t>(data[3]);
}

void write_be32(std::uint8_t *data, std::uint32_t value) {
    data[0] = static_cast<std::uint8_t>(value >> 24U);
    data[1] = static_cast<std::uint8_t>(value >> 16U);
    data[2] = static_cast<std::uint8_t>(value >> 8U);
    data[3] = static_cast<std::uint8_t>(value);
}

std::size_t align4(std::size_t value) {
    return (value + 3U) & ~static_cast<std::size_t>(3U);
}

std::size_t choose(MutatorState &state, std::size_t count) {
    if (!count) {
        return 0;
    }
    std::uniform_int_distribution<std::size_t> distribution(0, count - 1U);
    return distribution(state.rng);
}

bool parse_profile(const std::uint8_t *data, std::size_t size,
                   IccProfile &profile) {
    if (!data || size < kTagTableOffset ||
        read_be32(data + 36U) != kAcspSignature) {
        return false;
    }

    const std::uint32_t declared32 = read_be32(data);
    const std::size_t declared = declared32;
    if (declared < kTagTableOffset || declared > size) {
        return false;
    }

    const std::uint32_t count32 = read_be32(data + kTagCountOffset);
    const std::size_t count = count32;
    if (count > kMaxTags ||
        count > (declared - kTagTableOffset) / kTagEntrySize) {
        return false;
    }

    const std::size_t table_end = kTagTableOffset + count * kTagEntrySize;
    std::size_t copied_payload_bytes = 0;
    IccProfile parsed;
    std::copy_n(data, kHeaderSize, parsed.header.begin());
    parsed.tags.reserve(count);

    for (std::size_t index = 0; index < count; ++index) {
        const std::size_t entry_offset = kTagTableOffset + index * kTagEntrySize;
        const std::uint32_t tag_offset32 = read_be32(data + entry_offset + 4U);
        const std::uint32_t tag_size32 = read_be32(data + entry_offset + 8U);
        const std::size_t tag_offset = tag_offset32;
        const std::size_t tag_size = tag_size32;

        if (tag_offset < table_end || tag_offset > declared ||
            tag_size > declared - tag_offset ||
            tag_size > kMaxParsedPayloadBytes - copied_payload_bytes) {
            return false;
        }

        TagRecord tag;
        tag.signature = read_be32(data + entry_offset);
        tag.payload.assign(data + tag_offset, data + tag_offset + tag_size);
        copied_payload_bytes += tag_size;
        parsed.tags.push_back(std::move(tag));
    }

    profile = std::move(parsed);
    return true;
}

bool serialize_profile(const IccProfile &profile, std::size_t max_size,
                       std::vector<std::uint8_t> &output) {
    if (profile.tags.size() > kMaxTags || max_size < kTagTableOffset ||
        max_size > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    std::size_t total = kTagTableOffset + profile.tags.size() * kTagEntrySize;
    total = align4(total);
    for (const TagRecord &tag : profile.tags) {
        if (tag.payload.size() > max_size - std::min(total, max_size)) {
            return false;
        }
        total += tag.payload.size();
        if (total > max_size) {
            return false;
        }
        total = align4(total);
        if (total > max_size) {
            return false;
        }
    }

    if (total > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    output.assign(total, 0);
    std::copy(profile.header.begin(), profile.header.end(), output.begin());
    write_be32(output.data(), static_cast<std::uint32_t>(total));
    write_be32(output.data() + 36U, kAcspSignature);
    write_be32(output.data() + kTagCountOffset,
               static_cast<std::uint32_t>(profile.tags.size()));

    std::size_t payload_offset =
        align4(kTagTableOffset + profile.tags.size() * kTagEntrySize);
    for (std::size_t index = 0; index < profile.tags.size(); ++index) {
        const TagRecord &tag = profile.tags[index];
        const std::size_t entry_offset = kTagTableOffset + index * kTagEntrySize;
        write_be32(output.data() + entry_offset, tag.signature);
        write_be32(output.data() + entry_offset + 4U,
                   static_cast<std::uint32_t>(payload_offset));
        write_be32(output.data() + entry_offset + 8U,
                   static_cast<std::uint32_t>(tag.payload.size()));
        if (!tag.payload.empty()) {
            std::copy(tag.payload.begin(), tag.payload.end(),
                      output.begin() + static_cast<std::ptrdiff_t>(payload_offset));
        }
        payload_offset = align4(payload_offset + tag.payload.size());
    }
    return true;
}

void mutate_header(MutatorState &state, IccProfile &profile) {
    const std::size_t operation = choose(state, 8U);
    switch (operation) {
        case 0:
            write_be32(profile.header.data() + 8U,
                       choose(state, 2U) ? 0x04300000U : 0x05000000U);
            state.description = "icc-header-version";
            break;
        case 1:
            write_be32(profile.header.data() + 12U,
                       kDeviceClasses[choose(state, kDeviceClasses.size())]);
            state.description = "icc-header-class";
            break;
        case 2:
            write_be32(profile.header.data() + 16U,
                       kColorSpaces[choose(state, kColorSpaces.size())]);
            state.description = "icc-header-space";
            break;
        case 3:
            write_be32(profile.header.data() + 20U,
                       choose(state, 2U) ? make_signature('L', 'a', 'b', ' ')
                                         : make_signature('X', 'Y', 'Z', ' '));
            state.description = "icc-header-pcs";
            break;
        case 4:
            write_be32(profile.header.data() + 44U,
                       kBoundaryValues[choose(state, kBoundaryValues.size())]);
            state.description = "icc-header-flags";
            break;
        case 5:
            write_be32(profile.header.data() + 64U,
                       static_cast<std::uint32_t>(choose(state, 6U)));
            state.description = "icc-header-intent";
            break;
        case 6: {
            const std::size_t byte_offset = 68U + choose(state, 12U);
            profile.header[byte_offset] ^=
                static_cast<std::uint8_t>(1U << choose(state, 8U));
            state.description = "icc-header-illuminant";
            break;
        }
        default: {
            const std::size_t byte_offset = 84U + choose(state, 16U);
            profile.header[byte_offset] =
                static_cast<std::uint8_t>(state.rng() & 0xffU);
            state.description = "icc-header-id";
            break;
        }
    }
}

const TagRecord *choose_donor_tag(MutatorState &state,
                                  const IccProfile *donor) {
    if (!donor || donor->tags.empty()) {
        return nullptr;
    }
    return &donor->tags[choose(state, donor->tags.size())];
}

void mutate_payload(MutatorState &state, TagRecord &tag,
                    const TagRecord *donor) {
    if (tag.payload.empty()) {
        tag.payload.assign(8U, 0U);
        write_be32(tag.payload.data(),
                   kTypeSignatures[choose(state, kTypeSignatures.size())]);
        state.description = "icc-payload-create";
        return;
    }

    const std::size_t operation = choose(state, 6U);
    const std::size_t protected_prefix = tag.payload.size() > 8U ? 8U : 0U;
    switch (operation) {
        case 0: {
            const std::size_t position = protected_prefix +
                choose(state, tag.payload.size() - protected_prefix);
            tag.payload[position] ^=
                static_cast<std::uint8_t>(1U << choose(state, 8U));
            state.description = "icc-payload-bit";
            break;
        }
        case 1: {
            if (tag.payload.size() >= protected_prefix + 4U) {
                const std::size_t slots =
                    (tag.payload.size() - protected_prefix - 4U) / 4U + 1U;
                const std::size_t position = protected_prefix + 4U * choose(state, slots);
                write_be32(tag.payload.data() + position,
                           kBoundaryValues[choose(state, kBoundaryValues.size())]);
                state.description = "icc-payload-boundary";
            } else {
                tag.payload.back() ^= 0xffU;
                state.description = "icc-payload-byte";
            }
            break;
        }
        case 2:
            if (tag.payload.size() >= 4U) {
                write_be32(tag.payload.data(),
                           kTypeSignatures[choose(state, kTypeSignatures.size())]);
                state.description = "icc-payload-type";
            } else {
                tag.payload[choose(state, tag.payload.size())] = 0U;
                state.description = "icc-payload-zero";
            }
            break;
        case 3:
            if (donor && !donor->payload.empty()) {
                const std::size_t copy_size = std::min<std::size_t>(
                    64U, std::min(tag.payload.size(), donor->payload.size()));
                const std::size_t destination =
                    choose(state, tag.payload.size() - copy_size + 1U);
                const std::size_t source =
                    choose(state, donor->payload.size() - copy_size + 1U);
                std::copy_n(donor->payload.data() + source, copy_size,
                            tag.payload.data() + destination);
                state.description = "icc-payload-crossover";
            } else {
                tag.payload[choose(state, tag.payload.size())] = 0xffU;
                state.description = "icc-payload-ff";
            }
            break;
        case 4:
            if (tag.payload.size() > protected_prefix + 1U) {
                const std::size_t available = tag.payload.size() - protected_prefix;
                const std::size_t erase_size =
                    std::min<std::size_t>(available - 1U, 1U + choose(state, 16U));
                const std::size_t position = protected_prefix +
                    choose(state, available - erase_size + 1U);
                tag.payload.erase(tag.payload.begin() + static_cast<std::ptrdiff_t>(position),
                                  tag.payload.begin() + static_cast<std::ptrdiff_t>(position + erase_size));
                state.description = "icc-payload-delete";
            } else {
                tag.payload.push_back(0U);
                state.description = "icc-payload-append";
            }
            break;
        default: {
            const std::size_t insert_size = 1U + choose(state, 16U);
            const std::size_t position = protected_prefix +
                choose(state, tag.payload.size() - protected_prefix + 1U);
            std::vector<std::uint8_t> bytes(insert_size);
            for (std::uint8_t &byte : bytes) {
                byte = static_cast<std::uint8_t>(state.rng() & 0xffU);
            }
            tag.payload.insert(tag.payload.begin() + static_cast<std::ptrdiff_t>(position),
                               bytes.begin(), bytes.end());
            state.description = "icc-payload-insert";
            break;
        }
    }
}

bool mutate_profile(MutatorState &state, IccProfile &profile,
                    const IccProfile *donor, bool &corrupt_directory) {
    corrupt_directory = false;
    const std::size_t operation = choose(state, 10U);
    const TagRecord *donor_tag = choose_donor_tag(state, donor);

    if (operation == 0U || profile.tags.empty()) {
        mutate_header(state, profile);
        return true;
    }

    const std::size_t tag_index = choose(state, profile.tags.size());
    switch (operation) {
        case 1:
            profile.tags[tag_index].signature =
                kTagSignatures[choose(state, kTagSignatures.size())];
            state.description = "icc-tag-signature";
            break;
        case 2:
        case 3:
        case 4:
            mutate_payload(state, profile.tags[tag_index], donor_tag);
            break;
        case 5:
            if (profile.tags.size() > 1U) {
                profile.tags.erase(profile.tags.begin() +
                                   static_cast<std::ptrdiff_t>(tag_index));
                state.description = "icc-tag-delete";
            } else {
                mutate_header(state, profile);
            }
            break;
        case 6:
            if (profile.tags.size() < kMaxTags) {
                profile.tags.insert(
                    profile.tags.begin() + static_cast<std::ptrdiff_t>(tag_index),
                    profile.tags[tag_index]);
                state.description = "icc-tag-duplicate";
            } else {
                mutate_payload(state, profile.tags[tag_index], donor_tag);
            }
            break;
        case 7:
            if (donor_tag && profile.tags.size() < kMaxTags) {
                const std::size_t insert_at = choose(state, profile.tags.size() + 1U);
                profile.tags.insert(
                    profile.tags.begin() + static_cast<std::ptrdiff_t>(insert_at),
                    *donor_tag);
                state.description = "icc-tag-crossover";
            } else {
                mutate_payload(state, profile.tags[tag_index], nullptr);
            }
            break;
        case 8:
            if (profile.tags.size() > 1U) {
                std::size_t other = choose(state, profile.tags.size());
                if (other == tag_index) {
                    other = (other + 1U) % profile.tags.size();
                }
                std::swap(profile.tags[tag_index], profile.tags[other]);
                state.description = "icc-tag-reorder";
            } else {
                mutate_payload(state, profile.tags[tag_index], donor_tag);
            }
            break;
        default:
            corrupt_directory = true;
            state.description = "icc-directory-boundary";
            break;
    }
    return true;
}

void corrupt_tag_directory(MutatorState &state,
                           std::vector<std::uint8_t> &output,
                           std::size_t tag_count) {
    if (!tag_count || output.size() < kTagTableOffset + kTagEntrySize) {
        return;
    }

    const std::size_t index = choose(state, tag_count);
    const std::size_t entry_offset = kTagTableOffset + index * kTagEntrySize;
    const bool mutate_size = choose(state, 2U) != 0U;
    const std::size_t field_offset = entry_offset + (mutate_size ? 8U : 4U);
    const std::uint32_t current = read_be32(output.data() + field_offset);
    std::uint32_t replacement = 0;
    switch (choose(state, 5U)) {
        case 0:
            replacement = static_cast<std::uint32_t>(
                kTagTableOffset + tag_count * kTagEntrySize - 1U);
            break;
        case 1:
            replacement = static_cast<std::uint32_t>(output.size());
            break;
        case 2:
            replacement = 0xffffffffU;
            break;
        case 3:
            replacement = current ? current - 1U : 1U;
            break;
        default:
            replacement = current + 1U;
            break;
    }
    write_be32(output.data() + field_offset, replacement);
}

std::size_t fallback_mutation(MutatorState &state, const std::uint8_t *data,
                              std::size_t size, std::size_t max_size,
                              std::uint8_t **out_buf) {
    const std::size_t output_size = std::min(size, max_size);
    if (!data || !output_size) {
        *out_buf = nullptr;
        return 0;
    }

    std::vector<std::uint8_t> replacement(data, data + output_size);
    const std::size_t position = choose(state, replacement.size());
    replacement[position] ^=
        static_cast<std::uint8_t>(1U << choose(state, 8U));
    state.output.swap(replacement);
    state.description = "icc-fallback-byte";
    *out_buf = state.output.data();
    return state.output.size();
}

std::size_t mutate(MutatorState &state, std::uint8_t *data,
                   std::size_t size, std::uint8_t **out_buf,
                   std::uint8_t *add_data, std::size_t add_size,
                   std::size_t max_size) {
    IccProfile profile;
    if (!parse_profile(data, size, profile)) {
        return fallback_mutation(state, data, size, max_size, out_buf);
    }

    IccProfile donor;
    const IccProfile *donor_ptr = nullptr;
    if (add_data && parse_profile(add_data, add_size, donor)) {
        donor_ptr = &donor;
    }

    bool corrupt_directory = false;
    mutate_profile(state, profile, donor_ptr, corrupt_directory);
    if (!serialize_profile(profile, max_size, state.output)) {
        IccProfile fallback_profile;
        if (parse_profile(data, size, fallback_profile)) {
            mutate_header(state, fallback_profile);
            if (!serialize_profile(fallback_profile, max_size, state.output)) {
                return fallback_mutation(state, data, size, max_size, out_buf);
            }
        } else {
            return fallback_mutation(state, data, size, max_size, out_buf);
        }
    }

    if (corrupt_directory) {
        corrupt_tag_directory(state, state.output, profile.tags.size());
    }
    *out_buf = state.output.data();
    return state.output.size();
}

}  // namespace

extern "C" void *afl_custom_init(afl_state_t *, unsigned int seed) {
    return new (std::nothrow) MutatorState(seed);
}

extern "C" std::size_t afl_custom_fuzz(
    void *opaque, std::uint8_t *buf, std::size_t buf_size,
    std::uint8_t **out_buf, std::uint8_t *add_buf, std::size_t add_buf_size,
    std::size_t max_size) {
    if (!opaque || !out_buf) {
        return 0;
    }
    return mutate(*static_cast<MutatorState *>(opaque), buf, buf_size, out_buf,
                  add_buf, add_buf_size, max_size);
}

extern "C" std::size_t afl_custom_havoc_mutation(
    void *opaque, std::uint8_t *buf, std::size_t buf_size,
    std::uint8_t **out_buf, std::size_t max_size) {
    if (!opaque || !out_buf) {
        return 0;
    }
    return mutate(*static_cast<MutatorState *>(opaque), buf, buf_size, out_buf,
                  nullptr, 0, max_size);
}

extern "C" std::uint8_t afl_custom_havoc_mutation_probability(void *) {
    return 12U;
}

extern "C" const char *afl_custom_describe(void *opaque,
                                             std::size_t max_length) {
    if (!opaque) {
        return "icc-unavailable";
    }
    MutatorState &state = *static_cast<MutatorState *>(opaque);
    if (max_length && state.description.size() >= max_length) {
        state.description.resize(max_length - 1U);
    }
    return state.description.c_str();
}

extern "C" void afl_custom_deinit(void *opaque) {
    delete static_cast<MutatorState *>(opaque);
}
