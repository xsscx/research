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

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s seconds corpus-directory\n", argv[0]);
        return 2;
    }

    char *end = nullptr;
    long seconds = std::strtol(argv[1], &end, 10);
    if (!end || *end || seconds <= 0) {
        std::fprintf(stderr, "invalid duration: %s\n", argv[1]);
        return 2;
    }

    std::vector<std::filesystem::path> inputs;
    for (const auto& entry : std::filesystem::directory_iterator(argv[2])) {
        if (entry.is_regular_file())
            inputs.push_back(entry.path());
    }
    std::sort(inputs.begin(), inputs.end());
    if (inputs.empty()) {
        std::fprintf(stderr, "no corpus files in %s\n", argv[2]);
        return 2;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    uint64_t runs = 0;
    do {
        for (const auto& path : inputs) {
            std::ifstream stream(path, std::ios::binary);
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(stream)),
                                      std::istreambuf_iterator<char>());
            if (!data.empty()) {
                LLVMFuzzerTestOneInput(data.data(), data.size());
                ++runs;
            }
            if (std::chrono::steady_clock::now() >= deadline)
                break;
        }
    } while (std::chrono::steady_clock::now() < deadline);

    std::printf("stat::number_of_executed_units: %llu\n",
                static_cast<unsigned long long>(runs));
    return 0;
}
