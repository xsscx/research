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

#include <cstddef>
#include <cstdint>
#include <cstring>

struct afl_state;
using afl_state_t = struct afl_state;

extern "C" void *afl_custom_init(afl_state_t *, unsigned int seed);
extern "C" std::size_t afl_custom_fuzz(
    void *opaque, std::uint8_t *buf, std::size_t buf_size,
    std::uint8_t **out_buf, std::uint8_t *add_buf,
    std::size_t add_buf_size, std::size_t max_size);
extern "C" void afl_custom_deinit(void *opaque);
extern "C" std::size_t LLVMFuzzerMutate(std::uint8_t *data,
                                          std::size_t size,
                                          std::size_t max_size);

extern "C" std::size_t LLVMFuzzerCustomMutator(
    std::uint8_t *data, std::size_t size, std::size_t max_size,
    unsigned int seed) {
    if (!data || !max_size) {
        return 0;
    }

    if ((seed & 3U) == 0U) {
        return LLVMFuzzerMutate(data, size, max_size);
    }

    void *state = afl_custom_init(nullptr, seed);
    if (!state) {
        return LLVMFuzzerMutate(data, size, max_size);
    }

    std::uint8_t *output = nullptr;
    const std::size_t output_size = afl_custom_fuzz(
        state, data, size, &output, nullptr, 0U, max_size);
    if (!output || output_size > max_size) {
        afl_custom_deinit(state);
        return LLVMFuzzerMutate(data, size, max_size);
    }

    if (output_size) {
        std::memcpy(data, output, output_size);
    }
    afl_custom_deinit(state);
    return output_size;
}
