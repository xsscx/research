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

/** @file
    LibFuzzer harness for public IccConnect JSON configuration objects.

    Input is one ordinary JSON document. Top-level sections and nested objects
    are parsed, serialized, and parsed again without invoking a CLI or opening
    any path named by the input.
 */

#include <stddef.h>
#include <stdint.h>

#include "IccCmmConfig.h"
#include "IccJsonUtil.h"

static const json &SectionOrRoot(const json &root, const char *name) {
  if (root.is_object()) {
    const auto section = root.find(name);
    if (section != root.end())
      return *section;
  }

  return root;
}

template <typename T>
static size_t ExerciseRoundTrip(const json &value) {
  T parsed;
  if (!parsed.fromJson(value, true))
    return 0;

  json serialized;
  parsed.toJson(serialized);

  T replayed;
  const bool replayed_ok = replayed.fromJson(serialized, true);
  return serialized.dump().size() + static_cast<size_t>(replayed_ok);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!data || !size)
    return 0;

  json root;
  try {
    root = json::parse(data, data + size, nullptr, false);
  } catch (...) {
    return 0;
  }

  if (root.is_discarded())
    return 0;

  size_t observations = 0;
  observations += ExerciseRoundTrip<CIccCfgDataApply>(
      SectionOrRoot(root, "dataFiles"));
  observations += ExerciseRoundTrip<CIccCfgImageApply>(
      SectionOrRoot(root, "imageFiles"));
  observations += ExerciseRoundTrip<CIccCfgConnectOptions>(
      SectionOrRoot(root, "connect"));
  observations += ExerciseRoundTrip<CIccCfgCreateLink>(
      SectionOrRoot(root, "createLink"));
  observations += ExerciseRoundTrip<CIccCfgColorData>(
      SectionOrRoot(root, "colorData"));

  const json &search_apply = SectionOrRoot(root, "searchApply");
  observations += ExerciseRoundTrip<CIccCfgSearchApply>(search_apply);

  const json &profiles = SectionOrRoot(root, "profileSequence");
  observations += ExerciseRoundTrip<CIccCfgProfileSequence>(profiles);
  if (profiles.is_array() && !profiles.empty())
    observations += ExerciseRoundTrip<CIccCfgProfile>(profiles.front());

  const json &search_profiles =
      SectionOrRoot(search_apply, "profileSequence");
  observations += ExerciseRoundTrip<CIccCfgProfileSequence>(search_profiles);
  if (search_profiles.is_array() && !search_profiles.empty()) {
    observations += ExerciseRoundTrip<CIccCfgProfile>(
        search_profiles.front());
  }

  const json &pcc_weights = SectionOrRoot(search_apply, "pccWeights");
  if (pcc_weights.is_array() && !pcc_weights.empty()) {
    observations += ExerciseRoundTrip<CIccCfgPccWeight>(
        pcc_weights.front());
  }

  const json &color_data = SectionOrRoot(root, "colorData");
  const json &data_entries = SectionOrRoot(color_data, "data");
  if (data_entries.is_array() && !data_entries.empty()) {
    observations += ExerciseRoundTrip<CIccCfgDataEntry>(
        data_entries.front());
  }

  volatile size_t result_sink = observations;
  (void)result_sink;
  return 0;
}
