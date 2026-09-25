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

/*
 * CFL icc_fromjson_fuzzer - direct IccJSON profile parser coverage.
 *
 * Targets CIccProfileJson::ParseJson plus JSON-aware tag/MPE factories. This
 * complements AFL's iccFromJson tool target by keeping the callback in-process
 * and following the CLI parse/validate/save gates after successful parses.
 */

#include <stddef.h>
#include <stdint.h>

#include <cstdio>
#include <exception>
#include <new>
#include <string>

#include "IccMpeJsonFactory.h"
#include "IccProfileJson.h"
#include "IccTagJsonFactory.h"

struct IccJsonFactories {
  IccJsonFactories() {
    CIccTagCreator::PushFactory(new (std::nothrow) CIccTagJsonFactory());
    CIccMpeCreator::PushFactory(new (std::nothrow) CIccMpeJsonFactory());
  }
};

static IccJsonFactories g_factories;

static bool ParseJsonInput(const uint8_t *data, size_t size, IccJson &root) {
  try {
    root = IccJson::parse(data, data + size, nullptr, false);
  }
  catch (const std::exception &) {
    return false;
  }
  return !root.is_discarded();
}

static icProfileIDSaveMethod ProfileIdSaveMethod(const CIccProfileJson &profile) {
  for (int i = 0; i < 16; i++) {
    if (profile.m_Header.profileID.ID8[i])
      return icAlwaysWriteID;
  }
  return icVersionBasedID;
}

static void ExerciseCliSaveGate(CIccProfileJson &profile) {
  FILE *file = tmpfile();
  if (!file)
    return;

  SaveIccProfile(file, &profile, ProfileIdSaveMethod(profile));
  fclose(file);
}

static void ExerciseProfileJson(const IccJson &root) {
  CIccProfileJson profile;
  std::string reason;

  if (!profile.ParseJson(root, reason))
    return;

  std::string validate_report;
  profile.Validate(validate_report);
  ExerciseCliSaveGate(profile);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!data || size < 2)
    return 0;

  IccJson root;
  if (!ParseJsonInput(data, size, root))
    return 0;

  ExerciseProfileJson(root);

  if (root.is_object() && !root.contains("IccProfile")) {
    IccJson wrapped;
    wrapped["IccProfile"] = root;
    ExerciseProfileJson(wrapped);
  }

  return 0;
}
