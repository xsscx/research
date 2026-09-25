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
 * CFL icc_tojson_fuzzer - direct IccJSON profile serialization coverage.
 *
 * Accepts binary ICC input, reads it through CIccProfileJson, then serializes
 * through both object and string JSON paths.
 */

#include <stddef.h>
#include <stdint.h>

#include <exception>
#include <new>
#include <string>

#include "IccIO.h"
#include "IccMpeJsonFactory.h"
#include "IccProfileJson.h"
#include "IccTagJsonFactory.h"
#include "fuzz_utils.h"

struct IccToJsonFactories {
  IccToJsonFactories() {
    CIccTagCreator::PushFactory(new (std::nothrow) CIccTagJsonFactory());
    CIccMpeCreator::PushFactory(new (std::nothrow) CIccMpeJsonFactory());
  }
};

static IccToJsonFactories g_factories;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!data || size < 132)
    return 0;

  CIccMemIO mem;
  if (!mem.Attach(const_cast<icUInt8Number *>(data), size, false))
    return 0;

  CIccProfileJson profile;
  if (!profile.Read(&mem))
    return 0;

  try {
    IccJson root;
    profile.ToJson(root);

    std::string json_string;
    profile.ToJson(json_string, 2);

    std::string validate_report;
    profile.Validate(validate_report);
  }
  catch (const std::exception &) {
    return 0;
  }

  return 0;
}
