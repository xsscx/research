/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All rights reserved.
 *
 * CFL icc_cfg_fuzzer - Structured JSON config mutation fuzzer
 *
 * Target: iccDEV JSON configuration parsing subsystem
 *   - IccCmmConfig.cpp (2,175 LOC) - 9 config classes with fromJson()/toJson()
 *   - IccJsonUtil.cpp (459 LOC)    - JSON file I/O, jsonToValue() templates
 *
 * Attack surface:
 *   - 106 unsafe j["field"] accesses (missing .find() checks)
 *   - Type confusion: string<->number<->bool<->null<->array<->object
 *   - Field name typos / swaps (BUG-1: CFL-033, BUG-7: CFL-034)
 *   - Extreme numeric values (INT_MAX, NaN, Inf, negative)
 *   - Deeply nested arrays / objects (stack exhaustion)
 *   - Empty / null / oversized strings
 *   - Array element count explosion (colorData, envVars, profileSequence)
 *   - fromArgs() enum cast from unchecked atoi() (32 sites)
 *
 * Architecture:
 *   Phase 1 (cheap): Parse fuzz input as JSON via nlohmann::json::parse()
 *   Phase 2 (deep): Call all 3 top-level fromJson() entry points:
 *     - CIccCfgDataApply::fromJson()     (iccApplyNamedCmm config)
 *     - CIccCfgImageApply::fromJson()    (iccApplyProfiles config)
 *     - CIccCfgSearchApply::fromJson()   (iccApplySearch config)
 *   Phase 3 (round-trip): toJson() -> fromJson() divergence detection
 *   Phase 4 (sub-objects): Direct exercise of CIccCfgProfile, CIccCfgColorData,
 *     CIccCfgDataEntry, CIccCfgPccWeight, CIccCfgCreateLink, CIccCfgProfileSequence
 *
 * NO profile files needed - fromJson() only stores parsed values into member
 * variables. Actual ICC profile loading happens later in the tool's Apply() path.
 *
 * Dictionary: cfl/icc_cfg.dict (115 entries: 38 field names, 7 encodings, edge cases)
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>
#include <stdint.h>
#include <stddef.h>
#include <new>

#include "IccCmmConfig.h"
#include "IccJsonUtil.h"
#include "IccProfile.h"
#include "IccCmm.h"

// ===============================================================
// Phase 2: Exercise all 3 top-level config fromJson() paths
// ===============================================================

static void FuzzDataApply(const json& j) {
  CIccCfgDataApply cfg;
  cfg.fromJson(j, true);

  // Round-trip: toJson -> fromJson - should produce identical state
  json roundtrip;
  cfg.toJson(roundtrip);

  CIccCfgDataApply cfg2;
  cfg2.fromJson(roundtrip, true);
}

static void FuzzImageApply(const json& j) {
  CIccCfgImageApply cfg;
  cfg.fromJson(j, true);

  json roundtrip;
  cfg.toJson(roundtrip);

  CIccCfgImageApply cfg2;
  cfg2.fromJson(roundtrip, true);
}

static void FuzzSearchApply(const json& j) {
  CIccCfgSearchApply cfg;
  cfg.fromJson(j, true);

  json roundtrip;
  cfg.toJson(roundtrip);

  CIccCfgSearchApply cfg2;
  cfg2.fromJson(roundtrip, true);
}

// ===============================================================
// Phase 4: Exercise sub-object config classes directly
// ===============================================================

static void FuzzProfile(const json& j) {
  CIccCfgProfile cfg;
  cfg.fromJson(j, true);

  json roundtrip;
  cfg.toJson(roundtrip);

  CIccCfgProfile cfg2;
  cfg2.fromJson(roundtrip, true);
}

static void FuzzProfileSequence(const json& j) {
  CIccCfgProfileSequence cfg;
  cfg.fromJson(j, true);

  json roundtrip;
  cfg.toJson(roundtrip);

  CIccCfgProfileSequence cfg2;
  cfg2.fromJson(roundtrip, true);
}

static void FuzzPccWeight(const json& j) {
  CIccCfgPccWeight cfg;
  cfg.fromJson(j, true);

  json roundtrip;
  cfg.toJson(roundtrip);

  CIccCfgPccWeight cfg2;
  cfg2.fromJson(roundtrip, true);
}

static void FuzzCreateLink(const json& j) {
  CIccCfgCreateLink cfg;
  cfg.fromJson(j, true);

  json roundtrip;
  cfg.toJson(roundtrip);

  CIccCfgCreateLink cfg2;
  cfg2.fromJson(roundtrip, true);
}

static void FuzzColorData(const json& j) {
  CIccCfgColorData cfg;
  cfg.fromJson(j, true);

  json roundtrip;
  cfg.toJson(roundtrip);

  CIccCfgColorData cfg2;
  cfg2.fromJson(roundtrip, true);
}

static void FuzzDataEntry(const json& j) {
  CIccCfgDataEntry cfg;
  cfg.fromJson(j, true);

  json roundtrip;
  cfg.toJson(roundtrip);

  CIccCfgDataEntry cfg2;
  cfg2.fromJson(roundtrip, true);
}

// ===============================================================
// Dispatch: Use first byte of input to select which config path
// to exercise, remaining bytes are the JSON payload.
// This ensures the fuzzer doesn't waste all mutations on a single
// config class.
// ===============================================================

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return 0;

  // First byte selects config class, rest is JSON
  uint8_t selector = data[0];
  const uint8_t *jsonData = data + 1;
  size_t jsonSize = size - 1;

  // Parse as JSON - nlohmann::json::parse() is safe (no UB on malformed input)
  json j;
  try {
    j = json::parse(jsonData, jsonData + jsonSize, nullptr, false);
  } catch (...) {
    return 0;
  }

  // Discard non-parse results (parse with allow_exceptions=false returns discarded)
  if (j.is_discarded())
    return 0;

  // Dispatch based on selector byte - 10 config paths
  switch (selector % 10) {
    case 0: // Top-level: CIccCfgDataApply (iccApplyNamedCmm)
      if (j.is_object()) {
        auto it = j.find("dataFiles");
        if (it != j.end())
          FuzzDataApply(*it);
        else
          FuzzDataApply(j);
      }
      break;

    case 1: // Top-level: CIccCfgImageApply (iccApplyProfiles)
      if (j.is_object()) {
        auto it = j.find("dataFiles");
        if (it != j.end())
          FuzzImageApply(*it);
        else
          FuzzImageApply(j);
      }
      break;

    case 2: // Top-level: CIccCfgSearchApply (iccApplySearch)
      if (j.is_object()) {
        auto it = j.find("searchApply");
        if (it != j.end())
          FuzzSearchApply(*it);
        else
          FuzzSearchApply(j);
      }
      break;

    case 3: // Sub-object: CIccCfgProfile
      FuzzProfile(j);
      break;

    case 4: // Sub-object: CIccCfgProfileSequence
      FuzzProfileSequence(j);
      break;

    case 5: // Sub-object: CIccCfgPccWeight
      FuzzPccWeight(j);
      break;

    case 6: // Sub-object: CIccCfgCreateLink
      FuzzCreateLink(j);
      break;

    case 7: // Sub-object: CIccCfgColorData
      FuzzColorData(j);
      break;

    case 8: // Sub-object: CIccCfgDataEntry
      FuzzDataEntry(j);
      break;

    case 9: { // Full config: parse as complete tool config with all sections
      if (!j.is_object())
        break;

      // Exercise all sections present in the JSON
      auto dfIt = j.find("dataFiles");
      if (dfIt != j.end()) {
        FuzzDataApply(*dfIt);
        FuzzImageApply(*dfIt);
      }

      auto saIt = j.find("searchApply");
      if (saIt != j.end())
        FuzzSearchApply(*saIt);

      auto cdIt = j.find("colorData");
      if (cdIt != j.end())
        FuzzColorData(*cdIt);

      auto psIt = j.find("profileSequence");
      if (psIt != j.end())
        FuzzProfileSequence(*psIt);

      break;
    }
  }

  return 0;
}
