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

static constexpr size_t kMaxJsonInputSize = 256 * 1024;

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
  if (!data || size < 2 || size > kMaxJsonInputSize)
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
