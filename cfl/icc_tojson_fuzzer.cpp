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

static constexpr size_t kMaxIccInputSize = 1024 * 1024;

struct IccToJsonFactories {
  IccToJsonFactories() {
    CIccTagCreator::PushFactory(new (std::nothrow) CIccTagJsonFactory());
    CIccMpeCreator::PushFactory(new (std::nothrow) CIccMpeJsonFactory());
  }
};

static IccToJsonFactories g_factories;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!data || size < 132 || size > kMaxIccInputSize)
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
