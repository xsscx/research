/*
 * CFL icc_connect_fuzzer - direct IccConnect library coverage.
 *
 * Builds CIccCfgProfileSequence objects from fuzzed ICC data and exercises
 * CIccConnectCmm::CreateStandard(), including a bounded threaded path.
 */

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <string>

#include "IccConnect.h"
#include "IccCmmThread.h"
#include "IccDefs.h"
#include "IccUtil.h"
#include "fuzz_utils.h"

static constexpr size_t kMaxConnectInputSize = 1024 * 1024;

static bool WriteTempProfile(const uint8_t *data, size_t size, char *path, size_t path_size) {
  if (!fuzz_build_path(path, path_size, fuzz_tmpdir(), "/fuzz_connect_XXXXXX.icc"))
    return false;

  int fd = mkstemps(path, 4);
  if (fd == -1)
    return false;

  const uint8_t *cursor = data;
  size_t remaining = size;
  while (remaining) {
    ssize_t written = write(fd, cursor, remaining);
    if (written <= 0) {
      close(fd);
      unlink(path);
      return false;
    }
    cursor += written;
    remaining -= static_cast<size_t>(written);
  }

  close(fd);
  return true;
}

static void FillConfig(CIccCfgProfile &cfg, const char *path, uint8_t flags) {
  cfg.reset();
  cfg.m_iccFile = path ? path : "";
  cfg.m_intent = flags & 0x03;
  cfg.m_interpolation = (flags & 0x04) ? icInterpLinear : icInterpTetrahedral;
  cfg.m_useBPC = (flags & 0x08) != 0;
  cfg.m_adjustPcsLuminance = (flags & 0x10) != 0;
  cfg.m_useV5SubProfile = (flags & 0x20) != 0;
  cfg.m_useD2BxB2Dx = (flags & 0x40) != 0;
}

static void ExerciseApply(CIccConnectCmm *conn, uint8_t seed, uint8_t mode) {
  if (!conn || !conn->GetCmm())
    return;

  CIccCmm *cmm = conn->GetCmm();
  const int n_src = icGetSpaceSamples(cmm->GetSourceSpace());
  const int n_dst = icGetSpaceSamples(cmm->GetDestSpace());
  if (n_src <= 0 || n_src > 16 || n_dst <= 0 || n_dst > 16)
    return;

  const icUInt32Number n_pixels = conn->IsThreaded() ? 4 : 1;
  icFloatNumber src[16 * 4] = {};
  icFloatNumber dst[16 * 4] = {};

  for (icUInt32Number p = 0; p < n_pixels; p++) {
    for (int c = 0; c < n_src; c++) {
      src[p * n_src + c] = static_cast<icFloatNumber>((seed + p * 53 + c * 29) & 0xff) / 255.0f;
    }
  }

  if ((mode & 1) && n_pixels > 1)
    cmm->Apply(dst, src, n_pixels);
  else
    cmm->Apply(dst, src);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!data || size < 136 || size > kMaxConnectInputSize)
    return 0;

  const size_t profile_size = size - 4;
  const uint8_t *profile_data = data;
  const uint8_t *ctrl = data + profile_size;

  if (!fuzz_validate_icc_tags(profile_data, profile_size))
    return 0;

  const bool use_embedded = (ctrl[0] & 0x01) != 0;
  const bool try_named = (ctrl[0] & 0x02) != 0;
  const bool try_threaded = (ctrl[0] & 0x04) != 0 && profile_size <= 64 * 1024;
  const int thread_cases[] = {1, 2};
  const int n_threads = try_threaded ? thread_cases[(ctrl[1] >> 1) & 1] : 1;

  char tmp_profile[512] = {};
  if (!use_embedded) {
    if (!WriteTempProfile(profile_data, profile_size, tmp_profile, sizeof(tmp_profile)))
      return 0;
  }

  CIccCfgProfileSequence seq;
  CIccCfgProfilePtr cfg(new CIccCfgProfile());
  if (!cfg) {
    if (tmp_profile[0])
      unlink(tmp_profile);
    return 0;
  }
  FillConfig(*cfg, use_embedded ? nullptr : tmp_profile, ctrl[2]);
  seq.m_profiles.push_back(cfg);

  std::string err;
  std::unique_ptr<CIccConnectCmm> conn(CIccConnectCmm::CreateStandard(
      seq,
      use_embedded ? profile_data : nullptr,
      use_embedded ? static_cast<unsigned int>(std::min(profile_size, static_cast<size_t>(0xffffffffu))) : 0,
      n_threads,
      &err));
  if (conn)
    ExerciseApply(conn.get(), ctrl[3], ctrl[0]);

  if (try_named && tmp_profile[0]) {
    std::string named_err;
    std::unique_ptr<CIccConnectCmm> named(CIccConnectCmm::CreateNamed(seq, icSigUnknownData, true, &named_err));
    if (named)
      ExerciseApply(named.get(), ctrl[3], ctrl[0]);
  }

  if (tmp_profile[0])
    unlink(tmp_profile);
  return 0;
}
