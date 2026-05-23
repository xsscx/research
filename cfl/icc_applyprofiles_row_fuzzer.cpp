/*
 * Row-apply variant for iccApplyProfiles.
 *
 * This intentionally reuses the main image-pipeline harness while forcing the
 * batched CIccCmm::Apply(dst, src, pixel_count) branch used when the tool runs
 * with -threads other than 1.
 */

#define ICC_APPLYPROFILES_FORCE_ROW 1
#include "icc_applyprofiles_fuzzer.cpp"
