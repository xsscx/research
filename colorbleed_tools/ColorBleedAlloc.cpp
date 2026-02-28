/*!
 *  @file ColorBleedAlloc.cpp
 *  @brief OOM guard: icRealloc override for colorbleed tools
 *
 *  iccDEV routes all tag data allocations through icRealloc() (IccUtil.cpp).
 *  Malicious profiles can trigger 4GB+ allocations via CIccTagXYZ::SetSize,
 *  CIccTagData::SetSize, CIccMpeTintArray::Read, etc.
 *
 *  This file must be linked BEFORE libIccProfLib2-static.a so the linker
 *  picks our definition over the library's. build.sh handles link order.
 *
 *  Copyright (c) 2021-2026 David H Hoyt LLC
 *  License: GPL-3.0-or-later
 */

#include <cstdio>
#include <cstdlib>
#include <cstddef>

static constexpr size_t CB_MAX_SINGLE_ALLOC = 256 * 1024 * 1024; // 256 MB

// Must match iccDEV signature: void* icRealloc(void*, size_t)
void* icRealloc(void *ptr, size_t size) {
  if (size == 0) {
    free(ptr);
    return nullptr;
  }
  if (size > CB_MAX_SINGLE_ALLOC) {
    fprintf(stderr, "[ColorBleed] icRealloc(%p, %zu) rejected (%.1fMB > %zuMB limit)\n",
            ptr, size, (double)size / (1024.0*1024.0),
            CB_MAX_SINGLE_ALLOC / (1024*1024));
    free(ptr);
    return nullptr;
  }
  return realloc(ptr, size);
}
