# IccTest Library — Top-level CMakeLists.txt
# V2 recode of iccanalyzer-lite
#
# Copyright (c) 1994 - 2026 David H Hoyt LLC

cmake_minimum_required(VERSION 3.15)
project(IccTest VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── iccDEV paths ──
# Search order: ../iccDEV/Build, ../../iccDEV/Build, env ICCDEV_BUILD
if(NOT DEFINED ICCDEV_ROOT)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../iccDEV")
        set(ICCDEV_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../iccDEV")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../iccDEV")
        set(ICCDEV_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../iccDEV")
    else()
        message(FATAL_ERROR "Cannot find iccDEV. Set -DICCDEV_ROOT=<path>")
    endif()
endif()

# Detect build dir
if(EXISTS "${ICCDEV_ROOT}/Build/IccProfLib/libIccProfLib2-static.a")
    set(ICCDEV_BUILD "${ICCDEV_ROOT}/Build")
elseif(EXISTS "${ICCDEV_ROOT}/Build-ASAN/IccProfLib/libIccProfLib2-static.a")
    set(ICCDEV_BUILD "${ICCDEV_ROOT}/Build-ASAN")
else()
    message(WARNING "iccDEV static lib not found. Build iccDEV first.")
    set(ICCDEV_BUILD "${ICCDEV_ROOT}/Build")
endif()

message(STATUS "iccDEV root:  ${ICCDEV_ROOT}")
message(STATUS "iccDEV build: ${ICCDEV_BUILD}")

# ── Compiler flags matching V1 build.sh ──
option(ENABLE_SANITIZERS "Enable ASAN+UBSAN" ON)
option(ENABLE_COVERAGE "Enable code coverage" ON)

set(ICCTEST_SANITIZER_FLAGS
    "-fsanitize=address,undefined"
    "-fsanitize=float-divide-by-zero"
    "-fsanitize=float-cast-overflow"
    "-fsanitize=integer"
    "-fsanitize-recover=address,undefined"
)
set(ICCTEST_DEBUG_FLAGS
    "-g3" "-O0" "-DDEBUG"
    "-fno-omit-frame-pointer"
    "-fno-optimize-sibling-calls"
    "-fno-common"
)
set(ICCTEST_HARDENING_FLAGS
    "-fstack-protector-strong"
    "-D_FORTIFY_SOURCE=2"
)
set(ICCTEST_STANDARD_FLAGS
    "-Wall" "-Wextra" "-Wno-unused-parameter"
    "-Wformat=2" "-Wformat-security"
)

add_subdirectory(lib)
# CLI tool will be added in Phase 4
# add_subdirectory(cli)
