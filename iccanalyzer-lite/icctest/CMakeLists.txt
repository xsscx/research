# IccTest Library — Top-level CMakeLists.txt
# V2 recode of iccanalyzer-lite
#
# Copyright (c) 1994 - 2026 David H Hoyt LLC

cmake_minimum_required(VERSION 3.15)
project(IccTest VERSION 2.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CTest)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# ── Require Clang — reject GCC ──
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
        "IccTest requires Clang (got ${CMAKE_CXX_COMPILER_ID}).\n"
        "Use: cmake -DCMAKE_CXX_COMPILER=clang++-18 -DCMAKE_C_COMPILER=clang-18 ..")
endif()

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

set(ICCTEST_V1_BINARY "${PROJECT_SOURCE_DIR}/../iccanalyzer-lite" CACHE FILEPATH
    "Path to the V1 iccAnalyzer-lite binary used for parity verification")

function(icctest_static_lib_exists out_var build_dir)
    if(EXISTS "${build_dir}/IccProfLib/libIccProfLib2-static.a" OR
       EXISTS "${build_dir}/IccProfLib/libIccProfLib2-staticd.a")
        set(${out_var} TRUE PARENT_SCOPE)
    else()
        set(${out_var} FALSE PARENT_SCOPE)
    endif()
endfunction()

# Detect build dir
set(ICCDEV_BUILD "${ICCDEV_BUILD}" CACHE PATH
    "Path to the iccDEV build directory containing static libraries")

if(ICCDEV_BUILD)
    icctest_static_lib_exists(ICCTEST_HAVE_STATIC "${ICCDEV_BUILD}")
else()
    set(ICCTEST_HAVE_STATIC FALSE)
endif()

if(ICCTEST_HAVE_STATIC)
    # Explicit override from workflow or local developer environment.
else()
    icctest_static_lib_exists(ICCTEST_HAVE_STATIC_BUILD "${ICCDEV_ROOT}/Build")
    icctest_static_lib_exists(ICCTEST_HAVE_STATIC_RELEASE "${ICCDEV_ROOT}/Build-release")
    icctest_static_lib_exists(ICCTEST_HAVE_STATIC_ASAN "${ICCDEV_ROOT}/Build-ASAN")
endif()

if(NOT ICCTEST_HAVE_STATIC AND ICCTEST_HAVE_STATIC_BUILD)
    set(ICCDEV_BUILD "${ICCDEV_ROOT}/Build")
elseif(NOT ICCTEST_HAVE_STATIC AND ICCTEST_HAVE_STATIC_RELEASE)
    set(ICCDEV_BUILD "${ICCDEV_ROOT}/Build-release")
elseif(NOT ICCTEST_HAVE_STATIC AND ICCTEST_HAVE_STATIC_ASAN)
    set(ICCDEV_BUILD "${ICCDEV_ROOT}/Build-ASAN")
elseif(NOT ICCTEST_HAVE_STATIC)
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
add_subdirectory(cli)
add_subdirectory(tools)
