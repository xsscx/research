cmake_minimum_required(VERSION 3.19)
project(icc_fuzztest LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(GOOGLE_FUZZTEST_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/upstream"
    CACHE PATH "Google FuzzTest source checkout")
set(ICCDEV_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/iccDEV"
    CACHE PATH "iccDEV source checkout")
set(ICCDEV_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/iccdev"
    CACHE PATH "Instrumented iccDEV build directory")
set(ICCDEV_LIBRARY
    "${ICCDEV_BUILD_DIR}/IccProfLib/libIccProfLib2-static.a"
    CACHE FILEPATH "Instrumented static IccProfLib archive")
get_filename_component(_default_repo_root "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(ICC_FUZZTEST_REPO_ROOT "${_default_repo_root}"
    CACHE PATH "Research repository root used for curated seeds")

if(NOT EXISTS "${GOOGLE_FUZZTEST_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "Google FuzzTest checkout not found: ${GOOGLE_FUZZTEST_SOURCE_DIR}")
endif()
if(NOT EXISTS "${ICCDEV_SOURCE_DIR}/Build/Cmake/CMakeLists.txt")
    message(FATAL_ERROR "iccDEV checkout not found: ${ICCDEV_SOURCE_DIR}")
endif()
if(NOT EXISTS "${ICCDEV_LIBRARY}")
    message(FATAL_ERROR "instrumented IccProfLib archive not found: ${ICCDEV_LIBRARY}")
endif()

set(FUZZTEST_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(FUZZTEST_BUILD_FLATBUFFERS OFF CACHE BOOL "" FORCE)
add_subdirectory("${GOOGLE_FUZZTEST_SOURCE_DIR}"
                 "${CMAKE_CURRENT_BINARY_DIR}/google-fuzztest"
                 EXCLUDE_FROM_ALL)

# Instrument the harness; build.sh instruments the imported iccDEV archive.
fuzztest_setup_fuzzing_flags()
if(FUZZTEST_FUZZING_MODE OR FUZZTEST_COMPATIBILITY_MODE STREQUAL "libfuzzer")
    add_compile_options(
        -fno-omit-frame-pointer
        -fsanitize=undefined,integer,float-divide-by-zero,float-cast-overflow)
    add_link_options(
        -fsanitize=undefined,integer,float-divide-by-zero,float-cast-overflow)
endif()

find_package(ZLIB REQUIRED)
add_library(IccProfLib2-static STATIC IMPORTED GLOBAL)
set_target_properties(IccProfLib2-static PROPERTIES
    IMPORTED_LOCATION "${ICCDEV_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES
        "${ICCDEV_BUILD_DIR}/IccProfLib;${ICCDEV_SOURCE_DIR}/IccProfLib;${ICCDEV_SOURCE_DIR}"
    INTERFACE_COMPILE_DEFINITIONS ICC_USE_ZLIB=1)
target_link_libraries(IccProfLib2-static INTERFACE ZLIB::ZLIB)

enable_testing()
include(GoogleTest)

add_executable(icc_profile_fuzz_test icc_profile_fuzz_test.cpp)
target_compile_options(icc_profile_fuzz_test PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wno-deprecated-declarations
    -Wno-nullability-completeness
    -Wno-nullability-extension)
if(FUZZTEST_FUZZING_MODE OR FUZZTEST_COMPATIBILITY_MODE STREQUAL "libfuzzer")
    # Keep full integer instrumentation in the separately built iccDEV archive.
    # FuzzTest and standard-library templates intentionally use unsigned wrap
    # and narrowing while generating and reporting byte-domain inputs. FuzzTest
    # also deserializes an empty byte vector with a zero-length memcpy; libc
    # annotates the otherwise unused null pointer as nonnull.
    target_compile_options(icc_profile_fuzz_test PRIVATE
        -fno-sanitize=implicit-integer-conversion,unsigned-integer-overflow
        -fno-sanitize=nonnull-attribute)
endif()
target_compile_definitions(icc_profile_fuzz_test PRIVATE
    ICC_FUZZTEST_DEFAULT_REPO_ROOT="${ICC_FUZZTEST_REPO_ROOT}"
    ICC_FUZZTEST_DEFAULT_SEED_MANIFEST="${CMAKE_CURRENT_SOURCE_DIR}/seeds.txt")
target_link_libraries(icc_profile_fuzz_test PRIVATE IccProfLib2-static)
link_fuzztest(icc_profile_fuzz_test)

gtest_discover_tests(icc_profile_fuzz_test
    DISCOVERY_MODE PRE_TEST
    PROPERTIES
        ENVIRONMENT
            "ICC_FUZZTEST_REPO_ROOT=${ICC_FUZZTEST_REPO_ROOT};ICC_FUZZTEST_SEED_MANIFEST=${CMAKE_CURRENT_SOURCE_DIR}/seeds.txt")
