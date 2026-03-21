# IccTest Library — lib/CMakeLists.txt
# Builds libIccTest.a (static library)
#
# Copyright (c) 1994 - 2026 David H Hoyt LLC

set(ICCTEST_LIB_SOURCES
    src/ProfileView.cpp
    src/CheckRegistry.cpp
    src/Logger.cpp
    src/IccTestRunner.cpp
)

add_library(IccTest STATIC ${ICCTEST_LIB_SOURCES})

target_include_directories(IccTest PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(IccTest PRIVATE
    ${ICCDEV_ROOT}/IccProfLib
    ${ICCDEV_ROOT}/IccXML/IccLibXML
    /usr/include/libxml2
)

target_compile_features(IccTest PUBLIC cxx_std_17)

# Sanitizer and debug flags (matching V1)
if(ENABLE_SANITIZERS)
    target_compile_options(IccTest PRIVATE ${ICCTEST_SANITIZER_FLAGS})
    target_link_options(IccTest PUBLIC ${ICCTEST_SANITIZER_FLAGS})
endif()
if(ENABLE_COVERAGE)
    target_compile_options(IccTest PRIVATE
        -fprofile-instr-generate -fcoverage-mapping)
    target_link_options(IccTest PUBLIC
        -fprofile-instr-generate -fcoverage-mapping)
endif()

target_compile_options(IccTest PRIVATE
    ${ICCTEST_DEBUG_FLAGS}
    ${ICCTEST_HARDENING_FLAGS}
    ${ICCTEST_STANDARD_FLAGS}
)

# Link iccDEV static libs + system deps
target_link_libraries(IccTest PUBLIC
    ${ICCDEV_BUILD}/IccProfLib/libIccProfLib2-static.a
    ${ICCDEV_BUILD}/IccXML/libIccXML2-static.a
    xml2 tiff png jpeg z lzma m ssl crypto
)

# ── Unit tests ──
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()
