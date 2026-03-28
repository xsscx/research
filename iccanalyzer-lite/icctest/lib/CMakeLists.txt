# IccTest Library — lib/CMakeLists.txt
# Builds libIccTest.a (static library)
#
# Copyright (c) 1994 - 2026 David H Hoyt LLC

set(ICCTEST_LIB_SOURCES
    ../../IccDevSafeOverrides.cpp
    src/ProfileView.cpp
    src/CheckRegistry.cpp
    src/Logger.cpp
    src/IccTestRunner.cpp
    # Phase 2: Heuristic checks (H1-H174)
    src/checks/HeaderChecks.cpp
    src/checks/TagValidationChecks.cpp
    src/checks/RawScanChecks.cpp
    src/checks/DataValidationChecks.cpp
    src/checks/ComplianceChecks.cpp
    src/checks/IntegrityChecks.cpp
    src/checks/ImageChecks.cpp
    src/checks/XmlSafetyChecks.cpp
    src/checks/CodeQLPatternChecks.cpp
    src/checks/ExploitGapChecks.cpp
    # Phase 3: Conformance checks (CF-001..CF-329)
    src/checks/CfHeaderChecks.cpp
    src/checks/CfTagTypeChecks.cpp
    src/checks/CfRequiredChecks.cpp
    src/checks/CfLutChecks.cpp
    src/checks/CfV5Checks.cpp
    src/checks/CfQualityChecks.cpp
    src/checks/CfSecurityChecks.cpp
)

add_library(IccTest STATIC ${ICCTEST_LIB_SOURCES})

function(resolve_iccdev_static_lib out_var dir base)
    set(candidates
        "${dir}/${base}-static.a"
        "${dir}/${base}-staticd.a")
    foreach(candidate IN LISTS candidates)
        if(EXISTS "${candidate}")
            set(${out_var} "${candidate}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    message(FATAL_ERROR "Missing iccDEV static library for ${base} in ${dir}")
endfunction()

resolve_iccdev_static_lib(ICCTEST_LIB_PROF "${ICCDEV_BUILD}/IccProfLib" "libIccProfLib2")
resolve_iccdev_static_lib(ICCTEST_LIB_XML "${ICCDEV_BUILD}/IccXML" "libIccXML2")

target_include_directories(IccTest PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    # iccDEV headers needed by ProfileView.h (public API)
    ${ICCDEV_ROOT}/IccProfLib
    ${ICCDEV_ROOT}/IccXML/IccLibXML
    /usr/include/libxml2
)
target_include_directories(IccTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
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
target_link_options(IccTest PUBLIC
    "LINKER:--allow-multiple-definition"
)

target_compile_options(IccTest PRIVATE
    ${ICCTEST_DEBUG_FLAGS}
    ${ICCTEST_HARDENING_FLAGS}
    ${ICCTEST_STANDARD_FLAGS}
)

# Link iccDEV static libs + system deps
target_link_libraries(IccTest PUBLIC
    ${ICCTEST_LIB_PROF}
    ${ICCTEST_LIB_XML}
    xml2 tiff png jpeg z lzma m ssl crypto
)

# ── Unit tests ──
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()
