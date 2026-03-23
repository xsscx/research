# IccTest CLI — cli/CMakeLists.txt
# Builds the icctest command-line tool.
#
# Copyright (c) 1994 - 2026 David H Hoyt LLC

set(ICCTEST_CLI_SOURCES
    src/main.cpp
    src/ArgParser.cpp
    src/LinuxSandbox.cpp
    formatters/TextFormatter.cpp
    formatters/PawgFormatter.cpp
    formatters/JsonFormatter.cpp
    formatters/SarifFormatter.cpp
)

add_executable(icctest ${ICCTEST_CLI_SOURCES})

target_include_directories(icctest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/formatters
)

target_link_libraries(icctest PRIVATE
    -Wl,--whole-archive
    IccTest
    -Wl,--no-whole-archive
)

# Sanitizer compile flags must also be applied to CLI sources so that
# compile-time ASAN detection (__SANITIZE_ADDRESS__) works correctly.
# Link-time propagation from IccTest PUBLIC is not sufficient — the
# CLI binary would be ASAN-linked but LinuxSandbox.cpp wouldn't know,
# causing it to set RLIMIT_AS which kills ASAN's shadow mmap.
if(ENABLE_SANITIZERS)
    target_compile_options(icctest PRIVATE ${ICCTEST_SANITIZER_FLAGS})
endif()
if(ENABLE_COVERAGE)
    target_compile_options(icctest PRIVATE
        -fprofile-instr-generate -fcoverage-mapping)
endif()

target_compile_options(icctest PRIVATE
    ${ICCTEST_DEBUG_FLAGS}
    ${ICCTEST_HARDENING_FLAGS}
    ${ICCTEST_STANDARD_FLAGS}
)

install(TARGETS icctest DESTINATION bin)
