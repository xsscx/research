# IccTest CLI — cli/CMakeLists.txt
# Builds the icctest command-line tool.
#
# Copyright (c) 1994 - 2026 David H Hoyt LLC

set(ICCTEST_CLI_SOURCES
    src/main.cpp
    src/ArgParser.cpp
    src/LinuxSandbox.cpp
    formatters/TextFormatter.cpp
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

# Sanitizer flags propagate from IccTest's PUBLIC link options.
# Debug/hardening flags for CLI itself:
target_compile_options(icctest PRIVATE
    ${ICCTEST_DEBUG_FLAGS}
    ${ICCTEST_HARDENING_FLAGS}
    ${ICCTEST_STANDARD_FLAGS}
)

install(TARGETS icctest DESTINATION bin)
