# IccTest Library — tests/CMakeLists.txt
# Unit tests for core library types.
#
# Copyright (c) 1994 - 2026 David H Hoyt LLC

add_executable(icctest_unit_tests
    test_check_result.cpp
    test_profile_view.cpp
    test_check_registry.cpp
    test_logger.cpp
    test_runner.cpp
    test_main.cpp
)

# Use --whole-archive to force inclusion of all static initializers
# (REGISTER_HEURISTIC macros in check .cpp files).
target_link_libraries(icctest_unit_tests PRIVATE
    -Wl,--whole-archive IccTest -Wl,--no-whole-archive)

target_include_directories(icctest_unit_tests PRIVATE
    ${ICCDEV_ROOT}/IccProfLib
    ${ICCDEV_ROOT}/IccXML/IccLibXML
    /usr/include/libxml2
)

# Sanitizer flags for tests
if(ENABLE_SANITIZERS)
    target_compile_options(icctest_unit_tests PRIVATE ${ICCTEST_SANITIZER_FLAGS})
    target_link_options(icctest_unit_tests PRIVATE ${ICCTEST_SANITIZER_FLAGS})
endif()
if(ENABLE_COVERAGE)
    target_compile_options(icctest_unit_tests PRIVATE
        -fprofile-instr-generate -fcoverage-mapping)
    target_link_options(icctest_unit_tests PRIVATE
        -fprofile-instr-generate -fcoverage-mapping)
endif()

target_compile_options(icctest_unit_tests PRIVATE
    ${ICCTEST_DEBUG_FLAGS}
    ${ICCTEST_STANDARD_FLAGS}
)

if(BUILD_TESTING)
    add_test(NAME icctest_unit_tests COMMAND $<TARGET_FILE:icctest_unit_tests>)
    set_tests_properties(icctest_unit_tests PROPERTIES
        TIMEOUT 120
        ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0;LLVM_PROFILE_FILE=/dev/null"
    )
endif()
