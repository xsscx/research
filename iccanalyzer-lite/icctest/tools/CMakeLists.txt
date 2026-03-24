# IccTest Tools — parity and analysis helpers
#
# Copyright (c) 1994 - 2026 David H Hoyt LLC

add_executable(icctest-parity
    icctestParity.cpp
)

target_link_libraries(icctest-parity PRIVATE
    -Wl,--whole-archive
    IccTest
    -Wl,--no-whole-archive
)

if(ENABLE_SANITIZERS)
    target_compile_options(icctest-parity PRIVATE ${ICCTEST_SANITIZER_FLAGS})
endif()
if(ENABLE_COVERAGE)
    target_compile_options(icctest-parity PRIVATE
        -fprofile-instr-generate -fcoverage-mapping)
endif()

target_compile_options(icctest-parity PRIVATE
    ${ICCTEST_DEBUG_FLAGS}
    ${ICCTEST_HARDENING_FLAGS}
    ${ICCTEST_STANDARD_FLAGS}
)

install(TARGETS icctest-parity DESTINATION bin)

add_custom_target(icctest-verify-parity
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/verifyParity.py
        --v1-binary ${ICCTEST_V1_BINARY}
        --unit-binary $<TARGET_FILE:icctest_unit_tests>
        --v2-binary $<TARGET_FILE:icctest-parity>
        --heuristic-remap ${CMAKE_CURRENT_SOURCE_DIR}/heuristic-remap.tsv
        --output-dir ${CMAKE_BINARY_DIR}/parity-artifacts
        --pretty
    DEPENDS icctest-parity icctest_unit_tests
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMENT "Running IccTest raw/image parity verification"
    VERBATIM
)

if(BUILD_TESTING)
    add_test(
        NAME icctest_verify_pawg
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/verifyPawg.py
            --v1-binary ${ICCTEST_V1_BINARY}
            --v2-binary $<TARGET_FILE:icctest>
    )
    set_tests_properties(icctest_verify_pawg PROPERTIES
        TIMEOUT 120
        ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0;LLVM_PROFILE_FILE=/dev/null"
    )

    add_test(
        NAME icctest_verify_parity
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/verifyParity.py
            --v1-binary ${ICCTEST_V1_BINARY}
            --unit-binary $<TARGET_FILE:icctest_unit_tests>
            --v2-binary $<TARGET_FILE:icctest-parity>
            --heuristic-remap ${CMAKE_CURRENT_SOURCE_DIR}/heuristic-remap.tsv
    )
    set_tests_properties(icctest_verify_parity PROPERTIES
        TIMEOUT 420
        ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0;LLVM_PROFILE_FILE=/dev/null"
    )

    add_test(
        NAME icctest_generated_image_smoke
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/smokeGeneratedImageFormats.py
            --v1-binary ${ICCTEST_V1_BINARY}
            --v2-binary $<TARGET_FILE:icctest-parity>
            --heuristic-remap ${CMAKE_CURRENT_SOURCE_DIR}/heuristic-remap.tsv
    )
    set_tests_properties(icctest_generated_image_smoke PROPERTIES
        TIMEOUT 120
        ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0;LLVM_PROFILE_FILE=/dev/null"
    )

    add_test(
        NAME icctest_verify_cli_sandbox
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/verifyCliSandbox.py
            --cli-binary $<TARGET_FILE:icctest>
    )
    set_tests_properties(icctest_verify_cli_sandbox PROPERTIES
        TIMEOUT 60
        ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0;LLVM_PROFILE_FILE=/dev/null"
    )

    add_test(
        NAME icctest_verify_parity_tooling
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/verifyParityTooling.py
            --v1-binary ${ICCTEST_V1_BINARY}
            --v2-binary $<TARGET_FILE:icctest-parity>
    )
    set_tests_properties(icctest_verify_parity_tooling PROPERTIES
        TIMEOUT 60
        ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0;LLVM_PROFILE_FILE=/dev/null"
    )
endif()
