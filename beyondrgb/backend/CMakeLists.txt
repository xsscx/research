cmake_minimum_required(VERSION 3.16)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR
        "In-source builds are not supported.\n"
        "Run CMake with a dedicated build directory, for example:\n"
        "  cmake -S . -B build/Debug -D CMAKE_BUILD_TYPE=Debug\n"
        "  cmake -S . -B build/Release -D CMAKE_BUILD_TYPE=Release\n"
        "If you previously ran 'cmake .', delete CMakeCache.txt and CMakeFiles/ from the source tree."
    )
endif()

include(CheckCXXCompilerFlag)

# Sets the CMAKE Toolchain to the vcpkg installed using ./arch_config_environment
if (NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(_vcpkg_toolchain "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")
    if (EXISTS "${_vcpkg_toolchain}")
        set(CMAKE_TOOLCHAIN_FILE "${_vcpkg_toolchain}" CACHE FILEPATH "Path to the vcpkg toolchain file")
    endif ()
endif ()

# VCPKG on macOS requires system architectures to be set, so set those here.
# Requires a check for the right architecture (x86 or arm64) as well as making sure
# it is not already defined to allow the user to override it using the command line.
if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin" AND NOT DEFINED CMAKE_OSX_ARCHITECTURES)
    if (CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE INTERNAL "Cache the architectures so vcpkg knows what macOS architectures to build for" FORCE)
    elseif (CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
        set(CMAKE_OSX_ARCHITECTURES "x86_64" CACHE INTERNAL "Cache the architectures so vcpkg knows what macOS architectures to build for" FORCE)
    else ()
        message("Target architecture is unknown or different: '${CMAKE_HOST_SYSTEM_PROCESSOR}', defaulting to arm64")
        set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE INTERNAL "Cache the architectures so vcpkg knows what macOS architectures to build for" FORCE)
    endif ()
endif ()

# Trace VCPKG package finding (Use for debugging VCPKG errors)
#set(VCPKG_TRACE_FIND_PACKAGE ON)
#message("TRIPLET: ${VCPKG_TARGET_TRIPLET}")

project(beyond-rgb-backend DESCRIPTION "Imaging Art Beyond RGB" VERSION 2.4.0 LANGUAGES C CXX)

option(ENABLE_TESTS "Build backend unit tests" OFF)
option(ENABLE_COVERAGE "Enable backend coverage instrumentation" OFF)

set(BACKEND_COVERAGE_KIND "disabled")
set(BACKEND_COVERAGE_GCOV_TOOL "")
set(BACKEND_COVERAGE_LLVM_COV "")
set(BACKEND_COVERAGE_LLVM_PROFDATA "")

string(REGEX MATCH "^[0-9]+" BACKEND_C_COMPILER_VERSION_MAJOR "${CMAKE_C_COMPILER_VERSION}")
string(REGEX MATCH "^[0-9]+" BACKEND_CXX_COMPILER_VERSION_MAJOR "${CMAKE_CXX_COMPILER_VERSION}")

function(enable_target_coverage target_name)
    if (NOT ENABLE_COVERAGE)
        return()
    endif ()

    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${target_name} PRIVATE -O0 -g --coverage)
        target_link_options(${target_name} PRIVATE --coverage)
        find_program(backend_gcov_bin
            NAMES
                "gcov-${BACKEND_CXX_COMPILER_VERSION_MAJOR}"
                "gcov-${BACKEND_C_COMPILER_VERSION_MAJOR}"
                gcov
        )
        if (backend_gcov_bin)
            set(BACKEND_COVERAGE_KIND "gcov" PARENT_SCOPE)
            set(BACKEND_COVERAGE_GCOV_TOOL "${backend_gcov_bin}" PARENT_SCOPE)
        else ()
            message(WARNING
                "Could not find a gcov binary for GCC ${CMAKE_CXX_COMPILER_VERSION}. "
                "The coverage target will not be available."
            )
            set(BACKEND_COVERAGE_KIND "missing-tools" PARENT_SCOPE)
        endif ()
    elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${target_name} PRIVATE -O0 -g -fprofile-instr-generate -fcoverage-mapping)
        target_link_options(${target_name} PRIVATE -fprofile-instr-generate)
        find_program(backend_llvm_cov_bin
            NAMES
                "llvm-cov-${BACKEND_CXX_COMPILER_VERSION_MAJOR}"
                llvm-cov
        )
        find_program(backend_llvm_profdata_bin
            NAMES
                "llvm-profdata-${BACKEND_CXX_COMPILER_VERSION_MAJOR}"
                llvm-profdata
        )
        if (backend_llvm_cov_bin AND backend_llvm_profdata_bin)
            set(BACKEND_COVERAGE_KIND "llvm" PARENT_SCOPE)
            set(BACKEND_COVERAGE_LLVM_COV "${backend_llvm_cov_bin}" PARENT_SCOPE)
            set(BACKEND_COVERAGE_LLVM_PROFDATA "${backend_llvm_profdata_bin}" PARENT_SCOPE)
        else ()
            message(WARNING
                "llvm-cov/llvm-profdata were not found for Clang ${CMAKE_CXX_COMPILER_VERSION}. "
                "The coverage target will not be available."
            )
            set(BACKEND_COVERAGE_KIND "missing-tools" PARENT_SCOPE)
        endif ()
    else ()
        message(WARNING "Coverage is only configured for GCC and Clang toolchains.")
        set(BACKEND_COVERAGE_KIND "unsupported" PARENT_SCOPE)
    endif ()
endfunction()

function(detect_dependency_sanitizer_runtime out_var)
    set(${out_var} OFF PARENT_SCOPE)

    if (WIN32)
        return()
    endif ()

    find_program(BACKEND_NM_BIN NAMES llvm-nm nm)
    if (NOT BACKEND_NM_BIN)
        return()
    endif ()

    foreach(candidate IN LISTS ARGN)
        if (NOT candidate OR NOT EXISTS "${candidate}")
            continue()
        endif ()

        execute_process(
            COMMAND ${BACKEND_NM_BIN} -u "${candidate}"
            OUTPUT_VARIABLE candidate_symbols
            RESULT_VARIABLE candidate_result
            ERROR_QUIET
        )

        if (candidate_result EQUAL 0 AND candidate_symbols MATCHES "__asan_|__ubsan_")
            set(${out_var} ON PARENT_SCOPE)
            return()
        endif ()
    endforeach()
endfunction()

function(apply_websocketpp_gcc_workaround target_name)
    if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        return()
    endif ()

    check_cxx_compiler_flag("-Wno-template-id-cdtor" HAS_WNO_TEMPLATE_ID_CDTOR)
    if (HAS_WNO_TEMPLATE_ID_CDTOR)
        # websocketpp still uses template-ids on ctors/dtors, which newer GCC warns on in C++20.
        target_compile_options(${target_name} PRIVATE
            "$<$<COMPILE_LANGUAGE:CXX>:-Wno-template-id-cdtor>"
        )
    endif ()
endfunction()

set(GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
file(MAKE_DIRECTORY "${GENERATED_INCLUDE_DIR}")
configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/include/version.h.in"
        "${GENERATED_INCLUDE_DIR}/version.h"
        @ONLY)

# format!
include(${CMAKE_CURRENT_LIST_DIR}/cmake/clang-format.cmake)

#------------------------------------------
#Add VCPKG provided find_package Here
#------------------------------------------
find_package(asio CONFIG REQUIRED)
find_package(TIFF REQUIRED)
find_package(jsoncons CONFIG REQUIRED)
find_package(PNG REQUIRED)
find_package(boost_lexical_cast CONFIG REQUIRED)
find_package(boost_range CONFIG REQUIRED)

if (ENABLE_TESTS)
    find_package(Catch2 CONFIG REQUIRED)
endif ()

find_path(CPPCODEC_INCLUDE_DIR
    NAMES cppcodec/base64_rfc4648.hpp
    REQUIRED
)

find_package(OpenCV REQUIRED COMPONENTS core imgproc imgcodecs calib3d)

# LCMS and LibRAW
find_package(lcms REQUIRED)
find_package(LibRaw REQUIRED)

detect_dependency_sanitizer_runtime(BACKEND_LINKS_SANITIZER_RUNTIME
    "${TIFF_LIBRARY_RELEASE}"
    "${TIFF_LIBRARY_DEBUG}"
)
if (BACKEND_LINKS_SANITIZER_RUNTIME)
    message(STATUS
        "Static TIFF dependencies were built with ASan/UBSan; linking sanitizer runtimes for beyond-rgb-backend."
    )
endif ()

# Pthreads & OpenMP, Only needed on Linux & Windows since macOS includes these in the compiler.
if (NOT APPLE)
    find_package(Threads REQUIRED)
    find_package(OpenMP REQUIRED)
endif ()

# Include websocketpp AFTER vcpkg is configured
set(BUILD_TESTS OFF CACHE BOOL "Disable tests in websocketpp" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "Disable examples in websocketpp" FORCE)

# Configure cpptrace for macOS
if (APPLE)
    set(CPPTRACE_UNWIND_WITH_UNWIND ON CACHE BOOL "Use _Unwind for stack unwinding on macOS" FORCE)
endif ()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/submodules/cpptrace)

#------------------------------------------
# iccDEV — ICC profile library (submodule)
#------------------------------------------
include(${CMAKE_CURRENT_LIST_DIR}/cmake/FindIccDEV.cmake)

# Create .exe
add_executable(${PROJECT_NAME})

# Find all Header and Source files
target_sources(${PROJECT_NAME} PRIVATE
        src/main.cpp

        # backend_process
        src/backend_process/backend_process.cpp
        src/backend_process/ColorManagedImage.cpp
        src/backend_process/HalfSizePreview.cpp
        src/backend_process/pipeline.cpp
        src/backend_process/ReportRequest.cpp
        src/backend_process/SpectralPicker.cpp
        src/backend_process/SpectralPickerMeasured.cpp
        src/backend_process/ThumbnailLoader.cpp

        # image_processing
        src/image_processing/BitDepthScaler.cpp
        src/image_processing/ChannelSelector.cpp
        src/image_processing/ColorManagedCalibrator.cpp
        src/image_processing/FlatFieldor.cpp
        src/image_processing/ImageCalibrator.cpp
        src/image_processing/ImageProcessor.cpp
        src/image_processing/ImageReader.cpp
        src/image_processing/NoiseReduction.cpp
        src/image_processing/PixelRegestor.cpp
        src/image_processing/PreProcessor.cpp
        src/image_processing/ResultsProcessor.cpp
        src/image_processing/SpectralCalibrator.cpp
        src/image_processing/Verification.cpp

        # image_processing / results
        src/image_processing/results/calibration_results.cpp
        src/image_processing/results/colorimetry_formater.cpp
        src/image_processing/results/general_info_formater.cpp
        src/image_processing/results/m_color_formater.cpp
        src/image_processing/results/m_spectral_formater.cpp
        src/image_processing/results/r_camera_formater.cpp

        # image_util
        src/image_util/ArtObject.cpp
        src/image_util/BitDepthFinder.cpp
        src/image_util/ColorProfiles.cpp
        src/image_util/ColorTarget.cpp
        src/image_util/Image.cpp

        # image_util / image_reader
        src/image_util/image_reader/LibRawReader.cpp
        src/image_util/image_reader/LibRawThumbnail.cpp
        src/image_util/image_reader/LibTiffReader.cpp
        src/image_util/image_reader/TiffReaderOpenCV.cpp

        # image_util / image_writer
        src/image_util/image_writer/ImageWriter.cpp
        src/image_util/image_writer/ImageWriterStrategy.cpp
        src/image_util/image_writer/LibpngWriter.cpp
        src/image_util/image_writer/LibTiffWriter.cpp

        # reference_data
        src/reference_data/color_patch.cpp
        src/reference_data/illuminants.cpp
        src/reference_data/ref_data.cpp
        src/reference_data/ref_data_array.cpp
        src/reference_data/standard_observer.cpp
        src/reference_data/white_points.cpp

        # server
        src/server/communication_obj.cpp
        src/server/communicator.cpp
        src/server/globals_singleton.cpp
        src/server/process_manager.cpp
        src/server/request_server.cpp

        # utils
        src/utils/calibration_util.cpp
        src/utils/cmd_arg_manager.cpp
        src/utils/color_conversions.cpp
        src/utils/csv_parser.cpp
        src/utils/general_utils.cpp
        src/utils/json.cpp
        src/utils/jsonafiable.cpp
        src/utils/resource_paths.cpp
        src/utils/time_tracker.cpp
)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    target_sources(${PROJECT_NAME} PRIVATE src/compat/avx2_compat.c)
    set_source_files_properties(src/compat/avx2_compat.c PROPERTIES COMPILE_OPTIONS "-mavx2")
endif ()

# Set all source include files (ie. *.h)
target_include_directories(${PROJECT_NAME} PRIVATE
        "${GENERATED_INCLUDE_DIR}"
        ${CMAKE_CURRENT_SOURCE_DIR}/submodules/websocketpp
        "${CPPCODEC_INCLUDE_DIR}"
        "${LibRaw_INCLUDE_DIR}"
        ${OpenCV_INCLUDE_DIRS}
)
target_include_directories(${PROJECT_NAME} PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
# adds extra modes for compilation, since we dont use boost and asio instead, we need these
target_compile_definitions(${PROJECT_NAME} PRIVATE
        ASIO_STANDALONE
        WEBSOCKETPP_NO_BOOST
        _WEBSOCKETPP_CPP11_STL_
)
# VCPKG provided target_link_libraries
if (LibRaw_r_DEFINITIONS)
    target_compile_definitions(${PROJECT_NAME} PRIVATE ${LibRaw_r_DEFINITIONS})
endif ()
target_link_libraries(${PROJECT_NAME} PRIVATE
        cpptrace::cpptrace
        IccProfLib2-static  # iccDEV ICC profile library
        asio::asio
        jsoncons::jsoncons
        ${OpenCV_LIBS}
        TIFF::TIFF
        ${LibRaw_r_LIBRARIES}
        lcms::lcms
        PNG::PNG
        Boost::lexical_cast
        Boost::range
)

# Pthreads & OpenMP, only required on Linux & Windows since macOS includes these in its compiler.
if (NOT APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads OpenMP::OpenMP_CXX)
endif ()
if (BACKEND_LINKS_SANITIZER_RUNTIME)
    target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=address,undefined)
endif ()

# Set C++ standard
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)
apply_websocketpp_gcc_workaround(${PROJECT_NAME})

# weird fix for linux to remove malformed macro included in lib dependency
# TODO: remove this with a better fix
if (UNIX AND NOT APPLE)
    get_target_property(current_defs ${PROJECT_NAME} COMPILE_DEFINITIONS)
    if (current_defs)
        list(FILTER current_defs EXCLUDE REGEX "^-pthread$")
        set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_DEFINITIONS "${current_defs}")
    endif ()
endif ()

# ── IccProfLib Demo (educational) ────────────────────────────────────────
# Standalone program that proves IccProfLib is linked and working.
# Build:  cmake --build vuild --target iccproflib_demo
# Run:    ./vuild/iccproflib_demo [optional .icc file]
add_executable(iccproflib_demo src/demo/iccproflib_demo.cpp)
target_include_directories(iccproflib_demo PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_link_libraries(iccproflib_demo PRIVATE IccProfLib2-static)
target_compile_features(iccproflib_demo PRIVATE cxx_std_17)

if (ENABLE_TESTS)
    enable_testing()

    add_executable(unit_tests
            test/unit_utils.cpp
            src/server/globals_singleton.cpp
            src/utils/cmd_arg_manager.cpp
            src/utils/csv_parser.cpp
            src/utils/general_utils.cpp
            src/utils/resource_paths.cpp
    )

    target_include_directories(unit_tests PRIVATE
            "${GENERATED_INCLUDE_DIR}"
            "${CMAKE_CURRENT_SOURCE_DIR}/include"
    )
    target_link_libraries(unit_tests PRIVATE
            Catch2::Catch2WithMain
            Boost::lexical_cast
    )
    target_compile_features(unit_tests PRIVATE cxx_std_20)
    enable_target_coverage(unit_tests)

    add_test(NAME backend_unit_tests COMMAND unit_tests)

    if (ENABLE_COVERAGE)
        set(COVERAGE_DIR "${CMAKE_BINARY_DIR}/coverage")
        set(COVERAGE_HTML_DIR "${COVERAGE_DIR}/html")

        if (BACKEND_COVERAGE_KIND STREQUAL "gcov")
            find_program(LCOV_BIN lcov)
            find_program(GENHTML_BIN genhtml)

            if (LCOV_BIN AND GENHTML_BIN)
                set(COVERAGE_BASE "${COVERAGE_DIR}/base.info")
                set(COVERAGE_TEST "${COVERAGE_DIR}/test.info")
                set(COVERAGE_TOTAL "${COVERAGE_DIR}/total.info")
                set(COVERAGE_FILTERED "${COVERAGE_DIR}/filtered.info")

                add_custom_target(coverage
                        COMMAND ${CMAKE_COMMAND} -E rm -rf "${COVERAGE_DIR}"
                        COMMAND ${CMAKE_COMMAND} -E make_directory "${COVERAGE_DIR}"
                        COMMAND ${LCOV_BIN} --gcov-tool "${BACKEND_COVERAGE_GCOV_TOOL}" --directory . --zerocounters
                        COMMAND ${LCOV_BIN} --gcov-tool "${BACKEND_COVERAGE_GCOV_TOOL}" --directory . --capture --initial --output-file "${COVERAGE_BASE}"
                        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
                        COMMAND ${LCOV_BIN} --gcov-tool "${BACKEND_COVERAGE_GCOV_TOOL}" --directory . --capture --output-file "${COVERAGE_TEST}"
                        COMMAND ${LCOV_BIN} --add-tracefile "${COVERAGE_BASE}" --add-tracefile "${COVERAGE_TEST}" --output-file "${COVERAGE_TOTAL}"
                        COMMAND ${LCOV_BIN} --extract "${COVERAGE_TOTAL}" "${CMAKE_SOURCE_DIR}/src/utils/*" "${CMAKE_SOURCE_DIR}/src/server/globals_singleton.cpp" --output-file "${COVERAGE_FILTERED}"
                        COMMAND ${GENHTML_BIN} "${COVERAGE_FILTERED}" --output-directory "${COVERAGE_HTML_DIR}"
                        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
                        DEPENDS unit_tests
                        COMMENT "Generating backend coverage report"
                        VERBATIM
                )
            else ()
                message(WARNING "lcov/genhtml not found. Coverage target will not be available.")
            endif ()
        elseif (BACKEND_COVERAGE_KIND STREQUAL "llvm")
            set(COVERAGE_PROFILE_RAW "${COVERAGE_DIR}/unit_tests.profraw")
            set(COVERAGE_PROFILE_DATA "${COVERAGE_DIR}/unit_tests.profdata")
            set(COVERAGE_IGNORE_REGEX ".*/(vcpkg|submodules)/.*|/usr/include/.*|/usr/lib/.*")

            add_custom_target(coverage
                    COMMAND ${CMAKE_COMMAND} -E rm -rf "${COVERAGE_DIR}"
                    COMMAND ${CMAKE_COMMAND} -E make_directory "${COVERAGE_HTML_DIR}"
                    COMMAND ${CMAKE_COMMAND} -E env LLVM_PROFILE_FILE=${COVERAGE_PROFILE_RAW} ${CMAKE_CTEST_COMMAND} --output-on-failure
                    COMMAND ${BACKEND_COVERAGE_LLVM_PROFDATA} merge -sparse "${COVERAGE_PROFILE_RAW}" -o "${COVERAGE_PROFILE_DATA}"
                    COMMAND ${BACKEND_COVERAGE_LLVM_COV} report "${CMAKE_BINARY_DIR}/unit_tests" "-instr-profile=${COVERAGE_PROFILE_DATA}" "-ignore-filename-regex=${COVERAGE_IGNORE_REGEX}"
                    COMMAND ${BACKEND_COVERAGE_LLVM_COV} show "${CMAKE_BINARY_DIR}/unit_tests" "-instr-profile=${COVERAGE_PROFILE_DATA}" -format=html "-output-dir=${COVERAGE_HTML_DIR}" "-ignore-filename-regex=${COVERAGE_IGNORE_REGEX}"
                    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
                    DEPENDS unit_tests
                    COMMENT "Generating backend coverage report"
                    VERBATIM
            )
        else ()
            message(WARNING "Coverage tools are unavailable for this compiler configuration.")
        endif ()
    endif ()
endif ()
