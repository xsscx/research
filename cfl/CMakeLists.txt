# Fuzzing Harnesses for iccDEV
# CFL Branch - Complete LibFuzzer Integration with Full Instrumentation

cmake_minimum_required(VERSION 3.15)

set(CFL_SANITIZER "address" CACHE STRING "Fuzzer sanitizer: address or thread")
set_property(CACHE CFL_SANITIZER PROPERTY STRINGS address thread)

# Only build fuzzers with Clang and when explicitly enabled
if(ENABLE_FUZZING AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(STATUS "Fuzzing harnesses enabled with full instrumentation")
  find_package(ZLIB REQUIRED)

  # Common include directories
  set(FUZZER_INCLUDES
    ${CMAKE_SOURCE_DIR}/../../IccProfLib
    ${CMAKE_SOURCE_DIR}/../../IccXML/IccLibXML
    ${CMAKE_SOURCE_DIR}/../../Tools/CmdLine/IccCommon
    ${CMAKE_SOURCE_DIR}/../../Tools/CmdLine/IccApplyProfiles
    ${CMAKE_SOURCE_DIR}/../../Tools/CmdLine/IccProfilePlot
    ${CMAKE_SOURCE_DIR}/../../IccConnect/IccLibConnect
    ${CMAKE_SOURCE_DIR}/../../IccJSON/IccLibJSON
    ${CMAKE_BINARY_DIR}/IccConnect
    ${CMAKE_BINARY_DIR}/IccJSON
  )

  if(CFL_SANITIZER STREQUAL "thread")
    set(FUZZER_SANITIZERS -fsanitize=thread)
    set(FUZZER_COVERAGE_FLAGS)
    add_library(cfl_tsan_runner STATIC tsan_corpus_runner.cpp)
    target_compile_options(cfl_tsan_runner PRIVATE -fsanitize=thread)
    link_libraries(cfl_tsan_runner)
  elseif(CFL_SANITIZER STREQUAL "address")
    set(FUZZER_SANITIZERS -fsanitize=fuzzer,address,undefined)
    set(FUZZER_COVERAGE_FLAGS -fprofile-instr-generate -fcoverage-mapping)
  else()
    message(FATAL_ERROR "Unsupported CFL_SANITIZER=${CFL_SANITIZER}; use address or thread")
  endif()

  # Full instrumentation flags: sanitizers, debug, profiling, coverage
  # Based on iccAnalyzer instrumented build configuration
  set(FUZZER_COMPILE_FLAGS
    ${FUZZER_SANITIZERS}
    -g                              # Full debug symbols
    -O1                             # Minimal optimization for fuzzing
    -fno-omit-frame-pointer         # Preserve frame pointers for stack traces
    ${FUZZER_COVERAGE_FLAGS}
  )

  set(FUZZER_LINK_FLAGS
    ${FUZZER_SANITIZERS}
    ${FUZZER_COVERAGE_FLAGS}
  )

  # No additional link libraries needed - Clang provides runtime automatically
  link_libraries(ZLIB::ZLIB)

  # V5 DSP/OBS fuzzer
  add_executable(icc_v5dspobs_fuzzer icc_v5dspobs_fuzzer.cpp)
  target_compile_options(icc_v5dspobs_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_v5dspobs_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_v5dspobs_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_v5dspobs_fuzzer IccProfLib2)

  # Roundtrip fuzzer
  add_executable(icc_roundtrip_fuzzer icc_roundtrip_fuzzer.cpp)
  target_compile_options(icc_roundtrip_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_roundtrip_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_roundtrip_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_roundtrip_fuzzer IccProfLib2)

  # Unrestricted, in-memory IccProfLib API fuzzer
  add_executable(icc_proflib_fuzzer icc_proflib_fuzzer.cpp)
  target_compile_options(icc_proflib_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_proflib_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_proflib_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_proflib_fuzzer IccProfLib2)

  # Dump fuzzer
  add_executable(icc_dump_fuzzer icc_dump_fuzzer.cpp)
  target_compile_options(icc_dump_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_dump_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_dump_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_dump_fuzzer IccProfLib2)

  # Data-first profile visualization fuzzer. Compile IccVizModel.cpp as a
  # separate translation unit so this target exercises the public API boundary.
  add_executable(icc_profilevisualize_fuzzer
    icc_profilevisualize_fuzzer.cpp
    ${CMAKE_SOURCE_DIR}/../../Tools/CmdLine/IccProfilePlot/IccVizModel.cpp
  )
  target_compile_options(icc_profilevisualize_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_profilevisualize_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_profilevisualize_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_profilevisualize_fuzzer IccProfLib2)

  # Link fuzzer
  add_executable(icc_link_fuzzer icc_link_fuzzer.cpp)
  target_compile_options(icc_link_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_link_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_link_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_link_fuzzer IccProfLib2)

  # FromCube fuzzer
  add_executable(icc_fromcube_fuzzer icc_fromcube_fuzzer.cpp)
  target_compile_options(icc_fromcube_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_fromcube_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_fromcube_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_fromcube_fuzzer IccProfLib2)

  # ApplyNamedCmm fuzzer
  add_executable(icc_applynamedcmm_fuzzer icc_applynamedcmm_fuzzer.cpp)
  target_compile_options(icc_applynamedcmm_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_applynamedcmm_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_applynamedcmm_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_applynamedcmm_fuzzer IccProfLib2)

  set(TIFF_FUZZER_COMMON
    ${CMAKE_SOURCE_DIR}/../../Tools/CmdLine/IccApplyProfiles/TiffImg.cpp
  )

  # ApplyProfiles fuzzer
  add_executable(icc_applyprofiles_fuzzer icc_applyprofiles_fuzzer.cpp ${TIFF_FUZZER_COMMON})
  target_compile_options(icc_applyprofiles_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_applyprofiles_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_applyprofiles_fuzzer PRIVATE ${FUZZER_INCLUDES} ${TIFF_INCLUDE_DIRS})
  target_link_libraries(icc_applyprofiles_fuzzer IccConnect2-static IccProfLib2 ${TIFF_LIBRARIES})

  # ApplyProfiles row-apply fuzzer (-threads path)
  add_executable(icc_applyprofiles_row_fuzzer icc_applyprofiles_row_fuzzer.cpp ${TIFF_FUZZER_COMMON})
  target_compile_options(icc_applyprofiles_row_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_applyprofiles_row_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_applyprofiles_row_fuzzer PRIVATE ${FUZZER_INCLUDES} ${TIFF_INCLUDE_DIRS})
  target_link_libraries(icc_applyprofiles_row_fuzzer IccConnect2-static IccProfLib2 ${TIFF_LIBRARIES})

  # ApplySearch fuzzer
  add_executable(icc_applysearch_fuzzer icc_applysearch_fuzzer.cpp)
  if(CFL_SANITIZER STREQUAL "thread")
    target_compile_definitions(icc_applysearch_fuzzer PRIVATE CFL_APPLYSEARCH_THREADED=1)
  endif()
  target_compile_options(icc_applysearch_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_applysearch_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_applysearch_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_applysearch_fuzzer IccConnect2-static IccProfLib2)

  # ApplySearch weight-focused variant
  add_executable(icc_applysearch_weight_fuzzer icc_applysearch_weight_fuzzer.cpp)
  if(CFL_SANITIZER STREQUAL "thread")
    target_compile_definitions(icc_applysearch_weight_fuzzer PRIVATE CFL_APPLYSEARCH_THREADED=1)
  endif()
  target_compile_options(icc_applysearch_weight_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_applysearch_weight_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_applysearch_weight_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_applysearch_weight_fuzzer IccConnect2-static IccProfLib2)

  # IccConnect library fuzzer
  if(TARGET IccConnect2-static)
    add_executable(icc_connect_fuzzer icc_connect_fuzzer.cpp)
    target_compile_options(icc_connect_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
    target_link_options(icc_connect_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
    target_include_directories(icc_connect_fuzzer PRIVATE ${FUZZER_INCLUDES})
    target_link_libraries(icc_connect_fuzzer IccConnect2-static IccProfLib2)
  endif()

  # IccJSON library fuzzers
  if(TARGET IccJSON2-static)
    add_executable(icc_fromjson_fuzzer icc_fromjson_fuzzer.cpp)
    target_compile_options(icc_fromjson_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
    target_link_options(icc_fromjson_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
    target_include_directories(icc_fromjson_fuzzer PRIVATE ${FUZZER_INCLUDES})
    target_link_libraries(icc_fromjson_fuzzer IccJSON2-static IccProfLib2)

    add_executable(icc_tojson_fuzzer icc_tojson_fuzzer.cpp)
    target_compile_options(icc_tojson_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
    target_link_options(icc_tojson_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
    target_include_directories(icc_tojson_fuzzer PRIVATE ${FUZZER_INCLUDES})
    target_link_libraries(icc_tojson_fuzzer IccJSON2-static IccProfLib2)
  endif()

  # JSON Config fuzzer (IccCmmConfig.cpp + IccJsonUtil.cpp compiled in -- not in shared lib)
  set(CFG_FUZZER_SOURCES
    icc_cfg_fuzzer.cpp
    ${CMAKE_SOURCE_DIR}/../../IccConnect/IccLibConnect/IccCmmConfig.cpp
    ${CMAKE_SOURCE_DIR}/../../IccConnect/IccLibConnect/IccJsonUtil.cpp
  )
  add_executable(icc_cfg_fuzzer ${CFG_FUZZER_SOURCES})
  target_compile_options(icc_cfg_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_cfg_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_cfg_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_cfg_fuzzer IccProfLib2)

  # XML-based fuzzers (require IccXML)
  if(TARGET IccXML2)
    # FromXML fuzzer
    add_executable(icc_fromxml_fuzzer icc_fromxml_fuzzer.cpp)
    target_compile_options(icc_fromxml_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
    target_link_options(icc_fromxml_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
    target_include_directories(icc_fromxml_fuzzer PRIVATE ${FUZZER_INCLUDES})
    target_link_libraries(icc_fromxml_fuzzer IccProfLib2 IccXML2 xml2)

    # ToXML fuzzer
    add_executable(icc_toxml_fuzzer icc_toxml_fuzzer.cpp)
    target_compile_options(icc_toxml_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
    target_link_options(icc_toxml_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
    target_include_directories(icc_toxml_fuzzer PRIVATE ${FUZZER_INCLUDES})
    target_link_libraries(icc_toxml_fuzzer IccProfLib2 IccXML2 xml2)
  endif()

  # TIFF-based fuzzers (require TIFF)
  if(TIFF_FOUND)
    add_executable(icc_specsep_fuzzer icc_specsep_fuzzer.cpp ${TIFF_FUZZER_COMMON})
    target_compile_options(icc_specsep_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
    target_link_options(icc_specsep_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
    target_include_directories(icc_specsep_fuzzer PRIVATE ${FUZZER_INCLUDES} ${TIFF_INCLUDE_DIRS})
    target_link_libraries(icc_specsep_fuzzer IccProfLib2 ${TIFF_LIBRARIES})

    add_executable(icc_tiffdump_fuzzer icc_tiffdump_fuzzer.cpp ${TIFF_FUZZER_COMMON})
    target_compile_options(icc_tiffdump_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
    target_link_options(icc_tiffdump_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
    target_include_directories(icc_tiffdump_fuzzer PRIVATE ${FUZZER_INCLUDES} ${TIFF_INCLUDE_DIRS})
    target_link_libraries(icc_tiffdump_fuzzer IccProfLib2 ${TIFF_LIBRARIES})
  endif()

  message(STATUS "Fuzzing harnesses configured:")
  message(STATUS "  Core: proflib, v5dspobs, roundtrip, dump, link, fromcube, profilevisualize (7)")
  message(STATUS "  Apply: applynamedcmm, applyprofiles, applyprofiles-row, applysearch, applysearch-weight (5)")
  if(TARGET IccConnect2-static)
    message(STATUS "  Connect: connect (1)")
  endif()
  message(STATUS "  Config: cfg (1)")
  if(TARGET IccJSON2-static)
    message(STATUS "  JSON: fromjson, tojson (2)")
  endif()
  if(TARGET IccXML2)
    message(STATUS "  XML: fromxml, toxml (2)")
  endif()
  if(TIFF_FOUND)
    message(STATUS "  TIFF: specsep, tiffdump (2)")
  endif()
else()
  message(STATUS "Fuzzing disabled (requires Clang and -DENABLE_FUZZING=ON)")
endif()
