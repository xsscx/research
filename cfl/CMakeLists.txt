# Fuzzing Harnesses for iccDEV
# CFL Branch - Complete LibFuzzer Integration with Full Instrumentation

cmake_minimum_required(VERSION 3.15)

# Only build fuzzers with Clang and when explicitly enabled
if(ENABLE_FUZZING AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(STATUS "Fuzzing harnesses enabled with full instrumentation")
  
  # Common include directories
  set(FUZZER_INCLUDES
    ${CMAKE_SOURCE_DIR}/../../IccProfLib
    ${CMAKE_SOURCE_DIR}/../../IccXML/IccLibXML
    ${CMAKE_SOURCE_DIR}/../../Tools/CmdLine/IccCommon
    ${CMAKE_SOURCE_DIR}/../../Tools/CmdLine/IccApplyProfiles
  )
  
  # Full instrumentation flags: sanitizers, debug, profiling, coverage
  # Based on iccAnalyzer instrumented build configuration
  set(FUZZER_COMPILE_FLAGS
    -fsanitize=fuzzer,address,undefined
    -g                              # Full debug symbols
    -O1                             # Minimal optimization for fuzzing
    -fno-omit-frame-pointer         # Preserve frame pointers for stack traces
    -fprofile-instr-generate        # Clang instrumentation profiling
    -fcoverage-mapping              # Clang coverage mapping
  )
  
  set(FUZZER_LINK_FLAGS
    -fsanitize=fuzzer,address,undefined
    -fprofile-instr-generate        # Clang instrumentation profiling
  )
  
  # No additional link libraries needed - Clang provides runtime automatically
  
  # Core ICC profile fuzzer
  add_executable(icc_profile_fuzzer icc_profile_fuzzer.cpp)
  target_compile_options(icc_profile_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_profile_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_profile_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_profile_fuzzer IccProfLib2)
  
  # Calculator fuzzer
  add_executable(icc_calculator_fuzzer icc_calculator_fuzzer.cpp)
  target_compile_options(icc_calculator_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_calculator_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_calculator_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_calculator_fuzzer IccProfLib2)
  
  # V5 DSP/OBS fuzzer
  add_executable(icc_v5dspobs_fuzzer icc_v5dspobs_fuzzer.cpp)
  target_compile_options(icc_v5dspobs_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_v5dspobs_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_v5dspobs_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_v5dspobs_fuzzer IccProfLib2)
  
  # Multitag fuzzer
  add_executable(icc_multitag_fuzzer icc_multitag_fuzzer.cpp)
  target_compile_options(icc_multitag_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_multitag_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_multitag_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_multitag_fuzzer IccProfLib2)
  
  # Roundtrip fuzzer
  add_executable(icc_roundtrip_fuzzer icc_roundtrip_fuzzer.cpp)
  target_compile_options(icc_roundtrip_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_roundtrip_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_roundtrip_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_roundtrip_fuzzer IccProfLib2)
  
  # Dump fuzzer
  add_executable(icc_dump_fuzzer icc_dump_fuzzer.cpp)
  target_compile_options(icc_dump_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_dump_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_dump_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_dump_fuzzer IccProfLib2)
  
  # IO fuzzer
  add_executable(icc_io_fuzzer icc_io_fuzzer.cpp)
  target_compile_options(icc_io_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_io_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_io_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_io_fuzzer IccProfLib2)
  
  # Link fuzzer
  add_executable(icc_link_fuzzer icc_link_fuzzer.cpp)
  target_compile_options(icc_link_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_link_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_link_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_link_fuzzer IccProfLib2)
  
  # Spectral fuzzer
  add_executable(icc_spectral_fuzzer icc_spectral_fuzzer.cpp)
  target_compile_options(icc_spectral_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_spectral_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_spectral_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_spectral_fuzzer IccProfLib2)
  
  # Apply fuzzer
  add_executable(icc_apply_fuzzer icc_apply_fuzzer.cpp)
  target_compile_options(icc_apply_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_apply_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_apply_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_apply_fuzzer IccProfLib2)
  
  # ApplyNamedCmm fuzzer
  add_executable(icc_applynamedcmm_fuzzer icc_applynamedcmm_fuzzer.cpp)
  target_compile_options(icc_applynamedcmm_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_applynamedcmm_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_applynamedcmm_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_applynamedcmm_fuzzer IccProfLib2)
  
  # ApplyProfiles fuzzer
  add_executable(icc_applyprofiles_fuzzer icc_applyprofiles_fuzzer.cpp)
  target_compile_options(icc_applyprofiles_fuzzer PRIVATE ${FUZZER_COMPILE_FLAGS})
  target_link_options(icc_applyprofiles_fuzzer PRIVATE ${FUZZER_LINK_FLAGS})
  target_include_directories(icc_applyprofiles_fuzzer PRIVATE ${FUZZER_INCLUDES})
  target_link_libraries(icc_applyprofiles_fuzzer IccProfLib2)
  
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
    # SpecSep and TiffDump fuzzers require TiffImg.cpp compilation
    # TODO: Add TiffImg.cpp to build or create separate TIFF tools library
    # 
    # add_executable(icc_specsep_fuzzer icc_specsep_fuzzer.cpp)
    # target_compile_options(icc_specsep_fuzzer PRIVATE -fsanitize=fuzzer,address,undefined -g -O1)
    # target_link_options(icc_specsep_fuzzer PRIVATE -fsanitize=fuzzer,address,undefined)
    # target_include_directories(icc_specsep_fuzzer PRIVATE ${FUZZER_INCLUDES})
    # target_link_libraries(icc_specsep_fuzzer IccProfLib2 ${TIFF_LIBRARIES})
    # 
    # add_executable(icc_tiffdump_fuzzer icc_tiffdump_fuzzer.cpp)
    # target_compile_options(icc_tiffdump_fuzzer PRIVATE -fsanitize=fuzzer,address,undefined -g -O1)
    # target_link_options(icc_tiffdump_fuzzer PRIVATE -fsanitize=fuzzer,address,undefined)
    # target_include_directories(icc_tiffdump_fuzzer PRIVATE ${FUZZER_INCLUDES})
    # target_link_libraries(icc_tiffdump_fuzzer IccProfLib2 ${TIFF_LIBRARIES})
  endif()
  
  message(STATUS "Fuzzing harnesses configured:")
  message(STATUS "  Core: profile, calculator, v5dspobs, multitag, roundtrip, dump, io, link, spectral (9)")
  message(STATUS "  Apply: apply, applynamedcmm, applyprofiles (3)")
  if(TARGET IccXML2)
    message(STATUS "  XML: fromxml, toxml (2)")
  endif()
  if(TIFF_FOUND)
    message(STATUS "  TIFF: specsep, tiffdump (disabled - requires TiffImg.cpp)")
  endif()
else()
  message(STATUS "Fuzzing disabled (requires Clang and -DENABLE_FUZZING=ON)")
endif()
