cmake_minimum_required(VERSION 3.10)
project(iccAnalyzer-lite VERSION 3.5.0 LANGUAGES CXX)

# C++17 required
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# iccDEV subproject path
set(ICCDEV_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/iccDEV")
set(ICCDEV_BUILD "${ICCDEV_ROOT}/Build")

# Find required libraries
find_package(LibXml2 REQUIRED)

# Source files (must match build.sh SOURCES — 23 files)
set(SOURCES
    iccAnalyzer-lite.cpp
    IccAnalyzerConfig.cpp
    IccAnalyzerErrors.cpp
    IccAnalyzerSecurity.cpp
    IccAnalyzerPathValidation.cpp
    IccHeuristicsRawPost.cpp
    IccHeuristicsLibrary.cpp
    IccHeuristicsTagValidation.cpp
    IccHeuristicsDataValidation.cpp
    IccHeuristicsProfileCompliance.cpp
    IccHeuristicsIntegrity.cpp
    IccHeuristicsHeader.cpp
    IccAnalyzerSignatures.cpp
    IccAnalyzerValidation.cpp
    IccAnalyzerComprehensive.cpp
    IccAnalyzerInspect.cpp
    IccAnalyzerNinja.cpp
    IccAnalyzerLUT.cpp
    IccAnalyzerXMLExport.cpp
    IccAnalyzerCallGraph.cpp
    IccAnalyzerTagDetails.cpp
    IccImageAnalyzer.cpp
    IccAnalyzerJson.cpp
)

# Build executable
add_executable(iccAnalyzer-lite ${SOURCES})

# Include directories
target_include_directories(iccAnalyzer-lite PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${ICCDEV_ROOT}/IccProfLib
    ${ICCDEV_ROOT}/IccXML/IccLibXML
    ${LIBXML2_INCLUDE_DIR}
)

# Link libraries (use instrumented static libraries from iccDEV)
target_link_libraries(iccAnalyzer-lite
    ${ICCDEV_BUILD}/IccProfLib/libIccProfLib2-static.a
    ${ICCDEV_BUILD}/IccXML/libIccXML2-static.a
    ${LIBXML2_LIBRARIES}
    tiff
    ssl
    crypto
    z
    lzma
    m
)

# Compile definitions (matching build.sh)
target_compile_definitions(iccAnalyzer-lite PRIVATE
    ICCANALYZER_LITE
    DEBUG
    ICC_LOG_SAFE
    ICC_TRACE_NAN_ENABLED
)

# Debug + Sanitizer + Coverage flags (matching build.sh exactly)
target_compile_options(iccAnalyzer-lite PRIVATE
    -g3
    -O0
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
    -fno-common
    -fstack-protector-strong
    -fsanitize=address,undefined
    -fsanitize=float-divide-by-zero
    -fsanitize=float-cast-overflow
    -fsanitize=integer
    -fsanitize-recover=address,undefined
    -fprofile-instr-generate
    -fcoverage-mapping
    -Wall
    -Wextra
    -Wno-unused-parameter
)

target_link_options(iccAnalyzer-lite PRIVATE
    -fsanitize=address,undefined
    -fprofile-instr-generate
    "LINKER:--allow-multiple-definition"
)
