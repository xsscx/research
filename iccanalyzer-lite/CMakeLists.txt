cmake_minimum_required(VERSION 3.10)
project(iccAnalyzer-lite VERSION 2.9.0 LANGUAGES CXX)

# C++17 required
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build with ASAN + UBSAN + Coverage (matching iccDEV)
set(ICCANALYZER_LITE ON)

# iccDEV subproject path
set(ICCDEV_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/iccDEV")
set(ICCDEV_BUILD "${ICCDEV_ROOT}/Build")

# Find required libraries
find_package(LibXml2 REQUIRED)

# Source files
set(SOURCES
    iccAnalyzer-lite.cpp
    IccAnalyzerConfig.cpp
    IccAnalyzerErrors.cpp
    IccAnalyzerSecurity.cpp
    IccAnalyzerSignatures.cpp
    IccAnalyzerValidation.cpp
    IccAnalyzerComprehensive.cpp
    IccAnalyzerInspect.cpp
    IccAnalyzerNinja.cpp
    IccAnalyzerLUT.cpp
    IccAnalyzerXMLExport.cpp
    IccAnalyzerCallGraph.cpp
    IccAnalyzerTagDetails.cpp
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
    ssl
    crypto
    z
    gcov
)

# Compile definitions
target_compile_definitions(iccAnalyzer-lite PRIVATE ICCANALYZER_LITE)

# ASAN + UBSAN + Coverage flags (matching iccDEV build)
target_compile_options(iccAnalyzer-lite PRIVATE
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
    -g
    -O1
    -fprofile-arcs
    -ftest-coverage
    --coverage
)

target_link_options(iccAnalyzer-lite PRIVATE
    -fsanitize=address,undefined
    -fprofile-arcs
    --coverage
    "LINKER:--allow-multiple-definition"
)
