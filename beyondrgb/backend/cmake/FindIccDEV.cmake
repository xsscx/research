# FindIccDEV.cmake — builds IccProfLib2-static from iccDEV submodule
#
# Drop into backend/cmake/ and include() from backend/CMakeLists.txt.
# The iccDEV submodule must be at: backend/submodules/iccDEV
#
# Usage:
#   include(${CMAKE_CURRENT_LIST_DIR}/cmake/FindIccDEV.cmake)
#   target_link_libraries(myTarget PRIVATE IccProfLib2-static)
#   # Then: #include "IccProfile.h"

include_guard(GLOBAL)

get_filename_component(BACKEND_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(ICCDEV_SUBMODULE_DIR "${BACKEND_ROOT}/submodules/iccDEV")

if(NOT EXISTS "${ICCDEV_SUBMODULE_DIR}/IccProfLib/IccProfile.h")
    message(FATAL_ERROR
        "iccDEV submodule not found at ${ICCDEV_SUBMODULE_DIR}\n"
        "Run: git submodule update --init --recursive"
    )
endif()

# Variables expected by iccDEV's CMakeLists
set(ENABLE_SHARED_LIBS OFF CACHE BOOL "Build shared iccDEV libs" FORCE)
set(ENABLE_STATIC_LIBS ON  CACHE BOOL "Build static iccDEV libs" FORCE)
set(ENABLE_INSTALL_RIM OFF CACHE BOOL "Skip iccDEV install targets" FORCE)
set(PROJECT_UP_NAME "REFICCMAX")
set(REFICCMAX_VERSION "2.3.1.5")
set(REFICCMAX_MAJOR_VERSION "2")

add_subdirectory(
    "${ICCDEV_SUBMODULE_DIR}/Build/Cmake/IccProfLib"
    "${CMAKE_CURRENT_BINARY_DIR}/IccProfLib"
)

# Fix missing PUBLIC include propagation in upstream CMake
target_include_directories(IccProfLib2-static PUBLIC
    "$<BUILD_INTERFACE:${ICCDEV_SUBMODULE_DIR}/IccProfLib>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/IccProfLib>"
)

message(STATUS "iccDEV IccProfLib2-static ready (${REFICCMAX_VERSION})")
