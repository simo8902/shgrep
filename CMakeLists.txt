cmake_minimum_required(VERSION 3.20)
project(shgrep LANGUAGES C CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "shgrep requires native Windows x64")
endif()

# The distributable executable links both project code and Hyperscan to the static MSVC runtime.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

# COMPAT: Hyperscan's CMake passes no instruction-set flags to MSVC, and its fat runtime needs GCC ifunc, so a
# plain MSVC build compiles only the SSSE3 paths. /arch:AVX2 defines __AVX2__ (and __AVX__), which enables
# Hyperscan's AVX2, BMI2 and POPCNT code. Only the Hyperscan subdirectory gets the flag; shgrep's own code stays
# baseline so it can report an unsupported CPU instead of faulting.
set(SHGREP_HS_ARCH "AVX2" CACHE STRING "Instruction set for the bundled Hyperscan: AVX2, AVX512, or SSE")
set_property(CACHE SHGREP_HS_ARCH PROPERTY STRINGS AVX2 AVX512 SSE)
if(NOT SHGREP_HS_ARCH MATCHES "^(AVX2|AVX512|SSE)$")
    message(FATAL_ERROR "SHGREP_HS_ARCH must be AVX2, AVX512, or SSE")
endif()
# Hyperscan caches its CPU feature tests; rerun them when the target instruction set changes.
if(NOT SHGREP_HS_ARCH STREQUAL "${SHGREP_HS_ARCH_CONFIGURED}")
    unset(HAVE_AVX2 CACHE)
    unset(HAVE_AVX512 CACHE)
    unset(HAVE_AVX512VBMI CACHE)
    set(SHGREP_HS_ARCH_CONFIGURED "${SHGREP_HS_ARCH}" CACHE INTERNAL "")
endif()
# Chimera (Hyperscan prefilter + PCRE confirmation) adds backreferences, lookaround and other PCRE-only syntax to
# text search. It builds when PCRE 8.41+ source is present; Hyperscan's pcre.cmake builds it statically.
set(SHGREP_HYPERSCAN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libs/hyperscan-5.4.2")
set(SHGREP_DEFAULT_PCRE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/libs/pcre-8.45")
set(SHGREP_PCRE_SOURCE "${SHGREP_DEFAULT_PCRE_SOURCE}" CACHE PATH "PCRE 8.41+ source tree for Chimera")
# A cached path from before the move to libs/ would silently disable Chimera; fall back to the default.
if(NOT EXISTS "${SHGREP_PCRE_SOURCE}/pcre.h.generic" AND EXISTS "${SHGREP_DEFAULT_PCRE_SOURCE}/pcre.h.generic")
    set(SHGREP_PCRE_SOURCE "${SHGREP_DEFAULT_PCRE_SOURCE}" CACHE PATH "PCRE 8.41+ source tree for Chimera" FORCE)
endif()
if(EXISTS "${SHGREP_PCRE_SOURCE}/pcre.h.generic")
    set(PCRE_SOURCE "${SHGREP_PCRE_SOURCE}" CACHE PATH "" FORCE)
    set(PCRE_SUPPORT_UTF ON CACHE BOOL "" FORCE)
    set(PCRE_SUPPORT_UNICODE_PROPERTIES ON CACHE BOOL "" FORCE)
    # PERF: Chimera studies every pattern with PCRE_STUDY_JIT_COMPILE.
    set(PCRE_SUPPORT_JIT ON CACHE BOOL "" FORCE)
    set(PCRE_STATIC_RUNTIME ON CACHE BOOL "" FORCE)
    set(PCRE_BUILD_PCRECPP OFF CACHE BOOL "" FORCE)
    set(PCRE_BUILD_PCREGREP OFF CACHE BOOL "" FORCE)
    set(PCRE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
endif()
set(SHGREP_SAVED_C_FLAGS "${CMAKE_C_FLAGS}")
set(SHGREP_SAVED_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
if(MSVC AND SHGREP_HS_ARCH STREQUAL "AVX2")
    string(APPEND CMAKE_C_FLAGS " /arch:AVX2")
    string(APPEND CMAKE_CXX_FLAGS " /arch:AVX2")
elseif(MSVC AND SHGREP_HS_ARCH STREQUAL "AVX512")
    string(APPEND CMAKE_C_FLAGS " /arch:AVX512")
    string(APPEND CMAKE_CXX_FLAGS " /arch:AVX512")
endif()
add_subdirectory("${SHGREP_HYPERSCAN_DIR}" hyperscan-5.4.2 EXCLUDE_FROM_ALL)
set(CMAKE_C_FLAGS "${SHGREP_SAVED_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${SHGREP_SAVED_CXX_FLAGS}")

file(READ "${SHGREP_HYPERSCAN_DIR}/COPYING" HYPERSCAN_LICENSE_TEXT)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(src/license.hpp.in "${CMAKE_CURRENT_BINARY_DIR}/generated/license.hpp" @ONLY)

add_executable(shgrep src/main.cpp src/cli.cpp src/json.cpp src/search.cpp)
target_compile_features(shgrep PRIVATE cxx_std_20)
target_include_directories(shgrep PRIVATE "${SHGREP_HYPERSCAN_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}/generated")
# ntdll provides NtCreateFile for opening entries relative to their parent directory handle.
target_link_libraries(shgrep PRIVATE hs ntdll)
if(TARGET chimera)
    target_link_libraries(shgrep PRIVATE chimera pcre)
    target_include_directories(shgrep PRIVATE "${SHGREP_HYPERSCAN_DIR}/chimera")
    target_compile_definitions(shgrep PRIVATE SHGREP_CHIMERA)
else()
    message(STATUS "shgrep: PCRE source not found at ${SHGREP_PCRE_SOURCE}; building without backreference/lookaround support")
endif()
target_compile_definitions(shgrep PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
if(NOT SHGREP_HS_ARCH STREQUAL "SSE")
    target_compile_definitions(shgrep PRIVATE SHGREP_HS_${SHGREP_HS_ARCH})
endif()
if(MSVC)
    target_compile_options(shgrep PRIVATE /W4 /permissive- /utf-8)
endif()

install(TARGETS shgrep RUNTIME DESTINATION . COMPONENT shgrep)
