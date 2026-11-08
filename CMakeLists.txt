# 3.25 is the first CMake that knows the cxx_std_26 compile feature.
cmake_minimum_required(VERSION 3.25)
project(shgrep LANGUAGES C CXX)

# shgrep's own code is C++26. CMake has no cxx_std_26 mode for clang-cl, and clang-cl's /std:c++latest goes past
# C++26 (__cplusplus 202700L), so clang-cl gets clang's exact flag (__cplusplus and _MSVC_LANG 202400L).
option(SHGREP_STL_HARDENING "Enable MSVC STL hardening for shgrep targets" ON)
option(SHGREP_ASAN "Instrument shgrep targets with AddressSanitizer (separate diagnostic build only)" OFF)
set(SHGREP_ASAN_RUNTIME_DLL "" CACHE FILEPATH "Matching compiler clang_rt.asan_dynamic-x86_64.dll for SHGREP_ASAN")
option(SHGREP_ZERO_INIT "Zero-initialize automatic variables in shgrep targets (measure before release)" OFF)
option(SHGREP_UNSAFE_BUFFER_WARNINGS "Report Clang unsafe-buffer warnings in shgrep targets" OFF)
option(SHGREP_THREAD_SAFETY_WARNINGS "Report Clang thread-safety warnings in shgrep targets" OFF)
option(SHGREP_CLANG_TIDY "Run the src-only clang-tidy checks while building shgrep targets" OFF)
if(SHGREP_ASAN OR SHGREP_ZERO_INIT OR SHGREP_UNSAFE_BUFFER_WARNINGS OR SHGREP_THREAD_SAFETY_WARNINGS)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "shgrep diagnostic options require Clang; dependencies keep their own flags")
    endif()
endif()
if(SHGREP_ASAN)
    if(NOT EXISTS "${SHGREP_ASAN_RUNTIME_DLL}")
        message(FATAL_ERROR "SHGREP_ASAN needs SHGREP_ASAN_RUNTIME_DLL: select clang_rt.asan_dynamic-x86_64.dll from the matching compiler installation")
    endif()
    get_filename_component(SHGREP_ASAN_RUNTIME_NAME "${SHGREP_ASAN_RUNTIME_DLL}" NAME)
    if(NOT SHGREP_ASAN_RUNTIME_NAME STREQUAL "clang_rt.asan_dynamic-x86_64.dll")
        message(FATAL_ERROR "SHGREP_ASAN_RUNTIME_DLL must name clang_rt.asan_dynamic-x86_64.dll from the matching compiler")
    endif()
endif()
if(SHGREP_CLANG_TIDY)
    get_filename_component(SHGREP_COMPILER_BIN "${CMAKE_CXX_COMPILER}" DIRECTORY)
    find_program(SHGREP_CLANG_TIDY_EXECUTABLE NAMES clang-tidy HINTS "${SHGREP_COMPILER_BIN}" REQUIRED)
endif()

function(shgrep_use_cxx26 target)
    if(MSVC AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${target} PRIVATE /clang:-std=c++26)
    else()
        target_compile_features(${target} PRIVATE cxx_std_26)
    endif()
    if(MSVC AND SHGREP_STL_HARDENING)
        target_compile_definitions(${target} PRIVATE _MSVC_STL_HARDENING=1)
    endif()
    # Apply only to the two owning targets, never globally or to linked third-party targets.
    set(diagnostic_flags)
    if(SHGREP_ASAN)
        list(APPEND diagnostic_flags -fsanitize=address)
        if(MSVC)
            target_link_options(${target} PRIVATE /INCREMENTAL:NO)
        else()
            target_link_options(${target} PRIVATE -fsanitize=address)
        endif()
        # shgrep runs as the header packer in an earlier post-build command, so its runtime
        # must already exist before linking completes, not in a later post-build command.
        add_custom_command(TARGET ${target} PRE_LINK
            COMMAND "${CMAKE_COMMAND}" -E make_directory "$<TARGET_FILE_DIR:${target}>"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${SHGREP_ASAN_RUNTIME_DLL}"
                "$<TARGET_FILE_DIR:${target}>/clang_rt.asan_dynamic-x86_64.dll"
            COMMENT "Staging the matching AddressSanitizer runtime" VERBATIM)
    endif()
    if(SHGREP_ZERO_INIT)
        list(APPEND diagnostic_flags -ftrivial-auto-var-init=zero)
    endif()
    if(SHGREP_UNSAFE_BUFFER_WARNINGS)
        list(APPEND diagnostic_flags -Wunsafe-buffer-usage -Wno-error=unsafe-buffer-usage)
    endif()
    if(SHGREP_THREAD_SAFETY_WARNINGS)
        list(APPEND diagnostic_flags -Wthread-safety -Wno-error=thread-safety)
    endif()
    foreach(flag IN LISTS diagnostic_flags)
        if(MSVC)
            target_compile_options(${target} PRIVATE "/clang:${flag}")
        else()
            target_compile_options(${target} PRIVATE "${flag}")
        endif()
    endforeach()
    if(SHGREP_CLANG_TIDY)
        set_property(TARGET ${target} PROPERTY CXX_CLANG_TIDY
            "${SHGREP_CLANG_TIDY_EXECUTABLE};--config-file=${CMAKE_CURRENT_SOURCE_DIR}/src/.clang-tidy")
    endif()
endfunction()

# Give language servers the same per-file flags and include paths as the build.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "shgrep requires native Windows x64")
endif()

# The distributable executable links project code, Hyperscan and PCRE2 to the static MSVC runtime.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
# The compiler backend shares the release LLVM SDK ABI in every configuration.
add_compile_definitions(_ITERATOR_DEBUG_LEVEL=0)
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
# Chimera (Hyperscan + PCRE1) is no longer used; PCRE2 is linked directly below. Clear PCRE1 settings an older
# configure may have cached, or Hyperscan's pcre.cmake would still try to build the removed PCRE1 tree.
unset(PCRE_SOURCE CACHE)
unset(SHGREP_PCRE_SOURCE CACHE)
unset(CORRECT_PCRE_VERSION CACHE)
unset(PCRE_CHECKED CACHE)

set(SHGREP_HYPERSCAN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libs/hyperscan-5.4.2")
# Hyperscan needs only Boost's headers; the in-tree copy serves a fresh configure without a system Boost.
set(BOOST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/libs/boost-1.92.0" CACHE PATH "Boost headers for Hyperscan")
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

# PCRE2 with JIT runs the patterns Hyperscan rejects (backreferences, lookaround, \b in Unicode mode). It is the
# engine ripgrep uses for -P. Built statically, 8-bit only, with Unicode support; no tools or tests.
set(SHGREP_PCRE2_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libs/pcre2-10.49" CACHE PATH "PCRE2 source tree")
if(EXISTS "${SHGREP_PCRE2_DIR}/CMakeLists.txt")
    set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_PCRE2_8 ON CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_PCRE2_16 OFF CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_PCRE2_32 OFF CACHE BOOL "" FORCE)
    set(PCRE2_SUPPORT_JIT ON CACHE BOOL "" FORCE)
    set(PCRE2_SUPPORT_UNICODE ON CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_PCRE2GREP OFF CACHE BOOL "" FORCE)
    set(PCRE2_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(PCRE2_SHOW_REPORT OFF CACHE BOOL "" FORCE)
    add_subdirectory("${SHGREP_PCRE2_DIR}" pcre2 EXCLUDE_FROM_ALL)
endif()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")

# The compiler DLL contains LLVM/Clang/LLD; shgrep.exe retains the server and packer.
set(SHGREP_LLVM_ROOT "C:/llvm23.1.4" CACHE PATH "LLVM 23.1 development SDK")
find_package(LLVM 23.1 REQUIRED CONFIG PATHS "${SHGREP_LLVM_ROOT}/lib/cmake/llvm" NO_DEFAULT_PATH)
find_package(Clang REQUIRED CONFIG PATHS "${SHGREP_LLVM_ROOT}/lib/cmake/clang" NO_DEFAULT_PATH)
find_package(LLD REQUIRED CONFIG PATHS "${SHGREP_LLVM_ROOT}/lib/cmake/lld" NO_DEFAULT_PATH)
if(NOT LLVM_VERSION_MAJOR EQUAL 23 OR NOT TARGET clangInterpreter)
    message(FATAL_ERROR "shgrep's C++ REPL requires an LLVM 23 SDK with clangInterpreter")
endif()
# LLVM Windows release packages can retain the build machine's DIA SDK path.
get_target_property(SHGREP_PDB_LIBRARIES LLVMDebugInfoPDB INTERFACE_LINK_LIBRARIES)
foreach(SHGREP_PDB_LIBRARY IN LISTS SHGREP_PDB_LIBRARIES)
    if(SHGREP_PDB_LIBRARY MATCHES "[Dd][Ii][Aa][Gg][Uu][Ii][Dd][Ss]\\.lib$" AND NOT EXISTS "${SHGREP_PDB_LIBRARY}")
        string(REGEX REPLACE "/VC/Tools/MSVC/.*" "" SHGREP_VS_ROOT "${CMAKE_CXX_COMPILER}")
        find_library(SHGREP_DIA_LIBRARY NAMES diaguids
            HINTS "${SHGREP_VS_ROOT}/DIA SDK/lib/amd64" "$ENV{VSINSTALLDIR}/DIA SDK/lib/amd64"
            REQUIRED)
        list(TRANSFORM SHGREP_PDB_LIBRARIES REPLACE "^${SHGREP_PDB_LIBRARY}$" "${SHGREP_DIA_LIBRARY}")
        set_property(TARGET LLVMDebugInfoPDB PROPERTY INTERFACE_LINK_LIBRARIES "${SHGREP_PDB_LIBRARIES}")
    endif()
endforeach()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS src/json.hpp src/json.cpp src/repl_cpp.hpp)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/json.hpp" SHGREP_REPL_JSON_HEADER)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/json.cpp" SHGREP_REPL_JSON_SOURCE)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/repl_cpp.hpp" SHGREP_REPL_CPP_HEADER)
string(REPLACE "#pragma once" "" SHGREP_REPL_JSON_HEADER "${SHGREP_REPL_JSON_HEADER}")
string(REPLACE "#include \"json.hpp\"" "" SHGREP_REPL_JSON_SOURCE "${SHGREP_REPL_JSON_SOURCE}")
string(REPLACE "#pragma once" "" SHGREP_REPL_CPP_HEADER "${SHGREP_REPL_CPP_HEADER}")
string(REPLACE "#include \"json.hpp\"" "" SHGREP_REPL_CPP_HEADER "${SHGREP_REPL_CPP_HEADER}")
configure_file(src/repl_prelude.hpp.in "${CMAKE_CURRENT_BINARY_DIR}/generated/repl_prelude.hpp" @ONLY)
add_executable(shgrep src/main.cpp src/log_window.cpp src/cli.cpp src/json.cpp src/search.cpp src/ignore.cpp src/files.cpp
               src/backend.cpp src/teddy.cpp src/dfa.cpp src/lsp.cpp src/dotnet_projects.cpp src/compile_db.cpp src/lsp_watch.cpp
               src/workspace_profile.cpp
               src/rank.cpp src/embed.cpp src/meaning.cpp src/edit.cpp src/repl.cpp src/repl_compiler_loader.cpp src/external_diagnostics.cpp
               tools/pack_repl_headers.cpp)
# The executable has no LLVM link dependency. Only isolated REPL workers load this backend, through its
# versioned C entry point.
add_library(shgrep_compiler SHARED src/repl_compiler_backend.cpp src/repl_worker.cpp
            src/repl_headers_vfs.cpp src/repl_dll_executor.cpp src/json.cpp)
set_target_properties(shgrep_compiler PROPERTIES OUTPUT_NAME "shgrep-compiler"
    WINDOWS_EXPORT_ALL_SYMBOLS OFF MSVC_RUNTIME_LIBRARY MultiThreaded)
shgrep_use_cxx26(shgrep_compiler)
target_include_directories(shgrep_compiler SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
target_include_directories(shgrep_compiler PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(shgrep_compiler PRIVATE _WIN32_WINNT=0x0602 NDEBUG
    UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(shgrep_compiler PRIVATE clangInterpreter LLVMWindowsDriver lldCOFF lldCommon Cabinet bcrypt)
add_dependencies(shgrep shgrep_compiler)
target_compile_definitions(shgrep PRIVATE _WIN32_WINNT=0x0602 NDEBUG)
set_property(TARGET shgrep PROPERTY MSVC_RUNTIME_LIBRARY MultiThreaded)
target_link_options(shgrep PRIVATE "/SUBSYSTEM:CONSOLE,6.02")
if(MSVC)
    set_source_files_properties(src/repl_worker.cpp src/repl_headers_vfs.cpp src/repl_dll_executor.cpp PROPERTIES COMPILE_OPTIONS "/GR-")
    # Keep the existing compiler-runtime exports with their owning backend.
    set(SHGREP_REPL_EXPORTS
        malloc free calloc realloc __acrt_iob_func
        "__security_cookie,DATA" __security_check_cookie
        "??_7type_info@@6B@,DATA"
        "?__type_info_root_node@@3U__type_info_node@@A,DATA"
        "?nothrow@std@@3Unothrow_t@1@B,DATA"
        _Init_thread_abort "_Init_thread_epoch,DATA" _Init_thread_footer _Init_thread_header "_tls_index,DATA"
        "??2@YAPEAX_K@Z" "??3@YAXPEAX@Z" "??_U@YAPEAX_K@Z" "??_V@YAXPEAX@Z" "??3@YAXPEAX_K@Z"
        "?__POW10_SPLIT_2@std@@3QAY02$$CB_KA,DATA"
        "?__POW10_SPLIT@std@@3QAY02$$CB_KA,DATA"
        "?__DOUBLE_POW5_SPLIT@std@@3QAY01$$CB_KA,DATA"
        "?__DOUBLE_POW5_INV_SPLIT@std@@3QAY01$$CB_KA,DATA"
        "?_Large_power_data@std@@3QBIB,DATA")
    list(TRANSFORM SHGREP_REPL_EXPORTS PREPEND "LINKER:SHELL:/EXPORT:")
    target_link_options(shgrep_compiler PRIVATE ${SHGREP_REPL_EXPORTS}
        "LINKER:/MAP:${CMAKE_CURRENT_BINARY_DIR}/shgrep-compiler.map")
endif()

# Package Clang/LLVM resources and notices; discover MSVC and the Windows SDK
# on the target PC. Record the host toolset family for /MT ABI compatibility.
# cl.exe sits in <MSVC root>/bin/Hostx64/x64. clang-cl sits elsewhere and uses the toolset of the Visual Studio
# developer prompt it runs in, which that prompt names in VCToolsInstallDir.
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    get_filename_component(SHGREP_COMPILER_DIRECTORY "${CMAKE_CXX_COMPILER}" DIRECTORY)
    get_filename_component(SHGREP_DETECTED_MSVC_ROOT "${SHGREP_COMPILER_DIRECTORY}/../../.." ABSOLUTE)
else()
    file(TO_CMAKE_PATH "$ENV{VCToolsInstallDir}" SHGREP_DETECTED_MSVC_ROOT)
    string(REGEX REPLACE "/+$" "" SHGREP_DETECTED_MSVC_ROOT "${SHGREP_DETECTED_MSVC_ROOT}")
endif()
set(SHGREP_MSVC_ROOT "${SHGREP_DETECTED_MSVC_ROOT}" CACHE PATH "MSVC toolset matching the worker ABI")
get_filename_component(SHGREP_MSVC_VERSION "${SHGREP_MSVC_ROOT}" NAME)
if(NOT SHGREP_MSVC_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR "Set SHGREP_MSVC_ROOT to the versioned VC/Tools/MSVC directory used for the host")
endif()
target_compile_definitions(shgrep_compiler PRIVATE "SHGREP_REPL_MSVC_VERSION=\"${SHGREP_MSVC_VERSION}\"")
# The packed Clang resource directory is named after the LLVM major version.
target_compile_definitions(shgrep_compiler PRIVATE "SHGREP_LLVM_VERSION_MAJOR=\"${LLVM_VERSION_MAJOR}\"")
# Retain notices for the Microsoft runtime code linked into shgrep.exe.
# These build-machine paths are used only for notices, never target discovery.
string(REGEX REPLACE "/VC/Tools/MSVC/.*" "" SHGREP_VS_ROOT "${SHGREP_MSVC_ROOT}")
set(SHGREP_WINDOWS_SDK_ROOT "$ENV{WindowsSdkDir}" CACHE PATH "Windows SDK root for license notices")
if(NOT SHGREP_WINDOWS_SDK_ROOT)
    set(SHGREP_WINDOWS_SDK_ROOT "C:/Program Files (x86)/Windows Kits/10" CACHE PATH "Windows SDK root for license notices" FORCE)
endif()
file(TO_CMAKE_PATH "${SHGREP_WINDOWS_SDK_ROOT}" SHGREP_WINDOWS_SDK_ROOT)
set(SHGREP_WINDOWS_SDK_VERSION "$ENV{WindowsSDKVersion}" CACHE STRING "Windows SDK version for license notices")
string(REGEX REPLACE "[/\\\\]+$" "" SHGREP_WINDOWS_SDK_VERSION "${SHGREP_WINDOWS_SDK_VERSION}")
if(NOT SHGREP_WINDOWS_SDK_VERSION)
    file(GLOB SHGREP_SDK_VERSIONS RELATIVE "${SHGREP_WINDOWS_SDK_ROOT}/Include" "${SHGREP_WINDOWS_SDK_ROOT}/Include/10.*")
    list(SORT SHGREP_SDK_VERSIONS COMPARE NATURAL ORDER DESCENDING)
    list(GET SHGREP_SDK_VERSIONS 0 SHGREP_WINDOWS_SDK_VERSION)
endif()
set(SHGREP_WINDOWS_SDK_INCLUDE "${SHGREP_WINDOWS_SDK_ROOT}/Include/${SHGREP_WINDOWS_SDK_VERSION}")
set(SHGREP_PORTABLE_HAS_PCRE2 OFF)
if(TARGET pcre2-8-static)
    set(SHGREP_PORTABLE_HAS_PCRE2 ON)
endif()
configure_file(tools/stage_repl_runtime.cmake "${CMAKE_CURRENT_BINARY_DIR}/generated/stage_repl_runtime.cmake" @ONLY)
configure_file(tools/package_portable.cmake "${CMAKE_CURRENT_BINARY_DIR}/generated/package_portable.cmake" @ONLY)
configure_file(tools/portable-README.txt.in "${CMAKE_CURRENT_BINARY_DIR}/generated/portable-README.txt" @ONLY)
add_custom_command(TARGET shgrep POST_BUILD
    COMMAND "${CMAKE_COMMAND}" "-DDESTINATION=$<TARGET_FILE_DIR:shgrep>"
        "-DPACKER=$<TARGET_FILE:shgrep>"
        -P "${CMAKE_CURRENT_BINARY_DIR}/generated/stage_repl_runtime.cmake"
    COMMENT "Packing shgrep.dat" VERBATIM)
# Preserve the explicit data-refresh target without a dependency cycle.
add_custom_target(repl_runtime
    COMMAND "${CMAKE_COMMAND}" "-DDESTINATION=$<TARGET_FILE_DIR:shgrep>"
        "-DPACKER=$<TARGET_FILE:shgrep>"
        -P "${CMAKE_CURRENT_BINARY_DIR}/generated/stage_repl_runtime.cmake"
    DEPENDS shgrep COMMENT "Packing shgrep.dat" VERBATIM)
set_property(TARGET shgrep APPEND PROPERTY LINK_DEPENDS
    "${CMAKE_CURRENT_BINARY_DIR}/generated/stage_repl_runtime.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/portable-README.txt")
add_custom_target(portable_zip
    COMMAND "${CMAKE_COMMAND}" "-DMAIN_EXE=$<TARGET_FILE:shgrep>"
        "-DCOMPILER_DLL=$<TARGET_FILE:shgrep_compiler>" "-DCONFIG=$<CONFIG>"
        -P "${CMAKE_CURRENT_BINARY_DIR}/generated/package_portable.cmake"
    DEPENDS shgrep COMMENT "Packaging shgrep.exe, shgrep-compiler.dll and shgrep.dat" VERBATIM)
shgrep_use_cxx26(shgrep)

# Real C++26 reflection runs in a separate native Windows generator.
# Only portable generated C++ reaches the application and its existing LLVM/MSVC ABI.
set(SHGREP_REFLECTION_CXX "${CMAKE_CURRENT_SOURCE_DIR}/toolchains/mingw64/bin/g++.exe"
    CACHE FILEPATH "GCC 16+ compiler with C++26 reflection and matching libstdc++ <meta>")
if(NOT EXISTS "${SHGREP_REFLECTION_CXX}")
    message(FATAL_ERROR "Install GCC 16+ under toolchains/mingw64, or set SHGREP_REFLECTION_CXX to its g++.exe")
endif()
set(SHGREP_CONTRACT_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated/tool_contracts.generated.hpp")
add_custom_command(OUTPUT "${SHGREP_CONTRACT_HEADER}"
    COMMAND "${CMAKE_COMMAND}"
        "-DSHGREP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
        "-DSHGREP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
        "-DSHGREP_REFLECTION_CXX=${SHGREP_REFLECTION_CXX}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_contracts.cmake"
    DEPENDS tools/generate_contracts.cpp tools/generate_contracts.cmake
        src/tool_contracts.hpp src/contract_codec.hpp src/json.hpp src/json.cpp "${SHGREP_REFLECTION_CXX}"
    BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/generated/shgrep-reflect.exe"
    COMMENT "Generating tool contracts using C++26 reflection" VERBATIM)
add_custom_target(shgrep_contracts DEPENDS "${SHGREP_CONTRACT_HEADER}")
add_dependencies(shgrep shgrep_contracts)
target_include_directories(shgrep PRIVATE "${SHGREP_HYPERSCAN_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}/generated")
# ntdll provides NtCreateFile for opening entries relative to their parent directory handle; bcrypt provides the
# SHA-256 that read_file reports and edit_file/write_file check with expected_sha256; advapi32 copies a replaced
# file's permissions onto its replacement.
target_link_libraries(shgrep PRIVATE hs ntdll bcrypt advapi32 winhttp Cabinet user32 gdi32 shell32)
if(TARGET pcre2-8-static)
    target_link_libraries(shgrep PRIVATE pcre2-8-static)
    target_compile_definitions(shgrep PRIVATE SHGREP_PCRE2 PCRE2_CODE_UNIT_WIDTH=8)
else()
    message(STATUS "shgrep: PCRE2 not found at ${SHGREP_PCRE2_DIR}; building without backreference/lookaround support")
endif()
target_compile_definitions(shgrep PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
if(NOT SHGREP_HS_ARCH STREQUAL "SSE")
    target_compile_definitions(shgrep PRIVATE SHGREP_HS_${SHGREP_HS_ARCH})
endif()
if(MSVC)
    target_compile_options(shgrep PRIVATE /W4 /permissive- /utf-8)
    target_compile_options(shgrep_compiler PRIVATE /W4 /permissive- /utf-8 /GR-)
endif()

# GPU build (issue #87, build 2): meaning search with an embedding model on an AMD GPU. shgrep.exe compiles against
# llama.cpp's headers only and loads llama.dll, ggml*.dll and the GGUF at runtime from its own folder, so the
# portable parts start without them; a missing DLL, GPU or model fails ranked search with the exact cause.
#   SHGREP_LLAMA_ROOT        llama.cpp source tree (headers): include/llama.h, ggml/include/ggml.h
#   SHGREP_LLAMA_BIN         its HIP build output: llama.dll, ggml.dll, ggml-base.dll, ggml-cpu.dll, ggml-hip.dll
#   SHGREP_EMBED_MODEL_FILE  optional GGUF, copied beside shgrep.exe as embedding.gguf
option(SHGREP_EMBED "Build the GPU meaning-search build (needs SHGREP_LLAMA_ROOT and SHGREP_LLAMA_BIN)" OFF)
set(SHGREP_LLAMA_ROOT "C:/llama.cpp-0.9.0" CACHE PATH "llama.cpp source tree for SHGREP_EMBED")
set(SHGREP_LLAMA_BIN "${SHGREP_LLAMA_ROOT}/build-hip/bin" CACHE PATH "llama.cpp HIP DLL folder for SHGREP_EMBED")
set(SHGREP_EMBED_MODEL_FILE "" CACHE FILEPATH "GGUF embedding model copied beside shgrep.exe as embedding.gguf")
if(SHGREP_EMBED)
    if(NOT EXISTS "${SHGREP_LLAMA_ROOT}/include/llama.h" OR NOT EXISTS "${SHGREP_LLAMA_ROOT}/ggml/include/ggml.h")
        message(FATAL_ERROR "SHGREP_EMBED needs llama.cpp headers: set SHGREP_LLAMA_ROOT (now: ${SHGREP_LLAMA_ROOT})")
    endif()
    set(SHGREP_LLAMA_DLLS llama.dll ggml.dll ggml-base.dll ggml-cpu.dll ggml-hip.dll)
    set(SHGREP_LLAMA_DLL_PATHS "")
    foreach(SHGREP_LLAMA_DLL IN LISTS SHGREP_LLAMA_DLLS)
        if(NOT EXISTS "${SHGREP_LLAMA_BIN}/${SHGREP_LLAMA_DLL}")
            message(FATAL_ERROR "SHGREP_EMBED needs ${SHGREP_LLAMA_DLL} in SHGREP_LLAMA_BIN (now: ${SHGREP_LLAMA_BIN})")
        endif()
        list(APPEND SHGREP_LLAMA_DLL_PATHS "${SHGREP_LLAMA_BIN}/${SHGREP_LLAMA_DLL}")
    endforeach()
    target_compile_definitions(shgrep PRIVATE SHGREP_EMBED=1)
    target_include_directories(shgrep SYSTEM PRIVATE "${SHGREP_LLAMA_ROOT}/include" "${SHGREP_LLAMA_ROOT}/ggml/include")
    add_custom_command(TARGET shgrep POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${SHGREP_LLAMA_DLL_PATHS} "$<TARGET_FILE_DIR:shgrep>"
        COMMENT "shgrep: copying the llama.cpp DLLs beside shgrep.exe")
    install(FILES ${SHGREP_LLAMA_DLL_PATHS} DESTINATION . COMPONENT shgrep)
    if(SHGREP_EMBED_MODEL_FILE)
        if(NOT EXISTS "${SHGREP_EMBED_MODEL_FILE}")
            message(FATAL_ERROR "SHGREP_EMBED_MODEL_FILE does not exist: ${SHGREP_EMBED_MODEL_FILE}")
        endif()
        add_custom_command(TARGET shgrep POST_BUILD
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${SHGREP_EMBED_MODEL_FILE}" "$<TARGET_FILE_DIR:shgrep>/embedding.gguf"
            COMMENT "shgrep: copying the embedding model beside shgrep.exe")
        install(FILES "${SHGREP_EMBED_MODEL_FILE}" DESTINATION . RENAME embedding.gguf COMPONENT shgrep)
    endif()
endif()

# ThinLTO optimizes and drops unused code across shgrep and the LLVM libraries at link time. An LLVM SDK built with
# LLVM_ENABLE_LTO=Thin ships bitcode libraries, which only lld-link can link, so this needs clang-cl and lld-link.
option(SHGREP_THINLTO "Build shgrep with ThinLTO (requires clang-cl and lld-link)" OFF)
if(SHGREP_THINLTO)
    if(NOT MSVC OR NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "SHGREP_THINLTO requires clang-cl as CMAKE_C_COMPILER and CMAKE_CXX_COMPILER")
    endif()
    if(NOT CMAKE_LINKER MATCHES "lld-link(\\.exe)?$")
        message(FATAL_ERROR "SHGREP_THINLTO requires CMAKE_LINKER set to lld-link.exe (now: ${CMAKE_LINKER})")
    endif()
    foreach(SHGREP_LTO_TARGET IN ITEMS shgrep shgrep_compiler)
        target_compile_options(${SHGREP_LTO_TARGET} PRIVATE -flto=thin)
        target_link_options(${SHGREP_LTO_TARGET} PRIVATE
            "/lldltocache:${CMAKE_CURRENT_BINARY_DIR}/thinlto-cache/${SHGREP_LTO_TARGET}" /opt:lldltojobs=all)
    endforeach()
endif()

# Profile-guided optimization for shgrep.exe (search, LSP and file tools; not the REPL compiler DLL). Three builds:
#   1. -DSHGREP_PGO=GENERATE: shgrep.exe records which code runs. Use it normally with
#      LLVM_PROFILE_FILE=<folder>\shgrep-%p.profraw set for the MCP server; each process writes one file when it exits.
#   2. llvm-profdata merge -o <SHGREP_PGO_PROFILE> <folder>\*.profraw
#   3. -DSHGREP_PGO=USE: rebuild with that profile. Code changed since the profile only loses its tuning.
set(SHGREP_PGO "" CACHE STRING "Profile-guided optimization for shgrep.exe: empty (off), GENERATE or USE")
set_property(CACHE SHGREP_PGO PROPERTY STRINGS "" GENERATE USE)
set(SHGREP_PGO_PROFILE "${CMAKE_CURRENT_SOURCE_DIR}/pgo/shgrep.profdata" CACHE FILEPATH "Merged profile for SHGREP_PGO=USE")
if(SHGREP_PGO)
    if(NOT MSVC OR NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "SHGREP_PGO requires clang-cl as CMAKE_C_COMPILER and CMAKE_CXX_COMPILER")
    endif()
    if(SHGREP_PGO STREQUAL "GENERATE")
        # The instrumented code calls the profile runtime, which LLVM ships only when compiler-rt was built.
        execute_process(COMMAND "${CMAKE_CXX_COMPILER}" /clang:-print-resource-dir
                        OUTPUT_VARIABLE SHGREP_CLANG_RESOURCE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
        set(SHGREP_PGO_RUNTIME "${SHGREP_CLANG_RESOURCE_DIR}/lib/windows/clang_rt.profile-x86_64.lib")
        if(NOT EXISTS "${SHGREP_PGO_RUNTIME}")
            message(FATAL_ERROR "SHGREP_PGO=GENERATE needs ${SHGREP_PGO_RUNTIME}. Build compiler-rt's profile runtime "
                                "into this LLVM: add -DLLVM_ENABLE_RUNTIMES=compiler-rt to its CMake configure and "
                                "install again")
        endif()
        target_compile_options(shgrep PRIVATE -fprofile-instr-generate)
        target_link_libraries(shgrep PRIVATE "${SHGREP_PGO_RUNTIME}")
    elseif(SHGREP_PGO STREQUAL "USE")
        if(NOT EXISTS "${SHGREP_PGO_PROFILE}")
            message(FATAL_ERROR "SHGREP_PGO=USE needs the merged profile ${SHGREP_PGO_PROFILE}; set SHGREP_PGO_PROFILE")
        endif()
        # Functions changed or added since the profile simply get no profile data; that is not an error.
        target_compile_options(shgrep PRIVATE "-fprofile-instr-use=${SHGREP_PGO_PROFILE}"
                               -Wno-profile-instr-unprofiled -Wno-profile-instr-out-of-date -Wno-backend-plugin)
        # A new profile recompiles shgrep's sources.
        get_target_property(SHGREP_PGO_SOURCES shgrep SOURCES)
        set_property(SOURCE ${SHGREP_PGO_SOURCES} APPEND PROPERTY OBJECT_DEPENDS "${SHGREP_PGO_PROFILE}")
    else()
        message(FATAL_ERROR "SHGREP_PGO must be empty, GENERATE or USE (now: ${SHGREP_PGO})")
    endif()
endif()

target_compile_definitions(shgrep PRIVATE "SHGREP_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")

# The Roslyn server payload is supplied by the official dotnet tool installation.
set(SHGREP_ROSLYN_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.local-tools/.store/roslyn-language-server/5.13.0-1.26514.10/roslyn-language-server.win-x64/5.13.0-1.26514.10/tools/net10.0/win-x64" CACHE PATH "Roslyn language server payload")
if(EXISTS "${SHGREP_ROSLYN_ROOT}/Microsoft.CodeAnalysis.LanguageServer.exe")
    add_custom_target(deploy_roslyn ALL
        COMMAND "${CMAKE_COMMAND}" -E copy_directory "${SHGREP_ROSLYN_ROOT}" "$<TARGET_FILE_DIR:shgrep>/lsp/csharp/roslyn"
        COMMAND "${CMAKE_COMMAND}" -E copy_directory "${SHGREP_ROSLYN_ROOT}" "${CMAKE_CURRENT_SOURCE_DIR}/dist/lsp/csharp/roslyn"
        DEPENDS shgrep COMMENT "Staging Roslyn language server" VERBATIM)
    install(DIRECTORY "${SHGREP_ROSLYN_ROOT}/" DESTINATION lsp/csharp/roslyn COMPONENT shgrep)
else()
    message(STATUS "shgrep: Roslyn payload not found; set SHGREP_ROSLYN_ROOT to enable C# support")
endif()

set(SHGREP_DEPLOY
    "${CMAKE_CURRENT_SOURCE_DIR}/dist/shgrep.exe"
)
# The GPU build runs from its own build folder, beside its DLLs and model; dist/ keeps the portable build.
if(SHGREP_EMBED OR SHGREP_ASAN)
    set(SHGREP_DEPLOY "")
endif()
if(SHGREP_DEPLOY)
    string(REPLACE ";" "\n" SHGREP_DEPLOY_LINES "${SHGREP_DEPLOY}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/deploy-targets.txt" "${SHGREP_DEPLOY_LINES}\n")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/deploy-data-targets.txt" "${CMAKE_CURRENT_SOURCE_DIR}/dist/shgrep.dat\n")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/deploy-compiler-targets.txt" "${CMAKE_CURRENT_SOURCE_DIR}/dist/shgrep-compiler.dll\n")
    add_custom_target(deploy ALL
        COMMAND "${CMAKE_COMMAND}" "-DSOURCE=$<TARGET_FILE:shgrep>" "-DTARGETS_FILE=${CMAKE_CURRENT_BINARY_DIR}/deploy-targets.txt"
                "-DDATA_SOURCE=$<TARGET_FILE_DIR:shgrep>/shgrep.dat"
                "-DDATA_TARGETS_FILE=${CMAKE_CURRENT_BINARY_DIR}/deploy-data-targets.txt"
                "-DCOMPILER_SOURCE=$<TARGET_FILE:shgrep_compiler>"
                "-DCOMPILER_TARGETS_FILE=${CMAKE_CURRENT_BINARY_DIR}/deploy-compiler-targets.txt"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tools/deploy.cmake"
        COMMENT "Deploying shgrep.exe, shgrep-compiler.dll and shgrep.dat" VERBATIM)
    add_dependencies(deploy shgrep)
endif()

if(SHGREP_ASAN)
    install(CODE "message(FATAL_ERROR \"AddressSanitizer builds are diagnostic-only; build a normal release for installation\")" COMPONENT shgrep)
endif()
install(TARGETS shgrep RUNTIME DESTINATION . COMPONENT shgrep)
# Install the DLL file explicitly, excluding its build-only import library.
install(FILES "$<TARGET_FILE:shgrep_compiler>" "$<TARGET_FILE_DIR:shgrep>/shgrep.dat"
        "$<TARGET_FILE_DIR:shgrep>/README.txt" DESTINATION . COMPONENT shgrep)
# stage_repl_runtime.cmake writes these plain files beside shgrep.exe on every build.
install(FILES "$<TARGET_FILE_DIR:shgrep>/tools/fetch_lsp.py" DESTINATION tools COMPONENT shgrep)
install(DIRECTORY "$<TARGET_FILE_DIR:shgrep>/licenses" DESTINATION . COMPONENT shgrep)
