# Runs during the owner's normal build; the application keeps its clang-cl/MSVC ABI.
foreach(required IN ITEMS SHGREP_SOURCE_DIR SHGREP_BINARY_DIR SHGREP_REFLECTION_CXX)
    if(NOT DEFINED ${required})
        message(FATAL_ERROR "Missing ${required} for reflection generation")
    endif()
endforeach()
get_filename_component(compiler_bin "${SHGREP_REFLECTION_CXX}" DIRECTORY)
set(ENV{PATH} "${compiler_bin};$ENV{PATH}")
set(generator "${SHGREP_BINARY_DIR}/generated/shgrep-reflect.exe")
set(output "${SHGREP_BINARY_DIR}/generated/tool_contracts.generated.hpp")
file(MAKE_DIRECTORY "${SHGREP_BINARY_DIR}/generated")
execute_process(
    COMMAND "${SHGREP_REFLECTION_CXX}" -std=c++26 -freflection
        -DSHGREP_REFLECTION_GENERATOR -O0 -static -static-libgcc -static-libstdc++
        "-I${SHGREP_SOURCE_DIR}/src"
        "${SHGREP_SOURCE_DIR}/tools/generate_contracts.cpp"
        "${SHGREP_SOURCE_DIR}/src/json.cpp" -o "${generator}"
    RESULT_VARIABLE compiled OUTPUT_VARIABLE compiler_output ERROR_VARIABLE compiler_error
    TIMEOUT 600)
if(NOT compiled STREQUAL "0")
    message(FATAL_ERROR "Reflection generator compilation failed. GCC 16+ with <meta> is required.\n${compiler_output}\n${compiler_error}")
endif()
execute_process(COMMAND "${generator}" "${output}.tmp"
    RESULT_VARIABLE generated OUTPUT_VARIABLE generator_output ERROR_VARIABLE generator_error TIMEOUT 60)
if(NOT generated STREQUAL "0")
    file(REMOVE "${output}.tmp")
    message(FATAL_ERROR "Reflection generation failed; the previous header was kept.\n${generator_output}\n${generator_error}")
endif()
if(EXISTS "${output}")
    file(SHA256 "${output}" previous_hash)
    file(SHA256 "${output}.tmp" next_hash)
    if(previous_hash STREQUAL next_hash)
        file(REMOVE "${output}.tmp")
        return()
    endif()
endif()
# Publish by renaming the complete adjacent file, without truncating the existing header.
file(RENAME "${output}.tmp" "${output}" RESULT published)
if(NOT published STREQUAL "0")
    message(FATAL_ERROR "Cannot publish reflection header; the complete new file remains at ${output}.tmp: ${published}")
endif()
