cmake_minimum_required(VERSION 3.25)
if(NOT DESTINATION OR NOT PACKER OR NOT EXISTS "${PACKER}")
    message(FATAL_ERROR "Set DESTINATION and PACKER to the built shgrep.exe")
endif()
file(MAKE_DIRECTORY "${DESTINATION}")
# Dependency notices ship as plain files in licenses\ beside shgrep.exe; shgrep --license prints them (src/cli.cpp).
set(notices "${DESTINATION}/licenses")
file(REMOVE_RECURSE "${notices}")
file(MAKE_DIRECTORY "${notices}/msvc" "${notices}/windows-sdk")
# Visual Studio's BuildTools\ folder holds a second copy of 1033\ThirdPartyNotices.txt (6 MB).
file(COPY "@SHGREP_VS_ROOT@/Licenses/" DESTINATION "${notices}/msvc" PATTERN "BuildTools" EXCLUDE)
file(COPY "@SHGREP_WINDOWS_SDK_ROOT@/Licenses/@SHGREP_WINDOWS_SDK_VERSION@/" DESTINATION "${notices}/windows-sdk")
file(COPY "@CMAKE_CURRENT_SOURCE_DIR@/third_party/" DESTINATION "${notices}")
file(COPY_FILE "@SHGREP_HYPERSCAN_DIR@/COPYING" "${notices}/hyperscan-COPYING.txt")
if(@SHGREP_PORTABLE_HAS_PCRE2@)
    file(COPY_FILE "@SHGREP_PCRE2_DIR@/LICENCE.md" "${notices}/pcre2-LICENCE.md")
endif()
# The guide and the LSP downloader are plain files too; fetch_command() in src/lsp.cpp looks for tools\fetch_lsp.py
# beside shgrep.exe, so this also replaces any stale copy left in a build folder.
file(COPY_FILE "@CMAKE_CURRENT_BINARY_DIR@/generated/portable-README.txt" "${DESTINATION}/README.txt")
file(MAKE_DIRECTORY "${DESTINATION}/tools")
file(COPY_FILE "@CMAKE_CURRENT_SOURCE_DIR@/tools/fetch_lsp.py" "${DESTINATION}/tools/fetch_lsp.py")
# shgrep.dat holds only what REPL cells compile against: Clang's builtin headers for x86. Headers for other CPUs,
# GPUs and offload languages are left out; no x86 header includes them (intrin.h includes the ARM ones only on ARM).
# LLVM's own headers are not packed: cells cannot link against LLVM, because shgrep-compiler.dll exports none of it.
set(headers "@CMAKE_CURRENT_BINARY_DIR@/repl-headers")
file(REMOVE_RECURSE "${headers}")
file(COPY "@SHGREP_LLVM_ROOT@/lib/clang/@LLVM_VERSION_MAJOR@/include/" DESTINATION "${headers}"
    PATTERN "cuda_wrappers" EXCLUDE PATTERN "openmp_wrappers" EXCLUDE PATTERN "ppc_wrappers" EXCLUDE
    PATTERN "llvm_libc_wrappers" EXCLUDE PATTERN "llvm_offload_wrappers" EXCLUDE PATTERN "zos_wrappers" EXCLUDE
    PATTERN "sanitizer" EXCLUDE PATTERN "xray" EXCLUDE PATTERN "fuzzer" EXCLUDE PATTERN "profile" EXCLUDE
    REGEX "/(altivec|amdgpuintrin|amdhsa_abi|andes_vector|arm[^/]*|gpuintrin|hexagon_[^/]*|htm[^/]*|hvx_[^/]*|larchintrin|lasxintrin|lsxintrin|msa|nvptxintrin|opencl-c[^/]*|ptrauth|riscv_[^/]*|s390intrin|sifive_vector|spirvintrin|vecintrin|velintrin[^/]*|wasm_simd128|__clang_(cuda|hip|spirv|gpu)_[^/]*)\\.h$" EXCLUDE
    REGEX "/hlsl[^/]*$" EXCLUDE)
execute_process(COMMAND "${PACKER}" --pack-data "${DESTINATION}/shgrep.dat"
    "llvm/lib/clang/@LLVM_VERSION_MAJOR@/include" "${headers}"
    RESULT_VARIABLE packed_data ERROR_VARIABLE packing_error)
if(NOT packed_data EQUAL 0)
    message(FATAL_ERROR "Packing shgrep.dat failed (${packed_data}): ${packing_error}")
endif()
