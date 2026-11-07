#include "repl_compiler_api.hpp"
#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <map>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

// Dependency notices are plain files in licenses\ beside shgrep.exe; shgrep --license prints them without this DLL.

extern "C" __declspec(dllexport) int __cdecl shgrep_compiler_entry_v1(
    uint32_t abi, uint32_t operation, char* error, size_t capacity) noexcept {
    if (error && capacity) error[0] = '\0';
    const auto failure = [&](const char* message) noexcept {
        if (error && capacity) {
            const size_t length = std::min(std::strlen(message), capacity - 1);
            std::memcpy(error, message, length);
            error[length] = '\0';
        }
        return 1;
    };
    if (!error || !capacity) return 1;
    if (abi != shgrep::compiler_api::version)
        return failure("incompatible shgrep-compiler.dll ABI; use files from the same build");
    try {
        if (operation == shgrep::compiler_api::worker)
            return shgrep::run_compiler_worker();
        return failure("unsupported shgrep compiler operation");
    } catch (const std::exception& exception) {
        return failure(exception.what());
    } catch (...) {
        return failure("shgrep compiler backend threw a non-standard exception");
    }
}
