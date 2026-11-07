#include "repl.hpp"
#include "repl_compiler_api.hpp"
#include "repl_ipc.hpp"
#include <windows.h>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace {
shgrep::compiler_api::Entry compiler_entry() {
    // Keep the module loaded for process lifetime, including TLS notifications.
    static const auto entry = [] {
        std::wstring executable(32768, L'\0');
        const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (!length || length >= executable.size())
            throw std::runtime_error("cannot locate shgrep-compiler.dll beside shgrep.exe");
        executable.resize(length);
        const auto path = std::filesystem::path(executable).parent_path() / L"shgrep-compiler.dll";
        const HMODULE module = LoadLibraryExW(path.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module)
            throw std::runtime_error("cannot load shgrep-compiler.dll beside shgrep.exe (Windows error " +
                std::to_string(GetLastError()) + "); keep the DLL from the same build beside the executable");
        const auto address = GetProcAddress(module, shgrep::compiler_api::entry_name);
        if (!address) {
            FreeLibrary(module); // No backend operation has started.
            throw std::runtime_error("incompatible shgrep-compiler.dll: missing versioned compiler entry point");
        }
        return reinterpret_cast<shgrep::compiler_api::Entry>(address);
    }();
    return entry;
}

int invoke_compiler(uint32_t operation) {
    char error[4096]{};
    const int result = compiler_entry()(shgrep::compiler_api::version, operation, error, sizeof(error));
    error[sizeof(error) - 1] = '\0';
    if (error[0]) throw std::runtime_error(error);
    return result;
}
}

int shgrep::run_repl_worker() {
    // Loader failures must use the worker protocol, not raw text on stdout.
    try {
        return invoke_compiler(compiler_api::worker);
    } catch (const std::exception& error) {
        try {
            repl_ipc::write(GetStdHandle(STD_OUTPUT_HANDLE), Json::Object{
                {"kind", "fatal"}, {"ok", false}, {"error", error.what()}});
        } catch (...) {}
        return 1;
    }
}


