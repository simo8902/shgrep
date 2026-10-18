#pragma once
#include "json.hpp"
#include "search.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>

namespace shgrep {
// How the bundled clangd learns each workspace's compile flags, with nothing for the user to add.
struct CompileSetup {
    std::string fingerprint;  // changes exactly when clangd must restart with new flags
    Json initialization;      // clangd initializationOptions
    Json status;              // reported by file_info operation=lsp
};
// CONTRACT: existing workspace databases are combined per file (the root database wins conflicts, then newest).
//   Otherwise use a background CMake configure (cmake_enabled, Visual Studio found), a database generated
//   from .vcxproj files, then fallback flags that put every header folder on the include path.
//   Generated files live only under
//   <root>\.shgrep\lsp-state\cpp; read_only workspaces combine existing commands in memory or use fallback flags.
// PERF: rescans at most every 10 seconds per root; a finished background configure is picked up by a later call.
CompileSetup cpp_compile_setup(const std::filesystem::path& root, const SearchContext& context, bool cmake_enabled);
}
