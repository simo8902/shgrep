#pragma once
#include "json.hpp"

#include <atomic>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace shgrep {
struct SearchContext {
    std::vector<std::filesystem::path> allowed_roots;
    // --read-only: the write tools (edit_file, write_file, move_file, create_directory) are neither listed nor run.
    bool read_only = false;
    // --live-index (MCP server): each root has a watched index, and searches use it unless they pass index: false.
    bool live_index = false;
};

// Runs any tool, search or file tool; throws std::runtime_error with a model-facing message on failure.
Json run_tool(const std::string& name, const Json& arguments,
              const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled);
// The search tools' definitions (search, search_bytes, find_files).
Json tool_definitions();
// Every tool this server exposes under context, for tools/list.
Json tool_list(const SearchContext& context);
bool tool_available(const std::string& name, const SearchContext& context);
// Builds or loads each root's index and starts watching it; returns at once, the work runs on background threads.
void start_live_indexes(const SearchContext& context);
}
