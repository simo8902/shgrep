#pragma once
#include "json.hpp"
#include "search.hpp"

#include <atomic>
#include <cstdint>
#include <chrono>
#include <memory>
#include <string>

namespace shgrep {
// Validated disk snapshots used to synchronize language servers, never a content cache.
struct SourceText {
    std::filesystem::path path, root;
    std::string text, sha256, mtime;
};
SourceText read_source_text(const SearchContext& context, const std::string& path);
// Resolve metadata without reading source; validates existing paths and all parent handles.
SourceText source_descriptor(const SearchContext& context, const std::string& path, bool* directory = nullptr,
                             bool allow_missing = false, bool* exists = nullptr);
struct SourceChange { SourceText before; std::string after; };
// Preflight every snapshot, stage replacements and recovery bytes, commit atomically per file.
// On a later failure, restore committed files when their bytes still match our replacement.
Json apply_source_changes(const std::vector<SourceChange>& changes, const Json& arguments,
                          const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled,
                          const Json* move_arguments = nullptr);
std::vector<std::string> source_paths(const SearchContext& context, const std::string& root,
    const std::vector<std::string>& extensions, std::chrono::steady_clock::time_point deadline,
    const std::shared_ptr<std::atomic_bool>& cancelled);

// File tools. Reading: read_file, list_dir, file_info. Writing: edit_file, write_file, move_file, create_directory.
// CONTRACT: every path is resolved below a configured root one component at a time; '..' cannot leave the root,
// and symbolic links and junctions below the root are refused, never followed.
bool is_file_tool(const std::string& name);
bool is_write_tool(const std::string& name);
Json run_file_tool(const std::string& name, const Json& arguments, const SearchContext& context,
                   const std::shared_ptr<std::atomic_bool>& cancelled);
// read_only leaves out the write tools.
Json file_tool_definitions(bool read_only);
}
