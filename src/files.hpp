#pragma once
#include "json.hpp"
#include "search.hpp"

#include <atomic>
#include <cstdint>
#include <chrono>
#include <memory>
#include <string>

namespace shgrep {
// CONTRACT: one absolute deadline per tool request (timeout_ms from when run_tool received it). Each stage clamps its
//   own deadline with request_deadline, so locking, LSP work and commits together never outlast the request.
std::chrono::steady_clock::time_point request_deadline(std::chrono::steady_clock::time_point stage);
class RequestDeadline {
public:
    explicit RequestDeadline(std::chrono::steady_clock::time_point deadline);
    ~RequestDeadline();
    RequestDeadline(const RequestDeadline&) = delete;
    RequestDeadline& operator=(const RequestDeadline&) = delete;

private:
    bool had_previous_;
    std::chrono::steady_clock::time_point previous_;
};

// Validated disk snapshots used to synchronize language servers, never a content cache.
struct SourceText {
    std::filesystem::path path, root;
    std::string text, sha256, mtime;
};
SourceText read_source_text(const SearchContext& context, const std::string& path);
// Generated build metadata uses the same root checks, no-link traversal and atomic replacement as file tools.
// Leaves an identical existing file untouched. Does not notify LSP about its own configuration files.
void write_workspace_metadata(const SearchContext& context, const std::filesystem::path& path,
                              const std::string& bytes);
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
