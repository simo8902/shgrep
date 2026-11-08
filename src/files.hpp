#pragma once
#include "json.hpp"
#include "search.hpp"

#include <atomic>
#include <cstdint>
#include <chrono>
#include <memory>
#include <functional>
#include <string_view>
#include <string>

namespace shgrep {
// CONTRACT: one absolute deadline per tool request. Each backend stage clamps its deadline with request_deadline,
//   so workspace waits, LSP work and commits share the budget. MCP response encoding shares it too, except for
//   a bounded grace period to deliver partial search results after a timeout.
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
    // root is the first configured root, where relative paths resolve. Otherwise only an absolute path names the
    // file: the same relative spelling would read the first root's copy.
    bool first_root = false;
};
SourceText read_source_text(const SearchContext& context, const std::string& path);
// The first max_bytes of a file (fewer when it is shorter), opened with the same checks; raw bytes, not decoded.
std::string read_source_head(const SearchContext& context, const std::string& path, size_t max_bytes);
std::string source_text_digest(std::string_view text);
// SHA-256 (hex) of a whole file's bytes, streamed; throws when the file cannot be read.
std::string file_sha256(const std::filesystem::path& path);
// Save a complete text result atomically under the first configured root; the reader supplies bounded chunks.
Json save_output_artifact(const SearchContext& context, const std::function<bool(std::string&)>& next,
                          const std::function<void()>& check);
void remember_read_snapshot(const SearchContext& context, const std::filesystem::path& path, const std::string& sha256);
void require_read_snapshot(const SearchContext& context, const std::filesystem::path& path,
                           const std::string& sha256, bool explicit_sha_guard);
void forget_read_snapshot(const SearchContext& context, const std::filesystem::path& path);
void forget_read_snapshots_under(const SearchContext& context, const std::filesystem::path& path);
// Generated build metadata uses the same root checks, no-link traversal and atomic replacement as file tools.
// Leaves an identical existing file untouched. Does not notify LSP about its own configuration files.
void write_workspace_metadata(const SearchContext& context, const std::filesystem::path& path,
                              const std::string& bytes);
// The metadata folder `path` and its missing parents, made with the same checks and no-link traversal.
void create_workspace_metadata_directory(const SearchContext& context, const std::filesystem::path& path);
// The metadata folder `path` and its missing parents, made as above and kept from being renamed, removed or replaced
// by a link (every component held open without delete sharing) until the returned pin is released.
std::shared_ptr<void> pin_workspace_metadata_directory(const SearchContext& context, const std::filesystem::path& path);
// The metadata file `path`, created or emptied, open for writing with the same checks and no-link traversal. The
// handle is inheritable (for a child process's output) and the caller closes it.
void* create_workspace_metadata_log(const SearchContext& context, const std::filesystem::path& path);
// Resolve metadata without reading source; validates existing paths and all parent handles.
SourceText source_descriptor(const SearchContext& context, const std::string& path, bool* directory = nullptr,
                             bool allow_missing = false, bool* exists = nullptr);
struct SourceChange {
    SourceText before;
    std::string after;
    // The caller matched every replaced byte as exact literal text in the current file (a literal old_text/needle),
    // so the edit cannot rest on a stale read; apply_source_changes then needs no earlier session read of the file.
    // The before-sha256 check at commit still applies.
    bool anchored = false;
};
// Preflight every snapshot, stage replacements and recovery bytes, commit atomically per file.
// On a later failure, restore committed files when their bytes still match our replacement.
Json apply_source_changes(const std::vector<SourceChange>& changes, const Json& arguments,
                          const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled,
                          const Json* move_arguments = nullptr);
// The folder of the running shgrep.exe; empty when Windows cannot report it.
std::filesystem::path executable_directory();
// The lowercase extension that selects a file's language server. A file named CMakeLists.txt counts as ".cmake".
std::string language_extension(const std::filesystem::path& path);
// Empty extensions selects all files; filter runs before opening files or entering subdirectories.
std::vector<std::string> source_paths(const SearchContext& context, const std::string& root,
    const std::vector<std::string>& extensions, std::chrono::steady_clock::time_point deadline,
    const std::shared_ptr<std::atomic_bool>& cancelled,
    const std::function<bool(const std::string&, bool)>& filter = {});

// Render semantic results for people without changing the structured values.
// symbol_text adds each symbol's line_text to outline rows (symbol searches).
std::string render_semantic_text(const Json& result, bool outline,
                                 const std::shared_ptr<std::atomic_bool>& cancelled, bool line_numbers = true,
                                 bool symbol_text = false);

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
