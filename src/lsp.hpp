#pragma once
#include "files.hpp"
#include <shared_mutex>
#include <stdexcept>
#include <utility>

namespace shgrep {
// A language-server transport/protocol failure, configuration error, or request timeout after readiness.
// Caller mistakes (bad arguments, unknown symbol) stay std::runtime_error.
struct LspFailure : std::runtime_error {
    using std::runtime_error::runtime_error;
};
struct LspTimeoutFailure : LspFailure {
    using LspFailure::LspFailure;
};
// A semantic request reached its deadline while this server was starting or indexing.
// details is the MCP structuredContent object and also crosses the C++ REPL bridge.
struct IndexWarmingFailure : std::runtime_error {
    Json details;
    IndexWarmingFailure(std::string message, Json value)
        : std::runtime_error(std::move(message)), details(std::move(value)) {}
};
// A semantic lookup could not be resolved because of backend state or a genuine name-path miss.
// details carries the reason and any ranked candidates through MCP structuredContent and the C++ REPL.
struct SymbolLookupFailure : std::runtime_error {
    Json details;
    SymbolLookupFailure(std::string message, Json value)
        : std::runtime_error(std::move(message)), details(std::move(value)) {}
};
// CONTRACT: every LspFailure reaches the model through this banner, which tells it to relay the failure to the
//   user at once; fallback says what the output below it is (text matches, a plain read) or that there is none.
std::string lsp_failure_banner(const std::string& detail, const std::string& fallback);
// Resolve the direct LSP deadline without starting a server. Explicit top-level and nested values must agree.
int64_t lsp_request_timeout_ms(const Json& arguments, const SearchContext& context,
                               const std::shared_ptr<std::atomic_bool>& cancelled);
// Shared navigation, refactoring and lifecycle backend for the existing tool surface.
// root: the configured root that owns path (SourceText::root). Its .shgrep/lsp.json is the one server selection loads,
// so extensions claimed there count; an empty root checks only the built-in lists.
bool lsp_required(const std::filesystem::path& path, const std::filesystem::path& root);
// A code file that read_file serves only through LSP: lsp_required minus markup and data formats such as XML.
bool lsp_read_required(const std::filesystem::path& path, const std::filesystem::path& root);
std::string lsp_fallback_reason(const SourceText& source, const Json& arguments, const SearchContext& context,
                                const std::shared_ptr<std::atomic_bool>& cancelled);
std::string require_text_access(const SourceText& source, const Json& arguments, const SearchContext& context,
                                const std::shared_ptr<std::atomic_bool>& cancelled);
bool lsp_configured(const SourceText& source, const SearchContext& context);
// Stable identity of configured server commands/settings/coverage; starts no backend.
// root: the configured root whose servers are fingerprinted (the meaning index covers one root).
std::string lsp_index_fingerprint(const SearchContext& context, const std::filesystem::path& root,
                                  const std::shared_ptr<std::atomic_bool>& cancelled);
// Size and last-write time of a file from its metadata, without opening it; empty for a folder, a link, or when
// unavailable. Only a cache key (the symbol and meaning indexes skip unchanged files with it); reads still go
// through read_source_text.
std::string lsp_file_stamp(const std::filesystem::path& path);
// Why source has no server although a bundled one serves its type (not installed, or turned off); empty when a
//   server is configured or no bundled server knows the type. Callers report it through lsp_failure_banner.
std::string lsp_missing(const SourceText& source, const SearchContext& context);
// Records the language of a file a tool result shows the model (list_dir, find_files, search). Per request thread.
void lsp_note_listed_file(std::string_view path);
// Forgets the files recorded on this thread; called when a request starts (pool threads are reused).
void lsp_clear_listed_files();
// After a tool call: one notice line per bundled server that is missing (or lacks its prerequisite, such as Roslyn's
//   .NET) for files the call listed, each server at most once per process; empty otherwise. Clears the recorded
//   files. Nothing is said at session start, and languages the model has not been shown are never mentioned (#101).
std::string lsp_language_notice(const SearchContext& context);
// Starts, on a background thread, the language servers for the languages the workspace (the first root) holds, so the
//   first semantic request does not wait for a cold start. Returns at once; failures are logged, and the first query
//   for that language reports them. Off with --read-only or SHGREP_LSP_WARMUP=0.
void start_language_servers(const SearchContext& context);
// Cancels the warm-up at shutdown, waiting at most 5 seconds for it.
void stop_language_server_warmup();
Json lsp_query(const std::string& operation, const Json& arguments, const SearchContext& context,
               const std::shared_ptr<std::atomic_bool>& cancelled);
// Outlines of many files at once, for the meaning index (#87): per language server, up to one documentSymbol request
// per hardware thread is in flight, and files opened for it are closed again. files[i] is {path, sha256, outline}
// with outline in the overview shape ({results: [symbol rows]}), or {path, error} when that file failed.
Json lsp_outlines(const std::vector<std::string>& paths, const SearchContext& context,
                  const std::shared_ptr<std::atomic_bool>& cancelled, int64_t timeout_ms);
Json lsp_edit(const Json& arguments, const SearchContext& context,
              const std::shared_ptr<std::atomic_bool>& cancelled);
Json lsp_move(const Json& arguments, const SearchContext& context,
              const std::shared_ptr<std::atomic_bool>& cancelled);
// Called after every filesystem mutation; failures are reported as post-write warnings.
void lsp_after_mutation(Json& result, const std::string& tool, const Json& arguments, const SearchContext& context,
                        const std::shared_ptr<std::atomic_bool>& cancelled);
std::shared_timed_mutex& workspace_operation_mutex();
}
