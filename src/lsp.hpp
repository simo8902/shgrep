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
bool lsp_required(const std::filesystem::path& path);
// A code file that read_file serves only through LSP: lsp_required minus markup and data formats such as XML.
bool lsp_read_required(const std::filesystem::path& path);
std::string lsp_fallback_reason(const SourceText& source, const Json& arguments, const SearchContext& context,
                                const std::shared_ptr<std::atomic_bool>& cancelled);
std::string require_text_access(const SourceText& source, const Json& arguments, const SearchContext& context,
                                const std::shared_ptr<std::atomic_bool>& cancelled);
bool lsp_configured(const SourceText& source, const SearchContext& context);
// Why source has no server although a bundled one serves its type (not installed, or turned off); empty when a
//   server is configured or no bundled server knows the type. Callers report it through lsp_failure_banner.
std::string lsp_missing(const SourceText& source, const SearchContext& context);
// Problems with the bundled servers: not installed beside shgrep.exe, or missing what they need (Roslyn's .NET).
//   Starts nothing, so it is cheap enough for the session health check.
std::vector<std::string> lsp_health();
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
