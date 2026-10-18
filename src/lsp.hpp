#pragma once
#include "files.hpp"
#include <shared_mutex>
#include <stdexcept>

namespace shgrep {
// A language server failed: it did not start, crashed, broke protocol, timed out, had not finished indexing, or
// .shgrep/lsp.json is invalid. Caller mistakes (bad arguments, unknown symbol) stay std::runtime_error.
struct LspFailure : std::runtime_error {
    using std::runtime_error::runtime_error;
};
// CONTRACT: every LspFailure reaches the model through this banner, which tells it to relay the failure to the
//   user at once; fallback says what the output below it is (text matches, a plain read) or that there is none.
std::string lsp_failure_banner(const std::string& detail, const std::string& fallback);
// Shared navigation, refactoring and lifecycle backend for the existing tool surface.
bool lsp_configured(const SourceText& source, const SearchContext& context);
Json lsp_query(const std::string& operation, const Json& arguments, const SearchContext& context,
               const std::shared_ptr<std::atomic_bool>& cancelled);
Json lsp_edit(const Json& arguments, const SearchContext& context,
              const std::shared_ptr<std::atomic_bool>& cancelled);
Json lsp_move(const Json& arguments, const SearchContext& context,
              const std::shared_ptr<std::atomic_bool>& cancelled);
// Called after every filesystem mutation; failures are reported as post-write warnings.
void lsp_after_mutation(Json& result, const std::string& tool, const Json& arguments, const SearchContext& context,
                        const std::shared_ptr<std::atomic_bool>& cancelled);
std::shared_timed_mutex& workspace_operation_mutex();
}
