#pragma once
#include "files.hpp"
#include <shared_mutex>

namespace shgrep {
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
