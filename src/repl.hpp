#pragma once
#include "json.hpp"
#include <atomic>
#include <memory>
#include <string>

namespace shgrep {
struct SearchContext;
struct ReplState;
// Internal modes of the same executable; worker sessions remain separate processes.
int run_repl_worker();
int pack_runtime_data(int argc, wchar_t** argv);
std::shared_ptr<ReplState> make_repl_state();
Json run_repl(const Json& arguments, const SearchContext& context,
              const std::shared_ptr<std::atomic_bool>& cancelled);
Json repl_tool_definition();
Json lsp_tool_definition();
Json run_lsp_tool(const Json& arguments, const SearchContext& context,
                  const std::shared_ptr<std::atomic_bool>& cancelled);
// Runtime tool guidance shared by MCP startup and on-demand help; no project state is stored.
std::string tool_manual(const SearchContext& context, bool brief);
Json fallback_tool_definitions(const SearchContext& context);
Json fallback_arguments(const std::string& name, const Json& arguments, const SearchContext& context);
}
