#pragma once
#include "search.hpp"
#include <chrono>

namespace shgrep {
// Explicit workspace-configured command checks, independent of language-server availability.
Json external_diagnostics(const std::string& kind, const Json& arguments, const SearchContext& context,
    std::chrono::steady_clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled);
}
