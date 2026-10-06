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
};

Json run_tool(const std::string& name, const Json& arguments,
              const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled);
Json tool_definitions();
}
