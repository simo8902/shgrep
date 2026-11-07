#pragma once
#include "files.hpp"
#include <cstddef>
#include <utility>
#include <vector>

namespace shgrep {
// Plan a change inside validated UTF-8 byte bounds; never reads or commits a file.
std::string scoped_content_edit(const SourceText& source, size_t begin, size_t end,
                                const Json& arguments, const std::shared_ptr<std::atomic_bool>& cancelled);
std::string outside_content_edit(const SourceText& source, const std::vector<std::pair<size_t, size_t>>& protected_ranges,
                                 const Json& arguments, const std::shared_ptr<std::atomic_bool>& cancelled);
// Serena content and line editing, planned from current bytes and committed through apply_source_changes.
Json content_edit(const Json& arguments, const SearchContext& context,
                  const std::shared_ptr<std::atomic_bool>& cancelled);
}
