#pragma once
#include "json.hpp"
#include "search.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace shgrep {
// read_file's default and largest max_output_bytes: room for a whole 64 MiB file after JSON escaping.
constexpr uint32_t read_file_max_output = 256u << 20;

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
