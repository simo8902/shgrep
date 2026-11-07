// Serena-style facade/session/result behavior adapted to native C++; see third_party/solidlsp-LICENSE.txt.
#include "repl.hpp"
#include "files.hpp"
#include "lsp.hpp"
#include "embed.hpp"
#include "repl_ipc.hpp"
#include <thread>
#include <bcrypt.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cctype>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>

namespace shgrep {
namespace {
using J = Json;
using Clock = std::chrono::steady_clock;
constexpr size_t max_code = 256 * 1024, max_sessions = 8;
constexpr size_t max_value_bytes = 256ull << 20;
[[noreturn]] void fail(const std::string& message) { throw std::runtime_error(message); }
std::string string_arg(const J& args, const char* key, const std::string& fallback = {}) {
    const J* value = args.get(key);
    return value ? value->string() : fallback;
}
std::string path_text(const std::filesystem::path& path) {
    const auto text = path.generic_u8string();
    return {reinterpret_cast<const char*>(text.data()), text.size()};
}
size_t value_bytes(const J& root, size_t limit = max_value_bytes) {
    struct Pending { const J* value; unsigned depth; };
    std::vector<Pending> pending{{&root, 0}};
    size_t bytes = 0, nodes = 0;
    const auto add = [&](size_t amount) {
        if (amount > limit || bytes > limit - amount) fail("REPL value exceeds its memory limit; select smaller results");
        bytes += amount;
    };
    while (!pending.empty()) {
        const auto next = pending.back(); pending.pop_back();
        if (next.depth > 64 || ++nodes > 1000000) fail("REPL value exceeds nesting/element limits");
        const auto push = [&](const J& value) {
            if (nodes + pending.size() >= 1000000) fail("REPL value exceeds one million elements");
            pending.push_back({&value, next.depth + 1});
        };
        if (const auto* text = std::get_if<std::string>(&next.value->value)) add(J::escaped_size(*text));
        else if (const auto* array = std::get_if<J::Array>(&next.value->value)) {
            add(2 + (array->empty() ? 0 : array->size() - 1));
            for (const auto& value : *array) push(value);
        } else if (const auto* object = std::get_if<J::Object>(&next.value->value)) {
            add(2 + (object->empty() ? 0 : object->size() - 1));
            for (const auto& [key, value] : *object) { add(J::escaped_size(key) + 1); push(value); }
        } else add(next.value->dump().size());
    }
    return bytes;
}
struct Control {
    Clock::time_point deadline;
    std::shared_ptr<std::atomic_bool> cancelled;
    void check() const {
        if (cancelled && cancelled->load()) fail("REPL request cancelled");
        if (Clock::now() >= deadline) fail("REPL request timed out");
    }
};

const std::map<std::string, J>& backend_definitions() {
    static const auto definitions = [] {
        std::map<std::string, J> out;
        const J search = tool_definitions(), files = file_tool_definitions(false);
        for (const J* group : {&search, &files})
            for (const auto& tool : group->array()) out.emplace(tool.get("name")->string(), tool);
        return out;
    }();
    return definitions;
}
void erase_properties(J& definition, std::initializer_list<const char*> keys) {
    auto& schema = std::get<J::Object>(std::get<J::Object>(definition.value).at("inputSchema").value);
    auto& properties = std::get<J::Object>(schema.at("properties").value);
    for (const char* key : keys) properties.erase(key);
}
void operations(J& definition, J::Array allowed, const std::string& description) {
    auto& object = std::get<J::Object>(definition.value);
    auto& schema = std::get<J::Object>(object.at("inputSchema").value);
    auto& properties = std::get<J::Object>(schema.at("properties").value);
    properties["operation"] = J::Object{{"type", "string"}, {"enum", std::move(allowed)}};
    object["description"] = description;
}
J fallback_definition(const std::string& name) {
    const auto it = backend_definitions().find(name);
    if (it == backend_definitions().end()) fail("unknown fallback tool: " + name);
    J definition = it->second;
    if (name == "search") {
        erase_properties(definition, {"name_path", "include_body", "full_lines", "include_info", "depth", "include_kinds", "exclude_kinds",
            "substring_matching", "line", "column", "include_declaration", "allow_text_fallback"});
        if (embed_built())
            operations(definition, {"text", "meaning"}, "Search any file, including source code, by literal or regex patterns without requiring LSP. Omit intent for exhaustive grep-style results; explicit limits can truncate results. Nonblank intent returns ranked hunks: 90% meaning from the GPU embedding model plus 10% BM25. operation=meaning with intent (a question in words, no pattern) returns the best-matching LSP symbols (path, line range, name_path) for lsp.read_symbol; optional path scope and max_results. Use the lsp tool for semantic navigation and symbol edits.");
        else
            operations(definition, {"text"}, "Search any file, including source code, by literal or regex patterns without requiring LSP. Omit intent for exhaustive grep-style results; explicit limits can truncate results. Nonblank intent returns ranked hunks using built-in BM25 and an optional local reranker. Use the lsp tool for semantic navigation and symbol edits.");
        auto& props = std::get<J::Object>(std::get<J::Object>(std::get<J::Object>(definition.value).at("inputSchema").value).at("properties").value);
        props["pattern"] = J::Object{{"type", "string"}, {"description", "One literal or regex pattern."}};
        props["patterns"] = J::Object{{"type", "array"}, {"items", J::Object{{"type", "string"}}},
                                      {"description", "Up to 1000 text patterns in one filesystem pass."}};
        props["intent"] = J::Object{{"type", "string"}, {"description", "Optional. Nonblank intent ranks results with built-in BM25 (an optional reranker, when running, reorders the top ones). Omit for regular exhaustive search."}};
    } else if (name == "search_bytes") {
        std::get<J::Object>(definition.value)["description"] =
            "Search raw file bytes using hex literals or byte regex, with exact byte offsets and optional hex context. "
            "Default mode=literal and output=json; files and count outputs are also available. "
            "Programming/XML files are searchable without a language server.";
    } else if (name == "find_files") {
        erase_properties(definition, {"allow_text_fallback", "path", "name_path", "pattern", "substring_matching", "include_kinds", "exclude_kinds"});
        operations(definition, {"filesystem"}, "Find files by filename, path substring, glob, type or extension without reading contents. Default operation=filesystem; output=lines or json. Visibility and ignore filters apply. Use the lsp tool or repl s.lsp for symbol-based discovery.");
    } else if (name == "read_file") {
        erase_properties(definition, {"name_path", "full_lines", "include_kinds", "exclude_kinds", "depth", "format"});
        operations(definition, {"text"}, "Read text, docs, config, data and logs with optional 1-based offset and line limit. Code files (Python, C/C++, C#, Rust, JS/TS, Lua, shell, PowerShell and more) are never read as text: any read of one returns its LSP symbol outline, and offset/limit are ignored. Read one symbol's code with lsp method=lsp.read_symbol. Plain text of a code file needs allow_text_fallback=true and works only when its language server fails or is missing. XML/SVG stay text. Text headers include encoding, mtime and sha256 for guarded edits. Links are not followed.");
    } else if (name == "list_dir") {
        erase_properties(definition, {"format"});
        operations(definition, {"filesystem"}, "List filesystem entries with optional depth, visibility filters and explicit limits. Default operation=filesystem and depth=1. Entries distinguish files, directories and links; links are not followed. Use lsp method=lsp.list_symbols or repl s.lsp.list_symbols for code overviews.");
    } else if (name == "file_info") {
        erase_properties(definition, {"name_path", "severity", "start_line", "end_line", "group_by_symbol", "detail"});
        operations(definition, {"metadata", "availability"}, "Inspect filesystem metadata, or use availability with one file path to probe the current LSP text-fallback decision. The probe may start a server; it reports available, unavailable, warming or not_applicable and whether fallback is eligible. Default operation=metadata. Links are not followed.");
    } else if (name == "edit_file") {
        erase_properties(definition, {"name_path", "new_name", "rename_text_occurrences", "column", "diagnostics", "on_new_errors", "indent"});
        operations(definition, {"text", "replace_content", "replace_in_files", "insert_at_line", "replace_lines", "delete_lines"},
            "Edit nonprogramming text using exact replacements, regex replacements or 1-based line edits. replace_in_files supports bulk previews and selected occurrences; dry_run previews without writing. Programming/XML text edits require explicit fallback after unavailable or failing LSP; working LSP files remain excluded. Snapshot guards, encoding preservation and atomic per-file writes apply. Use the lsp tool or repl for semantic edits and rename.");
        auto& props = std::get<J::Object>(std::get<J::Object>(std::get<J::Object>(definition.value).at("inputSchema").value).at("properties").value);
        props["new_text"] = J::Object{{"type", "string"}, {"description", "Line insertion/replacement content."}};
        props["line"] = J::Object{{"type", "integer"}, {"description", "insert_at_line: 1-based insertion line; EOF allowed."}};
    } else if (name == "move_file") {
        operations(definition, {"filesystem"}, "Move a file or directory within configured roots. Default operation=filesystem; imports and references are not rewritten. dry_run previews the move; overwrite explicitly permits replacing an existing file. Links are not followed. Use lsp method=lsp.move_file or repl s.lsp.move_file for semantic import planning.");
    }
    if (name == "write_file")
        std::get<J::Object>(definition.value)["description"] =
            "Create a file atomically, creating missing parent directories. Existing files require overwrite=true. "
            "Replacing programming/XML files with a matching expected_sha256 is allowed; without it, explicit fallback requires unavailable or failing LSP. "
            "Encoding and line endings default to the existing file's when replacing. New files infer line endings from in-root EditorConfig, Git attributes, then sibling files, unless explicitly set. Snapshot guards are optional. Links are not followed.";
    else if (name == "create_directory")
        std::get<J::Object>(definition.value)["description"] =
            "Create a directory and missing parents within configured roots. An existing directory is accepted; links are not followed.";
    erase_properties(definition, {"diagnostics"});
    auto& props = std::get<J::Object>(std::get<J::Object>(std::get<J::Object>(definition.value).at("inputSchema").value).at("properties").value);
    auto describe = [&](const char* key, const char* description) {
        std::get<J::Object>(props.at(key).value)["description"] = description;
    };
    if (name == "search") {
        describe("path", "File or directory scope for text search, in any configured root; omit for the workspace (first root).");
        describe("mode", "Text pattern syntax; default regex. multiline controls whether matches may span lines.");
        describe("intent", "Optional task description. Nonblank intent ranks hunks with built-in BM25 (an optional local reranker, when running, reorders the top ones); omit for exhaustive grep-style results.");
    } else if (name == "search_bytes") {
        describe("pattern", "One hex literal or byte regex, according to mode.");
        describe("patterns", "Up to 1000 byte patterns in one pass, using the same mode.");
        describe("line_numbers", "Include line numbers in JSON results; default false.");
    } else if (name == "list_dir") {
        describe("depth", "Directory traversal depth, 1-32; default 1.");
    } else if (name == "edit_file") {
        describe("timeout_ms", "Semantic LSP edits default to 180000 ms; text and line edits default to 30000 ms (range 1-300000).");
    } else if (name == "read_file" || name == "file_info" || name == "move_file" || name == "write_file") {
        describe("timeout_ms", "Whole request deadline, 1-300000 ms; semantic LSP operations default to 180000 ms and text/filesystem operations to 30000 ms.");
    }
    return definition;
}
struct Method {
    std::string name, tool, operation;
    std::vector<std::string> positional;
    J::Object defaults;
    std::map<std::string, std::string> aliases;
    bool writes = false;
};
const std::vector<Method>& methods() {
    static const auto list = [] {
        std::vector<Method> out;
        auto add = [&](std::string name, std::string tool, std::string operation,
                       std::vector<std::string> positional, bool writes = false) -> Method& {
            out.push_back({std::move(name), std::move(tool), std::move(operation), std::move(positional), {},
                {{"relative_path", "path"}, {"name_path_pattern", "name_path"}, {"min_severity", "severity"}}, writes});
            return out.back();
        };
        add("lsp.get_symbols_overview", "read_file", "overview", {"relative_path", "depth"}).defaults = {{"format", "json"}};
        add("lsp.find_symbol", "search", "symbols", {"name_path_pattern", "depth", "relative_path", "include_body", "include_info"});
        add("lsp.find_referencing_symbols", "search", "references", {"name_path", "relative_path"});
        add("lsp.find_implementations", "search", "implementation", {"name_path", "relative_path"});
        add("lsp.find_declaration", "search", "declaration", {"relative_path", "name_path"});
        add("lsp.find_definition", "search", "definition", {"relative_path", "name_path"});
        add("lsp.find_type_definition", "search", "type_definition", {"relative_path", "name_path"});
        add("lsp.hover", "search", "hover", {"relative_path", "name_path"});
        add("lsp.read_symbol", "read_file", "symbol", {"name_path", "relative_path"});
        add("lsp.list_symbols", "list_dir", "overview", {"relative_path", "depth"}).defaults = {{"format", "json"}};
        add("lsp.find_files", "find_files", "lsp", {"relative_path"});
        add("lsp.get_diagnostics_for_file", "file_info", "diagnostics", {"relative_path", "start_line", "end_line", "min_severity"});
        auto& diagnostics = add("lsp.get_diagnostics_for_symbol", "file_info", "diagnostics", {"name_path", "relative_path"});
        diagnostics.defaults = {{"group_by_symbol", true}};
        diagnostics.aliases["reference_file"] = "path";
        add("lsp.restart_language_server", "file_info", "restart", {"relative_path"});
        add("lsp.status", "file_info", "lsp", {"relative_path"});
        add("lsp.availability", "file_info", "availability", {"relative_path"});
        add("lsp.rename_symbol", "edit_file", "rename", {"name_path", "relative_path", "new_name"}, true);
        add("lsp.safe_delete_symbol", "edit_file", "safe_delete", {"name_path_pattern", "relative_path"}, true);
        add("lsp.move_file", "move_file", "refactor", {"source", "destination"}, true);
        for (const auto& [name, operation] : std::vector<std::pair<std::string, std::string>>{
                {"replace_symbol_body", "symbol"}, {"insert_before_symbol", "insert_before"}, {"insert_after_symbol", "insert_after"}}) {
            auto& method = add("edit." + name, "edit_file", operation, {"name_path", "relative_path", "body"}, true);
            method.aliases["body"] = "new_text";
        }
        auto& partial = add("edit.replace_in_symbol", "edit_file", "replace_in_symbol",
                            {"name_path", "relative_path", "needle", "repl"}, true);
        partial.aliases["old_text"] = "needle";
        partial.aliases["new_text"] = "repl";
        auto& insertion = add("edit.insert_in_symbol", "edit_file", "insert_in_symbol",
                              {"name_path", "relative_path", "line", "new_text"}, true);
        insertion.aliases["body"] = "new_text";
        insertion.aliases["content"] = "new_text";
        auto& outside_replace = add("edit.replace_outside_symbols", "edit_file", "replace_outside_symbols",
                                    {"relative_path", "needle", "repl"}, true);
        outside_replace.aliases["old_text"] = "needle";
        outside_replace.aliases["new_text"] = "repl";
        auto& outside_insert = add("edit.insert_outside_symbols", "edit_file", "insert_outside_symbols",
                                   {"relative_path", "line", "new_text"}, true);
        outside_insert.aliases["body"] = "new_text";
        outside_insert.aliases["content"] = "new_text";
        add("edit.replace_content", "edit_file", "replace_content", {"relative_path", "needle", "repl", "mode", "allow_multiple_occurrences"}, true);
        add("edit.replace_in_files", "edit_file", "replace_in_files", {"needle", "repl", "mode", "relative_path"}, true).defaults = {{"path", "."}};
        add("edit.delete_lines", "edit_file", "delete_lines", {"relative_path", "start_line", "end_line"}, true);
        add("edit.replace_lines", "edit_file", "replace_lines", {"relative_path", "start_line", "end_line", "content"}, true).aliases["content"] = "new_text";
        add("edit.insert_at_line", "edit_file", "insert_at_line", {"relative_path", "line", "content"}, true).aliases["content"] = "new_text";
        add("edit.edit_file", "edit_file", "text", {"relative_path", "edits"}, true);
        auto& read = add("fs.read_file", "read_file", "text", {"relative_path", "start_line", "end_line"});
        read.aliases["start_line"] = "offset";
        add("fs.list_dir", "list_dir", "filesystem", {"relative_path", "depth"}).defaults = {{"path", "."}};
        auto& find = add("fs.find_file", "find_files", "filesystem", {"file_mask", "relative_path"});
        find.aliases["file_mask"] = "glob";
        find.defaults = {{"output", "json"}};
        add("fs.find_files", "find_files", "filesystem", {}).defaults = {{"output", "json"}};
        auto& search = add("fs.search_for_pattern", "search", "text", {"substring_pattern", "relative_path"});
        search.aliases["substring_pattern"] = "pattern";
        search.aliases["context_lines_before"] = "before_lines";
        search.aliases["context_lines_after"] = "after_lines";
        search.aliases["paths_include_glob"] = "include";
        search.aliases["paths_exclude_glob"] = "exclude";
        search.defaults = {{"multiline", true}, {"output", "json"}};
        add("fs.search_bytes", "search_bytes", "", {"pattern"}).defaults = {{"output", "json"}};
        add("fs.file_info", "file_info", "metadata", {"relative_path"});
        add("fs.create_text_file", "write_file", "", {"relative_path", "content"}, true).defaults = {{"overwrite", true}};
        add("fs.write_file", "write_file", "", {"relative_path", "content"}, true);
        add("fs.delete_file", "delete_file", "", {"relative_path"}, true);
        add("fs.move_file", "move_file", "filesystem", {"source", "destination"}, true);
        add("fs.create_directory", "create_directory", "", {"relative_path"}, true);
        return out;
    }();
    return list;
}
const Method* find_method(const std::string& name) {
    const auto& list = methods();
    const auto found = std::find_if(list.begin(), list.end(), [&](const auto& method) { return method.name == name; });
    return found == list.end() ? nullptr : &*found;
}
bool semantic_method(const Method& method);
// Navigation methods whose results are source locations (references, implementations, definitions).
bool location_method(const Method& method) {
    return method.name == "lsp.find_referencing_symbols" || method.name == "lsp.find_implementations" ||
           method.name == "lsp.find_definition" || method.name == "lsp.find_declaration" ||
           method.name == "lsp.find_type_definition";
}
// Location results as grep-style rows grouped by file in first-seen order: line number, the line's code and the
// enclosing symbol. Agents read results like grep output and rarely page past the first part (arXiv 2405.15793,
// 2608.13568, 2608.26130); format=json keeps every field.
std::string render_locations(const J& value) {
    const J* items = value.get("results");
    if (!items || !std::holds_alternative<J::Array>(items->value)) return value.dump() + "\n";
    const auto field = [](const J& item, const char* key) -> std::string {
        const J* found = item.get(key);
        return found && std::holds_alternative<std::string>(found->value) ? found->string() : std::string();
    };
    std::vector<std::string> order;
    std::map<std::string, std::string> rows;
    for (const auto& item : items->array()) {
        const std::string path = field(item, "path");
        if (!rows.contains(path)) order.push_back(path);
        std::string& row = rows[path];
        const J* line = item.get("line");
        row += "  " + (line && std::holds_alternative<int64_t>(line->value) ? std::to_string(line->integer()) : std::string("?")) + ": ";
        row += field(item, "line_text");
        if (const std::string symbol = field(item, "symbol"); !symbol.empty()) row += "    [in " + symbol + "]";
        row += "\n";
    }
    const size_t count = items->array().size();
    std::string out = "[" + std::to_string(count) + " location" + (count == 1 ? "" : "s") + " in " +
                      std::to_string(order.size()) + " file" + (order.size() == 1 ? "" : "s") + " | source: lsp]\n";
    for (const auto& path : order) out += path + "\n" + rows[path];
    if (!count) out += "(no locations)\n";
    std::string notes;
    for (const char* key : {"outside_roots", "stale_locations", "ignored_locations", "symbols_omitted"})
        if (const J* number = value.get(key); number && std::holds_alternative<int64_t>(number->value) && number->integer())
            notes += std::string(notes.empty() ? "" : ", ") + key + "=" + std::to_string(number->integer());
    if (!notes.empty()) out += "[lsp result notes: " + notes + "]\n";
    if (const J* partial = value.get("partial"); partial && std::holds_alternative<bool>(partial->value) && partial->boolean())
        out += "[partial results: the language server is still indexing]\n";
    return out;
}
J::Object method_properties(const Method& method) {
    const auto& original = backend_definitions().at(method.tool).get("inputSchema")->get("properties")->object();
    J::Object properties = original;
    properties.erase("operation");
    if (method.tool == "search" && method.operation != "text") {
        const std::set<std::string> allowed{"path", "name_path", "pattern", "patterns", "include_body", "full_lines", "substring_matching",
            "line", "column", "include_declaration", "timeout_ms", "include_info", "include_kinds", "exclude_kinds", "depth", "allow_text_fallback"};
        for (auto it = properties.begin(); it != properties.end();)
            if (!allowed.contains(it->first)) it = properties.erase(it); else ++it;
        if (method.operation == "symbols") { properties.erase("line"); properties.erase("column"); }
        else for (const char* key : {"depth", "include_info", "include_kinds", "exclude_kinds", "substring_matching", "patterns"})
            properties.erase(key);
        if (method.operation != "references") properties.erase("include_declaration");
        if (method.operation != "symbols" && method.operation != "references") properties.erase("full_lines");
        if (method.operation == "hover") properties.erase("include_body");
    } else if (method.tool == "file_info" && method.operation != "metadata") {
        for (auto it = properties.begin(); it != properties.end();) {
            const bool keep = it->first == "path" || it->first == "paths" || it->first == "timeout_ms" ||
                (method.operation == "diagnostics" && (it->first == "name_path" || it->first == "severity" ||
                 it->first == "start_line" || it->first == "end_line" || it->first == "group_by_symbol"));
            if (!keep) it = properties.erase(it); else ++it;
        }
        if (method.operation == "availability") properties.erase("paths");
    } else if (method.tool == "read_file" && method.operation != "text") {
        properties.erase("outline_first");
        if (method.operation == "overview") {
            properties.erase("line_numbers");
            properties.erase("name_path"); properties.erase("offset"); properties.erase("limit"); properties.erase("full_lines");
        } else {
            for (const char* key : {"depth", "include_kinds", "exclude_kinds"}) properties.erase(key);
            properties["offset"] = J::Object{{"type", "integer"}, {"minimum", 1},
                {"description", "First line relative to the selected symbol, starting at 1. Requires successful symbol resolution; output labels use absolute source lines."}};
            properties["limit"] = J::Object{{"type", "integer"}, {"minimum", 1},
                {"description", "Maximum symbol body lines; omit to read the remaining body. next_offset continues a partial read."}};
        }
    } else if (method.tool == "edit_file" && (method.operation == "symbol" || method.operation == "insert_before" ||
                method.operation == "insert_after" || method.operation == "rename" || method.operation == "safe_delete" ||
                method.operation == "replace_in_symbol" || method.operation == "insert_in_symbol" ||
                method.operation == "replace_outside_symbols" || method.operation == "insert_outside_symbols")) {
        const std::set<std::string> allowed{"path", "name_path", "new_name", "rename_text_occurrences", "new_text", "line", "column",
            "needle", "repl", "mode", "allow_multiple_occurrences", "indent",
            "diagnostics", "on_new_errors", "timeout_ms", "dry_run", "expected_sha256", "expected_mtime", "max_output_bytes"};
        for (auto it = properties.begin(); it != properties.end();)
            if (!allowed.contains(it->first)) it = properties.erase(it); else ++it;
        if (method.operation != "rename") {
            properties.erase("new_name"); properties.erase("column"); properties.erase("rename_text_occurrences");
            if (method.operation != "insert_in_symbol" && method.operation != "insert_outside_symbols") properties.erase("line");
        } else { properties.erase("new_text"); properties.erase("on_new_errors"); }
        if (method.operation == "safe_delete" || method.operation == "replace_in_symbol" || method.operation == "replace_outside_symbols") properties.erase("new_text");
        if (method.operation != "insert_in_symbol") properties.erase("indent");
        if (method.operation != "replace_in_symbol" && method.operation != "replace_outside_symbols")
            for (const char* key : {"needle", "repl", "mode", "allow_multiple_occurrences"}) properties.erase(key);
        if (method.operation == "replace_outside_symbols" || method.operation == "insert_outside_symbols") {
            properties.erase("name_path");
            if (method.operation == "replace_outside_symbols")
                std::get<J::Object>(properties.at("needle").value)["description"] =
                    "Literal or PCRE2 regex matched outside protected LSP symbol ranges, including namespace and module gaps. Matches crossing protected ranges fail; matches entirely inside them are ignored. Protection depends on server symbol coverage.";
            else std::get<J::Object>(properties.at("line").value)["description"] =
                    "Absolute 1-based insertion line outside protected LSP symbol ranges.";
        }
        if (method.operation == "replace_in_symbol") {
            std::get<J::Object>(properties.at("needle").value)["description"] =
                "Literal or PCRE2 regex matched only inside the selected symbol. Requires one unambiguous match unless allow_multiple_occurrences=true.";
            std::get<J::Object>(properties.at("repl").value)["description"] =
                "Replacement text; regex captures use $!1 etc. Newlines follow the file's style. Content outside matched spans is preserved.";
        }
        if (method.operation == "insert_in_symbol")
            std::get<J::Object>(properties.at("line").value)["description"] =
                "Absolute 1-based source line at which to insert. Its start must lie inside the selected symbol. "
                "Indentation is supplied verbatim by default; indent=match prefixes the target line whitespace to each nonblank inserted line.";
        if (properties.contains("max_output_bytes"))
            std::get<J::Object>(properties.at("max_output_bytes").value)["description"] =
                "Final MCP response byte limit, 512-1048576. Text responses paginate losslessly using top-level continue; structured JSON must fit. "
                "Inside a REPL cell the smallest requested limit applies to the final response; facade Values remain complete.";
        if (properties.contains("new_text"))
            std::get<J::Object>(properties.at("new_text").value)["description"] =
                "Replacement or inserted code. Newlines are converted to the file's line endings; "
                "before/after insertion preserves supplied leading and trailing newlines and code indentation.";
    } else if (method.name.starts_with("fs.") || method.name == "edit.edit_file" ||
               method.operation == "replace_content" || method.operation == "replace_in_files" ||
               method.operation == "delete_lines" || method.operation == "replace_lines" || method.operation == "insert_at_line") {
        properties = fallback_definition(method.tool).get("inputSchema")->get("properties")->object();
        properties.erase("operation");
    }
    if (method.tool == "list_dir" && method.operation == "overview")
        for (const char* key : {"hidden", "no_ignore", "max_results", "max_output_bytes"}) properties.erase(key);
    if (method.tool == "find_files" && method.operation == "lsp") {
        const std::set<std::string> allowed{"path", "timeout_ms"};
        for (auto it = properties.begin(); it != properties.end();)
            if (!allowed.contains(it->first)) it = properties.erase(it); else ++it;
    }
    if (method.name == "fs.read_file") properties["end_line"] = J::Object{{"type", "integer"}, {"description", "Optional last 1-based line, inclusive; omit for the default 100-line window or use -1 for all remaining lines."}};
    if (method.name == "fs.find_file") {
        properties.erase("roots");
        properties["path"] = J::Object{{"type", "string"}, {"description", "Directory scope; defaults to the first configured root."}};
    }
    if (method.aliases.contains("relative_path") && properties.contains("path")) {
        auto& path = std::get<J::Object>(properties.at("path").value);
        const auto description = path.find("description");
        const std::string existing = description == path.end() ? std::string{} : description->second.string();
        path["description"] = existing + (existing.empty() ? "" : " ") +
            "Accepts a path relative to the first configured root, or a full absolute path within any configured root.";
    }
    if (method.name == "lsp.rename_symbol")
        std::get<J::Object>(properties.at("new_name").value)["description"] =
            "New name passed to the language server. Proposed target files are synchronized and replanned before snapshot-checked writes.";
    if (method.name == "lsp.status" || method.name == "lsp.restart_language_server")
        properties["detail"] = J::Object{{"type", "string"}, {"enum", J::Array{"summary", "full"}}, {"default", "summary"},
            {"description", "Summary reports server identity, document count, indexing state, available failure reason and uptime_seconds (null when not running). full also includes capabilities and configuration details. Direct status defaults to text; format=json returns structured data."}};
    if (semantic_method(method)) {
        const bool overview = method.operation == "overview";
        const bool compact_symbols = method.name == "lsp.find_symbol" || location_method(method);
        properties["format"] = J::Object{{"type", "string"},
            {"enum", overview ? J::Array{"json", "text", "outline", "compact"} :
                compact_symbols ? J::Array{"json", "text", "compact"} : J::Array{"json", "text"}},
            {"description", "Presentation only. json preserves structured/rowpack results. Direct bodies/diffs and lsp.status default to readable text; "
                            "direct find_symbol without bodies, overviews, references, implementations and definitions default to compact. "
                            "REPL values default to structured data. outline/compact render named symbol kinds, names and line ranges "
                            "(find_symbol also shows line_text); for locations, compact and text group rows by file with line number, "
                            "the line's code and the enclosing symbol. compact does not include bodies."}};
    }
    return properties;
}
std::string accepted_arguments(const Method& method, const J::Object& properties) {
    std::set<std::string> keys;
    for (const auto& [key, value] : properties) { (void)value; keys.insert(key); }
    for (const auto& [alias, canonical] : method.aliases)
        if (properties.contains(canonical)) keys.insert(alias);
    std::string message = "; accepted arguments: ";
    bool first = true;
    for (const auto& key : keys) { message += (first ? "" : ", ") + key; first = false; }
    if (method.name == "lsp.find_files")
        message += ". For filename glob or substring filters, use the find_files tool or s.fs.find_files";
    return message;
}
J semantic_arguments_schema(const Method& method);
std::string help(const std::string& topic, const SearchContext& context, bool direct = false) {
    if (topic == "manual") return tool_manual(context, false);
    if (topic.empty() || topic == "s") {
        return "C++26 REPL powered by LLVM Clang-Repl. Use s.info(\"manual\") for tool routing, then s.info(\"lsp\"), s.info(\"edit\") or s.info(\"fs\").\n"
            "Pass one named argument object: auto hits = s.lsp.find_symbol({{\"name_path_pattern\", \"Foo\"}, {\"relative_path\", \"src\"}});\n"
            "Same call in shgrep syntax: auto hits = s::<3::lsp~>find_symbol({{\"name_path_pattern\", \"Foo\"}, {\"relative_path\", \"src\"}}); (<3 is decoration; group~>operation).\n"
            "Read fields with hits[\"results\"][size_t{0}][\"name_path\"].string(); iterate with for (auto hit : hits[\"results\"].array()).\n"
            "C++ variables, functions, classes, lambdas, loops and standard headers persist in this session.\n"
            "Omit the final expression's semicolon to return its value; std::cout/printf output and compiler diagnostics are captured.\n"
            "s.vars() lists user C++ declarations; s.clear() resets the worker after the current cell finishes.\n"
            "Facade calls read current filesystem data through shgrep's native backends. Stored results are snapshots.\n"
            "All facade positions are 1-based; columns are UTF-16. Completed file edits are not rolled back if a later operation fails.\n"
            "Each session has a separate worker (at most 8), with a 1 GiB job memory limit. Cells are limited to 256 KiB; captured output to 128 MiB.\n"
            "Compiler errors, timeout/cancellation, DLL link/load or initialization failure reset that session and discard its declarations. Retry corrected code with the same session_id and include all required headers/declarations; successful cells are not replayed. Normal reset attempts cleanup; forced termination cannot guarantee destructors. The server and other sessions remain available.\n"
            "C++ cells are trusted native code with OS access, not sandboxed by facade root checks. --read-only disables native execution.\n"
            "Keep shgrep.exe, shgrep-compiler.dll and shgrep.dat from the same build together for this REPL. The REPL, including semantic navigation, requires installed MSVC C++ Build Tools with a matching major.minor toolset, a Windows 10/11 SDK and a compatible x64 VC++ Redistributable. Cells generate DLLs in a private temporary session directory, retained until worker exit.\n"
            "Language servers are downloaded separately using tools/fetch_lsp.py; project dependencies and compiler flags must be available locally.\n"
            "The direct lsp MCP tool exposes semantic navigation and symbol edits without a C++ worker; s.lsp and s.edit also expose them in cells.\n"
            "Text search is exhaustive without intent; a nonblank intent returns hunks ranked by built-in BM25 (an optional local reranker, when running, reorders the top ones).\n"
            "Returned structured values may use shgrep-rowpack v1. The same response includes $format layouts/tables and data; no earlier call is needed to decode it.\n"
            "Inside the cell, Values retain ordinary fields and arrays. Captured output is separate from a returned structured value.";
    }
    if (topic == "Json" || topic == "Symbol" || topic == "Result" || topic == "Value") {
        return "Facade methods accept const shgrep::Json::Object& and return shgrep::cpp::Value.\n"
            "Value supports [\"field\"], [size_t{index}], get(key, fallback), array(), string(), integer(), boolean(), size(), and dump().\n"
            "array() returns a vector of Value copies. data exposes the underlying shgrep::Json. Use nullptr for JSON null.\n"
            "Native LSP collections use [\"results\"]; diagnostics use [\"items\"] and optional [\"grouped\"].\n"
            "Symbol fields include name, name_path, kind, path, line/column and ranges; include_body adds body. Plain tool output remains a string.\n"
            "Transport packing does not change Values inside the cell. When $format.name is shgrep-rowpack, decode data with that response's tables.\n"
            "J nodes contain raw JSON; A nodes contain child nodes; O nodes map keys to child nodes; S nodes use a zero-based schema index followed by field cells.\n"
            "Each schema descriptor lists field name(s) and type. $format.types defines raw/nested values, coordinates, file tuples and prefix/suffix names.\n"
            "Use zero-based table indices, concatenate prefixes exactly, and preserve all present values and array order. Otherwise read the response as ordinary JSON.";
    }
    if (const Method* method = find_method(topic)) {
        if (context.read_only && method->writes) fail("editing is disabled by --read-only");
        std::string text = direct ? "lsp method=" + method->name + "\nNative backend: " + method->tool
                                  : "s." + method->name + "(const shgrep::Json::Object& arguments = {})\nNative backend: " + method->tool;
        if (!method->operation.empty()) text += " operation=" + method->operation;
        if (direct) text += "\nPass the keys below in arguments; timeout_ms may be top-level or inside arguments.";
        text += "\nNamed object keys (canonical names and the aliases below are accepted):\n";
        const J::Object properties = direct ? semantic_arguments_schema(*method).get("properties")->object()
                                            : method_properties(*method);
        for (const auto& [name, schema] : properties) {
            const J* description = schema.get("description");
            text += "  " + name + ": " + (description ? description->string() : schema.dump()) + "\n";
        }
        if (!direct) for (const auto& [alias, key] : method->aliases)
            if (properties.contains(key)) text += "  alias " + alias + " -> " + key + "\n";
        if (!method->defaults.empty()) text += "Defaults: " + J(method->defaults).dump() + "\n";
        if (method->name == "lsp.find_declaration")
            text += "Selection uses name_path or 1-based line/column.\n";
        if (method->name == "lsp.rename_symbol")
            text += "Rename synchronizes proposed target files and requests up to three rename plans. Unreadable or unsynchronized targets abort before writing.\n"
                    "Version and snapshot checks still apply; matching the old spelling alone does not authorize an indexed edit. dry_run previews without writing.\n";
        return text;
    }
    std::string text;
    for (const auto& method : methods())
        if (method.name.starts_with(topic + ".") && !(context.read_only && method.writes))
            text += "s." + method.name + "({ ... })\n";
    if (text.empty()) fail("unknown or unavailable REPL facade/type: " + topic);
    return text;
}

class SessionFiles {
    // Declared before WorkerProcess handles so cleanup runs after job closure
    // even if the worker constructor fails.
    repl_ipc::Handle process_;
public:
    std::filesystem::path directory;
    SessionFiles() {
        std::wstring temporary(32768, L'\0');
        const DWORD length = GetTempPathW(static_cast<DWORD>(temporary.size()), temporary.data());
        if (!length || length >= temporary.size()) fail("cannot locate C++ session temporary directory");
        temporary.resize(length);
        for (unsigned attempt = 0; attempt != 16; ++attempt) {
            unsigned char random[16];
            if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
                fail("cannot generate a private C++ session directory name");
            std::wstring name = L"shgrep-repl-";
            for (auto byte : random) {
                name += L"0123456789abcdef"[byte >> 4];
                name += L"0123456789abcdef"[byte & 15];
            }
            auto candidate = std::filesystem::absolute(std::filesystem::path(temporary) / name).lexically_normal();
            if (CreateDirectoryW(candidate.c_str(), nullptr)) {
                directory = std::move(candidate);
                return;
            }
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                fail("cannot create private C++ session directory (Windows error " +
                     std::to_string(GetLastError()) + ")");
        }
        fail("cannot reserve a unique C++ session directory");
    }
    void attach(HANDLE process) { process_ = repl_ipc::duplicate(process); }
    ~SessionFiles() {
        // Termination is asynchronous. Never remove mapped code while the
        // worker is alive, including after a timeout or a constructor failure.
        if (process_.value && WaitForSingleObject(process_.value, 5000) != WAIT_OBJECT_0) return;
        if (directory.empty() || !directory.is_absolute() ||
            !directory.filename().wstring().starts_with(L"shgrep-repl-")) return;
        std::error_code ec;
        std::filesystem::remove_all(directory, ec);
    }
};

class WorkerProcess {
    SessionFiles files_;
    repl_ipc::Handle process_, job_, input_, output_;
    repl_ipc::Reader reader_;
    std::string phase_ = "starting worker process";
    [[noreturn]] void connection_failure(const repl_ipc::ConnectionFailure& error) const {
        std::string detail = std::string(error.what()) + "\nWorker phase: " + phase_;
        // Pipe closure may precede process signalling by a few instructions.
        const DWORD waited = WaitForSingleObject(process_.value, 50);
        DWORD exit_code = 0;
        if (waited == WAIT_OBJECT_0 && GetExitCodeProcess(process_.value, &exit_code)) {
            char code[11]{};
            std::snprintf(code, sizeof(code), "0x%08lX", static_cast<unsigned long>(exit_code));
            detail += "\nWorker exit code: " + std::string(code) + " (" + std::to_string(exit_code) + ")";
        } else if (waited == WAIT_TIMEOUT) {
            detail += "\nWorker has not exited; its IPC connection closed.";
        } else {
            detail += "\nCannot query worker exit status (Windows error " + std::to_string(GetLastError()) + ")";
        }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        if (job_.value && QueryInformationJobObject(job_.value, JobObjectExtendedLimitInformation,
                                                   &limits, sizeof(limits), nullptr))
            detail += "\nWorker job peak memory: " + std::to_string(limits.PeakJobMemoryUsed) +
                      " bytes; limit: " + std::to_string(limits.JobMemoryLimit) + " bytes";
        fail(detail);
    }
public:
    bool ready = false;
    explicit WorkerProcess(const SearchContext& context) {
        using repl_ipc::Handle;
        SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
        HANDLE child_read = nullptr, parent_write = nullptr, parent_read = nullptr, child_write = nullptr;
        if (!CreatePipe(&child_read, &parent_write, &security, 65536))
            fail("cannot create C++ worker input pipe");
        Handle child_input(child_read); input_.reset(parent_write);
        if (!CreatePipe(&parent_read, &child_write, &security, 65536))
            fail("cannot create C++ worker output pipe");
        output_.reset(parent_read); Handle child_output(child_write);
        if (!SetHandleInformation(input_.value, HANDLE_FLAG_INHERIT, 0) ||
            !SetHandleInformation(output_.value, HANDLE_FLAG_INHERIT, 0))
            fail("cannot isolate C++ worker pipe handles");
        job_.reset(CreateJobObjectW(nullptr, nullptr));
        if (!job_.value) fail("cannot create C++ worker job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY;
        limits.JobMemoryLimit = size_t{1} << 30;
        if (!SetInformationJobObject(job_.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
            fail("cannot set C++ worker memory limit");
        wchar_t executable[32768];
        const DWORD length = GetModuleFileNameW(nullptr, executable, static_cast<DWORD>(std::size(executable)));
        if (!length || length == std::size(executable)) fail("cannot resolve C++ worker executable");
        const auto path = std::filesystem::path(std::wstring(executable, length));
        std::wstring command = L"\"" + path.wstring() + L"\" --repl-worker";
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = child_input.value;
        startup.StartupInfo.hStdOutput = startup.StartupInfo.hStdError = child_output.value;
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        std::vector<unsigned char> attributes(bytes);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
        if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes))
            fail("cannot initialize C++ worker handle list");
        struct Attributes {
            LPPROC_THREAD_ATTRIBUTE_LIST value;
            ~Attributes() { DeleteProcThreadAttributeList(value); }
        } cleanup{startup.lpAttributeList};
        HANDLE inherited[]{child_input.value, child_output.value};
        if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                       inherited, sizeof(inherited), nullptr, nullptr))
            fail("cannot restrict C++ worker inherited handles");
        PROCESS_INFORMATION information{};
        const std::wstring directory = context.allowed_roots.empty() ? std::wstring() : context.allowed_roots.front().wstring();
        if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, TRUE,
                            CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr,
                            directory.empty() ? nullptr : directory.c_str(), &startup.StartupInfo, &information))
            fail("cannot start shgrep.exe --repl-worker (Windows error " +
                 std::to_string(GetLastError()) + ")");
        process_.reset(information.hProcess); Handle thread(information.hThread);
        if (!AssignProcessToJobObject(job_.value, process_.value)) {
            TerminateProcess(process_.value, 1);
            fail("cannot attach C++ worker to its lifetime/memory job");
        }
        files_.attach(process_.value);
        if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) {
            TerminateJobObject(job_.value, 1);
            fail("cannot start C++ worker thread");
        }
        write(J::Object{{"kind", "initialize"}, {"directory", path_text(files_.directory)}});
    }
    ~WorkerProcess() {
        if (!process_.value || WaitForSingleObject(process_.value, 0) == WAIT_OBJECT_0) return;
        if (ready) {
            try { write(J::Object{{"kind", "shutdown"}}); } catch (...) {}
            if (WaitForSingleObject(process_.value, 1000) == WAIT_OBJECT_0) return;
        }
        if (job_.value) TerminateJobObject(job_.value, 0);
    }
    HANDLE job() const { return job_.value; }
    J read() {
        try {
            for (;;) {
                J message = reader_.read(output_.value);
                const auto kind = string_arg(message, "kind");
                if (kind == "startup") {
                    if (ready) fail("unexpected C++ worker startup message after ready");
                    const auto phase = string_arg(message, "phase");
                    if (phase.empty() || phase.size() > 256) fail("invalid C++ worker startup phase");
                    phase_ = phase;
                    continue;
                }
                if (kind == "fatal") {
                    auto& error = std::get<J::Object>(message.value)["error"];
                    error = "C++ worker failed during " + phase_ + ": " +
                            (std::holds_alternative<std::string>(error.value) ? error.string() : "unknown worker error");
                }
                return message;
            }
        } catch (const repl_ipc::ConnectionFailure& error) { connection_failure(error); }
        catch (const std::exception& error) {
            fail(std::string(error.what()) + "\nWorker phase: " + phase_);
        }
    }
    void write(const J& value) {
        if (value.get("code")) phase_ = "compiling/executing C++ cell";
        try { repl_ipc::write(input_.value, value); }
        catch (const repl_ipc::ConnectionFailure& error) { connection_failure(error); }
    }
};
struct Session {
    std::timed_mutex mutex;
    std::unique_ptr<WorkerProcess> worker;
    std::shared_ptr<ReadSnapshots> read_snapshots = std::make_shared<ReadSnapshots>();
    int64_t idle_reset_ms = 0;
    Clock::time_point idle_since = Clock::now();
    bool reset_while_idle = false;
    // Declared last so the thread stops before the worker and mutex are destroyed.
    std::jthread idle_reaper;

    void configure_idle_reset(int64_t milliseconds) {
        idle_reset_ms = milliseconds;
        if (!milliseconds) {
            if (idle_reaper.joinable()) { idle_reaper.request_stop(); idle_reaper.join(); }
            return;
        }
        if (idle_reaper.joinable()) return;
        idle_reaper = std::jthread([this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (stop.stop_requested()) break;
                std::unique_lock lock(mutex, std::try_to_lock);
                if (!lock || !worker || !idle_reset_ms) continue;
                if (Clock::now() - idle_since < std::chrono::milliseconds(idle_reset_ms)) continue;
                worker.reset();
                reset_while_idle = true;
            }
        });
    }
};
} // namespace

struct ReplState {
    std::mutex mutex;
    std::map<std::string, std::shared_ptr<Session>> sessions;
};
std::shared_ptr<ReplState> make_repl_state() { return std::make_shared<ReplState>(); }

namespace {
std::string render_status_text(const J& value, const Control& control) {
    std::vector<J> statuses, capability_sets;
    std::map<std::string, size_t> known_capabilities;
    std::string other;
    const auto append_value = [&](const J& item) {
        const J* table = item.get("capability_sets");
        const auto append_status = [&](const J& status) {
            J row = status;
            const J* capability = row.get("capabilities");
            if (!capability && table && std::holds_alternative<J::Array>(table->value)) {
                if (const J* reference = row.get("capability_set")) {
                    const int64_t index = reference->integer();
                    if (index >= 0 && static_cast<uint64_t>(index) < table->array().size())
                        capability = &table->array()[static_cast<size_t>(index)];
                }
            }
            if (capability) {
                const std::string key = capability->dump();
                auto [entry, inserted] = known_capabilities.emplace(key, capability_sets.size());
                if (inserted) capability_sets.push_back(*capability);
                auto& object = std::get<J::Object>(row.value);
                object.erase("capabilities");
                object["capability_set"] = static_cast<uint64_t>(entry->second);
            }
            statuses.push_back(std::move(row));
        };
        if (const J* results = item.get("results"); results && std::holds_alternative<J::Array>(results->value)) {
            for (const auto& status : results->array()) append_status(status);
        } else if (item.get("language_id") && item.get("root")) append_status(item);
        else other += item.dump() + "\n";
    };
    if (const auto* text = std::get_if<std::string>(&value.value)) {
        size_t start = 0;
        while (start < text->size()) {
            control.check();
            const size_t end = text->find('\n', start);
            const std::string line = text->substr(start, end == std::string::npos ? end : end - start);
            if (!line.empty()) {
                try { append_value(J::parse(line)); }
                catch (const std::exception&) { other += line + "\n"; }
            }
            if (end == std::string::npos) break;
            start = end + 1;
        }
    } else append_value(value);
    const auto cell = [](std::string text) {
        std::string out;
        for (char c : text) {
            if (c == '\n') out += "\\n";
            else if (c == '\r') out += "\\r";
            else if (c == '|') out += "\\|";
            else out += c;
        }
        return out;
    };
    std::string out = "language | root | state | open docs | last error | uptime\n";
    for (const auto& status : statuses) {
        control.check();
        const auto field = [&](const char* key, const std::string& fallback = "-") {
            const J* item = status.get(key);
            return item && std::holds_alternative<std::string>(item->value) ? cell(item->string()) : fallback;
        };
        const J* documents = status.get("open_documents");
        const J* uptime = status.get("uptime_seconds");
        std::string error = field("failure_reason", "");
        if (error.empty()) error = field("stuck_reason", "-");
        out += field("language_id") + " | " + field("root") + " | " + field("indexing_state") + " | " +
            (documents ? documents->dump() : "-") + " | " + error + " | " +
            (uptime && !std::holds_alternative<std::nullptr_t>(uptime->value) ? uptime->dump() + "s" : "-") + "\n";
    }
    if (statuses.empty()) out += "(no language servers)\n";
    for (const auto& status : statuses) {
        control.check();
        if (status.get("capability_set") || status.get("dynamic_methods"))
            out += "\nServer details: " + status.dump() + "\n";
    }
    for (size_t i = 0; i < capability_sets.size(); ++i) {
        control.check();
        out += "\nCapability set " + std::to_string(i) + ": " + capability_sets[i].dump() + "\n";
    }
    return out + other;
}

class Dispatcher {
    const SearchContext& context_;
    const Control& control_;
public:
    size_t calls = 0, writes = 0;
    std::vector<std::string> warnings;
    std::optional<uint32_t> response_budget;
    Dispatcher(const SearchContext& context, const Control& control) : context_(context), control_(control) {}
    J invoke(const Method& method, const std::vector<J>& positional, const J::Object& keywords) {
        if (context_.read_only && method.writes) fail("editing is disabled by --read-only");
        if (positional.size() > method.positional.size()) fail("too many positional arguments for s." + method.name);
        J::Object arguments = method.defaults;
        std::set<std::string> supplied;
        const auto put = [&](std::string key, const J& value) {
            if (const auto alias = method.aliases.find(key); alias != method.aliases.end()) key = alias->second;
            if (!supplied.insert(key).second) fail("duplicate argument after alias normalization: " + key);
            arguments[key] = value;
        };
        for (size_t i = 0; i < positional.size(); ++i) put(method.positional[i], positional[i]);
        for (const auto& [key, value] : keywords) put(key, value);
        if (!method.operation.empty()) {
            if (const auto operation = arguments.find("operation"); operation != arguments.end() && operation->second.string() != method.operation)
                fail("s." + method.name + " fixes operation=" + method.operation);
            arguments["operation"] = method.operation;
        }
        if (method.name == "fs.find_file") {
            const std::string scope = arguments.contains("path") ? arguments.at("path").string() : ".";
            bool directory = false;
            const auto descriptor = source_descriptor(context_, scope, &directory);
            if (!directory) fail("fs.find_file relative_path must be a directory");
            arguments.erase("path");
            if (arguments.contains("roots")) fail("use relative_path or roots, not both");
            arguments["roots"] = J::Array{path_text(descriptor.path)};
        }
        if (method.name == "fs.read_file" && arguments.contains("end_line")) {
            const int64_t last = arguments.at("end_line").integer();
            arguments.erase("end_line");
            if (arguments.contains("limit")) fail("use end_line or limit, not both");
            if (last == -1) arguments["limit"] = std::numeric_limits<int64_t>::max();
            else {
                const int64_t first = arguments.contains("offset") ? arguments.at("offset").integer() : 1;
                if (first < 1 || last < first) fail("invalid 1-based fs.read_file line range");
                arguments["limit"] = last - first + 1;
            }
        }
        if (method.name == "fs.search_for_pattern") {
            for (const char* key : {"include", "exclude"})
                if (auto value = arguments.find(key); value != arguments.end() && std::holds_alternative<std::string>(value->second.value)) {
                    const std::string glob = value->second.string();
                    if (glob.empty()) arguments.erase(value);
                    else value->second = J::Array{glob};
                }
        }
        const auto properties = method_properties(method);
        // Native aliases/special parameters are resolved above; backend validation remains authoritative.
        for (const auto& [key, value] : arguments) {
            (void)value;
            if (key != "operation" && !properties.contains(key) &&
                !(method.name == "fs.find_file" && key == "roots")) fail("unknown argument " + key + " for s." + method.name + accepted_arguments(method, properties));
        }
        std::string presentation_format = "json";
        const bool symbol_line_numbers = method.name != "lsp.read_symbol" ||
            (arguments.contains("line_numbers") && arguments.at("line_numbers").boolean());
        if (semantic_method(method)) {
            if (auto limit = arguments.find("max_output_bytes"); limit != arguments.end()) {
                const int64_t requested = limit->second.integer();
                if (requested < 512 || requested > 1048576) fail("max_output_bytes must be 512-1048576");
                const auto budget = static_cast<uint32_t>(requested);
                response_budget = response_budget ? std::min(*response_budget, budget) : budget;
                arguments.erase(limit);
            }
            if (auto format = arguments.find("format"); format != arguments.end())
                presentation_format = format->second.string();
            if (presentation_format != "json" && presentation_format != "text" &&
                presentation_format != "outline" && presentation_format != "compact")
                fail("format must be json or text (overview also accepts outline/compact)");
            if (presentation_format == "outline" && method.operation != "overview")
                fail("format=outline is only for symbol overviews");
            if (presentation_format == "compact" && method.operation != "overview" && method.name != "lsp.find_symbol" &&
                !location_method(method))
                fail("format=compact is only for symbol searches, overviews and location results");
            if (presentation_format == "compact" && arguments.contains("include_body") && arguments.at("include_body").boolean())
                fail("format=compact cannot include symbol bodies");
            arguments.erase("format");
            // Always keep native semantic values structured until the chosen
            // presentation is applied below.
            if ((method.tool == "read_file" || method.tool == "list_dir") && method.operation != "text")
                arguments["format"] = "json";
        }
        const auto finish = [&](J value) -> J {
            value_bytes(value);
            if (presentation_format != "json") {
                J rendered = method.name == "lsp.status"
                    ? render_status_text(value, control_)
                    : method.name == "lsp.availability" ? J(value.dump() + "\n")
                    : location_method(method) && !(arguments.contains("include_body") && arguments.at("include_body").boolean())
                        ? J(render_locations(value))
                    : render_semantic_text(value, method.operation == "overview" || presentation_format == "compact", control_.cancelled, symbol_line_numbers,
                                           method.name == "lsp.find_symbol");
                value_bytes(rendered);
                return rendered;
            }
            return value;
        };
        SearchContext call_context = context_;
        call_context.require_intent = false;
        control_.check();
        ++calls;
        J result = run_backend_tool(method.tool, J(arguments), call_context, control_.cancelled);
        if (method.writes && (!arguments.contains("dry_run") || !arguments.at("dry_run").boolean())) ++writes;
        for (const char* key : {"access_note", "warning"}) if (const J* warning = result.get(key)) {
            if (!warning->string().empty()) warnings.push_back(warning->string());
        }
        if (const J* structured = result.get("structured_result")) return finish(*structured);
        const J* text = result.get("text");
        if (!text) return finish(std::move(result));
        const std::string& output = text->string();
        std::optional<J> parsed;
        if (!output.empty() && (output.front() == '{' || output.front() == '[')) {
            try { parsed = J::parse(output); } catch (const std::runtime_error&) {}
        }
        if (parsed) return finish(std::move(*parsed));
        return finish(*text);
    }
};
bool semantic_method(const Method& method) {
    return method.name.starts_with("lsp.") || method.name == "edit.replace_symbol_body" ||
           method.name == "edit.insert_before_symbol" || method.name == "edit.insert_after_symbol" ||
           method.name == "edit.replace_in_symbol" || method.name == "edit.insert_in_symbol" ||
           method.name == "edit.replace_outside_symbols" || method.name == "edit.insert_outside_symbols";
}
// Direct calls (the lsp tool and one-call repl cells) default to one readable shape: text for bodies, diffs and
// status; compact rows with named kinds (and line_text for searches) for symbol searches, overviews and locations.
void apply_direct_format(const Method& method, const std::vector<J>& positional, J::Object& keywords) {
    if (!semantic_method(method) || keywords.contains("format")) return;
    bool with_body = false;
    if (const auto found = keywords.find("include_body"); found != keywords.end()) with_body = found->second.boolean();
    for (size_t i = 0; i < positional.size() && i < method.positional.size(); ++i) {
        if (method.positional[i] == "format") return;
        if (method.positional[i] == "include_body") with_body = positional[i].boolean();
    }
    if (method.writes || method.name == "lsp.read_symbol" || method.name == "lsp.status" || with_body)
        keywords["format"] = "text";
    else if (method.name == "lsp.find_symbol" || method.operation == "overview" || location_method(method))
        keywords["format"] = "compact";
}
// Text results already carry the warnings the backend appended; returns only the lines not shown yet.
std::string unshown_warnings(const std::vector<std::string>& warnings, const J& result) {
    const std::string* shown = std::holds_alternative<std::string>(result.value) ? &result.string() : nullptr;
    std::string out;
    for (const auto& warning : warnings)
        for (size_t at = 0; at < warning.size();) {
            const size_t end = std::min(warning.find('\n', at), warning.size());
            const std::string line = warning.substr(at, end - at);
            if (!line.empty() && (!shown || shown->find(line) == std::string::npos)) out += line + "\n";
            at = end + 1;
        }
    return out;
}
J semantic_arguments_schema(const Method& method) {
    auto properties = method_properties(method);
    properties["timeout_ms"] = J::Object{{"type", "integer"}, {"minimum", 1}, {"maximum", 300000},
        {"description", "Whole request deadline in milliseconds. May instead be top-level; both values must agree."}};
    for (const auto& [alias, canonical] : method.aliases) {
        if (const auto found = properties.find(canonical); found != properties.end()) {
            J definition = found->second;
            auto& fields = std::get<J::Object>(definition.value);
            std::string description = "Alias for " + canonical + ".";
            if (alias == "relative_path" && canonical == "path") {
                if (const auto it = fields.find("description"); it != fields.end())
                    description += " " + it->second.string();
            }
            fields["description"] = std::move(description);
            properties.emplace(alias, std::move(definition));
        }
    }
    return J::Object{{"type", "object"}, {"additionalProperties", false}, {"properties", std::move(properties)}};
}
J semantic_help(const J& options, const SearchContext& context) {
    for (const auto& [key, value] : options.object()) {
        (void)value;
        if (key != "topic" && key != "format") fail("lsp help accepts only arguments.topic and arguments.format");
    }
    const std::string format = string_arg(options, "format", "text");
    if (format != "text" && format != "json") fail("help format must be text or json");
    const auto topic = string_arg(options, "topic");
    if (topic == "manual") {
        std::string manual = tool_manual(context, false);
        if (format == "text") return manual;
        return J::Object{{"topic", "manual"}, {"text", std::move(manual)}};
    }
    if (!topic.empty()) {
        const auto* method = find_method(topic);
        if (!method || !semantic_method(*method)) fail("unknown direct semantic method: " + topic);
        if (format == "text") return help(topic, context, true);
        return J::Object{{"method", topic}, {"inputSchema", semantic_arguments_schema(*method)},
            {"defaults", method->defaults}};
    }
    if (format == "text") {
        std::string text = "Direct LSP navigation and editing; no C++ worker is used.\n"
            "Pass named fields in arguments. timeout_ms may be top-level or inside arguments; both values must agree. Positions are 1-based UTF-16.\n"
            "Tool manual: method=help, arguments={\"topic\":\"manual\"}.\nMethods:\n";
        for (const auto& method : methods())
            if (semantic_method(method)) text += "  " + method.name + "\n";
        text += "Read one reference: method=help, arguments={\"topic\":\"edit.replace_in_symbol\"}.\n"
                "Use arguments.format=json for machine-readable schemas without a duplicate reference.\n";
        return text;
    }
    J::Array available;
    for (const auto& method : methods()) if (semantic_method(method)) available.emplace_back(method.name);
    return J::Object{{"methods", std::move(available)}, {"manual_topic", "manual"},
        {"usage", "Call lsp with method and an arguments object. Use method=help and arguments.topic=<method> for its schema. Set timeout_ms at the top level or inside arguments. If both are set, they must agree. No C++ worker is used."},
        {"example", J::Object{{"method", "lsp.find_symbol"},
            {"arguments", J::Object{{"name_path_pattern", "Foo"}, {"relative_path", "src"}}}}},
        {"coordinate_base", 1}, {"position_encoding", "utf-16"}};
}
} // namespace

std::string tool_manual(const SearchContext& context, bool brief) {
    std::string text = context.read_only
        ? "shgrep runs with --read-only: use filesystem search/read tools; semantic navigation, edits and native C++ execution are unavailable. "
          "Programming/XML files can be searched and read as text in this mode. "
        : "Use lsp for symbol lookup, code reads, references, rename and symbol edits; no C++ worker is needed. "
          "Start with lsp.find_symbol, then lsp.read_symbol; read_file on code returns its outline. "
          "Use search for text in any file, find_files for paths, list_dir for folders. "
          "Edit code with edit.replace_in_symbol or edit.replace_symbol_body; use outside-symbol edits for imports. "
          "Use lsp.rename_symbol for renames and lsp.safe_delete_symbol for reference-checked deletion. "
          "Use edit_file for non-code text and write_file for new files. "
          "Use repl for batches or computation across tool results, not single reads or edits. "
          "Read the tool manual with lsp method=help, arguments={\"topic\":\"manual\"}; use a method name as topic for its current schema. ";
    text += "The first configured root is the workspace and default search scope; live indexing and language-server warm-up use it when enabled. "
            "Use an explicit absolute path or roots for another configured root. "
            "Search matches come from current disk contents; the index only chooses candidate files. "
            ".shignore overrides .gitignore/.ignore; index and warm-up progress goes to .shgrep/index.log. ";
    if (brief) {
        if (!context.read_only)
            text += "Read targets before editing; expected_sha256 pins a snapshot, and on_new_errors=rollback restores a single-file edit on new diagnostic errors. "
                    "Text fallback requires allow_text_fallback=true and an unavailable or failing LSP. ";
        text += "Report the cause and impact of 'tell the user' banners; a notice alone does not make a successful call fail. ";
        return text;
    }
    text += "\nThis manual comes from the running binary; it stores no project memories or onboarding files.\n";
    if (!context.read_only) {
        text += "Examples (lsp tool arguments):\n"
                "  Find: {\"method\":\"lsp.find_symbol\",\"arguments\":{\"name_path_pattern\":\"Foo\",\"relative_path\":\"src\"}}\n"
                "  Read: {\"method\":\"lsp.read_symbol\",\"arguments\":{\"name_path\":\"Foo/Run\",\"path\":\"src/Foo.cs\"}}\n"
                "  Rename: {\"method\":\"lsp.rename_symbol\",\"arguments\":{\"name_path\":\"Foo/Run\",\"path\":\"src/Foo.cs\",\"new_name\":\"Execute\"}}\n"
                "Search another root with search arguments {\"path\":\"C:/another-configured-root/src\",\"pattern\":\"TODO\"}. "
                "Replace that example path with an allowed root; path accepts a file or folder.\n"
                "Before changing existing files, read the target or selected symbol. An explicit expected_sha256 "
                "pins the exact version; otherwise the session's latest read/preview is checked. "
                "On a stale snapshot, reread and replan. Use dry_run to review a diff. "
                "diagnostics=true requests checks; on_new_errors=rollback restores a single-file edit when new errors are found. "
                "Unavailable diagnostics do not certify a clean edit; completed edits survive later errors.\n"
                "Do not use text fallback just to bypass a working language server. Where supported, "
                "allow_text_fallback=true requires an unavailable or failing server. "
                "Use lsp.availability for coverage, lsp.status for load state; index_warming means loading is incomplete.\n"
                "Positions are 1-based, columns use UTF-16. Pass named arguments; timeout_ms belongs at the top level "
                "or inside arguments; both values must agree when both are supplied. "
                "Use format=json for structured output and a method help topic for current fields/defaults.\n"
                "In repl, s.info(\"manual\") returns this manual; s.info(\"lsp.read_symbol\") returns method help. "
                "Facade calls also accept s::<3::group~>operation(...); <3 is decoration. "
                "Omit the final expression's semicolon to return a value; session_id keeps declarations. "
                "Native cells have OS access; compiler errors, cancellation, timeout during execution or worker failure discard declarations. After a compiler error, retry corrected code with the same session_id and include required headers/declarations; earlier cells are not replayed. "
                "Keep shgrep.exe, shgrep-compiler.dll and shgrep.dat from one build together. "
                "Direct lsp does not need the compiler DLL; language servers and project dependencies must be installed locally.\n";
    }
    text += "A banner saying 'tell the user' reports a notice or failure: report its stated cause and impact. "
            "A successful tool call with a notice is still successful. Do not make failing calls to unlock other tools. "
            "If a response has continue, fetch its remaining pages; offload_output controls saved large outputs. "
            "Decode row-packed data with the $format tables in that same response.\n"
            "\nTools available in this mode (generated from tools/list):\n";
    const J definitions = tool_list(context);
    for (const auto& tool : definitions.array()) {
        const std::string& name = tool.get("name")->string();
        const std::string& description = tool.get("description")->string();
        const size_t sentence = description.find(". ");
        text += "  " + name + ": " + description.substr(0, sentence == std::string::npos ? description.size() : sentence + 1) + "\n";
        const J* schema = tool.get("inputSchema");
        if (const J* required = schema ? schema->get("required") : nullptr) {
            text += "    required:";
            for (const auto& field : required->array()) text += " " + field.string();
            text += "\n";
        }
    }
    if (!context.read_only) {
        text += "\nDirect methods (generated from the native registry):\n";
        for (const auto& method : methods())
            if (semantic_method(method)) text += "  " + method.name + "\n";
        text += "Get fields and defaults: lsp {\"method\":\"help\",\"arguments\":{\"topic\":\"<method>\",\"format\":\"json\"}}.\n";
    }
    return text;
}

J lsp_tool_definition() {
    J::Array names{"help"};
    J::Array branches;
    const J help_schema = J::Object{{"type", "object"}, {"additionalProperties", false},
        {"properties", J::Object{{"timeout_ms", J::Object{{"type", "integer"}, {"minimum", 1}, {"maximum", 300000},
            {"description", "Whole request deadline; may instead be top-level."}}},
            {"topic", J::Object{{"type", "string"},
            {"description", "Use manual for the tool-routing guide, or a direct semantic method name such as edit.replace_in_symbol for its schema."}}},
            {"format", J::Object{{"type", "string"}, {"enum", J::Array{"text", "json"}}, {"default", "text"},
                {"description", "Default readable text; json returns method schemas/defaults, the method list, or a structured manual."}}}}}};
    branches.emplace_back(J::Object{{"properties", J::Object{
        {"method", J::Object{{"const", "help"}}}, {"arguments", help_schema}}}});
    for (const auto& method : methods()) {
        if (!semantic_method(method)) continue;
        names.emplace_back(method.name);
        branches.emplace_back(J::Object{{"properties", J::Object{
            {"method", J::Object{{"const", method.name}}},
            {"arguments", semantic_arguments_schema(method)}}}});
    }
    return J::Object{{"name", "lsp"},
        {"description", "Direct semantic navigation and symbol edits through shgrep's own language-server backend. "
            "Works independently of the C++ REPL and compiler DLL. Call method=help for operations, arguments.topic=manual for the tool guide, or a method name as topic for its schema. "
            "Method names match the existing facades, including lsp.find_symbol, lsp.rename_symbol and edit.replace_symbol_body. "
            "Example: {\"method\":\"lsp.find_symbol\",\"arguments\":{\"name_path_pattern\":\"Foo\",\"relative_path\":\"src\"}}. "
            "Pass named fields in arguments; timeout_ms may be top-level or inside arguments and both values must agree. Defaults are 180000 ms for a ready target server and 300000 ms for cold or undetermined targets. Positions are 1-based with UTF-16 columns. "
            "Language servers and project dependencies must be installed separately. Missing or failing servers are reported; "
            "text fallback requires explicit permission where supported. Root restrictions, snapshot guards and native edit validation apply. "
            "dry_run previews edits. safe_delete blocks references and possible method/property contracts, or incomplete checks; dry_run reports blockers and the proposed diff. Same-name ancestor members may be conservatively treated as contracts, and results depend on language-server coverage. Direct symbol searches and overviews default to compact rows: named kind, short name under a shared parent, line range, and for searches the symbol line_text; format=json returns structured results with numeric kind and kind_name. Text bodies omit line numbers unless requested; diffs retain unified-diff hunk coordinates; format=json preserves structured/rowpack results. Use format=outline for overviews, read_symbol offset/limit for slices, edit.replace_in_symbol or edit.insert_in_symbol for symbol edits, and edit.replace_outside_symbols or edit.insert_outside_symbols for headers and imports. Outside-symbol edits use the ranges supplied by the language server; incomplete ranges can leave declarations unprotected. Status is observational and never starts servers. It lists eligible configured root/language servers as not_started until first use; indexing_state can also be ready, indexing, starting, stuck or failed. stuck_reason appears after 180 seconds without tracked activity; failure_reason reports startup errors. The root-local bundled:false setting in .shgrep/lsp.json disables bundled defaults while explicit servers remain configured. Semantic requests start the selected server on first use, wait for readiness and may return index_warming with startup failure or index progress details. Direct lsp.status defaults to summary rows; detail=full includes configuration details; multi-server responses use response-local capability_sets referenced by each row capability_set. Use format=json for structured output; compiled REPL cells default to structured values, while a cell holding one literal shgrep call returns the direct text. Diagnostics report coverage and do not certify external compiler-check completion. Unavailable with --read-only."},
        {"inputSchema", J::Object{{"type", "object"}, {"additionalProperties", false}, {"required", J::Array{"method"}},
            {"properties", J::Object{
                {"method", J::Object{{"type", "string"}, {"enum", std::move(names)}}},
                {"arguments", J::Object{{"type", "object"}, {"description", "Named method arguments; omit for help."}}},
                {"max_output_bytes", J::Object{{"type", "integer"}, {"minimum", 512}, {"maximum", 1048576},
                    {"description", "Optional final response byte limit. Text output uses lossless continuation; structured JSON must fit. The smaller of this and a method limit applies."}}},

                {"timeout_ms", J::Object{{"type", "integer"}, {"minimum", 1}, {"maximum", 300000},
                    {"description", "Whole request deadline including response encoding. May also be inside arguments; both values must agree. Default: 180000 ms for a ready target server, otherwise 300000 ms."}}}}},
            {"oneOf", std::move(branches)}}}};
}

J run_lsp_tool(const J& arguments, const SearchContext& context,
               const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (context.read_only) fail("direct semantic operations are disabled by --read-only");
    for (const auto& [key, value] : arguments.object()) {
        (void)value;
        if (key != "method" && key != "arguments" && key != "timeout_ms") fail("unknown lsp argument: " + key + "; accepted arguments: method, arguments, timeout_ms");
    }
    const auto name = string_arg(arguments, "method");
    if (name.empty()) fail("lsp requires method; use method=help to list methods");
    const int64_t timeout = lsp_request_timeout_ms(arguments, context, cancelled);
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout)), cancelled};
    const RequestDeadline deadline(control.deadline);
    control.check();
    J options = arguments.get("arguments") ? *arguments.get("arguments") : J::Object{};
    (void)options.object();
    std::get<J::Object>(options.value).erase("timeout_ms");
    if (name == "help") {
        J reference = semantic_help(options, context);
        if (std::holds_alternative<std::string>(reference.value)) return J::Object{{"text", std::move(reference)}};
        return J::Object{{"structured_result", std::move(reference)}};
    }
    const Method* method = find_method(name);
    if (!method || !semantic_method(*method)) fail("unknown direct semantic method: " + name);
    const J argument_schema = semantic_arguments_schema(*method);
    const auto& properties = argument_schema.get("properties")->object();
    for (const auto& [key, value] : options.object()) {
        (void)value;
        if (!properties.contains(key)) fail("unknown argument " + key + " for direct semantic method " + name + accepted_arguments(*method, properties));
    }
    auto keywords = options.object();
    apply_direct_format(*method, {}, keywords);  // format=json keeps structured results
    keywords["timeout_ms"] = timeout;
    Dispatcher dispatcher(context, control);
    try {
        J result = dispatcher.invoke(*method, {}, keywords);
        const std::string warnings = unshown_warnings(dispatcher.warnings, result);
        if (std::holds_alternative<std::string>(result.value) && string_arg(options, "format") != "json")
            return J::Object{{"text", result.string() + warnings},
                {"completed_writes", static_cast<uint64_t>(dispatcher.writes)},
                {"response_max_output_bytes", static_cast<uint64_t>(dispatcher.response_budget.value_or(0))}};
        return J::Object{{"structured_result", std::move(result)}, {"text", std::move(warnings)},
            {"completed_writes", static_cast<uint64_t>(dispatcher.writes)},
                {"response_max_output_bytes", static_cast<uint64_t>(dispatcher.response_budget.value_or(0))}};
    } catch (const IndexWarmingFailure& error) {
        std::string message = error.what();
        if (dispatcher.writes) message += "\nThe write operation completed; applied changes remain in place.";
        throw IndexWarmingFailure(std::move(message), error.details);
    } catch (const SymbolLookupFailure& error) {
        std::string message = error.what();
        if (dispatcher.writes) message += "\nThe write operation completed; applied changes remain in place.";
        throw SymbolLookupFailure(std::move(message), error.details);
    } catch (const std::exception& error) {
        fail(std::string(error.what()) +
             (dispatcher.writes ? "\nThe write operation completed; applied changes remain in place." : ""));
    }
}

J repl_tool_definition() {
    const J properties = J::Object{
        {"max_output_bytes", J::Object{{"type", "integer"}, {"minimum", 512}, {"maximum", 1048576},
            {"description", "Optional final response byte limit. Text output uses lossless continuation; structured JSON must fit. Facade Values inside the cell remain complete; the smallest requested limit applies."}}},
        {"code", J::Object{{"type", "string"}, {"maxLength", static_cast<uint64_t>(max_code)},
            {"description", "C++26 cell, at most 256 KiB. Use s.info() for facades. Facade calls may use shgrep syntax: s::<3::fs~>read_file(\"file.cs\") equals s.fs.read_file(\"file.cs\"). Omit the final expression's semicolon to return it."}}},
        {"session_id", J::Object{{"type", "string"}, {"minLength", 1}, {"maxLength", 64},
            {"pattern", "^[A-Za-z0-9_-]+$"}, {"default", "default"},
            {"description", "Process-local C++ session key, 1-64 ASCII letters/digits/_/-. Default 'default'; at most 8 sessions."}}},
        {"timeout_ms", J::Object{{"type", "integer"}, {"minimum", 1}, {"maximum", 300000}, {"default", 180000},
            {"description", "Whole request deadline including response encoding, 1-300000 ms, default 180000. Expiry/cancellation during cell execution terminates and resets this session's worker."}}},
        {"idle_reset_ms", J::Object{{"type", "integer"}, {"minimum", 0}, {"maximum", 86400000},
            {"description", "Opt in to resetting this session's worker after this many idle milliseconds; 0 disables it. The setting persists for this session when omitted. Reset clears saved declarations and is reported on the next call."}}}
    };
    return J::Object{
        {"name", "repl"},
        {"description",
            "Execute persistent C++26 cells through LLVM Clang-Repl for shgrep's own LSP navigation and semantic edits. "
            "Start with s.info(\"manual\") for tool routing; s.info(\"lsp\"), s.info(\"edit\"), s.info(\"fs\") or a method name gives the current reference. "
            "Pass one named argument object per facade call. Example: auto hits = s.lsp.find_symbol({{\"name_path_pattern\", \"Foo\"}, {\"relative_path\", \"src\"}}); hits[\"results\"].size() "
            "shgrep call syntax works too: s::<3::fs~>read_file(\"file.cs\") means s.fs.read_file(\"file.cs\"); <3 is a fixed decoration, the group (fs, lsp, edit) comes before ~> and the operation after it; s::<3::info(), s::<3::vars() and s::<3::clear() reach the helpers. A cell that is just one such call with literal arguments (strings, numbers, true/false, or one {{\"key\", value}} list) runs without the C++ compiler, as fast as a direct tool call. "
            "Values support [\"field\"], [size_t{index}], array(), string(), integer(), boolean() and dump(). "
            "Omit the final expression's semicolon to return its value. Structured values may use shgrep-rowpack v1: decode data using the same response's $format layouts and tables. "
            "Facade Values inside the cell are unpacked. Captured stdout/stderr are returned separately from structured values. "
            "Positions are 1-based with UTF-16 columns. Rename synchronizes proposed target files and rejects stale snapshots before writing. "
            "Completed edits remain applied if a later operation fails. Text search of source needs no LSP; fs.read_file of a code file returns its LSP outline. Unrestricted source text writes still require explicit fallback after LSP failure. Use partial symbol edits for small code changes. "
            "Language servers are installed separately with tools/fetch_lsp.py; no Serena runtime is required. "
            "Keep shgrep.exe, shgrep-compiler.dll and shgrep.dat from the same build together for this REPL. This REPL requires installed MSVC C++ Build Tools with a matching major.minor toolset, a Windows 10/11 SDK and a compatible x64 VC++ Redistributable; headers and libraries are discovered locally. Generated DLLs stay in a private temporary session directory until worker exit. Project dependencies must be available locally. "
            "s.vars() lists declarations; s.clear() resets after this cell. At most 8 sessions, each with a 1 GiB worker memory limit and 128 MiB captured output limit. "
            "Compiler errors, timeout, cancellation, DLL link/load or initialization failure lose that session's declarations. Compiler errors retire the worker; corrected code can reuse the same session_id with required headers/declarations. Earlier cells are not replayed. Normal reset attempts cooperative cleanup; forced termination cannot guarantee destructors. Native C++ has OS access; --read-only disables execution. "
            "Semantic facade calls wait for language-server readiness and can report index_warming with progress details. The direct lsp tool provides semantic navigation and symbol edits independently of this REPL."},
        {"inputSchema", J::Object{{"type", "object"}, {"additionalProperties", false},
                                  {"required", J::Array{"code"}}, {"properties", properties}}}
    };
}

J fallback_tool_definitions(const SearchContext& context) {
    J::Array definitions;
    for (const char* name : {"search", "search_bytes", "find_files", "read_file", "list_dir", "file_info",
                            "edit_file", "write_file", "delete_file", "move_file", "create_directory"})
        if (!(context.read_only && is_write_tool(name))) definitions.push_back(fallback_definition(name));
    return definitions;
}
J fallback_arguments(const std::string& name, const J& arguments, const SearchContext& context) {
    if (context.read_only && is_write_tool(name)) fail(name + " is disabled by --read-only");
    const J definition = fallback_definition(name);
    const auto& properties = definition.get("inputSchema")->get("properties")->object();
    for (const auto& [key, value] : arguments.object()) {
        (void)value;
        if (!properties.contains(key)) fail(key + " is not a plain " + name + " option; use repl for semantic operations");
    }
    J::Object args = arguments.object();
    if (const auto operation = properties.find("operation"); operation != properties.end()) {
        const auto& allowed = operation->second.get("enum")->array();
        const J chosen = args.contains("operation") ? args.at("operation") : allowed.front();
        if (std::none_of(allowed.begin(), allowed.end(), [&](const J& value) { return value.string() == chosen.string(); }))
            fail("semantic " + name + " operations are available through repl; this tool is a plain fallback");
        args["operation"] = chosen;
    }
    return args;
}
// shgrep's own call syntax for REPL cells: s::<3::fs~>read_file("file.cs") is s.fs.read_file("file.cs"). The <3 is
// a fixed decoration with no meaning; the group before ~> names the facade (fs, lsp, edit) and the name after it the
// operation. s::<3::info(), s::<3::vars() and s::<3::clear() reach the session helpers. Rewritten to the C++ facade
// before compilation, outside string literals and comments, so argument handling, dispatch, returned values and errors
// stay the facade's own. Lines are kept, so compiler messages keep their line numbers. `s::<` is never valid C++.
std::string translate_love_calls(const std::string& code) {
    static constexpr std::string_view prefix = "s::<3::";
    if (code.find(prefix) == std::string::npos) return code;
    const auto ident = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; };
    const auto line_of = [&](size_t at) { return 1 + std::count(code.begin(), code.begin() + static_cast<std::ptrdiff_t>(at), '\n'); };
    std::string out;
    out.reserve(code.size());
    size_t i = 0;
    const auto copy_until = [&](size_t end) { out.append(code, i, end - i); i = end; };
    while (i < code.size()) {
        const char c = code[i];
        const char next = i + 1 < code.size() ? code[i + 1] : '\0';
        if (c == '/' && next == '/') {
            const size_t end = code.find('\n', i);
            copy_until(end == std::string::npos ? code.size() : end);
        } else if (c == '/' && next == '*') {
            const size_t end = code.find("*/", i + 2);
            copy_until(end == std::string::npos ? code.size() : end + 2);
        } else if (c == 'R' && next == '"' && (i == 0 || !ident(code[i - 1]) || code[i - 1] == '8' || code[i - 1] == 'L' ||
                                                code[i - 1] == 'u' || code[i - 1] == 'U')) {
            const size_t open = code.find('(', i + 2);
            if (open == std::string::npos) { copy_until(code.size()); break; }
            const std::string close = ")" + code.substr(i + 2, open - i - 2) + "\"";
            const size_t end = code.find(close, open + 1);
            copy_until(end == std::string::npos ? code.size() : end + close.size());
        } else if (c == '"' || (c == '\'' && !(i > 0 && std::isxdigit(static_cast<unsigned char>(code[i - 1])) &&
                                                 std::isxdigit(static_cast<unsigned char>(next))))) {
            size_t end = i + 1;
            while (end < code.size() && code[end] != c && code[end] != '\n') end += code[end] == '\\' ? 2 : 1;
            copy_until(std::min(code.size(), end + 1));
        } else if (code.compare(i, prefix.size(), prefix) == 0 && (i == 0 || !ident(code[i - 1]))) {
            size_t at = i + prefix.size();
            const size_t group_start = at;
            while (at < code.size() && ident(code[at])) ++at;
            const std::string group = code.substr(group_start, at - group_start);
            if (code.compare(at, 2, "~>") == 0) {
                const size_t op_start = at + 2;
                at = op_start;
                while (at < code.size() && ident(code[at])) ++at;
                const std::string operation = code.substr(op_start, at - op_start);
                const std::string name = group + "." + operation;
                if (group.empty() || operation.empty() || !find_method(name))
                    fail("unknown shgrep call s::<3::" + group + "~>" + operation + " on line " + std::to_string(line_of(i)) +
                         "; groups are fs, lsp and edit, for example s::<3::fs~>read_file(\"file.cs\"). Use s::<3::info(\"" +
                         (group.empty() ? std::string("fs") : group) + "\") to list operations");
                out += "s." + name;
            } else if (group == "info" || group == "vars" || group == "clear") {
                out += "s." + group;
            } else {
                fail("malformed shgrep call on line " + std::to_string(line_of(i)) +
                     ": write s::<3::group~>operation(...), for example s::<3::fs~>read_file(\"file.cs\")");
            }
            i = at;
        } else {
            out.push_back(c);
            ++i;
        }
    }
    return out;
}

// A cell that is only one shgrep call with literal arguments, s::<3::fs~>read_file("file.cs") or
// s::<3::lsp~>find_symbol({{"name_path_pattern", "Foo"}}), runs through the dispatcher directly: same method, argument
// mapping and result, but no C++ worker start or compile. Anything else (variables, expressions, several statements)
// returns nullopt and compiles as before. A trailing semicolon makes the call a statement that returns no value.
struct DirectLoveCall {
    const Method* method = nullptr;
    std::vector<J> positional;
    J::Object keywords;
    bool returns = true;
};
std::optional<DirectLoveCall> direct_love_call(const std::string& code) {
    std::string_view text(code);
    const auto space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!text.empty() && space(text.front())) text.remove_prefix(1);
    while (!text.empty() && space(text.back())) text.remove_suffix(1);
    static constexpr std::string_view prefix = "s::<3::";
    if (!text.starts_with(prefix)) return std::nullopt;
    const auto ident = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; };
    size_t at = prefix.size();
    const auto skip = [&] { while (at < text.size() && space(text[at])) ++at; };
    const auto word = [&] {
        const size_t start = at;
        while (at < text.size() && ident(text[at])) ++at;
        return std::string(text.substr(start, at - start));
    };
    const std::string group = word();
    if (text.compare(at, 2, "~>") != 0) return std::nullopt;
    at += 2;
    const std::string operation = word();
    const Method* method = find_method(group + "." + operation);
    if (!method) return std::nullopt;  // the full translation reports the unknown name
    DirectLoveCall call;
    call.method = method;
    // C++ string literal with the simple escapes; anything unusual compiles through the worker instead.
    const auto string_literal = [&]() -> std::optional<std::string> {
        if (at >= text.size() || text[at] != '"') return std::nullopt;
        std::string value;
        for (++at; at < text.size() && text[at] != '"'; ++at) {
            if (text[at] == '\n') return std::nullopt;
            if (text[at] != '\\') { value.push_back(text[at]); continue; }
            if (++at >= text.size()) return std::nullopt;
            switch (text[at]) {
                case '\\': value.push_back('\\'); break;
                case '"': value.push_back('"'); break;
                case '\'': value.push_back('\''); break;
                case 'n': value.push_back('\n'); break;
                case 't': value.push_back('\t'); break;
                case 'r': value.push_back('\r'); break;
                default: return std::nullopt;
            }
        }
        if (at >= text.size()) return std::nullopt;
        ++at;
        return value;
    };
    const auto scalar = [&]() -> std::optional<J> {
        skip();
        if (auto value = string_literal()) return J(std::move(*value));
        if (text.compare(at, 4, "true") == 0 && !(at + 4 < text.size() && ident(text[at + 4]))) { at += 4; return J(true); }
        if (text.compare(at, 5, "false") == 0 && !(at + 5 < text.size() && ident(text[at + 5]))) { at += 5; return J(false); }
        const size_t start = at;
        if (at < text.size() && text[at] == '-') ++at;
        while (at < text.size() && std::isdigit(static_cast<unsigned char>(text[at]))) ++at;
        if (at == start || (at == start + 1 && text[start] == '-') || at - start > 18) { at = start; return std::nullopt; }
        if (at < text.size() && (ident(text[at]) || text[at] == '.')) { at = start; return std::nullopt; }
        return J(static_cast<int64_t>(std::stoll(std::string(text.substr(start, at - start)))));
    };
    skip();
    if (at >= text.size() || text[at] != '(') return std::nullopt;
    ++at;
    for (bool first = true;; first = false) {
        skip();
        if (at < text.size() && text[at] == ')') { ++at; break; }
        if (!first) {
            if (at >= text.size() || text[at] != ',') return std::nullopt;
            ++at;
            skip();
        }
        if (text.compare(at, 2, "{{") == 0) {
            // Named arguments {{"key", value}, ...}: only as the last argument, with literal values.
            ++at;
            for (;;) {
                skip();
                if (at < text.size() && text[at] == '}') { ++at; break; }
                if (!call.keywords.empty()) {
                    if (at >= text.size() || text[at] != ',') return std::nullopt;
                    ++at;
                    skip();
                }
                if (at >= text.size() || text[at] != '{') return std::nullopt;
                ++at;
                skip();
                const auto key = string_literal();
                skip();
                if (!key || at >= text.size() || text[at] != ',') return std::nullopt;
                ++at;
                auto value = scalar();
                skip();
                if (!value || at >= text.size() || text[at] != '}') return std::nullopt;
                ++at;
                if (!call.keywords.emplace(*key, std::move(*value)).second) return std::nullopt;
            }
            skip();
            if (at >= text.size() || text[at] != ')') return std::nullopt;
            ++at;
            break;
        }
        auto value = scalar();
        if (!value) return std::nullopt;
        call.positional.push_back(std::move(*value));
    }
    skip();
    if (at < text.size() && text[at] == ';') { call.returns = false; ++at; skip(); }
    if (at != text.size()) return std::nullopt;
    return call;
}

J run_repl(const J& arguments, const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled) {
    for (const auto& [key, value] : arguments.object()) {
        (void)value;
        if (key != "code" && key != "session_id" && key != "timeout_ms" && key != "idle_reset_ms") fail("unknown repl argument: " + key);
    }
    if (context.read_only)
        fail("native C++ execution is disabled by --read-only; use the plain read/search fallback tools");
    if (!arguments.get("code")) fail("repl requires code");
    if (arguments.get("code")->string().size() > max_code) fail("REPL code exceeds 256 KiB");
    const std::string code = translate_love_calls(arguments.get("code")->string());
    const int64_t timeout = arguments.get("timeout_ms") ? arguments.get("timeout_ms")->integer() : 180000;
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const int64_t idle_reset = arguments.get("idle_reset_ms") ? arguments.get("idle_reset_ms")->integer() : -1;
    if (arguments.get("idle_reset_ms") && (idle_reset < 0 || idle_reset > 86400000)) fail("idle_reset_ms must be 0-86400000");
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout)), cancelled};
    const RequestDeadline request(control.deadline);
    control.check();
    const std::string id = string_arg(arguments, "session_id", "default");
    if (id.empty() || id.size() > 64 || !std::all_of(id.begin(), id.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
        })) fail("session_id must contain 1-64 ASCII letters/digits/_/-");
    if (!context.repl_state) fail("REPL session storage is unavailable");
    std::shared_ptr<Session> session;
    {
        std::lock_guard lock(context.repl_state->mutex);
        auto found = context.repl_state->sessions.find(id);
        if (found == context.repl_state->sessions.end()) {
            if (context.repl_state->sessions.size() >= max_sessions) fail("REPL session limit is 8; reuse an existing session_id");
            found = context.repl_state->sessions.emplace(id, std::make_shared<Session>()).first;
        }
        session = found->second;
    }
    std::unique_lock lock(session->mutex, std::defer_lock);
    while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
    control.check();
    struct IdleClock {
        Session& session;
        ~IdleClock() { session.idle_since = Clock::now(); }
    } idle_clock{*session};
    if (idle_reset >= 0) session->configure_idle_reset(idle_reset);
    if (auto direct = direct_love_call(arguments.get("code")->string())) {
        // One shgrep call with literal arguments: no worker start, no compile. It is the same call as the direct
        // tool, so it gets the direct tool's readable defaults and text output; format=json keeps structured values.
        SearchContext direct_context = context;
        if (id != "default") direct_context.read_snapshots = session->read_snapshots;
        Dispatcher direct_dispatcher(direct_context, control);
        J::Object keywords = direct->keywords;
        apply_direct_format(*direct->method, direct->positional, keywords);
        J value = direct_dispatcher.invoke(*direct->method, direct->positional, keywords);
        const std::string warnings = unshown_warnings(direct_dispatcher.warnings, value);
        const auto format = keywords.find("format");
        const bool json_requested = format != keywords.end() && std::holds_alternative<std::string>(format->second.value) &&
                                    format->second.string() == "json";
        J::Object reply{{"text", warnings},
                        {"completed_writes", static_cast<uint64_t>(direct_dispatcher.writes)},
                        {"response_max_output_bytes", static_cast<uint64_t>(direct_dispatcher.response_budget.value_or(0))}};
        if (direct->returns && std::holds_alternative<std::string>(value.value) && !json_requested)
            reply["text"] = value.string() + warnings;
        else if (direct->returns)
            reply["structured_result"] = std::move(value);
        return reply;
    }
    const bool reset_while_idle = session->reset_while_idle;
    if (!session->worker) session->worker = std::make_unique<WorkerProcess>(context);
    session->reset_while_idle = false;
    WorkerProcess& worker = *session->worker;
    SearchContext session_context = context;
    if (id != "default") session_context.read_snapshots = session->read_snapshots;
    Dispatcher dispatcher(session_context, control);
    bool clear_session = false;
    J result;
    try {
        std::atomic_bool terminated = false;
        const HANDLE job = worker.job();
        std::jthread watchdog([&control, &terminated, job](std::stop_token stop) {
            while (!stop.stop_requested()) {
                if ((control.cancelled && control.cancelled->load()) || Clock::now() >= control.deadline) {
                    terminated.store(true);
                    TerminateJobObject(job, 1);
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
        if (!worker.ready) {
            const J ready = worker.read();
            if (!ready.get("kind") || ready.get("kind")->string() != "ready" || !ready.get("ok")->boolean())
                fail(ready.get("error") ? ready.get("error")->string() : "invalid C++ worker startup response");
            worker.ready = true;
        }
        worker.write(J::Object{{"code", code}});
        for (;;) {
            control.check();
            J message = worker.read();
            const std::string kind = string_arg(message, "kind");
            if (kind == "result") { result = std::move(message); break; }
            if (kind == "fatal") fail(string_arg(message, "error", "C++ worker failed"));
            if (kind != "call") fail("invalid C++ worker protocol message");
            J::Object reply{{"kind", "reply"}, {"ok", true}};
            try {
                const auto& options = message.get("arguments")->object();
                const std::string name = string_arg(message, "method");
                if (name == "s.info") {
                    for (const auto& [key, value] : options) {
                        (void)value;
                        if (key != "topic") fail("s.info accepts only topic");
                    }
                    reply["value"] = help(string_arg(J(options), "topic"), context);
                } else if (name == "s.clear") {
                    if (!options.empty()) fail("s.clear takes no arguments");
                    clear_session = true;
                    reply["value"] = "C++ session will be cleared after this cell completes.";
                } else {
                    const Method* method = find_method(name);
                    if (!method) fail("unknown C++ facade method: " + name);
                    reply["value"] = dispatcher.invoke(*method, {}, options);
                }
            } catch (const IndexWarmingFailure& error) {
                reply["ok"] = false;
                reply["error"] = error.what();
                reply["error_code"] = "index_warming";
                reply["error_data"] = error.details;
            } catch (const SymbolLookupFailure& error) {
                reply["ok"] = false;
                reply["error"] = error.what();
                reply["error_code"] = "symbol_lookup";
                reply["error_data"] = error.details;
            } catch (const std::exception& error) {
                reply["ok"] = false;
                reply["error"] = error.what();
            }
            worker.write(reply);
        }
        control.check();
        watchdog.request_stop();
        watchdog.join();
        if (terminated.load()) fail("C++ worker was terminated at its request deadline");
    } catch (const std::exception& error) {
        session->worker.reset();
        std::string reason = error.what();
        if (cancelled && cancelled->load()) reason = "REPL request cancelled";
        else if (Clock::now() >= control.deadline) reason = "REPL request timed out";
        fail(reason + "\nC++ worker session was reset; saved declarations are lost." +
             (dispatcher.writes ? "\nEarlier completed writes remain applied; this cell was not rolled back." : ""));
    }
    std::string output = string_arg(result, "text");
    if (reset_while_idle)
        output = "[REPL worker reset after idle timeout; saved declarations were cleared]\n" + output;
    for (const auto& warning : dispatcher.warnings)
        if (output.find(warning) == std::string::npos) output += "\n" + warning;
    const J* reset = result.get("reset_required");
    const bool compiler_reset = reset && reset->boolean();
    if (clear_session || compiler_reset) session->worker.reset();
    if (!result.get("ok")->boolean()) {
        std::string message = string_arg(result, "error", "C++ cell failed") +
            (output.empty() ? "" : "\n" + output) +
            (compiler_reset ? "\nWarning: C++ worker session was reset after compiler failure; saved declarations are lost.\nRetry corrected code with the same session_id, including any required headers and declarations." : "") +
            (dispatcher.writes ? "\nEarlier completed writes remain applied; this cell was not rolled back." : "");
        const J* error_code = result.get("error_code");
        if (error_code && std::holds_alternative<std::string>(error_code->value) && error_code->string() == "index_warming") {
            const J* details = result.get("error_data");
            throw IndexWarmingFailure(std::move(message), details ? *details : J(J::Object{}));
        }
        if (error_code && std::holds_alternative<std::string>(error_code->value) && error_code->string() == "symbol_lookup") {
            const J* details = result.get("error_data");
            throw SymbolLookupFailure(std::move(message), details ? *details : J(J::Object{}));
        }
        fail(std::move(message));
    }
    if (const J* value = result.get("value"))
        return J::Object{{"structured_result", *value}, {"text", std::move(output)},
                         {"completed_writes", static_cast<uint64_t>(dispatcher.writes)},
                {"response_max_output_bytes", static_cast<uint64_t>(dispatcher.response_budget.value_or(0))}};
    return J::Object{{"text", std::move(output)}, {"completed_writes", static_cast<uint64_t>(dispatcher.writes)},
                {"response_max_output_bytes", static_cast<uint64_t>(dispatcher.response_budget.value_or(0))}};
}
} // namespace shgrep
