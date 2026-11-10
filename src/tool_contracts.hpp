#pragma once
#include "json.hpp"
#include <optional>
#include <string>
#include <vector>
#ifdef SHGREP_REFLECTION_GENERATOR
#include <meta>
#endif

namespace shgrep::contracts {
// Annotations are consumed by the separate GCC reflection generator.
// The Windows application compiles these same types with its existing MSVC STL.
#ifdef SHGREP_REFLECTION_GENERATOR
// Literal pointers cannot be reflected as constant template arguments.
// Promote their contents to compiler-owned static objects before annotating.
consteval const char* annotation_text(const char* value) {
    return std::define_static_string(std::string_view(value));
}
#endif

struct Field {
    const char* extra;
    bool required;
#ifdef SHGREP_REFLECTION_GENERATOR
    consteval Field(const char* value, bool mandatory)
        : extra(annotation_text(value)), required(mandatory) {}
#endif
};
struct Record {};
struct Tool {
    const char* name;
    const char* description;
    int group;
    bool writes;
    int order;
#ifdef SHGREP_REFLECTION_GENERATOR
    consteval Tool(const char* tool_name, const char* tool_description, int tool_group, bool tool_writes, int tool_order)
        : name(annotation_text(tool_name)), description(annotation_text(tool_description)),
          group(tool_group), writes(tool_writes), order(tool_order) {}
#endif
};
struct WireName {
    const char* value;
#ifdef SHGREP_REFLECTION_GENERATOR
    consteval WireName(const char* text) : value(annotation_text(text)) {}
#endif
};

// Preserve backend-only operation aliases while still generating enum/string conversions.
template<class E> struct EnumText {
    using enum_type = E;
    std::string text;
};
}
#ifdef SHGREP_REFLECTION_GENERATOR
// One annotation per invocation; braced initializer commas stay inside that expression.
#define SHGREP_CONTRACT(...) [[=__VA_ARGS__]]
#else
#define SHGREP_CONTRACT(...)
#endif
namespace shgrep::contracts {
enum class SearchArgsModeChoice {
    value_0 SHGREP_CONTRACT(WireName{"regex"}),
    value_1 SHGREP_CONTRACT(WireName{"literal"}),
};

enum class SearchArgsOperationChoice {
    value_0 SHGREP_CONTRACT(WireName{"symbols"}),
    value_1 SHGREP_CONTRACT(WireName{"definition"}),
    value_2 SHGREP_CONTRACT(WireName{"declaration"}),
    value_3 SHGREP_CONTRACT(WireName{"type_definition"}),
    value_4 SHGREP_CONTRACT(WireName{"implementation"}),
    value_5 SHGREP_CONTRACT(WireName{"references"}),
    value_6 SHGREP_CONTRACT(WireName{"hover"}),
    value_7 SHGREP_CONTRACT(WireName{"text"}),
};

enum class SearchArgsOutputChoice {
    value_0 SHGREP_CONTRACT(WireName{"lines"}),
    value_1 SHGREP_CONTRACT(WireName{"files"}),
    value_2 SHGREP_CONTRACT(WireName{"files_without_match"}),
    value_3 SHGREP_CONTRACT(WireName{"count"}),
    value_4 SHGREP_CONTRACT(WireName{"json"}),
};

enum class SearchArgsPathsChoice {
    value_0 SHGREP_CONTRACT(WireName{"absolute"}),
    value_1 SHGREP_CONTRACT(WireName{"relative"}),
};

enum class SearchBytesArgsModeChoice {
    value_0 SHGREP_CONTRACT(WireName{"literal"}),
    value_1 SHGREP_CONTRACT(WireName{"regex"}),
};

enum class SearchBytesArgsOutputChoice {
    value_0 SHGREP_CONTRACT(WireName{"json"}),
    value_1 SHGREP_CONTRACT(WireName{"files"}),
    value_2 SHGREP_CONTRACT(WireName{"count"}),
};

enum class FindFilesArgsOperationChoice {
    value_0 SHGREP_CONTRACT(WireName{"filesystem"}),
    value_1 SHGREP_CONTRACT(WireName{"symbols"}),
    value_2 SHGREP_CONTRACT(WireName{"lsp"}),
};

enum class FindFilesArgsOutputChoice {
    value_0 SHGREP_CONTRACT(WireName{"lines"}),
    value_1 SHGREP_CONTRACT(WireName{"json"}),
};

enum class ReadFileArgsFormatChoice {
    value_0 SHGREP_CONTRACT(WireName{"json"}),
    value_1 SHGREP_CONTRACT(WireName{"compact"}),
    value_2 SHGREP_CONTRACT(WireName{"outline"}),
};

enum class ReadFileArgsOperationChoice {
    value_0 SHGREP_CONTRACT(WireName{"auto"}),
    value_1 SHGREP_CONTRACT(WireName{"overview"}),
    value_2 SHGREP_CONTRACT(WireName{"symbol"}),
    value_3 SHGREP_CONTRACT(WireName{"text"}),
};

enum class ListDirArgsOperationChoice {
    value_0 SHGREP_CONTRACT(WireName{"filesystem"}),
    value_1 SHGREP_CONTRACT(WireName{"overview"}),
};

enum class DiagnosticCheckChoice {
    lsp SHGREP_CONTRACT(WireName{"lsp"}),
    compiler SHGREP_CONTRACT(WireName{"compiler"}),
    build SHGREP_CONTRACT(WireName{"build"}),
    all SHGREP_CONTRACT(WireName{"all"}),
};

enum class FileInfoArgsDetailChoice {
    value_0 SHGREP_CONTRACT(WireName{"summary"}),
    value_1 SHGREP_CONTRACT(WireName{"full"}),
};

enum class FileInfoArgsOperationChoice {
    value_0 SHGREP_CONTRACT(WireName{"metadata"}),
    value_1 SHGREP_CONTRACT(WireName{"availability"}),
    value_2 SHGREP_CONTRACT(WireName{"lsp"}),
    value_3 SHGREP_CONTRACT(WireName{"diagnostics"}),
    value_4 SHGREP_CONTRACT(WireName{"restart"}),
};

enum class EditFileArgsIndentChoice {
    value_0 SHGREP_CONTRACT(WireName{"verbatim"}),
    value_1 SHGREP_CONTRACT(WireName{"match"}),
};

enum class EditFileArgsOnNewErrorsChoice {
    value_0 SHGREP_CONTRACT(WireName{"warn"}),
    value_1 SHGREP_CONTRACT(WireName{"rollback"}),
};

enum class EditFileArgsOperationChoice {
    value_0 SHGREP_CONTRACT(WireName{"auto"}),
    value_1 SHGREP_CONTRACT(WireName{"symbol"}),
    value_2 SHGREP_CONTRACT(WireName{"replace_in_symbol"}),
    value_3 SHGREP_CONTRACT(WireName{"insert_in_symbol"}),
    value_4 SHGREP_CONTRACT(WireName{"replace_outside_symbols"}),
    value_5 SHGREP_CONTRACT(WireName{"insert_outside_symbols"}),
    value_6 SHGREP_CONTRACT(WireName{"insert_before"}),
    value_7 SHGREP_CONTRACT(WireName{"insert_after"}),
    value_8 SHGREP_CONTRACT(WireName{"rename"}),
    value_9 SHGREP_CONTRACT(WireName{"safe_delete"}),
    value_10 SHGREP_CONTRACT(WireName{"text"}),
    value_11 SHGREP_CONTRACT(WireName{"replace_content"}),
    value_12 SHGREP_CONTRACT(WireName{"replace_in_files"}),
    value_13 SHGREP_CONTRACT(WireName{"insert_at_line"}),
    value_14 SHGREP_CONTRACT(WireName{"replace_lines"}),
    value_15 SHGREP_CONTRACT(WireName{"delete_lines"}),
};

enum class WriteFileArgsEncodingChoice {
    value_0 SHGREP_CONTRACT(WireName{"utf-8"}),
    value_1 SHGREP_CONTRACT(WireName{"utf-8-bom"}),
    value_2 SHGREP_CONTRACT(WireName{"utf-16le"}),
    value_3 SHGREP_CONTRACT(WireName{"utf-16be"}),
};

enum class WriteFileArgsEolChoice {
    value_0 SHGREP_CONTRACT(WireName{"lf"}),
    value_1 SHGREP_CONTRACT(WireName{"crlf"}),
    value_2 SHGREP_CONTRACT(WireName{"cr"}),
};

enum class MoveFileArgsOperationChoice {
    value_0 SHGREP_CONTRACT(WireName{"auto"}),
    value_1 SHGREP_CONTRACT(WireName{"refactor"}),
    value_2 SHGREP_CONTRACT(WireName{"filesystem"}),
};

enum class LspHelpArgsFormatChoice {
    value_0 SHGREP_CONTRACT(WireName{"text"}),
    value_1 SHGREP_CONTRACT(WireName{"json"}),
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"search", "Navigate live code through LSP: symbols, definition/declaration/type_definition, implementation, references, or hover. Bodies are opt-in; no LSP output cap. Lua, XML, C/C++, Rust, Python and C# (with the .NET 10+ SDK) work out of the box; .shgrep/lsp.json adds or overrides servers. Semantic operations require LSP. Text/byte searches can read all file types without a server. Semantic fallback remains explicit. operation=text requires intent (the task in words): built-in BM25 always ranks the hunks (at most 3 per file) and the best 10 return, with a note on how many were left out. An optional reranker (off unless SHGREP_RERANK_PORT is set), when running, only reorders the top ones; without it BM25 order is final. For every reference to a symbol use operation=references. Text searches skip programming/XML files before reading; explicit fallback cannot bypass a working server.", 0, false, 0}) SearchArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"Lines after matches.\"}", false})
    std::optional<int64_t> after_lines;
    SHGREP_CONTRACT(Field{"{\"description\":\"For semantic search, permit labeled whole-word text matches when LSP fails and a name can be determined; these are not semantic results. Has no effect on ordinary text or byte searches. Default false.\"}", false})
    std::optional<bool> allow_text_fallback;
    SHGREP_CONTRACT(Field{"{\"description\":\"Lines before matches.\"}", false})
    std::optional<int64_t> before_lines;
    SHGREP_CONTRACT(Field{"{\"description\":\"Show each match inside its whole enclosing function (else class); lines output. Brace languages and Python.\"}", false})
    std::optional<bool> block;
    SHGREP_CONTRACT(Field{"{\"description\":\"Unicode-aware.\"}", false})
    std::optional<bool> case_insensitive;
    SHGREP_CONTRACT(Field{"{\"description\":\"1-based UTF-16 column; use with line.\"}", false})
    std::optional<int64_t> column;
    SHGREP_CONTRACT(Field{"{\"description\":\"json: context bytes after.\"}", false})
    std::optional<int64_t> context_after_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"json: context bytes before.\"}", false})
    std::optional<int64_t> context_before_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"json: context bytes per side, default 80.\"}", false})
    std::optional<int64_t> context_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"Lines around matches, 0-100.\"}", false})
    std::optional<int64_t> context_lines;
    SHGREP_CONTRACT(Field{"{\"description\":\"Child depth from each symbol hit, default 0; -1 all.\"}", false})
    std::optional<int64_t> depth;
    SHGREP_CONTRACT(Field{"{\"description\":\"Globs of files or dirs to skip; a matching dir is not entered: \\\"third_party\\\".\"}", false})
    std::optional<std::vector<std::string>> exclude;
    SHGREP_CONTRACT(Field{"{\"description\":\"LSP kinds to exclude.\"}", false})
    std::optional<std::vector<int64_t>> exclude_kinds;
    SHGREP_CONTRACT(Field{"{\"description\":\"Text search: return every match in scan order without intent (renames, impact checks); large output is saved to a file with an inline preview. Not with intent. Default false.\"}", false})
    std::optional<bool> exhaustive;
    SHGREP_CONTRACT(Field{"{\"description\":\"Extensions to keep: [\\\"cpp\\\", \\\"h\\\"].\"}", false})
    std::optional<std::vector<std::string>> extensions;
    SHGREP_CONTRACT(Field{"{\"description\":\"With include_body, return complete touched source lines and body_range; inline lines may contain neighboring code. Default false.\"}", false})
    std::optional<bool> full_lines;
    SHGREP_CONTRACT(Field{"{\"description\":\"Include hidden files.\"}", false})
    std::optional<bool> hidden;
    SHGREP_CONTRACT(Field{"{\"description\":\"Case-insensitive globs (* ?): without '/' the filename, with '/' the relative path: \\\"*.cpp\\\", \\\"src/*\\\".\"}", false})
    std::optional<std::vector<std::string>> include;
    SHGREP_CONTRACT(Field{"{\"description\":\"Include complete symbol bodies; default false.\"}", false})
    std::optional<bool> include_body;
    SHGREP_CONTRACT(Field{"{\"description\":\"Include declaration in references; default false.\"}", false})
    std::optional<bool> include_declaration;
    SHGREP_CONTRACT(Field{"{\"description\":\"Include hover/signature information for symbol hits; default false.\"}", false})
    std::optional<bool> include_info;
    SHGREP_CONTRACT(Field{"{\"description\":\"LSP kinds 1-26 to include.\"}", false})
    std::optional<std::vector<int64_t>> include_kinds;
    SHGREP_CONTRACT(Field{"{\"description\":\"Trigram index opens only candidate files; results equal a plain scan. Default true unless --no-live-index.\"}", false})
    std::optional<bool> index;
    SHGREP_CONTRACT(Field{"{\"description\":\"Required for operation=text: the task in words, to locate where something is. Built-in BM25 always ranks the hunks (at most 3 per file) and the best 10 return; an optional reranker (off unless SHGREP_RERANK_PORT is set), when running, only reorders the top ones. A note says how many were left out.\"}", false})
    std::optional<std::string> intent;
    SHGREP_CONTRACT(Field{"{\"description\":\"Lines matching no pattern (not json).\"}", false})
    std::optional<bool> invert;
    SHGREP_CONTRACT(Field{"{\"description\":\"1-based usage line for definition/references, instead of name_path.\"}", false})
    std::optional<int64_t> line;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default true.\"}", false})
    std::optional<bool> line_numbers;
    SHGREP_CONTRACT(Field{"{\"description\":\"Block line limit, default none. Longer blocks show the header and 3 lines around each match (or the set context).\"}", false})
    std::optional<int64_t> max_block_lines;
    SHGREP_CONTRACT(Field{"{\"description\":\"Skip larger text files; default 256 MiB, max 512 MiB. Over 64 MiB, files are scanned in line chunks; multiline, invert and block skip them.\"}", false})
    std::optional<int64_t> max_file_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional line window; default 0 shows whole lines.\"}", false})
    std::optional<int64_t> max_line_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional per-file match limit; default unlimited.\"}", false})
    std::optional<int64_t> max_matches_per_file;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional byte cap, 512-1048576; default unlimited.\"}", false})
    std::optional<int64_t> max_output_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional result limit, 1-10000; default or 0 is unlimited. Set 50 for a short result list.\"}", false})
    std::optional<int64_t> max_results;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default regex (PCRE, per line). Backreferences, lookaround or \\\\b make the whole call slow; use word.\"}", false})
    std::optional<EnumText<SearchArgsModeChoice>> mode;
    SHGREP_CONTRACT(Field{"{\"description\":\"Matches may span lines.\"}", false})
    std::optional<bool> multiline;
    SHGREP_CONTRACT(Field{"{\"description\":\"Symbol name or slash-separated parent/name. /prefix anchors at the root; otherwise suffix match. Append #kind (e.g. ClassName#ctor). Plain generic names match generic symbols; unique lookups require one generic match and report candidates if ambiguous. Other ambiguities return candidates; overloads take an index such as Name[0]. No parent is selected.\"}", false})
    std::optional<std::string> name_path;
    SHGREP_CONTRACT(Field{"{\"description\":\"Include .gitignore/.ignore/.shignore'd files.\"}", false})
    std::optional<bool> no_ignore;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default symbols via LSP. text uses live grep; its text filters and budgets apply only there.\"}", false})
    std::optional<EnumText<SearchArgsOperationChoice>> operation;
    SHGREP_CONTRACT(Field{"{\"description\":\"lines (default, grouped by file; over 50 matches start with the busiest files), files (cheapest), files_without_match, count, json (byte offsets).\"}", false})
    std::optional<EnumText<SearchArgsOutputChoice>> output;
    SHGREP_CONTRACT(Field{"{\"description\":\"File or folder to limit text search or symbols to; other navigation needs a file. Omit for all workspaces.\"}", false})
    std::optional<std::string> path;
    SHGREP_CONTRACT(Field{"{\"description\":\"Substring of the relative path.\"}", false})
    std::optional<std::string> path_filter;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default: relative with one configured root, absolute with several. relative needs all selected targets in one root.\"}", false})
    std::optional<EnumText<SearchArgsPathsChoice>> paths;
    SHGREP_CONTRACT(Field{"{\"description\":\"One pattern; search LSP mode accepts symbol name paths and #kind hints such as ClassName#ctor. Plain generic type names match generic symbols.\"}", false})
    std::optional<std::string> pattern;
    SHGREP_CONTRACT(Field{"{\"description\":\"Text: up to 1000 in one pass. LSP: symbol name paths with optional #kind hints; plain generic type names match generic symbols.\"}", false})
    std::optional<std::vector<std::string>> patterns;
    SHGREP_CONTRACT(Field{"{\"description\":\"Absolute files or folders inside configured roots. Default: the workspace (first root) only.\"}", false})
    std::optional<std::vector<std::string>> roots;
    SHGREP_CONTRACT(Field{"{\"description\":\"Also open binary-extension files.\"}", false})
    std::optional<bool> sniff_all;
    SHGREP_CONTRACT(Field{"{\"description\":\"Substring match on the last name-path component only; default false.\"}", false})
    std::optional<bool> substring_matching;
    SHGREP_CONTRACT(Field{"{\"description\":\"1-300000 ms. Defaults: semantic 180000, text 30000, find_files 300000.\"}", false})
    std::optional<int64_t> timeout_ms;
    SHGREP_CONTRACT(Field{"{\"description\":\"File types: asm bat c cmake cpp cs css go h html java js json lua make md msbuild proto ps py rust sh sql toml ts txt xml yaml.\"}", false})
    std::optional<std::vector<std::string>> types;
    SHGREP_CONTRACT(Field{"{\"description\":\"Whole words; fast, unlike \\\\b.\"}", false})
    std::optional<bool> word;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"search_bytes", "Search raw bytes in any file, including programming/XML files, by hex or byte regex; exact offsets. No language server is required.", 0, false, 1}) SearchBytesArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"ASCII only.\"}", false})
    std::optional<bool> case_insensitive;
    SHGREP_CONTRACT(Field{"{\"description\":\"json: context bytes after.\"}", false})
    std::optional<int64_t> context_after_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"json: context bytes before.\"}", false})
    std::optional<int64_t> context_before_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"json: context bytes per side, default 80.\"}", false})
    std::optional<int64_t> context_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"Globs of files or dirs to skip; a matching dir is not entered: \\\"third_party\\\".\"}", false})
    std::optional<std::vector<std::string>> exclude;
    SHGREP_CONTRACT(Field{"{\"description\":\"Extensions to keep: [\\\"cpp\\\", \\\"h\\\"].\"}", false})
    std::optional<std::vector<std::string>> extensions;
    SHGREP_CONTRACT(Field{"{\"description\":\"Include hidden files.\"}", false})
    std::optional<bool> hidden;
    SHGREP_CONTRACT(Field{"{\"description\":\"Case-insensitive globs (* ?): without '/' the filename, with '/' the relative path: \\\"*.cpp\\\", \\\"src/*\\\".\"}", false})
    std::optional<std::vector<std::string>> include;
    SHGREP_CONTRACT(Field{"{\"description\":\"Add lines to json.\"}", false})
    std::optional<bool> line_numbers;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional per-file match limit; default unlimited.\"}", false})
    std::optional<int64_t> max_matches_per_file;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional byte cap, 512-1048576; default unlimited.\"}", false})
    std::optional<int64_t> max_output_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional result limit, 1-10000; default or 0 is unlimited. Set 50 for a short result list.\"}", false})
    std::optional<int64_t> max_results;
    SHGREP_CONTRACT(Field{"{\"description\":\"literal (default): hex such as \\\"4d5a\\\". regex: byte regex such as \\\"\\\\\\\\x4d\\\\\\\\x5a\\\" or plain ASCII.\"}", false})
    std::optional<EnumText<SearchBytesArgsModeChoice>> mode;
    SHGREP_CONTRACT(Field{"{\"description\":\"Include .gitignore/.ignore/.shignore'd files.\"}", false})
    std::optional<bool> no_ignore;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default json (offsets, hex context).\"}", false})
    std::optional<EnumText<SearchBytesArgsOutputChoice>> output;
    SHGREP_CONTRACT(Field{"{\"description\":\"Substring of the relative path.\"}", false})
    std::optional<std::string> path_filter;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default: relative with one configured root, absolute with several. relative needs all selected targets in one root.\"}", false})
    std::optional<EnumText<SearchArgsPathsChoice>> paths;
    SHGREP_CONTRACT(Field{"{\"description\":\"One pattern; search LSP mode accepts symbol name paths and #kind hints such as ClassName#ctor. Plain generic type names match generic symbols.\"}", false})
    std::optional<std::string> pattern;
    SHGREP_CONTRACT(Field{"{\"description\":\"Text: up to 1000 in one pass. LSP: symbol name paths with optional #kind hints; plain generic type names match generic symbols.\"}", false})
    std::optional<std::vector<std::string>> patterns;
    SHGREP_CONTRACT(Field{"{\"description\":\"Absolute dirs inside the configured roots. Default: the workspace (first root) only.\"}", false})
    std::optional<std::vector<std::string>> roots;
    SHGREP_CONTRACT(Field{"{\"description\":\"1-300000 ms. Defaults: semantic 180000, text 30000, find_files 300000.\"}", false})
    std::optional<int64_t> timeout_ms;
    SHGREP_CONTRACT(Field{"{\"description\":\"File types: asm bat c cmake cpp cs css go h html java js json lua make md msbuild proto ps py rust sh sql toml ts txt xml yaml.\"}", false})
    std::optional<std::vector<std::string>> types;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"find_files", "Find live files by name/path, configured LSP source files, or files containing symbol hits. Use list_dir for folder or symbol overviews.", 0, false, 2}) FindFilesArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"Symbol searches only: explicitly permit text fallback after LSP failure. Default false.\"}", false})
    std::optional<bool> allow_text_fallback;
    SHGREP_CONTRACT(Field{"{\"description\":\"Whole filename, case-insensitive.\"}", false})
    std::optional<std::string> exact_name;
    SHGREP_CONTRACT(Field{"{\"description\":\"Globs of files or dirs to skip; a matching dir is not entered: \\\"third_party\\\".\"}", false})
    std::optional<std::vector<std::string>> exclude;
    SHGREP_CONTRACT(Field{"{}", false})
    std::optional<std::vector<int64_t>> exclude_kinds;
    SHGREP_CONTRACT(Field{"{\"description\":\"Extensions to keep: [\\\"cpp\\\", \\\"h\\\"].\"}", false})
    std::optional<std::vector<std::string>> extensions;
    SHGREP_CONTRACT(Field{"{\"description\":\"Glob on the name or relative path.\"}", false})
    std::optional<std::string> glob;
    SHGREP_CONTRACT(Field{"{\"description\":\"Include hidden files.\"}", false})
    std::optional<bool> hidden;
    SHGREP_CONTRACT(Field{"{\"description\":\"Case-insensitive globs (* ?): without '/' the filename, with '/' the relative path: \\\"*.cpp\\\", \\\"src/*\\\".\"}", false})
    std::optional<std::vector<std::string>> include;
    SHGREP_CONTRACT(Field{"{}", false})
    std::optional<std::vector<int64_t>> include_kinds;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional byte cap, 512-1048576; default unlimited.\"}", false})
    std::optional<int64_t> max_output_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional result limit, 1-10000; default or 0 is unlimited. Set 50 for a short result list.\"}", false})
    std::optional<int64_t> max_results;
    SHGREP_CONTRACT(Field{"{\"description\":\"symbols: alternative to pattern; accepts #kind hints and plain generic type names.\"}", false})
    std::optional<std::string> name_path;
    SHGREP_CONTRACT(Field{"{\"description\":\"Include .gitignore/.ignore/.shignore'd files.\"}", false})
    std::optional<bool> no_ignore;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default filesystem. symbols finds files containing symbol hits; lsp lists configured source files without starting servers.\"}", false})
    std::optional<EnumText<FindFilesArgsOperationChoice>> operation;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default lines.\"}", false})
    std::optional<EnumText<FindFilesArgsOutputChoice>> output;
    SHGREP_CONTRACT(Field{"{\"description\":\"LSP file/directory scope; omit for all configured roots.\"}", false})
    std::optional<std::string> path;
    SHGREP_CONTRACT(Field{"{\"description\":\"Substring of the relative path.\"}", false})
    std::optional<std::string> path_filter;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default: relative with one configured root, absolute with several. relative needs all selected targets in one root.\"}", false})
    std::optional<EnumText<SearchArgsPathsChoice>> paths;
    SHGREP_CONTRACT(Field{"{\"description\":\"symbols: name-path pattern; accepts #kind hints and plain generic type names.\"}", false})
    std::optional<std::string> pattern;
    SHGREP_CONTRACT(Field{"{\"description\":\"Absolute dirs inside the configured roots. Default: the workspace (first root) only.\"}", false})
    std::optional<std::vector<std::string>> roots;
    SHGREP_CONTRACT(Field{"{\"description\":\"Text in the name or relative path.\"}", false})
    std::optional<std::string> substring;
    SHGREP_CONTRACT(Field{"{\"description\":\"symbols: substring match on final component.\"}", false})
    std::optional<bool> substring_matching;
    SHGREP_CONTRACT(Field{"{\"description\":\"1-300000 ms. Defaults: semantic 180000, text 30000, find_files 300000.\"}", false})
    std::optional<int64_t> timeout_ms;
    SHGREP_CONTRACT(Field{"{\"description\":\"File types: asm bat c cmake cpp cs css go h html java js json lua make md msbuild proto ps py rust sh sql toml ts txt xml yaml.\"}", false})
    std::optional<std::vector<std::string>> types;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"read_file", "Read non-code files as text with operation=text, or use LSP overviews and symbol bodies. A code file read without offset/limit returns its LSP outline; offset/limit return a window of its raw lines, at most 100 per call. Symbol offset/limit selects lines relative to its definition; format=outline shows kind, name and line range. Plain text of a code file requires allow_text_fallback=true and a failing or missing language server. With offload_output on (default), a text page ends at the last whole line under 8000 bytes and its status names the next offset; offload_output=false returns every requested line inline. Every header ends with its source: lsp (a language server) or text (plain file text). Text headers include encoding, mtime and sha256; multi-file reads with a common parent show that folder once. Binary and ordinary files >256 MiB refused (UTF-16 >64 MiB); saved UTF-8 outputs under .shgrep-output can be paged without that size cap. Links are never followed.", 1, false, 3}) ReadFileArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"Permit a plain text read of a code file, honoring offset/limit, only when its language server fails or is missing. Unavailable for directories or symbol reads with offset/limit. Non-code text reads need no permission. Default false.\"}", false})
    std::optional<bool> allow_text_fallback;
    SHGREP_CONTRACT(Field{"{\"description\":\"Overview child depth; default -1 (all).\"}", false})
    std::optional<int64_t> depth;
    SHGREP_CONTRACT(Field{"{\"description\":\"LSP kinds to exclude.\"}", false})
    std::optional<std::vector<int64_t>> exclude_kinds;
    SHGREP_CONTRACT(Field{"{\"description\":\"Overview defaults to json with numeric kind and kind_name; compact/outline shows named kinds and line ranges.\"}", false})
    std::optional<EnumText<ReadFileArgsFormatChoice>> format;
    SHGREP_CONTRACT(Field{"{\"description\":\"Symbol reads: include complete touched source lines and return body_range; inline lines may contain neighboring code. Default false.\"}", false})
    std::optional<bool> full_lines;
    SHGREP_CONTRACT(Field{"{\"description\":\"LSP kinds 1-26 to include.\"}", false})
    std::optional<std::vector<int64_t>> include_kinds;
    SHGREP_CONTRACT(Field{"{\"description\":\"The task in words. Returns only the lines of the file that best match it (BM25, plus meaning scores in the GPU build), verbatim with line numbers, at most 72 lines from the best 3 windows; skipped stretches are marked. Works for code and text files; not with offset/limit or name_path.\"}", false})
    std::optional<std::string> intent;
    SHGREP_CONTRACT(Field{"{\"description\":\"Line limit per text file, code-file window or selected symbol. Text reads default to 100 lines; code windows default to and cap at 100 lines; symbol reads default to all remaining lines.\"}", false})
    std::optional<int64_t> limit;
    SHGREP_CONTRACT(Field{"{\"description\":\"Text and symbol text presentation: include line prefixes; default false. Structured symbol bodies are unchanged.\"}", false})
    std::optional<bool> line_numbers;
    SHGREP_CONTRACT(Field{"{\"description\":\"Text reads: add size, mtime and sha256 to the header (file_info shows them too). Default false.\"}", false})
    std::optional<bool> metadata;
    SHGREP_CONTRACT(Field{"{\"description\":\"Read this symbol; offset/limit selects a body slice. Type/method accepts Rust impl wrappers; append #kind (e.g. ClassName#ctor). A plain generic type name resolves when unique; multiple generic matches return candidates. Other ambiguities return candidates; overloads take an index such as Name[0]. No parent is selected.\"}", false})
    std::optional<std::string> name_path;
    SHGREP_CONTRACT(Field{"{\"description\":\"First line, from 1. Text files, code-file windows and symbol bodies.\"}", false})
    std::optional<int64_t> offset;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default auto: LSP for programming/XML; text for other formats. No automatic fallback.\"}", false})
    std::optional<EnumText<ReadFileArgsOperationChoice>> operation;
    SHGREP_CONTRACT(Field{"{\"description\":\"Accepted for compatibility; code files return their LSP outline unless offset/limit ask for a window.\"}", false})
    std::optional<bool> outline_first;
    SHGREP_CONTRACT(Field{"{\"description\":\"Relative to the first root, or absolute inside a root.\"}", false})
    std::optional<std::string> path;
    SHGREP_CONTRACT(Field{"{\"description\":\"Up to 32 paths instead of path.\"}", false})
    std::optional<std::vector<std::string>> paths;
    SHGREP_CONTRACT(Field{"{\"description\":\"LSP deadline, 1-300000; default 180000 for semantic operations and 30000 for text/filesystem operations.\"}", false})
    std::optional<int64_t> timeout_ms;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"list_dir", "List files and folders: \"d sub/\", \"f name SIZE\", \"l link\". Links are never followed.", 1, false, 4}) ListDirArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"Filesystem: 1-32, default 1. Overview: child depth, default -1 (all).\"}", false})
    std::optional<int64_t> depth;
    SHGREP_CONTRACT(Field{"{\"description\":\"Overview defaults to json with numeric kind and kind_name; compact/outline shows named kinds and line ranges.\"}", false})
    std::optional<EnumText<ReadFileArgsFormatChoice>> format;
    SHGREP_CONTRACT(Field{"{\"description\":\"Include hidden entries.\"}", false})
    std::optional<bool> hidden;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional byte cap, 512-1048576. Default unlimited.\"}", false})
    std::optional<int64_t> max_output_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional entry limit, 1-10000; default unlimited.\"}", false})
    std::optional<int64_t> max_results;
    SHGREP_CONTRACT(Field{"{\"description\":\"Include .gitignore/.ignore/.shignore'd entries.\"}", false})
    std::optional<bool> no_ignore;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default filesystem; overview returns live LSP symbols by file.\"}", false})
    std::optional<EnumText<ListDirArgsOperationChoice>> operation;
    SHGREP_CONTRACT(Field{"{\"description\":\"Folder; default the first root.\"}", false})
    std::optional<std::string> path;
    SHGREP_CONTRACT(Field{"{\"description\":\"Filesystem deadline default 30000; operation=overview uses the LSP default of 180000.\"}", false})
    std::optional<int64_t> timeout_ms;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"file_info", "Disk metadata; availability probes the current per-file text-fallback decision without editing; lsp reports server readiness, diagnostics includes coverage metadata, and restart recovers an LSP server. Links are never followed.", 1, false, 5}) FileInfoArgs {
    SHGREP_CONTRACT(Field{"{\"default\":\"lsp\",\"description\":\"Optional diagnostics provider: lsp (default), compiler, build, or all. External checks run only on request using .shgrep/checks.json; compiler needs one file, build may use a directory. Build commands write artifacts. External modes do not accept symbol or line filters and are disabled in read-only mode. Status, exit code and captured output accompany parsed errors.\"}", false})
    std::optional<EnumText<DiagnosticCheckChoice>> check;
    SHGREP_CONTRACT(Field{"{\"description\":\"lsp/restart: default summary; full includes capabilities and configuration details.\"}", false})
    std::optional<EnumText<FileInfoArgsDetailChoice>> detail;
    SHGREP_CONTRACT(Field{"{\"description\":\"diagnostics: last 1-based line, inclusive; -1 or omitted means no upper bound.\"}", false})
    std::optional<int64_t> end_line;
    SHGREP_CONTRACT(Field{"{\"description\":\"diagnostics: add grouped results by file, severity and enclosing symbol (<file> if none); flat items remain. Default false.\"}", false})
    std::optional<bool> group_by_symbol;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional byte cap, 512-1048576. Default unlimited.\"}", false})
    std::optional<int64_t> max_output_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"diagnostics: restrict to a symbol; append #kind (e.g. ClassName#ctor). A plain generic type name resolves when unique; multiple generic matches return candidates. Other ambiguities return candidates; overloads take an index such as Name[0]. No parent is selected.\"}", false})
    std::optional<std::string> name_path;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default metadata. availability requires one file path and returns state, fallback_eligible, requires_text_fallback and reason from a live probe; lsp/restart may omit path to address all servers.\"}", false})
    std::optional<EnumText<FileInfoArgsOperationChoice>> operation;
    SHGREP_CONTRACT(Field{"{\"description\":\"Relative to the first root, or absolute inside a root.\"}", false})
    std::optional<std::string> path;
    SHGREP_CONTRACT(Field{"{\"description\":\"Up to 32 paths instead of path.\"}", false})
    std::optional<std::vector<std::string>> paths;
    SHGREP_CONTRACT(Field{"{\"description\":\"diagnostics: highest numeric severity to include, 1-4; default 4.\"}", false})
    std::optional<int64_t> severity;
    SHGREP_CONTRACT(Field{"{\"description\":\"diagnostics: first 1-based line, inclusive; default 1. Includes diagnostics overlapping the requested lines.\"}", false})
    std::optional<int64_t> start_line;
    SHGREP_CONTRACT(Field{"{\"description\":\"LSP deadline, 1-300000; default 180000 for semantic operations and 30000 for text/filesystem operations.\"}", false})
    std::optional<int64_t> timeout_ms;
};

struct SHGREP_CONTRACT(Record{}) TextEditArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"Exact content with CRLF/LF/CR treated equally; all ending variants count toward uniqueness unless replace_all.\"}", true})
    std::optional<std::string> old_text;
    SHGREP_CONTRACT(Field{"{\"description\":\"Replacement.\"}", true})
    std::optional<std::string> new_text;
    SHGREP_CONTRACT(Field{"{\"description\":\"Replace every match.\"}", false})
    std::optional<bool> replace_all;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"edit_file", "Live LSP symbol replace, replace_in_symbol/insert_in_symbol, replace_outside_symbols/insert_outside_symbols, insert_before/insert_after, rename across files (listing same-name mentions it leaves, e.g. other languages), or safe_delete with reference and method/property contract checks. Deletion is blocked when checks find relationships or cannot be completed; dry_run shows blockers and the proposed diff. Text replacements and line edits are for other formats; programming/XML require symbol or outside-symbol edits unless allow_text_fallback=true and LSP fails. Bulk text edits skip files requiring working LSP. Snapshot guards, encoding preservation, dry-run diffs and rollback on commit failure; atomic per file. Links are never followed.", 1, true, 6}) EditFileArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"Relative to the first root, or absolute inside a root.\"}", true})
    std::optional<std::string> path;
    SHGREP_CONTRACT(Field{"{\"description\":\"replace_content/replace_in_symbol/replace_outside_symbols: default false; reject nonunique matches.\"}", false})
    std::optional<bool> allow_multiple_occurrences;
    SHGREP_CONTRACT(Field{"{\"description\":\"Semantic fallback and unrestricted text writes only: require unavailable/failing LSP. Read-only text access needs no fallback permission.\"}", false})
    std::optional<bool> allow_text_fallback;
    SHGREP_CONTRACT(Field{"{\"description\":\"rename: 1-based UTF-16 column with line.\"}", false})
    std::optional<int64_t> column;
    SHGREP_CONTRACT(Field{"{\"description\":\"After writing source files, request up to 20 error diagnostics per file within a shared 3-second budget. Errors and unavailable checks produce warnings; writes remain applied unless on_new_errors=rollback. External compiler checks may be unverified. Default true; set false to skip.\"}", false})
    std::optional<bool> diagnostics;
    SHGREP_CONTRACT(Field{"{\"description\":\"Diff only, write nothing.\"}", false})
    std::optional<bool> dry_run;
    SHGREP_CONTRACT(Field{"{\"description\":\"1-256 edits.\"}", false})
    std::optional<std::vector<TextEditArgs>> edits;
    SHGREP_CONTRACT(Field{"{\"description\":\"replace_lines/delete_lines: last 1-based line, inclusive.\"}", false})
    std::optional<int64_t> end_line;
    SHGREP_CONTRACT(Field{"{\"description\":\"replace_in_files: abort if match count differs; -1 disables (default). Mutually exclusive with occurrence_ids.\"}", false})
    std::optional<int64_t> expected_count;
    SHGREP_CONTRACT(Field{"{\"description\":\"Fail if the file's mtime (from read_file) changed.\"}", false})
    std::optional<std::string> expected_mtime;
    SHGREP_CONTRACT(Field{"{\"description\":\"SHA-256 from read_file metadata or file_info. Without it, a file must match this session's latest read or dry-run preview (literal old_text/needle edits: the exact match guards them; multi-file edits: each file). The default REPL session shares this history. Use the same path spelling as the read; text search is not a read.\"}", false})
    std::optional<std::string> expected_sha256;
    SHGREP_CONTRACT(Field{"{\"description\":\"insert_in_symbol only. Default verbatim keeps supplied indentation. match prefixes the target line whitespace to each nonblank line, preserving supplied relative indentation.\"}", false})
    std::optional<EnumText<EditFileArgsIndentChoice>> indent;
    SHGREP_CONTRACT(Field{"{\"description\":\"rename: 1-based line instead of name_path; insert_at_line: insertion line (EOF allowed); insert_in_symbol: absolute source line inside the selected symbol; insert_outside_symbols: absolute source line outside protected symbols.\"}", false})
    std::optional<int64_t> line;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional diff byte cap; no cap by default.\"}", false})
    std::optional<int64_t> max_output_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"Content replacement syntax; default literal. Regex uses PCRE2, not Python re.\"}", false})
    std::optional<EnumText<SearchBytesArgsModeChoice>> mode;
    SHGREP_CONTRACT(Field{"{\"description\":\"Symbol path; overload [i] supported; append #kind (e.g. ClassName#ctor). A plain generic type name resolves when unique; multiple generic matches return candidates. Other ambiguities return candidates; overloads take an index such as Name[0]. No parent is selected.\"}", false})
    std::optional<std::string> name_path;
    SHGREP_CONTRACT(Field{"{\"description\":\"replace_content/replace_in_files/replace_in_symbol/replace_outside_symbols: nonempty literal or PCRE2 regex; DOTALL and MULTILINE enabled.\"}", false})
    std::optional<std::string> needle;
    SHGREP_CONTRACT(Field{"{\"description\":\"rename: new identifier; language server computes all affected files.\"}", false})
    std::optional<std::string> new_name;
    SHGREP_CONTRACT(Field{"{\"description\":\"Complete symbol replacement or inserted code. insert_before/after use complete field or property declarations, including inline members; unresolvable boundaries such as complex interpolation or JSX fail. LF/CRLF is converted to file endings; symbol insertion preserves supplied code indentation.\"}", false})
    std::optional<std::string> new_text;
    SHGREP_CONTRACT(Field{"{\"description\":\"replace_in_files: select preview IDs; unknown/stale IDs abort all changes.\"}", false})
    std::optional<std::vector<std::string>> occurrence_ids;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default warn keeps the write and reports errors. rollback (single-file edits; not rename or replace_in_files) also reads error diagnostics before and after the write, waiting up to 60 seconds each, and restores the previous text, then fails, when the write adds errors matched by source, code and message. Unavailable diagnostics keep the write with a warning.\"}", false})
    std::optional<EnumText<EditFileArgsOnNewErrorsChoice>> on_new_errors;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default auto: name_path selects symbol replacement; edits selects text. insert_before/after target complete field or property declarations; names in one declaration stay together.\"}", false})
    std::optional<EnumText<EditFileArgsOperationChoice>> operation;
    SHGREP_CONTRACT(Field{"{\"description\":\"replace_in_files: exclude root-relative files/directories before reading; takes precedence.\"}", false})
    std::optional<std::string> paths_exclude_glob;
    SHGREP_CONTRACT(Field{"{\"description\":\"replace_in_files: root-relative glob with *, ** and ?; default all nonignored visible files.\"}", false})
    std::optional<std::string> paths_include_glob;
    SHGREP_CONTRACT(Field{"{\"description\":\"rename: also rewrite whole-word mentions of the old name inside comments and string literals of the files the rename already edits (C-family, C#, Java, Go, Rust, JS/TS, Python, shell, PowerShell, Lua, YAML/TOML). Interpolated expressions stay code. Other files are only listed as leftovers. Default false.\"}", false})
    std::optional<bool> rename_text_occurrences;
    SHGREP_CONTRACT(Field{"{\"description\":\"Replacement template; regex capture references use $!1, $!2, etc.; literal mode is verbatim.\"}", false})
    std::optional<std::string> repl;
    SHGREP_CONTRACT(Field{"{\"description\":\"replace_lines/delete_lines: first 1-based line, inclusive.\"}", false})
    std::optional<int64_t> start_line;
    SHGREP_CONTRACT(Field{"{\"description\":\"Semantic LSP edits default 180000; text and line edits default 30000, within the 1-300000 ms range.\"}", false})
    std::optional<int64_t> timeout_ms;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"write_file", "Create files atomically; creates parent folders. To replace an existing programming/XML file, use overwrite=true with expected_sha256, symbol edits, or explicit fallback after LSP failure. Links are never followed.", 1, true, 7}) WriteFileArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"Relative to the first root, or absolute inside a root.\"}", true})
    std::optional<std::string> path;
    SHGREP_CONTRACT(Field{"{\"description\":\"Full contents.\"}", true})
    std::optional<std::string> content;
    SHGREP_CONTRACT(Field{"{\"description\":\"Semantic fallback and unrestricted text writes only: require unavailable/failing LSP. Read-only text access needs no fallback permission.\"}", false})
    std::optional<bool> allow_text_fallback;
    SHGREP_CONTRACT(Field{"{\"description\":\"After writing source files, request error diagnostics within a shared 3-second budget. Errors or unavailable checks produce warnings; writes remain applied unless on_new_errors=rollback. Default true; set false to skip.\"}", false})
    std::optional<bool> diagnostics;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default: the replaced file's; for new files, matching EditorConfig charset, then a unique majority among same-extension siblings, then utf-8. Unsupported configured charsets require an explicit encoding.\"}", false})
    std::optional<EnumText<WriteFileArgsEncodingChoice>> encoding;
    SHGREP_CONTRACT(Field{"{\"description\":\"Alias for line_endings; both must agree if provided.\"}", false})
    std::optional<EnumText<WriteFileArgsEolChoice>> eol;
    SHGREP_CONTRACT(Field{"{\"description\":\"Fail if the file's mtime (from read_file) changed.\"}", false})
    std::optional<std::string> expected_mtime;
    SHGREP_CONTRACT(Field{"{\"description\":\"SHA-256 from read_file metadata or file_info. Without it, an existing file must match this session's latest read or dry-run preview. The default REPL session shares this history. Use the same path spelling as the read; text search is not a read.\"}", false})
    std::optional<std::string> expected_sha256;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default: the replaced file's, or for new files EditorConfig, Git attributes, then sibling files; otherwise as given. Alias: eol.\"}", false})
    std::optional<EnumText<WriteFileArgsEolChoice>> line_endings;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default warn keeps the write and reports errors. rollback also reads error diagnostics before the write; when the write adds errors it restores the previous text (or removes a new file) and fails. Unavailable diagnostics keep the write with a warning.\"}", false})
    std::optional<EnumText<EditFileArgsOnNewErrorsChoice>> on_new_errors;
    SHGREP_CONTRACT(Field{"{\"description\":\"Replace an existing file.\"}", false})
    std::optional<bool> overwrite;
    SHGREP_CONTRACT(Field{"{\"description\":\"Diagnostic deadline, 1-300000; default 180000 when diagnostics=true.\"}", false})
    std::optional<int64_t> timeout_ms;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"delete_file", "Delete one file within the configured roots; no folders, no links. Needs a read, a dry_run preview or expected_sha256 first. References and imports are not checked: for code use lsp method=lsp.safe_delete_symbol.", 1, true, 8}) DeleteFileArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"Relative to the first root, or absolute inside a root.\"}", true})
    std::optional<std::string> path;
    SHGREP_CONTRACT(Field{"{\"description\":\"Preview and verify the target without deleting it.\"}", false})
    std::optional<bool> dry_run;
    SHGREP_CONTRACT(Field{"{\"description\":\"SHA-256 from read_file metadata or file_info. Without it, an existing file must match this session's latest read or dry-run preview. The default REPL session shares this history. Use the same path spelling as the read; text search is not a read.\"}", false})
    std::optional<std::string> expected_sha256;
    SHGREP_CONTRACT(Field{"{\"description\":\"Whole-request deadline, 1-300000 ms; default 30000.\"}", false})
    std::optional<int64_t> timeout_ms;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"move_file", "Move a file/folder; auto asks configured LSP servers for import edits when supported. Refactor requires that support; filesystem moves paths. File sources and overwritten destinations require a matching session read, preview, or explicit hash. Directory moves preserve content and invalidate path history. Active servers refresh after success. Links are never followed.", 1, true, 9}) MoveFileArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"Relative to the first root, or absolute inside a root.\"}", true})
    std::optional<std::string> source;
    SHGREP_CONTRACT(Field{"{\"description\":\"Relative to the first root, or absolute inside a root.\"}", true})
    std::optional<std::string> destination;
    SHGREP_CONTRACT(Field{"{\"description\":\"Preview import edits and move without writing.\"}", false})
    std::optional<bool> dry_run;
    SHGREP_CONTRACT(Field{"{\"description\":\"Expected overwritten file SHA-256; otherwise require this session's destination read or move preview. Requires overwrite=true.\"}", false})
    std::optional<std::string> expected_destination_sha256;
    SHGREP_CONTRACT(Field{"{\"description\":\"Fail if the file's mtime (from read_file) changed.\"}", false})
    std::optional<std::string> expected_mtime;
    SHGREP_CONTRACT(Field{"{\"description\":\"Expected source-file SHA-256; otherwise require this session's read or move preview.\"}", false})
    std::optional<std::string> expected_sha256;
    SHGREP_CONTRACT(Field{"{\"description\":\"Default auto. refactor requires willRenameFiles; filesystem bypasses semantic import edits.\"}", false})
    std::optional<EnumText<MoveFileArgsOperationChoice>> operation;
    SHGREP_CONTRACT(Field{"{\"description\":\"Replace an existing file; requires operation=filesystem.\"}", false})
    std::optional<bool> overwrite;
    SHGREP_CONTRACT(Field{"{\"description\":\"LSP deadline, 1-300000; default 180000 for semantic operations and 30000 for text/filesystem operations.\"}", false})
    std::optional<int64_t> timeout_ms;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"create_directory", "Create a folder and its parents (mkdir -p). Links are never followed.", 1, true, 10}) CreateDirectoryArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"Relative to the first root, or absolute inside a root.\"}", true})
    std::optional<std::string> path;
};

struct SHGREP_CONTRACT(Record{}) LspHelpArgs {
    SHGREP_CONTRACT(Field{"{\"default\":\"text\",\"description\":\"Default readable text; json returns method schemas/defaults, the method list, or a structured manual.\"}", false})
    std::optional<EnumText<LspHelpArgsFormatChoice>> format;
    SHGREP_CONTRACT(Field{"{\"description\":\"Whole request deadline; may instead be top-level.\",\"maximum\":300000,\"minimum\":1}", false})
    std::optional<int64_t> timeout_ms;
    SHGREP_CONTRACT(Field{"{\"description\":\"manual for the tool guide, a method name such as edit.replace_in_symbol for its fields, or a tool name such as search for every field that tool accepts.\"}", false})
    std::optional<std::string> topic;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"lsp", "Code navigation and symbol edits through language servers. Use it for a symbol's definition and every use, names that text search would also match in comments or other symbols, one symbol's code, renames, reference-checked deletes and symbol edits. Not for finding where something happens or a distinctive name (search with intent), or comments, strings, docs and config (search, edit_file). Main methods, fields in arguments: lsp.find_symbol {name_path_pattern, relative_path, include_body}; lsp.read_symbol {name_path, relative_path}; lsp.find_referencing_symbols {name_path, relative_path}; lsp.rename_symbol {name_path, relative_path, new_name}; edit.replace_in_symbol {name_path, relative_path, needle, repl}; edit.replace_symbol_body {name_path, relative_path, body}; edit.replace_outside_symbols {relative_path, needle, repl} for imports. Example: {\"method\":\"lsp.find_symbol\",\"arguments\":{\"name_path_pattern\":\"Foo\",\"relative_path\":\"src\"}}. name_path is parent/name (Class/Method), Name[0] for an overload, Foo#ctor for a kind. method=help lists every method; arguments.topic=<method> gives its fields, topic=manual the guide. Results that start with a partial note are incomplete: repeat the call. dry_run previews edits; edits check the session's latest read. Positions are 1-based with UTF-16 columns. Unavailable with --read-only.", 2, true, 11}) LspArgs {
    SHGREP_CONTRACT(Field{"{}", true})
    std::optional<std::string> method;
    SHGREP_CONTRACT(Field{"{\"description\":\"Named fields of the method; omit for help. A method's fields: method=help, arguments={\\\"topic\\\":\\\"<method>\\\"}. Unknown fields are refused with the accepted list.\",\"type\":\"object\"}", false})
    std::optional<Json> arguments;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional final response byte limit. Text output uses lossless continuation; structured JSON must fit. The smaller of this and a method limit applies.\",\"maximum\":1048576,\"minimum\":512}", false})
    std::optional<int64_t> max_output_bytes;
    SHGREP_CONTRACT(Field{"{\"description\":\"Whole request deadline including response encoding. May also be inside arguments; both values must agree. Default: 180000 ms for a ready target server, otherwise 300000 ms.\",\"maximum\":300000,\"minimum\":1}", false})
    std::optional<int64_t> timeout_ms;
};

struct SHGREP_CONTRACT(Record{}) SHGREP_CONTRACT(Tool{"repl", "Run persistent C++26 cells (Clang-Repl) that call shgrep's facades s.lsp, s.edit and s.fs. Use it for batches and computation across many tool results. Not for a single read, search or edit: call lsp, read_file or search directly. s.info(\"manual\") and s.info(\"<method>\") give the reference. Example: auto hits = s.lsp.find_symbol({{\"name_path_pattern\", \"Foo\"}}); hits[\"results\"].size() Omit the final semicolon to return a value. A cell that is one call in shgrep syntax with literal arguments, s::<3::fs~>read_file(\"a.cs\") for s.fs.read_file(\"a.cs\"), runs without the compiler. Other cells need the MSVC C++ Build Tools and a Windows SDK. session_id keeps declarations, at most 8 sessions; a compiler error, timeout or cancellation resets that session. Native code has OS access; --read-only disables execution.", 2, true, 12}) ReplArgs {
    SHGREP_CONTRACT(Field{"{\"description\":\"C++26 cell, at most 256 KiB. Use s.info() for facades. Facade calls may use shgrep syntax: s::<3::fs~>read_file(\\\"file.cs\\\") equals s.fs.read_file(\\\"file.cs\\\"). Omit the final expression's semicolon to return it.\",\"maxLength\":262144}", true})
    std::optional<std::string> code;
    SHGREP_CONTRACT(Field{"{\"description\":\"Opt in to resetting this session's worker after this many idle milliseconds; 0 disables it. The setting persists for this session when omitted. Reset clears saved declarations and is reported on the next call.\",\"maximum\":86400000,\"minimum\":0}", false})
    std::optional<int64_t> idle_reset_ms;
    SHGREP_CONTRACT(Field{"{\"description\":\"Optional final response byte limit. Text output uses lossless continuation; structured JSON must fit. Facade Values inside the cell remain complete; the smallest requested limit applies.\",\"maximum\":1048576,\"minimum\":512}", false})
    std::optional<int64_t> max_output_bytes;
    SHGREP_CONTRACT(Field{"{\"default\":\"default\",\"description\":\"Process-local C++ session key, 1-64 ASCII letters/digits/_/-. Default 'default'; at most 8 sessions.\",\"maxLength\":64,\"minLength\":1,\"pattern\":\"^[A-Za-z0-9_-]+$\"}", false})
    std::optional<std::string> session_id;
    SHGREP_CONTRACT(Field{"{\"default\":180000,\"description\":\"Whole request deadline including response encoding, 1-300000 ms, default 180000. Expiry/cancellation during cell execution terminates and resets this session's worker.\",\"maximum\":300000,\"minimum\":1}", false})
    std::optional<int64_t> timeout_ms;
};

} // namespace shgrep::contracts
#undef SHGREP_CONTRACT
