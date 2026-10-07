#include "cli.hpp"
#include "license.hpp"
#include "search.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>

namespace shgrep {
namespace {
std::atomic_bool cli_cancelled = false;
BOOL WINAPI on_console_signal(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        cli_cancelled.store(true);
        return TRUE;
    }
    return FALSE;
}
struct SignalHandler {
    SignalHandler() { SetConsoleCtrlHandler(on_console_signal, TRUE); }
    ~SignalHandler() { SetConsoleCtrlHandler(on_console_signal, FALSE); }
};
std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (!count) throw std::runtime_error("invalid command-line Unicode");
    std::string out(count, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), out.data(), count, nullptr, nullptr);
    return out;
}
void print(const std::string& value) { std::fwrite(value.data(), 1, value.size(), stdout); }
void usage() {
    print("shgrep: native filesystem search with Intel Hyperscan 5.4.2\n"
          "\n"
          "Usage:\n"
          "  shgrep search PATTERN [options]   Search file contents (regex by default)\n"
          "  shgrep search -e PATTERN [-e PATTERN...] [options]\n"
          "  shgrep search_bytes --pattern HEX [--pattern HEX...] [options]\n"
          "  shgrep find_files NAME [options]  Exact filename; wildcard NAME is a glob\n"
          "  shgrep find_files [--exact-name NAME | --substring TEXT | --glob GLOB] [options]\n"
          "  shgrep [--root DIR]...   Start the MCP STDIO server\n"
          "  shgrep --license         Print the bundled Hyperscan license\n"
          "\n"
          "Output (search): path:line:text lines, like rg/ug/tgrep\n"
          "  -l, --files-with-matches Print only paths of files with a match\n"
          "  --files-without-match    Print only paths of searched files without a match\n"
          "  -c, --count              Print path:N matching lines per file\n"
          "  --relative               Print paths relative to the single root\n"
          "  -A/-B/-C N               Lines of context after/before/around matches (max 100)\n"
          "  -N, --no-line-number     Omit line numbers\n"
          "  --output MODE            lines, files, files_without_match, count, or json\n"
          "  --json                   Structured JSON (byte offsets, pattern ids)\n"
          "\n"
          "Matching:\n"
          "  -F, --fixed-strings      Literal text (default for search: regex)\n"
          "  -E, --regex              Hyperscan regex; byte syntax for search_bytes\n"
          "  -i, --ignore-case        Case-insensitive matching\n"
          "  -w, --word-regexp        Whole-word matches\n"
          "  -v, --invert-match       Print lines that match no pattern\n"
          "  -U, --multiline          Matches may span lines\n"
          "  -e, --pattern TEXT       Add a pattern; repeat to search many in one pass\n"
          "\n"
          "Selection:\n"
          "  --root DIR               Search only inside this root; repeat for multiple roots\n"
          "  --whole                  Search the entire current drive instead of the current folder\n"
          "  -t, --type TYPE          File type such as cpp, py, rust, cs, cmake; repeatable\n"
          "  -g, --include GLOB       Include filename/path glob (whole-name match); repeatable\n"
          "  --exclude GLOB           Exclude filename/path glob; repeatable\n"
          "  --extension EXT          Restrict file extension; repeatable\n"
          "  --path-filter TEXT       Substring filter on relative path\n"
          "  --no-ignore              Ignore .gitignore and .ignore rules\n"
          "  --hidden                 Include hidden files and directories\n"
          "  --max-file-bytes N       Text file size limit, default 67108864\n"
          "\n"
          "Limits:\n"
          "  --max-results N          Default 100 (matches; files for -l/-c/find_files)\n"
          "  -m, --max-matches-per-file N  Default 20\n"
          "  --max-output-bytes N     Default 65536\n"
          "  --timeout-ms N           Default 30000; find_files defaults to 300000\n"
          "  --context-bytes N        JSON context bytes on each side, default 80\n"
          "\n"
          "Examples:\n"
          "  shgrep search \"TODO|FIXME\" -t cpp -C 2\n"
          "  shgrep search -F \"operator<<\" --root C:\\work -l\n"
          "  shgrep search_bytes --root C:\\work --pattern 4d5a --include *.exe\n"
          "  shgrep find_files --root C:\\work --glob *.sln\n");
}
void append(Json::Object& args, const std::string& key, const std::string& value) {
    auto it = args.find(key);
    if (it == args.end()) it = args.emplace(key, Json::Array{}).first;
    std::get<Json::Array>(it->second.value).emplace_back(value);
}
const Json& field(const Json::Object& object, const char* key) { return object.at(key); }
std::string grouped(uint64_t number) {
    std::string value = std::to_string(number);
    for (size_t pos = value.size(); pos > 3; pos -= 3) value.insert(pos - 3, 1, ',');
    return value;
}
void print_no_match(const std::string& name, const Json::Object& args, const SearchContext& context,
                    const Json::Object& summary) {
    const std::string& status = summary.at("status").string();
    const auto found = static_cast<uint64_t>(summary.at("matches_found").integer());
    if (name == "find_files") {
        print(status == "complete" ? "No files matched the requested filename and path filters.\n"
                                    : "No files returned (search status: " + status + ").\n");
    } else {
        const auto pattern = args.find("patterns");
        bool regex = false;
        if (auto mode = args.find("mode"); mode != args.end())
            regex = std::get_if<std::string>(&mode->second.value) && std::get<std::string>(mode->second.value) == "regex";
        if (found != 0) print("Matches were found, but none were returned within the output limit for ");
        else if (status == "complete") print(regex ? "No matches found for regex pattern(s): " : "No matches found for pattern(s): ");
        else print(regex ? "No matches returned for regex pattern(s): " : "No matches returned for pattern(s): ");
        if (pattern != args.end()) {
            if (auto list = std::get_if<Json::Array>(&pattern->second.value)) {
                for (size_t i = 0; i < list->size(); ++i) {
                    if (i) print(", ");
                    print((*list)[i].dump());
                }
            } else print(pattern->second.dump());
        } else if (auto one = args.find("pattern"); one != args.end()) print(one->second.dump());
        print(".\n");
    }
    print("Searched roots:\n");
    for (const auto& root : context.allowed_roots)
        print("  " + utf8(std::filesystem::absolute(root).lexically_normal().wstring()) + "\n");
    if (name != "find_files")
        print("Scanned " + grouped(static_cast<uint64_t>(summary.at("files_scanned").integer())) +
              " files in " + std::to_string(summary.at("elapsed_ms").integer()) + " ms.\n");
    if (status != "complete") print("Search status: " + status + " (results may be incomplete).\n");
    if (summary.at("file_errors").integer() != 0)
        print(grouped(static_cast<uint64_t>(summary.at("file_errors").integer())) + " file errors.\n");
}
std::string printable_line(const std::string& source, size_t begin, size_t end) {
    constexpr char digits[] = "0123456789abcdef";
    std::string line;
    line.reserve(end - begin);
    for (size_t i = begin; i < end; ++i) {
        unsigned char c = static_cast<unsigned char>(source[i]);
        if ((c < 0x20 && c != '\t') || c == 0x7f) {
            line += "\\x";
            line.push_back(digits[c >> 4]);
            line.push_back(digits[c & 15]);
        } else line.push_back(static_cast<char>(c));
    }
    return line;
}

void print_result(const std::string& name, const Json& result, const Json& request, const SearchContext& context) {
    const auto& root = result.object();
    const auto& results = field(root, "results").array();
    const auto& summary = field(root, "summary").object();
    if (results.empty()) {
        print_no_match(name, request.object(), context, summary);
    } else {
        bool multiple = false;
        if (auto patterns = request.get("patterns")) multiple = patterns->array().size() > 1;
        for (const auto& entry : results) {
            const auto& item = entry.object();
            std::string output = item.at("path").string();
            if (name != "find_files") {
                if (auto line = entry.get("line")) output += ":" + std::to_string(line->integer());
                else output += "@" + std::to_string(item.at("byte_start").integer());
                output += ":";
                if (auto text_context = entry.get("context")) {
                    const std::string& source = text_context->string();
                    size_t position = 0;
                    if (auto match = entry.get("context_match_start"))
                        position = static_cast<size_t>(match->integer());
                    else if (auto start = entry.get("context_start")) {
                        uint64_t offset = static_cast<uint64_t>(item.at("byte_start").integer());
                        uint64_t window = static_cast<uint64_t>(start->integer());
                        position = offset >= window ? static_cast<size_t>(offset - window) : 0;
                    }
                    position = std::min(position, source.size());
                    size_t begin = position == 0 ? std::string::npos : source.rfind('\n', position - 1);
                    begin = begin == std::string::npos ? 0 : begin + 1;
                    size_t end = source.find('\n', position);
                    if (end == std::string::npos) end = source.size();
                    while (end > begin && source[end - 1] == '\r') --end;
                    output += printable_line(source, begin, end);
                } else if (auto hex_context = entry.get("context_hex")) {
                    output += " hex:" + hex_context->string();
                }
                if (multiple) output += " [pattern " + std::to_string(item.at("pattern_id").integer()) + "]";
            }
            print(output + "\n");
        }
    }
    if (results.empty()) {
        if (auto selection = result.get("selection")) {
            const auto& counts = selection->object();
            if (name == "find_files") {
                print("Examined " + grouped(static_cast<uint64_t>(counts.at("regular_files_seen").integer())) +
                      " filenames in " + std::to_string(summary.at("elapsed_ms").integer()) + " ms; " +
                      grouped(static_cast<uint64_t>(counts.at("files_filtered").integer())) + " filtered; " +
                      grouped(static_cast<uint64_t>(counts.at("files_ignored").integer())) + " ignored; " +
                      grouped(static_cast<uint64_t>(counts.at("files_hidden").integer())) + " hidden; " +
                      grouped(static_cast<uint64_t>(counts.at("directories_pruned").integer())) +
                      " directories pruned; " +
                      grouped(static_cast<uint64_t>(counts.at("reparse_points_skipped").integer())) +
                      " reparse points skipped.\n");
            } else {
                print("Selection: " + grouped(static_cast<uint64_t>(counts.at("regular_files_seen").integer())) +
                      " regular files encountered; " +
                      grouped(static_cast<uint64_t>(counts.at("files_filtered").integer())) + " filtered; " +
                      grouped(static_cast<uint64_t>(counts.at("files_ignored").integer())) + " ignored; " +
                      grouped(static_cast<uint64_t>(counts.at("files_hidden").integer())) + " hidden; " +
                      grouped(static_cast<uint64_t>(counts.at("directories_pruned").integer())) +
                      " directories pruned; " +
                      grouped(static_cast<uint64_t>(counts.at("reparse_points_skipped").integer())) +
                      " reparse points skipped.\n");
            }
        }
    }
    for (const auto& skipped : field(root, "skipped_files").array()) {
        const auto& item = skipped.object();
        print("Skipped oversized text file: " + item.at("path").string() + " (" +
              grouped(static_cast<uint64_t>(item.at("size_bytes").integer())) +
              " bytes; text search did not inspect it).\n");
    }
    if (results.empty()) return;
    if (summary.at("status").string() != "complete")
        print("Search status: " + summary.at("status").string() + " (results may be incomplete).\n");
    if (summary.at("file_errors").integer() != 0)
        print(grouped(static_cast<uint64_t>(summary.at("file_errors").integer())) + " file errors.\n");
}
}

int run_cli(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    try {
        if (argc == 1) { usage(); return 0; }
        std::wstring command = argv[1];
        if (command == L"--help" || command == L"-h" || command == L"help") { usage(); return 0; }
        if (command == L"--version") { print("shgrep 0.1.0 (Intel Hyperscan 5.4.2)\n"); return 0; }
        if (command == L"--license") { print(hyperscan_license); return 0; }
        std::string name;
        if (command == L"search") name = "search";
        else if (command == L"search_bytes" || command == L"search-bytes") name = "search_bytes";
        else if (command == L"find_files" || command == L"find-files") name = "find_files";
        else throw std::runtime_error("unknown command; run shgrep --help");
        Json::Object args;
        SearchContext context;
        bool json = false, whole_drive = false;
        for (int i = 2; i < argc; ++i) {
            const std::wstring option = argv[i];
            if (option == L"--json") { json = true; continue; }
            if (option == L"--regex" || option == L"-E") { args["mode"] = "regex"; continue; }
            if (option == L"--fixed-strings" || option == L"-F") { args["mode"] = "literal"; continue; }
            if (option == L"--ignore-case" || option == L"-i") { args["case_insensitive"] = true; continue; }
            if (option == L"--word-regexp" || option == L"-w") { args["word"] = true; continue; }
            if (option == L"--files-with-matches" || option == L"-l") { args["output"] = "files"; continue; }
            if (option == L"--files-without-match") { args["output"] = "files_without_match"; continue; }
            if (option == L"--invert-match" || option == L"-v") { args["invert"] = true; continue; }
            if (option == L"--multiline" || option == L"-U") { args["multiline"] = true; continue; }
            if (option == L"--relative") { args["paths"] = "relative"; continue; }
            if (option == L"--count" || option == L"-c") { args["output"] = "count"; continue; }
            if (option == L"--no-line-number" || option == L"-N") { args["line_numbers"] = false; continue; }
            if (option == L"--sniff-all") { args["sniff_all"] = true; continue; }
            if (option == L"--line-numbers") { args["line_numbers"] = true; continue; }
            if (option == L"--no-ignore") { args["no_ignore"] = true; continue; }
            if (option == L"--hidden") { args["hidden"] = true; continue; }
            if (option == L"--whole") { whole_drive = true; continue; }
            if (option == L"--find-files")
                throw std::runtime_error("use: shgrep find_files NAME [--root DIR]");
            if (!option.empty() && option.front() != L'-') {
                if (name == "find_files") {
                    if (args.find("exact_name") != args.end() || args.find("substring") != args.end() ||
                        args.find("glob") != args.end())
                        throw std::runtime_error("specify one filename query for find_files");
                    if (option.find_first_of(L"*?") != std::wstring::npos) args["glob"] = utf8(option);
                    else args["exact_name"] = utf8(option);
                } else {
                    if (args.find("patterns") != args.end())
                        throw std::runtime_error("specify one positional pattern or repeat --pattern");
                    append(args, "patterns", utf8(option));
                }
                continue;
            }
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + utf8(option));
            std::wstring value = argv[++i];
            if (option == L"--root") context.allowed_roots.emplace_back(value);
            else if (option == L"--pattern" || option == L"-e") append(args, "patterns", utf8(value));
            else if (option == L"--include" || option == L"-g") append(args, "include", utf8(value));
            else if (option == L"--type" || option == L"-t") append(args, "types", utf8(value));
            else if (option == L"--output") args["output"] = utf8(value);
            else if (option == L"--exclude") append(args, "exclude", utf8(value));
            else if (option == L"--extension") append(args, "extensions", utf8(value));
            else if (option == L"--path-filter") args["path_filter"] = utf8(value);
            else if (option == L"--exact-name") args["exact_name"] = utf8(value);
            else if (option == L"--substring") args["substring"] = utf8(value);
            else if (option == L"--glob") args["glob"] = utf8(value);
            else {
                std::string key;
                if (option == L"--max-results") key = "max_results";
                else if (option == L"--max-matches-per-file") key = "max_matches_per_file";
                else if (option == L"--max-output-bytes") key = "max_output_bytes";
                else if (option == L"--max-file-bytes") key = "max_file_bytes";
                else if (option == L"--timeout-ms") key = "timeout_ms";
                else if (option == L"--context-bytes") key = "context_bytes";
                else if (option == L"--context-before-bytes") key = "context_before_bytes";
                else if (option == L"--context-after-bytes") key = "context_after_bytes";
                else if (option == L"--context" || option == L"-C") key = "context_lines";
                else if (option == L"--before-context" || option == L"-B") key = "before_lines";
                else if (option == L"--after-context" || option == L"-A") key = "after_lines";
                else if (option == L"--max-count" || option == L"-m") key = "max_matches_per_file";
                else throw std::runtime_error("unknown option: " + utf8(option));
                size_t consumed = 0;
                int64_t number = std::stoll(value, &consumed, 10);
                if (consumed != value.size()) throw std::runtime_error("invalid number for " + utf8(option));
                args[key] = number;
            }
        }
        if (whole_drive && !context.allowed_roots.empty())
            throw std::runtime_error("--whole cannot be combined with --root");
        if (context.allowed_roots.empty()) {
            auto current = std::filesystem::current_path();
            auto root = whole_drive ? current.root_path() : current;
            context.allowed_roots.push_back(root.empty() ? current : root);
        }
        cli_cancelled.store(false);
        SignalHandler handler;
        auto cancelled = std::shared_ptr<std::atomic_bool>(&cli_cancelled, [](std::atomic_bool*) {});
        if (json) args["output"] = "json";
        Json request(std::move(args));
        Json result = run_tool(name, request, context, cancelled);
        if (json) print(result.dump() + "\n");
        else if (const Json* text = result.get("text")) print(text->string());
        else print_result(name, result, request, context);
        const std::string& status = result.object().at("summary").object().at("status").string();
        return status == "cancelled" || status == "timeout" ? 3 : 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "shgrep: %s\n", error.what());
        return 2;
    }
}
}
