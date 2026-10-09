#include "search.hpp"
#include "backend.hpp"
#include "dfa.hpp"
#include "files.hpp"
#include "ignore.hpp"
#include "teddy.hpp"
#include "winfs.hpp"

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <hs.h>
#if defined(SHGREP_PCRE2)
#include <pcre2.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <exception>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <set>
#include <shared_mutex>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace shgrep {
namespace fs = std::filesystem;
namespace {
using Clock = std::chrono::steady_clock;
// Opt-in per-worker phase timing for the diagnostic "profile" argument. Each worker writes only its own slot,
// so the counters need no synchronization; alignas keeps slots on separate cache lines.
#pragma warning(push)
#pragma warning(disable : 4324)  // C4324 reports the alignas padding, which is the intent here.
struct alignas(64) WorkerProfile {
    int64_t wall = 0, busy = 0, list = 0, dir_open = 0, file_total = 0, file_open = 0, read = 0, scan = 0, close = 0;
    int64_t started = 0, finished = 0, slowest_file = 0;  // absolute ticks; slowest_file is a duration
    uint64_t files_opened = 0;
};
#pragma warning(pop)
int64_t ticks() {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return now.QuadPart;
}
int64_t ticks_to_us(int64_t t) {
    static const int64_t frequency = [] {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        return f.QuadPart;
    }();
    return t * 1000000 / frequency;
}
// Adds the elapsed ticks to *slot when stopped or destroyed; a null slot (profiling off) costs one branch.
class PhaseTimer {
public:
    explicit PhaseTimer(int64_t* slot) : slot_(slot), start_(slot ? ticks() : 0) {}
    ~PhaseTimer() { stop(); }
    PhaseTimer(const PhaseTimer&) = delete;
    PhaseTimer& operator=(const PhaseTimer&) = delete;
    void stop() {
        if (slot_) *slot_ += ticks() - start_;
        slot_ = nullptr;
    }
private:
    int64_t* slot_;
    int64_t start_;
};
int64_t* phase(WorkerProfile* p, int64_t WorkerProfile::*field) { return p ? &(p->*field) : nullptr; }
std::string text(const Json& obj, const char* key, const std::string& fallback = {}) {
    const Json* v = obj.get(key);
    if (!v) return fallback;
    return v->string();
}
bool boolean(const Json& obj, const char* key, bool fallback) {
    const Json* v = obj.get(key);
    return v ? v->boolean() : fallback;
}
uint32_t bounded(const Json& obj, const char* key, uint32_t fallback, uint32_t min, uint32_t max) {
    const Json* v = obj.get(key);
    if (!v) return fallback;
    int64_t n = v->integer();
    if (n < min || n > max) throw std::runtime_error(std::string(key) + " is out of range");
    return static_cast<uint32_t>(n);
}
std::vector<std::string> strings(const Json& obj, const char* key, size_t max_count = 1024, size_t max_length = 4096) {
    std::vector<std::string> out;
    const Json* v = obj.get(key);
    if (!v) return out;
    if (auto one = std::get_if<std::string>(&v->value)) out.push_back(*one);
    else for (const auto& item : v->array()) out.push_back(item.string());
    if (out.size() > max_count) throw std::runtime_error(std::string(key) + " contains too many values");
    for (const auto& s : out) if (s.size() > max_length) throw std::runtime_error(std::string(key) + " contains an oversized value");
    return out;
}
bool glob_match(const std::string& pattern, const std::string& value) {
    size_t p = 0, v = 0, star = std::string::npos, retry = 0;
    while (v < value.size()) {
        auto fold = [](char c) { return static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(c))); };
        if (p < pattern.size() && (pattern[p] == '?' || fold(pattern[p]) == fold(value[v]))) { ++p; ++v; }
        else if (p < pattern.size() && pattern[p] == '*') { star = p++; retry = v; }
        else if (star != std::string::npos) { p = star + 1; v = ++retry; }
        else return false;
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}
bool any_glob(const std::vector<std::string>& globs, const std::string& rel, const std::string& name) {
    for (const auto& g : globs) if (glob_match(g, rel) || (g.find('/') == std::string::npos && glob_match(g, name))) return true;
    return false;
}
char fold_ascii(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }
bool equals_folded(std::string_view a, std::string_view b) {
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) { return fold_ascii(x) == fold_ascii(y); });
}
struct Request {
    bool file_only = false, binary = false, insensitive = false, line = true;
    bool no_ignore = false, hidden = false, word = false, sniff_all = false, profile = false;
    bool invert = false, multiline = false, relative = false;
    bool use_index = false;  // search only: consult the snapshot index built by `shgrep index`
    bool block = false;      // lines output: show each match inside its enclosing function or class
    bool color = false;      // CLI terminal only: ANSI-colored paths, line numbers and matches
    uint32_t max_block_lines = 200;
    // output: "lines" (path:line:text), "files" (paths with a match), "files_without_match", "count" (path:N),
    // or "json".
    std::string mode = "regex", output = "lines", exact_name, substring, name_glob, path_filter;
    std::vector<std::string> patterns, includes, excludes, extensions, type_globs;
    std::vector<fs::path> roots;
    uint32_t max_results = 100, max_per_file = 20, max_output = 65536, timeout_ms = 30000;
    uint32_t context_before = 80, context_after = 80;
    uint32_t before_lines = 0, after_lines = 0;
    uint32_t max_line_bytes = 400;  // lines output: longer lines show a window around the match; 0 shows them whole
    uint64_t max_file_bytes = 67108864;
    Backend backend = Backend::automatic;
    // Set by run_tool, not parsed: directories, in walk path form, that are never entered (the pattern cache).
    std::vector<std::wstring> excluded_directories;
};
bool contains_folded(std::string_view hay, std::string_view needle) {
    if (needle.empty()) return true;
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end(),
                       [](char x, char y) { return fold_ascii(x) == fold_ascii(y); }) != hay.end();
}

// File types for the `types` filter, named as in ripgrep/tgrep where they overlap. Globs are space-separated
// and matched case-insensitively against the filename.
struct FileType {
    const char* name;
    const char* globs;
};
constexpr FileType file_types[] = {
    {"asm", "*.asm *.s *.S *.inc"},
    {"bat", "*.bat *.cmd"},
    {"c", "*.c *.h"},
    {"cmake", "CMakeLists.txt *.cmake"},
    {"cpp", "*.C *.cc *.cpp *.cxx *.c++ *.h *.H *.hh *.hpp *.hxx *.inl *.ipp *.tpp"},
    {"cs", "*.cs *.csx"},
    {"css", "*.css *.scss *.sass *.less"},
    {"go", "*.go"},
    {"h", "*.h *.hh *.hpp *.hxx *.inl"},
    {"html", "*.html *.htm *.xhtml"},
    {"java", "*.java"},
    {"js", "*.js *.mjs *.cjs *.jsx"},
    {"json", "*.json *.jsonc"},
    {"lua", "*.lua"},
    {"make", "Makefile makefile GNUmakefile *.mk *.mak"},
    {"md", "*.md *.markdown"},
    {"msbuild", "*.sln *.vcxproj *.vcxproj.filters *.csproj *.props *.targets"},
    {"proto", "*.proto"},
    {"ps", "*.ps1 *.psm1 *.psd1"},
    {"py", "*.py *.pyi *.pyw"},
    {"rust", "*.rs"},
    {"sh", "*.sh *.bash *.zsh"},
    {"sql", "*.sql"},
    {"toml", "*.toml"},
    {"ts", "*.ts *.tsx *.mts *.cts"},
    {"txt", "*.txt"},
    {"xml", "*.xml *.xaml *.xsd *.xsl"},
    {"yaml", "*.yaml *.yml"},
    // Aliases.
    {"python", "*.py *.pyi *.pyw"},
    {"rs", "*.rs"},
    {"csharp", "*.cs *.csx"},
    {"markdown", "*.md *.markdown"},
    {"powershell", "*.ps1 *.psm1 *.psd1"},
    {"javascript", "*.js *.mjs *.cjs *.jsx"},
    {"typescript", "*.ts *.tsx *.mts *.cts"},
    {"yml", "*.yaml *.yml"},
};

void append_type_globs(const std::string& type, std::vector<std::string>& globs) {
    for (const auto& known : file_types) {
        if (!equals_folded(type, known.name)) continue;
        std::string_view list = known.globs;
        while (!list.empty()) {
            size_t space = list.find(' ');
            globs.emplace_back(list.substr(0, space));
            if (space == std::string_view::npos) break;
            list.remove_prefix(space + 1);
        }
        return;
    }
    std::string names;
    for (const auto& known : file_types) {
        if (!names.empty()) names += ", ";
        names += known.name;
    }
    throw std::runtime_error("unknown file type \"" + type + "\"; known types: " + names);
}
// CONTRACT: argument names a tool accepts are exactly its advertised schema properties, plus the hidden
// "profile" diagnostic. Unknown names are errors, not ignored, so a misspelled or misplaced filter (say glob on
// search) cannot silently widen a search.
void reject_unknown_arguments(const std::string& tool, const Json& args) {
    static const auto accepted = [] {
        std::map<std::string, std::set<std::string>> names;
        const Json definitions = tool_definitions();  // SAFETY: named; ranging over a temporary's member dangles
        for (const auto& definition : definitions.array()) {
            const auto& object = definition.object();
            auto& known = names[object.at("name").string()];
            for (const auto& entry : object.at("inputSchema").object().at("properties").object()) known.insert(entry.first);
            known.insert("profile");
            known.insert("backend");
            known.insert("color");
        }
        return names;
    }();
    const auto& known = accepted.at(tool);
    for (const auto& entry : args.object()) {
        if (known.contains(entry.first)) continue;
        std::string valid;
        for (const auto& name : known) {
            if (name == "profile" || name == "backend" || name == "color") continue;
            if (!valid.empty()) valid += ", ";
            valid += name;
        }
        std::string name = entry.first.size() > 64 ? entry.first.substr(0, 64) + "..." : entry.first;
        throw std::runtime_error("unknown argument \"" + name + "\" for " + tool + "; valid arguments: " + valid);
    }
}

Request parse_request(const std::string& tool, const Json& args, const SearchContext& context) {
    args.object();
    reject_unknown_arguments(tool, args);
    Request r;
    r.file_only = tool == "find_files";
    r.binary = tool == "search_bytes";
    // CONTRACT: search defaults to regex like grep/rg/tgrep; search_bytes defaults to hex literals.
    r.mode = text(args, "mode", r.binary ? "literal" : "regex");
    if (r.mode != "literal" && r.mode != "regex") throw std::runtime_error("mode must be literal or regex");
    r.output = text(args, "output", r.binary ? "json" : "lines");
    if (r.file_only) {
        if (r.output != "lines" && r.output != "json") throw std::runtime_error("find_files output must be lines or json");
    } else if (r.binary) {
        if (r.output != "json" && r.output != "files" && r.output != "count")
            throw std::runtime_error("search_bytes output must be json, files, or count");
    } else if (r.output != "lines" && r.output != "files" && r.output != "files_without_match" &&
               r.output != "count" && r.output != "json") {
        throw std::runtime_error("output must be lines, files, files_without_match, count, or json");
    }
    r.word = boolean(args, "word", false);
    r.invert = boolean(args, "invert", false);
    r.multiline = boolean(args, "multiline", false);
    if (r.invert && (r.output == "json" || r.output == "files_without_match"))
        throw std::runtime_error("invert works with lines, files, and count output");
    const std::string paths = text(args, "paths", "relative");
    if (paths != "absolute" && paths != "relative") throw std::runtime_error("paths must be absolute or relative");
    r.relative = paths == "relative";
    r.sniff_all = boolean(args, "sniff_all", false);
    // A server started with --live-index searches through it unless the request says index: false.
    r.use_index = !r.file_only && !r.binary && boolean(args, "index", context.live_index);
    // CONTRACT: diagnostic for benchmarks; deliberately absent from tool_definitions so models never see it.
    r.profile = boolean(args, "profile", false);
    // CONTRACT: set only by the CLI for a terminal; absent from tool_definitions, like profile.
    r.color = boolean(args, "color", false);
    // CONTRACT: benchmark override, hidden like profile: auto (default, or SHGREP_BACKEND), hyperscan, teddy, dfa,
    // cuda, hip. An engine that cannot run the query is an error, never a silent substitute.
    if (args.get("backend")) {
        const auto backend = parse_backend(text(args, "backend"));
        if (!backend) throw std::runtime_error("backend must be auto, hyperscan, teddy, dfa, cuda, or hip");
        r.backend = *backend;
    } else if (!r.file_only) {
        r.backend = default_backend();
    }
    if (r.word && r.binary) throw std::runtime_error("word is supported by search only");
    r.block = !r.binary && !r.file_only && boolean(args, "block", false);
    r.max_block_lines = bounded(args, "max_block_lines", 200, 1, 100000);
    if (r.block && (r.output != "lines" || r.invert)) throw std::runtime_error("block works with lines output, without invert");
    uint32_t context_lines = bounded(args, "context_lines", 0, 0, 100);
    r.before_lines = bounded(args, "before_lines", context_lines, 0, 100);
    r.after_lines = bounded(args, "after_lines", context_lines, 0, 100);
    r.max_line_bytes = bounded(args, "max_line_bytes", 400, 0, 1048576);
    for (const auto& type : strings(args, "types", 32, 32)) append_type_globs(type, r.type_globs);
    r.insensitive = boolean(args, "case_insensitive", false);
    r.line = boolean(args, "line_numbers", !r.binary && !r.file_only);
    r.no_ignore = boolean(args, "no_ignore", false);
    r.hidden = boolean(args, "hidden", false);
    r.max_file_bytes = bounded(args, "max_file_bytes", 67108864, 1, 268435456);
    r.max_results = bounded(args, "max_results", 100, 1, 10000);
    r.max_per_file = bounded(args, "max_matches_per_file", 20, 1, 10000);
    r.max_output = bounded(args, "max_output_bytes", 65536, 512, 1048576);
    r.timeout_ms = bounded(args, "timeout_ms", r.file_only ? 300000 : 30000, 1, 300000);
    uint32_t context_bytes = bounded(args, "context_bytes", 80, 0, 1024);
    r.context_before = bounded(args, "context_before_bytes", context_bytes, 0, 1024);
    r.context_after = bounded(args, "context_after_bytes", context_bytes, 0, 1024);
    r.includes = strings(args, "include", 256);
    r.excludes = strings(args, "exclude", 256);
    r.extensions = strings(args, "extensions", 256, 32);
    r.path_filter = text(args, "path_filter");
    if (r.path_filter.size() > 4096) throw std::runtime_error("path_filter is too long");
    if (r.file_only) {
        r.exact_name = text(args, "exact_name");
        r.substring = text(args, "substring");
        r.name_glob = text(args, "glob");
        if (r.exact_name.size() > 4096 || r.substring.size() > 4096 || r.name_glob.size() > 4096)
            throw std::runtime_error("filename filter is too long");
    } else {
        r.patterns = strings(args, "patterns", 1000, 4096);
        if (r.patterns.empty()) r.patterns = strings(args, "pattern", 1, 4096);
        if (r.patterns.empty()) throw std::runtime_error("at least one pattern is required");
        for (const auto& p : r.patterns) {
            if (p.empty()) throw std::runtime_error("empty patterns are unsupported");
            if (!r.binary && (p.find('\0') != std::string::npos ||
                MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p.data(), static_cast<int>(p.size()), nullptr, 0) == 0))
                throw std::runtime_error("text patterns must be valid UTF-8 without NUL");
        }
        if (r.mode == "regex") for (const auto& p : r.patterns)
            if (p.find('\0') != std::string::npos) throw std::runtime_error("regex patterns cannot contain NUL; use byte escapes");
        if (r.binary && r.mode == "literal") {
            for (auto& p : r.patterns) {
                if (p.size() % 2) throw std::runtime_error("binary literal patterns must be even-length hex strings");
                std::string bytes;
                for (size_t i = 0; i < p.size(); i += 2) {
                    auto digit = [](char c) -> int {
                        if (c >= '0' && c <= '9') return c - '0';
                        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                        return -1;
                    };
                    int a = digit(p[i]), b = digit(p[i + 1]);
                    if (a < 0 || b < 0) throw std::runtime_error("binary literal patterns must be hex strings");
                    bytes.push_back(static_cast<char>((a << 4) | b));
                }
                p = std::move(bytes);
            }
        }
    }
    auto requested = strings(args, "roots", 64, 32768);
    if (requested.empty()) r.roots = context.allowed_roots;
    else for (const auto& s : requested) r.roots.push_back(native_path(s));
    if (r.roots.empty()) throw std::runtime_error("no roots configured");
    return r;
}

bool extension_passes(const Request& r, std::string_view name) {
    if (r.extensions.empty()) return true;
    auto dot = name.find_last_of('.');
    std::string_view ext = dot == std::string_view::npos ? std::string_view{} : name.substr(dot + 1);
    for (std::string_view candidate : r.extensions) {
        if (!candidate.empty() && candidate.front() == '.') candidate.remove_prefix(1);
        if (equals_folded(candidate, ext)) return true;
    }
    return false;
}

// PERF: rejects regular files on name-only criteria before the relative path is built.
bool type_passes(const Request& r, const std::string& name) {
    if (r.type_globs.empty()) return true;
    for (const auto& glob : r.type_globs) if (glob_match(glob, name)) return true;
    return false;
}

// PERF: on Windows the open is the expensive step of reading a file (antivirus filters run there), so text
// search skips files whose extension is an unambiguous binary format without opening them. Ambiguous ones
// (.bin, .dat, ...) are not listed; they still get the NUL probe. Request.sniff_all turns this off.
bool binary_extension(std::string_view name) {
    static constexpr std::string_view extensions[] = {
        "exe", "dll", "sys", "ocx", "obj", "o", "lib", "a", "so", "dylib", "pdb", "ilk", "exp", "idb", "pch",
        "ipch", "iobj", "ipdb", "winmd", "node", "class", "jar", "pyc", "pyo", "pyd", "wasm",
        "zip", "7z", "rar", "gz", "tgz", "bz2", "xz", "zst", "lz4", "cab", "msi", "nupkg", "whl", "iso",
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "tif", "tiff", "webp", "psd", "dds", "tga", "heic",
        "mp3", "wav", "ogg", "flac", "aac", "m4a", "mp4", "mkv", "avi", "mov", "wmv", "webm",
        "ttf", "otf", "woff", "woff2", "eot", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "sqlite", "sqlite3", "mdb", "accdb", "fbx", "blend", "spv", "pak", "bnk"};
    const size_t dot = name.find_last_of('.');
    if (dot == std::string_view::npos || dot + 1 == name.size() || name.size() - dot - 1 > 8) return false;
    const std::string_view ext = name.substr(dot + 1);
    for (std::string_view candidate : extensions)
        if (equals_folded(ext, candidate)) return true;
    return false;
}

bool name_prefilter(const Request& r, const std::string& name) {
    if (r.file_only && !r.exact_name.empty() && !equals_folded(name, r.exact_name)) return false;
    return extension_passes(r, name) && type_passes(r, name);
}

// CONTRACT: relative uses '/' separators.
bool path_passes(const Request& r, const std::string& relative, const std::string& name, bool directory) {
    if (any_glob(r.excludes, relative, name)) return false;
    if (directory) return true;
    if (r.file_only) {
        if (!r.exact_name.empty() && !equals_folded(name, r.exact_name)) return false;
        if (!r.substring.empty() && !contains_folded(name, r.substring) && !contains_folded(relative, r.substring)) return false;
        if (!r.name_glob.empty() && !glob_match(r.name_glob, name) && !glob_match(r.name_glob, relative)) return false;
    }
    if (!r.includes.empty() && !any_glob(r.includes, relative, name)) return false;
    if (!extension_passes(r, name) || !type_passes(r, name)) return false;
    if (!r.path_filter.empty() && !contains_folded(relative, r.path_filter)) return false;
    return true;
}
std::string regex_literal(const std::string& bytes, bool binary) {
    constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * (binary ? 4 : 2));
    for (unsigned char c : bytes) {
        if (binary) {
            out += "\\x";
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 15]);
        } else {
            if (c == '\\' || c == '.' || c == '^' || c == '$' || c == '|' ||
                c == '?' || c == '*' || c == '+' || c == '(' || c == ')' ||
                c == '[' || c == ']' || c == '{' || c == '}') out.push_back('\\');
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}
// COMPAT: CMake builds the bundled Hyperscan with /arch:AVX2 (or /arch:AVX512), including its own
// hs_valid_platform, so the CPU check lives here in code built for the baseline ISA and runs before any
// Hyperscan call. Without it an older CPU would fault on the first scan instead of getting an error.
void require_cpu() {
    const CpuFeatures& cpu = cpu_features();
#if defined(SHGREP_HS_AVX512)
    const bool supported = cpu.popcnt && cpu.bmi1 && cpu.bmi2 && cpu.avx2 && cpu.avx512bw;
#elif defined(SHGREP_HS_AVX2)
    const bool supported = cpu.popcnt && cpu.bmi1 && cpu.bmi2 && cpu.avx2;
#else
    const bool supported = cpu.ssse3;  // Hyperscan's baseline
#endif
    if (!supported)
        throw std::runtime_error("this CPU lacks the instruction set this shgrep build requires; "
                                 "rebuild with -DSHGREP_HS_ARCH=SSE");
}

// Everything that changes a compiled database. It is also the cache key.
struct CompileSpec {
    std::vector<std::string> patterns;
    bool binary = false, regex = false, insensitive = false, literal_api = false, som = false;
    // Requested engine, and whether the output depends on the order of same-end matches (lines, json). Neither is
    // part of the on-disk key: they never change the Hyperscan database.
    Backend backend = Backend::automatic;
    bool ordered = false;
    bool operator==(const CompileSpec&) const = default;
};

CompileSpec compile_spec(const Request& r) {
    CompileSpec spec;
    spec.patterns = r.patterns;
    spec.binary = r.binary;
    spec.regex = r.mode == "regex";
    spec.insensitive = r.insensitive;
    spec.backend = r.backend;
    spec.ordered = r.output == "lines" || r.output == "json";
    const bool ascii = std::all_of(r.patterns.begin(), r.patterns.end(), [](const std::string& p) {
        return std::all_of(p.begin(), p.end(), [](char c) { return static_cast<unsigned char>(c) < 0x80; });
    });
    // PERF: the literal API skips regex parsing and accepts any byte, but its caseless mode folds ASCII only,
    // so caseless non-ASCII text literals use the UTF-8 regex compiler instead.
    // COMPAT: Hyperscan 5.4.2 addLitExpression rejects a literal whose first byte is NUL as "empty"
    // (strcmp(expression, "") in compiler.cpp), although the length is passed separately; such byte patterns
    // go through the escaped-regex path instead.
    const bool leading_nul = std::any_of(r.patterns.begin(), r.patterns.end(),
                                         [](const std::string& p) { return !p.empty() && p.front() == '\0'; });
    spec.literal_api = !spec.regex && !leading_nul && (r.binary || !r.insensitive || ascii);
    // PERF: start-of-match tracking costs scan speed and stream state (performance.rst). json needs exact starts;
    // whole-word checks and multiline spans need them unless the literal length gives the start.
    spec.som = r.output == "json" || ((r.word || r.multiline) && !spec.literal_api);
    return spec;
}

bool env_off(const wchar_t* name) {
    wchar_t value[4] = {};
    return GetEnvironmentVariableW(name, value, 4) == 1 && value[0] == L'0';
}

bool env_on(const wchar_t* name) {
    wchar_t value[4] = {};
    return GetEnvironmentVariableW(name, value, 4) == 1 && value[0] == L'1';
}

// SHGREP_WORKERS=N (1-256) overrides the walk's thread count, one per active processor by default, for the
// worker-count sweep. Anything else is ignored.
unsigned env_workers() {
    wchar_t value[8] = {};
    const DWORD length = GetEnvironmentVariableW(L"SHGREP_WORKERS", value, 8);
    if (length == 0 || length >= 8) return 0;
    unsigned n = 0;
    for (DWORD i = 0; i < length; ++i) {
        if (value[i] < L'0' || value[i] > L'9') return 0;
        n = n * 10 + static_cast<unsigned>(value[i] - L'0');
    }
    return n >= 1 && n <= 256 ? n : 0;
}


// PERF: compiled Hyperscan databases persist across processes in <workspace>\.shgrep\db-cache, the workspace
// being the first configured root, so a CLI run does not pay the compile again (about 85 ms for 100 regexes).
// Owner-approved 2026-10-07; moved from %LOCALAPPDATA% into the workspace 2026-10-09.
// CONTRACT: only compiled patterns are stored, never file contents or results, so freshness is unaffected.
// Each file carries its full key (cache format, Hyperscan version, ISA build, every compile input) and is used
// only on an exact key match; hs_deserialize_database also rejects other versions and CPUs. Writes go to a
// temporary file and are renamed into place. --read-only loads existing entries but never writes into the
// workspace. Walks never enter the workspace's .shgrep directory. SHGREP_DB_CACHE=0 disables the cache.
constexpr size_t db_cache_files = 64;
constexpr auto db_cache_min_compile = std::chrono::milliseconds(5);
constexpr char db_cache_magic[8] = {'S', 'H', 'G', 'D', 'B', '0', '0', '1'};
constexpr wchar_t cache_directory_name[] = L".shgrep";

struct DbCache {
    std::wstring dir;  // empty: the cache is off
    bool writable = false;
};

// Resolved only when the in-memory database cache misses, so cached queries pay no extra open.
DbCache db_cache_for(const SearchContext& context) {
    if (env_off(L"SHGREP_DB_CACHE") || context.allowed_roots.empty()) return {};
    Handle h(CreateFileW(context.allowed_roots.front().c_str(), FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!h) return {};
    try {
        return {join_path(join_path(final_path(h.h), cache_directory_name), L"db-cache"), !context.read_only};
    } catch (const std::runtime_error&) {
        return {};
    }
}

std::string db_cache_key(const CompileSpec& spec) {
    std::string key = "shgrep-db-1|";
    key += hs_version();
#if defined(SHGREP_HS_AVX512)
    key += "|avx512|";
#elif defined(SHGREP_HS_AVX2)
    key += "|avx2|";
#else
    key += "|sse|";
#endif
    key += spec.binary ? 'b' : 't';
    key += spec.regex ? 'r' : 'l';
    key += spec.insensitive ? 'i' : 's';
    key += spec.literal_api ? 'a' : 'x';
    key += spec.som ? 'o' : 'n';
    for (const auto& p : spec.patterns) {
        key += '|';
        key += std::to_string(p.size());
        key += ':';
        key += p;
    }
    return key;
}

std::wstring db_cache_path(const std::wstring& dir, const std::string& key) {
    uint64_t hash = 1469598103934665603ull; // FNV-1a; the full key inside the file settles collisions
    for (unsigned char c : key) {
        hash ^= c;
        hash *= 1099511628211ull;
    }
    wchar_t name[32] = {};
    swprintf_s(name, L"\\%016llx.hsdb", static_cast<unsigned long long>(hash));
    return dir + name;
}

hs_database_t* load_cached_database(const std::wstring& dir, const std::string& key) {
    Handle file(CreateFileW(db_cache_path(dir, key).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file) return nullptr;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.h, &size) || size.QuadPart < 16 || size.QuadPart > (256ll << 20)) return nullptr;
    std::string data(static_cast<size_t>(size.QuadPart), '\0');
    for (size_t done = 0; done < data.size();) {
        DWORD got = 0;
        const auto want = static_cast<DWORD>(std::min<size_t>(data.size() - done, 1u << 20));
        if (!ReadFile(file.h, data.data() + done, want, &got, nullptr) || got == 0) return nullptr;
        done += got;
    }
    uint64_t key_length = 0;
    std::memcpy(&key_length, data.data() + 8, sizeof(key_length));
    if (std::memcmp(data.data(), db_cache_magic, sizeof(db_cache_magic)) != 0 || key_length != key.size() ||
        16 + key_length > data.size() || data.compare(16, key.size(), key) != 0) return nullptr;
    const size_t offset = 16 + key.size();
    hs_database_t* db = nullptr;
    if (hs_deserialize_database(data.data() + offset, data.size() - offset, &db) != HS_SUCCESS) return nullptr;
    return db;
}

void store_cached_database(const std::wstring& dir, const std::string& key, const hs_database_t* db) {
    char* serialized = nullptr;
    size_t length = 0;
    if (hs_serialize_database(db, &serialized, &length) != HS_SUCCESS) return;
    const std::unique_ptr<char, decltype(&std::free)> owned(serialized, &std::free);
    const std::wstring parent = dir.substr(0, dir.rfind(L'\\'));
    if (CreateDirectoryW(parent.c_str(), nullptr)) {
        // A new .shgrep directory ignores itself, so the cache never shows up as untracked files in git.
        Handle ignore(CreateFileW(join_path(parent, L".gitignore").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL, nullptr));
        DWORD put = 0;
        if (ignore) WriteFile(ignore.h, "*\n", 2, &put, nullptr);
    }
    CreateDirectoryW(dir.c_str(), nullptr);
    const std::wstring path = db_cache_path(dir, key);
    const std::wstring temp = path + L"." + std::to_wstring(GetCurrentProcessId()) + L"." +
                              std::to_wstring(GetCurrentThreadId()) + L".tmp";
    bool written = false;
    {
        Handle file(CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (file) {
            auto write_all = [&](const char* p, size_t n) {
                while (n) {
                    DWORD put = 0;
                    const auto want = static_cast<DWORD>(std::min<size_t>(n, 1u << 20));
                    if (!WriteFile(file.h, p, want, &put, nullptr) || put == 0) return false;
                    p += put;
                    n -= put;
                }
                return true;
            };
            const uint64_t key_length = key.size();
            std::string header(db_cache_magic, sizeof(db_cache_magic));
            header.append(reinterpret_cast<const char*>(&key_length), sizeof(key_length));
            header += key;
            written = write_all(header.data(), header.size()) && write_all(serialized, length);
        }
    }
    if (!written || !MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileW(temp.c_str());
        return;
    }
    // Keep the newest db_cache_files databases.
    WIN32_FIND_DATAW found{};
    HANDLE search = FindFirstFileW((dir + L"\\*.hsdb").c_str(), &found);
    if (search == INVALID_HANDLE_VALUE) return;
    std::vector<std::pair<uint64_t, std::wstring>> files;
    do {
        files.emplace_back((static_cast<uint64_t>(found.ftLastWriteTime.dwHighDateTime) << 32) |
                               found.ftLastWriteTime.dwLowDateTime, found.cFileName);
    } while (FindNextFileW(search, &found));
    FindClose(search);
    if (files.size() <= db_cache_files) return;
    std::sort(files.begin(), files.end());
    for (size_t i = 0; i + db_cache_files < files.size(); ++i) DeleteFileW((dir + L"\\" + files[i].second).c_str());
}

std::runtime_error unsupported_backend(Backend backend, const std::string& why) {
    return std::runtime_error(std::string("backend ") + backend_name(backend) + " cannot run this query: " + why);
}

// Null when Teddy can reproduce Hyperscan's report for the query; otherwise why it cannot.
const char* teddy_unsupported(const CompileSpec& spec) {
    if (!spec.literal_api) return "Teddy runs literal patterns only (mode literal; caseless literals must be ASCII)";
    if (spec.patterns.size() > Teddy::max_patterns) return "Teddy runs at most 64 patterns";
    if (!cpu_features().ssse3) return "Teddy needs SSSE3";
    return nullptr;
}

// Null when the query is one the DFA could run (its patterns may still be declined); otherwise why not.
const char* dfa_unsupported(const CompileSpec& spec) {
    if (spec.binary || !spec.regex) return "the DFA runs search regexes only";
    if (spec.som) return "the DFA does not track match starts (json output, word, multiline)";
    return nullptr;
}

struct Database {
    hs_database_t* db = nullptr;
    hs_scratch_t* scratch = nullptr; // prototype for hs_clone_scratch; never scanned with
    bool som = false, stream = false;
    std::vector<uint32_t> lengths;   // literal byte lengths by pattern id; empty for regex databases
    // Set when another engine scans text instead of db (see select_engine); db stays compiled as its fallback.
    std::unique_ptr<TextEngine> engine;
#if defined(SHGREP_PCRE2)
    // Set instead of db when Hyperscan rejected a text regex and PCRE2 accepted it: one code per pattern.
    std::vector<pcre2_code*> pcre;
    std::vector<bool> pcre_jit;
#endif
    ~Database() {
        if (scratch) hs_free_scratch(scratch);
        if (db) hs_free_database(db);
#if defined(SHGREP_PCRE2)
        for (pcre2_code* code : pcre) pcre2_code_free(code);
#endif
    }
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    Database(const CompileSpec& spec, const DbCache& cache) : som(spec.som), stream(spec.binary) {
        // PERF: text files are scanned as one in-memory block ("prefer block-based matching", performance.rst);
        // only search_bytes streams files in chunks.
        const unsigned mode = stream ? (HS_MODE_STREAM | (som ? HS_MODE_SOM_HORIZON_LARGE : 0)) : HS_MODE_BLOCK;
        const unsigned common = (spec.insensitive ? HS_FLAG_CASELESS : 0) | (som ? HS_FLAG_SOM_LEFTMOST : 0);
        const auto count = static_cast<unsigned>(spec.patterns.size());
        std::vector<std::string> expressions;
        std::vector<const char*> ptrs;
        std::vector<unsigned> flags(count, common), ids(count);
        std::vector<size_t> lens;
        for (unsigned i = 0; i < count; ++i) ids[i] = i;
        if (spec.literal_api)
            for (const auto& p : spec.patterns) lengths.push_back(static_cast<uint32_t>(p.size()));
        const std::string cache_key = cache.dir.empty() ? std::string() : db_cache_key(spec);
        if (!cache_key.empty()) db = load_cached_database(cache.dir, cache_key);
        if (db) {
            if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
                hs_free_database(db);
                db = nullptr;
                throw std::runtime_error("Hyperscan scratch allocation failed");
            }
            select_engine(spec);
            return;
        }
        const auto compile_start = Clock::now();
        hs_compile_error_t* error = nullptr;
        hs_error_t rc;
        if (spec.literal_api) {
            for (const auto& p : spec.patterns) {
                ptrs.push_back(p.data());
                lens.push_back(p.size());
            }
            rc = hs_compile_lit_multi(ptrs.data(), flags.data(), ids.data(), lens.data(), count, mode, nullptr, &db, &error);
        } else {
            // CONTRACT: text regexes are line-oriented like rg/tgrep: ^ and $ match at every line and '.' never
            // crosses '\n' (no HS_FLAG_DOTALL).
            const unsigned text = spec.binary ? 0 : (HS_FLAG_UTF8 | HS_FLAG_UCP | (spec.regex ? HS_FLAG_MULTILINE : 0));
            for (auto& f : flags) f |= text;
            expressions.reserve(count);
            for (const auto& p : spec.patterns) expressions.push_back(spec.regex ? p : regex_literal(p, spec.binary));
            for (const auto& e : expressions) ptrs.push_back(e.c_str());
            rc = hs_compile_multi(ptrs.data(), flags.data(), ids.data(), count, mode, nullptr, &db, &error);
        }
        if (rc != HS_SUCCESS) {
            std::string message = error && error->message ? error->message : "Hyperscan compilation failed";
            if (error && error->expression >= 0) message = "pattern " + std::to_string(error->expression) + ": " + message;
            if (error) hs_free_compile_error(error);
            db = nullptr;
#if defined(SHGREP_PCRE2)
            // CONTRACT: text regexes that Hyperscan rejects (backreferences, lookaround, \b under UCP, other
            // PCRE-only syntax) fall back to PCRE2 JIT, the engine ripgrep uses for -P. If PCRE2 rejects the
            // pattern too, its message is reported.
            if (spec.regex && !spec.binary) {
                if (spec.backend != Backend::automatic && spec.backend != Backend::hyperscan)
                    throw unsupported_backend(spec.backend, "Hyperscan rejects the pattern (" + message + "), so only PCRE2 can run it");
                compile_pcre(spec);
                return;
            }
#endif
            throw std::runtime_error(message);
        }
        if (error) hs_free_compile_error(error);
        if (!cache_key.empty() && cache.writable && Clock::now() - compile_start >= db_cache_min_compile)
            store_cached_database(cache.dir, cache_key, db);
        if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
            hs_free_database(db);
            db = nullptr;
            throw std::runtime_error("Hyperscan scratch allocation failed");
        }
        select_engine(spec);
    }

    // The compile-time half of backend dispatch: picks the engine that scans text for this query once Hyperscan
    // has compiled it. An explicit backend that cannot run the query is an error; auto keeps Hyperscan.
    void select_engine(const CompileSpec& spec) {
        const Backend want = spec.backend;
        if (want == Backend::hyperscan) return;
        if (want == Backend::teddy) {
            const char* why = teddy_unsupported(spec);
            if (!why) engine = Teddy::build(spec.patterns, spec.insensitive);
            if (!engine) throw unsupported_backend(want, why ? why : "Teddy rejected the patterns");
            return;
        }
        if (want == Backend::dfa) {
            // CONTRACT: without starts, the collector places a regex match at its last byte, so matches that end
            // together differ only in pattern id, which no output that the DFA serves shows; their order is free.
            const char* why = dfa_unsupported(spec);
            std::string declined;
            if (!why) engine = Dfa::build(spec.patterns, spec.insensitive, DfaLimits{}, declined);
            if (!engine) throw unsupported_backend(want, why ? std::string(why) : declined);
            return;
        }
        if (want == Backend::automatic) {
            // PERF: the DFA is not chosen automatically until benchmarks show where it beats Hyperscan.
            // PERF: up to Teddy::max_patterns text literals scan with the native AVX2 Teddy matcher; db stays
            // compiled as its fallback. Auto keeps Hyperscan where Teddy is unmeasured: without AVX2, and for
            // search_bytes. SHGREP_TEDDY=0 keeps auto off it.
            // CONTRACT: where two patterns can end at the same offset and the output shows which match came
            // first (lines focus, json per-file cap), auto keeps Hyperscan, whose order for such ties is undefined.
            if (!teddy_unsupported(spec) && !spec.binary && cpu_features().avx2 && !env_off(L"SHGREP_TEDDY")) {
                auto teddy = Teddy::build(spec.patterns, spec.insensitive);
                if (teddy && !(teddy->ties && spec.ordered)) engine = std::move(teddy);
            }
            return;
        }
        throw unsupported_backend(want, "not available in this build");
    }

#if defined(SHGREP_PCRE2)
    void compile_pcre(const CompileSpec& spec) {
        // CONTRACT: same line-oriented semantics as the Hyperscan path: UTF-8 with Unicode properties, ^ and $ at
        // every line, '.' never crossing '\n'.
        const uint32_t options = PCRE2_UTF | PCRE2_UCP | PCRE2_MULTILINE | (spec.insensitive ? PCRE2_CASELESS : 0);
        for (size_t i = 0; i < spec.patterns.size(); ++i) {
            int code = 0;
            PCRE2_SIZE offset = 0;
            pcre2_code* compiled = pcre2_compile(reinterpret_cast<PCRE2_SPTR>(spec.patterns[i].data()),
                                                 spec.patterns[i].size(), options, &code, &offset, nullptr);
            if (!compiled) {
                for (pcre2_code* earlier : pcre) pcre2_code_free(earlier);
                pcre.clear();
                PCRE2_UCHAR message[256] = {};
                pcre2_get_error_message(code, message, sizeof(message));
                throw std::runtime_error("pattern " + std::to_string(i) + ": " +
                                         reinterpret_cast<const char*>(message) + " at offset " + std::to_string(offset));
            }
            pcre.push_back(compiled);
            // PERF: JIT-compile the complete-match path; a pattern JIT cannot handle runs on the interpreter.
            pcre_jit.push_back(pcre2_jit_compile(compiled, PCRE2_JIT_COMPLETE) == 0);
        }
        // PCRE2 always reports exact start and end offsets.
        som = true;
        lengths.clear();
    }
#endif
};

// CONTRACT: caches compiled databases only, never file contents or results (CLAUDE.md "Allowed caching").
// Keyed by the full CompileSpec; least recently used entries are dropped past database_cache_entries.
std::shared_ptr<const Database> compiled_database(const Request& r, const SearchContext& context) {
    constexpr size_t database_cache_entries = 16;
    require_cpu();
    CompileSpec spec = compile_spec(r);
    static std::mutex mutex;
    static std::list<std::pair<CompileSpec, std::shared_ptr<const Database>>> cache;
    {
        std::lock_guard lock(mutex);
        for (auto it = cache.begin(); it != cache.end(); ++it) {
            if (it->first == spec) {
                cache.splice(cache.begin(), cache, it);
                return cache.front().second;
            }
        }
    }
    auto database = std::make_shared<const Database>(spec, db_cache_for(context));
    std::lock_guard lock(mutex);
    cache.emplace_front(std::move(spec), database);
    if (cache.size() > database_cache_entries) cache.pop_back();
    return database;
}

struct Event { unsigned id; uint64_t from, to; };
struct Collector {
    std::vector<Event> events;
    uint64_t found = 0;
    uint32_t max_per_file, remaining;
    bool full = false;
    // Count mode stores no events and never stops early; it counts distinct matching lines of `text`
    // (for bytes, where text is empty, every match counts).
    bool count_only = false;
    // COMPAT: Hyperscan rejects \b in UCP mode, so whole-word matching filters reported matches instead, like
    // rg -w: the bytes before and after must not be word characters. Non-ASCII bytes count as word characters.
    bool word = false;
    // Without SOM Hyperscan reports only end offsets: literal starts come from their lengths, and a regex
    // match is placed at its last byte, which is enough to find its line.
    bool som = true;
    const std::vector<uint32_t>* lengths = nullptr;
    // Lines output keeps the first match per line, so max_per_file and max_results count lines like rg -m.
    bool per_line = false;
    // Set when PCRE2 hit its match, depth or JIT stack limit, so the file was not fully searched.
    bool pcre_limit = false;
    std::string_view text;
    uint64_t line_end = 0, lines = 0;
    // Count output with several patterns also counts lines (matches, for bytes) per pattern id; empty otherwise.
    std::vector<uint64_t> pattern_lines, pattern_line_end;
    static bool word_byte(char c) {
        unsigned char u = static_cast<unsigned char>(c);
        return std::isalnum(u) || u == '_' || u >= 0x80;
    }
    static int callback(unsigned id, unsigned long long from, unsigned long long to, unsigned, void* raw) {
        auto& c = *static_cast<Collector*>(raw);
        if (!c.som) {
            const uint64_t length = c.lengths ? (*c.lengths)[id] : 1;
            from = to >= length ? to - length : 0;
        }
        if (c.word && ((from > 0 && from <= c.text.size() && word_byte(c.text[static_cast<size_t>(from - 1)])) ||
                       (to < c.text.size() && word_byte(c.text[static_cast<size_t>(to)]))))
            return 0;
        ++c.found;
        if (c.count_only) {
            if (!c.pattern_lines.empty()) {
                if (c.text.empty()) ++c.pattern_lines[id];
                else if (from >= c.pattern_line_end[id]) {
                    ++c.pattern_lines[id];
                    size_t newline = from < c.text.size() ? c.text.find('\n', static_cast<size_t>(from)) : std::string_view::npos;
                    c.pattern_line_end[id] = newline == std::string_view::npos ? c.text.size() + 1 : newline + 1;
                }
            }
            // Hyperscan reports matches in end-offset order, so a start before line_end is on a counted line.
            if (c.text.empty()) ++c.lines;
            else if (from >= c.line_end) {
                ++c.lines;
                size_t newline = from < c.text.size() ? c.text.find('\n', static_cast<size_t>(from)) : std::string_view::npos;
                c.line_end = newline == std::string_view::npos ? c.text.size() + 1 : newline + 1;
            }
            return 0;
        }
        if (c.per_line && !c.text.empty()) {
            // Matches arrive in end-offset order and never cross '\n', so a start before line_end is on a
            // line that already has an event.
            if (from < c.line_end) return 0;
            size_t newline = from < c.text.size() ? c.text.find('\n', static_cast<size_t>(from)) : std::string_view::npos;
            c.line_end = newline == std::string_view::npos ? c.text.size() + 1 : newline + 1;
        }
        if (c.events.size() < std::min(c.max_per_file, c.remaining)) c.events.push_back({id, from, to});
        else { c.full = true; return 1; }
        return 0;
    }
};

// Count output line: "path:N", plus " [id:N ...]" per matching pattern when several patterns were given.
std::string count_line(const std::string& display, const Collector& c) {
    std::string line = display + ":" + std::to_string(c.lines);
    if (!c.pattern_lines.empty()) {
        std::string parts;
        for (size_t id = 0; id < c.pattern_lines.size(); ++id) {
            if (!c.pattern_lines[id]) continue;
            if (!parts.empty()) parts.push_back(' ');
            parts += std::to_string(id) + ":" + std::to_string(c.pattern_lines[id]);
        }
        line += " [" + parts + "]";
    }
    return line + "\n";
}

// Lines of `text` that no match touches (rg -v), as events at each such line's first byte.
struct InvertedLines {
    std::vector<Event> events;  // at most `keep`
    uint64_t count = 0;         // all such lines
};
// CONTRACT: matched are match events in any order. A match touches the line holding its start and, when spans is
// set (multiline), every line up to its last byte.
InvertedLines invert_lines(std::string_view text, std::vector<Event> matched, uint32_t keep, bool spans) {
    std::sort(matched.begin(), matched.end(), [](const Event& a, const Event& b) { return a.from < b.from; });
    InvertedLines out;
    size_t next = 0, start = 0;
    uint64_t reach = 0;  // last byte touched by the matches seen so far
    bool seen = false;
    while (start < text.size()) {
        const size_t newline = text.find('\n', start);
        const size_t end = newline == std::string_view::npos ? text.size() : newline;  // the line is [start, end]
        for (; next < matched.size() && matched[next].from <= end; ++next) {
            const Event& m = matched[next];
            const uint64_t last = spans && m.to > m.from ? m.to - 1 : m.from;
            reach = seen ? std::max(reach, last) : last;
            seen = true;
        }
        if (!seen || reach < start) {
            ++out.count;
            if (out.events.size() < keep) out.events.push_back({0, start, start});
        }
        if (newline == std::string_view::npos) break;
        start = newline + 1;
    }
    return out;
}

bool seek(HANDLE h, uint64_t offset) {
    LARGE_INTEGER pos; pos.QuadPart = static_cast<LONGLONG>(offset);
    return SetFilePointerEx(h, pos, nullptr, FILE_BEGIN) != 0;
}

// CONTRACT: Sampling only classifies an already oversized file; it never proves text contents.
std::optional<bool> probe_binary(HANDLE h, uint64_t size) {
    std::array<char, 4096> sample{};
    if (!seek(h, 0)) return std::nullopt;
    DWORD got = 0;
    DWORD want = static_cast<DWORD>(std::min<uint64_t>(sample.size(), size));
    if (want && (!ReadFile(h, sample.data(), want, &got, nullptr) || got != want))
        return std::nullopt;
    if (got >= 2) {
        unsigned char first = static_cast<unsigned char>(sample[0]);
        unsigned char second = static_cast<unsigned char>(sample[1]);
        if ((first == 0xff && second == 0xfe) || (first == 0xfe && second == 0xff))
            return false;
    }
    if (std::find(sample.begin(), sample.begin() + got, '\0') != sample.begin() + got)
        return true;
    if (size > sample.size()) {
        if (!seek(h, size - sample.size())) return std::nullopt;
        if (!ReadFile(h, sample.data(), static_cast<DWORD>(sample.size()), &got, nullptr) ||
            got != static_cast<DWORD>(sample.size())) return std::nullopt;
        if (std::find(sample.begin(), sample.end(), '\0') != sample.end()) return true;
    }
    return false;
}
std::string read_window(HANDLE h, uint64_t start, uint64_t end) {
    if (end < start || end - start > 4096 || !seek(h, start)) return {};
    std::string out(static_cast<size_t>(end - start), '\0');
    DWORD read = 0;
    if (!out.empty() && !ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr)) return {};
    out.resize(read);
    return out;
}
std::string hex(const std::string& s) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out; out.reserve(s.size() * 2);
    for (unsigned char c : s) { out.push_back(digits[c >> 4]); out.push_back(digits[c & 15]); }
    return out;
}
// CONTRACT: strict UTF-8 (RFC 3629: no overlongs, surrogates, or code points above U+10FFFF), the same set
// MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS) accepts.
// PERF: ASCII runs are skipped 16 bytes at a time; MultiByteToWideChar ran at about 1 GB/s on source text.
// Length of the well-formed UTF-8 sequence at p[i] (lead byte >= 0x80), or 0 when it is not one. Same rules as
// valid_utf8: no overlongs, surrogates or code points above U+10FFFF.
size_t utf8_width(const unsigned char* p, size_t i, size_t n) {
    const unsigned char c = p[i];
    size_t length = 0;
    unsigned char low = 0x80, high = 0xbf;
    if (c >= 0xc2 && c <= 0xdf) length = 2;
    else if (c >= 0xe0 && c <= 0xef) {
        length = 3;
        if (c == 0xe0) low = 0xa0;
        else if (c == 0xed) high = 0x9f;
    } else if (c >= 0xf0 && c <= 0xf4) {
        length = 4;
        if (c == 0xf0) low = 0x90;
        else if (c == 0xf4) high = 0x8f;
    } else return 0;
    if (n - i < length || p[i + 1] < low || p[i + 1] > high) return 0;
    for (size_t k = 2; k < length; ++k)
        if ((p[i + k] & 0xc0) != 0x80) return 0;
    return length;
}

bool valid_utf8(std::string_view s) {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const size_t n = s.size();
    size_t i = 0;
    while (i < n) {
        if (i + 16 <= n) {
            const int mask = _mm_movemask_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i)));
            if (mask == 0) { i += 16; continue; }
            unsigned long first = 0;
            _BitScanForward(&first, static_cast<unsigned long>(mask));
            i += first;
        } else if (p[i] < 0x80) {
            ++i;
            continue;
        }
        const unsigned char c = p[i];
        size_t length = 0;
        unsigned char low = 0x80, high = 0xbf;
        if (c >= 0xc2 && c <= 0xdf) length = 2;
        else if (c >= 0xe0 && c <= 0xef) {
            length = 3;
            if (c == 0xe0) low = 0xa0;
            else if (c == 0xed) high = 0x9f;
        } else if (c >= 0xf0 && c <= 0xf4) {
            length = 4;
            if (c == 0xf0) low = 0x90;
            else if (c == 0xf4) high = 0x8f;
        } else return false;
        if (n - i < length || p[i + 1] < low || p[i + 1] > high) return false;
        for (size_t k = 2; k < length; ++k)
            if ((p[i + k] & 0xc0) != 0x80) return false;
        i += length;
    }
    return true;
}

struct DecodedText {
    std::string text;
    // UTF-16: one (decoded end, raw end) pair per code point.
    std::vector<std::pair<uint32_t, uint32_t>> boundaries;
    // Repaired UTF-8: valid bytes are copied verbatim, so offsets differ only after a U+FFFD; one (decoded end, raw
    // end) pair per replacement, and offsets between them map linearly.
    std::vector<std::pair<uint32_t, uint32_t>> anchors;
    uint32_t bom = 0;
    bool identity = true, sparse = false;

    uint64_t raw_offset(uint64_t decoded, bool end) const {
        if (identity) return bom + decoded;
        if (sparse) {
            // An offset inside a code point maps to its raw start, or its raw end when `end`, as below.
            size_t at = static_cast<size_t>(std::min<uint64_t>(decoded, text.size()));
            if (end) while (at < text.size() && (static_cast<unsigned char>(text[at]) & 0xc0) == 0x80) ++at;
            else while (at > 0 && at < text.size() && (static_cast<unsigned char>(text[at]) & 0xc0) == 0x80) --at;
            auto it = std::upper_bound(anchors.begin(), anchors.end(), at,
                [](size_t value, const auto& point) { return value < point.first; });
            if (it == anchors.begin()) return bom + at;
            --it;
            return it->second + (at - it->first);
        }
        if (decoded == 0) return bom;
        auto it = std::lower_bound(boundaries.begin(), boundaries.end(), decoded,
            [](const auto& point, uint64_t value) { return point.first < value; });
        if (it == boundaries.end()) return boundaries.empty() ? bom : boundaries.back().second;
        if (it->first == decoded) return it->second;
        return end ? it->second : (it == boundaries.begin() ? bom : (it - 1)->second);
    }
};

void append_codepoint(DecodedText& out, uint32_t cp, uint32_t raw_end) {
    if (cp <= 0x7f) out.text.push_back(static_cast<char>(cp));
    else if (cp <= 0x7ff) {
        out.text.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out.text.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
        out.text.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out.text.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.text.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
        out.text.push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out.text.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out.text.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.text.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
    out.boundaries.emplace_back(static_cast<uint32_t>(out.text.size()), raw_end);
}

DecodedText decode_text(std::string_view raw) {
    DecodedText out;
    const auto byte = [&](size_t i) { return static_cast<unsigned char>(raw[i]); };
    const bool utf16le = raw.size() >= 2 && byte(0) == 0xff && byte(1) == 0xfe;
    const bool utf16be = raw.size() >= 2 && byte(0) == 0xfe && byte(1) == 0xff;
    if (utf16le || utf16be) {
        out.identity = false;
        out.bom = 2;
        out.text.reserve(raw.size());
        const auto unit = [&](size_t i) -> uint16_t {
            return utf16le ? static_cast<uint16_t>(byte(i) | (byte(i + 1) << 8))
                           : static_cast<uint16_t>((byte(i) << 8) | byte(i + 1));
        };
        for (size_t i = 2; i < raw.size();) {
            uint32_t cp = 0xfffd;
            if (i + 1 < raw.size()) {
                cp = unit(i);
                i += 2;
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    if (i + 1 < raw.size()) {
                        uint32_t low = unit(i);
                        if (low >= 0xdc00 && low <= 0xdfff) {
                            cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                            i += 2;
                        } else cp = 0xfffd;
                    } else cp = 0xfffd;
                } else if (cp >= 0xdc00 && cp <= 0xdfff) cp = 0xfffd;
            } else ++i;
            append_codepoint(out, cp, static_cast<uint32_t>(i));
        }
        return out;
    }
    out.bom = raw.size() >= 3 && byte(0) == 0xef && byte(1) == 0xbb && byte(2) == 0xbf ? 3 : 0;
    const std::string_view body = raw.substr(out.bom);
    if (valid_utf8(body)) {
        out.text.assign(body);
        return out;
    }
    // PERF: lossy repair in bulk. Valid runs (ASCII skipped 16 bytes at a time) are copied verbatim and each
    // invalid byte becomes U+FFFD; only replacements record an offset anchor. Decoding per code point with a
    // boundary entry each took ~0.75 s and ~16 bytes of map per byte for a 60 MB file.
    out.identity = false;
    out.sparse = true;
    out.text.reserve(body.size() + body.size() / 8);
    const auto* p = reinterpret_cast<const unsigned char*>(body.data());
    const size_t n = body.size();
    size_t copied = 0, i = 0;
    while (i < n) {
        if (i + 16 <= n) {
            const int mask = _mm_movemask_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i)));
            if (mask == 0) { i += 16; continue; }
            unsigned long first = 0;
            _BitScanForward(&first, static_cast<unsigned long>(mask));
            i += first;
        } else if (p[i] < 0x80) {
            ++i;
            continue;
        }
        if (const size_t width = utf8_width(p, i, n)) {
            i += width;
            continue;
        }
        out.text.append(body.data() + copied, i - copied);
        out.text.append("\xef\xbf\xbd");
        copied = ++i;
        out.anchors.emplace_back(static_cast<uint32_t>(out.text.size()), static_cast<uint32_t>(out.bom + i));
    }
    out.text.append(body.data() + copied, n - copied);
    return out;
}
std::vector<uint64_t> lines_for(HANDLE h, const std::vector<Event>& events, std::vector<char>& buffer,
                                const std::shared_ptr<std::atomic_bool>& cancelled, Clock::time_point deadline,
                                std::string& state) {
    std::vector<uint64_t> lines(events.size(), 0);
    std::vector<size_t> order;
    order.reserve(events.size());
    for (size_t i = 0; i < events.size(); ++i) order.push_back(i);
    std::sort(order.begin(), order.end(), [&](size_t a, size_t b) { return events[a].from < events[b].from; });
    if (!seek(h, 0)) return lines;
    uint64_t line = 1, done = 0;
    for (size_t index : order) {
        while (done < events[index].from) {
            if (cancelled->load()) { state = "cancelled"; return lines; }
            if (Clock::now() >= deadline) { state = "timeout"; return lines; }
            DWORD want = static_cast<DWORD>(std::min<uint64_t>(buffer.size(), events[index].from - done)), got = 0;
            if (!ReadFile(h, buffer.data(), want, &got, nullptr) || got == 0) return lines;
            line += std::count(buffer.begin(), buffer.begin() + got, '\n');
            done += got;
        }
        lines[index] = line;
    }
    return lines;
}
Json::Object summary(uint64_t files, uint64_t bytes, uint64_t found, uint64_t returned,
                     uint64_t errors, uint64_t skipped_size, uint64_t skipped_binary,
                     uint64_t elapsed, const std::string& state) {
    return {{"files_scanned", files}, {"bytes_scanned", bytes}, {"matches_found", found},
            {"matches_returned", returned}, {"file_errors", errors},
            {"files_skipped_size", skipped_size}, {"files_skipped_binary", skipped_binary},
            {"elapsed_ms", elapsed}, {"truncated", state != "complete"}, {"status", state}};
}

constexpr size_t listing_buffer_bytes = 64 * 1024;
constexpr uint64_t text_memory_budget = 512ull << 20;
constexpr uint64_t small_text_bytes = 1ull << 20;
constexpr uint64_t binary_probe_bytes = 64 * 1024;
constexpr size_t retained_text_capacity = 8u << 20;

struct Control {
    std::shared_ptr<std::atomic_bool> cancelled;
    Clock::time_point deadline;
    std::atomic_bool stop{false};
    const char* interrupted() const {
        if (cancelled->load()) return "cancelled";
        if (Clock::now() >= deadline) return "timeout";
        return nullptr;
    }
};

// One file's rendered block for text output (lines, files, count).
// PERF: plain strings, not a Json object: map nodes cost an allocation each to build, to move while sorting
// (MSVC's map move allocates) and to free, which made sorting ~4,000 results take 3.5 ms.
struct TextBlock {
    std::string path, text;
    uint32_t units = 1;
};

// Request-wide results and counters shared by all workers.
struct Outcome {
    std::mutex mutex;
    Json::Array results;            // guarded by mutex; JSON output
    std::vector<TextBlock> blocks;  // guarded by mutex; text output
    Json::Array skipped_files;      // guarded by mutex
    std::string state = "complete"; // guarded by mutex
    size_t projected_bytes = 200;   // guarded by mutex
    size_t units = 0;               // guarded by mutex; matches, or files for files/count/find_files output
    std::exception_ptr failure;     // guarded by mutex
    std::atomic<size_t> returned{0};
    std::atomic<uint64_t> files{0}, bytes{0}, found{0}, errors{0}, skipped_size{0}, skipped_binary{0};
    std::atomic<uint64_t> regular_seen{0}, files_filtered{0}, files_ignored{0}, files_hidden{0};
    std::atomic<uint64_t> directories_pruned{0}, reparse_skipped{0};
    std::atomic<uint64_t> engine_fallbacks{0};  // files an engine failed on and Hyperscan rescanned
    std::atomic<uint64_t> index_missing{0};     // index candidates that no longer exist
    std::atomic_bool per_file_limited{false};
};

void finish(Outcome& out, Control& control, const char* state) {
    std::lock_guard lock(out.mutex);
    if (out.state == "complete") out.state = state;
    control.stop.store(true);
}

void fail(Outcome& out, Control& control, std::exception_ptr error) {
    std::lock_guard lock(out.mutex);
    if (!out.failure) out.failure = std::move(error);
    control.stop.store(true);
}

// A JSON-output item, or with `text` set a text-output block.
struct Candidate {
    Json item;
    size_t bytes;
    uint32_t units = 1;
    bool text = false;
    TextBlock block;
};

// Text-output candidate: `text` is one file's rendered block. bytes is its JSON-escaped size, which is what it
// costs inside the MCP response.
void add_text_candidate(std::vector<Candidate>& items, const std::string& display, std::string text, uint32_t units) {
    const size_t bytes = Json::escaped_size(text);
    items.push_back({Json(), bytes, units, true, TextBlock{display, std::move(text), units}});
}

// CONTRACT: called once per file; applies the request-wide result and output limits in arrival order.
// find_files JSON candidates carry bytes == 0 and are bounded by the final serialization pass instead.
void publish(const Request& r, Outcome& out, Control& control, std::vector<Candidate>& items, size_t content_budget) {
    if (items.empty()) return;
    std::lock_guard lock(out.mutex);
    for (auto& candidate : items) {
        if (out.state != "complete") break;
        if (out.units >= r.max_results) {
            out.state = "limit";
            control.stop.store(true);
            break;
        }
        if (candidate.bytes > content_budget || out.projected_bytes > content_budget - candidate.bytes) {
            out.state = "output_limit";
            control.stop.store(true);
            break;
        }
        out.projected_bytes += candidate.bytes;
        out.units += candidate.units;
        if (candidate.text) out.blocks.push_back(std::move(candidate.block));
        else out.results.push_back(std::move(candidate.item));
    }
    if (out.state == "complete" && out.units >= r.max_results) {
        out.state = "limit";
        control.stop.store(true);
    }
    out.returned.store(out.units);
}

// SAFETY: bounds the raw and decoded copies that concurrent text scans hold at once.
struct MemoryBudget {
    std::mutex mutex;
    std::condition_variable released;
    uint64_t in_use = 0;
    const uint64_t limit;

    explicit MemoryBudget(uint64_t bytes) : limit(bytes) {}
    // A single file larger than the budget still runs once nothing else holds memory.
    bool acquire(uint64_t bytes, const Control& control) {
        std::unique_lock lock(mutex);
        while (in_use != 0 && in_use + bytes > limit) {
            if (control.stop.load() || control.interrupted()) return false;
            released.wait_for(lock, std::chrono::milliseconds(20));
        }
        in_use += bytes;
        return true;
    }
    void release(uint64_t bytes) {
        {
            std::lock_guard lock(mutex);
            in_use -= bytes;
        }
        released.notify_all();
    }
};

// SAFETY: Hyperscan scratch is not thread-safe, so each worker owns a clone of the database prototype.
struct Worker {
    std::vector<char> buffer;  // 1 MiB chunk buffer for files over binary_probe_bytes; see chunk()
    // PERF: allocated on first use; zero-filling 1 MiB for every worker of every request cost ~1.5 ms of setup,
    // and small text files never touch it.
    std::vector<char>& chunk() {
        if (buffer.empty()) buffer.resize(1 << 20);
        return buffer;
    }
    // PERF: the whole-file read buffer is allocated without zero-filling (std::string::resize would memset it).
    std::unique_ptr<char[]> raw;
    size_t raw_capacity = 0;
    char* raw_buffer(size_t bytes) {
        if (bytes > raw_capacity || !raw) {
            raw = std::make_unique_for_overwrite<char[]>(std::max<size_t>(bytes, 1));
            raw_capacity = std::max<size_t>(bytes, 1);
        }
        return raw.get();
    }
    bool head_is_utf16() const {
        return raw_capacity >= 2 && ((static_cast<unsigned char>(raw[0]) == 0xff && static_cast<unsigned char>(raw[1]) == 0xfe) ||
                                     (static_cast<unsigned char>(raw[0]) == 0xfe && static_cast<unsigned char>(raw[1]) == 0xff));
    }
    void trim_raw() {
        if (raw_capacity > retained_text_capacity) {
            raw.reset();
            raw_capacity = 0;
        }
    }
    hs_scratch_t* scratch = nullptr;
    std::unique_ptr<EngineScratch> engine_scratch;  // the database engine's per-worker state, if it keeps any
    WorkerProfile* profile = nullptr;  // null unless the request asked for profile
    bool index_snapshot = false;       // scanning index candidates: a file deleted since the build is not an error
#if defined(SHGREP_PCRE2)
    // Worker-local PCRE2 state, created on first use.
    pcre2_match_data* pcre_match = nullptr;
    pcre2_match_context* pcre_context = nullptr;
    pcre2_jit_stack* pcre_stack = nullptr;
#endif
    Worker() = default;
    Worker(const Worker&) = delete;
    Worker& operator=(const Worker&) = delete;
    ~Worker() {
        if (scratch) hs_free_scratch(scratch);
#if defined(SHGREP_PCRE2)
        if (pcre_match) pcre2_match_data_free(pcre_match);
        if (pcre_context) pcre2_match_context_free(pcre_context);
        if (pcre_stack) pcre2_jit_stack_free(pcre_stack);
#endif
    }
};

struct ScanShared {
    const Request& r;
    const Database* database;
    Control& control;
    Outcome& out;
    MemoryBudget& memory;
    size_t content_budget;
    std::wstring relative_prefix;  // root plus separator, stripped from displayed paths; empty for absolute paths
};

// Appends text[start, end) for display: control bytes are escaped, and lines over max_line_bytes (0: no limit)
// are cut to a window starting a little before `focus` (the first match on a matched line).
// ANSI colors for the CLI's terminal output (request color, never set by MCP), as rg paints them.
// 24-bit colors, light enough for dark terminal themes.
constexpr const char* color_path = "\x1b[38;2;255;135;255m";     // light magenta #FF87FF
constexpr const char* color_line = "\x1b[38;2;135;255;135m";     // light green #87FF87
constexpr const char* color_match = "\x1b[1;38;2;255;95;135m";   // bold red-pink #FF5F87
constexpr const char* color_reset = "\x1b[0m";

std::string painted(const Request& r, const std::string& display) {
    return r.color ? color_path + display + color_reset : display;
}

void append_display_line(std::string& out, std::string_view text, size_t start, size_t end, size_t focus,
                         size_t max_line_bytes, const std::vector<std::pair<size_t, size_t>>* spans = nullptr) {
    const size_t lead_in = std::min<size_t>(100, max_line_bytes / 4);
    constexpr char digits[] = "0123456789abcdef";
    size_t from = start, to = end;
    if (max_line_bytes && end - start > max_line_bytes) {
        from = focus > start + lead_in ? focus - lead_in : start;
        while (from > start && (static_cast<unsigned char>(text[from]) & 0xc0) == 0x80) --from;
        to = std::min(end, from + max_line_bytes);
        while (to > from && to < end && (static_cast<unsigned char>(text[to]) & 0xc0) == 0x80) --to;
    }
    if (from > start) out += "...";
    // spans: sorted byte ranges of matches, painted while the bytes inside them are written.
    size_t span = 0;
    bool painting = false;
    for (size_t i = from; i < to; ++i) {
        if (spans) {
            while (span < spans->size() && (*spans)[span].second <= i) ++span;
            const bool inside = span < spans->size() && (*spans)[span].first <= i;
            if (inside != painting) {
                out += inside ? color_match : color_reset;
                painting = inside;
            }
        }
        unsigned char c = static_cast<unsigned char>(text[i]);
        if ((c < 0x20 && c != '\t') || c == 0x7f) {
            out += "\\x";
            out.push_back(digits[c >> 4]);
            out.push_back(digits[c & 15]);
        } else out.push_back(static_cast<char>(c));
    }
    if (painting) out += color_reset;
    if (to < end) out += "...";
}

// Renders one file as grep/rg/tgrep lines: "path:N:text" for matched lines, "path-N-text" for context lines,
// and "--" between non-adjacent groups.
// ---- Enclosing-block context -------------------------------------------------------------------------------------
// Owner-approved (2026-10-09): search's block option shows each match inside its whole enclosing function (or class
// when no function encloses it), so an agent reads exactly that code in one call.
// CONTRACT: a structural heuristic, not a parser. Brace languages: braces in comments, strings, character literals
// and preprocessor lines are skipped, but preprocessor branches with unbalanced braces can still mislead it.
// Python: indentation. A match with no enclosing function or class, a file of another language, or a block longer
// than max_block_lines keeps plain line context.
enum class BlockSyntax { none, braces, indent };

BlockSyntax block_syntax(std::string_view path) {
    const size_t dot = path.rfind('.');
    const size_t slash = path.find_last_of("/\\");
    if (dot == std::string_view::npos || (slash != std::string_view::npos && dot < slash)) return BlockSyntax::none;
    std::string ext(path.substr(dot + 1));
    for (char& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    static const std::set<std::string, std::less<>> braces{"c", "h", "cc", "cpp", "cxx", "c++", "hpp", "hh", "hxx",
        "h++", "inl", "ipp", "tpp", "cu", "cuh", "cs", "java", "js", "jsx", "mjs", "cjs", "ts", "tsx", "rs", "go",
        "swift", "kt", "kts", "scala", "php", "dart", "m", "mm", "groovy", "hlsl", "glsl", "fx", "shader"};
    if (braces.count(ext)) return BlockSyntax::braces;
    if (ext == "py" || ext == "pyw" || ext == "pyi") return BlockSyntax::indent;
    return BlockSyntax::none;
}

struct BraceBlock {
    size_t open, close, header;  // byte offsets of '{', its matching '}', and where its statement starts
};

// Every balanced brace block of `text`, ignoring braces in comments, strings, character literals and preprocessor
// lines; blocks are listed in order of their closing brace.
std::vector<BraceBlock> brace_blocks(std::string_view text, bool rust) {
    std::vector<BraceBlock> blocks;
    std::vector<std::pair<size_t, size_t>> open;  // '{' offset, statement start
    size_t statement = 0;
    bool line_start = true;
    const size_t n = text.size();
    const auto ident = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; };
    for (size_t i = 0; i < n; ++i) {
        const char c = text[i];
        if (c == '\n') { line_start = true; continue; }
        if (c == ' ' || c == '\t' || c == '\r') continue;
        const bool at_line_start = line_start;
        line_start = false;
        if (c == '#' && at_line_start && !rust) {
            // Preprocessor directive, with backslash continuations.
            while (i < n && text[i] != '\n') i += text[i] == '\\' && i + 1 < n ? 2 : 1;
            statement = i;
            line_start = true;
            continue;
        }
        if (c == '/' && i + 1 < n && text[i + 1] == '/') {
            while (i < n && text[i] != '\n') ++i;
            line_start = true;
            continue;
        }
        if (c == '/' && i + 1 < n && text[i + 1] == '*') {
            const size_t end = text.find("*/", i + 2);
            i = end == std::string_view::npos ? n : end + 1;
            continue;
        }
        if (c == '"') {
            if (i > 0 && text[i - 1] == 'R' && (i < 2 || !ident(text[i - 2]) || text[i - 2] == 'u' || text[i - 2] == 'U' ||
                                                text[i - 2] == 'L' || text[i - 2] == '8')) {
                // C++ raw string R"delim( ... )delim"
                const size_t paren = text.find('(', i + 1);
                if (paren != std::string_view::npos && paren - i <= 17) {
                    const std::string close = ")" + std::string(text.substr(i + 1, paren - i - 1)) + "\"";
                    const size_t end = text.find(close, paren + 1);
                    i = end == std::string_view::npos ? n : end + close.size() - 1;
                    continue;
                }
            }
            if (i > 0 && text[i - 1] == '@') {
                // C# verbatim string: "" is a quote, no escapes.
                for (++i; i < n; ++i) {
                    if (text[i] != '"') continue;
                    if (i + 1 < n && text[i + 1] == '"') { ++i; continue; }
                    break;
                }
                continue;
            }
            if (rust && i > 0 && (text[i - 1] == 'r' || text[i - 1] == '#')) {
                // Rust raw string r#"..."#: count the hashes before the quote.
                size_t hashes = 0, at = i;
                while (at > 0 && text[at - 1] == '#') { --at; ++hashes; }
                if (at > 0 && text[at - 1] == 'r') {
                    const std::string close = "\"" + std::string(hashes, '#');
                    const size_t end = text.find(close, i + 1);
                    i = end == std::string_view::npos ? n : end + close.size() - 1;
                    continue;
                }
            }
            for (++i; i < n && text[i] != '"'; ++i) {
                if (text[i] == '\\') ++i;
                else if (text[i] == '\n' && !rust) break;  // unterminated: stop at the line end
            }
            continue;
        }
        if (c == '\'') {
            if (rust && i + 2 < n && ident(text[i + 1]) && text[i + 2] != '\'') continue;  // lifetime 'a
            size_t j = i + 1;
            while (j < n && j - i <= 12 && text[j] != '\'' && text[j] != '\n') j += text[j] == '\\' ? 2 : 1;
            if (j < n && text[j] == '\'') i = j;
            continue;
        }
        if (c == '`') {
            for (++i; i < n && text[i] != '`'; ++i)
                if (text[i] == '\\') ++i;
            continue;
        }
        if (c == '{') {
            open.emplace_back(i, statement);
            statement = i + 1;
            continue;
        }
        if (c == '}') {
            if (!open.empty()) {
                blocks.push_back({open.back().first, i, open.back().second});
                open.pop_back();
            }
            statement = i + 1;
            continue;
        }
        if (c == ';') statement = i + 1;
    }
    return blocks;
}

// The first identifier of a block header, skipping comments, template<...> and attributes.
std::string_view header_word(std::string_view header) {
    size_t i = 0;
    const size_t n = header.size();
    while (i < n) {
        const char c = header[i];
        if (std::isspace(static_cast<unsigned char>(c))) { ++i; continue; }
        if (c == '/' && i + 1 < n && header[i + 1] == '/') {
            while (i < n && header[i] != '\n') ++i;
            continue;
        }
        if (c == '/' && i + 1 < n && header[i + 1] == '*') {
            const size_t end = header.find("*/", i + 2);
            i = end == std::string_view::npos ? n : end + 2;
            continue;
        }
        if (c == '[' || c == '@' || c == '#') {  // [[attribute]], [Attribute], @Annotation, #[attr]
            int depth = 0;
            for (; i < n; ++i) {
                if (header[i] == '[' || header[i] == '(') ++depth;
                else if ((header[i] == ']' || header[i] == ')') && --depth <= 0) { ++i; break; }
                else if (depth == 0 && std::isspace(static_cast<unsigned char>(header[i]))) break;
            }
            continue;
        }
        size_t end = i;
        while (end < n && (std::isalnum(static_cast<unsigned char>(header[end])) || header[end] == '_')) ++end;
        const std::string_view word = header.substr(i, end - i);
        if (word == "template" || word == "export") {
            i = end;
            if (word == "template") {
                int depth = 0;
                for (; i < n; ++i) {
                    if (header[i] == '<') ++depth;
                    else if (header[i] == '>' && --depth <= 0) { ++i; break; }
                }
            }
            continue;
        }
        return word;
    }
    return {};
}

bool control_word(std::string_view word) {
    static const std::set<std::string, std::less<>> words{"if", "else", "for", "foreach", "while", "do", "switch",
        "catch", "try", "finally", "return", "case", "default", "lock", "using", "synchronized", "match", "loop",
        "unsafe", "select", "defer", "go", "with", "fixed", "checked", "unchecked"};
    return words.count(word) != 0;
}

bool type_word(std::string_view word) {
    static const std::set<std::string, std::less<>> words{"class", "struct", "union", "enum", "interface", "impl",
        "trait", "record", "object", "protocol", "extension", "mod"};
    return words.count(word) != 0;
}

// Lines [first, last] (1-based) of the block enclosing byte `offset`, or nullopt.
std::optional<std::pair<uint64_t, uint64_t>> enclosing_block(std::string_view text, const std::vector<size_t>& line_starts,
                                                             BlockSyntax syntax, const std::vector<BraceBlock>& blocks,
                                                             size_t offset) {
    const auto line_of = [&](size_t at) {
        return static_cast<uint64_t>(std::upper_bound(line_starts.begin(), line_starts.end(), at) - line_starts.begin());
    };
    if (syntax == BlockSyntax::braces) {
        const BraceBlock* function = nullptr;
        const BraceBlock* type = nullptr;
        for (const auto& block : blocks) {
            if (!(block.open < offset && offset <= block.close) && !(block.header <= offset && offset <= block.open))
                continue;
            const std::string_view header = text.substr(block.header, block.open - block.header);
            const std::string_view word = header_word(header);
            if (word == "namespace" || word == "extern" || control_word(word)) continue;
            if (type_word(word)) {
                if (!type || block.open > type->open) type = &block;  // innermost type
                continue;
            }
            if (header.find('(') != std::string_view::npos && (!function || block.open < function->open))
                function = &block;  // outermost function
        }
        const BraceBlock* chosen = function ? function : type;
        if (!chosen) return std::nullopt;
        size_t start = chosen->header;
        while (start < chosen->open && std::isspace(static_cast<unsigned char>(text[start]))) ++start;
        return std::make_pair(line_of(start), line_of(chosen->close));
    }
    if (syntax != BlockSyntax::indent) return std::nullopt;
    const uint64_t lines = line_starts.size();
    const auto line_text = [&](uint64_t line) {
        const size_t begin = line_starts[line - 1];
        const size_t end = line < lines ? line_starts[line] : text.size();
        return text.substr(begin, end - begin);
    };
    const auto indent = [&](std::string_view s, bool& blank) {
        size_t i = 0;
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        blank = i == s.size() || s[i] == '\n' || s[i] == '\r' || s[i] == '#';
        return i;
    };
    const auto keyword = [](std::string_view s, size_t at) {
        const std::string_view rest = s.substr(at);
        return rest.rfind("def ", 0) == 0 || rest.rfind("async def ", 0) == 0 ? 1 : rest.rfind("class ", 0) == 0 ? 2 : 0;
    };
    const uint64_t hit = line_of(offset);
    bool blank = false;
    size_t limit = indent(line_text(hit), blank) + 1;  // the hit line itself may be the def
    uint64_t def_line = 0, class_line = 0;
    size_t def_indent = 0, class_indent = 0;
    for (uint64_t line = hit; line >= 1; --line) {
        const std::string_view s = line_text(line);
        const size_t at = indent(s, blank);
        if (blank || at >= limit) continue;
        limit = at;
        const int kind = keyword(s, at);
        if (kind == 1) { def_line = line; def_indent = at; }                           // ends at the outermost def
        else if (kind == 2 && !class_line) { class_line = line; class_indent = at; }  // innermost class
        if (at == 0) break;
    }
    if (!def_line && !class_line) return std::nullopt;
    uint64_t first = def_line ? def_line : class_line;
    const size_t base = def_line ? def_indent : class_indent;
    while (first > 1) {  // decorators
        const std::string_view s = line_text(first - 1);
        const size_t at = indent(s, blank);
        if (at != base || at >= s.size() || s[at] != '@') break;
        --first;
    }
    uint64_t last = def_line ? def_line : class_line;
    for (uint64_t line = last + 1; line <= lines; ++line) {
        const std::string_view s = line_text(line);
        const size_t at = indent(s, blank);
        if (blank) continue;
        if (at <= base) break;
        last = line;
    }
    return std::make_pair(first, last);
}

std::string render_lines(const Request& r, const std::string& display, std::string_view text, std::vector<Event> events) {
    std::sort(events.begin(), events.end(), [](const Event& a, const Event& b) { return a.from < b.from; });
    struct Hit { uint64_t line; size_t focus; };
    std::vector<Hit> hits;
    size_t cursor = 0;
    uint64_t line = 1;
    for (const auto& event : events) {
        const size_t from = static_cast<size_t>(std::min<uint64_t>(event.from, text.size()));
        for (;;) {
            size_t newline = text.find('\n', cursor);
            if (newline == std::string_view::npos || newline >= from) break;
            ++line;
            cursor = newline + 1;
        }
        if (hits.empty() || hits.back().line != line) hits.push_back({line, from});
        if (r.multiline && event.to > event.from + 1) {
            // Like rg -U: every line a match spans is a matched line.
            const size_t last = static_cast<size_t>(std::min<uint64_t>(event.to - 1, text.size()));
            size_t at = from;
            uint64_t spanned = line;
            for (;;) {
                size_t newline = text.find('\n', at);
                if (newline == std::string_view::npos || newline >= last) break;
                at = newline + 1;
                hits.push_back({++spanned, at});
            }
        }
    }
    if (r.multiline) {
        std::stable_sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) { return a.line < b.line; });
        hits.erase(std::unique(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) { return a.line == b.line; }),
                   hits.end());
    }
    struct Range { uint64_t first, last; };
    std::vector<Range> ranges;
    const BlockSyntax syntax = r.block ? block_syntax(display) : BlockSyntax::none;
    std::vector<size_t> line_starts;
    std::vector<BraceBlock> blocks;
    if (syntax != BlockSyntax::none) {
        line_starts.push_back(0);
        for (size_t i = 0; i < text.size(); ++i)
            if (text[i] == '\n') line_starts.push_back(i + 1);
        if (syntax == BlockSyntax::braces) {
            const bool rust = display.size() >= 3 && display.compare(display.size() - 3, 3, ".rs") == 0;
            blocks = brace_blocks(text, rust);
        }
    }
    std::vector<Range> wanted;
    for (const auto& hit : hits) {
        if (syntax != BlockSyntax::none) {
            const auto block = enclosing_block(text, line_starts, syntax, blocks, hit.focus);
            if (block && block->second - block->first < r.max_block_lines) {
                wanted.push_back({block->first, block->second});
                continue;
            }
        }
        wanted.push_back({hit.line > r.before_lines ? hit.line - r.before_lines : 1, hit.line + r.after_lines});
    }
    // Blocks can start before an earlier hit's range, so ranges are ordered before merging.
    std::sort(wanted.begin(), wanted.end(), [](const Range& a, const Range& b) { return a.first < b.first; });
    for (const auto& range : wanted) {
        if (!ranges.empty() && range.first <= ranges.back().last + 1) ranges.back().last = std::max(ranges.back().last, range.last);
        else ranges.push_back(range);
    }
    const std::string path = painted(r, display);
    std::vector<std::pair<size_t, size_t>> spans;
    if (r.color) {
        for (const auto& event : events)
            if (event.to > event.from) spans.emplace_back(static_cast<size_t>(event.from), static_cast<size_t>(event.to));
        std::sort(spans.begin(), spans.end());
    }
    std::string out;
    size_t pos = 0, hit_index = 0;
    uint64_t number = 1;
    bool exhausted = false;
    for (size_t group = 0; group < ranges.size() && !exhausted; ++group) {
        while (!exhausted && number < ranges[group].first) {
            size_t newline = text.find('\n', pos);
            if (newline == std::string_view::npos) exhausted = true;
            else { pos = newline + 1; ++number; }
        }
        if (exhausted || pos >= text.size()) break;
        // Like rg, groups are separated only when context lines were requested.
        if (group && (r.before_lines || r.after_lines || r.block)) out += "--\n";
        while (!exhausted && pos < text.size() && number <= ranges[group].last) {
            size_t newline = text.find('\n', pos);
            size_t end = newline == std::string_view::npos ? text.size() : newline;
            size_t shown_end = end;
            while (shown_end > pos && text[shown_end - 1] == '\r') --shown_end;
            while (hit_index < hits.size() && hits[hit_index].line < number) ++hit_index;
            const bool matched = hit_index < hits.size() && hits[hit_index].line == number;
            const char separator = matched ? ':' : '-';
            out += path;
            out.push_back(separator);
            if (r.line) {
                if (r.color) out += color_line;
                out += std::to_string(number);
                if (r.color) out += color_reset;
                out.push_back(separator);
            }
            append_display_line(out, text, pos, shown_end, matched ? hits[hit_index].focus : pos, r.max_line_bytes,
                                r.color ? &spans : nullptr);
            out.push_back('\n');
            if (newline == std::string_view::npos) exhausted = true;
            else { pos = newline + 1; ++number; }
        }
    }
    return out;
}

// PERF: one SSE2 pass (baseline x64) finds NUL bytes and any byte >= 0x80, so pure-ASCII text, the common
// case for source code, needs neither UTF-8 validation nor decoding.
struct ByteScan {
    bool nul = false, non_ascii = false;
};
ByteScan scan_bytes(std::string_view s) {
    const char* p = s.data();
    const size_t n = s.size();
    const __m128i zero = _mm_setzero_si128();
    int high = 0, nul = 0;
    size_t i = 0;
    for (; i + 16 <= n; i += 16) {
        const __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i));
        high |= _mm_movemask_epi8(v);
        nul |= _mm_movemask_epi8(_mm_cmpeq_epi8(v, zero));
    }
    for (; i < n; ++i) {
        const auto c = static_cast<unsigned char>(p[i]);
        high |= c & 0x80;
        nul |= c == 0;
    }
    return {nul != 0, high != 0};
}

// The text Hyperscan scans: the raw read buffer itself (zero-copy) or a decoded copy, with offsets mapped back
// to the file either way.
struct TextView {
    std::string_view text;
    const DecodedText* decoded = nullptr; // null on the zero-copy path
    uint32_t bom = 0;
    uint64_t raw_offset(uint64_t at, bool end) const { return decoded ? decoded->raw_offset(at, end) : bom + at; }
};

#if defined(SHGREP_PCRE2)
// Runs the PCRE2 fallback over one file and feeds matches to the collector in end-offset order, as Hyperscan
// would. Lines and count output need only the first match on a line, so the search jumps to the next line after
// each match; json output keeps every match up to the per-file limit. The full subject is always passed with a
// start offset, so lookbehind still sees text before the starting point.
void pcre_scan(const Database& db, Worker& w, std::string_view text, Collector& c, bool files_only) {
    if (!w.pcre_match) {
        w.pcre_match = pcre2_match_data_create(1, nullptr);
        w.pcre_context = pcre2_match_context_create(nullptr);
        // PERF: the default 32 KiB JIT stack fails on deep patterns; let it grow up to 8 MiB per worker.
        w.pcre_stack = pcre2_jit_stack_create(32 * 1024, 8 * 1024 * 1024, nullptr);
        if (!w.pcre_match || !w.pcre_context || !w.pcre_stack) throw std::runtime_error("PCRE2 allocation failed");
        pcre2_jit_stack_assign(w.pcre_context, nullptr, w.pcre_stack);
    }
    const auto subject = reinterpret_cast<PCRE2_SPTR>(text.data());
    const PCRE2_SIZE length = text.size();
    const bool first_per_line = c.per_line || c.count_only;
    const size_t cap = files_only ? 1 : first_per_line ? SIZE_MAX : static_cast<size_t>(c.max_per_file) + 1;
    std::vector<Event> events;
    for (size_t id = 0; id < db.pcre.size(); ++id) {
        size_t kept = 0;
        for (PCRE2_SIZE offset = 0; offset <= length && kept < cap;) {
            // CONTRACT: text reaching here is valid UTF-8 (validated or decoded), so UTF checks are skipped.
            const int rc = db.pcre_jit[id]
                ? pcre2_jit_match(db.pcre[id], subject, length, offset, 0, w.pcre_match, w.pcre_context)
                : pcre2_match(db.pcre[id], subject, length, offset, PCRE2_NO_UTF_CHECK, w.pcre_match, w.pcre_context);
            if (rc == PCRE2_ERROR_NOMATCH) break;
            if (rc < 0) {
                c.pcre_limit = true;
                break;
            }
            const PCRE2_SIZE* ovector = pcre2_get_ovector_pointer(w.pcre_match);
            const PCRE2_SIZE from = std::min(ovector[0], ovector[1]), to = ovector[1];
            events.push_back({static_cast<unsigned>(id), from, to});
            ++kept;
            if (first_per_line) {
                const size_t newline = text.find('\n', from);
                if (newline == std::string_view::npos) break;
                offset = newline + 1;
            } else if (to > offset) {
                offset = to;
            } else {
                // Empty match: step over one UTF-8 character.
                offset = to + 1;
                while (offset < length && (static_cast<unsigned char>(text[offset]) & 0xc0) == 0x80) ++offset;
            }
        }
    }
    std::sort(events.begin(), events.end(), [](const Event& a, const Event& b) {
        return a.to != b.to ? a.to < b.to : a.from < b.from;
    });
    for (const Event& event : events)
        if (Collector::callback(event.id, event.from, event.to, 0, &c)) break;
}
#endif

// Releases one text file's memory charge and any oversized worker buffer when its scan ends.
struct TextReservation {
    MemoryBudget& memory;
    Worker& worker;
    uint64_t bytes = 0;
    ~TextReservation() {
        worker.trim_raw();
        if (bytes) memory.release(bytes);
    }
};

// A whole text file read into the worker's raw buffer. counted is false when the file still has to be added to
// files_scanned/bytes_scanned once it is known not to be binary.
struct TextBytes {
    const char* raw;
    size_t size;
    bool utf16;
    bool counted;
};

// The measured path: file_size comes from the open handle. A NUL in the first block marks the file binary
// before the rest is read. Returns nullopt when the file was skipped or failed; counters and file_state are set.
std::optional<TextBytes> read_measured_text(const ScanShared& s, Worker& w, HANDLE h, uint64_t file_size,
                                            const std::string& display, std::string& file_state,
                                            TextReservation& reservation) {
    const Request& r = s.r;
    Outcome& out = s.out;
    w.chunk();
    if (file_size > r.max_file_bytes) {
        auto binary = probe_binary(h, file_size);
        if (!binary) ++out.errors;
        else if (*binary) ++out.skipped_binary;
        else {
            ++out.skipped_size;
            std::lock_guard lock(out.mutex);
            if (out.skipped_files.size() < 3)
                out.skipped_files.emplace_back(Json::Object{{"path", display}, {"reason", "text_file_size_limit"},
                                                            {"size_bytes", file_size}});
        }
        return std::nullopt;
    }
    // PERF: like rg/tgrep, a NUL in the first block marks the file binary before the rest is read.
    // UTF-16 text starts with a BOM and legitimately contains NUL bytes.
    const DWORD head_want = static_cast<DWORD>(std::min<uint64_t>(file_size, binary_probe_bytes));
    DWORD head = 0;
    if (head_want && (!ReadFile(h, w.buffer.data(), head_want, &head, nullptr) || head == 0)) {
        ++out.errors;
        return std::nullopt;
    }
    const bool utf16 = head >= 2 &&
        ((static_cast<unsigned char>(w.buffer[0]) == 0xff && static_cast<unsigned char>(w.buffer[1]) == 0xfe) ||
         (static_cast<unsigned char>(w.buffer[0]) == 0xfe && static_cast<unsigned char>(w.buffer[1]) == 0xff));
    if (!utf16 && std::find(w.buffer.begin(), w.buffer.begin() + head, '\0') != w.buffer.begin() + head) {
        ++out.skipped_binary;
        return std::nullopt;
    }
    const uint64_t charge = file_size >= small_text_bytes ? file_size * 3 : 0;
    if (charge && !s.memory.acquire(charge, s.control)) {
        if (const char* why = s.control.interrupted()) file_state = why;
        return std::nullopt;
    }
    reservation.bytes = charge;

    const auto size = static_cast<size_t>(file_size);
    char* raw = w.raw_buffer(size);
    std::copy(w.buffer.data(), w.buffer.data() + head, raw);
    size_t read = head;
    bool read_failed = false;
    while (read < size) {
        if (const char* why = s.control.interrupted()) { file_state = why; break; }
        DWORD got = 0;
        DWORD want = static_cast<DWORD>(std::min<size_t>(w.buffer.size(), size - read));
        if (!ReadFile(h, raw + read, want, &got, nullptr) || got == 0) {
            read_failed = true;
            break;
        }
        read += got;
    }
    ++out.files;
    out.bytes += read;
    LARGE_INTEGER current_size{};
    if (file_state == "complete" && (!GetFileSizeEx(h, &current_size) ||
        static_cast<uint64_t>(current_size.QuadPart) != file_size)) read_failed = true;
    if (read_failed) { ++out.errors; return std::nullopt; }
    if (file_state != "complete") return std::nullopt;
    return TextBytes{raw, read, utf16, true};
}

// CONTRACT: file_size is the directory listing's size for files up to binary_probe_bytes and the handle's
// measured size otherwise.
std::optional<TextBytes> read_text(const ScanShared& s, Worker& w, HANDLE h, uint64_t file_size,
                                   const std::string& display, std::string& file_state, TextReservation& reservation) {
    if (file_size <= binary_probe_bytes && file_size <= s.r.max_file_bytes) {
        // PERF: small files, the bulk of a source tree, take one ReadFile straight into the scan buffer with room
        // for one byte more than listed: no head copy and no size queries. The NUL check is scan_bytes's
        // whole-file pass in scan_text.
        // CONTRACT: a short ReadFile on a disk file means EOF, so the bytes read are the file's current contents
        // even if it shrank since listing. A full read means it grew; it is re-measured and read from the start.
        const DWORD room = static_cast<DWORD>(file_size) + 1;
        DWORD got = 0;
        char* raw = w.raw_buffer(room);
        if (!ReadFile(h, raw, room, &got, nullptr)) {
            ++s.out.errors;
            return std::nullopt;
        }
        if (got < room) return TextBytes{raw, got, got >= 2 && w.head_is_utf16(), false};
        LARGE_INTEGER size{}, start{};
        if (!GetFileSizeEx(h, &size) || size.QuadPart < 0 || !SetFilePointerEx(h, start, nullptr, FILE_BEGIN)) {
            ++s.out.errors;
            return std::nullopt;
        }
        file_size = static_cast<uint64_t>(size.QuadPart);
    }
    return read_measured_text(s, w, h, file_size, display, file_state, reservation);
}

void scan_text(const ScanShared& s, Worker& w, HANDLE h, uint64_t file_size, const std::string& display,
               uint32_t remaining, std::string& file_state, std::vector<Candidate>& items) {
    const Request& r = s.r;
    Outcome& out = s.out;
    TextReservation reservation{s.memory, w};
    PhaseTimer read_timer(phase(w.profile, &WorkerProfile::read));
    const auto contents = read_text(s, w, h, file_size, display, file_state, reservation);
    if (!contents) return;
    const char* raw = contents->raw;
    const size_t read = contents->size;
    const bool utf16 = contents->utf16;
    read_timer.stop();
    PhaseTimer scan_timer(phase(w.profile, &WorkerProfile::scan));

    // PERF: zero-copy path. BOM-less or UTF-8-BOM text that is pure ASCII or valid UTF-8 is exactly what
    // decode_text would produce, so Hyperscan scans the read buffer in place. UTF-16 and invalid UTF-8 are
    // decoded into a copy as before.
    const std::string_view file_bytes(raw, read);
    std::optional<DecodedText> decoded;
    TextView view;
    bool zero_copy = false;
    if (!utf16) {
        const uint32_t bom = read >= 3 && static_cast<unsigned char>(raw[0]) == 0xef &&
                                     static_cast<unsigned char>(raw[1]) == 0xbb &&
                                     static_cast<unsigned char>(raw[2]) == 0xbf ? 3u : 0u;
        const std::string_view body = file_bytes.substr(bom);
        const ByteScan scanned = scan_bytes(body);
        if (scanned.nul) { ++out.skipped_binary; return; }
        if (!scanned.non_ascii || valid_utf8(body)) {
            view.text = body;
            view.bom = bom;
            zero_copy = true;
        }
    }
    if (!zero_copy) {
        decoded.emplace(decode_text(file_bytes));
        if (decoded->text.find('\0') != std::string::npos) { ++out.skipped_binary; return; }
        view.text = decoded->text;
        view.decoded = &*decoded;
    }
    if (!contents->counted) {
        ++out.files;
        out.bytes += read;
    }

    const bool without = r.output == "files_without_match";
    const bool files_only = r.output == "files" || without, count_only = r.output == "count";
    // CONTRACT: invert needs every matching line of the file, so it collects without per-file or result caps;
    // the reported (non-matching) lines are capped afterwards. Memory stays bounded by the file's line count.
    const bool collect_all = r.invert;
    constexpr uint32_t unlimited = std::numeric_limits<uint32_t>::max();
    // PERF: files output stops each file at its first match.
    Collector collect{{}, 0, collect_all ? unlimited : files_only ? 1u : r.max_per_file, collect_all ? unlimited : remaining};
    collect.count_only = count_only && !collect_all;
    collect.word = r.word;
    collect.text = view.text;
    collect.som = s.database->som;
    collect.lengths = s.database->lengths.empty() ? nullptr : &s.database->lengths;
    if (collect.count_only && r.patterns.size() > 1) {
        collect.pattern_lines.assign(r.patterns.size(), 0);
        collect.pattern_line_end.assign(r.patterns.size(), 0);
    }
    // PERF: capped; reserving max_per_file (up to 10,000) events allocated hundreds of KB per scanned file.
    if (!collect.count_only) collect.events.reserve(std::min({collect.max_per_file, collect.remaining, 64u}));
    // PERF: the decoded file is one contiguous buffer, so block mode applies: no stream state, and end-anchored
    // patterns are resolved in the same call.
    collect.per_line = r.output == "lines" || collect_all;
#if defined(SHGREP_PCRE2)
    if (!s.database->pcre.empty()) {
        pcre_scan(*s.database, w, view.text, collect, files_only && !collect_all);
        if (collect.pcre_limit) ++out.errors;
    } else
#endif
    {
        // CONTRACT: an engine that fails reported nothing, so Hyperscan rescans the text into the same collector.
        const TextEngine* engine = s.database->engine.get();
        if (!engine || engine->scan(view.text, w.engine_scratch.get(), Collector::callback, &collect) == ScanStatus::failed) {
            if (engine) ++out.engine_fallbacks;
            hs_error_t rc = hs_scan(s.database->db, view.text.data(), static_cast<unsigned>(view.text.size()), 0,
                                    w.scratch, Collector::callback, &collect);
            if (rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED) throw std::runtime_error("Hyperscan text scan failed");
        }
    }
    if (collect.full && !files_only) out.per_file_limited.store(true);
    out.found += collect.found;

    if (r.invert) {
        // rg -v: report the lines no pattern matched.
        const uint32_t keep = r.output == "lines" ? std::min(r.max_per_file, remaining) : 0;
        InvertedLines inverted = invert_lines(view.text, std::move(collect.events), keep, r.multiline);
        if (!inverted.count) return;
        if (files_only) add_text_candidate(items, display, painted(r, display) + "\n", 1);
        else if (count_only) add_text_candidate(items, display, painted(r, display) + ":" + std::to_string(inverted.count) + "\n", 1);
        else {
            if (inverted.count > inverted.events.size()) out.per_file_limited.store(true);
            add_text_candidate(items, display, render_lines(r, display, view.text, inverted.events),
                               static_cast<uint32_t>(inverted.events.size()));
        }
        return;
    }
    if (files_only) {
        if (without ? collect.found == 0 : collect.found != 0) add_text_candidate(items, display, painted(r, display) + "\n", 1);
        return;
    }
    if (count_only) {
        if (collect.lines) add_text_candidate(items, display, count_line(painted(r, display), collect), 1);
        return;
    }
    if (r.output == "lines") {
        if (!collect.events.empty())
            add_text_candidate(items, display, render_lines(r, display, view.text, collect.events),
                               static_cast<uint32_t>(collect.events.size()));
        return;
    }

    std::vector<uint64_t> line_numbers(collect.events.size(), 1);
    if (r.line) {
        std::vector<size_t> order(collect.events.size());
        for (size_t i = 0; i < order.size(); ++i) order[i] = i;
        std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
            return collect.events[a].from < collect.events[b].from;
        });
        size_t cursor = 0;
        uint64_t line_number = 1;
        for (size_t i : order) {
            size_t target = static_cast<size_t>(std::min<uint64_t>(collect.events[i].from, view.text.size()));
            line_number += std::count(view.text.begin() + cursor, view.text.begin() + target, '\n');
            cursor = target;
            line_numbers[i] = line_number;
        }
    }
    for (size_t index = 0; index < collect.events.size(); ++index) {
        if (const char* why = s.control.interrupted()) { file_state = why; break; }
        const auto& event = collect.events[index];
        if (event.from > event.to || event.to > view.text.size()) {
            ++out.errors;
            continue;
        }
        size_t start = static_cast<size_t>(event.from > r.context_before ? event.from - r.context_before : 0);
        size_t end = static_cast<size_t>(std::min<uint64_t>(view.text.size(), event.to + r.context_after));
        while (start < event.from && start < view.text.size() &&
               (static_cast<unsigned char>(view.text[start]) & 0xc0) == 0x80) ++start;
        while (end < view.text.size() &&
               (static_cast<unsigned char>(view.text[end]) & 0xc0) == 0x80) ++end;
        bool context_truncated = end - start > 2048;
        if (context_truncated) {
            end = start + 2048;
            while (end > event.to && end < view.text.size() &&
                   (static_cast<unsigned char>(view.text[end]) & 0xc0) == 0x80) --end;
        }
        uint64_t from = view.raw_offset(event.from, false);
        uint64_t to = view.raw_offset(event.to, true);
        Json::Object item{{"pattern_id", static_cast<int64_t>(event.id)},
            {"path", display}, {"byte_start", from},
            {"byte_end", to}, {"binary", false},
            {"context", std::string(view.text.substr(start, end - start))},
            {"context_start", view.raw_offset(start, false)},
            {"context_match_start", event.from - start},
            {"context_match_end", event.to - start},
            {"context_truncated", context_truncated}};
        if (r.line) item.emplace("line", line_numbers[index]);
        Json candidate(std::move(item));
        const size_t bytes = candidate.dump().size() + 1;
        items.push_back({std::move(candidate), bytes});
    }
}

void scan_binary(const ScanShared& s, Worker& w, HANDLE h, uint64_t file_size, const std::string& display,
                 uint32_t remaining, std::string& file_state, std::vector<Candidate>& items) {
    const Request& r = s.r;
    Outcome& out = s.out;
    w.chunk();
    const bool files_only = r.output == "files", count_only = r.output == "count";
    Collector collect{{}, 0, files_only ? 1u : r.max_per_file, remaining};
    collect.count_only = count_only;
    collect.som = s.database->som;
    collect.lengths = s.database->lengths.empty() ? nullptr : &s.database->lengths;
    if (count_only && r.patterns.size() > 1) {
        collect.pattern_lines.assign(r.patterns.size(), 0);
        collect.pattern_line_end.assign(r.patterns.size(), 0);
    }
    // PERF: capped like scan_text; reserving max_per_file events allocated up to 10,000 per scanned file.
    if (!count_only) collect.events.reserve(std::min({collect.max_per_file, collect.remaining, 64u}));
    // PERF: an engine with a bounded match length scans the stream as chunks that overlap by its longest match
    // less one byte, instead of Hyperscan stream state. Literals have no end-of-data matches.
    // CONTRACT: if the engine fails, the file is rescanned from its start with Hyperscan into a fresh collector.
    const TextEngine* engine = s.database->engine.get();
    if (engine && (engine->max_match_bytes() == 0 || engine->max_match_bytes() > w.buffer.size() / 2)) engine = nullptr;
    const size_t overlap = engine ? engine->max_match_bytes() - 1 : 0;
    const Collector initial = collect;
    hs_stream_t* stream = nullptr;
    auto open_stream = [&] {
        if (hs_open_stream(s.database->db, 0, &stream) != HS_SUCCESS) throw std::runtime_error("Hyperscan stream allocation failed");
    };
    if (!engine) open_stream();
    uint64_t consumed = 0;
    size_t carry = 0;  // bytes at the front of w.buffer repeated from the previous chunk
    bool read_failed = false;
    while (consumed < file_size) {
        if (const char* why = s.control.interrupted()) { file_state = why; break; }
        DWORD want = static_cast<DWORD>(std::min<uint64_t>(w.buffer.size() - carry, file_size - consumed));
        DWORD got = 0;
        if (!ReadFile(h, w.buffer.data() + carry, want, &got, nullptr) || !got) { read_failed = true; break; }
        bool stopped = false;
        if (engine) {
            const size_t length = carry + got;
            const ScanStatus status = engine->scan_chunk(std::string_view(w.buffer.data(), length), carry, consumed - carry,
                                                         w.engine_scratch.get(), Collector::callback, &collect);
            if (status == ScanStatus::failed) {
                ++out.engine_fallbacks;
                engine = nullptr;
                collect = initial;
                consumed = 0;
                carry = 0;
                LARGE_INTEGER start{};
                if (!SetFilePointerEx(h, start, nullptr, FILE_BEGIN)) { read_failed = true; break; }
                open_stream();
                continue;
            }
            stopped = status == ScanStatus::stopped;
            const size_t keep = std::min(overlap, length);
            std::memmove(w.buffer.data(), w.buffer.data() + (length - keep), keep);
            carry = keep;
        } else {
            hs_error_t rc = hs_scan_stream(stream, w.buffer.data(), got, 0, w.scratch, Collector::callback, &collect);
            if (rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED) {
                hs_close_stream(stream, w.scratch, nullptr, nullptr);
                throw std::runtime_error("Hyperscan scan failed");
            }
            stopped = rc == HS_SCAN_TERMINATED;
        }
        consumed += got;
        if (collect.full || stopped) {
            if (!files_only) out.per_file_limited.store(true);
            break;
        }
    }
    // EOD callbacks are needed for anchored expressions on a complete scan.
    if (stream && file_state == "complete" && !read_failed && !collect.full) {
        hs_error_t rc = hs_close_stream(stream, w.scratch, Collector::callback, &collect);
        if (rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED) throw std::runtime_error("Hyperscan stream close failed");
        if (collect.full && !files_only) out.per_file_limited.store(true);
    } else if (stream) hs_close_stream(stream, w.scratch, nullptr, nullptr);
    ++out.files;
    out.bytes += consumed;
    out.found += collect.found;
    if (read_failed) ++out.errors;
    if (file_state != "complete") return;
    if (files_only) {
        if (collect.found) add_text_candidate(items, display, painted(r, display) + "\n", 1);
        return;
    }
    if (count_only) {
        if (collect.lines) add_text_candidate(items, display, count_line(painted(r, display), collect), 1);
        return;
    }
    std::vector<uint64_t> line_numbers;
    if (r.line) line_numbers = lines_for(h, collect.events, w.buffer, s.control.cancelled, s.control.deadline, file_state);
    for (size_t index = 0; index < collect.events.size(); ++index) {
        if (file_state != "complete") break;
        if (const char* why = s.control.interrupted()) { file_state = why; break; }
        const auto& event = collect.events[index];
        uint64_t from = event.from, to = event.to;
        uint64_t window_start = from > r.context_before ? from - r.context_before : 0;
        uint64_t window_end = std::min<uint64_t>(file_size, to + r.context_after);
        if (window_end - window_start > 2048) window_end = window_start + 2048;
        std::string context_bytes = read_window(h, window_start, window_end);
        bool binary_context = r.binary || context_bytes.find('\0') != std::string::npos || !valid_utf8(context_bytes);
        Json::Object item{{"pattern_id", static_cast<int64_t>(event.id)}, {"path", display},
                          {"byte_start", from}, {"byte_end", to}, {"binary", binary_context},
                          {binary_context ? "context_hex" : "context", binary_context ? hex(context_bytes) : context_bytes},
                          {"context_start", window_start}};
        // The same window with printable ASCII kept and every other byte shown as '.', so strings in binaries
        // are readable without decoding the hex.
        if (binary_context) {
            std::string readable(context_bytes.size(), '.');
            for (size_t i = 0; i < context_bytes.size(); ++i) {
                const auto c = static_cast<unsigned char>(context_bytes[i]);
                if (c >= 0x20 && c < 0x7f) readable[i] = static_cast<char>(c);
            }
            item.emplace("context_text", std::move(readable));
        }
        if (r.line) item.emplace("line", line_numbers[index]);
        Json candidate(std::move(item));
        const size_t bytes = candidate.dump().size() + 1;
        items.push_back({std::move(candidate), bytes});
    }
}

// PERF: CloseHandle on a searched file measured ~35 us, mostly filter-driver cleanup. Workers close inline: the
// close then scales with them, while one background closer serialized every close and held a 12-worker search
// at its 4-worker time (34.9 ms inline vs 56.1 ms deferred, median of 21 runs, 2026-10-09).
// SHGREP_DEFER_CLOSE=1 hands handles to the background thread instead, for A/B measurement; past max_pending
// queued handles a worker closes its own.
// CONTRACT: only read-only, share-all handles are deferred, so a pending close never blocks another writer,
// rename or delete.
class Closer {
public:
    // Null when disabled or when the thread could not start. Never destroyed: process exit closes what is left.
    static Closer* get() {
        static Closer* const closer = []() -> Closer* {
            if (!env_on(L"SHGREP_DEFER_CLOSE")) return nullptr;
            auto* made = new (std::nothrow) Closer();
            if (made && !made->start()) {
                delete made;
                made = nullptr;
            }
            return made;
        }();
        return closer;
    }

    void close(HANDLE h) {
        bool wake = false, full = false;
        {
            std::lock_guard lock(mutex_);
            if (pending_.size() >= max_pending) full = true;
            else {
                wake = pending_.empty();
                pending_.push_back(h);
            }
        }
        if (full) CloseHandle(h);
        else if (wake) ready_.notify_one();
    }

    // Handles queued but not yet taken by the thread; the profile reports it at response time.
    uint64_t pending() {
        std::lock_guard lock(mutex_);
        return pending_.size();
    }

private:
    static constexpr size_t max_pending = 16384;

    bool start() {
        try {
            pending_.reserve(1024);
            std::thread([this] { loop(); }).detach();
            return true;
        } catch (...) {
            return false;
        }
    }

    void loop() {
        std::vector<HANDLE> batch;
        for (;;) {
            {
                std::unique_lock lock(mutex_);
                ready_.wait(lock, [&] { return !pending_.empty(); });
                batch.swap(pending_);
            }
            for (HANDLE h : batch) CloseHandle(h);
            batch.clear();
        }
    }

    std::mutex mutex_;
    std::condition_variable ready_;
    std::vector<HANDLE> pending_;  // guarded by mutex_
};

void scan_file(const ScanShared& s, Worker& w, HANDLE directory, std::wstring_view name, const std::wstring& full_path,
               uint64_t listed_size) {
    const Request& r = s.r;
    Outcome& out = s.out;
    std::string display;
    const std::wstring_view shown = !s.relative_prefix.empty() && full_path.starts_with(s.relative_prefix)
        ? std::wstring_view(full_path).substr(s.relative_prefix.size()) : std::wstring_view(full_path);
    if (!try_utf8(shown, display)) { ++out.errors; return; }
    std::vector<Candidate> items;
    if (r.file_only) {
        // CONTRACT: find_files reads no file content; the directory-level root check bounds every name.
        ++out.files;
        ++out.found;
        if (r.output == "json") items.push_back({Json(Json::Object{{"path", std::move(display)}}), 0});
        else add_text_candidate(items, display, painted(r, display) + "\n", 1);
        publish(r, out, s.control, items, s.content_budget);
        return;
    }
    const size_t returned = std::min<size_t>(out.returned.load(), r.max_results);
    const uint32_t remaining = r.max_results - static_cast<uint32_t>(returned);
    if (remaining == 0) return;
    bool denied = false;
    PhaseTimer open_timer(phase(w.profile, &WorkerProfile::file_open));
    NTSTATUS status = 0;
    Handle h(open_relative(directory, name, false, denied, &status));
    if (!h) {
        constexpr NTSTATUS name_not_found = static_cast<NTSTATUS>(0xC0000034L);  // STATUS_OBJECT_NAME_NOT_FOUND
        constexpr NTSTATUS path_not_found = static_cast<NTSTATUS>(0xC000003AL);  // STATUS_OBJECT_PATH_NOT_FOUND
        if (w.index_snapshot && (status == name_not_found || status == path_not_found)) ++out.index_missing;
        else ++out.errors;
        return;
    }
    // PERF: small text files are sized from the listing; read_text re-measures any that grew since.
    uint64_t file_size = listed_size;
    if (r.binary || listed_size > binary_probe_bytes) {
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(h.h, &size) || size.QuadPart < 0) { ++out.errors; return; }
        file_size = static_cast<uint64_t>(size.QuadPart);
    }
    open_timer.stop();
    if (w.profile) ++w.profile->files_opened;
    std::string file_state = "complete";
    if (!r.binary) scan_text(s, w, h.h, file_size, display, remaining, file_state, items);
    else scan_binary(s, w, h.h, file_size, display, remaining, file_state, items);
    {
        PhaseTimer close_timer(phase(w.profile, &WorkerProfile::close));
        if (Closer* closer = Closer::get()) closer->close(std::exchange(h.h, INVALID_HANDLE_VALUE));
        else h.close();
    }
    if (file_state != "complete") {
        finish(out, s.control, file_state.c_str());
        return;
    }
    publish(r, out, s.control, items, s.content_budget);
}

std::string grouped_number(uint64_t number) {
    std::string value = std::to_string(number);
    for (size_t pos = value.size(); pos > 3; pos -= 3) value.insert(pos - 3, 1, ',');
    return value;
}

struct Footer {
    std::string state;
    std::vector<std::string> roots;
    uint64_t files = 0, errors = 0, skipped_size = 0, elapsed_ms = 0, returned = 0;
    bool show_selection = false;
    uint64_t seen = 0, filtered = 0, ignored = 0, hidden = 0, pruned = 0, reparse = 0;
};

// CONTRACT: text output stays silent on a complete search with results, like grep. Otherwise one or two short
// lines say why the list is empty or may be incomplete, so an agent does not mistake it for a full answer.
std::string render_footer(const Request& r, const Footer& f, const Json::Array& skipped) {
    std::string out;
    const bool per_file_units = r.file_only || r.output == "files" || r.output == "files_without_match" ||
                                r.output == "count";
    if (f.returned == 0) {
        out += r.file_only ? "No files matched." : "No matches.";
        if (!r.file_only) out += " Scanned " + grouped_number(f.files) + " files in " + std::to_string(f.elapsed_ms) + " ms.";
        out += " Roots:";
        for (const auto& root : f.roots) out += " " + root;
        out += '\n';
        if (f.show_selection)
            out += "Selection: " + grouped_number(f.seen) + " files seen, " + grouped_number(f.filtered) + " filtered, " +
                   grouped_number(f.ignored) + " ignored, " + grouped_number(f.hidden) + " hidden, " +
                   grouped_number(f.pruned) + " directories pruned, " + grouped_number(f.reparse) +
                   " reparse points skipped.\n";
    }
    for (const auto& entry : skipped) {
        const auto& item = entry.object();
        out += "Skipped oversized text file: " + item.at("path").string() + " (" +
               grouped_number(static_cast<uint64_t>(item.at("size_bytes").integer())) +
               " bytes; text search did not inspect it).\n";
    }
    if (f.state == "complete") return out;
    out += "[status " + f.state + ": ";
    if (f.state == "limit")
        out += "stopped at max_results=" + std::to_string(r.max_results) + "; more " +
               (per_file_units ? "files" : "matches") + " may exist. Narrow the search or raise max_results.]\n";
    else if (f.state == "per_file_limit")
        out += "some files have more than max_matches_per_file=" + std::to_string(r.max_per_file) +
               " matches; only the first are shown.]\n";
    else if (f.state == "output_limit")
        out += "stopped at max_output_bytes=" + std::to_string(r.max_output) + "; more results may exist.]\n";
    else if (f.state == "partial_files")
        out += grouped_number(f.errors) + " files unreadable, " + grouped_number(f.skipped_size) +
               " text files over max_file_bytes skipped.]\n";
    else if (f.state == "timeout")
        out += "timed out after " + std::to_string(r.timeout_ms) + " ms; results are partial.]\n";
    else out += "results are partial.]\n";
    return out;
}

HANDLE open_root_directory(const std::wstring& path) {
    return CreateFileW(long_path(path).c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS, nullptr);
}

struct WalkRoot {
    std::wstring path, final;
};

struct DirectoryTask {
    std::wstring path;
    std::string relative;
    std::shared_ptr<const IgnoreScope> ignore;
    std::shared_ptr<Handle> handle;
};

struct WalkBuffers {
    std::vector<uint64_t> listing = std::vector<uint64_t>(listing_buffer_bytes / sizeof(uint64_t));
    std::vector<DirEntry> entries;
    std::string name, relative;
};

// Selected files of one listed directory, opened relative to its handle; any worker may scan a batch.
struct FileBatch {
    std::shared_ptr<Handle> handle;
    std::shared_ptr<const std::wstring> directory;
    std::vector<DirEntry> files;
};
// PERF: at roughly 40 us of open/read/scan/close per file, 8 files (~0.3 ms) keep queue traffic negligible while
// one large directory still spreads across idle workers.
constexpr size_t file_batch_size = 8;

// CONTRACT: `directory` is the open parent handle and `name` the listed name; open the file with open_relative.
using FileVisitor = std::function<void(unsigned worker, HANDLE directory, std::wstring_view name, const std::wstring& path,
                                       uint64_t listed_size)>;

// Lists one directory: subdirectories to visit go to children, files that pass every filter go to files.
void visit_directory(const Request& r, const DirectoryTask& task, WalkBuffers& b, std::vector<DirectoryTask>& children,
                     std::vector<DirEntry>& files, Control& control, Outcome& out, WorkerProfile* p) {
    PhaseTimer list_timer(phase(p, &WorkerProfile::list));
    if (!list_directory(task.handle->h, b.listing, b.entries)) ++out.errors;

    std::shared_ptr<const IgnoreScope> scope = task.ignore;
    if (!r.no_ignore) {
        bool gitignore = false, dotignore = false;
        for (const auto& entry : b.entries) {
            if (entry.attributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (same_name(entry.name, L".gitignore")) gitignore = true;
            else if (same_name(entry.name, L".ignore")) dotignore = true;
        }
        if (gitignore || dotignore) {
            auto next = std::make_shared<IgnoreScope>();
            next->parent = task.ignore;
            read_ignore_rules(task.path, task.relative, gitignore, dotignore, next->rules);
            if (!next->rules.empty()) scope = std::move(next);
        }
    }

    list_timer.stop();
    for (auto& entry : b.entries) {
        if (control.stop.load()) return;
        if (const char* why = control.interrupted()) { finish(out, control, why); return; }
        const bool is_directory = (entry.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        // Junctions and symlinks are reparse points; they are never followed.
        const bool link = (entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        const bool regular = !is_directory && !link;
        if (!try_utf8(entry.name, b.name) || b.name.empty()) { ++out.errors; continue; }
        if (regular) ++out.regular_seen;
        if (regular && !name_prefilter(r, b.name)) { ++out.files_filtered; continue; }
        b.relative.assign(task.relative);
        if (!b.relative.empty()) b.relative.push_back('/');
        b.relative.append(b.name);
        const bool passes = path_passes(r, b.relative, b.name, is_directory);
        if (regular && !passes) { ++out.files_filtered; continue; }
        if (link) {
            ++out.reparse_skipped;
            if (is_directory) ++out.directories_pruned;
            continue;
        }
        if (is_directory && !r.excluded_directories.empty() && same_name(entry.name, cache_directory_name)) {
            const std::wstring path = join_path(task.path, entry.name);
            if (std::any_of(r.excluded_directories.begin(), r.excluded_directories.end(),
                            [&](const std::wstring& excluded) { return same_name(path, excluded.c_str()); })) {
                ++out.directories_pruned;
                continue;
            }
        }
        const bool visible = r.hidden || (b.name.front() != '.' && !(entry.attributes & FILE_ATTRIBUTE_HIDDEN));
        if (!visible) {
            if (is_directory) ++out.directories_pruned;
            else ++out.files_hidden;
            continue;
        }
        if (!r.no_ignore && ignored_path(scope.get(), b.relative, is_directory)) {
            if (is_directory) ++out.directories_pruned;
            else ++out.files_ignored;
            continue;
        }
        if (is_directory) {
            if (!passes) { ++out.directories_pruned; continue; }
            bool denied = false;
            PhaseTimer open_timer(phase(p, &WorkerProfile::dir_open));
            HANDLE child = open_relative(task.handle->h, entry.name, true, denied);
            open_timer.stop();
            if (child == INVALID_HANDLE_VALUE) {
                // CONTRACT: access-denied subdirectories are skipped without an error, matching skip_permission_denied.
                if (!denied) ++out.errors;
                continue;
            }
            children.push_back({join_path(task.path, entry.name), b.relative, scope, std::make_shared<Handle>(child)});
            continue;
        }
        if (!r.file_only && !r.binary) {
            // PERF: skip text-search files that cannot match without paying for the open; binary extensions are
            // listed in binary_extension.
            // CONTRACT: a listed size of 0 is not trusted; NTFS directory entries can lag a file still open for
            // writing, and read_text reads to EOF whatever the listing says.
            if (!r.sniff_all && binary_extension(b.name)) { ++out.skipped_binary; continue; }
        }
        files.push_back(std::move(entry));
    }
}

// A fixed set of threads that runs one job on all of them at once.
// PERF: walk threads are created once and parked between requests; creating 12 threads per request delayed the
// last worker's start by 3-4 ms.
class Crew {
public:
    explicit Crew(unsigned size) : size_(size) {
        threads_.reserve(size - 1);
        try {
            for (unsigned i = 1; i < size; ++i) threads_.emplace_back([this, i] { loop(i); });
        } catch (...) {
            stop();
            throw;
        }
    }
    ~Crew() { stop(); }
    Crew(const Crew&) = delete;
    Crew& operator=(const Crew&) = delete;
    unsigned size() const { return size_; }

    // Runs job(i) for every i in [0, size) concurrently, the caller as 0, and returns once all have returned.
    void run(const std::function<void(unsigned)>& job) {
        {
            std::lock_guard lock(mutex_);
            job_ = &job;
            remaining_ = size_ - 1;
            failure_ = nullptr;
            ++generation_;
        }
        wake_.notify_all();
        std::exception_ptr own;
        try { job(0); } catch (...) { own = std::current_exception(); }
        std::unique_lock lock(mutex_);
        done_.wait(lock, [&] { return remaining_ == 0; });
        job_ = nullptr;
        if (own) std::rethrow_exception(own);
        if (failure_) std::rethrow_exception(failure_);
    }

private:
    void loop(unsigned index) {
        uint64_t seen = 0;
        for (;;) {
            const std::function<void(unsigned)>* job = nullptr;
            {
                std::unique_lock lock(mutex_);
                wake_.wait(lock, [&] { return quit_ || generation_ != seen; });
                if (quit_) return;
                seen = generation_;
                job = job_;
            }
            std::exception_ptr error;
            try { (*job)(index); } catch (...) { error = std::current_exception(); }
            std::lock_guard lock(mutex_);
            if (error && !failure_) failure_ = error;
            if (--remaining_ == 0) done_.notify_one();
        }
    }
    void stop() {
        {
            std::lock_guard lock(mutex_);
            quit_ = true;
        }
        wake_.notify_all();
        for (auto& thread : threads_) thread.join();
    }

    const unsigned size_;
    std::mutex mutex_;
    std::condition_variable wake_, done_;
    const std::function<void(unsigned)>* job_ = nullptr;  // guarded by mutex_
    uint64_t generation_ = 0;                              // guarded by mutex_
    unsigned remaining_ = 0;                               // guarded by mutex_
    bool quit_ = false;                                    // guarded by mutex_
    std::exception_ptr failure_;                           // guarded by mutex_
    std::vector<std::thread> threads_;
};

// CONTRACT: a request takes a whole crew, so concurrent requests still each get their own full pool; at most one
// crew per concurrently running request is ever parked.
// COMPAT: parked crews are leaked at exit on purpose; ExitProcess ends their threads, while joining threads during
// static destruction is unsafe on Windows.
std::mutex& crew_mutex() {
    static auto* mutex = new std::mutex;
    return *mutex;
}
std::vector<std::unique_ptr<Crew>>& parked_crews() {
    static auto* crews = new std::vector<std::unique_ptr<Crew>>;
    return *crews;
}
std::unique_ptr<Crew> take_crew(unsigned size) {
    {
        std::lock_guard lock(crew_mutex());
        auto& parked = parked_crews();
        for (auto it = parked.begin(); it != parked.end(); ++it) {
            if ((*it)->size() != size) continue;
            auto crew = std::move(*it);
            parked.erase(it);
            return crew;
        }
    }
    return std::make_unique<Crew>(size);
}
void park_crew(std::unique_ptr<Crew> crew) {
    std::lock_guard lock(crew_mutex());
    parked_crews().push_back(std::move(crew));
}

// PERF: files above this listed size get a batch of their own that workers take first, so a multi-MB file starts
// early instead of becoming the walk's tail (a 2.5 MB file measured 9 ms under full load).
constexpr uint64_t large_file_bytes = 256 * 1024;
// PERF: workers list directories ahead of scanning while fewer files than this are queued, so large files are
// found early; the cap bounds queued file entries (and the directory handles they keep open) on huge trees.
// A paired A/B against scanning batches first measured 3-4% less walk time.
constexpr size_t listing_ahead_files = 16384;

// PERF: a bounded pool lists directories in parallel. Each listing's files are cut into batches that any worker
// may scan, so one large directory no longer runs on the single worker that listed it; measured as ~15% idle
// worker time before batching.
// CONTRACT: workers take large-file batches first, then directories while fewer than listing_ahead_files files are
// queued, then small-file batches. All stacks are LIFO, so the directory frontier (each entry holding one open
// handle) stays near depth-first size rather than the tree's full width.
// CONTRACT: profiles is null or holds worker_count slots, one per walk thread index.
void walk(const Request& r, const std::vector<WalkRoot>& roots, unsigned worker_count, Control& control,
          Outcome& out, const FileVisitor& on_file, WorkerProfile* profiles) {
    std::mutex mutex;
    std::condition_variable ready;
    std::vector<DirectoryTask> pending;
    std::vector<FileBatch> large, batches;
    size_t queued_files = 0;  // files in batches
    size_t active = 0;        // workers listing a directory, which may add work
    for (const auto& root : roots) {
        auto handle = std::make_shared<Handle>(open_root_directory(root.path));
        if (!*handle) { ++out.errors; continue; }
        pending.push_back({root.path, {}, nullptr, std::move(handle)});
    }
    auto scan_batch = [&](unsigned index, const FileBatch& batch, WorkerProfile* p) {
        try {
            PhaseTimer busy_timer(phase(p, &WorkerProfile::busy));
            for (const auto& entry : batch.files) {
                if (control.stop.load()) return;
                if (const char* why = control.interrupted()) { finish(out, control, why); return; }
                const int64_t file_started = p ? ticks() : 0;
                on_file(index, batch.handle->h, entry.name, join_path(*batch.directory, entry.name), entry.size);
                if (p) {
                    const int64_t spent = ticks() - file_started;
                    p->file_total += spent;
                    p->slowest_file = std::max(p->slowest_file, spent);
                }
            }
        } catch (...) {
            fail(out, control, std::current_exception());
        }
    };
    auto run = [&](unsigned index) {
        WorkerProfile* p = profiles ? &profiles[index] : nullptr;
        if (p) p->started = ticks();
        struct Finish {
            WorkerProfile* p;
            ~Finish() { if (p) p->finished = ticks(); }
        } finish_mark{p};
        PhaseTimer wall_timer(phase(p, &WorkerProfile::wall));
        WalkBuffers buffers;
        std::vector<DirectoryTask> children;
        std::vector<DirEntry> files, small;
        std::vector<FileBatch> made_large, made;
        for (;;) {
            std::optional<FileBatch> batch;
            DirectoryTask task;
            {
                std::unique_lock lock(mutex);
                while (large.empty() && batches.empty() && pending.empty() && active != 0 && !control.stop.load())
                    ready.wait_for(lock, std::chrono::milliseconds(20));
                if ((large.empty() && batches.empty() && pending.empty()) || control.stop.load()) {
                    ready.notify_all();
                    return;
                }
                if (!large.empty()) {
                    batch = std::move(large.back());
                    large.pop_back();
                } else if (!batches.empty() && (pending.empty() || queued_files >= listing_ahead_files)) {
                    batch = std::move(batches.back());
                    batches.pop_back();
                    queued_files -= batch->files.size();
                } else {
                    task = std::move(pending.back());
                    pending.pop_back();
                    ++active;
                }
            }
            if (batch) {
                scan_batch(index, *batch, p);
                continue;
            }
            children.clear();
            files.clear();
            small.clear();
            made_large.clear();
            made.clear();
            try {
                PhaseTimer busy_timer(phase(p, &WorkerProfile::busy));
                visit_directory(r, task, buffers, children, files, control, out, p);
                if (!files.empty()) {
                    auto directory = std::make_shared<const std::wstring>(task.path);
                    for (auto& file : files) {
                        if (file.size > large_file_bytes) made_large.push_back({task.handle, directory, {std::move(file)}});
                        else small.push_back(std::move(file));
                    }
                    for (size_t start = 0; start < small.size(); start += file_batch_size) {
                        const auto first = small.begin() + static_cast<ptrdiff_t>(start);
                        const auto last = small.begin() + static_cast<ptrdiff_t>(std::min(small.size(), start + file_batch_size));
                        made.push_back({task.handle, directory,
                                        std::vector<DirEntry>(std::make_move_iterator(first), std::make_move_iterator(last))});
                    }
                }
            } catch (...) {
                fail(out, control, std::current_exception());
                made_large.clear();
                made.clear();
                small.clear();
            }
            {
                std::lock_guard lock(mutex);
                for (auto& child : children) pending.push_back(std::move(child));
                for (auto& one : made_large) large.push_back(std::move(one));
                for (auto& some : made) batches.push_back(std::move(some));
                queued_files += small.size();
                --active;
            }
            ready.notify_all();
        }
    };
    auto crew = take_crew(worker_count);
    crew->run(run);
    park_crew(std::move(crew));
}

// CONTRACT: *_us values are worker time summed over all workers, except last_start, first_finish and last_finish
// (wall-clock offsets from the walk's start) and slowest_file (one file's duration).
Json::Object profile_json(const std::vector<WorkerProfile>& profiles, int64_t walk_started) {
    auto us = ticks_to_us;
    WorkerProfile sum;
    int64_t busy_min = INT64_MAX, busy_max = 0;
    int64_t start_last = 0, finish_first = INT64_MAX, finish_last = 0, slowest = 0;
    for (const auto& p : profiles) {
        start_last = std::max(start_last, p.started - walk_started);
        finish_first = std::min(finish_first, p.finished - walk_started);
        finish_last = std::max(finish_last, p.finished - walk_started);
        slowest = std::max(slowest, p.slowest_file);
    }
    for (const auto& p : profiles) {
        sum.wall += p.wall;
        sum.busy += p.busy;
        sum.list += p.list;
        sum.dir_open += p.dir_open;
        sum.file_total += p.file_total;
        sum.file_open += p.file_open;
        sum.read += p.read;
        sum.scan += p.scan;
        sum.close += p.close;
        sum.files_opened += p.files_opened;
        busy_min = std::min(busy_min, p.busy);
        busy_max = std::max(busy_max, p.busy);
    }
    const int64_t accounted = sum.file_open + sum.read + sum.scan + sum.close;
    return {{"workers", static_cast<uint64_t>(profiles.size())}, {"files_opened", sum.files_opened},
            {"wall_us", us(sum.wall)}, {"busy_us", us(sum.busy)}, {"idle_us", us(sum.wall - sum.busy)},
            {"busy_min_us", us(busy_min)}, {"busy_max_us", us(busy_max)},
            {"list_us", us(sum.list)}, {"dir_open_us", us(sum.dir_open)},
            {"file_open_us", us(sum.file_open)}, {"read_us", us(sum.read)}, {"scan_us", us(sum.scan)},
            {"close_us", us(sum.close)}, {"file_other_us", us(sum.file_total - accounted)},
            {"last_start_us", us(start_last)}, {"first_finish_us", us(finish_first)},
            {"last_finish_us", us(finish_last)}, {"slowest_file_us", us(slowest)}};
}
}

// ---- Optional snapshot trigram index ------------------------------------------------------------------------------
// Owner-approved (2026-10-09): an opt-in index like tgrep's. `shgrep index` writes one file per configured root to
// the workspace's .shgrep\index directory. A search with index: true does not walk an indexed root: it plans each
// pattern into an AND/OR query of literal trigrams, takes the candidate paths from the index, and opens only those,
// below the root one component at a time and never through a link.
// CONTRACT: a snapshot, consulted only when the request asks. Files added since the build are not searched, files
// deleted since are counted, not reported as errors, and a file edited since can be missed; every indexed result
// names the build time. Case-insensitive lookups use ASCII trigrams only, so a match that relies on Unicode case
// folding (KELVIN SIGN for k) can be missed too. Searches without the flag never touch any of this.
namespace {

constexpr char index_magic[8] = {'S', 'H', 'G', 'I', 'D', 'X', '3', '\0'};
constexpr uint32_t dense_trigram = 0xffffffffu;  // IndexTrigram::count of a trigram held by most files
constexpr uint32_t unindexed_file = 1;           // IndexFile::flags: contents unknown, always a candidate
constexpr size_t index_segment = 1u << 20;       // trigram positions sorted per batch while indexing a file
constexpr size_t index_sort_budget = 256u << 20; // bytes of postings held in memory before spilling a sorted run

// On-disk layout, little-endian: header, root path, file table, names, postings, trigram table.
struct IndexHeader {
    char magic[8];
    uint64_t built;  // FILETIME, UTC
    uint32_t files, trigrams;
    uint64_t root, root_size;  // UTF-8 final path of the indexed root
    uint64_t file_table, names, names_size, trigram_table, postings, postings_size;
};
struct IndexFile {
    uint32_t name, name_size;  // in the names blob: the '/'-separated path below the root
    uint64_t size;             // bytes when indexed
    uint64_t write_time;       // FILETIME of the last write when indexed
    uint32_t flags, reserved;
};
struct IndexTrigram {
    uint32_t key, count;  // sorted by key; count is dense_trigram for a trigram that constrains nothing
    uint64_t offset;      // in postings: count entries of (varint file id delta, location mask, next-byte mask)
};
// PERF: like tgrep's postings, two Bloom-style bytes per (trigram, file) let a lookup demand that consecutive
// trigrams of a literal sit at consecutive offsets (bit = offset % 8) and are followed by the literal's next byte
// (bit = folded byte % 8), so the index behaves almost like one of 4-grams.
struct IndexPosting {
    uint32_t id;
    uint8_t loc, next;
};

uint32_t index_fold(char c) {
    const auto b = static_cast<unsigned char>(c);
    return b >= 'A' && b <= 'Z' ? b + 32u : b;
}

bool index_widen(std::string_view s, std::wstring& out) {
    out.clear();
    if (s.empty()) return true;
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (size <= 0) return false;
    out.resize(static_cast<size_t>(size));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), size) == size;
}

// '/'-separated UTF-8 path of `path` below the walk root path `root`, as visit_directory builds relative paths.
bool index_relative(const std::wstring& path, const std::wstring& root, std::string& out) {
    size_t skip = root.size();
    if (path.size() <= skip) return false;
    if (path[skip] == L'\\' || path[skip] == L'/') ++skip;
    if (!try_utf8(std::wstring_view(path).substr(skip), out)) return false;
    std::replace(out.begin(), out.end(), '\\', '/');
    return true;
}

// The index file of the root whose final path is `root_final`, under the first configured root's .shgrep directory
// (which walks never enter). Empty when that root is unavailable.
std::wstring index_file_path(const SearchContext& context, const std::wstring& root_final) {
    if (context.allowed_roots.empty()) return {};
    Handle h(CreateFileW(context.allowed_roots.front().c_str(), FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!h) return {};
    std::wstring workspace;
    try { workspace = final_path(h.h); } catch (const std::runtime_error&) { return {}; }
    uint64_t hash = 1469598103934665603ull;  // FNV-1a; the root path inside the file settles collisions
    for (wchar_t c : root_final) {
        hash ^= static_cast<uint16_t>(std::towlower(c));
        hash *= 1099511628211ull;
    }
    wchar_t name[32] = {};
    swprintf_s(name, L"%016llx.idx", static_cast<unsigned long long>(hash));
    return join_path(join_path(join_path(workspace, cache_directory_name), L"index"), name);
}

std::string utc_text(uint64_t filetime) {
    FILETIME ft{static_cast<DWORD>(filetime), static_cast<DWORD>(filetime >> 32)};
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) return "unknown time";
    char text[32] = {};
    std::snprintf(text, sizeof(text), "%04u-%02u-%02u %02u:%02u UTC", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return text;
}

// The distinct folded trigrams of one file with their masks, packed as key << 16 | loc << 8 | next and sorted.
// PERF: positions are sorted in segments of index_segment and merged, so a large file needs O(segment) scratch.
struct TrigramSet {
    std::vector<uint32_t> occurrences;  // key << 7 | (offset % 8) << 4 | has-next << 3 | next % 8
    std::vector<uint64_t> grams, segment, merged;
    void collect(std::string_view text) {
        grams.clear();
        if (text.size() < 3) return;
        for (size_t first = 0; first + 2 < text.size(); first += index_segment) {
            const size_t last = std::min(text.size() - 2, first + index_segment);
            occurrences.clear();
            uint32_t key = index_fold(text[first]) << 8 | index_fold(text[first + 1]);
            for (size_t start = first; start < last; ++start) {
                key = (key << 8 | index_fold(text[start + 2])) & 0xffffffu;
                const uint32_t next = start + 3 < text.size() ? 8u | (index_fold(text[start + 3]) & 7u) : 0u;
                occurrences.push_back(key << 7 | static_cast<uint32_t>(start & 7) << 4 | next);
            }
            std::sort(occurrences.begin(), occurrences.end());
            segment.clear();
            for (size_t i = 0; i < occurrences.size();) {
                const uint32_t k = occurrences[i] >> 7;
                uint32_t loc = 0, next = 0;
                for (; i < occurrences.size() && occurrences[i] >> 7 == k; ++i) {
                    loc |= 1u << ((occurrences[i] >> 4) & 7);
                    if (occurrences[i] & 8) next |= 1u << (occurrences[i] & 7);
                }
                segment.push_back(uint64_t{k} << 16 | loc << 8 | next);
            }
            if (grams.empty()) {
                grams.swap(segment);
                continue;
            }
            merged.clear();
            size_t a = 0, b = 0;
            while (a < grams.size() || b < segment.size()) {
                if (b == segment.size() || (a < grams.size() && grams[a] >> 16 < segment[b] >> 16)) merged.push_back(grams[a++]);
                else if (a == grams.size() || segment[b] >> 16 < grams[a] >> 16) merged.push_back(segment[b++]);
                else merged.push_back(grams[a++] | segment[b++]);
            }
            grams.swap(merged);
        }
    }
};

enum class IndexRead { text, binary, unreadable };

// Reads a file the way scan_text sees it: binary for files search skips as binary, unreadable for read failures and
// files over max_bytes; for text, `text` is the scanned text, pointing into `raw` or `decoded`.
IndexRead index_text(HANDLE h, uint64_t max_bytes, std::string& raw, std::optional<DecodedText>& decoded,
                     std::string_view& text, uint64_t& size, uint64_t& write_time) {
    FILE_BASIC_INFO basic{};
    if (GetFileInformationByHandleEx(h, FileBasicInfo, &basic, sizeof(basic)))
        write_time = static_cast<uint64_t>(basic.LastWriteTime.QuadPart);
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(h, &length) || length.QuadPart < 0) return IndexRead::unreadable;
    size = static_cast<uint64_t>(length.QuadPart);
    if (size > max_bytes) return IndexRead::unreadable;
    raw.resize(static_cast<size_t>(size));
    size_t read = 0;
    while (read < raw.size()) {
        DWORD got = 0;
        const auto want = static_cast<DWORD>(std::min<size_t>(raw.size() - read, 1u << 20));
        if (!ReadFile(h, raw.data() + read, want, &got, nullptr) || got == 0) return IndexRead::unreadable;
        read += got;
    }
    const auto byte = [&](size_t i) { return static_cast<unsigned char>(raw[i]); };
    const bool utf16 = raw.size() >= 2 && ((byte(0) == 0xff && byte(1) == 0xfe) || (byte(0) == 0xfe && byte(1) == 0xff));
    if (!utf16) {
        const size_t bom = raw.size() >= 3 && byte(0) == 0xef && byte(1) == 0xbb && byte(2) == 0xbf ? 3 : 0;
        const std::string_view body = std::string_view(raw).substr(bom);
        const ByteScan scanned = scan_bytes(body);
        if (scanned.nul) return IndexRead::binary;
        if (!scanned.non_ascii || valid_utf8(body)) {
            text = body;
            return IndexRead::text;
        }
    }
    decoded.emplace(decode_text(raw));
    if (decoded->text.find('\0') != std::string::npos) return IndexRead::binary;
    text = decoded->text;
    return IndexRead::text;
}

void put_varint(std::string& out, uint32_t value) {
    while (value >= 0x80) {
        out.push_back(static_cast<char>(value | 0x80));
        value >>= 7;
    }
    out.push_back(static_cast<char>(value));
}

template <class T>
void put_raw(std::string& out, const T& value) {
    out.append(reinterpret_cast<const char*>(&value), sizeof(T));
}

void pad8(std::string& out) {
    while (out.size() % 8) out.push_back('\0');
}

struct SpillPosting {
    uint32_t key, id;
    uint16_t masks;  // location mask << 8 | next-byte mask
    uint16_t unused;
};
static_assert(sizeof(SpillPosting) == 12, "spill runs are raw arrays of SpillPosting");

bool spill_less(const SpillPosting& a, const SpillPosting& b) {
    return a.key != b.key ? a.key < b.key : a.id < b.id;
}

// External merge sort of (trigram, file) postings, as tgrep's bootstrap builder does: each producer fills a bounded
// buffer, sorts it and spills it to a run file when full, and merge() streams a k-way merge of the runs.
// PERF: peak memory is the budget plus the merge's read buffers and the largest posting list, whatever the tree's
// size; a tree that fits the budget never touches disk.
class PostingSorter {
public:
    PostingSorter(std::wstring directory, size_t budget_bytes, unsigned producers)
        : directory_(std::move(directory)),
          per_producer_(std::max<size_t>(budget_bytes / sizeof(SpillPosting) / std::max(producers, 1u), 1u << 16)),
          buffers_(std::max(producers, 1u)) {}
    ~PostingSorter() {
        for (const auto& run : runs_) DeleteFileW(run.c_str());
    }
    PostingSorter(const PostingSorter&) = delete;
    PostingSorter& operator=(const PostingSorter&) = delete;

    // CONTRACT: each producer index is used by one thread at a time.
    void add(unsigned producer, uint32_t key, uint32_t id, uint16_t masks) {
        auto& buffer = buffers_[producer];
        buffer.push_back({key, id, masks, 0});
        if (buffer.size() >= per_producer_) spill(buffer);
    }
    void add_file(unsigned producer, uint32_t id, const std::vector<uint64_t>& grams) {
        for (uint64_t gram : grams) add(producer, static_cast<uint32_t>(gram >> 16), id, static_cast<uint16_t>(gram));
    }
    // Calls on_key once per trigram in key order with its postings in id order. Single use.
    void merge(const std::function<void(uint32_t key, const std::vector<SpillPosting>&)>& on_key) {
        struct Run {
            std::vector<SpillPosting> memory;  // an unspilled buffer, or the read-ahead of a run file
            size_t at = 0;
            Handle file;
            bool more = false;  // the file has unread postings
        };
        std::vector<Run> runs;
        for (auto& buffer : buffers_) {
            if (buffer.empty()) continue;
            std::sort(buffer.begin(), buffer.end(), spill_less);
            Run run;
            run.memory.swap(buffer);
            runs.push_back(std::move(run));
        }
        const size_t read_ahead = std::max<size_t>(4096, (64u << 20) / sizeof(SpillPosting) / std::max<size_t>(runs_.size(), 1));
        const auto refill = [&](Run& run) {
            run.memory.resize(read_ahead);
            run.at = 0;
            size_t filled = 0;
            while (filled < read_ahead) {
                DWORD got = 0;
                const auto want = static_cast<DWORD>(std::min<size_t>((read_ahead - filled) * sizeof(SpillPosting), 1u << 24));
                if (!ReadFile(run.file.h, reinterpret_cast<char*>(run.memory.data() + filled), want, &got, nullptr))
                    throw std::runtime_error("cannot read an index sort run");
                if (got == 0) break;
                if (got % sizeof(SpillPosting)) throw std::runtime_error("truncated index sort run");
                filled += got / sizeof(SpillPosting);
            }
            run.memory.resize(filled);
            run.more = filled == read_ahead;
        };
        for (const auto& path : runs_) {
            Run run;
            run.file = Handle(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                          FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
            if (!run.file) throw std::runtime_error("cannot open an index sort run");
            refill(run);
            if (!run.memory.empty()) runs.push_back(std::move(run));
        }
        const auto later = [&](size_t a, size_t b) {
            return spill_less(runs[b].memory[runs[b].at], runs[a].memory[runs[a].at]);
        };
        std::vector<size_t> heap;
        for (size_t i = 0; i < runs.size(); ++i) heap.push_back(i);
        std::make_heap(heap.begin(), heap.end(), later);
        std::vector<SpillPosting> list;
        uint32_t key = 0;
        while (!heap.empty()) {
            std::pop_heap(heap.begin(), heap.end(), later);
            const size_t index = heap.back();
            Run& run = runs[index];
            const SpillPosting posting = run.memory[run.at++];
            if (!list.empty() && posting.key != key) {
                on_key(key, list);
                list.clear();
            }
            key = posting.key;
            if (list.empty() || list.back().id != posting.id) list.push_back(posting);
            if (run.at == run.memory.size() && run.more) refill(run);
            if (run.at < run.memory.size()) std::push_heap(heap.begin(), heap.end(), later);
            else heap.pop_back();
        }
        if (!list.empty()) on_key(key, list);
    }

private:
    void spill(std::vector<SpillPosting>& buffer) {
        std::sort(buffer.begin(), buffer.end(), spill_less);
        std::wstring path = join_path(directory_, L"sort-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                                      std::to_wstring(serial_.fetch_add(1)) + L".tmp");
        {
            Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
            if (!file) throw std::runtime_error("cannot create an index sort run");
            const char* data = reinterpret_cast<const char*>(buffer.data());
            size_t left = buffer.size() * sizeof(SpillPosting);
            while (left) {
                DWORD put = 0;
                const auto want = static_cast<DWORD>(std::min<size_t>(left, 1u << 24));
                if (!WriteFile(file.h, data, want, &put, nullptr) || put == 0) {
                    file.close();
                    DeleteFileW(path.c_str());
                    throw std::runtime_error("cannot write an index sort run (disk full?)");
                }
                data += put;
                left -= put;
            }
        }
        {
            std::lock_guard lock(runs_mutex_);
            runs_.push_back(std::move(path));
        }
        buffer.clear();
    }

    std::wstring directory_;
    size_t per_producer_;
    std::vector<std::vector<SpillPosting>> buffers_;
    std::mutex runs_mutex_;
    std::vector<std::wstring> runs_;
    std::atomic<uint64_t> serial_{0};
};

struct IndexEntry {
    std::string path;
    uint64_t size = 0, write_time = 0;
    uint32_t flags = 0;
};

// Buffered sequential writer for one index file.
class IndexWriter {
public:
    explicit IndexWriter(const std::wstring& path)
        : file_(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)) {
        if (!file_) throw std::runtime_error("cannot create the index file");
    }
    uint64_t position() const { return position_; }
    void write(const void* data, size_t size) {
        buffer_.append(static_cast<const char*>(data), size);
        position_ += size;
        if (buffer_.size() >= (4u << 20)) flush();
    }
    void pad8() {
        static constexpr char zeros[8] = {};
        if (position_ % 8) write(zeros, static_cast<size_t>(8 - position_ % 8));
    }
    void flush() {
        write_all(buffer_.data(), buffer_.size());
        buffer_.clear();
    }
    void rewrite_header(const IndexHeader& header) {
        flush();
        LARGE_INTEGER start{};
        if (!SetFilePointerEx(file_.h, start, nullptr, FILE_BEGIN)) throw std::runtime_error("cannot write the index file");
        write_all(reinterpret_cast<const char*>(&header), sizeof(header));
    }

private:
    void write_all(const char* data, size_t size) {
        while (size) {
            DWORD put = 0;
            const auto want = static_cast<DWORD>(std::min<size_t>(size, 1u << 24));
            if (!WriteFile(file_.h, data, want, &put, nullptr) || put == 0)
                throw std::runtime_error("cannot write the index file (disk full?)");
            data += put;
            size -= put;
        }
    }
    Handle file_;
    std::string buffer_;
    uint64_t position_ = 0;
};

// Creates the index directory (and a self-ignoring .shgrep) for the index file `file`; returns the directory.
std::wstring ensure_index_directory(const std::wstring& file) {
    const std::wstring dir = file.substr(0, file.rfind(L'\\'));
    const std::wstring parent = dir.substr(0, dir.rfind(L'\\'));
    if (CreateDirectoryW(parent.c_str(), nullptr)) {
        // A new .shgrep directory ignores itself, as store_cached_database does.
        Handle ignore(CreateFileW(join_path(parent, L".gitignore").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL, nullptr));
        DWORD put = 0;
        if (ignore) WriteFile(ignore.h, "*\n", 2, &put, nullptr);
    }
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

// Writes the index of `files` (file id = position) with the sorter's postings and publishes it at `target`.
// `dense` trigrams are kept as dense whatever their postings say: a merge cannot recover postings a predecessor
// never stored. Returns the index's size in bytes.
// COMPAT: a search may hold the current index mapped. Windows refuses to replace a mapped file but lets it be renamed
// (readers open it with FILE_SHARE_DELETE), so the predecessor moves aside and is deleted once nothing maps it.
uint64_t write_index_file(const std::wstring& target, const std::string& root_final, const std::vector<IndexEntry>& files,
                          PostingSorter& sorter, const std::unordered_set<uint32_t>& dense) {
    const std::wstring dir = ensure_index_directory(target);
    const std::wstring temp = target + L"." + std::to_wstring(GetCurrentProcessId()) + L".tmp";
    uint64_t total = 0;
    try {
        IndexWriter out(temp);
        IndexHeader header{};
        std::memcpy(header.magic, index_magic, sizeof(index_magic));
        FILETIME now{};
        GetSystemTimeAsFileTime(&now);
        header.built = static_cast<uint64_t>(now.dwHighDateTime) << 32 | now.dwLowDateTime;
        header.files = static_cast<uint32_t>(files.size());
        out.write(&header, sizeof(header));
        header.root = out.position();
        header.root_size = root_final.size();
        out.write(root_final.data(), root_final.size());
        out.pad8();
        header.file_table = out.position();
        uint64_t names = 0;
        for (const auto& f : files) {
            if (names + f.path.size() > 0xffffffffu) throw std::runtime_error("tree has too many paths to index");
            const IndexFile entry{static_cast<uint32_t>(names), static_cast<uint32_t>(f.path.size()), f.size, f.write_time,
                                  f.flags, 0};
            out.write(&entry, sizeof(entry));
            names += f.path.size();
        }
        header.names = out.position();
        header.names_size = names;
        for (const auto& f : files) out.write(f.path.data(), f.path.size());
        out.pad8();
        header.postings = out.position();
        const auto file_count = static_cast<uint32_t>(files.size());
        std::vector<IndexTrigram> table;
        std::string encoded;
        sorter.merge([&](uint32_t key, const std::vector<SpillPosting>& list) {
            // A trigram held by more than half of the files rules out too little to pay for its postings.
            if (dense.count(key) || (file_count >= 16 && list.size() > file_count / 2)) {
                table.push_back({key, dense_trigram, 0});
                return;
            }
            table.push_back({key, static_cast<uint32_t>(list.size()), out.position() - header.postings});
            encoded.clear();
            uint32_t previous = 0;
            for (const SpillPosting& posting : list) {
                put_varint(encoded, posting.id - previous);
                encoded.push_back(static_cast<char>(posting.masks >> 8));
                encoded.push_back(static_cast<char>(posting.masks & 0xff));
                previous = posting.id;
            }
            out.write(encoded.data(), encoded.size());
        });
        header.postings_size = out.position() - header.postings;
        // Dense trigrams whose files all changed have no postings left but must stay unconstraining.
        bool added = false;
        for (uint32_t key : dense) {
            const auto it = std::lower_bound(table.begin(), table.end(), key,
                                             [](const IndexTrigram& t, uint32_t k) { return t.key < k; });
            if (it != table.end() && it->key == key) continue;
            table.push_back({key, dense_trigram, 0});
            added = true;
        }
        if (added) std::sort(table.begin(), table.end(), [](const IndexTrigram& a, const IndexTrigram& b) { return a.key < b.key; });
        out.pad8();
        header.trigram_table = out.position();
        header.trigrams = static_cast<uint32_t>(table.size());
        out.write(table.data(), table.size() * sizeof(IndexTrigram));
        total = out.position();
        out.rewrite_header(header);
    } catch (...) {
        DeleteFileW(temp.c_str());
        throw;
    }
    if (!MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        const std::wstring aside = target + L".old." + std::to_wstring(GetCurrentProcessId()) + L"." +
                                   std::to_wstring(GetTickCount64());
        if (!MoveFileExW(target.c_str(), aside.c_str(), 0) ||
            !MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            DeleteFileW(temp.c_str());
            throw std::runtime_error("cannot publish the index file");
        }
    }
    // Earlier generations that no search maps any more; a mapped one refuses deletion and waits for a later pass.
    const std::wstring name = target.substr(target.rfind(L'\\') + 1);
    WIN32_FIND_DATAW found{};
    HANDLE search = FindFirstFileW(join_path(dir, name + L".old.*").c_str(), &found);
    if (search != INVALID_HANDLE_VALUE) {
        do DeleteFileW(join_path(dir, found.cFileName).c_str());
        while (FindNextFileW(search, &found));
        FindClose(search);
    }
    return total;
}

struct TreeIndex {
    std::vector<IndexEntry> files;
    uint64_t bytes = 0, unreadable = 0;
};

// Walks `root` with search's default selection (.gitignore/.ignore honored, hidden files and binary extensions
// skipped) and feeds every text file's trigrams to `sorter`; file ids are positions in the result. Binary files are
// kept without trigrams, so indexed searches skip them as plain searches do; unreadable files are always-candidates.
TreeIndex index_tree(const SearchContext& context, const WalkRoot& root, PostingSorter& sorter, unsigned worker_count,
                     const std::shared_ptr<std::atomic_bool>& cancelled) {
    Request r = parse_request("find_files", Json(Json::Object{}), context);
    r.excluded_directories.push_back(join_path(root.path, cache_directory_name));
    Control control{cancelled, Clock::now() + std::chrono::hours(24)};
    Outcome out;
    struct TreeWorker {
        TrigramSet trigrams;
        std::string raw;
        std::vector<std::pair<uint32_t, IndexEntry>> files;
    };
    std::vector<std::unique_ptr<TreeWorker>> workers;
    for (unsigned i = 0; i < worker_count; ++i) workers.push_back(std::make_unique<TreeWorker>());
    std::atomic<uint32_t> next_id{0};
    std::atomic<uint64_t> unreadable{0};
    walk(r, {root}, worker_count, control, out,
         [&](unsigned index, HANDLE directory, std::wstring_view name, const std::wstring& path, uint64_t listed) {
             TreeWorker& w = *workers[index];
             std::string name_utf8;
             if (!try_utf8(name, name_utf8) || binary_extension(name_utf8)) return;
             IndexEntry entry;
             if (!index_relative(path, root.path, entry.path)) { ++out.errors; return; }
             entry.size = listed;
             bool denied = false;
             Handle h(open_relative(directory, name, false, denied));
             std::optional<DecodedText> decoded;
             std::string_view contents;
             const IndexRead kind = h ? index_text(h.h, r.max_file_bytes, w.raw, decoded, contents, entry.size,
                                                   entry.write_time)
                                      : IndexRead::unreadable;
             const uint32_t id = next_id.fetch_add(1);
             if (kind == IndexRead::unreadable) {
                 entry.flags = unindexed_file;
                 ++unreadable;
             } else if (kind == IndexRead::text) {
                 w.trigrams.collect(contents);
                 sorter.add_file(index, id, w.trigrams.grams);
                 out.bytes += entry.size;
             }
             w.files.emplace_back(id, std::move(entry));
         }, nullptr);
    if (out.failure) std::rethrow_exception(out.failure);
    if (const char* why = control.interrupted()) throw std::runtime_error(std::string("index build ") + why);
    TreeIndex tree;
    tree.files.resize(next_id.load());
    for (auto& w : workers)
        for (auto& [id, entry] : w->files) tree.files[id] = std::move(entry);
    tree.bytes = out.bytes.load();
    tree.unreadable = unreadable.load();
    return tree;
}

unsigned index_workers() {
    const DWORD processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    return processors == 0 ? 1u : static_cast<unsigned>(processors);
}

// `shgrep index`: one snapshot per configured root.
Json build_index(const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled) {
    std::string text;
    for (const auto& allowed : context.allowed_roots) {
        const auto started = Clock::now();
        Handle root(CreateFileW(allowed.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        if (!root) throw std::runtime_error("configured root unavailable: " + utf8(allowed.wstring()));
        const WalkRoot walk_root{fs::absolute(allowed).lexically_normal().wstring(), final_path(root.h)};
        std::string root_final;
        if (!try_utf8(walk_root.final, root_final)) throw std::runtime_error("root path is not valid Unicode");
        const std::wstring file = index_file_path(context, walk_root.final);
        if (file.empty()) throw std::runtime_error("cannot locate the workspace .shgrep directory");
        const unsigned workers = index_workers();
        PostingSorter sorter(ensure_index_directory(file), index_sort_budget, workers);
        const TreeIndex tree = index_tree(context, walk_root, sorter, workers, cancelled);
        const uint64_t index_bytes = write_index_file(file, root_final, tree.files, sorter, {});
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
        std::string file_utf8;
        try_utf8(file, file_utf8);
        text += "Indexed " + std::to_string(tree.files.size()) + " files (" + std::to_string(tree.bytes >> 20) +
                " MiB of text) under " + utf8(walk_root.path) + " in " + std::to_string(ms) + " ms.\nIndex: " +
                file_utf8 + " (" + std::to_string(index_bytes >> 10) + " KiB)";
        if (tree.unreadable) text += "; " + std::to_string(tree.unreadable) + " unreadable files are always searched";
        text += ".\n";
    }
    return Json::Object{{"text", std::move(text)}, {"summary", Json::Object{{"status", std::string("complete")}}}};
}

// One index file mapped read-only.
class IndexView {
public:
    IndexView(const std::wstring& file, const std::wstring& root_final) {
        file_ = Handle(CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr));
        LARGE_INTEGER length{};
        if (!file_ || !GetFileSizeEx(file_.h, &length) || length.QuadPart < static_cast<LONGLONG>(sizeof(IndexHeader)))
            return;
        section_ = CreateFileMappingW(file_.h, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!section_) return;
        base_ = static_cast<const char*>(MapViewOfFile(section_, FILE_MAP_READ, 0, 0, 0));
        size_ = static_cast<uint64_t>(length.QuadPart);
        if (!base_ || !validate(root_final)) unmap();
    }
    ~IndexView() { unmap(); }
    IndexView(const IndexView&) = delete;
    IndexView& operator=(const IndexView&) = delete;
    explicit operator bool() const { return base_ != nullptr; }

    uint32_t files() const { return header_.files; }
    uint64_t built() const { return header_.built; }
    std::string_view path(uint32_t id) const {
        const IndexFile& f = file_table()[id];
        return std::string_view(base_ + header_.names + f.name, f.name_size);
    }
    uint64_t file_size(uint32_t id) const { return file_table()[id].size; }
    uint64_t write_time(uint32_t id) const { return file_table()[id].write_time; }
    uint32_t flags(uint32_t id) const { return file_table()[id].flags; }
    uint32_t trigram_count() const { return header_.trigrams; }
    const IndexTrigram& trigram_at(uint32_t i) const { return trigram_table()[i]; }
    const IndexTrigram* trigram(uint32_t key) const {
        const IndexTrigram* first = trigram_table();
        const IndexTrigram* last = first + header_.trigrams;
        const IndexTrigram* it = std::lower_bound(first, last, key, [](const IndexTrigram& t, uint32_t k) { return t.key < k; });
        return it != last && it->key == key ? it : nullptr;
    }
    // False when the list is dense or malformed.
    bool postings(const IndexTrigram& t, std::vector<IndexPosting>& out) const {
        out.clear();
        if (t.count == dense_trigram || t.offset > header_.postings_size) return false;
        const auto* p = reinterpret_cast<const unsigned char*>(base_ + header_.postings + t.offset);
        const auto* end = reinterpret_cast<const unsigned char*>(base_ + header_.postings + header_.postings_size);
        out.reserve(t.count);
        uint32_t id = 0;
        for (uint32_t i = 0; i < t.count; ++i) {
            uint32_t delta = 0;
            for (int shift = 0;; shift += 7) {
                if (p == end || shift > 28) return false;
                const unsigned char b = *p++;
                delta |= static_cast<uint32_t>(b & 0x7f) << shift;
                if (!(b & 0x80)) break;
            }
            if (end - p < 2) return false;
            id += delta;
            if (id >= header_.files || (i && delta == 0)) return false;
            out.push_back({id, p[0], p[1]});
            p += 2;
        }
        return true;
    }

private:
    const IndexFile* file_table() const { return reinterpret_cast<const IndexFile*>(base_ + header_.file_table); }
    const IndexTrigram* trigram_table() const { return reinterpret_cast<const IndexTrigram*>(base_ + header_.trigram_table); }
    bool fits(uint64_t offset, uint64_t bytes) const { return offset <= size_ && bytes <= size_ - offset; }
    bool validate(const std::wstring& root_final) {
        std::memcpy(&header_, base_, sizeof(header_));
        if (std::memcmp(header_.magic, index_magic, sizeof(index_magic)) != 0) return false;
        if (!fits(header_.root, header_.root_size) || !fits(header_.names, header_.names_size) ||
            !fits(header_.postings, header_.postings_size) || header_.file_table % 8 || header_.trigram_table % 8 ||
            !fits(header_.file_table, uint64_t{header_.files} * sizeof(IndexFile)) ||
            !fits(header_.trigram_table, uint64_t{header_.trigrams} * sizeof(IndexTrigram)))
            return false;
        std::string expected;
        if (!try_utf8(root_final, expected) ||
            std::string_view(base_ + header_.root, static_cast<size_t>(header_.root_size)) != expected)
            return false;
        for (uint32_t i = 0; i < header_.files; ++i) {
            const IndexFile& f = file_table()[i];
            if (uint64_t{f.name} + f.name_size > header_.names_size) return false;
        }
        return true;
    }
    void unmap() {
        if (base_) UnmapViewOfFile(base_);
        if (section_) CloseHandle(section_);
        base_ = nullptr;
        section_ = nullptr;
    }

    Handle file_;
    HANDLE section_ = nullptr;
    const char* base_ = nullptr;
    uint64_t size_ = 0;
    IndexHeader header_{};
};

// A conservative trigram query: every match of the pattern satisfies the node. all constrains nothing; literal
// requires its text; and/or combine children.
struct QueryNode {
    enum Kind : uint8_t { all, literal, and_, or_ } kind = all;
    std::string text;
    std::vector<QueryNode> children;
};

// Plans a PCRE-syntax regex into a QueryNode. Anything not understood becomes `all` for its part, so the plan can
// only be weaker than the regex, never stronger: a literal run ends at classes, '.', anchors, escapes that are not
// literal characters, and quantifiers, and a quantified character keeps only what every repetition count implies.
class QueryPlanner {
public:
    explicit QueryPlanner(std::string_view pattern) : p_(pattern) {}
    QueryNode plan() {
        QueryNode node = alternation();
        // Unparsed text (a stray ')') or (?x), where whitespace and comments are not literal, plans to nothing.
        if (failed_ || extended_ || pos_ != p_.size()) return {};
        return node;
    }
    bool insensitive() const { return insensitive_; }

private:
    struct Atom {
        bool is_char = false;  // one literal code point, in `chars`
        std::string chars;
        QueryNode node;
    };
    struct Quant {
        uint32_t min = 1, max = 1;  // max 0: unbounded
    };

    QueryNode alternation() {
        std::vector<QueryNode> branches;
        branches.push_back(concat());
        while (!failed_ && pos_ < p_.size() && p_[pos_] == '|') {
            ++pos_;
            branches.push_back(concat());
        }
        if (branches.size() == 1) return std::move(branches.front());
        QueryNode node;
        node.kind = QueryNode::or_;
        node.children = std::move(branches);
        return node;
    }

    QueryNode concat() {
        QueryNode node;
        node.kind = QueryNode::and_;
        std::string run;
        const auto flush = [&] {
            if (run.empty()) return;
            QueryNode literal;
            literal.kind = QueryNode::literal;
            literal.text = std::move(run);
            node.children.push_back(std::move(literal));
            run.clear();
        };
        while (!failed_ && pos_ < p_.size() && p_[pos_] != '|' && p_[pos_] != ')') {
            Atom a = atom();
            if (failed_) break;
            const Quant q = quantifier();
            if (failed_) break;
            if (a.is_char) {
                if (q.min == 0) { flush(); continue; }
                run += a.chars;
                // Repeated: a run cannot cross the repeats, but whatever follows still follows this character.
                if (q.max != 1) {
                    flush();
                    run = a.chars;
                }
                continue;
            }
            flush();
            if (q.min >= 1 && a.node.kind != QueryNode::all) node.children.push_back(std::move(a.node));
        }
        flush();
        return node;
    }

    void skip_until(char close) {
        const size_t end = p_.find(close, pos_);
        if (end == std::string_view::npos) failed_ = true;
        else pos_ = end + 1;
    }

    Atom atom() {
        Atom a;
        const char c = p_[pos_];
        if (c == '(') {
            ++pos_;
            bool consuming = true;
            if (pos_ < p_.size() && p_[pos_] == '?') {
                if (++pos_ >= p_.size()) { failed_ = true; return a; }
                const char k = p_[pos_];
                if (k == ':' || k == '>' || k == '|') {
                    ++pos_;
                } else if (k == '=' || k == '!') {
                    ++pos_;
                    consuming = false;  // lookahead
                } else if (k == '<' && pos_ + 1 < p_.size() && (p_[pos_ + 1] == '=' || p_[pos_ + 1] == '!')) {
                    pos_ += 2;
                    consuming = false;  // lookbehind
                } else if (k == '<' || k == '\'') {
                    ++pos_;
                    skip_until(k == '<' ? '>' : '\'');  // named group
                } else if (k == 'P' && pos_ + 1 < p_.size() && p_[pos_ + 1] == '<') {
                    pos_ += 2;
                    skip_until('>');
                } else {
                    // Inline options: (?i), (?i:...), (?-s) and so on.
                    while (pos_ < p_.size() && (std::isalpha(static_cast<unsigned char>(p_[pos_])) || p_[pos_] == '-')) {
                        if (p_[pos_] == 'i') insensitive_ = true;
                        if (p_[pos_] == 'x') extended_ = true;
                        ++pos_;
                    }
                    if (pos_ < p_.size() && p_[pos_] == ')') {
                        ++pos_;
                        return a;  // options only: matches nothing by itself
                    }
                    if (pos_ < p_.size() && p_[pos_] == ':') ++pos_;
                    else { failed_ = true; return a; }
                }
                if (failed_) return a;
            }
            QueryNode inner = alternation();
            if (failed_ || pos_ >= p_.size() || p_[pos_] != ')') { failed_ = true; return a; }
            ++pos_;
            if (consuming) a.node = std::move(inner);
            return a;
        }
        if (c == '[') {
            ++pos_;
            if (pos_ < p_.size() && p_[pos_] == '^') ++pos_;
            if (pos_ < p_.size() && p_[pos_] == ']') ++pos_;
            while (pos_ < p_.size() && p_[pos_] != ']') {
                if (p_[pos_] == '\\') pos_ += 2;
                else if (p_[pos_] == '[' && pos_ + 1 < p_.size() && p_[pos_ + 1] == ':') {
                    const size_t end = p_.find(":]", pos_ + 2);
                    if (end == std::string_view::npos) { failed_ = true; return a; }
                    pos_ = end + 2;
                } else {
                    ++pos_;
                }
            }
            if (pos_ >= p_.size()) { failed_ = true; return a; }
            ++pos_;
            return a;
        }
        if (c == '.' || c == '^' || c == '$') {
            ++pos_;
            return a;
        }
        if (c == '*' || c == '+' || c == '?' || c == '{') {
            failed_ = true;  // a quantifier with nothing to repeat, or a '{' that is not one
            return a;
        }
        if (c == '\\') return escape();
        return literal_char(a);
    }

    Atom& literal_char(Atom& a) {
        const auto lead = static_cast<unsigned char>(p_[pos_]);
        const size_t length = lead < 0x80 ? 1 : lead >= 0xf0 ? 4 : lead >= 0xe0 ? 3 : 2;
        if (pos_ + length > p_.size()) { failed_ = true; return a; }
        a.is_char = true;
        a.chars.assign(p_.substr(pos_, length));
        pos_ += length;
        return a;
    }

    Atom escape() {
        Atom a;
        if (++pos_ >= p_.size()) { failed_ = true; return a; }
        const char e = p_[pos_];
        const auto single = [&](char value) {
            ++pos_;
            a.is_char = true;
            a.chars.assign(1, value);
            return a;
        };
        switch (e) {
        case 't': return single('\t');
        case 'n': return single('\n');
        case 'r': return single('\r');
        case 'f': return single('\f');
        case 'e': return single('\x1b');
        case 'a': return single('\a');
        case 'x': {
            ++pos_;
            if (pos_ < p_.size() && p_[pos_] == '{') { skip_until('}'); return a; }
            uint32_t value = 0;
            size_t digits = 0;
            while (digits < 2 && pos_ < p_.size() && std::isxdigit(static_cast<unsigned char>(p_[pos_]))) {
                const char d = static_cast<char>(std::tolower(static_cast<unsigned char>(p_[pos_])));
                value = value * 16 + static_cast<uint32_t>(d <= '9' ? d - '0' : d - 'a' + 10);
                ++pos_;
                ++digits;
            }
            if (digits && value && value < 0x80) {
                a.is_char = true;
                a.chars.assign(1, static_cast<char>(value));
            }
            return a;
        }
        case 'Q': {
            ++pos_;
            const size_t end = p_.find("\\E", pos_);
            const size_t stop = end == std::string_view::npos ? p_.size() : end;
            if (stop > pos_) {
                a.node.kind = QueryNode::literal;
                a.node.text.assign(p_.substr(pos_, stop - pos_));
            }
            pos_ = end == std::string_view::npos ? p_.size() : end + 2;
            return a;
        }
        case 'p': case 'P': case 'o': case 'N':
            ++pos_;
            if (pos_ < p_.size() && p_[pos_] == '{') skip_until('}');
            else if ((e == 'p' || e == 'P') && pos_ < p_.size()) ++pos_;
            return a;
        case 'k': case 'g':
            ++pos_;
            if (pos_ < p_.size() && (p_[pos_] == '<' || p_[pos_] == '{' || p_[pos_] == '\'')) {
                skip_until(p_[pos_] == '<' ? '>' : p_[pos_] == '{' ? '}' : '\'');
            } else {
                if (pos_ < p_.size() && p_[pos_] == '-') ++pos_;
                while (pos_ < p_.size() && std::isdigit(static_cast<unsigned char>(p_[pos_]))) ++pos_;
            }
            return a;
        case 'c':
            pos_ += 2;
            if (pos_ > p_.size()) failed_ = true;
            return a;
        default:
            break;
        }
        if (std::isdigit(static_cast<unsigned char>(e))) {
            while (pos_ < p_.size() && std::isdigit(static_cast<unsigned char>(p_[pos_]))) ++pos_;  // backreference or octal
            return a;
        }
        if (std::isalpha(static_cast<unsigned char>(e))) {
            ++pos_;  // \d \w \s \b \B \A \z \Z \G \h \v \R \X \K \E ...: a class or an assertion
            return a;
        }
        return literal_char(a);  // escaped punctuation, or any escaped non-ASCII character, is itself
    }

    Quant quantifier() {
        Quant q;
        if (pos_ >= p_.size()) return q;
        const char c = p_[pos_];
        if (c == '*') q = {0, 0};
        else if (c == '+') q = {1, 0};
        else if (c == '?') q = {0, 1};
        else if (c == '{') {
            size_t at = pos_ + 1;
            const auto number = [&](uint32_t& value) {
                const size_t first = at;
                value = 0;
                while (at < p_.size() && std::isdigit(static_cast<unsigned char>(p_[at])) && at - first < 9)
                    value = value * 10 + static_cast<uint32_t>(p_[at++] - '0');
                return at > first;
            };
            uint32_t low = 0, high = 0;
            if (!number(low)) return q;  // not a quantifier: the next atom fails the plan
            high = low;
            if (at < p_.size() && p_[at] == ',') {
                ++at;
                if (!number(high)) high = 0;
            }
            if (at >= p_.size() || p_[at] != '}') return q;
            q = {low, high};
            pos_ = at;
        } else {
            return q;
        }
        ++pos_;
        if (pos_ < p_.size() && (p_[pos_] == '?' || p_[pos_] == '+')) ++pos_;  // lazy or possessive
        return q;
    }

    std::string_view p_;
    size_t pos_ = 0;
    bool failed_ = false, extended_ = false, insensitive_ = false;
};

using IdSet = std::optional<std::vector<uint32_t>>;  // nullopt: every indexed file

// Files that held every non-dense trigram of `text`, consecutive trigrams at consecutive offsets per their location
// masks, each followed by the literal's next byte per its next-byte mask.
IdSet literal_candidates(const IndexView& index, std::string_view text, bool insensitive) {
    struct Gram {
        size_t offset;
        int next;  // the folded byte after the trigram in the literal, % 8; -1 when unknown
        const IndexTrigram* entry;
    };
    const auto byte = [&](size_t i) { return static_cast<unsigned char>(text[i]); };
    std::vector<Gram> grams;
    for (size_t i = 0; i + 3 <= text.size(); ++i) {
        // Unicode case folding can match other bytes than a non-ASCII trigram holds.
        if (insensitive && (byte(i) >= 0x80 || byte(i + 1) >= 0x80 || byte(i + 2) >= 0x80)) continue;
        const uint32_t key = index_fold(text[i]) << 16 | index_fold(text[i + 1]) << 8 | index_fold(text[i + 2]);
        const IndexTrigram* entry = index.trigram(key);
        if (!entry) return std::vector<uint32_t>{};  // no indexed file held it
        if (entry->count == dense_trigram) continue;
        const bool next_known = i + 3 < text.size() && !(insensitive && byte(i + 3) >= 0x80);
        grams.push_back({i, next_known ? static_cast<int>(index_fold(text[i + 3]) & 7) : -1, entry});
    }
    if (grams.empty()) return std::nullopt;
    std::vector<std::vector<IndexPosting>> lists(grams.size());
    size_t driver = 0;
    for (size_t k = 0; k < grams.size(); ++k) {
        if (!index.postings(*grams[k].entry, lists[k])) return std::nullopt;
        if (lists[k].size() < lists[driver].size()) driver = k;
    }
    std::vector<size_t> cursor(grams.size(), 0);
    std::vector<const IndexPosting*> found(grams.size(), nullptr);
    std::vector<uint32_t> out;
    for (const IndexPosting& candidate : lists[driver]) {
        bool present = true, exhausted = false;
        for (size_t k = 0; k < grams.size() && present; ++k) {
            if (k == driver) { found[k] = &candidate; continue; }
            const auto& list = lists[k];
            size_t& c = cursor[k];
            while (c < list.size() && list[c].id < candidate.id) ++c;
            if (c == list.size()) exhausted = true;
            if (c == list.size() || list[c].id != candidate.id) present = false;
            else found[k] = &list[c];
        }
        if (exhausted) break;
        if (!present) continue;
        bool fits = true;
        for (size_t k = 0; k < grams.size() && fits; ++k)
            if (grams[k].next >= 0 && !(found[k]->next & (1u << grams[k].next))) fits = false;
        for (size_t k = 1; k < grams.size() && fits; ++k) {
            const auto shift = static_cast<unsigned>((grams[k].offset - grams[k - 1].offset) & 7);
            const unsigned loc = found[k - 1]->loc;
            const auto rotated = static_cast<uint8_t>(loc << shift | loc >> ((8 - shift) & 7));
            if (!(rotated & found[k]->loc)) fits = false;
        }
        if (fits) out.push_back(candidate.id);
    }
    return out;
}

IdSet evaluate_query(const IndexView& index, const QueryNode& node, bool insensitive) {
    switch (node.kind) {
    case QueryNode::all:
        return std::nullopt;
    case QueryNode::literal:
        return literal_candidates(index, node.text, insensitive);
    case QueryNode::and_: {
        IdSet result;
        std::vector<uint32_t> merged;
        for (const auto& child : node.children) {
            IdSet ids = evaluate_query(index, child, insensitive);
            if (!ids) continue;
            if (!result) result = std::move(ids);
            else {
                merged.clear();
                std::set_intersection(result->begin(), result->end(), ids->begin(), ids->end(), std::back_inserter(merged));
                result->swap(merged);
            }
            if (result->empty()) break;
        }
        return result;
    }
    case QueryNode::or_: {
        std::vector<uint32_t> result, merged;
        for (const auto& child : node.children) {
            IdSet ids = evaluate_query(index, child, insensitive);
            if (!ids) return std::nullopt;
            merged.clear();
            std::set_union(result.begin(), result.end(), ids->begin(), ids->end(), std::back_inserter(merged));
            result.swap(merged);
        }
        return result;
    }
    }
    return std::nullopt;
}

struct PatternPlan {
    QueryNode node;
    bool insensitive = false;
};

std::vector<PatternPlan> plan_patterns(const Request& r) {
    std::vector<PatternPlan> plans;
    for (const auto& pattern : r.patterns) {
        PatternPlan plan;
        plan.insensitive = r.insensitive;
        if (r.mode == "regex") {
            QueryPlanner planner(pattern);
            plan.node = planner.plan();
            plan.insensitive = plan.insensitive || planner.insensitive();
        } else {
            plan.node.kind = QueryNode::literal;
            plan.node.text = pattern;
        }
        plans.push_back(std::move(plan));
    }
    return plans;
}

// Files of `index` that may hold a match of some pattern, plus its always-candidates; nullopt when some pattern
// plans to nothing the index can look up.
IdSet base_candidates(const IndexView& index, const std::vector<PatternPlan>& plans) {
    std::vector<uint32_t> result, merged;
    for (const auto& plan : plans) {
        IdSet ids = evaluate_query(index, plan.node, plan.insensitive);
        if (!ids) return std::nullopt;
        merged.clear();
        std::set_union(result.begin(), result.end(), ids->begin(), ids->end(), std::back_inserter(merged));
        result.swap(merged);
    }
    std::vector<uint32_t> always;
    for (uint32_t id = 0; id < index.files(); ++id)
        if (index.flags(id) & unindexed_file) always.push_back(id);
    merged.clear();
    std::set_union(result.begin(), result.end(), always.begin(), always.end(), std::back_inserter(merged));
    return merged;
}

// literal_candidates for one file whose trigrams are known exactly (a live-index overlay entry).
bool literal_in_grams(const std::vector<uint64_t>& grams, std::string_view text, bool insensitive) {
    struct Gram {
        size_t offset;
        int next;
        unsigned loc, follow;
    };
    const auto byte = [&](size_t i) { return static_cast<unsigned char>(text[i]); };
    std::vector<Gram> found;
    for (size_t i = 0; i + 3 <= text.size(); ++i) {
        if (insensitive && (byte(i) >= 0x80 || byte(i + 1) >= 0x80 || byte(i + 2) >= 0x80)) continue;
        const uint64_t key = index_fold(text[i]) << 16 | index_fold(text[i + 1]) << 8 | index_fold(text[i + 2]);
        const auto it = std::lower_bound(grams.begin(), grams.end(), key, [](uint64_t g, uint64_t k) { return (g >> 16) < k; });
        if (it == grams.end() || (*it >> 16) != key) return false;
        const bool next_known = i + 3 < text.size() && !(insensitive && byte(i + 3) >= 0x80);
        found.push_back({i, next_known ? static_cast<int>(index_fold(text[i + 3]) & 7) : -1,
                         static_cast<unsigned>((*it >> 8) & 0xff), static_cast<unsigned>(*it & 0xff)});
    }
    for (size_t k = 0; k < found.size(); ++k)
        if (found[k].next >= 0 && !(found[k].follow & (1u << found[k].next))) return false;
    for (size_t k = 1; k < found.size(); ++k) {
        const auto shift = static_cast<unsigned>((found[k].offset - found[k - 1].offset) & 7);
        const unsigned loc = found[k - 1].loc;
        if (!(static_cast<uint8_t>(loc << shift | loc >> ((8 - shift) & 7)) & found[k].loc)) return false;
    }
    return true;
}

bool node_in_grams(const std::vector<uint64_t>& grams, const QueryNode& node, bool insensitive) {
    switch (node.kind) {
    case QueryNode::all:
        return true;
    case QueryNode::literal:
        return literal_in_grams(grams, node.text, insensitive);
    case QueryNode::and_:
        for (const auto& child : node.children)
            if (!node_in_grams(grams, child, insensitive)) return false;
        return true;
    case QueryNode::or_:
        for (const auto& child : node.children)
            if (node_in_grams(grams, child, insensitive)) return true;
        return false;
    }
    return true;
}

bool file_may_match(const std::vector<uint64_t>& grams, const std::vector<PatternPlan>& plans) {
    for (const auto& plan : plans)
        if (node_in_grams(grams, plan.node, plan.insensitive)) return true;
    return false;
}

struct IndexCandidate {
    std::string path;  // '/'-separated, below the root
    uint64_t size;
};

struct IndexUse {
    std::wstring root;  // walk root path, as file paths start
    std::vector<IndexCandidate> candidates;  // sorted by path, so consecutive candidates share directories
    uint64_t indexed_files = 0;
};

// The candidate's directories and name pass the request's filters, as visit_directory would have applied them.
bool index_path_passes(const Request& r, std::string_view relative, std::string_view name) {
    thread_local std::string prefix, part;
    size_t start = 0;
    for (size_t slash = relative.find('/'); slash != std::string_view::npos; slash = relative.find('/', slash + 1)) {
        prefix.assign(relative.substr(0, slash));
        part.assign(relative.substr(start, slash - start));
        if (!path_passes(r, prefix, part, true)) return false;
        start = slash + 1;
    }
    part.assign(name);
    prefix.assign(relative);
    return name_prefilter(r, part) && path_passes(r, prefix, part, false);
}

// One worker's open directory chain below an indexed root, reused while candidates stay in the same directory.
// SAFETY: each component is opened by name relative to its parent's handle with FILE_OPEN_REPARSE_POINT, as the
// walk does, so a junction or symlink below the root is opened as itself and nothing below it resolves.
struct DirCursor {
    std::vector<std::string> parts;
    std::vector<Handle> handles;  // handles[i] is the directory parts[0..i]
    std::wstring wide;
    HANDLE open(HANDLE root, std::string_view directory) {
        size_t depth = 0, start = 0;
        bool matching = true;
        while (!directory.empty() && start <= directory.size()) {
            size_t slash = directory.find('/', start);
            if (slash == std::string_view::npos) slash = directory.size();
            const std::string_view part = directory.substr(start, slash - start);
            start = slash + 1;
            if (matching && depth < parts.size() && parts[depth] == part) {
                ++depth;
                continue;
            }
            if (matching) {
                parts.resize(depth);
                handles.resize(depth);
                matching = false;
            }
            const HANDLE parent = handles.empty() ? root : handles.back().h;
            bool denied = false;
            if (!index_widen(part, wide)) return INVALID_HANDLE_VALUE;
            Handle child(open_relative(parent, wide, true, denied));
            if (!child) return INVALID_HANDLE_VALUE;
            parts.emplace_back(part);
            handles.push_back(std::move(child));
            ++depth;
        }
        if (matching) {
            parts.resize(depth);
            handles.resize(depth);
        }
        return handles.empty() ? root : handles.back().h;
    }
};

// Scans one indexed root's candidates instead of walking it.
void scan_index(const Request& r, const IndexUse& use, unsigned worker_count, Control& control, Outcome& out,
                const FileVisitor& on_file) {
    Handle root(open_root_directory(use.root));
    if (!root) { ++out.errors; return; }
    std::atomic<size_t> next{0};
    constexpr size_t chunk = 16;  // consecutive candidates share directories, so a worker takes them in runs
    auto run = [&](unsigned worker) {
        DirCursor cursor;
        std::wstring relative, full;
        for (;;) {
            if (control.stop.load()) return;
            if (const char* why = control.interrupted()) { finish(out, control, why); return; }
            const size_t first = next.fetch_add(chunk);
            if (first >= use.candidates.size()) return;
            const size_t last = std::min(first + chunk, use.candidates.size());
            for (size_t i = first; i < last && !control.stop.load(); ++i) {
                const std::string_view path = use.candidates[i].path;
                const size_t slash = path.rfind('/');
                const std::string_view directory = slash == std::string_view::npos ? std::string_view() : path.substr(0, slash);
                const std::string_view name = slash == std::string_view::npos ? path : path.substr(slash + 1);
                ++out.regular_seen;
                if (!index_path_passes(r, path, name)) { ++out.files_filtered; continue; }
                const HANDLE dir = cursor.open(root.h, directory);
                if (dir == INVALID_HANDLE_VALUE) { ++out.index_missing; continue; }
                if (!index_widen(path, relative)) { ++out.errors; continue; }
                std::replace(relative.begin(), relative.end(), L'/', L'\\');
                full = join_path(use.root, relative);
                const size_t cut = relative.rfind(L'\\');
                const std::wstring_view wide_name = cut == std::wstring::npos ? std::wstring_view(relative)
                                                                               : std::wstring_view(relative).substr(cut + 1);
                try {
                    on_file(worker, dir, wide_name, full, use.candidates[i].size);
                } catch (...) {
                    fail(out, control, std::current_exception());
                    return;
                }
            }
        }
    };
    auto crew = take_crew(worker_count);
    crew->run(run);
    park_crew(std::move(crew));
}

// Opens a file or directory below `parent` by its single name without following a link, with its basic and
// standard information.
HANDLE open_entry(HANDLE parent, std::wstring_view name, FILE_BASIC_INFO& basic, FILE_STANDARD_INFO& standard,
                  NTSTATUS& status) {
    constexpr ULONG file_open = 0x00000001;           // FILE_OPEN
    constexpr ULONG synchronous_io = 0x00000020;      // FILE_SYNCHRONOUS_IO_NONALERT
    constexpr ULONG open_reparse_point = 0x00200000;  // FILE_OPEN_REPARSE_POINT
    UNICODE_STRING object_name;
    object_name.Buffer = const_cast<PWSTR>(name.data());
    object_name.Length = object_name.MaximumLength = static_cast<USHORT>(name.size() * sizeof(wchar_t));
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = parent;
    attributes.ObjectName = &object_name;
    IO_STATUS_BLOCK io{};
    HANDLE handle = nullptr;
    status = NtCreateFile(&handle, FILE_GENERIC_READ, &attributes, &io, nullptr, 0,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, file_open,
                          synchronous_io | open_reparse_point, nullptr, 0);
    if (status < 0) return INVALID_HANDLE_VALUE;
    if (!GetFileInformationByHandleEx(handle, FileBasicInfo, &basic, sizeof(basic)) ||
        !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard))) {
        CloseHandle(handle);
        return INVALID_HANDLE_VALUE;
    }
    return handle;
}

// One overlay entry of a live index: a file changed or removed since the base index was written.
struct OverlayFile {
    uint64_t size = 0, write_time = 0, seq = 0;
    uint32_t flags = 0;
    bool removed = false;
    std::vector<uint64_t> grams;  // TrigramSet::grams
};

// Owner-approved (2026-10-09): the MCP server's live index for one root (`--live-index`), like tgrep serve.
// A watcher thread drains ReadDirectoryChangesW into a set of changed paths; an applier thread builds or loads the
// base index, reconciles it with the tree once, then re-indexes changed paths into an in-memory overlay; a merge
// thread folds a large overlay into a new base file in the background.
// CONTRACT: catch_up() returns only once every change Windows has reported is applied, so a search sees every edit
// completed before it started. Writes to a file that is still open may not be reported until it is closed. Buffer
// overflow, a changed .gitignore/.ignore and server start trigger a full reconciliation (size and last-write time
// against the tree), during which searches fall back to walking. Candidates are always read from disk; no file
// contents are cached.
class LiveIndex {
public:
    LiveIndex(SearchContext context, WalkRoot root, std::wstring file, std::string root_final)
        : context_(std::move(context)), root_(std::move(root)), file_(std::move(file)), root_final_(std::move(root_final)) {}

    void start() {
        root_handle_ = Handle(open_root_directory(root_.path));
        watch_ = Handle(CreateFileW(long_path(root_.path).c_str(), FILE_LIST_DIRECTORY,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr));
        event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!root_handle_ || !watch_ || !event_) {
            std::lock_guard lock(watch_mutex_);
            failed_ = true;
            state_ = "the root cannot be watched";
            return;
        }
        {
            // The watch starts before the build, so nothing that changes during it is lost.
            std::lock_guard lock(watch_mutex_);
            if (!issue_read()) {
                failed_ = true;
                state_ = "the root cannot be watched";
                return;
            }
        }
        std::thread([this] { watch_loop(); }).detach();
        std::thread([this] { apply_loop(); }).detach();
    }

    const std::wstring& final_path_text() const { return root_.final; }

    // The candidates for `r`, or nullopt with `why` when this index cannot serve it now.
    std::optional<IndexUse> serve(const Request& r, const Control& control, std::string& why) {
        if (!catch_up(control.deadline)) {
            std::lock_guard lock(watch_mutex_);
            why = state_;
            return std::nullopt;
        }
        const auto plans = plan_patterns(r);
        std::shared_lock lock(data_);
        IdSet ids = base_candidates(*base_, plans);
        if (!ids) {
            why = "a pattern has no literal text of 3+ bytes to look up";
            return std::nullopt;
        }
        IndexUse use{root_.path, {}, base_->files()};
        for (uint32_t id : *ids)
            if (!dead_[id]) use.candidates.push_back({std::string(base_->path(id)), base_->file_size(id)});
        uint64_t overlay_files = 0;
        for (const auto& [path, file] : overlay_) {
            if (file.removed) continue;
            ++overlay_files;
            if ((file.flags & unindexed_file) || file_may_match(file.grams, plans)) use.candidates.push_back({path, file.size});
        }
        use.indexed_files = base_->files() + overlay_files;
        std::sort(use.candidates.begin(), use.candidates.end(),
                  [](const IndexCandidate& a, const IndexCandidate& b) { return a.path < b.path; });
        return use;
    }

private:
    static constexpr DWORD watch_filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                          FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE |
                                          FILE_NOTIFY_CHANGE_ATTRIBUTES;
    static constexpr size_t max_pending = 100000;  // more changed paths than this are cheaper to reconcile

    // Waits, at most until the deadline and never more than 2 s, for every reported change to be applied. False
    // while the index is building or reconciling, so the search walks instead of waiting minutes.
    bool catch_up(Clock::time_point deadline) {
        std::unique_lock lock(watch_mutex_);
        if (!ready_ || failed_ || rescanning_) return false;
        deadline = std::min(deadline, Clock::now() + std::chrono::seconds(2));
        return watch_cv_.wait_until(lock, deadline, [&] {
                   return failed_ || rescanning_ ||
                          (!HasOverlappedIoCompleted(&overlapped_) && pending_.empty() && !rescan_ && !busy_);
               }) && !failed_ && !rescanning_;
    }

    // CONTRACT: watch_mutex_ held.
    bool issue_read() {
        overlapped_ = OVERLAPPED{};
        overlapped_.hEvent = event_;
        ResetEvent(event_);
        return ReadDirectoryChangesW(watch_.h, notify_.data(), static_cast<DWORD>(notify_.size() * sizeof(uint64_t)), TRUE,
                                     watch_filter, nullptr, &overlapped_, nullptr) != 0;
    }

    void watch_loop() {
        for (;;) {
            DWORD got = 0;
            const bool ok = GetOverlappedResult(watch_.h, &overlapped_, &got, TRUE) != 0;
            const DWORD error = ok ? 0 : GetLastError();
            bool stopped = false;
            {
                std::lock_guard lock(watch_mutex_);
                if (!ok && error != ERROR_NOTIFY_ENUM_DIR) {
                    failed_ = true;
                    state_ = "the watcher stopped (root deleted or renamed?)";
                } else if (!ok || got == 0) {
                    rescan_ = true;  // the change buffer overflowed: some changes are unknown
                } else {
                    parse(got);
                }
                if (!failed_ && !issue_read()) {
                    failed_ = true;
                    state_ = "the watcher stopped";
                }
                stopped = failed_;
            }
            watch_cv_.notify_all();
            if (stopped) return;
        }
    }

    // CONTRACT: watch_mutex_ held.
    void parse(DWORD bytes) {
        const auto* at = reinterpret_cast<const unsigned char*>(notify_.data());
        const auto* end = at + bytes;
        std::string relative;
        while (at + sizeof(FILE_NOTIFY_INFORMATION) <= end) {
            const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(at);
            const std::wstring_view name(info->FileName, info->FileNameLength / sizeof(wchar_t));
            if (try_utf8(name, relative) && !relative.empty()) {
                std::replace(relative.begin(), relative.end(), '\\', '/');
                const size_t slash = relative.rfind('/');
                const std::string_view leaf = slash == std::string::npos ? std::string_view(relative)
                                                                         : std::string_view(relative).substr(slash + 1);
                // The index's own writes below .shgrep never change what is indexed.
                const bool own = relative.size() >= 7 && equals_folded(std::string_view(relative).substr(0, 7), ".shgrep") &&
                                 (relative.size() == 7 || relative[7] == '/');
                if (!own) {
                    if (equals_folded(leaf, ".gitignore") || equals_folded(leaf, ".ignore")) rescan_ = true;
                    pending_.insert(relative);
                    if (pending_.size() > max_pending) {
                        pending_.clear();
                        rescan_ = true;
                    }
                }
            }
            if (info->NextEntryOffset == 0) break;
            at += info->NextEntryOffset;
        }
    }

    void apply_loop() {
        try {
            load_or_build();
        } catch (const std::exception& e) {
            std::lock_guard lock(watch_mutex_);
            failed_ = true;
            state_ = std::string("index build failed: ") + e.what();
            watch_cv_.notify_all();
            return;
        }
        {
            // An index written before the server started can be stale: reconcile it with the tree once.
            std::lock_guard lock(watch_mutex_);
            ready_ = true;
            rescan_ = true;
            state_ = "the index is reconciling with the tree";
        }
        for (;;) {
            std::set<std::string> batch;
            bool rescan = false;
            {
                std::unique_lock lock(watch_mutex_);
                watch_cv_.wait(lock, [&] { return failed_ || rescan_ || !pending_.empty(); });
                if (failed_) return;
                rescan = rescan_;
                rescan_ = false;
                batch.swap(pending_);
                busy_ = true;
                if (rescan) {
                    batch.clear();
                    rescanning_ = true;
                    state_ = "the index is reconciling with the tree";
                }
            }
            try {
                if (rescan) reconcile("");
                else for (const auto& path : batch) apply_path(path);
            } catch (const std::exception& e) {
                std::fprintf(stderr, "shgrep: live index: %s\n", e.what());
            }
            {
                std::lock_guard lock(watch_mutex_);
                busy_ = false;
                rescanning_ = false;
                state_ = "ready";
            }
            watch_cv_.notify_all();
            maybe_merge();
        }
    }

    void load_or_build() {
        auto base = std::make_shared<IndexView>(file_, root_.final);
        if (!*base) {
            const unsigned workers = index_workers();
            PostingSorter sorter(ensure_index_directory(file_), index_sort_budget, workers);
            const TreeIndex tree = index_tree(context_, root_, sorter, workers, std::make_shared<std::atomic_bool>(false));
            write_index_file(file_, root_final_, tree.files, sorter, {});
            base = std::make_shared<IndexView>(file_, root_.final);
            if (!*base) throw std::runtime_error("the new index cannot be read back");
        }
        std::unique_lock lock(data_);
        install(std::move(base));
    }

    // CONTRACT: data_ held exclusively.
    void install(std::shared_ptr<IndexView> base) {
        base_ = std::move(base);
        ids_.clear();
        ids_.reserve(base_->files());
        for (uint32_t id = 0; id < base_->files(); ++id) ids_.emplace(base_->path(id), id);
        dead_.assign(base_->files(), false);
    }

    // The handle and ignore scope (with its own rules) of a directory below the root, or false when it is gone, a
    // link, hidden or ignored. CONTRACT: applier thread only.
    bool directory(const std::string& relative, HANDLE& handle, std::shared_ptr<const IgnoreScope>& scope) {
        handle = cursor_.open(root_handle_.h, relative);
        if (handle == INVALID_HANDLE_VALUE) return false;
        const auto with_rules = [&](std::shared_ptr<const IgnoreScope> parent, const std::string& dir) {
            auto next = std::make_shared<IgnoreScope>();
            next->parent = parent;
            std::wstring wide;
            index_widen(dir, wide);
            std::replace(wide.begin(), wide.end(), L'/', L'\\');
            read_ignore_rules(dir.empty() ? root_.path : join_path(root_.path, wide), dir, true, true, next->rules);
            return next->rules.empty() ? parent : std::shared_ptr<const IgnoreScope>(std::move(next));
        };
        auto cached = scopes_.find("");
        if (cached == scopes_.end()) cached = scopes_.emplace("", DirState{true, with_rules(nullptr, "")}).first;
        scope = cached->second.scope;
        size_t depth = 0, start = 0;
        while (!relative.empty() && start <= relative.size()) {
            size_t slash = relative.find('/', start);
            if (slash == std::string::npos) slash = relative.size();
            const std::string prefix = relative.substr(0, slash);
            const std::string_view name = std::string_view(relative).substr(start, slash - start);
            start = slash + 1;
            auto it = scopes_.find(prefix);
            if (it == scopes_.end()) {
                bool selected = !name.empty() && name.front() != '.' && !ignored_path(scope.get(), prefix, true);
                FILE_BASIC_INFO basic{};
                if (selected && depth < cursor_.handles.size() &&
                    GetFileInformationByHandleEx(cursor_.handles[depth].h, FileBasicInfo, &basic, sizeof(basic)) &&
                    (basic.FileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_REPARSE_POINT)))
                    selected = false;
                it = scopes_.emplace(prefix, DirState{selected, selected ? with_rules(scope, prefix) : scope}).first;
            }
            if (!it->second.selected) return false;
            scope = it->second.scope;
            ++depth;
        }
        return true;
    }

    // Re-reads one changed path. CONTRACT: applier thread only.
    void apply_path(const std::string& relative) {
        const size_t slash = relative.rfind('/');
        const std::string parent = slash == std::string::npos ? std::string() : relative.substr(0, slash);
        const std::string name = slash == std::string::npos ? relative : relative.substr(slash + 1);
        HANDLE dir = INVALID_HANDLE_VALUE;
        std::shared_ptr<const IgnoreScope> scope;
        std::wstring wide;
        if (name.empty() || name.front() == '.' || !directory(parent, dir, scope) || !index_widen(name, wide)) {
            remove_tree(relative);
            return;
        }
        FILE_BASIC_INFO basic{};
        FILE_STANDARD_INFO standard{};
        NTSTATUS status = 0;
        Handle h(open_entry(dir, wide, basic, standard, status));
        if (!h) {
            constexpr NTSTATUS access_denied = static_cast<NTSTATUS>(0xC0000022L);
            if (status == access_denied && !binary_extension(name) && !ignored_path(scope.get(), relative, false)) {
                OverlayFile file;
                file.flags = unindexed_file;  // as the build does: searched every time, so the error is reported
                put(relative, std::move(file));
            } else {
                remove_tree(relative);
            }
            return;
        }
        const DWORD attributes = basic.FileAttributes;
        const bool is_directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if ((attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_HIDDEN)) ||
            ignored_path(scope.get(), relative, is_directory) || (!is_directory && binary_extension(name))) {
            remove_tree(relative);
            return;
        }
        if (is_directory) {
            h.close();
            reconcile(relative);  // a directory moved or created here: its files may never have been reported
            return;
        }
        index_file(relative, h.h, static_cast<uint64_t>(standard.EndOfFile.QuadPart));
    }

    // CONTRACT: applier thread only.
    void index_file(const std::string& relative, HANDLE h, uint64_t listed) {
        OverlayFile file;
        file.size = listed;
        std::optional<DecodedText> decoded;
        std::string_view contents;
        const IndexRead kind = index_text(h, Request{}.max_file_bytes, raw_, decoded, contents, file.size, file.write_time);
        if (kind == IndexRead::unreadable) {
            file.flags = unindexed_file;
        } else if (kind == IndexRead::text) {
            trigrams_.collect(contents);
            file.grams = trigrams_.grams;
        }
        put(relative, std::move(file));
    }

    void put(const std::string& relative, OverlayFile file) {
        std::unique_lock lock(data_);
        file.seq = ++seq_;
        if (const auto id = ids_.find(relative); id != ids_.end()) dead_[id->second] = true;
        overlay_[relative] = std::move(file);
    }

    // Marks `relative` and everything below it removed.
    void remove_tree(const std::string& relative) {
        std::unique_lock lock(data_);
        const std::string below = relative + "/";
        const auto mark = [&](const std::string& path) {
            OverlayFile& file = overlay_[path];
            file = OverlayFile{};
            file.removed = true;
            file.seq = ++seq_;
        };
        if (const auto id = ids_.find(relative); id != ids_.end() && !dead_[id->second]) {
            dead_[id->second] = true;
            mark(relative);
        } else if (const auto it = overlay_.find(relative); it != overlay_.end() && !it->second.removed) {
            mark(relative);
        }
        for (const auto& [path, id] : ids_) {
            if (!dead_[id] && path.size() > below.size() && path.compare(0, below.size(), below) == 0) {
                dead_[id] = true;
                mark(std::string(path));
            }
        }
        for (auto it = overlay_.lower_bound(below); it != overlay_.end() && it->first.compare(0, below.size(), below) == 0; ++it) {
            if (it->second.removed) continue;
            it->second = OverlayFile{};
            it->second.removed = true;
            it->second.seq = ++seq_;
        }
    }

    // Compares every selected file below `start` ('' for the root) with the index by size and last-write time,
    // re-indexes what differs and removes what is gone. CONTRACT: applier thread only.
    void reconcile(const std::string& start) {
        if (start.empty()) scopes_.clear();
        HANDLE first = INVALID_HANDLE_VALUE;
        std::shared_ptr<const IgnoreScope> first_scope;
        if (!directory(start, first, first_scope)) {
            if (!start.empty()) remove_tree(start);
            return;
        }
        std::vector<bool> seen_base;
        std::unordered_set<std::string> seen_overlay;
        std::vector<std::string> changed;
        {
            std::shared_lock lock(data_);
            seen_base.assign(base_->files(), false);
        }
        struct Item {
            std::string relative;
            std::shared_ptr<Handle> handle;  // null: the starting directory, held by cursor_
            std::shared_ptr<const IgnoreScope> scope;
            bool rules_loaded;
        };
        std::vector<Item> stack;
        stack.push_back({start, nullptr, first_scope, true});
        std::vector<uint64_t> listing(8192);
        std::vector<DirEntry> entries;
        std::string name, relative;
        std::wstring wide;
        while (!stack.empty()) {
            Item item = std::move(stack.back());
            stack.pop_back();
            const HANDLE handle = item.handle ? item.handle->h : first;
            if (!list_directory(handle, listing, entries)) continue;
            std::shared_ptr<const IgnoreScope> scope = item.scope;
            if (!item.rules_loaded) {
                bool rules = false;
                for (const auto& entry : entries)
                    if (!(entry.attributes & FILE_ATTRIBUTE_DIRECTORY) &&
                        (same_name(entry.name, L".gitignore") || same_name(entry.name, L".ignore"))) rules = true;
                if (rules) {
                    auto next = std::make_shared<IgnoreScope>();
                    next->parent = scope;
                    index_widen(item.relative, wide);
                    std::replace(wide.begin(), wide.end(), L'/', L'\\');
                    read_ignore_rules(join_path(root_.path, wide), item.relative, true, true, next->rules);
                    if (!next->rules.empty()) scope = std::move(next);
                }
            }
            for (const auto& entry : entries) {
                if (!try_utf8(entry.name, name) || name.empty()) continue;
                const bool is_directory = (entry.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                if (entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
                if (name.front() == '.' || (entry.attributes & FILE_ATTRIBUTE_HIDDEN)) continue;
                relative = item.relative.empty() ? name : item.relative + "/" + name;
                if (ignored_path(scope.get(), relative, is_directory)) continue;
                if (is_directory) {
                    bool denied = false;
                    HANDLE child = open_relative(handle, entry.name, true, denied);
                    if (child == INVALID_HANDLE_VALUE) continue;
                    stack.push_back({relative, std::make_shared<Handle>(child), scope, false});
                    continue;
                }
                if (binary_extension(name)) continue;
                std::shared_lock lock(data_);
                if (const auto it = overlay_.find(relative); it != overlay_.end()) {
                    seen_overlay.insert(relative);
                    if (!it->second.removed && it->second.size == entry.size && it->second.write_time == entry.write_time) continue;
                } else if (const auto id = ids_.find(relative); id != ids_.end() && !dead_[id->second]) {
                    seen_base[id->second] = true;
                    if (base_->file_size(id->second) == entry.size && base_->write_time(id->second) == entry.write_time) continue;
                }
                changed.push_back(relative);
            }
        }
        for (const auto& path : changed) {
            seen_overlay.insert(path);
            apply_path(path);
        }
        // Known files below `start` that the tree no longer has.
        std::vector<std::string> gone;
        {
            std::shared_lock lock(data_);
            const std::string below = start.empty() ? std::string() : start + "/";
            const auto under = [&](std::string_view path) { return below.empty() || path.compare(0, below.size(), below) == 0; };
            for (const auto& [path, id] : ids_)
                if (!dead_[id] && !seen_base[id] && under(path)) gone.emplace_back(path);
            for (const auto& [path, file] : overlay_)
                if (!file.removed && !seen_overlay.count(path) && under(path)) gone.push_back(path);
        }
        for (const auto& path : gone) remove_tree(path);
    }

    // Folds the overlay into a new base file once it grows past a sixteenth of the base, in the background; changes
    // applied meanwhile stay in the overlay.
    void maybe_merge() {
        size_t changed = 0, base_files = 0;
        {
            std::shared_lock lock(data_);
            changed = overlay_.size();
            base_files = base_->files();
        }
        if (changed < std::max<size_t>(4096, base_files / 16) || merging_.exchange(true)) return;
        std::thread([this] {
            try {
                merge();
            } catch (const std::exception& e) {
                std::fprintf(stderr, "shgrep: live index merge: %s\n", e.what());
            }
            merging_ = false;
        }).detach();
    }

    void merge() {
        std::shared_ptr<IndexView> base;
        std::vector<bool> dead;
        std::map<std::string, OverlayFile> overlay;
        uint64_t snapshot = 0;
        {
            std::shared_lock lock(data_);
            base = base_;
            dead = dead_;
            overlay = overlay_;
            snapshot = seq_;
        }
        std::vector<IndexEntry> files;
        std::vector<uint32_t> remap(base->files(), 0xffffffffu);
        for (uint32_t id = 0; id < base->files(); ++id) {
            if (dead[id]) continue;
            remap[id] = static_cast<uint32_t>(files.size());
            files.push_back({std::string(base->path(id)), base->file_size(id), base->write_time(id), base->flags(id)});
        }
        PostingSorter sorter(ensure_index_directory(file_), index_sort_budget, 1);
        std::unordered_set<uint32_t> dense;
        std::vector<IndexPosting> list;
        for (uint32_t i = 0; i < base->trigram_count(); ++i) {
            const IndexTrigram& t = base->trigram_at(i);
            if (t.count == dense_trigram) {
                dense.insert(t.key);
                continue;
            }
            if (!base->postings(t, list)) throw std::runtime_error("the base index is damaged");
            for (const IndexPosting& p : list)
                if (remap[p.id] != 0xffffffffu)
                    sorter.add(0, t.key, remap[p.id], static_cast<uint16_t>(p.loc << 8 | p.next));
        }
        for (const auto& [path, file] : overlay) {
            if (file.removed) continue;
            const auto id = static_cast<uint32_t>(files.size());
            files.push_back({path, file.size, file.write_time, file.flags});
            if (!file.grams.empty()) sorter.add_file(0, id, file.grams);
        }
        write_index_file(file_, root_final_, files, sorter, dense);
        auto next = std::make_shared<IndexView>(file_, root_.final);
        if (!*next) throw std::runtime_error("the merged index cannot be read back");
        std::unique_lock lock(data_);
        install(std::move(next));
        for (auto it = overlay_.begin(); it != overlay_.end();) {
            if (it->second.seq <= snapshot) {
                it = overlay_.erase(it);
                continue;
            }
            if (const auto id = ids_.find(it->first); id != ids_.end()) dead_[id->second] = true;
            ++it;
        }
    }

    struct DirState {
        bool selected;
        std::shared_ptr<const IgnoreScope> scope;  // including the directory's own rules
    };

    const SearchContext context_;
    const WalkRoot root_;
    const std::wstring file_;
    const std::string root_final_;

    // Index data. data_ guards base_, ids_, dead_, overlay_ and seq_.
    std::shared_mutex data_;
    std::shared_ptr<IndexView> base_;
    std::unordered_map<std::string_view, uint32_t> ids_;  // base path -> id; views into base_'s mapping
    std::vector<bool> dead_;                               // base ids superseded by overlay_
    std::map<std::string, OverlayFile> overlay_;          // sorted, so a directory's entries are one range
    uint64_t seq_ = 0;
    std::atomic_bool merging_{false};

    // Watcher state. watch_mutex_ guards everything here except notify_ while a read is pending.
    std::mutex watch_mutex_;
    std::condition_variable watch_cv_;
    Handle watch_;
    HANDLE event_ = nullptr;
    OVERLAPPED overlapped_{};
    std::vector<uint64_t> notify_ = std::vector<uint64_t>((1u << 20) / sizeof(uint64_t));  // 1 MiB, DWORD-aligned
    std::set<std::string> pending_;
    bool ready_ = false, failed_ = false, rescan_ = false, rescanning_ = false, busy_ = false;
    std::string state_ = "the index is being built";

    // Applier thread state.
    Handle root_handle_;
    DirCursor cursor_;
    std::unordered_map<std::string, DirState> scopes_;
    TrigramSet trigrams_;
    std::string raw_;
};

std::mutex& live_mutex() {
    static std::mutex mutex;
    return mutex;
}
// COMPAT: never destroyed; their threads run until the process exits.
std::vector<LiveIndex*>& live_indexes() {
    static auto* indexes = new std::vector<LiveIndex*>;
    return *indexes;
}

LiveIndex* find_live_index(const std::wstring& root_final) {
    std::lock_guard lock(live_mutex());
    for (LiveIndex* live : live_indexes()) {
        const std::wstring& final = live->final_path_text();
        if (final.size() == root_final.size() &&
            CompareStringOrdinal(final.data(), static_cast<int>(final.size()), root_final.data(),
                                 static_cast<int>(root_final.size()), TRUE) == CSTR_EQUAL)
            return live;
    }
    return nullptr;
}

// Serves each walk root from its live index (MCP server with --live-index) or its snapshot file. Roots the index
// serves move to `uses`; the others stay in `roots` and are walked. Returns the note the result carries.
std::string prepare_index(const Request& r, const SearchContext& context, const Control& control,
                          std::vector<WalkRoot>& roots, std::vector<IndexUse>& uses) {
    if (r.invert) return "[index not used: invert needs every file]\n";
    if (r.output == "files_without_match") return "[index not used: files_without_match needs every file]\n";
    if (r.hidden || r.no_ignore || r.sniff_all)
        return "[index not used: it holds the default selection, without hidden, ignored or binary-extension files]\n";
    std::string note;
    uint64_t oldest = 0;
    bool live_used = false;
    std::vector<WalkRoot> walked;
    for (auto& root : roots) {
        std::string display;
        try_utf8(root.path, display);
        if (LiveIndex* live = find_live_index(root.final)) {
            std::string why;
            auto use = live->serve(r, control, why);
            if (!use) {
                note += "[index not used for " + display + ": " + why + "; searched by walking]\n";
                walked.push_back(std::move(root));
                continue;
            }
            live_used = true;
            uses.push_back(std::move(*use));
            continue;
        }
        IndexView view(index_file_path(context, root.final), root.final);
        if (!view) {
            note += "[index: none for " + display + "; build it with: shgrep index --root \"" + display + "\"]\n";
            walked.push_back(std::move(root));
            continue;
        }
        IdSet ids = base_candidates(view, plan_patterns(r));
        if (!ids) {
            note += "[index not used for " + display + ": a pattern has no literal text of 3+ bytes to look up]\n";
            walked.push_back(std::move(root));
            continue;
        }
        if (!oldest || view.built() < oldest) oldest = view.built();
        IndexUse use{root.path, {}, view.files()};
        use.candidates.reserve(ids->size());
        for (uint32_t id : *ids) use.candidates.push_back({std::string(view.path(id)), view.file_size(id)});
        std::sort(use.candidates.begin(), use.candidates.end(),
                  [](const IndexCandidate& a, const IndexCandidate& b) { return a.path < b.path; });
        uses.push_back(std::move(use));
    }
    roots = std::move(walked);
    if (live_used) note += "[index: live, kept current by the file watcher]\n";
    if (oldest)
        note += "[index: snapshot built " + utc_text(oldest) + "; files added since then are not searched and files "
                "edited since can be missed; rebuild with: shgrep index]\n";
    return note;
}

} // namespace

void start_live_indexes(const SearchContext& context) {
    for (const auto& allowed : context.allowed_roots) {
        Handle root(CreateFileW(allowed.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        if (!root) {
            std::fprintf(stderr, "shgrep: live index: root unavailable\n");
            continue;
        }
        WalkRoot walk_root{fs::absolute(allowed).lexically_normal().wstring(), final_path(root.h)};
        std::string root_final;
        const std::wstring file = index_file_path(context, walk_root.final);
        if (!try_utf8(walk_root.final, root_final) || file.empty()) {
            std::fprintf(stderr, "shgrep: live index: cannot place the index for a root\n");
            continue;
        }
        auto* live = new LiveIndex(context, std::move(walk_root), file, std::move(root_final));
        {
            std::lock_guard lock(live_mutex());
            live_indexes().push_back(live);
        }
        live->start();
    }
}


Json run_tool(const std::string& name, const Json& arguments,
              const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (is_file_tool(name)) return run_file_tool(name, arguments, context, cancelled);
    // CONTRACT: CLI only (`shgrep index`); tool_list never offers it, so MCP clients cannot reach it.
    if (name == "index") return build_index(context, cancelled);
    if (name != "search" && name != "search_bytes" && name != "find_files") throw std::runtime_error("unknown tool");
    Request r = parse_request(name, arguments, context);
    const auto started = Clock::now();
    Control control{cancelled, started + std::chrono::milliseconds(r.timeout_ms)};
    const int64_t began = ticks();
    std::shared_ptr<const Database> database;
    if (!r.file_only) database = compiled_database(r, context);
    const int64_t compiled = ticks();
    std::vector<std::pair<fs::path, std::wstring>> roots;
    for (const auto& allowed : context.allowed_roots) {
        Handle h(CreateFileW(allowed.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        if (!h) throw std::runtime_error("configured root unavailable: " + utf8(allowed.wstring()));
        roots.emplace_back(allowed, final_path(h.h));
    }
    std::vector<std::pair<fs::path, std::wstring>> selected;
    for (const auto& raw : r.roots) {
        Handle h(CreateFileW(raw.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        if (!h) throw std::runtime_error("requested root unavailable: " + utf8(raw.wstring()));
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(h.h, &info) || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            throw std::runtime_error("requested root is not a directory");
        std::wstring final = final_path(h.h);
        bool allowed = false;
        for (const auto& root : roots) if (inside(final, root.second)) { allowed = true; break; }
        if (!allowed) throw std::runtime_error("requested root is outside configured roots");
        selected.emplace_back(raw, final);
    }
    std::sort(selected.begin(), selected.end(), [](const auto& a, const auto& b) { return a.second.size() < b.second.size(); });
    std::vector<WalkRoot> walk_roots;
    for (auto& candidate : selected) {
        bool covered = false;
        for (const auto& prior : walk_roots) if (inside(candidate.second, prior.final)) { covered = true; break; }
        if (!covered) walk_roots.push_back({fs::absolute(candidate.first).lexically_normal().wstring(), std::move(candidate.second)});
    }
    // CONTRACT: the workspace's .shgrep directory (the pattern cache) is never walked, whatever hidden or
    // no_ignore say. Walks build paths from the walk root's path, so the cache's final path is mapped onto it.
    if (!roots.empty()) {
        const std::wstring cache_parent = join_path(roots.front().second, cache_directory_name);
        for (const auto& root : walk_roots) {
            if (cache_parent.size() <= root.final.size() || !inside(cache_parent, root.final)) continue;
            const size_t skip = root.final.size() + (root.final.back() == L'\\' ? 0 : 1);
            r.excluded_directories.push_back(join_path(root.path, std::wstring_view(cache_parent).substr(skip)));
        }
    }

    const int64_t resolved = ticks();
    Outcome out;
    // JSON output is escaped twice (result object, then MCP text), so it gets half the budget; text output is
    // escaped once and keeps room for the footer.
    const bool text_output = r.output != "json";
    // PERF: publish never holds more than max_results items, so the shared vectors never reallocate under its
    // lock. Json's move is not noexcept (MSVC std::map), so each regrowth deep-copied every result while all
    // workers waited.
    if (text_output) out.blocks.reserve(r.max_results);
    else out.results.reserve(r.max_results);
    const size_t content_budget = text_output ? (r.max_output > 1024 ? r.max_output - 768 : r.max_output / 2)
                                              : (r.max_output >= 1024 ? (r.max_output - 512) / 2 : r.max_output / 2);
    // PERF: one worker per logical processor across all processor groups, by the owner's decision.
    // Concurrent MCP requests each get their own full pool.
    const DWORD processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    // PERF: measured 12/18/24 workers on a 12-thread CPU with a warm cache: more workers than logical
    // processors did not hide open latency and was up to 6 ms slower.
    const unsigned worker_override = env_workers();
    const unsigned worker_count = worker_override ? worker_override
                                  : processors == 0 ? 1u : static_cast<unsigned>(processors);
    std::vector<WorkerProfile> profiles(r.profile ? worker_count : 0);
    std::vector<std::unique_ptr<Worker>> workers;
    for (unsigned i = 0; i < worker_count; ++i) {
        auto worker = std::make_unique<Worker>();
        if (r.profile) worker->profile = &profiles[i];
        if (database) {
            // PCRE2 databases have no Hyperscan scratch; their match state is created per worker on first use.
            const bool cloned = !database->db || hs_clone_scratch(database->scratch, &worker->scratch) == HS_SUCCESS;
            if (!cloned) throw std::runtime_error("scratch allocation failed");
            if (database->engine) worker->engine_scratch = database->engine->make_scratch();
        }
        workers.push_back(std::move(worker));
    }
    MemoryBudget memory(text_memory_budget);
    // CONTRACT: relative paths need a single walk root, which the response then names once; with several roots
    // paths stay absolute.
    std::wstring relative_prefix;
    std::string relative_root;
    if (r.relative && walk_roots.size() == 1 && try_utf8(walk_roots.front().path, relative_root)) {
        relative_prefix = walk_roots.front().path;
        if (!relative_prefix.empty() && relative_prefix.back() != L'\\' && relative_prefix.back() != L'/')
            relative_prefix.push_back(L'\\');
    }
    // CONTRACT: only a request with index: true consults an index; every other search walks every root as before.
    std::vector<IndexUse> index_uses;
    std::string index_note;
    std::vector<WalkRoot> plain_roots = walk_roots;
    if (r.use_index) index_note = prepare_index(r, context, control, plain_roots, index_uses);
    const ScanShared shared{r, database.get(), control, out, memory, content_budget, relative_prefix};
    const int64_t prepared = ticks();
    const FileVisitor visit = [&](unsigned index, HANDLE directory, std::wstring_view name, const std::wstring& path,
                                  uint64_t listed_size) {
        try { scan_file(shared, *workers[index], directory, name, path, listed_size); }
        catch (const fs::filesystem_error&) { ++out.errors; }
    };
    for (const auto& use : index_uses) {
        for (auto& worker : workers) worker->index_snapshot = true;
        scan_index(r, use, worker_count, control, out, visit);
        for (auto& worker : workers) worker->index_snapshot = false;
    }
    if (!plain_roots.empty())
        walk(r, plain_roots, worker_count, control, out, visit, profiles.empty() ? nullptr : profiles.data());
    const int64_t walked = ticks();
    if (out.failure) std::rethrow_exception(out.failure);

    const uint64_t files = out.files.load(), errors = out.errors.load(), skipped_size = out.skipped_size.load();
    std::string state = out.state;
    if (state == "complete" && out.per_file_limited.load()) state = "per_file_limit";
    if (state == "complete" && (errors || skipped_size)) state = "partial_files";
    Json::Array results = std::move(out.results);
    std::vector<TextBlock> blocks = std::move(out.blocks);
    Json::Array skipped_files = std::move(out.skipped_files);
    // CONTRACT: workers finish files in nondeterministic order; sorting keeps output stable for a result set.
    // PERF: both sorts order indexes by keys read once, then move each element once; moving Json values
    // allocates on MSVC, and stable_sort moves each element O(log n) times.
    if (!blocks.empty()) {
        std::vector<size_t> order(blocks.size());
        for (size_t i = 0; i < order.size(); ++i) order[i] = i;
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return blocks[a].path < blocks[b].path; });
        std::vector<TextBlock> sorted;
        sorted.reserve(blocks.size());
        for (size_t i : order) sorted.push_back(std::move(blocks[i]));
        blocks = std::move(sorted);
    }
    if (!results.empty()) {
        struct Key {
            const std::string* path;
            const Json* start;
        };
        std::vector<Key> keys;
        keys.reserve(results.size());
        for (const auto& item : results) keys.push_back({&item.object().at("path").string(), item.get("byte_start")});
        std::vector<size_t> order(results.size());
        for (size_t i = 0; i < order.size(); ++i) order[i] = i;
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
            const Key& x = keys[a];
            const Key& y = keys[b];
            if (*x.path != *y.path) return *x.path < *y.path;
            return x.start && y.start && x.start->integer() < y.start->integer();
        });
        Json::Array sorted;
        sorted.reserve(results.size());
        for (size_t i : order) sorted.push_back(std::move(results[i]));
        results = std::move(sorted);
    }
    const int64_t ordered = ticks();
    auto elapsed = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count());
    uint64_t index_files = 0, index_opened = 0;
    for (const auto& use : index_uses) {
        index_files += use.indexed_files;
        index_opened += use.candidates.size();
    }
    if (!index_uses.empty()) {
        index_note += "[index: " + std::to_string(index_opened) + " of " + std::to_string(index_files) +
                      " indexed files were candidates";
        if (out.index_missing.load()) index_note += ", " + std::to_string(out.index_missing.load()) + " of them deleted since";
        index_note += "]\n";
    }
    // An index that ruled out every file is not a selection problem.
    bool show_selection = files == 0 && index_uses.empty();
    auto make_profile = [&] {
        // Request phases are wall-clock time on the calling thread.
        Json::Object profile = profile_json(profiles, prepared);
        profile.emplace("request_us", Json::Object{{"compile", ticks_to_us(compiled - began)},
            {"roots", ticks_to_us(resolved - compiled)}, {"setup", ticks_to_us(prepared - resolved)},
            {"walk", ticks_to_us(walked - prepared)}, {"sort", ticks_to_us(ordered - walked)},
            {"finish", ticks_to_us(ticks() - walked)}});
        if (database) {
            const char* engine = database->engine ? backend_name(database->engine->backend())
                                                  : database->db ? "hyperscan" : "pcre2";
            profile.emplace("backend", std::string(engine));
            profile.emplace("engine_fallbacks", out.engine_fallbacks.load());
        }
        if (Closer* closer = Closer::get()) profile.emplace("closes_pending", closer->pending());
        return profile;
    };
    if (text_output) {
        Footer footer{state, {}, files, errors, skipped_size, elapsed, 0, show_selection,
                      out.regular_seen.load(), out.files_filtered.load(), out.files_ignored.load(),
                      out.files_hidden.load(), out.directories_pruned.load(), out.reparse_skipped.load()};
        for (const auto& root : walk_roots) {
            std::string display;
            if (try_utf8(root.path, display)) footer.roots.push_back(std::move(display));
        }
        const bool separate_files = r.output == "lines" && (r.before_lines || r.after_lines);
        for (;;) {
            std::string text;
            uint64_t units = 0;
            size_t length = 0;
            for (const auto& block : blocks) length += block.text.size() + 3;
            text.reserve(length + 1024);
            if (!relative_prefix.empty() && !blocks.empty()) text += "[paths relative to " + relative_root + "]\n";
            for (size_t i = 0; i < blocks.size(); ++i) {
                if (separate_files && i) text += "--\n";
                text += blocks[i].text;
                units += blocks[i].units;
            }
            footer.state = state;
            footer.returned = units;
            text += render_footer(r, footer, skipped_files);
            text += index_note;
            // PERF: blocks were budgeted while publishing, so this loop rarely drops anything.
            if (blocks.empty() || Json::escaped_size(text) + 256 <= r.max_output) {
                // CONTRACT: the diagnostic profile is a trailing line, added after the budget check.
                if (!profiles.empty()) text += "[profile " + Json(make_profile()).dump() + "]\n";
                return Json::Object{{"text", std::move(text)},
                    {"summary", summary(files, out.bytes.load(), out.found.load(), units, errors, skipped_size,
                                        out.skipped_binary.load(), elapsed, state)}};
            }
            blocks.pop_back();
            state = "output_limit";
        }
    }
    Json output;
    do {
        Json::Object payload{{"results", results}, {"skipped_files", skipped_files},
            {"summary", summary(files, out.bytes.load(), out.found.load(), results.size(), errors, skipped_size,
                                out.skipped_binary.load(), elapsed, state)}};
        if (show_selection)
            payload.emplace("selection", Json::Object{{"regular_files_seen", out.regular_seen.load()},
                {"files_filtered", out.files_filtered.load()}, {"files_ignored", out.files_ignored.load()},
                {"files_hidden", out.files_hidden.load()}, {"directories_pruned", out.directories_pruned.load()},
                {"reparse_points_skipped", out.reparse_skipped.load()}});
        if (!relative_prefix.empty()) payload.emplace("root", relative_root);
        if (!index_note.empty())
            payload.emplace("index", Json::Object{{"note", index_note}, {"candidates", index_opened},
                                                  {"indexed_files", index_files}, {"deleted", out.index_missing.load()}});
        if (!profiles.empty()) payload.emplace("profile", make_profile());
        output = std::move(payload);
        if (output.dump().size() <= content_budget) break;
        if (show_selection) { show_selection = false; continue; }
        if (!skipped_files.empty()) { skipped_files.pop_back(); continue; }
        if (results.empty()) throw std::runtime_error("max_output_bytes cannot hold summary");
        results.pop_back(); state = "output_limit";
    } while (true);
    return output;
}

// CONTRACT: these descriptions are the model's only documentation of the tools; every statement must match the
// implementation. Update them with any behavior change.
Json tool_definitions() {
    // PERF: these schemas are sent to the model with every session; every word costs tokens. Keep contracts an
    // agent needs to call correctly, nothing else.
    auto schema = [](Json::Object properties) -> Json {
        return Json::Object{{"type", "object"}, {"properties", std::move(properties)}, {"additionalProperties", false}};
    };
    auto field = [](const char* type, const char* description) -> Json {
        return Json::Object{{"type", type}, {"description", description}};
    };
    auto list = [](const char* description) -> Json {
        return Json::Object{{"type", "array"}, {"items", Json::Object{{"type", "string"}}}, {"description", description}};
    };
    auto choice = [](Json::Array values, const char* description) -> Json {
        return Json::Object{{"type", "string"}, {"enum", std::move(values)}, {"description", description}};
    };
    Json::Object common{
        {"roots", list("Absolute dirs inside the configured roots. Default: all.")},
        {"types", list("File types: asm bat c cmake cpp cs css go h html java js json lua make md msbuild proto ps py "
                       "rust sh sql toml ts txt xml yaml.")},
        {"include", list("File globs (* ?, case-insensitive). Without '/' a glob matches the whole filename, with '/' "
                         "the whole relative path: \"*.cpp\", \"*parser*\", \"src/*\".")},
        {"exclude", list("Globs of files or dirs to skip; a matching dir is not entered: \"third_party\".")},
        {"extensions", list("Extensions to keep: [\"cpp\", \"h\"].")},
        {"path_filter", field("string", "Substring of the relative path.")},
        {"no_ignore", field("boolean", "Include .gitignore/.ignore'd files.")},
        {"hidden", field("boolean", "Include hidden files.")},
        {"max_results", field("integer", "1-10000, default 100.")},
        {"paths", choice(Json::Array{"absolute", "relative"}, "Default relative (to a single root).")},
        {"max_output_bytes", field("integer", "512-1048576, default 65536.")},
        {"timeout_ms", field("integer", "Default 30000 (find_files 300000).")}};

    auto content_props = common;
    content_props.emplace("pattern", field("string", "One pattern."));
    content_props.emplace("patterns", list("Up to 1000 patterns, one pass; json pattern_id is the index."));
    content_props.emplace("max_matches_per_file", field("integer", "Default 20."));
    content_props.emplace("context_bytes", field("integer", "json: context bytes per side, default 80."));
    content_props.emplace("context_before_bytes", field("integer", "json: context bytes before."));
    content_props.emplace("context_after_bytes", field("integer", "json: context bytes after."));

    auto search_props = content_props;
    search_props.emplace("mode", choice(Json::Array{"regex", "literal"},
        "Default regex (PCRE, per line). Backreferences, lookaround or \\b make the whole call slow; use word."));
    search_props.emplace("case_insensitive", field("boolean", "Unicode-aware."));
    search_props.emplace("output", choice(Json::Array{"lines", "files", "files_without_match", "count", "json"},
        "lines (default, path:line:text), files (cheapest), files_without_match, count, json (byte offsets)."));
    search_props.emplace("context_lines", field("integer", "Lines around matches, 0-100."));
    search_props.emplace("before_lines", field("integer", "Lines before matches."));
    search_props.emplace("after_lines", field("integer", "Lines after matches."));
    search_props.emplace("max_line_bytes", field("integer", "Window longer lines; default 400, 0 = whole."));
    search_props.emplace("block", field("boolean", "Show each match inside its whole enclosing function (else class); "
                                                   "lines output. Brace languages and Python."));
    search_props.emplace("max_block_lines", field("integer", "Longer blocks keep line context; default 200."));
    search_props.emplace("invert", field("boolean", "Lines matching no pattern (not json)."));
    search_props.emplace("multiline", field("boolean", "Matches may span lines."));
    search_props.emplace("word", field("boolean", "Whole words; fast, unlike \\b."));
    search_props.emplace("line_numbers", field("boolean", "Default true."));
    search_props.emplace("sniff_all", field("boolean", "Also open binary-extension files."));
    search_props.emplace("index", field("boolean", "Use the trigram index: opens only candidates. Default true when "
                                                   "the server runs --live-index (kept current); otherwise a "
                                                   "snapshot that can miss newer edits."));
    search_props.emplace("max_file_bytes", field("integer", "Skip larger text files; default 64 MiB."));

    auto bytes_props = content_props;
    bytes_props.emplace("mode", choice(Json::Array{"literal", "regex"},
        "literal (default): hex such as \"4d5a\". regex: byte regex such as \"\\\\x4d\\\\x5a\" or plain ASCII."));
    bytes_props.emplace("case_insensitive", field("boolean", "ASCII only."));
    bytes_props.emplace("output", choice(Json::Array{"json", "files", "count"}, "Default json (offsets, hex context)."));
    bytes_props.emplace("line_numbers", field("boolean", "Add lines to json."));

    auto files_props = common;
    files_props.emplace("exact_name", field("string", "Whole filename, case-insensitive."));
    files_props.emplace("substring", field("string", "Text in the name or relative path."));
    files_props.emplace("glob", field("string", "Glob on the name or relative path."));
    files_props.emplace("output", choice(Json::Array{"lines", "json"}, "Default lines."));

    return Json::Array{
        Json::Object{{"name", "search"}, {"description",
            "Search file contents like ripgrep, on the current disk state. Skips ignored, hidden and binary files. "
            "Put related terms in one call's patterns. A final [status ...] line means results are incomplete."},
            {"inputSchema", schema(search_props)}},
        Json::Object{{"name", "search_bytes"}, {"description",
            "Search raw bytes of any file (no decoding or binary skipping) by hex or byte regex; exact offsets."},
            {"inputSchema", schema(bytes_props)}},
        Json::Object{{"name", "find_files"}, {"description",
            "Find files by name or path without opening them. No filter lists all. Use list_dir for folders."},
            {"inputSchema", schema(files_props)}}
    };
}

bool tool_available(const std::string& name, const SearchContext& context) {
    if (name == "search" || name == "search_bytes" || name == "find_files") return true;
    return is_file_tool(name) && !(context.read_only && is_write_tool(name));
}

Json tool_list(const SearchContext& context) {
    Json::Array tools = tool_definitions().array();
    const Json file_tools = file_tool_definitions(context.read_only);  // SAFETY: named; ranging over a temporary's member dangles
    for (const auto& tool : file_tools.array()) tools.push_back(tool);
    return tools;
}
}
