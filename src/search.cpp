#include "search.hpp"

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <hs.h>
#if defined(SHGREP_CHIMERA)
#include <ch.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <exception>
#include <fstream>
#include <functional>
#include <limits>
#include <list>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>
#include <thread>

namespace shgrep {
namespace fs = std::filesystem;
namespace {
using Clock = std::chrono::steady_clock;
struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : h(value) {}
    ~Handle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    explicit operator bool() const { return h != INVALID_HANDLE_VALUE; }
};
std::string utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (!size) throw std::runtime_error("invalid Windows path encoding");
    std::string out(size, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), size, nullptr, nullptr);
    return out;
}
fs::path native_path(const std::string& s) {
    if (s.empty()) throw std::runtime_error("empty path");
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (!size) throw std::runtime_error("invalid UTF-8 path");
    std::wstring out(size, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), size);
    return fs::path(out);
}
std::wstring final_path(HANDLE h) {
    DWORD size = GetFinalPathNameByHandleW(h, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!size || size > 32768) throw std::runtime_error("cannot resolve filesystem path");
    std::wstring out(size, L'\0');
    DWORD written = GetFinalPathNameByHandleW(h, out.data(), size, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!written || written >= size) throw std::runtime_error("cannot resolve filesystem path");
    out.resize(written);
    return out;
}
bool inside(const std::wstring& path, const std::wstring& root) {
    if (path.size() < root.size() || CompareStringOrdinal(path.data(), static_cast<int>(root.size()),
         root.data(), static_cast<int>(root.size()), TRUE) != CSTR_EQUAL) return false;
    return path.size() == root.size() || root.back() == L'\\' || path[root.size()] == L'\\';
}

bool try_utf8(std::wstring_view s, std::string& out) {
    out.clear();
    if (s.empty()) return true;
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (!size) return false;
    out.resize(static_cast<size_t>(size));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), size,
                               nullptr, nullptr) == size;
}
// COMPAT: Win32 paths at MAX_PATH or longer need the \\?\ form unless the process opted into long paths.
// CONTRACT: path is absolute and lexically normal.
std::wstring long_path(const std::wstring& path) {
    if (path.size() < MAX_PATH - 12 || path.starts_with(L"\\\\?\\")) return path;
    if (path.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + path.substr(2);
    return L"\\\\?\\" + path;
}
std::wstring join_path(const std::wstring& directory, std::wstring_view name) {
    std::wstring out;
    out.reserve(directory.size() + 1 + name.size());
    out = directory;
    if (!out.empty() && out.back() != L'\\' && out.back() != L'/') out.push_back(L'\\');
    out.append(name);
    return out;
}
bool same_name(std::wstring_view a, const wchar_t* b) {
    return CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b, -1, TRUE) == CSTR_EQUAL;
}
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
    bool no_ignore = false, hidden = false, word = false, sniff_all = false;
    // output: "lines" (path:line:text), "files" (paths with a match), "count" (path:N), or "json".
    std::string mode = "regex", output = "lines", exact_name, substring, name_glob, path_filter;
    std::vector<std::string> patterns, includes, excludes, extensions, type_globs;
    std::vector<fs::path> roots;
    uint32_t max_results = 100, max_per_file = 20, max_output = 65536, timeout_ms = 30000;
    uint32_t context_before = 80, context_after = 80;
    uint32_t before_lines = 0, after_lines = 0;
    uint64_t max_file_bytes = 67108864;
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
Request parse_request(const std::string& tool, const Json& args, const SearchContext& context) {
    args.object();
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
    } else if (r.output != "lines" && r.output != "files" && r.output != "count" && r.output != "json") {
        throw std::runtime_error("output must be lines, files, count, or json");
    }
    r.word = boolean(args, "word", false);
    r.sniff_all = boolean(args, "sniff_all", false);
    if (r.word && r.binary) throw std::runtime_error("word is supported by search only");
    uint32_t context_lines = bounded(args, "context_lines", 0, 0, 100);
    r.before_lines = bounded(args, "before_lines", context_lines, 0, 100);
    r.after_lines = bounded(args, "after_lines", context_lines, 0, 100);
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

struct IgnoreRule {
    std::string base, pattern;
    bool negated = false, directory_only = false, has_slash = false;
};

bool ignore_glob(const std::string& pattern, std::string_view value) {
    if (pattern.find_first_of("*?") == std::string::npos) return pattern == value;
    std::vector<uint8_t> prior(value.size() + 1, 0), next(value.size() + 1, 0);
    prior[0] = 1;
    for (size_t p = 0; p < pattern.size();) {
        std::fill(next.begin(), next.end(), 0);
        if (pattern[p] == '*') {
            bool double_star = p + 1 < pattern.size() && pattern[p + 1] == '*';
            if (double_star && p + 2 < pattern.size() && pattern[p + 2] == '/') {
                next = prior;
                uint8_t reachable = prior[0];
                for (size_t v = 0; v < value.size(); ++v) {
                    reachable = static_cast<uint8_t>(reachable || prior[v + 1]);
                    if (value[v] == '/') next[v + 1] = reachable;
                }
                p += 3;
            } else {
                next[0] = prior[0];
                for (size_t v = 0; v < value.size(); ++v) {
                    next[v + 1] = static_cast<uint8_t>(prior[v + 1] ||
                        (next[v] && (double_star || value[v] != '/')));
                }
                p += double_star ? 2 : 1;
            }
        } else {
            for (size_t v = 0; v < value.size(); ++v)
                if (prior[v] && (pattern[p] == value[v] ||
                    (pattern[p] == '?' && value[v] != '/'))) next[v + 1] = 1;
            ++p;
        }
        prior.swap(next);
    }
    return prior[value.size()] != 0;
}

void read_ignore_rules(const std::wstring& directory, const std::string& base, bool gitignore, bool dotignore,
                       std::vector<IgnoreRule>& rules) {
    for (const wchar_t* filename : {L".gitignore", L".ignore"}) {
        if (!(filename[1] == L'g' ? gitignore : dotignore)) continue;
        fs::path rule_path(long_path(join_path(directory, filename)));
        std::error_code ec;
        uintmax_t rule_size = fs::file_size(rule_path, ec);
        if (ec || rule_size > (1u << 20)) continue;
        std::ifstream input(rule_path, std::ios::binary);
        if (!input) continue;
        std::string line;
        size_t lines = 0;
        while (lines++ < 4096 && std::getline(input, line)) {
            if (line.size() > 512) continue;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            bool escaped_lead = line.size() > 1 && line[0] == '\\' &&
                                (line[1] == '#' || line[1] == '!');
            if (!escaped_lead && line[0] == '#') continue;
            IgnoreRule rule;
            rule.base = base;
            if (!escaped_lead && line[0] == '!') {
                rule.negated = true;
                line.erase(0, 1);
            } else if (escaped_lead) line.erase(0, 1);
            while (!line.empty() && line.back() == ' ' &&
                   (line.size() < 2 || line[line.size() - 2] != '\\')) line.pop_back();
            if (line.empty()) continue;
            if (line.back() == '/') {
                rule.directory_only = true;
                line.pop_back();
            }
            if (!line.empty() && line.front() == '/') line.erase(0, 1);
            if (line.empty()) continue;
            rule.has_slash = line.find('/') != std::string::npos;
            rule.pattern = std::move(line);
            rules.push_back(std::move(rule));
        }
    }
}

// One directory's parsed .gitignore/.ignore rules, chained to the nearest ancestor that had rules.
// PERF: directories without ignore files share their parent's scope instead of allocating one.
struct IgnoreScope {
    std::shared_ptr<const IgnoreScope> parent;
    std::vector<IgnoreRule> rules;
};

// CONTRACT: rules apply from the root scope inward and the last matching rule wins, as in Git.
bool ignored_path(const IgnoreScope* scope, std::string_view relative, bool directory) {
    if (!scope) return false;
    bool ignored = ignored_path(scope->parent.get(), relative, directory);
    for (const auto& rule : scope->rules) {
        if (rule.directory_only && !directory) continue;
        std::string_view scoped = relative;
        if (!rule.base.empty()) {
            if (relative.size() <= rule.base.size() ||
                relative.compare(0, rule.base.size(), rule.base) != 0 ||
                relative[rule.base.size()] != '/') continue;
            scoped = relative.substr(rule.base.size() + 1);
        }
        bool matched = false;
        if (rule.has_slash) matched = ignore_glob(rule.pattern, scoped);
        else {
            // CONTRACT: like Git, a pattern without a slash matches the entry's own name only. Ignored parent
            // directories are never entered by the walker, so matching parent components here would wrongly
            // override a later directory-only negation such as "pcre" followed by "!pcre/".
            const size_t slash = scoped.rfind('/');
            matched = ignore_glob(rule.pattern, slash == std::string_view::npos ? scoped : scoped.substr(slash + 1));
        }
        if (matched) ignored = !rule.negated;
    }
    return ignored;
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
#if defined(SHGREP_HS_AVX2) || defined(SHGREP_HS_AVX512)
    static const bool supported = [] {
        int info[4];
        __cpuid(info, 0);
        if (info[0] < 7) return false;
        __cpuid(info, 1);
        const bool osxsave = (info[2] & (1 << 27)) != 0, avx = (info[2] & (1 << 28)) != 0;
        const bool popcnt = (info[2] & (1 << 23)) != 0;
        if (!osxsave || !avx || !popcnt) return false;
        const unsigned long long xcr0 = _xgetbv(0);
        if ((xcr0 & 0x6) != 0x6) return false;
        __cpuidex(info, 7, 0);
        bool ok = (info[1] & (1 << 3)) != 0 && (info[1] & (1 << 5)) != 0 && (info[1] & (1 << 8)) != 0; // BMI1 AVX2 BMI2
#if defined(SHGREP_HS_AVX512)
        ok = ok && (info[1] & (1 << 16)) != 0 && (info[1] & (1 << 30)) != 0 && (xcr0 & 0xe6) == 0xe6; // AVX512F BW
#endif
        return ok;
    }();
    if (!supported)
        throw std::runtime_error("this CPU lacks the instruction set this shgrep build requires; "
                                 "rebuild with -DSHGREP_HS_ARCH=SSE");
#endif
}

// Everything that changes a compiled database. It is also the cache key.
struct CompileSpec {
    std::vector<std::string> patterns;
    bool binary = false, regex = false, insensitive = false, literal_api = false, som = false;
    bool operator==(const CompileSpec&) const = default;
};

CompileSpec compile_spec(const Request& r) {
    CompileSpec spec;
    spec.patterns = r.patterns;
    spec.binary = r.binary;
    spec.regex = r.mode == "regex";
    spec.insensitive = r.insensitive;
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
    // whole-word checks need them unless the literal length gives the start.
    spec.som = r.output == "json" || (r.word && !spec.literal_api);
    return spec;
}

bool env_off(const wchar_t* name) {
    wchar_t value[4] = {};
    return GetEnvironmentVariableW(name, value, 4) == 1 && value[0] == L'0';
}

// PERF: compiled Hyperscan databases persist across processes in %LOCALAPPDATA%\shgrep\db-cache, so a CLI
// run does not pay the compile again (about 85 ms for 100 regexes). Owner-approved 2026-10-07.
// CONTRACT: only compiled patterns are stored, never file contents or results, so freshness is unaffected.
// Each file carries its full key (cache format, Hyperscan version, ISA build, every compile input) and is used
// only on an exact key match; hs_deserialize_database also rejects other versions and CPUs. Writes go to a
// temporary file and are renamed into place. SHGREP_DB_CACHE=0 disables the cache.
constexpr size_t db_cache_files = 64;
constexpr auto db_cache_min_compile = std::chrono::milliseconds(5);
constexpr char db_cache_magic[8] = {'S', 'H', 'G', 'D', 'B', '0', '0', '1'};

const std::wstring& db_cache_dir() {
    static const std::wstring dir = [] {
        if (env_off(L"SHGREP_DB_CACHE")) return std::wstring();
        wchar_t base[MAX_PATH] = {};
        const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
        if (length == 0 || length >= MAX_PATH) return std::wstring();
        return std::wstring(base, length) + L"\\shgrep\\db-cache";
    }();
    return dir;
}

std::string db_cache_key(const CompileSpec& spec) {
    if (db_cache_dir().empty()) return {};
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

std::wstring db_cache_path(const std::string& key) {
    uint64_t hash = 1469598103934665603ull; // FNV-1a; the full key inside the file settles collisions
    for (unsigned char c : key) {
        hash ^= c;
        hash *= 1099511628211ull;
    }
    wchar_t name[32] = {};
    swprintf_s(name, L"\\%016llx.hsdb", static_cast<unsigned long long>(hash));
    return db_cache_dir() + name;
}

hs_database_t* load_cached_database(const std::string& key) {
    Handle file(CreateFileW(db_cache_path(key).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
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

void store_cached_database(const std::string& key, const hs_database_t* db) {
    char* serialized = nullptr;
    size_t length = 0;
    if (hs_serialize_database(db, &serialized, &length) != HS_SUCCESS) return;
    const std::unique_ptr<char, decltype(&std::free)> owned(serialized, &std::free);
    const std::wstring& dir = db_cache_dir();
    CreateDirectoryW(dir.substr(0, dir.rfind(L'\\')).c_str(), nullptr);
    CreateDirectoryW(dir.c_str(), nullptr);
    const std::wstring path = db_cache_path(key);
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

struct Database {
    hs_database_t* db = nullptr;
    hs_scratch_t* scratch = nullptr; // prototype for hs_clone_scratch; never scanned with
    bool som = false, stream = false;
    std::vector<uint32_t> lengths;   // literal byte lengths by pattern id; empty for regex databases
#if defined(SHGREP_CHIMERA)
    // Set instead of db when Hyperscan rejected a text regex and Chimera accepted it.
    ch_database_t* chimera = nullptr;
    ch_scratch_t* chimera_scratch = nullptr; // prototype for ch_clone_scratch; never scanned with
#endif
    ~Database() {
        if (scratch) hs_free_scratch(scratch);
        if (db) hs_free_database(db);
#if defined(SHGREP_CHIMERA)
        if (chimera_scratch) ch_free_scratch(chimera_scratch);
        if (chimera) ch_free_database(chimera);
#endif
    }
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    explicit Database(const CompileSpec& spec) : som(spec.som), stream(spec.binary) {
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
        const std::string cache_key = db_cache_key(spec);
        if (!cache_key.empty()) db = load_cached_database(cache_key);
        if (db) {
            if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
                hs_free_database(db);
                db = nullptr;
                throw std::runtime_error("Hyperscan scratch allocation failed");
            }
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
#if defined(SHGREP_CHIMERA)
            // CONTRACT: text regexes that Hyperscan rejects (backreferences, lookaround, \b under UCP, other
            // PCRE-only syntax) fall back to Chimera: Hyperscan prefilter plus PCRE confirmation, block mode only.
            // If PCRE rejects the pattern too, its message is reported.
            if (spec.regex && !spec.binary) {
                compile_chimera(spec);
                return;
            }
#endif
            throw std::runtime_error(message);
        }
        if (error) hs_free_compile_error(error);
        if (!cache_key.empty() && Clock::now() - compile_start >= db_cache_min_compile) store_cached_database(cache_key, db);
        if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
            hs_free_database(db);
            db = nullptr;
            throw std::runtime_error("Hyperscan scratch allocation failed");
        }
    }

#if defined(SHGREP_CHIMERA)
    void compile_chimera(const CompileSpec& spec) {
        const unsigned flags = CH_FLAG_UTF8 | CH_FLAG_UCP | CH_FLAG_MULTILINE | (spec.insensitive ? CH_FLAG_CASELESS : 0);
        const auto count = static_cast<unsigned>(spec.patterns.size());
        std::vector<const char*> ptrs;
        std::vector<unsigned> pattern_flags(count, flags), ids(count);
        for (unsigned i = 0; i < count; ++i) {
            ptrs.push_back(spec.patterns[i].c_str());
            ids[i] = i;
        }
        ch_compile_error_t* error = nullptr;
        if (ch_compile_multi(ptrs.data(), pattern_flags.data(), ids.data(), count, CH_MODE_NOGROUPS, nullptr,
                             &chimera, &error) != CH_SUCCESS) {
            std::string message = error && error->message ? error->message : "Chimera compilation failed";
            if (error && error->expression >= 0) message = "pattern " + std::to_string(error->expression) + ": " + message;
            if (error) ch_free_compile_error(error);
            chimera = nullptr;
            throw std::runtime_error(message);
        }
        if (error) ch_free_compile_error(error);
        if (ch_alloc_scratch(chimera, &chimera_scratch) != CH_SUCCESS) {
            ch_free_database(chimera);
            chimera = nullptr;
            throw std::runtime_error("Chimera scratch allocation failed");
        }
        // Chimera always reports PCRE start and end offsets.
        som = true;
        lengths.clear();
    }
#endif
};

// CONTRACT: caches compiled databases only, never file contents or results (CLAUDE.md "Allowed caching").
// Keyed by the full CompileSpec; least recently used entries are dropped past database_cache_entries.
std::shared_ptr<const Database> compiled_database(const Request& r) {
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
    auto database = std::make_shared<const Database>(spec);
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
    // Set when PCRE (Chimera) hit its match or recursion limit, so the file was not fully searched.
    bool pcre_limit = false;
    std::string_view text;
    uint64_t line_end = 0, lines = 0;
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

#if defined(SHGREP_CHIMERA)
ch_callback_t HS_CDECL chimera_match(unsigned int id, unsigned long long from, unsigned long long to, unsigned int,
                                     unsigned int, const ch_capture_t*, void* context) {
    return Collector::callback(id, from, to, 0, context) ? CH_CALLBACK_TERMINATE : CH_CALLBACK_CONTINUE;
}

// PCRE hit its match or recursion limit: record the file as incompletely searched and skip that pattern.
ch_callback_t HS_CDECL chimera_error(ch_error_event_t, unsigned int, void*, void* context) {
    static_cast<Collector*>(context)->pcre_limit = true;
    return CH_CALLBACK_SKIP_PATTERN;
}
#endif
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
bool valid_utf8(std::string_view s) {
    if (s.empty()) return true;
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0) != 0;
}

struct DecodedText {
    std::string text;
    std::vector<std::pair<uint32_t, uint32_t>> boundaries;
    uint32_t bom = 0;
    bool identity = true;

    uint64_t raw_offset(uint64_t decoded, bool end) const {
        if (identity) return bom + decoded;
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
    std::string source(raw.substr(out.bom));
    if (valid_utf8(source)) {
        out.text = std::move(source);
        return out;
    }
    out.identity = false;
    out.text.reserve(source.size());
    for (size_t i = out.bom; i < raw.size();) {
        const unsigned char lead = byte(i);
        uint32_t cp = 0xfffd;
        size_t width = 1;
        if (lead < 0x80) cp = lead;
        else {
            size_t expected = lead >= 0xc2 && lead <= 0xdf ? 2 :
                              lead >= 0xe0 && lead <= 0xef ? 3 :
                              lead >= 0xf0 && lead <= 0xf4 ? 4 : 0;
            if (expected && i + expected <= raw.size()) {
                bool good = true;
                cp = lead & ((1u << (7 - expected)) - 1);
                for (size_t j = 1; j < expected; ++j) {
                    unsigned char part = byte(i + j);
                    if ((part & 0xc0) != 0x80) { good = false; break; }
                    cp = (cp << 6) | (part & 0x3f);
                }
                if (cp < (expected == 2 ? 0x80u : expected == 3 ? 0x800u : 0x10000u) ||
                    cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) good = false;
                if (good) width = expected;
                else cp = 0xfffd;
            }
        }
        i += width;
        append_codepoint(out, cp, static_cast<uint32_t>(i));
    }
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

// Request-wide results and counters shared by all workers.
struct Outcome {
    std::mutex mutex;
    Json::Array results;            // guarded by mutex
    Json::Array skipped_files;      // guarded by mutex
    std::string state = "complete"; // guarded by mutex
    size_t projected_bytes = 200;   // guarded by mutex
    size_t units = 0;               // guarded by mutex; matches, or files for files/count/find_files output
    std::exception_ptr failure;     // guarded by mutex
    std::atomic<size_t> returned{0};
    std::atomic<uint64_t> files{0}, bytes{0}, found{0}, errors{0}, skipped_size{0}, skipped_binary{0};
    std::atomic<uint64_t> regular_seen{0}, files_filtered{0}, files_ignored{0}, files_hidden{0};
    std::atomic<uint64_t> directories_pruned{0}, reparse_skipped{0};
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

struct Candidate {
    Json item;
    size_t bytes;
    uint32_t units = 1;
};

// Text-output candidate: `text` is one file's rendered block. bytes is its JSON-escaped size, which is what it
// costs inside the MCP response.
void add_text_candidate(std::vector<Candidate>& items, const std::string& display, std::string text, uint32_t units) {
    size_t bytes = Json(text).dump().size();
    items.push_back({Json(Json::Object{{"path", display}, {"text", std::move(text)}, {"units", static_cast<int64_t>(units)}}),
                     bytes, units});
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
        out.results.push_back(std::move(candidate.item));
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
    std::vector<char> buffer;
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
    void trim_raw() {
        if (raw_capacity > retained_text_capacity) {
            raw.reset();
            raw_capacity = 0;
        }
    }
    hs_scratch_t* scratch = nullptr;
#if defined(SHGREP_CHIMERA)
    ch_scratch_t* chimera_scratch = nullptr;
#endif
    Worker() = default;
    Worker(const Worker&) = delete;
    Worker& operator=(const Worker&) = delete;
    ~Worker() {
        if (scratch) hs_free_scratch(scratch);
#if defined(SHGREP_CHIMERA)
        if (chimera_scratch) ch_free_scratch(chimera_scratch);
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
};

// Appends text[start, end) for display: control bytes are escaped, and lines over max_line_bytes are cut to a
// window starting a little before `focus` (the first match on a matched line).
void append_display_line(std::string& out, std::string_view text, size_t start, size_t end, size_t focus) {
    constexpr size_t max_line_bytes = 400, lead_in = 100;
    constexpr char digits[] = "0123456789abcdef";
    size_t from = start, to = end;
    if (end - start > max_line_bytes) {
        from = focus > start + lead_in ? focus - lead_in : start;
        while (from > start && (static_cast<unsigned char>(text[from]) & 0xc0) == 0x80) --from;
        to = std::min(end, from + max_line_bytes);
        while (to > from && to < end && (static_cast<unsigned char>(text[to]) & 0xc0) == 0x80) --to;
    }
    if (from > start) out += "...";
    for (size_t i = from; i < to; ++i) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        if ((c < 0x20 && c != '\t') || c == 0x7f) {
            out += "\\x";
            out.push_back(digits[c >> 4]);
            out.push_back(digits[c & 15]);
        } else out.push_back(static_cast<char>(c));
    }
    if (to < end) out += "...";
}

// Renders one file as grep/rg/tgrep lines: "path:N:text" for matched lines, "path-N-text" for context lines,
// and "--" between non-adjacent groups.
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
    }
    struct Range { uint64_t first, last; };
    std::vector<Range> ranges;
    for (const auto& hit : hits) {
        uint64_t first = hit.line > r.before_lines ? hit.line - r.before_lines : 1;
        uint64_t last = hit.line + r.after_lines;
        if (!ranges.empty() && first <= ranges.back().last + 1) ranges.back().last = std::max(ranges.back().last, last);
        else ranges.push_back({first, last});
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
        if (group && (r.before_lines || r.after_lines)) out += "--\n";
        while (!exhausted && pos < text.size() && number <= ranges[group].last) {
            size_t newline = text.find('\n', pos);
            size_t end = newline == std::string_view::npos ? text.size() : newline;
            size_t shown_end = end;
            while (shown_end > pos && text[shown_end - 1] == '\r') --shown_end;
            while (hit_index < hits.size() && hits[hit_index].line < number) ++hit_index;
            const bool matched = hit_index < hits.size() && hits[hit_index].line == number;
            const char separator = matched ? ':' : '-';
            out += display;
            out.push_back(separator);
            if (r.line) {
                out += std::to_string(number);
                out.push_back(separator);
            }
            append_display_line(out, text, pos, shown_end, matched ? hits[hit_index].focus : pos);
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

void scan_text(const ScanShared& s, Worker& w, HANDLE h, uint64_t file_size, const std::string& display,
               uint32_t remaining, std::string& file_state, std::vector<Candidate>& items) {
    const Request& r = s.r;
    Outcome& out = s.out;
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
        return;
    }
    // PERF: like rg/tgrep, a NUL in the first block marks the file binary before the rest is read.
    // UTF-16 text starts with a BOM and legitimately contains NUL bytes.
    const DWORD head_want = static_cast<DWORD>(std::min<uint64_t>(file_size, binary_probe_bytes));
    DWORD head = 0;
    if (head_want && (!ReadFile(h, w.buffer.data(), head_want, &head, nullptr) || head == 0)) {
        ++out.errors;
        return;
    }
    const bool utf16 = head >= 2 &&
        ((static_cast<unsigned char>(w.buffer[0]) == 0xff && static_cast<unsigned char>(w.buffer[1]) == 0xfe) ||
         (static_cast<unsigned char>(w.buffer[0]) == 0xfe && static_cast<unsigned char>(w.buffer[1]) == 0xff));
    if (!utf16 && std::find(w.buffer.begin(), w.buffer.begin() + head, '\0') != w.buffer.begin() + head) {
        ++out.skipped_binary;
        return;
    }
    const uint64_t charge = file_size >= small_text_bytes ? file_size * 3 : 0;
    if (charge && !s.memory.acquire(charge, s.control)) {
        if (const char* why = s.control.interrupted()) file_state = why;
        return;
    }
    struct Reservation {
        MemoryBudget& memory;
        Worker& worker;
        uint64_t bytes;
        ~Reservation() {
            worker.trim_raw();
            if (bytes) memory.release(bytes);
        }
    } reservation{s.memory, w, charge};

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
    if (read_failed) { ++out.errors; return; }
    if (file_state != "complete") return;

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

    const bool files_only = r.output == "files", count_only = r.output == "count";
    // PERF: files output stops each file at its first match.
    Collector collect{{}, 0, files_only ? 1u : r.max_per_file, remaining};
    collect.count_only = count_only;
    collect.word = r.word;
    collect.text = view.text;
    collect.som = s.database->som;
    collect.lengths = s.database->lengths.empty() ? nullptr : &s.database->lengths;
    if (!count_only) collect.events.reserve(std::min(collect.max_per_file, collect.remaining));
    // PERF: the decoded file is one contiguous buffer, so block mode applies: no stream state, and end-anchored
    // patterns are resolved in the same call.
    collect.per_line = r.output == "lines";
#if defined(SHGREP_CHIMERA)
    if (s.database->chimera) {
        ch_error_t rc = ch_scan(s.database->chimera, view.text.data(), static_cast<unsigned>(view.text.size()), 0,
                                w.chimera_scratch, chimera_match, chimera_error, &collect);
        if (rc != CH_SUCCESS && rc != CH_SCAN_TERMINATED) throw std::runtime_error("Chimera text scan failed");
        if (collect.pcre_limit) ++out.errors;
    } else
#endif
    {
        hs_error_t rc = hs_scan(s.database->db, view.text.data(), static_cast<unsigned>(view.text.size()), 0,
                                w.scratch, Collector::callback, &collect);
        if (rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED) throw std::runtime_error("Hyperscan text scan failed");
    }
    if (collect.full && !files_only) out.per_file_limited.store(true);
    out.found += collect.found;

    if (files_only) {
        if (collect.found) add_text_candidate(items, display, display + "\n", 1);
        return;
    }
    if (count_only) {
        if (collect.lines) add_text_candidate(items, display, display + ":" + std::to_string(collect.lines) + "\n", 1);
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
    const bool files_only = r.output == "files", count_only = r.output == "count";
    Collector collect{{}, 0, files_only ? 1u : r.max_per_file, remaining};
    collect.count_only = count_only;
    collect.som = s.database->som;
    collect.lengths = s.database->lengths.empty() ? nullptr : &s.database->lengths;
    if (!count_only) collect.events.reserve(std::min(collect.max_per_file, collect.remaining));
    hs_stream_t* stream = nullptr;
    if (hs_open_stream(s.database->db, 0, &stream) != HS_SUCCESS) throw std::runtime_error("Hyperscan stream allocation failed");
    uint64_t consumed = 0;
    bool read_failed = false;
    while (consumed < file_size) {
        if (const char* why = s.control.interrupted()) { file_state = why; break; }
        DWORD want = static_cast<DWORD>(std::min<uint64_t>(w.buffer.size(), file_size - consumed));
        DWORD got = 0;
        if (!ReadFile(h, w.buffer.data(), want, &got, nullptr) || !got) { read_failed = true; break; }
        hs_error_t rc = hs_scan_stream(stream, w.buffer.data(), got, 0, w.scratch, Collector::callback, &collect);
        if (rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED) {
            hs_close_stream(stream, w.scratch, nullptr, nullptr);
            throw std::runtime_error("Hyperscan scan failed");
        }
        consumed += got;
        if (collect.full || rc == HS_SCAN_TERMINATED) {
            if (!files_only) out.per_file_limited.store(true);
            break;
        }
    }
    // EOD callbacks are needed for anchored expressions on a complete scan.
    if (file_state == "complete" && !read_failed && !collect.full) {
        hs_error_t rc = hs_close_stream(stream, w.scratch, Collector::callback, &collect);
        if (rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED) throw std::runtime_error("Hyperscan stream close failed");
        if (collect.full && !files_only) out.per_file_limited.store(true);
    } else hs_close_stream(stream, w.scratch, nullptr, nullptr);
    ++out.files;
    out.bytes += consumed;
    out.found += collect.found;
    if (read_failed) ++out.errors;
    if (file_state != "complete") return;
    if (files_only) {
        if (collect.found) add_text_candidate(items, display, display + "\n", 1);
        return;
    }
    if (count_only) {
        if (collect.lines) add_text_candidate(items, display, display + ":" + std::to_string(collect.lines) + "\n", 1);
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
        if (r.line) item.emplace("line", line_numbers[index]);
        Json candidate(std::move(item));
        const size_t bytes = candidate.dump().size() + 1;
        items.push_back({std::move(candidate), bytes});
    }
}

HANDLE open_relative(HANDLE parent, std::wstring_view name, bool directory, bool& denied);

void scan_file(const ScanShared& s, Worker& w, HANDLE directory, std::wstring_view name, const std::wstring& full_path) {
    const Request& r = s.r;
    Outcome& out = s.out;
    std::string display;
    if (!try_utf8(full_path, display)) { ++out.errors; return; }
    std::vector<Candidate> items;
    if (r.file_only) {
        // CONTRACT: find_files reads no file content; the directory-level root check bounds every name.
        ++out.files;
        ++out.found;
        if (r.output == "json") items.push_back({Json(Json::Object{{"path", std::move(display)}}), 0});
        else add_text_candidate(items, display, display + "\n", 1);
        publish(r, out, s.control, items, s.content_budget);
        return;
    }
    const size_t returned = std::min<size_t>(out.returned.load(), r.max_results);
    const uint32_t remaining = r.max_results - static_cast<uint32_t>(returned);
    if (remaining == 0) return;
    bool denied = false;
    Handle h(open_relative(directory, name, false, denied));
    if (!h) { ++out.errors; return; }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h.h, &size) || size.QuadPart < 0) { ++out.errors; return; }
    std::string file_state = "complete";
    if (!r.binary) scan_text(s, w, h.h, static_cast<uint64_t>(size.QuadPart), display, remaining, file_state, items);
    else scan_binary(s, w, h.h, static_cast<uint64_t>(size.QuadPart), display, remaining, file_state, items);
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
    const bool per_file_units = r.file_only || r.output == "files" || r.output == "count";
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

struct DirEntry {
    std::wstring name;
    DWORD attributes = 0;
    uint64_t size = 0;
};

// PERF: one handle per directory and 64 KiB batches of FILE_FULL_DIR_INFO supply names and attributes
// without a metadata call per entry.
bool list_directory(HANDLE directory, std::vector<uint64_t>& buffer, std::vector<DirEntry>& entries) {
    entries.clear();
    FILE_INFO_BY_HANDLE_CLASS request = FileFullDirectoryRestartInfo;
    for (;;) {
        if (!GetFileInformationByHandleEx(directory, request, buffer.data(),
                                          static_cast<DWORD>(buffer.size() * sizeof(uint64_t)))) {
            DWORD code = GetLastError();
            // An empty directory without "." entries (a FAT root) reports ERROR_FILE_NOT_FOUND.
            return code == ERROR_NO_MORE_FILES || code == ERROR_FILE_NOT_FOUND;
        }
        request = FileFullDirectoryInfo;
        const auto* cursor = reinterpret_cast<const unsigned char*>(buffer.data());
        for (;;) {
            const auto* info = reinterpret_cast<const FILE_FULL_DIR_INFO*>(cursor);
            std::wstring_view name(info->FileName, info->FileNameLength / sizeof(wchar_t));
            if (name != L"." && name != L"..")
                entries.push_back({std::wstring(name), info->FileAttributes, static_cast<uint64_t>(info->EndOfFile.QuadPart)});
            if (info->NextEntryOffset == 0) break;
            cursor += info->NextEntryOffset;
        }
    }
}

HANDLE open_root_directory(const std::wstring& path) {
    return CreateFileW(long_path(path).c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS, nullptr);
}

// SAFETY: below a root, every file and directory is opened by its single listed name relative to the parent's
// open handle, with FILE_OPEN_REPARSE_POINT. Each handle is therefore reached from the root handle one
// non-reparse component at a time, so a junction or symlink swapped in after listing is opened as itself
// rather than followed, and no path string is resolved again.
// PERF: this replaces a GetFinalPathNameByHandleW check per file and directory, which measured ~30 us per call
// and did not scale across threads (+90 ms per 6,000 files on 12 threads).
HANDLE open_relative(HANDLE parent, std::wstring_view name, bool directory, bool& denied) {
    constexpr ULONG file_open = 0x00000001;              // FILE_OPEN
    constexpr ULONG directory_file = 0x00000001;         // FILE_DIRECTORY_FILE
    constexpr ULONG sequential_only = 0x00000004;        // FILE_SEQUENTIAL_ONLY
    constexpr ULONG synchronous_io = 0x00000020;         // FILE_SYNCHRONOUS_IO_NONALERT
    constexpr ULONG non_directory_file = 0x00000040;     // FILE_NON_DIRECTORY_FILE
    constexpr ULONG open_reparse_point = 0x00200000;     // FILE_OPEN_REPARSE_POINT
    constexpr NTSTATUS access_denied = static_cast<NTSTATUS>(0xC0000022L);
    UNICODE_STRING object_name;
    object_name.Buffer = const_cast<PWSTR>(name.data());
    object_name.Length = object_name.MaximumLength = static_cast<USHORT>(name.size() * sizeof(wchar_t));
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = parent;
    attributes.ObjectName = &object_name;
    IO_STATUS_BLOCK io{};
    HANDLE handle = nullptr;
    const ACCESS_MASK access = directory ? (FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE) : FILE_GENERIC_READ;
    const ULONG options = synchronous_io | open_reparse_point |
                          (directory ? directory_file : (non_directory_file | sequential_only));
    const NTSTATUS status = NtCreateFile(&handle, access, &attributes, &io, nullptr, 0,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, file_open,
                                         options, nullptr, 0);
    denied = status == access_denied;
    return status >= 0 ? handle : INVALID_HANDLE_VALUE;
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

// CONTRACT: `directory` is the open parent handle and `name` the listed name; open the file with open_relative.
using FileVisitor = std::function<void(unsigned worker, HANDLE directory, std::wstring_view name, const std::wstring& path)>;

void visit_directory(const Request& r, const DirectoryTask& task, unsigned worker, WalkBuffers& b,
                     std::vector<DirectoryTask>& children, Control& control, Outcome& out, const FileVisitor& on_file) {
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

    for (const auto& entry : b.entries) {
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
            HANDLE child = open_relative(task.handle->h, entry.name, true, denied);
            if (child == INVALID_HANDLE_VALUE) {
                // CONTRACT: access-denied subdirectories are skipped without an error, matching skip_permission_denied.
                if (!denied) ++out.errors;
                continue;
            }
            children.push_back({join_path(task.path, entry.name), b.relative, scope, std::make_shared<Handle>(child)});
            continue;
        }
        if (!r.file_only && !r.binary) {
            // PERF: skip text-search files that cannot match without paying for the open. Empty files are
            // known from the listing; binary extensions are listed in binary_extension.
            if (entry.size == 0) { ++out.files; continue; }
            if (!r.sniff_all && binary_extension(b.name)) { ++out.skipped_binary; continue; }
        }
        on_file(worker, task.handle->h, entry.name, join_path(task.path, entry.name));
    }
}

// PERF: a bounded pool lists directories in parallel and scans files on the worker that found them.
// CONTRACT: pending is LIFO, so the frontier (each entry holding one open directory handle) stays near
// depth-first size rather than the tree's full width.
void walk(const Request& r, const std::vector<WalkRoot>& roots, unsigned worker_count, Control& control,
          Outcome& out, const FileVisitor& on_file) {
    std::mutex mutex;
    std::condition_variable ready;
    std::vector<DirectoryTask> pending;
    size_t active = 0;
    for (const auto& root : roots) {
        auto handle = std::make_shared<Handle>(open_root_directory(root.path));
        if (!*handle) { ++out.errors; continue; }
        pending.push_back({root.path, {}, nullptr, std::move(handle)});
    }
    auto run = [&](unsigned index) {
        WalkBuffers buffers;
        std::vector<DirectoryTask> children;
        for (;;) {
            DirectoryTask task;
            {
                std::unique_lock lock(mutex);
                while (pending.empty() && active != 0 && !control.stop.load())
                    ready.wait_for(lock, std::chrono::milliseconds(20));
                if (pending.empty() || control.stop.load()) {
                    ready.notify_all();
                    return;
                }
                task = std::move(pending.back());
                pending.pop_back();
                ++active;
            }
            children.clear();
            try {
                visit_directory(r, task, index, buffers, children, control, out, on_file);
            } catch (...) {
                fail(out, control, std::current_exception());
            }
            {
                std::lock_guard lock(mutex);
                for (auto& child : children) pending.push_back(std::move(child));
                --active;
            }
            ready.notify_all();
        }
    };
    std::vector<std::thread> threads;
    threads.reserve(worker_count);
    try {
        for (unsigned i = 1; i < worker_count; ++i) threads.emplace_back(run, i);
    } catch (...) {
        control.stop.store(true);
        for (auto& thread : threads) thread.join();
        throw;
    }
    run(0);
    for (auto& thread : threads) thread.join();
}
}

Json run_tool(const std::string& name, const Json& arguments,
              const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (name != "search" && name != "search_bytes" && name != "find_files") throw std::runtime_error("unknown tool");
    Request r = parse_request(name, arguments, context);
    const auto started = Clock::now();
    Control control{cancelled, started + std::chrono::milliseconds(r.timeout_ms)};
    std::shared_ptr<const Database> database;
    if (!r.file_only) database = compiled_database(r);
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

    Outcome out;
    // JSON output is escaped twice (result object, then MCP text), so it gets half the budget; text output is
    // escaped once and keeps room for the footer.
    const bool text_output = r.output != "json";
    const size_t content_budget = text_output ? (r.max_output > 1024 ? r.max_output - 768 : r.max_output / 2)
                                              : (r.max_output >= 1024 ? (r.max_output - 512) / 2 : r.max_output / 2);
    // PERF: one worker per logical processor across all processor groups, by the owner's decision.
    // Concurrent MCP requests each get their own full pool.
    const DWORD processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    // PERF: measured 12/18/24 workers on a 12-thread CPU with a warm cache: more workers than logical
    // processors did not hide open latency and was up to 6 ms slower.
    const unsigned worker_count = processors == 0 ? 1u : static_cast<unsigned>(processors);
    std::vector<std::unique_ptr<Worker>> workers;
    for (unsigned i = 0; i < worker_count; ++i) {
        auto worker = std::make_unique<Worker>();
        if (database) {
            worker->buffer.resize(1 << 20);
            bool cloned = false;
#if defined(SHGREP_CHIMERA)
            if (database->chimera) cloned = ch_clone_scratch(database->chimera_scratch, &worker->chimera_scratch) == CH_SUCCESS;
            else
#endif
            cloned = hs_clone_scratch(database->scratch, &worker->scratch) == HS_SUCCESS;
            if (!cloned) throw std::runtime_error("scratch allocation failed");
        }
        workers.push_back(std::move(worker));
    }
    MemoryBudget memory(text_memory_budget);
    const ScanShared shared{r, database.get(), control, out, memory, content_budget};
    walk(r, walk_roots, worker_count, control, out,
         [&](unsigned index, HANDLE directory, std::wstring_view name, const std::wstring& path) {
             try { scan_file(shared, *workers[index], directory, name, path); }
             catch (const fs::filesystem_error&) { ++out.errors; }
         });
    if (out.failure) std::rethrow_exception(out.failure);

    const uint64_t files = out.files.load(), errors = out.errors.load(), skipped_size = out.skipped_size.load();
    std::string state = out.state;
    if (state == "complete" && out.per_file_limited.load()) state = "per_file_limit";
    if (state == "complete" && (errors || skipped_size)) state = "partial_files";
    Json::Array results = std::move(out.results);
    Json::Array skipped_files = std::move(out.skipped_files);
    // CONTRACT: workers finish files in nondeterministic order; sorting keeps output stable for a result set.
    std::stable_sort(results.begin(), results.end(), [](const Json& a, const Json& b) {
        const std::string& left = a.object().at("path").string();
        const std::string& right = b.object().at("path").string();
        if (left != right) return left < right;
        const Json* x = a.get("byte_start");
        const Json* y = b.get("byte_start");
        return x && y && x->integer() < y->integer();
    });
    auto elapsed = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count());
    bool show_selection = files == 0;
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
            for (size_t i = 0; i < results.size(); ++i) {
                const auto& item = results[i].object();
                if (separate_files && i) text += "--\n";
                text += item.at("text").string();
                units += static_cast<uint64_t>(item.at("units").integer());
            }
            footer.state = state;
            footer.returned = units;
            text += render_footer(r, footer, skipped_files);
            // PERF: blocks were budgeted while publishing, so this loop rarely drops anything.
            if (results.empty() || Json(text).dump().size() + 256 <= r.max_output) {
                return Json::Object{{"text", std::move(text)},
                    {"summary", summary(files, out.bytes.load(), out.found.load(), units, errors, skipped_size,
                                        out.skipped_binary.load(), elapsed, state)}};
            }
            results.pop_back();
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
        output = std::move(payload);
        if (output.dump().size() <= content_budget) break;
        if (show_selection) { show_selection = false; continue; }
        if (!skipped_files.empty()) { skipped_files.pop_back(); continue; }
        if (results.empty()) throw std::runtime_error("max_output_bytes cannot hold summary");
        results.pop_back(); state = "output_limit";
    } while (true);
    return output;
}

Json tool_definitions() {
    auto schema = [](Json::Object properties) -> Json {
        return Json::Object{{"type", "object"}, {"properties", std::move(properties)}};
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
        {"roots", list("Directories to search, each inside the server's configured roots. Default: all configured roots. "
                       "Narrow this first on large workspaces.")},
        {"types", list("File types, like rg/tgrep -t: cpp, c, h, cs, py, rust, go, java, js, ts, json, yaml, toml, md, "
                       "cmake, msbuild, ps, sh, sql, xml, html, css, txt, asm, bat, proto, lua, make. Example: [\"cpp\", \"cmake\"].")},
        {"include", list("Keep only files matching any of these case-insensitive globs, like rg -g (* and ? only; * also "
                         "crosses '/'). A glob must match the WHOLE relative path ('/' separators) or, if it has no '/', the "
                         "whole filename: use \"*.cpp\", \"*parser*\", \"src/*\"; \"parser.cpp\" matches only that exact name.")},
        {"exclude", list("Skip files and directories matching any of these globs (same rules as include). "
                         "Excluded directories are not entered. Example: \"third_party/*\", \"*.min.js\".")},
        {"extensions", list("Keep only these file extensions, case-insensitive, with or without the dot: [\"cpp\", \"h\"].")},
        {"path_filter", field("string", "Keep only files whose relative path contains this case-insensitive substring, "
                                        "e.g. \"src/net/\".")},
        {"no_ignore", field("boolean", "Default false: .gitignore and .ignore rules are honored. "
                                       "Set true to also search ignored files such as build output.")},
        {"hidden", field("boolean", "Default false: names starting with '.' and Windows hidden files are skipped. "
                                    "Set true to include them.")},
        {"max_results", field("integer", "1-10000, default 100. Counts matching lines for lines output, matches for "
                                         "json, files for files/count output and find_files. Reaching it ends with "
                                         "status \"limit\".")},
        {"max_output_bytes", field("integer", "Hard cap on response size, 512-1048576, default 65536. "
                                              "Reaching it ends with status \"output_limit\".")},
        {"timeout_ms", field("integer", "Time limit, 1-300000 ms; default 30000, find_files 300000. "
                                        "On expiry the partial result has status \"timeout\".")}};

    auto content_props = common;
    content_props.emplace("pattern", field("string", "One pattern."));
    content_props.emplace("patterns", list("Several patterns searched in ONE pass over each file, like rg -e ... -e "
                                           "(up to 1000, 4096 bytes each). Cheaper than separate calls for related terms."));
    content_props.emplace("case_insensitive", field("boolean", "Like rg -i. Default false."));
    content_props.emplace("max_matches_per_file", field("integer", "Like rg -m: matching lines kept per file (matches for "
                                                                   "json), 1-10000, default 20. Hitting it gives status "
                                                                   "\"per_file_limit\"."));
    content_props.emplace("context_bytes", field("integer", "json output only: bytes of context on each side, 0-1024, default 80."));
    content_props.emplace("context_before_bytes", field("integer", "json output only: overrides context_bytes before the match."));
    content_props.emplace("context_after_bytes", field("integer", "json output only: overrides context_bytes after the match."));

    auto search_props = content_props;
    search_props.emplace("mode", choice(Json::Array{"regex", "literal"},
        "Default \"regex\": PCRE syntax, Unicode classes work, ^ and $ match at every line and '.' never crosses a "
        "newline, as in rg. Patterns run on Hyperscan; backreferences, lookaround and \\b automatically use the "
        "Hyperscan+PCRE hybrid (Chimera), which is slower. "
        "\"literal\" is rg -F: exact text, no escaping needed."));
    search_props.emplace("output", choice(Json::Array{"lines", "files", "count", "json"},
        "Default \"lines\": rg/tgrep style \"path:line:text\", context lines as \"path-line-text\", \"--\" between "
        "groups. \"files\": rg -l, one path per matching file. \"count\": rg -c, \"path:N\" matching lines. "
        "\"json\": objects with byte offsets, pattern_id, and byte context."));
    search_props.emplace("context_lines", field("integer", "Like rg -C: lines before and after each match, 0-100. Default 0."));
    search_props.emplace("before_lines", field("integer", "Like rg -B: lines before each match, 0-100; overrides context_lines."));
    search_props.emplace("after_lines", field("integer", "Like rg -A: lines after each match, 0-100; overrides context_lines."));
    search_props.emplace("word", field("boolean", "Like rg -w: the match must not touch a letter, digit, or '_' on "
                                                  "either side. Default false."));
    search_props.emplace("line_numbers", field("boolean", "Default true. false is rg -N."));
    search_props.emplace("sniff_all", field("boolean", "Default false: files with binary extensions (.exe, .dll, "
                                                       ".png, .zip, .pdf, ...) are skipped without being opened. "
                                                       "true opens and NUL-checks every file."));
    search_props.emplace("max_file_bytes", field("integer", "Text files larger than this are not searched and are "
                                                            "reported as skipped. 1-268435456, default 67108864."));

    auto bytes_props = content_props;
    bytes_props.emplace("mode", choice(Json::Array{"literal", "regex"},
        "Default \"literal\": each pattern is an even-length hex string, e.g. \"4d5a\" for bytes 4D 5A. "
        "\"regex\": Hyperscan byte regex, e.g. \"\\\\x4d\\\\x5a.{2}\"."));
    bytes_props.emplace("output", choice(Json::Array{"json", "files", "count"},
        "Default \"json\": exact byte offsets with hex context. \"files\": paths with a match. \"count\": \"path:N\" matches."));
    bytes_props.emplace("line_numbers", field("boolean", "Default false: count newlines before each match."));

    auto files_props = common;
    files_props.emplace("exact_name", field("string", "Whole filename, case-insensitive, e.g. \"CMakeLists.txt\". Fastest query."));
    files_props.emplace("substring", field("string", "Case-insensitive text found in the filename or relative path, e.g. \"config\"."));
    files_props.emplace("glob", field("string", "Case-insensitive * and ? glob matched against the filename or the whole "
                                                "relative path, e.g. \"*.sln\"."));
    files_props.emplace("output", choice(Json::Array{"lines", "json"}, "Default \"lines\": one path per line. \"json\": objects."));

    return Json::Array{
        Json::Object{{"name", "search"}, {"description",
            "grep/rg/tgrep for file CONTENTS: regex or literal search across directory trees, reading current bytes "
            "from disk (no index, so edits are visible immediately). Use it to find where an identifier, string, error "
            "message, or config key appears in source code. Output defaults to rg-style \"path:line:text\" lines; "
            "output \"files\" or \"count\" for rg -l / -c. Filter with types (-t), include (-g), path_filter, roots. "
            "Several patterns in 'patterns' cost one pass. Handles UTF-8 and UTF-16; skips binary files. A trailing "
            "\"[status ...]\" line means the list may be incomplete: narrow the search instead of trusting it. "
            "To find files by NAME use find_files."},
            {"inputSchema", schema(search_props)}},
        Json::Object{{"name", "search_bytes"}, {"description",
            "Search raw BYTES of any file, including executables, object files, databases, and dumps. Patterns are hex "
            "literals or Hyperscan byte regexes. JSON results give exact byte offsets and hex context. Use for binary "
            "signatures, magic numbers, or byte sequences; use search for normal text."},
            {"inputSchema", schema(bytes_props)}},
        Json::Object{{"name", "find_files"}, {"description",
            "Find files by NAME or PATH without reading contents, like rg --files with a filter. Much cheaper than "
            "search. Give exact_name, substring, or glob, optionally with types; if several are given all must match, "
            "and with none every selected file is listed. Returns one path per line. Use to locate a file before "
            "reading it, or to list files of a type."},
            {"inputSchema", schema(files_props)}}
    };
}
}
