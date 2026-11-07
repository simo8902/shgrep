#include "ignore.hpp"
#include "winfs.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cwctype>
#include <filesystem>
#include <mutex>
#include <span>
#include <spanstream>
#include <utility>

namespace shgrep {
namespace {
std::u32string ignore_characters(std::string_view text) {
    const std::wstring wide = text.empty() ? std::wstring() : native_path(std::string(text)).wstring();
    std::u32string out;
    for (size_t i = 0; i < wide.size(); ++i) {
        uint32_t c = wide[i];
        if (c >= 0xd800 && c <= 0xdbff && i + 1 < wide.size())
            c = 0x10000 + ((c - 0xd800) << 10) + (wide[++i] - 0xdc00);
        out.push_back(static_cast<char32_t>(c));
    }
    return out;
}
// CONTRACT: matching ignores case, as Git does on Windows (core.ignorecase=true) and as NTFS names do.
char32_t lower_case(char32_t c) {
    if (c < 0x80) return c >= U'A' && c <= U'Z' ? c + 32 : c;
    return c <= 0xFFFF ? static_cast<char32_t>(std::towlower(static_cast<wint_t>(c))) : c;
}
char32_t upper_case(char32_t c) {
    if (c < 0x80) return c >= U'a' && c <= U'z' ? c - 32 : c;
    return c <= 0xFFFF ? static_cast<char32_t>(std::towupper(static_cast<wint_t>(c))) : c;
}
bool equal_ignoring_case(std::string_view a, std::string_view b) {
    const auto ascii = [](std::string_view s) {
        return std::all_of(s.begin(), s.end(), [](char c) { return static_cast<unsigned char>(c) < 0x80; });
    };
    if (ascii(a) && ascii(b))
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
                   return lower_case(static_cast<unsigned char>(x)) == lower_case(static_cast<unsigned char>(y));
               });
    std::u32string wide_a, wide_b;
    try { wide_a = ignore_characters(a); wide_b = ignore_characters(b); }
    catch (const std::runtime_error&) { return a == b; }
    return wide_a.size() == wide_b.size() && std::equal(wide_a.begin(), wide_a.end(), wide_b.begin(),
                                                        [](char32_t x, char32_t y) { return lower_case(x) == lower_case(y); });
}
bool ignore_named_class(std::u32string_view name, char32_t c) {
    const bool lower = c >= U'a' && c <= U'z', upper = c >= U'A' && c <= U'Z';
    const bool digit = c >= U'0' && c <= U'9', alpha = lower || upper;
    if (name == U"alnum") return alpha || digit;
    if (name == U"alpha") return alpha;
    if (name == U"blank") return c == U' ' || c == U'\t';
    if (name == U"cntrl") return c < 32 || c == 127;
    if (name == U"digit") return digit;
    if (name == U"graph") return c >= 33 && c <= 126;
    if (name == U"lower") return lower;
    if (name == U"print") return c >= 32 && c <= 126;
    if (name == U"punct") return c >= 33 && c <= 126 && !alpha && !digit;
    if (name == U"space") return c == U' ' || (c >= U'\t' && c <= U'\r');
    if (name == U"upper") return upper;
    if (name == U"xdigit") return digit || (c >= U'a' && c <= U'f') || (c >= U'A' && c <= U'F');
    return false;
}
struct IgnoreToken {
    enum Kind { literal, any, star, double_star, directories, character_class } kind = literal;
    char32_t character = 0;
    bool negated = false;
    std::vector<std::pair<char32_t, char32_t>> ranges;
    std::vector<std::u32string> classes;
    bool accepts(char32_t c) const {
        if (kind == literal) return lower_case(c) == lower_case(character);
        if (c == U'/') return false;
        if (kind == any) return true;
        bool found = false;
        const char32_t lower = lower_case(c), upper = upper_case(c);
        for (const auto& [first, last] : ranges)
            found |= (c >= first && c <= last) || (lower >= first && lower <= last) || (upper >= first && upper <= last);
        for (const auto& name : classes) found |= ignore_named_class(name, c);
        return found != negated;
    }
};
} // namespace
// PERF: parse glob syntax once per rule load; every entry shares these immutable tokens.
struct IgnorePattern {
    std::vector<IgnoreToken> tokens;
    bool valid = true;
};
namespace {
std::shared_ptr<const IgnorePattern> compile_ignore_glob(const std::string& pattern) {
    if (pattern.find_first_of("*?[\\") == std::string::npos) return {};
    auto compiled = std::make_shared<IgnorePattern>();
    std::u32string pat;
    try { pat = ignore_characters(pattern); }
    catch (const std::runtime_error&) { compiled->valid = false; return compiled; }
    auto& tokens = compiled->tokens;
    for (size_t p = 0; p < pat.size();) {
        IgnoreToken token;
        const char32_t c = pat[p++];
        if (c == U'*') {
            token.kind = IgnoreToken::star;
            if (p < pat.size() && pat[p] == U'*') {
                token.kind = IgnoreToken::double_star;
                while (p < pat.size() && pat[p] == U'*') ++p;
                if (p < pat.size() && pat[p] == U'/') { token.kind = IgnoreToken::directories; ++p; }
            }
        } else if (c == U'?') token.kind = IgnoreToken::any;
        else if (c == U'[') {
            const size_t start = p;
            token.kind = IgnoreToken::character_class;
            if (p < pat.size() && (pat[p] == U'!' || pat[p] == U'^')) { token.negated = true; ++p; }
            bool first = true, closed = false;
            while (p < pat.size()) {
                if (pat[p] == U']' && !first) { ++p; closed = true; break; }
                first = false;
                if (pat[p] == U'[' && p + 1 < pat.size() && pat[p + 1] == U':') {
                    const size_t end = pat.find(U":]", p + 2);
                    if (end != std::u32string::npos) {
                        token.classes.push_back(pat.substr(p + 2, end - p - 2));
                        p = end + 2;
                        continue;
                    }
                }
                char32_t first_char = pat[p++];
                if (first_char == U'\\' && p < pat.size()) first_char = pat[p++];
                char32_t last_char = first_char;
                if (p + 1 < pat.size() && pat[p] == U'-' && pat[p + 1] != U']') {
                    ++p;
                    last_char = pat[p++];
                    if (last_char == U'\\' && p < pat.size()) last_char = pat[p++];
                }
                token.ranges.emplace_back(first_char, last_char);
            }
            if (!closed) { p = start; token = IgnoreToken{}; token.character = U'['; }
        } else {
            token.character = c == U'\\' && p < pat.size() ? pat[p++] : c;
        }
        tokens.push_back(std::move(token));
    }
    return compiled;
}
bool ignore_glob(const IgnoreRule& rule, std::string_view value) {
    if (!rule.compiled) return equal_ignoring_case(rule.pattern, value);
    if (!rule.compiled->valid) return false;
    std::u32string text;
    try { text = ignore_characters(value); }
    catch (const std::runtime_error&) { return false; }
    std::vector<uint8_t> prior(text.size() + 1, 0), next(text.size() + 1, 0);
    prior[0] = 1;
    for (const auto& token : rule.compiled->tokens) {
        std::fill(next.begin(), next.end(), uint8_t{0});
        if (token.kind == IgnoreToken::directories) {
            next = prior;
            uint8_t reachable = prior[0];
            for (size_t v = 0; v < text.size(); ++v) {
                reachable = static_cast<uint8_t>(reachable || prior[v + 1]);
                if (text[v] == U'/') next[v + 1] = reachable;
            }
        } else if (token.kind == IgnoreToken::star || token.kind == IgnoreToken::double_star) {
            next[0] = prior[0];
            for (size_t v = 0; v < text.size(); ++v)
                next[v + 1] = static_cast<uint8_t>(prior[v + 1] ||
                    (next[v] && (token.kind == IgnoreToken::double_star || text[v] != U'/')));
        } else {
            for (size_t v = 0; v < text.size(); ++v)
                if (prior[v] && token.accepts(text[v])) next[v + 1] = 1;
        }
        prior.swap(next);
    }
    return prior[text.size()] != 0;
}
}

namespace {
// The contents of an open rule file of at most 1 MiB, without a UTF-8 BOM; false when it is not a readable file.
bool read_rule_file(HANDLE file, std::string& contents) {
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    LARGE_INTEGER size{};
    if (file == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > (1u << 20)) return false;
    contents.clear();
    char block[4096];
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(file, block, sizeof(block), &got, nullptr)) return false;
        if (!got) break;
        if (contents.size() + got > (1u << 20)) return false;
        contents.append(block, got);
    }
    // Windows editors often save a BOM; it is not part of the first rule.
    if (contents.starts_with("\xEF\xBB\xBF")) contents.erase(0, 3);
    return true;
}

// Appends the rules of one gitignore-syntax text whose rules are relative to `base`.
void parse_ignore_text(const std::string& contents, const std::string& base, std::vector<IgnoreRule>& rules) {
    // Borrow the source bytes; each parsed rule owns its pattern before contents can be reused.
    std::ispanstream input{std::span<const char>{contents}};
    std::string line;
    while (std::getline(input, line)) {
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
        // Like Git, a leading slash anchors the rule to this .gitignore's folder: /config.json is not nested/config.json.
        const bool anchored = !line.empty() && line.front() == '/';
        if (anchored) line.erase(0, 1);
        if (line.empty()) continue;
        rule.has_slash = anchored || line.find('/') != std::string::npos;
        rule.pattern = std::move(line);
        rule.compiled = compile_ignore_glob(rule.pattern);
        rules.push_back(std::move(rule));
    }
}

std::wstring environment(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::wstring value(size, L'\0');
    value.resize(GetEnvironmentVariableW(name, value.data(), size));
    return value;
}

bool read_path(const std::wstring& path, std::string& contents) {
    if (path.empty()) return false;
    Handle file(CreateFileW(long_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    return file && read_rule_file(file.h, contents);
}

// Git's core.excludesFile from the user's config, else its default $XDG_CONFIG_HOME/git/ignore
// (%USERPROFILE%\.config\git\ignore).
std::wstring global_excludes_path() {
    const std::wstring home = environment(L"USERPROFILE");
    std::wstring xdg = environment(L"XDG_CONFIG_HOME");
    if (xdg.empty() && !home.empty()) xdg = join_path(home, L".config");
    std::wstring configured;
    // Git reads $XDG_CONFIG_HOME/git/config, then ~/.gitconfig; the last setting wins.
    for (const std::wstring& config : {xdg.empty() ? std::wstring() : join_path(join_path(xdg, L"git"), L"config"),
                                       home.empty() ? std::wstring() : join_path(home, L".gitconfig")}) {
        std::string text;
        if (!read_path(config, text)) continue;
        std::ispanstream input{std::span<const char>{text}};
        std::string line;
        bool core = false;
        while (std::getline(input, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
            const size_t first = line.find_first_not_of(" \t");
            if (first == std::string::npos || line[first] == '#' || line[first] == ';') continue;
            line.erase(0, first);
            if (line.front() == '[') {
                core = equal_ignoring_case(line.substr(0, std::min<size_t>(line.size(), 6)), "[core]");
                continue;
            }
            const size_t equals = line.find('=');
            if (!core || equals == std::string::npos) continue;
            std::string key = line.substr(0, equals), value = line.substr(equals + 1);
            while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
            const size_t start = value.find_first_not_of(" \t");
            value = start == std::string::npos ? std::string() : value.substr(start);
            if (value.size() >= 2 && value.front() == '"' && value.back() == '"') value = value.substr(1, value.size() - 2);
            for (size_t at = value.find("\\\\"); at != std::string::npos; at = value.find("\\\\", at + 1))
                value.erase(at, 1);  // a config string doubles each backslash
            if (!equal_ignoring_case(key, "excludesfile") || value.empty()) continue;
            std::wstring path;
            try { path = native_path(value).wstring(); } catch (const std::exception&) { continue; }
            if ((path.starts_with(L"~/") || path.starts_with(L"~\\")) && !home.empty()) path = join_path(home, path.substr(2));
            std::replace(path.begin(), path.end(), L'/', L'\\');
            configured = path;  // a later setting wins, as in Git
        }
    }
    if (!configured.empty()) return configured;
    return xdg.empty() ? std::wstring() : join_path(join_path(xdg, L"git"), L"ignore");
}

// The global excludes file's rules, read once per process; they apply below every root with the lowest precedence.
const std::vector<IgnoreRule>& global_rules() {
    static const std::vector<IgnoreRule> rules = [] {
        std::vector<IgnoreRule> loaded;
        std::string text;
        if (read_path(global_excludes_path(), text)) parse_ignore_text(text, "", loaded);
        return loaded;
    }();
    return rules;
}

// One rule's verdict on `relative`: matched or not.
bool rule_matches(const IgnoreRule& rule, std::string_view relative, bool directory) {
    if (rule.directory_only && !directory) return false;
    std::string_view scoped = relative;
    if (!rule.base.empty()) {
        if (relative.size() <= rule.base.size() ||
            relative.compare(0, rule.base.size(), rule.base) != 0 ||
            relative[rule.base.size()] != '/') return false;
        scoped = relative.substr(rule.base.size() + 1);
    }
    if (rule.has_slash) return ignore_glob(rule, scoped);
    // CONTRACT: like Git, a pattern without a slash matches the entry's own name only. Ignored parent directories are
    // never entered by the walker, so matching parent components here would wrongly override a later
    // directory-only negation such as "pcre" followed by "!pcre/".
    const size_t slash = scoped.rfind('/');
    return ignore_glob(rule, slash == std::string_view::npos ? scoped : scoped.substr(slash + 1));
}

bool scoped_ignored(const IgnoreScope* scope, std::string_view relative, bool directory, bool ignored) {
    if (!scope) return ignored;
    ignored = scoped_ignored(scope->parent.get(), relative, directory, ignored);
    for (const auto& rule : scope->rules)
        if (rule_matches(rule, relative, directory)) ignored = !rule.negated;
    return ignored;
}
}

void note_rule_file(std::wstring_view name, DWORD attributes, bool& gitignore, bool& dotignore, bool& git_dir) {
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) return;
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (same_name(name, L".git")) git_dir = true;
    } else if (same_name(name, L".gitignore")) gitignore = true;
    // .shignore is shgrep's own ignore file; it rides with .ignore (read after it, so its rules win).
    else if (same_name(name, L".ignore") || same_name(name, L".shignore")) dotignore = true;
}

void read_ignore_rules(const std::wstring& directory, const std::string& base, bool gitignore, bool dotignore,
                       std::vector<IgnoreRule>& rules, HANDLE directory_handle, bool git_exclude) {
    (void)directory;  // Reads are bound to the already verified parent handle.
    std::string contents;
    // A repository's .git/info/exclude comes first, so the folder's own .gitignore overrides it, as in Git.
    if (git_exclude) {
        bool denied = false;
        Handle git(open_relative(directory_handle, L".git", true, denied));
        Handle info(git ? open_relative(git.h, L"info", true, denied) : INVALID_HANDLE_VALUE);
        Handle exclude(info ? open_relative(info.h, L"exclude", false, denied) : INVALID_HANDLE_VALUE);
        if (exclude && read_rule_file(exclude.h, contents)) parse_ignore_text(contents, base, rules);
    }
    // .shignore last: the last matching rule wins, so the user's own list overrides .gitignore and .ignore, including
    // !negations that bring a .gitignore'd folder back.
    for (const wchar_t* filename : {L".gitignore", L".ignore", L".shignore"}) {
        if (!(filename[1] == L'g' ? gitignore : dotignore)) continue;
        bool denied = false;
        Handle file(open_relative(directory_handle, filename, false, denied));
        if (file && read_rule_file(file.h, contents)) parse_ignore_text(contents, base, rules);
    }
}

bool ignored_path(const IgnoreScope* scope, std::string_view relative, bool directory) {
    bool ignored = false;
    for (const auto& rule : global_rules())
        if (rule_matches(rule, relative, directory)) ignored = !rule.negated;
    return scoped_ignored(scope, relative, directory, ignored);
}
}
