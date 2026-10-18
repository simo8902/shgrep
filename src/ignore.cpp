#include "ignore.hpp"
#include "winfs.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
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
        if (kind == literal) return c == character;
        if (c == U'/') return false;
        if (kind == any) return true;
        bool found = false;
        for (const auto& [first, last] : ranges) found |= c >= first && c <= last;
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
    if (!rule.compiled) return rule.pattern == value;
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

void read_ignore_rules(const std::wstring& directory, const std::string& base, bool gitignore, bool dotignore,
                       std::vector<IgnoreRule>& rules) {
    for (const wchar_t* filename : {L".gitignore", L".ignore"}) {
        if (!(filename[1] == L'g' ? gitignore : dotignore)) continue;
        std::filesystem::path rule_path(long_path(join_path(directory, filename)));
        std::error_code ec;
        uintmax_t rule_size = std::filesystem::file_size(rule_path, ec);
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
}

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
        if (rule.has_slash) matched = ignore_glob(rule, scoped);
        else {
            // CONTRACT: like Git, a pattern without a slash matches the entry's own name only. Ignored parent
            // directories are never entered by the walker, so matching parent components here would wrongly
            // override a later directory-only negation such as "pcre" followed by "!pcre/".
            const size_t slash = scoped.rfind('/');
            matched = ignore_glob(rule, slash == std::string_view::npos ? scoped : scoped.substr(slash + 1));
        }
        if (matched) ignored = !rule.negated;
    }
    return ignored;
}
}
