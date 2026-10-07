#include "ignore.hpp"
#include "winfs.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>

namespace shgrep {
namespace {
bool ignore_glob(const std::string& pattern, std::string_view value) {
    if (pattern.find_first_of("*?") == std::string::npos) return pattern == value;
    std::vector<uint8_t> prior(value.size() + 1, 0), next(value.size() + 1, 0);
    prior[0] = 1;
    for (size_t p = 0; p < pattern.size();) {
        std::fill(next.begin(), next.end(), uint8_t{0});
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
            if (!line.empty() && line.front() == '/') line.erase(0, 1);
            if (line.empty()) continue;
            rule.has_slash = line.find('/') != std::string::npos;
            rule.pattern = std::move(line);
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
}
