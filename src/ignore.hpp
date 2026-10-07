#pragma once
// .gitignore/.ignore parsing and matching shared by the search walker and list_dir.

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace shgrep {
struct IgnoreRule {
    std::string base, pattern;
    bool negated = false, directory_only = false, has_slash = false;
};

// One directory's parsed .gitignore/.ignore rules, chained to the nearest ancestor that had rules.
// PERF: directories without ignore files share their parent's scope instead of allocating one.
struct IgnoreScope {
    std::shared_ptr<const IgnoreScope> parent;
    std::vector<IgnoreRule> rules;
};

// Appends the rules of directory's .gitignore and/or .ignore; base is the directory's path relative to the
// walk root ('/' separators, empty for the root).
void read_ignore_rules(const std::wstring& directory, const std::string& base, bool gitignore, bool dotignore,
                       std::vector<IgnoreRule>& rules);
// CONTRACT: rules apply from the root scope inward and the last matching rule wins, as in Git.
bool ignored_path(const IgnoreScope* scope, std::string_view relative, bool directory);
}
