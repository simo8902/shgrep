#pragma once
// .gitignore/.ignore parsing and matching shared by the search walker and list_dir.

#include <windows.h>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace shgrep {
struct IgnorePattern;
struct IgnoreRule {
    std::string base, pattern;
    std::shared_ptr<const IgnorePattern> compiled;
    bool negated = false, directory_only = false, has_slash = false;
};

// One directory's parsed .gitignore/.ignore rules, chained to the nearest ancestor that had rules.
// PERF: directories without ignore files share their parent's scope instead of allocating one.
struct IgnoreScope {
    std::shared_ptr<const IgnoreScope> parent;
    std::vector<IgnoreRule> rules;
};

// Appends the rules of directory's .git/info/exclude (when git_exclude and it is a repository), then of its
// .gitignore and/or .ignore; base is the directory's path relative to the walk root ('/' separators, empty for the
// root). A UTF-8 BOM is skipped; files over 1 MiB are not read.
void read_ignore_rules(const std::wstring& directory, const std::string& base, bool gitignore, bool dotignore,
                       std::vector<IgnoreRule>& rules, HANDLE directory_handle, bool git_exclude = true);
// Notes a listed entry that holds rules: a .gitignore or .ignore file, or a .git folder (its info/exclude).
void note_rule_file(std::wstring_view name, DWORD attributes, bool& gitignore, bool& dotignore, bool& git_dir);
// CONTRACT: Git's global excludes file (core.excludesFile, default %USERPROFILE%\.config\git\ignore) applies first,
//   then rules from the root scope inward, and the last matching rule wins, as in Git. Matching ignores case, as Git
//   does on Windows.
bool ignored_path(const IgnoreScope* scope, std::string_view relative, bool directory);
}
