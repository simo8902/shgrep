#pragma once
#include "winfs.hpp"
#include <algorithm>

namespace shgrep {
inline bool path_has_unicode(std::string_view text) {
    return std::any_of(text.begin(), text.end(), [](unsigned char c) { return c >= 0x80; });
}
inline std::wstring path_wide(std::string_view text) {
    return text.empty() ? std::wstring() : native_path(std::string(text)).wstring();
}
inline size_t path_character_end(std::wstring_view text, size_t pos) {
    const wchar_t c = text[pos++];
    if (c >= 0xd800 && c <= 0xdbff && pos < text.size() && text[pos] >= 0xdc00 && text[pos] <= 0xdfff) ++pos;
    return pos;
}
inline bool path_equal_unicode(std::string_view a, std::string_view b) {
    const auto x = path_wide(a), y = path_wide(b);
    if (x.empty() || y.empty()) return x.empty() && y.empty();
    return CompareStringOrdinal(x.data(), static_cast<int>(x.size()), y.data(), static_cast<int>(y.size()), TRUE) == CSTR_EQUAL;
}
inline bool path_contains_unicode(std::string_view text, std::string_view part) {
    const auto x = path_wide(text), y = path_wide(part);
    if (y.empty()) return true;
    if (x.empty()) return false;
    return FindStringOrdinal(FIND_FROMSTART, x.data(), static_cast<int>(x.size()), y.data(), static_cast<int>(y.size()), TRUE) >= 0;
}
// CONTRACT: wildcards consume Unicode characters (including surrogate pairs), with Windows ordinal casing.
inline bool path_glob_unicode(std::string_view pattern, std::string_view value) {
    const auto pat = path_wide(pattern), text = path_wide(value);
    size_t p = 0, v = 0, star = std::wstring::npos, retry = 0;
    while (v < text.size()) {
        if (p < pat.size() && pat[p] == L'*') { star = p++; retry = v; continue; }
        const size_t ve = path_character_end(text, v);
        if (p < pat.size()) {
            const size_t pe = path_character_end(pat, p);
            if (pat[p] == L'?' || CompareStringOrdinal(pat.data() + p, static_cast<int>(pe - p),
                text.data() + v, static_cast<int>(ve - v), TRUE) == CSTR_EQUAL) { p = pe; v = ve; continue; }
        }
        if (star == std::wstring::npos || retry == text.size()) return false;
        p = star + 1;
        retry = path_character_end(text, retry);
        v = retry;
    }
    while (p < pat.size() && pat[p] == L'*') ++p;
    return p == pat.size();
}
}
