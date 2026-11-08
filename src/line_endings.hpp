#pragma once
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace shgrep {
// Logical LF text with a sparse map to the original UTF-8 byte offsets.
struct LogicalText {
    std::string text, eol = "\n";
    std::vector<uint32_t> crlf;
    explicit LogicalText(std::string_view original) {
        size_t lf = 0, cr = 0;
        text.reserve(original.size());
        for (size_t i = 0; i < original.size(); ++i) {
            if (original[i] == '\r') {
                if (i + 1 < original.size() && original[i + 1] == '\n') {
                    crlf.push_back(static_cast<uint32_t>(text.size()));
                    ++i;
                } else ++cr;
                text.push_back('\n');
            } else {
                if (original[i] == '\n') ++lf;
                text.push_back(original[i]);
            }
        }
        if (!crlf.empty() && crlf.size() >= lf && crlf.size() >= cr) eol = "\r\n";
        else if (lf && lf >= cr) eol = "\n";
        else if (cr) eol = "\r";
    }
    size_t raw(size_t offset) const {
        return offset + static_cast<size_t>(std::lower_bound(crlf.begin(), crlf.end(), offset) - crlf.begin());
    }
    size_t logical(size_t raw_offset) const {
        size_t first = 0, last = crlf.size();
        while (first < last) {
            const size_t middle = first + (last - first) / 2;
            if (static_cast<size_t>(crlf[middle]) + middle < raw_offset) first = middle + 1;
            else last = middle;
        }
        return raw_offset - first;
    }
};
inline std::string_view nearby_line_ending(std::string_view text, size_t offset, std::string_view fallback) {
    const size_t before = offset ? text.find_last_of("\r\n", offset - 1) : std::string_view::npos;
    const size_t at = before == std::string_view::npos ? text.find_first_of("\r\n", offset) : before;
    if (at == std::string_view::npos) return fallback;
    if (text[at] == '\n') return at && text[at - 1] == '\r' ? "\r\n" : "\n";
    return at + 1 < text.size() && text[at + 1] == '\n' ? "\r\n" : "\r";
}
// lcfix.ps1 alignment, using the pre-edit region instead of a Git commit.
// Matched lines retain their exact endings; inserted/changed lines carry the preceding style.
std::string preserve_line_endings(std::string_view reference, std::string_view replacement,
                                  std::string_view fallback,
                                  const std::shared_ptr<std::atomic_bool>& cancelled);
}
