// Editing algorithms adapted from Serena 2.0.0; see third_party/solidlsp-LICENSE.txt.
#include "edit.hpp"
#include "lsp.hpp"
#include "path_match.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <set>
#include <stdexcept>
#ifdef SHGREP_PCRE2
#include <pcre2.h>
#endif

namespace shgrep {
namespace {
using Clock = std::chrono::steady_clock;
constexpr size_t max_file = 64ull << 20, max_plan = 256ull << 20, max_occurrences = 100000;
[[noreturn]] void fail(const std::string& message) { throw std::runtime_error(message); }
std::string arg(const Json& args, const char* key, const std::string& fallback = {}) {
    const Json* value = args.get(key);
    return value ? value->string() : fallback;
}
int64_t number(const Json& args, const char* key, int64_t fallback) {
    const Json* value = args.get(key);
    return value ? value->integer() : fallback;
}
bool flag(const Json& args, const char* key) {
    const Json* value = args.get(key);
    return value && value->boolean();
}
std::string path_text(const std::filesystem::path& path) {
    const auto text = path.generic_u8string();
    return {reinterpret_cast<const char*>(text.data()), text.size()};
}
struct Control {
    Clock::time_point deadline;
    std::shared_ptr<std::atomic_bool> cancelled;
    void check() const {
        if (cancelled && cancelled->load()) fail("edit cancelled; nothing written");
        if (Clock::now() >= deadline) fail("edit timed out; nothing written");
    }
};

// Match *, **, **/ and ? with Windows ordinal casing. DP avoids exponential wildcard backtracking.
bool glob(const std::string& pattern, const std::string& value) {
    if (pattern.empty()) return true;
    auto p = path_wide(pattern), v = path_wide(value);
    std::replace(p.begin(), p.end(), L'\\', L'/');
    std::vector<unsigned char> row(v.size() + 1), next(v.size() + 1);
    row[0] = 1;
    for (size_t i = 0; i < p.size();) {
        std::fill(next.begin(), next.end(), 0);
        if (p[i] == L'*') {
            const bool recursive = i + 1 < p.size() && p[i + 1] == L'*';
            i += recursive ? 2 : 1;
            const bool directory = recursive && i < p.size() && p[i] == L'/';
            if (directory) ++i;
            bool active = false;
            for (size_t j = 0; j <= v.size(); ++j) {
                active = active || row[j];
                if (directory) {
                    next[j] |= row[j];
                    if (j < v.size() && v[j] == L'/' && active) next[j + 1] = 1;
                } else {
                    next[j] = static_cast<unsigned char>(active);
                    if (j < v.size() && !recursive && v[j] == L'/') active = false;
                }
            }
        } else {
            const size_t end = path_character_end(p, i);
            for (size_t j = 0; j < v.size();) {
                const size_t ve = path_character_end(v, j);
                if (row[j] && ((p[i] == L'?' && v[j] != L'/') ||
                    CompareStringOrdinal(p.data() + i, static_cast<int>(end - i), v.data() + j,
                                         static_cast<int>(ve - j), TRUE) == CSTR_EQUAL)) next[ve] = 1;
                j = ve;
            }
            i = end;
        }
        row.swap(next);
    }
    return row.back() != 0;
}

// Serena's editor works on logical LF text. Keep a sparse map back to disk so mixed endings outside an edit survive.
struct LogicalText {
    std::string text, eol = "\n";
    std::vector<uint32_t> crlf;
    explicit LogicalText(const std::string& original) {
        if (original.find("\r\n") != std::string::npos) eol = "\r\n";
        else if (original.find('\n') == std::string::npos && original.find('\r') != std::string::npos) eol = "\r";
        text.reserve(original.size());
        for (size_t i = 0; i < original.size(); ++i) {
            if (original[i] == '\r') {
                if (i + 1 < original.size() && original[i + 1] == '\n') { crlf.push_back(static_cast<uint32_t>(text.size())); ++i; }
                text.push_back('\n');
            } else text.push_back(original[i]);
        }
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
    std::string ending(const std::string& replacement) const {
        if (eol == "\n") return replacement;
        std::string out;
        for (char c : replacement) { if (c == '\n') out += eol; else out += c; }
        return out;
    }
};

struct Occurrence {
    size_t start, end;
    std::string replacement, id;
    bool ambiguous = false, selected = true;
};

class Pattern {
    std::string needle_, replacement_;
    bool regex_;
    const Control& control_;
#ifdef SHGREP_PCRE2
    struct CodeFree { void operator()(pcre2_code* p) const { pcre2_code_free(p); } };
    struct DataFree { void operator()(pcre2_match_data* p) const { pcre2_match_data_free(p); } };
    struct ContextFree { void operator()(pcre2_match_context* p) const { pcre2_match_context_free(p); } };
    std::unique_ptr<pcre2_code, CodeFree> code_;
    std::unique_ptr<pcre2_match_data, DataFree> data_, probe_;
    std::unique_ptr<pcre2_match_context, ContextFree> context_;
    static int callout(pcre2_callout_block*, void* context) {
        const auto& control = *static_cast<const Control*>(context);
        return (control.cancelled && control.cancelled->load()) || Clock::now() >= control.deadline
            ? PCRE2_ERROR_CALLOUT : 0;
    }
    int match(std::string_view text, size_t start, uint32_t options, pcre2_match_data* data) const {
        const int result = pcre2_match(code_.get(), reinterpret_cast<PCRE2_SPTR>(text.data()), text.size(),
                                       start, options, data, context_.get());
        control_.check();
        if (result < 0 && result != PCRE2_ERROR_NOMATCH)
            fail("edit regex failed with PCRE2 error " + std::to_string(result) + "; nothing written");
        return result;
    }
    std::string expand(const std::string& text) const {
        const auto* spans = pcre2_get_ovector_pointer(data_.get());
        const size_t count = pcre2_get_ovector_count(data_.get());
        std::string out;
        for (size_t i = 0; i < replacement_.size();) {
            if (replacement_[i] != '$' || i + 2 >= replacement_.size() || replacement_[i + 1] != '!' ||
                !std::isdigit(static_cast<unsigned char>(replacement_[i + 2]))) {
                if (out.size() >= max_file) fail("expanded replacement exceeds 64 MiB");
                out.push_back(replacement_[i++]); continue;
            }
            i += 2;
            size_t group = 0;
            while (i < replacement_.size() && std::isdigit(static_cast<unsigned char>(replacement_[i]))) {
                const size_t digit = static_cast<size_t>(replacement_[i++] - '0');
                if (group > (std::numeric_limits<size_t>::max() - digit) / 10) fail("replacement group number is too large");
                group = group * 10 + digit;
            }
            if (group >= count) fail("replacement refers to nonexistent capture group $!" + std::to_string(group));
            if (spans[2 * group] != PCRE2_UNSET) {
                const size_t length = spans[2 * group + 1] - spans[2 * group];
                if (length > max_file - out.size()) fail("expanded replacement exceeds 64 MiB");
                out.append(text, spans[2 * group], length);
            }
        }
        return out;
    }
#endif
public:
    Pattern(const Json& args, const Control& control)
        : needle_(LogicalText(arg(args, "needle")).text), replacement_(LogicalText(arg(args, "repl")).text),
          regex_(arg(args, "mode", "literal") == "regex"), control_(control) {
        if (!args.get("needle") || !args.get("repl")) fail("content replacement requires needle and repl");
        const std::string mode = arg(args, "mode", "literal");
        if (mode != "literal" && mode != "regex") fail("mode must be literal or regex");
        if (needle_.empty() || needle_.size() > 65536) fail("needle must contain 1-65536 UTF-8 bytes");
        if (replacement_.size() > max_file) fail("replacement exceeds 64 MiB");
        if (!regex_) return;
#ifdef SHGREP_PCRE2
        int error = 0;
        PCRE2_SIZE at = 0;
        code_.reset(pcre2_compile(reinterpret_cast<PCRE2_SPTR>(needle_.data()), needle_.size(),
            PCRE2_UTF | PCRE2_UCP | PCRE2_DOTALL | PCRE2_MULTILINE | PCRE2_AUTO_CALLOUT, &error, &at, nullptr));
        if (!code_) {
            PCRE2_UCHAR message[256]{};
            pcre2_get_error_message(error, message, sizeof(message));
            fail("invalid edit regex at byte " + std::to_string(at) + ": " + reinterpret_cast<const char*>(message));
        }
        data_.reset(pcre2_match_data_create_from_pattern(code_.get(), nullptr));
        probe_.reset(pcre2_match_data_create_from_pattern(code_.get(), nullptr));
        context_.reset(pcre2_match_context_create(nullptr));
        if (!data_ || !probe_ || !context_) fail("cannot allocate edit regex state");
        pcre2_set_match_limit(context_.get(), 10000000);
        pcre2_set_depth_limit(context_.get(), 1000);
        pcre2_set_heap_limit(context_.get(), 65536);
        pcre2_set_callout(context_.get(), callout, const_cast<Control*>(&control_));
#else
        fail("regex editing requires the approved PCRE2 build");
#endif
    }
    std::vector<Occurrence> find(const std::string& text) const {
        std::vector<Occurrence> out;
        size_t start = 0, bytes = 0;
        bool retry_empty = false;
        while (start <= text.size()) {
            control_.check();
            size_t begin = 0, end = 0;
            std::string replacement;
            bool ambiguous = false;
            if (!regex_) {
                begin = text.find(needle_, start);
                if (begin == std::string::npos) break;
                end = begin + needle_.size();
                replacement = replacement_;
            } else {
#ifdef SHGREP_PCRE2
                const int result = match(text, start, retry_empty ? PCRE2_NOTEMPTY_ATSTART | PCRE2_ANCHORED : 0, data_.get());
                if (result == PCRE2_ERROR_NOMATCH) {
                    if (!retry_empty || start == text.size()) break;
                    do { ++start; } while (start < text.size() && (static_cast<unsigned char>(text[start]) & 0xc0) == 0x80);
                    retry_empty = false;
                    continue;
                }
                const auto* spans = pcre2_get_ovector_pointer(data_.get());
                begin = spans[0]; end = spans[1];
                if (begin > end) fail("edit regex returned a reversed range");
                replacement = expand(text);
                const std::string_view matched(text.data() + begin, end - begin);
                if (matched.find('\n') != std::string_view::npos && !matched.empty()) {
                    size_t first = 1;
                    while (first < matched.size() && (static_cast<unsigned char>(matched[first]) & 0xc0) == 0x80) ++first;
                    ambiguous = match(matched.substr(first), 0, 0, probe_.get()) != PCRE2_ERROR_NOMATCH;
                }
#endif
            }
            if (out.size() >= max_occurrences) fail("edit has over 100000 occurrences; narrow the scope");
            bytes += replacement.size() + sizeof(Occurrence);
            if (bytes > max_plan) fail("edit planning exceeds 256 MiB; narrow the scope");
            out.push_back({begin, end, std::move(replacement), {}, ambiguous, true});
            start = end;
            retry_empty = begin == end;
        }
        return out;
    }
};

std::string occurrence_lines(const std::string& text, const std::vector<Occurrence>& occurrences,
                             uint64_t first_line, const Control& control) {
    constexpr size_t shown_limit = 64;
    size_t cursor = 0;
    uint64_t line = first_line;
    std::string out = " at lines ";
    const size_t count = std::min(occurrences.size(), shown_limit);
    for (size_t i = 0; i < count; ++i) {
        const size_t stop = std::min(occurrences[i].start, text.size());
        while (cursor < stop) {
            if ((cursor & 1023) == 0) control.check();
            const char c = text[cursor++];
            if (c == '\n' || (c == '\r' && (cursor == text.size() || text[cursor] != '\n'))) ++line;
        }
        out += (i ? ", " : "") + std::to_string(line);
    }
    if (occurrences.size() > shown_limit)
        out += " (first " + std::to_string(shown_limit) + " of " + std::to_string(occurrences.size()) + ")";
    return out;
}

void reject_fields(const Json& args, std::initializer_list<const char*> fields) {
    for (const char* key : fields) if (args.get(key)) fail(std::string(key) + " is not valid for this edit operation");
}

std::string line_edit(const SourceText& source, const Json& args, const std::string& operation,
                      const Control& control) {
    LogicalText logical(source.text);
    const bool insertion = operation == "insert_at_line";
    const int64_t first = number(args, insertion ? "line" : "start_line", 0);
    const int64_t last = insertion ? first : number(args, "end_line", 0);
    if (first < 1 || last < first) fail("invalid inclusive line range; line edits use 1-based lines");
    // Scan only to the requested range; an array of every line offset could dwarf a newline-heavy source file.
    size_t begin = 0, end = 0;
    int64_t current = 1;
    while (current < first) {
        control.check();
        const size_t next = logical.text.find('\n', begin);
        if (next == std::string::npos) {
            if (!insertion || current + 1 != first || begin == logical.text.size()) fail("line is outside the file");
            begin = logical.text.size(); ++current; break;
        }
        begin = next + 1; ++current;
    }
    end = begin;
    if (!insertion) {
        for (; current <= last; ++current) {
            control.check();
            if (end == logical.text.size()) fail("line range is outside the file");
            const size_t next = logical.text.find('\n', end);
            end = next == std::string::npos ? logical.text.size() : next + 1;
        }
    }
    std::string replacement;
    if (operation != "delete_lines") {
        if (!args.get("new_text")) fail("line insertion/replacement requires new_text");
        replacement = LogicalText(arg(args, "new_text")).text;
        if (!replacement.ends_with("\n")) replacement += '\n';
        if (insertion && begin == logical.text.size() && begin && logical.text.back() != '\n')
            replacement.insert(replacement.begin(), '\n');
    }
    const std::string raw_replacement = logical.ending(replacement);
    const size_t raw_begin = logical.raw(begin), raw_end = logical.raw(end);
    if (raw_replacement.size() > max_file || source.text.size() - (raw_end - raw_begin) > max_file - raw_replacement.size())
        fail("edited file exceeds 64 MiB");
    std::string result = source.text;
    result.replace(raw_begin, raw_end - raw_begin, raw_replacement);
    control.check();
    return result;
}
} // namespace

std::string scoped_content_edit(const SourceText& source, size_t begin, size_t end,
                                const Json& args, const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (begin > end || end > source.text.size()) fail("invalid symbol edit range");
    const int64_t timeout = number(args, "timeout_ms", 30000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout)), cancelled};
    control.check();
    if (arg(args, "operation") == "insert_in_symbol") {
        const int64_t line = number(args, "line", 0);
        if (line < 1 || line > INT32_MAX) fail("line must be a 1-based source line");
        size_t point = 0;
        for (int64_t current = 1; current < line; ++current) {
            control.check();
            const size_t next = source.text.find('\n', point);
            if (next == std::string::npos) fail("insertion line is beyond EOF");
            point = next + 1;
        }
        if (point < begin || point >= end)
            fail("insertion line must start inside the selected symbol range");
        const std::string indentation = arg(args, "indent", "verbatim");
        if (indentation != "verbatim" && indentation != "match") fail("indent must be verbatim or match");
        if (indentation == "verbatim") return line_edit(source, args, "insert_at_line", control);
        if (!args.get("new_text")) fail("line insertion/replacement requires new_text");
        size_t indent_end = point;
        while (indent_end < source.text.size() &&
               (source.text[indent_end] == ' ' || source.text[indent_end] == '\t')) {
            if ((indent_end & 1023) == 0) control.check();
            ++indent_end;
        }
        const std::string prefix = source.text.substr(point, indent_end - point);
        const std::string input = LogicalText(arg(args, "new_text")).text;
        std::string indented;
        for (size_t at = 0; at < input.size();) {
            control.check();
            const size_t next = input.find('\n', at);
            const size_t last = next == std::string::npos ? input.size() : next + 1;
            const size_t content_end = next == std::string::npos ? input.size() : next;
            const bool blank = input.find_first_not_of(" \t", at) >= content_end;
            const size_t extra = blank ? 0 : prefix.size();
            if (indented.size() + extra + last - at > max_file) fail("indented insertion exceeds 64 MiB");
            if (!blank) indented += prefix;
            indented.append(input, at, last - at);
            at = last;
        }
        Json::Object adjusted = args.object();
        adjusted["new_text"] = std::move(indented);
        return line_edit(source, adjusted, "insert_at_line", control);
    }
    if (arg(args, "operation") != "replace_in_symbol") fail("unknown scoped edit operation");
    const std::string original = source.text.substr(begin, end - begin);
    LogicalText logical(original);
    // A one-line symbol has no newline from which to infer the file's style.
    if (source.text.find("\r\n") != std::string::npos) logical.eol = "\r\n";
    else if (source.text.find('\n') == std::string::npos && source.text.find('\r') != std::string::npos)
        logical.eol = "\r";
    const Pattern pattern(args, control);
    const auto occurrences = pattern.find(logical.text);
    if (occurrences.empty()) fail("no occurrences inside the selected symbol; nothing written");
    if (!flag(args, "allow_multiple_occurrences") && occurrences.size() != 1) {
        uint64_t first_line = 1;
        for (size_t at = 0; at < begin; ++at) {
            if ((at & 1023) == 0) control.check();
            if (source.text[at] == '\n' ||
                (source.text[at] == '\r' && (at + 1 == source.text.size() || source.text[at + 1] != '\n')))
                ++first_line;
        }
        fail("expression matches " + std::to_string(occurrences.size()) +
             " occurrences inside the symbol" + occurrence_lines(logical.text, occurrences, first_line, control) +
             "; refine needle or set allow_multiple_occurrences; nothing written");
    }
    std::string replacement;
    size_t cursor = 0;
    for (const auto& occurrence : occurrences) {
        control.check();
        if (occurrence.ambiguous) fail("ambiguous multiline match inside symbol; refine needle; nothing written");
        const size_t first = logical.raw(occurrence.start), last = logical.raw(occurrence.end);
        if (first < cursor) fail("overlapping symbol edit ranges");
        const std::string inserted = logical.ending(occurrence.replacement);
        if (replacement.size() + first - cursor + inserted.size() > max_file)
            fail("edited symbol exceeds 64 MiB");
        replacement.append(original, cursor, first - cursor);
        replacement += inserted;
        cursor = last;
    }
    if (replacement.size() + original.size() - cursor > max_file) fail("edited symbol exceeds 64 MiB");
    replacement.append(original, cursor, std::string::npos);
    if (source.text.size() - (end - begin) + replacement.size() > max_file)
        fail("edited file exceeds 64 MiB");
    std::string result = source.text;
    result.replace(begin, end - begin, replacement);
    control.check();
    return result;
}

std::string outside_content_edit(const SourceText& source,
                                 const std::vector<std::pair<size_t, size_t>>& protected_ranges,
                                 const Json& args, const std::shared_ptr<std::atomic_bool>& cancelled) {
    const int64_t timeout = number(args, "timeout_ms", 180000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout)), cancelled};
    const auto blocked = [&](size_t begin, size_t end) {
        for (const auto& [first, last] : protected_ranges) {
            control.check();
            if (first > last || last > source.text.size()) fail("invalid protected symbol range");
            if (begin == end ? (begin > first && begin < last) : (begin < last && first < end))
                return true;
        }
        return false;
    };
    const std::string operation = arg(args, "operation");
    if (operation == "insert_outside_symbols") {
        const int64_t line = number(args, "line", 0);
        if (line < 1 || line > INT32_MAX) fail("line must be a 1-based source line");
        LogicalText logical(source.text);
        size_t point = 0;
        for (int64_t current = 1; current < line; ++current) {
            control.check();
            const size_t next = logical.text.find('\n', point);
            if (next == std::string::npos) {
                if (current + 1 != line || point == logical.text.size()) fail("insertion line is beyond EOF");
                point = logical.text.size();
                break;
            }
            point = next + 1;
        }
        point = logical.raw(point);
        if (blocked(point, point)) fail("insertion line is inside a protected symbol; nothing written");
        return line_edit(source, args, "insert_at_line", control);
    }
    if (operation != "replace_outside_symbols") fail("unknown outside-symbol edit operation");
    LogicalText logical(source.text);
    const Pattern pattern(args, control);
    const auto matches = pattern.find(logical.text);
    std::vector<Occurrence> eligible;
    for (const auto& match : matches) {
        control.check();
        const size_t first = logical.raw(match.start), last = logical.raw(match.end);
        if (blocked(first, last)) {
            bool contained = false;
            for (const auto& [start, end] : protected_ranges)
                if (first >= start && last <= end && (first != last || (first > start && first < end))) {
                    contained = true;
                    break;
                }
            if (!contained) fail("match crosses a protected symbol boundary; nothing written");
            continue;
        }
        eligible.push_back(match);
    }
    if (eligible.empty()) fail("no occurrences outside protected symbols; nothing written");
    if (!flag(args, "allow_multiple_occurrences") && eligible.size() != 1)
        fail("expression matches " + std::to_string(eligible.size()) +
             " occurrences outside symbols" + occurrence_lines(logical.text, eligible, 1, control) +
             "; refine needle or set allow_multiple_occurrences; nothing written");
    std::string result;
    size_t cursor = 0;
    for (const auto& match : eligible) {
        control.check();
        if (match.ambiguous) fail("ambiguous multiline match; refine needle; nothing written");
        const size_t first = logical.raw(match.start), last = logical.raw(match.end);
        if (first < cursor) fail("overlapping edit ranges");
        const std::string replacement = logical.ending(match.replacement);
        if (result.size() + first - cursor + replacement.size() > max_file) fail("edited file exceeds 64 MiB");
        result.append(source.text, cursor, first - cursor);
        result += replacement;
        cursor = last;
    }
    if (result.size() + source.text.size() - cursor > max_file) fail("edited file exceeds 64 MiB");
    result.append(source.text, cursor, std::string::npos);
    control.check();
    return result;
}

Json content_edit(const Json& args, const SearchContext& context,
                  const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (context.read_only) fail("edit_file is disabled: --read-only");
    const int64_t timeout = number(args, "timeout_ms", 30000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout)), cancelled};
    control.check();
    const std::string operation = arg(args, "operation");
    const bool bulk = operation == "replace_in_files";
    const bool line = operation == "insert_at_line" || operation == "replace_lines" || operation == "delete_lines";
    reject_fields(args, {"edits", "name_path", "new_name", "column"});
    if (line) {
        reject_fields(args, {"needle", "repl", "mode", "allow_multiple_occurrences", "paths_include_glob",
                             "paths_exclude_glob", "occurrence_ids", "expected_count"});
        if (operation == "insert_at_line") reject_fields(args, {"start_line", "end_line"});
        else reject_fields(args, {"line"});
        if (operation == "delete_lines") reject_fields(args, {"new_text"});
        const std::string notice = require_text_access(source_descriptor(context, arg(args, "path")), args, context, cancelled);
        const SourceText source = read_source_text(context, arg(args, "path"));
        Json result = apply_source_changes({SourceChange{source, line_edit(source, args, operation, control)}}, args, context, cancelled);
        auto& text = std::get<Json::Object>(result.value).at("text");
        text = notice + text.string();
        std::get<Json::Object>(result.value)["access_note"] = notice;
        return result;
    }
    reject_fields(args, {"line", "start_line", "end_line", "new_text"});
    if (!bulk) reject_fields(args, {"paths_include_glob", "paths_exclude_glob", "occurrence_ids", "expected_count"});
    if (bulk) reject_fields(args, {"allow_multiple_occurrences", "expected_sha256", "expected_mtime", "diagnostics"});
    const bool allow_multiple = !bulk && flag(args, "allow_multiple_occurrences");
    const int64_t expected_count = number(args, "expected_count", -1);
    if (expected_count < -1) fail("expected_count must be -1 or nonnegative");
    if (args.get("occurrence_ids") && args.get("expected_count")) fail("use occurrence_ids or expected_count, not both");
    Pattern pattern(args, control);
    std::string include = arg(args, "paths_include_glob"), exclude = arg(args, "paths_exclude_glob");
    std::replace(include.begin(), include.end(), '\\', '/');
    std::replace(exclude.begin(), exclude.end(), '\\', '/');
    if (include.size() > 4096 || exclude.size() > 4096) fail("edit glob exceeds 4096 bytes");
    std::vector<std::string> paths;
    bool directory = false;
    const SourceText scope = source_descriptor(context, arg(args, "path"), &directory);
    if (!bulk && directory) fail("replace_content requires a file");
    const std::string scoped = path_text(scope.path.lexically_relative(scope.root));
    auto accepts = [&](const std::string& relative, bool folder) {
        if (!exclude.empty() && (glob(exclude, relative) ||
            (folder && exclude.ends_with("/**") && glob(exclude.substr(0, exclude.size() - 3), relative)))) return false;
        if (scoped != "." && !scoped.empty()) {
            const bool descendant = relative.size() > scoped.size() && relative[scoped.size()] == '/' &&
                path_equal_unicode(relative.substr(0, scoped.size()), scoped);
            const bool ancestor = folder && scoped.size() > relative.size() && scoped[relative.size()] == '/' &&
                path_equal_unicode(scoped.substr(0, relative.size()), relative);
            if (!path_equal_unicode(relative, scoped) && !descendant && !ancestor) return false;
        }
        return folder || include.empty() || glob(include, relative);
    };
    if (directory) paths = source_paths(context, path_text(scope.root), {}, control.deadline, cancelled, accepts);
    else if (accepts(path_text(scope.path.lexically_relative(scope.root)), false)) paths.push_back(path_text(scope.path));

    struct Plan { SourceText before; std::vector<Occurrence> occurrences; };
    std::vector<Plan> plans;
    std::set<std::wstring> seen;
    size_t count = 0, skipped = 0, skipped_lsp = 0, plan_bytes = 0;
    std::string fallback_notice;
    const std::string binding = source_text_digest(Json(Json::Array{arg(args, "mode", "literal"),
        arg(args, "needle"), arg(args, "repl")}).dump());
    for (const auto& path : paths) {
        control.check();
        SourceText descriptor;
        try { descriptor = source_descriptor(context, path); }
        catch (const std::runtime_error&) {
            if (!directory) throw;
            control.check(); ++skipped; continue;
        }
        if (lsp_required(descriptor.path)) {
            if (!directory) fallback_notice += require_text_access(descriptor, args, context, cancelled);
            else if (!flag(args, "allow_text_fallback")) { ++skipped_lsp; continue; }
            else {
                const std::string reason = lsp_fallback_reason(descriptor, args, context, cancelled);
                if (reason.empty()) { ++skipped_lsp; continue; }
                if (fallback_notice.empty()) fallback_notice = lsp_failure_banner(reason, "Explicit text fallback for files without working LSP");
            }
        }
        SourceText source;
        try { source = read_source_text(context, path); }
        catch (const std::runtime_error& error) {
            if (!directory || std::string(error.what()).starts_with("SHA-256")) throw;
            control.check(); ++skipped; continue;
        }
        if (!seen.insert(path_wide(path)).second) continue;
        LogicalText logical(source.text);
        auto occurrences = pattern.find(logical.text);
        if (occurrences.empty()) continue;
        if (occurrences.size() > max_occurrences - count) fail("edit has over 100000 occurrences; narrow the scope");
        count += occurrences.size();
        plan_bytes += source.text.size();
        const std::string shown = path_text(source.path.lexically_relative(source.root));
        for (size_t i = 0; i < occurrences.size(); ++i) {
            auto& occurrence = occurrences[i];
            const size_t begin = logical.raw(occurrence.start), end = logical.raw(occurrence.end);
            occurrence.start = begin; occurrence.end = end;
            occurrence.replacement = logical.ending(occurrence.replacement);
            occurrence.id = shown + ":" + std::to_string(i) + "@" +
                source_text_digest(path_text(source.path) + ":" + source.sha256 + ":" + binding + ":" +
                                   std::to_string(begin) + ":" + std::to_string(end)).substr(0, 16);
            plan_bytes += occurrence.id.size() + occurrence.replacement.size() + sizeof(Occurrence);
            if (plan_bytes > max_plan) fail("edit planning exceeds 256 MiB; narrow the scope");
        }
        plans.push_back({std::move(source), std::move(occurrences)});
    }
    auto listing = [&] {
        std::string out = "Found " + std::to_string(count) + " occurrences in " + std::to_string(plans.size()) + " files.\n";
        for (const auto& plan : plans) {
            const LogicalText logical(plan.before.text);
            size_t cursor = 0, line_number = 1, line_start = 0;
            const auto append_block = [&](std::string_view block, const char* prefix) {
                for (size_t at = 0;;) {
                    control.check();
                    const size_t next = block.find('\n', at);
                    out += prefix;
                    out.append(block.substr(at, next == std::string_view::npos ? next : next - at));
                    out += '\n';
                    if (next == std::string_view::npos) break;
                    at = next + 1;
                }
            };
            for (const auto& occurrence : plan.occurrences) {
                control.check();
                const size_t start = logical.logical(occurrence.start), end = logical.logical(occurrence.end);
                while (cursor < start) {
                    if (logical.text[cursor++] == '\n') { ++line_number; line_start = cursor; }
                }
                size_t end_line = line_number;
                for (size_t at = start; at < end; ++at) if (logical.text[at] == '\n') ++end_line;
                if (end > start && logical.text[end - 1] == '\n') --end_line;
                out += "[" + occurrence.id + "] " + (line_number == end_line ? "line " : "lines ") + std::to_string(line_number);
                if (end_line != line_number) out += "-" + std::to_string(end_line);
                if (occurrence.ambiguous) out += " [ambiguous: pattern matches inside this span]";
                out += '\n';

                const size_t next = logical.text.find('\n', end);
                const size_t line_end = next == std::string::npos ? logical.text.size() : next;
                std::string_view before(logical.text.data() + line_start, line_end - line_start);
                std::string after(logical.text, line_start, start - line_start);
                after += LogicalText(occurrence.replacement).text;
                after.append(logical.text, end, line_end - end);
                // Serena's line window omits a phantom EOF line and unchanged trailing context.
                if (line_end == logical.text.size()) {
                    if (before.ends_with("\n")) before.remove_suffix(1);
                    if (after.ends_with("\n")) after.pop_back();
                }
                for (;;) {
                    control.check();
                    const size_t old_last = before.rfind('\n'), new_last = after.rfind('\n');
                    if (old_last == std::string_view::npos || new_last == std::string::npos ||
                        before.substr(old_last + 1) != std::string_view(after).substr(new_last + 1)) break;
                    before = before.substr(0, old_last);
                    after.resize(new_last);
                }
                append_block(before, "    - ");
                append_block(after, "    + ");
            }
        }
        if (skipped) out += "Skipped " + std::to_string(skipped) + " unreadable, binary, or oversized files.\n";
        if (skipped_lsp) out += "[LSP required: skipped " + std::to_string(skipped_lsp) + " programming/XML files; use symbol edits]\n";
        return fallback_notice + out;
    };
    if (bulk && flag(args, "dry_run")) {
        // The listing is rebuilt on every request; keep only the hashes needed for freshness checks.
        const std::string preview = listing();
        for (const auto& plan : plans) remember_read_snapshot(context, plan.before.path, plan.before.sha256);
        return Json::Object{{"text", "Dry run, nothing written.\n" + preview}, {"access_note", fallback_notice}};
    }
    if (!count) fail("no occurrences found; nothing written" + (skipped ? " (some files were unreadable, binary, or oversized)" : std::string()) +
                     (skipped_lsp ? "; skipped " + std::to_string(skipped_lsp) + " programming/XML files that require LSP" : std::string()));
    if (!bulk && !allow_multiple && count > 1)
        fail("expression matches " + std::to_string(count) + " occurrences" +
             occurrence_lines(plans.front().before.text, plans.front().occurrences, 1, control) +
             "; refine needle or set allow_multiple_occurrences; nothing written");
    if (const Json* ids = args.get("occurrence_ids")) {
        if (args.get("expected_count")) fail("use occurrence_ids or expected_count, not both");
        if (ids->array().empty() || ids->array().size() > max_occurrences) fail("occurrence_ids must contain 1-100000 IDs");
        std::set<std::string> wanted;
        for (const auto& id : ids->array()) wanted.insert(id.string());
        for (auto& plan : plans) for (auto& occurrence : plan.occurrences)
            occurrence.selected = wanted.erase(occurrence.id) != 0;
        if (!wanted.empty()) fail("unknown or stale occurrence_ids; nothing written. Repeat dry_run to obtain current IDs");
    } else {
        if (expected_count >= 0 && static_cast<uint64_t>(expected_count) != count)
            fail("expected_count=" + std::to_string(expected_count) + " differs from " + std::to_string(count) +
                 "; nothing written.\n" + listing());
        for (const auto& plan : plans) for (const auto& occurrence : plan.occurrences)
            if (occurrence.ambiguous) fail("ambiguous multiline match; nothing written. Refine needle or explicitly select preview occurrence_ids.\n" + listing());
    }
    std::vector<SourceChange> changes;
    size_t selected_count = 0;
    for (auto& plan : plans) {
        control.check();
        std::string after;
        size_t cursor = 0;
        bool changed = false;
        for (const auto& occurrence : plan.occurrences) {
            if (!occurrence.selected) continue;
            control.check();
            if (occurrence.start < cursor) fail("overlapping edit ranges; nothing written");
            if (after.size() + occurrence.start - cursor + occurrence.replacement.size() > max_file)
                fail("edited file exceeds 64 MiB");
            after.append(plan.before.text, cursor, occurrence.start - cursor);
            after += occurrence.replacement;
            cursor = occurrence.end;
            changed = true; ++selected_count;
        }
        if (!changed) continue;
        if (after.size() + plan.before.text.size() - cursor > max_file) fail("edited file exceeds 64 MiB");
        after.append(plan.before.text, cursor, std::string::npos);
        plan_bytes += after.size();
        if (plan_bytes > max_plan) fail("edit planning exceeds 256 MiB; narrow the scope");
        changes.push_back({std::move(plan.before), std::move(after)});
    }
    control.check();
    Json result = apply_source_changes(changes, args, context, cancelled);
    auto& out = std::get<Json::Object>(result.value).at("text");
    std::get<Json::Object>(result.value)["access_note"] = fallback_notice;
    out = fallback_notice + std::to_string(selected_count) + " selected occurrences.\n" + out.string() +
        ((flag(args, "dry_run") && arg(args, "mode", "literal") == "literal" &&
          arg(args, "needle") == arg(args, "repl")) ? "Needle and replacement are identical; no content will change.\n" : "") +
        (skipped ? "Skipped " + std::to_string(skipped) + " unreadable, binary, or oversized files.\n" : "") +
        (skipped_lsp ? "[LSP required: skipped " + std::to_string(skipped_lsp) + " programming/XML files; use symbol edits]\n" : "");
    return result;
}
} // namespace shgrep
