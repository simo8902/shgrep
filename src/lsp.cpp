#include "lsp.hpp"
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <climits>
#include <compare>
#include <deque>
#include <functional>
#include <cwctype>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <thread>
#include <utility>

namespace shgrep {
namespace {
using Clock = std::chrono::steady_clock;
namespace fs = std::filesystem;
using J = Json;
[[noreturn]] void fail(const std::string& s) { throw std::runtime_error(s); }
std::string str(const J& j, const char* key, const std::string& fallback = "") {
    const J* p = j.get(key); return p ? p->string() : fallback;
}
bool flag(const J& j, const char* key, bool fallback = false) {
    const J* p = j.get(key); return p ? p->boolean() : fallback;
}
int64_t number(const J& j, const char* key, int64_t fallback) {
    const J* p = j.get(key); return p ? p->integer() : fallback;
}
std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    if (s.size() > INT_MAX) fail("UTF-8 text is too large");
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (!n) fail("invalid UTF-8");
    std::wstring out(static_cast<size_t>(n), 0);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}
std::string utf8(const std::wstring& s) {
    if (s.empty()) return {};
    if (s.size() > INT_MAX) fail("UTF-16 text is too large");
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (!n) fail("invalid UTF-16");
    std::string out(static_cast<size_t>(n), 0);
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}
std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
std::string uri(const fs::path& path) {
    std::wstring native = path.wstring();
    if (native.starts_with(L"\\\\?\\UNC\\")) native = L"\\\\" + native.substr(8);
    else if (native.starts_with(L"\\\\?\\")) native.erase(0, 4);
    std::replace(native.begin(), native.end(), L'\\', L'/');
    std::string s = utf8(native), out;
    constexpr char hex[] = "0123456789ABCDEF";
    if (s.starts_with("//")) { out = "file:"; } else { out = "file:///"; }
    for (unsigned char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '/' || c == ':' || c == '-' || c == '_' || c == '.' || c == '~') out.push_back(static_cast<char>(c));
        else { out.push_back('%'); out.push_back(hex[c >> 4]); out.push_back(hex[c & 15]); }
    }
    return out;
}
fs::path from_uri(const std::string& value) {
    if (!value.starts_with("file://")) fail("language server returned a non-file URI");
    std::string body = value.substr(7), decoded;
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < body.size(); ++i) {
        if (body[i] == '%') {
            if (i + 2 >= body.size() || digit(body[i + 1]) < 0 || digit(body[i + 2]) < 0) fail("invalid file URI");
            const char c = static_cast<char>(digit(body[i + 1]) * 16 + digit(body[i + 2]));
            if (!c) fail("NUL in file URI");
            decoded.push_back(c); i += 2;
        } else decoded.push_back(body[i]);
    }
    if (decoded.starts_with("/") && decoded.size() >= 3 && decoded[2] == ':') decoded.erase(0, 1);
    else if (!decoded.starts_with("/")) decoded = "//" + decoded;
    return fs::path(wide(decoded));
}
std::wstring quoted(const std::wstring& s) {
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : s) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'"') { out.append(slashes * 2 + 1, L'\\'); out.push_back(c); }
        else { out.append(slashes, L'\\'); out.push_back(c); }
        slashes = 0;
    }
    out.append(slashes * 2, L'\\'); out.push_back(L'"'); return out;
}
struct Control {
    Clock::time_point deadline;
    const std::shared_ptr<std::atomic_bool>& cancelled;
    void check() const {
        if (cancelled && cancelled->load()) fail("LSP request cancelled");
        if (Clock::now() >= deadline) fail("LSP request timed out");
    }
};
struct Handle {
    HANDLE h = nullptr;
    Handle() = default;
    explicit Handle(HANDLE value) : h(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    void reset(HANDLE value = nullptr) {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = value;
    }
};
struct PathLess {
    bool operator()(const std::wstring& a, const std::wstring& b) const {
        return CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(), static_cast<int>(b.size()), TRUE) == CSTR_LESS_THAN;
    }
};
struct Config {
    fs::path root;
    std::string language, key;
    std::vector<std::string> command, extensions, ignored_paths;
    J initialization = J::Object{}, settings = J::Object{};
};
bool glob_match(std::string_view pattern, std::string_view value) {
    std::vector<uint8_t> prior(value.size() + 1, 0), next(value.size() + 1, 0);
    prior[0] = 1;
    for (size_t p = 0; p < pattern.size();) {
        std::fill(next.begin(), next.end(), uint8_t{0});
        if (pattern[p] == '*') {
            const bool double_star = p + 1 < pattern.size() && pattern[p + 1] == '*';
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
                for (size_t v = 0; v < value.size(); ++v)
                    next[v + 1] = static_cast<uint8_t>(prior[v + 1] ||
                        (next[v] && (double_star || value[v] != '/')));
                p += double_star ? 2 : 1;
            }
        } else {
            for (size_t v = 0; v < value.size(); ++v)
                if (prior[v] && (pattern[p] == value[v] || (pattern[p] == '?' && value[v] != '/')))
                    next[v + 1] = 1;
            ++p;
        }
        prior.swap(next);
    }
    return prior[value.size()] != 0;
}
bool ignored_pattern_matches(std::string_view pattern, std::string_view path) {
    const bool has_slash = pattern.find('/') != std::string_view::npos;
    for (size_t end = path.find('/');; end = path.find('/', end + 1)) {
        const std::string_view prefix = path.substr(0, end == std::string_view::npos ? path.size() : end);
        if (has_slash ? glob_match(pattern, prefix) : glob_match(pattern, prefix.substr(prefix.rfind('/') == std::string_view::npos ? 0 : prefix.rfind('/') + 1)))
            return true;
        if (end == std::string_view::npos) break;
    }
    return false;
}
bool path_excluded(const Config& config, const fs::path& path) {
    if (config.ignored_paths.empty()) return false;
    std::wstring root = config.root.lexically_normal().wstring();
    std::wstring full = path.lexically_normal().wstring();
    std::replace(root.begin(), root.end(), L'/', L'\\');
    std::replace(full.begin(), full.end(), L'/', L'\\');
    if (!root.ends_with(L"\\")) root += L"\\";
    if (full.size() < root.size() ||
        CompareStringOrdinal(full.data(), static_cast<int>(root.size()), root.data(), static_cast<int>(root.size()), TRUE) != CSTR_EQUAL)
        return false;
    std::string relative = lower(utf8(full.substr(root.size())));
    std::replace(relative.begin(), relative.end(), '\\', '/');
    bool ignored = false;
    for (const auto& entry : config.ignored_paths) {
        const bool negated = !entry.empty() && entry.front() == '!';
        const std::string_view pattern(entry.data() + (negated ? 1 : 0), entry.size() - (negated ? 1 : 0));
        if (ignored_pattern_matches(pattern, relative)) ignored = !negated;
    }
    return ignored;
}
std::vector<Config> configs(const fs::path& root, const SearchContext& context) {
    const fs::path path = root / L".shgrep" / L"lsp.json";
    std::wstring metadata_path = path.wstring();
    if (!metadata_path.starts_with(L"\\\\?\\")) {
        if (metadata_path.starts_with(L"\\\\")) metadata_path = L"\\\\?\\UNC\\" + metadata_path.substr(2);
        else metadata_path = L"\\\\?\\" + metadata_path;
    }
    const DWORD attributes = GetFileAttributesW(metadata_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return {};
        fail("cannot inspect .shgrep/lsp.json");
    }
    const SourceText file = read_source_text(context, utf8(path.wstring()));
    const J json = J::parse(file.text);
    const J* servers = json.get("servers");
    if (!servers) fail(".shgrep/lsp.json needs a servers array");
    std::vector<Config> result;
    std::set<std::string> owned_extensions;
    for (const auto& server : servers->array()) {
        Config config;
        config.root = root;
        config.language = str(server, "language_id");
        if (config.language.empty()) fail("LSP server needs language_id");
        const J* command = server.get("command"), *extensions = server.get("extensions");
        if (!command || !extensions) fail("LSP server needs command and extensions arrays");
        for (const auto& arg : command->array()) {
            if (arg.string().find('\0') != std::string::npos) fail("NUL in LSP command");
            config.command.push_back(arg.string());
        }
        if (config.command.empty() || config.command.front().empty()) fail("empty LSP command");
        for (const auto& extension : extensions->array()) {
            std::string ext = lower(extension.string());
            if (!ext.starts_with(".")) ext = "." + ext;
            if (ext.size() < 2 || ext.find_first_of("/\\") != std::string::npos) fail("invalid LSP extension");
            if (!owned_extensions.insert(ext).second) fail("multiple language servers configured for " + ext);
            config.extensions.push_back(ext);
        }
        if (config.extensions.empty()) fail("empty LSP extensions");
        if (const J* ignored = server.get("ignored_paths")) {
            for (const auto& item : ignored->array()) {
                std::string pattern = item.string();
                std::replace(pattern.begin(), pattern.end(), '\\', '/');
                while (!pattern.empty() && pattern.back() == '/') pattern.pop_back();
                const size_t start = !pattern.empty() && pattern.front() == '!' ? 1 : 0;
                if (start == pattern.size() || pattern[start] == '/' || pattern.find(':') != std::string::npos)
                    fail("ignored_paths entries must be nonempty relative patterns");
                for (size_t part = start; part <= pattern.size();) {
                    const size_t end = pattern.find('/', part);
                    const std::string_view segment(pattern.data() + part,
                        (end == std::string::npos ? pattern.size() : end) - part);
                    if (segment == "..") fail("ignored_paths entries cannot traverse above the workspace");
                    if (end == std::string::npos) break;
                    part = end + 1;
                }
                config.ignored_paths.push_back(lower(std::move(pattern)));
            }
        }
        if (const J* p = server.get("initialization_options")) config.initialization = *p;
        if (const J* p = server.get("settings")) config.settings = *p;
        config.key = lower(utf8(root.wstring())) + ":" + file.sha256 + ":" + std::to_string(result.size());
        result.push_back(std::move(config));
    }
    return result;
}
std::optional<Config> configuration(const SourceText& source, const SearchContext& context) {
    const std::string ext = lower(utf8(source.path.extension().wstring()));
    for (auto& config : configs(source.root, context)) {
        if (std::find(config.extensions.begin(), config.extensions.end(), ext) != config.extensions.end()) return config;
    }
    return std::nullopt;
}
struct Position {
    int64_t line = 0, column = 0;
    auto operator<=>(const Position&) const = default;
    J json() const { return J::Object{{"line", line}, {"character", column}}; }
};
Position position(const J& j) {
    Position p{number(j, "line", -1), number(j, "character", -1)};
    if (p.line < 0 || p.column < 0 || p.line > INT32_MAX || p.column > INT32_MAX) fail("invalid LSP position");
    return p;
}
struct Range { Position start, end; };
Range range(const J& j) {
    const J* s = j.get("start"), *e = j.get("end");
    if (!s || !e) fail("missing LSP range");
    Range r{position(*s), position(*e)};
    if (r.end < r.start) fail("reversed LSP range");
    return r;
}
Position text_end(const std::string& text) {
    Position out;
    const std::wstring w = wide(text);
    for (size_t i = 0; i < w.size(); ++i) {
        if (w[i] == L'\r' || w[i] == L'\n') {
            if (w[i] == L'\r' && i + 1 < w.size() && w[i + 1] == L'\n') ++i;
            ++out.line; out.column = 0;
        } else ++out.column;
    }
    return out;
}
size_t offset(const std::wstring& text, Position wanted) {
    size_t i = 0;
    int64_t line = 0;
    while (i < text.size() && line < wanted.line) {
        if (text[i] == L'\r' || text[i] == L'\n') {
            if (text[i] == L'\r' && i + 1 < text.size() && text[i + 1] == L'\n') ++i;
            ++line;
        }
        ++i;
    }
    if (line != wanted.line) fail("LSP range is outside the current file");
    const size_t start = i;
    while (i < text.size() && text[i] != L'\r' && text[i] != L'\n') ++i;
    if (static_cast<uint64_t>(wanted.column) > i - start) fail("LSP column is outside the current line");
    const size_t result = start + static_cast<size_t>(wanted.column);
    if (result > 0 && result < text.size() && text[result - 1] >= 0xD800 && text[result - 1] <= 0xDBFF &&
        text[result] >= 0xDC00 && text[result] <= 0xDFFF) fail("LSP range splits a UTF-16 surrogate pair");
    return result;
}
std::string body(const SourceText& source, Range r) {
    const std::wstring text = wide(source.text);
    const size_t begin = offset(text, r.start), end = offset(text, r.end);
    return utf8(text.substr(begin, end - begin));
}

bool file_glob(std::wstring pattern, std::wstring path, bool insensitive) {
    std::replace(path.begin(), path.end(), L'\\', L'/');
    if (insensitive) {
        for (auto& c : path) c = static_cast<wchar_t>(std::towlower(c));
        for (auto& c : pattern) c = static_cast<wchar_t>(std::towlower(c));
    }
    const size_t brace = pattern.find(L'{');
    if (brace != std::wstring::npos) {
        size_t end = brace + 1, nesting = 1, start = end;
        std::vector<std::wstring> options;
        for (; end < pattern.size(); ++end) {
            if (pattern[end] == L'{') ++nesting;
            if (pattern[end] == L'}' && --nesting == 0) { options.push_back(pattern.substr(start, end - start)); break; }
            if (pattern[end] == L',' && nesting == 1) { options.push_back(pattern.substr(start, end - start)); start = end + 1; }
        }
        if (end == pattern.size()) fail("invalid file-operation glob braces");
        for (const auto& option : options)
            if (file_glob(pattern.substr(0, brace) + option + pattern.substr(end + 1), path, false)) return true;
        return false;
    }
    // Memoized glob matching keeps ** from causing exponential backtracking.
    std::map<std::pair<size_t, size_t>, bool> memo;
    std::function<bool(size_t, size_t)> match = [&](size_t p, size_t s) {
        const auto key = std::pair{p, s};
        if (const auto it = memo.find(key); it != memo.end()) return it->second;
        bool result = false;
        if (p == pattern.size()) result = s == path.size();
        else if (pattern[p] == L'*') {
            const bool recursive = p + 1 < pattern.size() && pattern[p + 1] == L'*';
            const size_t next = p + (recursive ? 2 : 1);
            result = match(next, s) || (recursive && next < pattern.size() && pattern[next] == L'/' && match(next + 1, s)) ||
                     (s < path.size() && (recursive || path[s] != L'/') && match(p, s + 1));
        } else if (s < path.size() && pattern[p] == L'?') result = path[s] != L'/' && match(p + 1, s + 1);
        else if (s < path.size() && pattern[p] == L'[') {
            size_t end = pattern.find(L']', p + 1), at = p + 1;
            if (end == std::wstring::npos) fail("invalid file-operation glob character class");
            const bool negate = at < end && (pattern[at] == L'!' || pattern[at] == L'^');
            if (negate) ++at;
            bool selected = false;
            while (at < end) {
                if (at + 2 < end && pattern[at + 1] == L'-') {
                    selected |= pattern[at] <= path[s] && path[s] <= pattern[at + 2]; at += 3;
                } else selected |= pattern[at++] == path[s];
            }
            result = path[s] != L'/' && selected != negate && match(end + 1, s + 1);
        } else if (s < path.size()) result = pattern[p] == path[s] && match(p + 1, s + 1);
        memo.emplace(key, result); return result;
    };
    return match(0, 0);
}

class Session {
    Handle input_, output_, process_, job_;
    std::thread reader_, writer_;
    std::mutex writer_mutex_;
    std::timed_mutex sender_mutex_;
    mutable std::mutex registrations_mutex_;
    std::condition_variable writer_ready_;
    std::string outgoing_;
    bool writer_stopping_ = false, write_done_ = true, write_ok_ = true;
    std::mutex messages_mutex_;
    std::condition_variable messages_ready_;
    std::deque<J> messages_;
    std::string reader_error_;
    std::map<std::wstring, J, PathLess> published_diagnostics_;
    std::map<std::string, std::pair<std::string, J>> registrations_;
    int64_t next_id_ = 0;
    J capabilities_ = J::Object{};
    int sync_kind_ = 0;
    struct Document { std::string hash, uri; int64_t version; Position end; };
    std::map<std::wstring, Document, PathLess> documents_;

    bool read_exact(char* data, size_t size) {
        while (size) {
            DWORD got = 0;
            const DWORD chunk = static_cast<DWORD>(std::min<size_t>(size, 1u << 20));
            if (!ReadFile(output_.h, data, chunk, &got, nullptr) || !got) return false;
            data += got; size -= got;
        }
        return true;
    }
    void reader_loop() noexcept {
        try {
            for (;;) {
                std::string header;
                char c = 0;
                while (!header.ends_with("\r\n\r\n")) {
                    if (!read_exact(&c, 1)) fail("language server closed its output");
                    header.push_back(c);
                    if (header.size() > 16384) fail("invalid LSP framing header");
                }
                size_t length = 0;
                bool found = false;
                for (size_t p = 0; p < header.size();) {
                    const size_t end = header.find("\r\n", p);
                    const std::string line = header.substr(p, end - p);
                    if (lower(line).starts_with("content-length:")) {
                        if (found) fail("duplicate LSP Content-Length");
                        const std::string value = line.substr(15);
                        size_t consumed = 0;
                        const size_t first = value.find_first_not_of(" \t");
                        if (first == std::string::npos || value[first] < '0' || value[first] > '9') fail("invalid LSP Content-Length");
                        const unsigned long long parsed = std::stoull(value, &consumed);
                        if (parsed > std::numeric_limits<size_t>::max() ||
                            value.find_first_not_of(" \t", consumed) != std::string::npos) fail("invalid LSP Content-Length");
                        length = static_cast<size_t>(parsed); found = true;
                    }
                    if (end == std::string::npos) break;
                    p = end + 2;
                }
                if (!found) fail("missing LSP Content-Length");
                std::string payload(length, 0);
                if (!read_exact(payload.data(), payload.size())) fail("language server closed a partial response");
                J message = J::parse(payload);
                if (!message.get("id")) {
                    if (str(message, "method") == "textDocument/publishDiagnostics") {
                        if (const J* params = message.get("params")) {
                            std::lock_guard lock(messages_mutex_);
                            if (params->get("diagnostics")) {
                                try { published_diagnostics_[from_uri(str(*params, "uri")).lexically_normal().make_preferred().wstring()] = *params; }
                                catch (const std::exception&) { continue; }
                            }
                            messages_ready_.notify_all();
                        }
                    }
                    continue;
                }
                if (message.get("method")) {
                    const std::shared_ptr<std::atomic_bool> background;
                    const Control control{Clock::now() + std::chrono::seconds(30), background};
                    answer(message, control);
                    continue;
                }
                {
                    std::lock_guard lock(messages_mutex_);
                    messages_.push_back(std::move(message));
                }
                messages_ready_.notify_one();
            }
        } catch (const std::exception& e) {
            std::lock_guard lock(messages_mutex_);
            reader_error_ = e.what();
            messages_ready_.notify_all();
        }
    }
    void writer_loop() noexcept {
        for (;;) {
            std::string frame;
            {
                std::unique_lock lock(writer_mutex_);
                writer_ready_.wait(lock, [&] { return writer_stopping_ || !write_done_; });
                if (writer_stopping_) return;
                frame = std::move(outgoing_);
            }
            bool ok = true;
            for (size_t offset = 0; offset < frame.size();) {
                DWORD written = 0;
                const DWORD size = static_cast<DWORD>(std::min<size_t>(frame.size() - offset, 1u << 20));
                if (!WriteFile(input_.h, frame.data() + offset, size, &written, nullptr) || !written) { ok = false; break; }
                offset += written;
            }
            {
                std::lock_guard lock(writer_mutex_);
                write_ok_ = ok; write_done_ = true;
            }
            writer_ready_.notify_all();
        }
    }
    void send(J message, const Control& control) {
        control.check();
        std::unique_lock<std::timed_mutex> sender(sender_mutex_, std::defer_lock);
        while (!sender.try_lock_for(std::chrono::milliseconds(10))) control.check();
        control.check();
        const std::string payload = message.dump();
        std::unique_lock lock(writer_mutex_);
        if (writer_stopping_ || !write_done_) fail("invalid LSP writer state");
        outgoing_ = "Content-Length: " + std::to_string(payload.size()) + "\r\n\r\n" + payload;
        write_done_ = false; writer_ready_.notify_all();
        while (!write_done_) {
            writer_ready_.wait_for(lock, std::chrono::milliseconds(10));
            control.check();
        }
        if (!write_ok_) fail("cannot write to language server");
    }
    J setting(const std::string& section) const {
        J value = config.settings;
        size_t start = 0;
        while (start < section.size()) {
            const size_t end = section.find('.', start);
            const J* next = value.get(section.substr(start, end - start));
            if (!next) return nullptr;
            J copy = *next; value = std::move(copy);
            if (end == std::string::npos) break;
            start = end + 1;
        }
        return value;
    }
    void answer(const J& request, const Control& control) {
        const std::string method = str(request, "method");
        J result = nullptr;
        if (method == "workspace/configuration") {
            J::Array values;
            const J* params = request.get("params"), *items = params ? params->get("items") : nullptr;
            if (items) for (const auto& item : items->array()) values.push_back(setting(str(item, "section")));
            result = std::move(values);
        } else if (method == "workspace/workspaceFolders") {
            result = J::Array{J::Object{{"uri", uri(config.root)}, {"name", utf8(config.root.filename().wstring())}}};
        } else if (method == "workspace/applyEdit") {
            result = J::Object{{"applied", false}, {"failureReason", "unsolicited server edits require an explicit edit_file operation"}};
        } else if (method == "client/registerCapability" || method == "client/unregisterCapability") {
            std::lock_guard lock(registrations_mutex_);
            const J* params = request.get("params");
            const J* entries = params ? params->get(method == "client/registerCapability" ? "registrations" : "unregisterations") : nullptr;
            if (!entries && params) entries = params->get("unregistrations");
            if (entries) for (const auto& entry : entries->array()) {
                const std::string id = str(entry, "id");
                if (method == "client/registerCapability")
                    registrations_[id] = {str(entry, "method"), entry.get("registerOptions") ? *entry.get("registerOptions") : J(J::Object{})};
                else registrations_.erase(id);
            }
        } else if (method != "window/workDoneProgress/create" && !method.ends_with("/refresh")) {
            send(J::Object{{"jsonrpc", "2.0"}, {"id", *request.get("id")},
                 {"error", J::Object{{"code", -32601}, {"message", "unsupported client request"}}}}, control);
            return;
        }
        send(J::Object{{"jsonrpc", "2.0"}, {"id", *request.get("id")}, {"result", std::move(result)}}, control);
    }
public:
    Config config;
    std::timed_mutex mutex;
    explicit Session(Config value) : config(std::move(value)) {}
    ~Session() { stop(); }
    void stop() noexcept {
        if (job_.h) TerminateJobObject(job_.h, 0);
        else if (process_.h) TerminateProcess(process_.h, 0);
        {
            std::lock_guard lock(writer_mutex_);
            writer_stopping_ = true; write_done_ = true; write_ok_ = false;
        }
        writer_ready_.notify_all();
        if (writer_.joinable()) { CancelSynchronousIo(writer_.native_handle()); writer_.join(); }
        input_.reset();
        if (reader_.joinable()) { CancelSynchronousIo(reader_.native_handle()); reader_.join(); }
        output_.reset(); process_.reset(); job_.reset();
        documents_.clear();
        std::lock_guard lock(messages_mutex_);
        messages_.clear(); reader_error_.clear(); published_diagnostics_.clear();
        { std::lock_guard registrations_lock(registrations_mutex_); registrations_.clear(); }
        capabilities_ = J::Object{};
    }
    J request(const std::string& method, J params, const Control& control) {
        for (int attempt = 0;; ++attempt) {
            const int64_t id = ++next_id_;
            send(J::Object{{"jsonrpc", "2.0"}, {"id", id}, {"method", method}, {"params", params}}, control);
            for (;;) {
                control.check();
                J message;
                {
                    std::unique_lock lock(messages_mutex_);
                    if (messages_.empty()) {
                        if (!reader_error_.empty()) fail(reader_error_);
                        messages_ready_.wait_for(lock, std::chrono::milliseconds(10));
                        continue;
                    }
                    message = std::move(messages_.front()); messages_.pop_front();
                }
                if (message.get("method")) { answer(message, control); continue; }
                if (message.get("id")->dump() != J(id).dump()) continue;
                if (const J* error = message.get("error")) {
                    if (number(*error, "code", 0) == -32801 && attempt < 2) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(50 * (attempt + 1)));
                        control.check();
                        break;
                    }
                    fail("language server " + method + ": " + error->dump());
                }
                const J* result = message.get("result");
                if (!result) fail("invalid LSP response to " + method);
                return *result;
            }
        }
    }
    void notify(const std::string& method, J params, const Control& control) {
        send(J::Object{{"jsonrpc", "2.0"}, {"method", method}, {"params", std::move(params)}}, control);
    }
    void start(const Control& control) {
        if (process_.h) return;
        SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
        Handle child_input, child_output, child_error;
        HANDLE a = nullptr, b = nullptr;
        if (!CreatePipe(&a, &b, &security, 0)) fail("cannot create LSP stdin pipe");
        child_input.reset(a); input_.reset(b);
        if (!SetHandleInformation(input_.h, HANDLE_FLAG_INHERIT, 0)) fail("cannot isolate LSP stdin");
        if (!CreatePipe(&a, &b, &security, 0)) fail("cannot create LSP stdout pipe");
        output_.reset(a); child_output.reset(b);
        if (!SetHandleInformation(output_.h, HANDLE_FLAG_INHERIT, 0)) fail("cannot isolate LSP stdout");
        HANDLE stderr_copy = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_ERROR_HANDLE), GetCurrentProcess(),
                             &stderr_copy, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
            stderr_copy = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr);
            if (stderr_copy == INVALID_HANDLE_VALUE) fail("cannot prepare LSP stderr");
        }
        child_error.reset(stderr_copy);
        job_.reset(CreateJobObjectW(nullptr, nullptr));
        if (!job_.h) fail("cannot create LSP process job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job_.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) fail("cannot configure LSP process job");
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        std::vector<unsigned char> storage(bytes);
        auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) fail("cannot prepare LSP process attributes");
        HANDLE inherited[]{child_input.h, child_output.h, child_error.h};
        if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr)) {
            DeleteProcThreadAttributeList(attributes); fail("cannot isolate LSP child handles");
        }
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = child_input.h;
        startup.StartupInfo.hStdOutput = child_output.h;
        startup.StartupInfo.hStdError = child_error.h;
        startup.lpAttributeList = attributes;
        std::wstring command;
        for (const auto& part : config.command) {
            if (!command.empty()) command.push_back(L' ');
            command += quoted(wide(part));
        }
        PROCESS_INFORMATION process{};
        const BOOL created = CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, config.root.c_str(),
            &startup.StartupInfo, &process);
        const DWORD error = GetLastError();
        DeleteProcThreadAttributeList(attributes);
        if (!created) fail("cannot start LSP command (Windows error " + std::to_string(error) + ")");
        process_.reset(process.hProcess);
        Handle thread(process.hThread);
        if (!AssignProcessToJobObject(job_.h, process_.h)) {
            TerminateProcess(process_.h, 1); fail("cannot assign language server to its process job");
        }
        if (ResumeThread(thread.h) == static_cast<DWORD>(-1)) fail("cannot resume language server");
        child_input.reset(); child_output.reset(); child_error.reset();
        {
            std::lock_guard lock(writer_mutex_);
            writer_stopping_ = false; write_done_ = true; write_ok_ = true; outgoing_.clear();
        }
        reader_ = std::thread([this] { reader_loop(); });
        writer_ = std::thread([this] { writer_loop(); });
        J initialize = request("initialize", J::Object{
            {"processId", static_cast<int64_t>(GetCurrentProcessId())}, {"rootUri", uri(config.root)}, {"locale", "en"},
            {"clientInfo", J::Object{{"name", "shgrep"}, {"version", "0.3.0"}}},
            {"workspaceFolders", J::Array{J::Object{{"uri", uri(config.root)}, {"name", utf8(config.root.filename().wstring())}}}},
            {"initializationOptions", config.initialization},
            {"capabilities", J::Object{
                {"general", J::Object{{"positionEncodings", J::Array{"utf-16"}}}},
                {"workspace", J::Object{{"configuration", true}, {"workspaceFolders", true}, {"applyEdit", false},
                    {"workspaceEdit", J::Object{{"documentChanges", true}, {"failureHandling", "undo"}}},
                    {"fileOperations", J::Object{{"dynamicRegistration", true}, {"didCreate", true}, {"didRename", true}, {"willRename", true}}}}},
                {"textDocument", J::Object{
                    {"documentSymbol", J::Object{{"hierarchicalDocumentSymbolSupport", true}, {"dynamicRegistration", true}, {"symbolKind", J::Object{{"valueSet", J::Array{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26}}}}}},
                    {"definition", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
                    {"declaration", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
                    {"typeDefinition", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
                    {"implementation", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
                    {"rename", J::Object{{"prepareSupport", true}, {"dynamicRegistration", true}}},
                    {"references", J::Object{{"dynamicRegistration", true}}},
                    {"hover", J::Object{{"dynamicRegistration", true}, {"contentFormat", J::Array{"markdown", "plaintext"}}}},
                    {"publishDiagnostics", J::Object{{"versionSupport", true}, {"relatedInformation", true}}},
                    {"diagnostic", J::Object{{"dynamicRegistration", false}, {"relatedDocumentSupport", false}}},
                    {"synchronization", J::Object{{"dynamicRegistration", false}, {"didSave", true}}}
                }}
            }}
        }, control);
        const J* capabilities = initialize.get("capabilities");
        if (!capabilities) fail("language server initialize response has no capabilities");
        capabilities_ = *capabilities;
        if (str(capabilities_, "positionEncoding", "utf-16") != "utf-16") fail("language server did not negotiate UTF-16 positions");
        const J* sync = capabilities_.get("textDocumentSync");
        sync_kind_ = sync ? static_cast<int>(std::holds_alternative<int64_t>(sync->value) ? sync->integer() : number(*sync, "change", 0)) : 0;
        if (sync_kind_ != 1 && sync_kind_ != 2) fail("language server does not support live document synchronization");
        notify("initialized", J::Object{}, control);
        notify("workspace/didChangeConfiguration", J::Object{{"settings", config.settings}}, control);
    }
    void require(const char* capability) const {
        if (!supports(capability)) fail(std::string("language server lacks ") + capability);
    }
    static std::string capability_method(const std::string& capability) {
        static const std::map<std::string, std::string> names{
            {"documentSymbolProvider","textDocument/documentSymbol"}, {"definitionProvider","textDocument/definition"},
            {"declarationProvider","textDocument/declaration"}, {"typeDefinitionProvider","textDocument/typeDefinition"},
            {"implementationProvider","textDocument/implementation"}, {"referencesProvider","textDocument/references"},
            {"hoverProvider","textDocument/hover"}, {"renameProvider","textDocument/rename"},
            {"diagnosticProvider","textDocument/diagnostic"}};
        auto it = names.find(capability); return it == names.end() ? capability : it->second;
    }
    bool supports(const char* capability) const {
        const J* p = capabilities_.get(capability);
        if (p && (std::holds_alternative<J::Object>(p->value) || (std::holds_alternative<bool>(p->value) && p->boolean()))) return true;
        const std::string method = capability_method(capability);
        std::lock_guard lock(registrations_mutex_);
        for (const auto& [id, entry] : registrations_) { (void)id; if (entry.first == method) return true; }
        return false;
    }
    void service_pending(const Control& control) {
        for (;;) {
            J message;
            {
                std::lock_guard lock(messages_mutex_);
                if (messages_.empty()) return;
                message = std::move(messages_.front()); messages_.pop_front();
            }
            if (message.get("method")) answer(message, control);
        }
    }
    bool file_operation(const std::string& name, const fs::path& path, bool directory = false) const {
        std::vector<J> options;
        const J* workspace = capabilities_.get("workspace");
        const J* operations = workspace ? workspace->get("fileOperations") : nullptr;
        if (const J* configured = operations ? operations->get(name) : nullptr) options.push_back(*configured);
        {
            std::lock_guard lock(registrations_mutex_);
            for (const auto& [id, entry] : registrations_) { (void)id;
                if (entry.first == "workspace/" + name + "Files") options.push_back(entry.second);
            }
        }
        for (const auto& option : options) {
            const J* filters = option.get("filters");
            if (!filters) continue;
            for (const auto& filter : filters->array()) {
                if (!str(filter, "scheme").empty() && str(filter, "scheme") != "file") continue;
                const J* pattern = filter.get("pattern");
                if (!pattern) continue;
                const std::string kind = str(*pattern, "matches");
                if ((kind == "file" && directory) || (kind == "folder" && !directory)) continue;
                const J* settings = pattern->get("options");
                if (file_glob(wide(str(*pattern, "glob")), path.wstring(), settings && flag(*settings, "ignoreCase"))) return true;
            }
        }
        return false;
    }
    bool prepare_rename() const {
        const J* rename = capabilities_.get("renameProvider");
        return rename && std::holds_alternative<J::Object>(rename->value) && flag(*rename, "prepareProvider");
    }
    J status() const {
        std::lock_guard lock(registrations_mutex_);
        J::Array dynamic;
        for (const auto& [id, entry] : registrations_) { (void)id; dynamic.push_back(entry.first); }
        return J::Object{{"language_id", config.language}, {"root", utf8(config.root.wstring())},
                         {"capabilities", capabilities_}, {"dynamic_methods", std::move(dynamic)},
                         {"open_documents", static_cast<int64_t>(documents_.size())}};
    }
    int64_t document_version(const SourceText& source) const {
        const auto it = documents_.find(source.path.wstring());
        if (it == documents_.end()) fail("workspace edit targets a file that was not synchronized before the request");
        return it->second.version;
    }
    J diagnostics(const SourceText& source, const Control& control) {
        service_pending(control);
        const std::string id = document_uri(source);
        if (supports("diagnosticProvider")) {
            J::Object params{{"textDocument", J::Object{{"uri", id}}}};
            if (const J* provider = capabilities_.get("diagnosticProvider"))
                if (std::holds_alternative<J::Object>(provider->value))
                    if (const J* identifier = provider->get("identifier")) params.emplace("identifier", *identifier);
            J result = request("textDocument/diagnostic", std::move(params), control);
            if (str(result, "kind") != "full" || !result.get("items")) fail("expected a full diagnostic report");
            return J::Object{{"items", *result.get("items")}, {"version_verified", true}, {"transport", "pull"}};
        }
        for (;;) {
            control.check();
            {
                std::unique_lock lock(messages_mutex_);
                auto found = published_diagnostics_.find(source.path.lexically_normal().make_preferred().wstring());
                if (found != published_diagnostics_.end()) {
                    const J* version = found->second.get("version");
                    if (!version || (std::holds_alternative<int64_t>(version->value) && version->integer() == document_version(source)))
                        return J::Object{{"items", *found->second.get("diagnostics")},
                            {"version_verified", version != nullptr}, {"transport", "publish"}};
                }
                if (!reader_error_.empty()) fail(reader_error_);
                messages_ready_.wait_for(lock, std::chrono::milliseconds(10));
            }
            service_pending(control);
        }
    }
    void saved(const SourceText& source, const Control& control) {
        const J* sync = capabilities_.get("textDocumentSync");
        const J* save = sync && std::holds_alternative<J::Object>(sync->value) ? sync->get("save") : nullptr;
        if (!save || (std::holds_alternative<bool>(save->value) && !save->boolean())) return;
        J::Object params{{"textDocument", J::Object{{"uri", document_uri(source)}}}};
        if (std::holds_alternative<J::Object>(save->value) && flag(*save, "includeText")) params.emplace("text", source.text);
        notify("textDocument/didSave", std::move(params), control);
    }
    int sync_one(const SourceText& source, const Control& control) {
        const std::string id = uri(source.path);
        const std::wstring key = source.path.wstring();
        auto found = documents_.find(key);
        if (found == documents_.end()) {
            {
                std::lock_guard lock(messages_mutex_);
                published_diagnostics_.erase(source.path.lexically_normal().make_preferred().wstring());
            }
            notify("textDocument/didOpen", J::Object{{"textDocument", J::Object{
                {"uri", id}, {"languageId", config.language}, {"version", 1}, {"text", source.text}}}}, control);
            documents_.emplace(key, Document{source.sha256, id, 1, text_end(source.text)});
            return 1;
        }
        if (found->second.hash == source.sha256) return 0;
        {
            std::lock_guard lock(messages_mutex_);
            published_diagnostics_.erase(source.path.lexically_normal().make_preferred().wstring());
        }
        J::Object change{{"text", source.text}};
        if (sync_kind_ == 2) change.emplace("range", J::Object{{"start", Position{}.json()}, {"end", found->second.end.json()}});
        notify("textDocument/didChange", J::Object{
            {"textDocument", J::Object{{"uri", found->second.uri}, {"version", ++found->second.version}}},
            {"contentChanges", J::Array{std::move(change)}}}, control);
        found->second.hash = source.sha256;
        found->second.end = text_end(source.text);
        return 2;
    }
    void synchronize(const SourceText* primary, const SearchContext& context, const Control& control, bool save = false) {
        std::vector<std::string> paths = source_paths(context, utf8(config.root.wstring()), config.extensions, control.deadline, control.cancelled);
        paths.erase(std::remove_if(paths.begin(), paths.end(), [&](const auto& path) {
            return path_excluded(config, fs::path(wide(path)));
        }), paths.end());
        if (primary) paths.push_back(utf8(primary->path.wstring()));
        std::set<std::wstring, PathLess> seen;
        J::Array changes;
        for (const auto& path : paths) {
            control.check();
            SourceText source;
            try { source = read_source_text(context, path); }
            catch (const std::exception& e) {
                if (std::string(e.what()).ends_with(" is not valid Unicode source text")) continue;
                throw;
            }
            const std::string id = uri(source.path);
            if (!seen.insert(source.path.wstring()).second) continue;
            const int type = sync_one(source, control);
            if (type) {
                changes.push_back(J::Object{{"uri", id}, {"type", type}});
                if (save) saved(source, control);
                if (save && type == 1 && file_operation("didCreate", source.path))
                    notify("workspace/didCreateFiles", J::Object{{"files", J::Array{J::Object{{"uri", id}}}}}, control);
            }
        }
        for (auto it = documents_.begin(); it != documents_.end();) {
            if (seen.contains(it->first)) { ++it; continue; }
            if (path_excluded(config, fs::path(it->first))) {
                notify("textDocument/didClose", J::Object{{"textDocument", J::Object{{"uri", it->second.uri}}}}, control);
                { std::lock_guard lock(messages_mutex_); published_diagnostics_.erase(it->first); }
                it = documents_.erase(it);
                continue;
            }
            // Explicitly opened hidden/ignored files still exist outside the default walk selection.
            std::optional<SourceText> existing;
            bool removed = false;
            try { existing = read_source_text(context, utf8(it->first)); }
            catch (const std::exception& e) {
                const std::string message = e.what();
                if (message.ends_with(" is not valid Unicode source text")) {
                    // Close an older valid snapshot without telling the server the file was deleted.
                } else if (message.find(": not found") != std::string::npos) {
                    removed = true;
                } else throw;
            }
            if (existing) {
                const int type = sync_one(*existing, control);
                if (type) { changes.push_back(J::Object{{"uri", it->second.uri}, {"type", type}}); if (save) saved(*existing, control); }
                ++it;
                continue;
            }
            notify("textDocument/didClose", J::Object{{"textDocument", J::Object{{"uri", it->second.uri}}}}, control);
            if (removed) changes.push_back(J::Object{{"uri", it->second.uri}, {"type", 3}});
            { std::lock_guard lock(messages_mutex_); published_diagnostics_.erase(it->first); }
            it = documents_.erase(it);
        }
        if (!changes.empty()) notify("workspace/didChangeWatchedFiles", J::Object{{"changes", std::move(changes)}}, control);
    }
    std::string document_uri(const SourceText& source) const {
        const auto it = documents_.find(source.path.wstring());
        if (it == documents_.end()) fail("file has not been synchronized with the language server");
        return it->second.uri;
    }
    bool has_document(const SourceText& source) const {
        const auto it = documents_.find(source.path.wstring());
        return it != documents_.end() && it->second.hash == source.sha256;
    }
    void assert_current(const SourceText& source) const {
        if (!has_document(source)) fail("source changed during LSP navigation; retry the request");
    }
};
std::mutex registry_mutex;
std::map<std::string, std::shared_ptr<Session>> registry;
std::shared_ptr<Session> session_for(const Config& config) {
    std::lock_guard lock(registry_mutex);
    auto it = registry.find(config.key);
    if (it != registry.end()) return it->second;
    // Retire superseded configuration for the same workspace/language once no query holds it.
    for (auto i = registry.begin(); i != registry.end();) {
        if (i->second.use_count() == 1 && i->second->config.root == config.root && i->second->config.language == config.language)
            i = registry.erase(i);
        else ++i;
    }
    auto session = std::make_shared<Session>(config);
    registry.emplace(config.key, session); return session;
}

struct Symbol {
    std::string name, name_path;
    int64_t kind;
    Range extent, selection;
    int depth;
    bool has_body;
};
std::string normalized_name(const J& item, const std::string& language) {
    std::string name = str(item, "name");
    // SolidLSP's Lua adapter normalizes qualified method/function names at each tree level.
    if (language == "lua" && (number(item, "kind", 0) == 6 || number(item, "kind", 0) == 12)) {
        size_t separator = name.rfind('.');
        if (separator == std::string::npos) separator = name.rfind(':');
        if (separator != std::string::npos) name.erase(0, separator + 1);
    }
    return name;
}
void flatten(const J& items, const std::string& parent, int depth, std::vector<Symbol>& result, const std::string& language) {
    if (std::holds_alternative<std::nullptr_t>(items.value)) return;
    // SolidLSP ls.py: sibling overloads receive stable, zero-based indices.
    std::map<std::string, size_t> totals, indices;
    for (const auto& item : items.array()) ++totals[str(item, "containerName") + "\n" + normalized_name(item, language)];
    for (const auto& item : items.array()) {
        const std::string name = normalized_name(item, language);
        const std::string sibling_key = str(item, "containerName") + "\n" + name;
        const size_t overload = indices[sibling_key]++;
        const std::string component = totals[sibling_key] > 1 ? name + "[" + std::to_string(overload) + "]" : name;
        const J* extent = item.get("range"), *selection = item.get("selectionRange");
        const bool hierarchical = extent && selection;
        if (!extent) {
            const J* location = item.get("location");
            extent = location ? location->get("range") : nullptr;
        }
        if (!extent) continue;
        const std::string prefix = hierarchical ? parent : str(item, "containerName");
        Symbol symbol{name, prefix.empty() ? component : prefix + "/" + component,
                      number(item, "kind", 0), range(*extent),
                      range(selection ? *selection : *extent), depth, hierarchical};
        if (symbol.selection.start < symbol.extent.start || symbol.extent.end < symbol.selection.end)
            fail("language server returned a selection outside its symbol range");
        result.push_back(symbol);
        if (const J* children = item.get("children")) flatten(*children, symbol.name_path, depth + 1, result, language);
    }
}
std::vector<Symbol> symbols(Session& session, const SourceText& source, const Control& control) {
    session.require("documentSymbolProvider");
    const J raw = session.request("textDocument/documentSymbol",
        J::Object{{"textDocument", J::Object{{"uri", session.document_uri(source)}}}}, control);
    std::vector<Symbol> result; flatten(raw, "", 0, result, session.config.language); return result;
}
bool matches(const Symbol& symbol, std::string pattern, bool substring) {
    if (pattern.empty()) return true;
    const bool anchored = pattern.starts_with("/");
    if (anchored) pattern.erase(0, 1);
    while (pattern.ends_with("/")) pattern.pop_back();
    auto split = [](const std::string& value) {
        std::vector<std::string> parts; size_t start = 0;
        for (;;) {
            const size_t end = value.find('/', start);
            parts.push_back(value.substr(start, end - start));
            if (end == std::string::npos) break;
            start = end + 1;
        }
        return parts;
    };
    const auto wanted = split(pattern), actual = split(symbol.name_path);
    if (wanted.size() > actual.size() || (anchored && wanted.size() != actual.size())) return false;
    auto indexed = [](const std::string& name) {
        const size_t bracket = name.rfind('[');
        return bracket != std::string::npos && name.ends_with("]") && bracket + 2 < name.size() &&
            name.find_first_not_of("0123456789", bracket + 1) == name.size() - 1;
    };
    for (size_t i = 0; i < wanted.size(); ++i) {
        std::string name = actual[actual.size() - wanted.size() + i];
        const std::string& part = wanted[i];
        if (!indexed(part) && indexed(name)) name.erase(name.rfind('['));
        if (substring && i + 1 == wanted.size()) {
            if (name.find(part) == std::string::npos) return false;
        } else if (name != part) return false;
    }
    return true;
}
std::string shown_path(const SourceText& source) {
    return utf8(source.path.lexically_relative(source.root).generic_wstring());
}
J coordinates(Range r) {
    return J::Object{{"start_line", r.start.line + 1}, {"start_column", r.start.column + 1},
                     {"end_line", r.end.line + 1}, {"end_column", r.end.column + 1}};
}
J symbol_json(const Symbol& symbol, const SourceText& source, bool include_body) {
    J::Object out{{"path", shown_path(source)}, {"name", symbol.name}, {"name_path", symbol.name_path}, {"kind", symbol.kind},
                   {"line", symbol.selection.start.line + 1}, {"column", symbol.selection.start.column + 1},
                   {"range", coordinates(symbol.extent)}, {"selection_range", coordinates(symbol.selection)}, {"body_available", symbol.has_body}};
    if (include_body) {
        if (!symbol.has_body) fail("language server returned flat SymbolInformation without a reliable symbol-body range");
        out.emplace("body", body(source, symbol.extent));
    }
    return out;
}
const Symbol& unique(const std::vector<Symbol>& symbols, const std::string& name) {
    const Symbol* exact = nullptr;
    const std::string anchored = name.starts_with("/") ? name.substr(1) : name;
    size_t exact_count = 0;
    for (const auto& symbol : symbols) if (symbol.name_path == anchored) { exact = &symbol; ++exact_count; }
    if (exact_count == 1) return *exact;
    const Symbol* found = nullptr;
    for (const auto& symbol : symbols) if (matches(symbol, name, false)) {
        if (found) fail("ambiguous symbol name_path; use its full path or a line/column position");
        found = &symbol;
    }
    if (!found) fail("no symbol matches " + name);
    return *found;
}
J query_file(const std::string& operation, const J& args, const SourceText& original,
             const Config& config, const SearchContext& context, const Control& control,
             std::set<std::string>& synchronized) {
    auto session = session_for(config);
    std::unique_lock<std::timed_mutex> lock(session->mutex, std::defer_lock);
    while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
    try {
        session->start(control);
        if (synchronized.insert(config.key).second) session->synchronize(&original, context, control);
        else session->sync_one(original, control);
        session->service_pending(control);
        const SourceText source = read_source_text(context, utf8(original.path.wstring()));
        session->assert_current(source);
        const std::string pattern = str(args, "name_path", str(args, "pattern"));
        J::Array results;
        int64_t outside = 0, stale = 0, ignored = 0;
        if (operation == "status" || operation == "restart") {
            if (operation == "restart") { session->stop(); session->start(control); session->synchronize(&source, context, control); }
            return session->status();
        }
        if (operation == "diagnostics") {
            J::Object report = session->diagnostics(source, control).object();
            std::optional<Range> within;
            if (!pattern.empty()) within = unique(symbols(*session, source, control), pattern).extent;
            const int64_t severity = number(args, "severity", 4);
            if (severity < 1 || severity > 4) fail("severity must be 1-4");
            J::Array items;
            for (const auto& item : report.at("items").array()) {
                const J* extent = item.get("range"); if (!extent) fail("diagnostic has no range");
                const Range r = range(*extent);
                if (number(item, "severity", 1) > severity) continue;
                if (within && (r.end < within->start || within->end < r.start)) continue;
                J::Object normalized = item.object(); normalized["range"] = coordinates(r);
                if (const J* related = item.get("relatedInformation")) {
                    J::Array information;
                    for (const auto& entry : related->array()) {
                        J::Object result = entry.object();
                        if (const J* location = entry.get("location")) {
                            J::Object converted = location->object();
                            const J* extent = location->get("range"); if (!extent) fail("related diagnostic has no range");
                            converted["range"] = coordinates(range(*extent));
                            result["location"] = std::move(converted);
                        }
                        information.push_back(std::move(result));
                    }
                    normalized["relatedInformation"] = std::move(information);
                }
                items.push_back(std::move(normalized));
            }
            report["items"] = std::move(items);
            if (read_source_text(context, utf8(source.path.wstring())).sha256 != source.sha256) fail("file changed during diagnostics; retry");
            report.emplace("path", shown_path(source)); report.emplace("sha256", source.sha256);
            report.emplace("coordinate_base", 1); report.emplace("position_encoding", "utf-16");
            return report;
        }
        if (operation == "symbols" || operation == "overview") {
            const auto found = symbols(*session, source, control);
            const int64_t depth = number(args, "depth", 0);
            if (depth < -1) fail("depth must be -1 or greater");
            if (flag(args, "require_unique")) {
                results.push_back(symbol_json(unique(found, pattern), source, flag(args, "include_body")));
            } else {
                std::vector<std::string> patterns{pattern};
                if (const J* list = args.get("patterns")) {
                    patterns.clear();
                    for (const auto& item : list->array()) patterns.push_back(item.string());
                    if (patterns.empty()) fail("patterns must not be empty");
                }
                auto kinds_match = [&](const Symbol& symbol) {
                    bool include = true;
                    for (const char* key : {"include_kinds", "exclude_kinds"}) if (const J* values = args.get(key)) {
                        bool present = false;
                        for (const auto& value : values->array()) {
                            if (value.integer() < 1 || value.integer() > 26) fail("symbol kinds must be 1-26");
                            present |= value.integer() == symbol.kind;
                        }
                        if (std::string(key) == "include_kinds" && !values->array().empty()) include &= present;
                        if (std::string(key) == "exclude_kinds") include &= !present;
                    }
                    return include;
                };
                std::set<std::string> emitted;
                for (const auto& symbol : found) {
                    if (operation == "overview" && depth >= 0 && symbol.depth > depth) continue;
                    bool matched = false;
                    for (const auto& p : patterns) matched |= matches(symbol, p, flag(args, "substring_matching"));
                    if (!matched || !kinds_match(symbol)) continue;
                    auto emit = [&](const Symbol& item, bool primary) {
                        if (!emitted.insert(item.name_path).second) return;
                        J::Object result = symbol_json(item, source, primary && flag(args, "include_body")).object();
                        if (primary && flag(args, "include_info") && !flag(args, "include_body")) {
                            session->require("hoverProvider");
                            const J info = session->request("textDocument/hover", J::Object{
                                {"textDocument", J::Object{{"uri", session->document_uri(source)}}}, {"position", item.selection.start.json()}}, control);
                            result.emplace("info", info);
                        }
                        results.push_back(std::move(result));
                    };
                    emit(symbol, true);
                    if (operation == "symbols" && !flag(args, "include_body") && depth != 0)
                        for (const auto& child : found)
                            if (child.name_path.starts_with(symbol.name_path + "/") && kinds_match(child) &&
                                (depth < 0 || child.depth <= symbol.depth + depth)) emit(child, false);
                }
            }
        } else {
            Position at;
            if (!pattern.empty()) {
                const auto found = symbols(*session, source, control);
                at = unique(found, pattern).selection.start;
            } else {
                const int64_t line = number(args, "line", 0), column = number(args, "column", 0);
                if (line < 1 || column < 1 || line > INT32_MAX || column > INT32_MAX)
                    fail("navigation needs name_path or 1-based line and column (1-2147483647)");
                at = {line - 1, column - 1};
                offset(wide(source.text), at);
            }
            const bool references = operation == "references";
            static const std::map<std::string, std::pair<const char*, const char*>> operations{
                {"definition", {"definitionProvider", "textDocument/definition"}},
                {"declaration", {"declarationProvider", "textDocument/declaration"}},
                {"type_definition", {"typeDefinitionProvider", "textDocument/typeDefinition"}},
                {"implementation", {"implementationProvider", "textDocument/implementation"}},
                {"references", {"referencesProvider", "textDocument/references"}},
                {"hover", {"hoverProvider", "textDocument/hover"}}};
            const auto method = operations.find(operation);
            if (method == operations.end()) fail("unknown LSP navigation operation");
            session->require(method->second.first);
            J::Object params{{"textDocument", J::Object{{"uri", session->document_uri(source)}}}, {"position", at.json()}};
            if (references) params.emplace("context", J::Object{{"includeDeclaration", flag(args, "include_declaration")}});
            J raw = session->request(method->second.second, std::move(params), control);
            if (operation == "hover") {
                if (read_source_text(context, utf8(source.path.wstring())).sha256 != source.sha256) fail("file changed during hover; retry");
                return J::Object{{"path", shown_path(source)}, {"sha256", source.sha256}, {"hover", raw}, {"backend", "lsp"}};
            }
            J::Array locations;
            if (std::holds_alternative<J::Array>(raw.value)) locations = raw.array();
            else if (!std::holds_alternative<std::nullptr_t>(raw.value)) locations.push_back(raw);
            std::map<std::wstring, std::set<std::string>, PathLess> dedup;
            std::map<std::wstring, std::vector<Symbol>, PathLess> owners;
            for (const auto& location : locations) {
                control.check();
                const bool link = location.get("targetUri") != nullptr;
                const std::string id = str(location, link ? "targetUri" : "uri");
                const J* raw_range = location.get(link ? "targetSelectionRange" : "range");
                if (!raw_range) fail("language server returned a location without a range");
                const Range found = range(*raw_range);
                SourceText target;
                try {
                    const fs::path target_path = from_uri(id);
                    if (path_excluded(config, target_path)) { ++ignored; continue; }
                    target = read_source_text(context, utf8(target_path.wstring()));
                }
                catch (const std::exception& e) {
                    const std::string message = e.what();
                    if (message.find("outside the configured roots") != std::string::npos ||
                        message.find("non-file URI") != std::string::npos) { ++outside; continue; }
                    if (message.find(": not found") != std::string::npos ||
                        message.ends_with(" is not valid Unicode source text")) { ++stale; continue; }
                    throw;
                }
                if (!dedup[target.path.wstring()].insert(raw_range->dump()).second) continue;
                // Other configured languages are readable, but their bodies are never taken from an old server buffer.
                const auto target_config = configuration(target, context);
                if (target_config && path_excluded(*target_config, target.path)) { ++ignored; continue; }
                if (target_config && target_config->key == config.key && !session->has_document(target)) {
                    ++ignored;
                    continue;
                }
                if (target_config && target_config->key == config.key) session->assert_current(target);
                offset(wide(target.text), found.start);
                offset(wide(target.text), found.end);
                J::Object result{{"path", shown_path(target)}, {"line", found.start.line + 1},
                                  {"column", found.start.column + 1}, {"range", coordinates(found)}};
                if (references) result.emplace("reference_name", body(target, Range{found.start, found.end}));
                if (session->supports("documentSymbolProvider") && target_config && target_config->key == config.key) {
                    auto owner = owners.find(target.path.wstring());
                    if (owner == owners.end()) owner = owners.emplace(target.path.wstring(), symbols(*session, target, control)).first;
                    const Symbol* enclosing = nullptr;
                    auto container_kind = [](int64_t kind) {
                        return kind == 1 || kind == 2 || kind == 3 || kind == 4 || kind == 5 || kind == 6 ||
                               kind == 9 || kind == 10 || kind == 11 || kind == 12 || kind == 19 || kind == 23;
                    };
                    for (const auto& symbol : owner->second) {
                        const bool variable = symbol.kind == 13 || symbol.kind == 14;
                        const bool multiline_container = container_kind(symbol.kind) &&
                            symbol.extent.start.line != symbol.extent.end.line;
                        if (!(variable || multiline_container) ||
                            symbol.extent.start > found.start || found.end > symbol.extent.end) continue;
                        if (!enclosing || enclosing->extent.start < symbol.extent.start ||
                            (enclosing->extent.start == symbol.extent.start && enclosing->depth < symbol.depth))
                            enclosing = &symbol;
                    }
                    if (enclosing) {
                        result.emplace("symbol", enclosing->name_path);
                        if (flag(args, "include_body") && enclosing->has_body) result.emplace("body", body(target, enclosing->extent));
                    }
                }
                results.push_back(std::move(result));
                if (read_source_text(context, utf8(target.path.wstring())).sha256 != target.sha256)
                    fail("navigation target changed during the request; retry");
            }
        }
        if (read_source_text(context, utf8(source.path.wstring())).sha256 != source.sha256)
            fail("source changed during LSP navigation; retry");
        return J::Object{{"path", shown_path(source)}, {"sha256", source.sha256}, {"mtime", source.mtime}, {"results", std::move(results)},
                          {"outside_roots", outside}, {"stale_locations", stale}, {"ignored_locations", ignored}, {"backend", "lsp"}};
    } catch (...) {
        session->stop();
        throw;
    }
}
} // namespace

std::shared_timed_mutex& workspace_operation_mutex() {
    static std::shared_timed_mutex mutex;
    return mutex;
}

bool lsp_configured(const SourceText& source, const SearchContext& context) {
    return configuration(source, context).has_value();
}

Json lsp_query(const std::string& operation, const Json& arguments, const SearchContext& context,
               const std::shared_ptr<std::atomic_bool>& cancelled) {
    const int64_t timeout = number(arguments, "timeout_ms", 30000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{Clock::now() + std::chrono::milliseconds(timeout), cancelled};
    std::set<std::string> synchronized;
    const bool symbol_query = operation == "symbols" || operation == "overview";
    if (operation == "files")
        for (const char* key : {"name_path", "pattern", "patterns", "substring_matching", "include_kinds", "exclude_kinds"})
            if (arguments.get(key)) fail(std::string(key) + " requires operation=symbols");
    if (!symbol_query)
        for (const char* key : {"depth", "include_info", "include_kinds", "exclude_kinds", "substring_matching"})
            if (arguments.get(key)) fail(std::string(key) + " is only for symbol lookup");
    if (symbol_query && (arguments.get("line") || arguments.get("column"))) fail("line/column requires a navigation operation");
    if (operation != "references" && arguments.get("include_declaration")) fail("include_declaration requires references");
    if (operation == "hover" && arguments.get("include_body")) fail("hover does not accept include_body");
    const bool named = arguments.get("name_path") || arguments.get("pattern");
    if ((arguments.get("name_path") && arguments.get("pattern")) || (arguments.get("patterns") && named))
        fail("give name_path, pattern, or patterns, not several");
    if (operation != "symbols" && arguments.get("patterns")) fail("patterns is only supported for symbol search");
    if (operation != "symbols" && operation != "overview" && named &&
        (arguments.get("line") || arguments.get("column"))) fail("give a symbol name or line/column, not both");
    const std::string path = str(arguments, "path");
    std::optional<SourceText> scope;
    if (!path.empty()) {
        bool directory = false;
        scope = source_descriptor(context, path, &directory);
        if (!directory && operation == "files") {
            const auto config = configuration(*scope, context);
            J::Array files;
            if (config) files.push_back(J::Object{{"path", shown_path(*scope)}, {"root", utf8(scope->root.wstring())}, {"language_id", config->language}});
            return J::Object{{"results", std::move(files)}, {"backend", "lsp"}};
        }
        if (!directory) {
            const SourceText source = read_source_text(context, path);
            const auto config = configuration(source, context);
            if (!config) fail("no LSP server configured for this file in .shgrep/lsp.json; use operation: text");
            return query_file(operation, arguments, source, *config, context, control, synchronized);
        }
    }
    if (operation != "symbols" && operation != "overview" && operation != "files" && operation != "status" && operation != "restart")
        fail("this navigation operation requires a file path");
    auto below = [](const fs::path& child, const fs::path& parent) {
        std::wstring prefix = parent.wstring();
        if (!prefix.ends_with(L"\\") && !prefix.ends_with(L"/")) prefix += L"\\";
        const std::wstring candidate = child.wstring();
        return candidate.size() >= prefix.size() &&
            CompareStringOrdinal(candidate.data(), static_cast<int>(prefix.size()), prefix.data(), static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL;
    };
    J::Array results;
    std::set<std::wstring, PathLess> scanned;
    for (const auto& root : context.allowed_roots) {
        const fs::path absolute = fs::absolute(root).lexically_normal();
        if (scope && !below(scope->path, absolute) && !below(absolute, scope->path) &&
            PathLess{}(scope->path.wstring(), absolute.wstring()) != PathLess{}(absolute.wstring(), scope->path.wstring())) continue;
        const auto configured = configs(absolute, context);
        if (operation == "status" || operation == "restart") {
            for (const auto& config : configured) {
                auto session = session_for(config);
                std::unique_lock<std::timed_mutex> lock(session->mutex, std::defer_lock);
                while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
                try {
                    if (operation == "restart") session->stop();
                    session->start(control);
                    session->synchronize(nullptr, context, control);
                    session->service_pending(control);
                    results.push_back(session->status());
                    synchronized.insert(config.key);
                } catch (...) { session->stop(); throw; }
            }
            continue;
        }
        std::vector<std::string> extensions;
        for (const auto& config : configured)
            extensions.insert(extensions.end(), config.extensions.begin(), config.extensions.end());
        if (extensions.empty()) continue;
        const auto paths = source_paths(context, utf8(absolute.wstring()), extensions, control.deadline, cancelled);
        for (const auto& file : paths) {
            control.check();
            SourceText source = operation == "files" ? source_descriptor(context, file) : read_source_text(context, file);
            if (scope && !below(source.path, scope->path) &&
                (PathLess{}(source.path.wstring(), scope->path.wstring()) || PathLess{}(scope->path.wstring(), source.path.wstring()))) continue;
            if (!scanned.insert(source.path.wstring()).second) continue;
            const auto config = configuration(source, context);
            if (!config || path_excluded(*config, source.path)) continue;
            if (operation == "files") {
                results.push_back(J::Object{{"path", shown_path(source)}, {"root", utf8(source.root.wstring())}, {"language_id", config->language}});
                continue;
            }
            J::Object per_file = arguments.object();
            per_file["path"] = file;
            const J response = query_file(operation, per_file, source, *config, context, control, synchronized);
            for (const auto& symbol : response.get("results")->array()) {
                J::Object item = symbol.object();
                item.emplace("root", utf8(absolute.wstring()));
                results.push_back(std::move(item));
            }
        }
    }
    if (operation != "files" && synchronized.empty() && !scope) fail("no LSP source files found; configure .shgrep/lsp.json or use operation: text");
    return J::Object{{"results", std::move(results)}, {"backend", "lsp"}};
}

namespace {
std::unique_lock<std::timed_mutex> acquire(Session& session, const Control& control) {
    std::unique_lock<std::timed_mutex> lock(session.mutex, std::defer_lock);
    while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
    return lock;
}
std::string newlines(const std::string& text, const std::string& reference) {
    const bool crlf = reference.find("\r\n") != std::string::npos;
    std::string out;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\r' || text[i] == '\n') {
            if (text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n') ++i;
            out += crlf ? "\r\n" : "\n";
        } else out.push_back(text[i]);
    }
    return out;
}
std::vector<SourceChange> workspace_changes(Session& session, const J& edit, const Config& config,
                                           const SearchContext& context, const Control& control) {
    if (std::holds_alternative<std::nullptr_t>(edit.value)) fail("language server returned no workspace edit");
    if (edit.get("changes") && edit.get("documentChanges")) fail("ambiguous workspace edit: changes and documentChanges");
    if (const J* annotations = edit.get("changeAnnotations"))
        for (const auto& [id, annotation] : annotations->object()) {
            (void)id;
            if (flag(annotation, "needsConfirmation")) fail("workspace edit requires an unsupported change confirmation; nothing written");
        }
    struct Entry { SourceText source; std::vector<J> edits; };
    std::map<std::wstring, Entry, PathLess> entries;
    auto add = [&](const std::string& id, const J& edits, const J* version) {
        control.check();
        const fs::path path = from_uri(id);
        if (path_excluded(config, path))
            fail("language server workspace edit targets ignored_paths; nothing written");
        SourceText source = read_source_text(context, utf8(path.wstring()));
        session.assert_current(source);
        if (version && !std::holds_alternative<std::nullptr_t>(version->value) &&
            version->integer() != session.document_version(source)) fail("stale workspace edit document version");
        auto [it, inserted] = entries.try_emplace(source.path.wstring(), Entry{source, {}});
        if (!inserted && it->second.source.sha256 != source.sha256) fail("workspace edit source changed during planning");
        for (const auto& item : edits.array()) it->second.edits.push_back(item);
    };
    if (const J* changes = edit.get("changes"))
        for (const auto& [id, edits] : changes->object()) add(id, edits, nullptr);
    if (const J* changes = edit.get("documentChanges"))
        for (const auto& change : changes->array()) {
            if (change.get("kind")) fail("workspace edit contains a file resource operation; use move_file for file moves; nothing written");
            const J* document = change.get("textDocument"), *edits = change.get("edits");
            if (!document || !edits) fail("invalid TextDocumentEdit");
            add(str(*document, "uri"), *edits, document->get("version"));
        }
    std::vector<SourceChange> result;
    for (auto& [path, entry] : entries) {
        (void)path; control.check();
        struct Replacement { size_t start, end, order; std::wstring text; };
        std::vector<Replacement> replacements;
        std::wstring text = wide(entry.source.text);
        for (const auto& item : entry.edits) {
            const J* extent = item.get("range"), *replacement = item.get("newText");
            if (!extent || !replacement) fail("invalid LSP TextEdit");
            const Range r = range(*extent);
            replacements.push_back({offset(text, r.start), offset(text, r.end), replacements.size(),
                                    wide(newlines(replacement->string(), entry.source.text))});
        }
        // SolidLSP applies edits from the end; same-position inserts retain protocol array order.
        std::sort(replacements.begin(), replacements.end(), [](const auto& a, const auto& b) {
            if (a.start != b.start) return a.start > b.start;
            return a.order > b.order;
        });
        size_t boundary = text.size() + 1;
        for (const auto& replacement : replacements) {
            if (replacement.end > boundary || (replacement.start == boundary && replacement.end > replacement.start))
                fail("overlapping LSP TextEdits; nothing written");
            text.replace(replacement.start, replacement.end - replacement.start, replacement.text);
            boundary = replacement.start;
        }
        result.push_back({std::move(entry.source), utf8(text)});
    }
    return result;
}
}

Json lsp_edit(const Json& arguments, const SearchContext& context,
              const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (context.read_only) fail("edit_file is disabled: --read-only");
    const int64_t timeout = number(arguments, "timeout_ms", 30000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{Clock::now() + std::chrono::milliseconds(timeout), cancelled};
    const SourceText source = read_source_text(context, str(arguments, "path"));
    if (const J* expected = arguments.get("expected_sha256"))
        if (source.sha256 != lower(expected->string())) fail("expected_sha256 does not match current file");
    if (const J* expected = arguments.get("expected_mtime"))
        if (source.mtime != expected->string()) fail("expected_mtime does not match current file");
    const auto config = configuration(source, context);
    if (!config) fail("no language server configured for this file; use operation=text");
    auto session = session_for(*config);
    auto lock = acquire(*session, control);
    try {
        session->start(control); session->synchronize(&source, context, control); session->service_pending(control);
        session->assert_current(source);
        std::string operation = str(arguments, "operation", "symbol");
        if (operation == "auto") operation = "symbol";
        const std::string name = str(arguments, "name_path");
        const auto found = name.empty() ? std::vector<Symbol>{} : symbols(*session, source, control);
        const Symbol* selected = name.empty() ? nullptr : &unique(found, name);
        Position at;
        if (selected) {
            if (arguments.get("line") || arguments.get("column")) fail("give name_path or line/column, not both");
            at = selected->selection.start;
        } else {
            const int64_t line = number(arguments, "line", 0), column = number(arguments, "column", 0);
            if (operation != "rename" || line < 1 || column < 1 || line > INT32_MAX || column > INT32_MAX)
                fail("symbol edits need name_path; rename also accepts 1-based line/column");
            at = {line - 1, column - 1}; offset(wide(source.text), at);
        }
        std::vector<SourceChange> changes;
        if (operation == "rename") {
            const std::string new_name = str(arguments, "new_name");
            if (new_name.empty() || new_name.find('\0') != std::string::npos) fail("rename requires a nonempty new_name");
            session->require("renameProvider");
            J::Object params{{"textDocument", J::Object{{"uri", session->document_uri(source)}}}, {"position", at.json()}};
            if (session->prepare_rename()) {
                const J prepared = session->request("textDocument/prepareRename", params, control);
                if (std::holds_alternative<std::nullptr_t>(prepared.value)) fail("language server refuses rename at this position");
            }
            params.emplace("newName", new_name);
            changes = workspace_changes(*session, session->request("textDocument/rename", std::move(params), control), *config, context, control);
        } else {
            if (!selected || !selected->has_body) fail("symbol has no reliable editable definition range");
            if (operation == "safe_delete") {
                session->require("referencesProvider");
                const J references = session->request("textDocument/references", J::Object{
                    {"textDocument", J::Object{{"uri", session->document_uri(source)}}}, {"position", at.json()},
                    {"context", J::Object{{"includeDeclaration", false}}}}, control);
                if (!std::holds_alternative<std::nullptr_t>(references.value))
                    for (const auto& reference : references.array()) {
                        const fs::path target_path = from_uri(str(reference, "uri"));
                        if (path_excluded(*config, target_path))
                            fail("safe_delete refused: ignored_paths may contain references");
                        const SourceText target = source_descriptor(context, utf8(target_path.wstring()));
                        const J* extent = reference.get("range"); if (!extent) fail("reference has no range");
                        const Range r = range(*extent);
                        const bool same = !PathLess{}(target.path.wstring(), source.path.wstring()) &&
                                          !PathLess{}(source.path.wstring(), target.path.wstring());
                        if (!same || r.start < selected->extent.start || selected->extent.end < r.end)
                            fail("safe_delete refused: symbol has references outside its definition; use search operation=references");
                    }
            } else if (operation != "symbol" && operation != "insert_before" && operation != "insert_after") fail("unknown symbol edit operation");
            std::wstring text = wide(source.text);
            size_t begin = offset(text, selected->extent.start), end = offset(text, selected->extent.end);
            std::string replacement = operation == "safe_delete" ? "" : str(arguments, "new_text");
            if (operation != "safe_delete" && !arguments.get("new_text")) fail("this symbol edit requires new_text");
            replacement = newlines(replacement, source.text);
            if (operation == "insert_before") {
                const size_t line_start = offset(text, Position{selected->extent.start.line, 0});
                if (text.substr(line_start, begin - line_start).find_first_not_of(L" \t") != std::wstring::npos)
                    fail("insert_before cannot split an inline definition; replace the containing symbol instead");
                begin = end = line_start;
                if (!replacement.ends_with("\n")) replacement += source.text.find("\r\n") != std::string::npos ? "\r\n" : "\n";
            } else if (operation == "insert_after") {
                if (selected->extent.end.column == 0) begin = end;
                else {
                    size_t next = text.find_first_of(L"\r\n", end);
                    if (text.substr(end, next == std::wstring::npos ? next : next - end).find_first_not_of(L" \t") != std::wstring::npos)
                        fail("insert_after requires the definition to end on its own line");
                    if (next == std::wstring::npos) { begin = text.size(); replacement = (source.text.find("\r\n") != std::string::npos ? "\r\n" : "\n") + replacement; }
                    else { if (text[next] == L'\r' && next + 1 < text.size() && text[next + 1] == L'\n') ++next; begin = next + 1; }
                }
                end = begin;
                if (!replacement.ends_with("\n")) replacement += source.text.find("\r\n") != std::string::npos ? "\r\n" : "\n";
            }
            text.replace(begin, end - begin, wide(replacement));
            changes.push_back({source, utf8(text)});
        }
        control.check();
        const auto current = read_source_text(context, utf8(source.path.wstring()));
        if (current.sha256 != source.sha256 || (arguments.get("expected_mtime") && current.mtime != source.mtime))
            fail("source changed during refactoring; retry");
        J result = apply_source_changes(changes, arguments, context, cancelled);
        return result;
    } catch (...) { session->stop(); throw; }
}

Json lsp_move(const Json& arguments, const SearchContext& context,
              const std::shared_ptr<std::atomic_bool>& cancelled) {
    const std::string operation = str(arguments, "operation", "auto");
    if (operation != "auto" && operation != "filesystem" && operation != "refactor") fail("move_file operation must be auto, filesystem, or refactor");
    if (operation != "filesystem" && flag(arguments, "overwrite")) fail("LSP file moves do not overwrite; use operation=filesystem explicitly");
    const int64_t timeout = number(arguments, "timeout_ms", 30000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{Clock::now() + std::chrono::milliseconds(timeout), cancelled};
    bool directory = false;
    const SourceText source = source_descriptor(context, str(arguments, "source"), &directory);
    bool destination_exists = false;
    const SourceText destination = source_descriptor(context, str(arguments, "destination"), nullptr, true, &destination_exists);
    if (source.path == source.root || destination.path == destination.root) fail("cannot move a configured root");
    if (!PathLess{}(source.path.wstring(), destination.path.wstring()) && !PathLess{}(destination.path.wstring(), source.path.wstring()))
        fail("source and destination are the same path");
    const std::wstring prefix = source.path.wstring() + L"\\";
    const std::wstring dest = destination.path.wstring();
    if (dest.size() > prefix.size() && CompareStringOrdinal(dest.data(), static_cast<int>(prefix.size()),
            prefix.data(), static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL) fail("cannot move a directory into itself");
    if (destination_exists && !flag(arguments, "overwrite")) fail("move destination already exists; nothing written");
    std::vector<SourceChange> changes;
    bool supported = false;
    if (operation != "filesystem")
        for (const auto& config : configs(source.root, context)) {
            const std::string extension = lower(utf8(source.path.extension().wstring()));
            if (!directory && std::find(config.extensions.begin(), config.extensions.end(), extension) == config.extensions.end()) continue;
            auto session = session_for(config);
            auto lock = acquire(*session, control);
            try {
                session->start(control); session->synchronize(nullptr, context, control); session->service_pending(control);
                if (!(session->file_operation("willRename", source.path, directory) || session->file_operation("willRename", destination.path, directory))) continue;
                supported = true;
                const J edit = session->request("workspace/willRenameFiles", J::Object{
                    {"files", J::Array{J::Object{{"oldUri", uri(source.path)}, {"newUri", uri(destination.path)}}}}}, control);
                if (!std::holds_alternative<std::nullptr_t>(edit.value)) {
                    auto planned = workspace_changes(*session, edit, config, context, control);
                    for (auto& change : planned) changes.push_back(std::move(change));
                }
            } catch (...) { session->stop(); throw; }
        }
    if (operation == "refactor" && !supported) fail("no configured language server supports willRenameFiles; nothing written");
    return apply_source_changes(changes, arguments, context, cancelled, &arguments);
}

void lsp_after_mutation(Json& result, const std::string& tool, const Json& arguments,
                        const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled) {
    std::vector<std::shared_ptr<Session>> active;
    { std::lock_guard lock(registry_mutex); for (const auto& [key, session] : registry) { (void)key; active.push_back(session); } }
    const Control control{Clock::now() + std::chrono::seconds(30), cancelled};
    auto belongs = [](const fs::path& child, const fs::path& root) {
        const std::wstring candidate = child.wstring(), parent = root.wstring();
        return candidate.size() >= parent.size() &&
            CompareStringOrdinal(candidate.data(), static_cast<int>(parent.size()), parent.data(), static_cast<int>(parent.size()), TRUE) == CSTR_EQUAL &&
            (candidate.size() == parent.size() || parent.ends_with(L"\\") || candidate[parent.size()] == L'\\');
    };
    for (auto& session : active) {
        try {
            auto lock = acquire(*session, control);
            try {
                const auto current = configs(session->config.root, context);
                const bool retained = std::any_of(current.begin(), current.end(), [&](const auto& config) { return config.key == session->config.key; });
                if (!retained) {
                    session->stop();
                    std::lock_guard registry_lock(registry_mutex);
                    registry.erase(session->config.key);
                    continue;
                }
                session->start(control);
                bool directory = false;
                const std::string path = tool == "move_file" ? str(arguments, "destination") : str(arguments, "path");
                const SourceText descriptor = source_descriptor(context, path, &directory);
                const bool relevant = belongs(descriptor.path, session->config.root);
                std::optional<SourceText> primary;
                const std::string extension = lower(utf8(descriptor.path.extension().wstring()));
                if (relevant && !directory && std::find(session->config.extensions.begin(), session->config.extensions.end(), extension) != session->config.extensions.end())
                    primary = read_source_text(context, path);
                if (tool == "move_file") {
                    const auto old = source_descriptor(context, str(arguments, "source"), nullptr, true);
                    if ((relevant || belongs(old.path, session->config.root)) &&
                        (session->file_operation("didRename", old.path, directory) || session->file_operation("didRename", descriptor.path, directory)))
                        session->notify("workspace/didRenameFiles", J::Object{
                            {"files", J::Array{J::Object{{"oldUri", uri(old.path)}, {"newUri", uri(descriptor.path)}}}}}, control);
                } else if (tool == "create_directory" && relevant && session->file_operation("didCreate", descriptor.path, true)) {
                    const J* text = result.get("text");
                    if (text && text->string().starts_with("Created "))
                        session->notify("workspace/didCreateFiles", J::Object{{"files", J::Array{J::Object{{"uri", uri(descriptor.path)}}}}}, control);
                }
                session->synchronize(primary ? &*primary : nullptr, context, control, true);
            } catch (...) { session->stop(); throw; }
        } catch (const std::exception& e) {
            auto& object = std::get<J::Object>(result.value);
            const std::string warning = "[warning: filesystem changes applied; LSP synchronization failed: " + std::string(e.what()) + "]\n";
            if (auto it = object.find("text"); it != object.end()) it->second = it->second.string() + warning;
            else object.emplace("warning", warning);
        }
    }
}
} // namespace shgrep
