#include "files.hpp"
#include "lsp.hpp"
#include "edit.hpp"
#include "rank.hpp"
#include "ignore.hpp"
#include "winfs.hpp"

#include <aclapi.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <functional>
#include <map>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace shgrep {
namespace {
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

[[noreturn]] void fail(const std::string& message) { throw std::runtime_error(message); }
using CancelFlag = std::shared_ptr<std::atomic_bool>;
void check_cancelled(const CancelFlag& cancelled) {
    if (!cancelled) return;  // Recovery reads deliberately run without request interruption.
    if (cancelled->load()) fail("request cancelled; nothing was written");
    if (Clock::now() >= request_deadline(Clock::time_point::max()))
        fail("request timed out before commit; nothing was written");
}

// CONTRACT: read_file, file_info and edit_file decode whole files; larger files are refused, never cut.
constexpr uint64_t max_text_bytes = 64ull << 20;
constexpr size_t max_paths = 32;
constexpr ULONG share_all = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
constexpr ACCESS_MASK directory_access = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES;

// NtCreateFile values from ntifs.h, named here so they cannot collide with winternl.h macros.
constexpr ULONG disposition_open = 0x1, disposition_create = 0x2, disposition_open_if = 0x3;
constexpr ULONG option_directory = 0x1, option_sequential = 0x4, option_synchronous = 0x20,
                option_non_directory = 0x40, option_open_reparse_point = 0x200000;
constexpr ULONG_PTR information_created = 2;  // FILE_CREATED
constexpr NTSTATUS status_collision = static_cast<NTSTATUS>(0xC0000035L);
constexpr NTSTATUS status_is_directory = static_cast<NTSTATUS>(0xC00000BAL);
constexpr NTSTATUS status_not_directory = static_cast<NTSTATUS>(0xC0000103L);

std::string win32_text(DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                        FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
                                        reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring message = length && buffer ? std::wstring(buffer, length) : std::wstring();
    if (buffer) LocalFree(buffer);
    while (!message.empty() && (std::iswspace(message.back()) || message.back() == L'.')) message.pop_back();
    std::string out;
    if (message.empty() || !try_utf8(message, out)) return "Windows error " + std::to_string(code);
    return out;
}

std::string status_text(NTSTATUS status) {
    switch (static_cast<uint32_t>(status)) {
    case 0xC0000034: case 0xC000003A: return "not found";
    case 0xC0000035: return "already exists";
    case 0xC0000022: return "access denied";
    case 0xC0000043: return "in use by another process (sharing violation)";
    case 0xC0000103: return "a path component is not a directory";
    case 0xC00000BA: return "is a directory";
    case 0xC0000056: return "is being deleted";
    case 0xC0000033: return "invalid name";
    default: return win32_text(RtlNtStatusToDosError(status));
    }
}

// Opens name relative to the open directory parent. Never resolves more than the one component it is given.
NTSTATUS nt_open(HANDLE parent, std::wstring_view name, ACCESS_MASK access, ULONG share, ULONG disposition,
                 ULONG options, ULONG attributes, Handle& out, ULONG_PTR* information = nullptr) {
    UNICODE_STRING object_name;
    object_name.Buffer = const_cast<PWSTR>(name.data());
    object_name.Length = object_name.MaximumLength = static_cast<USHORT>(name.size() * sizeof(wchar_t));
    OBJECT_ATTRIBUTES object{};
    object.Length = sizeof(object);
    object.RootDirectory = parent;
    object.ObjectName = &object_name;
    object.Attributes = OBJ_CASE_INSENSITIVE;
    IO_STATUS_BLOCK io{};
    HANDLE handle = nullptr;
    const NTSTATUS status = NtCreateFile(&handle, access | SYNCHRONIZE, &object, &io, nullptr, attributes, share,
                                         disposition, options | option_synchronous, nullptr, 0);
    if (status < 0) return status;
    out = Handle(handle);
    if (information) *information = io.Information;
    return status;
}

DWORD attributes_of(HANDLE handle, const std::string& path) {
    FILE_ATTRIBUTE_TAG_INFO info{};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info))) {
        const DWORD code = GetLastError();
        fail(path + ": cannot read attributes (" + win32_text(code) + ")");
    }
    return info.FileAttributes;
}

void refuse_link(HANDLE handle, const std::string& path) {
    if (attributes_of(handle, path) & FILE_ATTRIBUTE_REPARSE_POINT)
        fail(path + " is a symbolic link, junction or other reparse point; shgrep never follows links");
}

FILE_BASIC_INFO basic_info(HANDLE handle, const std::string& path) {
    FILE_BASIC_INFO info{};
    if (!GetFileInformationByHandleEx(handle, FileBasicInfo, &info, sizeof(info))) {
        const DWORD code = GetLastError();
        fail(path + ": cannot read file times (" + win32_text(code) + ")");
    }
    return info;
}

std::string format_mtime(int64_t filetime) {
    const auto ticks = static_cast<uint64_t>(filetime);
    FILETIME ft{static_cast<DWORD>(ticks), static_cast<DWORD>(ticks >> 32)};
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) return "unknown";
    char buffer[48];
    std::snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u.%07lluZ", static_cast<unsigned>(st.wYear),
                  static_cast<unsigned>(st.wMonth), static_cast<unsigned>(st.wDay), static_cast<unsigned>(st.wHour),
                  static_cast<unsigned>(st.wMinute), static_cast<unsigned>(st.wSecond),
                  static_cast<unsigned long long>(ticks % 10000000));
    return buffer;
}

// Incremental SHA-256, so a file read in pieces hashes like one read whole.
class Sha256 {
public:
    Sha256() {
        static const BCRYPT_ALG_HANDLE algorithm = [] {
            BCRYPT_ALG_HANDLE handle = nullptr;
            return BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) ? handle
                                                                                                             : nullptr;
        }();
        if (!algorithm || !BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash_, nullptr, 0, nullptr, 0, 0)))
            fail("SHA-256 is unavailable");
    }
    ~Sha256() { if (hash_) BCryptDestroyHash(hash_); }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    void add(std::string_view data) {
        for (size_t offset = 0; offset < data.size();) {
            const auto chunk = static_cast<ULONG>(std::min<size_t>(data.size() - offset, size_t{1} << 30));
            if (!BCRYPT_SUCCESS(BCryptHashData(hash_, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data() + offset)),
                                               chunk, 0))) fail("SHA-256 failed");
            offset += chunk;
        }
    }
    std::string hex() {
        unsigned char digest[32];
        if (!BCRYPT_SUCCESS(BCryptFinishHash(hash_, digest, sizeof(digest), 0))) fail("SHA-256 failed");
        constexpr char digits[] = "0123456789abcdef";
        std::string out;
        for (unsigned char c : digest) {
            out.push_back(digits[c >> 4]);
            out.push_back(digits[c & 15]);
        }
        return out;
    }

private:
    BCRYPT_HASH_HANDLE hash_ = nullptr;
};

std::string sha256_hex(std::string_view data) {
    Sha256 hash;
    hash.add(data);
    return hash.hex();
}

// ---- Arguments ----

std::string string_arg(const Json& args, const char* key) {
    const Json* value = args.get(key);
    if (!value) fail(std::string(key) + " is required");
    const auto* text = std::get_if<std::string>(&value->value);
    if (!text) fail(std::string(key) + " must be a string");
    return *text;
}

bool bool_arg(const Json& args, const char* key, bool fallback) {
    const Json* value = args.get(key);
    if (!value) return fallback;
    const auto* flag = std::get_if<bool>(&value->value);
    if (!flag) fail(std::string(key) + " must be true or false");
    return *flag;
}

int64_t int_arg(const Json& args, const char* key, int64_t fallback, int64_t min, int64_t max) {
    const Json* value = args.get(key);
    if (!value) return fallback;
    const auto* number = std::get_if<int64_t>(&value->value);
    if (!number || *number < min || *number > max)
        fail(std::string(key) + " must be an integer from " + std::to_string(min) + " to " + std::to_string(max));
    return *number;
}

std::vector<std::string> path_args(const Json& args) {
    const Json* one = args.get("path");
    const Json* many = args.get("paths");
    if (one && many) fail("give path or paths, not both");
    if (one) return {string_arg(args, "path")};
    if (!many) fail("path is required");
    const auto* list = std::get_if<Json::Array>(&many->value);
    if (!list || list->empty() || list->size() > max_paths) fail("paths must be a list of 1 to 32 path strings");
    std::vector<std::string> out;
    for (const auto& item : *list) {
        const auto* text = std::get_if<std::string>(&item.value);
        if (!text) fail("paths must be a list of 1 to 32 path strings");
        out.push_back(*text);
    }
    return out;
}

// CONTRACT: like the search tools, argument names outside a tool's schema are errors, so a misspelled option
// cannot silently do something else.
void reject_unknown(const std::string& tool, const Json& args) {
    static const auto accepted = [] {
        std::map<std::string, std::set<std::string>> names;
        const Json definitions = file_tool_definitions(false);  // SAFETY: named; ranging over a temporary dangles
        for (const auto& definition : definitions.array()) {
            const auto& object = definition.object();
            auto& known = names[object.at("name").string()];
            for (const auto& entry : object.at("inputSchema").object().at("properties").object()) known.insert(entry.first);
        }
        return names;
    }();
    const auto& known = accepted.at(tool);
    for (const auto& entry : args.object()) {
        if (known.contains(entry.first)) continue;
        std::string valid;
        for (const auto& name : known) valid += (valid.empty() ? "" : ", ") + name;
        const std::string name = entry.first.size() > 64 ? entry.first.substr(0, 64) + "..." : entry.first;
        fail("unknown argument \"" + name + "\" for " + tool + "; valid arguments: " + valid);
    }
}

// ---- Paths ----

std::wstring without_verbatim(std::wstring path) {
    if (path.starts_with(L"\\\\?\\UNC\\")) return L"\\\\" + path.substr(8);
    if (path.starts_with(L"\\\\?\\")) return path.substr(4);
    return path;
}

std::wstring trim_separator(std::wstring path) {
    while (path.size() > 3 && (path.back() == L'\\' || path.back() == L'/')) path.pop_back();
    return path;
}

struct Root {
    std::wstring lexical;    // absolute and lexically normal: the form paths are displayed in
    std::wstring canonical;  // the opened root's final path, so absolute paths in that form are accepted too
};

std::vector<Root> configured_roots(const SearchContext& context) {
    std::vector<Root> roots;
    for (const auto& allowed : context.allowed_roots) {
        std::error_code ec;
        const fs::path absolute = fs::absolute(allowed, ec);
        if (ec) continue;
        Root root;
        root.lexical = trim_separator(absolute.lexically_normal().wstring());
        Handle handle(CreateFileW(long_path(root.lexical).c_str(), FILE_READ_ATTRIBUTES, share_all, nullptr,
                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        if (handle) {
            try { root.canonical = trim_separator(without_verbatim(final_path(handle.h))); }
            catch (const std::exception&) {}
        }
        roots.push_back(std::move(root));
    }
    if (roots.empty()) fail("no roots configured");
    return roots;
}

// A path below a configured root, held as its components; nothing is resolved until it is opened.
struct Target {
    std::wstring root;
    std::vector<std::wstring> parts;

    std::wstring full(size_t count) const {
        std::wstring out = root;
        for (size_t i = 0; i < count && i < parts.size(); ++i) out = join_path(out, parts[i]);
        return out;
    }
    std::string display(size_t count) const {
        std::string out;
        return try_utf8(full(count), out) ? out : std::string("<path not representable as UTF-8>");
    }
    std::string display() const { return display(parts.size()); }
    std::string relative(size_t count) const {
        std::string out, piece;
        for (size_t i = 0; i < count && i < parts.size(); ++i) {
            if (!out.empty()) out.push_back('/');
            if (try_utf8(parts[i], piece)) out += piece;
        }
        return out.empty() ? "." : out;
    }
    std::string relative() const { return relative(parts.size()); }
    const std::wstring& name() const { return parts.back(); }
};

void check_name(const std::wstring& name, const std::string& path) {
    if (name.size() > 255) fail("path \"" + path + "\" has a name longer than 255 characters");
    for (wchar_t c : name)
        if (c < 32 || std::wcschr(L"<>:\"|?*", c))
            fail("path \"" + path + "\" contains a character Windows does not allow in names (< > : \" | ? * or a "
                 "control character); alternate data streams are not supported");
    if (name.back() == L'.' || name.back() == L' ')
        fail("path \"" + path + "\" has a name ending in '.' or ' ', which Windows does not allow");
    std::wstring stem = name.substr(0, name.find(L'.'));
    while (!stem.empty() && stem.back() == L' ') stem.pop_back();
    static constexpr const wchar_t* reserved[] = {
        L"CON", L"PRN", L"AUX", L"NUL", L"COM1", L"COM2", L"COM3", L"COM4", L"COM5", L"COM6", L"COM7", L"COM8",
        L"COM9", L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5", L"LPT6", L"LPT7", L"LPT8", L"LPT9"};
    for (const wchar_t* device : reserved)
        if (same_name(stem, device)) fail("path \"" + path + "\" uses a reserved Windows device name");
}

// CONTRACT: a relative path resolves against the first configured root; an absolute one must lie inside a
// configured root after lexical normalization. '..' that would leave the root is an error. No filesystem access.
Target resolve(const SearchContext& context, const std::string& text) {
    if (text.empty()) fail("path is empty");
    if (text.size() > 32767) fail("path is too long");
    if (text.find('\0') != std::string::npos) fail("path contains a NUL character");
    std::wstring raw = without_verbatim(native_path(text).wstring());
    std::replace(raw.begin(), raw.end(), L'/', L'\\');
    const fs::path path(raw);
    const std::vector<Root> roots = configured_roots(context);
    Target target;
    std::wstring rest;
    if (path.has_root_name() || path.has_root_directory()) {
        if (!path.is_absolute())
            fail("path \"" + text + "\" is relative to a drive or to the current drive's root; give it relative "
                 "to the root (\"src/main.cpp\") or as a full absolute path");
        const std::wstring normal = trim_separator(path.lexically_normal().wstring());
        size_t best = 0;
        for (const auto& root : roots) {
            for (const std::wstring* form : {&root.lexical, &root.canonical}) {
                if (form->empty() || form->size() <= best || !inside(normal, *form)) continue;
                best = form->size();
                target.root = root.lexical;
                rest = normal.substr(form->size());
            }
        }
        if (target.root.empty()) fail("path \"" + text + "\" is outside the configured roots");
    } else {
        target.root = roots.front().lexical;
        rest = raw;
    }
    size_t start = 0;
    while (start <= rest.size()) {
        size_t end = rest.find(L'\\', start);
        if (end == std::wstring::npos) end = rest.size();
        const std::wstring part = rest.substr(start, end - start);
        start = end + 1;
        if (part.empty() || part == L".") continue;
        if (part == L"..") {
            if (target.parts.empty()) fail("path \"" + text + "\" uses '..' to leave the root");
            target.parts.pop_back();
        } else target.parts.push_back(part);
    }
    for (const auto& part : target.parts) check_name(part, text);
    return target;
}

// Opens the configured root itself. Links in the root's own path are the owner's choice and are followed.
Handle open_root(const Target& target) {
    Handle root(CreateFileW(long_path(target.root).c_str(), directory_access | SYNCHRONIZE, share_all, nullptr,
                            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!root) {
        const DWORD code = GetLastError();
        fail("configured root unavailable: " + target.display(0) + " (" + win32_text(code) + ")");
    }
    return root;
}

// Opens the directory that holds target's last component.
// SAFETY: walks down from the configured root one component at a time, each opened relative to its parent's
// handle with FILE_OPEN_REPARSE_POINT and refused if it is a reparse point. No symbolic link or junction below
// the root is ever followed, and no path string is resolved again between the check and the use.
Handle open_parent(const Target& target, bool create_missing, std::vector<std::string>* created = nullptr,
                   const CancelFlag& cancelled = {}) {
    check_cancelled(cancelled);
    Handle directory = open_root(target);
    for (size_t i = 0; i + 1 < target.parts.size(); ++i) {
        check_cancelled(cancelled);
        Handle child;
        ULONG_PTR information = 0;
        const NTSTATUS status = nt_open(directory.h, target.parts[i], directory_access, share_all,
                                        create_missing ? disposition_open_if : disposition_open,
                                        option_directory | option_open_reparse_point, 0, child, &information);
        if (status < 0) fail(target.display(i + 1) + ": " + status_text(status));
        refuse_link(child.h, target.display(i + 1));
        if (created && information == information_created) created->push_back(target.relative(i + 1) + "/");
        directory = std::move(child);
    }
    return directory;
}

// Opens target as a regular file for reading. share decides whether other writers may keep working meanwhile.
Handle open_file(HANDLE directory, const Target& target, ULONG share) {
    Handle file;
    const NTSTATUS status = nt_open(directory, target.name(), FILE_GENERIC_READ, share, disposition_open,
                                    option_non_directory | option_open_reparse_point | option_sequential, 0, file);
    if (status == status_is_directory) fail(target.display() + " is a directory; use list_dir");
    if (status < 0) fail(target.display() + ": " + status_text(status));
    refuse_link(file.h, target.display());
    return file;
}

// Reads the whole file into data. Returns false, with data unspecified, when it is larger than limit.
bool read_all(HANDLE file, const std::string& path, uint64_t limit, std::string& data,
              const CancelFlag& cancelled = {}) {
    check_cancelled(cancelled);
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size)) {
        const DWORD code = GetLastError();
        fail(path + ": cannot read its size (" + win32_text(code) + ")");
    }
    if (static_cast<uint64_t>(size.QuadPart) > limit) return false;
    data.clear();
    data.reserve(static_cast<size_t>(size.QuadPart));
    constexpr DWORD chunk = 1 << 20;
    for (;;) {
        check_cancelled(cancelled);
        const size_t used = data.size();
        data.resize(used + chunk);
        DWORD got = 0;
        if (!ReadFile(file, data.data() + used, chunk, &got, nullptr)) {
            const DWORD code = GetLastError();
            fail(path + ": read failed (" + win32_text(code) + ")");
        }
        data.resize(used + got);
        if (got == 0) return true;
        if (data.size() > limit) return false;
    }
}

// ---- Text decoding ----

enum class Encoding { utf8, utf8_bom, utf16le, utf16be };

const char* encoding_name(Encoding encoding) {
    switch (encoding) {
    case Encoding::utf8_bom: return "utf-8-bom";
    case Encoding::utf16le: return "utf-16le";
    case Encoding::utf16be: return "utf-16be";
    default: return "utf-8";
    }
}

Encoding parse_encoding(const std::string& name) {
    if (name == "utf-8") return Encoding::utf8;
    if (name == "utf-8-bom") return Encoding::utf8_bom;
    if (name == "utf-16le") return Encoding::utf16le;
    if (name == "utf-16be") return Encoding::utf16be;
    fail("encoding must be utf-8, utf-8-bom, utf-16le or utf-16be");
}

struct TextFile {
    Encoding encoding = Encoding::utf8;
    std::string text;  // UTF-8 without the BOM
    bool binary = false;
    uint64_t nul_offset = 0;
    uint64_t invalid = 0;  // byte sequences shown as U+FFFD; nonzero means text does not round-trip to the file
    uint64_t crlf = 0, lf = 0, cr = 0, lines = 0;
    bool final_newline = false;
};

// Length of the strict UTF-8 sequence at p (RFC 3629, as MultiByteToWideChar accepts), or 0 if it is invalid.
size_t utf8_length(const unsigned char* p, size_t n) {
    const unsigned char c = p[0];
    if (c < 0x80) return 1;
    size_t length = 0;
    unsigned char low = 0x80, high = 0xbf;
    if (c >= 0xc2 && c <= 0xdf) length = 2;
    else if (c >= 0xe0 && c <= 0xef) {
        length = 3;
        if (c == 0xe0) low = 0xa0;
        else if (c == 0xed) high = 0x9f;
    } else if (c >= 0xf0 && c <= 0xf4) {
        length = 4;
        if (c == 0xf0) low = 0x90;
        else if (c == 0xf4) high = 0x8f;
    } else return 0;
    if (n < length || p[1] < low || p[1] > high) return 0;
    for (size_t k = 2; k < length; ++k)
        if ((p[k] & 0xc0) != 0x80) return 0;
    return length;
}

void count_lines(TextFile& f) {
    const std::string& t = f.text;
    for (size_t i = 0; i < t.size(); ++i) {
        if (t[i] == '\n') ++f.lf;
        else if (t[i] == '\r') {
            if (i + 1 < t.size() && t[i + 1] == '\n') { ++f.crlf; ++i; }
            else ++f.cr;
        }
    }
    // CONTRACT: lines are counted at '\n' like search's line numbers, so both tools number lines alike.
    f.lines = t.empty() ? 0 : f.lf + f.crlf + (t.back() == '\n' ? 0 : 1);
    f.final_newline = !t.empty() && (t.back() == '\n' || t.back() == '\r');
}

// CONTRACT: matches search's selection: a BOM-marked UTF-16 file is text; otherwise any NUL byte makes it binary.
TextFile decode(const std::string& raw) {
    TextFile f;
    std::string_view body(raw);
    auto starts = [&](std::string_view bom) { return body.starts_with(bom); };
    if (starts("\xEF\xBB\xBF")) { f.encoding = Encoding::utf8_bom; body.remove_prefix(3); }
    else if (starts("\xFF\xFE")) { f.encoding = Encoding::utf16le; body.remove_prefix(2); }
    else if (starts("\xFE\xFF")) { f.encoding = Encoding::utf16be; body.remove_prefix(2); }
    if (f.encoding == Encoding::utf16le || f.encoding == Encoding::utf16be) {
        const bool little = f.encoding == Encoding::utf16le;
        std::wstring wide(body.size() / 2, L'\0');
        for (size_t i = 0; i < wide.size(); ++i) {
            const auto first = static_cast<unsigned char>(body[2 * i]), second = static_cast<unsigned char>(body[2 * i + 1]);
            wide[i] = static_cast<wchar_t>(little ? (first | (second << 8)) : (second | (first << 8)));
        }
        if (body.size() % 2) ++f.invalid;
        const size_t nul = wide.find(L'\0');
        if (nul != std::wstring::npos) {
            f.binary = true;
            f.nul_offset = 2 + 2 * static_cast<uint64_t>(nul);
            return f;
        }
        if (!try_utf8(wide, f.text)) {
            // Unpaired surrogates: convert with U+FFFD in their place.
            ++f.invalid;
            const int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0,
                                                 nullptr, nullptr);
            f.text.assign(static_cast<size_t>(size), '\0');
            WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), f.text.data(), size, nullptr,
                                nullptr);
        }
    } else {
        if (const void* nul = std::memchr(body.data(), 0, body.size())) {
            f.binary = true;
            f.nul_offset = (raw.size() - body.size()) + static_cast<uint64_t>(static_cast<const char*>(nul) - body.data());
            return f;
        }
        f.text.reserve(body.size());
        const auto* p = reinterpret_cast<const unsigned char*>(body.data());
        size_t i = 0, run = 0;
        while (i < body.size()) {
            if (p[i] < 0x80) { ++i; continue; }
            if (const size_t length = utf8_length(p + i, body.size() - i)) { i += length; continue; }
            f.text.append(body.data() + run, i - run);
            f.text += "\xEF\xBF\xBD";
            ++f.invalid;
            run = ++i;
        }
        f.text.append(body.data() + run, body.size() - run);
    }
    count_lines(f);
    return f;
}

std::string encode(std::string_view text, Encoding encoding) {
    if (encoding == Encoding::utf8) return std::string(text);
    if (encoding == Encoding::utf8_bom) return "\xEF\xBB\xBF" + std::string(text);
    std::wstring wide;
    if (!text.empty()) {
        const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
        wide.assign(static_cast<size_t>(size), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), size);
    }
    const bool little = encoding == Encoding::utf16le;
    std::string out = little ? "\xFF\xFE" : "\xFE\xFF";
    out.reserve(2 + wide.size() * 2);
    for (wchar_t c : wide) {
        const auto low = static_cast<char>(c & 0xff), high = static_cast<char>((c >> 8) & 0xff);
        out.push_back(little ? low : high);
        out.push_back(little ? high : low);
    }
    return out;
}

enum class Eol { none, lf, crlf, cr, mixed };

Eol eol_style(const TextFile& f) {
    const int kinds = (f.crlf > 0) + (f.lf > 0) + (f.cr > 0);
    if (kinds == 0) return Eol::none;
    if (kinds > 1) return Eol::mixed;
    return f.crlf ? Eol::crlf : f.lf ? Eol::lf : Eol::cr;
}

std::string_view eol_text(Eol eol) { return eol == Eol::crlf ? "\r\n" : eol == Eol::cr ? "\r" : "\n"; }

std::string eol_name(const TextFile& f) {
    switch (eol_style(f)) {
    case Eol::none: return "no line breaks";
    case Eol::lf: return "lf";
    case Eol::crlf: return "crlf";
    case Eol::cr: return "cr";
    default: break;
    }
    std::string out;
    if (f.crlf) out += "crlf " + std::to_string(f.crlf);
    if (f.lf) out += std::string(out.empty() ? "" : ", ") + "lf " + std::to_string(f.lf);
    if (f.cr) out += std::string(out.empty() ? "" : ", ") + "cr " + std::to_string(f.cr);
    return "mixed (" + out + ")";
}

// Every CRLF or lone LF in s becomes eol; a lone CR is kept.
std::string replace_newlines(std::string_view s, std::string_view eol) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\r' && i + 1 < s.size() && s[i + 1] == '\n') { out += eol; ++i; }
        else if (s[i] == '\n') out += eol;
        else out.push_back(s[i]);
    }
    return out;
}

// ---- Output budget ----

// CONTRACT: counts the JSON-escaped size of the text, which is what max_output_bytes limits; the reserve below
// leaves room for the MCP envelope and one trailing status line.
struct Budget {
    size_t limit = 0, used = 0;
    size_t max_output = 0;
    explicit Budget(size_t max) : limit(max > 1024 ? max - 768 : max / 2), max_output(max) {}
    bool fits(std::string_view s) const { return used + Json::escaped_size(s) - 2 <= limit; }
    void take(std::string_view s) { used += Json::escaped_size(s) - 2; }
};

size_t max_output_arg(const Json& args) {
    if (!args.get("max_output_bytes")) return std::numeric_limits<size_t>::max();
    return static_cast<size_t>(int_arg(args, "max_output_bytes", 65536, 512, 1048576));
}

std::string file_header(const std::string& path, uint64_t bytes, const std::string& sha256, const TextFile& text,
                        const FILE_BASIC_INFO& basic) {
    std::string header = "[file " + path + " | " + std::to_string(text.lines) + " lines, " + std::to_string(bytes) +
                         " bytes | " + encoding_name(text.encoding) + ", " + eol_name(text) + ", " +
                         (text.final_newline ? "final newline" : "no final newline");
    if (text.invalid)
        header += ", " + std::to_string(text.invalid) + " invalid byte sequences shown as U+FFFD (edit_file refuses "
                  "this file)";
    return header + " | mtime " + format_mtime(basic.LastWriteTime.QuadPart) + " | sha256 " + sha256 + " | source: text]\n";
}
std::string file_header(const std::string& path, const std::string& raw, const TextFile& text,
                        const FILE_BASIC_INFO& basic) {
    return file_header(path, raw.size(), sha256_hex(raw), text, basic);
}

// ---- read_file ----

struct ReadOptions {
    uint64_t offset = 1, limit = UINT64_MAX;
    bool numbers = true;
    CancelFlag cancelled;
};

constexpr uint64_t max_streamed_text_bytes = 256ull << 20;

// PERF: a UTF-8 file over max_text_bytes is read once in 1 MiB pieces. The header's counts and sha256 are computed
//   on the way and only the requested window of lines is kept, so memory stays flat whatever the offset.
// CONTRACT: the output equals render_file's for the same bytes; UTF-16 files this large are refused.
std::string render_large_file(std::string& out, const std::string& path, HANDLE file, const FILE_BASIC_INFO& basic,
                       const ReadOptions& options, const std::string& header_path, bool saved_output) {
    Sha256 hash;
    TextFile counts;  // everything but text
    uint64_t bytes = 0, decoded_size = 0, number = 1, shown = 0, line_bytes = 0;
    std::string window, line, carry;
    bool first = true, pending_cr = false, more = false;
    char last = 0;
    auto emit_line = [&](bool had_newline) {
        if (had_newline && !line.empty() && line.back() == '\r') line.pop_back();
        if (options.numbers) window += std::to_string(number) + " | ";
        window += line;
        window.push_back('\n');
        line.clear();
        ++shown;
    };
    // Decoded text arrives here, in order; it mirrors count_lines and render_file's line walk.
    auto consume = [&](std::string_view text) {
        for (const char c : text) {
            if (pending_cr) {
                pending_cr = false;
                if (c == '\n') ++counts.crlf;
                else ++counts.cr;
            }
            if (c == '\r') pending_cr = true;
            if (c == '\n' && last != '\r') ++counts.lf;
            // CONTRACT: subtract only after the offset check; an unlimited read must not overflow an end line.
            const bool inside = number >= options.offset && number - options.offset < options.limit;
            if (shown == options.limit) more = true;
            if (inside) line.push_back(c);
            ++line_bytes;
            if (c == '\n') {
                if (inside) { line.pop_back(); emit_line(true); }
                ++number;
                line_bytes = 0;
            }
            last = c;
        }
        decoded_size += text.size();
    };
    std::string piece(1u << 20, '\0');
    for (;;) {
        check_cancelled(options.cancelled);
        DWORD got = 0;
        if (!ReadFile(file, piece.data(), static_cast<DWORD>(piece.size()), &got, nullptr)) {
            const DWORD code = GetLastError();
            fail(path + ": read failed (" + win32_text(code) + ")");
        }
        const bool end = got == 0;
        std::string_view raw(piece.data(), got);
        hash.add(raw);
        bytes += got;
        if (!saved_output && bytes > max_streamed_text_bytes) fail(path + " is larger than 256 MiB; use search");
        if (first && !end) {
            first = false;
            if (raw.starts_with("\xFF\xFE") || raw.starts_with("\xFE\xFF"))
                fail(path + " is UTF-16 and larger than 64 MiB; read it with search");
            if (raw.starts_with("\xEF\xBB\xBF")) { counts.encoding = Encoding::utf8_bom; raw.remove_prefix(3); }
        }
        if (std::memchr(raw.data(), 0, raw.size())) fail(path + " is binary; use search_bytes");
        // Repairs invalid UTF-8 like decode(); a sequence split between pieces waits in carry for the next one.
        std::string buffer = carry + std::string(raw);
        carry.clear();
        const auto* p = reinterpret_cast<const unsigned char*>(buffer.data());
        size_t i = 0, run = 0;
        while (i < buffer.size()) {
            if (p[i] < 0x80) { ++i; continue; }
            if (const size_t length = utf8_length(p + i, buffer.size() - i)) { i += length; continue; }
            if (!end && buffer.size() - i < 4) break;
            consume(std::string_view(buffer).substr(run, i - run));
            consume("\xEF\xBF\xBD");
            ++counts.invalid;
            run = ++i;
        }
        consume(std::string_view(buffer).substr(run, i - run));
        carry.assign(buffer, i, std::string::npos);
        if (end) break;
    }
    if (pending_cr) ++counts.cr;
    if (line_bytes && number >= options.offset && number - options.offset < options.limit && shown < options.limit) emit_line(false);
    counts.lines = decoded_size == 0 ? 0 : counts.lf + counts.crlf + (last == '\n' ? 0 : 1);
    counts.final_newline = decoded_size != 0 && (last == '\n' || last == '\r');
    const std::string digest = hash.hex();
    out += file_header(header_path, bytes, digest, counts, basic);
    if (options.offset > counts.lines && !(counts.lines == 0 && options.offset == 1)) {
        out += "[offset " + std::to_string(options.offset) + " is past the end: the file has " + std::to_string(counts.lines) + " lines]\n";
        return digest;
    }
    out += window;
    if (more)
        out += "[status limit: showed lines " + std::to_string(options.offset) + "-" + std::to_string(options.offset + shown - 1) +
               " of " + std::to_string(counts.lines) + " (limit=" + std::to_string(options.limit) +
               "); continue with offset=" + std::to_string(options.offset + shown) + "]\n";
    return digest;
}

void render_file(std::string& out, const Target& target, const ReadOptions& options, const std::string& header_path,
                 const SearchContext& context) {
    const std::string path = target.display();
    if (target.parts.empty()) fail(path + " is a configured root directory; use list_dir");
    std::string raw;
    FILE_BASIC_INFO basic{};
    {
        Handle directory = open_parent(target, false);
        Handle file = open_file(directory.h, target, share_all);
        basic = basic_info(file.h, path);
        LARGE_INTEGER size{};
        if (GetFileSizeEx(file.h, &size) && static_cast<uint64_t>(size.QuadPart) > max_text_bytes) {
            const bool saved_output = target.parts.size() == 2 && target.parts.front() == L".shgrep-output";
            if (!saved_output && static_cast<uint64_t>(size.QuadPart) > max_streamed_text_bytes) fail(path + " is larger than 256 MiB; use search");
            const std::string digest = render_large_file(out, path, file.h, basic, options, header_path, saved_output);
            if (context.record_user_reads)
                remember_read_snapshot(context, fs::path(target.full(target.parts.size())), digest);
            return;
        }
        if (!read_all(file.h, path, max_text_bytes, raw)) fail(path + " is larger than 64 MiB; use search");
    }
    const TextFile text = decode(raw);
    if (text.binary) fail(path + " is binary; use search_bytes");
    if (context.record_user_reads)
        remember_read_snapshot(context, fs::path(target.full(target.parts.size())), sha256_hex(raw));
    out += file_header(header_path, raw, text, basic);
    if (options.offset > text.lines && !(text.lines == 0 && options.offset == 1)) {
        out += "[offset " + std::to_string(options.offset) + " is past the end: the file has " + std::to_string(text.lines) + " lines]\n";
        return;
    }
    const std::string& t = text.text;
    size_t pos = 0;
    uint64_t number = 1, shown = 0;
    while (number < options.offset && pos < t.size()) {
        const size_t newline = t.find('\n', pos);
        pos = newline == std::string::npos ? t.size() : newline + 1;
        ++number;
    }
    const uint64_t first = number;
    while (pos < t.size() && shown < options.limit) {
        const size_t newline = t.find('\n', pos);
        size_t end = newline == std::string::npos ? t.size() : newline;
        if (newline != std::string::npos && end > pos && t[end - 1] == '\r') --end;
        if (options.numbers) out += std::to_string(number) + " | ";
        out.append(t, pos, end - pos);
        out.push_back('\n');
        ++shown; ++number;
        pos = newline == std::string::npos ? t.size() : newline + 1;
    }
    if (pos < t.size())
        out += "[status limit: showed lines " + std::to_string(first) + "-" + std::to_string(first + shown - 1) +
               " of " + std::to_string(text.lines) + " (limit=" + std::to_string(options.limit) +
               "); continue with offset=" + std::to_string(first + shown) + "]\n";
}

// "json" (default) or "compact"/"outline": how a symbol overview is shown.
std::string outline_format(const Json& args) {
    const std::string format = args.get("format") ? string_arg(args, "format") : "json";
    if (format != "compact" && format != "outline" && format != "json") fail("format must be compact, outline, or json");
    return format;
}

// PERF: an overview as one line per symbol, "LINE kind name_path", about a fifth of the json with its ranges. The
//   name_path is exactly what read_file name_path, search and edit_file take next.
Json semantic_file_result(const Json& result, const Json& file) {
    Json::Object value = file.object();
    Json::Array selected;
    const auto& items = result.get("results")->array();
    const size_t first = std::min(static_cast<size_t>(file.get("result_offset")->integer()), items.size());
    const size_t count = std::min(static_cast<size_t>(file.get("result_count")->integer()), items.size() - first);
    for (size_t i = 0; i < count; ++i) selected.push_back(items[first + i]);
    value.erase("result_offset"); value.erase("result_count");
    value["results"] = std::move(selected);
    return value;
}

std::string semantic_read_notes(const Json& result) {
    std::string out;
    if (const Json* partial = result.get("partial"); partial && partial->boolean())
        out += "[partial results: the language server is still indexing]\n";
    if (const Json* errors = result.get("errors"))
        for (const auto& error : errors->array())
            out += "[error " + error.get("path")->string() + ": " + error.get("error")->string() + "]\n";
    if (const Json* fallback = result.get("fallback_text")) out += fallback->string();
    return out;
}

std::string compact_outline(const Json& result, bool symbol_text = false) {
    if (const Json* files = result.get("files")) {
        std::string out;
        for (const auto& file : files->array()) {
            if (!file.get("path") && file.get("requested_path"))
                out += "[scope " + file.get("requested_path")->string() + "]\n";
            out += compact_outline(semantic_file_result(result, file), symbol_text);
        }
        return out + semantic_read_notes(result);
    }
    static constexpr const char* kinds[] = {"unknown", "file", "module", "namespace", "package", "class", "method", "property",
        "field", "constructor", "enum", "interface", "function", "variable", "constant", "string", "number", "boolean",
        "array", "object", "key", "null", "enumMember", "struct", "event", "operator", "typeParameter"};
    const Json* items = result.get("results");
    const size_t count = items ? items->array().size() : 0;
    std::string out;
    const Json* file = result.get("path");
    if (file) {
        out = "[outline " + file->string() + " | " + std::to_string(count) + " symbols";
        if (const Json* mtime = result.get("mtime")) out += " | mtime " + mtime->string();
        if (const Json* sha = result.get("sha256")) out += " | sha256 " + sha->string();
        out += " | source: lsp]\n";
    } else {
        std::set<std::string> files;
        if (items) for (const auto& item : items->array()) if (const Json* p = item.get("path")) files.insert(p->string());
        out = "[outline | " + std::to_string(count) + " symbols in " + std::to_string(files.size()) + " files | source: lsp]\n";
    }
    std::string current, current_parent;
    bool parent_shown = false;
    if (items) for (const auto& item : items->array()) {
        const Json* path = item.get("path");
        if (!file && path && path->string() != current) {
            current = path->string();
            parent_shown = false;
            out += current + "\n";
        }
        const Json* kind = item.get("kind");
        const int64_t k = kind && std::holds_alternative<int64_t>(kind->value) ? kind->integer() : 0;
        const Json* range = item.get("range");
        const int64_t first = range && range->get("start_line") ? range->get("start_line")->integer()
            : (item.get("line") ? item.get("line")->integer() : 0);
        int64_t last = range && range->get("end_line") ? range->get("end_line")->integer() : first;
        if (range && range->get("end_column") && range->get("end_column")->integer() == 1 && last > first) --last;
        const Json* kind_name = item.get("kind_name");
        const std::string shown_kind = kind_name && std::holds_alternative<std::string>(kind_name->value)
            ? kind_name->string() : kinds[k >= 1 && k <= 26 ? k : 0];
        const std::string name_path = item.get("name_path") ? item.get("name_path")->string() : "";
        const size_t slash = name_path.rfind('/');
        const std::string parent = slash == std::string::npos ? "" : name_path.substr(0, slash);
        const std::string name = slash == std::string::npos ? name_path : name_path.substr(slash + 1);
        if (!parent_shown || parent != current_parent) {
            if (!parent.empty()) out += (file ? "" : "  ") + std::string("[inside ") + parent + "]\n";
            else if (parent_shown && !current_parent.empty()) out += (file ? "" : "  ") + std::string("[top level]\n");
            current_parent = parent;
            parent_shown = true;
        }
        out += (file ? "" : "  ") + shown_kind + " " + name + " L" + std::to_string(first) + "-" + std::to_string(last);
        if (const Json* line_text = symbol_text ? item.get("line_text") : nullptr;
            line_text && std::holds_alternative<std::string>(line_text->value)) {
            const std::string& shown = line_text->string();
            const size_t start = shown.find_first_not_of(" \t");
            if (start != std::string::npos) out += " | " + shown.substr(start, 200);
        }
        out += "\n";
    }
    if (!count) out += "(no symbols)\n";
    return out + semantic_read_notes(result);
}

void slice_symbol_bodies(Json& result, uint64_t first, uint64_t limit,
                         const std::shared_ptr<std::atomic_bool>& cancelled) {
    auto& object = std::get<Json::Object>(result.value);
    auto found = object.find("results");
    if (found == object.end()) return;
    for (auto& item : std::get<Json::Array>(found->second.value)) {
        if (cancelled && cancelled->load()) fail("symbol read cancelled");
        if (Clock::now() >= request_deadline(Clock::time_point::max())) fail("symbol read timed out");
        const Json* body_value = item.get("body");
        if (!body_value) continue;
        const std::string original = body_value->string();
        const auto next_line = [&](size_t at) {
            const size_t end = original.find_first_of("\r\n", at);
            if (end == std::string::npos) return original.size();
            return end + ((original[end] == '\r' && end + 1 < original.size() && original[end + 1] == '\n') ? 2 : 1);
        };
        uint64_t lines = 0;
        for (size_t at = 0; at < original.size(); at = next_line(at)) {
            if ((lines & 1023) == 0) {
                if (cancelled && cancelled->load()) fail("symbol read cancelled");
                if (Clock::now() >= request_deadline(Clock::time_point::max())) fail("symbol read timed out");
            }
            ++lines;
        }
        if (first > lines + 1) fail("symbol offset is beyond its body");
        size_t begin = 0;
        for (uint64_t line = 1; line < first && begin < original.size(); ++line) {
            if ((line & 1023) == 0) {
                if (cancelled && cancelled->load()) fail("symbol read cancelled");
                if (Clock::now() >= request_deadline(Clock::time_point::max())) fail("symbol read timed out");
            }
            begin = next_line(begin);
        }
        size_t end = begin;
        uint64_t shown = 0;
        while (end < original.size() && shown < limit) {
            if (cancelled && cancelled->load()) fail("symbol read cancelled");
            if (Clock::now() >= request_deadline(Clock::time_point::max())) fail("symbol read timed out");
            ++shown;
            end = next_line(end);
        }
        const Json* range = item.get("range");
        const int64_t start = range && range->get("start_line")
            ? range->get("start_line")->integer() : (item.get("line") ? item.get("line")->integer() : 1);
        auto& fields = std::get<Json::Object>(item.value);
        fields["body"] = original.substr(begin, end - begin);
        fields["body_start_line"] = start + static_cast<int64_t>(first - 1);
        fields["body_end_line"] = start + static_cast<int64_t>(first - 1 + shown) - 1;
        fields["body_complete"] = begin == 0 && end == original.size();
        if (end < original.size()) fields["next_offset"] = first + shown;
        if (auto actual = fields.find("body_range"); actual != fields.end()) {
            auto& coordinates = std::get<Json::Object>(actual->second.value);
            const int64_t slice_line = start + static_cast<int64_t>(first - 1);
            if (begin == end && begin == original.size()) {
                coordinates["start_line"] = coordinates.at("end_line");
                coordinates["start_column"] = coordinates.at("end_column");
                fields["body_start_line"] = coordinates.at("end_line");
                fields["body_end_line"] = coordinates.at("end_line").integer() - 1;
                continue;
            }
            coordinates["start_line"] = slice_line;
            coordinates["start_column"] = 1;
            int64_t end_line = slice_line;
            size_t last_start = begin;
            for (size_t pos = begin; pos < end;) {
                if (original[pos] == '\r' || original[pos] == '\n') {
                    if (original[pos] == '\r' && pos + 1 < end && original[pos + 1] == '\n') ++pos;
                    ++end_line;
                    last_start = ++pos;
                } else ++pos;
            }
            const size_t length = end - last_start;
            const int columns = length ? MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                original.data() + last_start, static_cast<int>(length), nullptr, 0) : 0;
            if (length && columns == 0) fail("symbol body contains invalid UTF-8");
            coordinates["end_line"] = end_line;
            coordinates["end_column"] = static_cast<int64_t>(columns) + 1;
        }
    }
}

Json read_file(const Json& args, const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled) {
    const std::vector<std::string> paths = path_args(args);
    ReadOptions options;
    options.cancelled = cancelled;
    options.offset = static_cast<uint64_t>(int_arg(args, "offset", 1, 1, INT64_MAX));
    options.limit = args.get("limit") ? static_cast<uint64_t>(int_arg(args, "limit", 1, 1, INT64_MAX)) : UINT64_MAX;
    options.numbers = bool_arg(args, "line_numbers", false);
    const std::string operation = args.get("operation") ? string_arg(args, "operation") : "auto";
    if (operation != "auto" && operation != "text" && operation != "overview" && operation != "symbol")
        fail("read_file operation must be auto, text, overview, or symbol");
    if (operation == "text" && args.get("name_path")) fail("operation=text does not accept name_path");
    const bool requested_json = outline_format(args) == "json";
    const bool symbol_read = operation == "symbol" || args.get("name_path");
    if (args.get("full_lines") && bool_arg(args, "full_lines", false) && !symbol_read)
        fail("full_lines requires a symbol read");
    if (args.get("format") && (operation == "text" || (!symbol_read && (args.get("offset") || args.get("limit")))))
        fail("format is only for symbol reads and overviews");
    const bool text_mode = !symbol_read && (operation == "text" || args.get("offset") || args.get("limit"));
    // COMPAT: outline_first is still accepted and type-checked; code-file text reads now always get the outline.
    (void)bool_arg(args, "outline_first", false);
    const bool json_format = requested_json && !text_mode;
    if (text_mode && (args.get("depth") || args.get("include_kinds") || args.get("exclude_kinds")))
        fail("depth/include_kinds/exclude_kinds require a symbol read");
    if ((args.get("offset") || args.get("limit")) && operation == "overview")
        fail("offset/limit require text or symbol reads");
    std::string out, access_note, common_folder;
    if (paths.size() > 1) {
        try {
            std::wstring folder;
            bool shared = true;
            for (const auto& path : paths) {
                const Target target = resolve(context, path);
                if (target.parts.empty()) { shared = false; break; }
                const std::wstring parent = target.full(target.parts.size() - 1);
                if (folder.empty()) folder = parent;
                else if (!same_name(folder, parent.c_str())) { shared = false; break; }
            }
            if (shared) try_utf8(folder, common_folder);
        } catch (const std::exception&) {
            common_folder.clear();  // Per-path errors are still handled by the normal read loop.
        }
    }
    bool folder_shown = false;
    bool semantic_attempted = false;
    Json::Array semantic_results, semantic_files, errors;
    auto add_note = [&](const std::string& note) { out += note; access_note += note; };
    for (const auto& path : paths) {
        if (cancelled && cancelled->load()) fail("read_file cancelled");
        bool path_semantic = false;
        auto read = [&] {
            const bool allow_fallback = bool_arg(args, "allow_text_fallback", false);
            bool directory = false;
            const SourceText descriptor = source_descriptor(context, path, &directory);
            // CONTRACT: a code file is read only through LSP. A text read of one (operation=text, offset, limit) gets
            //   its outline; plain text needs allow_text_fallback=true and a failing server (see lsp_read_required).
            const bool redirected = text_mode && !symbol_read && !directory && lsp_read_required(descriptor.path);
            const bool semantic = redirected || (!text_mode && (directory || operation != "auto" ||
                                                  args.get("name_path") || lsp_required(descriptor.path)));
            if (semantic) {
                path_semantic = true;
                semantic_attempted = true;
                if (operation == "symbol" && !args.get("name_path")) fail("symbol read requires name_path");
                if (args.get("line_numbers") && !redirected && !symbol_read)
                    fail("line_numbers is only for text or symbol reads");
                Json::Object query = args.object();
                query.erase("paths"); query.erase("format"); query.erase("allow_text_fallback"); query["path"] = path;
                query.erase("offset"); query.erase("limit"); query.erase("outline_first");
                if (redirected || symbol_read) query.erase("line_numbers");
                query["include_body"] = symbol_read;
                if (symbol_read && !directory) query["require_match"] = true;
                try {
                    Json result = lsp_query(symbol_read ? "symbols" : "overview", query, context, cancelled);
                    if (symbol_read) slice_symbol_bodies(result, options.offset, options.limit, cancelled);
                    if (symbol_read || json_format) {
                        Json::Object metadata = result.object();
                        if (paths.size() > 1) metadata["requested_path"] = path;
                        metadata["result_offset"] = static_cast<uint64_t>(semantic_results.size());
                        const Json* items = result.get("results");
                        metadata["result_count"] = static_cast<uint64_t>(items ? items->array().size() : 0);
                        if (items) for (const auto& item : items->array()) semantic_results.push_back(item);
                        metadata.erase("results");
                        semantic_files.emplace_back(std::move(metadata));
                    } else {
                        if (redirected && (args.get("offset") || args.get("limit")))
                            out += "[" + path + ": code files are read through LSP, so offset/limit were not applied; "
                                   "read one symbol with lsp method=lsp.read_symbol]\n";
                        out += compact_outline(result);
                    }
                    return;
                } catch (const LspFailure& e) {
                    // Symbol-relative offsets have no meaning without a
                    // successfully resolved symbol; never apply them to the file.
                    if (directory || !allow_fallback || (symbol_read && (args.get("offset") || args.get("limit")))) throw;
                    if ((cancelled && cancelled->load()) || Clock::now() >= request_deadline(Clock::time_point::max())) throw;
                    add_note(lsp_failure_banner(e.what(), "Explicit text fallback for " + path));
                }
            }
            ReadOptions text_options = options;
            if (!args.get("limit")) text_options.limit = 100;
            const Target target = resolve(context, path);
            std::string header_path = target.display();
            std::string basename;
            if (!common_folder.empty() && !target.parts.empty() && try_utf8(target.name(), basename)) {
                if (!folder_shown) { out += "[folder " + common_folder + "]\n"; folder_shown = true; }
                header_path = std::move(basename);
            }
            render_file(out, target, text_options, header_path, context);
        };
        if (!args.get("paths")) read();
        else {
            try { read(); }
            catch (const IndexWarmingFailure& e) {
                Json details = e.details;
                if (std::holds_alternative<Json::Object>(details.value)) std::get<Json::Object>(details.value)["path"] = path;
                throw IndexWarmingFailure(path + ": " + e.what(), std::move(details));
            }
            catch (const SymbolLookupFailure& e) {
                Json details = e.details;
                if (std::holds_alternative<Json::Object>(details.value)) std::get<Json::Object>(details.value)["path"] = path;
                throw SymbolLookupFailure(path + ": " + e.what(), std::move(details));
            }
            catch (const LspFailure& e) {
                errors.emplace_back(Json::Object{{"path", path}, {"error", e.what()}});
                if (!symbol_read && (!json_format || !path_semantic)) add_note(lsp_failure_banner(path + ": " + e.what(),
                    "No automatic text fallback; use allow_text_fallback=true for files (folders have no text form)"));
            }
            catch (const std::exception& e) {
                errors.emplace_back(Json::Object{{"path", path}, {"error", e.what()}});
                if (!symbol_read && (!json_format || !path_semantic)) add_note("[error " + std::string(e.what()) + "]\n");
            }
        }
    }
    if (!semantic_files.empty() || ((symbol_read || (json_format && semantic_attempted)) && !errors.empty())) {
        Json::Object combined;
        if (paths.size() == 1 && semantic_files.size() == 1 && errors.empty() && out.empty()) {
            combined = semantic_files.front().object();
            combined.erase("result_offset"); combined.erase("result_count");
        } else {
            bool partial = false;
            for (const auto& file : semantic_files)
                if (const Json* value = file.get("partial"); value && value->boolean()) partial = true;
            combined = Json::Object{{"backend", "lsp"}, {"files", std::move(semantic_files)},
                                    {"errors", std::move(errors)}, {"partial", partial}};
            if (!out.empty()) combined["fallback_text"] = std::move(out);
        }
        combined["results"] = std::move(semantic_results);
        return Json::Object{{"structured_result", std::move(combined)}};
    }
    return Json::Object{{"text", std::move(out)}, {"access_note", std::move(access_note)}};
}

// ---- file_info ----

void info_one(std::string& out, const SearchContext& context, const std::string& requested) {
    const Target target = resolve(context, requested);
    const std::string path = target.display();
    Handle directory = target.parts.empty() ? Handle() : open_parent(target, false);
    Handle item;
    if (target.parts.empty()) item = open_root(target);
    else {
        const NTSTATUS status = nt_open(directory.h, target.name(), FILE_READ_ATTRIBUTES, share_all, disposition_open,
                                        option_open_reparse_point, 0, item);
        if (status < 0) fail(path + ": " + status_text(status));
    }
    const DWORD attributes = attributes_of(item.h, path);
    const FILE_BASIC_INFO basic = basic_info(item.h, path);
    out += "[info " + path + "]\n";
    static constexpr std::pair<DWORD, const char*> named_flags[] = {
        {FILE_ATTRIBUTE_READONLY, "read-only"}, {FILE_ATTRIBUTE_HIDDEN, "hidden"}, {FILE_ATTRIBUTE_SYSTEM, "system"}};
    std::string flags;
    for (const auto& [bit, name] : named_flags)
        if (attributes & bit) flags += (flags.empty() ? "" : ", ") + std::string(name);
    const std::string mtime = "mtime: " + format_mtime(basic.LastWriteTime.QuadPart) + "\n";
    const std::string flag_line = flags.empty() ? "" : "attributes: " + flags + "\n";
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        out += "type: link (symbolic link, junction or other reparse point; not followed)\n" + mtime + flag_line;
        return;
    }
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        out += "type: directory\n" + mtime + flag_line;
        return;
    }
    item.close();
    Handle file = open_file(directory.h, target, share_all);
    LARGE_INTEGER size{};
    GetFileSizeEx(file.h, &size);
    out += "type: file\nsize: " + std::to_string(size.QuadPart) + " bytes\n" + mtime + flag_line;
    std::string raw;
    if (!read_all(file.h, path, max_text_bytes, raw)) {
        out += "content: not inspected (over 64 MiB)\n";
        return;
    }
    const TextFile text = decode(raw);
    if (context.record_user_reads)
        remember_read_snapshot(context, fs::path(target.full(target.parts.size())), sha256_hex(raw));
    if (text.binary) {
        out += "binary: yes (NUL byte at offset " + std::to_string(text.nul_offset) + ")\nsha256: " + sha256_hex(raw) + "\n";
        return;
    }
    out += "binary: no\nencoding: " + std::string(encoding_name(text.encoding)) +
           (text.invalid ? " (" + std::to_string(text.invalid) + " invalid byte sequences)" : "") +
           "\nlines: " + std::to_string(text.lines) + "\nline_endings: " + eol_name(text) +
           "\nfinal_newline: " + (text.final_newline ? "yes" : "no") + "\nsha256: " + sha256_hex(raw) + "\n";
}

Json file_info(const Json& args, const SearchContext& context) {
    const std::vector<std::string> paths = path_args(args);
    Budget budget(max_output_arg(args));
    std::string out;
    for (size_t i = 0; i < paths.size(); ++i) {
        std::string one;
        if (paths.size() == 1 && !args.get("paths")) info_one(one, context, paths[i]);
        else {
            try { info_one(one, context, paths[i]); }
            catch (const IndexWarmingFailure& e) {
                Json details = e.details;
                if (std::holds_alternative<Json::Object>(details.value)) std::get<Json::Object>(details.value)["path"] = paths[i];
                throw IndexWarmingFailure(paths[i] + ": " + e.what(), std::move(details));
            }
            catch (const SymbolLookupFailure& e) {
                Json details = e.details;
                if (std::holds_alternative<Json::Object>(details.value)) std::get<Json::Object>(details.value)["path"] = paths[i];
                throw SymbolLookupFailure(paths[i] + ": " + e.what(), std::move(details));
            }
            catch (const std::exception& e) { one = "[error " + std::string(e.what()) + "]\n"; }
        }
        if (!budget.fits(one)) {
            std::string unread;
            for (size_t j = i; j < paths.size(); ++j) unread += (unread.empty() ? "" : ", ") + paths[j];
            out += "[status output_limit: max_output_bytes=" + std::to_string(budget.max_output) +
                   " reached; not shown: " + unread + "]\n";
            break;
        }
        budget.take(one);
        out += one;
    }
    return Json::Object{{"text", std::move(out)}};
}

// ---- list_dir ----

struct Listing {
    bool hidden = false, no_ignore = false;
    uint64_t max_entries = 500;
    Budget budget{65536};
    Clock::time_point deadline;
    const std::shared_ptr<std::atomic_bool>* cancelled = nullptr;
    std::vector<uint64_t> buffer = std::vector<uint64_t>((64 * 1024) / sizeof(uint64_t));
    std::string out;
    uint64_t entries = 0, hidden_skipped = 0, ignored_skipped = 0, errors = 0;
    std::string status;  // empty while the listing is complete
};

// Lists directory, then descends into each subdirectory right after its own line, while depth allows.
// CONTRACT: same selection as search's walker: hidden items and .gitignore/.ignore matches are skipped unless
// asked for, reparse points are listed but never entered.
void list_tree(Listing& s, HANDLE directory, const std::wstring& path, const std::string& relative,
               const std::string& ignore_relative, std::shared_ptr<const IgnoreScope> scope, uint32_t depth) {
    std::vector<DirEntry> entries;
    if (!list_directory(directory, s.buffer, entries)) ++s.errors;
    if (!s.no_ignore) {
        bool gitignore = false, dotignore = false, git_dir = false;
        for (const auto& entry : entries) note_rule_file(entry.name, entry.attributes, gitignore, dotignore, git_dir);
        if (gitignore || dotignore || git_dir) {
            auto next = std::make_shared<IgnoreScope>();
            next->parent = scope;
            read_ignore_rules(path, ignore_relative, gitignore, dotignore, next->rules, directory, git_dir);
            if (!next->rules.empty()) scope = std::move(next);
        }
    }
    std::sort(entries.begin(), entries.end(), [](const DirEntry& a, const DirEntry& b) {
        const int order = CompareStringOrdinal(a.name.data(), static_cast<int>(a.name.size()), b.name.data(),
                                               static_cast<int>(b.name.size()), TRUE);
        return order == CSTR_LESS_THAN || (order == CSTR_EQUAL && a.name < b.name);
    });
    std::string name, child, line;
    for (const auto& entry : entries) {
        if (!s.status.empty()) return;
        if (s.cancelled && *s.cancelled && (*s.cancelled)->load()) { s.status = "cancelled"; return; }
        if (Clock::now() > s.deadline) { s.status = "timeout"; return; }
        if (!try_utf8(entry.name, name) || name.empty()) { ++s.errors; continue; }
        const bool is_directory = (entry.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        const bool link = (entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        child = relative == "." ? name : relative + "/" + name;
        if (!s.hidden && (name.front() == '.' || (entry.attributes & FILE_ATTRIBUTE_HIDDEN))) { ++s.hidden_skipped; continue; }
        const std::string ignore_child = ignore_relative.empty() ? name : ignore_relative + "/" + name;
        if (!s.no_ignore && ignored_path(scope.get(), ignore_child, is_directory)) { ++s.ignored_skipped; continue; }
        if (link) line = "l " + child + (is_directory ? "/" : "") + "\n";
        else if (is_directory) line = "d " + child + "/\n";
        else line = "f " + child + " " + std::to_string(entry.size) + "\n";
        if (s.entries >= s.max_entries) { s.status = "limit"; return; }
        if (!s.budget.fits(line)) { s.status = "output_limit"; return; }
        s.budget.take(line);
        s.out += line;
        ++s.entries;
        if (!is_directory || link || depth <= 1) continue;
        bool denied = false;
        Handle sub(open_relative(directory, entry.name, true, denied));
        if (!sub) { ++s.errors; continue; }
        list_tree(s, sub.h, join_path(path, entry.name), child, ignore_child, scope, depth - 1);
    }
}

Json list_dir(const Json& args, const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled) {
    const Target target = resolve(context, args.get("path") ? string_arg(args, "path") : std::string("."));
    const auto depth = static_cast<uint32_t>(int_arg(args, "depth", 1, 1, 32));
    Listing s;
    // CONTRACT: list_dir applies search's filters by default; hidden true and no_ignore true opt out of them.
    s.hidden = bool_arg(args, "hidden", false);
    s.no_ignore = bool_arg(args, "no_ignore", false);
    s.max_entries = args.get("max_results") ? static_cast<uint64_t>(int_arg(args, "max_results", 500, 1, 10000)) : UINT64_MAX;
    s.budget = Budget(max_output_arg(args));
    const auto timeout = int_arg(args, "timeout_ms", 30000, 1, 300000);
    s.deadline = Clock::now() + std::chrono::milliseconds(timeout);
    s.cancelled = &cancelled;
    const std::string path = target.display();
    Handle directory = open_root(target);
    std::shared_ptr<const IgnoreScope> scope;
    std::string ignore_relative;
    // CONTRACT: ignore coordinates stay relative to the configured root; output stays relative to the listing.
    for (size_t i = 0; i < target.parts.size(); ++i) {
        if (cancelled && cancelled->load()) fail("request cancelled");
        if (Clock::now() > s.deadline) fail("listing timed out while opening its directory");
        if (!s.no_ignore) {
            auto ancestor = std::make_shared<IgnoreScope>();
            ancestor->parent = scope;
            read_ignore_rules(final_path(directory.h), ignore_relative, true, true, ancestor->rules, directory.h);
            if (!ancestor->rules.empty()) scope = std::move(ancestor);
        }
        Handle child;
        const NTSTATUS status = nt_open(directory.h, target.parts[i], directory_access, share_all, disposition_open,
                                        option_directory | option_open_reparse_point, 0, child);
        if (status == status_not_directory) fail(path + " is a file; use read_file or file_info");
        if (status < 0) fail(path + ": " + status_text(status));
        refuse_link(child.h, target.display(i + 1));
        directory = std::move(child);
        ignore_relative = target.relative(i + 1);
    }
    const std::string header = "[dir " + path + " | depth " + std::to_string(depth) + "]\n";
    s.budget.take(header);
    list_tree(s, directory.h, final_path(directory.h), ".", ignore_relative, scope, depth);
    std::string out = header + s.out;
    if (s.entries == 0 && s.status.empty()) out += "(no entries shown)\n";
    if (s.hidden_skipped || s.ignored_skipped) {
        out += "[not shown:";
        if (s.hidden_skipped) out += " " + std::to_string(s.hidden_skipped) + " hidden (hidden: false hid them)";
        if (s.ignored_skipped)
            out += std::string(s.hidden_skipped ? "," : "") + " " + std::to_string(s.ignored_skipped) +
                   " ignored by .gitignore/.ignore/.shignore (no_ignore: false hid them)";
        out += "]\n";
    }
    if (s.errors) out += "[" + std::to_string(s.errors) + " entries or directories could not be read]\n";
    if (s.status == "limit")
        out += "[status limit: stopped at max_results=" + std::to_string(s.max_entries) +
               " entries; list a subdirectory, lower depth or raise max_results]\n";
    else if (s.status == "output_limit")
        out += "[status output_limit: stopped at max_output_bytes=" + std::to_string(s.budget.max_output) +
               "; list a subdirectory or lower depth]\n";
    else if (s.status == "timeout")
        out += "[status timeout: stopped after " + std::to_string(timeout) + " ms; the listing is partial]\n";
    else if (s.status == "cancelled") out += "[status cancelled: the listing is partial]\n";
    return Json::Object{{"text", std::move(out)}};
}

// ---- Atomic writes ----

// CONTRACT: serializes this process's writes, so concurrent requests cannot interleave read-modify-write cycles.
std::mutex& write_mutex() {
    static std::mutex mutex;
    return mutex;
}

// FILE_RENAME_INFORMATION (ntifs.h). Its first member is the BOOLEAN ReplaceIfExists for FileRenameInformation and
// the ULONG Flags of FileRenameInformationEx (Windows 10 1607).
struct RenameInfo {
    DWORD flags;
    HANDLE root;
    DWORD name_bytes;
    WCHAR name[1];
};
static_assert(offsetof(RenameInfo, root) == offsetof(FILE_RENAME_INFO, RootDirectory));
static_assert(offsetof(RenameInfo, name) == offsetof(FILE_RENAME_INFO, FileName));
constexpr DWORD rename_replace_if_exists = 0x1, rename_posix_semantics = 0x2;
constexpr ULONG file_rename_information = 10, file_rename_information_ex = 65;

// COMPAT: kernel32's SetFileInformationByHandle(FileRenameInfo) expands FileName against the process's current
// directory before renaming, so a bare name moved the file into the working directory and a RootDirectory handle
// was rejected as an invalid parameter. NtSetInformationFile takes the name as given, relative to RootDirectory.
using NtSetInformationFileFn = NTSTATUS(NTAPI*)(HANDLE, IO_STATUS_BLOCK*, void*, ULONG, ULONG);
NtSetInformationFileFn nt_set_information_file() {
    static const auto function = reinterpret_cast<NtSetInformationFileFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
    return function;
}

// Renames the open item to name inside the open directory target_directory. Returns 0 or a Win32 error. original,
// when given, is an open handle to the file being replaced.
// CONTRACT: name is a single component; the target is reached through the directory handle, never a path string.
DWORD rename_handle(HANDLE item, HANDLE target_directory, const std::wstring& name, bool replace, Handle* original) {
    const NtSetInformationFileFn set_information = nt_set_information_file();
    if (!set_information) return ERROR_PROC_NOT_FOUND;
    std::vector<unsigned char> buffer(sizeof(RenameInfo) + name.size() * sizeof(wchar_t));
    auto* info = reinterpret_cast<RenameInfo*>(buffer.data());
    info->root = target_directory;
    info->name_bytes = static_cast<DWORD>(name.size() * sizeof(wchar_t));
    std::memcpy(info->name, name.data(), info->name_bytes);
    // POSIX semantics replace a target that is still open (with delete sharing), such as our own original handle.
    info->flags = rename_posix_semantics | (replace ? rename_replace_if_exists : 0);
    const auto size = static_cast<ULONG>(buffer.size());
    IO_STATUS_BLOCK io{};
    NTSTATUS status = set_information(item, &io, info, size, file_rename_information_ex);
    if (status >= 0) return 0;
    const auto code = static_cast<uint32_t>(status);
    // STATUS_INVALID_PARAMETER, STATUS_INVALID_INFO_CLASS, STATUS_NOT_SUPPORTED
    if (code != 0xC000000D && code != 0xC0000003 && code != 0xC00000BB) return RtlNtStatusToDosError(status);
    // COMPAT: FAT, exFAT and Windows before 10 1607 lack POSIX renames, and a plain rename cannot replace an open
    // file, so the original handle is released first.
    if (original) original->close();
    info->flags = replace ? 1 : 0;
    status = set_information(item, &io, info, size, file_rename_information);
    return status >= 0 ? 0 : RtlNtStatusToDosError(status);
}

std::string rename_error(DWORD code) {
    if (code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS) return "already exists; pass overwrite: true to replace it";
    if (code == ERROR_NOT_SAME_DEVICE) return "the destination is on another volume, which move_file does not support";
    if (code == ERROR_ACCESS_DENIED)
        return "access denied (the target may be read-only, a directory, or open in another program)";
    return win32_text(code);
}

// Deletes the temporary file on close unless disarmed.
struct DiscardOnFailure {
    HANDLE handle;
    bool armed = true;
    ~DiscardOnFailure() {
        if (!armed) return;
        FILE_DISPOSITION_INFO info{TRUE};
        SetFileInformationByHandle(handle, FileDispositionInfo, &info, sizeof(info));
    }
};

// Writes bytes to a new temporary file beside the target, flushes it, then renames it onto the target. With
// replace false the rename fails if the target exists, so creating never clobbers a file that appeared meanwhile.
// Readers therefore see the old contents or the new ones, never a partial file.
struct StagedWrite {
    Handle file;
    bool armed = true;
    ~StagedWrite() {
        if (armed && file) {
            FILE_DISPOSITION_INFO info{TRUE};
            SetFileInformationByHandle(file.h, FileDispositionInfo, &info, sizeof(info));
        }
    }
};
// SAFETY: a replacement takes the original's DACL, including whether it is protected from inheritance, so an edit
//   never widens access to the folder's inherited permissions. Volumes without ACLs (FAT, exFAT) have none to copy.
void copy_permissions(HANDLE from, HANDLE to, const std::string& path) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    DWORD code = GetSecurityInfo(from, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &descriptor);
    if (code == ERROR_NOT_SUPPORTED || code == ERROR_INVALID_FUNCTION) return;
    if (code != ERROR_SUCCESS) fail(path + ": cannot read its permissions (" + win32_text(code) + "); nothing was written");
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision)) control = 0;
    const SECURITY_INFORMATION what = DACL_SECURITY_INFORMATION |
        ((control & SE_DACL_PROTECTED) ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
    code = SetSecurityInfo(to, SE_FILE_OBJECT, what, nullptr, nullptr, dacl, nullptr);
    LocalFree(descriptor);
    if (code != ERROR_SUCCESS) fail(path + ": cannot carry its permissions over (" + win32_text(code) + "); nothing was written");
}

std::unique_ptr<StagedWrite> stage_write(HANDLE directory, const Target& target, const std::string& bytes,
                                          DWORD attributes, HANDLE permissions_from = nullptr,
                                          const CancelFlag& cancelled = {}) {
    check_cancelled(cancelled);
    static std::atomic<uint32_t> counter{0};
    const std::string path = target.display();
    auto staged = std::make_unique<StagedWrite>();
    Handle& temp = staged->file;
    for (int attempt = 0;; ++attempt) {
        const std::wstring temp_name = L".shgrep-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                       std::to_wstring(++counter) + L".tmp";
        const NTSTATUS status = nt_open(directory, temp_name, DELETE | WRITE_DAC | FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES, 0,
                                        disposition_create, option_non_directory,
                                        attributes ? attributes : FILE_ATTRIBUTE_NORMAL, temp);
        if (status >= 0) break;
        if (status != status_collision || attempt == 8)
            fail(path + ": cannot create a temporary file in its folder (" + status_text(status) +
                 "); nothing was written");
    }
    if (permissions_from) copy_permissions(permissions_from, temp.h, path);
    for (size_t offset = 0; offset < bytes.size();) {
        check_cancelled(cancelled);
        const auto chunk = static_cast<DWORD>(std::min<size_t>(bytes.size() - offset, size_t{1} << 24));
        DWORD written = 0;
        if (!WriteFile(temp.h, bytes.data() + offset, chunk, &written, nullptr) || written == 0) {
            const DWORD code = GetLastError();
            fail(path + ": write failed (" + win32_text(code) + "); nothing was written");
        }
        offset += written;
    }
    check_cancelled(cancelled);
    if (!FlushFileBuffers(temp.h)) {
        const DWORD code = GetLastError();
        fail(path + ": flush failed (" + win32_text(code) + "); nothing was written");
    }
    return staged;
}
bool same_file(HANDLE a, HANDLE b) {
    FILE_ID_INFO x{}, y{};
    if (GetFileInformationByHandleEx(a, FileIdInfo, &x, sizeof(x)) && GetFileInformationByHandleEx(b, FileIdInfo, &y, sizeof(y)))
        return x.VolumeSerialNumber == y.VolumeSerialNumber && std::memcmp(&x.FileId, &y.FileId, sizeof(x.FileId)) == 0;
    BY_HANDLE_FILE_INFORMATION p{}, q{};  // volumes without 128-bit file ids
    return GetFileInformationByHandle(a, &p) && GetFileInformationByHandle(b, &q) &&
           p.dwVolumeSerialNumber == q.dwVolumeSerialNumber && p.nFileIndexHigh == q.nFileIndexHigh &&
           p.nFileIndexLow == q.nFileIndexLow;
}
// SAFETY: the original stays open with share-delete, so another program can rename a new file over its path, as an
//   editor's atomic save does. The commit goes ahead only while the path still names the file whose bytes were
//   checked; otherwise that save would be silently overwritten.
void require_unreplaced(HANDLE directory, const Target& target, HANDLE original) {
    Handle current;
    const NTSTATUS status = nt_open(directory, target.name(), FILE_READ_ATTRIBUTES, share_all, disposition_open,
                                    option_open_reparse_point, 0, current);
    if (status < 0 || !same_file(current.h, original))
        fail(target.display() + " was replaced by another program after it was read; read it again. Nothing was written");
}

// SAFETY: replaces target with the staged file only while target still names original, with no check/use gap.
//   1. The checked file is reopened by name with delete access while denying delete sharing, and must be the same
//      file as original. From then on no other program can rename, replace or delete it.
//   2. That locked handle moves the original aside, so only the checked file can move.
//   3. The staged file takes the free name without replace semantics. If another program created the name in that
//      instant, its version is kept; the original returns when the name is still free, else stays beside it.
//   Readers can see the name absent for that instant; they never see a partial file. Returns a cleanup warning, or
//   an empty string. Throws when nothing was changed or both versions were kept.
std::string commit_over(HANDLE directory, const Target& target, HANDLE staged, HANDLE original) {
    Handle locked;
    // Write sharing stays open: in-place writers were never excluded, and a replacing commit always needed every other
    // handle to share delete. Denying delete sharing is what stops a rename or replacement of the checked file.
    const NTSTATUS status = nt_open(directory, target.name(), DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    disposition_open, option_non_directory | option_open_reparse_point, 0, locked);
    if (static_cast<uint32_t>(status) == 0xC0000043)
        fail(target.display() + " is open in another program that blocks replacing it; close it and retry. This file was not changed");
    if (status < 0 || !same_file(locked.h, original))
        fail(target.display() + " was replaced by another program after it was read; read it again. This file was not changed");
    static std::atomic<uint32_t> counter{0};
    std::wstring aside;
    for (int attempt = 0;; ++attempt) {
        aside = L".shgrep-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(++counter) + L".old";
        const DWORD code = rename_handle(locked.h, directory, aside, false, nullptr);
        if (!code) break;
        if ((code != ERROR_ALREADY_EXISTS && code != ERROR_FILE_EXISTS) || attempt == 8)
            fail(target.display() + ": " + rename_error(code) + "; this file was not changed");
    }
    if (const DWORD code = rename_handle(staged, directory, target.name(), false, nullptr)) {
        if (!rename_handle(locked.h, directory, target.name(), false, nullptr))
            fail(target.display() + ": " + rename_error(code) + "; this file was not changed");
        std::string kept;
        try_utf8(aside, kept);
        fail(target.display() + ": another program created this file during the commit; its version was kept and the "
             "previous contents remain beside it as " + kept + ". This file was not changed by shgrep");
    }
    // The moved-aside original goes when its last handle closes; callers keep their own recovery bytes.
    FILE_DISPOSITION_INFO remove{TRUE};
    if (SetFileInformationByHandle(locked.h, FileDispositionInfo, &remove, sizeof(remove))) return {};
    const DWORD error = GetLastError();
    std::string kept;
    try_utf8(aside, kept);
    return "[warning: " + target.display() + " was replaced; its previous contents could not be removed and remain as " +
           kept + " beside it: " + win32_text(error) + "]\n";
}

// commit_warning, when given, receives a cleanup warning from a replacement commit.
FILE_BASIC_INFO atomic_write(HANDLE directory, const Target& target, const std::string& bytes, bool replace,
                             DWORD attributes, Handle* original, const CancelFlag& cancelled = {},
                             std::string* commit_warning = nullptr) {
    auto staged = stage_write(directory, target, bytes, attributes, original && *original ? original->h : nullptr, cancelled);
    // CONTRACT: cancellation wins until the atomic rename; after commit report the applied change.
    if (replace && original && *original) {
        check_cancelled(cancelled);
        std::string warning = commit_over(directory, target, staged->file.h, original->h);
        staged->armed = false;
        if (commit_warning) *commit_warning += warning;
    } else {
        if (original && *original) require_unreplaced(directory, target, original->h);
        check_cancelled(cancelled);
        if (const DWORD code = rename_handle(staged->file.h, directory, target.name(), replace, original))
            fail(target.display() + ": " + rename_error(code) + "; nothing was written");
        staged->armed = false;
    }
    try { return basic_info(staged->file.h, target.display()); }
    catch (const std::exception&) { return FILE_BASIC_INFO{}; }
}

constexpr DWORD kept_attributes = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE |
                                  FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

std::string hash_file_handle(HANDLE file, const std::string& path, const CancelFlag& cancelled,
                             TextFile* formatting = nullptr) {
    LARGE_INTEGER start{};
    if (!SetFilePointerEx(file, start, nullptr, FILE_BEGIN)) fail(path + ": cannot seek before hashing");
    Sha256 hash;
    bool any_text = false, pending_cr = false;
    uint16_t last = 0;
    int half_unit = -1;
    const auto character = [&](uint16_t c) {
        any_text = true;
        if (!c) formatting->binary = true;
        if (pending_cr) {
            if (c == '\n') ++formatting->crlf;
            else ++formatting->cr;
            pending_cr = false;
        }
        if (c == '\n' && last != '\r') ++formatting->lf;
        if (c == '\r') pending_cr = true;
        last = c;
    };
    const auto consume = [&](std::string_view raw) {
        if (!formatting) return;
        const bool utf16 = formatting->encoding == Encoding::utf16le || formatting->encoding == Encoding::utf16be;
        for (unsigned char c : raw) {
            if (!utf16) character(c);
            else if (half_unit < 0) half_unit = c;
            else {
                character(static_cast<uint16_t>(formatting->encoding == Encoding::utf16le
                    ? half_unit | (c << 8) : (half_unit << 8) | c));
                half_unit = -1;
            }
        }
    };
    if (formatting) {
        *formatting = TextFile{};
        std::string prefix(3, '\0');
        size_t filled = 0;
        while (filled < prefix.size()) {
            check_cancelled(cancelled);
            DWORD got = 0;
            if (!ReadFile(file, prefix.data() + filled, static_cast<DWORD>(prefix.size() - filled), &got, nullptr))
                fail(path + ": cannot read snapshot header: " + win32_text(GetLastError()));
            if (!got) break;
            filled += got;
        }
        prefix.resize(filled);
        hash.add(prefix);
        std::string_view body(prefix);
        if (body.starts_with("\xEF\xBB\xBF")) { formatting->encoding = Encoding::utf8_bom; body.remove_prefix(3); }
        else if (body.starts_with("\xFF\xFE")) { formatting->encoding = Encoding::utf16le; body.remove_prefix(2); }
        else if (body.starts_with("\xFE\xFF")) { formatting->encoding = Encoding::utf16be; body.remove_prefix(2); }
        consume(body);
    }
    std::string buffer(1u << 20, '\0');
    for (;;) {
        check_cancelled(cancelled);
        DWORD got = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &got, nullptr))
            fail(path + ": cannot read snapshot hash: " + win32_text(GetLastError()));
        if (!got) break;
        const std::string_view raw(buffer.data(), got);
        hash.add(raw);
        consume(raw);
    }
    if (formatting) {
        if (pending_cr) ++formatting->cr;
        if (half_unit >= 0) ++formatting->invalid;
        formatting->lines = any_text ? formatting->lf + formatting->crlf + (last == '\n' ? 0 : 1) : 0;
        formatting->final_newline = any_text && (last == '\n' || last == '\r');
    }
    return hash.hex();
}

void check_digest_guards(const Json& args, const std::string& path, const std::string& digest, const FILE_BASIC_INFO& basic) {
    if (args.get("expected_sha256")) {
        std::string expected = string_arg(args, "expected_sha256");
        std::transform(expected.begin(), expected.end(), expected.begin(),
                       [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
        const std::string& actual = digest;
        if (expected != actual)
            fail(path + " changed since it was read: its sha256 is now " + actual + ". Read it again; nothing was "
                 "written.");
    }
    if (args.get("expected_mtime")) {
        const std::string actual = format_mtime(basic.LastWriteTime.QuadPart);
        if (string_arg(args, "expected_mtime") != actual)
            fail(path + " changed since it was read: its mtime is now " + actual + ". Read it again; nothing was "
                 "written.");
    }
}

void check_guards(const Json& args, const std::string& path, const std::string& raw, const FILE_BASIC_INFO& basic) {
    check_digest_guards(args, path, args.get("expected_sha256") ? sha256_hex(raw) : std::string{}, basic);
}

// ---- Unified diff ----

std::vector<std::string_view> split_lines(std::string_view text, const CancelFlag& cancelled = {}) {
    std::vector<std::string_view> lines;
    for (size_t pos = 0; pos < text.size();) {
        check_cancelled(cancelled);
        const size_t newline = text.find('\n', pos);
        const size_t end = newline == std::string_view::npos ? text.size() : newline + 1;
        lines.push_back(text.substr(pos, end - pos));
        pos = end;
    }
    return lines;
}

// Myers' O(ND) shortest edit script over a and b; false when it needs more than max_d edits.
bool myers(const std::string_view* a, int n, const std::string_view* b, int m, int max_d, std::string& script,
           const CancelFlag& cancelled) {
    const int offset = max_d + 1;
    std::vector<int> v(static_cast<size_t>(2 * max_d + 3), 0);
    std::vector<std::vector<int>> trace;  // trace[d][k + d]: furthest x on diagonal k after d edits
    int found = -1;
    for (int d = 0; d <= max_d && found < 0; ++d) {
        check_cancelled(cancelled);
        for (int k = -d; k <= d; k += 2) {
            int x = (k == -d || (k != d && v[offset + k - 1] < v[offset + k + 1])) ? v[offset + k + 1]
                                                                                   : v[offset + k - 1] + 1;
            int y = x - k;
            while (x < n && y < m && a[x] == b[y]) { ++x; ++y; }
            v[offset + k] = x;
            if (x >= n && y >= m) { found = d; break; }
        }
        trace.emplace_back(v.begin() + (offset - d), v.begin() + (offset + d + 1));
    }
    if (found < 0) return false;
    std::string reversed;
    int x = n, y = m;
    for (int d = found; d > 0; --d) {
        const std::vector<int>& prior = trace[static_cast<size_t>(d - 1)];
        auto at = [&](int k) { return prior[static_cast<size_t>(k + d - 1)]; };
        const int k = x - y;
        const int prior_k = (k == -d || (k != d && at(k - 1) < at(k + 1))) ? k + 1 : k - 1;
        const int prior_x = at(prior_k), prior_y = prior_x - prior_k;
        while (x > prior_x && y > prior_y) { reversed.push_back(' '); --x; --y; }
        reversed.push_back(prior_k == k + 1 ? '+' : '-');
        x = prior_x;
        y = prior_y;
    }
    while (x > 0 && y > 0) { reversed.push_back(' '); --x; --y; }
    script.assign(reversed.rbegin(), reversed.rend());
    return true;
}

struct DiffOp {
    char kind;  // ' ' unchanged, '-' removed, '+' added
    size_t a, b;  // line indexes in the old and new text where the op stands
};

struct Diff {
    std::string text;
    uint64_t added = 0, removed = 0;
};

// PERF: the common prefix and suffix are trimmed first, so an edit costs O(changed lines) for the script. Very
// large or very different middles fall back to replacing the whole changed block.
Diff unified_diff(std::string_view old_text, std::string_view new_text, const std::string& label,
                  const CancelFlag& cancelled = {}) {
    check_cancelled(cancelled);
    constexpr size_t context = 3;
    const auto a = split_lines(old_text, cancelled), b = split_lines(new_text, cancelled);
    size_t prefix = 0;
    while (prefix < a.size() && prefix < b.size() && a[prefix] == b[prefix]) {
        check_cancelled(cancelled); ++prefix;
    }
    size_t suffix = 0;
    while (suffix < a.size() - prefix && suffix < b.size() - prefix &&
           a[a.size() - 1 - suffix] == b[b.size() - 1 - suffix]) {
        check_cancelled(cancelled); ++suffix;
    }
    const size_t n = a.size() - prefix - suffix, m = b.size() - prefix - suffix;
    std::vector<DiffOp> ops;
    for (size_t i = prefix - std::min(prefix, context); i < prefix; ++i) ops.push_back({' ', i, i});
    std::string script;
    if (n + m > 20000 || !myers(a.data() + prefix, static_cast<int>(n), b.data() + prefix, static_cast<int>(m),
                                static_cast<int>(std::min<size_t>(n + m, 2000)), script, cancelled))
        script = std::string(n, '-') + std::string(m, '+');
    size_t x = prefix, y = prefix;
    for (char kind : script) {
        check_cancelled(cancelled);
        ops.push_back({kind, x, y});
        if (kind != '+') ++x;
        if (kind != '-') ++y;
    }
    for (size_t i = 0; i < std::min(suffix, context); ++i) ops.push_back({' ', x + i, y + i});

    Diff diff;
    if (n == 0 && m == 0) return diff;
    diff.text = "--- a/" + label + "\n+++ b/" + label + "\n";
    auto range = [](size_t start, size_t count) {
        if (count == 1) return std::to_string(start + 1);
        return std::to_string(count ? start + 1 : start) + "," + std::to_string(count);
    };
    size_t i = 0;
    while (i < ops.size()) {
        check_cancelled(cancelled);
        while (i < ops.size() && ops[i].kind == ' ') ++i;
        if (i == ops.size()) break;
        const size_t start = i >= context ? i - context : 0;
        size_t end = i;
        for (;;) {
            while (end < ops.size() && ops[end].kind != ' ') ++end;
            size_t next = end;
            while (next < ops.size() && ops[next].kind == ' ') ++next;
            if (next < ops.size() && next - end <= 2 * context) { end = next; continue; }
            break;
        }
        const size_t stop = std::min(ops.size(), end + context);
        size_t a_count = 0, b_count = 0;
        for (size_t k = start; k < stop; ++k) {
            if (ops[k].kind != '+') ++a_count;
            if (ops[k].kind != '-') ++b_count;
        }
        diff.text += "@@ -" + range(ops[start].a, a_count) + " +" + range(ops[start].b, b_count) + " @@\n";
        for (size_t k = start; k < stop; ++k) {
            check_cancelled(cancelled);
            const std::string_view line = ops[k].kind == '+' ? b[ops[k].b] : a[ops[k].a];
            std::string_view shown = line;
            if (shown.ends_with('\n')) shown.remove_suffix(1);
            if (shown.ends_with('\r')) shown.remove_suffix(1);
            diff.text.push_back(ops[k].kind);
            diff.text.append(shown);
            diff.text.push_back('\n');
            if (!line.ends_with('\n')) diff.text += "\\ No newline at end of file\n";
            if (ops[k].kind == '+') ++diff.added;
            if (ops[k].kind == '-') ++diff.removed;
        }
        i = stop;
    }
    return diff;
}

// Cuts text at a line boundary to fit budget, with a note saying so.
std::string fit(const std::string& text, Budget& budget, const std::string& note) {
    if (budget.fits(text)) {
        budget.take(text);
        return text;
    }
    std::string out;
    for (size_t pos = 0; pos < text.size();) {
        const size_t newline = text.find('\n', pos);
        const size_t end = newline == std::string::npos ? text.size() : newline + 1;
        const std::string_view line(text.data() + pos, end - pos);
        if (!budget.fits(line)) break;
        budget.take(line);
        out.append(line);
        pos = end;
    }
    return out + note;
}

// ---- edit_file ----

struct Edit {
    std::string old_text, new_text;
    bool replace_all = false;
};

std::vector<Edit> parse_edits(const Json& args) {
    const Json* value = args.get("edits");
    const auto* list = value ? std::get_if<Json::Array>(&value->value) : nullptr;
    if (!list || list->empty() || list->size() > 256)
        fail("edits must be a list of 1 to 256 {old_text, new_text, replace_all} objects");
    std::vector<Edit> edits;
    for (const auto& item : *list) {
        if (!std::holds_alternative<Json::Object>(item.value)) fail("each edit must be an object {old_text, new_text}");
        for (const auto& entry : item.object())
            if (entry.first != "old_text" && entry.first != "new_text" && entry.first != "replace_all")
                fail("unknown edit field \"" + entry.first.substr(0, 64) + "\"; valid: old_text, new_text, replace_all");
        Edit edit;
        edit.old_text = string_arg(item, "old_text");
        edit.new_text = string_arg(item, "new_text");
        edit.replace_all = bool_arg(item, "replace_all", false);
        edits.push_back(std::move(edit));
    }
    return edits;
}

size_t count_matches(std::string_view text, std::string_view needle, const CancelFlag& cancelled) {
    size_t count = 0;
    for (size_t pos = text.find(needle); pos != std::string_view::npos; pos = text.find(needle, pos + needle.size())) {
        check_cancelled(cancelled); ++count;
    }
    return count;
}

uint64_t line_at(std::string_view text, size_t pos) {
    return 1 + static_cast<uint64_t>(std::count(text.begin(), text.begin() + static_cast<ptrdiff_t>(pos), '\n'));
}

// Applies one edit to content. The old_text forms tried follow the file's line endings, so text written with
// LF matches a CRLF file and new_text is inserted with the same endings.
void apply_edit(std::string& content, const Edit& edit, Eol eol, size_t index, size_t total, uint64_t& replacements,
                const CancelFlag& cancelled) {
    const std::string where = total > 1 ? "edit " + std::to_string(index + 1) + " of " + std::to_string(total) : "the edit";
    if (edit.old_text.empty()) fail(where + ": old_text is empty");
    if (edit.old_text == edit.new_text) fail(where + ": old_text and new_text are identical");
    std::vector<std::pair<std::string, std::string>> forms;
    if (eol == Eol::lf || eol == Eol::crlf || eol == Eol::cr) {
        forms.emplace_back(replace_newlines(edit.old_text, eol_text(eol)), replace_newlines(edit.new_text, eol_text(eol)));
    } else {
        forms.emplace_back(edit.old_text, edit.new_text);
        if (eol == Eol::mixed) {
            for (std::string_view ending : {std::string_view("\n"), std::string_view("\r\n")}) {
                std::pair<std::string, std::string> form{replace_newlines(edit.old_text, ending),
                                                         replace_newlines(edit.new_text, ending)};
                if (std::find(forms.begin(), forms.end(), form) == forms.end()) forms.push_back(std::move(form));
            }
        }
    }
    const std::pair<std::string, std::string>* chosen = nullptr;
    size_t count = 0;
    for (const auto& form : forms) {
        if ((count = count_matches(content, form.first, cancelled)) != 0) { chosen = &form; break; }
    }
    if (!chosen) {
        std::string message = where + ": old_text was not found";
        if (index > 0) message += " (in the text produced by the earlier edits)";
        // A hint for the common near miss: the first line matches but whitespace further on does not.
        std::string_view first = edit.old_text;
        first = first.substr(0, first.find('\n'));
        while (!first.empty() && std::isspace(static_cast<unsigned char>(first.front()))) first.remove_prefix(1);
        while (!first.empty() && std::isspace(static_cast<unsigned char>(first.back()))) first.remove_suffix(1);
        if (first.size() >= 4 && first.size() < edit.old_text.size()) {
            const size_t at = content.find(first);
            if (at != std::string::npos)
                message += "; its first line occurs at line " + std::to_string(line_at(content, at)) +
                           ", so compare the rest, including indentation and trailing spaces";
        }
        fail(message + ". Nothing was written.");
    }
    if (count > 1 && !edit.replace_all) {
        std::string lines;
        size_t shown = 0;
        for (size_t pos = content.find(chosen->first); pos != std::string::npos && shown < 5;
             pos = content.find(chosen->first, pos + chosen->first.size()), ++shown)
            lines += (lines.empty() ? "" : ", ") + std::to_string(line_at(content, pos));
        fail(where + ": old_text matches " + std::to_string(count) + " times (at lines " + lines +
             (count > 5 ? ", ..." : "") + "); include more surrounding text to make it unique, or set replace_all. "
             "Nothing was written.");
    }
    std::string next;
    next.reserve(content.size() + (chosen->second.size() > chosen->first.size()
                                       ? (chosen->second.size() - chosen->first.size()) * count : 0));
    size_t pos = 0;
    for (size_t at = content.find(chosen->first); at != std::string::npos;
         at = edit.replace_all ? content.find(chosen->first, at + chosen->first.size()) : std::string::npos) {
        check_cancelled(cancelled);
        next.append(content, pos, at - pos);
        next += chosen->second;
        pos = at + chosen->first.size();
    }
    next.append(content, pos, std::string::npos);
    content = std::move(next);
    replacements += edit.replace_all ? count : 1;
}

Json edit_file(const Json& args, const SearchContext& context, const CancelFlag& cancelled) {
    const Target target = resolve(context, string_arg(args, "path"));
    if (target.parts.empty()) fail("path names a configured root, not a file");
    const std::vector<Edit> edits = parse_edits(args);
    const bool dry_run = bool_arg(args, "dry_run", false);
    Budget budget(max_output_arg(args));
    const std::string path = target.display();
    std::unique_lock lock(write_mutex(), std::defer_lock);
    while (!lock.try_lock()) { check_cancelled(cancelled); Sleep(1); }
    check_cancelled(cancelled);
    Handle directory = open_parent(target, false, nullptr, cancelled);
    // CONTRACT: no other process may open the file for writing between this read and the rename.
    Handle file = open_file(directory.h, target, FILE_SHARE_READ | FILE_SHARE_DELETE);
    const FILE_BASIC_INFO basic = basic_info(file.h, path);
    std::string raw;
    if (!read_all(file.h, path, max_text_bytes, raw, cancelled)) fail(path + " is larger than 64 MiB; edit_file does not edit it");
    check_guards(args, path, raw, basic);
    const fs::path snapshot_path(target.full(target.parts.size()));
    const std::string before_digest = sha256_hex(raw);
    if (!dry_run) require_read_snapshot(context, snapshot_path, before_digest, args.get("expected_sha256") != nullptr);
    const TextFile text = decode(raw);
    if (text.binary) fail(path + " is binary (NUL byte at offset " + std::to_string(text.nul_offset) + "); edit_file edits text only");
    if (text.invalid)
        fail(path + " is not valid " + encoding_name(text.encoding) + " (" + std::to_string(text.invalid) +
             " invalid byte sequences); editing it would change bytes outside the edit, so nothing was written");
    if (!dry_run && (basic.FileAttributes & FILE_ATTRIBUTE_READONLY)) fail(path + " is read-only; nothing was written");
    std::string content = text.text;
    uint64_t replacements = 0;
    for (size_t i = 0; i < edits.size(); ++i) {
        check_cancelled(cancelled);
        apply_edit(content, edits[i], eol_style(text), i, edits.size(), replacements, cancelled);
    }
    check_cancelled(cancelled);
    const std::string bytes = encode(content, text.encoding);
    check_cancelled(cancelled);
    if (bytes == raw) {
        if (dry_run) remember_read_snapshot(context, snapshot_path, before_digest);
        return Json::Object{{"text", "No change: the edits leave " + path + " as it was; nothing was written.\n"}, {"changed", false}};
    }
    TextFile after;
    after.text = content;
    count_lines(after);
    const Diff diff = unified_diff(text.text, content, target.relative(), cancelled);
    FILE_BASIC_INFO written = basic;
    std::string commit_warning;
    if (!dry_run)
        written = atomic_write(directory.h, target, bytes, true, basic.FileAttributes & kept_attributes, &file, cancelled, &commit_warning);
    remember_read_snapshot(context, snapshot_path, dry_run ? before_digest : sha256_hex(bytes));
    std::string summary = std::string(dry_run ? "Dry run, nothing written. Would edit " : "Edited ") + path + ": " +
                          std::to_string(edits.size()) + (edits.size() == 1 ? " edit, " : " edits, ") +
                          std::to_string(replacements) + (replacements == 1 ? " replacement" : " replacements") +
                          ", +" + std::to_string(diff.added) + " -" + std::to_string(diff.removed) + " lines. ";
    summary += "Now " + std::to_string(after.lines) + " lines, " + encoding_name(text.encoding) + ", " + eol_name(after);
    if (!dry_run) summary += " | mtime " + format_mtime(written.LastWriteTime.QuadPart) + " | sha256 " + sha256_hex(bytes);
    summary += "\n" + commit_warning;
    if (!args.get("max_output_bytes")) return Json::Object{{"text", summary + diff.text}};
    budget.take(summary);
    return Json::Object{{"text", summary + fit(diff.text, budget, dry_run
        ? "[diff cut at max_output_bytes]\n" : "[diff cut at max_output_bytes; the edit was applied in full]\n")}};
}


// Formatting configuration is read under the same root and no-link policy as file writes.
struct EolConfig { size_t depth; std::string text; };

std::string eol_trim(std::string_view value) {
    const size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const size_t last = value.find_last_not_of(" \t\r\n");
    return std::string(value.substr(first, last - first + 1));
}

std::string eol_lower(std::string value) {
    for (char& c : value) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return value;
}

std::vector<std::string> eol_lines(std::string_view text) {
    std::vector<std::string> lines;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t end = text.find('\n', pos);
        if (end == std::string_view::npos) end = text.size();
        std::string line(text.substr(pos, end - pos));
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(std::move(line));
        pos = end + 1;
    }
    return lines;
}

// Compare signed decimal integers without imposing a machine-integer limit.
bool eol_number(std::wstring_view text, bool& negative, std::wstring_view& digits) {
    if (text.empty()) return false;
    negative = text.front() == L'-';
    if (negative) text.remove_prefix(1);
    if (text.empty()) return false;
    for (wchar_t c : text) if (c < L'0' || c > L'9') return false;
    while (text.size() > 1 && text.front() == L'0') text.remove_prefix(1);
    if (text == L"0") negative = false;
    digits = text;
    return true;
}

int eol_compare_number(std::wstring_view a, std::wstring_view b) {
    bool an = false, bn = false;
    std::wstring_view ad, bd;
    if (!eol_number(a, an, ad) || !eol_number(b, bn, bd)) return 0;
    if (an != bn) return an ? -1 : 1;
    int cmp = ad.size() == bd.size() ? ad.compare(bd) : ad.size() < bd.size() ? -1 : 1;
    return an ? -cmp : cmp;
}

// Match a configuration glob against one root-relative pathname. EditorConfig
// braces and Git wildmatch differ, so they share only the basic wildcard engine.
bool eol_glob(std::wstring pattern, std::wstring_view path, bool editor,
              const CancelFlag& cancelled) {
    uint64_t steps = 0;
    std::function<bool(const std::wstring&, size_t, size_t)> match;
    match = [&](const std::wstring& p, size_t pi, size_t ti) -> bool {
        if ((++steps & 4095) == 0) check_cancelled(cancelled);
        if (steps > 2000000) fail("formatting configuration glob is too complex; nothing was written");
        if (pi == p.size()) return ti == path.size();
        wchar_t c = p[pi];
        if (c == L'\\' && pi + 1 < p.size()) {
            c = p[++pi];
        } else if (c == L'*') {
            size_t end = pi + 1;
            while (end < p.size() && p[end] == L'*') ++end;
            const bool recursive = end - pi >= 2 && (editor ||
                ((pi == 0 || p[pi - 1] == L'/') && (end == p.size() || p[end] == L'/')));
            if (recursive && end < p.size() && p[end] == L'/' &&
                (pi == 0 || p[pi - 1] == L'/')) {
                if (match(p, end + 1, ti)) return true;
                for (size_t i = ti; i < path.size(); ++i)
                    if (path[i] == L'/' && match(p, end + 1, i + 1)) return true;
                return false;
            }
            for (size_t i = ti;; ++i) {
                if (match(p, end, i)) return true;
                if (i == path.size() || (!recursive && path[i] == L'/')) break;
            }
            return false;
        } else if (c == L'?') {
            if (ti == path.size() || path[ti] == L'/') return false;
            size_t next = ti + 1;
            if (path[ti] >= 0xd800 && path[ti] <= 0xdbff && next < path.size() &&
                path[next] >= 0xdc00 && path[next] <= 0xdfff) ++next;
            return match(p, pi + 1, next);
        } else if (c == L'[') {
            size_t end = pi + 1;
            if (end < p.size() && (p[end] == L'!' || (!editor && p[end] == L'^'))) ++end;
            if (end < p.size() && p[end] == L']') ++end;
            while (end < p.size() && p[end] != L']') {
                if (!editor && p[end] == L'[' && end + 1 < p.size() && p[end + 1] == L':') {
                    const size_t close = p.find(L":]", end + 2);
                    if (close != std::wstring::npos) { end = close + 2; continue; }
                }
                if (p[end] == L'\\' && end + 1 < p.size()) ++end;
                ++end;
            }
            if (end < p.size()) {
                if (ti == path.size() || path[ti] == L'/') return false;
                size_t i = pi + 1;
                const bool negate = i < end && (p[i] == L'!' || (!editor && p[i] == L'^'));
                if (negate) ++i;
                bool found = false;
                const wchar_t value = editor ? path[ti] : static_cast<wchar_t>(std::towlower(path[ti]));
                while (i < end) {
                    if (!editor && p[i] == L'[' && i + 1 < end && p[i + 1] == L':') {
                        const size_t close = p.find(L":]", i + 2);
                        if (close != std::wstring::npos && close < end) {
                            const std::wstring_view cls(p.data() + i + 2, close - i - 2);
                            const bool digit = value >= L'0' && value <= L'9';
                            const bool lower = value >= L'a' && value <= L'z';
                            const bool upper = value >= L'A' && value <= L'Z';
                            const bool alpha = lower || upper;
                            if (cls == L"alnum") found |= alpha || digit;
                            else if (cls == L"alpha") found |= alpha;
                            else if (cls == L"blank") found |= value == L' ' || value == L'\t';
                            else if (cls == L"cntrl") found |= value < 32 || value == 127;
                            else if (cls == L"digit") found |= digit;
                            else if (cls == L"graph") found |= value >= 33 && value <= 126;
                            else if (cls == L"lower" || cls == L"upper") found |= alpha;
                            else if (cls == L"print") found |= value >= 32 && value <= 126;
                            else if (cls == L"punct") found |= value >= 33 && value <= 126 && !alpha && !digit;
                            else if (cls == L"space") found |= value == L' ' || (value >= L'\t' && value <= L'\r');
                            else if (cls == L"xdigit") found |= digit || (value >= L'a' && value <= L'f');
                            i = close + 2;
                            continue;
                        }
                    }
                    if (p[i] >= 0xd800 && p[i] <= 0xdbff && i + 1 < end &&
                        p[i + 1] >= 0xdc00 && p[i + 1] <= 0xdfff) {
                        if (ti + 1 < path.size() && path[ti] == p[i] && path[ti + 1] == p[i + 1]) found = true;
                        i += 2;
                        continue;
                    }
                    wchar_t first = p[i++];
                    if (first == L'\\' && i < end) first = p[i++];
                    wchar_t last = first;
                    if (!editor && i + 1 < end && p[i] == L'-') {
                        ++i; last = p[i++];
                        if (last == L'\\' && i < end) last = p[i++];
                    }
                    if (!editor) { first = static_cast<wchar_t>(std::towlower(first)); last = static_cast<wchar_t>(std::towlower(last)); }
                    if (value >= first && value <= last) found = true;
                }
                size_t next = ti + 1;
                if (path[ti] >= 0xd800 && path[ti] <= 0xdbff && next < path.size() &&
                    path[next] >= 0xdc00 && path[next] <= 0xdfff) ++next;
                return found != negate && match(p, end + 1, next);
            }
        } else if (editor && c == L'{') {
            size_t end = pi + 1, nesting = 0;
            std::vector<size_t> commas;
            for (; end < p.size(); ++end) {
                if (p[end] == L'\\' && end + 1 < p.size()) { ++end; continue; }
                if (p[end] == L'[') {
                    while (++end < p.size() && p[end] != L']') if (p[end] == L'\\' && end + 1 < p.size()) ++end;
                    if (end == p.size()) break;
                } else if (p[end] == L'{') ++nesting;
                else if (p[end] == L'}') { if (!nesting) break; --nesting; }
                else if (p[end] == L',' && !nesting) commas.push_back(end);
            }
            if (end < p.size() && !commas.empty()) {
                commas.push_back(end);
                size_t start = pi + 1;
                for (size_t stop : commas) {
                    const std::wstring expanded = p.substr(0, pi) + p.substr(start, stop - start) + p.substr(end + 1);
                    if (match(expanded, pi, ti)) return true;
                    start = stop + 1;
                }
                return false;
            }
            if (end < p.size()) {
                std::wstring_view body(p.data() + pi + 1, end - pi - 1);
                const size_t dots = body.find(L"..");
                bool na = false, nb = false;
                std::wstring_view da, db;
                if (dots != std::wstring_view::npos && eol_number(body.substr(0, dots), na, da) &&
                    eol_number(body.substr(dots + 2), nb, db) &&
                    eol_compare_number(body.substr(0, dots), body.substr(dots + 2)) < 0) {
                    size_t i = ti;
                    if (i < path.size() && path[i] == L'-') ++i;
                    const size_t digits = i;
                    while (i < path.size() && path[i] >= L'0' && path[i] <= L'9') {
                        ++i;
                        const auto number = path.substr(ti, i - ti);
                        if (i > digits && eol_compare_number(number, body.substr(0, dots)) >= 0 &&
                            eol_compare_number(number, body.substr(dots + 2)) <= 0 &&
                            match(p, end + 1, i)) return true;
                    }
                    return false;
                }
            }
        }
        if (ti == path.size()) return false;
        const wchar_t actual = path[ti];
        if (editor ? c != actual : std::towlower(c) != std::towlower(actual)) return false;
        return match(p, pi + 1, ti + 1);
    };
    return match(pattern, 0, 0);
}

std::wstring eol_relative_path(const Target& target, size_t depth) {
    std::wstring result;
    for (size_t i = depth; i < target.parts.size(); ++i) {
        if (!result.empty()) result.push_back(L'/');
        result += target.parts[i];
    }
    return result;
}

bool eol_pattern_matches(std::string_view bytes, std::wstring_view path, bool editor,
                         const CancelFlag& cancelled) {
    if (bytes.empty() || bytes.back() == '/') return false;
    std::wstring pattern;
    try { pattern = native_path(std::string(bytes)).wstring(); }
    catch (const std::exception&) { fail("formatting configuration contains invalid UTF-8"); }
    size_t characters = 0;
    for (size_t i = 0; i < pattern.size(); ++i, ++characters)
        if (pattern[i] >= 0xd800 && pattern[i] <= 0xdbff && i + 1 < pattern.size() &&
            pattern[i + 1] >= 0xdc00 && pattern[i + 1] <= 0xdfff) ++i;
    if (characters > 1024) fail("formatting configuration glob exceeds 1024 characters; nothing was written");
    const bool anchored = !pattern.empty() && pattern.front() == L'/';
    if (anchored) pattern.erase(pattern.begin());
    bool slash = false, escaped = false, in_class = false;
    for (wchar_t c : pattern) {
        if (escaped) { escaped = false; continue; }
        if (c == L'\\') { escaped = true; continue; }
        if (c == L'[') in_class = true;
        else if (c == L']') in_class = false;
        else if (c == L'/' && !in_class) slash = true;
    }
    if (!slash && !anchored) {
        const size_t last = path.find_last_of(L'/');
        if (last != std::wstring_view::npos) path.remove_prefix(last + 1);
    }
    return eol_glob(std::move(pattern), path, editor, cancelled);
}

std::vector<EolConfig> eol_configs(const Target& target, const wchar_t* name,
                                   const CancelFlag& cancelled) {
    std::vector<Handle> directories;
    directories.push_back(open_root(target));
    for (size_t depth = 0; depth + 1 < target.parts.size(); ++depth) {
        check_cancelled(cancelled);
        Handle child;
        const NTSTATUS status = nt_open(directories.back().h, target.parts[depth], directory_access, share_all,
                                        disposition_open, option_directory | option_open_reparse_point, 0, child);
        if (status < 0) fail(target.display(depth + 1) + ": " + status_text(status));
        refuse_link(child.h, target.display(depth + 1));
        directories.push_back(std::move(child));
    }
    std::vector<EolConfig> configs;
    const bool editor = name[1] == L'e';
    for (size_t depth = directories.size(); depth-- > 0;) {
        check_cancelled(cancelled);
        Handle file;
        const NTSTATUS status = nt_open(directories[depth].h, name, FILE_GENERIC_READ, share_all, disposition_open,
                                        option_non_directory | option_open_reparse_point | option_sequential, 0, file);
        if (status < 0) {
            if (static_cast<uint32_t>(status) != 0xC0000034)
                fail(target.display(depth) + ": cannot read formatting configuration: " + status_text(status));
            continue;
        }
        const std::string label = target.display(depth) + "/" + (editor ? ".editorconfig" : ".gitattributes");
        refuse_link(file.h, label);
        std::string raw;
        if (!read_all(file.h, label, 1ull << 20, raw, cancelled))
            fail(label + " is larger than 1 MiB; nothing was written");
        const TextFile decoded = decode(raw);
        if (decoded.binary || decoded.invalid ||
            (decoded.encoding != Encoding::utf8 && decoded.encoding != Encoding::utf8_bom))
            fail(label + " is not valid UTF-8; nothing was written");
        bool root = false;
        if (editor) {
            for (const auto& raw_line : eol_lines(decoded.text)) {
                const std::string line = eol_trim(raw_line);
                if (line.empty() || line[0] == '#' || line[0] == ';') continue;
                if (line.front() == '[' && line.back() == ']') break;
                const size_t equals = line.find('=');
                if (equals != std::string::npos &&
                    eol_lower(eol_trim(std::string_view(line).substr(0, equals))) == "root")
                    root = eol_lower(eol_trim(std::string_view(line).substr(equals + 1))) == "true";
            }
        }
        configs.push_back({depth, decoded.text});
        if (root) break;
    }
    std::reverse(configs.begin(), configs.end());
    return configs;
}

std::string eol_editorconfig(const Target& target, const CancelFlag& cancelled) {
    std::string result;
    for (const auto& config : eol_configs(target, L".editorconfig", cancelled)) {
        bool preamble = true, selected = false;
        const std::wstring path = eol_relative_path(target, config.depth);
        for (const auto& original : eol_lines(config.text)) {
            check_cancelled(cancelled);
            const std::string line = eol_trim(original);
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;
            if (line.front() == '[' && line.back() == ']') {
                preamble = false;
                selected = eol_pattern_matches(std::string_view(line).substr(1, line.size() - 2), path, true, cancelled);
                continue;
            }
            const size_t equals = line.find('=');
            if (equals == std::string::npos) continue;
            const std::string key = eol_lower(eol_trim(std::string_view(line).substr(0, equals)));
            const std::string value = eol_lower(eol_trim(std::string_view(line).substr(equals + 1)));
            if (!preamble && selected && key == "end_of_line") {
                if (value == "lf" || value == "crlf" || value == "cr") result = value;
                else result.clear();
            }
        }
    }
    return result;
}

std::optional<Encoding> editorconfig_encoding(const Target& target, const CancelFlag& cancelled) {
    std::string charset;
    for (const auto& config : eol_configs(target, L".editorconfig", cancelled)) {
        bool preamble = true, selected = false;
        const std::wstring path = eol_relative_path(target, config.depth);
        for (const auto& original : eol_lines(config.text)) {
            check_cancelled(cancelled);
            const std::string line = eol_trim(original);
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;
            if (line.front() == '[' && line.back() == ']') {
                preamble = false;
                selected = eol_pattern_matches(std::string_view(line).substr(1, line.size() - 2), path, true, cancelled);
                continue;
            }
            const size_t equals = line.find('=');
            if (equals == std::string::npos || preamble || !selected) continue;
            if (eol_lower(eol_trim(std::string_view(line).substr(0, equals))) == "charset") {
                charset = eol_lower(eol_trim(std::string_view(line).substr(equals + 1)));
                if (charset == "unset") charset.clear();
            }
        }
    }
    if (charset.empty()) return std::nullopt;
    if (charset == "utf-8") return Encoding::utf8;
    if (charset == "utf-8-bom") return Encoding::utf8_bom;
    if (charset == "utf-16le") return Encoding::utf16le;
    if (charset == "utf-16be") return Encoding::utf16be;
    fail("unsupported EditorConfig charset '" + charset + "'; specify a supported encoding explicitly");
}

// Split attributes while decoding Git's C-quoted pattern syntax.
std::vector<std::string> eol_git_tokens(std::string_view line) {
    std::vector<std::string> tokens;
    size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
        if (i == line.size()) break;
        std::string token;
        if (line[i] == '"' && tokens.empty()) {
            ++i;
            bool closed = false;
            while (i < line.size()) {
                char c = line[i++];
                if (c == '"') { closed = true; break; }
                if (c == '\\' && i < line.size()) {
                    c = line[i++];
                    if (c >= '0' && c <= '7') {
                        unsigned value = static_cast<unsigned>(c - '0');
                        for (int n = 0; n < 2 && i < line.size() && line[i] >= '0' && line[i] <= '7'; ++n)
                            value = value * 8 + static_cast<unsigned>(line[i++] - '0');
                        c = static_cast<char>(value);
                    } else if (c == 'a') c = '\a';
                    else if (c == 'b') c = '\b';
                    else if (c == 't') c = '\t';
                    else if (c == 'n') c = '\n';
                    else if (c == 'v') c = '\v';
                    else if (c == 'f') c = '\f';
                    else if (c == 'r') c = '\r';
                    else if (c != '\\' && c != '"') fail("invalid quoted .gitattributes pattern");
                }
                token.push_back(c);
            }
            if (!closed || (i < line.size() && line[i] != ' ' && line[i] != '\t'))
                fail("invalid quoted .gitattributes pattern");
        } else {
            const size_t start = i;
            while (i < line.size() && line[i] != ' ' && line[i] != '\t') ++i;
            token.assign(line.substr(start, i - start));
        }
        tokens.push_back(std::move(token));
    }
    return tokens;
}

struct GitEol { std::string text, eol; };

void eol_git_attribute(const std::string& token, GitEol& state,
                       const std::map<std::string, std::vector<std::string>>& macros, size_t depth) {
    if (depth > 32) fail("recursive .gitattributes macro; nothing was written");
    if (token.empty()) return;
    std::string name = token, value = "true";
    if (name.front() == '-') { name.erase(0, 1); value = "false"; }
    else if (name.front() == '!') { name.erase(0, 1); value.clear(); }
    else if (const size_t equals = name.find('='); equals != std::string::npos) {
        value = name.substr(equals + 1); name.erase(equals);
    }
    if (name == "text") state.text = value;
    else if (name == "eol") state.eol = value;
    else if (name == "crlf") {
        if (value == "input") state.eol = "lf";
        else if (value == "true" || value == "false") state.text = value;
        else if (value.empty()) state.text.clear();
    } else if (value == "true") {
        const auto it = macros.find(name);
        if (it != macros.end())
            for (const auto& expanded : it->second) eol_git_attribute(expanded, state, macros, depth + 1);
    }
}

GitEol eol_gitattributes(const Target& target, const CancelFlag& cancelled) {
    const auto configs = eol_configs(target, L".gitattributes", cancelled);
    std::map<std::string, std::vector<std::string>> macros;
    macros["binary"] = {"-diff", "-merge", "-text"};
    for (const auto& config : configs) {
        if (config.depth != 0) continue;
        for (const auto& raw : eol_lines(config.text)) {
            const std::string line = eol_trim(raw);
            if (!line.starts_with("[attr]")) continue;
            auto tokens = eol_git_tokens(line);
            if (tokens.size() > 1 && tokens[0].size() > 6)
                macros[tokens[0].substr(6)] = std::vector<std::string>(tokens.begin() + 1, tokens.end());
        }
    }
    GitEol state;
    for (const auto& config : configs) {
        const std::wstring path = eol_relative_path(target, config.depth);
        for (const auto& raw : eol_lines(config.text)) {
            check_cancelled(cancelled);
            const std::string line = eol_trim(raw);
            if (line.empty() || line[0] == '#' || line.starts_with("[attr]")) continue;
            const auto tokens = eol_git_tokens(line);
            if (tokens.size() < 2 || tokens[0].empty() || tokens[0][0] == '!') continue;
            if (!eol_pattern_matches(tokens[0], path, false, cancelled)) continue;
            for (size_t i = 1; i < tokens.size(); ++i) eol_git_attribute(tokens[i], state, macros, 0);
        }
    }
    return state;
}

std::string eol_siblings(HANDLE directory, const Target& target, const CancelFlag& cancelled) {
    std::vector<uint64_t> buffer((64 * 1024) / sizeof(uint64_t));
    std::vector<DirEntry> entries;
    if (!list_directory(directory, buffer, entries))
        fail(target.display(target.parts.size() - 1) + ": cannot inspect sibling files for line endings");
    uint64_t lf = 0, crlf = 0, cr = 0;
    for (const auto& entry : entries) {
        check_cancelled(cancelled);
        if (entry.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        if (same_name(entry.name, target.name().c_str()) || entry.size > max_text_bytes) continue;
        Handle file;
        const NTSTATUS status = nt_open(directory, entry.name, FILE_GENERIC_READ, share_all, disposition_open,
                                        option_non_directory | option_open_reparse_point | option_sequential, 0, file);
        if (status < 0) continue;
        try {
            if (attributes_of(file.h, target.display()) & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            std::string raw;
            if (!read_all(file.h, target.display(), max_text_bytes, raw, cancelled)) continue;
            const TextFile text = decode(raw);
            if (text.binary || text.invalid) continue;
            if (text.lf > text.crlf && text.lf > text.cr) ++lf;
            else if (text.crlf > text.lf && text.crlf > text.cr) ++crlf;
            else if (text.cr > text.lf && text.cr > text.crlf) ++cr;
        } catch (const std::exception&) {
            check_cancelled(cancelled);
        }
    }
    if (lf > crlf && lf > cr) return "lf";
    if (crlf > lf && crlf > cr) return "crlf";
    if (cr > lf && cr > crlf) return "cr";
    return {};
}

std::optional<Encoding> sibling_encoding(HANDLE directory, const Target& target, const CancelFlag& cancelled) {
    std::vector<uint64_t> buffer((64 * 1024) / sizeof(uint64_t));
    std::vector<DirEntry> entries;
    if (!list_directory(directory, buffer, entries))
        fail(target.display(target.parts.size() - 1) + ": cannot inspect sibling encodings");
    const std::wstring extension = fs::path(target.name()).extension().wstring();
    uint64_t counts[4] = {};
    for (const auto& entry : entries) {
        check_cancelled(cancelled);
        if (entry.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        const std::wstring sibling_extension = fs::path(entry.name).extension().wstring();
        if (same_name(entry.name, target.name().c_str()) || entry.size > max_text_bytes ||
            (extension.empty() ? !sibling_extension.empty() : !same_name(extension, sibling_extension.c_str()))) continue;
        Handle file;
        const NTSTATUS status = nt_open(directory, entry.name, FILE_GENERIC_READ, share_all, disposition_open,
                                        option_non_directory | option_open_reparse_point | option_sequential, 0, file);
        if (status < 0) continue;
        try {
            if (attributes_of(file.h, target.display()) & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            std::string raw;
            if (!read_all(file.h, target.display(), max_text_bytes, raw, cancelled) || raw.empty()) continue;
            const TextFile text = decode(raw);
            if (!text.binary && !text.invalid) ++counts[static_cast<size_t>(text.encoding)];
        } catch (const std::exception&) {
            check_cancelled(cancelled);
        }
    }
    size_t best = 0;
    for (size_t i = 1; i < 4; ++i) if (counts[i] > counts[best]) best = i;
    if (!counts[best]) return std::nullopt;
    for (size_t i = 0; i < 4; ++i) if (i != best && counts[i] == counts[best]) return std::nullopt;
    return static_cast<Encoding>(best);
}

std::string eol_for_new_file(HANDLE directory, const Target& target, std::string_view content,
                             const CancelFlag& cancelled) {
    std::string result = eol_editorconfig(target, cancelled);
    if (!result.empty()) return result;
    const GitEol git = eol_gitattributes(target, cancelled);
    // An explicit -text prevents conversion, including sibling-based conversion.
    if (git.text == "false" || (git.text == "auto" && content.find('\0') != std::string_view::npos)) return {};
    if (git.eol == "lf" || git.eol == "crlf") return git.eol;
    return eol_siblings(directory, target, cancelled);
}

// ---- write_file ----

Json write_file(const Json& args, const SearchContext& context, const CancelFlag& cancelled) {
    const Target target = resolve(context, string_arg(args, "path"));
    if (target.parts.empty()) fail("path names a configured root, not a file");
    const std::string content = string_arg(args, "content");
    const bool overwrite = bool_arg(args, "overwrite", false);
    const bool hash_guarded = overwrite && args.get("expected_sha256");
    bool checked_exists = false;
    const SourceText descriptor = source_descriptor(context, string_arg(args, "path"), nullptr, true, &checked_exists);
    const std::string notice = overwrite && checked_exists && !hash_guarded
        ? require_text_access(descriptor, args, context, cancelled) : std::string();
    std::string endings;
    if (args.get("line_endings")) endings = string_arg(args, "line_endings");
    if (args.get("eol")) {
        const std::string alias = string_arg(args, "eol");
        if (args.get("line_endings") && endings != alias) fail("eol and line_endings must agree");
        endings = alias;
    }
    if ((args.get("line_endings") || args.get("eol")) &&
        endings != "lf" && endings != "crlf" && endings != "cr")
        fail("line_endings and eol must be lf, crlf, or cr");
    bool encoding_given = args.get("encoding") != nullptr;
    Encoding encoding = encoding_given ? parse_encoding(string_arg(args, "encoding")) : Encoding::utf8;
    const std::string path = target.display();
    std::unique_lock lock(write_mutex(), std::defer_lock);
    while (!lock.try_lock()) { check_cancelled(cancelled); Sleep(1); }
    check_cancelled(cancelled);
    std::vector<std::string> created;
    Handle directory = open_parent(target, true, &created, cancelled);
    Handle existing;
    const NTSTATUS status = nt_open(directory.h, target.name(), FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                    disposition_open, option_non_directory | option_open_reparse_point, 0, existing);
    const bool exists = status >= 0;
    DWORD attributes = 0;
    uint64_t old_lines = 0;
    if (status == status_is_directory) fail(path + " is a directory");
    if (!exists && static_cast<uint32_t>(status) != 0xC0000034)
        fail(path + ": " + status_text(status));
    if (exists) {
        refuse_link(existing.h, path);
        if (!overwrite) fail(path + " already exists; pass overwrite: true to replace it. Nothing was written.");
        if (!checked_exists && !hash_guarded && lsp_required(descriptor.path))
            fail(path + " appeared during creation; retry through LSP. Nothing was written.");
        const FILE_BASIC_INFO basic = basic_info(existing.h, path);
        if (basic.FileAttributes & FILE_ATTRIBUTE_READONLY) fail(path + " is read-only; nothing was written");
        attributes = basic.FileAttributes & kept_attributes;
        std::string raw;
        TextFile old;
        std::string digest;
        if (read_all(existing.h, path, max_text_bytes, raw, cancelled)) {
            digest = sha256_hex(raw);
            old = decode(raw);
        } else {
            raw.clear();
            digest = hash_file_handle(existing.h, path, cancelled, &old);
        }
        check_digest_guards(args, path, digest, basic);
        require_read_snapshot(context, fs::path(target.full(target.parts.size())), digest,
                              args.get("expected_sha256") != nullptr);
        old_lines = old.binary ? 0 : old.lines;
        // CONTRACT: replacing also preserves large files' BOM and line-ending style without caching their bytes.
        if (!old.binary) {
            if (!encoding_given) encoding = old.encoding;
            if (endings.empty()) {
                const Eol style = eol_style(old);
                if (style == Eol::crlf || (style == Eol::mixed && old.crlf >= old.lf)) endings = "crlf";
                else if (style == Eol::lf || style == Eol::mixed) endings = "lf";
                else if (style == Eol::cr) endings = "cr";
            }
        }
    } else if (args.get("expected_sha256") || args.get("expected_mtime")) {
        fail(path + " does not exist, so expected_sha256/expected_mtime cannot match; nothing was written");
    }
    if (!exists && !encoding_given) {
        if (const auto configured = editorconfig_encoding(target, cancelled)) encoding = *configured;
        else if (const auto sibling = sibling_encoding(directory.h, target, cancelled)) encoding = *sibling;
    }
    if (!exists && endings.empty() && content.find_first_of("\r\n") != std::string::npos)
        endings = eol_for_new_file(directory.h, target, content, cancelled);
    std::string text;
    if (endings.empty()) {
        text = content;
    } else {
        const std::string_view eol = endings == "crlf" ? "\r\n" : endings == "cr" ? "\r" : "\n";
        text.reserve(content.size());
        for (size_t i = 0; i < content.size(); ++i) {
            if (content[i] == '\r') {
                if (i + 1 < content.size() && content[i + 1] == '\n') ++i;
                text += eol;
            } else if (content[i] == '\n') {
                text += eol;
            } else {
                text.push_back(content[i]);
            }
        }
    }
    const std::string bytes = encode(text, encoding);
    std::string commit_warning;
    const FILE_BASIC_INFO written = atomic_write(directory.h, target, bytes, exists, attributes,
                                                 exists ? &existing : nullptr, cancelled, &commit_warning);
    remember_read_snapshot(context, fs::path(target.full(target.parts.size())), sha256_hex(bytes));
    TextFile result;
    result.text = text;
    count_lines(result);
    std::string out = notice + std::string(exists ? "Replaced " : "Created ") + path + " (" + std::to_string(result.lines) +
                      " lines, " + std::to_string(bytes.size()) + " bytes, " + encoding_name(encoding) + ", " +
                      eol_name(result) + (exists ? "; it had " + std::to_string(old_lines) + " lines" : "") + ")";
    out += " | mtime " + format_mtime(written.LastWriteTime.QuadPart) + " | sha256 " + sha256_hex(bytes) + "\n" + commit_warning;
    if (!created.empty()) {
        out += "Created folders:";
        for (const auto& folder : created) out += " " + folder;
        out += "\n";
    }
    return Json::Object{{"text", std::move(out)}, {"access_note", notice}};
}

// ---- delete_file ----

Json delete_file(const Json& args, const SearchContext& context, const CancelFlag& cancelled) {
    const Target target = resolve(context, string_arg(args, "path"));
    if (target.parts.empty()) fail("delete_file cannot delete a configured root");
    const std::string path = target.display();
    const bool dry = bool_arg(args, "dry_run", false);
    std::unique_lock lock(write_mutex(), std::defer_lock);
    while (!lock.try_lock()) { check_cancelled(cancelled); Sleep(1); }
    check_cancelled(cancelled);
    Handle parent = open_parent(target, false, nullptr, cancelled);
    Handle file;
    // Deny concurrent writes and renames while hashing and deleting the verified handle.
    const NTSTATUS status = nt_open(parent.h, target.name(), FILE_GENERIC_READ | DELETE,
                                    FILE_SHARE_READ, disposition_open,
                                    option_non_directory | option_open_reparse_point, 0, file);
    if (status == status_is_directory) fail(path + " is a directory; delete_file only deletes files");
    if (status < 0) fail(path + ": " + status_text(status));
    refuse_link(file.h, path);
    const FILE_BASIC_INFO basic = basic_info(file.h, path);
    if (basic.FileAttributes & FILE_ATTRIBUTE_READONLY) fail(path + " is read-only; nothing was deleted");
    Sha256 hash;
    std::string buffer(1u << 20, '\0');
    uint64_t bytes = 0;
    for (;;) {
        check_cancelled(cancelled);
        DWORD got = 0;
        if (!ReadFile(file.h, buffer.data(), static_cast<DWORD>(buffer.size()), &got, nullptr))
            fail(path + ": read failed (" + win32_text(GetLastError()) + "); nothing was deleted");
        if (!got) break;
        hash.add(std::string_view(buffer.data(), got));
        bytes += got;
    }
    const std::string digest = hash.hex();
    if (args.get("expected_sha256")) {
        std::string expected = string_arg(args, "expected_sha256");
        std::transform(expected.begin(), expected.end(), expected.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (expected != digest) fail(path + " changed since it was read: its sha256 is now " +
                                     digest + ". Read it again; nothing was deleted");
    }
    check_cancelled(cancelled);
    require_unreplaced(parent.h, target, file.h);
    const std::string details = path + " (" + std::to_string(bytes) + " bytes, sha256 " + digest + ")";
    const fs::path snapshot_path(target.full(target.parts.size()));
    if (dry) {
        remember_read_snapshot(context, snapshot_path, digest);
        return Json::Object{{"text", "Dry run, nothing deleted. Would delete " + details + "\n"}};
    }
    require_read_snapshot(context, snapshot_path, digest, args.get("expected_sha256") != nullptr);
    check_cancelled(cancelled);
    const NtSetInformationFileFn set_information = nt_set_information_file();
    if (!set_information) fail("cannot delete " + path + ": NtSetInformationFile unavailable");
    struct DispositionEx { ULONG flags; } disposition{0x1 | 0x2};
    IO_STATUS_BLOCK io{};
    NTSTATUS deletion = set_information(file.h, &io, &disposition, sizeof(disposition), 64);
    bool pending = false;
    if (deletion < 0) {
        const uint32_t code = static_cast<uint32_t>(deletion);
        if (code != 0xC000000D && code != 0xC0000003 && code != 0xC00000BB)
            fail("cannot delete " + path + ": " + status_text(deletion) + "; nothing was deleted");
        FILE_DISPOSITION_INFO ordinary{TRUE};
        if (!SetFileInformationByHandle(file.h, FileDispositionInfo, &ordinary, sizeof(ordinary)))
            fail("cannot delete " + path + ": " + win32_text(GetLastError()) + "; nothing was deleted");
        pending = true;  // Other open handles can delay removal on filesystems without POSIX deletion.
    }
    file.close();
    forget_read_snapshot(context, snapshot_path);
    return Json::Object{{"text", std::string(pending ? "Marked for deletion " : "Deleted ") + details +
        (pending ? "; removal may wait for other handles to close.\n" : "\n")}};
}

// ---- move_file, create_directory ----

bool same_parts(const std::vector<std::wstring>& a, const std::vector<std::wstring>& b, size_t count) {
    for (size_t i = 0; i < count; ++i)
        if (CompareStringOrdinal(a[i].data(), static_cast<int>(a[i].size()), b[i].data(),
                                 static_cast<int>(b[i].size()), TRUE) != CSTR_EQUAL) return false;
    return true;
}

Json move_file_unlocked(const Json& args, const SearchContext& context, const CancelFlag& cancelled = {},
                        const std::string* planned_source_sha = nullptr) {
    check_cancelled(cancelled);
    const Target source = resolve(context, string_arg(args, "source"));
    const Target destination = resolve(context, string_arg(args, "destination"));
    const bool overwrite = bool_arg(args, "overwrite", false);
    if (source.parts.empty() || destination.parts.empty()) fail("move_file cannot move a configured root or onto one");
    const bool same_root = CompareStringOrdinal(source.root.data(), static_cast<int>(source.root.size()),
                                                destination.root.data(), static_cast<int>(destination.root.size()),
                                                TRUE) == CSTR_EQUAL;
    if (same_root && source.parts == destination.parts) fail("source and destination are the same path");
    if (same_root && destination.parts.size() > source.parts.size() &&
        same_parts(source.parts, destination.parts, source.parts.size()))
        fail("cannot move a directory into itself");
    Handle source_directory = open_parent(source, false, nullptr, cancelled);
    Handle item;
    const NTSTATUS status = nt_open(source_directory.h, source.name(), DELETE | FILE_GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_DELETE,
                                    disposition_open, option_open_reparse_point, 0, item);
    if (status < 0) fail(source.display() + ": " + status_text(status));
    refuse_link(item.h, source.display());
    const bool is_directory = (attributes_of(item.h, source.display()) & FILE_ATTRIBUTE_DIRECTORY) != 0;
    std::string source_sha;
    if (!is_directory) {
        source_sha = hash_file_handle(item.h, source.display(), cancelled);
        if (planned_source_sha) {
            if (source_sha != *planned_source_sha) fail("move source changed after planning; nothing moved");
        } else {
            check_digest_guards(args, source.display(), source_sha, basic_info(item.h, source.display()));
            require_read_snapshot(context, fs::path(source.full(source.parts.size())), source_sha, args.get("expected_sha256"));
        }
    } else if (args.get("expected_sha256") || args.get("expected_mtime")) {
        fail("move snapshot guards apply to files, not directories");
    }
    std::vector<std::string> created;
    Handle destination_directory = open_parent(destination, true, &created, cancelled);
    Handle previous;
    bool replace_existing = false;
    if (overwrite) {
        const NTSTATUS opened = nt_open(destination_directory.h, destination.name(), FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE, disposition_open, option_non_directory | option_open_reparse_point, 0, previous);
        if (opened >= 0) {
            refuse_link(previous.h, destination.display());
            const std::string digest = hash_file_handle(previous.h, destination.display(), cancelled);
            const Json* expected = args.get("expected_destination_sha256");
            if (expected) check_digest_guards(Json::Object{{"expected_sha256", *expected}},
                destination.display(), digest, FILE_BASIC_INFO{});
            require_read_snapshot(context, fs::path(destination.full(destination.parts.size())), digest, expected);
            replace_existing = true;
        } else if (static_cast<uint32_t>(opened) != 0xC0000034) {
            fail(destination.display() + ": " + status_text(opened));
        } else if (args.get("expected_destination_sha256")) {
            fail("expected move destination does not exist; nothing moved");
        }
    } else if (args.get("expected_destination_sha256")) fail("expected_destination_sha256 requires overwrite=true");
    check_cancelled(cancelled);
    require_unreplaced(source_directory.h, source, item.h);
    std::string commit_warning;
    // A case-only rename with overwrite opens the source itself as the destination; that is a plain rename.
    if (previous && same_file(previous.h, item.h)) previous.close();
    if (previous) {
        if (is_directory) fail("cannot move directory " + source.display() + " over the file " + destination.display());
        // The replaced destination must still be the file whose bytes were checked; see commit_over.
        try { commit_warning = commit_over(destination_directory.h, destination, item.h, previous.h); }
        catch (const std::exception& e) { fail("cannot move " + source.display() + " to " + destination.display() + ": " + e.what()); }
    } else if (const DWORD code = rename_handle(item.h, destination_directory.h, destination.name(), replace_existing, nullptr)) {
        fail("cannot move " + source.display() + " to " + destination.display() + ": " + rename_error(code));
    }
    forget_read_snapshots_under(context, fs::path(source.full(source.parts.size())));
    forget_read_snapshots_under(context, fs::path(destination.full(destination.parts.size())));
    std::string out = std::string("Moved ") + (is_directory ? "directory " : "") + source.display() + " -> " +
                      destination.display() + "\n" + commit_warning;
    Json::Array moved_files;
    if (!is_directory) {
        // The rename above is the commit point: a later metadata failure is reported, never thrown, so callers do
        // not roll back other edits around a move that already happened.
        std::string mtime;
        try { mtime = format_mtime(basic_info(item.h, destination.display()).LastWriteTime.QuadPart); }
        catch (const std::exception& e) {
            out += "[warning: moved, but its new metadata could not be read: " + std::string(e.what()) + "]\n";
        }
        remember_read_snapshot(context, fs::path(destination.full(destination.parts.size())), source_sha);
        moved_files.emplace_back(Json::Object{{"path", destination.display()}, {"sha256", source_sha}, {"mtime", mtime}});
        out += destination.display() + (mtime.empty() ? std::string() : " | mtime " + mtime) + " | sha256 " + source_sha + "\n";
    }
    if (!created.empty()) {
        out += "Created folders:";
        for (const auto& folder : created) out += " " + folder;
        out += "\n";
    }
    return Json::Object{{"text", std::move(out)}, {"files", std::move(moved_files)}};
}

Json move_file(const Json& args, const SearchContext& context) {
    std::lock_guard lock(write_mutex());
    return move_file_unlocked(args, context);
}

Json create_directory(const Json& args, const SearchContext& context, const CancelFlag& cancelled = {}) {
    check_cancelled(cancelled);
    const Target target = resolve(context, string_arg(args, "path"));
    if (target.parts.empty()) fail("path names a configured root, which already exists");
    const std::string path = target.display();
    std::lock_guard lock(write_mutex());
    std::vector<std::string> created;
    Handle parent = open_parent(target, true, &created, cancelled);
    check_cancelled(cancelled);
    Handle directory;
    ULONG_PTR information = 0;
    const NTSTATUS status = nt_open(parent.h, target.name(), directory_access, share_all, disposition_open_if,
                                    option_directory | option_open_reparse_point, 0, directory, &information);
    if (status == status_not_directory) fail(path + " exists and is a file");
    if (status < 0) fail(path + ": " + status_text(status));
    refuse_link(directory.h, path);
    if (information == information_created) created.push_back(target.relative() + "/");
    if (created.empty()) return Json::Object{{"text", "Already exists: " + path + "\n"}};
    std::string out = "Created " + path + "\nCreated folders:";
    for (const auto& folder : created) out += " " + folder;
    return Json::Object{{"text", out + "\n"}};
}
}

SourceText source_descriptor(const SearchContext& context, const std::string& path, bool* directory, bool allow_missing, bool* exists) {
    const Target target = resolve(context, path);
    Handle item = open_root(target);
    bool present = true;
    for (size_t i = 0; i < target.parts.size(); ++i) {
        Handle child;
        const bool last = i + 1 == target.parts.size();
        const NTSTATUS status = nt_open(item.h, target.parts[i], last ? FILE_READ_ATTRIBUTES : directory_access, share_all,
            disposition_open, option_open_reparse_point | (last ? 0 : option_directory), 0, child);
        if (status < 0) {
            if (allow_missing && (static_cast<uint32_t>(status) == 0xC0000034 || static_cast<uint32_t>(status) == 0xC000003A)) {
                present = false; item.close(); break;
            }
            fail(target.display(i + 1) + ": " + status_text(status));
        }
        refuse_link(child.h, target.display(i + 1));
        item = std::move(child);
    }
    if (exists) *exists = present;
    if (directory) *directory = item && (attributes_of(item.h, target.display()) & FILE_ATTRIBUTE_DIRECTORY);
    return {fs::path(target.full(target.parts.size())), fs::path(target.root), {}, {}};
}

namespace {
thread_local bool request_deadline_set = false;
thread_local Clock::time_point current_request_deadline;
}
Clock::time_point request_deadline(Clock::time_point stage) {
    return request_deadline_set ? std::min(stage, current_request_deadline) : stage;
}
RequestDeadline::RequestDeadline(Clock::time_point deadline)
    : had_previous_(request_deadline_set), previous_(current_request_deadline) {
    current_request_deadline = had_previous_ ? std::min(deadline, previous_) : deadline;
    request_deadline_set = true;
}
RequestDeadline::~RequestDeadline() {
    request_deadline_set = had_previous_;
    current_request_deadline = previous_;
}

std::string render_semantic_text(const Json& result, bool outline,
                                 const std::shared_ptr<std::atomic_bool>& cancelled, bool line_numbers,
                                 bool symbol_text) {
    const auto check = [&] {
        if (cancelled && cancelled->load()) fail("response rendering cancelled");
        if (Clock::now() >= request_deadline(Clock::time_point::max())) fail("response rendering timed out");
    };
    check();
    if (const auto* text = std::get_if<std::string>(&result.value)) return *text;
    if (outline) return compact_outline(result, symbol_text);
    if (const Json* files = result.get("files")) {
        std::string out;
        for (const auto& file : files->array()) {
            check();
            out += render_semantic_text(semantic_file_result(result, file), false, cancelled, line_numbers);
        }
        return out + semantic_read_notes(result);
    }
    const Json* items = result.get("results");
    if (!items || !std::holds_alternative<Json::Array>(items->value)) return result.dump(check);
    std::string out;
    for (const auto& item : items->array()) {
        check();
        const Json* body = item.get("body");
        if (!body) { out += item.dump(check) + "\n"; continue; }
        const auto field = [&](const char* key) -> const Json* {
            if (const Json* value = item.get(key)) return value;
            return result.get(key);
        };
        const Json* bounds = item.get("body_range");
        if (!bounds) bounds = item.get("range");
        int64_t line = item.get("body_start_line") ? item.get("body_start_line")->integer()
            : (bounds && bounds->get("start_line") ? bounds->get("start_line")->integer()
                : (item.get("line") ? item.get("line")->integer() : 1));
        const std::string& source = body->string();
        int64_t last = line;
        if (!source.empty()) {
            for (size_t i = 0; i < source.size(); ++i) {
                if (source[i] == '\r' || source[i] == '\n') {
                    if (source[i] == '\r' && i + 1 < source.size() && source[i + 1] == '\n') ++i;
                    ++last;
                }
            }
            if (source.back() == '\r' || source.back() == '\n') --last;
        } else --last;
        out += "[";
        if (const Json* path = field("path")) out += path->string();
        if (const Json* name_path = item.get("name_path")) out += " | " + name_path->string();
        else if (const Json* owner = item.get("symbol")) out += " | " + owner->string();
        out += " | L" + std::to_string(line) + "-" + std::to_string(last);
        if (item.get("line") && item.get("column"))
            out += " | at " + std::to_string(item.get("line")->integer()) + ":" +
                   std::to_string(item.get("column")->integer());
        if (const Json* sha = field("sha256")) out += " | sha256 " + sha->string();
        if (const Json* mtime = field("mtime")) out += " | mtime " + mtime->string();
        out += " | source: lsp]\n";
        for (size_t at = 0; at < source.size();) {
            check();
            const size_t next = source.find_first_of("\r\n", at);
            const size_t end = next == std::string::npos ? source.size() : next;
            if (line_numbers) out += std::to_string(line) + " | ";
            ++line;
            out.append(source, at, end - at);
            out += '\n';
            if (next == std::string::npos) break;
            at = next + ((source[next] == '\r' && next + 1 < source.size() && source[next + 1] == '\n') ? 2 : 1);
        }
        if (const Json* next = item.get("next_offset"))
            out += "[more: read_symbol offset=" + std::to_string(next->integer()) + "]\n";
    }
    if (items->array().empty()) {
        out = "[lsp | 0 results";
        if (const Json* path = result.get("path")) out += " | " + path->string();
        else if (const Json* requested = result.get("requested_path")) out += " | " + requested->string();
        if (const Json* sha = result.get("sha256")) out += " | sha256 " + sha->string();
        if (const Json* mtime = result.get("mtime")) out += " | mtime " + mtime->string();
        out += "]\n";
    }
    std::string omitted;
    for (const char* key : {"outside_roots", "stale_locations", "ignored_locations", "symbols_omitted"})
        if (const Json* count = result.get(key); count && count->integer())
            omitted += std::string(omitted.empty() ? "" : ", ") + key + "=" + std::to_string(count->integer());
    if (!omitted.empty()) out += "[lsp result notes: " + omitted + "]\n";
    return out + semantic_read_notes(result);
}

Json apply_source_changes(const std::vector<SourceChange>& changes, const Json& arguments,
                          const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled,
                          const Json* move_arguments) {
    if (context.read_only) fail("writes are disabled: --read-only");
    const bool dry = bool_arg(arguments, "dry_run", false);
    const auto deadline = request_deadline(Clock::now() + std::chrono::milliseconds(int_arg(arguments, "timeout_ms", 30000, 1, 300000)));
    auto check = [&] {
        if (cancelled && cancelled->load()) fail("edit cancelled before commit");
        if (Clock::now() >= deadline) fail("edit timed out before commit");
    };
    std::lock_guard lock(write_mutex());
    struct Pending {
        Target target;
        Handle parent, original;
        FILE_BASIC_INFO basic{};
        std::string old_bytes, new_bytes;
        std::unique_ptr<StagedWrite> replacement, recovery;
        bool committed = false;
    };
    std::vector<std::unique_ptr<Pending>> pending;
    std::vector<std::pair<fs::path, std::string>> preview_snapshots;
    std::set<std::wstring> seen;
    std::string out;
    std::string committed_metadata, commit_warnings;
    Json::Array committed_files;
    std::optional<Target> move_source, move_destination;
    std::string move_source_sha;
    bool move_is_file = false;
    if (move_arguments) {
        move_source = resolve(context, string_arg(*move_arguments, "source"));
        move_destination = resolve(context, string_arg(*move_arguments, "destination"));
        bool directory = false;
        (void)source_descriptor(context, string_arg(*move_arguments, "source"), &directory);
        if (!directory) {
            Handle parent = open_parent(*move_source, false);
            Handle file = open_file(parent.h, *move_source, FILE_SHARE_READ | FILE_SHARE_DELETE);
            move_source_sha = hash_file_handle(file.h, move_source->display(), cancelled);
            move_is_file = true;
            check_digest_guards(*move_arguments, move_source->display(), move_source_sha, basic_info(file.h, move_source->display()));
            const fs::path path(move_source->full(move_source->parts.size()));
            if (dry) preview_snapshots.emplace_back(path, move_source_sha);
            else require_read_snapshot(context, path, move_source_sha, move_arguments->get("expected_sha256"));
        } else if (move_arguments->get("expected_sha256") || move_arguments->get("expected_mtime")) {
            fail("move snapshot guards apply to files, not directories");
        }
        const Json* destination_sha = move_arguments->get("expected_destination_sha256");
        if (destination_sha && !bool_arg(*move_arguments, "overwrite", false))
            fail("expected_destination_sha256 requires overwrite=true");
        if (dry && bool_arg(*move_arguments, "overwrite", false)) {
            bool exists = false;
            (void)source_descriptor(context, string_arg(*move_arguments, "destination"), nullptr, true, &exists);
            if (exists) {
                Handle parent = open_parent(*move_destination, false);
                Handle file = open_file(parent.h, *move_destination, FILE_SHARE_READ | FILE_SHARE_DELETE);
                const std::string digest = hash_file_handle(file.h, move_destination->display(), cancelled);
                if (destination_sha) check_digest_guards(Json::Object{{"expected_sha256", *destination_sha}},
                    move_destination->display(), digest, FILE_BASIC_INFO{});
                preview_snapshots.emplace_back(fs::path(move_destination->full(move_destination->parts.size())), digest);
            } else if (destination_sha) fail("expected move destination does not exist; nothing moved");
        }
    }
    std::wstring primary;
    if (arguments.get("path")) { const Target target = resolve(context, string_arg(arguments, "path")); primary = target.full(target.parts.size()); }
    for (const auto& change : changes) {
        check();
        auto p = std::make_unique<Pending>();
        p->target = resolve(context, [&] { std::string s; if (!try_utf8(change.before.path.wstring(), s)) fail("invalid path"); return s; }());
        std::wstring key = p->target.full(p->target.parts.size());
        std::transform(key.begin(), key.end(), key.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
        if (!seen.insert(key).second) fail("duplicate file in workspace edit");
        p->parent = open_parent(p->target, false);
        p->original = open_file(p->parent.h, p->target, FILE_SHARE_READ | FILE_SHARE_DELETE);
        p->basic = basic_info(p->original.h, p->target.display());
        if (!read_all(p->original.h, p->target.display(), max_text_bytes, p->old_bytes)) fail("workspace edit file exceeds 64 MiB");
        if (sha256_hex(p->old_bytes) != change.before.sha256) fail(p->target.display() + " changed before commit; nothing was written");
        const bool is_primary = (!primary.empty() && primary == p->target.full(p->target.parts.size())) ||
            (move_source && move_source->full(move_source->parts.size()) == p->target.full(p->target.parts.size()));
        if (is_primary) check_guards(arguments, p->target.display(), p->old_bytes, p->basic);
        const fs::path snapshot_path(p->target.full(p->target.parts.size()));
        const std::string digest = sha256_hex(p->old_bytes);
        if (dry) preview_snapshots.emplace_back(snapshot_path, digest);
        else require_read_snapshot(context, snapshot_path, digest, is_primary && arguments.get("expected_sha256"));
        const TextFile text = decode(p->old_bytes);
        if (text.binary || text.invalid || text.text != change.before.text) fail("workspace edit snapshot mismatch");
        if (!dry && (p->basic.FileAttributes & FILE_ATTRIBUTE_READONLY)) fail(p->target.display() + " is read-only; nothing was written");
        p->new_bytes = encode(change.after, text.encoding);
        if (p->new_bytes.size() > max_text_bytes) fail("workspace edit result exceeds 64 MiB");
        if (p->new_bytes == p->old_bytes) continue;
        out += unified_diff(text.text, change.after, p->target.relative(), cancelled).text;
        pending.push_back(std::move(p));
    }
    if (dry) {
        for (const auto& [path, digest] : preview_snapshots) remember_read_snapshot(context, path, digest);
        return Json::Object{{"text", "Dry run, nothing written. " + std::to_string(pending.size()) + " files would change.\n" +
            (move_arguments ? "Would move " + string_arg(*move_arguments, "source") + " -> " + string_arg(*move_arguments, "destination") + "\n" : "") + out}};
    }
    // Stage every replacement and recovery before the first target is changed.
    for (auto& p : pending) {
        check();
        p->replacement = stage_write(p->parent.h, p->target, p->new_bytes, p->basic.FileAttributes & kept_attributes, p->original.h);
        p->recovery = stage_write(p->parent.h, p->target, p->old_bytes, p->basic.FileAttributes & kept_attributes, p->original.h);
        if (!SetFileInformationByHandle(p->recovery->file.h, FileBasicInfo, &p->basic, sizeof(p->basic)))
            fail("cannot prepare recovery metadata; nothing was written");
    }
    try {
        check();
        for (auto& p : pending) {
            check();
            commit_warnings += commit_over(p->parent.h, p->target, p->replacement->file.h, p->original.h);
            p->replacement->armed = false;
            p->replacement->file.close();
            p->committed = true;
            p->original.close();
            p->original = open_file(p->parent.h, p->target, FILE_SHARE_READ | FILE_SHARE_DELETE);
            std::string actual;
            if (!read_all(p->original.h, p->target.display(), max_text_bytes, actual) || actual != p->new_bytes)
                fail(p->target.display() + ": replacement read-back differs");
            Target result_target = p->target;
            if (move_source && same_name(move_source->root, p->target.root.c_str()) &&
                p->target.parts.size() >= move_source->parts.size() &&
                same_parts(move_source->parts, p->target.parts, move_source->parts.size())) {
                result_target = *move_destination;
                result_target.parts.insert(result_target.parts.end(),
                    p->target.parts.begin() + move_source->parts.size(), p->target.parts.end());
            }
            const std::string path = result_target.display();
            const std::string digest = sha256_hex(actual);
            const std::string mtime = format_mtime(basic_info(p->original.h, p->target.display()).LastWriteTime.QuadPart);
            committed_files.emplace_back(Json::Object{{"path", path}, {"sha256", digest}, {"mtime", mtime}});
            committed_metadata += path + " | mtime " + mtime + " | sha256 " + digest + "\n";
        }
        // The move is last: its failure restores all preceding import/reference edits.
        if (move_arguments) {
            for (auto& p : pending) {
                if (move_is_file && p->target.full(p->target.parts.size()) == move_source->full(move_source->parts.size()))
                    move_source_sha = sha256_hex(p->new_bytes);
                p->original.close();
            }
            const Json moved = move_file_unlocked(*move_arguments, context, cancelled, move_is_file ? &move_source_sha : nullptr);
            out += moved.get("text")->string();
            for (const auto& file : moved.get("files")->array()) {
                const std::string path = file.get("path")->string();
                const bool already_reported = std::any_of(committed_files.begin(), committed_files.end(),
                    [&](const Json& previous) { return previous.get("path")->string() == path; });
                if (!already_reported) committed_files.push_back(file);
            }
        }
    } catch (const std::exception& error) {
        std::string recovery_errors;
        for (auto it = pending.rbegin(); it != pending.rend(); ++it) {
            auto& p = *it;
            if (!p->committed) continue;
            try {
                p->original.close();
                p->original = open_file(p->parent.h, p->target, FILE_SHARE_READ | FILE_SHARE_DELETE);
                std::string actual;
                if (!read_all(p->original.h, p->target.display(), max_text_bytes, actual) || actual != p->new_bytes)
                    fail("concurrent modification; recovery refused to overwrite it");
                commit_warnings += commit_over(p->parent.h, p->target, p->recovery->file.h, p->original.h);
                p->recovery->armed = false;
            } catch (const std::exception& e) {
                std::string backup;
                try { try_utf8(without_verbatim(final_path(p->recovery->file.h)), backup); } catch (...) {}
                p->recovery->armed = false;
                recovery_errors += "\n" + p->target.display() + ": " + e.what() + "; recovery bytes retained at " + backup;
            }
        }
        fail(std::string(error.what()) + (recovery_errors.empty() ? "; committed text changes restored" :
             "; recovery incomplete, inspect these files:" + recovery_errors) +
             (commit_warnings.empty() ? "" : "\n" + commit_warnings));
    }
    for (const auto& file : committed_files)
        remember_read_snapshot(context, native_path(file.get("path")->string()), file.get("sha256")->string());
    return Json::Object{{"text", "Applied " + std::to_string(pending.size()) + " file changes.\n" + committed_metadata +
                                 commit_warnings + out},
                        {"files", std::move(committed_files)}};
}

void write_workspace_metadata(const SearchContext& context, const fs::path& path, const std::string& bytes) {
    if (context.read_only) fail("writes are disabled: --read-only");
    const Target target = resolve(context, utf8(path.wstring()));
    if (target.parts.empty()) fail("metadata path names a configured root");
    std::lock_guard lock(write_mutex());
    Handle parent = open_parent(target, true);
    Handle original;
    const NTSTATUS status = nt_open(parent.h, target.name(), FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                    disposition_open, option_non_directory | option_open_reparse_point, 0, original);
    DWORD attributes = 0;
    if (status >= 0) {
        refuse_link(original.h, target.display());
        const FILE_BASIC_INFO basic = basic_info(original.h, target.display());
        std::string current;
        if (read_all(original.h, target.display(), static_cast<uint64_t>(bytes.size()), current) && current == bytes) return;
        if (basic.FileAttributes & FILE_ATTRIBUTE_READONLY) fail(target.display() + " is read-only");
        attributes = basic.FileAttributes & kept_attributes;
    } else if (static_cast<uint32_t>(status) != 0xC0000034) fail(target.display() + ": " + status_text(status));
    (void)atomic_write(parent.h, target, bytes, static_cast<bool>(original), attributes, original ? &original : nullptr);
}

// The metadata folder `path` (and its missing parents), made through the same no-link handles.
void create_workspace_metadata_directory(const SearchContext& context, const fs::path& path) {
    if (context.read_only) fail("writes are disabled: --read-only");
    const Target target = resolve(context, utf8(path.wstring()));
    if (target.parts.empty()) fail("metadata path names a configured root");
    std::lock_guard lock(write_mutex());
    Handle parent = open_parent(target, true);
    Handle directory;
    const NTSTATUS status = nt_open(parent.h, target.name(), directory_access, share_all, disposition_open_if,
                                    option_directory | option_open_reparse_point, 0, directory);
    if (status < 0) fail(target.display() + ": " + status_text(status));
    refuse_link(directory.h, target.display());
}

// Opens the metadata file `path` emptied for writing, through the same no-link handles; inheritable, for a child
// process's output. Others may read it meanwhile.
HANDLE create_workspace_metadata_log(const SearchContext& context, const fs::path& path) {
    if (context.read_only) fail("writes are disabled: --read-only");
    const Target target = resolve(context, utf8(path.wstring()));
    if (target.parts.empty()) fail("metadata path names a configured root");
    std::lock_guard lock(write_mutex());
    Handle parent = open_parent(target, true);
    Handle file;
    // FILE_READ_ATTRIBUTES: refuse_link reads the attributes; FILE_GENERIC_WRITE alone makes it fail with access denied.
    const NTSTATUS status = nt_open(parent.h, target.name(), FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                                    disposition_open_if,
                                    option_non_directory | option_open_reparse_point, FILE_ATTRIBUTE_NORMAL, file);
    if (status < 0) fail(target.display() + ": " + status_text(status));
    refuse_link(file.h, target.display());
    FILE_END_OF_FILE_INFO end{};
    if (!SetFileInformationByHandle(file.h, FileEndOfFileInfo, &end, sizeof(end)) ||
        !SetHandleInformation(file.h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        const DWORD code = GetLastError();
        fail(target.display() + ": cannot prepare it for writing (" + win32_text(code) + ")");
    }
    return std::exchange(file.h, INVALID_HANDLE_VALUE);
}

Json save_output_artifact(const SearchContext& context, const std::function<bool(std::string&)>& next,
                          const std::function<void()>& check) {
    if (context.read_only) fail("output offloading is disabled in read-only mode");
    if (context.allowed_roots.empty()) fail("output offloading requires a configured root");
    check();
    std::lock_guard lock(write_mutex());
    static std::atomic<uint64_t> serial{0};
    const auto candidate = [&] {
        return context.allowed_roots.front() / L".shgrep-output" /
            (L"result-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) +
             L"-" + std::to_wstring(++serial) + L".txt");
    };
    Target target = resolve(context, utf8(candidate().wstring()));
    Handle parent = open_parent(target, true);
    auto staged = stage_write(parent.h, target, {}, FILE_ATTRIBUTE_NORMAL);
    uint64_t total = 0;
    size_t preview_characters = 0;
    std::string preview, piece;
    while (next(piece)) {
        check();
        for (size_t at = 0; at < piece.size();) {
            check();
            const DWORD count = static_cast<DWORD>(std::min<size_t>(piece.size() - at, size_t{1} << 20));
            DWORD written = 0;
            if (!WriteFile(staged->file.h, piece.data() + at, count, &written, nullptr) || !written)
                fail("cannot save output: " + win32_text(GetLastError()));
            at += written;
            total += written;
        }
        for (const unsigned char c : piece) {
            if ((c & 0xC0) != 0x80) {
                if (preview_characters == 500) break;
                ++preview_characters;
            }
            preview += static_cast<char>(c);
        }
        piece.clear();
    }
    check();
    if (!FlushFileBuffers(staged->file.h)) fail("cannot flush saved output: " + win32_text(GetLastError()));
    for (int attempt = 0;; ++attempt) {
        check();
        const DWORD code = rename_handle(staged->file.h, parent.h, target.name(), false, nullptr);
        if (!code) break;
        if ((code != ERROR_ALREADY_EXISTS && code != ERROR_FILE_EXISTS) || attempt == 8)
            fail("cannot publish saved output: " + rename_error(code));
        target = resolve(context, utf8(candidate().wstring()));
    }
    staged->armed = false;
    return Json::Object{{"path", target.display()}, {"bytes", total}, {"preview", std::move(preview)}};
}

std::string source_text_digest(std::string_view text) { return sha256_hex(text); }

static std::wstring snapshot_key(const fs::path& path) {
    // Windows directories can be case-sensitive. Different spellings must never share a guard.
    return path.lexically_normal().wstring();
}

void remember_read_snapshot(const SearchContext& context, const fs::path& path, const std::string& sha256) {
    if (context.read_snapshots) context.read_snapshots->remember(snapshot_key(path), sha256);
}

void forget_read_snapshot(const SearchContext& context, const fs::path& path) {
    if (context.read_snapshots) context.read_snapshots->erase(snapshot_key(path));
}

void forget_read_snapshots_under(const SearchContext& context, const fs::path& path) {
    if (!context.read_snapshots) return;
    const std::wstring key = snapshot_key(path);
    context.read_snapshots->erase_under(key, key.ends_with(L"\\") ? key : key + L"\\");
}

void require_read_snapshot(const SearchContext& context, const fs::path& path,
                           const std::string& sha256, bool explicit_sha_guard) {
    if (explicit_sha_guard) return;  // The ordinary expected_sha256 check validates this guard under the write lock.
    if (!context.read_snapshots) fail("read history is unavailable; supply expected_sha256");
    const std::string remembered = context.read_snapshots->find(snapshot_key(path));
    if (remembered.empty())
        fail("read the file in this session (or read it again: its read record expired) or supply expected_sha256 "
             "before editing; nothing was written");
    if (remembered != sha256)
        fail("file changed since it was read in this session; read it again; nothing was written");
}

SourceText read_source_text(const SearchContext& context, const std::string& path) {
    const Target target = resolve(context, path);
    if (target.parts.empty()) fail("expected a file: " + path);
    Handle parent = open_parent(target, false);
    Handle file = open_file(parent.h, target, share_all);
    std::string raw;
    if (!read_all(file.h, path, max_text_bytes, raw)) fail(path + " is larger than 64 MiB");
    TextFile text = decode(raw);
    if (text.binary || text.invalid) fail(path + " is not valid Unicode source text");
    return {std::filesystem::path(target.full(target.parts.size())), std::filesystem::path(target.root),
            std::move(text.text), sha256_hex(raw), format_mtime(basic_info(file.h, path).LastWriteTime.QuadPart)};
}

std::filesystem::path executable_directory() {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (n == 0) return {};
        if (n < buffer.size()) { buffer.resize(n); break; }
        if (buffer.size() >= 32768) return {};
        buffer.resize(buffer.size() * 2);
    }
    return std::filesystem::path(buffer).parent_path();
}

std::string language_extension(const std::filesystem::path& path) {
    // CMake's project file has no .cmake extension, but its server and language are CMake's.
    if (_wcsicmp(path.filename().c_str(), L"CMakeLists.txt") == 0) return ".cmake";
    std::string ext;
    if (!try_utf8(path.extension().wstring(), ext)) return {};
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return ext;
}

std::vector<std::string> source_paths(const SearchContext& context, const std::string& root,
    const std::vector<std::string>& extensions, Clock::time_point deadline,
    const std::shared_ptr<std::atomic_bool>& cancelled,
    const std::function<bool(const std::string&, bool)>& filter) {
    const Target target = resolve(context, root);
    if (!target.parts.empty()) fail("LSP workspace must be a configured root");
    Handle directory = open_root(target);
    std::vector<std::string> paths;
    std::function<void(HANDLE, const std::wstring&, const std::string&, std::shared_ptr<const IgnoreScope>)> walk;
    walk = [&](HANDLE handle, const std::wstring& absolute, const std::string& relative,
               std::shared_ptr<const IgnoreScope> scope) {
        if (cancelled && cancelled->load()) fail("LSP request cancelled");
        if (Clock::now() >= deadline) fail("LSP synchronization timed out");
        std::vector<uint64_t> buffer((64 * 1024) / sizeof(uint64_t));
        std::vector<DirEntry> entries;
        if (!list_directory(handle, buffer, entries)) fail("cannot enumerate LSP workspace: " + root);
        bool gitignore = false, dotignore = false, git_dir = false;
        for (const auto& e : entries) note_rule_file(e.name, e.attributes, gitignore, dotignore, git_dir);
        if (gitignore || dotignore || git_dir) {
            auto next = std::make_shared<IgnoreScope>();
            next->parent = scope;
            read_ignore_rules(absolute, relative, gitignore, dotignore, next->rules, handle, git_dir);
            if (!next->rules.empty()) scope = std::move(next);
        }
        for (const auto& e : entries) {
            if (cancelled && cancelled->load()) fail("LSP request cancelled");
            if (Clock::now() >= deadline) fail("LSP synchronization timed out");
            if (e.attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_HIDDEN)) continue;
            std::string name;
            if (!try_utf8(e.name, name) || name.empty() || name.front() == '.') continue;
            const bool folder = (e.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const std::string child = relative.empty() ? name : relative + "/" + name;
            if (ignored_path(scope.get(), child, folder) || (filter && !filter(child, folder))) continue;
            if (folder) {
                bool denied = false;
                Handle sub(open_relative(handle, e.name, true, denied));
                if (!sub) fail("cannot enumerate LSP directory: " + child);
                walk(sub.h, join_path(absolute, e.name), child, scope);
            } else {
                const std::string ext = language_extension(std::filesystem::path(e.name));
                if (extensions.empty() || std::find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
                    std::string path;
                    if (!try_utf8(join_path(absolute, e.name), path)) fail("invalid source path");
                    if (extensions.empty() && paths.size() >= 1000000) fail("file enumeration exceeds one million paths; narrow the edit scope");
                    paths.push_back(std::move(path));
                }
            }
        }
    };
    walk(directory.h, target.root, "", nullptr);
    std::sort(paths.begin(), paths.end());
    return paths;
}

bool is_file_tool(const std::string& name) {
    return name == "read_file" || name == "list_dir" || name == "file_info" || is_write_tool(name);
}

bool is_write_tool(const std::string& name) {
    return name == "edit_file" || name == "write_file" || name == "delete_file" || name == "move_file" || name == "create_directory";
}

// Report the same live decision that unrestricted text edits use, without making an edit.
Json file_lsp_availability(const Json& arguments, const SearchContext& context, const CancelFlag& cancelled) {
    if (arguments.get("paths")) fail("availability requires a single path");
    const std::string path = string_arg(arguments, "path");
    bool directory = false;
    const SourceText source = source_descriptor(context, path, &directory);
    if (directory) fail("availability requires a file, not a directory");
    Json::Object result{{"path", path}, {"fallback_eligible", false},
                        {"requires_text_fallback", lsp_required(source.path)}};
    if (!lsp_required(source.path)) {
        result["state"] = "not_applicable";
        result["reason"] = "This file does not require LSP for text edits.";
        return result;
    }
    try {
        const std::string reason = lsp_fallback_reason(source, arguments, context, cancelled);
        if (reason.empty()) {
            result["state"] = "available";
            result["reason"] = "The current file overview probe succeeded.";
        } else {
            result["state"] = "unavailable";
            result["reason"] = reason;
            result["fallback_eligible"] = true;
        }
    } catch (const IndexWarmingFailure& error) {
        if ((cancelled && cancelled->load()) || Clock::now() >= request_deadline(Clock::time_point::max())) throw;
        result["state"] = "warming";
        result["reason"] = error.what();
        result["details"] = error.details;
    }
    return result;
}


// Identity of an error diagnostic across edits: line numbers shift, so only source, code and message count.
static std::string diagnostic_identity(const Json& item) {
    std::string key;
    for (const char* field : {"source", "code", "message"}) {
        if (const Json* value = item.get(field))
            key += std::holds_alternative<std::string>(value->value) ? value->string() : value->dump();
        key += '\x1f';
    }
    return key;
}
static void add_rollback_warning(Json& result, const std::string& message) {
    auto& object = std::get<Json::Object>(result.value);
    object.at("text") = object.at("text").string() + message;
    if (auto it = object.find("warning"); it != object.end()) it->second = it->second.string() + message;
    else object.emplace("warning", message);
}
static std::map<std::string, size_t> error_identities(const Json& report) {
    std::map<std::string, size_t> keys;
    if (const Json* items = report.get("items"))
        for (const auto& item : items->array()) {
            const Json* severity = item.get("severity");
            if (severity && std::holds_alternative<int64_t>(severity->value) && severity->integer() != 1) continue;
            ++keys[diagnostic_identity(item)];
        }
    return keys;
}

Json run_file_tool(const std::string& name, const Json& arguments, const SearchContext& context,
                   const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (!std::holds_alternative<Json::Object>(arguments.value)) fail("arguments must be an object");
    if (context.read_only && is_write_tool(name)) fail(name + " is disabled: this server runs with --read-only");
    reject_unknown(name, arguments);
    const bool want_diagnostics = (name == "edit_file" || name == "write_file") &&
        bool_arg(arguments, "diagnostics", true);
    const bool dry_run = is_write_tool(name) && bool_arg(arguments, "dry_run", false);
    if (name == "edit_file") (void)max_output_arg(arguments);
    if (cancelled && cancelled->load()) fail("request cancelled");
    const std::string operation = arguments.get("operation") ? string_arg(arguments, "operation") : "auto";
    if (name == "read_file") return read_file(arguments, context, cancelled);
    if (name == "list_dir") {
        if (operation == "auto" || operation == "filesystem") {
            if (arguments.get("format")) fail("format is only for operation=overview");
            return list_dir(arguments, context, cancelled);
        }
        if (operation != "overview") fail("list_dir operation must be filesystem or overview");
        for (const char* key : {"hidden", "no_ignore", "max_results", "max_output_bytes"})
            if (arguments.get(key)) fail(std::string(key) + " is only for filesystem listing");
        Json::Object query = arguments.object();
        if (!query.contains("path")) query.emplace("path", ".");
        const bool json_format = outline_format(arguments) == "json";
        query.erase("format");
        try {
            const Json result = lsp_query("overview", query, context, cancelled);
            if (json_format) return Json::Object{{"structured_result", result}};
            return Json::Object{{"text", compact_outline(result)}};
        }
        catch (const LspFailure&) { throw; }
    }
    if (name == "file_info") {
        if (operation != "diagnostics")
            for (const char* key : {"start_line", "end_line", "group_by_symbol"})
                if (arguments.get(key)) fail(std::string(key) + " requires operation=diagnostics");
        if (arguments.get("detail") && operation != "lsp" && operation != "restart")
            fail("detail is only for LSP status or restart");
        if (operation == "availability") {
            if (arguments.get("name_path") || arguments.get("severity") || arguments.get("max_output_bytes"))
                fail("availability accepts only path and timeout_ms");
            return Json::Object{{"structured_result", file_lsp_availability(arguments, context, cancelled)}};
        }
        if (operation == "auto" || operation == "metadata") {
            if (arguments.get("name_path") || arguments.get("severity")) fail("name_path/severity require diagnostics");
            return file_info(arguments, context);
        }
        if (operation != "lsp" && operation != "diagnostics" && operation != "restart")
            fail("file_info operation must be metadata, lsp, diagnostics, or restart");
        if (arguments.get("max_output_bytes")) fail("LSP information has no output byte cap");
        if (operation != "diagnostics" && (arguments.get("name_path") || arguments.get("severity")))
            fail("name_path/severity require diagnostics");
        const std::string method = operation == "lsp" ? "status" : operation;
        if (!arguments.get("paths")) {
            Json status = lsp_query(method, arguments, context, cancelled);
            return Json::Object{{"text", status.dump() + "\n"}};
        }
        std::string out, warning;
        const auto add_warning = [&](const std::string& message) { out += message; warning += message; };
        for (const auto& path : path_args(arguments)) {
            Json::Object query = arguments.object(); query.erase("paths"); query["path"] = path;
            try { out += lsp_query(method, query, context, cancelled).dump() + "\n"; }
            catch (const IndexWarmingFailure& e) {
                Json details = e.details;
                if (std::holds_alternative<Json::Object>(details.value)) std::get<Json::Object>(details.value)["path"] = path;
                throw IndexWarmingFailure(path + ": " + e.what(), std::move(details));
            }
            catch (const SymbolLookupFailure& e) {
                Json details = e.details;
                if (std::holds_alternative<Json::Object>(details.value)) std::get<Json::Object>(details.value)["path"] = path;
                throw SymbolLookupFailure(path + ": " + e.what(), std::move(details));
            }
            catch (const LspFailure& e) { add_warning(lsp_failure_banner(path + ": " + e.what(), "No fallback exists for this request")); }
            catch (const std::exception& e) { add_warning("[error " + path + ": " + e.what() + "]\n"); }
        }
        return Json::Object{{"text", std::move(out)}, {"warning", std::move(warning)}};
    }
    // on_new_errors=rollback: compare error diagnostics before and after a single-file write, and restore the previous
    // contents when the write adds errors. Line numbers shift, so errors match by source, code and message.
    const std::string on_new_errors = arguments.get("on_new_errors") ? string_arg(arguments, "on_new_errors") : "warn";
    if (on_new_errors != "warn" && on_new_errors != "rollback") fail("on_new_errors must be warn or rollback");
    const bool rollback = on_new_errors == "rollback" && !dry_run;
    if (on_new_errors == "rollback") {
        if (!want_diagnostics) fail("on_new_errors=rollback requires diagnostics=true");
        if (operation == "rename" || operation == "replace_in_files")
            fail("on_new_errors=rollback supports single-file edits; rename and replace_in_files only report diagnostics");
    }
    struct ErrorBaseline {
        bool applies = false, ready = false, existed = false;
        SourceText before;
        std::map<std::string, size_t> errors;
        std::string problem;
    } baseline;
    if (rollback) {
        const std::string path = string_arg(arguments, "path");
        const SourceText descriptor = source_descriptor(context, path, nullptr, true, &baseline.existed);
        baseline.applies = lsp_required(descriptor.path);
        if (baseline.applies) {
            try {
                if (baseline.existed) {
                    baseline.before = read_source_text(context, path);
                    // Rollback compares before and after, so both reads may wait for a slow server (Roslyn on a real
                    // solution needs more than the 3 seconds ordinary post-edit diagnostics allow).
                    const Json report = lsp_query("diagnostics", Json::Object{{"path", path}, {"severity", 1},
                        {"timeout_ms", int64_t{60000}}}, context, cancelled);
                    baseline.errors = error_identities(report);
                }
                baseline.ready = true;
            } catch (const std::exception& e) { baseline.problem = e.what(); }
        }
    }
    std::optional<std::map<std::string, size_t>> errors_after;
    std::vector<std::string> error_lines_after;
    Json result;
    if (name == "edit_file") {
        const bool content = operation == "replace_content" || operation == "replace_in_files" ||
            operation == "insert_at_line" || operation == "replace_lines" || operation == "delete_lines";
        const bool scoped = operation == "replace_in_symbol" || operation == "insert_in_symbol" ||
            operation == "replace_outside_symbols" || operation == "insert_outside_symbols";
        if (arguments.get("indent") && operation != "insert_in_symbol") fail("indent requires operation=insert_in_symbol");
        if (!content && !scoped && operation != "auto" && operation != "symbol" && operation != "text" && operation != "insert_before" &&
            operation != "insert_after" && operation != "rename" && operation != "safe_delete") fail("unknown edit_file operation");
        if (!content && !scoped)
            for (const char* key : {"needle", "repl", "mode", "allow_multiple_occurrences", "paths_include_glob",
                                    "paths_exclude_glob", "occurrence_ids", "expected_count", "start_line", "end_line"})
                if (arguments.get(key)) fail(std::string(key) + " requires a content or line edit operation");
        const bool semantic = !content && operation != "text" && (operation != "auto" || arguments.get("name_path"));
        if (content) result = content_edit(arguments, context, cancelled);
        else if (semantic) {
            if (arguments.get("edits")) fail("semantic edits do not accept text edits");
            if (operation != "rename" && arguments.get("new_name")) fail("new_name requires operation=rename");
            if (operation != "rename" && arguments.get("rename_text_occurrences"))
                fail("rename_text_occurrences requires operation=rename");
            if ((operation == "rename" || operation == "safe_delete") && arguments.get("new_text")) fail("rename/safe_delete do not accept new_text");
            result = lsp_edit(arguments, context, cancelled);
        } else {
            for (const char* key : {"name_path", "new_text", "new_name", "line", "column", "rename_text_occurrences"})
                if (arguments.get(key)) fail(std::string(key) + " is only for semantic edits");
            const std::string notice = require_text_access(source_descriptor(context, string_arg(arguments, "path")),
                                                           arguments, context, cancelled);
            result = edit_file(arguments, context, cancelled);
            auto& text = std::get<Json::Object>(result.value).at("text");
            text = notice + text.string();
            std::get<Json::Object>(result.value)["access_note"] = notice;
        }
    } else if (name == "write_file") result = write_file(arguments, context, cancelled);
    else if (name == "delete_file") result = delete_file(arguments, context, cancelled);
    else if (name == "move_file") {
        try { result = lsp_move(arguments, context, cancelled); }
        catch (const LspFailure& e) {
            // Import planning failed before anything was written; auto moves still happen, without import edits.
            if (operation != "auto") throw;
            Json::Object plain = arguments.object();
            plain["operation"] = "filesystem";
            result = lsp_move(Json(std::move(plain)), context, cancelled);
            auto& text = std::get<Json::Object>(result.value).at("text");
            const std::string warning = lsp_failure_banner(e.what(), "Fallback: the move was done without import updates; check references by hand");
            text = warning + text.string();
            std::get<Json::Object>(result.value)["warning"] = warning;
        }
    }
    else if (name == "create_directory") result = create_directory(arguments, context, cancelled);
    else fail("unknown tool");
    if (name == "edit_file" && arguments.get("max_output_bytes") &&
        (operation == "replace_content" || operation == "replace_in_files" || operation == "insert_at_line" ||
         operation == "replace_lines" || operation == "delete_lines")) {
        Budget budget(max_output_arg(arguments));
        auto& text = std::get<Json::Object>(result.value).at("text");
        text = fit(text.string(), budget, dry_run ? "[preview cut at max_output_bytes; nothing written]\n"
                                                : "[diff cut at max_output_bytes; edits applied in full]\n");
    }
    if (!dry_run) {
        lsp_after_mutation(result, name, arguments, context, cancelled);
        if (want_diagnostics) {
            const auto add_warning = [&](const std::string& message) {
                auto& object = std::get<Json::Object>(result.value);
                object.at("text") = object.at("text").string() + message;
                if (auto it = object.find("warning"); it != object.end()) it->second = it->second.string() + message;
                else object.emplace("warning", message);
            };
            std::vector<std::string> diagnostic_paths;
            const Json* files = result.get("files");
            if (files && std::holds_alternative<Json::Array>(files->value)) {
                for (const auto& file : files->array())
                    if (const Json* path = file.get("path")) diagnostic_paths.push_back(path->string());
            } else if (!result.get("changed") || result.get("changed")->boolean()) {
                diagnostic_paths.push_back(string_arg(arguments, "path"));
            }
            const auto deadline = request_deadline(Clock::now() + std::chrono::seconds(rollback ? 60 : 3));
            Json::Array reports;
            for (const auto& path : diagnostic_paths) {
                try {
                    if (!lsp_required(source_descriptor(context, path).path)) continue;
                    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
                    if (remaining < 1) fail("diagnostics time budget exhausted");
                    Json::Object query{{"path", path}, {"severity", 1}, {"timeout_ms", static_cast<int64_t>(remaining)}};
                    Json report = lsp_query("diagnostics", query, context, cancelled);
                    if (rollback && !errors_after) {
                        errors_after = error_identities(report);
                        for (const auto& item : report.get("items")->array()) {
                            const Json* range = item.get("range");
                            const Json* start = range ? range->get("start_line") : nullptr;
                            const Json* message = item.get("message");
                            error_lines_after.push_back(
                                (start && std::holds_alternative<int64_t>(start->value) ? "L" + std::to_string(start->integer()) + ": " : std::string()) +
                                (message && std::holds_alternative<std::string>(message->value) ? message->string() : std::string("error")));
                        }
                    }
                    auto& report_object = std::get<Json::Object>(report.value);
                    auto& items = std::get<Json::Array>(report_object.at("items").value);
                    if (items.size() > 20) {
                        report_object["omitted_errors"] = static_cast<uint64_t>(items.size() - 20);
                        items.resize(20);
                    }
                    if (!items.empty())
                        add_warning("[warning: write applied; error diagnostics reported for " + path + "]\n");
                    // Text keeps only what an agent acts on: the error count and the error items. Project-loading
                    // and coverage details stay in the structured diagnostics field.
                    auto& text = std::get<Json::Object>(result.value).at("text");
                    std::string line = "[post-edit diagnostics " + path + ": " + std::to_string(items.size()) + " error" +
                                       (items.size() == 1 ? "" : "s");
                    if (const Json* omitted = report_object.contains("omitted_errors") ? &report_object.at("omitted_errors") : nullptr)
                        line += " (+" + std::to_string(omitted->integer()) + " more)";
                    if (const Json* partial = report.get("partial"); partial && partial->boolean()) line += ", partial";
                    line += "]";
                    if (!items.empty()) line += " " + Json(items).dump();
                    text = text.string() + line + "\n";
                    reports.push_back(std::move(report));
                } catch (const IndexWarmingFailure& e) {
                    add_warning("[warning: write applied; diagnostics unavailable for " + path + ": " + e.what() + "]\n");
                    auto& object = std::get<Json::Object>(result.value);
                    object["warning_code"] = "index_warming";
                    object["warning_details"] = e.details;
                } catch (const std::exception& e) {
                    add_warning("[warning: write applied; diagnostics unavailable for " + path + ": " + e.what() + "]\n");
                }
            }
            if (!reports.empty()) std::get<Json::Object>(result.value)["diagnostics"] = std::move(reports);
        }
        const bool changed = !result.get("changed") || result.get("changed")->boolean();
        if (rollback && baseline.applies && changed) {
            if (!baseline.ready) {
                add_rollback_warning(result, "[warning: on_new_errors=rollback could not read diagnostics before the write: " +
                                     baseline.problem + "; the write was kept]\n");
            } else if (!errors_after) {
                add_rollback_warning(result, "[warning: on_new_errors=rollback could not read diagnostics after the write; the write was kept]\n");
            } else {
                size_t added = 0;
                for (const auto& [identity, count] : *errors_after) {
                    const auto before = baseline.errors.find(identity);
                    const size_t old_count = before == baseline.errors.end() ? 0 : before->second;
                    if (count > old_count) added += count - old_count;
                }
                if (added) {
                    const std::string path = string_arg(arguments, "path");
                    std::string restore_problem;
                    try {
                        if (baseline.existed) {
                            // The text is restored in the file's current encoding.
                            const SourceText now = read_source_text(context, path);
                            Json restored = apply_source_changes({SourceChange{now, baseline.before.text}},
                                Json::Object{{"path", path}, {"timeout_ms", int64_t{30000}}}, context, cancelled);
                            lsp_after_mutation(restored, "edit_file", Json::Object{{"path", path}}, context, cancelled);
                        } else {
                            Json removed = delete_file(Json::Object{{"path", path}}, context, cancelled);
                            lsp_after_mutation(removed, "delete_file", Json::Object{{"path", path}}, context, cancelled);
                        }
                    } catch (const std::exception& e) { restore_problem = e.what(); }
                    std::string listed;
                    for (size_t i = 0; i < std::min<size_t>(5, error_lines_after.size()); ++i) listed += "\n  " + error_lines_after[i];
                    if (error_lines_after.size() > 5) listed += "\n  ...";
                    fail("write rejected: it added " + std::to_string(added) + " new error diagnostic" + (added == 1 ? "" : "s") +
                         " to " + path + (restore_problem.empty()
                             ? (baseline.existed ? "; the previous contents were restored" : "; the new file was removed")
                             : "; restoring failed (" + restore_problem + "), so the write remains applied") +
                         ". Current errors:" + listed);
                }
            }
        }
    }
    return result;
}

// CONTRACT: these descriptions are the model's only documentation of the tools; every statement must match the
// implementation. Update them with any behavior change.
Json file_tool_definitions(bool read_only) {
    // PERF: sent to the model with every session; keep only what an agent needs to call correctly.
    auto schema = [](Json::Object properties, Json::Array required = {}) -> Json {
        Json::Object out{{"type", "object"}, {"properties", std::move(properties)}, {"additionalProperties", false}};
        if (!required.empty()) out.emplace("required", std::move(required));
        return out;
    };
    auto field = [](const char* type, const char* description) -> Json {
        return Json::Object{{"type", type}, {"description", description}};
    };
    auto choice = [](Json::Array values, const char* description) -> Json {
        return Json::Object{{"type", "string"}, {"enum", std::move(values)}, {"description", description}};
    };
    const char* path_text = "Relative to the first root, or absolute inside a root.";
    const Json path = field("string", path_text);
    const Json paths = Json::Object{{"type", "array"}, {"items", Json::Object{{"type", "string"}}},
        {"description", "Up to 32 paths instead of path."}};
    const Json max_output = field("integer", "Optional byte cap, 512-1048576. Default unlimited.");
    const Json expected_sha256 = field("string", "Expected SHA-256 from read_file or file_info. Without it, existing files must match this session's latest file/symbol read or dry-run preview; multi-file edits require a snapshot for each file. Direct tools share history with the default REPL; named sessions have separate history. Use the same path spelling for reads and edits. Text search does not establish a snapshot.");
    const Json expected_mtime = field("string", "Fail if the file's mtime (from read_file) changed.");
    const Json text_fallback = field("boolean", "Semantic fallback and unrestricted text writes only: require unavailable/failing LSP. Read-only text access needs no fallback permission.");
    const std::string common_paths = " Links are never followed.";

    Json::Array tools;
    tools.push_back(Json::Object{{"name", "read_file"}, {"description",
        "Read non-code files as text with operation=text, or use LSP overviews and symbol bodies. A text read of a code file returns its LSP outline. "
        "Symbol offset/limit selects lines relative to its definition; format=outline shows kind, name and line range. "
        "Plain text of a code file requires allow_text_fallback=true and a failing or missing language server. "
        "No output byte cap. Every header ends with its source: lsp (a language server) or text (plain file text). Text headers include encoding, mtime and sha256; multi-file reads with a common parent show that folder once. Binary and ordinary files >256 MiB refused (UTF-16 >64 MiB); saved UTF-8 outputs under .shgrep-output can be paged without that size cap." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path}, {"paths", paths},
            {"allow_text_fallback", field("boolean", "Permit a plain text read of a code file, honoring offset/limit, only when its language server fails or is missing. Unavailable for directories or symbol reads with offset/limit. Non-code text reads need no permission. Default false.")},
            {"outline_first", field("boolean", "Accepted for compatibility; code files always return their LSP outline instead of text.")},
            {"offset", field("integer", "First line, from 1. Non-code text files and symbol bodies only.")},
            {"limit", field("integer", "Line limit per non-code text file or selected symbol; ignored for a code file, which returns its outline. Text reads default to 100 lines; symbol reads default to all remaining lines.")},
            {"operation", choice(Json::Array{"auto", "overview", "symbol", "text"}, "Default auto: LSP for programming/XML; text for other formats. No automatic fallback.")},
            {"name_path", field("string", "Read this symbol; offset/limit selects a body slice. Type/method accepts Rust impl wrappers; append #kind (e.g. ClassName#ctor). A plain generic type name resolves when unique; multiple generic matches return candidates. Other ambiguities return candidates; overloads take an index such as Name[0]. No parent is selected.")},
            {"full_lines", field("boolean", "Symbol reads: include complete touched source lines and return body_range; inline lines may contain neighboring code. Default false.")},
            {"include_kinds", Json::Object{{"type", "array"}, {"items", Json::Object{{"type", "integer"}}}, {"description", "LSP kinds 1-26 to include."}}},
            {"exclude_kinds", Json::Object{{"type", "array"}, {"items", Json::Object{{"type", "integer"}}}, {"description", "LSP kinds to exclude."}}},
            {"depth", field("integer", "Overview child depth; default -1 (all).")},
            {"format", choice(Json::Array{"json", "compact", "outline"}, "Overview defaults to json with numeric kind and kind_name; compact/outline shows named kinds and line ranges.")},
            {"timeout_ms", field("integer", "LSP deadline, 1-300000; default 180000 for semantic operations and 30000 for text/filesystem operations.")},
            {"line_numbers", field("boolean", "Text and symbol text presentation: include line prefixes; default false. Structured symbol bodies are unchanged.")}})}});
    tools.push_back(Json::Object{{"name", "list_dir"}, {"description",
        "List files and folders: \"d sub/\", \"f name SIZE\", \"l link\"." + common_paths},
        {"inputSchema", schema(Json::Object{
            {"path", field("string", "Folder; default the first root.")},
            {"operation", choice(Json::Array{"filesystem", "overview"}, "Default filesystem; overview returns live LSP symbols by file.")},
            {"depth", field("integer", "Filesystem: 1-32, default 1. Overview: child depth, default -1 (all).")},
            {"format", choice(Json::Array{"json", "compact", "outline"}, "Overview defaults to json with numeric kind and kind_name; compact/outline shows named kinds and line ranges.")},
            {"hidden", field("boolean", "Include hidden entries.")},
            {"no_ignore", field("boolean", "Include .gitignore/.ignore/.shignore'd entries.")},
            {"max_results", field("integer", "Optional entry limit, 1-10000; default unlimited.")},
            {"timeout_ms", field("integer", "Filesystem deadline default 30000; operation=overview uses the LSP default of 180000.")},
            {"max_output_bytes", max_output}})}});
    tools.push_back(Json::Object{{"name", "file_info"}, {"description",
        "Disk metadata; availability probes the current per-file text-fallback decision without editing; lsp reports server readiness, diagnostics includes coverage metadata, and restart recovers an LSP server." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path}, {"paths", paths},
            {"operation", choice(Json::Array{"metadata", "availability", "lsp", "diagnostics", "restart"}, "Default metadata. availability requires one file path and returns state, fallback_eligible, requires_text_fallback and reason from a live probe; lsp/restart may omit path to address all servers.")},
            {"detail", choice(Json::Array{"summary", "full"}, "lsp/restart: default summary; full includes capabilities and configuration details.")},
            {"name_path", field("string", "diagnostics: restrict to a symbol; append #kind (e.g. ClassName#ctor). A plain generic type name resolves when unique; multiple generic matches return candidates. Other ambiguities return candidates; overloads take an index such as Name[0]. No parent is selected.")},
            {"severity", field("integer", "diagnostics: highest numeric severity to include, 1-4; default 4.")},
            {"start_line", field("integer", "diagnostics: first 1-based line, inclusive; default 1. Includes diagnostics overlapping the requested lines.")},
            {"end_line", field("integer", "diagnostics: last 1-based line, inclusive; -1 or omitted means no upper bound.")},
            {"group_by_symbol", field("boolean", "diagnostics: add grouped results by file, severity and enclosing symbol (<file> if none); flat items remain. Default false.")},
            {"timeout_ms", field("integer", "LSP deadline, 1-300000; default 180000 for semantic operations and 30000 for text/filesystem operations.")},
            {"max_output_bytes", max_output}})}});
    if (read_only) return tools;

    const Json edit_item = Json::Object{{"type", "object"}, {"additionalProperties", false},
        {"required", Json::Array{"old_text", "new_text"}},
        {"properties", Json::Object{
            {"old_text", field("string", "Exact text; must match once unless replace_all.")},
            {"new_text", field("string", "Replacement.")},
            {"replace_all", field("boolean", "Replace every match.")}}}};
    tools.push_back(Json::Object{{"name", "edit_file"}, {"description",
        "Live LSP symbol replace, replace_in_symbol/insert_in_symbol, replace_outside_symbols/insert_outside_symbols, insert_before/insert_after, rename across files (listing same-name mentions it leaves, e.g. other languages), or safe_delete with reference and method/property contract checks. Deletion is blocked when checks find relationships or cannot be completed; dry_run shows blockers and the proposed diff. "
        "Text replacements and line edits are for other formats; programming/XML require symbol or outside-symbol edits unless allow_text_fallback=true and LSP fails. Bulk text edits skip files requiring working LSP. "
        "Snapshot guards, encoding preservation, dry-run diffs and rollback on commit failure; atomic per file." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path},
            {"allow_text_fallback", text_fallback},
            {"edits", Json::Object{{"type", "array"}, {"items", edit_item}, {"description", "1-256 edits."}}},
            {"operation", choice(Json::Array{"auto", "symbol", "replace_in_symbol", "insert_in_symbol", "replace_outside_symbols", "insert_outside_symbols", "insert_before", "insert_after", "rename", "safe_delete", "text", "replace_content", "replace_in_files", "insert_at_line", "replace_lines", "delete_lines"}, "Default auto: name_path selects symbol replacement; edits selects text. insert_before/after target complete field or property declarations; names in one declaration stay together.")},
            {"name_path", field("string", "Symbol path; overload [i] supported; append #kind (e.g. ClassName#ctor). A plain generic type name resolves when unique; multiple generic matches return candidates. Other ambiguities return candidates; overloads take an index such as Name[0]. No parent is selected.")},
            {"new_name", field("string", "rename: new identifier; language server computes all affected files.")},
            {"rename_text_occurrences", field("boolean", "rename: also rewrite whole-word mentions of the old name inside comments and string literals of the files the rename already edits (C-family, C#, Java, Go, Rust, JS/TS, Python, shell, PowerShell, Lua, YAML/TOML). Interpolated expressions stay code. Other files are only listed as leftovers. Default false.")},
            {"line", field("integer", "rename: 1-based line instead of name_path; insert_at_line: insertion line (EOF allowed); insert_in_symbol: absolute source line inside the selected symbol; insert_outside_symbols: absolute source line outside protected symbols.")},
            {"start_line", field("integer", "replace_lines/delete_lines: first 1-based line, inclusive.")},
            {"end_line", field("integer", "replace_lines/delete_lines: last 1-based line, inclusive.")},
            {"needle", field("string", "replace_content/replace_in_files/replace_in_symbol/replace_outside_symbols: nonempty literal or PCRE2 regex; DOTALL and MULTILINE enabled.")},
            {"repl", field("string", "Replacement template; regex capture references use $!1, $!2, etc.; literal mode is verbatim.")},
            {"mode", choice(Json::Array{"literal", "regex"}, "Content replacement syntax; default literal. Regex uses PCRE2, not Python re.")},
            {"allow_multiple_occurrences", field("boolean", "replace_content/replace_in_symbol/replace_outside_symbols: default false; reject nonunique matches.")},
            {"indent", choice(Json::Array{"verbatim", "match"}, "insert_in_symbol only. Default verbatim keeps supplied indentation. match prefixes the target line whitespace to each nonblank line, preserving supplied relative indentation.")},
            {"paths_include_glob", field("string", "replace_in_files: root-relative glob with *, ** and ?; default all nonignored visible files.")},
            {"paths_exclude_glob", field("string", "replace_in_files: exclude root-relative files/directories before reading; takes precedence.")},
            {"occurrence_ids", Json::Object{{"type", "array"}, {"items", field("string", "Current preview occurrence ID.")}, {"description", "replace_in_files: select preview IDs; unknown/stale IDs abort all changes."}}},
            {"expected_count", field("integer", "replace_in_files: abort if match count differs; -1 disables (default). Mutually exclusive with occurrence_ids.")},
            {"column", field("integer", "rename: 1-based UTF-16 column with line.")},
            {"diagnostics", field("boolean", "After writing source files, request up to 20 error diagnostics per file within a shared 3-second budget. Errors and unavailable checks produce warnings; writes remain applied unless on_new_errors=rollback. External compiler checks may be unverified. Default true; set false to skip.")},
            {"on_new_errors", choice(Json::Array{"warn", "rollback"}, "Default warn keeps the write and reports errors. rollback (single-file edits; not rename or replace_in_files) also reads error diagnostics before and after the write, waiting up to 60 seconds each, and restores the previous text, then fails, when the write adds errors matched by source, code and message. Unavailable diagnostics keep the write with a warning.")},
            {"new_text", field("string", "Complete symbol replacement or inserted code. insert_before/after use complete field or property declarations, including inline members; unresolvable boundaries such as complex interpolation or JSX fail. LF/CRLF is converted to file endings; symbol insertion preserves supplied code indentation.")},
            {"timeout_ms", field("integer", "Semantic LSP edits default 180000; text and line edits default 30000, within the 1-300000 ms range.")},
            {"dry_run", field("boolean", "Diff only, write nothing.")},
            {"expected_sha256", expected_sha256}, {"expected_mtime", expected_mtime},
            {"max_output_bytes", field("integer", "Optional diff byte cap; no cap by default.")}}, Json::Array{"path"})}});
    tools.push_back(Json::Object{{"name", "write_file"}, {"description",
        "Create files atomically; creates parent folders. To replace an existing programming/XML file, use overwrite=true with expected_sha256, symbol edits, or explicit fallback after LSP failure." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path},
            {"allow_text_fallback", text_fallback},
            {"content", field("string", "Full contents.")},
            {"diagnostics", field("boolean", "After writing source files, request error diagnostics within a shared 3-second budget. Errors or unavailable checks produce warnings; writes remain applied unless on_new_errors=rollback. Default true; set false to skip.")},
            {"on_new_errors", choice(Json::Array{"warn", "rollback"}, "Default warn keeps the write and reports errors. rollback also reads error diagnostics before the write; when the write adds errors it restores the previous text (or removes a new file) and fails. Unavailable diagnostics keep the write with a warning.")},
            {"timeout_ms", field("integer", "Diagnostic deadline, 1-300000; default 180000 when diagnostics=true.")},
            {"overwrite", field("boolean", "Replace an existing file.")},
            {"line_endings", choice(Json::Array{"lf", "crlf", "cr"}, "Default: the replaced file's, or for new files EditorConfig, Git attributes, then sibling files; otherwise as given. Alias: eol.")},
            {"eol", choice(Json::Array{"lf", "crlf", "cr"}, "Alias for line_endings; both must agree if provided.")},
            {"encoding", choice(Json::Array{"utf-8", "utf-8-bom", "utf-16le", "utf-16be"},
                                "Default: the replaced file's; for new files, matching EditorConfig charset, then a unique majority among same-extension siblings, then utf-8. Unsupported configured charsets require an explicit encoding.")},
            {"expected_sha256", expected_sha256}, {"expected_mtime", expected_mtime}},
            Json::Array{"path", "content"})}});
    tools.push_back(Json::Object{{"name", "delete_file"}, {"description",
        "Delete one file within configured roots. No links or directories; requires a matching session read, dry-run preview, or explicit SHA-256 guard. "
        "Source-file deletion does not check references or rewrite imports. Active language servers refresh after deletion." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path}, {"expected_sha256", expected_sha256},
            {"dry_run", field("boolean", "Preview and verify the target without deleting it.")},
            {"timeout_ms", field("integer", "Whole-request deadline, 1-300000 ms; default 30000.")}},
            Json::Array{"path"})}});
    tools.push_back(Json::Object{{"name", "move_file"}, {"description",
        "Move a file/folder; auto asks configured LSP servers for import edits when supported. Refactor requires that support; filesystem moves paths. File sources and overwritten destinations require a matching session read, preview, or explicit hash. Directory moves preserve content and invalidate path history. Active servers refresh after success." + common_paths},
        {"inputSchema", schema(Json::Object{{"source", field("string", path_text)},
            {"destination", field("string", path_text)},
            {"operation", choice(Json::Array{"auto", "refactor", "filesystem"}, "Default auto. refactor requires willRenameFiles; filesystem bypasses semantic import edits.")},
            {"dry_run", field("boolean", "Preview import edits and move without writing.")},
            {"timeout_ms", field("integer", "LSP deadline, 1-300000; default 180000 for semantic operations and 30000 for text/filesystem operations.")},
            {"expected_sha256", field("string", "Expected source-file SHA-256; otherwise require this session's read or move preview.")},
            {"expected_mtime", expected_mtime},
            {"expected_destination_sha256", field("string", "Expected overwritten file SHA-256; otherwise require this session's destination read or move preview. Requires overwrite=true.")},
            {"overwrite", field("boolean", "Replace an existing file; requires operation=filesystem.")}},
            Json::Array{"source", "destination"})}});
    tools.push_back(Json::Object{{"name", "create_directory"}, {"description",
        "Create a folder and its parents (mkdir -p)." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path}}, Json::Array{"path"})}});
    return tools;
}
}
