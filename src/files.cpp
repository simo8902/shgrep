#include "files.hpp"
#include "lsp.hpp"
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
    if (cancelled && cancelled->load()) fail("request cancelled; nothing was written");
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
    return header + " | mtime " + format_mtime(basic.LastWriteTime.QuadPart) + " | sha256 " + sha256 + "]\n";
}
std::string file_header(const std::string& path, const std::string& raw, const TextFile& text,
                        const FILE_BASIC_INFO& basic) {
    return file_header(path, raw.size(), sha256_hex(raw), text, basic);
}

// ---- read_file ----

struct ReadOptions {
    uint64_t offset = 1, limit = UINT64_MAX;
    bool numbers = true;
};

constexpr uint64_t max_streamed_text_bytes = 256ull << 20;

// PERF: a UTF-8 file over max_text_bytes is read once in 1 MiB pieces. The header's counts and sha256 are computed
//   on the way and only the requested window of lines is kept, so memory stays flat whatever the offset.
// CONTRACT: the output equals render_file's for the same bytes; UTF-16 files this large are refused.
void render_large_file(std::string& out, const std::string& path, HANDLE file, const FILE_BASIC_INFO& basic,
                       const ReadOptions& options) {
    Sha256 hash;
    TextFile counts;  // everything but text
    uint64_t bytes = 0, decoded_size = 0, number = 1, shown = 0, line_bytes = 0;
    std::string window, line, carry;
    bool first = true, pending_cr = false, more = false;
    char last = 0;
    auto emit_line = [&](bool had_newline) {
        if (had_newline && !line.empty() && line.back() == '\r') line.pop_back();
        if (options.numbers) {
            char prefix[32];
            std::snprintf(prefix, sizeof(prefix), "%6llu", static_cast<unsigned long long>(number));
            window += prefix;
            window += "\xE2\x86\x92";
        }
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
        DWORD got = 0;
        if (!ReadFile(file, piece.data(), static_cast<DWORD>(piece.size()), &got, nullptr)) {
            const DWORD code = GetLastError();
            fail(path + ": read failed (" + win32_text(code) + ")");
        }
        const bool end = got == 0;
        std::string_view raw(piece.data(), got);
        hash.add(raw);
        bytes += got;
        if (bytes > max_streamed_text_bytes) fail(path + " is larger than 256 MiB; use search");
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
    out += file_header(path, bytes, hash.hex(), counts, basic);
    if (options.offset > counts.lines && !(counts.lines == 0 && options.offset == 1)) {
        out += "[offset " + std::to_string(options.offset) + " is past the end: the file has " + std::to_string(counts.lines) + " lines]\n";
        return;
    }
    out += window;
    if (more)
        out += "[status limit: showed lines " + std::to_string(options.offset) + "-" + std::to_string(options.offset + shown - 1) +
               " of " + std::to_string(counts.lines) + " (limit=" + std::to_string(options.limit) +
               "); continue with offset=" + std::to_string(options.offset + shown) + "]\n";
}

void render_file(std::string& out, const Target& target, const ReadOptions& options) {
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
            if (static_cast<uint64_t>(size.QuadPart) > max_streamed_text_bytes) fail(path + " is larger than 256 MiB; use search");
            render_large_file(out, path, file.h, basic, options);
            return;
        }
        if (!read_all(file.h, path, max_text_bytes, raw)) fail(path + " is larger than 64 MiB; use search");
    }
    const TextFile text = decode(raw);
    if (text.binary) fail(path + " is binary; use search_bytes");
    out += file_header(path, raw, text, basic);
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
        if (options.numbers) {
            char prefix[32];
            std::snprintf(prefix, sizeof(prefix), "%6llu", static_cast<unsigned long long>(number));
            out += prefix; out += "\xE2\x86\x92";
        }
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

// "compact" (default) or "json": how a symbol overview is shown.
std::string outline_format(const Json& args) {
    const std::string format = args.get("format") ? string_arg(args, "format") : "compact";
    if (format != "compact" && format != "json") fail("format must be compact or json");
    return format;
}

// PERF: an overview as one line per symbol, "LINE kind name_path", about a fifth of the json with its ranges. The
//   name_path is exactly what read_file name_path, search and edit_file take next.
std::string compact_outline(const Json& result) {
    static constexpr const char* kinds[] = {"?", "file", "module", "namespace", "package", "class", "method", "property",
        "field", "ctor", "enum", "interface", "fn", "var", "const", "string", "number", "bool", "array", "object", "key",
        "null", "member", "struct", "event", "operator", "typeparam"};
    const Json* items = result.get("results");
    const size_t count = items ? items->array().size() : 0;
    std::string out;
    const Json* file = result.get("path");
    if (file) {
        out = "[outline " + file->string() + " | " + std::to_string(count) + " symbols";
        if (const Json* mtime = result.get("mtime")) out += " | mtime " + mtime->string();
        if (const Json* sha = result.get("sha256")) out += " | sha256 " + sha->string();
        out += "]\n";
    } else {
        std::set<std::string> files;
        if (items) for (const auto& item : items->array()) if (const Json* p = item.get("path")) files.insert(p->string());
        out = "[outline | " + std::to_string(count) + " symbols in " + std::to_string(files.size()) + " files]\n";
    }
    std::string current;
    if (items) for (const auto& item : items->array()) {
        const Json* path = item.get("path");
        if (!file && path && path->string() != current) {
            current = path->string();
            out += current + "\n";
        }
        const Json* kind = item.get("kind");
        const int64_t k = kind && std::holds_alternative<int64_t>(kind->value) ? kind->integer() : 0;
        char line[16];
        std::snprintf(line, sizeof(line), "%6lld ", static_cast<long long>(item.get("line") ? item.get("line")->integer() : 0));
        std::string name = kinds[k >= 1 && k <= 26 ? k : 0];
        name.resize(std::max<size_t>(name.size(), 9), ' ');
        out += (file ? "" : "  ") + std::string(line) + name + " " + (item.get("name_path") ? item.get("name_path")->string() : "") + "\n";
    }
    if (!count) out += "(no symbols)\n";
    return out;
}

Json read_file(const Json& args, const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled) {
    const std::vector<std::string> paths = path_args(args);
    ReadOptions options;
    options.offset = static_cast<uint64_t>(int_arg(args, "offset", 1, 1, INT64_MAX));
    options.limit = args.get("limit") ? static_cast<uint64_t>(int_arg(args, "limit", 1, 1, INT64_MAX)) : UINT64_MAX;
    options.numbers = bool_arg(args, "line_numbers", true);
    const std::string operation = args.get("operation") ? string_arg(args, "operation") : "auto";
    if (operation != "auto" && operation != "text" && operation != "overview" && operation != "symbol")
        fail("read_file operation must be auto, text, overview, or symbol");
    if (operation == "text" && args.get("name_path")) fail("operation=text does not accept name_path");
    const bool json_format = outline_format(args) == "json";
    if (args.get("format") && (operation == "text" || args.get("offset") || args.get("limit") || args.get("name_path")))
        fail("format is only for symbol overviews");
    const bool text_mode = operation == "text" || args.get("offset") || args.get("limit");
    if (text_mode && (args.get("depth") || args.get("include_kinds") || args.get("exclude_kinds")))
        fail("depth/include_kinds/exclude_kinds require a symbol read");
    if ((args.get("offset") || args.get("limit")) && (operation == "overview" || operation == "symbol" || args.get("name_path")))
        fail("line ranges and symbol reads are mutually exclusive");
    std::string out;
    for (const auto& path : paths) {
        if (cancelled && cancelled->load()) fail("read_file cancelled");
        auto read = [&] {
            const bool text_range = operation == "text" || args.get("offset") || args.get("limit");
            // CONTRACT: when the language server fails on a file, the read falls back to the file's text under the
            //   failure banner; a folder outline has no text fallback and fails with the banner.
            std::string failure;
            if (!text_range) {
                bool directory = false;
                const SourceText descriptor = source_descriptor(context, path, &directory);
                bool semantic = directory || operation != "auto" || args.get("name_path");
                if (!semantic) {
                    try { semantic = lsp_configured(descriptor, context); }
                    catch (const LspFailure& e) { failure = e.what(); }
                }
                if (semantic) {
                    if (operation == "symbol" && !args.get("name_path")) fail("symbol read requires name_path");
                    if (args.get("line_numbers")) fail("line_numbers is only for text reads");
                    Json::Object query = args.object();
                    query.erase("paths"); query.erase("format"); query["path"] = path;
                    query["include_body"] = args.get("name_path") != nullptr;
                    try {
                        const Json result = lsp_query(args.get("name_path") ? "symbols" : "overview", query, context, cancelled);
                        out += args.get("name_path") || json_format ? result.dump() + "\n" : compact_outline(result);
                        return;
                    } catch (const LspFailure& e) {
                        if (directory) throw;
                        failure = e.what();
                    }
                }
            }
            if (!failure.empty())
                out += lsp_failure_banner(failure, args.get("name_path")
                    ? "Fallback below: the file's text; locate the symbol with search operation=text"
                    : "Fallback below: the file's text instead of its symbol outline");
            render_file(out, resolve(context, path), options);
        };
        if (!args.get("paths")) read();
        else {
            try { read(); }
            catch (const LspFailure& e) { out += lsp_failure_banner(path + ": " + e.what(), "No fallback exists for a folder outline"); }
            catch (const std::exception& e) { out += "[error " + std::string(e.what()) + "]\n"; }
        }
    }
    return Json::Object{{"text", std::move(out)}};
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
        bool gitignore = false, dotignore = false;
        for (const auto& entry : entries) {
            if (entry.attributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (same_name(entry.name, L".gitignore")) gitignore = true;
            else if (same_name(entry.name, L".ignore")) dotignore = true;
        }
        if (gitignore || dotignore) {
            auto next = std::make_shared<IgnoreScope>();
            next->parent = scope;
            read_ignore_rules(path, ignore_relative, gitignore, dotignore, next->rules);
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
            read_ignore_rules(final_path(directory.h), ignore_relative, true, true, ancestor->rules);
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
                   " ignored by .gitignore/.ignore (no_ignore: false hid them)";
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

FILE_BASIC_INFO atomic_write(HANDLE directory, const Target& target, const std::string& bytes, bool replace,
                             DWORD attributes, Handle* original, const CancelFlag& cancelled = {}) {
    auto staged = stage_write(directory, target, bytes, attributes, original && *original ? original->h : nullptr, cancelled);
    if (original && *original) require_unreplaced(directory, target, original->h);
    // CONTRACT: cancellation wins until the atomic rename; after commit report the applied change.
    check_cancelled(cancelled);
    if (const DWORD code = rename_handle(staged->file.h, directory, target.name(), replace, original))
        fail(target.display() + ": " + rename_error(code) + "; nothing was written");
    staged->armed = false;
    try { return basic_info(staged->file.h, target.display()); }
    catch (const std::exception&) { return FILE_BASIC_INFO{}; }
}

constexpr DWORD kept_attributes = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE |
                                  FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

void check_guards(const Json& args, const std::string& path, const std::string& raw, const FILE_BASIC_INFO& basic) {
    if (args.get("expected_sha256")) {
        std::string expected = string_arg(args, "expected_sha256");
        std::transform(expected.begin(), expected.end(), expected.begin(),
                       [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
        const std::string actual = sha256_hex(raw);
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
    if (bytes == raw) return Json::Object{{"text", "No change: the edits leave " + path + " as it was; nothing was written.\n"}};
    TextFile after;
    after.text = content;
    count_lines(after);
    const Diff diff = unified_diff(text.text, content, target.relative(), cancelled);
    FILE_BASIC_INFO written = basic;
    if (!dry_run) written = atomic_write(directory.h, target, bytes, true, basic.FileAttributes & kept_attributes, &file, cancelled);
    std::string summary = std::string(dry_run ? "Dry run, nothing written. Would edit " : "Edited ") + path + ": " +
                          std::to_string(edits.size()) + (edits.size() == 1 ? " edit, " : " edits, ") +
                          std::to_string(replacements) + (replacements == 1 ? " replacement" : " replacements") +
                          ", +" + std::to_string(diff.added) + " -" + std::to_string(diff.removed) + " lines. ";
    summary += "Now " + std::to_string(after.lines) + " lines, " + encoding_name(text.encoding) + ", " + eol_name(after);
    if (!dry_run) summary += " | mtime " + format_mtime(written.LastWriteTime.QuadPart) + " | sha256 " + sha256_hex(bytes);
    summary += "\n";
    if (!args.get("max_output_bytes")) return Json::Object{{"text", summary + diff.text}};
    budget.take(summary);
    return Json::Object{{"text", summary + fit(diff.text, budget, dry_run
        ? "[diff cut at max_output_bytes]\n" : "[diff cut at max_output_bytes; the edit was applied in full]\n")}};
}

// ---- write_file ----

Json write_file(const Json& args, const SearchContext& context, const CancelFlag& cancelled) {
    const Target target = resolve(context, string_arg(args, "path"));
    if (target.parts.empty()) fail("path names a configured root, not a file");
    const std::string content = string_arg(args, "content");
    const bool overwrite = bool_arg(args, "overwrite", false);
    std::string endings;
    if (args.get("line_endings")) {
        endings = string_arg(args, "line_endings");
        if (endings != "lf" && endings != "crlf") fail("line_endings must be lf or crlf");
    }
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
        const FILE_BASIC_INFO basic = basic_info(existing.h, path);
        if (basic.FileAttributes & FILE_ATTRIBUTE_READONLY) fail(path + " is read-only; nothing was written");
        attributes = basic.FileAttributes & kept_attributes;
        std::string raw;
        const bool whole = read_all(existing.h, path, max_text_bytes, raw, cancelled);
        if (whole) check_guards(args, path, raw, basic);
        else if (args.get("expected_sha256") || args.get("expected_mtime"))
            fail(path + " is larger than 64 MiB, so expected_sha256/expected_mtime cannot be checked; nothing was written");
        if (whole) {
            const TextFile old = decode(raw);
            old_lines = old.lines;
            // CONTRACT: when replacing, encoding and line endings default to the existing file's.
            if (!old.binary) {
                if (!encoding_given) encoding = old.encoding;
                if (endings.empty()) {
                    const Eol style = eol_style(old);
                    if (style == Eol::crlf || (style == Eol::mixed && old.crlf >= old.lf)) endings = "crlf";
                    else if (style == Eol::lf || style == Eol::mixed) endings = "lf";
                }
            }
        }
    } else if (args.get("expected_sha256") || args.get("expected_mtime")) {
        fail(path + " does not exist, so expected_sha256/expected_mtime cannot match; nothing was written");
    }
    const std::string text = endings.empty() ? content : replace_newlines(content, endings == "crlf" ? "\r\n" : "\n");
    const std::string bytes = encode(text, encoding);
    const FILE_BASIC_INFO written = atomic_write(directory.h, target, bytes, exists, attributes,
                                                 exists ? &existing : nullptr, cancelled);
    TextFile result;
    result.text = text;
    count_lines(result);
    std::string out = std::string(exists ? "Replaced " : "Created ") + path + " (" + std::to_string(result.lines) +
                      " lines, " + std::to_string(bytes.size()) + " bytes, " + encoding_name(encoding) + ", " +
                      eol_name(result) + (exists ? "; it had " + std::to_string(old_lines) + " lines" : "") + ")";
    out += " | mtime " + format_mtime(written.LastWriteTime.QuadPart) + " | sha256 " + sha256_hex(bytes) + "\n";
    if (!created.empty()) {
        out += "Created folders:";
        for (const auto& folder : created) out += " " + folder;
        out += "\n";
    }
    return Json::Object{{"text", std::move(out)}};
}

// ---- move_file, create_directory ----

bool same_parts(const std::vector<std::wstring>& a, const std::vector<std::wstring>& b, size_t count) {
    for (size_t i = 0; i < count; ++i)
        if (CompareStringOrdinal(a[i].data(), static_cast<int>(a[i].size()), b[i].data(),
                                 static_cast<int>(b[i].size()), TRUE) != CSTR_EQUAL) return false;
    return true;
}

Json move_file_unlocked(const Json& args, const SearchContext& context) {
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
    Handle source_directory = open_parent(source, false);
    Handle item;
    const NTSTATUS status = nt_open(source_directory.h, source.name(), DELETE | FILE_READ_ATTRIBUTES, share_all,
                                    disposition_open, option_open_reparse_point, 0, item);
    if (status < 0) fail(source.display() + ": " + status_text(status));
    refuse_link(item.h, source.display());
    const bool is_directory = (attributes_of(item.h, source.display()) & FILE_ATTRIBUTE_DIRECTORY) != 0;
    std::vector<std::string> created;
    Handle destination_directory = open_parent(destination, true, &created);
    if (const DWORD code = rename_handle(item.h, destination_directory.h, destination.name(), overwrite, nullptr))
        fail("cannot move " + source.display() + " to " + destination.display() + ": " + rename_error(code));
    std::string out = std::string("Moved ") + (is_directory ? "directory " : "") + source.display() + " -> " +
                      destination.display() + "\n";
    if (!created.empty()) {
        out += "Created folders:";
        for (const auto& folder : created) out += " " + folder;
        out += "\n";
    }
    return Json::Object{{"text", std::move(out)}};
}

Json move_file(const Json& args, const SearchContext& context) {
    std::lock_guard lock(write_mutex());
    return move_file_unlocked(args, context);
}

Json create_directory(const Json& args, const SearchContext& context) {
    const Target target = resolve(context, string_arg(args, "path"));
    if (target.parts.empty()) fail("path names a configured root, which already exists");
    const std::string path = target.display();
    std::lock_guard lock(write_mutex());
    std::vector<std::string> created;
    Handle parent = open_parent(target, true, &created);
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
    std::set<std::wstring> seen;
    std::string out;
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
        if (!primary.empty() && same_name(primary, p->target.full(p->target.parts.size()).c_str()))
            check_guards(arguments, p->target.display(), p->old_bytes, p->basic);
        const TextFile text = decode(p->old_bytes);
        if (text.binary || text.invalid || text.text != change.before.text) fail("workspace edit snapshot mismatch");
        if (!dry && (p->basic.FileAttributes & FILE_ATTRIBUTE_READONLY)) fail(p->target.display() + " is read-only; nothing was written");
        p->new_bytes = encode(change.after, text.encoding);
        if (p->new_bytes.size() > max_text_bytes) fail("workspace edit result exceeds 64 MiB");
        if (p->new_bytes == p->old_bytes) continue;
        out += unified_diff(text.text, change.after, p->target.relative()).text;
        pending.push_back(std::move(p));
    }
    if (dry) return Json::Object{{"text", "Dry run, nothing written. " + std::to_string(pending.size()) + " files would change.\n" +
        (move_arguments ? "Would move " + string_arg(*move_arguments, "source") + " -> " + string_arg(*move_arguments, "destination") + "\n" : "") + out}};
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
            require_unreplaced(p->parent.h, p->target, p->original.h);
            if (const DWORD code = rename_handle(p->replacement->file.h, p->parent.h, p->target.name(), true, &p->original))
                fail(p->target.display() + ": " + rename_error(code));
            p->replacement->armed = false;
            p->replacement->file.close();
            p->committed = true;
            p->original.close();
            p->original = open_file(p->parent.h, p->target, FILE_SHARE_READ | FILE_SHARE_DELETE);
            std::string actual;
            if (!read_all(p->original.h, p->target.display(), max_text_bytes, actual) || actual != p->new_bytes)
                fail(p->target.display() + ": replacement read-back differs");
        }
        // The move is last: its failure restores all preceding import/reference edits.
        if (move_arguments) {
            for (auto& p : pending) p->original.close();
            out += move_file_unlocked(*move_arguments, context).get("text")->string();
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
                if (const DWORD code = rename_handle(p->recovery->file.h, p->parent.h, p->target.name(), true, &p->original))
                    fail(rename_error(code));
                p->recovery->armed = false;
            } catch (const std::exception& e) {
                std::string backup;
                try { try_utf8(without_verbatim(final_path(p->recovery->file.h)), backup); } catch (...) {}
                p->recovery->armed = false;
                recovery_errors += "\n" + p->target.display() + ": " + e.what() + "; recovery bytes retained at " + backup;
            }
        }
        fail(std::string(error.what()) + (recovery_errors.empty() ? "; committed text changes restored" :
             "; recovery incomplete, inspect these files:" + recovery_errors));
    }
    return Json::Object{{"text", "Applied " + std::to_string(pending.size()) + " file changes.\n" + out}};
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

std::vector<std::string> source_paths(const SearchContext& context, const std::string& root,
    const std::vector<std::string>& extensions, Clock::time_point deadline,
    const std::shared_ptr<std::atomic_bool>& cancelled) {
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
        bool gitignore = false, dotignore = false;
        for (const auto& e : entries) {
            if (e.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) continue;
            gitignore |= same_name(e.name, L".gitignore");
            dotignore |= same_name(e.name, L".ignore");
        }
        if (gitignore || dotignore) {
            auto next = std::make_shared<IgnoreScope>();
            next->parent = scope;
            read_ignore_rules(absolute, relative, gitignore, dotignore, next->rules);
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
            if (ignored_path(scope.get(), child, folder)) continue;
            if (folder) {
                bool denied = false;
                Handle sub(open_relative(handle, e.name, true, denied));
                if (!sub) fail("cannot enumerate LSP directory: " + child);
                walk(sub.h, join_path(absolute, e.name), child, scope);
            } else {
                std::string ext;
                if (!try_utf8(std::filesystem::path(e.name).extension().wstring(), ext)) continue;
                std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
                    std::string path;
                    if (!try_utf8(join_path(absolute, e.name), path)) fail("invalid source path");
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
    return name == "edit_file" || name == "write_file" || name == "move_file" || name == "create_directory";
}

Json run_file_tool(const std::string& name, const Json& arguments, const SearchContext& context,
                   const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (!std::holds_alternative<Json::Object>(arguments.value)) fail("arguments must be an object");
    if (context.read_only && is_write_tool(name)) fail(name + " is disabled: this server runs with --read-only");
    reject_unknown(name, arguments);
    const bool want_diagnostics = is_write_tool(name) && bool_arg(arguments, "diagnostics", false);
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
            return Json::Object{{"text", json_format ? result.dump() + "\n" : compact_outline(result)}};
        }
        catch (const LspFailure& e) {
            Json listing = list_dir(Json(Json::Object{{"path", query.at("path")}}), context, cancelled);
            auto& text = std::get<Json::Object>(listing.value).at("text");
            text = lsp_failure_banner(e.what(), "Fallback below: the plain folder listing instead of symbols") + text.string();
            return listing;
        }
    }
    if (name == "file_info") {
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
        if (!arguments.get("paths")) return Json::Object{{"text", lsp_query(method, arguments, context, cancelled).dump() + "\n"}};
        std::string out;
        for (const auto& path : path_args(arguments)) {
            Json::Object query = arguments.object(); query.erase("paths"); query["path"] = path;
            try { out += lsp_query(method, query, context, cancelled).dump() + "\n"; }
            catch (const LspFailure& e) { out += lsp_failure_banner(path + ": " + e.what(), "No fallback exists for this request"); }
            catch (const std::exception& e) { out += "[error " + path + ": " + e.what() + "]\n"; }
        }
        return Json::Object{{"text", std::move(out)}};
    }
    Json result;
    if (name == "edit_file") {
        if (operation != "auto" && operation != "symbol" && operation != "text" && operation != "insert_before" &&
            operation != "insert_after" && operation != "rename" && operation != "safe_delete") fail("unknown edit_file operation");
        const bool semantic = operation != "text" && (operation != "auto" || arguments.get("name_path"));
        if (semantic) {
            if (arguments.get("edits")) fail("semantic edits do not accept text edits");
            if (operation != "rename" && arguments.get("new_name")) fail("new_name requires operation=rename");
            if ((operation == "rename" || operation == "safe_delete") && arguments.get("new_text")) fail("rename/safe_delete do not accept new_text");
            result = lsp_edit(arguments, context, cancelled);
        } else {
            for (const char* key : {"name_path", "new_text", "new_name", "line", "column"})
                if (arguments.get(key)) fail(std::string(key) + " is only for semantic edits");
            result = edit_file(arguments, context, cancelled);
        }
    } else if (name == "write_file") result = write_file(arguments, context, cancelled);
    else if (name == "move_file") {
        try { result = lsp_move(arguments, context, cancelled); }
        catch (const LspFailure& e) {
            // Import planning failed before anything was written; auto moves still happen, without import edits.
            if (operation != "auto") throw;
            Json::Object plain = arguments.object();
            plain["operation"] = "filesystem";
            result = lsp_move(Json(std::move(plain)), context, cancelled);
            auto& text = std::get<Json::Object>(result.value).at("text");
            text = lsp_failure_banner(e.what(), "Fallback: the move was done without import updates; check references by hand") +
                   text.string();
        }
    }
    else if (name == "create_directory") result = create_directory(arguments, context);
    else fail("unknown tool");
    if (!dry_run) {
        lsp_after_mutation(result, name, arguments, context, cancelled);
        if (want_diagnostics) {
            try {
                Json::Object query{{"path", string_arg(arguments, "path")}};
                if (const Json* timeout = arguments.get("timeout_ms")) query.emplace("timeout_ms", *timeout);
                auto& text = std::get<Json::Object>(result.value).at("text");
                text = text.string() + lsp_query("diagnostics", query, context, cancelled).dump() + "\n";
            } catch (const LspFailure& e) {
                auto& text = std::get<Json::Object>(result.value).at("text");
                text = text.string() + lsp_failure_banner(std::string("diagnostics after the write failed: ") + e.what(),
                                                          "The write itself succeeded");
            } catch (const std::exception& e) {
                auto& text = std::get<Json::Object>(result.value).at("text");
                text = text.string() + "[warning: write applied; diagnostics unavailable: " + e.what() + "]\n";
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
    const Json expected_sha256 = field("string", "Fail if the file's sha256 (from read_file) changed.");
    const Json expected_mtime = field("string", "Fail if the file's mtime (from read_file) changed.");
    const std::string common_paths = " Links are never followed.";

    Json::Array tools;
    tools.push_back(Json::Object{{"name", "read_file"}, {"description",
        "Read live code through LSP: symbol overview by default (one \"LINE kind name_path\" line each; format=json for ranges), or name_path for a symbol body. "
        "Explicit offset/limit or operation=text reads lines (all remaining lines unless limit is set). Unconfigured formats use text. "
        "No output byte cap. Text header includes encoding, mtime and sha256; binary and >256 MiB refused (UTF-16 >64 MiB)." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path}, {"paths", paths},
            {"offset", field("integer", "First line, from 1.")},
            {"limit", field("integer", "Optional text line limit per file; default all remaining lines.")},
            {"operation", choice(Json::Array{"auto", "overview", "symbol", "text"}, "Default auto: LSP if configured, otherwise text.")},
            {"name_path", field("string", "Read this symbol's complete body; slash-separated parent/name with optional overload [i].")},
            {"include_kinds", Json::Object{{"type", "array"}, {"items", Json::Object{{"type", "integer"}}}, {"description", "LSP kinds 1-26 to include."}}},
            {"exclude_kinds", Json::Object{{"type", "array"}, {"items", Json::Object{{"type", "integer"}}}, {"description", "LSP kinds to exclude."}}},
            {"depth", field("integer", "Overview child depth; default -1 (all).")},
            {"format", choice(Json::Array{"compact", "json"}, "Overview: compact lines \"LINE kind name_path\" (default) or json with ranges.")},
            {"timeout_ms", field("integer", "LSP deadline, 1-300000; default 30000.")},
            {"line_numbers", field("boolean", "Text line numbers; default true.")}})}});
    tools.push_back(Json::Object{{"name", "list_dir"}, {"description",
        "List files and folders: \"d sub/\", \"f name SIZE\", \"l link\"." + common_paths},
        {"inputSchema", schema(Json::Object{
            {"path", field("string", "Folder; default the first root.")},
            {"operation", choice(Json::Array{"filesystem", "overview"}, "Default filesystem; overview returns live LSP symbols by file.")},
            {"depth", field("integer", "Filesystem: 1-32, default 1. Overview: child depth, default -1 (all).")},
            {"format", choice(Json::Array{"compact", "json"}, "Overview: compact lines per file (default) or json with ranges.")},
            {"hidden", field("boolean", "Include hidden entries.")},
            {"no_ignore", field("boolean", "Include .gitignore/.ignore'd entries.")},
            {"max_results", field("integer", "Optional entry limit, 1-10000; default unlimited.")},
            {"timeout_ms", field("integer", "Default 30000.")},
            {"max_output_bytes", max_output}})}});
    tools.push_back(Json::Object{{"name", "file_info"}, {"description",
        "Disk metadata, or operation=lsp for server capabilities, diagnostics for current file/symbol problems, restart for LSP recovery." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path}, {"paths", paths},
            {"operation", choice(Json::Array{"metadata", "lsp", "diagnostics", "restart"}, "Default metadata. lsp/restart may omit path to address all configured servers.")},
            {"name_path", field("string", "diagnostics: restrict to this symbol.")},
            {"severity", field("integer", "diagnostics: highest numeric severity to include, 1-4; default 4.")},
            {"timeout_ms", field("integer", "LSP deadline, 1-300000; default 30000.")},
            {"max_output_bytes", max_output}})}});
    if (read_only) return tools;

    const Json edit_item = Json::Object{{"type", "object"}, {"additionalProperties", false},
        {"required", Json::Array{"old_text", "new_text"}},
        {"properties", Json::Object{
            {"old_text", field("string", "Exact text; must match once unless replace_all.")},
            {"new_text", field("string", "Replacement.")},
            {"replace_all", field("boolean", "Replace every match.")}}}};
    tools.push_back(Json::Object{{"name", "edit_file"}, {"description",
        "Live LSP symbol replace, insert_before/insert_after, rename across files (listing same-name mentions it leaves, e.g. other languages), or reference-checked safe_delete. "
        "Text edits remain available. Snapshot guards, encoding preservation, dry-run diffs and rollback on commit failure; atomic per file." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path},
            {"edits", Json::Object{{"type", "array"}, {"items", edit_item}, {"description", "1-256 edits."}}},
            {"operation", choice(Json::Array{"auto", "symbol", "insert_before", "insert_after", "rename", "safe_delete", "text"}, "Default auto: name_path selects symbol replacement; edits selects text.")},
            {"name_path", field("string", "Unique slash-separated symbol path; overload [i] supported.")},
            {"new_name", field("string", "rename: new identifier; language server computes all affected files.")},
            {"line", field("integer", "rename: 1-based line instead of name_path.")},
            {"column", field("integer", "rename: 1-based UTF-16 column with line.")},
            {"diagnostics", field("boolean", "Return diagnostics for the primary file after a successful write; default false.")},
            {"new_text", field("string", "Complete replacement symbol, including declaration; used with name_path.")},
            {"timeout_ms", field("integer", "LSP deadline, 1-300000; default 30000.")},
            {"dry_run", field("boolean", "Diff only, write nothing.")},
            {"expected_sha256", expected_sha256}, {"expected_mtime", expected_mtime},
            {"max_output_bytes", field("integer", "Optional diff byte cap; no cap by default.")}}, Json::Array{"path"})}});
    tools.push_back(Json::Object{{"name", "write_file"}, {"description",
        "Create or replace a file atomically; creates parent folders." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path},
            {"content", field("string", "Full contents.")},
            {"diagnostics", field("boolean", "Include diagnostics after writing; default false.")},
            {"timeout_ms", field("integer", "Diagnostic deadline, 1-300000; default 30000.")},
            {"overwrite", field("boolean", "Replace an existing file.")},
            {"line_endings", choice(Json::Array{"lf", "crlf"}, "Default: the replaced file's, else as given.")},
            {"encoding", choice(Json::Array{"utf-8", "utf-8-bom", "utf-16le", "utf-16be"},
                                "Default: the replaced file's, else utf-8.")},
            {"expected_sha256", expected_sha256}, {"expected_mtime", expected_mtime}},
            Json::Array{"path", "content"})}});
    tools.push_back(Json::Object{{"name", "move_file"}, {"description",
        "Move a file/folder; auto asks configured LSP servers for import edits when supported. Refactor requires that support; filesystem moves paths. Active servers refresh after success." + common_paths},
        {"inputSchema", schema(Json::Object{{"source", field("string", path_text)},
            {"destination", field("string", path_text)},
            {"operation", choice(Json::Array{"auto", "refactor", "filesystem"}, "Default auto. refactor requires willRenameFiles; filesystem bypasses semantic import edits.")},
            {"dry_run", field("boolean", "Preview import edits and move without writing.")},
            {"timeout_ms", field("integer", "LSP deadline, 1-300000; default 30000.")},
            {"overwrite", field("boolean", "Replace an existing file; requires operation=filesystem.")}},
            Json::Array{"source", "destination"})}});
    tools.push_back(Json::Object{{"name", "create_directory"}, {"description",
        "Create a folder and its parents (mkdir -p)." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path}}, Json::Array{"path"})}});
    return tools;
}
}
