#include "files.hpp"
#include "ignore.hpp"
#include "winfs.hpp"

#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <map>
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

std::string sha256_hex(std::string_view data) {
    static const BCRYPT_ALG_HANDLE algorithm = [] {
        BCRYPT_ALG_HANDLE handle = nullptr;
        return BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) ? handle
                                                                                                         : nullptr;
    }();
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (!algorithm || !BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0)))
        fail("SHA-256 is unavailable");
    unsigned char digest[32];
    bool ok = true;
    for (size_t offset = 0; ok && offset < data.size();) {
        const auto chunk = static_cast<ULONG>(std::min<size_t>(data.size() - offset, size_t{1} << 30));
        ok = BCRYPT_SUCCESS(BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data() + offset)),
                                           chunk, 0));
        offset += chunk;
    }
    ok = ok && BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, sizeof(digest), 0));
    BCryptDestroyHash(hash);
    if (!ok) fail("SHA-256 failed");
    constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (unsigned char c : digest) {
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 15]);
    }
    return out;
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
Handle open_parent(const Target& target, bool create_missing, std::vector<std::string>* created = nullptr) {
    Handle directory = open_root(target);
    for (size_t i = 0; i + 1 < target.parts.size(); ++i) {
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
bool read_all(HANDLE file, const std::string& path, uint64_t limit, std::string& data) {
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
    uint32_t max_output = 0;
    explicit Budget(uint32_t max) : limit(max > 1024 ? max - 768 : max / 2), max_output(max) {}
    bool fits(std::string_view s) const { return used + Json::escaped_size(s) - 2 <= limit; }
    void take(std::string_view s) { used += Json::escaped_size(s) - 2; }
};

uint32_t max_output_arg(const Json& args) {
    return static_cast<uint32_t>(int_arg(args, "max_output_bytes", 65536, 512, 1048576));
}

std::string file_header(const std::string& path, const std::string& raw, const TextFile& text,
                        const FILE_BASIC_INFO& basic) {
    std::string header = "[file " + path + " | " + std::to_string(text.lines) + " lines, " + std::to_string(raw.size()) +
                         " bytes | " + encoding_name(text.encoding) + ", " + eol_name(text) + ", " +
                         (text.final_newline ? "final newline" : "no final newline");
    if (text.invalid)
        header += ", " + std::to_string(text.invalid) + " invalid byte sequences shown as U+FFFD (edit_file refuses "
                  "this file)";
    return header + " | mtime " + format_mtime(basic.LastWriteTime.QuadPart) + " | sha256 " + sha256_hex(raw) + "]\n";
}

// ---- read_file ----

struct ReadOptions {
    uint64_t offset = 1, limit = UINT64_MAX;
    bool numbers = true;
};

enum class Rendered { complete, cut, not_shown };

Rendered render_file(std::string& out, Budget& budget, const Target& target, const ReadOptions& options) {
    const std::string path = target.display();
    if (target.parts.empty()) fail(path + " is a configured root directory; use list_dir");
    std::string raw;
    FILE_BASIC_INFO basic{};
    {
        Handle directory = open_parent(target, false);
        Handle file = open_file(directory.h, target, share_all);
        basic = basic_info(file.h, path);
        if (!read_all(file.h, path, max_text_bytes, raw))
            fail(path + " is larger than 64 MiB; read_file reads whole files up to that size. Use search to find "
                 "the lines you need.");
    }
    const TextFile text = decode(raw);
    if (text.binary)
        fail(path + " is binary (NUL byte at offset " + std::to_string(text.nul_offset) +
             "); use search_bytes to inspect it");
    const std::string header = file_header(path, raw, text, basic);
    if (!budget.fits(header)) return Rendered::not_shown;
    budget.take(header);
    out += header;
    if (options.offset > text.lines && !(text.lines == 0 && options.offset == 1)) {
        out += "[offset " + std::to_string(options.offset) + " is past the end: the file has " +
               std::to_string(text.lines) + " lines]\n";
        return Rendered::complete;
    }
    const std::string& t = text.text;
    size_t pos = 0;
    uint64_t number = 1;
    while (number < options.offset && pos < t.size()) {
        const size_t newline = t.find('\n', pos);
        pos = newline == std::string::npos ? t.size() : newline + 1;
        ++number;
    }
    const uint64_t first = number;
    uint64_t shown = 0;
    bool out_of_budget = false;
    std::string line;
    while (pos < t.size() && shown < options.limit) {
        const size_t newline = t.find('\n', pos);
        size_t end = newline == std::string::npos ? t.size() : newline;
        if (newline != std::string::npos && end > pos && t[end - 1] == '\r') --end;
        line.clear();
        if (options.numbers) {
            char prefix[32];
            std::snprintf(prefix, sizeof(prefix), "%6llu", static_cast<unsigned long long>(number));
            line += prefix;
            line += "\xE2\x86\x92";  // U+2192 RIGHTWARDS ARROW
        }
        line.append(t, pos, end - pos);
        line.push_back('\n');
        if (!budget.fits(line)) { out_of_budget = true; break; }
        budget.take(line);
        out += line;
        ++shown;
        ++number;
        pos = newline == std::string::npos ? t.size() : newline + 1;
    }
    const std::string total = std::to_string(text.lines);
    const std::string range = std::to_string(first) + "-" + std::to_string(first + shown - 1);
    const std::string next = std::to_string(first + shown);
    if (out_of_budget) {
        if (shown == 0)
            out += "[status output_limit: line " + std::to_string(first) + " alone does not fit in max_output_bytes=" +
                   std::to_string(budget.max_output) + "; raise max_output_bytes (up to 1048576) or use search]\n";
        else
            out += "[status output_limit: showed lines " + range + " of " + total + " within max_output_bytes=" +
                   std::to_string(budget.max_output) + "; continue with offset=" + next + "]\n";
        return Rendered::cut;
    }
    if (pos < t.size())
        out += "[status limit: showed lines " + range + " of " + total + " (limit=" + std::to_string(options.limit) +
               "); continue with offset=" + next + "]\n";
    return Rendered::complete;
}

Json read_file(const Json& args, const SearchContext& context) {
    const std::vector<std::string> paths = path_args(args);
    const bool several = args.get("paths") != nullptr;
    ReadOptions options;
    options.offset = static_cast<uint64_t>(int_arg(args, "offset", 1, 1, INT64_MAX));
    if (args.get("limit")) options.limit = static_cast<uint64_t>(int_arg(args, "limit", 0, 1, INT64_MAX));
    options.numbers = bool_arg(args, "line_numbers", true);
    // CONTRACT: the whole file by default; only an explicit limit or max_output_bytes shortens the output.
    Budget budget(static_cast<uint32_t>(int_arg(args, "max_output_bytes", read_file_max_output, 512,
                                                read_file_max_output)));
    std::string out;
    for (size_t i = 0; i < paths.size(); ++i) {
        Rendered rendered = Rendered::complete;
        if (!several) rendered = render_file(out, budget, resolve(context, paths[i]), options);
        else {
            try { rendered = render_file(out, budget, resolve(context, paths[i]), options); }
            catch (const std::exception& e) {
                // CONTRACT: with paths, one unreadable file is reported in place and the others are still read.
                const std::string error = "[error " + std::string(e.what()) + "]\n";
                if (!budget.fits(error)) rendered = Rendered::not_shown;
                else { budget.take(error); out += error; }
            }
        }
        if (rendered == Rendered::complete) continue;
        std::string unread;
        for (size_t j = rendered == Rendered::cut ? i + 1 : i; j < paths.size(); ++j) unread += (unread.empty() ? "" : ", ") + paths[j];
        if (!unread.empty())
            out += "[status output_limit: max_output_bytes=" + std::to_string(budget.max_output) +
                   " reached; not read: " + unread + "]\n";
        break;
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
               std::shared_ptr<const IgnoreScope> scope, uint32_t depth) {
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
            read_ignore_rules(path, relative == "." ? std::string() : relative, gitignore, dotignore, next->rules);
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
        if (!s.no_ignore && ignored_path(scope.get(), child, is_directory)) { ++s.ignored_skipped; continue; }
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
        list_tree(s, sub.h, join_path(path, entry.name), child, scope, depth - 1);
    }
}

Json list_dir(const Json& args, const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled) {
    const Target target = resolve(context, args.get("path") ? string_arg(args, "path") : std::string("."));
    const auto depth = static_cast<uint32_t>(int_arg(args, "depth", 1, 1, 32));
    Listing s;
    // CONTRACT: list_dir shows everything by default; hidden false and no_ignore false opt into search's filters.
    s.hidden = bool_arg(args, "hidden", true);
    s.no_ignore = bool_arg(args, "no_ignore", true);
    s.max_entries = static_cast<uint64_t>(int_arg(args, "max_results", 500, 1, 10000));
    s.budget = Budget(max_output_arg(args));
    const auto timeout = int_arg(args, "timeout_ms", 30000, 1, 300000);
    s.deadline = Clock::now() + std::chrono::milliseconds(timeout);
    s.cancelled = &cancelled;
    const std::string path = target.display();
    Handle directory;
    if (target.parts.empty()) directory = open_root(target);
    else {
        Handle parent = open_parent(target, false);
        const NTSTATUS status = nt_open(parent.h, target.name(), directory_access, share_all, disposition_open,
                                        option_directory | option_open_reparse_point, 0, directory);
        if (status == status_not_directory) fail(path + " is a file; use read_file or file_info");
        if (status < 0) fail(path + ": " + status_text(status));
        refuse_link(directory.h, path);
    }
    const std::string header = "[dir " + path + " | depth " + std::to_string(depth) + "]\n";
    s.budget.take(header);
    list_tree(s, directory.h, target.full(target.parts.size()), ".", nullptr, depth);
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
FILE_BASIC_INFO atomic_write(HANDLE directory, const Target& target, const std::string& bytes, bool replace,
                             DWORD attributes, Handle* original) {
    static std::atomic<uint32_t> counter{0};
    const std::string path = target.display();
    Handle temp;
    for (int attempt = 0;; ++attempt) {
        const std::wstring temp_name = L".shgrep-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                       std::to_wstring(++counter) + L".tmp";
        const NTSTATUS status = nt_open(directory, temp_name, DELETE | FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES, 0,
                                        disposition_create, option_non_directory,
                                        attributes ? attributes : FILE_ATTRIBUTE_NORMAL, temp);
        if (status >= 0) break;
        if (status != status_collision || attempt == 8)
            fail(path + ": cannot create a temporary file in its folder (" + status_text(status) +
                 "); nothing was written");
    }
    DiscardOnFailure discard{temp.h};
    for (size_t offset = 0; offset < bytes.size();) {
        const auto chunk = static_cast<DWORD>(std::min<size_t>(bytes.size() - offset, size_t{1} << 24));
        DWORD written = 0;
        if (!WriteFile(temp.h, bytes.data() + offset, chunk, &written, nullptr) || written == 0) {
            const DWORD code = GetLastError();
            fail(path + ": write failed (" + win32_text(code) + "); nothing was written");
        }
        offset += written;
    }
    if (!FlushFileBuffers(temp.h)) {
        const DWORD code = GetLastError();
        fail(path + ": flush failed (" + win32_text(code) + "); nothing was written");
    }
    if (const DWORD code = rename_handle(temp.h, directory, target.name(), replace, original))
        fail(path + ": " + rename_error(code) + "; nothing was written");
    discard.armed = false;
    try { return basic_info(temp.h, path); }
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

std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> lines;
    for (size_t pos = 0; pos < text.size();) {
        const size_t newline = text.find('\n', pos);
        const size_t end = newline == std::string_view::npos ? text.size() : newline + 1;
        lines.push_back(text.substr(pos, end - pos));
        pos = end;
    }
    return lines;
}

// Myers' O(ND) shortest edit script over a and b; false when it needs more than max_d edits.
bool myers(const std::string_view* a, int n, const std::string_view* b, int m, int max_d, std::string& script) {
    const int offset = max_d + 1;
    std::vector<int> v(static_cast<size_t>(2 * max_d + 3), 0);
    std::vector<std::vector<int>> trace;  // trace[d][k + d]: furthest x on diagonal k after d edits
    int found = -1;
    for (int d = 0; d <= max_d && found < 0; ++d) {
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
Diff unified_diff(std::string_view old_text, std::string_view new_text, const std::string& label) {
    constexpr size_t context = 3;
    const auto a = split_lines(old_text), b = split_lines(new_text);
    size_t prefix = 0;
    while (prefix < a.size() && prefix < b.size() && a[prefix] == b[prefix]) ++prefix;
    size_t suffix = 0;
    while (suffix < a.size() - prefix && suffix < b.size() - prefix &&
           a[a.size() - 1 - suffix] == b[b.size() - 1 - suffix]) ++suffix;
    const size_t n = a.size() - prefix - suffix, m = b.size() - prefix - suffix;
    std::vector<DiffOp> ops;
    for (size_t i = prefix - std::min(prefix, context); i < prefix; ++i) ops.push_back({' ', i, i});
    std::string script;
    if (n + m > 20000 || !myers(a.data() + prefix, static_cast<int>(n), b.data() + prefix, static_cast<int>(m),
                                static_cast<int>(std::min<size_t>(n + m, 2000)), script))
        script = std::string(n, '-') + std::string(m, '+');
    size_t x = prefix, y = prefix;
    for (char kind : script) {
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

size_t count_matches(std::string_view text, std::string_view needle) {
    size_t count = 0;
    for (size_t pos = text.find(needle); pos != std::string_view::npos; pos = text.find(needle, pos + needle.size())) ++count;
    return count;
}

uint64_t line_at(std::string_view text, size_t pos) {
    return 1 + static_cast<uint64_t>(std::count(text.begin(), text.begin() + static_cast<ptrdiff_t>(pos), '\n'));
}

// Applies one edit to content. The old_text forms tried follow the file's line endings, so text written with
// LF matches a CRLF file and new_text is inserted with the same endings.
void apply_edit(std::string& content, const Edit& edit, Eol eol, size_t index, size_t total, uint64_t& replacements) {
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
        if ((count = count_matches(content, form.first)) != 0) { chosen = &form; break; }
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
        next.append(content, pos, at - pos);
        next += chosen->second;
        pos = at + chosen->first.size();
    }
    next.append(content, pos, std::string::npos);
    content = std::move(next);
    replacements += edit.replace_all ? count : 1;
}

Json edit_file(const Json& args, const SearchContext& context) {
    const Target target = resolve(context, string_arg(args, "path"));
    if (target.parts.empty()) fail("path names a configured root, not a file");
    const std::vector<Edit> edits = parse_edits(args);
    const bool dry_run = bool_arg(args, "dry_run", false);
    Budget budget(max_output_arg(args));
    const std::string path = target.display();
    std::lock_guard lock(write_mutex());
    Handle directory = open_parent(target, false);
    // CONTRACT: no other process may open the file for writing between this read and the rename.
    Handle file = open_file(directory.h, target, FILE_SHARE_READ | FILE_SHARE_DELETE);
    const FILE_BASIC_INFO basic = basic_info(file.h, path);
    std::string raw;
    if (!read_all(file.h, path, max_text_bytes, raw)) fail(path + " is larger than 64 MiB; edit_file does not edit it");
    check_guards(args, path, raw, basic);
    const TextFile text = decode(raw);
    if (text.binary) fail(path + " is binary (NUL byte at offset " + std::to_string(text.nul_offset) + "); edit_file edits text only");
    if (text.invalid)
        fail(path + " is not valid " + encoding_name(text.encoding) + " (" + std::to_string(text.invalid) +
             " invalid byte sequences); editing it would change bytes outside the edit, so nothing was written");
    if (!dry_run && (basic.FileAttributes & FILE_ATTRIBUTE_READONLY)) fail(path + " is read-only; nothing was written");
    std::string content = text.text;
    uint64_t replacements = 0;
    for (size_t i = 0; i < edits.size(); ++i) apply_edit(content, edits[i], eol_style(text), i, edits.size(), replacements);
    const std::string bytes = encode(content, text.encoding);
    if (bytes == raw) return Json::Object{{"text", "No change: the edits leave " + path + " as it was; nothing was written.\n"}};
    TextFile after;
    after.text = content;
    count_lines(after);
    const Diff diff = unified_diff(text.text, content, target.relative());
    FILE_BASIC_INFO written = basic;
    if (!dry_run) written = atomic_write(directory.h, target, bytes, true, basic.FileAttributes & kept_attributes, &file);
    std::string summary = std::string(dry_run ? "Dry run, nothing written. Would edit " : "Edited ") + path + ": " +
                          std::to_string(edits.size()) + (edits.size() == 1 ? " edit, " : " edits, ") +
                          std::to_string(replacements) + (replacements == 1 ? " replacement" : " replacements") +
                          ", +" + std::to_string(diff.added) + " -" + std::to_string(diff.removed) + " lines. ";
    summary += "Now " + std::to_string(after.lines) + " lines, " + encoding_name(text.encoding) + ", " + eol_name(after);
    if (!dry_run) summary += " | mtime " + format_mtime(written.LastWriteTime.QuadPart) + " | sha256 " + sha256_hex(bytes);
    summary += "\n";
    budget.take(summary);
    return Json::Object{{"text", summary + fit(diff.text, budget, dry_run
        ? "[diff cut at max_output_bytes]\n" : "[diff cut at max_output_bytes; the edit was applied in full]\n")}};
}

// ---- write_file ----

Json write_file(const Json& args, const SearchContext& context) {
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
    std::lock_guard lock(write_mutex());
    std::vector<std::string> created;
    Handle directory = open_parent(target, true, &created);
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
        const bool whole = read_all(existing.h, path, max_text_bytes, raw);
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
                                                 exists ? &existing : nullptr);
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

Json move_file(const Json& args, const SearchContext& context) {
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
    std::lock_guard lock(write_mutex());
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
    if (name == "read_file") return read_file(arguments, context);
    if (name == "list_dir") return list_dir(arguments, context, cancelled);
    if (name == "file_info") return file_info(arguments, context);
    if (name == "edit_file") return edit_file(arguments, context);
    if (name == "write_file") return write_file(arguments, context);
    if (name == "move_file") return move_file(arguments, context);
    if (name == "create_directory") return create_directory(arguments, context);
    fail("unknown tool");
}

// CONTRACT: these descriptions are the model's only documentation of the tools; every statement must match the
// implementation. Update them with any behavior change.
Json file_tool_definitions(bool read_only) {
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
    const char* path_text = "Relative to the first configured root (\"src/main.cpp\") or absolute inside a configured "
                            "root.";
    const Json path = field("string", path_text);
    const Json paths = Json::Object{{"type", "array"}, {"items", Json::Object{{"type", "string"}}},
        {"description", "Up to 32 paths, read in one call, instead of path. An unreadable one is reported in place."}};
    const Json max_output = field("integer", "Hard cap on the response size, 512-1048576, default 65536.");
    const Json expected_sha256 = field("string", "The sha256 from read_file's header. The call fails, writing nothing, "
                                                 "if the file's current bytes hash differently.");
    const Json expected_mtime = field("string", "The mtime from read_file's header. The call fails, writing nothing, "
                                                "if the file's modification time differs.");
    const std::string common_paths =
        " Paths: relative to the first configured root or absolute inside a configured root; '..' cannot leave the "
        "root, and a symbolic link or junction anywhere below the root is refused, never followed.";

    Json::Array tools;
    tools.push_back(Json::Object{{"name", "read_file"}, {"description",
        "Read a text file's exact and complete contents, with line numbers. By default the whole file is returned; "
        "lines are never cut or abbreviated. Give path, or paths to read several files; offset (first line, from 1) "
        "and limit (number of lines, default all) apply to each file. Each file starts with a header: [file PATH | "
        "N lines, B bytes | ENCODING (utf-8, utf-8-bom, "
        "utf-16le, utf-16be), LINE ENDINGS (lf, crlf, cr, mixed (...) or no line breaks), final newline or no final "
        "newline | mtime T | sha256 H]. Each line reads \"    42\xE2\x86\x92text\" (line_numbers false drops the "
        "prefix); the header names the line terminators, which are not shown. If limit or max_output_bytes ends a "
        "file early, a \"[status ...]\" line gives the total line count and the offset to continue from. Hidden and "
        ".gitignore'd files are readable: those filters apply only to tree walks. Binary files (a NUL byte) are "
        "refused; use search_bytes. Files over 64 MiB are refused; use search." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path}, {"paths", paths},
            {"offset", field("integer", "First line to show, counting from 1. Default 1.")},
            {"limit", field("integer", "Number of lines to show per file. Default: every line from offset to the end.")},
            {"line_numbers", field("boolean", "Default true: prefix each line with its number and \xE2\x86\x92.")},
            {"max_output_bytes", field("integer", "Optional cap on the response size, 512-268435456. Default: the "
                                                  "maximum, so whole files are returned.")}})}});
    tools.push_back(Json::Object{{"name", "list_dir"}, {"description",
        "List a folder's files AND subfolders (find_files never lists folders). One entry per line, relative to the "
        "folder: \"d sub/\" for a directory, \"f name SIZE\" for a file (SIZE in bytes), \"l name\" for a symbolic "
        "link or junction (listed, never entered). Entries are sorted by name, and each directory is followed by its "
        "contents down to depth levels. Every entry is listed by default, hidden and .gitignore'd ones included; "
        "hidden false or no_ignore false apply search's filters, and a final [not shown: ...] note counts what they "
        "skipped. A final "
        "\"[status ...]\" line means the listing is incomplete." + common_paths},
        {"inputSchema", schema(Json::Object{
            {"path", field("string", "Folder to list. Default: the first configured root. Relative to that root or "
                                     "absolute inside a configured root.")},
            {"depth", field("integer", "1-32, default 1: the folder's own entries; 2 adds their contents, and so on.")},
            {"hidden", field("boolean", "Default true: hidden items are listed. false skips names starting with '.' "
                                        "and items with the Windows hidden attribute.")},
            {"no_ignore", field("boolean", "Default true: .gitignore/.ignore are not applied. false skips the items "
                                           "they ignore.")},
            {"max_results", field("integer", "Maximum entries listed, 1-10000, default 500.")},
            {"timeout_ms", field("integer", "1-300000, default 30000. On expiry the partial listing has status "
                                            "timeout.")},
            {"max_output_bytes", max_output}})}});
    tools.push_back(Json::Object{{"name", "file_info"}, {"description",
        "Describe a file or folder without printing its contents: type (file, directory, or link: a symbolic link "
        "or junction, reported but not followed), size, mtime and attributes; for a file up to 64 MiB also whether "
        "it is binary, and for text its encoding, line count, line endings, final newline and sha256. Give path or "
        "paths." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path}, {"paths", paths}, {"max_output_bytes", max_output}})}});
    if (read_only) return tools;

    const Json edit_item = Json::Object{{"type", "object"}, {"additionalProperties", false},
        {"required", Json::Array{"old_text", "new_text"}},
        {"properties", Json::Object{
            {"old_text", field("string", "Exact text to replace, including whitespace and indentation.")},
            {"new_text", field("string", "Replacement text; may be empty to delete old_text.")},
            {"replace_all", field("boolean", "Default false: old_text must match exactly once. true replaces every "
                                             "occurrence.")}}}};
    tools.push_back(Json::Object{{"name", "edit_file"}, {"description",
        "Replace exact text in a file. edits is a list of {old_text, new_text, replace_all}, applied in order, each "
        "to the result of the one before. An old_text that is not found, or found more than once without "
        "replace_all, fails the call: the error names the edit and how many times it matched (with line numbers). "
        "All edits apply or none do, and the file is replaced atomically (temporary file + rename). old_text and "
        "new_text may use \\n line breaks in a CRLF file: they are matched and written with the file's own line "
        "endings, and the encoding and BOM are kept. Returns a unified diff. dry_run shows the diff without writing. "
        "expected_sha256 or expected_mtime (from read_file's header) refuse the edit if the file changed after it "
        "was read; the output gives the new values for the next edit. Refuses binary files, files with invalid "
        "UTF-8 or UTF-16, read-only files and files over 64 MiB." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path},
            {"edits", Json::Object{{"type", "array"}, {"items", edit_item},
                {"description", "1-256 replacements, applied in order."}}},
            {"dry_run", field("boolean", "Default false. true returns the diff and writes nothing.")},
            {"expected_sha256", expected_sha256}, {"expected_mtime", expected_mtime},
            {"max_output_bytes", max_output}}, Json::Array{"path", "edits"})}});
    tools.push_back(Json::Object{{"name", "write_file"}, {"description",
        "Create a file, or replace all of it, with content. Missing parent folders are created. An existing file is "
        "replaced only when overwrite is true. The write is atomic (temporary file + rename). line_endings (lf or "
        "crlf) converts every line break in content; encoding is utf-8, utf-8-bom, utf-16le or utf-16be. When "
        "replacing a text file both default to what it used; for a new file the encoding defaults to utf-8 and "
        "content's line breaks are kept as given. Returns the new line count, size, mtime and sha256." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path},
            {"content", field("string", "The complete new file contents.")},
            {"overwrite", field("boolean", "Default false: fail if the file exists. true replaces it.")},
            {"line_endings", choice(Json::Array{"lf", "crlf"}, "Convert every line break in content to this. "
                                    "Default: the replaced file's endings, or content as given for a new file.")},
            {"encoding", choice(Json::Array{"utf-8", "utf-8-bom", "utf-16le", "utf-16be"},
                                "Default: the replaced file's encoding, or utf-8 for a new file.")},
            {"expected_sha256", expected_sha256}, {"expected_mtime", expected_mtime}},
            Json::Array{"path", "content"})}});
    tools.push_back(Json::Object{{"name", "move_file"}, {"description",
        "Move or rename a file or folder within the roots, atomically. Missing parent folders of destination are "
        "created. An existing destination file is replaced only when overwrite is true; a folder is never replaced. "
        "Moves within one volume only." + common_paths},
        {"inputSchema", schema(Json::Object{{"source", field("string", path_text)},
            {"destination", field("string", path_text)},
            {"overwrite", field("boolean", "Default false: fail if destination exists.")}},
            Json::Array{"source", "destination"})}});
    tools.push_back(Json::Object{{"name", "create_directory"}, {"description",
        "Create a folder and any missing parents, like mkdir -p; an existing folder is not an error." + common_paths},
        {"inputSchema", schema(Json::Object{{"path", path}}, Json::Array{"path"})}});
    return tools;
}
}
