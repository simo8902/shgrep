#pragma once
// Windows filesystem primitives shared by the search walker and the file tools.

#include <windows.h>
#include <winternl.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace shgrep {
struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : h(value) {}
    ~Handle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : h(std::exchange(other.h, INVALID_HANDLE_VALUE)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            close();
            h = std::exchange(other.h, INVALID_HANDLE_VALUE);
        }
        return *this;
    }
    explicit operator bool() const { return h != INVALID_HANDLE_VALUE; }
    void close() {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = INVALID_HANDLE_VALUE;
    }
};
inline std::string utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (!size) throw std::runtime_error("invalid Windows path encoding");
    std::string out(size, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), size, nullptr, nullptr);
    return out;
}
inline std::filesystem::path native_path(const std::string& s) {
    if (s.empty()) throw std::runtime_error("empty path");
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (!size) throw std::runtime_error("invalid UTF-8 path");
    std::wstring out(size, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), size);
    return std::filesystem::path(out);
}
inline std::wstring final_path(HANDLE h) {
    DWORD size = GetFinalPathNameByHandleW(h, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!size || size > 32768) throw std::runtime_error("cannot resolve filesystem path");
    std::wstring out(size, L'\0');
    DWORD written = GetFinalPathNameByHandleW(h, out.data(), size, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!written || written >= size) throw std::runtime_error("cannot resolve filesystem path");
    out.resize(written);
    return out;
}
inline bool inside(const std::wstring& path, const std::wstring& root) {
    if (path.size() < root.size() || CompareStringOrdinal(path.data(), static_cast<int>(root.size()),
         root.data(), static_cast<int>(root.size()), TRUE) != CSTR_EQUAL) return false;
    return path.size() == root.size() || root.back() == L'\\' || path[root.size()] == L'\\';
}

inline bool try_utf8(std::wstring_view s, std::string& out) {
    out.clear();
    if (s.empty()) return true;
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (!size) return false;
    out.resize(static_cast<size_t>(size));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), size,
                               nullptr, nullptr) == size;
}
// COMPAT: Win32 paths at MAX_PATH or longer need the \\?\ form unless the process opted into long paths.
// CONTRACT: path is absolute and lexically normal.
inline std::wstring long_path(const std::wstring& path) {
    if (path.size() < MAX_PATH - 12 || path.starts_with(L"\\\\?\\")) return path;
    if (path.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + path.substr(2);
    return L"\\\\?\\" + path;
}
inline std::wstring absolute_long_path(const std::filesystem::path& path) {
    return long_path(std::filesystem::absolute(path).lexically_normal().wstring());
}
inline std::wstring join_path(const std::wstring& directory, std::wstring_view name) {
    std::wstring out;
    out.reserve(directory.size() + 1 + name.size());
    out = directory;
    if (!out.empty() && out.back() != L'\\' && out.back() != L'/') out.push_back(L'\\');
    out.append(name);
    return out;
}
inline bool same_name(std::wstring_view a, const wchar_t* b) {
    return CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b, -1, TRUE) == CSTR_EQUAL;
}

struct DirEntry {
    std::wstring name;
    DWORD attributes = 0;
    uint64_t size = 0;
    uint64_t write_time = 0;  // FILETIME of the last write
};

// PERF: one handle per directory and 64 KiB batches of FILE_FULL_DIR_INFO supply names and attributes
// without a metadata call per entry.
inline bool list_directory(HANDLE directory, std::vector<uint64_t>& buffer, std::vector<DirEntry>& entries) {
    entries.clear();
    FILE_INFO_BY_HANDLE_CLASS request = FileFullDirectoryRestartInfo;
    for (;;) {
        if (!GetFileInformationByHandleEx(directory, request, buffer.data(),
                                          static_cast<DWORD>(buffer.size() * sizeof(uint64_t)))) {
            DWORD code = GetLastError();
            // An empty directory without "." entries (a FAT root) reports ERROR_FILE_NOT_FOUND.
            return code == ERROR_NO_MORE_FILES || code == ERROR_FILE_NOT_FOUND;
        }
        request = FileFullDirectoryInfo;
        const auto* cursor = reinterpret_cast<const unsigned char*>(buffer.data());
        for (;;) {
            const auto* info = reinterpret_cast<const FILE_FULL_DIR_INFO*>(cursor);
            std::wstring_view name(info->FileName, info->FileNameLength / sizeof(wchar_t));
            if (name != L"." && name != L"..")
                entries.push_back({std::wstring(name), info->FileAttributes, static_cast<uint64_t>(info->EndOfFile.QuadPart),
                                   static_cast<uint64_t>(info->LastWriteTime.QuadPart)});
            if (info->NextEntryOffset == 0) break;
            cursor += info->NextEntryOffset;
        }
    }
}

// SAFETY: below a root, every file and directory is opened by its single listed name relative to the parent's
// open handle, with FILE_OPEN_REPARSE_POINT. Each handle is therefore reached from the root handle one
// non-reparse component at a time, so a junction or symlink swapped in after listing is opened as itself
// rather than followed, and no path string is resolved again.
// PERF: this replaces a GetFinalPathNameByHandleW check per file and directory, which measured ~30 us per call
// and did not scale across threads (+90 ms per 6,000 files on 12 threads).
// `result`, when given, receives the NTSTATUS of the open.
inline HANDLE open_relative(HANDLE parent, std::wstring_view name, bool directory, bool& denied,
                            NTSTATUS* result = nullptr) {
    constexpr ULONG file_open = 0x00000001;              // FILE_OPEN
    constexpr ULONG directory_file = 0x00000001;         // FILE_DIRECTORY_FILE
    constexpr ULONG sequential_only = 0x00000004;        // FILE_SEQUENTIAL_ONLY
    constexpr ULONG synchronous_io = 0x00000020;         // FILE_SYNCHRONOUS_IO_NONALERT
    constexpr ULONG non_directory_file = 0x00000040;     // FILE_NON_DIRECTORY_FILE
    constexpr ULONG open_reparse_point = 0x00200000;     // FILE_OPEN_REPARSE_POINT
    constexpr NTSTATUS access_denied = static_cast<NTSTATUS>(0xC0000022L);
    UNICODE_STRING object_name;
    object_name.Buffer = const_cast<PWSTR>(name.data());
    object_name.Length = object_name.MaximumLength = static_cast<USHORT>(name.size() * sizeof(wchar_t));
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = parent;
    attributes.ObjectName = &object_name;
    IO_STATUS_BLOCK io{};
    HANDLE handle = nullptr;
    const ACCESS_MASK access = directory ? (FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE) : FILE_GENERIC_READ;
    const ULONG options = synchronous_io | open_reparse_point |
                          (directory ? directory_file : (non_directory_file | sequential_only));
    const NTSTATUS status = NtCreateFile(&handle, access, &attributes, &io, nullptr, 0,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, file_open,
                                         options, nullptr, 0);
    denied = status == access_denied;
    if (result) *result = status;
    return status >= 0 ? handle : INVALID_HANDLE_VALUE;
}

// ---- shgrep's own folders below a root ----
// SAFETY: the index, its sort runs and the sync cookies live in <root>\.shgrep, which anyone able to edit the root can
// replace with a junction or symbolic link. The root is opened by its path (links in a configured root's own path are
// the owner's choice); every folder below it is opened or created by its single name relative to its parent's handle
// with FILE_OPEN_REPARSE_POINT and refused unless it is a plain directory, and every file inside is created, opened,
// renamed and deleted by its single name relative to that folder's handle, as open_parent and stage_write do for
// edits. No path string below the root is resolved again, so a link swapped in at any time can never send a write
// outside the root.
namespace metadir {
constexpr ULONG disposition_open = 0x1, disposition_create = 0x2, disposition_open_if = 0x3;
constexpr ULONG option_directory = 0x1, option_sequential = 0x4, option_synchronous = 0x20, option_non_directory = 0x40,
                option_delete_on_close = 0x1000, option_open_reparse_point = 0x200000;
constexpr ULONG_PTR information_created = 2;  // FILE_CREATED
constexpr ULONG share_all = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
constexpr ACCESS_MASK directory_access = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES;

// Opens `name` relative to the open directory `parent`, never following a link. Never resolves more than that one
// component.
inline NTSTATUS open_at(HANDLE parent, std::wstring_view name, ACCESS_MASK access, ULONG share, ULONG disposition,
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
                                         disposition, options | option_synchronous | option_open_reparse_point,
                                         nullptr, 0);
    if (status < 0) return status;
    out = Handle(handle);
    if (information) *information = io.Information;
    return status;
}

inline bool plain_directory(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO info{};
    return GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info)) &&
           (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

// COMPAT: kernel32's SetFileInformationByHandle(FileRenameInfo) expands the name against the current directory;
// NtSetInformationFile takes it as given, relative to RootDirectory (see rename_handle in files.cpp).
using SetInformationFn = NTSTATUS(NTAPI*)(HANDLE, IO_STATUS_BLOCK*, void*, ULONG, ULONG);
inline SetInformationFn set_information() {
    static const auto function = reinterpret_cast<SetInformationFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
    return function;
}
}  // namespace metadir

// The folder `parts` below the configured root `root` (an absolute path), reached as the SAFETY note above says.
// Invalid when the root is unavailable or a component is missing (without create), a file, a link or a junction.
// With create, missing folders are made, and a new .shgrep gets a .gitignore that ignores it, so shgrep's own files
// never show up as untracked in git.
inline Handle open_metadata_directory(const std::wstring& root, std::initializer_list<std::wstring_view> parts,
                                      bool create) {
    using namespace metadir;
    Handle directory(CreateFileW(long_path(root).c_str(), directory_access | SYNCHRONIZE, share_all, nullptr,
                                 OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!directory) return Handle{};
    for (const std::wstring_view part : parts) {
        Handle child;
        ULONG_PTR information = 0;
        if (open_at(directory.h, part, directory_access, share_all, create ? disposition_open_if : disposition_open,
                    option_directory, 0, child, &information) < 0 ||
            !plain_directory(child.h))
            return Handle{};
        if (information == information_created && part == L".shgrep") {
            Handle ignore;
            DWORD put = 0;
            if (open_at(child.h, L".gitignore", FILE_GENERIC_WRITE, 0, disposition_create, option_non_directory,
                        FILE_ATTRIBUTE_NORMAL, ignore) >= 0)
                WriteFile(ignore.h, "*\n", 2, &put, nullptr);
        }
        directory = std::move(child);
    }
    return directory;
}

// Opens the existing entry `name` of the open folder `directory` itself; a link is opened as the link.
inline bool open_metadata_entry(HANDLE directory, std::wstring_view name, ACCESS_MASK access, ULONG share, Handle& out) {
    using namespace metadir;
    return open_at(directory, name, access, share, disposition_open, option_non_directory, 0, out) >= 0;
}

// Deletes the entry `name` of the open folder `directory`; a link is deleted as the link. False when it is absent, in
// use without delete sharing, or mapped by a reader.
inline bool delete_metadata_entry(HANDLE directory, std::wstring_view name) {
    Handle entry;
    if (!open_metadata_entry(directory, name, DELETE | FILE_READ_ATTRIBUTES, metadir::share_all, entry)) return false;
    FILE_DISPOSITION_INFO info{TRUE};
    return SetFileInformationByHandle(entry.h, FileDispositionInfo, &info, sizeof(info)) != 0;
}

// Creates the new file `name` in the open folder `directory`, replacing a stale entry of that name (a link is
// removed as the link). With temporary, the file is deleted when its handle closes. False when it cannot be made.
inline bool create_metadata_file(HANDLE directory, std::wstring_view name, ACCESS_MASK access, bool temporary,
                                 Handle& out) {
    using namespace metadir;
    const ULONG options = option_non_directory | option_sequential | (temporary ? option_delete_on_close : 0);
    const DWORD attributes = temporary ? FILE_ATTRIBUTE_TEMPORARY : FILE_ATTRIBUTE_NORMAL;
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (open_at(directory, name, access | DELETE, 0, disposition_create, options, attributes, out) >= 0) return true;
        if (attempt == 0 && !delete_metadata_entry(directory, name)) return false;
    }
    return false;
}

// Renames the open entry `item` to `name` inside the open folder `directory`. False when it cannot, for example
// because replace is false and `name` exists, or the file at `name` is mapped.
inline bool rename_metadata_entry(HANDLE item, HANDLE directory, std::wstring_view name, bool replace) {
    const metadir::SetInformationFn set = metadir::set_information();
    if (!set) return false;
    struct Info {
        ULONG flags;  // FILE_RENAME_INFORMATION_EX::Flags; FILE_RENAME_INFORMATION::ReplaceIfExists is its low byte
        HANDLE root;
        ULONG name_bytes;
        WCHAR name[1];
    };
    std::vector<unsigned char> buffer(sizeof(Info) + name.size() * sizeof(wchar_t));
    auto* info = reinterpret_cast<Info*>(buffer.data());
    info->root = directory;
    info->name_bytes = static_cast<ULONG>(name.size() * sizeof(wchar_t));
    std::memcpy(info->name, name.data(), info->name_bytes);
    // POSIX semantics replace a target that readers hold open with delete sharing.
    info->flags = 0x2 | (replace ? 0x1 : 0);  // FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS
    IO_STATUS_BLOCK io{};
    const auto size = static_cast<ULONG>(buffer.size());
    NTSTATUS status = set(item, &io, info, size, 65);  // FileRenameInformationEx
    if (status >= 0) return true;
    const auto code = static_cast<uint32_t>(status);
    // STATUS_INVALID_PARAMETER, STATUS_INVALID_INFO_CLASS, STATUS_NOT_SUPPORTED: no POSIX renames (FAT, exFAT, old
    // Windows), so a plain rename.
    if (code != 0xC000000D && code != 0xC0000003 && code != 0xC00000BB) return false;
    info->flags = replace ? 1 : 0;
    status = set(item, &io, info, size, 10);  // FileRenameInformation
    return status >= 0;
}

// The sync-cookie folder below the watched `root` (absolute): <root>\.shgrep\cookies, created when missing and
// reached as open_metadata_directory says; invalid when a link or junction stands in the way. Watchers drop everything
// below .shgrep except their own cookies. Callers reopen it for every cookie rather than keep it open, so the folder
// stays deletable and a .shgrep deleted meanwhile is made again.
inline Handle cookie_directory(const std::wstring& root) {
    return open_metadata_directory(root, {L".shgrep", L"cookies"}, true);
}

// A sync-cookie name unique within the machine: this process's id and a per-process counter.
inline std::wstring sync_cookie_name() {
    static std::atomic<uint64_t> next{0};
    return L"cookie-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(++next);
}

// Creates, and at once deletes, the file `name` in the open cookie folder `directory`. Windows reports a tree's
// changes in order, so once a recursive watcher of that tree reports the cookie it has reported every change made
// before this call (Watchman's sync cookie). The waiter registers `name` before calling, so the report cannot pass
// unnoticed. False when the folder is invalid or the cookie cannot be created.
inline bool touch_sync_cookie(const Handle& directory, const std::wstring& name) {
    if (!directory) return false;
    Handle cookie;
    return create_metadata_file(directory.h, name, FILE_GENERIC_WRITE, true, cookie);
}
}
