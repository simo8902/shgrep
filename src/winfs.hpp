#pragma once
// Windows filesystem primitives shared by the search walker and the file tools.

#include <windows.h>
#include <winternl.h>

#include <cstdint>
#include <filesystem>
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
                entries.push_back({std::wstring(name), info->FileAttributes, static_cast<uint64_t>(info->EndOfFile.QuadPart)});
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
inline HANDLE open_relative(HANDLE parent, std::wstring_view name, bool directory, bool& denied) {
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
    return status >= 0 ? handle : INVALID_HANDLE_VALUE;
}
}
