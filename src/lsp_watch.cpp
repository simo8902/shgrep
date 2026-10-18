#include "lsp_watch.hpp"
#include <windows.h>
#include <cwctype>
#include <mutex>
#include <set>
#include <string>
#include <thread>

namespace shgrep {
namespace fs = std::filesystem;
namespace {
constexpr size_t kMaxPending = 100000;  // more changed paths than this are cheaper to treat as a reload
constexpr DWORD kFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE |
                          FILE_NOTIFY_CHANGE_LAST_WRITE;

std::wstring extended(const fs::path& path) {
    const std::wstring p = path.wstring();
    if (p.starts_with(L"\\\\?\\")) return p;
    if (p.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + p.substr(2);
    return L"\\\\?\\" + p;
}
bool tool_folder(std::wstring_view relative) {
    const size_t slash = relative.find(L'\\');
    std::wstring first(relative.substr(0, slash));
    for (auto& c : first) c = static_cast<wchar_t>(std::towlower(c));
    return first == L".git" || first == L".shgrep";
}
} // namespace

struct DirectoryWatch::State {
    fs::path root;
    HANDLE directory = INVALID_HANDLE_VALUE, changed = nullptr, stop = nullptr;
    OVERLAPPED overlapped{};
    std::vector<uint64_t> buffer = std::vector<uint64_t>((64 * 1024) / sizeof(uint64_t));
    std::thread thread;
    std::mutex mutex;
    std::set<std::wstring> pending;  // root-relative, as Windows reported them
    bool reload = false, failed = false;

    ~State() {
        if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
        if (changed) CloseHandle(changed);
        if (stop) CloseHandle(stop);
    }
    bool issue() {
        overlapped = OVERLAPPED{};
        overlapped.hEvent = changed;
        ResetEvent(changed);
        return ReadDirectoryChangesW(directory, buffer.data(), static_cast<DWORD>(buffer.size() * sizeof(uint64_t)), TRUE,
                                     kFilter, nullptr, &overlapped, nullptr) != 0;
    }
    // CONTRACT: mutex held.
    void parse(DWORD bytes) {
        const auto* at = reinterpret_cast<const unsigned char*>(buffer.data());
        const auto* end = at + bytes;
        while (at + sizeof(FILE_NOTIFY_INFORMATION) <= end) {
            const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(at);
            const std::wstring name(info->FileName, info->FileNameLength / sizeof(wchar_t));
            if (!name.empty() && !tool_folder(name)) {
                // A folder renamed into place brings files Windows never reports one by one.
                if (info->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                    const DWORD attributes = GetFileAttributesW(extended(root / name).c_str());
                    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) reload = true;
                }
                pending.insert(name);
                if (pending.size() > kMaxPending) { pending.clear(); reload = true; }
            }
            if (info->NextEntryOffset == 0) break;
            at += info->NextEntryOffset;
        }
    }
    void loop() {
        for (;;) {
            HANDLE events[2]{changed, stop};
            if (WaitForMultipleObjects(2, events, FALSE, INFINITE) != WAIT_OBJECT_0) {
                CancelIoEx(directory, &overlapped);
                DWORD ignored = 0;
                GetOverlappedResult(directory, &overlapped, &ignored, TRUE);
                return;
            }
            DWORD got = 0;
            const bool ok = GetOverlappedResult(directory, &overlapped, &got, FALSE) != 0;
            std::lock_guard lock(mutex);
            if (!ok || got == 0) reload = true;  // ERROR_NOTIFY_ENUM_DIR: the buffer overflowed
            else parse(got);
            if (!issue()) { failed = true; return; }
        }
    }
};

DirectoryWatch::DirectoryWatch(const fs::path& root) : state_(std::make_unique<State>()) {
    State& s = *state_;
    s.root = root;
    s.directory = CreateFileW(extended(root).c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    s.changed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    s.stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    // The first read is issued before the constructor returns, so no later change is missed.
    if (s.directory == INVALID_HANDLE_VALUE || !s.changed || !s.stop || !s.issue()) { s.failed = true; return; }
    s.thread = std::thread([state = state_.get()] { state->loop(); });
}

DirectoryWatch::~DirectoryWatch() {
    if (state_->stop) SetEvent(state_->stop);
    if (state_->thread.joinable()) state_->thread.join();
}

bool DirectoryWatch::failed() const {
    std::lock_guard lock(state_->mutex);
    return state_->failed;
}

void DirectoryWatch::take(std::vector<fs::path>& changed, bool& reload) {
    std::lock_guard lock(state_->mutex);
    // SAFETY: a watch that stopped can no longer vouch for anything.
    reload = state_->reload || state_->failed;
    state_->reload = false;
    for (const auto& name : state_->pending) changed.push_back(state_->root / name);
    state_->pending.clear();
}
}
