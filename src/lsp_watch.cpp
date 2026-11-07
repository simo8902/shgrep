#include "lsp_watch.hpp"
#include "winfs.hpp"
#include <windows.h>
#include <condition_variable>
#include <cwctype>
#include <map>
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
    // 1 MiB, so a checkout or a build's burst of changes fits without a reload (which restarts the language server).
    std::vector<uint64_t> buffer = std::vector<uint64_t>((1u << 20) / sizeof(uint64_t));
    std::thread thread;
    std::mutex mutex;
    std::condition_variable cv;      // signalled after every report
    std::set<std::wstring> pending;  // root-relative, as Windows reported them
    std::map<std::wstring, bool> cookies;  // sync cookies being waited for -> reported yet
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
        const auto read = [&] {
            return ReadDirectoryChangesW(directory, buffer.data(), static_cast<DWORD>(buffer.size() * sizeof(uint64_t)),
                                         TRUE, kFilter, nullptr, &overlapped, nullptr) != 0;
        };
        if (read()) return true;
        // COMPAT: over the network Windows refuses a change buffer above 64 KB.
        if (GetLastError() != ERROR_INVALID_PARAMETER || buffer.size() * sizeof(uint64_t) <= 64 * 1024) return false;
        buffer.assign((64 * 1024) / sizeof(uint64_t), 0);
        return read();
    }
    // CONTRACT: mutex held.
    void parse(DWORD bytes) {
        const auto* at = reinterpret_cast<const unsigned char*>(buffer.data());
        const auto* end = at + bytes;
        while (at + sizeof(FILE_NOTIFY_INFORMATION) <= end) {
            const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(at);
            const std::wstring name(info->FileName, info->FileNameLength / sizeof(wchar_t));
            // A sync cookie that sync() waits for; like everything else below .shgrep it is never reported.
            constexpr std::wstring_view cookie_prefix = L".shgrep\\cookies\\";
            if (name.size() > cookie_prefix.size() &&
                CompareStringOrdinal(name.data(), static_cast<int>(cookie_prefix.size()), cookie_prefix.data(),
                                     static_cast<int>(cookie_prefix.size()), TRUE) == CSTR_EQUAL)
                if (const auto it = cookies.find(name.substr(cookie_prefix.size())); it != cookies.end()) it->second = true;
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
            cv.notify_all();
            if (!issue()) { failed = true; cv.notify_all(); return; }
        }
    }
};

DirectoryWatch::DirectoryWatch(const fs::path& root) : state_(std::make_unique<State>()) {
    State& s = *state_;
    s.root = root;
    // Created before the watch starts, so its own folders are never reported.
    cookie_directory(fs::absolute(root).lexically_normal().wstring());
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

DirectoryWatch::Sync DirectoryWatch::sync(std::chrono::milliseconds timeout) {
    State& s = *state_;
    const std::wstring name = sync_cookie_name();
    {
        // Registered before the cookie exists, so its report cannot pass unnoticed.
        std::lock_guard lock(s.mutex);
        if (s.failed) return Sync::confirmed;  // take() reports reload
        s.cookies.emplace(name, false);
    }
    // Reopened per cookie, so a .shgrep deleted meanwhile (the cache cleared) is made again.
    const bool touched = touch_sync_cookie(cookie_directory(fs::absolute(s.root).lexically_normal().wstring()), name);
    std::unique_lock lock(s.mutex);
    // A lost report (reload) or a stopped watch also ends the wait: take() then tells the caller to reread everything.
    const bool seen = touched && s.cv.wait_for(lock, timeout, [&] { return s.cookies.at(name) || s.reload || s.failed; });
    s.cookies.erase(name);
    return seen ? Sync::confirmed : touched ? Sync::timed_out : Sync::no_cookie;
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
