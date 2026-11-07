#pragma once
#include <chrono>
#include <filesystem>
#include <memory>
#include <vector>

namespace shgrep {
// CONTRACT: reports every path below root that Windows says changed (created, written, renamed, deleted) since the
//   previous take(). reload is set when changes were lost (buffer overflow, a folder renamed into place, a failed
//   watch); the caller must then treat every file as possibly changed. Paths below .git and .shgrep are dropped.
// Writes to a file that another program still holds open may not be reported until it is closed.
class DirectoryWatch {
public:
    explicit DirectoryWatch(const std::filesystem::path& root);
    ~DirectoryWatch();
    DirectoryWatch(const DirectoryWatch&) = delete;
    DirectoryWatch& operator=(const DirectoryWatch&) = delete;
    void take(std::vector<std::filesystem::path>& changed, bool& reload);
    enum class Sync {
        confirmed,  // the next take() holds every change made before sync(), or sets reload
        timed_out,  // the cookie was not reported within the timeout; changes made before sync() may be missing
        no_cookie,  // the cookie cannot be created (.shgrep unwritable, or a link or junction there); likewise
    };
    // Waits, at most `timeout`, until Windows has reported a fresh sync cookie below root\.shgrep\cookies, so the next
    // take() holds every change made before this call. Anything but confirmed leaves the caller unable to vouch for
    // files it did not reread itself.
    Sync sync(std::chrono::milliseconds timeout);
    // The root could not be watched at all; callers must fall back to checking every file themselves.
    bool failed() const;

private:
    struct State;
    std::unique_ptr<State> state_;
};
}
