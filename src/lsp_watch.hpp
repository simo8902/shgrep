#pragma once
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
    // The root could not be watched at all; callers must fall back to checking every file themselves.
    bool failed() const;

private:
    struct State;
    std::unique_ptr<State> state_;
};
}
