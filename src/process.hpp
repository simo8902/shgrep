#pragma once
#include <atomic>
#include <cstddef>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace shgrep {
struct CapturedProcess {
    std::string status, output, error;
    std::optional<uint32_t> exit_code;
    bool truncated = false;
    bool started = false;
};
// Direct executable invocation, Windows argument quoting, isolated inherited handles and kill-on-close job.
// The executable's directory is prepended to PATH only in this child's environment.
CapturedProcess capture_process(const std::vector<std::string>& arguments, const std::filesystem::path& directory,
    std::chrono::steady_clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled,
    size_t max_output_bytes = 1024 * 1024);
// SAFETY (#51): the mandatory offline/telemetry opt-out variables every child process shgrep starts receives. Applied
// last, so neither the parent's environment nor a configuration can override them.
const std::vector<std::pair<std::wstring, std::wstring>>& offline_environment();
}
