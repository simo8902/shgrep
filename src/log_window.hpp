#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>

#include "json.hpp"

namespace shgrep {
enum class LogLevel { debug, info, warning, error };

// Owns an optional UI thread. Logging never writes to the MCP transport or throws
// into a request; destroy this after all producers have finished.
class LogWindow {
public:
    explicit LogWindow(bool enabled = false, std::move_only_function<void()> exit_handler = {}) noexcept;
    ~LogWindow();
    LogWindow(const LogWindow&) = delete;
    LogWindow& operator=(const LogWindow&) = delete;

    void write(LogLevel level, std::string_view message, std::string_view tool = {},
               std::string_view request_id = {}, int64_t elapsed_ms = -1) noexcept;

    // Serialize only when the viewer is active; logging failures never reach the caller.
    void write_payload(LogLevel level, std::string_view label, const Json& value,
                       std::string_view tool = {}, std::string_view request_id = {}) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
