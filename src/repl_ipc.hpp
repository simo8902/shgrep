#pragma once
#include "json.hpp"
#include <windows.h>
#include <algorithm>
#include <string>
#include <utility>

namespace shgrep::repl_ipc {
constexpr size_t max_frame = 256ull << 20;
class ConnectionFailure : public std::runtime_error {
public:
    DWORD windows_error;
    ConnectionFailure(const char* operation, DWORD code)
        : std::runtime_error(std::string("C++ REPL worker connection closed while ") + operation +
              " (Windows error " + std::to_string(code) + ")"), windows_error(code) {}
};
struct Handle {
    HANDLE value = nullptr;
    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) { reset(); value = std::exchange(other.value, nullptr); }
        return *this;
    }
    HANDLE release() noexcept { return std::exchange(value, nullptr); }
    void reset(HANDLE handle = nullptr) {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
        value = handle;
    }
};
inline void write(HANDLE pipe, const Json& message) {
    std::string text = message.dump();
    if (text.size() > max_frame) throw std::runtime_error("C++ REPL message exceeds 256 MiB");
    text += '\n';
    size_t offset = 0;
    while (offset < text.size()) {
        DWORD sent = 0;
        const auto count = static_cast<DWORD>(std::min<size_t>(65536, text.size() - offset));
        const BOOL written = WriteFile(pipe, text.data() + offset, count, &sent, nullptr);
        if (!written || !sent)
            throw ConnectionFailure("writing", written ? ERROR_BROKEN_PIPE : GetLastError());
        offset += sent;
    }
}
class Reader {
    std::string pending_;
    size_t scanned_ = 0;
public:
    Json read(HANDLE pipe) {
        for (;;) {
            const size_t newline = pending_.find('\n', scanned_);
            if (newline != std::string::npos) {
                std::string line = pending_.substr(0, newline);
                pending_.erase(0, newline + 1);
                scanned_ = 0;
                return Json::parse(line);
            }
            scanned_ = pending_.size();
            char block[8192];
            DWORD received = 0;
            const BOOL read = ReadFile(pipe, block, sizeof(block), &received, nullptr);
            if (!read || !received)
                throw ConnectionFailure("reading", read ? ERROR_BROKEN_PIPE : GetLastError());
            if (pending_.size() > max_frame - received)
                throw std::runtime_error("C++ REPL message exceeds 256 MiB");
            pending_.append(block, received);
        }
    }
};
inline Handle duplicate(HANDLE source) {
    HANDLE copy = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &copy, 0, FALSE, DUPLICATE_SAME_ACCESS))
        throw std::runtime_error("cannot duplicate C++ REPL channel");
    return Handle(copy);
}
} // namespace shgrep::repl_ipc
