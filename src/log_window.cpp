#include "log_window.hpp"

#include <windows.h>
#include <richedit.h>
#include <shellapi.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cwchar>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace shgrep {
namespace {
constexpr size_t max_pending_messages = 2048;
constexpr LONG max_display_chars = 1024 * 1024;
constexpr wchar_t window_class[] = L"shgrep.LogWindow";
constexpr UINT tray_callback = WM_APP + 1;
constexpr UINT tray_show_command = 1;
constexpr UINT tray_exit_command = 2;

std::wstring log_text(std::string_view text, size_t limit) {
    // Bound the conversion too. Windows replaces an incomplete UTF-8 sequence
    // at the byte boundary; never leave a lone high surrogate at the UTF-16 cap.
    const int bytes = static_cast<int>(std::min(text.size(), limit * 4));
    if (bytes == 0) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), bytes, nullptr, 0);
    std::wstring wide(static_cast<size_t>(size), L'\0');
    if (size) MultiByteToWideChar(CP_UTF8, 0, text.data(), bytes, wide.data(), size);
    if (wide.size() > limit) wide.resize(limit);
    if (!wide.empty() && wide.back() >= 0xd800 && wide.back() <= 0xdbff) wide.pop_back();
    std::wstring out;
    out.reserve(wide.size());
    for (wchar_t c : wide) {
        if (c == L'\r') continue;
        if (c == L'\n') out += L"\r\n";
        else out += c >= L' ' || c == L'\t' ? c : L'?';
    }
    return out;
}

const wchar_t* level_name(LogLevel level) {
    switch (level) {
    case LogLevel::debug: return L"DEBUG";
    case LogLevel::warning: return L"WARNING";
    case LogLevel::error: return L"ERROR";
    default: return L"INFO";
    }
}

COLORREF level_color(LogLevel level) {
    switch (level) {
    case LogLevel::debug: return RGB(100, 100, 100);
    case LogLevel::warning: return RGB(160, 85, 0);
    case LogLevel::error: return RGB(190, 0, 0);
    default: return RGB(20, 20, 20);
    }
}
}

struct LogWindow::Impl {
    struct Entry {
        LogLevel level;
        std::wstring text;
        LONG tool_begin = -1;
        LONG tool_end = -1;
    };

    std::mutex mutex;
    std::deque<Entry> pending;
    size_t dropped = 0;
    std::atomic_bool stopping{false};
    std::atomic_bool accepting{true};
    // All handles below belong exclusively to the UI thread.
    HWND window = nullptr;
    HWND editor = nullptr;
    HFONT font = nullptr;
    NOTIFYICONDATAW tray{};
    bool tray_present = false;
    bool exit_requested = false;
    UINT taskbar_created = 0;
    std::move_only_function<void()> exit_handler;
    std::thread ui_thread;

    explicit Impl(std::move_only_function<void()> handler)
        : exit_handler(std::move(handler)), ui_thread([this] { run(); }) {}
    ~Impl() {
        stopping.store(true);
        // The UI's 100 ms timer wakes the message loop without cross-thread
        // window access, including when the window is minimized.
        if (ui_thread.joinable()) ui_thread.join();
    }

    void write(LogLevel level, std::string_view message, std::string_view tool,
               std::string_view request_id, int64_t elapsed_ms, std::string_view label = {}) noexcept {
        try {
            if (!accepting.load() || stopping.load()) return;
            SYSTEMTIME now{};
            GetLocalTime(&now);
            wchar_t timestamp[32]{};
            std::swprintf(timestamp, 32, L"%02u:%02u:%02u.%03u ",
                          static_cast<unsigned>(now.wHour), static_cast<unsigned>(now.wMinute),
                          static_cast<unsigned>(now.wSecond), static_cast<unsigned>(now.wMilliseconds));
            size_t offset = 0;
            size_t part = 0;
            do {
                if (!accepting.load() || stopping.load()) return;
                size_t end = offset + std::min<size_t>(message.size() - offset, 4096);
                // Back up to the leading byte so a valid UTF-8 code point is
                // converted in one piece, even at a chunk boundary.
                while (end < message.size() && end > offset &&
                       (static_cast<unsigned char>(message[end]) & 0xc0) == 0x80) --end;
                if (end == offset && offset < message.size())
                    end = offset + std::min<size_t>(message.size() - offset, 4096);

                Entry entry{level, timestamp};
                entry.text += level_name(level);
                if (!tool.empty()) {
                    entry.text += L" [";
                    entry.tool_begin = static_cast<LONG>(entry.text.size());
                    entry.text += log_text(tool, 128);
                    entry.tool_end = static_cast<LONG>(entry.text.size());
                    entry.text += L"]";
                }
                if (!request_id.empty()) entry.text += L" request=" + log_text(request_id, 512);
                if (!label.empty()) entry.text += L" " + log_text(label, 256);
                if (message.size() > 4096) {
                    entry.text += L" [part " + std::to_wstring(++part) + L"; UTF-8 bytes " +
                        std::to_wstring(offset) + L"-" + std::to_wstring(end) + L"/" +
                        std::to_wstring(message.size()) + L"]";
                }
                entry.text += L" ";
                // The byte-sized chunk fits the conversion limit without a cutoff.
                entry.text += log_text(message.substr(offset, end - offset), 4096);
                if (elapsed_ms >= 0) entry.text += L" (" + std::to_wstring(elapsed_ms) + L" ms)";
                entry.text += L"\r\n";
                {
                    std::lock_guard lock(mutex);
                    if (!accepting.load() || stopping.load()) return;
                    if (pending.size() == max_pending_messages) {
                        pending.pop_front();
                        ++dropped;
                    }
                    pending.push_back(std::move(entry));
                }
                offset = end;
            } while (offset < message.size());
        } catch (...) {
            // Surface incomplete logging on the next drain without letting an
            // allocation failure escape into the operation being described.
            try {
                std::lock_guard lock(mutex);
                ++dropped;
            } catch (...) {}
        }
    }

    void append(const Entry& entry, LONG& removed_chars, LONG& removed_lines) {
        GETTEXTLENGTHEX request{GTL_NUMCHARS | GTL_PRECISE, 1200};
        // Rich Edit selection offsets count paragraph breaks as one character.
        const LRESULT count = SendMessageW(editor, EM_GETTEXTLENGTHEX,
                                           reinterpret_cast<WPARAM>(&request), 0);
        LONG length = static_cast<LONG>(count);
        if (length + static_cast<LONG>(entry.text.size()) > max_display_chars) {
            const LONG cut = std::max(length / 4,
                length + static_cast<LONG>(entry.text.size()) - max_display_chars);
            const LONG line = static_cast<LONG>(SendMessageW(editor, EM_EXLINEFROMCHAR, 0, cut));
            LONG boundary = static_cast<LONG>(SendMessageW(editor, EM_LINEINDEX, line + 1, 0));
            if (boundary < 0) boundary = length;
            removed_lines += static_cast<LONG>(SendMessageW(editor, EM_EXLINEFROMCHAR, 0, boundary));
            removed_chars += boundary;
            CHARRANGE oldest{0, boundary};
            SendMessageW(editor, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&oldest));
            SendMessageW(editor, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L""));
            length -= boundary;
        }
        CHARRANGE end{length, length};
        SendMessageW(editor, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&end));
        CHARFORMAT2W format{};
        format.cbSize = sizeof(format);
        format.dwMask = CFM_COLOR | CFM_BACKCOLOR | CFM_BOLD;
        format.crTextColor = level_color(entry.level);
        format.crBackColor = RGB(255, 255, 255);
        SendMessageW(editor, EM_SETCHARFORMAT, SCF_SELECTION, reinterpret_cast<LPARAM>(&format));
        SendMessageW(editor, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(entry.text.c_str()));
        if (entry.tool_begin >= 0 && entry.tool_end > entry.tool_begin) {
            CHARRANGE tool{length + entry.tool_begin, length + entry.tool_end};
            SendMessageW(editor, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&tool));
            format.dwMask = CFM_BACKCOLOR | CFM_BOLD;
            format.dwEffects = CFE_BOLD;
            format.crBackColor = RGB(255, 245, 170);
            SendMessageW(editor, EM_SETCHARFORMAT, SCF_SELECTION, reinterpret_cast<LPARAM>(&format));
        }
    }

    void drain() {
        std::deque<Entry> batch;
        size_t lost = 0;
        {
            std::lock_guard lock(mutex);
            // Bound UI work per tick; producers never wait for text rendering.
            const size_t count = std::min<size_t>(pending.size(), 128);
            for (size_t i = 0; i < count; ++i) {
                batch.push_back(std::move(pending.front()));
                pending.pop_front();
            }
            lost = std::exchange(dropped, 0);
        }
        if (lost) batch.push_front(Entry{LogLevel::warning,
            L"WARNING Dropped " + std::to_wstring(lost) + L" queued log entries; payloads may be incomplete.\r\n"});
        if (batch.empty()) return;

        CHARRANGE selection{};
        SendMessageW(editor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&selection));
        POINT scroll{};
        SendMessageW(editor, EM_GETSCROLLPOS, 0, reinterpret_cast<LPARAM>(&scroll));
        const LONG first_line = static_cast<LONG>(SendMessageW(editor, EM_GETFIRSTVISIBLELINE, 0, 0));
        SCROLLINFO info{};
        info.cbSize = sizeof(info);
        info.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
        const bool follow = !GetScrollInfo(editor, SB_VERT, &info) ||
            static_cast<int64_t>(info.nPos) + std::max<UINT>(info.nPage, 1) > info.nMax;

        // Restore read-only/redraw state even if formatting allocation fails.
        struct Update {
            HWND control;
            explicit Update(HWND value) : control(value) {
                SendMessageW(control, WM_SETREDRAW, FALSE, 0);
                SendMessageW(control, EM_SETREADONLY, FALSE, 0);
            }
            ~Update() {
                SendMessageW(control, EM_SETREADONLY, TRUE, 0);
                SendMessageW(control, WM_SETREDRAW, TRUE, 0);
                RedrawWindow(control, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE);
            }
        } update(editor);
        LONG removed_chars = 0;
        LONG removed_lines = 0;
        for (const auto& entry : batch) append(entry, removed_chars, removed_lines);
        if (removed_chars > 0) {
            append(Entry{LogLevel::warning,
                L"WARNING Rolling history limit reached; older displayed log text was removed.\r\n"},
                removed_chars, removed_lines);
        }
        selection.cpMin = std::max<LONG>(0, selection.cpMin - removed_chars);
        selection.cpMax = std::max<LONG>(0, selection.cpMax - removed_chars);
        SendMessageW(editor, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&selection));
        if (follow) {
            SendMessageW(editor, WM_VSCROLL, SB_BOTTOM, 0);
            POINT bottom{};
            SendMessageW(editor, EM_GETSCROLLPOS, 0, reinterpret_cast<LPARAM>(&bottom));
            bottom.x = scroll.x;
            SendMessageW(editor, EM_SETSCROLLPOS, 0, reinterpret_cast<LPARAM>(&bottom));
        } else if (removed_lines == 0) {
            SendMessageW(editor, EM_SETSCROLLPOS, 0, reinterpret_cast<LPARAM>(&scroll));
        } else {
            const LONG current = static_cast<LONG>(SendMessageW(editor, EM_GETFIRSTVISIBLELINE, 0, 0));
            const LONG wanted = std::max<LONG>(0, first_line - removed_lines);
            SendMessageW(editor, EM_LINESCROLL, 0, wanted - current);
            POINT adjusted{};
            SendMessageW(editor, EM_GETSCROLLPOS, 0, reinterpret_cast<LPARAM>(&adjusted));
            adjusted.x = scroll.x;
            SendMessageW(editor, EM_SETSCROLLPOS, 0, reinterpret_cast<LPARAM>(&adjusted));
        }
    }

    void remove_tray_icon() noexcept {
        if (tray_present) {
            Shell_NotifyIconW(NIM_DELETE, &tray);
            tray_present = false;
        }
    }

    bool add_tray_icon(HWND hwnd) noexcept {
        if (tray_present) return true;
        tray = {};
        tray.cbSize = sizeof(tray);
        tray.hWnd = hwnd;
        tray.uID = 1;
        tray.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        tray.uCallbackMessage = tray_callback;
        tray.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
        std::swprintf(tray.szTip, sizeof(tray.szTip) / sizeof(tray.szTip[0]),
                      L"shgrep Logs (PID %lu)", static_cast<unsigned long>(GetCurrentProcessId()));
        if (!Shell_NotifyIconW(NIM_ADD, &tray)) return false;
        tray_present = true;
        tray.uVersion = NOTIFYICON_VERSION_4;
        if (!Shell_NotifyIconW(NIM_SETVERSION, &tray)) {
            remove_tray_icon();
            return false;
        }
        return true;
    }

    void report_tray_failure() noexcept {
        write(LogLevel::warning, "Tray icon unavailable; the log window remains on the taskbar", {}, {}, -1);
        std::fprintf(stderr, "shgrep: tray icon unavailable; keeping the log window on the taskbar\n");
    }

    void show_logs(HWND hwnd) noexcept {
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
        if (editor) SetFocus(editor);
    }

    void show_tray_menu(HWND hwnd) {
        HMENU menu = CreatePopupMenu();
        if (!menu) {
            write(LogLevel::error, "Cannot create the tray menu", {}, {}, -1);
            return;
        }
        const UINT exit_flags = MF_STRING | (exit_requested || !exit_handler ? MF_GRAYED : MF_ENABLED);
        if (!AppendMenuW(menu, MF_STRING, tray_show_command, L"Show logs") ||
            !AppendMenuW(menu, exit_flags, tray_exit_command, L"Exit")) {
            DestroyMenu(menu);
            write(LogLevel::error, "Cannot populate the tray menu", {}, {}, -1);
            return;
        }
        POINT cursor{};
        GetCursorPos(&cursor);
        SetForegroundWindow(hwnd);
        const UINT command = static_cast<UINT>(TrackPopupMenu(menu,
            TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, cursor.x, cursor.y, 0, hwnd, nullptr));
        DestroyMenu(menu);
        // Let the shell dismiss the menu properly when the user clicks elsewhere.
        PostMessageW(hwnd, WM_NULL, 0, 0);
        if (command == tray_show_command) {
            show_logs(hwnd);
        } else if (command == tray_exit_command && !exit_requested && exit_handler) {
            exit_requested = true;
            write(LogLevel::info, "Tray Exit selected; shutting down the MCP server", {}, {}, -1);
            exit_handler();
        } else if (command == 0 && tray_present) {
            Shell_NotifyIconW(NIM_SETFOCUS, &tray);
        }
    }

    static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) noexcept {
        auto* self = reinterpret_cast<Impl*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<Impl*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(hwnd, message, wp, lp);
        try {
            if (self->taskbar_created != 0 && message == self->taskbar_created) {
                // Explorer discarded all notification icons; register this process again.
                self->tray_present = false;
                if (!self->add_tray_icon(hwnd)) {
                    self->report_tray_failure();
                    if (!IsWindowVisible(hwnd)) ShowWindow(hwnd, SW_SHOWMINNOACTIVE);
                }
                return 0;
            }
            switch (message) {
            case WM_CLOSE:
                if (self->add_tray_icon(hwnd)) ShowWindow(hwnd, SW_HIDE);
                else {
                    self->report_tray_failure();
                    ShowWindow(hwnd, SW_SHOWMINNOACTIVE);
                }
                return 0;
            case tray_callback:
                if (HIWORD(lp) == self->tray.uID) {
                    const UINT event = LOWORD(lp);
                    if (event == WM_CONTEXTMENU) self->show_tray_menu(hwnd);
                    else if (event == WM_LBUTTONDBLCLK || event == NIN_SELECT || event == NIN_KEYSELECT)
                        self->show_logs(hwnd);
                }
                return 0;
            case WM_SIZE:
                if (self->editor) {
                    RECT area{};
                    GetClientRect(hwnd, &area);
                    MoveWindow(self->editor, 0, 0, area.right, area.bottom, TRUE);
                }
                return 0;
            case WM_TIMER:
                if (wp == 1) {
                    if (self->stopping.load()) {
                        DestroyWindow(hwnd);
                        return 0;
                    }
                    // Retry cancellation if Exit arrived just before stdin began waiting.
                    // The callback only interrupts the protected input-read section.
                    if (self->exit_requested && self->exit_handler) self->exit_handler();
                    self->drain();
                }
                return 0;
            case WM_DESTROY:
                self->remove_tray_icon();
                KillTimer(hwnd, 1);
                self->editor = nullptr;
                self->window = nullptr;
                PostQuitMessage(0);
                return 0;
            }
        } catch (...) {
            self->accepting.store(false);
            std::fprintf(stderr, "shgrep: log window update failed; MCP server continues\n");
            DestroyWindow(hwnd);
            return 0;
        }
        return DefWindowProcW(hwnd, message, wp, lp);
    }

    void run() noexcept {
        HMODULE rich_edit = nullptr;
        const HINSTANCE instance = GetModuleHandleW(nullptr);
        bool registered = false;
        try {
            taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
            if (taskbar_created == 0)
                std::fprintf(stderr, "shgrep: cannot register the Explorer restart notification for the tray icon\n");
            rich_edit = LoadLibraryW(L"Msftedit.dll");
            if (!rich_edit) throw std::runtime_error("cannot load the Windows Rich Edit control");
            WNDCLASSEXW cls{};
            cls.cbSize = sizeof(cls);
            cls.lpfnWndProc = window_proc;
            cls.hInstance = instance;
            cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
            cls.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
            cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
            cls.lpszClassName = window_class;
            registered = RegisterClassExW(&cls) != 0;
            if (!registered) throw std::runtime_error("cannot register the log window class");
            const std::wstring title = L"shgrep Logs (PID " + std::to_wstring(GetCurrentProcessId()) + L")";
            window = CreateWindowExW(WS_EX_APPWINDOW, window_class, title.c_str(), WS_OVERLAPPEDWINDOW,
                                     CW_USEDEFAULT, CW_USEDEFAULT, 900, 600, nullptr, nullptr, instance, this);
            if (!window) throw std::runtime_error("cannot create the log window");
            editor = CreateWindowExW(WS_EX_CLIENTEDGE, L"RICHEDIT50W", L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY | ES_NOHIDESEL,
                0, 0, 0, 0, window, nullptr, instance, nullptr);
            if (!editor) throw std::runtime_error("cannot create the log text control");
            SendMessageW(editor, EM_SETTEXTMODE, TM_RICHTEXT, 0);
            SendMessageW(editor, EM_EXLIMITTEXT, 0, max_display_chars);
            SendMessageW(editor, EM_SETBKGNDCOLOR, 0, RGB(255, 255, 255));
            SendMessageW(editor, EM_SETUNDOLIMIT, 0, 0);
            HDC dc = GetDC(window);
            const int dpi = dc ? GetDeviceCaps(dc, LOGPIXELSY) : 96;
            if (dc) ReleaseDC(window, dc);
            font = CreateFontW(-MulDiv(10, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                FIXED_PITCH | FF_MODERN, L"Consolas");
            SendMessageW(editor, WM_SETFONT,
                reinterpret_cast<WPARAM>(font ? font : reinterpret_cast<HFONT>(GetStockObject(ANSI_FIXED_FONT))), FALSE);
            RECT area{};
            GetClientRect(window, &area);
            MoveWindow(editor, 0, 0, area.right, area.bottom, TRUE);
            if (!SetTimer(window, 1, 100, nullptr)) throw std::runtime_error("cannot start the log window timer");
            if (!add_tray_icon(window)) report_tray_failure();
            if (!stopping.load()) ShowWindow(window, SW_SHOWMINNOACTIVE);
            MSG message{};
            int status;
            while ((status = GetMessageW(&message, nullptr, 0, 0)) > 0) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            if (status == -1) throw std::runtime_error("log window message loop failed");
        } catch (const std::exception& e) {
            std::fprintf(stderr, "shgrep: log window unavailable: %s; MCP server continues\n", e.what());
        } catch (...) {
            std::fprintf(stderr, "shgrep: log window unavailable; MCP server continues\n");
        }
        accepting.store(false);
        remove_tray_icon();
        if (window) DestroyWindow(window);
        if (font) DeleteObject(font);
        if (registered) UnregisterClassW(window_class, instance);
        if (rich_edit) FreeLibrary(rich_edit);
    }
};

LogWindow::LogWindow(bool enabled, std::move_only_function<void()> exit_handler) noexcept {
    if (enabled) {
        try { impl_ = std::make_unique<Impl>(std::move(exit_handler)); }
        catch (...) { std::fprintf(stderr, "shgrep: cannot start log window; MCP server continues\n"); }
    }
}

LogWindow::~LogWindow() = default;

void LogWindow::write(LogLevel level, std::string_view message, std::string_view tool,
                      std::string_view request_id, int64_t elapsed_ms) noexcept {
    if (impl_) impl_->write(level, message, tool, request_id, elapsed_ms);
}

void LogWindow::write_payload(LogLevel level, std::string_view label, const Json& value,
                              std::string_view tool, std::string_view request_id) noexcept {
    if (!impl_ || !impl_->accepting.load() || impl_->stopping.load()) return;
    try {
        const std::string payload = value.dump();
        impl_->write(level, payload, tool, request_id, -1, label);
    } catch (...) {
        write(LogLevel::error, "Could not serialize full log payload", tool, request_id);
    }
}
}
