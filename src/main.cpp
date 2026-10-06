#include "json.hpp"
#include "cli.hpp"
#include "search.hpp"

#include <windows.h>
#include <fcntl.h>
#include <io.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace {
using shgrep::Json;
std::mutex output_mutex;
void send(const Json& message) {
    std::string line = message.dump() + "\n";
    std::lock_guard lock(output_mutex);
    std::fwrite(line.data(), 1, line.size(), stdout);
    std::fflush(stdout);
}
Json error(const Json& id, int code, const std::string& message) {
    return Json::Object{{"jsonrpc", "2.0"}, {"id", id},
                        {"error", Json::Object{{"code", code}, {"message", message}}}};
}
Json success(const Json& id, Json result) {
    return Json::Object{{"jsonrpc", "2.0"}, {"id", id}, {"result", std::move(result)}};
}
Json tool_response(const Json& id, Json& result, uint32_t max_bytes) {
    // CONTRACT: text output (lines/files/count) is sent as-is so agents read grep-style lines, not JSON.
    if (const Json* text = result.get("text")) {
        std::string core = text->string(), marker;
        for (;;) {
            Json response = success(id, Json::Object{{"content", Json::Array{Json::Object{{"type", "text"}, {"text", core + marker}}}}});
            if (response.dump().size() <= max_bytes) return response;
            if (core.empty()) throw std::runtime_error("max_output_bytes cannot hold MCP response");
            size_t cut = core.size() >= 2 ? core.rfind('\n', core.size() - 2) : std::string::npos;
            core.resize(cut == std::string::npos ? 0 : cut + 1);
            marker = "[status output_limit: response cut at max_output_bytes; more results may exist.]\n";
        }
    }
    for (;;) {
        Json response = success(id, Json::Object{{"content", Json::Array{Json::Object{{"type", "text"}, {"text", result.dump()}}}}});
        if (response.dump().size() <= max_bytes) return response;
        auto& object = std::get<Json::Object>(result.value);
        auto& items = std::get<Json::Array>(object.at("results").value);
        if (items.empty()) throw std::runtime_error("max_output_bytes cannot hold MCP response");
        items.pop_back();
        auto& summary = std::get<Json::Object>(object.at("summary").value);
        summary["matches_returned"] = static_cast<uint64_t>(items.size());
        summary["truncated"] = true;
        if (summary.at("status").string() == "complete") summary["status"] = "output_limit";
    }
}
Json tool_error_response(const Json& id, std::string message, uint32_t max_bytes) {
    if (message.size() > 1024) message.resize(1024);
    for (;;) {
        while (!message.empty() && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
               message.data(), static_cast<int>(message.size()), nullptr, 0)) message.pop_back();
        Json response = success(id, Json::Object{{"isError", true},
            {"content", Json::Array{Json::Object{{"type", "text"}, {"text", message}}}}});
        if (response.dump().size() <= max_bytes || message.empty()) return response;
        message.resize(message.size() / 2);
    }
}
std::string request_key(const Json& id) { return id.dump(); }
bool read_line(std::string& line) {
    line.clear();
    bool oversized = false;
    for (;;) {
        int c = std::getc(stdin);
        if (c == EOF) return !line.empty() || oversized;
        if (c == '\n') {
            if (oversized) line.clear();
            return true;
        }
        if (line.size() < 1048576) line.push_back(static_cast<char>(c));
        else oversized = true;
    }
}
}

int wmain(int argc, wchar_t** argv) {
    DWORD console_mode = 0;
    if (argc == 1 && GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &console_mode))
        return shgrep::run_cli(argc, argv);
    if (argc > 1 && std::wstring(argv[1]) != L"--root") return shgrep::run_cli(argc, argv);
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    shgrep::SearchContext context;
    for (int i = 1; i < argc; ++i) {
        if (std::wstring(argv[i]) == L"--root" && i + 1 < argc) context.allowed_roots.emplace_back(argv[++i]);
        else { std::fprintf(stderr, "usage: shgrep [--root DIRECTORY]... for MCP; shgrep --help for CLI\n"); return 2; }
    }
    if (context.allowed_roots.empty()) context.allowed_roots.push_back(std::filesystem::current_path());
    std::mutex active_mutex;
    std::map<std::string, std::shared_ptr<std::atomic_bool>> active;
    std::vector<std::future<void>> tasks;
    std::string line;
    while (read_line(line)) {
        for (auto it = tasks.begin(); it != tasks.end();) {
            if (it->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                try { it->get(); } catch (const std::exception& e) { std::fprintf(stderr, "worker: %s\n", e.what()); }
                it = tasks.erase(it);
            } else ++it;
        }
        if (line.empty()) { send(error(nullptr, -32700, "invalid or oversized JSON message")); continue; }
        Json request;
        try { request = Json::parse(line); }
        catch (const std::exception& e) { send(error(nullptr, -32700, e.what())); continue; }
        const Json* id_ptr = request.get("id");
        Json id = id_ptr ? *id_ptr : Json(nullptr);
        bool has_id = id_ptr && !std::holds_alternative<std::nullptr_t>(id_ptr->value);
        try {
            const Json* version = request.get("jsonrpc");
            const Json* method = request.get("method");
            if (!version || !std::holds_alternative<std::string>(version->value) || version->string() != "2.0" ||
                !method || !std::holds_alternative<std::string>(method->value)) {
                send(error(id, -32600, "invalid JSON-RPC request")); continue;
            }
            if (id_ptr && !std::holds_alternative<std::string>(id_ptr->value) &&
                !std::holds_alternative<int64_t>(id_ptr->value) &&
                !std::holds_alternative<std::nullptr_t>(id_ptr->value)) {
                send(error(nullptr, -32600, "invalid JSON-RPC id")); continue;
            }
            if (id_ptr && id_ptr->dump().size() > 256) { send(error(nullptr, -32600, "JSON-RPC id is too long")); continue; }
            const std::string& name = method->string();
            if (name == "notifications/cancelled") {
                const Json* params = request.get("params");
                const Json* target = params ? params->get("requestId") : nullptr;
                if (target) {
                    std::lock_guard lock(active_mutex);
                    auto it = active.find(request_key(*target));
                    if (it != active.end()) it->second->store(true);
                }
                continue;
            }
            if (!has_id) continue;
            if (name == "initialize") {
                const Json* params = request.get("params");
                const Json* wanted = params ? params->get("protocolVersion") : nullptr;
                std::string protocol = "2025-06-18";
                if (wanted && std::holds_alternative<std::string>(wanted->value)) {
                    if (wanted->string() == "2024-11-05" || wanted->string() == "2025-03-26" || wanted->string() == "2025-06-18")
                        protocol = wanted->string();
                }
                send(success(id, Json::Object{{"protocolVersion", protocol},
                                              {"capabilities", Json::Object{{"tools", Json::Object{}}}},
                                              {"serverInfo", Json::Object{{"name", "shgrep"}, {"version", "0.1.0"}}}}));
            } else if (name == "ping") send(success(id, Json::Object{}));
            else if (name == "tools/list") send(success(id, Json::Object{{"tools", shgrep::tool_definitions()}}));
            else if (name == "tools/call") {
                const Json* params = request.get("params");
                if (!params || !params->get("name")) { send(error(id, -32602, "tool name required")); continue; }
                std::string tool_name = params->get("name")->string();
                if (tool_name != "search" && tool_name != "search_bytes" && tool_name != "find_files") {
                    send(error(id, -32602, "unknown tool")); continue;
                }
                Json arguments = params->get("arguments") ? *params->get("arguments") : Json::Object{};
                auto flag = std::make_shared<std::atomic_bool>(false);
                std::string key = request_key(id);
                {
                    std::lock_guard lock(active_mutex);
                    if (active.size() >= 4) { send(error(id, -32000, "server busy")); continue; }
                    if (active.contains(key)) { send(error(id, -32600, "duplicate request id")); continue; }
                    active.emplace(key, flag);
                }
                try { tasks.push_back(std::async(std::launch::async, [&, id, tool_name, arguments, flag, key] {
                    uint32_t max_bytes = 65536;
                    try {
                        if (const Json* limit = arguments.get("max_output_bytes")) {
                            int64_t requested = limit->integer();
                            if (requested >= 512 && requested <= 1048576) max_bytes = static_cast<uint32_t>(requested);
                        }
                        Json result = shgrep::run_tool(tool_name, arguments, context, flag);
                        send(tool_response(id, result, max_bytes));
                    } catch (const std::exception& e) {
                        send(tool_error_response(id, e.what(), max_bytes));
                    }
                    std::lock_guard lock(active_mutex);
                    active.erase(key);
                })); }
                catch (...) {
                    std::lock_guard lock(active_mutex);
                    active.erase(key);
                    throw;
                }
            } else send(error(id, -32601, "method not found"));
        } catch (const std::exception& e) {
            send(error(id, -32602, e.what()));
        }
    }
    {
        std::lock_guard lock(active_mutex);
        for (auto& [_, flag] : active) flag->store(true);
    }
    for (auto& task : tasks) {
        try { task.get(); } catch (const std::exception& e) { std::fprintf(stderr, "worker: %s\n", e.what()); }
    }
    return 0;
}
