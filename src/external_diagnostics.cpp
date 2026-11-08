#include "external_diagnostics.hpp"
#include "files.hpp"
#include "process.hpp"
#include <windows.h>
#include <algorithm>
#include <charconv>
#include <regex>
#include <sstream>
#include <stdexcept>

namespace shgrep {
namespace {
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
using J = Json;

std::string text(const J& value, const char* key, const std::string& fallback = {}) {
    const J* found = value.get(key);
    return found ? found->string() : fallback;
}
std::string path_text(const fs::path& path) {
    auto value = path.wstring();
    if (value.starts_with(L"\\\\?\\UNC\\")) value = L"\\\\" + value.substr(8);
    else if (value.starts_with(L"\\\\?\\")) value.erase(0, 4);
    const auto encoded = fs::path(value).generic_u8string();
    return std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size());
}
fs::path path_from_utf8(const std::string& value) {
    return fs::path(std::u8string(reinterpret_cast<const char8_t*>(value.data()), value.size()));
}
int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}
std::string expand_command_token(std::string_view value, const std::string& root, const std::string& path) {
    std::string result;
    for (size_t position = 0; position < value.size();) {
        if (value.substr(position).starts_with("{root}")) {
            result += root;
            position += 6;
        } else if (value.substr(position).starts_with("{path}")) {
            result += path;
            position += 6;
        } else result += value[position++];
    }
    return result;
}
// Preserve valid UTF-8; decode legacy Windows compiler output using the current system code page.
std::string output_utf8(const std::string& bytes, std::string& encoding) {
    encoding = "utf-8";
    if (bytes.empty()) return {};
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0))
        return bytes;
    encoding = "system-codepage-fallback";
    const int count = MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (!count) throw std::runtime_error("cannot decode compiler output");
    std::wstring wide(static_cast<size_t>(count), L'\0');
    if (!MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), wide.data(), count))
        throw std::runtime_error("cannot decode compiler output");
    const int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), count, nullptr, 0, nullptr, nullptr);
    if (!size) throw std::runtime_error("cannot encode compiler output as UTF-8");
    std::string result(static_cast<size_t>(size), '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, wide.data(), count, result.data(), size, nullptr, nullptr))
        throw std::runtime_error("cannot encode compiler output as UTF-8");
    return result;
}
int64_t line_number(const std::string& value) {
    int64_t number = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && number > 0 ? number : 0;
}
void truncate_utf8(std::string& value, size_t limit) {
    if (value.size() <= limit) return;
    while (limit > 0 && (static_cast<unsigned char>(value[limit]) & 0xc0) == 0x80) --limit;
    value.resize(limit);
}
std::string parse_line(std::string_view line) {
    std::string result;
    for (size_t i = 0; i < line.size();) {
        if (line[i] == '\x1b' && i + 1 < line.size() && line[i + 1] == '[') {
            i += 2;
            while (i < line.size()) {
                const auto c = static_cast<unsigned char>(line[i++]);
                if (c >= 0x40 && c <= 0x7e) break;
            }
        } else result += line[i++];
    }
    const size_t first = result.find_first_not_of(" \t");
    if (first != std::string::npos) {
        size_t digit = first;
        while (digit < result.size() && result[digit] >= '0' && result[digit] <= '9') ++digit;
        if (digit > first && digit < result.size() && result[digit] == '>') result.erase(0, digit + 1);
    }
    return result;
}
J::Array parse_diagnostics(const std::string& output, const std::string& kind, const fs::path& directory,
                          int64_t maximum_severity, bool failed, const std::function<bool()>& out_of_time,
                          bool& interrupted) {
    // out_of_time() may throw (cancellation); true stops parsing and keeps the items found so far.
    interrupted = false;
    static const std::regex gcc(R"(^\s*(.+):([0-9]+):([0-9]+):\s*(fatal error|error|warning|note):\s*(.*)$)");
    static const std::regex gcc_line(R"(^\s*(.+):([0-9]+):\s*(fatal error|error|warning|note):\s*(.*)$)");
    static const std::regex msvc(R"(^\s*(.+)\(([0-9]+)(?:,([0-9]+))?\)\s*:\s*(fatal error|error|warning|note)\s*([A-Za-z][0-9]+)?\s*:\s*(.*)$)");
    static const std::regex cmake(R"(^\s*CMake (Error|Warning)(?: at | in )(.+?)(?::([0-9]+))?(?: \([^)]*\))?:\s*(.*)$)");
    static const std::regex linker(R"(^.*\b(fatal error|error)\s+(LNK[0-9]+):\s*(.*)$)");
    static const std::regex general(R"(^\s*(?:.+?:\s*)?(fatal error|error|warning|Error|Warning):\s*(.*)$)");
    J::Array result;
    std::istringstream lines(output);
    std::string line;
    while (result.size() < 200 && std::getline(lines, line)) {
        if (out_of_time()) {
            interrupted = true;
            break;
        }
        line = parse_line(line);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const size_t start = line.find_first_not_of(" \t");
        if (start != std::string::npos) {
            size_t end = start;
            while (end < line.size() && line[end] >= '0' && line[end] <= '9') ++end;
            while (end < line.size() && (line[end] == ' ' || line[end] == '\t')) ++end;
            if (line[start] == '|' || (end > start && end < line.size() && line[end] == '|')) continue;
        }
        // Keep raw output intact; bound regex work and individual parsed messages.
        truncate_utf8(line, 8192);
        std::smatch match;
        std::string file, message, category, code;
        int64_t first = 0, column = 0;
        bool located = false;
        if (std::regex_match(line, match, gcc) || std::regex_match(line, match, msvc)) {
            const bool microsoft = match.size() == 7;
            file = match[1]; first = line_number(match[2]); column = line_number(match[3]);
            category = match[4]; message = match[microsoft ? 6 : 5];
            if (microsoft) code = match[5];
            located = true;
        } else if (std::regex_match(line, match, gcc_line)) {
            file = match[1]; first = line_number(match[2]); category = match[3]; message = match[4];
            located = true;
        } else if (std::regex_match(line, match, cmake)) {
            category = match[1] == "Warning" ? "warning" : "error";
            file = match[2]; first = line_number(match[3]); message = match[4];
            located = true;
        } else if (std::regex_match(line, match, linker)) {
            category = match[1]; code = match[2]; message = match[3];
        } else if (std::regex_match(line, match, general)) {
            category = match[1] == "Warning" ? "warning" : match[1].str();
            message = match[2];
        } else if (line.find("undefined reference") != std::string::npos ||
                   line.find("undefined symbol:") != std::string::npos ||
                   (line.find("ld.exe:") != std::string::npos && line.find("error:") != std::string::npos)) {
            category = "error"; message = line;
        } else continue;
        const int64_t severity = category == "warning" ? 2 : category == "note" ? 3 : 1;
        if (severity > maximum_severity) continue;
        if (message.empty()) message = category + " (see captured output for the following message)";
        truncate_utf8(message, 2048);
        J::Object item{{"severity", severity}, {"message", message}, {"source", kind}};
        if (!code.empty()) item.emplace("code", code);
        if (located) {
            auto path = path_from_utf8(file);
            if (!path.is_absolute()) path = directory / path;
            item.emplace("path", path_text(path.lexically_normal()));
            if (first > 0) item.emplace("line", first);
            if (column > 0) item.emplace("column", column);
            // Compiler columns can count bytes or display cells; never label these as LSP UTF-16 ranges.
            item.emplace("position_encoding", "compiler");
            item.emplace("coordinate_base", 1);
        }
        result.emplace_back(std::move(item));
    }
    if (failed && std::none_of(result.begin(), result.end(), [](const J& item) {
            return item.get("severity")->integer() == 1;
        })) {
        if (result.size() >= 200) result.pop_back();
        result.emplace_back(J::Object{{"severity", 1}, {"source", kind},
            {"message", "Command failed; see exit_code, error and output for the actual compiler/build failure."}});
    }
    return result;
}
}

Json external_diagnostics(const std::string& kind, const Json& arguments, const SearchContext& context,
    Clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (kind != "compiler" && kind != "build") throw std::runtime_error("unknown external diagnostic check");
    if (context.read_only) throw std::runtime_error("external commands are disabled by --read-only");
    const auto check = [&] {
        if (cancelled && cancelled->load()) throw std::runtime_error("external check cancelled");
        if (Clock::now() >= deadline) throw std::runtime_error("external check request timed out");
    };
    check();
    const int64_t severity = arguments.get("severity") ? arguments.get("severity")->integer() : 4;
    if (severity < 1 || severity > 4) throw std::runtime_error("severity must be 1-4");
    bool directory = false;
    const auto scope = source_descriptor(context, text(arguments, "path", "."), &directory);
    J::Object report{{"source", kind}, {"status", "unconfigured"}, {"successful", false},
        {"exit_code", nullptr}, {"items", J::Array{}}, {"started_at_unix_ms", nullptr},
        {"completed_at_unix_ms", nullptr}, {"completed_after_edit", nullptr},
        {"path", path_text(scope.path)}, {"output", ""}, {"output_truncated", false}};
    bool ran = false;  // the command's output is in the report
    try {
        const fs::path config_path = scope.root / L".shgrep" / L"checks.json";
        bool config_exists = false;
        source_descriptor(context, path_text(config_path), nullptr, true, &config_exists);
        if (!config_exists) {
            report.emplace("error", "Configure this check in .shgrep/checks.json; no command was run.");
            return report;
        }
        std::error_code size_error;
        const auto config_size = fs::file_size(config_path, size_error);
        if (size_error || config_size > 65536)
            throw std::runtime_error("checks.json must be a readable file of at most 64 KiB");
        const auto config_source = read_source_text(context, path_text(config_path));
        const J config = J::parse(config_source.text);
        (void)config.object();
        const J* setting = config.get(kind);
        if (!setting) {
            report.emplace("error", "No " + kind + " command is configured in .shgrep/checks.json.");
            return report;
        }
        (void)setting->object();
        for (const auto& [key, value] : setting->object()) {
            (void)value;
            if (key != "command" && key != "cwd") throw std::runtime_error("unknown external check setting: " + key);
        }
        const J* command = setting->get("command");
        if (!command || command->array().empty() || command->array().size() > 256)
            throw std::runtime_error("external command must be an array of 1-256 strings");
        if (kind == "compiler" && directory)
            throw std::runtime_error("compiler check requires one file path");
        fs::path cwd = path_from_utf8(text(*setting, "cwd", "."));
        if (!cwd.is_absolute()) cwd = scope.root / cwd;
        bool cwd_directory = false;
        const auto validated_cwd = source_descriptor(context, path_text(cwd), &cwd_directory);
        if (!cwd_directory || validated_cwd.root != scope.root)
            throw std::runtime_error("external check cwd must be a directory within the selected configured root");
        cwd = path_from_utf8(path_text(validated_cwd.path));
        std::vector<std::string> command_arguments;
        bool uses_file = false;
        for (const auto& token : command->array()) {
            auto value = token.string();
            uses_file = uses_file || value.find("{path}") != std::string::npos;
            command_arguments.push_back(expand_command_token(value, path_text(scope.root), path_text(scope.path)));
        }
        if (kind == "compiler" && !uses_file)
            throw std::runtime_error("compiler command must contain {path} for the requested source file");
        std::optional<SourceText> before;
        if (kind == "compiler") before = read_source_text(context, path_text(scope.path));
        check();
        const auto started = now_ms();
        const auto captured = capture_process(command_arguments, cwd, deadline, cancelled);
        if (captured.started) {
            report["started_at_unix_ms"] = started;
            report["completed_at_unix_ms"] = now_ms();
        }
        report["status"] = captured.status;
        report["exit_code"] = captured.exit_code ? J(static_cast<uint64_t>(*captured.exit_code)) : J(nullptr);
        report["successful"] = captured.status == "completed" && captured.exit_code && *captured.exit_code == 0;
        report["output_truncated"] = captured.truncated;
        report["cwd"] = path_text(cwd);
        report["configuration_sha256"] = config_source.sha256;
        std::string encoding;
        const auto output = output_utf8(captured.output, encoding);
        report["output"] = output;
        report["output_encoding"] = encoding;
        if (!captured.error.empty()) report["error"] = captured.error;
        // The command may have used the whole request deadline (status timed_out); its captured output is still the
        // answer. Parsing gets a short allowance of its own and stops early rather than discarding the report.
        ran = true;
        const auto parse_deadline = Clock::now() + std::chrono::milliseconds(2000);
        bool parse_interrupted = false;
        report["items"] = parse_diagnostics(output, kind, cwd, severity,
            captured.status != "completed" || !captured.exit_code || *captured.exit_code != 0,
            [&] {
                if (cancelled && cancelled->load()) throw std::runtime_error("external check cancelled");
                return Clock::now() >= parse_deadline;
            }, parse_interrupted);
        report["items_truncated"] = parse_interrupted || report.at("items").array().size() >= 200;
        if (parse_interrupted)
            report["items_note"] = "parsing stopped at its time allowance; the full captured text is in output";
        if (report.at("items_truncated").boolean() || captured.truncated ||
            std::any_of(report.at("items").array().begin(), report.at("items").array().end(),
                [](const J& item) { return item.get("severity")->integer() == 1; }))
            report["successful"] = false;
        if (before) {
            std::optional<SourceText> after;
            try {
                after = read_source_text(context, path_text(scope.path));
            } catch (const std::exception& e) {
                if (cancelled && cancelled->load()) throw;
                // Past the deadline the reread can fail; the captured result is kept, marked unverified.
                report["sha256"] = before->sha256;
                report["completed_after_edit"] = false;
                report["error"] = (captured.error.empty() ? std::string() : captured.error + "; ") +
                                  "cannot reread the source after the check (" + e.what() + "), so it may be stale";
                return report;
            }
            const bool unchanged = before->sha256 == after->sha256;
            report["sha256"] = before->sha256;
            report["completed_after_edit"] = unchanged && captured.exit_code.has_value() &&
                (captured.status == "completed" || captured.status == "failed") && captured.error.empty();
            if (!unchanged) {
                report["status"] = "stale";
                report["successful"] = false;
                report["error"] = "source changed during compiler check; the captured result is retained but is stale";
            }
        }
        return report;
    } catch (const std::exception& error) {
        // Once the command ran, its report is returned even past the deadline; only cancellation discards it.
        if ((cancelled && cancelled->load()) || (!ran && Clock::now() >= deadline)) throw;
        report["status"] = "error";
        report["successful"] = false;
        report["error"] = error.what();
        return report;
    }
}
}
