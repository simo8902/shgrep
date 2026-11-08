#include "lsp.hpp"
#include "external_diagnostics.hpp"
#include "thread_safety.hpp"
#include "edit.hpp"
#include "banner.hpp"
#include "compile_db.hpp"
#include "dotnet_projects.hpp"
#include "ignore.hpp"
#include "lsp_watch.hpp"
#include "process.hpp"
#include "workspace_profile.hpp"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <algorithm>
#include <array>
#include <string_view>
#include <list>
#include <unordered_map>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <climits>
#include <compare>
#include <deque>
#include <functional>
#include <cwctype>
#include <limits>
#include <map>
#include <fstream>
#include <future>
#include <iterator>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <stop_token>
#include <thread>
#include <tuple>
#include <utility>

namespace shgrep {
namespace {
using Clock = std::chrono::steady_clock;
namespace fs = std::filesystem;
using J = Json;
class RejectedLspRequest : public std::runtime_error {
public:
    bool fallback_eligible;
    explicit RejectedLspRequest(const std::string& message, bool fallback = false)
        : std::runtime_error(message), fallback_eligible(fallback) {}
};
[[noreturn]] void reject_request(const std::string& message, bool fallback = false) {
    throw RejectedLspRequest(message, fallback);
}
[[noreturn]] void fail(const std::string& s) { throw std::runtime_error(s); }
// A server position that does not fit the file's text: the server counts lines or columns differently from the LSP
//   rule shgrep follows (\n, \r\n and a lone \r each end a line). That file's answer is unusable, but the server is
//   healthy, so it is not restarted and a folder walk skips just that file and reports it.
class PositionMismatch : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
// A malformed answer from the language server, or no server for the request, as opposed to a caller mistake;
//   callers turn it into the failure banner.
[[noreturn]] void server_fail(const std::string& s) { throw LspFailure(s); }
// Field reads shared by requests and server answers. Language servers send null for absent optional fields
// (containerName, detail, version), so null reads as missing; any other wrong type names the field.
std::string str(const J& j, const char* key, const std::string& fallback = "") {
    const J* p = j.get(key);
    if (!p || std::holds_alternative<std::nullptr_t>(p->value)) return fallback;
    if (const auto* text = std::get_if<std::string>(&p->value)) return *text;
    throw std::runtime_error(std::string("field \"") + key + "\" must be a string");
}
bool flag(const J& j, const char* key, bool fallback = false) {
    const J* p = j.get(key);
    if (!p || std::holds_alternative<std::nullptr_t>(p->value)) return fallback;
    if (const auto* value = std::get_if<bool>(&p->value)) return *value;
    if (const auto* text = std::get_if<std::string>(&p->value); text && (*text == "true" || *text == "false"))
        return *text == "true";
    throw std::runtime_error(std::string("field \"") + key + "\" must be true or false");
}
int64_t number(const J& j, const char* key, int64_t fallback) {
    const J* p = j.get(key);
    if (!p || std::holds_alternative<std::nullptr_t>(p->value)) return fallback;
    try { return p->integer(); }
    catch (const std::exception&) {}
    throw std::runtime_error(std::string("field \"") + key + "\" must be an integer");
}
std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    if (s.size() > INT_MAX) fail("UTF-8 text is too large");
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (!n) fail("invalid UTF-8");
    std::wstring out(static_cast<size_t>(n), 0);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}
std::string utf8(const std::wstring& s) {
    if (s.empty()) return {};
    if (s.size() > INT_MAX) fail("UTF-16 text is too large");
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (!n) fail("invalid UTF-16");
    std::string out(static_cast<size_t>(n), 0);
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}
std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
std::string uri(const fs::path& path) {
    std::wstring native = path.wstring();
    if (native.starts_with(L"\\\\?\\UNC\\")) native = L"\\\\" + native.substr(8);
    else if (native.starts_with(L"\\\\?\\")) native.erase(0, 4);
    std::replace(native.begin(), native.end(), L'\\', L'/');
    std::string s = utf8(native), out;
    constexpr char hex[] = "0123456789ABCDEF";
    if (s.starts_with("//")) { out = "file:"; } else { out = "file:///"; }
    for (unsigned char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '/' || c == ':' || c == '-' || c == '_' || c == '.' || c == '~') out.push_back(static_cast<char>(c));
        else { out.push_back('%'); out.push_back(hex[c >> 4]); out.push_back(hex[c & 15]); }
    }
    return out;
}
fs::path from_uri(const std::string& value) {
    if (!value.starts_with("file://")) server_fail("language server returned a non-file URI");
    std::string body = value.substr(7), decoded;
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < body.size(); ++i) {
        if (body[i] == '%') {
            if (i + 2 >= body.size() || digit(body[i + 1]) < 0 || digit(body[i + 2]) < 0) fail("invalid file URI");
            const char c = static_cast<char>(digit(body[i + 1]) * 16 + digit(body[i + 2]));
            if (!c) fail("NUL in file URI");
            decoded.push_back(c); i += 2;
        } else decoded.push_back(body[i]);
    }
    if (decoded.starts_with("/") && decoded.size() >= 3 && decoded[2] == ':') decoded.erase(0, 1);
    else if (!decoded.starts_with("/")) decoded = "//" + decoded;
    return fs::path(wide(decoded));
}
std::wstring quoted(const std::wstring& s) {
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : s) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'"') { out.append(slashes * 2 + 1, L'\\'); out.push_back(c); }
        else { out.append(slashes, L'\\'); out.push_back(c); }
        slashes = 0;
    }
    out.append(slashes * 2, L'\\'); out.push_back(L'"'); return out;
}
struct Control {
    Clock::time_point deadline;
    const std::shared_ptr<std::atomic_bool>& cancelled;
    void check() const {
        if (cancelled && cancelled->load()) fail("LSP request cancelled");
        if (Clock::now() >= deadline) throw LspTimeoutFailure("language server did not answer before timeout_ms");
    }
};
struct Handle {
    HANDLE h = nullptr;
    Handle() = default;
    explicit Handle(HANDLE value) : h(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    void reset(HANDLE value = nullptr) {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = value;
    }
};
struct PathLess {
    bool operator()(const std::wstring& a, const std::wstring& b) const {
        return CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(), static_cast<int>(b.size()), TRUE) == CSTR_LESS_THAN;
    }
};
struct Config {
    fs::path root;
    std::string language, key, server;
    std::vector<std::string> command, extensions, ignored_paths;
    std::map<std::string, std::string> extension_languages;
    J initialization = J::Object{}, settings = J::Object{};
    std::vector<fs::path> state_directories;  // created before the server starts
    // The configured root whose .shgrep holds state_directories. root can change to another workspace root
    // (shared C# and JavaScript servers), so the state folders are checked against this one.
    fs::path state_root;
    bool bundled = false;
    // CONTRACT: the server indexes the whole workspace from disk itself. shgrep then opens only the files a request
    //   touches or that changed since the server read them, and cross-file requests wait for indexing to finish.
    //   Otherwise every matching file is opened, which servers without their own index need.
    bool indexes_workspace = false;
    J details;  // extra status, e.g. where clangd's compile flags came from
    bool managed_projects = false;
    fs::path dotnet, working_directory;
    std::vector<fs::path> workspace_roots;
    size_t project_budget = 128; // Soft budget; a required closure is never truncated.
    int64_t project_idle_ms = 300000;
    // Variables set for the server on top of shgrep's own environment (Roslyn's DOTNET_ROOT).
    std::vector<std::pair<std::wstring, std::wstring>> environment;
};

// SAFETY: offline_environment() (process.hpp) is the mandatory child environment for every process started here.

// Evaluation only: no targets, build, restore, shell, or persistent MSBuild worker.
// The job owns every child and is killed on cancellation, deadline, or any exceptional return.
J evaluate_dotnet_project(const Config& config, const fs::path& project,
                         const std::string& framework, const Control& control) {
    control.check();
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE read_handle = nullptr, write_handle = nullptr;
    if (!CreatePipe(&read_handle, &write_handle, &security, 0)) fail("cannot create MSBuild evaluation pipe");
    Handle output(read_handle), child_output(write_handle);
    if (!SetHandleInformation(output.h, HANDLE_FLAG_INHERIT, 0)) fail("cannot isolate MSBuild evaluation pipe");
    Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (input.h == INVALID_HANDLE_VALUE) fail("cannot open MSBuild evaluation input");
    Handle job(CreateJobObjectW(nullptr, nullptr));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job.h || !SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        fail("cannot isolate MSBuild evaluation process");
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<unsigned char> storage(bytes);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) fail("cannot prepare MSBuild child handles");
    HANDLE inherited[]{input.h, child_output.h};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attributes); fail("cannot isolate MSBuild child handles");
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.h;
    startup.StartupInfo.hStdOutput = startup.StartupInfo.hStdError = child_output.h;
    startup.lpAttributeList = attributes;
    const auto less = [](const std::wstring& a, const std::wstring& b) {
        return CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(), static_cast<int>(b.size()), TRUE) == CSTR_LESS_THAN;
    };
    std::map<std::wstring, std::wstring, decltype(less)> variables(less);
    wchar_t* inherited_environment = GetEnvironmentStringsW();
    if (!inherited_environment) { DeleteProcThreadAttributeList(attributes); fail("cannot read MSBuild environment"); }
    for (const wchar_t* at = inherited_environment; *at; at += wcslen(at) + 1) {
        const std::wstring entry(at);
        const size_t equals = entry.find(L'=', 1);
        if (equals != std::wstring::npos) variables[entry.substr(0, equals)] = entry.substr(equals + 1);
    }
    FreeEnvironmentStringsW(inherited_environment);
    for (const auto& [name, value] : config.environment) variables[name] = value;
    // The offline policy is mandatory, including case-insensitive configuration overrides.
    for (const auto& [name, value] : offline_environment()) variables[name] = value;
    for (const auto* name : {L"DOTNET_CLI_TELEMETRY_OPTOUT", L"DOTNET_SKIP_FIRST_TIME_EXPERIENCE",
                            L"DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE", L"DOTNET_NOLOGO", L"MSBUILDDISABLENODEREUSE"})
        variables[name] = L"1";
    variables[L"MSBuildEnableWorkloadResolver"] = L"false";
    variables[L"DOTNET_CLI_UI_LANGUAGE"] = L"en-US";
    variables[L"DOTNET_CLI_UTF8_ENCODING"] = L"1";
    std::wstring environment;
    for (const auto& [name, value] : variables) { environment += name + L"=" + value; environment.push_back(L'\0'); }
    environment.push_back(L'\0');
    std::wstring command = quoted(config.dotnet.wstring()) + L" msbuild " + quoted(project.wstring()) +
        L" -nologo -verbosity:quiet -nodeReuse:false -property:DesignTimeBuild=true -property:Configuration=Debug"
        L" -property:NuGetInteractive=false -getItem:Compile,ProjectReference"
        L" -getProperty:TargetFrameworks,MSBuildAllProjects,NETCoreSdkVersion,MSBuildToolsPath";
    if (!framework.empty()) command += L" " + quoted(L"-property:TargetFramework=" + wide(framework));
    PROCESS_INFORMATION child{};
    const BOOL created = CreateProcessW(config.dotnet.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
        environment.data(), project.parent_path().c_str(), &startup.StartupInfo, &child);
    const DWORD error = GetLastError();
    DeleteProcThreadAttributeList(attributes);
    if (!created) fail("cannot start MSBuild project evaluation (Windows error " + std::to_string(error) + ")");
    Handle process(child.hProcess), thread(child.hThread);
    if (!AssignProcessToJobObject(job.h, process.h)) {
        TerminateProcess(process.h, 1); fail("cannot assign MSBuild evaluation to its job");
    }
    if (ResumeThread(thread.h) == static_cast<DWORD>(-1)) fail("cannot resume MSBuild evaluation");
    child_output.reset(); input.reset();
    std::string captured;
    char buffer[65536];
    for (;;) {
        control.check();
        DWORD available = 0;
        if (!PeekNamedPipe(output.h, nullptr, 0, nullptr, &available, nullptr)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) break;
            fail("cannot read MSBuild evaluation output");
        }
        if (available) {
            DWORD got = 0;
            if (!ReadFile(output.h, buffer, std::min<DWORD>(available, sizeof(buffer)), &got, nullptr) || !got)
                fail("cannot read MSBuild evaluation output");
            captured.append(buffer, got);
        } else if (WaitForSingleObject(process.h, 10) == WAIT_OBJECT_0) {
            if (!PeekNamedPipe(output.h, nullptr, 0, nullptr, &available, nullptr) || !available) break;
        }
    }
    while (WaitForSingleObject(process.h, 10) == WAIT_TIMEOUT) control.check();
    DWORD exit = 1;
    if (!GetExitCodeProcess(process.h, &exit)) fail("cannot read MSBuild evaluation exit status");
    if (exit) fail("project evaluation failed for " + utf8(project.wstring()) +
        "; evaluation requires MSBuild 17.8 or newer and an installed compatible SDK; no build or restore was requested: " +
        captured.substr(0, 4096));
    // Warnings may precede the JSON on stdout. Each candidate must parse as a complete evaluation response.
    for (size_t at = captured.find('{'); at != std::string::npos; at = captured.find('{', at + 1)) {
        control.check();
        try {
            J parsed = J::parse(captured.substr(at));
            if (parsed.get("Properties") && parsed.get("Items")) return parsed;
        } catch (const std::exception&) {}
    }
    fail("MSBuild did not return evaluated project items for " + utf8(project.wstring()));
}

std::string document_language_id(const Config& config, const fs::path& path) {
    const std::string extension = language_extension(path);
    const auto language = config.extension_languages.find(extension);
    return language == config.extension_languages.end() ? config.language : language->second;
}
bool glob_match(std::string_view pattern, std::string_view value) {
    std::vector<uint8_t> prior(value.size() + 1, 0), next(value.size() + 1, 0);
    prior[0] = 1;
    for (size_t p = 0; p < pattern.size();) {
        std::fill(next.begin(), next.end(), uint8_t{0});
        if (pattern[p] == '*') {
            const bool double_star = p + 1 < pattern.size() && pattern[p + 1] == '*';
            if (double_star && p + 2 < pattern.size() && pattern[p + 2] == '/') {
                next = prior;
                uint8_t reachable = prior[0];
                for (size_t v = 0; v < value.size(); ++v) {
                    reachable = static_cast<uint8_t>(reachable || prior[v + 1]);
                    if (value[v] == '/') next[v + 1] = reachable;
                }
                p += 3;
            } else {
                next[0] = prior[0];
                for (size_t v = 0; v < value.size(); ++v)
                    next[v + 1] = static_cast<uint8_t>(prior[v + 1] ||
                        (next[v] && (double_star || value[v] != '/')));
                p += double_star ? 2 : 1;
            }
        } else {
            for (size_t v = 0; v < value.size(); ++v)
                if (prior[v] && (pattern[p] == value[v] || (pattern[p] == '?' && value[v] != '/')))
                    next[v + 1] = 1;
            ++p;
        }
        prior.swap(next);
    }
    return prior[value.size()] != 0;
}
bool ignored_pattern_matches(std::string_view pattern, std::string_view path) {
    const bool has_slash = pattern.find('/') != std::string_view::npos;
    for (size_t end = path.find('/');; end = path.find('/', end + 1)) {
        const std::string_view prefix = path.substr(0, end == std::string_view::npos ? path.size() : end);
        if (has_slash ? glob_match(pattern, prefix) : glob_match(pattern, prefix.substr(prefix.rfind('/') == std::string_view::npos ? 0 : prefix.rfind('/') + 1)))
            return true;
        if (end == std::string_view::npos) break;
    }
    return false;
}
bool path_excluded(const Config& config, const fs::path& path) {
    if (config.ignored_paths.empty()) return false;
    std::wstring root = config.root.lexically_normal().wstring();
    std::wstring full = path.lexically_normal().wstring();
    std::replace(root.begin(), root.end(), L'/', L'\\');
    std::replace(full.begin(), full.end(), L'/', L'\\');
    if (!root.ends_with(L"\\")) root += L"\\";
    if (full.size() < root.size() ||
        CompareStringOrdinal(full.data(), static_cast<int>(root.size()), root.data(), static_cast<int>(root.size()), TRUE) != CSTR_EQUAL)
        return false;
    std::string relative = lower(utf8(full.substr(root.size())));
    std::replace(relative.begin(), relative.end(), '\\', '/');
    bool ignored = false;
    for (const auto& entry : config.ignored_paths) {
        const bool negated = !entry.empty() && entry.front() == '!';
        const std::string_view pattern(entry.data() + (negated ? 1 : 0), entry.size() - (negated ? 1 : 0));
        if (ignored_pattern_matches(pattern, relative)) ignored = !negated;
    }
    return ignored;
}
// CONTRACT: tools/fetch_lsp.py installs pinned servers into <SHGREP_LSP_ROOT or shgrep.exe folder>\lsp; folders and executables match
//   its PINS. They serve every workspace with no per-workspace setup. .shgrep/lsp.json entries take over the extensions
//   they name, and "bundled": false there turns these default servers off. A server that was not installed is
//   skipped; missing_bundled names it so the text fallback for its files carries the failure banner.
struct BundledServer {
    const char* language;
    const char* name;
    const wchar_t* executable;
    std::vector<std::string> extensions;
    std::map<std::string, std::string> extension_languages;
};
const std::vector<BundledServer>& bundled_servers() {
    static const std::vector<BundledServer> servers{
        {"lua", "LuaLS", L"lua\\bin\\lua-language-server.exe", {".lua"}},
        {"xml", "LemMinX", L"xml\\lemminx.exe", {".xml", ".xsd", ".xsl", ".xslt", ".svg"}},
        {"cpp", "clangd", L"clangd\\bin\\clangd.exe", {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"}},
        {"rust", "rust-analyzer", L"rust\\rust-analyzer.exe", {".rs"}},
        {"python", "ty", L"python\\ty.exe", {".py", ".pyi"}},
        // tsserver through typescript-language-server: honors tsconfig/jsconfig projects and path aliases (Vite's @/),
        // and uses the workspace's own node_modules/typescript when present. Deno stays available through
        // .shgrep/lsp.json for Deno projects.
        {"javascript", "typescript-language-server", L"typescript\\node.exe",
         {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"},
         {{".jsx", "javascriptreact"}, {".ts", "typescript"}, {".tsx", "typescriptreact"},
          {".mts", "typescript"}, {".cts", "typescript"}}},
        {"csharp", "Roslyn", L"csharp\\roslyn\\Microsoft.CodeAnalysis.LanguageServer.exe", {".cs"}},
        // language_extension() maps CMakeLists.txt to ".cmake".
        {"cmake", "neocmakelsp", L"cmake\\neocmakelsp.exe", {".cmake"}},
    };
    return servers;
}
const BundledServer& bundled_server(std::string_view language) {
    for (const auto& server : bundled_servers()) if (server.language == language) return server;
    throw std::logic_error("unknown bundled language server");
}
// COMPAT: Roslyn runs on .NET 10 and loads projects through the SDK's
//   MSBuild, so it needs a dotnet with a 10+ runtime and an SDK. It looks in DOTNET_ROOT, then PATH; without one it
//   starts but loads no project and answers every request empty. shgrep therefore finds a usable dotnet itself
//   (DOTNET_ROOT, PATH, then %ProgramFiles%\dotnet), hands it over as DOTNET_ROOT, and reports a missing one
//   instead of starting the server. Rechecked every 30 seconds, so a fresh .NET install is picked up.
struct DotNet { fs::path root; std::string problem; };
DotNet find_dotnet() {
    static std::mutex mutex;
    static DotNet cached;
    static std::chrono::steady_clock::time_point checked{};
    std::lock_guard lock(mutex);
    const auto now = std::chrono::steady_clock::now();
    if (checked != std::chrono::steady_clock::time_point{} && now - checked < std::chrono::seconds(30)) return cached;
    std::vector<fs::path> candidates;
    std::wstring buffer(32768, L'\0');
    if (const DWORD n = GetEnvironmentVariableW(L"DOTNET_ROOT", buffer.data(), static_cast<DWORD>(buffer.size())); n && n < buffer.size())
        candidates.emplace_back(std::wstring(buffer.data(), n));
    if (const DWORD n = SearchPathW(nullptr, L"dotnet.exe", nullptr, static_cast<DWORD>(buffer.size()), buffer.data(), nullptr); n && n < buffer.size())
        candidates.push_back(fs::path(std::wstring(buffer.data(), n)).parent_path());
    if (const DWORD n = GetEnvironmentVariableW(L"ProgramFiles", buffer.data(), static_cast<DWORD>(buffer.size())); n && n < buffer.size())
        candidates.push_back(fs::path(std::wstring(buffer.data(), n)) / L"dotnet");
    std::string seen;
    DotNet result;
    for (const auto& root : candidates) {
        std::error_code error;
        if (!fs::is_regular_file(root / L"dotnet.exe", error)) continue;
        int runtime = 0;
        for (const auto& entry : fs::directory_iterator(root / L"shared" / L"Microsoft.NETCore.App", error))
            runtime = std::max(runtime, static_cast<int>(std::wcstol(entry.path().filename().c_str(), nullptr, 10)));
        bool sdk = false;
        for (const auto& entry : fs::directory_iterator(root / L"sdk", error)) if (entry.is_directory(error)) { sdk = true; break; }
        if (runtime >= 10 && sdk) { result.root = root; break; }
        if (seen.empty())
            seen = " (" + utf8(root.wstring()) + " has " + (runtime ? ".NET " + std::to_string(runtime) : std::string("no runtime")) +
                   (sdk ? "" : " and no SDK") + ")";
    }
    if (result.root.empty())
        result.problem = "needs the .NET 10 or newer SDK, and no dotnet with one was found in DOTNET_ROOT, PATH or "
                         "%ProgramFiles%\\dotnet" + seen + "; install it from https://dot.net";
    cached = result;
    checked = now;
    return result;
}
// Why the bundled server for language cannot run although it is installed; empty when nothing is missing.
std::string bundled_prerequisite(std::string_view language) {
    return language == "csharp" ? find_dotnet().problem : std::string();
}
// executable_directory() is shared through files.hpp.
const fs::path& bundled_directory() {
    static const fs::path directory = [] {
        std::wstring configured(32768, L'\0');
        const DWORD n = GetEnvironmentVariableW(L"SHGREP_LSP_ROOT", configured.data(),
                                                static_cast<DWORD>(configured.size()));
        if (n > 0 && n < configured.size()) {
            fs::path root(std::wstring(configured.data(), n));
            if (!root.is_absolute()) root = executable_directory() / root;
            return root.lexically_normal() / L"lsp";
        }
        const fs::path executable = executable_directory();
        return executable.empty() ? fs::path{} : executable / L"lsp";
    }();
    return directory;
}
// CONTRACT: fetch_lsp.py receives the parent directory and writes its servers into that directory's lsp folder.
std::string fetch_command() {
    const fs::path& base = bundled_directory();
    const fs::path module_directory = executable_directory();
    const std::string folder = base.empty() ? std::string("<folder for shared LSP servers>")
                                             : utf8(base.parent_path().wstring());
    std::string script = "<shgrep sources>\\tools\\fetch_lsp.py";
    const fs::path packaged_script = module_directory / L"tools" / L"fetch_lsp.py";
    std::error_code error;
    if (fs::is_regular_file(packaged_script, error)) script = utf8(packaged_script.wstring());
#ifdef SHGREP_SOURCE_DIR
    if (script.starts_with("<")) {
        fs::path source = fs::path(SHGREP_SOURCE_DIR) / L"tools" / L"fetch_lsp.py";
        if (fs::is_regular_file(source, error)) script = utf8(source.make_preferred().wstring());
    }
#endif
    return "python \"" + script + "\" \"" + folder + "\"";
}
// cpp_setup: false for lookups that cannot use clangd (another language, status, post-write retention checks). They
//   reuse the last prepared C++ setup and never scan, write C++ state or start a CMake configure.
void add_bundled(std::vector<Config>& result, const fs::path& root, const std::set<std::string>& owned,
                 const SearchContext& context, bool cmake_configure, const std::shared_ptr<std::atomic_bool>& cancelled,
                 bool cpp_setup) {
    const fs::path& base = bundled_directory();
    if (base.empty()) return;
    const fs::path state = root / L".shgrep" / L"lsp-state";
    auto add = [&](const BundledServer& server,
                   std::vector<std::string> arguments, J settings = J::Object{}, J initialization = J::Object{},
                   std::vector<fs::path> directories = {}, const std::string& variant = {}, J details = nullptr) {
        const fs::path executable = base / server.executable;
        std::error_code error;
        if (!fs::is_regular_file(executable, error)) return;
        std::vector<std::string> extensions = server.extensions;
        std::erase_if(extensions, [&](const std::string& ext) { return owned.contains(ext); });
        if (extensions.empty()) return;
        Config config;
        config.root = root;
        config.language = server.language;
        config.server = server.name;
        config.command.push_back(utf8(executable.wstring()));
        config.command.insert(config.command.end(), arguments.begin(), arguments.end());
        config.extensions = std::move(extensions);
        for (const auto& ext : config.extensions)
            if (const auto language = server.extension_languages.find(ext); language != server.extension_languages.end())
                config.extension_languages.emplace(*language);
        config.settings = std::move(settings);
        config.initialization = std::move(initialization);
        config.state_directories = std::move(directories);
        config.state_root = root;
        config.bundled = true;
        config.indexes_workspace = true;
        config.details = std::move(details);
        // A new variant (clangd's compile database changed) is a new key, so the old server is retired.
        config.key = lower(utf8(root.wstring())) + ":bundled:" + server.language + ":" + variant;
        for (const auto& ext : config.extensions) {
            config.key += ":" + ext;
            if (const auto language = config.extension_languages.find(ext); language != config.extension_languages.end())
                config.key += "=" + language->second;
        }
        result.push_back(std::move(config));
    };
    // COMPAT: LuaLS keeps logs and generated meta files in the folders it is given; Lua 5.1 suits the owner's
    //   game scripts, and a workspace .luarc.json still overrides it.
    const fs::path lua = state / L"lua";
    add(bundled_server("lua"),
        {"--logpath=" + utf8((lua / L"logs").wstring()), "--metapath=" + utf8((lua / L"meta").wstring())},
        J::Object{{"Lua", J::Object{{"runtime", J::Object{{"version", "Lua 5.1"}}},
                                    {"telemetry", J::Object{{"enable", false}}},
                                    {"workspace", J::Object{{"checkThirdParty", false}}}}}},
        J::Object{}, {lua / L"logs", lua / L"meta"});
    // SAFETY: LemMinX must not fetch schemas or DTDs from the network or resolve external entities.
    const fs::path xml = state / L"xml";
    const J xml_settings = J::Object{{"xml", J::Object{
        {"server", J::Object{{"workDir", utf8(xml.wstring())}}},
        {"logs", J::Object{{"file", utf8((xml / L"lemminx.log").wstring())}}},
        {"telemetry", J::Object{{"enabled", false}}},
        {"downloadExternalResources", J::Object{{"enabled", false}}},
        {"validation", J::Object{{"resolveExternalEntities", false}}}}}};
    add(bundled_server("xml"), {},
        xml_settings, J::Object{{"settings", xml_settings}}, {xml});
    // compile_db.cpp finds or generates clangd's compile flags. SHGREP_CLANGD_LOG=info|verbose raises its stderr log
    // for diagnosing index problems.
    const fs::path clangd = base / bundled_server("cpp").executable;
    std::string clangd_log = "error";
    wchar_t level[16];
    if (const DWORD n = GetEnvironmentVariableW(L"SHGREP_CLANGD_LOG", level, 16); n && n < 16) {
        const std::string requested = lower(utf8(std::wstring(level, n)));
        if (requested == "info" || requested == "verbose") clangd_log = requested;
    }
    std::error_code clangd_error;
    if (fs::is_regular_file(clangd, clangd_error)) {
        std::optional<CompileSetup> prepared;
        if (cpp_setup) prepared = cpp_compile_setup(root, context, cmake_configure, cancelled);
        else prepared = cpp_compile_setup_cached(root);
        // Not prepared yet: listed for status with a placeholder variant; the first C++ request prepares it.
        const CompileSetup setup = prepared ? std::move(*prepared) : CompileSetup{"unprepared", J::Object{},
            J::Object{{"source", "not prepared; the first C/C++ request prepares the compile database"}}};
        add(bundled_server("cpp"),
            // --background-index keeps its shards beside the compile database; limits of 0 return every result.
            // PERF: -j uses every hardware thread (clangd's default is the physical cores) for ASTs and indexing.
            {"--log=" + clangd_log, "--header-insertion=never", "--background-index", "--limit-results=0", "--limit-references=0",
             "--rename-file-limit=0", "--pch-storage=disk",
             "-j=" + std::to_string(std::max(std::thread::hardware_concurrency(), 1u))},
            J::Object{}, setup.initialization, {}, setup.fingerprint,
            J::Object{{"compile_database", setup.status}});
    }
    // rust-analyzer loads Cargo projects through the user's cargo; without it only syntax-level features work.
    // The default workspace/symbol limit of 128 would cut symbol searches short.
    add(bundled_server("rust"), {}, J::Object{},
        J::Object{{"workspace", J::Object{{"symbol", J::Object{{"search", J::Object{{"limit", 1000000}}}}}}}});
    add(bundled_server("python"), {"server"});
    add(bundled_server("cmake"), {"stdio"});
    // SAFETY: automatic type acquisition would query the npm registry with the workspace's package names, so it is
    //   off; tsserver then resolves types only from the workspace's node_modules. The workspace TypeScript is preferred,
    //   and the bundled one is the fallback. tsserver logging stays off.
    const fs::path typescript = base / L"typescript";
    const J typescript_settings = J::Object{
        {"typescript", J::Object{{"tsserver", J::Object{{"log", "off"}}}, {"disableAutomaticTypeAcquisition", true}}},
        {"javascript", J::Object{{"tsserver", J::Object{{"log", "off"}}}}}};
    add(bundled_server("javascript"),
        {utf8((typescript / L"node_modules" / L"typescript-language-server" / L"lib" / L"cli.mjs").wstring()), "--stdio"},
        typescript_settings,
        J::Object{{"disableAutomaticTypingAcquisition", true},
                  {"hostInfo", "shgrep"},
                  {"tsserver", J::Object{{"fallbackPath", utf8((typescript / L"node_modules" / L"typescript" / L"lib").wstring())},
                                         {"logVerbosity", "off"}}},
                  {"preferences", J::Object{{"includeCompletionsForModuleExports", false}}}});
    if (!result.empty() && result.back().language == "javascript") {
        auto& config = result.back();
        // Node writes no telemetry; these keep npm and update checks quiet should anything spawn them.
        config.environment.emplace_back(L"NO_UPDATE_NOTIFIER", L"1");
        config.environment.emplace_back(L"NPM_CONFIG_UPDATE_NOTIFIER", L"false");
        config.environment.emplace_back(L"NPM_CONFIG_OFFLINE", L"true");
        // Issue #50: one tsserver serves every configured root (tsserver loads many tsconfig projects in one process);
        // project_profile adds a separate instance only for a repo pinning a different TypeScript version.
        config.workspace_roots = context.allowed_roots;
        if (config.workspace_roots.empty()) config.workspace_roots.push_back(root);
        for (auto& workspace : config.workspace_roots)
            workspace = source_descriptor(context, utf8(workspace.wstring())).path;
        std::sort(config.workspace_roots.begin(), config.workspace_roots.end());
        config.root = fs::absolute(config.workspace_roots.front()).lexically_normal();
        std::string identity = utf8(executable_directory().wstring());
        for (const auto& ext : config.extensions) identity += "|" + ext;
        for (const auto& workspace : config.workspace_roots) identity += "\n" + lower(utf8(fs::absolute(workspace).wstring()));
        config.key = "workspace:javascript:" + source_text_digest(identity);
    }
    // SAFETY: package restore would write obj\ folders into the workspace and fetch packages from the network;
    //   without it, projects whose packages were never restored lack those references.
    if (const DotNet dotnet = find_dotnet(); dotnet.problem.empty()) {
        // A different dotnet is a new variant, so the server restarts on it; the status shows which one is used.
        const std::string dotnet_root = utf8(dotnet.root.wstring());
        // SAFETY (#51): Roslyn restores projects automatically and restores a hidden "Canonical.csproj" for files
        //   outside any project (file-based programs); both contact NuGet feeds and rewrite obj\ files. Both options
        //   are global, so Roslyn asks for them as "projects.<name>"; the "csharp|projects" copy covers older servers.
        //   As a safety net, any restore that still runs reads only the machine's NuGet package folder and an empty
        //   local feed: packages already on disk resolve, nothing is downloaded, and no package name leaves.
        const fs::path offline_feed = state / L"csharp" / L"offline-feed";
        const J restore_off = J::Object{{"dotnet_enable_automatic_restore", false},
                                        {"dotnet_enable_file_based_programs", false}};
        add(bundled_server("csharp"), {"--stdio", "--logLevel", "Information", "--telemetryLevel", "off"},
            J::Object{{"projects", restore_off}, {"csharp|projects", restore_off}},
            J::Object{}, {offline_feed}, dotnet_root, J::Object{{"dotnet_root", dotnet_root}});
        if (!result.empty() && result.back().language == "csharp") {
            auto& config = result.back();
            config.environment.emplace_back(L"DOTNET_ROOT", dotnet.root.wstring());
            config.environment.emplace_back(L"DOTNET_CLI_TELEMETRY_OPTOUT", L"1");
            config.environment.emplace_back(L"DOTNET_SKIP_FIRST_TIME_EXPERIENCE", L"1");
            config.environment.emplace_back(L"DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE", L"1");
            // MSBuild reads environment variables as properties: restores use only local folders (see above).
            std::wstring packages(32768, L'\0');
            DWORD length = GetEnvironmentVariableW(L"NUGET_PACKAGES", packages.data(), static_cast<DWORD>(packages.size()));
            if (length && length < packages.size()) packages.resize(length);
            else {
                length = GetEnvironmentVariableW(L"USERPROFILE", packages.data(), static_cast<DWORD>(packages.size()));
                packages = length && length < packages.size()
                    ? (fs::path(packages.substr(0, length)) / L".nuget" / L"packages").wstring() : std::wstring();
            }
            config.environment.emplace_back(L"RestoreSources",
                packages.empty() ? offline_feed.wstring() : packages + L";" + offline_feed.wstring());
            config.managed_projects = true;
            config.dotnet = dotnet.root / L"dotnet.exe";
            config.workspace_roots = context.allowed_roots;
            if (config.workspace_roots.empty()) config.workspace_roots.push_back(root);
            for (auto& workspace : config.workspace_roots)
                workspace = source_descriptor(context, utf8(workspace.wstring())).path;
            std::sort(config.workspace_roots.begin(), config.workspace_roots.end());
            config.root = fs::absolute(config.workspace_roots.front()).lexically_normal();
            std::string identity = utf8(executable_directory().wstring()) + dotnet_root;
            for (const auto& workspace : config.workspace_roots) identity += "\n" + lower(utf8(fs::absolute(workspace).wstring()));
            config.key = "managed:csharp:" + source_text_digest(identity);
        }
    }
}
std::vector<Config> configs_from_disk(const fs::path& root, const SearchContext& context,
                                      const std::shared_ptr<std::atomic_bool>& cancelled, bool cpp_setup) {
    const fs::path path = root / L".shgrep" / L"lsp.json";
    std::wstring metadata_path = path.wstring();
    if (!metadata_path.starts_with(L"\\\\?\\")) {
        if (metadata_path.starts_with(L"\\\\")) metadata_path = L"\\\\?\\UNC\\" + metadata_path.substr(2);
        else metadata_path = L"\\\\?\\" + metadata_path;
    }
    std::vector<Config> result;
    std::set<std::string> owned_extensions;
    const DWORD attributes = GetFileAttributesW(metadata_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) fail("cannot inspect .shgrep/lsp.json");
        add_bundled(result, root, owned_extensions, context, true, cancelled, cpp_setup);
        return result;
    }
    const SourceText file = read_source_text(context, utf8(path.wstring()));
    const J json = J::parse(file.text);
    const J* servers = json.get("servers");
    if (!servers) fail(".shgrep/lsp.json needs a servers array");
    for (const auto& server : servers->array()) {
        Config config;
        config.root = root;
        config.language = str(server, "language_id");
        if (config.language.empty()) fail("LSP server needs language_id");
        config.server = config.language;
        const J* command = server.get("command"), *extensions = server.get("extensions");
        if (!command || !extensions) fail("LSP server needs command and extensions arrays");
        for (const auto& arg : command->array()) {
            if (arg.string().find('\0') != std::string::npos) fail("NUL in LSP command");
            config.command.push_back(arg.string());
        }
        if (config.command.empty() || config.command.front().empty()) fail("empty LSP command");
        for (const auto& extension : extensions->array()) {
            std::string ext = lower(extension.string());
            if (!ext.starts_with(".")) ext = "." + ext;
            if (ext.size() < 2 || ext.find_first_of("/\\") != std::string::npos) fail("invalid LSP extension");
            if (!owned_extensions.insert(ext).second) fail("multiple language servers configured for " + ext);
            config.extensions.push_back(ext);
        }
        if (config.extensions.empty()) fail("empty LSP extensions");
        if (const J* ignored = server.get("ignored_paths")) {
            for (const auto& item : ignored->array()) {
                std::string pattern = item.string();
                std::replace(pattern.begin(), pattern.end(), '\\', '/');
                while (!pattern.empty() && pattern.back() == '/') pattern.pop_back();
                const size_t start = !pattern.empty() && pattern.front() == '!' ? 1 : 0;
                if (start == pattern.size() || pattern[start] == '/' || pattern.find(':') != std::string::npos)
                    fail("ignored_paths entries must be nonempty relative patterns");
                for (size_t part = start; part <= pattern.size();) {
                    const size_t end = pattern.find('/', part);
                    const std::string_view segment(pattern.data() + part,
                        (end == std::string::npos ? pattern.size() : end) - part);
                    if (segment == "..") fail("ignored_paths entries cannot traverse above the workspace");
                    if (end == std::string::npos) break;
                    part = end + 1;
                }
                config.ignored_paths.push_back(lower(std::move(pattern)));
            }
        }
        if (const J* p = server.get("initialization_options")) config.initialization = *p;
        config.indexes_workspace = flag(server, "indexes_workspace", false);
        if (const J* p = server.get("settings")) config.settings = *p;
        config.key = lower(utf8(root.wstring())) + ":" + file.sha256 + ":" + std::to_string(result.size());
        result.push_back(std::move(config));
    }
    if (flag(json, "bundled", true))
        add_bundled(result, root, owned_extensions, context, flag(json, "cmake_configure", true), cancelled, cpp_setup);
    return result;
}
// `cancelled`: the request's flag, or null where the caller has none (its deadline still bounds the C++ setup).
std::vector<Config> configs(const fs::path& root, const SearchContext& context,
                            const std::shared_ptr<std::atomic_bool>& cancelled, bool cpp_setup = true) {
    try { return configs_from_disk(root, context, cancelled, cpp_setup); }
    catch (const LspFailure&) { throw; }
    catch (const std::exception& e) { throw LspFailure(std::string("language server configuration failed: ") + e.what()); }
}
Config project_profile(Config config, const SourceText& source, const SearchContext& context) {
            if (config.managed_projects) {
                const auto profile = config.key.find(":sdk:");
                if (profile != std::string::npos) config.key.resize(profile);
                config.working_directory.clear();
                std::get<J::Object>(config.details.value).erase("sdk_profile");
                // Separate instances only for distinct SDK selection profiles, never per repository or solution.
                for (fs::path parent = source.path.parent_path();;) {
                    const fs::path path = parent / L"global.json";
                    const DWORD attributes = GetFileAttributesW(path.c_str());
                    if (attributes != INVALID_FILE_ATTRIBUTES) {
                        const auto snapshot = read_source_text(context, utf8(path.wstring()));
                        const J global = J::parse(snapshot.text);
                        if (const J* sdk = global.get("sdk")) {
                            config.key += ":sdk:" + source_text_digest(sdk->dump());
                            config.working_directory = parent;
                            std::get<J::Object>(config.details.value)["sdk_profile"] = *sdk;
                        }
                        break;
                    }
                    if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND)
                        fail("cannot inspect SDK selection file " + utf8(path.wstring()));
                    if (parent == source.root || parent == parent.parent_path()) break;
                    parent = parent.parent_path();
                }
            }
    if (config.language == "javascript" && config.bundled && !config.workspace_roots.empty()) {
        // One tsserver per TypeScript version: the nearest node_modules/typescript decides, else the bundled one.
        if (const auto profile = config.key.find(":ts:"); profile != std::string::npos) config.key.resize(profile);
        std::string version = "bundled";
        fs::path library;
        for (fs::path parent = source.path.parent_path();; parent = parent.parent_path()) {
            const fs::path package = parent / L"node_modules" / L"typescript" / L"package.json";
            const DWORD attributes = GetFileAttributesW(package.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES) {
                try {
                    const J json = J::parse(read_source_text(context, utf8(package.wstring())).text);
                    version = str(json, "version");
                    if (version.empty()) fail("TypeScript package has no version");
                    library = package.parent_path() / L"lib";
                } catch (const std::exception& error) {
                    throw LspFailure("cannot select the TypeScript server for " + utf8(package.wstring()) + ": " + error.what());
                }
                break;
            }
            const DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
                throw LspFailure("cannot inspect the TypeScript package " + utf8(package.wstring()) +
                     " (Windows error " + std::to_string(error) + ")");
            if (parent == source.root || parent == parent.parent_path()) break;
        }
        config.key += ":ts:" + version;
        if (!library.empty() && std::holds_alternative<J::Object>(config.initialization.value)) {
            auto& tsserver = std::get<J::Object>(config.initialization.value)["tsserver"];
            if (!std::holds_alternative<J::Object>(tsserver.value)) tsserver = J::Object{};
            std::get<J::Object>(tsserver.value)["path"] = utf8(library.wstring());
        }
    }
    return config;
}
std::optional<Config> configuration(const SourceText& source, const SearchContext& context,
                                   const std::shared_ptr<std::atomic_bool>& cancelled) {
    const std::string ext = language_extension(source.path);
    const auto& cpp = bundled_server("cpp").extensions;
    const bool cpp_setup = std::find(cpp.begin(), cpp.end(), ext) != cpp.end();
    for (auto& config : configs(source.root, context, cancelled, cpp_setup))
        if (std::find(config.extensions.begin(), config.extensions.end(), ext) != config.extensions.end())
            return project_profile(std::move(config), source, context);
    return std::nullopt;
}
// Why a file that configuration() left without a server has none, when a bundled server would serve its type:
//   the server was not installed, or "bundled": false turned it off. Empty for types no bundled server knows.
std::string missing_bundled(const SourceText& source) {
    const std::string ext = language_extension(source.path);
    for (const auto& server : bundled_servers()) {
        if (std::find(server.extensions.begin(), server.extensions.end(), ext) == server.extensions.end()) continue;
        const fs::path& base = bundled_directory();
        std::error_code error;
        if (!base.empty() && fs::is_regular_file(base / server.executable, error)) {
            if (const std::string problem = bundled_prerequisite(server.language); !problem.empty())
                return std::string("no language server for ") + ext + " files: the bundled " + server.name + " " + problem;
            return std::string("no language server for ") + ext + " files: the bundled " + server.name +
                   " is turned off by \"bundled\": false in .shgrep/lsp.json and no server there handles " + ext;
        }
        return std::string("no language server for ") + ext + " files: the bundled " + server.name + " is not installed; shgrep " +
               "expects it at " + (base.empty() ? std::string("lsp\\ beside shgrep.exe") : utf8((base / server.executable).wstring())) +
               ". Download the bundled servers there with: " + fetch_command() + " (or add a server to .shgrep/lsp.json)";
    }
    return {};
}


std::string missing_server_message(const SourceText& source) {
    std::string message = missing_bundled(source);
    if (message.empty()) message = "no language server for this file type (add one to .shgrep/lsp.json)";
    return message;
}

struct Position {
    int64_t line = 0, column = 0;
    auto operator<=>(const Position&) const = default;
    J json() const { return J::Object{{"line", line}, {"character", column}}; }
};
Position position(const J& j) {
    Position p{number(j, "line", -1), number(j, "character", -1)};
    if (p.line < 0 || p.column < 0 || p.line > INT32_MAX || p.column > INT32_MAX) fail("invalid LSP position");
    return p;
}
struct Range { Position start, end; };
Range range(const J& j) {
    const J* s = j.get("start"), *e = j.get("end");
    if (!s || !e) server_fail("missing LSP range");
    Range r{position(*s), position(*e)};
    if (r.end < r.start) server_fail("reversed LSP range");
    return r;
}
Position text_end(const std::string& text) {
    Position out;
    const std::wstring w = wide(text);
    for (size_t i = 0; i < w.size(); ++i) {
        if (w[i] == L'\r' || w[i] == L'\n') {
            if (w[i] == L'\r' && i + 1 < w.size() && w[i + 1] == L'\n') ++i;
            ++out.line; out.column = 0;
        } else ++out.column;
    }
    return out;
}
size_t offset(const std::wstring& text, Position wanted) {
    const auto mismatch = [&](const std::string& what) {
        std::string message = what;
        for (size_t at = text.find(L'\r'); at != std::wstring::npos; at = text.find(L'\r', at + 1))
            if (at + 1 >= text.size() || text[at + 1] != L'\n') {
                message += " (the file ends a line with a lone CR, which the LSP counts as a line break but some "
                           "servers do not, so their positions drift; normalizing its line endings fixes it)";
                break;
            }
        throw PositionMismatch(message);
    };
    size_t i = 0;
    int64_t line = 0;
    while (i < text.size() && line < wanted.line) {
        if (text[i] == L'\r' || text[i] == L'\n') {
            if (text[i] == L'\r' && i + 1 < text.size() && text[i + 1] == L'\n') ++i;
            ++line;
        }
        ++i;
    }
    if (line != wanted.line) mismatch("LSP range is outside the current file");
    const size_t start = i;
    while (i < text.size() && text[i] != L'\r' && text[i] != L'\n') ++i;
    if (static_cast<uint64_t>(wanted.column) > i - start) mismatch("LSP column is outside the current line");
    const size_t result = start + static_cast<size_t>(wanted.column);
    if (result > 0 && result < text.size() && text[result - 1] >= 0xD800 && text[result - 1] <= 0xDBFF &&
        text[result] >= 0xDC00 && text[result] <= 0xDFFF) fail("LSP range splits a UTF-16 surrogate pair");
    return result;
}
Range body_lines_range(const SourceText& source, Range r) {
    const std::wstring text = wide(source.text);
    (void)offset(text, r.start);
    size_t end = offset(text, r.end);
    r.start.column = 0;
    // An exclusive end at column zero already excludes that following line.
    if (r.end.column == 0) return r;
    while (end < text.size() && text[end] != L'\r' && text[end] != L'\n') {
        ++end;
        ++r.end.column;
    }
    if (end < text.size()) {
        ++r.end.line;
        r.end.column = 0;
    }
    return r;
}
std::string body(const SourceText& source, Range r) {
    const std::wstring text = wide(source.text);
    const size_t begin = offset(text, r.start), end = offset(text, r.end);
    return utf8(text.substr(begin, end - begin));
}

bool file_glob(std::wstring pattern, std::wstring path, bool insensitive) {
    std::replace(path.begin(), path.end(), L'\\', L'/');
    if (insensitive) {
        for (auto& c : path) c = static_cast<wchar_t>(std::towlower(c));
        for (auto& c : pattern) c = static_cast<wchar_t>(std::towlower(c));
    }
    const size_t brace = pattern.find(L'{');
    if (brace != std::wstring::npos) {
        size_t end = brace + 1, nesting = 1, start = end;
        std::vector<std::wstring> options;
        for (; end < pattern.size(); ++end) {
            if (pattern[end] == L'{') ++nesting;
            if (pattern[end] == L'}' && --nesting == 0) { options.push_back(pattern.substr(start, end - start)); break; }
            if (pattern[end] == L',' && nesting == 1) { options.push_back(pattern.substr(start, end - start)); start = end + 1; }
        }
        if (end == pattern.size()) fail("invalid file-operation glob braces");
        for (const auto& option : options)
            if (file_glob(pattern.substr(0, brace) + option + pattern.substr(end + 1), path, false)) return true;
        return false;
    }
    // Memoized glob matching keeps ** from causing exponential backtracking.
    std::map<std::pair<size_t, size_t>, bool> memo;
    std::function<bool(size_t, size_t)> match = [&](size_t p, size_t s) {
        const auto key = std::pair{p, s};
        if (const auto it = memo.find(key); it != memo.end()) return it->second;
        bool result = false;
        if (p == pattern.size()) result = s == path.size();
        else if (pattern[p] == L'*') {
            const bool recursive = p + 1 < pattern.size() && pattern[p + 1] == L'*';
            const size_t next = p + (recursive ? 2 : 1);
            result = match(next, s) || (recursive && next < pattern.size() && pattern[next] == L'/' && match(next + 1, s)) ||
                     (s < path.size() && (recursive || path[s] != L'/') && match(p, s + 1));
        } else if (s < path.size() && pattern[p] == L'?') result = path[s] != L'/' && match(p + 1, s + 1);
        else if (s < path.size() && pattern[p] == L'[') {
            size_t end = pattern.find(L']', p + 1), at = p + 1;
            if (end == std::wstring::npos) fail("invalid file-operation glob character class");
            const bool negate = at < end && (pattern[at] == L'!' || pattern[at] == L'^');
            if (negate) ++at;
            bool selected = false;
            while (at < end) {
                if (at + 2 < end && pattern[at + 1] == L'-') {
                    selected |= pattern[at] <= path[s] && path[s] <= pattern[at + 2]; at += 3;
                } else selected |= pattern[at++] == path[s];
            }
            result = path[s] != L'/' && selected != negate && match(end + 1, s + 1);
        } else if (s < path.size()) result = pattern[p] == path[s] && match(p + 1, s + 1);
        memo.emplace(key, result); return result;
    };
    return match(0, 0);
}

// The .gitignore/.ignore and dot-name rules source walks apply, for one path the watcher reported.
bool walk_skips(const fs::path& root, const fs::path& path) {
    std::wstring prefix = root.lexically_normal().wstring();
    const std::wstring full = path.lexically_normal().wstring();
    if (!prefix.ends_with(L"\\")) prefix += L"\\";
    if (full.size() <= prefix.size() || CompareStringOrdinal(full.data(), static_cast<int>(prefix.size()), prefix.data(),
                                                              static_cast<int>(prefix.size()), TRUE) != CSTR_EQUAL) return true;
    const std::wstring relative = full.substr(prefix.size());
    std::shared_ptr<const IgnoreScope> scope;
    std::wstring folder = prefix.substr(0, prefix.size() - 1);
    Handle directory(CreateFileW(root.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!directory.h || directory.h == INVALID_HANDLE_VALUE) return true;
    std::string base;
    for (size_t start = 0;;) {
        const bool gitignore = true, dotignore = true;
        if (gitignore || dotignore) {
            auto next = std::make_shared<IgnoreScope>();
            next->parent = scope;
            read_ignore_rules(folder, base, gitignore, dotignore, next->rules, directory.h);
            if (!next->rules.empty()) scope = std::move(next);
        }
        const size_t slash = relative.find(L'\\', start);
        const std::wstring component = relative.substr(start, slash == std::wstring::npos ? std::wstring::npos : slash - start);
        if (component.empty() || component.front() == L'.') return true;
        const std::string child = base.empty() ? utf8(component) : base + "/" + utf8(component);
        if (ignored_path(scope.get(), child, slash != std::wstring::npos)) return true;
        if (slash == std::wstring::npos) return false;
        UNICODE_STRING name{};
        name.Buffer = const_cast<wchar_t*>(component.data());
        name.Length = name.MaximumLength = static_cast<USHORT>(component.size() * sizeof(wchar_t));
        OBJECT_ATTRIBUTES attributes{};
        attributes.Length = sizeof(attributes);
        attributes.RootDirectory = directory.h;
        attributes.ObjectName = &name;
        attributes.Attributes = OBJ_CASE_INSENSITIVE;
        IO_STATUS_BLOCK io{};
        Handle next;
        const NTSTATUS status = NtCreateFile(&next.h, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes, &io, nullptr, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            1, 0x00200021, nullptr, 0);  // open an existing directory, synchronously, without following reparse points
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (status < 0 || !GetFileInformationByHandleEx(next.h, FileAttributeTagInfo, &tag, sizeof(tag)) ||
            (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return true;
        directory.reset(next.h);
        next.h = nullptr;
        folder += L"\\" + component;
        base = child;
        start = slash + 1;
    }
}
// The identifier the request points at; rename and reference checks compare index ranges against it.
std::string identifier_at(const std::string& text, Position at) {
    const std::wstring w = wide(text);
    const size_t i = offset(w, at);
    auto word = [](wchar_t c) { return std::iswalnum(c) || c == L'_'; };
    size_t begin = i, end = i;
    while (begin > 0 && word(w[begin - 1])) --begin;
    while (end < w.size() && word(w[end])) ++end;
    std::string name = utf8(w.substr(begin, end - begin));
    if (name.empty() || std::isdigit(static_cast<unsigned char>(name.front()))) return {};
    return name;
}
// What tools/egress_firewall.ps1 recorded for program: "blocked", "not blocked", or no record. It reads the script's
// egress-block.json beside shgrep.exe or the bundled servers; it does not query the live firewall.
std::string firewall_record(const fs::path& program) {
    static std::mutex mutex;
    static std::string loaded_stamp;
    static std::set<std::string> programs;
    std::vector<fs::path> markers{executable_directory() / L"egress-block.json"};
    if (!bundled_directory().empty()) markers.push_back(bundled_directory().parent_path() / L"egress-block.json");
    for (const auto& marker : markers) {
        WIN32_FILE_ATTRIBUTE_DATA data{};
        if (!GetFileAttributesExW(marker.c_str(), GetFileExInfoStandard, &data) ||
            (data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) continue;
        const std::string stamp = lower(utf8(marker.wstring())) + ":" + std::to_string(data.ftLastWriteTime.dwHighDateTime) +
            ":" + std::to_string(data.ftLastWriteTime.dwLowDateTime) + ":" + std::to_string(data.nFileSizeLow);
        std::lock_guard lock(mutex);
        if (stamp != loaded_stamp) {
            programs.clear();
            try {
                std::ifstream file(marker, std::ios::binary);
                std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                if (text.starts_with("\xEF\xBB\xBF")) text.erase(0, 3);  // Set-Content -Encoding utf8 writes a BOM
                const J json = J::parse(text);
                if (const J* listed = json.get("programs"))
                    for (const auto& item : listed->array())
                        programs.insert(lower(utf8(fs::path(wide(item.string())).lexically_normal().wstring())));
            } catch (const std::exception&) {
                return "firewall record unreadable: " + utf8(marker.wstring());
            }
            loaded_stamp = stamp;
        }
        return programs.contains(lower(utf8(program.lexically_normal().wstring()))) ? "block rule recorded; live firewall state unverified" : "no block rule recorded for this program";
    }
    return "no firewall rules recorded; run tools/egress_firewall.ps1 as administrator";
}
class Session {
    // Every failure inside a session is the server's, not the caller's.
    [[noreturn]] static void fail(const std::string& s) { throw LspFailure(s); }
    Handle input_, output_, process_, job_;
    std::thread reader_, writer_;
    std::mutex writer_mutex_;
    std::timed_mutex sender_mutex_;
    mutable sync::Mutex registrations_mutex_;
    std::condition_variable writer_ready_;
    std::string outgoing_;
    bool writer_stopping_ = false, write_done_ = true, write_ok_ = true;
    mutable std::mutex messages_mutex_;
    std::condition_variable messages_ready_;
    // SAFETY: the reader runs inside the MCP process, outside the REPL worker's memory limit, so what a server sends is
    //   bounded: one message's body (its Content-Length) and the bodies of the responses queued until a request takes
    //   them. A server past either limit fails the session instead of growing the process.
    static constexpr size_t kMaxMessageBytes = 64u << 20;
    static constexpr size_t kMaxQueuedBytes = 128u << 20;
    static constexpr size_t kMaxQueuedMessages = 4096;
    struct Queued { J message; size_t bytes; };
    std::deque<Queued> messages_;  // responses, oldest first
    size_t queued_bytes_ = 0;      // the bodies of messages_
    std::string reader_error_;
    // SAFETY: notification state is bounded too. Diagnostics are kept only for open documents, the only ones
    //   diagnostics() reads (opening or changing a document drops its old report), and at most kMaxDiagnosticBytes of
    //   them in all. At most kMaxProgress work-done reports stay open at once, and titles are cut to kMaxProgressTitle.
    //   Capability registrations keep their options only where file_operation reads them; past kMaxRegistrations or
    //   kMaxRegistrationBytes a registration is refused with an error response.
    static constexpr size_t kMaxDiagnosticBytes = 128u << 20;
    static constexpr size_t kMaxProgress = 256, kMaxProgressKey = 1024, kMaxProgressTitle = 256, kMaxProgressMessage = 1024;
    static constexpr size_t kMaxRegistrations = 1024, kMaxRegistrationBytes = 4u << 20;
    struct Published { J params; size_t bytes; };
    std::map<std::wstring, Published, PathLess> published_diagnostics_;  // by diagnostic_key; messages_mutex_
    std::set<std::wstring, PathLess> diagnosed_;  // diagnostic_key of every open document; messages_mutex_
    size_t diagnostic_bytes_ = 0;                 // the bodies of published_diagnostics_; messages_mutex_
    struct Registration { std::string method; J options; size_t bytes; };
    std::map<std::string, Registration> registrations_ SHGREP_GUARDED_BY(registrations_mutex_);  // by id; registrations_mutex_
    size_t registration_bytes_ SHGREP_GUARDED_BY(registrations_mutex_) = 0;                      // registrations_mutex_
    Clock::time_point initialized_at_{};  // when "initialized" was sent; late dynamic registrations settle after it
    Clock::time_point process_started_at_{};
    std::atomic<Clock::duration::rep> last_request_ticks_{0};
    static constexpr int64_t kServerIdleMs = 300000;  // protected by the session mutex
    int64_t next_id_ = 0;
    J capabilities_ = J::Object{};
    int sync_kind_ = 0;
    // rust-analyzer's experimental/serverStatus: answers before quiescence miss the not-yet-loaded project.
    bool announces_status_ = false, status_seen_ = false, quiescent_ = true, ready_ = false;
    // The index was ready at least once since start; an empty outline is then a real answer, not a cold server's.
    bool ever_ready_ = false;
    bool roslyn_projects_ready_ = false;  // messages_mutex_
    std::string roslyn_project_error_;  // messages_mutex_
    std::string status_message_, status_health_;  // bounded experimental/serverStatus details; messages_mutex_
    struct ProjectLoad { std::wstring file; std::string state, message; };
    static constexpr size_t kMaxTrackedProjects = 256;
    std::map<std::wstring, ProjectLoad, PathLess> project_loads_;  // explicit window/logMessage project states; messages_mutex_
    std::string latest_project_state_, latest_project_message_;
    std::wstring latest_project_file_;
    // Work-done progress the server reports ($/progress), by token; messages_mutex_.
    struct Progress { std::string title, message; int64_t percentage = -1; };
    std::map<std::string, Progress> progress_;
    Clock::time_point last_progress_log_{};  // messages_mutex_; throttle server progress in the viewer
    Clock::time_point last_activity_{};  // server start, progress or a newly opened document; messages_mutex_
    // indexes_workspace sessions: documents changed since the server indexed them stay open (pinned_); others
    // opened for a request are closed again once more than kRecentDocuments are open (recent_, oldest first).
    static constexpr size_t kRecentDocuments = 32;
    // PERF: changed files stay open, but past this many the server is restarted to reread the tree instead, so a
    //   bulk change (checkout, code generation) never leaves the workspace open in the server.
    static constexpr size_t kPinnedDocuments = 256;
    std::unique_ptr<DirectoryWatch> watch_;
    // Workspace-wide servers (one per language for all roots) watch every other root too.
    std::vector<std::unique_ptr<DirectoryWatch>> extra_watches_;
    std::vector<DirectoryWatch*> watches() const {
        std::vector<DirectoryWatch*> all;
        if (watch_) all.push_back(watch_.get());
        for (const auto& watch : extra_watches_) if (watch) all.push_back(watch.get());
        return all;
    }
    bool watches_ok() const {
        if (!watch_) return false;
        const auto all = watches();
        return std::none_of(all.begin(), all.end(), [](DirectoryWatch* watch) { return watch->failed(); });
    }
    void reset_watches() { watch_.reset(); extra_watches_.clear(); }
    // The workspace root holding path, for ignore rules; the session root when none does.
    fs::path root_of(const fs::path& path) const {
        const std::wstring full = path.lexically_normal().wstring();
        for (const auto& root : config.workspace_roots) {
            std::wstring prefix = root.lexically_normal().wstring();
            if (!prefix.ends_with(L"\\")) prefix += L"\\";
            if (full.size() > prefix.size() && CompareStringOrdinal(full.data(), static_cast<int>(prefix.size()),
                    prefix.data(), static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL) return root;
        }
        return config.root;
    }
    std::set<std::wstring, PathLess> pinned_;
    std::deque<std::wstring> recent_;
    struct Document { std::string hash, uri; int64_t version; Position end; };
    std::map<std::wstring, Document, PathLess> documents_;

    static std::wstring diagnostic_key(const fs::path& path) { return path.lexically_normal().make_preferred().wstring(); }
    static std::string bounded_progress_text(std::string text, size_t maximum) {
        if (text.size() > maximum) {
            size_t cut = maximum;
            while (cut && (static_cast<unsigned char>(text[cut]) & 0xc0) == 0x80) --cut;
            text.resize(cut);
        }
        return text;
    }
    // Drops the report kept for `key`; `closed` also stops keeping later ones (the document closed).
    // CONTRACT: messages_mutex_ held.
    void forget_diagnostics(const std::wstring& key, bool closed) {
        if (const auto it = published_diagnostics_.find(key); it != published_diagnostics_.end()) {
            diagnostic_bytes_ -= it->second.bytes;
            published_diagnostics_.erase(it);
        }
        if (closed) diagnosed_.erase(key);
    }
    bool read_exact(char* data, size_t size) {
        while (size) {
            DWORD got = 0;
            const DWORD chunk = static_cast<DWORD>(std::min<size_t>(size, 1u << 20));
            if (!ReadFile(output_.h, data, chunk, &got, nullptr) || !got) return false;
            data += got; size -= got;
        }
        return true;
    }
    static bool path_within(const fs::path& child, const fs::path& parent) {
        std::wstring prefix = parent.lexically_normal().wstring();
        if (prefix.empty()) return false;
        if (!prefix.ends_with(L"\\") && !prefix.ends_with(L"/")) prefix += L"\\";
        const std::wstring candidate = child.lexically_normal().wstring();
        return candidate.size() >= prefix.size() &&
            CompareStringOrdinal(candidate.data(), static_cast<int>(prefix.size()), prefix.data(),
                                 static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL;
    }
    // CONTRACT: messages_mutex_ held. Project load diagnostics arrive through window/logMessage.
    bool update_project_state_locked(std::string_view text) {
        const std::string folded = lower(std::string(text));
        std::string state;
        size_t path_start = std::string::npos;
        const std::string loading_marker = "loading project:";
        if (const size_t at = folded.find("error while loading "); at != std::string::npos) {
            state = "failed";
            path_start = at + std::string("error while loading ").size();
        } else if (const size_t at = folded.find("successfully completed load of "); at != std::string::npos) {
            state = "loaded";
            path_start = at + std::string("successfully completed load of ").size();
        } else if (const size_t at = folded.find(loading_marker); at != std::string::npos) {
            state = "loading";
            path_start = at + loading_marker.size();
        } else if (const size_t at = folded.find("successfully loaded project file"); at != std::string::npos) {
            state = "loaded";
            path_start = at + std::string("successfully loaded project file").size();
        } else if (const size_t at = folded.find("failed to load project file"); at != std::string::npos) {
            state = "failed";
            path_start = at + std::string("failed to load project file").size();
        } else return false;
        while (path_start < text.size() && std::isspace(static_cast<unsigned char>(text[path_start]))) ++path_start;
        if (path_start < text.size() && (text[path_start] == '\'' || text[path_start] == '"')) ++path_start;
        const size_t extension = folded.find(".csproj", path_start);
        if (extension == std::string::npos) return false;
        const size_t path_end = extension + 7;
        if (path_end <= path_start || path_end - path_start > 2048) return false;
        const std::wstring file = fs::path(wide(std::string(text.substr(path_start, path_end - path_start)))).lexically_normal().wstring();
        if (!fs::path(file).is_absolute()) return false;
        if (!project_loads_.contains(file) && project_loads_.size() >= managed_tracking_limit_.load()) return false;
        const std::string message = bounded_progress_text(std::string(text), kMaxProgressMessage);
        project_loads_[file] = ProjectLoad{file, state, message};
        latest_project_file_ = file;
        latest_project_state_ = state;
        latest_project_message_ = message;
        if (state == "loading") ready_ = false;
        last_activity_ = Clock::now();
        messages_ready_.notify_all();
        return true;
    }
    const ProjectLoad* project_load_locked(const SourceText* source) const {
        if (!source) {
            const auto loading = std::find_if(project_loads_.begin(), project_loads_.end(),
                [](const auto& item) { return item.second.state == "loading"; });
            if (loading != project_loads_.end()) return &loading->second;
            const auto it = project_loads_.find(latest_project_file_);
            return it == project_loads_.end() ? nullptr : &it->second;
        }
        const ProjectLoad* best = nullptr;
        size_t best_length = 0;
        for (const auto& [file, project] : project_loads_) {
            (void)file;
            const fs::path project_file(project.file);
            const fs::path directory = project_file.parent_path();
            if (directory.wstring().size() > best_length && path_within(source->path, directory)) {
                best = &project;
                best_length = directory.wstring().size();
            }
        }
        return best;
    }
    std::string project_state_locked(const SourceText* source = nullptr) const {
        if (announces_status_ && status_seen_) return quiescent_ ? "loaded" : "loading";
        if (const ProjectLoad* project = project_load_locked(source)) return project->state;
        return source || latest_project_state_.empty() ? "unknown" : latest_project_state_;
    }
    bool project_loading_locked(const SourceText* source = nullptr) const {
        if (source) return project_state_locked(source) == "loading";
        return std::any_of(project_loads_.begin(), project_loads_.end(),
            [](const auto& item) { return item.second.state == "loading"; });
    }
    void append_project_details_locked(J::Object& details, const SourceText* source) const {
        std::string state = project_state_locked(source);
        if (project_loading_locked(source)) state = "loading";
        details.emplace("project_state", std::move(state));
        if (announces_status_ && status_seen_) {
            if (!status_message_.empty()) details.emplace("project_status_message", status_message_);
            return;
        }
        if (const ProjectLoad* project = project_load_locked(source)) {
            details.emplace("project_file", utf8(project->file));
            if (!project->message.empty()) details.emplace("project_status_message", project->message);
        }
    }
public:
    J project_details(const SourceText& source) const {
        std::lock_guard lock(messages_mutex_);
        J::Object details;
        append_project_details_locked(details, &source);
        return details;
    }
private:
    void reader_loop() noexcept {
        try {
            for (;;) {
                std::string header;
                char c = 0;
                while (!header.ends_with("\r\n\r\n")) {
                    if (!read_exact(&c, 1)) fail("language server closed its output");
                    header.push_back(c);
                    if (header.size() > 16384) fail("invalid LSP framing header");
                }
                size_t length = 0;
                bool found = false;
                for (size_t p = 0; p < header.size();) {
                    const size_t end = header.find("\r\n", p);
                    const std::string line = header.substr(p, end - p);
                    if (lower(line).starts_with("content-length:")) {
                        if (found) fail("duplicate LSP Content-Length");
                        const std::string value = line.substr(15);
                        size_t consumed = 0;
                        const size_t first = value.find_first_not_of(" \t");
                        if (first == std::string::npos || value[first] < '0' || value[first] > '9') fail("invalid LSP Content-Length");
                        const unsigned long long parsed = std::stoull(value, &consumed);
                        if (parsed > std::numeric_limits<size_t>::max() ||
                            value.find_first_not_of(" \t", consumed) != std::string::npos) fail("invalid LSP Content-Length");
                        length = static_cast<size_t>(parsed); found = true;
                    }
                    if (end == std::string::npos) break;
                    p = end + 2;
                }
                if (!found) fail("missing LSP Content-Length");
                if (length > kMaxMessageBytes)
                    fail("language server sent a " + std::to_string(length) + "-byte message; shgrep accepts at most " +
                         std::to_string(kMaxMessageBytes >> 20) + " MiB");
                std::string payload(length, 0);
                if (!read_exact(payload.data(), payload.size())) fail("language server closed a partial response");
                J message = J::parse(payload);
                if (!message.get("id")) {
                    if (config.managed_projects && str(message, "method") == "workspace/projectInitializationComplete") {
                        std::lock_guard lock(messages_mutex_);
                        roslyn_projects_ready_ = true;
                        last_activity_ = Clock::now();
                        messages_ready_.notify_all();
                        continue;
                    }
                    if (str(message, "method") == "$/progress") {
                        const J* params = message.get("params");
                        const J* value = params ? params->get("value") : nullptr;
                        const J* token = params ? params->get("token") : nullptr;
                        if (value && token && std::holds_alternative<J::Object>(value->value)) {
                            const J* percentage = value->get("percentage");
                            const int64_t percent = percentage && std::holds_alternative<int64_t>(percentage->value) ? percentage->integer() : -1;
                            const std::string kind = str(*value, "kind"), key = token->dump();
                            std::lock_guard lock(messages_mutex_);
                            if (kind == "begin") {
                                if (key.size() > kMaxProgressKey || (progress_.size() >= kMaxProgress && !progress_.contains(key)))
                                    fail("language server opened more than " + std::to_string(kMaxProgress) +
                                         " work-done progress reports without ending them, or an oversized token");
                                std::string title = bounded_progress_text(str(*value, "title"), kMaxProgressTitle);
                                std::string message = bounded_progress_text(str(*value, "message"), kMaxProgressMessage);
                                progress_[key] = Progress{std::move(title), std::move(message), percent};
                                ready_ = false;
                            }
                            else if (kind == "report") {
                                if (auto it = progress_.find(key); it != progress_.end()) {
                                    if (percent >= 0) it->second.percentage = percent;
                                    if (value->get("message"))
                                        it->second.message = bounded_progress_text(str(*value, "message"), kMaxProgressMessage);
                                }
                            }
                            if (auto it = progress_.find(key); it != progress_.end()) {
                                const std::string title = lower(it->second.title);
                                const bool indexing = title.find("diagnos") == std::string::npos &&
                                    title.find("check") == std::string::npos && title.find("lint") == std::string::npos;
                                const auto now = Clock::now();
                                if (indexing && (kind == "begin" || kind == "end" ||
                                    (kind == "report" && (last_progress_log_ == Clock::time_point{} ||
                                     now - last_progress_log_ >= std::chrono::seconds(5))))) {
                                    std::string line = "language server " + config.server + " (" + config.language +
                                        ", root " + utf8(config.root.wstring()) + "): ";
                                    line += it->second.title.empty() ? "indexing" : it->second.title;
                                    if (!it->second.message.empty()) line += ": " + it->second.message;
                                    if (it->second.percentage >= 0) line += " " + std::to_string(it->second.percentage) + "%";
                                    if (kind == "end") line += " (finished)";
                                    index_log(false, line);
                                    last_progress_log_ = now;
                                }
                            }
                            if (kind == "end") progress_.erase(key);
                            last_activity_ = Clock::now();
                            messages_ready_.notify_all();
                        }
                        continue;
                    }
                    if (str(message, "method") == "experimental/serverStatus") {
                        if (const J* params = message.get("params")) {
                            std::lock_guard lock(messages_mutex_);
                            status_seen_ = true;
                            quiescent_ = flag(*params, "quiescent", true);
                            status_message_ = bounded_progress_text(str(*params, "message"), kMaxProgressMessage);
                            status_health_ = bounded_progress_text(str(*params, "health"), kMaxProgressTitle);
                            ready_ = quiescent_;
                            messages_ready_.notify_all();
                        }
                        continue;
                    }
                    if (str(message, "method") == "window/logMessage") {
                        const J* params = message.get("params");
                        const std::string text = params ? str(*params, "message") : std::string{};
                        std::lock_guard lock(messages_mutex_);
                        if (!update_project_state_locked(text) && config.managed_projects &&
                            lower(text).find("error while loading ") != std::string::npos) {
                            roslyn_project_error_ = bounded_progress_text(text, kMaxProgressMessage);
                            messages_ready_.notify_all();
                        }
                        continue;
                    }
                    if (str(message, "method") == "textDocument/publishDiagnostics") {
                        if (const J* params = message.get("params")) {
                            std::lock_guard lock(messages_mutex_);
                            if (params->get("diagnostics")) {
                                std::wstring key;
                                try { key = diagnostic_key(from_uri(str(*params, "uri"))); }
                                catch (const std::exception&) { continue; }
                                if (diagnosed_.contains(key)) {
                                    forget_diagnostics(key, false);
                                    if (diagnostic_bytes_ + length > kMaxDiagnosticBytes)
                                        fail("language server's diagnostics for open documents exceed " +
                                             std::to_string(kMaxDiagnosticBytes >> 20) + " MiB");
                                    diagnostic_bytes_ += length;
                                    published_diagnostics_[key] = Published{*params, length};
                                }
                            }
                            messages_ready_.notify_all();
                        }
                    }
                    continue;
                }
                if (message.get("method")) {
                    const std::shared_ptr<std::atomic_bool> background;
                    const Control control{Clock::now() + std::chrono::seconds(30), background};
                    answer(message, control);
                    continue;
                }
                {
                    std::lock_guard lock(messages_mutex_);
                    if (messages_.size() >= kMaxQueuedMessages || queued_bytes_ + length > kMaxQueuedBytes)
                        fail("language server sent more responses than requests took (" + std::to_string(messages_.size()) +
                             " queued, " + std::to_string(queued_bytes_ >> 20) + " MiB)");
                    queued_bytes_ += length;
                    messages_.push_back({std::move(message), length});
                }
                messages_ready_.notify_one();
            }
        } catch (const std::exception& e) {
            std::lock_guard lock(messages_mutex_);
            reader_error_ = e.what();
            messages_ready_.notify_all();
        }
    }
    void writer_loop() noexcept {
        for (;;) {
            std::string frame;
            {
                std::unique_lock lock(writer_mutex_);
                writer_ready_.wait(lock, [&] { return writer_stopping_ || !write_done_; });
                if (writer_stopping_) return;
                frame = std::move(outgoing_);
            }
            bool ok = true;
            for (size_t offset = 0; offset < frame.size();) {
                DWORD written = 0;
                const DWORD size = static_cast<DWORD>(std::min<size_t>(frame.size() - offset, 1u << 20));
                if (!WriteFile(input_.h, frame.data() + offset, size, &written, nullptr) || !written) { ok = false; break; }
                offset += written;
            }
            {
                std::lock_guard lock(writer_mutex_);
                write_ok_ = ok; write_done_ = true;
            }
            writer_ready_.notify_all();
        }
    }
    void send(J message, const Control& control) {
        control.check();
        last_request_ticks_.store(Clock::now().time_since_epoch().count(), std::memory_order_relaxed);
        std::unique_lock<std::timed_mutex> sender(sender_mutex_, std::defer_lock);
        while (!sender.try_lock_for(std::chrono::milliseconds(10))) control.check();
        control.check();
        const std::string payload = message.dump();
        std::unique_lock lock(writer_mutex_);
        if (writer_stopping_ || !write_done_) fail("invalid LSP writer state");
        outgoing_ = "Content-Length: " + std::to_string(payload.size()) + "\r\n\r\n" + payload;
        write_done_ = false; writer_ready_.notify_all();
        while (!write_done_) {
            writer_ready_.wait_for(lock, std::chrono::milliseconds(10));
            control.check();
        }
        if (!write_ok_) fail("cannot write to language server");
    }
    J setting(const std::string& section) const {
        J value = config.settings;
        size_t start = 0;
        while (start < section.size()) {
            const size_t end = section.find('.', start);
            const J* next = value.get(section.substr(start, end - start));
            if (!next) return nullptr;
            J copy = *next; value = std::move(copy);
            if (end == std::string::npos) break;
            start = end + 1;
        }
        return value;
    }
    void answer(const J& request, const Control& control) {
        const std::string method = str(request, "method");
        J result = nullptr;
        bool refused = false;  // a registration past the limits
        if (method == "workspace/configuration") {
            J::Array values;
            const J* params = request.get("params"), *items = params ? params->get("items") : nullptr;
            if (items) for (const auto& item : items->array()) values.push_back(setting(str(item, "section")));
            result = std::move(values);
        } else if (method == "workspace/workspaceFolders") {
            J::Array folders;
            if (!config.workspace_roots.empty()) {
                for (const auto& root : config.workspace_roots)
                    folders.emplace_back(J::Object{{"uri", uri(root)}, {"name", utf8(root.filename().wstring())}});
            } else {
                folders.emplace_back(J::Object{{"uri", uri(config.root)}, {"name", utf8(config.root.filename().wstring())}});
            }
            result = std::move(folders);
        } else if (method == "workspace/applyEdit") {
            result = J::Object{{"applied", false}, {"failureReason", "unsolicited server edits require an explicit edit_file operation"}};
        } else if (method == "client/registerCapability" || method == "client/unregisterCapability") {
            sync::LockGuard lock(registrations_mutex_);
            const J* params = request.get("params");
            const J* entries = params ? params->get(method == "client/registerCapability" ? "registrations" : "unregisterations") : nullptr;
            if (!entries && params) entries = params->get("unregistrations");
            if (entries) for (const auto& entry : entries->array()) {
                const std::string id = str(entry, "id");
                if (const auto it = registrations_.find(id); it != registrations_.end()) {
                    registration_bytes_ -= it->second.bytes;
                    registrations_.erase(it);
                }
                if (method != "client/registerCapability") continue;
                std::string registered = str(entry, "method");
                // Only file_operation reads options, those of workspace/{did,will}{Create,Rename,Delete}Files.
                const J* given = entry.get("registerOptions");
                J options = given && registered.starts_with("workspace/") && registered.ends_with("Files") ? *given : J(J::Object{});
                const size_t bytes = id.size() + registered.size() + options.dump().size();
                if (registrations_.size() >= kMaxRegistrations || registration_bytes_ + bytes > kMaxRegistrationBytes) {
                    refused = true;
                    continue;
                }
                registration_bytes_ += bytes;
                registrations_[id] = Registration{std::move(registered), std::move(options), bytes};
            }
        } else if (method != "window/workDoneProgress/create" && !method.ends_with("/refresh")) {
            send(J::Object{{"jsonrpc", "2.0"}, {"id", *request.get("id")},
                 {"error", J::Object{{"code", -32601}, {"message", "unsupported client request"}}}}, control);
            return;
        }
        if (refused) {
            send(J::Object{{"jsonrpc", "2.0"}, {"id", *request.get("id")},
                 {"error", J::Object{{"code", -32603}, {"message", "too many capability registrations; limit " +
                     std::to_string(kMaxRegistrations) + " or " + std::to_string(kMaxRegistrationBytes >> 20) + " MiB"}}}}, control);
            return;
        }
        send(J::Object{{"jsonrpc", "2.0"}, {"id", *request.get("id")}, {"result", std::move(result)}}, control);
    }
    std::unique_ptr<DotnetProjects> project_pool_;
    std::vector<std::string> project_base_command_;
    std::string project_fingerprint_;
    bool project_partial_ = false, project_syntax_only_ = false;
    std::optional<SearchContext> project_discovery_context_;
    std::optional<SourceText> project_discovery_focus_;
    std::shared_ptr<std::atomic_bool> project_discovery_cancelled_;
    std::string project_discovery_error_;
    Clock::time_point project_discovery_last_user_{};
    std::atomic<size_t> managed_tracking_limit_{kMaxTrackedProjects};
public:
    Config config;
    std::timed_mutex mutex;
    explicit Session(Config value) : config(std::move(value)) {
        project_base_command_ = config.command;
        if (config.managed_projects) {
            project_reaper_ = std::jthread([this](std::stop_token stop) {
                while (!stop.stop_requested()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    if (stop.stop_requested()) break;
                    std::unique_lock lock(mutex, std::try_to_lock);
                    if (!lock || !project_pool_) continue;
                    if (project_discovery_cancelled_ && project_discovery_cancelled_->load()) {
                        project_discovery_context_.reset();
                        project_discovery_focus_.reset();
                        project_discovery_cancelled_.reset();
                    }
                    const auto now = Clock::now();
                    if (project_discovery_last_user_ != Clock::time_point{} &&
                        now - project_discovery_last_user_ >= std::chrono::milliseconds(config.project_idle_ms)) {
                        this->stop();
                        project_pool_->unloaded();
                        project_fingerprint_.clear();
                        project_discovery_context_.reset();
                        project_discovery_focus_.reset();
                        project_discovery_cancelled_.reset();
                        project_discovery_last_user_ = {};
                        continue;
                    }
                    if (project_pool_->expire_idle(now, std::chrono::milliseconds(config.project_idle_ms))) {
                        this->stop();
                        project_pool_->unloaded();
                        project_fingerprint_.clear();
                        continue;
                    }
                    if (!project_pool_->unevaluated() || !project_discovery_context_ || !project_discovery_focus_ ||
                        !project_discovery_error_.empty()) continue;
                    auto cancelled = std::make_shared<std::atomic_bool>(false);
                    std::stop_callback cancel_on_stop(stop, [cancelled] { cancelled->store(true); });
                    const Control control{Clock::now() + std::chrono::seconds(30), cancelled};
                    try {
                        start(control, &*project_discovery_context_, &*project_discovery_focus_, false, false, false, true);
                    } catch (const std::exception& error) {
                        if (!stop.stop_requested()) {
                            project_partial_ = true;
                            project_discovery_error_ = error.what();
                        }
                    }
                }
            });
        }
    }
    ~Session() {
        project_reaper_.request_stop();
        if (project_reaper_.joinable()) project_reaper_.join();
        stop();
    }
    void stop() noexcept {
        if (job_.h) TerminateJobObject(job_.h, 0);
        else if (process_.h) TerminateProcess(process_.h, 0);
        {
            std::lock_guard lock(writer_mutex_);
            writer_stopping_ = true; write_done_ = true; write_ok_ = false;
        }
        writer_ready_.notify_all();
        if (writer_.joinable()) { CancelSynchronousIo(writer_.native_handle()); writer_.join(); }
        input_.reset();
        if (reader_.joinable()) { CancelSynchronousIo(reader_.native_handle()); reader_.join(); }
        output_.reset(); process_.reset(); job_.reset();
        process_started_at_ = {};
        last_request_ticks_.store(0, std::memory_order_relaxed);
        documents_.clear();
        std::lock_guard lock(messages_mutex_);
        messages_.clear(); queued_bytes_ = 0; reader_error_.clear();
        published_diagnostics_.clear(); diagnosed_.clear(); diagnostic_bytes_ = 0;
        status_seen_ = false; quiescent_ = true; announces_status_ = false; ready_ = false; ever_ready_ = false; roslyn_projects_ready_ = false;
        status_message_.clear(); status_health_.clear(); roslyn_project_error_.clear(); project_loads_.clear(); latest_project_state_.clear();
        latest_project_message_.clear(); latest_project_file_.clear(); progress_.clear(); last_activity_ = {}; initialized_at_ = {};
        reset_watches(); pinned_.clear(); recent_.clear();
        { sync::LockGuard registrations_lock(registrations_mutex_); registrations_.clear(); registration_bytes_ = 0; }
        capabilities_ = J::Object{};
    }
    J request(const std::string& method, J params, const Control& control) {
        try {
            for (int attempt = 0;; ++attempt) {
                const int64_t id = ++next_id_;
                send(J::Object{{"jsonrpc", "2.0"}, {"id", id}, {"method", method}, {"params", params}}, control);
                for (;;) {
                    control.check();
                    J message;
                    {
                        std::unique_lock lock(messages_mutex_);
                        if (messages_.empty()) {
                            if (!reader_error_.empty()) fail(reader_error_);
                            messages_ready_.wait_for(lock, std::chrono::milliseconds(10));
                            continue;
                        }
                        message = std::move(messages_.front().message);
                        queued_bytes_ -= messages_.front().bytes;
                        messages_.pop_front();
                    }
                    if (message.get("method")) { answer(message, control); continue; }
                    if (message.get("id")->dump() != J(id).dump()) continue;
                    if (const J* error = message.get("error")) {
                        if (number(*error, "code", 0) == -32801 && attempt < 2) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(50 * (attempt + 1)));
                            control.check();
                            break;
                        }
                        // CONTRACT: an error reply means the server works and declines this request (clangd will not rename
                        //   a macro, a method is unsupported): a plain error the caller can act on. Only an internal error
                        //   (-32603) says the server itself broke, which is an LspFailure with the relay banner.
                        if (number(*error, "code", -32603) == -32603)
                            fail("language server " + method + ": " + error->dump());
                        reject_request("language server declined " + method + ": " +
                                       str(*error, "message", error->dump()), true);
                    }
                    const J* result = message.get("result");
                    if (!result) fail("invalid LSP response to " + method);
                    return *result;
                }
            }
        } catch (const LspTimeoutFailure&) {
            std::lock_guard lock(messages_mutex_);
            if (!index_ready_locked())
                throw warming_failure_locked(initialized_at_ == Clock::time_point{} ? "startup" : "workspace_index");
            throw;
        }
    }

    // Several requests in flight at once; servers answer them in parallel (clangd builds each file's AST on its own
    // worker). Answers come back in the order of `params`; an error reply leaves that entry null and puts the server's
    // message in errors[i]. ContentModified (-32801) is retried up to twice, like request().
    std::vector<J> request_many(const std::string& method, const std::vector<J>& params, std::vector<std::string>& errors,
                                const Control& control) {
        std::vector<J> results(params.size());
        errors.assign(params.size(), {});
        std::vector<int> attempts(params.size(), 0);
        std::map<int64_t, size_t> waiting;  // request id -> index into params
        const auto send_one = [&](size_t index) {
            const int64_t id = ++next_id_;
            waiting.emplace(id, index);
            send(J::Object{{"jsonrpc", "2.0"}, {"id", id}, {"method", method}, {"params", params[index]}}, control);
        };
        for (size_t i = 0; i < params.size(); ++i) send_one(i);
        while (!waiting.empty()) {
            control.check();
            J message;
            {
                std::unique_lock lock(messages_mutex_);
                if (messages_.empty()) {
                    if (!reader_error_.empty()) fail(reader_error_);
                    messages_ready_.wait_for(lock, std::chrono::milliseconds(10));
                    continue;
                }
                message = std::move(messages_.front().message);
                queued_bytes_ -= messages_.front().bytes;
                messages_.pop_front();
            }
            if (message.get("method")) { answer(message, control); continue; }
            const J* id_field = message.get("id");
            if (!id_field || !std::holds_alternative<int64_t>(id_field->value)) continue;
            const auto found = waiting.find(id_field->integer());
            if (found == waiting.end()) continue;  // the answer to an earlier, abandoned request
            const size_t index = found->second;
            waiting.erase(found);
            if (const J* error = message.get("error")) {
                if (number(*error, "code", 0) == -32801 && attempts[index] < 2) {
                    ++attempts[index];
                    send_one(index);
                    continue;
                }
                errors[index] = "language server " + method + ": " + str(*error, "message", error->dump());
                continue;
            }
            const J* result = message.get("result");
            if (!result) {
                errors[index] = "invalid LSP response to " + method;
                continue;
            }
            results[index] = *result;
        }
        return results;
    }
    // Outlines of many files with up to `window` documentSymbol requests in flight (the meaning index, #87). Files this
    // call opens are closed again after their window, so the server never holds more than `window` extra files; files
    // that were already open stay open. raw[i] is the server's answer for sources[i]; errors[i] is set instead on failure.
    void outline_batch(const std::vector<SourceText>& sources, size_t window, std::vector<J>& raw,
                       std::vector<std::string>& errors, const Control& control) {
        require("documentSymbolProvider");
        raw.assign(sources.size(), J());
        errors.assign(sources.size(), {});
        window = std::max<size_t>(window, 1);
        for (size_t first = 0; first < sources.size(); first += window) {
            const size_t last = std::min(sources.size(), first + window);
            std::vector<std::wstring> opened;
            const auto close_opened = [&] {
                for (const auto& key : opened)
                    if (!pinned_.contains(key)) close_document(key, control);
                opened.clear();
            };
            try {
                std::vector<J> params;
                params.reserve(last - first);
                for (size_t i = first; i < last; ++i) {
                    const std::wstring key = sources[i].path.wstring();
                    if (documents_.find(key) == documents_.end()) opened.push_back(key);
                    sync_one(sources[i], control);
                    params.push_back(J::Object{{"textDocument", J::Object{{"uri", documents_.at(key).uri}}}});
                }
                std::vector<std::string> window_errors;
                std::vector<J> answers = request_many("textDocument/documentSymbol", params, window_errors, control);
                for (size_t i = first; i < last; ++i) {
                    raw[i] = std::move(answers[i - first]);
                    errors[i] = std::move(window_errors[i - first]);
                }
            } catch (...) {
                // Best effort: a timed-out control can make the closes throw too; the request's error wins.
                try { close_opened(); } catch (...) {}
                throw;
            }
            close_opened();
        }
    }
    void notify(const std::string& method, J params, const Control& control) {
        send(J::Object{{"jsonrpc", "2.0"}, {"method", method}, {"params", std::move(params)}}, control);
    }
    void start(const Control& control, const SearchContext* context = nullptr, const SourceText* primary = nullptr,
               bool reverse = false, bool whole_workspace = false, bool require_complete = false,
               bool background = false) {
        if (config.managed_projects && context) {
            if (!background) {
                project_discovery_error_.clear();
                if (primary) {
                    project_discovery_last_user_ = Clock::now();
                    project_discovery_cancelled_ = control.cancelled;
                    project_discovery_context_ = *context;
                    project_discovery_context_->record_user_reads = false;
                    project_discovery_focus_ = SourceText{primary->path, primary->root, {}, primary->sha256, {}, primary->first_root};
                }
            }
            if (!project_pool_) project_pool_ = std::make_unique<DotnetProjects>();
            SearchContext workspace = *context;
            workspace.allowed_roots = config.workspace_roots;
            const auto plan = project_pool_->prepare(workspace, primary, reverse, whole_workspace,
                [&](const fs::path& path, const std::string& framework) {
                    return evaluate_dotnet_project(config, path, framework, control);
                }, [&](const SourceText& project) {
                    control.check();
                    return project_profile(config, project, workspace).key == config.key;
                }, [&] { control.check(); }, control.cancelled, std::chrono::milliseconds(config.project_idle_ms),
                config.project_budget, control.deadline, !background);
            project_partial_ = plan.partial;
            project_syntax_only_ = plan.syntax_only;
            managed_tracking_limit_.store(std::max(kMaxTrackedProjects, plan.projects.size() + kMaxTrackedProjects));
            if (require_complete && plan.partial) {
                std::string why;
                for (const auto& blocker : plan.blockers) why += "\n  " + blocker;
                throw SymbolLookupFailure("project dependency graph is incomplete; semantic writes are blocked" +
                    (why.empty() ? std::string() : ". Blocking:" + why),
                    J::Object{{"code", "project_loading"}, {"reason", "incomplete_project_graph"}, {"project_loading", project_pool_->status()}});
            }
            if (plan.fingerprint != project_fingerprint_) {
                stop();
                config.command = project_base_command_;
                project_fingerprint_ = plan.fingerprint;
            }
        }
        if (config.managed_projects && project_fingerprint_.empty())
            fail("managed C# backend requires a project-loading context before startup");
        if (process_.h) return;
        try {
            start_impl(control);
        } catch (const IndexWarmingFailure&) {
            throw;
        } catch (const std::exception& error) {
            if (control.cancelled && control.cancelled->load()) throw;
            throw LspFailure("language server " + config.server + " failed to start: " + error.what());
        }
    }

    void start_impl(const Control& control) {
        if (process_.h) return;
        // Managed C# already has project-aware idle unloading. Other backends release their
        // entire job after five minutes without requests; the next operation starts them again.
        // Create this thread on first use, never for a temporary observational status session.
        if (!config.managed_projects && !project_reaper_.joinable()) {
            project_reaper_ = std::jthread([this](std::stop_token stop) {
                while (!stop.stop_requested()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    if (stop.stop_requested()) break;
                    std::unique_lock lock(mutex, std::try_to_lock);
                    if (!lock) {
                        // A long operation is still using this session; its runtime is not idle time.
                        last_request_ticks_.store(Clock::now().time_since_epoch().count(), std::memory_order_relaxed);
                        continue;
                    }
                    if (!process_.h) continue;
                    const auto ticks = last_request_ticks_.load(std::memory_order_relaxed);
                    const auto used = Clock::time_point{Clock::duration{ticks}};
                    if (ticks && Clock::now() - used >= std::chrono::milliseconds(kServerIdleMs))
                        this->stop();
                }
            });
        }
        {
            std::lock_guard lock(messages_mutex_);
            ready_ = false; ever_ready_ = false; status_seen_ = false; quiescent_ = true; announces_status_ = false;
            status_message_.clear(); status_health_.clear(); progress_.clear(); initialized_at_ = {};
            last_activity_ = Clock::now();
        }
        // The watch starts before the server reads the tree, so no change made meanwhile is missed.
        if (config.indexes_workspace && !config.managed_projects) {
            watch_ = std::make_unique<DirectoryWatch>(config.root);
            for (const auto& root : config.workspace_roots)
                if (PathLess{}(root.wstring(), config.root.wstring()) || PathLess{}(config.root.wstring(), root.wstring()))
                    extra_watches_.push_back(std::make_unique<DirectoryWatch>(root));
        }
        // SAFETY (#93): state folders sit under the server's root (.shgrep\lsp-state). They are made from that root
        // without following links or junctions, and stay pinned against replacement while the server runs, so a
        // junction at .shgrep or below cannot send the server's writes outside the workspace.
        state_pins_.clear();
        if (!config.state_directories.empty()) {
            SearchContext state_context;
            state_context.allowed_roots = {config.state_root.empty() ? config.root : config.state_root};
            for (const auto& directory : config.state_directories) {
                try {
                    state_pins_.push_back(pin_workspace_metadata_directory(state_context, directory));
                } catch (const std::exception& e) {
                    state_pins_.clear();
                    fail("cannot create language server state folder " + utf8(directory.wstring()) + ": " + e.what());
                }
            }
        }
        SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
        Handle child_input, child_output, child_error;
        HANDLE a = nullptr, b = nullptr;
        if (!CreatePipe(&a, &b, &security, 0)) fail("cannot create LSP stdin pipe");
        child_input.reset(a); input_.reset(b);
        if (!SetHandleInformation(input_.h, HANDLE_FLAG_INHERIT, 0)) fail("cannot isolate LSP stdin");
        if (!CreatePipe(&a, &b, &security, 0)) fail("cannot create LSP stdout pipe");
        output_.reset(a); child_output.reset(b);
        if (!SetHandleInformation(output_.h, HANDLE_FLAG_INHERIT, 0)) fail("cannot isolate LSP stdout");
        HANDLE stderr_copy = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_ERROR_HANDLE), GetCurrentProcess(),
                             &stderr_copy, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
            stderr_copy = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr);
            if (stderr_copy == INVALID_HANDLE_VALUE) fail("cannot prepare LSP stderr");
        }
        child_error.reset(stderr_copy);
        job_.reset(CreateJobObjectW(nullptr, nullptr));
        if (!job_.h) fail("cannot create LSP process job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job_.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) fail("cannot configure LSP process job");
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        std::vector<unsigned char> storage(bytes);
        auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) fail("cannot prepare LSP process attributes");
        HANDLE inherited[]{child_input.h, child_output.h, child_error.h};
        if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr)) {
            DeleteProcThreadAttributeList(attributes); fail("cannot isolate LSP child handles");
        }
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = child_input.h;
        startup.StartupInfo.hStdOutput = child_output.h;
        startup.StartupInfo.hStdError = child_error.h;
        startup.lpAttributeList = attributes;
        std::wstring command;
        for (const auto& part : config.command) {
            if (!command.empty()) command.push_back(L' ');
            command += quoted(wide(part));
        }
        // Configuration overrides inherited values, but cannot override the mandatory offline policy.
        auto child_environment = config.environment;
        for (const auto& [name, value] : offline_environment()) {
            std::erase_if(child_environment, [&](const auto& item) {
                return CompareStringOrdinal(item.first.data(), static_cast<int>(item.first.size()), name.data(),
                                            static_cast<int>(name.size()), TRUE) == CSTR_EQUAL;
            });
            child_environment.emplace_back(name, value);
        }
        std::wstring environment;
        if (!child_environment.empty()) {
            std::vector<std::wstring> entries;
            if (wchar_t* block = GetEnvironmentStringsW()) {
                for (const wchar_t* entry = block; *entry; entry += wcslen(entry) + 1) {
                    const std::wstring_view text(entry);
                    const size_t equals = text.find(L'=', 1);  // "=C:=C:\\dir" entries start with '='
                    const bool overridden = std::any_of(child_environment.begin(), child_environment.end(), [&](const auto& item) {
                        return equals == item.first.size() &&
                            CompareStringOrdinal(entry, static_cast<int>(equals), item.first.data(), static_cast<int>(item.first.size()), TRUE) == CSTR_EQUAL;
                    });
                    if (!overridden) entries.emplace_back(text);
                }
                FreeEnvironmentStringsW(block);
            }
            for (const auto& [name, value] : child_environment) entries.push_back(name + L"=" + value);
            // CreateProcess expects the block sorted by name, case-insensitively.
            std::sort(entries.begin(), entries.end(), [](const std::wstring& a, const std::wstring& b) {
                const size_t na = a.find(L'=', 1), nb = b.find(L'=', 1);
                return CompareStringOrdinal(a.data(), static_cast<int>(std::min(na, a.size())),
                                            b.data(), static_cast<int>(std::min(nb, b.size())), TRUE) == CSTR_LESS_THAN;
            });
            for (const auto& entry : entries) { environment += entry; environment.push_back(L'\0'); }
            environment.push_back(L'\0');
        }
        PROCESS_INFORMATION process{};
        const BOOL created = CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            environment.empty() ? nullptr : environment.data(),
            (config.working_directory.empty() ? config.root : config.working_directory).c_str(), &startup.StartupInfo, &process);
        const DWORD error = GetLastError();
        DeleteProcThreadAttributeList(attributes);
        if (!created) fail("cannot start LSP command (Windows error " + std::to_string(error) + ")");
        process_.reset(process.hProcess);
        Handle thread(process.hThread);
        if (!AssignProcessToJobObject(job_.h, process_.h)) {
            TerminateProcess(process_.h, 1); fail("cannot assign language server to its process job");
        }
        if (ResumeThread(thread.h) == static_cast<DWORD>(-1)) fail("cannot resume language server");
        process_started_at_ = Clock::now();
        child_input.reset(); child_output.reset(); child_error.reset();
        {
            std::lock_guard lock(writer_mutex_);
            writer_stopping_ = false; write_done_ = true; write_ok_ = true; outgoing_.clear();
        }
        reader_ = std::thread([this] { reader_loop(); });
        writer_ = std::thread([this] { writer_loop(); });
        J::Array workspace_folders;
        if (!config.workspace_roots.empty()) {
            for (const auto& root : config.workspace_roots)
                workspace_folders.emplace_back(J::Object{{"uri", uri(root)}, {"name", utf8(root.filename().wstring())}});
        } else workspace_folders.emplace_back(J::Object{{"uri", uri(config.root)}, {"name", utf8(config.root.filename().wstring())}});
        J initialize = request("initialize", J::Object{
            {"processId", static_cast<int64_t>(GetCurrentProcessId())}, {"rootUri", uri(config.root)}, {"locale", "en"},
            {"clientInfo", J::Object{{"name", "shgrep"}, {"version", "0.3.0"}}},
            {"workspaceFolders", std::move(workspace_folders)},
            {"initializationOptions", config.initialization},
            {"capabilities", J::Object{
                {"general", J::Object{{"positionEncodings", J::Array{"utf-16"}}}},
                {"workspace", J::Object{{"configuration", true}, {"workspaceFolders", true}, {"applyEdit", false},
                    {"workspaceEdit", J::Object{{"documentChanges", true}, {"failureHandling", "undo"}}},
                    {"fileOperations", J::Object{{"dynamicRegistration", true}, {"didCreate", true}, {"didRename", true}, {"willRename", true}, {"didDelete", true}}}}},
                {"textDocument", J::Object{
                    {"documentSymbol", J::Object{{"hierarchicalDocumentSymbolSupport", true}, {"dynamicRegistration", true}, {"symbolKind", J::Object{{"valueSet", J::Array{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26}}}}}},
                    {"definition", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
                    {"declaration", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
                    {"typeDefinition", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
                    {"implementation", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
                    {"typeHierarchy", J::Object{{"dynamicRegistration", true}}},
                    {"rename", J::Object{{"prepareSupport", true}, {"dynamicRegistration", true}}},
                    {"references", J::Object{{"dynamicRegistration", true}}},
                    {"hover", J::Object{{"dynamicRegistration", true}, {"contentFormat", J::Array{"markdown", "plaintext"}}}},
                    {"publishDiagnostics", J::Object{{"versionSupport", true}, {"relatedInformation", true}}},
                    {"diagnostic", J::Object{{"dynamicRegistration", false}, {"relatedDocumentSupport", false}}},
                    {"synchronization", J::Object{{"dynamicRegistration", false}, {"didSave", true}}}
                }},
                {"experimental", J::Object{{"serverStatusNotification", true}}},
                {"window", J::Object{{"workDoneProgress", true}}}
            }}
        }, control);
        const J* capabilities = initialize.get("capabilities");
        if (!capabilities) fail("language server initialize response has no capabilities");
        capabilities_ = *capabilities;
        if (const J* info = initialize.get("serverInfo"); info && std::holds_alternative<J::Object>(info->value))
            announces_status_ = str(*info, "name").find("rust-analyzer") != std::string::npos;
        if (str(capabilities_, "positionEncoding", "utf-16") != "utf-16") fail("language server did not negotiate UTF-16 positions");
        const J* sync = capabilities_.get("textDocumentSync");
        sync_kind_ = sync ? static_cast<int>(std::holds_alternative<int64_t>(sync->value) ? sync->integer() : number(*sync, "change", 0)) : 0;
        if (sync_kind_ != 1 && sync_kind_ != 2) fail("language server does not support live document synchronization");
        notify("initialized", J::Object{}, control);
        initialized_at_ = Clock::now();
        notify("workspace/didChangeConfiguration", J::Object{{"settings", config.settings}}, control);
        if (config.managed_projects && project_pool_) {
            J::Array projects;
            for (const auto& path : project_pool_->requested()) projects.emplace_back(uri(path));
            if (projects.empty()) {
                std::lock_guard lock(messages_mutex_);
                roslyn_projects_ready_ = true;
            } else {
                notify("project/open", J::Object{{"projects", std::move(projects)}}, control);
            }
        }
        { std::lock_guard lock(messages_mutex_); last_activity_ = Clock::now(); }
    }
    void require(const char* capability) const {
        // COMPAT: Some servers register navigation features after "initialized", so a
        //   request right after start waits up to 3 seconds for registrations before calling a feature missing.
        const auto settle = initialized_at_ + std::chrono::seconds(3);
        while (!supports(capability) && Clock::now() < settle) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (!supports(capability)) fail(std::string("language server lacks ") + capability);
    }
    static std::string capability_method(const std::string& capability) {
        static const std::map<std::string, std::string> names{
            {"documentSymbolProvider","textDocument/documentSymbol"}, {"definitionProvider","textDocument/definition"},
            {"declarationProvider","textDocument/declaration"}, {"typeDefinitionProvider","textDocument/typeDefinition"},
            {"implementationProvider","textDocument/implementation"}, {"referencesProvider","textDocument/references"},
            {"typeHierarchyProvider","textDocument/prepareTypeHierarchy"},
            {"hoverProvider","textDocument/hover"}, {"renameProvider","textDocument/rename"},
            {"diagnosticProvider","textDocument/diagnostic"}};
        auto it = names.find(capability); return it == names.end() ? capability : it->second;
    }
    bool supports(const char* capability) const {
        const J* p = capabilities_.get(capability);
        if (p && (std::holds_alternative<J::Object>(p->value) || (std::holds_alternative<bool>(p->value) && p->boolean()))) return true;
        const std::string method = capability_method(capability);
        sync::LockGuard lock(registrations_mutex_);
        for (const auto& [id, entry] : registrations_) { (void)id; if (entry.method == method) return true; }
        return false;
    }
    void drain(const Control& control) {
        for (;;) {
            J message;
            {
                std::lock_guard lock(messages_mutex_);
                if (messages_.empty()) return;
                message = std::move(messages_.front().message); queued_bytes_ -= messages_.front().bytes; messages_.pop_front();
            }
            if (message.get("method")) answer(message, control);
        }
    }
    // CONTRACT: waits for a status-announcing server to finish loading, but stops 5 s short of the deadline and
    //   proceeds, so a server that never settles still answers instead of timing out.
    void service_pending(const Control& control) {
        drain(control);
        if (!announces_status_) return;
        const auto give_up = control.deadline - std::chrono::seconds(5);
        for (;;) {
            {
                std::unique_lock lock(messages_mutex_);
                if (status_seen_ && quiescent_) return;
                if (!reader_error_.empty()) fail(reader_error_);
                if (Clock::now() >= give_up) return;
                messages_ready_.wait_for(lock, std::chrono::milliseconds(50));
            }
            control.check();
            drain(control);
        }
    }
    bool file_operation(const std::string& name, const fs::path& path, bool directory = false) const {
        std::vector<J> options;
        const J* workspace = capabilities_.get("workspace");
        const J* operations = workspace ? workspace->get("fileOperations") : nullptr;
        if (const J* configured = operations ? operations->get(name) : nullptr) options.push_back(*configured);
        {
            sync::LockGuard lock(registrations_mutex_);
            for (const auto& [id, entry] : registrations_) { (void)id;
                if (entry.method == "workspace/" + name + "Files") options.push_back(entry.options);
            }
        }
        for (const auto& option : options) {
            const J* filters = option.get("filters");
            if (!filters) continue;
            for (const auto& filter : filters->array()) {
                if (!str(filter, "scheme").empty() && str(filter, "scheme") != "file") continue;
                const J* pattern = filter.get("pattern");
                if (!pattern) continue;
                const std::string kind = str(*pattern, "matches");
                if ((kind == "file" && directory) || (kind == "folder" && !directory)) continue;
                const J* settings = pattern->get("options");
                if (file_glob(wide(str(*pattern, "glob")), path.wstring(), settings && flag(*settings, "ignoreCase"))) return true;
            }
        }
        return false;
    }
    bool prepare_rename() const {
        const J* rename = capabilities_.get("renameProvider");
        return rename && std::holds_alternative<J::Object>(rename->value) && flag(*rename, "prepareProvider");
    }
    bool project_partial() const { return config.managed_projects && project_partial_; }
    bool project_syntax_only() const { return config.managed_projects && project_syntax_only_; }
    const ProjectLoad* managed_project_load_locked(const fs::path& path) const {
        const auto key = [](const fs::path& value) {
            std::wstring text = value.lexically_normal().wstring();
            if (text.starts_with(L"\\\\?\\UNC\\")) text = L"\\\\" + text.substr(8);
            else if (text.starts_with(L"\\\\?\\")) text.erase(0, 4);
            std::replace(text.begin(), text.end(), L'/', L'\\');
            return text;
        };
        const auto wanted = key(path);
        for (const auto& [file, state] : project_loads_) {
            const auto candidate = key(fs::path(file));
            if (CompareStringOrdinal(wanted.data(), static_cast<int>(wanted.size()),
                candidate.data(), static_cast<int>(candidate.size()), TRUE) == CSTR_EQUAL) return &state;
        }
        return nullptr;
    }
    J managed_project_status() const {
        if (!project_pool_) return J::Object{{"projects", J::Array{}}, {"state", "not_started"}};
        J result = project_pool_->status();
        auto& status = std::get<J::Object>(result.value);
        if (!project_discovery_error_.empty()) status["discovery_error"] = project_discovery_error_;
        auto& rows = std::get<J::Array>(status.at("projects").value);
        std::lock_guard lock(messages_mutex_);
        for (auto& row : rows) {
            if (str(row, "state") != "requested") continue;
            auto& object = std::get<J::Object>(row.value);
            if (!process_.h) object["state"] = "unloaded";
            else if (const auto* load = managed_project_load_locked(fs::path(wide(str(row, "path"))))) {
                object["state"] = load->state;
                if (!load->message.empty()) object["message"] = load->message;
            } else if (roslyn_projects_ready_) {
                object["state"] = "initialization_complete";
            }
        }
        return result;
    }
    J status(bool full = false) {
        J::Object result{{"language_id", config.language}, {"server", config.server},
                         {"root", utf8(config.root.wstring())},
                         {"open_documents", static_cast<int64_t>(documents_.size())}};
        result["uptime_seconds"] = process_started_at_ == Clock::time_point{} || !process_.h ||
            WaitForSingleObject(process_.h, 0) != WAIT_TIMEOUT ? J(nullptr) :
            J(static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - process_started_at_).count()));
        if (process_.h) {
            result["process_id"] = static_cast<uint64_t>(GetProcessId(process_.h));
            PROCESS_MEMORY_COUNTERS_EX counters{};
            counters.cb = sizeof(counters);
            if (K32GetProcessMemoryInfo(process_.h, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters))) {
                result["memory"] = J::Object{
                    {"working_set_bytes", static_cast<uint64_t>(counters.WorkingSetSize)},
                    {"peak_working_set_bytes", static_cast<uint64_t>(counters.PeakWorkingSetSize)},
                    {"private_bytes", static_cast<uint64_t>(counters.PrivateUsage)}};
            } else {
                result["memory"] = J::Object{{"error", "cannot read process memory"},
                    {"windows_error", static_cast<uint64_t>(GetLastError())}};
            }
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            if (job_.h && QueryInformationJobObject(job_.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits), nullptr)) {
                result["job_peak_memory_bytes"] = static_cast<uint64_t>(limits.PeakJobMemoryUsed);
            }
        }
        J::Array language_ids{config.language};
        std::set<std::string> seen{config.language};
        for (const auto& [extension, language] : config.extension_languages) {
            (void)extension;
            if (seen.insert(language).second) language_ids.emplace_back(language);
        }
        result.emplace("language_ids", std::move(language_ids));
        {
            sync::LockGuard lock(registrations_mutex_);
            if (full) {
                J::Array dynamic;
                std::set<std::string> dynamic_seen;
                for (const auto& [id, entry] : registrations_) {
                    (void)id;
                    if (dynamic_seen.insert(entry.method).second) dynamic.push_back(entry.method);
                }
                result.emplace("capabilities", capabilities_);
                result.emplace("dynamic_methods", std::move(dynamic));
                if (std::holds_alternative<J::Object>(config.details.value))
                    for (const auto& [key, value] : config.details.object()) result.emplace(key, value);
            }
        }
        {
            std::lock_guard progress_lock(messages_mutex_);
            const std::string busy = indexing_locked();
            std::string state = readiness_state_locked();
            if (last_activity_ == Clock::time_point{}) {
                if (state != "failed") state = "not_started";
            } else if (state != "ready" && state != "failed" &&
                       Clock::now() - last_activity_ >= std::chrono::seconds(180)) {
                state = "stuck";
            }
            const std::string display_busy = state == "not_started" ? "not started" :
                state == "stuck" ? "no server activity for 180 seconds" : busy;
            result["ready"] = state == "ready";
            result["indexing_state"] = state;
            if (state == "failed") result["failure_reason"] = reader_error_.empty() ? busy : reader_error_;
            if (state == "stuck")
                result["stuck_reason"] = "no server activity for 180 seconds while waiting for readiness";
            if (config.indexes_workspace)
                result["indexing"] = (state == "not_started" || state == "stuck") ?
                    display_busy : (busy.empty() ? std::string("complete") : busy);
            if (const Progress* progress = indexing_progress_locked()) {
                J::Object details{{"title", progress->title}};
                if (progress->percentage >= 0) details.emplace("percentage", progress->percentage);
                if (!progress->message.empty()) details.emplace("message", progress->message);
                result["indexing_progress"] = std::move(details);
            }
            if (announces_status_ && status_seen_) {
                J::Object details{{"quiescent", quiescent_}};
                if (!status_message_.empty()) details.emplace("message", status_message_);
                if (!status_health_.empty()) details.emplace("health", status_health_);
                result["server_status"] = std::move(details);
            }
        }
        if (config.managed_projects) {
            result["project_loading"] = managed_project_status();
            result["project_idle_ms"] = config.project_idle_ms;
            result["project_budget"] = static_cast<uint64_t>(config.project_budget);
            J::Array roots;
            for (const auto& root : config.workspace_roots) roots.emplace_back(utf8(root.wstring()));
            result["workspace_roots"] = std::move(roots);
        }
        result["idle_timeout_ms"] = config.managed_projects ? config.project_idle_ms : kServerIdleMs;
        // Issue #51: what keeps this server's data on the machine.
        result["egress"] = J::Object{
            {"telemetry_and_downloads", config.bundled
                ? "disabled by server settings and enforced offline environment; binary audit unverified"
                : "offline environment only; check this server's own settings"},
            {"firewall", config.command.empty() ? std::string("unknown")
                                                : firewall_record(fs::path(wide(config.command.front())))}};
        return result;
    }
    int64_t document_version(const SourceText& source) const {
        const auto it = documents_.find(source.path.wstring());
        if (it == documents_.end()) fail("workspace edit targets a file that was not synchronized before the request");
        return it->second.version;
    }
    J diagnostics(const SourceText& source, const Control& control) {
        service_pending(control);
        const std::string id = document_uri(source);
        if (supports("diagnosticProvider")) {
            J::Object params{{"textDocument", J::Object{{"uri", id}}}};
            if (const J* provider = capabilities_.get("diagnosticProvider"))
                if (std::holds_alternative<J::Object>(provider->value))
                    if (const J* identifier = provider->get("identifier")) params.emplace("identifier", *identifier);
            J result = request("textDocument/diagnostic", std::move(params), control);
            if (str(result, "kind") != "full" || !result.get("items")) fail("expected a full diagnostic report");
            return J::Object{{"items", *result.get("items")}, {"version_verified", true}, {"transport", "pull"}};
        }
        for (;;) {
            control.check();
            {
                std::unique_lock lock(messages_mutex_);
                auto found = published_diagnostics_.find(diagnostic_key(source.path));
                if (found != published_diagnostics_.end()) {
                    const J* version = found->second.params.get("version");
                    if (!version || (std::holds_alternative<int64_t>(version->value) && version->integer() == document_version(source)))
                        return J::Object{{"items", *found->second.params.get("diagnostics")},
                            {"version_verified", version != nullptr}, {"transport", "publish"}};
                }
                if (!reader_error_.empty()) fail(reader_error_);
                messages_ready_.wait_for(lock, std::chrono::milliseconds(10));
            }
            service_pending(control);
        }
    }
    void saved(const SourceText& source, const Control& control) {
        const J* sync = capabilities_.get("textDocumentSync");
        const J* save = sync && std::holds_alternative<J::Object>(sync->value) ? sync->get("save") : nullptr;
        if (!save || (std::holds_alternative<bool>(save->value) && !save->boolean())) return;
        J::Object params{{"textDocument", J::Object{{"uri", document_uri(source)}}}};
        if (std::holds_alternative<J::Object>(save->value) && flag(*save, "includeText")) params.emplace("text", source.text);
        notify("textDocument/didSave", std::move(params), control);
    }
    int sync_one(const SourceText& source, const Control& control) {
        const std::string id = uri(source.path);
        const std::wstring key = source.path.wstring();
        auto found = documents_.find(key);
        if (found == documents_.end()) {
            {
                std::lock_guard lock(messages_mutex_);
                forget_diagnostics(diagnostic_key(source.path), false);
                diagnosed_.insert(diagnostic_key(source.path));  // before didOpen, so the server's first report is kept
                // Opening can start new server work (clangd loads the compile database on first open).
                if (config.indexes_workspace) { last_activity_ = Clock::now(); ready_ = false; }
            }
            notify("textDocument/didOpen", J::Object{{"textDocument", J::Object{
                {"uri", id}, {"languageId", document_language_id(config, source.path)}, {"version", 1}, {"text", source.text}}}}, control);
            documents_.emplace(key, Document{source.sha256, id, 1, text_end(source.text)});
            return 1;
        }
        if (found->second.hash == source.sha256) return 0;
        {
            std::lock_guard lock(messages_mutex_);
            forget_diagnostics(diagnostic_key(source.path), false);
            if (config.indexes_workspace) { last_activity_ = Clock::now(); ready_ = false; }
        }
        J::Object change{{"text", source.text}};
        if (sync_kind_ == 2) change.emplace("range", J::Object{{"start", Position{}.json()}, {"end", found->second.end.json()}});
        notify("textDocument/didChange", J::Object{
            {"textDocument", J::Object{{"uri", found->second.uri}, {"version", ++found->second.version}}},
            {"contentChanges", J::Array{std::move(change)}}}, control);
        found->second.hash = source.sha256;
        found->second.end = text_end(source.text);
        return 2;
    }
    void synchronize(const SourceText* primary, const SearchContext& context, const Control& control, bool save = false) {
        if (config.indexes_workspace && watches_ok()) { synchronize_changed(primary, context, control, save); return; }
        std::vector<std::string> paths;
        if (config.managed_projects && project_pool_) paths = project_pool_->sources();
        else {
            std::vector<fs::path> roots = config.workspace_roots;
            if (roots.empty()) roots.push_back(config.root);
            for (const auto& root : roots) {
                auto listed = source_paths(context, utf8(root.wstring()), config.extensions, control.deadline, control.cancelled);
                paths.insert(paths.end(), listed.begin(), listed.end());
            }
        }
        paths.erase(std::remove_if(paths.begin(), paths.end(), [&](const auto& path) {
            return path_excluded(config, fs::path(wide(path)));
        }), paths.end());
        if (primary) paths.push_back(utf8(primary->path.wstring()));
        std::set<std::wstring, PathLess> seen;
        J::Array changes;
        for (const auto& path : paths) {
            control.check();
            SourceText source;
            try {
                if (config.managed_projects) {
                    bool exists = false;
                    (void)source_descriptor(context, path, nullptr, true, &exists);
                    if (!exists) continue; // Generated Compile items need not exist before a build.
                }
                source = read_source_text(context, path);
            }
            catch (const std::exception& e) {
                if (std::string(e.what()).ends_with(" is not valid Unicode source text")) continue;
                throw;
            }
            const std::string id = uri(source.path);
            if (!seen.insert(source.path.wstring()).second) continue;
            const int type = sync_one(source, control);
            if (type) {
                changes.push_back(J::Object{{"uri", id}, {"type", type}});
                if (save) saved(source, control);
                if (save && type == 1 && file_operation("didCreate", source.path))
                    notify("workspace/didCreateFiles", J::Object{{"files", J::Array{J::Object{{"uri", id}}}}}, control);
            }
        }
        for (auto it = documents_.begin(); it != documents_.end();) {
            if (seen.contains(it->first)) { ++it; continue; }
            if (path_excluded(config, fs::path(it->first)) ||
                (config.managed_projects && project_pool_ && !project_pool_->contains_source(fs::path(it->first)))) {
                notify("textDocument/didClose", J::Object{{"textDocument", J::Object{{"uri", it->second.uri}}}}, control);
                { std::lock_guard lock(messages_mutex_); forget_diagnostics(diagnostic_key(it->first), true); }
                it = documents_.erase(it);
                continue;
            }
            // Explicitly opened hidden/ignored files still exist outside the default walk selection.
            std::optional<SourceText> existing;
            bool removed = false;
            try { existing = read_source_text(context, utf8(it->first)); }
            catch (const std::exception& e) {
                const std::string message = e.what();
                if (message.ends_with(" is not valid Unicode source text")) {
                    // Close an older valid snapshot without telling the server the file was deleted.
                } else if (message.find(": not found") != std::string::npos) {
                    removed = true;
                } else throw;
            }
            if (existing) {
                const int type = sync_one(*existing, control);
                if (type) { changes.push_back(J::Object{{"uri", it->second.uri}, {"type", type}}); if (save) saved(*existing, control); }
                ++it;
                continue;
            }
            notify("textDocument/didClose", J::Object{{"textDocument", J::Object{{"uri", it->second.uri}}}}, control);
            if (removed) changes.push_back(J::Object{{"uri", it->second.uri}, {"type", 3}});
            { std::lock_guard lock(messages_mutex_); forget_diagnostics(diagnostic_key(it->first), true); }
            it = documents_.erase(it);
        }
        if (!changes.empty()) notify("workspace/didChangeWatchedFiles", J::Object{{"changes", std::move(changes)}}, control);
    }
    bool is_open(const SourceText& source) const { return documents_.contains(source.path.wstring()); }
    // indexes_workspace: keeps the server's answers current without opening the workspace. Files Windows reported as
    // changed are opened and stay open; open documents are rechecked; the server reads everything else from disk.
    void synchronize_changed(const SourceText* primary, const SearchContext& context, const Control& control, bool save) {
        std::vector<fs::path> changed;
        bool reload = false;
        // The server must answer from every change made before this request, including ones Windows has not reported
        // yet; a sync cookie waits for those (at most 10 s, or the request's deadline).
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            control.deadline - decltype(control.deadline)::clock::now());
        const auto wait = std::clamp(left, std::chrono::milliseconds(0), std::chrono::milliseconds(10000));
        // Every watched root must confirm; a lasting failure of any root falls back for all of them.
        DirectoryWatch::Sync synced = DirectoryWatch::Sync::confirmed;
        for (DirectoryWatch* watch : watches()) {
            const DirectoryWatch::Sync result = watch->sync(wait);
            // Each watch reports only its own state; any one asking for a reload forces it for the request.
            bool watch_reload = false;
            watch->take(changed, watch_reload);
            reload = reload || watch_reload;
            if (result == DirectoryWatch::Sync::no_cookie) synced = result;
            else if (result != DirectoryWatch::Sync::confirmed && synced == DirectoryWatch::Sync::confirmed) synced = result;
        }
        if (!reload && synced != DirectoryWatch::Sync::confirmed) {
            // SAFETY: unconfirmed, the watch cannot vouch that it reported every change made before this request, and
            // the server answers from its own index for every file not open, which could then be stale.
            if (synced == DirectoryWatch::Sync::no_cookie) {
                // Lasting (.shgrep unwritable, or a link or junction there): stop relying on the watch, as for a root
                // that cannot be watched; synchronize() then rereads every source file itself.
                reset_watches();
                synchronize(primary, context, control, save);
                return;
            }
            server_fail("the workspace watcher did not confirm within " + std::to_string(wait.count()) +
                        " ms that it had reported every change made before this request, so the language server could "
                        "answer from stale files; no semantic answer was produced. Retry the request");
        }
        if (!reload) {
            const size_t relevant = static_cast<size_t>(std::count_if(changed.begin(), changed.end(), [&](const fs::path& path) {
                const std::string extension = language_extension(path);
                return std::find(config.extensions.begin(), config.extensions.end(), extension) != config.extensions.end();
            }));
            reload = pinned_.size() + relevant > kPinnedDocuments;
        }
        if (reload) {
            // SAFETY: some changes are unknown, so the server's index may be stale; a restart makes it reread the tree.
            stop();
            start(control);
            changed.clear();
            if (!watches_ok()) { synchronize(primary, context, control, save); return; }
        }
        J::Array events;
        auto publish = [&](const SourceText& source, int type) {
            if (!type) return;
            if (save) saved(source, control);
            if (save && type == 1 && file_operation("didCreate", source.path))
                notify("workspace/didCreateFiles", J::Object{{"files", J::Array{J::Object{{"uri", uri(source.path)}}}}}, control);
        };
        auto read = [&](const std::wstring& path, bool& removed) -> std::optional<SourceText> {
            removed = false;
            try { return read_source_text(context, utf8(path)); }
            catch (const std::exception& e) {
                const std::string message = e.what();
                removed = message.find(": not found") != std::string::npos;
                if (!removed && !message.ends_with(" is a directory; use list_dir") &&
                    !message.ends_with(" is not valid Unicode source text")) throw;
            }
            return std::nullopt;
        };
        std::set<std::wstring, PathLess> seen;
        for (const auto& path : changed) {
            control.check();
            const std::string extension = language_extension(path);
            if (std::find(config.extensions.begin(), config.extensions.end(), extension) == config.extensions.end()) continue;
            const std::wstring key = path.lexically_normal().wstring();
            if (!seen.insert(key).second) continue;
            if (!documents_.contains(key) && (path_excluded(config, path) || walk_skips(root_of(path), path))) continue;
            bool removed = false;
            const auto source = read(key, removed);
            if (!source) {
                // Deleted, a folder now, or legacy-encoded: the server must not keep answering from old bytes.
                close_document(key, control);
                pinned_.erase(key);
                if (removed) events.push_back(J::Object{{"uri", uri(path)}, {"type", 3}});
                continue;
            }
            pinned_.insert(source->path.wstring());
            publish(*source, sync_one(*source, control));
            events.push_back(J::Object{{"uri", uri(source->path)}, {"type", 2}});
        }
        // Open documents can change before their report arrives, e.g. a write that is still in flight.
        for (auto it = documents_.begin(); it != documents_.end();) {
            control.check();
            const std::wstring key = it->first;
            ++it;  // sync_one never inserts or erases an existing document; close_document erases only key
            if (seen.contains(key)) continue;
            bool removed = false;
            const auto current = read(key, removed);
            if (!current) {
                close_document(key, control);
                pinned_.erase(key);
                if (removed) events.push_back(J::Object{{"uri", uri(fs::path(key))}, {"type", 3}});
                continue;
            }
            const int type = sync_one(*current, control);
            if (type) { pinned_.insert(current->path.wstring()); publish(*current, type); }
        }
        if (primary) {
            if (save) pinned_.insert(primary->path.wstring());
            publish(*primary, sync_one(*primary, control));
            touch(primary->path.wstring());
        }
        evict(control);
        if (!events.empty()) notify("workspace/didChangeWatchedFiles", J::Object{{"changes", std::move(events)}}, control);
    }
    void close_document(const std::wstring& key, const Control& control) {
        const auto it = documents_.find(key);
        if (it == documents_.end()) return;
        notify("textDocument/didClose", J::Object{{"textDocument", J::Object{{"uri", it->second.uri}}}}, control);
        { std::lock_guard lock(messages_mutex_); forget_diagnostics(diagnostic_key(it->first), true); }
        documents_.erase(it);
    }
    // Opens (or updates) a file a request reads; in indexes_workspace sessions it is closed again by evict().
    void use(const SourceText& source, const Control& control) {
        sync_one(source, control);
        if (config.indexes_workspace) { touch(source.path.wstring()); evict(control); }
    }
    // COMPAT: tsserver builds a project from tsconfig.json or jsconfig.json; without either, a script belongs to an
    //   inferred project of the files that are open, so references, implementations and renames miss every other
    //   file (a Vite JSX app without jsconfig). Before such cross-file requests, the scripts under the nearest
    //   package.json folder are opened, skipping dependency and build-output folders, up to kLooseScripts files.
    bool open_loose_scripts(const SourceText& source, const SearchContext& context, const Control& control) {
        // false: more than kLooseScripts scripts were found, so the inferred project misses the rest; callers mark
        // reads partial and refuse writes that need every reference (F10).
        if (config.language != "javascript") return true;
        const auto exists = [](const fs::path& path) { return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES; };
        fs::path package_root;
        for (fs::path parent = source.path.parent_path();; parent = parent.parent_path()) {
            if (exists(parent / L"tsconfig.json") || exists(parent / L"jsconfig.json")) return true;  // tsserver loads it
            if (package_root.empty() && exists(parent / L"package.json")) package_root = parent;
            if (parent == source.root || parent == parent.parent_path()) break;
        }
        if (package_root.empty()) package_root = source.path.parent_path();
        static const std::set<std::string> skipped{"node_modules", "dist", "build", "out", "coverage", ".next", ".nuxt", ".output"};
        // source_paths walks a configured root; the filter enters only the package folder and skips dependency and
        // build-output folders inside it, so the rest of the root is never listed.
        const std::string package = lower(utf8(package_root.lexically_relative(source.root).generic_wstring()));
        const bool whole_root = package.empty() || package == ".";
        const auto inside_package = [&](const std::string& relative, bool folder) {
            const std::string child = lower(relative);
            if (!whole_root) {
                const bool ancestor = folder && (package == child || package.starts_with(child + "/"));
                if (!ancestor && !child.starts_with(package + "/")) return false;
                if (ancestor) return true;
            }
            const size_t slash = child.rfind('/');
            return !folder || !skipped.contains(slash == std::string::npos ? child : child.substr(slash + 1));
        };
        size_t opened = 0;
        for (const auto& path : source_paths(context, utf8(source.root.wstring()), config.extensions, control.deadline,
                                             control.cancelled, inside_package)) {
            control.check();
            if (++opened > kLooseScripts) return false;
            try { sync_one(read_source_text(context, path), control); }
            catch (const std::exception& e) {
                if (!std::string(e.what()).ends_with(" is not valid Unicode source text")) throw;
            }
        }
        return true;
    }
    static constexpr size_t kLooseScripts = 1000;
    // A file shgrep just wrote: the server must see these bytes now, not when the watcher reports them.
    void pin(const SourceText& source, const Control& control) {
        if (pinned_.size() >= kPinnedDocuments && !pinned_.contains(source.path.wstring())) {
            // The next synchronize restarts the server, which then reads these bytes from disk.
            use(source, control);
            return;
        }
        pinned_.insert(source.path.wstring());
        std::erase_if(recent_, [&](const std::wstring& item) { return !PathLess{}(item, source.path.wstring()) && !PathLess{}(source.path.wstring(), item); });
        sync_one(source, control);
    }
    void touch(const std::wstring& key) {
        if (pinned_.contains(key)) return;
        std::erase_if(recent_, [&](const std::wstring& item) { return !PathLess{}(item, key) && !PathLess{}(key, item); });
        recent_.push_back(key);
    }
    void evict(const Control& control) {
        while (recent_.size() > kRecentDocuments) {
            const std::wstring key = recent_.front();
            recent_.pop_front();
            if (!pinned_.contains(key)) close_document(key, control);
        }
    }
    // CONTRACT: messages_mutex_ held. An active indexing progress report, when available.
    const Progress* indexing_progress_locked() const {
        for (const auto& [token, progress] : progress_) {
            (void)token;
            const std::string title = lower(progress.title);
            // Diagnostics and checks do not change what the workspace index knows.
            if (title.find("diagnos") != std::string::npos || title.find("check") != std::string::npos ||
                title.find("lint") != std::string::npos) continue;
            return &progress;
        }
        return nullptr;
    }
    // CONTRACT: messages_mutex_ held.
    bool index_ready_locked(const SourceText* source = nullptr) const {
        if (!reader_error_.empty() || !roslyn_project_error_.empty() || initialized_at_ == Clock::time_point{}) return false;
        if (!config.indexes_workspace) return true;
        if (config.managed_projects && project_pool_ && !roslyn_projects_ready_) return false;
        if (project_loading_locked(source)) return false;
        if (announces_status_) return status_seen_ && quiescent_;
        if (indexing_progress_locked()) return false;
        return ready_ || (last_activity_ != Clock::time_point{} &&
                          Clock::now() - last_activity_ >= std::chrono::seconds(2));
    }
    // CONTRACT: messages_mutex_ held.
    std::string readiness_state_locked(const SourceText* source = nullptr) {
        if (!reader_error_.empty() || !roslyn_project_error_.empty()) return "failed";
        if (config.managed_projects && project_pool_)
            for (const auto& path : project_pool_->requested()) {
                const auto* load = managed_project_load_locked(path);
                if (load && load->state == "failed") return "failed";
            }
        if (!index_ready_locked(source)) {
            if (announces_status_ && status_seen_) return "indexing";
            if (project_loading_locked(source)) return "indexing";
            if (indexing_progress_locked()) return "indexing";
            return "starting";
        }
        ready_ = ever_ready_ = true;
        return "ready";
    }
    // CONTRACT: messages_mutex_ held. Empty once the server's index covers the workspace, else what it is doing.
    std::string indexing_locked(const SourceText* source = nullptr) {
        if (index_ready_locked(source)) { ready_ = ever_ready_ = true; return {}; }
        if (config.managed_projects && project_pool_) {
            size_t loaded = 0;
            for (const auto& path : project_pool_->requested()) {
                const auto* load = managed_project_load_locked(path);
                if (load && load->state == "failed") return "project failed to load: " + utf8(path.wstring());
                if (load && load->state == "loaded") ++loaded;
            }
            if (!roslyn_projects_ready_)
                return "loading projects " + std::to_string(loaded) + " of " + std::to_string(project_pool_->requested().size());
        }
        if (project_loading_locked(source)) return "loading a project";
        if (announces_status_) {
            if (!status_seen_ || status_message_.empty()) return "loading the project";
            return status_message_;
        }
        if (const Progress* progress = indexing_progress_locked()) {
            std::string busy = progress->title.empty() ? "working" : progress->title;
            if (!progress->message.empty()) busy += ": " + progress->message;
            if (progress->percentage >= 0) busy += " " + std::to_string(progress->percentage) + "%";
            return busy;
        }
        return "starting";
    }
    // CONTRACT: messages_mutex_ held.
    J readiness_details_locked(const std::string& phase, const SourceText* source = nullptr) {
        const std::string busy = indexing_locked(source);
        const std::string state = readiness_state_locked(source);
        J::Object details{{"code", "index_warming"}, {"reason", "index_in_progress"},
                          {"phase", phase}, {"ready", false}, {"indexing_state", state},
                          {"server", config.server}};
        if (state == "failed") {
            details["reason"] = reader_error_.empty() ? "project_load_failed" : "server_failed_to_start";
            details["failure_reason"] = !reader_error_.empty() ? reader_error_ :
                !roslyn_project_error_.empty() ? roslyn_project_error_ : busy;
        } else if (phase == "startup") {
            details["reason"] = "server_start_timeout";
            details["failure_reason"] = "language server did not answer before timeout_ms";
        }
        if (!busy.empty()) details.emplace("indexing", busy);
        if (const Progress* progress = indexing_progress_locked()) {
            J::Object progress_details{{"title", progress->title}};
            if (progress->percentage >= 0) progress_details.emplace("percentage", progress->percentage);
            if (!progress->message.empty()) progress_details.emplace("message", progress->message);
            details.emplace("indexing_progress", std::move(progress_details));
        }
        if (announces_status_ && status_seen_) {
            J::Object server_status{{"quiescent", quiescent_}};
            if (!status_message_.empty()) server_status.emplace("message", status_message_);
            if (!status_health_.empty()) server_status.emplace("health", status_health_);
            details.emplace("server_status", std::move(server_status));
        }
        append_project_details_locked(details, source);
        return details;
    }
    // CONTRACT: messages_mutex_ held.
    // record: false when the failure only decides a response's partial flag (warming_timeout) and is not raised; the
    //   index log then stays free of one warning per answered file.
    IndexWarmingFailure warming_failure_locked(const std::string& phase, const SourceText* source = nullptr,
                                               bool record = true) {
        J details = readiness_details_locked(phase, source);
        const std::string state = str(details, "indexing_state", "starting");
        const std::string busy = str(details, "indexing");
        std::string message;
        if (state == "failed" || (phase == "startup" && !reader_error_.empty())) {
            const std::string reason = str(details, "failure_reason", "language server did not answer before timeout_ms");
            message = "language server " + config.server + " failed to start: " + reason;
        } else if (phase == "startup") {
            // Alive but not initialized yet: a slow cold start (Roslyn loads MSBuild), not a failure.
            message = "index_warming: language server " + config.server + " is still starting and did not finish "
                      "initializing within timeout_ms; no semantic result was returned. Retry shortly or pass a larger timeout_ms";
        } else {
            message = "index_warming: language server " + config.server + " (" + config.language + ", root " +
                      utf8(config.root.wstring()) + ") is ";
            message += state == "indexing" ? "still indexing the workspace" : "starting";
            if (!busy.empty()) message += " (" + busy + ")";
            if (source) message += " while answering for " + utf8(source->path.wstring());
            message += "; no semantic result was returned. Retry shortly or pass a larger timeout_ms";
        }
        // The log keeps which server held the request, phase and readiness, even when the caller only sees a retry.
        if (record) index_log(true, message + " [phase " + phase + ", state " + state + "]");
        return IndexWarmingFailure(std::move(message), std::move(details));
    }
    bool ever_ready() {
        std::lock_guard lock(messages_mutex_);
        return ever_ready_;
    }
    std::optional<IndexWarmingFailure> warming_timeout(const SourceText* source = nullptr) {
        std::lock_guard lock(messages_mutex_);
        if (index_ready_locked(source)) { ready_ = ever_ready_ = true; return std::nullopt; }
        return warming_failure_locked(initialized_at_ == Clock::time_point{} ? "startup" : "workspace_index", source, false);
    }
    // CONTRACT: cross-file answers come from the server's index, so they wait until it covers the whole workspace.
    void wait_indexed(const Control& control, const SourceText* source = nullptr) {
        if (!config.indexes_workspace) {
            std::lock_guard lock(messages_mutex_);
            if (!reader_error_.empty()) fail(reader_error_);
            if (initialized_at_ != Clock::time_point{}) ready_ = ever_ready_ = true;
            return;
        }
        const auto give_up = control.deadline - std::chrono::seconds(2);
        auto next_progress_log = Clock::now() + std::chrono::seconds(2);
        bool logged_wait = false;
        try {
            for (;;) {
                {
                    std::unique_lock lock(messages_mutex_);
                    if (!reader_error_.empty()) fail(reader_error_);
                    if (!roslyn_project_error_.empty())
                        throw SymbolLookupFailure("C# project failed to load",
                            J::Object{{"code", "project_loading"}, {"reason", "project_load_failed"},
                                      {"message", roslyn_project_error_}});
                    if (config.managed_projects && project_pool_) {
                        for (const auto& path : project_pool_->requested()) {
                            const auto* load = managed_project_load_locked(path);
                            if (load && load->state == "failed")
                                throw SymbolLookupFailure("C# project failed to load: " + utf8(path.wstring()),
                                    J::Object{{"code", "project_loading"}, {"reason", "project_load_failed"},
                                        {"project", utf8(path.wstring())}, {"message", load->message}});
                        }
                    }
                    const std::string busy = indexing_locked(source);
                    if (busy.empty()) {
                        ready_ = ever_ready_ = true;
                        if (logged_wait) {
                            lock.unlock();
                            index_log(false, "language server " + config.server + " (" + config.language +
                                ", root " + utf8(config.root.wstring()) + ") is ready");
                        }
                        return;
                    }
                    if (Clock::now() >= give_up) throw warming_failure_locked("workspace_index", source);
                    if (Clock::now() >= next_progress_log) {
                        next_progress_log = Clock::now() + std::chrono::seconds(5);
                        logged_wait = true;
                        lock.unlock();
                        index_log(false, "waiting for language server " + config.server + " (" + config.language +
                            ", root " + utf8(config.root.wstring()) + "): " + busy);
                        lock.lock();
                    }
                    messages_ready_.wait_for(lock, std::chrono::milliseconds(50));
                }
                control.check();
                drain(control);
            }
        } catch (const LspTimeoutFailure&) {
            std::lock_guard lock(messages_mutex_);
            if (!index_ready_locked(source)) throw warming_failure_locked("workspace_index", source);
            throw;
        }
    }
    std::string document_uri(const SourceText& source) const {
        const auto it = documents_.find(source.path.wstring());
        if (it == documents_.end()) fail("file has not been synchronized with the language server");
        return it->second.uri;
    }
    bool has_document(const SourceText& source) const {
        const auto it = documents_.find(source.path.wstring());
        return it != documents_.end() && it->second.hash == source.sha256;
    }
    void assert_current(const SourceText& source) const {
        if (!has_document(source)) fail("source changed during LSP navigation; retry the request");
    }
private:
    // Handles that keep the server's state folders from being replaced while it runs (start_impl).
    std::vector<std::shared_ptr<void>> state_pins_;
    // Last, so it is joined before any state it observes is destroyed.
    std::jthread project_reaper_;
};
std::mutex registry_mutex;
std::map<std::string, std::shared_ptr<Session>> registry;
std::shared_ptr<Session> session_for(const Config& config) {
    std::lock_guard lock(registry_mutex);
    auto it = registry.find(config.key);
    if (it != registry.end()) return it->second;
    // Retire superseded configuration for the same workspace/language once no query holds it.
    for (auto i = registry.begin(); i != registry.end();) {
        // Workspace-wide servers keep one instance per toolchain profile side by side; only per-root servers retire.
        if (config.workspace_roots.empty() && i->second->config.workspace_roots.empty() && i->second.use_count() == 1 &&
            i->second->config.root == config.root && i->second->config.language == config.language)
            i = registry.erase(i);
        else ++i;
    }
    auto session = std::make_shared<Session>(config);
    registry.emplace(config.key, session); return session;
}
std::shared_ptr<Session> existing_session_for(const Config& config) {
    std::lock_guard lock(registry_mutex);
    const auto it = registry.find(config.key);
    return it == registry.end() ? nullptr : it->second;
}
std::vector<std::shared_ptr<Session>> existing_sessions_for(const Config& config) {
    if (config.workspace_roots.empty()) {
        if (auto session = existing_session_for(config)) return {std::move(session)};
        return {};
    }
    // Workspace-wide servers run one instance per toolchain profile (.NET SDK or TypeScript version).
    std::vector<std::shared_ptr<Session>> sessions;
    std::lock_guard lock(registry_mutex);
    for (const auto& [key, session] : registry)
        if (key == config.key || key.starts_with(config.key + ":sdk:") || key.starts_with(config.key + ":ts:"))
            sessions.push_back(session);
    return sessions;
}
// PERF: restart and directory moves start a bundled server only when it already runs or the root holds a file it serves.
//   Status uses the same eligibility check to report it without launching it, so checking a Lua workspace never launches clangd.
bool worth_starting(const Config& config, const SearchContext& context, const Control& control) {
    if (!config.bundled) return true;
    if (!existing_sessions_for(config).empty()) return true;
    if (!config.workspace_roots.empty()) {
        for (const auto& root : config.workspace_roots)
            if (!source_paths(context, utf8(root.wstring()), config.extensions, control.deadline, control.cancelled).empty()) return true;
        return false;
    }
    return !source_paths(context, utf8(config.root.wstring()), config.extensions, control.deadline, control.cancelled).empty();
}

struct Symbol {
    std::string name, name_path;
    int64_t kind;
    Range extent, selection;
    int depth;
    bool has_body;
};


// CONTRACT (symbol index): a server's document symbols depend only on the file's bytes and the server
//   configuration, so each outline is kept under (configuration key, path) with the sha256 of the text it came
//   from, and reused while that file is unchanged. Per-file server round trips are the known cost on large
//   repositories (arXiv 2604.18413); Serena keeps a content-hash symbol cache the same way. Folder symbol searches
//   answer from it without opening the file in the server; a miss asks the server and fills it. Empty outlines are
//   kept only after the server's index was ready once; C# (syntax-only until its project loads) is never kept. Full outlines stay in memory up to kMaxSymbols
//   symbols (least recently used dropped first); each file's distinct names (up to kMaxNames) with their stamps are
//   also saved to %LOCALAPPDATA%\shgrep\symbol-names.bin, so restarts keep skipping unchanged files.
class SymbolIndex {
public:
    // Full outlines (every symbol with ranges) are large; names are small. The name layer decides which files a
    // folder search must read and keeps every file; the outline layer keeps the most recently used outlines up to
    // kMaxSymbols symbols, so a walk over a folder larger than that cannot evict what the next walk needs to skip.
    static constexpr size_t kMaxSymbols = 1'000'000;
    static constexpr size_t kMaxNames = 4'000'000;
    std::optional<std::vector<Symbol>> find(const std::string& key, const std::string& sha256) {
        std::lock_guard lock(mutex_);
        const auto found = outlines_.find(key);
        if (found == outlines_.end() || found->second.sha256 != sha256) return std::nullopt;
        order_.splice(order_.end(), order_, found->second.position);  // most recently used last
        return found->second.symbols;
    }
    // The distinct symbol names of a file whose size and last-write time still equal `stamp`, without reading the
    // file. Unchanged metadata is trusted and changed metadata means a re-read and re-hash (the mtime-then-hash rule
    // of LAFORGE, arXiv 2108.12469, and OxyMake, arXiv 2606.20989). The gap: a same-size edit inside one 100 ns
    // write-time tick.
    std::optional<std::vector<std::string>> names_stamped(const std::string& key, const std::string& stamp) {
        if (stamp.empty()) return std::nullopt;
        std::lock_guard lock(mutex_);
        const auto found = names_.find(key);
        if (found == names_.end() || found->second.stamp != stamp) return std::nullopt;
        found->second.used = true;
        return found->second.names;
    }
    // Attaches the metadata stamp taken before the read whose text hashed to sha256. A file changed between the stamp
    // and the read only makes the next lookup miss and re-read; it never pairs new metadata with old names.
    void attach_stamp(const std::string& key, const std::string& sha256, const std::string& stamp) {
        std::lock_guard lock(mutex_);
        if (const auto found = names_.find(key); found != names_.end() && found->second.sha256 == sha256 &&
            (found->second.stamp != stamp || !found->second.used)) {
            found->second.stamp = stamp;
            found->second.used = true;
            dirty_ = true;
        }
    }
    void store(const std::string& key, const std::string& sha256, const std::vector<Symbol>& symbols) {
        if (sha256.empty() || symbols.size() > kMaxSymbols) return;  // callers decide whether an empty outline is real
        std::vector<std::string> names;
        names.reserve(symbols.size());
        for (const auto& symbol : symbols) names.push_back(symbol.name);
        std::sort(names.begin(), names.end());
        names.erase(std::unique(names.begin(), names.end()), names.end());
        std::lock_guard lock(mutex_);
        // Names: one small entry per file; the same bytes keep their verified stamp.
        std::string stamp;
        if (const auto found = names_.find(key); found != names_.end()) {
            if (found->second.sha256 == sha256) stamp = std::move(found->second.stamp);
            name_total_ -= found->second.names.size();
            names_.erase(found);
        }
        if (name_total_ + names.size() <= kMaxNames) {
            name_total_ += names.size();
            names_.emplace(key, Names{sha256, std::move(stamp), std::move(names), true});
            dirty_ = true;
        }
        // Outlines: least recently used dropped first.
        if (const auto found = outlines_.find(key); found != outlines_.end()) {
            total_ -= found->second.symbols.size();
            order_.erase(found->second.position);
            outlines_.erase(found);
        }
        while (total_ + symbols.size() > kMaxSymbols && !order_.empty()) {
            if (const auto oldest = outlines_.find(order_.front()); oldest != outlines_.end()) {
                total_ -= oldest->second.symbols.size();
                outlines_.erase(oldest);
            }
            order_.pop_front();
        }
        order_.push_back(key);
        outlines_.emplace(key, Outline{sha256, symbols, std::prev(order_.end())});
        total_ += symbols.size();
    }
    // Persistence of the name layer (with stamps), so a restart keeps skipping unchanged files. The file lives under
    // %LOCALAPPDATA%\shgrep, outside every workspace: a file planted in a repository cannot hide its symbols. Only
    // stamped entries are written. A damaged, oversized or foreign file is ignored and replaced on the next save.
    void load(const std::wstring& path) {
        std::lock_guard lock(mutex_);
        path_ = path;
        if (path.empty()) return;
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return;
        LARGE_INTEGER size{};
        std::string bytes;
        if (GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= kMaxSavedBytes) {
            bytes.resize(static_cast<size_t>(size.QuadPart));
            DWORD read = 0;
            if (!ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) || read != bytes.size())
                bytes.clear();
        }
        CloseHandle(file);
        size_t at = 0;
        const auto take = [&](size_t count) -> std::optional<std::string_view> {
            if (bytes.size() - at < count) return std::nullopt;
            const std::string_view out(bytes.data() + at, count);
            at += count;
            return out;
        };
        const auto number = [&]() -> std::optional<uint32_t> {
            const auto raw = take(4);
            if (!raw) return std::nullopt;
            uint32_t value = 0;
            for (size_t i = 0; i < 4; ++i) value |= static_cast<uint32_t>(static_cast<unsigned char>((*raw)[i])) << (8 * i);
            return value;
        };
        const auto text = [&]() -> std::optional<std::string> {
            const auto length = number();
            if (!length) return std::nullopt;
            const auto raw = take(*length);
            if (!raw) return std::nullopt;
            return std::string(*raw);
        };
        std::unordered_map<std::string, Names> loaded;
        size_t loaded_names = 0;
        const auto magic = take(kSavedMagic.size());
        auto entries = magic && *magic == kSavedMagic ? number() : std::nullopt;
        // Every entry holds at least four length fields, so a count larger than that allows is a damaged file.
        if (!entries || *entries > (bytes.size() - at) / 16) return;
        for (uint32_t i = 0; i < *entries; ++i) {
            auto key = text(), sha256 = text(), stamp = text();
            const auto count = number();
            if (!key || !sha256 || !stamp || !count || *count > (bytes.size() - at) / 4) return;
            Names entry{std::move(*sha256), std::move(*stamp), {}, false};
            entry.names.reserve(*count);
            for (uint32_t n = 0; n < *count; ++n) {
                auto name = text();
                if (!name) return;
                entry.names.push_back(std::move(*name));
            }
            loaded_names += entry.names.size();
            if (loaded_names > kMaxNames) return;
            loaded.emplace(std::move(*key), std::move(entry));
        }
        if (at != bytes.size()) return;
        names_ = std::move(loaded);
        name_total_ = loaded_names;
    }
    // Writes the name layer when it changed, at most every 30 seconds; atomic (temporary file, then replace).
    void save_if_due() {
        std::string bytes;
        std::wstring path;
        {
            std::lock_guard lock(mutex_);
            const auto now = Clock::now();
            if (!dirty_ || path_.empty() || (saved_ != Clock::time_point{} && now - saved_ < std::chrono::seconds(30))) return;
            const bool used_only = name_total_ > kMaxNames / 2;  // crowded: keep what this process needed
            const auto put_number = [&](size_t value) {
                for (size_t i = 0; i < 4; ++i) bytes.push_back(static_cast<char>((value >> (8 * i)) & 0xff));
            };
            const auto put_text = [&](std::string_view value) { put_number(value.size()); bytes.append(value); };
            size_t count = 0;
            for (const auto& [key, entry] : names_) count += !entry.stamp.empty() && (!used_only || entry.used);
            bytes.append(kSavedMagic);
            put_number(count);
            for (const auto& [key, entry] : names_) {
                if (entry.stamp.empty() || (used_only && !entry.used)) continue;
                put_text(key);
                put_text(entry.sha256);
                put_text(entry.stamp);
                put_number(entry.names.size());
                for (const auto& name : entry.names) put_text(name);
            }
            if (bytes.size() > kMaxSavedBytes) return;
            dirty_ = false;
            saved_ = now;
            path = path_;
        }
        CreateDirectoryW(path.substr(0, path.rfind(L'\\')).c_str(), nullptr);
        const std::wstring temporary = path + L".tmp";
        HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        bool written = file != INVALID_HANDLE_VALUE;
        for (size_t at = 0; written && at < bytes.size();) {
            DWORD wrote = 0;
            const DWORD chunk = static_cast<DWORD>(std::min<size_t>(bytes.size() - at, 1 << 20));
            written = WriteFile(file, bytes.data() + at, chunk, &wrote, nullptr) && wrote == chunk;
            at += wrote;
        }
        if (file != INVALID_HANDLE_VALUE) {
            written = written && FlushFileBuffers(file);
            CloseHandle(file);
        }
        if (!written || !MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            const DWORD error = GetLastError();
            DeleteFileW(temporary.c_str());
            index_log(true, "symbol index names not saved to " + utf8(path) + " (Windows error " +
                            std::to_string(error) + "); the next folder search tries again");
            std::lock_guard lock(mutex_);
            dirty_ = true;
        }
    }
private:
    static constexpr std::string_view kSavedMagic = "SHGSYMN1";
    static constexpr int64_t kMaxSavedBytes = 256LL << 20;
    struct Outline {
        std::string sha256;
        std::vector<Symbol> symbols;
        std::list<std::string>::iterator position;
    };
    struct Names {
        std::string sha256;
        std::string stamp;  // size and write time seen just before the read that produced sha256; empty if unverified
        std::vector<std::string> names;  // distinct symbol names, sorted
        bool used = false;  // looked up or written by this process (a crowded saved file keeps only these)
    };
    std::mutex mutex_;
    std::list<std::string> order_;  // outline keys, least recently used first
    std::unordered_map<std::string, Outline> outlines_;
    std::unordered_map<std::string, Names> names_;
    size_t total_ = 0, name_total_ = 0;
    bool dirty_ = false;          // names changed since the last save
    Clock::time_point saved_{};  // last save
    std::wstring path_;           // the saved file; empty without LOCALAPPDATA
};
// Process lifetime on purpose: request threads can still be reading it while the server exits.
// %LOCALAPPDATA%\shgrep\symbol-names.bin, or empty when LOCALAPPDATA is unset (the index then stays in memory).
std::wstring symbol_names_path() {
    wchar_t base[MAX_PATH] = {};
    const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
    if (!length || length >= MAX_PATH) return {};
    return std::wstring(base, length) + L"\\shgrep\\symbol-names.bin";
}
SymbolIndex& symbol_index() {
    static auto* index = [] {
        auto* created = new SymbolIndex;
        created->load(symbol_names_path());
        return created;
    }();
    return *index;
}
std::string symbol_index_key(const Config& config, const fs::path& path) {
    return config.key + "\n" + lower(utf8(path.wstring()));
}
// Size and last-write time from the file's metadata, without opening it; empty when unavailable, for a folder or a
// link. Only a cache key: every read still goes through the guarded read_source_text.
// The \\?\ spelling of an absolute path, so long paths work; separators are made native first.
std::wstring long_path_name(fs::path path) {
    std::wstring name = path.make_preferred().wstring();
    if (!name.starts_with(L"\\\\?\\"))
        name = name.starts_with(L"\\\\") ? L"\\\\?\\UNC\\" + name.substr(2) : L"\\\\?\\" + name;
    return name;
}
std::string file_stamp(const fs::path& path) {
    const std::wstring name = long_path_name(path);
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(name.c_str(), GetFileExInfoStandard, &data)) return {};
    if (data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) return {};
    return std::to_string(data.nFileSizeHigh) + ":" + std::to_string(data.nFileSizeLow) + ":" +
           std::to_string(data.ftLastWriteTime.dwHighDateTime) + ":" + std::to_string(data.ftLastWriteTime.dwLowDateTime);
}
// Content roles (workspace_profile.hpp layer 3) by lower-case path, with the stamp their head was read under; a
// changed stamp reads the head again. Process memory only; cleared when it reaches kMaxEntries.
class RoleCache {
public:
    static constexpr size_t kMaxEntries = 500'000;
    std::optional<FileRole> find(const std::string& key, const std::string& stamp) {
        std::lock_guard lock(mutex_);
        const auto found = roles_.find(key);
        if (found == roles_.end() || found->second.first != stamp) return std::nullopt;
        return found->second.second;
    }
    void store(const std::string& key, const std::string& stamp, FileRole role) {
        std::lock_guard lock(mutex_);
        if (roles_.size() >= kMaxEntries) roles_.clear();
        roles_[key] = {stamp, role};
    }
private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::pair<std::string, FileRole>> roles_;
};
RoleCache& role_cache() {
    static auto* cache = new RoleCache;  // process lifetime, like symbol_index
    return *cache;
}
std::string namespace_source_name(const J& item, const std::wstring& source, const std::string& supplied) {
    const int64_t kind = number(item, "kind", 0);
    const J* selection = item.get("selectionRange");
    if ((kind != 2 && kind != 3 && kind != 4) || supplied.empty()) return supplied;
    const J* extent = item.get("range");
    if (!extent) if (const J* location = item.get("location")) extent = location->get("range");
    if (!selection && !extent) return supplied;
    const Range selected = range(selection ? *selection : *extent);
    size_t anchor = offset(source, selected.start);
    size_t selected_end = selection ? offset(source, selected.end) : anchor;
    if (anchor >= source.size() || selected_end < anchor) return supplied;
    if (!selection) {
        // Flat SymbolInformation has no identifier range. Read only its declaration header.
        size_t at = anchor;
        for (;;) {
            while (at < source.size() && std::iswspace(source[at])) ++at;
            const size_t word = at;
            while (at < source.size() && (std::iswalnum(source[at]) || source[at] == L'_')) ++at;
            const std::wstring_view token(source.data() + word, at - word);
            if (token == L"namespace" || token == L"package" || token == L"module" || token == L"mod") {
                while (at < source.size() && std::iswspace(source[at])) ++at;
                anchor = selected_end = at;
                break;
            }
            if (token != L"inline" && token != L"export" && token != L"declare" &&
                token != L"public" && token != L"private") break;
        }
    }
    const auto identifier = [](wchar_t c) {
        return c >= 128 || std::iswalnum(c) || c == L'_' || c == L'$' || c == L'@' || c == L'`';
    };
    const auto space = [](wchar_t c) { return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n'; };
    size_t begin = anchor, end = anchor;
    while (begin && identifier(source[begin - 1])) --begin;
    while (end < source.size() && identifier(source[end])) ++end;
    if (begin == end) return supplied; // Quoted external modules keep the server's exact name.
    for (;;) {
        size_t separator = begin;
        while (separator && space(source[separator - 1])) --separator;
        size_t previous = separator;
        if (previous && (source[previous - 1] == L'.' || source[previous - 1] == L'\\')) --previous;
        else if (previous >= 2 && source.compare(previous - 2, 2, L"::") == 0) previous -= 2;
        else break;
        while (previous && space(source[previous - 1])) --previous;
        const size_t token_end = previous;
        while (previous && identifier(source[previous - 1])) --previous;
        if (token_end == previous) break;
        begin = previous;
    }
    for (;;) {
        size_t separator = end;
        while (separator < source.size() && space(source[separator])) ++separator;
        size_t next = separator;
        if (next < source.size() && (source[next] == L'.' || source[next] == L'\\')) ++next;
        else if (source.compare(next, 2, L"::") == 0) next += 2;
        else break;
        while (next < source.size() && space(source[next])) ++next;
        const size_t token_begin = next;
        while (next < source.size() && identifier(source[next])) ++next;
        if (next == token_begin) break;
        end = next;
    }
    if (selected_end > end) return supplied;
    size_t keyword_end = begin;
    while (keyword_end && space(source[keyword_end - 1])) --keyword_end;
    size_t keyword_begin = keyword_end;
    while (keyword_begin && identifier(source[keyword_begin - 1])) --keyword_begin;
    const std::wstring_view keyword(source.data() + keyword_begin, keyword_end - keyword_begin);
    if (keyword != L"namespace" && keyword != L"package" && keyword != L"module" && keyword != L"mod")
        return supplied;
    std::wstring qualified;
    for (size_t i = begin; i < end; ++i) if (!space(source[i])) qualified += source[i];
    const std::string recovered = utf8(qualified);
    const bool suffix = recovered.size() > supplied.size() && recovered.ends_with(supplied) &&
        (recovered[recovered.size() - supplied.size() - 1] == '.' ||
         recovered[recovered.size() - supplied.size() - 1] == ':' ||
         recovered[recovered.size() - supplied.size() - 1] == '\\');
    return recovered == supplied || suffix ? recovered : supplied;
}

std::string normalized_name(const J& item, const std::string& language, const std::wstring& source) {
    std::string name = namespace_source_name(item, source, str(item, "name"));
    // SolidLSP's Lua adapter normalizes qualified method/function names at each tree level.
    if (language == "lua" && (number(item, "kind", 0) == 6 || number(item, "kind", 0) == 12)) {
        size_t separator = name.rfind('.');
        if (separator == std::string::npos) separator = name.rfind(':');
        if (separator != std::string::npos) name.erase(0, separator + 1);
    }
    // COMPAT: Roslyn names members with their signature ("Run(int) : int", "_orders : List<int>", "OrderService()").
    //   Name paths use the bare name, so Run matches and overloads get Run[0]/Run[1]; generic arguments stay.
    if (language == "csharp" && number(item, "kind", 0) != 2 && number(item, "kind", 0) != 3 && number(item, "kind", 0) != 4) {
        if (const size_t type = name.find(" : "); type != std::string::npos) name.resize(type);
        if (const size_t parameters = name.find('('); parameters != std::string::npos && parameters > 0) name.resize(parameters);
        while (!name.empty() && name.back() == ' ') name.pop_back();
        if (name.empty()) name = str(item, "name");
    }
    return name;
}
void flatten(const J& items, const std::string& parent, int depth, std::vector<Symbol>& result,
             const std::string& language, const std::wstring& source, const Control& control) {
    if (std::holds_alternative<std::nullptr_t>(items.value)) return;
    // SolidLSP ls.py: sibling overloads receive stable, zero-based indices.
    std::map<std::string, size_t> totals, indices;
    std::vector<std::string> names;
    names.reserve(items.array().size());
    for (const auto& item : items.array()) {
        control.check();
        names.push_back(normalized_name(item, language, source));
        ++totals[str(item, "containerName") + "\n" + names.back()];
    }
    std::map<std::string, std::string> namespace_aliases;
    for (size_t i = 0; i < items.array().size(); ++i) {
        const auto& item = items.array()[i];
        const int64_t kind = number(item, "kind", 0);
        if (kind != 2 && kind != 3 && kind != 4) continue;
        const std::string supplied = str(item, "name");
        const auto [at, inserted] = namespace_aliases.emplace(supplied, names[i]);
        if (!inserted && at->second != names[i]) at->second.clear();
    }
    size_t item_index = 0;
    for (const auto& item : items.array()) {
        control.check();
        const std::string& name = names[item_index++];
        const std::string sibling_key = str(item, "containerName") + "\n" + name;
        const size_t overload = indices[sibling_key]++;
        const std::string component = totals[sibling_key] > 1 ? name + "[" + std::to_string(overload) + "]" : name;
        const J* extent = item.get("range"), *selection = item.get("selectionRange");
        const bool hierarchical = extent && selection;
        if (!extent) {
            const J* location = item.get("location");
            extent = location ? location->get("range") : nullptr;
        }
        if (!extent) continue;
        std::string prefix = hierarchical ? parent : str(item, "containerName");
        if (!hierarchical) {
            const auto alias = namespace_aliases.find(prefix);
            if (alias != namespace_aliases.end() && !alias->second.empty()) prefix = alias->second;
        }
        Symbol symbol{name, prefix.empty() ? component : prefix + "/" + component,
                      number(item, "kind", 0), range(*extent),
                      range(selection ? *selection : *extent), depth, hierarchical};
        if (symbol.selection.start < symbol.extent.start || symbol.extent.end < symbol.selection.end)
            server_fail("language server returned a selection outside its symbol range");
        result.push_back(symbol);
        if (const J* children = item.get("children")) flatten(*children, symbol.name_path, depth + 1, result, language, source, control);
    }
}
std::string shown_path(const SourceText& source);

J symbol_lookup_details(Session& session, const SourceText& source, const std::string& reason,
                         std::string_view name_path = {}) {
    J::Object details{{"code", "symbol_lookup"}, {"reason", reason}, {"path", shown_path(source)}};
    if (!name_path.empty()) details.emplace("requested_name_path", std::string(name_path));
    const J project = session.project_details(source);
    if (std::holds_alternative<J::Object>(project.value))
        for (const auto& [key, value] : project.object()) details.emplace(key, value);
    return details;
}

std::vector<Symbol> symbols(Session& session, const SourceText& source, const Control& control) {
    session.require("documentSymbolProvider");
    if (!session.has_document(source)) {
        J details = symbol_lookup_details(session, source, "file_not_loaded");
        throw SymbolLookupFailure("symbol lookup could not run because the file is not loaded in the language server",
                                  std::move(details));
    }
    const J raw = session.request("textDocument/documentSymbol",
        J::Object{{"textDocument", J::Object{{"uri", session.document_uri(source)}}}}, control);
    std::vector<Symbol> result;
    flatten(raw, "", 0, result, session.config.language, wide(source.text), control);
    // An empty outline is kept only once the server's index has been ready: before that, empty can mean "not loaded".
    if (!session.config.managed_projects && (!result.empty() || session.ever_ready()))
        symbol_index().store(symbol_index_key(session.config, source.path), source.sha256, result);
    return result;
}
std::string_view symbol_kind_name(int64_t kind) {
    switch (kind) {
    case 1: return "file";
    case 2: return "module";
    case 3: return "namespace";
    case 4: return "package";
    case 5: return "class";
    case 6: return "method";
    case 7: return "property";
    case 8: return "field";
    case 9: return "constructor";
    case 10: return "enum";
    case 11: return "interface";
    case 12: return "function";
    case 13: return "variable";
    case 14: return "constant";
    case 15: return "string";
    case 16: return "number";
    case 17: return "boolean";
    case 18: return "array";
    case 19: return "object";
    case 20: return "key";
    case 21: return "null";
    case 22: return "enumMember";
    case 23: return "struct";
    case 24: return "event";
    case 25: return "operator";
    case 26: return "typeParameter";
    default: return "unknown";
    }
}
int64_t symbol_kind_id(std::string_view hint) {
    std::string normalized;
    normalized.reserve(hint.size());
    for (const unsigned char c : hint)
        normalized.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c));
    if (normalized == "file") return 1;
    if (normalized == "module") return 2;
    if (normalized == "namespace") return 3;
    if (normalized == "package") return 4;
    if (normalized == "class") return 5;
    if (normalized == "method") return 6;
    if (normalized == "property") return 7;
    if (normalized == "field") return 8;
    if (normalized == "constructor" || normalized == "ctor") return 9;
    if (normalized == "enum") return 10;
    if (normalized == "interface") return 11;
    if (normalized == "function") return 12;
    if (normalized == "variable") return 13;
    if (normalized == "constant") return 14;
    if (normalized == "string") return 15;
    if (normalized == "number") return 16;
    if (normalized == "boolean") return 17;
    if (normalized == "array") return 18;
    if (normalized == "object") return 19;
    if (normalized == "key") return 20;
    if (normalized == "null") return 21;
    if (normalized == "enummember") return 22;
    if (normalized == "struct") return 23;
    if (normalized == "event") return 24;
    if (normalized == "operator") return 25;
    if (normalized == "typeparameter") return 26;
    return 0;
}
class NamePathMatcher {
    struct Component { std::string_view name, index; };
    bool any_, anchored_, has_kind_{};
    int64_t kind_{};
    // Views borrow the caller's immutable pattern for this request.
    std::vector<Component> wanted_;

    static Component component(std::string_view text) {
        Component parts{text, {}};
        const size_t bracket = text.rfind('[');
        if (bracket != std::string_view::npos && text.ends_with("]") && bracket + 2 < text.size() &&
            text.find_first_not_of("0123456789", bracket + 1) == text.size() - 1) {
            parts.name = text.substr(0, bracket);
            parts.index = text.substr(bracket + 1, text.size() - bracket - 2);
            while (parts.index.size() > 1 && parts.index.front() == '0') parts.index.remove_prefix(1);
        }
        return parts;
    }
    static std::string_view generic_base_name(std::string_view name) {
        const size_t opening = name.find('<');
        if (opening == std::string_view::npos || opening == 0 || !name.ends_with(">")) return name;
        const std::string_view base = name.substr(0, opening);
        if (base == "operator" || base.ends_with("::operator") || base.ends_with(" operator")) return name;
        size_t depth = 0;
        for (size_t i = opening; i < name.size(); ++i) {
            if (name[i] == '<') ++depth;
            else if (name[i] == '>' && name[i - 1] != '-') {
                if (!depth) return name;
                if (--depth == 0 && i + 1 != name.size()) return name;
            }
        }
        return depth == 0 ? name.substr(0, opening) : name;
    }
public:
    explicit NamePathMatcher(std::string_view pattern)
        : any_(false), anchored_(pattern.starts_with("/")) {
        if (anchored_) pattern.remove_prefix(1);
        const size_t hash = pattern.rfind('#');
        if (hash != std::string_view::npos) {
            const int64_t requested_kind = symbol_kind_id(pattern.substr(hash + 1));
            if (requested_kind) {
                has_kind_ = true;
                kind_ = requested_kind;
                pattern = pattern.substr(0, hash);
            }
        }
        any_ = pattern.empty();
        if (any_) return;
        while (pattern.ends_with("/")) pattern.remove_suffix(1);
        for (size_t start = 0;;) {
            const size_t end = pattern.find('/', start);
            wanted_.push_back(component(pattern.substr(start, end - start)));
            if (end == std::string_view::npos) break;
            start = end + 1;
        }
    }
    bool matches(const Symbol& symbol, bool substring, bool generic_base = false) const {
        if (has_kind_ && symbol.kind != kind_) return false;
        if (any_) return true;
        if (matches_path(symbol.name_path, substring, generic_base)) return true;
        // Unnamed namespace containers stay visible in results, but callers can omit them in a lookup.
        if (symbol.name_path.find("(anonymous namespace)") != std::string::npos ||
            symbol.name_path.find("(unnamed namespace)") != std::string::npos) {
            std::string named_path;
            std::string_view remaining = symbol.name_path;
            bool omitted = false;
            for (;;) {
                const size_t slash = remaining.find('/');
                const std::string_view raw = remaining.substr(0, slash);
                const Component part = component(raw);
                if (slash != std::string_view::npos &&
                    (part.name == "(anonymous namespace)" || part.name == "(unnamed namespace)")) {
                    omitted = true;
                } else {
                    if (!named_path.empty()) named_path += '/';
                    named_path += raw;
                }
                if (slash == std::string_view::npos) break;
                remaining.remove_prefix(slash + 1);
            }
            if (omitted && matches_path(named_path, substring, generic_base)) return true;
        }
        // Rust document symbols name method containers "impl Type" or
        // "impl Trait for Type". Keep their canonical paths in results while
        // accepting Type/method for lookup. Explicit overload indices survive.
        std::string rust_path;
        bool has_impl = false;
        std::string_view remaining = symbol.name_path;
        for (;;) {
            const size_t slash = remaining.find('/');
            const Component part = component(remaining.substr(0, slash));
            std::string_view name = part.name;
            if (name.starts_with("impl<")) {
                size_t depth = 0, stop = 4;
                for (; stop < name.size(); ++stop) {
                    if (name[stop] == '<') ++depth;
                    else if (name[stop] == '>' && name[stop - 1] != '-' && depth && --depth == 0) { ++stop; break; }
                }
                if (stop < name.size() && name[stop] == ' ') {
                    name.remove_prefix(stop);
                    while (name.starts_with(" ")) name.remove_prefix(1);
                    has_impl = true;
                }
            } else if (name.starts_with("impl ")) {
                name.remove_prefix(5);
                has_impl = true;
            }
            if (name.data() != part.name.data()) {
                if (const size_t for_at = name.rfind(" for "); for_at != std::string_view::npos)
                    name.remove_prefix(for_at + 5);
                if (const size_t generic = name.find('<'); generic != std::string_view::npos)
                    name = name.substr(0, generic);
                while (name.ends_with(" ")) name.remove_suffix(1);
            }
            if (!rust_path.empty()) rust_path += '/';
            rust_path += name;
            if (!part.index.empty()) rust_path += "[" + std::string(part.index) + "]";
            if (slash == std::string_view::npos) break;
            remaining.remove_prefix(slash + 1);
        }
        if (has_impl && matches_path(rust_path, substring, generic_base)) return true;
        // clangd names an out-of-line member definition "Class::member" under its namespace, so it also matches the
        // name path Class/member.
        if (symbol.name_path.find("::") == std::string::npos) return false;
        std::string split;
        split.reserve(symbol.name_path.size());
        size_t generic_depth = 0;
        for (size_t i = 0; i < symbol.name_path.size(); ++i) {
            if (symbol.name_path[i] == '<') ++generic_depth;
            else if (symbol.name_path[i] == '>' && i && symbol.name_path[i - 1] != '-' && generic_depth) --generic_depth;
            if (!generic_depth && symbol.name_path.compare(i, 2, "::") == 0) {
                split.push_back('/');
                ++i;
            } else {
                split.push_back(symbol.name_path[i]);
            }
        }
        return matches_path(split, substring, generic_base);
    }
private:
    bool matches_path(std::string_view actual, bool substring, bool generic_base) const {
        bool available = true;
        for (size_t i = wanted_.size(); i > 0; --i) {
            if (!available) return false;
            const size_t slash = actual.rfind('/');
            const Component part = component(actual.substr(slash == std::string_view::npos ? 0 : slash + 1));
            if (slash == std::string_view::npos) available = false;
            else actual = actual.substr(0, slash);
            const Component& wanted = wanted_[i - 1];
            if (!wanted.index.empty() && wanted.index != part.index) return false;
            const std::string_view candidate = generic_base && wanted.name.find('<') == std::string_view::npos
                ? generic_base_name(part.name) : part.name;
            if (substring && i == wanted_.size()) {
                if (part.name.find(wanted.name) == std::string_view::npos &&
                    candidate.find(wanted.name) == std::string_view::npos) return false;
            } else if (part.name != wanted.name && candidate != wanted.name) return false;
        }
        return !anchored_ || !available;
    }
};
std::string shown_path(const SourceText& source) {
    // CONTRACT: a shown path reads back the same file. Relative paths resolve against the first root, so files of
    //   other roots are shown absolute; otherwise two roots' src/Helper.cs would look alike and follow-ups would
    //   open the first root's copy.
    if (!source.first_root) return utf8(source.path.wstring());
    return utf8(source.path.lexically_relative(source.root).generic_wstring());
}
J coordinates(Range r) {
    return J::Object{{"start_line", r.start.line + 1}, {"start_column", r.start.column + 1},
                     {"end_line", r.end.line + 1}, {"end_column", r.end.column + 1}};
}
J symbol_json(const Symbol& symbol, const SourceText& source, bool include_body, bool full_lines) {
    J::Object out{{"path", shown_path(source)}, {"name", symbol.name}, {"name_path", symbol.name_path}, {"kind", symbol.kind},
                   {"kind_name", std::string(symbol_kind_name(symbol.kind))},
                   {"line", symbol.selection.start.line + 1}, {"column", symbol.selection.start.column + 1},
                   {"range", coordinates(symbol.extent)}, {"selection_range", coordinates(symbol.selection)}, {"body_available", symbol.has_body}};
    if (include_body) {
        if (!symbol.has_body) server_fail("language server returned flat SymbolInformation without a reliable symbol-body range");
        const Range returned_range = full_lines ? body_lines_range(source, symbol.extent) : symbol.extent;
        out.emplace("body", body(source, returned_range));
        if (full_lines) out.emplace("body_range", coordinates(returned_range));
        out.emplace("sha256", source.sha256);
        out.emplace("mtime", source.mtime);
    }
    return out;
}
const Symbol& unique(Session& session, const SourceText& source,
                     const std::vector<Symbol>& symbols, const std::string& name) {
    J project_details = session.project_details(source);
    const std::string project_state = str(project_details, "project_state", "unknown");
    if (project_state == "loading") {
        if (auto warming = session.warming_timeout(&source)) throw *warming;
        J details = symbol_lookup_details(session, source, "index_in_progress", name);
        std::get<J::Object>(details.value)["code"] = "index_warming";
        std::get<J::Object>(details.value)["project_state"] = project_state;
        std::get<J::Object>(details.value)["indexing_state"] = "indexing";
        throw IndexWarmingFailure("language server is still loading the project; no semantic result was returned",
                                  std::move(details));
    }
    if (project_state == "failed") {
        J details = symbol_lookup_details(session, source, "project_not_loaded", name);
        std::get<J::Object>(details.value)["project_state"] = project_state;
        throw SymbolLookupFailure("the language server reported that the containing project failed to load",
                                  std::move(details));
    }
    const NamePathMatcher matcher(name);
    const Symbol* exact = nullptr;
    const std::string anchored = name.starts_with("/") ? name.substr(1) : name;
    size_t exact_count = 0;
    for (const auto& symbol : symbols)
        if (symbol.name_path == anchored && matcher.matches(symbol, false)) { exact = &symbol; ++exact_count; }
    if (exact_count == 1) return *exact;

    std::vector<const Symbol*> found;
    for (const auto& symbol : symbols) if (matcher.matches(symbol, false)) found.push_back(&symbol);
    if (found.empty())
        for (const auto& symbol : symbols) if (matcher.matches(symbol, false, true)) found.push_back(&symbol);
    if (found.size() > 1) {
        // Never widen to a shared ancestor: edits, navigation and diagnostics need one exact target.
        constexpr size_t max_ambiguity_candidates = 20;
        J::Array candidates;
        for (size_t i = 0; i < std::min(max_ambiguity_candidates, found.size()); ++i) {
            const Symbol& candidate = *found[i];
            candidates.emplace_back(J::Object{
                {"name_path", candidate.name_path},
                {"kind", candidate.kind},
                {"kind_name", std::string(symbol_kind_name(candidate.kind))},
                {"line", candidate.selection.start.line + 1},
                {"column", candidate.selection.start.column + 1}});
        }
        J details = symbol_lookup_details(session, source, "ambiguous_name_path", name);
        std::get<J::Object>(details.value).emplace("candidate_count", static_cast<int64_t>(found.size()));
        std::get<J::Object>(details.value).emplace("candidates_truncated", found.size() > max_ambiguity_candidates);
        std::get<J::Object>(details.value).emplace("candidates", std::move(candidates));
        std::string listed;
        for (size_t i = 0; i < std::min<size_t>(8, found.size()); ++i)
            listed += "\n  " + found[i]->name_path + " (" + std::string(symbol_kind_name(found[i]->kind)) + ", line " +
                      std::to_string(found[i]->selection.start.line + 1) + ")";
        if (found.size() > 8) listed += "\n  ... " + std::to_string(found.size() - 8) + " more";
        throw SymbolLookupFailure("ambiguous symbol name_path; nothing was selected or written. Use a candidate's exact "
                                  "name_path (overloads carry an index such as Name[0]), a kind hint, or a line/column position. "
                                  "Candidates:" + listed, std::move(details));
    }
    if (found.empty()) {
        if (symbols.empty()) {
            J details = symbol_lookup_details(session, source, "empty_document_symbol", name);
            const std::string state = str(details, "project_state", "unknown");
            if (state == "loading") {
                if (auto warming = session.warming_timeout(&source)) throw *warming;
                std::get<J::Object>(details.value)["code"] = "index_warming";
                std::get<J::Object>(details.value)["reason"] = "index_in_progress";
                std::get<J::Object>(details.value)["indexing_state"] = "indexing";
                throw IndexWarmingFailure("language server is still loading the project; no semantic result was returned",
                                          std::move(details));
            }
            if (state == "failed") {
                std::get<J::Object>(details.value)["reason"] = "project_not_loaded";
                throw SymbolLookupFailure("the language server reported that the containing project failed to load",
                                          std::move(details));
            }
            throw SymbolLookupFailure("documentSymbol returned no symbols for " + shown_path(source),
                                      std::move(details));
        }

        const auto components = [](std::string_view path) {
            std::vector<std::string_view> result;
            if (path.starts_with("/")) path.remove_prefix(1);
            for (size_t start = 0; start < path.size();) {
                const size_t slash = path.find('/', start);
                const size_t scope = path.find("::", start);
                const bool scoped = scope != std::string_view::npos &&
                    (slash == std::string_view::npos || scope < slash);
                const size_t end = scoped ? scope : slash;
                result.push_back(path.substr(start, end - start));
                if (end == std::string_view::npos) break;
                start = end + (scoped ? 2 : 1);
            }
            return result;
        };
        constexpr size_t max_component_bytes = 256;
        const auto edit_distance = [max_component_bytes](std::string_view left, std::string_view right) {
            if (left == right) return size_t{0};
            const size_t difference = left.size() > right.size() ? left.size() - right.size() : right.size() - left.size();
            if (left.size() > max_component_bytes || right.size() > max_component_bytes)
                return max_component_bytes + difference;
            if (left.size() > right.size()) std::swap(left, right);
            std::vector<size_t> previous(right.size() + 1), current(right.size() + 1);
            for (size_t column = 0; column <= right.size(); ++column) previous[column] = column;
            for (size_t row = 1; row <= left.size(); ++row) {
                current[0] = row;
                for (size_t column = 1; column <= right.size(); ++column) {
                    current[column] = std::min({
                        previous[column] + 1,
                        current[column - 1] + 1,
                        previous[column - 1] + (left[row - 1] == right[column - 1] ? 0 : 1)});
                }
                previous.swap(current);
            }
            return previous.back();
        };
        const auto wanted = components(name);
        struct Candidate { size_t score; const Symbol* symbol; };
        std::vector<Candidate> candidates;
        candidates.reserve(symbols.size());
        for (const auto& symbol : symbols) {
            const auto actual = components(symbol.name_path);
            const size_t compared = std::min(wanted.size(), actual.size());
            size_t score = 0;
            for (size_t offset = 1; offset <= compared; ++offset)
                score += edit_distance(wanted[wanted.size() - offset], actual[actual.size() - offset]);
            if (wanted.size() > actual.size())
                score += (wanted.size() - actual.size()) * (max_component_bytes);
            if (name.starts_with("/") && actual.size() > wanted.size())
                score += (actual.size() - wanted.size()) * (max_component_bytes);
            candidates.push_back({score, &symbol});
        }
        std::sort(candidates.begin(), candidates.end(), [](const Candidate& left, const Candidate& right) {
            if (left.score != right.score) return left.score < right.score;
            return left.symbol->name_path < right.symbol->name_path;
        });
        J::Array suggestions;
        for (size_t i = 0; i < std::min<size_t>(5, candidates.size()); ++i) {
            const Symbol& candidate = *candidates[i].symbol;
            suggestions.emplace_back(J::Object{
                {"name_path", candidate.name_path},
                {"line", candidate.selection.start.line + 1},
                {"score", static_cast<int64_t>(candidates[i].score)}});
        }
        std::string nearest;
        for (size_t i = 0; i < std::min<size_t>(5, candidates.size()); ++i)
            nearest += "\n  " + candidates[i].symbol->name_path + " (line " +
                       std::to_string(candidates[i].symbol->selection.start.line + 1) + ")";
        J details = symbol_lookup_details(session, source, "no_match", name);
        std::get<J::Object>(details.value).emplace("candidates", std::move(suggestions));
        throw SymbolLookupFailure("no symbol matches " + name + (nearest.empty() ? std::string() : ". Nearest:" + nearest),
                                  std::move(details));
    }
    return *found.front();
}
// Serena selects identifiers before enclosing ranges, then groups data symbols under their structural parent.
const Symbol* diagnostic_owner(const std::vector<Symbol>& found, Position at, const Control& control) {
    const Symbol* selected = nullptr;
    std::tuple<int, int64_t, int64_t, int64_t, int64_t> best;
    const auto contains = [&](const Range& r) { return r.start <= at && at <= r.end; };
    for (const auto& symbol : found) {
        control.check();
        int priority;
        if (contains(symbol.selection)) priority = 0;
        else if (contains(symbol.extent)) priority = 1;
        else if (symbol.selection.start == at) priority = 2;
        else if (symbol.extent.start == at) priority = 3;
        else if (symbol.selection.start.line == at.line && at.column <= symbol.selection.start.column) priority = 4;
        else if (symbol.extent.start.line == at.line && at.column <= symbol.extent.start.column) priority = 5;
        else continue;
        const int64_t lines = symbol.extent.end.line - symbol.extent.start.line;
        const int64_t columns = lines == 0 ? symbol.extent.end.column - symbol.extent.start.column : symbol.extent.end.column;
        const auto key = std::make_tuple(priority, lines, columns, symbol.extent.start.line, symbol.extent.start.column);
        if (!selected || key < best) { selected = &symbol; best = key; }
    }
    const auto container = [](int64_t kind) {
        return kind == 1 || kind == 2 || kind == 3 || kind == 4 || kind == 5 || kind == 6 ||
               kind == 9 || kind == 10 || kind == 11 || kind == 12 || kind == 19 || kind == 23;
    };
    while (selected && !container(selected->kind)) {
        control.check();
        const size_t slash = selected->name_path.rfind('/');
        if (slash == std::string::npos) break;
        const std::string parent = selected->name_path.substr(0, slash);
        const auto enclosing = std::find_if(found.begin(), found.end(), [&](const Symbol& symbol) { return symbol.name_path == parent; });
        if (enclosing == found.end()) break;
        selected = &*enclosing;
    }
    return selected;
}
std::string diagnostic_severity(const J& diagnostic) {
    if (!diagnostic.get("severity")) return "Unknown";
    switch (number(diagnostic, "severity", 1)) {
    case 1: return "Error";
    case 2: return "Warning";
    case 3: return "Information";
    case 4: return "Hint";
    default: return "Severity_" + std::to_string(number(diagnostic, "severity", 1));
    }
}

J query_file(const std::string& operation, const J& args, const SourceText& original,
             const Config& config, const SearchContext& context, const Control& control,
             std::set<std::string>& synchronized, bool workspace_query = false,
             const std::vector<Symbol>* cached = nullptr) {
    // cached: this file's outline from the symbol index, for the bytes in `original` (symbols/overview only). The
    //   answer is built from it alone: the server is not started, locked, synchronized or waited for.
    if (cached && operation != "symbols" && operation != "overview") cached = nullptr;
    auto session = session_for(config);
    std::unique_lock<std::timed_mutex> lock(session->mutex, std::defer_lock);
    if (!cached) while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
    bool reusable = false;
    try {
        const bool reverse = operation == "references" || operation == "implementation";
        bool first_for_server = false, loose_scripts_cut = false;
        if (!cached) {
            if (workspace_query && synchronized.contains(config.key)) session->start(control);
            else session->start(control, &context, &original, reverse, workspace_query);
            if (session->project_syntax_only() && operation != "symbols" && operation != "overview" &&
                operation != "status" && operation != "restart")
                throw SymbolLookupFailure("the file's project is unavailable; only a partial syntax outline is available",
                    J::Object{{"code", "project_loading"}, {"reason", "project_not_loaded"}, {"project_loading", session->managed_project_status()}});
            first_for_server = synchronized.insert(config.key).second;
            if (first_for_server) session->synchronize(&original, context, control);
            else session->use(original, control);
            if (reverse || operation == "definition" || operation == "declaration" || operation == "type_definition")
                loose_scripts_cut = !session->open_loose_scripts(original, context, control);
            session->service_pending(control);
        }
        const SourceText source = cached ? original : read_source_text(context, utf8(original.path.wstring()));
        if (!cached) session->assert_current(source);
        reusable = true;
        const std::string pattern = str(args, "name_path", str(args, "pattern"));
        const auto require_capability = [&](const char* capability) {
            try { session->require(capability); }
            catch (const LspFailure& error) {
                control.check();
                reject_request(error.what(), true);
            }
            control.check();
        };
        const auto query_symbols = [&]() {
            if (cached) return *cached;
            require_capability("documentSymbolProvider");
            return symbols(*session, source, control);
        };
        J::Array results;
        int64_t outside = 0, stale = 0, ignored = 0, owners_omitted = 0;
        if (operation == "status" || operation == "restart") {
            if (operation == "restart") { reusable = false; session->stop(); session->start(control, &context, &source); session->synchronize(&source, context, control); }
            return session->status(str(args, "detail", "summary") == "full");
        }
        const bool grouped_diagnostics = operation == "diagnostics" &&
            (flag(args, "group_by_symbol") || !pattern.empty());
        const bool partial_outline = config.managed_projects && (operation == "symbols" || operation == "overview");
        // A folder query opens its files one by one, and each didOpen restarts the 2 s quiet wait of servers without
        // progress reports, so N files cost 2N seconds and time out. Document symbols come from the file itself: once
        // this request saw the server's index ready, later files of the same folder query do not wait again.
        const bool index_seen_this_request = workspace_query && !first_for_server &&
                                             (operation == "symbols" || operation == "overview");
        if (!cached && !partial_outline && !index_seen_this_request && (operation != "diagnostics" || grouped_diagnostics))
            session->wait_indexed(control, &source);
        if (operation == "diagnostics") {
            J::Object report = session->diagnostics(source, control).object();
            const bool grouped = flag(args, "group_by_symbol");
            const int64_t first_line = number(args, "start_line", 1) - 1;
            const int64_t last_line = number(args, "end_line", -1);
            std::optional<std::vector<Symbol>> file_symbols;
            const auto get_symbols = [&]() -> const std::vector<Symbol>& {
                if (!file_symbols) file_symbols = query_symbols();
                return *file_symbols;
            };
            std::optional<Range> within;
            if (!pattern.empty()) within = unique(*session, source, get_symbols(), pattern).extent;
            const int64_t severity = number(args, "severity", 4);
            if (severity < 1 || severity > 4) reject_request("severity must be 1-4");
            std::map<std::string, std::map<std::string, J::Array>> groups;
            J::Array items;
            for (const auto& item : report.at("items").array()) {
                control.check();
                const J* extent = item.get("range"); if (!extent) fail("diagnostic has no range");
                const Range r = range(*extent);
                if (number(item, "severity", 1) > severity) continue;
                if (r.end.line < first_line || (last_line != -1 && r.start.line > last_line - 1)) continue;
                if (within && (r.end < within->start || within->end < r.start)) continue;
                J::Object normalized = item.object(); normalized["range"] = coordinates(r);
                if (const J* related = item.get("relatedInformation")) {
                    J::Array information;
                    for (const auto& entry : related->array()) {
                        J::Object result = entry.object();
                        if (const J* location = entry.get("location")) {
                            J::Object converted = location->object();
                            const J* extent = location->get("range"); if (!extent) fail("related diagnostic has no range");
                            converted["range"] = coordinates(range(*extent));
                            result["location"] = std::move(converted);
                        }
                        information.push_back(std::move(result));
                    }
                    normalized["relatedInformation"] = std::move(information);
                }
                if (grouped) {
                    const Symbol* owner = diagnostic_owner(get_symbols(), r.start, control);
                    J::Object entry{{"message", normalized.at("message")}, {"range", normalized.at("range")}};
                    for (const char* key : {"code", "source"})
                        if (const auto value = normalized.find(key); value != normalized.end()) entry.emplace(key, value->second);
                    groups[diagnostic_severity(item)][owner ? owner->name_path : "<file>"].push_back(std::move(entry));
                }
                items.push_back(std::move(normalized));
            }
            report["items"] = std::move(items);
            if (grouped) {
                J::Object by_severity;
                for (auto& [severity_name, names] : groups) {
                    control.check();
                    J::Object by_symbol;
                    for (auto& [name, diagnostics] : names) by_symbol.emplace(name, std::move(diagnostics));
                    by_severity.emplace(severity_name, std::move(by_symbol));
                }
                J::Object by_file;
                if (!by_severity.empty()) by_file.emplace(shown_path(source), std::move(by_severity));
                report.emplace("grouped", std::move(by_file));
            }
            if (read_source_text(context, utf8(source.path.wstring())).sha256 != source.sha256) fail("file changed during diagnostics; retry");
            report.emplace("path", shown_path(source)); report.emplace("sha256", source.sha256);
            report.emplace("coordinate_base", 1); report.emplace("position_encoding", "utf-16");
            std::set<std::string> reported_sources;
            for (const auto& item : report.at("items").array())
                if (const J* origin = item.get("source"); origin && std::holds_alternative<std::string>(origin->value))
                    reported_sources.insert(origin->string());
            J::Array providers;
            for (const auto& provider : reported_sources) providers.emplace_back(provider);
            report.emplace("language_id", config.language);
            report.emplace("diagnostic_sources", std::move(providers));
            report.emplace("observed_at_unix_ms", static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()));
            report.emplace("coverage", J::Object{
                {"origin", "language_server"},
                {"external_check", J::Object{{"status", "unverified"},
                    {"completed_after_edit", nullptr}, {"last_completed_at", nullptr}}},
                {"note", "version_verified covers diagnostic freshness, not completion of cargo check or another compiler check. "
                         "An empty items array does not certify a successful external check."}});
            if (config.managed_projects) {
                report["project_loading"] = session->managed_project_status();
                if (session->project_partial()) report["partial"] = true;
            }
            return report;
        }
        if (operation == "symbols" || operation == "overview") {
            const int64_t depth = number(args, "depth", operation == "overview" ? -1 : 0);
            if (depth < -1) reject_request("depth must be -1 or greater");
            std::array<bool, 27> included{}, excluded{};
            bool restrict_kinds = false;
            for (const char* key : {"include_kinds", "exclude_kinds"}) if (const J* values = args.get(key)) {
                const bool include = std::string_view(key) == "include_kinds";
                for (const auto& value : values->array()) {
                    const int64_t kind = value.integer();
                    if (kind < 1 || kind > 26) reject_request("symbol kinds must be 1-26");
                    (include ? included : excluded)[static_cast<size_t>(kind)] = true;
                    if (include) restrict_kinds = true;
                }
            }
            const auto kinds_match = [&](const Symbol& symbol) {
                if (symbol.kind < 1 || symbol.kind > 26) return !restrict_kinds;
                const size_t kind = static_cast<size_t>(symbol.kind);
                return (!restrict_kinds || included[kind]) && !excluded[kind];
            };
            const auto found = query_symbols();
            std::set<int64_t> wanted_lines;
            for (const auto& symbol : found)
                if (symbol.selection.start.line >= 0) wanted_lines.insert(symbol.selection.start.line);
            std::map<int64_t, std::string_view> source_lines;
            const std::string_view text = source.text;
            int64_t line_number = 0;
            for (size_t begin = 0; begin <= text.size() && !wanted_lines.empty(); ++line_number) {
                control.check();
                const size_t newline = text.find_first_of("\r\n", begin);
                const size_t end = newline == std::string_view::npos ? text.size() : newline;
                if (wanted_lines.erase(line_number)) source_lines.emplace(line_number, text.substr(begin, end - begin));
                if (newline == std::string_view::npos) break;
                begin = newline + (text[newline] == '\r' && newline + 1 < text.size() && text[newline + 1] == '\n' ? 2 : 1);
            }
            const auto symbol_result = [&](const Symbol& symbol, bool include_body) {
                J::Object value = symbol_json(symbol, source, include_body, flag(args, "full_lines")).object();
                if (const auto line = source_lines.find(symbol.selection.start.line); line != source_lines.end())
                    value.emplace("line_text", std::string(line->second));
                return value;
            };
            // A symbol read of one file that matches nothing reports why, with the nearest names, instead of 0 results.
            if (flag(args, "require_match") && !pattern.empty() && !args.get("patterns") && !flag(args, "substring_matching")) {
                const NamePathMatcher probe(pattern);
                const bool any = std::any_of(found.begin(), found.end(), [&](const Symbol& symbol) {
                    return probe.matches(symbol, false) || probe.matches(symbol, false, true);
                });
                if (!any) (void)unique(*session, source, found, pattern);
            }
            if (flag(args, "require_unique")) {
                results.push_back(symbol_result(unique(*session, source, found, pattern), flag(args, "include_body")));
            } else {
                std::vector<std::string> patterns{pattern};
                if (const J* list = args.get("patterns")) {
                    patterns.clear();
                    for (const auto& item : list->array()) patterns.push_back(item.string());
                    if (patterns.empty()) reject_request("patterns must not be empty");
                }
                // Patterns and found symbols stay immutable while their views are used.
                std::vector<NamePathMatcher> matchers;
                matchers.reserve(patterns.size());
                for (const auto& item : patterns) matchers.emplace_back(item);
                const bool substring = flag(args, "substring_matching");
                const bool include_body = flag(args, "include_body"), include_info = flag(args, "include_info");
                const bool expand = operation == "symbols" && !include_body && depth != 0;
                std::unordered_map<std::string_view, std::vector<const Symbol*>> descendants;
                if (expand) {
                    for (const auto& child : found) {
                        control.check();
                        if (!kinds_match(child)) continue;
                        const std::string_view path = child.name_path;
                        for (size_t slash = path.find('/'); slash != std::string_view::npos;
                             slash = path.find('/', slash + 1))
                            descendants[path.substr(0, slash)].push_back(&child);
                    }
                }
                std::set<std::string_view> emitted;
                for (const auto& symbol : found) {
                    control.check();
                    if (operation == "overview" && depth >= 0 && symbol.depth > depth) continue;
                    if (!kinds_match(symbol) || !std::any_of(matchers.begin(), matchers.end(),
                        [&](const NamePathMatcher& matcher) { return matcher.matches(symbol, substring, true); })) continue;
                    auto emit = [&](const Symbol& item, bool primary) {
                        if (!emitted.insert(item.name_path).second) return;
                        J::Object result = symbol_result(item, primary && include_body);
                        if (primary && include_info && !include_body) {
                            require_capability("hoverProvider");
                            const J info = session->request("textDocument/hover", J::Object{
                                {"textDocument", J::Object{{"uri", session->document_uri(source)}}}, {"position", item.selection.start.json()}}, control);
                            result.emplace("info", info);
                        }
                        results.push_back(std::move(result));
                    };
                    emit(symbol, true);
                    if (expand) {
                        const auto children = descendants.find(symbol.name_path);
                        if (children != descendants.end()) for (const Symbol* child : children->second) {
                            control.check();
                            if (depth < 0 || static_cast<int64_t>(child->depth) - symbol.depth <= depth)
                                emit(*child, false);
                        }
                    }
                }
            }
        } else {
            Position at;
            if (!pattern.empty()) {
                const auto found = query_symbols();
                at = unique(*session, source, found, pattern).selection.start;
            } else {
                const int64_t line = number(args, "line", 0), column = number(args, "column", 0);
                if (line < 1 || column < 1 || line > INT32_MAX || column > INT32_MAX)
                    reject_request("navigation needs name_path or 1-based line and column (1-2147483647)");
                at = {line - 1, column - 1};
                try { offset(wide(source.text), at); }
                catch (const std::runtime_error& error) { reject_request(error.what()); }
            }
            const bool references = operation == "references";
            static const std::map<std::string, std::pair<const char*, const char*>> operations{
                {"definition", {"definitionProvider", "textDocument/definition"}},
                {"declaration", {"declarationProvider", "textDocument/declaration"}},
                {"type_definition", {"typeDefinitionProvider", "textDocument/typeDefinition"}},
                {"implementation", {"implementationProvider", "textDocument/implementation"}},
                {"references", {"referencesProvider", "textDocument/references"}},
                {"hover", {"hoverProvider", "textDocument/hover"}}};
            const auto method = operations.find(operation);
            if (method == operations.end()) reject_request("unknown LSP navigation operation");
            require_capability(method->second.first);
            if (operation != "hover") session->wait_indexed(control, &source);
            // Index answers for unopened files are checked against current bytes: each reference must still spell it.
            const std::string expected = references ? identifier_at(source.text, at) : std::string{};
            J::Object params{{"textDocument", J::Object{{"uri", session->document_uri(source)}}}, {"position", at.json()}};
            if (references) params.emplace("context", J::Object{{"includeDeclaration", flag(args, "include_declaration")}});
            J raw = session->request(method->second.second, std::move(params), control);
            if (operation == "hover") {
                if (read_source_text(context, utf8(source.path.wstring())).sha256 != source.sha256) fail("file changed during hover; retry");
                J::Object result{{"path", shown_path(source)}, {"sha256", source.sha256}, {"hover", raw}, {"backend", "lsp"}};
                if (session->project_partial()) {
                    result.emplace("partial", true);
                    result.emplace("project_loading", session->managed_project_status());
                }
                return result;
            }
            J::Array locations;
            if (std::holds_alternative<J::Array>(raw.value)) locations = raw.array();
            else if (!std::holds_alternative<std::nullptr_t>(raw.value)) locations.push_back(raw);
            std::map<std::wstring, std::set<std::string>, PathLess> dedup;
            std::map<std::wstring, std::vector<Symbol>, PathLess> owners;
            std::set<std::wstring, PathLess> owners_unavailable;
            struct DecodedTarget { std::string sha256; std::wstring text; };
            std::map<std::wstring, DecodedTarget, PathLess> decoded_targets;
            constexpr size_t kOwnerFiles = 16;  // unopened files opened per request to name enclosing symbols
            size_t opened_for_owners = 0;
            for (const auto& location : locations) {
                control.check();
                const bool link = location.get("targetUri") != nullptr;
                const std::string id = str(location, link ? "targetUri" : "uri");
                const J* raw_range = location.get(link ? "targetSelectionRange" : "range");
                if (!raw_range) server_fail("language server returned a location without a range");
                const Range found = range(*raw_range);
                SourceText target;
                try {
                    const fs::path target_path = from_uri(id);
                    if (path_excluded(config, target_path)) { ++ignored; continue; }
                    target = read_source_text(context, utf8(target_path.wstring()));
                }
                catch (const std::exception& e) {
                    const std::string message = e.what();
                    if (message.find("outside the configured roots") != std::string::npos ||
                        message.find("non-file URI") != std::string::npos) { ++outside; continue; }
                    if (message.find(": not found") != std::string::npos ||
                        message.ends_with(" is not valid Unicode source text")) { ++stale; continue; }
                    throw;
                }
                if (!dedup[target.path.wstring()].insert(raw_range->dump()).second) continue;
                // Other configured languages are readable, but their bodies are never taken from an old server buffer.
                const auto target_config = configuration(target, context, control.cancelled);
                if (target_config && path_excluded(*target_config, target.path)) { ++ignored; continue; }
                const bool same_server = target_config && target_config->key == config.key;
                bool from_index = false;
                if (same_server && !session->has_document(target)) {
                    // A server without its own index only knows open documents; anything else is a leftover.
                    if (!config.indexes_workspace || session->is_open(target)) { ++ignored; continue; }
                    from_index = true;
                }
                if (same_server && !from_index) session->assert_current(target);
                auto& decoded = decoded_targets[target.path.wstring()];
                if (decoded.sha256 != target.sha256) {
                    decoded.text = wide(target.text);
                    decoded.sha256 = target.sha256;
                }
                const size_t begin = offset(decoded.text, found.start), end = offset(decoded.text, found.end);
                std::string reference_name;
                if (references || (from_index && !expected.empty()))
                    reference_name = utf8(decoded.text.substr(begin, end - begin));
                if (from_index && !expected.empty() && reference_name != expected) { ++stale; continue; }
                J::Object result{{"path", shown_path(target)}, {"line", found.start.line + 1},
                                  {"column", found.start.column + 1}, {"range", coordinates(found)}};
                if (references) result.emplace("reference_name", std::move(reference_name));
                {
                    // Each location carries its source line, so an agent needs no follow-up read to see the use
                    // (arXiv 2608.13568: inline lines cut file reads per episode from 5.2 to 3.2 and tokens by 19%).
                    const size_t newline = begin ? decoded.text.rfind(L'\n', begin - 1) : std::wstring::npos;
                    const size_t line_start = newline == std::wstring::npos ? 0 : newline + 1;
                    size_t line_stop = decoded.text.find_first_of(L"\r\n", begin);
                    if (line_stop == std::wstring::npos) line_stop = decoded.text.size();
                    std::wstring line = decoded.text.substr(line_start, line_stop - line_start);
                    const size_t first = line.find_first_not_of(L" \t");
                    line = first == std::wstring::npos ? std::wstring() : line.substr(first, 240);
                    // A cut between a surrogate pair would leave a lone high surrogate that utf8() rejects.
                    if (line.size() == 240 && line.back() >= 0xD800 && line.back() <= 0xDBFF) line.pop_back();
                    result.emplace("line_text", utf8(line));
                }
                const bool owner_known = owners.contains(target.path.wstring());
                if (from_index && !owner_known && session->supports("documentSymbolProvider")) {
                    // Enclosing symbols need the document open; a bounded number per request keeps parsing cheap.
                    if (opened_for_owners < kOwnerFiles) { session->use(target, control); ++opened_for_owners; }
                    else ++owners_omitted;
                }
                if (session->supports("documentSymbolProvider") && same_server && (owner_known || session->is_open(target))) {
                    auto owner = owners.find(target.path.wstring());
                    if (owner == owners.end()) {
                        try { owner = owners.emplace(target.path.wstring(), symbols(*session, target, control)).first; }
                        catch (const RejectedLspRequest&) {
                            control.check();
                            owners_unavailable.insert(target.path.wstring());
                            owner = owners.emplace(target.path.wstring(), std::vector<Symbol>{}).first;
                        }
                    }
                    if (owners_unavailable.contains(target.path.wstring())) ++owners_omitted;
                    const Symbol* enclosing = nullptr;
                    auto container_kind = [](int64_t kind) {
                        return kind == 1 || kind == 2 || kind == 3 || kind == 4 || kind == 5 || kind == 6 ||
                               kind == 9 || kind == 10 || kind == 11 || kind == 12 || kind == 19 || kind == 23;
                    };
                    for (const auto& symbol : owner->second) {
                        const bool variable = symbol.kind == 13 || symbol.kind == 14;
                        const bool container = container_kind(symbol.kind);
                        if (!(variable || container) ||
                            symbol.extent.start > found.start || found.end > symbol.extent.end) continue;
                        if (!enclosing || enclosing->extent.start < symbol.extent.start ||
                            (enclosing->extent.start == symbol.extent.start && enclosing->depth < symbol.depth))
                            enclosing = &symbol;
                    }
                    if (enclosing) {
                        result.emplace("symbol", enclosing->name_path);
                        if (flag(args, "include_body") && enclosing->has_body) {
                            const Range returned_range = flag(args, "full_lines")
                                ? body_lines_range(target, enclosing->extent) : enclosing->extent;
                            result.emplace("body", body(target, returned_range));
                            result.emplace("body_range", coordinates(returned_range));
                            result.emplace("sha256", target.sha256);
                            result.emplace("mtime", target.mtime);
                        }
                    }
                }
                results.push_back(std::move(result));
                if (read_source_text(context, utf8(target.path.wstring())).sha256 != target.sha256)
                    fail("navigation target changed during the request; retry");
            }
        }
        if (!cached && read_source_text(context, utf8(source.path.wstring())).sha256 != source.sha256)
            fail("source changed during LSP navigation; retry");
        if (context.record_user_reads && (operation == "symbols" || operation == "overview"))
            remember_read_snapshot(context, source.path, source.sha256);
        J::Object response{{"path", shown_path(source)}, {"sha256", source.sha256}, {"mtime", source.mtime}, {"results", std::move(results)},
                           {"outside_roots", outside}, {"stale_locations", stale}, {"ignored_locations", ignored}, {"backend", "lsp"}};
        if (owners_omitted) response.emplace("symbols_omitted", owners_omitted);  // enclosing symbol left out for these
        if (cached) {
            response.emplace("partial", false);
            return response;
        }
        const auto warming = session->warming_timeout(&source);
        response.emplace("partial", static_cast<bool>(warming) || session->project_partial() || loose_scripts_cut);
        if (loose_scripts_cut)
            response.emplace("coverage_note", "only the first " + std::to_string(Session::kLooseScripts) +
                " scripts of this package (no tsconfig.json or jsconfig.json) were opened; results can miss files. "
                "Fix: add a jsconfig.json at the package root");
        if (config.managed_projects) {
            response.emplace("syntax_only", session->project_syntax_only() || static_cast<bool>(warming));
            if (session->project_partial()) response.emplace("project_loading", session->managed_project_status());
        }
        if (warming) response.emplace("index_warming", warming->details);
        return response;
    } catch (const IndexWarmingFailure&) {
        // A cached answer never started, locked or used the server, so none of these failures are the server's.
        if (cached) throw;
        if (!reusable || (control.cancelled && control.cancelled->load()) || Clock::now() >= control.deadline)
            session->stop();
        throw;
    } catch (const LspTimeoutFailure&) {
        if (cached) throw;
        if (auto warming = session->warming_timeout(&original)) {
            if (!reusable) session->stop();
            throw *warming;
        }
        if (!reusable || (control.cancelled && control.cancelled->load()) || Clock::now() >= control.deadline)
            session->stop();
        throw;
    } catch (const RejectedLspRequest& error) {
        if (cached) throw;
        // Session health and fallback eligibility are independent.
        if (!reusable || (control.cancelled && control.cancelled->load()) || Clock::now() >= control.deadline)
            session->stop();
        if (error.fallback_eligible) throw LspFailure(error.what());
        throw;
    } catch (const SymbolLookupFailure&) {
        if (cached) throw;
        if (!reusable || (control.cancelled && control.cancelled->load()) || Clock::now() >= control.deadline)
            session->stop();
        throw;
    } catch (const PositionMismatch&) {
        throw;  // the server answered; the file's text and its positions disagree (see PositionMismatch)
    } catch (...) {
        if (cached) throw;
        session->stop();
        throw;
    }
}
} // namespace

std::string lsp_failure_banner(const std::string& detail, const std::string& fallback) {
    return failure_banner("LSP FAILURE", detail, fallback);
}

int64_t lsp_request_timeout_ms(const Json& arguments, const SearchContext& context,
                               const std::shared_ptr<std::atomic_bool>& cancelled) {
    const J* options = arguments.get("arguments");
    if (options) options->object();
    const J* outer = arguments.get("timeout_ms");
    const J* inner = options ? options->get("timeout_ms") : nullptr;
    if (outer || inner) {
        const int64_t value = (outer ? outer : inner)->integer();
        if (value < 1 || value > 300000) fail("timeout_ms must be 1-300000");
        if (outer && inner && inner->integer() != value)
            fail("top-level and arguments.timeout_ms must agree");
        return value;
    }
    if (options && str(*options, "check", "lsp") != "lsp") return 300000;
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(300000)), cancelled};
    control.check();
    if (!options || options->get("paths") || str(arguments, "method") == "lsp.restart_language_server")
        return 300000;
    if (options->get("path") && options->get("relative_path")) return 300000;
    const std::string path = str(*options, "path", str(*options, "relative_path"));
    if (path.empty()) return 300000;
    bool directory = false;
    const SourceText source = source_descriptor(context, path, &directory);
    if (directory) return 300000;
    const auto config = configuration(source, context, cancelled);
    control.check();
    if (!config) return 300000;
    const auto session = existing_session_for(*config);
    if (!session) return 300000;
    std::unique_lock<std::timed_mutex> lock(session->mutex, std::try_to_lock);
    if (!lock.owns_lock()) return 300000;
    const J status = session->status();
    control.check();
    const J* uptime = status.get("uptime_seconds");
    return str(status, "indexing_state") == "ready" && uptime &&
           !std::holds_alternative<std::nullptr_t>(uptime->value) ? 180000 : 300000;
}

std::shared_timed_mutex& workspace_operation_mutex() {
    static std::shared_timed_mutex mutex;
    return mutex;
}

// Whether an explicit server in root's .shgrep/lsp.json claims extension. That is the only file configs() loads for
// files under root, so classification and server selection agree; nested lsp.json files are never consulted.
// nullopt: the file exists but is a link, a directory, unreadable or invalid, so its claims are unknown. Side-effect
// free: it only reads that file (never through a link), cached by its write time and size.
std::optional<bool> configured_extension(const fs::path& root, const std::string& extension) {
    if (root.empty()) return false;
    static std::mutex mutex;
    // By lower-case UTF-8 config path: write stamp, then the claimed extensions (nullopt: unreadable or invalid).
    static std::map<std::string, std::pair<std::string, std::optional<std::set<std::string>>>> cache;
    std::wstring config = (root / L".shgrep" / L"lsp.json").wstring();
    if (!config.starts_with(L"\\\\?\\")) {  // same long-path spelling as configs_from_disk
        if (config.starts_with(L"\\\\")) config = L"\\\\?\\UNC\\" + config.substr(2);
        else config = L"\\\\?\\" + config;
    }
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(config.c_str(), GetFileExInfoStandard, &data)) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return false;  // bundled defaults only
        return std::nullopt;
    }
    // configs_from_disk refuses a linked or directory lsp.json, so its claims are unknown, not empty.
    if (data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) return std::nullopt;
    const std::string stamp = std::to_string(data.ftLastWriteTime.dwHighDateTime) + ":" +
        std::to_string(data.ftLastWriteTime.dwLowDateTime) + ":" + std::to_string(data.nFileSizeHigh) + ":" +
        std::to_string(data.nFileSizeLow);
    std::lock_guard lock(mutex);
    auto& entry = cache[lower(utf8(config))];
    if (entry.first != stamp) {
        std::optional<std::set<std::string>> claimed;
        try {
            std::ifstream file(fs::path(config), std::ios::binary);
            if (!file) throw std::runtime_error("unreadable");
            const std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            const J json = J::parse(text);
            const J* servers = json.get("servers");
            if (!servers) throw std::runtime_error("no servers array");
            std::set<std::string> found;
            for (const auto& server : servers->array())
                if (const J* extensions = server.get("extensions"))
                    for (const auto& item : extensions->array()) {
                        std::string ext = lower(item.string());
                        if (!ext.starts_with(".")) ext = "." + ext;
                        found.insert(ext);
                    }
            claimed = std::move(found);
        } catch (const std::exception&) {}  // the request that loads its servers reports the exact error
        entry = {stamp, std::move(claimed)};
    }
    if (!entry.second) return std::nullopt;
    return entry.second->contains(extension);
}

// Markup and data formats: read as text even when a server handles them, and never assumed to need one.
bool plain_text_format(const std::string& extension) {
    static const std::set<std::string> formats{
        ".xml", ".xsd", ".xsl", ".xslt", ".svg", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini",
        ".md", ".mdx", ".txt", ".csv", ".log"
    };
    return formats.contains(extension);
}

bool lsp_required(const std::filesystem::path& path, const std::filesystem::path& root) {
    const std::string name = lower(utf8(path.filename().wstring()));
    if (name == "cmakelists.txt" || name == "makefile" || name == "gnumakefile") return true;
    const std::string extension = lower(utf8(path.extension().wstring()));
    if (extension == ".in") return lsp_required(path.stem(), root);
    for (const auto& server : bundled_servers())
        if (std::find(server.extensions.begin(), server.extensions.end(), extension) != server.extensions.end()) return true;
    static const std::set<std::string> programming{
        ".asm", ".s", ".inc", ".bat", ".cmd", ".cmake", ".c++", ".h++", ".tpp", ".csx",
        ".go", ".java", ".js", ".mjs", ".cjs", ".jsx", ".mk", ".mak", ".proto", ".ps1", ".psm1", ".psd1",
        ".pyw", ".sh", ".bash", ".zsh", ".sql", ".ts", ".tsx", ".mts", ".cts", ".kt", ".kts", ".swift",
        ".m", ".mm", ".rb", ".r", ".php", ".pl", ".pm", ".ex", ".exs", ".erl", ".hrl", ".hs", ".lhs",
        ".fs", ".fsi", ".fsx", ".scala", ".sc", ".clj", ".cljs", ".cljc", ".dart", ".zig", ".jl",
        ".groovy", ".gvy", ".lua", ".luau", ".v", ".sv", ".svh", ".vhd", ".vhdl"
    };
    if (programming.contains(extension)) return true;
    // Extensions an explicit server is configured for get the same semantic routing and text-write rules.
    if (const auto claimed = configured_extension(root, extension)) return *claimed;
    // An unusable root lsp.json may name a server for this extension; keep text edits behind the explicit fallback
    // (its probe fails with the configuration error) rather than opening them. Docs, data and extensionless files
    // stay plain text, so the configuration itself can still be repaired.
    return !extension.empty() && !plain_text_format(extension);
}

// CONTRACT: a code file is read only through its language server. read_file text reads (operation=text, offset,
//   limit) of such a file return the LSP outline; plain text needs allow_text_fallback=true and a failing server.
//   Markup and data formats that a server may also cover (XML, SVG, JSON, YAML...) stay readable as text.
bool lsp_read_required(const std::filesystem::path& path, const std::filesystem::path& root) {
    return lsp_required(path, root) && !plain_text_format(language_extension(path));
}

std::string lsp_fallback_reason(const SourceText& source, const Json& arguments, const SearchContext& context,
                                const std::shared_ptr<std::atomic_bool>& cancelled) {
    Json::Object query{{"path", utf8(source.path.wstring())}, {"depth", 0}};
    if (const Json* timeout = arguments.get("timeout_ms")) query.emplace("timeout_ms", *timeout);
    try { (void)lsp_query("overview", query, context, cancelled); }
    catch (const RejectedLspRequest& e) {
        if (!e.fallback_eligible || (cancelled && cancelled->load()) ||
            Clock::now() >= request_deadline(Clock::time_point::max())) throw;
        return e.what();
    }
    catch (const LspFailure& e) {
        if ((cancelled && cancelled->load()) || Clock::now() >= request_deadline(Clock::time_point::max())) throw;
        return e.what();
    }
    return {};
}

std::string require_text_access(const SourceText& source, const Json& arguments, const SearchContext& context,
                                const std::shared_ptr<std::atomic_bool>& cancelled) {
    const bool allow_fallback = flag(arguments, "allow_text_fallback");
    if (!lsp_required(source.path, source.root)) return {};
    const std::string path = utf8(source.path.wstring());
    if (!allow_fallback)
        fail(path + ": Text edits require the direct lsp tool for programming files and XML. "
             "Text fallback requires allow_text_fallback=true and an unavailable or failing language server");
    const std::string reason = lsp_fallback_reason(source, arguments, context, cancelled);
    if (reason.empty()) fail(path + ": LSP is working; unrestricted text edits are forbidden. Use the direct lsp tool for symbol edits");
    return lsp_failure_banner(reason, "Explicit text fallback for " + path);
}

bool lsp_configured(const SourceText& source, const SearchContext& context) {
    return configuration(source, context, nullptr).has_value();
}
std::string lsp_file_stamp(const fs::path& path) {
    return file_stamp(path);
}

std::string lsp_index_fingerprint(const SearchContext& context, const std::filesystem::path& root,
                                  const std::shared_ptr<std::atomic_bool>& cancelled) {
    // Only `root`'s configuration: the meaning index covers one root, and setup prepared meanwhile for another root
    // (a folder query there runs CMake setup) must not invalidate it.
    std::vector<std::string> rows;
    {
        if (cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled");
        for (const auto& config : configs(root, context, cancelled, false)) {
            J::Array command, extensions, environment, roots, ignored;
            J::Object languages;
            for (const auto& argument : config.command) command.emplace_back(argument);
            for (const auto& extension : config.extensions) extensions.emplace_back(extension);
            for (const auto& path : config.ignored_paths) ignored.emplace_back(path);
            for (const auto& [extension, language] : config.extension_languages) languages[extension] = language;
            for (const auto& [name, value] : config.environment)
                environment.emplace_back(J::Array{utf8(name), utf8(value)});
            for (const auto& folder : config.workspace_roots) roots.emplace_back(utf8(folder.wstring()));
            rows.push_back(J(J::Object{{"key", config.key}, {"command", std::move(command)},
                {"extensions", std::move(extensions)}, {"environment", std::move(environment)},
                {"roots", std::move(roots)}, {"ignored_paths", std::move(ignored)},
                {"extension_languages", std::move(languages)}, {"root", utf8(config.root.wstring())},
                {"working_directory", utf8(config.working_directory.wstring())}, {"dotnet", utf8(config.dotnet.wstring())},
                {"initialization", config.initialization},
                {"settings", config.settings}}).dump());
        }
    }
    std::sort(rows.begin(), rows.end());
    J::Array sorted;
    for (auto& row : rows) sorted.emplace_back(std::move(row));
    return source_text_digest(J(std::move(sorted)).dump());
}

std::string lsp_missing(const SourceText& source, const SearchContext& context) {
    return configuration(source, context, nullptr) ? std::string() : missing_bundled(source);
}

namespace {
// Extensions of files the current request showed the model (list_dir, find_files, search). Per request thread.
thread_local std::set<std::string> listed_extensions;
std::mutex language_notice_mutex;
std::set<std::string> language_noticed;  // bundled servers already warned about in this process
}

void lsp_note_listed_file(std::string_view path) {
    if (path.empty() || listed_extensions.size() >= 256) return;
    const std::string ext = language_extension(fs::path(wide(std::string(path))));
    if (!ext.empty()) listed_extensions.insert(ext);
}

void lsp_clear_listed_files() { listed_extensions.clear(); }

std::string lsp_language_notice(const SearchContext& context) {
    // #101: nothing about language servers is said at session start. A missing bundled server (or its missing
    // prerequisite, such as Roslyn's .NET) is named once per process, after a tool result first shows the model files
    // that server would handle, unless the workspace's .shgrep/lsp.json gives those files its own server or turns the
    // bundled defaults off. A Rust repository never hears about JavaScript or CMake. Nothing is started.
    std::set<std::string> listed;
    listed.swap(listed_extensions);
    if (listed.empty()) return {};
    std::vector<const BundledServer*> relevant;
    for (const auto& server : bundled_servers())
        if (std::any_of(server.extensions.begin(), server.extensions.end(),
                        [&](const std::string& ext) { return listed.contains(ext); }))
            relevant.push_back(&server);
    if (relevant.empty()) return {};
    {
        std::lock_guard lock(language_notice_mutex);
        std::erase_if(relevant, [&](const BundledServer* server) { return language_noticed.contains(server->name); });
    }
    if (relevant.empty()) return {};
    std::set<std::string> owned;
    bool bundled = true;
    if (!context.allowed_roots.empty()) {
        const fs::path config = context.allowed_roots.front() / L".shgrep" / L"lsp.json";
        std::error_code error;
        if (fs::exists(config, error)) {
            try {
                SearchContext quiet = context;
                quiet.record_user_reads = false;  // not the user's read
                const J json = J::parse(read_source_text(quiet, utf8(config.wstring())).text);
                bundled = flag(json, "bundled", true);
                if (const J* servers = json.get("servers"))
                    for (const auto& server : servers->array())
                        if (const J* extensions = server.get("extensions"))
                            for (const auto& extension : extensions->array()) {
                                std::string ext = lower(extension.string());
                                owned.insert(ext.starts_with(".") ? ext : "." + ext);
                            }
            } catch (const std::exception&) {}  // an invalid lsp.json is reported by the request that loads it
        }
    }
    if (!bundled) return {};
    const fs::path& base = bundled_directory();
    std::string missing;
    std::vector<std::string> problems;
    for (const BundledServer* server : relevant) {
        std::string shown;  // the listed extensions this server would handle and no custom server owns
        for (const auto& ext : server->extensions)
            if (listed.contains(ext) && !owned.contains(ext)) shown += (shown.empty() ? "" : ", ") + ext;
        if (shown.empty()) continue;
        std::error_code error;
        const bool installed = !base.empty() && fs::is_regular_file(base / server->executable, error);
        const std::string problem = installed ? bundled_prerequisite(server->language) : std::string();
        if (installed && problem.empty()) continue;
        {
            std::lock_guard lock(language_notice_mutex);
            if (!language_noticed.insert(server->name).second) continue;  // another request just warned
        }
        if (!installed)
            missing += (missing.empty() ? "" : "; ") + std::string(server->name) + " (" + server->language + ", for the " +
                       shown + " files listed) at " +
                       (base.empty() ? std::string("lsp\\ beside shgrep.exe") : utf8((base / server->executable).wstring()));
        else
            problems.push_back(std::string("the bundled ") + server->name + " for the " + shown + " files listed " + problem);
    }
    if (!missing.empty())
        problems.insert(problems.begin(), "no language server is installed for files this result lists: " + missing +
                        ". Semantic tools for those files need it; install with: " + fetch_command());
    std::string notice;
    for (const auto& problem : problems) notice += "[shgrep notice: " + problem + "]\n";
    return notice;
}

namespace {
// The warm-up thread of start_language_servers. Guarded by warmup_mutex. COMPAT: never destroyed, so a thread still
// running at exit (stop_language_server_warmup not called, or it gave up waiting) cannot terminate the process.
std::mutex warmup_mutex;
std::thread& warmup_thread = *new std::thread;
std::shared_ptr<std::atomic_bool> warmup_cancelled;
std::future<void> warmup_done;
}

void start_language_servers(const SearchContext& context) {
    if (context.read_only || context.allowed_roots.empty()) return;  // --read-only exposes no semantic tools
    wchar_t value[4] = {};
    if (GetEnvironmentVariableW(L"SHGREP_LSP_WARMUP", value, 4) == 1 && value[0] == L'0') {
        index_log(false, "language server warm-up off (SHGREP_LSP_WARMUP=0); servers start on first use");
        return;
    }
    if (workspace_too_broad(context)) {  // finding its languages would scan most of the disk
        index_log(true, "language server warm-up skipped: the workspace is too broad; servers start on first use");
        return;
    }
    std::lock_guard lock(warmup_mutex);
    if (warmup_thread.joinable()) return;
    warmup_cancelled = std::make_shared<std::atomic_bool>(false);
    std::promise<void> done;
    warmup_done = done.get_future();
    warmup_thread = std::thread([context, cancelled = warmup_cancelled, done = std::move(done)]() mutable {
        // PERF: only servers whose files the workspace holds start, so a C++ repo never launches
        //   Roslyn. Each start takes the session's own lock, so a query that arrives meanwhile waits for this start
        //   instead of starting the server twice; no workspace gate is held, so edits are never blocked by it.
        // Progress goes to the index log (index_log), never into tool results.
        try {
            const Control control{Clock::now() + std::chrono::minutes(5), cancelled};
            const fs::path root = fs::absolute(context.allowed_roots.front()).lexically_normal();
            // Workspace profile: a language whose files here are all data, generated or vendored gets no warm start
            // (it still starts on first use).
            const FolderProbe probe = file_system_probe(root);
            std::string started, skipped;
            for (const auto& config : configs(root, context, cancelled)) {
                if (cancelled->load()) break;
                try {
                    // Bundled servers start only for files in the workspace itself. worth_starting would also accept
                    //   files in any other root for workspace-wide servers (C#, TypeScript), which may never be queried.
                    std::vector<std::string> files;
                    if (config.bundled) {
                        files = source_paths(context, utf8(root.wstring()), config.extensions, control.deadline, cancelled);
                        std::erase_if(files, [&](const std::string& file) {
                            const fs::path native(wide(file));
                            return file_path_role(root, native, language_extension(native), &probe) != FileRole::source;
                        });
                        if (files.empty()) {
                            skipped += (skipped.empty() ? "" : ", ") + config.language;
                            continue;
                        }
                    }
                    // Start the instance queries will use: workspace-wide servers run one per toolchain profile
                    //   (TypeScript version, .NET SDK), and queries resolve that profile from the file. Starting the base
                    //   configuration instead ran a second tsserver that no query ever reached.
                    const Config profiled = files.empty() ? config
                        : project_profile(config, source_descriptor(context, files.front()), context);
                    const auto began = Clock::now();
                    auto session = session_for(profiled);
                    std::unique_lock<std::timed_mutex> session_lock(session->mutex, std::defer_lock);
                    while (!session_lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
                    session->start(control, &context);
                    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - began).count();
                    index_log(false, "language server started: " + config.language + " (" + config.server + ") in " +
                                         std::to_string(ms) + " ms; it indexes in the background");
                    started += (started.empty() ? "" : ", ") + config.language;
                } catch (const std::exception& e) {
                    if (cancelled->load()) break;
                    // The first query for this language starts it again and reports the failure itself.
                    index_log(true, "language server warm-up failed for " + config.language + ": " + e.what());
                }
            }
            if (!cancelled->load())
                index_log(false, "language server warm-up done; started: " + (started.empty() ? std::string("none") : started) +
                                     "; no source files (only data, generated or vendored, or none) in the workspace for: " +
                                     (skipped.empty() ? std::string("none") : skipped));
        } catch (const std::exception& e) {
            if (!cancelled->load()) index_log(true, std::string("language server warm-up failed: ") + e.what());
        }
        done.set_value();
    });
}

void stop_language_server_warmup() {
    std::lock_guard lock(warmup_mutex);
    if (!warmup_thread.joinable()) return;
    warmup_cancelled->store(true);
    // A start blocked in the server's process I/O may not notice the flag at once; shutdown never waits long for it.
    if (warmup_done.wait_for(std::chrono::seconds(5)) == std::future_status::ready) warmup_thread.join();
    else warmup_thread.detach();
}

Json lsp_query(const std::string& operation, const Json& arguments, const SearchContext& context,
               const std::shared_ptr<std::atomic_bool>& cancelled) {
    const int64_t timeout = number(arguments, "timeout_ms", 180000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout)), cancelled};
    if (arguments.get("detail")) {
        const std::string detail = str(arguments, "detail");
        if ((operation != "status" && operation != "restart") || (detail != "summary" && detail != "full"))
            fail("detail=summary|full is only supported by status and restart");
    }
    std::set<std::string> synchronized;
    const bool symbol_query = operation == "symbols" || operation == "overview";
    if (arguments.get("full_lines")) {
        const bool full_lines = flag(arguments, "full_lines");
        if (full_lines && (!flag(arguments, "include_body") ||
                           (!symbol_query && operation != "references")))
            fail("full_lines requires include_body for symbols or references");
    }
    if (operation == "diagnostics") {
        const int64_t first = number(arguments, "start_line", 1), last = number(arguments, "end_line", -1);
        if (first < 1 || first > INT32_MAX || (last != -1 && (last < first || last > INT32_MAX)))
            fail("diagnostics require 1-based start_line/end_line (1-2147483647); end_line=-1 means no upper bound");
        (void)flag(arguments, "group_by_symbol");
    } else {
        for (const char* key : {"start_line", "end_line", "group_by_symbol", "check"})
            if (arguments.get(key)) fail(std::string(key) + " requires operation=diagnostics");
    }
    if (operation == "files")
        for (const char* key : {"name_path", "pattern", "patterns", "substring_matching", "include_kinds", "exclude_kinds"})
            if (arguments.get(key)) fail(std::string(key) + " requires operation=symbols");
    if (!symbol_query)
        for (const char* key : {"depth", "include_info", "include_kinds", "exclude_kinds", "substring_matching"})
            if (arguments.get(key)) fail(std::string(key) + " is only for symbol lookup");
    if (symbol_query && (arguments.get("line") || arguments.get("column"))) fail("line/column requires a navigation operation");
    if (operation != "references" && arguments.get("include_declaration")) fail("include_declaration requires references");
    if (operation == "hover" && arguments.get("include_body")) fail("hover does not accept include_body");
    const bool named = arguments.get("name_path") || arguments.get("pattern");
    if ((arguments.get("name_path") && arguments.get("pattern")) || (arguments.get("patterns") && named))
        fail("give name_path, pattern, or patterns, not several");
    if (operation != "symbols" && arguments.get("patterns")) fail("patterns is only supported for symbol search");
    if (operation != "symbols" && operation != "overview" && named &&
        (arguments.get("line") || arguments.get("column"))) fail("give a symbol name or line/column, not both");
    const std::string diagnostic_check = str(arguments, "check", "lsp");
    if (diagnostic_check != "lsp" && diagnostic_check != "compiler" &&
        diagnostic_check != "build" && diagnostic_check != "all")
        fail("check must be lsp, compiler, build, or all");
    if (operation == "diagnostics" && diagnostic_check != "lsp") {
        if (context.read_only) fail("external diagnostic commands are disabled by --read-only");
        if (named || flag(arguments, "group_by_symbol") ||
            number(arguments, "start_line", 1) != 1 || number(arguments, "end_line", -1) != -1)
            fail("external checks do not accept symbol or line filters; use check=lsp for those filters");
        J::Object report{{"items", J::Array{}}, {"path", str(arguments, "path", ".")}};
        J::Object checks;
        bool complete = true, successful = true;
        if (diagnostic_check == "all") {
            auto lsp_arguments = arguments.object();
            lsp_arguments.erase("check");
            try {
                report = lsp_query(operation, J(std::move(lsp_arguments)), context, cancelled).object();
                for (auto& item : std::get<J::Array>(report.at("items").value)) {
                    auto& fields = std::get<J::Object>(item.value);
                    fields["origin"] = "lsp";
                    fields["position_encoding"] = "utf-16";
                    fields["coordinate_base"] = 1;
                    if (number(item, "severity", 1) == 1) successful = false;
                }
                const bool partial = report.contains("partial") && report.at("partial").boolean();
                if (partial) { complete = false; successful = false; }
                checks.emplace("lsp", J::Object{{"status", partial ? "partial" : "reported"}});
                if (const auto coverage = report.find("coverage"); coverage != report.end())
                    report["lsp_coverage"] = coverage->second;
            } catch (const IndexWarmingFailure& error) {
                control.check();
                complete = false; successful = false;
                checks.emplace("lsp", J::Object{{"status", "unavailable"}, {"error", error.what()},
                    {"code", "index_warming"}, {"details", error.details}});
            } catch (const SymbolLookupFailure& error) {
                control.check();
                complete = false; successful = false;
                checks.emplace("lsp", J::Object{{"status", "unavailable"}, {"error", error.what()},
                    {"code", "symbol_lookup"}, {"details", error.details}});
            } catch (const std::exception& error) {
                control.check();
                complete = false; successful = false;
                checks.emplace("lsp", J::Object{{"status", "unavailable"}, {"error", error.what()}});
            }
        }
        for (const char* kind : {"compiler", "build"}) {
            if (diagnostic_check != "all" && diagnostic_check != kind) continue;
            if (cancelled && cancelled->load()) control.check();
            // An earlier check that used up the deadline keeps its report; this one is reported as not run.
            if (Clock::now() >= control.deadline) {
                complete = false;
                successful = false;
                checks.emplace(kind, J::Object{{"source", kind}, {"status", "timed_out"}, {"successful", false},
                    {"items", J::Array{}}, {"error", "not run: the request deadline expired during an earlier check"}});
                continue;
            }
            J checked = external_diagnostics(kind, arguments, context, control.deadline, cancelled);
            const auto status = str(checked, "status");
            if (status != "completed" && status != "failed") complete = false;
            if (status == "failed" && checked.get("error")) complete = false;
            if (flag(checked, "output_truncated") || flag(checked, "items_truncated")) complete = false;
            if (!flag(checked, "successful")) successful = false;
            auto& items = std::get<J::Array>(report.at("items").value);
            for (const auto& item : checked.get("items")->array()) items.push_back(item);
            checks.emplace(kind, std::move(checked));
        }
        report["check"] = diagnostic_check;
        report["checks"] = std::move(checks);
        report["successful"] = successful;
        report["partial"] = !complete;
        report["coordinate_base"] = 1;
        report["position_encoding"] = diagnostic_check == "all" ? "mixed" : "compiler";
        report["coverage"] = J::Object{{"origin", diagnostic_check == "all" ? "lsp_and_external_commands" : "external_command"},
            {"note", "Command status covers only the configured command and its scope. Compiler columns retain their native units; they are not LSP UTF-16 ranges."}};
        return report;
    }
    const std::string path = str(arguments, "path");
    std::optional<SourceText> scope;
    if (!path.empty()) {
        bool directory = false;
        scope = source_descriptor(context, path, &directory);
        if (!directory && !lsp_required(scope->path, scope->root))
            fail("LSP operations are only for programming files and XML; use text tools for this file");
        if (!directory && operation == "files") {
            const auto config = configuration(*scope, context, cancelled);
            J::Array files;
            if (config) files.push_back(J::Object{{"path", shown_path(*scope)}, {"root", utf8(scope->root.wstring())}, {"language_id", document_language_id(*config, scope->path)}});
            return J::Object{{"results", std::move(files)}, {"backend", "lsp"}};
        }
        if (!directory) {
            const auto config = configuration(*scope, context, cancelled);
            if (!config) server_fail(missing_server_message(*scope));
            const SourceText source = read_source_text(context, path);
            return query_file(operation, arguments, source, *config, context, control, synchronized);
        }
    }
    if (operation != "symbols" && operation != "overview" && operation != "files" && operation != "status" && operation != "restart")
        fail("this navigation operation requires a file path");
    auto below = [](const fs::path& child, const fs::path& parent) {
        std::wstring prefix = parent.wstring();
        if (!prefix.ends_with(L"\\") && !prefix.ends_with(L"/")) prefix += L"\\";
        const std::wstring candidate = child.wstring();
        return candidate.size() >= prefix.size() &&
            CompareStringOrdinal(candidate.data(), static_cast<int>(prefix.size()), prefix.data(), static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL;
    };
    J::Array results, warming_details;
    // Files of one server or project repeat the same warming state; keep one entry per distinct state.
    std::map<std::string, size_t> warming_index;
    std::vector<uint64_t> warming_counts;
    std::set<std::wstring, PathLess> scanned;
    bool any_server = false, partial = false;
    // Folder symbol searches: how many files the symbol index answered, and why the walk stopped early, if it did.
    bool folder_cut = false;
    size_t from_index = 0, reads_skipped = 0;
    std::string coverage_note;
    // Workspace profile: files a folder symbol walk left out, by role (indexed by FileRole) and by top folder.
    std::array<size_t, 4> skipped_by_role{};
    std::map<std::string, size_t> skipped_areas;
    // Files a server answered with positions that do not fit their text (PositionMismatch): left out and reported.
    std::vector<std::string> unanswered;
    size_t unanswered_count = 0;
    std::string unanswered_reason;
    // The names a folder symbol search asks for: a file whose indexed names hold none of them needs no read.
    std::vector<std::string> wanted_patterns;
    if (const J* list = arguments.get("patterns"); list && std::holds_alternative<J::Array>(list->value))
        for (const auto& item : list->array())
            if (std::holds_alternative<std::string>(item.value)) wanted_patterns.push_back(item.string());
    if (wanted_patterns.empty())
        if (std::string name = str(arguments, "name_path", str(arguments, "pattern")); !name.empty())
            wanted_patterns.push_back(std::move(name));
    // A pattern matches only symbols whose own name contains the pattern's last component (without a leading "/",
    // "#kind", "[index]" or "<generic>" part), so a file none of whose names contain it cannot match: skipping it is
    // safe. A file that might match is read and answered exactly; an empty component reads every file.
    const bool wanted_substring = flag(arguments, "substring_matching");
    std::vector<std::string> wanted_leaves;
    for (const auto& item : wanted_patterns) {
        std::string_view leaf = item;
        if (const size_t slash = leaf.rfind('/'); slash != std::string_view::npos) leaf.remove_prefix(slash + 1);
        if (const size_t cut = leaf.find_first_of("#[<("); cut != std::string_view::npos) leaf = leaf.substr(0, cut);
        wanted_leaves.emplace_back(leaf);
    }
    const auto worth_reading = [&](const std::vector<std::string>& names) {
        if (operation != "symbols" || wanted_leaves.empty()) return true;
        for (const auto& leaf : wanted_leaves) {
            if (leaf.empty()) return true;
            for (const auto& name : names)
                if (name.find(leaf) != std::string::npos ||
                    (wanted_substring && lower(name).find(lower(leaf)) != std::string::npos)) return true;
        }
        return false;
    };
    for (const auto& root : context.allowed_roots) {
        const fs::path absolute = fs::absolute(root).lexically_normal();
        if (scope && !below(scope->path, absolute) && !below(absolute, scope->path) &&
            PathLess{}(scope->path.wstring(), absolute.wstring()) != PathLess{}(absolute.wstring(), scope->path.wstring())) continue;
        // Status reports the last prepared C++ setup without configuring it.
        const auto config_started = Clock::now();
        const auto configured = configs(absolute, context, cancelled, operation != "status");
        if (operation == "status") {
            const auto log_delay = [&](const std::string& action, const Clock::time_point began) {
                const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - began).count();
                if (ms >= 500) index_log(false, "LSP status " + action + " took " + std::to_string(ms) + " ms");
            };
            const std::string root_name = utf8(absolute.wstring());
            log_delay("configuration for " + root_name, config_started);
            for (const auto& config : configured) {
                const auto scan_started = Clock::now();
                const bool eligible = worth_starting(config, context, control);
                log_delay("file scan for " + config.server + " in " + root_name, scan_started);
                if (!eligible) continue;
                auto sessions = existing_sessions_for(config);
                if (sessions.empty()) sessions.push_back(std::make_shared<Session>(config));
                for (auto& session : sessions) {
                    if (!synchronized.insert(session->config.key).second) continue;
                    const auto lock_started = Clock::now();
                    std::unique_lock<std::timed_mutex> lock(session->mutex, std::defer_lock);
                    while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
                    log_delay("waiting for " + config.server + " in " + root_name, lock_started);
                    const auto status_started = Clock::now();
                    results.push_back(session->status(str(arguments, "detail", "summary") == "full"));
                    log_delay("reading " + config.server + " in " + root_name, status_started);
                }
            }
            continue;
        }
        if (operation == "restart") {
            for (const auto& config : configured) {
                if (!worth_starting(config, context, control)) continue;
                auto sessions = existing_sessions_for(config);
                if (sessions.empty()) sessions.push_back(session_for(config));
                for (auto& session : sessions) {
                    if (!synchronized.insert(session->config.key).second) continue;
                    std::unique_lock<std::timed_mutex> lock(session->mutex, std::defer_lock);
                    while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
                    try {
                        session->stop();
                        session->start(control, &context);
                        session->synchronize(nullptr, context, control);
                        session->service_pending(control);
                        results.push_back(session->status(str(arguments, "detail", "summary") == "full"));
                    } catch (...) { session->stop(); throw; }
                }
            }
            continue;
        }
        std::vector<std::string> extensions;
        for (const auto& config : configured)
            extensions.insert(extensions.end(), config.extensions.begin(), config.extensions.end());
        if (extensions.empty()) continue;
        any_server = true;
        // Walk only the requested folder: walking the whole root and dropping files outside the scope afterwards read
        // every file of the root first (42,241 for rust-experimental when old tools was asked) and ran out of time.
        // source_paths walks from the configured root (its ignore rules start there); the filter keeps only the
        // folders leading to the scope and everything inside it.
        const bool scoped = scope && below(scope->path, absolute);
        const fs::path walk = scoped ? scope->path : absolute;
        std::function<bool(const std::string&, bool)> in_scope;
        if (scoped) {
            const std::string scope_relative = lower(utf8(scope->path.lexically_relative(absolute).generic_wstring()));
            in_scope = [scope_relative](const std::string& child, bool folder) {
                const std::string name = lower(child);
                if (name == scope_relative || name.starts_with(scope_relative + "/")) return true;
                return folder && scope_relative.starts_with(name + "/");
            };
        }
        const auto paths = source_paths(context, utf8(absolute.wstring()), extensions, control.deadline, cancelled, in_scope);
        // A folder query asks a server about each file in turn; the log shows its size, slow files and where it stopped.
        const auto folder_started = Clock::now();
        const std::string folder_name = utf8(walk.wstring());
        if (operation != "files")
            index_log(false, "folder " + operation + " over " + folder_name + ": " + std::to_string(paths.size()) +
                             " source files");
        // Workspace profile (workspace_profile.hpp): data, generated and vendored files stay out of a folder symbol
        // walk (and of the meaning index's listing), so servers spend their time on source. A scope that holds nothing else is walked in full: a request
        // aimed at such a folder asked for those files. Path roles need no I/O; content roles read a file's head.
        const bool symbol_walk = operation == "symbols" || operation == "overview";
        std::vector<FileRole> roles(paths.size(), FileRole::source);
        bool profile_filter = false;
        // The meaning index lists its files with source_only, so it embeds no data, generated or vendored file.
        const bool profile_walk = symbol_walk || (operation == "files" && flag(arguments, "source_only"));
        if (profile_walk) {
            // Layer 3 build evidence, asked of the file system once per folder and file name in this walk.
            const FolderProbe probe = file_system_probe(absolute);
            size_t source_files = 0;
            for (size_t i = 0; i < paths.size(); ++i) {
                const fs::path native(wide(paths[i]));
                roles[i] = file_path_role(absolute, native, language_extension(native), &probe);
                if (roles[i] == FileRole::source) ++source_files;
            }
            profile_filter = source_files > 0;
        }
        // Symbol searches stop at 90% of the request's time and answer with what they have, marked partial: every
        // outline fetched so far stays in the symbol index, so a repeated call goes further instead of starting over.
        const auto budget = control.deadline - folder_started;
        const auto soft_stop = budget > std::chrono::hours(1) ? Clock::time_point::max() : folder_started + budget * 9 / 10;
        // Server configuration depends only on a file's folder and extension (project_profile looks upward from the
        // folder), so it is resolved once per folder and extension instead of once per file.
        std::map<std::string, std::optional<Config>> profiles;
        for (const auto& file : paths) {
            if (symbol_walk && Clock::now() >= soft_stop) {
                folder_cut = true;
                coverage_note = "the walk stopped after " + std::to_string(scanned.size()) + " of " +
                                std::to_string(paths.size()) + " files in " + folder_name +
                                " to answer within timeout_ms; outlines fetched so far are kept, so repeating the call "
                                "goes further, or narrow relative_path";
                index_log(true, "folder " + operation + ": " + coverage_note);
                break;
            }
            try { control.check(); }
            catch (const std::exception& e) {
                if (operation != "files")
                    index_log(true, "folder " + operation + " over " + folder_name + " stopped after " +
                                    std::to_string(scanned.size()) + " of " + std::to_string(paths.size()) + " files (" +
                                    std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        Clock::now() - folder_started).count()) + " ms): " + e.what());
                throw;
            }
            SourceText source;
            try {
                source = source_descriptor(context, file);
                if (!lsp_required(source.path, source.root)) continue;
            }
            catch (const std::exception& e) {
                // Same rule as Session::synchronize: legacy-encoded files stay out of LSP results.
                if (std::string(e.what()).ends_with(" is not valid Unicode source text")) continue;
                throw;
            }
            if (scope && !below(source.path, scope->path) &&
                (PathLess{}(source.path.wstring(), scope->path.wstring()) || PathLess{}(scope->path.wstring(), source.path.wstring()))) continue;
            if (!scanned.insert(source.path.wstring()).second) continue;
            if (profile_filter) {
                FileRole role = roles[static_cast<size_t>(&file - paths.data())];
                if (role == FileRole::source && language_kind(language_extension(source.path)) == LanguageKind::programming) {
                    const std::string role_key = lower(utf8(source.path.wstring()));
                    const std::string role_stamp = file_stamp(source.path);
                    if (const auto known = role_stamp.empty() ? std::nullopt : role_cache().find(role_key, role_stamp))
                        role = *known;
                    else {
                        // An unreadable head stays source: the full read below reports the real problem.
                        try { role = content_role(read_source_head(context, file, profile_head_bytes)); }
                        catch (const std::exception&) { role = FileRole::source; }
                        if (!role_stamp.empty()) role_cache().store(role_key, role_stamp, role);
                    }
                }
                if (role != FileRole::source) {
                    ++skipped_by_role[static_cast<size_t>(role)];
                    const std::wstring below_walk = source.path.lexically_relative(walk).generic_wstring();
                    const size_t slash = below_walk.find(L'/');
                    ++skipped_areas[slash == std::wstring::npos ? std::string(".") : utf8(below_walk.substr(0, slash))];
                    continue;
                }
            }
            const std::string profile_key = lower(utf8(source.path.parent_path().wstring())) + "|" +
                                            language_extension(source.path);
            auto profile = profiles.find(profile_key);
            if (profile == profiles.end()) profile = profiles.emplace(profile_key, configuration(source, context, cancelled)).first;
            const std::optional<Config>& config = profile->second;
            if (!config || path_excluded(*config, source.path)) continue;
            if (operation == "files") {
                results.push_back(J::Object{{"path", shown_path(source)}, {"root", utf8(source.root.wstring())}, {"language_id", document_language_id(*config, source.path)}});
                continue;
            }
            J::Object per_file = arguments.object();
            per_file["path"] = file;
            const auto file_started = Clock::now();
            // The symbol index answers unchanged files without the server; hover info still needs it.
            const bool indexable = symbol_walk && !config->managed_projects && !flag(arguments, "include_info") &&
                                   !flag(arguments, "require_unique") && !flag(arguments, "require_match");
            const std::string index_key = indexable ? symbol_index_key(*config, source.path) : std::string();
            // The stamp is taken before the read, so a change during the read can only cause a later re-read.
            const std::string stamp = indexable ? file_stamp(source.path) : std::string();
            if (!stamp.empty())
                if (const auto names = symbol_index().names_stamped(index_key, stamp); names && !worth_reading(*names)) {
                    ++from_index;
                    ++reads_skipped;
                    continue;
                }
            try { source = read_source_text(context, file); }
            catch (const std::exception& e) {
                // Same rule as Session::synchronize: legacy-encoded files stay out of LSP results.
                if (std::string(e.what()).ends_with(" is not valid Unicode source text")) continue;
                throw;
            }
            std::optional<std::vector<Symbol>> cached;
            if (indexable) cached = symbol_index().find(index_key, source.sha256);
            if (cached) ++from_index;
            J response;
            try {
                // A single slow server call must not consume the response's reserved time.
                const Control file_control{symbol_walk ? soft_stop : control.deadline, cancelled};
                response = query_file(operation, per_file, source, *config, context, file_control, synchronized, true,
                                      cached ? &*cached : nullptr);
            } catch (const LspTimeoutFailure&) {
                if (!symbol_walk || Clock::now() < soft_stop || (cancelled && cancelled->load())) throw;
                folder_cut = true;
                coverage_note = "the walk stopped while reading " + file + " after attempting " +
                    std::to_string(scanned.size()) + " of " + std::to_string(paths.size()) +
                    " files; results are incomplete. Repeat the call or narrow relative_path";
                index_log(true, "folder " + operation + ": " + coverage_note);
                break;
            } catch (const IndexWarmingFailure& e) {
                const std::string reason = str(e.details, "reason");
                if (!symbol_walk || Clock::now() < soft_stop - std::chrono::seconds(2) ||
                    (cancelled && cancelled->load()) ||
                    (reason != "index_in_progress" && reason != "server_start_timeout")) throw;
                folder_cut = true;
                coverage_note = "the walk stopped while waiting for " + config->server + " at " + file +
                    "; results are incomplete. Repeat the call or narrow relative_path";
                index_log(true, "folder " + operation + ": " + coverage_note);
                break;
            } catch (const PositionMismatch& e) {
                // One file whose server positions do not fit its text must not end a folder walk.
                if (unanswered.size() < 5) unanswered.push_back(utf8(source.path.wstring()) + " (" + config->server + ")");
                ++unanswered_count;
                if (unanswered_reason.empty()) unanswered_reason = e.what();
                index_log(true, "folder " + operation + " over " + folder_name + " left out " +
                                utf8(source.path.wstring()) + " (" + config->server + "): " + e.what());
                continue;
            } catch (const std::exception& e) {
                index_log(true, "folder " + operation + " over " + folder_name + " stopped at " +
                                utf8(source.path.wstring()) + " (" + config->server + ", " +
                                std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                                    Clock::now() - folder_started).count()) + " ms in): " + e.what());
                throw;
            }
            if (!stamp.empty()) symbol_index().attach_stamp(index_key, source.sha256, stamp);
            if (const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - file_started).count();
                took >= 2000)
                index_log(false, "slow folder " + operation + ": " + config->server + " took " + std::to_string(took) +
                                 " ms for " + utf8(source.path.wstring()));
            if (const J* flag_value = response.get("partial"); flag_value && flag_value->boolean()) {
                partial = true;
                if (const J* details = response.get("index_warming")) {
                    const auto [group, inserted] = warming_index.emplace(details->dump(), warming_details.size());
                    if (inserted) {
                        J::Object entry = details->object();
                        entry["paths"] = J::Array{};
                        warming_details.emplace_back(std::move(entry));
                        warming_counts.push_back(0);
                    }
                    auto& paths = std::get<J::Array>(std::get<J::Object>(warming_details[group->second].value)["paths"].value);
                    if (paths.size() < 5) paths.emplace_back(shown_path(source));
                    ++warming_counts[group->second];
                }
            }
            for (const auto& symbol : response.get("results")->array()) {
                J::Object item = symbol.object();
                item.emplace("root", utf8(absolute.wstring()));
                results.push_back(std::move(item));
            }
        }
        if (operation != "files")
            index_log(false, "folder " + operation + " over " + folder_name + " done in " +
                             std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                                 Clock::now() - folder_started).count()) + " ms; " + std::to_string(from_index) +
                             " outlines from the symbol index, " + std::to_string(reads_skipped) + " without reading the file; " +
                             std::to_string(skipped_by_role[1]) + " data, " + std::to_string(skipped_by_role[2]) + " generated, " +
                             std::to_string(skipped_by_role[3]) + " vendored files left out");
        if (folder_cut) break;
    }
    if (operation == "symbols" || operation == "overview") symbol_index().save_if_due();
    // A scoped folder may hold no source files, but with no server at all an empty answer would hide the gap.
    if (operation != "files" && operation != "status" && synchronized.empty() && from_index == 0 && (!scope || !any_server)) server_fail("no LSP source files found; install the bundled servers with tools/fetch_lsp.py, or add one to .shgrep/lsp.json. This semantic request has no fallback; for plain text matches make a separate search call with operation=text");
    J::Object response{{"results", std::move(results)}, {"backend", "lsp"}};
    if ((operation == "status" || operation == "restart") && str(arguments, "detail", "summary") == "full") {
        J::Array capability_sets;
        std::map<std::string, uint64_t> known;
        for (auto& result : std::get<J::Array>(response.at("results").value)) {
            auto& row = std::get<J::Object>(result.value);
            const auto capability = row.find("capabilities");
            if (capability == row.end()) continue;
            const std::string key = capability->second.dump();
            auto [entry, inserted] = known.emplace(key, static_cast<uint64_t>(capability_sets.size()));
            if (inserted) capability_sets.push_back(capability->second);
            row["capability_set"] = entry->second;
            row.erase(capability);
        }
        if (!capability_sets.empty()) response.emplace("capability_sets", std::move(capability_sets));
    }
    if (operation == "symbols" || operation == "overview") {
        response.emplace("partial", partial || folder_cut);
        if (folder_cut) response.emplace("coverage_note", coverage_note);
        // Say what the workspace profile left out and how to get it, so a skipped file is never a silent miss.
        if (const size_t skipped = skipped_by_role[1] + skipped_by_role[2] + skipped_by_role[3]) {
            J::Object counts;
            std::string kinds;
            for (const FileRole role : {FileRole::data, FileRole::generated, FileRole::vendored}) {
                const size_t count = skipped_by_role[static_cast<size_t>(role)];
                if (!count) continue;
                counts.emplace(std::string(role_name(role)), static_cast<int64_t>(count));
                kinds += (kinds.empty() ? "" : ", ") + std::to_string(count) + " " + std::string(role_name(role));
            }
            std::vector<std::pair<size_t, std::string>> areas;
            for (const auto& [area, count] : skipped_areas) areas.emplace_back(count, area);
            std::sort(areas.begin(), areas.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
            std::string largest;
            for (size_t i = 0; i < areas.size() && i < 3; ++i)
                largest += (largest.empty() ? "" : ", ") + areas[i].second + " " + std::to_string(areas[i].first);
            response.emplace("skipped_files", std::move(counts));
            response.emplace("skipped_note", std::to_string(skipped) + " files left out as not source (" + kinds +
                "; largest folders: " + largest + "); point relative_path at one of those folders or files to include them");
        }
        if (unanswered_count) {
            std::string list;
            for (const auto& item : unanswered) list += (list.empty() ? "" : "; ") + item;
            if (unanswered_count > unanswered.size()) list += "; ...";
            response.emplace("unanswered_files", static_cast<int64_t>(unanswered_count));
            response.emplace("unanswered_note", std::to_string(unanswered_count) +
                " file(s) left out because the server's positions do not fit their text: " + list + ". First reason: " +
                unanswered_reason);
        }
        if (from_index) response.emplace("from_symbol_index", static_cast<int64_t>(from_index));
        for (size_t i = 0; i < warming_details.size(); ++i)
            std::get<J::Object>(warming_details[i].value)["file_count"] = warming_counts[i];
        if (partial) response.emplace("index_warming", std::move(warming_details));
    }
    return response;
}


Json lsp_outlines(const std::vector<std::string>& paths, const SearchContext& context,
                  const std::shared_ptr<std::atomic_bool>& cancelled, int64_t timeout_ms) {
    if (timeout_ms < 1 || timeout_ms > 300000) fail("timeout_ms must be 1-300000");
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout_ms)), cancelled};
    std::vector<SourceText> sources(paths.size());
    std::vector<std::string> errors(paths.size());
    std::vector<J> outlines(paths.size());
    struct Group {
        Config config;
        std::vector<size_t> items;
    };
    std::map<std::string, Group> groups;  // one per language server session
    for (size_t i = 0; i < paths.size(); ++i) {
        control.check();
        try {
            sources[i] = read_source_text(context, paths[i]);
            if (!lsp_required(sources[i].path, sources[i].root)) { errors[i] = "not a language-server file"; continue; }
            const auto config = configuration(sources[i], context, cancelled);
            if (!config || path_excluded(*config, sources[i].path)) { errors[i] = "no language server for this file"; continue; }
            groups.try_emplace(config->key, Group{*config, {}}).first->second.items.push_back(i);
        } catch (const LspFailure&) {
            throw;
        } catch (const std::exception& error) {
            errors[i] = error.what();
        }
    }
    // PERF: one request in flight per hardware thread keeps every core busy in the server.
    const size_t window = std::max<size_t>(std::thread::hardware_concurrency(), 4);
    std::set<std::string> synchronized;
    for (auto& [key, group] : groups) {
        if (group.config.managed_projects) {
            // C# project loading has its own lifecycle; those files keep the one-at-a-time path.
            for (const size_t i : group.items) {
                try {
                    outlines[i] = query_file("overview", J::Object{{"path", paths[i]}, {"depth", static_cast<int64_t>(-1)}},
                                             sources[i], group.config, context, control, synchronized, true);
                } catch (const LspTimeoutFailure&) {
                    throw;
                } catch (const std::exception& error) {
                    errors[i] = error.what();
                }
            }
            continue;
        }
        // Unchanged files are answered from the symbol index; only the rest go to the server.
        std::vector<size_t> pending;
        for (const size_t i : group.items) {
            control.check();
            if (auto cached = symbol_index().find(symbol_index_key(group.config, sources[i].path), sources[i].sha256)) {
                J::Array rows;
                rows.reserve(cached->size());
                for (const auto& symbol : *cached) rows.push_back(symbol_json(symbol, sources[i], false, false));
                outlines[i] = J::Object{{"results", std::move(rows)}};
            } else pending.push_back(i);
        }
        if (pending.empty()) continue;
        auto session = session_for(group.config);
        std::unique_lock<std::timed_mutex> lock(session->mutex, std::defer_lock);
        while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
        const SourceText& first = sources[pending.front()];
        try {
            session->start(control, &context, &first, false, true);
            if (synchronized.insert(group.config.key).second) session->synchronize(&first, context, control);
            session->service_pending(control);
        } catch (...) {
            session->stop();  // a half-started server is not reused (query_file does the same)
            throw;
        }
        std::vector<SourceText> batch;
        batch.reserve(pending.size());
        for (const size_t i : pending) batch.push_back(sources[i]);
        std::vector<J> raw;
        std::vector<std::string> failed;
        session->outline_batch(batch, window, raw, failed, control);
        for (size_t n = 0; n < pending.size(); ++n) {
            const size_t i = pending[n];
            if (!failed[n].empty()) { errors[i] = failed[n]; continue; }
            std::vector<Symbol> found;
            flatten(raw[n], "", 0, found, group.config.language, wide(sources[i].text), control);
            if (!found.empty() || session->ever_ready())
                symbol_index().store(symbol_index_key(group.config, sources[i].path), sources[i].sha256, found);
            J::Array rows;
            rows.reserve(found.size());
            for (const auto& symbol : found) rows.push_back(symbol_json(symbol, sources[i], false, false));
            outlines[i] = J::Object{{"results", std::move(rows)}};
        }
    }
    symbol_index().save_if_due();
    J::Array files;
    files.reserve(paths.size());
    for (size_t i = 0; i < paths.size(); ++i) {
        J::Object entry{{"path", paths[i]}, {"sha256", sources[i].sha256}};
        if (!errors[i].empty()) entry.emplace("error", errors[i]);
        else entry.emplace("outline", std::move(outlines[i]));
        files.push_back(std::move(entry));
    }
    return J::Object{{"files", std::move(files)}};
}

namespace {
std::unique_lock<std::timed_mutex> acquire(Session& session, const Control& control) {
    std::unique_lock<std::timed_mutex> lock(session.mutex, std::defer_lock);
    while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
    return lock;
}
std::string newlines(const std::string& text, const std::string& reference) {
    const bool crlf = reference.find("\r\n") != std::string::npos;
    const bool cr = !crlf && reference.find('\n') == std::string::npos && reference.find('\r') != std::string::npos;
    std::string out;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\r' || text[i] == '\n') {
            if (text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n') ++i;
            out += crlf ? "\r\n" : cr ? "\r" : "\n";
        } else out.push_back(text[i]);
    }
    return out;
}

// Byte spans [begin, end) of comments and string literals, found by a conservative per-family lexer. nullopt when the
// extension has no lexer here, or when a JavaScript/TypeScript template cannot be classified safely; callers then leave
// that file untouched. Template-literal substitutions (${...}) stay code, so identifiers there are never treated as text.
std::optional<std::vector<std::pair<size_t, size_t>>> comment_string_spans(const fs::path& path, std::string_view text) {
    const std::string ext = language_extension(path);
    static const std::set<std::string> c_like{".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp",
        ".cs", ".java", ".kt", ".kts", ".swift", ".go", ".rs", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts",
        ".m", ".mm", ".scala", ".dart"};
    static const std::set<std::string> hash_like{".py", ".pyi", ".sh", ".bash", ".ps1", ".psm1", ".psd1", ".rb", ".toml",
        ".yaml", ".yml", ".cmake"};
    static const std::set<std::string> templates{".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"};
    static const std::set<std::string> cpp_family{".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp",
        ".m", ".mm"};
    const bool c = c_like.contains(ext), hash = hash_like.contains(ext), lua = ext == ".lua";
    if (!c && !hash && !lua) return std::nullopt;
    const bool python = ext == ".py" || ext == ".pyi", csharp = ext == ".cs", rust = ext == ".rs";
    const bool powershell = ext == ".ps1" || ext == ".psm1" || ext == ".psd1";
    const bool cpp = cpp_family.contains(ext);
    // Single quotes take no backslash escapes in these languages.
    const bool literal_single = ext == ".sh" || ext == ".bash" || powershell || ext == ".toml" || ext == ".yaml" || ext == ".yml";
    const size_t n = text.size();
    const auto ident = [](char ch) { return std::isalnum(static_cast<unsigned char>(ch)) || ch == '_'; };
    const auto line_end = [&](size_t from) {
        const size_t e = text.find_first_of("\r\n", from);
        return e == std::string_view::npos ? n : e;
    };
    const auto until = [&](size_t from, std::string_view close) {
        const size_t e = text.find(close, from);
        return e == std::string_view::npos ? n : e + close.size();
    };
    // One-line quoted literal; an escape skips the next byte. Stops at an unterminated line end.
    const auto quoted = [&](size_t start, char quote, bool escapes) {
        size_t j = start + 1;
        while (j < n && text[j] != '\r' && text[j] != '\n') {
            if (escapes && (text[j] == '\\' || (powershell && text[j] == '`')) && j + 1 < n) { j += 2; continue; }
            if (text[j] == quote) return j + 1;
            ++j;
        }
        return j;
    };
    std::vector<std::pair<size_t, size_t>> spans;
    // Interpolated strings keep their embedded expressions as code: C# $"..{x}..", Python f"..{x}..",
    // Kotlin/Dart/Scala "..${x}..", Swift "..\(x)..". Doubled braces are literal text in C# and Python.
    const bool dollar_brace = ext == ".kt" || ext == ".kts" || ext == ".dart" || ext == ".scala";
    const bool swift = ext == ".swift";
    const auto emit_string = [&](size_t begin, size_t end, bool braces) {
        size_t piece = begin;
        for (size_t j = begin; j < end;) {
            size_t open = 0;
            if (braces && text[j] == '{') {
                if (j + 1 < end && text[j + 1] == '{') { j += 2; continue; }
                open = 1;
            } else if (dollar_brace && text[j] == '$' && j + 1 < end && text[j + 1] == '{') open = 2;
            else if (dollar_brace && text[j] == '$' && j + 1 < end && ident(text[j + 1])) {
                spans.emplace_back(piece, j);  // "$name" templates: the name is code
                for (++j; j < end && ident(text[j]); ++j) {}
                piece = j;
                continue;
            } else if (swift && text[j] == '\\' && j + 1 < end && text[j + 1] == '(') open = 2;
            else if (text[j] == '\\' && j + 1 < end) { j += 2; continue; }
            if (!open) { ++j; continue; }
            spans.emplace_back(piece, j);
            const char opener = text[j + open - 1], closer = opener == '(' ? ')' : '}';
            size_t depth = 1;
            for (j += open; j < end && depth; ++j) {
                if (text[j] == opener) ++depth;
                else if (text[j] == closer) --depth;
            }
            piece = j;
        }
        spans.emplace_back(piece, end);
    };
    for (size_t i = 0; i < n;) {
        const char ch = text[i];
        const char next = i + 1 < n ? text[i + 1] : '\0';
        size_t end = 0;
        if (c && ch == '/' && next == '/') end = line_end(i);
        else if (c && ch == '/' && next == '*') end = until(i + 2, "*/");
        else if (powershell && ch == '<' && next == '#') end = until(i + 2, "#>");
        else if (hash && ch == '#') end = line_end(i);
        else if (lua && ch == '-' && next == '-')
            end = text.compare(i + 2, 2, "[[") == 0 ? until(i + 4, "]]") : line_end(i);
        else if (lua && ch == '[' && next == '[') end = until(i + 2, "]]");
        else if (python && (text.compare(i, 3, "\"\"\"") == 0 || text.compare(i, 3, "'''") == 0))
            end = until(i + 3, text.substr(i, 3));
        else if (csharp && text.compare(i, 3, "\"\"\"") == 0) {
            size_t quotes = 3;
            while (i + quotes < n && text[i + quotes] == '"') ++quotes;
            end = until(i + quotes, std::string(quotes, '"'));
        } else if (csharp && ch == '@' && next == '"') {
            size_t j = i + 2;
            while (j < n) {
                if (text[j] == '"') {
                    if (j + 1 < n && text[j + 1] == '"') { j += 2; continue; }
                    ++j;
                    break;
                }
                ++j;
            }
            end = j;
        } else if (cpp && ch == 'R' && next == '"' && (i == 0 || !ident(text[i - 1]) || text[i - 1] == '8' ||
                   text[i - 1] == 'L' || text[i - 1] == 'u' || text[i - 1] == 'U')) {
            const size_t open = text.find('(', i + 2);
            if (open != std::string_view::npos && open - i - 2 <= 16)
                end = until(open + 1, ")" + std::string(text.substr(i + 2, open - i - 2)) + "\"");
        } else if (rust && ch == 'r' && (next == '"' || next == '#') && (i == 0 || !ident(text[i - 1]))) {
            size_t hashes = 0;
            while (i + 1 + hashes < n && text[i + 1 + hashes] == '#') ++hashes;
            if (i + 1 + hashes < n && text[i + 1 + hashes] == '"')
                end = until(i + 2 + hashes, "\"" + std::string(hashes, '#'));
        } else if (templates.contains(ext) && ch == '`') {
            // Template literal: text pieces around ${...} substitutions, which remain code. A substitution is lexed as
            // code (quotes, comments, regex literals and nested templates), so a brace inside a string there cannot end
            // it early. Only the outermost template's text is emitted. Text that cannot be classified (an unterminated
            // template, string, comment or regex) makes the whole file unsupported, so the optional rewrite skips it.
            struct Frame { bool expression; size_t depth; };
            std::vector<Frame> stack{{false, 0}};
            const auto closed_quote = [&](size_t start, char quote) -> size_t {
                for (size_t k = start + 1; k < n && text[k] != '\r' && text[k] != '\n'; ++k) {
                    if (text[k] == '\\') {  // an escape, including a CRLF line continuation
                        ++k;
                        if (k + 1 < n && text[k] == '\r' && text[k + 1] == '\n') ++k;
                        continue;
                    }
                    if (text[k] == quote) return k + 1;
                }
                return std::string_view::npos;
            };
            // A '/' after one of these starts a regex literal; after a value it divides.
            const auto regex_follows = [](char previous) {
                return std::string_view("(,=:[!&|?{};+-*%<>~^").find(previous) != std::string_view::npos;
            };
            size_t j = i + 1, piece = j;
            char last = '{';  // last significant code byte in the current substitution
            while (j < n && !stack.empty()) {
                Frame& top = stack.back();
                const char at = text[j], after = j + 1 < n ? text[j + 1] : '\0';
                if (!top.expression) {
                    if (at == '\\' && j + 1 < n) { j += 2; continue; }
                    if (at == '`') {
                        if (stack.size() == 1) spans.emplace_back(piece, j);
                        stack.pop_back();
                        ++j;
                        last = ')';
                        continue;
                    }
                    if (at == '$' && after == '{') {
                        if (stack.size() == 1) spans.emplace_back(piece, j);
                        stack.push_back({true, 1});
                        j += 2;
                        last = '{';
                        continue;
                    }
                    ++j;
                    continue;
                }
                if (at == '\'' || at == '"') {
                    const size_t close = closed_quote(j, at);
                    if (close == std::string_view::npos) return std::nullopt;
                    j = close;
                    last = ')';
                } else if (at == '/' && after == '/') {
                    j = line_end(j);
                } else if (at == '/' && after == '*') {
                    const size_t close = text.find("*/", j + 2);
                    if (close == std::string_view::npos) return std::nullopt;
                    j = close + 2;
                } else if (at == '/' && regex_follows(last)) {
                    size_t k = j + 1;
                    bool in_class = false;
                    for (; k < n && text[k] != '\r' && text[k] != '\n'; ++k) {
                        if (text[k] == '\\') { ++k; continue; }
                        if (text[k] == '[') in_class = true;
                        else if (text[k] == ']') in_class = false;
                        else if (text[k] == '/' && !in_class) break;
                    }
                    if (k >= n || text[k] != '/') return std::nullopt;
                    for (j = k + 1; j < n && ident(text[j]); ++j) {}
                    last = ')';
                } else if (at == '`') {
                    stack.push_back({false, 0});
                    ++j;
                } else if (at == '{') {
                    ++top.depth;
                    last = '{';
                    ++j;
                } else if (at == '}') {
                    ++j;
                    last = '}';
                    if (--top.depth == 0) {
                        stack.pop_back();
                        if (stack.size() == 1) piece = j;
                    }
                } else {
                    if (!std::isspace(static_cast<unsigned char>(at))) last = at;
                    ++j;
                }
            }
            if (!stack.empty()) return std::nullopt;
            i = j;
            continue;
        } else if (ch == '"') end = quoted(i, '"', true);
        else if (ch == '\'') {
            if (rust) {
                // 'x' or '\n' is a char literal; anything else ('a in generics) is a lifetime.
                if (next == '\\') end = quoted(i, '\'', true);
                else if (i + 2 < n && text[i + 2] == '\'') end = i + 3;
            } else if (!(cpp && i > 0 && std::isxdigit(static_cast<unsigned char>(text[i - 1])) &&
                         std::isxdigit(static_cast<unsigned char>(next)))) {  // skip C++14 digit separators
                end = quoted(i, '\'', !literal_single);
            }
        }
        if (end > i) {
            const bool interpolated_prefix = i > 0 && ((csharp && (text[i - 1] == '$' || (text[i - 1] == '@' && i > 1 &&
                text[i - 2] == '$'))) || (python && (text[i - 1] == 'f' || text[i - 1] == 'F')));
            const bool csharp_at_dollar = csharp && ch == '@' && i > 0 && text[i - 1] == '$';
            if ((text[i] == '"' || text[i] == '\'' || csharp_at_dollar) && (interpolated_prefix || csharp_at_dollar ||
                ((dollar_brace || swift) && text[i] == '"')))
                emit_string(i, end, interpolated_prefix || csharp_at_dollar);
            else spans.emplace_back(i, end);
            i = end;
        } else ++i;
    }
    return spans;
}

// Rewrite whole-word old_name mentions inside comments or string literals of the files a rename already edits.
// Returns a note for the response; files without a lexer are listed and left as they are.
std::string rewrite_rename_text_mentions(const std::string& old_name, const std::string& new_name,
                                         std::vector<SourceChange>& changes) {
    if (old_name.empty() || old_name == new_name) return {};
    const auto word = [](unsigned char ch) { return std::isalnum(ch) || ch == '_' || ch >= 0x80; };
    size_t total = 0, files = 0;
    std::vector<std::string> unsupported;
    for (auto& change : changes) {
        const auto spans = comment_string_spans(change.before.path, change.after);
        if (!spans) { unsupported.push_back(shown_path(change.before)); continue; }
        std::string out;
        size_t copied = 0, count = 0;
        for (const auto& [begin, end] : *spans) {
            const std::string_view bounded(change.after.data(), end);  // keeps each search inside its span
            for (size_t at = bounded.find(old_name, begin); at != std::string_view::npos;
                 at = bounded.find(old_name, at + old_name.size())) {
                const size_t stop = at + old_name.size();
                if ((at > 0 && word(static_cast<unsigned char>(change.after[at - 1]))) ||
                    (stop < change.after.size() && word(static_cast<unsigned char>(change.after[stop])))) continue;
                out.append(change.after, copied, at - copied);
                out += new_name;
                copied = stop;
                ++count;
            }
        }
        if (!count) continue;
        out.append(change.after, copied, std::string::npos);
        change.after = std::move(out);
        total += count;
        ++files;
    }
    std::string note;
    if (total)
        note = "[renamed " + std::to_string(total) + " comment/string mention" + (total == 1 ? "" : "s") + " of " +
               old_name + " in " + std::to_string(files) + " file" + (files == 1 ? "" : "s") + " the rename already edits]\n";
    if (!unsupported.empty()) {
        note += "[comment/string rewrite skipped for " + std::to_string(unsupported.size()) + " file" +
                (unsupported.size() == 1 ? "" : "s") +
                " with no lexer for its language or text it could not classify safely (e.g. an unterminated template):";
        for (size_t i = 0; i < std::min<size_t>(5, unsupported.size()); ++i) note += " " + unsupported[i];
        if (unsupported.size() > 5) note += " ...";
        note += "]\n";
    }
    return note;
}
// CONTRACT: a language server renames only what it understands: one language, never strings, comments, FFI
//   declarations or build files. The old name is looked up as a whole word in the workspace's other text files,
//   and the ones the rename leaves alone are listed so a cross-language use (a Rust extern for a C function) is not
//   missed. Best effort: it stops at the request's deadline and says so.
std::string rename_leftovers(const std::string& old_name, const std::vector<SourceChange>& changes,
                             const SearchContext& context, const Control& control) {
    if (old_name.empty()) return {};
    static const std::vector<std::string> kinds{
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp", ".rs", ".py", ".pyi", ".lua", ".xml",
        ".json", ".toml", ".yaml", ".yml", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte",
        ".cs", ".razor", ".cshtml", ".xaml", ".csproj", ".props", ".targets", ".sql", ".html", ".css", ".scss", ".go",
        ".java", ".kt", ".kts", ".swift", ".m", ".mm", ".def", ".idl", ".cmake", ".txt", ".md", ".bat", ".ps1", ".psm1",
        ".sh"};
    std::map<std::wstring, const SourceChange*, PathLess> changed;
    for (const auto& change : changes) changed.emplace(change.before.path.wstring(), &change);
    const auto word = [](unsigned char c) { return std::isalnum(c) || c == '_' || c >= 0x80; };
    // Exclude vendored trees; remaining text mentions can include comments, strings, and unrelated names.
    static const std::set<std::string> vendored{"libs", "third_party", "thirdparty", "3rdparty", "vendor",
                                                "external", "extern", "deps", "node_modules", "target"};
    // Decided from the root-relative path before reading, so vendored trees cost no file reads.
    const auto vendored_path = [&](const std::string& path) {
        std::string relative = lower(path);
        for (const auto& root : context.allowed_roots) {
            std::string prefix = lower(utf8(fs::absolute(root).lexically_normal().wstring()));
            if (!prefix.ends_with("\\")) prefix += "\\";
            if (relative.starts_with(prefix)) { relative.erase(0, prefix.size()); break; }
        }
        size_t start = 0;
        for (size_t slash = relative.find_first_of("/\\"); slash != std::string::npos; slash = relative.find_first_of("/\\", start)) {
            const std::string part = relative.substr(start, slash - start);
            // Build output and bundled SDKs: build, build-llvm, dist, bin, obj, out, llvm-sdk.
            if (vendored.contains(part) || part.starts_with("build") || part == "dist" || part == "bin" ||
                part == "obj" || part == "out" || part.ends_with("-sdk")) return true;
            start = slash + 1;
        }
        return false;
    };
    std::set<std::wstring, PathLess> edited_paths;
    for (const auto& change : changes) edited_paths.insert(change.before.path.wstring());
    std::vector<std::string> hits;
    size_t files = 0, total = 0, vendored_skipped = 0, unreadable = 0;
    bool partial = false;  // the deadline or an error ended the scan early
    try {
        std::vector<std::string> paths;
        for (const auto& root : context.allowed_roots) {
            auto listed = source_paths(context, utf8(root.wstring()), kinds, control.deadline, control.cancelled);
            paths.insert(paths.end(), listed.begin(), listed.end());
        }
        for (const auto& change : changes) paths.push_back(utf8(change.before.path.wstring()));
        std::set<std::wstring, PathLess> scanned_paths;
        for (const auto& path : paths) {
            if (Clock::now() >= control.deadline) { partial = true; break; }
            // Vendored trees are skipped unless the rename itself edits the file.
            if (!edited_paths.contains(fs::path(wide(path)).lexically_normal().wstring()) && vendored_path(path)) {
                ++vendored_skipped;
                continue;
            }
            SourceText text;
            try { text = read_source_text(context, path); }
            catch (const std::exception&) { ++unreadable; continue; }  // legacy-encoded, binary or too large
            if (!scanned_paths.insert(text.path.wstring()).second) continue;
            const auto edited = changed.find(text.path.wstring());
            if (edited != changed.end()) text.text = edited->second->after;
            bool counted = false;
            uint64_t line = 1;
            size_t line_start = 0, scanned = 0;
            for (size_t at = text.text.find(old_name); at != std::string::npos; at = text.text.find(old_name, at + 1)) {
                control.check();
                const size_t end = at + old_name.size();
                if ((at > 0 && word(static_cast<unsigned char>(text.text[at - 1]))) ||
                    (end < text.text.size() && word(static_cast<unsigned char>(text.text[end])))) continue;
                for (; scanned < at; ++scanned) {
                    if (text.text[scanned] == '\r' || text.text[scanned] == '\n') {
                        if (text.text[scanned] == '\r' && scanned + 1 < at && text.text[scanned + 1] == '\n') ++scanned;
                        ++line;
                        line_start = scanned + 1;
                    }
                }
                if (!counted) { ++files; counted = true; }
                ++total;
                if (hits.size() < 10) {
                    const size_t line_end = text.text.find_first_of("\r\n", at);
                    std::string shown = text.text.substr(line_start, (line_end == std::string::npos ? text.text.size() : line_end) - line_start);
                    const size_t first = shown.find_first_not_of(" \t");
                    shown = first == std::string::npos ? std::string{} : shown.substr(first, 160);
                    hits.push_back("  " + shown_path(text) + ":" + std::to_string(line) + ": " + shown);
                }
            }
        }
    } catch (const std::exception&) { partial = true; }
    if (!total && !partial) return {};
    std::string out = "[warning: " + std::to_string(total) + " whole-word mention" + (total == 1 ? "" : "s") + " of " + old_name +
                      " in " + std::to_string(files) + " file" + (files == 1 ? "" : "s") + " after the planned rename "
                      "(including comments, strings and unrelated names; " + std::to_string(vendored_skipped) +
                      " untouched vendored or build-output file" + (vendored_skipped == 1 ? "" : "s") + " skipped" +
                      (unreadable ? ", " + std::to_string(unreadable) + " file" + (unreadable == 1 ? "" : "s") +
                                    " not readable as Unicode text" : std::string()) + "); check them by hand" +
                      (partial ? "; the scan stopped at the request deadline, so there may be more" : "") + "]\n";
    for (const auto& hit : hits) out += hit + "\n";
    if (total > hits.size()) out += "  ... " + std::to_string(total - hits.size()) + " more\n";
    return out;
}

// After a multi-file write, before the watcher reports it, so the next request already sees the new bytes.
void resync_written(Session& session, const std::vector<SourceChange>& changes, const SearchContext& context, const Control& control) {
    for (const auto& change : changes) {
        try { session.pin(read_source_text(context, utf8(change.before.path.wstring())), control); }
        catch (const std::exception&) {}  // e.g. legacy-encoded now; the watcher's report closes it
    }
}
// CONTRACT: in indexes_workspace sessions, edits may target files the server only knows from its index. Those are
//   accepted when every replaced range still spells old_name (rename) or, without old_name, on the watcher's word
//   that the file is unchanged since the server read it.
std::vector<SourceChange> workspace_changes(Session& session, const J& edit, const Config& config,
                                           const SearchContext& context, const Control& control,
                                           const std::string& old_name = {}, bool require_synchronized = false) {
    if (std::holds_alternative<std::nullptr_t>(edit.value)) server_fail("language server returned no workspace edit");
    if (edit.get("changes") && edit.get("documentChanges")) server_fail("ambiguous workspace edit: changes and documentChanges");
    if (const J* annotations = edit.get("changeAnnotations"))
        for (const auto& [id, annotation] : annotations->object()) {
            (void)id;
            if (flag(annotation, "needsConfirmation")) fail("workspace edit requires an unsupported change confirmation; nothing written");
        }
    struct Entry { SourceText source; std::vector<J> edits; bool from_index = false; };
    std::map<std::wstring, Entry, PathLess> entries;
    auto add = [&](const std::string& id, const J& edits, const J* version) {
        control.check();
        const fs::path path = from_uri(id);
        if (path_excluded(config, path))
            fail("language server workspace edit targets ignored_paths; nothing written");
        SourceText source = read_source_text(context, utf8(path.wstring()));
        if (require_synchronized && !session.has_document(source))
            fail("rename target changed or is not synchronized; nothing written, retry");
        const bool from_index = session.config.indexes_workspace && !session.is_open(source);
        const bool versioned = version && !std::holds_alternative<std::nullptr_t>(version->value);
        if (from_index) {
            if (versioned) fail("stale workspace edit document version");
        } else {
            session.assert_current(source);
            if (versioned && version->integer() != session.document_version(source)) fail("stale workspace edit document version");
        }
        auto [it, inserted] = entries.try_emplace(source.path.wstring(), Entry{source, {}, from_index});
        if (!inserted && it->second.source.sha256 != source.sha256) fail("workspace edit source changed during planning");
        for (const auto& item : edits.array()) it->second.edits.push_back(item);
    };
    if (const J* changes = edit.get("changes"))
        for (const auto& [id, edits] : changes->object()) add(id, edits, nullptr);
    if (const J* changes = edit.get("documentChanges"))
        for (const auto& change : changes->array()) {
            if (change.get("kind")) fail("workspace edit contains a file resource operation; use move_file for file moves; nothing written");
            const J* document = change.get("textDocument"), *edits = change.get("edits");
            if (!document || !edits) fail("invalid TextDocumentEdit");
            add(str(*document, "uri"), *edits, document->get("version"));
        }
    std::vector<SourceChange> result;
    for (auto& [path, entry] : entries) {
        (void)path; control.check();
        struct Replacement { size_t start, end, order; std::wstring text; };
        std::vector<Replacement> replacements;
        std::wstring text = wide(entry.source.text);
        // F4: a replacement keeps the endings of the lines it matches in the range it replaces; new lines take the
        // ending next to the edit, not one style chosen for the whole (possibly mixed) file.
        const std::string file_ending = newlines("\n", entry.source.text);
        const auto nearby = [&](size_t at) -> std::string {
            const size_t before = at ? text.find_last_of(L"\r\n", at - 1) : std::wstring::npos;
            const size_t found = before == std::wstring::npos ? text.find_first_of(L"\r\n", at) : before;
            if (found == std::wstring::npos) return file_ending;
            if (text[found] == L'\n') return found && text[found - 1] == L'\r' ? "\r\n" : "\n";
            return found + 1 < text.size() && text[found + 1] == L'\n' ? "\r\n" : "\r";
        };
        for (const auto& item : entry.edits) {
            const J* extent = item.get("range"), *replacement = item.get("newText");
            if (!extent || !replacement) server_fail("invalid LSP TextEdit");
            const Range r = range(*extent);
            if (entry.from_index && !old_name.empty() &&
                text.substr(offset(text, r.start), offset(text, r.end) - offset(text, r.start)) != wide(old_name))
                fail("the language server's index is out of date for " + utf8(entry.source.path.wstring()) +
                     "; nothing written, retry once it has caught up");
            const size_t start = offset(text, r.start), stop = offset(text, r.end);
            const std::string& inserted = replacement->string();
            replacements.push_back({start, stop, replacements.size(),
                inserted.find_first_of("\r\n") == std::string::npos ? wide(inserted)
                    : wide(preserve_line_endings(utf8(text.substr(start, stop - start)), inserted, nearby(start),
                                                 control.cancelled))});
        }
        // SolidLSP applies edits from the end; same-position inserts retain protocol array order.
        std::sort(replacements.begin(), replacements.end(), [](const auto& a, const auto& b) {
            if (a.start != b.start) return a.start > b.start;
            return a.order > b.order;
        });
        size_t boundary = text.size() + 1;
        for (const auto& replacement : replacements) {
            if (replacement.end > boundary || (replacement.start == boundary && replacement.end > replacement.start))
                server_fail("overlapping LSP TextEdits; nothing written");
            text.replace(replacement.start, replacement.end - replacement.start, replacement.text);
            boundary = replacement.start;
        }
        result.push_back({std::move(entry.source), utf8(text)});
    }
    return result;
}
}

namespace {
// Serena CodeEditor symbol layout rules; see third_party/solidlsp-LICENSE.txt.
bool edit_space(wchar_t c) {
    return (c >= 0x09 && c <= 0x0d) || (c >= 0x1c && c <= 0x20) || c == 0x85 || c == 0xa0 ||
        c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f ||
        c == 0x205f || c == 0x3000;
}
struct MemberSpan {
    size_t begin, end;
    bool xml_attribute = false;
    bool comma_separated = false;
    bool inline_suite = false;
};

bool member_insert_target(const Symbol& symbol, const std::vector<Symbol>& symbols) {
    if (symbol.kind == 7 || symbol.kind == 8) return true;
    if (symbol.kind != 13) return false;
    for (const auto& parent : symbols) {
        if (parent.kind != 5 && parent.kind != 11 && parent.kind != 19 && parent.kind != 23) continue;
        const size_t slash = symbol.name_path.rfind('/');
        if (slash != std::string::npos && symbol.name_path.substr(0, slash) == parent.name_path) return true;
    }
    return false;
}

// Mask literals and comments without moving offsets. Newlines in comments remain
// visible as statement separators; literals retain a marker and hide internal newlines.
std::wstring member_code_mask(const std::wstring& text, size_t first, size_t last,
                              const std::string& language, const Control& control,
                              std::vector<std::pair<size_t, size_t>>* comments = nullptr) {
    std::wstring mask = text;
    for (size_t i = first; i < last; ++i) {
        if ((i & 4095) == 0) control.check();
        if (text[i] == L'\r' && (i + 1 == last || text[i + 1] != L'\n')) mask[i] = L'\n';
    }
    const auto hide = [&](size_t begin, size_t end, bool keep_lines) {
        for (size_t j = begin; j < end; ++j) {
            if ((j & 4095) == 0) control.check();
            if (!keep_lines || (text[j] != L'\r' && text[j] != L'\n')) mask[j] = L' ';
        }
    };
    const auto lua_long_end = [&](size_t at) -> size_t {
        if (at >= last || text[at] != L'[') return std::wstring::npos;
        size_t p = at + 1;
        while (p < last && text[p] == L'=') ++p;
        if (p == last || text[p] != L'[') return std::wstring::npos;
        const std::wstring close = L"]" + std::wstring(p - at - 1, L'=') + L"]";
        const size_t end = text.find(close, p + 1);
        if (end == std::wstring::npos || end + close.size() > last)
            fail("cannot determine member declaration: unterminated Lua long string or comment");
        return end + close.size();
    };
    for (size_t i = first; i < last;) {
        if ((i & 4095) == 0) control.check();
        const wchar_t c = text[i];
        if (language == "lua" && c == L'-' && i + 1 < last && text[i + 1] == L'-') {
            size_t end = lua_long_end(i + 2);
            if (end == std::wstring::npos) {
                end = text.find_first_of(L"\r\n", i + 2);
                if (end == std::wstring::npos || end > last) end = last;
            }
            if (comments) comments->emplace_back(i, end);
            hide(i, end, true); i = end; continue;
        }
        if (language == "lua" && c == L'[') {
            const size_t end = lua_long_end(i);
            if (end != std::wstring::npos) { hide(i, end, false); mask[i] = wchar_t{2}; i = end; continue; }
        }
        if ((language == "python" && c == L'#') ||
            ((language == "cpp" || language == "csharp" || language == "javascript" || language == "rust" || language == "annotation") &&
             c == L'/' && i + 1 < last && text[i + 1] == L'/')) {
            size_t end = text.find_first_of(L"\r\n", i + 1);
            if (end == std::wstring::npos || end > last) end = last;
            if (comments) comments->emplace_back(i, end);
            hide(i, end, true); i = end; continue;
        }
        if ((language == "cpp" || language == "csharp" || language == "javascript" || language == "rust" || language == "annotation") &&
            c == L'/' && i + 1 < last && text[i + 1] == L'*') {
            size_t p = i + 2, depth = 1;
            while (p < last && depth) {
                if (language == "rust" && p + 1 < last && text[p] == L'/' && text[p + 1] == L'*') { ++depth; p += 2; }
                else if (p + 1 < last && text[p] == L'*' && text[p + 1] == L'/') { --depth; p += 2; }
                else ++p;
                if ((p & 4095) == 0) control.check();
            }
            if (depth) fail("cannot determine member declaration: unterminated comment");
            if (comments) comments->emplace_back(i, p);
            hide(i, p, true); i = p; continue;
        }
        if ((language == "cpp" || language == "csharp") && c == L'#') {
            const size_t newline = i ? text.find_last_of(L"\r\n", i - 1) : std::wstring::npos;
            const size_t line = newline == std::wstring::npos ? 0 : newline + 1;
            if (text.find_first_not_of(L" \t\r", line) != i)
                fail("cannot determine member declaration around a preprocessor directive");
            size_t end = i;
            do {
                end = text.find_first_of(L"\r\n", end);
                if (end == std::wstring::npos || end >= last) { end = last; break; }
                if (end == i || text[end - 1] != L'\\') break;
                if (text[end] == L'\r' && end + 1 < last && text[end + 1] == L'\n') ++end;
                ++end;
            } while (end < last);
            hide(i, end, true);
            if (end > i) mask[end - 1] = wchar_t{1};
            i = end; continue;
        }
        if (language == "javascript" && c == L'/') {
            size_t before = i;
            while (before > first && edit_space(mask[before - 1])) --before;
            bool regex = before == first ||
                std::wstring_view(L"=(:,[!{;?&|").find(mask[before - 1]) != std::wstring_view::npos ||
                (before >= first + 2 && mask[before - 1] == L'>' && mask[before - 2] == L'=');
            if (!regex && before > first) {
                size_t word = before;
                while (word > first && (std::iswalnum(mask[word - 1]) || mask[word - 1] == L'_')) --word;
                const std::wstring_view previous(mask.data() + word, before - word);
                regex = previous == L"return" || previous == L"throw" || previous == L"case" ||
                        previous == L"yield" || previous == L"await";
            }
            if (regex) {
                size_t p = i + 1;
                bool character_class = false, closed = false;
                while (p < last && text[p] != L'\r' && text[p] != L'\n') {
                    if (text[p] == L'\\' && p + 1 < last) { p += 2; continue; }
                    if (text[p] == L'[') character_class = true;
                    else if (text[p] == L']') character_class = false;
                    else if (text[p] == L'/' && !character_class) { ++p; closed = true; break; }
                    ++p;
                }
                if (!closed) fail("cannot determine member declaration around a regular expression");
                hide(i, p, false); mask[i] = wchar_t{2}; i = p; continue;
            }
            const size_t next = text.find(L'/', i + 1);
            const size_t newline = text.find_first_of(L"\r\n", i + 1);
            if (next != std::wstring::npos && next < last &&
                (newline == std::wstring::npos || next < newline)) {
                const size_t punctuation = text.find_first_of(L"{}[]();", i + 1);
                if (punctuation < next)
                    fail("cannot distinguish a regular expression from division while locating a member");
            }
        }
        if (language == "cpp" && c == L'R' && i + 1 < last && text[i + 1] == L'"') {
            const size_t open = text.find(L'(', i + 2);
            if (open == std::wstring::npos || open >= last || open - i > 18)
                fail("cannot determine member declaration: invalid raw string");
            const std::wstring close = L")" + text.substr(i + 2, open - i - 2) + L"\"";
            const size_t end = text.find(close, open + 1);
            if (end == std::wstring::npos || end + close.size() > last)
                fail("cannot determine member declaration: unterminated raw string");
            hide(i, end + close.size(), false); mask[i] = wchar_t{2}; i = end + close.size(); continue;
        }
        if (language == "rust" && c == L'r') {
            size_t p = i + 1;
            while (p < last && text[p] == L'#') ++p;
            if (p < last && text[p] == L'"') {
                const std::wstring close = L"\"" + std::wstring(p - i - 1, L'#');
                const size_t end = text.find(close, p + 1);
                if (end == std::wstring::npos || end + close.size() > last)
                    fail("cannot determine member declaration: unterminated raw string");
                hide(i, end + close.size(), false); mask[i] = wchar_t{2}; i = end + close.size(); continue;
            }
        }
        if (c != L'\'' && c != L'"' && !(language == "javascript" && c == wchar_t{96})) { ++i; continue; }
        if (language == "rust" && c == L'\'' && i + 2 < last &&
            (std::iswalnum(text[i + 1]) || text[i + 1] == L'_') && text[i + 2] != L'\'') { ++i; continue; }
        const bool csharp_interpolated = language == "csharp" && c == L'"' &&
            ((i && text[i - 1] == L'$') || (i >= 2 && text[i - 1] == L'@' && text[i - 2] == L'$'));
        const bool python_interpolated = language == "python" &&
            ((i && (text[i - 1] == L'f' || text[i - 1] == L'F')) ||
             (i >= 2 && (text[i - 2] == L'f' || text[i - 2] == L'F') &&
              (text[i - 1] == L'r' || text[i - 1] == L'R')));
        const bool verbatim = language == "csharp" &&
            ((i && text[i - 1] == L'@') || (i >= 2 && text[i - 1] == L'$' && text[i - 2] == L'@'));
        size_t quotes = 1;
        if ((language == "python" || language == "csharp") && c != wchar_t{96}) {
            while (i + quotes < last && text[i + quotes] == c) ++quotes;
            if (quotes < 3) quotes = 1;
        }
        if (csharp_interpolated && quotes >= 3)
            fail("cannot determine member declaration around an interpolated raw string");
        size_t p = i + quotes, interpolation = 0;
        bool closed = false;
        while (p < last) {
            if ((p & 4095) == 0) control.check();
            if (interpolation) {
                if (text[p] == L'\'' || text[p] == L'"' || text[p] == wchar_t{96} ||
                    (text[p] == L'/' && p + 1 < last && (text[p + 1] == L'/' || text[p + 1] == L'*')) ||
                    (language == "python" && text[p] == L'#'))
                    fail("cannot determine member declaration around a complex interpolation");
                if (text[p] == L'{') ++interpolation;
                else if (text[p] == L'}') --interpolation;
                ++p; continue;
            }
            if (c == wchar_t{96} && text[p] == L'$' && p + 1 < last && text[p + 1] == L'{') {
                interpolation = 1; p += 2; continue;
            }
            if ((csharp_interpolated || python_interpolated) && text[p] == L'{') {
                if (p + 1 < last && text[p + 1] == L'{') { p += 2; continue; }
                interpolation = 1; ++p; continue;
            }
            if ((csharp_interpolated || python_interpolated) && text[p] == L'}' &&
                p + 1 < last && text[p + 1] == L'}') { p += 2; continue; }
            if (!verbatim && quotes == 1 && text[p] == L'\\' && p + 1 < last) { p += 2; continue; }
            if (text[p] == c) {
                if (verbatim && p + 1 < last && text[p + 1] == c) { p += 2; continue; }
                size_t run = 0;
                while (p + run < last && text[p + run] == c) ++run;
                if (run >= quotes) { p += quotes; closed = true; break; }
                p += run; continue;
            }
            if (quotes == 1 && c != wchar_t{96} && !verbatim && (text[p] == L'\r' || text[p] == L'\n'))
                fail("cannot determine member declaration: unterminated string");
            ++p;
        }
        if (!closed) fail("cannot determine member declaration: unterminated string");
        hide(i, p, false); mask[i] = wchar_t{2}; i = p;
    }
    return mask;
}

MemberSpan xml_member_span(const std::wstring& text, const Symbol& symbol, const Control& control) {
    const size_t anchor = offset(text, symbol.selection.start);
    const size_t open = text.rfind(L'<', anchor);
    if (open == std::wstring::npos || open + 1 >= text.size() || text[open + 1] == L'/')
        fail("cannot determine XML member boundary");
    size_t close = open + 1;
    wchar_t quote = 0;
    for (; close < text.size(); ++close) {
        if ((close & 4095) == 0) control.check();
        const wchar_t c = text[close];
        if (quote) { if (c == quote) quote = 0; }
        else if (c == L'\'' || c == L'"') quote = c;
        else if (c == L'>') break;
    }
    if (close == text.size() || anchor > close) fail("cannot determine XML member boundary");
    size_t p = open + 1;
    while (p < close && !edit_space(text[p]) && text[p] != L'/' && text[p] != L'>') ++p;
    const size_t symbol_begin = offset(text, symbol.extent.start), symbol_end = offset(text, symbol.extent.end);
    if (symbol.has_body && symbol_begin <= open && symbol_end > close) {
        size_t before_close = close;
        while (before_close > open && edit_space(text[before_close - 1])) --before_close;
        const bool self_closing = before_close > open && text[before_close - 1] == L'/';
        size_t element_end = close + 1;
        if (self_closing && text.find_first_not_of(L" \t\r\n", element_end) < symbol_end)
            fail("cannot determine complete XML element boundary");
        if (!self_closing) {
            const std::wstring tag = text.substr(open + 1, p - open - 1);
            const std::wstring ending = L"</" + tag;
            const size_t closing = text.rfind(ending, symbol_end - 1);
            const size_t after_name = closing == std::wstring::npos ? symbol_end : closing + ending.size();
            if (closing == std::wstring::npos || closing <= close || after_name >= symbol_end ||
                (!edit_space(text[after_name]) && text[after_name] != L'>'))
                fail("cannot determine complete XML element boundary");
            const size_t closing_end = text.find(L'>', after_name);
            if (closing_end == std::wstring::npos || closing_end >= symbol_end ||
                text.find_first_not_of(L" \t\r\n", closing_end + 1) < symbol_end)
                fail("cannot determine complete XML element boundary");
            element_end = closing_end + 1;
        }
        return {open, element_end, false, false, false};
    }
    if (anchor < p) fail("cannot determine complete XML element boundary");
    while (p < close) {
        while (p < close && edit_space(text[p])) ++p;
        if (p == close || text[p] == L'/') break;
        const size_t begin = p;
        while (p < close && !edit_space(text[p]) && text[p] != L'=' && text[p] != L'/' && text[p] != L'>') ++p;
        if (p == begin) fail("cannot determine XML attribute boundary");
        const size_t name_end = p;
        while (p < close && edit_space(text[p])) ++p;
        if (p == close || text[p++] != L'=') fail("cannot determine XML attribute boundary");
        while (p < close && edit_space(text[p])) ++p;
        if (p == close || (text[p] != L'\'' && text[p] != L'"')) fail("cannot determine XML attribute boundary");
        const wchar_t delimiter = text[p++];
        while (p < close && text[p] != delimiter) {
            if ((p & 4095) == 0) control.check();
            ++p;
        }
        if (p == close) fail("cannot determine XML attribute boundary");
        ++p;
        if (anchor >= begin && anchor < p) {
            const std::wstring label = wide(symbol.name);
            const std::wstring attribute = text.substr(begin, name_end - begin);
            if (label != attribute &&
                !(label.starts_with(attribute) && label.size() > attribute.size() &&
                  (label[attribute.size()] == L'=' || label[attribute.size()] == L':' ||
                   edit_space(label[attribute.size()]))))
                fail("cannot identify the selected XML attribute");
            return {begin, p, true, false, false};
        }
    }
    fail("cannot determine XML member boundary");
}

// Keep adjacent, whole-line comments attached to their declaration during insertion.
size_t leading_comment_start(const std::wstring& text, size_t begin,
                             const std::string& language, const Control& control) {
    if (language != "cpp" && language != "csharp" && language != "javascript" &&
        language != "rust" && language != "python" && language != "lua") return begin;
    if (!begin) return begin;
    std::vector<std::pair<size_t, size_t>> comments;
    (void)member_code_mask(text, 0, begin, language, control, &comments);
    size_t point = begin;
    for (auto it = comments.rbegin(); it != comments.rend(); ++it) {
        control.check();
        const auto [first, last] = *it;
        if (last > point) continue;
        size_t breaks = 0;
        bool adjacent = true;
        for (size_t at = last; at < point; ++at) {
            if ((at & 4095) == 0) control.check();
            if (!edit_space(text[at])) { adjacent = false; break; }
            if (text[at] == L'\n' || (text[at] == L'\r' &&
                (at + 1 == point || text[at + 1] != L'\n'))) ++breaks;
        }
        if (!adjacent || breaks > 1) break; // A blank line separates documentation from code.
        const size_t newline = first ? text.find_last_of(L"\r\n", first - 1) : std::wstring::npos;
        const size_t line = newline == std::wstring::npos ? 0 : newline + 1;
        if (text.find_first_not_of(L" \t", line) != first) break; // Leave a previous member's trailing comment.
        point = first;
    }
    return point;
}

size_t decorated_declaration_start(const std::wstring& text, size_t begin,
                                   const std::string& language, const Control& control) {
    if (language == "xml" || language == "lua" || language == "ruby") return begin;
    const auto marker = [&](size_t at) {
        if (at >= text.size()) return false;
        if (text[at] == L'@') return true;
        if ((language == "csharp" || language == "powershell") && text[at] == L'[') return true;
        if (language == "cpp" && text.compare(at, 2, L"[[") == 0) return true;
        return text.compare(at, 2, L"#[") == 0;
    };
    const size_t newline = begin ? text.find_last_of(L"\r\n", begin - 1) : std::wstring::npos;
    size_t line = newline == std::wstring::npos ? 0 : newline + 1;
    const size_t first = text.find_first_not_of(L" \t", line);
    if (first == std::wstring::npos || first > begin) return begin;
    const std::wstring indent = text.substr(line, first - line);
    size_t floor = first < begin && marker(first) ? first : begin;
    while (line) {
        control.check();
        size_t end = line - 1;
        if (end && text[end - 1] == L'\r') --end;
        const size_t previous = end ? text.find_last_of(L"\r\n", end - 1) : std::wstring::npos;
        const size_t start = previous == std::wstring::npos ? 0 : previous + 1;
        const size_t at = text.find_first_not_of(L" \t", start);
        if (at < end && text.substr(start, at - start) == indent) {
            if (marker(at)) floor = at;
            else if (text[at] != L')' && text[at] != L']') break;
        } else if (at < end && at - start < indent.size()) break;
        line = start;
    }
    if (floor == begin) return begin;
    const std::string lexical_language =
        language == "python" || language == "cpp" || language == "csharp" ||
        language == "javascript" || language == "rust" ? language : "annotation";
    const std::wstring mask = member_code_mask(text, floor, begin, lexical_language, control);
    size_t at = floor;
    const auto whitespace = [&] { while (at < begin && edit_space(mask[at])) ++at; };
    const auto group = [&] {
        std::vector<wchar_t> closing;
        do {
            if ((at & 4095) == 0) control.check();
            const wchar_t c = mask[at++];
            if (c == L'(') closing.push_back(L')');
            else if (c == L'[') closing.push_back(L']');
            else if (c == L'{') closing.push_back(L'}');
            else if (c == L')' || c == L']' || c == L'}') {
                if (closing.empty() || closing.back() != c) return false;
                closing.pop_back();
            }
        } while (at < begin && !closing.empty());
        return closing.empty();
    };
    const auto identifier = [](wchar_t c) {
        return c >= 128 || std::iswalnum(c) || c == L'_' || c == L'$';
    };
    while (at < begin) {
        control.check();
        whitespace();
        if (at == begin) break;
        if (!marker(at)) fail("cannot separate decorators from the preceding declaration; nothing written");
        if (mask[at] == L'#') ++at;
        if (mask[at] == L'[') {
            if (!group()) fail("unbalanced attribute or decorator prefix; nothing written");
        } else {
            ++at; // @annotation or @decorator
            const size_t expression = at;
            while (at < begin && (identifier(mask[at]) || mask[at] == L'.' || mask[at] == L':')) ++at;
            if (at == expression && (at == begin || mask[at] != L'(')) fail("cannot identify the decorator expression; nothing written");
            for (;;) {
                whitespace();
                if (at == begin || (mask[at] != L'(' && mask[at] != L'[')) break;
                if (!group()) fail("unbalanced attribute or decorator prefix; nothing written");
            }
        }
        whitespace();
    }
    return floor;
}

// The first character after the attributes, decorators and comments that lead a declaration starting at begin;
// never past limit (the selected name). Strings inside attribute arguments are skipped whole.
size_t undecorated_declaration_start(const std::wstring& text, size_t begin, size_t limit, const std::string& language) {
    const auto balanced = [&](size_t at, wchar_t open, wchar_t close) -> size_t {
        size_t depth = 0;
        for (; at < limit; ++at) {
            const wchar_t c = text[at];
            if (c == L'"' || c == L'\'') {
                for (++at; at < limit && text[at] != c; ++at) if (text[at] == L'\\') ++at;
                continue;
            }
            if (c == open) ++depth;
            else if (c == close && depth && --depth == 0) return at + 1;
        }
        return std::wstring::npos;
    };
    size_t at = begin;
    for (;;) {
        size_t p = at;
        while (p < limit && std::iswspace(text[p])) ++p;
        if (p >= limit) return at;
        if (text.compare(p, 2, L"//") == 0 || (language == "python" && text[p] == L'#' && text.compare(p, 2, L"#[") != 0)) {
            const size_t end = text.find(L'\n', p);
            if (end == std::wstring::npos || end >= limit) return p;
            at = end + 1;
        } else if (text.compare(p, 2, L"/*") == 0) {
            const size_t end = text.find(L"*/", p + 2);
            if (end == std::wstring::npos || end + 2 > limit) return p;
            at = end + 2;
        } else if (text[p] == L'[' || text.compare(p, 2, L"#[") == 0) {
            const size_t end = balanced(text[p] == L'#' ? p + 1 : p, L'[', L']');
            if (end == std::wstring::npos) return p;
            at = end;
        } else if (text[p] == L'@') {
            size_t end = p + 1;
            while (end < limit && (std::iswalnum(text[end]) || text[end] == L'_' || text[end] == L'.')) ++end;
            if (end < limit && text[end] == L'(') {
                end = balanced(end, L'(', L')');
                if (end == std::wstring::npos) return p;
            }
            at = end;
        } else {
            return p;
        }
    }
}

MemberSpan member_declaration_span(const std::wstring& text, const Symbol& symbol,
                                   const std::vector<Symbol>& symbols, const std::string& language,
                                   const Control& control) {
    if (language == "xml") return xml_member_span(text, symbol, control);
    if (language != "cpp" && language != "csharp" && language != "javascript" &&
        language != "rust" && language != "python" && language != "lua")
        fail("cannot determine member boundary for this language");
    const size_t anchor = offset(text, symbol.selection.start);
    const size_t selection_end = offset(text, symbol.selection.end);
    if (anchor >= text.size() || selection_end < anchor) fail("invalid member selection range");

    size_t scope_begin = 0, scope_end = text.size();
    const size_t slash = symbol.name_path.rfind('/');
    if (slash != std::string::npos) {
        const std::string parent_path = symbol.name_path.substr(0, slash);
        for (const auto& parent : symbols) {
            if (!parent.has_body || parent.name_path != parent_path) continue;
            const size_t begin = offset(text, parent.extent.start), end = offset(text, parent.extent.end);
            if (end >= begin && begin <= anchor && selection_end <= end && end - begin < scope_end - scope_begin) {
                scope_begin = begin; scope_end = end;
            }
        }
    }
    const auto with_decorators = [&](size_t begin) {
        return decorated_declaration_start(text, begin, language, control);
    };
    if ((language == "python" || language == "lua") && symbol.kind == 7 && symbol.has_body) {
        const size_t begin = offset(text, symbol.extent.start), end = offset(text, symbol.extent.end);
        if (begin < anchor && end > selection_end && begin >= scope_begin && end <= scope_end &&
            symbol.extent.end.line > symbol.extent.start.line)
            return {with_decorators(begin), end, false, false, false};
    }

    const std::wstring mask = member_code_mask(text, scope_begin, scope_end, language, control);
    if (mask[anchor] != text[anchor]) fail("member selection is inside a comment or literal");
    const auto jsx_start = [&](size_t at) {
        if (language != "javascript" || mask[at] != L'<' || at + 1 >= scope_end ||
            !(std::iswalpha(mask[at + 1]) || mask[at + 1] == L'>' || mask[at + 1] == L'/')) return false;
        size_t previous = at;
        while (previous > scope_begin && edit_space(mask[previous - 1])) --previous;
        if (previous == scope_begin || std::wstring_view(L"=(:,[>{;").find(mask[previous - 1]) != std::wstring_view::npos)
            return true;
        size_t word = previous;
        while (word > scope_begin && (std::iswalnum(mask[word - 1]) || mask[word - 1] == L'_')) --word;
        const std::wstring_view token(mask.data() + word, previous - word);
        return token == L"return" || token == L"yield";
    };
    int brace = 0, paren = 0, bracket = 0, angle = 0;
    size_t begin = scope_begin;
    bool inline_suite = false;
    for (size_t i = scope_begin; i < anchor; ++i) {
        if ((i & 4095) == 0) control.check();
        const wchar_t c = mask[i];
        if (jsx_start(i)) fail("cannot determine a member boundary around JSX");
        if (c == wchar_t{1}) { begin = i + 1; angle = 0; inline_suite = false; continue; }
        if (c == L'(') ++paren;
        else if (c == L')') { if (--paren < 0) fail("cannot determine member declaration boundary"); }
        else if (c == L'[') ++bracket;
        else if (c == L']') { if (--bracket < 0) fail("cannot determine member declaration boundary"); }
        if (paren || bracket) continue;
        if (c == L'{') { ++brace; begin = i + 1; angle = 0; }
        else if (c == L'}') { if (--brace < 0) fail("cannot determine member declaration boundary"); begin = i + 1; angle = 0; }
        else if (language == "rust" && c == L'<') ++angle;
        else if (language == "rust" && c == L'>' && angle && (!i || mask[i - 1] != L'-')) --angle;
        else if (c == L';' || ((language == "rust" || language == "lua") && brace && !angle && c == L',')) {
            begin = i + 1; angle = 0;
        } else if (c == L'\n' && (language == "python" || language == "lua" || language == "javascript") &&
                   (language != "python" || !brace)) {
            size_t previous = i;
            while (previous > begin && edit_space(mask[previous - 1])) --previous;
            bool continued = previous > begin &&
                std::wstring_view(L"=,:.+-*/\\").find(mask[previous - 1]) != std::wstring_view::npos;
            if (!continued && language == "javascript" && previous > begin) {
                size_t word = previous;
                while (word > begin && (std::iswalnum(mask[word - 1]) || mask[word - 1] == L'_')) --word;
                const std::wstring_view modifier(mask.data() + word, previous - word);
                continued = modifier == L"public" || modifier == L"private" || modifier == L"protected" ||
                            modifier == L"static" || modifier == L"readonly" || modifier == L"declare" ||
                            modifier == L"abstract" || modifier == L"override";
            }
            if (!continued) { begin = i + 1; angle = 0; inline_suite = false; }
        } else if (language == "cpp" && c == L':' && brace) {
            size_t word = i;
            while (word > scope_begin && std::iswalpha(mask[word - 1])) --word;
            const std::wstring_view access(mask.data() + word, i - word);
            if (access == L"public" || access == L"private" || access == L"protected") begin = i + 1;
        } else if (language == "python" && c == L':' && !brace) {
            const size_t line = text.find_last_of(L"\r\n", i);
            const size_t line_begin = line == std::wstring::npos ? 0 : line + 1;
            const size_t word = text.find_first_not_of(L" \t", line_begin);
            if (word != std::wstring::npos && word < i &&
                (text.compare(word, 6, L"class ") == 0 || text.compare(word, 4, L"def ") == 0 ||
                 text.compare(word, 10, L"async def ") == 0)) {
                begin = i + 1; inline_suite = true;
            }
        }
    }
    if (paren || bracket) fail("cannot determine member declaration boundary");
    if (language == "lua") {
        const size_t newline = anchor ? mask.find_last_of(L"\r\n", anchor - 1) : std::wstring::npos;
        const size_t line_begin = newline == std::wstring::npos ? 0 : newline + 1;
        const size_t function = mask.find(L"function", line_begin);
        if (function < anchor) fail("cannot determine a member boundary inside an inline Lua function");
    }
    const size_t boundary = begin;
    while (begin < anchor && edit_space(text[begin])) ++begin;
    if (boundary > scope_begin && (mask[boundary - 1] == L';' || mask[boundary - 1] == L',' ||
                                    mask[boundary - 1] == L'}')) {
        size_t comment = boundary;
        while (comment < anchor && (text[comment] == L' ' || text[comment] == L'\t')) ++comment;
        if (comment + 1 < anchor && ((text[comment] == L'/' && text[comment + 1] == L'/') ||
                                     (text[comment] == L'-' && text[comment + 1] == L'-'))) {
            if (language == "lua" && comment + 2 < anchor && text[comment + 2] == L'[')
                fail("cannot insert beside a multiline Lua comment");
            const size_t newline = text.find_first_of(L"\r\n", comment);
            if (newline < anchor) {
                begin = newline + 1;
                while (begin < anchor && edit_space(text[begin])) ++begin;
            }
        } else if (comment + 1 < anchor && text[comment] == L'/' && text[comment + 1] == L'*') {
            fail("cannot determine whether an inline comment belongs to the preceding member");
        }
    }
    begin = with_decorators(begin);
    if (language == "python") {
        const size_t previous = begin ? text.find_last_of(L"\r\n", begin - 1) : std::wstring::npos;
        const size_t line_begin = previous == std::wstring::npos ? 0 : previous + 1;
        if (text.find_first_not_of(L" \t", line_begin) < begin) inline_suite = true;
    }
    if (begin > anchor) fail("cannot determine member declaration boundary");
    if (inline_suite && language == "python" && text.find(L"def ", begin) < anchor)
        fail("cannot insert beside a compound definition in an inline Python suite");

    const int base_brace = brace;
    bool property_body = false, method_body = false, assigned = false, type_annotation = false, method_like = false;
    angle = 0;
    for (size_t i = anchor; i < scope_end; ++i) {
        if ((i & 4095) == 0) control.check();
        const wchar_t c = mask[i];
        if (c == wchar_t{1}) fail("cannot determine a member boundary across a preprocessor directive");
        if (jsx_start(i) || (language == "javascript" && assigned && c == L'<' && i + 1 < scope_end &&
            (std::iswalpha(mask[i + 1]) || mask[i + 1] == L'>' || mask[i + 1] == L'/')))
            fail("cannot determine a member boundary around JSX or a generic expression");
        if (language == "javascript" && c == L'(' && brace == base_brace &&
            !paren && !bracket && !assigned && !type_annotation) method_like = true;
        if (c == L'(') ++paren;
        else if (c == L')') { if (--paren < 0) fail("cannot determine member declaration boundary"); }
        else if (c == L'[') ++bracket;
        else if (c == L']') { if (--bracket < 0) fail("cannot determine member declaration boundary"); }
        if (paren || bracket) continue;
        if (language == "lua" && brace == base_brace &&
            (i == scope_begin || (!std::iswalnum(mask[i - 1]) && mask[i - 1] != L'_'))) {
            if (mask.compare(i, 8, L"function") == 0 &&
                (i + 8 >= scope_end || (!std::iswalnum(mask[i + 8]) && mask[i + 8] != L'_')))
                fail("cannot determine a member boundary around an inline Lua function");
            if (mask.compare(i, 3, L"end") == 0 &&
                (i + 3 >= scope_end || (!std::iswalnum(mask[i + 3]) && mask[i + 3] != L'_')))
                fail("cannot determine a member boundary beside a Lua end");
        }
        if (language == "rust" && c == L'<') { ++angle; continue; }
        if (language == "rust" && c == L'>' && angle && (!i || mask[i - 1] != L'-')) { --angle; continue; }
        if (language == "javascript" && brace == base_brace && c == L':' && !method_like && !assigned)
            type_annotation = true;
        if (brace == base_brace && !angle && c == L'=') assigned = true;
        if (c == L'{') {
            if (language == "csharp" && brace == base_brace && !assigned &&
                (symbol.kind == 6 || symbol.kind == 9 || symbol.kind == 12))
                method_body = true;
            if (brace == base_brace && (symbol.kind == 7 || symbol.kind == 8) && !assigned &&
                (language == "csharp" || (language == "javascript" && (!type_annotation || method_like))))
                property_body = true;
            ++brace;
        } else if (c == L'}') {
            if (brace == base_brace) {
                if (language == "rust" || (language == "lua" && base_brace > 0))
                    return {begin, i, false, true, inline_suite};
                if (language == "javascript") return {begin, i, false, false, inline_suite};
                fail("cannot determine complete member declaration");
            }
            --brace;
            if (method_body && brace == base_brace)
                return {begin, i + 1, false, false, inline_suite};
            if (property_body && brace == base_brace) {
                size_t next = i + 1;
                while (next < scope_end && edit_space(mask[next])) ++next;
                if (next < scope_end && mask[next] == L'=') { property_body = false; assigned = true; continue; }
                if (next < scope_end && mask[next] == L';') return {begin, next + 1, false, false, inline_suite};
                return {begin, i + 1, false, false, inline_suite};
            }
        } else if (brace == base_brace && !angle && c == L';') {
            return {begin, i + 1, false, false, inline_suite || language == "python"};
        } else if (brace == base_brace && !angle && c == L',' &&
                   (language == "rust" || (language == "lua" && base_brace > 0))) {
            return {begin, i + 1, false, true, inline_suite};
        } else if (brace == base_brace && !angle && c == L'\n' &&
                   (language == "python" || language == "javascript" || (language == "lua" && !base_brace))) {
            size_t previous = i;
            while (previous > anchor && edit_space(mask[previous - 1])) --previous;
            if (previous > anchor && std::wstring_view(L"=,:.+-*/\\").find(mask[previous - 1]) != std::wstring_view::npos)
                continue;
            const size_t line_end = text[i] == L'\n' && i > anchor && text[i - 1] == L'\r' ? i - 1 : i;
            return {begin, line_end, false, false, inline_suite};
        }
    }
    if ((language == "python" || language == "lua" || language == "javascript") && !paren && !bracket && brace == base_brace)
        return {begin, scope_end, false, false, inline_suite};
    fail("cannot determine complete member declaration");
}

std::string inserted_member_text(const SourceText& source, const Symbol& symbol,
                                 const std::vector<Symbol>& symbols, const std::string& language,
                                 const std::string& operation, const Json& arguments, const Control& control) {
    if (!arguments.get("new_text")) fail("this symbol edit requires new_text");
    std::wstring text = wide(source.text);
    const MemberSpan span = member_declaration_span(text, symbol, symbols, language, control);
    const size_t selection_begin = offset(text, symbol.selection.start);
    const size_t selection_end = offset(text, symbol.selection.end);
    if (span.begin >= span.end || span.end > text.size() || span.begin > selection_begin || span.end < selection_end)
        fail("invalid member declaration boundary");
    std::wstring replacement = wide(newlines(str(arguments, "new_text"), source.text));
    if (replacement.empty()) return source.text;
    const std::wstring eol = source.text.find("\r\n") != std::string::npos ? L"\r\n" :
        (source.text.find('\n') == std::string::npos && source.text.find('\r') != std::string::npos ? L"\r" : L"\n");
    size_t point = operation == "insert_before" ? span.begin : span.end;
    if (span.xml_attribute) {
        replacement = operation == "insert_before" ? replacement + L" " : L" " + replacement;
    } else if (language == "xml") {
        // XML mixed content must not acquire implicit whitespace.
    } else if (span.inline_suite && language == "python") {
        if (replacement.find_first_of(L"\r\n") != std::wstring::npos)
            fail("multiline insertion into an inline Python suite requires a multiline suite");
        if (replacement.find(L'#') != std::wstring::npos)
            fail("cannot insert an inline Python member containing a comment marker");
        if (operation == "insert_after") {
            const size_t newline = text.find_first_of(L"\r\n", span.end);
            const size_t line_end = newline == std::wstring::npos ? text.size() : newline;
            const size_t tail = text.find_first_not_of(L" \t\r", span.end);
            if (tail < line_end && text[tail] == L'#')
                fail("cannot insert after an inline Python member with a trailing comment");
        }
        while (!replacement.empty() && replacement.back() == L';') replacement.pop_back();
        if (operation == "insert_before") replacement += L"; ";
        else replacement = (text[span.end - 1] == L';' ? L" " : L"; ") + replacement +
                           (text[span.end - 1] == L';' ? L";" : L"");
    } else {
        const auto starts_newline = [&] { return !replacement.empty() && (replacement.front() == L'\r' || replacement.front() == L'\n'); };
        const auto ends_newline = [&] { return !replacement.empty() && (replacement.back() == L'\r' || replacement.back() == L'\n'); };
        const bool comma = span.comma_separated;
        const bool target_comma = comma && text[span.end - 1] == L',';
        if (comma) {
            const size_t last = replacement.find_last_not_of(L" \t\r\n");
            if (last == std::wstring::npos) fail("comma-separated insertion requires a member declaration");
            if (replacement[last] != L',') {
                const size_t line = replacement.find_last_of(L"\r\n", last);
                const size_t start = line == std::wstring::npos ? 0 : line + 1;
                if ((language == "rust" && replacement.find(L"//", start) <= last) ||
                    (language == "lua" && replacement.find(L"--", start) <= last))
                    fail("cannot add a member separator after a trailing line comment");
                replacement.insert(last + 1, 1, L',');
            }
        }
        if (operation == "insert_before") {
            point = leading_comment_start(text, span.begin, language, control);
            const size_t previous = point ? text.find_last_of(L"\r\n", point - 1) : std::wstring::npos;
            const size_t line_begin = previous == std::wstring::npos ? 0 : previous + 1;
            if (text.find_first_not_of(L" \t", line_begin) >= point) point = line_begin;
            if (point != line_begin && !starts_newline()) replacement = eol + replacement;
            if (!ends_newline()) replacement += eol;
        } else if (comma && !target_comma) {
            point = span.end;
            const bool leading = starts_newline(), trailing = ends_newline();
            replacement = L"," + (leading ? L"" : eol) + replacement + (trailing ? L"" : eol);
        } else if (span.end && (text[span.end - 1] == L'\n' ||
                   (text[span.end - 1] == L'\r' && (span.end == text.size() || text[span.end] != L'\n')))) {
            point = span.end;
            if (!ends_newline()) replacement += eol;
        } else {
            const size_t newline = text.find_first_of(L"\r\n", span.end);
            const size_t line_end = newline == std::wstring::npos ? text.size() : newline;
            size_t tail = span.end;
            while (tail < line_end && (text[tail] == L' ' || text[tail] == L'\t' || text[tail] == L'\r')) ++tail;
            bool comment = tail < line_end &&
                ((tail + 1 < line_end && text[tail] == L'/' && text[tail + 1] == L'/') ||
                 (tail + 1 < line_end && text[tail] == L'-' && text[tail + 1] == L'-') ||
                 (language == "python" && text[tail] == L'#'));
            if (language == "lua" && comment && tail + 2 < line_end && text[tail + 2] == L'[')
                fail("cannot insert beside a multiline Lua comment");
            if (tail + 1 < line_end && text[tail] == L'/' && text[tail + 1] == L'*') {
                const size_t close = text.find(L"*/", tail + 2);
                if (close == std::wstring::npos || close + 2 > line_end ||
                    text.find_first_not_of(L" \t\r", close + 2) < line_end)
                    fail("cannot determine placement beside a block comment");
                comment = true;
            }
            if (tail == line_end || comment) {
                point = newline == std::wstring::npos ? text.size() : newline + 1;
                if (newline != std::wstring::npos && text[newline] == L'\r' &&
                    point < text.size() && text[point] == L'\n') ++point;
                const bool leading = starts_newline(), trailing = ends_newline();
                replacement = (newline == std::wstring::npos && !leading ? eol : L"") +
                              replacement + (trailing ? L"" : eol);
            } else {
                const bool leading = starts_newline(), trailing = ends_newline();
                replacement = (leading ? L"" : eol) + replacement + (trailing ? L"" : eol);
            }
        }
    }
    const size_t byte_point = utf8(text.substr(0, point)).size();
    replacement = wide(preserve_line_endings({}, utf8(replacement),
        nearby_line_ending(source.text, byte_point, "\n"), control.cancelled));
    text.insert(point, replacement);
    return utf8(text);
}

std::string edited_symbol_text(const SourceText& source, const Symbol& symbol,
                               const std::string& operation, const Json& arguments, const Control& control) {
    std::wstring text = wide(source.text);
    size_t begin = offset(text, symbol.extent.start), end = offset(text, symbol.extent.end);
    const auto only_indent = [&](size_t from, size_t to) {
        return text.find_first_not_of(L" \t", from) >= to;
    };
    const size_t line_start = offset(text, Position{symbol.extent.start.line, 0});
    if (operation == "safe_delete") {
        text.erase(begin, end - begin);
        // Delete blank lines starting where the removed definition began; the preceding separator survives.
        size_t blank_end = line_start;
        while (blank_end < text.size()) {
            size_t next = text.find(L'\n', blank_end);
            const size_t stop = next == std::wstring::npos ? text.size() : next + 1;
            if (!std::all_of(text.begin() + blank_end, text.begin() + stop, edit_space)) break;
            blank_end = stop;
        }
        text.erase(line_start, blank_end - line_start);
        return utf8(text);
    }
    if (!arguments.get("new_text")) fail("this symbol edit requires new_text");
    std::wstring replacement = wide(newlines(str(arguments, "new_text"), source.text));
    const std::wstring eol = source.text.find("\r\n") != std::string::npos ? L"\r\n" :
        (source.text.find('\n') == std::string::npos && source.text.find('\r') != std::string::npos ? L"\r" : L"\n");
    auto trim_end = [&] { while (!replacement.empty() && edit_space(replacement.back())) replacement.pop_back(); };
    if ((operation == "insert_before" || operation == "insert_after") && replacement.empty()) return source.text;
    const auto starts_newline = [&] { return !replacement.empty() && (replacement.front() == L'\r' || replacement.front() == L'\n'); };
    const auto ends_newline = [&] { return !replacement.empty() && (replacement.back() == L'\r' || replacement.back() == L'\n'); };
    if (operation == "symbol") {
        // Some servers include a final line break in the range; retain separators and indentation outside the definition.
        while (begin < end && edit_space(text[begin])) ++begin;
        while (end > begin && edit_space(text[end - 1])) --end;
        trim_end();
        const auto first = std::find_if_not(replacement.begin(), replacement.end(), edit_space);
        replacement.erase(replacement.begin(), first);
        // COMPAT: clangd ranges for declarations (prototypes, fields, `struct X {...};`) stop before the ';'. A body
        //   that brings its own ';' replaces the old one too, instead of leaving "...;;".
        if (!replacement.empty() && replacement.back() == L';') {
            const size_t after = text.find_first_not_of(L" \t", end);
            if (after < text.size() && text[after] == L';') end = after + 1;
        }
    } else if (operation == "insert_before") {
        if (!only_indent(line_start, begin))
            fail("insert_before cannot split an inline definition; replace the containing symbol instead");
        if (!ends_newline()) replacement += eol;
        begin = end = line_start;
    } else if (operation == "insert_after") {
        if (text.substr(begin, end - begin) == wide(symbol.name))
            fail("cannot insert_after an identifier-only symbol; use insert_before or replace its containing symbol");
        if (!ends_newline()) replacement += eol;
        // An exclusive end at column zero already points at the insertion line.
        if (symbol.extent.end.column == 0) begin = end;
        else {
            const size_t next = text.find_first_of(L"\r\n", end);
            const size_t stop = next == std::wstring::npos ? text.size() : next;
            // COMPAT: clangd ranges for declarations (prototypes, fields, `struct X {...};`) stop before the ';'.
            const size_t after = text.find_first_not_of(L" \t", end);
            const size_t tail = after < stop && text[after] == L';' ? after + 1 : end;
            if (!only_indent(tail, stop))
                fail("insert_after requires the definition to end on its own line");
            if (next == std::wstring::npos) {
                begin = text.size();
                if (!starts_newline()) replacement = eol + replacement;
            }
            else {
                begin = next + 1;
                if (text[next] == L'\r' && begin < text.size() && text[begin] == L'\n') ++begin;
            }
        }
        end = begin;
    } else fail("unknown symbol edit operation");
    const size_t byte_begin = utf8(text.substr(0, begin)).size();
    replacement = wide(preserve_line_endings(utf8(text.substr(begin, end - begin)), utf8(replacement),
        nearby_line_ending(source.text, byte_begin, "\n"), control.cancelled));
    text.replace(begin, end - begin, replacement);
    return utf8(text);
}
} // namespace

std::vector<std::pair<size_t, size_t>> outside_symbol_ranges(
    const SourceText& source, const std::vector<Symbol>& found,
    std::string language, const Control& control) {
    if (language == "typescript" || language == "typescriptreact" || language == "javascriptreact") language = "javascript";
    if (language == "c" || language == "c++") language = "cpp";
    if (language == "cs") language = "csharp";
    const std::wstring text = wide(source.text);
    std::vector<std::pair<size_t, size_t>> ranges;
    const auto byte = [&](size_t position) { return utf8(text.substr(0, position)).size(); };
    // Servers differ on whether a range takes the line break after the symbol (Python and Lua ranges often end at the
    // next line's column 0) or blank lines before it. Those bytes are not code: whole whitespace-only lines at the start
    // and trailing spaces/line breaks at the end stay outside the protected range, so a blank line next to a symbol can
    // be edited without the match "crossing" the symbol. Indentation before the first code byte stays protected.
    const std::string& bytes = source.text;
    const auto protect = [&](size_t begin, size_t end) {
        while (begin < end) {
            size_t at = begin;
            while (at < end && (bytes[at] == ' ' || bytes[at] == '\t')) ++at;
            if (at == end || (bytes[at] != '\n' && bytes[at] != '\r')) break;
            begin = at + (bytes[at] == '\r' && at + 1 < end && bytes[at + 1] == '\n' ? 2 : 1);
        }
        while (end > begin && (bytes[end - 1] == ' ' || bytes[end - 1] == '\t' || bytes[end - 1] == '\r' ||
                               bytes[end - 1] == '\n')) --end;
        ranges.emplace_back(begin, end);
    };
    for (const auto& symbol : found) {
        control.check();
        if (!symbol.has_body) fail("language server did not provide complete document symbol ranges; nothing written");
        const size_t first = offset(text, symbol.extent.start);
        const size_t last = offset(text, symbol.extent.end);
        if (first > last) fail("language server returned a reversed symbol range");
        const bool container = (symbol.kind == 2 || symbol.kind == 3 || symbol.kind == 4) &&
            (language == "cpp" || language == "csharp" || language == "javascript" || language == "rust");
        if (!container) {
            protect(byte(first), byte(last));
            continue;
        }
        const size_t selection_end = offset(text, symbol.selection.end);
        const std::wstring mask = member_code_mask(text, first, last, language, control);
        size_t open = selection_end;
        while (open < last && mask[open] != L'{' && mask[open] != L';') {
            if ((open & 4095) == 0) control.check();
            ++open;
        }
        // A C# file-scoped namespace (`namespace X;`) guards only its header; its members follow to the end of file.
        if (open < last && mask[open] == L';' && language == "csharp") {
            protect(byte(first), byte(open + 1));
            continue;
        }
        // COMPAT: clangd gives using-declarations (`using std::x;`) and namespace aliases the namespace kind, with a
        //   range that stops before the ';'. They have no body, so, like a Rust `mod x;`, the whole range is guarded.
        if (open == last || mask[open] == L';') {
            protect(byte(first), byte(last));
            continue;
        }
        size_t depth = 1, close = open + 1;
        for (; close < last && depth; ++close) {
            if ((close & 4095) == 0) control.check();
            if (mask[close] == L'{') ++depth;
            else if (mask[close] == L'}') --depth;
        }
        if (depth) fail("cannot determine namespace or module body; nothing written");
        protect(byte(first), byte(open + 1));
        protect(byte(close - 1), byte(last));
    }
    return ranges;
}

// Collect conservative evidence before safe-deleting a method/property. Same-name
// ancestor members are potential contracts even when a server cannot prove the override.
void safe_delete_contracts(Session& session, const SourceText& source, const Symbol& selected,
                                  const std::vector<Symbol>& document_symbols, const Config& config,
                                  const SearchContext& context, const Control& control,
                                  std::map<std::wstring, std::string, PathLess>& checked, std::string& evidence) {
    if (selected.kind != 6 && selected.kind != 7) return;
    const auto slash = selected.name_path.rfind('/');
    if (slash == std::string::npos) fail("cannot identify the enclosing type for contract checks");
    const std::string owner_path = selected.name_path.substr(0, slash);
    const Symbol* owner = nullptr;
    for (const auto& symbol : document_symbols)
        if (symbol.name_path == owner_path && (symbol.kind == 5 || symbol.kind == 11 || symbol.kind == 23)) {
            owner = &symbol;
            break;
        }
    if (!owner) fail("cannot identify the enclosing type for contract checks");
    // COMPAT: Roslyn offers definition but not declaration; for C# members they name the same place.
    const char* declaration_method = session.supports("declarationProvider") ? "textDocument/declaration"
        : session.supports("definitionProvider") ? "textDocument/definition" : nullptr;
    if (!declaration_method) session.require("declarationProvider");
    session.require("implementationProvider");
    session.require("typeHierarchyProvider");
    session.require("documentSymbolProvider");
    const auto same_path = [](const fs::path& a, const fs::path& b) {
        return !PathLess{}(a.wstring(), b.wstring()) && !PathLess{}(b.wstring(), a.wstring());
    };
    const auto load = [&](const std::string& id) -> SourceText {
        const fs::path path = from_uri(id);
        if (path_excluded(config, path)) fail("contract location is in ignored_paths");
        SourceText target = read_source_text(context, utf8(path.wstring()));
        const auto target_config = configuration(target, context, control.cancelled);
        if (!target_config || target_config->key != config.key)
            fail("contract location is outside the active language server");
        session.use(target, control);
        session.assert_current(target);
        if (const auto it = checked.find(target.path.wstring()); it != checked.end() && it->second != target.sha256)
            fail("contract file changed during safe_delete");
        checked[target.path.wstring()] = target.sha256;
        return target;
    };
    const auto locations = [&](const J& raw, const char* kind) {
        J::Array entries;
        if (std::holds_alternative<J::Array>(raw.value)) entries = raw.array();
        else if (!std::holds_alternative<std::nullptr_t>(raw.value)) entries.push_back(raw);
        for (const auto& location : entries) {
            control.check();
            const bool link = location.get("targetUri") != nullptr;
            const std::string id = str(location, link ? "targetUri" : "uri");
            const J* item_range = location.get(link ? "targetSelectionRange" : "range");
            if (id.empty() || !item_range) fail("language server returned an invalid contract location");
            const Range where = range(*item_range);
            const SourceText target = load(id);
            const std::wstring content = wide(target.text);
            offset(content, where.start);
            offset(content, where.end);
            const bool self = same_path(target.path, source.path) &&
                !(where.end < selected.selection.start || selected.selection.end < where.start);
            if (!self)
                evidence += std::string(kind) + ": " + shown_path(target) + ":" +
                    std::to_string(where.start.line + 1) + ":" + std::to_string(where.start.column + 1) + "\n";
        }
    };
    const auto query = [&](const char* method, const SourceText& document, const Position& pos) {
        session.assert_current(document);
        return session.request(method, J::Object{
            {"textDocument", J::Object{{"uri", session.document_uri(document)}}}, {"position", pos.json()}}, control);
    };
    locations(query(declaration_method, source, selected.selection.start), "declaration");
    locations(query("textDocument/implementation", source, selected.selection.start), "implementation");
    const auto simple_name = [](const std::string& name) {
        const size_t dot = name.rfind('.');
        return dot == std::string::npos ? name : name.substr(dot + 1);
    };
    const std::string member_name = simple_name(selected.name);
    const std::string owner_prefix = owner_path + "/";
    const bool csharp = config.language == "csharp";
    // C#: an inherited class member can only be replaced through an explicit override modifier.
    const bool selected_overrides = [&] {
        const std::wstring text = wide(source.text);
        const size_t from = offset(text, selected.extent.start), to = offset(text, selected.selection.start);
        for (size_t at = text.find(L"override", from); at != std::wstring::npos && at + 8 <= to; at = text.find(L"override", at + 8)) {
            const bool left = at == 0 || !(std::iswalnum(text[at - 1]) || text[at - 1] == L'_');
            const bool right = at + 8 >= text.size() || !(std::iswalnum(text[at + 8]) || text[at + 8] == L'_');
            if (left && right) return true;
        }
        return false;
    }();
    const auto inside_workspace = [&](const std::string& id) {
        if (!id.starts_with("file:")) return false;
        try {
            const std::wstring candidate = from_uri(id).lexically_normal().wstring();
            return std::any_of(context.allowed_roots.begin(), context.allowed_roots.end(), [&](const fs::path& root) {
                std::wstring prefix = fs::absolute(root).lexically_normal().wstring();
                if (!prefix.ends_with(L"\\")) prefix += L"\\";
                return candidate.size() > prefix.size() &&
                    CompareStringOrdinal(candidate.data(), static_cast<int>(prefix.size()), prefix.data(),
                                         static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL;
            });
        } catch (const std::exception&) { return false; }
    };
    std::set<std::string> examined;  // supertypes already checked, by file and name path or by external name
    // A supertype outside the workspace (framework metadata) cannot be read for its members.
    const auto external_supertype = [&](const std::string& type_name, const std::string& detail) {
        if (!examined.insert("external\n" + type_name).second) return;
        const std::string shown = (type_name.empty() ? std::string("a type") : type_name) +
            (detail.empty() ? std::string() : " (" + detail + ")");
        if (csharp) {
            const bool interface_like = type_name.size() > 1 && type_name[0] == 'I' && std::isupper(static_cast<unsigned char>(type_name[1]));
            if (selected_overrides)
                evidence += "external override: " + member_name + " overrides a member inherited from outside the workspace via " + shown + "\n";
            else if (interface_like)
                evidence += "possible external contract: interface " + shown + " is outside the workspace; check " + member_name + " by hand\n";
            return;
        }
        const bool object_type = type_name == "object" || type_name == "Object" || type_name == "System.Object";
        static const std::set<std::string> object_members{"Equals", "GetHashCode", "ToString", "Finalize"};
        if (!object_type || object_members.contains(member_name))
            evidence += "possible external contract: " + shown + " is outside the workspace; check " + member_name + " by hand\n";
    };
    size_t candidates = 0;
    // Same-name members of one workspace supertype are contracts unless the server shows a sibling overload, not the
    // selected member, implements them. Returns false when this supertype was already checked.
    const auto check_supertype = [&](const SourceText& target, const std::vector<Symbol>& members, const Symbol& parent_symbol) {
        if (!examined.insert(utf8(target.path.lexically_normal().wstring()) + "\n" + parent_symbol.name_path).second) return false;
        const std::string prefix = parent_symbol.name_path + "/";
        for (const auto& member : members) {
            control.check();
            if (simple_name(member.name) != member_name || (member.kind != 6 && member.kind != 7) ||
                !member.name_path.starts_with(prefix) ||
                member.name_path.find('/', prefix.size()) != std::string::npos) continue;
            if (++candidates > 512) fail("too many candidate contract members");
            const J implementations = query("textDocument/implementation", target, member.selection.start);
            J::Array implemented;
            if (std::holds_alternative<J::Array>(implementations.value)) implemented = implementations.array();
            else if (!std::holds_alternative<std::nullptr_t>(implementations.value)) implemented.push_back(implementations);
            bool selected_implements = false, sibling_implements = false;
            for (const auto& location : implemented) {
                const bool link = location.get("targetUri") != nullptr;
                const std::string id = str(location, link ? "targetUri" : "uri");
                const J* item_range = location.get(link ? "targetSelectionRange" : "range");
                if (id.empty() || !item_range || !id.starts_with("file:")) continue;
                const Range where = range(*item_range);
                // URIs decode to forward slashes; compare normalized paths, as load() does for other locations.
                if (!same_path(from_uri(id).lexically_normal(), source.path.lexically_normal())) continue;
                if (!(where.end < selected.selection.start || selected.selection.end < where.start)) {
                    selected_implements = true;
                    continue;
                }
                for (const auto& sibling : document_symbols)
                    if (&sibling != &selected && sibling.name_path.starts_with(owner_prefix) &&
                        sibling.name_path.find('/', owner_prefix.size()) == std::string::npos &&
                        simple_name(sibling.name) == member_name &&
                        !(where.end < sibling.selection.start || sibling.selection.end < where.start))
                        sibling_implements = true;
            }
            // Anything unclear stays a contract.
            if (sibling_implements && !selected_implements) continue;
            evidence += std::string(selected_implements ? "ancestor contract: " : "possible ancestor contract: ") +
                shown_path(target) + ":" + std::to_string(member.selection.start.line + 1) + ":" +
                std::to_string(member.selection.start.column + 1) + " (" + member.name_path + ")\n";
            locations(implementations, "related implementation");
        }
        return true;
    };
    const auto type_at = [&](const std::vector<Symbol>& members, const Range& where) -> const Symbol* {
        const Symbol* found_type = nullptr;
        for (const auto& symbol : members)
            if ((symbol.kind == 5 || symbol.kind == 11 || symbol.kind == 23) &&
                !(symbol.selection.end < where.start || where.end < symbol.selection.start)) {
                if (found_type) fail("ambiguous supertype symbol in contract check");
                found_type = &symbol;
            }
        return found_type;
    };
    // 1. The server's type hierarchy.
    session.assert_current(source);
    J initial = query("textDocument/prepareTypeHierarchy", source, owner->selection.start);
    if (!std::holds_alternative<J::Array>(initial.value) || initial.array().empty())
        fail("language server could not prepare the enclosing type hierarchy");
    J::Array queue = initial.array();
    std::set<std::string> visited;
    size_t cursor = 0;
    while (cursor < queue.size()) {
        control.check();
        if (cursor >= 256) fail("type hierarchy exceeds the contract-check limit");
        const J item = queue[cursor++];
        const std::string id = str(item, "uri");
        const J* selection = item.get("selectionRange");
        if (id.empty() || !selection) fail("language server returned an invalid type hierarchy item");
        const std::string key = id + selection->dump();
        if (!visited.insert(key).second) continue;
        const J parents = session.request("typeHierarchy/supertypes", J::Object{{"item", item}}, control);
        if (std::holds_alternative<std::nullptr_t>(parents.value)) continue;
        for (const auto& parent : parents.array()) {
            control.check();
            const std::string parent_uri = str(parent, "uri");
            const J* parent_selection = parent.get("selectionRange");
            if (parent_uri.empty() || !parent_selection) fail("language server returned an invalid supertype");
            if (!inside_workspace(parent_uri)) { external_supertype(str(parent, "name"), str(parent, "detail")); continue; }
            const SourceText target = load(parent_uri);
            session.wait_indexed(control, &target);
            const auto members = symbols(session, target, control);
            const Symbol* parent_symbol = type_at(members, range(*parent_selection));
            if (!parent_symbol || !parent_symbol->has_body)
                fail("supertype lacks a reliable hierarchical document symbol");
            check_supertype(target, members, *parent_symbol);
            queue.push_back(parent);
        }
    }
    // 2. COMPAT: Roslyn can answer typeHierarchy/supertypes with nothing. C# base lists are also read from source and
    //    each base type resolved with go-to-definition, transitively, so contracts never depend on that one request.
    if (!csharp) return;
    std::vector<std::pair<SourceText, Symbol>> types{{source, *owner}};
    std::set<std::string> walked;
    for (size_t at = 0; at < types.size(); ++at) {
        control.check();
        if (at >= 256) fail("base types exceed the contract-check limit");
        const SourceText file = types[at].first;
        const Symbol type = types[at].second;
        if (!walked.insert(utf8(file.path.lexically_normal().wstring()) + "\n" + type.name_path).second) continue;
        const std::wstring text = wide(file.text);
        const size_t limit = offset(text, type.extent.end);
        const auto word_at = [&](size_t p, std::wstring_view word) {
            return text.compare(p, word.size(), word) == 0 &&
                (p == 0 || !(std::iswalnum(text[p - 1]) || text[p - 1] == L'_')) &&
                (p + word.size() >= text.size() || !(std::iswalnum(text[p + word.size()]) || text[p + word.size()] == L'_'));
        };
        // The base list follows the name, generic parameters and primary-constructor parameters, before any where
        // clause (whose colons are constraints).
        size_t colon = std::wstring::npos;
        int depth = 0;
        for (size_t p = offset(text, type.selection.end); p < limit; ++p) {
            const wchar_t c = text[p];
            if (c == L'<' || c == L'(' || c == L'[') ++depth;
            else if (c == L'>' || c == L')' || c == L']') { if (depth) --depth; }
            else if (!depth && (c == L'{' || c == L';' || word_at(p, L"where"))) break;
            else if (!depth && c == L':') { colon = p; break; }
        }
        if (colon == std::wstring::npos) continue;
        std::vector<std::pair<size_t, size_t>> entries;
        depth = 0;
        for (size_t p = colon + 1, entry = colon + 1; p <= limit; ++p) {
            const wchar_t c = p < limit ? text[p] : L'{';
            if (c == L'<' || c == L'(' || c == L'[') ++depth;
            else if (c == L'>' || c == L')' || c == L']') { if (depth) --depth; }
            else if (!depth && (c == L',' || c == L'{' || c == L';' || word_at(p, L"where"))) {
                entries.emplace_back(entry, p);
                entry = p + 1;
                if (c != L',') break;
            }
        }
        for (const auto& [entry_begin, entry_end] : entries) {
            control.check();
            // The base type's last identifier, before generic or primary-constructor arguments.
            size_t name_end = entry_begin;
            for (size_t r = entry_begin; r < entry_end && text[r] != L'<' && text[r] != L'('; ++r) name_end = r + 1;
            while (name_end > entry_begin && std::iswspace(text[name_end - 1])) --name_end;
            size_t name_begin = name_end;
            while (name_begin > entry_begin && (std::iswalnum(text[name_begin - 1]) || text[name_begin - 1] == L'_')) --name_begin;
            if (name_begin == name_end) continue;
            const std::string type_name = utf8(text.substr(name_begin, name_end - name_begin));
            const J definition = query("textDocument/definition", file, text_end(utf8(text.substr(0, name_begin))));
            J::Array targets;
            if (std::holds_alternative<J::Array>(definition.value)) targets = definition.array();
            else if (!std::holds_alternative<std::nullptr_t>(definition.value)) targets.push_back(definition);
            if (targets.empty()) {
                evidence += "possible ancestor contract: base type " + type_name + " of " + type.name_path +
                    " could not be resolved; check " + member_name + " by hand\n";
                continue;
            }
            for (const auto& location : targets) {
                const bool link = location.get("targetUri") != nullptr;
                const std::string id = str(location, link ? "targetUri" : "uri");
                const J* item_range = location.get(link ? "targetSelectionRange" : "range");
                if (id.empty() || !item_range) fail("language server returned an invalid base type location");
                if (!inside_workspace(id)) { external_supertype(type_name, std::string()); continue; }
                const SourceText target = load(id);
                session.wait_indexed(control, &target);
                const auto members = symbols(session, target, control);
                const Symbol* base = type_at(members, range(*item_range));
                if (!base || !base->has_body) {
                    evidence += "possible ancestor contract: base type " + type_name + " has no reliable document symbol; check " +
                        member_name + " by hand\n";
                    continue;
                }
                check_supertype(target, members, *base);
                types.emplace_back(target, *base);
            }
        }
    }
}

Json lsp_edit(const Json& arguments, const SearchContext& context,
              const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (context.read_only) fail("edit_file is disabled: --read-only");
    const int64_t timeout = number(arguments, "timeout_ms", 180000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout)), cancelled};
    const SourceText descriptor = source_descriptor(context, str(arguments, "path"));
    if (!lsp_required(descriptor.path, descriptor.root)) fail("LSP edits are only for programming files and XML; use text edits for this file");
    const SourceText source = read_source_text(context, str(arguments, "path"));
    if (const J* expected = arguments.get("expected_sha256"))
        if (source.sha256 != lower(expected->string())) fail("expected_sha256 does not match current file");
    if (const J* expected = arguments.get("expected_mtime"))
        if (source.mtime != expected->string()) fail("expected_mtime does not match current file");
    const auto config = configuration(source, context, cancelled);
    if (!config) server_fail(missing_server_message(source));
    auto session = session_for(*config);
    auto lock = acquire(*session, control);
    bool reusable = false;
    try {
        const std::string planned_operation = str(arguments, "operation", "symbol");
        const bool needs_reverse_closure = planned_operation == "rename" || planned_operation == "safe_delete";
        session->start(control, &context, &source, needs_reverse_closure, false, needs_reverse_closure);
        if (session->project_syntax_only())
            throw SymbolLookupFailure("the source project is unavailable; semantic writes are blocked",
                J::Object{{"code", "project_loading"}, {"reason", "project_not_loaded"}, {"project_loading", session->managed_project_status()}});
        session->synchronize(&source, context, control);
        // SAFETY (F10): rename and safe_delete need every reference; with loose scripts cut short they would miss some.
        if (needs_reverse_closure && !session->open_loose_scripts(source, context, control))
            fail("this package has more than " + std::to_string(Session::kLooseScripts) + " scripts and no "
                 "tsconfig.json or jsconfig.json, so references cannot be complete; " + planned_operation +
                 " was refused and nothing was written. Fix: add a jsconfig.json at the package root");
        session->service_pending(control);
        session->assert_current(source);
        reusable = true;
        session->wait_indexed(control, &source);
        std::string operation = str(arguments, "operation", "symbol");
        if (operation == "auto") operation = "symbol";
        const std::string name = str(arguments, "name_path");
        const bool outside = operation == "replace_outside_symbols" || operation == "insert_outside_symbols";
        if (outside) {
            if (arguments.get("name_path") || arguments.get("column")) fail("outside-symbol edits do not accept name_path or column");
            for (const char* key : {"paths_include_glob", "paths_exclude_glob", "occurrence_ids", "expected_count", "start_line", "end_line"})
                if (arguments.get(key)) fail(std::string(key) + " is not valid for outside-symbol edits");
            if (operation == "insert_outside_symbols") {
                for (const char* key : {"needle", "repl", "mode", "allow_multiple_occurrences"})
                    if (arguments.get(key)) fail(std::string(key) + " is not valid for outside-symbol insertion");
            } else if (arguments.get("new_text")) fail("replace_outside_symbols uses repl, not new_text");
        }
        const auto found = (outside || !name.empty()) ? symbols(*session, source, control) : std::vector<Symbol>{};
        const Symbol* selected = name.empty() ? nullptr : &unique(*session, source, found, name);
        Position at;
        if (outside) {
            if (operation == "replace_outside_symbols" && arguments.get("line"))
                fail("replace_outside_symbols does not accept line");
        } else if (selected) {
            if (arguments.get("column") || (arguments.get("line") && operation != "insert_in_symbol"))
                fail("give name_path or line/column, not both; insert_in_symbol accepts name_path and line");
            at = selected->selection.start;
        } else {
            const int64_t line = number(arguments, "line", 0), column = number(arguments, "column", 0);
            if (operation != "rename" || line < 1 || column < 1 || line > INT32_MAX || column > INT32_MAX)
                fail("symbol edits need name_path; rename also accepts 1-based line/column");
            at = {line - 1, column - 1}; offset(wide(source.text), at);
        }
        std::vector<SourceChange> changes;
        std::map<std::wstring, std::string, PathLess> contract_snapshots;
        std::string leftovers, delete_blockers;
        if (outside) {
            const auto protected_ranges = outside_symbol_ranges(source, found, config->language, control);
            changes.push_back({source, outside_content_edit(source, protected_ranges, arguments, cancelled)});
        } else if (operation == "rename") {
            const std::string new_name = str(arguments, "new_name");
            if (new_name.empty() || new_name.find('\0') != std::string::npos) fail("rename requires a nonempty new_name");
            session->require("renameProvider");
            session->wait_indexed(control);
            J::Object params{{"textDocument", J::Object{{"uri", session->document_uri(source)}}}, {"position", at.json()}};
            if (session->prepare_rename()) {
                const J prepared = session->request("textDocument/prepareRename", params, control);
                if (std::holds_alternative<std::nullptr_t>(prepared.value)) fail("language server refuses rename at this position");
            }
            params.emplace("newName", new_name);
            J edit;
            for (int attempt = 0;; ++attempt) {
                edit = session->request("textDocument/rename", params, control);
                if (std::holds_alternative<std::nullptr_t>(edit.value) || !config->indexes_workspace) break;
                std::vector<std::string> targets;
                if (const J* by_file = edit.get("changes"))
                    for (const auto& [id, edits] : by_file->object()) { (void)edits; targets.push_back(id); }
                if (const J* documents = edit.get("documentChanges"))
                    for (const auto& change : documents->array())
                        if (const J* document = change.get("textDocument")) targets.push_back(str(*document, "uri"));
                bool synchronized_targets = false;
                for (const auto& id : targets) {
                    control.check();
                    const fs::path path = from_uri(id);
                    if (path_excluded(*config, path))
                        fail("language server workspace edit targets ignored_paths; nothing written");
                    const SourceText current = read_source_text(context, utf8(path.wstring()));
                    if (session->has_document(current)) continue;
                    session->pin(current, control);
                    synchronized_targets = true;
                }
                if (!synchronized_targets) break;
                if (attempt == 2) server_fail("language server kept planning rename edits for unsynchronized files; nothing written");
                session->service_pending(control);
                session->wait_indexed(control);
            }
            const std::string old_name = identifier_at(source.text, at);
            changes = workspace_changes(*session, edit, *config, context, control, old_name, true);
            if (flag(arguments, "rename_text_occurrences")) leftovers = rewrite_rename_text_mentions(old_name, new_name, changes);
            leftovers += rename_leftovers(old_name, changes, context, control);
        } else {
            std::string member_language = config->language;
            if (member_language == "typescript" || member_language == "typescriptreact" ||
                member_language == "javascriptreact") member_language = "javascript";
            if (member_language == "c" || member_language == "c++") member_language = "cpp";
            if (member_language == "cs") member_language = "csharp";
            const bool member_language_supported = member_language == "cpp" || member_language == "csharp" ||
                member_language == "javascript" || member_language == "rust" || member_language == "python" ||
                member_language == "lua" || member_language == "xml";
            const bool member_insertion = selected && member_language_supported &&
                (operation == "insert_before" || operation == "insert_after") &&
                (member_language == "xml" || member_insert_target(*selected, found));
            if (!selected || (!selected->has_body && !member_insertion))
                fail("symbol has no reliable editable definition range");
            if (operation == "safe_delete") {
                try {
                    session->require("referencesProvider");
                    session->wait_indexed(control);
                    const J references = session->request("textDocument/references", J::Object{
                        {"textDocument", J::Object{{"uri", session->document_uri(source)}}}, {"position", at.json()},
                        {"context", J::Object{{"includeDeclaration", false}}}}, control);
                    if (!std::holds_alternative<std::nullptr_t>(references.value))
                        for (const auto& reference : references.array()) {
                            control.check();
                            const fs::path target_path = from_uri(str(reference, "uri"));
                            if (path_excluded(*config, target_path)) fail("ignored_paths may contain references");
                            const SourceText target = read_source_text(context, utf8(target_path.wstring()));
                            const J* extent = reference.get("range"); if (!extent) fail("reference has no range");
                            const Range r = range(*extent);
                            const bool same = !PathLess{}(target.path.wstring(), source.path.wstring()) &&
                                              !PathLess{}(source.path.wstring(), target.path.wstring());
                            if (!same || r.start < selected->extent.start || selected->extent.end < r.end)
                                delete_blockers += "reference: " + shown_path(target) + ":" +
                                    std::to_string(r.start.line + 1) + ":" + std::to_string(r.start.column + 1) + "\n";
                        }
                    safe_delete_contracts(*session, source, *selected, found, *config, context, control,
                                          contract_snapshots, delete_blockers);
                } catch (const std::exception& error) {
                    control.check();
                    delete_blockers += std::string("contract or reference check incomplete: ") + error.what() + "\n";
                }
                if (!delete_blockers.empty() && !flag(arguments, "dry_run"))
                    fail("safe_delete refused; nothing was written:\n" + delete_blockers);
            } else if (operation != "symbol" && operation != "insert_before" && operation != "insert_after" &&
                       operation != "replace_in_symbol" && operation != "insert_in_symbol") fail("unknown symbol edit operation");
            if (operation == "replace_in_symbol" || operation == "insert_in_symbol") {
                const std::wstring original = wide(source.text);
                const size_t first = offset(original, selected->extent.start);
                const size_t last = offset(original, selected->extent.end);
                const size_t begin = utf8(original.substr(0, first)).size();
                const size_t end = begin + utf8(original.substr(first, last - first)).size();
                changes.push_back({source, scoped_content_edit(source, begin, end, arguments, cancelled)});
            } else if (member_insertion) {
                changes.push_back({source, inserted_member_text(source, *selected, found, member_language,
                                                                operation, arguments, control)});
            } else {
                Symbol editable = *selected;
                if (member_language == "csharp" &&
                    (selected->kind == 6 || selected->kind == 9 || selected->kind == 12) &&
                    (operation == "safe_delete" || operation == "symbol" || operation == "insert_before" || operation == "insert_after")) {
                    const std::wstring original = wide(source.text);
                    const size_t anchor = offset(original, selected->selection.start);
                    const size_t selection_end = offset(original, selected->selection.end);
                    Position identifier_position = selected->selection.start;
                    if (anchor < original.size() && original[anchor] == L'@') ++identifier_position.column;
                    const std::string actual = identifier_at(source.text, identifier_position);
                    std::string expected = selected->name;
                    if (const size_t paren = expected.find('('); paren != std::string::npos) expected.resize(paren);
                    if (const size_t generic = expected.find('<'); generic != std::string::npos) expected.resize(generic);
                    if (const size_t dot = expected.rfind('.'); dot != std::string::npos) expected.erase(0, dot + 1);
                    if (!expected.empty() && expected.front() == '~') expected.erase(0, 1);
                    if (!expected.empty() && expected.front() == '@') expected.erase(0, 1);
                    if (actual.empty() || actual != expected)
                        fail("language server selection does not identify the requested C# method; nothing written");
                    const MemberSpan span = member_declaration_span(original, *selected, found, member_language, control);
                    if (span.begin > anchor || span.end < selection_end || span.begin >= span.end)
                        fail("cannot determine a complete C# method declaration; nothing written");
                    for (const auto& sibling : found) {
                        if (&sibling == selected) continue;
                        const size_t sibling_anchor = offset(original, sibling.selection.start);
                        if (sibling_anchor >= selection_end && sibling_anchor < span.end &&
                            sibling.extent.start >= selected->extent.start &&
                            sibling.extent.end <= selected->extent.end) continue;
                        if (sibling_anchor >= selection_end && sibling_anchor < span.end)
                            fail("method boundary crosses another symbol; nothing written");
                    }
                    editable.extent.start = text_end(utf8(original.substr(0, span.begin)));
                    editable.extent.end = text_end(utf8(original.substr(0, span.end)));
                }
                if (operation == "safe_delete" || operation == "symbol" || operation == "insert_before") {
                    const std::wstring original = wide(source.text);
                    const size_t begin = offset(original, editable.extent.start);
                    size_t recovered = decorated_declaration_start(original, begin, member_language, control);
                    if (operation == "insert_before")
                        recovered = leading_comment_start(original, recovered, member_language, control);
                    const size_t selected_begin = offset(original, selected->selection.start);
                    if (recovered > selected_begin) fail("declaration starts after its selected name; nothing written");
                    for (const auto& sibling : found) {
                        if (&sibling == selected) continue;
                        const size_t sibling_begin = offset(original, sibling.selection.start);
                        if (sibling_begin >= recovered && sibling_begin < begin)
                            fail("attribute boundary crosses another symbol; nothing written");
                    }
                    size_t start = recovered;
                    if (operation == "symbol") {
                        // A replacement that brings no attributes, decorators or leading comments of its own keeps the
                        // existing ones: only the declaration itself is replaced.
                        const std::string body = str(arguments, "new_text");
                        const size_t first = body.find_first_not_of(" \t\r\n");
                        const std::string_view lead = first == std::string::npos ? std::string_view{} : std::string_view(body).substr(first);
                        const bool brings_prefix = lead.starts_with("[") || lead.starts_with("@") || lead.starts_with("#[") ||
                            lead.starts_with("//") || lead.starts_with("/*") || (member_language == "python" && lead.starts_with("#"));
                        if (!brings_prefix) start = undecorated_declaration_start(original, recovered, selected_begin, member_language);
                    }
                    editable.extent.start = text_end(utf8(original.substr(0, start)));
                }
                changes.push_back({source, edited_symbol_text(source, editable, operation, arguments, control)});
            }
        }
        // A literal needle/old_text was matched in the bytes just read, which proves the caller knew the replaced text;
        // such edits need no earlier session read. Regex, whole-body, insert, rename and delete edits still do.
        if ((operation == "replace_in_symbol" || operation == "replace_outside_symbols") &&
            str(arguments, "mode", "literal") == "literal")
            for (auto& change : changes) change.anchored = true;
        control.check();
        const auto current = read_source_text(context, utf8(source.path.wstring()));
        if (current.sha256 != source.sha256 || (arguments.get("expected_mtime") && current.mtime != source.mtime))
            fail("source changed during refactoring; retry");
        for (const auto& [path, digest] : contract_snapshots) {
            control.check();
            if (read_source_text(context, utf8(path)).sha256 != digest)
                fail("contract or reference file changed during safe_delete; retry");
        }
        J result = apply_source_changes(changes, arguments, context, cancelled);
        if (flag(arguments, "dry_run") &&
            (operation == "replace_in_symbol" || operation == "replace_outside_symbols") &&
            str(arguments, "mode", "literal") == "literal" &&
            str(arguments, "needle") == str(arguments, "repl")) {
            auto& text = std::get<J::Object>(result.value)["text"];
            text = text.string() + "Needle and replacement are identical; no content will change.\n";
        }
        if (!delete_blockers.empty()) {
            auto& object = std::get<J::Object>(result.value);
            object["text"] = "safe_delete would be blocked; nothing written:\n" +
                delete_blockers + object.at("text").string();
            object["safe_delete_blocked"] = true;
        }
        if (config->indexes_workspace) resync_written(*session, changes, context, control);
        if (!leftovers.empty()) {
            auto& text = std::get<J::Object>(result.value)["text"];
            text = text.string() + leftovers;
        }
        return result;
    } catch (const IndexWarmingFailure&) {
        if (!reusable || (cancelled && cancelled->load()) || Clock::now() >= control.deadline) session->stop();
        throw;
    } catch (const LspTimeoutFailure&) {
        if (auto warming = session->warming_timeout(&source)) {
            if (!reusable) session->stop();
            throw *warming;
        }
        if (!reusable || (cancelled && cancelled->load()) || Clock::now() >= control.deadline) session->stop();
        throw;
    } catch (const RejectedLspRequest&) {
        if (!reusable || (cancelled && cancelled->load()) || Clock::now() >= control.deadline) session->stop();
        throw;
    } catch (const SymbolLookupFailure&) {
        if (!reusable || (cancelled && cancelled->load()) || Clock::now() >= control.deadline) session->stop();
        throw;
    } catch (...) { session->stop(); throw; }
}

Json lsp_move(const Json& arguments, const SearchContext& context,
              const std::shared_ptr<std::atomic_bool>& cancelled) {
    const std::string operation = str(arguments, "operation", "auto");
    if (operation != "auto" && operation != "filesystem" && operation != "refactor") fail("move_file operation must be auto, filesystem, or refactor");
    if (operation != "filesystem" && flag(arguments, "overwrite")) fail("LSP file moves do not overwrite; use operation=filesystem explicitly");
    const int64_t timeout = number(arguments, "timeout_ms", operation == "filesystem" ? 30000 : 180000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout)), cancelled};
    bool directory = false;
    const SourceText source = source_descriptor(context, str(arguments, "source"), &directory);
    bool destination_exists = false;
    const SourceText destination = source_descriptor(context, str(arguments, "destination"), nullptr, true, &destination_exists);
    if (source.path == source.root || destination.path == destination.root) fail("cannot move a configured root");
    // Paths equal but for letter case name the same entry on Windows: a case-only rename of the last component (#95).
    // It moves like any other path (auto/refactor still ask the server for import edits naming the new spelling); its
    // destination "exists" only as the source itself, so it needs no overwrite.
    const bool case_only = !PathLess{}(source.path.wstring(), destination.path.wstring()) &&
                           !PathLess{}(destination.path.wstring(), source.path.wstring());
    if (case_only && source.path.wstring() == destination.path.wstring()) fail("source and destination are the same path");
    if (case_only && source.path.parent_path().wstring() != destination.path.parent_path().wstring())
        fail("only the last path component's letter case can change in one move; move the folder whose case changes "
             "itself; nothing written");
    const std::wstring prefix = source.path.wstring() + L"\\";
    const std::wstring dest = destination.path.wstring();
    if (dest.size() > prefix.size() && CompareStringOrdinal(dest.data(), static_cast<int>(prefix.size()),
            prefix.data(), static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL) fail("cannot move a directory into itself");
    if (destination_exists && !case_only && !flag(arguments, "overwrite"))
        fail("move destination already exists; nothing written");
    std::vector<SourceChange> changes;
    bool supported = false;
    std::vector<Config> move_configs;
    if (operation != "filesystem") {
        if (directory) {
            std::set<std::string> seen;
            for (const auto& base : configs(source.root, context, cancelled)) {
                if (!base.managed_projects) { move_configs.push_back(base); continue; }
                bool found = false;
                for (const auto& root : base.workspace_roots)
                    for (const auto& path : source_paths(context, utf8(root.wstring()), {".csproj"}, control.deadline, cancelled)) {
                        control.check();
                        auto selected = project_profile(base, source_descriptor(context, path), context);
                        if (seen.insert(selected.key).second) move_configs.push_back(std::move(selected));
                        found = true;
                    }
                if (!found && seen.insert(base.key).second) move_configs.push_back(base);
            }
        } else if (auto selected = configuration(source, context, cancelled)) move_configs.push_back(std::move(*selected));
    }
    for (const auto& config : move_configs) {
            const std::string extension = language_extension(source.path);
            if (!directory && std::find(config.extensions.begin(), config.extensions.end(), extension) == config.extensions.end()) continue;
            if (directory && !worth_starting(config, context, control)) continue;
            auto session = session_for(config);
            auto lock = acquire(*session, control);
            bool reusable = false;
            try {
                session->start(control, &context, directory ? nullptr : &source, true, directory, true);
                session->synchronize(nullptr, context, control); session->service_pending(control);
                reusable = true;
                session->wait_indexed(control);
                if (!(session->file_operation("willRename", source.path, directory) || session->file_operation("willRename", destination.path, directory))) continue;
                supported = true;
                session->wait_indexed(control);
                // SAFETY: import edits carry no old text to check, so in an indexing session every file they touch is
                //   opened with its current bytes and the server is asked again; the edits then rest on exactly what
                //   shgrep will change, and workspace_changes verifies them against the open documents.
                J edit;
                for (int attempt = 0;; ++attempt) {
                    edit = session->request("workspace/willRenameFiles", J::Object{
                        {"files", J::Array{J::Object{{"oldUri", uri(source.path)}, {"newUri", uri(destination.path)}}}}}, control);
                    if (std::holds_alternative<std::nullptr_t>(edit.value) || !session->config.indexes_workspace) break;
                    std::vector<std::string> targets;
                    if (const J* changes_by_file = edit.get("changes"))
                        for (const auto& [id, edits] : changes_by_file->object()) { (void)edits; targets.push_back(id); }
                    if (const J* documents = edit.get("documentChanges"))
                        for (const auto& change : documents->array())
                            if (const J* document = change.get("textDocument")) targets.push_back(str(*document, "uri"));
                    bool opened = false;
                    for (const auto& id : targets) {
                        std::optional<SourceText> current;
                        try { current = read_source_text(context, utf8(from_uri(id).wstring())); }
                        catch (const std::exception&) { continue; }  // workspace_changes reports it below
                        if (session->has_document(*current)) continue;
                        session->pin(*current, control);
                        opened = true;
                    }
                    if (!opened) break;
                    if (attempt == 2) server_fail("language server kept planning import edits for files that changed; nothing written");
                    session->service_pending(control);
                }
                if (!std::holds_alternative<std::nullptr_t>(edit.value)) {
                    auto planned = workspace_changes(*session, edit, config, context, control);
                    for (auto& change : planned) changes.push_back(std::move(change));
                }
            } catch (const IndexWarmingFailure&) {
                if (!reusable || (cancelled && cancelled->load()) || Clock::now() >= control.deadline) session->stop();
                throw;
            } catch (const LspTimeoutFailure&) {
                if (auto warming = session->warming_timeout()) {
                    if (!reusable) session->stop();
                    throw *warming;
                }
                if (!reusable || (cancelled && cancelled->load()) || Clock::now() >= control.deadline) session->stop();
                throw;
            } catch (const RejectedLspRequest&) {
                if (!reusable || (cancelled && cancelled->load()) || Clock::now() >= control.deadline) session->stop();
                throw;
            } catch (...) { session->stop(); throw; }
        }
    if (operation == "refactor" && !supported) fail("no configured language server supports willRenameFiles; nothing written");
    return apply_source_changes(changes, arguments, context, cancelled, &arguments);
}

void lsp_after_mutation(Json& result, const std::string& tool, const Json& arguments,
                        const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled) {
    std::vector<std::shared_ptr<Session>> active;
    { std::lock_guard lock(registry_mutex); for (const auto& [key, session] : registry) { (void)key; active.push_back(session); } }
    // After the request's deadline the sync is left to the next request, which catches up the same way.
    const Control control{request_deadline(Clock::now() + std::chrono::seconds(30)), cancelled};
    if (Clock::now() >= control.deadline || (tool == "delete_file" && cancelled && cancelled->load())) {
        if (tool == "delete_file" && !active.empty()) {
            auto& object = std::get<J::Object>(result.value);
            const std::string warning = "[warning: deletion applied; language-server synchronization was deferred]\n";
            if (auto it = object.find("text"); it != object.end()) it->second = it->second.string() + warning;
            object["warning"] = warning;
        }
        return;
    }
    auto belongs = [](const fs::path& child, const fs::path& root) {
        const std::wstring candidate = child.wstring(), parent = root.wstring();
        return candidate.size() >= parent.size() &&
            CompareStringOrdinal(candidate.data(), static_cast<int>(parent.size()), parent.data(), static_cast<int>(parent.size()), TRUE) == CSTR_EQUAL &&
            (candidate.size() == parent.size() || parent.ends_with(L"\\") || candidate[parent.size()] == L'\\');
    };
    for (auto& session : active) {
        try {
            auto lock = acquire(*session, control);
            try {
                const auto current = configs(session->config.root, context, cancelled, false);
                const bool retained = std::any_of(current.begin(), current.end(), [&](const auto& config) {
                    return config.key == session->config.key ||
                        (!config.workspace_roots.empty() && (session->config.key.starts_with(config.key + ":sdk:") ||
                                                             session->config.key.starts_with(config.key + ":ts:")));
                });
                if (!retained) {
                    session->stop();
                    std::lock_guard registry_lock(registry_mutex);
                    registry.erase(session->config.key);
                    continue;
                }
                session->start(control, &context);
                bool directory = false;
                const std::string path = tool == "move_file" ? str(arguments, "destination") : str(arguments, "path");
                const SourceText descriptor = source_descriptor(context, path, &directory, tool == "delete_file");
                const auto session_contains = [&](const fs::path& path) {
                    if (session->config.workspace_roots.empty()) return belongs(path, session->config.root);
                    return std::any_of(session->config.workspace_roots.begin(), session->config.workspace_roots.end(),
                        [&](const auto& root) { return belongs(path, root); });
                };
                const bool relevant = session_contains(descriptor.path);
                std::optional<SourceText> primary;
                const std::string extension = language_extension(descriptor.path);
                if (tool != "delete_file" && relevant && !directory &&
                    std::find(session->config.extensions.begin(), session->config.extensions.end(), extension) != session->config.extensions.end())
                    primary = read_source_text(context, path);
                if (tool == "move_file") {
                    const auto old = source_descriptor(context, str(arguments, "source"), nullptr, true);
                    if ((relevant || session_contains(old.path)) &&
                        (session->file_operation("didRename", old.path, directory) || session->file_operation("didRename", descriptor.path, directory)))
                        session->notify("workspace/didRenameFiles", J::Object{
                            {"files", J::Array{J::Object{{"oldUri", uri(old.path)}, {"newUri", uri(descriptor.path)}}}}}, control);
                } else if (tool == "delete_file" && relevant && session->file_operation("didDelete", descriptor.path)) {
                    session->notify("workspace/didDeleteFiles", J::Object{
                        {"files", J::Array{J::Object{{"uri", uri(descriptor.path)}}}}}, control);
                } else if (tool == "create_directory" && relevant && session->file_operation("didCreate", descriptor.path, true)) {
                    const J* text = result.get("text");
                    if (text && text->string().starts_with("Created "))
                        session->notify("workspace/didCreateFiles", J::Object{{"files", J::Array{J::Object{{"uri", uri(descriptor.path)}}}}}, control);
                }
                session->synchronize(primary ? &*primary : nullptr, context, control, true);
            } catch (...) { session->stop(); throw; }
        } catch (const IndexWarmingFailure& e) {
            auto& object = std::get<J::Object>(result.value);
            const std::string warning = lsp_failure_banner("language server synchronization is still warming after the write: " + std::string(e.what()),
                "The write itself succeeded; retry semantic requests when the server is ready.");
            if (auto it = object.find("text"); it != object.end()) it->second = it->second.string() + warning;
            if (auto it = object.find("warning"); it != object.end()) it->second = it->second.string() + warning;
            else object.emplace("warning", warning);
            object["warning_code"] = "index_warming";
            object["warning_details"] = e.details;
        } catch (const std::exception& e) {
            auto& object = std::get<J::Object>(result.value);
            const std::string warning = lsp_failure_banner("language server synchronization failed after the write: " + std::string(e.what()),
                "The write itself succeeded; symbol results may be stale until the server recovers.");
            if (auto it = object.find("text"); it != object.end()) it->second = it->second.string() + warning;
            if (auto it = object.find("warning"); it != object.end()) it->second = it->second.string() + warning;
            else object.emplace("warning", warning);
        }
    }
}
} // namespace shgrep
