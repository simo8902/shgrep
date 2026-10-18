#include "compile_db.hpp"
#include "files.hpp"
#include <windows.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cwctype>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace shgrep {
namespace {
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
using J = Json;

constexpr auto kRescan = std::chrono::seconds(10);
constexpr auto kFallbackRescan = std::chrono::seconds(60);
constexpr int kScanDepth = 5;
constexpr size_t kScanFolders = 20000;
constexpr size_t kFallbackIncludes = 1024;
constexpr size_t kProjectBytes = 16u << 20;
constexpr auto kConfigureTimeout = std::chrono::minutes(15);
constexpr uint64_t kSeed = 14695981039346656037ull;

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
    bool valid() const { return h && h != INVALID_HANDLE_VALUE; }
};

std::string utf8(const std::wstring& s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), 0);
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}
std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(n), 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}
std::wstring lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}
std::string lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
// Paths handed to cmake, clangd and status output carry no \\?\ prefix.
fs::path plain(const fs::path& path) {
    const std::wstring p = path.wstring();
    if (p.starts_with(L"\\\\?\\UNC\\")) return fs::path(L"\\\\" + p.substr(8));
    if (p.starts_with(L"\\\\?\\")) return fs::path(p.substr(4));
    return path;
}
std::wstring extended(const fs::path& path) {
    const std::wstring p = path.wstring();
    if (p.starts_with(L"\\\\?\\")) return p;
    if (p.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + p.substr(2);
    return L"\\\\?\\" + p;
}
uint64_t mix(uint64_t h, std::string_view s) {
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ull; }
    h ^= 0xff; h *= 1099511628211ull;
    return h;
}
std::string hex(uint64_t v) {
    char buffer[17];
    std::snprintf(buffer, sizeof buffer, "%016llx", static_cast<unsigned long long>(v));
    return buffer;
}

struct Stamp { uint64_t size = 0, time = 0; bool exists = false; };
Stamp stamp(const fs::path& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(extended(path).c_str(), GetFileExInfoStandard, &data) ||
        (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) return {};
    return {(static_cast<uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow,
            (static_cast<uint64_t>(data.ftLastWriteTime.dwHighDateTime) << 32) | data.ftLastWriteTime.dwLowDateTime, true};
}
// Names, sizes and write times of build inputs; any edit, addition or removal changes it.
std::string inputs_fingerprint(const std::vector<fs::path>& files) {
    uint64_t h = kSeed;
    for (const auto& file : files) {
        const Stamp s = stamp(file);
        h = mix(h, utf8(lower(file.wstring())));
        h = mix(h, std::to_string(s.size) + ":" + std::to_string(s.time));
    }
    return hex(h);
}
std::string read_text(const fs::path& path, size_t limit = 4096) {
    std::ifstream in(extended(path), std::ios::binary);
    if (!in) return {};
    std::string text;
    text.resize(limit + 1);
    in.read(text.data(), static_cast<std::streamsize>(text.size()));
    text.resize(static_cast<size_t>(in.gcount()));
    if (text.size() > limit) return {};
    return text;
}
void write_text(const fs::path& path, const std::string& text) {
    const fs::path temporary = path.wstring() + L"." + std::to_wstring(GetCurrentProcessId()) + L".tmp";
    {
        std::ofstream out(extended(temporary), std::ios::binary | std::ios::trunc);
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
        if (!out.flush()) throw std::runtime_error("cannot write " + utf8(path.wstring()));
    }
    if (!MoveFileExW(extended(temporary).c_str(), extended(path).c_str(), MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileW(extended(temporary).c_str());
        throw std::runtime_error("cannot replace " + utf8(path.wstring()));
    }
}

// Windows compilation databases use CRT quoting: backslashes are special only before a double quote.
J::Array command_arguments(std::string_view command) {
    J::Array result;
    size_t p = 0;
    while (p < command.size()) {
        while (p < command.size() && (command[p] == ' ' || command[p] == '\t')) ++p;
        if (p == command.size()) break;
        std::string argument;
        bool quoted = false;
        while (p < command.size() && (quoted || (command[p] != ' ' && command[p] != '\t'))) {
            size_t slashes = 0;
            while (p < command.size() && command[p] == '\\') { ++slashes; ++p; }
            if (p < command.size() && command[p] == '"') {
                argument.append(slashes / 2, '\\');
                if (slashes % 2) { argument.push_back('"'); ++p; }
                else if (quoted && p + 1 < command.size() && command[p + 1] == '"') {
                    argument.push_back('"'); p += 2;
                } else { quoted = !quoted; ++p; }
            } else {
                argument.append(slashes, '\\');
                if (p < command.size() && (quoted || (command[p] != ' ' && command[p] != '\t')))
                    argument.push_back(command[p++]);
                else break;
            }
        }
        result.emplace_back(std::move(argument));
    }
    return result;
}
struct CompilePathLess {
    bool operator()(const std::wstring& a, const std::wstring& b) const {
        return CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(), static_cast<int>(b.size()), TRUE) == CSTR_LESS_THAN;
    }
};
struct CombinedDatabase {
    J::Array entries;
    J::Object changes;
    J::Array paths;
    std::string fingerprint;
    uint64_t duplicates = 0;
};
CombinedDatabase combine_databases(const fs::path& root, std::vector<fs::path> databases, bool virtual_commands) {
    // CONTRACT: the workspace database wins conflicts. Otherwise the newest configuration wins for each file;
    //   commands for unrelated projects are retained regardless of which database was written last.
    const fs::path root_database = root / L"compile_commands.json";
    std::map<fs::path, Stamp> stamps;
    for (const auto& database : databases) stamps.emplace(database, stamp(database));
    std::sort(databases.begin(), databases.end(), [&](const fs::path& a, const fs::path& b) {
        const bool ar = lower(a.wstring()) == lower(root_database.wstring());
        const bool br = lower(b.wstring()) == lower(root_database.wstring());
        if (ar != br) return ar;
        const auto at = stamps.at(a).time, bt = stamps.at(b).time;
        return at != bt ? at > bt : lower(a.wstring()) < lower(b.wstring());
    });
    CombinedDatabase combined;
    std::set<std::wstring, CompilePathLess> seen;
    uint64_t hash = kSeed;
    size_t total_bytes = 0;
    constexpr size_t database_bytes = 256u << 20, total_limit = 512u << 20;
    for (const auto& database : databases) {
        const Stamp size = stamp(database);
        if (!size.exists) throw std::runtime_error("compile database disappeared: " + utf8(database.wstring()));
        if (size.size > database_bytes || size.size > total_limit - total_bytes)
            throw std::runtime_error("compile databases exceed the 256 MiB per-file / 512 MiB total metadata limit");
        const std::string bytes = read_text(database, static_cast<size_t>(size.size));
        if (bytes.empty()) throw std::runtime_error("cannot read compile database: " + utf8(database.wstring()));
        total_bytes += bytes.size();
        hash = mix(mix(hash, utf8(database.wstring())), bytes);
        const J parsed = J::parse(bytes);
        combined.paths.emplace_back(utf8(database.wstring()));
        for (const auto& entry : parsed.array()) {
            auto fields = entry.object();
            const auto directory_it = fields.find("directory"), file_it = fields.find("file");
            if (directory_it == fields.end() || file_it == fields.end())
                throw std::runtime_error("compile database entry requires directory and file: " + utf8(database.wstring()));
            fs::path directory = fs::path(wide(directory_it->second.string()));
            fs::path file = fs::path(wide(file_it->second.string()));
            if (directory.empty() || file.empty()) throw std::runtime_error("compile database directory/file is empty");
            if (directory.is_relative()) directory = database.parent_path() / directory;
            directory = plain(directory).lexically_normal();
            if (file.is_relative()) file = directory / file;
            file = plain(file).lexically_normal();
            const auto args = fields.find("arguments"), command = fields.find("command");
            if (args == fields.end() && command == fields.end())
                throw std::runtime_error("compile database entry requires arguments or command: " + utf8(database.wstring()));
            if (args != fields.end()) {
                if (args->second.array().empty()) throw std::runtime_error("compile database arguments is empty");
                for (const auto& argument : args->second.array()) (void)argument.string();
            } else if (command->second.string().empty()) throw std::runtime_error("compile database command is empty");
            if (!seen.insert(file.wstring()).second) { ++combined.duplicates; continue; }
            if (seen.size() > 1000000) throw std::runtime_error("compile databases exceed one million distinct files");
            fields["directory"] = utf8(directory.wstring());
            fields["file"] = utf8(file.wstring());
            if (virtual_commands) {
                J::Array arguments = args != fields.end() ? args->second.array() : command_arguments(command->second.string());
                if (arguments.empty()) throw std::runtime_error("compile database command has no arguments");
                combined.changes[utf8(file.wstring())] = J::Object{
                    {"workingDirectory", utf8(directory.wstring())}, {"compilationCommand", std::move(arguments)}};
            } else combined.entries.emplace_back(std::move(fields));
        }
    }
    combined.fingerprint = hex(hash);
    return combined;
}

// Bounded structural walk for build metadata. Unlike source walks it enters .gitignore'd build folders, because
// that is where compile_commands.json lives.
struct Layout { std::vector<fs::path> databases, cmake_inputs, projects; };
bool skipped_folder(const std::wstring& name) {
    static const std::set<std::wstring> names{L".git", L".hg", L".svn", L".shgrep", L".vs", L".vscode", L".idea",
                                              L".cache", L".tgrep", L".serena", L"node_modules", L"__pycache__"};
    return names.contains(lower(name));
}
void scan_folder(const fs::path& folder, int depth, bool build_tree, Layout& layout, size_t& folders) {
    if (++folders > kScanFolders) return;
    WIN32_FIND_DATAW data;
    HANDLE find = FindFirstFileExW(extended(folder / L"*").c_str(), FindExInfoBasic, &data, FindExSearchNameMatch,
                                   nullptr, FIND_FIRST_EX_LARGE_FETCH);
    if (find == INVALID_HANDLE_VALUE) return;
    std::vector<std::pair<std::wstring, bool>> entries;
    do {
        const std::wstring name = data.cFileName;
        if (name == L"." || name == L"..") continue;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;  // SAFETY: links are never followed
        entries.emplace_back(name, (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
    } while (FindNextFileW(find, &data));
    FindClose(find);
    // CONTRACT: a CMake build tree (CMakeCache.txt) contributes its compile_commands.json only. Its generated
    //   .cmake files and .vcxproj files change on every build and must not trigger a reconfigure.
    build_tree = build_tree || std::any_of(entries.begin(), entries.end(), [](const auto& entry) {
        return !entry.second && lower(entry.first) == L"cmakecache.txt";
    });
    std::vector<fs::path> children;
    for (const auto& [name, directory] : entries) {
        if (directory) {
            if (depth < kScanDepth && !skipped_folder(name)) children.push_back(folder / name);
            continue;
        }
        const std::wstring n = lower(name);
        if (n == L"compile_commands.json") layout.databases.push_back(folder / name);
        else if (build_tree) continue;
        else if (n == L"cmakelists.txt" || n == L"cmakepresets.json" || n == L"cmakeuserpresets.json" ||
                 (n.size() > 6 && n.ends_with(L".cmake"))) layout.cmake_inputs.push_back(folder / name);
        else if (n.ends_with(L".vcxproj")) layout.projects.push_back(folder / name);
    }
    for (const auto& child : children) scan_folder(child, depth + 1, build_tree, layout, folders);
}

Handle null_device(bool write) {
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    return Handle(CreateFileW(L"NUL", write ? GENERIC_WRITE : GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &security, OPEN_EXISTING, 0, nullptr));
}
fs::path system_folder() {
    wchar_t buffer[MAX_PATH];
    const UINT n = GetSystemDirectoryW(buffer, MAX_PATH);
    return n && n < MAX_PATH ? fs::path(std::wstring(buffer, n)) : fs::path(L"C:\\Windows\\System32");
}
// SAFETY: the child inherits only its standard handles and dies with its job object when shgrep exits.
bool launch(std::wstring command, HANDLE output, HANDLE error, const fs::path& folder, Handle& process, Handle& job,
            std::string& problem) {
    Handle input = null_device(false);
    if (!input.valid()) { problem = "cannot open NUL"; return false; }
    job.reset(CreateJobObjectW(nullptr, nullptr));
    if (!job.h) { problem = "cannot create a process job"; return false; }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        problem = "cannot configure a process job"; return false;
    }
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<unsigned char> storage(bytes);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) { problem = "cannot prepare process attributes"; return false; }
    HANDLE inherited[3]{input.h, output, error};
    const size_t count = output == error ? 2 : 3;
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, count * sizeof(HANDLE),
                                   nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attributes);
        problem = "cannot isolate child handles"; return false;
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.h;
    startup.StartupInfo.hStdOutput = output;
    startup.StartupInfo.hStdError = error;
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION info{};
    const BOOL created = CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, folder.c_str(), &startup.StartupInfo, &info);
    const DWORD code = GetLastError();
    DeleteProcThreadAttributeList(attributes);
    if (!created) { problem = "cannot start process (Windows error " + std::to_string(code) + ")"; return false; }
    process.reset(info.hProcess);
    Handle thread(info.hThread);
    if (!AssignProcessToJobObject(job.h, process.h)) {
        TerminateProcess(process.h, 1);
        problem = "cannot assign process to its job"; return false;
    }
    ResumeThread(thread.h);
    return true;
}
std::optional<std::string> run_capture(const std::wstring& command, std::chrono::milliseconds timeout) {
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE r = nullptr, w = nullptr;
    if (!CreatePipe(&r, &w, &security, 0)) return std::nullopt;
    Handle read(r), write(w), error = null_device(true);
    if (!SetHandleInformation(read.h, HANDLE_FLAG_INHERIT, 0) || !error.valid()) return std::nullopt;
    Handle process, job;
    std::string problem;
    if (!launch(command, write.h, error.h, system_folder(), process, job, problem)) return std::nullopt;
    write.reset();
    const auto deadline = Clock::now() + timeout;
    std::string out;
    char buffer[4096];
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(read.h, nullptr, 0, nullptr, &available, nullptr)) break;  // writer closed: finished
        if (available) {
            DWORD got = 0;
            if (!ReadFile(read.h, buffer, std::min<DWORD>(available, sizeof buffer), &got, nullptr) || !got) break;
            out.append(buffer, got);
            if (out.size() > (1u << 20)) return std::nullopt;
            continue;
        }
        if (Clock::now() >= deadline) return std::nullopt;
        WaitForSingleObject(process.h, 20);
    }
    return out;
}

// The CMake configure needs MSVC's environment; Visual Studio ships cmake.exe and ninja.exe with its C++ CMake tools.
struct Toolchain { fs::path vcvars, cmake, ninja; std::string problem; };
fs::path on_path(const wchar_t* name) {
    wchar_t buffer[MAX_PATH];
    const DWORD n = SearchPathW(nullptr, name, nullptr, MAX_PATH, buffer, nullptr);
    return n && n < MAX_PATH ? fs::path(std::wstring(buffer, n)) : fs::path{};
}
Toolchain find_toolchain() {
    Toolchain tools;
    wchar_t base[MAX_PATH];
    const DWORD n = GetEnvironmentVariableW(L"ProgramFiles(x86)", base, MAX_PATH);
    const fs::path vswhere = n && n < MAX_PATH
        ? fs::path(std::wstring(base, n)) / L"Microsoft Visual Studio" / L"Installer" / L"vswhere.exe" : fs::path{};
    if (vswhere.empty() || !stamp(vswhere).exists) { tools.problem = "Visual Studio (vswhere.exe) not found"; return tools; }
    const auto found = run_capture(L"\"" + vswhere.wstring() + L"\" -latest -products * -requires "
        L"Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath -utf8", std::chrono::seconds(30));
    std::string install = found ? *found : "";
    while (!install.empty() && std::isspace(static_cast<unsigned char>(install.back()))) install.pop_back();
    if (const size_t line = install.find_first_of("\r\n"); line != std::string::npos) install.resize(line);
    if (install.empty()) { tools.problem = "no Visual Studio installation with the x64 C++ tools"; return tools; }
    const fs::path root = wide(install);
    tools.vcvars = root / L"VC" / L"Auxiliary" / L"Build" / L"vcvars64.bat";
    const fs::path bundled = root / L"Common7" / L"IDE" / L"CommonExtensions" / L"Microsoft" / L"CMake";
    tools.cmake = bundled / L"CMake" / L"bin" / L"cmake.exe";
    tools.ninja = bundled / L"Ninja" / L"ninja.exe";
    if (!stamp(tools.cmake).exists) tools.cmake = on_path(L"cmake.exe");
    if (!stamp(tools.ninja).exists) tools.ninja = on_path(L"ninja.exe");
    if (!stamp(tools.vcvars).exists) tools.problem = "vcvars64.bat not found in " + install;
    else if (tools.cmake.empty()) tools.problem = "cmake.exe not found (install Visual Studio's C++ CMake tools)";
    else if (tools.ninja.empty()) tools.problem = "ninja.exe not found (install Visual Studio's C++ CMake tools)";
    return tools;
}
const Toolchain& toolchain() {
    static const Toolchain tools = find_toolchain();
    return tools;
}
// COMPAT: a quoted argument ending in a backslash would escape its closing quote.
std::wstring argument(const fs::path& path) {
    std::wstring value = path.wstring();
    if (value.ends_with(L"\\")) value += L".";
    return value;
}

struct Fallback { std::vector<std::string> flags, sources; };  // fallback include flags and the files they serve
struct RootState {
    std::mutex mutex;
    Clock::time_point scanned{}, flags_time{};
    bool cached_ready = false, flags_ready = false, cmake_running = false;
    CompileSetup cached;
    Fallback fallback;
    std::string cmake_note;
    std::thread worker;
    HANDLE job = nullptr;  // the running configure, so shutdown can end it
    std::atomic_bool stopping{false};
};
struct Registry {
    std::mutex mutex;
    std::map<std::wstring, std::shared_ptr<RootState>> roots;
    ~Registry() {
        for (auto& [key, state] : roots) {
            (void)key;
            state->stopping = true;
            { std::lock_guard lock(state->mutex); if (state->job) TerminateJobObject(state->job, 1); }
            if (state->worker.joinable()) state->worker.join();
        }
    }
};
Registry& registry() {
    static Registry instance;
    return instance;
}

void configure(const std::shared_ptr<RootState>& state, const fs::path& root, const std::string& inputs) {
    const fs::path base = root / L".shgrep" / L"lsp-state" / L"cpp";
    const fs::path out = base / L"cmake";
    const Toolchain& tools = toolchain();
    std::string note;
    bool ok = false;
    std::error_code error;
    fs::create_directories(out, error);
    if (error) note = "cannot create " + utf8(out.wstring());
    else {
        SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
        Handle log(CreateFileW(extended(base / L"cmake.log").c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        // cmd /s strips the outer quotes and runs: "vcvars64.bat" >nul && "cmake.exe" -S ... -B ...
        const std::wstring command = L"\"" + (system_folder() / L"cmd.exe").wstring() + L"\" /d /s /c \"\"" +
            tools.vcvars.wstring() + L"\" >nul && \"" + tools.cmake.wstring() + L"\" -S \"" + argument(root) +
            L"\" -B \"" + argument(out) + L"\" -G Ninja \"-DCMAKE_MAKE_PROGRAM=" + tools.ninja.wstring() +
            L"\" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug\"";
        Handle process, job;
        if (!log.valid()) note = "cannot create cmake.log";
        else if (!launch(command, log.h, log.h, root, process, job, note)) {}
        else {
            { std::lock_guard lock(state->mutex); state->job = job.h; }
            const auto deadline = Clock::now() + kConfigureTimeout;
            while (WaitForSingleObject(process.h, 250) == WAIT_TIMEOUT) {
                if (state->stopping) break;
                if (Clock::now() >= deadline) { TerminateJobObject(job.h, 1); note = "CMake configure timed out"; break; }
            }
            { std::lock_guard lock(state->mutex); state->job = nullptr; }
            DWORD code = 1;
            GetExitCodeProcess(process.h, &code);
            ok = note.empty() && code == 0 && stamp(out / L"compile_commands.json").exists;
            if (!ok && note.empty()) note = "CMake configure failed; see .shgrep/lsp-state/cpp/cmake.log";
        }
    }
    if (state->stopping) return;
    // Remember the inputs either way: success marks the database current, failure is not retried until they change.
    try { write_text(base / (ok ? L"cmake.inputs" : L"cmake.failed"), inputs); } catch (...) {}
    std::lock_guard lock(state->mutex);
    state->cmake_running = false;
    state->cmake_note = ok ? "" : note;
    state->cached_ready = false;
}
void start_configure(const std::shared_ptr<RootState>& state, const fs::path& root, const std::string& inputs) {
    const Toolchain& tools = toolchain();
    if (!tools.problem.empty()) { state->cmake_note = "skipped: " + tools.problem; return; }
    if (state->worker.joinable()) state->worker.join();  // the previous run already cleared cmake_running
    state->cmake_running = true;
    state->cmake_note.clear();
    state->worker = std::thread([state, root, inputs] { configure(state, root, inputs); });
}

// .vcxproj reading: the Debug|x64 ClCompile settings and every ClCompile item. Property sheets and MSBuild
// functions are not evaluated; values that still hold macros are dropped.
size_t find_ci(std::string_view text, std::string_view needle, size_t from = 0) {
    if (needle.empty() || text.size() < needle.size()) return std::string_view::npos;
    for (size_t i = from; i + needle.size() <= text.size(); ++i) {
        size_t k = 0;
        while (k < needle.size() && std::tolower(static_cast<unsigned char>(text[i + k])) ==
                                    std::tolower(static_cast<unsigned char>(needle[k]))) ++k;
        if (k == needle.size()) return i;
    }
    return std::string_view::npos;
}
void replace_ci(std::string& text, std::string_view from, std::string_view to) {
    for (size_t at = find_ci(text, from); at != std::string::npos; at = find_ci(text, from, at + to.size()))
        text.replace(at, from.size(), to);
}
std::string attribute(std::string_view tag, std::string_view name) {
    const std::string key = std::string(name) + "=\"";
    size_t at = find_ci(tag, key);
    if (at == std::string_view::npos) return {};
    at += key.size();
    const size_t end = tag.find('"', at);
    return end == std::string_view::npos ? std::string{} : std::string(tag.substr(at, end - at));
}
std::string element(std::string_view block, std::string_view name) {
    const std::string open = "<" + std::string(name), close = "</" + std::string(name) + ">";
    for (size_t at = block.find(open); at != std::string_view::npos; at = block.find(open, at + open.size())) {
        const size_t after = at + open.size();
        if (after >= block.size() || (block[after] != '>' && block[after] != ' ')) continue;
        const size_t start = block.find('>', after);
        if (start == std::string_view::npos || block[start - 1] == '/') return {};
        const size_t end = block.find(close, start);
        return end == std::string_view::npos ? std::string{} : std::string(block.substr(start + 1, end - start - 1));
    }
    return {};
}
std::string unescape(std::string text) {
    static constexpr std::pair<const char*, const char*> entities[]{
        {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", "\""}, {"&apos;", "'"}, {"&amp;", "&"}};
    for (const auto& [from, to] : entities) replace_ci(text, from, to);
    return text;
}
std::vector<std::string> split(const std::string& text) {
    std::vector<std::string> parts;
    size_t start = 0;
    for (size_t at = 0; at <= text.size(); ++at) {
        if (at < text.size() && text[at] != ';') continue;
        std::string part = text.substr(start, at - start);
        const auto first = part.find_first_not_of(" \t\r\n"), last = part.find_last_not_of(" \t\r\n");
        if (first != std::string::npos) parts.push_back(part.substr(first, last - first + 1));
        start = at + 1;
    }
    return parts;
}
struct Project {
    std::string folder, root, name;
    std::optional<std::string> expand(std::string value) const {
        replace_ci(value, "$(ProjectDir)", folder + "\\");
        replace_ci(value, "$(MSBuildProjectDirectory)", folder);
        replace_ci(value, "$(MSBuildThisFileDirectory)", folder + "\\");
        replace_ci(value, "$(SolutionDir)", root + "\\");
        replace_ci(value, "$(Platform)", "x64");
        replace_ci(value, "$(Configuration)", "Debug");
        replace_ci(value, "$(ProjectName)", name);
        replace_ci(value, "$(TargetName)", name);
        if (value.empty() || value.find("$(") != std::string::npos || value.find("%(") != std::string::npos) return std::nullopt;
        return value;
    }
    std::string absolute(const std::string& value) const {
        fs::path path = wide(value);
        if (path.is_relative()) path = fs::path(wide(folder)) / path;
        return utf8(path.lexically_normal().wstring());
    }
};
std::string standard(const std::string& value) {
    static const std::map<std::string, std::string> flags{
        {"stdcpp14", "/std:c++14"}, {"stdcpp17", "/std:c++17"}, {"stdcpp20", "/std:c++20"},
        {"stdcpplatest", "/std:c++latest"}, {"stdc11", "/std:c11"}, {"stdc17", "/std:c17"}};
    const auto found = flags.find(lower_ascii(value));
    return found == flags.end() ? std::string{} : found->second;
}
void read_project(const fs::path& path, const fs::path& root, J::Array& entries, std::set<std::wstring>& seen) {
    std::string text = read_text(path, kProjectBytes);
    if (text.starts_with("\xEF\xBB\xBF")) text.erase(0, 3);
    if (text.empty()) return;
    const Project project{utf8(path.parent_path().wstring()), utf8(root.wstring()), utf8(path.stem().wstring())};
    std::string settings;
    int best = -1;
    for (size_t at = text.find("<ItemDefinitionGroup"); at != std::string::npos; at = text.find("<ItemDefinitionGroup", at + 1)) {
        const size_t open = text.find('>', at), close = text.find("</ItemDefinitionGroup>", at);
        if (open == std::string::npos || close == std::string::npos || close < open) break;
        const std::string condition = attribute(std::string_view(text).substr(at, open - at), "Condition");
        const int rank = condition.find("Debug|x64") != std::string::npos ? 3
                       : condition.find("|x64") != std::string::npos ? 2 : condition.empty() ? 1 : 0;
        if (rank > best) { best = rank; settings = element(std::string_view(text).substr(at, close - at + 22), "ClCompile"); }
    }
    std::vector<std::string> includes, defines;
    for (const auto& part : split(unescape(element(settings, "AdditionalIncludeDirectories"))))
        if (auto value = project.expand(part)) includes.push_back(project.absolute(*value));
    for (const auto& part : split(unescape(element(settings, "PreprocessorDefinitions"))))
        if (auto value = project.expand(part)) defines.push_back(*value);
    const std::string cpp_standard = standard(element(settings, "LanguageStandard"));
    const std::string c_standard = standard(element(settings, "LanguageStandard_C"));
    static const std::set<std::string> sources{".c", ".cc", ".cpp", ".cxx", ".c++"};
    const std::string marker = "<ClCompile Include=\"";
    for (size_t at = text.find(marker); at != std::string::npos; at = text.find(marker, at)) {
        at += marker.size();
        const size_t end = text.find('"', at);
        if (end == std::string::npos) break;
        const auto value = project.expand(unescape(text.substr(at, end - at)));
        at = end;
        if (!value || value->find_first_of("*?") != std::string::npos) continue;
        const std::string file = project.absolute(*value);
        const std::string extension = lower_ascii(utf8(fs::path(wide(file)).extension().wstring()));
        if (!sources.contains(extension) || !seen.insert(lower(wide(file))).second) continue;
        const bool c = extension == ".c";
        J::Array arguments{"cl.exe", "/nologo", "/EHsc", c ? "/TC" : "/TP"};
        const std::string& language = c ? c_standard : cpp_standard;
        if (!language.empty()) arguments.push_back(language);
        for (const auto& include : includes) arguments.push_back("/I" + include);
        for (const auto& define : defines) arguments.push_back("/D" + define);
        arguments.push_back("/c");
        arguments.push_back(file);
        entries.push_back(J::Object{{"directory", project.folder}, {"file", file}, {"arguments", std::move(arguments)}});
    }
}
fs::path project_database(const fs::path& base, const fs::path& root, const std::vector<fs::path>& projects) {
    const fs::path out = base / L"vcxproj", database = out / L"compile_commands.json";
    const std::string inputs = inputs_fingerprint(projects);
    if (stamp(database).exists && read_text(base / L"vcxproj.inputs") == inputs) return database;
    J::Array entries;
    std::set<std::wstring> seen;
    for (const auto& project : projects) read_project(project, root, entries, seen);
    if (entries.empty()) throw std::runtime_error("the .vcxproj files list no C/C++ sources");
    std::error_code error;
    fs::create_directories(out, error);
    if (error) throw std::runtime_error("cannot create " + utf8(out.wstring()));
    write_text(database, J(std::move(entries)).dump());
    write_text(base / L"vcxproj.inputs", inputs);
    return database;
}

// Last resort: every folder holding a header, plus its parents up to the root, so "x.h" and "dir/x.h" resolve.
// The sources are listed too, so clangd's background index covers the workspace without a real database.
Fallback scan_fallback(const fs::path& root, const SearchContext& context) {
    static const std::set<std::string> header_types{".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"};
    std::vector<std::string> files;
    try {
        files = source_paths(context, utf8(root.wstring()),
                             {".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp", ".c", ".cc", ".cpp", ".cxx", ".c++"},
                             Clock::now() + std::chrono::seconds(30), nullptr);
    } catch (const std::exception&) { return {}; }
    Fallback result;
    std::vector<std::string> headers;
    for (auto& file : files) {
        const std::string clean = utf8(plain(fs::path(wide(file))).wstring());
        if (header_types.contains(lower_ascii(utf8(fs::path(wide(clean)).extension().wstring())))) headers.push_back(clean);
        else result.sources.push_back(clean);
    }
    const std::wstring top = lower(root.lexically_normal().wstring());
    std::map<std::pair<size_t, std::wstring>, fs::path> folders;  // shallow folders first
    for (const auto& header : headers) {
        for (fs::path folder = fs::path(wide(header)).parent_path(); ; folder = folder.parent_path()) {
            const std::wstring key = lower(folder.lexically_normal().wstring());
            if (!key.starts_with(top)) break;
            const auto depth = static_cast<size_t>(std::count(key.begin() + static_cast<std::ptrdiff_t>(top.size()), key.end(), L'\\'));
            if (!folders.emplace(std::pair{depth, key}, folder).second || key.size() == top.size()) break;
        }
    }
    for (const auto& [key, folder] : folders) {
        (void)key;
        if (result.flags.size() == kFallbackIncludes) break;
        result.flags.push_back("-I" + utf8(folder.wstring()));
    }
    return result;
}
// Rewritten only when the source list or flags change; clangd picks up new files through didOpen meanwhile.
fs::path fallback_database(const fs::path& base, const fs::path& root, const Fallback& fallback) {
    uint64_t h = mix(kSeed, "fallback-v2");  // v2: C++ entries name a standard
    for (const auto& flag : fallback.flags) h = mix(h, flag);
    for (const auto& source : fallback.sources) h = mix(h, source);
    const fs::path out = base / L"fallback", database = out / L"compile_commands.json";
    if (stamp(database).exists && read_text(base / L"fallback.inputs") == hex(h)) return database;
    J::Array entries;
    for (const auto& source : fallback.sources) {
        const bool c = lower_ascii(utf8(fs::path(wide(source)).extension().wstring())) == ".c";
        J::Array arguments{c ? "clang" : "clang++"};
        // COMPAT: clang's default is C++17, which misparses newer code until the tree is lost (references then go
        //   missing); C++20 also parses code written for older standards.
        if (!c) arguments.push_back("-std=c++20");
        for (const auto& flag : fallback.flags) arguments.push_back(flag);
        arguments.push_back("-c");
        arguments.push_back(source);
        entries.push_back(J::Object{{"directory", utf8(root.wstring())}, {"file", source}, {"arguments", std::move(arguments)}});
    }
    std::error_code error;
    fs::create_directories(out, error);
    if (error) throw std::runtime_error("cannot create " + utf8(out.wstring()));
    write_text(database, J(std::move(entries)).dump());
    write_text(base / L"fallback.inputs", hex(h));
    return database;
}
} // namespace

CompileSetup cpp_compile_setup(const fs::path& workspace, const SearchContext& context, bool cmake_enabled) {
    const fs::path root = plain(workspace).lexically_normal();
    std::shared_ptr<RootState> state;
    {
        auto& roots = registry();
        std::lock_guard lock(roots.mutex);
        auto& slot = roots.roots[lower(root.wstring())];
        if (!slot) slot = std::make_shared<RootState>();
        state = slot;
    }
    std::lock_guard lock(state->mutex);
    const auto now = Clock::now();
    if (state->cached_ready && now - state->scanned < kRescan) return state->cached;
    Layout layout;
    size_t folders = 0;
    scan_folder(root, 0, false, layout, folders);
    std::sort(layout.cmake_inputs.begin(), layout.cmake_inputs.end());
    std::sort(layout.projects.begin(), layout.projects.end());
    const fs::path base = root / L".shgrep" / L"lsp-state" / L"cpp";
    J::Object status;
    std::string source, combined_identity;
    fs::path database;
    J::Object initialization;
    bool virtual_database = false;
    // 1. Preserve every independent project's commands instead of overriding the workspace with one build.
    if (layout.databases.size() == 1) { database = layout.databases.front(); source = "existing"; }
    else if (!layout.databases.empty()) {
        auto combined = combine_databases(root, layout.databases, context.read_only);
        combined_identity = combined.fingerprint;
        status["paths"] = std::move(combined.paths);
        status["duplicate_commands"] = combined.duplicates;
        status["conflict_policy"] = "workspace database first, then newest database per file";
        source = "existing (combined)";
        if (context.read_only) {
            virtual_database = true;
            database = layout.databases.front();
            status["files"] = static_cast<uint64_t>(combined.changes.size());
            initialization["compilationDatabaseChanges"] = std::move(combined.changes);
        } else {
            status["files"] = static_cast<uint64_t>(combined.entries.size());
            database = base / L"combined" / L"compile_commands.json";
            const std::string merged = J(std::move(combined.entries)).dump();
            write_workspace_metadata(context, database, merged);
        }
    }
    // 2. CMake configure in the background; until it finishes, an older result or the steps below are used.
    if (database.empty() && stamp(root / L"CMakeLists.txt").exists) {
        if (!cmake_enabled) status["cmake"] = "disabled by \"cmake_configure\": false in .shgrep/lsp.json";
        else if (context.read_only) status["cmake"] = "skipped: --read-only";
        else {
            const std::string inputs = inputs_fingerprint(layout.cmake_inputs);
            const fs::path generated = base / L"cmake" / L"compile_commands.json";
            const bool present = stamp(generated).exists;
            if (present && read_text(base / L"cmake.inputs") == inputs) { database = generated; source = "cmake"; }
            else {
                if (!state->cmake_running && read_text(base / L"cmake.failed") != inputs) start_configure(state, root, inputs);
                status["cmake"] = state->cmake_running ? "configuring in the background; log: .shgrep/lsp-state/cpp/cmake.log"
                                : state->cmake_note.empty() ? "failed for the current CMake files; see .shgrep/lsp-state/cpp/cmake.log"
                                : state->cmake_note;
                if (present) { database = generated; source = "cmake (outdated until the configure finishes)"; }
            }
        }
    }
    // 3. Visual Studio projects.
    if (database.empty() && !layout.projects.empty() && !context.read_only) {
        try { database = project_database(base, root, layout.projects); source = "vcxproj"; }
        catch (const std::exception& e) { status["vcxproj"] = e.what(); }
    }
    std::string identity;
    if (!database.empty()) {
        const Stamp s = stamp(database);
        if (!virtual_database) {
            initialization["compilationDatabasePath"] = utf8(database.parent_path().wstring());
            status["path"] = utf8(database.wstring());
        }
        identity = combined_identity.empty()
            ? source + "|" + utf8(lower(database.wstring())) + "|" + std::to_string(s.size) + ":" + std::to_string(s.time)
            : source + "|" + combined_identity;
    } else {
        // 4. Fallback include paths; recomputed at most once a minute because it walks every C/C++ file.
        source = "fallback";
        if (!state->flags_ready || now - state->flags_time >= kFallbackRescan) {
            state->fallback = scan_fallback(root, context);
            state->flags_ready = true;
            state->flags_time = now;
        }
        J::Array flags;
        identity = source;
        for (const auto& flag : state->fallback.flags) { flags.push_back(flag); identity += "|" + flag; }
        initialization["fallbackFlags"] = std::move(flags);
        if (!context.read_only && !state->fallback.sources.empty()) {
            try {
                const fs::path generated = fallback_database(base, root, state->fallback);
                initialization["compilationDatabasePath"] = utf8(generated.parent_path().wstring());
                status["path"] = utf8(generated.wstring());
            } catch (const std::exception& e) { status["fallback"] = e.what(); }
        }
        status["include_dirs"] = static_cast<int64_t>(state->fallback.flags.size());
    }
    status["source"] = source;
    state->cached = CompileSetup{hex(mix(kSeed, identity)), J(std::move(initialization)), J(std::move(status))};
    state->cached_ready = true;
    state->scanned = now;
    return state->cached;
}
}
