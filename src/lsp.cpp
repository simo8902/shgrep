#include "lsp.hpp"
#include "banner.hpp"
#include "compile_db.hpp"
#include "ignore.hpp"
#include "lsp_watch.hpp"
#include <windows.h>
#include <algorithm>
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
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <thread>
#include <utility>

namespace shgrep {
namespace {
using Clock = std::chrono::steady_clock;
namespace fs = std::filesystem;
using J = Json;
[[noreturn]] void fail(const std::string& s) { throw std::runtime_error(s); }
// A malformed answer from the language server, or no server for the request, as opposed to a caller mistake;
//   callers turn it into the failure banner.
[[noreturn]] void server_fail(const std::string& s) { throw LspFailure(s); }
std::string str(const J& j, const char* key, const std::string& fallback = "") {
    const J* p = j.get(key); return p ? p->string() : fallback;
}
bool flag(const J& j, const char* key, bool fallback = false) {
    const J* p = j.get(key); return p ? p->boolean() : fallback;
}
int64_t number(const J& j, const char* key, int64_t fallback) {
    const J* p = j.get(key); return p ? p->integer() : fallback;
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
        if (Clock::now() >= deadline) throw LspFailure("language server did not answer before timeout_ms");
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
    std::string language, key;
    std::vector<std::string> command, extensions, ignored_paths;
    J initialization = J::Object{}, settings = J::Object{};
    std::vector<fs::path> state_directories;  // created before the server starts
    bool bundled = false;
    // CONTRACT: the server indexes the whole workspace from disk itself. shgrep then opens only the files a request
    //   touches or that changed since the server read them, and cross-file requests wait for indexing to finish.
    //   Otherwise every matching file is opened, which servers without their own index need.
    bool indexes_workspace = false;
    J details;  // extra status, e.g. where clangd's compile flags came from
    // Variables set for the server on top of shgrep's own environment (OmniSharp's DOTNET_ROOT).
    std::vector<std::pair<std::wstring, std::wstring>> environment;
};
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
// CONTRACT: tools/fetch_lsp.py installs these servers into <shgrep.exe folder>\lsp; folders and executables match
//   its PINS. They serve every workspace with no configuration. .shgrep/lsp.json entries take over the extensions
//   they name, and "bundled": false there turns the shipped servers off. A server that was not installed is
//   skipped; missing_bundled names it so the text fallback for its files carries the failure banner.
struct BundledServer { const char* language; const char* name; const wchar_t* executable; std::vector<std::string> extensions; };
const std::vector<BundledServer>& bundled_servers() {
    static const std::vector<BundledServer> servers{
        {"lua", "LuaLS", L"lua\\bin\\lua-language-server.exe", {".lua"}},
        {"xml", "LemMinX", L"xml\\lemminx.exe", {".xml", ".xsd", ".xsl", ".xslt", ".svg"}},
        {"cpp", "clangd", L"clangd\\bin\\clangd.exe", {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"}},
        {"rust", "rust-analyzer", L"rust\\rust-analyzer.exe", {".rs"}},
        {"python", "ty", L"python\\ty.exe", {".py", ".pyi"}},
        {"csharp", "OmniSharp", L"csharp\\OmniSharp.exe", {".cs"}},
    };
    return servers;
}
const BundledServer& bundled_server(std::string_view language) {
    for (const auto& server : bundled_servers()) if (server.language == language) return server;
    throw std::logic_error("unknown bundled language server");
}
// COMPAT: OmniSharp 2 runs on .NET 10 (runtimeconfig: 10.0, LatestMajor) and loads projects through the SDK's
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
const fs::path& bundled_directory() {
    static const fs::path directory = [] {
        std::wstring buffer(MAX_PATH, L'\0');
        for (;;) {
            const DWORD n = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
            if (n == 0) return fs::path{};
            if (n < buffer.size()) { buffer.resize(n); break; }
            if (buffer.size() >= 32768) return fs::path{};
            buffer.resize(buffer.size() * 2);
        }
        return fs::path(buffer).parent_path() / L"lsp";
    }();
    return directory;
}
// CONTRACT: every report of a missing bundled server names where shgrep expects it and this command, which downloads
//   the pinned servers into the lsp folder beside this shgrep.exe (each deployed copy has its own).
std::string fetch_command() {
    const fs::path& base = bundled_directory();
    const std::string folder = base.empty() ? std::string("<folder of shgrep.exe>") : utf8(base.parent_path().wstring());
    std::string script = "<shgrep sources>\\tools\\fetch_lsp.py";
#ifdef SHGREP_SOURCE_DIR
    fs::path source = fs::path(SHGREP_SOURCE_DIR) / L"tools" / L"fetch_lsp.py";
    std::error_code error;
    if (fs::is_regular_file(source, error)) script = utf8(source.make_preferred().wstring());
#endif
    return "python \"" + script + "\" \"" + folder + "\"";
}
void add_bundled(std::vector<Config>& result, const fs::path& root, const std::set<std::string>& owned,
                 const SearchContext& context, bool cmake_configure) {
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
        config.command.push_back(utf8(executable.wstring()));
        config.command.insert(config.command.end(), arguments.begin(), arguments.end());
        config.extensions = std::move(extensions);
        config.settings = std::move(settings);
        config.initialization = std::move(initialization);
        config.state_directories = std::move(directories);
        config.bundled = true;
        config.indexes_workspace = true;
        config.details = std::move(details);
        // A new variant (clangd's compile database changed) is a new key, so the old server is retired.
        config.key = lower(utf8(root.wstring())) + ":bundled:" + server.language + ":" + variant;
        for (const auto& ext : config.extensions) config.key += ":" + ext;
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
        const CompileSetup setup = cpp_compile_setup(root, context, cmake_configure);
        add(bundled_server("cpp"),
            // --background-index keeps its shards beside the compile database; limits of 0 return every result.
            {"--log=" + clangd_log, "--header-insertion=never", "--background-index", "--limit-results=0", "--limit-references=0",
             "--rename-file-limit=0"},
            J::Object{}, setup.initialization, {}, setup.fingerprint,
            J::Object{{"compile_database", setup.status}});
    }
    // rust-analyzer loads Cargo projects through the user's cargo; without it only syntax-level features work.
    // The default workspace/symbol limit of 128 would cut symbol searches short.
    add(bundled_server("rust"), {}, J::Object{},
        J::Object{{"workspace", J::Object{{"symbol", J::Object{{"search", J::Object{{"limit", 1000000}}}}}}}});
    add(bundled_server("python"), {"server"});
    // SAFETY: package restore would write obj\ folders into the workspace and fetch packages from the network;
    //   without it, projects whose packages were never restored lack those references.
    if (const DotNet dotnet = find_dotnet(); dotnet.problem.empty()) {
        // A different dotnet is a new variant, so the server restarts on it; the status shows which one is used.
        const std::string dotnet_root = utf8(dotnet.root.wstring());
        add(bundled_server("csharp"), {"-lsp", "DotNet:enablePackageRestore=false"}, J::Object{}, J::Object{}, {},
            dotnet_root, J::Object{{"dotnet_root", dotnet_root}});
        if (!result.empty() && result.back().language == "csharp")
            result.back().environment.emplace_back(L"DOTNET_ROOT", dotnet.root.wstring());
    }
}
std::vector<Config> configs_from_disk(const fs::path& root, const SearchContext& context) {
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
        add_bundled(result, root, owned_extensions, context, true);
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
    if (flag(json, "bundled", true)) add_bundled(result, root, owned_extensions, context, flag(json, "cmake_configure", true));
    return result;
}
std::vector<Config> configs(const fs::path& root, const SearchContext& context) {
    try { return configs_from_disk(root, context); }
    catch (const LspFailure&) { throw; }
    catch (const std::exception& e) { throw LspFailure(std::string("language server configuration failed: ") + e.what()); }
}
std::optional<Config> configuration(const SourceText& source, const SearchContext& context) {
    const std::string ext = lower(utf8(source.path.extension().wstring()));
    for (auto& config : configs(source.root, context)) {
        if (std::find(config.extensions.begin(), config.extensions.end(), ext) != config.extensions.end()) return config;
    }
    return std::nullopt;
}
// Why a file that configuration() left without a server has none, when a bundled server would serve its type:
//   the server was not installed, or "bundled": false turned it off. Empty for types no bundled server knows.
std::string missing_bundled(const SourceText& source) {
    const std::string ext = lower(utf8(source.path.extension().wstring()));
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
    size_t i = 0;
    int64_t line = 0;
    while (i < text.size() && line < wanted.line) {
        if (text[i] == L'\r' || text[i] == L'\n') {
            if (text[i] == L'\r' && i + 1 < text.size() && text[i + 1] == L'\n') ++i;
            ++line;
        }
        ++i;
    }
    if (line != wanted.line) fail("LSP range is outside the current file");
    const size_t start = i;
    while (i < text.size() && text[i] != L'\r' && text[i] != L'\n') ++i;
    if (static_cast<uint64_t>(wanted.column) > i - start) fail("LSP column is outside the current line");
    const size_t result = start + static_cast<size_t>(wanted.column);
    if (result > 0 && result < text.size() && text[result - 1] >= 0xD800 && text[result - 1] <= 0xDBFF &&
        text[result] >= 0xDC00 && text[result] <= 0xDFFF) fail("LSP range splits a UTF-16 surrogate pair");
    return result;
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
    std::string base;
    for (size_t start = 0;;) {
        const bool gitignore = GetFileAttributesW((folder + L"\\.gitignore").c_str()) != INVALID_FILE_ATTRIBUTES;
        const bool dotignore = GetFileAttributesW((folder + L"\\.ignore").c_str()) != INVALID_FILE_ATTRIBUTES;
        if (gitignore || dotignore) {
            auto next = std::make_shared<IgnoreScope>();
            next->parent = scope;
            read_ignore_rules(folder, base, gitignore, dotignore, next->rules);
            if (!next->rules.empty()) scope = std::move(next);
        }
        const size_t slash = relative.find(L'\\', start);
        const std::wstring component = relative.substr(start, slash == std::wstring::npos ? std::wstring::npos : slash - start);
        if (component.empty() || component.front() == L'.') return true;
        const std::string child = base.empty() ? utf8(component) : base + "/" + utf8(component);
        if (ignored_path(scope.get(), child, slash != std::wstring::npos)) return true;
        if (slash == std::wstring::npos) return false;
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
class Session {
    // Every failure inside a session is the server's, not the caller's.
    [[noreturn]] static void fail(const std::string& s) { throw LspFailure(s); }
    Handle input_, output_, process_, job_;
    std::thread reader_, writer_;
    std::mutex writer_mutex_;
    std::timed_mutex sender_mutex_;
    mutable std::mutex registrations_mutex_;
    std::condition_variable writer_ready_;
    std::string outgoing_;
    bool writer_stopping_ = false, write_done_ = true, write_ok_ = true;
    mutable std::mutex messages_mutex_;
    std::condition_variable messages_ready_;
    std::deque<J> messages_;
    std::string reader_error_;
    std::map<std::wstring, J, PathLess> published_diagnostics_;
    std::map<std::string, std::pair<std::string, J>> registrations_;
    Clock::time_point initialized_at_{};  // when "initialized" was sent; late dynamic registrations settle after it
    int64_t next_id_ = 0;
    J capabilities_ = J::Object{};
    int sync_kind_ = 0;
    // rust-analyzer's experimental/serverStatus: answers before quiescence miss the not-yet-loaded project.
    bool announces_status_ = false, status_seen_ = false, quiescent_ = true;  // status_seen_/quiescent_: messages_mutex_
    // Work-done progress the server reports ($/progress), by token; messages_mutex_.
    struct Progress { std::string title; int64_t percentage = -1; };
    std::map<std::string, Progress> progress_;
    Clock::time_point last_activity_{};  // server start, progress or a newly opened document; messages_mutex_
    // indexes_workspace sessions: documents changed since the server indexed them stay open (pinned_); others
    // opened for a request are closed again once more than kRecentDocuments are open (recent_, oldest first).
    static constexpr size_t kRecentDocuments = 32;
    // PERF: changed files stay open, but past this many the server is restarted to reread the tree instead, so a
    //   bulk change (checkout, code generation) never leaves the workspace open in the server.
    static constexpr size_t kPinnedDocuments = 256;
    std::unique_ptr<DirectoryWatch> watch_;
    std::set<std::wstring, PathLess> pinned_;
    std::deque<std::wstring> recent_;
    struct Document { std::string hash, uri; int64_t version; Position end; };
    std::map<std::wstring, Document, PathLess> documents_;

    bool read_exact(char* data, size_t size) {
        while (size) {
            DWORD got = 0;
            const DWORD chunk = static_cast<DWORD>(std::min<size_t>(size, 1u << 20));
            if (!ReadFile(output_.h, data, chunk, &got, nullptr) || !got) return false;
            data += got; size -= got;
        }
        return true;
    }
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
                std::string payload(length, 0);
                if (!read_exact(payload.data(), payload.size())) fail("language server closed a partial response");
                J message = J::parse(payload);
                if (!message.get("id")) {
                    if (str(message, "method") == "$/progress") {
                        const J* params = message.get("params");
                        const J* value = params ? params->get("value") : nullptr;
                        const J* token = params ? params->get("token") : nullptr;
                        if (value && token && std::holds_alternative<J::Object>(value->value)) {
                            const J* percentage = value->get("percentage");
                            const int64_t percent = percentage && std::holds_alternative<int64_t>(percentage->value) ? percentage->integer() : -1;
                            const std::string kind = str(*value, "kind"), key = token->dump();
                            std::lock_guard lock(messages_mutex_);
                            if (kind == "begin") progress_[key] = Progress{str(*value, "title"), percent};
                            else if (kind == "report") { if (auto it = progress_.find(key); it != progress_.end() && percent >= 0) it->second.percentage = percent; }
                            else if (kind == "end") progress_.erase(key);
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
                            messages_ready_.notify_all();
                        }
                        continue;
                    }
                    if (str(message, "method") == "textDocument/publishDiagnostics") {
                        if (const J* params = message.get("params")) {
                            std::lock_guard lock(messages_mutex_);
                            if (params->get("diagnostics")) {
                                try { published_diagnostics_[from_uri(str(*params, "uri")).lexically_normal().make_preferred().wstring()] = *params; }
                                catch (const std::exception&) { continue; }
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
                    messages_.push_back(std::move(message));
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
        if (method == "workspace/configuration") {
            J::Array values;
            const J* params = request.get("params"), *items = params ? params->get("items") : nullptr;
            if (items) for (const auto& item : items->array()) values.push_back(setting(str(item, "section")));
            result = std::move(values);
        } else if (method == "workspace/workspaceFolders") {
            result = J::Array{J::Object{{"uri", uri(config.root)}, {"name", utf8(config.root.filename().wstring())}}};
        } else if (method == "workspace/applyEdit") {
            result = J::Object{{"applied", false}, {"failureReason", "unsolicited server edits require an explicit edit_file operation"}};
        } else if (method == "client/registerCapability" || method == "client/unregisterCapability") {
            std::lock_guard lock(registrations_mutex_);
            const J* params = request.get("params");
            const J* entries = params ? params->get(method == "client/registerCapability" ? "registrations" : "unregisterations") : nullptr;
            if (!entries && params) entries = params->get("unregistrations");
            if (entries) for (const auto& entry : entries->array()) {
                const std::string id = str(entry, "id");
                if (method == "client/registerCapability")
                    registrations_[id] = {str(entry, "method"), entry.get("registerOptions") ? *entry.get("registerOptions") : J(J::Object{})};
                else registrations_.erase(id);
            }
        } else if (method != "window/workDoneProgress/create" && !method.ends_with("/refresh")) {
            send(J::Object{{"jsonrpc", "2.0"}, {"id", *request.get("id")},
                 {"error", J::Object{{"code", -32601}, {"message", "unsupported client request"}}}}, control);
            return;
        }
        send(J::Object{{"jsonrpc", "2.0"}, {"id", *request.get("id")}, {"result", std::move(result)}}, control);
    }
public:
    Config config;
    std::timed_mutex mutex;
    explicit Session(Config value) : config(std::move(value)) {}
    ~Session() { stop(); }
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
        documents_.clear();
        std::lock_guard lock(messages_mutex_);
        messages_.clear(); reader_error_.clear(); published_diagnostics_.clear();
        status_seen_ = false; quiescent_ = true; announces_status_ = false; progress_.clear();
        watch_.reset(); pinned_.clear(); recent_.clear();
        { std::lock_guard registrations_lock(registrations_mutex_); registrations_.clear(); }
        capabilities_ = J::Object{};
    }
    J request(const std::string& method, J params, const Control& control) {
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
                    message = std::move(messages_.front()); messages_.pop_front();
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
                    if (number(*error, "code", -32603) == -32603) fail("language server " + method + ": " + error->dump());
                    throw std::runtime_error("language server declined " + method + ": " + str(*error, "message", error->dump()));
                }
                const J* result = message.get("result");
                if (!result) fail("invalid LSP response to " + method);
                return *result;
            }
        }
    }
    void notify(const std::string& method, J params, const Control& control) {
        send(J::Object{{"jsonrpc", "2.0"}, {"method", method}, {"params", std::move(params)}}, control);
    }
    void start(const Control& control) {
        if (process_.h) return;
        // The watch starts before the server reads the tree, so no change made meanwhile is missed.
        if (config.indexes_workspace) watch_ = std::make_unique<DirectoryWatch>(config.root);
        for (const auto& directory : config.state_directories) {
            std::error_code error;
            fs::create_directories(directory, error);
            if (error) fail("cannot create language server state folder " + utf8(directory.wstring()) + ": " + error.message());
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
        // config.environment overrides same-named variables (case-insensitive) of shgrep's own environment.
        std::wstring environment;
        if (!config.environment.empty()) {
            std::vector<std::wstring> entries;
            if (wchar_t* block = GetEnvironmentStringsW()) {
                for (const wchar_t* entry = block; *entry; entry += wcslen(entry) + 1) {
                    const std::wstring_view text(entry);
                    const size_t equals = text.find(L'=', 1);  // "=C:=C:\\dir" entries start with '='
                    const bool overridden = std::any_of(config.environment.begin(), config.environment.end(), [&](const auto& item) {
                        return equals == item.first.size() &&
                            CompareStringOrdinal(entry, static_cast<int>(equals), item.first.data(), static_cast<int>(item.first.size()), TRUE) == CSTR_EQUAL;
                    });
                    if (!overridden) entries.emplace_back(text);
                }
                FreeEnvironmentStringsW(block);
            }
            for (const auto& [name, value] : config.environment) entries.push_back(name + L"=" + value);
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
            environment.empty() ? nullptr : environment.data(), config.root.c_str(), &startup.StartupInfo, &process);
        const DWORD error = GetLastError();
        DeleteProcThreadAttributeList(attributes);
        if (!created) fail("cannot start LSP command (Windows error " + std::to_string(error) + ")");
        process_.reset(process.hProcess);
        Handle thread(process.hThread);
        if (!AssignProcessToJobObject(job_.h, process_.h)) {
            TerminateProcess(process_.h, 1); fail("cannot assign language server to its process job");
        }
        if (ResumeThread(thread.h) == static_cast<DWORD>(-1)) fail("cannot resume language server");
        child_input.reset(); child_output.reset(); child_error.reset();
        {
            std::lock_guard lock(writer_mutex_);
            writer_stopping_ = false; write_done_ = true; write_ok_ = true; outgoing_.clear();
        }
        reader_ = std::thread([this] { reader_loop(); });
        writer_ = std::thread([this] { writer_loop(); });
        J initialize = request("initialize", J::Object{
            {"processId", static_cast<int64_t>(GetCurrentProcessId())}, {"rootUri", uri(config.root)}, {"locale", "en"},
            {"clientInfo", J::Object{{"name", "shgrep"}, {"version", "0.3.0"}}},
            {"workspaceFolders", J::Array{J::Object{{"uri", uri(config.root)}, {"name", utf8(config.root.filename().wstring())}}}},
            {"initializationOptions", config.initialization},
            {"capabilities", J::Object{
                {"general", J::Object{{"positionEncodings", J::Array{"utf-16"}}}},
                {"workspace", J::Object{{"configuration", true}, {"workspaceFolders", true}, {"applyEdit", false},
                    {"workspaceEdit", J::Object{{"documentChanges", true}, {"failureHandling", "undo"}}},
                    {"fileOperations", J::Object{{"dynamicRegistration", true}, {"didCreate", true}, {"didRename", true}, {"willRename", true}}}}},
                {"textDocument", J::Object{
                    {"documentSymbol", J::Object{{"hierarchicalDocumentSymbolSupport", true}, {"dynamicRegistration", true}, {"symbolKind", J::Object{{"valueSet", J::Array{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26}}}}}},
                    {"definition", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
                    {"declaration", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
                    {"typeDefinition", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
                    {"implementation", J::Object{{"linkSupport", true}, {"dynamicRegistration", true}}},
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
        { std::lock_guard lock(messages_mutex_); last_activity_ = Clock::now(); }
    }
    void require(const char* capability) const {
        // COMPAT: OmniSharp registers every navigation feature dynamically a few milliseconds after "initialized", so a
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
            {"hoverProvider","textDocument/hover"}, {"renameProvider","textDocument/rename"},
            {"diagnosticProvider","textDocument/diagnostic"}};
        auto it = names.find(capability); return it == names.end() ? capability : it->second;
    }
    bool supports(const char* capability) const {
        const J* p = capabilities_.get(capability);
        if (p && (std::holds_alternative<J::Object>(p->value) || (std::holds_alternative<bool>(p->value) && p->boolean()))) return true;
        const std::string method = capability_method(capability);
        std::lock_guard lock(registrations_mutex_);
        for (const auto& [id, entry] : registrations_) { (void)id; if (entry.first == method) return true; }
        return false;
    }
    void drain(const Control& control) {
        for (;;) {
            J message;
            {
                std::lock_guard lock(messages_mutex_);
                if (messages_.empty()) return;
                message = std::move(messages_.front()); messages_.pop_front();
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
            std::lock_guard lock(registrations_mutex_);
            for (const auto& [id, entry] : registrations_) { (void)id;
                if (entry.first == "workspace/" + name + "Files") options.push_back(entry.second);
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
    J status() const {
        std::lock_guard lock(registrations_mutex_);
        J::Array dynamic;
        for (const auto& [id, entry] : registrations_) { (void)id; dynamic.push_back(entry.first); }
        J::Object result{{"language_id", config.language}, {"root", utf8(config.root.wstring())},
                         {"capabilities", capabilities_}, {"dynamic_methods", std::move(dynamic)},
                         {"open_documents", static_cast<int64_t>(documents_.size())}};
        if (std::holds_alternative<J::Object>(config.details.value))
            for (const auto& [key, value] : config.details.object()) result.emplace(key, value);
        if (config.indexes_workspace) {
            std::lock_guard progress_lock(messages_mutex_);
            const std::string busy = indexing_locked();
            result.emplace("indexing", busy.empty() ? std::string("complete") : busy);
        }
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
                auto found = published_diagnostics_.find(source.path.lexically_normal().make_preferred().wstring());
                if (found != published_diagnostics_.end()) {
                    const J* version = found->second.get("version");
                    if (!version || (std::holds_alternative<int64_t>(version->value) && version->integer() == document_version(source)))
                        return J::Object{{"items", *found->second.get("diagnostics")},
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
                published_diagnostics_.erase(source.path.lexically_normal().make_preferred().wstring());
                // Opening can start new server work (clangd loads the compile database on first open).
                if (config.indexes_workspace) last_activity_ = Clock::now();
            }
            notify("textDocument/didOpen", J::Object{{"textDocument", J::Object{
                {"uri", id}, {"languageId", config.language}, {"version", 1}, {"text", source.text}}}}, control);
            documents_.emplace(key, Document{source.sha256, id, 1, text_end(source.text)});
            return 1;
        }
        if (found->second.hash == source.sha256) return 0;
        {
            std::lock_guard lock(messages_mutex_);
            published_diagnostics_.erase(source.path.lexically_normal().make_preferred().wstring());
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
        if (config.indexes_workspace && watch_ && !watch_->failed()) { synchronize_changed(primary, context, control, save); return; }
        std::vector<std::string> paths = source_paths(context, utf8(config.root.wstring()), config.extensions, control.deadline, control.cancelled);
        paths.erase(std::remove_if(paths.begin(), paths.end(), [&](const auto& path) {
            return path_excluded(config, fs::path(wide(path)));
        }), paths.end());
        if (primary) paths.push_back(utf8(primary->path.wstring()));
        std::set<std::wstring, PathLess> seen;
        J::Array changes;
        for (const auto& path : paths) {
            control.check();
            SourceText source;
            try { source = read_source_text(context, path); }
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
            if (path_excluded(config, fs::path(it->first))) {
                notify("textDocument/didClose", J::Object{{"textDocument", J::Object{{"uri", it->second.uri}}}}, control);
                { std::lock_guard lock(messages_mutex_); published_diagnostics_.erase(it->first); }
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
            { std::lock_guard lock(messages_mutex_); published_diagnostics_.erase(it->first); }
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
        watch_->take(changed, reload);
        if (!reload) {
            const size_t relevant = static_cast<size_t>(std::count_if(changed.begin(), changed.end(), [&](const fs::path& path) {
                const std::string extension = lower(utf8(path.extension().wstring()));
                return std::find(config.extensions.begin(), config.extensions.end(), extension) != config.extensions.end();
            }));
            reload = pinned_.size() + relevant > kPinnedDocuments;
        }
        if (reload) {
            // SAFETY: some changes are unknown, so the server's index may be stale; a restart makes it reread the tree.
            stop();
            start(control);
            changed.clear();
            if (!watch_ || watch_->failed()) { synchronize(primary, context, control, save); return; }
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
            catch (const std::exception& e) { removed = std::string(e.what()).find(": not found") != std::string::npos; }
            return std::nullopt;
        };
        std::set<std::wstring, PathLess> seen;
        for (const auto& path : changed) {
            control.check();
            const std::string extension = lower(utf8(path.extension().wstring()));
            if (std::find(config.extensions.begin(), config.extensions.end(), extension) == config.extensions.end()) continue;
            const std::wstring key = path.lexically_normal().wstring();
            if (!seen.insert(key).second) continue;
            if (!documents_.contains(key) && (path_excluded(config, path) || walk_skips(config.root, path))) continue;
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
        { std::lock_guard lock(messages_mutex_); published_diagnostics_.erase(it->first); }
        documents_.erase(it);
    }
    // Opens (or updates) a file a request reads; in indexes_workspace sessions it is closed again by evict().
    void use(const SourceText& source, const Control& control) {
        sync_one(source, control);
        if (config.indexes_workspace) { touch(source.path.wstring()); evict(control); }
    }
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
    // CONTRACT: messages_mutex_ held. Empty once the server's index covers the workspace, else what it is doing.
    std::string indexing_locked() const {
        if (announces_status_) return status_seen_ && quiescent_ ? "" : "loading the project";
        for (const auto& [token, progress] : progress_) {
            (void)token;
            // Diagnostics and checks (cargo check, workspace diagnosis) do not change what the index knows.
            const std::string title = lower(progress.title);
            if (title.find("diagnos") != std::string::npos || title.find("check") != std::string::npos ||
                title.find("lint") != std::string::npos) continue;
            return (progress.title.empty() ? std::string("working") : progress.title) +
                   (progress.percentage >= 0 ? " " + std::to_string(progress.percentage) + "%" : "");
        }
        // Servers announce indexing a moment after starting or opening a file; quiet means settled.
        if (Clock::now() - last_activity_ < std::chrono::seconds(1)) return "starting";
        return {};
    }
    // CONTRACT: cross-file answers come from the server's index, so they wait until it covers the whole workspace.
    //   Near the deadline the request fails with a retry hint rather than returning partial results.
    void wait_indexed(const Control& control) {
        if (!config.indexes_workspace) return;
        const auto give_up = control.deadline - std::chrono::seconds(2);
        for (;;) {
            {
                std::unique_lock lock(messages_mutex_);
                if (!reader_error_.empty()) fail(reader_error_);
                const std::string busy = indexing_locked();
                if (busy.empty()) return;
                if (Clock::now() >= give_up)
                    fail("language server is still indexing the workspace (" + busy +
                         "); results would be incomplete, so retry shortly or pass a larger timeout_ms");
                messages_ready_.wait_for(lock, std::chrono::milliseconds(50));
            }
            control.check();
            drain(control);
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
};
std::mutex registry_mutex;
std::map<std::string, std::shared_ptr<Session>> registry;
std::shared_ptr<Session> session_for(const Config& config) {
    std::lock_guard lock(registry_mutex);
    auto it = registry.find(config.key);
    if (it != registry.end()) return it->second;
    // Retire superseded configuration for the same workspace/language once no query holds it.
    for (auto i = registry.begin(); i != registry.end();) {
        if (i->second.use_count() == 1 && i->second->config.root == config.root && i->second->config.language == config.language)
            i = registry.erase(i);
        else ++i;
    }
    auto session = std::make_shared<Session>(config);
    registry.emplace(config.key, session); return session;
}
// PERF: workspace-wide status, restart and directory moves start a bundled server only when it already runs or
//   the root holds a file it serves, so a Lua workspace never launches clangd.
bool worth_starting(const Config& config, const SearchContext& context, const Control& control) {
    if (!config.bundled) return true;
    { std::lock_guard lock(registry_mutex); if (registry.contains(config.key)) return true; }
    return !source_paths(context, utf8(config.root.wstring()), config.extensions, control.deadline, control.cancelled).empty();
}

struct Symbol {
    std::string name, name_path;
    int64_t kind;
    Range extent, selection;
    int depth;
    bool has_body;
};
std::string normalized_name(const J& item, const std::string& language) {
    std::string name = str(item, "name");
    // SolidLSP's Lua adapter normalizes qualified method/function names at each tree level.
    if (language == "lua" && (number(item, "kind", 0) == 6 || number(item, "kind", 0) == 12)) {
        size_t separator = name.rfind('.');
        if (separator == std::string::npos) separator = name.rfind(':');
        if (separator != std::string::npos) name.erase(0, separator + 1);
    }
    return name;
}
void flatten(const J& items, const std::string& parent, int depth, std::vector<Symbol>& result, const std::string& language) {
    if (std::holds_alternative<std::nullptr_t>(items.value)) return;
    // SolidLSP ls.py: sibling overloads receive stable, zero-based indices.
    std::map<std::string, size_t> totals, indices;
    for (const auto& item : items.array()) ++totals[str(item, "containerName") + "\n" + normalized_name(item, language)];
    for (const auto& item : items.array()) {
        const std::string name = normalized_name(item, language);
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
        const std::string prefix = hierarchical ? parent : str(item, "containerName");
        Symbol symbol{name, prefix.empty() ? component : prefix + "/" + component,
                      number(item, "kind", 0), range(*extent),
                      range(selection ? *selection : *extent), depth, hierarchical};
        if (symbol.selection.start < symbol.extent.start || symbol.extent.end < symbol.selection.end)
            server_fail("language server returned a selection outside its symbol range");
        result.push_back(symbol);
        if (const J* children = item.get("children")) flatten(*children, symbol.name_path, depth + 1, result, language);
    }
}
std::vector<Symbol> symbols(Session& session, const SourceText& source, const Control& control) {
    session.require("documentSymbolProvider");
    const J raw = session.request("textDocument/documentSymbol",
        J::Object{{"textDocument", J::Object{{"uri", session.document_uri(source)}}}}, control);
    std::vector<Symbol> result; flatten(raw, "", 0, result, session.config.language); return result;
}
bool matches(const Symbol& symbol, std::string pattern, bool substring) {
    if (pattern.empty()) return true;
    const bool anchored = pattern.starts_with("/");
    if (anchored) pattern.erase(0, 1);
    while (pattern.ends_with("/")) pattern.pop_back();
    auto split = [](const std::string& value) {
        std::vector<std::string> parts; size_t start = 0;
        for (;;) {
            const size_t end = value.find('/', start);
            parts.push_back(value.substr(start, end - start));
            if (end == std::string::npos) break;
            start = end + 1;
        }
        return parts;
    };
    const auto wanted = split(pattern), actual = split(symbol.name_path);
    if (wanted.size() > actual.size() || (anchored && wanted.size() != actual.size())) return false;
    auto indexed = [](const std::string& name) {
        const size_t bracket = name.rfind('[');
        return bracket != std::string::npos && name.ends_with("]") && bracket + 2 < name.size() &&
            name.find_first_not_of("0123456789", bracket + 1) == name.size() - 1;
    };
    for (size_t i = 0; i < wanted.size(); ++i) {
        std::string name = actual[actual.size() - wanted.size() + i];
        const std::string& part = wanted[i];
        if (!indexed(part) && indexed(name)) name.erase(name.rfind('['));
        if (substring && i + 1 == wanted.size()) {
            if (name.find(part) == std::string::npos) return false;
        } else if (name != part) return false;
    }
    return true;
}
std::string shown_path(const SourceText& source) {
    return utf8(source.path.lexically_relative(source.root).generic_wstring());
}
J coordinates(Range r) {
    return J::Object{{"start_line", r.start.line + 1}, {"start_column", r.start.column + 1},
                     {"end_line", r.end.line + 1}, {"end_column", r.end.column + 1}};
}
J symbol_json(const Symbol& symbol, const SourceText& source, bool include_body) {
    J::Object out{{"path", shown_path(source)}, {"name", symbol.name}, {"name_path", symbol.name_path}, {"kind", symbol.kind},
                   {"line", symbol.selection.start.line + 1}, {"column", symbol.selection.start.column + 1},
                   {"range", coordinates(symbol.extent)}, {"selection_range", coordinates(symbol.selection)}, {"body_available", symbol.has_body}};
    if (include_body) {
        if (!symbol.has_body) server_fail("language server returned flat SymbolInformation without a reliable symbol-body range");
        out.emplace("body", body(source, symbol.extent));
    }
    return out;
}
const Symbol& unique(const std::vector<Symbol>& symbols, const std::string& name) {
    const Symbol* exact = nullptr;
    const std::string anchored = name.starts_with("/") ? name.substr(1) : name;
    size_t exact_count = 0;
    for (const auto& symbol : symbols) if (symbol.name_path == anchored) { exact = &symbol; ++exact_count; }
    if (exact_count == 1) return *exact;
    const Symbol* found = nullptr;
    for (const auto& symbol : symbols) if (matches(symbol, name, false)) {
        if (found) fail("ambiguous symbol name_path; use its full path or a line/column position");
        found = &symbol;
    }
    if (!found) fail("no symbol matches " + name);
    return *found;
}
J query_file(const std::string& operation, const J& args, const SourceText& original,
             const Config& config, const SearchContext& context, const Control& control,
             std::set<std::string>& synchronized) {
    auto session = session_for(config);
    std::unique_lock<std::timed_mutex> lock(session->mutex, std::defer_lock);
    while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
    try {
        session->start(control);
        if (synchronized.insert(config.key).second) session->synchronize(&original, context, control);
        else session->use(original, control);
        session->service_pending(control);
        const SourceText source = read_source_text(context, utf8(original.path.wstring()));
        session->assert_current(source);
        const std::string pattern = str(args, "name_path", str(args, "pattern"));
        J::Array results;
        int64_t outside = 0, stale = 0, ignored = 0, owners_omitted = 0;
        if (operation == "status" || operation == "restart") {
            if (operation == "restart") { session->stop(); session->start(control); session->synchronize(&source, context, control); }
            return session->status();
        }
        if (operation == "diagnostics") {
            J::Object report = session->diagnostics(source, control).object();
            std::optional<Range> within;
            if (!pattern.empty()) within = unique(symbols(*session, source, control), pattern).extent;
            const int64_t severity = number(args, "severity", 4);
            if (severity < 1 || severity > 4) fail("severity must be 1-4");
            J::Array items;
            for (const auto& item : report.at("items").array()) {
                const J* extent = item.get("range"); if (!extent) fail("diagnostic has no range");
                const Range r = range(*extent);
                if (number(item, "severity", 1) > severity) continue;
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
                items.push_back(std::move(normalized));
            }
            report["items"] = std::move(items);
            if (read_source_text(context, utf8(source.path.wstring())).sha256 != source.sha256) fail("file changed during diagnostics; retry");
            report.emplace("path", shown_path(source)); report.emplace("sha256", source.sha256);
            report.emplace("coordinate_base", 1); report.emplace("position_encoding", "utf-16");
            return report;
        }
        if (operation == "symbols" || operation == "overview") {
            const auto found = symbols(*session, source, control);
            const int64_t depth = number(args, "depth", operation == "overview" ? -1 : 0);
            if (depth < -1) fail("depth must be -1 or greater");
            if (flag(args, "require_unique")) {
                results.push_back(symbol_json(unique(found, pattern), source, flag(args, "include_body")));
            } else {
                std::vector<std::string> patterns{pattern};
                if (const J* list = args.get("patterns")) {
                    patterns.clear();
                    for (const auto& item : list->array()) patterns.push_back(item.string());
                    if (patterns.empty()) fail("patterns must not be empty");
                }
                auto kinds_match = [&](const Symbol& symbol) {
                    bool include = true;
                    for (const char* key : {"include_kinds", "exclude_kinds"}) if (const J* values = args.get(key)) {
                        bool present = false;
                        for (const auto& value : values->array()) {
                            if (value.integer() < 1 || value.integer() > 26) fail("symbol kinds must be 1-26");
                            present |= value.integer() == symbol.kind;
                        }
                        if (std::string(key) == "include_kinds" && !values->array().empty()) include &= present;
                        if (std::string(key) == "exclude_kinds") include &= !present;
                    }
                    return include;
                };
                std::set<std::string> emitted;
                for (const auto& symbol : found) {
                    if (operation == "overview" && depth >= 0 && symbol.depth > depth) continue;
                    bool matched = false;
                    for (const auto& p : patterns) matched |= matches(symbol, p, flag(args, "substring_matching"));
                    if (!matched || !kinds_match(symbol)) continue;
                    auto emit = [&](const Symbol& item, bool primary) {
                        if (!emitted.insert(item.name_path).second) return;
                        J::Object result = symbol_json(item, source, primary && flag(args, "include_body")).object();
                        if (primary && flag(args, "include_info") && !flag(args, "include_body")) {
                            session->require("hoverProvider");
                            const J info = session->request("textDocument/hover", J::Object{
                                {"textDocument", J::Object{{"uri", session->document_uri(source)}}}, {"position", item.selection.start.json()}}, control);
                            result.emplace("info", info);
                        }
                        results.push_back(std::move(result));
                    };
                    emit(symbol, true);
                    if (operation == "symbols" && !flag(args, "include_body") && depth != 0)
                        for (const auto& child : found)
                            if (child.name_path.starts_with(symbol.name_path + "/") && kinds_match(child) &&
                                (depth < 0 || child.depth <= symbol.depth + depth)) emit(child, false);
                }
            }
        } else {
            Position at;
            if (!pattern.empty()) {
                const auto found = symbols(*session, source, control);
                at = unique(found, pattern).selection.start;
            } else {
                const int64_t line = number(args, "line", 0), column = number(args, "column", 0);
                if (line < 1 || column < 1 || line > INT32_MAX || column > INT32_MAX)
                    fail("navigation needs name_path or 1-based line and column (1-2147483647)");
                at = {line - 1, column - 1};
                offset(wide(source.text), at);
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
            if (method == operations.end()) fail("unknown LSP navigation operation");
            session->require(method->second.first);
            if (operation != "hover") session->wait_indexed(control);
            // Index answers for unopened files are checked against current bytes: each reference must still spell it.
            const std::string expected = references ? identifier_at(source.text, at) : std::string{};
            J::Object params{{"textDocument", J::Object{{"uri", session->document_uri(source)}}}, {"position", at.json()}};
            if (references) params.emplace("context", J::Object{{"includeDeclaration", flag(args, "include_declaration")}});
            J raw = session->request(method->second.second, std::move(params), control);
            if (operation == "hover") {
                if (read_source_text(context, utf8(source.path.wstring())).sha256 != source.sha256) fail("file changed during hover; retry");
                return J::Object{{"path", shown_path(source)}, {"sha256", source.sha256}, {"hover", raw}, {"backend", "lsp"}};
            }
            J::Array locations;
            if (std::holds_alternative<J::Array>(raw.value)) locations = raw.array();
            else if (!std::holds_alternative<std::nullptr_t>(raw.value)) locations.push_back(raw);
            std::map<std::wstring, std::set<std::string>, PathLess> dedup;
            std::map<std::wstring, std::vector<Symbol>, PathLess> owners;
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
                const auto target_config = configuration(target, context);
                if (target_config && path_excluded(*target_config, target.path)) { ++ignored; continue; }
                const bool same_server = target_config && target_config->key == config.key;
                bool from_index = false;
                if (same_server && !session->has_document(target)) {
                    // A server without its own index only knows open documents; anything else is a leftover.
                    if (!config.indexes_workspace || session->is_open(target)) { ++ignored; continue; }
                    from_index = true;
                }
                if (same_server && !from_index) session->assert_current(target);
                offset(wide(target.text), found.start);
                offset(wide(target.text), found.end);
                if (from_index && !expected.empty() && body(target, Range{found.start, found.end}) != expected) { ++stale; continue; }
                J::Object result{{"path", shown_path(target)}, {"line", found.start.line + 1},
                                  {"column", found.start.column + 1}, {"range", coordinates(found)}};
                if (references) result.emplace("reference_name", body(target, Range{found.start, found.end}));
                const bool owner_known = owners.contains(target.path.wstring());
                if (from_index && !owner_known && session->supports("documentSymbolProvider")) {
                    // Enclosing symbols need the document open; a bounded number per request keeps parsing cheap.
                    if (opened_for_owners < kOwnerFiles) { session->use(target, control); ++opened_for_owners; }
                    else ++owners_omitted;
                }
                if (session->supports("documentSymbolProvider") && same_server && (owner_known || session->is_open(target))) {
                    auto owner = owners.find(target.path.wstring());
                    if (owner == owners.end()) owner = owners.emplace(target.path.wstring(), symbols(*session, target, control)).first;
                    const Symbol* enclosing = nullptr;
                    auto container_kind = [](int64_t kind) {
                        return kind == 1 || kind == 2 || kind == 3 || kind == 4 || kind == 5 || kind == 6 ||
                               kind == 9 || kind == 10 || kind == 11 || kind == 12 || kind == 19 || kind == 23;
                    };
                    for (const auto& symbol : owner->second) {
                        const bool variable = symbol.kind == 13 || symbol.kind == 14;
                        const bool multiline_container = container_kind(symbol.kind) &&
                            symbol.extent.start.line != symbol.extent.end.line;
                        if (!(variable || multiline_container) ||
                            symbol.extent.start > found.start || found.end > symbol.extent.end) continue;
                        if (!enclosing || enclosing->extent.start < symbol.extent.start ||
                            (enclosing->extent.start == symbol.extent.start && enclosing->depth < symbol.depth))
                            enclosing = &symbol;
                    }
                    if (enclosing) {
                        result.emplace("symbol", enclosing->name_path);
                        if (flag(args, "include_body") && enclosing->has_body) result.emplace("body", body(target, enclosing->extent));
                    }
                }
                results.push_back(std::move(result));
                if (read_source_text(context, utf8(target.path.wstring())).sha256 != target.sha256)
                    fail("navigation target changed during the request; retry");
            }
        }
        if (read_source_text(context, utf8(source.path.wstring())).sha256 != source.sha256)
            fail("source changed during LSP navigation; retry");
        J::Object response{{"path", shown_path(source)}, {"sha256", source.sha256}, {"mtime", source.mtime}, {"results", std::move(results)},
                           {"outside_roots", outside}, {"stale_locations", stale}, {"ignored_locations", ignored}, {"backend", "lsp"}};
        if (owners_omitted) response.emplace("symbols_omitted", owners_omitted);  // enclosing symbol left out for these
        return response;
    } catch (...) {
        session->stop();
        throw;
    }
}
// Last name-path components a symbol search looks for, without overload index; empty when any symbol may match.
std::vector<std::string> symbol_names(const J& args) {
    std::vector<std::string> names;
    if (const J* list = args.get("patterns")) for (const auto& item : list->array()) names.push_back(item.string());
    else names.push_back(str(args, "name_path", str(args, "pattern")));
    for (auto& name : names) {
        if (const size_t slash = name.rfind('/'); slash != std::string::npos) name = name.substr(slash + 1);
        if (const size_t bracket = name.find('['); bracket != std::string::npos) name.resize(bracket);
        // C++ qualifies out-of-line definitions (Foo::bar); the declaration in the class says only bar.
        if (const size_t colons = name.rfind("::"); colons != std::string::npos) name = name.substr(colons + 2);
        if (name.empty()) return {};
    }
    return names;
}
bool contains_folded(std::string_view text, std::string_view needle) {
    if (needle.empty()) return true;
    const auto fold = [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); };
    return std::search(text.begin(), text.end(), needle.begin(), needle.end(),
                       [&](char a, char b) { return fold(a) == fold(b); }) != text.end();
}
} // namespace

std::string lsp_failure_banner(const std::string& detail, const std::string& fallback) {
    return failure_banner("LSP FAILURE", detail, fallback);
}

std::shared_timed_mutex& workspace_operation_mutex() {
    static std::shared_timed_mutex mutex;
    return mutex;
}

bool lsp_configured(const SourceText& source, const SearchContext& context) {
    return configuration(source, context).has_value();
}

std::string lsp_missing(const SourceText& source, const SearchContext& context) {
    return configuration(source, context) ? std::string() : missing_bundled(source);
}

std::vector<std::string> lsp_health() {
    std::vector<std::string> problems;
    std::string missing;
    const fs::path& base = bundled_directory();
    for (const auto& server : bundled_servers()) {
        std::error_code error;
        if (base.empty() || !fs::is_regular_file(base / server.executable, error))
            missing += (missing.empty() ? "" : ", ") + std::string(server.name) + " (" + server.language + ") at " +
                       (base.empty() ? std::string("lsp\\ beside shgrep.exe") : utf8((base / server.executable).wstring()));
        else if (const std::string problem = bundled_prerequisite(server.language); !problem.empty())
            problems.push_back(std::string("the bundled ") + server.name + " (" + server.language + ") " + problem);
    }
    if (!missing.empty())
        problems.insert(problems.begin(), "bundled language servers are missing, so their files fall back to text: shgrep "
                        "expects " + missing + ". Download them there with: " + fetch_command());
    return problems;
}

Json lsp_query(const std::string& operation, const Json& arguments, const SearchContext& context,
               const std::shared_ptr<std::atomic_bool>& cancelled) {
    const int64_t timeout = number(arguments, "timeout_ms", 30000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout)), cancelled};
    std::set<std::string> synchronized;
    const bool symbol_query = operation == "symbols" || operation == "overview";
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
    const std::string path = str(arguments, "path");
    std::optional<SourceText> scope;
    if (!path.empty()) {
        bool directory = false;
        scope = source_descriptor(context, path, &directory);
        if (!directory && operation == "files") {
            const auto config = configuration(*scope, context);
            J::Array files;
            if (config) files.push_back(J::Object{{"path", shown_path(*scope)}, {"root", utf8(scope->root.wstring())}, {"language_id", config->language}});
            return J::Object{{"results", std::move(files)}, {"backend", "lsp"}};
        }
        if (!directory) {
            const SourceText source = read_source_text(context, path);
            const auto config = configuration(source, context);
            if (!config) {
                const std::string missing = missing_bundled(source);
                server_fail(missing.empty() ? "no language server for this file type (add one to .shgrep/lsp.json); use operation: text"
                                            : missing + "; use operation: text");
            }
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
    J::Array results;
    std::set<std::wstring, PathLess> scanned;
    bool any_server = false;
    for (const auto& root : context.allowed_roots) {
        const fs::path absolute = fs::absolute(root).lexically_normal();
        if (scope && !below(scope->path, absolute) && !below(absolute, scope->path) &&
            PathLess{}(scope->path.wstring(), absolute.wstring()) != PathLess{}(absolute.wstring(), scope->path.wstring())) continue;
        const auto configured = configs(absolute, context);
        if (operation == "status" || operation == "restart") {
            for (const auto& config : configured) {
                if (!worth_starting(config, context, control)) continue;
                auto session = session_for(config);
                std::unique_lock<std::timed_mutex> lock(session->mutex, std::defer_lock);
                while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
                try {
                    if (operation == "restart") session->stop();
                    session->start(control);
                    session->synchronize(nullptr, context, control);
                    session->service_pending(control);
                    results.push_back(session->status());
                    synchronized.insert(config.key);
                } catch (...) { session->stop(); throw; }
            }
            continue;
        }
        std::vector<std::string> extensions;
        for (const auto& config : configured)
            extensions.insert(extensions.end(), config.extensions.begin(), config.extensions.end());
        if (extensions.empty()) continue;
        any_server = true;
        const auto paths = source_paths(context, utf8(absolute.wstring()), extensions, control.deadline, cancelled);
        // PERF: a workspace-wide symbol search opens a file in an indexing server only when one of the names occurs in
        //   its text (ASCII case folded); a symbol's name always appears where it is declared or defined, so this
        //   drops nothing, unlike workspace/symbol, which names one location per symbol and may cap its results.
        const std::vector<std::string> names = operation == "symbols" ? symbol_names(arguments) : std::vector<std::string>{};
        for (const auto& file : paths) {
            control.check();
            SourceText source;
            try { source = operation == "files" ? source_descriptor(context, file) : read_source_text(context, file); }
            catch (const std::exception& e) {
                // Same rule as Session::synchronize: legacy-encoded files stay out of LSP results.
                if (std::string(e.what()).ends_with(" is not valid Unicode source text")) continue;
                throw;
            }
            if (scope && !below(source.path, scope->path) &&
                (PathLess{}(source.path.wstring(), scope->path.wstring()) || PathLess{}(scope->path.wstring(), source.path.wstring()))) continue;
            if (!scanned.insert(source.path.wstring()).second) continue;
            const auto config = configuration(source, context);
            if (!config || path_excluded(*config, source.path)) continue;
            if (operation == "files") {
                results.push_back(J::Object{{"path", shown_path(source)}, {"root", utf8(source.root.wstring())}, {"language_id", config->language}});
                continue;
            }
            if (config->indexes_workspace && !names.empty() &&
                std::none_of(names.begin(), names.end(), [&](const std::string& name) { return contains_folded(source.text, name); })) {
                synchronized.insert(config->key);  // a search with no hits is an empty result, not "no source files"
                continue;
            }
            J::Object per_file = arguments.object();
            per_file["path"] = file;
            const J response = query_file(operation, per_file, source, *config, context, control, synchronized);
            for (const auto& symbol : response.get("results")->array()) {
                J::Object item = symbol.object();
                item.emplace("root", utf8(absolute.wstring()));
                results.push_back(std::move(item));
            }
        }
    }
    // A scoped folder may hold no source files, but with no server at all an empty answer would hide the gap.
    if (operation != "files" && synchronized.empty() && (!scope || !any_server)) server_fail("no LSP source files found; install the bundled servers with tools/fetch_lsp.py, add one to .shgrep/lsp.json, or use operation: text");
    return J::Object{{"results", std::move(results)}, {"backend", "lsp"}};
}

namespace {
std::unique_lock<std::timed_mutex> acquire(Session& session, const Control& control) {
    std::unique_lock<std::timed_mutex> lock(session.mutex, std::defer_lock);
    while (!lock.try_lock_for(std::chrono::milliseconds(10))) control.check();
    return lock;
}
std::string newlines(const std::string& text, const std::string& reference) {
    const bool crlf = reference.find("\r\n") != std::string::npos;
    std::string out;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\r' || text[i] == '\n') {
            if (text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n') ++i;
            out += crlf ? "\r\n" : "\n";
        } else out.push_back(text[i]);
    }
    return out;
}
// CONTRACT: a language server renames only what it understands: one language, never strings, comments, FFI
//   declarations or build files. The old name is looked up as a whole word in the workspace's other text files,
//   and the ones the rename leaves alone are listed so a cross-language use (a Rust extern for a C function) is not
//   missed. Best effort: it stops at the request's deadline and says so.
std::string rename_leftovers(const std::string& old_name, const std::vector<SourceChange>& changes, const fs::path& root,
                             const SearchContext& context, const Control& control) {
    if (old_name.empty()) return {};
    static const std::vector<std::string> kinds{
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp", ".rs", ".py", ".pyi", ".lua", ".xml",
        ".json", ".toml", ".yaml", ".yml", ".js", ".ts", ".cs", ".go", ".java", ".kt", ".swift", ".m", ".mm", ".def",
        ".idl", ".cmake", ".txt", ".md", ".bat", ".ps1", ".sh"};
    std::set<std::wstring, PathLess> changed;
    for (const auto& change : changes) changed.insert(change.before.path.wstring());
    const auto word = [](unsigned char c) { return std::isalnum(c) || c == '_' || c >= 0x80; };
    // Vendored code and comments mention common words ("helper") all the time; neither is a use the rename missed.
    static const std::set<std::string> vendored{"libs", "third_party", "thirdparty", "3rdparty", "vendor",
                                                "external", "extern", "deps", "node_modules", "target"};
    const auto vendored_path = [&](const SourceText& text) {
        const std::string shown = lower(shown_path(text));
        size_t start = 0;
        for (size_t slash = shown.find_first_of("/\\"); slash != std::string::npos; slash = shown.find_first_of("/\\", start)) {
            if (vendored.contains(shown.substr(start, slash - start))) return true;
            start = slash + 1;
        }
        return false;
    };
    const auto in_comment = [](std::string_view before, const std::string& extension) {
        const size_t first = before.find_first_not_of(" \t");
        const std::string_view lead = first == std::string_view::npos ? std::string_view{} : before.substr(first);
        const bool hash_comments = extension == ".py" || extension == ".pyi" || extension == ".toml" || extension == ".yaml" ||
                                   extension == ".yml" || extension == ".sh" || extension == ".ps1" || extension == ".cmake";
        return before.find("//") != std::string_view::npos || before.find("/*") != std::string_view::npos ||
               lead.starts_with("* ") || lead == "*" || lead.starts_with("--") || lead.starts_with("<!--") ||
               (hash_comments && before.find('#') != std::string_view::npos);
    };
    std::vector<std::string> hits;
    size_t files = 0, total = 0;
    bool partial = false;
    try {
        for (const auto& path : source_paths(context, utf8(root.wstring()), kinds, control.deadline, control.cancelled)) {
            if (Clock::now() >= control.deadline) { partial = true; break; }
            SourceText text;
            try { text = read_source_text(context, path); }
            catch (const std::exception&) { continue; }  // legacy-encoded or too large: not searched
            if (changed.contains(text.path.wstring()) || vendored_path(text)) continue;
            const std::string extension = lower(utf8(text.path.extension().wstring()));
            bool counted = false;
            uint64_t line = 1;
            size_t line_start = 0, scanned = 0;
            for (size_t at = text.text.find(old_name); at != std::string::npos; at = text.text.find(old_name, at + 1)) {
                const size_t end = at + old_name.size();
                if ((at > 0 && word(static_cast<unsigned char>(text.text[at - 1]))) ||
                    (end < text.text.size() && word(static_cast<unsigned char>(text.text[end])))) continue;
                for (; scanned < at; ++scanned) if (text.text[scanned] == '\n') { ++line; line_start = scanned + 1; }
                if (in_comment(std::string_view(text.text).substr(line_start, at - line_start), extension)) continue;
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
                      " in " + std::to_string(files) + " file" + (files == 1 ? "" : "s") + " the rename does not change (other "
                      "languages, FFI, strings, build files; comments and vendored folders skipped); check them by hand" +
                      (partial ? "; the search stopped at the deadline, so there may be more" : "") + "]\n";
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
                                           const std::string& old_name = {}) {
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
        for (const auto& item : entry.edits) {
            const J* extent = item.get("range"), *replacement = item.get("newText");
            if (!extent || !replacement) server_fail("invalid LSP TextEdit");
            const Range r = range(*extent);
            if (entry.from_index && !old_name.empty() &&
                text.substr(offset(text, r.start), offset(text, r.end) - offset(text, r.start)) != wide(old_name))
                fail("the language server's index is out of date for " + utf8(entry.source.path.wstring()) +
                     "; nothing written, retry once it has caught up");
            replacements.push_back({offset(text, r.start), offset(text, r.end), replacements.size(),
                                    wide(newlines(replacement->string(), entry.source.text))});
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

Json lsp_edit(const Json& arguments, const SearchContext& context,
              const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (context.read_only) fail("edit_file is disabled: --read-only");
    const int64_t timeout = number(arguments, "timeout_ms", 30000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout)), cancelled};
    const SourceText source = read_source_text(context, str(arguments, "path"));
    if (const J* expected = arguments.get("expected_sha256"))
        if (source.sha256 != lower(expected->string())) fail("expected_sha256 does not match current file");
    if (const J* expected = arguments.get("expected_mtime"))
        if (source.mtime != expected->string()) fail("expected_mtime does not match current file");
    const auto config = configuration(source, context);
    if (!config) {
        const std::string missing = missing_bundled(source);
        server_fail(missing.empty() ? "no language server configured for this file; use operation=text" : missing + "; use operation=text");
    }
    auto session = session_for(*config);
    auto lock = acquire(*session, control);
    try {
        session->start(control); session->synchronize(&source, context, control); session->service_pending(control);
        session->assert_current(source);
        std::string operation = str(arguments, "operation", "symbol");
        if (operation == "auto") operation = "symbol";
        const std::string name = str(arguments, "name_path");
        const auto found = name.empty() ? std::vector<Symbol>{} : symbols(*session, source, control);
        const Symbol* selected = name.empty() ? nullptr : &unique(found, name);
        Position at;
        if (selected) {
            if (arguments.get("line") || arguments.get("column")) fail("give name_path or line/column, not both");
            at = selected->selection.start;
        } else {
            const int64_t line = number(arguments, "line", 0), column = number(arguments, "column", 0);
            if (operation != "rename" || line < 1 || column < 1 || line > INT32_MAX || column > INT32_MAX)
                fail("symbol edits need name_path; rename also accepts 1-based line/column");
            at = {line - 1, column - 1}; offset(wide(source.text), at);
        }
        std::vector<SourceChange> changes;
        std::string leftovers;
        if (operation == "rename") {
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
            changes = workspace_changes(*session, session->request("textDocument/rename", std::move(params), control), *config,
                                        context, control, identifier_at(source.text, at));
            leftovers = rename_leftovers(identifier_at(source.text, at), changes, source.root, context, control);
        } else {
            if (!selected || !selected->has_body) fail("symbol has no reliable editable definition range");
            if (operation == "safe_delete") {
                session->require("referencesProvider");
                session->wait_indexed(control);
                const J references = session->request("textDocument/references", J::Object{
                    {"textDocument", J::Object{{"uri", session->document_uri(source)}}}, {"position", at.json()},
                    {"context", J::Object{{"includeDeclaration", false}}}}, control);
                if (!std::holds_alternative<std::nullptr_t>(references.value))
                    for (const auto& reference : references.array()) {
                        const fs::path target_path = from_uri(str(reference, "uri"));
                        if (path_excluded(*config, target_path))
                            fail("safe_delete refused: ignored_paths may contain references");
                        const SourceText target = source_descriptor(context, utf8(target_path.wstring()));
                        const J* extent = reference.get("range"); if (!extent) fail("reference has no range");
                        const Range r = range(*extent);
                        const bool same = !PathLess{}(target.path.wstring(), source.path.wstring()) &&
                                          !PathLess{}(source.path.wstring(), target.path.wstring());
                        if (!same || r.start < selected->extent.start || selected->extent.end < r.end)
                            fail("safe_delete refused: symbol has references outside its definition; use search operation=references");
                    }
            } else if (operation != "symbol" && operation != "insert_before" && operation != "insert_after") fail("unknown symbol edit operation");
            std::wstring text = wide(source.text);
            size_t begin = offset(text, selected->extent.start), end = offset(text, selected->extent.end);
            std::string replacement = operation == "safe_delete" ? "" : str(arguments, "new_text");
            if (operation == "safe_delete") {
                // Like Serena: a symbol alone on its lines goes with those lines and the blank lines after it, so the
                // gap before it is what separates its neighbours.
                const auto blank = [&](size_t from, size_t to) { return text.substr(from, to - from).find_first_not_of(L" \t") == std::wstring::npos; };
                const size_t line_start = offset(text, Position{selected->extent.start.line, 0});
                const size_t line_end = std::min(text.find_first_of(L"\r\n", end), text.size());
                if (blank(line_start, begin) && blank(end, line_end)) {
                    begin = line_start;
                    end = line_end;
                    auto step_newline = [&](size_t at) {
                        if (at < text.size() && text[at] == L'\r') ++at;
                        if (at < text.size() && text[at] == L'\n') ++at;
                        return at;
                    };
                    end = step_newline(end);
                    for (;;) {
                        size_t at = end;
                        while (at < text.size() && (text[at] == L' ' || text[at] == L'\t')) ++at;
                        if (at >= text.size() || (text[at] != L'\r' && text[at] != L'\n')) break;
                        end = step_newline(at);
                    }
                }
            }
            if (operation != "safe_delete" && !arguments.get("new_text")) fail("this symbol edit requires new_text");
            replacement = newlines(replacement, source.text);
            if (operation == "insert_before") {
                const size_t line_start = offset(text, Position{selected->extent.start.line, 0});
                if (text.substr(line_start, begin - line_start).find_first_not_of(L" \t") != std::wstring::npos)
                    fail("insert_before cannot split an inline definition; replace the containing symbol instead");
                begin = end = line_start;
                const std::string eol = source.text.find("\r\n") != std::string::npos ? "\r\n" : "\n";
                if (!replacement.ends_with("\n")) replacement += eol;
                // Like Serena: one blank line keeps the new symbol apart from the one it precedes.
                if (!replacement.ends_with(eol + eol)) replacement += eol;
            } else if (operation == "insert_after") {
                if (selected->extent.end.column == 0) begin = end;
                else {
                    size_t next = text.find_first_of(L"\r\n", end);
                    if (text.substr(end, next == std::wstring::npos ? next : next - end).find_first_not_of(L" \t") != std::wstring::npos)
                        fail("insert_after requires the definition to end on its own line");
                    if (next == std::wstring::npos) { begin = text.size(); replacement = (source.text.find("\r\n") != std::string::npos ? "\r\n" : "\n") + replacement; }
                    else { if (text[next] == L'\r' && next + 1 < text.size() && text[next + 1] == L'\n') ++next; begin = next + 1; }
                }
                end = begin;
                const std::string eol = source.text.find("\r\n") != std::string::npos ? "\r\n" : "\n";
                if (!replacement.ends_with("\n")) replacement += eol;
                // Like Serena: one blank line keeps the new symbol apart from the one it follows.
                if (!replacement.starts_with(eol)) replacement = eol + replacement;
            }
            text.replace(begin, end - begin, wide(replacement));
            changes.push_back({source, utf8(text)});
        }
        control.check();
        const auto current = read_source_text(context, utf8(source.path.wstring()));
        if (current.sha256 != source.sha256 || (arguments.get("expected_mtime") && current.mtime != source.mtime))
            fail("source changed during refactoring; retry");
        J result = apply_source_changes(changes, arguments, context, cancelled);
        if (config->indexes_workspace) resync_written(*session, changes, context, control);
        if (!leftovers.empty()) {
            auto& text = std::get<J::Object>(result.value)["text"];
            text = text.string() + leftovers;
        }
        return result;
    } catch (...) { session->stop(); throw; }
}

Json lsp_move(const Json& arguments, const SearchContext& context,
              const std::shared_ptr<std::atomic_bool>& cancelled) {
    const std::string operation = str(arguments, "operation", "auto");
    if (operation != "auto" && operation != "filesystem" && operation != "refactor") fail("move_file operation must be auto, filesystem, or refactor");
    if (operation != "filesystem" && flag(arguments, "overwrite")) fail("LSP file moves do not overwrite; use operation=filesystem explicitly");
    const int64_t timeout = number(arguments, "timeout_ms", 30000);
    if (timeout < 1 || timeout > 300000) fail("timeout_ms must be 1-300000");
    const Control control{request_deadline(Clock::now() + std::chrono::milliseconds(timeout)), cancelled};
    bool directory = false;
    const SourceText source = source_descriptor(context, str(arguments, "source"), &directory);
    bool destination_exists = false;
    const SourceText destination = source_descriptor(context, str(arguments, "destination"), nullptr, true, &destination_exists);
    if (source.path == source.root || destination.path == destination.root) fail("cannot move a configured root");
    if (!PathLess{}(source.path.wstring(), destination.path.wstring()) && !PathLess{}(destination.path.wstring(), source.path.wstring()))
        fail("source and destination are the same path");
    const std::wstring prefix = source.path.wstring() + L"\\";
    const std::wstring dest = destination.path.wstring();
    if (dest.size() > prefix.size() && CompareStringOrdinal(dest.data(), static_cast<int>(prefix.size()),
            prefix.data(), static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL) fail("cannot move a directory into itself");
    if (destination_exists && !flag(arguments, "overwrite")) fail("move destination already exists; nothing written");
    std::vector<SourceChange> changes;
    bool supported = false;
    if (operation != "filesystem")
        for (const auto& config : configs(source.root, context)) {
            const std::string extension = lower(utf8(source.path.extension().wstring()));
            if (!directory && std::find(config.extensions.begin(), config.extensions.end(), extension) == config.extensions.end()) continue;
            if (directory && !worth_starting(config, context, control)) continue;
            auto session = session_for(config);
            auto lock = acquire(*session, control);
            try {
                session->start(control); session->synchronize(nullptr, context, control); session->service_pending(control);
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
    if (Clock::now() >= control.deadline) return;
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
                const auto current = configs(session->config.root, context);
                const bool retained = std::any_of(current.begin(), current.end(), [&](const auto& config) { return config.key == session->config.key; });
                if (!retained) {
                    session->stop();
                    std::lock_guard registry_lock(registry_mutex);
                    registry.erase(session->config.key);
                    continue;
                }
                session->start(control);
                bool directory = false;
                const std::string path = tool == "move_file" ? str(arguments, "destination") : str(arguments, "path");
                const SourceText descriptor = source_descriptor(context, path, &directory);
                const bool relevant = belongs(descriptor.path, session->config.root);
                std::optional<SourceText> primary;
                const std::string extension = lower(utf8(descriptor.path.extension().wstring()));
                if (relevant && !directory && std::find(session->config.extensions.begin(), session->config.extensions.end(), extension) != session->config.extensions.end())
                    primary = read_source_text(context, path);
                if (tool == "move_file") {
                    const auto old = source_descriptor(context, str(arguments, "source"), nullptr, true);
                    if ((relevant || belongs(old.path, session->config.root)) &&
                        (session->file_operation("didRename", old.path, directory) || session->file_operation("didRename", descriptor.path, directory)))
                        session->notify("workspace/didRenameFiles", J::Object{
                            {"files", J::Array{J::Object{{"oldUri", uri(old.path)}, {"newUri", uri(descriptor.path)}}}}}, control);
                } else if (tool == "create_directory" && relevant && session->file_operation("didCreate", descriptor.path, true)) {
                    const J* text = result.get("text");
                    if (text && text->string().starts_with("Created "))
                        session->notify("workspace/didCreateFiles", J::Object{{"files", J::Array{J::Object{{"uri", uri(descriptor.path)}}}}}, control);
                }
                session->synchronize(primary ? &*primary : nullptr, context, control, true);
            } catch (...) { session->stop(); throw; }
        } catch (const std::exception& e) {
            auto& object = std::get<J::Object>(result.value);
            const std::string warning = lsp_failure_banner("language server synchronization failed after the write: " + std::string(e.what()),
                "The write itself succeeded; symbol results may be stale until the server recovers.");
            if (auto it = object.find("text"); it != object.end()) it->second = it->second.string() + warning;
            else object.emplace("warning", warning);
        }
    }
}
} // namespace shgrep
