#include "dotnet_projects.hpp"

#include <windows.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>

namespace shgrep {
namespace {
namespace fs = std::filesystem;
using Clock = DotnetProjects::Clock;
std::wstring path_key(const fs::path& path) {
    std::wstring value = path.lexically_normal().wstring();
    if (value.starts_with(L"\\\\?\\UNC\\")) value = L"\\\\" + value.substr(8);
    else if (value.starts_with(L"\\\\?\\")) value.erase(0, 4);
    std::replace(value.begin(), value.end(), L'/', L'\\');
    return value;
}
std::string utf8_path(const fs::path& path) {
    const auto bytes = fs::path(path_key(path)).generic_u8string();
    return std::string(bytes.begin(), bytes.end());
}
fs::path native_path(const std::string& text) {
    return fs::path(std::u8string(text.begin(), text.end()));
}
struct Less {
    bool operator()(const fs::path& a, const fs::path& b) const {
        const auto x = path_key(a), y = path_key(b);
        return CompareStringOrdinal(x.data(), static_cast<int>(x.size()),
            y.data(), static_cast<int>(y.size()), TRUE) == CSTR_LESS_THAN;
    }
};
using Paths = std::set<fs::path, Less>;
std::string string_field(const Json& object, const char* name) {
    const Json* value = object.get(name);
    return value ? value->string() : std::string{};
}
std::vector<std::string> split_list(const std::string& text) {
    std::vector<std::string> result;
    for (size_t at = 0; at < text.size();) {
        const size_t end = text.find(';', at);
        if (end != at) result.push_back(text.substr(at, end == std::string::npos ? end : end - at));
        if (end == std::string::npos) break;
        at = end + 1;
    }
    return result;
}
bool within(const fs::path& path, const fs::path& root) {
    auto clean = [](const fs::path& p) {
        std::wstring value = p.lexically_normal().wstring();
        if (value.starts_with(L"\\\\?\\UNC\\")) value = L"\\\\" + value.substr(8);
        else if (value.starts_with(L"\\\\?\\")) value.erase(0, 4);
        std::replace(value.begin(), value.end(), L'/', L'\\');
        return value;
    };
    auto a = clean(path), b = clean(fs::absolute(root));
    if (a.size() == b.size()) return CompareStringOrdinal(a.data(), static_cast<int>(a.size()),
        b.data(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
    if (!b.ends_with(L"\\")) b += L'\\';
    return a.size() > b.size() && CompareStringOrdinal(a.data(), static_cast<int>(b.size()),
        b.data(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}
bool workspace_path(const fs::path& path, const SearchContext& context) {
    return std::any_of(context.allowed_roots.begin(), context.allowed_roots.end(),
        [&](const auto& root) { return within(path, root); });
}
// Reading of project XML without MSBuild, for projects MSBuild could not evaluate.
std::string ascii_lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c; });
    return text;
}
// The value of attribute `name` in the tag spanning [at, end), or nullopt when absent or malformed.
std::optional<std::string> xml_attribute(const std::string& text, const std::string& lower, size_t at, size_t end,
                                         std::string_view name) {
    const auto space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    for (size_t probe = lower.find(name, at); probe != std::string::npos && probe < end; probe = lower.find(name, probe + 1)) {
        size_t after = probe + name.size();
        while (after < end && space(lower[after])) ++after;
        if (probe == 0 || !space(lower[probe - 1]) || after >= end || lower[after] != '=') continue;
        const size_t quote = lower.find_first_of("\"'", after);
        if (quote == std::string::npos || quote > end) return std::nullopt;
        const size_t close = lower.find(lower[quote], quote + 1);
        if (close == std::string::npos || close > end) return std::nullopt;
        return text.substr(quote + 1, close - quote - 1);
    }
    return std::nullopt;
}
// A path MSBuild would read without evaluation: relative to `base`, or after a leading $(MSBuildThisFileDirectory) or
// $(MSBuildProjectDirectory). nullopt for any other property, item, metadata or wildcard.
std::optional<fs::path> literal_msbuild_path(std::string value, const fs::path& base, const fs::path& this_file_directory,
                                             const fs::path& project_directory) {
    const std::string lower = ascii_lower(value);
    fs::path from = base;
    for (const auto& [macro, directory] : {std::pair<std::string_view, const fs::path*>{"$(msbuildthisfiledirectory)", &this_file_directory},
                                           std::pair<std::string_view, const fs::path*>{"$(msbuildprojectdirectory)", &project_directory}}) {
        if (!lower.starts_with(macro)) continue;
        value.erase(0, macro.size());
        while (!value.empty() && (value.front() == '\\' || value.front() == '/')) value.erase(0, 1);
        from = *directory;
        break;
    }
    if (value.empty() || value.find_first_of("$@%*?;") != std::string::npos) return std::nullopt;
    std::replace(value.begin(), value.end(), '/', '\\');
    return (from / native_path(value)).lexically_normal();
}
// The project references a project that MSBuild could not evaluate declares in its own XML and in the workspace files it
// imports (Directory.Build files included), used only to decide whether that failure can affect a request. nullopt
// when they cannot be known without MSBuild: property-built paths, wildcards, imports outside the roots, or old-format
// GUID references.
std::optional<Paths> raw_project_references(const SearchContext& context, const SourceText& project) {
    if (project.path.empty()) return std::nullopt;
    const fs::path project_directory = project.path.parent_path();
    Paths result, seen;
    std::function<bool(const fs::path&, const std::string&, int)> scan = [&](const fs::path& file, const std::string& text, int depth) {
        const std::string lower = ascii_lower(text);
        const fs::path directory = file.parent_path();
        if (lower.find("<visualstudioproject") != std::string::npos &&
            (lower.find("project = \"{") != std::string::npos || lower.find("project=\"{") != std::string::npos)) return false;
        for (size_t at = lower.find("<projectreference"); at != std::string::npos; at = lower.find("<projectreference", at + 17)) {
            if (at + 17 < lower.size() && !std::strchr(" \t\r\n/>", lower[at + 17])) continue;
            const size_t end = lower.find('>', at);
            if (end == std::string::npos) return false;
            const auto include = xml_attribute(text, lower, at, end, "include");
            if (!include) return false;
            // Item paths resolve against the project's folder, wherever the item is declared.
            const auto path = literal_msbuild_path(*include, project_directory, directory, project_directory);
            if (!path) return false;
            result.insert(*path);
        }
        for (size_t at = lower.find("<import"); at != std::string::npos; at = lower.find("<import", at + 7)) {
            // <Import ...> only; <ImportGroup> merely wraps imports.
            if (at + 7 < lower.size() && !std::strchr(" \t\r\n/>", lower[at + 7])) continue;
            const size_t end = lower.find('>', at);
            if (end == std::string::npos) return false;
            const std::string_view tag(lower.data() + at, end - at);
            if (tag.find("sdk=") != std::string_view::npos) continue;
            const auto imported = xml_attribute(text, lower, at, end, "project");
            if (!imported) return false;
            const std::string target = ascii_lower(*imported);
            if (target.starts_with("$(msbuild") && !target.starts_with("$(msbuildthisfiledirectory)") &&
                !target.starts_with("$(msbuildprojectdirectory)")) continue;  // toolchain-owned imports
            if (target.starts_with("$(vctargetspath)") || target.starts_with("$(userrootdir)")) continue;
            const auto path = literal_msbuild_path(*imported, directory, directory, project_directory);
            if (!path || depth >= 8 || !workspace_path(*path, context)) return false;
            if (!seen.insert(*path).second) continue;
            bool exists = false;
            try { (void)source_descriptor(context, utf8_path(*path), nullptr, true, &exists); }
            catch (const std::exception&) { return false; }
            if (!exists) continue;  // a missing import adds nothing
            try { if (!scan(*path, read_source_text(context, utf8_path(*path)).text, depth + 1)) return false; }
            catch (const std::exception&) { return false; }
        }
        return true;
    };
    for (fs::path parent = project_directory; within(parent, project.root); parent = parent.parent_path()) {
        for (const wchar_t* name : {L"Directory.Build.props", L"Directory.Build.targets"}) {
            const fs::path candidate = parent / name;
            if (GetFileAttributesW(candidate.c_str()) == INVALID_FILE_ATTRIBUTES || !seen.insert(candidate).second) continue;
            try { if (!scan(candidate, read_source_text(context, utf8_path(candidate)).text, 1)) return std::nullopt; }
            catch (const std::exception&) { return std::nullopt; }
        }
        if (parent == parent.parent_path()) break;
    }
    if (!scan(project.path, project.text, 0)) return std::nullopt;
    return result;
}
}

struct DotnetProjects::State {
    struct Project {
        SourceText source;
        Paths references, compile;
        std::map<fs::path, std::string, Less> inputs;
        std::string revision, sdk, error, discovery_inputs;
        fs::path repository;
        // After an evaluation failure: references read from the project XML, or nullopt when unknown.
        std::optional<Paths> raw_references;
    };
    std::map<fs::path, Project, Less> catalog;
    std::map<fs::path, Clock::time_point, Less> seeds;
    std::vector<fs::path> active;
    std::string fingerprint;
    bool partial = false, syntax_only = false, over_budget = false;
    std::vector<std::string> blockers;
    size_t unevaluated = 0;
    fs::path focus;
    std::string focus_revision;
    Paths focus_refresh, unexamined;

    Paths closure(const Paths& seeds, const Check& check) const {
        Paths result;
        std::vector<fs::path> queue(seeds.begin(), seeds.end());
        for (size_t at = 0; at < queue.size(); ++at) {
            check();
            const auto& path = queue[at];
            if (!result.insert(path).second) continue;
            const auto found = catalog.find(path);
            if (found == catalog.end()) throw std::runtime_error("project reference is not catalogued: " + utf8_path(path));
            for (const auto& reference : found->second.references) queue.push_back(reference);
        }
        return result;
    }
};
DotnetProjects::DotnetProjects() : state_(std::make_unique<State>()) {}
DotnetProjects::~DotnetProjects() = default;

DotnetProjects::Plan DotnetProjects::prepare(const SearchContext& context, const SourceText* focus,
    bool reverse, bool whole_workspace, const Evaluate& evaluate, const std::function<bool(const SourceText&)>& in_profile,
    const Check& check, const std::shared_ptr<std::atomic_bool>& cancelled,
    std::chrono::milliseconds idle_timeout, size_t project_budget, Clock::time_point deadline, bool touch_owners) {
    auto& state = *state_;
    auto now = Clock::now();
    Paths discovered;
    for (const auto& root : context.allowed_roots) {
        check();
        for (const auto& path : source_paths(context, utf8_path(root), {".csproj"},
            deadline, cancelled)) {
            check();
            discovered.insert(source_descriptor(context, path).path);
        }
    }
    if (focus && (Less{}(state.focus, focus->path) || Less{}(focus->path, state.focus) ||
                  state.focus_revision != focus->sha256)) {
        state.focus = focus->path;
        state.focus_revision = focus->sha256;
        state.focus_refresh.clear();
        for (const auto& [path, project] : state.catalog) {
            (void)project;
            state.focus_refresh.insert(path);
        }
    }
    std::vector<fs::path> queue;
    Paths queued, force_refresh;
    const auto enqueue = [&](const fs::path& path) {
        if (queued.insert(path).second) queue.push_back(path);
    };
    if (reverse || whole_workspace) {
        for (const auto& path : discovered) enqueue(path);
    } else {
        // Refresh known projects and give likely owners priority. Linked owners are discovered incrementally.
        for (const auto& path : discovered) {
            check();
            const auto known = state.catalog.find(path);
            const bool likely_owner = focus && (within(focus->path, path.parent_path()) ||
                (known != state.catalog.end() && known->second.compile.contains(focus->path)));
            if (known != state.catalog.end() || likely_owner) enqueue(path);
            if (likely_owner && state.focus_refresh.contains(path)) force_refresh.insert(path);
        }
        const size_t discovery_batch = touch_owners ? 8 : 1;
        size_t added = 0;
        for (const auto& path : discovered) {
            check();
            const bool needs_refresh = state.focus_refresh.contains(path) && !force_refresh.contains(path);
            const bool needs_discovery = !queued.contains(path);
            if (!needs_refresh && !needs_discovery) continue;
            if (added == discovery_batch) break;
            enqueue(path);
            if (needs_refresh) force_refresh.insert(path);
            ++added;
        }
        for (const auto& path : state.focus_refresh) {
            check();
            if (discovered.contains(path) || force_refresh.contains(path)) continue;
            if (added == discovery_batch) break;
            enqueue(path);
            force_refresh.insert(path);
            ++added;
        }
    }
    Paths visited, evaluated;
    state.partial = false;
    const auto refresh = [&](const fs::path& path, bool force) {
        auto& project = state.catalog[path];
        try {
            const SourceText source = read_source_text(context, utf8_path(path));
            std::string discovery_inputs;
            for (fs::path parent = source.path.parent_path(); within(parent, source.root); parent = parent.parent_path()) {
                check();
                for (const wchar_t* name : {L"global.json", L"Directory.Build.props", L"Directory.Build.targets", L"Directory.Packages.props"}) {
                    const fs::path candidate = parent / name;
                    const DWORD attributes = GetFileAttributesW(candidate.c_str());
                    const DWORD access_error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
                    discovery_inputs += utf8_path(candidate) + "\n";
                    if (attributes != INVALID_FILE_ATTRIBUTES)
                        discovery_inputs += read_source_text(context, utf8_path(candidate)).sha256;
                    else if (access_error != ERROR_FILE_NOT_FOUND && access_error != ERROR_PATH_NOT_FOUND)
                        throw std::runtime_error("cannot inspect project configuration: " + utf8_path(candidate));
                    discovery_inputs += "\n";
                }
                if (parent == parent.parent_path()) break;
            }
            bool changed = force || project.revision.empty() || project.source.sha256 != source.sha256 ||
                project.discovery_inputs != discovery_inputs || !project.error.empty();
            if (!changed) for (const auto& [input, digest] : project.inputs) {
                check();
                bool exists = false;
                (void)source_descriptor(context, utf8_path(input), nullptr, true, &exists);
                if (!exists || read_source_text(context, utf8_path(input)).sha256 != digest) { changed = true; break; }
            }
            if (!changed) return;
            evaluated.insert(path);
            project = State::Project{};
            project.source = source;
            project.discovery_inputs = std::move(discovery_inputs);
            project.repository = source.root;
            for (fs::path parent = source.path.parent_path(); within(parent, source.root); parent = parent.parent_path()) {
                check();
                const DWORD attributes = GetFileAttributesW((parent / L".git").c_str());
                if (attributes != INVALID_FILE_ATTRIBUTES) { project.repository = parent; break; }
                if (parent == parent.parent_path()) break;
            }
            for (fs::path parent = source.path.parent_path(); within(parent, source.root); parent = parent.parent_path()) {
                check();
                const fs::path global = parent / L"global.json";
                const DWORD attributes = GetFileAttributesW(global.c_str());
                if (attributes != INVALID_FILE_ATTRIBUTES) {
                    const auto snapshot = read_source_text(context, utf8_path(global));
                    project.inputs[snapshot.path] = snapshot.sha256;
                    break;
                }
                const DWORD error = GetLastError();
                if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
                    throw std::runtime_error("cannot inspect project SDK selection: " + utf8_path(global));
                if (parent == parent.parent_path()) break;
            }
            const auto add_evaluation = [&](const Json& data) {
                const Json* properties = data.get("Properties"), *items = data.get("Items");
                if (!properties || !items) throw std::runtime_error("MSBuild evaluation did not return Properties and Items");
                project.sdk = string_field(*properties, "NETCoreSdkVersion");
                if (project.sdk.empty()) project.sdk = string_field(*properties, "MSBuildToolsPath");
                for (const auto& input : split_list(string_field(*properties, "MSBuildAllProjects"))) {
                    const fs::path candidate = native_path(input);
                    if (!workspace_path(candidate, context)) continue; // SDK imports are owned by the installed toolchain.
                    const auto snapshot = read_source_text(context, input);
                    project.inputs[snapshot.path] = snapshot.sha256;
                }
                for (const char* kind : {"Compile", "ProjectReference"}) {
                    const Json* values = items->get(kind);
                    if (!values) continue;
                    for (const auto& item : values->array()) {
                        check();
                        const std::string full = string_field(item, "FullPath");
                        if (full.empty()) throw std::runtime_error(std::string("MSBuild ") + kind + " has no FullPath");
                        if (!workspace_path(native_path(full), context)) {
                            if (std::string_view(kind) == "ProjectReference")
                                throw std::runtime_error("project reference is outside configured roots: " + full);
                            continue; // External generated/framework source is not editable workspace source.
                        }
                        const auto descriptor = source_descriptor(context, full, nullptr, true);
                        if (std::string_view(kind) == "Compile") project.compile.insert(descriptor.path);
                        else project.references.insert(descriptor.path);
                    }
                }
            };
            const Json outer = evaluate(path, {});
            add_evaluation(outer);
            const auto* properties = outer.get("Properties");
            for (const auto& framework : split_list(properties ? string_field(*properties, "TargetFrameworks") : "")) {
                check();
                add_evaluation(evaluate(path, framework));
            }
            std::string revision = source.sha256 + project.sdk + project.discovery_inputs;
            for (const auto& [input, digest] : project.inputs) revision += utf8_path(input) + digest;
            for (const auto& item : project.compile) revision += utf8_path(item);
            for (const auto& item : project.references) revision += utf8_path(item);
            project.revision = source_text_digest(revision);
        } catch (const std::exception& error) {
            check(); // A cancellation or deadline never becomes a partial catalog.
            project.error = error.what();
            project.revision.clear();
            project.raw_references = raw_project_references(context, project.source);
        }
    };
    for (size_t at = 0; at < queue.size(); ++at) {
        check();
        const fs::path path = queue[at];
        if (!visited.insert(path).second) continue;
        const bool forced = reverse || whole_workspace || force_refresh.contains(path);
        refresh(path, forced);
        if (forced || evaluated.contains(path)) state.focus_refresh.erase(path);
        const auto& project = state.catalog.at(path);
        if (!project.error.empty()) state.partial = true;
        for (const auto& reference : project.references) queue.push_back(reference);
    }
    for (auto at = state.catalog.begin(); at != state.catalog.end();) {
        if (!visited.contains(at->first)) { state.seeds.erase(at->first); at = state.catalog.erase(at); }
        else ++at;
    }
    Paths owners;
    const auto find_owners = [&] {
        owners.clear();
        if (!focus) return;
        for (const auto& [path, project] : state.catalog)
            if (project.compile.contains(focus->path)) owners.insert(path);
    };
    find_owners();
    for (auto at = state.focus_refresh.begin(); at != state.focus_refresh.end();) {
        if (!state.catalog.contains(*at)) at = state.focus_refresh.erase(at);
        else ++at;
    }
    state.unexamined.clear();
    for (const auto& path : discovered) {
        check();
        if (!visited.contains(path)) state.unexamined.insert(path);
    }
    state.unevaluated = state.focus_refresh.size() + state.unexamined.size();
    state.partial = state.unevaluated != 0;  // failed projects count below, once the required set is known
    state.blockers.clear();
    if (state.unevaluated)
        state.blockers.push_back(std::to_string(state.unevaluated) + " discovered project(s) not evaluated yet");
    if (whole_workspace) for (const auto& [path, project] : state.catalog) {
        check();
        if (!project.source.path.empty() && in_profile(project.source)) owners.insert(path);
    }
    state.syntax_only = focus && owners.empty();
    if (reverse) {
        bool added;
        do {
            added = false;
            for (const auto& [path, project] : state.catalog) {
                check();
                if (!owners.contains(path) && std::any_of(project.references.begin(), project.references.end(),
                    [&](const auto& target) { return owners.contains(target); }))
                    added = owners.insert(path).second || added;
            }
        } while (added);
    }
    const Paths required = state.closure(owners, check);
    for (const auto& path : required) {
        const auto& project = state.catalog.at(path);
        if (!project.error.empty()) {
            state.partial = true;
            state.syntax_only = true;
            if (state.blockers.size() < 5) state.blockers.push_back(utf8_path(path) + ": required project failed evaluation");
        }
    }
    // A failed project outside the required set matters only when it could add to it: for reverse and
    // whole-workspace requests, when its own XML references a required project or its references are unknown.
    // Forward navigation needs only the closure. Failures stay visible in status either way.
    if (reverse || whole_workspace)
        for (const auto& [path, project] : state.catalog) {
            check();
            if (project.error.empty() || required.contains(path)) continue;
            const bool unknown = !project.raw_references;
            if (unknown || std::any_of(project.raw_references->begin(), project.raw_references->end(),
                    [&](const auto& target) { return required.contains(target); })) {
                state.partial = true;
                if (state.blockers.size() >= 5) break;
                state.blockers.push_back(utf8_path(path) + (unknown
                    ? ": failed evaluation and its project references cannot be read without MSBuild"
                    : ": failed evaluation and references a required project"));
            }
        }
    now = Clock::now(); // Evaluation time does not consume a project's idle allowance.
    for (auto at = state.seeds.begin(); at != state.seeds.end();) {
        if (!state.catalog.contains(at->first) || now - at->second >= idle_timeout) at = state.seeds.erase(at);
        else ++at;
    }
    auto owner_used = now;
    if (!touch_owners && !state.seeds.empty()) {
        owner_used = Clock::time_point::min();
        for (const auto& [path, used] : state.seeds) owner_used = std::max(owner_used, used);
    }
    for (const auto& owner : owners) {
        if (touch_owners) state.seeds[owner] = now;
        else state.seeds.try_emplace(owner, owner_used);
    }
    const auto active_closure = [&] {
        Paths roots;
        for (const auto& [path, used] : state.seeds) roots.insert(path);
        return state.closure(roots, check);
    };
    Paths active = active_closure();
    while (active.size() > project_budget) {
        auto oldest = state.seeds.end();
        for (auto at = state.seeds.begin(); at != state.seeds.end(); ++at)
            if (!owners.contains(at->first) && (oldest == state.seeds.end() || at->second < oldest->second)) oldest = at;
        if (oldest == state.seeds.end()) break; // Required closures are never clipped to meet a memory target.
        state.seeds.erase(oldest);
        active = active_closure();
    }
    state.over_budget = active.size() > project_budget;
    std::vector<fs::path> selected;
    std::string fingerprint;
    for (const auto& path : active) {
        const auto& project = state.catalog.at(path);
        if (!project.error.empty()) continue; // Syntax-only requests expose failed projects in status.
        selected.push_back(path);
        fingerprint += utf8_path(path) + "\n" + project.revision + "\n";
    }
    state.active = selected;
    state.fingerprint = source_text_digest(fingerprint);
    return {state.active, state.fingerprint, state.partial || state.syntax_only, state.syntax_only, state.blockers};
}
bool DotnetProjects::contains_source(const fs::path& path) const {
    for (const auto& project : state_->active) {
        const auto found = state_->catalog.find(project);
        if (found != state_->catalog.end() && found->second.compile.contains(path)) return true;
    }
    return false;
}
std::vector<std::string> DotnetProjects::sources() const {
    Paths unique;
    for (const auto& path : state_->active) {
        const auto found = state_->catalog.find(path);
        if (found != state_->catalog.end()) unique.insert(found->second.compile.begin(), found->second.compile.end());
    }
    std::vector<std::string> result;
    for (const auto& path : unique) result.push_back(utf8_path(path));
    return result;
}
bool DotnetProjects::expire_idle(Clock::time_point now, std::chrono::milliseconds timeout) {
    bool expired = false;
    for (auto at = state_->seeds.begin(); at != state_->seeds.end();) {
        if (now - at->second >= timeout) { expired = true; at = state_->seeds.erase(at); }
        else ++at;
    }
    return expired;
}
void DotnetProjects::unloaded() { state_->active.clear(); state_->fingerprint.clear(); }
const std::vector<fs::path>& DotnetProjects::requested() const { return state_->active; }
size_t DotnetProjects::unevaluated() const { return state_->unevaluated; }
Json DotnetProjects::status() const {
    Json::Array projects;
    Paths active(state_->active.begin(), state_->active.end());
    for (const auto& [path, project] : state_->catalog) {
        Json::Object item{{"path", utf8_path(path)}, {"repository", utf8_path(project.repository)},
            {"sdk", project.sdk}, {"state", !project.error.empty() ? "evaluation_failed" :
                active.contains(path) ? "requested" : "unloaded"}};
        if (!project.error.empty()) item["error"] = project.error;
        if (state_->focus_refresh.contains(path)) item["ownership_refresh_pending"] = true;
        Json::Array references;
        for (const auto& target : project.references) references.emplace_back(utf8_path(target));
        item["references"] = std::move(references);
        projects.emplace_back(std::move(item));
    }
    for (const auto& path : state_->unexamined)
        projects.emplace_back(Json::Object{{"path", utf8_path(path)}, {"state", "discovered"}});
    return Json::Object{{"projects", std::move(projects)}, {"partial", state_->partial || state_->syntax_only},
        {"syntax_only", state_->syntax_only}, {"over_project_budget", state_->over_budget},
        {"requested_projects", static_cast<uint64_t>(state_->active.size())},
        {"unevaluated_projects", static_cast<uint64_t>(state_->unevaluated)}};
}

}
