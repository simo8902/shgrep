#include "workspace_profile.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <unordered_map>

namespace shgrep {
namespace {
bool one_of(std::string_view value, std::initializer_list<std::string_view> names) {
    return std::find(names.begin(), names.end(), value) != names.end();
}
// Folders that only ever hold third-party code installed or checked in beside the project.
bool vendored_folder(std::string_view name) {
    return one_of(name, {"node_modules", "bower_components", "jspm_packages", "third_party", "thirdparty",
                         "third-party", "vendor", "vendors", "external", "externals", "pods", "carthage",
                         "site-packages", "dist-packages"});
}
// Folders that only ever hold tool caches or generator output, whatever project they sit in.
bool generated_folder(std::string_view name) {
    return one_of(name, {"__pycache__", "cmakefiles", ".gradle", ".pytest_cache", ".mypy_cache", ".ruff_cache",
                         ".next", ".nuxt", ".svelte-kit", "generated"}) ||
           name.starts_with("cmake-build-");
}
// File names that generators produce.
bool generated_name(std::string_view name) {
    for (const std::string_view suffix : {".min.js", ".min.css", ".min.mjs", ".g.cs", ".g.i.cs", ".designer.cs",
                                          "_pb2.py", "_pb2_grpc.py", ".pb.go", ".pb.h", ".pb.cc"})
        if (name.ends_with(suffix)) return true;
    return name.find(".generated.") != std::string_view::npos || name.starts_with("moc_");
}
bool any_file(const FolderProbe& probe, std::string_view folder, std::initializer_list<std::string_view> files) {
    return std::any_of(files.begin(), files.end(), [&](std::string_view file) { return probe.has_file(folder, file); });
}
// Layer 3: build evidence for `folder` (whose last name is `name`) and its parent folder.
FileRole evidence_role(const FolderProbe& probe, std::string_view folder, std::string_view name, std::string_view parent) {
    if (probe.has_file(folder, "pyvenv.cfg")) return FileRole::vendored;
    if (any_file(probe, folder, {"cmakecache.txt", "build.ninja", "cachedir.tag"})) return FileRole::generated;
    if (name == "target" && any_file(probe, parent, {"cargo.toml", "pom.xml"})) return FileRole::generated;
    if ((name == "obj" || name == "bin") &&
        (probe.has_suffix(parent, ".csproj") || probe.has_suffix(parent, ".fsproj") || probe.has_suffix(parent, ".vbproj")))
        return FileRole::generated;
    if (name == "build" && any_file(probe, parent, {"cmakelists.txt", "build.gradle", "build.gradle.kts", "settings.gradle",
                                                     "settings.gradle.kts", "meson.build", "setup.py", "pyproject.toml",
                                                     "package.json"}))
        return FileRole::generated;
    if (name == "dist" && any_file(probe, parent, {"package.json", "pyproject.toml", "setup.py", "setup.cfg"}))
        return FileRole::generated;
    if (name == "out" && any_file(probe, parent, {"package.json", "tsconfig.json"})) return FileRole::generated;
    return FileRole::source;
}
}

LanguageKind language_kind(std::string_view extension) {
    // Linguist types: XML-family, JSON, YAML, TOML, INI and CSV are data; HTML and CSS are markup; text is prose.
    if (one_of(extension, {".xml", ".xsd", ".xsl", ".xslt", ".svg", ".json", ".jsonc", ".yaml", ".yml", ".toml",
                           ".ini", ".csv", ".tsv"}))
        return LanguageKind::data;
    if (one_of(extension, {".html", ".htm", ".css", ".scss", ".sass", ".less"})) return LanguageKind::markup;
    if (one_of(extension, {".md", ".mdx", ".txt", ".rst", ".log"})) return LanguageKind::prose;
    return LanguageKind::programming;
}

FileRole path_role(std::string_view relative, std::string_view extension, const FolderProbe* probe) {
    if (language_kind(extension) == LanguageKind::data) return FileRole::data;
    size_t start = 0;
    for (size_t slash = relative.find('/'); slash != std::string_view::npos; slash = relative.find('/', start)) {
        const std::string_view name = relative.substr(start, slash - start);
        if (vendored_folder(name)) return FileRole::vendored;
        if (generated_folder(name)) return FileRole::generated;
        if (probe) {
            const std::string_view folder = relative.substr(0, slash);
            const std::string_view parent = start ? relative.substr(0, start - 1) : std::string_view();
            if (const FileRole role = evidence_role(*probe, folder, name, parent); role != FileRole::source) return role;
        }
        start = slash + 1;
    }
    return generated_name(relative.substr(start)) ? FileRole::generated : FileRole::source;
}

FileRole content_role(std::string_view head) {
    std::string lowered(head.substr(0, std::min(head.size(), profile_head_bytes)));
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // Markers generators write at the top of their output (protoc, Roslyn and .NET tools, Go, Bazel, Linguist's list).
    for (const std::string_view marker : {"<auto-generated", "@generated", "do not edit", "code generated by",
                                          "this file was automatically generated", "this file is automatically generated",
                                          "autogenerated by", "auto-generated by",
                                          "generated by the protocol buffer compiler"})
        if (lowered.find(marker) != std::string::npos) return FileRole::generated;
    // Minified: a full head with almost no line breaks (an average line over 1000 bytes).
    if (lowered.size() >= 2048 && static_cast<size_t>(std::count(lowered.begin(), lowered.end(), '\n')) * 1000 < lowered.size())
        return FileRole::generated;
    return FileRole::source;
}

namespace {
std::string narrow(const std::wstring& text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(size > 0 ? size : 0), '\0');
    if (size > 0) WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size, nullptr, nullptr);
    return out;
}
std::wstring widen(std::string_view text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(size > 0 ? size : 0), L'\0');
    if (size > 0) MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size);
    return out;
}
std::string lowered(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}
// The \\?\ spelling of an absolute path, so long paths work.
std::wstring long_name(std::filesystem::path path) {
    std::wstring name = path.make_preferred().wstring();
    if (!name.starts_with(L"\\\\?\\"))
        name = name.starts_with(L"\\\\") ? L"\\\\?\\UNC\\" + name.substr(2) : L"\\\\?\\" + name;
    return name;
}
}

FolderProbe file_system_probe(std::filesystem::path root) {
    auto memo = std::make_shared<std::unordered_map<std::string, bool>>();
    const auto folder_path = [root](std::string_view folder) {
        std::filesystem::path path = root;
        if (!folder.empty()) path /= std::filesystem::path(widen(folder));
        return path;
    };
    FolderProbe probe;
    probe.has_file = [memo, folder_path](std::string_view folder, std::string_view file) {
        std::string key = std::string(folder) + "\n" + std::string(file);
        if (const auto found = memo->find(key); found != memo->end()) return found->second;
        const DWORD attributes = GetFileAttributesW(long_name(folder_path(folder) / std::filesystem::path(widen(file))).c_str());
        const bool present = attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
        memo->emplace(std::move(key), present);
        return present;
    };
    probe.has_suffix = [memo, folder_path](std::string_view folder, std::string_view suffix) {
        std::string key = std::string(folder) + "\n*" + std::string(suffix);
        if (const auto found = memo->find(key); found != memo->end()) return found->second;
        bool present = false;
        WIN32_FIND_DATAW data{};
        const std::wstring pattern = long_name(folder_path(folder) / std::filesystem::path(L"*" + widen(suffix)));
        if (HANDLE find = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, 0);
            find != INVALID_HANDLE_VALUE) {
            do {
                if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && lowered(narrow(data.cFileName)).ends_with(suffix)) {
                    present = true;
                    break;
                }
            } while (FindNextFileW(find, &data));
            FindClose(find);
        }
        memo->emplace(std::move(key), present);
        return present;
    };
    return probe;
}

FileRole file_path_role(const std::filesystem::path& root, const std::filesystem::path& file, std::string_view extension,
                        const FolderProbe* probe) {
    std::string relative = lowered(narrow(file.lexically_relative(root).generic_wstring()));
    if (relative.empty() || relative.starts_with("..")) relative = lowered(narrow(file.filename().wstring()));
    return path_role(relative, extension, probe);
}

std::string_view role_name(FileRole role) {
    switch (role) {
        case FileRole::data: return "data";
        case FileRole::generated: return "generated";
        case FileRole::vendored: return "vendored";
        default: return "source";
    }
}
}
