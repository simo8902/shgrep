#pragma once
#include <cstddef>
#include <filesystem>
#include <functional>
#include <initializer_list>
#include <string>
#include <string_view>

namespace shgrep {
// CONTRACT (workspace profile): what each file of a workspace is, so folder-wide semantic walks, server warm-up and
//   the meaning index spend work only on source. All layers are side-effect free: file-system answers come through
//   a probe that reads metadata only.
//   1. Language kind by extension, after GitHub Linguist's types (programming, markup, data, prose). Extension alone
//      identifies a file's language about 85% of the time (arXiv 2101.08508).
//   2. Role by name: dependency folders (vendored) and tool-cache folders and generated file names (generated), the
//      path and file-name rules Linguist and large repository studies use (arXiv 1704.00135, 1806.04556).
//   3. Role by build evidence: a folder is build output when its own contents or its parent's build manifest say so
//      (CMakeCache.txt or build.ninja inside; CACHEDIR.TAG, the cache-directory standard Cargo writes into target;
//      pyvenv.cfg for a virtual environment; target beside Cargo.toml or pom.xml; obj and bin beside a .NET project;
//      build, dist and out beside the manifest whose tool writes them). Build systems are found by such sentinel
//      files (arXiv 2506.17948), and a build-derived map is what agents should trust for structure (arXiv 2601.10112).
//      Common names such as build, dist, target, obj, bin and out are source unless that evidence exists.
//   4. Role by content: generated-file header markers and minified text in a file's first bytes.
//   A file is "source" only when no layer says otherwise. Callers report what they skipped and let an explicitly
//   scoped request include it, so nothing is hidden.
enum class LanguageKind { programming, markup, data, prose };
enum class FileRole { source, data, generated, vendored };

// Layer 3 file-system answers about a folder below the configured root ('/' separators, lower case; "" is the root).
// Callers memoize them; a probe that cannot tell answers false.
struct FolderProbe {
    std::function<bool(std::string_view folder, std::string_view file)> has_file;     // a file of exactly this name
    std::function<bool(std::string_view folder, std::string_view suffix)> has_suffix; // a file whose name ends so
};

// extension: lower case with its dot (".xml"); CMakeLists.txt arrives as ".cmake".
LanguageKind language_kind(std::string_view extension);
// relative: the path below its configured root, '/' separators, lower case. Data comes from the extension, the rest
// from folder and file names and, with a probe, from build evidence.
FileRole path_role(std::string_view relative, std::string_view extension, const FolderProbe* probe);
// head: the first bytes of a file (up to profile_head_bytes). Generated when it carries a generator marker or reads
// as minified text; source otherwise.
FileRole content_role(std::string_view head);
inline constexpr size_t profile_head_bytes = 4096;
std::string_view role_name(FileRole role);

// A FolderProbe over the real file system below `root`: attribute and directory-listing queries only, no file is
// opened. Answers are memoized for the probe's lifetime; one probe serves one thread.
FolderProbe file_system_probe(std::filesystem::path root);
// path_role of an absolute `file` below `root`; extension is files.hpp language_extension(file).
FileRole file_path_role(const std::filesystem::path& root, const std::filesystem::path& file, std::string_view extension,
                        const FolderProbe* probe);
}
