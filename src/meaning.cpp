#include "meaning.hpp"

#include "files.hpp"
#include "lsp.hpp"
#include "lsp_watch.hpp"
#include "winfs.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <thread>
#include <unordered_map>

namespace shgrep {
namespace {
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

constexpr size_t max_chunk_chars = 1200;  // bench/symbol_eval.py MAXCH
constexpr uint32_t type_max_lines = 60;   // bench/symbol_eval.py CLASS_MAX_LINES
constexpr size_t embed_group = 256;       // chunks embedded per GPU call while indexing

struct Chunk {
    std::string name_path, kind;
    uint32_t start = 0, end = 0;   // the symbol's lines, 1-based
    uint32_t first = 0, last = 0;  // this chunk's lines
    std::string text;
    std::vector<float> vector;
};
struct FileEntry {
    std::string sha256;  // empty: index again on the next refresh (the outline was partial)
    std::string shown;   // the path as search output shows it
    std::vector<Chunk> chunks;
    std::string stamp;   // size and write time when sha256 was taken (lsp_file_stamp); process memory only, not saved
};
struct Index {
    std::timed_mutex mutex;  // protects the index data while it is read or changed
    std::timed_mutex build_mutex;  // only one refresh may build at a time
    std::atomic_bool background_refresh{false};
    std::mutex progress_mutex;
    std::string progress = "not built yet";
    std::string root;                          // normalized key of the workspace root
    std::string profile;                       // server configuration and embedding model identity
    std::map<std::string, FileEntry> files;   // normalized absolute path -> entry
    uint64_t skipped = 0;                      // files whose outline failed in the last refresh
    bool dirty = false;                        // mutations not yet saved by a complete refresh
    bool disk_checked = false;                 // the saved index was read (or found unusable) for this root
    // Changes below the root since the last complete refresh (listing_still_valid). Never destroyed, like the index.
    std::unique_ptr<DirectoryWatch> watch;
    std::string watch_root;                    // path_key of the watched root
    std::vector<std::string> listing;          // shown paths of the last complete listing; empty: list again
    std::map<std::string, fs::path> pending_changed;  // path_key -> path, reported but not yet handled by a refresh
    bool pending_reload = true;                // changes may be missing: list and check every file again
};
Index& meaning_index() {
    // Never destroyed: a search or the background builder may still hold it while static destructors run at exit.
    static Index& index = *new Index;
    return index;
}

// The background builder (start_meaning_index); never destroyed, as above.
struct Builder {
    std::mutex mutex;
    std::shared_ptr<std::atomic_bool> stop = std::make_shared<std::atomic_bool>(false);
    std::thread thread;
};
Builder& builder() {
    static Builder& instance = *new Builder;
    return instance;
}

void set_progress(const std::string& text) {
    auto& index = meaning_index();
    std::lock_guard lock(index.progress_mutex);
    index.progress = text;
}
std::string progress() {
    auto& index = meaning_index();
    std::lock_guard lock(index.progress_mutex);
    return index.progress;
}

[[noreturn]] void meaning_failure(const std::string& cause) {
    throw std::runtime_error("MEANING SEARCH FAILURE - tell the user: " + cause +
                             " Text search, file tools and LSP still work.");
}

// Windows paths compare case-insensitively and with either slash.
std::string path_key(const fs::path& path) {
    std::string out = utf8(path.lexically_normal().wstring());
    for (char& c : out) {
        if (c == '/') c = '\\';
        else if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

fs::path workspace_root(const SearchContext& context) {
    if (context.allowed_roots.empty()) meaning_failure("no workspace root is configured.");
    return fs::absolute(context.allowed_roots.front()).lexically_normal();
}

// A path from tool output (relative to the workspace, or absolute) as an index key.
fs::path absolute_of(const fs::path& root, std::string_view shown) {
    std::wstring wide;
    if (!shown.empty()) {
        const int size = MultiByteToWideChar(CP_UTF8, 0, shown.data(), static_cast<int>(shown.size()), nullptr, 0);
        wide.resize(static_cast<size_t>(std::max(size, 0)));
        if (size > 0) MultiByteToWideChar(CP_UTF8, 0, shown.data(), static_cast<int>(shown.size()), wide.data(), size);
    }
    const fs::path path(wide);
    return path.is_absolute() ? path : root / path;
}
std::string key_of(const fs::path& root, std::string_view shown) {
    return path_key(absolute_of(root, shown));
}

int64_t remaining_ms(Clock::time_point deadline) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return std::clamp<int64_t>(left, 1, 300000);
}

// SHGREP_MEANING_MAX_FILES (default 5000): the most LSP files the index embeds.
size_t max_index_files() {
    wchar_t value[16] = {};
    const DWORD size = GetEnvironmentVariableW(L"SHGREP_MEANING_MAX_FILES", value, 16);
    if (!size) return 5000;
    wchar_t* end = nullptr;
    const long long parsed = size < 16 ? std::wcstoll(value, &end, 10) : -1;
    if (!end || *end || end == value || parsed < 1 || parsed > 1000000)
        meaning_failure("SHGREP_MEANING_MAX_FILES must be a number from 1 to 1000000.");
    return static_cast<size_t>(parsed);
}

bool chunked_kind(std::string_view kind) {
    return kind == "function" || kind == "method" || kind == "constructor" || kind == "class" || kind == "struct" ||
           kind == "enum";
}

std::string_view trimmed(std::string_view line) {
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
    return line;
}

// Lines of text without their line ends; index 0 is line 1.
std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> lines;
    size_t begin = 0;
    for (;;) {
        const size_t newline = text.find('\n', begin);
        std::string_view line = text.substr(begin, newline == std::string_view::npos ? std::string_view::npos : newline - begin);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        lines.push_back(line);
        if (newline == std::string_view::npos) break;
        begin = newline + 1;
    }
    return lines;
}

// First line of the // or /* comment block directly above `start` (bench/symbol_eval.py leading_comment).
uint32_t leading_comment(const std::vector<std::string_view>& lines, uint32_t start) {
    uint32_t first = start;
    while (first >= 2 && first - 2 < lines.size()) {
        const std::string_view above = trimmed(lines[first - 2]);
        if (!(above.starts_with("//") || above.starts_with("/*") || above.starts_with("*"))) break;
        --first;
    }
    return first;
}

// Chunks of one file from its LSP outline (bench/symbol_eval.py build_chunks).
std::vector<Chunk> chunk_file(std::string_view text, const Json& outline) {
    std::vector<Chunk> chunks;
    const Json* results = outline.get("results");
    if (!results) return chunks;
    const auto lines = split_lines(text);
    std::vector<bool> covered(lines.size(), false);
    const auto emit = [&](Chunk part, uint32_t first, uint32_t last) {
        const auto close = [&] {
            if (std::any_of(part.text.begin(), part.text.end(), [](char c) {
                    return c != ' ' && c != '\t' && c != '\n' && c != '\r';
                })) chunks.push_back(part);
            part.text.clear();
        };
        for (uint32_t line = first; line <= last; ++line) {
            std::string_view content = lines[line - 1];
            if (!part.text.empty() && part.text.size() + content.size() + 1 > max_chunk_chars) close();
            if (part.text.empty()) part.first = line;
            else part.text.push_back('\n');
            while (content.size() > max_chunk_chars) {
                // SourceText is UTF-8: never split a code point across embedding documents.
                size_t count = max_chunk_chars;
                while (count && (static_cast<unsigned char>(content[count]) & 0xc0) == 0x80) --count;
                part.text.append(content.substr(0, count));
                part.last = line;
                close();
                part.first = line;
                content.remove_prefix(count);
            }
            part.text.append(content);
            part.last = line;
        }
        close();
    };
    for (const Json& symbol : results->array()) {
        const Json* kind = symbol.get("kind_name");
        const Json* range = symbol.get("range");
        const Json* name = symbol.get("name_path");
        if (!kind || !range || !name || !chunked_kind(kind->string())) continue;
        const Json* start_field = range->get("start_line");
        const Json* end_field = range->get("end_line");
        if (!start_field || !end_field) continue;
        const auto start = static_cast<uint32_t>(std::clamp<int64_t>(start_field->integer(), 1, static_cast<int64_t>(lines.size())));
        const auto end = static_cast<uint32_t>(std::clamp<int64_t>(end_field->integer(), start, static_cast<int64_t>(lines.size())));
        const bool type = kind->string() == "class" || kind->string() == "struct" || kind->string() == "enum";
        const uint32_t first = leading_comment(lines, start);
        const uint32_t last = type ? std::min(end, start + type_max_lines - 1) : end;
        for (uint32_t line = first; line <= last; ++line) covered[line - 1] = true;
        emit(Chunk{name->string(), kind->string(), start, end, first, first, {}, {}}, first, last);
    }
    // Headers, globals and declarations without a selected LSP symbol remain searchable.
    for (size_t first = 0; first < lines.size();) {
        if (covered[first]) { ++first; continue; }
        size_t last = first;
        while (last + 1 < lines.size() && !covered[last + 1] && last - first + 1 < 30) ++last;
        const auto begin = static_cast<uint32_t>(first + 1), end = static_cast<uint32_t>(last + 1);
        emit(Chunk{"<outside symbols>:" + std::to_string(begin) + "-" + std::to_string(end),
                   "text", begin, end, begin, begin, {}, {}}, begin, end);
        first = last + 1;
    }
    return chunks;
}

std::string file_name(std::string_view shown) {
    const size_t slash = shown.find_last_of("/\\");
    return std::string(slash == std::string_view::npos ? shown : shown.substr(slash + 1));
}

// Saved per server/model profile: <workspace>\.shgrep\meaning-<profile>.idx; complete refreshes only
// per process, so a restart re-embeds only files whose bytes changed. Layout (little-endian): "SHGMEAN1", u32
// version, identity string, u64 dimensions, u64 files; per file: key, sha256, shown path, u64 chunks; per chunk:
// name path, kind, u32 start, end, first, last, text, dimensions x f32. Strings are u64 length + bytes.
constexpr char saved_magic[8] = {'S', 'H', 'G', 'M', 'E', 'A', 'N', '1'};
constexpr uint32_t saved_version = 3;  // bump when the chunk rules, the embedded text or this layout change

fs::path saved_path(const fs::path& root, const std::string& profile) {
    return root / L".shgrep" / ("meaning-" + profile + ".idx");
}

// The largest saved index read or written: 1 GiB, or 256 KiB per file the index may hold when that is more. A larger
// file is not loaded (the index is rebuilt), and a larger index is not saved, so a rebuild never loops.
uint64_t max_saved_bytes() {
    return std::max<uint64_t>(uint64_t{1} << 30, static_cast<uint64_t>(max_index_files()) * (uint64_t{256} << 10));
}

void put_u64(std::string& out, uint64_t value) {
    char bytes[8];
    std::memcpy(bytes, &value, 8);
    out.append(bytes, 8);
}
void put_u32(std::string& out, uint32_t value) {
    char bytes[4];
    std::memcpy(bytes, &value, 4);
    out.append(bytes, 4);
}
void put_string(std::string& out, std::string_view value) {
    put_u64(out, value.size());
    out.append(value);
}

// Bounds-checked reads of an untrusted file: every length is checked against the bytes left.
struct SavedReader {
    std::string_view data;
    size_t at = 0;
    void need(uint64_t size) const {
        if (size > data.size() - at) throw std::runtime_error("file is cut short");
    }
    uint64_t u64() {
        need(8);
        uint64_t value;
        std::memcpy(&value, data.data() + at, 8);
        at += 8;
        return value;
    }
    uint32_t u32() {
        need(4);
        uint32_t value;
        std::memcpy(&value, data.data() + at, 4);
        at += 4;
        return value;
    }
    std::string string() {
        const uint64_t size = u64();
        need(size);
        std::string value(data.substr(at, static_cast<size_t>(size)));
        at += static_cast<size_t>(size);
        return value;
    }
};

std::map<std::string, FileEntry> read_saved(const fs::path& root, const std::string& identity, size_t dimensions,
                                            const std::string& profile, const std::function<void()>& check) {
    // SAFETY (#96): the cache is read in the MCP process, outside any worker memory cap. Its size is bounded before
    // anything is allocated, it is read and parsed with cancellation/deadline checks, and every count is checked
    // against the smallest record it could describe, so a corrupt or inflated cache cannot reserve more than its bytes.
    std::ifstream file(saved_path(root, profile), std::ios::binary);
    if (!file) return {};  // nothing saved yet
    file.seekg(0, std::ios::end);
    const std::streamoff length = file.tellg();
    file.seekg(0, std::ios::beg);
    if (length < 0 || !file) throw std::runtime_error("cannot read its size");
    if (static_cast<uint64_t>(length) > max_saved_bytes())
        throw std::runtime_error("larger than the " + std::to_string(max_saved_bytes() >> 20) + " MiB cache limit");
    std::string bytes(static_cast<size_t>(length), '\0');
    constexpr size_t block = 4u << 20;
    for (size_t done = 0; done < bytes.size();) {
        check();
        const size_t want = std::min(block, bytes.size() - done);
        file.read(bytes.data() + done, static_cast<std::streamsize>(want));
        if (static_cast<size_t>(file.gcount()) != want) throw std::runtime_error("file is cut short");
        done += want;
    }
    SavedReader in{bytes};
    in.need(sizeof(saved_magic));
    if (std::memcmp(bytes.data(), saved_magic, sizeof(saved_magic)) != 0) throw std::runtime_error("not a meaning index");
    in.at = sizeof(saved_magic);
    if (in.u32() != saved_version) throw std::runtime_error("older layout or chunk rules");
    if (in.string() != identity) throw std::runtime_error("made with another embedding model");
    if (in.u64() != dimensions) throw std::runtime_error("other vector length");
    // Smallest serialized records: a file is three string lengths and a chunk count; a chunk is three string lengths,
    // four line numbers and its vector.
    constexpr uint64_t min_file_bytes = 4 * sizeof(uint64_t);
    const uint64_t min_chunk_bytes = 3 * sizeof(uint64_t) + 4 * sizeof(uint32_t) +
                                     static_cast<uint64_t>(dimensions) * sizeof(float);
    std::map<std::string, FileEntry> files;
    const uint64_t count = in.u64();
    if (count > (bytes.size() - in.at) / min_file_bytes) throw std::runtime_error("file count exceeds the file");
    uint64_t parsed = 0;
    for (uint64_t f = 0; f < count; ++f) {
        std::string key = in.string();
        FileEntry entry;
        entry.sha256 = in.string();
        entry.shown = in.string();
        const uint64_t chunks = in.u64();
        if (chunks > (bytes.size() - in.at) / min_chunk_bytes) throw std::runtime_error("chunk count exceeds the file");
        entry.chunks.reserve(static_cast<size_t>(chunks));
        for (uint64_t c = 0; c < chunks; ++c) {
            if (++parsed % 1024 == 0) check();
            Chunk chunk;
            chunk.name_path = in.string();
            chunk.kind = in.string();
            chunk.start = in.u32();
            chunk.end = in.u32();
            chunk.first = in.u32();
            chunk.last = in.u32();
            chunk.text = in.string();
            in.need(static_cast<uint64_t>(dimensions) * sizeof(float));
            chunk.vector.resize(dimensions);
            std::memcpy(chunk.vector.data(), bytes.data() + in.at, dimensions * sizeof(float));
            in.at += dimensions * sizeof(float);
            entry.chunks.push_back(std::move(chunk));
        }
        files.emplace(std::move(key), std::move(entry));
    }
    if (in.at != bytes.size()) throw std::runtime_error("unexpected bytes at the end");
    return files;
}

void write_saved(const Index& index, const SearchContext& context, const fs::path& root, const std::string& identity,
                 size_t dimensions) {
    std::string out(saved_magic, sizeof(saved_magic));
    put_u32(out, saved_version);
    put_string(out, identity);
    put_u64(out, dimensions);
    put_u64(out, index.files.size());
    for (const auto& [key, entry] : index.files) {
        put_string(out, key);
        put_string(out, entry.sha256);
        put_string(out, entry.shown);
        put_u64(out, entry.chunks.size());
        for (const auto& chunk : entry.chunks) {
            put_string(out, chunk.name_path);
            put_string(out, chunk.kind);
            put_u32(out, chunk.start);
            put_u32(out, chunk.end);
            put_u32(out, chunk.first);
            put_u32(out, chunk.last);
            put_string(out, chunk.text);
            if (chunk.vector.size() != dimensions) throw std::runtime_error("a chunk has no vector");
            out.append(reinterpret_cast<const char*>(chunk.vector.data()), dimensions * sizeof(float));
        }
    }
    if (out.size() > max_saved_bytes()) {
        index_log(true, "meaning index: not saved; " + std::to_string(out.size() >> 20) + " MiB is over the " +
                            std::to_string(max_saved_bytes() >> 20) + " MiB cache limit (raise SHGREP_MEANING_MAX_FILES "
                            "or list vendored folders in .shignore)");
        return;
    }
    create_workspace_metadata_directory(context, root / L".shgrep");
    write_workspace_metadata(context, saved_path(root, index.profile), out);
}

// Brings the index up to date with the workspace's LSP files. Background refresh releases the data lock during
// slow reads, LSP calls and embedding; the build lock still prevents concurrent refreshes. On return, held protects
// the result. lock_workspace takes the shared workspace gate around background LSP calls.
// Microseconds per phase of one meaning search, returned by search operation=meaning profile=true.
// CONTRACT: a hidden benchmark switch like text search's profile; absent from the tool definitions. A null profile
// costs one branch per phase.
struct MeaningProfile {
    int64_t embed_query_us = 0, lock_wait_us = 0, listing_us = 0, fingerprint_us = 0, saved_read_us = 0,
            change_check_us = 0, outline_embed_us = 0, finish_us = 0, collect_us = 0, dense_us = 0, bm25_us = 0,
            rank_us = 0, format_us = 0, total_us = 0;
    uint64_t files_listed = 0, files_changed = 0, chunks = 0;
    Json json() const {
        return Json::Object{{"embed_query_us", embed_query_us}, {"lock_wait_us", lock_wait_us},
                            {"listing_us", listing_us}, {"fingerprint_us", fingerprint_us},
                            {"saved_read_us", saved_read_us}, {"change_check_us", change_check_us},
                            {"outline_embed_us", outline_embed_us}, {"finish_us", finish_us},
                            {"collect_us", collect_us}, {"dense_us", dense_us}, {"bm25_us", bm25_us},
                            {"rank_us", rank_us}, {"format_us", format_us}, {"total_us", total_us},
                            {"files_listed", static_cast<int64_t>(files_listed)},
                            {"files_changed", static_cast<int64_t>(files_changed)},
                            {"chunks", static_cast<int64_t>(chunks)}};
    }
};
int64_t* slot(MeaningProfile* profile, int64_t MeaningProfile::*field) { return profile ? &(profile->*field) : nullptr; }
// Adds the time since `since` to *target (when profiling) and returns now, the start of the next phase.
Clock::time_point lap(int64_t* target, Clock::time_point since) {
    const auto now = Clock::now();
    if (target) *target += std::chrono::duration_cast<std::chrono::microseconds>(now - since).count();
    return now;
}

// A changed path that is not an indexed file can change the workspace listing when it is (or was) a folder, a file
// a language server handles, or a file that steers listing and server setup (ignore files, compile databases,
// CMake and clangd files). Folder renames and deletions arrive as extension-less paths, so those count too.
bool can_change_listing(const fs::path& path, const fs::path& root) {
    std::error_code error;
    if (!path.has_extension() || fs::is_directory(path, error)) return true;
    std::wstring name = path.filename().wstring();
    for (wchar_t& c : name) c = static_cast<wchar_t>(std::towlower(c));
    static const std::set<std::wstring> steering{L"compile_commands.json", L"compile_flags.txt", L"cmakelists.txt",
                                                 L"cmakepresets.json", L"cmakeuserpresets.json"};
    return steering.contains(name) || lsp_required(path, root);
}
// Drains the root's directory watch (lsp_watch.hpp) into index.pending_changed and says whether the last complete
// listing still holds: the watch confirmed it reported every change, none was lost, and every changed path that
// can matter is an indexed file that still exists. Changes stay pending until a refresh completes, so an
// interrupted refresh loses none. The caller holds the index lock. read_only: no watch, whose sync cookies are
// written below root\.shgrep; every refresh lists the workspace.
bool listing_still_valid(Index& index, const fs::path& root, Clock::time_point deadline, bool read_only) {
    if (read_only) return false;
    if (!index.watch || index.watch_root != path_key(root)) {
        index.listing.clear();
        index.pending_changed.clear();
        index.pending_reload = true;
        index.watch_root = path_key(root);
        // Made before the first listing, so every later change is reported. A watch that cannot be made only costs
        // the listing; the next refresh tries again.
        try {
            index.watch = std::make_unique<DirectoryWatch>(root);
        } catch (const std::exception& error) {
            index.watch.reset();
            index_log(true, std::string("meaning index: no change watch for the listing (") + error.what() + ")");
            return false;
        }
    }
    if (index.watch->failed()) return false;
    const auto wait = std::chrono::milliseconds(std::min<int64_t>(remaining_ms(deadline), 2000));
    const bool confirmed = index.watch->sync(wait) == DirectoryWatch::Sync::confirmed;
    std::vector<fs::path> paths;
    bool reload = false;
    index.watch->take(paths, reload);
    index.pending_reload = index.pending_reload || reload || !confirmed;
    for (auto& path : paths) {
        const std::string key = path_key(path);
        index.pending_changed.emplace(key, std::move(path));
    }
    if (index.pending_reload || index.listing.empty()) return false;
    for (const auto& [key, path] : index.pending_changed) {
        if (index.files.contains(key)) {
            if (lsp_file_stamp(path).empty()) return false;  // deleted, or replaced by a folder or link
        } else if (can_change_listing(path, root)) {
            return false;
        }
    }
    return true;
}

void refresh(const SearchContext& context, Clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled,
             bool lock_workspace, std::unique_lock<std::timed_mutex>& held, MeaningProfile* timings = nullptr) {
    auto& index = meaning_index();
    auto mark = Clock::now();
    std::unique_lock<std::timed_mutex> build(index.build_mutex, std::defer_lock);
    while (!build.try_lock_for(std::chrono::milliseconds(50))) {
        if (cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled");
        if (Clock::now() >= deadline)
            throw std::runtime_error("meaning search timed out: the symbol index is being built (" + progress() + "); retry shortly");
    }
    struct BackgroundGuard {
        std::atomic_bool& active;
        bool enabled;
        ~BackgroundGuard() { if (enabled) active.store(false); }
    } background{index.background_refresh, lock_workspace};
    if (lock_workspace) index.background_refresh.store(true);
    held = std::unique_lock<std::timed_mutex>(index.mutex, std::defer_lock);
    while (!held.try_lock_for(std::chrono::milliseconds(50))) {
        if (cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled");
        if (Clock::now() >= deadline)
            throw std::runtime_error("meaning search timed out: the symbol index is being built (" + progress() + "); retry shortly");
    }
    mark = lap(slot(timings, &MeaningProfile::lock_wait_us), mark);
    const fs::path root = workspace_root(context);
    // Callers have the model ready, so its identity is known; vectors of another model are never mixed in.
    const std::string identity = embed_model_identity();
    const size_t dimensions = embed_dimensions();
    SearchContext quiet = context;
    quiet.record_user_reads = false;  // the index's reads are not the user's reads
    const auto check = [&] {
        if (cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled");
        if (Clock::now() >= deadline)
            throw std::runtime_error("meaning search timed out while building the symbol index (" + progress() + "); retry shortly");
    };
    // Searches may read completed entries while the background builder waits for LSP or the model.
    const auto outside_index_lock = [&](auto&& call) {
        if (!lock_workspace) return call();
        held.unlock();
        try {
            auto result = call();
            held.lock();
            return result;
        } catch (...) {
            held.lock();
            throw;
        }
    };
    // LSP calls take the shared workspace gate when the caller does not hold it (the background builder).
    const auto gated = [&](auto&& call) {
        return outside_index_lock([&] {
            std::shared_lock<std::shared_timed_mutex> gate(workspace_operation_mutex(), std::defer_lock);
            if (lock_workspace)
                while (!gate.try_lock_for(std::chrono::milliseconds(50))) check();
            return call();
        });
    };
    const auto lsp = [&](const std::string& operation, Json::Object arguments) {
        arguments["timeout_ms"] = remaining_ms(deadline);
        return gated([&] { return lsp_query(operation, Json(std::move(arguments)), quiet, cancelled); });
    };
    const auto outline_files = [&](const std::vector<std::string>& paths) {
        return gated([&] { return lsp_outlines(paths, quiet, cancelled, remaining_ms(deadline)); });
    };

    std::vector<std::string> shown_paths;
    const auto list_workspace = [&] {
        set_progress("listing the LSP files under " + utf8(root.wstring()) + " (folders in .shignore are skipped)");
        // source_only: the workspace profile leaves data, generated and vendored files out of the index.
        const Json listing = lsp("files", {{"path", utf8(root.wstring())}, {"source_only", true}});
        shown_paths.clear();
        if (const Json* results = listing.get("results"))
            for (const Json& item : results->array())
                if (const Json* path = item.get("path")) shown_paths.push_back(path->string());
        // SAFETY: a workspace that holds vendored trees (Boost, SDK headers, build folders) would take hours to embed.
        const size_t max_files = max_index_files();
        if (shown_paths.size() > max_files) {
            set_progress("not built: " + std::to_string(shown_paths.size()) + " LSP files, over the limit of " +
                         std::to_string(max_files));
            meaning_failure("the workspace " + utf8(root.wstring()) + " has " + std::to_string(shown_paths.size()) +
                            " LSP source files; the meaning index takes at most " + std::to_string(max_files) +
                            " (SHGREP_MEANING_MAX_FILES). Fix: list vendored and build folders in .shignore "
                            "(for example libs/, build-*/), or raise SHGREP_MEANING_MAX_FILES.");
        }
    };
    // PERF: listing walks the whole workspace (64 ms of a 217 ms search on a 60k-line repository). The last complete
    // listing is reused while the root's watch confirms that only indexed files changed since then.
    bool reuse_listing = listing_still_valid(index, root, deadline, context.read_only);
    if (reuse_listing) shown_paths = index.listing;
    else list_workspace();
    mark = lap(slot(timings, &MeaningProfile::listing_us), mark);

    // Listing prepares the effective C++ setup; fingerprint the resulting configuration afterwards.
    std::string setup = gated([&] { return lsp_index_fingerprint(quiet, root, cancelled); });
    std::string profile = source_text_digest(identity + "\n" + setup);
    if (reuse_listing && (index.root != path_key(root) || index.profile != profile)) {
        // A configuration change can change which files are listed, and the watch never reports .shgrep\lsp.json.
        reuse_listing = false;
        list_workspace();
        setup = gated([&] { return lsp_index_fingerprint(quiet, root, cancelled); });
        profile = source_text_digest(identity + "\n" + setup);
    }
    mark = lap(slot(timings, &MeaningProfile::fingerprint_us), mark);
    if (index.root != path_key(root) || index.profile != profile) {
        index.files.clear();
        index.root = path_key(root);
        index.profile = profile;
        index.dirty = false;
        index.disk_checked = false;
    }
    if (!index.disk_checked && !identity.empty()) {
        index.disk_checked = true;
        set_progress("reading the saved index " + utf8(saved_path(root, profile).wstring()));
        try {
            auto saved = outside_index_lock([&] { return read_saved(root, identity, dimensions, profile, check); });
            index.files = std::move(saved);
        } catch (const std::exception& error) {
            index.files.clear();
            // Interrupted, not unusable: the next refresh reads it again.
            if ((cancelled && cancelled->load()) || Clock::now() >= deadline) {
                index.disk_checked = false;
                throw;
            }
            index_log(true, "meaning index: " + utf8(saved_path(root, profile).wstring()) + " not used (" +
                           error.what() + "); rebuilding it");
        }
    }

    mark = lap(slot(timings, &MeaningProfile::saved_read_us), mark);
    std::set<std::string> listed;
    std::vector<std::pair<std::string, FileEntry>> pending;  // parsed, waiting for vectors
    size_t pending_chunks = 0, embedded = 0, done = 0;
    uint64_t skipped = 0;
    std::vector<std::string> skipped_why;  // the first few skipped files and why, for the progress line
    const auto note_skip = [&](const std::string& path, const std::string& why) {
        if (skipped_why.size() < 5) skipped_why.push_back(path + " (" + why + ")");
    };
    const auto flush = [&] {
        // The model sees what each chunk is: "title: rank.cpp | text: shgrep/Ranker::rank\n<code>".
        std::vector<EmbedDocument> documents;
        std::vector<Chunk*> targets;
        std::vector<std::string> titles, texts;
        titles.reserve(pending_chunks);
        texts.reserve(pending_chunks);
        for (auto& [key, entry] : pending)
            for (auto& chunk : entry.chunks) {
                titles.push_back(file_name(entry.shown));
                texts.push_back(chunk.name_path + "\n" + chunk.text);
                targets.push_back(&chunk);
            }
        documents.reserve(targets.size());
        for (size_t i = 0; i < targets.size(); ++i) documents.push_back({titles[i], texts[i]});
        std::vector<std::vector<float>> vectors;
        try {
            vectors = outside_index_lock([&] { return embed_documents(documents, deadline, cancelled); });
        } catch (const EmbedFailure& error) {
            meaning_failure(std::string(error.what()) + ".");
        }
        for (size_t i = 0; i < targets.size(); ++i) targets[i]->vector = std::move(vectors[i]);
        for (auto& [key, entry] : pending) {
            index.files[key] = std::move(entry);
            index.dirty = true;
        }
        embedded += targets.size();
        pending.clear();
        pending_chunks = 0;
    };
    // Pass 1: which files changed since they were indexed (reads only; cheap).
    struct Changed {
        std::string key, shown;
        SourceText source;
        std::string stamp;
    };
    std::vector<Changed> changed;
    for (const auto& shown : shown_paths) {
        check();
        ++done;
        if ((done & 63) == 0)
            set_progress("checked " + std::to_string(done) + " of " + std::to_string(shown_paths.size()) + " files for changes");
        const std::string key = key_of(root, shown);
        listed.insert(key);
        const auto known = index.files.find(key);
        const bool indexed = known != index.files.end() && !known->second.sha256.empty();
        // The watch reported no change to this file since the last complete refresh.
        if (reuse_listing && indexed && !index.pending_changed.contains(key)) continue;
        // PERF: same size and write time as when its hash was taken, so it is not read again (124 ms per search for
        // 231 files before); the symbol index keys its entries the same way. The stamp is taken before the read, so
        // a change during the read only causes a later re-read.
        const std::string stamp = lsp_file_stamp(absolute_of(root, shown));
        if (indexed && !stamp.empty() && known->second.stamp == stamp) continue;
        SourceText source;
        try {
            source = outside_index_lock([&] { return read_source_text(quiet, shown); });
        } catch (const std::exception&) {
            check();  // Cancellation/deadline must not become a skipped file.
            ++skipped;  // Keep the saved entry until the file can be read again.
            note_skip(shown, "unreadable");
            continue;
        }
        if (const auto found = index.files.find(key); found != index.files.end() && !found->second.sha256.empty() &&
                                                      found->second.sha256 == source.sha256) {
            found->second.stamp = stamp;  // same text under a new stamp: touched, or loaded from the saved index
            continue;
        }
        changed.push_back({key, shown, std::move(source), stamp});
    }
    mark = lap(slot(timings, &MeaningProfile::change_check_us), mark);
    if (timings) {
        timings->files_listed = shown_paths.size();
        timings->files_changed = changed.size();
    }
    // Pass 2: outlines of the changed files, many at once (lsp_outlines keeps one request per hardware thread in
    // flight), then chunks and vectors.
    constexpr size_t outline_group = 64;
    for (size_t first = 0; first < changed.size(); first += outline_group) {
        check();
        const size_t last = std::min(changed.size(), first + outline_group);
        set_progress("outlined " + std::to_string(first) + " of " + std::to_string(changed.size()) + " changed files (" +
                     std::to_string(shown_paths.size()) + " in the workspace), embedded " + std::to_string(embedded) +
                     " new chunks");
        std::vector<std::string> paths;
        paths.reserve(last - first);
        for (size_t i = first; i < last; ++i) paths.push_back(changed[i].shown);
        Json outlines;
        try {
            outlines = outline_files(paths);
        } catch (const std::runtime_error& error) {
            if (std::string_view(error.what()).starts_with("meaning search")) throw;
            check();
            skipped += last - first;  // their server failed; the next refresh tries again
            for (size_t i = first; i < last; ++i) note_skip(changed[i].shown, error.what());
            continue;
        }
        const Json* files = outlines.get("files");
        for (size_t i = first; i < last; ++i) {
            const Json* file = files && i - first < files->array().size() ? &files->array()[i - first] : nullptr;
            const Json* outline = file ? file->get("outline") : nullptr;
            if (!outline || !outline->get("results") ||
                !std::holds_alternative<Json::Array>(outline->get("results")->value)) {
                ++skipped;
                const Json* error = file ? file->get("error") : nullptr;
                note_skip(changed[i].shown, error && std::holds_alternative<std::string>(error->value) ? error->string()
                                                                                                    : "no outline");
                continue;
            }
            const Json* revision = file->get("sha256");
            if (!revision || revision->string() != changed[i].source.sha256) {
                ++skipped;  // The file changed between the source read and its outline.
                note_skip(changed[i].shown, "changed while indexing");
                continue;
            }
            const Json* partial = outline->get("partial");
            if (partial && partial->boolean()) {
                ++skipped;
                note_skip(changed[i].shown, "partial outline: its server was still indexing");
                continue;
            }
            FileEntry entry{changed[i].source.sha256, changed[i].shown,
                            chunk_file(changed[i].source.text, *outline), changed[i].stamp};
            pending_chunks += entry.chunks.size();
            pending.emplace_back(changed[i].key, std::move(entry));
            if (pending_chunks >= embed_group) flush();
        }
    }
    if (!pending.empty()) flush();
    mark = lap(slot(timings, &MeaningProfile::outline_embed_us), mark);
    for (auto it = index.files.begin(); it != index.files.end();) {
        if (listed.contains(it->first)) {
            ++it;
        } else {
            it = index.files.erase(it);
            index.dirty = true;
        }
    }
    index.skipped = skipped;
    size_t chunks = 0;
    for (const auto& [key, entry] : index.files) chunks += entry.chunks.size();
    set_progress(std::string(skipped ? "incomplete: " : "ready: ") + std::to_string(chunks) + " chunks in " + std::to_string(index.files.size()) + " files" +
                 (skipped ? ", " + std::to_string(skipped) + " files skipped: " + [&] {
                     std::string list;
                     for (const auto& item : skipped_why) list += (list.empty() ? "" : "; ") + item;
                     return list + (skipped > skipped_why.size() ? "; ..." : "");
                 }() : ""));
    mark = lap(slot(timings, &MeaningProfile::finish_us), mark);
    const std::string setup_after = gated([&] { return lsp_index_fingerprint(quiet, root, cancelled); });
    mark = lap(slot(timings, &MeaningProfile::fingerprint_us), mark);
    if (setup_after != setup)
        meaning_failure("language-server configuration changed while indexing; retry with the current setup.");
    // This refresh saw every change taken from the watch; a skipped file needs a full listing to be retried.
    if (skipped) {
        index.listing.clear();
    } else {
        index.listing = shown_paths;
        index.pending_changed.clear();
        index.pending_reload = false;
    }
    if (skipped) {
        if (lock_workspace) return;  // Background indexing retains its existing bounded retry loop.
        meaning_failure(std::to_string(skipped) + " source file(s) could not be indexed completely; "
                        "the saved index was preserved. Fix the language-server/read errors and retry.");
    }
    if (index.dirty && !context.read_only && !identity.empty()) {
        try {
            write_saved(index, context, root, identity, dimensions);
            index.dirty = false;
        } catch (const std::exception& error) {
            index_log(true, "meaning index: cannot save " + utf8(saved_path(root, index.profile).wstring()) + " (" + error.what() + ")");
        }
    }
    lap(slot(timings, &MeaningProfile::finish_us), mark);
}

std::vector<float> question_vector(const std::string& question, Clock::time_point deadline,
                                   const std::shared_ptr<std::atomic_bool>& cancelled) {
    try {
        return embed_query(question, deadline, cancelled);
    } catch (const EmbedFailure& error) {
        meaning_failure(std::string(error.what()) + ".");
    }
}

double dot(const std::vector<float>& a, const std::vector<float>& b) {
    double sum = 0;
    const size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) sum += static_cast<double>(a[i]) * b[i];
    return sum;
}

std::vector<double> scaled(const std::vector<double>& values) {
    std::vector<double> out(values.size(), 0.0);
    if (values.empty()) return out;
    const auto [low, high] = std::minmax_element(values.begin(), values.end());
    if (*high > *low)
        for (size_t i = 0; i < values.size(); ++i) out[i] = (values[i] - *low) / (*high - *low);
    return out;
}
}

double meaning_weight() {
    wchar_t value[16] = {};
    const DWORD size = GetEnvironmentVariableW(L"SHGREP_MEANING_WEIGHT", value, 16);
    if (!size) return 0.9;
    wchar_t* end = nullptr;
    const long percent = size < 16 ? std::wcstol(value, &end, 10) : -1;
    if (!end || *end || end == value || percent < 0 || percent > 100)
        meaning_failure("SHGREP_MEANING_WEIGHT must be a number from 0 to 100.");
    return static_cast<double>(percent) / 100.0;
}

void start_meaning_index(const SearchContext& context) {
    if (!embed_built() || context.allowed_roots.empty()) return;
    auto& b = builder();
    std::lock_guard lock(b.mutex);
    if (b.thread.joinable() || b.stop->load()) return;
    // SAFETY (F5): joined by stop_meaning_index before the server returns, and cancelled through `stop`, so it never
    // runs while static state it uses (LSP sessions, logs) is destroyed. The thread keeps its own copy of the context.
    b.thread = std::thread([context, stop = b.stop] {
        try {
            // Waits for the model (its own failure is reported by the first question), then builds the index.
            (void)embed_query("ready", Clock::now() + std::chrono::hours(1), stop);
            // Files whose language server was still starting are skipped; try those again a few times.
            for (int attempt = 0; attempt < 5 && !stop->load(); ++attempt) {
                bool complete = false;
                {
                    std::unique_lock<std::timed_mutex> held;
                    refresh(context, Clock::now() + std::chrono::hours(6), stop, true, held);
                    complete = meaning_index().skipped == 0;
                }
                index_log(false, "meaning index " + progress());
                if (complete) break;
                for (int waited = 0; waited < 300 && !stop->load(); ++waited)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        } catch (const std::exception& error) {
            if (!stop->load()) index_log(true, std::string("meaning index not built: ") + error.what());
        }
    });
}

void stop_meaning_index() {
    auto& b = builder();
    std::thread thread;
    {
        std::lock_guard lock(b.mutex);
        b.stop->store(true);
        thread = std::move(b.thread);
    }
    if (thread.joinable()) thread.join();
}

Json meaning_search(const Json& arguments, const SearchContext& context,
                    const std::shared_ptr<std::atomic_bool>& cancelled) {
    const Json* intent_field = arguments.get("intent");
    const std::string question = intent_field ? intent_field->string() : std::string();
    if (question.find_first_not_of(" \t\r\n") == std::string::npos)
        throw std::runtime_error("operation=meaning requires intent: the question in words, for example "
                                 "\"where are deleted objects removed from culling\"");
    if (question.size() > 4096) throw std::runtime_error("intent is at most 4096 UTF-8 bytes");
    if (!embed_built())
        meaning_failure("this shgrep build has no meaning search (portable build); use the GPU build for operation=meaning.");
    int64_t limit = 10;
    if (const Json* field = arguments.get("max_results")) limit = field->integer();
    if (limit < 1 || limit > 1000) throw std::runtime_error("max_results must be 1-1000 for operation=meaning");
    int64_t timeout = 180000;
    if (const Json* field = arguments.get("timeout_ms")) timeout = field->integer();
    if (timeout < 1 || timeout > 300000) throw std::runtime_error("timeout_ms must be 1-300000");
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout);
    const double weight = meaning_weight();
    MeaningProfile profile_data;
    const Json* profile_field = arguments.get("profile");
    MeaningProfile* profile = profile_field && profile_field->boolean() ? &profile_data : nullptr;
    const auto search_started = Clock::now();

    const std::vector<float> q = question_vector(question, deadline, cancelled);
    auto mark = lap(slot(profile, &MeaningProfile::embed_query_us), search_started);
    auto& index = meaning_index();
    const fs::path root = workspace_root(context);
    std::unique_lock<std::timed_mutex> held(index.mutex, std::defer_lock);
    bool partial = false;
    if (index.background_refresh.load()) {
        // An empty partial answer reads as "nothing found" and makes agents rephrase the query many times.
        // Keep the first search waiting (bounded) until the index has files, so it returns something useful.
        const auto useful_by = std::min(deadline, Clock::now() + std::chrono::milliseconds(20000));
        for (;;) {
            while (!held.try_lock_for(std::chrono::milliseconds(50))) {
                if (cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled");
                if (Clock::now() >= deadline)
                    throw std::runtime_error("meaning search timed out waiting for the index (" + progress() + ")");
            }
            partial = index.background_refresh.load();
            if (!partial) { held.unlock(); break; }
            if (!index.files.empty() || Clock::now() >= useful_by) break;
            held.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    mark = lap(slot(profile, &MeaningProfile::lock_wait_us), mark);
    if (!partial) refresh(context, deadline, cancelled, false, held, profile);
    mark = Clock::now();  // refresh recorded its own phases
    std::string scope;
    if (const Json* path = arguments.get("path"); path && !path->string().empty()) scope = key_of(root, path->string());

    struct Ref {
        const FileEntry* file;
        const Chunk* chunk;
    };
    std::vector<Ref> refs;
    std::vector<RankCandidate> candidates;
    std::vector<std::string> documents;  // name path + chunk text, the BM25 document
    const bool same_root = index.root == path_key(root);
    for (const auto& [key, entry] : index.files) {
        if (!same_root) break;
        if (!scope.empty() && key != scope && !(key.starts_with(scope) && key.size() > scope.size() && key[scope.size()] == '\\'))
            continue;
        for (const auto& chunk : entry.chunks) refs.push_back({&entry, &chunk});
    }
    documents.reserve(refs.size());
    for (const auto& ref : refs) documents.push_back(ref.chunk->text);
    candidates.reserve(refs.size());
    for (size_t i = 0; i < refs.size(); ++i)
        candidates.push_back({refs[i].file->shown, refs[i].chunk->first, refs[i].chunk->last, documents[i],
                              refs[i].chunk->name_path});
    if (profile) profile->chunks = refs.size();
    mark = lap(slot(profile, &MeaningProfile::collect_us), mark);
    std::vector<double> dense(refs.size());
    for (size_t i = 0; i < refs.size(); ++i) {
        if ((i & 1023) == 0 && cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled");
        dense[i] = dot(q, refs[i].chunk->vector);
    }
    const std::vector<double> d = scaled(dense);
    mark = lap(slot(profile, &MeaningProfile::dense_us), mark);
    const std::vector<double> b = scaled(bm25_scores(question, candidates, cancelled));
    mark = lap(slot(profile, &MeaningProfile::bm25_us), mark);
    std::vector<size_t> order(refs.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::vector<double> score(refs.size());
    for (size_t i = 0; i < refs.size(); ++i) score[i] = weight * d[i] + (1 - weight) * b[i];
    std::stable_sort(order.begin(), order.end(), [&](size_t x, size_t y) { return score[x] > score[y]; });
    mark = lap(slot(profile, &MeaningProfile::rank_us), mark);

    // Adaptive-k (Taguchi et al., EMNLP 2025): a clear drop after the top results means the rest is noise.
    // Stay at the requested limit when the score distribution is flat.
    int64_t shown_limit = limit;
    if (order.size() > 3) {
        const size_t cap = std::min<size_t>(order.size() - 1, static_cast<size_t>(limit));
        size_t cut = 0;
        double best_gap = 0.0;
        for (size_t k = 3; k < cap; ++k) {
            const double gap = score[order[k - 1]] - score[order[k]];
            if (gap > best_gap) { best_gap = gap; cut = k; }
        }
        if (cut > 0 && best_gap >= 0.01) shown_limit = static_cast<int64_t>(cut);
    }

    std::string text = "[meaning " + std::to_string(static_cast<int>(weight * 100 + 0.5)) + "% + bm25 " +
                       std::to_string(100 - static_cast<int>(weight * 100 + 0.5)) + "%; index " + progress() +
                       "; model " + embedder_state() + "]\n";
    if (partial) text += "[partial results: the index is building; results may be incomplete or stale]\n";
    if (shown_limit < limit)
        text += "[showing " + std::to_string(shown_limit) + " of up to " + std::to_string(limit) +
                " results: largest score gap]\n";
    Json::Array results;
    std::set<std::string> seen;
    const auto snippet_of = [](const std::string& body, size_t max_lines, size_t max_bytes) {
        std::string out;
        size_t at = 0, lines = 0;
        while (at < body.size() && lines < max_lines && out.size() < max_bytes) {
            size_t end = body.find('\n', at);
            if (end == std::string::npos) end = body.size();
            std::string line = body.substr(at, end - at);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            size_t cut = std::min(line.size(), max_bytes - out.size());
            while (cut > 0 && cut < line.size() && (static_cast<unsigned char>(line[cut]) & 0xc0) == 0x80) --cut;
            out.append(line, 0, cut);
            if (cut < line.size()) { out += "..."; break; }
            out += '\n';
            ++lines;
            at = end + 1;
        }
        return out;
    };
    for (size_t i : order) {
        if (static_cast<int64_t>(results.size()) >= shown_limit) break;
        const Ref& ref = refs[i];
        const std::string key = ref.file->shown + "\n" + ref.chunk->name_path + "\n" + std::to_string(ref.chunk->start);
        if (!seen.insert(key).second) continue;
        char shown_score[32];
        std::snprintf(shown_score, sizeof(shown_score), "%.3f", score[i]);
        text += ref.file->shown + ":" + std::to_string(ref.chunk->start) + "-" + std::to_string(ref.chunk->end) + " " +
                ref.chunk->kind + " " + ref.chunk->name_path + " (score " + shown_score + ", best part lines " +
                std::to_string(ref.chunk->first) + "-" + std::to_string(ref.chunk->last) + ")\n";
        Json::Object row{{"path", ref.file->shown}, {"name_path", ref.chunk->name_path},
                         {"kind_name", ref.chunk->kind}, {"start_line", static_cast<int64_t>(ref.chunk->start)},
                         {"end_line", static_cast<int64_t>(ref.chunk->end)},
                         {"first_line", static_cast<int64_t>(ref.chunk->first)},
                         {"last_line", static_cast<int64_t>(ref.chunk->last)}, {"score", score[i]}};
        if (ref.chunk->kind == "text") {
            row["body"] = ref.chunk->text;
            text += ref.chunk->text + "\n";
        } else {
            // A short head lets the agent judge a hit without a second read_symbol call.
            const bool top = results.empty();
            const std::string snippet = snippet_of(ref.chunk->text, top ? 10u : 4u, top ? 1200u : 400u);
            row["snippet"] = snippet;
            std::string marked;
            for (char c : snippet) {
                marked += c;
                if (c == '\n') marked += "  | ";
            }
            if (!snippet.empty() && snippet.back() != '\n') marked += '\n';
            text += "  | " + marked;
        }
        results.push_back(std::move(row));
    }
    if (results.empty()) text += "No indexed symbols" + std::string(scope.empty() ? "" : " under that path") + ".\n";
    else text += "[snippets show the start of each symbol; lsp.read_symbol returns the rest; text chunks include their body; follow callers with lsp.find_referencing_symbols]\n";
    if (profile) {
        lap(slot(profile, &MeaningProfile::format_us), mark);
        lap(slot(profile, &MeaningProfile::total_us), search_started);
    }
    if (const Json* format = arguments.get("output"); format && format->string() == "json") {
        Json::Object reply{{"results", std::move(results)}, {"index", progress()}, {"partial", partial},
                           {"model", embedder_state()}, {"cache_path", utf8(saved_path(root, index.profile).wstring())}};
        if (profile) reply["profile"] = profile->json();
        return Json::Object{{"text", Json(std::move(reply)).dump() + "\n"}};
    }
    if (profile) text += "[profile " + profile->json().dump() + "]\n";
    return Json::Object{{"text", std::move(text)}};
}

Ranker::DenseScorer meaning_hunk_scorer(const std::string& intent, const SearchContext& context,
                                        EmbedClock::time_point deadline) {
    return [intent, context, deadline](const std::vector<RankCandidate>& candidates,
                                       const std::shared_ptr<std::atomic_bool>& cancelled) {
        const std::vector<float> q = question_vector(intent, deadline, cancelled);
        std::unique_lock<std::timed_mutex> held;
        refresh(context, deadline, cancelled, false, held);
        auto& index = meaning_index();
        const fs::path root = workspace_root(context);
        std::unordered_map<std::string_view, const FileEntry*> by_path;  // candidate path -> entry
        std::vector<double> scores(candidates.size(), -1.0);
        for (size_t i = 0; i < candidates.size(); ++i) {
            if ((i & 1023) == 0 && cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled");
            const RankCandidate& candidate = candidates[i];
            auto [it, added] = by_path.try_emplace(candidate.path, nullptr);
            if (added) {
                const auto found = index.files.find(key_of(root, candidate.path));
                it->second = found == index.files.end() ? nullptr : &found->second;
            }
            if (!it->second) continue;
            double best = -1.0;
            for (const Chunk& chunk : it->second->chunks) {
                const bool overlaps = !candidate.first_line ||
                    (chunk.first <= candidate.last_line && candidate.first_line <= chunk.last);
                if (overlaps) best = std::max(best, dot(q, chunk.vector));
            }
            scores[i] = best;
        }
        return scores;
    };
}
}
