#include "meaning.hpp"

#include "files.hpp"
#include "lsp.hpp"
#include "winfs.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <map>
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
};
struct Index {
    std::timed_mutex mutex;  // one refresh at a time; held while reading the files below
    std::mutex progress_mutex;
    std::string progress = "not built yet";
    std::string root;                          // normalized key of the workspace root
    std::map<std::string, FileEntry> files;   // normalized absolute path -> entry
    uint64_t skipped = 0;                      // files whose outline failed in the last refresh
    bool disk_checked = false;                 // the saved index was read (or found unusable) for this root
};
Index& meaning_index() {
    static Index index;
    return index;
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
std::string key_of(const fs::path& root, std::string_view shown) {
    std::wstring wide;
    if (!shown.empty()) {
        const int size = MultiByteToWideChar(CP_UTF8, 0, shown.data(), static_cast<int>(shown.size()), nullptr, 0);
        wide.resize(static_cast<size_t>(std::max(size, 0)));
        if (size > 0) MultiByteToWideChar(CP_UTF8, 0, shown.data(), static_cast<int>(shown.size()), wide.data(), size);
    }
    const fs::path path(wide);
    return path_key(path.is_absolute() ? path : root / path);
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
        Chunk part{name->string(), kind->string(), start, end, first, first, {}, {}};
        size_t size = 0;
        const auto close = [&] {
            if (std::any_of(part.text.begin(), part.text.end(), [](char c) { return c != ' ' && c != '\t' && c != '\n'; }))
                chunks.push_back(part);
        };
        for (uint32_t line = first; line <= last; ++line) {
            const std::string_view content = lines[line - 1];
            if (!part.text.empty() && size + content.size() + 1 > max_chunk_chars) {
                close();
                part.text.clear();
                part.first = line;
                size = 0;
            }
            if (!part.text.empty()) part.text.push_back('\n');
            part.text.append(content.substr(0, max_chunk_chars));
            part.last = line;
            size += content.size() + 1;
        }
        close();
    }
    return chunks;
}

std::string file_name(std::string_view shown) {
    const size_t slash = shown.find_last_of("/\\");
    return std::string(slash == std::string_view::npos ? shown : shown.substr(slash + 1));
}

// The saved index: <workspace>\.shgrep\meaning.idx, rewritten after a refresh that changed anything and read once
// per process, so a restart re-embeds only files whose bytes changed. Layout (little-endian): "SHGMEAN1", u32
// version, identity string, u64 dimensions, u64 files; per file: key, sha256, shown path, u64 chunks; per chunk:
// name path, kind, u32 start, end, first, last, text, dimensions x f32. Strings are u64 length + bytes.
constexpr char saved_magic[8] = {'S', 'H', 'G', 'M', 'E', 'A', 'N', '1'};
constexpr uint32_t saved_version = 2;  // bump when the chunk rules, the embedded text or this layout change

fs::path saved_path(const fs::path& root) {
    return root / L".shgrep" / L"meaning.idx";
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

std::map<std::string, FileEntry> read_saved(const fs::path& root, const std::string& identity, size_t dimensions) {
    std::ifstream file(saved_path(root), std::ios::binary);
    if (!file) return {};  // nothing saved yet
    std::string bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    SavedReader in{bytes};
    in.need(sizeof(saved_magic));
    if (std::memcmp(bytes.data(), saved_magic, sizeof(saved_magic)) != 0) throw std::runtime_error("not a meaning index");
    in.at = sizeof(saved_magic);
    if (in.u32() != saved_version) throw std::runtime_error("older layout or chunk rules");
    if (in.string() != identity) throw std::runtime_error("made with another embedding model");
    if (in.u64() != dimensions) throw std::runtime_error("other vector length");
    std::map<std::string, FileEntry> files;
    const uint64_t count = in.u64();
    for (uint64_t f = 0; f < count; ++f) {
        std::string key = in.string();
        FileEntry entry;
        entry.sha256 = in.string();
        entry.shown = in.string();
        const uint64_t chunks = in.u64();
        in.need(chunks);  // each chunk takes far more than one byte; stops absurd counts before reserving
        entry.chunks.reserve(static_cast<size_t>(chunks));
        for (uint64_t c = 0; c < chunks; ++c) {
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
    create_workspace_metadata_directory(context, root / L".shgrep");
    write_workspace_metadata(context, saved_path(root), out);
}

// Brings the index up to date with the workspace's LSP files. Holds the index lock until it returns; on the
// deadline it keeps what it finished and throws with the progress. lock_workspace: take the shared workspace gate
// around LSP calls (the background builder; tool requests already hold it).
void refresh(const SearchContext& context, Clock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled,
             bool lock_workspace, std::unique_lock<std::timed_mutex>& held) {
    auto& index = meaning_index();
    held = std::unique_lock<std::timed_mutex>(index.mutex, std::defer_lock);
    while (!held.try_lock_for(std::chrono::milliseconds(50))) {
        if (cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled");
        if (Clock::now() >= deadline)
            throw std::runtime_error("meaning search timed out: the symbol index is being built (" + progress() + "); retry shortly");
    }
    const fs::path root = workspace_root(context);
    if (index.root != path_key(root)) {
        index.files.clear();
        index.root = path_key(root);
        index.disk_checked = false;
    }
    // Callers have the model ready, so its identity is known; vectors of another model are never mixed in.
    const std::string identity = embed_model_identity();
    const size_t dimensions = embed_dimensions();
    if (!index.disk_checked && !identity.empty()) {
        index.disk_checked = true;
        set_progress("reading the saved index " + utf8(saved_path(root).wstring()));
        try {
            index.files = read_saved(root, identity, dimensions);
        } catch (const std::exception& error) {
            index.files.clear();
            index_log(true, "meaning index: " + utf8(saved_path(root).wstring()) + " not used (" + error.what() +
                            "); rebuilding it");
        }
    }
    SearchContext quiet = context;
    quiet.record_user_reads = false;  // the index's reads are not the user's reads
    const auto check = [&] {
        if (cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled");
        if (Clock::now() >= deadline)
            throw std::runtime_error("meaning search timed out while building the symbol index (" + progress() + "); retry shortly");
    };
    // LSP calls take the shared workspace gate when the caller does not hold it (the background builder).
    const auto gated = [&](auto&& call) {
        std::shared_lock<std::shared_timed_mutex> gate(workspace_operation_mutex(), std::defer_lock);
        if (lock_workspace)
            while (!gate.try_lock_for(std::chrono::milliseconds(50))) check();
        return call();
    };
    const auto lsp = [&](const std::string& operation, Json::Object arguments) {
        arguments["timeout_ms"] = remaining_ms(deadline);
        return gated([&] { return lsp_query(operation, Json(std::move(arguments)), quiet, cancelled); });
    };
    const auto outline_files = [&](const std::vector<std::string>& paths) {
        return gated([&] { return lsp_outlines(paths, quiet, cancelled, remaining_ms(deadline)); });
    };

    set_progress("listing the LSP files under " + utf8(root.wstring()) + " (folders in .shignore are skipped)");
    const Json listing = lsp("files", {{"path", utf8(root.wstring())}});
    std::vector<std::string> shown_paths;
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

    std::set<std::string> listed;
    std::vector<std::pair<std::string, FileEntry>> pending;  // parsed, waiting for vectors
    size_t pending_chunks = 0, embedded = 0, done = 0, removed = 0, updated = 0;
    uint64_t skipped = 0;
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
            vectors = embed_documents(documents, deadline, cancelled);
        } catch (const EmbedFailure& error) {
            meaning_failure(std::string(error.what()) + ".");
        }
        for (size_t i = 0; i < targets.size(); ++i) targets[i]->vector = std::move(vectors[i]);
        for (auto& [key, entry] : pending) index.files[key] = std::move(entry);
        embedded += targets.size();
        pending.clear();
        pending_chunks = 0;
    };
    // Pass 1: which files changed since they were indexed (reads only; cheap).
    struct Changed {
        std::string key, shown;
        SourceText source;
    };
    std::vector<Changed> changed;
    for (const auto& shown : shown_paths) {
        check();
        ++done;
        if ((done & 63) == 0)
            set_progress("checked " + std::to_string(done) + " of " + std::to_string(shown_paths.size()) + " files for changes");
        const std::string key = key_of(root, shown);
        listed.insert(key);
        SourceText source;
        try {
            source = read_source_text(quiet, shown);
        } catch (const std::exception&) {
            removed += index.files.erase(key);  // unreadable or not Unicode text: not indexed
            continue;
        }
        if (const auto found = index.files.find(key); found != index.files.end() && !found->second.sha256.empty() &&
                                                      found->second.sha256 == source.sha256)
            continue;
        changed.push_back({key, shown, std::move(source)});
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
            for (size_t i = first; i < last; ++i) removed += index.files.erase(changed[i].key);
            continue;
        }
        const Json* files = outlines.get("files");
        for (size_t i = first; i < last; ++i) {
            const Json* file = files && i - first < files->array().size() ? &files->array()[i - first] : nullptr;
            const Json* outline = file ? file->get("outline") : nullptr;
            if (!outline) {
                ++skipped;
                removed += index.files.erase(changed[i].key);
                continue;
            }
            const Json* partial = outline->get("partial");
            FileEntry entry{partial && partial->boolean() ? std::string() : changed[i].source.sha256, changed[i].shown,
                            chunk_file(changed[i].source.text, *outline)};
            pending_chunks += entry.chunks.size();
            pending.emplace_back(changed[i].key, std::move(entry));
            ++updated;  // re-chunked, even when it has no chunks now
            if (pending_chunks >= embed_group) flush();
        }
    }
    if (!pending.empty()) flush();
    for (auto it = index.files.begin(); it != index.files.end();) {
        if (listed.contains(it->first)) {
            ++it;
        } else {
            it = index.files.erase(it);
            ++removed;
        }
    }
    index.skipped = skipped;
    size_t chunks = 0;
    for (const auto& [key, entry] : index.files) chunks += entry.chunks.size();
    set_progress("ready: " + std::to_string(chunks) + " chunks in " + std::to_string(index.files.size()) + " files" +
                 (skipped ? ", " + std::to_string(skipped) + " files skipped (their language server failed)" : ""));
    if ((updated || removed) && !context.read_only && !identity.empty()) {
        try {
            write_saved(index, context, root, identity, dimensions);
        } catch (const std::exception& error) {
            index_log(true, "meaning index: cannot save " + utf8(saved_path(root).wstring()) + " (" + error.what() + ")");
        }
    }
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
    // The context outlives the server loop; the thread keeps its own copy.
    std::thread([context] {
        try {
            // Waits for the model (its own failure is reported by the first question), then builds the index.
            (void)embed_query("ready", Clock::now() + std::chrono::hours(1), {});
            // Files whose language server was still starting are skipped; try those again a few times.
            for (int attempt = 0; attempt < 5; ++attempt) {
                {
                    std::unique_lock<std::timed_mutex> held;
                    refresh(context, Clock::now() + std::chrono::hours(6), {}, true, held);
                }
                index_log(false, "meaning index " + progress());
                if (!meaning_index().skipped) break;
                std::this_thread::sleep_for(std::chrono::seconds(30));
            }
        } catch (const std::exception& error) {
            index_log(true, std::string("meaning index not built: ") + error.what());
        }
    }).detach();
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

    const std::vector<float> q = question_vector(question, deadline, cancelled);
    std::unique_lock<std::timed_mutex> held;
    refresh(context, deadline, cancelled, false, held);
    auto& index = meaning_index();
    const fs::path root = workspace_root(context);
    std::string scope;
    if (const Json* path = arguments.get("path"); path && !path->string().empty()) scope = key_of(root, path->string());

    struct Ref {
        const FileEntry* file;
        const Chunk* chunk;
    };
    std::vector<Ref> refs;
    std::vector<RankCandidate> candidates;
    std::vector<std::string> documents;  // name path + chunk text, the BM25 document
    for (const auto& [key, entry] : index.files) {
        if (!scope.empty() && key != scope && !(key.starts_with(scope) && key.size() > scope.size() && key[scope.size()] == '\\'))
            continue;
        for (const auto& chunk : entry.chunks) refs.push_back({&entry, &chunk});
    }
    documents.reserve(refs.size());
    for (const auto& ref : refs) documents.push_back(ref.chunk->name_path + "\n" + ref.chunk->text);
    candidates.reserve(refs.size());
    for (size_t i = 0; i < refs.size(); ++i)
        candidates.push_back({refs[i].file->shown, refs[i].chunk->first, refs[i].chunk->last, documents[i]});
    std::vector<double> dense(refs.size());
    for (size_t i = 0; i < refs.size(); ++i) {
        if ((i & 1023) == 0 && cancelled && cancelled->load()) throw std::runtime_error("meaning search cancelled");
        dense[i] = dot(q, refs[i].chunk->vector);
    }
    const std::vector<double> d = scaled(dense), b = scaled(bm25_scores(question, candidates, cancelled));
    std::vector<size_t> order(refs.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::vector<double> score(refs.size());
    for (size_t i = 0; i < refs.size(); ++i) score[i] = weight * d[i] + (1 - weight) * b[i];
    std::stable_sort(order.begin(), order.end(), [&](size_t x, size_t y) { return score[x] > score[y]; });

    std::string text = "[meaning " + std::to_string(static_cast<int>(weight * 100 + 0.5)) + "% + bm25 " +
                       std::to_string(100 - static_cast<int>(weight * 100 + 0.5)) + "%; index " + progress() +
                       "; model " + embedder_state() + "]\n";
    Json::Array results;
    std::set<std::string> seen;
    for (size_t i : order) {
        if (static_cast<int64_t>(results.size()) >= limit) break;
        const Ref& ref = refs[i];
        const std::string key = ref.file->shown + "\n" + ref.chunk->name_path + "\n" + std::to_string(ref.chunk->start);
        if (!seen.insert(key).second) continue;
        char shown_score[32];
        std::snprintf(shown_score, sizeof(shown_score), "%.3f", score[i]);
        text += ref.file->shown + ":" + std::to_string(ref.chunk->start) + "-" + std::to_string(ref.chunk->end) + " " +
                ref.chunk->kind + " " + ref.chunk->name_path + " (score " + shown_score + ", best part lines " +
                std::to_string(ref.chunk->first) + "-" + std::to_string(ref.chunk->last) + ")\n";
        results.push_back(Json::Object{{"path", ref.file->shown}, {"name_path", ref.chunk->name_path},
                                       {"kind_name", ref.chunk->kind}, {"start_line", static_cast<int64_t>(ref.chunk->start)},
                                       {"end_line", static_cast<int64_t>(ref.chunk->end)}, {"score", score[i]}});
    }
    if (results.empty()) text += "No indexed symbols" + std::string(scope.empty() ? "" : " under that path") + ".\n";
    else text += "[read one with lsp.read_symbol name_path and path; follow callers with lsp.find_referencing_symbols]\n";
    if (const Json* format = arguments.get("output"); format && format->string() == "json")
        return Json::Object{{"text", Json(Json::Object{{"results", std::move(results)}, {"index", progress()},
                                                         {"model", embedder_state()}}).dump() + "\n"}};
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
