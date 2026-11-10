#pragma once
#include "json.hpp"
#include "repl.hpp"

#include <atomic>
#include <filesystem>
#include <functional>
#include <list>
#include <memory>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace shgrep {
// Read history for snapshot-guarded writes: path -> sha256 of the bytes last read in this session.
// SAFETY: bounded by least-recently-used expiry. An expired path has no record, so its next write fails until the
//   file is read again (or expected_sha256 is supplied); expiry never turns a guarded write into an unguarded one.
//   Paths deleted by other programs are not tracked; they age out like any other unused record.
struct ReadSnapshots {
    static constexpr size_t max_paths = 16384;
    void remember(const std::wstring& key, const std::string& sha256) {
        std::lock_guard lock(mutex_);
        if (auto found = hashes_.find(key); found != hashes_.end()) {
            found->second.first = sha256;
            order_.splice(order_.begin(), order_, found->second.second);
            return;
        }
        order_.push_front(key);
        hashes_.emplace(key, std::make_pair(sha256, order_.begin()));
        while (hashes_.size() > max_paths) {
            hashes_.erase(order_.back());
            order_.pop_back();
        }
    }
    // The remembered hash, or empty when the path was never read or its record expired.
    std::string find(const std::wstring& key) {
        std::lock_guard lock(mutex_);
        const auto found = hashes_.find(key);
        if (found == hashes_.end()) return {};
        order_.splice(order_.begin(), order_, found->second.second);
        return found->second.first;
    }
    void erase(const std::wstring& key) {
        std::lock_guard lock(mutex_);
        if (auto found = hashes_.find(key); found != hashes_.end()) {
            order_.erase(found->second.second);
            hashes_.erase(found);
        }
    }
    // key itself and every path below it (prefix ends with a separator).
    void erase_under(const std::wstring& key, const std::wstring& prefix) {
        std::lock_guard lock(mutex_);
        for (auto it = hashes_.lower_bound(key); it != hashes_.end() && (it->first == key || it->first.starts_with(key));) {
            if (it->first == key || it->first.starts_with(prefix)) {
                order_.erase(it->second.second);
                it = hashes_.erase(it);
            } else ++it;
        }
    }

private:
    std::mutex mutex_;
    std::list<std::wstring> order_;  // most recently used first
    std::map<std::wstring, std::pair<std::string, std::list<std::wstring>::iterator>> hashes_;
};

// MCP text results over this many bytes are saved under .shgrep-output with a preview (offload_output), and
// read_file pages stop below it (SearchContext::text_page_bytes). arXiv 2603.05344 uses the same 8,000.
inline constexpr size_t offload_text_bytes = 8000;

struct SearchContext {
    std::vector<std::filesystem::path> allowed_roots;
    // --read-only: the write tools (edit_file, write_file, move_file, create_directory) are neither listed nor run, and
    // the live index, which writes index files and sync cookies into the workspace, stays off.
    bool read_only = false;
    // MCP server (on unless --no-live-index or --read-only): the workspace (the first root) has a watched index, and
    // searches there use it unless they pass index: false; other roots are walked. False for the one-shot CLI,
    // which checks a snapshot against the tree instead.
    bool live_index = false;
    // Native backend intent policy (the lsp tool's search). The plain MCP search tool and REPL text search ask for
    // intent or exhaustive=true only when the search can reach code files (gate_plain_text_search).
    // Supplying intent still enables ranking through the native backend.
    bool require_intent = false;
    // Shared by direct tools and the default REPL; named REPL sessions use their own state.
    std::shared_ptr<ReadSnapshots> read_snapshots = std::make_shared<ReadSnapshots>();
    bool record_user_reads = false;
    // Set per MCP read_file call while offloading is on: a text page ends at the last whole line that keeps the
    // response under this many bytes, with a continue offset, so the file is paged instead of copied to
    // .shgrep-output. 0 (REPL, CLI, offload_output=false): the requested lines are returned whole.
    size_t text_page_bytes = 0;
    // Process-local REPL values belong to this server context and are never used as search caches.
    std::shared_ptr<ReplState> repl_state = make_repl_state();
};

// A large text-search result kept in a temporary file instead of memory. The MCP server writes it to the client in
// pieces; only plain tools called without max_output_bytes ever produce one.
class TextStream {
public:
    using Reader = std::move_only_function<void(uint64_t offset, uint64_t length, std::string& bytes)>;
    explicit TextStream(Reader reader) : read_(std::move(reader)) {}
    void add_text(std::string text);
    void add_spilled(uint64_t offset, uint64_t length);
    // Next piece (about 1 MiB) of the whole text. No UTF-8 sequence is split between pieces, so escaping the pieces
    // one by one equals escaping the whole text. False at the end.
    bool next(std::string& piece);
    // Enable before the first read when a failed offload may need to resend the complete stream.
    void retain_for_replay() { retain_text_ = true; }
    void rewind() { part_ = 0; at_ = 0; carry_.clear(); retain_text_ = false; }

private:
    struct Part {
        std::string text;
        uint64_t offset = 0, length = 0;
        bool spilled = false;
    };
    Reader read_;
    std::vector<Part> parts_;
    size_t part_ = 0;
    uint64_t at_ = 0;
    std::string carry_;
    bool retain_text_ = false;
};

// Default whole-request deadline; semantic LSP operations get a longer first-use window.
int64_t default_request_timeout_ms(const std::string& name, const Json& arguments);
// Runs any tool, search or file tool; throws std::runtime_error with a model-facing message on failure.
// A non-null stream receives a large text-search result instead of result["text"] (see TextStream). A text_limit
// above zero fails an unranked text search as soon as its raw output passes that many bytes.
Json run_tool(const std::string& name, const Json& arguments,
              const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled,
              std::shared_ptr<TextStream>* stream = nullptr, uint64_t text_limit = 0);
// Plain search tool and REPL text search: the intent rule for searches that can reach code files (CONTRACT at its
// definition). Returns the arguments without exhaustive, or throws std::runtime_error naming intent/exhaustive.
Json gate_plain_text_search(Json arguments, const SearchContext& context);
// Internal facade dispatch: retains semantic operations, workspace locking and native validation.
Json run_backend_tool(const std::string& name, const Json& arguments,
                      const SearchContext& context, const std::shared_ptr<std::atomic_bool>& cancelled,
                      std::shared_ptr<TextStream>* stream = nullptr, uint64_t text_limit = 0);
// CONTRACT: the session health check. Empty when the reranker answers and every bundled language server is
//   installed with what it needs. A missing language server makes one SHGREP HEALTH failure banner listing each
//   problem; the optional reranker's absence is only a "[shgrep: ...]" note, since ranked searches then use BM25 order.
//   It starts no language server and has no side effects; the MCP server attaches it once, to the first tool result.
std::string health_notice(const SearchContext& context);
// The search tools' definitions (search, search_bytes, find_files).
Json tool_definitions();
// Every tool this server exposes under context, for tools/list.
Json tool_list(const SearchContext& context);
bool tool_available(const std::string& name, const SearchContext& context);
// Builds or loads the workspace's index (the first root) and starts watching it, unless workspace_too_broad; returns at
// once, the work runs on background threads.
void start_live_indexes(const SearchContext& context);
// Opens the index log (.shgrep/index.log) when no live index does it (--no-live-index, --read-only).
void open_workspace_log(const SearchContext& context);
// True when the workspace (the first root) is a drive root, the user profile or another folder holding system folders:
// too broad to index or to scan for language server warm-up.
bool workspace_too_broad(const SearchContext& context);
// CONTRACT: index and language-server warm-up events reach the user here, never in tool results (a request that
//   names index: true still gets its own notes): .shgrep\index.log in the workspace, rewritten at each server start;
//   stderr, which MCP clients keep in their own log; and the log window through the listener.
void index_log(bool warning, const std::string& message);
// Receives every index_log line, under the log's lock; an empty function removes it before its target goes away.
void set_index_log_listener(std::move_only_function<void(bool warning, const std::string& message)> listener);
}
