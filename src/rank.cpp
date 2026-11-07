#include "rank.hpp"
#include "banner.hpp"
#include "files.hpp"
#include <condition_variable>
#include <mutex>
#include <array>
#include <windows.h>
#include <winhttp.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace shgrep {
namespace {
constexpr size_t max_query_terms = 64;

uint32_t setting_number(const wchar_t* name, uint32_t fallback, uint32_t high) {
    wchar_t buffer[32];
    const DWORD size = GetEnvironmentVariableW(name, buffer, 32);
    if (!size) return fallback;
    const auto bad = [&] {
        std::string label;
        for (const wchar_t* c = name; *c; ++c) label.push_back(static_cast<char>(*c));
        return std::runtime_error(label + " must be a number from 0 to " + std::to_string(high));
    };
    if (size >= 32) throw bad();
    uint64_t result = 0;
    for (DWORD i = 0; i < size; ++i) {
        if (buffer[i] < L'0' || buffer[i] > L'9') throw bad();
        result = result * 10 + static_cast<unsigned>(buffer[i] - L'0');
        if (result > high) throw bad();
    }
    return static_cast<uint32_t>(result);
}

struct WinHttpHandle {
    HINTERNET value;
    ~WinHttpHandle() { if (value) WinHttpCloseHandle(value); }
};

// One blocking JSON POST to a loopback llama-server. Throws std::runtime_error on any transport or HTTP failure.
// SAFETY: loopback only (127.0.0.1), no proxy, no redirects, no credentials or cookies.
using RankClock = std::chrono::steady_clock;
void check_rank_request(RankClock::time_point deadline,
                        const std::shared_ptr<std::atomic_bool>& cancelled) {
    if (cancelled && cancelled->load()) throw std::runtime_error("ranked search cancelled");
    if (RankClock::now() >= deadline) throw std::runtime_error("ranked search timed out");
}

// A transport failure records whether it happened before sending, which controls the retry pause below.
using RerankResponse = std::expected<std::string, RerankFailure>;

// Process-wide memory of an unreachable reranker (issue #88). Windows retries a refused loopback connect for about
// 2 s, so without it every ranked search paid that wait. After one unreachable result, searches skip the reranker for
// SHGREP_RERANK_RETRY_MS, then try again once; a successful rerank clears it.
struct RerankOutage {
    std::mutex mutex;
    uint32_t port = 0;  // 0 = no outage recorded
    RankClock::time_point retry_at{};
    std::string reason;
};
RerankOutage& rerank_outage() {
    static RerankOutage outage;
    return outage;
}
// Empty when the reranker on `port` may be tried now; otherwise why it is skipped and when it is tried again.
std::string rerank_skip_reason(uint32_t port) {
    auto& outage = rerank_outage();
    std::lock_guard lock(outage.mutex);
    const auto now = RankClock::now();
    if (outage.port != port || now >= outage.retry_at) return {};
    const auto seconds = std::chrono::ceil<std::chrono::seconds>(outage.retry_at - now).count();
    return "skipped: it was unreachable on an earlier search (" + outage.reason + "); next try in " +
           std::to_string(seconds) + " s";
}
void record_rerank_outage(uint32_t port, const std::string& reason, uint32_t retry_ms) {
    if (!retry_ms) return;  // SHGREP_RERANK_RETRY_MS=0: try on every search
    auto& outage = rerank_outage();
    std::lock_guard lock(outage.mutex);
    outage.port = port;
    outage.retry_at = RankClock::now() + std::chrono::milliseconds(retry_ms);
    outage.reason = reason;
}
void clear_rerank_outage(uint32_t port) {
    auto& outage = rerank_outage();
    std::lock_guard lock(outage.mutex);
    if (outage.port == port) outage.port = 0;
}
struct HttpState {
    std::mutex mutex;
    std::condition_variable ready;
    DWORD completed = 0, error = 0, read_size = 0;
    std::string body;
    std::array<char, 16384> buffer{};
    static void CALLBACK callback(HINTERNET, DWORD_PTR context, DWORD status, void* info, DWORD size) {
        if (!context) return;
        auto* owner = reinterpret_cast<std::shared_ptr<HttpState>*>(context);
        auto state = *owner;
        if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
            delete owner;  // Last notification; pending I/O retains the shared buffers until here.
            return;
        }
        std::lock_guard lock(state->mutex);
        if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR) {
            state->error = info && size >= sizeof(WINHTTP_ASYNC_RESULT)
                ? static_cast<WINHTTP_ASYNC_RESULT*>(info)->dwError : ERROR_INVALID_DATA;
        } else if (status == WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE ||
                   status == WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE ||
                   status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE) {
            state->completed = status;
            if (status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE) state->read_size = size;
        }
        state->ready.notify_all();
    }
};
RerankResponse post_json(uint32_t port, const wchar_t* path, const std::string& body,
                         RankClock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled,
                         int& status_out) {
    check_rank_request(deadline, cancelled);
    WinHttpHandle session{WinHttpOpen(L"shgrep-rank/1", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC)};
    if (!session.value) return std::unexpected(RerankFailure{"cannot initialize WinHTTP"});
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - RankClock::now()).count();
    const int budget = static_cast<int>(std::clamp<int64_t>(remaining, 1, 300000));
    WinHttpSetTimeouts(session.value, std::min(budget, 2000), std::min(budget, 2000), budget, budget);
    WinHttpHandle connection{WinHttpConnect(session.value, L"127.0.0.1", static_cast<INTERNET_PORT>(port), 0)};
    if (!connection.value) return std::unexpected(RerankFailure{"cannot connect to the reranker"});
    auto state = std::make_shared<HttpState>();
    state->body = body;
    WinHttpHandle request{WinHttpOpenRequest(connection.value, L"POST", path, nullptr, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, 0)};
    if (!request.value) return std::unexpected(RerankFailure{"cannot create the reranker request"});
    auto owner = std::make_unique<std::shared_ptr<HttpState>>(state);
    const DWORD_PTR context = reinterpret_cast<DWORD_PTR>(owner.get());
    if (!WinHttpSetOption(request.value, WINHTTP_OPTION_CONTEXT_VALUE,
                          const_cast<DWORD_PTR*>(&context), sizeof(context)))
        return std::unexpected(RerankFailure{"cannot configure reranker request context"});
    if (WinHttpSetStatusCallback(request.value, HttpState::callback,
          WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS | WINHTTP_CALLBACK_FLAG_HANDLES, 0) == WINHTTP_INVALID_STATUS_CALLBACK)
        return std::unexpected(RerankFailure{"cannot configure reranker completion callback"});
    owner.release(); // The HANDLE_CLOSING callback owns this context, including on cancellation.
    DWORD redirects = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    DWORD disabled = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    if (!WinHttpSetOption(request.value, WINHTTP_OPTION_REDIRECT_POLICY, &redirects, sizeof(redirects)) ||
        !WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)))
        return std::unexpected(RerankFailure{"cannot configure reranker request policy"});
    auto begin = [&] {
        check_rank_request(deadline, cancelled);
        std::lock_guard lock(state->mutex);
        state->completed = state->error = state->read_size = 0;
    };
    // Only failures before sending start the retry pause; later failures belong to this request.
    auto started = [](BOOL ok, bool sending) -> std::expected<void, RerankFailure> {
        if (ok) return {};
        const DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING) return {};
        return std::unexpected(RerankFailure{
            "reranker request failed (WinHTTP error " + std::to_string(error) + ")", sending});
    };
    auto wait = [&](DWORD expected) -> std::expected<void, RerankFailure> {
        std::unique_lock lock(state->mutex);
        for (;;) {
            // A budget shorter than Windows' ~2 s connect retry ends before the refusal arrives; still unreachable.
            if (expected == WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE && !(cancelled && cancelled->load()) &&
                RankClock::now() >= deadline)
                return std::unexpected(RerankFailure{
                    "reranker did not accept the connection within the reranking budget", true});
            check_rank_request(deadline, cancelled);
            if (state->error)
                return std::unexpected(RerankFailure{
                    "reranker response failed (WinHTTP error " + std::to_string(state->error) + ")",
                    expected == WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE});
            if (state->completed == expected) return {};
            state->ready.wait_for(lock, std::chrono::milliseconds(10));
        }
    };
    static const wchar_t headers[] = L"Content-Type: application/json\r\nConnection: close\r\n";
    const auto size = static_cast<DWORD>(state->body.size());
    begin();
    if (auto result = started(WinHttpSendRequest(request.value, headers, static_cast<DWORD>(-1),
            state->body.data(), size, size, context), true); !result)
        return std::unexpected(std::move(result.error()));
    if (auto result = wait(WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE); !result)
        return std::unexpected(std::move(result.error()));
    begin();
    if (auto result = started(WinHttpReceiveResponse(request.value, nullptr), false); !result)
        return std::unexpected(std::move(result.error()));
    if (auto result = wait(WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE); !result)
        return std::unexpected(std::move(result.error()));
    DWORD status = 0, status_size = sizeof(status);
    if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
        return std::unexpected(RerankFailure{"cannot read the reranker's HTTP status"});
    status_out = static_cast<int>(status);
    std::string response;
    for (;;) {
        begin();
        if (auto result = started(WinHttpReadData(request.value, state->buffer.data(), static_cast<DWORD>(state->buffer.size()), nullptr), false); !result)
            return std::unexpected(std::move(result.error()));
        if (auto result = wait(WINHTTP_CALLBACK_STATUS_READ_COMPLETE); !result)
            return std::unexpected(std::move(result.error()));
        const DWORD got = state->read_size;
        if (!got) break;
        if (got > state->buffer.size() || response.size() + got > (4u << 20))
            return std::unexpected(RerankFailure{"reranker response exceeds 4 MiB"});
        response.append(state->buffer.data(), got);
    }
    check_rank_request(deadline, cancelled);
    return response;
}

// Document text for the reranker: where the hunk is, then its code cut to max_bytes at a character boundary.
std::string rerank_document(const RankCandidate& candidate, size_t max_bytes) {
    std::string text = "file: ";
    text.append(candidate.path);
    if (candidate.first_line)
        text += " (lines " + std::to_string(candidate.first_line) + "-" +
                std::to_string(std::max(candidate.first_line, candidate.last_line)) + ")";
    text += '\n';
    size_t cut = std::min(candidate.code.size(), max_bytes);
    while (cut > 0 && cut < candidate.code.size() && (static_cast<unsigned char>(candidate.code[cut]) & 0xc0) == 0x80) --cut;
    text.append(candidate.code.substr(0, cut));
    return text;
}

// Lowercase terms; identifiers split at snake_case and camelCase boundaries ("HTTPServer" -> http, server).
template<class Emit>
void for_each_term(std::string_view text, Emit&& emit, RankClock::time_point deadline,
                   const std::shared_ptr<std::atomic_bool>& cancelled) {
    std::string term;
    const auto flush = [&] {
        if (term.size() >= 2) emit(term);
        term.clear();
    };
    const auto is_lower = [](unsigned char c) { return c >= 'a' && c <= 'z'; };
    const auto is_upper = [](unsigned char c) { return c >= 'A' && c <= 'Z'; };
    const auto is_digit = [](unsigned char c) { return c >= '0' && c <= '9'; };
    for (size_t i = 0; i < text.size(); ++i) {
        if ((i & 4095) == 0) check_rank_request(deadline, cancelled);
        const auto c = static_cast<unsigned char>(text[i]);
        if (!is_lower(c) && !is_upper(c) && !is_digit(c) && c < 0x80) { flush(); continue; }
        if (is_upper(c) && !term.empty()) {
            const auto previous = static_cast<unsigned char>(text[i - 1]);
            const bool next_lower = i + 1 < text.size() && is_lower(static_cast<unsigned char>(text[i + 1]));
            if (is_lower(previous) || is_digit(previous) || (is_upper(previous) && next_lower)) flush();
        }
        term.push_back(is_upper(c) ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c));
    }
    flush();
}

// Instruction words that would otherwise outrank the task's own words, because BM25 favours rare terms.
bool stop_word(const std::string& term) {
    static const std::unordered_set<std::string> words{
        "a", "about", "all", "an", "and", "any", "are", "as", "at", "be", "by", "can", "code", "could", "do", "does",
        "each", "explain", "file", "files", "find", "for", "from", "get", "has", "have", "how", "if", "in", "into",
        "is", "it", "its", "locate", "look", "me", "my", "need", "not", "of", "on", "or", "our", "please", "see",
        "should", "show", "so", "some", "that", "the", "their", "them", "then", "there", "these", "this", "those",
        "to", "use", "used", "uses", "using", "want", "was", "we", "what", "when", "where", "which", "while", "who",
        "why", "will", "with", "would", "you", "your"};
    return words.contains(term);
}

// BM25 scores of the intent over path + code, one per candidate.
std::vector<double> bm25(const std::string& intent, const std::vector<RankCandidate>& candidates,
                         RankClock::time_point deadline, const std::shared_ptr<std::atomic_bool>& cancelled) {
    std::vector<double> scores(candidates.size(), 0.0);
    std::unordered_map<std::string, uint32_t> query;
    for_each_term(intent, [&](const std::string& term) {
        if (query.size() < max_query_terms && !stop_word(term)) query.emplace(term, static_cast<uint32_t>(query.size()));
    }, deadline, cancelled);
    if (query.empty() || candidates.empty()) return scores;
    // PERF: term frequencies are kept sparse (query terms only), so memory is bounded by matches, not candidates x terms.
    std::vector<std::vector<std::pair<uint32_t, uint32_t>>> frequencies(candidates.size());
    std::vector<uint32_t> lengths(candidates.size(), 0), document_frequency(query.size(), 0);
    uint64_t total_length = 0;
    for (size_t i = 0; i < candidates.size(); ++i) {
        check_rank_request(deadline, cancelled);
        auto& counts = frequencies[i];
        const auto count = [&](const std::string& term) {
            ++lengths[i];
            const auto it = query.find(term);
            if (it == query.end()) return;
            for (auto& [slot, tf] : counts) if (slot == it->second) { ++tf; return; }
            counts.emplace_back(it->second, 1u);
        };
        for_each_term(candidates[i].path, count, deadline, cancelled);
        for_each_term(candidates[i].code, count, deadline, cancelled);
        total_length += lengths[i];
        for (const auto& [slot, tf] : counts) ++document_frequency[slot];
    }
    const double n = static_cast<double>(candidates.size());
    const double average = std::max(1.0, static_cast<double>(total_length) / n);
    for (size_t i = 0; i < candidates.size(); ++i) {
        check_rank_request(deadline, cancelled);
        for (const auto& [slot, tf] : frequencies[i]) {
            const double df = document_frequency[slot];
            const double idf = std::log(1.0 + (n - df + 0.5) / (df + 0.5));
            const double f = tf;
            scores[i] += idf * f * 2.2 / (f + 1.2 * (0.25 + 0.75 * lengths[i] / average));
        }
    }
    return scores;
}

// What the intent asks for, so its own kind of file is not demoted ("where do the tests mock the clock").
struct IntentKinds {
    bool tests = false, docs = false;
};
IntentKinds intent_kinds(const std::string& intent, RankClock::time_point deadline,
                         const std::shared_ptr<std::atomic_bool>& cancelled) {
    static const std::unordered_set<std::string> test_words{
        "test", "tests", "testing", "spec", "specs", "fixture", "fixtures", "mock", "mocks", "e2e", "unittest"};
    static const std::unordered_set<std::string> doc_words{
        "doc", "docs", "documentation", "readme", "guide", "tutorial", "changelog", "markdown", "manual"};
    IntentKinds kinds;
    for_each_term(intent, [&](const std::string& term) {
        kinds.tests = kinds.tests || test_words.contains(term);
        kinds.docs = kinds.docs || doc_words.contains(term);
    }, deadline, cancelled);
    return kinds;
}

// File-kind weight on the BM25 score by path shape (issue #90; rules after sweet-search's grep prior and test-path
// rules, references/sweet-search-investigation.md section 3.4): 1 source; 0.5 tests and docs unless the intent asks
// for them; 0.25 generated, vendored, built or minified files and lockfiles.
double path_prior(std::string_view path, IntentKinds wanted) {
    std::string p = "/";
    p.reserve(path.size() + 1);
    for (char c : path) p.push_back(c == '\\' ? '/' : (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
    const size_t slash = p.rfind('/');
    const std::string_view name = std::string_view(p).substr(slash + 1);  // lowercase basename
    const std::string_view original = path.substr(path.size() - name.size());  // basename as written
    const size_t dot = name.rfind('.');
    const std::string_view stem = dot == std::string_view::npos ? name : name.substr(0, dot);
    const std::string_view extension = dot == std::string_view::npos ? std::string_view() : name.substr(dot + 1);
    const auto has_dir = [&](std::string_view dir) {
        // A whole directory segment: "/dist/" matches, "/distance/" and a file named dist do not.
        for (size_t at = p.find(dir); at != std::string::npos; at = p.find(dir, at + 1))
            if (at > 0 && p[at - 1] == '/' && at + dir.size() < p.size() && p[at + dir.size()] == '/' &&
                at + dir.size() < slash + 1)
                return true;
        return false;
    };
    const auto any_dir = [&](std::initializer_list<std::string_view> dirs) {
        for (auto dir : dirs) if (has_dir(dir)) return true;
        return false;
    };

    static const std::unordered_set<std::string_view> lockfiles{
        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "pnpm-lock.yml", "bun.lock",
        "bun.lockb", "cargo.lock", "go.sum", "poetry.lock", "pipfile.lock", "uv.lock", "pdm.lock", "composer.lock",
        "gemfile.lock", "podfile.lock", "package.resolved", "mix.lock", "pubspec.lock", "flake.lock",
        "gradle.lockfile", "packages.lock.json", "deno.lock"};
    if (lockfiles.contains(name) || any_dir({"vendor", "dist", "build", "node_modules", "obj"}) ||
        name.ends_with(".min.js") || name.ends_with(".min.css") || name.ends_with(".pb.go") ||
        name.ends_with("_pb2.py") || name.find(".generated.") != std::string_view::npos ||
        name.ends_with(".g.cs") || name.ends_with(".g.i.cs") || name.ends_with(".designer.cs"))
        return 0.25;

    const auto script_extension = [&] {
        for (std::string_view e : {"js", "jsx", "ts", "tsx", "cjs", "mjs", "cts", "mts"}) if (extension == e) return true;
        return false;
    };
    const auto test_named = [&] {
        if (stem.ends_with("_test") || stem.ends_with("_spec") || (stem.starts_with("test_") && dot != std::string_view::npos) ||
            name == "conftest.py")
            return true;
        if (script_extension())  // foo.test.ts, foo-spec.js, foo_test.jsx
            for (std::string_view tag : {"test", "spec"})
                if (stem.size() > tag.size() && stem.ends_with(tag)) {
                    const char before = stem[stem.size() - tag.size() - 1];
                    if (before == '.' || before == '-' || before == '_') return true;
                }
        // FooTest.cs, FooTests.java: case-sensitive, so "latest.cs" or "Contest.java" stay source.
        const size_t odot = original.rfind('.');
        const std::string_view ostem = odot == std::string_view::npos ? original : original.substr(0, odot);
        for (std::string_view e : {"java", "kt", "kts", "scala", "cs", "swift", "m", "mm", "php"})
            if (extension == e && (ostem.ends_with("Test") || ostem.ends_with("Tests")) && ostem.size() > 5) return true;
        return false;
    };
    if (!wanted.tests &&
        (any_dir({"__tests__", "__mocks__", "test", "tests", "spec", "specs", "testdata", "test_data", "fixture",
                  "fixtures", "e2e", "mock", "mocks", "testing", "integration-test", "integration-tests",
                  "integration_test", "integration_tests", "unit-test", "unit-tests", "unit_test", "unit_tests",
                  "acceptance-test", "acceptance-tests", "acceptance_test", "acceptance_tests"}) ||
         test_named()))
        return 0.5;

    if (!wanted.docs) {
        for (std::string_view e : {"md", "mdx", "markdown", "rst", "adoc", "rdoc", "txt"})
            if (extension == e) return 0.5;
        if (any_dir({"doc", "docs"})) return 0.5;
    }
    return 1.0;
}
}

uint32_t rank_scan_limit() {
    const uint32_t limit = setting_number(L"SHGREP_RANK_SCAN_LIMIT", 50000, 100000000);
    return limit ? limit : UINT32_MAX;
}

std::vector<double> bm25_scores(const std::string& intent, const std::vector<RankCandidate>& candidates,
                                const std::shared_ptr<std::atomic_bool>& cancelled) {
    return bm25(intent, candidates, request_deadline(RankClock::time_point::max()), cancelled);
}

Ranker::Ranker(std::string intent) : intent_(std::move(intent)) {
    if (intent_.size() > 4096) throw std::runtime_error("intent is at most 4096 UTF-8 bytes");
    return_limit_ = setting_number(L"SHGREP_RANK_RETURN", 10, 100000);
    per_file_ = setting_number(L"SHGREP_RANK_PER_FILE", 3, 100000);
    // The reranker is off unless SHGREP_RERANK_PORT names its port, so no search waits on a server that was never
    // started (issues #87, #88). 0 also turns it off.
    rerank_port_set_ = GetEnvironmentVariableW(L"SHGREP_RERANK_PORT", nullptr, 0) != 0;
    rerank_port_ = setting_number(L"SHGREP_RERANK_PORT", 0, 65535);
    rerank_retry_ms_ = setting_number(L"SHGREP_RERANK_RETRY_MS", 60000, 3600000);
    rerank_pool_ = setting_number(L"SHGREP_RERANK_POOL", 24, 100000);
    rerank_budget_ms_ = std::max<uint32_t>(setting_number(L"SHGREP_RERANK_BUDGET_MS", 3000, 300000), 1);
}

// Scores the ranked candidates in one request and reorders them by the reranker's relevance, best first.
std::expected<void, RerankFailure> Ranker::rerank(const std::vector<RankCandidate>& candidates, std::vector<Ranked>& ranked,
                                                  const std::shared_ptr<std::atomic_bool>& cancelled) {
    constexpr size_t document_bytes = 2000;
    Json::Array documents;
    documents.reserve(ranked.size());
    for (const auto& item : ranked) documents.emplace_back(rerank_document(candidates[item.index], document_bytes));
    const std::string body = Json(Json::Object{{"model", "reranker"}, {"query", intent_}, {"documents", std::move(documents)}}).dump();
    int status = 0;
    const auto deadline = request_deadline(RankClock::now() + std::chrono::milliseconds(rerank_budget_ms_));
    auto response = post_json(rerank_port_, L"/v1/rerank", body, deadline, cancelled, status);
    if (!response) return std::unexpected(std::move(response.error()));
    if (status == 404) response = post_json(rerank_port_, L"/rerank", body, deadline, cancelled, status);
    if (!response) return std::unexpected(std::move(response.error()));
    if (status != 200) return std::unexpected(RerankFailure{"reranker answered HTTP " + std::to_string(status)});
    Json parsed;
    try { parsed = Json::parse(*response); }
    catch (const std::exception&) { return std::unexpected(RerankFailure{"reranker returned invalid JSON"}); }
    const Json* results = std::holds_alternative<Json::Object>(parsed.value) ? parsed.get("results") : nullptr;
    if (!results || !std::holds_alternative<Json::Array>(results->value))
        return std::unexpected(RerankFailure{"reranker answer has no results; start llama-server with --reranking --pooling rank"});
    std::vector<double> relevance(ranked.size(), std::numeric_limits<double>::quiet_NaN());
    for (const Json& entry : results->array()) {
        const Json* index = std::holds_alternative<Json::Object>(entry.value) ? entry.get("index") : nullptr;
        const Json* score = std::holds_alternative<Json::Object>(entry.value) ? entry.get("relevance_score") : nullptr;
        if (!index || !score || !std::holds_alternative<int64_t>(index->value))
            return std::unexpected(RerankFailure{"reranker result is malformed"});
        double value = 0;
        if (const auto* real = std::get_if<double>(&score->value)) value = *real;
        else if (const auto* whole = std::get_if<int64_t>(&score->value)) value = static_cast<double>(*whole);
        else return std::unexpected(RerankFailure{"reranker result is malformed"});
        const int64_t at = index->integer();
        if (at < 0 || static_cast<size_t>(at) >= relevance.size() || !std::isfinite(value))
            return std::unexpected(RerankFailure{"reranker result is out of range"});
        relevance[static_cast<size_t>(at)] = value;
    }
    for (double value : relevance)
        if (std::isnan(value)) return std::unexpected(RerankFailure{"reranker did not score every candidate"});
    for (size_t i = 0; i < ranked.size(); ++i) {
        ranked[i].reranked = true;
        ranked[i].rerank_score = relevance[i];
    }
    std::stable_sort(ranked.begin(), ranked.end(), [](const Ranked& a, const Ranked& b) { return a.rerank_score > b.rerank_score; });
    reranked_ = ranked.size();
    return {};
}

std::vector<Ranked> Ranker::rank(const std::vector<RankCandidate>& candidates,
                                  const std::shared_ptr<std::atomic_bool>& cancelled) {
    const auto deadline = request_deadline(RankClock::time_point::max());
    check_rank_request(deadline, cancelled);
    std::vector<double> scores = bm25(intent_, candidates, deadline, cancelled);
    // Path prior (#90): source above tests and docs, those above generated and vendored files. Hunks of one file share
    // their path, so each path is classified once.
    const IntentKinds wanted = intent_kinds(intent_, deadline, cancelled);
    std::unordered_map<std::string_view, double> priors;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if ((i & 4095) == 0) check_rank_request(deadline, cancelled);
        if (scores[i] == 0) continue;
        auto [it, added] = priors.try_emplace(candidates[i].path, 1.0);
        if (added) it->second = path_prior(candidates[i].path, wanted);
        scores[i] *= it->second;
    }
    // GPU build (#87): weight x dense + (1 - weight) x BM25 (with its path prior), each min-max scaled over the
    // candidates. The scorer's failures propagate: ranked search then fails with the cause, never BM25 alone.
    if (dense_ && !candidates.empty()) {
        const std::vector<double> dense = dense_(candidates, cancelled);
        if (dense.size() != candidates.size()) throw std::runtime_error("meaning scores do not match the candidates");
        const auto scaled = [](const std::vector<double>& values) {
            const auto [low, high] = std::minmax_element(values.begin(), values.end());
            std::vector<double> out(values.size(), 0.0);
            if (*high > *low)
                for (size_t i = 0; i < values.size(); ++i) out[i] = (values[i] - *low) / (*high - *low);
            return out;
        };
        const std::vector<double> d = scaled(dense), b = scaled(scores);
        for (size_t i = 0; i < scores.size(); ++i) scores[i] = dense_weight_ * d[i] + (1 - dense_weight_) * b[i];
    }
    std::vector<size_t> order(candidates.size());
    std::iota(order.begin(), order.end(), size_t{0});
    size_t comparisons = 0;
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        if ((++comparisons & 4095) == 0) check_rank_request(deadline, cancelled);
        return scores[a] > scores[b];
    });
    // With a reranker the keyword stage keeps a wider pool for it to reorder; without one it keeps what is returned.
    const bool use_reranker = rerank_port_ != 0;
    const size_t keep = use_reranker ? rerank_pool_ : return_limit_;
    std::vector<Ranked> ranked;
    std::unordered_map<std::string_view, size_t> per_file;
    for (size_t position = 0; position < order.size(); ++position) {
        check_rank_request(deadline, cancelled);
        const size_t index = order[position];
        if (per_file_ && ++per_file[candidates[index].path] > per_file_) continue;
        ranked.push_back({index, position, scores[index]});
        if (keep && ranked.size() == keep) break;
    }
    mode_ = dense_ ? "meaning" : "keyword";
    rerank_error_.clear();
    reranked_ = rerank_ms_ = 0;
    if (use_reranker && ranked.size() > 1) {
        const auto started = std::chrono::steady_clock::now();
        // Routine reranker errors leave the original order intact; report the reason with the search result.
        if (std::string skipped = rerank_skip_reason(rerank_port_); !skipped.empty()) {
            rerank_error_ = std::move(skipped);
        } else {
            std::expected<void, RerankFailure> result;
            try {
                result = rerank(candidates, ranked, cancelled);
                if (result) {
                    mode_ = "rerank";
                    clear_rerank_outage(rerank_port_);
                }
            } catch (const std::exception& error) {
                check_rank_request(deadline, cancelled);
                rerank_error_ = error.what();
            }
            if (!result) {
                check_rank_request(deadline, cancelled);
                rerank_error_ = std::move(result.error().message);
                if (result.error().unreachable)
                    record_rerank_outage(rerank_port_, rerank_error_, rerank_retry_ms_);
            }
        }
        rerank_ms_ = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());
    }
    check_rank_request(deadline, cancelled);
    if (return_limit_ && ranked.size() > return_limit_) ranked.resize(return_limit_);
    candidates_ = candidates.size();
    returned_ = ranked.size();
    return ranked;
}

std::string Ranker::check_reranker(const std::shared_ptr<std::atomic_bool>& cancelled) {
    const RequestDeadline health_deadline(RankClock::now() + std::chrono::seconds(3));
    if (!rerank_port_)
        return std::string("the optional reranker is off (") + (rerank_port_set_ ? "SHGREP_RERANK_PORT=0" : "SHGREP_RERANK_PORT not set") +
               "); ranked searches use built-in BM25 only";
    const std::vector<RankCandidate> candidates{{"health.txt", 1, 1, "merge two sorted lists"}, {"health.txt", 3, 3, "draw a circle"}};
    std::vector<Ranked> ranked{{0, 0, 0}, {1, 1, 0}};
    const auto notice = [&](const std::string& reason) {
        return "the optional reranker on 127.0.0.1:" + std::to_string(rerank_port_) + " is not running (" + reason +
               "); ranked searches use built-in BM25 only. To also rerank the top hunks, start: llama-server -m "
               "<reranker>.gguf --reranking --pooling rank --embedding --host 127.0.0.1 --port " + std::to_string(rerank_port_);
    };
    // An explicit check always tries the server and updates the retry pause that ranked searches use.
    std::expected<void, RerankFailure> result;
    try {
        result = rerank(candidates, ranked, cancelled);
        if (result) clear_rerank_outage(rerank_port_);
    } catch (const std::exception& error) {
        return notice(error.what());
    }
    if (!result) {
        if (result.error().unreachable)
            record_rerank_outage(rerank_port_, result.error().message, rerank_retry_ms_);
        return notice(result.error().message);
    }
    return {};
}

Json Ranker::report() const {
    Json::Object report{{"mode", mode_}, {"candidates", candidates_}, {"returned", returned_},
                        {"return_limit", static_cast<int64_t>(return_limit_)},
                        {"per_file_cap", static_cast<int64_t>(per_file_)},
                        {"ranking", dense_ ? std::to_string(static_cast<int>(dense_weight_ * 100 + 0.5)) + "% meaning + " +
                                                 std::to_string(100 - static_cast<int>(dense_weight_ * 100 + 0.5)) + "% bm25(k1=1.2,b=0.75)"
                                           : std::string("bm25(k1=1.2,b=0.75)")},
                        {"path_prior", "source 1, tests/docs 0.5, generated 0.25"}};
    if (!rerank_port_) report.emplace("reranker", rerank_port_set_ ? "off (SHGREP_RERANK_PORT=0)" : "off (SHGREP_RERANK_PORT not set)");
    if (rerank_port_) {
        report.emplace("rerank_port", static_cast<int64_t>(rerank_port_));
        report.emplace("rerank_scored", reranked_);
        report.emplace("rerank_ms", rerank_ms_);
        if (!rerank_error_.empty()) report.emplace("rerank_error", rerank_error_);
    }
    return report;
}
}
