#include "rank.hpp"
#include "banner.hpp"
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
std::string post_json(uint32_t port, const wchar_t* path, const std::string& body, int timeout_ms, int& status_out) {
    WinHttpHandle session{WinHttpOpen(L"shgrep-rank/1", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS, 0)};
    if (!session.value) throw std::runtime_error("cannot initialize WinHTTP");
    WinHttpSetTimeouts(session.value, 2000, 2000, timeout_ms, timeout_ms);
    WinHttpHandle connection{WinHttpConnect(session.value, L"127.0.0.1", static_cast<INTERNET_PORT>(port), 0)};
    if (!connection.value) throw std::runtime_error("cannot connect to the reranker");
    WinHttpHandle request{WinHttpOpenRequest(connection.value, L"POST", path, nullptr, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, 0)};
    if (!request.value) throw std::runtime_error("cannot create the reranker request");
    DWORD redirects = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    DWORD disabled = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    WinHttpSetOption(request.value, WINHTTP_OPTION_REDIRECT_POLICY, &redirects, sizeof(redirects));
    WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled));
    static const wchar_t headers[] = L"Content-Type: application/json\r\nConnection: close\r\n";
    const auto size = static_cast<DWORD>(body.size());
    if (!WinHttpSendRequest(request.value, headers, static_cast<DWORD>(-1), const_cast<char*>(body.data()), size, size, 0) ||
        !WinHttpReceiveResponse(request.value, nullptr))
        throw std::runtime_error("reranker unreachable or timed out (WinHTTP error " + std::to_string(GetLastError()) + ")");
    DWORD status = 0, status_size = sizeof(status);
    if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
        throw std::runtime_error("cannot read the reranker's HTTP status");
    status_out = static_cast<int>(status);
    std::string response;
    char buffer[16384];
    for (;;) {
        DWORD got = 0;
        if (!WinHttpReadData(request.value, buffer, sizeof(buffer), &got))
            throw std::runtime_error("reranker response failed (WinHTTP error " + std::to_string(GetLastError()) + ")");
        if (!got) break;
        if (response.size() + got > (4u << 20)) throw std::runtime_error("reranker response exceeds 4 MiB");
        response.append(buffer, got);
    }
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
void for_each_term(std::string_view text, Emit&& emit) {
    std::string term;
    const auto flush = [&] {
        if (term.size() >= 2) emit(term);
        term.clear();
    };
    const auto is_lower = [](unsigned char c) { return c >= 'a' && c <= 'z'; };
    const auto is_upper = [](unsigned char c) { return c >= 'A' && c <= 'Z'; };
    const auto is_digit = [](unsigned char c) { return c >= '0' && c <= '9'; };
    for (size_t i = 0; i < text.size(); ++i) {
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
std::vector<double> bm25(const std::string& intent, const std::vector<RankCandidate>& candidates) {
    std::vector<double> scores(candidates.size(), 0.0);
    std::unordered_map<std::string, uint32_t> query;
    for_each_term(intent, [&](const std::string& term) {
        if (query.size() < max_query_terms && !stop_word(term)) query.emplace(term, static_cast<uint32_t>(query.size()));
    });
    if (query.empty() || candidates.empty()) return scores;
    // PERF: term frequencies are kept sparse (query terms only), so memory is bounded by matches, not candidates x terms.
    std::vector<std::vector<std::pair<uint32_t, uint32_t>>> frequencies(candidates.size());
    std::vector<uint32_t> lengths(candidates.size(), 0), document_frequency(query.size(), 0);
    uint64_t total_length = 0;
    for (size_t i = 0; i < candidates.size(); ++i) {
        auto& counts = frequencies[i];
        const auto count = [&](const std::string& term) {
            ++lengths[i];
            const auto it = query.find(term);
            if (it == query.end()) return;
            for (auto& [slot, tf] : counts) if (slot == it->second) { ++tf; return; }
            counts.emplace_back(it->second, 1u);
        };
        for_each_term(candidates[i].path, count);
        for_each_term(candidates[i].code, count);
        total_length += lengths[i];
        for (const auto& [slot, tf] : counts) ++document_frequency[slot];
    }
    const double n = static_cast<double>(candidates.size());
    const double average = std::max(1.0, static_cast<double>(total_length) / n);
    for (size_t i = 0; i < candidates.size(); ++i) {
        for (const auto& [slot, tf] : frequencies[i]) {
            const double df = document_frequency[slot];
            const double idf = std::log(1.0 + (n - df + 0.5) / (df + 0.5));
            const double f = tf;
            scores[i] += idf * f * 2.2 / (f + 1.2 * (0.25 + 0.75 * lengths[i] / average));
        }
    }
    return scores;
}
}

uint32_t rank_scan_limit() {
    const uint32_t limit = setting_number(L"SHGREP_RANK_SCAN_LIMIT", 50000, 100000000);
    return limit ? limit : UINT32_MAX;
}

Ranker::Ranker(std::string intent) : intent_(std::move(intent)) {
    if (intent_.size() > 4096) throw std::runtime_error("intent is at most 4096 UTF-8 bytes");
    return_limit_ = setting_number(L"SHGREP_RANK_RETURN", 10, 100000);
    per_file_ = setting_number(L"SHGREP_RANK_PER_FILE", 3, 100000);
    rerank_port_ = setting_number(L"SHGREP_RERANK_PORT", 8081, 65535);  // 0 = reranker off (tests, benchmarks)
    rerank_pool_ = setting_number(L"SHGREP_RERANK_POOL", 24, 100000);
    rerank_budget_ms_ = std::max<uint32_t>(setting_number(L"SHGREP_RERANK_BUDGET_MS", 3000, 300000), 1);
}

// Scores the ranked candidates in one request and reorders them by the reranker's relevance, best first.
void Ranker::rerank(const std::vector<RankCandidate>& candidates, std::vector<Ranked>& ranked) {
    constexpr size_t document_bytes = 2000;
    Json::Array documents;
    documents.reserve(ranked.size());
    for (const auto& item : ranked) documents.emplace_back(rerank_document(candidates[item.index], document_bytes));
    const std::string body = Json(Json::Object{{"model", "reranker"}, {"query", intent_}, {"documents", std::move(documents)}}).dump();
    int status = 0;
    std::string response = post_json(rerank_port_, L"/v1/rerank", body, static_cast<int>(rerank_budget_ms_), status);
    if (status == 404) response = post_json(rerank_port_, L"/rerank", body, static_cast<int>(rerank_budget_ms_), status);
    if (status != 200) throw std::runtime_error("reranker answered HTTP " + std::to_string(status));
    Json parsed;
    try { parsed = Json::parse(response); }
    catch (const std::exception&) { throw std::runtime_error("reranker returned invalid JSON"); }
    const Json* results = std::holds_alternative<Json::Object>(parsed.value) ? parsed.get("results") : nullptr;
    if (!results || !std::holds_alternative<Json::Array>(results->value))
        throw std::runtime_error("reranker answer has no results; start llama-server with --reranking --pooling rank");
    std::vector<double> relevance(ranked.size(), std::numeric_limits<double>::quiet_NaN());
    for (const Json& entry : results->array()) {
        const Json* index = std::holds_alternative<Json::Object>(entry.value) ? entry.get("index") : nullptr;
        const Json* score = std::holds_alternative<Json::Object>(entry.value) ? entry.get("relevance_score") : nullptr;
        if (!index || !score || !std::holds_alternative<int64_t>(index->value))
            throw std::runtime_error("reranker result is malformed");
        double value = 0;
        if (const auto* real = std::get_if<double>(&score->value)) value = *real;
        else if (const auto* whole = std::get_if<int64_t>(&score->value)) value = static_cast<double>(*whole);
        else throw std::runtime_error("reranker result is malformed");
        const int64_t at = index->integer();
        if (at < 0 || static_cast<size_t>(at) >= relevance.size() || !std::isfinite(value))
            throw std::runtime_error("reranker result is out of range");
        relevance[static_cast<size_t>(at)] = value;
    }
    for (double value : relevance)
        if (std::isnan(value)) throw std::runtime_error("reranker did not score every candidate");
    for (size_t i = 0; i < ranked.size(); ++i) {
        ranked[i].reranked = true;
        ranked[i].rerank_score = relevance[i];
    }
    std::stable_sort(ranked.begin(), ranked.end(), [](const Ranked& a, const Ranked& b) { return a.rerank_score > b.rerank_score; });
    reranked_ = ranked.size();
}

std::vector<Ranked> Ranker::rank(const std::vector<RankCandidate>& candidates) {
    const std::vector<double> scores = bm25(intent_, candidates);
    std::vector<size_t> order(candidates.size());
    std::iota(order.begin(), order.end(), size_t{0});
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return scores[a] > scores[b]; });
    // With a reranker the keyword stage keeps a wider pool for it to reorder; without one it keeps what is returned.
    const bool use_reranker = rerank_port_ != 0;
    const size_t keep = use_reranker ? rerank_pool_ : return_limit_;
    std::vector<Ranked> ranked;
    std::unordered_map<std::string_view, size_t> per_file;
    for (size_t position = 0; position < order.size(); ++position) {
        const size_t index = order[position];
        if (per_file_ && ++per_file[candidates[index].path] > per_file_) continue;
        ranked.push_back({index, position, scores[index]});
        if (keep && ranked.size() == keep) break;
    }
    mode_ = "keyword";
    rerank_error_.clear();
    reranked_ = rerank_ms_ = 0;
    if (use_reranker && ranked.size() > 1) {
        const auto started = std::chrono::steady_clock::now();
        try {
            rerank(candidates, ranked);
            mode_ = "rerank";
        } catch (const std::exception& error) {
            const std::string port = std::to_string(rerank_port_);
            throw std::runtime_error(failure_banner("RERANK FAILURE",
                "the reranker on 127.0.0.1:" + port + " failed (" + error.what() + "), so this ranked search returned "
                "nothing", "Start it with: llama-server -m <reranker>.gguf --reranking --pooling rank --embedding "
                "--host 127.0.0.1 --port " + port + " (SHGREP_RERANK_PORT names another port), then retry"));
        }
        rerank_ms_ = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());
    }
    if (return_limit_ && ranked.size() > return_limit_) ranked.resize(return_limit_);
    candidates_ = candidates.size();
    returned_ = ranked.size();
    return ranked;
}

std::string Ranker::check_reranker() {
    if (!rerank_port_) return "the reranker is turned off by SHGREP_RERANK_PORT=0, so ranked searches use BM25 only";
    const std::vector<RankCandidate> candidates{{"health.txt", 1, 1, "merge two sorted lists"}, {"health.txt", 3, 3, "draw a circle"}};
    std::vector<Ranked> ranked{{0, 0, 0}, {1, 1, 0}};
    try { rerank(candidates, ranked); }
    catch (const std::exception& error) {
        return "the reranker on 127.0.0.1:" + std::to_string(rerank_port_) + " does not work (" + error.what() +
               "); start it with: llama-server -m <reranker>.gguf --reranking --pooling rank --embedding --host 127.0.0.1 "
               "--port " + std::to_string(rerank_port_);
    }
    return {};
}

Json Ranker::report() const {
    Json::Object report{{"mode", mode_}, {"candidates", candidates_}, {"returned", returned_},
                        {"return_limit", static_cast<int64_t>(return_limit_)},
                        {"per_file_cap", static_cast<int64_t>(per_file_)}, {"ranking", "bm25(k1=1.2,b=0.75)"}};
    if (!rerank_port_) report.emplace("reranker", "off (SHGREP_RERANK_PORT=0)");
    if (rerank_port_) {
        report.emplace("rerank_port", static_cast<int64_t>(rerank_port_));
        report.emplace("rerank_scored", reranked_);
        report.emplace("rerank_ms", rerank_ms_);
        if (!rerank_error_.empty()) report.emplace("rerank_error", rerank_error_);
    }
    return report;
}
}
