#include "rank.hpp"
#include <windows.h>
#include <algorithm>
#include <cmath>
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

Ranker::Ranker(std::string intent) : intent_(std::move(intent)) {
    if (intent_.size() > 4096) throw std::runtime_error("intent is at most 4096 UTF-8 bytes");
    return_limit_ = setting_number(L"SHGREP_RANK_RETURN", 10, 100000);
    per_file_ = setting_number(L"SHGREP_RANK_PER_FILE", 3, 100000);
}

std::vector<Ranked> Ranker::rank(const std::vector<RankCandidate>& candidates) {
    const std::vector<double> scores = bm25(intent_, candidates);
    std::vector<size_t> order(candidates.size());
    std::iota(order.begin(), order.end(), size_t{0});
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return scores[a] > scores[b]; });
    std::vector<Ranked> ranked;
    std::unordered_map<std::string_view, size_t> per_file;
    for (size_t position = 0; position < order.size(); ++position) {
        const size_t index = order[position];
        if (per_file_ && ++per_file[candidates[index].path] > per_file_) continue;
        ranked.push_back({index, position, scores[index]});
        if (return_limit_ && ranked.size() == return_limit_) break;
    }
    candidates_ = candidates.size();
    returned_ = ranked.size();
    return ranked;
}

Json Ranker::report() const {
    return Json::Object{{"mode", "keyword"}, {"candidates", candidates_}, {"returned", returned_},
                        {"return_limit", static_cast<int64_t>(return_limit_)},
                        {"per_file_cap", static_cast<int64_t>(per_file_)}, {"ranking", "bm25(k1=1.2,b=0.75)"}};
}
}
