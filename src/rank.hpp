#pragma once
#include "json.hpp"
#include <cstdint>
#include <atomic>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace shgrep {
// One finding as the ranker sees it: source text without grep path/line prefixes.
struct RankCandidate {
    std::string_view path;
    uint64_t first_line = 0, last_line = 0;  // 0 when line numbers are unknown
    std::string_view code;
};

struct Ranked {
    size_t index = 0;           // into the candidates passed to rank()
    size_t keyword_rank = 0;    // 0-based BM25 position before any per-file cap
    double score = 0;           // BM25 of the intent over path + code
    bool reranked = false;      // a reranker scored this candidate
    double rerank_score = 0;    // the reranker's relevance score when reranked
};

// Routine reranker failures carry their retry classification without exception matching.
struct RerankFailure {
    std::string message;
    bool unreachable = false; // Only failures before the request is sent start the retry pause.
};

// Most matches a ranked search collects before ranking (SHGREP_RANK_SCAN_LIMIT, default 50000, 0 = no limit), so one
// loose pattern in a very large tree cannot make ranking hold millions of hits. UINT32_MAX when unlimited.
uint32_t rank_scan_limit();

// Request-local ranking of findings against the task's intent. No state survives the request.
// CONTRACT: BM25 (k1 1.2, b 0.75) over path + code, identifiers split at _ and camelCase, instruction words ignored;
//   ties keep scan order. At most SHGREP_RANK_PER_FILE (default 3, 0 = no cap) candidates per file and at most
//   SHGREP_RANK_RETURN (default 10, 0 = all) in total are returned, best first.
// CONTRACT: optional reranker, off unless SHGREP_RERANK_PORT is set to a nonzero port (unset or 0 = keyword order
//   only). A llama-server started with --reranking on 127.0.0.1:SHGREP_RERANK_PORT scores the best
//   SHGREP_RERANK_POOL (default 24, 0 = all) keyword candidates in one POST /v1/rerank, and they return in its order.
//   When it is unreachable, slow (SHGREP_RERANK_BUDGET_MS, default 3000) or answers badly, rank() returns BM25
//   keyword order and report() carries rerank_error, which the search states in its ranking note.
//   When it cannot be reached at all (refused or failed connect), later searches in this process skip it for
//   SHGREP_RERANK_RETRY_MS (default 60000, 0 = try every search) and say so in rerank_error; a success clears that.
//   Searches can be cancelled during reranking; HTTP attempts share the remaining request and reranking budgets.
class Ranker {
public:
    explicit Ranker(std::string intent);
    std::vector<Ranked> rank(const std::vector<RankCandidate>& candidates,
                             const std::shared_ptr<std::atomic_bool>& cancelled = {});
    Json report() const;
    // Overrides SHGREP_RANK_PER_FILE for this request; 1 makes every returned candidate a different file (files and
    // count output rank whole files by their best hunk).
    void set_per_file(uint32_t cap) { per_file_ = cap; }
    // GPU build (#87): meaning scores per candidate (higher is closer, any scale). With one set, rank() orders by
    // weight x dense + (1 - weight) x BM25, each scaled to [0, 1] over the candidates. A throw from the scorer fails
    // the ranking: there is no BM25-only fallback.
    using DenseScorer = std::move_only_function<std::vector<double>(const std::vector<RankCandidate>&,
                                                          const std::shared_ptr<std::atomic_bool>&)>;
    void set_dense(DenseScorer scorer, double weight) { dense_ = std::move(scorer); dense_weight_ = weight; }
    // Empty when the reranker answers a two-document request correctly; otherwise why it is not used (informational:
    // ranked searches then use BM25 keyword order).
    std::string check_reranker(const std::shared_ptr<std::atomic_bool>& cancelled = {});
private:
    std::expected<void, RerankFailure> rerank(const std::vector<RankCandidate>& candidates, std::vector<Ranked>& ranked,
                const std::shared_ptr<std::atomic_bool>& cancelled);
    std::string intent_;
    uint32_t return_limit_ = 10, per_file_ = 3;
    uint32_t rerank_port_ = 0, rerank_pool_ = 24, rerank_budget_ms_ = 3000, rerank_retry_ms_ = 60000;
    bool rerank_port_set_ = false;  // SHGREP_RERANK_PORT is present in the environment (for the "off" note)
    uint64_t candidates_ = 0, returned_ = 0, reranked_ = 0, rerank_ms_ = 0;
    std::string mode_ = "keyword", rerank_error_;
    DenseScorer dense_;
    double dense_weight_ = 0.9;
};

// BM25 (the Ranker's keyword stage, without the path prior) of the intent over each candidate's path + code.
std::vector<double> bm25_scores(const std::string& intent, const std::vector<RankCandidate>& candidates,
                                const std::shared_ptr<std::atomic_bool>& cancelled = {});
}
