#pragma once
#include "json.hpp"
#include <cstdint>
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

// Most matches a ranked search collects before ranking (SHGREP_RANK_SCAN_LIMIT, default 50000, 0 = no limit), so one
// loose pattern in a very large tree cannot make ranking hold millions of hits. UINT32_MAX when unlimited.
uint32_t rank_scan_limit();

// Request-local ranking of findings against the task's intent. No state survives the request.
// CONTRACT: BM25 (k1 1.2, b 0.75) over path + code, identifiers split at _ and camelCase, instruction words ignored;
//   ties keep scan order. At most SHGREP_RANK_PER_FILE (default 3, 0 = no cap) candidates per file and at most
//   SHGREP_RANK_RETURN (default 10, 0 = all) in total are returned, best first.
// CONTRACT: optional reranker. When SHGREP_RERANK_PORT names a llama-server started with --reranking, the best
//   SHGREP_RERANK_POOL (default 24, 0 = all) keyword candidates are scored in one POST /v1/rerank and returned in the
//   reranker's order. The reranker never makes a search fail: when it is unreachable, slow (SHGREP_RERANK_BUDGET_MS,
//   default 3000) or answers badly, the keyword order is returned and the report carries rerank_error. A search
//   cannot be cancelled while it waits for the reranker, for at most the budget.
class Ranker {
public:
    explicit Ranker(std::string intent);
    std::vector<Ranked> rank(const std::vector<RankCandidate>& candidates);
    Json report() const;
private:
    void rerank(const std::vector<RankCandidate>& candidates, std::vector<Ranked>& ranked);
    std::string intent_;
    uint32_t return_limit_ = 10, per_file_ = 3;
    uint32_t rerank_port_ = 0, rerank_pool_ = 24, rerank_budget_ms_ = 3000;
    uint64_t candidates_ = 0, returned_ = 0, reranked_ = 0, rerank_ms_ = 0;
    std::string mode_ = "keyword", rerank_error_;
};
}
