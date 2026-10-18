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
    size_t index = 0;          // into the candidates passed to rank()
    size_t keyword_rank = 0;   // 0-based BM25 position before any per-file cap
    double score = 0;          // BM25 of the intent over path + code
};

// Request-local keyword ranking of findings against the task's intent. No state survives the request, no network.
// CONTRACT: BM25 (k1 1.2, b 0.75) over path + code, identifiers split at _ and camelCase, instruction words ignored;
//   ties keep scan order. At most SHGREP_RANK_PER_FILE (default 3, 0 = no cap) candidates per file and at most
//   SHGREP_RANK_RETURN (default 10, 0 = all) in total are returned, best first.
class Ranker {
public:
    explicit Ranker(std::string intent);
    std::vector<Ranked> rank(const std::vector<RankCandidate>& candidates);
    Json report() const;
private:
    std::string intent_;
    uint32_t return_limit_ = 10, per_file_ = 3;
    uint64_t candidates_ = 0, returned_ = 0;
};
}
