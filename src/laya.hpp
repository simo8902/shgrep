#pragma once
#include "json.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace shgrep {
// Streaming digest for comparing findings with a final fresh scan, without retaining a second content copy.
class LayaFingerprint {
public:
    LayaFingerprint();
    ~LayaFingerprint();
    LayaFingerprint(const LayaFingerprint&) = delete;
    LayaFingerprint& operator=(const LayaFingerprint&) = delete;
    void add(std::string_view text);
    std::string finish();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// One finding as Laya sees it: source text without grep path/line prefixes.
struct LayaCandidate {
    std::string_view path;
    uint64_t first_line = 0, last_line = 0;  // 0 when line numbers are unknown
    std::string_view code;
};

struct LayaRanked {
    size_t index = 0;         // into the candidates passed to rank()
    size_t lexical_rank = 0;  // 0-based BM25 position
    bool scored = false;      // false when the time budget ran out first
    double probability = 0;   // Laya P(relevant); 0 when not scored
    double score = 0;         // RRF(k=60) of lexical and Laya probability ranks
};

// Request-local ranking against llama-server's /v1/systemone. No source text or result survives the request.
// CONTRACT: BM25 over the intent picks a pool (at most 3 per file); the best of the pool get one Laya noul decision
//   each, in parallel up to the server's slots, until the time budget ends. Scored candidates are ordered by RRF of
//   keyword and Laya ranks and kept when P >= 0.5 (at least 3); unscored ones keep keyword order below them.
//   SHGREP_LAYA_POOL=0 drops the per-file cap and SHGREP_LAYA_RETURN=0 drops the P filter.
//   Budget expiry is reported, never an error; an unreachable or failing server, cancellation and the request
//   deadline are errors.
class LayaSelector {
public:
    LayaSelector(std::string intent, std::shared_ptr<std::atomic_bool> cancelled,
                 std::chrono::steady_clock::time_point deadline);
    ~LayaSelector();
    LayaSelector(const LayaSelector&) = delete;
    LayaSelector& operator=(const LayaSelector&) = delete;
    // Returns at most the configured number of candidates, best first.
    std::vector<LayaRanked> rank(const std::vector<LayaCandidate>& candidates);
    Json report() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
