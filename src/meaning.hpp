#pragma once
#include "embed.hpp"
#include "json.hpp"
#include "rank.hpp"
#include "search.hpp"
#include <atomic>
#include <memory>
#include <string>

namespace shgrep {
// Meaning search over LSP symbols (issue #87, GPU build). The workspace (the first root) gets an in-memory index:
// one chunk per function, method, constructor, class, struct or enum from the language server's outline, with the
// comment block above it (classes, structs and enums cut at 60 lines; parts of at most 1200 characters), one
// EmbeddingGemma vector per chunk. A file is re-chunked and re-embedded only when its bytes change.
// CONTRACT: score = weight x dense + (1 - weight) x BM25, each min-max scaled per question over all chunks;
//   weight is SHGREP_MEANING_WEIGHT percent (default 90). Symbols and files rank by their best chunk.
// CONTRACT: no fallback. In the portable build, or when the model, its DLLs or the GPU fail, every call throws
//   std::runtime_error starting with "MEANING SEARCH FAILURE" and naming the cause; text search, file tools and LSP
//   do not depend on it.

// Builds the index in the background once the model is ready, so the first question does not wait for it. Returns
// at once; a no-op in the portable build. Failures are logged and the next question reports them.
void start_meaning_index(const SearchContext& context);

// search operation=meaning: the LSP symbols that best match `intent` (a question in words), best first.
// Arguments: intent (required), path (file or folder scope), max_results (default 10), timeout_ms.
Json meaning_search(const Json& arguments, const SearchContext& context,
                    const std::shared_ptr<std::atomic_bool>& cancelled);

// Ranker::DenseScorer for ranked text search: per hunk, the closest indexed chunk of the same file that overlaps
// its lines (any chunk of the file when the hunk has no line numbers); -1 for hunks of files without chunks.
Ranker::DenseScorer meaning_hunk_scorer(const std::string& intent, const SearchContext& context,
                                        EmbedClock::time_point deadline);

// SHGREP_MEANING_WEIGHT / 100 (default 0.9).
double meaning_weight();
}
