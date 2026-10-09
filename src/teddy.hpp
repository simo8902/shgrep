#pragma once
#include "backend.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace shgrep {

// Teddy multi-literal matcher: SSSE3-style nibble lookups (PSHUFB) on 32-byte AVX2 vectors, 8 buckets
// ("Slim" Teddy), fingerprints of 1 to 3 bytes. A vector pass finds candidate positions; a verify step compares
// the full literals of the candidate's buckets. Like Hyperscan's literal API it reports every occurrence of
// every literal, overlapping ones included.
//
// References: Hyperscan's Teddy matcher and the aho-corasick crate's packed/teddy/README.md.
class Teddy final : public TextEngine {
public:
    static constexpr size_t max_patterns = 64;
    static constexpr size_t bucket_count = 8;

    // Null when the matcher does not apply: no SSSE3, no patterns, an empty pattern, or more than max_patterns.
    // AVX2 CPUs scan 32 bytes per step, others 16 with SSSE3. `caseless` folds ASCII only, like Hyperscan's
    // caseless literal mode. Literals are raw bytes; NUL is an ordinary byte.
    static std::unique_ptr<Teddy> build(const std::vector<std::string>& patterns, bool caseless);

    // Reports like Hyperscan's literal API: every occurrence of every literal, overlapping ones included, with its
    // exact start, in ascending end offset and then pattern id. Never fails.
    Backend backend() const override { return Backend::teddy; }
    std::unique_ptr<EngineScratch> make_scratch() const override;
    ScanStatus scan(std::string_view text, EngineScratch* scratch, MatchHandler on_match, void* context) const override;
    size_t max_match_bytes() const override { return longest; }
    ScanStatus scan_chunk(std::string_view chunk, size_t fresh_from, uint64_t base, EngineScratch* scratch,
                          MatchHandler on_match, void* context) const override;

    // Everything below is the compiled form; the build and scan code in teddy.cpp are its only users.
    struct Literal {
        std::string bytes; // lower-cased when caseless
        unsigned id = 0;
    };
    unsigned fingerprint = 1;     // bytes per candidate, 1 to 3
    bool caseless = false;
    bool wide = false;            // AVX2: 32-byte blocks; otherwise SSSE3, 16
    // Some literal ends another (or duplicates it), so two ids can end at the same offset. Hyperscan leaves their
    // order undefined; Teddy reports them by id.
    bool ties = false;
    // Start order is not report order (literal lengths differ, or ties), so matches are held and sorted.
    bool reorder = false;
    size_t shortest = 0, longest = 0;
    alignas(32) uint8_t low[3][32] = {};  // per fingerprint byte: low-nibble table, duplicated in both lanes
    alignas(32) uint8_t high[3][32] = {}; // per fingerprint byte: high-nibble table
    std::vector<Literal> literals;
    std::vector<uint32_t> bucket_begin; // bucket_count + 1 offsets into bucket_items
    std::vector<uint32_t> bucket_items; // indices into literals
};

} // namespace shgrep
