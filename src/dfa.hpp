#pragma once
#include "backend.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace shgrep {

// Bounds on one DFA build. Exceeding any of them declines the build, and Hyperscan runs the query.
struct DfaLimits {
    size_t max_nfa_states = 100000;
    size_t max_dfa_states = 10000;
    size_t max_table_bytes = 16u << 20;  // the transition table kept for scanning
    size_t max_build_bytes = 64u << 20;  // NFA state sets held while determinizing
    uint32_t max_build_ms = 100;
};

// Eagerly built, multi-pattern, unanchored DFA over UTF-8 bytes for a subset of the text regex syntax, with
// exactly Hyperscan's semantics under HS_FLAG_UTF8 | HS_FLAG_UCP | HS_FLAG_MULTILINE (and HS_FLAG_CASELESS):
// every (pattern, end offset) of every match is reported once, in ascending end offset, then pattern id.
//
// Accepted: literals (any UTF-8), '.', bracket classes of literals and ranges, groups ( ) and (?: ), alternation,
// * + ? {n} {n,} {n,m} (n, m <= 1000, lazy forms included), ^ and $ (line anchors), and the escapes \t \n \r \f
// \e \a \xhh \x{h..} and backslash-punctuation. Caseless patterns must be ASCII; k and s also match U+212A and
// U+017F, as Hyperscan's Unicode case folding does. Everything whose meaning depends on Unicode tables (\w \d
// \s \p, POSIX classes) or that PCRE and Hyperscan treat specially (\b, \A, \z, inline flags, backreferences,
// possessive quantifiers, a '{' that is not a quantifier) is declined rather than approximated.
//
// The DFA does not track match starts. Its transition table is immutable and shared by all workers, so it keeps
// no per-worker scratch. States whose only exits are one to three bytes are skipped with SIMD compares.
class Dfa final : public TextEngine {
public:
    // Null, with `why` set, when a pattern is outside the subset or a limit is exceeded.
    static std::unique_ptr<Dfa> build(const std::vector<std::string>& patterns, bool caseless,
                                      const DfaLimits& limits, std::string& why);

    Backend backend() const override { return Backend::dfa; }
    ScanStatus scan(std::string_view text, EngineScratch* scratch, MatchHandler on_match, void* context) const override;

    // Everything below is the compiled form; the build and scan code in dfa.cpp are its only users.
    struct Special {
        std::vector<unsigned> matches;     // pattern ids ending here when the next byte is not '\n'
        std::vector<unsigned> matches_nl;  // ... when the next byte is '\n' or the text ends ($ holds)
        bool accelerate = false;           // no `matches`, and only escape[0..escapes) leave the state
        unsigned escapes = 0;
        uint8_t escape[3] = {};
    };
    std::vector<uint32_t> table;   // next = table[state + byte_class[byte]]; state ids are row offsets
    uint8_t byte_class[256] = {};
    unsigned shift = 0;            // log2 of the row length
    uint32_t start = 0;
    uint32_t special_min = 0;      // states at or above this report matches or accelerate
    std::vector<Special> special;  // by (state - special_min) >> shift
    size_t states = 0;
};

} // namespace shgrep
